/* Copyright (c) 2017-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_cell.c
 * \brief Test hidden service cell functionality.
 */

#define HS_INTROPOINT_PRIVATE
#define HS_SERVICE_PRIVATE

#include "test/test.h"
#include "test/test_helpers.h"
#include "test/log_test_helpers.h"

#include "lib/crypt_ops/crypto_ed25519.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "feature/hs/hs_cell.h"
#include "feature/hs/hs_intropoint.h"
#include "feature/hs/hs_service.h"

#include "core/or/circuitlist.h"

/* Trunnel. */
#include "trunnel/hs/cell_establish_intro.h"
#include "trunnel/hs/cell_token.h"

/** We simulate the creation of an outgoing ESTABLISH_INTRO cell, and then we
 *  parse it from the receiver side. */
static void
test_gen_establish_intro_cell(void *arg)
{
  (void) arg;
  ssize_t ret;
  char circ_nonce[DIGEST_LEN] = {0};
  uint8_t buf[RELAY_PAYLOAD_SIZE];
  trn_cell_establish_intro_t *cell_in = NULL;

  crypto_rand(circ_nonce, sizeof(circ_nonce));

  /* Create outgoing ESTABLISH_INTRO cell and extract its payload so that we
     attempt to parse it. */
  {
    /* We only need the auth key pair here. */
    hs_service_intro_point_t *ip = service_intro_point_new(NULL);
    /* Auth key pair is generated in the constructor so we are all set for
     * using this IP object. */
    ret = hs_cell_build_establish_intro(circ_nonce, ip, buf);
    service_intro_point_free(ip);
    tt_u64_op(ret, OP_GT, 0);
  }

  /* Check the contents of the cell */
  {
    /* First byte is the auth key type: make sure its correct */
    tt_int_op(buf[0], OP_EQ, TRUNNEL_HS_INTRO_AUTH_KEY_TYPE_ED25519);
    /* Next two bytes is auth key len */
    tt_int_op(ntohs(get_uint16(buf+1)), OP_EQ, ED25519_PUBKEY_LEN);
    /* Skip to the number of extensions: no extensions */
    tt_int_op(buf[35], OP_EQ, 0);
    /* Skip to the sig len. Make sure it's the size of an ed25519 sig */
    tt_int_op(ntohs(get_uint16(buf+35+1+32)), OP_EQ, ED25519_SIG_LEN);
  }

  /* Parse it as the receiver */
  {
    ret = trn_cell_establish_intro_parse(&cell_in, buf, sizeof(buf));
    tt_u64_op(ret, OP_GT, 0);

    ret = verify_establish_intro_cell(cell_in,
                                      (const uint8_t *) circ_nonce,
                                      sizeof(circ_nonce));
    tt_u64_op(ret, OP_EQ, 0);
  }

 done:
  trn_cell_establish_intro_free(cell_in);
}

/* Mocked ed25519_sign_prefixed() function that always fails :) */
static int
mock_ed25519_sign_prefixed(ed25519_signature_t *signature_out,
                           const uint8_t *msg, size_t msg_len,
                           const char *prefix_str,
                           const ed25519_keypair_t *keypair) {
  (void) signature_out;
  (void) msg;
  (void) msg_len;
  (void) prefix_str;
  (void) keypair;
  return -1;
}

/** We simulate a failure to create an ESTABLISH_INTRO cell */
static void
test_gen_establish_intro_cell_bad(void *arg)
{
  (void) arg;
  ssize_t cell_len = 0;
  trn_cell_establish_intro_t *cell = NULL;
  char circ_nonce[DIGEST_LEN] = {0};
  hs_service_intro_point_t *ip = NULL;

  MOCK(ed25519_sign_prefixed, mock_ed25519_sign_prefixed);

  crypto_rand(circ_nonce, sizeof(circ_nonce));

  setup_full_capture_of_logs(LOG_WARN);
  /* Easiest way to make that function fail is to mock the
     ed25519_sign_prefixed() function and make it fail. */
  cell = trn_cell_establish_intro_new();
  tt_assert(cell);
  ip = service_intro_point_new(NULL);
  cell_len = hs_cell_build_establish_intro(circ_nonce, ip, NULL);
  service_intro_point_free(ip);
  expect_log_msg_containing("Unable to make signature for "
                            "ESTABLISH_INTRO cell.");
  teardown_capture_of_logs();
  tt_i64_op(cell_len, OP_EQ, -1);

 done:
  trn_cell_establish_intro_free(cell);
  UNMOCK(ed25519_sign_prefixed);
}

/** We build introduce1 cell with a token */
static void
test_introduce1_token_cell(void *arg)
{
  (void) arg;
  // int ret;
  ssize_t payload_len;
  uint8_t payload[RELAY_PAYLOAD_SIZE] = {0};
  hs_cell_introduce1_data_t data;
  hs_cell_introduce2_data_t data_2;
  ed25519_keypair_t key_pair;
  curve25519_keypair_t c_key_pair;
  uint8_t subcredential[DIGEST256_LEN];
  uint8_t rendezvous_cookie[REND_COOKIE_LEN];
  char redemption_hmac[HS_DOS_REDEMPTION_MAC];
  unsigned char token_rn[HS_DOS_EC_BN_LEN];
  unsigned char dleq_pk[HS_DOS_EC_POINT_LEN];
  link_specifier_t *l_spec;
  // hs_service_t service;
  // origin_circuit_t *circ;

  memset(&data, 0, sizeof(data));
  memset(&data_2, 0, sizeof(data_2));

  // circ = TO_ORIGIN_CIRCUIT(dummy_origin_circuit_new(11));

  curve25519_keypair_generate(&c_key_pair, 0);
  ed25519_keypair_generate(&key_pair, 0);

  /* Setup data... */
  data.is_legacy = 0;
  data.auth_pk = &key_pair.pubkey;
  data.client_kp = &c_key_pair;
  data.enc_pk = &c_key_pair.pubkey;
  data.onion_pk = &c_key_pair.pubkey;
  data.hs_dos_token = 1;
  data.rendezvous_cookie = rendezvous_cookie;
  data.subcredential = subcredential;
  memcpy(data.redemption_hmac, redemption_hmac, HS_DOS_REDEMPTION_MAC);
  memcpy(data.token_rn, token_rn, HS_DOS_EC_BN_LEN);
  memcpy(data.dleq_pk, dleq_pk, HS_DOS_EC_POINT_LEN);
  data.link_specifiers = smartlist_new();
  l_spec = link_specifier_new();
  smartlist_add(data.link_specifiers, l_spec);


  payload_len = hs_cell_build_introduce1(&data, payload);
  tt_assert(payload_len>0);
  // data_2.payload = payload;
  // data_2.payload_len = payload_len;
  // ret =  hs_cell_parse_introduce2(&data_2, circ, &service);
  // /* TODO */
  // if (!ret){
  //   printf("successful parsing\n");
  // }
  done:
    link_specifier_free(l_spec);
    smartlist_free(data.link_specifiers);
}


/** We try to build a token2 cell and parse it */
static void
test_build_token2_cells(void *arg)
{
  (void) arg;
  hs_dos_init_curve();
  int ret;
  int batch_size = 30;
  uint8_t dleq_pk[HS_DOS_EC_POINT_LEN];
  uint8_t dleq_proof[HS_DOS_PROOF_LEN];
  smartlist_t *cells = smartlist_new();
  hs_dos_sig_token_t **s_tok = hs_dos_sig_tokens_new(batch_size);
  for (int i=0; i<batch_size; i++){
    s_tok[i]->seq_num = i;
    s_tok[i]->oprf_out_blind_token = EC_POINT_dup(hs_dos_get_generator(),
                                                  hs_dos_get_group());
  }
  
  ret = hs_cell_build_token2_cells(cells, batch_size, dleq_pk, dleq_proof, s_tok);
  tt_assert(ret == 0);

  SMARTLIST_FOREACH_BEGIN(cells, hs_cell_token2_data_t*, data){
    // printf("length: %ld\n", data->payload_len);
    trn_cell_token2_t *cell = NULL;
    size_t pl = trn_cell_token2_parse(&cell, data->payload, data->payload_len);
    tt_assert(pl > 0);
    tt_assert(pl == data->payload_len);
  }SMARTLIST_FOREACH_END(data);

  done:
    hs_dos_sig_tokens_free(s_tok, batch_size);
    smartlist_free(cells);
    hs_dos_terminate_curve();
}

struct testcase_t hs_cell_tests[] = {
  { "gen_establish_intro_cell", test_gen_establish_intro_cell, TT_FORK,
    NULL, NULL },
  { "gen_establish_intro_cell_bad", test_gen_establish_intro_cell_bad, TT_FORK,
    NULL, NULL },
  { "test_introduce1_token_cell", test_introduce1_token_cell, TT_FORK,
    NULL, NULL },
  { "test_build_token2_cells", test_build_token2_cells, TT_FORK,
    NULL, NULL },
  END_OF_TESTCASES
};