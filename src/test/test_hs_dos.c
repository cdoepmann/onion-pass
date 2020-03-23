/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file test_hs_dos.c
 * @brief DOCDOC
 **/

#include "orconfig.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include "core/crypto/hs_dos_crypto.h"
#include "test/test.h"
#include "test/log_test_helpers.h"
#include "lib/defs/digest_sizes.h"
#include "lib/malloc/malloc.h"
#include "lib/encoding/binascii.h"
#include "feature/hs/hs_service.h"
#include "feature/hs/hs_descriptor.h"

/**
 * Test if curve initializes*/
static void test_hs_dos_init_curve(void *arg)
{
  (void) arg;
  tt_assert(0 == hs_dos_init_curve());
  done:
    hs_dos_terminate_curve();
    return;
};

/**
 * Test if curve initializes and handler is set*/
static void test_hs_dos_load_handler(void *arg)
{
  (void) arg;
  tor_assert(0 == hs_dos_init_curve());
  hs_dos_handler_t *handler = hs_dos_handler_t_new();
  tt_assert(handler);
  done:
    hs_dos_handler_t_free(handler);
    hs_dos_terminate_curve();
    return;
};

/**
 * Test spent_tokens map. Very roughly.*/
static void test_hs_dos_test_spent_tokens(void *arg)
{
  (void) arg;
  tor_assert(0 == hs_dos_init_curve());
  hs_dos_handler_t *handler = hs_dos_handler_t_new();
  tor_assert(handler);
  BIGNUM *n = BN_new();
  BIGNUM *m = BN_new();
  tor_assert(n);
  tor_assert(m);
  tt_assert(0 == hs_dos_rand_mod_order(n));
  tt_assert(0 == hs_dos_rand_mod_order(m));
  tt_assert(0==hs_dos_is_token_spent(m, handler));
  tt_assert(0 == hs_dos_add_spent_token(n, handler));
  tt_assert(1==hs_dos_is_token_spent(n, handler));
  tt_assert(1==hs_dos_check_and_spend_token(n, handler));
  tt_assert(0==hs_dos_is_token_spent(m, handler));
  tt_assert(0==hs_dos_check_and_spend_token(m, handler));
  tt_assert(1==hs_dos_check_and_spend_token(m, handler));
  done:
    BN_free(n);
    BN_free(m);
    hs_dos_handler_t_free(handler);
    hs_dos_terminate_curve();
    return;
};

/**
 * Test if hash_to_curve works properly*/
static void test_hash_to_curve(void *arg)
{
  (void) arg;
  EC_POINT *point = NULL;
  EC_POINT *cmp_point = NULL;
  BIGNUM *token_rn = NULL;
  int test_size = 100;

  tor_assert(0 == hs_dos_init_curve());

  for (int i=0; i< test_size; i++){
    point = EC_POINT_new(hs_dos_get_group());
    tor_assert(point);
    cmp_point = EC_POINT_new(hs_dos_get_group());
    tor_assert(cmp_point);
    token_rn = BN_new();
    tor_assert(token_rn);

    tor_assert(1 == BN_rand(token_rn, HS_DOS_EC_BN_LEN*8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY));

    tt_assert(0 == hash_to_curve(point, token_rn));
    tt_assert(0 == hs_dos_validate_point(point));
    tt_assert(0 == hash_to_curve(cmp_point, token_rn));
    tt_assert(0 == hs_dos_points_cmp(point, cmp_point));

    BN_free(token_rn);
    token_rn = NULL;
    EC_POINT_free(point);
    point = NULL;
    EC_POINT_free(cmp_point);
    cmp_point = NULL;
  }

  done:
    BN_free(token_rn);
    EC_POINT_free(point);
    EC_POINT_free(cmp_point);
    hs_dos_terminate_curve();
    return;
};

/**
 * Test if curve initializes and handler is set*/
static void test_hs_dos_tokens_new(void *arg)
{
  (void) arg;
  int batch_size = 1;
  tor_assert(0 == hs_dos_init_curve());
  hs_dos_handler_t *handler = hs_dos_handler_t_new();
  tor_assert(handler);
  hs_dos_token_t **client_token = hs_dos_tokens_new(batch_size);
  tt_assert(client_token);
  done:
    hs_dos_tokens_free(client_token, batch_size);
    hs_dos_handler_t_free(handler);
    hs_dos_terminate_curve();
    return;
};

/**
 * Test if token is correctly b64 encoded and decoded.*/
static void test_hs_dos_b64_encoding(void *arg)
{
  (void) arg;
  tor_assert(0 == hs_dos_init_curve());
  char b64_t[HS_DOS_B64_TOK_LEN];
  hs_dos_token_t *tok = hs_dos_token_t_new();
  hs_dos_storable_token_t *t1 = hs_dos_storable_token_t_new();
  hs_dos_storable_token_t *t2 = hs_dos_storable_token_t_new();
  tt_assert(0 == hs_dos_generate_token(tok));
  tt_assert(EC_POINT_copy(t1->signature, tok->token_point));
  tt_assert(BN_copy(t1->token_rn, tok->token_rn));
  tt_assert(hs_dos_b64_encode_token(b64_t, (const hs_dos_storable_token_t*) t1)>1);
  tt_assert(0 == hs_dos_b64_decode_token(t2, (const char*) b64_t));
  tt_assert(0 == BN_cmp(t1->token_rn, t2->token_rn));
  tt_assert(0 == hs_dos_points_cmp( (const EC_POINT*) t1->signature, (const EC_POINT*) t2->signature));
  done:
    hs_dos_token_t_free(tok);
    hs_dos_storable_token_t_free(t1);
    hs_dos_storable_token_t_free(t2);
    hs_dos_terminate_curve();
    return;
};

/**
 * Test iff only valid tokens can be redeemed. */
static void test_hs_dos_token_validity(void *arg)
{
  (void) arg;
  tor_assert(0 == hs_dos_init_curve());
  hs_dos_handler_t *handler = hs_dos_handler_t_new();
  tor_assert(handler);
  int batch_size = 15;
  const char *data = "test_req_binding_data";
  const char *incorrect_data = "XXXX_req_binding_XXXX";
  size_t data_len = strlen(data);
  char client_redemption_hmac[DIGEST256_LEN];
  const EC_GROUP *ec = hs_dos_get_group();
  tor_assert(ec);
  EC_POINT *hs_pub_oprf_key = EC_POINT_new(ec), *generator = EC_POINT_new(ec);
  tor_assert(hs_pub_oprf_key); tor_assert(generator);
  tor_assert(0 == hs_dos_get_descriptor_points(hs_pub_oprf_key, generator, handler));
  hs_dos_proof_t *hs_proof = hs_dos_proof_t_new();
  hs_dos_proof_t *incorrect_hs_proof = hs_dos_proof_t_new();
  hs_dos_token_t **client_token = hs_dos_tokens_new(batch_size);
  hs_dos_sig_token_t **hs_token = hs_dos_sig_tokens_new(batch_size);
  tt_assert(0 == hs_dos_prepare_n_tokens(client_token, batch_size));
  // Now the client sends the tokens to be signed
  for (int i=0; i<batch_size; i++){
    tt_assert(client_token[i]->blind_token);
    EC_POINT_free(hs_token[i]->blind_token);
    hs_token[i]->blind_token = client_token[i]->blind_token;
  }
  tt_assert(0 == hs_dos_sign_n_tokens(hs_proof, hs_token, batch_size, handler));
  //Now the server sends back signatures and proof for the tokens
  for (int i=0; i<batch_size; i++){
    tt_assert(hs_token[i]->oprf_out_blind_token);
    EC_POINT_free(client_token[i]->oprf_out_blind_token);
    client_token[i]->oprf_out_blind_token = hs_token[i]->oprf_out_blind_token;
  }
  tt_assert(0 == hs_dos_rand_mod_order(incorrect_hs_proof->c));
  tt_assert(0 == hs_dos_rand_mod_order(incorrect_hs_proof->s));
  tt_assert(hs_dos_verify_and_unblind_tokens(incorrect_hs_proof, client_token, hs_pub_oprf_key, batch_size));
  tt_assert(0 == hs_dos_verify_and_unblind_tokens(hs_proof, client_token, hs_pub_oprf_key, batch_size));
  
  const BIGNUM *t_rn = client_token[0]->token_rn;
  const EC_POINT *sig = client_token[0]->token_point;
  // Should fail
  tt_assert(0 == hs_dos_prepare_redemption(client_redemption_hmac, t_rn, sig, data, data_len));
  tt_assert(hs_dos_redeem_token(client_redemption_hmac, t_rn, data, data_len, handler));
  t_rn = client_token[1]->token_rn;
  sig = client_token[1]->signed_token;
  tt_assert(0 == hs_dos_prepare_redemption(client_redemption_hmac, t_rn, sig, incorrect_data, data_len));
  tt_assert(hs_dos_redeem_token(client_redemption_hmac, t_rn, data, data_len, handler));
  hs_dos_handler_t_free(handler);
  handler = hs_dos_handler_t_new();
  tt_assert(handler);
  // Should fail because they are used or incorrect key...
  for (int i=0; i<batch_size; i++){
    const BIGNUM *client_t_rn = client_token[i]->token_rn;
    const EC_POINT *signature = client_token[i]->signed_token;
    tt_assert(0 == hs_dos_prepare_redemption(client_redemption_hmac, client_t_rn, signature, data, data_len));
    tt_assert(1 == hs_dos_redeem_token(client_redemption_hmac, client_t_rn, data, data_len, handler));
  }
  done:
    for (int i=0; i<batch_size; i++){
      hs_token[i]->blind_token = NULL;
      client_token[i]->oprf_out_blind_token = NULL;
    }
    hs_dos_proof_t_free(hs_proof);
    hs_dos_proof_t_free(incorrect_hs_proof);
    hs_dos_sig_tokens_free(hs_token, batch_size);
    hs_dos_tokens_free(client_token, batch_size);
    EC_POINT_free(hs_pub_oprf_key);
    EC_POINT_free(generator);
    hs_dos_handler_t_free(handler);
    hs_dos_terminate_curve();
};

/**
 * Test if batch_size=15 tokens can be issued and redeemed as intended
 * Test if spent tokens cannot be redeemed twice.*/
static void test_hs_dos_token_cycle(void *arg)
{
  (void) arg;
  tor_assert(0 == hs_dos_init_curve());
  hs_dos_handler_t *handler = hs_dos_handler_t_new();
  tor_assert(handler);
  int batch_size = 15;
  // char* b64_tokens;
  const char *data = "test_req_binding_data";
  size_t data_len = strlen(data);
  char client_redemption_hmac[DIGEST256_LEN];
  const EC_GROUP *ec = hs_dos_get_group();
  tor_assert(ec);
  EC_POINT *hs_pub_oprf_key = EC_POINT_new(ec), *generator = EC_POINT_new(ec);
  tor_assert(hs_pub_oprf_key); tor_assert(generator);
  tor_assert(0 == hs_dos_get_descriptor_points(hs_pub_oprf_key, generator, handler));
  hs_dos_proof_t *hs_proof = hs_dos_proof_t_new();
  hs_dos_token_t **client_token = hs_dos_tokens_new(batch_size);
  hs_dos_sig_token_t **hs_token = hs_dos_sig_tokens_new(batch_size);
  tt_assert(0 == hs_dos_prepare_n_tokens(client_token, batch_size));
  // Now the client sends the tokens to be signed
  for (int i=0; i<batch_size; i++){
    tt_assert(client_token[i]->blind_token);
    EC_POINT_free(hs_token[i]->blind_token);
    hs_token[i]->blind_token = client_token[i]->blind_token;
  }
  // tt_assert(hs_dos_set_n_blind_tokens(hs_token, (const EC_POINT**) points, batch_size));
  tt_assert(0 == hs_dos_sign_n_tokens(hs_proof, hs_token, batch_size, handler));
  //Now the server sends back signatures and proof for the tokens
  for (int i=0; i<batch_size; i++){
    tt_assert(hs_token[i]->oprf_out_blind_token);
    EC_POINT_free(client_token[i]->oprf_out_blind_token);
    client_token[i]->oprf_out_blind_token = hs_token[i]->oprf_out_blind_token;
  }
  // tt_assert(0 == hs_dos_set_oprfkey_n_tokens(client_token, (const EC_POINT**) points, batch_size));
  tt_assert(0 == hs_dos_verify_and_unblind_tokens(hs_proof, client_token, hs_pub_oprf_key, batch_size));

  // tt_assert(NULL != (b64_tokens = hs_dos_get_storable_tokens((const hs_dos_token_t**) client_token, batch_size)));
  // tor_free(b64_tokens);

  // Use tokens for redemption...
  for (int i=0; i<batch_size; i++){
    const BIGNUM *client_t_rn = client_token[i]->token_rn;
    const EC_POINT *signature = client_token[i]->signed_token;
    tt_assert(0 == hs_dos_prepare_redemption(client_redemption_hmac, client_t_rn, signature, data, data_len));
    tt_assert(0 == hs_dos_redeem_token(client_redemption_hmac, client_t_rn, data, data_len, handler));
  }
  // Should fail if reused
  for (int i=0; i<batch_size; i++){
    const BIGNUM *client_t_rn = client_token[i]->token_rn;
    const EC_POINT *signature = client_token[i]->signed_token;
    tt_assert(0 == hs_dos_prepare_redemption(client_redemption_hmac, client_t_rn, signature, data, data_len));
    tt_assert(1 == hs_dos_redeem_token(client_redemption_hmac, client_t_rn, data, data_len, handler));
  }
  done:
    for (int i=0; i<batch_size; i++){
      hs_token[i]->blind_token = NULL;
      client_token[i]->oprf_out_blind_token = NULL;
    }
    hs_dos_proof_t_free(hs_proof);
    hs_dos_sig_tokens_free(hs_token, batch_size);
    hs_dos_tokens_free(client_token, batch_size);
    EC_POINT_free(hs_pub_oprf_key);
    EC_POINT_free(generator);
    // tor_free(b64_tokens);
    hs_dos_handler_t_free(handler);
    hs_dos_terminate_curve();
};

/** Test if batch_size=15 tokens can be requested successfully */
static void test_hs_dos_token_request(void *arg)
{
  (void) arg;
  tor_assert(0 == hs_dos_init_curve());
  hs_dos_handler_t *handler = hs_dos_handler_t_new();
  tor_assert(handler);
  int batch_size = 15;
  // char* b64_tokens;
  const char *data = "test_req_binding_data";
  size_t data_len = strlen(data);
  char client_redemption_hmac[DIGEST256_LEN];
  const EC_GROUP *ec = hs_dos_get_group();
  tor_assert(ec);
  EC_POINT *hs_pub_oprf_key = EC_POINT_new(ec), *generator = EC_POINT_new(ec);
  tor_assert(hs_pub_oprf_key); tor_assert(generator);
  tor_assert(0 == hs_dos_get_descriptor_points(hs_pub_oprf_key, generator, handler));
  hs_dos_proof_t *hs_proof = hs_dos_proof_t_new();
  hs_dos_token_t **client_token = hs_dos_tokens_new(batch_size);
  hs_dos_sig_token_t **hs_token = hs_dos_sig_tokens_new(batch_size);
  tt_assert(0 == hs_dos_prepare_n_tokens(client_token, batch_size));
  // Now the client sends the tokens to be signed
  for (int i=0; i<batch_size; i++){
    tt_assert(client_token[i]->blind_token);
    EC_POINT_free(hs_token[i]->blind_token);
    hs_token[i]->blind_token = client_token[i]->blind_token;
  }
  // tt_assert(hs_dos_set_n_blind_tokens(hs_token, (const EC_POINT**) points, batch_size));
  tt_assert(0 == hs_dos_sign_n_tokens(hs_proof, hs_token, batch_size, handler));
  //Now the server sends back signatures and proof for the tokens
  for (int i=0; i<batch_size; i++){
    tt_assert(hs_token[i]->oprf_out_blind_token);
    EC_POINT_free(client_token[i]->oprf_out_blind_token);
    client_token[i]->oprf_out_blind_token = hs_token[i]->oprf_out_blind_token;
  }
  // tt_assert(0 == hs_dos_set_oprfkey_n_tokens(client_token, (const EC_POINT**) points, batch_size));
  tt_assert(0 == hs_dos_verify_and_unblind_tokens(hs_proof, client_token, hs_pub_oprf_key, batch_size));

  // tt_assert(NULL != (b64_tokens = hs_dos_get_storable_tokens((const hs_dos_token_t**) client_token, batch_size)));
  // tor_free(b64_tokens);

  // Use tokens for redemption...
  for (int i=0; i<batch_size; i++){
    const BIGNUM *client_t_rn = client_token[i]->token_rn;
    const EC_POINT *signature = client_token[i]->signed_token;
    tt_assert(0 == hs_dos_prepare_redemption(client_redemption_hmac, client_t_rn, signature, data, data_len));
    tt_assert(0 == hs_dos_redeem_token(client_redemption_hmac, client_t_rn, data, data_len, handler));
  }
  // Should fail if reused
  for (int i=0; i<batch_size; i++){
    const BIGNUM *client_t_rn = client_token[i]->token_rn;
    const EC_POINT *signature = client_token[i]->signed_token;
    tt_assert(0 == hs_dos_prepare_redemption(client_redemption_hmac, client_t_rn, signature, data, data_len));
    tt_assert(1 == hs_dos_redeem_token(client_redemption_hmac, client_t_rn, data, data_len, handler));
  }
  done:
    for (int i=0; i<batch_size; i++){
      hs_token[i]->blind_token = NULL;
      client_token[i]->oprf_out_blind_token = NULL;
    }
    hs_dos_proof_t_free(hs_proof);
    hs_dos_sig_tokens_free(hs_token, batch_size);
    hs_dos_tokens_free(client_token, batch_size);
    EC_POINT_free(hs_pub_oprf_key);
    EC_POINT_free(generator);
    // tor_free(b64_tokens);
    hs_dos_handler_t_free(handler);
    hs_dos_terminate_curve();
};

struct testcase_t hs_dos_tests[] = {
  { "hs_dos_init_curve", test_hs_dos_init_curve, TT_FORK, NULL, NULL },
  { "hs_dos_load_handler", test_hs_dos_load_handler, TT_FORK, NULL, NULL },
  { "hs_dos_test_spent_tokens", test_hs_dos_test_spent_tokens, TT_FORK, NULL, NULL },
  { "hash_to_curve", test_hash_to_curve, TT_FORK, NULL, NULL },
  { "hs_dos_tokens_new", test_hs_dos_tokens_new, TT_FORK, NULL, NULL },
  { "hs_dos_b64_encoding", test_hs_dos_b64_encoding, TT_FORK, NULL, NULL },
  { "hs_dos_token_validity", test_hs_dos_token_validity, TT_FORK, NULL, NULL },
  { "hs_dos_token_cycle", test_hs_dos_token_cycle, TT_FORK, NULL, NULL },
  { "hs_dos_token_request", test_hs_dos_token_request, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};