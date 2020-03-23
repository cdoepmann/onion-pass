/* Copyright (c) 2017-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_circuit.c
 **/

#define HS_CIRCUIT_PRIVATE

#include "core/or/or.h"
#include "app/config/config.h"
#include "core/crypto/hs_ntor.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/policies.h"
#include "core/or/relay.h"
#include "core/or/crypt_path.h"
#include "core/or/channel.h"

#include "feature/client/circpathbias.h"
#include "feature/hs/hs_cell.h"
#include "feature/hs/hs_circuit.h"
#include "feature/hs/hs_circuitmap.h"
#include "feature/hs/hs_ident.h"
#include "feature/hs/hs_service.h"
#include "feature/nodelist/describe.h"
#include "feature/nodelist/nodelist.h"
#include "feature/rend/rendservice.h"
#include "feature/stats/rephist.h"
#include "lib/crypt_ops/crypto_dh.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_util.h"

#include "feature/hs/hs_dos.h"
#include "trunnel/hs/cell_token.h"

/* Trunnel. */
#include "trunnel/ed25519_cert.h"
#include "trunnel/hs/cell_common.h"
#include "trunnel/hs/cell_establish_intro.h"

#include "core/or/cpath_build_state_st.h"
#include "core/or/crypt_path_st.h"
#include "feature/nodelist/node_st.h"
#include "core/or/origin_circuit_st.h"

#include <sys/resource.h>

/* Unsets and frees all variables stored in circ, related to a request
 * or receipt of hs dos tokens */
void unset_token_request(origin_circuit_t *circ)
{
  tor_assert(circ);
  circ->token1_cells_sent = 0;
  circ->token1_cells_initiated = 0;
  circ->token2_cells_initiated = 0;
  circ->cur_size = 0;
  hs_dos_tokens_free(circ->client_token, circ->batch_size);
  if (circ->service_token){
    SMARTLIST_FOREACH(circ->service_token,
                      hs_dos_sig_token_t*,
                      sig_tok,
                      hs_dos_sig_token_t_free(sig_tok));
  }
  smartlist_free(circ->service_token);
  hs_dos_proof_t_free(circ->dleq_proof);
  if (circ->dleq_pk){
    EC_POINT_free(circ->dleq_pk);
    circ->dleq_pk = NULL;
  }
  circ->batch_size = 0;
};

/* Build and send the token1 cells
 * Return 0 on success, -1 on failure */
int hs_circ_send_token1_cells(origin_circuit_t *rdv_circ,
                              uint8_t pow_len,
                              const uint8_t *pow)
{
  int ret = -1;
  ssize_t payload_len;
  ssize_t token_len;
  uint8_t payload[RELAY_PAYLOAD_SIZE] = {0};
  trn_cell_token1_t *cell;
  trn_cell_extension_t *ext;
  trn_hs_pow_t *hs_pow;
  trn_hs_token_t *cur_token = NULL;
  hs_dos_token_t **client_token;
  int batch_size;
  unsigned char encoded_token[HS_DOS_EC_POINT_LEN];

  client_token = rdv_circ->client_token;
  batch_size = rdv_circ->batch_size;

  tor_assert(rdv_circ);
  tor_assert(rdv_circ->hs_ident);
  tor_assert(client_token);
  tor_assert(batch_size>0);
  if (pow_len>0)
    tor_assert(pow);

  cell = trn_cell_token1_new();
  tor_assert(cell);
  hs_pow = trn_hs_pow_new();
  tor_assert(hs_pow);
  ext = trn_cell_extension_new();
  tor_assert(ext);
  /* Set extension data. None are used. */
  trn_cell_extension_set_num(ext, 0);
  trn_cell_token1_set_extensions(cell, ext);
  trn_cell_token1_set_last_cell(cell, 0);
  trn_cell_token1_set_token_num(cell, 0);
  trn_cell_token1_setlen_tokens(cell, 0);
  trn_cell_token1_setlen_pow(cell, 1);
  trn_cell_token1_setlen_batch_size(cell, 1);
  trn_cell_token1_set_first_cell(cell, 1);
  trn_cell_token1_set_batch_size(cell, 0, batch_size);
  trn_hs_pow_set_pow_len(hs_pow, pow_len);
  memcpy(trn_hs_pow_getarray_proof_of_work(hs_pow), pow, pow_len);
  trn_cell_token1_set_pow(cell, 0, hs_pow);

  for (uint8_t seq=0; seq<batch_size; seq++){

    tor_assert(client_token[seq]);
    tor_assert(client_token[seq]->blind_token);

    cur_token = trn_hs_token_new();
    tor_assert(cur_token);

    trn_hs_token_set_seq_num(cur_token, seq);
    client_token[seq]->seq_num = seq;
    if (hs_dos_encode_ec_point(encoded_token, client_token[seq]->blind_token))
      goto end;
    memcpy(trn_hs_token_getarray_token(cur_token),
           encoded_token,
           HS_DOS_EC_POINT_LEN);
    payload_len = trn_cell_token1_encoded_len(cell);
    token_len = trn_hs_token_encoded_len(cur_token);
    if (payload_len<0 || token_len<0){
      goto end;
    }
    /* TODO: properly handle the case where this is not true
     * It should only be possible in the first iteration of the loop
     * Currently the first token simply will not be used */
    if (payload_len+token_len<=RELAY_PAYLOAD_SIZE){
      trn_cell_token1_set_token_num(cell,
                                    trn_cell_token1_get_token_num(cell)+1);
      trn_cell_token1_add_tokens(cell, cur_token);
      cur_token = NULL;
    }
    else{
      log_warn(LD_BUG, "Unable to add token (%u of %d)"
                       "to TOKEN1 cell on circuit %u.",
                        seq,
                        batch_size,
                        TO_CIRCUIT(rdv_circ)->n_circ_id);
      goto end;
    }

    /* This is the last cell we are building */
    if (seq==batch_size-1){
      trn_cell_token1_set_last_cell(cell, 1);
    }

    /* This cell is either full or the last one so we can send it */
    if(seq==batch_size-1 || payload_len+(2*token_len)>RELAY_PAYLOAD_SIZE){
      payload_len = trn_cell_token1_encode(payload, RELAY_PAYLOAD_SIZE, cell);
      if (relay_send_command_from_edge(CONTROL_CELL_ID, TO_CIRCUIT(rdv_circ),
                                      RELAY_COMMAND_TOKEN1,
                                      (const char *) payload, payload_len,
                                      rdv_circ->cpath->prev) < 0) {
        /* On error, circuit is closed. */
        log_warn(LD_REND, "Unable to send TOKEN1 cell on circuit %u.",
                TO_CIRCUIT(rdv_circ)->n_circ_id);
        goto end;
      }
      /* Make the loop continue and prepare another cell
       * unset cell etc*/
      if(seq!=batch_size-1){
        payload_len = 0;
        memset(payload, 0, RELAY_PAYLOAD_SIZE);
        if (cur_token){
          trn_hs_token_free(cur_token);
          cur_token = NULL;
        }
        trn_cell_token1_setlen_tokens(cell, 0);
        trn_cell_token1_setlen_pow(cell, 0);
        hs_pow = NULL;
        trn_cell_token1_setlen_batch_size(cell, 0);
        trn_cell_token1_set_last_cell(cell, 0);
        trn_cell_token1_set_first_cell(cell, 0);
        trn_cell_token1_set_token_num(cell, 0);
      }
    }
  }

  /* Success */
  ret = 0;

  end:
    if (cur_token){
      trn_hs_token_free(cur_token);
      cur_token = NULL;
    }
    trn_cell_token1_setlen_tokens(cell, 0);
    trn_cell_token1_setlen_pow(cell, 0);
    trn_cell_token1_setlen_batch_size(cell, 0);
    trn_cell_token1_free(cell);
    return ret;
};

/* A circuit is about to become an e2e rendezvous circuit. Check
 * <b>circ_purpose</b> and ensure that it's properly set. Return true iff
 * circuit purpose is properly set, otherwise return false. */
static int
circuit_purpose_is_correct_for_rend(unsigned int circ_purpose,
                                    int is_service_side)
{
  if (is_service_side) {
    if (circ_purpose != CIRCUIT_PURPOSE_S_CONNECT_REND) {
      log_warn(LD_BUG,
            "HS e2e circuit setup with wrong purpose (%d)", circ_purpose);
      return 0;
    }
  }

  if (!is_service_side) {
    if (circ_purpose != CIRCUIT_PURPOSE_C_REND_READY &&
        circ_purpose != CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED) {
      log_warn(LD_BUG,
            "Client e2e circuit setup with wrong purpose (%d)", circ_purpose);
      return 0;
    }
  }

  return 1;
}

/* Create and return a crypt path for the final hop of a v3 prop224 rendezvous
 * circuit. Initialize the crypt path crypto using the output material from the
 * ntor key exchange at <b>ntor_key_seed</b>.
 *
 * If <b>is_service_side</b> is set, we are the hidden service and the final
 * hop of the rendezvous circuit is the client on the other side. */
static crypt_path_t *
create_rend_cpath(const uint8_t *ntor_key_seed, size_t seed_len,
                  int is_service_side)
{
  uint8_t keys[HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN];
  crypt_path_t *cpath = NULL;

  /* Do the key expansion */
  if (hs_ntor_circuit_key_expansion(ntor_key_seed, seed_len,
                                    keys, sizeof(keys)) < 0) {
    goto err;
  }

  /* Setup the cpath */
  cpath = tor_malloc_zero(sizeof(crypt_path_t));
  cpath->magic = CRYPT_PATH_MAGIC;

  if (cpath_init_circuit_crypto(cpath, (char*)keys, sizeof(keys),
                                is_service_side, 1) < 0) {
    tor_free(cpath);
    goto err;
  }

 err:
  memwipe(keys, 0, sizeof(keys));
  return cpath;
}

/* We are a v2 legacy HS client: Create and return a crypt path for the hidden
 * service on the other side of the rendezvous circuit <b>circ</b>. Initialize
 * the crypt path crypto using the body of the RENDEZVOUS1 cell at
 * <b>rend_cell_body</b> (which must be at least DH1024_KEY_LEN+DIGEST_LEN
 * bytes).
 */
static crypt_path_t *
create_rend_cpath_legacy(origin_circuit_t *circ, const uint8_t *rend_cell_body)
{
  crypt_path_t *hop = NULL;
  char keys[DIGEST_LEN+CPATH_KEY_MATERIAL_LEN];

  /* first DH1024_KEY_LEN bytes are g^y from the service. Finish the dh
   * handshake...*/
  tor_assert(circ->build_state);
  tor_assert(circ->build_state->pending_final_cpath);
  hop = circ->build_state->pending_final_cpath;

  tor_assert(hop->rend_dh_handshake_state);
  if (crypto_dh_compute_secret(LOG_PROTOCOL_WARN, hop->rend_dh_handshake_state,
                               (char*)rend_cell_body, DH1024_KEY_LEN,
                               keys, DIGEST_LEN+CPATH_KEY_MATERIAL_LEN)<0) {
    log_warn(LD_GENERAL, "Couldn't complete DH handshake.");
    goto err;
  }
  /* ... and set up cpath. */
  if (cpath_init_circuit_crypto(hop,
                                keys+DIGEST_LEN, sizeof(keys)-DIGEST_LEN,
                                0, 0) < 0)
    goto err;

  /* Check whether the digest is right... */
  if (tor_memneq(keys, rend_cell_body+DH1024_KEY_LEN, DIGEST_LEN)) {
    log_warn(LD_PROTOCOL, "Incorrect digest of key material.");
    goto err;
  }

  /* clean up the crypto stuff we just made */
  crypto_dh_free(hop->rend_dh_handshake_state);
  hop->rend_dh_handshake_state = NULL;

  goto done;

 err:
  hop = NULL;

 done:
  memwipe(keys, 0, sizeof(keys));
  return hop;
}

/* Append the final <b>hop</b> to the cpath of the rend <b>circ</b>, and mark
 * <b>circ</b> ready for use to transfer HS relay cells. */
static void
finalize_rend_circuit(origin_circuit_t *circ, crypt_path_t *hop,
                      int is_service_side)
{
  tor_assert(circ);
  tor_assert(hop);

  /* Notify the circuit state machine that we are splicing this circuit */
  int new_circ_purpose = is_service_side ?
    CIRCUIT_PURPOSE_S_REND_JOINED : CIRCUIT_PURPOSE_C_REND_JOINED;
  circuit_change_purpose(TO_CIRCUIT(circ), new_circ_purpose);

  /* All is well. Extend the circuit. */
  hop->state = CPATH_STATE_OPEN;
  /* Set the windows to default. */
  hop->package_window = circuit_initial_package_window();
  hop->deliver_window = CIRCWINDOW_START;

  /* Now that this circuit has finished connecting to its destination,
   * make sure circuit_get_open_circ_or_launch is willing to return it
   * so we can actually use it. */
  circ->hs_circ_has_timed_out = 0;

  /* Append the hop to the cpath of this circuit */
  cpath_extend_linked_list(&circ->cpath, hop);

  /* In legacy code, 'pending_final_cpath' points to the final hop we just
   * appended to the cpath. We set the original pointer to NULL so that we
   * don't double free it. */
  if (circ->build_state) {
    circ->build_state->pending_final_cpath = NULL;
  }

  /* Finally, mark circuit as ready to be used for client streams */
  if (!is_service_side) {
    circuit_try_attaching_streams(circ);
  }
}

/* For a given circuit and a service introduction point object, register the
 * intro circuit to the circuitmap. This supports legacy intro point. */
static void
register_intro_circ(const hs_service_intro_point_t *ip,
                    origin_circuit_t *circ)
{
  tor_assert(ip);
  tor_assert(circ);

  if (ip->base.is_only_legacy) {
    hs_circuitmap_register_intro_circ_v2_service_side(circ,
                                                      ip->legacy_key_digest);
  } else {
    hs_circuitmap_register_intro_circ_v3_service_side(circ,
                                         &ip->auth_key_kp.pubkey);
  }
}

/* Return the number of opened introduction circuit for the given circuit that
 * is matching its identity key. */
static unsigned int
count_opened_desc_intro_point_circuits(const hs_service_t *service,
                                       const hs_service_descriptor_t *desc)
{
  unsigned int count = 0;

  tor_assert(service);
  tor_assert(desc);

  DIGEST256MAP_FOREACH(desc->intro_points.map, key,
                       const hs_service_intro_point_t *, ip) {
    const circuit_t *circ;
    const origin_circuit_t *ocirc = hs_circ_service_get_intro_circ(ip);
    if (ocirc == NULL) {
      continue;
    }
    circ = TO_CIRCUIT(ocirc);
    tor_assert(circ->purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO ||
               circ->purpose == CIRCUIT_PURPOSE_S_INTRO);
    /* Having a circuit not for the requested service is really bad. */
    tor_assert(ed25519_pubkey_eq(&service->keys.identity_pk,
                                 &ocirc->hs_ident->identity_pk));
    /* Only count opened circuit and skip circuit that will be closed. */
    if (!circ->marked_for_close && circ->state == CIRCUIT_STATE_OPEN) {
      count++;
    }
  } DIGEST256MAP_FOREACH_END;
  return count;
}

/* From a given service, rendezvous cookie and handshake info, create a
 * rendezvous point circuit identifier. This can't fail. */
STATIC hs_ident_circuit_t *
create_rp_circuit_identifier(const hs_service_t *service,
                             const uint8_t *rendezvous_cookie,
                             const curve25519_public_key_t *server_pk,
                             const hs_ntor_rend_cell_keys_t *keys)
{
  hs_ident_circuit_t *ident;
  uint8_t handshake_info[CURVE25519_PUBKEY_LEN + DIGEST256_LEN];

  tor_assert(service);
  tor_assert(rendezvous_cookie);
  tor_assert(server_pk);
  tor_assert(keys);

  ident = hs_ident_circuit_new(&service->keys.identity_pk,
                               HS_IDENT_CIRCUIT_RENDEZVOUS);
  /* Copy the RENDEZVOUS_COOKIE which is the unique identifier. */
  memcpy(ident->rendezvous_cookie, rendezvous_cookie,
         sizeof(ident->rendezvous_cookie));
  /* Build the HANDSHAKE_INFO which looks like this:
   *    SERVER_PK        [32 bytes]
   *    AUTH_INPUT_MAC   [32 bytes]
   */
  memcpy(handshake_info, server_pk->public_key, CURVE25519_PUBKEY_LEN);
  memcpy(handshake_info + CURVE25519_PUBKEY_LEN, keys->rend_cell_auth_mac,
         DIGEST256_LEN);
  tor_assert(sizeof(ident->rendezvous_handshake_info) ==
             sizeof(handshake_info));
  memcpy(ident->rendezvous_handshake_info, handshake_info,
         sizeof(ident->rendezvous_handshake_info));
  /* Finally copy the NTOR_KEY_SEED for e2e encryption on the circuit. */
  tor_assert(sizeof(ident->rendezvous_ntor_key_seed) ==
             sizeof(keys->ntor_key_seed));
  memcpy(ident->rendezvous_ntor_key_seed, keys->ntor_key_seed,
         sizeof(ident->rendezvous_ntor_key_seed));
  return ident;
}

/* From a given service and service intro point, create an introduction point
 * circuit identifier. This can't fail. */
static hs_ident_circuit_t *
create_intro_circuit_identifier(const hs_service_t *service,
                                const hs_service_intro_point_t *ip)
{
  hs_ident_circuit_t *ident;

  tor_assert(service);
  tor_assert(ip);

  ident = hs_ident_circuit_new(&service->keys.identity_pk,
                               HS_IDENT_CIRCUIT_INTRO);
  ed25519_pubkey_copy(&ident->intro_auth_pk, &ip->auth_key_kp.pubkey);

  return ident;
}

/* For a given introduction point and an introduction circuit, send the
 * ESTABLISH_INTRO cell. The service object is used for logging. This can fail
 * and if so, the circuit is closed and the intro point object is flagged
 * that the circuit is not established anymore which is important for the
 * retry mechanism. */
static void
send_establish_intro(const hs_service_t *service,
                     hs_service_intro_point_t *ip, origin_circuit_t *circ)
{
  ssize_t cell_len;
  uint8_t payload[RELAY_PAYLOAD_SIZE];

  tor_assert(service);
  tor_assert(ip);
  tor_assert(circ);

  /* Encode establish intro cell. */
  cell_len = hs_cell_build_establish_intro(circ->cpath->prev->rend_circ_nonce,
                                           ip, payload);
  if (cell_len < 0) {
    log_warn(LD_REND, "Unable to encode ESTABLISH_INTRO cell for service %s "
                      "on circuit %u. Closing circuit.",
             safe_str_client(service->onion_address),
             TO_CIRCUIT(circ)->n_circ_id);
    goto err;
  }

  /* Send the cell on the circuit. */
  if (relay_send_command_from_edge(CONTROL_CELL_ID, TO_CIRCUIT(circ),
                                   RELAY_COMMAND_ESTABLISH_INTRO,
                                   (char *) payload, cell_len,
                                   circ->cpath->prev) < 0) {
    log_info(LD_REND, "Unable to send ESTABLISH_INTRO cell for service %s "
                      "on circuit %u.",
             safe_str_client(service->onion_address),
             TO_CIRCUIT(circ)->n_circ_id);
    /* On error, the circuit has been closed. */
    goto done;
  }

  /* Record the attempt to use this circuit. */
  pathbias_count_use_attempt(circ);
  goto done;

 err:
  circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
 done:
  memwipe(payload, 0, sizeof(payload));
}

/* Return a string constant describing the anonymity of service. */
static const char *
get_service_anonymity_string(const hs_service_t *service)
{
  if (service->config.is_single_onion) {
    return "single onion";
  } else {
    return "hidden";
  }
}

/* For a given service, the ntor onion key and a rendezvous cookie, launch a
 * circuit to the rendezvous point specified by the link specifiers. On
 * success, a circuit identifier is attached to the circuit with the needed
 * data. This function will try to open a circuit for a maximum value of
 * MAX_REND_FAILURES then it will give up. */
static void
launch_rendezvous_point_circuit(const hs_service_t *service,
                                const hs_service_intro_point_t *ip,
                                const hs_cell_introduce2_data_t *data)
{

  struct rusage before_u, after_u;
  int circ_needs_uptime;
  time_t now = time(NULL);
  extend_info_t *info = NULL;
  origin_circuit_t *circ = NULL;
  getrusage(RUSAGE_SELF, &before_u);

  tor_assert(service);
  tor_assert(ip);
  tor_assert(data);

  circ_needs_uptime = hs_service_requires_uptime_circ(service->config.ports);

  /* Get the extend info data structure for the chosen rendezvous point
   * specified by the given link specifiers. */
  info = hs_get_extend_info_from_lspecs(data->link_specifiers,
                                        &data->onion_pk,
                                        service->config.is_single_onion);
  if (info == NULL) {
    /* We are done here, we can't extend to the rendezvous point.
     * If you're running an IPv6-only v3 single onion service on 0.3.2 or with
     * 0.3.2 clients, and somehow disable the option check, it will fail here.
     */
    log_fn(LOG_PROTOCOL_WARN, LD_REND,
           "Not enough info to open a circuit to a rendezvous point for "
           "%s service %s.",
           get_service_anonymity_string(service),
           safe_str_client(service->onion_address));
    goto end;
  }

  for (int i = 0; i < MAX_REND_FAILURES; i++) {
    int circ_flags = CIRCLAUNCH_NEED_CAPACITY | CIRCLAUNCH_IS_INTERNAL;
    if (circ_needs_uptime) {
      circ_flags |= CIRCLAUNCH_NEED_UPTIME;
    }
    /* Firewall and policies are checked when getting the extend info.
     *
     * We only use a one-hop path on the first attempt. If the first attempt
     * fails, we use a 3-hop path for reachability / reliability.
     * See the comment in retry_service_rendezvous_point() for details. */
    if (service->config.is_single_onion && i == 0) {
      circ_flags |= CIRCLAUNCH_ONEHOP_TUNNEL;
    }

    circ = circuit_launch_by_extend_info(CIRCUIT_PURPOSE_S_CONNECT_REND, info,
                                         circ_flags);
    if (circ != NULL) {
      /* Stop retrying, we have a circuit! */
      break;
    }
  }
  if (circ == NULL) {
    log_warn(LD_REND, "Giving up on launching a rendezvous circuit to %s "
                      "for %s service %s",
             safe_str_client(extend_info_describe(info)),
             get_service_anonymity_string(service),
             safe_str_client(service->onion_address));
    goto end;
  }
  log_info(LD_REND, "Rendezvous circuit launched to %s with cookie %s "
                    "for %s service %s",
           safe_str_client(extend_info_describe(info)),
           safe_str_client(hex_str((const char *) data->rendezvous_cookie,
                                   REND_COOKIE_LEN)),
           get_service_anonymity_string(service),
           safe_str_client(service->onion_address));
  tor_assert(circ->build_state);
  /* Rendezvous circuit have a specific timeout for the time spent on trying
   * to connect to the rendezvous point. */
  circ->build_state->expiry_time = now + MAX_REND_TIMEOUT;

  /* Create circuit identifier and key material. */
  {
    hs_ntor_rend_cell_keys_t keys;
    curve25519_keypair_t ephemeral_kp;
    /* No need for extra strong, this is only for this circuit life time. This
     * key will be used for the RENDEZVOUS1 cell that will be sent on the
     * circuit once opened. */
    curve25519_keypair_generate(&ephemeral_kp, 0);
    if (hs_ntor_service_get_rendezvous1_keys(&ip->auth_key_kp.pubkey,
                                             &ip->enc_key_kp,
                                             &ephemeral_kp, &data->client_pk,
                                             &keys) < 0) {
      /* This should not really happened but just in case, don't make tor
       * freak out, close the circuit and move on. */
      log_info(LD_REND, "Unable to get RENDEZVOUS1 key material for "
                        "service %s",
               safe_str_client(service->onion_address));
      circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
      goto end;
    }
    circ->hs_ident = create_rp_circuit_identifier(service,
                                                  data->rendezvous_cookie,
                                                  &ephemeral_kp.pubkey, &keys);
    memwipe(&ephemeral_kp, 0, sizeof(ephemeral_kp));
    memwipe(&keys, 0, sizeof(keys));
    tor_assert(circ->hs_ident);
  }

 end:
  extend_info_free(info);
  getrusage(RUSAGE_SELF, &after_u);
  timersub(&after_u.ru_utime, &before_u.ru_utime, &circ->cpu_time_user);
  timersub(&after_u.ru_stime, &before_u.ru_stime, &circ->cpu_time_system);
  struct timeval result;
  timeradd(&circ->cpu_time_user, &circ->cpu_time_system, &result);
  printf("circ launch as part of INTRO2 Handling (should be subtracted)\n%ld\n", result.tv_usec);
}

/* Return true iff the given service rendezvous circuit circ is allowed for a
 * relaunch to the rendezvous point. */
static int
can_relaunch_service_rendezvous_point(const origin_circuit_t *circ)
{
  tor_assert(circ);
  /* This is initialized when allocating an origin circuit. */
  tor_assert(circ->build_state);
  tor_assert(TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_S_CONNECT_REND);

  /* XXX: Retrying under certain condition. This is related to #22455. */

  /* Avoid to relaunch twice a circuit to the same rendezvous point at the
   * same time. */
  if (circ->hs_service_side_rend_circ_has_been_relaunched) {
    log_info(LD_REND, "Rendezvous circuit to %s has already been retried. "
                      "Skipping retry.",
             safe_str_client(
                  extend_info_describe(circ->build_state->chosen_exit)));
    goto disallow;
  }

  /* We check failure_count >= hs_get_service_max_rend_failures()-1 below, and
   * the -1 is because we increment the failure count for our current failure
   * *after* this clause. */
  int max_rend_failures = hs_get_service_max_rend_failures() - 1;

  /* A failure count that has reached maximum allowed or circuit that expired,
   * we skip relaunching. */
  if (circ->build_state->failure_count > max_rend_failures ||
      circ->build_state->expiry_time <= time(NULL)) {
    log_info(LD_REND, "Attempt to build a rendezvous circuit to %s has "
                      "failed with %d attempts and expiry time %ld. "
                      "Giving up building.",
             safe_str_client(
                  extend_info_describe(circ->build_state->chosen_exit)),
             circ->build_state->failure_count,
             (long int) circ->build_state->expiry_time);
    goto disallow;
  }

  /* Allowed to relaunch. */
  return 1;
 disallow:
  return 0;
}

/* Retry the rendezvous point of circ by launching a new circuit to it. */
static void
retry_service_rendezvous_point(const origin_circuit_t *circ)
{
  int flags = 0;
  origin_circuit_t *new_circ;
  cpath_build_state_t *bstate;

  tor_assert(circ);
  /* This is initialized when allocating an origin circuit. */
  tor_assert(circ->build_state);
  tor_assert(TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_S_CONNECT_REND);

  /* Ease our life. */
  bstate = circ->build_state;

  log_info(LD_REND, "Retrying rendezvous point circuit to %s",
           safe_str_client(extend_info_describe(bstate->chosen_exit)));

  /* Get the current build state flags for the next circuit. */
  flags |= (bstate->need_uptime) ? CIRCLAUNCH_NEED_UPTIME : 0;
  flags |= (bstate->need_capacity) ? CIRCLAUNCH_NEED_CAPACITY : 0;
  flags |= (bstate->is_internal) ? CIRCLAUNCH_IS_INTERNAL : 0;

  /* We do NOT add the onehop tunnel flag even though it might be a single
   * onion service. The reason is that if we failed once to connect to the RP
   * with a direct connection, we consider that chances are that we will fail
   * again so try a 3-hop circuit and hope for the best. Because the service
   * has no anonymity (single onion), this change of behavior won't affect
   * security directly. */

  new_circ = circuit_launch_by_extend_info(CIRCUIT_PURPOSE_S_CONNECT_REND,
                                           bstate->chosen_exit, flags);
  if (new_circ == NULL) {
    log_warn(LD_REND, "Failed to launch rendezvous circuit to %s",
             safe_str_client(extend_info_describe(bstate->chosen_exit)));
    goto done;
  }

  /* Transfer build state information to the new circuit state in part to
   * catch any other failures. */
  new_circ->build_state->failure_count = bstate->failure_count+1;
  new_circ->build_state->expiry_time = bstate->expiry_time;
  new_circ->hs_ident = hs_ident_circuit_dup(circ->hs_ident);

 done:
  return;
}

/* Using the given descriptor intro point ip, the node of the
 * rendezvous point rp_node and the service's subcredential, populate the
 * already allocated intro1_data object with the needed key material and link
 * specifiers.
 *
 * Return 0 on success or a negative value if we couldn't properly filled the
 * introduce1 data from the RP node. In other word, it means the RP node is
 * unusable to use in the introduction. */
static int
setup_introduce1_data(const hs_desc_intro_point_t *ip,
                      const node_t *rp_node,
                      const uint8_t *subcredential,
                      const ed25519_public_key_t *identity_pk,
                      const EC_POINT *dleq_pk,
                      const hs_dos_storable_token_t *tok,
                      hs_cell_introduce1_data_t *intro1_data)
{
  int ret = -1;
  smartlist_t *rp_lspecs;
  char rq_binding_data[HS_SERVICE_ADDR_LEN_BASE32+1];

  tor_assert(ip);
  tor_assert(rp_node);
  tor_assert(subcredential);
  tor_assert(intro1_data);

  intro1_data->hs_dos_token = 0;

  /* Build the link specifiers from the node at the end of the rendezvous
   * circuit that we opened for this introduction. */
  rp_lspecs = node_get_link_specifier_smartlist(rp_node, 0);
  if (smartlist_len(rp_lspecs) == 0) {
    /* We can't rendezvous without link specifiers. */
    smartlist_free(rp_lspecs);
    goto end;
  }

  /* Populate the introduce1 data object. */
  memset(intro1_data, 0, sizeof(hs_cell_introduce1_data_t));
  if (ip->legacy.key != NULL) {
    intro1_data->is_legacy = 1;
    intro1_data->legacy_key = ip->legacy.key;
  }
  intro1_data->auth_pk = &ip->auth_key_cert->signed_key;
  intro1_data->enc_pk = &ip->enc_key;
  intro1_data->subcredential = subcredential;
  intro1_data->link_specifiers = rp_lspecs;
  intro1_data->onion_pk = node_get_curve25519_onion_key(rp_node);
  if (intro1_data->onion_pk == NULL) {
    /* We can't rendezvous without the curve25519 onion key. */
    goto end;
  }
  /* Add the token data if available */
  if (dleq_pk && tok && identity_pk){
    hs_build_address(identity_pk, HS_VERSION_THREE, rq_binding_data);
    if (hs_dos_prepare_redemption(intro1_data->redemption_hmac,
                              tok->token_rn,
                              tok->signature,
                              rq_binding_data,
                              HS_SERVICE_ADDR_LEN_BASE32+1)){
      goto end;
    }
    if (hs_dos_encode_bn(intro1_data->token_rn, tok->token_rn)){
      goto end;
    }
    if (hs_dos_encode_ec_point(intro1_data->dleq_pk, dleq_pk)){
      goto end;
    }
    /* Everything went fine, we have a token to spend */
    intro1_data->hs_dos_token = 1;
  }
  /* Success, we have valid introduce data. */
  ret = 0;

 end:
  return ret;
}

/* ========== */
/* Public API */
/* ========== */

/* Return an introduction point circuit matching the given intro point object.
 * NULL is returned is no such circuit can be found. */
origin_circuit_t *
hs_circ_service_get_intro_circ(const hs_service_intro_point_t *ip)
{
  tor_assert(ip);

  if (ip->base.is_only_legacy) {
    return hs_circuitmap_get_intro_circ_v2_service_side(ip->legacy_key_digest);
  } else {
    return hs_circuitmap_get_intro_circ_v3_service_side(
                                        &ip->auth_key_kp.pubkey);
  }
}

/* Called when we fail building a rendezvous circuit at some point other than
 * the last hop: launches a new circuit to the same rendezvous point. This
 * supports legacy service.
 *
 * We currently relaunch connections to rendezvous points if:
 * - A rendezvous circuit timed out before connecting to RP.
 * - The rendezvous circuit failed to connect to the RP.
 *
 * We avoid relaunching a connection to this rendezvous point if:
 * - We have already tried MAX_REND_FAILURES times to connect to this RP,
 * - We've been trying to connect to this RP for more than MAX_REND_TIMEOUT
 *   seconds, or
 * - We've already retried this specific rendezvous circuit.
 */
void
hs_circ_retry_service_rendezvous_point(origin_circuit_t *circ)
{
  tor_assert(circ);
  tor_assert(TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_S_CONNECT_REND);

  /* Check if we are allowed to relaunch to the rendezvous point of circ. */
  if (!can_relaunch_service_rendezvous_point(circ)) {
    goto done;
  }

  /* Flag the circuit that we are relaunching, to avoid to relaunch twice a
   * circuit to the same rendezvous point at the same time. */
  circ->hs_service_side_rend_circ_has_been_relaunched = 1;

  /* Legacy services don't have a hidden service ident. */
  if (circ->hs_ident) {
    retry_service_rendezvous_point(circ);
  } else {
    rend_service_relaunch_rendezvous(circ);
  }

 done:
  return;
}

/* For a given service and a service intro point, launch a circuit to the
 * extend info ei. If the service is a single onion, and direct_conn is true,
 * a one-hop circuit will be requested.
 *
 * Return 0 if the circuit was successfully launched and tagged
 * with the correct identifier. On error, a negative value is returned. */
int
hs_circ_launch_intro_point(hs_service_t *service,
                           const hs_service_intro_point_t *ip,
                           extend_info_t *ei,
                           bool direct_conn)
{
  /* Standard flags for introduction circuit. */
  int ret = -1, circ_flags = CIRCLAUNCH_NEED_UPTIME | CIRCLAUNCH_IS_INTERNAL;
  origin_circuit_t *circ;

  tor_assert(service);
  tor_assert(ip);
  tor_assert(ei);

  /* Update circuit flags in case of a single onion service that requires a
   * direct connection. */
  tor_assert_nonfatal(ip->circuit_retries > 0);
  /* Only single onion services can make direct conns */
  if (BUG(!service->config.is_single_onion && direct_conn)) {
    goto end;
  }
  /* We only use a one-hop path on the first attempt. If the first attempt
   * fails, we use a 3-hop path for reachability / reliability.
   * (Unlike v2, retries is incremented by the caller before it calls this
   * function.) */
  if (direct_conn && ip->circuit_retries == 1) {
    circ_flags |= CIRCLAUNCH_ONEHOP_TUNNEL;
  }

  log_info(LD_REND, "Launching a circuit to intro point %s for service %s.",
           safe_str_client(extend_info_describe(ei)),
           safe_str_client(service->onion_address));

  /* Note down the launch for the retry period. Even if the circuit fails to
   * be launched, we still want to respect the retry period to avoid stress on
   * the circuit subsystem. */
  service->state.num_intro_circ_launched++;
  circ = circuit_launch_by_extend_info(CIRCUIT_PURPOSE_S_ESTABLISH_INTRO,
                                       ei, circ_flags);
  if (circ == NULL) {
    goto end;
  }

  /* Setup the circuit identifier and attach it to it. */
  circ->hs_ident = create_intro_circuit_identifier(service, ip);
  tor_assert(circ->hs_ident);
  /* Register circuit in the global circuitmap. */
  register_intro_circ(ip, circ);

  /* Success. */
  ret = 0;
 end:
  return ret;
}

/* Called when a service introduction point circuit is done building. Given
 * the service and intro point object, this function will send the
 * ESTABLISH_INTRO cell on the circuit. Return 0 on success. Return 1 if the
 * circuit has been repurposed to General because we already have too many
 * opened. */
int
hs_circ_service_intro_has_opened(hs_service_t *service,
                                 hs_service_intro_point_t *ip,
                                 const hs_service_descriptor_t *desc,
                                 origin_circuit_t *circ)
{
  int ret = 0;
  unsigned int num_intro_circ, num_needed_circ;

  tor_assert(service);
  tor_assert(ip);
  tor_assert(desc);
  tor_assert(circ);

  /* Cound opened circuits that have sent ESTABLISH_INTRO cells or are already
   * established introduction circuits */
  num_intro_circ = count_opened_desc_intro_point_circuits(service, desc);
  num_needed_circ = service->config.num_intro_points;
  if (num_intro_circ > num_needed_circ) {
    /* There are too many opened valid intro circuit for what the service
     * needs so repurpose this one. */

    /* XXX: Legacy code checks options->ExcludeNodes and if not NULL it just
     * closes the circuit. I have NO idea why it does that so it hasn't been
     * added here. I can only assume in case our ExcludeNodes list changes but
     * in that case, all circuit are flagged unusable (config.c). --dgoulet */

    log_info(LD_CIRC | LD_REND, "Introduction circuit just opened but we "
                                "have enough for service %s. Repurposing "
                                "it to general and leaving internal.",
             safe_str_client(service->onion_address));
    tor_assert(circ->build_state->is_internal);
    /* Remove it from the circuitmap. */
    hs_circuitmap_remove_circuit(TO_CIRCUIT(circ));
    /* Cleaning up the hidden service identifier and repurpose. */
    hs_ident_circuit_free(circ->hs_ident);
    circ->hs_ident = NULL;
    if (circuit_should_use_vanguards(TO_CIRCUIT(circ)->purpose))
      circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_HS_VANGUARDS);
    else
      circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_C_GENERAL);

    /* Inform that this circuit just opened for this new purpose. */
    circuit_has_opened(circ);
    /* This return value indicate to the caller that the IP object should be
     * removed from the service because it's corresponding circuit has just
     * been repurposed. */
    ret = 1;
    goto done;
  }

  log_info(LD_REND, "Introduction circuit %u established for service %s.",
           TO_CIRCUIT(circ)->n_circ_id,
           safe_str_client(service->onion_address));
  circuit_log_path(LOG_INFO, LD_REND, circ);

  /* Time to send an ESTABLISH_INTRO cell on this circuit. On error, this call
   * makes sure the circuit gets closed. */
  send_establish_intro(service, ip, circ);

 done:
  return ret;
}

/* Called when a service rendezvous point circuit is done building. Given the
 * service and the circuit, this function will send a RENDEZVOUS1 cell on the
 * circuit using the information in the circuit identifier. If the cell can't
 * be sent, the circuit is closed. */
void
hs_circ_service_rp_has_opened(const hs_service_t *service,
                              origin_circuit_t *circ)
{
  size_t payload_len;
  uint8_t payload[RELAY_PAYLOAD_SIZE] = {0};

  tor_assert(service);
  tor_assert(circ);
  tor_assert(circ->hs_ident);

  /* Some useful logging. */
  log_info(LD_REND, "Rendezvous circuit %u has opened with cookie %s "
                    "for service %s",
           TO_CIRCUIT(circ)->n_circ_id,
           hex_str((const char *) circ->hs_ident->rendezvous_cookie,
                   REND_COOKIE_LEN),
           safe_str_client(service->onion_address));
  circuit_log_path(LOG_INFO, LD_REND, circ);

  /* This can't fail. */
  payload_len = hs_cell_build_rendezvous1(
                        circ->hs_ident->rendezvous_cookie,
                        sizeof(circ->hs_ident->rendezvous_cookie),
                        circ->hs_ident->rendezvous_handshake_info,
                        sizeof(circ->hs_ident->rendezvous_handshake_info),
                        payload);

  /* Pad the payload with random bytes so it matches the size of a legacy cell
   * which is normally always bigger. Also, the size of a legacy cell is
   * always smaller than the RELAY_PAYLOAD_SIZE so this is safe. */
  if (payload_len < HS_LEGACY_RENDEZVOUS_CELL_SIZE) {
    crypto_rand((char *) payload + payload_len,
                HS_LEGACY_RENDEZVOUS_CELL_SIZE - payload_len);
    payload_len = HS_LEGACY_RENDEZVOUS_CELL_SIZE;
  }

  if (relay_send_command_from_edge(CONTROL_CELL_ID, TO_CIRCUIT(circ),
                                   RELAY_COMMAND_RENDEZVOUS1,
                                   (const char *) payload, payload_len,
                                   circ->cpath->prev) < 0) {
    /* On error, circuit is closed. */
    log_warn(LD_REND, "Unable to send RENDEZVOUS1 cell on circuit %u "
                      "for service %s",
             TO_CIRCUIT(circ)->n_circ_id,
             safe_str_client(service->onion_address));
    goto done;
  }

  /* Setup end-to-end rendezvous circuit between the client and us. */
  if (hs_circuit_setup_e2e_rend_circ(circ,
                       circ->hs_ident->rendezvous_ntor_key_seed,
                       sizeof(circ->hs_ident->rendezvous_ntor_key_seed),
                       1) < 0) {
    log_warn(LD_GENERAL, "Failed to setup circ");
    goto done;
  }

 done:
  memwipe(payload, 0, sizeof(payload));
}

/* Circ has been expecting an INTRO_ESTABLISHED cell that just arrived. Handle
 * the INTRO_ESTABLISHED cell payload of length payload_len arriving on the
 * given introduction circuit circ. The service is only used for logging
 * purposes. Return 0 on success else a negative value. */
int
hs_circ_handle_intro_established(const hs_service_t *service,
                                 const hs_service_intro_point_t *ip,
                                 origin_circuit_t *circ,
                                 const uint8_t *payload, size_t payload_len)
{
  int ret = -1;

  tor_assert(service);
  tor_assert(ip);
  tor_assert(circ);
  tor_assert(payload);

  if (BUG(TO_CIRCUIT(circ)->purpose != CIRCUIT_PURPOSE_S_ESTABLISH_INTRO)) {
    goto done;
  }

  /* Try to parse the payload into a cell making sure we do actually have a
   * valid cell. For a legacy node, it's an empty payload so as long as we
   * have the cell, we are good. */
  if (!ip->base.is_only_legacy &&
      hs_cell_parse_intro_established(payload, payload_len) < 0) {
    log_warn(LD_REND, "Unable to parse the INTRO_ESTABLISHED cell on "
                      "circuit %u for service %s",
             TO_CIRCUIT(circ)->n_circ_id,
             safe_str_client(service->onion_address));
    goto done;
  }

  /* Switch the purpose to a fully working intro point. */
  circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_S_INTRO);
  /* Getting a valid INTRODUCE_ESTABLISHED means we've successfully used the
   * circuit so update our pathbias subsystem. */
  pathbias_mark_use_success(circ);
  /* Success. */
  ret = 0;

 done:
  return ret;
}

/* We just received an INTRODUCE2 cell on the established introduction circuit
 * circ.  Handle the INTRODUCE2 payload of size payload_len for the given
 * circuit and service. This cell is associated with the intro point object ip
 * and the subcredential. Return 0 on success else a negative value. */
int
hs_circ_handle_introduce2(hs_service_t *service,
                          const origin_circuit_t *circ,
                          hs_service_intro_point_t *ip,
                          const uint8_t *subcredential,
                          const uint8_t *payload, size_t payload_len)
{
  int ret = -1;
  time_t elapsed;
  hs_cell_introduce2_data_t data = {0};

  tor_assert(service);
  tor_assert(circ);
  tor_assert(ip);
  tor_assert(subcredential);
  tor_assert(payload);

  /* Populate the data structure with everything we need for the cell to be
   * parsed, decrypted and key material computed correctly. */
  data.auth_pk = &ip->auth_key_kp.pubkey;
  data.enc_kp = &ip->enc_key_kp;
  data.subcredential = subcredential;
  data.payload = payload;
  data.payload_len = payload_len;
  data.link_specifiers = smartlist_new();
  data.replay_cache = ip->replay_cache;
  data.dleq_pk = NULL;
  data.token_rn = NULL;

  if (hs_cell_parse_introduce2(&data, circ, service) < 0) {
    goto done;
  }

  /* Check whether we've seen this REND_COOKIE before to detect repeats. */
  if (replaycache_add_test_and_elapsed(
           service->state.replay_cache_rend_cookie,
           data.rendezvous_cookie, sizeof(data.rendezvous_cookie),
           &elapsed)) {
    /* A Tor client will send a new INTRODUCE1 cell with the same REND_COOKIE
     * as its previous one if its intro circ times out while in state
     * CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT. If we received the first
     * INTRODUCE1 cell (the intro-point relay converts it into an INTRODUCE2
     * cell), we are already trying to connect to that rend point (and may
     * have already succeeded); drop this cell. */
    log_info(LD_REND, "We received an INTRODUCE2 cell with same REND_COOKIE "
                      "field %ld seconds ago. Dropping cell.",
             (long int) elapsed);
    goto done;
  }

  /* At this point, we just confirmed that the full INTRODUCE2 cell is valid
   * so increment our counter that we've seen one on this intro point. */
  ip->introduce2_count++;

  /* Before sending, lets make sure this cell can be sent on the service
   * circuit asking the DoS defenses. */
  if (!hs_dos_can_launch_rendezvous(service,
                                    data.dleq_pk,
                                    data.token_rn,
                                    data.redemption_hmac)){
    char *msg;
    static ratelim_t rlimit = RATELIM_INIT(5 * 60);
    if ((msg = rate_limit_log(&rlimit, approx_time()))) {
      log_info(LD_REND, "Can't launch v3 rendezvous circuit due to DoS "
                            "limitations. Ignoring INTRO2 cell");
      tor_free(msg);
    }
    printf("Rejecting rendezvous circuit construction!\n");
    goto done;
  }

  /* Launch rendezvous circuit with the onion key and rend cookie. */
  launch_rendezvous_point_circuit(service, ip, &data);

  /* Success. */
  ret = 0;
  
 done:
  if (data.dleq_pk){
    EC_POINT_free(data.dleq_pk);
  }
  if (data.token_rn){
    BN_free(data.token_rn);
  }
  link_specifier_smartlist_free(data.link_specifiers);
  memwipe(&data, 0, sizeof(data));
  return ret;
}

/* Return 0 if cell is valid for current service and circuit state
 * 1 if not, -1 on error */
static int
validate_token1_cell(const hs_service_t *service,
                     origin_circuit_t *circ,
                     hs_cell_token1_data_t *data)
{
  tor_assert(service);
  tor_assert(circ);
  tor_assert(data);
  /* TODO Perform the check on the proof of work */
  if (data->is_first && (data->batch_size > service->config.hs_dos_token_num ||
                         circ->token1_cells_initiated ||
                         data->token_num > data->batch_size)){
    return 1;
  }
  else if (!data->is_first && (data->token_num+circ->service_token->num_used >
                                                          circ->batch_size ||
                               !circ->token1_cells_initiated)){
    return 1;
  }
  else{
    return 0;
  }
};

/* Will send the TOKEN2 cells, for which the relevant data should be held
 * in the service and circ.
 * It will free and unset all token request data stored in circ.  */
static void hs_dos_send_token2_cells(const hs_service_t *service,
                                     origin_circuit_t *circ)
{
  hs_dos_sig_token_t **tokens = NULL;
  hs_dos_proof_t *proof = NULL;
  smartlist_t *cells = NULL;
  unsigned char encoded_proof[HS_DOS_PROOF_LEN];
  unsigned char encoded_dleq_pk[HS_DOS_EC_POINT_LEN];
  const hs_dos_handler_t *handler = NULL;
  const EC_POINT *dleq_pk = NULL;
  int idx = 0;

  tor_assert(service);
  tor_assert(circ);
  tor_assert(circ->batch_size == circ->service_token->num_used);

  handler = (const hs_dos_handler_t*) service->cur_handler;
  tor_assert(handler);

  cells = smartlist_new();
  tor_assert(cells);

  tokens = tor_malloc(sizeof(hs_dos_sig_token_t*) * circ->batch_size);
  proof = hs_dos_proof_t_new();

  SMARTLIST_FOREACH_BEGIN(circ->service_token, hs_dos_sig_token_t*, t){
    tokens[idx] = t;
    idx++;
  } SMARTLIST_FOREACH_END(t);

  if (hs_dos_sign_n_tokens(proof, tokens, circ->batch_size, handler)){
    goto end;
  }
  if (hs_dos_encode_proof(encoded_proof, proof))
    goto end;
  
  dleq_pk = EC_KEY_get0_public_key(handler->hs_dos_oprf_key);
  tor_assert(dleq_pk);

  if (hs_dos_encode_ec_point(encoded_dleq_pk, dleq_pk))
    goto end;

  if (hs_cell_build_token2_cells(cells,
                                 circ->batch_size,
                                 (uint8_t*) encoded_dleq_pk,
                                 (uint8_t*) encoded_proof,
                                 tokens)){
    goto end;
  }

  /* Send cells and free them! */
  SMARTLIST_FOREACH_BEGIN(cells, hs_cell_token2_data_t*, data){
    /* This indicates an error */
    if (data->payload_len <= 0){
      log_warn(LD_REND, "Unable to send TOKEN1 cell on circuit %u.",
                TO_CIRCUIT(circ)->n_circ_id);
      goto end;
    }
    else{
      if (relay_send_command_from_edge(CONTROL_CELL_ID, TO_CIRCUIT(circ),
                            RELAY_COMMAND_TOKEN2,
                            (const char *) data->payload, data->payload_len,
                            circ->cpath->prev) < 0) {
        /* On error, circuit is closed. */
        log_warn(LD_REND, "Unable to send TOKEN1 cell on circuit %u.",
                TO_CIRCUIT(circ)->n_circ_id);
        goto end;
      }
    }
  }SMARTLIST_FOREACH_END(data);

  
  end:
    if (cells){
      SMARTLIST_FOREACH(cells,
                        hs_cell_token2_data_t*,
                        t2_data,
                        hs_cell_token2_data_free(t2_data));
      smartlist_free(cells);
    }
    unset_token_request(circ);
    tor_free(tokens);
    hs_dos_proof_t_free(proof);
};

/* We just received a TOKEN1 cell on the established rendezvous circuit
 * circ.  Handle the TOKEN1 payload of size payload_len for the given
 * circuit and service. Return 0 on success else a negative value. */
int
hs_circ_handle_token1(const hs_service_t *service,
                      origin_circuit_t *circ,
                      const uint8_t *payload,
                      size_t payload_len)
{
  int ret = -1;
  hs_cell_token1_data_t data;

  tor_assert(service);
  tor_assert(circ);
  tor_assert(payload);

  if (!service->config.hs_dos_defense_enabled){
    goto done;
  }
  if (!service->cur_handler){
    goto done;
  }
  memset(&data, 0, sizeof(hs_cell_token1_data_t));

  /* Populate the data structure with everything we need for the cell to be
   * parsed, decrypted and key material computed correctly. */
  data.payload = payload;
  data.payload_len = payload_len;

  if (hs_cell_parse_token1(&data, circ, service) < 0) {
    goto done;
  }

  /* This should not happen, we close the circuit */
  if (validate_token1_cell(service, circ, &data)){
    log_warn(LD_REND,
           "Closing RENDEZVOUS circuit. TOKEN1 cell invalid. %s",
           service->onion_address);
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
    goto done;
  }
  /* We have a new request */
  if (data.is_first){
    circ->batch_size = data.batch_size;
    circ->service_token = smartlist_new();
    tor_assert(data.tokens);
    smartlist_add_all(circ->service_token, data.tokens);
    circ->token1_cells_initiated = 1;
  }
  else{ /* This belongs to an existing request */
    tor_assert(circ->service_token);
    tor_assert(data.tokens);
    smartlist_add_all(circ->service_token, data.tokens);
  }
  /* Request is complete, we can handle it */
  if (data.is_last){
    if (circ->batch_size != circ->service_token->num_used){
      log_warn(LD_REND, "Closing circuit."
               "Received an incorrect number of TOKEN1 requests %s",
               service->onion_address);
      circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
      goto done;
    }
    printf("Parsed TOKEN1 cells\n");
    hs_dos_send_token2_cells(service, circ);
  }

  /* Success. */
  ret = 0;

 done:
  /* We do not free the content of the data.tokens, as we might either need it
   * or should have freed it earlier */
  if (ret && data.tokens){
    SMARTLIST_FOREACH(data.tokens,
                      hs_dos_sig_token_t*,
                      sig_tok,
                      hs_dos_sig_token_t_free(sig_tok));
  }
  if (data.tokens)
    smartlist_free(data.tokens);
  tor_free(data.pow);
  memwipe(&data, 0, sizeof(data));
  return ret;
}

/* Circuit <b>circ</b> just finished the rend ntor key exchange. Use the key
 * exchange output material at <b>ntor_key_seed</b> and setup <b>circ</b> to
 * serve as a rendezvous end-to-end circuit between the client and the
 * service. If <b>is_service_side</b> is set, then we are the hidden service
 * and the other side is the client.
 *
 * Return 0 if the operation went well; in case of error return -1. */
int
hs_circuit_setup_e2e_rend_circ(origin_circuit_t *circ,
                               const uint8_t *ntor_key_seed, size_t seed_len,
                               int is_service_side)
{
  if (BUG(!circuit_purpose_is_correct_for_rend(TO_CIRCUIT(circ)->purpose,
                                        is_service_side))) {
    return -1;
  }

  crypt_path_t *hop = create_rend_cpath(ntor_key_seed, seed_len,
                                        is_service_side);
  if (!hop) {
    log_warn(LD_REND, "Couldn't get v3 %s cpath!",
             is_service_side ? "service-side" : "client-side");
    return -1;
  }

  finalize_rend_circuit(circ, hop, is_service_side);

  return 0;
}

/* We are a v2 legacy HS client and we just received a RENDEZVOUS1 cell
 * <b>rend_cell_body</b> on <b>circ</b>. Finish up the DH key exchange and then
 * extend the crypt path of <b>circ</b> so that the hidden service is on the
 * other side. */
int
hs_circuit_setup_e2e_rend_circ_legacy_client(origin_circuit_t *circ,
                                             const uint8_t *rend_cell_body)
{

  if (BUG(!circuit_purpose_is_correct_for_rend(
                                      TO_CIRCUIT(circ)->purpose, 0))) {
    return -1;
  }

  crypt_path_t *hop = create_rend_cpath_legacy(circ, rend_cell_body);
  if (!hop) {
    log_warn(LD_GENERAL, "Couldn't get v2 cpath.");
    return -1;
  }

  finalize_rend_circuit(circ, hop, 0);

  return 0;
}

/* Given the introduction circuit intro_circ, the rendezvous circuit
 * rend_circ, a descriptor intro point object ip and the service's
 * subcredential, send an INTRODUCE1 cell on intro_circ.
 *
 * This will also setup the circuit identifier on rend_circ containing the key
 * material for the handshake and e2e encryption. Return 0 on success else
 * negative value. Because relay_send_command_from_edge() closes the circuit
 * on error, it is possible that intro_circ is closed on error.
 * tok and dleq_pk are NULL if no token is available */
int
hs_circ_send_introduce1(origin_circuit_t *intro_circ,
                        origin_circuit_t *rend_circ,
                        const hs_desc_intro_point_t *ip,
                        const uint8_t *subcredential,
                        const EC_POINT *dleq_pk,
                        const hs_dos_storable_token_t *tok)
{
  int ret = -1;
  ssize_t payload_len;
  uint8_t payload[RELAY_PAYLOAD_SIZE] = {0};
  hs_cell_introduce1_data_t intro1_data;

  tor_assert(intro_circ);
  tor_assert(rend_circ);
  tor_assert(ip);
  tor_assert(subcredential);

  /* It is undefined behavior in hs_cell_introduce1_data_clear() if intro1_data
   * has been declared on the stack but not initialized. Here, we set it to 0.
   */
  memset(&intro1_data, 0, sizeof(hs_cell_introduce1_data_t));

  /* This takes various objects in order to populate the introduce1 data
   * object which is used to build the content of the cell. */
  const node_t *exit_node = build_state_get_exit_node(rend_circ->build_state);
  if (exit_node == NULL) {
    log_info(LD_REND, "Unable to get rendezvous point for circuit %u. "
             "Failing.", TO_CIRCUIT(intro_circ)->n_circ_id);
    goto done;
  }

  /* We should never select an invalid rendezvous point in theory but if we
   * do, this function will fail to populate the introduce data. */
  if (setup_introduce1_data(ip, exit_node, subcredential,
                            &intro_circ->hs_ident->identity_pk,
                            dleq_pk, tok, &intro1_data) < 0) {
    log_warn(LD_REND, "Unable to setup INTRODUCE1 data. The chosen rendezvous "
                      "point is unusable. Closing circuit.");
    goto close;
  }

  /* Final step before we encode a cell, we setup the circuit identifier which
   * will generate both the rendezvous cookie and client keypair for this
   * connection. Those are put in the ident. */
  intro1_data.rendezvous_cookie = rend_circ->hs_ident->rendezvous_cookie;
  intro1_data.client_kp = &rend_circ->hs_ident->rendezvous_client_kp;

  memcpy(intro_circ->hs_ident->rendezvous_cookie,
         rend_circ->hs_ident->rendezvous_cookie,
         sizeof(intro_circ->hs_ident->rendezvous_cookie));

  /* From the introduce1 data object, this will encode the INTRODUCE1 cell
   * into payload which is then ready to be sent as is. */
  payload_len = hs_cell_build_introduce1(&intro1_data, payload);
  if (BUG(payload_len < 0)) {
    goto close;
  }

  if (relay_send_command_from_edge(CONTROL_CELL_ID, TO_CIRCUIT(intro_circ),
                                   RELAY_COMMAND_INTRODUCE1,
                                   (const char *) payload, payload_len,
                                   intro_circ->cpath->prev) < 0) {
    /* On error, circuit is closed. */
    log_warn(LD_REND, "Unable to send INTRODUCE1 cell on circuit %u.",
             TO_CIRCUIT(intro_circ)->n_circ_id);
    goto done;
  }

  /* Success. */
  ret = 0;
  goto done;

 close:
  circuit_mark_for_close(TO_CIRCUIT(rend_circ), END_CIRC_REASON_INTERNAL);
 done:
  hs_cell_introduce1_data_clear(&intro1_data);
  memwipe(payload, 0, sizeof(payload));
  return ret;
}

/* Send an ESTABLISH_RENDEZVOUS cell along the rendezvous circuit circ. On
 * success, 0 is returned else -1 and the circuit is marked for close. */
int
hs_circ_send_establish_rendezvous(origin_circuit_t *circ)
{
  ssize_t cell_len = 0;
  uint8_t cell[RELAY_PAYLOAD_SIZE] = {0};

  tor_assert(circ);
  tor_assert(TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND);

  log_info(LD_REND, "Send an ESTABLISH_RENDEZVOUS cell on circuit %u",
           TO_CIRCUIT(circ)->n_circ_id);

  /* Set timestamp_dirty, because circuit_expire_building expects it,
   * and the rend cookie also means we've used the circ. */
  TO_CIRCUIT(circ)->timestamp_dirty = time(NULL);

  /* We've attempted to use this circuit. Probe it if we fail */
  pathbias_count_use_attempt(circ);

  /* Generate the RENDEZVOUS_COOKIE and place it in the identifier so we can
   * complete the handshake when receiving the acknowledgement. */
  crypto_rand((char *) circ->hs_ident->rendezvous_cookie, HS_REND_COOKIE_LEN);
  /* Generate the client keypair. No need to be extra strong, not long term */
  curve25519_keypair_generate(&circ->hs_ident->rendezvous_client_kp, 0);

  cell_len =
    hs_cell_build_establish_rendezvous(circ->hs_ident->rendezvous_cookie,
                                       cell);
  if (BUG(cell_len < 0)) {
    goto err;
  }

  if (relay_send_command_from_edge(CONTROL_CELL_ID, TO_CIRCUIT(circ),
                                   RELAY_COMMAND_ESTABLISH_RENDEZVOUS,
                                   (const char *) cell, cell_len,
                                   circ->cpath->prev) < 0) {
    /* Circuit has been marked for close */
    log_warn(LD_REND, "Unable to send ESTABLISH_RENDEZVOUS cell on "
                      "circuit %u", TO_CIRCUIT(circ)->n_circ_id);
    memwipe(cell, 0, cell_len);
    goto err;
  }

  memwipe(cell, 0, cell_len);
  return 0;
 err:
  return -1;
}

/* We are about to close or free this <b>circ</b>. Clean it up from any
 * related HS data structures. This function can be called multiple times
 * safely for the same circuit. */
void
hs_circ_cleanup(circuit_t *circ)
{
  tor_assert(circ);

  /* If it's a service-side intro circ, notify the HS subsystem for the intro
   * point circuit closing so it can be dealt with cleanly. */
  if (circ->purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO ||
      circ->purpose == CIRCUIT_PURPOSE_S_INTRO) {
    hs_service_intro_circ_has_closed(TO_ORIGIN_CIRCUIT(circ));
  }

  /* Clear HS circuitmap token for this circ (if any). Very important to be
   * done after the HS subsystem has been notified of the close else the
   * circuit will not be found.
   *
   * We do this at the close if possible because from that point on, the
   * circuit is good as dead. We can't rely on removing it in the circuit
   * free() function because we open a race window between the close and free
   * where we can't register a new circuit for the same intro point. */
  if (circ->hs_token) {
    hs_circuitmap_remove_circuit(circ);
  }
}
