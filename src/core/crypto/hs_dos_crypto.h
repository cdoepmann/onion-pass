/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file hs_dos_crypto.h
 * @brief Header for core/crypto/hs_dos_crypto.c
 **/

#ifndef TOR_CORE_CRYPTO_HS_DOS_CRYPTO_H
#define TOR_CORE_CRYPTO_HS_DOS_CRYPTO_H

#include "core/or/or.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <time.h>
#include "lib/ctime/di_ops.h"
#include "lib/crypt_ops/crypto_ed25519.h"

/* For now we use NIST P256 as the elliptic curve
 * THIS CURVE SHOULD LATER BE REPLACE BY CURVE25519
 * AS THE NIST CURVE MIGHT BE INSECURE */
#define HS_DOS_EC_NID NID_X9_62_prime256v1

#define HS_DOS_EC_BN_LEN 32
#define HS_DOS_EC_POINT_LEN (2*HS_DOS_EC_BN_LEN)
#define HS_DOS_PROOF_LEN (2*HS_DOS_EC_BN_LEN)
#define HS_DOS_REDEMPTION_MAC DIGEST256_LEN
#define HS_DOS_B64_BN_LEN 45
#define HS_DOS_B64_P_LEN (2*HS_DOS_B64_BN_LEN)
#define HS_DOS_B64_TOK_LEN (3*HS_DOS_B64_BN_LEN)

typedef struct hs_dos_token_t {
  uint8_t seq_num; // The sequence number of the token in the current batch
  BIGNUM *token_rn; // t
  EC_POINT *token_point; // T = H_1(t)
  BIGNUM *blinding_factor; // r
  BIGNUM *unblinding_factor; // r^(-1)
  EC_POINT *blind_token; // M
  EC_POINT *oprf_out_blind_token; // Z = kM
  EC_POINT *signed_token; // N = r^(-1)*Z
  BIGNUM *nonce;
  EC_POINT *A; // A = nonce*X
  EC_POINT *B; // B = nonce*M
} hs_dos_token_t;

typedef struct hs_dos_sig_token_t {
  uint8_t seq_num; // The sequence number of the token in the current batch
  EC_POINT *blind_token; // M
  EC_POINT *oprf_out_blind_token; // Z = kM
} hs_dos_sig_token_t;

/* Used by the client to to store tokens. */
typedef struct hs_dos_storable_token_t {
  BIGNUM *token_rn; // t
  EC_POINT *signature; // N = r^(-1)*Z
} hs_dos_storable_token_t;

/* Can be used by the client to hold spendable tokens
 * or tokens for which a signature has been requested. */
typedef struct hs_dos_token_batch_t {
  time_t creation_time;
  ed25519_public_key_t identity_pk;
  EC_POINT *dleq_pk;
  smartlist_t *storable_tokens;
} hs_dos_token_batch_t;

typedef struct hs_dos_proof_t {
  BIGNUM *c; // c = H_3(X, Y, M, Z, A, B)
  BIGNUM *s; // s = (t -ck) % order
} hs_dos_proof_t;

typedef struct hs_dos_handler_t {
  EC_KEY *hs_dos_oprf_key; // holds k and Y=kX
  digest256map_t *spent_tokens; // map of signed tokens. efficiency? space?
  time_t creation_time; // needs to be set correctly
} hs_dos_handler_t;

// Memory allocation and de-allocation for structs

hs_dos_token_t *hs_dos_token_t_new(void);
void hs_dos_token_t_free(hs_dos_token_t *t);
hs_dos_sig_token_t *hs_dos_sig_token_t_new(void);
void hs_dos_sig_token_t_free(hs_dos_sig_token_t *t);
hs_dos_proof_t *hs_dos_proof_t_new(void);
void hs_dos_proof_t_free(hs_dos_proof_t *p);
hs_dos_token_t **hs_dos_tokens_new(int batch_size);
void hs_dos_tokens_free(hs_dos_token_t **t, int batch_size);
hs_dos_sig_token_t **hs_dos_sig_tokens_new(int batch_size);
void hs_dos_sig_tokens_free(hs_dos_sig_token_t **t, int batch_size);
hs_dos_handler_t *hs_dos_handler_t_new(void);
void hs_dos_handler_t_free(hs_dos_handler_t *h);
hs_dos_storable_token_t *hs_dos_storable_token_t_new(void);
hs_dos_storable_token_t *hs_dos_get_storable_token(const hs_dos_token_t *tok);
void hs_dos_storable_token_t_free(hs_dos_storable_token_t *tok);
hs_dos_token_batch_t *hs_dos_token_batch_t_new(
                                const ed25519_public_key_t identity_pk,
                                const EC_POINT *dleq_pk);
void hs_dos_token_storable_batch_t_free(hs_dos_token_batch_t *batch);

// The high level functions:

int hs_dos_init_curve(void);
int hs_dos_terminate_curve(void);
int hs_dos_prepare_n_tokens(hs_dos_token_t **token, int batch_size);
int hs_dos_sign_n_tokens(hs_dos_proof_t *proof, hs_dos_sig_token_t **token, int batch_size, const hs_dos_handler_t *handler);
int hs_dos_set_oprfkey_n_tokens(hs_dos_token_t **token, const EC_POINT **oprf_sig, int batch_size);
int hs_dos_set_n_blind_tokens(hs_dos_sig_token_t **token, const EC_POINT **blind_token, int batch_size); //needed -> better refactor code!
int hs_dos_prepare_redemption(char *redemption_hmac, const BIGNUM *t_rn, const EC_POINT *signature, const char *data, size_t data_len);
int hs_dos_redeem_token(const char *redemption_hmac, const BIGNUM *t_rn, const char *data, size_t data_len, hs_dos_handler_t *handler);
int hs_dos_verify_and_unblind_tokens(const hs_dos_proof_t *rcv_proof, hs_dos_token_t **token, const EC_POINT *hs_pub_oprf_key, int batch_size);
int hs_dos_get_descriptor_points(EC_POINT *pub_key, EC_POINT *base_point, const hs_dos_handler_t *handler);
const EC_GROUP *hs_dos_get_group(void);
const BIGNUM *hs_dos_get_order(void);
const EC_POINT *hs_dos_get_generator(void);
// char *hs_dos_get_storable_tokens(const hs_dos_token_t **token, int batch_size);

// Helper functions -- DECIDE what to list in header file?

int hs_dos_b64_encode_bn(char *b64_bn, const BIGNUM *bn);
int hs_dos_b64_decode_bn(BIGNUM *bn, const char *b64_bn);
int hs_dos_b64_encode_point(char *b64_p, const EC_POINT *p);
int hs_dos_b64_decode_point(EC_POINT *p, const char *b64_p);
int hs_dos_b64_encode_token(char *b64_t, const hs_dos_storable_token_t *t);
int hs_dos_b64_decode_token(hs_dos_storable_token_t *t, const char *b64_t);
int hs_dos_encode_bn(unsigned char *bytes, const BIGNUM *bn);
int hs_dos_decode_bn(BIGNUM *bn, const unsigned char *bn_bin);
int hs_dos_encode_ec_point(unsigned char *bytes, const EC_POINT *point);
int hs_dos_decode_ec_point(EC_POINT *point, const unsigned char *point_bin);
int hs_dos_encode_proof(unsigned char *bytes, const hs_dos_proof_t *proof);
int hs_dos_decode_proof(hs_dos_proof_t *proof, const unsigned char *bytes);

int hash_to_curve(EC_POINT *curve_point, const BIGNUM *token_rn);
int hs_dos_validate_point(const EC_POINT *p);
int hs_dos_ec_mul(EC_POINT *result, const EC_POINT *base, const BIGNUM *scalar);
int hs_dos_rand_mod_order(BIGNUM *n);
int hs_dos_points_cmp(const EC_POINT *a, const EC_POINT *b);
EC_KEY *hs_dos_generate_keypair(void);
int hs_dos_verify_batch_proof(const hs_dos_proof_t *rcv_proof, const hs_dos_token_t **token, const EC_POINT *hs_pub_oprf_key, int batch_size);
int hs_dos_unblind_n_tokens(hs_dos_token_t **token, int batch_size);
int hs_dos_generate_token(hs_dos_token_t *token);
int hs_dos_blind_token(hs_dos_token_t *token);
int hs_dos_compute_oprf(hs_dos_sig_token_t *token, const hs_dos_handler_t *handler);
int hs_dos_unblind_token(hs_dos_token_t *token);
int hs_dos_compute_shared_key(char *shared_key, const BIGNUM *t_rn, const EC_POINT *signature);
void hs_dos_compute_req_hmac(char *hmac_proof, const char *shared_key, const char *data, size_t data_len);
int hs_dos_verify_digest_len_256(const char *a, const char *b);
int hs_dos_compute_dleq_proof(hs_dos_proof_t *proof, hs_dos_token_t *token, const EC_POINT *hs_pub_key, const hs_dos_handler_t *handler);
int hs_dos_compute_batch_proof(hs_dos_proof_t *proof, const hs_dos_sig_token_t **token, int batch_size, const hs_dos_handler_t *handler);
int hs_dos_add_spent_token(const BIGNUM *t_rn, hs_dos_handler_t *handler);
int hs_dos_is_token_spent(const BIGNUM *t_rn, hs_dos_handler_t *handler);
int hs_dos_check_and_spend_token(const BIGNUM *t_rn, hs_dos_handler_t *handler);

#endif /* !defined(TOR_CORE_CRYPTO_HS_DOS_CRYPTO_H) */
