/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file hs_dos_crypto.c
 * @brief DOCDOC
 **/

#include "core/or/or.h"
#include "orconfig.h"
#include "lib/malloc/malloc.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/ctime/di_ops.h"
#include "lib/log/util_bug.h"
#include "lib/defs/digest_sizes.h"
#include "lib/encoding/binascii.h"
#include "lib/crypt_ops/crypto_ed25519.h"

#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#include "core/crypto/hs_dos_crypto.h"

/* This is taken from Privacy Pass. May be changed. */
#define HS_DOS_SK_HMAC_TAG "hash_derive_key"
#define HS_DOS_SK_HMAC_TAG_LEN strlen(HS_DOS_SK_HMAC_TAG)
#define HS_DOS_REQ_TAG "hash_request_binding"
#define HS_DOS_REQ_TAG_LEN strlen(HS_DOS_REQ_TAG)
#define HS_DOS_SSWU_H2C_LABEL "H2C-P256-SHA256-SSWU-"
#define HS_DOS_SSWU_H2C_LABEL_LEN strlen(HS_DOS_SSWU_H2C_LABEL)

/* This controls which hash_to_curve implementation is used. */
#define HS_DOS_USE_SSWU 1

/** Boolean: has our crypto library been initialized? */
static int hs_dos_crypto_initialized_ = 0;

/** A little hack before implementing proper lists */
static int HS_DOS_IS_MEMBER = 1;

/** TODO: Declare elsewhere? Check scope? */
BN_CTX *hs_dos_bn_ctx = NULL;
EC_GROUP *hs_dos_ec = NULL; // GG
const EC_POINT *hs_dos_ec_generator = NULL; // X
const BIGNUM *hs_dos_ec_order = NULL;
BIGNUM *hs_dos_field_prime = NULL;
BIGNUM *hs_dos_field_a = NULL;
BIGNUM *hs_dos_field_b = NULL;
BIGNUM *hs_dos_bDivA = NULL;
BIGNUM *hs_dos_pPlus1Div4 = NULL;


/* Create a new token batch and initialize all values.
 * Only actual tokens have to be added to sl later. */
hs_dos_token_batch_t *hs_dos_token_batch_t_new(
                                const ed25519_public_key_t identity_pk,
                                const EC_POINT *dleq_pk)
{
  tor_assert(dleq_pk);
  hs_dos_token_batch_t *batch = tor_malloc(sizeof(hs_dos_token_batch_t));
  time(&batch->creation_time);
  memcpy(batch->identity_pk.pubkey,
         identity_pk.pubkey,
         ED25519_PUBKEY_LEN);
  batch->dleq_pk = EC_POINT_dup(dleq_pk, hs_dos_get_group());
  tor_assert(batch->dleq_pk);
  batch->storable_tokens = smartlist_new();
  return batch; 
};

void hs_dos_token_storable_batch_t_free(hs_dos_token_batch_t *batch)
{
  if (batch == NULL)
    return;
  EC_POINT_free(batch->dleq_pk);
  batch->dleq_pk = NULL;
  SMARTLIST_FOREACH(batch->storable_tokens,
                    hs_dos_storable_token_t *,
                    s_tok,
                    hs_dos_storable_token_t_free(s_tok));
  smartlist_free(batch->storable_tokens);
  tor_free(batch);
  return;
};

/**
 * Allocate new handler.
 * Allocate memory for all members.
 * Create new oprf key for issuing tokens.
 * Return pointer to new allocated proof.
 **/
hs_dos_handler_t *hs_dos_handler_t_new(void)
{
  hs_dos_handler_t *h = tor_malloc(sizeof(hs_dos_handler_t));
  h->hs_dos_oprf_key = hs_dos_generate_keypair();
  h->spent_tokens = digest256map_new();
  time(&(h->creation_time));
  return h;
};

/**
 * Free handler.
 * Free memory for all members.
 **/
void hs_dos_handler_t_free(hs_dos_handler_t *h)
{
  if (h == NULL)
    return;
  EC_KEY_free(h->hs_dos_oprf_key);
  digest256map_free(h->spent_tokens, NULL);
  tor_free(h);
  return;
};

/* Get storable token from token
 * Allocates new memory. */
hs_dos_storable_token_t *hs_dos_storable_token_t_new(void)
{
  BIGNUM *t_rn = BN_new();
  tor_assert(t_rn);
  EC_POINT *signature = EC_POINT_new(hs_dos_ec);
  tor_assert(signature);
  hs_dos_storable_token_t *tok_out = tor_malloc(
                                      sizeof(hs_dos_storable_token_t));
  tok_out->signature = signature;
  tok_out->token_rn = t_rn;
  return tok_out;
};

/* Get storable token from token
 * Allocates new memory. */
hs_dos_storable_token_t *hs_dos_get_storable_token(const hs_dos_token_t *tok)
{
  tor_assert(tok);
  tor_assert(tok->token_rn);
  tor_assert(tok->signed_token);
  hs_dos_storable_token_t *tok_out = tor_malloc(sizeof(hs_dos_storable_token_t));
  tok_out->token_rn = BN_dup(tok->token_rn);
  tor_assert(tok_out->token_rn);
  tok_out->signature = EC_POINT_dup(tok->signed_token, hs_dos_ec);
  tor_assert(tok_out->signature);
  return tok_out;
};

/* Free struct and members of tok. */
void hs_dos_storable_token_t_free(hs_dos_storable_token_t *tok)
{
  if (tok == NULL)
    return;
  EC_POINT_free(tok->signature);
  tok->signature = NULL;
  BN_free(tok->token_rn);
  tok->token_rn = NULL;
  tor_free(tok);
  return;
};

/* Precomputes bDivA = -B/A and pplus1div4 = (p+1)/4 for the group we use.
 * These are needed by simplified_swu in order to hash to a curve point.
 * Return 0 on success, -1 on failure. */
static int precompute_sswu_parameters(void)
{
  int ret = -1;

  tor_assert(hs_dos_field_a);
  tor_assert(hs_dos_field_b);
  tor_assert(hs_dos_field_prime);

  if (hs_dos_pPlus1Div4){
    BN_free(hs_dos_pPlus1Div4);
  }
  hs_dos_pPlus1Div4 = BN_new();
  tor_assert(hs_dos_pPlus1Div4);
  if (hs_dos_bDivA){
    BN_free(hs_dos_bDivA);
  }
  hs_dos_bDivA = BN_new();
  tor_assert(hs_dos_bDivA);

  // bDivA = -B/A
  if(NULL == BN_mod_inverse(hs_dos_bDivA,
                            hs_dos_field_a,
                            hs_dos_field_prime,
                            hs_dos_bn_ctx)){
    goto done;
  }
  if (!BN_mul(hs_dos_bDivA, hs_dos_bDivA, hs_dos_field_b, hs_dos_bn_ctx))
    goto done;
  if (BN_is_negative(hs_dos_bDivA)){
    BN_set_negative(hs_dos_bDivA, 0);
  }
  else{
    BN_set_negative(hs_dos_bDivA, 1);
  }
  
  if (!BN_nnmod(hs_dos_bDivA, hs_dos_bDivA, hs_dos_field_prime, hs_dos_bn_ctx))
    goto done;

  // pplus1div4 = (p+1)/4
  if (!BN_one(hs_dos_pPlus1Div4))
    goto done;
	if (!BN_add(hs_dos_pPlus1Div4, hs_dos_pPlus1Div4, hs_dos_field_prime))
    goto done;
	if (!BN_rshift(hs_dos_pPlus1Div4, hs_dos_pPlus1Div4, 2))
    goto done;

  ret = 0;

  done:
    if (ret){
      if (hs_dos_pPlus1Div4){
        BN_free(hs_dos_pPlus1Div4);
        hs_dos_pPlus1Div4 = NULL;
      }
      if (hs_dos_bDivA){
        BN_free(hs_dos_bDivA);
        hs_dos_bDivA = NULL;
      }
    }
    return ret;
};

/**
 * Initialize the elliptic curve with the default library context.
 * Some of these parameters are just created for convenience.
 * Return 0 on success, -1 on failure. */
int hs_dos_init_curve(void)
{
  if (hs_dos_crypto_initialized_)
    return 0;
  if(NULL == (hs_dos_ec = EC_GROUP_new_by_curve_name(HS_DOS_EC_NID)))
    return -1;
  if(NULL == (hs_dos_bn_ctx = BN_CTX_new()))
    return -1;
  if(NULL == (hs_dos_ec_order = EC_GROUP_get0_order(hs_dos_ec)))
    return -1;
  if(NULL == (hs_dos_ec_generator = EC_GROUP_get0_generator(hs_dos_ec)))
    return -1;
  if (hs_dos_field_prime)
    BN_free(hs_dos_field_prime);
  hs_dos_field_prime = BN_new();
  tor_assert(hs_dos_field_prime);
  if (hs_dos_field_a)
    BN_free(hs_dos_field_a);
  hs_dos_field_a = BN_new();
  tor_assert(hs_dos_field_a);
  if (hs_dos_field_b)
    BN_free(hs_dos_field_b);
  hs_dos_field_b = BN_new();
  tor_assert(hs_dos_field_b);
  if (!EC_GROUP_get_curve_GFp(hs_dos_ec,
                              hs_dos_field_prime,
                              hs_dos_field_a,
                              hs_dos_field_b,
                              hs_dos_bn_ctx)){
    return -1;
  }
  if (HS_DOS_USE_SSWU){
    precompute_sswu_parameters();
  }
  hs_dos_crypto_initialized_ = 1;
  return 0; 
};

/**
 * Initialize the elliptic curve with the default library context.
 * Some of these parameters are just created for convenience.
 * Return 0 on success, -1 on failure. */
int hs_dos_terminate_curve(void)
{
  if (hs_dos_crypto_initialized_){
    hs_dos_crypto_initialized_ = 0;
  }
  else{
    return 0;
  }
  if(hs_dos_ec){
    EC_GROUP_free(hs_dos_ec);
    hs_dos_ec = NULL;
    hs_dos_ec_order = NULL;
    hs_dos_ec_generator = NULL;
  }
  if(hs_dos_bn_ctx){
    BN_CTX_free(hs_dos_bn_ctx);
    hs_dos_bn_ctx = NULL;
  }
  if (hs_dos_field_prime){
    BN_free(hs_dos_field_prime);
    hs_dos_field_prime = NULL;
  }
  if (hs_dos_field_a){
    BN_free(hs_dos_field_a);
    hs_dos_field_a = NULL;
  }
  if (hs_dos_field_b){
    BN_free(hs_dos_field_b);
    hs_dos_field_b = NULL;
  }
  if (hs_dos_bDivA){
    BN_free(hs_dos_bDivA);
    hs_dos_bDivA = NULL;
  }
  if (hs_dos_pPlus1Div4){
    BN_free(hs_dos_pPlus1Div4);
    hs_dos_pPlus1Div4 = NULL;
  }
  return 0; 
};

/**
 * Allocate new token.
 * Allocate memory for all members.
 * Return pointer to new allocated token.
 **/
hs_dos_token_t *hs_dos_token_t_new(void)
{
  hs_dos_token_t *t = tor_malloc(sizeof(hs_dos_token_t));
  t->A = EC_POINT_new(hs_dos_ec);
  tor_assert(t->A);
  t->B = EC_POINT_new(hs_dos_ec);
  tor_assert(t->B);
  t->blind_token = EC_POINT_new(hs_dos_ec);
  tor_assert(t->blind_token);
  t->blinding_factor = BN_new();
  tor_assert(t->blinding_factor);
  t->nonce = BN_new();
  tor_assert(t->nonce);
  t->oprf_out_blind_token = EC_POINT_new(hs_dos_ec);
  tor_assert(t->oprf_out_blind_token);
  t->token_rn = BN_new();
  tor_assert(t->token_rn);
  t->token_point = EC_POINT_new(hs_dos_ec);
  tor_assert(t->token_point);
  t->signed_token = EC_POINT_new(hs_dos_ec);
  tor_assert(t->signed_token);
  t->unblinding_factor = BN_new();
  tor_assert(t->unblinding_factor);
  return t;
};

/**
 * Free token.
 * Free memory for all members.
 **/
void hs_dos_token_t_free(hs_dos_token_t *t)
{
  if (t == NULL)
    return;
  EC_POINT_free(t->A);
  EC_POINT_free(t->B);
  EC_POINT_free(t->blind_token);
  BN_free(t->blinding_factor);
  BN_free(t->nonce);
  EC_POINT_free(t->oprf_out_blind_token);
  EC_POINT_free(t->token_point);
  BN_free(t->token_rn);
  EC_POINT_free(t->signed_token);
  BN_free(t->unblinding_factor);
  tor_free(t);
  return;
};

/**
 * Allocate new signature token used only by the hs to save memory.
 * Allocate memory for all members.
 * Return pointer to new allocated tokens.
 **/
hs_dos_sig_token_t *hs_dos_sig_token_t_new(void)
{
  hs_dos_sig_token_t *t = tor_malloc(sizeof(hs_dos_sig_token_t));
  t->blind_token = EC_POINT_new(hs_dos_ec);
  tor_assert(t->blind_token);
  t->oprf_out_blind_token = EC_POINT_new(hs_dos_ec);
  tor_assert(t->oprf_out_blind_token);
  return t;
}

/**
 * Free signature token.
 * Free memory for all members.
 **/
void hs_dos_sig_token_t_free(hs_dos_sig_token_t *t)
{
  if (t == NULL)
    return;
  if (t->blind_token){
    EC_POINT_free(t->blind_token);
    t->blind_token = NULL;
  }
  if (t->oprf_out_blind_token){
    EC_POINT_free(t->oprf_out_blind_token);
    t->oprf_out_blind_token = NULL;
  }
  tor_free(t);
  return;
};

/**
 * Allocate batch_size new signature tokens.
 * Allocate memory for all members.
 * Return pointer to new allocated tokens.
 **/
hs_dos_sig_token_t **hs_dos_sig_tokens_new(int batch_size)
{
  hs_dos_sig_token_t **token = tor_malloc(sizeof(hs_dos_sig_token_t*)*batch_size);
  for (int i=0; i< batch_size; i++){
    token[i] = hs_dos_sig_token_t_new();
  }
  return token;
};

/**
 * Free batch_size signature tokens.
 * Free memory for all members.
 **/
void hs_dos_sig_tokens_free(hs_dos_sig_token_t **t, int batch_size)
{
  if (t == NULL)
    return;
  for (int i=0; i< batch_size; i++){
    hs_dos_sig_token_t_free(t[i]);
  }
  tor_free(t);
  return;
};

/**
 * Allocate batch_size new tokens.
 * Allocate memory for all members.
 * Return pointer to new allocated tokens.
 **/
hs_dos_token_t **hs_dos_tokens_new(int batch_size)
{
  hs_dos_token_t **token = tor_malloc(sizeof(hs_dos_token_t*)*batch_size);
  for (int i=0; i< batch_size; i++){
    token[i] = hs_dos_token_t_new();
  }
  return token;
};

/**
 * Free batch_size tokens.
 * Free memory for all members.
 **/
void hs_dos_tokens_free(hs_dos_token_t **t, int batch_size)
{
  if (t == NULL)
    return;
  for (int i=0; i< batch_size; i++){
    hs_dos_token_t_free(t[i]);
  }
  tor_free(t);
  return;
};

/**
 * Allocate new proof.
 * Allocate memory for all members.
 * Return pointer to new allocated proof.
 **/
hs_dos_proof_t *hs_dos_proof_t_new(void)
{
  hs_dos_proof_t *p = tor_malloc(sizeof(hs_dos_proof_t));
  p->c = BN_new();
  tor_assert(p->c);
  p->s = BN_new();
  tor_assert(p->s);
  return p;
};

/**
 * Free proof.
 * Free memory for all members.
 **/
void hs_dos_proof_t_free(hs_dos_proof_t *p)
{
  if (p == NULL)
    return;
  if (p->c){
    BN_free(p->c);
    p->c = NULL;
  }
  if (p->s){
    BN_free(p->s);
    p->s = NULL;
  }
  tor_free(p);
  return;
};

/**
 * Validate EC_POINT.
 * Neutral element is not considered valid.
 * Return 0 if point is valid, 1 if not, -1 on error. */
int hs_dos_validate_point(const EC_POINT *p)
{
  int on_curve = -1;
  tor_assert(p);
  on_curve = EC_POINT_is_on_curve(hs_dos_ec, p, hs_dos_bn_ctx);
  if (on_curve == 1){
    /* Do not accept neutral element! */
    if (EC_POINT_is_at_infinity(hs_dos_ec, p))
      return 1;
    return 0;
  }
  else if (on_curve == 0){
    return 1;
  }
  else{
    return -1;
  }
};

/**
 * Compute scalar multiplication of scalar*base.
 * If base==NULL, use default generator of the group.
 * Store in result.
 * Return 0 on success, -1 on failure.*/
int hs_dos_ec_mul(EC_POINT *result, const EC_POINT *base, const BIGNUM *scalar)
{
  if (!base){
    if (!EC_POINT_mul(hs_dos_ec, result, scalar, NULL, NULL, hs_dos_bn_ctx))
      return -1;
  }
  else
  {
    if (!EC_POINT_mul(hs_dos_ec, result, NULL, base, scalar, hs_dos_bn_ctx))
      return -1;
  }
  return 0;
};

/**
 * Generate random number modulo the the EC order.
 * Store in n.
 * Return 0 on success, -1 on failure.*/
int hs_dos_rand_mod_order(BIGNUM *n)
{
  if (BN_rand_range(n, hs_dos_ec_order))
    return 0;
  return -1;
};

/**
 * Create a new keypair in *<b>keypair_out</b>.
 * Return pointer. */
EC_KEY *hs_dos_generate_keypair(void)
{ 
  EC_KEY *key = EC_KEY_new_by_curve_name(HS_DOS_EC_NID);
  tor_assert(key);
  if(!EC_KEY_generate_key(key)){
    EC_KEY_free(key);
    key = NULL;
    tor_assert(key);
  }
  return key;
};

/* Compute the SHA256 hash of token_rn including labels.
   Compute the result modulo prime.
 * Store the resulting BIGNUM in u.
 * Return 0 on success, -1 on failure. */
static int hash_to_base(BIGNUM *u, const BIGNUM *token_rn, const BIGNUM *prime)
{
  int ret = -1;
  char digest_out[DIGEST256_LEN];
  unsigned char data[HS_DOS_EC_BN_LEN];
  crypto_digest_t *hash;
  
  tor_assert(token_rn);
  tor_assert(u);
  
  hash = crypto_digest256_new(DIGEST_SHA256);

  crypto_digest_add_bytes(hash, "h2b", strlen("h2b"));
  crypto_digest_add_bytes(hash,
                          HS_DOS_SSWU_H2C_LABEL,
                          HS_DOS_SSWU_H2C_LABEL_LEN);
  /* Add data length? */
  if (hs_dos_encode_bn(data, token_rn))
    goto done;
  crypto_digest_add_bytes(hash, (const char*) data, HS_DOS_EC_BN_LEN);
  crypto_digest_get_digest(hash, digest_out, DIGEST256_LEN);

  if (NULL == BN_bin2bn((const unsigned char*) digest_out,
                        HS_DOS_EC_BN_LEN,
                        u)){
    goto done;
  }

  if (!BN_nnmod(u, u, prime, hs_dos_bn_ctx))
    goto done;
  /* Success */
  ret = 0;

  done:
    crypto_digest_free(hash);
    return ret;
};

/* Compute simplified swu coordinates and store in result
 * Return 0 on success, -1 on failure. */
static int simplified_swu(EC_POINT *result, const BIGNUM *t)
{
  int ret = -1;
	BIGNUM *u, *t0, *y2, *bDivA, *g, *pPlus1Div4, *x, *y;
  const BIGNUM *p, *A, *B;

  tor_assert(t);

  u = BN_new();
  tor_assert(u);
  t0 = BN_new();
  tor_assert(t0);
  y2 = BN_new();
  tor_assert(y2);
  bDivA = hs_dos_bDivA;
  tor_assert(bDivA);
  g = BN_new();
  tor_assert(g);
  pPlus1Div4 = hs_dos_pPlus1Div4;
  tor_assert(pPlus1Div4);
  x = BN_new();
  tor_assert(x);
  y = BN_new();
  tor_assert(y);
  p = hs_dos_field_prime;
  tor_assert(p);
  A = hs_dos_field_a;
  tor_assert(A);
  B = hs_dos_field_b;
  tor_assert(B);

  /* Actual calculation of the coordinates */

	// u = -t^2
  if (!BN_mul(u, t, t, hs_dos_bn_ctx))
    goto done;
  if (BN_is_negative(u)){
    BN_set_negative(u, 0);
  }
  else{
    BN_set_negative(u, 1);
  }
  if (!BN_nnmod(u, u, p, hs_dos_bn_ctx))
    goto done;

	// t0 = 1/(u^2+u)
  if (!BN_mul(t0, u, u, hs_dos_bn_ctx))
    goto done;
  if (!BN_mod_add(t0, t0, u, p, hs_dos_bn_ctx))
    goto done;

	// if t is {0,1,-1} returns error (point at infinity)
	if (BN_is_zero(t0)) {
		goto done;
	}
  if(NULL == BN_mod_inverse(t0, t0, p, hs_dos_bn_ctx))
    goto done;

	// x = (-B/A)*( 1+1/(u^2+u) ) = bDivA*(1+t0)
  if (!BN_one(x))
    goto done;
  if (!BN_add(x, x, t0))
    goto done;
  if (!BN_mod_mul(x, x, bDivA, p, hs_dos_bn_ctx))
    goto done;

	// g = (x^2+A)*x+B
  if (!BN_mod_mul(g, x, x, p, hs_dos_bn_ctx))
    goto done;
  if (!BN_add(g, g, A))
    goto done;
	if (!BN_mod_mul(g, g, x, p, hs_dos_bn_ctx))
    goto done;
  if (!BN_mod_add(g, g, B, p, hs_dos_bn_ctx))
    goto done;

	// y = g^((p+1)/4)
  if (!BN_mod_exp(y, g, pPlus1Div4, p, hs_dos_bn_ctx))
    goto done;

	// if y^2 != g, then x = -t^2*x and y = (-1)^{(p+1)/4}*t^3*y
  if (!BN_mod_mul(y2, y, y, p, hs_dos_bn_ctx))
    goto done;
  if (BN_cmp(y2, g) != 0){
		// x = -t^2*x
    if (!BN_mod_mul(x, x, u, p, hs_dos_bn_ctx))
      goto done;
		// y = t^3*y
    if (!BN_mod_mul(y, y, u, p, hs_dos_bn_ctx))
      goto done;
    if (BN_is_negative(y)){
      BN_set_negative(y, 0);
    }
    else{
      BN_set_negative(y, 1);
    }
		if (!BN_mod_mul(y, y, t, p, hs_dos_bn_ctx))
      goto done;
  }

  /* TODO we should only touch result in case we are succesful */
  if (!EC_POINT_set_affine_coordinates(hs_dos_ec, result, x, y, hs_dos_bn_ctx))
    goto done;
  
  /* Validation of the resulting point */
  ret = hs_dos_validate_point(result);

  done:
    /* Free everything */
	  BN_free(u);
    BN_free(t0);
    BN_free(y2);
    BN_free(g);
    BN_free(x);
    BN_free(y);
    return ret;
};

/* Hashes the given token_rn to a curve_point as specified in
 * draft-irtf-cfrg-hash-to-curve.txt
 * Return 0 on success, -1 on error.
 * Might change the value of curve_point on error! */
int hash_to_curve(EC_POINT *curve_point, const BIGNUM *token_rn)
{
  int ret = -1;
  BIGNUM *u = NULL; 

  tor_assert(curve_point);
  tor_assert(token_rn);

  u = BN_new();
  tor_assert(u);

  if (HS_DOS_USE_SSWU){
    if (hash_to_base(u, token_rn, hs_dos_field_prime))
      goto done;
    if (simplified_swu(curve_point, u))
      goto done;
  }
  else{
    if (hash_to_base(u, token_rn, hs_dos_ec_order))
      goto done;    
    if (hs_dos_ec_mul(curve_point, NULL, u))
      goto done;
  }

  /* Success */
  ret = 0;
  
  done:
    BN_free(u);
    return ret;
};


/** Generate a new random token and hash it to a point on the curve.
 * 1) we generate a random number
 * and 2) HASH it to a point on the curve
 * (Elligator2 for Curve25519, simplifiedSWU for NIST-P256)
 * Return 0 on success, -1 on failure. */
int hs_dos_generate_token(hs_dos_token_t *token)
{
  tor_assert(token);
  tor_assert(token->token_rn);
  tor_assert(token->token_point);
  if (!BN_rand(token->token_rn,
               HS_DOS_EC_BN_LEN*8,
               BN_RAND_TOP_ANY,
               BN_RAND_BOTTOM_ANY)){
    return -1;
  }
  return hash_to_curve(token->token_point, token->token_rn);
};

/** 
 * --- CLIENT WRAPPER  ---
 * Create n=batch_size new random tokens.
 * Result is ready to be sent to Hidden Service.
 * Return 0 on success, -1 on failure. */
int hs_dos_prepare_n_tokens(hs_dos_token_t **token, int batch_size)
{
  for (int i=0; i< batch_size; i++){
    if(hs_dos_generate_token(token[i]))
      return -1;
    if (hs_dos_blind_token(token[i]))
      return -1;
  }
  return 0;
};

/** 
 * --- HS WRAPPER ---
 * Sign n=batch_size tokens.
 * Tokens holds an array of allocated and validated tokens
 * retrieved from a client.
 * Tokens are signed and DLEQ proof is stored in proof.
 * Result is ready to be sent to Client.
 * Return 0 on success, -1 on failure. */
int hs_dos_sign_n_tokens(hs_dos_proof_t *proof, hs_dos_sig_token_t **token, int batch_size, const hs_dos_handler_t *handler)
{
  int i;
  for (i=0; i< batch_size; i++){
    if (hs_dos_validate_point(token[i]->blind_token)){
      return -1;
    }
    if (hs_dos_compute_oprf(token[i], handler))
      return -1;
  }
  if (hs_dos_compute_batch_proof(proof, (const hs_dos_sig_token_t**) token, batch_size, handler)){
    log_warn(LD_BUG, "hs_dos -> batch proof fail\n");
    return -1;
  }
  return 0;
};

/** Generate a new blinding factor.
 * Return 0 on success, -1 on failure. */
static int hs_dos_generate_blinding_factor(hs_dos_token_t *token)
{
  if (!BN_rand_range(token->blinding_factor, hs_dos_ec_order))
    return -1;
  return 0;
};

/**
 * Blind the token Calculate the blinding factor.
 * Store everything in token.
 * Return 0 on success, negative on failure.
 **/
int hs_dos_blind_token(hs_dos_token_t *token)
{
  tor_assert(token);
  tor_assert(token->token_point);
  tor_assert(token->blind_token);

  if (hs_dos_generate_blinding_factor(token))
    return -1;
  tor_assert(token->blinding_factor);
  return hs_dos_ec_mul(token->blind_token, token->token_point, token->blinding_factor);
};

/**
 * Compute OPRF with handler->hs_dos_oprf_key as key.
 * Use token as input.
 * Store everything in token.
 * Return 0 on success, negative on failure.
 **/
int hs_dos_compute_oprf(hs_dos_sig_token_t *token, const hs_dos_handler_t *handler)
{
  return hs_dos_ec_mul(token->oprf_out_blind_token, token->blind_token, EC_KEY_get0_private_key(handler->hs_dos_oprf_key));
};

/**
 * Computes the modular inverse of the blinding factor
 * using hs_dos_ec_order.
 * Store the result in token->unblinding_factor.
 * Return 0 on success, negative on failure.
 **/
static int hs_dos_compute_unblinding_factor(hs_dos_token_t *token)
{
  if(NULL == BN_mod_inverse(token->unblinding_factor, token->blinding_factor, hs_dos_ec_order, hs_dos_bn_ctx))
    return -1;
  return 0;
};

/**
 * Sets the oprf_sig retrieved from the hs for each token.
 * Return 0 on success, negative on failure.
 **/
int hs_dos_set_oprfkey_n_tokens(hs_dos_token_t **token, const EC_POINT **oprf_sig, int batch_size)
{
  for (int i=0; i<batch_size; i++){
    tor_assert(oprf_sig[i]);
    EC_POINT_free(token[i]->oprf_out_blind_token);
    token[i]->oprf_out_blind_token = (EC_POINT*) oprf_sig[i];
  }
  return 0;
};

/**
 * Sets the blind tokens retrieved from the client.
 * Return 0 on success, negative on failure.
 **/
int hs_dos_set_n_blind_tokens(hs_dos_sig_token_t **token, const EC_POINT **blind_token, int batch_size)
{
  for (int i=0; i<batch_size; i++){
    tor_assert(blind_token[i]);
    EC_POINT_free(token[i]->blind_token);
    token[i]->blind_token = (EC_POINT*) blind_token[i];
  }
  return 0;
};

/**
 * Unblinds the signed_token.
 * Store the result in token->.
 * Return 0 on success, negative on failure.
 **/
int hs_dos_unblind_token(hs_dos_token_t *token)
{
  if (hs_dos_compute_unblinding_factor(token))
    return -1;
  return hs_dos_ec_mul(token->signed_token, token->oprf_out_blind_token, token->unblinding_factor);
};

/**
 * Unblinds the tokens.
 * Store the result in tokens.
 * Return 0 on success, negative on failure.
 * If failure, this might unblind just a part of the tokens!
 **/
int hs_dos_unblind_n_tokens(hs_dos_token_t **token, int batch_size)
{
  for (int i=0; i< batch_size; i++){
    if (hs_dos_unblind_token(token[i]))
      return -1;
  }
  return 0;
};

/**
 * Store bytes of bn in bytes (big endian).
 * bytes will be HS_DOS_EC_BN_LEN bytes (0-padded).
 * Return 0 on success, negative on failure.
 **/
int hs_dos_encode_bn(unsigned char *bytes, const BIGNUM *bn)
{
  if (BN_bn2binpad(bn, bytes, HS_DOS_EC_BN_LEN) < HS_DOS_EC_BN_LEN)
    return -1;
  return 0;
};

/**
 * Store bytes of point in bytes (big endian).
 * bytes will be HS_DOS_EC_POINT_LEN bytes.
 * x and y coordinate both 32 bytes (0-padded).
 * Return 0 on success, negative on failure.
 **/
int hs_dos_encode_ec_point(unsigned char *bytes, const EC_POINT *point)
{ 
  BIGNUM *x = BN_new(), *y = BN_new();
  tor_assert(x); tor_assert(y);
  if (!EC_POINT_get_affine_coordinates(hs_dos_ec, point, x, y, hs_dos_bn_ctx)){
    log_warn(LD_BUG, "hs_dos_encode_ec_point -> EC_POINT_get_affine_coordinates\n");
    goto fail;
  }
  if (hs_dos_encode_bn(bytes, x)){
    log_warn(LD_BUG, "hs_dos_encode_ec_point -> hs_dos_encode_bn 1\n");
    goto fail;
  }
  if (hs_dos_encode_bn(bytes+HS_DOS_EC_BN_LEN, y)){
    log_warn(LD_BUG, "hs_dos_encode_ec_point -> hs_dos_encode_bn 2\n");
    goto fail;
  }
  BN_free(x), BN_free(y);
  return 0;
  fail:
    BN_free(x), BN_free(y);
    return -1;
};

/**
 * Store bytes of proof in bytes (big endian).
 * bytes will be HS_DOS_PROOF_LEN bytes.
 * x and y coordinate both 32 bytes (0-padded).
 * Return 0 on success, negative on failure.
 **/
int hs_dos_encode_proof(unsigned char *bytes, const hs_dos_proof_t *proof)
{ 
  tor_assert(proof);
  tor_assert(bytes);

  if (hs_dos_encode_bn(bytes, proof->c)){
    log_warn(LD_BUG, "hs_dos_encode_ec_point -> hs_dos_encode_bn 1\n");
    goto fail;
  }
  if (hs_dos_encode_bn(bytes+HS_DOS_EC_BN_LEN, proof->s)){
    log_warn(LD_BUG, "hs_dos_encode_ec_point -> hs_dos_encode_bn 2\n");
    goto fail;
  }
  return 0;
  fail:
    return -1;
};

/**
 * Derive shared key from token.
 * Store DIGEST256_LEN bytes in shared_key.
 * Return 0 on success, negative on failure.
 **/
int hs_dos_compute_shared_key(char *shared_key, const BIGNUM *t_rn, const EC_POINT *signature)
{
  unsigned char msg[3*HS_DOS_EC_BN_LEN];
  if (hs_dos_encode_bn(msg, t_rn))
    return -1;
  if (hs_dos_encode_ec_point(msg+HS_DOS_EC_BN_LEN, signature))
    return -1;
  crypto_hmac_sha256(shared_key, HS_DOS_SK_HMAC_TAG, HS_DOS_SK_HMAC_TAG_LEN, (char*) msg, 3*HS_DOS_EC_BN_LEN);
  return 0;
};

/**
 * Compute HMAC_sk(tag|data). Store in hmac_proof.
 * Asserts on failure.
 **/
void hs_dos_compute_req_hmac(char *hmac_proof, const char *shared_key, const char *data, size_t data_len)
{ 
  size_t msg_len = data_len+HS_DOS_REQ_TAG_LEN;
  char *msg = tor_malloc(msg_len*sizeof(char));
  memcpy(msg, HS_DOS_REQ_TAG, HS_DOS_REQ_TAG_LEN);
  memcpy(msg+HS_DOS_REQ_TAG_LEN, data, data_len);
  crypto_hmac_sha256(hmac_proof, shared_key, DIGEST256_LEN, msg, msg_len);
  tor_free(msg);
  return;
};

/**
 * --- CLIENT WRAPPER  ---
 * Prepare a token for redemption.
 * Store DIGEST256_LEN bytes in redemption_hmac.
 * Return 0 on success, negative on failure.
 */
int hs_dos_prepare_redemption(char *redemption_hmac, const BIGNUM *t_rn, const EC_POINT *signature, const char *data, size_t data_len)
{
  char shared_key[DIGEST256_LEN];
  if (hs_dos_compute_shared_key(shared_key, t_rn, signature))
    return -1;
  hs_dos_compute_req_hmac(redemption_hmac, shared_key, data, data_len);
  return 0;
};

/**
 * --- HS WRAPPER ---
 * Redeem a token.
 * Return 0 if token is accepted, 1 if not (spent already, invalid etc),
 * -1 on error. */
int hs_dos_redeem_token(const char *redemption_hmac, const BIGNUM *t_rn, const char *data, size_t data_len, hs_dos_handler_t *handler)
{
  int ret = -1;
  EC_POINT *signature = NULL;
  EC_POINT *t_point = NULL;
  char shared_key[DIGEST256_LEN];
  char cmp_hmac[DIGEST256_LEN];

  tor_assert(redemption_hmac);
  tor_assert(t_rn);
  tor_assert(data);
  tor_assert(handler);

  int tok_spent = hs_dos_check_and_spend_token(t_rn, handler);
  if (tok_spent)
    return tok_spent;

  signature = EC_POINT_new(hs_dos_ec);
  tor_assert(signature);
  t_point = EC_POINT_new(hs_dos_ec);
  tor_assert(t_point);

  if (hash_to_curve(t_point, t_rn))
    goto done;
  if (hs_dos_ec_mul(signature, t_point, EC_KEY_get0_private_key(handler->hs_dos_oprf_key)))
    goto done;
  if (hs_dos_compute_shared_key(shared_key, t_rn, signature))
    goto done;
  hs_dos_compute_req_hmac(cmp_hmac, shared_key, data, data_len);

  ret = hs_dos_verify_digest_len_256(redemption_hmac, cmp_hmac);

  done:
    EC_POINT_free(signature), EC_POINT_free(t_point);
    return ret;
};

/**
 * Verify two Hmacs a and b of size DIGEST256_LEN.
 * Return 0 if equal, 1 otherwise.
 **/
int hs_dos_verify_digest_len_256(const char *a, const char *b)
{ 
  return !tor_memeq(a, b, DIGEST256_LEN);
};

/**
 * Compute commitment to token signing key.
 * Store in token.
 * Return 0 on success, negative on failure.
 **/
static int hs_dos_compute_commitment(hs_dos_token_t *token)
{ 
  if (!BN_rand_range(token->nonce, hs_dos_ec_order))
    return -1;
  if (hs_dos_ec_mul(token->A, NULL, token->nonce))
    return -1;
  if (hs_dos_ec_mul(token->B, token->blind_token, token->nonce))
    return -1;
  return 0;
};


/* Decode HS_DOS_EC_BN_LEN bytes from binary bn_bin to BIGNUM bn.
 * Return 0 on success, negative on failure.
 **/
int hs_dos_decode_bn(BIGNUM *bn, const unsigned char *bn_bin)
{
  tor_assert(bn);
  tor_assert(bn_bin);
  if (NULL == BN_bin2bn(bn_bin, HS_DOS_EC_BN_LEN, bn))
    return -1;
  return 0;
};


/* Decode HS_DOS_EC_POINT_LEN bytes from binary point_bin to EC_POINT point.
 * Return 0 on success, negative on failure.
 **/
int hs_dos_decode_ec_point(EC_POINT *point, const unsigned char *point_bin)
{
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();

  tor_assert(x); tor_assert(y);
  tor_assert(point);
  tor_assert(point_bin);

  if (hs_dos_decode_bn(x, point_bin))
    goto err;
  if (hs_dos_decode_bn(y, point_bin+HS_DOS_EC_BN_LEN))
    goto err;
  if (!EC_POINT_set_affine_coordinates(hs_dos_ec, point, x, y, hs_dos_bn_ctx))
    goto err;
  if (hs_dos_validate_point(point))
    goto err;
  BN_free(x); BN_free(y);
  return 0;
  err:
    BN_free(x); BN_free(y);
    return -1;
};

/* Decode HS_DOS_PROOF_LEN bytes from binary to proof.
 * Return 0 on success, negative on failure.
 **/
int hs_dos_decode_proof(hs_dos_proof_t *proof, const unsigned char *bytes)
{
  tor_assert(proof);
  tor_assert(proof->c);
  tor_assert(proof->s);
  tor_assert(bytes);
  if (hs_dos_decode_bn(proof->c, bytes))
    goto err;
  if (hs_dos_decode_bn(proof->s, bytes+HS_DOS_EC_BN_LEN))
    goto err;
  return 0;
  err:
    return -1;
};

/**
 * Compute hash of points.
 * Store in proof.
 * Return 0 on success, negative on failure.
 **/
static int hs_dos_compute_proof_c(hs_dos_proof_t *proof, const hs_dos_token_t *token, const EC_POINT *hs_pub_key)
{ 
  BIGNUM *tmp = BN_new();
  tor_assert(tmp);
  size_t msg_len = (6*2*HS_DOS_EC_BN_LEN);
  char *msg = tor_malloc(msg_len*sizeof(char));
  unsigned char *iterator = (unsigned char*) msg;
  char c[DIGEST256_LEN];
  if (hs_dos_encode_ec_point(iterator, hs_dos_ec_generator)){
    log_warn(LD_BUG, "hs_dos_compute_proof_c -> hs_dos_encode_ec_point hs_dos_ec_generator\n");
    goto fail;
  }
  iterator += 2*HS_DOS_EC_BN_LEN;
  if (hs_dos_encode_ec_point(iterator, hs_pub_key)){
    log_warn(LD_BUG, "hs_dos_compute_proof_c -> hs_dos_encode_ec_point hs_pub_key\n");
    goto fail;
  }
  iterator += 2*HS_DOS_EC_BN_LEN;
  if (hs_dos_encode_ec_point(iterator, token->blind_token)){
    log_warn(LD_BUG, "hs_dos_compute_proof_c -> hs_dos_encode_ec_point blind_token\n");
    goto fail;
  }
  iterator += 2*HS_DOS_EC_BN_LEN;
  if (hs_dos_encode_ec_point(iterator, token->oprf_out_blind_token)){
    log_warn(LD_BUG, "hs_dos_compute_proof_c -> hs_dos_encode_ec_point oprf_out_blind_token\n");
    goto fail;
  }
  iterator += 2*HS_DOS_EC_BN_LEN;
  if (hs_dos_encode_ec_point(iterator, token->A)){
    log_warn(LD_BUG, "hs_dos_compute_proof_c -> hs_dos_encode_ec_point A\n");
    goto fail;
  }
  iterator += 2*HS_DOS_EC_BN_LEN;
  if (hs_dos_encode_ec_point(iterator, token->B)){
    log_warn(LD_BUG, "hs_dos_compute_proof_c -> hs_dos_encode_ec_point B\n");
    goto fail;
  }
  if (crypto_digest256(c, msg, msg_len, DIGEST_SHA256))
    goto fail;
  //bin2bn
  if (NULL == BN_bin2bn((unsigned char*) c, HS_DOS_EC_BN_LEN, tmp))
    goto fail;
  if (!BN_nnmod(proof->c, tmp, hs_dos_ec_order, hs_dos_bn_ctx))
    goto fail;
  BN_free(tmp);
  tor_free(msg);
  return 0;
  fail:
    BN_free(tmp);
    tor_free(msg);
    return -1;
};

/**
 * Compute s for proof.
 * Store in proof.
 * Return 0 on success, negative on failure.
 **/
static int hs_dos_compute_proof_s(hs_dos_proof_t *proof, const hs_dos_token_t *token, const hs_dos_handler_t *handler)
{
  BIGNUM *ck = BN_new();
  tor_assert(ck);
  if (!BN_mod_mul(ck, proof->c, EC_KEY_get0_private_key(handler->hs_dos_oprf_key), hs_dos_ec_order, hs_dos_bn_ctx))
    goto fail;
  if (!BN_mod_sub(proof->s, token->nonce, ck, hs_dos_ec_order, hs_dos_bn_ctx))
    goto fail;
  BN_free(ck);
  return 0;
  fail:
    BN_free(ck);
    return -1;
};

/**
 * Compute DLEQ proof for token.
 * Store in proof.
 * Return 0 on success, negative on failure.
 **/
int hs_dos_compute_dleq_proof(hs_dos_proof_t *proof, hs_dos_token_t *token, const EC_POINT *hs_pub_key, const hs_dos_handler_t *handler)
{
  if (hs_dos_compute_commitment(token))
    return -1;
  if (hs_dos_compute_proof_c(proof, token, hs_pub_key))
    return -1;
  return hs_dos_compute_proof_s(proof, token, handler);
};

/**
 * Compute seed.
 * Store in seed.
 * Return 0 on success, negative on failure.
 **/
static int hs_dos_compute_batch_seed(char *seed, const EC_POINT **M, const EC_POINT **Z, const EC_POINT *hs_pub_key, int batch_size)
{
  unsigned char bytes[2*HS_DOS_EC_BN_LEN];
  crypto_digest_t *hash = crypto_digest256_new(DIGEST_SHA256);
  if (hs_dos_encode_ec_point(bytes, hs_dos_ec_generator)){
    log_warn(LD_BUG, "hs_dos_compute_batch_seed -> hs_dos_encode_ec_point 1\n");
    goto fail;
  }
  crypto_digest_add_bytes(hash, (char*) bytes, 2*HS_DOS_EC_BN_LEN);
  if (hs_dos_encode_ec_point(bytes, hs_pub_key)){
    log_warn(LD_BUG, "hs_dos_compute_batch_seed -> hs_dos_encode_ec_point 2\n");
    goto fail;
  }
  crypto_digest_add_bytes(hash, (char*) bytes, 2*HS_DOS_EC_BN_LEN);
  for (int i=0; i<batch_size; i++){
    if (hs_dos_encode_ec_point(bytes, M[i])){
      log_warn(LD_BUG, "hs_dos_compute_batch_seed -> hs_dos_encode_ec_point loop1 - M[%d]: %p\n", i, M[i]);
      goto fail;
    }
    crypto_digest_add_bytes(hash, (char*) bytes, 2*HS_DOS_EC_BN_LEN);
    if (hs_dos_encode_ec_point(bytes, Z[i])){
      log_warn(LD_BUG, "hs_dos_compute_batch_seed -> hs_dos_encode_ec_point loop2: %d\n", i);
      goto fail;
    }
    crypto_digest_add_bytes(hash, (char*) bytes, 2*HS_DOS_EC_BN_LEN);
  }
  crypto_digest_get_digest(hash, seed, DIGEST256_LEN);
  crypto_digest_free(hash);
  return 0;
  fail:
    crypto_digest_free(hash);
    return -1;
};

/**
 * Compute batch proof.
 * Store in proof.
 * Return 0 on success, negative on failure.
 **/
int hs_dos_compute_batch_proof(hs_dos_proof_t *proof, const hs_dos_sig_token_t **token, int batch_size, const hs_dos_handler_t *handler)
{
  int i;
  EC_POINT **M = tor_malloc(batch_size*sizeof(EC_POINT*));
  EC_POINT **Z = tor_malloc(batch_size*sizeof(EC_POINT*));
  BIGNUM **c = tor_malloc(batch_size*sizeof(BIGNUM*));;
  char *seed = tor_malloc(DIGEST256_LEN*sizeof(char));
  unsigned char *prng = tor_malloc(batch_size*HS_DOS_EC_BN_LEN*sizeof(unsigned char));
  BIGNUM *tmp = BN_new();
  tor_assert(tmp);
  hs_dos_token_t *meta_token = hs_dos_token_t_new();
  for (i=0; i<batch_size; i++){
    M[i] = (token[i])->blind_token;
    Z[i] = (token[i])->oprf_out_blind_token;
  }
  i = -1;
  if (hs_dos_compute_batch_seed(seed, (const EC_POINT**) M, (const EC_POINT**) Z, EC_KEY_get0_public_key(handler->hs_dos_oprf_key), batch_size)){
    log_warn(LD_BUG, "hs_dos_compute_batch_proof -> hs_dos_compute_batch_seed\n");
    goto fail;
  }
  crypto_xof((uint8_t*) prng, batch_size*HS_DOS_EC_BN_LEN, (uint8_t*) seed, DIGEST256_LEN);
  for (i=0; i<batch_size; i++){
    c[i] = BN_new();
    tor_assert(c[i]);
    if (NULL == BN_bin2bn(prng+(i*HS_DOS_EC_BN_LEN), HS_DOS_EC_BN_LEN, tmp)){
      log_warn(LD_BUG, "hs_dos_compute_batch_proof -> BN_bin2bn\n");
      goto fail;
    }
    if (!BN_nnmod(c[i], tmp, hs_dos_ec_order, hs_dos_bn_ctx)){
      log_warn(LD_BUG, "hs_dos_compute_batch_proof -> BN_nnmod\n");
      goto fail;
    }
  }
  i = batch_size-1;
  if (!EC_POINTs_mul(hs_dos_ec, meta_token->blind_token, NULL, batch_size, (const EC_POINT**) M, (const BIGNUM**) c, hs_dos_bn_ctx)){
    log_warn(LD_BUG, "hs_dos_compute_batch_proof -> EC_POINTs_mul 1\n");
    goto fail;
  }
  if (!EC_POINTs_mul(hs_dos_ec, meta_token->oprf_out_blind_token, NULL, batch_size, (const EC_POINT**) Z, (const BIGNUM**) c, hs_dos_bn_ctx)){
    log_warn(LD_BUG, "hs_dos_compute_batch_proof -> EC_POINTs_mul 2\n");
    goto fail;
  }
  if (hs_dos_compute_dleq_proof(proof, meta_token, EC_KEY_get0_public_key(handler->hs_dos_oprf_key), handler)){
    log_warn(LD_BUG, "hs_dos_compute_batch_proof -> hs_dos_compute_dleq_proof\n");
    goto fail;
  }
  hs_dos_token_t_free(meta_token);
  BN_free(tmp);
  while(i>=0){
    BN_free(c[i]);
    i--;
  }
  tor_free(seed);
  tor_free(prng);
  tor_free(M);
  tor_free(Z);
  tor_free(c);
  return 0;
  fail:
    while(i>=0){
      BN_free(c[i]);
      i--;
    }
    BN_free(tmp);
    hs_dos_token_t_free(meta_token);
    tor_free(seed);
    tor_free(prng);
    tor_free(M);
    tor_free(Z);
    tor_free(c);
    return -1;
};

/**
 * Verify batch proof.
 * Return 0 if valid, 1 if not, -1 on error.
 **/
int hs_dos_verify_batch_proof(const hs_dos_proof_t *rcv_proof, const hs_dos_token_t **token, const EC_POINT *hs_pub_oprf_key, int batch_size)
{
  int i;
  EC_POINT **M = tor_malloc(batch_size*sizeof(EC_POINT*));
  EC_POINT **Z = tor_malloc(batch_size*sizeof(EC_POINT*));
  BIGNUM **c = tor_malloc(batch_size*sizeof(BIGNUM*));;
  char *seed = tor_malloc(DIGEST256_LEN*sizeof(char));
  unsigned char *prng = tor_malloc(batch_size*HS_DOS_EC_BN_LEN*sizeof(unsigned char));
  BIGNUM *tmp = BN_new();
  tor_assert(tmp);
  hs_dos_token_t *meta_token = hs_dos_token_t_new();
  // Alllocations from here on only in verification of proof:
  hs_dos_proof_t *proof_c = hs_dos_proof_t_new();
  for (i=0; i<batch_size; i++){
    M[i] = (token[i])->blind_token;
    Z[i] = (token[i])->oprf_out_blind_token;
  }
  i = -1;
  if (hs_dos_compute_batch_seed(seed, (const EC_POINT**) M, (const EC_POINT**) Z, hs_pub_oprf_key, batch_size))
    goto fail;
  crypto_xof((uint8_t*) prng, batch_size*HS_DOS_EC_BN_LEN, (uint8_t*) seed, DIGEST256_LEN);
  for (i=0; i<batch_size; i++){
    c[i] = BN_new();
    tor_assert(c[i]);
    if (NULL == BN_bin2bn(prng+(i*HS_DOS_EC_BN_LEN), HS_DOS_EC_BN_LEN, tmp))
      goto fail;
    if (!BN_nnmod(c[i], tmp, hs_dos_ec_order, hs_dos_bn_ctx))
      goto fail;
  }
  i = batch_size-1;
  if (!EC_POINTs_mul(hs_dos_ec, meta_token->blind_token, NULL, batch_size, (const EC_POINT**) M, (const BIGNUM**) c, hs_dos_bn_ctx))
    goto fail;
  if (!EC_POINTs_mul(hs_dos_ec, meta_token->oprf_out_blind_token, NULL, batch_size, (const EC_POINT**) Z, (const BIGNUM**) c, hs_dos_bn_ctx))
    goto fail;
  if (!EC_POINT_mul(hs_dos_ec, meta_token->A, rcv_proof->s, hs_pub_oprf_key, rcv_proof->c, hs_dos_bn_ctx))
    goto fail;
  BIGNUM *B[2];
  EC_POINT *B_points[2];
  B[0] = rcv_proof->s, B[1] = rcv_proof->c;
  B_points[0] = meta_token->blind_token; B_points[1] = meta_token->oprf_out_blind_token;
  if (!EC_POINTs_mul(hs_dos_ec, meta_token->B, NULL, 2, (const EC_POINT**) B_points, (const BIGNUM**) B, hs_dos_bn_ctx))
    goto fail;
  if (hs_dos_compute_proof_c(proof_c, meta_token, hs_pub_oprf_key))
    goto fail;
  int result = BN_cmp(rcv_proof->c, proof_c->c);
  
  hs_dos_token_t_free(meta_token);
  BN_free(tmp);
  while(i>=0){
    BN_free(c[i]);
    i--;
  }
  tor_free(seed);
  tor_free(prng);
  tor_free(M);
  tor_free(Z);
  tor_free(c);
  hs_dos_proof_t_free(proof_c);
  if (result == 0)
    return 0;
  return 1;
  fail:
    while(i>=0){
      BN_free(c[i]);
      i--;
    }
    BN_free(tmp);
    hs_dos_token_t_free(meta_token);
    tor_free(seed);
    tor_free(prng);
    tor_free(M);
    tor_free(Z);
    tor_free(c);
    hs_dos_proof_t_free(proof_c);
    return -1;
}

/** 
 * --- CLIENT WRAPPER  ---
 * Verify and unblind tokens.
 * Return 0 on success, 1 if proof not valid, -1 on failure. */
int hs_dos_verify_and_unblind_tokens(const hs_dos_proof_t *rcv_proof, hs_dos_token_t **token, const EC_POINT *hs_pub_oprf_key, int batch_size)
{
  for (int i=0; i<batch_size; i++){
    /* We only check the oprf_out_blind_token
     * because we received it from server */
    if (hs_dos_validate_point(token[i]->oprf_out_blind_token)){
      return -1;
    }
  }
  int prf_invalid = hs_dos_verify_batch_proof(rcv_proof, (const hs_dos_token_t**) token, hs_pub_oprf_key, batch_size);
  if (!prf_invalid)
    return hs_dos_unblind_n_tokens(token, batch_size);
  return prf_invalid;
};

/**
 * Spend a token.
 * Avoids replay of tokens.
 * Return 0 on success, negative on failure.
 **/
int hs_dos_add_spent_token(const BIGNUM *t_rn, hs_dos_handler_t *handler)
{
  // DIGEST256_LEN == HS_DOS_EC_BN_LEN
  uint8_t key[DIGEST256_LEN];
  if (hs_dos_encode_bn((unsigned char*) key, t_rn))
    return -1;
  digest256map_set(handler->spent_tokens, key, &HS_DOS_IS_MEMBER);
  return 0;
};

/**
 * Check if a token has been spent.
 * Avoids replay of tokens.
 * Return 1 if spent, 0 if not, -1 on error.
 **/
int hs_dos_is_token_spent(const BIGNUM *t_rn, hs_dos_handler_t *handler)
{
  // DIGEST256_LEN == HS_DOS_EC_BN_LEN
  int *member = NULL;
  uint8_t key[DIGEST256_LEN];

  if (hs_dos_encode_bn((unsigned char*) key, t_rn))
    return -1;
  member = digest256map_get(handler->spent_tokens, key);
  if (member)
    return 1;
  return 0;
};

/**
 * Check if a token has been spent. Add to spend list if not.
 * Avoids replay of tokens.
 * Return 1 if spent, 0 if not (but added now), -1 on error.
 **/
int hs_dos_check_and_spend_token(const BIGNUM *t_rn, hs_dos_handler_t *handler)
{
  // DIGEST256_LEN == HS_DOS_EC_BN_LEN
  int *member = NULL;
  uint8_t key[DIGEST256_LEN];

  if (hs_dos_encode_bn((unsigned char*) key, t_rn))
    return -1;
  member = digest256map_get(handler->spent_tokens, key);;
  if (member)
    return 1;
  digest256map_set(handler->spent_tokens, key, &HS_DOS_IS_MEMBER);
  return 0;
};

/**
 * Create copies of the public key and generator in the supplied parameters.
 * Used to build hs descriptor.
 * Return 0 on success, negative on failure. */
int hs_dos_get_descriptor_points(EC_POINT *pub_key, EC_POINT *base_point, const hs_dos_handler_t *handler)
{
  if (!EC_POINT_copy(pub_key, EC_KEY_get0_public_key(handler->hs_dos_oprf_key)))
    return -1;
  if (!EC_POINT_copy(base_point, hs_dos_ec_generator))
    return -1;
  return 0;
};

/**
 * Return a pointer to currently used group.*/
const EC_GROUP *hs_dos_get_group(void)
{ 
  hs_dos_init_curve();
  tor_assert(hs_dos_ec);
  return (const EC_GROUP*) hs_dos_ec;
};

/**
 * Return a pointer to currently used generator.*/
const EC_POINT *hs_dos_get_generator(void)
{
  hs_dos_init_curve();
  tor_assert(hs_dos_ec_generator);
  return hs_dos_ec_generator;
};

/**
 * Return a pointer to order of currently used group.*/
const BIGNUM *hs_dos_get_order(void)
{
  hs_dos_init_curve();
  tor_assert(hs_dos_ec_order);
  return hs_dos_ec_order;
};

/**
 * Encode BN to base64.
 * Return number of bytes written on success, negative on failure.
 **/
int hs_dos_b64_encode_bn(char *b64_bn, const BIGNUM *bn)
{
  unsigned char b64_bytes[HS_DOS_EC_BN_LEN];
  if (hs_dos_encode_bn(b64_bytes, bn))
    return -1;
  return base64_encode(b64_bn, HS_DOS_B64_BN_LEN, (const char*) b64_bytes, HS_DOS_EC_BN_LEN, 0);
};

/**
 * Decode b64_bn to bn.
 * Return 0 on success, negative on failure. */
int hs_dos_b64_decode_bn(BIGNUM *bn, const char *b64_bn)
{
  char bn_bytes[HS_DOS_EC_BN_LEN];
  if (base64_decode(bn_bytes, HS_DOS_EC_BN_LEN, b64_bn, HS_DOS_B64_BN_LEN)<1)
    return -1;
  if (NULL == BN_bin2bn((const unsigned char*) bn_bytes, HS_DOS_EC_BN_LEN, bn))
    return -1;
  return 0;
};

/**
 * Encode EC_POINT to base64.
 * Return number of bytes written on success, negative on failure.*/
int hs_dos_b64_encode_point(char *b64_p, const EC_POINT *p)
{
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  tor_assert(x);
  tor_assert(y);
  int written_x = 0;
  int written_y = 0;
  if (!EC_POINT_get_affine_coordinates(hs_dos_ec, p, x, y, hs_dos_bn_ctx)){
    log_warn(LD_BUG, "hs_dos affine failes");
    goto fail;
  }
  written_x = hs_dos_b64_encode_bn(b64_p, x);
  if (written_x<1)
    goto fail;
  strncat(b64_p, ",", 2);
  written_x++;
  written_y = hs_dos_b64_encode_bn(b64_p+written_x, y);
  if (written_y<1)
    goto fail;
  tor_free(x);
  tor_free(y);
  return written_x+written_y;
  fail:
    tor_free(x);
    tor_free(y);
    return -1;
};

/**
 * Decode b64_p to EC_POINT.
 * Return 0 on success, negative on failure. */
int hs_dos_b64_decode_point(EC_POINT *p, const char *b64_p)
{
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  tor_assert(x);
  tor_assert(y);
  char *coordinate, *str, *tofree;
  tofree = str = tor_strdup(b64_p);
  coordinate = strsep(&str, ",");
  if (hs_dos_b64_decode_bn(x, coordinate))
    goto fail;
  coordinate = strsep(&str, ",");
  if (hs_dos_b64_decode_bn(y, coordinate))
    goto fail;
  if (!EC_POINT_set_affine_coordinates(hs_dos_ec, p, x, y, hs_dos_bn_ctx))
    goto fail;
  tor_free(x);
  tor_free(y);
  tor_free(tofree);
  return 0;
  fail:
    tor_free(x);
    tor_free(y);
    tor_free(tofree);
    return -1;
};

/**
 * Encode storable token to base64.
 * Return number of bytes written on success, negative on failure.*/
int hs_dos_b64_encode_token(char *b64_t, const hs_dos_storable_token_t *t)
{
  tor_assert(t);
  tor_assert(b64_t);
  int written_rn = 0;
  int written_sig = 0;
  written_rn = hs_dos_b64_encode_bn(b64_t, t->token_rn);
  if (written_rn<1)
    return -1;
  strncat(b64_t, ",", 2);
  written_rn++;
  written_sig = hs_dos_b64_encode_point(b64_t+written_rn, t->signature);
  if (written_sig<1)
    return -1;
  return written_sig+written_rn;
};

/**
 * Decode token stored on disk as b64_token.
 * Store in token.
 * Return 0 on success, negative on failure. */
int hs_dos_b64_decode_token(hs_dos_storable_token_t *t, const char *b64_t)
{
  tor_assert(t);
  tor_assert(b64_t);
  char *coordinate, *str, *tofree;
  tofree = str = tor_strdup(b64_t);
  coordinate = strsep(&str, ",");
  if (hs_dos_b64_decode_bn(t->token_rn, coordinate))
    goto fail;
  if (hs_dos_b64_decode_point(t->signature, str))
    goto fail;
  tor_free(tofree);
  return 0;  
  fail:
    tor_free(tofree);
    return -1;
};

/**
 * Store tokens on disk.
 * Return pointer to new allocated b64_token string, NULL on failure.
 **/
// char *hs_dos_get_storable_tokens(const hs_dos_token_t **token, int batch_size)
// {
//   tor_assert(token);
//   char *b64_tokens = tor_malloc_zero(sizeof(char)*batch_size*(HS_DOS_B64_TOK_LEN+1));
//   char *iterator = b64_tokens;
//   for (int i=0; i<batch_size; i++){
//     int bytes;
//     if ( 1 > (bytes = hs_dos_b64_encode_token(iterator, token[i]))){
//       continue; // ignore this token and try next
//     }
//     strncat(iterator, "\n", 2);
//     iterator = iterator+bytes+1;
//   }
//   if (b64_tokens == iterator){
//     log_warn(LD_BUG, "hs_dos_store_tokens -> nothing written: %p, %p", iterator, b64_tokens);
//     goto fail;
//   }
//   return b64_tokens;
//   fail:
//     tor_free(b64_tokens);
//     return NULL;
// };

/**
 * Returns 1 if the points are not equal, 0 if they are, or -1 on error.*/
int hs_dos_points_cmp(const EC_POINT *a, const EC_POINT *b)
{
  return EC_POINT_cmp(hs_dos_ec, a, b, hs_dos_bn_ctx);
};