/* Copyright (c) 2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "config.h"
#include "router.h"
#include "routerkeys.h"
#include "torcert.h"

/**
 * Read an ed25519 key and associated certificates from files beginning with
 * <b>fname</b>, with certificate type <b>cert_type</b>.  On failure, return
 * NULL; on success return the keypair.
 *
 * If INIT_ED_KEY_CREATE is set in <b>flags</b>, then create the key (and
 * certificate if requested) if it doesn't exist, and save it to disk.
 *
 * If INIT_ED_KEY_NEEDCERT is set in <b>flags</b>, load/create a certificate
 * too and store it in *<b>cert_out</b>.  Fail if the cert can't be
 * found/created.  To create a certificate, <b>signing_key</b> must be set to
 * the key that should sign it; <b>now</b> to the current time, and
 * <b>lifetime</b> to the lifetime of the key.
 *
 * If INIT_ED_KEY_REPLACE is set in <b>flags</b>, then create and save new key
 * whether we can read the old one or not.
 *
 * If INIT_ED_KEY_EXTRA_STRONG is set in <b>flags</b>, set the extra_strong
 * flag when creating the secret key.
 *
 * If INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT is set in <b>flags</b>, and
 * we create a new certificate, create it with the signing key embedded.
 *
 * If INIT_ED_KEY_SPLIT is set in <b>flags</b>, and we create a new key,
 * store the public key in a separate file from the secret key.
 *
 * If INIT_ED_KEY_MISSING_SECRET_OK is set in <b>flags</b>, and we find a
 * public key file but no secret key file, return successfully anyway.
 *
 * If INIT_ED_KEY_OMIT_SECRET is set in <b>flags</b>, do not even try to
 * load or return a secret key (but create and save on if needed).
 */
ed25519_keypair_t *
ed_key_init_from_file(const char *fname, uint32_t flags,
                      int severity,
                      const ed25519_keypair_t *signing_key,
                      time_t now,
                      time_t lifetime,
                      uint8_t cert_type,
                      struct tor_cert_st **cert_out)
{
  char *secret_fname = NULL;
  char *public_fname = NULL;
  char *cert_fname = NULL;
  int created_pk = 0, created_sk = 0, created_cert = 0;
  const int try_to_load = ! (flags & INIT_ED_KEY_REPLACE);

  char tag[8];
  tor_snprintf(tag, sizeof(tag), "type%d", (int)cert_type);

  tor_cert_t *cert = NULL;
  char *got_tag = NULL;
  ed25519_keypair_t *keypair = tor_malloc_zero(sizeof(ed25519_keypair_t));

  tor_asprintf(&secret_fname, "%s_secret_key", fname);
  tor_asprintf(&public_fname, "%s_public_key", fname);
  tor_asprintf(&cert_fname, "%s_cert", fname);

  /* Try to read the secret key. */
  const int have_secret = try_to_load &&
    !(flags & INIT_ED_KEY_OMIT_SECRET) &&
    ed25519_seckey_read_from_file(&keypair->seckey,
                                  &got_tag, secret_fname) == 0;

  if (have_secret) {
    if (strcmp(got_tag, tag)) {
      tor_log(severity, LD_OR, "%s has wrong tag", secret_fname);
      goto err;
    }
    /* Derive the public key */
    if (ed25519_public_key_generate(&keypair->pubkey, &keypair->seckey)<0) {
      tor_log(severity, LD_OR, "%s can't produce a public key", secret_fname);
      goto err;
    }
  }

  /* If it's absent and that's okay, try to read the pubkey. */
  int found_public = 0;
  if (!have_secret && try_to_load) {
    tor_free(got_tag);
    found_public = ed25519_pubkey_read_from_file(&keypair->pubkey,
                                                 &got_tag, public_fname) == 0;
    if (found_public && strcmp(got_tag, tag)) {
      tor_log(severity, LD_OR, "%s has wrong tag", public_fname);
      goto err;
    }
  }

  /* If the secret key is absent and it's not allowed to be, fail. */
  if (!have_secret && found_public && !(flags & INIT_ED_KEY_MISSING_SECRET_OK))
    goto err;

  /* If it's absent, and we're not supposed to make a new keypair, fail. */
  if (!have_secret && !found_public && !(flags & INIT_ED_KEY_CREATE))
    goto err;

  /* if it's absent, make a new keypair and save it. */
  if (!have_secret && !found_public) {
    const int split = !! (flags & INIT_ED_KEY_SPLIT);
    tor_free(keypair);
    keypair = ed_key_new(signing_key, flags, now, lifetime,
                         cert_type, &cert);
    if (!keypair) {
      tor_log(severity, LD_OR, "Couldn't create keypair");
      goto err;
    }

    created_pk = created_sk = created_cert = 1;
    if (ed25519_seckey_write_to_file(&keypair->seckey, secret_fname, tag) < 0
        ||
        (split &&
         ed25519_pubkey_write_to_file(&keypair->pubkey, public_fname, tag) < 0)
        ||
        (cert &&
         crypto_write_tagged_contents_to_file(cert_fname, "ed25519v1-cert",
                                 tag, cert->encoded, cert->encoded_len) < 0)) {
      tor_log(severity, LD_OR, "Couldn't write keys or cert to file.");
      goto err;
    }
    goto done;
  }

  /* If we're not supposed to get a cert, we're done. */
  if (! (flags & INIT_ED_KEY_NEEDCERT))
    goto done;

  /* Read a cert. */
  uint8_t certbuf[256];
  ssize_t cert_body_len = crypto_read_tagged_contents_from_file(
                 cert_fname, "ed25519v1-cert",
                 &got_tag, certbuf, sizeof(certbuf));
  if (cert_body_len >= 0 && !strcmp(got_tag, tag))
    cert = tor_cert_parse(certbuf, cert_body_len);

  /* If we got it, check it to the extent we can. */
  int bad_cert = 0;

  if (! cert) {
    tor_log(severity, LD_OR, "Cert was unparseable");
    bad_cert = 1;
  } else if (!tor_memeq(cert->signed_key.pubkey, keypair->pubkey.pubkey,
                        ED25519_PUBKEY_LEN)) {
    tor_log(severity, LD_OR, "Cert was for wrong key");
    bad_cert = 1;
  } else if (tor_cert_checksig(cert, &signing_key->pubkey, now) < 0 &&
             (signing_key || cert->cert_expired)) {
    tor_log(severity, LD_OR, "Can't check certificate");
    bad_cert = 1;
  }

  if (bad_cert) {
    tor_cert_free(cert);
    cert = NULL;
  }

  /* If we got a cert, we're done. */
  if (cert)
    goto done;

  /* If we didn't get a cert, and we're not supposed to make one, fail. */
  if (!signing_key || !(flags & INIT_ED_KEY_CREATE))
    goto err;

  /* We have keys but not a certificate, so make one. */
  uint32_t cert_flags = 0;
  if (flags & INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT)
    cert_flags |= CERT_FLAG_INCLUDE_SIGNING_KEY;
  cert = tor_cert_create(signing_key, cert_type,
                         &keypair->pubkey,
                         now, lifetime,
                         cert_flags);

  if (! cert)
    goto err;

  /* Write it to disk. */
  created_cert = 1;
  if (crypto_write_tagged_contents_to_file(cert_fname, "ed25519v1-cert",
                             tag, cert->encoded, cert->encoded_len) < 0) {
    tor_log(severity, LD_OR, "Couldn't write cert to disk.");
    goto err;
  }

 done:
  if (cert_out)
    *cert_out = cert;
  else
    tor_cert_free(cert);

  goto cleanup;

 err:
  if (keypair)
    memwipe(keypair, 0, sizeof(*keypair));
  tor_free(keypair);
  tor_cert_free(cert);
  if (cert_out)
    *cert_out = NULL;
  if (created_sk)
    unlink(secret_fname);
  if (created_pk)
    unlink(public_fname);
  if (created_cert)
    unlink(cert_fname);

 cleanup:
  tor_free(secret_fname);
  tor_free(public_fname);
  tor_free(cert_fname);
  tor_free(got_tag);

  return keypair;
}

/**
 * Create a new signing key and (optionally) certficiate; do not read or write
 * from disk.  See ed_key_init_from_file() for more information.
 */
ed25519_keypair_t *
ed_key_new(const ed25519_keypair_t *signing_key,
           uint32_t flags,
           time_t now,
           time_t lifetime,
           uint8_t cert_type,
           struct tor_cert_st **cert_out)
{
  if (cert_out)
    *cert_out = NULL;

  const int extra_strong = !! (flags & INIT_ED_KEY_EXTRA_STRONG);
  ed25519_keypair_t *keypair = tor_malloc_zero(sizeof(ed25519_keypair_t));
  if (ed25519_keypair_generate(keypair, extra_strong) < 0)
    goto err;

  if (! (flags & INIT_ED_KEY_NEEDCERT))
    return keypair;

  tor_assert(signing_key);
  tor_assert(cert_out);
  uint32_t cert_flags = 0;
  if (flags & INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT)
    cert_flags |= CERT_FLAG_INCLUDE_SIGNING_KEY;
  tor_cert_t *cert = tor_cert_create(signing_key, cert_type,
                                     &keypair->pubkey,
                                     now, lifetime,
                                     cert_flags);
  if (! cert)
    goto err;

  *cert_out = cert;
  return keypair;

 err:
  tor_free(keypair);
  return NULL;
}

static ed25519_keypair_t *master_identity_key = NULL;
static ed25519_keypair_t *master_signing_key = NULL;
static ed25519_keypair_t *current_auth_key = NULL;
static tor_cert_t *signing_key_cert = NULL;
static tor_cert_t *link_cert_cert = NULL;
static tor_cert_t *auth_key_cert = NULL;

static uint8_t *rsa_ed_crosscert = NULL;
static size_t rsa_ed_crosscert_len = 0;

/**
 * Running as a server: load, reload, or refresh our ed25519 keys and
 * certificates, creating and saving new ones as needed.
 */
int
load_ed_keys(const or_options_t *options, time_t now)
{
  ed25519_keypair_t *id = NULL;
  ed25519_keypair_t *sign = NULL;
  ed25519_keypair_t *auth = NULL;
  const ed25519_keypair_t *sign_signing_key_with_id = NULL;
  const ed25519_keypair_t *use_signing = NULL;
  const tor_cert_t *check_signing_cert = NULL;
  tor_cert_t *sign_cert = NULL;
  tor_cert_t *auth_cert = NULL;

#define FAIL(msg) do {                          \
    log_warn(LD_OR, (msg));                     \
    goto err;                                   \
  } while (0)
#define SET_KEY(key, newval) do {               \
    ed25519_keypair_free(key);                  \
    key = (newval);                             \
  } while (0)
#define SET_CERT(cert, newval) do {             \
    tor_cert_free(cert);                        \
    cert = (newval);                            \
  } while (0)
#define EXPIRES_SOON(cert, interval)            \
  (!(cert) || (cert)->valid_until < now + (interval))

  /* XXXX support encrypted identity keys fully */

  /* First try to get the signing key to see how it is. */
  if (master_signing_key) {
    check_signing_cert = signing_key_cert;
    use_signing = master_signing_key;
  } else {
    char *fname =
      options_get_datadir_fname2(options, "keys", "ed25519_signing");
    sign = ed_key_init_from_file(
               fname,
               INIT_ED_KEY_NEEDCERT|
               INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT,
               LOG_INFO,
               NULL, 0, 0, CERT_TYPE_ID_SIGNING, &sign_cert);
    tor_free(fname);
    check_signing_cert = sign_cert;
    use_signing = sign;
  }

  const int need_new_signing_key =
    NULL == use_signing ||
    EXPIRES_SOON(check_signing_cert, 0);
  const int want_new_signing_key =
    need_new_signing_key ||
    EXPIRES_SOON(check_signing_cert, options->TestingSigningKeySlop);

  {
    uint32_t flags =
      (INIT_ED_KEY_CREATE|INIT_ED_KEY_SPLIT|
       INIT_ED_KEY_EXTRA_STRONG);
    if (! need_new_signing_key)
      flags |= INIT_ED_KEY_MISSING_SECRET_OK;
    if (! want_new_signing_key)
      flags |= INIT_ED_KEY_OMIT_SECRET;

    char *fname =
      options_get_datadir_fname2(options, "keys", "ed25519_master_id");
    id = ed_key_init_from_file(
             fname,
             flags,
             LOG_WARN, NULL, 0, 0, 0, NULL);
    tor_free(fname);
    if (!id)
      FAIL("Missing identity key");
    if (tor_mem_is_zero((char*)id->seckey.seckey, sizeof(id->seckey)))
      sign_signing_key_with_id = NULL;
    else
      sign_signing_key_with_id = id;
  }

  if (need_new_signing_key && NULL == sign_signing_key_with_id)
    FAIL("Can't load master key make a new signing key.");

  if (want_new_signing_key && sign_signing_key_with_id) {
    uint32_t flags = (INIT_ED_KEY_CREATE|
                      INIT_ED_KEY_REPLACE|
                      INIT_ED_KEY_EXTRA_STRONG|
                      INIT_ED_KEY_NEEDCERT|
                      INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT);
    char *fname =
      options_get_datadir_fname2(options, "keys", "ed25519_signing");
    sign = ed_key_init_from_file(fname,
                                 flags, LOG_WARN,
                                 sign_signing_key_with_id, now,
                                 options->SigningKeyLifetime,
                                 CERT_TYPE_ID_SIGNING, &sign_cert);
    tor_free(fname);
    if (!sign)
      FAIL("Missing signing key");
    use_signing = sign;
  } else if (want_new_signing_key) {
    static ratelim_t missing_master = RATELIM_INIT(3600);
    log_fn_ratelim(&missing_master, LOG_WARN, LD_OR,
                   "Signing key will expire soon, but I can't load the "
                   "master key to sign a new one!");
  }

  tor_assert(use_signing);

  /* At this point we no longer need our secret identity key.  So wipe
   * it, if we loaded it in the first place. */
  memwipe(id->seckey.seckey, 0, sizeof(id->seckey));

  if (!rsa_ed_crosscert && server_mode(options)) {
    uint8_t *crosscert;
    ssize_t crosscert_len = tor_make_rsa_ed25519_crosscert(&id->pubkey,
                                                   get_server_identity_key(),
                                                   now+10*365*86400,/*XXXX*/
                                                   &crosscert);
    rsa_ed_crosscert_len = crosscert_len;
    rsa_ed_crosscert = crosscert;
  }

  if (!current_auth_key ||
      EXPIRES_SOON(auth_key_cert, options->TestingAuthKeySlop)) {
    auth = ed_key_new(use_signing, INIT_ED_KEY_NEEDCERT,
                      now,
                      options->TestingAuthKeyLifetime,
                      CERT_TYPE_SIGNING_AUTH, &auth_cert);

    if (!auth)
      FAIL("Can't create auth key");
  }

  /* We've generated or loaded everything.  Put them in memory. */

  if (! master_identity_key) {
    SET_KEY(master_identity_key, id);
  } else {
    tor_free(id);
  }
  if (sign) {
    SET_KEY(master_signing_key, sign);
    SET_CERT(signing_key_cert, sign_cert);
  }
  if (auth) {
    SET_KEY(current_auth_key, auth);
    SET_CERT(auth_key_cert, auth_cert);
  }

  return 0;
 err:
  ed25519_keypair_free(id);
  ed25519_keypair_free(sign);
  ed25519_keypair_free(auth);
  tor_cert_free(sign_cert);
  tor_cert_free(auth_cert);
  return -1;
}

/**DOCDOC*/
int
generate_ed_link_cert(const or_options_t *options, time_t now)
{
  const tor_x509_cert_t *link = NULL, *id = NULL;
  tor_cert_t *link_cert = NULL;

  if (tor_tls_get_my_certs(1, &link, &id) < 0 || link == NULL) {
    log_warn(LD_OR, "Can't get my x509 link cert.");
    return -1;
  }

  const digests_t *digests = tor_x509_cert_get_cert_digests(link);

  if (link_cert_cert &&
      ! EXPIRES_SOON(link_cert_cert, options->TestingLinkKeySlop) &&
      fast_memeq(digests->d[DIGEST_SHA256], link_cert_cert->signed_key.pubkey,
                 DIGEST256_LEN)) {
    return 0;
  }

  ed25519_public_key_t dummy_key;
  memcpy(dummy_key.pubkey, digests->d[DIGEST_SHA256], DIGEST256_LEN);

  link_cert = tor_cert_create(get_master_signing_keypair(),
                              CERT_TYPE_SIGNING_LINK,
                              &dummy_key,
                              now,
                              options->TestingLinkCertLifetime, 0);

  if (link_cert) {
    SET_CERT(link_cert_cert, link_cert);
  }
  return 0;
}

#undef FAIL
#undef SET_KEY
#undef SET_CERT

int
should_make_new_ed_keys(const or_options_t *options, const time_t now)
{
  if (!master_identity_key ||
      !master_signing_key ||
      !current_auth_key ||
      !link_cert_cert ||
      EXPIRES_SOON(signing_key_cert, options->TestingSigningKeySlop) ||
      EXPIRES_SOON(auth_key_cert, options->TestingAuthKeySlop) ||
      EXPIRES_SOON(link_cert_cert, options->TestingLinkKeySlop))
    return 1;

  const tor_x509_cert_t *link = NULL, *id = NULL;

  if (tor_tls_get_my_certs(1, &link, &id) < 0 || link == NULL)
    return 1;

  const digests_t *digests = tor_x509_cert_get_cert_digests(link);

  if (!fast_memeq(digests->d[DIGEST_SHA256],
                  link_cert_cert->signed_key.pubkey,
                  DIGEST256_LEN)) {
    return 1;
  }

  return 0;
}

#undef EXPIRES_SOON

const ed25519_public_key_t *
get_master_identity_key(void)
{
  if (!master_identity_key)
    return NULL;
  return &master_identity_key->pubkey;
}

const ed25519_keypair_t *
get_master_signing_keypair(void)
{
  return master_signing_key;
}

const struct tor_cert_st *
get_master_signing_key_cert(void)
{
  return signing_key_cert;
}

const ed25519_keypair_t *
get_current_auth_keypair(void)
{
  return current_auth_key;
}

const tor_cert_t *
get_current_link_cert_cert(void)
{
  return link_cert_cert;
}

const tor_cert_t *
get_current_auth_key_cert(void)
{
  return auth_key_cert;
}

void
get_master_rsa_crosscert(const uint8_t **cert_out,
                         size_t *size_out)
{
  *cert_out = rsa_ed_crosscert;
  *size_out = rsa_ed_crosscert_len;
}

/** Construct cross-certification for the master identity key with
 * the ntor onion key. Store the sign of the corresponding ed25519 public key
 * in *<b>sign_out</b>. */
tor_cert_t *
make_ntor_onion_key_crosscert(const curve25519_keypair_t *onion_key,
      const ed25519_public_key_t *master_id_key, time_t now, time_t lifetime,
      int *sign_out)
{
  tor_cert_t *cert = NULL;
  ed25519_keypair_t ed_onion_key;

  if (ed25519_keypair_from_curve25519_keypair(&ed_onion_key, sign_out,
                                              onion_key) < 0)
    goto end;

  cert = tor_cert_create(&ed_onion_key, CERT_TYPE_ONION_ID, master_id_key,
      now, lifetime, 0);

 end:
  memwipe(&ed_onion_key, 0, sizeof(ed_onion_key));
  return cert;
}

/** Construct and return an RSA signature for the TAP onion key to
 * cross-certify the RSA and Ed25519 identity keys. Set <b>len_out</b> to its
 * length. */
uint8_t *
make_tap_onion_key_crosscert(const crypto_pk_t *onion_key,
                             const ed25519_public_key_t *master_id_key,
                             const crypto_pk_t *rsa_id_key,
                             int *len_out)
{
  uint8_t signature[PK_BYTES];
  uint8_t signed_data[DIGEST_LEN + ED25519_PUBKEY_LEN];

  *len_out = 0;
  crypto_pk_get_digest(rsa_id_key, (char*)signed_data);
  memcpy(signed_data + DIGEST_LEN, master_id_key->pubkey, ED25519_PUBKEY_LEN);

  int r = crypto_pk_private_sign(onion_key,
                               (char*)signature, sizeof(signature),
                               (const char*)signed_data, sizeof(signed_data));
  if (r < 0)
    return NULL;

  *len_out = r;

  return tor_memdup(signature, r);
}

/** Check whether an RSA-TAP cross-certification is correct. Return 0 if it
 * is, -1 if it isn't. */
int
check_tap_onion_key_crosscert(const uint8_t *crosscert,
                              int crosscert_len,
                              const crypto_pk_t *onion_pkey,
                              const ed25519_public_key_t *master_id_pkey,
                              const uint8_t *rsa_id_digest)
{
  uint8_t *cc = tor_malloc(crypto_pk_keysize(onion_pkey));
  int cc_len =
    crypto_pk_public_checksig(onion_pkey,
                              (char*)cc,
                              crypto_pk_keysize(onion_pkey),
                              (const char*)crosscert,
                              crosscert_len);
  if (cc_len < 0) {
    goto err;
  }
  if (cc_len < DIGEST_LEN + ED25519_PUBKEY_LEN) {
    log_warn(LD_DIR, "Short signature on cross-certification with TAP key");
    goto err;
  }
  if (tor_memneq(cc, rsa_id_digest, DIGEST_LEN) ||
      tor_memneq(cc + DIGEST_LEN, master_id_pkey->pubkey,
                 ED25519_PUBKEY_LEN)) {
    log_warn(LD_DIR, "Incorrect cross-certification with TAP key");
    goto err;
  }

  tor_free(cc);
  return 0;
 err:
  tor_free(cc);
  return -1;
}

void
routerkeys_free_all(void)
{
  ed25519_keypair_free(master_identity_key);
  ed25519_keypair_free(master_signing_key);
  ed25519_keypair_free(current_auth_key);
  tor_cert_free(signing_key_cert);
  tor_cert_free(link_cert_cert);
  tor_cert_free(auth_key_cert);

  master_identity_key = master_signing_key = NULL;
  current_auth_key = NULL;
  signing_key_cert = link_cert_cert = auth_key_cert = NULL;
}

