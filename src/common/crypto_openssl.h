/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_openssl.h
 *
 * \brief Headers for crypto_openssl.c
 **/

#ifndef TOR_CRYPTO_OPENSSL_H
#define TOR_CRYPTO_OPENSSL_H

#include <stdio.h>
#include "util.h"

#include <openssl/engine.h>

DISABLE_GCC_WARNING(redundant-decls)

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/conf.h>
#include <openssl/hmac.h>

ENABLE_GCC_WARNING(redundant-decls)

/*
  Macro to create an arbitrary OpenSSL version number as used by
  OPENSSL_VERSION_NUMBER or SSLeay(), since the actual numbers are a bit hard
  to read.

  Don't use this directly, instead use one of the other OPENSSL_V macros
  below.

  The format is: 4 bits major, 8 bits minor, 8 bits fix, 8 bits patch, 4 bit
  status.
 */
#define OPENSSL_VER(a,b,c,d,e)                                \
  (((a)<<28) |                                                \
   ((b)<<20) |                                                \
   ((c)<<12) |                                                \
   ((d)<< 4) |                                                \
    (e))
/** An openssl release number.  For example, OPENSSL_V(0,9,8,'j') is the
 * version for the released version of 0.9.8j */
#define OPENSSL_V(a,b,c,d) \
  OPENSSL_VER((a),(b),(c),(d)-'a'+1,0xf)
/** An openssl release number for the first release in the series.  For
 * example, OPENSSL_V_NOPATCH(1,0,0) is the first released version of OpenSSL
 * 1.0.0. */
#define OPENSSL_V_NOPATCH(a,b,c) \
  OPENSSL_VER((a),(b),(c),0,0xf)
/** The first version that would occur for any alpha or beta in an openssl
 * series. For example, OPENSSL_V_SERIES(0,9,8) is greater than any released
 * 0.9.7, and less than any released 0.9.8. */
#define OPENSSL_V_SERIES(a,b,c) \
  OPENSSL_VER((a),(b),(c),0,0)

#ifdef ANDROID
/* Android's OpenSSL seems to have removed all of its Engine support. */
#define DISABLE_ENGINES
#endif

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VER(1,1,0,0,5) && \
  !defined(LIBRESSL_VERSION_NUMBER)
/* OpenSSL as of 1.1.0pre4 has an "new" thread API, which doesn't require
 * seting up various callbacks.
 *
 * OpenSSL 1.1.0pre4 has a messed up `ERR_remove_thread_state()` prototype,
 * while the previous one was restored in pre5, and the function made a no-op
 * (along with a deprecated annotation, which produces a compiler warning).
 *
 * While it is possible to support all three versions of the thread API,
 * a version that existed only for one snapshot pre-release is kind of
 * pointless, so let's not.
 */
#define NEW_THREAD_API
#endif /* OPENSSL_VERSION_NUMBER >= OPENSSL_VER(1,1,0,0,5) && ... */

tor_mutex_t **openssl_mutexes_;
int n_openssl_mutexes_;

/* global openssl state */
const char * crypto_openssl_get_version_str(void);
const char * crypto_openssl_get_header_version_str(void);

/* generics OpenSSL functions */
char * parse_openssl_version_str(const char *raw_version);
void openssl_locking_cb_(int mode, int n, const char *file, int line);
void tor_set_openssl_thread_id(CRYPTO_THREADID *threadid);

/* OpenSSL threading setup function */
int setup_openssl_threading(void);

/* Tor OpenSSL utility functions */
void free_openssl(void);

#endif /* !defined(TOR_CRYPTO_OPENSSL_H) */

