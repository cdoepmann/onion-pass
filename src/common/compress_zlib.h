/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file compress_zlib.h
 * \brief Header for compress_zlib.c
 **/

#ifndef TOR_COMPRESS_ZLIB_H
#define TOR_COMPRESS_ZLIB_H

int tor_zlib_method_supported(void);

const char *tor_zlib_get_version_str(void);

const char *tor_zlib_get_header_version_str(void);

int tor_zlib_compress(char **out, size_t *out_len,
                      const char *in, size_t in_len,
                      compress_method_t method);

int tor_zlib_uncompress(char **out, size_t *out_len,
                        const char *in, size_t in_len,
                        compress_method_t method,
                        int complete_only,
                        int protocol_warn_level);

/** Internal state for an incremental zlib/gzip compression/decompression. */
typedef struct tor_zlib_compress_state_t tor_zlib_compress_state_t;

tor_zlib_compress_state_t *
tor_zlib_compress_new(int compress,
                      compress_method_t method,
                      compression_level_t compression_level);

tor_compress_output_t
tor_zlib_compress_process(tor_zlib_compress_state_t *state,
                          char **out, size_t *out_len,
                          const char **in, size_t *in_len,
                          int finish);

void tor_zlib_compress_free(tor_zlib_compress_state_t *state);

size_t tor_zlib_compress_state_size(const tor_zlib_compress_state_t *state);

size_t tor_zlib_get_total_allocation(void);

#endif // TOR_COMPRESS_ZLIB_H.
