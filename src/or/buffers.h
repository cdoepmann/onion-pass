/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file buffers.h
 * \brief Header file for buffers.c.
 **/

#ifndef TOR_BUFFERS_H
#define TOR_BUFFERS_H

#include "compat.h"
#include "compat.h"
#include "torint.h"
#include "testsupport.h"

typedef struct buf_t buf_t;

struct tor_tls_t;
struct tor_compress_state_t;
struct ext_or_cmd_t;

buf_t *buf_new(void);
buf_t *buf_new_with_capacity(size_t size);
size_t buf_get_default_chunk_size(const buf_t *buf);
void buf_free(buf_t *buf);
void buf_clear(buf_t *buf);
buf_t *buf_copy(const buf_t *buf);

MOCK_DECL(size_t, buf_datalen, (const buf_t *buf));
size_t buf_allocation(const buf_t *buf);
size_t buf_slack(const buf_t *buf);

uint32_t buf_get_oldest_chunk_timestamp(const buf_t *buf, uint32_t now);
size_t buf_get_total_allocation(void);

int read_to_buf(tor_socket_t s, size_t at_most, buf_t *buf, int *reached_eof,
                int *socket_error);
int read_to_buf_tls(struct tor_tls_t *tls, size_t at_most, buf_t *buf);

int flush_buf(tor_socket_t s, buf_t *buf, size_t sz, size_t *buf_flushlen);
int flush_buf_tls(struct tor_tls_t *tls, buf_t *buf, size_t sz,
                  size_t *buf_flushlen);

int write_to_buf(const char *string, size_t string_len, buf_t *buf);
int write_to_buf_compress(buf_t *buf, struct tor_compress_state_t *state,
                          const char *data, size_t data_len, int done);
int move_buf_to_buf(buf_t *buf_out, buf_t *buf_in, size_t *buf_flushlen);
void peek_from_buf(char *string, size_t string_len, const buf_t *buf);
void buf_remove_from_front(buf_t *buf, size_t n);
int fetch_from_buf(char *string, size_t string_len, buf_t *buf);
int fetch_from_buf_line(buf_t *buf, char *data_out, size_t *data_len);

#define PEEK_BUF_STARTSWITH_MAX 16
int peek_buf_startswith(const buf_t *buf, const char *cmd);

int buf_set_to_copy(buf_t **output,
                    const buf_t *input);

void assert_buf_ok(buf_t *buf);

int buf_find_string_offset(const buf_t *buf, const char *s, size_t n);
void buf_pullup(buf_t *buf, size_t bytes,
                const char **head_out, size_t *len_out);

#ifdef BUFFERS_PRIVATE
#ifdef TOR_UNIT_TESTS
buf_t *buf_new_with_data(const char *cp, size_t sz);
#endif
ATTR_UNUSED STATIC size_t preferred_chunk_size(size_t target);

#define DEBUG_CHUNK_ALLOC
/** A single chunk on a buffer. */
typedef struct chunk_t {
  struct chunk_t *next; /**< The next chunk on the buffer. */
  size_t datalen; /**< The number of bytes stored in this chunk */
  size_t memlen; /**< The number of usable bytes of storage in <b>mem</b>. */
#ifdef DEBUG_CHUNK_ALLOC
  size_t DBG_alloc;
#endif
  char *data; /**< A pointer to the first byte of data stored in <b>mem</b>. */
  uint32_t inserted_time; /**< Timestamp in truncated ms since epoch
                           * when this chunk was inserted. */
  char mem[FLEXIBLE_ARRAY_MEMBER]; /**< The actual memory used for storage in
                * this chunk. */
} chunk_t;

/** Magic value for buf_t.magic, to catch pointer errors. */
#define BUFFER_MAGIC 0xB0FFF312u
/** A resizeable buffer, optimized for reading and writing. */
struct buf_t {
  uint32_t magic; /**< Magic cookie for debugging: Must be set to
                   *   BUFFER_MAGIC. */
  size_t datalen; /**< How many bytes is this buffer holding right now? */
  size_t default_chunk_size; /**< Don't allocate any chunks smaller than
                              * this for this buffer. */
  chunk_t *head; /**< First chunk in the list, or NULL for none. */
  chunk_t *tail; /**< Last chunk in the list, or NULL for none. */
};
#endif

#endif

