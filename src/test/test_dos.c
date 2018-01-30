/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define DOS_PRIVATE
#define TOR_CHANNEL_INTERNAL_
#define CIRCUITLIST_PRIVATE

#include "or.h"
#include "dos.h"
#include "circuitlist.h"
#include "geoip.h"
#include "channel.h"
#include "test.h"
#include "log_test_helpers.h"

static unsigned int
mock_enable_dos_protection(const networkstatus_t *ns)
{
  (void) ns;
  return 1;
}

/** Test that the connection tracker of the DoS subsystem will block clients
 *  who try to establish too many connections */
static void
test_dos_conn_creation(void *arg)
{
  (void) arg;

  MOCK(get_param_cc_enabled, mock_enable_dos_protection);
  MOCK(get_param_conn_enabled, mock_enable_dos_protection);

  /* Initialize test data */
  or_connection_t or_conn;
  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(&or_conn.real_addr,
                                          "18.0.0.1"));
  tor_addr_t *addr = &or_conn.real_addr;

  /* Get DoS subsystem limits */
  dos_init();
  uint32_t max_concurrent_conns = get_param_conn_max_concurrent_count(NULL);

  /* Introduce new client */
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, addr, NULL, now);
  { /* Register many conns from this client but not enough to get it blocked */
    unsigned int i;
    for (i = 0; i < max_concurrent_conns; i++) {
      dos_new_client_conn(&or_conn);
    }
  }

  /* Check that new conns are still permitted */
  tt_int_op(DOS_CONN_DEFENSE_NONE, OP_EQ,
            dos_conn_addr_get_defense_type(addr));

  /* Register another conn and check that new conns are not allowed anymore */
  dos_new_client_conn(&or_conn);
  tt_int_op(DOS_CONN_DEFENSE_CLOSE, OP_EQ,
            dos_conn_addr_get_defense_type(addr));

  /* Close a client conn and see that a new conn will be permitted again */
  dos_close_client_conn(&or_conn);
  tt_int_op(DOS_CONN_DEFENSE_NONE, OP_EQ,
            dos_conn_addr_get_defense_type(addr));

  /* Register another conn and see that defense measures get reactivated */
  dos_new_client_conn(&or_conn);
  tt_int_op(DOS_CONN_DEFENSE_CLOSE, OP_EQ,
            dos_conn_addr_get_defense_type(addr));

 done:
  dos_free_all();
}

/** Helper mock: Place a fake IP addr for this channel in <b>addr_out</b> */
static int
mock_channel_get_addr_if_possible(channel_t *chan, tor_addr_t *addr_out)
{
  (void)chan;
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(addr_out, "18.0.0.1"));
  return 1;

 done:
  return 0;
}

/** Test that the circuit tracker of the DoS subsystem will block clients who
 *  try to establish too many circuits. */
static void
test_dos_circuit_creation(void *arg)
{
  (void) arg;
  unsigned int i;

  MOCK(get_param_cc_enabled, mock_enable_dos_protection);
  MOCK(get_param_conn_enabled, mock_enable_dos_protection);
  MOCK(channel_get_addr_if_possible,
       mock_channel_get_addr_if_possible);

  /* Initialize channels/conns/circs that will be used */
  channel_t *chan = tor_malloc_zero(sizeof(channel_t));
  channel_init(chan);
  chan->is_client = 1;

  /* Initialize test data */
  or_connection_t or_conn;
  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(&or_conn.real_addr,
                                          "18.0.0.1"));
  tor_addr_t *addr = &or_conn.real_addr;

  /* Get DoS subsystem limits */
  dos_init();
  uint32_t max_circuit_count = get_param_cc_circuit_burst(NULL);
  uint32_t min_conc_conns_for_cc =
    get_param_cc_min_concurrent_connection(NULL);

  /* Introduce new client and establish enough connections to activate the
   * circuit counting subsystem */
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, addr, NULL, now);
  for (i = 0; i < min_conc_conns_for_cc ; i++) {
    dos_new_client_conn(&or_conn);
  }

  /* Register new circuits for this client and conn, but not enough to get
   * detected as dos */
  for (i=0; i < max_circuit_count-1; i++) {
    dos_cc_new_create_cell(chan);
  }
  /* see that we didn't get detected for dosing */
  tt_int_op(DOS_CC_DEFENSE_NONE, OP_EQ, dos_cc_get_defense_type(chan));

  /* Register another CREATE cell that will push us over the limit. Check that
   * the cell gets refused. */
  dos_cc_new_create_cell(chan);
  tt_int_op(DOS_CC_DEFENSE_REFUSE_CELL, OP_EQ, dos_cc_get_defense_type(chan));

  /* TODO: Wait a few seconds before sending the cell, and check that the
     buckets got refilled properly. */
  /* TODO: Actually send a Tor cell (instead of calling the DoS function) and
   * check that it will get refused */

 done:
  tor_free(chan);
  dos_free_all();
}

/** Test that the DoS subsystem properly refills the circuit token buckets. */
static void
test_dos_bucket_refill(void *arg)
{
  (void) arg;
  int i;
  /* For this test, this variable is set to the current circ count of the token
   * bucket. */
  uint32_t current_circ_count;

  MOCK(get_param_cc_enabled, mock_enable_dos_protection);
  MOCK(get_param_conn_enabled, mock_enable_dos_protection);
  MOCK(channel_get_addr_if_possible,
       mock_channel_get_addr_if_possible);

  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  update_approx_time(now);

  /* Initialize channels/conns/circs that will be used */
  channel_t *chan = tor_malloc_zero(sizeof(channel_t));
  channel_init(chan);
  chan->is_client = 1;
  or_connection_t or_conn;
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(&or_conn.real_addr,
                                          "18.0.0.1"));
  tor_addr_t *addr = &or_conn.real_addr;

  /* Initialize DoS subsystem and get relevant limits */
  dos_init();
  uint32_t max_circuit_count = get_param_cc_circuit_burst(NULL);
  int circ_rate = tor_lround(get_circuit_rate_per_second());
  /* Check that the circuit rate is a positive number and smaller than the max
   * circuit count */
  tt_int_op(circ_rate, OP_GT, 1);
  tt_int_op(circ_rate, OP_LT, max_circuit_count);

  /* Register this client */
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, addr, NULL, now);
  dos_new_client_conn(&or_conn);

  /* Fetch this client from the geoip cache and get its DoS structs */
  clientmap_entry_t *entry = geoip_lookup_client(addr, NULL,
                                                 GEOIP_CLIENT_CONNECT);
  tt_assert(entry);
  dos_client_stats_t* dos_stats = &entry->dos_stats;
  /* Check that the circuit bucket is still uninitialized */
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, 0);

  /* Send a create cell: then check that the circ token bucket got initialized
   * and one circ was subtracted. */
  dos_cc_new_create_cell(chan);
  current_circ_count = max_circuit_count - 1;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send 29 more CREATEs and ensure that the bucket is missing 30
   * tokens */
  for (i=0; i < 29; i++) {
   dos_cc_new_create_cell(chan);
   current_circ_count--;
  }
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* OK! Progress time forward one sec, refill the bucket and check that the
   * refill happened correctly. */
  now += 1;
  update_approx_time(now);
  cc_stats_refill_bucket(&dos_stats->cc_stats, addr);
  /* check refill */
  current_circ_count += circ_rate;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send as many CREATE cells as needed to deplete our token bucket
   * completely */
  for (; current_circ_count != 0; current_circ_count--) {
   dos_cc_new_create_cell(chan);
  }
  tt_uint_op(current_circ_count, OP_EQ, 0);
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now progress time a week forward, and check that the token bucket does not
   * have more than max_circs allowance, even tho we let it simmer for so
   * long. */
  now += 604800; /* a week */
  update_approx_time(now);
  cc_stats_refill_bucket(&dos_stats->cc_stats, addr);
  current_circ_count += max_circuit_count;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

 done:
  tor_free(chan);
  dos_free_all();
}

struct testcase_t dos_tests[] = {
  { "conn_creation", test_dos_conn_creation, TT_FORK, NULL, NULL },
  { "circuit_creation", test_dos_circuit_creation, TT_FORK, NULL, NULL },
  { "bucket_refill", test_dos_bucket_refill, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

