/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

/* These macros pull in declarations for some functions and structures that
 * are typically file-private. */
#define GEOIP_PRIVATE
#include "or.h"
#include "config.h"
#include "geoip.h"
#include "test.h"

  /* Record odd numbered fake-IPs using ipv6, even numbered fake-IPs
   * using ipv4.  Since our fake geoip database is the same between
   * ipv4 and ipv6, we should get the same result no matter which
   * address family we pick for each IP. */
#define SET_TEST_ADDRESS(i) do {                \
    if ((i) & 1) {                              \
      SET_TEST_IPV6(i);                         \
      tor_addr_from_in6(&addr, &in6);           \
    } else {                                    \
      tor_addr_from_ipv4h(&addr, (uint32_t) i); \
    }                                           \
  } while (0)

  /* Make sure that country ID actually works. */
#define SET_TEST_IPV6(i) \
  do {                                                          \
    set_uint32(in6.s6_addr + 12, htonl((uint32_t) (i)));        \
  } while (0)
#define CHECK_COUNTRY(country, val) do {                                \
    /* test ipv4 country lookup */                                      \
    tt_str_op(country, OP_EQ,                                              \
               geoip_get_country_name(geoip_get_country_by_ipv4(val))); \
    /* test ipv6 country lookup */                                      \
    SET_TEST_IPV6(val);                                                 \
    tt_str_op(country, OP_EQ,                                              \
               geoip_get_country_name(geoip_get_country_by_ipv6(&in6))); \
  } while (0)

/** Run unit tests for GeoIP code. */
static void
test_geoip(void *arg)
{
  int i, j;
  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  char *s = NULL, *v = NULL;
  const char *bridge_stats_1 =
      "bridge-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "bridge-ips zz=24,xy=8\n"
      "bridge-ip-versions v4=16,v6=16\n"
      "bridge-ip-transports <OR>=24\n",
  *dirreq_stats_1 =
      "dirreq-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "dirreq-v3-ips ab=8\n"
      "dirreq-v3-reqs ab=8\n"
      "dirreq-v3-resp ok=0,not-enough-sigs=0,unavailable=0,not-found=0,"
          "not-modified=0,busy=0\n"
      "dirreq-v3-direct-dl complete=0,timeout=0,running=0\n"
      "dirreq-v3-tunneled-dl complete=0,timeout=0,running=0\n",
  *dirreq_stats_2 =
      "dirreq-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "dirreq-v3-ips \n"
      "dirreq-v3-reqs \n"
      "dirreq-v3-resp ok=0,not-enough-sigs=0,unavailable=0,not-found=0,"
          "not-modified=0,busy=0\n"
      "dirreq-v3-direct-dl complete=0,timeout=0,running=0\n"
      "dirreq-v3-tunneled-dl complete=0,timeout=0,running=0\n",
  *dirreq_stats_3 =
      "dirreq-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "dirreq-v3-ips \n"
      "dirreq-v3-reqs \n"
      "dirreq-v3-resp ok=8,not-enough-sigs=0,unavailable=0,not-found=0,"
          "not-modified=0,busy=0\n"
      "dirreq-v3-direct-dl complete=0,timeout=0,running=0\n"
      "dirreq-v3-tunneled-dl complete=0,timeout=0,running=0\n",
  *dirreq_stats_4 =
      "dirreq-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "dirreq-v3-ips \n"
      "dirreq-v3-reqs \n"
      "dirreq-v3-resp ok=8,not-enough-sigs=0,unavailable=0,not-found=0,"
          "not-modified=0,busy=0\n"
      "dirreq-v3-direct-dl complete=0,timeout=0,running=0\n"
      "dirreq-v3-tunneled-dl complete=0,timeout=0,running=4\n",
  *entry_stats_1 =
      "entry-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "entry-ips ab=8\n",
  *entry_stats_2 =
      "entry-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "entry-ips \n";
  tor_addr_t addr;
  struct in6_addr in6;

  /* Populate the DB a bit.  Add these in order, since we can't do the final
   * 'sort' step.  These aren't very good IP addresses, but they're perfectly
   * fine uint32_t values. */
  (void)arg;
  tt_int_op(0,OP_EQ, geoip_parse_entry("10,50,AB", AF_INET));
  tt_int_op(0,OP_EQ, geoip_parse_entry("52,90,XY", AF_INET));
  tt_int_op(0,OP_EQ, geoip_parse_entry("95,100,AB", AF_INET));
  tt_int_op(0,OP_EQ, geoip_parse_entry("\"105\",\"140\",\"ZZ\"", AF_INET));
  tt_int_op(0,OP_EQ, geoip_parse_entry("\"150\",\"190\",\"XY\"", AF_INET));
  tt_int_op(0,OP_EQ, geoip_parse_entry("\"200\",\"250\",\"AB\"", AF_INET));

  /* Populate the IPv6 DB equivalently with fake IPs in the same range */
  tt_int_op(0,OP_EQ, geoip_parse_entry("::a,::32,AB", AF_INET6));
  tt_int_op(0,OP_EQ, geoip_parse_entry("::34,::5a,XY", AF_INET6));
  tt_int_op(0,OP_EQ, geoip_parse_entry("::5f,::64,AB", AF_INET6));
  tt_int_op(0,OP_EQ, geoip_parse_entry("::69,::8c,ZZ", AF_INET6));
  tt_int_op(0,OP_EQ, geoip_parse_entry("::96,::be,XY", AF_INET6));
  tt_int_op(0,OP_EQ, geoip_parse_entry("::c8,::fa,AB", AF_INET6));

  /* We should have 4 countries: ??, ab, xy, zz. */
  tt_int_op(4,OP_EQ, geoip_get_n_countries());
  memset(&in6, 0, sizeof(in6));

  CHECK_COUNTRY("??", 3);
  CHECK_COUNTRY("ab", 32);
  CHECK_COUNTRY("??", 5);
  CHECK_COUNTRY("??", 51);
  CHECK_COUNTRY("xy", 150);
  CHECK_COUNTRY("xy", 190);
  CHECK_COUNTRY("??", 2000);

  tt_int_op(0,OP_EQ, geoip_get_country_by_ipv4(3));
  SET_TEST_IPV6(3);
  tt_int_op(0,OP_EQ, geoip_get_country_by_ipv6(&in6));

  get_options_mutable()->BridgeRelay = 1;
  get_options_mutable()->BridgeRecordUsageByCountry = 1;
  /* Put 9 observations in AB... */
  for (i=32; i < 40; ++i) {
    SET_TEST_ADDRESS(i);
    geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL, now-7200);
  }
  SET_TEST_ADDRESS(225);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL, now-7200);
  /* and 3 observations in XY, several times. */
  for (j=0; j < 10; ++j)
    for (i=52; i < 55; ++i) {
      SET_TEST_ADDRESS(i);
      geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL, now-3600);
    }
  /* and 17 observations in ZZ... */
  for (i=110; i < 127; ++i) {
    SET_TEST_ADDRESS(i);
    geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL, now);
  }
  geoip_get_client_history(GEOIP_CLIENT_CONNECT, &s, &v);
  tt_assert(s);
  tt_assert(v);
  tt_str_op("zz=24,ab=16,xy=8",OP_EQ, s);
  tt_str_op("v4=16,v6=16",OP_EQ, v);
  tor_free(s);
  tor_free(v);

  /* Now clear out all the AB observations. */
  geoip_remove_old_clients(now-6000);
  geoip_get_client_history(GEOIP_CLIENT_CONNECT, &s, &v);
  tt_assert(s);
  tt_assert(v);
  tt_str_op("zz=24,xy=8",OP_EQ, s);
  tt_str_op("v4=16,v6=16",OP_EQ, v);
  tor_free(s);
  tor_free(v);

  /* Start testing bridge statistics by making sure that we don't output
   * bridge stats without initializing them. */
  s = geoip_format_bridge_stats(now + 86400);
  tt_ptr_op(s, OP_EQ, NULL);

  /* Initialize stats and generate the bridge-stats history string out of
   * the connecting clients added above. */
  geoip_bridge_stats_init(now);
  s = geoip_format_bridge_stats(now + 86400);
  tt_assert(s);
  tt_str_op(bridge_stats_1,OP_EQ, s);
  tor_free(s);

  /* Stop collecting bridge stats and make sure we don't write a history
   * string anymore. */
  geoip_bridge_stats_term();
  s = geoip_format_bridge_stats(now + 86400);
  tt_ptr_op(s, OP_EQ, NULL);

  /* Stop being a bridge and start being a directory mirror that gathers
   * directory request statistics. */
  geoip_bridge_stats_term();
  get_options_mutable()->BridgeRelay = 0;
  get_options_mutable()->BridgeRecordUsageByCountry = 0;
  get_options_mutable()->DirReqStatistics = 1;

  /* Start testing dirreq statistics by making sure that we don't collect
   * dirreq stats without initializing them. */
  SET_TEST_ADDRESS(100);
  geoip_note_client_seen(GEOIP_CLIENT_NETWORKSTATUS, &addr, NULL, now);
  s = geoip_format_dirreq_stats(now + 86400);
  tt_ptr_op(s, OP_EQ, NULL);

  /* Initialize stats, note one connecting client, and generate the
   * dirreq-stats history string. */
  geoip_dirreq_stats_init(now);
  SET_TEST_ADDRESS(100);
  geoip_note_client_seen(GEOIP_CLIENT_NETWORKSTATUS, &addr, NULL, now);
  s = geoip_format_dirreq_stats(now + 86400);
  tt_str_op(dirreq_stats_1,OP_EQ, s);
  tor_free(s);

  /* Stop collecting stats, add another connecting client, and ensure we
   * don't generate a history string. */
  geoip_dirreq_stats_term();
  SET_TEST_ADDRESS(101);
  geoip_note_client_seen(GEOIP_CLIENT_NETWORKSTATUS, &addr, NULL, now);
  s = geoip_format_dirreq_stats(now + 86400);
  tt_ptr_op(s, OP_EQ, NULL);

  /* Re-start stats, add a connecting client, reset stats, and make sure
   * that we get an all empty history string. */
  geoip_dirreq_stats_init(now);
  SET_TEST_ADDRESS(100);
  geoip_note_client_seen(GEOIP_CLIENT_NETWORKSTATUS, &addr, NULL, now);
  geoip_reset_dirreq_stats(now);
  s = geoip_format_dirreq_stats(now + 86400);
  tt_str_op(dirreq_stats_2,OP_EQ, s);
  tor_free(s);

  /* Note a successful network status response and make sure that it
   * appears in the history string. */
  geoip_note_ns_response(GEOIP_SUCCESS);
  s = geoip_format_dirreq_stats(now + 86400);
  tt_str_op(dirreq_stats_3,OP_EQ, s);
  tor_free(s);

  /* Start a tunneled directory request. */
  geoip_start_dirreq((uint64_t) 1, 1024, DIRREQ_TUNNELED);
  s = geoip_format_dirreq_stats(now + 86400);
  tt_str_op(dirreq_stats_4,OP_EQ, s);
  tor_free(s);

  /* Stop collecting directory request statistics and start gathering
   * entry stats. */
  geoip_dirreq_stats_term();
  get_options_mutable()->DirReqStatistics = 0;
  get_options_mutable()->EntryStatistics = 1;

  /* Start testing entry statistics by making sure that we don't collect
   * anything without initializing entry stats. */
  SET_TEST_ADDRESS(100);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL, now);
  s = geoip_format_entry_stats(now + 86400);
  tt_ptr_op(s, OP_EQ, NULL);

  /* Initialize stats, note one connecting client, and generate the
   * entry-stats history string. */
  geoip_entry_stats_init(now);
  SET_TEST_ADDRESS(100);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL, now);
  s = geoip_format_entry_stats(now + 86400);
  tt_str_op(entry_stats_1,OP_EQ, s);
  tor_free(s);

  /* Stop collecting stats, add another connecting client, and ensure we
   * don't generate a history string. */
  geoip_entry_stats_term();
  SET_TEST_ADDRESS(101);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL, now);
  s = geoip_format_entry_stats(now + 86400);
  tt_ptr_op(s, OP_EQ, NULL);

  /* Re-start stats, add a connecting client, reset stats, and make sure
   * that we get an all empty history string. */
  geoip_entry_stats_init(now);
  SET_TEST_ADDRESS(100);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL, now);
  geoip_reset_entry_stats(now);
  s = geoip_format_entry_stats(now + 86400);
  tt_str_op(entry_stats_2,OP_EQ, s);
  tor_free(s);

  /* Test the OOM handler. Add a client, run the OOM. */
  geoip_entry_stats_init(now);
  SET_TEST_ADDRESS(100);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL,
                         now - (12 * 60 * 60));
  /* We've seen this 12 hours ago. Run the OOM, it should clean the entry
   * because it is above the minimum cutoff of 4 hours. */
  size_t bytes_removed = geoip_client_cache_handle_oom(now, 1000);
  tt_size_op(bytes_removed, OP_GT, 0);

  /* Do it again but this time with an entry with a lower cutoff. */
  geoip_entry_stats_init(now);
  SET_TEST_ADDRESS(100);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL,
                         now - (3 * 60 * 60));
  bytes_removed = geoip_client_cache_handle_oom(now, 1000);
  tt_size_op(bytes_removed, OP_EQ, 0);

  /* Stop collecting entry statistics. */
  geoip_entry_stats_term();
  get_options_mutable()->EntryStatistics = 0;

 done:
  tor_free(s);
  tor_free(v);
}

static void
test_geoip_with_pt(void *arg)
{
  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  char *s = NULL;
  int i;
  tor_addr_t addr;
  struct in6_addr in6;

  (void)arg;
  get_options_mutable()->BridgeRelay = 1;
  get_options_mutable()->BridgeRecordUsageByCountry = 1;

  memset(&in6, 0, sizeof(in6));

  /* No clients seen yet. */
  s = geoip_get_transport_history();
  tor_assert(!s);

  /* 4 connections without a pluggable transport */
  for (i=0; i < 4; ++i) {
    SET_TEST_ADDRESS(i);
    geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL, now-7200);
  }

  /* 9 connections with "alpha" */
  for (i=4; i < 13; ++i) {
    SET_TEST_ADDRESS(i);
    geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, "alpha", now-7200);
  }

  /* one connection with "beta" */
  SET_TEST_ADDRESS(13);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, "beta", now-7200);

  /* 14 connections with "charlie" */
  for (i=14; i < 28; ++i) {
    SET_TEST_ADDRESS(i);
    geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, "charlie", now-7200);
  }

  /* 131 connections with "ddr" */
  for (i=28; i < 159; ++i) {
    SET_TEST_ADDRESS(i);
    geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, "ddr", now-7200);
  }

  /* 8 connections with "entropy" */
  for (i=159; i < 167; ++i) {
    SET_TEST_ADDRESS(i);
    geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, "entropy", now-7200);
  }

  /* 2 connections from the same IP with two different transports. */
  SET_TEST_ADDRESS(++i);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, "fire", now-7200);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, "google", now-7200);

  /* Test the transport history string. */
  s = geoip_get_transport_history();
  tor_assert(s);
  tt_str_op(s,OP_EQ, "<OR>=8,alpha=16,beta=8,charlie=16,ddr=136,"
             "entropy=8,fire=8,google=8");

  /* Stop collecting entry statistics. */
  geoip_entry_stats_term();
  get_options_mutable()->EntryStatistics = 0;

 done:
  tor_free(s);
}

#undef SET_TEST_ADDRESS
#undef SET_TEST_IPV6
#undef CHECK_COUNTRY

#define ENT(name)                                                       \
  { #name, test_ ## name , 0, NULL, NULL }
#define FORK(name)                                                      \
  { #name, test_ ## name , TT_FORK, NULL, NULL }

struct testcase_t geoip_tests[] = {
  { "geoip", test_geoip, TT_FORK, NULL, NULL },
  { "geoip_with_pt", test_geoip_with_pt, TT_FORK, NULL, NULL },

  END_OF_TESTCASES
};

