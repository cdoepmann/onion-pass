/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

#define CONFIG_PRIVATE
#include "or.h"
#include "addressmap.h"
#include "config.h"
#include "confparse.h"
#include "connection_edge.h"
#include "test.h"
#include "util.h"
#include "address.h"
#include "entrynodes.h"
#include "transports.h"

static void
test_config_addressmap(void *arg)
{
  char buf[1024];
  char address[256];
  time_t expires = TIME_MAX;
  (void)arg;

  strlcpy(buf, "MapAddress .invalidwildcard.com *.torserver.exit\n" // invalid
          "MapAddress *invalidasterisk.com *.torserver.exit\n" // invalid
          "MapAddress *.google.com *.torserver.exit\n"
          "MapAddress *.yahoo.com *.google.com.torserver.exit\n"
          "MapAddress *.cn.com www.cnn.com\n"
          "MapAddress *.cnn.com www.cnn.com\n"
          "MapAddress ex.com www.cnn.com\n"
          "MapAddress ey.com *.cnn.com\n"
          "MapAddress www.torproject.org 1.1.1.1\n"
          "MapAddress other.torproject.org "
            "this.torproject.org.otherserver.exit\n"
          "MapAddress test.torproject.org 2.2.2.2\n"
          "MapAddress www.google.com 3.3.3.3\n"
          "MapAddress www.example.org 4.4.4.4\n"
          "MapAddress 4.4.4.4 7.7.7.7\n"
          "MapAddress 4.4.4.4 5.5.5.5\n"
          "MapAddress www.infiniteloop.org 6.6.6.6\n"
          "MapAddress 6.6.6.6 www.infiniteloop.org\n"
          , sizeof(buf));

  config_get_lines(buf, &(get_options_mutable()->AddressMap), 0);
  config_register_addressmaps(get_options());

/* Use old interface for now, so we don't need to rewrite the unit tests */
#define addressmap_rewrite(a,s,eo,ao)                                   \
  addressmap_rewrite((a),(s),AMR_FLAG_USE_IPV4_DNS|AMR_FLAG_USE_IPV6_DNS, \
                     (eo),(ao))

  /* MapAddress .invalidwildcard.com .torserver.exit  - no match */
  strlcpy(address, "www.invalidwildcard.com", sizeof(address));
  tt_assert(!addressmap_rewrite(address, sizeof(address), &expires, NULL));

  /* MapAddress *invalidasterisk.com .torserver.exit  - no match */
  strlcpy(address, "www.invalidasterisk.com", sizeof(address));
  tt_assert(!addressmap_rewrite(address, sizeof(address), &expires, NULL));

  /* Where no mapping for FQDN match on top-level domain */
  /* MapAddress .google.com .torserver.exit */
  strlcpy(address, "reader.google.com", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "reader.torserver.exit");

  /* MapAddress *.yahoo.com *.google.com.torserver.exit */
  strlcpy(address, "reader.yahoo.com", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "reader.google.com.torserver.exit");

  /*MapAddress *.cnn.com www.cnn.com */
  strlcpy(address, "cnn.com", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "www.cnn.com");

  /* MapAddress .cn.com www.cnn.com */
  strlcpy(address, "www.cn.com", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "www.cnn.com");

  /* MapAddress ex.com www.cnn.com  - no match */
  strlcpy(address, "www.ex.com", sizeof(address));
  tt_assert(!addressmap_rewrite(address, sizeof(address), &expires, NULL));

  /* MapAddress ey.com *.cnn.com - invalid expression */
  strlcpy(address, "ey.com", sizeof(address));
  tt_assert(!addressmap_rewrite(address, sizeof(address), &expires, NULL));

  /* Where mapping for FQDN match on FQDN */
  strlcpy(address, "www.google.com", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "3.3.3.3");

  strlcpy(address, "www.torproject.org", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "1.1.1.1");

  strlcpy(address, "other.torproject.org", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "this.torproject.org.otherserver.exit");

  strlcpy(address, "test.torproject.org", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "2.2.2.2");

  /* Test a chain of address mappings and the order in which they were added:
          "MapAddress www.example.org 4.4.4.4"
          "MapAddress 4.4.4.4 7.7.7.7"
          "MapAddress 4.4.4.4 5.5.5.5"
  */
  strlcpy(address, "www.example.org", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "5.5.5.5");

  /* Test infinite address mapping results in no change */
  strlcpy(address, "www.infiniteloop.org", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "www.infiniteloop.org");

  /* Test we don't find false positives */
  strlcpy(address, "www.example.com", sizeof(address));
  tt_assert(!addressmap_rewrite(address, sizeof(address), &expires, NULL));

  /* Test top-level-domain matching a bit harder */
  config_free_lines(get_options_mutable()->AddressMap);
  addressmap_clear_configured();
  strlcpy(buf, "MapAddress *.com *.torserver.exit\n"
          "MapAddress *.torproject.org 1.1.1.1\n"
          "MapAddress *.net 2.2.2.2\n"
          , sizeof(buf));
  config_get_lines(buf, &(get_options_mutable()->AddressMap), 0);
  config_register_addressmaps(get_options());

  strlcpy(address, "www.abc.com", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "www.abc.torserver.exit");

  strlcpy(address, "www.def.com", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "www.def.torserver.exit");

  strlcpy(address, "www.torproject.org", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "1.1.1.1");

  strlcpy(address, "test.torproject.org", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "1.1.1.1");

  strlcpy(address, "torproject.net", sizeof(address));
  tt_assert(addressmap_rewrite(address, sizeof(address), &expires, NULL));
  tt_str_op(address,==, "2.2.2.2");

  /* We don't support '*' as a mapping directive */
  config_free_lines(get_options_mutable()->AddressMap);
  addressmap_clear_configured();
  strlcpy(buf, "MapAddress * *.torserver.exit\n", sizeof(buf));
  config_get_lines(buf, &(get_options_mutable()->AddressMap), 0);
  config_register_addressmaps(get_options());

  strlcpy(address, "www.abc.com", sizeof(address));
  tt_assert(!addressmap_rewrite(address, sizeof(address), &expires, NULL));

  strlcpy(address, "www.def.net", sizeof(address));
  tt_assert(!addressmap_rewrite(address, sizeof(address), &expires, NULL));

  strlcpy(address, "www.torproject.org", sizeof(address));
  tt_assert(!addressmap_rewrite(address, sizeof(address), &expires, NULL));

#undef addressmap_rewrite

 done:
  config_free_lines(get_options_mutable()->AddressMap);
  get_options_mutable()->AddressMap = NULL;
}

static int
is_private_dir(const char* path)
{
  struct stat st;
  int r = stat(path, &st);
  if (r) {
    return 0;
  }
#if !defined (_WIN32)
  if ((st.st_mode & (S_IFDIR | 0777)) != (S_IFDIR | 0700)) {
    return 0;
  }
#endif
  return 1;
}

static void
test_config_check_or_create_data_subdir(void *arg)
{
  or_options_t *options = get_options_mutable();
  char *datadir;
  const char *subdir = "test_stats";
  char *subpath;
  struct stat st;
  int r;
#if !defined (_WIN32)
  unsigned group_permission;
#endif
  (void)arg;

  tor_free(options->DataDirectory);
  datadir = options->DataDirectory = tor_strdup(get_fname("datadir-0"));
  subpath = get_datadir_fname(subdir);

#if defined (_WIN32)
  tt_int_op(mkdir(options->DataDirectory), ==, 0);
#else
  tt_int_op(mkdir(options->DataDirectory, 0700), ==, 0);
#endif

  r = stat(subpath, &st);

  // The subdirectory shouldn't exist yet,
  // but should be created by the call to check_or_create_data_subdir.
  tt_assert(r && (errno == ENOENT));
  tt_assert(!check_or_create_data_subdir(subdir));
  tt_assert(is_private_dir(subpath));

  // The check should return 0, if the directory already exists
  // and is private to the user.
  tt_assert(!check_or_create_data_subdir(subdir));

  r = stat(subpath, &st);
  if (r) {
    tt_abort_perror("stat");
  }

#if !defined (_WIN32)
  group_permission = st.st_mode | 0070;
  r = chmod(subpath, group_permission);

  if (r) {
    tt_abort_perror("chmod");
  }

  // If the directory exists, but its mode is too permissive
  // a call to check_or_create_data_subdir should reset the mode.
  tt_assert(!is_private_dir(subpath));
  tt_assert(!check_or_create_data_subdir(subdir));
  tt_assert(is_private_dir(subpath));
#endif

 done:
  rmdir(subpath);
  tor_free(datadir);
  tor_free(subpath);
}

static void
test_config_write_to_data_subdir(void *arg)
{
  or_options_t* options = get_options_mutable();
  char *datadir;
  char *cp = NULL;
  const char* subdir = "test_stats";
  const char* fname = "test_file";
  const char* str =
      "Lorem ipsum dolor sit amet, consetetur sadipscing\n"
      "elitr, sed diam nonumy eirmod\n"
      "tempor invidunt ut labore et dolore magna aliquyam\n"
      "erat, sed diam voluptua.\n"
      "At vero eos et accusam et justo duo dolores et ea\n"
      "rebum. Stet clita kasd gubergren,\n"
      "no sea takimata sanctus est Lorem ipsum dolor sit amet.\n"
      "Lorem ipsum dolor sit amet,\n"
      "consetetur sadipscing elitr, sed diam nonumy eirmod\n"
      "tempor invidunt ut labore et dolore\n"
      "magna aliquyam erat, sed diam voluptua. At vero eos et\n"
      "accusam et justo duo dolores et\n"
      "ea rebum. Stet clita kasd gubergren, no sea takimata\n"
      "sanctus est Lorem ipsum dolor sit amet.";
  char* filepath = NULL;
  (void)arg;

  tor_free(options->DataDirectory);
  datadir = options->DataDirectory = tor_strdup(get_fname("datadir-1"));
  filepath = get_datadir_fname2(subdir, fname);

#if defined (_WIN32)
  tt_int_op(mkdir(options->DataDirectory), ==, 0);
#else
  tt_int_op(mkdir(options->DataDirectory, 0700), ==, 0);
#endif

  // Write attempt shoudl fail, if subdirectory doesn't exist.
  tt_assert(write_to_data_subdir(subdir, fname, str, NULL));
  tt_assert(! check_or_create_data_subdir(subdir));

  // Content of file after write attempt should be
  // equal to the original string.
  tt_assert(!write_to_data_subdir(subdir, fname, str, NULL));
  cp = read_file_to_str(filepath, 0, NULL);
  tt_str_op(cp,==, str);
  tor_free(cp);

  // A second write operation should overwrite the old content.
  tt_assert(!write_to_data_subdir(subdir, fname, str, NULL));
  cp = read_file_to_str(filepath, 0, NULL);
  tt_str_op(cp,==, str);
  tor_free(cp);

 done:
  (void) unlink(filepath);
  rmdir(options->DataDirectory);
  tor_free(datadir);
  tor_free(filepath);
  tor_free(cp);
}

/* Test helper function: Make sure that a bridge line gets parsed
 * properly. Also make sure that the resulting bridge_line_t structure
 * has its fields set correctly. */
static void
good_bridge_line_test(const char *string, const char *test_addrport,
                      const char *test_digest, const char *test_transport,
                      const smartlist_t *test_socks_args)
{
  char *tmp = NULL;
  bridge_line_t *bridge_line = parse_bridge_line(string);
  tt_assert(bridge_line);

  /* test addrport */
  tmp = tor_strdup(fmt_addrport(&bridge_line->addr, bridge_line->port));
  tt_str_op(test_addrport,==, tmp);
  tor_free(tmp);

  /* If we were asked to validate a digest, but we did not get a
     digest after parsing, we failed. */
  if (test_digest && tor_digest_is_zero(bridge_line->digest))
    tt_assert(0);

  /* If we were not asked to validate a digest, and we got a digest
     after parsing, we failed again. */
  if (!test_digest && !tor_digest_is_zero(bridge_line->digest))
    tt_assert(0);

  /* If we were asked to validate a digest, and we got a digest after
     parsing, make sure it's correct. */
  if (test_digest) {
    tmp = tor_strdup(hex_str(bridge_line->digest, DIGEST_LEN));
    tor_strlower(tmp);
    tt_str_op(test_digest,==, tmp);
    tor_free(tmp);
  }

  /* If we were asked to validate a transport name, make sure tha it
     matches with the transport name that was parsed. */
  if (test_transport && !bridge_line->transport_name)
    tt_assert(0);
  if (!test_transport && bridge_line->transport_name)
    tt_assert(0);
  if (test_transport)
    tt_str_op(test_transport,==, bridge_line->transport_name);

  /* Validate the SOCKS argument smartlist. */
  if (test_socks_args && !bridge_line->socks_args)
    tt_assert(0);
  if (!test_socks_args && bridge_line->socks_args)
    tt_assert(0);
  if (test_socks_args)
    tt_assert(smartlist_strings_eq(test_socks_args,
                                     bridge_line->socks_args));

 done:
  tor_free(tmp);
  bridge_line_free(bridge_line);
}

/* Test helper function: Make sure that a bridge line is
 * unparseable. */
static void
bad_bridge_line_test(const char *string)
{
  bridge_line_t *bridge_line = parse_bridge_line(string);
  if (bridge_line)
    TT_FAIL(("%s was supposed to fail, but it didn't.", string));
  tt_assert(!bridge_line);

 done:
  bridge_line_free(bridge_line);
}

static void
test_config_parse_bridge_line(void *arg)
{
  (void) arg;
  good_bridge_line_test("192.0.2.1:4123",
                        "192.0.2.1:4123", NULL, NULL, NULL);

  good_bridge_line_test("192.0.2.1",
                        "192.0.2.1:443", NULL, NULL, NULL);

  good_bridge_line_test("transport [::1]",
                        "[::1]:443", NULL, "transport", NULL);

  good_bridge_line_test("transport 192.0.2.1:12 "
                        "4352e58420e68f5e40bf7c74faddccd9d1349413",
                        "192.0.2.1:12",
                        "4352e58420e68f5e40bf7c74faddccd9d1349413",
                        "transport", NULL);

  {
    smartlist_t *sl_tmp = smartlist_new();
    smartlist_add_asprintf(sl_tmp, "twoandtwo=five");

    good_bridge_line_test("transport 192.0.2.1:12 "
                    "4352e58420e68f5e40bf7c74faddccd9d1349413 twoandtwo=five",
                    "192.0.2.1:12", "4352e58420e68f5e40bf7c74faddccd9d1349413",
                    "transport", sl_tmp);

    SMARTLIST_FOREACH(sl_tmp, char *, s, tor_free(s));
    smartlist_free(sl_tmp);
  }

  {
    smartlist_t *sl_tmp = smartlist_new();
    smartlist_add_asprintf(sl_tmp, "twoandtwo=five");
    smartlist_add_asprintf(sl_tmp, "z=z");

    good_bridge_line_test("transport 192.0.2.1:12 twoandtwo=five z=z",
                          "192.0.2.1:12", NULL, "transport", sl_tmp);

    SMARTLIST_FOREACH(sl_tmp, char *, s, tor_free(s));
    smartlist_free(sl_tmp);
  }

  {
    smartlist_t *sl_tmp = smartlist_new();
    smartlist_add_asprintf(sl_tmp, "dub=come");
    smartlist_add_asprintf(sl_tmp, "save=me");

    good_bridge_line_test("transport 192.0.2.1:12 "
                          "4352e58420e68f5e40bf7c74faddccd9d1349666 "
                          "dub=come save=me",

                          "192.0.2.1:12",
                          "4352e58420e68f5e40bf7c74faddccd9d1349666",
                          "transport", sl_tmp);

    SMARTLIST_FOREACH(sl_tmp, char *, s, tor_free(s));
    smartlist_free(sl_tmp);
  }

  good_bridge_line_test("192.0.2.1:1231 "
                        "4352e58420e68f5e40bf7c74faddccd9d1349413",
                        "192.0.2.1:1231",
                        "4352e58420e68f5e40bf7c74faddccd9d1349413",
                        NULL, NULL);

  /* Empty line */
  bad_bridge_line_test("");
  /* bad transport name */
  bad_bridge_line_test("tr$n_sp0r7 190.20.2.2");
  /* weird ip address */
  bad_bridge_line_test("a.b.c.d");
  /* invalid fpr */
  bad_bridge_line_test("2.2.2.2:1231 4352e58420e68f5e40bf7c74faddccd9d1349");
  /* no k=v in the end */
  bad_bridge_line_test("obfs2 2.2.2.2:1231 "
                       "4352e58420e68f5e40bf7c74faddccd9d1349413 what");
  /* no addrport */
  bad_bridge_line_test("asdw");
  /* huge k=v value that can't fit in SOCKS fields */
  bad_bridge_line_test(
           "obfs2 2.2.2.2:1231 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aa=b");
}

static void
test_config_parse_transport_options_line(void *arg)
{
  smartlist_t *options_sl = NULL, *sl_tmp = NULL;

  (void) arg;

  { /* too small line */
    options_sl = get_options_from_transport_options_line("valley", NULL);
    tt_assert(!options_sl);
  }

  { /* no k=v values */
    options_sl = get_options_from_transport_options_line("hit it!", NULL);
    tt_assert(!options_sl);
  }

  { /* correct line, but wrong transport specified */
    options_sl =
      get_options_from_transport_options_line("trebuchet k=v", "rook");
    tt_assert(!options_sl);
  }

  { /* correct -- no transport specified */
    sl_tmp = smartlist_new();
    smartlist_add_asprintf(sl_tmp, "ladi=dadi");
    smartlist_add_asprintf(sl_tmp, "weliketo=party");

    options_sl =
      get_options_from_transport_options_line("rook ladi=dadi weliketo=party",
                                              NULL);
    tt_assert(options_sl);
    tt_assert(smartlist_strings_eq(options_sl, sl_tmp));

    SMARTLIST_FOREACH(sl_tmp, char *, s, tor_free(s));
    smartlist_free(sl_tmp);
    sl_tmp = NULL;
    SMARTLIST_FOREACH(options_sl, char *, s, tor_free(s));
    smartlist_free(options_sl);
    options_sl = NULL;
  }

  { /* correct -- correct transport specified */
    sl_tmp = smartlist_new();
    smartlist_add_asprintf(sl_tmp, "ladi=dadi");
    smartlist_add_asprintf(sl_tmp, "weliketo=party");

    options_sl =
      get_options_from_transport_options_line("rook ladi=dadi weliketo=party",
                                              "rook");
    tt_assert(options_sl);
    tt_assert(smartlist_strings_eq(options_sl, sl_tmp));
    SMARTLIST_FOREACH(sl_tmp, char *, s, tor_free(s));
    smartlist_free(sl_tmp);
    sl_tmp = NULL;
    SMARTLIST_FOREACH(options_sl, char *, s, tor_free(s));
    smartlist_free(options_sl);
    options_sl = NULL;
  }

 done:
  if (options_sl) {
    SMARTLIST_FOREACH(options_sl, char *, s, tor_free(s));
    smartlist_free(options_sl);
  }
  if (sl_tmp) {
    SMARTLIST_FOREACH(sl_tmp, char *, s, tor_free(s));
    smartlist_free(sl_tmp);
  }
}

/* Mocks needed for the transport plugin line test */

static void pt_kickstart_proxy_mock(const smartlist_t *transport_list,
                                    char **proxy_argv, int is_server);
static int transport_add_from_config_mock(const tor_addr_t *addr,
                                          uint16_t port, const char *name,
                                          int socks_ver);
static int transport_is_needed_mock(const char *transport_name);

static int pt_kickstart_proxy_mock_call_count = 0;
static int transport_add_from_config_mock_call_count = 0;
static int transport_is_needed_mock_call_count = 0;
static int transport_is_needed_mock_return = 0;

static void
pt_kickstart_proxy_mock(const smartlist_t *transport_list,
                        char **proxy_argv, int is_server)
{
  ++pt_kickstart_proxy_mock_call_count;
}

static int
transport_add_from_config_mock(const tor_addr_t *addr,
                               uint16_t port, const char *name,
                               int socks_ver)
{
  ++transport_add_from_config_mock_call_count;

  return 0;
}

static int
transport_is_needed_mock(const char *transport_name)
{
  ++transport_is_needed_mock_call_count;

  return transport_is_needed_mock_return;
}

/**
 * Test parsing for the ClientTransportPlugin and ServerTransportPlugin config
 * options.
 */

static void
test_config_parse_transport_plugin_line(void *arg)
{
  or_options_t *options = get_options_mutable();
  int r, tmp;
  int old_pt_kickstart_proxy_mock_call_count;
  int old_transport_add_from_config_mock_call_count;
  int old_transport_is_needed_mock_call_count;

  /* Bad transport lines - too short */
  r = parse_transport_line(options, "bad", 1, 0);
  tt_assert(r < 0);
  r = parse_transport_line(options, "bad", 1, 1);
  tt_assert(r < 0);
  r = parse_transport_line(options, "bad bad", 1, 0);
  tt_assert(r < 0);
  r = parse_transport_line(options, "bad bad", 1, 1);
  tt_assert(r < 0);

  /* Test transport list parsing */
  r = parse_transport_line(options,
      "transport_1 exec /usr/bin/fake-transport", 1, 0);
  tt_assert(r == 0);
  r = parse_transport_line(options,
   "transport_1 exec /usr/bin/fake-transport", 1, 1);
  tt_assert(r == 0);
  r = parse_transport_line(options,
      "transport_1,transport_2 exec /usr/bin/fake-transport", 1, 0);
  tt_assert(r == 0);
  r = parse_transport_line(options,
      "transport_1,transport_2 exec /usr/bin/fake-transport", 1, 1);
  tt_assert(r == 0);
  /* Bad transport identifiers */
  r = parse_transport_line(options,
      "transport_* exec /usr/bin/fake-transport", 1, 0);
  tt_assert(r < 0);
  r = parse_transport_line(options,
      "transport_* exec /usr/bin/fake-transport", 1, 1);
  tt_assert(r < 0);

  /* Check SOCKS cases for client transport */
  r = parse_transport_line(options,
      "transport_1 socks4 1.2.3.4:567", 1, 0);
  tt_assert(r == 0);
  r = parse_transport_line(options,
      "transport_1 socks5 1.2.3.4:567", 1, 0);
  tt_assert(r == 0);
  /* Proxy case for server transport */
  r = parse_transport_line(options,
      "transport_1 proxy 1.2.3.4:567", 1, 1);
  tt_assert(r == 0);
  /* Multiple-transport error exit */
  r = parse_transport_line(options,
      "transport_1,transport_2 socks5 1.2.3.4:567", 1, 0);
  tt_assert(r < 0);
  r = parse_transport_line(options,
      "transport_1,transport_2 proxy 1.2.3.4:567", 1, 1);
  /* No port error exit */
  r = parse_transport_line(options,
      "transport_1 socks5 1.2.3.4", 1, 0);
  tt_assert(r < 0);
  r = parse_transport_line(options,
     "transport_1 proxy 1.2.3.4", 1, 1);
  tt_assert(r < 0);
  /* Unparsable address error exit */
  r = parse_transport_line(options,
      "transport_1 socks5 1.2.3:6x7", 1, 0);
  tt_assert(r < 0);
  r = parse_transport_line(options,
      "transport_1 proxy 1.2.3:6x7", 1, 1);
  tt_assert(r < 0);

  /* "Strange {Client|Server}TransportPlugin field" error exit */
  r = parse_transport_line(options,
      "transport_1 foo bar", 1, 0);
  tt_assert(r < 0);
  r = parse_transport_line(options,
      "transport_1 foo bar", 1, 1);
  tt_assert(r < 0);

  /* No sandbox mode error exit */
  tmp = options->Sandbox;
  options->Sandbox = 1;
  r = parse_transport_line(options,
      "transport_1 exec /usr/bin/fake-transport", 1, 0);
  tt_assert(r < 0);
  r = parse_transport_line(options,
      "transport_1 exec /usr/bin/fake-transport", 1, 1);
  tt_assert(r < 0);
  options->Sandbox = tmp;

  /*
   * These final test cases cover code paths that only activate without
   * validate_only, so they need mocks in place.
   */
  MOCK(pt_kickstart_proxy, pt_kickstart_proxy_mock);
  old_pt_kickstart_proxy_mock_call_count =
    pt_kickstart_proxy_mock_call_count;
  r = parse_transport_line(options,
      "transport_1 exec /usr/bin/fake-transport", 0, 1);
  tt_assert(r == 0);
  tt_assert(pt_kickstart_proxy_mock_call_count ==
      old_pt_kickstart_proxy_mock_call_count + 1);
  UNMOCK(pt_kickstart_proxy);

  /* This one hits a log line in the !validate_only case only */
  r = parse_transport_line(options,
      "transport_1 proxy 1.2.3.4:567", 0, 1);
  tt_assert(r == 0);

  /* Check mocked client transport cases */
  MOCK(pt_kickstart_proxy, pt_kickstart_proxy_mock);
  MOCK(transport_add_from_config, transport_add_from_config_mock);
  MOCK(transport_is_needed, transport_is_needed_mock);

  /* Unnecessary transport case */
  transport_is_needed_mock_return = 0;
  old_pt_kickstart_proxy_mock_call_count =
    pt_kickstart_proxy_mock_call_count;
  old_transport_add_from_config_mock_call_count =
    transport_add_from_config_mock_call_count;
  old_transport_is_needed_mock_call_count =
    transport_is_needed_mock_call_count;
  r = parse_transport_line(options,
      "transport_1 exec /usr/bin/fake-transport", 0, 0);
  /* Should have succeeded */
  tt_assert(r == 0);
  /* transport_is_needed() should have been called */
  tt_assert(transport_is_needed_mock_call_count ==
      old_transport_is_needed_mock_call_count + 1);
  /*
   * pt_kickstart_proxy() and transport_add_from_config() should
   * not have been called.
   */
  tt_assert(pt_kickstart_proxy_mock_call_count ==
      old_pt_kickstart_proxy_mock_call_count);
  tt_assert(transport_add_from_config_mock_call_count ==
      old_transport_add_from_config_mock_call_count);

  /* Necessary transport case */
  transport_is_needed_mock_return = 1;
  old_pt_kickstart_proxy_mock_call_count =
    pt_kickstart_proxy_mock_call_count;
  old_transport_add_from_config_mock_call_count =
    transport_add_from_config_mock_call_count;
  old_transport_is_needed_mock_call_count =
    transport_is_needed_mock_call_count;
  r = parse_transport_line(options,
      "transport_1 exec /usr/bin/fake-transport", 0, 0);
  /* Should have succeeded */
  tt_assert(r == 0);
  /*
   * transport_is_needed() and pt_kickstart_proxy() should have been
   * called.
   */
  tt_assert(pt_kickstart_proxy_mock_call_count ==
      old_pt_kickstart_proxy_mock_call_count + 1);
  tt_assert(transport_is_needed_mock_call_count ==
      old_transport_is_needed_mock_call_count + 1);
  /* transport_add_from_config() should not have been called. */
  tt_assert(transport_add_from_config_mock_call_count ==
      old_transport_add_from_config_mock_call_count);

  /* proxy case */
  transport_is_needed_mock_return = 1;
  old_pt_kickstart_proxy_mock_call_count =
    pt_kickstart_proxy_mock_call_count;
  old_transport_add_from_config_mock_call_count =
    transport_add_from_config_mock_call_count;
  old_transport_is_needed_mock_call_count =
    transport_is_needed_mock_call_count;
  r = parse_transport_line(options,
      "transport_1 socks5 1.2.3.4:567", 0, 0);
  /* Should have succeeded */
  tt_assert(r == 0);
  /*
   * transport_is_needed() and transport_add_from_config() should have
   * been called.
   */
  tt_assert(transport_add_from_config_mock_call_count ==
      old_transport_add_from_config_mock_call_count + 1);
  tt_assert(transport_is_needed_mock_call_count ==
      old_transport_is_needed_mock_call_count + 1);
  /* pt_kickstart_proxy() should not have been called. */
  tt_assert(pt_kickstart_proxy_mock_call_count ==
      old_pt_kickstart_proxy_mock_call_count);

  /* Done with mocked client transport cases */
  UNMOCK(transport_is_needed);
  UNMOCK(transport_add_from_config);
  UNMOCK(pt_kickstart_proxy);

 done:
  /* Make sure we undo all mocks */
  UNMOCK(pt_kickstart_proxy);
  UNMOCK(transport_add_from_config);
  UNMOCK(transport_is_needed);

  return;
}

// Tests if an options with MyFamily fingerprints missing '$' normalises
// them correctly and also ensure it also works with multiple fingerprints
static void
test_config_fix_my_family(void *arg)
{
  char *err = NULL;
  const char *family = "$1111111111111111111111111111111111111111, "
                       "1111111111111111111111111111111111111112, "
                       "$1111111111111111111111111111111111111113";

  or_options_t* options = options_new();
  or_options_t* defaults = options_new();
  (void) arg;

  options_init(options);
  options_init(defaults);
  options->MyFamily = tor_strdup(family);

  options_validate(NULL, options, defaults, 0, &err) ;

  if (err != NULL) {
    TT_FAIL(("options_validate failed: %s", err));
  }

  tt_str_op(options->MyFamily,==, "$1111111111111111111111111111111111111111, "
                                "$1111111111111111111111111111111111111112, "
                                "$1111111111111111111111111111111111111113");

  done:
    if (err != NULL) {
      tor_free(err);
    }

    or_options_free(options);
    or_options_free(defaults);
}

#define CONFIG_TEST(name, flags)                          \
  { #name, test_config_ ## name, flags, NULL, NULL }

struct testcase_t config_tests[] = {
  CONFIG_TEST(addressmap, 0),
  CONFIG_TEST(parse_bridge_line, 0),
  CONFIG_TEST(parse_transport_options_line, 0),
  CONFIG_TEST(parse_transport_plugin_line, TT_FORK),
  CONFIG_TEST(check_or_create_data_subdir, TT_FORK),
  CONFIG_TEST(write_to_data_subdir, TT_FORK),
  CONFIG_TEST(fix_my_family, 0),
  END_OF_TESTCASES
};

