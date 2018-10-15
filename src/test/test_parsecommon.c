/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "core/or/or.h"
#include "test/test.h"
#include "lib/memarea/memarea.h"
#include "lib/encoding/binascii.h"
#include "feature/dirparse/parsecommon.h"
#include "test/log_test_helpers.h"

static void
test_parsecommon_tokenize_string_null(void *arg)
{

  memarea_t *area = memarea_new();
  smartlist_t *tokens = smartlist_new();

  (void)arg;

  const char *str_with_null = "a\0bccccccccc";

  int retval =
  tokenize_string(area, str_with_null,
                  str_with_null + 3,
                  tokens, NULL, 0);

  tt_int_op(retval, OP_EQ, -1);

 done:
  memarea_drop_all(area);
  smartlist_free(tokens);
  return;
}

static void
test_parsecommon_get_next_token_success(void *arg)
{
  memarea_t *area = memarea_new();
  const char *str = "uptime 1024";
  const char *end = str + strlen(str);
  const char **s = &str;
  token_rule_t table = T01("uptime", K_UPTIME, GE(1), NO_OBJ);
  (void)arg;

  directory_token_t *token = get_next_token(area, s, end, &table);

  tt_int_op(token->tp, OP_EQ, K_UPTIME);
  tt_int_op(token->n_args, OP_EQ, 1);
  tt_str_op(*(token->args), OP_EQ, "1024");
  tt_assert(!token->object_type);
  tt_int_op(token->object_size, OP_EQ, 0);
  tt_assert(!token->object_body);

  tt_ptr_op(*s, OP_EQ, end);

 done:
  memarea_drop_all(area);
  return;
}

static void
test_parsecommon_get_next_token_concat_args(void *arg)
{
  memarea_t *area = memarea_new();
  const char *str = "proto A=1 B=2";
  const char *end = str + strlen(str);
  const char **s = &str;
  token_rule_t rule = T01("proto", K_PROTO, CONCAT_ARGS, NO_OBJ);
  (void)arg;

  directory_token_t *token = get_next_token(area, s, end, &rule);

  tt_int_op(token->tp, OP_EQ, K_PROTO);
  tt_int_op(token->n_args, OP_EQ, 1);
  tt_str_op(*(token->args), OP_EQ, "A=1 B=2");

 done:
  memarea_drop_all(area);
}

static void
test_parsecommon_get_next_token_parse_keys(void *arg)
{
  (void)arg;

  memarea_t *area = memarea_new();
  const char *str =
    "onion-key\n"
    "-----BEGIN RSA PUBLIC KEY-----\n"
    "MIGJAoGBAMDdIya33BfNlHOkzoTKSTT8EjD64waMfUr372syVHiFjHhObwKwGA5u\n"
    "sHaMIe9r+Ij/4C1dKyuXkcz3DOl6gWNhTD7dZ89I+Okoh1jWe30jxCiAcywC22p5\n"
    "XLhrDkX1A63Z7XCH9ltwU2WMqWsVM98N2GR6MTujP7wtqdLExYN1AgMBAAE=\n"
    "-----END RSA PUBLIC KEY-----\n";

  const char *end = str + strlen(str);
  const char **s = (const char **)&str;
  directory_token_t *token = NULL;
  directory_token_t *token2 = NULL;

  token_rule_t rule = T1("onion-key", R_IPO_ONION_KEY, NO_ARGS, NEED_KEY_1024);

  token = get_next_token(area, s, end, &rule);

  tt_int_op(token->tp, OP_EQ, R_IPO_ONION_KEY);
  tt_int_op(token->n_args, OP_EQ, 0);
  tt_str_op(token->object_type, OP_EQ, "RSA PUBLIC KEY");
  tt_int_op(token->object_size, OP_EQ, 0);
  tt_assert(!token->object_body);
  tt_assert(token->key);
  tt_assert(!token->error);

  const char *str2 =
    "client-key\n"
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIICXAIBAAKBgQCwS810a2auH2PQchOBz9smNgjlDu31aq0IYlUohSYbhcv5AJ+d\n"
    "DY0nfZWzS+mZPwzL3UiEnTt6PVv7AgoZ5V9ZJWJTKIURjJpkK0mstfJKHKIZhf84\n"
    "pmFfRej9GQViB6NLtp1obOXJgJixSlMfw9doDI4NoAnEISCyH/tD77Qs2wIDAQAB\n"
    "AoGAbDg8CKkdQOnX9c7xFpCnsE8fKqz9eddgHHNwXw1NFTwOt+2gDWKSMZmv2X5S\n"
    "CVZg3owZxf5W0nT0D6Ny2+6nliak7foYAvkD0BsCiBhgftwC0zAo6k5rIbUKB3PJ\n"
    "QLFXgpJhqWuXkODyt/hS/GTernR437WVSEGp1bnALqiFabECQQDaqHOxzoWY/nvH\n"
    "KrfUi8EhqCnqERlRHwrW0MQZ1RPvF16OPPma+xa+ht/amfh3vYN5tZY82Zm43gGl\n"
    "XWL5cZhNAkEAzmdSootYVnqLLLRMfHKXnO1XbaEcA/08MDNKGlSclBJixFenE8jX\n"
    "iQsUbHwMJuGONvzWpRGPBP2f8xBd28ZtxwJARY+LZshtpfNniz/ixYJESaHG28je\n"
    "xfjbKOW3TQSFV+2WTifFvHEeljQwKMoMyoMGvYRwLCGJjs9JtMLVxsdFjQJBAKwD\n"
    "3BBvBQ39TuPQ1zWX4tb7zjMlY83HTFP3Sriq71tP/1QWoL2SUl56B2lp8E6vB/C3\n"
    "wsMK4SCNprHRYAd7VZ0CQDKn6Zhd11P94PLs0msybFEh1VXr6CEW/BrxBgbL4ls6\n"
    "dbX5XO0z4Ra8gYXgObgimhyMDYO98Idt5+Z3HIdyrSc=\n"
    "-----END RSA PRIVATE KEY-----\n";

  const char *end2 = str2 + strlen(str2);
  const char **s2 = (const char **)&str2;

  token_rule_t rule2 = T01("client-key", C_CLIENT_KEY, NO_ARGS,
                           NEED_SKEY_1024);

  token2 = get_next_token(area, s2, end2, &rule2);

  tt_int_op(token2->tp, OP_EQ, C_CLIENT_KEY);
  tt_int_op(token2->n_args, OP_EQ, 0);
  tt_str_op(token2->object_type, OP_EQ, "RSA PRIVATE KEY");
  tt_int_op(token2->object_size, OP_EQ, 0);
  tt_assert(!token2->object_body);
  tt_assert(token2->key);
  tt_assert(!token->error);

 done:
  if (token) token_clear(token);
  if (token2) token_clear(token2);
  memarea_drop_all(area);
}

#define PARSECOMMON_TEST(name) \
  { #name, test_parsecommon_ ## name, 0, NULL, NULL }

struct testcase_t parsecommon_tests[] = {
  PARSECOMMON_TEST(tokenize_string_null),
  PARSECOMMON_TEST(get_next_token_success),
  PARSECOMMON_TEST(get_next_token_concat_args),
  PARSECOMMON_TEST(get_next_token_parse_keys),
  END_OF_TESTCASES
};

