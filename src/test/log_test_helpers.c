/* Copyright (c) 2015-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */
#define LOG_PRIVATE
#include "torlog.h"
#include "log_test_helpers.h"

/**
 * \file log_test_helpers.c
 * \brief Code to check for expected log messages during testing.
 */

static void mock_saving_logv(int severity, log_domain_mask_t domain,
                             const char *funcname, const char *suffix,
                             const char *format, va_list ap)
  CHECK_PRINTF(5, 0);

/**
 * Smartlist of all the logs we've received since we last set up
 * log capture.
 */
static smartlist_t *saved_logs = NULL;

/** Boolean: should we also send messages to the test-runner? */
static int echo_to_real_logs = 1;

/** Record logs at this level or more severe */
static int record_logs_at_level = LOG_ERR;

/**
 * As setup_capture_of_logs, but do not relay log messages into the main
 * logging system.
 *
 * Avoid using this function; use setup_capture_of_logs() instead if you
 * can. If you must use this function, then make sure you detect any
 * unexpected log messages, and treat them as test failures. */
int
setup_full_capture_of_logs(int new_level)
{
  int result = setup_capture_of_logs(new_level);
  echo_to_real_logs = 0;
  return result;
}

/**
 * Temporarily capture all the messages logged at severity <b>new_level</b> or
 * higher. Return the previous log level; you'll need to pass it into
 * teardown_capture_of_logs().
 *
 * This function does not prevent messages from being sent to the main
 * logging system.
 */
int
setup_capture_of_logs(int new_level)
{
  int previous_log = log_global_min_severity_;

  /* Only change the log_global_min_severity_ if we're making things _more_
   * verbose.  Otherwise we could prevent real log messages that the test-
   * runner wanted.
   */
  if (log_global_min_severity_ < new_level)
    log_global_min_severity_ = new_level;

  record_logs_at_level = new_level;
  mock_clean_saved_logs();
  saved_logs = smartlist_new();
  MOCK(logv, mock_saving_logv);
  echo_to_real_logs = 1;
  return previous_log;
}

/**
 * Undo setup_capture_of_logs().
 */
void
teardown_capture_of_logs(int prev)
{
  UNMOCK(logv);
  log_global_min_severity_ = prev;
  mock_clean_saved_logs();
}

/**
 * Clear all messages in mock_saved_logs()
 */
void
mock_clean_saved_logs(void)
{
  if (!saved_logs)
    return;
  SMARTLIST_FOREACH(saved_logs, mock_saved_log_entry_t *, m,
                    { tor_free(m->generated_msg); tor_free(m); });
  smartlist_free(saved_logs);
  saved_logs = NULL;
}

/**
 * Return a list of all the messages captured since the last
 * setup_[full_]capture_of_logs() call. Each log call is recorded as a
 * mock_saved_log_entry_t.
 */
const smartlist_t *
mock_saved_logs(void)
{
  return saved_logs;
}

/**
 * Return true iff there is a message recorded by log capture
 * that is exactly equal to <b>msg</b>
 */
int
mock_saved_log_has_message(const char *msg)
{
  if (saved_logs) {
    SMARTLIST_FOREACH(saved_logs, mock_saved_log_entry_t *, m,
                      {
                        if (msg && m->generated_msg &&
                            !strcmp(msg, m->generated_msg)) {
                          return 1;
                        }
                      });
  }

  return 0;
}

/**
 * Return true iff there is a message recorded by log capture
 * that contains <b>msg</b> as a substring.
 */
int
mock_saved_log_has_message_containing(const char *msg)
{
  if (saved_logs) {
    SMARTLIST_FOREACH(saved_logs, mock_saved_log_entry_t *, m,
                      {
                        if (msg && m->generated_msg &&
                            strstr(m->generated_msg, msg)) {
                          return 1;
                        }
                      });
  }

  return 0;
}


/** Return true iff the saved logs have any messages with <b>severity</b> */
int
mock_saved_log_has_severity(int severity)
{
  int has_sev = 0;
  if (saved_logs) {
    SMARTLIST_FOREACH(saved_logs, mock_saved_log_entry_t *, m,
                      {
                        if (m->severity == severity) {
                          has_sev = 1;
                        }
                      });
  }

  return has_sev;
}

/** Return true iff the the saved logs have at lease one message */
int
mock_saved_log_has_entry(void)
{
  if (saved_logs) {
    return smartlist_len(saved_logs) > 0;
  }
  return 0;
}

/* Replacement for logv: record the log message, and (maybe) send it
 * into the logging system again.
 */
static void
mock_saving_logv(int severity, log_domain_mask_t domain,
                 const char *funcname, const char *suffix,
                 const char *format, va_list ap)
{
  char *buf = tor_malloc_zero(10240);
  int n;
  n = tor_vsnprintf(buf,10240,format,ap);
  tor_assert(n < 10240-1);
  buf[n]='\n';
  buf[n+1]='\0';

  if (echo_to_real_logs) {
    tor_log(severity, domain|LD_NO_MOCK, "%s", buf);
  }

  if (severity > record_logs_at_level) {
    tor_free(buf);
    return;
  }

  if (!saved_logs)
    saved_logs = smartlist_new();

  mock_saved_log_entry_t *e = tor_malloc_zero(sizeof(mock_saved_log_entry_t));
  e->severity = severity;
  e->funcname = funcname;
  e->suffix = suffix;
  e->format = format;
  e->generated_msg = tor_strdup(buf);
  tor_free(buf);

  smartlist_add(saved_logs, e);
}
