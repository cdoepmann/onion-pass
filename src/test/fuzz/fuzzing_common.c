#define CRYPTO_ED25519_PRIVATE
#include "orconfig.h"
#include "or.h"
#include "backtrace.h"
#include "config.h"
#include "fuzzing.h"
#include "crypto.h"
#include "crypto_ed25519.h"

extern const char tor_git_revision[];
const char tor_git_revision[] = "";

static int
mock_crypto_pk_public_checksig__nocheck(const crypto_pk_t *env, char *to,
                                        size_t tolen,
                                        const char *from, size_t fromlen)
{
  tor_assert(env && to && from);
  (void)fromlen;
  /* We could look at from[0..fromlen-1] ... */
  tor_assert(tolen >= crypto_pk_keysize(env));
  memset(to, 0x01, 20);
  return 20;
}

static int
mock_crypto_pk_public_checksig_digest__nocheck(crypto_pk_t *env,
                                               const char *data,
                                               size_t datalen,
                                               const char *sig,
                                               size_t siglen)
{
  tor_assert(env && data && sig);
  (void)datalen;
  (void)siglen;
  /* We could look at data[..] and sig[..] */
  return 0;
}

static int
mock_ed25519_checksig__nocheck(const ed25519_signature_t *signature,
                      const uint8_t *msg, size_t len,
                      const ed25519_public_key_t *pubkey)
{
  tor_assert(signature && msg && pubkey);
  /* We could look at msg[0..len-1] ... */
  (void)len;
  return 0;
}

static int
mock_ed25519_checksig_batch__nocheck(int *okay_out,
                                     const ed25519_checkable_t *checkable,
                                     int n_checkable)
{
  tor_assert(checkable);
  int i;
  for (i = 0; i < n_checkable; ++i) {
    /* We could look at messages and signatures XXX */
    tor_assert(checkable[i].pubkey);
    tor_assert(checkable[i].msg);
    if (okay_out)
      okay_out[i] = 1;
  }
  return 0;
}

static int
mock_ed25519_impl_spot_check__nocheck(void)
{
  return 0;
}


void
disable_signature_checking(void)
{
  MOCK(crypto_pk_public_checksig,
       mock_crypto_pk_public_checksig__nocheck);
  MOCK(crypto_pk_public_checksig_digest,
       mock_crypto_pk_public_checksig_digest__nocheck);
  MOCK(ed25519_checksig, mock_ed25519_checksig__nocheck);
  MOCK(ed25519_checksig_batch, mock_ed25519_checksig_batch__nocheck);
  MOCK(ed25519_impl_spot_check, mock_ed25519_impl_spot_check__nocheck);
}

#ifdef LLVM_FUZZ
int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  static int initialized = 0;
  if (!initialized) {
    if (fuzz_init() < 0)
      abort();
  }

  return fuzz_main(Data, Size);
}

#else /* Not LLVM_FUZZ, so AFL. */

int
main(int argc, char **argv)
{
  size_t size;

  tor_threads_init();
  {
    struct sipkey sipkey = { 1337, 7331 };
    siphash_set_global_key(&sipkey);
  }

  /* Disable logging by default to speed up fuzzing. */
  int loglevel = LOG_ERR;

  /* Initialise logging first */
  init_logging(1);
  configure_backtrace_handler(get_version());

  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--warn")) {
      loglevel = LOG_WARN;
    } else if (!strcmp(argv[i], "--notice")) {
      loglevel = LOG_NOTICE;
    } else if (!strcmp(argv[i], "--info")) {
      loglevel = LOG_INFO;
    } else if (!strcmp(argv[i], "--debug")) {
      loglevel = LOG_DEBUG;
    }
  }

  {
    log_severity_list_t s;
    memset(&s, 0, sizeof(s));
    set_log_severity_config(loglevel, LOG_ERR, &s);
    /* ALWAYS log bug warnings. */
    s.masks[LOG_WARN-LOG_ERR] |= LD_BUG;
    add_stream_log(&s, "", fileno(stdout));
  }

  /* Make BUG() and nonfatal asserts crash */
  tor_set_failed_assertion_callback(abort);

  if (fuzz_init() < 0)
    abort();

#ifdef __AFL_HAVE_MANUAL_CONTROL
  /* Tell AFL to pause and fork here - ignored if not using AFL */
  __AFL_INIT();
#endif

#define MAX_FUZZ_SIZE (128*1024)
  char *input = read_file_to_str_until_eof(0, MAX_FUZZ_SIZE, &size);
  tor_assert(input);
  fuzz_main((const uint8_t*)input, size);
  tor_free(input);

  if (fuzz_cleanup() < 0)
    abort();
  return 0;
}

#endif

