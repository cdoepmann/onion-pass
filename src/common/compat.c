/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file compat.c
 * \brief Wrappers to make calls more portable.  This code defines
 * functions such as tor_snprintf, get/set various data types,
 * renaming, setting socket options, switching user IDs.  It is basically
 * where the non-portable items are conditionally included depending on
 * the platform.
 **/

#define COMPAT_PRIVATE
#include "common/compat.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <sys/locking.h>
#endif

#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_SYS_UTIME_H
#include <sys/utime.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif

#ifdef _WIN32
#include <conio.h>
#include <wchar.h>
/* Some mingw headers lack these. :p */
#if defined(HAVE_DECL__GETWCH) && !HAVE_DECL__GETWCH
wint_t _getwch(void);
#endif
#ifndef WEOF
#define WEOF (wchar_t)(0xFFFF)
#endif
#if defined(HAVE_DECL_SECUREZEROMEMORY) && !HAVE_DECL_SECUREZEROMEMORY
static inline void
SecureZeroMemory(PVOID ptr, SIZE_T cnt)
{
  volatile char *vcptr = (volatile char*)ptr;
  while (cnt--)
    *vcptr++ = 0;
}
#endif /* defined(HAVE_DECL_SECUREZEROMEMORY) && !HAVE_DECL_SECUREZEROMEMORY */
#elif defined(HAVE_READPASSPHRASE_H)
#include <readpassphrase.h>
#else
#include "tor_readpassphrase.h"
#endif /* defined(_WIN32) || ... */

/* Includes for the process attaching prevention */
#if defined(HAVE_SYS_PRCTL_H) && defined(__linux__)
/* Only use the linux prctl;  the IRIX prctl is totally different */
#include <sys/prctl.h>
#elif defined(__APPLE__)
#include <sys/ptrace.h>
#endif /* defined(HAVE_SYS_PRCTL_H) && defined(__linux__) || ... */

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* FreeBSD needs this to know what version it is */
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif
#ifdef HAVE_SYS_SYSLIMITS_H
#include <sys/syslimits.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include "lib/log/torlog.h"
#include "common/util.h"
#include "lib/container/smartlist.h"
#include "lib/wallclock/tm_cvt.h"
#include "lib/net/address.h"
#include "lib/sandbox/sandbox.h"

/** Number of extra file descriptors to keep in reserve beyond those that we
 * tell Tor it's allowed to use. */
#define ULIMIT_BUFFER 32 /* keep 32 extra fd's beyond ConnLimit_ */

/** Learn the maximum allowed number of file descriptors, and tell the
 * system we want to use up to that number. (Some systems have a low soft
 * limit, and let us set it higher.)  We compute this by finding the largest
 * number that we can use.
 *
 * If the limit is below the reserved file descriptor value (ULIMIT_BUFFER),
 * return -1 and <b>max_out</b> is untouched.
 *
 * If we can't find a number greater than or equal to <b>limit</b>, then we
 * fail by returning -1 and <b>max_out</b> is untouched.
 *
 * If we are unable to set the limit value because of setrlimit() failing,
 * return 0 and <b>max_out</b> is set to the current maximum value returned
 * by getrlimit().
 *
 * Otherwise, return 0 and store the maximum we found inside <b>max_out</b>
 * and set <b>max_sockets</b> with that value as well.*/
int
set_max_file_descriptors(rlim_t limit, int *max_out)
{
  if (limit < ULIMIT_BUFFER) {
    log_warn(LD_CONFIG,
             "ConnLimit must be at least %d. Failing.", ULIMIT_BUFFER);
    return -1;
  }

  /* Define some maximum connections values for systems where we cannot
   * automatically determine a limit. Re Cygwin, see
   * http://archives.seul.org/or/talk/Aug-2006/msg00210.html
   * For an iPhone, 9999 should work. For Windows and all other unknown
   * systems we use 15000 as the default. */
#ifndef HAVE_GETRLIMIT
#if defined(CYGWIN) || defined(__CYGWIN__)
  const char *platform = "Cygwin";
  const unsigned long MAX_CONNECTIONS = 3200;
#elif defined(_WIN32)
  const char *platform = "Windows";
  const unsigned long MAX_CONNECTIONS = 15000;
#else
  const char *platform = "unknown platforms with no getrlimit()";
  const unsigned long MAX_CONNECTIONS = 15000;
#endif /* defined(CYGWIN) || defined(__CYGWIN__) || ... */
  log_fn(LOG_INFO, LD_NET,
         "This platform is missing getrlimit(). Proceeding.");
  if (limit > MAX_CONNECTIONS) {
    log_warn(LD_CONFIG,
             "We do not support more than %lu file descriptors "
             "on %s. Tried to raise to %lu.",
             (unsigned long)MAX_CONNECTIONS, platform, (unsigned long)limit);
    return -1;
  }
  limit = MAX_CONNECTIONS;
#else /* !(!defined(HAVE_GETRLIMIT)) */
  struct rlimit rlim;

  if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
    log_warn(LD_NET, "Could not get maximum number of file descriptors: %s",
             strerror(errno));
    return -1;
  }
  if (rlim.rlim_max < limit) {
    log_warn(LD_CONFIG,"We need %lu file descriptors available, and we're "
             "limited to %lu. Please change your ulimit -n.",
             (unsigned long)limit, (unsigned long)rlim.rlim_max);
    return -1;
  }

  if (rlim.rlim_max > rlim.rlim_cur) {
    log_info(LD_NET,"Raising max file descriptors from %lu to %lu.",
             (unsigned long)rlim.rlim_cur, (unsigned long)rlim.rlim_max);
  }
  /* Set the current limit value so if the attempt to set the limit to the
   * max fails at least we'll have a valid value of maximum sockets. */
  *max_out = (int)rlim.rlim_cur - ULIMIT_BUFFER;
  set_max_sockets(*max_out);
  rlim.rlim_cur = rlim.rlim_max;

  if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
    int couldnt_set = 1;
    const int setrlimit_errno = errno;
#ifdef OPEN_MAX
    uint64_t try_limit = OPEN_MAX - ULIMIT_BUFFER;
    if (errno == EINVAL && try_limit < (uint64_t) rlim.rlim_cur) {
      /* On some platforms, OPEN_MAX is the real limit, and getrlimit() is
       * full of nasty lies.  I'm looking at you, OSX 10.5.... */
      rlim.rlim_cur = MIN((rlim_t) try_limit, rlim.rlim_cur);
      if (setrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        if (rlim.rlim_cur < (rlim_t)limit) {
          log_warn(LD_CONFIG, "We are limited to %lu file descriptors by "
                   "OPEN_MAX (%lu), and ConnLimit is %lu.  Changing "
                   "ConnLimit; sorry.",
                   (unsigned long)try_limit, (unsigned long)OPEN_MAX,
                   (unsigned long)limit);
        } else {
          log_info(LD_CONFIG, "Dropped connection limit to %lu based on "
                   "OPEN_MAX (%lu); Apparently, %lu was too high and rlimit "
                   "lied to us.",
                   (unsigned long)try_limit, (unsigned long)OPEN_MAX,
                   (unsigned long)rlim.rlim_max);
        }
        couldnt_set = 0;
      }
    }
#endif /* defined(OPEN_MAX) */
    if (couldnt_set) {
      log_warn(LD_CONFIG,"Couldn't set maximum number of file descriptors: %s",
               strerror(setrlimit_errno));
    }
  }
  /* leave some overhead for logs, etc, */
  limit = rlim.rlim_cur;
#endif /* !defined(HAVE_GETRLIMIT) */

  if (limit > INT_MAX)
    limit = INT_MAX;
  tor_assert(max_out);
  *max_out = (int)limit - ULIMIT_BUFFER;
  set_max_sockets(*max_out);

  return 0;
}

/** Hold the result of our call to <b>uname</b>. */
static char uname_result[256];
/** True iff uname_result is set. */
static int uname_result_is_set = 0;

/** Return a pointer to a description of our platform.
 */
MOCK_IMPL(const char *,
get_uname,(void))
{
#ifdef HAVE_UNAME
  struct utsname u;
#endif
  if (!uname_result_is_set) {
#ifdef HAVE_UNAME
    if (uname(&u) != -1) {
      /* (Linux says 0 is success, Solaris says 1 is success) */
      strlcpy(uname_result, u.sysname, sizeof(uname_result));
    } else
#endif /* defined(HAVE_UNAME) */
      {
#ifdef _WIN32
        OSVERSIONINFOEX info;
        int i;
        const char *plat = NULL;
        static struct {
          unsigned major; unsigned minor; const char *version;
        } win_version_table[] = {
          { 6, 2, "Windows 8" },
          { 6, 1, "Windows 7" },
          { 6, 0, "Windows Vista" },
          { 5, 2, "Windows Server 2003" },
          { 5, 1, "Windows XP" },
          { 5, 0, "Windows 2000" },
          /* { 4, 0, "Windows NT 4.0" }, */
          { 4, 90, "Windows Me" },
          { 4, 10, "Windows 98" },
          /* { 4, 0, "Windows 95" } */
          { 3, 51, "Windows NT 3.51" },
          { 0, 0, NULL }
        };
        memset(&info, 0, sizeof(info));
        info.dwOSVersionInfoSize = sizeof(info);
        if (! GetVersionEx((LPOSVERSIONINFO)&info)) {
          strlcpy(uname_result, "Bizarre version of Windows where GetVersionEx"
                  " doesn't work.", sizeof(uname_result));
          uname_result_is_set = 1;
          return uname_result;
        }
        if (info.dwMajorVersion == 4 && info.dwMinorVersion == 0) {
          if (info.dwPlatformId == VER_PLATFORM_WIN32_NT)
            plat = "Windows NT 4.0";
          else
            plat = "Windows 95";
        } else {
          for (i=0; win_version_table[i].major>0; ++i) {
            if (win_version_table[i].major == info.dwMajorVersion &&
                win_version_table[i].minor == info.dwMinorVersion) {
              plat = win_version_table[i].version;
              break;
            }
          }
        }
        if (plat) {
          strlcpy(uname_result, plat, sizeof(uname_result));
        } else {
          if (info.dwMajorVersion > 6 ||
              (info.dwMajorVersion==6 && info.dwMinorVersion>2))
            tor_snprintf(uname_result, sizeof(uname_result),
                         "Very recent version of Windows [major=%d,minor=%d]",
                         (int)info.dwMajorVersion,(int)info.dwMinorVersion);
          else
            tor_snprintf(uname_result, sizeof(uname_result),
                         "Unrecognized version of Windows [major=%d,minor=%d]",
                         (int)info.dwMajorVersion,(int)info.dwMinorVersion);
        }
#ifdef VER_NT_SERVER
      if (info.wProductType == VER_NT_SERVER ||
          info.wProductType == VER_NT_DOMAIN_CONTROLLER) {
        strlcat(uname_result, " [server]", sizeof(uname_result));
      }
#endif /* defined(VER_NT_SERVER) */
#else /* !(defined(_WIN32)) */
        /* LCOV_EXCL_START -- can't provoke uname failure */
        strlcpy(uname_result, "Unknown platform", sizeof(uname_result));
        /* LCOV_EXCL_STOP */
#endif /* defined(_WIN32) */
      }
    uname_result_is_set = 1;
  }
  return uname_result;
}

/*
 *   Process control
 */

#if defined(HW_PHYSMEM64)
/* This appears to be an OpenBSD thing */
#define INT64_HW_MEM HW_PHYSMEM64
#elif defined(HW_MEMSIZE)
/* OSX defines this one */
#define INT64_HW_MEM HW_MEMSIZE
#endif /* defined(HW_PHYSMEM64) || ... */

/**
 * Helper: try to detect the total system memory, and return it. On failure,
 * return 0.
 */
static uint64_t
get_total_system_memory_impl(void)
{
#if defined(__linux__)
  /* On linux, sysctl is deprecated. Because proc is so awesome that you
   * shouldn't _want_ to write portable code, I guess? */
  unsigned long long result=0;
  int fd = -1;
  char *s = NULL;
  const char *cp;
  size_t file_size=0;
  if (-1 == (fd = tor_open_cloexec("/proc/meminfo",O_RDONLY,0)))
    return 0;
  s = read_file_to_str_until_eof(fd, 65536, &file_size);
  if (!s)
    goto err;
  cp = strstr(s, "MemTotal:");
  if (!cp)
    goto err;
  /* Use the system sscanf so that space will match a wider number of space */
  if (sscanf(cp, "MemTotal: %llu kB\n", &result) != 1)
    goto err;

  close(fd);
  tor_free(s);
  return result * 1024;

  /* LCOV_EXCL_START Can't reach this unless proc is broken. */
 err:
  tor_free(s);
  close(fd);
  return 0;
  /* LCOV_EXCL_STOP */
#elif defined (_WIN32)
  /* Windows has MEMORYSTATUSEX; pretty straightforward. */
  MEMORYSTATUSEX ms;
  memset(&ms, 0, sizeof(ms));
  ms.dwLength = sizeof(ms);
  if (! GlobalMemoryStatusEx(&ms))
    return 0;

  return ms.ullTotalPhys;

#elif defined(HAVE_SYSCTL) && defined(INT64_HW_MEM)
  /* On many systems, HW_PYHSMEM is clipped to 32 bits; let's use a better
   * variant if we know about it. */
  uint64_t memsize = 0;
  size_t len = sizeof(memsize);
  int mib[2] = {CTL_HW, INT64_HW_MEM};
  if (sysctl(mib,2,&memsize,&len,NULL,0))
    return 0;

  return memsize;

#elif defined(HAVE_SYSCTL) && defined(HW_PHYSMEM)
  /* On some systems (like FreeBSD I hope) you can use a size_t with
   * HW_PHYSMEM. */
  size_t memsize=0;
  size_t len = sizeof(memsize);
  int mib[2] = {CTL_HW, HW_USERMEM};
  if (sysctl(mib,2,&memsize,&len,NULL,0))
    return 0;

  return memsize;

#else
  /* I have no clue. */
  return 0;
#endif /* defined(__linux__) || ... */
}

/**
 * Try to find out how much physical memory the system has. On success,
 * return 0 and set *<b>mem_out</b> to that value. On failure, return -1.
 */
MOCK_IMPL(int,
get_total_system_memory, (size_t *mem_out))
{
  static size_t mem_cached=0;
  uint64_t m = get_total_system_memory_impl();
  if (0 == m) {
    /* LCOV_EXCL_START -- can't make this happen without mocking. */
    /* We couldn't find our memory total */
    if (0 == mem_cached) {
      /* We have no cached value either */
      *mem_out = 0;
      return -1;
    }

    *mem_out = mem_cached;
    return 0;
    /* LCOV_EXCL_STOP */
  }

#if SIZE_MAX != UINT64_MAX
  if (m > SIZE_MAX) {
    /* I think this could happen if we're a 32-bit Tor running on a 64-bit
     * system: we could have more system memory than would fit in a
     * size_t. */
    m = SIZE_MAX;
  }
#endif /* SIZE_MAX != UINT64_MAX */

  *mem_out = mem_cached = (size_t) m;

  return 0;
}

/** Emit the password prompt <b>prompt</b>, then read up to <b>buflen</b>
 * bytes of passphrase into <b>output</b>. Return the number of bytes in
 * the passphrase, excluding terminating NUL.
 */
ssize_t
tor_getpass(const char *prompt, char *output, size_t buflen)
{
  tor_assert(buflen <= SSIZE_MAX);
  tor_assert(buflen >= 1);
#if defined(HAVE_READPASSPHRASE)
  char *pwd = readpassphrase(prompt, output, buflen, RPP_ECHO_OFF);
  if (pwd == NULL)
    return -1;
  return strlen(pwd);
#elif defined(_WIN32)
  int r = -1;
  while (*prompt) {
    _putch(*prompt++);
  }

  tor_assert(buflen <= INT_MAX);
  wchar_t *buf = tor_calloc(buflen, sizeof(wchar_t));

  wchar_t *ptr = buf, *lastch = buf + buflen - 1;
  while (ptr < lastch) {
    wint_t ch = _getwch();
    switch (ch) {
      case '\r':
      case '\n':
      case WEOF:
        goto done_reading;
      case 3:
        goto done; /* Can't actually read ctrl-c this way. */
      case '\b':
        if (ptr > buf)
          --ptr;
        continue;
      case 0:
      case 0xe0:
        ch = _getwch(); /* Ignore; this is a function or arrow key */
        break;
      default:
        *ptr++ = ch;
        break;
    }
  }
 done_reading:
  ;

#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS 0x80
#endif

  /* Now convert it to UTF-8 */
  r = WideCharToMultiByte(CP_UTF8,
                          WC_NO_BEST_FIT_CHARS|WC_ERR_INVALID_CHARS,
                          buf, (int)(ptr-buf),
                          output, (int)(buflen-1),
                          NULL, NULL);
  if (r <= 0) {
    r = -1;
    goto done;
  }

  tor_assert(r < (int)buflen);

  output[r] = 0;

 done:
  SecureZeroMemory(buf, sizeof(wchar_t)*buflen);
  tor_free(buf);
  return r;
#else
#error "No implementation for tor_getpass found!"
#endif /* defined(HAVE_READPASSPHRASE) || ... */
}

/** Return the amount of free disk space we have permission to use, in
 * bytes. Return -1 if the amount of free space can't be determined. */
int64_t
tor_get_avail_disk_space(const char *path)
{
#ifdef HAVE_STATVFS
  struct statvfs st;
  int r;
  memset(&st, 0, sizeof(st));

  r = statvfs(path, &st);
  if (r < 0)
    return -1;

  int64_t result = st.f_bavail;
  if (st.f_frsize) {
    result *= st.f_frsize;
  } else if (st.f_bsize) {
    result *= st.f_bsize;
  } else {
    return -1;
  }

  return result;
#elif defined(_WIN32)
  ULARGE_INTEGER freeBytesAvail;
  BOOL ok;

  ok = GetDiskFreeSpaceEx(path, &freeBytesAvail, NULL, NULL);
  if (!ok) {
    return -1;
  }
  return (int64_t)freeBytesAvail.QuadPart;
#else
  (void)path;
  errno = ENOSYS;
  return -1;
#endif /* defined(HAVE_STATVFS) || ... */
}
