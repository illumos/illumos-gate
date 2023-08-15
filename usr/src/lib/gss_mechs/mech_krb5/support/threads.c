/*
 * util/support/threads.c
 *
 * Copyright 2004,2005,2006 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * Preliminary thread support.
 */

#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include "k5-thread.h"
#include "k5-platform.h"
#include "supp-int.h"

MAKE_INIT_FUNCTION(krb5int_thread_support_init);
MAKE_FINI_FUNCTION(krb5int_thread_support_fini);

#ifndef ENABLE_THREADS /* no thread support */

static void (*destructors[K5_KEY_MAX])(void *);
struct tsd_block { void *values[K5_KEY_MAX]; };
static struct tsd_block tsd_no_threads;
static unsigned char destructors_set[K5_KEY_MAX];

int krb5int_pthread_loaded (void)
{
    return 0;
}

#elif defined(_WIN32)

static DWORD tls_idx;
static CRITICAL_SECTION key_lock;
struct tsd_block {
  void *values[K5_KEY_MAX];
};
static void (*destructors[K5_KEY_MAX])(void *);
static unsigned char destructors_set[K5_KEY_MAX];

void krb5int_thread_detach_hook (void)
{
    /* XXX Memory leak here!
       Need to destroy all TLS objects we know about for this thread.  */
    struct tsd_block *t;
    int i, err;

    err = CALL_INIT_FUNCTION(krb5int_thread_support_init);
    if (err)
	return;

    t = TlsGetValue(tls_idx);
    if (t == NULL)
	return;
    for (i = 0; i < K5_KEY_MAX; i++) {
	if (destructors_set[i] && destructors[i] && t->values[i]) {
	    void *v = t->values[i];
	    t->values[i] = 0;
	    (*destructors[i])(v);
	}
    }
}

/* Stub function not used on Windows. */
int krb5int_pthread_loaded (void)
{
    return 0;
}
#else /* POSIX threads */

/* Must support register/delete/register sequence, e.g., if krb5 is
   loaded so this support code stays in the process, and gssapi is
   loaded, unloaded, and loaded again.  */

static k5_mutex_t key_lock = K5_MUTEX_PARTIAL_INITIALIZER;
static void (*destructors[K5_KEY_MAX])(void *);
static unsigned char destructors_set[K5_KEY_MAX];

/* This is not safe yet!

   Thread termination concurrent with key deletion can cause two
   threads to interfere.  It's a bit tricky, since one of the threads
   will want to remove this structure from the list being walked by
   the other.

   Other cases, like looking up data while the library owning the key
   is in the process of being unloaded, we don't worry about.  */

struct tsd_block {
    struct tsd_block *next;
    void *values[K5_KEY_MAX];
};

#ifdef HAVE_PRAGMA_WEAK_REF
# pragma weak pthread_getspecific
# pragma weak pthread_setspecific
# pragma weak pthread_key_create
# pragma weak pthread_key_delete
# pragma weak pthread_create
# pragma weak pthread_join
static volatile int flag_pthread_loaded = -1;
static void loaded_test_aux(void)
{
    if (flag_pthread_loaded == -1)
	flag_pthread_loaded = 1;
    else
	/* Could we have been called twice?  */
	flag_pthread_loaded = 0;
}
static pthread_once_t loaded_test_once = PTHREAD_ONCE_INIT;
int krb5int_pthread_loaded (void)
{
    int x = flag_pthread_loaded;
    if (x != -1)
	return x;
    if (&pthread_getspecific == 0
	|| &pthread_setspecific == 0
	|| &pthread_key_create == 0
	|| &pthread_key_delete == 0
	|| &pthread_once == 0
	|| &pthread_mutex_lock == 0
	|| &pthread_mutex_unlock == 0
	|| &pthread_mutex_destroy == 0
	|| &pthread_mutex_init == 0
	|| &pthread_self == 0
	|| &pthread_equal == 0
	/* Any program that's really multithreaded will have to be
	   able to create threads.  */
	|| &pthread_create == 0
	|| &pthread_join == 0
	/* Okay, all the interesting functions -- or stubs for them --
	   seem to be present.  If we call pthread_once, does it
	   actually seem to cause the indicated function to get called
	   exactly one time?  */
	|| pthread_once(&loaded_test_once, loaded_test_aux) != 0
	|| pthread_once(&loaded_test_once, loaded_test_aux) != 0
	/* This catches cases where pthread_once does nothing, and
	   never causes the function to get called.  That's a pretty
	   clear violation of the POSIX spec, but hey, it happens.  */
	|| flag_pthread_loaded < 0) {
	flag_pthread_loaded = 0;
	return 0;
    }
    /* If we wanted to be super-paranoid, we could try testing whether
       pthread_get/setspecific work, too.  I don't know -- so far --
       of any system with non-functional stubs for those.  */
    return flag_pthread_loaded;
}
static struct tsd_block tsd_if_single;
# define GET_NO_PTHREAD_TSD()	(&tsd_if_single)
#else
# define GET_NO_PTHREAD_TSD()	(abort(),(struct tsd_block *)0)
#endif

static pthread_key_t key;
static void thread_termination(void *);

static void thread_termination (void *tptr)
{
    int err = k5_mutex_lock(&key_lock);
    if (err == 0) {
        int i, pass, none_found;
        struct tsd_block *t = tptr;

        /* Make multiple passes in case, for example, a libkrb5 cleanup
            function wants to print out an error message, which causes
            com_err to allocate a thread-specific buffer, after we just
            freed up the old one.

            Shouldn't actually happen, if we're careful, but check just in
            case.  */

        pass = 0;
        none_found = 0;
        while (pass < 4 && !none_found) {
            none_found = 1;
            for (i = 0; i < K5_KEY_MAX; i++) {
                if (destructors_set[i] && destructors[i] && t->values[i]) {
                    void *v = t->values[i];
                    t->values[i] = 0;
                    (*destructors[i])(v);
                    none_found = 0;
                }
            }
        }
        free (t);
        err = k5_mutex_unlock(&key_lock);
   }

    /* remove thread from global linked list */
}

#endif /* no threads vs Win32 vs POSIX */

void *k5_getspecific (k5_key_t keynum)
{
    struct tsd_block *t;
    int err;

    err = CALL_INIT_FUNCTION(krb5int_thread_support_init);
    if (err)
	return NULL;

    assert(keynum >= 0 && keynum < K5_KEY_MAX);
    assert(destructors_set[keynum] == 1);

#ifndef ENABLE_THREADS

    t = &tsd_no_threads;

#elif defined(_WIN32)

    t = TlsGetValue(tls_idx);

#else /* POSIX */

    if (K5_PTHREADS_LOADED)
	t = pthread_getspecific(key);
    else
	t = GET_NO_PTHREAD_TSD();

#endif

    if (t == NULL)
	return NULL;
    return t->values[keynum];
}

int k5_setspecific (k5_key_t keynum, void *value)
{
    struct tsd_block *t;
    int err;

    err = CALL_INIT_FUNCTION(krb5int_thread_support_init);
    if (err)
	return err;

    assert(keynum >= 0 && keynum < K5_KEY_MAX);
    assert(destructors_set[keynum] == 1);

#ifndef ENABLE_THREADS

    t = &tsd_no_threads;

#elif defined(_WIN32)

    t = TlsGetValue(tls_idx);
    if (t == NULL) {
	int i;
	t = malloc(sizeof(*t));
	if (t == NULL)
	    return errno;
	for (i = 0; i < K5_KEY_MAX; i++)
	    t->values[i] = 0;
	/* add to global linked list */
	/*	t->next = 0; */
	err = TlsSetValue(tls_idx, t);
	if (!err) {
	    free(t);
	    return GetLastError();
	}
    }

#else /* POSIX */

    if (K5_PTHREADS_LOADED) {
	t = pthread_getspecific(key);
	if (t == NULL) {
	    int i;
	    t = malloc(sizeof(*t));
	    if (t == NULL)
		return errno;
	    for (i = 0; i < K5_KEY_MAX; i++)
		t->values[i] = 0;
	    /* add to global linked list */
	    t->next = 0;
	    err = pthread_setspecific(key, t);
	    if (err) {
		free(t);
		return err;
	    }
	}
    } else {
	t = GET_NO_PTHREAD_TSD();
    }

#endif

    t->values[keynum] = value;
    return 0;
}

int k5_key_register (k5_key_t keynum, void (*destructor)(void *))
{
    int err;

    err = CALL_INIT_FUNCTION(krb5int_thread_support_init);
    if (err)
	return err;

    assert(keynum >= 0 && keynum < K5_KEY_MAX);

#ifndef ENABLE_THREADS

    assert(destructors_set[keynum] == 0);
    destructors[keynum] = destructor;
    destructors_set[keynum] = 1;
    err = 0;

#elif defined(_WIN32)

    /* XXX: This can raise EXCEPTION_POSSIBLE_DEADLOCK.  */
    EnterCriticalSection(&key_lock);
    assert(destructors_set[keynum] == 0);
    destructors_set[keynum] = 1;
    destructors[keynum] = destructor;
    LeaveCriticalSection(&key_lock);
    err = 0;

#else /* POSIX */

    err = k5_mutex_lock(&key_lock);
    if (err == 0) {
	assert(destructors_set[keynum] == 0);
	destructors_set[keynum] = 1;
	destructors[keynum] = destructor;
	err = k5_mutex_unlock(&key_lock);
    }

#endif
    return 0;
}

int k5_key_delete (k5_key_t keynum)
{
    assert(keynum >= 0 && keynum < K5_KEY_MAX);

#ifndef ENABLE_THREADS

    assert(destructors_set[keynum] == 1);
    if (destructors[keynum] && tsd_no_threads.values[keynum])
	(*destructors[keynum])(tsd_no_threads.values[keynum]);
    destructors[keynum] = 0;
    tsd_no_threads.values[keynum] = 0;
    destructors_set[keynum] = 0;

#elif defined(_WIN32)

    /* XXX: This can raise EXCEPTION_POSSIBLE_DEADLOCK.  */
    EnterCriticalSection(&key_lock);
    /* XXX Memory leak here!
       Need to destroy the associated data for all threads.
       But watch for race conditions in case threads are going away too.  */
    assert(destructors_set[keynum] == 1);
    destructors_set[keynum] = 0;
    destructors[keynum] = 0;
    LeaveCriticalSection(&key_lock);

#else /* POSIX */

    {
	int err;

	/* XXX RESOURCE LEAK:

	   Need to destroy the allocated objects first!  */

	err = k5_mutex_lock(&key_lock);
	if (err == 0) {
	    assert(destructors_set[keynum] == 1);
	    destructors_set[keynum] = 0;
	    destructors[keynum] = NULL;
	    k5_mutex_unlock(&key_lock);
	}
    }

#endif

    return 0;
}

int krb5int_call_thread_support_init (void)
{
    return CALL_INIT_FUNCTION(krb5int_thread_support_init);
}

#include "cache-addrinfo.h"

#ifdef DEBUG_THREADS_STATS
#include <stdio.h>
static FILE *stats_logfile;
#endif

int krb5int_thread_support_init (void)
{
    int err;

#ifdef SHOW_INITFINI_FUNCS
    printf("krb5int_thread_support_init\n");
#endif

#ifdef DEBUG_THREADS_STATS
    /*    stats_logfile = stderr; */
    stats_logfile = fopen("/dev/tty", "w+");
    if (stats_logfile == NULL)
      stats_logfile = stderr;
#endif

#ifndef ENABLE_THREADS

    /* Nothing to do for TLS initialization.  */

#elif defined(_WIN32)

    tls_idx = TlsAlloc();
    /* XXX This can raise an exception if memory is low!  */
    InitializeCriticalSection(&key_lock);

#else /* POSIX */

    err = k5_mutex_finish_init(&key_lock);
    if (err)
	return err;
    if (K5_PTHREADS_LOADED) {
	err = pthread_key_create(&key, thread_termination);
	if (err)
	    return err;
    }

#endif

    err = krb5int_init_fac();
    if (err)
	return err;

    err = krb5int_err_init();
    if (err)
	return err;

    return 0;
}

void krb5int_thread_support_fini (void)
{
    if (! INITIALIZER_RAN (krb5int_thread_support_init))
	return;

#ifdef SHOW_INITFINI_FUNCS
    printf("krb5int_thread_support_fini\n");
#endif

#ifndef ENABLE_THREADS

    /* Do nothing.  */

#elif defined(_WIN32)

    /* ... free stuff ... */
    TlsFree(tls_idx);
    DeleteCriticalSection(&key_lock);

#else /* POSIX */

    if (! INITIALIZER_RAN(krb5int_thread_support_init))
	return;
    if (K5_PTHREADS_LOADED)
	pthread_key_delete(key);
    /* ... delete stuff ... */
    k5_mutex_destroy(&key_lock);

#endif

#ifdef DEBUG_THREADS_STATS
    fflush(stats_logfile);
    /* XXX Should close if not stderr, in case unloading library but
       not exiting.  */
#endif

    krb5int_fini_fac();
}

#ifdef DEBUG_THREADS_STATS
void KRB5_CALLCONV
k5_mutex_lock_update_stats(k5_debug_mutex_stats *m,
			   k5_mutex_stats_tmp startwait)
{
  k5_debug_time_t now;
  k5_debug_timediff_t tdiff, tdiff2;

  now = get_current_time();
  (void) krb5int_call_thread_support_init();
  m->count++;
  m->time_acquired = now;
  tdiff = timediff(now, startwait);
  tdiff2 = tdiff * tdiff;
  if (m->count == 1 || m->lockwait.valmin > tdiff)
    m->lockwait.valmin = tdiff;
  if (m->count == 1 || m->lockwait.valmax < tdiff)
    m->lockwait.valmax = tdiff;
  m->lockwait.valsum += tdiff;
  m->lockwait.valsqsum += tdiff2;
}

void KRB5_CALLCONV
krb5int_mutex_unlock_update_stats(k5_debug_mutex_stats *m)
{
  k5_debug_time_t now = get_current_time();
  k5_debug_timediff_t tdiff, tdiff2;
  tdiff = timediff(now, m->time_acquired);
  tdiff2 = tdiff * tdiff;
  if (m->count == 1 || m->lockheld.valmin > tdiff)
    m->lockheld.valmin = tdiff;
  if (m->count == 1 || m->lockheld.valmax < tdiff)
    m->lockheld.valmax = tdiff;
  m->lockheld.valsum += tdiff;
  m->lockheld.valsqsum += tdiff2;
}

#include <math.h>
static double
get_stddev(struct k5_timediff_stats sp, int count)
{
  long double mu, mu_squared, rho_squared;
  mu = (long double) sp.valsum / count;
  mu_squared = mu * mu;
  /* SUM((x_i - mu)^2)
     = SUM(x_i^2 - 2*mu*x_i + mu^2)
     = SUM(x_i^2) - 2*mu*SUM(x_i) + N*mu^2

     Standard deviation rho^2 = SUM(...) / N.  */
  rho_squared = (sp.valsqsum - 2 * mu * sp.valsum + count * mu_squared) / count;
  return sqrt(rho_squared);
}

void KRB5_CALLCONV
krb5int_mutex_report_stats(k5_mutex_t *m)
{
  char *p;

  /* Tweak this to only record data on "interesting" locks.  */
  if (m->stats.count < 10)
    return;
  if (m->stats.lockwait.valsum < 10 * m->stats.count)
    return;

  p = strrchr(m->loc_created.filename, '/');
  if (p == NULL)
    p = m->loc_created.filename;
  else
    p++;
  fprintf(stats_logfile, "mutex @%p: created at line %d of %s\n",
	  (void *) m, m->loc_created.lineno, p);
  if (m->stats.count == 0)
    fprintf(stats_logfile, "\tnever locked\n");
  else {
    double sd_wait, sd_hold;
    sd_wait = get_stddev(m->stats.lockwait, m->stats.count);
    sd_hold = get_stddev(m->stats.lockheld, m->stats.count);
    fprintf(stats_logfile,
	    "\tlocked %d time%s; wait %lu/%f/%lu/%fus, hold %lu/%f/%lu/%fus\n",
	    m->stats.count, m->stats.count == 1 ? "" : "s",
	    (unsigned long) m->stats.lockwait.valmin,
	    (double) m->stats.lockwait.valsum / m->stats.count,
	    (unsigned long) m->stats.lockwait.valmax,
	    sd_wait,
	    (unsigned long) m->stats.lockheld.valmin,
	    (double) m->stats.lockheld.valsum / m->stats.count,
	    (unsigned long) m->stats.lockheld.valmax,
	    sd_hold);
  }
}
#else
/* On Windows, everything defined in the export list must be defined.
   The UNIX systems where we're using the export list don't seem to
   care.  */
#undef krb5int_mutex_lock_update_stats
void KRB5_CALLCONV
krb5int_mutex_lock_update_stats(k5_debug_mutex_stats *m,
				k5_mutex_stats_tmp startwait)
{
}
#undef krb5int_mutex_unlock_update_stats
void KRB5_CALLCONV
krb5int_mutex_unlock_update_stats(k5_debug_mutex_stats *m)
{
}
#undef krb5int_mutex_report_stats
void KRB5_CALLCONV
krb5int_mutex_report_stats(k5_mutex_t *m)
{
}
#endif

/* Mutex allocation functions, for use in plugins that may not know
   what options a given set of libraries was compiled with.  */
int KRB5_CALLCONV
krb5int_mutex_alloc (k5_mutex_t **m)
{
    k5_mutex_t *ptr;
    int err;

    ptr = malloc (sizeof (k5_mutex_t));
    if (ptr == NULL)
	return errno;
    err = k5_mutex_init (ptr);
    if (err) {
	free (ptr);
	return err;
    }
    *m = ptr;
    return 0;
}

void KRB5_CALLCONV
krb5int_mutex_free (k5_mutex_t *m)
{
    (void) k5_mutex_destroy (m);
    free (m);
}

/* Callable versions of the various macros.  */
int KRB5_CALLCONV
krb5int_mutex_lock (k5_mutex_t *m)
{
    return k5_mutex_lock (m);
}
int KRB5_CALLCONV
krb5int_mutex_unlock (k5_mutex_t *m)
{
    return k5_mutex_unlock (m);
}
