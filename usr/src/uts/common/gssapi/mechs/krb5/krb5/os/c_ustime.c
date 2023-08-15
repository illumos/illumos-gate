/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/crypto/os/c_ustime.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * krb5_mstimeofday for BSD 4.3
 */

#include "k5-int.h"
#include "k5-thread.h"

k5_mutex_t krb5int_us_time_mutex = K5_MUTEX_PARTIAL_INITIALIZER;

struct time_now { krb5_int32 sec, usec; };

#if defined(_WIN32)

   /* Microsoft Windows NT and 95   (32bit)  */
   /* This one works for WOW (Windows on Windows, ntvdm on Win-NT) */

#include <time.h>
#include <sys/timeb.h>
#include <string.h>

static krb5_error_code
get_time_now(struct time_now *n)
{
    struct _timeb timeptr;
    _ftime(&timeptr);
    n->sec = timeptr.time;
    n->usec = timeptr.millitm * 1000;
    return 0;
}

#else

/* Everybody else is UNIX, right?  POSIX 1996 doesn't give us
   gettimeofday, but what real OS doesn't?  */

static krb5_error_code
get_time_now(struct time_now *n)
{
    struct timeval tv;
#ifdef _KERNEL
    timestruc_t now;

    gethrestime(&now);
    tv.tv_sec = now.tv_sec;
    tv.tv_usec = now.tv_nsec / (NANOSEC / MICROSEC);
#else
    if (gettimeofday(&tv, (struct timezone *)0) == -1)
	return errno;
#endif

    n->sec = tv.tv_sec;
    n->usec = tv.tv_usec;
    return 0;
}

#endif

static struct time_now last_time;

krb5_error_code
krb5_crypto_us_timeofday(krb5_int32 *seconds, krb5_int32 *microseconds)
{
    struct time_now now;
    krb5_error_code err;

    err = get_time_now(&now);
    if (err)
	return err;

    err = k5_mutex_lock(&krb5int_us_time_mutex);
    if (err)
	return err;
    /* Just guessing: If the number of seconds hasn't changed, yet the
       microseconds are moving backwards, we probably just got a third
       instance of returning the same clock value from the system, so
       the saved value was artificially incremented.

       On Windows, where we get millisecond accuracy currently, that's
       quite likely.  On UNIX, it appears that we always get new
       microsecond values, so this case should never trigger.  */
    if ((now.sec == last_time.sec) && (now.usec <= last_time.usec)) {
	/* Same as last time??? */
	now.usec = ++last_time.usec;
	if (now.usec >= 1000000) {
	    ++now.sec;
	    now.usec = 0;
	}
	/* For now, we're not worrying about the case of enough
	   returns of the same value that we roll over now.sec, and
	   the next call still gets the previous now.sec value.  */
    }
    last_time.sec = now.sec;	/* Remember for next time */
    last_time.usec = now.usec;
    (void) k5_mutex_unlock(&krb5int_us_time_mutex);

    *seconds = now.sec;
    *microseconds = now.usec;
    return 0;
}
