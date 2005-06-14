/*
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
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
 
#define	NEED_SOCKETS
#include <k5-int.h>

#ifdef macintosh

/* We're a Macintosh -- do Mac time things.  */

/*
 * This code is derived from kerberos/src/lib/des/mac_time.c from
 * the Cygnus Support release of Kerberos V4:
 *
 * mac_time.c
 * (Originally time_stuff.c)
 * Copyright 1989 by the Massachusetts Institute of Technology.
 * Macintosh ooperating system interface for Kerberos.
 */

#include <ConditionalMacros.h>
#include <script.h>		/* Defines MachineLocation, used by getTimeZoneOffset */
#include <ToolUtils.h>		/* Defines BitTst(), called by getTimeZoneOffset() */
#include <OSUtils.h>		/* Defines GetDateTime */
#include <DriverServices.h> /* Nanosecond timing */
#include <CodeFragments.h>	/* Check for presence of UpTime */
#include <Math64.h>			/* 64-bit integer math */

/* Mac Cincludes */
#include <string.h>
#include <stddef.h>

static krb5_int32 last_sec = 0, last_usec = 0;

/* Check for availability of microseconds or better timer */
Boolean HaveAccurateTime ();

/* Convert nanoseconds to date and time */
void AbsoluteToSecsNanosecs (
      AbsoluteTime		eventTime,              /* Value to convert   */
      UInt32			*eventSeconds,         /* Result goes here   */
      UInt32			*residualNanoseconds    /* Fractional second  */
   );

/*
 * The Unix epoch is 1/1/70, the Mac epoch is 1/1/04.
 *
 * 70 - 4 = 66 year differential
 *
 * Thus the offset is:
 *
 * (66 yrs) * (365 days/yr) * (24 hours/day) * (60 mins/hour) * (60 secs/min)
 * plus
 * (17 leap days) * (24 hours/day) * (60 mins/hour) * (60 secs/min)
 *
 * Don't forget the offset from GMT.
 */

/* returns the offset in hours between the mac local time and the GMT  */
/* unsigned krb5_int32 */
krb5_int32
getTimeZoneOffset()
{
    MachineLocation macLocation;
    long gmtDelta;

    macLocation.u.gmtDelta=0L;
    ReadLocation(&macLocation); 
    gmtDelta=macLocation.u.gmtDelta & 0x00FFFFFF;
    if (BitTst((void *)&gmtDelta,23L))
	gmtDelta |= 0xFF000000;
    gmtDelta /= 3600L;
    return(gmtDelta);
}

/* Returns the GMT in seconds (and fake microseconds) using the Unix epoch */

/*
 * Note that unix timers are guaranteed that consecutive calls to timing functions will
 * always return monotonically increasing values for time; even if called within one microsecond,
 * they must increase from one call to another. We must preserve this property in this code,
 * even though Mac UpTime does not make such guarantees... (actually it does, but it measures in 
 * units that can be finer than 1 microsecond, so conversion can cause repeat microsecond values
 */

krb5_error_code
krb5_crypto_us_timeofday(seconds, microseconds)
    krb5_int32 *seconds, *microseconds;
{
    krb5_int32 sec, usec;
    time_t the_time;

    GetDateTime (&the_time);

    sec = the_time - 
    	((66 * 365 * 24 * 60 * 60) + (17 *  24 * 60 * 60) + 
    	(getTimeZoneOffset() * 60 * 60));

#if TARGET_CPU_PPC	    						/* Only PPC has accurate time */
    if (HaveAccurateTime ()) {					/* Does hardware support accurate time? */
    
    	AbsoluteTime 	absoluteTime;
    	UInt32			nanoseconds;
    	
    	absoluteTime = UpTime ();
    	AbsoluteToSecsNanosecs (absoluteTime, &sec, &nanoseconds);
    	
    	usec = nanoseconds / 1000;
    } else
#endif /* TARGET_CPU_PPC */
    {
	    GetDateTime (&sec);
	    usec = 0;
	}
	
	/* Fix secs to UNIX epoch */
	
    sec -= ((66 * 365 * 24 * 60 * 60) + (17 *  24 * 60 * 60) + 
    	(getTimeZoneOffset() * 60 * 60));

	/* Make sure that we are _not_ repeating */
	
	if (sec < last_sec) {	/* Seconds should be at least equal to last seconds */
		sec = last_sec;
	}
	
	if (sec == last_sec) {			/* Same seconds as last time? */
		if (usec <= last_usec) {	/* Yep, microseconds must be bigger than last time*/
			usec = last_usec + 1;
		}
		
		if (usec >= 1000000) {		/* handle 1e6 wraparound */
			sec++;
			usec = 0;
		}
	}

    last_sec = sec;						/* Remember for next time */
    last_usec = usec;

    *seconds = sec;
    *microseconds = usec;					/* Return the values */

    return 0;
}

/* Check if we have microsecond or better timer */

Boolean HaveAccurateTime ()
{
	static	Boolean alreadyChecked = false;
	static	haveAccurateTime = false;
	
	if (!alreadyChecked) {
		alreadyChecked = true;
		haveAccurateTime = false;
#if TARGET_CPU_PPC
		if ((Ptr) UpTime != (Ptr) kUnresolvedCFragSymbolAddress) {
			UInt32	minAbsoluteTimeDelta;
			UInt32	theAbsoluteTimeToNanosecondNumerator;
			UInt32	theAbsoluteTimeToNanosecondDenominator;
			UInt32	theProcessorToAbsoluteTimeNumerator;
			UInt32	theProcessorToAbsoluteTimeDenominator;

			GetTimeBaseInfo (
				&minAbsoluteTimeDelta,
				&theAbsoluteTimeToNanosecondNumerator,
				&theAbsoluteTimeToNanosecondDenominator,
				&theProcessorToAbsoluteTimeNumerator,
				&theProcessorToAbsoluteTimeDenominator);
				
			/* minAbsoluteTimeDelta is the period in which Uptime is updated, in absolute time */
			/* We convert it to nanoseconds and compare it with .5 microsecond */
			
			if (minAbsoluteTimeDelta * theAbsoluteTimeToNanosecondNumerator <
				500 * theAbsoluteTimeToNanosecondDenominator) {
				haveAccurateTime = true;
			}
		}
#endif /* TARGET_CPU_PPC */
	}
	
	return haveAccurateTime;
}

/* Convert nanoseconds to date and time */

void AbsoluteToSecsNanosecs (
      AbsoluteTime		eventTime,              /* Value to convert   */
      UInt32			*eventSeconds,         /* Result goes here   */
      UInt32			*residualNanoseconds    /* Fractional second  */
   )
{
   UInt64					eventNanoseconds;
   UInt64					eventSeconds64;
   static const UInt64		kTenE9 = U64SetU (1000000000);
   static UInt64			gNanosecondsAtStart = U64SetU (0);

   /*
    * If this is the first call, compute the offset between
    * GetDateTime and UpTime.
    */
   if (U64Compare (gNanosecondsAtStart, U64SetU (0)) == 0) {
      UInt32				secondsAtStart;
      AbsoluteTime			absoluteTimeAtStart;
      UInt64				upTimeAtStart;
	  UInt64				nanosecondsAtStart;

      GetDateTime (&secondsAtStart);
      upTimeAtStart = UnsignedWideToUInt64 (AbsoluteToNanoseconds (UpTime()));
	  nanosecondsAtStart = U64SetU (secondsAtStart);
      nanosecondsAtStart = U64Multiply (nanosecondsAtStart, kTenE9);
      gNanosecondsAtStart = U64Subtract (nanosecondsAtStart, upTimeAtStart);
   }
   /*
    * Convert the event time (UpTime value) to nanoseconds and add
    * the local time epoch.
    */
   eventNanoseconds = UnsignedWideToUInt64 (AbsoluteToNanoseconds (eventTime));
   eventNanoseconds = U64Add (gNanosecondsAtStart, eventNanoseconds);
   /*
    * eventSeconds = eventNanoseconds /= 10e9;
    * residualNanoseconds = eventNanoseconds % 10e9;
    * Finally, compute the local time (seconds) and fraction.
    */
   eventSeconds64 = U64Div (eventNanoseconds, kTenE9);
   eventNanoseconds = U64Subtract (eventNanoseconds, U64Multiply (eventSeconds64, kTenE9));
   *eventSeconds = (UInt64ToUnsignedWide (eventSeconds64)).lo;
   *residualNanoseconds = (UInt64ToUnsignedWide (eventNanoseconds)).lo;
}
#elif defined(_WIN32)

   /* Microsoft Windows NT and 95   (32bit)  */
   /* This one works for WOW (Windows on Windows, ntvdm on Win-NT) */

#include <time.h>
#include <sys/timeb.h>
#include <string.h>

krb5_error_code
krb5_crypto_us_timeofday(seconds, microseconds)
register krb5_int32 *seconds, *microseconds;
{
    struct _timeb timeptr;
    krb5_int32 sec, usec;
    static krb5_int32 last_sec = 0;
    static krb5_int32 last_usec = 0;

    _ftime(&timeptr);                           /* Get the current time */
    sec  = timeptr.time;
    usec = timeptr.millitm * 1000;

    if ((sec == last_sec) && (usec <= last_usec)) { /* Same as last time??? */
        usec = ++last_usec;
        if (usec >= 1000000) {
            ++sec;
            usec = 0;
        }
    }
    last_sec = sec;                             /* Remember for next time */
    last_usec = usec;

    *seconds = sec;                             /* Return the values */
    *microseconds = usec;

    return 0;
}

#elif defined (_MSDOS)


/*
 * Originally written by John Gilmore, Cygnus Support, May '94.
 * Public Domain.
 */

#include <time.h>
#include <sys/timeb.h>
#include <dos.h>
#include <string.h>

/*
 * Time handling.  Translate Unix time calls into Kerberos internal 
 * procedure calls.
 *
 * Due to the fact that DOS time can be unreliable we have reverted
 * to using the AT hardware clock and converting it to Unix time.
 */

static time_t win_gettime ();
static long win_time_get_epoch();               /* Adjust for MSC 7.00 bug */

krb5_error_code
krb5_crypto_us_timeofday(seconds, microseconds)
register krb5_int32 *seconds, *microseconds;
{
    krb5_int32 sec, usec;
    static krb5_int32 last_sec = 0;
    static krb5_int32 last_usec = 0;

    sec = win_gettime ();                       /* Get the current time */
    usec = 0;                                   /* Can't do microseconds */

    if (sec == last_sec) {                      /* Same as last time??? */
        usec = ++last_usec;                     /* Yep, so do microseconds */
        if (usec >= 1000000) {
            ++sec;
            usec = 0;
        }
    }
    last_sec = sec;                             /* Remember for next time */
    last_usec = usec;

    *seconds = sec;                             /* Return the values */
    *microseconds = usec;

    return 0;
}


static time_t
win_gettime () {
    struct tm tm;
    union _REGS inregs;                         /* For calling BIOS */
    union _REGS outregs;
    struct _timeb now;
    time_t time;
    long convert;                               /* MSC 7.00 bug work around */

    _ftime(&now);                               /* Daylight savings time */

    /* Get time from AT hardware clock INT 0x1A, AH=2 */
    (void) memset(&inregs, 0, sizeof(inregs));
    inregs.h.ah = 2;
    _int86(0x1a, &inregs, &outregs);

    /* 0x13 = decimal 13, hence the decoding below */
    tm.tm_sec = 10 * ((outregs.h.dh & 0xF0) >> 4) + (outregs.h.dh & 0x0F);
    tm.tm_min = 10 * ((outregs.h.cl & 0xF0) >> 4) + (outregs.h.cl & 0x0F);
    tm.tm_hour = 10 * ((outregs.h.ch & 0xF0) >> 4) + (outregs.h.ch & 0x0F);

    /* Get date from AT hardware clock INT 0x1A, AH=4 */
    (void) memset(&inregs, 0, sizeof(inregs));
    inregs.h.ah = 4;
    _int86(0x1a, &inregs, &outregs);

    tm.tm_mday = 10 * ((outregs.h.dl & 0xF0) >> 4) + (outregs.h.dl & 0x0F);
    tm.tm_mon = 10 * ((outregs.h.dh & 0xF0) >> 4) + (outregs.h.dh & 0x0F) - 1;
    tm.tm_year = 10 * ((outregs.h.cl & 0xF0) >> 4) + (outregs.h.cl & 0x0F);
    tm.tm_year += 100 * ((10 * (outregs.h.ch & 0xF0) >> 4)
	            + (outregs.h.ch & 0x0F) - 19);

    tm.tm_wday = 0;
    tm.tm_yday = 0;
    tm.tm_isdst = now.dstflag;

    time = mktime(&tm);

    convert = win_time_get_epoch();
    return time + convert;

}


/*
 * This routine figures out the current time epoch and returns the
 * conversion factor.  It exists because 
 * Microloss screwed the pooch on the time() and _ftime() calls in
 * its release 7.0 libraries.  They changed the epoch to Dec 31, 1899!
 * Idiots...   We try to cope.
 */

static struct tm jan_1_70 = {0, 0, 0, 1, 0, 70};
static long epoch = 0;
static int epoch_set = 0;

long
win_time_get_epoch()
{

    if (!epoch_set) {
        epoch = 0 - mktime (&jan_1_70);	/* Seconds til 1970 localtime */
        epoch += _timezone;		/* Seconds til 1970 GMT */
        epoch_set = 1;
    }
    return epoch;
}


#else


/* We're a Unix machine -- do Unix time things.  */

#ifdef _KERNEL
#include <sys/time.h>
#else
#include <time.h>
#include <errno.h>
#endif

static struct timeval last_tv = {0, 0};

krb5_error_code
krb5_crypto_us_timeofday(seconds, microseconds)
    register krb5_int32 *seconds, *microseconds;
{
	struct timeval tv;
	timestruc_t now;

#ifndef _KERNEL
	if (gettimeofday(&tv, (struct timezone *)NULL) == -1) {
		/* failed, return errno */
		return ((krb5_error_code) errno);
	}
#else
	gethrestime(&now);
	tv.tv_sec = now.tv_sec;
	tv.tv_usec = now.tv_nsec / (NANOSEC / MICROSEC);
#endif
	if ((tv.tv_sec == last_tv.tv_sec) && (tv.tv_usec == last_tv.tv_usec)) {
		if (++last_tv.tv_usec >= 1000000) {
			last_tv.tv_usec = 0;
			last_tv.tv_sec++;
		}
		tv = last_tv;
	} else
		last_tv = tv;

	*seconds = tv.tv_sec;
	*microseconds = tv.tv_usec;
	return (0);
}

#endif
