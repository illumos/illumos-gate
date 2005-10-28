/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* This code placed in the public domain by Mark W. Eichin */

#include <stdio.h>
#include <k5-int.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#include <time.h>
#endif

/* take a struct tm, return seconds from GMT epoch */
/* like mktime, this ignores tm_wday and tm_yday. */
/* unlike mktime, this does not set them... it only passes a return value. */

static const int days_in_month[12] = {
0,				/* jan 31 */
31,				/* feb 28 */
59,				/* mar 31 */
90,				/* apr 30 */
120,				/* may 31 */
151,				/* jun 30 */
181,				/* jul 31 */
212,				/* aug 31 */
243,				/* sep 30 */
273,				/* oct 31 */
304,				/* nov 30 */
334				/* dec 31 */
};

#define hasleapday(year) (year%400?(year%100?(year%4?0:1):0):1)

time_t gmt_mktime(struct tm *t)
{
  time_t accum;

#define assert_time(cnd) if(!(cnd)) return (time_t) -1

  /*
   * For 32-bit signed time_t centered on 1/1/1970, the range is:
   * time 0x80000000 -> Fri Dec 13 16:45:52 1901
   * time 0x7fffffff -> Mon Jan 18 22:14:07 2038
   *
   * So years 1901 and 2038 are allowable, but we can't encode all
   * dates in those years, and we're not doing overflow/underflow
   * checking for such cases.
   */
  assert_time(t->tm_year>=1);
  assert_time(t->tm_year<=138);
  assert_time(t->tm_mon>=0);
  assert_time(t->tm_mon<=11);
  assert_time(t->tm_mday>=1);
  assert_time(t->tm_mday<=31);
  assert_time(t->tm_hour>=0);
  assert_time(t->tm_hour<=23);
  assert_time(t->tm_min>=0);
  assert_time(t->tm_min<=59);
  assert_time(t->tm_sec>=0);
  assert_time(t->tm_sec<=62);

#undef assert_time


  accum = t->tm_year - 70;
  accum *= 365;			/* 365 days/normal year */

  /* add in leap day for all previous years */
  if (t->tm_year >= 70)
    accum += (t->tm_year - 69) / 4;
  else
    accum -= (72 - t->tm_year) / 4;
  /* add in leap day for this year */
  if(t->tm_mon >= 2)		/* march or later */
    if(hasleapday((t->tm_year + 1900))) accum += 1;

  accum += days_in_month[t->tm_mon];
  accum += t->tm_mday-1;	/* days of month are the only 1-based field */
  accum *= 24;			/* 24 hour/day */
  accum += t->tm_hour;
  accum *= 60;			/* 60 minute/hour */
  accum += t->tm_min;
  accum *= 60;			/* 60 seconds/minute */
  accum += t->tm_sec;

  return accum;
}
