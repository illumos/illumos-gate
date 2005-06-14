/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * /src/NTP/REPOSITORY/v4/libparse/clk_rcc8000.c,v 3.5 1997/01/19 12:44:40 kardel Exp
 *  
 * clk_rcc8000.c,v 3.5 1997/01/19 12:44:40 kardel Exp
 *
 * Radiocode Clocks Ltd RCC 8000 Intelligent Off-Air Master Clock support
 *
 * Created by R.E.Broughton from clk_trimtaip.c
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(REFCLOCK) && (defined(PARSE) || defined(PARSEPPS)) && defined(CLOCK_RCC8000)

#include <sys/types.h>
#include <sys/time.h>
#include <sys/errno.h>
#include "ntp_fp.h"
#include "ntp_unixtime.h"
#include "ntp_calendar.h"

#include "parse.h"

/* Type II Serial Output format
 *
 *	0000000000111111111122222222223	/ char
 *	0123456789012345678901234567890	\ posn
 *	HH:MM:SS.XYZ DD/MM/YY DDD W Prn   Actual
 *      33 44 55 666 00 11 22       7     Parse
 *        :  :  .      /  /          rn   Check
 *     "15:50:36.534 30/09/94 273 5 A\x0d\x0a"
 *
 * DDD - Day of year number
 *   W - Day of week number (Sunday is 0)
 * P is the Status. See comment below for details.
 */

#define	O_USEC		O_WDAY
static struct format rcc8000_fmt =
{ { { 13, 2 }, {16, 2}, { 19, 2}, /* Day, Month, Year */ 
    {  0, 2 }, { 3, 2}, {  6, 2}, /* Hour, Minute, Second */ 
    {  9, 3 }, {28, 1}, {  0, 0}, /* uSec, Status (Valid,Reject,BST,Leapyear) */  },
  "  :  :  .      /  /          \r\n", 
/*"15:50:36.534 30/09/94 273 5 A\x0d\x0a" */
  0 
};

static unsigned long cvt_rcc8000();

clockformat_t clock_rcc8000 =
{
  (unsigned long (*)())0,       /* no input handling */
  cvt_rcc8000,		/* Radiocode clock conversion */
  syn_simple,			/* easy time stamps for RS232 (fallback) */
  (unsigned long (*)())0,       /* no direct PPS monitoring */
  (unsigned long (*)())0,	/* no time code synthesizer monitoring */
  (void *)&rcc8000_fmt,		/* conversion configuration */
  "Radiocode RCC8000",
  31,				/* string buffer */
  F_END|SYNC_START, /* END delimiter, START synchronisation */
  0,				/* no private data */
  { 0, 0},
  '0',
  '\n',
  '0'
};

static unsigned long
cvt_rcc8000(buffer, size, format, clock)
  register char          *buffer;
  register int            size;
  register struct format *format;
  register clocktime_t   *clock;
{
  if (!Strok(buffer, format->fixed_string)) return CVT_NONE;
#define	OFFS(x) format->field_offsets[(x)].offset
#define STOI(x, y) Stoi(&buffer[OFFS(x)], y, format->field_offsets[(x)].length)
  if (	STOI(O_DAY,	&clock->day)	||
	STOI(O_MONTH,	&clock->month)	||
	STOI(O_YEAR,	&clock->year)	||
	STOI(O_HOUR,	&clock->hour)	||
	STOI(O_MIN,	&clock->minute)	||
	STOI(O_SEC,	&clock->second)	||
	STOI(O_USEC,	&clock->usecond)
     ) return CVT_FAIL|CVT_BADFMT;
  clock->usecond *= 1000;

  clock->utcoffset = 0;

#define RCCP buffer[28]
/*
 * buffer[28] is the ASCII representation of a hex character ( 0 through F )
 *      The four bits correspond to:
 *      8 - Valid Time
 *      4 - Reject Code
 *      2 - British Summer Time (receiver set to emit GMT all year.)
 *      1 - Leap year
 */
#define RCC8000_VALID  0x8
#define RCC8000_REJECT 0x4
#define RCC8000_BST    0x2
#define RCC8000_LEAPY  0x1

 clock->flags = 0;

 if ( (RCCP >= '0' && RCCP <= '9') || (RCCP >= 'A' && RCCP <= 'F') )
   {
     register int flag;

     flag = (RCCP >= '0' && RCCP <= '9' ) ?  RCCP - '0' : RCCP - 'A' + 10;

     if (!(flag & RCC8000_VALID))
       clock->flags |= PARSEB_POWERUP;

     clock->flags |= PARSEB_UTC; /* British special - guess why 8-) */
    
     /* other flags not used */
    }
  return CVT_OK;
}

#else  /* not (REFCLOCK && (PARSE || PARSEPPS) && CLOCK_RCC8000) */
int clk_rcc8000_bs;
#endif  /* not (REFCLOCK && (PARSE || PARSEPPS) && CLOCK_RCC8000) */

/*
 * History:
 *
 * clk_rcc8000.c,v
 * Revision 3.5  1997/01/19 12:44:40  kardel
 * 3-5.88.1 reconcilation
 *
 * Revision 3.4  1996/11/24 20:09:45  kardel
 * RELEASE_5_86_12_2 reconcilation
 *
 * Revision 3.3  1995/02/16 22:37:08  kardel
 * LONG -> long - somehow missed this bugger
 *
 * Revision 3.2  1994/10/16  18:55:52  kardel
 * integrate RCC8000 modifications from R. E. Broughton
 *
 * Revision 3.1  1994/10/03  21:59:24  kardel
 * 3.4e cleanup/integration
 *
 */
