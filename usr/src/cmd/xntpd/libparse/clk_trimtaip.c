/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * /src/NTP/REPOSITORY/v4/libparse/clk_trimtaip.c,v 1.4 1997/01/19 12:44:41 kardel Exp
 *
 * Trimble SV6 clock support
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(REFCLOCK) && (defined(PARSE) || defined(PARSEPPS)) && defined(CLOCK_TRIMTAIP)

#include <sys/types.h>
#include <sys/time.h>
#include <sys/errno.h>
#include "ntp_fp.h"
#include "ntp_unixtime.h"
#include "ntp_calendar.h"

#include "parse.h"

/*	0000000000111111111122222222223333333	/ char
 *	0123456789012345678901234567890123456	\ posn
 *	>RTMhhmmssdddDDMMYYYYoodnnvrrrrr;*xx<	Actual
 *	----33445566600112222BB7__-_____--99-	Parse
 *	>RTM                      1     ;*  <",	Check
 */

#define	hexval(x) (('0' <= (x) && (x) <= '9') ? (x) - '0' : \
	('a' <= (x) && (x) <= 'f') ? (x) - 'a' + 10 : \
	('A' <= (x) && (x) <= 'F') ? (x) - 'A' + 10 : \
	-1)
#define	O_USEC		O_WDAY
#define	O_GPSFIX	O_FLAGS
#define	O_CHKSUM	O_UTCHOFFSET
static struct format trimsv6_fmt =
{ { { 13, 2 }, {15, 2}, { 17, 4}, /* Day, Month, Year */
    {  4, 2 }, { 6, 2}, {  8, 2}, /* Hour, Minute, Second */
    { 10, 3 }, {23, 1}, {  0, 0}, /* uSec, FIXes (WeekDAY, FLAGS, ZONE) */
    { 34, 2 }, { 0, 0}, { 21, 2}, /* cksum, -, utcS (UTC[HMS]OFFSET) */
  },
  ">RTM                      1     ;*  <",
  0
};



/* clk_trimtaip.c */
static u_long cvt_trimtaip P((char *, unsigned int, void *, clocktime_t *, void *));

clockformat_t clock_trimtaip =
{
  NULL,				/* no input handling */
  cvt_trimtaip,			/* Trimble conversion */
  syn_simple,			/* easy time stamps for RS232 (fallback) */
  pps_simple,			/* easy PPS monitoring */
  NULL,				/* no time code synthesizer monitoring */
  (void *)&trimsv6_fmt,		/* conversion configuration */
  "Trimble SV6/TAIP",
  37,				/* string buffer */
  F_START|F_END|SYNC_START|SYNC_ONE, /* paket START/END delimiter, START synchronisation, PPS ONE sampling */
  0,				/* no private data */
  { 0, 0},
  '>',
  '<',
  '\0'
};

static u_long
cvt_trimtaip(buffer, size, vf, clock, vt)
  register char          *buffer;
  register unsigned int   size;
  register void		 *vf;
  register clocktime_t   *clock;
  register void		 *vt;
{
  register struct format *format = vf;
  long gpsfix;
  u_char calc_csum = 0;
  long   recv_csum;
  int	 i;

  if (!Strok(buffer, format->fixed_string)) return CVT_NONE;
#define	OFFS(x) format->field_offsets[(x)].offset
#define	STOI(x, y) \
	Stoi(&buffer[OFFS(x)], y, \
	       format->field_offsets[(x)].length)
  if (	STOI(O_DAY,	&clock->day)	||
	STOI(O_MONTH,	&clock->month)	||
	STOI(O_YEAR,	&clock->year)	||
	STOI(O_HOUR,	&clock->hour)	||
	STOI(O_MIN,	&clock->minute)	||
	STOI(O_SEC,	&clock->second)	||
	STOI(O_USEC,	&clock->usecond)||
	STOI(O_GPSFIX,	&gpsfix)
     ) return CVT_FAIL|CVT_BADFMT;

  clock->usecond *= 1000;
  /* Check that the checksum is right */
  for (i=OFFS(O_CHKSUM)-1; i >= 0; i--) calc_csum ^= buffer[i];
  recv_csum =	(hexval(buffer[OFFS(O_CHKSUM)]) << 4) |
	 hexval(buffer[OFFS(O_CHKSUM)+1]);
  if (recv_csum < 0) return CVT_FAIL|CVT_BADTIME;
  if (((u_char) recv_csum) != calc_csum) return CVT_FAIL|CVT_BADTIME;

  clock->utcoffset = 0;

  /* What should flags be set to ? */
  clock->flags = PARSEB_UTC;

  /* if the current GPS fix is 9 (unknown), reject */
  if (0 > gpsfix || gpsfix > 9) clock->flags |= PARSEB_POWERUP;

  return CVT_OK;
}

#else /* not (REFCLOCK && (PARSE || PARSEPPS) && CLOCK_TRIMTAIP) */
int clk_trimtaip_bs;
#endif /* not (REFCLOCK && (PARSE || PARSEPPS) && CLOCK_TRIMTAIP) */

/*
 * History:
 *
 * clk_trimtaip.c,v
 * Revision 1.4  1997/01/19 12:44:41  kardel
 * 3-5.88.1 reconcilation
 *
 * Revision 1.3  1996/11/24 20:09:47  kardel
 * RELEASE_5_86_12_2 reconcilation
 *
 * Revision 1.2  1994/10/03 21:59:29  kardel
 * 3.4e cleanup/integration
 *
 * Revision 1.1.1.1  1994/08/15  11:23:00  kardel
 * Release 4b of August 14th, 1994
 *
 * Revision 3.9  1994/02/02  17:45:27  kardel
 * rcs ids fixed
 *
 * Revision 3.7  1994/01/25  19:05:17  kardel
 * 94/01/23 reconcilation
 *
 * Revision 3.6  1993/10/30  09:44:45  kardel
 * conditional compilation flag cleanup
 *
 * Revision 3.5  1993/10/09  15:01:35  kardel
 * file structure unified
 *
 * revision 3.4
 * date: 1993/10/08 14:44:51;  author: kardel;
 * trimble - initial working version
 *
 * revision 3.3
 * date: 1993/10/03 19:10:50;  author: kardel;
 * restructured I/O handling
 *
 * revision 3.2
 * date: 1993/09/27 21:07:17;  author: kardel;
 * Trimble alpha integration
 *
 * revision 3.1
 * date: 1993/09/26 23:40:29;  author: kardel;
 * new parse driver logic
 *
 */
