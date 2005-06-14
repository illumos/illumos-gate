/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * /src/NTP/REPOSITORY/v4/libparse/clk_dcf7000.c,v 3.18 1997/01/19 12:44:36 kardel Exp
 *  
 * clk_dcf7000.c,v 3.18 1997/01/19 12:44:36 kardel Exp
 *
 * ELV DCF7000 module
 *
 * Copyright (C) 1992,1993,1994,1995,1996 by Frank Kardel
 * Friedrich-Alexander Universität Erlangen-Nürnberg, Germany
 *                                    
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(REFCLOCK) && (defined(PARSE) || defined(PARSEPPS)) && defined(CLOCK_DCF7000)

#include <sys/types.h>
#include <sys/time.h>
#include <sys/errno.h>
#include "ntp_fp.h"
#include "ntp_unixtime.h"
#include "ntp_calendar.h"

#include "parse.h"

static struct format dcf7000_fmt =
{				/* ELV DCF7000 */
  {
    {  6, 2}, {  3, 2}, {  0, 2},
    { 12, 2}, { 15, 2}, { 18, 2},
    {  9, 2}, { 21, 2},
  },
  "  -  -  -  -  -  -  -  \r",
  0
};    

static u_long cvt_dcf7000 P((char *, unsigned int, void *, clocktime_t *, void *));

clockformat_t clock_dcf7000 =
{
  NULL,				/* no input handling */
  cvt_dcf7000,			/* ELV DCF77 conversion */
  syn_simple,			/* easy time stamps */
  NULL,				/* no direct PPS monitoring */
  NULL,				/* no time code synthesizer monitoring */
  (void *)&dcf7000_fmt,		/* conversion configuration */
  "ELV DCF7000",		/* ELV clock */
  24,				/* string buffer */
  F_END|SYNC_END,		/* END packet delimiter / synchronisation */
  0,				/* no private data (complete pakets) */
  { 0, 0},
  '\0',
  '\r',
  '\0'
};

/*
 * cvt_dcf7000
 *
 * convert dcf7000 type format
 */
static u_long
cvt_dcf7000(buffer, size, vf, clock, vt)
  register char          *buffer;
  register unsigned int   size;
  register void          *vf;
  register clocktime_t   *clock;
  register void          *vt;
{
  register struct format *format = vf;
  if (!Strok(buffer, format->fixed_string))
    {
      return CVT_NONE;
    }
  else
    {
      if (Stoi(&buffer[format->field_offsets[O_DAY].offset], &clock->day,
	       format->field_offsets[O_DAY].length) ||
	  Stoi(&buffer[format->field_offsets[O_MONTH].offset], &clock->month,
	       format->field_offsets[O_MONTH].length) ||
	  Stoi(&buffer[format->field_offsets[O_YEAR].offset], &clock->year,
	       format->field_offsets[O_YEAR].length) ||
	  Stoi(&buffer[format->field_offsets[O_HOUR].offset], &clock->hour,
	       format->field_offsets[O_HOUR].length) ||
	  Stoi(&buffer[format->field_offsets[O_MIN].offset], &clock->minute,
	       format->field_offsets[O_MIN].length) ||
	  Stoi(&buffer[format->field_offsets[O_SEC].offset], &clock->second,
	       format->field_offsets[O_SEC].length))
	{
	  return CVT_FAIL|CVT_BADFMT;
	}
      else
	{
	  char *f = &buffer[format->field_offsets[O_FLAGS].offset];
	  long flags;
	  
	  clock->flags = 0;
	  clock->usecond = 0;

	  if (Stoi(f, &flags, format->field_offsets[O_FLAGS].length))
	    {
	      return CVT_FAIL|CVT_BADFMT;
	    }
	  else
	    {
	      if (flags & 0x1)
		clock->utcoffset = -2*60*60;
	      else
		clock->utcoffset = -1*60*60;

	      if (flags & 0x2)
		clock->flags |= PARSEB_ANNOUNCE;

	      if (flags & 0x4)
		clock->flags |= PARSEB_NOSYNC;
	    }
	  return CVT_OK;
	}
    }
}

#else /* not (REFCLOCK && (PARSE || PARSEPPS) && CLOCK_DCF7000) */
int clk_dcf7000_bs;
#endif /* not (REFCLOCK && (PARSE || PARSEPPS) && CLOCK_DCF7000) */

/*
 * History:
 *
 * clk_dcf7000.c,v
 * Revision 3.18  1997/01/19 12:44:36  kardel
 * 3-5.88.1 reconcilation
 *
 * Revision 3.17  1996/12/01 16:04:13  kardel
 * freeze for 5.86.12.2 PARSE-Patch
 *
 * Revision 3.16  1996/11/24 20:09:42  kardel
 * RELEASE_5_86_12_2 reconcilation
 *
 * Revision 3.15  1996/10/05 13:30:19  kardel
 * general update
 *
 * Revision 3.14  1994/10/03  21:59:18  kardel
 * 3.4e cleanup/integration
 *
 * Revision 3.13  1994/10/03  10:04:02  kardel
 * 3.4e reconcilation
 *
 * Revision 3.12  1994/05/30  10:19:57  kardel
 * LONG cleanup
 *
 * Revision 3.11  1994/02/02  17:45:14  kardel
 * rcs ids fixed
 *
 * Revision 3.6  1993/10/09  15:01:27  kardel
 * file structure unified
 *
 * Revision 3.5  1993/10/03  19:10:41  kardel
 * restructured I/O handling
 *
 * Revision 3.4  1993/09/27  21:08:02  kardel
 * utcoffset now in seconds
 *
 * Revision 3.3  1993/09/26  23:40:20  kardel
 * new parse driver logic
 *
 * Revision 3.2  1993/07/09  11:37:15  kardel
 * Initial restructured version + GPS support
 *
 * Revision 3.1  1993/07/06  10:00:14  kardel
 * DCF77 driver goes generic...
 *
 */
