/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * /src/NTP/REPOSITORY/v4/libparse/parse_conf.c,v 3.24 1997/01/19 12:44:45 kardel Exp
 *  
 * parse_conf.c,v 3.24 1997/01/19 12:44:45 kardel Exp
 *
 * Parser configuration module for reference clocks
 *
 * STREAM define switches between two personalities of the module
 * if STREAM is defined this module can be used with dcf77sync.c as
 * a STREAMS kernel module. In this case the time stamps will be
 * a struct timeval.
 * when STREAM is not defined NTP time stamps will be used.
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

#if defined(REFCLOCK) && (defined(PARSE) || defined(PARSEPPS))

#include <sys/types.h>
#include <sys/time.h>
#include <sys/errno.h>
#include "ntp_fp.h"
#include "ntp_unixtime.h"
#include "ntp_calendar.h"

#include "parse.h"

#ifdef CLOCK_SCHMID
extern clockformat_t clock_schmid;
#endif

#ifdef CLOCK_DCF7000
extern clockformat_t clock_dcf7000;
#endif

#ifdef CLOCK_MEINBERG
extern clockformat_t clock_meinberg[];
#endif

#ifdef CLOCK_RAWDCF
extern clockformat_t clock_rawdcf;
#endif

#ifdef CLOCK_TRIMTAIP
extern clockformat_t clock_trimtaip;
#endif

#ifdef CLOCK_TRIMTSIP
extern clockformat_t clock_trimtsip;
#endif

#ifdef CLOCK_RCC8000
extern clockformat_t clock_rcc8000;
#endif

#ifdef CLOCK_HOPF6021
extern clockformat_t clock_hopf6021;
#endif

#ifdef CLOCK_COMPUTIME
extern clockformat_t clock_computime;
#endif

/*
 * format definitions
 */
clockformat_t *clockformats[] =
{
#ifdef CLOCK_MEINBERG
  &clock_meinberg[0],
  &clock_meinberg[1],
  &clock_meinberg[2],
#endif
#ifdef CLOCK_DCF7000
  &clock_dcf7000,
#endif
#ifdef CLOCK_SCHMID
  &clock_schmid,
#endif
#ifdef CLOCK_RAWDCF
  &clock_rawdcf,
#endif
#ifdef CLOCK_TRIMTAIP
  &clock_trimtaip,
#endif
#if defined(CLOCK_TRIMTSIP) && !defined(PARSESTREAM)
  &clock_trimtsip,
#endif
#ifdef CLOCK_RCC8000
  &clock_rcc8000,
#endif
#ifdef CLOCK_HOPF6021
  &clock_hopf6021,
#endif
#ifdef CLOCK_COMPUTIME
  &clock_computime,
#endif
0};

unsigned short nformats = sizeof(clockformats) / sizeof(clockformats[0]) - 1;

#else /* not (REFCLOCK && (PARSE || PARSEPPS)) */
int parse_conf_bs;
#endif /* not (REFCLOCK && (PARSE || PARSEPPS)) */

/*
 * History:
 *
 * parse_conf.c,v
 * Revision 3.24  1997/01/19 12:44:45  kardel
 * 3-5.88.1 reconcilation
 *
 * Revision 3.23  1996/12/01 16:04:17  kardel
 * freeze for 5.86.12.2 PARSE-Patch
 *
 * Revision 3.22  1996/11/30 20:45:19  kardel
 * initial compilable SunOS 4 version of parse autoconfigure
 *
 * Revision 3.21  1996/11/24 20:09:49  kardel
 * RELEASE_5_86_12_2 reconcilation
 *
 * Revision 3.20  1996/11/16 19:12:51  kardel
 * Added DIEM receiver
 *
 * Revision 3.19  1996/10/05 13:30:22  kardel
 * general update
 *
 * Revision 3.18  1995/12/17  18:08:54  kardel
 * Hopf 6021 added - base code
 *
 * Revision 3.17  1994/10/03  21:59:35  kardel
 * 3.4e cleanup/integration
 *
 * Revision 3.16  1994/10/03  10:04:16  kardel
 * 3.4e reconcilation
 *
 * Revision 3.15  1994/02/02  17:45:32  kardel
 * rcs ids fixed
 *
 * Revision 3.13  1994/01/25  19:05:23  kardel
 * 94/01/23 reconcilation
 *
 * Revision 3.12  1994/01/23  17:22:02  kardel
 * 1994 reconcilation
 *
 * Revision 3.11  1993/11/01  20:00:24  kardel
 * parse Solaris support (initial version)
 *
 * Revision 3.10  1993/10/09  15:01:37  kardel
 * file structure unified
 *
 * Revision 3.9  1993/09/26  23:40:19  kardel
 * new parse driver logic
 *
 * Revision 3.8  1993/09/02  23:20:57  kardel
 * dragon extiction
 *
 * Revision 3.7  1993/09/01  21:44:52  kardel
 * conditional cleanup
 *
 * Revision 3.6  1993/09/01  11:25:09  kardel
 * patch accident 8-(
 *
 * Revision 3.5  1993/08/31  22:31:14  kardel
 * SINIX-M SysVR4 integration
 *
 * Revision 3.4  1993/08/27  00:29:42  kardel
 * compilation cleanup
 *
 * Revision 3.3  1993/07/14  09:04:45  kardel
 * only when REFCLOCK && PARSE is defined
 *
 * Revision 3.2  1993/07/09  11:37:13  kardel
 * Initial restructured version + GPS support
 *
 * Revision 3.1  1993/07/06  10:00:11  kardel
 * DCF77 driver goes generic...
 *
 */
