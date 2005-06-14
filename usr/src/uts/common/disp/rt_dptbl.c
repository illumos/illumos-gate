/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/proc.h>
#include <sys/priocntl.h>
#include <sys/class.h>
#include <sys/disp.h>
#include <sys/rt.h>
#include <sys/rtpriocntl.h>
#include <sys/modctl.h>

/*
 * The purpose of this file is to allow a user to make their own
 * rt_dptbl. The contents of this file should be included in the
 * rt_dptbl(4) man page with proper instructions for making
 * and replacing the RT_DPTBL.kmod in modules/sched. This was the
 * only way to provide functionality equivalent to the mkboot/cunix
 * method in SVr4 without having the utilities mkboot/cunix in
 * SunOS/Svr4.
 * It is recommended that the system calls be used to change the time
 * quantums instead of re-building the module.
 */

static struct modlmisc modlmisc = {
	&mod_miscops, "realtime dispatch table"
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, 0
};

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

#define	RTGPPRIO0	100	/* Global priority for RT priority 0 */

rtdpent_t	config_rt_dptbl[] = {

/*   	prilevel    Time quantum */

	RTGPPRIO0,	100,
	RTGPPRIO0+1,	100,
	RTGPPRIO0+2,	100,
	RTGPPRIO0+3,	100,
	RTGPPRIO0+4,	100,
	RTGPPRIO0+5,	100,
	RTGPPRIO0+6,	100,
	RTGPPRIO0+7,	100,
	RTGPPRIO0+8,	100,
	RTGPPRIO0+9,	100,
	RTGPPRIO0+10,	80,
	RTGPPRIO0+11,	80,
	RTGPPRIO0+12,	80,
	RTGPPRIO0+13,	80,
	RTGPPRIO0+14,	80,
	RTGPPRIO0+15,	80,
	RTGPPRIO0+16,	80,
	RTGPPRIO0+17,	80,
	RTGPPRIO0+18,	80,
	RTGPPRIO0+19,	80,
	RTGPPRIO0+20,	60,
	RTGPPRIO0+21,	60,
	RTGPPRIO0+22,	60,
	RTGPPRIO0+23,	60,
	RTGPPRIO0+24,	60,
	RTGPPRIO0+25,	60,
	RTGPPRIO0+26,	60,
	RTGPPRIO0+27,	60,
	RTGPPRIO0+28,	60,
	RTGPPRIO0+29,	60,
	RTGPPRIO0+30,	40,
	RTGPPRIO0+31,	40,
	RTGPPRIO0+32,	40,
	RTGPPRIO0+33,	40,
	RTGPPRIO0+34,	40,
	RTGPPRIO0+35,	40,
	RTGPPRIO0+36,	40,
	RTGPPRIO0+37,	40,
	RTGPPRIO0+38,	40,
	RTGPPRIO0+39,	40,
	RTGPPRIO0+40,	20,
	RTGPPRIO0+41,	20,
	RTGPPRIO0+42,	20,
	RTGPPRIO0+43,	20,
	RTGPPRIO0+44,	20,
	RTGPPRIO0+45,	20,
	RTGPPRIO0+46,	20,
	RTGPPRIO0+47,	20,
	RTGPPRIO0+48,	20,
	RTGPPRIO0+49,	20,
	RTGPPRIO0+50,	10,
	RTGPPRIO0+51,	10,
	RTGPPRIO0+52,	10,
	RTGPPRIO0+53,	10,
	RTGPPRIO0+54,	10,
	RTGPPRIO0+55,	10,
	RTGPPRIO0+56,	10,
	RTGPPRIO0+57,	10,
	RTGPPRIO0+58,	10,
	RTGPPRIO0+59,	10
};

/*
 * Return the address of config_rt_dptbl
 */
rtdpent_t *
rt_getdptbl()
{
	return (config_rt_dptbl);
}
