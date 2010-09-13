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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/proc.h>
#include <sys/priocntl.h>
#include <sys/class.h>
#include <sys/disp.h>
#include <sys/fx.h>
#include <sys/fxpriocntl.h>
#include <sys/modctl.h>

/*
 * The purpose of this file is to allow a user to make their own
 * fx_dptbl. The contents of this file should be included in the
 * fx_dptbl(4) man page with proper instructions for making
 * and replacing the FX_DPTBL in usr/kernel/sched.
 * It is recommended that the system calls be used to change the time
 * quantums instead of re-building the module.
 */

static struct modlmisc modlmisc = {
	&mod_miscops, "Fixed priority dispatch table"
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

#define	FXGPUP0	0	/* Global priority for FX user priority 0 */



fxdpent_t	config_fx_dptbl[] = {

/*	glbpri		qntm */

	FXGPUP0+0,	20,
	FXGPUP0+1,	20,
	FXGPUP0+2,	20,
	FXGPUP0+3,	20,
	FXGPUP0+4,	20,
	FXGPUP0+5,	20,
	FXGPUP0+6,	20,
	FXGPUP0+7,	20,
	FXGPUP0+8,	20,
	FXGPUP0+9,	20,
	FXGPUP0+10,	16,
	FXGPUP0+11,	16,
	FXGPUP0+12,	16,
	FXGPUP0+13,	16,
	FXGPUP0+14,	16,
	FXGPUP0+15,	16,
	FXGPUP0+16,	16,
	FXGPUP0+17,	16,
	FXGPUP0+18,	16,
	FXGPUP0+19,	16,
	FXGPUP0+20,	12,
	FXGPUP0+21,	12,
	FXGPUP0+22,	12,
	FXGPUP0+23,	12,
	FXGPUP0+24,	12,
	FXGPUP0+25,	12,
	FXGPUP0+26,	12,
	FXGPUP0+27,	12,
	FXGPUP0+28,	12,
	FXGPUP0+29,	12,
	FXGPUP0+30,	 8,
	FXGPUP0+31,	 8,
	FXGPUP0+32,	 8,
	FXGPUP0+33,	 8,
	FXGPUP0+34,	 8,
	FXGPUP0+35,	 8,
	FXGPUP0+36,	 8,
	FXGPUP0+37,	 8,
	FXGPUP0+38,	 8,
	FXGPUP0+39,	 8,
	FXGPUP0+40,	 4,
	FXGPUP0+41,	 4,
	FXGPUP0+42,	 4,
	FXGPUP0+43,	 4,
	FXGPUP0+44,	 4,
	FXGPUP0+45,	 4,
	FXGPUP0+46,	 4,
	FXGPUP0+47,	 4,
	FXGPUP0+48,	 4,
	FXGPUP0+49,	 4,
	FXGPUP0+50,	 4,
	FXGPUP0+51,	 4,
	FXGPUP0+52,	 4,
	FXGPUP0+53,	 4,
	FXGPUP0+54,	 4,
	FXGPUP0+55,	 4,
	FXGPUP0+56,	 4,
	FXGPUP0+57,	 4,
	FXGPUP0+58,	 4,
	FXGPUP0+59,	 2,
	FXGPUP0+60,	 2,
};

pri_t config_fx_maxumdpri = sizeof (config_fx_dptbl) / sizeof (fxdpent_t) - 1;

/*
 * Return the address of config_fx_dptbl
 */
fxdpent_t *
fx_getdptbl()
{
	return (config_fx_dptbl);
}


/*
 * Return the address of fx_maxumdpri
 */
pri_t
fx_getmaxumdpri()
{
	/*
	 * the config_fx_dptbl table.
	 */
	return (config_fx_maxumdpri);
}
