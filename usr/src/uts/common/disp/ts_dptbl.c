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
#include <sys/ts.h>
#include <sys/tspriocntl.h>
#include <sys/modctl.h>

/*
 * The purpose of this file is to allow a user to make their own
 * ts_dptbl. The contents of this file should be included in the
 * ts_dptbl(4) man page with proper instructions for making
 * and replacing the TS_DPTBL.kmod in modules/sched. This was the
 * only way to provide functionality equivalent to the mkboot/cunix
 * method in SVr4 without having the utilities mkboot/cunix in
 * SunOS/Svr4.
 * It is recommended that the system calls be used to change the time
 * quantums instead of re-building the module.
 * There are also other tunable time sharing parameters in here also
 * that used to be in param.c
 */

extern int ts_dispatch_extended;

static struct modlmisc modlmisc = {
	&mod_miscops, "Time sharing dispatch table"
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

#define	TSGPUP0	0	/* Global priority for TS user priority 0 */
#define	TSGPKP0	60	/* Global priority for TS kernel priority 0 */

/*
 * array of global priorities used by ts procs sleeping or
 * running in kernel mode after sleep
 */

pri_t config_ts_kmdpris[] = {
	TSGPKP0,    TSGPKP0+1,  TSGPKP0+2,  TSGPKP0+3,
	TSGPKP0+4,  TSGPKP0+5,  TSGPKP0+6,  TSGPKP0+7,
	TSGPKP0+8,  TSGPKP0+9,  TSGPKP0+10, TSGPKP0+11,
	TSGPKP0+12, TSGPKP0+13, TSGPKP0+14, TSGPKP0+15,
	TSGPKP0+16, TSGPKP0+17, TSGPKP0+18, TSGPKP0+19,
	TSGPKP0+20, TSGPKP0+21, TSGPKP0+22, TSGPKP0+23,
	TSGPKP0+24, TSGPKP0+25, TSGPKP0+26, TSGPKP0+27,
	TSGPKP0+28, TSGPKP0+29, TSGPKP0+30, TSGPKP0+31,
	TSGPKP0+32, TSGPKP0+33, TSGPKP0+34, TSGPKP0+35,
	TSGPKP0+36, TSGPKP0+37, TSGPKP0+38, TSGPKP0+39
};

tsdpent_t	config_ts_dptbl[] = {

/*	glbpri		qntm	tqexp	slprt	mxwt	lwt */

	TSGPUP0+0,	20,	 0,	50,	    0,	50,
	TSGPUP0+1,	20,	 0,	50,	    0,	50,
	TSGPUP0+2,	20,	 0,	50,	    0,	50,
	TSGPUP0+3,	20,	 0,	50,	    0,	50,
	TSGPUP0+4,	20,	 0,	50,	    0,	50,
	TSGPUP0+5,	20,	 0,	50,	    0,	50,
	TSGPUP0+6,	20,	 0,	50,	    0,	50,
	TSGPUP0+7,	20,	 0,	50,	    0,	50,
	TSGPUP0+8,	20,	 0,	50,	    0,	50,
	TSGPUP0+9,	20,	 0,	50,	    0,	50,
	TSGPUP0+10,	16,	 0,	51,	    0,	51,
	TSGPUP0+11,	16,	 1,	51,	    0,	51,
	TSGPUP0+12,	16,	 2,	51,	    0,	51,
	TSGPUP0+13,	16,	 3,	51,	    0,	51,
	TSGPUP0+14,	16,	 4,	51,	    0,	51,
	TSGPUP0+15,	16,	 5,	51,	    0,	51,
	TSGPUP0+16,	16,	 6,	51,	    0,	51,
	TSGPUP0+17,	16,	 7,	51,	    0,	51,
	TSGPUP0+18,	16,	 8,	51,	    0,	51,
	TSGPUP0+19,	16,	 9,	51,	    0,	51,
	TSGPUP0+20,	12,	10,	52,	    0,	52,
	TSGPUP0+21,	12,	11,	52,	    0,	52,
	TSGPUP0+22,	12,	12,	52,	    0,	52,
	TSGPUP0+23,	12,	13,	52,	    0,	52,
	TSGPUP0+24,	12,	14,	52,	    0,	52,
	TSGPUP0+25,	12,	15,	52,	    0,	52,
	TSGPUP0+26,	12,	16,	52,	    0,	52,
	TSGPUP0+27,	12,	17,	52,	    0,	52,
	TSGPUP0+28,	12,	18,	52,	    0,	52,
	TSGPUP0+29,	12,	19,	52,	    0,	52,
	TSGPUP0+30,	 8,	20,	53,	    0,	53,
	TSGPUP0+31,	 8,	21,	53,	    0,	53,
	TSGPUP0+32,	 8,	22,	53,	    0,	53,
	TSGPUP0+33,	 8,	23,	53,	    0,	53,
	TSGPUP0+34,	 8,	24,	53,	    0,	53,
	TSGPUP0+35,	 8,	25,	54,	    0,	54,
	TSGPUP0+36,	 8,	26,	54,	    0,	54,
	TSGPUP0+37,	 8,	27,	54,	    0,	54,
	TSGPUP0+38,	 8,	28,	54,	    0,	54,
	TSGPUP0+39,	 8,	29,	54,	    0,	54,
	TSGPUP0+40,	 4,	30,	55,	    0,	55,
	TSGPUP0+41,	 4,	31,	55,	    0,	55,
	TSGPUP0+42,	 4,	32,	55,	    0,	55,
	TSGPUP0+43,	 4,	33,	55,	    0,	55,
	TSGPUP0+44,	 4,	34,	55,	    0,	55,
	TSGPUP0+45,	 4,	35,	56,	    0,	56,
	TSGPUP0+46,	 4,	36,	57,	    0,	57,
	TSGPUP0+47,	 4,	37,	58,	    0,	58,
	TSGPUP0+48,	 4,	38,	58,	    0,	58,
	TSGPUP0+49,	 4,	39,	58,	    0,	59,
	TSGPUP0+50,	 4,	40,	58,	    0,	59,
	TSGPUP0+51,	 4,	41,	58,	    0,	59,
	TSGPUP0+52,	 4,	42,	58,	    0,	59,
	TSGPUP0+53,	 4,	43,	58,	    0,	59,
	TSGPUP0+54,	 4,	44,	58,	    0,	59,
	TSGPUP0+55,	 4,	45,	58,	    0,	59,
	TSGPUP0+56,	 4,	46,	58,	    0,	59,
	TSGPUP0+57,	 4,	47,	58,	    0,	59,
	TSGPUP0+58,	 4,	48,	58,	    0,	59,
	TSGPUP0+59,	 2,	49,	59,	32000,	59
};

/*
 * config_ts_dptbl_server[] is an alternate dispatch table that may
 * deliver better performance on large server configurations.
 * This table must be the same size as the default table, config_ts_dptbl.
 */
tsdpent_t	config_ts_dptbl_server[] = {

/*	glbpri		qntm	tqexp	slprt	mxwt	lwt */

	TSGPUP0+0,	40,	 0,	 1,	    2,	40,
	TSGPUP0+1,	38,	 0,	 2,	    2,	40,
	TSGPUP0+2,	38,	 1,	 3,	    2,	40,
	TSGPUP0+3,	38,	 1,	 4,	    2,	40,
	TSGPUP0+4,	38,	 2,	 5,	    2,	40,
	TSGPUP0+5,	38,	 2,	 6,	    2,	40,
	TSGPUP0+6,	38,	 3,	 7,	    2,	40,
	TSGPUP0+7,	38,	 3,	 8,	    2,	40,
	TSGPUP0+8,	38,	 4,	 9,	    2,	40,
	TSGPUP0+9,	38,	 4,	10,	    2,	40,
	TSGPUP0+10,	38,	 5,	11,	    2,	40,
	TSGPUP0+11,	38,	 5,	12,	    2,	40,
	TSGPUP0+12,	38,	 6,	13,	    2,	40,
	TSGPUP0+13,	38,	 6,	14,	    2,	40,
	TSGPUP0+14,	38,	 7,	15,	    2,	40,
	TSGPUP0+15,	38,	 7,	16,	    2,	40,
	TSGPUP0+16,	38,	 8,	17,	    2,	40,
	TSGPUP0+17,	38,	 8,	18,	    2,	40,
	TSGPUP0+18,	38,	 9,	19,	    2,	40,
	TSGPUP0+19,	38,	 9,	20,	    2,	40,
	TSGPUP0+20,	36,	10,	21,	    2,	40,
	TSGPUP0+21,	36,	11,	22,	    2,	40,
	TSGPUP0+22,	36,	12,	23,	    2,	40,
	TSGPUP0+23,	36,	13,	24,	    2,	40,
	TSGPUP0+24,	36,	14,	25,	    2,	40,
	TSGPUP0+25,	36,	15,	26,	    2,	40,
	TSGPUP0+26,	36,	16,	27,	    2,	40,
	TSGPUP0+27,	36,	17,	28,	    2,	40,
	TSGPUP0+28,	36,	18,	29,	    2,	40,
	TSGPUP0+29,	36,	19,	30,	    2,	40,
	TSGPUP0+30,	36,	20,	31,	    2,	40,
	TSGPUP0+31,	36,	21,	32,	    2,	40,
	TSGPUP0+32,	36,	22,	33,	    2,	40,
	TSGPUP0+33,	36,	23,	34,	    2,	40,
	TSGPUP0+34,	36,	24,	35,	    2,	40,
	TSGPUP0+35,	36,	25,	36,	    2,	40,
	TSGPUP0+36,	36,	26,	37,	    2,	40,
	TSGPUP0+37,	36,	27,	38,	    2,	40,
	TSGPUP0+38,	36,	28,	39,	    2,	40,
	TSGPUP0+39,	36,	29,	40,	    2,	40,
	TSGPUP0+40,	36,	30,	41,	    2,	41,
	TSGPUP0+41,	34,	31,	42,	    2,	42,
	TSGPUP0+42,	34,	32,	43,	    2,	43,
	TSGPUP0+43,	34,	33,	44,	    2,	44,
	TSGPUP0+44,	34,	34,	45,	    2,	45,
	TSGPUP0+45,	34,	35,	46,	    2,	46,
	TSGPUP0+46,	34,	36,	47,	    2,	47,
	TSGPUP0+47,	34,	37,	48,	    2,	48,
	TSGPUP0+48,	34,	38,	49,	    2,	49,
	TSGPUP0+49,	34,	39,	50,	    2,	50,
	TSGPUP0+50,	34,	40,	51,	    2,	51,
	TSGPUP0+51,	34,	41,	52,	    2,	52,
	TSGPUP0+52,	34,	42,	53,	    2,	53,
	TSGPUP0+53,	34,	43,	54,	    2,	54,
	TSGPUP0+54,	34,	44,	55,	    2,	55,
	TSGPUP0+55,	34,	45,	56,	    2,	56,
	TSGPUP0+56,	34,	46,	57,	    2,	57,
	TSGPUP0+57,	34,	47,	58,	    2,	58,
	TSGPUP0+58,	34,	48,	59,	    2,	59,
	TSGPUP0+59,	34,	49,	59,	    2,	59
};



pri_t config_ts_maxumdpri = sizeof (config_ts_dptbl) / sizeof (tsdpent_t) - 1;

/*
 * Return the address of config_ts_dptbl
 */
tsdpent_t *
ts_getdptbl()
{
	/*
	 * If ts_dispatch_extended is -1, set it to 0x0
	 * to choose the default TS table.
	 */
	if (ts_dispatch_extended == -1)
		ts_dispatch_extended = 0;

	/*
	 * If ts_dispatch_extended is non-zero, use the
	 * "large server style" TS dispatch table.
	 */
	if (ts_dispatch_extended)
		return (config_ts_dptbl_server);
	else
		return (config_ts_dptbl);
}

/*
 * Return the address of config_ts_kmdpris
 */
pri_t *
ts_getkmdpris()
{
	return (config_ts_kmdpris);
}

/*
 * Return the address of ts_maxumdpri
 */
pri_t
ts_getmaxumdpri()
{
	/*
	 * The config_ts_dptbl_server table must be the same size as
	 * the config_ts_dptbl table.
	 */
	/*LINTED*/
	ASSERT(sizeof (config_ts_dptbl) == sizeof (config_ts_dptbl_server));
	return (config_ts_maxumdpri);
}
