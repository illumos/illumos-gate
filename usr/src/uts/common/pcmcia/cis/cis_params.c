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
 * Copyright (c) 1995-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/autoconf.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/kstat.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/kobj.h>

#include <sys/pctypes.h>
#include <pcmcia/sys/cs_types.h>
#include <pcmcia/sys/cis.h>
#include <pcmcia/sys/cis_handlers.h>

/*
 *
 * The following speed tables are used by cistpl_devspeed() to generate
 *	device speeds from tuple data.
 *
 * Define the device speed table.  For a description of this table's contents,
 *	see PCMCIA Release 2.01 Card Metaformat pg. 5-14 table 5-12.
 *
 * All times in this table are in nS.
 */
uint32_t cistpl_devspeed_table[CISTPL_DEVSPEED_MAX_TBL] = {
    0,		/* 0x00 - DSPEED_NULL */
    250,	/* 0x01 - DSPEED_250NS */
    200,	/* 0x02 - DSPEED_200NS */
    150,	/* 0x03 - DSPEED_150NS */
    100,	/* 0x04 - DSPEED_100NS */
    0,		/* 0x05 - reserved */
    0,		/* 0x06 - reserved */
    0		/* 0x07 - use extended speed byte */
};

/*
 * Define the power-of-10 table.
 */
uint32_t cistpl_exspeed_tenfac[] = {
    1,		/* 10^0 */
    10,		/* 10^1 */
    100,	/* 10^2 */
    1000,	/* 10^3 */
    10000,	/* 10^4 */
    100000,	/* 10^5 */
    1000000,	/* 10^6 */
    10000000	/* 10^7	 */
};

/*
 * The extended device speed code mantissa table.
 *
 * This table is described in PCMCIA Release 2.01 Card Metaformat
 *	pg. 5-15 table 5-13.
 *
 * The description of this table uses non-integer values.  We multiply
 *	everything by 10 before it goes into the table, and the code
 *	will divide by 10 after it calculates the device speed.
 */
uint32_t cistpl_devspeed_man[CISTPL_DEVSPEED_MAX_MAN] = {
    0,		/* no units */
    10,		/* no units */
    12,		/* no units */
    13,		/* no units */
    15,		/* no units */
    20,		/* no units */
    25,		/* no units */
    30,		/* no units */
    35,		/* no units */
    40,		/* no units */
    45,		/* no units */
    50,		/* no units */
    55,		/* no units */
    60,		/* no units */
    70,		/* no units */
    80,		/* no units */
};

/*
 * The extended device speed code exponent table.
 *
 * This table is described in PCMCIA Release 2.01 Card Metaformat
 *	pg. 5-15 table 5-13.
 *
 * The description of this table uses various timing units.  This
 *	table contains all times in nS.
 */
uint32_t cistpl_devspeed_exp[CISTPL_DEVSPEED_MAX_EXP] = {
    1,		/* 1 nS */
    10,		/* 10 nS */
    100,	/* 100 nS */
    1000,	/* 1000 nS */
    10000,	/* 10000 nS */
    100000,	/* 100000 nS */
    1000000,	/* 1000000 nS */
    10000000	/* 10000000 nS */
};

/*
 * The power description mantissa table.
 *
 * This table is described in PCMCIA Release 2.01 Card Metaformat
 *	pg. 5-28 table 5-32.
 *
 * The description of this table uses non-integer values.  We multiply
 *	everything by 10 before it goes into the table, and the code
 *	will divide by 10 after it calculates the device power.
 */
uint32_t cistpl_pd_man[] = {
    10,		/* no units */
    12,		/* no units */
    13,		/* no units */
    15,		/* no units */
    20,		/* no units */
    25,		/* no units */
    30,		/* no units */
    35,		/* no units */
    40,		/* no units */
    45,		/* no units */
    50,		/* no units */
    55,		/* no units */
    60,		/* no units */
    70,		/* no units */
    80,		/* no units */
    90,		/* no units */
};

/*
 * The power description exponent table.
 *
 * This table is described in PCMCIA Release 2.01 Card Metaformat
 *	pg. 5-28 table 5-32.
 *
 * The description of this table uses various voltage and current units.
 *	This table contains all currents in nanoAMPS and all voltages
 *	in microVOLTS.
 *
 * Note if you're doing a current table lookup, you need to multiply
 *	the lookup value by ten.
 */
uint32_t cistpl_pd_exp[] = {
    10,		/* 10 microVOLTS, 100 nanoAMPS */
    100,	/* 100 microVOLTS, 1000 nanoAMPS */
    1000,	/* 1000 microVOLTS, 10000 nanoAMPS */
    10000,	/* 10000 microVOLTS, 100000 nanoAMPS */
    100000,	/* 100000 microVOLTS, 1000000 nanoAMPS */
    1000000,	/* 1000000 microVOLTS, 10000000 nanoAMPS */
    10000000,	/* 10000000 microVOLTS, 100000000 nanoAMPS */
    100000000	/* 100000000 microVOLTS, 1000000000 nanoAMPS */
};

/*
 * Fill out the structure pointers.
 */
cistpl_devspeed_struct_t cistpl_devspeed_struct = {
	cistpl_devspeed_table,
	cistpl_exspeed_tenfac,
	cistpl_devspeed_man,
	cistpl_devspeed_exp,
};

cistpl_pd_struct_t cistpl_pd_struct = {
	cistpl_pd_man,
	cistpl_pd_exp,
};

/*
 * Some handy lookup tables that should probably eventually be
 *	done away with.
 *
 * These are used mostly by the CISTPL_CFTABLE_ENTRY tuple handler.
 */
uint32_t cistpl_cftable_io_size_table[] = {
	0,
	1,
	2,
	4,
};

uint32_t cistpl_cftable_shift_table[] = {
	0,
	8,
	16,
	24,
};

/*
 * List of tuples in the global CIS to ignore if they show
 *	up in both the global and function-specific CIS lists.
 * This list MUST end with CISTPL_NULL.
 */
cistpl_ignore_list_t cistpl_ignore_list[] = {
	CISTPL_FUNCID,
	CISTPL_FUNCE,
	CISTPL_CONFIG,
	CISTPL_CFTABLE_ENTRY,
	CISTPL_NULL	/* list must end with CISTPL_NULL */
};
