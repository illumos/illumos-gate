/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DKTP_CMDK_H
#define	_SYS_DKTP_CMDK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/cmlb.h>
#include <sys/dktp/tgdk.h>

#define	CMDK_UNITSHF	6
#define	CMDK_MAXPART	(1 << CMDK_UNITSHF)

/*
 * Model number is 40 ASCII characters
 * Serial number is 20 ASCII characters
 */
#define	CMDK_HWIDLEN	(64)

struct	cmdk {
	/* set during probe */
	dev_info_t	*dk_dip;
	dev_t		dk_dev;
	struct tgdk_obj *dk_tgobjp;		/* target disk object pointer */

	/* set during attach */
	cmlb_handle_t	dk_cmlbhandle;
	ddi_devid_t	dk_devid;

	kmutex_t	dk_mutex;		/* mutex for cmdk struct */

	long		dk_flag;
	uint64_t	dk_open_reg[OTYPCNT];	/* bit per partition: 2^6 */
	ulong_t		dk_open_lyr[CMDK_MAXPART]; /* OTYP_LYR cnt/partition */
	uint64_t	dk_open_exl;		/* bit per partition: 2^6 */

	struct bbh_obj	dk_bbh_obj;

	/*
	 * BBH variables
	 * protected by dk_bbh_mutex
	 */
	krwlock_t	dk_bbh_mutex;		/* bbh mutex */
	tgdk_iob_handle	dk_alts_hdl;		/* iob for V_ALTSCTR */
	uint32_t	dk_altused;		/* num entries in V_ALTSCTR */
	uint32_t	*dk_slc_cnt;		/* entries per slice */
	struct alts_ent	**dk_slc_ent;		/* link to remap data */

	/*
	 * for power management
	 */
	kmutex_t	dk_pm_mutex;
	kcondvar_t	dk_suspend_cv;
	uint32_t	dk_pm_level;
	uint32_t	dk_pm_is_enabled;
};

/*
 * Power Management definitions
 */
#define	CMDK_SPINDLE_UNINIT	((uint_t)(-1))
#define	CMDK_SPINDLE_OFF	0x0
#define	CMDK_SPINDLE_ON		0x1

/*	common disk flags definitions					*/
#define	CMDK_OPEN		0x1
#define	CMDK_SUSPEND		0x2
#define	CMDK_TGDK_OPEN		0x4

#define	CMDKUNIT(dev) (getminor((dev)) >> CMDK_UNITSHF)
#define	CMDKPART(dev) (getminor((dev)) & (CMDK_MAXPART - 1))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_CMDK_H */
