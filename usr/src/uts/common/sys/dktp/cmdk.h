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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DKTP_CMDK_H
#define	_SYS_DKTP_CMDK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	CMDK_UNITSHF	6
#define	CMDK_MAXPART	(1 << CMDK_UNITSHF)

struct	dk_openinfo {
	uint64_t	dk_reg[OTYPCNT];	/* bit per partition: 2^6 */
	ulong_t		dk_lyr[CMDK_MAXPART];	/* OTYP_LYR cnt per partition */
	uint64_t	dk_exl;			/* bit per partition: 2^6 */
};

struct	cmdk_label {
	opaque_t	dkl_objp;
	char		dkl_name[OBJNAMELEN];
};

#define	CMDK_LABEL_MAX	3
struct	cmdk {
	long		dk_flag;
	dev_info_t	*dk_dip;
	dev_t		dk_dev;

	ksema_t		dk_semoclose;	/* lock for opens/closes 	*/
	struct		dk_openinfo dk_open;

	opaque_t 	dk_tgobjp;	/* target disk object pointer	*/
	opaque_t 	dk_lbobjp;
	struct cmdk_label dk_lb[CMDK_LABEL_MAX];

	kmutex_t	dk_pinfo_lock;
	kcondvar_t	dk_pinfo_cv;
	int		dk_pinfo_state;
};

/*	common disk flags definitions					*/
#define	CMDK_OPEN		0x1
#define	CMDK_VALID_LABEL	0x2
#define	CMDK_TGDK_OPEN		0x4

#define	CMDKUNIT(dev) (getminor((dev)) >> CMDK_UNITSHF)
#define	CMDKPART(dev) (getminor((dev)) & (CMDK_MAXPART - 1))

#define	CMDK_TGOBJP(dkp)	(dkp)->dk_tgobjp

/*	dk_pinfo_states for cmdk_part_info() */
#define	CMDK_PARTINFO_INVALID	0
#define	CMDK_PARTINFO_BUSY	1
#define	CMDK_PARTINFO_BUSY2	2
#define	CMDK_PARTINFO_VALID	3


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_CMDK_H */
