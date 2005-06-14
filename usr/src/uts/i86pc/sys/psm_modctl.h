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
 * Copyright (c) 1993, by Sun Microsystems, Inc.
 */

#ifndef	_SYS_PSM_MODCTL_H
#define	_SYS_PSM_MODCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * loadable module support.
 */

#ifdef	__cplusplus
extern "C" {
#endif

struct psm_sw {
	struct psm_sw	*psw_forw;
	struct psm_sw	*psw_back;
	struct psm_info *psw_infop;
	int	psw_flag;
};

#define	PSM_MOD_INSTALL		0x0001
#define	PSM_MOD_IDENTIFY	0x0002

/* For psm */
struct modlpsm {
	struct mod_ops		*psm_modops;
	char			*psm_linkinfo;
	struct psm_sw		*psm_swp;
};

extern struct psm_sw *psmsw;
extern kmutex_t psmsw_lock;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PSM_MODCTL_H */
