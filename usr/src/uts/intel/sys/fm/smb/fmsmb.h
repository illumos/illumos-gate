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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FM_SMB_FMSMB_H
#define	_SYS_FM_SMB_FMSMB_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/nvpair.h>

#ifdef _KERNEL
#include <sys/systm.h>

extern nvlist_t *fm_smb_bboard(uint_t);
extern nvlist_t *fm_smb_mc_bboards(uint_t);
extern int fm_smb_chipinst(uint_t, uint_t *, uint16_t *);
extern int fm_smb_mc_chipinst(uint_t, uint_t *);
extern void fm_smb_fmacompat();

#endif  /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_FM_SMB_FMSMB_H */
