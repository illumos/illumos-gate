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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_DKTP_SNLB_H
#define	_SYS_DKTP_SNLB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dklabel.h>
#include <sys/dktp/altsctr.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SNVTOC		DK_LABEL_LOC

#define	SNDKMAP		NDKMAP
#define	SNUSLICE_WHOLE	2
#define	SNFPART_WHOLE	0

struct	sn_lbdata {
	daddr_t		s_ustart;
	long		s_capacity;
	struct	dk_label s_dklb;
	struct	partition s_fpart[SNDKMAP];
	long		 *s_alts_altcount;
	struct	alts_ent **s_alts_firstalt;
	struct	alts_ent *s_alts_enttbl;	/* alternate sectors	*/
	long		s_alts_entused;
	tgdk_iob_handle	s_hdl_enttbl;
};

struct	sn_label {
	struct dklb_ext	*s_extp;
	opaque_t	s_dkobjp;
	kmutex_t	s_mutex;
	krwlock_t	s_rw_mutex;
	struct sn_lbdata s_data;
	struct	bbh_obj s_bbh;
	dev_t		s_dev;			/* so snlb can create prop */
	dev_info_t 	*s_dip;			/* ditto */
	ddi_devid_t	s_devid;
	int		s_flags;
};

/*
 * Bits in s_flags
 */
#define	SNLB_HWID	0x1	/* disk has a hardware devid */
#define	SNLB_FABID	0x2	/* disk has a fabricated devid */

#define	SNLB_PART(dev) (getminor((dev)) & (SNDKMAP|(SNDKMAP-1)))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_SNLB_H */
