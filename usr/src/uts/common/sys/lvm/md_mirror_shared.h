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

#ifndef _SYS_MD_MIRROR_SHARED_H
#define	_SYS_MD_MIRROR_SHARED_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/lvm/mdvar.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * md_m_shared32_od is part of old 32 bit format
 */
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif
typedef struct md_m_shared32_od {
	uint_t		ms_flags;
	uint_t		xms_mx[2];	/* replaces kmutex_t ms_mx */
	/*
	 * The following are really private to the mirror code
	 * but are stored on a per component basic
	 */
	comp_state_t	ms_state;	/* component state */
	uint_t		ms_lasterrcnt;
	dev32_t		ms_orig_dev;
	daddr32_t	ms_orig_blk;
	mdkey_t		ms_hs_key;
	mddb_recid_t	ms_hs_id;
	struct timeval32 ms_timestamp;   /* time of last state change */
} md_m_shared32_od_t;

typedef struct md_m_shared {
	uint_t		ms_flags;
	/*
	 *	The following are really private to the mirror code
	 *	but are stored on a per component basic
	 */
	comp_state_t	ms_state;	/* component state */
	uint_t		ms_lasterrcnt;
	md_dev64_t	ms_orig_dev;	/* 64 bit */
	diskaddr_t	ms_orig_blk;
	mdkey_t		ms_hs_key;
	mddb_recid_t	ms_hs_id;
	md_timeval32_t	ms_timestamp;	/* time of last state change, 32 bit */
} md_m_shared_t;

#define	MDM_S_NOWRITE	0x0001
#define	MDM_S_WRTERR	0x0002
#define	MDM_S_READERR	0x0004
#define	MDM_S_IOERR	(MDM_S_WRTERR | MDM_S_READERR)
#define	MDM_S_ISOPEN	0x0008
#define	MDM_S_RS_TRIED	0x0010		/* resync has tried this component */
#define	MDM_S_PROBEOPEN	0x0020		/* accessed via probe */

typedef struct ms_cd_info {
	md_dev64_t	cd_dev;
	md_dev64_t	cd_orig_dev;
} ms_cd_info_t;

typedef struct ms_new_dev {
	md_dev64_t	nd_dev;
	mdkey_t		nd_key;
	diskaddr_t	nd_start_blk;
	diskaddr_t	nd_nblks;
	int		nd_labeled;
	mddb_recid_t	nd_hs_id;
} ms_new_dev_t;
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MD_MIRROR_SHARED_H */
