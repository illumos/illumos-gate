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

#ifndef _SYS_TL_H
#define	_SYS_TL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These are Sun private declarations. Not to be used by any
 * external applications/code.
 */

/*
 * Protocol level for option header - (hex for ascii "TL")
 * (Hopefully unique!)
 */
#define	TL_PROT_LEVEL 0x544c

/*
 * Option and data structures used for sending credentials
 */
#define	TL_OPT_PEER_CRED 10
typedef struct tl_credopt {
	uid_t	tc_uid;		/* Effective user id */
	gid_t	tc_gid;		/* Effective group id */
	uid_t	tc_ruid;	/* Real user id */
	gid_t	tc_rgid;	/* Real group id */
	uid_t	tc_suid;	/* Saved user id (from exec) */
	gid_t	tc_sgid;	/* Saved group id (from exec) */
	uint_t	tc_ngroups;	/* number of supplementary groups */
} tl_credopt_t;

#define	TL_OPT_PEER_UCRED 11	/* data structure is ucred */

/*
 * Ioctl's for the 'tl' driver
 */
#define	TL_IOC		(('T' << 16)|('L' << 8))
#define	TL_IOC_CREDOPT	(TL_IOC|001)
/* unused		(TL_IOC|002) */
#define	TL_IOC_UCREDOPT	(TL_IOC|003)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_TL_H */
