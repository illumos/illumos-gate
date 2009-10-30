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

#ifndef _SYS_MNTIO_H
#define	_SYS_MNTIO_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Mntfs io control commands
 */
#define	MNTIOC			('m' << 8)
#define	MNTIOC_NMNTS		(MNTIOC|1)	/* Get # of mounted resources */
#define	MNTIOC_GETDEVLIST	(MNTIOC|2)	/* Get mounted dev no.'s */
#define	MNTIOC_SETTAG		(MNTIOC|3)	/* Set a tag on a mounted fs */
#define	MNTIOC_CLRTAG		(MNTIOC|4)	/* Clear a tag from a fs */
#define	MNTIOC_SHOWHIDDEN	(MNTIOC|6)	/* private */
#define	MNTIOC_GETMNTENT	(MNTIOC|7)	/* private */
#define	MNTIOC_GETEXTMNTENT	(MNTIOC|8)	/* private */
#define	MNTIOC_GETMNTANY	(MNTIOC|9)	/* private */

/*
 * Private mntfs return codes
 */
#define	MNTFS_EOF	1
#define	MNTFS_TOOLONG	2


#define	MAX_MNTOPT_TAG	64	/* Maximum size for a mounted file system tag */

struct mnttagdesc {
	uint_t	mtd_major;		/* major number of mounted resource */
	uint_t	mtd_minor;		/* minor number of mounted resource */
	char	*mtd_mntpt;		/* mount point for mounted resource */
	char	*mtd_tag;		/* tag to set/clear */
};

#ifdef _SYSCALL32
struct mnttagdesc32 {
	uint32_t	mtd_major;	/* major number of mounted resource */
	uint32_t	mtd_minor;	/* minor number of mounted resource */
	caddr32_t	mtd_mntpt;	/* mount point for mounted resource */
	caddr32_t	mtd_tag;	/* tag to set/clear */
};
#endif /* _SYSCALL32 */


struct mntlookup {
	size_t	mtl_mntpt_off;
	char	*mtl_mntpt;
	major_t	mtl_major;
	minor_t	mtl_minor;
	ino64_t	mtl_ino;
	char	mtl_fstype[_ST_FSTYPSZ];
};

#ifdef _SYSCALL32
struct mntlookup32 {
	size32_t	mtl_mntpt_off;
	caddr32_t	mtl_mntpt;
	major32_t	mtl_major;
	minor32_t	mtl_minor;
	ino64_t		mtl_ino;
	char		mtl_fstype[_ST_FSTYPSZ];
};
#endif /* _SYSCALL32 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MNTIO_H */
