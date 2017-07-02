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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#ifndef	_SYS_VFSTAB_H
#define	_SYS_VFSTAB_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	VFSTAB	"/etc/vfstab"
#define	VFS_LINE_MAX	1024

#define	VFS_TOOLONG	1	/* entry exceeds VFS_LINE_MAX */
#define	VFS_TOOMANY	2	/* too many fields in line */
#define	VFS_TOOFEW	3	/* too few fields in line */

#define	vfsnull(vp)	((vp)->vfs_special = (vp)->vfs_fsckdev = \
			    (vp)->vfs_mountp = (vp)->vfs_fstype = \
			    (vp)->vfs_fsckpass = (vp)->vfs_automnt = \
			    (vp)->vfs_mntopts = NULL)

#define	putvfsent(fd, vp)\
	fprintf((fd), "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", \
		(vp)->vfs_special ? (vp)->vfs_special : "-", \
		(vp)->vfs_fsckdev ? (vp)->vfs_fsckdev : "-", \
		(vp)->vfs_mountp ? (vp)->vfs_mountp : "-", \
		(vp)->vfs_fstype ? (vp)->vfs_fstype : "-", \
		(vp)->vfs_fsckpass ? (vp)->vfs_fsckpass : "-", \
		(vp)->vfs_automnt ? (vp)->vfs_automnt : "-", \
		(vp)->vfs_mntopts ? (vp)->vfs_mntopts : "-")

struct vfstab {
	char	*vfs_special;
	char	*vfs_fsckdev;
	char	*vfs_mountp;
	char	*vfs_fstype;
	char	*vfs_fsckpass;
	char	*vfs_automnt;
	char	*vfs_mntopts;
};

extern int	getvfsent(FILE *, struct vfstab *);
extern int	getvfsspec(FILE *, struct vfstab *, char *);
extern int	getvfsfile(FILE *, struct vfstab *, char *);
extern int	getvfsany(FILE *, struct vfstab *, struct vfstab *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VFSTAB_H */
