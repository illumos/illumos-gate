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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MNTTAB_H
#define	_SYS_MNTTAB_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MNTTAB	"/etc/mnttab"
#define	MNT_LINE_MAX	1024

#define	MNT_TOOLONG	1	/* entry exceeds MNT_LINE_MAX */
#define	MNT_TOOMANY	2	/* too many fields in line */
#define	MNT_TOOFEW	3	/* too few fields in line */

#define	mntnull(mp)\
	((mp)->mnt_special = (mp)->mnt_mountp = \
	    (mp)->mnt_fstype = (mp)->mnt_mntopts = \
	    (mp)->mnt_time = NULL)

#define	putmntent(fd, mp)	(-1)

/*
 * The fields in struct extmnttab should match those in struct mnttab until new
 * fields are encountered. This allows hasmntopt(), getmntent_common() and
 * mntioctl() to cast one type to the other safely.
 *
 * The fields in struct mnttab, struct extmnttab and struct mntentbuf must all
 * match those in the corresponding 32-bit versions defined in mntvnops.c.
 */
struct mnttab {
	char	*mnt_special;
	char	*mnt_mountp;
	char	*mnt_fstype;
	char	*mnt_mntopts;
	char	*mnt_time;
};

struct extmnttab {
	char	*mnt_special;
	char	*mnt_mountp;
	char	*mnt_fstype;
	char	*mnt_mntopts;
	char	*mnt_time;
	uint_t	mnt_major;
	uint_t	mnt_minor;
};

struct mntentbuf {
	struct	extmnttab *mbuf_emp;
	size_t 	mbuf_bufsize;
	char	*mbuf_buf;
};

#if !defined(_KERNEL)
extern void	resetmnttab(FILE *);
extern int	getmntent(FILE *, struct mnttab *);
extern int	getextmntent(FILE *, struct extmnttab *, size_t);
extern int	getmntany(FILE *, struct mnttab *, struct mnttab *);
extern char	*hasmntopt(struct mnttab *, char *);
extern char	*mntopt(char **);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MNTTAB_H */
