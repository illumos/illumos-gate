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

#ifndef	_FSLIB_H
#define	_FSLIB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include	<sys/mnttab.h>

/*
 * This structure is used to build a list of
 * mnttab structures from /etc/mnttab.
 */
typedef struct mntlist {
	int		mntl_flags;
	uint_t		mntl_dev;
	struct extmnttab *mntl_mnt;
	struct mntlist	*mntl_next;
} mntlist_t;

/*
 * Bits for mntl_flags.
 */
#define	MNTL_UNMOUNT	0x01	/* unmount this entry */
#define	MNTL_DIRECT	0x02	/* direct mount entry */

/*
 * Routines available in fslib.c:
 */
void			fsfreemnttab(struct extmnttab *);
struct extmnttab 	*fsdupmnttab(struct extmnttab *);
void			fsfreemntlist(mntlist_t *);

mntlist_t	*fsmkmntlist(FILE *);
mntlist_t	*fsgetmntlist(void);
mntlist_t	*fsgetmlast(mntlist_t *, struct mnttab *);
void	cmp_requested_to_actual_options(char *, char *, char *, char *);

int	fsgetmlevel(char *);
int	fsstrinlist(const char *, const char **);
int	fsgetmaxphys(int *, int *);

boolean_t 	fsisstdopt(const char *);

/*
 * Routines for determining which zone a mount resides in.
 */
struct zone_summary;

struct		zone_summary *fs_get_zone_summaries(void);
boolean_t	fs_mount_in_other_zone(const struct zone_summary *,
    const char *);

#undef MIN
#undef MAX
#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#define	MAX(a, b)	((a) > (b) ? (a) : (b))

#define	MAXLINE		2048

#ifdef	__cplusplus
}
#endif

#endif	/* _FSLIB_H */
