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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef __UTIL_H
#define	__UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/vtoc.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * General queue structure
 */
struct q {
	struct q	*q_next;
#define	q_head	q_next
	struct q	*q_prev;
#define	q_tail	q_prev
};

void my_remque(struct q *, struct q *);
void my_insque(struct q *, struct q *);

#define	INSQUE(head, ptr) my_insque(&(head), &(ptr)->q)
#define	REMQUE(head, ptr) my_remque(&(head), &(ptr)->q)
#define	HEAD(type, head) ((type *)(head.q_head))
#define	NEXT(type, ptr)	((type *)(ptr->q.q_next))
#define	TAIL(type, head) ((type *)(head.q_tail))
#define	PREV(type, ptr)	((type *)(ptr->q.q_prev))

/* don't need this on intel -- no backwards compat. to worry about */
void		partition_conv(struct vtoc *, uint_t, uchar_t *, uchar_t *);
void		partition_conv_2(struct vtoc *, uint_t, ulong_t *, uchar_t *);
int		partition_low(struct vtoc *);

char 		*location_newdev(char *, char *);
dev_t		location_localdev(char *);

/*
 * property list management functions.
 */
char 		*prop_attr_del(char *, char *);
char 		*prop_attr_get(char *, char *);
char 		*prop_attr_put(char *, char *, char *);
char		*prop_attr_merge(char *, char *);

char		*props_get(struct vol *);
void		props_set(struct vol *, char *);
void		props_merge(struct vol *, struct vol *);

dev_t		minor_alloc(struct vol *);
void		minor_free(minor_t);
struct vol	*minor_getvol(minor_t);
void		minor_clrvol(minor_t);
void		minor_chgvol(minor_t, struct vol *);

char		*makename(char *, size_t);

char		*path_make(struct vvnode *);
uint_t		path_type(struct vvnode *);
char 		*path_nis(char *);
char 		*path_unnis(char *);
char		**path_split(char *);
void		path_freeps(char **);
char		*path_mntrename(char *, char *, char *);

char 		*mnt_special_test(char *);
char 		*mnt_mp_test(char *);
void		mnt_mp_rename(char *, char *);
void		mnt_special_rename(char *, char *);
struct mnttab	*mnt_mnttab(char *);
void		mnt_free_mnttab(struct mnttab *);



uint_t		hash_string(char *);

bool_t		dso_load(char *, char *, int);

bool_t		unsafe_check(struct vol *);

int		dev_to_part(struct vol *, int);

/*
 * functions to generate signatures from data.
 */
void		calc_md4(uchar_t *, size_t, u_longlong_t *);
ulong_t		calc_crc(uchar_t *, size_t);

char		*sh_to_regex(char *);
void		match_path_cache_clear(void);
char 		**match_path(char *, int (*testpath)(char *));
char		*rawpath(char *);
int		makepath(char *, mode_t);

/*
 * memory allocation stuff.
 */
extern void	*vold_malloc(size_t);
extern void	*vold_realloc(void *, size_t);
extern void	*vold_calloc(size_t, size_t);
extern char 	*vold_strdup(const char *);

#ifdef	__cplusplus
}
#endif

#endif /* __UTIL_H */
