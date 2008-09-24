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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PMAP_COMMON_H
#define	_PMAP_COMMON_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct lwpstack {
	lwpid_t	lwps_lwpid;
	stack_t	lwps_stack;
} lwpstack_t;

/*
 * Used to set the advice type var (at_map) when parsing the arguments to
 * pmadvise.  Later, when creating the map list, at_map is used as a mask
 * to determine if any generic advice applies to each memory mapping.
 */
enum	atype_enum {
	AT_PRIVM,
	AT_SHARED,
	AT_HEAP,
	AT_STACK,
	AT_SEG,
	AT_NTYPES
};

extern int cmpstacks(const void *, const void *);
extern char *make_name(struct ps_prochandle *, int, uintptr_t,
    const char *, char *, size_t);
extern char *anon_name(char *, const pstatus_t *, lwpstack_t *, uint_t,
    uintptr_t, size_t, int, int, int *);


#ifdef	__cplusplus
}
#endif

#endif	/* _PMAP_COMMON_H */
