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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NSCTL_H
#define	_NSCTL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/nsctl/nsctl.h>


/*
 * External file descriptor.
 */

#ifndef _LIBNSCTL_H
#ifndef _KMEMUSER
typedef struct nsc_fd_s { int x; } nsc_fd_t;
#endif
#endif


/*
 * Runtime Solaris release checking.
 *
 * nsc_check_release() is called with the string build release
 * (BUILD_REV_STR) and an optional array of nsc_release_t. The array
 * defines a map of build release to acceptable runtime release for the
 * component.  The build release is always an acceptable runtime
 * release and need not be included in the map.
 *
 * build   - the build release (e.g. "5.7")
 * runtime - comma &/or space separated list of acceptable runtime
 *           releases (e.g. "5.7, 5.8")
 */

typedef struct nsc_release {
	const char *build;	/* build release */
	const char *runtime;	/* runtime release(s) */
} nsc_release_t;

extern void _nsc_nocheck(void);
extern nsc_fd_t *nsc_open(char *, int, int);
extern nsc_fd_t *nsc_fdopen(int, char *, int);
extern int nsc_close(nsc_fd_t *);
extern int nsc_fileno(nsc_fd_t *);
extern int nsc_reserve(nsc_fd_t *);
extern int nsc_release(nsc_fd_t *);
extern int nsc_partsize(nsc_fd_t *, nsc_size_t *);
extern int nsc_freeze(char *path);
extern int nsc_unfreeze(char *path);
extern int nsc_isfrozen(char *path);
extern int nsc_getsystemid(int *id);
extern int nsc_name_to_id(char *name, int *id);
extern int nsc_id_to_name(char **name, int id);
extern int nsc_check_release(const char *, nsc_release_t *, char **);

#ifdef	__cplusplus
}
#endif

#endif /* _NSCTL_H */
