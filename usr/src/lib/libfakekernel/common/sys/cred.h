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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _SYS_CRED_H
#define	_SYS_CRED_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The credential is an opaque kernel private data structure defined in
 * <sys/cred_impl.h>.
 */

typedef struct cred cred_t;

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

cred_t *_curcred(void);
#define	CRED()		(_curcred())	/* current cred_t pointer */

extern int ngroups_max;

/*
 * kcred is used when you need all privileges.
 */
extern struct cred *kcred;

extern void cred_init(void);
extern void crhold(cred_t *);
extern void crfree(cred_t *);

extern cred_t *zone_kcred(void);

extern uid_t crgetuid(const cred_t *);
extern uid_t crgetruid(const cred_t *);
extern uid_t crgetsuid(const cred_t *);
extern gid_t crgetgid(const cred_t *);
extern gid_t crgetrgid(const cred_t *);
extern gid_t crgetsgid(const cred_t *);
extern zoneid_t crgetzoneid(const cred_t *);
extern projid_t crgetprojid(const cred_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CRED_H */
