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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PSET_H
#define	_SYS_PSET_H

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_ASM)

#include <sys/types.h>
#include <sys/processor.h>
#include <sys/procset.h>

typedef int psetid_t;

/* special processor set id's */
#define	PS_NONE		-1
#define	PS_QUERY	-2
#define	PS_MYID		-3
#define	PS_SOFT		-4
#define	PS_HARD		-5
#define	PS_QUERY_TYPE	-6

/* types of processor sets */
#define	PS_SYSTEM	1
#define	PS_PRIVATE	2

#ifndef	_KERNEL

extern int	pset_create(psetid_t *);
extern int	pset_destroy(psetid_t);
extern int	pset_assign(psetid_t, processorid_t, psetid_t *);
extern int	pset_info(psetid_t, int *, uint_t *, processorid_t *);
extern int	pset_bind(psetid_t, idtype_t, id_t, psetid_t *);
extern int	pset_bind_lwp(psetid_t, id_t, pid_t, psetid_t *);
extern int	pset_getloadavg(psetid_t, double [], int);
extern int	pset_list(psetid_t *, uint_t *);
extern int	pset_setattr(psetid_t, uint_t);
extern int	pset_getattr(psetid_t, uint_t *);

#endif	/* ! _KERNEL */

#endif	/* !defined(_ASM) */

/* system call subcodes */
#define	PSET_CREATE		0
#define	PSET_DESTROY		1
#define	PSET_ASSIGN		2
#define	PSET_INFO		3
#define	PSET_BIND		4
#define	PSET_GETLOADAVG		5
#define	PSET_LIST		6
#define	PSET_SETATTR		7
#define	PSET_GETATTR		8
#define	PSET_ASSIGN_FORCED	9
#define	PSET_BIND_LWP		10

/* attribute bits */
#define	PSET_NOESCAPE	0x0001

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PSET_H */
