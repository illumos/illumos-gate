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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__XSEM_H__
#define	__XSEM_H__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * xsem.h: to provide a semaphore system (used by the smq routines)
 *
 * these routines come from the libxposix library.
 */

#include <pthread.h>
#include <time.h>


/* DEFINES */
#define	XSEM_ERROR	-1
#define	XSEM_EBUSY	1
#define	XSEM_ETIME	2


/* STRUCTURES */
typedef struct
{
	pthread_mutex_t	semMutex;
	pthread_cond_t	semCV;
	int		semaphore;
} xsem_t;


/* PROTOTYPES */
int	xsem_init(xsem_t *sem, int pshared, unsigned int value);
void	xsem_destroy(xsem_t *sem);
int	xsem_wait(xsem_t *sem);
int	xsem_trywait(xsem_t *sem);
int	xsem_post(xsem_t *sem);
void	xsem_getvalue(xsem_t *sem, int *sval);

int	xsem_xwait(xsem_t *sem, int timeout, timestruc_t *time);

#ifdef	__cplusplus
}
#endif

#endif /* __XSEM_H__ */
