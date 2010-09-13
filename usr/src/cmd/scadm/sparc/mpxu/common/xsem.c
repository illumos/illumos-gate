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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * xsem.c: to provide a semaphore system (used by the smq routines)
 *
 * these routines come from the libxposix library.
 */

#include <pthread.h>
#include <time.h>

#include "xsem.h"


int
xsem_init(xsem_t *sem, int pshared, unsigned int value)
{
	if (pshared != 0)
		return (-1);

	pthread_mutex_init(&sem->semMutex, NULL);
	pthread_cond_init(&sem->semCV, NULL);
	sem->semaphore = value;

	return (0);
}

void
xsem_destroy(xsem_t *sem)
{
	pthread_mutex_destroy(&sem->semMutex);
	pthread_cond_destroy(&sem->semCV);
	sem->semaphore = 0;
}

int
xsem_wait(xsem_t *sem)
{
	pthread_mutex_lock(&sem->semMutex);

	if (sem->semaphore < 0) {
		sem->semaphore = 0;
		pthread_mutex_unlock(&sem->semMutex);
		return (XSEM_ERROR);
	}

	if (sem->semaphore > 0) {
		sem->semaphore--;
	} else {
		while (sem->semaphore == 0)
			pthread_cond_wait(&sem->semCV, &sem->semMutex);

		if (sem->semaphore != 0) {
			sem->semaphore--;
		} else {
			pthread_mutex_unlock(&sem->semMutex);
			return (XSEM_ERROR);
		}
	}

	pthread_mutex_unlock(&sem->semMutex);
	return (0);
}


int
xsem_trywait(xsem_t *sem)
{
	pthread_mutex_lock(&sem->semMutex);

	if (sem->semaphore < 0) {
		sem->semaphore = 0;
		pthread_mutex_unlock(&sem->semMutex);
		return (XSEM_ERROR);
	}

	if (sem->semaphore == 0) {
		pthread_mutex_unlock(&sem->semMutex);
		return (XSEM_EBUSY);
	} else {
		sem->semaphore--;
	}

	pthread_mutex_unlock(&sem->semMutex);
	return (0);
}


int
xsem_post(xsem_t *sem)
{
	pthread_mutex_lock(&sem->semMutex);
	sem->semaphore++;
	pthread_cond_signal(&sem->semCV);
	pthread_mutex_unlock(&sem->semMutex);

	return (0);
}


void
xsem_getvalue(xsem_t *sem, int *sval)
{
	*sval = sem->semaphore;
}



int
xsem_xwait(xsem_t *sem, int timeout, timestruc_t *mytime)
{
	int		status;
	timestruc_t	delay;

	if (timeout == 0)
		return (xsem_wait(sem));
	else {
		pthread_mutex_lock(&sem->semMutex);

		if (sem->semaphore < 0) {
			sem->semaphore = 0;
			pthread_mutex_unlock(&sem->semMutex);
			return (XSEM_ERROR);
		}

		if (sem->semaphore > 0) {
			sem->semaphore--;
		} else {
			status = 0;

			delay  = *mytime;
			delay.tv_sec = delay.tv_sec + time(NULL);
			while ((sem->semaphore == 0) && (status == 0)) {
				status = pthread_cond_timedwait(&sem->semCV,
				    &sem->semMutex, &delay);
			}

			/*
			 * Check one more time in case thread didn't have a
			 * chance to check before timeout ??? TBD
			 */

			if (status != 0) {
				pthread_mutex_unlock(&sem->semMutex);
				return (XSEM_ETIME);
			} else if (sem->semaphore != 0) {
				sem->semaphore--;
			} else {
				pthread_mutex_unlock(&sem->semMutex);
				return (XSEM_ERROR);
			}
		}

		pthread_mutex_unlock(&sem->semMutex);
	}

	return (0);
}
