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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_osd.h
 *
 * PURPOSE: Operating System Dependent layer
 * Description:
 *	Provide OS dependent data structures & functions with
 *	a canonical DAPL interface. Designed to be portable
 *	and hide OS specific quirks of common functions.
 *
 * $Id: dapl_osd.h,v 1.38 2003/08/20 14:08:57 sjs2 Exp $
 */

#ifndef _DAPL_OSD_H_
#define	_DAPL_OSD_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * <assert.h> keys off of NDEBUG
 */
#ifdef	DAPL_DBG
#undef	NDEBUG
#else
#define	NDEBUG
#endif

#include <dat/udat.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>
#include <netdb.h>
#include <atomic.h>
#include "dapl_debug.h"

/*
 * networking related headers
 */
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ctype.h>
#include <arpa/inet.h>

#ifndef _INLINE_
#define	_INLINE_
#endif /* _INLINE_ */

/*
 * initialization function
 */
void dapl_os_init(void);

#define	dapl_os_panic(args) 			\
{					\
	fprintf(stderr, "PANIC in %s:%i:\n", __FILE__, __LINE__); \
	fprintf(stderr, args);			\
	exit(1);				\
}

int dapl_os_get_env_bool(
	char		*env_str);

int dapl_os_get_env_val(
	char		*env_str,
	int		def_val);

/*
 * Atomic operations
 */
typedef volatile DAT_COUNT DAPL_ATOMIC;

/*
 * dapl_os_atomic_inc
 *
 * get the current value of '*v', and then increment it.
 *
 * This is equivalent to an IB atomic fetch and add of 1,
 * except that a DAT_COUNT might be 32 bits, rather than 64
 * and it occurs in local memory.
 *
 * void dapl_os_atomic_inc(INOUT	DAPL_ATOMIC *v)
 */
#define	dapl_os_atomic_inc(v)	atomic_add_32((uint32_t *)(v), 1)

/*
 * dapl_os_atomic_dec
 *
 * decrement the current value of '*v'. No return value is required.
 *
 * void dapl_os_atomic_dec(INOUT	DAPL_ATOMIC *v)
 */
#define	dapl_os_atomic_dec(v)	assert(*v != 0);		\
				atomic_add_32((uint32_t *)(v), -1)

/*
 * dapl_os_atomic_assign
 *
 * assign 'new_value' to '*v' if the current value
 * matches the provided 'match_value'.
 *
 * Make no assignment if there is no match.
 *
 * Return the current value in any case.
 *
 * This matches the IBTA atomic operation compare & swap
 * except that it is for local memory and a DAT_COUNT may
 * be only 32 bits, rather than 64.
 *
 * DAT_COUNT dapl_os_atomic_assign(INOUT DAPL_ATOMIC *v,
 *	IN DAT_COUNT match_value, IN DAT_COUNT new_value)
 */
#define	dapl_os_atomic_assign(v, match_value, new_value)		\
		atomic_cas_32((uint32_t *)(v), (uint32_t)(match_value),	\
		    (uint32_t)(new_value))

/*
 * Thread Functions
 */
typedef pthread_t		DAPL_OS_THREAD;

DAT_RETURN
dapl_os_thread_create(
	IN  void			(*func)	(void *),
	IN  void			*data,
	OUT DAPL_OS_THREAD		*thread_id);


/*
 * Lock Functions
 */

typedef pthread_mutex_t 	DAPL_OS_LOCK;

/*
 * DAT_RETURN dapl_os_lock_init(IN DAPL_OS_LOCK *m)
 */
#define	dapl_os_lock_init(m)	(void)					\
				((0 == pthread_mutex_init((m), NULL)) ?	\
					DAT_SUCCESS :			\
					(DAT_CLASS_ERROR | DAT_INTERNAL_ERROR))

/* DAT_RETURN dapl_os_lock(IN DAPL_OS_LOCK *m) */
#define	dapl_os_lock(m)		((DAT_RETURN)(				\
				(0 == pthread_mutex_lock((m))) ?	\
					DAT_SUCCESS :			\
					(DAT_CLASS_ERROR | DAT_INTERNAL_ERROR)))

/* DAT_RETURN dapl_os_unlock(IN DAPL_OS_LOCK *m) */
#define	dapl_os_unlock(m)	((DAT_RETURN)(				\
				(0 == pthread_mutex_unlock((m))) ?	\
					DAT_SUCCESS :			\
					(DAT_CLASS_ERROR | DAT_INTERNAL_ERROR)))

/* DAT_RETURN dapl_os_lock_destroy(IN DAPL_OS_LOCK *m) */
#define	dapl_os_lock_destroy(m)	((DAT_RETURN)(				\
				(0 == pthread_mutex_destroy((m))) ?	\
					DAT_SUCCESS :			\
					(DAT_CLASS_ERROR | DAT_INTERNAL_ERROR)))
/*
 * Wait Objects
 */

/*
 * The wait object invariant: Presuming a call to dapl_os_wait_object_wait
 * occurs at some point, there will be at least one wakeup after each call
 * to dapl_os_wait_object_signal.  I.e. Signals are not ignored, though
 * they may be coallesced.
 */

typedef struct
{
    DAT_BOOLEAN		signaled;
    pthread_cond_t	cv;
    pthread_mutex_t	lock;
} DAPL_OS_WAIT_OBJECT;

/* function prototypes */
DAT_RETURN
dapl_os_wait_object_init(
    IN DAPL_OS_WAIT_OBJECT *wait_obj);

DAT_RETURN
dapl_os_wait_object_wait(
    IN	DAPL_OS_WAIT_OBJECT *wait_obj,
    IN  DAT_TIMEOUT timeout_val);

DAT_RETURN
dapl_os_wait_object_wakeup(
    IN	DAPL_OS_WAIT_OBJECT *wait_obj);

DAT_RETURN
dapl_os_wait_object_destroy(
    IN	DAPL_OS_WAIT_OBJECT *wait_obj);

/*
 * Memory Functions
 */

/* void *dapl_os_alloc(int size) */
#define	dapl_os_alloc(size)	malloc((size))

/* void *dapl_os_realloc(void *ptr, int size) */
#define	dapl_os_realloc(ptr, size) realloc((ptr), (size))

/* void dapl_os_free(void *ptr, int size) */
#define	dapl_os_free(ptr, size)	free((ptr))

/* void * dapl_os_memzero(void *loc, int size) */
#define	dapl_os_memzero(loc, size)	memset((loc), 0, (size))

/* void * dapl_os_memcpy(void *dest, const void *src, int len) */
#define	dapl_os_memcpy(dest, src, len)	memcpy((dest), (src), (len))

/* int dapl_os_memcmp(const void *mem1, const void *mem2, int len) */
#define	dapl_os_memcmp(mem1, mem2, len)	memcmp((mem1), (mem2), (len))

/*
 * String Functions
 */

/* unsigned int dapl_os_strlen(const char *str) */
#define	dapl_os_strlen(str)	strlen((str))
/* char * dapl_os_strdup(const char *str) */
#define	dapl_os_strdup(str)	strdup((str))
/* char *strcpy(char *dest, char *src) */
#define	dapl_os_strcpy(dest, src) 	strcpy((dest), (src))
/* char *strncpy(char *s1, const char *s2, size_t n) */
#define	dapl_os_strncpy(dest, src, len) strncpy((dest), (src), (len))
/* char *strcat(char *dest, char *src) */
#define	dapl_os_strcat(dest, src) 	strcat((dest), (src))

/*
 * Timer Functions
 */

typedef DAT_UINT64		DAPL_OS_TIMEVAL;


typedef unsigned long long int	DAPL_OS_TICKS;

/* function prototypes */

/*
 * Sleep for the number of micro seconds specified by the invoking
 * function
 *
 * void dapl_os_sleep_usec(int sleep_time)
 */
#define	dapl_os_sleep_usec(sleep_time)	{				\
		struct timespec sleep_spec;				\
		sleep_spec.tv_sec = (sleep_time) / 100000;		\
		sleep_spec.tv_nsec = (sleep_time) % 100000 * 1000;	\
		nanosleep(&sleep_spec, NULL);				\
		}

DAT_RETURN dapl_os_get_time(DAPL_OS_TIMEVAL *);

/*
 *
 * Name Service Helper functions
 *
 */
#if defined(IBHOSTS_NAMING)
#define	dapls_osd_getaddrinfo(name, addr_ptr)		\
				getaddrinfo((name), NULL, NULL, (addr_ptr))
#define	dapls_osd_freeaddrinfo(addr) freeaddrinfo((addr))

#endif /* IBHOSTS_NAMING */

/*
 * *printf format helpers. We use the C string constant concatenation
 * ability to define 64 bit formats, which unfortunatly are non standard
 * in the C compiler world. E.g. %llx for gcc, %I64x for Windows
 */
#define	F64d   "%lld"
#define	F64u   "%llu"
#define	F64x   "%llx"
#define	F64X   "%llX"


/*
 *  Conversion Functions
 */

/* long int dapl_os_strtol(const char *nptr, char **endptr, int base) */
#define	dapl_os_strtol(nptr, endptr, base)	strtol((nptr), (endptr), (base))

/*
 *  Helper Functions
 */


#define	dapl_os_assert(expression)	assert((expression))
#define	dapl_os_printf			printf
#define	dapl_os_vprintf(fmt, args)	vprintf((fmt), (args))
#define	dapl_os_syslog(fmt, args)	vsyslog(LOG_USER | LOG_DEBUG,	\
						(fmt), (args))
#ifdef __cplusplus
}
#endif

#endif /* _DAPL_OSD_H_ */
