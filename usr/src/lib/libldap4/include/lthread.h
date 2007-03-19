/*
 *
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* lthread.h - ldap threads header file */

#ifndef _LTHREAD_H
#define _LTHREAD_H

#if defined( THREAD_SUNOS4_LWP )
/***********************************
 *                                 *
 * thread definitions for sunos4   *
 *                                 *
 ***********************************/

#define _THREAD

#include <lwp/lwp.h>
#include <lwp/stackdep.h>

typedef void	*(*VFP)();

/* thread attributes and thread type */
typedef int		pthread_attr_t;
typedef thread_t	pthread_t;

/* default attr states */
#define pthread_mutexattr_default	NULL
#define pthread_condattr_default	NULL

/* thread state - joinable or not */
#define PTHREAD_CREATE_JOINABLE	0
#define PTHREAD_CREATE_DETACHED	1
/* thread scope - who is in scheduling pool */
#define PTHREAD_SCOPE_PROCESS	0
#define PTHREAD_SCOPE_SYSTEM	1

/* mutex attributes and mutex type */
typedef int	pthread_mutexattr_t;
typedef mon_t	pthread_mutex_t;

/* condition variable attributes and condition variable type */
typedef int	pthread_condattr_t;
typedef struct lwpcv {
	int		lcv_created;
	cv_t		lcv_cv;
} pthread_cond_t;

/* mutex and condition variable scope - process or system */
#define PTHREAD_SHARE_PRIVATE	0
#define PTHREAD_SHARE_PROCESS	1

#else /* end sunos4 */

#if defined( THREAD_SUNOS5_LWP )
/***********************************
 *                                 *
 * thread definitions for sunos5   *
 *                                 *
 ***********************************/

#define _THREAD

#include <thread.h>
#include <synch.h>

typedef void	*(*VFP)();

/* sunos5 threads are preemptive */
#define PTHREAD_PREEMPTIVE	1

#ifndef _PTHREAD_H

/* thread attributes and thread type */
typedef int		pthread_attr_t;
typedef thread_t	pthread_t;

/* thread state - joinable or not */
#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED THR_DETACHED
/* thread scope - who is in scheduling pool */
#define PTHREAD_SCOPE_PROCESS   0
#define PTHREAD_SCOPE_SYSTEM    THR_BOUND

/* mutex attributes and mutex type */
typedef int	pthread_mutexattr_t;
typedef mutex_t	pthread_mutex_t;

/* condition variable attributes and condition variable type */
typedef int     pthread_condattr_t;
typedef cond_t	pthread_cond_t;

#endif /* _PTHREAD_H */

/* default attr states */
#define pthread_mutexattr_default	NULL
#define pthread_condattr_default	NULL

/* mutex and condition variable scope - process or system */
#define PTHREAD_SHARE_PRIVATE   USYNC_THREAD
#define PTHREAD_SHARE_PROCESS   USYNC_PROCESS

#else /* end sunos5 */

#if defined( THREAD_MIT_PTHREADS )
/***********************************
 *                                 *
 * definitions for mit pthreads    *
 *                                 *
 ***********************************/

#define _THREAD

#include <pthread.h>

#else /* end mit pthreads */

#if defined( THREAD_DCE_PTHREADS )
/***********************************
 *                                 *
 * definitions for dce pthreads    *
 *                                 *
 ***********************************/

#define _THREAD

#include <pthread.h>

/* dce threads are preemptive */
#define PTHREAD_PREEMPTIVE	1

#define pthread_attr_init( a )		pthread_attr_create( a )
#define pthread_attr_destroy( a )	pthread_attr_delete( a )
#define pthread_attr_setdetachstate( a, b ) \
					pthread_attr_setdetach_np( a, b )

#endif /* dce pthreads */
#endif /* mit pthreads */
#endif /* sunos5 */
#endif /* sunos4 */

#ifndef _THREAD

/***********************************
 *                                 *
 * thread definitions for no       *
 * underlying library support      *
 *                                 *
 ***********************************/

typedef void	*(*VFP)();

/* thread attributes and thread type */
typedef int	pthread_attr_t;
typedef int	pthread_t;

/* default attr states */
#define pthread_mutexattr_default	NULL
#define pthread_condattr_default	NULL

/* thread state - joinable or not */
#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 0
/* thread scope - who is in scheduling pool */
#define PTHREAD_SCOPE_PROCESS   0
#define PTHREAD_SCOPE_SYSTEM    0

/* mutex attributes and mutex type */
typedef int	pthread_mutexattr_t;
typedef int	pthread_mutex_t;

/* mutex and condition variable scope - process or system */
#define PTHREAD_SHARE_PRIVATE   0
#define PTHREAD_SHARE_PROCESS   0

/* condition variable attributes and condition variable type */
typedef int     pthread_condattr_t;
typedef int	pthread_cond_t;

#endif /* no threads support */
#endif /* _LTHREAD_H */
