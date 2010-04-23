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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_MUTEX_H
#define	_SYS_MUTEX_H

#ifndef	_ASM
#include <sys/types.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

/*
 * Public interface to mutual exclusion locks.  See mutex(9F) for details.
 *
 * The basic mutex type is MUTEX_ADAPTIVE, which is expected to be used
 * in almost all of the kernel.  MUTEX_SPIN provides interrupt blocking
 * and must be used in interrupt handlers above LOCK_LEVEL.  The iblock
 * cookie argument to mutex_init() encodes the interrupt level to block.
 * The iblock cookie must be NULL for adaptive locks.
 *
 * MUTEX_DEFAULT is the type usually specified (except in drivers) to
 * mutex_init().  It is identical to MUTEX_ADAPTIVE.
 *
 * MUTEX_DRIVER is always used by drivers.  mutex_init() converts this to
 * either MUTEX_ADAPTIVE or MUTEX_SPIN depending on the iblock cookie.
 *
 * Mutex statistics can be gathered on the fly, without rebooting or
 * recompiling the kernel, via the lockstat driver (lockstat(7D)).
 */
typedef enum {
	MUTEX_ADAPTIVE = 0,	/* spin if owner is running, otherwise block */
	MUTEX_SPIN = 1,		/* block interrupts and spin */
	MUTEX_DRIVER = 4,	/* driver (DDI) mutex */
	MUTEX_DEFAULT = 6	/* kernel default mutex */
} kmutex_type_t;

typedef struct mutex {
#ifdef _LP64
	void	*_opaque[1];
#else
	void	*_opaque[2];
#endif
} kmutex_t;

#ifdef _KERNEL

/*
 * A padded mutex, one per 64 byte cache line.  Use when false sharing is
 * an issue but beware of the extra memory it uses.  Consumers may want to
 * consider aligning their pad_mutex_t's to a cache line boundary as well.
 */
typedef struct pad_mutex {
	kmutex_t	pad_mutex;
#ifdef _LP64
	char		pad_pad[64 - sizeof (kmutex_t)];
#endif
} pad_mutex_t;

#define	MUTEX_HELD(x)		(mutex_owned(x))
#define	MUTEX_NOT_HELD(x)	(!mutex_owned(x) || panicstr || quiesce_active)

extern	void	mutex_init(kmutex_t *, char *, kmutex_type_t, void *);
extern	void	mutex_destroy(kmutex_t *);
extern	void	mutex_enter(kmutex_t *);
extern	int	mutex_tryenter(kmutex_t *);
extern	void	mutex_exit(kmutex_t *);
extern	int	mutex_owned(const kmutex_t *);
extern	struct _kthread *mutex_owner(const kmutex_t *);

extern  ushort_t mutex_backoff_base;
extern  uint_t mutex_backoff_cap;
extern  ushort_t mutex_cap_factor;
extern  uchar_t mutex_backoff_shift;
extern  void (*mutex_lock_delay)(uint_t);
extern  uint_t (*mutex_lock_backoff)(uint_t);
extern  void (*mutex_delay)(void);
extern  void mutex_delay_default(void);
extern  void mutex_sync(void);

extern	void default_lock_delay(uint_t);
extern	uint_t default_lock_backoff(uint_t);

#endif	/* _KERNEL */

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MUTEX_H */
