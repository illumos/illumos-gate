/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Pluribus Networks Inc.
 */

#ifndef _COMPAT_FREEBSD_SYS_MUTEX_H_
#define	_COMPAT_FREEBSD_SYS_MUTEX_H_

#ifdef	_KERNEL

#include <sys/debug.h>

#define	MTX_DEF		0x00000000
#define	MTX_SPIN	0x00000001

struct mtx;

void mtx_init(struct mtx *, char *name, const char *type_name, int opts);
void mtx_destroy(struct mtx *);

#endif	/* KERNEL */
#include_next <sys/mutex.h>
#ifdef	_KERNEL

struct mtx {
	kmutex_type_t	t;
	kmutex_t	m;
};

static __inline void mtx_lock(struct mtx *mtx)
{
	mutex_enter(&mtx->m);
}

static __inline void mtx_unlock(struct mtx *mtx)
{
	mutex_exit(&mtx->m);
}

static __inline void mtx_lock_spin(struct mtx *mtx)
{
	mutex_enter(&mtx->m);
}

static __inline void mtx_unlock_spin(struct mtx *mtx)
{
	mutex_exit(&mtx->m);
}

static __inline int mtx_owned(struct mtx *mtx)
{
	return (mutex_owned(&mtx->m));
}

#define	MA_OWNED	0

static __inline void mtx_assert(struct mtx *mtx, int what)
{
	switch (what) {
	case MA_OWNED:
		ASSERT(mutex_owned(&mtx->m));
		break;
	}
}

#endif	/* _KERNEL */

#endif	/* _COMPAT_FREEBSD_SYS_MUTEX_H_ */
