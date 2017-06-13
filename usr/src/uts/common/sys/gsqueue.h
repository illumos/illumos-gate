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
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _SYS_GSQUEUE_H
#define	_SYS_GSQUEUE_H

/*
 * Standard interfaces to serializaion queues for everyone (except IP).
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

typedef struct gsqueue gsqueue_t;
typedef struct gsqueue_set gsqueue_set_t;

typedef void (*gsqueue_cb_f)(gsqueue_set_t *, gsqueue_t *, void *, boolean_t);
typedef void (*gsqueue_proc_f)(void *, mblk_t *, gsqueue_t *, void *);

extern gsqueue_set_t *gsqueue_set_create(pri_t);
extern void gsqueue_set_destroy(gsqueue_set_t *);
extern gsqueue_t *gsqueue_set_get(gsqueue_set_t *, uint_t);

extern uintptr_t gsqueue_set_cb_add(gsqueue_set_t *, gsqueue_cb_f, void *);
extern int gsqueue_set_cb_remove(gsqueue_set_t *, uintptr_t);

#define	GSQUEUE_FILL	0x0001
#define	GSQUEUE_NODRAIN	0x0002
#define	GSQUEUE_PROCESS	0x0004

extern void gsqueue_enter_one(gsqueue_t *, mblk_t *, gsqueue_proc_f, void *,
    int, uint8_t);

#define	GSQUEUE_DEFAULT_PRIORITY	MAXCLSYSPRI

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GSQUEUE_H */
