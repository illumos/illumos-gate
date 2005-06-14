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
 * Copyright (c) 1992-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_AUDIODEBUG_H
#define	_SYS_AUDIODEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Audio debugging macros
 */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(AUDIOTRACE) || defined(DBRITRACE)

#ifndef NAUDIOTRACE
#define	NAUDIOTRACE 1024
#endif

struct audiotrace {
	int count;
	int function;		/* address of function */
	int trace_action;	/* descriptive 4 characters */
	int object;		/* object operated on */
};

extern struct audiotrace audiotrace_buffer[];
extern struct audiotrace *audiotrace_ptr;
extern int audiotrace_count;

#define	ATRACEINIT() {				\
	if (audiotrace_ptr == NULL)		\
		audiotrace_ptr = audiotrace_buffer; \
	}

#define	LOCK_TRACE()	(uint_t)ddi_enter_critical()
#define	UNLOCK_TRACE(x)	ddi_exit_critical((uint_t)x)

#if defined(AUDIOTRACE)
#define	ATRACE(func, act, obj) {		\
	int __s = LOCK_TRACE();			\
	int *_p = &audiotrace_ptr->count;	\
	*_p++ = ++audiotrace_count;		\
	*_p++ = (int)(func);			\
	*_p++ = (int)(act);			\
	*_p++ = (int)(obj);			\
	if ((struct audiotrace *)(void *)_p >= &audiotrace_buffer[NAUDIOTRACE])\
		audiotrace_ptr = audiotrace_buffer; \
	else					\
		audiotrace_ptr = (struct audiotrace *)(void *)_p; \
	UNLOCK_TRACE(__s);			\
	}
#else
#define	ATRACE(a, b, c)
#endif

#if defined(DBRITRACE)
#define	DTRACE(func, act, obj) {		\
	int __s = LOCK_TRACE();			\
	int *_p = &audiotrace_ptr->count;	\
	*_p++ = ++audiotrace_count;		\
	*_p++ = (int)(func);			\
	*_p++ = (int)(act);			\
	*_p++ = (int)(obj);			\
	if ((struct audiotrace *)(void *)_p >= &audiotrace_buffer[NAUDIOTRACE])\
		audiotrace_ptr = audiotrace_buffer; \
	else					\
		audiotrace_ptr = (struct audiotrace *)(void *)_p; \
	UNLOCK_TRACE(__s);			\
	}
#else
#define	DTRACE(a, b, c)
#endif

#else	/* !AUDIOTRACE */

/* If no tracing, define no-ops */
#define	ATRACEINIT()
#define	ATRACE(a, b, c)
#define	DTRACE(a, b, c)

#endif	/* !AUDIOTRACE */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_AUDIODEBUG_H */
