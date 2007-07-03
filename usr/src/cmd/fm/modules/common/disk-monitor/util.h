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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _UTIL_H
#define	_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Utility functions and macros
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

extern int _dm_assert(const char *assertion, const char *file, int line,
    const char *func);

#if defined(__STDC__)
#if __STDC_VERSION__ - 0 >= 199901L
#define	dm_assert(EX) (void)((EX) ? 0 : \
	_dm_assert(#EX, __FILE__, __LINE__, __func__))
#else
#define	dm_assert(EX) (void)((EX) ? 0 : \
	_dm_assert(#EX, __FILE__, __LINE__, NULL))
#endif /* __STDC_VERSION__ - 0 >= 199901L */
#else
#define	dm_assert(EX) (void)((EX) ? 0 : \
	_dm_assert("EX", __FILE__, __LINE__, NULL))
#endif  /* __STDC__ */

/*
 * The following structures comprise the implementation of the
 * queue structure that's used to construct the list of state
 * changes.  Removals from the queue are blocking operations that
 * cause the thread to wait until new entries are added.
 */
struct q_node {
	void			*data;
	struct q_node		*next;
};

typedef struct q_head {
	/*
	 * Block On Empty (when queue is empty, the calling thread will be
	 * blocked until something is added)
	 */
	boolean_t		boe;
	pthread_mutex_t		mutex;
	pthread_cond_t		cvar;
	void			*(*nalloc)(size_t);
	void			(*nfree)(void *, size_t);
	void			(*data_dealloc)(void *);
	struct q_node		*nodep;
} qu_t;

typedef enum log_class {
	MM_CONF		= 0x0001,
	MM_HPMGR	= 0x0004,
	MM_SCHGMGR	= 0x0008,
	MM_MAIN		= 0x0040,
	MM_TOPO 	= 0x0100,
	MM_ERR		= 0x0200,
	MM_WARN		= 0x0400,
	MM_NOTE		= 0x0800,
	MM_OTHER	= 0x1000
} log_class_t;

extern void queue_add(qu_t *qp, void *data);
extern void *queue_remove(qu_t *qp);
extern qu_t *new_queue(boolean_t block_on_empty, void *(*nodealloc)(size_t),
    void (*nodefree)(void *, size_t), void (*deallocator)(void *));
extern void queue_free(qu_t **qp);

extern void *dmalloc(size_t sz);
extern void *dzmalloc(size_t sz);
extern char *dstrdup(const char *s);
extern void dfree(void *p, size_t sz);
extern void dstrfree(char *s);

extern void log_msg(log_class_t cl, const char *fmt, ...);
extern void log_err(const char *fmt, ...);
extern void log_warn(const char *fmt, ...);
extern void log_warn_e(const char *fmt, ...);
extern void vcont(log_class_t cl, const char *fmt, va_list val);

#ifdef	__cplusplus
}
#endif

#endif /* _UTIL_H */
