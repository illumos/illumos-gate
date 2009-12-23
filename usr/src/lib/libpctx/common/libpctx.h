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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBPCTX_H
#define	_LIBPCTX_H

#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>

/*
 * The process context library allows callers to use the facilities
 * of /proc to control processes in a simplified way by managing
 * the process via an event loop.  The controlling process expresses
 * interest in various events which are handled as callbacks by the
 * library.
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct __pctx pctx_t;

/*
 * A vprintf-like error handling routine can be passed in for use
 * by more sophisticated callers.  If specified as NULL, errors
 * are written to stderr.
 */
typedef void (pctx_errfn_t)(const char *fn, const char *fmt, va_list ap);

extern pctx_t *pctx_create(const char *filename, char *const *argv,
    void *arg, int verbose, pctx_errfn_t *errfn);
extern pctx_t *pctx_capture(pid_t pid,
    void *arg, int verbose, pctx_errfn_t *errfn);

typedef int pctx_sysc_execfn_t(pctx_t *, pid_t, id_t, char *, void *);
typedef void pctx_sysc_forkfn_t(pctx_t *, pid_t, id_t, pid_t, void *);
typedef void pctx_sysc_exitfn_t(pctx_t *, pid_t, id_t, int, void *);
typedef int pctx_sysc_lwp_createfn_t(pctx_t *, pid_t, id_t, void *);
typedef int pctx_init_lwpfn_t(pctx_t *, pid_t, id_t, void *);
typedef int pctx_fini_lwpfn_t(pctx_t *, pid_t, id_t, void *);
typedef int pctx_sysc_lwp_exitfn_t(pctx_t *, pid_t, id_t, void *);

extern void pctx_terminate(pctx_t *);

typedef	enum {
	PCTX_NULL_EVENT = 0,
	PCTX_SYSC_EXEC_EVENT,
	PCTX_SYSC_FORK_EVENT,
	PCTX_SYSC_EXIT_EVENT,
	PCTX_SYSC_LWP_CREATE_EVENT,
	PCTX_INIT_LWP_EVENT,
	PCTX_FINI_LWP_EVENT,
	PCTX_SYSC_LWP_EXIT_EVENT
} pctx_event_t;

extern int pctx_set_events(pctx_t *pctx, ...);

extern int pctx_run(pctx_t *pctx, uint_t msec, uint_t nsamples,
    int (*tick)(pctx_t *, pid_t, id_t, void *));

extern void pctx_release(pctx_t *pctx);

/*
 * Implementation-private interfaces used by libcpc.
 */
struct __cpc;
extern int __pctx_cpc(pctx_t *, struct __cpc *, int, id_t,
	void *, void *, void *, int);
extern void __pctx_cpc_register_callback(void (*)(struct __cpc *,
	struct __pctx *));

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBPCTX_H */
