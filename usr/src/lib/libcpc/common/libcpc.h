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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBCPC_H
#define	_LIBCPC_H

#include <sys/types.h>
#include <sys/cpc_impl.h>
#include <inttypes.h>
#include <libpctx.h>
#include <stdarg.h>
#include <signal.h>
#include <string.h>
#include <ucontext.h>
#include <sys/processor.h>

/*
 * This library allows hardware performance counters present in
 * certain processors to be used by applications to monitor their
 * own statistics, the statistics of others, or the statistics of a given CPU.
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct __cpc cpc_t;
typedef struct __cpc_set cpc_set_t;
typedef struct __cpc_buf cpc_buf_t;

/*
 * Current library version must be passed to cpc_open().
 */
#define	CPC_VER_CURRENT		2

/*
 * Initializes the library for use and returns a pointer to an identifier that
 * must be used as the cpc argument in subsequent libcpc calls.
 */
extern cpc_t *cpc_open(int ver);
extern int cpc_close(cpc_t *cpc);

/*
 * Query information about the underlying processor.
 */
extern uint_t cpc_npic(cpc_t *cpc);
extern uint_t cpc_caps(cpc_t *cpc);
extern const char *cpc_cciname(cpc_t *cpc);
extern const char *cpc_cpuref(cpc_t *cpc);

/*
 * A vprintf-like error handling routine can be passed to the
 * library for use by more sophisticated callers.
 * If specified as NULL, errors are written to stderr.
 */
typedef void (cpc_errhndlr_t)(const char *fn, int subcode, const char *fmt,
    va_list ap);
extern int cpc_seterrhndlr(cpc_t *cpc, cpc_errhndlr_t *fn);

extern cpc_set_t *cpc_set_create(cpc_t *cpc);
extern int cpc_set_destroy(cpc_t *cpc, cpc_set_t *set);

/*
 * If successful, returns an index for the new request within the set which is
 * needed later to retrieve the request's data.
 * Returns -1 if unsuccessful and sets errno to indicate the error.
 */
extern int cpc_set_add_request(cpc_t *cpc, cpc_set_t *set, const char *event,
    uint64_t preset, uint_t flags, uint_t nattrs, const cpc_attr_t *attrs);

extern cpc_buf_t *cpc_buf_create(cpc_t *cpc, cpc_set_t *set);
extern int cpc_buf_destroy(cpc_t *cpc, cpc_buf_t *buf);

/*
 * Binds the set to the current LWP.
 */
extern int cpc_bind_curlwp(cpc_t *cpc, cpc_set_t *set, uint_t flags);

/*
 * Binds the set to the specified LWP in a process controlled via libpctx.
 */
extern int cpc_bind_pctx(cpc_t *cpc, pctx_t *pctx, id_t id, cpc_set_t *set,
	    uint_t flags);

/*
 * Binds the set to the specified CPU.  The process must have sufficient
 * privileges to bind to the CPU via processor_bind(2).  An LWP can only
 * bind to one CPU at a time.  To measure more than one CPU simultaneously,
 * one LWP must be created for each CPU.
 */
extern int cpc_bind_cpu(cpc_t *cpc, processorid_t id, cpc_set_t *set,
	uint_t flags);

/*
 * Set the starting value for the indexed counter, and restart counting for a
 * set that was frozen by a counter overflow.
 */
extern int cpc_request_preset(cpc_t *cpc, int index, uint64_t preset);
extern int cpc_set_restart(cpc_t *cpc, cpc_set_t *set);

/*
 * Unbinds the set and frees up associated resources. cpc_buf_t's must be
 * explicitly freed via cpc_buf_destroy().
 */
extern int cpc_unbind(cpc_t *cpc, cpc_set_t *set);

/*
 * Samples a set into a cpc_buf_t. The provided set must be bound, and the
 * buf must have been created with the set being sampled.
 */
extern int cpc_set_sample(cpc_t *cpc, cpc_set_t *set, cpc_buf_t *buf);

extern void cpc_buf_sub(cpc_t *cpc, cpc_buf_t *ds, cpc_buf_t *a, cpc_buf_t *b);
extern void cpc_buf_add(cpc_t *cpc, cpc_buf_t *ds, cpc_buf_t *a, cpc_buf_t *b);
extern void cpc_buf_copy(cpc_t *cpc, cpc_buf_t *ds, cpc_buf_t *src);
extern void cpc_buf_zero(cpc_t *cpc, cpc_buf_t *buf);

/*
 * Gets or sets the value of the request specified by index.
 */
extern int cpc_buf_get(cpc_t *cpc, cpc_buf_t *buf, int index, uint64_t *val);
extern int cpc_buf_set(cpc_t *cpc, cpc_buf_t *buf, int index, uint64_t val);
extern hrtime_t cpc_buf_hrtime(cpc_t *cpc, cpc_buf_t *buf);
extern uint64_t cpc_buf_tick(cpc_t *cpc, cpc_buf_t *buf);

extern void cpc_walk_requests(cpc_t *cpc, cpc_set_t *set, void *arg,
    void (*action)(void *arg, int index, const char *event, uint64_t preset,
	uint_t flags, int nattrs, const cpc_attr_t *attrs));

extern void cpc_walk_events_all(cpc_t *cpc, void *arg,
    void (*action)(void *arg, const char *event));
extern void cpc_walk_generic_events_all(cpc_t *cpc, void *arg,
    void (*action)(void *arg, const char *event));
extern void cpc_walk_events_pic(cpc_t *cpc, uint_t picno, void *arg,
    void (*action)(void *arg, uint_t picno, const char *event));
extern void cpc_walk_generic_events_pic(cpc_t *cpc, uint_t picno, void *arg,
    void (*action)(void *arg, uint_t picno, const char *event));
extern void cpc_walk_attrs(cpc_t *cpc, void *arg,
    void (*action)(void *arg, const char *attr));

extern int cpc_enable(cpc_t *cpc);
extern int cpc_disable(cpc_t *cpc);

#if defined(__sparc) || defined(__i386)

/*
 * Obsolete libcpc interfaces.
 */
#define	CPC_VER_NONE 0

typedef struct _cpc_event cpc_event_t;

extern uint_t cpc_version(uint_t ver);
extern int cpc_access();
extern int cpc_getcpuver(void);
extern const char *cpc_getcciname(int cpuver);
extern const char *cpc_getcpuref(int cpuver);
extern uint_t cpc_getnpic(int cpuver);
typedef void (cpc_errfn_t)(const char *fn, const char *fmt, va_list ap);
extern void cpc_seterrfn(cpc_errfn_t *errfn);
extern const char *cpc_getusage(int cpuver);
extern void cpc_walk_names(int cpuver, int regno, void *arg,
    void (*action)(void *arg, int regno, const char *name, uint8_t bits));
extern int cpc_strtoevent(int cpuver, const char *spec, cpc_event_t *event);
extern char *cpc_eventtostr(cpc_event_t *event);
extern void cpc_event_accum(cpc_event_t *accum, cpc_event_t *event);
extern void cpc_event_diff(cpc_event_t *diff,
    cpc_event_t *left, cpc_event_t *right);
extern int cpc_bind_event(cpc_event_t *event, int flags);
extern int cpc_take_sample(cpc_event_t *event);
extern int cpc_count_usr_events(int enable);
extern int cpc_count_sys_events(int enable);
extern int cpc_rele(void);
extern int cpc_pctx_bind_event(pctx_t *pctx,
    id_t lwpid, cpc_event_t *event, int flags);
extern int cpc_pctx_take_sample(pctx_t *pctx, id_t lwpid, cpc_event_t *event);
extern int cpc_pctx_rele(pctx_t *pctx, id_t lwpid);
extern int cpc_pctx_invalidate(pctx_t *pctx, id_t lwpid);
extern int cpc_shared_open(void);
extern void cpc_shared_close(int fd);
extern int cpc_shared_bind_event(int fd, cpc_event_t *event, int flags);
extern int cpc_shared_take_sample(int fd, cpc_event_t *event);
extern int cpc_shared_rele(int fd);

#endif /* __sparc || __i386 */

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBCPC_H */
