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

#ifndef	_FMD_API_H
#define	_FMD_API_H

#include <sys/types.h>
#include <libnvpair.h>
#include <stdarg.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Fault Management Daemon Client Interfaces
 *
 * Note: The contents of this file are private to the implementation of the
 * Solaris system and FMD subsystem and are subject to change at any time
 * without notice.  Applications and drivers using these interfaces will fail
 * to run on future releases.  These interfaces should not be used for any
 * purpose until they are publicly documented for use outside of Sun.
 */

#define	FMD_API_VERSION_1	1
#define	FMD_API_VERSION_2	2
#define	FMD_API_VERSION_3	3
#define	FMD_API_VERSION_4	4

#define	FMD_API_VERSION		FMD_API_VERSION_4

typedef struct fmd_hdl fmd_hdl_t;
typedef struct fmd_event fmd_event_t;
typedef struct fmd_case fmd_case_t;
typedef struct fmd_xprt fmd_xprt_t;

struct topo_hdl;

#define	FMD_B_FALSE	0		/* false value for booleans as int */
#define	FMD_B_TRUE	1		/* true value for booleans as int */

#ifndef	MIN
#define	MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef	MAX
#define	MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#define	FMD_TYPE_BOOL	0		/* int */
#define	FMD_TYPE_INT32	1		/* int32_t */
#define	FMD_TYPE_UINT32	2		/* uint32_t */
#define	FMD_TYPE_INT64	3		/* int64_t */
#define	FMD_TYPE_UINT64	4		/* uint64_t */
#define	FMD_TYPE_STRING	5		/* const char* */
#define	FMD_TYPE_TIME	6		/* uint64_t */
#define	FMD_TYPE_SIZE	7		/* uint64_t */

typedef struct fmd_prop {
	const char *fmdp_name;		/* property name */
	uint_t fmdp_type;		/* property type (see above) */
	const char *fmdp_defv;		/* default value */
} fmd_prop_t;

typedef struct fmd_stat {
	char fmds_name[32];		/* statistic name */
	uint_t fmds_type;		/* statistic type (see above) */
	char fmds_desc[64];		/* statistic description */
	union {
		int bool;		/* FMD_TYPE_BOOL */
		int32_t i32;		/* FMD_TYPE_INT32 */
		uint32_t ui32;		/* FMD_TYPE_UINT32 */
		int64_t i64;		/* FMD_TYPE_INT64 */
		uint64_t ui64;		/* FMD_TYPE_UINT64, TIME, SIZE */
		char *str;		/* FMD_TYPE_STRING */
	} fmds_value;
} fmd_stat_t;

typedef struct fmd_hdl_ops {
	void (*fmdo_recv)(fmd_hdl_t *, fmd_event_t *, nvlist_t *, const char *);
	void (*fmdo_timeout)(fmd_hdl_t *, id_t, void *);
	void (*fmdo_close)(fmd_hdl_t *, fmd_case_t *);
	void (*fmdo_stats)(fmd_hdl_t *);
	void (*fmdo_gc)(fmd_hdl_t *);
	int (*fmdo_send)(fmd_hdl_t *, fmd_xprt_t *, fmd_event_t *, nvlist_t *);
	void (*fmdo_topo)(fmd_hdl_t *, struct topo_hdl *);
} fmd_hdl_ops_t;

#define	FMD_SEND_SUCCESS	0	/* fmdo_send queued event */
#define	FMD_SEND_FAILED		1	/* fmdo_send unrecoverable error */
#define	FMD_SEND_RETRY		2	/* fmdo_send requests retry */

typedef struct fmd_hdl_info {
	const char *fmdi_desc;		/* fmd client description string */
	const char *fmdi_vers;		/* fmd client version string */
	const fmd_hdl_ops_t *fmdi_ops;	/* ops vector for client */
	const fmd_prop_t *fmdi_props;	/* array of configuration props */
} fmd_hdl_info_t;

extern void _fmd_init(fmd_hdl_t *);
extern void _fmd_fini(fmd_hdl_t *);

extern int fmd_hdl_register(fmd_hdl_t *, int, const fmd_hdl_info_t *);
extern void fmd_hdl_unregister(fmd_hdl_t *);

extern void fmd_hdl_subscribe(fmd_hdl_t *, const char *);
extern void fmd_hdl_unsubscribe(fmd_hdl_t *, const char *);

extern void fmd_hdl_setspecific(fmd_hdl_t *, void *);
extern void *fmd_hdl_getspecific(fmd_hdl_t *);

extern void fmd_hdl_opendict(fmd_hdl_t *, const char *);
extern struct topo_hdl *fmd_hdl_topo_hold(fmd_hdl_t *, int);
extern void fmd_hdl_topo_rele(fmd_hdl_t *, struct topo_hdl *);

#define	FMD_NOSLEEP		0x0	/* do not sleep or retry on failure */
#define	FMD_SLEEP		0x1	/* sleep or retry if alloc fails */

extern void *fmd_hdl_alloc(fmd_hdl_t *, size_t, int);
extern void *fmd_hdl_zalloc(fmd_hdl_t *, size_t, int);
extern void fmd_hdl_free(fmd_hdl_t *, void *, size_t);

extern char *fmd_hdl_strdup(fmd_hdl_t *, const char *, int);
extern void fmd_hdl_strfree(fmd_hdl_t *, char *);

extern void fmd_hdl_vabort(fmd_hdl_t *, const char *, va_list) __NORETURN;
extern void fmd_hdl_abort(fmd_hdl_t *, const char *, ...) __NORETURN;

extern void fmd_hdl_verror(fmd_hdl_t *, const char *, va_list);
extern void fmd_hdl_error(fmd_hdl_t *, const char *, ...);

extern void fmd_hdl_vdebug(fmd_hdl_t *, const char *, va_list);
extern void fmd_hdl_debug(fmd_hdl_t *, const char *, ...);

extern int32_t fmd_prop_get_int32(fmd_hdl_t *, const char *);
extern int64_t fmd_prop_get_int64(fmd_hdl_t *, const char *);
extern char *fmd_prop_get_string(fmd_hdl_t *, const char *);
extern void fmd_prop_free_string(fmd_hdl_t *, char *);

#define	FMD_STAT_NOALLOC	0x0	/* fmd should use caller's memory */
#define	FMD_STAT_ALLOC		0x1	/* fmd should allocate stats memory */

extern fmd_stat_t *fmd_stat_create(fmd_hdl_t *, uint_t, uint_t, fmd_stat_t *);
extern void fmd_stat_destroy(fmd_hdl_t *, uint_t, fmd_stat_t *);
extern void fmd_stat_setstr(fmd_hdl_t *, fmd_stat_t *, const char *);

extern fmd_case_t *fmd_case_open(fmd_hdl_t *, void *);
extern void fmd_case_reset(fmd_hdl_t *, fmd_case_t *);
extern void fmd_case_solve(fmd_hdl_t *, fmd_case_t *);
extern void fmd_case_close(fmd_hdl_t *, fmd_case_t *);

extern const char *fmd_case_uuid(fmd_hdl_t *, fmd_case_t *);
extern fmd_case_t *fmd_case_uulookup(fmd_hdl_t *, const char *);
extern void fmd_case_uuclose(fmd_hdl_t *, const char *);
extern int fmd_case_uuclosed(fmd_hdl_t *, const char *);
extern void fmd_case_uuresolved(fmd_hdl_t *, const char *);

extern int fmd_case_solved(fmd_hdl_t *, fmd_case_t *);
extern int fmd_case_closed(fmd_hdl_t *, fmd_case_t *);

extern void fmd_case_add_ereport(fmd_hdl_t *, fmd_case_t *, fmd_event_t *);
extern void fmd_case_add_serd(fmd_hdl_t *, fmd_case_t *, const char *);
extern void fmd_case_add_suspect(fmd_hdl_t *, fmd_case_t *, nvlist_t *);

extern void fmd_case_setspecific(fmd_hdl_t *, fmd_case_t *, void *);
extern void *fmd_case_getspecific(fmd_hdl_t *, fmd_case_t *);

extern void fmd_case_setprincipal(fmd_hdl_t *, fmd_case_t *, fmd_event_t *);
extern fmd_event_t *fmd_case_getprincipal(fmd_hdl_t *, fmd_case_t *);

extern fmd_case_t *fmd_case_next(fmd_hdl_t *, fmd_case_t *);
extern fmd_case_t *fmd_case_prev(fmd_hdl_t *, fmd_case_t *);

extern void fmd_buf_create(fmd_hdl_t *, fmd_case_t *, const char *, size_t);
extern void fmd_buf_destroy(fmd_hdl_t *, fmd_case_t *, const char *);
extern void fmd_buf_read(fmd_hdl_t *, fmd_case_t *,
    const char *, void *, size_t);
extern void fmd_buf_write(fmd_hdl_t *, fmd_case_t *,
    const char *, const void *, size_t);
extern size_t fmd_buf_size(fmd_hdl_t *, fmd_case_t *, const char *);

extern void fmd_serd_create(fmd_hdl_t *, const char *, uint_t, hrtime_t);
extern void fmd_serd_destroy(fmd_hdl_t *, const char *);
extern int fmd_serd_exists(fmd_hdl_t *, const char *);
extern void fmd_serd_reset(fmd_hdl_t *, const char *);
extern int fmd_serd_record(fmd_hdl_t *, const char *, fmd_event_t *);
extern int fmd_serd_fired(fmd_hdl_t *, const char *);
extern int fmd_serd_empty(fmd_hdl_t *, const char *);

extern pthread_t fmd_thr_create(fmd_hdl_t *, void (*)(void *), void *);
extern void fmd_thr_destroy(fmd_hdl_t *, pthread_t);
extern void fmd_thr_signal(fmd_hdl_t *, pthread_t);

extern id_t fmd_timer_install(fmd_hdl_t *, void *, fmd_event_t *, hrtime_t);
extern void fmd_timer_remove(fmd_hdl_t *, id_t);

extern nvlist_t *fmd_nvl_create_fault(fmd_hdl_t *,
    const char *, uint8_t, nvlist_t *, nvlist_t *, nvlist_t *);

extern int fmd_nvl_class_match(fmd_hdl_t *, nvlist_t *, const char *);
extern int fmd_nvl_fmri_expand(fmd_hdl_t *, nvlist_t *);
extern int fmd_nvl_fmri_present(fmd_hdl_t *, nvlist_t *);
extern int fmd_nvl_fmri_unusable(fmd_hdl_t *, nvlist_t *);
extern int fmd_nvl_fmri_retire(fmd_hdl_t *, nvlist_t *);
extern int fmd_nvl_fmri_unretire(fmd_hdl_t *, nvlist_t *);
extern int fmd_nvl_fmri_replaced(fmd_hdl_t *, nvlist_t *);
extern int fmd_nvl_fmri_service_state(fmd_hdl_t *, nvlist_t *);
extern int fmd_nvl_fmri_has_fault(fmd_hdl_t *, nvlist_t *, int, char *);

#define	FMD_HAS_FAULT_FRU	0
#define	FMD_HAS_FAULT_ASRU	1
#define	FMD_HAS_FAULT_RESOURCE	2

extern int fmd_nvl_fmri_contains(fmd_hdl_t *, nvlist_t *, nvlist_t *);
extern nvlist_t *fmd_nvl_fmri_translate(fmd_hdl_t *, nvlist_t *, nvlist_t *);

extern nvlist_t *fmd_nvl_alloc(fmd_hdl_t *, int);
extern nvlist_t *fmd_nvl_dup(fmd_hdl_t *, nvlist_t *, int);

extern int fmd_event_local(fmd_hdl_t *, fmd_event_t *);
extern uint64_t fmd_event_ena_create(fmd_hdl_t *);


#define	FMD_XPRT_RDONLY		0x1	/* transport is read-only */
#define	FMD_XPRT_RDWR		0x3	/* transport is read-write */
#define	FMD_XPRT_ACCEPT		0x4	/* transport is accepting connection */
#define	FMD_XPRT_SUSPENDED	0x8	/* transport starts suspended */

extern fmd_xprt_t *fmd_xprt_open(fmd_hdl_t *, uint_t, nvlist_t *, void *);
extern void fmd_xprt_close(fmd_hdl_t *, fmd_xprt_t *);
extern void fmd_xprt_post(fmd_hdl_t *, fmd_xprt_t *, nvlist_t *, hrtime_t);
extern void fmd_xprt_suspend(fmd_hdl_t *, fmd_xprt_t *);
extern void fmd_xprt_resume(fmd_hdl_t *, fmd_xprt_t *);
extern int fmd_xprt_error(fmd_hdl_t *, fmd_xprt_t *);
extern nvlist_t *fmd_xprt_translate(fmd_hdl_t *, fmd_xprt_t *, fmd_event_t *);
extern void fmd_xprt_setspecific(fmd_hdl_t *, fmd_xprt_t *, void *);
extern void *fmd_xprt_getspecific(fmd_hdl_t *, fmd_xprt_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_API_H */
