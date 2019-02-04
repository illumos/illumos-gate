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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef	_FMD_ADM_H
#define	_FMD_ADM_H

#include <fm/fmd_api.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Fault Management Daemon Administrative Interfaces
 *
 * Note: The contents of this file are private to the implementation of the
 * Solaris system and FMD subsystem and are subject to change at any time
 * without notice.  Applications and drivers using these interfaces will fail
 * to run on future releases.  These interfaces should not be used for any
 * purpose until they are publicly documented for use outside of Sun.
 */

#define	FMD_ADM_VERSION	1		/* library ABI interface version */
#define	FMD_ADM_PROGRAM	0		/* connect library to system fmd */

typedef struct fmd_adm fmd_adm_t;

extern fmd_adm_t *fmd_adm_open(const char *, uint32_t, int);
extern void fmd_adm_close(fmd_adm_t *);
extern const char *fmd_adm_errmsg(fmd_adm_t *);

typedef struct fmd_adm_stats {
	fmd_stat_t *ams_buf;		/* statistics data array */
	uint_t ams_len;			/* length of data array */
} fmd_adm_stats_t;

extern int fmd_adm_stats_read(fmd_adm_t *, const char *, fmd_adm_stats_t *);
extern int fmd_adm_stats_free(fmd_adm_t *, fmd_adm_stats_t *);

typedef struct fmd_adm_modinfo {
	const char *ami_name;		/* string name of module */
	const char *ami_desc;		/* module description */
	const char *ami_vers;		/* module version */
	uint_t ami_flags;		/* flags (see below) */
} fmd_adm_modinfo_t;

#define	FMD_ADM_MOD_FAILED	0x1	/* module has failed */

typedef int fmd_adm_module_f(const fmd_adm_modinfo_t *, void *);

extern int fmd_adm_module_iter(fmd_adm_t *, fmd_adm_module_f *, void *);
extern int fmd_adm_module_load(fmd_adm_t *, const char *);
extern int fmd_adm_module_unload(fmd_adm_t *, const char *);
extern int fmd_adm_module_reset(fmd_adm_t *, const char *);
extern int fmd_adm_module_stats(fmd_adm_t *, const char *, fmd_adm_stats_t *);
extern int fmd_adm_module_gc(fmd_adm_t *, const char *);

typedef struct fmd_adm_rsrcinfo {
	const char *ari_fmri;		/* fmri name of resource */
	const char *ari_uuid;		/* uuid name of resource */
	const char *ari_case;		/* uuid of case associated w/ state */
	uint_t ari_flags;		/* flags (see below) */
} fmd_adm_rsrcinfo_t;

#define	FMD_ADM_RSRC_FAULTY	0x1	/* resource is faulty */
#define	FMD_ADM_RSRC_UNUSABLE	0x2	/* resource is unusable */
#define	FMD_ADM_RSRC_INVISIBLE	0x4	/* resource is not directly visible */

typedef struct fmd_adm_caseinfo {
	const char *aci_uuid;
	const char *aci_code;
	const char *aci_url;
	nvlist_t *aci_event;
} fmd_adm_caseinfo_t;

typedef int fmd_adm_rsrc_f(const fmd_adm_rsrcinfo_t *, void *);
typedef int fmd_adm_case_f(const fmd_adm_caseinfo_t *, void *);

extern int fmd_adm_rsrc_count(fmd_adm_t *, int, uint32_t *);
extern int fmd_adm_rsrc_iter(fmd_adm_t *, int, fmd_adm_rsrc_f *, void *);
extern int fmd_adm_rsrc_flush(fmd_adm_t *, const char *);
extern int fmd_adm_rsrc_repaired(fmd_adm_t *, const char *);
extern int fmd_adm_rsrc_replaced(fmd_adm_t *, const char *);
extern int fmd_adm_rsrc_acquit(fmd_adm_t *, const char *, const char *);
extern int fmd_adm_case_repair(fmd_adm_t *, const char *);
extern int fmd_adm_case_acquit(fmd_adm_t *, const char *);
extern int fmd_adm_case_iter(fmd_adm_t *, const char *, fmd_adm_case_f *,
    void *);

typedef struct fmd_adm_serdinfo {
	const char *asi_name;		/* name of serd engine */
	uint64_t asi_delta;		/* nsecs from oldest event to now */
	uint64_t asi_n;			/* N parameter (event count) */
	uint64_t asi_t;			/* T parameter (nanoseconds) */
	uint_t asi_count;		/* number of events in engine */
	uint_t asi_flags;		/* flags (see below) */
} fmd_adm_serdinfo_t;

#define	FMD_ADM_SERD_FIRED	0x1	/* serd engine has fired */

typedef int fmd_adm_serd_f(const fmd_adm_serdinfo_t *, void *);

extern int fmd_adm_serd_iter(fmd_adm_t *, const char *,
    fmd_adm_serd_f *, void *);
extern int fmd_adm_serd_reset(fmd_adm_t *, const char *, const char *);

typedef void fmd_adm_xprt_f(id_t, void *);

extern int fmd_adm_xprt_iter(fmd_adm_t *, fmd_adm_xprt_f *, void *);
extern int fmd_adm_xprt_stats(fmd_adm_t *, id_t, fmd_adm_stats_t *);

extern int fmd_adm_log_rotate(fmd_adm_t *, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_ADM_H */
