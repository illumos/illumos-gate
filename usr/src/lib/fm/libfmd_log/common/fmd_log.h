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
 *
 * Copyright 2024 Oxide Computer Co.
 */

#ifndef	_FMD_LOG_H
#define	_FMD_LOG_H

#include <libnvpair.h>
#include <exacct.h>
#include <regex.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Fault Management Daemon Log File Interfaces
 *
 * Note: The contents of this file are private to the implementation of the
 * Solaris system and FMD subsystem and are subject to change at any time
 * without notice.  Applications and drivers using these interfaces will fail
 * to run on future releases.  These interfaces should not be used for any
 * purpose until they are publicly documented for use outside of Sun.
 */

#define	FMD_LOG_VERSION	3		/* library ABI interface version */

typedef struct fmd_log fmd_log_t;

extern fmd_log_t *fmd_log_open(int, const char *, int *);
extern void fmd_log_close(fmd_log_t *);
extern const char *fmd_log_label(fmd_log_t *);

extern const char *fmd_log_errmsg(fmd_log_t *, int);
extern int fmd_log_errno(fmd_log_t *);

typedef struct fmd_log_header {
	const char *log_creator;	/* ea_get_creator(3EXACCT) string */
	const char *log_hostname;	/* ea_get_hostname(3EXACCT) string */
	const char *log_label;		/* fmd(8) log file label */
	const char *log_version;	/* fmd(8) log file version */
	const char *log_osrelease;	/* uname(1) -r value at creation time */
	const char *log_osversion;	/* uname(1) -v value at creation time */
	const char *log_platform;	/* uname(1) -i value at creation time */
	const char *log_uuid;		/* fmd(8) log file uuid */
} fmd_log_header_t;

extern void fmd_log_header(fmd_log_t *, fmd_log_header_t *);

typedef struct fmd_log_record {
	ea_object_t *rec_grp;		/* log file exacct record group */
	nvlist_t *rec_nvl;		/* protocol name-value pair list */
	const char *rec_class;		/* protocol event class */
	uint64_t rec_sec;		/* time-of-day seconds */
	uint64_t rec_nsec;		/* time-of-day nanoseconds */
	struct fmd_log_record *rec_xrefs; /* array of cross-references */
	uint32_t rec_nrefs;		/* size of rec_xrefs array */
	off64_t rec_off;		/* file offset (if requested) */
} fmd_log_record_t;

typedef int fmd_log_rec_f(fmd_log_t *, const fmd_log_record_t *, void *);
typedef int fmd_log_err_f(fmd_log_t *, void *);

extern int fmd_log_rewind(fmd_log_t *);
extern int fmd_log_iter(fmd_log_t *, fmd_log_rec_f *, void *);
extern int fmd_log_seek(fmd_log_t *, off64_t);

#define	FMD_LOG_XITER_REFS	0x1	/* load event cross-references */
#define	FMD_LOG_XITER_OFFS	0x2	/* compute rec_off for each record */
#define	FMD_LOG_XITER_MASK	0x3	/* mask of all valid flag bits */

typedef struct fmd_log_filter {
	fmd_log_rec_f *filt_func;	/* filter function (see below) */
	void *filt_arg;			/* filter argument (see below) */
} fmd_log_filter_t;

extern fmd_log_rec_f fmd_log_filter_class;	/* char *name of event class */
extern fmd_log_rec_f fmd_log_filter_uuid;	/* char *uuid of list.suspect */
extern fmd_log_rec_f fmd_log_filter_before;	/* struct timeval * latest */
extern fmd_log_rec_f fmd_log_filter_after;	/* struct timeval * earliest */
extern fmd_log_rec_f fmd_log_filter_nv;		/* char *namevalue in event */
extern fmd_log_rec_f fmd_log_filter_nv_multi;	/* multiple name-value pairs */

extern int fmd_log_filter(fmd_log_t *,
    uint_t, fmd_log_filter_t *, const fmd_log_record_t *);

typedef struct fmd_log_filter_nvarg {
	char	*nvarg_name;
	char	*nvarg_value;
	regex_t	*nvarg_value_regex;
	struct fmd_log_filter_nvarg *nvarg_next;
} fmd_log_filter_nvarg_t;

/*
 * fmd_log_xiter() can be used to perform sophisticated iteration over an fmd
 * log file such as that required by fmdump(8).  The arguments are as follows:
 *
 * fmd_log_t *lp - log to use for iteration from fmd_log_open()
 * uint_t iflags - FMD_LOG_XITER_* flags (see above)
 * uint_t filtc - count of number of filters (or zero for no filtering)
 * fmd_log_filter_t *filtv - array of 'filtc' filter structures
 * fmd_log_rec_f *rfunc - function to invoke for each record in log
 * fmd_log_err_f *efunc - function to invoke for any errors in log
 * void *private - argument to pass to 'rfunc' and 'efunc' callbacks
 * ulong_t *cntp - pointer to storage for record count (or NULL)
 */
extern int fmd_log_xiter(fmd_log_t *, uint_t, uint_t, fmd_log_filter_t *,
    fmd_log_rec_f *, fmd_log_err_f *, void *, ulong_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_LOG_H */
