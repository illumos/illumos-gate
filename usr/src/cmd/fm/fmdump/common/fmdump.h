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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#ifndef	_FMDUMP_H
#define	_FMDUMP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <synch.h>

#include <sys/types.h>
#include <sys/fm/protocol.h>

#include <fm/fmd_log.h>
#include <fm/fmd_msg.h>
#include <fm/libtopo.h>

#ifdef DEBUG
#define	ASSERT(x) (assert(x))
#else
#define	ASSERT(x)
#endif

enum {
	FMDUMP_SHORT,
	FMDUMP_VERB1,
	FMDUMP_VERB2,
	FMDUMP_PRETTY,
	FMDUMP_MSG,
	FMDUMP_JSON,
	FMDUMP_NFMTS
};

typedef struct fmdump_ops {
	const char *do_label;
	struct fmdump_fmt {
		const char *do_hdr;
		fmd_log_rec_f *do_func;
	} do_formats[FMDUMP_NFMTS];
} fmdump_ops_t;

typedef struct fmdump_arg {
	const struct fmdump_fmt *da_fmt;
	fmd_log_filter_t *da_fv;
	uint_t da_fc;
	FILE *da_fp;
} fmdump_arg_t;

typedef struct fmdump_lyr {
	fmd_log_rec_f *dy_func;
	void *dy_arg;
	FILE *dy_fp;
} fmdump_lyr_t;

extern const fmdump_ops_t fmdump_err_ops;
extern const fmdump_ops_t fmdump_flt_ops;
extern const fmdump_ops_t fmdump_asru_ops;
extern const fmdump_ops_t fmdump_info_ops;

extern const char *g_pname;
extern ulong_t g_errs;
extern ulong_t g_recs;
extern char *g_root;

extern struct topo_hdl *g_thp;
extern fmd_msg_hdl_t *g_msg;

extern void fmdump_printf(FILE *, const char *, ...);
extern void fmdump_warn(const char *, ...);
extern void fmdump_vwarn(const char *, va_list);

extern char *fmdump_date(char *, size_t, const fmd_log_record_t *);
extern char *fmdump_year(char *, size_t, const fmd_log_record_t *);
extern char *fmdump_nvl2str(nvlist_t *nvl);

extern int fmdump_render_nvlist(nvlist_prtctl_t, void *, nvlist_t *,
    const char *, nvlist_t *);

extern int fmdump_print_json(fmd_log_t *, const fmd_log_record_t *, FILE *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMDUMP_H */
