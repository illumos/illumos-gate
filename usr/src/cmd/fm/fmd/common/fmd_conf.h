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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FMD_CONF_H
#define	_FMD_CONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct fmd_conf_param;

typedef struct fmd_conf_ops {
	int (*co_set)(struct fmd_conf_param *, const char *);
	void (*co_get)(const struct fmd_conf_param *, void *);
	int (*co_del)(struct fmd_conf_param *, const char *);
	void (*co_free)(struct fmd_conf_param *);
} fmd_conf_ops_t;

typedef struct fmd_conf_formal {
	const char *cf_name;
	const fmd_conf_ops_t *cf_ops;
	const char *cf_default;
} fmd_conf_formal_t;

typedef struct fmd_conf_param {
	const fmd_conf_formal_t *cp_formal;
	struct fmd_conf_param *cp_next;
	union {
		uint64_t cpv_num;
		char *cpv_str;
		void *cpv_ptr;
	} cp_value;
} fmd_conf_param_t;

typedef struct fmd_conf_defer {
	char *cd_name;
	char *cd_value;
	struct fmd_conf_defer *cd_next;
} fmd_conf_defer_t;

typedef struct fmd_conf {
	pthread_rwlock_t cf_lock;
	const fmd_conf_formal_t *cf_argv;
	int cf_argc;
	uint_t cf_flag;
	fmd_conf_param_t *cf_params;
	fmd_conf_param_t **cf_parhash;
	uint_t cf_parhashlen;
	fmd_conf_defer_t *cf_defer;
} fmd_conf_t;

typedef struct fmd_conf_verb {
	const char *cv_name;
	int (*cv_exec)(fmd_conf_t *, int, char *[]);
} fmd_conf_verb_t;

typedef struct fmd_conf_path {
	const char **cpa_argv;
	int cpa_argc;
} fmd_conf_path_t;

typedef struct fmd_conf_mode {
	const char *cm_name;
	const char *cm_desc;
	uint_t cm_bits;
} fmd_conf_mode_t;

extern int fmd_conf_mode_set(const fmd_conf_mode_t *,
    fmd_conf_param_t *, const char *);
extern void fmd_conf_mode_get(const fmd_conf_param_t *, void *);

extern int fmd_conf_notsup(fmd_conf_param_t *, const char *);
extern void fmd_conf_nop(fmd_conf_param_t *);

extern const fmd_conf_ops_t fmd_conf_bool;	/* int */
extern const fmd_conf_ops_t fmd_conf_int8;	/* int8_t */
extern const fmd_conf_ops_t fmd_conf_uint8;	/* uint8_t */
extern const fmd_conf_ops_t fmd_conf_int16;	/* int16_t */
extern const fmd_conf_ops_t fmd_conf_uint16;	/* uint16_t */
extern const fmd_conf_ops_t fmd_conf_int32;	/* int32_t */
extern const fmd_conf_ops_t fmd_conf_uint32;	/* uint32_t */
extern const fmd_conf_ops_t fmd_conf_int64;	/* int64_t */
extern const fmd_conf_ops_t fmd_conf_uint64;	/* uint64_t */
extern const fmd_conf_ops_t fmd_conf_string;	/* const char* */
extern const fmd_conf_ops_t fmd_conf_path;	/* fmd_conf_path_t* */
extern const fmd_conf_ops_t fmd_conf_list;	/* fmd_conf_path_t* */
extern const fmd_conf_ops_t fmd_conf_time;	/* hrtime_t */
extern const fmd_conf_ops_t fmd_conf_size;	/* uint64_t */
extern const fmd_conf_ops_t fmd_conf_signal;	/* int */
extern const fmd_conf_ops_t fmd_conf_parent;	/* any */

extern const char FMD_PROP_SUBSCRIPTIONS[];	/* fmd_conf_list */
extern const char FMD_PROP_DICTIONARIES[];	/* fmd_conf_list */

#define	FMD_CONF_DEFER	0x1			/* permit deferred settings */

extern fmd_conf_t *fmd_conf_open(const char *,
    int, const fmd_conf_formal_t *, uint_t);
extern void fmd_conf_merge(fmd_conf_t *, const char *);
extern void fmd_conf_propagate(fmd_conf_t *, fmd_conf_t *, const char *);
extern void fmd_conf_close(fmd_conf_t *);

extern const char *fmd_conf_getnzstr(fmd_conf_t *, const char *);
extern const fmd_conf_ops_t *fmd_conf_gettype(fmd_conf_t *, const char *);
extern int fmd_conf_getprop(fmd_conf_t *, const char *, void *);
extern int fmd_conf_setprop(fmd_conf_t *, const char *, const char *);
extern int fmd_conf_delprop(fmd_conf_t *, const char *, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_CONF_H */
