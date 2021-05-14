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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2021 Jason King
 */

#ifndef _RUST_H
#define	_RUST_H

#include <errno.h>
#include <sys/types.h>
#include "demangle-sys.h"
#include "demangle_int.h"
#include "strview.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum rustenc_version {
	RUSTENC_LEGACY = -1,
	RUSTENC_V0 = 0
} rustenc_version_t;

typedef struct rust_state {
	const char	*rs_str; /* The original string */
	custr_t		*rs_demangled;
	sysdem_ops_t	*rs_ops;
	custr_alloc_t	rs_cualloc;
	strview_t	rs_orig; /* strview of original string, sans prefix */
	int		rs_error;
	rustenc_version_t rs_encver;
	uint64_t	rs_lt_depth;
	boolean_t	rs_skip;
	boolean_t	rs_args_stay_open;
	boolean_t	rs_args_is_open;
	boolean_t	rs_verbose;
	boolean_t	rs_show_const_type;
	boolean_t	rs_isutf8;
} rust_state_t;
#define	HAS_ERROR(_st) ((_st)->rs_error != 0)
#define	SET_ERROR(_st) ((_st)->rs_error = errno)

/*
 * In certain circumstances, we need to parse an item, but not emit any
 * output. These macros assist in that. To use:
 *
 * rust_state_t *st;
 * boolean_t saved_state;
 * ...
 * SKIP_BEGIN(st, saved_state);
 * ... stuff to no emit
 * SKIP_END(st, saved_state);
 */
#define	SKIP_BEGIN(_st, _save)		\
	(_save) = (_st)->rs_skip,	\
	(_st)->rs_skip = B_TRUE
#define	SKIP_END(_st, _n) (_st)->rs_skip = (_n)

boolean_t rust_appendc(rust_state_t *, char);
boolean_t rust_append(rust_state_t *, const char *);
boolean_t rust_append_printf(rust_state_t *, const char *, ...) __PRINTFLIKE(2);
boolean_t rust_append_sv(rust_state_t *restrict, uint64_t, strview_t *restrict);
boolean_t rust_append_utf8_c(rust_state_t *, uint32_t);
boolean_t rust_parse_base10(rust_state_t *restrict, strview_t *restrict,
    uint64_t *restrict);
boolean_t rust_demangle_legacy(rust_state_t *restrict, strview_t *restrict);
boolean_t rust_demangle_v0(rust_state_t *restrict, strview_t *restrict);

boolean_t rustv0_puny_decode(rust_state_t *restrict, strview_t *restrict,
    boolean_t);

#ifdef __cplusplus
}
#endif

#endif /* _RUST_H */
