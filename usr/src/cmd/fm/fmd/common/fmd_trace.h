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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FMD_TRACE_H
#define	_FMD_TRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdarg.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct fmd_tracerec {
	hrtime_t tr_time;	/* high-resolution timestamp */
	const char *tr_file;	/* source file name */
	uint32_t tr_line;	/* source file line */
	uint16_t tr_errno;	/* errno value if error */
	uint8_t tr_tag;		/* tag (see <fmd_subr.h>) */
	uint8_t tr_depth;	/* depth of tr_stack[] */
	char tr_msg[64];	/* formatted message */
	uintptr_t tr_stack[1];	/* stack trace (optional) */
} fmd_tracerec_t;

typedef struct fmd_tracebuf {
	fmd_tracerec_t *tb_buf;	/* pointer to first trace record */
	fmd_tracerec_t *tb_end;	/* pointer to last trace record */
	fmd_tracerec_t *tb_ptr;	/* next trace record to use */
	uint_t tb_frames;	/* maximum captured frames */
	uint_t tb_recs;		/* number of trace records */
	uint_t tb_size;		/* size of each record */
	uint_t tb_depth;	/* recursion depth of trace function */
} fmd_tracebuf_t;

typedef fmd_tracerec_t *fmd_tracebuf_f(fmd_tracebuf_t *,
    uint_t, const char *, va_list);

extern fmd_tracebuf_t *fmd_trace_create(void);
extern void fmd_trace_destroy(fmd_tracebuf_t *);

extern fmd_tracebuf_f fmd_trace_none;
extern fmd_tracebuf_f fmd_trace_lite;
extern fmd_tracebuf_f fmd_trace_full;

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_TRACE_H */
