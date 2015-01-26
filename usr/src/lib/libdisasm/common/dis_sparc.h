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

/*
 * Copyright 2007 Jason King.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _DIS_SPARC_H
#define	_DIS_SPARC_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	DIS_DEBUG_NONE		0x00L
#define	DIS_DEBUG_COMPAT	0x01L
#define	DIS_DEBUG_SYN_ALL	0x02L
#define	DIS_DEBUG_PRTBIN	0x04L
#define	DIS_DEBUG_PRTFMT	0x08L

#define	DIS_DEBUG_ALL DIS_DEBUG_SYN_ALL|DIS_DEBUG_PRTBIN|DIS_DEBUG_PRTFMT

typedef struct dis_handle_sparc {
	char		*dhx_buf;
	size_t		dhx_buflen;
	int		dhx_debug;
} dis_handle_sparc_t;

/* different types of things we can have in inst_t */
#define	INST_NONE	0x00
#define	INST_DEF	0x01
#define	INST_TBL	0x02

struct inst;
struct overlay;

typedef struct inst inst_t;
typedef struct overlay overlay_t;

typedef int (*format_fcn)(dis_handle_t *, uint32_t, const inst_t *, int);

typedef struct table {
	const struct inst	*tbl_inp;
	const struct overlay	*tbl_ovp;
	format_fcn		tbl_fmt;
	uint32_t		tbl_field;
	uint32_t		tbl_len;
} table_t;

struct inst {
	int in_type;
	int in_arch;
	union {
		struct {
			const char	*in_name;
			uint32_t	in_flags;
		} in_def;
		const table_t *in_tbl;
	} in_data;
};

struct overlay {
	int	ov_idx;
	inst_t	ov_inst;
};

extern const table_t initial_table;

void prt_binary(uint32_t, int);
#ifdef	__cplusplus
}
#endif

#endif	/* _DIS_SPARC_H */
