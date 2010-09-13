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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_POOLCFG_H
#define	_POOLCFG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	po_create,
	po_remove
} prop_op_t;

typedef union {
	uint64_t	u;
	int64_t		i;
	double		d;
	uchar_t		b;
	const char	*s;
} pv_u;

typedef struct prop {
	const char *prop_name;
	pool_value_t *prop_value;
	prop_op_t prop_op;
	struct prop *prop_next;
} prop_t;

typedef struct assoc {
	int assoc_type;
	const char *assoc_name;
	struct assoc *assoc_next;
} assoc_t;

typedef struct cmd {
	void (*cmd)(struct cmd *);
	const char *cmd_tgt1;
	const char *cmd_tgt2;
	uint64_t cmd_qty;
	prop_t *cmd_prop_list;
	assoc_t *cmd_assoc_list;
} cmd_t;

typedef void (*cmdfunc)(cmd_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _POOLCFG_H */
