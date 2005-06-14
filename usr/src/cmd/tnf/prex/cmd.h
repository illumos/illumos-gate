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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _CMD_H
#define	_CMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include <sys/types.h>
#include "queue.h"
#include "expr.h"
#include "set.h"
#include "fcn.h"

#include <tnf/tnfctl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Typedefs
 */

typedef enum cmd_kind {
	CMD_ENABLE,
	CMD_DISABLE,
	CMD_CONNECT,
	CMD_CLEAR,
	CMD_TRACE,
	CMD_UNTRACE
} cmd_kind_t;

typedef struct cmd {
	queue_node_t	qn;
	boolean_t	isnamed;
	boolean_t	isnew;
	union {
#ifdef LATEBINDSETS
		char		*setname_p;
#endif
		expr_t		*expr_p;
	} expr;
	char		*fcnname_p;
	cmd_kind_t	kind;
} cmd_t;

typedef
tnfctl_errcode_t (*cmd_traverse_func_t) (
					expr_t * expr_p,
					cmd_kind_t kind,
					fcn_t * fcn_p,
					boolean_t isnew,
					void *calldata_p);


/*
 * Declarations
 */

cmd_t *cmd_set(char *setname_p, cmd_kind_t kind, char *fcnname_p);
cmd_t *cmd_expr(expr_t * expr_p, cmd_kind_t kind, char *fcnname_p);
void cmd_list(void);
#if 0
void cmd_mark(void);
void cmd_delete(int cmdnum);
#endif
tnfctl_errcode_t cmd_traverse(cmd_traverse_func_t percmdfunc, void *calldata_p);
tnfctl_errcode_t cmd_callback(cmd_t *cmd, cmd_traverse_func_t percmdfunc,
	void *calldata_p);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_H */
