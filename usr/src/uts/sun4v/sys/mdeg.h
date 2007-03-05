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

#ifndef _MDEG_H
#define	_MDEG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MD Event Generator (mdeg) interface.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/mdesc.h>

/*
 * Specification of a node property.
 */
typedef struct {
	uint8_t		type;
	char		*namep;
	union {
		char		*strp;
		uint64_t	val;
	} _p;

} mdeg_prop_spec_t;

#define	ps_str	_p.strp
#define	ps_val	_p.val

/*
 * Specification of unique node in the MD. The array
 * of property name value pairs is used to determine
 * whether the node matches the specification.
 */
typedef struct {
	char			*namep;
	mdeg_prop_spec_t	*specp;
} mdeg_node_spec_t;

/*
 * Specification of a method to match nodes. The
 * array of properties are used to match two nodes
 * from different MDs. If the specified properties
 * match, the nodes are the same.
 */
typedef struct {
	char		*namep;
	md_prop_match_t	*matchp;
} mdeg_node_match_t;

/*
 * The result of the MD update as communicated
 * through the parameter to the registered callback.
 */
typedef struct {
	md_t		*mdp;
	mde_cookie_t	*mdep;
	int		nelem;
} mdeg_diff_t;

/*
 * Results of the MD update for a specific registration
 */
typedef struct {
	mdeg_diff_t	added;
	mdeg_diff_t	removed;
	mdeg_diff_t	match_curr;
	mdeg_diff_t	match_prev;
} mdeg_result_t;

/*
 * Client Interface
 */

#define	MDEG_SUCCESS	0
#define	MDEG_FAILURE	1

typedef uint64_t mdeg_handle_t;

typedef int (*mdeg_cb_t)(void *cb_argp, mdeg_result_t *resp);

int mdeg_register(mdeg_node_spec_t *pspecp, mdeg_node_match_t *nmatchp,
    mdeg_cb_t cb, void *cb_argp, mdeg_handle_t *hdlp);

int mdeg_unregister(mdeg_handle_t hdl);


#ifdef __cplusplus
}
#endif

#endif /* _MDEG_H */
