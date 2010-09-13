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

#ifndef _ISNS_CFG_H
#define	_ISNS_CFG_H

#ifdef __cplusplus
extern "C" {
#endif

/* the list of the administratively configured control nodes */
typedef struct ctrl_node {
	uchar_t *name;
	struct ctrl_node *next;
} ctrl_node_t;

/* function prototype */
int
load_config(
	boolean_t
);

int is_control_node(uchar_t *);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_CFG_H */
