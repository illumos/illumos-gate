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

#ifndef _ISNS_ADMINTF_H
#define	_ISNS_ADMINTF_H

#include	<libxml/tree.h>
#include	<libxml/parser.h>
#include	<isns_mgmt.h>

#ifdef __cplusplus
extern "C" {
#endif

int get_serverconfig_op(xmlDocPtr);
int get_node_op(request_t *, xmlDocPtr);
int get_dd_op(request_t *, xmlDocPtr);
int get_ddset_op(request_t *, xmlDocPtr);
int enumerate_node_op(xmlDocPtr);
int enumerate_dd_op(xmlDocPtr);
int enumerate_ddset_op(xmlDocPtr);
int getAssociated_dd_to_node_op(request_t *, xmlDocPtr);
int getAssociated_node_to_dd_op(request_t *, xmlDocPtr);
int getAssociated_dd_to_ddset_op(request_t *, xmlDocPtr);
int getAssociated_ddset_to_dd_op(request_t *, xmlDocPtr);
int delete_dd_ddset_op(request_t *, xmlDocPtr, object_type);
int delete_ddmember_ddsetmember_op(request_t *, xmlDocPtr, object_type);
int createModify_dd_ddset_op(request_t *, xmlDocPtr);
int create_ddmember_ddsetmember_op(request_t *, xmlDocPtr, object_type);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_ADMINTF_H */
