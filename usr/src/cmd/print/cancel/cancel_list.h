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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_CANCEL_LIST_H
#define	_CANCEL_LIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _cancel_req cancel_req_t;
struct _cancel_req {
	char *printer;
	ns_bsd_addr_t *binding;
	char **list;
};

extern cancel_req_t ** cancel_list_add_item(cancel_req_t **list, char *printer,
		char *item);
extern cancel_req_t ** cancel_list_add_list(cancel_req_t **list, char *printer,
		char **items);
extern cancel_req_t ** cancel_list_add_binding_list(cancel_req_t **list,
		ns_bsd_addr_t *binding, char **items);

#ifdef __cplusplus
}
#endif

#endif /* _CANCEL_LIST_H */
