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

#ifndef _ISNS_DSAPI_H
#define	_ISNS_DSAPI_H

#include <isns_server.h>

#ifdef __cplusplus
extern "C" {
#endif

int target_init_data();
int target_load_obj(void **, isns_obj_t **, uchar_t *);
int target_add_obj(const isns_obj_t *);
int target_modify_obj(const isns_obj_t *);
int target_delete_obj(const isns_obj_t *);
int target_delete_assoc(const isns_obj_t *);
int target_update_commit();
int target_update_retreat();

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_DSAPI_H */
