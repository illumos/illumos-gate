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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DIRECTORY_LIBRARY_IMPL_H
#define	_DIRECTORY_LIBRARY_IMPL_H

/*
 * Internal implementation of the client side of directory lookup.
 */

#ifdef __cplusplus
extern "C" {
#endif

directory_error_t directory_error_from_rpc(directory_error_rpc *de_rpc);
bool_t directory_error_to_rpc(directory_error_rpc *de_rpc,
    directory_error_t de);


directory_error_t directory_get_v(directory_t d, directory_entry_list_t *ret,
    char **ids, int nids, char *types, char **attr_list);

#ifdef __cplusplus
}
#endif

#endif /* _DIRECTORY_LIBRARY_IMPL_H */
