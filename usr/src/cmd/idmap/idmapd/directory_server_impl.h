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

#ifndef _DIRECTORY_SERVER_IMPL_H
#define	_DIRECTORY_SERVER_IMPL_H

/*
 * Internal implementation details for the server side of directory lookup.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Functions to populate Directory Attribute Value lists.
 */
directory_error_t str_list_dav(directory_values_rpc *lvals,
    const char * const *str_list, int n);
directory_error_t uint_list_dav(directory_values_rpc *lvals,
    const unsigned int *uint_list, int n);
directory_error_t bin_list_dav(directory_values_rpc *lvals,
    const void *array, int n, size_t sz);

/*
 * Split a name@domain into name, domain.  Recommend allocating the
 * destination buffers the same size as the input, on the stack,
 * using variable length arrays.
 */
void split_name(char *name, char *domain, char *id);

/*
 * Insert a directory_error_t into a directory entry to be returned.
 * Caller MUST NOT free the directory_error_t.
 */
void directory_entry_set_error(directory_entry_rpc *ent,
    directory_error_t de);

/*
 * This is the structure by which a provider supplies its entry points.
 * The name is not currently used.
 */
struct directory_provider_static {
	char *name;
	directory_error_t (*get)(
	    directory_entry_rpc *ret,
	    idmap_utf8str_list *ids,
	    idmap_utf8str types,
	    idmap_utf8str_list *attrs);
};

#ifdef __cplusplus
}
#endif

#endif /* _DIRECTORY_SERVER_IMPL_H */
