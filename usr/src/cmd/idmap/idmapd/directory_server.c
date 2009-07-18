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

/*
 * Server-side support for directory information lookup functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <malloc.h>
#include <sys/types.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <note.h>
#include "idmapd.h"
#include "directory.h"
#include "directory_private.h"
#include <rpcsvc/idmap_prot.h>
#include "directory_library_impl.h"
#include "directory_server_impl.h"
#include "sized_array.h"
#include "miscutils.h"

/*
 * Here's a list of all of the modules that provide directory
 * information.  In the fullness of time this should probably be
 * a plugin-able switch mechanism.
 * Note that the list is in precedence order.
 */
extern struct directory_provider_static directory_provider_builtin;
extern struct directory_provider_static directory_provider_nsswitch;
extern struct directory_provider_static directory_provider_ad;
struct directory_provider_static *providers[] = {
	&directory_provider_builtin,
	&directory_provider_nsswitch,
	&directory_provider_ad,
};

/*
 * This is the entry point for all directory lookup service requests.
 */
bool_t
directory_get_common_1_svc(
    idmap_utf8str_list ids,
    idmap_utf8str types,
    idmap_utf8str_list attrs,
    directory_results_rpc *result,
    struct svc_req *req)
{
	NOTE(ARGUNUSED(req))
	int nids;
	directory_entry_rpc *entries;
	directory_error_t de;
	int i;

	nids = ids.idmap_utf8str_list_len;

	entries = (directory_entry_rpc *)
	    calloc(nids, sizeof (directory_entry_rpc));
	if (entries == NULL)
		goto nomem;
	result->directory_results_rpc_u.entries.entries_val = entries;
	result->directory_results_rpc_u.entries.entries_len = nids;
	result->failed = FALSE;

	for (i = 0; i < nids; i++) {
		if (strlen(ids.idmap_utf8str_list_val[i]) >
		    IDMAP_MAX_NAME_LEN) {
			directory_entry_set_error(&entries[i],
			    directory_error("invalid_arg.id.too_long",
			    "Identifier too long", NULL));
		}
	}

	for (i = 0; i < NELEM(providers); i++) {
		de = providers[i]->get(entries, &ids, types,
		    &attrs);
		if (de != NULL)
			goto err;
	}

	return (TRUE);

nomem:
	de = directory_error("ENOMEM.get_common",
	    "Insufficient memory retrieving directory data", NULL);

err:
	xdr_free(xdr_directory_results_rpc, (char *)result);
	result->failed = TRUE;
	return (
	    directory_error_to_rpc(&result->directory_results_rpc_u.err, de));
}

/*
 * Split name into {domain, name}.
 * Suggest allocating name and domain on the stack, same size as id,
 * using variable length arrays.
 */
void
split_name(char *name, char *domain, char *id)
{
	char *p;

	if ((p = strchr(id, '@')) != NULL) {
		(void) strlcpy(name, id, p - id + 1);
		(void) strcpy(domain, p + 1);
	} else if ((p = strchr(id, '\\')) != NULL) {
		(void) strcpy(name, p + 1);
		(void) strlcpy(domain, id, p - id + 1);
	} else {
		(void) strcpy(name, id);
		(void) strcpy(domain, "");
	}
}

/*
 * Given a list of strings, return a set of directory attribute values.
 *
 * Mark that the attribute was found.
 *
 * Note that the terminating \0 is *not* included in the result, because
 * that's the way that strings come from LDAP.
 * (Note also that the client side stuff adds in a terminating \0.)
 *
 * Note that on error the array may have been partially populated and will
 * need to be cleaned up by the caller.  This is normally not a problem
 * because the caller will need to clean up several such arrays.
 */
directory_error_t
str_list_dav(directory_values_rpc *lvals, const char * const *str_list, int n)
{
	directory_value_rpc *dav;
	int i;

	if (n == 0) {
		for (n = 0; str_list[n] != NULL; n++)
			/* LOOP */;
	}

	dav = calloc(n, sizeof (directory_value_rpc));
	if (dav == NULL)
		goto nomem;

	lvals->directory_values_rpc_u.values.values_val = dav;
	lvals->directory_values_rpc_u.values.values_len = n;
	lvals->found = TRUE;

	for (i = 0; i < n; i++) {
		int len;

		len = strlen(str_list[i]);
		dav[i].directory_value_rpc_val = memdup(str_list[i], len);
		if (dav[i].directory_value_rpc_val == NULL)
			goto nomem;
		dav[i].directory_value_rpc_len = len;
	}

	return (NULL);

nomem:
	return (directory_error("ENOMEM.str_list_dav",
	    "Insufficient memory copying values"));
}

/*
 * Given a list of unsigned integers, return a set of string directory
 * attribute values.
 *
 * Mark that the attribute was found.
 *
 * Note that the terminating \0 is *not* included in the result, because
 * that's the way that strings come from LDAP.
 * (Note also that the client side stuff adds in a terminating \0.)
 *
 * Note that on error the array may have been partially populated and will
 * need to be cleaned up by the caller.  This is normally not a problem
 * because the caller will need to clean up several such arrays.
 */
directory_error_t
uint_list_dav(directory_values_rpc *lvals, const unsigned int *array, int n)
{
	directory_value_rpc *dav;
	int i;

	dav = calloc(n, sizeof (directory_value_rpc));
	if (dav == NULL)
		goto nomem;

	lvals->directory_values_rpc_u.values.values_val = dav;
	lvals->directory_values_rpc_u.values.values_len = n;
	lvals->found = TRUE;

	for (i = 0; i < n; i++) {
		char buf[100];	/* larger than any integer */
		int len;

		(void) snprintf(buf, sizeof (buf), "%u", array[i]);

		len = strlen(buf);
		dav[i].directory_value_rpc_val = memdup(buf, len);
		if (dav[i].directory_value_rpc_val == NULL)
			goto nomem;
		dav[i].directory_value_rpc_len = len;
	}

	return (NULL);

nomem:
	return (directory_error("ENOMEM.uint_list_dav",
	    "Insufficient memory copying values"));
}

/*
 * Given a list of fixed-length binary chunks, return a set of binary
 * directory attribute values.
 *
 * Mark that the attribute was found.
 *
 * Note that on error the array may have been partially populated and will
 * need to be cleaned up by the caller.  This is normally not a problem
 * because the caller will need to clean up several such arrays.
 */
directory_error_t
bin_list_dav(directory_values_rpc *lvals, const void *array, int n, size_t sz)
{
	directory_value_rpc *dav;
	char *inbuf = (char *)array;
	int i;

	dav = calloc(n, sizeof (directory_value_rpc));
	if (dav == NULL)
		goto nomem;

	lvals->directory_values_rpc_u.values.values_val = dav;
	lvals->directory_values_rpc_u.values.values_len = n;
	lvals->found = TRUE;

	for (i = 0; i < n; i++) {
		dav[i].directory_value_rpc_val = memdup(inbuf, sz);
		if (dav[i].directory_value_rpc_val == NULL)
			goto nomem;
		dav[i].directory_value_rpc_len = sz;
		inbuf += sz;
	}

	return (NULL);

nomem:
	return (directory_error("ENOMEM.bin_list_dav",
	    "Insufficient memory copying values"));
}

/*
 * Set up to return an error on a particular directory entry.
 * Note that the caller need not (and in fact must not) free
 * the directory_error_t; it will be freed when the directory entry
 * list is freed.
 */
void
directory_entry_set_error(directory_entry_rpc *ent, directory_error_t de)
{
	xdr_free(xdr_directory_entry_rpc, (char *)&ent);
	ent->status = DIRECTORY_ERROR;
	(void) directory_error_to_rpc(&ent->directory_entry_rpc_u.err, de);
}
