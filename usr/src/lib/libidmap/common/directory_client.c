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
 * Directory lookup functions.  These are shims that translate from the API
 * into the RPC protocol.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <malloc.h>
#include <sys/types.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include "directory.h"
#include "directory_private.h"
#include <rpcsvc/idmap_prot.h>
#include "directory_library_impl.h"
#include "sized_array.h"

static directory_error_t copy_directory_attribute_value(
    directory_attribute_value_t *dav,
    directory_values_rpc *dav_rpc);
static directory_error_t copy_directory_entry(directory_entry_t *ent,
    directory_entry_rpc *ent_rpc);
static void directory_results_free(directory_results_rpc *dr);
static directory_datum_t directory_datum(void *data, size_t len);
static void directory_datum_free(directory_datum_t d);

/*
 * This is the actual implementation of the opaque directory_t structure.
 */
struct directory {
	CLIENT	*client;
};

/*
 * Set up a directory search context.
 */
directory_error_t
directory_open(directory_t *ret)
{
	directory_t d;
	directory_error_t de;
	char host[] = "localhost";

	*ret = NULL;

	d = calloc(1, sizeof (*d));
	if (d == NULL)
		goto nomem;

	d->client = clnt_door_create(IDMAP_PROG, IDMAP_V1, 0);
	if (d->client == NULL) {
		de = directory_error("clnt_create.directory_open",
		    "Error: %1",
		    clnt_spcreateerror(host),
		    NULL);
		goto err;
	}

	*ret = d;
	return (NULL);

nomem:
	de = directory_error("ENOMEM.directory_open",
	    "Insufficient memory setting up directory access", NULL);
err:
	directory_close(d);
	return (de);
}

/*
 * Tear down a directory search context.
 *
 * Does nothing if d==NULL.
 */
void
directory_close(directory_t d)
{
	if (d == NULL)
		return;

	if (d->client != NULL)
		clnt_destroy(d->client);

	free(d);
}

/*
 * Given a list of identifiers, a list of their types, and a list of attributes,
 * return the information.
 */
directory_error_t
directory_get_v(
    directory_t d,
    directory_entry_list_t *ret,
    char **ids,
    int nids,
    char *types,
    char **attr_list)
{
	int nattrs;
	directory_entry_list_t del;
	directory_error_t de;
	directory_results_rpc dr;
	idmap_utf8str_list sl_ids;
	idmap_utf8str_list sl_attrs;
	directory_entry_rpc *users;
	int i;
	enum clnt_stat cs;

	*ret = NULL;
	del = NULL;

	if (nids == 0) {
		for (nids = 0; ids[nids] != NULL; nids++)
			/* LOOP */;
	}

	for (nattrs = 0; attr_list[nattrs] != NULL; nattrs++)
		/* LOOP */;

	sl_ids.idmap_utf8str_list_len = nids;
	sl_ids.idmap_utf8str_list_val = ids;
	sl_attrs.idmap_utf8str_list_len = nattrs;
	sl_attrs.idmap_utf8str_list_val = attr_list;

	(void) memset(&dr, 0, sizeof (dr));
	cs = directory_get_common_1(sl_ids, types, sl_attrs, &dr, d->client);
	if (cs != RPC_SUCCESS) {
		char errbuf[100];	/* well long enough for any integer */
		(void) sprintf(errbuf, "%d", cs);
		de = directory_error("RPC.Get_common",
		    "Get_common RPC (%1)%2", errbuf,
		    clnt_sperror(d->client, ""), NULL);
		goto err;
	}

	if (dr.failed) {
		de = directory_error_from_rpc(
		    &dr.directory_results_rpc_u.err);
		goto err;
	}

	assert(dr.directory_results_rpc_u.entries.entries_len == nids);

	users = dr.directory_results_rpc_u.entries.entries_val;

	del = sized_array(nids, sizeof (directory_entry_t));

	for (i = 0; i < nids; i++) {
		de = copy_directory_entry(&del[i], &users[i]);
		if (de != NULL)
			goto err;
	}

	directory_results_free(&dr);

	*ret = del;
	return (NULL);

err:
	directory_results_free(&dr);
	directory_free(del);
	return (de);
}

/*
 * Free the results from a directory_get_*() request.
 */
void
directory_free(directory_entry_list_t del)
{
	directory_entry_t *ent;
	directory_attribute_value_t dav;
	int i;
	int j;
	int k;

	if (del == NULL)
		return;

	/* For each directory entry returned */
	for (i = 0; i < sized_array_n(del); i++) {
		ent = &del[i];

		if (ent->attrs != NULL) {
			/* For each attribute */
			for (j = 0; j < sized_array_n(ent->attrs); j++) {
				dav = ent->attrs[j];
				if (dav != NULL) {
					for (k = 0; k < sized_array_n(dav); k++)
						directory_datum_free(dav[k]);

					sized_array_free(dav);
				}
			}
			sized_array_free(ent->attrs);
		}

		directory_error_free(ent->err);
	}

	sized_array_free(del);
}

/*
 * Create a directory datum.  Note that we allocate an extra byte and
 * zero it, so that strings get null-terminated.  Return NULL on error.
 */
static
directory_datum_t
directory_datum(void *data, size_t len)
{
	void *p;

	p = sized_array(len + 1, 1);
	if (p == NULL)
		return (NULL);
	(void) memcpy(p, data, len);
	*((char *)p + len) = '\0';
	return (p);
}

/*
 * Return the size of a directory_datum_t.  Note that this does not include
 * the terminating \0, so it represents the value as returned by LDAP.
 */
size_t
directory_datum_len(directory_datum_t d)
{
	/*
	 * Deduct the terminal \0, so that binary data gets the
	 * expected length.
	 */
	return (sized_array_n(d) - 1);
}

static
void
directory_datum_free(directory_datum_t d)
{
	sized_array_free(d);
}

/*
 * Unmarshall an RPC directory entry into an API directory entry.
 */
static
directory_error_t
copy_directory_entry(
    directory_entry_t *ent,
    directory_entry_rpc *ent_rpc)
{
	int nattrs;
	int i;
	directory_error_t de;

	/* If the entry wasn't found, leave the entry attrs and err NULL. */
	if (ent_rpc->status == DIRECTORY_NOT_FOUND)
		return (NULL);

	if (ent_rpc->status == DIRECTORY_ERROR) {
		ent->err = directory_error_from_rpc(
		    &ent_rpc->directory_entry_rpc_u.err);
		return (NULL);
	}

	nattrs = ent_rpc->directory_entry_rpc_u.attrs.attrs_len;

	ent->attrs = sized_array(nattrs, sizeof (directory_attribute_value_t));
	if (ent->attrs == NULL) {
		return (directory_error("ENOMEM.copy_directory_entry",
		    "Insufficient memory copying directory entry", NULL));
	}
	for (i = 0; i < nattrs; i++) {
		de = copy_directory_attribute_value(&ent->attrs[i],
		    &ent_rpc->directory_entry_rpc_u.attrs.attrs_val[i]);
		if (de != NULL)
			return (de);
	}

	return (NULL);
}

/*
 * Unmarshall an RPC directory attribute value into the API equivalent.
 *
 * Note that on error some entries may have been copied, and so
 * the caller needs to clean up dav.  This is normally not a problem
 * since the caller will have called this function several times and
 * will need to clean up the results from the other calls too.
 */
static
directory_error_t
copy_directory_attribute_value(
    directory_attribute_value_t *dav,
    directory_values_rpc *dav_rpc)
{
	int i;
	int nvals;
	directory_value_rpc *vals;

	/* If it wasn't found, leave the corresponding entry NULL */
	if (!dav_rpc->found)
		return (NULL);

	nvals = dav_rpc->directory_values_rpc_u.values.values_len;
	*dav = sized_array(nvals + 1, sizeof (directory_datum_t));
	if (*dav == NULL) {
		return (directory_error("ENOMEM.copy_directory_attribute_value",
		    "Insufficient memory copying directory entry", NULL));
	}

	vals = dav_rpc->directory_values_rpc_u.values.values_val;
	for (i = 0; i < nvals; i++) {
		(*dav)[i] = directory_datum(vals[i].directory_value_rpc_val,
		    vals[i].directory_value_rpc_len);
		if ((*dav)[i] == NULL) {
			return (directory_error(
			    "ENOMEM.copy_directory_attribute_value",
			    "Insufficient memory copying directory entry",
			    NULL));
		}
	}

	return (NULL);
}

/*
 * Free the results of a directory RPC request.
 */
static
void
directory_results_free(directory_results_rpc *dr)
{
	xdr_free(xdr_directory_results_rpc, (char *)&dr);
}
