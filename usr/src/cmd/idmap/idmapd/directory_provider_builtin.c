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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Retrieve directory information for built-in users and groups
 */

#include <stdio.h>
#include <limits.h>
#include <sys/idmap.h>
#include <sys/param.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <note.h>
#include "idmapd.h"
#include "directory.h"
#include "directory_private.h"
#include <rpcsvc/idmap_prot.h>
#include "directory_server_impl.h"
#include "miscutils.h"
#include "sidutil.h"

static directory_error_t sid_dav(directory_values_rpc *lvals,
    const wksids_table_t *wksid);
static directory_error_t directory_provider_builtin_populate(
    directory_entry_rpc *pent, const wksids_table_t *wksid,
    idmap_utf8str_list *attrs);

/*
 * Retrieve information by name.
 * Called indirectly through the directory_provider_static structure.
 */
static
directory_error_t
directory_provider_builtin_get(
    directory_entry_rpc *del,
    idmap_utf8str_list *ids,
    idmap_utf8str types,
    idmap_utf8str_list *attrs)
{
	int i;

	for (i = 0; i < ids->idmap_utf8str_list_len; i++) {
		const wksids_table_t *wksid;
		directory_error_t de;
		int type;

		/*
		 * Extract the type for this particular ID.
		 * Advance to the next type, if it's there, else keep
		 * using this type until we run out of IDs.
		 */
		type = *types;
		if (*(types+1) != '\0')
			types++;

		/*
		 * If this entry has already been handled, one way or another,
		 * skip it.
		 */
		if (del[i].status != DIRECTORY_NOT_FOUND)
			continue;

		char *id = ids->idmap_utf8str_list_val[i];

		/*
		 * End-to-end error injection point.
		 * NEEDSWORK:  should probably eliminate this for production
		 */
		if (streq(id, " DEBUG BUILTIN ERROR ")) {
			directory_entry_set_error(&del[i],
			    directory_error("Directory_provider_builtin.debug",
			    "Directory_provider_builtin:  artificial error",
			    NULL));
			continue;
		}

		if (type == DIRECTORY_ID_SID[0])
			wksid = find_wk_by_sid(id);
		else {
			int idmap_id_type;
			if (type == DIRECTORY_ID_NAME[0])
				idmap_id_type = IDMAP_POSIXID;
			else if (type == DIRECTORY_ID_USER[0])
				idmap_id_type = IDMAP_UID;
			else if (type == DIRECTORY_ID_GROUP[0])
				idmap_id_type = IDMAP_GID;
			else {
				directory_entry_set_error(&del[i],
				    directory_error("invalid_arg.id_type",
				    "Invalid ID type \"%1\"",
				    types, NULL));
				continue;
			}

			int id_len = strlen(id);
			char name[id_len + 1];
			char domain[id_len + 1];

			split_name(name, domain, id);

			wksid = find_wksid_by_name(name, domain, idmap_id_type);
		}

		if (wksid == NULL)
			continue;

		de = directory_provider_builtin_populate(&del[i], wksid, attrs);
		if (de != NULL) {
			directory_entry_set_error(&del[i], de);
			de = NULL;
		}
	}

	return (NULL);
}

/*
 * Given a well-known name entry and a list of attributes that were
 * requested, populate the structure to return to the caller.
 */
static
directory_error_t
directory_provider_builtin_populate(
    directory_entry_rpc *pent,
    const wksids_table_t *wksid,
    idmap_utf8str_list *attrs)
{
	int j;
	directory_values_rpc *llvals;
	int nattrs;

	nattrs = attrs->idmap_utf8str_list_len;

	llvals = calloc(nattrs, sizeof (directory_values_rpc));
	if (llvals == NULL)
		goto nomem;

	pent->status = DIRECTORY_FOUND;
	pent->directory_entry_rpc_u.attrs.attrs_val = llvals;
	pent->directory_entry_rpc_u.attrs.attrs_len = nattrs;

	for (j = 0; j < nattrs; j++) {
		directory_values_rpc *val;
		char *a;
		directory_error_t de;

		/*
		 * We're going to refer to these a lot, so make a shorthand
		 * copy.
		 */
		a = attrs->idmap_utf8str_list_val[j];
		val = &llvals[j];

		/*
		 * Start by assuming no errors and that we don't have
		 * the information.
		 */
		val->found = FALSE;
		de = NULL;

		if (strcaseeq(a, "uid")) {
			de = str_list_dav(val, &wksid->winname, 1);
		} else if (strcaseeq(a, "uidNumber")) {
			if (wksid->pid != IDMAP_SENTINEL_PID &&
			    wksid->is_user) {
				de = uint_list_dav(val, &wksid->pid, 1);
			}
		} else if (strcaseeq(a, "gidNumber")) {
			if (wksid->pid != IDMAP_SENTINEL_PID &&
			    !wksid->is_user) {
				de = uint_list_dav(val, &wksid->pid, 1);
			}
		} else if (strcaseeq(a, "displayName") || strcaseeq(a, "cn")) {
			de = str_list_dav(val, &wksid->winname, 1);
		} else if (strcaseeq(a, "distinguishedName")) {
			char *container;
			if (wksid->domain == NULL) {
				container = "Users";
			} else {
				container = "Builtin";
			}
			RDLOCK_CONFIG();
			char *dn;
			(void) asprintf(&dn,
			    "CN=%s,CN=%s,DC=%s",
			    wksid->winname, container, _idmapdstate.hostname);
			UNLOCK_CONFIG();
			const char *cdn = dn;
			de = str_list_dav(val, &cdn, 1);
			free(dn);
		} else if (strcaseeq(a, "objectClass")) {
			if (wksid->is_wuser) {
				static const char *objectClasses[] = {
					"top",
					"person",
					"organizationalPerson",
					"user",
				};
				de = str_list_dav(val, objectClasses,
				    NELEM(objectClasses));
			} else {
				static const char *objectClasses[] = {
					"top",
					"group",
				};
				de = str_list_dav(val, objectClasses,
				    NELEM(objectClasses));
			}
		} else if (strcaseeq(a, "objectSid")) {
			de = sid_dav(val, wksid);
		} else if (strcaseeq(a, "x-sun-canonicalName")) {
			char *canon;

			if (wksid->domain == NULL) {
				RDLOCK_CONFIG();
				(void) asprintf(&canon, "%s@%s",
				    wksid->winname, _idmapdstate.hostname);
				UNLOCK_CONFIG();
			} else if (streq(wksid->domain, "")) {
				canon = strdup(wksid->winname);
			} else {
				(void) asprintf(&canon, "%s@%s",
				    wksid->winname, wksid->domain);
			}

			if (canon == NULL)
				goto nomem;
			const char *ccanon = canon;
			de = str_list_dav(val, &ccanon, 1);
			free(canon);
		} else if (strcaseeq(a, "x-sun-provider")) {
			const char *provider = "Builtin";
			de = str_list_dav(val, &provider, 1);
		}
		if (de != NULL)
			return (de);
	}

	return (NULL);

nomem:
	return (directory_error("ENOMEM.users",
	    "No memory allocating return value for user lookup", NULL));
}

/*
 * Given a well-known name structure, generate a binary-format SID.
 * It's a bit perverse that we must take a text-format SID and turn it into
 * a binary-format SID, only to have the caller probably turn it back into
 * text format, but SIDs are carried across LDAP in binary format.
 */
static
directory_error_t
sid_dav(directory_values_rpc *lvals, const wksids_table_t *wksid)
{
	char *text_sid;
	sid_t *sid;
	directory_error_t de;

	if (wksid->sidprefix == NULL) {
		RDLOCK_CONFIG();
		(void) asprintf(&text_sid, "%s-%d",
		    _idmapdstate.cfg->pgcfg.machine_sid,
		    wksid->rid);
		UNLOCK_CONFIG();
	} else {
		(void) asprintf(&text_sid, "%s-%d",
		    wksid->sidprefix, wksid->rid);
	}

	if (text_sid == NULL)
		goto nomem;

	sid = sid_fromstr(text_sid);
	free(text_sid);

	if (sid == NULL)
		goto nomem;

	sid_to_le(sid);

	de = bin_list_dav(lvals, sid, 1, sid_len(sid));

	sid_free(sid);

	return (de);

nomem:
	return (directory_error("ENOMEM.sid_dav",
	    "No memory allocating SID for user lookup", NULL));
}

struct directory_provider_static directory_provider_builtin = {
	"builtin",
	directory_provider_builtin_get,
};
