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
 * Retrieve directory information for standard UNIX users/groups.
 * (NB:  not just from files, but all nsswitch sources.)
 */

#include <pwd.h>
#include <grp.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <note.h>
#include <errno.h>
#include "idmapd.h"
#include "directory.h"
#include "directory_private.h"
#include <rpcsvc/idmap_prot.h>
#include "directory_server_impl.h"
#include "miscutils.h"
#include "sidutil.h"

static directory_error_t machine_sid_dav(directory_values_rpc *lvals,
    unsigned int rid);
static directory_error_t directory_provider_nsswitch_populate(
    directory_entry_rpc *pent, struct passwd *pwd, struct group *grp,
    idmap_utf8str_list *attrs);

/*
 * Retrieve information by name.
 * Called indirectly through the directory_provider_static structure.
 */
static
directory_error_t
directory_provider_nsswitch_get(
    directory_entry_rpc *del,
    idmap_utf8str_list *ids,
    idmap_utf8str types,
    idmap_utf8str_list *attrs)
{
	int i;

	RDLOCK_CONFIG();

	/* 6835280 spurious lint error if the strlen is in the declaration */
	int host_name_len = strlen(_idmapdstate.hostname);
	char my_host_name[host_name_len + 1];
	(void) strcpy(my_host_name, _idmapdstate.hostname);

	/* We use len later, so this is not merely a workaround for 6835280 */
	int machine_sid_len = strlen(_idmapdstate.cfg->pgcfg.machine_sid);
	char my_machine_sid[machine_sid_len + 1];
	(void) strcpy(my_machine_sid, _idmapdstate.cfg->pgcfg.machine_sid);

	UNLOCK_CONFIG();

	for (i = 0; i < ids->idmap_utf8str_list_len; i++) {
		struct passwd *pwd = NULL;
		struct group *grp = NULL;
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

		if (type == DIRECTORY_ID_SID[0]) {
			/*
			 * Is it our SID?
			 * Check whether the first part matches, then a "-",
			 * then a single RID.
			 */
			if (strncasecmp(id, my_machine_sid, machine_sid_len) !=
			    0)
				continue;
			if (id[machine_sid_len] != '-')
				continue;
			char *p;
			uint32_t rid =
			    strtoul(id + machine_sid_len + 1, &p, 10);
			if (*p != '\0')
				continue;

			if (rid < LOCALRID_UID_MIN) {
				/* Builtin, not handled here */
				continue;
			}

			if (rid <= LOCALRID_UID_MAX) {
				/* User */
				errno = 0;
				pwd = getpwuid(rid - LOCALRID_UID_MIN);
				if (pwd == NULL) {
					if (errno == 0)		/* Not found */
						continue;
					char buf[40];
					int err = errno;
					(void) snprintf(buf, sizeof (buf),
					    "%d", err);
					directory_entry_set_error(&del[i],
					    directory_error("errno.getpwuid",
					    "getpwuid: %2 (%1)",
					    buf, strerror(err), NULL));
					continue;
				}
			} else if (rid >= LOCALRID_GID_MIN &&
			    rid <= LOCALRID_GID_MAX) {
				/* Group */
				errno = 0;
				grp = getgrgid(rid - LOCALRID_GID_MIN);
				if (grp == NULL) {
					if (errno == 0)		/* Not found */
						continue;
					char buf[40];
					int err = errno;
					(void) snprintf(buf, sizeof (buf),
					    "%d", err);
					directory_entry_set_error(&del[i],
					    directory_error("errno.getgrgid",
					    "getgrgid: %2 (%1)",
					    buf, strerror(err), NULL));
					continue;
				}
			} else
				continue;

		} else {
			int id_len = strlen(id);
			char name[id_len + 1];
			char domain[id_len + 1];

			split_name(name, domain, id);

			if (domain[0] != '\0') {
				if (!domain_eq(domain, my_host_name))
					continue;
			}

			/*
			 * If the caller has requested user or group
			 * information specifically, we only set one of
			 * pwd or grp.
			 * If the caller has requested either type, we try
			 * both in the hopes of getting one.
			 * Note that directory_provider_nsswitch_populate
			 * considers it to be an error if both are set.
			 */
			if (type != DIRECTORY_ID_GROUP[0]) {
				/* prep for not found / error case */
				errno = 0;

				pwd = getpwnam(name);
				if (pwd == NULL && errno != 0) {
					char buf[40];
					int err = errno;
					(void) snprintf(buf, sizeof (buf),
					    "%d", err);
					directory_entry_set_error(&del[i],
					    directory_error("errno.getpwnam",
					    "getpwnam: %2 (%1)",
					    buf, strerror(err), NULL));
					continue;
				}
			}

			if (type != DIRECTORY_ID_USER[0]) {
				/* prep for not found / error case */
				errno = 0;

				grp = getgrnam(name);
				if (grp == NULL && errno != 0) {
					char buf[40];
					int err = errno;
					(void) snprintf(buf, sizeof (buf),
					    "%d", err);
					directory_entry_set_error(&del[i],
					    directory_error("errno.getgrnam",
					    "getgrnam: %2 (%1)",
					    buf, strerror(err), NULL));
					continue;
				}
			}
		}

		/*
		 * Didn't find it, don't populate the structure.
		 * Another provider might populate it.
		 */
		if (pwd == NULL && grp == NULL)
			continue;

		de = directory_provider_nsswitch_populate(&del[i], pwd, grp,
		    attrs);
		if (de != NULL) {
			directory_entry_set_error(&del[i], de);
			de = NULL;
			continue;
		}
	}

	return (NULL);
}

/*
 * Given a pwd structure or a grp structure, and a list of attributes that
 * were requested, populate the structure to return to the caller.
 */
static
directory_error_t
directory_provider_nsswitch_populate(
    directory_entry_rpc *pent,
    struct passwd *pwd,
    struct group *grp,
    idmap_utf8str_list *attrs)
{
	int j;
	directory_values_rpc *llvals;
	int nattrs;

	/*
	 * If it wasn't for this case, everything would be a lot simpler.
	 * UNIX allows users and groups with the same name.  Windows doesn't.
	 */
	if (pwd != NULL && grp != NULL) {
		return directory_error("Ambiguous.Name",
		    "Ambiguous name, is both a user and a group",
		    NULL);
	}

	nattrs = attrs->idmap_utf8str_list_len;

	llvals = calloc(nattrs, sizeof (directory_values_rpc));
	if (llvals == NULL)
		goto nomem;

	pent->directory_entry_rpc_u.attrs.attrs_val = llvals;
	pent->directory_entry_rpc_u.attrs.attrs_len = nattrs;
	pent->status = DIRECTORY_FOUND;

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
		 * the information
		 */
		val->found = FALSE;
		de = NULL;

		if (pwd != NULL) {
			/*
			 * Handle attributes for user entries.
			 */
			if (strcaseeq(a, "cn")) {
				const char *p = pwd->pw_name;
				de = str_list_dav(val, &p, 1);
			} else if (strcaseeq(a, "objectClass")) {
				static const char *objectClasses[] = {
					"top",
					"posixAccount",
				};
				de = str_list_dav(val, objectClasses,
				    NELEM(objectClasses));
			} else if (strcaseeq(a, "gidNumber")) {
				de = uint_list_dav(val, &pwd->pw_gid, 1);
			} else if (strcaseeq(a, "objectSid")) {
				de = machine_sid_dav(val,
				    pwd->pw_uid + LOCALRID_UID_MIN);
			} else if (strcaseeq(a, "displayName")) {
				const char *p = pwd->pw_gecos;
				de = str_list_dav(val, &p, 1);
			} else if (strcaseeq(a, "distinguishedName")) {
				char *dn;
				RDLOCK_CONFIG();
				(void) asprintf(&dn,
				    "uid=%s,ou=people,dc=%s",
				    pwd->pw_name, _idmapdstate.hostname);
				UNLOCK_CONFIG();
				if (dn == NULL)
					goto nomem;
				const char *cdn = dn;
				de = str_list_dav(val, &cdn, 1);
				free(dn);
			} else if (strcaseeq(a, "uid")) {
				const char *p = pwd->pw_name;
				de = str_list_dav(val, &p, 1);
			} else if (strcaseeq(a, "uidNumber")) {
				de = uint_list_dav(val, &pwd->pw_uid, 1);
			} else if (strcaseeq(a, "gecos")) {
				const char *p = pwd->pw_gecos;
				de = str_list_dav(val, &p, 1);
			} else if (strcaseeq(a, "homeDirectory")) {
				const char *p = pwd->pw_dir;
				de = str_list_dav(val, &p, 1);
			} else if (strcaseeq(a, "loginShell")) {
				const char *p = pwd->pw_shell;
				de = str_list_dav(val, &p, 1);
			} else if (strcaseeq(a, "x-sun-canonicalName")) {
				char *canon;
				RDLOCK_CONFIG();
				(void) asprintf(&canon, "%s@%s",
				    pwd->pw_name, _idmapdstate.hostname);
				UNLOCK_CONFIG();
				if (canon == NULL)
					goto nomem;
				const char *ccanon = canon;
				de = str_list_dav(val, &ccanon, 1);
				free(canon);
			} else if (strcaseeq(a, "x-sun-provider")) {
				const char *provider = "UNIX-passwd";
				de = str_list_dav(val, &provider, 1);
			}
		} else if (grp != NULL)  {
			/*
			 * Handle attributes for group entries.
			 */
			if (strcaseeq(a, "cn")) {
				const char *p = grp->gr_name;
				de = str_list_dav(val, &p, 1);
			} else if (strcaseeq(a, "objectClass")) {
				static const char *objectClasses[] = {
					"top",
					"posixGroup",
				};
				de = str_list_dav(val, objectClasses,
				    NELEM(objectClasses));
			} else if (strcaseeq(a, "gidNumber")) {
				de = uint_list_dav(val, &grp->gr_gid, 1);
			} else if (strcaseeq(a, "objectSid")) {
				de = machine_sid_dav(val,
				    grp->gr_gid + LOCALRID_GID_MIN);
			} else if (strcaseeq(a, "displayName")) {
				const char *p = grp->gr_name;
				de = str_list_dav(val, &p, 1);
			} else if (strcaseeq(a, "distinguishedName")) {
				char *dn;
				RDLOCK_CONFIG();
				(void) asprintf(&dn,
				    "cn=%s,ou=group,dc=%s",
				    grp->gr_name, _idmapdstate.hostname);
				UNLOCK_CONFIG();
				if (dn == NULL)
					goto nomem;
				const char *cdn = dn;
				de = str_list_dav(val, &cdn, 1);
				free(dn);
			} else if (strcaseeq(a, "memberUid")) {
				/*
				 * NEEDSWORK:  There is probably a non-cast
				 * way to do this, but I don't immediately
				 * see it.
				 */
				const char * const *members =
				    (const char * const *)grp->gr_mem;
				de = str_list_dav(val, members, 0);
			} else if (strcaseeq(a, "x-sun-canonicalName")) {
				char *canon;
				RDLOCK_CONFIG();
				(void) asprintf(&canon, "%s@%s",
				    grp->gr_name, _idmapdstate.hostname);
				UNLOCK_CONFIG();
				if (canon == NULL)
					goto nomem;
				const char *ccanon = canon;
				de = str_list_dav(val, &ccanon, 1);
				free(canon);
			} else if (strcaseeq(a, "x-sun-provider")) {
				const char *provider = "UNIX-group";
				de = str_list_dav(val, &provider, 1);
			}
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
 * Populate a directory attribute value with a SID based on our machine SID
 * and the specified RID.
 *
 * It's a bit perverse that we must take a text-format SID and turn it into
 * a binary-format SID, only to have the caller probably turn it back into
 * text format, but SIDs are carried across LDAP in binary format.
 */
static
directory_error_t
machine_sid_dav(directory_values_rpc *lvals, unsigned int rid)
{
	sid_t *sid;
	directory_error_t de;

	RDLOCK_CONFIG();
	int len = strlen(_idmapdstate.cfg->pgcfg.machine_sid);
	char buf[len + 100];	/* 100 is enough space for any RID */
	(void) snprintf(buf, sizeof (buf), "%s-%u",
	    _idmapdstate.cfg->pgcfg.machine_sid, rid);
	UNLOCK_CONFIG();

	sid = sid_fromstr(buf);
	if (sid == NULL)
		goto nomem;

	sid_to_le(sid);

	de = bin_list_dav(lvals, sid, 1, sid_len(sid));
	sid_free(sid);
	return (de);

nomem:
	return (directory_error("ENOMEM.machine_sid_dav",
	    "Out of memory allocating return value for lookup", NULL));
}

struct directory_provider_static directory_provider_nsswitch = {
	"files",
	directory_provider_nsswitch_get,
};
