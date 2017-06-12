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
 *
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#include <grp.h>
#include "ldap_common.h"
#include <string.h>

/* String which may need to be removed from beginning of group password */
#define	_CRYPT		"{CRYPT}"
#define	_NO_PASSWD_VAL	""

/* Group attributes filters */
#define	_G_NAME		"cn"
#define	_G_GID		"gidnumber"
#define	_G_PASSWD	"userpassword"
#define	_G_MEM		"memberuid"

#define	_F_GETGRNAM	"(&(objectClass=posixGroup)(cn=%s))"
#define	_F_GETGRNAM_SSD	"(&(%%s)(cn=%s))"
#define	_F_GETGRGID	"(&(objectClass=posixGroup)(gidNumber=%u))"
#define	_F_GETGRGID_SSD	"(&(%%s)(gidNumber=%u))"
/*
 * Group membership can be defined by either username or DN, so when searching
 * for groups by member we need to consider both. The first parameter in the
 * filter is replaced by username, the second by DN.
 */
#define	_F_GETGRMEM \
	"(&(objectClass=posixGroup)(|(memberUid=%s)(memberUid=%s)))"
#define	_F_GETGRMEM_SSD	"(&(%%s)(|(memberUid=%s)(memberUid=%s)))"

/*
 * Copied from getpwnam.c, needed to look up user DN.
 * Would it be better to move to ldap_common.h rather than duplicate?
 */
#define	_F_GETPWNAM	"(&(objectClass=posixAccount)(uid=%s))"
#define	_F_GETPWNAM_SSD	"(&(%%s)(uid=%s))"

static const char *gr_attrs[] = {
	_G_NAME,
	_G_GID,
	_G_PASSWD,
	_G_MEM,
	(char *)NULL
};


/*
 * _nss_ldap_group2str is the data marshaling method for the group getXbyY
 * (e.g., getgrnam(), getgrgid(), getgrent()) backend processes. This method
 * is called after a successful ldap search has been performed. This method
 * will parse the ldap search values into the file format.
 * e.g.
 *
 * adm::4:root,adm,daemon
 *
 */

static int
_nss_ldap_group2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int		i;
	int		nss_result;
	int		buflen = 0, len;
	int		firstime = 1;
	char		*buffer = NULL;
	ns_ldap_result_t	*result = be->result;
	char		**gname, **passwd, **gid, *password, *end;
	char		gid_nobody[NOBODY_STR_LEN];
	char		*gid_nobody_v[1];
	char		*member_str, *strtok_state;
	ns_ldap_attr_t	*members;

	(void) snprintf(gid_nobody, sizeof (gid_nobody), "%u", GID_NOBODY);
	gid_nobody_v[0] = gid_nobody;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);
	buflen = argp->buf.buflen;

	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, buflen)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_grp2str;
		}
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;

	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(buffer, 0, buflen);

	gname = __ns_ldap_getAttr(result->entry, _G_NAME);
	if (gname == NULL || gname[0] == NULL || (strlen(gname[0]) < 1)) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_grp2str;
	}
	passwd = __ns_ldap_getAttr(result->entry, _G_PASSWD);
	if (passwd == NULL || passwd[0] == NULL || (strlen(passwd[0]) == 0)) {
		/* group password could be NULL, replace it with "" */
		password = _NO_PASSWD_VAL;
	} else {
		/*
		 * Preen "{crypt}" if necessary.
		 * If the password does not include the {crypt} prefix
		 * then the password may be plain text.  And thus
		 * perhaps crypt(3c) should be used to encrypt it.
		 * Currently the password is copied verbatim.
		 */
		if (strncasecmp(passwd[0], _CRYPT, strlen(_CRYPT)) == 0)
			password = passwd[0] + strlen(_CRYPT);
		else
			password = passwd[0];
	}
	gid = __ns_ldap_getAttr(result->entry, _G_GID);
	if (gid == NULL || gid[0] == NULL || (strlen(gid[0]) < 1)) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_grp2str;
	}
	/* Validate GID */
	if (strtoul(gid[0], &end, 10) > MAXUID)
		gid = gid_nobody_v;
	len = snprintf(buffer, buflen, "%s:%s:%s:", gname[0], password, gid[0]);
	TEST_AND_ADJUST(len, buffer, buflen, result_grp2str);

	members = __ns_ldap_getAttrStruct(result->entry, _G_MEM);
	if (members == NULL || members->attrvalue == NULL) {
		/* no member is fine, skip processing the member list */
		goto nomember;
	}

	for (i = 0; i < members->value_count; i++) {
		if (members->attrvalue[i] == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_grp2str;
		}
		/*
		 * If we find an '=' in the member attribute value, treat it as
		 * a DN, otherwise as a username.
		 */
		if (member_str = strchr(members->attrvalue[i], '=')) {
			member_str++; /* skip over the '=' */
			/* Fail if we can't pull a username out of the RDN */
			if (! (member_str = strtok_r(member_str,
			    ",", &strtok_state))) {
				nss_result = NSS_STR_PARSE_PARSE;
				goto result_grp2str;
			}
		} else {
			member_str = members->attrvalue[i];
		}
		if (*member_str != '\0') {
			if (firstime) {
				len = snprintf(buffer, buflen, "%s",
				    member_str);
				TEST_AND_ADJUST(len, buffer, buflen,
				    result_grp2str);
				firstime = 0;
			} else {
				len = snprintf(buffer, buflen, ",%s",
				    member_str);
				TEST_AND_ADJUST(len, buffer, buflen,
				    result_grp2str);
			}
		}
	}
nomember:
	/* The front end marshaller doesn't need the trailing nulls */
	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);
result_grp2str:
	(void) __ns_ldap_freeResult(&be->result);
	return (nss_result);
}

/*
 * getbynam gets a group entry by name. This function constructs an ldap
 * search filter using the name invocation parameter and the getgrnam search
 * filter defined. Once the filter is constructed, we searche for a matching
 * entry and marshal the data results into struct group for the frontend
 * process. The function _nss_ldap_group2ent performs the data marshaling.
 */

static nss_status_t
getbynam(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	char		groupname[SEARCHFILTERLEN];
	int		ret;

	if (_ldap_filter_name(groupname, argp->key.name, sizeof (groupname)) !=
	    0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETGRNAM, groupname);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata), _F_GETGRNAM_SSD, groupname);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
	    _GROUP, searchfilter, NULL, _merge_SSD_filter, userdata));
}


/*
 * getbygid gets a group entry by number. This function constructs an ldap
 * search filter using the name invocation parameter and the getgrgid search
 * filter defined. Once the filter is constructed, we searche for a matching
 * entry and marshal the data results into struct group for the frontend
 * process. The function _nss_ldap_group2ent performs the data marshaling.
 */

static nss_status_t
getbygid(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char searchfilter[SEARCHFILTERLEN];
	char userdata[SEARCHFILTERLEN];
	int ret;

	if (argp->key.uid > MAXUID)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETGRGID, argp->key.uid);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETGRGID_SSD, argp->key.uid);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
	    _GROUP, searchfilter, NULL, _merge_SSD_filter, userdata));

}


/*
 * getbymember returns all groups a user is defined in. This function
 * uses different architectural procedures than the other group backend
 * system calls because it's a private interface. This function constructs
 * an ldap search filter using the name invocation parameter. Once the
 * filter is constructed, we search for all matching groups counting
 * and storing each group name, gid, etc. Data marshaling is used for
 * group processing. The function _nss_ldap_group2ent() performs the
 * data marshaling.
 *
 * (const char *)argp->username;	(size_t)strlen(argp->username);
 * (gid_t)argp->gid_array;		(int)argp->maxgids;
 * (int)argp->numgids;
 */

static nss_status_t
getbymember(ldap_backend_ptr be, void *a)
{
	int			i, j, k;
	int			gcnt = (int)0;
	char			**groupvalue, **membervalue, *member_str;
	char			*strtok_state;
	nss_status_t		lstat;
	struct nss_groupsbymem	*argp = (struct nss_groupsbymem *)a;
	char			searchfilter[SEARCHFILTERLEN];
	char			userdata[SEARCHFILTERLEN];
	char			name[SEARCHFILTERLEN];
	ns_ldap_result_t	*result;
	ns_ldap_entry_t		*curEntry;
	char			*username, **dn_attr, *dn;
	gid_t			gid;
	int			ret;

	if (strcmp(argp->username, "") == 0 ||
	    strcmp(argp->username, "root") == 0)
		return ((nss_status_t)NSS_NOTFOUND);

	if (_ldap_filter_name(name, argp->username, sizeof (name)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter), _F_GETPWNAM, name);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata), _F_GETPWNAM_SSD, name);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	/*
	 * Look up the user DN in ldap. If it's not found, search solely by
	 * username.
	 */
	lstat = (nss_status_t)_nss_ldap_nocb_lookup(be, NULL,
	    _PASSWD, searchfilter, NULL, _merge_SSD_filter, userdata);
	if (lstat != (nss_status_t)NS_LDAP_SUCCESS)
		return ((nss_status_t)lstat);

	if (be->result == NULL ||
	    !(dn_attr = __ns_ldap_getAttr(be->result->entry, "dn")))
		dn = name;
	else
		dn = dn_attr[0];

	ret = snprintf(searchfilter, sizeof (searchfilter), _F_GETGRMEM, name,
	    dn);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata), _F_GETGRMEM_SSD, name,
	    dn);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	/*
	 * Free up resources from user DN search before performing group
	 * search.
	 */
	(void) __ns_ldap_freeResult((ns_ldap_result_t **)&be->result);

	gcnt = (int)argp->numgids;
	lstat = (nss_status_t)_nss_ldap_nocb_lookup(be, NULL,
	    _GROUP, searchfilter, NULL, _merge_SSD_filter, userdata);
	if (lstat != (nss_status_t)NS_LDAP_SUCCESS)
		return ((nss_status_t)lstat);
	if (be->result == NULL)
		return (NSS_NOTFOUND);
	username = (char *)argp->username;
	result = (ns_ldap_result_t *)be->result;
	curEntry = (ns_ldap_entry_t *)result->entry;
	for (i = 0; i < result->entries_count && curEntry != NULL; i++) {
		membervalue = __ns_ldap_getAttr(curEntry, "memberUid");
		if (membervalue == NULL) {
			curEntry = curEntry->next;
			continue;
		}
		for (j = 0; membervalue[j]; j++) {
			/*
			 * If we find an '=' in the member attribute
			 * value, treat it as a DN, otherwise as a
			 * username.
			 */
			if (member_str = strchr(membervalue[j], '=')) {
				member_str++; /* skip over the '=' */
				member_str = strtok_r(member_str, ",",
				    &strtok_state);
			} else {
				member_str = membervalue[j];
			}
			if (member_str != NULL &&
			    strcmp(member_str, username) == 0) {
				groupvalue = __ns_ldap_getAttr(curEntry,
				    "gidnumber");
				if (groupvalue == NULL ||
				    groupvalue[0] == NULL) {
					/* Drop this group from the list */
					break;
				}
				errno = 0;
				gid = (gid_t)strtol(groupvalue[0],
				    (char **)NULL, 10);

				if (errno == 0 &&
				    argp->numgids < argp->maxgids) {
					for (k = 0; k < argp->numgids; k++) {
						if (argp->gid_array[k] == gid)
							/* already exists */
							break;
					}
					if (k == argp->numgids)
						argp->gid_array[argp->numgids++]
						    = gid;
				}
				break;
			}
		}
		curEntry = curEntry->next;
	}

	(void) __ns_ldap_freeResult((ns_ldap_result_t **)&be->result);
	if (gcnt == argp->numgids)
		return ((nss_status_t)NSS_NOTFOUND);

	/*
	 * Return NSS_SUCCESS only if array is full.
	 * Explained in <nss_dbdefs.h>.
	 */
	return ((nss_status_t)((argp->numgids == argp->maxgids)
	    ? NSS_SUCCESS
	    : NSS_NOTFOUND));
}

static ldap_backend_op_t gr_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
	getbynam,
	getbygid,
	getbymember
};


/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_group_constr(const char *dummy1, const char *dummy2,
    const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(gr_ops,
	    sizeof (gr_ops)/sizeof (gr_ops[0]), _GROUP, gr_attrs,
	    _nss_ldap_group2str));
}
