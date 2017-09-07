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
#define	_G_MEMUID	"memberuid"
#define	_G_MEM_DN	"member"	/* DN */

#define	_F_GETGRNAM	"(&(objectClass=posixGroup)(cn=%s))"
#define	_F_GETGRNAM_SSD	"(&(%%s)(cn=%s))"
#define	_F_GETGRGID	"(&(objectClass=posixGroup)(gidNumber=%u))"
#define	_F_GETGRGID_SSD	"(&(%%s)(gidNumber=%u))"

/*
 * When searching for groups in which a specified user is a member,
 * there are a few different membership schema that might be in use.
 * We'll use a filter that should work with an of the common ones:
 * "memberUid=NAME", or "member=DN" (try uniquemember too?)
 * The first parameter in the filter string is replaced by username,
 * and the remaining ones by the full DN.
 */
#define	_F_GETGRMEM "(&(objectClass=posixGroup)" \
	"(|(memberUid=%s)(member=%s)))"
#define	_F_GETGRMEM_SSD	"(&(%%s)" \
	"(|(memberUid=%s)(member=%s)))"

static const char *gr_attrs[] = {
	_G_NAME,
	_G_GID,
	_G_PASSWD,
	_G_MEMUID,
	_G_MEM_DN,
	(char *)NULL
};

static int
getmembers_UID(char **bufpp, int *lenp, ns_ldap_attr_t *members);
static int
getmembers_DN(char **bufpp, int *lenp, ns_ldap_attr_t *members);


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
	char		*buffer = NULL;
	ns_ldap_result_t	*result = be->result;
	char		**gname, **passwd, **gid, *password, *end;
	char		gid_nobody[NOBODY_STR_LEN];
	char		*gid_nobody_v[1];
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

	members = __ns_ldap_getAttrStruct(result->entry, _G_MEMUID);
	if (members != NULL && members->attrvalue != NULL) {
		nss_result = getmembers_UID(&buffer, &buflen, members);
		if (nss_result != 0)
			goto result_grp2str;
	}

	members = __ns_ldap_getAttrStruct(result->entry, _G_MEM_DN);
	if (members != NULL && members->attrvalue != NULL) {
		nss_result = getmembers_DN(&buffer, &buflen, members);
		if (nss_result != 0)
			goto result_grp2str;
	}

	/* The front end marshaller doesn't need the trailing nulls */
	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);
result_grp2str:
	(void) __ns_ldap_freeResult(&be->result);
	return (nss_result);
}

/*
 * Process the list values from the "memberUid" attribute of the
 * current group.  Note that this list is often empty, and we
 * get the real list of members via getmember_DN (see below).
 */
static int
getmembers_UID(char **bufpp, int *lenp, ns_ldap_attr_t *members)
{
	char	*member_str, *strtok_state;
	char	*buffer;
	int	buflen;
	int	i, len;
	int	nss_result = 0;
	int	firsttime;

	buffer = *bufpp;
	buflen = *lenp;
	firsttime = (buffer[-1] == ':');

	for (i = 0; i < members->value_count; i++) {
		member_str = members->attrvalue[i];
		if (member_str == NULL)
			goto out;

#ifdef DEBUG
		(void) fprintf(stdout, "getmembers_UID: uid=<%s>\n",
		    member_str);
#endif
		/*
		 * If not a valid Unix user name, or
		 * not valid in ldap, just skip.
		 */
		if (member_str[0] == '\0' ||
		    strpbrk(member_str, " ,:=") != NULL)
			continue;

		if (firsttime)
			len = snprintf(buffer, buflen, "%s", member_str);
		else
			len = snprintf(buffer, buflen, ",%s", member_str);
		TEST_AND_ADJUST(len, buffer, buflen, out);
	}

out:
	*bufpp = buffer;
	*lenp = buflen;
	return (nss_result);
}

/*
 * Process the list values from the "member" attribute of the
 * current group.  Note that this list is ONLY one that can be
 * assumed to be non-empty.  The problem here is that this list
 * contains the list of members as "distinguished names" (DN),
 * and we want the Unix names (known here as "uid").  We must
 * lookup the "uid" for each DN in the member list.  Example:
 * CN=Doe\, John,OU=Users,DC=contoso,DC=com => john.doe
 */
static int
getmembers_DN(char **bufpp, int *lenp, ns_ldap_attr_t *members)
{
	ns_ldap_error_t *error = NULL;
	char	*member_dn, *member_uid;
	char	*buffer;
	int	buflen;
	int	i, len;
	int	nss_result = 0;
	int	firsttime;

	buffer = *bufpp;
	buflen = *lenp;
	firsttime = (buffer[-1] == ':');

	for (i = 0; i < members->value_count; i++) {
		member_dn = members->attrvalue[i];
		if (member_dn == NULL)
			goto out;

		/*
		 * The attribute name was "member", so these should be
		 * full distinguished names (DNs).  We need to loookup
		 * the Unix UID (name) for each.
		 */
#ifdef DEBUG
		(void) fprintf(stdout, "getmembers_DN: dn=%s\n",
		    member_dn);
#endif
		if (member_dn[0] == '\0')
			continue;

		nss_result = __ns_ldap_dn2uid(member_dn,
		    &member_uid, NULL, &error);
		if (nss_result != NS_LDAP_SUCCESS) {
			(void) __ns_ldap_freeError(&error);
			error = NULL;
			continue;
		}
#ifdef DEBUG
		(void) fprintf(stdout, "getmembers_DN: uid=<%s>\n",
		    member_uid);
#endif
		/* Skip invalid names. */
		if (member_uid[0] == '\0' ||
		    strpbrk(member_uid, " ,:=") != NULL) {
			free(member_uid);
			continue;
		}

		if (firsttime)
			len = snprintf(buffer, buflen, "%s", member_uid);
		else
			len = snprintf(buffer, buflen, ",%s", member_uid);
		free(member_uid);
		TEST_AND_ADJUST(len, buffer, buflen, out);
	}

out:
	*bufpp = buffer;
	*lenp = buflen;
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
 * Use a custom attributes list for getbymember, because the LDAP
 * query for this requests a list of groups, and the result can be
 * very large if it includes the list of members with each group.
 * We don't need or want the list of members in this case.
 */
static const char *grbymem_attrs[] = {
	_G_NAME,	/* cn */
	_G_GID,		/* gidnumber */
	(char *)NULL
};

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
	ns_ldap_error_t		*error = NULL;
	int			i, j, k;
	int			gcnt = (int)0;
	char			**groupvalue;
	nss_status_t		lstat;
	struct nss_groupsbymem	*argp = (struct nss_groupsbymem *)a;
	char			searchfilter[SEARCHFILTERLEN];
	char			userdata[SEARCHFILTERLEN];
	char			name[SEARCHFILTERLEN];
	char			escdn[SEARCHFILTERLEN];
	ns_ldap_result_t	*result;
	ns_ldap_entry_t		*curEntry;
	char			*dn;
	gid_t			gid;
	int			ret1, ret2;

	if (strcmp(argp->username, "") == 0 ||
	    strcmp(argp->username, "root") == 0)
		return ((nss_status_t)NSS_NOTFOUND);

	if (_ldap_filter_name(name, argp->username, sizeof (name)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	/*
	 * Look up the user DN in ldap. If it's not found, search solely by
	 * username.
	 */
	lstat = __ns_ldap_uid2dn(name, &dn, NULL, &error);
	if (lstat != (nss_status_t)NS_LDAP_SUCCESS) {
		/* Can't get DN.  Use bare name */
		(void) __ns_ldap_freeError(&error);
		dn = name;
	}
	/* Note: must free dn if != name */

	/*
	 * Compose filter patterns
	 */
	ret1 = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETGRMEM, name, dn);
	ret2 = snprintf(userdata, sizeof (userdata),
	    _F_GETGRMEM_SSD, name, dn);
	if (dn != name)
		free(dn);
	if (ret1 >= sizeof (searchfilter) || ret1 < 0)
		return ((nss_status_t)NSS_NOTFOUND);
	if (ret2 >= sizeof (userdata) || ret2 < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	/*
	 * Query for groups matching the filter.
	 */
	lstat = (nss_status_t)_nss_ldap_nocb_lookup(be, NULL,
	    _GROUP, searchfilter, grbymem_attrs,
	    _merge_SSD_filter, userdata);
	if (lstat != (nss_status_t)NS_LDAP_SUCCESS)
		return ((nss_status_t)lstat);
	if (be->result == NULL)
		return (NSS_NOTFOUND);

	/*
	 * Walk the query result, collecting GIDs.
	 */
	result = (ns_ldap_result_t *)be->result;
	curEntry = (ns_ldap_entry_t *)result->entry;
	gcnt = (int)argp->numgids;
	for (i = 0; i < result->entries_count; i++) {

		/*
		 * Does this group have a gidNumber attr?
		 */
		groupvalue = __ns_ldap_getAttr(curEntry, _G_GID);
		if (groupvalue == NULL || groupvalue[0] == NULL) {
			/* Drop this group from the list */
			goto next_group;
		}

		/*
		 * Convert it to a numeric GID
		 */
		errno = 0;
		gid = (gid_t)strtol(groupvalue[0], (char **)NULL, 10);
		if (errno != 0)
			goto next_group;

		/*
		 * If we don't already have this GID, add it.
		 */
		if (argp->numgids < argp->maxgids) {
			for (k = 0; k < argp->numgids; k++) {
				if (argp->gid_array[k] == gid) {
					/* already have it */
					goto next_group;
				}
			}
			argp->gid_array[argp->numgids++] = gid;
		}

	next_group:
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
