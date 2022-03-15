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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <pwd.h>
#include <idmap.h>
#include <ctype.h>
#include "ad_common.h"

/* passwd attributes and filters */
#define	_PWD_DN			"dn"
#define	_PWD_SAN		"sAMAccountName"
#define	_PWD_OBJSID		"objectSid"
#define	_PWD_PRIMARYGROUPID	"primaryGroupID"
#define	_PWD_CN			"cn"
#define	_PWD_HOMEDIRECTORY	"homedirectory"
#define	_PWD_LOGINSHELL		"loginshell"
#define	_PWD_OBJCLASS		"objectClass"

#define	_F_GETPWNAM		"(sAMAccountName=%.*s)"
#define	_F_GETPWUID		"(objectSid=%s)"

static const char *pwd_attrs[] = {
	_PWD_SAN,
	_PWD_OBJSID,
	_PWD_PRIMARYGROUPID,
	_PWD_CN,
	_PWD_HOMEDIRECTORY,
	_PWD_LOGINSHELL,
	_PWD_OBJCLASS,
	(char *)NULL
};

static int
update_buffer(ad_backend_ptr be, nss_XbyY_args_t *argp,
		const char *name, const char *domain,
		uid_t uid, gid_t gid, const char *gecos,
		const char *homedir, const char *shell)
{
	int	buflen;
	char	*buffer;

	if (be->db_type == NSS_AD_DB_PASSWD_BYNAME) {
		/*
		 * The canonical name obtained from AD lookup may not match
		 * the case of the name (i.e. key) in the request. Therefore,
		 * use the name from the request to construct the result.
		 */
		buflen = snprintf(NULL, 0, "%s:%s:%u:%u:%s:%s:%s",
		    argp->key.name, "x", uid, gid, gecos, homedir, shell) + 1;
	} else {
		if (domain == NULL)
			domain = WK_DOMAIN;
		buflen = snprintf(NULL, 0, "%s@%s:%s:%u:%u:%s:%s:%s",
		    name, domain, "x", uid, gid, gecos, homedir, shell) + 1;
	}


	if (argp->buf.result != NULL) {
		buffer = be->buffer = malloc(buflen);
		if (be->buffer == NULL)
			return (-1);
		be->buflen = buflen;
	} else {
		if (buflen > argp->buf.buflen)
			return (-1);
		buflen = argp->buf.buflen;
		buffer = argp->buf.buffer;
	}

	if (be->db_type == NSS_AD_DB_PASSWD_BYNAME)
		(void) snprintf(buffer, buflen, "%s:%s:%u:%u:%s:%s:%s",
		    argp->key.name, "x", uid, gid, gecos, homedir, shell);
	else
		(void) snprintf(buffer, buflen, "%s@%s:%s:%u:%u:%s:%s:%s",
		    name, domain, "x", uid, gid, gecos, homedir, shell);
	return (0);
}


#define	NET_SCHEME	"/net"

/*
 * 1) If the homeDirectory string is in UNC format then convert it into
 * a /net format. This needs to be revisited later but is fine for now
 * because Solaris does not support -hosts automount map for CIFS yet.
 *
 * 2) If homeDirectory contains ':' then return NULL because ':' is the
 * delimiter in passwd entries and may break apps that parse these entries.
 *
 * 3) For all other cases return the same string that was passed to
 * this function.
 */
static
char *
process_homedir(char *homedir)
{
	size_t	len, smb_len;
	char	*smb_homedir;
	int	i, slash = 0;

	len = strlen(homedir);

	if (strchr(homedir, ':') != NULL)
		/*
		 * Ignore paths that have colon ':' because ':' is a
		 * delimiter for the passwd entry.
		 */
		return (NULL);

	if (!(len > 1 && homedir[0] == '\\' && homedir[1] == '\\'))
		/* Keep homedir intact if not in UNC format */
		return (homedir);

	/*
	 * Convert UNC string into /net format
	 * Example: \\server\abc -> /net/server/abc
	 */
	smb_len = len + 1 + sizeof (NET_SCHEME);
	if ((smb_homedir = calloc(1, smb_len)) == NULL)
		return (NULL);
	(void) strlcpy(smb_homedir, NET_SCHEME, smb_len);
	for (i = strlen(smb_homedir); *homedir != '\0'; homedir++) {
		if (*homedir == '\\') {
			/* Reduce double backslashes into one */
			if (slash)
				slash = 0;
			else {
				slash = 1;
				smb_homedir[i++] = '/';
			}
		} else {
			smb_homedir[i++] = *homedir;
			slash = 0;
		}
	}
	return (smb_homedir);
}

/*
 * _nss_ad_passwd2str is the data marshaling method for the passwd getXbyY
 * (e.g., getbyuid(), getbyname(), getpwent()) backend processes. This method is
 * called after a successful AD search has been performed. This method will
 * parse the AD search values into the file format.
 * e.g.
 *
 * blue@whale:x:123456:10:Blue Whale:/:
 *
 */
static int
_nss_ad_passwd2str(ad_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			nss_result;
	adutils_result_t	*result = be->result;
	const adutils_entry_t	*entry;
	char			**sid_v, *ptr, **pgid_v, *end;
	ulong_t			tmp;
	uint32_t		urid, grid;
	uid_t			uid;
	gid_t			gid;
	idmap_stat		gstat;
	idmap_get_handle_t 	*ig = NULL;
	char			**name_v, **dn_v, *domain = NULL;
	char			**gecos_v, **shell_v;
	char			**homedir_v = NULL, *homedir = NULL;
	char			*NULL_STR = "";

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);
	entry = adutils_getfirstentry(result);
	nss_result = NSS_STR_PARSE_PARSE;

	/* Create handles for idmap service */
	if (idmap_get_create(&ig) != 0)
		goto result_pwd2str;

	/* Get name */
	name_v = adutils_getattr(entry, _PWD_SAN);
	if (name_v == NULL || name_v[0] == NULL || *name_v[0] == '\0')
		goto result_pwd2str;

	/* Get domain */
	dn_v = adutils_getattr(entry, _PWD_DN);
	if (dn_v == NULL || dn_v[0] == NULL || *dn_v[0] == '\0')
		goto result_pwd2str;
	domain = adutils_dn2dns(dn_v[0]);

	/* Get objectSID (in text format) */
	sid_v = adutils_getattr(entry, _PWD_OBJSID);
	if (sid_v == NULL || sid_v[0] == NULL || *sid_v[0] == '\0')
		goto result_pwd2str;

	/* Break SID into prefix and rid */
	if ((ptr = strrchr(sid_v[0], '-')) == NULL)
		goto result_pwd2str;
	*ptr = '\0';
	end = ++ptr;
	tmp = strtoul(ptr, &end, 10);
	if (end == ptr || tmp > UINT32_MAX)
		goto result_pwd2str;
	urid = (uint32_t)tmp;

	/* We already have uid -- no need to call idmapd */
	if (be->db_type == NSS_AD_DB_PASSWD_BYUID)
		uid = argp->key.uid;
	else
		uid = be->uid;

	/* Get primaryGroupID */
	pgid_v = adutils_getattr(entry, _PWD_PRIMARYGROUPID);
	if (pgid_v == NULL || pgid_v[0] == NULL || *pgid_v[0] == '\0')
		/*
		 * If primaryGroupID is not found then we request
		 * a GID to be mapped to the given user's objectSID
		 * (diagonal mapping) and use this GID as the primary
		 * GID for the entry.
		 */
		grid = urid;
	else {
		end = pgid_v[0];
		tmp = strtoul(pgid_v[0], &end, 10);
		if (end == pgid_v[0] || tmp > UINT32_MAX)
			goto result_pwd2str;
		grid = (uint32_t)tmp;
	}

	/* Map group SID to GID using idmap service */
	if (idmap_get_gidbysid(ig, sid_v[0], grid, 0, &gid, &gstat) != 0)
		goto result_pwd2str;
	if (idmap_get_mappings(ig) != 0 || gstat != 0) {
		RESET_ERRNO();
		goto result_pwd2str;
	}

	/* Get gecos, homedirectory and shell information if available */
	gecos_v = adutils_getattr(entry, _PWD_CN);
	if (gecos_v == NULL || gecos_v[0] == NULL || *gecos_v[0] == '\0')
		gecos_v = &NULL_STR;

	homedir_v = adutils_getattr(entry, _PWD_HOMEDIRECTORY);
	if (homedir_v == NULL || homedir_v[0] == NULL || *homedir_v[0] == '\0')
		homedir = NULL_STR;
	else if ((homedir = process_homedir(homedir_v[0])) == NULL)
		homedir = NULL_STR;

	shell_v = adutils_getattr(entry, _PWD_LOGINSHELL);
	if (shell_v == NULL || shell_v[0] == NULL || *shell_v[0] == '\0')
		shell_v = &NULL_STR;

	if (update_buffer(be, argp, name_v[0], domain, uid, gid,
	    gecos_v[0], homedir, shell_v[0]) < 0)
		nss_result = NSS_STR_PARSE_ERANGE;
	else
		nss_result = NSS_STR_PARSE_SUCCESS;

result_pwd2str:
	idmap_get_destroy(ig);
	(void) adutils_freeresult(&be->result);
	free(domain);
	if (homedir != NULL_STR && homedir_v != NULL &&
	    homedir != homedir_v[0])
		free(homedir);
	return ((int)nss_result);
}

/*
 * getbyname gets a passwd entry by winname. This function constructs an ldap
 * search filter using the name invocation parameter and the getpwnam search
 * filter defined. Once the filter is constructed, we search for a matching
 * entry and marshal the data results into struct passwd for the frontend
 * process. The function _nss_ad_passwd2ent performs the data marshaling.
 */

static nss_status_t
getbyname(ad_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		*searchfilter;
	char		name[SEARCHFILTERLEN];
	char		*dname;
	int		filterlen, namelen;
	int		flag;
	nss_status_t	stat;
	idmap_stat	idmaprc;
	uid_t		uid;
	gid_t		gid;
	int		is_user, is_wuser, try_idmap;

	be->db_type = NSS_AD_DB_PASSWD_BYNAME;

	/* Sanitize name so that it can be used in our LDAP filter */
	if (_ldap_filter_name(name, argp->key.name, sizeof (name)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	if ((dname = strchr(name, '@')) == NULL)
		return ((nss_status_t)NSS_NOTFOUND);

	*dname = '\0';
	dname++;

	/*
	 * Map the given name to UID using idmap service. If idmap
	 * call fails then this will save us doing AD discovery and
	 * AD lookup here.
	 */
	flag = (strcasecmp(dname, WK_DOMAIN) == 0) ?
	    IDMAP_REQ_FLG_WK_OR_LOCAL_SIDS_ONLY : 0;
	is_wuser = -1;
	is_user = 1;
	if (idmap_get_w2u_mapping(NULL, NULL, name,
	    dname, flag, &is_user, &is_wuser, &be->uid, NULL,
	    NULL, NULL) != IDMAP_SUCCESS) {
		RESET_ERRNO();
		return ((nss_status_t)NSS_NOTFOUND);
	}

	/* If this is not a Well-Known SID then try AD lookup. */
	if (strcasecmp(dname, WK_DOMAIN) != 0) {
		/* Assemble filter using the given name */
		namelen = strlen(name);
		filterlen = snprintf(NULL, 0, _F_GETPWNAM, namelen, name) + 1;
		if ((searchfilter = (char *)malloc(filterlen)) == NULL)
			return ((nss_status_t)NSS_NOTFOUND);
		(void) snprintf(searchfilter, filterlen, _F_GETPWNAM,
		    namelen, name);
		stat = _nss_ad_lookup(be, argp, _PASSWD, searchfilter,
		    dname, &try_idmap);
		free(searchfilter);

		if (!try_idmap)
			return (stat);

	}

	/*
	 * Either this is a Well-Known SID or AD lookup failed. Map
	 * the given name to GID using idmap service and construct
	 * the passwd entry.
	 */
	is_wuser = -1;
	is_user = 0; /* Map name to primary gid */
	idmaprc = idmap_get_w2u_mapping(NULL, NULL, name, dname,
	    flag, &is_user, &is_wuser, &gid, NULL, NULL, NULL);
	if (idmaprc != IDMAP_SUCCESS) {
		RESET_ERRNO();
		return ((nss_status_t)NSS_NOTFOUND);
	}

	/* Create passwd(5) style string */
	if (update_buffer(be, argp, name, dname,
	    be->uid, gid, "", "", "") < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	/* Marshall the data, sanitize the return status and return */
	stat = _nss_ad_marshall_data(be, argp);
	return (_nss_ad_sanitize_status(be, argp, stat));
}


/*
 * getbyuid gets a passwd entry by uid number. This function constructs an ldap
 * search filter using the uid invocation parameter and the getpwuid search
 * filter defined. Once the filter is constructed, we search for a matching
 * entry and marshal the data results into struct passwd for the frontend
 * process. The function _nss_ad_passwd2ent performs the data marshaling.
 */

static nss_status_t
getbyuid(ad_backend_ptr be, void *a)
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char			searchfilter[ADUTILS_MAXHEXBINSID + 14];
	char			*sidprefix = NULL;
	idmap_rid_t		rid;
	char			cbinsid[ADUTILS_MAXHEXBINSID + 1];
	char			*winname = NULL, *windomain = NULL;
	int			is_user, is_wuser;
	gid_t			gid;
	idmap_stat		idmaprc;
	int			ret, try_idmap;
	nss_status_t		stat;

	be->db_type = NSS_AD_DB_PASSWD_BYUID;

	stat = (nss_status_t)NSS_NOTFOUND;

	/* nss_ad does not support non ephemeral uids */
	if (argp->key.uid <= MAXUID)
		goto out;

	/* Map the given UID to a SID using the idmap service */
	if (idmap_get_u2w_mapping(&argp->key.uid, NULL, 0,
	    1, NULL, &sidprefix, &rid, &winname, &windomain,
	    NULL, NULL) != 0) {
		RESET_ERRNO();
		goto out;
	}

	/*
	 * NULL winname implies a local SID or unresolvable SID both of
	 * which cannot be used to generated passwd(5) entry
	 */
	if (winname == NULL)
		goto out;

	/* If this is not a Well-Known SID try AD lookup */
	if (windomain != NULL && strcasecmp(windomain, WK_DOMAIN) != 0) {
		if (adutils_txtsid2hexbinsid(sidprefix, &rid,
		    &cbinsid[0], sizeof (cbinsid)) != 0)
			goto out;

		ret = snprintf(searchfilter, sizeof (searchfilter),
		    _F_GETPWUID, cbinsid);
		if (ret >= sizeof (searchfilter) || ret < 0)
			goto out;

		stat = _nss_ad_lookup(be, argp, _PASSWD, searchfilter,
		    windomain, &try_idmap);

		if (!try_idmap)
			goto out;
	}

	/* Map winname to primary gid using idmap service */
	is_user = 0;
	is_wuser = -1;
	idmaprc = idmap_get_w2u_mapping(NULL, NULL,
	    winname, windomain, 0, &is_user, &is_wuser, &gid,
	    NULL, NULL, NULL);

	if (idmaprc != IDMAP_SUCCESS) {
		RESET_ERRNO();
		goto out;
	}

	/* Create passwd(5) style string */
	if (update_buffer(be, argp, winname, windomain,
	    argp->key.uid, gid, "", "", "") < 0)
		goto out;

	/* Marshall the data, sanitize the return status and return */
	stat = _nss_ad_marshall_data(be, argp);
	stat = _nss_ad_sanitize_status(be, argp, stat);

out:
	idmap_free(sidprefix);
	idmap_free(winname);
	idmap_free(windomain);
	return (stat);
}

static ad_backend_op_t passwd_ops[] = {
	_nss_ad_destr,
	_nss_ad_endent,
	_nss_ad_setent,
	_nss_ad_getent,
	getbyname,
	getbyuid
};

/*
 * _nss_ad_passwd_constr is where life begins. This function calls the
 * generic AD constructor function to define and build the abstract
 * data types required to support AD operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ad_passwd_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ad_constr(passwd_ops,
	    sizeof (passwd_ops)/sizeof (passwd_ops[0]),
	    _PASSWD, pwd_attrs, _nss_ad_passwd2str));
}
