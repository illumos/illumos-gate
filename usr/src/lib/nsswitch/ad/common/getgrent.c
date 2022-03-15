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

#include <grp.h>
#include <idmap.h>
#include "ad_common.h"

static int
update_buffer(ad_backend_ptr be, nss_XbyY_args_t *argp,
		const char *name, const char *domain, gid_t gid)
{
	int	buflen;
	char	*buffer;

	if (domain == NULL)
		domain = WK_DOMAIN;

	buflen = snprintf(NULL, 0, "%s@%s::%u:", name, domain, gid) + 1;

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

	(void) snprintf(buffer, buflen, "%s@%s::%u:", name, domain, gid);
	return (0);
}

/*
 * getbynam gets a group entry by name. This function constructs an ldap
 * search filter using the name invocation parameter and the getgrnam search
 * filter defined. Once the filter is constructed, we search for a matching
 * entry and marshal the data results into struct group for the frontend
 * process. The function _nss_ad_group2ent performs the data marshaling.
 */
static nss_status_t
getbynam(ad_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		name[SEARCHFILTERLEN];
	char		*dname;
	nss_status_t	stat;
	idmap_stat	idmaprc;
	gid_t		gid;
	int		is_user, is_wuser;

	be->db_type = NSS_AD_DB_GROUP_BYNAME;

	/* Sanitize name so that it can be used in our LDAP filter */
	if (_ldap_filter_name(name, argp->key.name, sizeof (name)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	if ((dname = strchr(name, '@')) == NULL)
		return ((nss_status_t)NSS_NOTFOUND);

	*dname = '\0';
	dname++;

	/*
	 * Map the name to gid using idmap service.
	 */
	is_wuser = -1;
	is_user = 0; /* Map name to gid */
	idmaprc = idmap_get_w2u_mapping(NULL, NULL, name, dname,
	    0, &is_user, &is_wuser, &gid, NULL, NULL, NULL);
	if (idmaprc != IDMAP_SUCCESS) {
		RESET_ERRNO();
		return ((nss_status_t)NSS_NOTFOUND);
	}

	/* Create group(5) style string */
	if (update_buffer(be, argp, name, dname, gid) < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	/* Marshall the data, sanitize the return status and return */
	stat = _nss_ad_marshall_data(be, argp);
	return (_nss_ad_sanitize_status(be, argp, stat));
}

/*
 * getbygid gets a group entry by number. This function constructs an ldap
 * search filter using the name invocation parameter and the getgrgid search
 * filter defined. Once the filter is constructed, we searche for a matching
 * entry and marshal the data results into struct group for the frontend
 * process. The function _nss_ad_group2ent performs the data marshaling.
 */
static nss_status_t
getbygid(ad_backend_ptr be, void *a)
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char			*winname = NULL, *windomain = NULL;
	nss_status_t		stat;

	be->db_type = NSS_AD_DB_GROUP_BYGID;

	stat = (nss_status_t)NSS_NOTFOUND;

	/* nss_ad does not support non ephemeral gids */
	if (argp->key.gid <= MAXUID)
		goto out;

	/* Map the given GID to a SID using the idmap service */
	if (idmap_get_u2w_mapping(&argp->key.gid, NULL, 0,
	    0, NULL, NULL, NULL, &winname, &windomain,
	    NULL, NULL) != 0) {
		RESET_ERRNO();
		goto out;
	}

	/*
	 * NULL winname implies a local SID or unresolvable SID both of
	 * which cannot be used to generated group(5) entry
	 */
	if (winname == NULL)
		goto out;

	/* Create group(5) style string */
	if (update_buffer(be, argp, winname, windomain, argp->key.gid) < 0)
		goto out;

	/* Marshall the data, sanitize the return status and return */
	stat = _nss_ad_marshall_data(be, argp);
	stat = _nss_ad_sanitize_status(be, argp, stat);

out:
	idmap_free(winname);
	idmap_free(windomain);
	return (stat);
}

static ad_backend_op_t gr_ops[] = {
	_nss_ad_destr,
	_nss_ad_endent,
	_nss_ad_setent,
	_nss_ad_getent,
	getbynam,
	getbygid
};

/*ARGSUSED0*/
nss_backend_t *
_nss_ad_group_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ad_constr(gr_ops,
	    sizeof (gr_ops)/sizeof (gr_ops[0]), _GROUP, NULL, NULL));
}
