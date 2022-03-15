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

#include <shadow.h>
#include <stdlib.h>
#include "ad_common.h"

static int
update_buffer(ad_backend_ptr be, nss_XbyY_args_t *argp,
		const char *name, const char *domain)
{
	int	buflen;
	char	*buffer;

	/*
	 * The user password is not available in the AD object and therefore
	 * sp_pwdp will be "*NP*".
	 *
	 * nss_ad will leave aging fields empty (i.e. The front end
	 * marshaller will set sp_lstchgst, sp_min, sp_max, sp_warn,
	 * sp_inact, and sp_expire to -1 and sp_flag to 0) because shadow
	 * fields are irrevalent with AD and krb5.
	 */

	buflen = snprintf(NULL, 0, "%s@%s:*NP*:::::::", name, domain) + 1;

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

	buflen = snprintf(buffer, buflen, "%s@%s:*NP*:::::::",
	    name, domain) + 1;
	return (0);
}

/*
 * getbynam gets a shadow entry by winname. This function constructs an ldap
 * search filter using the name invocation parameter and the getspnam search
 * filter defined. Once the filter is constructed we search for a matching
 * entry and marshal the data results into struct shadow for the frontend
 * process. The function _nss_ad_shadow2ent performs the data marshaling.
 */
static nss_status_t
getbynam(ad_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		name[SEARCHFILTERLEN + 1];
	char		*dname;
	nss_status_t	stat;
	idmap_stat	idmaprc;
	uid_t		uid;
	int		is_user, is_wuser;

	be->db_type = NSS_AD_DB_SHADOW_BYNAME;

	/* Sanitize name so that it can be used in our LDAP filter */
	if (_ldap_filter_name(name, argp->key.name, sizeof (name)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	if ((dname = strchr(name, '@')) == NULL)
		return ((nss_status_t)NSS_NOTFOUND);

	*dname = '\0';
	dname++;

	/*
	 * Use idmap service to verify that the given
	 * name is a valid Windows name.
	 */
	is_wuser = -1;
	is_user = 1;
	idmaprc = idmap_get_w2u_mapping(NULL, NULL, name, dname,
	    0, &is_user, &is_wuser, &uid, NULL, NULL, NULL);
	if (idmaprc != IDMAP_SUCCESS) {
		RESET_ERRNO();
		return ((nss_status_t)NSS_NOTFOUND);
	}

	/* Create shadow(5) style string */
	if (update_buffer(be, argp, name, dname) < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	/* Marshall the data, sanitize the return status and return */
	stat = _nss_ad_marshall_data(be, argp);
	return (_nss_ad_sanitize_status(be, argp, stat));
}

static ad_backend_op_t sp_ops[] = {
    _nss_ad_destr,
    _nss_ad_endent,
    _nss_ad_setent,
    _nss_ad_getent,
    getbynam
};


/*
 * _nss_ad_passwd_constr is where life begins. This function calls the
 * generic ldap constructor function to define and build the abstract
 * data types required to support ldap operations.
 */
/*ARGSUSED0*/
nss_backend_t *
_nss_ad_shadow_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ad_constr(sp_ops,
	    sizeof (sp_ops)/sizeof (sp_ops[0]),
	    _SHADOW, NULL, NULL));
}
