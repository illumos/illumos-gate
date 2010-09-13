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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ldap_common.h"

/* bootparams attributes filters */
#define	_B_HOSTNAME		"cn"
#define	_B_PARAMETER		"bootparameter"
#define	_F_GETBOOTPARAMBYNAME	"(&(objectClass=bootableDevice)(cn=%s))"
#define	_F_GETBOOTPARAMBYNAME_SSD "(&(%%s)(cn=%s))"

static const char *bootparams_attrs[] = {
	_B_HOSTNAME,
	_B_PARAMETER,
	(char *)NULL
};

/*
 * _nss_ldap_bootparams2str is the data marshaling method for the
 * bootparams bootparams_getbyname backend processes.
 * This method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into the file format.
 *
 * A host's bootparameters are returned on one line separated by white
 * space. The LDAP server stores each boot parameter as a separate entry.
 * If more than one bootparameter is available, a white space separated buffer
 * must be constructed and returned.
 *
 */

static int
_nss_ldap_bootparams2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	uint_t		i;
	int		buflen = 0, len = 0;
	int		nss_result, firsttime;
	ns_ldap_attr_t	*bparams;
	char		*buffer, **names;
	ns_ldap_result_t	*result = be->result;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);
	buflen = argp->buf.buflen;
	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, buflen)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_bp2str;
		}
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;

	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	names = __ns_ldap_getAttr(result->entry, _B_HOSTNAME);
	if (names == NULL || names[0] == NULL ||
			(strlen(names[0]) < 1)) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_bp2str;
	}
	bparams = __ns_ldap_getAttrStruct(result->entry, _B_PARAMETER);
	if (bparams == NULL || bparams->attrvalue == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_bp2str;
	}
	firsttime = 1;
	for (i = 0; i < bparams->value_count; i++) {
		if (bparams->attrvalue[i] == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_bp2str;
		}
		/*
		 * Skip client host name. The early version of ldapaddent
		 * adds hostname as a boot param and it should be filtered.
		 */
		if (strcasecmp(names[0], bparams->attrvalue[i]) != 0) {
			if (firsttime) {
				firsttime = 0;
				len = snprintf(buffer, buflen, "%s",
					bparams->attrvalue[i]);
			} else
				len = snprintf(buffer, buflen, " %s",
					bparams->attrvalue[i]);
			TEST_AND_ADJUST(len, buffer, buflen, result_bp2str);
		}
	}
	/* The front end marshaller doesn't need to copy trailing nulls */
	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);

result_bp2str:

	(void) __ns_ldap_freeResult(&be->result);
	return (nss_result);
}

/*
 * getbyname gets bootparameters by host name. This function constructs an
 * ldap search filter using the host name invocation parameter and the
 * getbootparambyname search filter defined. Once the filter is
 * constructed, we search for matching entries and marshal the data
 * results into argp->buf.buffer for the frontend process. The function
 * _nss_ldap_bootparams2ent performs the data marshaling.
 *
 * RFC 2307, An Approach for Using LDAP as a Network Information Service,
 * indicates that dn's be fully qualified. Host name searches will be on
 * fully qualified host names (e.g., foo.bar.sun.com).
 */

static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	char		hostname[3 * MAXHOSTNAMELEN];
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		ret;

	if (_ldap_filter_name(hostname, argp->key.name, sizeof (hostname)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETBOOTPARAMBYNAME, hostname);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETBOOTPARAMBYNAME_SSD, hostname);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);
	return ((nss_status_t)_nss_ldap_lookup(be, argp,
		_BOOTPARAMS, searchfilter, NULL,
		_merge_SSD_filter, userdata));
}


static ldap_backend_op_t bootparams_ops[] = {
	_nss_ldap_destr,
	getbyname
};


/*
 * _nss_ldap_bootparams_constr is where life begins. This function calls
 * the generic ldap constructor function to define and build the abstract
 * data types required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_bootparams_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(bootparams_ops,
		sizeof (bootparams_ops)/sizeof (bootparams_ops[0]),
		_BOOTPARAMS, bootparams_attrs, _nss_ldap_bootparams2str));
}
