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

#include <rpc/rpcent.h>
#include "ns_internal.h"
#include "ldap_common.h"

/* rpc attributes filters */
#define	_R_NAME			"cn"
#define	_R_NUMBER		"oncrpcnumber"


#define	_F_GETRPCBYNAME		"(&(objectClass=oncRpc)(cn=%s))"
#define	_F_GETRPCBYNAME_SSD	"(&(%%s)(cn=%s))"
#define	_F_GETRPCBYNUMBER	"(&(objectClass=oncRpc)(oncRpcNumber=%d))"
#define	_F_GETRPCBYNUMBER_SSD	"(&(%%s)(oncRpcNumber=%d))"

static const char *rpc_attrs[] = {
	_R_NAME,
	_R_NUMBER,
	(char *)NULL
};

/*
 * _nss_ldap_rpc2str is the data marshaling method for the rpc getXbyY
 * (e.g., getbyname(), getbynumber(), getrpcent()) backend processes.
 * This method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into the file format.
 * e.g.
 *
 * nfs_acl 100227
 * snmp 100122  na.snmp snmp-cmc snmp-synoptics snmp-unisys snmp-utk
 */
static int
_nss_ldap_rpc2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	uint_t		i;
	int		nss_result;
	int		buflen = 0, len;
	char		*cname = NULL;
	char		*buffer = NULL;
	ns_ldap_result_t	*result = be->result;
	ns_ldap_attr_t	*names;
	char		**rpcnumber;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);
	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	buflen = argp->buf.buflen;
	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, buflen)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_rpc2str;
		}
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;


	names = __ns_ldap_getAttrStruct(result->entry, _R_NAME);
	if (names == NULL || names->attrvalue == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_rpc2str;
	}
	/* Get the canonical rpc name */
	cname = __s_api_get_canonical_name(result->entry, names, 1);
	if (cname == NULL || (len = strlen(cname)) < 1) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_rpc2str;
	}
	rpcnumber = __ns_ldap_getAttr(result->entry, _R_NUMBER);
	if (rpcnumber == NULL || rpcnumber[0] == NULL ||
			(len = strlen(rpcnumber[0])) < 1) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_rpc2str;
	}
	len = snprintf(buffer, buflen,  "%s %s", cname, rpcnumber[0]);
	TEST_AND_ADJUST(len, buffer, buflen, result_rpc2str);
	/* Append aliases */
	for (i = 0; i < names->value_count; i++) {
		if (names->attrvalue[i] == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_rpc2str;
		}
		/* Skip the canonical name */
		if (strcasecmp(names->attrvalue[i], cname) != 0) {
			len = snprintf(buffer, buflen,  " %s",
					names->attrvalue[i]);
			TEST_AND_ADJUST(len, buffer, buflen, result_rpc2str);
		}
	}

	/* The front end marshaller doesn't need to copy trailing nulls */
	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);

result_rpc2str:

	(void) __ns_ldap_freeResult(&be->result);
	return (nss_result);
}

/*
 * getbyname gets struct rpcent values by rpc name. This function
 * constructs an ldap search filter using the rpc name invocation
 * parameter and the getrpcbyname search filter defined. Once the
 * filter is constructed, we search for a matching entry and marshal
 * the data results into *rpc = (struct rpcent *)argp->buf.result.
 * The function _nss_ldap_rpc2ent performs the data marshaling.
 */

static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	char		name[SEARCHFILTERLEN];
	int		ret;

	if (_ldap_filter_name(name, argp->key.name, sizeof (name)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter), _F_GETRPCBYNAME,
	    name);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata), _F_GETRPCBYNAME_SSD, name);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp, _RPC, searchfilter,
		NULL, _merge_SSD_filter, userdata));
}


/*
 * getbynumber gets struct rpcent values by rpc number. This function
 * constructs an ldap search filter using the rpc number invocation
 * parameter and the getrpcbynumber search filter defined. Once the
 * filter is constructed, we search for a matching entry and marshal
 * the data results into *rpc = (struct rpcent *)argp->buf.result.
 * The function _nss_ldap_rpc2ent performs the data marshaling.
 */

static nss_status_t
getbynumber(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		ret;

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETRPCBYNUMBER, argp->key.number);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETRPCBYNUMBER_SSD, argp->key.number);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp, _RPC, searchfilter,
		NULL, _merge_SSD_filter, userdata));
}


static ldap_backend_op_t rpc_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
	getbyname,
	getbynumber
};


/*
 * _nss_ldap_rpc_constr is where life begins. This function calls the generic
 * ldap constructor function to define and build the abstract data types
 * required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_rpc_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(rpc_ops,
		sizeof (rpc_ops)/sizeof (rpc_ops[0]),
		_RPC, rpc_attrs, _nss_ldap_rpc2str));
}
