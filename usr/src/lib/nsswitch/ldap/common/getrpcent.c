/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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
 * _nss_ldap_rpc2ent is the data marshaling method for the rpc getXbyY
 * (e.g., getbyname(), getbynumber(), getrpcent()) backend processes.
 * This method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into *rpc = (struct
 * rpcent *)argp->buf.result which the frontend process expects. Three
 * error conditions are expected and returned to nsswitch.
 */

static int
_nss_ldap_rpc2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int		i, j;
	int		nss_result;
	int		buflen = (int)0;
	int		firstime = (int)1;
	unsigned long	len = 0L;
	char		**mp, *cname = NULL;
	char		*buffer = (char *)NULL;
	char		*ceiling = (char *)NULL;
	struct rpcent	*rpc = (struct rpcent *)NULL;
	ns_ldap_result_t	*result = be->result;
	ns_ldap_attr_t	*attrptr;

	buffer = (char *)argp->buf.buffer;
	buflen = (size_t)argp->buf.buflen;
	if (!argp->buf.result) {
		nss_result = (int)NSS_STR_PARSE_ERANGE;
		goto result_rpc2ent;
	}
	rpc = (struct rpcent *)argp->buf.result;
	ceiling = buffer + buflen;

	nss_result = (int)NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	attrptr = getattr(result, 0);
	if (attrptr == NULL) {
		nss_result = (int)NSS_STR_PARSE_PARSE;
		goto result_rpc2ent;
	}
	for (i = 0; i < result->entry->attr_count; i++) {
		attrptr = getattr(result, i);
		if (attrptr == NULL) {
			nss_result = (int)NSS_STR_PARSE_PARSE;
			goto result_rpc2ent;
		}
		if (strcasecmp(attrptr->attrname, _R_NAME) == 0) {
			for (j = 0; j < attrptr->value_count; j++) {
			/* traverse for all multivalued values */
				if (firstime) {
					/* rpc name */
					cname = __s_api_get_canonical_name(
						result->entry, attrptr, 1);
					if (cname == NULL ||
						(len = strlen(cname)) < 1) {
						nss_result =
							NSS_STR_PARSE_PARSE;
						goto result_rpc2ent;
					}
					rpc->r_name = buffer;
					buffer += len + 1;
					if (buffer >= ceiling) {
						nss_result =
						    (int)NSS_STR_PARSE_ERANGE;
						goto result_rpc2ent;
					}
					(void) strcpy(rpc->r_name, cname);
					/* alias list */
					mp = rpc->r_aliases =
						    (char **)ROUND_UP(buffer,
						    sizeof (char **));
					buffer = (char *)rpc->r_aliases +
						    sizeof (char *) *
						    (attrptr->value_count + 1);
					buffer = (char *)ROUND_UP(buffer,
						    sizeof (char **));
					if (buffer >= ceiling) {
						nss_result =
						    (int)NSS_STR_PARSE_ERANGE;
						goto result_rpc2ent;
					}
					firstime = (int)0;
				}
				/* alias list */
				if ((attrptr->attrvalue[j] == NULL) ||
				    (len = strlen(attrptr->attrvalue[j])) < 1) {
					nss_result = (int)NSS_STR_PARSE_PARSE;
					goto result_rpc2ent;
				}
				/* skip canonical name */
				if (strcmp(attrptr->attrvalue[j], cname) == 0)
					continue;
				*mp = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_rpc2ent;
				}
				(void) strcpy(*mp++, attrptr->attrvalue[j]);
				continue;
			}
		}
		if (strcasecmp(attrptr->attrname, _R_NUMBER) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_rpc2ent;
			}
			errno = 0;
			rpc->r_number = (int)strtol(attrptr->attrvalue[0],
						    (char **)NULL, 10);
			if (errno != 0) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_rpc2ent;
			}
			continue;
		}
	}
	if (mp != NULL)
		*mp = NULL;

#ifdef DEBUG
	(void) fprintf(stdout, "\n[getrpcent.c: _nss_ldap_rpc2ent]\n");
	(void) fprintf(stdout, "        r_name: [%s]\n", rpc->r_name);
	if (mp != NULL) {
		for (mp = rpc->r_aliases; *mp != NULL; mp++)
			(void) fprintf(stdout, "     r_aliases: [%s]\n", *mp);
	}
	(void) fprintf(stdout, "      r_number: [%d]\n", rpc->r_number);
#endif /* DEBUG */

result_rpc2ent:

	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
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
		_RPC, rpc_attrs, _nss_ldap_rpc2ent));
}
