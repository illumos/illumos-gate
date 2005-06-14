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

#include <ctype.h>
#include <netdb.h>
#include "ns_internal.h"
#include "ldap_common.h"

/* protocols attributes filters */
#define	_P_NAME			"cn"
#define	_P_PROTO		"ipprotocolnumber"
#define	_F_GETPROTOBYNAME	"(&(objectClass=ipProtocol)(cn=%s))"
#define	_F_GETPROTOBYNAME_SSD	"(&(%%s)(cn=%s))"
#define	_F_GETPROTOBYNUMBER	\
	"(&(objectClass=ipProtocol)(ipProtocolNumber=%d))"
#define	_F_GETPROTOBYNUMBER_SSD	\
	"(&(%%s)(ipProtocolNumber=%d))"

static const char *protocols_attrs[] = {
	_P_NAME,
	_P_PROTO,
	(char *)NULL
};


/*
 * _nss_ldap_protocols2ent is the data marshaling method for the protocols
 * getXbyY * (e.g., getbyname(), getbynumber(), getent()) backend processes.
 * This method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into *proto = (struct
 * protoent *)argp->buf.result which the frontend process expects. Three error
 * conditions are expected and returned to nsswitch.
 */

static int
_nss_ldap_protocols2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int		i, j;
	int		nss_result;
	int		buflen = (int)0;
	int		firstime = (int)1;
	unsigned long	len = 0L;
	char		*cp, **mp, *cname = NULL;
	char		*buffer = (char *)NULL;
	char		*ceiling = (char *)NULL;
	struct protoent	*proto = (struct protoent *)NULL;
	ns_ldap_result_t	*result = be->result;
	ns_ldap_attr_t	*attrptr;

	buffer = (char *)argp->buf.buffer;
	buflen = (size_t)argp->buf.buflen;
	if (!argp->buf.result) {
		nss_result = (int)NSS_STR_PARSE_ERANGE;
		goto result_pls2ent;
	}
	proto = (struct protoent *)argp->buf.result;
	ceiling = buffer + buflen;

	nss_result = (int)NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	attrptr = getattr(result, 0);
	if (attrptr == NULL) {
		nss_result = (int)NSS_STR_PARSE_PARSE;
		goto result_pls2ent;
	}
	for (i = 0; i < result->entry->attr_count; i++) {
		attrptr = getattr(result, i);
		if (attrptr == NULL) {
			nss_result = (int)NSS_STR_PARSE_PARSE;
			goto result_pls2ent;
		}
		if (strcasecmp(attrptr->attrname, _P_NAME) == 0) {
			for (j = 0; j < attrptr->value_count; j++) {
				if (firstime) {
					/* protocol name */
					cname = __s_api_get_canonical_name(
						result->entry, attrptr, 1);
					if (cname == NULL ||
						(len = strlen(cname)) < 1) {
						nss_result =
							NSS_STR_PARSE_PARSE;
						goto result_pls2ent;
					}
					proto->p_name = buffer;
					buffer += len + 1;
					if (buffer >= ceiling) {
						nss_result =
						    (int)NSS_STR_PARSE_ERANGE;
						goto result_pls2ent;
					}
					(void) strcpy(proto->p_name, cname);
					mp = proto->p_aliases =
						(char **)ROUND_UP(buffer,
						sizeof (char **));
					buffer = (char *)proto->p_aliases +
						sizeof (char *) *
						(attrptr->value_count + 1);
					buffer = (char *)ROUND_UP(buffer,
						sizeof (char **));
					if (buffer >= ceiling) {
						nss_result =
						    (int)NSS_STR_PARSE_ERANGE;
						goto result_pls2ent;
					}
					firstime = (int)0;
				}
				/* alias list */
				if ((attrptr->attrvalue[j] == NULL) ||
				    (len = strlen(attrptr->attrvalue[j])) < 1) {
					nss_result = NSS_STR_PARSE_PARSE;
					goto result_pls2ent;
				}
				/*
				 * When the data is imported by ldapaddent,
				 * it does not save the aliase in the "cn"
				 * that is same as the canonical name but only
				 * differnt in case.
				 * e.g.
				 * icmp		1	ICMP
				 *
				 * is saved as
				 *
				 * dn: cn=icmp, ...
				 * ...
				 * cn: icmp
				 * ...
				 * So it needs to replicate the canonical name
				 * as an aliase of upper case.
				 *
				 * But in the case of
				 * ospf		89 OSPFIGP
				 * it creates a redundant aliase.
				 * e.g.
				 * dn: cn=icmp, ...
				 * ...
				 * cn: ospf
				 * cn: OSPFIGP
				 * ...
				 *
				 * getent services ospf
				 * ==> ospf	89 ospf OSPFIGP
				 *
				 * Some condition check is added to handle this
				 * scenario. Such check also works with
				 * following scenario.
				 * dn: cn=icmp, ...
				 * ...
				 * cn: icmp
				 * cn: ICMP
				 * ...
				 */
				if (strcmp(proto->p_name,
				    attrptr->attrvalue[j]) == 0) {
					if (attrptr->value_count > 1)
						/* Do not replicate */
						continue;
					for (cp = attrptr->attrvalue[j];
					    *cp; cp++)
						*cp = toupper(*cp);
				}
				*mp = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_pls2ent;
				}
				(void) strcpy(*mp++, attrptr->attrvalue[j]);
				continue;
			}
		}
		if (strcasecmp(attrptr->attrname, _P_PROTO) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_pls2ent;
			}
			errno = 0;
			proto->p_proto = (int)strtol(attrptr->attrvalue[0],
					    (char **)NULL, 10);
			if (errno != 0) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_pls2ent;
			}
			continue;
		}
	}

#ifdef DEBUG
	(void) fprintf(stdout, "\n[getprotoent.c: _nss_ldap_protocols2ent]\n");
	(void) fprintf(stdout, "        p_name: [%s]\n", proto->p_name);
	if (mp != NULL) {
		for (mp = proto->p_aliases; *mp != NULL; mp++)
			(void) fprintf(stdout, "     p_aliases: [%s]\n", *mp);
	}
	(void) fprintf(stdout, "       p_proto: [%d]\n", proto->p_proto);
#endif /* DEBUG */

result_pls2ent:

	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
}


/*
 * getbyname gets struct protoent values by protocol name. This
 * function constructs an ldap search filter using the protocol
 * name invocation parameter and the getprotobyname search filter
 * defined. Once the filter is constructed, we search for a matching
 * entry and marshal the data results into *proto = (struct *
 * protoent *)argp->buf.result. The function _nss_ldap_protocols2ent
 * performs the data marshaling.
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

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETPROTOBYNAME, name);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETPROTOBYNAME_SSD, name);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
		_PROTOCOLS, searchfilter, NULL,
		_merge_SSD_filter, userdata));
}


/*
 * getbynumber gets struct protoent values by protocol number. This
 * function constructs an ldap search filter using the protocol
 * name invocation parameter and the getprotobynumber search filter
 * defined. Once the filter is constructed, we search for a matching
 * entry and marshal the data results into *proto = (struct *
 * protoent *)argp->buf.result. The function _nss_ldap_protocols2ent
 * performs the data marshaling.
 */

static nss_status_t
getbynumber(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		ret;

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETPROTOBYNUMBER, argp->key.number);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETPROTOBYNUMBER_SSD, argp->key.number);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
		_PROTOCOLS, searchfilter, NULL,
		_merge_SSD_filter, userdata));
}

static ldap_backend_op_t proto_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
	getbyname,
	getbynumber
};


/*
 * _nss_ldap_protocols_constr is where life begins. This function calls
 * the generic ldap constructor function to define and build the abstract
 * data types required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_protocols_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(proto_ops,
		sizeof (proto_ops)/sizeof (proto_ops[0]), _PROTOCOLS,
		protocols_attrs, _nss_ldap_protocols2ent));
}
