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

typedef struct protocol_alias {
	char	*protocol;
	char	*alias;
} protocol_alias_t;

static const protocol_alias_t ip_aliases[10] = {
	{ "ip", "IP" },
	{ "ipip", "IP-IP" },
	{ "ipcomp", "IPComp" },
	{ "ipv6", "IPv6" },
	{ "ipv6-route", "IPv6-Route" },
	{ "ipv6-frag", "IPv6-Frag" },
	{ "ipv6-icmp", "IPv6-ICMP" },
	{ "ipv6-nonxt", "IPv6-NoNxt" },
	{ "ipv6-opts", "IPv6-Opts" },
	{ NULL, NULL }
};

/*
 * When the data is imported by ldapaddent, it does not save the aliase in the
 * "cn" that is same as the canonical name but only different in case.
 * e.g.
 * icmp		1	ICMP
 *
 * is saved as
 *
 * dn: cn=icmp, ...
 * ...
 * cn: icmp
 * ...
 *
 * So it needs to replicate the canonical name as an alias of upper case.
 * But some protocol does have different aliases.
 *
 * e.g.
 * dn: cn=ospf, ...
 * ...
 * cn: ospf
 * cn: OSPFIGP
 * ...
 *
 * For many ip* protocols, the aliases are mixed cased. Maybe it's case
 * insensitive. But this fucntion tries to restore the aliases to the original
 * form as much as possible. If the alias can't be found in the aliases table,
 * it assumes the alias is all upper case.
 *
 */
static char *
get_alias(char *protocol) {
	int	i;
	char	*cp;

	if (strncmp(protocol, "ip", 2) == 0) {
		for (i = 0; ip_aliases[i].protocol != NULL; i++) {
			if (strcmp(protocol, ip_aliases[i].protocol) == 0)
				return (ip_aliases[i].alias);
		}
		/*
		 * No aliase in the table. Return an all upper case aliase
		 */
		for (cp = protocol; *cp; cp++)
			*cp = toupper(*cp);

		return (protocol);
	} else {
		/* Return an all upper case aliase */
		for (cp = protocol; *cp; cp++)
			*cp = toupper(*cp);

		return (protocol);
	}

}
/*
 * _nss_ldap_protocols2str is the data marshaling method for the protocols
 * getXbyY * (e.g., getbyname(), getbynumber(), getent()) backend processes.
 * This method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into a file format.
 * e.g.
 * idrp 45 IDRP
 * or
 * ospf 89 OSPFIGP
 */

static int
_nss_ldap_protocols2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	uint_t		i;
	int		nss_result;
	int		buflen = 0, len;
	char		*cname = NULL;
	char		*buffer = NULL, **number, *alias;
	ns_ldap_result_t	*result = be->result;
	ns_ldap_attr_t	*names;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);

	buflen = argp->buf.buflen;
	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, buflen)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_pls2str;
		}
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;

	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	names = __ns_ldap_getAttrStruct(result->entry, _P_NAME);
	if (names == NULL || names->attrvalue == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_pls2str;
	}
	/* Get the canonical name */
	cname = __s_api_get_canonical_name(result->entry, names, 1);
	if (cname == NULL || (len = strlen(cname)) < 1) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_pls2str;
	}
	number = __ns_ldap_getAttr(result->entry, _P_PROTO);
	if (number == NULL || number[0] == NULL ||
			(len = strlen(number[0])) < 1) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_pls2str;
	}
	len = snprintf(buffer, buflen,  "%s %s", cname, number[0]);
	TEST_AND_ADJUST(len, buffer, buflen, result_pls2str);
	/* Append aliases */
	if (names->value_count == 1) {
		/* create an aliase from protocol name */
		alias = get_alias(cname);
		len = snprintf(buffer, buflen,  " %s", alias);
		TEST_AND_ADJUST(len, buffer, buflen, result_pls2str);

	} else {
		for (i = 0; i < names->value_count; i++) {
			if (names->attrvalue[i] == NULL) {
				nss_result = NSS_STR_PARSE_PARSE;
				goto result_pls2str;
			}
			/* Skip the canonical name */
			if (strcasecmp(names->attrvalue[i], cname) != 0) {
				len = snprintf(buffer, buflen,  " %s",
						names->attrvalue[i]);
				TEST_AND_ADJUST(len, buffer, buflen,
						result_pls2str);
			}
		}
	}

	/* The front end marshaller doesn't need to copy trailing nulls */
	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);

result_pls2str:

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
		protocols_attrs, _nss_ldap_protocols2str));
}
