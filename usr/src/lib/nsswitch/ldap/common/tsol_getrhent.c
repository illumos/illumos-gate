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

#include <netdb.h>
#include "ldap_common.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/tsol/tndb.h>

/* tnrhdb attributes filters */
#define	_TNRHDB_ADDR		"ipTnetNumber"
#define	_TNRHDB_TNAME		"ipTnetTemplateName"
#define	_F_GETTNDBBYADDR	"(&(objectClass=ipTnetHost)(ipTnetNumber=%s))"
#define	_F_GETTNDBBYADDR_SSD	"(&(%%s)(ipTnetNumber=%s))"

static const char *tnrhdb_attrs[] = {
	_TNRHDB_ADDR,
	_TNRHDB_TNAME,
	NULL
};

static void
escape_colon(char *in, char *out) {
	int i, j;
	for (i = 0, j = 0; in[i] != '\0'; i++) {
		if (in[i] == ':') {
			out[j++] = '\\';
			out[j++] = in[i];
		} else
			out[j++] = in[i];
	}
	out[j] = '\0';
}

/*
 * _nss_ldap_tnrhdb2str is the data marshaling method for the tnrhdb
 * (tsol_getrhbyaddr()/tsol_getrhent()) backend processes.
 * This method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into the file format.
 *
 * e.g.
 *
 * 192.168.120.6:public
 * fec0\:\:a00\:20ff\:fea0\:21f7:cipso
 *
 */
static int
_nss_ldap_tnrhdb2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			nss_result = NSS_STR_PARSE_SUCCESS;
	int			len = 0;
	char			*buffer = NULL;
	char			**addr, **template, *addr_out;
	ns_ldap_result_t	*result = be->result;
	char addr6[INET6_ADDRSTRLEN + 5]; /* 5 '\' for ':' at most */

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);

	addr = __ns_ldap_getAttr(result->entry, _TNRHDB_ADDR);
	if (addr == NULL || addr[0] == NULL || (strlen(addr[0]) < 1)) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_tnrhdb2str;
	}

	/*
	 * Escape ':' in IPV6.
	 * The value is stored in LDAP directory without escape charaters.
	 */
	if (strchr(addr[0], ':') != NULL) {
		escape_colon(addr[0], addr6);
		addr_out = addr6;
	} else
		addr_out = addr[0];

	template = __ns_ldap_getAttr(result->entry, _TNRHDB_TNAME);
	if (template == NULL || template[0] == NULL ||
			(strlen(template[0]) < 1)) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_tnrhdb2str;
	}
	/* "addr:template" */
	len = strlen(addr_out) + strlen(template[0]) + 2;

	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, len)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_tnrhdb2str;
		}
		be->buflen = len - 1;
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;

	(void) snprintf(buffer, len, "%s:%s", addr_out, template[0]);

result_tnrhdb2str:
	(void) __ns_ldap_freeResult(&be->result);
	return (nss_result);
}


static nss_status_t
getbyaddr(ldap_backend_ptr be, void *a)
{
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;

	if (argp->key.hostaddr.addr == NULL ||
		(argp->key.hostaddr.type != AF_INET &&
		argp->key.hostaddr.type != AF_INET6))
			return (NSS_NOTFOUND);
	if (strchr(argp->key.hostaddr.addr, ':') != NULL) {
		/* IPV6 */
		if (argp->key.hostaddr.type == AF_INET)
			return (NSS_NOTFOUND);
	} else {
		/* IPV4 */
		if (argp->key.hostaddr.type == AF_INET6)
			return (NSS_NOTFOUND);
	}

	/*
	 * The IPV6 addresses are saved in the directory without '\'s.
	 * So don't need to escape colons in IPV6 addresses.
	 */
	if (snprintf(searchfilter, sizeof (searchfilter), _F_GETTNDBBYADDR,
	    argp->key.hostaddr.addr) < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	if (snprintf(userdata, sizeof (userdata), _F_GETTNDBBYADDR_SSD,
	    argp->key.hostaddr.addr) < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return (_nss_ldap_lookup(be, argp, _TNRHDB, searchfilter, NULL,
	    _merge_SSD_filter, userdata));
}


static ldap_backend_op_t tnrhdb_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
	getbyaddr
};


/* ARGSUSED */
nss_backend_t *
_nss_ldap_tnrhdb_constr(const char *dummy1,
    const char *dummy2,
    const char *dummy3,
    const char *dummy4,
    const char *dummy5)
{
	return ((nss_backend_t *)_nss_ldap_constr(tnrhdb_ops,
		sizeof (tnrhdb_ops)/sizeof (tnrhdb_ops[0]), _TNRHDB,
		tnrhdb_attrs, _nss_ldap_tnrhdb2str));
}
