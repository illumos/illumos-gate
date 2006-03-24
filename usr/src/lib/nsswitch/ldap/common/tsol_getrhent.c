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

static int
_nss_ldap_tnrhdb2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			i, nss_result;
	int			len = 0;
	int			buflen = 0;
	char			*buffer = NULL;
	char			*ceiling = NULL;
	ns_ldap_attr_t		*attrptr;
	ns_ldap_result_t	*result = be->result;
	tsol_rhstr_t		*rhstrp;

	buffer = argp->buf.buffer;
	buflen = argp->buf.buflen;
	if (argp->buf.result == NULL) {
		nss_result = NSS_STR_PARSE_ERANGE;
		goto result_tnrhdb2ent;
	}
	rhstrp = (tsol_rhstr_t *)(argp->buf.result);
	rhstrp->family = 0;
	rhstrp->address = rhstrp->template = NULL;
	ceiling = buffer + buflen;
	(void) memset(argp->buf.buffer, 0, buflen);
	attrptr = getattr(result, 0);
	if (attrptr == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_tnrhdb2ent;
	}
	for (i = 0; i < result->entry->attr_count; i++) {
		attrptr = getattr(result, i);
		if (attrptr == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_tnrhdb2ent;
		}
		if (strcasecmp(attrptr->attrname, _TNRHDB_ADDR) == 0) {
			len = strlen(attrptr->attrvalue[0]);
			if (len < 1 || (attrptr->attrvalue[0] == '\0')) {
				nss_result = NSS_STR_PARSE_PARSE;
				goto result_tnrhdb2ent;
			}
			rhstrp->address = buffer;
			buffer += len + 1;
			if (buffer >= ceiling) {
				nss_result = (int)NSS_STR_PARSE_ERANGE;
				goto result_tnrhdb2ent;
			}
			(void) strcpy(rhstrp->address, attrptr->attrvalue[0]);
			continue;
		}
		if (strcasecmp(attrptr->attrname, _TNRHDB_TNAME) == 0) {
			len = strlen(attrptr->attrvalue[0]);
			if (len < 1 || (attrptr->attrvalue[0] == '\0')) {
				nss_result = NSS_STR_PARSE_PARSE;
				goto result_tnrhdb2ent;
			}
			rhstrp->template = buffer;
			buffer += len + 1;
			if (buffer >= ceiling) {
				nss_result = (int)NSS_STR_PARSE_ERANGE;
				goto result_tnrhdb2ent;
			}
			(void) strcpy(rhstrp->template, attrptr->attrvalue[0]);
			continue;
		}
	}
	nss_result = NSS_STR_PARSE_SUCCESS;

#ifdef	DEBUG
	(void) printf("\n[tsol_getrhent.c: _nss_ldap_tnrhdb2ent]\n");
	(void) printf("      address: [%s]\n",
	    rhstrp->address ? rhstrp->address : "NULL");
	(void) printf("template: [%s]\n",
	    rhstrp->template ? rhstrp->template : "NULL");
#endif	/* DEBUG */

result_tnrhdb2ent:
	(void) __ns_ldap_freeResult(&be->result);
	return (nss_result);
}


static nss_status_t
getbyaddr(ldap_backend_ptr be, void *a)
{
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	struct in_addr  addr;
	char 		buf[18];
	extern char	*inet_ntoa_r();

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[tsol_getrhent.c: getbyaddr]\n");
#endif	/* DEBUG */

	(void) memcpy(&addr, argp->key.hostaddr.addr, sizeof (addr));
	(void) inet_ntoa_r(addr, buf);

	if (snprintf(searchfilter, sizeof (searchfilter), _F_GETTNDBBYADDR,
	    buf) < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	if (snprintf(userdata, sizeof (userdata), _F_GETTNDBBYADDR_SSD,
	    buf) < 0)
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
#ifdef	DEBUG
	(void) fprintf(stdout,
	    "\n[tsol_getrhent.c: _nss_ldap_tnrhdb_constr]\n");
#endif
	return ((nss_backend_t *)_nss_ldap_constr(tnrhdb_ops,
		sizeof (tnrhdb_ops)/sizeof (tnrhdb_ops[0]), _TNRHDB,
		tnrhdb_attrs, _nss_ldap_tnrhdb2ent));
}
