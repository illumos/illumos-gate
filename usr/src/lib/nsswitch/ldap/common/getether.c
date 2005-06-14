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

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include "ldap_common.h"

/* ether attributes filters */
#define	_E_HOSTNAME		"cn"
#define	_E_MACADDRESS		"macaddress"
#define	_F_GETETHERBYHOST	"(&(objectClass=ieee802Device)(cn=%s))"
#define	_F_GETETHERBYHOST_SSD	"(&(%%s)(cn=%s))"
#define	_F_GETETHERBYETHER	"(&(objectClass=ieee802Device)(macAddress=%s))"
#define	_F_GETETHERBYETHER_SSD	"(&(%%s)(macAddress=%s))"

static const char *ethers_attrs[] = {
	_E_HOSTNAME,
	_E_MACADDRESS,
	(char *)NULL
};


/*
 * _nss_ldap_ethers2ent is the data marshaling method for the ethers
 * getXbyY * (e.g., getbyhost(), getbyether()) backend processes. This
 * method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into uchar_t *ether
 * = argp->buf.buffer which the frontend process expects. Three error
 * conditions are expected and returned to nsswitch.
 *
 * Place the resulting struct ether_addr from the ldap query into
 * argp->buf.result only if argp->buf.result is initialized (not NULL).
 * e.g., it happens for the call ether_hostton.
 *
 * Place the resulting hostname into argp->buf.buffer only if
 * argp->buf.buffer is initialized. I.e. it happens for the call
 * ether_ntohost.
 *
 * argp->buf.buflen does not make sense for ethers. It is always set
 * to 0 by the frontend. The caller only passes a hostname pointer in
 * case of ether_ntohost, that is assumed to be big enough. For
 * ether_hostton, the struct ether_addr passed is a fixed size.
 *
 * The interface does not let the caller specify how long is the buffer
 * pointed by host. We make a safe assumption that the callers will
 * always give MAXHOSTNAMELEN. In any case, it is the only finite number
 * we can lay our hands on in case of runaway strings, memory corruption etc.
 */

static int
_nss_ldap_ethers2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			i, ip;
	int			nss_result;
	int			buflen = (int)0;
	unsigned int		t[ETHERADDRL];
	unsigned long		len = 0L;
	char			*host = NULL;
	struct ether_addr	*ether = NULL;
	ns_ldap_result_t	*result = be->result;
	ns_ldap_attr_t	*attrptr;
	int etherflag = 0, hostflag = 0;

	if (argp->buf.buffer) {
		hostflag = 1;
		host = argp->buf.buffer;
	}

	buflen = (size_t)argp->buf.buflen;

	if (argp->buf.result) {
		etherflag = 1;
		ether = (struct ether_addr *)argp->buf.result;
	}

	nss_result = (int)NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	attrptr = getattr(result, 0);
	if (attrptr == NULL) {
		nss_result = (int)NSS_STR_PARSE_PARSE;
		goto result_ea2ent;
	}

	for (i = 0; i < result->entry->attr_count; i++) {
		attrptr = getattr(result, i);
		if (attrptr == NULL) {
			nss_result = (int)NSS_STR_PARSE_PARSE;
			goto result_ea2ent;
		}
		if (hostflag) {
			if (strcasecmp(attrptr->attrname, _E_HOSTNAME) == 0) {
				if ((attrptr->attrvalue[0] == NULL) ||
				    (len = strlen(attrptr->attrvalue[0])) < 1) {
					nss_result = (int)NSS_STR_PARSE_PARSE;
					goto result_ea2ent;
				}
				if (len > MAXHOSTNAMELEN) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_ea2ent;
				}
				(void) strcpy(host, attrptr->attrvalue[0]);
				continue;
			}
		}
		if (etherflag) {
			if (strcasecmp(attrptr->attrname, _E_MACADDRESS) == 0) {
				if ((attrptr->attrvalue[0] == NULL) ||
				    (len = strlen(attrptr->attrvalue[0])) < 1) {
					nss_result = (int)NSS_STR_PARSE_PARSE;
					goto result_ea2ent;
				}
				ip = (int)sscanf(attrptr->attrvalue[0],
					"%x:%x:%x:%x:%x:%x", &t[0], &t[1],
					&t[2], &t[3], &t[4], &t[5]);
				if (ip != ETHERADDRL) {
					nss_result = (int)NSS_STR_PARSE_PARSE;
					goto result_ea2ent;
				}
				for (ip = 0; ip < ETHERADDRL; ip++)
					ether->ether_addr_octet[ip] =
						(uchar_t)t[ip];
				continue;
			}
		}
	}

#ifdef DEBUG
	(void) fprintf(stdout, "\n[ether_addr.c: _nss_ldap_ethers2ent]\n");
	if (host != NULL)
		(void) fprintf(stdout, "      hostname: [%s]\n", host);
	if (ether != NULL)
		(void) fprintf(stdout,
		    "    ether_addr: [%x:%x:%x:%x:%x:%x]\n",
		    ether->ether_addr_octet[0],
		    ether->ether_addr_octet[1],
		    ether->ether_addr_octet[2],
		    ether->ether_addr_octet[3],
		    ether->ether_addr_octet[4],
		    ether->ether_addr_octet[5]);
#endif /* DEBUG */

result_ea2ent:

	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
}

/*
 * getbyhost gets an ethernet address by hostname. This function
 * constructs an ldap search filter using the hostname invocation
 * parameter and the getetherbyhost search filter defined. Once
 * the filter is constructed, we search for a matching entry and
 * marshal the data results into uchar_t *ether for the frontend
 * process. The function _nss_ldap_ethers2ent performs the data
 * marshaling.
 *
 * RFC 2307, An Approach for Using LDAP as a Network Information Service,
 * indicates that dn's be fully qualified. Host name searches will be on
 * fully qualified host names (e.g., foo.bar.sun.com).
 */

static nss_status_t
getbyhost(ldap_backend_ptr be, void *a)
{
	char		hostname[3 * MAXHOSTNAMELEN];
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		ret;

	if (_ldap_filter_name(hostname, argp->key.name, sizeof (hostname)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETETHERBYHOST, hostname);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETETHERBYHOST_SSD, hostname);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
		_ETHERS, searchfilter, NULL,
		_merge_SSD_filter, userdata));
}


/*
 * getbyether gets an ethernet address by ethernet address. This
 * function constructs an ldap search filter using the ASCII
 * ethernet address invocation parameter and the getetherbyether
 * search filter defined. Once the filter is constructed, we
 * search for a matching entry and  marshal the data results into
 * uchar_t *ether for the frontend process. The function
 * _nss_ldap_ethers2ent performs the data marshaling.
 */

static nss_status_t
getbyether(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		etherstr[18];
	uchar_t	*e = argp->key.ether;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		ret;

	ret = snprintf(etherstr, sizeof (etherstr), "%x:%x:%x:%x:%x:%x",
	    *e, *(e + 1), *(e + 2), *(e + 3), *(e + 4), *(e + 5));
	if (ret >= sizeof (etherstr) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETETHERBYETHER, etherstr);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETETHERBYETHER_SSD, etherstr);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
		_ETHERS, searchfilter, NULL,
		_merge_SSD_filter, userdata));
}


static ldap_backend_op_t ethers_ops[] = {
	_nss_ldap_destr,
	getbyhost,
	getbyether
};


/*
 * _nss_ldap_ethers_constr is where life begins. This function calls the
 * generic ldap constructor function to define and build the abstract
 * data types required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_ethers_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(ethers_ops,
		sizeof (ethers_ops)/sizeof (ethers_ops[0]), _ETHERS,
		ethers_attrs, _nss_ldap_ethers2ent));
}
