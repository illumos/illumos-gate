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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * This file contains routines to read/write formatted entries from/to
 * libipadm data store /etc/ipadm/ipadm.conf. Each entry in the DB is a
 * series of IPADM_NVPAIR_SEP separated (name, value) pairs, as shown
 * below:
 *		name=value[;...]
 *
 * The 'name' determines how to interpret 'value'. The supported names are:
 *
 *  IPADM_NVP_IPV6ADDR - value holds local and remote IPv6 addresses and when
 *	       converted to nvlist, will contain nvpairs for local and remote
 *	       addresses. These nvpairs are of type DATA_TYPE_STRING
 *
 *  IPADM_NVP_IPV4ADDR - value holds local and remote IPv4 addresses and when
 *	       converted to nvlist, will contain nvpairs for local and remote
 *	       addresses. These nvpairs are of type DATA_TYPE_STRING
 *
 *  IPADM_NVP_INTFID - value holds token, prefixlen, stateless and stateful
 *	       info and when converted to nvlist, will contain following nvpairs
 *			interface_id: DATA_TYPE_UINT8_ARRAY
 *			prefixlen: DATA_TYPE_UINT32
 *			stateless: DATA_TYPE_STRING
 *			stateful: DATA_TYPE_STRING
 *
 *  IPADM_NVP_DHCP - value holds wait time and primary info and when converted
 *	       to nvlist, will contain following nvpairs
 *			wait:	DATA_TYPE_INT32
 *			primary: DATA_TYPE_BOOLEAN
 *
 *  IPADM_NVP_FAMILIES - value holds interface families and when converted
 *	       to nvlist, will be a DATA_TYPE_UINT16_ARRAY
 *
 *  IPADM_NVP_MIFNAMES - value holds IPMP group members and when converted
 *	       to nvlist, will be a DATA_TYPE_STRING_ARRAY
 *
 *  default  - value is a single entity and when converted to nvlist, will
 *	       contain nvpair of type DATA_TYPE_STRING. nvpairs private to
 *	       ipadm are of this type. Further the property name and property
 *	       values are stored as nvpairs of this type.
 *
 * The syntax for each line is described above the respective functions below.
 */

#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dld.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sockio.h>
#include "libipadm_impl.h"

#define	MAXLINELEN		1024
#define	IPADM_NVPAIR_SEP	";"
#define	IPADM_NAME_SEP		","

static char ipadm_rootdir[MAXPATHLEN] = "/";

static int ipadm_process_db_line(db_wfunc_t *, void *, FILE *fp, FILE *nfp,
    ipadm_db_op_t);

/*
 * convert nvpair to a "name=value" string for writing to the DB.
 */
typedef size_t ipadm_wfunc_t(nvpair_t *, char *, size_t);

/*
 * ipadm_rfunc_t takes (`name', `value') and adds the appropriately typed
 * nvpair to the nvlist.
 */
typedef ipadm_status_t ipadm_rfunc_t(nvlist_t *, char *, char *);

static ipadm_rfunc_t	i_ipadm_str_dbline2nvl, i_ipadm_ip4_dbline2nvl,
			i_ipadm_ip6_dbline2nvl, i_ipadm_intfid_dbline2nvl,
			i_ipadm_dhcp_dbline2nvl, i_ipadm_families_dbline2nvl,
			i_ipadm_groupmembers_dbline2nvl;

static ipadm_wfunc_t	i_ipadm_str_nvp2dbline, i_ipadm_ip4_nvp2dbline,
			i_ipadm_ip6_nvp2dbline, i_ipadm_intfid_nvp2dbline,
			i_ipadm_dhcp_nvp2dbline, i_ipadm_families_nvp2dbline,
			i_ipadm_groupmembers_nvp2dbline;

/*
 * table of function pointers to read/write formatted entries from/to
 * ipadm.conf.
 */
typedef struct ipadm_conf_ent_s {
	const char		*ipent_type_name;
	ipadm_wfunc_t		*ipent_wfunc;
	ipadm_rfunc_t		*ipent_rfunc;
} ipadm_conf_ent_t;

static ipadm_conf_ent_t ipadm_conf_ent[] = {
	{ IPADM_NVP_IPV6ADDR, i_ipadm_ip6_nvp2dbline, i_ipadm_ip6_dbline2nvl },
	{ IPADM_NVP_IPV4ADDR, i_ipadm_ip4_nvp2dbline, i_ipadm_ip4_dbline2nvl },
	{ IPADM_NVP_INTFID, i_ipadm_intfid_nvp2dbline,
	    i_ipadm_intfid_dbline2nvl },
	{ IPADM_NVP_DHCP, i_ipadm_dhcp_nvp2dbline, i_ipadm_dhcp_dbline2nvl },
	{ IPADM_NVP_FAMILIES, i_ipadm_families_nvp2dbline,
	    i_ipadm_families_dbline2nvl },
	{ IPADM_NVP_MIFNAMES, i_ipadm_groupmembers_nvp2dbline,
	    i_ipadm_groupmembers_dbline2nvl},
	{ NULL,	i_ipadm_str_nvp2dbline,	i_ipadm_str_dbline2nvl }
};

static ipadm_conf_ent_t *
i_ipadm_find_conf_type(const char *type)
{
	int	i;

	for (i = 0; ipadm_conf_ent[i].ipent_type_name != NULL; i++)
		if (strcmp(type, ipadm_conf_ent[i].ipent_type_name) == 0)
			break;
	return (&ipadm_conf_ent[i]);
}

/*
 * Extracts the hostnames IPADM_NVP_IPADDRHNAME and IPADM_NVP_IPDADDRHNAME from
 * the given nvlist `nvl' and adds the strings to `buf'.
 */
size_t
i_ipadm_ip_addhostname2dbline(nvlist_t *nvl, char *buf, size_t buflen)
{
	char	*cp;
	char	tmpbuf[IPADM_STRSIZE];

	/* Add the local hostname */
	if (nvlist_lookup_string(nvl, IPADM_NVP_IPADDRHNAME, &cp) != 0)
		return (0);
	(void) strlcat(buf, cp, buflen); /* local hostname */

	/* Add the dst hostname */
	if (nvlist_lookup_string(nvl, IPADM_NVP_IPDADDRHNAME, &cp) != 0) {
		/* no dst addr. just add a NULL character */
		(void) snprintf(tmpbuf, sizeof (tmpbuf), ",");
	} else {
		(void) snprintf(tmpbuf, sizeof (tmpbuf), ",%s", cp);
	}
	return (strlcat(buf, tmpbuf, buflen));
}

/*
 * Converts IPADM_NVP_IPV4ADDR nvpair to a string representation for writing to
 * the DB. The converted string format:
 *	ipv4addr=<local numeric IP string or hostname,remote numeric IP
 *          string or hostname>
 */
static size_t
i_ipadm_ip4_nvp2dbline(nvpair_t *nvp, char *buf, size_t buflen)
{
	nvlist_t	*v;
	int		nbytes;

	assert(nvpair_type(nvp) == DATA_TYPE_NVLIST &&
	    strcmp(nvpair_name(nvp), IPADM_NVP_IPV4ADDR) == 0);

	(void) snprintf(buf, buflen, "%s=", IPADM_NVP_IPV4ADDR);
	if (nvpair_value_nvlist(nvp, &v) != 0)
		goto fail;
	nbytes = i_ipadm_ip_addhostname2dbline(v, buf, buflen);
	if (nbytes != 0)
		return (nbytes);
fail:
	buf[0] = '\0';
	return (0);
}

/*
 * Converts IPADM_NVP_IPV6ADDR nvpair to a string representation for writing to
 * the DB. The converted string format:
 *	ipv6addr=<local numeric IP string or hostname,remote numeric IP
 *          string or hostname>
 */
static size_t
i_ipadm_ip6_nvp2dbline(nvpair_t *nvp, char *buf, size_t buflen)
{
	nvlist_t	*v;
	int		nbytes;

	assert(nvpair_type(nvp) == DATA_TYPE_NVLIST &&
	    strcmp(nvpair_name(nvp), IPADM_NVP_IPV6ADDR) == 0);

	(void) snprintf(buf, buflen, "%s=", IPADM_NVP_IPV6ADDR);
	if (nvpair_value_nvlist(nvp, &v) != 0)
		goto fail;
	nbytes = i_ipadm_ip_addhostname2dbline(v, buf, buflen);
	if (nbytes != 0)
		return (nbytes);
fail:
	buf[0] = '\0';
	return (0);
}

/*
 * Converts IPADM_NVP_INTFID nvpair to a string representation for writing to
 * the DB. The converted string format:
 *	IPADM_NVP_INTFID=<intfid/prefixlen>,{yes|no},{yes|no}
 */
static size_t
i_ipadm_intfid_nvp2dbline(nvpair_t *nvp, char *buf, size_t buflen)
{
	char		addrbuf[IPADM_STRSIZE];
	nvlist_t	*v;
	uint32_t	prefixlen;
	struct in6_addr	in6addr;
	char		*stateless;
	char		*stateful;

	assert(nvpair_type(nvp) == DATA_TYPE_NVLIST &&
	    strcmp(nvpair_name(nvp), IPADM_NVP_INTFID) == 0);

	(void) snprintf(buf, buflen, "%s=", IPADM_NVP_INTFID);
	if (nvpair_value_nvlist(nvp, &v) != 0)
		goto fail;
	if (i_ipadm_nvl2in6_addr(v, IPADM_NVP_IPNUMADDR, &in6addr) !=
	    IPADM_SUCCESS)
		goto fail;
	(void) inet_ntop(AF_INET6, &in6addr, addrbuf,
	    sizeof (addrbuf));
	(void) strlcat(buf, addrbuf, buflen);
	if (nvlist_lookup_uint32(v, IPADM_NVP_PREFIXLEN, &prefixlen) != 0 ||
	    nvlist_lookup_string(v, IPADM_NVP_STATELESS, &stateless) != 0 ||
	    nvlist_lookup_string(v, IPADM_NVP_STATEFUL, &stateful) != 0)
		goto fail;
	(void) snprintf(addrbuf, sizeof (addrbuf), "/%d,%s,%s",
	    prefixlen, stateless, stateful);
	return (strlcat(buf, addrbuf, buflen));
fail:
	buf[0] = '\0';
	return (0);
}

/*
 * Converts IPADM_NVP_DHCP nvpair to a string representation for writing to the
 * DB. The converted string format:
 *	IPADM_NVP_DHCP=<wait_time>,{yes|no}
 */
static size_t
i_ipadm_dhcp_nvp2dbline(nvpair_t *nvp, char *buf, size_t buflen)
{
	char		addrbuf[IPADM_STRSIZE];
	int32_t		wait;
	boolean_t	primary;
	nvlist_t	*v;

	assert(nvpair_type(nvp) == DATA_TYPE_NVLIST &&
	    strcmp(nvpair_name(nvp), IPADM_NVP_DHCP) == 0);

	if (nvpair_value_nvlist(nvp, &v) != 0 ||
	    nvlist_lookup_int32(v, IPADM_NVP_WAIT, &wait) != 0 ||
	    nvlist_lookup_boolean_value(v, IPADM_NVP_PRIMARY, &primary) != 0) {
		return (0);
	}
	(void) snprintf(buf, buflen, "%s=", IPADM_NVP_DHCP);
	(void) snprintf(addrbuf, sizeof (addrbuf), "%d,%s", wait,
	    (primary ? "yes" : "no"));
	return (strlcat(buf, addrbuf, buflen));
}

/*
 * Constructs a "<name>=<value>" string from the nvpair, whose type must
 * be STRING.
 */
static size_t
i_ipadm_str_nvp2dbline(nvpair_t *nvp, char *buf, size_t buflen)
{
	char	*str = NULL;

	assert(nvpair_type(nvp) == DATA_TYPE_STRING);
	if (nvpair_value_string(nvp, &str) != 0)
		return (0);
	return (snprintf(buf, buflen, "%s=%s", nvpair_name(nvp), str));
}

/*
 * Converts a nvlist to string of the form:
 *  <prop0>=<val0>,...,<valn>;...;<propn>=<val0>,...,<valn>;
 */
size_t
ipadm_nvlist2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	nvpair_t	*nvp = NULL;
	uint_t		nbytes = 0, tbytes = 0;
	ipadm_conf_ent_t *ipent;
	size_t		bufsize = buflen;

	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		ipent = i_ipadm_find_conf_type(nvpair_name(nvp));
		nbytes = (*ipent->ipent_wfunc)(nvp, buf, buflen);
		/* add nvpair separator */
		nbytes += snprintf(buf + nbytes, buflen - nbytes, "%s",
		    IPADM_NVPAIR_SEP);
		buflen -= nbytes;
		buf += nbytes;
		tbytes += nbytes;
		if (tbytes >= bufsize)	/* buffer overflow */
			return (0);
	}
	nbytes = snprintf(buf, buflen, "%c%c", '\n', '\0');
	tbytes += nbytes;
	if (tbytes >= bufsize)
		return (0);
	return (tbytes);
}

/*
 * Adds a nvpair, using the `name' and `value', to the nvlist in `nvl'.
 * The value will be interpreted as explained at the top of this file.
 */
static ipadm_status_t
i_ipadm_add_nvpair(nvlist_t *nvl, char *name, char *value)
{
	ipadm_conf_ent_t	*ipent;

	ipent = i_ipadm_find_conf_type(name);
	return ((*ipent->ipent_rfunc)(nvl, name, value));
}

/*
 * Adds an nvpair for IPv4 addr to the nvlist. The "name" is the string in
 * IPADM_NVP_IPV4ADDR. The "value" for IPADM_NVP_IPV4ADDR is another nvlist.
 * Allocate the value nvlist for IPADM_NVP_IPV4ADDR if necessary, and add
 * the address and hostnames from the address object `ipaddr' to it.
 * Then add the allocated nvlist to `nvl'.
 */
ipadm_status_t
i_ipadm_add_ipaddr2nvl(nvlist_t *nvl, ipadm_addrobj_t ipaddr)
{
	nvlist_t		*nvl_addr = NULL;
	int			err;
	char			*name;
	sa_family_t		af = ipaddr->ipadm_af;

	if (af == AF_INET) {
		name = IPADM_NVP_IPV4ADDR;
	} else {
		assert(af == AF_INET6);
		name = IPADM_NVP_IPV6ADDR;
	}

	if (!nvlist_exists(nvl, name)) {
		if ((err = nvlist_alloc(&nvl_addr, NV_UNIQUE_NAME, 0)) != 0)
			return (ipadm_errno2status(err));
		if ((err = nvlist_add_nvlist(nvl, name, nvl_addr)) != 0) {
			nvlist_free(nvl_addr);
			return (ipadm_errno2status(err));
		}
		nvlist_free(nvl_addr);
	}
	if ((err = nvlist_lookup_nvlist(nvl, name, &nvl_addr)) != 0 ||
	    (err = nvlist_add_string(nvl_addr, IPADM_NVP_IPADDRHNAME,
	    ipaddr->ipadm_static_aname)) != 0)
		return (ipadm_errno2status(err));
	if (ipaddr->ipadm_static_dname[0] != '\0') {
		if ((err = nvlist_add_string(nvl_addr, IPADM_NVP_IPDADDRHNAME,
		    ipaddr->ipadm_static_dname)) != 0)
			return (ipadm_errno2status(err));
	}

	return (IPADM_SUCCESS);
}

/*
 * Adds an nvpair for IPv6 interface id to the nvlist. The "name" is
 * the string in IPADM_NVP_INTFID. The "value" for IPADM_NVP_INTFID is another
 * nvlist. Allocate the value nvlist for IPADM_NVP_INTFID if necessary, and add
 * the interface id and its prefixlen from the address object `ipaddr' to it.
 * Then add the allocated nvlist to `nvl'.
 */
ipadm_status_t
i_ipadm_add_intfid2nvl(nvlist_t *nvl, ipadm_addrobj_t addr)
{
	nvlist_t	*nvl_addr = NULL;
	struct in6_addr	addr6;
	int		err;

	if (!nvlist_exists(nvl, IPADM_NVP_INTFID)) {
		if ((err = nvlist_alloc(&nvl_addr, NV_UNIQUE_NAME, 0)) != 0)
			return (ipadm_errno2status(err));
		if ((err = nvlist_add_nvlist(nvl, IPADM_NVP_INTFID,
		    nvl_addr)) != 0) {
			nvlist_free(nvl_addr);
			return (ipadm_errno2status(err));
		}
		nvlist_free(nvl_addr);
	}
	if ((err = nvlist_lookup_nvlist(nvl, IPADM_NVP_INTFID,
	    &nvl_addr)) != 0 || (err = nvlist_add_uint32(nvl_addr,
	    IPADM_NVP_PREFIXLEN, addr->ipadm_intfidlen)) != 0) {
		return (ipadm_errno2status(err));
	}
	addr6 = addr->ipadm_intfid.sin6_addr;
	if ((err = nvlist_add_uint8_array(nvl_addr, IPADM_NVP_IPNUMADDR,
	    addr6.s6_addr, 16)) != 0) {
		return (ipadm_errno2status(err));
	}
	if (addr->ipadm_stateless)
		err = nvlist_add_string(nvl_addr, IPADM_NVP_STATELESS, "yes");
	else
		err = nvlist_add_string(nvl_addr, IPADM_NVP_STATELESS, "no");
	if (err != 0)
		return (ipadm_errno2status(err));
	if (addr->ipadm_stateful)
		err = nvlist_add_string(nvl_addr, IPADM_NVP_STATEFUL, "yes");
	else
		err = nvlist_add_string(nvl_addr, IPADM_NVP_STATEFUL, "no");
	if (err != 0)
		return (ipadm_errno2status(err));

	return (IPADM_SUCCESS);
}

/*
 * Adds an nvpair for a dhcp address object to the nvlist. The "name" is
 * the string in IPADM_NVP_DHCP. The "value" for IPADM_NVP_DHCP is another
 * nvlist. Allocate the value nvlist for IPADM_NVP_DHCP if necessary, and add
 * the parameters from the arguments `primary' and `wait'.
 * Then add the allocated nvlist to `nvl'.
 */
ipadm_status_t
i_ipadm_add_dhcp2nvl(nvlist_t *nvl, boolean_t primary, int32_t wait)
{
	nvlist_t	*nvl_dhcp = NULL;
	int		err;

	if (!nvlist_exists(nvl, IPADM_NVP_DHCP)) {
		if ((err = nvlist_alloc(&nvl_dhcp, NV_UNIQUE_NAME, 0)) != 0)
			return (ipadm_errno2status(err));
		if ((err = nvlist_add_nvlist(nvl, IPADM_NVP_DHCP,
		    nvl_dhcp)) != 0) {
			nvlist_free(nvl_dhcp);
			return (ipadm_errno2status(err));
		}
		nvlist_free(nvl_dhcp);
	}
	if ((err = nvlist_lookup_nvlist(nvl, IPADM_NVP_DHCP, &nvl_dhcp)) != 0 ||
	    (err = nvlist_add_int32(nvl_dhcp, IPADM_NVP_WAIT, wait)) != 0 ||
	    (err = nvlist_add_boolean_value(nvl_dhcp, IPADM_NVP_PRIMARY,
	    primary)) != 0) {
		return (ipadm_errno2status(err));
	}

	return (IPADM_SUCCESS);
}

/*
 * Add (name, value) as an nvpair of type DATA_TYPE_STRING to nvlist.
 */
static ipadm_status_t
i_ipadm_str_dbline2nvl(nvlist_t *nvl, char *name, char *value)
{
	int err;

	/* if value is NULL create an empty node */
	if (value == NULL)
		err = nvlist_add_string(nvl, name, "");
	else
		err = nvlist_add_string(nvl, name, value);

	return (ipadm_errno2status(err));
}

/*
 * `name' = IPADM_NVP_IPV4ADDR and
 * `value' = <local numeric IP string or hostname,remote numeric IP string or
 *     hostname>
 * This function will add an nvlist with the hostname information in
 * nvpairs to the nvlist in `nvl'.
 */
static ipadm_status_t
i_ipadm_ip4_dbline2nvl(nvlist_t *nvl, char *name, char *value)
{
	char			*cp, *hname;
	struct ipadm_addrobj_s	ipaddr;

	assert(strcmp(name, IPADM_NVP_IPV4ADDR) == 0 && value != NULL);

	bzero(&ipaddr, sizeof (ipaddr));
	ipaddr.ipadm_af = AF_INET;

	hname = value; /* local hostname */
	cp = strchr(hname, ',');
	assert(cp != NULL);
	*cp++ = '\0';
	(void) strlcpy(ipaddr.ipadm_static_aname, hname,
	    sizeof (ipaddr.ipadm_static_aname));

	if (*cp != '\0') {
		/* we have a dst hostname */
		(void) strlcpy(ipaddr.ipadm_static_dname, cp,
		    sizeof (ipaddr.ipadm_static_dname));
	}
	return (i_ipadm_add_ipaddr2nvl(nvl, &ipaddr));
}

/*
 * `name' = IPADM_NVP_IPV6ADDR and
 * `value' = <local numeric IP string or hostname,remote numeric IP string or
 *     hostname>
 * This function will add an nvlist with the hostname information in
 * nvpairs to the nvlist in `nvl'.
 */
static ipadm_status_t
i_ipadm_ip6_dbline2nvl(nvlist_t *nvl, char *name, char *value)
{
	char			*cp, *hname;
	struct ipadm_addrobj_s	ipaddr;

	assert(strcmp(name, IPADM_NVP_IPV6ADDR) == 0 && value != NULL);

	bzero(&ipaddr, sizeof (ipaddr));
	ipaddr.ipadm_af = AF_INET6;

	hname = value; /* local hostname */
	cp = strchr(hname, ',');
	assert(cp != NULL);
	*cp++ = '\0';
	(void) strlcpy(ipaddr.ipadm_static_aname, hname,
	    sizeof (ipaddr.ipadm_static_aname));

	if (*cp != '\0') {
		/* we have a dst hostname */
		(void) strlcpy(ipaddr.ipadm_static_dname, cp,
		    sizeof (ipaddr.ipadm_static_dname));
	}
	return (i_ipadm_add_ipaddr2nvl(nvl, &ipaddr));
}

/*
 * `name' = IPADM_NVP_INTFID and `value' = <intfid/prefixlen>,{yes,no},{yes|no}
 * This function will add an nvlist with the address object information in
 * nvpairs to the nvlist in `nvl'.
 */
static ipadm_status_t
i_ipadm_intfid_dbline2nvl(nvlist_t *nvl, char *name, char *value)
{
	char			*cp;
	struct ipadm_addrobj_s	ipaddr;
	char			*endp;
	char			*prefixlen;
	char			*stateless;
	char			*stateful;

	assert(strcmp(name, IPADM_NVP_INTFID) == 0 && value != NULL);

	bzero(&ipaddr, sizeof (ipaddr));

	cp = strchr(value, '/');
	assert(cp != NULL);

	*cp++ = '\0';
	ipaddr.ipadm_intfid.sin6_family = AF_INET6;
	(void) inet_pton(AF_INET6, value, &ipaddr.ipadm_intfid.sin6_addr);

	prefixlen = cp;
	cp = strchr(cp, ',');
	assert(cp != NULL);
	*cp++ = '\0';

	errno = 0;
	ipaddr.ipadm_intfidlen = (uint32_t)strtoul(prefixlen, &endp, 10);
	if (*endp != '\0' || errno != 0)
		return (ipadm_errno2status(errno));

	stateless = cp;
	stateful = strchr(stateless, ',');
	assert(stateful != NULL);
	*stateful++ = '\0';
	ipaddr.ipadm_stateless = (strcmp(stateless, "yes") == 0);
	ipaddr.ipadm_stateful = (strcmp(stateful, "yes") == 0);

	/* Add all of it to the given nvlist */
	return (i_ipadm_add_intfid2nvl(nvl, &ipaddr));
}

/*
 * `name' = IPADM_NVP_DHCP and `value' = <wait_time>,{yes|no}
 * This function will add an nvlist with the dhcp address object information in
 * nvpairs to the nvlist in `nvl'.
 */
static ipadm_status_t
i_ipadm_dhcp_dbline2nvl(nvlist_t *nvl, char *name, char *value)
{
	char		*cp;
	char		*endp;
	long		wait_time;
	boolean_t	primary;

	assert(strcmp(name, IPADM_NVP_DHCP) == 0 && value != NULL);
	cp = strchr(value, ',');
	assert(cp != NULL);
	*cp++ = '\0';
	errno = 0;
	wait_time = strtol(value, &endp, 10);
	if (*endp != '\0' || errno != 0)
		return (ipadm_errno2status(errno));
	primary = (strcmp(cp, "yes") == 0);
	return (i_ipadm_add_dhcp2nvl(nvl, primary, (int32_t)wait_time));
}

/*
 * Input 'nvp': name = IPADM_NVP_FAMILIES and value = array of 'uint16_t'
 *
 *
 */
static size_t
i_ipadm_families_nvp2dbline(nvpair_t *nvp, char *buf, size_t buflen)
{
	uint_t nelem = 0;
	uint16_t *elem;

	assert(nvpair_type(nvp) == DATA_TYPE_UINT16_ARRAY);

	if (nvpair_value_uint16_array(nvp,
	    &elem, &nelem) != 0) {
		buf[0] = '\0';
		return (0);
	}

	assert(nelem != 0 || nelem > 2);

	if (nelem == 1) {
		return (snprintf(buf, buflen, "%s=%d",
		    nvpair_name(nvp), elem[0]));
	} else {
		return (snprintf(buf, buflen, "%s=%d,%d",
		    nvpair_name(nvp), elem[0], elem[1]));
	}
}

/*
 * name = IPADM_NVP_FAMILIES and value = <FAMILY>[,FAMILY]
 *
 * output nvp: name = IPADM_NVP_FAMILIES and value = array of 'uint16_t'
 *
 */
static ipadm_status_t
i_ipadm_families_dbline2nvl(nvlist_t *nvl, char *name, char *value)
{
	uint16_t	families[2];
	uint_t	nelem = 0;
	char	*val, *lasts;

	if ((val = strtok_r(value,
	    ",", &lasts)) != NULL) {
		families[0] = atoi(val);
		nelem++;
		if ((val = strtok_r(NULL,
		    ",", &lasts)) != NULL) {
			families[1] = atoi(val);
			nelem++;
		}
		return (ipadm_errno2status(nvlist_add_uint16_array(nvl,
		    IPADM_NVP_FAMILIES, families, nelem)));
	}

	return (IPADM_INVALID_ARG);
}

/*
 * input nvp: name = IPADM_NVP_MIFNAMES and value = array of 'char *'
 *
 *
 */
static size_t
i_ipadm_groupmembers_nvp2dbline(nvpair_t *nvp, char *buf, size_t buflen)
{
	uint_t nelem = 0;
	char **elem;
	size_t n;

	assert(nvpair_type(nvp) == DATA_TYPE_STRING_ARRAY);

	if (nvpair_value_string_array(nvp,
	    &elem, &nelem) != 0) {
		buf[0] = '\0';
		return (0);
	}

	assert(nelem != 0);

	n = snprintf(buf, buflen, "%s=", IPADM_NVP_MIFNAMES);
	if (n >= buflen)
		return (n);

	while (nelem-- > 0) {
		n = strlcat(buf, elem[nelem], buflen);
		if (nelem > 0)
			n = strlcat(buf, ",", buflen);

		if (n > buflen)
			return (n);
	}

	return (n);
}

/*
 * name = IPADM_NVP_MIFNAMES and value = <if_name>[,if_name]
 *
 * output nvp: name = IPADM_NVP_MIFNAMES and value = array of 'char *'
 */
static ipadm_status_t
i_ipadm_groupmembers_dbline2nvl(nvlist_t *nvl, char *name, char *value)
{
	char	**members = NULL;
	char	*member = NULL;
	char	*val, *lasts;
	uint_t	m_cnt = 0;
	ipadm_status_t	ret = IPADM_SUCCESS;

	assert(strcmp(name, IPADM_NVP_MIFNAMES) == 0 && value != NULL);

	for (val = strtok_r(value, ",", &lasts);
	    val != NULL;
	    val = strtok_r(NULL, ",", &lasts)) {
		if ((m_cnt % 4) == 0) {
			char **tmp = recallocarray(members, m_cnt, m_cnt + 4,
			    sizeof (char *));

			if (tmp == NULL) {
				ret = IPADM_NO_MEMORY;
				goto fail;
			}

			members = tmp;
		}

		member = calloc(1, LIFNAMSIZ);

		if (member == NULL) {
			ret = IPADM_NO_MEMORY;
			goto fail;
		}

		(void) strlcpy(member, val, LIFNAMSIZ);
		members[m_cnt++] = member;

	}

	if ((ret = ipadm_errno2status(nvlist_add_string_array(nvl,
	    IPADM_NVP_MIFNAMES, members, m_cnt))) != IPADM_SUCCESS)
		goto fail;

fail:
	while (m_cnt-- > 0) {
		free(members[m_cnt]);
	}

	free(members);

	return (ret);
}

/*
 * Parses the buffer, for name-value pairs and creates nvlist. The value
 * is always considered to be a string.
 */
ipadm_status_t
ipadm_str2nvlist(const char *inbuf, nvlist_t **ipnvl, uint_t flags)
{
	ipadm_status_t	status;
	char	*nv, *name, *val, *buf, *cp, *sep;
	int	err;

	if (inbuf == NULL || inbuf[0] == '\0' || ipnvl == NULL)
		return (IPADM_INVALID_ARG);
	*ipnvl = NULL;

	/*
	 * If IPADM_NORVAL is set, then `inbuf' should be comma delimited values
	 */
	if ((flags & IPADM_NORVAL) && strchr(inbuf, '=') != NULL)
		return (IPADM_INVALID_ARG);

	if ((cp = buf = strdup(inbuf)) == NULL)
		return (ipadm_errno2status(errno));

	while (isspace(*buf))
		buf++;

	if (*buf == '\0') {
		status = IPADM_INVALID_ARG;
		goto fail;
	}

	nv = buf;
	/*
	 * work on one nvpair at a time and extract the name and value
	 */
	sep = ((flags & IPADM_NORVAL) ? IPADM_NAME_SEP : IPADM_NVPAIR_SEP);
	while ((nv = strsep(&buf, sep)) != NULL) {
		if (*nv == '\n')
			continue;
		name = nv;
		if ((val = strchr(nv, '=')) != NULL)
			*val++ = '\0';
		if (*ipnvl == NULL &&
		    (err = nvlist_alloc(ipnvl, NV_UNIQUE_NAME, 0)) != 0) {
			status = ipadm_errno2status(err);
			goto fail;
		}
		if (nvlist_exists(*ipnvl, name)) {
			status = IPADM_EXISTS;
			goto fail;
		}
		/* Add the extracted nvpair to the nvlist `ipnvl'. */
		status = i_ipadm_add_nvpair(*ipnvl, name, val);
		if (status != IPADM_SUCCESS)
			goto fail;
	}
	free(cp);
	return (IPADM_SUCCESS);
fail:
	free(cp);
	nvlist_free(*ipnvl);
	*ipnvl = NULL;
	return (status);
}

/*
 * Opens the data store for read/write operation. For write operation we open
 * another file and scribble the changes to it and copy the new file back to
 * old file.
 */
int
ipadm_rw_db(db_wfunc_t *db_walk_func, void *arg, const char *db_file,
    mode_t db_perms, ipadm_db_op_t db_op)
{
	FILE		*fp, *nfp = NULL;
	char		file[MAXPATHLEN];
	char		newfile[MAXPATHLEN];
	int		nfd;
	boolean_t	writeop;
	int		err = 0;

	writeop = (db_op != IPADM_DB_READ);

	(void) snprintf(file, MAXPATHLEN, "%s/%s", ipadm_rootdir, db_file);

	/* open the data store */
	if ((fp = fopen(file, (writeop ? "r+" : "r"))) == NULL)
		return (errno);

	if (writeop) {
		(void) snprintf(newfile, MAXPATHLEN, "%s/%s.new",
		    ipadm_rootdir, db_file);
		if ((nfd = open(newfile, O_WRONLY | O_CREAT | O_TRUNC,
		    db_perms)) < 0) {
			err = errno;
			(void) fclose(fp);
			return (err);
		}

		if ((nfp = fdopen(nfd, "w")) == NULL) {
			err = errno;
			(void) close(nfd);
			(void) fclose(fp);
			(void) unlink(newfile);
			return (err);
		}
	}
	err = ipadm_process_db_line(db_walk_func, arg, fp, nfp, db_op);
	if (!writeop)
		goto done;
	if (err != 0 && err != ENOENT)
		goto done;

	if (fflush(nfp) == EOF) {
		err = errno;
		goto done;
	}
	(void) fclose(fp);
	(void) fclose(nfp);

	if (rename(newfile, file) < 0) {
		err = errno;
		(void) unlink(newfile);
	}
	return (err);
done:
	if (nfp != NULL) {
		(void) fclose(nfp);
		if (err != 0)
			(void) unlink(newfile);
	}
	(void) fclose(fp);
	return (err);
}

/*
 * Processes each line of the configuration file, skipping lines with
 * leading spaces, blank lines and comments. The line form the DB
 * is converted to nvlist and the callback function is called to process
 * the list. The buf could be modified by the callback function and
 * if this is a write operation and buf is not truncated, buf will
 * be written to disk.
 *
 * Further if cont is set to B_FALSE,  the remainder of the file will
 * continue to be read (however callback function will not be called) and,
 * if necessary, written to disk as well.
 */
static int
ipadm_process_db_line(db_wfunc_t *db_walk_func, void *arg, FILE *fp, FILE *nfp,
    ipadm_db_op_t db_op)
{
	int		err = 0;
	char		buf[MAXLINELEN];
	boolean_t	cont = B_TRUE;
	int		i, len;
	nvlist_t	*db_nvl = NULL;
	boolean_t	line_deleted = B_FALSE;

	while (fgets(buf, MAXLINELEN, fp) != NULL) {
		/*
		 * Skip leading spaces, blank lines, and comments.
		 */
		len = strnlen(buf, MAXLINELEN);
		for (i = 0; i < len; i++) {
			if (!isspace(buf[i]))
				break;
		}

		if (i != len && buf[i] != '#' && cont) {
			if (ipadm_str2nvlist(buf, &db_nvl, 0) == 0) {
				cont = db_walk_func(arg, db_nvl, buf,
				    MAXLINELEN, &err);
			} else {
				/* Delete corrupted line. */
				buf[0] = '\0';
			}
			nvlist_free(db_nvl);
			db_nvl = NULL;
		}
		if (err != 0)
			break;
		if (nfp != NULL && buf[0] == '\0')
			line_deleted = B_TRUE;
		if (nfp != NULL	&& buf[0] != '\0' && fputs(buf, nfp) == EOF) {
			err = errno;
			break;
		}
	}

	if (err != 0 || !cont)
		return (err);

	if (db_op == IPADM_DB_WRITE) {
		nvlist_t	*nvl;

		/*
		 * `arg' will be NULL when we are doing in-line update of
		 * entries.
		 */
		if (arg != NULL) {
			nvl = ((ipadm_dbwrite_cbarg_t *)arg)->dbw_nvl;
			/*
			 * If the specified entry is not found above, we add
			 * the entry to the configuration file, here.
			 */
			(void) memset(buf, 0, MAXLINELEN);
			if (ipadm_nvlist2str(nvl, buf, MAXLINELEN) == 0)
				err = ENOBUFS;
			else if (fputs(buf, nfp) == EOF)
				err = errno;
		}
		return (err);
	}

	if (db_op == IPADM_DB_DELETE && line_deleted)
		return (0);

	/* if we have come this far, then we didn't find any match */
	return (ENOENT);
}
