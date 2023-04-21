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
 */

#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mac_flow.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <inet/ip.h>
#include <inet/ip6.h>

#include <libdladm.h>
#include <libdlflow.h>
#include <libdlflow_impl.h>

/* max port number for UDP, TCP & SCTP */
#define	MAX_PORT	65535

static fad_checkf_t do_check_local_ip;
static fad_checkf_t do_check_remote_ip;
static fad_checkf_t do_check_protocol;
static fad_checkf_t do_check_local_port;
static fad_checkf_t do_check_remote_port;

static dladm_status_t do_check_port(char *, boolean_t, flow_desc_t *);

static fattr_desc_t	attr_table[] = {
	{ "local_ip",		do_check_local_ip },
	{ "remote_ip",		do_check_remote_ip },
	{ "transport",		do_check_protocol },
	{ "local_port",		do_check_local_port },
	{ "remote_port",	do_check_remote_port },
	{ "dsfield",		do_check_dsfield },
};

#define	DLADM_MAX_FLOWATTRS	(sizeof (attr_table) / sizeof (fattr_desc_t))

static dladm_status_t
do_check_local_ip(char *attr_val, flow_desc_t *fdesc)
{
	return (do_check_ip_addr(attr_val, B_TRUE, fdesc));
}

static dladm_status_t
do_check_remote_ip(char *attr_val, flow_desc_t *fdesc)
{
	return (do_check_ip_addr(attr_val, B_FALSE, fdesc));
}

dladm_status_t
do_check_ip_addr(char *addr_str, boolean_t local, flow_desc_t *fd)
{
	dladm_status_t	status;
	int		prefix_max, prefix_len = 0;
	char		*prefix_str, *endp = NULL;
	flow_mask_t	mask;
	in6_addr_t	*addr;
	uchar_t		*netmask;
	struct in_addr	v4addr;
	struct in6_addr	v6addr;
	int		family;

	if ((prefix_str = strchr(addr_str, '/')) != NULL) {
		*prefix_str++ = '\0';
		errno = 0;
		prefix_len = (int)strtol(prefix_str, &endp, 10);
		if (errno != 0 || prefix_len == 0 || *endp != '\0')
			return (DLADM_STATUS_INVALID_PREFIXLEN);
	}
	if (inet_pton(AF_INET, addr_str, &v4addr.s_addr) == 1) {
		family = AF_INET;
	} else if (inet_pton(AF_INET6, addr_str, v6addr.s6_addr) == 1) {
		family = AF_INET6;
	} else {
		return (DLADM_STATUS_INVALID_IP);
	}

	mask = FLOW_IP_VERSION;
	if (local) {
		mask |= FLOW_IP_LOCAL;
		addr = &fd->fd_local_addr;
		netmask = (uchar_t *)&fd->fd_local_netmask;
	} else {
		mask |= FLOW_IP_REMOTE;
		addr = &fd->fd_remote_addr;
		netmask = (uchar_t *)&fd->fd_remote_netmask;
	}

	if (family == AF_INET) {
		IN6_INADDR_TO_V4MAPPED(&v4addr, addr);
		prefix_max = IP_ABITS;
		fd->fd_ipversion = IPV4_VERSION;
		netmask = (uchar_t *)
		    &(V4_PART_OF_V6((*((in6_addr_t *)(void *)netmask))));
	} else {
		*addr = v6addr;
		prefix_max = IPV6_ABITS;
		fd->fd_ipversion = IPV6_VERSION;
	}

	if (prefix_len == 0)
		prefix_len = prefix_max;

	status = dladm_prefixlen2mask(prefix_len, prefix_max, netmask);

	if (status != DLADM_STATUS_OK) {
		return (DLADM_STATUS_INVALID_PREFIXLEN);
	}

	fd->fd_mask |= mask;
	return (DLADM_STATUS_OK);
}

dladm_status_t
do_check_protocol(char *attr_val, flow_desc_t *fdesc)
{
	uint8_t	protocol;

	protocol = dladm_str2proto(attr_val);

	if (protocol != 0) {
		fdesc->fd_mask |= FLOW_IP_PROTOCOL;
		fdesc->fd_protocol = protocol;
		return (DLADM_STATUS_OK);
	} else {
		return (DLADM_STATUS_INVALID_PROTOCOL);
	}
}

dladm_status_t
do_check_local_port(char *attr_val, flow_desc_t *fdesc)
{
	return (do_check_port(attr_val, B_TRUE, fdesc));
}

dladm_status_t
do_check_remote_port(char *attr_val, flow_desc_t *fdesc)
{
	return (do_check_port(attr_val, B_FALSE, fdesc));
}

dladm_status_t
do_check_port(char *attr_val, boolean_t local, flow_desc_t *fdesc)
{
	char	*endp = NULL;
	long	val;

	val = strtol(attr_val, &endp, 10);
	if (val < 1 || val > MAX_PORT || *endp != '\0')
		return (DLADM_STATUS_INVALID_PORT);
	if (local) {
		fdesc->fd_mask |= FLOW_ULP_PORT_LOCAL;
		fdesc->fd_local_port = htons((uint16_t)val);
	} else {
		fdesc->fd_mask |= FLOW_ULP_PORT_REMOTE;
		fdesc->fd_remote_port = htons((uint16_t)val);
	}

	return (DLADM_STATUS_OK);
}

/*
 * Check for invalid and/or duplicate attribute specification
 */
static dladm_status_t
flow_attrlist_check(dladm_arg_list_t *attrlist)
{
	uint_t		i, j;
	boolean_t	isset[DLADM_MAX_FLOWATTRS];
	boolean_t	matched;

	for (j = 0; j < DLADM_MAX_FLOWATTRS; j++)
		isset[j] = B_FALSE;

	for (i = 0; i < attrlist->al_count; i++) {
		matched = B_FALSE;
		for (j = 0; j < DLADM_MAX_FLOWATTRS; j++) {
			if (strcmp(attrlist->al_info[i].ai_name,
			    attr_table[j].ad_name) == 0) {
				if (isset[j])
					return (DLADM_STATUS_FLOW_INCOMPATIBLE);
				else
					isset[j] = B_TRUE;
				matched = B_TRUE;
			}
		}
		/*
		 * if the attribute did not match any of the attribute in
		 * attr_table, then it's an invalid attribute.
		 */
		if (!matched)
			return (DLADM_STATUS_BADARG);
	}
	return (DLADM_STATUS_OK);
}

/*
 * Convert an attribute list to a flow_desc_t using the attribute ad_check()
 * functions.
 */
dladm_status_t
dladm_flow_attrlist_extract(dladm_arg_list_t *attrlist, flow_desc_t *flowdesc)
{
	dladm_status_t	status = DLADM_STATUS_BADARG;
	uint_t		i;

	for (i = 0; i < attrlist->al_count; i++) {
		dladm_arg_info_t	*aip = &attrlist->al_info[i];
		uint_t			j;

		if (aip->ai_val[0] == NULL)
			return (DLADM_STATUS_BADARG);

		for (j = 0; j < DLADM_MAX_FLOWATTRS; j++) {
			fattr_desc_t	*adp = &attr_table[j];

			if (strcasecmp(aip->ai_name, adp->ad_name) != 0)
				continue;

			if (adp->ad_check != NULL)
				status = adp->ad_check(*aip->ai_val, flowdesc);
			else
				status = DLADM_STATUS_BADARG;

			if (status != DLADM_STATUS_OK)
				return (status);
		}
	}

	/*
	 * Make sure protocol is specified if either local or
	 * remote port is specified.
	 */
	if ((flowdesc->fd_mask &
	    (FLOW_ULP_PORT_LOCAL | FLOW_ULP_PORT_REMOTE)) != 0 &&
	    (flowdesc->fd_mask & FLOW_IP_PROTOCOL) == 0)
		return (DLADM_STATUS_PORT_NOPROTO);

	return (status);
}

void
dladm_free_attrs(dladm_arg_list_t *list)
{
	dladm_free_args(list);
}

dladm_status_t
dladm_parse_flow_attrs(char *str, dladm_arg_list_t **listp, boolean_t novalues)
{

	if (dladm_parse_args(str, listp, novalues)
	    != DLADM_STATUS_OK)
		return (DLADM_STATUS_ATTR_PARSE_ERR);

	if (*listp != NULL && flow_attrlist_check(*listp)
	    != DLADM_STATUS_OK) {
		dladm_free_attrs(*listp);
		return (DLADM_STATUS_ATTR_PARSE_ERR);
	}

	return (DLADM_STATUS_OK);
}

dladm_status_t
do_check_dsfield(char *str, flow_desc_t *fd)
{
	char		*mask_str, *endp = NULL;
	uint_t		mask = 0xff, value;

	if ((mask_str = strchr(str, ':')) != NULL) {
		*mask_str++ = '\0';
		errno = 0;
		mask = strtoul(mask_str, &endp, 16);
		if (errno != 0 || mask == 0 || mask > 0xff ||
		    *endp != '\0')
			return (DLADM_STATUS_INVALID_DSFMASK);
	}
	errno = 0;
	endp = NULL;
	value = strtoul(str, &endp, 16);
	if (errno != 0 || value == 0 || value > 0xff || *endp != '\0')
		return (DLADM_STATUS_INVALID_DSF);

	fd->fd_dsfield = (uint8_t)value;
	fd->fd_dsfield_mask = (uint8_t)mask;
	fd->fd_mask |= FLOW_IP_DSFIELD;
	return (DLADM_STATUS_OK);
}

char *
dladm_proto2str(uint8_t protocol)
{
	if (protocol == IPPROTO_TCP)
		return ("tcp");
	if (protocol == IPPROTO_UDP)
		return ("udp");
	if (protocol == IPPROTO_SCTP)
		return ("sctp");
	if (protocol == IPPROTO_ICMPV6)
		return ("icmpv6");
	if (protocol == IPPROTO_ICMP)
		return ("icmp");
	else
		return ("");
}

uint8_t
dladm_str2proto(const char *protostr)
{
	if (strncasecmp(protostr, "tcp", 3) == 0)
		return (IPPROTO_TCP);
	else if (strncasecmp(protostr, "udp", 3) == 0)
		return (IPPROTO_UDP);
	else if (strncasecmp(protostr, "sctp", 4) == 0)
		return (IPPROTO_SCTP);
	else if (strncasecmp(protostr, "icmpv6", 6) == 0)
		return (IPPROTO_ICMPV6);
	else if (strncasecmp(protostr, "icmp", 4) == 0)
		return (IPPROTO_ICMP);

	return (0);
}

void
dladm_flow_attr_ip2str(dladm_flow_attr_t *attrp, char *buf, size_t buf_len)
{
	flow_desc_t	fdesc = attrp->fa_flow_desc;
	struct in_addr	ipaddr;
	int		prefix_len, prefix_max;
	char		*cp, abuf[INET6_ADDRSTRLEN];

	if (fdesc.fd_mask & FLOW_IP_LOCAL) {
		if (fdesc.fd_ipversion == IPV6_VERSION) {
			(void) inet_ntop(AF_INET6, &fdesc.fd_local_addr, abuf,
			    INET6_ADDRSTRLEN);
			cp = abuf;
			prefix_max = IPV6_ABITS;
		} else {
			ipaddr.s_addr = fdesc.fd_local_addr._S6_un._S6_u32[3];
			cp = inet_ntoa(ipaddr);
			prefix_max = IP_ABITS;
		}
		(void) dladm_mask2prefixlen(&fdesc.fd_local_netmask,
		    prefix_max, &prefix_len);
		(void) snprintf(buf, buf_len, "LCL:%s/%d  ", cp, prefix_len);
	} else if (fdesc.fd_mask & FLOW_IP_REMOTE) {
		if (fdesc.fd_ipversion == IPV6_VERSION) {
			(void) inet_ntop(AF_INET6, &fdesc.fd_remote_addr, abuf,
			    INET6_ADDRSTRLEN);
			cp = abuf;
			prefix_max = IPV6_ABITS;
		} else {
			ipaddr.s_addr = fdesc.fd_remote_addr._S6_un._S6_u32[3];
			cp = inet_ntoa(ipaddr);
			prefix_max = IP_ABITS;
		}
		(void) dladm_mask2prefixlen(&fdesc.fd_remote_netmask,
		    prefix_max, &prefix_len);
		(void) snprintf(buf, buf_len, "RMT:%s/%d  ", cp, prefix_len);
	} else {
		buf[0] = '\0';
	}
}

void
dladm_flow_attr_proto2str(dladm_flow_attr_t *attrp, char *buf, size_t buf_len)
{
	flow_desc_t	fdesc = attrp->fa_flow_desc;

	(void) snprintf(buf, buf_len, "%s",
	    dladm_proto2str(fdesc.fd_protocol));
}

void
dladm_flow_attr_port2str(dladm_flow_attr_t *attrp, char *buf, size_t buf_len)
{
	flow_desc_t	fdesc = attrp->fa_flow_desc;

	if (fdesc.fd_mask & FLOW_ULP_PORT_LOCAL) {
		(void) snprintf(buf, buf_len, "%d",
		    ntohs(fdesc.fd_local_port));
	} else if (fdesc.fd_mask & FLOW_ULP_PORT_REMOTE) {
		(void) snprintf(buf, buf_len, "%d",
		    ntohs(fdesc.fd_remote_port));
	} else {
		buf[0] = '\0';
	}
}

void
dladm_flow_attr_dsfield2str(dladm_flow_attr_t *attrp, char *buf, size_t buf_len)
{
	flow_desc_t	fdesc = attrp->fa_flow_desc;

	if (fdesc.fd_mask & FLOW_IP_DSFIELD) {
		(void) snprintf(buf, buf_len, "0x%x:0x%x",
		    fdesc.fd_dsfield, fdesc.fd_dsfield_mask);
	} else {
		buf[0] = '\0';
	}
}
