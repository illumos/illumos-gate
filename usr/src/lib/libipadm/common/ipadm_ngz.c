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
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 */

#include <errno.h>
#include <fcntl.h>
#include <priv_utils.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zone.h>
#include <libipadm.h>
#include <libdladm.h>
#include <libdllink.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/route.h>
#include <errno.h>
#include <inet/ip.h>
#include <string.h>
#include <libinetutil.h>
#include <unistd.h>
#include <libipadm_impl.h>
#include <sys/brand.h>

#define	ROUNDUP_LONG(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof (long) - 1))) : sizeof (long))
#define	HOST_MASK	0xffffffffU

typedef struct ngz_walk_data_s {
	ipadm_handle_t	ngz_iph;
	zoneid_t	ngz_zoneid;
	char		*ngz_ifname;
	boolean_t	ngz_s10c;
	ipadm_status_t  ngz_ipstatus;
	persist_cb_t	ngz_persist_if;
} ngz_walk_data_t;

/*
 * Tell the kernel to add, delete or change a route
 */
static void
i_ipadm_rtioctl4(int rtsock,
    int action,			/* RTM_DELETE, etc */
    in_addr_t dst,
    in_addr_t gate,
    uint_t masklen,
    char *ifname,
    uint8_t metric,
    int flags)
{
	static int rt_sock_seqno = 0;
	struct {
		struct rt_msghdr w_rtm;
		struct sockaddr_in w_dst;
		struct sockaddr_in w_gate;
		uint8_t w_space[512];
	} w;
	struct sockaddr_in w_mask;
	struct sockaddr_dl w_ifp;
	uint8_t *cp;
	long cc;

again:
	(void) memset(&w, 0, sizeof (w));
	(void) memset(&w_mask, 0, sizeof (w_mask));
	(void) memset(&w_ifp, 0, sizeof (w_ifp));
	cp = w.w_space;
	w.w_rtm.rtm_msglen = sizeof (struct rt_msghdr) +
	    2 * ROUNDUP_LONG(sizeof (struct sockaddr_in));
	w.w_rtm.rtm_version = RTM_VERSION;
	w.w_rtm.rtm_type = action;
	w.w_rtm.rtm_flags = (flags | RTF_ZONE);
	w.w_rtm.rtm_seq = ++rt_sock_seqno;
	w.w_rtm.rtm_addrs = RTA_DST|RTA_GATEWAY;
	if (metric != 0 || action == RTM_CHANGE) {
		w.w_rtm.rtm_rmx.rmx_hopcount = metric;
		w.w_rtm.rtm_inits |= RTV_HOPCOUNT;
	}
	w.w_dst.sin_family = AF_INET;
	w.w_dst.sin_addr.s_addr = dst;
	w.w_gate.sin_family = AF_INET;
	w.w_gate.sin_addr.s_addr = gate;
	if (masklen == HOST_MASK) {
		w.w_rtm.rtm_flags |= RTF_HOST;
	} else {
		struct sockaddr_storage m4;

		w.w_rtm.rtm_addrs |= RTA_NETMASK;
		w_mask.sin_family = AF_INET;
		if (plen2mask(masklen, AF_INET, (struct sockaddr *)&m4) != 0) {
			return;
		}
		w_mask.sin_addr = ((struct sockaddr_in *)&m4)->sin_addr;
		(void) memmove(cp, &w_mask, sizeof (w_mask));
		cp += ROUNDUP_LONG(sizeof (struct sockaddr_in));
		w.w_rtm.rtm_msglen += ROUNDUP_LONG(sizeof (struct sockaddr_in));
	}
	w_ifp.sdl_family = AF_LINK;
	w.w_rtm.rtm_addrs |= RTA_IFP;
	w_ifp.sdl_index = if_nametoindex(ifname);
	(void) memmove(cp, &w_ifp, sizeof (w_ifp));
	w.w_rtm.rtm_msglen += ROUNDUP_LONG(sizeof (struct sockaddr_dl));

	cc = write(rtsock, &w, w.w_rtm.rtm_msglen);
	if (cc < 0) {
		if (errno == ESRCH && (action == RTM_CHANGE ||
		    action == RTM_DELETE)) {
			if (action == RTM_CHANGE) {
				action = RTM_ADD;
				goto again;
			}
			return;
		}
		return;
	} else if (cc != w.w_rtm.rtm_msglen) {
		return;
	}
}

static void
i_ipadm_rtioctl6(int rtsock,
    int action,			/* RTM_DELETE, etc */
    in6_addr_t dst,
    in6_addr_t gate,
    uint_t prefix_length,
    char *ifname,
    int flags)
{
	static int rt_sock_seqno = 0;
	struct {
		struct rt_msghdr w_rtm;
		struct sockaddr_in6 w_dst;
		struct sockaddr_in6 w_gate;
		uint8_t w_space[512];
	} w;
	struct sockaddr_in6 w_mask;
	struct sockaddr_dl w_ifp;
	uint8_t *cp;
	long cc;

again:
	(void) memset(&w, 0, sizeof (w));
	(void) memset(&w_mask, 0, sizeof (w_mask));
	(void) memset(&w_ifp, 0, sizeof (w_ifp));
	cp = w.w_space;
	w.w_rtm.rtm_msglen = sizeof (struct rt_msghdr) +
	    2 * ROUNDUP_LONG(sizeof (struct sockaddr_in6));
	w.w_rtm.rtm_version = RTM_VERSION;
	w.w_rtm.rtm_type = action;
	w.w_rtm.rtm_flags = (flags | RTF_ZONE);
	w.w_rtm.rtm_seq = ++rt_sock_seqno;
	w.w_rtm.rtm_addrs = RTA_DST|RTA_GATEWAY;
	w.w_dst.sin6_family = AF_INET6;
	w.w_dst.sin6_addr = dst;
	w.w_gate.sin6_family = AF_INET6;
	w.w_gate.sin6_addr = gate;
	if (prefix_length == IPV6_ABITS) {
		w.w_rtm.rtm_flags |= RTF_HOST;
	} else {
		struct sockaddr_storage m6;

		w.w_rtm.rtm_addrs |= RTA_NETMASK;
		w_mask.sin6_family = AF_INET6;
		if (plen2mask(prefix_length, AF_INET6,
		    (struct sockaddr *)&m6) != 0) {
			return;
		}
		w_mask.sin6_addr = ((struct sockaddr_in6 *)&m6)->sin6_addr;
		(void) memmove(cp, &w_mask, sizeof (w_mask));
		cp += ROUNDUP_LONG(sizeof (struct sockaddr_in6));
		w.w_rtm.rtm_msglen +=
		    ROUNDUP_LONG(sizeof (struct sockaddr_in6));
	}
	w_ifp.sdl_family = AF_LINK;
	w.w_rtm.rtm_addrs |= RTA_IFP;
	w_ifp.sdl_index = if_nametoindex(ifname);
	(void) memmove(cp, &w_ifp, sizeof (w_ifp));
	w.w_rtm.rtm_msglen += ROUNDUP_LONG(sizeof (struct sockaddr_dl));

	cc = write(rtsock, &w, w.w_rtm.rtm_msglen);
	if (cc < 0) {
		if (errno == ESRCH && (action == RTM_CHANGE ||
		    action == RTM_DELETE)) {
			if (action == RTM_CHANGE) {
				action = RTM_ADD;
				goto again;
			}
			return;
		}
		return;
	} else if (cc != w.w_rtm.rtm_msglen) {
		return;
	}
}

/*
 * Return TRUE if running in a Solaris 10 Container.
 */
static boolean_t
i_ipadm_zone_is_s10c(zoneid_t zoneid)
{
	char brand[MAXNAMELEN];

	if (zone_getattr(zoneid, ZONE_ATTR_BRAND, brand, sizeof (brand)) < 0)
		return (B_FALSE);
	return (strcmp(brand, NATIVE_BRAND_NAME) != 0);
}

/*
 * Configure addresses on link. `buf' is a string of comma-separated
 * IP addresses.
 */
static ipadm_status_t
i_ipadm_ngz_addr(ipadm_handle_t iph, char *link, char *buf)
{
	ipadm_status_t ipstatus;
	ipadm_addrobj_t ipaddr;
	char *cp;

	for (cp = strtok(buf, ","); cp != NULL; cp = strtok(NULL, ",")) {
		ipstatus = ipadm_create_addrobj(IPADM_ADDR_STATIC, link,
		    &ipaddr);
		if (ipstatus != IPADM_SUCCESS)
			return (ipstatus);
		/*
		 * ipadm_set_addr does the appropriate name resolution and
		 * sets up the ipadm_static_addr field.
		 */
		ipstatus = ipadm_set_addr(ipaddr, cp, AF_UNSPEC);
		if (ipstatus != IPADM_SUCCESS) {
			ipadm_destroy_addrobj(ipaddr);
			return (ipstatus);
		}

		ipstatus = ipadm_create_addr(iph, ipaddr,
		    (IPADM_OPT_ACTIVE | IPADM_OPT_UP));
		if (ipstatus != IPADM_SUCCESS) {
			ipadm_destroy_addrobj(ipaddr);
			return (ipstatus);
		}
		ipadm_destroy_addrobj(ipaddr);
	}
	return (IPADM_SUCCESS);
}

/*
 * The (*persist_if)() will set up persistent information for the interface,
 * based on what interface families are required, so just resolve the
 * address and inform the callback about the linkname, and required address
 * families.
 */
static ipadm_status_t
i_ipadm_ngz_persist_if(char *link, char *buf,
    void (*ngz_persist_if)(char *, boolean_t, boolean_t))
{
	char *cp, *slashp, addr[INET6_ADDRSTRLEN];
	ipadm_status_t ipstatus;
	struct sockaddr_storage ss;
	boolean_t v4 = B_FALSE;
	boolean_t v6 = B_FALSE;

	for (cp = strtok(buf, ","); cp != NULL; cp = strtok(NULL, ",")) {
		/* remove the /<masklen> that's always added by zoneadmd */
		slashp = strchr(cp, '/');
		(void) strlcpy(addr, cp, (slashp - cp + 1));

		/* resolve the address to find the family */
		bzero(&ss, sizeof (ss));
		ipstatus = i_ipadm_resolve_addr(addr, AF_UNSPEC, &ss);
		if (ipstatus != IPADM_SUCCESS)
			return (ipstatus);
		switch (ss.ss_family) {
		case AF_INET:
			v4 = B_TRUE;
			break;
		case AF_INET6:
			v6 = B_TRUE;
			break;
		default:
			return (IPADM_BAD_ADDR);
		}
	}
	(*ngz_persist_if)(link, v4, v6);
	return (IPADM_SUCCESS);
}

static void
i_ipadm_create_ngz_route(int rtsock, char *link, uint8_t *buf, size_t buflen)
{
	struct in6_addr defrouter;
	boolean_t isv6;
	struct in_addr gw4;
	uint8_t *cp;
	const in6_addr_t ipv6_all_zeros = { 0, 0, 0, 0 };

	if (rtsock == -1)
		return;

	for (cp = buf; cp < buf + buflen; cp += sizeof (defrouter)) {
		bcopy(cp, &defrouter, sizeof (defrouter));
		if (IN6_IS_ADDR_UNSPECIFIED(&defrouter))
			break;
		isv6 = !IN6_IS_ADDR_V4MAPPED(&defrouter);
		if (isv6) {
			i_ipadm_rtioctl6(rtsock, RTM_ADD, ipv6_all_zeros,
			    defrouter, 0, link, RTF_GATEWAY);
		} else {
			IN6_V4MAPPED_TO_INADDR(&defrouter, &gw4);
			i_ipadm_rtioctl4(rtsock, RTM_ADD, INADDR_ANY,
			    gw4.s_addr, 0, link, 0, RTF_GATEWAY);
		}
	}
}

/*
 * Wrapper function to zone_getattr() for retrieving from-gz attributes that
 * were made availabe for exclusive IP non-global zones by zoneadmd from teh
 * global zone.
 */
static ipadm_status_t
i_ipadm_zone_get_network(zoneid_t zoneid, datalink_id_t linkid, int type,
    void *buf, size_t *bufsize)
{
	zone_net_data_t *zndata;
	ipadm_status_t ret = IPADM_SUCCESS;

	zndata = calloc(1, sizeof (*zndata) + *bufsize);
	if (zndata == NULL)
		return (IPADM_NO_MEMORY);
	zndata->zn_type = type;
	zndata->zn_linkid = linkid;
	zndata->zn_len = *bufsize;

	if (zone_getattr(zoneid, ZONE_ATTR_NETWORK, zndata,
	    sizeof (*zndata) + *bufsize) < 0) {
		ret = ipadm_errno2status(errno);
		goto out;
	}
	*bufsize = zndata->zn_len;
	bcopy(zndata->zn_val, buf, *bufsize);
out:
	free(zndata);
	return (ret);
}

/*
 * Callback function that configures a single datalink in a non-global zone.
 */
static int
i_ipadm_zone_network_attr(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	ngz_walk_data_t *nwd = arg;
	zoneid_t zoneid = nwd->ngz_zoneid;
	uint8_t buf[PIPE_BUF];
	dladm_status_t dlstatus;
	ipadm_status_t ipstatus;
	char link[MAXLINKNAMELEN];
	ipadm_handle_t iph = nwd->ngz_iph;
	int rtsock = iph->iph_rtsock;
	char *ifname = nwd->ngz_ifname;
	boolean_t s10c = nwd->ngz_s10c;
	boolean_t is_ipmgmtd = (iph->iph_flags & IPH_IPMGMTD);
	size_t bufsize = sizeof (buf);

	bzero(buf, bufsize);
	ipstatus = i_ipadm_zone_get_network(zoneid, linkid,
	    ZONE_NETWORK_ADDRESS, buf, &bufsize);
	if (ipstatus != IPADM_SUCCESS)
		goto fail;

	dlstatus = dladm_datalink_id2info(dh, linkid, NULL, NULL,
	    NULL, link, sizeof (link));
	if (dlstatus != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	/*
	 * if ifname has been specified, then skip interfaces that don't match
	 */
	if (ifname != NULL && strcmp(ifname, link) != 0)
		return (DLADM_WALK_CONTINUE);

	/*
	 * Plumb the interface and configure addresses on for S10 Containers.
	 * We need to always do this for S10C because ipadm persistent
	 * configuration is not available in S10C. For ipkg zones,
	 * we skip the actual plumbing/configuration, but will call the
	 * (*ngz_persist_if)() callback to create the persistent state for the
	 * interface. The interface will be configured in ipkg zones when
	 * ipadm_enable_if() is invoked to restore persistent configuration.
	 */
	if (is_ipmgmtd && !s10c) {
		(void) i_ipadm_ngz_persist_if(link, (char *)buf,
		    nwd->ngz_persist_if);
		return (DLADM_WALK_CONTINUE);
	}
	ipstatus = i_ipadm_ngz_addr(iph, link, (char *)buf);
	if (ipstatus != IPADM_SUCCESS)
		goto fail;

	/* apply any default router information.  */
	bufsize = sizeof (buf);
	bzero(buf, bufsize);
	ipstatus = i_ipadm_zone_get_network(zoneid, linkid,
	    ZONE_NETWORK_DEFROUTER, buf, &bufsize);
	if (ipstatus != IPADM_SUCCESS)
		goto fail;

	i_ipadm_create_ngz_route(rtsock, link, buf, bufsize);

	return (DLADM_WALK_CONTINUE);
fail:
	if (ifname != NULL) {
		nwd->ngz_ipstatus = ipstatus;
		return (DLADM_WALK_TERMINATE);
	}
	return (DLADM_WALK_CONTINUE);
}

/*
 * ipmgmt_net_from_gz_init() initializes exclusive-IP stack non-global zones by
 * extracting configuration that has been saved in the kernel and applying
 * that information to the appropriate datalinks for the zone. If an ifname
 * argument is passed in, only the selected IP interface corresponding to
 * datalink will be initialized, otherwise all datalinks will be plumbed for IP
 * and IP address and route information will be configured.
 */
ipadm_status_t
ipadm_init_net_from_gz(ipadm_handle_t iph, char *ifname,
    void (*persist_if)(char *, boolean_t, boolean_t))
{
	ngz_walk_data_t nwd;
	uint64_t flags;
	dladm_handle_t dlh = iph->iph_dlh;
	datalink_id_t linkid;

	if (iph->iph_zoneid == GLOBAL_ZONEID)
		return (IPADM_NOTSUP);

	if (ifname != NULL &&
	    i_ipadm_get_flags(iph, ifname, AF_INET, &flags) != IPADM_SUCCESS &&
	    i_ipadm_get_flags(iph, ifname, AF_INET6, &flags) != IPADM_SUCCESS)
		return (IPADM_ENXIO);

	if (ifname != NULL && !(flags & IFF_L3PROTECT))
		return (IPADM_SUCCESS); /* nothing to initialize */

	nwd.ngz_iph = iph;
	nwd.ngz_zoneid = iph->iph_zoneid;
	nwd.ngz_ifname = ifname;
	nwd.ngz_persist_if = persist_if;
	nwd.ngz_s10c = i_ipadm_zone_is_s10c(iph->iph_zoneid);
	nwd.ngz_ipstatus = IPADM_SUCCESS;
	if (ifname != NULL) {
		if (dladm_name2info(dlh, ifname, &linkid, NULL, NULL,
		    NULL) != DLADM_STATUS_OK) {
			return (IPADM_ENXIO);
		}
		(void) i_ipadm_zone_network_attr(dlh, linkid, &nwd);
	} else {
		(void) dladm_walk_datalink_id(i_ipadm_zone_network_attr, dlh,
		    &nwd, DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
	}
	return (nwd.ngz_ipstatus);
}
