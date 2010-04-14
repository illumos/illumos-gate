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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *
 * MODULE: dapl_name_service.c
 *
 * PURPOSE: Provide simple, file base name services in the absence
 *	    of DNS hooks for a particular transport type. If an
 *	    InfiniBand implementation supports IPoIB, this should
 *	    not be used.
 *
 * Description: Interfaces in this file are completely described in
 *		dapl_name_service.h
 */

/*
 * Include files for setting up a network name
 */
#include "dapl.h"
#include "dapl_name_service.h"

#include <netinet/in.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <net/if_types.h>
#include <arpa/inet.h>
#include <poll.h>
#include <ibd/ibd.h>

#ifdef IBHOSTS_NAMING
#define	MAP_FILE		"/etc/dapl/ibhosts"
#define	MAX_GID_ENTRIES		32
DAPL_GID_MAP			g_gid_map_table[MAX_GID_ENTRIES];

DAT_RETURN dapli_ns_create_gid_map(void);
DAT_RETURN dapli_ns_add_address(IN DAPL_GID_MAP	*gme);
#endif /* IBHOSTS_NAMING */

/*
 * dapls_ns_init
 *
 * Initialize naming services
 *
 * Input:
 *	none
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapls_ns_init(void)
{
	DAT_RETURN	dat_status;

	dat_status = DAT_SUCCESS;
#ifdef IBHOSTS_NAMING
	dat_status = dapli_ns_create_gid_map();
#endif /* IBHOSTS_NAMING */

	return (dat_status);
}

#ifdef IBHOSTS_NAMING
/*
 * dapls_create_gid_map()
 *
 * Read /usr/local/etc/ibhosts to obtain host names and GIDs.
 * Create a table containing IP addresses and GIDs which can
 * be used for lookups.
 *
 * This implementation is a simple method providing name services
 * when more advanced mechanisms do not exist. The proper way
 * to obtain these mappings is to use a name service such as is
 * provided by IPoIB on InfiniBand.
 *
 * Input:
 *	device_name		Name of device as reported by the provider
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	char * to string number
 */
DAT_RETURN
dapli_ns_create_gid_map(void)
{
	FILE			*f;
	ib_gid_t		gid;
	char			hostname[128];
	int			rc;
	struct addrinfo		*addr;
	struct sockaddr_in	*si;
	DAPL_GID_MAP		gmt;

	f = fopen(MAP_FILE, "r");
	if (f == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, "ERROR: Must have file <%s> "
		    "for IP/GID mappings\n", MAP_FILE);
		return (DAT_ERROR(DAT_INTERNAL_ERROR, 0));
	}

	rc = fscanf(f, "%s " F64x " " F64x, hostname,
	    &gid.gid_prefix, &gid.gid_guid);
	while (rc != EOF) {
		rc = dapls_osd_getaddrinfo(hostname, &addr);

		if (rc != 0) {
			/*
			 * hostname not registered in DNS,
			 * provide a dummy value
			 */
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "WARNING: <%s> not registered in "
			    "DNS, using dummy IP value\n", hostname);
			gmt.ip_address = 0x01020304;
		} else {
			/*
			 * Load into the ip/gid mapping table
			 */
			si = (struct sockaddr_in *)addr->ai_addr;
			if (AF_INET == addr->ai_addr->sa_family) {
				gmt.ip_address = si->sin_addr.s_addr;
			} else {
				dapl_dbg_log(DAPL_DBG_TYPE_ERR,
				    "WARNING: <%s> Address family "
				    "not supported, using dummy "
				    "IP value\n", hostname);
				gmt.ip_address = 0x01020304;
			}
			dapls_osd_freeaddrinfo(addr);
		}
		gmt.gid.gid_prefix = gid.gid_prefix;
		gmt.gid.gid_guid = gid.gid_guid;

		dapli_ns_add_address(&gmt);
		rc = fscanf(f, "%s " F64x " " F64x, hostname,
		    &gid.gid_prefix, &gid.gid_guid);
	}
	(void) fclose(f);
	return (DAT_SUCCESS);
}

/*
 * dapli_ns_add_address
 *
 * Add a table entry to the  gid_map_table.
 *
 * Input:
 *	remote_ia_address	remote IP address
 *	gid			pointer to output gid
 *
 * Output:
 * 	gid			filled in GID
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapli_ns_add_address(
	IN DAPL_GID_MAP	*gme)
{
	DAPL_GID_MAP	*gmt;
	int		count;

	gmt = g_gid_map_table;
	for (count = 0, gmt = g_gid_map_table; gmt->ip_address; gmt++) {
		count++;
	}
	if (count > MAX_GID_ENTRIES) {
		return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES, 0));
	}

	*gmt = *gme;
	return (DAT_SUCCESS);
}

/*
 * dapls_ns_lookup_address
 *
 * Look up the provided IA_ADDRESS in the gid_map_table. Return
 * the gid if found.
 *
 * Input:
 *	remote_ia_address	remote IP address
 *	gid			pointer to output gid
 *	timeout			timeout in microseconds
 *
 * Output:
 * 	gid			filled in GID
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapls_ns_lookup_address(
	IN  DAPL_IA			*ia_ptr,
	IN  DAT_IA_ADDRESS_PTR		remote_ia_address,
	IN  DAT_TIMEOUT			timeout,
	OUT ib_gid_t			*gid)
{
	DAPL_GID_MAP		*gmt;
	struct sockaddr_in	*si;

	/* unused here */
	ia_ptr = ia_ptr;
	si = (struct sockaddr_in *)remote_ia_address;

	for (gmt = g_gid_map_table; gmt->ip_address; gmt++) {
		if (gmt->ip_address == si->sin_addr.s_addr) {
			gid->gid_guid = gmt->gid.gid_guid;
			gid->gid_prefix = gmt->gid.gid_prefix;
			return (DAT_SUCCESS);
		}
	}
	return (DAT_ERROR(DAT_INVALID_PARAMETER, 0));
}
#endif /* IBHOSTS_NAMING */

/*
 * utility function for printing a socket
 */
char *
dapls_inet_ntop(struct sockaddr *addr, char *buf, size_t len)
{
	void	*addr_ptr;

	if (addr->sa_family == AF_INET) {
		/* LINTED: E_BAD_PTR_CAST_ALIGN */
		addr_ptr = (void *)&((struct sockaddr_in *)addr)->sin_addr;
	} else if (addr->sa_family == AF_INET6) {
		/* LINTED: E_BAD_PTR_CAST_ALIGN */
		addr_ptr = (void *)&((struct sockaddr_in6 *)addr)->sin6_addr;
	} else {
		if (len > strlen("bad address")) {
			(void) sprintf(buf, "bad address");
		}
		return (buf);
	}
	return ((char *)inet_ntop(addr->sa_family, addr_ptr, buf, len));
}

/*
 * dapls_ns_lookup_address
 *
 * translates an IP address into a GID
 *
 * Input:
 * 	ia_ptr			pointer to IA object
 *	remote_ia_address	remote IP address
 *	gid			pointer to output gid
 *	timeout			timeout in microseconds
 *
 * Output:
 * 	gid			filled in GID
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_ADDRRESS
 *	DAT_INVALID_PARAMETER
 *	DAT_INTERNAL_ERROR
 */

#define	NS_MAX_RETRIES	60

DAT_RETURN
dapls_ns_lookup_v4(
	IN  DAPL_IA			*ia_ptr,
	IN  struct sockaddr_in		*addr,
	IN  DAT_TIMEOUT			timeout,
	OUT ib_gid_t			*gid);
DAT_RETURN
dapls_ns_lookup_v6(
	IN  DAPL_IA			*ia_ptr,
	IN  struct sockaddr_in6		*addr,
	IN  DAT_TIMEOUT			timeout,
	OUT ib_gid_t			*gid);

static int dapls_ns_subnet_match_v4(int s, DAPL_IA *ia_ptr,
    struct sockaddr_in *addr);
static int dapls_ns_subnet_match_v6(int s, DAPL_IA *ia_ptr,
    struct sockaddr_in6 *addr);

static int dapls_ns_send_packet_v6(int s, struct sockaddr_in6 *addr);
static int dapls_ns_resolve_addr(int af, struct sockaddr *addr,
    DAT_TIMEOUT timeout);

DAT_RETURN
dapls_ns_lookup_address(
	IN  DAPL_IA			*ia_ptr,
	IN  DAT_IA_ADDRESS_PTR		remote_ia_address,
	IN  DAT_TIMEOUT			timeout,
	OUT ib_gid_t			*gid)
{
	DAT_RETURN		dat_status;
	struct sockaddr		*sock = (struct sockaddr *)remote_ia_address;

	if (sock->sa_family == AF_INET) {
		dat_status = dapls_ns_lookup_v4(ia_ptr,
		    /* LINTED: E_BAD_PTR_CAST_ALIGN */
		    (struct sockaddr_in *)sock, timeout, gid);
	} else if (sock->sa_family == AF_INET6) {
		dat_status = dapls_ns_lookup_v6(ia_ptr,
		    /* LINTED: E_BAD_PTR_CAST_ALIGN */
		    (struct sockaddr_in6 *)sock, timeout, gid);
	} else {
		dat_status = DAT_INVALID_PARAMETER;
	}
	return (dat_status);
}

DAT_RETURN
dapls_ns_lookup_v4(
	IN  DAPL_IA			*ia_ptr,
	IN  struct sockaddr_in		*addr,
	IN  DAT_TIMEOUT			timeout,
	OUT ib_gid_t			*gid)
{
	struct xarpreq		ar;
	struct sockaddr_in	*sin;
	uchar_t			*mac;
	int			s, retries = 0;

	(void) dapl_os_memzero(&ar, sizeof (ar));
	sin = (struct sockaddr_in *)&ar.xarp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr->sin_addr.s_addr;
	ar.xarp_ha.sdl_family = AF_LINK;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_lookup_v4: socket: %s\n", strerror(errno));
		return (DAT_INTERNAL_ERROR);
	}
	if (dapls_ns_subnet_match_v4(s, ia_ptr, addr) != 0) {
		(void) close(s);
		return (DAT_INVALID_ADDRESS);
	}
again:;
	if (ioctl(s, SIOCGXARP, (caddr_t)&ar) < 0) {
		/*
		 * if SIOCGXARP failed, we force the ARP
		 * cache to be filled by connecting to the
		 * destination IP address.
		 */
		if (retries <= NS_MAX_RETRIES &&
		    dapls_ns_resolve_addr(AF_INET, (struct sockaddr *)addr,
		    timeout) == 0) {
			retries++;
			goto again;
		}
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, "ns_lookup_v4: giving up\n");
		(void) close(s);
		return (DAT_ERROR(DAT_INVALID_ADDRESS,
		    DAT_INVALID_ADDRESS_UNREACHABLE));
	}
	if ((ar.xarp_flags & ATF_COM) == 0 &&
	    ar.xarp_ha.sdl_type == IFT_IB && retries <= NS_MAX_RETRIES) {
		/*
		 * we get here if arp resolution is still incomplete
		 */
		retries++;
		(void) sleep(1);
		goto again;
	}
	(void) close(s);

	mac = (uchar_t *)LLADDR(&ar.xarp_ha);
	if (ar.xarp_flags & ATF_COM &&
	    ar.xarp_ha.sdl_type == IFT_IB &&
	    ar.xarp_ha.sdl_alen >= sizeof (ipoib_mac_t)) {
		ib_gid_t tmp_gid;

		/* LINTED: E_BAD_PTR_CAST_ALIGN */
		(void) dapl_os_memcpy(&tmp_gid,
		    &((ipoib_mac_t *)mac)->ipoib_gidpref, sizeof (ib_gid_t));
		/*
		 * gids from the ARP table are in network order, convert
		 * the gids from network order to host byte order
		 */
		gid->gid_prefix = BETOH_64(tmp_gid.gid_prefix);
		gid->gid_guid = BETOH_64(tmp_gid.gid_guid);
	} else {
		int i, len;

		len = ar.xarp_ha.sdl_alen;
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_lookup_v4: failed, non IB address: "
		    "len = %d, addr = 0x", len);
		if (len > 0) {
			for (i = 0; i < len; i++) {
				dapl_dbg_log(DAPL_DBG_TYPE_ERR,
				    "%02x", (int)mac[i] & 0xff);
			}
		} else {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR, "0");
		}
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, "\n");
		return (DAT_INVALID_ADDRESS);
	}
	return (DAT_SUCCESS);
}

DAT_RETURN
dapls_ns_lookup_v6(
	IN  DAPL_IA			*ia_ptr,
	IN  struct sockaddr_in6		*addr,
	IN  DAT_TIMEOUT			timeout,
	OUT ib_gid_t			*gid)
{
	struct lifreq		lifr;
	uchar_t			*mac;
	int			s, retries = 0;

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s < 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_lookup_v6: socket: %s\n", strerror(errno));
		return (DAT_INTERNAL_ERROR);
	}
	if (dapls_ns_subnet_match_v6(s, ia_ptr, addr) != 0) {
		(void) close(s);
		return (DAT_INVALID_ADDRESS);
	}
	(void) dapl_os_memzero(&lifr, sizeof (lifr));
	(void) dapl_os_memcpy(&lifr.lifr_nd.lnr_addr, addr, sizeof (*addr));
	(void) dapl_os_strcpy(lifr.lifr_name, ia_ptr->hca_ptr->name);

again:;
	if (ioctl(s, SIOCLIFGETND, (caddr_t)&lifr) < 0)  {
		/*
		 * if SIOCLIFGETND failed, we force the ND
		 * cache to be filled by connecting to the
		 * destination IP address.
		 */
		if (retries < NS_MAX_RETRIES &&
		    dapls_ns_send_packet_v6(s, addr) == 0 &&
		    dapls_ns_resolve_addr(AF_INET6, (struct sockaddr *)addr,
		    timeout) == 0) {
			retries++;
			goto again;
		}
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, "ns_lookup_v6: giving up\n");
		(void) close(s);
		return (DAT_ERROR(DAT_INVALID_ADDRESS,
		    DAT_INVALID_ADDRESS_UNREACHABLE));
	}
	if (lifr.lifr_nd.lnr_hdw_len == 0 && retries <= NS_MAX_RETRIES) {
		/*
		 * lnr_hdw_len == 0 means that the ND entry
		 * is still incomplete. we need to retry the ioctl.
		 */
		retries++;
		(void) sleep(1);
		goto again;
	}
	(void) close(s);

	mac = (uchar_t *)lifr.lifr_nd.lnr_hdw_addr;
	if (lifr.lifr_nd.lnr_hdw_len >= sizeof (ipoib_mac_t)) {
		ib_gid_t tmp_gid;
		/* LINTED: E_BAD_PTR_CAST_ALIGN */
		(void) dapl_os_memcpy(&tmp_gid,
		    &((ipoib_mac_t *)mac)->ipoib_gidpref, sizeof (ib_gid_t));
		/*
		 * gids from the ND table are in network order, convert
		 * the gids from network order to host byte order
		 */
		gid->gid_prefix = BETOH_64(tmp_gid.gid_prefix);
		gid->gid_guid = BETOH_64(tmp_gid.gid_guid);
	} else {
		int i, len;

		len = lifr.lifr_nd.lnr_hdw_len;
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_lookup_v6: failed, non IB address: "
		    "len = %d, addr = 0x", len);
		if (len > 0) {
			for (i = 0; i < len; i++) {
				dapl_dbg_log(DAPL_DBG_TYPE_ERR,
				    "%02x", (int)mac[i] & 0xff);
			}
		} else {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR, "0");
		}
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, "\n");
		return (DAT_INVALID_ADDRESS);
	}
	return (DAT_SUCCESS);
}

static int
dapls_ns_send_packet_v6(int s, struct sockaddr_in6 *addr)
{
	if (sendto(s, NULL, 0, MSG_DONTROUTE, (struct sockaddr *)addr,
	    sizeof (*addr)) < 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_send_packet_v6: failed: %s\n", strerror(errno));
		return (-1);
	}
	return (0);
}

static int
dapls_ns_subnet_match_v4(int s, DAPL_IA *ia_ptr, struct sockaddr_in *addr)
{
	struct lifreq		lifreq;
	int			retval;
	uint32_t		netmask, netaddr, netaddr_dest;

	(void) dapl_os_strcpy(lifreq.lifr_name, ia_ptr->hca_ptr->name);

	retval = ioctl(s, SIOCGLIFNETMASK, (caddr_t)&lifreq);
	if (retval < 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_subnet_match_v4: cannot get netmask: %s\n",
		    strerror(errno));
		return (-1);
	}
	netmask = ((struct sockaddr_in *)&lifreq.lifr_addr)->
	    sin_addr.s_addr;

	/*
	 * we need to get the interface address here because the
	 * address in ia_ptr->hca_ptr->hca_address might not
	 * necessarily be an IPv4 address.
	 */
	retval = ioctl(s, SIOCGLIFADDR, (caddr_t)&lifreq);
	if (retval < 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_subnet_match_v4: cannot get local addr: %s\n",
		    strerror(errno));
		return (-1);
	}
	netaddr = ((struct sockaddr_in *)&lifreq.lifr_addr)->
	    sin_addr.s_addr & netmask;
	netaddr_dest = addr->sin_addr.s_addr & netmask;

	if (netaddr != netaddr_dest) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_subnet_match_v4: netaddrs don't match: "
		    "local %x, remote %x\n", netaddr, netaddr_dest);
		return (-1);
	}
	return (0);
}

static int
dapls_ns_subnet_match_v6(int s, DAPL_IA *ia_ptr, struct sockaddr_in6 *addr)
{
	struct lifreq		lifreq;
	struct sockaddr_in6	netmask_sock;
	uchar_t			*netmask, *local_addr, *dest_addr;
	int			i, retval;

	(void) dapl_os_strcpy(lifreq.lifr_name, ia_ptr->hca_ptr->name);

	retval = ioctl(s, SIOCGLIFNETMASK, (caddr_t)&lifreq);
	if (retval < 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_subnet_match_v6: cannot get netmask: %s\n",
		    strerror(errno));
		return (-1);
	}
	(void) dapl_os_memcpy(&netmask_sock, &lifreq.lifr_addr,
	    sizeof (netmask_sock));

	/*
	 * we need to get the interface address here because the
	 * address in ia_ptr->hca_ptr->hca_address might not
	 * necessarily be an IPv6 address.
	 */
	retval = ioctl(s, SIOCGLIFADDR, (caddr_t)&lifreq);
	if (retval < 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_subnet_match_v6: cannot get local addr: %s\n",
		    strerror(errno));
		return (-1);
	}
	netmask = (uchar_t *)&netmask_sock.sin6_addr;
	local_addr = (uchar_t *)&((struct sockaddr_in6 *)&lifreq.lifr_addr)->
	    sin6_addr;
	dest_addr = (uchar_t *)&addr->sin6_addr;

	for (i = 0; i < sizeof (addr->sin6_addr); i++) {
		if (((local_addr[i] ^ dest_addr[i]) & netmask[i]) != 0) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "ns_subnet_match_v6: subnets do not match\n");
			return (-1);
		}
	}
	return (0);
}

static int
dapls_ns_resolve_addr(int af, struct sockaddr *addr, DAT_TIMEOUT timeout)
{
	struct sockaddr_storage	sock;
	struct sockaddr_in	*v4dest;
	struct sockaddr_in6	*v6dest;
	struct pollfd		pollfd;
	int			fd, retval;
	int			tmo;
	int			ip_version;

	if (af == AF_INET) {
		ip_version = 4;
	} else if (af == AF_INET6) {
		ip_version = 6;
	} else {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_resolve_addr: invalid af %d\n", af);
		return (-1);
	}
	fd = socket(af, SOCK_STREAM, 0);
	if (fd < 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_resolve_addr: ipv%d, cannot create socket %s\n",
		    ip_version, strerror(errno));
		return (-1);
	}

	/*
	 * set socket to non-blocking mode
	 */
	retval = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (retval < 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_resolve_addr: ipv%d, fcntl failed: %s\n",
		    ip_version, strerror(errno));
		(void) close(fd);
		return (-1);
	}

	/*
	 * connect to the discard port (9) at the dest IP
	 */
	(void) dapl_os_memzero(&sock, sizeof (sock));
	if (af == AF_INET) {
		v4dest = (struct sockaddr_in *)&sock;
		v4dest->sin_family = AF_INET;
		v4dest->sin_addr.s_addr =
		    /* LINTED: E_BAD_PTR_CAST_ALIGN */
		    ((struct sockaddr_in *)addr)->sin_addr.s_addr;
		v4dest->sin_port = htons(9);

		retval = connect(fd, (struct sockaddr *)v4dest,
		    sizeof (struct sockaddr_in));
	} else {
		v6dest = (struct sockaddr_in6 *)&sock;
		v6dest->sin6_family = AF_INET6;
		/* LINTED: E_BAD_PTR_CAST_ALIGN */
		(void) dapl_os_memcpy(&v6dest->sin6_addr,
		    &((struct sockaddr_in6 *)addr)->sin6_addr,
		    sizeof (struct sockaddr_in6));
		v6dest->sin6_port = htons(9);

		retval = connect(fd, (struct sockaddr *)v6dest,
		    sizeof (struct sockaddr_in6));
	}

	/*
	 * we can return immediately if connect succeeds
	 */
	if (retval == 0) {
		(void) close(fd);
		return (0);
	}
	/*
	 * receiving a RST means that the arp/nd entry should
	 * already be resolved
	 */
	if (retval < 0 && errno == ECONNREFUSED) {
		errno = 0;
		(void) close(fd);
		return (0);
	}

	/*
	 * for all other cases, we poll on the fd
	 */
	pollfd.fd = fd;
	pollfd.events = POLLIN | POLLOUT;
	pollfd.revents = 0;

	if (timeout == DAT_TIMEOUT_INFINITE ||
	    timeout == 0) {
		/*
		 * -1 means infinite
		 */
		tmo = -1;
	} else {
		/*
		 * convert timeout from usecs to msecs
		 */
		tmo = timeout/1000;
	}
	retval = poll(&pollfd, 1, tmo);
	if (retval > 0) {
		int	so_error = 0, len = sizeof (so_error);

		retval = getsockopt(fd, SOL_SOCKET, SO_ERROR,
		    &so_error, &len);
		if (retval == 0) {
			/*
			 * we only return 0 if so_error == 0 or
			 * so_error == ECONNREFUSED. for all other
			 * cases retval is non-zero.
			 */
			if (so_error != 0 && so_error != ECONNREFUSED) {
				retval = -1;
				errno = so_error;
				dapl_dbg_log(DAPL_DBG_TYPE_ERR,
				    "ns_resolve_addr: ipv%d, so_error: %s\n",
				    ip_version, strerror(errno));
			}
		} else {
			/*
			 * if retval != 0, it must be -1. and errno must
			 * have been set by getsockopt.
			 */
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "ns_resolve_addr: ipv%d, getsockopt: %s\n",
			    ip_version, strerror(errno));
		}
	} else {
		if (retval == 0) {
			errno = ETIMEDOUT;
		}
		retval = -1;
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "ns_resolve_addr: ipv%d, poll: %s\n",
		    ip_version, strerror(errno));
	}
	(void) close(fd);
	return (retval);
}
