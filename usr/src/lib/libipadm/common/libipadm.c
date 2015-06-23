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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/sockio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/route.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <arpa/inet.h>
#include <libintl.h>
#include <libdlpi.h>
#include <libinetutil.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdliptun.h>
#include <strings.h>
#include <zone.h>
#include <ctype.h>
#include <limits.h>
#include <assert.h>
#include <netdb.h>
#include <pwd.h>
#include <auth_attr.h>
#include <secdb.h>
#include <nss_dbdefs.h>
#include "libipadm_impl.h"

/* error codes and text description */
static struct ipadm_error_info {
	ipadm_status_t	error_code;
	const char	*error_desc;
} ipadm_errors[] = {
	{ IPADM_SUCCESS,	"Operation succeeded" },
	{ IPADM_FAILURE,	"Operation failed" },
	{ IPADM_EAUTH,		"Insufficient user authorizations" },
	{ IPADM_EPERM,		"Permission denied" },
	{ IPADM_NO_BUFS,	"No buffer space available" },
	{ IPADM_NO_MEMORY,	"Insufficient memory" },
	{ IPADM_BAD_ADDR,	"Invalid address" },
	{ IPADM_BAD_PROTOCOL,	"Incorrect protocol family for operation" },
	{ IPADM_DAD_FOUND,	"Duplicate address detected" },
	{ IPADM_EXISTS,		"Already exists" },
	{ IPADM_IF_EXISTS,	"Interface already exists" },
	{ IPADM_ADDROBJ_EXISTS, "Address object already exists" },
	{ IPADM_ADDRCONF_EXISTS, "Addrconf already in progress" },
	{ IPADM_ENXIO,		"Interface does not exist" },
	{ IPADM_GRP_NOTEMPTY,	"IPMP group is not empty" },
	{ IPADM_INVALID_ARG,	"Invalid argument provided" },
	{ IPADM_INVALID_NAME,	"Invalid name" },
	{ IPADM_DLPI_FAILURE,	"Could not open DLPI link" },
	{ IPADM_DLADM_FAILURE,	"Datalink does not exist" },
	{ IPADM_PROP_UNKNOWN,   "Unknown property" },
	{ IPADM_ERANGE,		"Value is outside the allowed range" },
	{ IPADM_ESRCH,		"Value does not exist" },
	{ IPADM_EOVERFLOW,	"Number of values exceeds the allowed limit" },
	{ IPADM_NOTFOUND,	"Object not found" },
	{ IPADM_IF_INUSE,	"Interface already in use" },
	{ IPADM_ADDR_INUSE,	"Address already in use" },
	{ IPADM_BAD_HOSTNAME,	"Hostname maps to multiple IP addresses" },
	{ IPADM_ADDR_NOTAVAIL,	"Can't assign requested address" },
	{ IPADM_ALL_ADDRS_NOT_ENABLED, "All addresses could not be enabled" },
	{ IPADM_NDPD_NOT_RUNNING, "IPv6 autoconf daemon in.ndpd not running" },
	{ IPADM_DHCP_START_ERROR, "Could not start dhcpagent" },
	{ IPADM_DHCP_IPC_ERROR,	"Could not communicate with dhcpagent" },
	{ IPADM_DHCP_IPC_TIMEOUT, "Communication with dhcpagent timed out" },
	{ IPADM_TEMPORARY_OBJ,	"Persistent operation on temporary object" },
	{ IPADM_IPC_ERROR,	"Could not communicate with ipmgmtd" },
	{ IPADM_NOTSUP,		"Operation not supported" },
	{ IPADM_OP_DISABLE_OBJ, "Operation not supported on disabled object" },
	{ IPADM_EBADE,		"Invalid data exchange with daemon" },
	{ IPADM_GZ_PERM,	"Operation not permitted on from-gz interface"}
};

#define	IPADM_NUM_ERRORS	(sizeof (ipadm_errors) / sizeof (*ipadm_errors))

ipadm_status_t
ipadm_errno2status(int error)
{
	switch (error) {
	case 0:
		return (IPADM_SUCCESS);
	case ENXIO:
		return (IPADM_ENXIO);
	case ENOMEM:
		return (IPADM_NO_MEMORY);
	case ENOBUFS:
		return (IPADM_NO_BUFS);
	case EINVAL:
		return (IPADM_INVALID_ARG);
	case EBUSY:
		return (IPADM_IF_INUSE);
	case EEXIST:
		return (IPADM_EXISTS);
	case EADDRNOTAVAIL:
		return (IPADM_ADDR_NOTAVAIL);
	case EADDRINUSE:
		return (IPADM_ADDR_INUSE);
	case ENOENT:
		return (IPADM_NOTFOUND);
	case ERANGE:
		return (IPADM_ERANGE);
	case EPERM:
		return (IPADM_EPERM);
	case ENOTSUP:
	case EOPNOTSUPP:
		return (IPADM_NOTSUP);
	case EBADF:
		return (IPADM_IPC_ERROR);
	case EBADE:
		return (IPADM_EBADE);
	case ESRCH:
		return (IPADM_ESRCH);
	case EOVERFLOW:
		return (IPADM_EOVERFLOW);
	default:
		return (IPADM_FAILURE);
	}
}

/*
 * Returns a message string for the given libipadm error status.
 */
const char *
ipadm_status2str(ipadm_status_t status)
{
	int	i;

	for (i = 0; i < IPADM_NUM_ERRORS; i++) {
		if (status == ipadm_errors[i].error_code)
			return (dgettext(TEXT_DOMAIN,
			    ipadm_errors[i].error_desc));
	}

	return (dgettext(TEXT_DOMAIN, "<unknown error>"));
}

/*
 * Opens a handle to libipadm.
 * Possible values for flags:
 *  IPH_VRRP:	Used by VRRP daemon to set the socket option SO_VRRP.
 *  IPH_LEGACY:	This is used whenever an application needs to provide a
 *		logical interface name while creating or deleting
 *		interfaces and static addresses.
 *  IPH_INIT:   Used by ipadm_init_prop(), to initialize protocol properties
 *		on reboot.
 */
ipadm_status_t
ipadm_open(ipadm_handle_t *handle, uint32_t flags)
{
	ipadm_handle_t	iph;
	ipadm_status_t	status = IPADM_SUCCESS;
	zoneid_t	zoneid;
	ushort_t	zflags;
	int		on = B_TRUE;

	if (handle == NULL)
		return (IPADM_INVALID_ARG);
	*handle = NULL;

	if (flags & ~(IPH_VRRP|IPH_LEGACY|IPH_INIT|IPH_IPMGMTD))
		return (IPADM_INVALID_ARG);

	if ((iph = calloc(1, sizeof (struct ipadm_handle))) == NULL)
		return (IPADM_NO_MEMORY);
	iph->iph_sock = -1;
	iph->iph_sock6 = -1;
	iph->iph_door_fd = -1;
	iph->iph_rtsock = -1;
	iph->iph_flags = flags;
	(void) pthread_mutex_init(&iph->iph_lock, NULL);

	if ((iph->iph_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ||
	    (iph->iph_sock6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		goto errnofail;
	}

	/*
	 * We open a handle to libdladm here, to facilitate some daemons (like
	 * nwamd) which opens handle to libipadm before devfsadmd installs the
	 * right device permissions into the kernel and requires "all"
	 * privileges to open DLD_CONTROL_DEV.
	 *
	 * In a non-global shared-ip zone there will be no DLD_CONTROL_DEV node
	 * and dladm_open() will fail. So, we avoid this by not calling
	 * dladm_open() for such zones.
	 */
	zoneid = getzoneid();
	iph->iph_zoneid = zoneid;
	if (zoneid != GLOBAL_ZONEID) {
		if (zone_getattr(zoneid, ZONE_ATTR_FLAGS, &zflags,
		    sizeof (zflags)) < 0) {
			goto errnofail;
		}
	}
	if ((zoneid == GLOBAL_ZONEID) || (zflags & ZF_NET_EXCL)) {
		if (dladm_open(&iph->iph_dlh) != DLADM_STATUS_OK) {
			ipadm_close(iph);
			return (IPADM_DLADM_FAILURE);
		}
		if (zoneid != GLOBAL_ZONEID) {
			iph->iph_rtsock = socket(PF_ROUTE, SOCK_RAW, 0);
			/*
			 * Failure to open rtsock is ignored as this is
			 * only used in non-global zones to initialize
			 * routing socket information.
			 */
		}
	} else {
		assert(zoneid != GLOBAL_ZONEID);
		iph->iph_dlh = NULL;
	}
	if (flags & IPH_VRRP) {
		if (setsockopt(iph->iph_sock6, SOL_SOCKET, SO_VRRP, &on,
		    sizeof (on)) < 0 || setsockopt(iph->iph_sock, SOL_SOCKET,
		    SO_VRRP, &on, sizeof (on)) < 0) {
			goto errnofail;
		}
	}
	*handle = iph;
	return (status);

errnofail:
	status = ipadm_errno2status(errno);
	ipadm_close(iph);
	return (status);
}

/*
 * Closes and frees the libipadm handle.
 */
void
ipadm_close(ipadm_handle_t iph)
{
	if (iph == NULL)
		return;
	if (iph->iph_sock != -1)
		(void) close(iph->iph_sock);
	if (iph->iph_sock6 != -1)
		(void) close(iph->iph_sock6);
	if (iph->iph_rtsock != -1)
		(void) close(iph->iph_rtsock);
	if (iph->iph_door_fd != -1)
		(void) close(iph->iph_door_fd);
	dladm_close(iph->iph_dlh);
	(void) pthread_mutex_destroy(&iph->iph_lock);
	free(iph);
}

/*
 * Checks if the caller has the authorization to configure network
 * interfaces.
 */
boolean_t
ipadm_check_auth(void)
{
	struct passwd	pwd;
	char		buf[NSS_BUFLEN_PASSWD];

	/* get the password entry for the given user ID */
	if (getpwuid_r(getuid(), &pwd, buf, sizeof (buf)) == NULL)
		return (B_FALSE);

	/* check for presence of given authorization */
	return (chkauthattr(NETWORK_INTERFACE_CONFIG_AUTH, pwd.pw_name) != 0);
}

/*
 * Stores the index value of the interface in `ifname' for the address
 * family `af' into the buffer pointed to by `index'.
 */
static ipadm_status_t
i_ipadm_get_index(ipadm_handle_t iph, const char *ifname, sa_family_t af,
    int *index)
{
	struct lifreq	lifr;
	int		sock;

	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (af == AF_INET)
		sock = iph->iph_sock;
	else
		sock = iph->iph_sock6;

	if (ioctl(sock, SIOCGLIFINDEX, (caddr_t)&lifr) < 0)
		return (ipadm_errno2status(errno));
	*index = lifr.lifr_index;

	return (IPADM_SUCCESS);
}

/*
 * Maximum amount of time (in milliseconds) to wait for Duplicate Address
 * Detection to complete in the kernel.
 */
#define	DAD_WAIT_TIME		1000

/*
 * Any time that flags are changed on an interface where either the new or the
 * existing flags have IFF_UP set, we'll get a RTM_NEWADDR message to
 * announce the new address added and its flag status.
 * We wait here for that message and look for IFF_UP.
 * If something's amiss with the kernel, though, we don't wait forever.
 * (Note that IFF_DUPLICATE is a high-order bit, and we cannot see
 * it in the routing socket messages.)
 */
static ipadm_status_t
i_ipadm_dad_wait(ipadm_handle_t handle, const char *lifname, sa_family_t af,
    int rtsock)
{
	struct pollfd	fds[1];
	union {
		struct if_msghdr ifm;
		char buf[1024];
	} msg;
	int		index;
	ipadm_status_t	retv;
	uint64_t	flags;
	hrtime_t	starttime, now;

	fds[0].fd = rtsock;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	retv = i_ipadm_get_index(handle, lifname, af, &index);
	if (retv != IPADM_SUCCESS)
		return (retv);

	starttime = gethrtime();
	for (;;) {
		now = gethrtime();
		now = (now - starttime) / 1000000;
		if (now >= DAD_WAIT_TIME)
			break;
		if (poll(fds, 1, DAD_WAIT_TIME - (int)now) <= 0)
			break;
		if (read(rtsock, &msg, sizeof (msg)) <= 0)
			break;
		if (msg.ifm.ifm_type != RTM_NEWADDR)
			continue;
		/* Note that ifm_index is just 16 bits */
		if (index == msg.ifm.ifm_index && (msg.ifm.ifm_flags & IFF_UP))
			return (IPADM_SUCCESS);
	}

	retv = i_ipadm_get_flags(handle, lifname, af, &flags);
	if (retv != IPADM_SUCCESS)
		return (retv);
	if (flags & IFF_DUPLICATE)
		return (IPADM_DAD_FOUND);

	return (IPADM_SUCCESS);
}

/*
 * Sets the flags `on_flags' and resets the flags `off_flags' for the logical
 * interface in `lifname'.
 *
 * If the new flags value will transition the interface from "down" to "up"
 * then duplicate address detection is performed by the kernel.  This routine
 * waits to get the outcome of that test.
 */
ipadm_status_t
i_ipadm_set_flags(ipadm_handle_t iph, const char *lifname, sa_family_t af,
    uint64_t on_flags, uint64_t off_flags)
{
	struct lifreq	lifr;
	uint64_t	oflags;
	ipadm_status_t	ret;
	int		rtsock = -1;
	int		sock, err;

	ret = i_ipadm_get_flags(iph, lifname, af, &oflags);
	if (ret != IPADM_SUCCESS)
		return (ret);

	sock = (af == AF_INET ? iph->iph_sock : iph->iph_sock6);

	/*
	 * Any time flags are changed on an interface that has IFF_UP set,
	 * we get a routing socket message.  We care about the status,
	 * though, only when the new flags are marked "up."
	 */
	if (!(oflags & IFF_UP) && (on_flags & IFF_UP))
		rtsock = socket(PF_ROUTE, SOCK_RAW, af);

	oflags |= on_flags;
	oflags &= ~off_flags;
	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, lifname, sizeof (lifr.lifr_name));
	lifr.lifr_flags = oflags;
	if (ioctl(sock, SIOCSLIFFLAGS, (caddr_t)&lifr) < 0) {
		err = errno;
		if (rtsock != -1)
			(void) close(rtsock);
		return (ipadm_errno2status(err));
	}
	if (rtsock == -1) {
		return (IPADM_SUCCESS);
	} else {
		/* Wait for DAD to complete. */
		ret = i_ipadm_dad_wait(iph, lifname, af, rtsock);
		(void) close(rtsock);
		return (ret);
	}
}

/*
 * Returns the flags value for the logical interface in `lifname'
 * in the buffer pointed to by `flags'.
 */
ipadm_status_t
i_ipadm_get_flags(ipadm_handle_t iph, const char *lifname, sa_family_t af,
    uint64_t *flags)
{
	struct lifreq	lifr;
	int		sock;

	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, lifname, sizeof (lifr.lifr_name));
	if (af == AF_INET)
		sock = iph->iph_sock;
	else
		sock = iph->iph_sock6;

	if (ioctl(sock, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		return (ipadm_errno2status(errno));
	}
	*flags = lifr.lifr_flags;

	return (IPADM_SUCCESS);
}

/*
 * Determines whether or not an interface name represents a loopback
 * interface, before the interface has been plumbed.
 * It is assumed that the interface name in `ifname' is of correct format
 * as verified by ifparse_ifspec().
 *
 * Returns: B_TRUE if loopback, B_FALSE if not.
 */
boolean_t
i_ipadm_is_loopback(const char *ifname)
{
	int len = strlen(LOOPBACK_IF);

	return (strncmp(ifname, LOOPBACK_IF, len) == 0 &&
	    (ifname[len] == '\0' || ifname[len] == IPADM_LOGICAL_SEP));
}

/*
 * Determines whether or not an interface name represents a vni
 * interface, before the interface has been plumbed.
 * It is assumed that the interface name in `ifname' is of correct format
 * as verified by ifparse_ifspec().
 *
 * Returns: B_TRUE if vni, B_FALSE if not.
 */
boolean_t
i_ipadm_is_vni(const char *ifname)
{
	ifspec_t	ifsp;

	return (ifparse_ifspec(ifname, &ifsp) &&
	    strcmp(ifsp.ifsp_devnm, "vni") == 0);
}

/*
 * Returns B_TRUE if `ifname' is an IP interface on a 6to4 tunnel.
 */
boolean_t
i_ipadm_is_6to4(ipadm_handle_t iph, char *ifname)
{
	dladm_status_t		dlstatus;
	datalink_class_t	class;
	iptun_params_t		params;
	datalink_id_t		linkid;

	if (iph->iph_dlh == NULL) {
		assert(iph->iph_zoneid != GLOBAL_ZONEID);
		return (B_FALSE);
	}
	dlstatus = dladm_name2info(iph->iph_dlh, ifname, &linkid, NULL,
	    &class, NULL);
	if (dlstatus == DLADM_STATUS_OK && class == DATALINK_CLASS_IPTUN) {
		params.iptun_param_linkid = linkid;
		dlstatus = dladm_iptun_getparams(iph->iph_dlh, &params,
		    DLADM_OPT_ACTIVE);
		if (dlstatus == DLADM_STATUS_OK &&
		    params.iptun_param_type == IPTUN_TYPE_6TO4) {
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * Returns B_TRUE if `ifname' represents an IPMP underlying interface.
 */
boolean_t
i_ipadm_is_under_ipmp(ipadm_handle_t iph, const char *ifname)
{
	struct lifreq	lifr;

	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (ioctl(iph->iph_sock, SIOCGLIFGROUPNAME, (caddr_t)&lifr) < 0) {
		if (ioctl(iph->iph_sock6, SIOCGLIFGROUPNAME,
		    (caddr_t)&lifr) < 0) {
			return (B_FALSE);
		}
	}
	return (lifr.lifr_groupname[0] != '\0');
}

/*
 * Returns B_TRUE if `ifname' represents an IPMP meta-interface.
 */
boolean_t
i_ipadm_is_ipmp(ipadm_handle_t iph, const char *ifname)
{
	uint64_t flags;

	if (i_ipadm_get_flags(iph, ifname, AF_INET, &flags) != IPADM_SUCCESS &&
	    i_ipadm_get_flags(iph, ifname, AF_INET6, &flags) != IPADM_SUCCESS)
		return (B_FALSE);

	return ((flags & IFF_IPMP) != 0);
}

/*
 * For a given interface name, ipadm_if_enabled() checks if v4
 * or v6 or both IP interfaces exist in the active configuration.
 */
boolean_t
ipadm_if_enabled(ipadm_handle_t iph, const char *ifname, sa_family_t af)
{
	struct lifreq	lifr;
	int		s4 = iph->iph_sock;
	int		s6 = iph->iph_sock6;

	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	switch (af) {
	case AF_INET:
		if (ioctl(s4, SIOCGLIFFLAGS, (caddr_t)&lifr) == 0)
			return (B_TRUE);
		break;
	case AF_INET6:
		if (ioctl(s6, SIOCGLIFFLAGS, (caddr_t)&lifr) == 0)
			return (B_TRUE);
		break;
	case AF_UNSPEC:
		if (ioctl(s4, SIOCGLIFFLAGS, (caddr_t)&lifr) == 0 ||
		    ioctl(s6, SIOCGLIFFLAGS, (caddr_t)&lifr) == 0) {
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * Apply the interface property by retrieving information from nvl.
 */
static ipadm_status_t
i_ipadm_init_ifprop(ipadm_handle_t iph, nvlist_t *nvl)
{
	nvpair_t	*nvp;
	char		*name, *pname = NULL;
	char		*protostr = NULL, *ifname = NULL, *pval = NULL;
	uint_t		proto;
	int		err = 0;

	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		name = nvpair_name(nvp);
		if (strcmp(name, IPADM_NVP_IFNAME) == 0) {
			if ((err = nvpair_value_string(nvp, &ifname)) != 0)
				break;
		} else if (strcmp(name, IPADM_NVP_PROTONAME) == 0) {
			if ((err = nvpair_value_string(nvp, &protostr)) != 0)
				break;
		} else {
			assert(!IPADM_PRIV_NVP(name));
			pname = name;
			if ((err = nvpair_value_string(nvp, &pval)) != 0)
				break;
		}
	}
	if (err != 0)
		return (ipadm_errno2status(err));
	proto = ipadm_str2proto(protostr);
	return (ipadm_set_ifprop(iph, ifname, pname, pval, proto,
	    IPADM_OPT_ACTIVE));
}

/*
 * Instantiate the address object or set the address object property by
 * retrieving the configuration from the nvlist `nvl'.
 */
ipadm_status_t
i_ipadm_init_addrobj(ipadm_handle_t iph, nvlist_t *nvl)
{
	nvpair_t	*nvp;
	char		*name;
	char		*aobjname = NULL, *pval = NULL, *ifname = NULL;
	sa_family_t	af = AF_UNSPEC;
	ipadm_addr_type_t atype = IPADM_ADDR_NONE;
	int		err = 0;
	ipadm_status_t	status = IPADM_SUCCESS;

	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		name = nvpair_name(nvp);
		if (strcmp(name, IPADM_NVP_IFNAME) == 0) {
			if ((err = nvpair_value_string(nvp, &ifname)) != 0)
				break;
		} else if (strcmp(name, IPADM_NVP_AOBJNAME) == 0) {
			if ((err = nvpair_value_string(nvp, &aobjname)) != 0)
				break;
		} else if (i_ipadm_name2atype(name, &af, &atype)) {
			break;
		} else {
			assert(!IPADM_PRIV_NVP(name));
			err = nvpair_value_string(nvp, &pval);
			break;
		}
	}
	if (err != 0)
		return (ipadm_errno2status(err));

	switch (atype) {
	case IPADM_ADDR_STATIC:
		status = i_ipadm_enable_static(iph, ifname, nvl, af);
		break;
	case IPADM_ADDR_DHCP:
		status = i_ipadm_enable_dhcp(iph, ifname, nvl);
		if (status == IPADM_DHCP_IPC_TIMEOUT)
			status = IPADM_SUCCESS;
		break;
	case IPADM_ADDR_IPV6_ADDRCONF:
		status = i_ipadm_enable_addrconf(iph, ifname, nvl);
		break;
	case IPADM_ADDR_NONE:
		status = ipadm_set_addrprop(iph, name, pval, aobjname,
		    IPADM_OPT_ACTIVE);
		break;
	}

	return (status);
}

/*
 * Instantiate the interface object by retrieving the configuration from
 * `ifnvl'. The nvlist `ifnvl' contains all the persistent configuration
 * (interface properties and address objects on that interface) for the
 * given `ifname'.
 */
ipadm_status_t
i_ipadm_init_ifobj(ipadm_handle_t iph, const char *ifname, nvlist_t *ifnvl)
{
	nvlist_t	*nvl = NULL;
	nvpair_t	*nvp;
	char		*afstr;
	ipadm_status_t	status;
	ipadm_status_t	ret_status = IPADM_SUCCESS;
	char		newifname[LIFNAMSIZ];
	char		*aobjstr;
	sa_family_t	af = AF_UNSPEC;
	boolean_t	is_ngz = (iph->iph_zoneid != GLOBAL_ZONEID);

	(void) strlcpy(newifname, ifname, sizeof (newifname));
	/*
	 * First plumb the given interface and then apply all the persistent
	 * interface properties and then instantiate any persistent addresses
	 * objects on that interface.
	 */
	for (nvp = nvlist_next_nvpair(ifnvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(ifnvl, nvp)) {
		if (nvpair_value_nvlist(nvp, &nvl) != 0)
			continue;

		if (nvlist_lookup_string(nvl, IPADM_NVP_FAMILY, &afstr) == 0) {
			status = i_ipadm_plumb_if(iph, newifname, atoi(afstr),
			    IPADM_OPT_ACTIVE);
			/*
			 * If the interface is already plumbed, we should
			 * ignore this error because there might be address
			 * address objects on that interface that needs to
			 * be enabled again.
			 */
			if (status == IPADM_IF_EXISTS)
				status = IPADM_SUCCESS;

			if (is_ngz)
				af = atoi(afstr);
		} else if (nvlist_lookup_string(nvl, IPADM_NVP_AOBJNAME,
		    &aobjstr) == 0) {
			/*
			 * For a static address, we need to search for
			 * the prefixlen in the nvlist `ifnvl'.
			 */
			if (nvlist_exists(nvl, IPADM_NVP_IPV4ADDR) ||
			    nvlist_exists(nvl, IPADM_NVP_IPV6ADDR)) {
				status = i_ipadm_merge_prefixlen_from_nvl(ifnvl,
				    nvl, aobjstr);
				if (status != IPADM_SUCCESS)
					continue;
			}
			status = i_ipadm_init_addrobj(iph, nvl);
			/*
			 * If this address is in use on some other interface,
			 * we want to record an error to be returned as
			 * a soft error and continue processing the rest of
			 * the addresses.
			 */
			if (status == IPADM_ADDR_NOTAVAIL) {
				ret_status = IPADM_ALL_ADDRS_NOT_ENABLED;
				status = IPADM_SUCCESS;
			}
		} else {
			assert(nvlist_exists(nvl, IPADM_NVP_PROTONAME));
			status = i_ipadm_init_ifprop(iph, nvl);
		}
		if (status != IPADM_SUCCESS)
			return (status);
	}

	if (is_ngz && af != AF_UNSPEC)
		ret_status = ipadm_init_net_from_gz(iph, newifname, NULL);
	return (ret_status);
}

/*
 * Retrieves the persistent configuration for the given interface(s) in `ifs'
 * by contacting the daemon and dumps the information in `allifs'.
 */
ipadm_status_t
i_ipadm_init_ifs(ipadm_handle_t iph, const char *ifs, nvlist_t **allifs)
{
	nvlist_t		*nvl = NULL;
	size_t			nvlsize, bufsize;
	ipmgmt_initif_arg_t	*iargp;
	char			*buf = NULL, *nvlbuf = NULL;
	ipmgmt_get_rval_t	*rvalp = NULL;
	int			err;
	ipadm_status_t		status = IPADM_SUCCESS;

	if ((err = ipadm_str2nvlist(ifs, &nvl, IPADM_NORVAL)) != 0)
		return (ipadm_errno2status(err));

	err = nvlist_pack(nvl, &nvlbuf, &nvlsize, NV_ENCODE_NATIVE, 0);
	if (err != 0) {
		status = ipadm_errno2status(err);
		goto done;
	}
	bufsize = sizeof (*iargp) + nvlsize;
	if ((buf = malloc(bufsize)) == NULL) {
		status = ipadm_errno2status(errno);
		goto done;
	}

	/* populate the door_call argument structure */
	iargp = (void *)buf;
	iargp->ia_cmd = IPMGMT_CMD_INITIF;
	iargp->ia_flags = 0;
	iargp->ia_family = AF_UNSPEC;
	iargp->ia_nvlsize = nvlsize;
	(void) bcopy(nvlbuf, buf + sizeof (*iargp), nvlsize);

	if ((rvalp = malloc(sizeof (ipmgmt_get_rval_t))) == NULL) {
		status = ipadm_errno2status(errno);
		goto done;
	}
	if ((err = ipadm_door_call(iph, iargp, bufsize, (void **)&rvalp,
	    sizeof (*rvalp), B_TRUE)) != 0) {
		status = ipadm_errno2status(err);
		goto done;
	}

	/*
	 * Daemon reply pointed to by rvalp contains ipmgmt_get_rval_t structure
	 * followed by a list of packed nvlists, each of which represents
	 * configuration information for the given interface(s).
	 */
	err = nvlist_unpack((char *)rvalp + sizeof (ipmgmt_get_rval_t),
	    rvalp->ir_nvlsize, allifs, NV_ENCODE_NATIVE);
	if (err != 0)
		status = ipadm_errno2status(err);
done:
	nvlist_free(nvl);
	free(buf);
	free(nvlbuf);
	free(rvalp);
	return (status);
}

/*
 * Returns B_FALSE if
 * (1) `ifname' is NULL or has no string or has a string of invalid length
 * (2) ifname is a logical interface and IPH_LEGACY is not set, or
 */
boolean_t
i_ipadm_validate_ifname(ipadm_handle_t iph, const char *ifname)
{
	ifspec_t ifsp;

	if (ifname == NULL || ifname[0] == '\0' ||
	    !ifparse_ifspec(ifname, &ifsp))
		return (B_FALSE);
	if (ifsp.ifsp_lunvalid)
		return (ifsp.ifsp_lun > 0 && (iph->iph_flags & IPH_LEGACY));
	return (B_TRUE);
}

/*
 * Wrapper for sending a non-transparent I_STR ioctl().
 * Returns: Result from ioctl().
 */
int
i_ipadm_strioctl(int s, int cmd, char *buf, int buflen)
{
	struct strioctl ioc;

	(void) memset(&ioc, 0, sizeof (ioc));
	ioc.ic_cmd = cmd;
	ioc.ic_timout = 0;
	ioc.ic_len = buflen;
	ioc.ic_dp = buf;

	return (ioctl(s, I_STR, (char *)&ioc));
}

/*
 * Make a door call to the server and checks if the door call succeeded or not.
 * `is_varsize' specifies that the data returned by ipmgmtd daemon is of
 * variable size and door will allocate buffer using mmap(). In such cases
 * we re-allocate the required memory,n assign it to `rbufp', copy the data to
 * `rbufp' and then call munmap() (see below).
 *
 * It also checks to see if the server side procedure ran successfully by
 * checking for ir_err. Therefore, for some callers who just care about the
 * return status can set `rbufp' to NULL and set `rsize' to 0.
 */
int
ipadm_door_call(ipadm_handle_t iph, void *arg, size_t asize, void **rbufp,
    size_t rsize, boolean_t is_varsize)
{
	door_arg_t	darg;
	int		err;
	ipmgmt_retval_t	rval, *rvalp;
	boolean_t	reopen = B_FALSE;

	if (rbufp == NULL) {
		rvalp = &rval;
		rbufp = (void **)&rvalp;
		rsize = sizeof (rval);
	}

	darg.data_ptr = arg;
	darg.data_size = asize;
	darg.desc_ptr = NULL;
	darg.desc_num = 0;
	darg.rbuf = *rbufp;
	darg.rsize = rsize;

reopen:
	(void) pthread_mutex_lock(&iph->iph_lock);
	/* The door descriptor is opened if it isn't already */
	if (iph->iph_door_fd == -1) {
		if ((iph->iph_door_fd = open(IPMGMT_DOOR, O_RDONLY)) < 0) {
			err = errno;
			(void) pthread_mutex_unlock(&iph->iph_lock);
			return (err);
		}
	}
	(void) pthread_mutex_unlock(&iph->iph_lock);

	if (door_call(iph->iph_door_fd, &darg) == -1) {
		/*
		 * Stale door descriptor is possible if ipmgmtd was restarted
		 * since last iph_door_fd was opened, so try re-opening door
		 * descriptor.
		 */
		if (!reopen && errno == EBADF) {
			(void) close(iph->iph_door_fd);
			iph->iph_door_fd = -1;
			reopen = B_TRUE;
			goto reopen;
		}
		return (errno);
	}
	err = ((ipmgmt_retval_t *)(void *)(darg.rbuf))->ir_err;
	if (darg.rbuf != *rbufp) {
		/*
		 * if the caller is expecting the result to fit in specified
		 * buffer then return failure.
		 */
		if (!is_varsize)
			err = EBADE;
		/*
		 * The size of the buffer `*rbufp' was not big enough
		 * and the door itself allocated buffer, for us. We will
		 * hit this, on several occasion as for some cases
		 * we cannot predict the size of the return structure.
		 * Reallocate the buffer `*rbufp' and memcpy() the contents
		 * to new buffer.
		 */
		if (err == 0) {
			void *newp;

			/* allocated memory will be freed by the caller */
			if ((newp = realloc(*rbufp, darg.rsize)) == NULL) {
				err = ENOMEM;
			} else {
				*rbufp = newp;
				(void) memcpy(*rbufp, darg.rbuf, darg.rsize);
			}
		}
		/* munmap() the door buffer */
		(void) munmap(darg.rbuf, darg.rsize);
	} else {
		if (darg.rsize != rsize)
			err = EBADE;
	}
	return (err);
}
