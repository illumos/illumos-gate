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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright (c) 2016-2017, Chris Fraire <cfraire@me.com>.
 */

/*
 * This file contains functions for address management such as creating
 * an address, deleting an address, enabling an address, disabling an
 * address, bringing an address down or up, setting/getting properties
 * on an address object and listing address information
 * for all addresses in active as well as persistent configuration.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netdb.h>
#include <inet/ip.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <sys/sockio.h>
#include <errno.h>
#include <unistd.h>
#include <stropts.h>
#include <zone.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ctype.h>
#include <dhcpagent_util.h>
#include <dhcpagent_ipc.h>
#include <dhcp_inittab.h>
#include <dhcp_symbol.h>
#include <ipadm_ndpd.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdliptun.h>
#include <ifaddrs.h>
#include "libipadm_impl.h"

#define	SIN6(a)		((struct sockaddr_in6 *)a)
#define	SIN(a)		((struct sockaddr_in *)a)

static ipadm_status_t	i_ipadm_create_addr(ipadm_handle_t, ipadm_addrobj_t,
			    uint32_t);
static ipadm_status_t	i_ipadm_create_dhcp(ipadm_handle_t, ipadm_addrobj_t,
			    uint32_t);
static ipadm_status_t	i_ipadm_delete_dhcp(ipadm_handle_t, ipadm_addrobj_t,
			    boolean_t);
static ipadm_status_t	i_ipadm_refresh_dhcp(ipadm_addrobj_t);
static ipadm_status_t	i_ipadm_get_db_addr(ipadm_handle_t, const char *,
			    const char *, nvlist_t **);
static ipadm_status_t	i_ipadm_op_dhcp(ipadm_addrobj_t, dhcp_ipc_type_t,
			    int *);
static ipadm_status_t	i_ipadm_dhcp_status(ipadm_addrobj_t addr,
			    dhcp_status_t *status, int *dhcperror);
static ipadm_status_t	i_ipadm_validate_create_addr(ipadm_handle_t,
			    ipadm_addrobj_t, uint32_t);
static ipadm_status_t	i_ipadm_addr_persist_nvl(ipadm_handle_t, nvlist_t *,
			    uint32_t);
static ipadm_status_t	i_ipadm_get_default_prefixlen(struct sockaddr_storage *,
			    uint32_t *);
static ipadm_status_t	i_ipadm_get_static_addr_db(ipadm_handle_t,
			    ipadm_addrobj_t);
static boolean_t	i_ipadm_is_user_aobjname_valid(const char *);
static ipadm_prop_desc_t	*i_ipadm_get_addrprop_desc(const char *pname);

/*
 * Callback functions to retrieve property values from the kernel. These
 * functions, when required, translate the values from the kernel to a format
 * suitable for printing. They also retrieve DEFAULT, PERM and POSSIBLE values
 * for a given property.
 */
static ipadm_pd_getf_t	i_ipadm_get_prefixlen, i_ipadm_get_addr_flag,
			i_ipadm_get_zone, i_ipadm_get_broadcast,
			i_ipadm_get_primary, i_ipadm_get_reqhost;

/*
 * Callback functions to set property values. These functions translate the
 * values to a format suitable for kernel consumption, allocate the necessary
 * ioctl buffers and then invoke ioctl(); or in the case of reqhost, get the
 * collaborating agent to set the value.
 */
static ipadm_pd_setf_t	i_ipadm_set_prefixlen, i_ipadm_set_addr_flag,
			i_ipadm_set_zone, i_ipadm_set_reqhost;

static ipadm_status_t	i_ipadm_set_aobj_addrprop(ipadm_handle_t iph,
    ipadm_addrobj_t ipaddr, uint_t flags, const char *propname);

/* address properties description table */
ipadm_prop_desc_t ipadm_addrprop_table[] = {
	{ "broadcast", NULL, IPADMPROP_CLASS_ADDR, MOD_PROTO_NONE, 0,
	    NULL, NULL, i_ipadm_get_broadcast },

	{ "deprecated", NULL, IPADMPROP_CLASS_ADDR, MOD_PROTO_NONE, 0,
	    i_ipadm_set_addr_flag, i_ipadm_get_onoff,
	    i_ipadm_get_addr_flag },

	{ IPADM_NVP_PREFIXLEN, NULL, IPADMPROP_CLASS_ADDR, MOD_PROTO_NONE, 0,
	    i_ipadm_set_prefixlen, i_ipadm_get_prefixlen,
	    i_ipadm_get_prefixlen },

	/*
	 * primary is read-only because there is no operation to un-set
	 * DHCP_IF_PRIMARY in dhcpagent except to delete-addr and then
	 * re-create-addr.
	 */
	{ "primary", NULL, IPADMPROP_CLASS_ADDR, MOD_PROTO_NONE, 0,
		NULL, NULL, i_ipadm_get_primary },

	{ "private", NULL, IPADMPROP_CLASS_ADDR, MOD_PROTO_NONE, 0,
	    i_ipadm_set_addr_flag, i_ipadm_get_onoff, i_ipadm_get_addr_flag },

	{ IPADM_NVP_REQHOST, NULL, IPADMPROP_CLASS_ADDR, MOD_PROTO_NONE, 0,
	    i_ipadm_set_reqhost, NULL, i_ipadm_get_reqhost },

	{ "transmit", NULL, IPADMPROP_CLASS_ADDR, MOD_PROTO_NONE, 0,
	    i_ipadm_set_addr_flag, i_ipadm_get_onoff, i_ipadm_get_addr_flag },

	{ "zone", NULL, IPADMPROP_CLASS_ADDR, MOD_PROTO_NONE, 0,
	    i_ipadm_set_zone, NULL, i_ipadm_get_zone },

	{ NULL, NULL, 0, 0, 0, NULL, NULL, NULL }
};

static ipadm_prop_desc_t up_addrprop = { "up", NULL, IPADMPROP_CLASS_ADDR,
					MOD_PROTO_NONE, 0, NULL, NULL, NULL };

/*
 * Helper function that initializes the `ipadm_ifname', `ipadm_aobjname', and
 * `ipadm_atype' fields of the given `ipaddr'.
 */
void
i_ipadm_init_addr(ipadm_addrobj_t ipaddr, const char *ifname,
    const char *aobjname, ipadm_addr_type_t atype)
{
	bzero(ipaddr, sizeof (struct ipadm_addrobj_s));
	(void) strlcpy(ipaddr->ipadm_ifname, ifname,
	    sizeof (ipaddr->ipadm_ifname));
	(void) strlcpy(ipaddr->ipadm_aobjname, aobjname,
	    sizeof (ipaddr->ipadm_aobjname));
	ipaddr->ipadm_atype = atype;
}

/*
 * Determine the permission of the property depending on whether it has a
 * set() and/or get() callback functions.
 */
static ipadm_status_t
i_ipadm_pd2permstr(ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize)
{
	uint_t	perm;
	size_t	nbytes;

	perm = 0;
	if (pdp->ipd_set != NULL)
		perm |= MOD_PROP_PERM_WRITE;
	if (pdp->ipd_get != NULL)
		perm |= MOD_PROP_PERM_READ;

	nbytes = snprintf(buf, *bufsize, "%c%c",
	    ((perm & MOD_PROP_PERM_READ) != 0) ? 'r' : '-',
	    ((perm & MOD_PROP_PERM_WRITE) != 0) ? 'w' : '-');

	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		return (IPADM_NO_BUFS);
	}
	return (IPADM_SUCCESS);
}

/*
 * Given an addrobj with `ipadm_aobjname' filled in, i_ipadm_get_addrobj()
 * retrieves the information necessary for any operation on the object,
 * such as delete-addr, enable-addr, disable-addr, up-addr, down-addr,
 * refresh-addr, get-addrprop or set-addrprop. The information include
 * the logical interface number, address type, address family,
 * the interface id (if the address type is IPADM_ADDR_IPV6_ADDRCONF) and
 * the ipadm_flags that indicate if the address is present in
 * active configuration or persistent configuration or both. If the address
 * is not found, IPADM_NOTSUP is returned.
 */
ipadm_status_t
i_ipadm_get_addrobj(ipadm_handle_t iph, ipadm_addrobj_t ipaddr)
{
	ipmgmt_aobjop_arg_t	larg;
	ipmgmt_aobjop_rval_t	rval, *rvalp;
	int			err = 0;

	/* populate the door_call argument structure */
	larg.ia_cmd = IPMGMT_CMD_AOBJNAME2ADDROBJ;
	(void) strlcpy(larg.ia_aobjname, ipaddr->ipadm_aobjname,
	    sizeof (larg.ia_aobjname));

	rvalp = &rval;
	err = ipadm_door_call(iph, &larg, sizeof (larg), (void **)&rvalp,
	    sizeof (rval), B_FALSE);
	if (err != 0)
		return (ipadm_errno2status(err));
	(void) strlcpy(ipaddr->ipadm_ifname, rval.ir_ifname,
	    sizeof (ipaddr->ipadm_ifname));
	ipaddr->ipadm_lifnum = rval.ir_lnum;
	ipaddr->ipadm_atype = rval.ir_atype;
	ipaddr->ipadm_af = rval.ir_family;
	ipaddr->ipadm_flags = rval.ir_flags;
	switch (rval.ir_atype) {
	case IPADM_ADDR_IPV6_ADDRCONF:
		ipaddr->ipadm_intfid = rval.ipmgmt_ir_intfid;
		break;
	case IPADM_ADDR_DHCP:
		if (strlcpy(ipaddr->ipadm_reqhost, rval.ipmgmt_ir_reqhost,
		    sizeof (ipaddr->ipadm_reqhost)) >=
		    sizeof (ipaddr->ipadm_reqhost)) {
			/*
			 * shouldn't get here as the buffers are defined
			 * with same length, MAX_NAME_LEN
			 */
			return (IPADM_FAILURE);
		}
		break;
	default:
		break;
	}

	return (IPADM_SUCCESS);
}

/*
 * Retrieves the static address (IPv4 or IPv6) for the given address object
 * in `ipaddr' from persistent DB.
 */
static ipadm_status_t
i_ipadm_get_static_addr_db(ipadm_handle_t iph, ipadm_addrobj_t ipaddr)
{
	ipadm_status_t		status;
	nvlist_t		*onvl;
	nvlist_t		*anvl = NULL;
	nvlist_t		*nvladdr;
	nvpair_t		*nvp;
	char			*name;
	char			*aobjname = ipaddr->ipadm_aobjname;
	char			*sname;
	sa_family_t		af = AF_UNSPEC;

	/*
	 * Get the address line in the nvlist `onvl' from ipmgmtd daemon.
	 */
	status = i_ipadm_get_db_addr(iph, NULL, aobjname, &onvl);
	if (status != IPADM_SUCCESS)
		return (status);
	/*
	 * Walk through the nvlist `onvl' to extract the IPADM_NVP_IPV4ADDR
	 * or the IPADM_NVP_IPV6ADDR name-value pair.
	 */
	for (nvp = nvlist_next_nvpair(onvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(onvl, NULL)) {
		if (nvpair_value_nvlist(nvp, &anvl) != 0)
			continue;
		if (nvlist_exists(anvl, IPADM_NVP_IPV4ADDR) ||
		    nvlist_exists(anvl, IPADM_NVP_IPV6ADDR))
			break;
	}
	if (nvp == NULL)
		goto fail;
	for (nvp = nvlist_next_nvpair(anvl, NULL);
	    nvp != NULL; nvp = nvlist_next_nvpair(anvl, nvp)) {
		name = nvpair_name(nvp);
		if (strcmp(name, IPADM_NVP_IPV4ADDR) == 0) {
			af = AF_INET;
			break;
		} else if (strcmp(name, IPADM_NVP_IPV6ADDR) == 0) {
			af = AF_INET6;
			break;
		}
	}
	assert(af != AF_UNSPEC);
	if (nvpair_value_nvlist(nvp, &nvladdr) != 0 ||
	    nvlist_lookup_string(nvladdr, IPADM_NVP_IPADDRHNAME, &sname) != 0 ||
	    ipadm_set_addr(ipaddr, sname, af) != IPADM_SUCCESS) {
		goto fail;
	}
	nvlist_free(onvl);
	return (IPADM_SUCCESS);
fail:
	nvlist_free(onvl);
	return (IPADM_NOTFOUND);
}

/*
 * For the given `addrobj->ipadm_lifnum' and `addrobj->ipadm_af', this function
 * fills in the address objname, the address type and the ipadm_flags.
 */
ipadm_status_t
i_ipadm_get_lif2addrobj(ipadm_handle_t iph, ipadm_addrobj_t addrobj)
{
	ipmgmt_aobjop_arg_t	larg;
	ipmgmt_aobjop_rval_t	rval, *rvalp;
	int			err;

	larg.ia_cmd = IPMGMT_CMD_LIF2ADDROBJ;
	(void) strlcpy(larg.ia_ifname, addrobj->ipadm_ifname,
	    sizeof (larg.ia_ifname));
	larg.ia_lnum = addrobj->ipadm_lifnum;
	larg.ia_family = addrobj->ipadm_af;

	rvalp = &rval;
	err = ipadm_door_call(iph, &larg, sizeof (larg), (void **)&rvalp,
	    sizeof (rval), B_FALSE);
	if (err != 0)
		return (ipadm_errno2status(err));
	(void) strlcpy(addrobj->ipadm_aobjname, rval.ir_aobjname,
	    sizeof (addrobj->ipadm_aobjname));
	addrobj->ipadm_atype = rval.ir_atype;
	addrobj->ipadm_flags = rval.ir_flags;

	return (IPADM_SUCCESS);
}

/*
 * Adds an addrobj to ipmgmtd daemon's aobjmap (active configuration).
 * with the given name and logical interface number.
 * This API is called by in.ndpd to add addrobjs when new prefixes or
 * dhcpv6 addresses are configured.
 */
ipadm_status_t
ipadm_add_aobjname(ipadm_handle_t iph, const char *ifname, sa_family_t af,
    const char *aobjname, ipadm_addr_type_t atype, int lnum)
{
	ipmgmt_aobjop_arg_t	larg;
	int			err;

	larg.ia_cmd = IPMGMT_CMD_ADDROBJ_ADD;
	(void) strlcpy(larg.ia_ifname, ifname, sizeof (larg.ia_ifname));
	(void) strlcpy(larg.ia_aobjname, aobjname, sizeof (larg.ia_aobjname));
	larg.ia_atype = atype;
	larg.ia_lnum = lnum;
	larg.ia_family = af;
	err = ipadm_door_call(iph, &larg, sizeof (larg), NULL, 0, B_FALSE);
	return (ipadm_errno2status(err));
}

/*
 * Deletes an address object with given name and logical number from ipmgmtd
 * daemon's aobjmap (active configuration). This API is called by in.ndpd to
 * remove addrobjs when auto-configured prefixes or dhcpv6 addresses are
 * removed.
 */
ipadm_status_t
ipadm_delete_aobjname(ipadm_handle_t iph, const char *ifname, sa_family_t af,
    const char *aobjname, ipadm_addr_type_t atype, int lnum)
{
	struct ipadm_addrobj_s	aobj;

	i_ipadm_init_addr(&aobj, ifname, aobjname, atype);
	aobj.ipadm_af = af;
	aobj.ipadm_lifnum = lnum;
	return (i_ipadm_delete_addrobj(iph, &aobj, IPADM_OPT_ACTIVE));
}

/*
 * Gets all the addresses from active configuration and populates the
 * address information in `addrinfo'.
 */
static ipadm_status_t
i_ipadm_active_addr_info(ipadm_handle_t iph, const char *ifname,
    ipadm_addr_info_t **addrinfo, uint32_t ipadm_flags, int64_t lifc_flags)
{
	ipadm_status_t		status;
	struct ifaddrs		*ifap, *ifa;
	ipadm_addr_info_t	*curr, *prev = NULL;
	struct ifaddrs		*cifaddr;
	struct lifreq		lifr;
	int			sock;
	uint64_t		flags;
	char			cifname[LIFNAMSIZ];
	struct sockaddr_in6	*sin6;
	struct ipadm_addrobj_s	ipaddr;
	char			*sep;
	int			lnum;

retry:
	*addrinfo = NULL;

	/* Get all the configured addresses */
	if (getallifaddrs(AF_UNSPEC, &ifa, lifc_flags) < 0)
		return (ipadm_errno2status(errno));
	/* Return if there is nothing to process. */
	if (ifa == NULL)
		return (IPADM_SUCCESS);
	bzero(&lifr, sizeof (lifr));
	for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next) {
		struct sockaddr_storage data;

		(void) strlcpy(cifname, ifap->ifa_name, sizeof (cifname));
		lnum = 0;
		if ((sep = strrchr(cifname, ':')) != NULL) {
			*sep++ = '\0';
			lnum = atoi(sep);
		}
		if (ifname != NULL && strcmp(cifname, ifname) != 0)
			continue;
		if (!(ipadm_flags & IPADM_OPT_ZEROADDR) &&
		    sockaddrunspec(ifap->ifa_addr) &&
		    !(ifap->ifa_flags & IFF_DHCPRUNNING))
			continue;

		/* Allocate and populate the current node in the list. */
		if ((curr = calloc(1, sizeof (ipadm_addr_info_t))) == NULL)
			goto fail;

		/* Link to the list in `addrinfo'. */
		if (prev != NULL)
			prev->ia_ifa.ifa_next = &curr->ia_ifa;
		else
			*addrinfo = curr;
		prev = curr;

		cifaddr = &curr->ia_ifa;
		if ((cifaddr->ifa_name = strdup(ifap->ifa_name)) == NULL)
			goto fail;
		cifaddr->ifa_flags = ifap->ifa_flags;
		cifaddr->ifa_addr = malloc(sizeof (struct sockaddr_storage));
		if (cifaddr->ifa_addr == NULL)
			goto fail;
		(void) memcpy(cifaddr->ifa_addr, ifap->ifa_addr,
		    sizeof (struct sockaddr_storage));
		cifaddr->ifa_netmask = malloc(sizeof (struct sockaddr_storage));
		if (cifaddr->ifa_netmask == NULL)
			goto fail;
		(void) memcpy(cifaddr->ifa_netmask, ifap->ifa_netmask,
		    sizeof (struct sockaddr_storage));
		if (ifap->ifa_flags & IFF_POINTOPOINT) {
			cifaddr->ifa_dstaddr = malloc(
			    sizeof (struct sockaddr_storage));
			if (cifaddr->ifa_dstaddr == NULL)
				goto fail;
			(void) memcpy(cifaddr->ifa_dstaddr, ifap->ifa_dstaddr,
			    sizeof (struct sockaddr_storage));
		} else if (ifap->ifa_flags & IFF_BROADCAST) {
			cifaddr->ifa_broadaddr = malloc(
			    sizeof (struct sockaddr_storage));
			if (cifaddr->ifa_broadaddr == NULL)
				goto fail;
			(void) memcpy(cifaddr->ifa_broadaddr,
			    ifap->ifa_broadaddr,
			    sizeof (struct sockaddr_storage));
		}
		/* Get the addrobj name stored for this logical interface. */
		ipaddr.ipadm_aobjname[0] = '\0';
		(void) strlcpy(ipaddr.ipadm_ifname, cifname,
		    sizeof (ipaddr.ipadm_ifname));
		ipaddr.ipadm_lifnum = lnum;
		ipaddr.ipadm_af = ifap->ifa_addr->sa_family;
		status = i_ipadm_get_lif2addrobj(iph, &ipaddr);

		/*
		 * Find address type from ifa_flags, if we could not get it
		 * from daemon.
		 */
		(void) memcpy(&data, ifap->ifa_addr,
		    sizeof (struct sockaddr_in6));
		sin6 = SIN6(&data);
		flags = ifap->ifa_flags;
		if (status == IPADM_SUCCESS) {
			(void) strlcpy(curr->ia_aobjname, ipaddr.ipadm_aobjname,
			    sizeof (curr->ia_aobjname));
			curr->ia_atype = ipaddr.ipadm_atype;
		} else if ((flags & IFF_DHCPRUNNING) && (!(flags & IFF_IPV6) ||
		    !IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))) {
			curr->ia_atype = IPADM_ADDR_DHCP;
		} else if (flags & IFF_ADDRCONF) {
			curr->ia_atype = IPADM_ADDR_IPV6_ADDRCONF;
		} else {
			curr->ia_atype = IPADM_ADDR_STATIC;
		}
		/*
		 * Populate the flags for the active configuration from the
		 * `ifa_flags'.
		 */
		if (!(flags & IFF_UP)) {
			if (flags & IFF_DUPLICATE)
				curr->ia_state = IFA_DUPLICATE;
			else
				curr->ia_state = IFA_DOWN;
		} else {
			curr->ia_cflags |= IA_UP;
			if (flags & IFF_RUNNING) {
				(void) strlcpy(lifr.lifr_name, ifap->ifa_name,
				    sizeof (lifr.lifr_name));
				sock = (ifap->ifa_addr->sa_family == AF_INET) ?
				    iph->iph_sock : iph->iph_sock6;
				if (ioctl(sock, SIOCGLIFDADSTATE,
				    (caddr_t)&lifr) < 0) {
					if (errno == ENXIO) {
						freeifaddrs(ifa);
						ipadm_free_addr_info(*addrinfo);
						goto retry;
					}
					goto fail;
				}
				if (lifr.lifr_dadstate == DAD_IN_PROGRESS)
					curr->ia_state = IFA_TENTATIVE;
				else
					curr->ia_state = IFA_OK;
			} else {
				curr->ia_state = IFA_INACCESSIBLE;
			}
		}
		if (flags & IFF_UNNUMBERED)
			curr->ia_cflags |= IA_UNNUMBERED;
		if (flags & IFF_PRIVATE)
			curr->ia_cflags |= IA_PRIVATE;
		if (flags & IFF_TEMPORARY)
			curr->ia_cflags |= IA_TEMPORARY;
		if (flags & IFF_DEPRECATED)
			curr->ia_cflags |= IA_DEPRECATED;

	}

	freeifaddrs(ifa);
	return (IPADM_SUCCESS);

fail:
	/* On error, cleanup everything and return. */
	ipadm_free_addr_info(*addrinfo);
	*addrinfo = NULL;
	freeifaddrs(ifa);
	return (ipadm_errno2status(errno));
}

/*
 * From the given `name', i_ipadm_name2atype() deduces the address type
 * and address family. If the `name' implies an address, it returns B_TRUE.
 * Else, returns B_FALSE and leaves the output parameters unchanged.
 */
boolean_t
i_ipadm_name2atype(const char *name, sa_family_t *af, ipadm_addr_type_t *type)
{
	boolean_t	is_addr = B_TRUE;

	if (strcmp(name, IPADM_NVP_IPV4ADDR) == 0) {
		*af = AF_INET;
		*type = IPADM_ADDR_STATIC;
	} else if (strcmp(name, IPADM_NVP_IPV6ADDR) == 0) {
		*af = AF_INET6;
		*type = IPADM_ADDR_STATIC;
	} else if (strcmp(name, IPADM_NVP_DHCP) == 0) {
		*af = AF_INET;
		*type = IPADM_ADDR_DHCP;
	} else if (strcmp(name, IPADM_NVP_INTFID) == 0) {
		*af = AF_INET6;
		*type = IPADM_ADDR_IPV6_ADDRCONF;
	} else {
		is_addr = B_FALSE;
	}

	return (is_addr);
}

/*
 * Parses the given nvlist `nvl' for an address or an address property.
 * The input nvlist must contain either an address or an address property.
 * `ainfo' is an input as well as output parameter. When an address or an
 * address property is found, `ainfo' is updated with the information found.
 * Some of the fields may be already filled in by the calling function.
 *
 * The fields that will be filled/updated by this function are `ia_pflags',
 * `ia_sname' and `ia_dname'. Values for `ia_pflags' are obtained if the `nvl'
 * contains an address property. `ia_sname', `ia_dname', and `ia_pflags' are
 * obtained if `nvl' contains an address.
 */
static ipadm_status_t
i_ipadm_nvl2ainfo_common(nvlist_t *nvl, ipadm_addr_info_t *ainfo)
{
	nvlist_t		*nvladdr;
	char			*name;
	char			*propstr = NULL;
	char			*sname, *dname;
	nvpair_t		*nvp;
	sa_family_t		af;
	ipadm_addr_type_t	atype;
	boolean_t		is_addr = B_FALSE;
	int			err;

	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		name = nvpair_name(nvp);
		if (i_ipadm_name2atype(name, &af, &atype)) {
			err = nvpair_value_nvlist(nvp, &nvladdr);
			is_addr = B_TRUE;
		} else if (IPADM_PRIV_NVP(name)) {
			continue;
		} else {
			err = nvpair_value_string(nvp, &propstr);
		}
		if (err != 0)
			return (ipadm_errno2status(err));
	}

	if (is_addr) {
		/*
		 * We got an address from the nvlist `nvl'.
		 * Parse `nvladdr' and populate relevant information
		 * in `ainfo'.
		 */
		switch (atype) {
		case IPADM_ADDR_STATIC:
			if (strcmp(name, "up") == 0 &&
			    strcmp(propstr, "yes") == 0) {
				ainfo->ia_pflags |= IA_UP;
			}
			/*
			 * For static addresses, we need to get the hostnames.
			 */
			err = nvlist_lookup_string(nvladdr,
			    IPADM_NVP_IPADDRHNAME, &sname);
			if (err != 0)
				return (ipadm_errno2status(err));
			(void) strlcpy(ainfo->ia_sname, sname,
			    sizeof (ainfo->ia_sname));
			err = nvlist_lookup_string(nvladdr,
			    IPADM_NVP_IPDADDRHNAME, &dname);
			if (err == 0) {
				(void) strlcpy(ainfo->ia_dname, dname,
				    sizeof (ainfo->ia_dname));
			}
			break;
		case IPADM_ADDR_DHCP:
		case IPADM_ADDR_IPV6_ADDRCONF:
			/*
			 * dhcp and addrconf address objects are always
			 * marked up when re-enabled.
			 */
			ainfo->ia_pflags |= IA_UP;
			break;
		default:
			return (IPADM_FAILURE);
		}
	} else {
		/*
		 * We got an address property from `nvl'. Parse the
		 * name and the property value. Update the `ainfo->ia_pflags'
		 * for the flags.
		 */
		if (strcmp(name, "deprecated") == 0) {
			if (strcmp(propstr, IPADM_ONSTR) == 0)
				ainfo->ia_pflags |= IA_DEPRECATED;
		} else if (strcmp(name, "private") == 0) {
			if (strcmp(propstr, IPADM_ONSTR) == 0)
				ainfo->ia_pflags |= IA_PRIVATE;
		}
	}

	return (IPADM_SUCCESS);
}

/*
 * Parses the given nvlist `nvl' for an address or an address property.
 * The input nvlist must contain either an address or an address property.
 * `ainfo' is an input as well as output parameter. When an address or an
 * address property is found, `ainfo' is updated with the information found.
 * Some of the fields may be already filled in by the calling function,
 * because of previous calls to i_ipadm_nvl2ainfo_active().
 *
 * Since the address object in `nvl' is also in the active configuration, the
 * fields that will be filled/updated by this function are `ia_pflags',
 * `ia_sname' and `ia_dname'.
 *
 * If this function returns an error, the calling function will take
 * care of freeing the fields in `ainfo'.
 */
static ipadm_status_t
i_ipadm_nvl2ainfo_active(nvlist_t *nvl, ipadm_addr_info_t *ainfo)
{
	return (i_ipadm_nvl2ainfo_common(nvl, ainfo));
}

/*
 * Parses the given nvlist `nvl' for an address or an address property.
 * The input nvlist must contain either an address or an address property.
 * `ainfo' is an input as well as output parameter. When an address or an
 * address property is found, `ainfo' is updated with the information found.
 * Some of the fields may be already filled in by the calling function,
 * because of previous calls to i_ipadm_nvl2ainfo_persist().
 *
 * All the relevant fields in `ainfo' will be filled by this function based
 * on what we find in `nvl'.
 *
 * If this function returns an error, the calling function will take
 * care of freeing the fields in `ainfo'.
 */
static ipadm_status_t
i_ipadm_nvl2ainfo_persist(nvlist_t *nvl, ipadm_addr_info_t *ainfo)
{
	nvlist_t		*nvladdr;
	struct ifaddrs		*ifa;
	char			*name;
	char			*ifname = NULL;
	char			*aobjname = NULL;
	char			*propstr = NULL;
	nvpair_t		*nvp;
	sa_family_t		af;
	ipadm_addr_type_t	atype;
	boolean_t		is_addr = B_FALSE;
	size_t			size = sizeof (struct sockaddr_storage);
	uint32_t		plen = 0;
	int			err;
	ipadm_status_t		status;

	status = i_ipadm_nvl2ainfo_common(nvl, ainfo);
	if (status != IPADM_SUCCESS)
		return (status);

	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		name = nvpair_name(nvp);
		if (strcmp(name, IPADM_NVP_IFNAME) == 0) {
			err = nvpair_value_string(nvp, &ifname);
		} else if (strcmp(name, IPADM_NVP_AOBJNAME) == 0) {
			err = nvpair_value_string(nvp, &aobjname);
		} else if (i_ipadm_name2atype(name, &af, &atype)) {
			err = nvpair_value_nvlist(nvp, &nvladdr);
			is_addr = B_TRUE;
		} else {
			err = nvpair_value_string(nvp, &propstr);
		}
		if (err != 0)
			return (ipadm_errno2status(err));
	}

	ifa = &ainfo->ia_ifa;
	(void) strlcpy(ainfo->ia_aobjname, aobjname,
	    sizeof (ainfo->ia_aobjname));
	if (ifa->ifa_name == NULL && (ifa->ifa_name = strdup(ifname)) == NULL)
		return (IPADM_NO_MEMORY);
	if (is_addr) {
		struct sockaddr_in6 data;

		/*
		 * We got an address from the nvlist `nvl'.
		 * Parse `nvladdr' and populate `ifa->ifa_addr'.
		 */
		ainfo->ia_atype = atype;
		if ((ifa->ifa_addr = calloc(1, size)) == NULL)
			return (IPADM_NO_MEMORY);
		switch (atype) {
		case IPADM_ADDR_STATIC:
			ifa->ifa_addr->sa_family = af;
			break;
		case IPADM_ADDR_DHCP:
			ifa->ifa_addr->sa_family = AF_INET;
			break;
		case IPADM_ADDR_IPV6_ADDRCONF:
			data.sin6_family = AF_INET6;
			if (i_ipadm_nvl2in6_addr(nvladdr, IPADM_NVP_IPNUMADDR,
			    &data.sin6_addr) != IPADM_SUCCESS)
				return (IPADM_NO_MEMORY);
			err = nvlist_lookup_uint32(nvladdr, IPADM_NVP_PREFIXLEN,
			    &plen);
			if (err != 0)
				return (ipadm_errno2status(err));
			if ((ifa->ifa_netmask = malloc(size)) == NULL)
				return (IPADM_NO_MEMORY);
			if ((err = plen2mask(plen, af, ifa->ifa_netmask)) != 0)
				return (ipadm_errno2status(err));
			(void) memcpy(ifa->ifa_addr, &data, sizeof (data));
			break;
		default:
			return (IPADM_FAILURE);
		}
	} else {
		if (strcmp(name, "prefixlen") == 0) {
			/*
			 * If a prefixlen was found, update the
			 * `ainfo->ia_ifa.ifa_netmask'.
			 */

			if ((ifa->ifa_netmask = malloc(size)) == NULL)
				return (IPADM_NO_MEMORY);
			/*
			 * Address property lines always follow the address
			 * line itself in the persistent db. We must have
			 * found a valid `ainfo->ia_ifa.ifa_addr' by now.
			 */
			assert(ifa->ifa_addr != NULL);
			err = plen2mask(atoi(propstr), ifa->ifa_addr->sa_family,
			    ifa->ifa_netmask);
			if (err != 0)
				return (ipadm_errno2status(err));
		}
	}

	return (IPADM_SUCCESS);
}

/*
 * Retrieves all addresses from active config and appends to it the
 * addresses that are found only in persistent config. In addition,
 * it updates the persistent fields for each address from information
 * found in persistent config. The output parameter `addrinfo' contains
 * complete information regarding all addresses in active as well as
 * persistent config.
 */
static ipadm_status_t
i_ipadm_get_all_addr_info(ipadm_handle_t iph, const char *ifname,
    ipadm_addr_info_t **addrinfo, uint32_t ipadm_flags, int64_t lifc_flags)
{
	nvlist_t		*nvladdr = NULL;
	nvlist_t		*onvl = NULL;
	nvpair_t		*nvp;
	ipadm_status_t		status;
	ipadm_addr_info_t	*ainfo = NULL;
	ipadm_addr_info_t	*curr;
	ipadm_addr_info_t	*last = NULL;
	char			*aobjname;

	/* Get all addresses from active config. */
	status = i_ipadm_active_addr_info(iph, ifname, &ainfo, ipadm_flags,
	    lifc_flags);
	if (status != IPADM_SUCCESS)
		goto fail;

	/* Get all addresses from persistent config. */
	status = i_ipadm_get_db_addr(iph, ifname, NULL, &onvl);
	/*
	 * If no address was found in persistent config, just
	 * return what we found in active config.
	 */
	if (status == IPADM_NOTFOUND) {
		/*
		 * If nothing was found neither active nor persistent
		 * config, this means that the interface does not exist,
		 * if one was provided in `ifname'.
		 */
		if (ainfo == NULL && ifname != NULL)
			return (IPADM_ENXIO);
		*addrinfo = ainfo;
		return (IPADM_SUCCESS);
	}
	/* In case of any other error, cleanup and return. */
	if (status != IPADM_SUCCESS)
		goto fail;
	/* we append to make sure, loopback addresses are first */
	if (ainfo != NULL) {
		for (curr = ainfo; IA_NEXT(curr) != NULL; curr = IA_NEXT(curr))
			;
		last = curr;
	}

	/*
	 * `onvl' will contain all the address lines from the db. Each line
	 * could contain the address itself or an address property. Addresses
	 * and address properties are found in separate lines.
	 *
	 * If an address A was found in active, we will already have `ainfo',
	 * and it is present in persistent configuration as well, we need to
	 * update `ainfo' with persistent information (`ia_pflags).
	 * For each address B found only in persistent configuration,
	 * append the address to the list with the address info for B from
	 * `onvl'.
	 */
	for (nvp = nvlist_next_nvpair(onvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(onvl, nvp)) {
		if (nvpair_value_nvlist(nvp, &nvladdr) != 0)
			continue;
		if (nvlist_lookup_string(nvladdr, IPADM_NVP_AOBJNAME,
		    &aobjname) != 0)
			continue;
		for (curr = ainfo; curr != NULL; curr = IA_NEXT(curr)) {
			if (strcmp(curr->ia_aobjname, aobjname) == 0)
				break;
		}
		if (curr == NULL) {
			/*
			 * We did not find this address object in `ainfo'.
			 * This means that the address object exists only
			 * in the persistent configuration. Get its
			 * details and append to `ainfo'.
			 */
			curr = calloc(1, sizeof (ipadm_addr_info_t));
			if (curr == NULL)
				goto fail;
			curr->ia_state = IFA_DISABLED;
			if (last != NULL)
				last->ia_ifa.ifa_next = &curr->ia_ifa;
			else
				ainfo = curr;
			last = curr;
		}
		/*
		 * Fill relevant fields of `curr' from the persistent info
		 * in `nvladdr'. Call the appropriate function based on the
		 * `ia_state' value.
		 */
		if (curr->ia_state == IFA_DISABLED)
			status = i_ipadm_nvl2ainfo_persist(nvladdr, curr);
		else
			status = i_ipadm_nvl2ainfo_active(nvladdr, curr);
		if (status != IPADM_SUCCESS)
			goto fail;
	}
	*addrinfo = ainfo;
	nvlist_free(onvl);
	return (status);
fail:
	/* On error, cleanup and return. */
	nvlist_free(onvl);
	ipadm_free_addr_info(ainfo);
	*addrinfo = NULL;
	return (status);
}

/*
 * Callback function that sets the property `prefixlen' on the address
 * object in `arg' to the value in `pval'.
 */
/* ARGSUSED */
static ipadm_status_t
i_ipadm_set_prefixlen(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t af, uint_t flags)
{
	struct sockaddr_storage	netmask;
	struct lifreq		lifr;
	int			err, s;
	unsigned long		prefixlen, abits;
	char			*end;
	ipadm_addrobj_t		ipaddr = (ipadm_addrobj_t)arg;

	if (ipaddr->ipadm_atype == IPADM_ADDR_DHCP)
		return (IPADM_NOTSUP);

	errno = 0;
	prefixlen = strtoul(pval, &end, 10);
	if (errno != 0 || *end != '\0')
		return (IPADM_INVALID_ARG);

	abits = (af == AF_INET ? IP_ABITS : IPV6_ABITS);
	if (prefixlen == 0 || prefixlen == (abits - 1))
		return (IPADM_INVALID_ARG);

	if ((err = plen2mask(prefixlen, af, (struct sockaddr *)&netmask)) != 0)
		return (ipadm_errno2status(err));

	s = (af == AF_INET ? iph->iph_sock : iph->iph_sock6);

	bzero(&lifr, sizeof (lifr));
	i_ipadm_addrobj2lifname(ipaddr, lifr.lifr_name,
	    sizeof (lifr.lifr_name));
	(void) memcpy(&lifr.lifr_addr, &netmask, sizeof (netmask));
	if (ioctl(s, SIOCSLIFNETMASK, (caddr_t)&lifr) < 0)
		return (ipadm_errno2status(errno));

	/* now, change the broadcast address to reflect the prefixlen */
	if (af == AF_INET) {
		/*
		 * get the interface address and set it, this should reset
		 * the broadcast address.
		 */
		(void) ioctl(s, SIOCGLIFADDR, (caddr_t)&lifr);
		(void) ioctl(s, SIOCSLIFADDR, (caddr_t)&lifr);
	}

	return (IPADM_SUCCESS);
}


/*
 * Callback function that sets the given value `pval' to one of the
 * properties among `deprecated', `private', and `transmit' as defined in
 * `pdp', on the address object in `arg'.
 */
/* ARGSUSED */
static ipadm_status_t
i_ipadm_set_addr_flag(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t af, uint_t flags)
{
	char		lifname[LIFNAMSIZ];
	uint64_t	on_flags = 0, off_flags = 0;
	boolean_t	on;
	ipadm_addrobj_t	ipaddr = (ipadm_addrobj_t)arg;

	if (ipaddr->ipadm_atype == IPADM_ADDR_DHCP &&
	    strcmp(pdp->ipd_name, "deprecated") == 0)
		return (IPADM_NOTSUP);

	if (strcmp(pval, IPADM_ONSTR) == 0)
		on = B_TRUE;
	else if (strcmp(pval, IPADM_OFFSTR) == 0)
		on = B_FALSE;
	else
		return (IPADM_INVALID_ARG);

	if (strcmp(pdp->ipd_name, "private") == 0) {
		if (on)
			on_flags = IFF_PRIVATE;
		else
			off_flags = IFF_PRIVATE;
	} else if (strcmp(pdp->ipd_name, "transmit") == 0) {
		if (on)
			off_flags = IFF_NOXMIT;
		else
			on_flags = IFF_NOXMIT;
	} else if (strcmp(pdp->ipd_name, "deprecated") == 0) {
		if (on)
			on_flags = IFF_DEPRECATED;
		else
			off_flags = IFF_DEPRECATED;
	} else {
		return (IPADM_PROP_UNKNOWN);
	}

	i_ipadm_addrobj2lifname(ipaddr, lifname, sizeof (lifname));
	return (i_ipadm_set_flags(iph, lifname, af, on_flags, off_flags));
}

/*
 * Callback function that sets the property `zone' on the address
 * object in `arg' to the value in `pval'.
 */
/* ARGSUSED */
static ipadm_status_t
i_ipadm_set_zone(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t af, uint_t flags)
{
	struct lifreq	lifr;
	zoneid_t	zoneid;
	int		s;

	/*
	 * To modify the zone assignment such that it persists across
	 * reboots, zonecfg(1M) must be used.
	 */
	if (flags & IPADM_OPT_PERSIST) {
		return (IPADM_NOTSUP);
	} else if (flags & IPADM_OPT_ACTIVE) {
		/* put logical interface into all zones */
		if (strcmp(pval, "all-zones") == 0) {
			zoneid = ALL_ZONES;
		} else {
			/* zone must be ready or running */
			if ((zoneid = getzoneidbyname(pval)) == -1)
				return (ipadm_errno2status(errno));
		}
	} else {
		return (IPADM_INVALID_ARG);
	}

	s = (af == AF_INET ? iph->iph_sock : iph->iph_sock6);
	bzero(&lifr, sizeof (lifr));
	i_ipadm_addrobj2lifname((ipadm_addrobj_t)arg, lifr.lifr_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_zoneid = zoneid;
	if (ioctl(s, SIOCSLIFZONE, (caddr_t)&lifr) < 0)
		return (ipadm_errno2status(errno));

	return (IPADM_SUCCESS);
}

/*
 * Callback function that sets the property `reqhost' on the address
 * object in `arg' to the value in `pval'.
 */
/* ARGSUSED */
static ipadm_status_t
i_ipadm_set_reqhost(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t af, uint_t flags)
{
	ipadm_status_t		status;
	ipadm_addrobj_t		ipaddr = (ipadm_addrobj_t)arg;

	if (ipaddr->ipadm_atype != IPADM_ADDR_DHCP)
		return (IPADM_NOTSUP);

	/*
	 * If requested to set reqhost just from active config but the
	 * address is not in active config, return error.
	 */
	if (!(ipaddr->ipadm_flags & IPMGMT_ACTIVE) &&
	    (flags & IPADM_OPT_ACTIVE) && !(flags & IPADM_OPT_PERSIST)) {
		return (IPADM_NOTFOUND);
	}

	status = ipadm_set_reqhost(ipaddr, pval);
	if (status != IPADM_SUCCESS)
		return (status);

	if (ipaddr->ipadm_flags & IPMGMT_ACTIVE) {
		status = i_ipadm_refresh_dhcp(ipaddr);

		/*
		 * We do not report a problem for IPADM_DHCP_IPC_TIMEOUT since
		 * it is only a soft error to indicate the caller that the
		 * lease might be renewed after the function returns.
		 */
		if (status != IPADM_SUCCESS && status != IPADM_DHCP_IPC_TIMEOUT)
			return (status);
	}

	status = i_ipadm_set_aobj_addrprop(iph, ipaddr, flags,
	    IPADM_NVP_REQHOST);
	return (status);
}

/*
 * Used by address object property callback functions that need to do a
 * two-stage update because the addrprop is cached on the address object.
 */
static ipadm_status_t
i_ipadm_set_aobj_addrprop(ipadm_handle_t iph, ipadm_addrobj_t ipaddr,
    uint_t flags, const char *propname)
{
	ipadm_status_t	status;
	uint32_t	two_stage_flags;

	/*
	 * Send the updated address object information to ipmgmtd, since the
	 * cached version of an addrprop resides on an aobjmap, but do
	 * not change the ACTIVE/PERSIST state of the aobjmap. Instead, request
	 * a two-stage, SET_PROPS update with ACTIVE/PERSIST as the first stage
	 * per the existing aobjmap flags and a second stage encoded in
	 * IPADM_OPT_PERSIST_PROPS.
	 */
	two_stage_flags = (flags | IPADM_OPT_SET_PROPS)
	    & ~(IPADM_OPT_ACTIVE | IPADM_OPT_PERSIST);
	if (ipaddr->ipadm_flags & IPMGMT_ACTIVE)
		two_stage_flags |= IPADM_OPT_ACTIVE;
	if (ipaddr->ipadm_flags & IPMGMT_PERSIST)
		two_stage_flags |= IPADM_OPT_PERSIST;
	if (flags & IPADM_OPT_PERSIST)
		two_stage_flags |= IPADM_OPT_PERSIST_PROPS;

	status = i_ipadm_addr_persist(iph, ipaddr, B_FALSE, two_stage_flags,
	    propname);
	return (status);
}

/*
 * Callback function that gets the property `broadcast' for the address
 * object in `arg'.
 */
/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_broadcast(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t af,
    uint_t valtype)
{
	struct sockaddr_in	*sin;
	struct lifreq		lifr;
	char			lifname[LIFNAMSIZ];
	ipadm_addrobj_t		ipaddr = (ipadm_addrobj_t)arg;
	ipadm_status_t		status;
	size_t			nbytes = 0;
	uint64_t		ifflags = 0;

	i_ipadm_addrobj2lifname(ipaddr, lifname, sizeof (lifname));
	if (ipaddr->ipadm_flags & IPMGMT_ACTIVE) {
		status = i_ipadm_get_flags(iph, lifname, af, &ifflags);
		if (status != IPADM_SUCCESS)
			return (status);
		if (!(ifflags & IFF_BROADCAST)) {
			buf[0] = '\0';
			return (IPADM_SUCCESS);
		}
	}

	switch (valtype) {
	case MOD_PROP_DEFAULT: {
		struct sockaddr_storage	mask;
		struct in_addr		broadaddr;
		uint_t			plen;
		in_addr_t		addr, maddr;
		char			val[MAXPROPVALLEN];
		uint_t			valsz = MAXPROPVALLEN;
		ipadm_status_t		status;
		int			err;
		struct sockaddr_in	*sin;

		if (!(ipaddr->ipadm_flags & IPMGMT_ACTIVE)) {
			/*
			 * Since the address is unknown we cannot
			 * obtain default prefixlen
			 */
			if (ipaddr->ipadm_atype == IPADM_ADDR_DHCP ||
			    ipaddr->ipadm_af == AF_INET6) {
				buf[0] = '\0';
				return (IPADM_SUCCESS);
			}
			/*
			 * For the static address, we get the address from the
			 * persistent db.
			 */
			status = i_ipadm_get_static_addr_db(iph, ipaddr);
			if (status != IPADM_SUCCESS)
				return (status);
			sin = SIN(&ipaddr->ipadm_static_addr);
			addr = sin->sin_addr.s_addr;
		} else {
			/*
			 * If the address object is active, we retrieve the
			 * address from kernel.
			 */
			bzero(&lifr, sizeof (lifr));
			(void) strlcpy(lifr.lifr_name, lifname,
			    sizeof (lifr.lifr_name));
			if (ioctl(iph->iph_sock, SIOCGLIFADDR,
			    (caddr_t)&lifr) < 0)
				return (ipadm_errno2status(errno));

			addr = (SIN(&lifr.lifr_addr))->sin_addr.s_addr;
		}
		/*
		 * For default broadcast address, get the address and the
		 * default prefixlen for that address and then compute the
		 * broadcast address.
		 */
		status = i_ipadm_get_prefixlen(iph, arg, NULL, val, &valsz, af,
		    MOD_PROP_DEFAULT);
		if (status != IPADM_SUCCESS)
			return (status);

		plen = atoi(val);
		if ((err = plen2mask(plen, AF_INET,
		    (struct sockaddr *)&mask)) != 0)
			return (ipadm_errno2status(err));
		maddr = (SIN(&mask))->sin_addr.s_addr;
		broadaddr.s_addr = (addr & maddr) | ~maddr;
		nbytes = snprintf(buf, *bufsize, "%s", inet_ntoa(broadaddr));
		break;
	}
	case MOD_PROP_ACTIVE:
		bzero(&lifr, sizeof (lifr));
		(void) strlcpy(lifr.lifr_name, lifname,
		    sizeof (lifr.lifr_name));
		if (ioctl(iph->iph_sock, SIOCGLIFBRDADDR,
		    (caddr_t)&lifr) < 0) {
			return (ipadm_errno2status(errno));
		} else {
			sin = SIN(&lifr.lifr_addr);
			nbytes = snprintf(buf, *bufsize, "%s",
			    inet_ntoa(sin->sin_addr));
		}
		break;
	default:
		return (IPADM_INVALID_ARG);
	}
	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		return (IPADM_NO_BUFS);
	}
	return (IPADM_SUCCESS);
}

/*
 * Callback function that retrieves the value of the property `prefixlen'
 * for the address object in `arg'.
 */
/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_prefixlen(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t af,
    uint_t valtype)
{
	struct lifreq	lifr;
	ipadm_addrobj_t	ipaddr = (ipadm_addrobj_t)arg;
	char		lifname[LIFNAMSIZ];
	int		s;
	uint32_t	prefixlen;
	size_t		nbytes;
	ipadm_status_t	status;
	uint64_t	lifflags;

	i_ipadm_addrobj2lifname(ipaddr, lifname, sizeof (lifname));
	if (ipaddr->ipadm_flags & IPMGMT_ACTIVE) {
		status = i_ipadm_get_flags(iph, lifname, af, &lifflags);
		if (status != IPADM_SUCCESS) {
			return (status);
		} else if (lifflags & IFF_POINTOPOINT) {
			buf[0] = '\0';
			return (status);
		}
	}

	s = (af == AF_INET ? iph->iph_sock : iph->iph_sock6);
	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, lifname, sizeof (lifr.lifr_name));
	switch (valtype) {
	case MOD_PROP_POSSIBLE:
		if (af == AF_INET)
			nbytes = snprintf(buf, *bufsize, "1-30,32");
		else
			nbytes = snprintf(buf, *bufsize, "1-126,128");
		break;
	case MOD_PROP_DEFAULT:
		if (ipaddr->ipadm_flags & IPMGMT_ACTIVE) {
			/*
			 * For static addresses, we retrieve the address
			 * from kernel if it is active.
			 */
			if (ioctl(s, SIOCGLIFADDR, (caddr_t)&lifr) < 0)
				return (ipadm_errno2status(errno));
			status = i_ipadm_get_default_prefixlen(
			    &lifr.lifr_addr, &prefixlen);
			if (status != IPADM_SUCCESS)
				return (status);
		} else if ((ipaddr->ipadm_flags & IPMGMT_PERSIST) &&
		    ipaddr->ipadm_atype == IPADM_ADDR_DHCP) {
			/*
			 * Since the address is unknown we cannot
			 * obtain default prefixlen
			 */
			buf[0] = '\0';
			return (IPADM_SUCCESS);
		} else {
			/*
			 * If not in active config, we use the address
			 * from persistent store.
			 */
			status = i_ipadm_get_static_addr_db(iph, ipaddr);
			if (status != IPADM_SUCCESS)
				return (status);
			status = i_ipadm_get_default_prefixlen(
			    &ipaddr->ipadm_static_addr, &prefixlen);
			if (status != IPADM_SUCCESS)
				return (status);
		}
		nbytes = snprintf(buf, *bufsize, "%u", prefixlen);
		break;
	case MOD_PROP_ACTIVE:
		if (ioctl(s, SIOCGLIFNETMASK, (caddr_t)&lifr) < 0)
			return (ipadm_errno2status(errno));
		prefixlen = lifr.lifr_addrlen;
		nbytes = snprintf(buf, *bufsize, "%u", prefixlen);
		break;
	default:
		return (IPADM_INVALID_ARG);
	}
	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		return (IPADM_NO_BUFS);
	}
	return (IPADM_SUCCESS);
}

/*
 * Callback function that retrieves the value of one of the properties
 * among `deprecated', `private', and `transmit' for the address object
 * in `arg'.
 */
/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_addr_flag(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t af,
    uint_t valtype)
{
	boolean_t	on = B_FALSE;
	char		lifname[LIFNAMSIZ];
	ipadm_status_t	status = IPADM_SUCCESS;
	uint64_t	ifflags;
	size_t		nbytes;
	ipadm_addrobj_t	ipaddr = (ipadm_addrobj_t)arg;

	switch (valtype) {
	case MOD_PROP_DEFAULT:
		if (strcmp(pdp->ipd_name, "private") == 0 ||
		    strcmp(pdp->ipd_name, "deprecated") == 0) {
			on = B_FALSE;
		} else if (strcmp(pdp->ipd_name, "transmit") == 0) {
			on = B_TRUE;
		} else {
			return (IPADM_PROP_UNKNOWN);
		}
		break;
	case MOD_PROP_ACTIVE:
		/*
		 * If the address is present in active configuration, we
		 * retrieve it from kernel to get the property value.
		 * Else, there is no value to return.
		 */
		i_ipadm_addrobj2lifname(ipaddr, lifname, sizeof (lifname));
		status = i_ipadm_get_flags(iph, lifname, af, &ifflags);
		if (status != IPADM_SUCCESS)
			return (status);
		if (strcmp(pdp->ipd_name, "private") == 0)
			on = (ifflags & IFF_PRIVATE);
		else if (strcmp(pdp->ipd_name, "transmit") == 0)
			on = !(ifflags & IFF_NOXMIT);
		else if (strcmp(pdp->ipd_name, "deprecated") == 0)
			on = (ifflags & IFF_DEPRECATED);
		break;
	default:
		return (IPADM_INVALID_ARG);
	}
	nbytes = snprintf(buf, *bufsize, "%s",
	    (on ? IPADM_ONSTR : IPADM_OFFSTR));
	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		status = IPADM_NO_BUFS;
	}

	return (status);
}

/*
 * Callback function that retrieves the value of the property `zone'
 * for the address object in `arg'.
 */
/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_zone(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t af,
    uint_t valtype)
{
	struct lifreq	lifr;
	char		zone_name[ZONENAME_MAX];
	int		s;
	size_t		nbytes = 0;

	if (iph->iph_zoneid != GLOBAL_ZONEID) {
		buf[0] = '\0';
		return (IPADM_SUCCESS);
	}

	/*
	 * we are in global zone. See if the lifname is assigned to shared-ip
	 * zone or global zone.
	 */
	switch (valtype) {
	case MOD_PROP_DEFAULT:
		if (getzonenamebyid(GLOBAL_ZONEID, zone_name,
		    sizeof (zone_name)) > 0)
			nbytes = snprintf(buf, *bufsize, "%s", zone_name);
		else
			return (ipadm_errno2status(errno));
		break;
	case MOD_PROP_ACTIVE:
		bzero(&lifr, sizeof (lifr));
		i_ipadm_addrobj2lifname((ipadm_addrobj_t)arg, lifr.lifr_name,
		    sizeof (lifr.lifr_name));
		s = (af == AF_INET ? iph->iph_sock : iph->iph_sock6);

		if (ioctl(s, SIOCGLIFZONE, (caddr_t)&lifr) == -1)
			return (ipadm_errno2status(errno));

		if (lifr.lifr_zoneid == ALL_ZONES) {
			nbytes = snprintf(buf, *bufsize, "%s", "all-zones");
		} else if (getzonenamebyid(lifr.lifr_zoneid, zone_name,
		    sizeof (zone_name)) < 0) {
			return (ipadm_errno2status(errno));
		} else {
			nbytes = snprintf(buf, *bufsize, "%s", zone_name);
		}
		break;
	default:
		return (IPADM_INVALID_ARG);
	}
	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		return (IPADM_NO_BUFS);
	}

	return (IPADM_SUCCESS);
}

/*
 * Callback function that retrieves the value of the property `primary'
 * for the address object in `arg'.
 */
/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_primary(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t af,
    uint_t valtype)
{
	ipadm_addrobj_t	ipaddr = (ipadm_addrobj_t)arg;
	const char		*onoff = "";
	size_t			nbytes;

	switch (valtype) {
	case MOD_PROP_DEFAULT:
		if (ipaddr->ipadm_atype == IPADM_ADDR_DHCP)
			onoff = IPADM_OFFSTR;
		break;
	case MOD_PROP_ACTIVE:
		if (ipaddr->ipadm_atype == IPADM_ADDR_DHCP) {
			dhcp_status_t	dhcp_status;
			ipadm_status_t	ipc_status;
			int			error;

			ipc_status = i_ipadm_dhcp_status(ipaddr, &dhcp_status,
			    &error);
			if (ipc_status != IPADM_SUCCESS &&
			    ipc_status != IPADM_NOTFOUND)
				return (ipc_status);

			onoff = dhcp_status.if_dflags & DHCP_IF_PRIMARY ?
			    IPADM_ONSTR : IPADM_OFFSTR;
		}
		break;
	default:
		return (IPADM_INVALID_ARG);
	}

	nbytes = strlcpy(buf, onoff, *bufsize);
	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		return (IPADM_NO_BUFS);
	}

	return (IPADM_SUCCESS);
}

/*
 * Callback function that retrieves the value of the property `reqhost'
 * for the address object in `arg'.
 */
/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_reqhost(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t af,
    uint_t valtype)
{
	ipadm_addrobj_t	ipaddr = (ipadm_addrobj_t)arg;
	const char	*reqhost = "";
	size_t		nbytes;

	switch (valtype) {
	case MOD_PROP_DEFAULT:
		break;
	case MOD_PROP_ACTIVE:
		if (ipaddr->ipadm_atype == IPADM_ADDR_DHCP)
			reqhost = ipaddr->ipadm_reqhost;
		break;
	default:
		return (IPADM_INVALID_ARG);
	}

	nbytes = strlcpy(buf, reqhost, *bufsize);
	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		return (IPADM_NO_BUFS);
	}

	return (IPADM_SUCCESS);
}

static ipadm_prop_desc_t *
i_ipadm_get_addrprop_desc(const char *pname)
{
	int i;

	for (i = 0; ipadm_addrprop_table[i].ipd_name != NULL; i++) {
		if (strcmp(pname, ipadm_addrprop_table[i].ipd_name) == 0 ||
		    (ipadm_addrprop_table[i].ipd_old_name != NULL &&
		    strcmp(pname, ipadm_addrprop_table[i].ipd_old_name) == 0))
			return (&ipadm_addrprop_table[i]);
	}
	return (NULL);
}

/*
 * Gets the value of the given address property `pname' for the address
 * object with name `aobjname'.
 */
ipadm_status_t
ipadm_get_addrprop(ipadm_handle_t iph, const char *pname, char *buf,
    uint_t *bufsize, const char *aobjname, uint_t valtype)
{
	struct ipadm_addrobj_s	ipaddr;
	ipadm_status_t		status = IPADM_SUCCESS;
	sa_family_t		af;
	ipadm_prop_desc_t	*pdp = NULL;

	if (iph == NULL || pname == NULL || buf == NULL ||
	    bufsize == NULL || *bufsize == 0 || aobjname == NULL) {
		return (IPADM_INVALID_ARG);
	}

	/* find the property in the property description table */
	if ((pdp = i_ipadm_get_addrprop_desc(pname)) == NULL)
		return (IPADM_PROP_UNKNOWN);

	/*
	 * For the given aobjname, get the addrobj it represents and
	 * retrieve the property value for that object.
	 */
	i_ipadm_init_addr(&ipaddr, "", aobjname, IPADM_ADDR_NONE);
	if ((status = i_ipadm_get_addrobj(iph, &ipaddr)) != IPADM_SUCCESS)
		return (status);

	if (ipaddr.ipadm_atype == IPADM_ADDR_IPV6_ADDRCONF)
		return (IPADM_NOTSUP);
	af = ipaddr.ipadm_af;

	/*
	 * Call the appropriate callback function to based on the field
	 * that was asked for.
	 */
	switch (valtype) {
	case IPADM_OPT_PERM:
		status = i_ipadm_pd2permstr(pdp, buf, bufsize);
		break;
	case IPADM_OPT_ACTIVE:
		if (!(ipaddr.ipadm_flags & IPMGMT_ACTIVE)) {
			buf[0] = '\0';
		} else {
			status = pdp->ipd_get(iph, &ipaddr, pdp, buf, bufsize,
			    af, MOD_PROP_ACTIVE);
		}
		break;
	case IPADM_OPT_DEFAULT:
		status = pdp->ipd_get(iph, &ipaddr, pdp, buf, bufsize,
		    af, MOD_PROP_DEFAULT);
		break;
	case IPADM_OPT_POSSIBLE:
		if (pdp->ipd_get_range != NULL) {
			status = pdp->ipd_get_range(iph, &ipaddr, pdp, buf,
			    bufsize, af, MOD_PROP_POSSIBLE);
			break;
		}
		buf[0] = '\0';
		break;
	case IPADM_OPT_PERSIST:
		status = i_ipadm_get_persist_propval(iph, pdp, buf, bufsize,
		    &ipaddr);
		break;
	default:
		status = IPADM_INVALID_ARG;
		break;
	}

	return (status);
}

/*
 * Sets the value of the given address property `pname' to `pval' for the
 * address object with name `aobjname'.
 */
ipadm_status_t
ipadm_set_addrprop(ipadm_handle_t iph, const char *pname,
    const char *pval, const char *aobjname, uint_t pflags)
{
	struct ipadm_addrobj_s	ipaddr;
	sa_family_t		af;
	ipadm_prop_desc_t	*pdp = NULL;
	char			defbuf[MAXPROPVALLEN];
	uint_t			defbufsize = MAXPROPVALLEN;
	boolean_t 		reset = (pflags & IPADM_OPT_DEFAULT);
	ipadm_status_t		status = IPADM_SUCCESS;

	/* Check for solaris.network.interface.config authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);

	if (iph == NULL || pname == NULL || aobjname == NULL || pflags == 0 ||
	    pflags == IPADM_OPT_PERSIST ||
	    (pflags & ~(IPADM_COMMON_OPT_MASK|IPADM_OPT_DEFAULT)) ||
	    (!reset && pval == NULL)) {
		return (IPADM_INVALID_ARG);
	}

	/* find the property in the property description table */
	if ((pdp = i_ipadm_get_addrprop_desc(pname)) == NULL)
		return (IPADM_PROP_UNKNOWN);

	if (pdp->ipd_set == NULL || (reset && pdp->ipd_get == NULL))
		return (IPADM_NOTSUP);

	if (!(pdp->ipd_flags & IPADMPROP_MULVAL) &&
	    (pflags & (IPADM_OPT_APPEND|IPADM_OPT_REMOVE))) {
		return (IPADM_INVALID_ARG);
	}

	/*
	 * For the given aobjname, get the addrobj it represents and
	 * set the property value for that object.
	 */
	i_ipadm_init_addr(&ipaddr, "", aobjname, IPADM_ADDR_NONE);
	if ((status = i_ipadm_get_addrobj(iph, &ipaddr)) != IPADM_SUCCESS)
		return (status);

	if (!(ipaddr.ipadm_flags & IPMGMT_ACTIVE))
		return (IPADM_OP_DISABLE_OBJ);

	/* Persistent operation not allowed on a temporary object. */
	if ((pflags & IPADM_OPT_PERSIST) &&
	    !(ipaddr.ipadm_flags & IPMGMT_PERSIST))
		return (IPADM_TEMPORARY_OBJ);

	/*
	 * Currently, setting an address property on an address object of type
	 * IPADM_ADDR_IPV6_ADDRCONF is not supported. Supporting it involves
	 * in.ndpd retrieving the address properties from ipmgmtd for given
	 * address object and then setting them on auto-configured addresses,
	 * whenever in.ndpd gets a new prefix. This will be supported in
	 * future releases.
	 */
	if (ipaddr.ipadm_atype == IPADM_ADDR_IPV6_ADDRCONF)
		return (IPADM_NOTSUP);

	/*
	 * Setting an address property on an address object that is
	 * not present in active configuration is not supported.
	 */
	if (!(ipaddr.ipadm_flags & IPMGMT_ACTIVE))
		return (IPADM_NOTSUP);

	af = ipaddr.ipadm_af;
	if (reset) {
		/*
		 * If we were asked to reset the value, we need to fetch
		 * the default value and set the default value.
		 */
		status = pdp->ipd_get(iph, &ipaddr, pdp, defbuf, &defbufsize,
		    af, MOD_PROP_DEFAULT);
		if (status != IPADM_SUCCESS)
			return (status);
		pval = defbuf;
	}
	/* set the user provided or default property value */
	status = pdp->ipd_set(iph, &ipaddr, pdp, pval, af, pflags);
	if (status != IPADM_SUCCESS)
		return (status);

	/*
	 * If IPADM_OPT_PERSIST was set in `flags', we need to store
	 * property and its value in persistent DB.
	 */
	if (pflags & IPADM_OPT_PERSIST) {
		status = i_ipadm_persist_propval(iph, pdp, pval, &ipaddr,
		    pflags);
	}

	return (status);
}

/*
 * Remove the address specified by the address object in `addr'
 * from kernel. If the address is on a non-zero logical interface, we do a
 * SIOCLIFREMOVEIF, otherwise we set the address to INADDR_ANY for IPv4 or
 * :: for IPv6.
 */
ipadm_status_t
i_ipadm_delete_addr(ipadm_handle_t iph, ipadm_addrobj_t addr)
{
	struct lifreq	lifr;
	int		sock;
	ipadm_status_t	status;

	bzero(&lifr, sizeof (lifr));
	i_ipadm_addrobj2lifname(addr, lifr.lifr_name, sizeof (lifr.lifr_name));
	sock = (addr->ipadm_af == AF_INET ? iph->iph_sock : iph->iph_sock6);
	if (addr->ipadm_lifnum == 0) {
		/*
		 * Fake the deletion of the 0'th address by
		 * clearing IFF_UP and setting it to as 0.0.0.0 or ::.
		 */
		status = i_ipadm_set_flags(iph, addr->ipadm_ifname,
		    addr->ipadm_af, 0, IFF_UP);
		if (status != IPADM_SUCCESS)
			return (status);
		bzero(&lifr.lifr_addr, sizeof (lifr.lifr_addr));
		lifr.lifr_addr.ss_family = addr->ipadm_af;
		if (ioctl(sock, SIOCSLIFADDR, (caddr_t)&lifr) < 0)
			return (ipadm_errno2status(errno));
		if (ioctl(sock, SIOCSLIFDSTADDR, (caddr_t)&lifr) < 0)
			return (ipadm_errno2status(errno));
	} else if (ioctl(sock, SIOCLIFREMOVEIF, (caddr_t)&lifr) < 0) {
		return (ipadm_errno2status(errno));
	}

	return (IPADM_SUCCESS);
}

/*
 * Extracts the IPv6 address from the nvlist in `nvl'.
 */
ipadm_status_t
i_ipadm_nvl2in6_addr(nvlist_t *nvl, char *addr_type, in6_addr_t *in6_addr)
{
	uint8_t	*addr6;
	uint_t	n;

	if (nvlist_lookup_uint8_array(nvl, addr_type, &addr6, &n) != 0)
		return (IPADM_NOTFOUND);
	assert(n == 16);
	bcopy(addr6, in6_addr->s6_addr, n);
	return (IPADM_SUCCESS);
}

/*
 * Used to validate the given addrobj name string. Length of `aobjname'
 * cannot exceed IPADM_AOBJ_USTRSIZ. `aobjname' should start with an
 * alphabetic character and it can only contain alphanumeric characters.
 */
static boolean_t
i_ipadm_is_user_aobjname_valid(const char *aobjname)
{
	const char	*cp;

	if (aobjname == NULL || strlen(aobjname) >= IPADM_AOBJ_USTRSIZ ||
	    !isalpha(*aobjname)) {
		return (B_FALSE);
	}
	for (cp = aobjname + 1; *cp && isalnum(*cp); cp++)
		;
	return (*cp == '\0');
}

/*
 * Computes the prefixlen for the given `addr' based on the netmask found using
 * the order specified in /etc/nsswitch.conf. If not found, then the
 * prefixlen is computed using the Classful subnetting semantics defined
 * in RFC 791 for IPv4 and RFC 4291 for IPv6.
 */
static ipadm_status_t
i_ipadm_get_default_prefixlen(struct sockaddr_storage *addr, uint32_t *plen)
{
	sa_family_t af = addr->ss_family;
	struct sockaddr_storage mask;
	struct sockaddr_in *m = (struct sockaddr_in *)&mask;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	struct in_addr ia;
	uint32_t prefixlen = 0;

	switch (af) {
	case AF_INET:
		sin = SIN(addr);
		ia.s_addr = ntohl(sin->sin_addr.s_addr);
		get_netmask4(&ia, &m->sin_addr);
		m->sin_addr.s_addr = htonl(m->sin_addr.s_addr);
		m->sin_family = AF_INET;
		prefixlen = mask2plen((struct sockaddr *)&mask);
		break;
	case AF_INET6:
		sin6 = SIN6(addr);
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
			prefixlen = 10;
		else
			prefixlen = 64;
		break;
	default:
		return (IPADM_INVALID_ARG);
	}
	*plen = prefixlen;
	return (IPADM_SUCCESS);
}

ipadm_status_t
i_ipadm_resolve_addr(const char *name, sa_family_t af,
    struct sockaddr_storage *ss)
{
	struct addrinfo hints, *ai;
	int rc;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	boolean_t is_mapped;

	(void) memset(&hints, 0, sizeof (hints));
	hints.ai_family = af;
	hints.ai_flags = (AI_ALL | AI_V4MAPPED);
	rc = getaddrinfo(name, NULL, &hints, &ai);
	if (rc != 0) {
		if (rc == EAI_NONAME)
			return (IPADM_BAD_ADDR);
		else
			return (IPADM_FAILURE);
	}
	if (ai->ai_next != NULL) {
		/* maps to more than one hostname */
		freeaddrinfo(ai);
		return (IPADM_BAD_HOSTNAME);
	}
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	is_mapped = IN6_IS_ADDR_V4MAPPED(&(SIN6(ai->ai_addr))->sin6_addr);
	if (is_mapped) {
		sin = SIN(ss);
		sin->sin_family = AF_INET;
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		IN6_V4MAPPED_TO_INADDR(&(SIN6(ai->ai_addr))->sin6_addr,
		    &sin->sin_addr);
	} else {
		sin6 = SIN6(ss);
		sin6->sin6_family = AF_INET6;
		bcopy(ai->ai_addr, sin6, sizeof (*sin6));
	}
	freeaddrinfo(ai);
	return (IPADM_SUCCESS);
}

/*
 * This takes a static address string <addr>[/<mask>] or a hostname
 * and maps it to a single numeric IP address, consulting DNS if
 * hostname was provided. If a specific address family was requested,
 * an error is returned if the given hostname does not map to an address
 * of the given family. Note that this function returns failure
 * if the name maps to more than one IP address.
 */
ipadm_status_t
ipadm_set_addr(ipadm_addrobj_t ipaddr, const char *astr, sa_family_t af)
{
	char		*prefixlenstr;
	uint32_t	prefixlen = 0;
	char		*endp;
	/*
	 * We use (NI_MAXHOST + 5) because the longest possible
	 * astr will have (NI_MAXHOST + '/' + {a maximum of 32 for IPv4
	 * or a maximum of 128 for IPv6 + '\0') chars
	 */
	char		addrstr[NI_MAXHOST + 5];
	ipadm_status_t	status;

	(void) snprintf(addrstr, sizeof (addrstr), "%s", astr);
	if ((prefixlenstr = strchr(addrstr, '/')) != NULL) {
		*prefixlenstr++ = '\0';
		errno = 0;
		prefixlen = strtoul(prefixlenstr, &endp, 10);
		if (errno != 0 || *endp != '\0')
			return (IPADM_INVALID_ARG);
		if ((af == AF_INET && prefixlen > IP_ABITS) ||
		    (af == AF_INET6 && prefixlen > IPV6_ABITS))
			return (IPADM_INVALID_ARG);
	}

	status = i_ipadm_resolve_addr(addrstr, af, &ipaddr->ipadm_static_addr);
	if (status == IPADM_SUCCESS) {
		(void) strlcpy(ipaddr->ipadm_static_aname, addrstr,
		    sizeof (ipaddr->ipadm_static_aname));
		ipaddr->ipadm_af = ipaddr->ipadm_static_addr.ss_family;
		ipaddr->ipadm_static_prefixlen = prefixlen;
	}
	return (status);
}

/*
 * Gets the static source address from the address object in `ipaddr'.
 * Memory for `addr' should be already allocated by the caller.
 */
ipadm_status_t
ipadm_get_addr(const ipadm_addrobj_t ipaddr, struct sockaddr_storage *addr)
{
	if (ipaddr == NULL || ipaddr->ipadm_atype != IPADM_ADDR_STATIC ||
	    addr == NULL) {
		return (IPADM_INVALID_ARG);
	}
	*addr = ipaddr->ipadm_static_addr;

	return (IPADM_SUCCESS);
}

/*
 * Set up tunnel destination address in ipaddr by contacting DNS.
 * The function works similar to ipadm_set_addr().
 * The dst_addr must resolve to exactly one address. IPADM_BAD_ADDR is returned
 * if dst_addr resolves to more than one address. The caller has to verify
 * that ipadm_static_addr and ipadm_static_dst_addr have the same ss_family
 */
ipadm_status_t
ipadm_set_dst_addr(ipadm_addrobj_t ipaddr, const char *daddrstr, sa_family_t af)
{
	ipadm_status_t	status;

	/* mask lengths are not meaningful for point-to-point interfaces. */
	if (strchr(daddrstr, '/') != NULL)
		return (IPADM_BAD_ADDR);

	status = i_ipadm_resolve_addr(daddrstr, af,
	    &ipaddr->ipadm_static_dst_addr);
	if (status == IPADM_SUCCESS) {
		(void) strlcpy(ipaddr->ipadm_static_dname, daddrstr,
		    sizeof (ipaddr->ipadm_static_dname));
	}
	return (status);
}

/*
 * Sets the interface ID in the address object `ipaddr' with the address
 * in the string `interface_id'. This interface ID will be used when
 * ipadm_create_addr() is called with `ipaddr' with address type
 * set to IPADM_ADDR_IPV6_ADDRCONF.
 */
ipadm_status_t
ipadm_set_interface_id(ipadm_addrobj_t ipaddr, const char *interface_id)
{
	struct sockaddr_in6	*sin6;
	char			*end;
	char			*cp;
	uint32_t		prefixlen;
	char			addrstr[INET6_ADDRSTRLEN + 1];

	if (ipaddr == NULL || interface_id == NULL ||
	    ipaddr->ipadm_atype != IPADM_ADDR_IPV6_ADDRCONF)
		return (IPADM_INVALID_ARG);

	(void) strlcpy(addrstr, interface_id, sizeof (addrstr));
	if ((cp = strchr(addrstr, '/')) == NULL)
		return (IPADM_INVALID_ARG);
	*cp++ = '\0';
	sin6 = &ipaddr->ipadm_intfid;
	if (inet_pton(AF_INET6, addrstr, &sin6->sin6_addr) == 1) {
		errno = 0;
		prefixlen = strtoul(cp, &end, 10);
		if (errno != 0 || *end != '\0' || prefixlen > IPV6_ABITS)
			return (IPADM_INVALID_ARG);
		sin6->sin6_family = AF_INET6;
		ipaddr->ipadm_intfidlen = prefixlen;
		return (IPADM_SUCCESS);
	}
	return (IPADM_INVALID_ARG);
}

/*
 * Sets the value for the field `ipadm_stateless' in address object `ipaddr'.
 */
ipadm_status_t
ipadm_set_stateless(ipadm_addrobj_t ipaddr, boolean_t stateless)
{
	if (ipaddr == NULL ||
	    ipaddr->ipadm_atype != IPADM_ADDR_IPV6_ADDRCONF)
		return (IPADM_INVALID_ARG);
	ipaddr->ipadm_stateless = stateless;

	return (IPADM_SUCCESS);
}

/*
 * Sets the value for the field `ipadm_stateful' in address object `ipaddr'.
 */
ipadm_status_t
ipadm_set_stateful(ipadm_addrobj_t ipaddr, boolean_t stateful)
{
	if (ipaddr == NULL ||
	    ipaddr->ipadm_atype != IPADM_ADDR_IPV6_ADDRCONF)
		return (IPADM_INVALID_ARG);
	ipaddr->ipadm_stateful = stateful;

	return (IPADM_SUCCESS);
}

/*
 * Sets the dhcp parameter `ipadm_primary' in the address object `ipaddr'.
 * The field is used during the address creation with address
 * type IPADM_ADDR_DHCP. It specifies if the interface should be set
 * as a primary interface for getting dhcp global options from the DHCP server.
 */
ipadm_status_t
ipadm_set_primary(ipadm_addrobj_t ipaddr, boolean_t primary)
{
	if (ipaddr == NULL || ipaddr->ipadm_atype != IPADM_ADDR_DHCP)
		return (IPADM_INVALID_ARG);
	ipaddr->ipadm_primary = primary;

	return (IPADM_SUCCESS);
}

/*
 * Sets the dhcp parameter `ipadm_wait' in the address object `ipaddr'.
 * This field is used during the address creation with address type
 * IPADM_ADDR_DHCP. It specifies how long the API ipadm_create_addr()
 * should wait before returning while the dhcp address is being acquired
 * by the dhcpagent.
 * Possible values:
 * - IPADM_DHCP_WAIT_FOREVER : Do not return until dhcpagent returns.
 * - IPADM_DHCP_WAIT_DEFAULT : Wait a default amount of time before returning.
 * - <integer>	   : Wait the specified number of seconds before returning.
 */
ipadm_status_t
ipadm_set_wait_time(ipadm_addrobj_t ipaddr, int32_t wait)
{
	if (ipaddr == NULL || ipaddr->ipadm_atype != IPADM_ADDR_DHCP)
		return (IPADM_INVALID_ARG);
	ipaddr->ipadm_wait = wait;
	return (IPADM_SUCCESS);
}

/*
 * Sets the dhcp parameter `ipadm_reqhost' in the address object `ipaddr',
 * but validate any non-nil value using ipadm_is_valid_hostname() and also
 * check length.
 */
ipadm_status_t
ipadm_set_reqhost(ipadm_addrobj_t ipaddr, const char *reqhost)
{
	const size_t HNLEN = sizeof (ipaddr->ipadm_reqhost);

	if (ipaddr == NULL || ipaddr->ipadm_atype != IPADM_ADDR_DHCP)
		return (IPADM_INVALID_ARG);

	if (ipadm_is_nil_hostname(reqhost))
		*ipaddr->ipadm_reqhost = '\0';
	else if (!ipadm_is_valid_hostname(reqhost))
		return (IPADM_INVALID_ARG);
	else if (strlcpy(ipaddr->ipadm_reqhost, reqhost, HNLEN) >= HNLEN)
		return (IPADM_INVALID_ARG);
	return (IPADM_SUCCESS);
}

/*
 * Creates a placeholder for the `ipadm_aobjname' in the ipmgmtd `aobjmap'.
 * If the `aobjname' already exists in the daemon's `aobjmap' then
 * IPADM_ADDROBJ_EXISTS will be returned.
 *
 * If the libipadm consumer set `ipaddr.ipadm_aobjname[0]' to `\0', then the
 * daemon will generate an `aobjname' for the given `ipaddr'.
 */
ipadm_status_t
i_ipadm_lookupadd_addrobj(ipadm_handle_t iph, ipadm_addrobj_t ipaddr)
{
	ipmgmt_aobjop_arg_t	larg;
	ipmgmt_aobjop_rval_t	rval, *rvalp;
	int			err;

	bzero(&larg, sizeof (larg));
	larg.ia_cmd = IPMGMT_CMD_ADDROBJ_LOOKUPADD;
	(void) strlcpy(larg.ia_aobjname, ipaddr->ipadm_aobjname,
	    sizeof (larg.ia_aobjname));
	(void) strlcpy(larg.ia_ifname, ipaddr->ipadm_ifname,
	    sizeof (larg.ia_ifname));
	larg.ia_family = ipaddr->ipadm_af;
	larg.ia_atype = ipaddr->ipadm_atype;

	rvalp = &rval;
	err = ipadm_door_call(iph, &larg, sizeof (larg), (void **)&rvalp,
	    sizeof (rval), B_FALSE);
	if (err == 0 && ipaddr->ipadm_aobjname[0] == '\0') {
		/* copy the daemon generated `aobjname' into `ipadddr' */
		(void) strlcpy(ipaddr->ipadm_aobjname, rval.ir_aobjname,
		    sizeof (ipaddr->ipadm_aobjname));
	}
	if (err == EEXIST)
		return (IPADM_ADDROBJ_EXISTS);
	return (ipadm_errno2status(err));
}

/*
 * Sets the logical interface number in the ipmgmtd's memory map for the
 * address object `ipaddr'. If another address object has the same
 * logical interface number, IPADM_ADDROBJ_EXISTS is returned.
 */
ipadm_status_t
i_ipadm_setlifnum_addrobj(ipadm_handle_t iph, ipadm_addrobj_t ipaddr)
{
	ipmgmt_aobjop_arg_t	larg;
	ipmgmt_retval_t		rval, *rvalp;
	int			err;

	if (iph->iph_flags & IPH_IPMGMTD)
		return (IPADM_SUCCESS);

	bzero(&larg, sizeof (larg));
	larg.ia_cmd = IPMGMT_CMD_ADDROBJ_SETLIFNUM;
	(void) strlcpy(larg.ia_aobjname, ipaddr->ipadm_aobjname,
	    sizeof (larg.ia_aobjname));
	larg.ia_lnum = ipaddr->ipadm_lifnum;
	(void) strlcpy(larg.ia_ifname, ipaddr->ipadm_ifname,
	    sizeof (larg.ia_ifname));
	larg.ia_family = ipaddr->ipadm_af;

	rvalp = &rval;
	err = ipadm_door_call(iph, &larg, sizeof (larg), (void **)&rvalp,
	    sizeof (rval), B_FALSE);
	if (err == EEXIST)
		return (IPADM_ADDROBJ_EXISTS);
	return (ipadm_errno2status(err));
}

/*
 * Creates the IPv4 or IPv6 address in the nvlist `nvl' on the interface
 * `ifname'. If a hostname is present, it is resolved before the address
 * is created.
 */
ipadm_status_t
i_ipadm_enable_static(ipadm_handle_t iph, const char *ifname, nvlist_t *nvl,
    sa_family_t af)
{
	char			*prefixlenstr = NULL;
	char			*upstr = NULL;
	char			*sname = NULL, *dname = NULL;
	struct ipadm_addrobj_s	ipaddr;
	char			*aobjname = NULL;
	nvlist_t		*nvaddr = NULL;
	nvpair_t		*nvp;
	char			*cidraddr;
	char			*name;
	ipadm_status_t		status;
	int			err = 0;
	uint32_t		flags = IPADM_OPT_ACTIVE;

	/* retrieve the address information */
	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		name = nvpair_name(nvp);
		if (strcmp(name, IPADM_NVP_IPV4ADDR) == 0 ||
		    strcmp(name, IPADM_NVP_IPV6ADDR) == 0) {
			err = nvpair_value_nvlist(nvp, &nvaddr);
		} else if (strcmp(name, IPADM_NVP_AOBJNAME) == 0) {
			err = nvpair_value_string(nvp, &aobjname);
		} else if (strcmp(name, IPADM_NVP_PREFIXLEN) == 0) {
			err = nvpair_value_string(nvp, &prefixlenstr);
		} else if (strcmp(name, "up") == 0) {
			err = nvpair_value_string(nvp, &upstr);
		}
		if (err != 0)
			return (ipadm_errno2status(err));
	}
	for (nvp = nvlist_next_nvpair(nvaddr, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvaddr, nvp)) {
		name = nvpair_name(nvp);
		if (strcmp(name, IPADM_NVP_IPADDRHNAME) == 0)
			err = nvpair_value_string(nvp, &sname);
		else if (strcmp(name, IPADM_NVP_IPDADDRHNAME) == 0)
			err = nvpair_value_string(nvp, &dname);
		if (err != 0)
			return (ipadm_errno2status(err));
	}

	if (strcmp(upstr, "yes") == 0)
		flags |= IPADM_OPT_UP;

	/* build the address object from the above information */
	i_ipadm_init_addr(&ipaddr, ifname, aobjname, IPADM_ADDR_STATIC);
	if (prefixlenstr != NULL && atoi(prefixlenstr) > 0) {
		if (asprintf(&cidraddr, "%s/%s", sname, prefixlenstr) == -1)
			return (IPADM_NO_MEMORY);
		status = ipadm_set_addr(&ipaddr, cidraddr, af);
		free(cidraddr);
	} else {
		status = ipadm_set_addr(&ipaddr, sname, af);
	}
	if (status != IPADM_SUCCESS)
		return (status);

	if (dname != NULL) {
		status = ipadm_set_dst_addr(&ipaddr, dname, af);
		if (status != IPADM_SUCCESS)
			return (status);
	}
	return (i_ipadm_create_addr(iph, &ipaddr, flags));
}

/*
 * Creates a dhcp address on the interface `ifname' based on the
 * IPADM_ADDR_DHCP address object parameters from the nvlist `nvl'.
 */
ipadm_status_t
i_ipadm_enable_dhcp(ipadm_handle_t iph, const char *ifname, nvlist_t *nvl)
{
	int32_t			wait = IPADM_DHCP_WAIT_DEFAULT;
	boolean_t		primary = B_FALSE;
	nvlist_t		*nvdhcp = NULL;
	nvpair_t		*nvp;
	char			*name;
	struct ipadm_addrobj_s	ipaddr;
	char			*aobjname = NULL, *reqhost = NULL;
	int			err = 0;
	ipadm_status_t		ipadm_err = IPADM_SUCCESS;

	/* Extract the dhcp parameters */
	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		name = nvpair_name(nvp);
		if (strcmp(name, IPADM_NVP_DHCP) == 0)
			err = nvpair_value_nvlist(nvp, &nvdhcp);
		else if (strcmp(name, IPADM_NVP_AOBJNAME) == 0)
			err = nvpair_value_string(nvp, &aobjname);
		else if (strcmp(name, IPADM_NVP_REQHOST) == 0)
			err = nvpair_value_string(nvp, &reqhost);
		if (err != 0)
			return (ipadm_errno2status(err));
	}
	for (nvp = nvlist_next_nvpair(nvdhcp, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvdhcp, nvp)) {
		name = nvpair_name(nvp);
		if (strcmp(name, IPADM_NVP_WAIT) == 0)
			err = nvpair_value_int32(nvp, &wait);
		else if (strcmp(name, IPADM_NVP_PRIMARY) == 0)
			err = nvpair_value_boolean_value(nvp, &primary);
		if (err != 0)
			return (ipadm_errno2status(err));
	}

	/* Build the address object */
	i_ipadm_init_addr(&ipaddr, ifname, aobjname, IPADM_ADDR_DHCP);
	ipaddr.ipadm_primary = primary;
	if (iph->iph_flags & IPH_INIT)
		ipaddr.ipadm_wait = 0;
	else
		ipaddr.ipadm_wait = wait;
	ipadm_err = ipadm_set_reqhost(&ipaddr, reqhost);
	if (ipadm_err != IPADM_SUCCESS)
		return (ipadm_err);
	ipaddr.ipadm_af = AF_INET;
	return (i_ipadm_create_dhcp(iph, &ipaddr, IPADM_OPT_ACTIVE));
}

/*
 * Creates auto-configured addresses on the interface `ifname' based on
 * the IPADM_ADDR_IPV6_ADDRCONF address object parameters from the nvlist `nvl'.
 */
ipadm_status_t
i_ipadm_enable_addrconf(ipadm_handle_t iph, const char *ifname, nvlist_t *nvl)
{
	struct ipadm_addrobj_s	ipaddr;
	char		*stateful = NULL, *stateless = NULL;
	uint_t		n;
	uint8_t		*addr6 = NULL;
	uint32_t	intfidlen = 0;
	char		*aobjname;
	nvlist_t	*nvaddr;
	nvpair_t	*nvp;
	char		*name;
	int		err = 0;

	/* Extract the parameters */
	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		name = nvpair_name(nvp);
		if (strcmp(name, IPADM_NVP_INTFID) == 0)
			err = nvpair_value_nvlist(nvp, &nvaddr);
		else if (strcmp(name, IPADM_NVP_AOBJNAME) == 0)
			err = nvpair_value_string(nvp, &aobjname);
		if (err != 0)
			return (ipadm_errno2status(err));
	}
	for (nvp = nvlist_next_nvpair(nvaddr, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvaddr, nvp)) {
		name = nvpair_name(nvp);
		if (strcmp(name, IPADM_NVP_IPNUMADDR) == 0)
			err = nvpair_value_uint8_array(nvp, &addr6, &n);
		if (strcmp(name, IPADM_NVP_PREFIXLEN) == 0)
			err = nvpair_value_uint32(nvp, &intfidlen);
		else if (strcmp(name, IPADM_NVP_STATELESS) == 0)
			err = nvpair_value_string(nvp, &stateless);
		else if (strcmp(name, IPADM_NVP_STATEFUL) == 0)
			err = nvpair_value_string(nvp, &stateful);
		if (err != 0)
			return (ipadm_errno2status(err));
	}
	/* Build the address object. */
	i_ipadm_init_addr(&ipaddr, ifname, aobjname, IPADM_ADDR_IPV6_ADDRCONF);
	if (intfidlen > 0) {
		ipaddr.ipadm_intfidlen = intfidlen;
		bcopy(addr6, &ipaddr.ipadm_intfid.sin6_addr.s6_addr, n);
	}
	ipaddr.ipadm_stateless = (strcmp(stateless, "yes") == 0);
	ipaddr.ipadm_stateful = (strcmp(stateful, "yes") == 0);
	return (i_ipadm_create_ipv6addrs(iph, &ipaddr, IPADM_OPT_ACTIVE));
}

/*
 * Allocates `ipadm_addrobj_t' and populates the relevant member fields based on
 * the provided `type'. `aobjname' represents the address object name, which
 * is of the form `<ifname>/<addressname>'.
 *
 * The caller has to minimally provide <ifname>. If <addressname> is not
 * provided, then a default one will be generated by the API.
 */
ipadm_status_t
ipadm_create_addrobj(ipadm_addr_type_t type, const char *aobjname,
    ipadm_addrobj_t *ipaddr)
{
	ipadm_addrobj_t	newaddr;
	ipadm_status_t	status;
	char		*aname, *cp;
	char		ifname[IPADM_AOBJSIZ];
	ifspec_t 	ifsp;

	if (ipaddr == NULL)
		return (IPADM_INVALID_ARG);
	*ipaddr = NULL;

	if (aobjname == NULL || aobjname[0] == '\0')
		return (IPADM_INVALID_ARG);

	if (strlcpy(ifname, aobjname, IPADM_AOBJSIZ) >= IPADM_AOBJSIZ)
		return (IPADM_INVALID_ARG);

	if ((aname = strchr(ifname, '/')) != NULL)
		*aname++ = '\0';

	/* Check if the interface name is valid. */
	if (!ifparse_ifspec(ifname, &ifsp))
		return (IPADM_INVALID_ARG);

	/* Check if the given addrobj name is valid. */
	if (aname != NULL && !i_ipadm_is_user_aobjname_valid(aname))
		return (IPADM_INVALID_ARG);

	if ((newaddr = calloc(1, sizeof (struct ipadm_addrobj_s))) == NULL)
		return (IPADM_NO_MEMORY);

	/*
	 * If the ifname has logical interface number, extract it and assign
	 * it to `ipadm_lifnum'. Only applications with IPH_LEGACY set will do
	 * this today. We will check for the validity later in
	 * i_ipadm_validate_create_addr().
	 */
	if (ifsp.ifsp_lunvalid) {
		newaddr->ipadm_lifnum = ifsp.ifsp_lun;
		cp = strchr(ifname, IPADM_LOGICAL_SEP);
		*cp = '\0';
	}
	(void) strlcpy(newaddr->ipadm_ifname, ifname,
	    sizeof (newaddr->ipadm_ifname));

	if (aname != NULL) {
		(void) snprintf(newaddr->ipadm_aobjname,
		    sizeof (newaddr->ipadm_aobjname), "%s/%s", ifname, aname);
	}

	switch (type) {
	case IPADM_ADDR_IPV6_ADDRCONF:
		newaddr->ipadm_intfidlen = 0;
		newaddr->ipadm_stateful = B_TRUE;
		newaddr->ipadm_stateless = B_TRUE;
		newaddr->ipadm_af = AF_INET6;
		break;

	case IPADM_ADDR_DHCP:
		newaddr->ipadm_primary = B_FALSE;
		newaddr->ipadm_wait = IPADM_DHCP_WAIT_DEFAULT;
		newaddr->ipadm_af = AF_INET;
		break;

	case IPADM_ADDR_STATIC:
		newaddr->ipadm_af = AF_UNSPEC;
		newaddr->ipadm_static_prefixlen = 0;
		break;

	default:
		status = IPADM_INVALID_ARG;
		goto fail;
	}
	newaddr->ipadm_atype = type;
	*ipaddr = newaddr;
	return (IPADM_SUCCESS);
fail:
	free(newaddr);
	return (status);
}

/*
 * Returns `aobjname' from the address object in `ipaddr'.
 */
ipadm_status_t
ipadm_get_aobjname(const ipadm_addrobj_t ipaddr, char *aobjname, size_t len)
{
	if (ipaddr == NULL || aobjname == NULL)
		return (IPADM_INVALID_ARG);
	if (strlcpy(aobjname, ipaddr->ipadm_aobjname, len) >= len)
		return (IPADM_INVALID_ARG);

	return (IPADM_SUCCESS);
}

/*
 * Frees the address object in `ipaddr'.
 */
void
ipadm_destroy_addrobj(ipadm_addrobj_t ipaddr)
{
	free(ipaddr);
}

/*
 * Retrieves the logical interface name from `ipaddr' and stores the
 * string in `lifname'.
 */
void
i_ipadm_addrobj2lifname(ipadm_addrobj_t ipaddr, char *lifname, int lifnamesize)
{
	if (ipaddr->ipadm_lifnum != 0) {
		(void) snprintf(lifname, lifnamesize, "%s:%d",
		    ipaddr->ipadm_ifname, ipaddr->ipadm_lifnum);
	} else {
		(void) snprintf(lifname, lifnamesize, "%s",
		    ipaddr->ipadm_ifname);
	}
}

/*
 * Checks if a non-zero static address is present on the 0th logical interface
 * of the given IPv4 or IPv6 physical interface. For an IPv4 interface, it
 * also checks if the interface is under DHCP control. If the condition is true,
 * the output argument `exists' will be set to B_TRUE. Otherwise, `exists'
 * is set to B_FALSE.
 *
 * Note that *exists will not be initialized if an error is encountered.
 */
static ipadm_status_t
i_ipadm_addr_exists_on_if(ipadm_handle_t iph, const char *ifname,
    sa_family_t af, boolean_t *exists)
{
	struct lifreq	lifr;
	int		sock;

	/* For IPH_LEGACY, a new logical interface will never be added. */
	if (iph->iph_flags & IPH_LEGACY) {
		*exists = B_FALSE;
		return (IPADM_SUCCESS);
	}
	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (af == AF_INET) {
		sock = iph->iph_sock;
		if (ioctl(sock, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0)
			return (ipadm_errno2status(errno));
		if (lifr.lifr_flags & IFF_DHCPRUNNING) {
			*exists = B_TRUE;
			return (IPADM_SUCCESS);
		}
	} else {
		sock = iph->iph_sock6;
	}
	if (ioctl(sock, SIOCGLIFADDR, (caddr_t)&lifr) < 0)
		return (ipadm_errno2status(errno));
	*exists = !sockaddrunspec((struct sockaddr *)&lifr.lifr_addr);

	return (IPADM_SUCCESS);
}

/*
 * Adds a new logical interface in the kernel for interface
 * `addr->ipadm_ifname', if there is a non-zero address on the 0th
 * logical interface or if the 0th logical interface is under DHCP
 * control. On success, it sets the lifnum in the address object `addr'.
 */
ipadm_status_t
i_ipadm_do_addif(ipadm_handle_t iph, ipadm_addrobj_t addr)
{
	ipadm_status_t	status;
	boolean_t	addif;
	struct lifreq	lifr;
	int		sock;

	addr->ipadm_lifnum = 0;
	status = i_ipadm_addr_exists_on_if(iph, addr->ipadm_ifname,
	    addr->ipadm_af, &addif);
	if (status != IPADM_SUCCESS)
		return (status);
	if (addif) {
		/*
		 * If there is an address on 0th logical interface,
		 * add a new logical interface.
		 */
		bzero(&lifr, sizeof (lifr));
		(void) strlcpy(lifr.lifr_name, addr->ipadm_ifname,
		    sizeof (lifr.lifr_name));
		sock = (addr->ipadm_af == AF_INET ? iph->iph_sock :
		    iph->iph_sock6);
		if (ioctl(sock, SIOCLIFADDIF, (caddr_t)&lifr) < 0)
			return (ipadm_errno2status(errno));
		addr->ipadm_lifnum = i_ipadm_get_lnum(lifr.lifr_name);
	}
	return (IPADM_SUCCESS);
}

/*
 * Reads all the address lines from the persistent DB into the nvlist `onvl',
 * when both `ifname' and `aobjname' are NULL. If an `ifname' is provided,
 * it returns all the addresses for the given interface `ifname'.
 * If an `aobjname' is specified, then the address line corresponding to
 * that name will be returned.
 */
static ipadm_status_t
i_ipadm_get_db_addr(ipadm_handle_t iph, const char *ifname,
    const char *aobjname, nvlist_t **onvl)
{
	ipmgmt_getaddr_arg_t	garg;
	ipmgmt_get_rval_t	*rvalp;
	int			err;
	size_t			nvlsize;
	char			*nvlbuf;

	/* Populate the door_call argument structure */
	bzero(&garg, sizeof (garg));
	garg.ia_cmd = IPMGMT_CMD_GETADDR;
	if (aobjname != NULL)
		(void) strlcpy(garg.ia_aobjname, aobjname,
		    sizeof (garg.ia_aobjname));
	if (ifname != NULL)
		(void) strlcpy(garg.ia_ifname, ifname, sizeof (garg.ia_ifname));

	rvalp = malloc(sizeof (ipmgmt_get_rval_t));
	err = ipadm_door_call(iph, &garg, sizeof (garg), (void **)&rvalp,
	    sizeof (*rvalp), B_TRUE);
	if (err == 0) {
		nvlsize = rvalp->ir_nvlsize;
		nvlbuf = (char *)rvalp + sizeof (ipmgmt_get_rval_t);
		err = nvlist_unpack(nvlbuf, nvlsize, onvl, NV_ENCODE_NATIVE);
	}
	free(rvalp);
	return (ipadm_errno2status(err));
}

/*
 * Adds the IP address contained in the 'ipaddr' argument to the physical
 * interface represented by 'ifname' after doing the required validation.
 * If the interface does not exist, it is created before the address is
 * added.
 *
 * If IPH_LEGACY is set in iph_flags, flags has to be IPADM_OPT_ACTIVE
 * and a default addrobj name will be generated. Input `addr->ipadm_aobjname',
 * if provided, will be ignored and replaced with the newly generated name.
 * The interface name provided has to be a logical interface name that
 * already exists. No new logical interface will be added in this function.
 *
 * If IPADM_OPT_V46 is passed in the flags, then both IPv4 and IPv6 interfaces
 * are plumbed (if they haven't been already).  Otherwise, just the interface
 * specified in `addr' is plumbed.
 */
ipadm_status_t
ipadm_create_addr(ipadm_handle_t iph, ipadm_addrobj_t addr, uint32_t flags)
{
	ipadm_status_t		status;
	sa_family_t		af;
	sa_family_t		daf;
	sa_family_t		other_af;
	boolean_t		created_af = B_FALSE;
	boolean_t		created_other_af = B_FALSE;
	ipadm_addr_type_t	type;
	char			*ifname = addr->ipadm_ifname;
	boolean_t		legacy = (iph->iph_flags & IPH_LEGACY);
	boolean_t		aobjfound;
	boolean_t		is_6to4;
	struct lifreq		lifr;
	uint64_t		ifflags;
	boolean_t		is_boot = (iph->iph_flags & IPH_IPMGMTD);

	/* check for solaris.network.interface.config authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);

	/* Validate the addrobj. This also fills in addr->ipadm_ifname. */
	status = i_ipadm_validate_create_addr(iph, addr, flags);
	if (status != IPADM_SUCCESS)
		return (status);

	/*
	 * For Legacy case, check if an addrobj already exists for the
	 * given logical interface name. If one does not exist,
	 * a default name will be generated and added to the daemon's
	 * aobjmap.
	 */
	if (legacy) {
		struct ipadm_addrobj_s	ipaddr;

		ipaddr = *addr;
		status = i_ipadm_get_lif2addrobj(iph, &ipaddr);
		if (status == IPADM_SUCCESS) {
			aobjfound = B_TRUE;
			/*
			 * With IPH_LEGACY, modifying an address that is not
			 * a static address will return with an error.
			 */
			if (ipaddr.ipadm_atype != IPADM_ADDR_STATIC)
				return (IPADM_NOTSUP);
			/*
			 * we found the addrobj in daemon, copy over the
			 * aobjname to `addr'.
			 */
			(void) strlcpy(addr->ipadm_aobjname,
			    ipaddr.ipadm_aobjname, IPADM_AOBJSIZ);
		} else if (status == IPADM_NOTFOUND) {
			aobjfound = B_FALSE;
		} else {
			return (status);
		}
	}

	af = addr->ipadm_af;
	/*
	 * Create a placeholder for this address object in the daemon.
	 * Skip this step if we are booting a zone (and therefore being called
	 * from ipmgmtd itself), and, for IPH_LEGACY case if the
	 * addrobj already exists.
	 *
	 * Note that the placeholder is not needed in the NGZ boot case,
	 * when zoneadmd has itself applied the "allowed-ips" property to clamp
	 * down any interface configuration, so the namespace for the interface
	 * is fully controlled by the GZ.
	 */
	if (!is_boot && (!legacy || !aobjfound)) {
		status = i_ipadm_lookupadd_addrobj(iph, addr);
		if (status != IPADM_SUCCESS)
			return (status);
	}

	is_6to4 = i_ipadm_is_6to4(iph, ifname);
	/* Plumb the IP interfaces if necessary */
	status = i_ipadm_create_if(iph, ifname, af, flags);
	if (status != IPADM_SUCCESS && status != IPADM_IF_EXISTS) {
		(void) i_ipadm_delete_addrobj(iph, addr, IPADM_OPT_ACTIVE);
		return (status);
	}
	if (status == IPADM_SUCCESS)
		created_af = B_TRUE;
	if (!is_6to4 && !legacy && (flags & IPADM_OPT_V46)) {
		other_af = (af == AF_INET ? AF_INET6 : AF_INET);
		status = i_ipadm_create_if(iph, ifname, other_af, flags);
		if (status != IPADM_SUCCESS && status != IPADM_IF_EXISTS) {
			(void) i_ipadm_delete_if(iph, ifname, af, flags);
			return (status);
		}
		if (status == IPADM_SUCCESS)
			created_other_af = B_TRUE;
	}

	/*
	 * Some input validation based on the interface flags:
	 * 1. in non-global zones, make sure that we are not persistently
	 *    creating addresses on interfaces that are acquiring
	 *    address from the global zone.
	 * 2. Validate static addresses for IFF_POINTOPOINT interfaces.
	 */
	if (addr->ipadm_atype == IPADM_ADDR_STATIC) {
		status = i_ipadm_get_flags(iph, ifname, af, &ifflags);
		if (status != IPADM_SUCCESS)
			goto fail;

		if (iph->iph_zoneid != GLOBAL_ZONEID &&
		    (ifflags & IFF_L3PROTECT) && (flags & IPADM_OPT_PERSIST)) {
			status = IPADM_GZ_PERM;
			goto fail;
		}
		daf = addr->ipadm_static_dst_addr.ss_family;
		if (ifflags & IFF_POINTOPOINT) {
			if (is_6to4) {
				if (af != AF_INET6 || daf != AF_UNSPEC) {
					status = IPADM_INVALID_ARG;
					goto fail;
				}
			} else {
				if (daf != af) {
					status = IPADM_INVALID_ARG;
					goto fail;
				}
				/* Check for a valid dst address. */
				if (!legacy && sockaddrunspec(
				    (struct sockaddr *)
				    &addr->ipadm_static_dst_addr)) {
					status = IPADM_BAD_ADDR;
					goto fail;
				}
			}
		} else {
			/*
			 * Disallow setting of dstaddr when the link is not
			 * a point-to-point link.
			 */
			if (daf != AF_UNSPEC)
				return (IPADM_INVALID_ARG);
		}
	}

	/*
	 * For 6to4 interfaces, kernel configures a default link-local
	 * address. We need to replace it, if the caller has provided
	 * an address that is different from the default link-local.
	 */
	if (status == IPADM_SUCCESS && is_6to4) {
		bzero(&lifr, sizeof (lifr));
		(void) strlcpy(lifr.lifr_name, addr->ipadm_ifname,
		    sizeof (lifr.lifr_name));
		if (ioctl(iph->iph_sock6, SIOCGLIFADDR, &lifr) < 0) {
			status = ipadm_errno2status(errno);
			goto fail;
		}
		if (sockaddrcmp(&lifr.lifr_addr, &addr->ipadm_static_addr))
			return (IPADM_SUCCESS);
	}

	/* Create the address. */
	type = addr->ipadm_atype;
	switch (type) {
	case IPADM_ADDR_STATIC:
		status = i_ipadm_create_addr(iph, addr, flags);
		break;
	case IPADM_ADDR_DHCP:
		status = i_ipadm_create_dhcp(iph, addr, flags);
		break;
	case IPADM_ADDR_IPV6_ADDRCONF:
		status = i_ipadm_create_ipv6addrs(iph, addr, flags);
		break;
	default:
		status = IPADM_INVALID_ARG;
		break;
	}

	/*
	 * If address was not created successfully, unplumb the interface
	 * if it was plumbed implicitly in this function and remove the
	 * addrobj created by the ipmgmtd daemon as a placeholder.
	 * If IPH_LEGACY is set, then remove the addrobj only if it was
	 * created in this function.
	 */
fail:
	if (status != IPADM_DHCP_IPC_TIMEOUT &&
	    status != IPADM_SUCCESS) {
		if (!legacy) {
			if (created_af || created_other_af) {
				if (created_af) {
					(void) i_ipadm_delete_if(iph, ifname,
					    af, flags);
				}
				if (created_other_af) {
					(void) i_ipadm_delete_if(iph, ifname,
					    other_af, flags);
				}
			} else {
				(void) i_ipadm_delete_addrobj(iph, addr, flags);
			}
		} else if (!aobjfound) {
			(void) i_ipadm_delete_addrobj(iph, addr, flags);
		}
	}

	return (status);
}

/*
 * Creates the static address in `ipaddr' in kernel. After successfully
 * creating it, it updates the ipmgmtd daemon's aobjmap with the logical
 * interface information.
 */
static ipadm_status_t
i_ipadm_create_addr(ipadm_handle_t iph, ipadm_addrobj_t ipaddr, uint32_t flags)
{
	struct lifreq			lifr;
	ipadm_status_t			status = IPADM_SUCCESS;
	int				sock;
	struct sockaddr_storage		m, *mask = &m;
	const struct sockaddr_storage	*addr = &ipaddr->ipadm_static_addr;
	const struct sockaddr_storage	*daddr = &ipaddr->ipadm_static_dst_addr;
	sa_family_t			af;
	boolean_t			legacy = (iph->iph_flags & IPH_LEGACY);
	struct ipadm_addrobj_s		legacy_addr;
	boolean_t			default_prefixlen = B_FALSE;
	boolean_t			is_boot;

	is_boot = ((iph->iph_flags & IPH_IPMGMTD) != 0);
	af = ipaddr->ipadm_af;
	sock = (af == AF_INET ? iph->iph_sock : iph->iph_sock6);

	/* If prefixlen was not provided, get default prefixlen */
	if (ipaddr->ipadm_static_prefixlen == 0) {
		/* prefixlen was not provided, get default prefixlen */
		status = i_ipadm_get_default_prefixlen(
		    &ipaddr->ipadm_static_addr,
		    &ipaddr->ipadm_static_prefixlen);
		if (status != IPADM_SUCCESS)
			return (status);
		default_prefixlen = B_TRUE;
	}
	(void) plen2mask(ipaddr->ipadm_static_prefixlen, af,
	    (struct sockaddr *)mask);

	/*
	 * Create a new logical interface if needed; otherwise, just
	 * use the 0th logical interface.
	 */
retry:
	if (!(iph->iph_flags & IPH_LEGACY)) {
		status = i_ipadm_do_addif(iph, ipaddr);
		if (status != IPADM_SUCCESS)
			return (status);
		/*
		 * We don't have to set the lifnum for IPH_INIT case, because
		 * there is no placeholder created for the address object in
		 * this case. For IPH_LEGACY, we don't do this because the
		 * lifnum is given by the caller and it will be set in the
		 * end while we call the i_ipadm_addr_persist().
		 */
		if (!(iph->iph_flags & IPH_INIT)) {
			status = i_ipadm_setlifnum_addrobj(iph, ipaddr);
			if (status == IPADM_ADDROBJ_EXISTS)
				goto retry;
			if (status != IPADM_SUCCESS)
				return (status);
		}
	}
	i_ipadm_addrobj2lifname(ipaddr, lifr.lifr_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr = *mask;
	if (ioctl(sock, SIOCSLIFNETMASK, (caddr_t)&lifr) < 0) {
		status = ipadm_errno2status(errno);
		goto ret;
	}
	lifr.lifr_addr = *addr;
	if (ioctl(sock, SIOCSLIFADDR, (caddr_t)&lifr) < 0) {
		status = ipadm_errno2status(errno);
		goto ret;
	}
	/* Set the destination address, if one is given. */
	if (daddr->ss_family != AF_UNSPEC) {
		lifr.lifr_addr = *daddr;
		if (ioctl(sock, SIOCSLIFDSTADDR, (caddr_t)&lifr) < 0) {
			status = ipadm_errno2status(errno);
			goto ret;
		}
	}

	if (flags & IPADM_OPT_UP) {
		status = i_ipadm_set_flags(iph, lifr.lifr_name, af, IFF_UP, 0);

		/*
		 * IPADM_DAD_FOUND is a soft-error for create-addr.
		 * No need to tear down the address.
		 */
		if (status == IPADM_DAD_FOUND)
			status = IPADM_SUCCESS;
	}

	if (status == IPADM_SUCCESS && !is_boot) {
		/*
		 * For IPH_LEGACY, we might be modifying the address on
		 * an address object that already exists e.g. by doing
		 * "ifconfig bge0:1 <addr>; ifconfig bge0:1 <newaddr>"
		 * So, we need to store the object only if it does not
		 * already exist in ipmgmtd.
		 */
		if (legacy) {
			bzero(&legacy_addr, sizeof (legacy_addr));
			(void) strlcpy(legacy_addr.ipadm_aobjname,
			    ipaddr->ipadm_aobjname,
			    sizeof (legacy_addr.ipadm_aobjname));
			status = i_ipadm_get_addrobj(iph, &legacy_addr);
			if (status == IPADM_SUCCESS &&
			    legacy_addr.ipadm_lifnum >= 0) {
				return (status);
			}
		}
		status = i_ipadm_addr_persist(iph, ipaddr, default_prefixlen,
		    flags, NULL);
	}
ret:
	if (status != IPADM_SUCCESS && !legacy)
		(void) i_ipadm_delete_addr(iph, ipaddr);
	return (status);
}

/*
 * Removes the address object identified by `aobjname' from both active and
 * persistent configuration. The address object will be removed from only
 * active configuration if IPH_LEGACY is set in `iph->iph_flags'.
 *
 * If the address type is IPADM_ADDR_STATIC or IPADM_ADDR_DHCP, the address
 * in the address object will be removed from the physical interface.
 * If the address type is IPADM_ADDR_DHCP, the flag IPADM_OPT_RELEASE specifies
 * whether the lease should be released. If IPADM_OPT_RELEASE is not
 * specified, the lease will be dropped. This option is not supported
 * for other address types.
 *
 * If the address type is IPADM_ADDR_IPV6_ADDRCONF, the link-local address and
 * all the autoconfigured addresses will be removed.
 * Finally, the address object is also removed from ipmgmtd's aobjmap and from
 * the persistent DB.
 */
ipadm_status_t
ipadm_delete_addr(ipadm_handle_t iph, const char *aobjname, uint32_t flags)
{
	ipadm_status_t		status;
	struct ipadm_addrobj_s	ipaddr;
	boolean_t		release = ((flags & IPADM_OPT_RELEASE) != 0);

	/* check for solaris.network.interface.config authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);

	/* validate input */
	if (flags == 0 || ((flags & IPADM_OPT_PERSIST) &&
	    !(flags & IPADM_OPT_ACTIVE)) ||
	    (flags & ~(IPADM_COMMON_OPT_MASK|IPADM_OPT_RELEASE))) {
		return (IPADM_INVALID_ARG);
	}
	bzero(&ipaddr, sizeof (ipaddr));
	if (aobjname == NULL || strlcpy(ipaddr.ipadm_aobjname, aobjname,
	    IPADM_AOBJSIZ) >= IPADM_AOBJSIZ) {
		return (IPADM_INVALID_ARG);
	}

	/* Retrieve the address object information from ipmgmtd. */
	status = i_ipadm_get_addrobj(iph, &ipaddr);
	if (status != IPADM_SUCCESS)
		return (status);

	if (release && ipaddr.ipadm_atype != IPADM_ADDR_DHCP)
		return (IPADM_NOTSUP);
	/*
	 * If requested to delete just from active config but the address
	 * is not in active config, return error.
	 */
	if (!(ipaddr.ipadm_flags & IPMGMT_ACTIVE) &&
	    (flags & IPADM_OPT_ACTIVE) && !(flags & IPADM_OPT_PERSIST)) {
		return (IPADM_NOTFOUND);
	}

	/*
	 * If address is present in active config, remove it from
	 * kernel.
	 */
	if (ipaddr.ipadm_flags & IPMGMT_ACTIVE) {
		switch (ipaddr.ipadm_atype) {
		case IPADM_ADDR_STATIC:
			status = i_ipadm_delete_addr(iph, &ipaddr);
			break;
		case IPADM_ADDR_DHCP:
			status = i_ipadm_delete_dhcp(iph, &ipaddr, release);
			break;
		case IPADM_ADDR_IPV6_ADDRCONF:
			status = i_ipadm_delete_ipv6addrs(iph, &ipaddr);
			break;
		default:
			/*
			 * This is the case of address object name residing in
			 * daemon's aobjmap (added by ADDROBJ_LOOKUPADD). Fall
			 * through and delete that address object.
			 */
			break;
		}

		/*
		 * If the address was previously deleted from the active
		 * config, we will get a IPADM_ENXIO from kernel.
		 * We will still proceed and purge the address information
		 * in the DB.
		 */
		if (status == IPADM_ENXIO)
			status = IPADM_SUCCESS;
		else if (status != IPADM_SUCCESS)
			return (status);
	}

	if (!(ipaddr.ipadm_flags & IPMGMT_PERSIST) &&
	    (flags & IPADM_OPT_PERSIST)) {
		flags &= ~IPADM_OPT_PERSIST;
	}
	status = i_ipadm_delete_addrobj(iph, &ipaddr, flags);
	if (status == IPADM_NOTFOUND)
		return (status);
	return (IPADM_SUCCESS);
}

/*
 * Starts the dhcpagent and sends it the message DHCP_START to start
 * configuring a dhcp address on the given interface in `addr'.
 * After making the dhcpagent request, it also updates the
 * address object information in ipmgmtd's aobjmap and creates an
 * entry in persistent DB if IPADM_OPT_PERSIST is set in `flags'.
 */
static ipadm_status_t
i_ipadm_create_dhcp(ipadm_handle_t iph, ipadm_addrobj_t addr, uint32_t flags)
{
	ipadm_status_t	status;
	ipadm_status_t	dh_status;

	if (dhcp_start_agent(DHCP_IPC_MAX_WAIT) == -1)
		return (IPADM_DHCP_START_ERROR);
	/*
	 * Create a new logical interface if needed; otherwise, just
	 * use the 0th logical interface.
	 */
retry:
	status = i_ipadm_do_addif(iph, addr);
	if (status != IPADM_SUCCESS)
		return (status);
	/*
	 * We don't have to set the lifnum for IPH_INIT case, because
	 * there is no placeholder created for the address object in this
	 * case.
	 */
	if (!(iph->iph_flags & IPH_INIT)) {
		status = i_ipadm_setlifnum_addrobj(iph, addr);
		if (status == IPADM_ADDROBJ_EXISTS)
			goto retry;
		if (status != IPADM_SUCCESS)
			return (status);
	}
	/* Send DHCP_START to the dhcpagent. */
	status = i_ipadm_op_dhcp(addr, DHCP_START, NULL);
	/*
	 * We do not undo the create-addr operation for IPADM_DHCP_IPC_TIMEOUT
	 * since it is only a soft error to indicate the caller that the lease
	 * might be required after the function returns.
	 */
	if (status != IPADM_SUCCESS && status != IPADM_DHCP_IPC_TIMEOUT)
		goto fail;
	dh_status = status;

	/* Persist the address object information in ipmgmtd. */
	status = i_ipadm_addr_persist(iph, addr, B_FALSE, flags, NULL);
	if (status != IPADM_SUCCESS)
		goto fail;

	return (dh_status);
fail:
	/* In case of error, delete the dhcp address */
	(void) i_ipadm_delete_dhcp(iph, addr, B_TRUE);
	return (status);
}

/*
 * Releases/drops the dhcp lease on the logical interface in the address
 * object `addr'. If `release' is set to B_FALSE, the lease will be dropped.
 */
static ipadm_status_t
i_ipadm_delete_dhcp(ipadm_handle_t iph, ipadm_addrobj_t addr, boolean_t release)
{
	ipadm_status_t	status;
	int		dherr;

	/* Send DHCP_RELEASE or DHCP_DROP to the dhcpagent */
	if (release) {
		status = i_ipadm_op_dhcp(addr, DHCP_RELEASE, &dherr);
		/*
		 * If no lease was obtained on the object, we should
		 * drop the dhcp control on the interface.
		 */
		if (status != IPADM_SUCCESS && dherr == DHCP_IPC_E_OUTSTATE)
			status = i_ipadm_op_dhcp(addr, DHCP_DROP, NULL);
	} else {
		status = i_ipadm_op_dhcp(addr, DHCP_DROP, NULL);
	}
	if (status != IPADM_SUCCESS)
		return (status);

	/* Delete the logical interface */
	if (addr->ipadm_lifnum != 0) {
		struct lifreq lifr;

		bzero(&lifr, sizeof (lifr));
		i_ipadm_addrobj2lifname(addr, lifr.lifr_name,
		    sizeof (lifr.lifr_name));
		if (ioctl(iph->iph_sock, SIOCLIFREMOVEIF, (caddr_t)&lifr) < 0)
			return (ipadm_errno2status(errno));
	}

	return (IPADM_SUCCESS);
}

/*
 * Communicates with the dhcpagent to send a dhcp message of type `type'.
 * It returns the dhcp error in `dhcperror' if a non-null pointer is provided
 * in `dhcperror'.
 */
static ipadm_status_t
i_ipadm_op_dhcp(ipadm_addrobj_t addr, dhcp_ipc_type_t type, int *dhcperror)
{
	dhcp_ipc_request_t	*request;
	dhcp_ipc_reply_t	*reply	= NULL;
	dhcp_symbol_t		*entry = NULL;
	dhcp_data_type_t	dtype = DHCP_TYPE_NONE;
	void			*d4o = NULL;
	uint16_t		d4olen = 0;
	char			ifname[LIFNAMSIZ];
	int			error;
	int			dhcp_timeout;

	/* Construct a message to the dhcpagent. */
	bzero(&ifname, sizeof (ifname));
	i_ipadm_addrobj2lifname(addr, ifname, sizeof (ifname));
	if (addr->ipadm_primary)
		type |= DHCP_PRIMARY;

	/* Set up a CD_HOSTNAME option, if applicable, to send through IPC */
	switch (DHCP_IPC_CMD(type)) {
	case DHCP_START:
	case DHCP_EXTEND:
		if (addr->ipadm_af == AF_INET && addr->ipadm_reqhost != NULL &&
		    *addr->ipadm_reqhost != '\0') {
			entry = inittab_getbycode(ITAB_CAT_STANDARD,
			    ITAB_CONS_INFO, CD_HOSTNAME);
			if (entry == NULL) {
				return (IPADM_FAILURE);
			} else {
				d4o = inittab_encode(entry, addr->ipadm_reqhost,
				    &d4olen, B_FALSE);
				free(entry);
				entry = NULL;
				if (d4o == NULL)
					return (IPADM_FAILURE);
				dtype = DHCP_TYPE_OPTION;
			}
		}
		break;
	default:
		break;
	}

	request = dhcp_ipc_alloc_request(type, ifname, d4o, d4olen, dtype);
	if (request == NULL) {
		free(d4o);
		return (IPADM_NO_MEMORY);
	}

	if (addr->ipadm_wait == IPADM_DHCP_WAIT_FOREVER)
		dhcp_timeout = DHCP_IPC_WAIT_FOREVER;
	else if (addr->ipadm_wait == IPADM_DHCP_WAIT_DEFAULT)
		dhcp_timeout = DHCP_IPC_WAIT_DEFAULT;
	else
		dhcp_timeout = addr->ipadm_wait;
	/* Send the message to dhcpagent. */
	error = dhcp_ipc_make_request(request, &reply, dhcp_timeout);
	free(request);
	free(d4o);
	if (error == 0) {
		error = reply->return_code;
		free(reply);
	}
	if (error != 0) {
		if (dhcperror != NULL)
			*dhcperror = error;
		if (error != DHCP_IPC_E_TIMEOUT)
			return (IPADM_DHCP_IPC_ERROR);
		else if (dhcp_timeout != 0)
			return (IPADM_DHCP_IPC_TIMEOUT);
	}

	return (IPADM_SUCCESS);
}

/*
 * Communicates with the dhcpagent to send a dhcp message of type
 * DHCP_STATUS, and copy on success into the `status' instance owned by the
 * caller. It returns any dhcp error in `dhcperror' if a non-null pointer
 * is provided.
 */
static ipadm_status_t
i_ipadm_dhcp_status(ipadm_addrobj_t addr, dhcp_status_t *status,
    int *dhcperror)
{
	dhcp_ipc_type_t		type = DHCP_STATUS;
	dhcp_ipc_request_t	*request;
	dhcp_ipc_reply_t	*reply;
	dhcp_status_t		*private_status;
	size_t			reply_size;
	int			error;

	if (addr->ipadm_af == AF_INET6)
		type |= DHCP_V6;

	request = dhcp_ipc_alloc_request(type, addr->ipadm_ifname, NULL, 0,
	    DHCP_TYPE_NONE);
	if (request == NULL)
		return (IPADM_NO_MEMORY);

	error = dhcp_ipc_make_request(request, &reply, DHCP_IPC_WAIT_DEFAULT);
	free(request);
	if (error != 0) {
		if (dhcperror != NULL)
			*dhcperror = error;
		return (error != DHCP_IPC_E_TIMEOUT ? IPADM_DHCP_IPC_ERROR
		    : IPADM_DHCP_IPC_TIMEOUT);
	}

	error = reply->return_code;
	if (error == DHCP_IPC_E_UNKIF) {
		free(reply);
		bzero(status, sizeof (dhcp_status_t));
		return (IPADM_NOTFOUND);
	}

	private_status = dhcp_ipc_get_data(reply, &reply_size, NULL);
	if (reply_size < DHCP_STATUS_VER1_SIZE) {
		free(reply);
		return (IPADM_DHCP_IPC_ERROR);
	}

	/*
	 * Copy the status out of the memory allocated by this function into
	 * memory owned by the caller.
	 */
	*status = *private_status;
	free(reply);
	return (IPADM_SUCCESS);
}

/*
 * Returns the IP addresses of the specified interface in both the
 * active and the persistent configuration. If no
 * interface is specified, it returns all non-zero IP addresses
 * configured on all interfaces in active and persistent
 * configurations.
 * `addrinfo' will contain addresses that are
 * (1) in both active and persistent configuration (created persistently)
 * (2) only in active configuration (created temporarily)
 * (3) only in persistent configuration (disabled addresses)
 *
 * Address list that is returned by this function must be freed
 * using the ipadm_freeaddr_info() function.
 */
ipadm_status_t
ipadm_addr_info(ipadm_handle_t iph, const char *ifname,
    ipadm_addr_info_t **addrinfo, uint32_t flags, int64_t lifc_flags)
{
	ifspec_t	ifsp;

	if (addrinfo == NULL || iph == NULL)
		return (IPADM_INVALID_ARG);
	if (ifname != NULL &&
	    (!ifparse_ifspec(ifname, &ifsp) || ifsp.ifsp_lunvalid)) {
		return (IPADM_INVALID_ARG);
	}
	return (i_ipadm_get_all_addr_info(iph, ifname, addrinfo,
	    flags, lifc_flags));
}

/*
 * Frees the structure allocated by ipadm_addr_info().
 */
void
ipadm_free_addr_info(ipadm_addr_info_t *ainfo)
{
	freeifaddrs((struct ifaddrs *)ainfo);
}

/*
 * Makes a door call to ipmgmtd to update its `aobjmap' with the address
 * object in `ipaddr'. This door call also can update the persistent DB to
 * remember address object to be recreated on next reboot or on an
 * ipadm_enable_addr()/ipadm_enable_if() call.
 */
ipadm_status_t
i_ipadm_addr_persist(ipadm_handle_t iph, const ipadm_addrobj_t ipaddr,
    boolean_t default_prefixlen, uint32_t flags, const char *propname)
{
	char			*aname = ipaddr->ipadm_aobjname;
	nvlist_t		*nvl;
	int			err = 0;
	ipadm_status_t		status;
	uint_t			pflags = 0;

	/*
	 * Construct the nvl to send to the door.
	 */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
		return (IPADM_NO_MEMORY);
	if ((err = nvlist_add_string(nvl, IPADM_NVP_IFNAME,
	    ipaddr->ipadm_ifname)) != 0 ||
	    (err = nvlist_add_string(nvl, IPADM_NVP_AOBJNAME, aname)) != 0 ||
	    (err = nvlist_add_int32(nvl, IPADM_NVP_LIFNUM,
	    ipaddr->ipadm_lifnum)) != 0) {
		status = ipadm_errno2status(err);
		goto ret;
	}
	switch (ipaddr->ipadm_atype) {
	case IPADM_ADDR_STATIC:
		status = i_ipadm_add_ipaddr2nvl(nvl, ipaddr);
		if (status != IPADM_SUCCESS)
			goto ret;
		if (flags & IPADM_OPT_UP)
			err = nvlist_add_string(nvl, "up", "yes");
		else
			err = nvlist_add_string(nvl, "up", "no");
		status = ipadm_errno2status(err);
		break;
	case IPADM_ADDR_DHCP:
		status = i_ipadm_add_dhcp2nvl(nvl, ipaddr->ipadm_primary,
		    ipaddr->ipadm_wait);
		if (status != IPADM_SUCCESS)
			goto ret;

		/*
		 * For purposes of updating the ipmgmtd cached representation of
		 * reqhost (ipmgmt_am_reqhost), include a value here in `nvl',
		 * but the value is actually fully persisted as a separate
		 * i_ipadm_persist_propval below.
		 */
		err = nvlist_add_string(nvl, IPADM_NVP_REQHOST,
		    ipaddr->ipadm_reqhost);
		status = ipadm_errno2status(err);
		break;
	case IPADM_ADDR_IPV6_ADDRCONF:
		status = i_ipadm_add_intfid2nvl(nvl, ipaddr);
		break;
	}
	if (status != IPADM_SUCCESS)
		goto ret;

	if (iph->iph_flags & IPH_INIT) {
		/*
		 * IPMGMT_INIT tells the ipmgmtd to set both IPMGMT_ACTIVE and
		 * IPMGMT_PERSIST on the address object in its `aobjmap'.
		 * For the callers ipadm_enable_if() and ipadm_enable_addr(),
		 * IPADM_OPT_PERSIST is not set in their flags. They send
		 * IPH_INIT in iph_flags, so that the address object will be
		 * set as both IPMGMT_ACTIVE and IPMGMT_PERSIST.
		 */
		pflags |= IPMGMT_INIT;
	} else {
		if (flags & IPADM_OPT_ACTIVE)
			pflags |= IPMGMT_ACTIVE;
		if (flags & IPADM_OPT_PERSIST)
			pflags |= IPMGMT_PERSIST;
		if (flags & IPADM_OPT_SET_PROPS)
			pflags |= IPMGMT_PROPS_ONLY;
	}
	status = i_ipadm_addr_persist_nvl(iph, nvl, pflags);

	if (flags & IPADM_OPT_SET_PROPS) {
		/*
		 * Set PERSIST per IPADM_OPT_PROPS_PERSIST, and then un-set the
		 * SET_PROPS bits.
		 */
		flags |= IPADM_OPT_ACTIVE;
		if (flags & IPADM_OPT_PERSIST_PROPS)
			flags |= IPADM_OPT_PERSIST;
		else
			flags &= ~IPADM_OPT_PERSIST;
		flags &= ~(IPADM_OPT_SET_PROPS | IPADM_OPT_PERSIST_PROPS);
	}

	if (status == IPADM_SUCCESS && (flags & IPADM_OPT_PERSIST)) {
		char		pbuf[MAXPROPVALLEN], *pval = NULL;
		ipadm_prop_desc_t	*pdp = NULL;

		/*
		 * addprop properties are stored on separate lines in the DB and
		 * not along with the address itself. Call the function that
		 * persists address properties.
		 */

		switch (ipaddr->ipadm_atype) {
		case IPADM_ADDR_STATIC:
			if (!default_prefixlen && (propname == NULL ||
			    strcmp(propname, IPADM_NVP_PREFIXLEN) == 0)) {
				pdp = i_ipadm_get_addrprop_desc(
				    IPADM_NVP_PREFIXLEN);
				(void) snprintf(pbuf, sizeof (pbuf), "%u",
				    ipaddr->ipadm_static_prefixlen);
				pval = pbuf;
			}
			break;
		case IPADM_ADDR_DHCP:
			if (propname == NULL ||
			    strcmp(propname, IPADM_NVP_REQHOST) == 0) {
				pdp = i_ipadm_get_addrprop_desc(
				    IPADM_NVP_REQHOST);
				pval = ipaddr->ipadm_reqhost;
			}
			break;
		default:
			break;
		}

		if (pval != NULL) {
			assert(pdp != NULL);
			status = i_ipadm_persist_propval(iph, pdp, pval,
			    ipaddr, flags);
		}
	}

ret:
	nvlist_free(nvl);
	return (status);
}

/*
 * Makes the door call to ipmgmtd to store the address object in the
 * nvlist `nvl'.
 */
static ipadm_status_t
i_ipadm_addr_persist_nvl(ipadm_handle_t iph, nvlist_t *nvl, uint32_t flags)
{
	char			*buf = NULL, *nvlbuf = NULL;
	size_t			nvlsize, bufsize;
	ipmgmt_setaddr_arg_t	*sargp;
	int			err;

	err = nvlist_pack(nvl, &nvlbuf, &nvlsize, NV_ENCODE_NATIVE, 0);
	if (err != 0)
		return (ipadm_errno2status(err));
	bufsize = sizeof (*sargp) + nvlsize;
	buf = calloc(1, bufsize);
	sargp = (void *)buf;
	sargp->ia_cmd = IPMGMT_CMD_SETADDR;
	sargp->ia_flags = flags;
	sargp->ia_nvlsize = nvlsize;
	(void) bcopy(nvlbuf, buf + sizeof (*sargp), nvlsize);
	err = ipadm_door_call(iph, buf, bufsize, NULL, 0, B_FALSE);
	free(buf);
	free(nvlbuf);
	return (ipadm_errno2status(err));
}

/*
 * Makes a door call to ipmgmtd to remove the address object in `ipaddr'
 * from its `aobjmap'. This door call also removes the address object and all
 * its properties from the persistent DB if IPADM_OPT_PERSIST is set in
 * `flags', so that the object will not be recreated on next reboot or on an
 * ipadm_enable_addr()/ipadm_enable_if() call.
 */
ipadm_status_t
i_ipadm_delete_addrobj(ipadm_handle_t iph, const ipadm_addrobj_t ipaddr,
    uint32_t flags)
{
	ipmgmt_addr_arg_t	arg;
	int			err;

	arg.ia_cmd = IPMGMT_CMD_RESETADDR;
	arg.ia_flags = 0;
	if (flags & IPADM_OPT_ACTIVE)
		arg.ia_flags |= IPMGMT_ACTIVE;
	if (flags & IPADM_OPT_PERSIST)
		arg.ia_flags |= IPMGMT_PERSIST;
	(void) strlcpy(arg.ia_aobjname, ipaddr->ipadm_aobjname,
	    sizeof (arg.ia_aobjname));
	arg.ia_lnum = ipaddr->ipadm_lifnum;
	err = ipadm_door_call(iph, &arg, sizeof (arg), NULL, 0, B_FALSE);
	return (ipadm_errno2status(err));
}

/*
 * Checks if the caller is authorized for the up/down operation.
 * Retrieves the address object corresponding to `aobjname' from ipmgmtd
 * and retrieves the address flags for that object from kernel.
 * The arguments `ipaddr' and `ifflags' must be allocated by the caller.
 */
static ipadm_status_t
i_ipadm_updown_common(ipadm_handle_t iph, const char *aobjname,
    ipadm_addrobj_t ipaddr, uint32_t ipadm_flags, uint64_t *ifflags)
{
	ipadm_status_t	status;
	char		lifname[LIFNAMSIZ];

	/* check for solaris.network.interface.config authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);

	/* validate input */
	if (aobjname == NULL || strlcpy(ipaddr->ipadm_aobjname, aobjname,
	    IPADM_AOBJSIZ) >= IPADM_AOBJSIZ) {
		return (IPADM_INVALID_ARG);
	}

	/* Retrieve the address object information. */
	status = i_ipadm_get_addrobj(iph, ipaddr);
	if (status != IPADM_SUCCESS)
		return (status);

	if (!(ipaddr->ipadm_flags & IPMGMT_ACTIVE))
		return (IPADM_OP_DISABLE_OBJ);
	if ((ipadm_flags & IPADM_OPT_PERSIST) &&
	    !(ipaddr->ipadm_flags & IPMGMT_PERSIST))
		return (IPADM_TEMPORARY_OBJ);
	if (ipaddr->ipadm_atype == IPADM_ADDR_IPV6_ADDRCONF ||
	    (ipaddr->ipadm_atype == IPADM_ADDR_DHCP &&
	    (ipadm_flags & IPADM_OPT_PERSIST)))
		return (IPADM_NOTSUP);

	i_ipadm_addrobj2lifname(ipaddr, lifname, sizeof (lifname));
	return (i_ipadm_get_flags(iph, lifname, ipaddr->ipadm_af, ifflags));
}

/*
 * Marks the address in the address object `aobjname' up. This operation is
 * not supported for an address object of type IPADM_ADDR_IPV6_ADDRCONF.
 * For an address object of type IPADM_ADDR_DHCP, this operation can
 * only be temporary and no updates will be made to the persistent DB.
 */
ipadm_status_t
ipadm_up_addr(ipadm_handle_t iph, const char *aobjname, uint32_t ipadm_flags)
{
	struct ipadm_addrobj_s ipaddr;
	ipadm_status_t	status;
	uint64_t	flags;
	char		lifname[LIFNAMSIZ];

	status = i_ipadm_updown_common(iph, aobjname, &ipaddr, ipadm_flags,
	    &flags);
	if (status != IPADM_SUCCESS)
		return (status);
	if (flags & IFF_UP)
		goto persist;
	/*
	 * If the address is already a duplicate, then refresh-addr
	 * should be used to mark it up.
	 */
	if (flags & IFF_DUPLICATE)
		return (IPADM_DAD_FOUND);

	i_ipadm_addrobj2lifname(&ipaddr, lifname, sizeof (lifname));
	status = i_ipadm_set_flags(iph, lifname, ipaddr.ipadm_af, IFF_UP, 0);
	if (status != IPADM_SUCCESS)
		return (status);

persist:
	/* Update persistent DB. */
	if (ipadm_flags & IPADM_OPT_PERSIST) {
		status = i_ipadm_persist_propval(iph, &up_addrprop,
		    "yes", &ipaddr, 0);
	}

	return (status);
}

/*
 * Marks the address in the address object `aobjname' down. This operation is
 * not supported for an address object of type IPADM_ADDR_IPV6_ADDRCONF.
 * For an address object of type IPADM_ADDR_DHCP, this operation can
 * only be temporary and no updates will be made to the persistent DB.
 */
ipadm_status_t
ipadm_down_addr(ipadm_handle_t iph, const char *aobjname, uint32_t ipadm_flags)
{
	struct ipadm_addrobj_s ipaddr;
	ipadm_status_t	status;
	struct lifreq	lifr;
	uint64_t	flags;

	status = i_ipadm_updown_common(iph, aobjname, &ipaddr, ipadm_flags,
	    &flags);
	if (status != IPADM_SUCCESS)
		return (status);
	i_ipadm_addrobj2lifname(&ipaddr, lifr.lifr_name,
	    sizeof (lifr.lifr_name));
	if (flags & IFF_UP) {
		status = i_ipadm_set_flags(iph, lifr.lifr_name,
		    ipaddr.ipadm_af, 0, IFF_UP);
		if (status != IPADM_SUCCESS)
			return (status);
	} else if (flags & IFF_DUPLICATE) {
		/*
		 * Clear the IFF_DUPLICATE flag.
		 */
		if (ioctl(iph->iph_sock, SIOCGLIFADDR, &lifr) < 0)
			return (ipadm_errno2status(errno));
		if (ioctl(iph->iph_sock, SIOCSLIFADDR, &lifr) < 0)
			return (ipadm_errno2status(errno));
	}

	/* Update persistent DB */
	if (ipadm_flags & IPADM_OPT_PERSIST) {
		status = i_ipadm_persist_propval(iph, &up_addrprop,
		    "no", &ipaddr, 0);
	}

	return (status);
}

/*
 * Refreshes the address in the address object `aobjname'. If the address object
 * is of type IPADM_ADDR_STATIC, DAD is re-initiated on the address. If
 * `ipadm_flags' has IPADM_OPT_INFORM set, a DHCP_INFORM message is sent to the
 * dhcpagent for this static address. If the address object is of type
 * IPADM_ADDR_DHCP, a DHCP_EXTEND message is sent to the dhcpagent.
 * If a dhcp address has not yet been acquired, a DHCP_START is sent to the
 * dhcpagent. This operation is not supported for an address object of
 * type IPADM_ADDR_IPV6_ADDRCONF.
 */
ipadm_status_t
ipadm_refresh_addr(ipadm_handle_t iph, const char *aobjname,
    uint32_t ipadm_flags)
{
	ipadm_status_t		status = IPADM_SUCCESS;
	uint64_t		flags;
	struct ipadm_addrobj_s	ipaddr;
	sa_family_t		af;
	char			lifname[LIFNAMSIZ];
	boolean_t		inform =
	    ((ipadm_flags & IPADM_OPT_INFORM) != 0);

	/* check for solaris.network.interface.config authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);

	bzero(&ipaddr, sizeof (ipaddr));
	/* validate input */
	if (aobjname == NULL || strlcpy(ipaddr.ipadm_aobjname, aobjname,
	    IPADM_AOBJSIZ) >= IPADM_AOBJSIZ) {
		return (IPADM_INVALID_ARG);
	}

	/* Retrieve the address object information. */
	status = i_ipadm_get_addrobj(iph, &ipaddr);
	if (status != IPADM_SUCCESS)
		return (status);

	if (!(ipaddr.ipadm_flags & IPMGMT_ACTIVE))
		return (IPADM_OP_DISABLE_OBJ);

	if (i_ipadm_is_vni(ipaddr.ipadm_ifname))
		return (IPADM_NOTSUP);
	if (inform && ipaddr.ipadm_atype != IPADM_ADDR_STATIC)
		return (IPADM_INVALID_ARG);
	af = ipaddr.ipadm_af;
	if (ipaddr.ipadm_atype == IPADM_ADDR_STATIC) {
		i_ipadm_addrobj2lifname(&ipaddr, lifname, sizeof (lifname));
		status = i_ipadm_get_flags(iph, lifname, af, &flags);
		if (status != IPADM_SUCCESS)
			return (status);
		if (inform) {
			if (dhcp_start_agent(DHCP_IPC_MAX_WAIT) == -1)
				return (IPADM_DHCP_START_ERROR);

			ipaddr.ipadm_wait = IPADM_DHCP_WAIT_DEFAULT;
			return (i_ipadm_op_dhcp(&ipaddr, DHCP_INFORM, NULL));
		}
		if (!(flags & IFF_DUPLICATE))
			return (IPADM_SUCCESS);
		status = i_ipadm_set_flags(iph, lifname, af, IFF_UP, 0);
	} else if (ipaddr.ipadm_atype == IPADM_ADDR_DHCP) {
		status = i_ipadm_refresh_dhcp(&ipaddr);
	} else {
		status = IPADM_NOTSUP;
	}
	return (status);
}

/*
 * This is called from ipadm_refresh_addr() and i_ipadm_set_reqhost() to
 * send a DHCP_EXTEND message and possibly a DHCP_START message
 * to the dhcpagent.
 */
static ipadm_status_t
i_ipadm_refresh_dhcp(ipadm_addrobj_t ipaddr)
{
	ipadm_status_t		status;
	int			dherr;

	status = i_ipadm_op_dhcp(ipaddr, DHCP_EXTEND, &dherr);
	/*
	 * Restart the dhcp address negotiation with server if no
	 * address has been acquired yet.
	 */
	if (status != IPADM_SUCCESS && dherr == DHCP_IPC_E_OUTSTATE) {
		ipaddr->ipadm_wait = IPADM_DHCP_WAIT_DEFAULT;
		status = i_ipadm_op_dhcp(ipaddr, DHCP_START, NULL);
	}

	return (status);
}

/*
 * This is called from ipadm_create_addr() to validate the address parameters.
 * It does the following steps:
 * 1. Validates the interface name.
 * 2. Verifies that the interface is not an IPMP meta-interface or an
 *	underlying interface.
 * 3. In case of a persistent operation, verifies that the interface
 *	is persistent. Returns error if interface is not enabled but
 *	is in persistent config.
 * 4. Verifies that the destination address is not set or the address type is
 *	not DHCP or ADDRCONF when the interface is a loopback interface.
 * 5. Verifies that the address type is not DHCP or ADDRCONF when the interface
 *	has IFF_VRRP interface flag set.
 */
static ipadm_status_t
i_ipadm_validate_create_addr(ipadm_handle_t iph, ipadm_addrobj_t ipaddr,
    uint32_t flags)
{
	sa_family_t		af;
	sa_family_t		other_af;
	char			*ifname;
	ipadm_status_t		status;
	boolean_t		legacy = (iph->iph_flags & IPH_LEGACY);
	boolean_t		islo, isvni;
	uint64_t		ifflags = 0;
	boolean_t		p_exists;
	boolean_t		af_exists, other_af_exists, a_exists;

	if (ipaddr == NULL || flags == 0 || flags == IPADM_OPT_PERSIST ||
	    (flags & ~(IPADM_COMMON_OPT_MASK|IPADM_OPT_UP|IPADM_OPT_V46))) {
		return (IPADM_INVALID_ARG);
	}

	if (ipaddr->ipadm_af == AF_UNSPEC)
		return (IPADM_BAD_ADDR);

	if (!legacy && ipaddr->ipadm_lifnum != 0)
		return (IPADM_INVALID_ARG);

	if (legacy && ipaddr->ipadm_atype != IPADM_ADDR_STATIC)
		return (IPADM_NOTSUP);

	ifname = ipaddr->ipadm_ifname;

	if (i_ipadm_is_ipmp(iph, ifname) || i_ipadm_is_under_ipmp(iph, ifname))
		return (IPADM_NOTSUP);

	af = ipaddr->ipadm_af;
	af_exists = ipadm_if_enabled(iph, ifname, af);
	/*
	 * For legacy case, interfaces are not implicitly plumbed. We need to
	 * check if the interface exists in the active configuration.
	 */
	if (legacy && !af_exists)
		return (IPADM_ENXIO);

	other_af = (af == AF_INET ? AF_INET6 : AF_INET);
	other_af_exists = ipadm_if_enabled(iph, ifname, other_af);
	/*
	 * Check if one of the v4 or the v6 interfaces exists in the
	 * active configuration. An interface is considered disabled only
	 * if both v4 and v6 are not active.
	 */
	a_exists = (af_exists || other_af_exists);

	/* Check if interface exists in the persistent configuration. */
	status = i_ipadm_if_pexists(iph, ifname, af, &p_exists);
	if (status != IPADM_SUCCESS)
		return (status);
	if (!a_exists && p_exists)
		return (IPADM_OP_DISABLE_OBJ);
	if ((flags & IPADM_OPT_PERSIST) && a_exists && !p_exists) {
		/*
		 * If address has to be created persistently,
		 * and the interface does not exist in the persistent
		 * store but in active config, fail.
		 */
		return (IPADM_TEMPORARY_OBJ);
	}
	if (af_exists) {
		status = i_ipadm_get_flags(iph, ifname, af, &ifflags);
		if (status != IPADM_SUCCESS)
			return (status);
	}

	/* Perform validation steps (4) and (5) */
	islo = i_ipadm_is_loopback(ifname);
	isvni = i_ipadm_is_vni(ifname);
	switch (ipaddr->ipadm_atype) {
	case IPADM_ADDR_STATIC:
		if ((islo || isvni) && ipaddr->ipadm_static_dname[0] != '\0')
			return (IPADM_INVALID_ARG);
		/* Check for a valid src address */
		if (!legacy && sockaddrunspec(
		    (struct sockaddr *)&ipaddr->ipadm_static_addr))
			return (IPADM_BAD_ADDR);
		break;
	case IPADM_ADDR_DHCP:
		if (islo || (ifflags & IFF_VRRP))
			return (IPADM_NOTSUP);
		break;
	case IPADM_ADDR_IPV6_ADDRCONF:
		if (islo || (ifflags & IFF_VRRP) ||
		    i_ipadm_is_6to4(iph, ifname)) {
			return (IPADM_NOTSUP);
		}
		break;
	default:
		return (IPADM_INVALID_ARG);
	}

	return (IPADM_SUCCESS);
}

ipadm_status_t
i_ipadm_merge_addrprops_from_nvl(nvlist_t *invl, nvlist_t *onvl,
    const char *aobjname)
{
	const char * const	ADDRPROPS[] =
	    { IPADM_NVP_PREFIXLEN, IPADM_NVP_REQHOST };
	const size_t		ADDRPROPSLEN =
	    sizeof (ADDRPROPS) / sizeof (*ADDRPROPS);
	nvpair_t	*nvp, *propnvp;
	nvlist_t	*tnvl;
	char		*aname;
	const char	*propname;
	size_t		i;
	int		err;

	for (i = 0; i < ADDRPROPSLEN; ++i) {
		propname = ADDRPROPS[i];

		for (nvp = nvlist_next_nvpair(invl, NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(invl, nvp)) {
			if (nvpair_value_nvlist(nvp, &tnvl) == 0 &&
			    nvlist_exists(tnvl, propname) &&
			    nvlist_lookup_string(tnvl, IPADM_NVP_AOBJNAME,
			    &aname) == 0 && strcmp(aname, aobjname) == 0) {

				/*
				 * property named `propname' exists for given
				 * aobj
				 */
				(void) nvlist_lookup_nvpair(tnvl, propname,
				    &propnvp);
				err = nvlist_add_nvpair(onvl, propnvp);
				if (err == 0) {
					err = nvlist_remove(invl,
					    nvpair_name(nvp), nvpair_type(nvp));
				}
				if (err != 0)
					return (ipadm_errno2status(err));
				break;
			}
		}
	}
	return (IPADM_SUCCESS);
}

/*
 * Re-enables the address object `aobjname' based on the saved
 * configuration for `aobjname'.
 */
ipadm_status_t
ipadm_enable_addr(ipadm_handle_t iph, const char *aobjname, uint32_t flags)
{
	nvlist_t	*addrnvl, *nvl;
	nvpair_t	*nvp;
	ipadm_status_t	status;
	struct ipadm_addrobj_s ipaddr;

	/* check for solaris.network.interface.config authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);

	/* validate input */
	if (flags & IPADM_OPT_PERSIST)
		return (IPADM_NOTSUP);
	if (aobjname == NULL || strlcpy(ipaddr.ipadm_aobjname, aobjname,
	    IPADM_AOBJSIZ) >= IPADM_AOBJSIZ) {
		return (IPADM_INVALID_ARG);
	}

	/* Retrieve the address object information. */
	status = i_ipadm_get_addrobj(iph, &ipaddr);
	if (status != IPADM_SUCCESS)
		return (status);
	if (ipaddr.ipadm_flags & IPMGMT_ACTIVE)
		return (IPADM_ADDROBJ_EXISTS);

	status = i_ipadm_get_db_addr(iph, NULL, aobjname, &addrnvl);
	if (status != IPADM_SUCCESS)
		return (status);

	assert(addrnvl != NULL);

	for (nvp = nvlist_next_nvpair(addrnvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(addrnvl, nvp)) {
		if (nvpair_value_nvlist(nvp, &nvl) != 0)
			continue;

		if (nvlist_exists(nvl, IPADM_NVP_IPV4ADDR) ||
		    nvlist_exists(nvl, IPADM_NVP_IPV6ADDR) ||
		    nvlist_exists(nvl, IPADM_NVP_DHCP)) {
			status = i_ipadm_merge_addrprops_from_nvl(addrnvl, nvl,
			    aobjname);
			if (status != IPADM_SUCCESS)
				continue;
		}
		iph->iph_flags |= IPH_INIT;
		status = i_ipadm_init_addrobj(iph, nvl);
		iph->iph_flags &= ~IPH_INIT;
		if (status != IPADM_SUCCESS)
			break;
	}

	nvlist_free(addrnvl);
	return (status);
}

/*
 * Disables the address object in `aobjname' from the active configuration.
 * Error code return values follow the model in ipadm_delete_addr().
 */
ipadm_status_t
ipadm_disable_addr(ipadm_handle_t iph, const char *aobjname, uint32_t flags)
{
	/* validate input */
	if (flags & IPADM_OPT_PERSIST)
		return (IPADM_NOTSUP);

	return (ipadm_delete_addr(iph, aobjname, IPADM_OPT_ACTIVE));
}
