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

#include <errno.h>
#include <sys/sockio.h>
#include <sys/list.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stropts.h>
#include <strings.h>
#include <libdlpi.h>
#include <libdllink.h>
#include <libinetutil.h>
#include <inet/ip.h>
#include <limits.h>
#include <zone.h>
#include <ipadm_ndpd.h>
#include <ipmp_query.h>
#include "libipadm_impl.h"

static ipadm_status_t	i_ipadm_slifname_arp(char *, uint64_t, int);
static ipadm_status_t	i_ipadm_slifname(ipadm_handle_t, char *, char *,
			    uint64_t, int, uint32_t);
static ipadm_status_t	i_ipadm_create_ipmp_peer(ipadm_handle_t, char *,
			    sa_family_t);
static ipadm_status_t	i_ipadm_persist_if(ipadm_handle_t, const char *,
			    sa_family_t, uint32_t);
static ipadm_status_t   i_ipadm_allocate_ifinfo(ipadm_if_info_t **);
static ipadm_status_t	i_ipadm_get_db_if(ipadm_handle_t, const char *,
			    nvlist_t **);
static ipadm_status_t i_ipadm_nvl2ifinfo(nvlist_t *, ipadm_if_info_t **);
static ipadm_status_t i_ipadm_fill_cmembers(char *, ipadm_ipmp_members_t *);
static ipadm_status_t i_ipadm_fill_pmembers(nvlist_t *, ipadm_ipmp_members_t *);
static ipadm_status_t i_ipadm_add_persistent_if_info(ipadm_if_info_t *,
		    ipadm_if_info_t *);
static void i_ipadm_free_ipmp_members(ipadm_ipmp_members_t *);
static ipadm_status_t i_ipadm_persist_update_ipmp(ipadm_handle_t, const char *,
	const char *,
	ipadm_ipmp_op_t);
static ipadm_status_t i_ipadm_update_ipmp(ipadm_handle_t, const char *,
	const char *, uint32_t,
	ipadm_ipmp_op_t);

/*
 * Returns B_FALSE if the interface in `ifname' has at least one address that is
 * IFF_UP in the addresses in `ifa'.
 */
static boolean_t
i_ipadm_is_if_down(char *ifname, struct ifaddrs *ifa)
{
	struct ifaddrs	*ifap;
	char		cifname[LIFNAMSIZ];
	char		*sep;

	for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next) {
		(void) strlcpy(cifname, ifap->ifa_name, sizeof (cifname));
		if ((sep = strrchr(cifname, IPADM_LOGICAL_SEP)) != NULL)
			*sep = '\0';
		/*
		 * If this condition is true, there is at least one
		 * address that is IFF_UP. So, we need to return B_FALSE.
		 */
		if (strcmp(cifname, ifname) == 0 &&
		    (ifap->ifa_flags & IFF_UP)) {
			return (B_FALSE);
		}
	}
	/* We did not find any IFF_UP addresses. */
	return (B_TRUE);
}

/*
 * Retrieves the information for the interface `ifname' from active
 * config if `ifname' is specified and returns the result in the list `if_info'.
 * Otherwise, it retrieves the information for all the interfaces in
 * the active config and returns the result in the list `if_info'.
 */
static ipadm_status_t
i_ipadm_active_if_info(ipadm_handle_t iph, const char *ifname,
    ipadm_if_info_t **if_info, int64_t lifc_flags)
{
	struct lifreq	*buf;
	struct lifreq	*lifrp;
	struct lifreq	lifrl;
	ipadm_if_info_t	*last = NULL;
	ipadm_if_info_t	*ifp;
	int		s;
	int		n;
	int		numifs;
	ipadm_status_t	status = IPADM_SUCCESS;

	*if_info = NULL;
	/*
	 * Get information for all interfaces.
	 */
	if (getallifs(iph->iph_sock, 0, &buf, &numifs, lifc_flags) != 0)
		return (ipadm_errno2status(errno));

	lifrp = buf;
	for (n = 0; n < numifs; n++, lifrp++) {
		/* Skip interfaces with logical num != 0 */
		if (i_ipadm_get_lnum(lifrp->lifr_name) != 0)
			continue;
		/*
		 * Skip the current interface if a specific `ifname' has
		 * been requested and current interface does not match
		 * `ifname'.
		 */
		if (ifname != NULL && strcmp(lifrp->lifr_name, ifname) != 0)
			continue;
		/*
		 * Check if the interface already exists in our list.
		 * If it already exists, we need to update its flags.
		 */
		for (ifp = *if_info; ifp != NULL; ifp = ifp->ifi_next) {
			if (strcmp(lifrp->lifr_name, ifp->ifi_name) == 0)
				break;
		}
		if (ifp == NULL) {
			if ((status =
			    i_ipadm_allocate_ifinfo(&ifp)) != IPADM_SUCCESS)
					break;

			(void) strlcpy(ifp->ifi_name, lifrp->lifr_name,
			    sizeof (ifp->ifi_name));
			/* Update the `ifi_next' pointer for this new node */
			if (*if_info == NULL)
				*if_info = ifp;
			else
				last->ifi_next = ifp;
			last = ifp;
		}

		/*
		 * Retrieve the flags for the interface by doing a
		 * SIOCGLIFFLAGS to populate the `ifi_cflags' field.
		 */
		(void) strlcpy(lifrl.lifr_name,
		    lifrp->lifr_name, sizeof (lifrl.lifr_name));
		s = (lifrp->lifr_addr.ss_family == AF_INET) ?
		    iph->iph_sock : iph->iph_sock6;
		if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifrl) < 0)
			continue;

		/* a regular interface by default */
		ifp->ifi_class = IPADM_IF_CLASS_REGULAR;

		if (lifrl.lifr_flags & IFF_BROADCAST)
			ifp->ifi_cflags |= IFIF_BROADCAST;
		if (lifrl.lifr_flags & IFF_MULTICAST)
			ifp->ifi_cflags |= IFIF_MULTICAST;
		if (lifrl.lifr_flags & IFF_POINTOPOINT)
			ifp->ifi_cflags |= IFIF_POINTOPOINT;
		if (lifrl.lifr_flags & IFF_VIRTUAL) {
			ifp->ifi_cflags |= IFIF_VIRTUAL;
			ifp->ifi_class = IPADM_IF_CLASS_VIRTUAL;
		}
		if (lifrl.lifr_flags & IFF_IPMP) {
			ifp->ifi_cflags |= IFIF_IPMP;
			ifp->ifi_class = IPADM_IF_CLASS_IPMP;
		}
		if (lifrl.lifr_flags & IFF_STANDBY)
			ifp->ifi_cflags |= IFIF_STANDBY;
		if (lifrl.lifr_flags & IFF_INACTIVE)
			ifp->ifi_cflags |= IFIF_INACTIVE;
		if (lifrl.lifr_flags & IFF_VRRP)
			ifp->ifi_cflags |= IFIF_VRRP;
		if (lifrl.lifr_flags & IFF_NOACCEPT)
			ifp->ifi_cflags |= IFIF_NOACCEPT;
		if (lifrl.lifr_flags & IFF_IPV4)
			ifp->ifi_cflags |= IFIF_IPV4;
		if (lifrl.lifr_flags & IFF_IPV6)
			ifp->ifi_cflags |= IFIF_IPV6;
		if (lifrl.lifr_flags & IFF_L3PROTECT)
			ifp->ifi_cflags |= IFIF_L3PROTECT;

		/*
		 * Retrieve active IPMP members. This may fail in in.mpathd if
		 * the IPMP interface has just been created with no members.
		 * Hence, ignore errors, cmembers will just be empty.
		 */
		if (ifp->ifi_class == IPADM_IF_CLASS_IPMP) {
			if (ioctl(s, SIOCGLIFGROUPNAME, (caddr_t)&lifrl) == 0) {
				(void) i_ipadm_fill_cmembers(
				    lifrl.lifr_groupname,
				    &ifp->ifi_ipmp_cmembers);
			}
		}
	}
	free(buf);
	if (status != IPADM_SUCCESS) {
		ipadm_free_if_info(*if_info);
		*if_info = NULL;
	}
	return (status);
}

/*
 * Returns the interface information for `ifname' in `if_info' from persistent
 * config if `ifname' is non-null. Otherwise, it returns all the interfaces
 * from persistent config in `if_info'.
 */
static ipadm_status_t
i_ipadm_persist_if_info(ipadm_handle_t iph, const char *ifname,
    ipadm_if_info_t **if_info)
{
	ipadm_status_t	status = IPADM_SUCCESS;
	nvlist_t	*ifs_info_nvl;

	*if_info = NULL;

	if ((status = i_ipadm_get_db_if(iph,
	    ifname, &ifs_info_nvl)) != IPADM_SUCCESS)
		return (status);

	assert(ifs_info_nvl != NULL);

	return (i_ipadm_nvl2ifinfo(ifs_info_nvl, if_info));
}

static ipadm_status_t
i_ipadm_nvl2ifinfo(nvlist_t *ifs_info_nvl, ipadm_if_info_t **if_info)
{
	ipadm_if_info_t *ific = NULL, *ifil = NULL;
	nvlist_t	*if_info_nvl;
	nvpair_t	*nvp;
	char		*strval;
	ipadm_status_t	status = IPADM_SUCCESS;
	uint16_t	*families;
	uint_t		nelem = 0;

	for (nvp = nvlist_next_nvpair(ifs_info_nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(ifs_info_nvl, nvp)) {
		if (nvpair_value_nvlist(nvp, &if_info_nvl) != 0)
			continue;

		status = i_ipadm_allocate_ifinfo(&ific);
		if (status != IPADM_SUCCESS) {
			ipadm_free_if_info(*if_info);
			break;
		}
		if (nvlist_lookup_string(if_info_nvl, IPADM_NVP_IFNAME,
		    &strval) != 0) {
			ipadm_free_if_info(ific);
			ific = NULL;
			continue;
		}
		(void) strlcpy(ific->ifi_name, strval,
		    sizeof (ific->ifi_name));

		if (nvlist_lookup_uint16_array(if_info_nvl,
		    IPADM_NVP_FAMILIES, &families, &nelem) == 0) {
			while (nelem-- > 0) {
				if (families[nelem] == AF_INET)
					ific->ifi_pflags |= IFIF_IPV4;
				else if (families[nelem] == AF_INET6)
					ific->ifi_pflags |= IFIF_IPV6;
			}
		}

		if (nvlist_lookup_string(if_info_nvl,
		    IPADM_NVP_IFCLASS, &strval) == 0)
			ific->ifi_class = atoi(strval);
		else
			ific->ifi_class = IPADM_IF_CLASS_REGULAR;

		if (ific->ifi_class == IPADM_IF_CLASS_IPMP)
			/* do not expect any failures there */
			(void) i_ipadm_fill_pmembers(if_info_nvl,
			    &ific->ifi_ipmp_pmembers);

		if (*if_info == NULL)
			*if_info = ific;
		else
			ifil->ifi_next = ific;
		ifil = ific;
	}

	nvlist_free(ifs_info_nvl);
	return (status);
}

/*
 * Fill the ipadm_if_info_t->ifi_ipmp_pmembers by info from
 * ipadm DB
 */
static ipadm_status_t
i_ipadm_fill_pmembers(nvlist_t *if_info_nvl, ipadm_ipmp_members_t *pmembers)
{
	uint_t	nelem = 0;
	char	**members;
	ipadm_ipmp_member_t *ipmp_member;

	if (nvlist_lookup_string_array(if_info_nvl, IPADM_NVP_MIFNAMES,
	    &members, &nelem) != 0)
		return (IPADM_SUCCESS);

	while (nelem-- > 0) {
		if ((ipmp_member = calloc(1,
		    sizeof (ipadm_ipmp_member_t))) == NULL)
			return (ipadm_errno2status(errno));

		(void) strlcpy(ipmp_member->if_name, members[nelem],
		    sizeof (ipmp_member->if_name));
		list_insert_tail(pmembers, ipmp_member);
	}
	return (IPADM_SUCCESS);
}

/*
 * Fill the ipadm_if_info_t->ifi_ipmp_cmembers by info from
 * kernel (libipmp is used to retrieve the required info)
 */
static ipadm_status_t
i_ipadm_fill_cmembers(char *grname, ipadm_ipmp_members_t *cmembers)
{
	ipmp_handle_t ipmp_handle;
	ipmp_groupinfo_t *grinfo;
	ipmp_iflist_t *iflistp;
	ipadm_ipmp_member_t *ipmp_member;
	ipadm_status_t ipadm_status = IPADM_SUCCESS;
	int i;

	if (ipmp_open(&ipmp_handle) != IPMP_SUCCESS)
		return (IPADM_FAILURE);

	if (ipmp_getgroupinfo(ipmp_handle, grname, &grinfo) != IPMP_SUCCESS) {
		ipadm_status = IPADM_FAILURE;
		goto fail2;
	}

	iflistp = grinfo->gr_iflistp;
	for (i = 0; i < iflistp->il_nif; i++) {
		if ((ipmp_member = calloc(1,
		    sizeof (ipadm_ipmp_member_t))) == NULL) {
			ipadm_status = ipadm_errno2status(errno);
			goto fail1;
		}
		(void) strlcpy(ipmp_member->if_name, iflistp->il_ifs[i],
		    sizeof (ipmp_member->if_name));
		list_insert_tail(cmembers, ipmp_member);
	}

fail1:
	ipmp_freegroupinfo(grinfo);
fail2:
	ipmp_close(ipmp_handle);
	return (ipadm_status);
}

/*
 * Collects information for `ifname' if one is specified from both
 * active and persistent config in `if_info'. If no `ifname' is specified,
 * this returns all the interfaces in active and persistent config in
 * `if_info'.
 */
ipadm_status_t
i_ipadm_get_all_if_info(ipadm_handle_t iph, const char *ifname,
    ipadm_if_info_t **if_info, int64_t lifc_flags)
{
	ipadm_status_t	status;
	ipadm_if_info_t	*aifinfo = NULL;
	ipadm_if_info_t	*pifinfo = NULL;
	ipadm_if_info_t	*aifp;
	ipadm_if_info_t	*pifp;
	ipadm_if_info_t	*last = NULL;
	struct ifaddrs	*ifa;
	struct ifaddrs	*ifap;

	/*
	 * Retrive the information for the requested `ifname' or all
	 * interfaces from active configuration.
	 */
retry:
	status = i_ipadm_active_if_info(iph, ifname, &aifinfo, lifc_flags);
	if (status != IPADM_SUCCESS)
		return (status);
	/* Get the interface state for each interface in `aifinfo'. */
	if (aifinfo != NULL) {
		/* We need all addresses to get the interface state */
		if (getallifaddrs(AF_UNSPEC, &ifa, (LIFC_NOXMIT|LIFC_TEMPORARY|
		    LIFC_ALLZONES|LIFC_UNDER_IPMP)) != 0) {
			status = ipadm_errno2status(errno);
			goto fail;
		}
		for (aifp = aifinfo; aifp != NULL; aifp = aifp->ifi_next) {
			/*
			 * Find the `ifaddrs' structure from `ifa'
			 * for this interface. We need the IFF_* flags
			 * to find the interface state.
			 */
			for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next) {
				if (strcmp(ifap->ifa_name, aifp->ifi_name) == 0)
					break;
			}
			if (ifap == NULL) {
				/*
				 * The interface might have been removed
				 * from kernel. Retry getting all the active
				 * interfaces.
				 */
				freeifaddrs(ifa);
				ipadm_free_if_info(aifinfo);
				aifinfo = NULL;
				goto retry;
			}
			if (!(ifap->ifa_flags & IFF_RUNNING) ||
			    (ifap->ifa_flags & IFF_FAILED))
				aifp->ifi_state = IFIS_FAILED;
			else if (ifap->ifa_flags & IFF_OFFLINE)
				aifp->ifi_state = IFIS_OFFLINE;
			else if (i_ipadm_is_if_down(aifp->ifi_name, ifa))
				aifp->ifi_state = IFIS_DOWN;
			else
				aifp->ifi_state = IFIS_OK;
			if (aifp->ifi_next == NULL)
				last = aifp;
		}
		freeifaddrs(ifa);
	}
	/*
	 * Get the persistent interface information in `pifinfo'.
	 */
	status = i_ipadm_persist_if_info(iph, ifname, &pifinfo);
	if (status == IPADM_NOTFOUND) {
		*if_info = aifinfo;
		return (IPADM_SUCCESS);
	}
	if (status != IPADM_SUCCESS)
		goto fail;

	/*
	 * Process the persistent interface information.
	 *
	 * First try to get the persistent "standby" property, as that isn't
	 * retrieved by i_ipadm_persist_if_info().
	 *
	 * Next, if a persistent interface is also found in `aifinfo', update
	 * its entry in `aifinfo' with the persistent information from
	 * `pifinfo'. If an interface is found in `pifinfo', but not in
	 * `aifinfo', it means that this interface was disabled. We should
	 * add this interface to `aifinfo' and set it state to IFIF_DISABLED.
	 */
	for (pifp = pifinfo; pifp != NULL; pifp = pifp->ifi_next) {
		char buf[10] = "";
		uint_t bufsize = sizeof (buf);

		status = ipadm_get_ifprop(iph, pifp->ifi_name, "standby", buf,
		    &bufsize, MOD_PROTO_IP, IPADM_OPT_PERSIST);

		if (status == IPADM_SUCCESS && strcmp(buf, "on") == 0)
			pifp->ifi_pflags |= IFIF_STANDBY;

		for (aifp = aifinfo; aifp != NULL; aifp = aifp->ifi_next) {
			if (strcmp(aifp->ifi_name, pifp->ifi_name) == 0) {
				break;
			}
		}

		if (aifp == NULL) {
			if ((status =
			    i_ipadm_allocate_ifinfo(&aifp)) != IPADM_SUCCESS)
				goto fail;

			(void) strlcpy(aifp->ifi_name, pifp->ifi_name,
			    sizeof (aifp->ifi_name));

			aifp->ifi_next = NULL;
			aifp->ifi_state = IFIS_DISABLED;
			if (last != NULL)
				last->ifi_next = aifp;
			else
				aifinfo = aifp;
			last = aifp;
		}

		if ((status = i_ipadm_add_persistent_if_info(aifp,
		    pifp)) != IPADM_SUCCESS)
			goto fail;
	}
	*if_info = aifinfo;
	ipadm_free_if_info(pifinfo);
	return (IPADM_SUCCESS);
fail:
	*if_info = NULL;
	ipadm_free_if_info(aifinfo);
	ipadm_free_if_info(pifinfo);
	return (status);
}

/*
 * Updates active if_info by data from persistent if_info
 */
static ipadm_status_t
i_ipadm_add_persistent_if_info(ipadm_if_info_t *aifp, ipadm_if_info_t *pifp)
{
	ipadm_ipmp_member_t *pp_ipmp_member, *ap_ipmp_member;

	ipadm_ipmp_members_t *apmembers = &aifp->ifi_ipmp_pmembers;
	ipadm_ipmp_members_t *ppmembers = &pifp->ifi_ipmp_pmembers;

	aifp->ifi_pflags = pifp->ifi_pflags;
	aifp->ifi_class = pifp->ifi_class;

	for (pp_ipmp_member = list_head(ppmembers); pp_ipmp_member;
	    pp_ipmp_member = list_next(ppmembers, pp_ipmp_member)) {
		if ((ap_ipmp_member = calloc(1,
		    sizeof (ipadm_ipmp_member_t))) == NULL)
			return (ipadm_errno2status(errno));

		(void) strlcpy(ap_ipmp_member->if_name,
		    pp_ipmp_member->if_name,
		    sizeof (ap_ipmp_member->if_name));

		list_insert_tail(apmembers, ap_ipmp_member);
	}
	return (IPADM_SUCCESS);
}

static ipadm_status_t
i_ipadm_allocate_ifinfo(ipadm_if_info_t **if_info)
{
	*if_info = calloc(1, sizeof (ipadm_if_info_t));
	if (*if_info == NULL)
		return (ipadm_errno2status(errno));

	/* List of active (current) members */
	list_create(&((*if_info)->ifi_ipmp_cmembers),
	    sizeof (ipadm_ipmp_member_t),
	    offsetof(ipadm_ipmp_member_t, node));

	/* List of persistent members */
	list_create(&((*if_info)->ifi_ipmp_pmembers),
	    sizeof (ipadm_ipmp_member_t),
	    offsetof(ipadm_ipmp_member_t, node));

	return (IPADM_SUCCESS);
}

/*
 * Reads all the interface lines from the persistent DB into the nvlist `onvl',
 * when `ifname' is NULL.
 * If an `ifname' is specified, then the interface line corresponding to
 * that name will be returned.
 */
static ipadm_status_t
i_ipadm_get_db_if(ipadm_handle_t iph, const char *ifname, nvlist_t **onvl)
{
	ipmgmt_getif_arg_t	garg;

	/* Populate the door_call argument structure */
	bzero(&garg, sizeof (garg));
	garg.ia_cmd = IPMGMT_CMD_GETIF;
	if (ifname != NULL)
		(void) strlcpy(garg.ia_ifname, ifname, sizeof (garg.ia_ifname));

	return (i_ipadm_call_ipmgmtd(iph, (void *) &garg, sizeof (garg), onvl));
}

int
i_ipadm_get_lnum(const char *ifname)
{
	char *num = strrchr(ifname, IPADM_LOGICAL_SEP);

	if (num == NULL)
		return (0);

	return (atoi(++num));
}

/*
 * Sets the output argument `exists' to true or false based on whether
 * any persistent configuration is available for `ifname' and returns
 * IPADM_SUCCESS as status. If the persistent information cannot be retrieved,
 * `exists' is unmodified and an error status is returned.
 */
ipadm_status_t
i_ipadm_if_pexists(ipadm_handle_t iph, const char *ifname, sa_family_t af,
    boolean_t *exists)
{
	ipadm_if_info_t	*ifinfo;
	ipadm_status_t	status;

	/*
	 * if IPH_IPMGMTD is set, we know that the caller (ipmgmtd) already
	 * knows about persistent configuration in the first place, so we
	 * just return success.
	 */
	if (iph->iph_flags & IPH_IPMGMTD) {
		*exists = B_FALSE;
		return (IPADM_SUCCESS);
	}
	status = i_ipadm_persist_if_info(iph, ifname, &ifinfo);
	if (status == IPADM_SUCCESS) {
		*exists = ((af == AF_INET &&
		    (ifinfo->ifi_pflags & IFIF_IPV4)) ||
		    (af == AF_INET6 &&
		    (ifinfo->ifi_pflags & IFIF_IPV6)));
		ipadm_free_if_info(ifinfo);
	} else if (status == IPADM_NOTFOUND) {
		status = IPADM_SUCCESS;
		*exists = B_FALSE;
	}
	return (status);
}

/*
 * Open "/dev/udp{,6}" for use as a multiplexor to PLINK the interface stream
 * under. We use "/dev/udp" instead of "/dev/ip" since STREAMS will not let
 * you PLINK a driver under itself, and "/dev/ip" is typically the driver at
 * the bottom of the stream for tunneling interfaces.
 */
ipadm_status_t
ipadm_open_arp_on_udp(const char *udp_dev_name, int *fd)
{
	int err;

	if ((*fd = open(udp_dev_name, O_RDWR)) == -1)
		return (ipadm_errno2status(errno));

	/*
	 * Pop off all undesired modules (note that the user may have
	 * configured autopush to add modules above udp), and push the
	 * arp module onto the resulting stream. This is used to make
	 * IP+ARP be able to atomically track the muxid for the I_PLINKed
	 * STREAMS, thus it isn't related to ARP running the ARP protocol.
	 */
	while (ioctl(*fd, I_POP, 0) != -1)
		;
	if (errno == EINVAL && ioctl(*fd, I_PUSH, ARP_MOD_NAME) != -1)
		return (IPADM_SUCCESS);
	err = errno;
	(void) close(*fd);

	return (ipadm_errno2status(err));
}

/*
 * i_ipadm_create_ipmp() is called from i_ipadm_create_ipmp_peer() when an
 * underlying interface in an ipmp group G is plumbed for an address family,
 * but the meta-interface for the other address family `af' does not exist
 * yet for the group G. If `af' is IPv6, we need to bring up the
 * link-local address.
 */
static ipadm_status_t
i_ipadm_create_ipmp(ipadm_handle_t iph, char *ifname, sa_family_t af,
    const char *grname, uint32_t ipadm_flags)
{
	ipadm_status_t	status;
	struct lifreq	lifr;
	int		sock;
	int		err;

	assert(ipadm_flags & IPADM_OPT_IPMP);

	/* Create the ipmp underlying interface */
	status = i_ipadm_create_if(iph, ifname, af, ipadm_flags);
	if (status != IPADM_SUCCESS && status != IPADM_IF_EXISTS)
		return (status);

	/*
	 * To preserve backward-compatibility, always bring up the link-local
	 * address for implicitly-created IPv6 IPMP interfaces.
	 */
	if (af == AF_INET6)
		(void) i_ipadm_set_flags(iph, ifname, AF_INET6, IFF_UP, 0);

	sock = (af == AF_INET ? iph->iph_sock : iph->iph_sock6);
	/*
	 * If the caller requested a different group name, issue a
	 * SIOCSLIFGROUPNAME on the new IPMP interface.
	 */
	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (strcmp(lifr.lifr_name, grname) != 0) {
		(void) strlcpy(lifr.lifr_groupname, grname, LIFGRNAMSIZ);
		if (ioctl(sock, SIOCSLIFGROUPNAME, &lifr) == -1) {
			err = errno;
			/* Remove the interface we created. */
			if (status == IPADM_SUCCESS) {
				(void) i_ipadm_delete_if(iph, ifname, af,
				    ipadm_flags);
			}
			return (ipadm_errno2status(err));
		}
	}

	return (IPADM_SUCCESS);
}

/*
 * Checks if `ifname' is plumbed and in an IPMP group on its "other" address
 * family.  If so, create a matching IPMP group for address family `af'.
 */
static ipadm_status_t
i_ipadm_create_ipmp_peer(ipadm_handle_t iph, char *ifname, sa_family_t af)
{
	lifgroupinfo_t	lifgr;
	ipadm_status_t	status = IPADM_SUCCESS;
	struct lifreq	lifr;
	int		other_af_sock;

	assert(af == AF_INET || af == AF_INET6);

	other_af_sock = (af == AF_INET ? iph->iph_sock6 : iph->iph_sock);

	/*
	 * iph is the handle for the interface that we are trying to plumb.
	 * other_af_sock is the socket for the "other" address family.
	 */
	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (ioctl(other_af_sock, SIOCGLIFGROUPNAME, &lifr) != 0)
		return (IPADM_SUCCESS);

	(void) strlcpy(lifgr.gi_grname, lifr.lifr_groupname, LIFGRNAMSIZ);
	if (ioctl(other_af_sock, SIOCGLIFGROUPINFO, &lifgr) != 0)
		return (IPADM_SUCCESS);

	/*
	 * If `ifname' *is* the IPMP group interface, or if the relevant
	 * address family is already configured, then there's nothing to do.
	 */
	if (strcmp(lifgr.gi_grifname, ifname) == 0 ||
	    (af == AF_INET && lifgr.gi_v4) || (af == AF_INET6 && lifgr.gi_v6)) {
		return (IPADM_SUCCESS);
	}

	status = i_ipadm_create_ipmp(iph, lifgr.gi_grifname, af,
	    lifgr.gi_grname, IPADM_OPT_ACTIVE|IPADM_OPT_IPMP);
	return (status);
}

/*
 * Issues the ioctl SIOCSLIFNAME to kernel on the given ARP stream fd.
 */
static ipadm_status_t
i_ipadm_slifname_arp(char *ifname, uint64_t flags, int fd)
{
	struct lifreq	lifr;
	ifspec_t	ifsp;

	bzero(&lifr, sizeof (lifr));
	(void) ifparse_ifspec(ifname, &ifsp);
	lifr.lifr_ppa = ifsp.ifsp_ppa;
	lifr.lifr_flags = flags;
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	/*
	 * Tell ARP the name and unit number for this interface.
	 * Note that arp has no support for transparent ioctls.
	 */
	if (i_ipadm_strioctl(fd, SIOCSLIFNAME, (char *)&lifr,
	    sizeof (lifr)) == -1) {
		return (ipadm_errno2status(errno));
	}
	return (IPADM_SUCCESS);
}

/*
 * Issues the ioctl SIOCSLIFNAME to kernel. If IPADM_OPT_GENPPA is set in
 * `ipadm_flags', then a ppa will be generated. `newif' will be updated
 * with the generated ppa.
 */
static ipadm_status_t
i_ipadm_slifname(ipadm_handle_t iph, char *ifname, char *newif, uint64_t flags,
    int fd, uint32_t ipadm_flags)
{
	struct lifreq	lifr;
	ipadm_status_t	status = IPADM_SUCCESS;
	int		err = 0;
	sa_family_t	af;
	int		ppa;
	ifspec_t	ifsp;
	boolean_t	valid_if;

	bzero(&lifr, sizeof (lifr));
	if (ipadm_flags & IPADM_OPT_GENPPA) {
		/*
		 * We'd like to just set lifr_ppa to UINT_MAX and have the
		 * kernel pick a PPA.  Unfortunately, that would mishandle
		 * two cases:
		 *
		 *	1. If the PPA is available but the groupname is taken
		 *	   (e.g., the "ipmp2" IP interface name is available
		 *	   but the "ipmp2" groupname is taken) then the
		 *	   auto-assignment by the kernel will fail.
		 *
		 *	2. If we're creating (e.g.) an IPv6-only IPMP
		 *	   interface, and there's already an IPv4-only IPMP
		 *	   interface, the kernel will allow us to accidentally
		 *	   reuse the IPv6 IPMP interface name (since
		 *	   SIOCSLIFNAME uniqueness is per-interface-type).
		 *	   This will cause administrative confusion.
		 *
		 * Thus, we instead take a brute-force approach of checking
		 * whether the IPv4 or IPv6 name is already in-use before
		 * attempting the SIOCSLIFNAME.  As per (1) above, the
		 * SIOCSLIFNAME may still fail, in which case we just proceed
		 * to the next one.  If this approach becomes too slow, we
		 * can add a new SIOC* to handle this case in the kernel.
		 */
		for (ppa = 0; ppa < UINT_MAX; ppa++) {
			(void) snprintf(lifr.lifr_name, LIFNAMSIZ, "%s%d",
			    ifname, ppa);

			if (ioctl(iph->iph_sock, SIOCGLIFFLAGS, &lifr) != -1 ||
			    errno != ENXIO)
				continue;

			if (ioctl(iph->iph_sock6, SIOCGLIFFLAGS, &lifr) != -1 ||
			    errno != ENXIO)
				continue;

			lifr.lifr_ppa = ppa;
			lifr.lifr_flags = flags;

			err = ioctl(fd, SIOCSLIFNAME, &lifr);
			if (err != -1 || errno != EEXIST)
				break;
		}
		if (err == -1) {
			status = ipadm_errno2status(errno);
		} else {
			/*
			 * PPA has been successfully established.
			 * Update `newif' with the ppa.
			 */
			assert(newif != NULL);
			if (snprintf(newif, LIFNAMSIZ, "%s%d", ifname,
			    ppa) >= LIFNAMSIZ)
				return (IPADM_INVALID_ARG);
		}
	} else {
		/* We should have already validated the interface name. */
		valid_if = ifparse_ifspec(ifname, &ifsp);
		assert(valid_if);

		/*
		 * Before we call SIOCSLIFNAME, ensure that the IPMP group
		 * interface for this address family exists.  Otherwise, the
		 * kernel will kick the interface out of the group when we do
		 * the SIOCSLIFNAME.
		 *
		 * Example: suppose bge0 is plumbed for IPv4 and in group "a".
		 * If we're now plumbing bge0 for IPv6, but the IPMP group
		 * interface for "a" is not plumbed for IPv6, the SIOCSLIFNAME
		 * will kick bge0 out of group "a", which is undesired.
		 */
		if (flags & IFF_IPV4)
			af = AF_INET;
		else
			af = AF_INET6;
		status = i_ipadm_create_ipmp_peer(iph, ifname, af);
		if (status != IPADM_SUCCESS)
			return (status);
		lifr.lifr_ppa = ifsp.ifsp_ppa;
		lifr.lifr_flags = flags;
		(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
		if (ioctl(fd, SIOCSLIFNAME, &lifr) == -1)
			status = ipadm_errno2status(errno);
	}

	return (status);
}

/*
 * Plumbs the interface `ifname' for the address family `af'. It also persists
 * the interface for `af' if IPADM_OPT_PERSIST is set in `ipadm_flags'.
 */
ipadm_status_t
i_ipadm_plumb_if(ipadm_handle_t iph, char *ifname, sa_family_t af,
    uint32_t ipadm_flags)
{
	int		ip_muxid;
	int		mux_fd = -1, ip_fd, arp_fd;
	char		*udp_dev_name;
	dlpi_handle_t	dh_arp = NULL, dh_ip;
	uint64_t	ifflags;
	struct lifreq	lifr;
	uint_t		dlpi_flags;
	ipadm_status_t	status = IPADM_SUCCESS;
	char		*linkname;
	boolean_t	legacy = (iph->iph_flags & IPH_LEGACY);
	zoneid_t	zoneid;
	char		newif[LIFNAMSIZ];
	char		lifname[LIFNAMSIZ];
	datalink_id_t	linkid;
	int		sock;
	boolean_t	islo;
	boolean_t	is_persistent =
	    ((ipadm_flags & IPADM_OPT_PERSIST) != 0);
	uint32_t	dlflags;
	dladm_status_t	dlstatus;

	if (iph->iph_dlh != NULL) {
		dlstatus = dladm_name2info(iph->iph_dlh, ifname, &linkid,
		    &dlflags, NULL, NULL);
	}
	/*
	 * If we're in the global zone and we're plumbing a datalink, make
	 * sure that the datalink is not assigned to a non-global zone.  Note
	 * that the non-global zones don't need this check, because zoneadm
	 * has taken care of this when the zones boot.
	 */
	if (iph->iph_zoneid == GLOBAL_ZONEID && dlstatus == DLADM_STATUS_OK) {
		zoneid = ALL_ZONES;
		if (zone_check_datalink(&zoneid, linkid) == 0) {
			/* interface is in use by a non-global zone. */
			return (IPADM_IF_INUSE);
		}
	}

	/* loopback interfaces are just added as logical interface */
	bzero(&lifr, sizeof (lifr));
	islo = i_ipadm_is_loopback(ifname);
	if (islo || i_ipadm_get_lnum(ifname) != 0) {
		(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
		if (af == AF_INET)
			sock = iph->iph_sock;
		else
			sock = iph->iph_sock6;
		if (islo && ioctl(sock, SIOCGLIFADDR, (caddr_t)&lifr) >= 0)
			return (IPADM_IF_EXISTS);
		if (ioctl(sock, SIOCLIFADDIF, (caddr_t)&lifr) < 0)
			return (ipadm_errno2status(errno));

		/*
		 * By default, kernel configures 127.0.0.1 on the loopback
		 * interface. Replace this with 0.0.0.0 to be consistent
		 * with interface creation on other physical interfaces.
		 */
		if (islo && !legacy) {
			bzero(&lifr.lifr_addr, sizeof (lifr.lifr_addr));
			lifr.lifr_addr.ss_family = af;
			if (ioctl(sock, SIOCSLIFADDR, (caddr_t)&lifr) < 0)
				return (ipadm_errno2status(errno));
			if (is_persistent) {
				status = i_ipadm_persist_if(iph,
				    ifname, af, ipadm_flags);
				if (status != IPADM_SUCCESS) {
					(void) i_ipadm_delete_if(iph, ifname,
					    af, IPADM_OPT_ACTIVE);
				}
			}
		}
		return (status);
	}

	dlpi_flags = DLPI_NOATTACH;

	/*
	 * If IPADM_OPT_IPMP is specified, then this is a request
	 * to create an IPMP interface atop /dev/ipmpstub0.  (We can't simply
	 * pass "ipmpstub0" as devname since an admin *could* have a normal
	 * vanity-named link named "ipmpstub0" that they'd like to plumb.)
	 */
	if (ipadm_flags & IPADM_OPT_IPMP) {
		dlpi_flags |= DLPI_DEVONLY;
		linkname = "ipmpstub0";
	} else {
		/*
		 * Verify that the user is not creating a persistent
		 * IP interface on a non-persistent data-link.
		 */
		if (!i_ipadm_is_vni(ifname) && dlstatus == DLADM_STATUS_OK &&
		    is_persistent && !(dlflags & DLADM_OPT_PERSIST)) {
				return (IPADM_TEMPORARY_OBJ);
		}
		linkname = ifname;
	}

	/*
	 * We use DLPI_NOATTACH because the ip module will do the attach
	 * itself for DLPI style-2 devices.
	 */
	if (dlpi_open(linkname, &dh_ip, dlpi_flags) != DLPI_SUCCESS)
		return (IPADM_DLPI_FAILURE);
	ip_fd = dlpi_fd(dh_ip);
	if (ioctl(ip_fd, I_PUSH, IP_MOD_NAME) == -1) {
		status = ipadm_errno2status(errno);
		goto done;
	}

	/*
	 * Set IFF_IPV4/IFF_IPV6 flags. The kernel only allows modifications
	 * to IFF_IPv4, IFF_IPV6, IFF_BROADCAST, IFF_XRESOLV, IFF_NOLINKLOCAL.
	 */
	ifflags = 0;

	/* Set the name string and the IFF_IPV* flag */
	if (af == AF_INET) {
		ifflags = IFF_IPV4;
	} else {
		ifflags = IFF_IPV6;
		/*
		 * With the legacy method, the link-local address should be
		 * configured as part of the interface plumb, using the default
		 * token. If IPH_LEGACY is not specified, we want to set :: as
		 * the address and require the admin to explicitly call
		 * ipadm_create_addr() with the address object type set to
		 * IPADM_ADDR_IPV6_ADDRCONF to create the link-local address
		 * as well as the autoconfigured addresses.
		 */
		if (!legacy && !i_ipadm_is_6to4(iph, ifname))
			ifflags |= IFF_NOLINKLOCAL;
	}
	(void) strlcpy(newif, ifname, sizeof (newif));
	status = i_ipadm_slifname(iph, ifname, newif, ifflags, ip_fd,
	    ipadm_flags);
	if (status != IPADM_SUCCESS)
		goto done;

	/* Get the full set of existing flags for this stream */
	status = i_ipadm_get_flags(iph, newif, af, &ifflags);
	if (status != IPADM_SUCCESS)
		goto done;

	udp_dev_name = (af == AF_INET6 ? UDP6_DEV_NAME : UDP_DEV_NAME);
	status = ipadm_open_arp_on_udp(udp_dev_name, &mux_fd);
	if (status != IPADM_SUCCESS)
		goto done;

	/* Check if arp is not needed */
	if (ifflags & (IFF_NOARP|IFF_IPV6)) {
		/*
		 * PLINK the interface stream so that the application can exit
		 * without tearing down the stream.
		 */
		if ((ip_muxid = ioctl(mux_fd, I_PLINK, ip_fd)) == -1)
			status = ipadm_errno2status(errno);
		goto done;
	}

	/*
	 * This interface does use ARP, so set up a separate stream
	 * from the interface to ARP.
	 *
	 * We use DLPI_NOATTACH because the arp module will do the attach
	 * itself for DLPI style-2 devices.
	 */
	if (dlpi_open(linkname, &dh_arp, dlpi_flags) != DLPI_SUCCESS) {
		status = IPADM_DLPI_FAILURE;
		goto done;
	}

	arp_fd = dlpi_fd(dh_arp);
	if (ioctl(arp_fd, I_PUSH, ARP_MOD_NAME) == -1) {
		status = ipadm_errno2status(errno);
		goto done;
	}

	status = i_ipadm_slifname_arp(newif, ifflags, arp_fd);
	if (status != IPADM_SUCCESS)
		goto done;
	/*
	 * PLINK the IP and ARP streams so that ifconfig can exit
	 * without tearing down the stream.
	 */
	if ((ip_muxid = ioctl(mux_fd, I_PLINK, ip_fd)) == -1) {
		status = ipadm_errno2status(errno);
		goto done;
	}

	if (ioctl(mux_fd, I_PLINK, arp_fd) < 0) {
		status = ipadm_errno2status(errno);
		(void) ioctl(mux_fd, I_PUNLINK, ip_muxid);
	}

done:
	dlpi_close(dh_ip);
	if (dh_arp != NULL)
		dlpi_close(dh_arp);

	if (mux_fd != -1)
		(void) close(mux_fd);

	if (status == IPADM_SUCCESS) {
		/* copy back new ifname */
		(void) strlcpy(ifname, newif, LIFNAMSIZ);
		/*
		 * If it is a 6to4 tunnel, create a default
		 * addrobj name for the default address on the 0'th
		 * logical interface and set IFF_UP in the interface flags.
		 */
		if (i_ipadm_is_6to4(iph, ifname)) {
			struct ipadm_addrobj_s addr;

			i_ipadm_init_addr(&addr, ifname, "", IPADM_ADDR_STATIC);
			addr.ipadm_af = af;
			status = i_ipadm_lookupadd_addrobj(iph, &addr);
			if (status != IPADM_SUCCESS)
				return (status);
			status = ipadm_add_aobjname(iph, ifname,
			    af, addr.ipadm_aobjname, IPADM_ADDR_STATIC, 0);
			if (status != IPADM_SUCCESS)
				return (status);
			addr.ipadm_lifnum = 0;
			i_ipadm_addrobj2lifname(&addr, lifname,
			    sizeof (lifname));
			status = i_ipadm_set_flags(iph, lifname, af,
			    IFF_UP, 0);
			if (status != IPADM_SUCCESS)
				return (status);
		} else {
			/*
			 * Prevent static IPv6 addresses from triggering
			 * autoconf. This does not have to be done for
			 * 6to4 tunnel interfaces, since in.ndpd will
			 * not autoconfigure those interfaces.
			 */
			if (af == AF_INET6 && !legacy)
				(void) i_ipadm_disable_autoconf(newif);
		}

		/*
		 * If IPADM_OPT_PERSIST was set in flags, store the
		 * interface in persistent DB.
		 */
		if (is_persistent) {
			status = i_ipadm_persist_if(iph,
			    newif, af, ipadm_flags);
			if (status != IPADM_SUCCESS) {
				(void) i_ipadm_delete_if(iph, newif, af,
				    IPADM_OPT_ACTIVE);
			}
		}
	}
	if (status == IPADM_EXISTS)
		status = IPADM_IF_EXISTS;
	return (status);
}

/*
 * Unplumbs the interface in `ifname' of family `af'.
 */
ipadm_status_t
i_ipadm_unplumb_if(ipadm_handle_t iph, const char *ifname, sa_family_t af)
{
	int		ip_muxid, arp_muxid;
	int		mux_fd = -1;
	int		muxid_fd = -1;
	char		*udp_dev_name;
	uint64_t	flags;
	boolean_t	changed_arp_muxid = B_FALSE;
	int		save_errno;
	struct lifreq	lifr;
	ipadm_status_t	ret = IPADM_SUCCESS;
	int		sock;
	lifgroupinfo_t	lifgr;
	ifaddrlistx_t	*ifaddrs, *ifaddrp;
	boolean_t	v6 = (af == AF_INET6);

	/* Just do SIOCLIFREMOVEIF on loopback interfaces */
	bzero(&lifr, sizeof (lifr));
	if (i_ipadm_is_loopback(ifname) ||
	    (i_ipadm_get_lnum(ifname) != 0 && (iph->iph_flags & IPH_LEGACY))) {
		(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
		if (ioctl((af == AF_INET) ? iph->iph_sock : iph->iph_sock6,
		    SIOCLIFREMOVEIF, (caddr_t)&lifr) < 0) {
			return (ipadm_errno2status(errno));
		}
		return (IPADM_SUCCESS);
	}

	/*
	 * We used /dev/udp or udp6 to set up the mux. So we have to use
	 * the same now for PUNLINK also.
	 */
	if (v6) {
		udp_dev_name = UDP6_DEV_NAME;
		sock = iph->iph_sock6;
	} else {
		udp_dev_name = UDP_DEV_NAME;
		sock = iph->iph_sock;
	}
	if ((muxid_fd = open(udp_dev_name, O_RDWR)) == -1) {
		ret = ipadm_errno2status(errno);
		goto done;
	}
	ret = ipadm_open_arp_on_udp(udp_dev_name, &mux_fd);
	if (ret != IPADM_SUCCESS)
		goto done;
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (ioctl(muxid_fd, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		ret = ipadm_errno2status(errno);
		goto done;
	}
	flags = lifr.lifr_flags;
again:
	if (flags & IFF_IPMP) {
		/*
		 * There are two reasons the I_PUNLINK can fail with EBUSY:
		 * (1) if IP interfaces are in the group, or (2) if IPMP data
		 * addresses are administratively up.  For case (1), we fail
		 * here with a specific error message.  For case (2), we bring
		 * down the addresses prior to doing the I_PUNLINK.  If the
		 * I_PUNLINK still fails with EBUSY then the configuration
		 * must have changed after our checks, in which case we branch
		 * back up to `again' and rerun this logic.  The net effect is
		 * that unplumbing an IPMP interface will only fail with EBUSY
		 * if IP interfaces are in the group.
		 */
		if (ioctl(sock, SIOCGLIFGROUPNAME, &lifr) == -1) {
			ret = ipadm_errno2status(errno);
			goto done;
		}
		(void) strlcpy(lifgr.gi_grname, lifr.lifr_groupname,
		    LIFGRNAMSIZ);
		if (ioctl(sock, SIOCGLIFGROUPINFO, &lifgr) == -1) {
			ret = ipadm_errno2status(errno);
			goto done;
		}
		if ((v6 && lifgr.gi_nv6 != 0) || (!v6 && lifgr.gi_nv4 != 0)) {
			ret = IPADM_GRP_NOTEMPTY;
			goto done;
		}

		/*
		 * The kernel will fail the I_PUNLINK if the IPMP interface
		 * has administratively up addresses; bring them down.
		 */
		if (ifaddrlistx(ifname, IFF_UP|IFF_DUPLICATE,
		    0, &ifaddrs) == -1) {
			ret = ipadm_errno2status(errno);
			goto done;
		}
		ifaddrp = ifaddrs;
		for (; ifaddrp != NULL; ifaddrp = ifaddrp->ia_next) {
			int sock = (ifaddrp->ia_flags & IFF_IPV4) ?
			    iph->iph_sock : iph->iph_sock6;
			struct lifreq lifrl;

			if (((ifaddrp->ia_flags & IFF_IPV6) && !v6) ||
			    (!(ifaddrp->ia_flags & IFF_IPV6) && v6))
				continue;

			bzero(&lifrl, sizeof (lifrl));
			(void) strlcpy(lifrl.lifr_name, ifaddrp->ia_name,
			    sizeof (lifrl.lifr_name));
			if (ioctl(sock, SIOCGLIFFLAGS, &lifrl) < 0) {
				ret = ipadm_errno2status(errno);
				ifaddrlistx_free(ifaddrs);
				goto done;
			}
			if (lifrl.lifr_flags & IFF_UP) {
				ret = i_ipadm_set_flags(iph, lifrl.lifr_name,
				    ((lifrl.lifr_flags & IFF_IPV4) ? AF_INET :
				    AF_INET6), 0, IFF_UP);
				if (ret != IPADM_SUCCESS) {
					ifaddrlistx_free(ifaddrs);
					goto done;
				}
			} else if (lifrl.lifr_flags & IFF_DUPLICATE) {
				if (ioctl(sock, SIOCGLIFADDR, &lifrl) < 0 ||
				    ioctl(sock, SIOCSLIFADDR, &lifrl) < 0) {
					ret = ipadm_errno2status(errno);
					ifaddrlistx_free(ifaddrs);
					goto done;
				}
			}
		}
		ifaddrlistx_free(ifaddrs);
	}

	if (ioctl(muxid_fd, SIOCGLIFMUXID, (caddr_t)&lifr) < 0) {
		ret = ipadm_errno2status(errno);
		goto done;
	}
	arp_muxid = lifr.lifr_arp_muxid;
	ip_muxid = lifr.lifr_ip_muxid;

	/*
	 * We don't have a good way of knowing whether the arp stream is
	 * plumbed. We can't rely on IFF_NOARP because someone could
	 * have turned it off later using "ifconfig xxx -arp".
	 */
	if (arp_muxid != 0) {
		if (ioctl(mux_fd, I_PUNLINK, arp_muxid) < 0) {
			/*
			 * See the comment before the SIOCGLIFGROUPNAME call.
			 */
			if (errno == EBUSY && (flags & IFF_IPMP))
				goto again;

			if ((errno == EINVAL) &&
			    (flags & (IFF_NOARP | IFF_IPV6))) {
				/*
				 * Some plumbing utilities set the muxid to
				 * -1 or some invalid value to signify that
				 * there is no arp stream. Set the muxid to 0
				 * before trying to unplumb the IP stream.
				 * IP does not allow the IP stream to be
				 * unplumbed if it sees a non-null arp muxid,
				 * for consistency of IP-ARP streams.
				 */
				lifr.lifr_arp_muxid = 0;
				(void) ioctl(muxid_fd, SIOCSLIFMUXID,
				    (caddr_t)&lifr);
				changed_arp_muxid = B_TRUE;
			}
			/*
			 * In case of any other error, we continue with
			 * the unplumb.
			 */
		}
	}

	if (ioctl(mux_fd, I_PUNLINK, ip_muxid) < 0) {
		if (changed_arp_muxid) {
			/*
			 * Some error occurred, and we need to restore
			 * everything back to what it was.
			 */
			save_errno = errno;
			lifr.lifr_arp_muxid = arp_muxid;
			lifr.lifr_ip_muxid = ip_muxid;
			(void) ioctl(muxid_fd, SIOCSLIFMUXID, (caddr_t)&lifr);
			errno = save_errno;
		}
		/*
		 * See the comment before the SIOCGLIFGROUPNAME call.
		 */
		if (errno == EBUSY && (flags & IFF_IPMP))
			goto again;

		ret = ipadm_errno2status(errno);
	}
done:
	if (muxid_fd != -1)
		(void) close(muxid_fd);
	if (mux_fd != -1)
		(void) close(mux_fd);

	if (af == AF_INET6 && ret == IPADM_SUCCESS) {
		/*
		 * in.ndpd maintains the phyints in its memory even after
		 * the interface is plumbed, so that it can be reused when
		 * the interface gets plumbed again. The default behavior
		 * of in.ndpd is to start autoconfiguration for an interface
		 * that gets plumbed. We need to send the
		 * message IPADM_ENABLE_AUTOCONF to in.ndpd to restore this
		 * default behavior on replumb.
		 */
		(void) i_ipadm_enable_autoconf(ifname);
	}
	return (ret);
}

/*
 * Saves the given interface name `ifname' with address family `af' in
 * persistent DB.
 */
static ipadm_status_t
i_ipadm_persist_if(ipadm_handle_t iph, const char *ifname, sa_family_t af,
    uint32_t ipadm_flags)
{
	ipmgmt_if_arg_t		ifarg;
	int			err;

	(void) strlcpy(ifarg.ia_ifname, ifname, sizeof (ifarg.ia_ifname));
	ifarg.ia_family = af;
	if (ipadm_flags & IPADM_OPT_IPMP)
		ifarg.ia_ifclass = IPADM_IF_CLASS_IPMP;
	else
		ifarg.ia_ifclass = IPADM_IF_CLASS_REGULAR;

	ifarg.ia_cmd = IPMGMT_CMD_SETIF;
	ifarg.ia_flags = IPMGMT_PERSIST;
	err = ipadm_door_call(iph, &ifarg, sizeof (ifarg), NULL, 0, B_FALSE);
	return (ipadm_errno2status(err));
}

/*
 * Remove the IP interface from active configuration. If IPADM_OPT_PERSIST
 * is set in `ipadm_flags', it is also removed from persistent configuration.
 */
ipadm_status_t
i_ipadm_delete_if(ipadm_handle_t iph, const char *ifname, sa_family_t af,
    uint32_t ipadm_flags)
{
	ipadm_status_t		ret = IPADM_SUCCESS;
	ipadm_status_t		db_status;
	char			tmp_ifname[LIFNAMSIZ];
	char			*cp;
	struct ipadm_addrobj_s	ipaddr;
	boolean_t		is_persistent =
	    (ipadm_flags & IPADM_OPT_PERSIST);

	ret = i_ipadm_unplumb_if(iph, ifname, af);
	if (ret != IPADM_SUCCESS)
		goto done;

	cp = strrchr(ifname, IPADM_LOGICAL_SEP);
	if (cp != NULL) {
		assert(iph->iph_flags & IPH_LEGACY);
		/*
		 * This is a non-zero logical interface.
		 * Find the addrobj and remove it from the daemon's memory.
		 */
		(void) strlcpy(tmp_ifname, ifname, sizeof (tmp_ifname));
		tmp_ifname[cp - ifname] = '\0';
		*cp++ = '\0';
		ipaddr.ipadm_lifnum = atoi(cp);
		(void) strlcpy(ipaddr.ipadm_ifname, tmp_ifname,
		    sizeof (ipaddr.ipadm_ifname));
		ipaddr.ipadm_af = af;
		ret = i_ipadm_get_lif2addrobj(iph, &ipaddr);
		if (ret == IPADM_SUCCESS) {
			ret = i_ipadm_delete_addrobj(iph, &ipaddr,
			    IPADM_OPT_ACTIVE);
		} else if (ret == IPADM_NOTFOUND) {
			ret = IPADM_SUCCESS;
		}
		return (ret);
	}
done:
	/*
	 * Even if interface does not exist, remove all its addresses and
	 * properties from the persistent store. If interface does not
	 * exist both in kernel and the persistent store, return IPADM_ENXIO.
	 */
	if ((ret == IPADM_ENXIO && is_persistent) || ret == IPADM_SUCCESS) {
		db_status = i_ipadm_delete_ifobj(iph, ifname, af,
		    is_persistent);
		if (db_status == IPADM_SUCCESS)
			ret = IPADM_SUCCESS;
	}

	return (ret);
}

/*
 * Resets all addresses on interface `ifname' with address family `af'
 * from ipmgmtd daemon. If is_persistent = B_TRUE, all interface properties
 * and address objects of `ifname' for `af' are also removed from the
 * persistent DB.
 */
ipadm_status_t
i_ipadm_delete_ifobj(ipadm_handle_t iph, const char *ifname, sa_family_t af,
    boolean_t is_persistent)
{
	ipmgmt_if_arg_t		ifarg;
	int			err;

	ifarg.ia_cmd = IPMGMT_CMD_RESETIF;
	ifarg.ia_flags = IPMGMT_ACTIVE;
	if (is_persistent)
		ifarg.ia_flags |= IPMGMT_PERSIST;
	ifarg.ia_family = af;
	(void) strlcpy(ifarg.ia_ifname, ifname, LIFNAMSIZ);

	err = ipadm_door_call(iph, &ifarg, sizeof (ifarg), NULL, 0, B_FALSE);
	return (ipadm_errno2status(err));
}

/*
 * Create the interface by plumbing it for IP.
 * This function will check if there is saved configuration information
 * for `ifname' and return IPADM_OP_DISABLE_OBJ if the name-space
 * for `ifname' is taken.
 */
ipadm_status_t
i_ipadm_create_if(ipadm_handle_t iph, char *ifname, sa_family_t af,
    uint32_t ipadm_flags)
{
	ipadm_status_t	status;
	boolean_t	p_exists;
	sa_family_t	other_af;

	/*
	 * Return error, if the interface already exists in either the active
	 * or the persistent configuration.
	 */
	if (ipadm_if_enabled(iph, ifname, af))
		return (IPADM_IF_EXISTS);

	if (!(iph->iph_flags & IPH_LEGACY)) {
		status = i_ipadm_if_pexists(iph, ifname, af, &p_exists);
		if (status != IPADM_SUCCESS)
			return (status);
		other_af = (af == AF_INET ? AF_INET6 : AF_INET);
		if (p_exists) {
			if (!ipadm_if_enabled(iph, ifname, other_af))
				return (IPADM_OP_DISABLE_OBJ);
			else
				ipadm_flags &= ~IPADM_OPT_PERSIST;
		}
	}

	return (i_ipadm_plumb_if(iph, ifname, af, ipadm_flags));
}

/*
 * Plumbs an interface. Creates both IPv4 and IPv6 interfaces by
 * default, unless a value in `af' is specified. The interface may be plumbed
 * only if there is no previously saved persistent configuration information
 * for the interface (in which case the ipadm_enable_if() function must
 * be used to enable the interface).
 *
 * Returns: IPADM_SUCCESS, IPADM_FAILURE, IPADM_IF_EXISTS,
 * IPADM_IF_PERSIST_EXISTS, IPADM_DLPI_FAILURE,
 * or appropriate ipadm_status_t corresponding to the errno.
 *
 * `ifname' must point to memory that can hold upto LIFNAMSIZ chars. It may
 * be over-written with the actual interface name when a PPA has to be
 * internally generated by the library.
 */
ipadm_status_t
ipadm_create_if(ipadm_handle_t iph, char *ifname, sa_family_t af,
    uint32_t flags)
{
	ipadm_status_t	status;
	boolean_t	created_v4 = B_FALSE;
	char		newifname[LIFNAMSIZ];

	/* Check for the required authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);

	if (flags == 0 || ((flags & IPADM_OPT_PERSIST) &&
	    !(flags & IPADM_OPT_ACTIVE)) ||
	    (flags & ~(IPADM_COMMON_OPT_MASK | IPADM_OPT_IPMP |
	    IPADM_OPT_GENPPA))) {
		return (IPADM_INVALID_ARG);
	}
	if (flags & IPADM_OPT_GENPPA) {
		if (snprintf(newifname, LIFNAMSIZ, "%s0", ifname) >=
		    LIFNAMSIZ)
			return (IPADM_INVALID_ARG);
	} else {
		if (strlcpy(newifname, ifname, LIFNAMSIZ) >= LIFNAMSIZ)
			return (IPADM_INVALID_ARG);
	}

	if (!i_ipadm_validate_ifname(iph, newifname))
		return (IPADM_INVALID_ARG);

	if ((af == AF_INET || af == AF_UNSPEC) &&
	    !i_ipadm_is_6to4(iph, ifname)) {
		status = i_ipadm_create_if(iph, ifname, AF_INET, flags);
		if (status != IPADM_SUCCESS)
			return (status);
		created_v4 = B_TRUE;
	}
	if (af == AF_INET6 || af == AF_UNSPEC) {
		status = i_ipadm_create_if(iph, ifname, AF_INET6, flags);
		if (status != IPADM_SUCCESS) {
			if (created_v4) {
				(void) i_ipadm_delete_if(iph, ifname, AF_INET,
				    IPADM_OPT_ACTIVE);
			}
			return (status);
		}
	}

	return (IPADM_SUCCESS);
}

ipadm_status_t
ipadm_add_ipmp_member(ipadm_handle_t iph, const char *gifname,
    const char *mifname, uint32_t ipadm_flags)
{
	return (i_ipadm_update_ipmp(iph, gifname, mifname,
	    ipadm_flags, IPADM_ADD_IPMP));
}

ipadm_status_t
ipadm_remove_ipmp_member(ipadm_handle_t iph, const char *gifname,
    const char *mifname, uint32_t ipadm_flags)
{
	return (i_ipadm_update_ipmp(iph, gifname, mifname,
	    ipadm_flags, IPADM_REMOVE_IPMP));
}

/*
 * Updates active IPMP configuration according to the specified
 * command. It also persists the configuration if IPADM_OPT_PERSIST
 * is set in `ipadm_flags'.
 */
static ipadm_status_t
i_ipadm_update_ipmp(ipadm_handle_t iph, const char *gifname,
    const char *mifname, uint32_t ipadm_flags, ipadm_ipmp_op_t op)
{
	ipadm_status_t status;
	char	groupname1[LIFGRNAMSIZ];
	char	groupname2[LIFGRNAMSIZ];

	/* Check for the required authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);

	if (!(ipadm_flags & IPADM_OPT_ACTIVE) ||
	    gifname == NULL || mifname == NULL)
		return (IPADM_INVALID_ARG);

	if (!ipadm_if_enabled(iph, gifname, AF_UNSPEC) ||
	    !ipadm_if_enabled(iph, mifname, AF_UNSPEC))
		return (IPADM_OP_DISABLE_OBJ);

	if (!i_ipadm_is_ipmp(iph, gifname))
		return (IPADM_INVALID_ARG);

	if (op == IPADM_ADD_IPMP && i_ipadm_is_under_ipmp(iph, mifname))
		return (IPADM_IF_INUSE);

	if ((status = i_ipadm_get_groupname_active(iph, gifname,
	    groupname2, sizeof (groupname2))) != IPADM_SUCCESS)
		return (status);

	if (op == IPADM_REMOVE_IPMP) {
		if ((status = i_ipadm_get_groupname_active(iph, mifname,
		    groupname1, sizeof (groupname1))) != IPADM_SUCCESS)
			return (status);

		if (groupname1[0] == '\0' ||
		    strcmp(groupname1, groupname2) != 0)
			return (IPADM_INVALID_ARG);

		groupname2[0] = '\0';
	}

	if ((ipadm_flags & IPADM_OPT_PERSIST) &&
	    (status = i_ipadm_persist_update_ipmp(iph, gifname,
	    mifname, op)) != IPADM_SUCCESS)
		return (status);

	return (i_ipadm_set_groupname_active(iph, mifname, groupname2));
}

/*
 * Call the ipmgmtd to update the IPMP configuration in ipadm DB.
 * After this call the DB will know that mifname is under gifname and
 * gifname has a member, which name is mifname.
 */
static ipadm_status_t
i_ipadm_persist_update_ipmp(ipadm_handle_t iph, const char *gifname,
    const char *mifname, ipadm_ipmp_op_t op)
{
	ipmgmt_ipmp_update_arg_t args;
	int err;

	assert(op == IPADM_ADD_IPMP || op == IPADM_REMOVE_IPMP);

	bzero(&args, sizeof (ipmgmt_ipmp_update_arg_t));

	args.ia_cmd = IPMGMT_CMD_IPMP_UPDATE;

	(void) strlcpy(args.ia_gifname, gifname, sizeof (args.ia_gifname));
	(void) strlcpy(args.ia_mifname, mifname, sizeof (args.ia_mifname));

	if (op == IPADM_ADD_IPMP)
		args.ia_flags = IPMGMT_APPEND;
	else
		args.ia_flags = IPMGMT_REMOVE;

	args.ia_flags |= IPMGMT_PERSIST;

	err = ipadm_door_call(iph, &args, sizeof (args), NULL, 0, B_FALSE);
	return (ipadm_errno2status(err));
}

/*
 * Deletes the interface in `ifname'. Removes both IPv4 and IPv6 interfaces
 * when `af' = AF_UNSPEC.
 */
ipadm_status_t
ipadm_delete_if(ipadm_handle_t iph, const char *ifname, sa_family_t af,
    uint32_t flags)
{
	ipadm_status_t status1 = IPADM_SUCCESS;
	ipadm_status_t status2 = IPADM_SUCCESS;
	ipadm_status_t other;

	/* Check for the required authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);

	/* Validate the `ifname' for any logical interface. */
	if (flags == 0 || (flags & ~(IPADM_COMMON_OPT_MASK)) ||
	    !i_ipadm_validate_ifname(iph, ifname))
		return (IPADM_INVALID_ARG);

	if (af == AF_INET || af == AF_UNSPEC)
		status1 = i_ipadm_delete_if(iph, ifname, AF_INET, flags);
	if (af == AF_INET6 || af == AF_UNSPEC)
		status2 = i_ipadm_delete_if(iph, ifname, AF_INET6, flags);
	/*
	 * If the family has been uniquely identified, we return the
	 * associated status, even if that is ENXIO. Calls from ifconfig
	 * which can only unplumb one of IPv4/IPv6 at any time fall under
	 * this category.
	 */
	if (af == AF_INET)
		return (status1);
	else if (af == AF_INET6)
		return (status2);
	else if (af != AF_UNSPEC)
		return (IPADM_INVALID_ARG);

	/*
	 * If af is AF_UNSPEC, then we return the following:
	 * status1,		if status1 == status2
	 * IPADM_SUCCESS,	if either of status1 or status2 is SUCCESS
	 *			and the other status is ENXIO
	 * IPADM_ENXIO,		if both status1 and status2 are ENXIO
	 * IPADM_FAILURE	otherwise.
	 */
	if (status1 == status2) {
		/* covers the case when both status1 and status2 are ENXIO */
		return (status1);
	} else if (status1 == IPADM_SUCCESS || status2 == IPADM_SUCCESS) {
		if (status1 == IPADM_SUCCESS)
			other = status2;
		else
			other = status1;
		return (other == IPADM_ENXIO ? IPADM_SUCCESS : IPADM_FAILURE);
	} else {
		return (IPADM_FAILURE);
	}
}

/*
 * Returns information about all interfaces in both active and persistent
 * configuration. If `ifname' is not NULL, it returns only the interface
 * identified by `ifname'.
 *
 * Return values:
 *	On success: IPADM_SUCCESS.
 *	On error  : IPADM_INVALID_ARG, IPADM_ENXIO or IPADM_FAILURE.
 */
ipadm_status_t
ipadm_if_info(ipadm_handle_t iph, const char *ifname,
    ipadm_if_info_t **if_info, uint32_t flags, int64_t lifc_flags)
{
	ipadm_status_t	status;
	ifspec_t	ifsp;

	if (if_info == NULL || iph == NULL || flags != 0)
		return (IPADM_INVALID_ARG);

	if (ifname != NULL &&
	    (!ifparse_ifspec(ifname, &ifsp) || ifsp.ifsp_lunvalid)) {
		return (IPADM_INVALID_ARG);
	}

	status = i_ipadm_get_all_if_info(iph, ifname, if_info, lifc_flags);
	if (status != IPADM_SUCCESS)
		return (status);
	if (ifname != NULL && *if_info == NULL)
		return (IPADM_ENXIO);

	return (IPADM_SUCCESS);
}

/*
 * Frees the linked list allocated by ipadm_if_info().
 */
void
ipadm_free_if_info(ipadm_if_info_t *ifinfo)
{
	ipadm_if_info_t	*ifinfo_next;

	for (; ifinfo != NULL; ifinfo = ifinfo_next) {
		ifinfo_next = ifinfo->ifi_next;
		i_ipadm_free_ipmp_members(&ifinfo->ifi_ipmp_cmembers);
		i_ipadm_free_ipmp_members(&ifinfo->ifi_ipmp_pmembers);
		free(ifinfo);
	}
}

static void
i_ipadm_free_ipmp_members(ipadm_ipmp_members_t *ipmp_members)
{
	ipadm_ipmp_member_t *ipmp_member;

	while ((ipmp_member = list_remove_head(ipmp_members)) != NULL)
		free(ipmp_member);

	list_destroy(ipmp_members);
}

/*
 * Re-enable the interface `ifname' based on the saved configuration
 * for `ifname'.
 */
ipadm_status_t
ipadm_enable_if(ipadm_handle_t iph, const char *ifname, uint32_t flags)
{
	boolean_t	set_init = B_FALSE;
	nvlist_t	*ifnvl;
	ipadm_status_t	status;
	ifspec_t	ifsp;

	/* Check for the required authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);

	/* Check for logical interfaces. */
	if (!ifparse_ifspec(ifname, &ifsp) || ifsp.ifsp_lunvalid)
		return (IPADM_INVALID_ARG);

	/* Enabling an interface persistently is not supported. */
	if (flags & IPADM_OPT_PERSIST)
		return (IPADM_NOTSUP);

	/*
	 * Return early by checking if the interface is already enabled.
	 */
	if (ipadm_if_enabled(iph, ifname, AF_INET) &&
	    ipadm_if_enabled(iph, ifname, AF_INET6))
		return (IPADM_IF_EXISTS);

	/*
	 * Enable the interface and restore all its interface properties
	 * and address objects.
	 */
	status = i_ipadm_init_ifs(iph, ifname, &ifnvl);
	if (status != IPADM_SUCCESS)
		return (status);

	assert(ifnvl != NULL);
	/*
	 * ipadm_enable_if() does exactly what ipadm_init_ifs() does,
	 * but only for one interface. We need to set IPH_INIT because
	 * ipmgmtd daemon does not have to write the interface to the
	 * persistent db. The interface is already available in the
	 * persistent db and we are here to re-enable the persistent
	 * configuration.
	 *
	 * But we need to make sure we're not accidentally clearing an
	 * IPH_INIT flag that was already set when we were called.
	 */
	if ((iph->iph_flags & IPH_INIT) == 0) {
		iph->iph_flags |= IPH_INIT;
		set_init = B_TRUE;
	}

	status = i_ipadm_init_ifobj(iph, ifname, ifnvl);

	if (set_init)
		iph->iph_flags &= ~IPH_INIT;

	nvlist_free(ifnvl);
	return (status);
}

/*
 * Disable the interface `ifname' by removing it from the active configuration.
 * Error code return values follow the model in ipadm_delete_if()
 */
ipadm_status_t
ipadm_disable_if(ipadm_handle_t iph, const char *ifname, uint32_t flags)
{
	ipadm_status_t	status1, status2, other;
	ifspec_t	ifsp;

	/* Check for the required authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);

	/* Check for logical interfaces. */
	if (!ifparse_ifspec(ifname, &ifsp) || ifsp.ifsp_lunvalid)
		return (IPADM_INVALID_ARG);

	/* Disabling an interface persistently is not supported. */
	if (flags & IPADM_OPT_PERSIST)
		return (IPADM_NOTSUP);

	status1 = i_ipadm_unplumb_if(iph, ifname, AF_INET6);
	if (status1 == IPADM_SUCCESS)
		status1 = i_ipadm_delete_ifobj(iph, ifname, AF_INET6, B_FALSE);
	status2 = i_ipadm_unplumb_if(iph, ifname, AF_INET);
	if (status2 == IPADM_SUCCESS)
		status2 = i_ipadm_delete_ifobj(iph, ifname, AF_INET, B_FALSE);
	if (status1 == status2) {
		return (status2);
	} else if (status1 == IPADM_SUCCESS || status2 == IPADM_SUCCESS) {
		if (status1 == IPADM_SUCCESS)
			other = status2;
		else
			other = status1;
		return (other == IPADM_ENXIO ? IPADM_SUCCESS : IPADM_FAILURE);
	} else {
		return (IPADM_FAILURE);
	}
}

/*
 * FIXME Remove this when ifconfig(1M) is updated to use IPMP support
 * in libipadm.
 */
/*
 * This workaround is required by ifconfig(1M) whenever an
 * interface is moved into an IPMP group to update the daemon's
 * in-memory mapping of `aobjname' to 'lifnum'.
 *
 * For `IPMGMT_ACTIVE' case, i_ipadm_delete_ifobj() would only fail if
 * door_call(3C) fails. Also, there is no use in returning error because
 * `ifname' would have been successfuly moved into IPMP group, by this time.
 */
void
ipadm_if_move(ipadm_handle_t iph, const char *ifname)
{
	(void) i_ipadm_delete_ifobj(iph, ifname, AF_INET, B_FALSE);
	(void) i_ipadm_delete_ifobj(iph, ifname, AF_INET6, B_FALSE);
}

ipadm_status_t
i_ipadm_set_groupname_active(ipadm_handle_t iph, const char *ifname,
    const char *groupname)
{
	struct lifreq   lifr;
	ipadm_addr_info_t *addrinfo, *ia;
	ipadm_status_t	status = IPADM_SUCCESS;

	(void) memset(&lifr, 0, sizeof (lifr));

	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	(void) strlcpy(lifr.lifr_groupname, groupname,
	    sizeof (lifr.lifr_groupname));

	/* Disable all addresses on the interface */
	(void) i_ipadm_active_addr_info(iph, ifname, &addrinfo,
	    IPADM_OPT_ACTIVE | IPADM_OPT_ZEROADDR, IFF_UP | IFF_DUPLICATE);

	for (ia = addrinfo; ia != NULL; ia = IA_NEXT(ia)) {
		if (strlen(ia->ia_aobjname) > 0) {
			(void) ipadm_disable_addr(iph, ia->ia_aobjname, 0);
		} else {
			/*
			 * There's an address on this interfaces with no
			 * corresponding addrobj. Just clear IFF_UP.
			 */
			(void) i_ipadm_set_flags(iph, ifname,
			    addrinfo->ia_ifa.ifa_addr->sa_family, 0, IFF_UP);
		}
	}

	if (ioctl(iph->iph_sock, SIOCSLIFGROUPNAME, (caddr_t)&lifr) == -1 &&
	    ioctl(iph->iph_sock6, SIOCSLIFGROUPNAME, (caddr_t)&lifr) == -1)
		status = ipadm_errno2status(errno);

	/* Enable all addresses on the interface */
	for (ia = addrinfo; ia != NULL; ia = IA_NEXT(ia)) {
		if (strlen(ia->ia_aobjname) > 0) {
			(void) ipadm_enable_addr(iph, ia->ia_aobjname, 0);
		} else {
			/*
			 * There's an address on this interfaces with no
			 * corresponding addrobj. Just set IFF_UP.
			 */
			(void) i_ipadm_set_flags(iph, ifname,
			    addrinfo->ia_ifa.ifa_addr->sa_family, IFF_UP, 0);
		}
	}

	if (status == IPADM_SUCCESS) {
		if (groupname[0] == '\0') {
			/*
			 * If interface was removed from IPMP group, unset the
			 * DEPRECATED and NOFAILOVER flags.
			 */
			(void) i_ipadm_set_flags(iph, ifname, AF_INET, 0,
			    IFF_DEPRECATED | IFF_NOFAILOVER);
			(void) i_ipadm_set_flags(iph, ifname, AF_INET6, 0,
			    IFF_DEPRECATED | IFF_NOFAILOVER);
		} else if (addrinfo == NULL) {
			/*
			 * If interface was added to IPMP group and there are no
			 * active addresses, explicitly bring it up to be used
			 * for link-based IPMP configuration.
			 */
			(void) i_ipadm_set_flags(iph, ifname, AF_INET,
			    IFF_UP, 0);
			(void) i_ipadm_set_flags(iph, ifname, AF_INET6,
			    IFF_UP, 0);
		}
	}

	ipadm_free_addr_info(addrinfo);

	return (status);
}

ipadm_status_t
i_ipadm_get_groupname_active(ipadm_handle_t iph, const char *ifname,
    char *groupname, size_t size)
{
	struct lifreq   lifr;

	(void) memset(&lifr, 0, sizeof (lifr));

	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));

	if (ioctl(iph->iph_sock, SIOCGLIFGROUPNAME, (caddr_t)&lifr) == -1 &&
	    ioctl(iph->iph_sock6, SIOCGLIFGROUPNAME, (caddr_t)&lifr) == -1)
		return (ipadm_errno2status(errno));

	(void) strlcpy(groupname, lifr.lifr_groupname, size);

	return (IPADM_SUCCESS);
}

/*
 * Returns B_TRUE if `ifname' represents an IPMP underlying interface.
 */
boolean_t
i_ipadm_is_under_ipmp(ipadm_handle_t iph, const char *ifname)
{

	char	groupname[LIFGRNAMSIZ];

	if (i_ipadm_get_groupname_active(iph, ifname, groupname,
	    sizeof (groupname)) != IPADM_SUCCESS ||
	    groupname[0] == '\0' ||
	    strcmp(ifname, groupname) == 0)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Returns B_TRUE if `ifname' represents an IPMP group interface.
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
