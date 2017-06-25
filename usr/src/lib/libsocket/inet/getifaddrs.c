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
 * Copyright 2017 Sebastian Wiedenroth. All rights reserved.
 */

#include <netdb.h>
#include <nss_dbdefs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <sys/sockio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <net/if.h>
#include <door.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/dld_ioc.h>
#include <sys/dld.h>
#include <sys/dls_mgmt.h>
#include <sys/mac.h>
#include <sys/dlpi.h>
#include <net/if_types.h>
#include <ifaddrs.h>
#include <libsocket_priv.h>

/*
 * Create a linked list of `struct ifaddrs' structures, one for each
 * address that is UP. If successful, store the list in *ifap and
 * return 0.  On errors, return -1 and set `errno'.
 *
 * The storage returned in *ifap is allocated dynamically and can
 * only be properly freed by passing it to `freeifaddrs'.
 */
int
getifaddrs(struct ifaddrs **ifap)
{
	int		err;
	char		*cp;
	struct ifaddrs	*curr;

	if (ifap == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*ifap = NULL;
	err = getallifaddrs(AF_UNSPEC, ifap, LIFC_ENABLED);
	if (err == 0) {
		for (curr = *ifap; curr != NULL; curr = curr->ifa_next) {
			if ((cp = strchr(curr->ifa_name, ':')) != NULL)
				*cp = '\0';
		}
	}
	return (err);
}

void
freeifaddrs(struct ifaddrs *ifa)
{
	struct ifaddrs *curr;

	while (ifa != NULL) {
		curr = ifa;
		ifa = ifa->ifa_next;
		free(curr->ifa_name);
		free(curr->ifa_addr);
		free(curr->ifa_netmask);
		free(curr->ifa_dstaddr);
		free(curr->ifa_data);
		free(curr);
	}
}

static uint_t
dlpi_iftype(uint_t dlpitype)
{
	switch (dlpitype) {
	case DL_ETHER:
		return (IFT_ETHER);

	case DL_ATM:
		return (IFT_ATM);

	case DL_CSMACD:
		return (IFT_ISO88023);

	case DL_TPB:
		return (IFT_ISO88024);

	case DL_TPR:
		return (IFT_ISO88025);

	case DL_FDDI:
		return (IFT_FDDI);

	case DL_IB:
		return (IFT_IB);

	case DL_OTHER:
		return (IFT_OTHER);
	}

	return (IFT_OTHER);
}

/*
 * Make a door call to dlmgmtd.
 * If successful the result is stored in rbuf and 0 returned.
 * On errors, return -1 and set `errno'.
 */
static int
dl_door_call(int door_fd, void *arg, size_t asize, void *rbuf, size_t *rsizep)
{
	int err;
	door_arg_t	darg;
	darg.data_ptr	= arg;
	darg.data_size	= asize;
	darg.desc_ptr	= NULL;
	darg.desc_num	= 0;
	darg.rbuf	= rbuf;
	darg.rsize	= *rsizep;

	if (door_call(door_fd, &darg) == -1) {
		return (-1);
	}

	if (darg.rbuf != rbuf) {
		/*
		 * The size of the input rbuf was not big enough so that
		 * the door allocated the rbuf itself. In this case, return
		 * the required size to the caller.
		 */
		err = errno;
		(void) munmap(darg.rbuf, darg.rsize);
		*rsizep = darg.rsize;
		errno = err;
		return (-1);
	} else if (darg.rsize != *rsizep) {
		return (-1);
	}
	return (0);
}


/*
 * Get the name from dlmgmtd by linkid.
 * If successful the result is stored in name_retval and 0 returned.
 * On errors, return -1 and set `errno'.
 */
static int
dl_get_name(int door_fd, datalink_id_t linkid,
    dlmgmt_getname_retval_t *name_retval)
{
	size_t name_sz = sizeof (*name_retval);
	dlmgmt_door_getname_t getname;
	bzero(&getname, sizeof (dlmgmt_door_getname_t));
	getname.ld_cmd = DLMGMT_CMD_GETNAME;
	getname.ld_linkid = linkid;

	if (dl_door_call(door_fd, &getname, sizeof (getname), name_retval,
	    &name_sz) < 0) {
		return (-1);
	}
	if (name_retval->lr_err != 0) {
		errno = name_retval->lr_err;
		return (-1);
	}
	return (0);
}

/*
 * Get the next link from dlmgmtd.
 * Start iterating by passing DATALINK_INVALID_LINKID as linkid.
 * The end is marked by next_retval.lr_linkid set to DATALINK_INVALID_LINKID.
 * If successful the result is stored in next_retval and 0 returned.
 * On errors, return -1 and set `errno'.
 */
static int
dl_get_next(int door_fd, datalink_id_t linkid, datalink_class_t class,
    datalink_media_t dmedia, uint32_t flags,
    dlmgmt_getnext_retval_t *next_retval)
{
	size_t next_sz = sizeof (*next_retval);
	dlmgmt_door_getnext_t getnext;
	bzero(&getnext, sizeof (dlmgmt_door_getnext_t));
	getnext.ld_cmd = DLMGMT_CMD_GETNEXT;
	getnext.ld_class = class;
	getnext.ld_dmedia = dmedia;
	getnext.ld_flags = flags;
	getnext.ld_linkid = linkid;

	if (dl_door_call(door_fd, &getnext, sizeof (getnext), next_retval,
	    &next_sz) < 0) {
		return (-1);
	}
	if (next_retval->lr_err != 0) {
		errno = next_retval->lr_err;
		return (-1);
	}
	return (0);
}

/*
 * Returns all addresses configured on the system. If flags contain
 * LIFC_ENABLED, only the addresses that are UP are returned.
 * Address list that is returned by this function must be freed
 * using freeifaddrs().
 */
int
getallifaddrs(sa_family_t af, struct ifaddrs **ifap, int64_t flags)
{
	struct lifreq *buf = NULL;
	struct lifreq *lifrp;
	struct lifreq lifrl;
	int ret;
	int s, n, numifs;
	struct ifaddrs *curr, *prev;
	struct sockaddr_dl *ifa_addr = NULL;
	if_data_t *ifa_data = NULL;
	sa_family_t lifr_af;
	datalink_id_t linkid;
	dld_ioc_attr_t dia;
	dld_macaddrinfo_t *dmip;
	dld_ioc_macaddrget_t *iomp = NULL;
	dlmgmt_getnext_retval_t next_retval;
	dlmgmt_getname_retval_t	name_retval;
	int bufsize;
	int nmacaddr = 1024;
	int sock4 = -1;
	int sock6 = -1;
	int door_fd = -1;
	int dld_fd = -1;
	int err;

	if ((sock4 = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ||
	    (sock6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ||
	    (door_fd = open(DLMGMT_DOOR, O_RDONLY)) < 0 ||
	    (dld_fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		goto fail;

	bufsize = sizeof (dld_ioc_macaddrget_t) + nmacaddr *
	    sizeof (dld_macaddrinfo_t);
	if ((iomp = calloc(1, bufsize)) == NULL)
		goto fail;

retry:
	/* Get all interfaces from SIOCGLIFCONF */
	ret = getallifs(sock4, af, &buf, &numifs, (flags & ~LIFC_ENABLED));
	if (ret != 0)
		goto fail;

	/*
	 * Loop through the interfaces obtained from SIOCGLIFCOMF
	 * and retrieve the addresses, netmask and flags.
	 */
	prev = NULL;
	lifrp = buf;
	*ifap = NULL;
	for (n = 0; n < numifs; n++, lifrp++) {

		/* Prepare for the ioctl call */
		(void) strncpy(lifrl.lifr_name, lifrp->lifr_name,
		    sizeof (lifrl.lifr_name));
		lifr_af = lifrp->lifr_addr.ss_family;
		if (af != AF_UNSPEC && lifr_af != af)
			continue;

		s = (lifr_af == AF_INET ? sock4 : sock6);

		if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifrl) < 0)
			goto fail;
		if ((flags & LIFC_ENABLED) && !(lifrl.lifr_flags & IFF_UP))
			continue;

		/*
		 * Allocate the current list node. Each node contains data
		 * for one ifaddrs structure.
		 */
		curr = calloc(1, sizeof (struct ifaddrs));
		if (curr == NULL)
			goto fail;

		if (prev != NULL) {
			prev->ifa_next = curr;
		} else {
			/* First node in the linked list */
			*ifap = curr;
		}
		prev = curr;

		curr->ifa_flags = lifrl.lifr_flags;
		if ((curr->ifa_name = strdup(lifrp->lifr_name)) == NULL)
			goto fail;

		curr->ifa_addr = malloc(sizeof (struct sockaddr_storage));
		if (curr->ifa_addr == NULL)
			goto fail;
		(void) memcpy(curr->ifa_addr, &lifrp->lifr_addr,
		    sizeof (struct sockaddr_storage));

		/* Get the netmask */
		if (ioctl(s, SIOCGLIFNETMASK, (caddr_t)&lifrl) < 0)
			goto fail;
		curr->ifa_netmask = malloc(sizeof (struct sockaddr_storage));
		if (curr->ifa_netmask == NULL)
			goto fail;
		(void) memcpy(curr->ifa_netmask, &lifrl.lifr_addr,
		    sizeof (struct sockaddr_storage));

		/* Get the destination for a pt-pt interface */
		if (curr->ifa_flags & IFF_POINTOPOINT) {
			if (ioctl(s, SIOCGLIFDSTADDR, (caddr_t)&lifrl) < 0)
				goto fail;
			curr->ifa_dstaddr = malloc(
			    sizeof (struct sockaddr_storage));
			if (curr->ifa_dstaddr == NULL)
				goto fail;
			(void) memcpy(curr->ifa_dstaddr, &lifrl.lifr_addr,
			    sizeof (struct sockaddr_storage));
		} else if (curr->ifa_flags & IFF_BROADCAST) {
			if (ioctl(s, SIOCGLIFBRDADDR, (caddr_t)&lifrl) < 0)
				goto fail;
			curr->ifa_broadaddr = malloc(
			    sizeof (struct sockaddr_storage));
			if (curr->ifa_broadaddr == NULL)
				goto fail;
			(void) memcpy(curr->ifa_broadaddr, &lifrl.lifr_addr,
			    sizeof (struct sockaddr_storage));
		}

	}

	/* add AF_LINK entries */
	if (af == AF_UNSPEC || af == AF_LINK) {

		linkid = DATALINK_INVALID_LINKID;
		for (;;) {
			if (dl_get_next(door_fd, linkid, DATALINK_CLASS_ALL,
			    DATALINK_ANY_MEDIATYPE, DLMGMT_ACTIVE,
			    &next_retval) != 0) {
				break;
			}

			linkid = next_retval.lr_linkid;
			if (linkid == DATALINK_INVALID_LINKID)
				break;

			/* get mac addr */
			iomp->dig_size = nmacaddr * sizeof (dld_macaddrinfo_t);
			iomp->dig_linkid = linkid;

			if (ioctl(dld_fd, DLDIOC_MACADDRGET, iomp) < 0)
				continue;

			dmip = (dld_macaddrinfo_t *)(iomp + 1);

			/* get name */
			if (dl_get_name(door_fd, linkid, &name_retval) != 0)
				continue;

			/* get MTU */
			dia.dia_linkid = linkid;
			if (ioctl(dld_fd, DLDIOC_ATTR, &dia) < 0)
				continue;

			curr = calloc(1, sizeof (struct ifaddrs));
			if (curr == NULL)
				goto fail;

			curr->ifa_flags = prev->ifa_flags;
			prev->ifa_next = curr;
			prev = curr;

			if ((curr->ifa_name = strdup(name_retval.lr_link)) ==
			    NULL)
				goto fail;

			curr->ifa_addr =
			    calloc(1, sizeof (struct sockaddr_storage));
			if (curr->ifa_addr == NULL)
				goto fail;

			curr->ifa_data = calloc(1, sizeof (if_data_t));
			if (curr->ifa_data == NULL)
				goto fail;

			curr->ifa_addr->sa_family = AF_LINK;
			ifa_addr = (struct sockaddr_dl *)curr->ifa_addr;
			ifa_data = curr->ifa_data;

			(void) memcpy(ifa_addr->sdl_data, dmip->dmi_addr,
			    dmip->dmi_addrlen);
			ifa_addr->sdl_alen = dmip->dmi_addrlen;

			ifa_data->ifi_mtu = dia.dia_max_sdu;
			ifa_data->ifi_type = dlpi_iftype(next_retval.lr_media);

			/*
			 * get interface index
			 * This is only possible if the link has been plumbed.
			 */
			if (strlcpy(lifrl.lifr_name, name_retval.lr_link,
			    sizeof (lifrl.lifr_name)) >=
			    sizeof (lifrl.lifr_name))
				continue;

			if (ioctl(sock4, SIOCGLIFINDEX, (caddr_t)&lifrl) >= 0) {
				ifa_addr->sdl_index = lifrl.lifr_index;
			} else if (ioctl(sock6, SIOCGLIFINDEX,
			    (caddr_t)&lifrl) >= 0) {
				/* retry for IPv6 */
				ifa_addr->sdl_index = lifrl.lifr_index;
			}
		}
	}
	free(buf);
	free(iomp);
	(void) close(sock4);
	(void) close(sock6);
	(void) close(door_fd);
	(void) close(dld_fd);
	return (0);
fail:
	err = errno;
	free(buf);
	free(iomp);
	freeifaddrs(*ifap);
	*ifap = NULL;
	if (err == ENXIO)
		goto retry;

	if (sock4 != -1)
		(void) close(sock4);
	if (sock6 != -1)
		(void) close(sock6);
	if (door_fd != -1)
		(void) close(door_fd);
	if (dld_fd != -1)
		(void) close(dld_fd);
	errno = err;
	return (-1);
}

/*
 * Do a SIOCGLIFCONF and store all the interfaces in `buf'.
 */
int
getallifs(int s, sa_family_t af, struct lifreq **lifr, int *numifs,
    int64_t lifc_flags)
{
	struct lifnum lifn;
	struct lifconf lifc;
	size_t bufsize;
	char *tmp;
	caddr_t *buf = (caddr_t *)lifr;

	lifn.lifn_family = af;
	lifn.lifn_flags = lifc_flags;

	*buf = NULL;
retry:
	if (ioctl(s, SIOCGLIFNUM, &lifn) < 0)
		goto fail;

	/*
	 * When calculating the buffer size needed, add a small number
	 * of interfaces to those we counted.  We do this to capture
	 * the interface status of potential interfaces which may have
	 * been plumbed between the SIOCGLIFNUM and the SIOCGLIFCONF.
	 */
	bufsize = (lifn.lifn_count + 4) * sizeof (struct lifreq);

	if ((tmp = realloc(*buf, bufsize)) == NULL)
		goto fail;

	*buf = tmp;
	lifc.lifc_family = af;
	lifc.lifc_flags = lifc_flags;
	lifc.lifc_len = bufsize;
	lifc.lifc_buf = *buf;
	if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) < 0)
		goto fail;

	*numifs = lifc.lifc_len / sizeof (struct lifreq);
	if (*numifs >= (lifn.lifn_count + 4)) {
		/*
		 * If every entry was filled, there are probably
		 * more interfaces than (lifn.lifn_count + 4).
		 * Redo the ioctls SIOCGLIFNUM and SIOCGLIFCONF to
		 * get all the interfaces.
		 */
		goto retry;
	}
	return (0);
fail:
	free(*buf);
	*buf = NULL;
	return (-1);
}
