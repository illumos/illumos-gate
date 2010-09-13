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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inet/common.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

#define	IPIF_SEPARATOR_CHAR	":"

/*
 * Given an interface name, this function retrives the associated
 * index value. Returns index value if successful, zero otherwise.
 * The length of the supplied interface name must be at most
 * IF_NAMESIZE-1 bytes
 */
uint32_t
if_nametoindex(const char *ifname)
{
	int		s;
	struct lifreq	lifr;
	int		save_err;
	size_t		size;


	/* Make sure the given name is not NULL */
	if ((ifname == NULL)||(*ifname == '\0')) {
		errno = ENXIO;
		return (0);
	}

	/*
	 * Fill up the interface name in the ioctl
	 * request message. Make sure that the length of
	 * the given interface name <= (IF_NAMESIZE-1)
	 */
	size = strlen(ifname);
	if (size > (IF_NAMESIZE - 1)) {
		errno = EINVAL;
		return (0);
	}

	strncpy(lifr.lifr_name, ifname, size +1);

	/* Check the v4 interfaces first */
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
		if (ioctl(s, SIOCGLIFINDEX, (caddr_t)&lifr) >= 0) {
			(void) close(s);
			return (lifr.lifr_index);
		}
		(void) close(s);
	}

	/* Check the v6 interface list */
	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s < 0)
		return (0);

	if (ioctl(s, SIOCGLIFINDEX, (caddr_t)&lifr) < 0)
		lifr.lifr_index = 0;

	save_err = errno;
	(void) close(s);
	errno = save_err;
	return (lifr.lifr_index);
}

/*
 * Given an index, this function returns the associated interface
 * name in the supplied buffer ifname.
 * Returns physical interface name if successful, NULL otherwise.
 * The interface name returned will be at most IF_NAMESIZE-1 bytes.
 */
char *
if_indextoname(uint32_t ifindex, char *ifname)
{
	int		n;
	int		s;
	char		*buf;
	uint32_t	index;
	struct lifnum	lifn;
	struct lifconf	lifc;
	struct lifreq	*lifrp;
	int		numifs;
	size_t		bufsize;
	boolean_t 	found;
	uint_t		flags;

	flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES | LIFC_UNDER_IPMP;

	/* A interface index of 0 is invalid */
	if (ifindex == 0) {
		errno = ENXIO;
		return (NULL);
	}

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s < 0) {
		s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s < 0) {
			return (NULL);
		}
	}

	/* Prepare to send a SIOCGLIFNUM request message */
	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = flags;
	if (ioctl(s, SIOCGLIFNUM, (char *)&lifn) < 0) {
		int save_err = errno;
		(void) close(s);
		errno = save_err;
		return (NULL);
	}

	/*
	 * NOTE: "+ 10" sleaze mitigates new IP interfaces showing up between
	 * the SIOCGLIFNUM and the SIOCGLIFCONF.
	 */
	numifs = lifn.lifn_count + 10;

	/*
	 * Provide enough buffer to obtain the interface
	 * list from the kernel as response to a SIOCGLIFCONF
	 * request
	 */

	bufsize = numifs * sizeof (struct lifreq);
	buf = malloc(bufsize);
	if (buf == NULL) {
		int save_err = errno;
		(void) close(s);
		errno = save_err;
		return (NULL);
	}
	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = flags;
	lifc.lifc_len = bufsize;
	lifc.lifc_buf = buf;
	if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) < 0) {
		int save_err = errno;
		(void) close(s);
		errno = save_err;
		free(buf);
		return (NULL);
	}

	lifrp = lifc.lifc_req;
	found = B_FALSE;
	for (n = lifc.lifc_len / sizeof (struct lifreq); n > 0; n--, lifrp++) {
		/*
		 * Obtain the index value of each interface, and
		 * match to see if the retrived index value matches
		 * the given one. If so we return the corresponding
		 * device name of that interface.
		 */
		size_t	size;

		index = if_nametoindex(lifrp->lifr_name);
		if (index == 0)
			/* Oops the interface just disappeared */
			continue;
		if (index == ifindex) {
			size = strcspn(lifrp->lifr_name,
			    (char *)IPIF_SEPARATOR_CHAR);
			lifrp->lifr_name[size] = '\0';
			found = B_TRUE;
			(void) strncpy(ifname, lifrp->lifr_name, size + 1);
			break;
		}
	}
	(void) close(s);
	free(buf);
	if (!found) {
		errno = ENXIO;
		return (NULL);
	}
	return (ifname);
}

/*
 * This function returns all the interface names and indexes
 */
struct if_nameindex *
if_nameindex(void)
{
	int		n;
	int		s;
	boolean_t	found;
	char		*buf;
	struct lifnum	lifn;
	struct lifconf	lifc;
	struct lifreq	*lifrp;
	int		numifs;
	int		index;
	int		i;
	int 		physinterf_num;
	size_t		bufsize;
	struct if_nameindex	 *interface_list;
	struct if_nameindex	 *interface_entry;

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s < 0) {
		s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s < 0)
			return (NULL);
	}

	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
	if (ioctl(s, SIOCGLIFNUM, (char *)&lifn) < 0)
		return (NULL);
	numifs = lifn.lifn_count;

	bufsize = numifs * sizeof (struct lifreq);
	buf = malloc(bufsize);
	if (buf == NULL) {
		int save_err = errno;
		(void) close(s);
		errno = save_err;
		return (NULL);
	}
	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
	lifc.lifc_len = bufsize;
	lifc.lifc_buf = buf;
	if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) < 0) {
		int save_err = errno;
		(void) close(s);
		errno = save_err;
		free(buf);
		return (NULL);
	}

	lifrp = lifc.lifc_req;
	(void) close(s);

	/* Allocate the array of if_nameindex structure */
	interface_list = malloc((numifs + 1) * sizeof (struct if_nameindex));
	if (!interface_list) {
		int save_err = errno;
		free(buf);
		errno = save_err;
		return (NULL);
	}
	/*
	 * Make sure that terminator structure automatically
	 * happens to be all zeroes.
	 */
	bzero(interface_list, ((numifs + 1) * sizeof (struct if_nameindex)));
	interface_entry = interface_list;
	physinterf_num = 0;
	for (n = numifs; n > 0; n--, lifrp++) {
		size_t	size;

		size = strcspn(lifrp->lifr_name, (char *)IPIF_SEPARATOR_CHAR);
		found = B_FALSE;
		/*
		 * Search the current array to see if this interface
		 * already exists. Only compare the physical name.
		 */
		for (i = 0; i < physinterf_num; i++) {
			if (strncmp(interface_entry[i].if_name,
			    lifrp->lifr_name, size) == 0) {
				found = B_TRUE;
				break;
			}
		}

		/* New one. Allocate an array element and fill it */
		if (!found) {
			/*
			 * Obtain the index value for the interface
			 */
			interface_entry[physinterf_num].if_index =
			    if_nametoindex(lifrp->lifr_name);

			if (interface_entry[physinterf_num].if_index == 0) {
				/* The interface went away. Skip this entry. */
				continue;
			}

			/*
			 * Truncate the name to ensure that it represents
			 * a physical interface.
			 */
			lifrp->lifr_name[size] = '\0';
			if ((interface_entry[physinterf_num].if_name =
			    strdup(lifrp->lifr_name)) == NULL) {
				int save_err;

				if_freenameindex(interface_list);
				save_err = errno;
				free(buf);
				errno = save_err;
				return (NULL);
			}

			physinterf_num++;
		}
	}

	/* Create the last one of the array */
	interface_entry[physinterf_num].if_name = NULL;
	interface_entry[physinterf_num].if_index = 0;

	/* Free up the excess array space */
	free(buf);
	interface_list = realloc(interface_list, ((physinterf_num + 1) *
	    sizeof (struct if_nameindex)));

	return (interface_list);
}

/*
 * This function frees the the array that is created while
 * the if_nameindex function.
 */
void
if_freenameindex(struct if_nameindex *ptr)
{
	struct if_nameindex *p;

	if (ptr == NULL)
		return;

	/* First free the if_name member in each array element */
	for (p = ptr; p->if_name != NULL; p++)
		free(p->if_name);

	/* Now free up the array space */
	free(ptr);
}
