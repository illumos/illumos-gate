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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This module reads and writes the stable identifier values, DUID and IAID.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <libdlpi.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/dhcp6.h>
#include <dhcp_inittab.h>

#define	DUID_FILE	"/etc/dhcp/duid"
#define	IAID_FILE	"/etc/dhcp/iaid"

struct iaid_ent {
	uint32_t	ie_iaid;
	char		ie_name[LIFNAMSIZ];
};

/*
 * read_stable_duid(): read the system's stable DUID, if any
 *
 *   input: size_t *: pointer to a size_t to return the DUID length
 *  output: uchar_t *: the DUID buffer, or NULL on error (and errno is set)
 *    note: memory returned is from malloc; caller must free.
 */

uchar_t *
read_stable_duid(size_t *duidlen)
{
	int fd;
	ssize_t retv;
	struct stat sb;
	uchar_t *duid = NULL;

	if ((fd = open(DUID_FILE, O_RDONLY)) == -1)
		return (NULL);
	if (fstat(fd, &sb) != -1 && S_ISREG(sb.st_mode) &&
	    (duid = malloc(sb.st_size)) != NULL) {
		retv = read(fd, duid, sb.st_size);
		if (retv == sb.st_size) {
			*duidlen = sb.st_size;
		} else {
			free(duid);
			/*
			 * Make sure that errno always gets set when something
			 * goes wrong.
			 */
			if (retv >= 0)
				errno = EINVAL;
			duid = NULL;
		}
	}
	(void) close(fd);
	return (duid);
}

/*
 * write_stable_duid(): write the system's stable DUID.
 *
 *   input: const uchar_t *: pointer to the DUID buffer
 *	    size_t: length of the DUID
 *  output: int: 0 on success, -1 on error.  errno is set on error.
 */

int
write_stable_duid(const uchar_t *duid, size_t duidlen)
{
	int fd;
	ssize_t retv;

	(void) unlink(DUID_FILE);
	if ((fd = open(DUID_FILE, O_WRONLY | O_CREAT, 0644)) == -1)
		return (-1);
	retv = write(fd, duid, duidlen);
	if (retv == duidlen) {
		return (close(fd));
	} else {
		(void) close(fd);
		if (retv >= 0)
			errno = ENOSPC;
		return (-1);
	}
}

/*
 * make_stable_duid(): create a new DUID
 *
 *   input: const char *: name of physical interface for reference
 *	    size_t *: pointer to a size_t to return the DUID length
 *  output: uchar_t *: the DUID buffer, or NULL on error (and errno is set)
 *    note: memory returned is from malloc; caller must free.
 */

uchar_t *
make_stable_duid(const char *physintf, size_t *duidlen)
{
	int len;
	dlpi_info_t dlinfo;
	dlpi_handle_t dh = NULL;
	uint_t arptype;
	duid_en_t *den;

	/*
	 * Try to read the MAC layer address for the physical interface
	 * provided as a hint.  If that works, we can use a DUID-LLT.
	 */

	if (dlpi_open(physintf, &dh, 0) == DLPI_SUCCESS &&
	    dlpi_bind(dh, DLPI_ANY_SAP, NULL) == DLPI_SUCCESS &&
	    dlpi_info(dh, &dlinfo, 0) == DLPI_SUCCESS &&
	    (len = dlinfo.di_physaddrlen) > 0 &&
	    (arptype = dlpi_arptype(dlinfo.di_mactype) != 0)) {
		duid_llt_t *dllt;
		time_t now;

		if ((dllt = malloc(sizeof (*dllt) + len)) == NULL) {
			dlpi_close(dh);
			return (NULL);
		}

		(void) memcpy((dllt + 1), dlinfo.di_physaddr, len);
		dllt->dllt_dutype = htons(DHCPV6_DUID_LLT);
		dllt->dllt_hwtype = htons(arptype);
		now = time(NULL) - DUID_TIME_BASE;
		dllt->dllt_time = htonl(now);
		*duidlen = sizeof (*dllt) + len;
		dlpi_close(dh);
		return ((uchar_t *)dllt);
	}
	if (dh != NULL)
		dlpi_close(dh);

	/*
	 * If we weren't able to create a DUID based on the network interface
	 * in use, then generate one based on a UUID.
	 */
	den = malloc(sizeof (*den) + UUID_LEN);
	if (den != NULL) {
		uuid_t uuid;

		den->den_dutype = htons(DHCPV6_DUID_EN);
		DHCPV6_SET_ENTNUM(den, DHCPV6_SUN_ENT);
		uuid_generate(uuid);
		(void) memcpy(den + 1, uuid, UUID_LEN);
		*duidlen = sizeof (*den) + UUID_LEN;
	}
	return ((uchar_t *)den);
}

/*
 * read_stable_iaid(): read a link's stable IAID, if any
 *
 *   input: const char *: interface name
 *  output: uint32_t: the IAID, or 0 if none
 */

uint32_t
read_stable_iaid(const char *intf)
{
	int fd;
	struct iaid_ent ie;

	if ((fd = open(IAID_FILE, O_RDONLY)) == -1)
		return (0);
	while (read(fd, &ie, sizeof (ie)) == sizeof (ie)) {
		if (strcmp(intf, ie.ie_name) == 0) {
			(void) close(fd);
			return (ie.ie_iaid);
		}
	}
	(void) close(fd);
	return (0);
}

/*
 * write_stable_iaid(): write out a link's stable IAID
 *
 *   input: const char *: interface name
 *  output: uint32_t: the IAID, or 0 if none
 */

int
write_stable_iaid(const char *intf, uint32_t iaid)
{
	int fd;
	struct iaid_ent ie;
	ssize_t retv;

	if ((fd = open(IAID_FILE, O_RDWR | O_CREAT, 0644)) == -1)
		return (0);
	while (read(fd, &ie, sizeof (ie)) == sizeof (ie)) {
		if (strcmp(intf, ie.ie_name) == 0) {
			(void) close(fd);
			if (iaid == ie.ie_iaid) {
				return (0);
			} else {
				errno = EINVAL;
				return (-1);
			}
		}
	}
	(void) memset(&ie, 0, sizeof (ie));
	ie.ie_iaid = iaid;
	(void) strlcpy(ie.ie_name, intf, sizeof (ie.ie_name));
	retv = write(fd, &ie, sizeof (ie));
	(void) close(fd);
	if (retv == sizeof (ie)) {
		return (0);
	} else {
		if (retv >= 0)
			errno = ENOSPC;
		return (-1);
	}
}

/*
 * make_stable_iaid(): create a stable IAID for a link
 *
 *   input: const char *: interface name
 *	    uint32_t: the ifIndex for this link (as a "hint")
 *  output: uint32_t: the new IAID, never zero
 */

/* ARGSUSED */
uint32_t
make_stable_iaid(const char *intf, uint32_t hint)
{
	int fd;
	struct iaid_ent ie;
	uint32_t maxid, minunused;
	boolean_t recheck;

	if ((fd = open(IAID_FILE, O_RDONLY)) == -1)
		return (hint);
	maxid = 0;
	minunused = 1;
	/*
	 * This logic is deliberately unoptimized.  The reason is that it runs
	 * essentially just once per interface for the life of the system.
	 * Once the IAID is established, there's no reason to generate it
	 * again, and all we care about here is correctness.  Also, IAIDs tend
	 * to get added in a logical sequence order, so the outer loop should
	 * not normally run more than twice.
	 */
	do {
		recheck = B_FALSE;
		while (read(fd, &ie, sizeof (ie)) == sizeof (ie)) {
			if (ie.ie_iaid > maxid)
				maxid = ie.ie_iaid;
			if (ie.ie_iaid == minunused) {
				recheck = B_TRUE;
				minunused++;
			}
			if (ie.ie_iaid == hint)
				hint = 0;
		}
		if (recheck)
			(void) lseek(fd, 0, SEEK_SET);
	} while (recheck);
	(void) close(fd);
	if (hint != 0)
		return (hint);
	else if (maxid != UINT32_MAX)
		return (maxid + 1);
	else
		return (minunused);
}
