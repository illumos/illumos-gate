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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This program does the following:
 *
 * a) Returns:
 *	0	- if the program successfully determined the net strategy.
 *	!0	- if an error occurred.
 *
 * b) If the program is successful, it prints three tokens to
 *    stdout: <root fs type> <interface name> <net config strategy>.
 *    where:
 *	<root fs type>		-	"nfs" or "ufs"
 *	<interface name>	-	"hme0" or "none"
 *	<net config strategy>	-	"dhcp", "rarp", "bootprops"
 *					or "none"
 *
 *    Eg:
 *	# /sbin/netstrategy
 *	ufs hme0 dhcp
 *
 *    <root fs type> identifies the system's root file system type.
 *
 *    <interface name> is the 16 char name of the root interface, and is only
 *	set if rarp/dhcp was used to configure the interface.
 *
 *    <net config strategy> can be either "rarp", "dhcp", "bootprops", or
 *	"none" depending on which strategy was used to configure the
 *	interface. Is "none" if no interface was configured using a
 *	net-based strategy.
 *
 * CAVEATS: what about autoclient systems? XXX
 *
 * The logic here must match that in usr/src/uts/common/fs/nfs/nfs_dlinet.c,
 * in particular that code (which implements diskless boot) imposes an
 * ordering on possible ways of configuring network interfaces.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <alloca.h>
#include <sys/systeminfo.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <sys/statvfs.h>
#include <libdevinfo.h>

static char *program;

static char *
get_root_fstype()
{
	static struct statvfs vfs;

	/* root location */
	if (statvfs("/", &vfs) < 0) {
		return ("none");
	} else {
		if (strncmp(vfs.f_basetype, "nfs", sizeof ("nfs") - 1) == 0)
			vfs.f_basetype[sizeof ("nfs") - 1] = '\0';
		return (vfs.f_basetype);
	}
}

/*
 * The following boot properties can be used to configure a network
 * interface in the case of a diskless boot.
 *	host-ip, subnet-mask, server-path, server-name, server-ip.
 *
 * XXX non-diskless case requires "network-interface"?
 */
static boolean_t
boot_properties_present()
{
	/* XXX should use sys/bootprops.h, but it's not delivered */
	const char *required_properties[] = {
		"host-ip",
		"subnet-mask",
		"server-path",
		"server-name",
		"server-ip",
		NULL,
	};
	const char **prop = required_properties;
	char *prop_value;
	di_node_t dn;

	if ((dn = di_init("/", DINFOPROP)) == DI_NODE_NIL) {
		(void) fprintf(stderr, "%s: di_init: %s\n", program,
		    strerror(errno));
		di_fini(dn);
		return (B_FALSE);
	}

	while (*prop != NULL) {
		if (di_prop_lookup_strings(DDI_DEV_T_ANY,
		    dn, *prop, &prop_value) != 1) {
			di_fini(dn);
			return (B_FALSE);
		}
		prop++;
	}
	di_fini(dn);

	return (B_TRUE);
}

static char *
get_first_interface()
{
	int fd;
	struct lifnum ifnum;
	struct lifconf ifconf;
	struct lifreq *ifr;
	static char interface[IFNAMSIZ];

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		(void) fprintf(stderr, "%s: socket: %s\n", program,
		    strerror(errno));
		return (NULL);
	}

	ifnum.lifn_family = AF_UNSPEC;
	ifnum.lifn_flags = 0;
	ifnum.lifn_count = 0;

	if (ioctl(fd, SIOCGLIFNUM, &ifnum) < 0) {
		(void) fprintf(stderr, "%s: SIOCGLIFNUM: %s\n", program,
		    strerror(errno));
		(void) close(fd);
		return (NULL);
	}

	ifconf.lifc_family = AF_UNSPEC;
	ifconf.lifc_flags = 0;
	ifconf.lifc_len = ifnum.lifn_count * sizeof (struct lifreq);
	ifconf.lifc_buf = alloca(ifconf.lifc_len);

	if (ioctl(fd, SIOCGLIFCONF, &ifconf) < 0) {
		(void) fprintf(stderr, "%s: SIOCGLIFCONF: %s\n", program,
		    strerror(errno));
		(void) close(fd);
		return (NULL);
	}

	for (ifr = ifconf.lifc_req; ifr < &ifconf.lifc_req[ifconf.lifc_len /
	    sizeof (ifconf.lifc_req[0])]; ifr++) {

		if (strchr(ifr->lifr_name, ':') != NULL)
			continue;	/* skip logical interfaces */

		if (ioctl(fd, SIOCGLIFFLAGS, ifr) < 0) {
			(void) fprintf(stderr, "%s: SIOCGIFFLAGS: %s\n",
			    program, strerror(errno));
			continue;
		}

		if (ifr->lifr_flags & (IFF_VIRTUAL|IFF_POINTOPOINT))
			continue;

		if (ifr->lifr_flags & IFF_UP) {
			/*
			 * For the "nfs rarp" and "nfs bootprops"
			 * cases, we assume that the first non-virtual
			 * IFF_UP interface is the one used.
			 *
			 * Since the order of the interfaces retrieved
			 * via SIOCGLIFCONF is not deterministic, this
			 * is largely silliness, but (a) "it's always
			 * been this way", (b) machines booted this
			 * way typically only have one interface, and
			 * (c) no one consumes the interface name in
			 * the RARP case anyway.
			 */
			(void) strncpy(interface, ifr->lifr_name, IFNAMSIZ);
			(void) close(fd);
			return (interface);
		}
	}

	(void) close(fd);

	return (NULL);
}

/*
 * Is DHCP running on the specified interface?
 */
static boolean_t
check_dhcp_running(char *interface)
{
	int fd;
	struct ifreq ifr;

	if (interface == NULL)
		return (B_FALSE);

	(void) strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		(void) fprintf(stderr, "%s: socket: %s\n", program,
		    strerror(errno));
		return (B_FALSE);
	}

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		(void) fprintf(stderr, "%s: SIOCGIFFLAGS: %s\n",
		    program, strerror(errno));
		return (B_FALSE);
	}

	if (ifr.ifr_flags & IFF_DHCPRUNNING)
		return (B_TRUE);

	return (B_FALSE);
}

/* ARGSUSED */
int
main(int argc, char *argv[])
{
	char *root, *interface, *strategy, dummy;
	long len;

	root = interface = strategy = NULL;
	program = argv[0];

	root = get_root_fstype();

	/*
	 * If diskless, perhaps boot properties were used to configure
	 * the interface.
	 */
	if ((strcmp(root, "nfs") == 0) && boot_properties_present()) {
		strategy = "bootprops";

		interface = get_first_interface();
		if (interface == NULL) {
			(void) fprintf(stderr,
			    "%s: cannot identify root interface.\n", program);
			return (2);
		}

		(void) printf("%s %s %s\n", root, interface, strategy);
		return (0);
	}

	/*
	 * Handle the simple case where diskless dhcp tells us everything
	 * we need to know.
	 */
	if ((len = sysinfo(SI_DHCP_CACHE, &dummy, sizeof (dummy))) > 1) {
		/* interface is first thing in cache. */
		strategy = "dhcp";
		interface = alloca(len);
		(void) sysinfo(SI_DHCP_CACHE, interface, len);
		(void) printf("%s %s %s\n", root, interface, strategy);
		return (0);
	}

	/*
	 * We're not "nfs dhcp", "nfs none" is impossible, and we don't handle
	 * "ufs rarp" (consumers are coded to deal with this reality), so
	 * there are three possible situations:
	 *
	 *	1. We're "ufs dhcp" if there are any interfaces which have
	 *	   obtained their addresses through DHCP.  That is, if there
	 *	   are any IFF_UP and non-IFF_VIRTUAL interfaces also have
	 *	   IFF_DHCPRUNNING set.
	 *
	 *	2. We're "ufs none" if our filesystem is local and there
	 *	   are no interfaces which have obtained their addresses
	 *	   through DHCP.
	 *
	 *	3. We're "nfs rarp" if our filesystem is remote and there's
	 *	   at least IFF_UP non-IFF_VIRTUAL interface (which there
	 *	   *must* be, since we're running over NFS somehow), then
	 *	   it must be RARP since SI_DHCP_CACHE call above failed.
	 *	   It's too bad there isn't an IFF_RARPRUNNING flag.
	 */

	interface = get_first_interface();

	if (check_dhcp_running(interface))
		strategy = "dhcp";

	if (strcmp(root, "nfs") == 0 || strcmp(root, "cachefs") == 0) {
		if (interface == NULL) {
			(void) fprintf(stderr,
			    "%s: cannot identify root interface.\n", program);
			return (2);
		}
		if (strategy == NULL)
			strategy = "rarp";	/*  must be rarp/bootparams */
	} else {
		if (interface == NULL || strategy == NULL)
			interface = strategy = "none";
	}

	(void) printf("%s %s %s\n", root, interface, strategy);
	return (0);
}
