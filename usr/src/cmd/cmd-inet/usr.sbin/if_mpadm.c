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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <ipmp_admin.h>
#include <libinetutil.h>
#include <locale.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/types.h>

typedef	void		offline_func_t(const char *, ipmp_handle_t);

static const char	*progname;
static int		sioc4fd, sioc6fd;
static offline_func_t	do_offline, undo_offline;
static boolean_t	set_lifflags(const char *, uint64_t);
static boolean_t	is_offline(const char *);
static void		warn(const char *, ...);
static void		die(const char *, ...);

static void
usage()
{
	(void) fprintf(stderr, "Usage: %s [-d | -r] <interface>\n", progname);
	exit(1);
}

static const char *
mpadm_errmsg(uint32_t error)
{
	switch (error) {
	case IPMP_EUNKIF:
		return ("not a physical interface or not in an IPMP group");
	case IPMP_EMINRED:
		return ("no other functioning interfaces are in its IPMP "
		    "group");
	default:
		return (ipmp_errmsg(error));
	}
}

int
main(int argc, char **argv)
{
	int retval;
	ipmp_handle_t handle;
	offline_func_t *ofuncp = NULL;
	const char *ifname;
	int c;

	if ((progname = strrchr(argv[0], '/')) != NULL)
		progname++;
	else
		progname = argv[0];

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "d:r:")) != EOF) {
		switch (c) {
		case 'd':
			ifname = optarg;
			ofuncp = do_offline;
			break;
		case 'r':
			ifname = optarg;
			ofuncp = undo_offline;
			break;
		default :
			usage();
		}
	}

	if (ofuncp == NULL)
		usage();

	/*
	 * Create the global V4 and V6 socket ioctl descriptors.
	 */
	sioc4fd = socket(AF_INET, SOCK_DGRAM, 0);
	sioc6fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sioc4fd == -1 || sioc6fd == -1)
		die("cannot create sockets");

	if ((retval = ipmp_open(&handle)) != IPMP_SUCCESS)
		die("cannot create ipmp handle: %s\n", ipmp_errmsg(retval));

	(*ofuncp)(ifname, handle);

	ipmp_close(handle);
	(void) close(sioc4fd);
	(void) close(sioc6fd);

	return (EXIT_SUCCESS);
}

/*
 * Checks whether IFF_OFFLINE is set on `ifname'.
 */
boolean_t
is_offline(const char *ifname)
{
	struct lifreq lifr = { 0 };

	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (ioctl(sioc4fd, SIOCGLIFFLAGS, &lifr) == -1) {
		if (errno != ENXIO ||
		    ioctl(sioc6fd, SIOCGLIFFLAGS, &lifr) == -1) {
			die("cannot get interface flags on %s", ifname);
		}
	}

	return ((lifr.lifr_flags & IFF_OFFLINE) != 0);
}

static void
do_offline(const char *ifname, ipmp_handle_t handle)
{
	ifaddrlistx_t *ifaddrp, *ifaddrs;
	int retval;

	if (is_offline(ifname))
		die("interface %s is already offline\n", ifname);

	if ((retval = ipmp_offline(handle, ifname, 1)) != IPMP_SUCCESS)
		die("cannot offline %s: %s\n", ifname, mpadm_errmsg(retval));

	/*
	 * Get all the up addresses for `ifname' and bring them down.
	 */
	if (ifaddrlistx(ifname, IFF_UP, 0, &ifaddrs) == -1)
		die("cannot get addresses on %s", ifname);

	for (ifaddrp = ifaddrs; ifaddrp != NULL; ifaddrp = ifaddrp->ia_next) {
		if (!(ifaddrp->ia_flags & IFF_OFFLINE))
			warn("IFF_OFFLINE vanished on %s\n", ifaddrp->ia_name);

		if (!set_lifflags(ifaddrp->ia_name,
		    ifaddrp->ia_flags & ~IFF_UP))
			warn("cannot bring down address on %s\n",
			    ifaddrp->ia_name);
	}

	ifaddrlistx_free(ifaddrs);
}

static void
undo_offline(const char *ifname, ipmp_handle_t handle)
{
	ifaddrlistx_t *ifaddrp, *ifaddrs;
	int retval;

	if (!is_offline(ifname))
		die("interface %s is not offline\n", ifname);

	/*
	 * Get all the down addresses for `ifname' and bring them up.
	 */
	if (ifaddrlistx(ifname, 0, IFF_UP, &ifaddrs) == -1)
		die("cannot get addresses for %s", ifname);

	for (ifaddrp = ifaddrs; ifaddrp != NULL; ifaddrp = ifaddrp->ia_next) {
		if (!(ifaddrp->ia_flags & IFF_OFFLINE))
			warn("IFF_OFFLINE vanished on %s\n", ifaddrp->ia_name);

		if (!set_lifflags(ifaddrp->ia_name, ifaddrp->ia_flags | IFF_UP))
			warn("cannot bring up address on %s\n",
			    ifaddrp->ia_name);
	}

	ifaddrlistx_free(ifaddrs);

	/*
	 * Undo the offline.
	 */
	if ((retval = ipmp_undo_offline(handle, ifname)) != IPMP_SUCCESS) {
		die("cannot undo-offline %s: %s\n", ifname,
		    mpadm_errmsg(retval));
	}

	/*
	 * Verify whether IFF_OFFLINE is set as a sanity check.
	 */
	if (is_offline(ifname))
		warn("in.mpathd has not cleared IFF_OFFLINE on %s\n", ifname);
}

/*
 * Change `lifname' to have `flags' set.  Returns B_TRUE on success.
 */
static boolean_t
set_lifflags(const char *lifname, uint64_t flags)
{
	struct lifreq 	lifr = { 0 };
	int		fd = (flags & IFF_IPV4) ? sioc4fd : sioc6fd;

	(void) strlcpy(lifr.lifr_name, lifname, LIFNAMSIZ);
	lifr.lifr_flags = flags;

	return (ioctl(fd, SIOCSLIFFLAGS, &lifr) >= 0);
}

/* PRINTFLIKE1 */
static void
die(const char *format, ...)
{
	va_list alist;
	char *errstr = strerror(errno);

	format = gettext(format);
	(void) fprintf(stderr, gettext("%s: fatal: "), progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", errstr);

	exit(EXIT_FAILURE);
}

/* PRINTFLIKE1 */
static void
warn(const char *format, ...)
{
	va_list alist;
	char *errstr = strerror(errno);

	format = gettext(format);
	(void) fprintf(stderr, gettext("%s: warning: "), progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", errstr);
}
