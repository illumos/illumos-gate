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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ctfs.h>
#include <sys/contract/process.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <libuutil.h>
#include <poll.h>
#include <port.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdarg.h>

#include <locale.h>
#include <langinfo.h>

struct {
	const char *name;
	int found;
} types[] = {
	{ "process", 0 },
	{ "device", 0 },
	{ NULL }
};

typedef struct watched_fd {
	int wf_fd;
	int wf_type;
} watched_fd_t;

/*
 * usage
 *
 * Educate the user.
 */
static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "Usage: %s [-f] [-r] [-v] contract-id | contract-type ...\n"),
	    uu_getpname());
	exit(UU_EXIT_USAGE);
}

/*
 * sopen
 *
 * Given a format string and a variable number of arguments, create a
 * file name and open it.  Warn with 'permerror' and return -1 if
 * opening the file returned EPERM or EACCES, die with 'error' on all
 * other error conditions.
 */
static int
sopen(const char *format, const char *error, const char *permerror, ...)
{
	char path[PATH_MAX];
	int fd;
	va_list varg;

	va_start(varg, permerror);
	if (vsnprintf(path, PATH_MAX, format, varg) >= PATH_MAX) {
		errno = ENAMETOOLONG;
		uu_vdie(error, varg);
	}

	if ((fd = open64(path, O_RDONLY | O_NONBLOCK)) == -1) {
		if (permerror && (errno == EPERM || errno == EACCES))
			uu_vwarn(permerror, varg);
		else
			uu_vdie(error, varg);
	}
	va_end(varg);

	return (fd);
}

/*
 * hdr_event
 *
 * Display the output header.
 */
static void
hdr_event(void)
{
	(void) printf("%-8s%-8s%-5s%-4s%-9s%s\n",
	    "CTID", "EVID", "CRIT", "ACK", "CTTYPE", "SUMMARY");
}

/*
 * get_event
 *
 * Read and display a contract event.
 */
static int
get_event(int fd, int type, int verbose)
{
	ct_evthdl_t ev;
	uint_t flags;

	/*
	 * Read a contract event.
	 */
	if (errno = ct_event_read(fd, &ev)) {
		if (errno == EAGAIN)
			return (0);
		uu_die(gettext("could not receive contract event"));
	}

	/*
	 * Emit a one-line event summary.
	 */
	flags = ct_event_get_flags(ev);
	(void) printf("%-8ld%-8lld%-5s%-4s%-9s",
	    ct_event_get_ctid(ev),
	    ct_event_get_evid(ev),
	    (flags & CTE_INFO) ? "info" : (flags & CTE_NEG) ? "neg" : "crit",
	    flags & CTE_ACK ? "yes" : "no",
	    types[type].name);

	/*
	 * Display event details, if requested.
	 * (Since this is also needed by ctrun, the common
	 * contract_event_dump is found in libcontract.)
	 */
	contract_event_dump(stdout, ev, verbose);

	ct_event_free(ev);
	return (1);
}

/*
 * get_type
 *
 * Given a contract type name, return an index into the 'types' array.
 * Exits on failure.
 */
static int
get_type(const char *typestr)
{
	int i;
	for (i = 0; types[i].name; i++)
		if (strcmp(types[i].name, typestr) == 0)
			return (i);
	uu_die(gettext("invalid contract type: %s\n"), typestr);
	/* NOTREACHED */
}

/*
 * contract_type
 *
 * Given a contract id, return an index into the 'types' array.
 * Returns -1 on failure.
 */
static int
contract_type(ctid_t id)
{
	ct_stathdl_t hdl;
	int type, fd;

	/*
	 * This could be faster (e.g. by reading the link itself), but
	 * this is the most straightforward implementation.
	 */
	if ((fd = contract_open(id, NULL, "status", O_RDONLY)) == -1)
		return (-1);
	if (errno = ct_status_read(fd, CTD_COMMON, &hdl)) {
		(void) close(fd);
		return (-1);
	}
	type = get_type(ct_status_get_type(hdl));
	ct_status_free(hdl);
	(void) close(fd);
	return (type);
}

/*
 * ctid_compar
 *
 * A simple contract ID comparator.
 */
static int
ctid_compar(const void *a1, const void *a2)
{
	ctid_t id1 = *(ctid_t *)a1;
	ctid_t id2 = *(ctid_t *)a2;

	if (id1 > id2)
		return (1);
	if (id2 > id1)
		return (-1);
	return (0);
}

int
main(int argc, char **argv)
{
	int	opt_reliable = 0;
	int	opt_reset = 0;
	int	opt_verbose = 0;
	int	port_fd;
	watched_fd_t *wfd;
	int	i, nfds, nids;
	ctid_t	*ids, last;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	(void) uu_setpname(argv[0]);

	while ((i = getopt(argc, argv, "rfv")) !=  EOF) {
		switch (i) {
		case 'r':
			opt_reliable = 1;
			break;
		case 'f':
			opt_reset = 1;
			break;
		case 'v':
			opt_verbose = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc <= 0)
		usage();

	wfd = calloc(argc, sizeof (struct pollfd));
	if (wfd == NULL)
		uu_die("calloc");
	ids = calloc(argc, sizeof (ctid_t));
	if (ids == NULL)
		uu_die("calloc");

	/*
	 * Scan our operands for contract ids and types.
	 */
	nfds = 0;
	nids = 0;
	for (i = 0; i < argc; i++) {
		int id;
		if (strchr(argv[i], '/') != NULL)
			uu_die(gettext("invalid contract type: %s\n"), argv[i]);

		/*
		 * If argument isn't a number between 0 and INT_MAX,
		 * treat it as a contract type.
		 */
		if (uu_strtoint(argv[i], &id, sizeof (id), 10, 1, INT_MAX)) {
			int type;
			wfd[nfds].wf_fd =
			    sopen(CTFS_ROOT "/%s/bundle",
			    gettext("invalid contract type: %s\n"), NULL,
			    argv[i]);
			wfd[nfds].wf_type = type = get_type(argv[i]);
			if (types[type].found) {
				(void) close(wfd[nfds].wf_fd);
				continue;
			}
			types[type].found = 1;
			nfds++;
		} else {
			ids[nids++] = id;
		}
	}

	/*
	 * Eliminate those contract ids which are represented by
	 * contract types, so we don't get duplicate event reports from
	 * them.
	 *
	 * Sorting the array first allows us to efficiently skip
	 * duplicate ids.  We know that the array only contains
	 * integers [0, INT_MAX].
	 */
	qsort(ids, nids, sizeof (ctid_t), ctid_compar);
	last = -1;
	for (i = 0; i < nids; i++) {
		int type, fd;

		if (ids[i] == last)
			continue;
		last = ids[i];

		fd = sopen(CTFS_ROOT "/all/%d/events",
		    gettext("invalid contract id: %d\n"),
		    gettext("could not access contract id %d\n"), ids[i]);
		if (fd == -1)
			continue;
		if ((type = contract_type(ids[i])) == -1) {
			(void) close(fd);
			uu_warn(gettext("could not access contract id %d\n"),
			    ids[i]);
			continue;
		}
		if (types[type].found) {
			(void) close(fd);
			continue;
		}
		wfd[nfds].wf_fd = fd;
		wfd[nfds].wf_type = type;
		nfds++;
	}
	free(ids);

	if (nfds == 0)
		uu_die(gettext("no contracts to watch\n"));

	/*
	 * Handle options.
	 */
	if (opt_reliable)
		for (i = 0; i < nfds; i++)
			if (ioctl(wfd[i].wf_fd, CT_ERELIABLE, NULL) == -1) {
				uu_warn("could not request reliable events");
				break;
			}

	if (opt_reset)
		for (i = 0; i < nfds; i++)
			(void) ioctl(wfd[i].wf_fd, CT_ERESET, NULL);


	/*
	 * Allocate an event point, and associate all our endpoint file
	 * descriptors with it.
	 */
	if ((port_fd = port_create()) == -1)
		goto port_error;
	for (i = 0; i < nfds; i++)
		if (port_associate(port_fd, PORT_SOURCE_FD, wfd[i].wf_fd,
		    POLLIN, &wfd[i]) == -1)
			goto port_error;

	/*
	 * Loop waiting for and displaying events.
	 */
	hdr_event();
	for (;;) {
		port_event_t pe;
		watched_fd_t *w;
		if (port_get(port_fd, &pe, NULL) == -1) {
			if (errno == EINTR)
				continue;
			goto port_error;
		}
		w = pe.portev_user;
		while (get_event(pe.portev_object, w->wf_type, opt_verbose))
			;
		if (port_associate(port_fd, PORT_SOURCE_FD, pe.portev_object,
		    POLLIN, pe.portev_user) == -1)
			goto port_error;
	}

port_error:
	uu_die(gettext("error waiting for contract events"));

	return (1);	/* placate cc */
}
