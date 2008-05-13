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
 * sppptun.c - Solaris STREAMS PPP multiplexing tunnel driver
 * installer.
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stropts.h>
#include <fcntl.h>
#include <locale.h>
#include <sys/fcntl.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/sppptun.h>
#include <libdlpi.h>

static char *myname;		/* Copied from argv[0] */
static int verbose;		/* -v on command line */

/* Data gathered during per-style attach routine. */
struct attach_data {
	ppptun_lname appstr;    /* String to append to interface name (PPA) */
	ppptun_atype localaddr; /* Local interface address */
	uint_t locallen;	/* Length of local address */
};

/* Per-protocol plumbing data */
struct protos {
	const char *name;
	const char *desc;
	int (*attach)(struct protos *prot, char *linkname,
	    struct attach_data *adata);
	uint_t protval;
	int style;
};

/*
 * Print a usage string and terminate.  Used for command line argument
 * errors.  Does not return.
 */
static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "Usage:\n\t%s plumb [<protocol> <device>]\n"
	    "\t%s unplumb <interface-name>\n"
	    "\t%s query\n"), myname, myname, myname);
	exit(1);
}

/*
 * General DLPI function.  This is called indirectly through
 * the protos structure for the selected lower stream protocol.
 */
static int
sppp_dlpi(struct protos *prot, char *linkname, struct attach_data *adata)
{
	int retv;
	uint_t ppa;
	dlpi_handle_t dh;

	if (verbose)
		(void) printf(gettext("opening DLPI link %s\n"), linkname);
	if ((retv = dlpi_open(linkname, &dh, 0)) != DLPI_SUCCESS) {
		(void) fprintf(stderr, gettext("%s: failed opening %s: %s\n"),
		    myname, linkname, dlpi_strerror(retv));
		return (-1);
	}

	if (verbose) {
		(void) printf(gettext("binding to Ethertype %04X\n"),
		    prot->protval);
	}
	if ((retv = dlpi_bind(dh, prot->protval, NULL)) != DLPI_SUCCESS) {
		(void) fprintf(stderr, gettext("%s: failed binding on %s: %s"),
		    myname, linkname, dlpi_strerror(retv));
		dlpi_close(dh);
		return (-1);
	}

	adata->locallen = DLPI_PHYSADDR_MAX;
	if ((retv = dlpi_get_physaddr(dh, DL_CURR_PHYS_ADDR, &adata->localaddr,
	    &adata->locallen)) != DLPI_SUCCESS) {
		(void) fprintf(stderr, gettext("%s: failed getting physical"
		    " address on %s: %s"), myname, linkname,
		    dlpi_strerror(retv));
		dlpi_close(dh);
		return (-1);
	}

	/* Store ppa to append to interface name. */
	if ((retv = dlpi_parselink(linkname, NULL, &ppa)) != DLPI_SUCCESS) {
		(void) fprintf(stderr, gettext("%s: failed parsing linkname on"
		    " %s: %s"), myname, linkname, dlpi_strerror(retv));
		dlpi_close(dh);
		return (-1);
	}

	(void) snprintf(adata->appstr, sizeof (adata->appstr), "%d", ppa);

	return (dlpi_fd(dh));
}


static struct protos proto_list[] = {
	{ "pppoe", "RFC 2516 PPP over Ethernet", sppp_dlpi, ETHERTYPE_PPPOES,
	    PTS_PPPOE },
	{ "pppoed", "RFC 2516 PPP over Ethernet Discovery", sppp_dlpi,
	    ETHERTYPE_PPPOED, PTS_PPPOE },
	{ NULL }
};

/*
 * Issue a STREAMS I_STR ioctl and fetch the result.  Returns -1 on
 * error, or length of returned data on success.
 */
static int
strioctl(int fd, int cmd, void *ptr, int ilen, int olen, const char *iocname)
{
	struct strioctl	str;

	str.ic_cmd = cmd;
	str.ic_timout = 0;
	str.ic_len = ilen;
	str.ic_dp = ptr;

	if (ioctl(fd, I_STR, &str) == -1) {
		perror(iocname);
		return (-1);
	}

	if (olen >= 0) {
		if (str.ic_len > olen && verbose > 1) {
			(void) printf(gettext("%s:%s: extra data received; "
			    "%d > %d\n"), myname, iocname, str.ic_len, olen);
		} else if (str.ic_len < olen) {
			(void) fprintf(stderr, gettext("%s:%s: expected %d "
			    "bytes, got %d\n"), myname, iocname, olen,
			    str.ic_len);
			return (-1);
		}
	}

	return (str.ic_len);
}

/*
 * Handle user request to plumb a new lower stream under the sppptun
 * driver.
 */
static int
plumb_it(int argc, char **argv)
{
	int devfd, muxfd, muxid;
	struct ppptun_info pti;
	char *cp, *linkname;
	struct protos *prot;
	struct attach_data adata;

	/* If no protocol requested, then list known protocols. */
	if (optind == argc) {
		(void) puts("Known tunneling protocols:");
		for (prot = proto_list; prot->name != NULL; prot++)
			(void) printf("\t%s\t%s\n", prot->name, prot->desc);
		return (0);
	}

	/* If missing protocol or device, then abort. */
	if (optind != argc-2)
		usage();

	/* Look up requested protocol. */
	cp = argv[optind++];
	for (prot = proto_list; prot->name != NULL; prot++)
		if (strcasecmp(cp, prot->name) == 0)
			break;
	if (prot->name == NULL) {
		(void) fprintf(stderr, gettext("%s: unknown protocol %s\n"),
		    myname, cp);
		return (1);
	}

	/* Get interface. */
	linkname = argv[optind];
	/* Call per-protocol attach routine to open device */
	if (verbose)
		(void) printf(gettext("opening %s\n"), linkname);
	if ((devfd = (*prot->attach)(prot, linkname, &adata)) < 0)
		return (1);

	/* Open sppptun driver */
	if (verbose)
		(void) printf(gettext("opening /dev/%s\n"), PPP_TUN_NAME);
	if ((muxfd = open("/dev/" PPP_TUN_NAME, O_RDWR)) < 0) {
		perror("/dev/" PPP_TUN_NAME);
		return (1);
	}

	/* Push sppptun module on top of lower driver. */
	if (verbose)
		(void) printf(gettext("pushing %s on %s\n"), PPP_TUN_NAME,
		    linkname);
	if (ioctl(devfd, I_PUSH, PPP_TUN_NAME) == -1) {
		perror("I_PUSH " PPP_TUN_NAME);
		return (1);
	}

	/* Get the name of the newly-created lower stream. */
	if (verbose)
		(void) printf(gettext("getting new interface name\n"));
	if (strioctl(devfd, PPPTUN_GNAME, pti.pti_name, 0,
	    sizeof (pti.pti_name), "PPPTUN_GNAME") < 0)
		return (1);
	if (verbose)
		(void) printf(gettext("got interface %s\n"), pti.pti_name);

	/* Convert stream name to protocol-specific name. */
	if ((cp = strchr(pti.pti_name, ':')) != NULL)
		*cp = '\0';
	(void) snprintf(pti.pti_name+strlen(pti.pti_name),
	    sizeof (pti.pti_name)-strlen(pti.pti_name), "%s:%s", adata.appstr,
	    prot->name);

	/* Change the lower stream name. */
	if (verbose)
		(void) printf(gettext("resetting interface name to %s\n"),
		    pti.pti_name);
	if (strioctl(devfd, PPPTUN_SNAME, pti.pti_name,
	    sizeof (pti.pti_name), 0, "PPPTUN_SNAME") < 0) {
		if (errno == EEXIST)
			(void) fprintf(stderr, gettext("%s: %s already "
			    "installed\n"), myname, pti.pti_name);
		return (1);
	}

	/*
	 * Send down the local interface address to the lower stream
	 * so that it can originate packets.
	 */
	if (verbose)
		(void) printf(gettext("send down local address\n"));
	if (strioctl(devfd, PPPTUN_LCLADDR, &adata.localaddr, adata.locallen,
	    0, "PPPTUN_LCLADDR") < 0)
		return (1);

	/* Link the lower stream under the tunnel device. */
	if (verbose)
		(void) printf(gettext("doing I_PLINK\n"));
	if ((muxid = ioctl(muxfd, I_PLINK, devfd)) == -1) {
		perror("I_PLINK");
		return (1);
	}

	/*
	 * Give the tunnel driver the multiplex ID of the new lower
	 * stream.  This allows the unplumb function to find and
	 * disconnect the lower stream.
	 */
	if (verbose)
		(void) printf(gettext("sending muxid %d and style %d to "
		    "driver\n"), muxid, prot->style);
	pti.pti_muxid = muxid;
	pti.pti_style = prot->style;
	if (strioctl(muxfd, PPPTUN_SINFO, &pti, sizeof (pti), 0,
	    "PPPTUN_SINFO") < 0)
		return (1);

	if (verbose)
		(void) printf(gettext("done; installed %s\n"), pti.pti_name);
	else
		(void) puts(pti.pti_name);

	return (0);
}

/*
 * Handle user request to unplumb an existing lower stream from the
 * sppptun driver.
 */
static int
unplumb_it(int argc, char **argv)
{
	char *ifname;
	int muxfd;
	struct ppptun_info pti;

	/*
	 * Need to have the name of the lower stream on the command
	 * line.
	 */
	if (optind != argc-1)
		usage();

	ifname = argv[optind];

	/* Open the tunnel driver. */
	if (verbose)
		(void) printf(gettext("opening /dev/%s\n"), PPP_TUN_NAME);
	if ((muxfd = open("/dev/" PPP_TUN_NAME, O_RDWR)) < 0) {
		perror("/dev/" PPP_TUN_NAME);
		return (1);
	}

	/* Get lower stream information; including multiplex ID. */
	if (verbose)
		(void) printf(gettext("getting info from driver\n"));
	(void) strncpy(pti.pti_name, ifname, sizeof (pti.pti_name));
	if (strioctl(muxfd, PPPTUN_GINFO, &pti, sizeof (pti),
	    sizeof (pti), "PPPTUN_GINFO") < 0)
		return (1);
	if (verbose)
		(void) printf(gettext("got muxid %d from driver\n"),
		    pti.pti_muxid);

	/* Unlink lower stream from driver. */
	if (verbose)
		(void) printf(gettext("doing I_PUNLINK\n"));
	if (ioctl(muxfd, I_PUNLINK, pti.pti_muxid) < 0) {
		perror("I_PUNLINK");
		return (1);
	}
	if (verbose)
		(void) printf(gettext("done!\n"));

	return (0);
}

/*
 * Handle user request to list lower streams plumbed under the sppptun
 * driver.
 */
/*ARGSUSED*/
static int
query_interfaces(int argc, char **argv)
{
	int muxfd, i;
	union ppptun_name ptn;

	/* No other arguments permitted. */
	if (optind != argc)
		usage();

	/* Open the tunnel driver. */
	if (verbose)
		(void) printf(gettext("opening /dev/%s\n"), PPP_TUN_NAME);
	if ((muxfd = open("/dev/" PPP_TUN_NAME, O_RDWR)) < 0) {
		perror("/dev/" PPP_TUN_NAME);
		return (1);
	}

	/* Read and print names of lower streams. */
	for (i = 0; ; i++) {
		ptn.ptn_index = i;
		if (strioctl(muxfd, PPPTUN_GNNAME, &ptn, sizeof (ptn),
		    sizeof (ptn), "PPPTUN_GNNAME") < 0) {
			perror("PPPTUN_GNNAME");
			break;
		}
		/* Stop when we index off the end of the list. */
		if (ptn.ptn_name[0] == '\0')
			break;
		(void) puts(ptn.ptn_name);
	}
	return (0);
}

/*
 * Invoked by SIGALRM -- timer prevents problems in driver from
 * hanging the utility.
 */
/*ARGSUSED*/
static void
toolong(int dummy)
{
	(void) fprintf(stderr, gettext("%s: time-out in driver\n"), myname);
	exit(1);
}

int
main(int argc, char **argv)
{
	int opt, errflag = 0;
	char *arg;

	myname = *argv;


	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* Parse command line flags */
	while ((opt = getopt(argc, argv, "v")) != EOF)
		switch (opt) {
		case 'v':
			verbose++;
			break;
		default:
			errflag++;
			break;
		}
	if (errflag != 0 || optind >= argc)
		usage();

	/* Set alarm to avoid stalling on any driver errors. */
	(void) signal(SIGALRM, toolong);
	(void) alarm(2);

	/* Switch out based on user-requested function. */
	arg = argv[optind++];
	if (strcmp(arg, "plumb") == 0)
		return (plumb_it(argc, argv));
	if (strcmp(arg, "unplumb") == 0)
		return (unplumb_it(argc, argv));
	if (strcmp(arg, "query") == 0)
		return (query_interfaces(argc, argv));

	usage();
	return (1);
}
