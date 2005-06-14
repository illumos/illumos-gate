/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <alloca.h>
#include <stropts.h>
#include <fcntl.h>
#include <locale.h>
#include <sys/dlpi.h>
#include <sys/fcntl.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/sppptun.h>

static char *myname;		/* Copied from argv[0] */
static int verbose;		/* -v on command line */

/* Data gathered during per-style attach routine. */
struct attach_data {
	ppptun_lname appstr;	/* String to append to interface name (PPA) */
	ppptun_atype localaddr;	/* Local interface address */
	int locallen;		/* Length of local address */
};

/* Per-protocol plumbing data */
struct protos {
	const char *name;
	const char *desc;
	int (*attach)(struct protos *prot, char *ifname,
	    struct attach_data *adata);
	int protval;
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
 * Await a DLPI response to a previous driver command.  "etype" is set
 * to the expected response primitive.  "rptr" and "rlen" may point to
 * a buffer to hold returned data, if desired.  Otherwise, "rptr" is
 * NULL.  Returns -1 on error, 0 on success.
 *
 * If "rlen" is a positive number, then it indicates the number of
 * bytes expected in return, and any longer response is truncated to
 * that value, and any shorter response generates a warning message.
 * If it's a negative number, then it indicates the maximum number of
 * bytes expected, and no warning is printed if fewer are received.
 */
static int
dlpi_reply(int fd, int etype, void *rptr, int rlen)
{
	/* Align 'buf' on natural boundary for aggregates. */
	uintptr_t buf[BUFSIZ/sizeof (uintptr_t)];
	int flags;
	union DL_primitives *dlp = (union DL_primitives *)buf;
	struct strbuf  ctl;

	/* read reply */
	ctl.buf = (caddr_t)dlp;
	ctl.len = 0;
	ctl.maxlen = BUFSIZ;
	flags = 0;
	if (getmsg(fd, &ctl, NULL, &flags) < 0) {
		perror("getmsg");
		return (-1);
	}

	/* Validate reply.  */
	if (ctl.len < sizeof (t_uscalar_t)) {
		(void) fprintf(stderr, gettext("%s: request: short reply\n"),
		    myname);
		return (-1);
	}

	if (dlp->dl_primitive == DL_ERROR_ACK) {
		(void) fprintf(stderr,
		    gettext("%s: request:  dl_errno %lu errno %lu\n"), myname,
		    dlp->error_ack.dl_errno, dlp->error_ack.dl_unix_errno);
		return (-1);
	}
	if (dlp->dl_primitive != etype) {
		(void) fprintf(stderr, gettext("%s: request: unexpected "
		    "dl_primitive %lu received\n"), myname, dlp->dl_primitive);
		return (-1);
	}
	if (rptr == NULL)
		return (0);
	if (ctl.len < rlen) {
		(void) fprintf(stderr, gettext("%s: request: short information"
		    " received %d < %d\n"), myname, ctl.len, rlen);
		return (-1);
	}
	if (rlen < 0)
		rlen = -rlen;
	(void) memcpy(rptr, buf, rlen);
	return (0);
}

/*
 * Send a DLPI Info-Request message and return the response in the
 * provided buffer.  Returns -1 on error, 0 on success.
 */
static int
dlpi_info_req(int fd, dl_info_ack_t *info_ack)
{
	dl_info_req_t info_req;
	struct strbuf ctl;
	int flags;

	(void) memset(&info_req, '\0', sizeof (info_req));
	info_req.dl_primitive = DL_INFO_REQ;

	ctl.maxlen = 0;
	ctl.len = DL_INFO_REQ_SIZE;
	ctl.buf = (char *)&info_req;

	flags = 0;
	if (putmsg(fd, &ctl, (struct strbuf *)NULL, flags) < 0) {
		perror("putmsg DL_INFO_REQ");
		return (-1);
	}
	return (dlpi_reply(fd, DL_INFO_ACK, info_ack, sizeof (*info_ack)));
}

/*
 * Send a DLPI Attach-Request message for the indicated PPA.  Returns
 * -1 on error, 0 for success.
 */
static int
dlpi_attach_req(int fd, int ppa)
{
	dl_attach_req_t attach_req;
	struct strbuf ctl;
	int flags;

	(void) memset(&attach_req, '\0', sizeof (attach_req));
	attach_req.dl_primitive = DL_ATTACH_REQ;
	attach_req.dl_ppa = ppa;

	ctl.maxlen = 0;
	ctl.len = DL_ATTACH_REQ_SIZE;
	ctl.buf = (char *)&attach_req;

	flags = 0;
	if (putmsg(fd, &ctl, (struct strbuf *)NULL, flags) < 0) {
		perror("putmsg DL_ATTACH_REQ");
		return (-1);
	}
	return (dlpi_reply(fd, DL_OK_ACK, NULL, 0));
}

/*
 * Send a DLPI Bind-Request message for the requested SAP and set the
 * local address.  Returns -1 for error.  Otherwise, the length of the
 * local address is returned.
 */
static int
dlpi_bind_req(int fd, int sap, uint8_t *localaddr, int maxaddr)
{
	dl_bind_req_t bind_req;
	dl_bind_ack_t *back;
	struct strbuf ctl;
	int flags, repsize, rsize;

	(void) memset(&bind_req, '\0', sizeof (*&bind_req));
	bind_req.dl_primitive = DL_BIND_REQ;
	/* DLPI SAPs are in host byte order! */
	bind_req.dl_sap = sap;
	bind_req.dl_service_mode = DL_CLDLS;

	ctl.maxlen = 0;
	ctl.len = DL_BIND_REQ_SIZE;
	ctl.buf = (char *)&bind_req;

	flags = 0;
	if (putmsg(fd, &ctl, (struct strbuf *)NULL, flags) < 0) {
		perror("putmsg DL_BIND_REQ");
		return (-1);
	}

	repsize = sizeof (*back) + maxaddr;
	back = (dl_bind_ack_t *)alloca(repsize);
	if (dlpi_reply(fd, DL_BIND_ACK, (void *)back, -repsize) < 0)
		return (-1);
	rsize = back->dl_addr_length;
	if (rsize > maxaddr || back->dl_addr_offset+rsize > repsize) {
		(void) fprintf(stderr, gettext("%s: Bad hardware address size "
		    "from driver; %d > %d or %lu+%d > %d\n"), myname,
		    rsize, maxaddr, back->dl_addr_offset, rsize, repsize);
		return (-1);
	}
	(void) memcpy(localaddr, (char *)back + back->dl_addr_offset, rsize);
	return (rsize);
}

/*
 * Return a printable string for a DLPI style number.  (Unfortunately,
 * these style numbers aren't just simple integer values, and printing
 * with %d gives ugly output.)
 */
static const char *
styleof(int dlstyle)
{
	static char buf[32];

	switch (dlstyle) {
	case DL_STYLE1:
		return ("1");
	case DL_STYLE2:
		return ("2");
	}
	(void) snprintf(buf, sizeof (buf), gettext("Unknown (0x%04X)"),
	    dlstyle);
	return ((const char *)buf);
}

/*
 * General DLPI attach function.  This is called indirectly through
 * the protos structure for the selected lower stream protocol.
 */
static int
dlpi_attach(struct protos *prot, char *ifname, struct attach_data *adata)
{
	int devfd, ppa, dlstyle, retv;
	dl_info_ack_t dl_info;
	char tname[MAXPATHLEN], *cp;

	cp = ifname + strlen(ifname) - 1;
	while (cp > ifname && isdigit(*cp))
		cp--;
	cp++;
	ppa = strtol(cp, NULL, 10);

	/*
	 * Try once for the exact device name as a node.  If it's
	 * there, then this should be a DLPI style 1 driver (one node
	 * per instance).  If it's not, then it should be a style 2
	 * driver (attach specifies instance number).
	 */
	dlstyle = DL_STYLE1;
	(void) strlcpy(tname, ifname, MAXPATHLEN-1);
	if ((devfd = open(tname, O_RDWR)) < 0) {
		if (cp < ifname + MAXPATHLEN)
			tname[cp - ifname] = '\0';
		if ((devfd = open(tname, O_RDWR)) < 0) {
			perror(ifname);
			return (-1);
		}
		dlstyle = DL_STYLE2;
	}

	if (verbose)
		(void) printf(gettext("requesting device info on %s\n"),
		    tname);
	if (dlpi_info_req(devfd, &dl_info))
		return (-1);
	if (dl_info.dl_provider_style != dlstyle) {
		(void) fprintf(stderr, gettext("%s: unexpected DLPI provider "
		    "style on %s: got %s, "), myname, tname,
		    styleof(dl_info.dl_provider_style));
		(void) fprintf(stderr, gettext("expected %s\n"),
		    styleof(dlstyle));
		if (ifname[0] != '\0' &&
		    !isdigit(ifname[strlen(ifname) - 1])) {
			(void) fprintf(stderr, gettext("(did you forget an "
			    "instance number?)\n"));
		}
		(void) close(devfd);
		return (-1);
	}

	if (dlstyle == DL_STYLE2) {
		if (verbose)
			(void) printf(gettext("attaching to ppa %d\n"), ppa);
		if (dlpi_attach_req(devfd, ppa)) {
			(void) close(devfd);
			return (-1);
		}
	}

	if (verbose)
		(void) printf(gettext("binding to Ethertype %04X\n"),
		    prot->protval);
	retv = dlpi_bind_req(devfd, prot->protval,
	    (uint8_t *)&adata->localaddr, sizeof (adata->localaddr));
	if (retv < 0) {
		(void) close(devfd);
		return (-1);
	}
	adata->locallen = retv;

	(void) snprintf(adata->appstr, sizeof (adata->appstr), "%d", ppa);
	return (devfd);
}


static struct protos proto_list[] = {
	{ "pppoe", "RFC 2516 PPP over Ethernet", dlpi_attach, ETHERTYPE_PPPOES,
	    PTS_PPPOE },
	{ "pppoed", "RFC 2516 PPP over Ethernet Discovery", dlpi_attach,
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
	char *cp, *ifname;
	struct protos *prot;
	char dname[MAXPATHLEN];
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

	/* Get interface and make relative to /dev/ if necessary. */
	ifname = argv[optind];
	if (ifname[0] != '.' && ifname[0] != '/') {
		(void) snprintf(dname, sizeof (dname), "/dev/%s", ifname);
		ifname = dname;
	}

	/* Call per-protocol attach routine to open device */
	if (verbose)
		(void) printf(gettext("opening %s\n"), ifname);
	devfd = (*prot->attach)(prot, ifname, &adata);
	if (devfd < 0)
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
		    ifname);
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
