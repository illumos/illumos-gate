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

/* FIXME: from snoop. Use common library when it comes into existence */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stropts.h>
#include <sys/signal.h>
#include <sys/dlpi.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stropts.h>
#include <stdlib.h>
#include <ctype.h>
#include <values.h>

#define	DLMAXWAIT	(10)	/* max wait in seconds for response */
#define	DLMAXBUF	(80)

typedef union dlbuf {
	union DL_primitives dl;
	char *buf[DLMAXBUF];
} dlbuf_t;

static int	timed_getmsg(int, struct strbuf *, struct strbuf *, int *, int);
static boolean_t	expecting(ulong_t, union DL_primitives *);

/*
 * Issue DL_INFO_REQ and wait for DL_INFO_ACK.
 */
static int
dlinforeq(int fd, dl_info_ack_t *infoackp)
{
	dlbuf_t	buf;
	struct	strbuf	ctl;
	int	flags;

	buf.dl.info_req.dl_primitive = DL_INFO_REQ;

	ctl.maxlen = sizeof (buf);
	ctl.len = DL_INFO_REQ_SIZE;
	ctl.buf = (char *)&buf.dl;

	flags = RS_HIPRI;

	if (putmsg(fd, &ctl, NULL, flags) < 0)
		return (-1);
	if (timed_getmsg(fd, &ctl, NULL, &flags, DLMAXWAIT) != 0)
		return (-1);

	if (!expecting(DL_INFO_ACK, &buf.dl))
		return (-1);

	if (ctl.len < DL_INFO_ACK_SIZE)
		return (-1);
	if (flags != RS_HIPRI)
		return (-1);
	if (infoackp != NULL)
		*infoackp = buf.dl.info_ack;
	return (0);
}

/*
 * Issue DL_ATTACH_REQ.
 * Return zero on success, nonzero on error.
 */
static int
dlattachreq(int fd, ulong_t ppa)
{
	dlbuf_t	buf;
	struct	strbuf	ctl;
	int	flags;

	buf.dl.attach_req.dl_primitive = DL_ATTACH_REQ;
	buf.dl.attach_req.dl_ppa = ppa;

	ctl.maxlen = sizeof (buf.dl);
	ctl.len = DL_ATTACH_REQ_SIZE;
	ctl.buf = (char *)&buf.dl;

	flags = 0;

	if (putmsg(fd, &ctl, NULL, flags) < 0)
		return (-1);
	if (timed_getmsg(fd, &ctl, NULL, &flags, DLMAXWAIT) != 0)
		return (-1);

	if (!expecting(DL_OK_ACK, &buf.dl))
		return (-1);
	return (0);
}

static int
timed_getmsg(int fd, struct strbuf *ctlp, struct strbuf *datap, int *flagsp,
    int timeout)
{
	struct pollfd	pfd;
	int		rc;

	pfd.fd = fd;

	pfd.events = POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;
	if ((rc = poll(&pfd, 1, timeout * 1000)) == 0)
		return (0);
	else if (rc == -1)
		return (0);

	/* poll returned > 0 for this fd so getmsg should not block */
	*flagsp = 0;

	if ((rc = getmsg(fd, ctlp, datap, flagsp)) < 0)
		return (0);

	/*
	 * Check for MOREDATA and/or MORECTL.
	 */
	if ((rc & (MORECTL | MOREDATA)) == (MORECTL | MOREDATA))
		return (-1);
	if (rc & MORECTL)
		return (-1);
	if (rc & MOREDATA)
		return (-1);
	/*
	 * Check for at least sizeof (long) control data portion.
	 */
	if (ctlp->len < sizeof (long))
		return (-1);
	return (0);
}

static boolean_t
expecting(ulong_t prim, union DL_primitives *dlp)
{
	if (dlp->dl_primitive == DL_ERROR_ACK || dlp->dl_primitive != prim)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Convert a device id to a ppa value
 * e.g. "le0" -> 0
 */
static int
device_ppa(char *device)
{
	char *p;
	char *tp;

	p = strpbrk(device, "0123456789");
	if (p == NULL)
		return (0);
	/* ignore numbers within device names */
	for (tp = p; *tp != '\0'; tp++)
		if (!isdigit(*tp))
			return (device_ppa(tp));
	return (atoi(p));
}

/*
 * Convert a device id to a pathname.
 * DLPI style 1 devices: "le0" -> "/dev/le0".
 * DLPI style 2 devices: "le0" -> "/dev/le".
 */
static char *
device_path(char *device)
{
	static char buff[IF_NAMESIZE + 1];
	struct stat st;
	char *p;

	(void) strcpy(buff, "/dev/");
	(void) strlcat(buff, device, IF_NAMESIZE);

	if (stat(buff, &st) == 0)
		return (buff);

	for (p = buff + (strlen(buff) - 1); p > buff; p--) {
		if (isdigit(*p))
			*p = '\0';
		else
			break;
	}
	return (buff);
}

/*
 * Open up the device, and attach if needed.
 */
int
ifname_open(char *device)
{
	char *devname;
	ulong_t ppa;
	int netfd;
	dl_info_ack_t	netdl;

	/*
	 * Determine which network device
	 * to use if none given.
	 * Should get back a value like "/dev/le0".
	 */

	devname = device_path(device);
	if ((netfd = open(devname, O_RDWR)) < 0)
		return (-1);

	ppa = device_ppa(device);

	/*
	 * Check for DLPI Version 2.
	 */
	if (dlinforeq(netfd, &netdl) != 0) {
		(void) close(netfd);
		return (-1);
	}

	if (netdl.dl_version != DL_VERSION_2) {
		(void) close(netfd);
		return (-1);
	}

	/*
	 * Attach for DLPI Style 2.
	 */
	if (netdl.dl_provider_style == DL_STYLE2) {
		if (dlattachreq(netfd, ppa) != 0) {
			(void) close(netfd);
			return (-1);
		}

		/* Reread more specific information */
		if (dlinforeq(netfd, &netdl) != 0) {
			(void) close(netfd);
			return (-1);
		}
	}

	return (netfd);
}
