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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"		/* SunOS */

#include	<sys/types.h>
#include	<sys/stropts.h>
#include	<sys/signal.h>
#include	<sys/dlpi.h>
#include	<stdio.h>
#include	<stdarg.h>

#include	"snoop.h"

#define	DLMAXWAIT	(10)	/* max wait in seconds for response */
#define	DLMAXBUF	(256)


static void sigalrm(int);
static void strgetmsg(int, struct strbuf *, struct strbuf *, int *, char *);
static void err(const char *, ...);
static void syserr(char *);

/*
 * Issue DL_INFO_REQ and wait for DL_INFO_ACK.
 */
void
dlinforeq(int fd, dl_info_ack_t *infoackp)
{
	union	DL_primitives	*dlp;
	char	buf[DLMAXBUF];
	struct	strbuf	ctl;
	int	flags;

	dlp = (union DL_primitives *)buf;

	dlp->info_req.dl_primitive = DL_INFO_REQ;

	ctl.maxlen = DLMAXBUF;
	ctl.len = DL_INFO_REQ_SIZE;
	ctl.buf = (char *)dlp;

	flags = RS_HIPRI;

	if (putmsg(fd, &ctl, NULL, flags) < 0)
		syserr("dlinforeq:  putmsg");

	strgetmsg(fd, &ctl, NULL, &flags, "dlinfoack");
	expecting(DL_INFO_ACK, dlp, "dlinfoack");

	if (ctl.len < DL_INFO_ACK_SIZE)
		err("dlinfoack:  response ctl.len too short:  %d", ctl.len);

	if (flags != RS_HIPRI)
		err("dlinfoack:  DL_INFO_ACK was not M_PCPROTO");

	if (infoackp)
		*infoackp = dlp->info_ack;
}

/*
 * Issue DL_ATTACH_REQ.
 * Return zero on success, nonzero on error.
 */
void
dlattachreq(int fd, ulong_t ppa)
{
	union	DL_primitives	*dlp;
	char	buf[DLMAXBUF];
	struct	strbuf	ctl;
	int	flags;

	dlp = (union DL_primitives *)buf;

	dlp->attach_req.dl_primitive = DL_ATTACH_REQ;
	dlp->attach_req.dl_ppa = ppa;

	ctl.maxlen = DLMAXBUF;
	ctl.len = DL_ATTACH_REQ_SIZE;
	ctl.buf = (char *)dlp;

	flags = 0;

	if (putmsg(fd, &ctl, NULL, flags) < 0)
		syserr("dlattachreq:  putmsg");

	strgetmsg(fd, &ctl, NULL, &flags, "dlattachreq");
	expecting(DL_OK_ACK, dlp, "dlattachreq");
}

/*
 * Issue DL_PROMISCON_REQ and wait for DL_OK_ACK.
 */
void
dlpromiscon(int fd, int level)
{
	union	DL_primitives	*dlp;
	char	buf[DLMAXBUF];
	struct	strbuf	ctl;
	int	flags;

	dlp = (union DL_primitives *)buf;

	dlp->promiscon_req.dl_primitive = DL_PROMISCON_REQ;
	dlp->promiscon_req.dl_level = level;

	ctl.maxlen = DLMAXBUF;
	ctl.len = DL_PROMISCON_REQ_SIZE;
	ctl.buf = (char *)dlp;

	flags = 0;

	if (putmsg(fd, &ctl, NULL, flags) < 0)
		syserr("dlpromiscon:  putmsg");

	strgetmsg(fd, &ctl, NULL, &flags, "dlpromisconreq");
	expecting(DL_OK_ACK, dlp, "dlpromisconreq");
}

void
dlbindreq(int fd, ulong_t sap, ulong_t max_conind, ushort_t service_mode,
    ushort_t conn_mgmt)
{
	union	DL_primitives	*dlp;
	char	buf[DLMAXBUF];
	struct	strbuf	ctl;
	int	flags;

	dlp = (union DL_primitives *)buf;

	dlp->bind_req.dl_primitive = DL_BIND_REQ;
	dlp->bind_req.dl_sap = sap;
	dlp->bind_req.dl_max_conind = max_conind;
	dlp->bind_req.dl_service_mode = service_mode;
	dlp->bind_req.dl_conn_mgmt = conn_mgmt;
	dlp->bind_req.dl_xidtest_flg = 0;

	ctl.maxlen = DLMAXBUF;
	ctl.len = DL_BIND_REQ_SIZE;
	ctl.buf = (char *)dlp;

	flags = 0;

	if (putmsg(fd, &ctl, NULL, flags) < 0)
		syserr("dlbindreq:  putmsg");

	ctl.len = 0;

	strgetmsg(fd, &ctl, NULL, &flags, "dlbindack");
	expecting(DL_BIND_ACK, dlp, "dlbindack");

	if (ctl.len < sizeof (DL_BIND_ACK_SIZE))
		err("dlbindack:  response ctl.len too short:  %d", ctl.len);
}

/* ARGSUSED */
static void
sigalrm(int unused)
{
	(void) err("sigalrm:  TIMEOUT");
}

void
strgetmsg(int fd, struct strbuf *ctlp, struct strbuf *datap, int *flagsp,
    char *caller)
{
	int	rc;
	static	char	errmsg[80];

	/*
	 * Start timer.
	 */
	if (snoop_alarm(DLMAXWAIT, sigalrm) < 0) {
		sprintf(errmsg, "%s:  alarm", caller);
		syserr(errmsg);
	}

	/*
	 * Set flags argument and issue getmsg().
	 */
	*flagsp = 0;
	if ((rc = getmsg(fd, ctlp, datap, flagsp)) < 0) {
		sprintf(errmsg, "%s:  getmsg", caller);
		syserr(errmsg);
	}

	/*
	 * Stop timer.
	 */
	if (snoop_alarm(0, sigalrm) < 0) {
		sprintf(errmsg, "%s:  alarm", caller);
		syserr(errmsg);
	}

	/*
	 * Check for MOREDATA and/or MORECTL.
	 */
	if ((rc & (MORECTL | MOREDATA)) == (MORECTL | MOREDATA))
		err("%s:  strgetmsg:  MORECTL|MOREDATA", caller);
	if (rc & MORECTL)
		err("%s:  strgetmsg:  MORECTL", caller);
	if (rc & MOREDATA)
		err("%s:  strgetmsg:  MOREDATA", caller);

	/*
	 * Check for at least sizeof (long) control data portion.
	 */
	if (ctlp->len < sizeof (long))
		err("%s:  control portion length < sizeof (long)",
		caller);
}

char *
show_dltype(int dl_errno)
{
	switch (dl_errno) {
	case DL_ACCESS:	/* Improper permissions for request */
		return ("Improper permissions for request");
	case DL_BADADDR:
		return ("DLSAP addr in improper format or invalid");
	case DL_BADCORR:	/* Seq number not from outstand DL_CONN_IND */
		return ("Seq number not from outstand DL_CONN_IND");
	case DL_BADDATA:	/* User data exceeded provider limit */
		return ("User data exceeded provider limit");
	case DL_BADPPA:	/* Specified PPA was invalid */
		return ("Specified PPA was invalid");
	case DL_BADPRIM:	/* Primitive received not known by provider */
		return ("Primitive received not known by provider");
	case DL_BADQOSPARAM:	/* QOS parameters contained invalid values */
		return ("QOS parameters contained invalid values");
	case DL_BADQOSTYPE:	/* QOS structure type is unknown/unsupported */
		return ("QOS structure type is unknown/unsupported");
	case DL_BADSAP:	/* Bad LSAP selector */
		return ("Bad LSAP selector");
	case DL_BADTOKEN:	/* Token used not an active stream */
		return ("Token used not an active stream");
	case DL_BOUND:	/* Attempted second bind with dl_max_conind */
		return ("Attempted second bind with dl_max_conind");
	case DL_INITFAILED:	/* Physical Link initialization failed */
		return ("Physical Link initialization failed");
	case DL_NOADDR:	/* Provider couldn't allocate alt. address */
		return ("Provider couldn't allocate alt. address");
	case DL_NOTINIT:	/* Physical Link not initialized */
		return ("Physical Link not initialized");
	case DL_OUTSTATE:	/* Primitive issued in improper state */
		return ("Primitive issued in improper state");
	case DL_SYSERR:	/* UNIX system error occurred */
		return ("UNIX system error occurred");
	case DL_UNSUPPORTED:	/* Requested serv. not supplied by provider */
		return ("Requested serv. not supplied by provider");
	case DL_UNDELIVERABLE:	/* Previous data unit could not be delivered */
		return ("Previous data unit could not be delivered");
	case DL_NOTSUPPORTED:	/* Primitive is known but not supported */
		return ("Primitive is known but not supported");
	case DL_TOOMANY:	/* limit exceeded	*/
		return ("Limit exceeded");
	case DL_NOTENAB:	/* Promiscuous mode not enabled */
		return ("Promiscuous mode not enabled");
	case DL_BUSY:	/* Other streams for PPA in post-attached */
		return ("Other streams for PPA in post-attached");
	case DL_NOAUTO:	/* Automatic handling XID&TEST not supported */
		return ("Automatic handling XID&TEST not supported");
	case DL_NOXIDAUTO:    /* Automatic handling of XID not supported */
		return ("Automatic handling of XID not supported");
	case DL_NOTESTAUTO:	/* Automatic handling of TEST not supported */
		return ("Automatic handling of TEST not supported");
	case DL_XIDAUTO:	/* Automatic handling of XID response */
		return ("Automatic handling of XID response");
	case DL_TESTAUTO:	/* AUtomatic handling of TEST response */
		return ("Automatic handling of TEST response");
	case DL_PENDING:	/* pending outstanding connect indications */
		return ("Pending outstanding connect indications");
	}
	return ("Unknown DLPI error");
}

int
expecting(ulong_t prim, union DL_primitives *dlp, char *caller)
{
	if (dlp->dl_primitive == DL_ERROR_ACK) {
		fprintf(stderr, "fatal dlpi error: %s. Device %s\n",
			show_dltype(dlp->error_ack.dl_errno),
			device ? device : "unknown");
		err("%s:  DL_ERROR_ACK:  dl_errno %d unix_errno %d\n",
		caller,
		dlp->error_ack.dl_errno,
		dlp->error_ack.dl_unix_errno);
		return (1);
	}

	if (dlp->dl_primitive != prim) {
		err("%s:  unexpected primitive 0x%x received\n",
		caller,
		dlp->dl_primitive);
		return (1);
	}

	return (0);
}

static void
err(const char *format, ...)
{
	va_list	alist;

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	(void) fprintf(stderr, "\n");
	exit(1);
}

void
syserr(char *s)
{
	perror(s);
	exit(1);
}
