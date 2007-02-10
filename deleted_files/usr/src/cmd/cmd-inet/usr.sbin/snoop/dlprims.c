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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"		/* SunOS */

#include	<stdlib.h>
#include	<string.h>
#include	<sys/types.h>
#include	<stropts.h>
#include	<sys/signal.h>
#include	<sys/dlpi.h>
#include	<sys/sysmacros.h>
#include	<errno.h>
#include	<stdio.h>
#include	<stdarg.h>

#include	"snoop.h"

#define	DLMAXWAIT	(10)	/* max wait in seconds for response */
#define	DLMAXBUF	(256)

static void sigalrm(int);
static void dl_msg_common(int, t_uscalar_t, t_uscalar_t, t_uscalar_t,
    t_uscalar_t, void *, int);
static int strputmsg(int, void *, size_t, int);
static int strgetmsg(int, void *, size_t *, t_uscalar_t, t_uscalar_t, size_t);
static int expecting(t_uscalar_t, t_uscalar_t, t_uscalar_t, void *, size_t);
static void syserr(const char *, ...);
static int timer_ctl(int);
static char *show_dlerror(int);

/*
 * Issue DL_INFO_REQ and wait for DL_INFO_ACK.
 */
void
dlinforeq(int fd, dl_info_ack_t *infoackp)
{
	dl_info_req_t	*dlireq;
	uint64_t	vbuf[DLMAXBUF / sizeof (uint64_t)];

	dlireq = (dl_info_req_t *)vbuf;

	dl_msg_common(fd, DL_INFO_REQ, DL_INFO_REQ_SIZE, DL_INFO_ACK,
	    DL_INFO_ACK_SIZE, dlireq, RS_HIPRI);

	/* Copy the response to the caller */
	if (infoackp != NULL)
		(void) memcpy(infoackp, vbuf, DL_INFO_ACK_SIZE);

}

/*
 * Issue DL_ATTACH_REQ and wait for DL_OK_ACK.
 */
void
dlattachreq(int fd, ulong_t ppa)
{
	dl_attach_req_t	*dlareq;
	uint64_t	vbuf[DLMAXBUF / sizeof (uint64_t)];

	dlareq = (dl_attach_req_t *)vbuf;
	dlareq->dl_ppa = ppa;

	dl_msg_common(fd, DL_ATTACH_REQ, DL_ATTACH_REQ_SIZE, DL_OK_ACK,
	    DL_OK_ACK_SIZE, dlareq, 0);

}

/*
 * Issue DL_PROMISCON_REQ and wait for DL_OK_ACK.
 */
void
dlpromiscon(int fd, int level)
{
	dl_promiscon_req_t	*dlpon;
	uint64_t		vbuf[DLMAXBUF / sizeof (uint64_t)];

	dlpon = (dl_promiscon_req_t *)vbuf;
	dlpon->dl_level = level;

	dl_msg_common(fd, DL_PROMISCON_REQ, DL_PROMISCON_REQ_SIZE, DL_OK_ACK,
	    DL_OK_ACK_SIZE, dlpon, 0);

}

/*
 * Issue DL_BIND_REQ and wait for DL_BIND_ACK
 */
void
dlbindreq(int fd, ulong_t sap, ulong_t max_conind, ushort_t service_mode,
    ushort_t conn_mgmt)
{
	dl_bind_req_t		*dlbreq;
	uint64_t		vbuf[DLMAXBUF / sizeof (uint64_t)];

	dlbreq = (dl_bind_req_t *)vbuf;
	dlbreq->dl_sap = sap;
	dlbreq->dl_max_conind = max_conind;
	dlbreq->dl_service_mode = service_mode;
	dlbreq->dl_conn_mgmt = conn_mgmt;
	dlbreq->dl_xidtest_flg = 0;

	dl_msg_common(fd, DL_BIND_REQ, DL_BIND_REQ_SIZE, DL_BIND_ACK,
	    DL_BIND_ACK_SIZE, dlbreq, 0);

}

/*
 * Common routine for dispatching and retrieving DLPI requests.
 */
static void
dl_msg_common(int fd, t_uscalar_t prim, t_uscalar_t primsz, t_uscalar_t rprim,
    t_uscalar_t rprimsz, void *dlreq, int flags)
{
	union DL_primitives	*dlp = dlreq;
	size_t			size = primsz;

	dlp->dl_primitive = prim;

	/* Start a timer */
	if (timer_ctl(DLMAXWAIT) < 0)
		syserr("snoop: Failed to start timer");

	/* Put the primitive downstream */
	if (strputmsg(fd, dlreq, size, flags) == -1) {
		syserr("snoop: error sending DLPI message to device: %s\t%s\n ",
		    (device ? device : "Unknown"), strerror(errno));
	}

	/* Retrieve and check response to issued primitve */
	if (strgetmsg(fd, dlreq, &size, prim, rprim, rprimsz) == -1) {
		syserr("snoop: error reading DLPI message from device: %s"
		    "\t%s\n ", (device ? device : "Unknown"), strerror(errno));
	}

	/* Stop the timer */
	if (timer_ctl(0)  < 0)
		syserr("snoop: Failed to stop timer");

}

static int
strputmsg(int fd, void *cbuf, size_t clen, int flags)
{
	struct strbuf	ctl;

	ctl.buf = cbuf;
	ctl.len = clen;

	return (putmsg(fd, &ctl, NULL, flags));
}

/*
 * Retrieve messages from the descriptor. Check the retrieved message
 * is the desired response to the issued primitive.
 */
static int
strgetmsg(int fd, void *cbuf, size_t *csize, t_uscalar_t prim,
    t_uscalar_t rprim, size_t rprimsz)
{
	struct strbuf   ctl;
	int		flags = 0;
	int		rc;

	ctl.buf = cbuf;
	ctl.len = 0;
	ctl.maxlen = DLMAXBUF;

	do {
		if ((rc = getmsg(fd, &ctl, NULL, &flags)) < 0)
			return (-1);

		/*
		 * The supplied DLMAXBUF sized buffers are large enough to
		 * retrieve all valid DLPI responses in one iteration.
		 * If MORECTL or MOREDATA are set this indicates that this
		 * message is NOT a response we are interested in.
		 * Temporary buffers are used to drain the remainder of this
		 * message.  The special case we have to account for is if
		 * a higher priority messages is enqueued whilst handling
		 * this condition. We use a change in the flags parameter
		 * returned by getmsg() to indicate the message has changed.
		 */
		while (rc & (MORECTL | MOREDATA)) {
			struct strbuf	cscratch, dscratch;
			uint64_t	bufc[DLMAXBUF], bufd[DLMAXBUF];
			int		oflags = flags;

			cscratch.buf = (char *)bufc;
			dscratch.buf = (char *)bufd;
			cscratch.len = dscratch.len = 0;
			cscratch.maxlen = dscratch.maxlen = sizeof (bufc);

			if ((rc = getmsg(fd, &cscratch, &dscratch, &flags)) < 0)
				return (-1);

			if ((flags != oflags) && !(rc & (MORECTL | MOREDATA)) &&
			    (cscratch.len != 0)) {
				ctl.len = MIN(cscratch.len, DLMAXBUF);
				memcpy(cbuf, bufc, ctl.len);
				break;
			}
		}
		*csize = ctl.len;
	} while (expecting(prim, rprim, rprimsz, cbuf, *csize) != 0);

	return (0);
}

/*
 * Checks the DLPI response for validity.
 */
static int
expecting(t_uscalar_t prim, t_uscalar_t rprim, t_uscalar_t rprimsz,
    void *dlpret, size_t size)
{
	union DL_primitives	*dlp = dlpret;

	/*
	 * We need at least enough space for a primitive and a
	 * buffer to interpret.
	 */
	if ((dlp == NULL) || (size < sizeof (t_uscalar_t)))
		return (-1);

	if (dlp->dl_primitive == DL_ERROR_ACK) {
		/*
		 * Fatal Error. However, first check that it's big
		 * enough to be a DL_ERROR_ACK and that it also in
		 * response to the primitive we issued
		 */
		dl_error_ack_t  *dlerr = (dl_error_ack_t *)dlp;

		if (size < DL_ERROR_ACK_SIZE)
			return (-1);

		/* Is it ours? */
		if (dlerr->dl_error_primitive != prim)
			return (-1);

		/* As close as we can establish, it's our error */
		syserr("snoop: fatal DLPI error: %d\t%s\nDevice: %s\n",
		    dlerr->dl_errno, show_dlerror(dlerr->dl_errno),
		    (device ? device : "Unknown"));
	}

	/*
	 * Check to see if the returned primitive is what we were
	 * expecting and if it is large enough to contain the minimum
	 * size.
	 */
	if ((dlp->dl_primitive != rprim) || (size < rprimsz))
		return (-1);

	return (0);

}

static char *
show_dlerror(int dl_errno)
{
	switch (dl_errno) {
	case DL_ACCESS:
		return ("Improper permissions for request");
	case DL_BADADDR:
		return ("DLSAP addr in improper format or invalid");
	case DL_BADCORR:
		return ("Seq number not from outstand DL_CONN_IND");
	case DL_BADDATA:
		return ("User data exceeded provider limit");
	case DL_BADPPA:
		return ("Specified PPA was invalid");
	case DL_BADPRIM:
		return ("Primitive received not known by provider");
	case DL_BADQOSPARAM:
		return ("QOS parameters contained invalid values");
	case DL_BADQOSTYPE:
		return ("QOS structure type is unknown/unsupported");
	case DL_BADSAP:
		return ("Bad LSAP selector");
	case DL_BADTOKEN:
		return ("Token used not an active stream");
	case DL_BOUND:
		return ("Attempted second bind with dl_max_conind");
	case DL_INITFAILED:
		return ("Physical Link initialization failed");
	case DL_NOADDR:
		return ("Provider couldn't allocate alt. address");
	case DL_NOTINIT:
		return ("Physical Link not initialized");
	case DL_OUTSTATE:
		return ("Primitive issued in improper state");
	case DL_SYSERR:
		return ("UNIX system error occurred");
	case DL_UNSUPPORTED:
		return ("Requested serv. not supplied by provider");
	case DL_UNDELIVERABLE:
		return ("Previous data unit could not be delivered");
	case DL_NOTSUPPORTED:
		return ("Primitive is known but not supported");
	case DL_TOOMANY:
		return ("Limit exceeded");
	case DL_NOTENAB:
		return ("Promiscuous mode not enabled");
	case DL_BUSY:
		return ("Other streams for PPA in post-attached");
	case DL_NOAUTO:
		return ("Automatic handling XID&TEST not supported");
	case DL_NOXIDAUTO:
		return ("Automatic handling of XID not supported");
	case DL_NOTESTAUTO:
		return ("Automatic handling of TEST not supported");
	case DL_XIDAUTO:
		return ("Automatic handling of XID response");
	case DL_TESTAUTO:
		return ("Automatic handling of TEST response");
	case DL_PENDING:
		return ("Pending outstanding connect indications");
	}
	return ("Unknown DLPI error");
}

static void
syserr(const char *format, ...)
{
	va_list	alist;

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	(void) fprintf(stderr, "\n");
	exit(1);
}

static int
timer_ctl(int timeout)
{
	return (snoop_alarm(timeout, sigalrm));
}

/* ARGSUSED */
static void
sigalrm(int unused)
{
	syserr("sigalrm:  TIMEOUT");
}
