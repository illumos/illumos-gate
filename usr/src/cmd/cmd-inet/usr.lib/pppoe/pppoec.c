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
 * PPPoE Client-mode "chat" utility for use with Solaris PPP 4.0.
 *
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stropts.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net/sppptun.h>
#include <net/pppoe.h>

#include "common.h"
#include "logging.h"

/*
 * This value, currently set to the characters "POE1," is used to
 * distinguish among control messages from multiple lower streams
 * under /dev/sppp.  This feature is needed to support PPP translation
 * (LAC-like behavior), but isn't currently used.
 */
#define	PPPOE_DISCRIM	0x504F4531

/* milliseconds between retries */
#define	PADI_RESTART_TIME	500
#define	PADR_RESTART_TIME	2000

/* default inquiry mode timer in milliseconds. */
#define	PADI_INQUIRY_DWELL	3000

/* maximum timer value in milliseconds */
#define	RESTART_LIMIT	5000

char *myname;		/* copy of argv[0] for error messages */
static int verbose;	/* -v flag given */
static int onlyflag;	/* keyword "only" at end of command line */
static char *service = "";	/* saved service name from command line */

static int pado_wait_time = 0;	/* see main() */
static int pads_wait_time = PADR_RESTART_TIME;

static int tunfd;	/* open connection to sppptun driver */

static struct timeval tvstart;	/* time of last PADI/PADR transmission */

struct server_filter {
	struct server_filter *sf_next;	/* Next filter in list */
	struct ether_addr sf_mac;	/* Ethernet address */
	struct ether_addr sf_mask;	/* Mask (0 or 0xFF in each byte) */
	const char *sf_name;		/* String for AC-Name compare */
	boolean_t sf_hasmac;		/* Set if string could be MAC */
	boolean_t sf_isexcept;		/* Ignore server if matching */
};

/* List of filters defined on command line. */
static struct server_filter *sfhead, *sftail;

/*
 * PPPoE Client State Machine
 */

/* Client events */
#define	PCSME_CLOSE	0	/* User close */
#define	PCSME_OPEN	1	/* User open */
#define	PCSME_TOP	2	/* Timeout+ (counter non-zero) */
#define	PCSME_TOM	3	/* Timeout- (counter zero) */
#define	PCSME_RPADT	4	/* Receive PADT (unexpected here) */
#define	PCSME_RPADOP	5	/* Receive desired PADO */
#define	PCSME_RPADO	6	/* Receive ordinary PADO */
#define	PCSME_RPADS	7	/* Receive PADS */
#define	PCSME_RPADSN	8	/* Receive bad (errored) PADS */
#define	PCSME__MAX	9

/* Client states */
#define	PCSMS_DEAD	0	/* Initial state */
#define	PCSMS_INITSENT	1	/* PADI sent */
#define	PCSMS_OFFRRCVD	2	/* PADO received */
#define	PCSMS_REQSENT	3	/* PADR sent */
#define	PCSMS_CONVERS	4	/* Conversational */
#define	PCSMS__MAX	5

/* Client actions */
#define	PCSMA_NONE	0	/* Do nothing */
#define	PCSMA_FAIL	1	/* Unrecoverable error */
#define	PCSMA_SPADI	2	/* Send PADI */
#define	PCSMA_ADD	3	/* Add ordinary server to list */
#define	PCSMA_SPADR	4	/* Send PADR to top server */
#define	PCSMA_SPADRP	5	/* Send PADR to this server (make top) */
#define	PCSMA_SPADRN	6	/* Send PADR to next (or terminate) */
#define	PCSMA_OPEN	7	/* Start PPP */
#define	PCSMA__MAX	8

static uint8_t client_next_state[PCSMS__MAX][PCSME__MAX] = {
/* 0 PCSMS_DEAD Initial state */
	{
		PCSMS_DEAD,	/* PCSME_CLOSE  User close */
		PCSMS_INITSENT,	/* PCSME_OPEN   User open */
		PCSMS_DEAD,	/* PCSME_TOP    Timeout+ */
		PCSMS_DEAD,	/* PCSME_TOM    Timeout- */
		PCSMS_DEAD,	/* PCSME_RPADT  Receive PADT */
		PCSMS_DEAD,	/* PCSME_RPADOP Receive desired PADO */
		PCSMS_DEAD,	/* PCSME_RPADO  Receive ordinary PADO */
		PCSMS_DEAD,	/* PCSME_RPADS  Receive PADS */
		PCSMS_DEAD,	/* PCSME_RPADSN Receive bad PADS */
	},
/* 1 PCSMS_INITSENT PADI sent */
	{
		PCSMS_DEAD,	/* PCSME_CLOSE  User close */
		PCSMS_INITSENT,	/* PCSME_OPEN   User open */
		PCSMS_INITSENT,	/* PCSME_TOP    Timeout+ */
		PCSMS_DEAD,	/* PCSME_TOM    Timeout- */
		PCSMS_DEAD,	/* PCSME_RPADT  Receive PADT */
		PCSMS_REQSENT,	/* PCSME_RPADOP Receive desired PADO */
		PCSMS_OFFRRCVD,	/* PCSME_RPADO  Receive ordinary PADO */
		PCSMS_INITSENT,	/* PCSME_RPADS  Receive PADS */
		PCSMS_INITSENT,	/* PCSME_RPADSN Receive bad PADS */
	},
/* 2 PCSMS_OFFRRCVD PADO received */
	{
		PCSMS_DEAD,	/* PCSME_CLOSE  User close */
		PCSMS_INITSENT,	/* PCSME_OPEN   User open */
		PCSMS_REQSENT,	/* PCSME_TOP    Timeout+ */
		PCSMS_REQSENT,	/* PCSME_TOM    Timeout- */
		PCSMS_DEAD,	/* PCSME_RPADT  Receive PADT */
		PCSMS_REQSENT,	/* PCSME_RPADOP Receive desired PADO */
		PCSMS_OFFRRCVD,	/* PCSME_RPADO  Receive ordinary PADO */
		PCSMS_OFFRRCVD,	/* PCSME_RPADS  Receive PADS */
		PCSMS_OFFRRCVD,	/* PCSME_RPADSN Receive bad PADS */
	},
/* 3 PCSMS_REQSENT  PADR sent */
	{
		PCSMS_DEAD,	/* PCSME_CLOSE  User close */
		PCSMS_INITSENT,	/* PCSME_OPEN   User open */
		PCSMS_REQSENT,	/* PCSME_TOP    Timeout+ */
		PCSMS_REQSENT,	/* PCSME_TOM    Timeout- */
		PCSMS_DEAD,	/* PCSME_RPADT  Receive PADT */
		PCSMS_REQSENT,	/* PCSME_RPADOP Receive desired PADO */
		PCSMS_REQSENT,	/* PCSME_RPADO  Receive ordinary PADO */
		PCSMS_CONVERS,	/* PCSME_RPADS  Receive PADS */
		PCSMS_REQSENT,	/* PCSME_RPADSN Receive bad PADS */
	},
/* 4 PCSMS_CONVERS  Conversational */
	{
		PCSMS_DEAD,	/* PCSME_CLOSE  User close */
		PCSMS_INITSENT,	/* PCSME_OPEN   User open */
		PCSMS_CONVERS,	/* PCSME_TOP    Timeout+ */
		PCSMS_CONVERS,	/* PCSME_TOM    Timeout- */
		PCSMS_DEAD,	/* PCSME_RPADT  Receive PADT */
		PCSMS_CONVERS,	/* PCSME_RPADOP Receive desired PADO */
		PCSMS_CONVERS,	/* PCSME_RPADO  Receive ordinary PADO */
		PCSMS_CONVERS,	/* PCSME_RPADS  Receive PADS */
		PCSMS_CONVERS,	/* PCSME_RPADSN Receive bad PADS */
	},
};

static uint8_t client_action[PCSMS__MAX][PCSME__MAX] = {
/* 0 PCSMS_DEAD Initial state */
	{
		PCSMA_NONE,	/* PCSME_CLOSE  User close */
		PCSMA_SPADI,	/* PCSME_OPEN   User open */
		PCSMA_NONE,	/* PCSME_TOP    Timeout+ */
		PCSMA_NONE,	/* PCSME_TOM    Timeout- */
		PCSMA_NONE,	/* PCSME_RPADT  Receive PADT */
		PCSMA_NONE,	/* PCSME_RPADOP Receive desired PADO */
		PCSMA_NONE,	/* PCSME_RPADO  Receive ordinary PADO */
		PCSMA_NONE,	/* PCSME_RPADS  Receive PADS */
		PCSMA_NONE,	/* PCSME_RPADSN Receive bad PADS */
	},
/* 1 PCSMS_INITSENT PADI sent */
	{
		PCSMA_FAIL,	/* PCSME_CLOSE  User close */
		PCSMA_SPADI,	/* PCSME_OPEN   User open */
		PCSMA_SPADI,	/* PCSME_TOP    Timeout+ */
		PCSMA_FAIL,	/* PCSME_TOM    Timeout- */
		PCSMA_FAIL,	/* PCSME_RPADT  Receive PADT */
		PCSMA_SPADRP,	/* PCSME_RPADOP Receive desired PADO */
		PCSMA_ADD,	/* PCSME_RPADO  Receive ordinary PADO */
		PCSMA_NONE,	/* PCSME_RPADS  Receive PADS */
		PCSMA_NONE,	/* PCSME_RPADSN Receive bad PADS */
	},
/* 2 PCSMS_OFFRRCVD PADO received */
	{
		PCSMA_FAIL,	/* PCSME_CLOSE  User close */
		PCSMA_SPADI,	/* PCSME_OPEN   User open */
		PCSMA_SPADR,	/* PCSME_TOP    Timeout+ */
		PCSMA_SPADR,	/* PCSME_TOM    Timeout- */
		PCSMA_FAIL,	/* PCSME_RPADT  Receive PADT */
		PCSMA_SPADRP,	/* PCSME_RPADOP Receive desired PADO */
		PCSMA_ADD,	/* PCSME_RPADO  Receive ordinary PADO */
		PCSMA_NONE,	/* PCSME_RPADS  Receive PADS */
		PCSMA_NONE,	/* PCSME_RPADSN Receive bad PADS */
	},
/* 3 PCSMS_REQSENT  PADR sent */
	{
		PCSMA_FAIL,	/* PCSME_CLOSE  User close */
		PCSMA_SPADI,	/* PCSME_OPEN   User open */
		PCSMA_SPADR,	/* PCSME_TOP    Timeout+ */
		PCSMA_SPADRN,	/* PCSME_TOM    Timeout- */
		PCSMA_FAIL,	/* PCSME_RPADT  Receive PADT */
		PCSMA_ADD,	/* PCSME_RPADOP Receive desired PADO */
		PCSMA_ADD,	/* PCSME_RPADO  Receive ordinary PADO */
		PCSMA_OPEN,	/* PCSME_RPADS  Receive PADS */
		PCSMA_SPADRN,	/* PCSME_RPADSN Receive bad PADS */
	},
/* 4 PCSMS_CONVERS  Conversational */
	{
		PCSMA_FAIL,	/* PCSME_CLOSE  User close */
		PCSMA_SPADI,	/* PCSME_OPEN   User open */
		PCSMA_FAIL,	/* PCSME_TOP    Timeout+ */
		PCSMA_FAIL,	/* PCSME_TOM    Timeout- */
		PCSMA_FAIL,	/* PCSME_RPADT  Receive PADT */
		PCSMA_NONE,	/* PCSME_RPADOP Receive desired PADO */
		PCSMA_NONE,	/* PCSME_RPADO  Receive ordinary PADO */
		PCSMA_NONE,	/* PCSME_RPADS  Receive PADS */
		PCSMA_NONE,	/* PCSME_RPADSN Receive bad PADS */
	},
};

/*
 * PPPoE Message structure -- holds data from a received PPPoE
 * message.  These are copied and saved when queuing offers from
 * possible servers.
 */
typedef struct poesm_s {
	struct poesm_s	*poemsg_next;	/* Next message in list */
	const poep_t	*poemsg_data;	/* Pointer to PPPoE packet */
	int		poemsg_len;	/* Length of packet */
	ppptun_atype	poemsg_sender;	/* Address of sender */
	const char	*poemsg_iname;	/* Name of input interface */
} poemsg_t;

/*
 * PPPoE State Machine structure -- holds state of PPPoE negotiation;
 * currently, there's exactly one of these per pppoec instance.
 */
typedef struct {
	int		poesm_state;		/* PCSMS_* */
	int		poesm_timer;		/* Milliseconds to next TO */
	int		poesm_count;		/* Retry countdown */
	int		poesm_interval;		/* Reload value */
	uint32_t	poesm_sequence;		/* Sequence for PADR */

	poemsg_t	*poesm_firstoff;	/* Queue of valid offers; */
	poemsg_t	*poesm_lastoff;		/* first is best offer */
	poemsg_t	*poesm_tried;		/* Tried and failed offers */

	int		poesm_localid;		/* Local session ID (driver) */
} poesm_t;

/*
 * Convert an internal PPPoE event code number into a printable
 * string.
 */
static const char *
poe_event(int event)
{
	static const char *poeevent[PCSME__MAX] = {
		"Close", "Open", "TO+", "TO-", "rPADT",
		"rPADO+", "rPADO", "rPADS", "rPADS-"
	};

	if (event < 0 || event >= PCSME__MAX) {
		return ("?");
	}
	return (poeevent[event]);
}

/*
 * Convert an internal PPPoE state number into a printable string.
 */
static const char *
poe_state(int state)
{
	static const char *poestate[PCSMS__MAX] = {
		"Dead", "InitSent", "OffrRcvd", "ReqSent", "Convers",
	};

	if (state < 0 || state >= PCSMS__MAX) {
		return ("?");
	}
	return (poestate[state]);
}

/*
 * Convert an internal PPPoE action number into a printable string.
 */
static const char *
poe_action(int act)
{
	static const char *poeaction[PCSMA__MAX] = {
		"None", "Fail", "SendPADI", "Add", "SendPADR",
		"SendPADR+", "SendPADR-", "Open"
	};

	if (act < 0 || act >= PCSMA__MAX) {
		return ("?");
	}
	return (poeaction[act]);
}

/*
 * This calls mygetmsg (which discards partial messages as needed) and
 * logs errors as appropriate.
 */
static int
pppoec_getmsg(int fd, struct strbuf *ctrl, struct strbuf *data, int *flags)
{
	int retv;

	for (;;) {
		retv = mygetmsg(fd, ctrl, data, flags);
		if (retv == 0)
			break;
		if (retv < 0) {
			if (errno == EINTR)
				continue;
			logstrerror("getmsg");
			break;
		}
		if (verbose) {
			if (!(retv & (MORECTL | MOREDATA)))
				logerr("%s: discard: "
				    "unexpected status %d\n", myname, retv);
			else
				logerr("%s: discard: "
				    "truncated %s%smessage\n", myname,
				    retv & MORECTL ? "control " : "",
				    retv & MOREDATA ? "data " : "");
		}
	}
	return (retv);
}

/*
 * Connect the control path to the lower stream of interest.  This
 * must be called after opening the tunnel driver in order to
 * establish the interface to be used for signaling.  Returns local
 * session ID number.
 */
static int
set_control(const char *dname)
{
	struct ppptun_peer ptp;
	union ppptun_name ptn;

	/* Fetch the local session ID first. */
	(void) memset(&ptp, '\0', sizeof (ptp));
	ptp.ptp_style = PTS_PPPOE;
	if (strioctl(tunfd, PPPTUN_SPEER, &ptp, sizeof (ptp), sizeof (ptp)) <
	    0) {
		logstrerror("PPPTUN_SPEER");
		exit(1);
	}

	/* Connect to lower stream. */
	(void) snprintf(ptn.ptn_name, sizeof (ptn.ptn_name), "%s:pppoed",
	    dname);
	if (strioctl(tunfd, PPPTUN_SCTL, &ptn, sizeof (ptn), 0) < 0) {
		logerr("%s: PPPTUN_SCTL %s: %s\n", myname,
		    ptn.ptn_name, mystrerror(errno));
		exit(1);
	}
	return (ptp.ptp_lsessid);
}

/*
 * Check if standard input is actually a viable connection to the
 * tunnel driver.  This is the normal mode of operation with pppd; the
 * tunnel driver is opened by pppd as the tty and pppoec is exec'd as
 * the connect script.
 */
static void
check_stdin(void)
{
	struct ppptun_info pti;
	union ppptun_name ptn;

	if (strioctl(0, PPPTUN_GDATA, &ptn, 0, sizeof (ptn)) < 0) {
		if (errno == EINVAL)
			logerr("%s: PPPoE operation requires "
			    "the use of a tunneling device\n", myname);
		else
			logstrerror("PPPTUN_GDATA");
		exit(1);
	}
	if (ptn.ptn_name[0] != '\0') {
		if (strioctl(0, PPPTUN_GINFO, &pti, 0, sizeof (pti)) < 0) {
			logstrerror("PPPTUN_GINFO");
			exit(1);
		}
		if (pti.pti_style != PTS_PPPOE) {
			logerr("%s: Cannot connect to server "
			    "using PPPoE; stream already set to style %d\n",
			    myname, pti.pti_style);
			exit(1);
		}
		if (verbose)
			logerr("%s: Warning:  PPPoE data link "
			    "already connected\n", myname);
		exit(0);
	}
	/* Standard input is the tunnel driver; use it. */
	tunfd = 0;
}

/*
 * Write a summary of a PPPoE message to the given file.  This is used
 * for logging and to display received offers in the inquiry (-i) mode.
 */
static void
display_pppoe(FILE *out, const poep_t *poep, int plen, const ppptun_atype *pap)
{
	int ttyp;
	int tlen;
	const uint8_t *tagp;
	const uint8_t *dp;
	const char *str;
	poer_t poer;
	uint32_t mask;

	if (out == stderr)
		logerr(" ");	/* Give us a timestamp */
	/* Print name of sender. */
	(void) fprintf(out, "%-16s ", ehost(pap));

	/* Loop through tags and print each. */
	tagp = (const uint8_t *)(poep + 1);
	while (poe_tagcheck(poep, plen, tagp)) {
		ttyp = POET_GET_TYPE(tagp);
		if (ttyp == POETT_END)
			break;
		tlen = POET_GET_LENG(tagp);
		dp = POET_DATA(tagp);
		str = NULL;
		switch (ttyp) {
		case POETT_SERVICE:	/* Service-Name */
			str = "Svc";
			break;
		case POETT_ACCESS:	/* AC-Name */
			str = "Name";
			break;
		case POETT_UNIQ:	/* Host-Uniq */
			str = "Uniq";
			break;
		case POETT_COOKIE:	/* AC-Cookie */
			str = "Cookie";
			break;
		case POETT_VENDOR:	/* Vendor-Specific */
			break;
		case POETT_RELAY:	/* Relay-Session-Id */
			str = "Relay";
			break;
		case POETT_NAMERR:	/* Service-Name-Error */
			str = "SvcNameErr";
			break;
		case POETT_SYSERR:	/* AC-System-Error */
			str = "SysErr";
			break;
		case POETT_GENERR:	/* Generic-Error */
			str = "GenErr";
			break;
		case POETT_MULTI:	/* Multicast-Capable */
			break;
		case POETT_HURL:	/* Host-URL */
			str = "URL";
			break;
		case POETT_MOTM:	/* Message-Of-The-Minute */
			str = "Mesg";
			break;
		case POETT_RTEADD:	/* IP-Route-Add */
			break;
		}
		switch (ttyp) {
		case POETT_NAMERR:	/* Service-Name-Error */
		case POETT_SYSERR:	/* AC-System-Error */
			if (tlen > 0 && *dp == '\0')
				tlen = 0;
			/* FALLTHROUGH */
		case POETT_SERVICE:	/* Service-Name */
		case POETT_ACCESS:	/* AC-Name */
		case POETT_GENERR:	/* Generic-Error */
		case POETT_MOTM:	/* Message-Of-The-Minute */
		case POETT_HURL:	/* Host-URL */
			(void) fprintf(out, "%s:\"%.*s\" ", str, tlen, dp);
			break;
		case POETT_UNIQ:	/* Host-Uniq */
		case POETT_COOKIE:	/* AC-Cookie */
		case POETT_RELAY:	/* Relay-Session-Id */
			(void) fprintf(out, "%s:", str);
			while (--tlen >= 0)
				(void) fprintf(out, "%02X", *dp++);
			(void) putc(' ', out);
			break;
		case POETT_VENDOR:	/* Vendor-Specific */
			(void) fputs("Vendor:", out);
			if (tlen >= 4) {
				if (*dp++ != 0) {
					(void) fprintf(out, "(%02X?)", dp[-1]);
				}
				(void) fprintf(out, "%x-%x-%x:", dp[0], dp[1],
				    dp[2]);
				tlen -= 4;
				dp += 3;
			}
			while (--tlen >= 0)
				(void) fprintf(out, "%02X", *dp++);
			(void) putc(' ', out);
			break;
		case POETT_MULTI:	/* Multicast-Capable */
			(void) fprintf(out, "Multi:%d ", *dp);
			break;
		case POETT_RTEADD:	/* IP-Route-Add */
			if (tlen != sizeof (poer)) {
				(void) fprintf(out, "RTE%d? ", tlen);
				break;
			}
			(void) memcpy(&poer, dp, sizeof (poer));
			(void) fputs("RTE:", out);
			if (poer.poer_dest_network == 0)
				(void) fputs("default", out);
			else
				(void) fputs(ihost(poer.poer_dest_network),
				    out);
			mask = ntohl(poer.poer_subnet_mask);
			if (mask != 0 && mask != (uint32_t)~0) {
				if ((~mask & (~mask + 1)) == 0)
					(void) fprintf(out, "/%d",
					    sizeof (struct in_addr) * NBBY +
					    1 - ffs(mask));
				else
					(void) fprintf(out, "/%s",
					    ihost(poer.poer_subnet_mask));
			}
			(void) fprintf(out, ",%s,%u ",
			    ihost(poer.poer_gateway), ntohl(poer.poer_metric));
			break;
		default:
			(void) fprintf(out, "%s:%d ", poe_tagname(ttyp), tlen);
			break;
		}
		tagp = POET_NEXT(tagp);
	}
	(void) putc('\n', out);
}

/*
 * Transmit a PPPoE message to the indicated destination.  Used for
 * PADI and PADR messages.
 */
static int
send_pppoe(const poep_t *poep, const char *msgname,
    const ppptun_atype *destaddr)
{
	struct strbuf ctrl;
	struct strbuf data;
	struct ppptun_control *ptc;

	/* Set up the control data expected by the driver. */
	ptc = (struct ppptun_control *)pkt_octl;
	(void) memset(ptc, '\0', sizeof (*ptc));
	ptc->ptc_discrim = PPPOE_DISCRIM;
	ptc->ptc_action = PTCA_CONTROL;
	ptc->ptc_address = *destaddr;
	ctrl.len = sizeof (*ptc);
	ctrl.buf = (caddr_t)ptc;
	data.len = poe_length(poep) + sizeof (*poep);
	data.buf = (caddr_t)poep;
	if (verbose)
		logerr("%s: Sending %s to %s: %d bytes\n",
		    myname, msgname, ehost(destaddr), data.len);
	if (putmsg(tunfd, &ctrl, &data, 0) < 0) {
		logstrerror("putmsg");
		return (-1);
	}
	return (0);
}

/*
 * Create and transmit a PPPoE Active Discovery Initiation packet.
 * This is broadcasted to all hosts on the LAN.
 */
static int
send_padi(int localid)
{
	poep_t *poep;
	ppptun_atype destaddr;

	poep = poe_mkheader(pkt_output, POECODE_PADI, 0);
	(void) poe_add_str(poep, POETT_SERVICE, "");
	(void) poe_add_long(poep, POETT_UNIQ, localid);
	(void) memset(&destaddr, '\0', sizeof (destaddr));
	(void) memcpy(destaddr.pta_pppoe.ptma_mac, ether_bcast,
	    sizeof (destaddr.pta_pppoe.ptma_mac));
	return (send_pppoe(poep, "PADI", &destaddr));
}

/*
 * This is used by the procedure below -- when the alarm goes off,
 * just exit.  (This was once a dummy procedure and used the EINTR
 * side-effect to terminate the loop, but that's not reliable, since
 * the EINTR could be caught and ignored by the calls to standard
 * output.)
 */
/* ARGSUSED */
static void
alarm_hand(int dummy)
{
	exit(0);
}

/*
 * Send out a single PADI and listen for servers.  This implements the
 * "inquiry" (-i) mode.
 */
static void
find_all_servers(int localid)
{
	struct strbuf ctrl;
	struct strbuf data;
	poep_t *poep;
	int flags;
	struct sigaction act;
	struct ppptun_control *ptc;

	/* Set a default 3-second timer */
	(void) memset(&act, '\0', sizeof (act));
	act.sa_handler = alarm_hand;
	(void) sigaction(SIGALRM, &act, NULL);
	(void) alarm((pado_wait_time + 999) / 1000);

	/* Broadcast a single request. */
	if (send_padi(localid) != 0)
		return;

	/* Loop over responses and print them. */
	for (;;) {
		ctrl.maxlen = PKT_OCTL_LEN;
		ctrl.buf = (caddr_t)pkt_octl;
		data.maxlen = PKT_INPUT_LEN;
		data.buf = (caddr_t)pkt_input;
		flags = 0;

		if (pppoec_getmsg(tunfd, &ctrl, &data, &flags) < 0)
			break;

		/* Ignore unwanted responses from the driver. */
		if (ctrl.len != sizeof (*ptc)) {
			if (verbose)
				logerr("%s: unexpected %d byte"
				    " control message from driver.\n", myname,
				    ctrl.len);
			continue;
		}
		ptc = (struct ppptun_control *)pkt_octl;
		poep = (poep_t *)pkt_input;

		/* If it's an offer, then print it out. */
		if (poe_code(poep) == POECODE_PADO) {
			display_pppoe(stdout, poep, data.len,
			    &ptc->ptc_address);
		}
	}
}

/*
 * Parse a server filter from the command line.  The passed-in string
 * must be allocated and unchanged, since a pointer to it is saved in
 * the filter data structure.  The string is also parsed for a MAC
 * address, if possible.
 */
static void
parse_filter(const char *str, int exceptflag)
{
	struct server_filter *sfnew;
	const char *cp;
	const char *wordstart;
	const char *wordend;
	int len;
	char hbuf[MAXHOSTNAMELEN];
	uchar_t *ucp;
	uchar_t *mcp;

	/* Allocate the new filter structure. */
	sfnew = (struct server_filter *)calloc(1, sizeof (*sfnew));
	if (sfnew == NULL) {
		logstrerror("filter allocation");
		exit(1);
	}

	/* Save the string for AC-Name comparison. */
	sfnew->sf_name = str;

	sfnew->sf_isexcept = exceptflag == 0 ? 0 : 1;

	/* Extract just one word. */
	cp = str;
	while (isspace(*cp))
		cp++;
	wordstart = cp;
	while (*cp != '\0' && !isspace(*cp))
		cp++;
	wordend = cp;
	if ((len = wordend - wordstart) >= sizeof (hbuf))
		len = sizeof (hbuf) - 1;
	(void) strlcpy(hbuf, wordstart, len);
	hbuf[len] = '\0';

	/* Try to translate this as an Ethernet host or address. */
	mcp = sfnew->sf_mask.ether_addr_octet;
	if (ether_hostton(hbuf, &sfnew->sf_mac) == 0) {
		mcp[0] = mcp[1] = mcp[2] = mcp[3] = mcp[4] = mcp[5] = 0xFF;
		sfnew->sf_hasmac = 1;
	} else {
		ucp = sfnew->sf_mac.ether_addr_octet;
		len = wordend - wordstart;
		cp = wordstart;
		while (cp < wordend) {
			if (ucp >= sfnew->sf_mac.ether_addr_octet +
			    sizeof (sfnew->sf_mac))
				break;
			if (*cp == '*') {
				*mcp++ = *ucp++ = 0;
				cp++;
			} else {
				if (!isxdigit(*cp))
					break;
				*ucp = hexdecode(*cp++);
				if (cp < wordend && isxdigit(*cp)) {
					*ucp = (*ucp << 4) |
					    hexdecode(*cp++);
				}
				ucp++;
				*mcp++ = 0xFF;
			}
			if (cp < wordend) {
				if (*cp != ':' || cp + 1 == wordend)
					break;
				cp++;
			}
		}
		if (cp >= wordend)
			sfnew->sf_hasmac = 1;
		else if (verbose)
			logerr("%s: treating '%.*s' as server "
			    "name only, not MAC address\n", myname, len,
			    wordstart);
	}

	/* Add to end of list. */
	if (sftail == NULL)
		sfhead = sfnew;
	else
		sftail->sf_next = sfnew;
	sftail = sfnew;
}

/*
 * Create a copy of a given PPPoE message.  This is used for enqueuing
 * received PADO (offers) from possible servers.
 */
static poemsg_t *
save_message(const poemsg_t *pmsg)
{
	poemsg_t *newmsg;
	char *cp;

	newmsg = (poemsg_t *)malloc(sizeof (*pmsg) + pmsg->poemsg_len +
		strlen(pmsg->poemsg_iname) + 1);
	if (newmsg != NULL) {
		newmsg->poemsg_next = NULL;
		newmsg->poemsg_data = (const poep_t *)(newmsg + 1);
		(void) memcpy(newmsg + 1, pmsg->poemsg_data, pmsg->poemsg_len);
		newmsg->poemsg_len = pmsg->poemsg_len;
		cp = (char *)newmsg->poemsg_data + pmsg->poemsg_len;
		newmsg->poemsg_iname = (const char *)cp;
		(void) strcpy(cp, pmsg->poemsg_iname);
		(void) memcpy(&newmsg->poemsg_sender, &pmsg->poemsg_sender,
		    sizeof (newmsg->poemsg_sender));
	}
	return (newmsg);
}

/*
 * Create and send a PPPoE Active Discovery Request (PADR) message to
 * the sender of the given PADO.  Some tags -- Service-Name,
 * AC-Cookie, and Relay-Session-Id -- must be copied from PADO to
 * PADR.  Others are not.  The Service-Name must be selected from the
 * offered services in the PADO based on the user's requested service
 * name.  If the server offered "wildcard" service, then we ask for
 * this only if we can't find the user's requested service.
 *
 * Returns 1 if we can't send a valid PADR in response to the given
 * PADO.  The offer should be ignored and the next one tried.
 */
static int
send_padr(poesm_t *psm, const poemsg_t *pado)
{
	poep_t *poep;
	boolean_t haswild;
	boolean_t hassvc;
	const uint8_t *tagp;
	int ttyp;
	int tlen;

	/*
	 * Increment sequence number for PADR so that we don't mistake
	 * old replies for valid ones if the server is very slow.
	 */
	psm->poesm_sequence++;

	poep = poe_mkheader(pkt_output, POECODE_PADR, 0);
	(void) poe_two_longs(poep, POETT_UNIQ, psm->poesm_localid,
	    psm->poesm_sequence);

	haswild = B_FALSE;
	hassvc = B_FALSE;
	tagp = (const uint8_t *)(pado->poemsg_data + 1);
	while (poe_tagcheck(pado->poemsg_data, pado->poemsg_len, tagp)) {
		ttyp = POET_GET_TYPE(tagp);
		if (ttyp == POETT_END)
			break;
		tlen = POET_GET_LENG(tagp);
		switch (ttyp) {
		case POETT_SERVICE:	/* Service-Name */
			/* Allow only one */
			if (hassvc)
				break;
			if (tlen == 0) {
				haswild = B_TRUE;
				break;
			}
			if (service[0] == '\0' ||
			    (tlen == strlen(service) &&
				memcmp(service, POET_DATA(tagp), tlen) == 0)) {
				(void) poe_tag_copy(poep, tagp);
				hassvc = B_TRUE;
			}
			break;
		/* Ones we should discard */
		case POETT_ACCESS:	/* AC-Name */
		case POETT_UNIQ:	/* Host-Uniq */
		case POETT_NAMERR:	/* Service-Name-Error */
		case POETT_SYSERR:	/* AC-System-Error */
		case POETT_GENERR:	/* Generic-Error */
		case POETT_HURL:	/* Host-URL */
		case POETT_MOTM:	/* Message-Of-The-Minute */
		case POETT_RTEADD:	/* IP-Route-Add */
		case POETT_VENDOR:	/* Vendor-Specific */
		case POETT_MULTI:	/* Multicast-Capable */
		default:		/* Anything else we don't understand */
			break;
		/* Ones we should copy */
		case POETT_COOKIE:	/* AC-Cookie */
		case POETT_RELAY:	/* Relay-Session-Id */
			(void) poe_tag_copy(poep, tagp);
			break;
		}
		tagp = POET_NEXT(tagp);
	}
	if (!hassvc) {
		if (haswild)
			(void) poe_add_str(poep, POETT_SERVICE, "");
		else
			return (1);
	}

	return (send_pppoe(poep, "PADR", &pado->poemsg_sender));
}

/*
 * ********************************************************************
 * act_* functions implement the actions driven by the state machine
 * tables.  See "action_table" below.
 *
 * All action routines must return the next state value.
 * ********************************************************************
 */

/* ARGSUSED */
static int
act_none(poesm_t *psm, poemsg_t *pmsg, int event, int nextst)
{
	return (nextst);
}

/* ARGSUSED */
static int
act_fail(poesm_t *psm, poemsg_t *pmsg, int event, int nextst)
{
	if (verbose)
		logerr("%s: unrecoverable error\n", myname);
	return (PCSMS_DEAD);
}

/* ARGSUSED */
static int
act_spadi(poesm_t *psm, poemsg_t *pmsg, int event, int nextst)
{
	if (send_padi(psm->poesm_localid) != 0)
		return (PCSMS_DEAD);
	/*
	 * If this is the first time, then initialize the retry count
	 * and interval.
	 */
	if (psm->poesm_state == PCSMS_DEAD) {
		psm->poesm_count = 3;
		psm->poesm_interval = pado_wait_time;
	} else {
		if ((psm->poesm_interval <<= 1) > RESTART_LIMIT)
			psm->poesm_interval = RESTART_LIMIT;
	}
	psm->poesm_timer = psm->poesm_interval;
	(void) gettimeofday(&tvstart, NULL);
	return (nextst);
}

/* ARGSUSED */
static int
act_add(poesm_t *psm, poemsg_t *pmsg, int event, int nextst)
{
	pmsg = save_message(pmsg);
	if (pmsg != NULL) {
		if (psm->poesm_lastoff == NULL)
			psm->poesm_firstoff = pmsg;
		else
			psm->poesm_lastoff->poemsg_next = pmsg;
		psm->poesm_lastoff = pmsg;
	}
	return (nextst);
}

/* ARGSUSED */
static int
act_spadr(poesm_t *psm, poemsg_t *pmsg, int event, int nextst)
{
	poemsg_t *msgp;
	int retv;

	for (;;) {
		if ((msgp = psm->poesm_firstoff) == NULL)
			return (PCSMS_DEAD);
		retv = send_padr(psm, msgp);
		if (retv < 0)
			return (PCSMS_DEAD);
		if (retv == 0)
			break;
		/* Can't send this request; try looking at next offer. */
		psm->poesm_firstoff = msgp->poemsg_next;
		msgp->poemsg_next = psm->poesm_tried;
		psm->poesm_tried = msgp;
	}
	if (psm->poesm_state != PCSMS_REQSENT) {
		psm->poesm_count = 3;
		psm->poesm_interval = pads_wait_time;
	} else {
		if ((psm->poesm_interval <<= 1) > RESTART_LIMIT)
			psm->poesm_interval = RESTART_LIMIT;
	}
	psm->poesm_timer = psm->poesm_interval;
	(void) gettimeofday(&tvstart, NULL);
	return (nextst);
}

/* ARGSUSED */
static int
act_spadrp(poesm_t *psm, poemsg_t *pmsg, int event, int nextst)
{
	int retv;

	retv = send_padr(psm, pmsg);
	if (retv < 0)
		return (PCSMS_DEAD);
	pmsg = save_message(pmsg);
	if (retv > 0) {
		/*
		 * Cannot use this one; mark as tried and continue as
		 * if we never saw it.
		 */
		pmsg->poemsg_next = psm->poesm_tried;
		psm->poesm_tried = pmsg;
		return (psm->poesm_state);
	}
	pmsg->poemsg_next = psm->poesm_firstoff;
	psm->poesm_firstoff = pmsg;
	if (psm->poesm_lastoff == NULL)
		psm->poesm_lastoff = pmsg;
	psm->poesm_count = 3;
	psm->poesm_timer = psm->poesm_interval = pads_wait_time;
	(void) gettimeofday(&tvstart, NULL);
	return (nextst);
}

/* ARGSUSED */
static int
act_spadrn(poesm_t *psm, poemsg_t *pmsg, int event, int nextst)
{
	poemsg_t *msgp;
	int retv;

	if ((msgp = psm->poesm_firstoff) == NULL)
		return (PCSMS_DEAD);
	do {
		psm->poesm_firstoff = msgp->poemsg_next;
		msgp->poemsg_next = psm->poesm_tried;
		psm->poesm_tried = msgp;
		if ((msgp = psm->poesm_firstoff) == NULL)
			return (PCSMS_DEAD);
		retv = send_padr(psm, msgp);
		if (retv < 0)
			return (PCSMS_DEAD);
	} while (retv != 0);
	psm->poesm_count = 3;
	psm->poesm_timer = psm->poesm_interval = pads_wait_time;
	(void) gettimeofday(&tvstart, NULL);
	return (nextst);
}

/*
 * For safety -- remove end of line from strings passed back to pppd.
 */
static void
remove_eol(char *str, size_t len)
{
	while (len > 0) {
		if (*str == '\n')
			*str = '$';
		str++;
		len--;
	}
}

/* ARGSUSED */
static int
act_open(poesm_t *psm, poemsg_t *pmsg, int event, int nextst)
{
	struct ppptun_peer ptp;
	union ppptun_name ptn;
	const char *cp;
	FILE *fp;
	const uint8_t *tagp, *vp;
	int tlen, ttyp;
	char *access;
	uint32_t val;
	size_t acc_len, serv_len;

	/*
	 * The server has now assigned its session ID for the data
	 * (PPP) portion of this tunnel.  Send that ID down to the
	 * driver.
	 */
	(void) memset(&ptp, '\0', sizeof (ptp));
	ptp.ptp_lsessid = psm->poesm_localid;
	ptp.ptp_rsessid = poe_session_id(pmsg->poemsg_data);
	(void) memcpy(&ptp.ptp_address, &pmsg->poemsg_sender,
	    sizeof (ptp.ptp_address));
	ptp.ptp_style = PTS_PPPOE;
	if (strioctl(tunfd, PPPTUN_SPEER, &ptp, sizeof (ptp), sizeof (ptp)) <
	    0) {
		logstrerror("PPPTUN_SPEER");
		return (PCSMS_DEAD);
	}

	/*
	 * Data communication is now possible on this session.
	 * Connect the data portion to the correct lower stream.
	 */
	if ((cp = strchr(pmsg->poemsg_iname, ':')) == NULL)
		cp = pmsg->poemsg_iname + strlen(pmsg->poemsg_iname);
	(void) snprintf(ptn.ptn_name, sizeof (ptn.ptn_name), "%.*s:pppoe",
	    cp - pmsg->poemsg_iname, pmsg->poemsg_iname);
	if (strioctl(tunfd, PPPTUN_SDATA, &ptn, sizeof (ptn), 0) < 0) {
		logerr("%s: PPPTUN_SDATA %s: %s\n",
		    myname, ptn.ptn_name, mystrerror(errno));
		return (PCSMS_DEAD);
	}
	if (verbose)
		logerr("%s: Connection open; session %04X on "
		    "%s\n", myname, ptp.ptp_rsessid, ptn.ptn_name);

	/*
	 * Walk through the PADS message to get the access server name
	 * and the service.  If there are multiple instances of either
	 * tag, then take the last access server and the first
	 * non-null service.
	 */
	access = "";
	acc_len = 0;
	serv_len = strlen(service);
	tagp = (const uint8_t *)(pmsg->poemsg_data + 1);
	while (poe_tagcheck(pmsg->poemsg_data, pmsg->poemsg_len, tagp)) {
		ttyp = POET_GET_TYPE(tagp);
		if (ttyp == POETT_END)
			break;
		tlen = POET_GET_LENG(tagp);
		if (ttyp == POETT_ACCESS) {
			access = (char *)POET_DATA(tagp);
			acc_len = tlen;
		}
		if (serv_len == 0 && ttyp == POETT_SERVICE && tlen != 0) {
			service = (char *)POET_DATA(tagp);
			serv_len = tlen;
		}
		tagp = POET_NEXT(tagp);
	}

	/*
	 * Remove end of line to make sure that integrity of values
	 * passed back to pppd can't be compromised by the PPPoE
	 * server.
	 */
	remove_eol(service, serv_len);
	remove_eol(access, acc_len);

	/*
	 * pppd has given us a pipe as fd 3, and we're expected to
	 * write out the values of the following environment
	 * variables:
	 *	IF_AND_SERVICE
	 *	SERVICE_NAME
	 *	AC_NAME
	 *	AC_MAC
	 *	SESSION_ID
	 *	VENDOR_SPECIFIC_1 ... N
	 * See usr.bin/pppd/plugins/pppoe.c for more information.
	 */
	if ((fp = fdopen(3, "w")) != NULL) {
		(void) fprintf(fp, "%.*s:%.*s\n",
		    cp - pmsg->poemsg_iname, pmsg->poemsg_iname, serv_len,
		    service);
		(void) fprintf(fp, "%.*s\n", serv_len, service);
		(void) fprintf(fp, "%.*s\n", acc_len, access);
		(void) fprintf(fp, "%s\n", ehost(&pmsg->poemsg_sender));
		(void) fprintf(fp, "%d\n", poe_session_id(pmsg->poemsg_data));
		tagp = (const uint8_t *)(pmsg->poemsg_data + 1);
		while (poe_tagcheck(pmsg->poemsg_data, pmsg->poemsg_len,
		    tagp)) {
			ttyp = POET_GET_TYPE(tagp);
			if (ttyp == POETT_END)
				break;
			tlen = POET_GET_LENG(tagp);
			if (ttyp == POETT_VENDOR && tlen >= 4) {
				(void) memcpy(&val, POET_DATA(tagp), 4);
				(void) fprintf(fp, "%08lX:",
				    (unsigned long)ntohl(val));
				tlen -= 4;
				vp = POET_DATA(tagp) + 4;
				while (--tlen >= 0)
					(void) fprintf(fp, "%02X", *vp++);
				(void) putc('\n', fp);
			}
			tagp = POET_NEXT(tagp);
		}
		(void) fclose(fp);
	}

	return (nextst);
}

static int (* const action_table[PCSMA__MAX])(poesm_t *psm, poemsg_t *pmsg,
    int event, int nextst) = {
	    act_none, act_fail, act_spadi, act_add, act_spadr, act_spadrp,
	    act_spadrn, act_open
};

/*
 * Dispatch an event and a corresponding message on a given state
 * machine.
 */
static void
handle_event(poesm_t *psm, int event, poemsg_t *pmsg)
{
	int nextst;

	if (verbose)
		logerr("%s: PPPoE Event %s (%d) in state %s "
		    "(%d): action %s (%d)\n", myname, poe_event(event), event,
		    poe_state(psm->poesm_state), psm->poesm_state,
		    poe_action(client_action[psm->poesm_state][event]),
		    client_action[psm->poesm_state][event]);

	nextst = (*action_table[client_action[psm->poesm_state][event]])(psm,
	    pmsg, event, client_next_state[psm->poesm_state][event]);

	if (verbose)
		logerr("%s: PPPoE State change %s (%d) -> %s (%d)\n", myname,
		    poe_state(psm->poesm_state), psm->poesm_state,
		    poe_state(nextst), nextst);

	psm->poesm_state = nextst;

	/*
	 * Life-altering states are handled here.  If we reach dead
	 * state again after starting, then we failed.  If we reach
	 * conversational state, then we're open.
	 */
	if (nextst == PCSMS_DEAD) {
		if (verbose)
			logerr("%s: action failed\n", myname);
		exit(1);
	}
	if (nextst == PCSMS_CONVERS) {
		if (verbose)
			logerr("%s: connected\n", myname);
		exit(0);
	}
}

/*
 * Check for error message tags in the PPPoE packet.  We must ignore
 * offers that merely report errors, and need to log errors in any
 * case.
 */
static int
error_check(poemsg_t *pmsg)
{
	const uint8_t *tagp;
	int ttyp;

	tagp = (const uint8_t *)(pmsg->poemsg_data + 1);
	while (poe_tagcheck(pmsg->poemsg_data, pmsg->poemsg_len, tagp)) {
		ttyp = POET_GET_TYPE(tagp);
		if (ttyp == POETT_END)
			break;
		if (ttyp == POETT_NAMERR || ttyp == POETT_SYSERR ||
		    ttyp == POETT_GENERR) {
			if (verbose)
				display_pppoe(stderr, pmsg->poemsg_data,
				    pmsg->poemsg_len, &pmsg->poemsg_sender);
			return (-1);
		}
		tagp = POET_NEXT(tagp);
	}
	return (0);
}

/*
 * Extract sequence number, if any, from PADS message, so that we can
 * relate it to the PADR that we sent.
 */
static uint32_t
get_sequence(const poemsg_t *pmsg)
{
	const uint8_t *tagp;
	int ttyp;
	uint32_t vals[2];

	tagp = (const uint8_t *)(pmsg->poemsg_data + 1);
	while (poe_tagcheck(pmsg->poemsg_data, pmsg->poemsg_len, tagp)) {
		ttyp = POET_GET_TYPE(tagp);
		if (ttyp == POETT_END)
			break;
		if (ttyp == POETT_UNIQ) {
			if (POET_GET_LENG(tagp) < sizeof (vals))
				break;
			(void) memcpy(vals, POET_DATA(tagp), sizeof (vals));
			return (ntohl(vals[1]));
		}
		tagp = POET_NEXT(tagp);
	}
	return (0);
}

/*
 * Server filter cases:
 *
 *	No filters -- all servers generate RPADO+ event; select the
 *	first responding server.
 *
 *	Only "except" filters -- matching servers are RPADO, others
 *	are RPADO+.
 *
 *	Mix of filters -- those matching "pass" are RPADO+, those
 *	matching "except" are RPADO, and all others are also RPADO.
 *
 * If the "only" keyword was given, then RPADO becomes -1; only RPADO+
 * events occur.
 */
static int
use_server(poemsg_t *pado)
{
	struct server_filter *sfp;
	const uchar_t *sndp;
	const uchar_t *macp;
	const uchar_t *maskp;
	int i;
	int passmatched;
	const uint8_t *tagp;
	int ttyp;

	/*
	 * If no service mentioned in offer, then we can't use it.
	 */
	tagp = (const uint8_t *)(pado->poemsg_data + 1);
	ttyp = POETT_END;
	while (poe_tagcheck(pado->poemsg_data, pado->poemsg_len, tagp)) {
		ttyp = POET_GET_TYPE(tagp);
		if (ttyp == POETT_END || ttyp == POETT_SERVICE)
			break;
		tagp = POET_NEXT(tagp);
	}
	if (ttyp != POETT_SERVICE)
		return (-1);

	passmatched = 0;
	for (sfp = sfhead; sfp != NULL; sfp = sfp->sf_next) {
		passmatched |= !sfp->sf_isexcept;
		if (sfp->sf_hasmac) {
			sndp = pado->poemsg_sender.pta_pppoe.ptma_mac;
			macp = sfp->sf_mac.ether_addr_octet;
			maskp = sfp->sf_mask.ether_addr_octet;
			i = sizeof (pado->poemsg_sender.pta_pppoe.ptma_mac);
			for (; i > 0; i--)
				if (((*macp++ ^ *sndp++) & *maskp++) != 0)
					break;
			if (i <= 0)
				break;
		}
	}

	if (sfp == NULL) {
		/*
		 * No match encountered; if only exclude rules have
		 * been seen, then accept this offer.
		 */
		if (!passmatched)
			return (PCSME_RPADOP);
	} else {
		if (!sfp->sf_isexcept)
			return (PCSME_RPADOP);
	}
	if (onlyflag)
		return (-1);
	return (PCSME_RPADO);
}

/*
 * This is the normal event loop.  It initializes the state machine
 * and sends in an Open event to kick things off.  Then it drops into
 * a loop to dispatch events for the state machine.
 */
static void
find_server(int localid)
{
	poesm_t psm;
	struct pollfd pfd[1];
	struct timeval tv, tvnow;
	int retv;
	poemsg_t pmsg;
	struct strbuf ctrl;
	struct strbuf data;
	poep_t *poep;
	int flags;
	uint32_t seqval;
	struct ppptun_control *ptc;

	(void) memset(&psm, '\0', sizeof (psm));

	/*
	 * Initialize the sequence number with something handy.  It
	 * doesn't need to be absolutely unique, since the localid
	 * value actually demultiplexes everything.  This just makes
	 * the operation a little safer.
	 */
	psm.poesm_sequence = getpid() << 16;
	psm.poesm_localid = localid;

	/* Start the state machine */
	handle_event(&psm, PCSME_OPEN, NULL);

	/* Enter event polling loop. */
	pfd[0].fd = tunfd;
	pfd[0].events = POLLIN;
	for (;;) {
		/* Wait for timeout or message */
		retv = poll(pfd, 1, psm.poesm_timer > 0 ? psm.poesm_timer :
		    INFTIM);
		if (retv < 0) {
			logstrerror("poll");
			break;
		}

		/* Handle a timeout */
		if (retv == 0) {
			psm.poesm_timer = 0;
			handle_event(&psm, --psm.poesm_count > 0 ? PCSME_TOP :
			    PCSME_TOM, NULL);
			continue;
		}

		/* Adjust the timer for the time we slept. */
		if (psm.poesm_timer > 0) {
			(void) gettimeofday(&tvnow, NULL);
			tv = tvnow;
			if ((tv.tv_sec -= tvstart.tv_sec) < 0) {
				/* Darn */
				tv.tv_sec = 1;
				tv.tv_usec = 0;
			} else if ((tv.tv_usec -= tvstart.tv_usec) < 0) {
				tv.tv_usec += 1000000;
				if (--tv.tv_sec < 0)
					tv.tv_sec = 0;
			}
			psm.poesm_timer -= tv.tv_sec*1000 + tv.tv_usec/1000;
			tvstart = tvnow;
		}

		/* Read in the message from the server. */
		ctrl.maxlen = PKT_OCTL_LEN;
		ctrl.buf = (caddr_t)pkt_octl;
		data.maxlen = PKT_INPUT_LEN;
		data.buf = (caddr_t)pkt_input;
		flags = 0;

		if (pppoec_getmsg(tunfd, &ctrl, &data, &flags) < 0)
			break;

		if (ctrl.len != sizeof (*ptc)) {
			if (verbose)
				logerr("%s: discard: ctrl len %d\n", myname,
				    ctrl.len);
			continue;
		}
		poep = (poep_t *)pkt_input;
		(void) memset(&pmsg, '\0', sizeof (pmsg));
		pmsg.poemsg_next = NULL;
		pmsg.poemsg_data = poep;
		pmsg.poemsg_len = data.len;
		ptc = (struct ppptun_control *)pkt_octl;
		if (ptc->ptc_action != PTCA_CONTROL) {
			if (verbose)
				logerr("%s: discard: unexpected action %d\n",
				    myname, ptc->ptc_action);
			continue;
		}
		pmsg.poemsg_iname = ptc->ptc_name;
		if (verbose)
			logerr("%s: Received %s from %s/%s\n",
			    myname, poe_codename(poep->poep_code),
			    ehost(&ptc->ptc_address), pmsg.poemsg_iname);
		pmsg.poemsg_sender = ptc->ptc_address;

		/* Check for messages from unexpected peers. */
		if ((poep->poep_code == POECODE_PADT ||
		    poep->poep_code == POECODE_PADS) &&
		    (psm.poesm_firstoff == NULL ||
			memcmp(&psm.poesm_firstoff->poemsg_sender,
			    &pmsg.poemsg_sender,
			    sizeof (pmsg.poemsg_sender)) != 0)) {
			if (verbose) {
				logerr("%s: Unexpected peer %s", myname,
				    ehost(&ptc->ptc_address));
				logerr(" != %s\n",
				    ehost(&psm.poesm_firstoff->poemsg_sender));
			}
			continue;
		}

		/* Eliminate stale PADS responses. */
		if (poep->poep_code == POECODE_PADS) {
			seqval = get_sequence(&pmsg);
			if (seqval != psm.poesm_sequence) {
				if (verbose) {
					if (seqval == 0)
						logerr(
						    "%s: PADS has no sequence "
						    "number.\n", myname);
					else
						logerr(
						    "%s: PADS has sequence "
						    "%08X instead of %08X.\n",
						    myname, seqval,
						    psm.poesm_sequence);
				}
				continue;
			}
		}

		/* Dispatch message event. */
		retv = error_check(&pmsg);
		switch (poep->poep_code) {
		case POECODE_PADT:
			handle_event(&psm, PCSME_RPADT, &pmsg);
			break;
		case POECODE_PADS:
			/*
			 * Got a PPPoE Active Discovery Session-
			 * confirmation message.  It's a PADS event if
			 * everything's in order.  It's a PADS- event
			 * if the message is merely reporting an
			 * error.
			 */
			handle_event(&psm, retv != 0 ? PCSME_RPADSN :
			    PCSME_RPADS, &pmsg);
			break;
		case POECODE_PADO:
			/* Ignore offers that merely report errors. */
			if (retv != 0)
				break;
			/* Ignore offers from servers we don't want. */
			if ((retv = use_server(&pmsg)) < 0)
				break;
			/* Dispatch either RPADO or RAPDO+ event. */
			handle_event(&psm, retv, &pmsg);
			break;

		default:
			if (verbose)
				logerr("%s: Unexpected code %s (%d)\n", myname,
				    poe_codename(poep->poep_code),
				    poep->poep_code);
			break;
		}
	}
	exit(1);
}

static void
usage(void)
{
	logerr("Usage:\n"
	    "\t%s [-os#] [-v] <dev> [<service> [<server> [only]]]\n\n"
	    "    or\n\n"
	    "\t%s [-o#] [-v] -i <dev>\n", myname, myname);
	exit(1);
}

/*
 * In addition to the usual 0-2 file descriptors, pppd will leave fd 3
 * open on a pipe to receive the environment variables.  See
 * pppoe_device_pipe() in pppd/plugins/pppoe.c and device_pipe_hook in
 * pppd/main.c.
 */
int
main(int argc, char **argv)
{
	int inquiry_mode, exceptflag, arg, localid;
	char *cp;

	log_to_stderr(LOGLVL_DBG);

	if ((myname = *argv) == NULL)
		myname = "pppoec";

	inquiry_mode = 0;
	while ((arg = getopt(argc, argv, "io:s:v")) != EOF)
		switch (arg) {
		case 'i':
			inquiry_mode++;
			break;
		case 'v':
			verbose++;
			break;
		case 'o':
			pado_wait_time = strtol(optarg, &cp, 0);
			if (pado_wait_time <= 0 || *cp != '\0' ||
			    cp == optarg) {
				logerr("%s: illegal PADO wait time: %s\n",
				    myname, optarg);
				exit(1);
			}
			break;
		case 's':
			pads_wait_time = strtol(optarg, &cp, 0);
			if (pads_wait_time <= 0 || *cp != '\0' ||
			    cp == optarg) {
				logerr("%s: illegal PADS wait time: %s\n",
				    myname, optarg);
				exit(1);
			}
			break;
		case '?':
			usage();
		}

	/* Handle inquiry mode. */
	if (inquiry_mode) {
		if (optind != argc-1)
			usage();
		if (pado_wait_time == 0)
			pado_wait_time = PADI_INQUIRY_DWELL;

		/* Invoked by user; open the tunnel driver myself. */
		tunfd = open(tunnam, O_RDWR | O_NOCTTY);
		if (tunfd == -1) {
			logstrerror(tunnam);
			exit(1);
		}

		/*
		 * Set up the control stream for PPPoE negotiation
		 * (set_control), then broadcast a query for all servers
		 * and listen for replies (find_all_servers).
		 */
		find_all_servers(set_control(argv[optind]));
		return (0);
	}

	if (pado_wait_time == 0)
		pado_wait_time = PADI_RESTART_TIME;

	if (optind >= argc)
		usage();

	/* Make sure we've got a usable tunnel driver on stdin. */
	check_stdin();

	/* Set up the control stream for PPPoE negotiation. */
	localid = set_control(argv[optind++]);

	/* Pick the service, if any. */
	if (optind < argc)
		service = argv[optind++];

	/* Parse out the filters. */
	if (optind < argc) {
		if (strcasecmp(argv[argc - 1], "only") == 0) {
			argc--;
			onlyflag = 1;
		}
		exceptflag = 0;
		for (; optind < argc; optind++) {
			if (!exceptflag &&
			    strcasecmp(argv[optind], "except") == 0) {
				exceptflag = 1;
			} else {
				parse_filter(argv[optind], exceptflag);
				exceptflag = 0;
			}
		}
	}

	/* Enter the main loop. */
	find_server(localid);

	return (0);
}
