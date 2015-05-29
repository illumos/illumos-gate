/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/debug.h>
#include <sys/tihdr.h>
#include "connstat.h"

int
mibopen(const char *proto)
{
	int saved;
	int fd;

	fd = open("/dev/arp", O_RDWR);
	if (fd == -1) {
		return (-1);
	}

	if (ioctl(fd, I_PUSH, proto) == -1) {
		saved = errno;
		(void) close(fd);
		errno = saved;
		return (-1);
	}

	return (fd);
}

int
conn_walk(int fd, connstat_proto_t *proto, conn_walk_state_t *state)
{
	struct strbuf cbuf, dbuf;
	struct opthdr *hdr;
	int flags, r, err = 0;
	struct {
		struct T_optmgmt_req req;
		struct opthdr hdr;
	} req;
	union {
		struct T_optmgmt_ack ack;
		uint8_t space[sizeof (struct T_optmgmt_ack) +
		    sizeof (struct opthdr) * 2];
	} ack;

	bzero(&cbuf, sizeof (cbuf));
	bzero(&dbuf, sizeof (dbuf));

	req.req.PRIM_type = T_OPTMGMT_REQ;
	req.req.OPT_offset = (caddr_t)&req.hdr - (caddr_t)&req;
	req.req.OPT_length = sizeof (req.hdr);
	req.req.MGMT_flags = T_CURRENT;

	req.hdr.level = proto->csp_miblevel;
	req.hdr.name = 0;
	req.hdr.len = 0;

	cbuf.buf = (caddr_t)&req;
	cbuf.len = sizeof (req);

	if (putmsg(fd, &cbuf, NULL, 0) == -1) {
		warn("failed to request connection info: putmsg");
		return (-1);
	}

	/*
	 * Each reply consists of a control part for one fixed structure or
	 * table, as defined in mib2.h.  The format is a T_OPTMGMT_ACK
	 * containing an opthdr structure.  The level and name identify the
	 * entry, and len is the size of the data part of the message.
	 */
	for (;;) {
		cbuf.buf = (caddr_t)&ack;
		cbuf.maxlen = sizeof (ack);
		flags = 0;

		/*
		 * We first do a getmsg() for the control part so that we
		 * can allocate a properly sized buffer to read the data
		 * part.
		 */
		do {
			r = getmsg(fd, &cbuf, NULL, &flags);
		} while (r < 0 && errno == EINTR);

		if (r < 0) {
			warn("failed to fetch further connection info");
			err = -1;
			break;
		} else if ((r & MORECTL) != 0) {
			warnx("failed to fetch full control message");
			err = -1;
			break;
		}

		if (cbuf.len < sizeof (struct T_optmgmt_ack) ||
		    ack.ack.PRIM_type != T_OPTMGMT_ACK ||
		    ack.ack.MGMT_flags != T_SUCCESS ||
		    ack.ack.OPT_length < sizeof (struct opthdr)) {
			warnx("cannot process invalid message from getmsg()");
			err = -1;
			break;
		}

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		hdr = (struct opthdr *)((caddr_t)&ack + ack.ack.OPT_offset);
		if (r == 0 && hdr->level == 0 && hdr->name == 0) {
			/*
			 * snmpcom_req() has sent us the final End-Of-Data
			 * message, so there's nothing further to read.
			 */
			break;
		}

		/* Only data should remain. */
		VERIFY3S(r, ==, MOREDATA);

		/* Allocate a buffer to hold the data portion of the message */
		if ((dbuf.buf = realloc(dbuf.buf, hdr->len)) == NULL) {
			warn("failed to realloc() buffer");
			err = -1;
			break;
		}
		dbuf.maxlen = hdr->len;
		dbuf.len = 0;
		flags = 0;

		do {
			r = getmsg(fd, NULL, &dbuf, &flags);
		} while (r < 0 && errno == EINTR);

		if (r < 0) {
			warn("failed to fetch connection data: getmsg()");
			err = -1;
			break;
		} else if (r != 0) {
			warnx("failed to fetch all data: "
			    "getmsg() returned %d", r);
			err = -1;
			break;
		}

		if ((state->cws_flags & CS_IPV4) &&
		    hdr->name == proto->csp_mibv4name) {
			proto->csp_v4walk(&dbuf, state);
		} else if ((state->cws_flags & CS_IPV6) &&
		    hdr->name == proto->csp_mibv6name) {
			proto->csp_v6walk(&dbuf, state);
		}
	}

	free(dbuf.buf);

	return (err);
}
