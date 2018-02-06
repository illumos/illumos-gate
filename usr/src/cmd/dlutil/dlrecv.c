/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Receive a raw Ethernet frame from dlsend.
 */

#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <stdarg.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <libdlpi.h>
#include <stddef.h>
#include <stdint.h>
#include <endian.h>
#include <ctype.h>
#include <err.h>

#include "dlsend.h"


static uint_t dlrecv_sap = DLSEND_SAP;
static const char *dlrecv_prog;

static void
dlrecv_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		(void) fprintf(stderr, "%s: ", dlrecv_prog);
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage: %s [-s sap] device\n"
	    "\t-s sap\tspecify SAP to send on\n",
	    dlrecv_prog);
}

static boolean_t
dlrecv_isvalid(dlsend_msg_t *msg)
{
	uint_t i;
	boolean_t nul;

	nul = B_FALSE;
	for (i = 0; i < sizeof (msg->dm_host); i++) {
		if (!isprint(msg->dm_host[i]) &&
		    msg->dm_host[i] != '\0') {
			warnx("Encountered bad byte in dm_host[%d]\n",
			    i);
			return (B_FALSE);
		}

		if (msg->dm_host[i] == '\0')
			nul = B_TRUE;
	}

	if (!nul) {
		warnx("Missing NUL in dm_host\n");
		return (B_FALSE);
	}

	nul = B_FALSE;
	for (i = 0; i < sizeof (msg->dm_mesg); i++) {
		if (!isprint(msg->dm_mesg[i]) &&
		    msg->dm_mesg[i] != '\0') {
			warnx("Encountered bad byte in dm_mesg[%d]\n",
			    i);
			return (B_FALSE);
		}

		if (msg->dm_mesg[i] == '\0')
			nul = B_TRUE;
	}

	if (!nul) {
		warnx("Missing NUL in dm_mesg\n");
		return (B_FALSE);
	}

	if (strcmp(msg->dm_mesg, DLSEND_MSG) != 0) {
		warnx("Missing expected message (%s)\n", DLSEND_MSG);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static void
dlrecv_print(dlsend_msg_t *msg, dlpi_recvinfo_t *rinfo, boolean_t invalid)
{
	uint_t i;

	(void) printf("Received %s from ", invalid ?
	    "invalid message" : "Elbereth");

	for (i = 0; i < rinfo->dri_destaddrlen; i++) {
		(void) printf("%02x", rinfo->dri_destaddr[i]);
		if (i + 1 != rinfo->dri_destaddrlen)
			(void) putchar(':');
	}

	if (invalid) {
		return;
	}

	(void) printf(" seq=%" PRIu64 " host=%s\n", betoh64(msg->dm_count),
	    msg->dm_host);
}

int
main(int argc, char *argv[])
{
	int c, ret;
	char *eptr;
	unsigned long sap;
	uint_t bind_sap;
	dlpi_handle_t dh;

	dlrecv_prog = basename(argv[0]);

	while ((c = getopt(argc, argv, ":s:")) != -1) {
		switch (c) {
		case 's':
			errno = 0;
			sap = strtoul(optarg, &eptr, 10);
			if (errno != 0 || sap == 0 || sap >= UINT16_MAX ||
			    *eptr != '\0') {
				dlrecv_usage("Invalid value for sap (-s): %s\n",
				    optarg);
				return (2);
			}
			dlrecv_sap = sap;
			break;
		case ':':
			dlrecv_usage("Option -%c requires an operand\n",
			    optopt);
			return (2);
		case '?':
			dlrecv_usage("Unknown option: -%c\n", optopt);
			return (2);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		dlrecv_usage("missing required operands\n");
		return (2);
	}

	if ((ret = dlpi_open(argv[0], &dh, 0)) != DLPI_SUCCESS) {
		warnx("failed to open %s: %s\n", argv[0],
		    dlpi_strerror(ret));
		exit(1);
	}

	if ((ret = dlpi_bind(dh, dlrecv_sap, &bind_sap)) != DLPI_SUCCESS) {
		warnx("failed to bind to sap 0x%x: %s\n", dlrecv_sap,
		    dlpi_strerror(ret));
		exit(1);
	}

	if (bind_sap != dlrecv_sap) {
		warnx("failed to bind to requested sap 0x%x, bound to "
		    "0x%x\n", dlrecv_sap, bind_sap);
		exit(1);
	}

	for (;;) {
		dlpi_recvinfo_t rinfo;
		dlsend_msg_t msg;
		size_t msglen;
		boolean_t invalid = B_FALSE;

		msglen = sizeof (msg);
		ret = dlpi_recv(dh, NULL, NULL, &msg, &msglen, -1, &rinfo);
		if (ret != DLPI_SUCCESS) {
			warnx("failed to receive data: %s\n",
			    dlpi_strerror(ret));
			continue;
		}

		if (msglen != rinfo.dri_totmsglen) {
			warnx("message truncated: expected %ld bytes, "
			    "got %ld\n", sizeof (dlsend_msg_t),
			    rinfo.dri_totmsglen);
			invalid = B_TRUE;
		}

		if (msglen != sizeof (msg)) {
			warnx("message too short: expected %ld bytes, "
			    "got %ld\n", sizeof (dlsend_msg_t),
			    msglen);
			invalid = B_TRUE;
		}

		if (!invalid) {
			invalid = !dlrecv_isvalid(&msg);
		}

		dlrecv_print(&msg, &rinfo, invalid);
	}

	/* LINTED: E_STMT_NOT_REACHED */
	return (0);
}
