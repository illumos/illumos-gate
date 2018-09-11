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
 * Send a raw Ethernet frame once a second to a specified MAC address.
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
#include <err.h>

#include "dlsend.h"

static uint_t dlsend_sap = DLSEND_SAP;
static const char *dlsend_msg = DLSEND_MSG;
static const char *dlsend_prog;

static void
dlsend_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		(void) fprintf(stderr, "%s: ", dlsend_prog);
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage: %s [-s sap] device target-mac\n"
	    "\t-s sap\tspecify SAP to send on\n",
	    dlsend_prog);
}

int
main(int argc, char *argv[])
{
	int c, maclen, ret;
	unsigned long sap;
	char *eptr;
	uchar_t *mac;
	char host[MAXHOSTNAMELEN];
	uint_t bind_sap;
	dlpi_handle_t dh;
	uint64_t count;

	dlsend_prog = basename(argv[0]);

	while ((c = getopt(argc, argv, ":s:")) != -1) {
		switch (c) {
		case 's':
			errno = 0;
			sap = strtoul(optarg, &eptr, 10);
			if (errno != 0 || sap == 0 || sap >= UINT16_MAX ||
			    *eptr != '\0') {
				dlsend_usage("Invalid value for sap (-s): %s\n",
				    optarg);
				return (2);
			}
			dlsend_sap = sap;
			break;
		case ':':
			dlsend_usage("Option -%c requires an operand\n",
			    optopt);
			return (2);
		case '?':
			dlsend_usage("Unknown option: -%c\n", optopt);
			return (2);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		dlsend_usage("missing required operands\n");
		return (2);
	}

	if ((mac = _link_aton(argv[1], &maclen)) == NULL) {
		warnx("failed to convert target address %s\n", argv[1]);
		return (1);
	}

	if (gethostname(host, sizeof (host)) != 0) {
		warnx("failed to obtain the system hostname: %s\n",
		    strerror(errno));
		(void) strlcpy(host, "<unknown host>", sizeof (host));
	}

	if ((ret = dlpi_open(argv[0], &dh, 0)) != DLPI_SUCCESS) {
		warnx("failed to open %s: %s\n", argv[0],
		    dlpi_strerror(ret));
		exit(1);
	}

	if ((ret = dlpi_bind(dh, dlsend_sap, &bind_sap)) != DLPI_SUCCESS) {
		warnx("failed to bind to sap 0x%x: %s\n", dlsend_sap,
		    dlpi_strerror(ret));
		exit(1);
	}

	if (bind_sap != dlsend_sap) {
		warnx("failed to bind to requested sap 0x%x, bound to "
		    "0x%x\n", dlsend_sap, bind_sap);
		exit(1);
	}

	count = 0;
	for (;;) {
		dlsend_msg_t msg;

		count++;
		bzero(&msg, sizeof (msg));
		msg.dm_count = htobe64(count);
		(void) strlcpy(msg.dm_host, host, sizeof (msg.dm_host));
		(void) strlcpy(msg.dm_mesg, dlsend_msg, sizeof (msg.dm_mesg));
		ret = dlpi_send(dh, mac, maclen, &msg, sizeof (msg), NULL);
		if (ret != DLPI_SUCCESS) {
			warnx("failed to send message: %s\n",
			    dlpi_strerror(ret));
			exit(1);
		}

		(void) sleep(1);
	}

	/* LINTED: E_STMT_NOT_REACHED */
	return (0);
}
