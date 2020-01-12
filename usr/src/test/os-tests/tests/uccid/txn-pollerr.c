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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * Verify that closing a transaction while polling generates POLLERR.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <sys/debug.h>
#include <poll.h>
#include <port.h>

#include <sys/usb/clients/ccid/uccid.h>

int
main(int argc, char *argv[])
{
	int fd, port;
	uccid_cmd_txn_end_t end;
	uccid_cmd_txn_begin_t begin;
	port_event_t pe;
	timespec_t to;

	if (argc != 2) {
		errx(EXIT_FAILURE, "missing required ccid path");
	}

	if ((port = port_create()) == -1) {
		err(EXIT_FAILURE, "failed to create event port: %d",
		    port);
	}

	if ((fd = open(argv[1], O_RDWR | O_EXCL)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	bzero(&begin, sizeof (begin));
	begin.uct_version = UCCID_CURRENT_VERSION;
	if (ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin) != 0) {
		err(EXIT_FAILURE, "failed to issue begin ioctl");
	}

	/*
	 * Do not poll for pollout here, since by default, after grabbing a
	 * transaction, the device is writeable.
	 */
	if (port_associate(port, PORT_SOURCE_FD, fd, POLLIN, NULL) != 0) {
		err(EXIT_FAILURE, "failed to associate");
	}

	bzero(&end, sizeof (end));
	end.uct_version = UCCID_CURRENT_VERSION;
	end.uct_flags = UCCID_TXN_END_RELEASE;

	if (ioctl(fd, UCCID_CMD_TXN_END, &end) != 0) {
		err(EXIT_FAILURE, "failed to issue end ioctl");
	}

	bzero(&to, sizeof (timespec_t));
	if (port_get(port, &pe, &to) != 0) {
		err(EXIT_FAILURE, "failed to port_get()");
	}

	VERIFY3S(pe.portev_source, ==, PORT_SOURCE_FD);
	VERIFY3S(pe.portev_object, ==, fd);
	VERIFY3S(pe.portev_events & POLLERR, !=, 0);

	return (0);
}
