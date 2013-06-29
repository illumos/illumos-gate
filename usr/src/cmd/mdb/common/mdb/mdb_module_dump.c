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
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 */

/*
 * Dump a region of memory from a target and dump it to a temporary file. This
 * only makes sense for mdb, not for kmdb.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libproc.h>
#include <sys/sysmacros.h>
#include <errno.h>
#include <strings.h>

#include <mdb/mdb_module.h>
#include <mdb/mdb.h>

int
mdb_module_dumpfd(int fd, uintptr_t tgtaddr, size_t tgtsize)
{
#ifdef _KMDB
	return (-1);
#endif
	int toread, towrite, ret;
	char buf[1024];

	while (tgtsize > 0) {
		toread = MIN(sizeof (buf), tgtsize);
		towrite = mdb_vread(buf, toread, tgtaddr);
		if (towrite < 0) {
			mdb_printf("failed to read dmod from target");
			return (-1);
		}
		tgtsize -= towrite;
		tgtaddr += towrite;
		do {
			ret = write(fd, buf, towrite);
			if (ret > 0)
				towrite -= ret;
		} while (ret < towrite && errno == EINTR);

		if (ret < 0) {
			mdb_printf("failed to write to temporary dmod "
			    "file: %s\n", strerror(errno));
			return (-1);
		}
	}

	return (0);
}
