/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include "proxy-io.h"

int
proxy_read_write_loop(int readfd, int writefd)
{
	int	rbytes, bytes_to_write, bytes_written;
	char 	readbuf[BUFFER_SIZ];
	char	*ptr;

	rbytes = read(readfd, readbuf, sizeof (readbuf));

	if (rbytes > 0) {
		bytes_to_write = rbytes;
		ptr = readbuf;
		while (bytes_to_write > 0) {
			if ((bytes_written =
			    write(writefd, ptr, bytes_to_write)) < 0) {
				perror("write");
				return (0);
			}
			bytes_to_write -= bytes_written;
			ptr += bytes_written;
		}
	} else if (rbytes <= 0) {
		return (0);
	}
	/* Read and write successful */
	return (1);
}
