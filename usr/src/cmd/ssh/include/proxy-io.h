/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PROXY_IO_H
#define	_PROXY_IO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Read/write loop for ssh proxies.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	BUFFER_SIZ	8192

int proxy_read_write_loop(int readfd, int writefd);

#ifdef __cplusplus
}
#endif

#endif /* _PROXY_IO_H */
