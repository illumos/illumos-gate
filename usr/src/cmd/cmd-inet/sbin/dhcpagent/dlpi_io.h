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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	DLPI_IO_H
#define	DLPI_IO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netinet/in.h>
#include <sys/types.h>
#include <libdlpi.h>

/*
 * dlpi_io.[ch] contain the interface the agent uses to interact with
 * DLPI for data transfer primitives. see dlpi_io.c for documentation
 * on how to use the exported functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef ushort_t *filter_func_t(ushort_t *, void *);

filter_func_t	dhcp_filter;
boolean_t	set_packet_filter(dlpi_handle_t, filter_func_t *, void *,
		    const char *);
ssize_t		dlpi_recvfrom(dlpi_handle_t, void *, size_t,
		    struct sockaddr_in *, struct sockaddr_in *);
ssize_t		dlpi_sendto(dlpi_handle_t, void *, size_t, struct sockaddr_in *,
		    uchar_t *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* DLPI_IO_H */
