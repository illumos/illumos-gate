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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	DLPI_IO_H
#define	DLPI_IO_H

#pragma ident	"%W%	%E% SMI"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/dlpi.h>

/*
 * dlpi_io.[ch] contain the interface the agent uses to interact with
 * DLPI.  it makes use of dlprims.c (and should be its only consumer).
 * see dlpi_io.c for documentation on how to use the exported
 * functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * buffer size to be used in control part of DLPI messages, in bytes
 */
#define	DLPI_BUF_MAX	256

/*
 * timeout to be used on DLPI-related operations, in seconds
 */
#define	DLPI_TIMEOUT	5

/*
 * flags for dlpi_recv_link()
 */
#define	DLPI_RECV_SHORT	0x01	/* short reads are expected */

typedef ushort_t *filter_func_t(ushort_t *, void *);

filter_func_t	dhcp_filter, blackhole_filter;
uchar_t		*build_broadcast_dest(dl_info_ack_t *, uchar_t *);
void		set_packet_filter(int, filter_func_t *, void *, const char *);
int		dlpi_open(const char *, dl_info_ack_t *, size_t, t_uscalar_t);
int		dlpi_close(int);
ssize_t		dlpi_recvfrom(int, void *, size_t, struct sockaddr_in *);
ssize_t		dlpi_recv_link(int, void *, size_t, uint32_t);
ssize_t		dlpi_send_link(int, void *, size_t, uchar_t *, size_t);
ssize_t		dlpi_sendto(int, void *, size_t, struct sockaddr_in *,
		    uchar_t *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* DLPI_IO_H */
