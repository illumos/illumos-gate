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
 * Copyright 1990-1999, 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * UDP implementation-specific definitions
 */

#ifndef _UDP_INET_H
#define	_UDP_INET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern int		udp_header_len(struct inetgram *);
extern in_port_t	udp_ports(uint16_t *, enum Ports);
extern int		udp_input(int);
extern int		udp_output(int, struct inetgram *);
extern void		udp_socket_init(struct inetboot_socket *);

#ifdef	__cplusplus
}
#endif

#endif /* _UDP_INET_H */
