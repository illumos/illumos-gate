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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NETWORK_H
#define	_NETWORK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	NETWORK_ERROR_UNKNOWN		-1
#define	NETWORK_ERROR_HOST		-2
#define	NETWORK_ERROR_SERVICE		-3
#define	NETWORK_ERROR_PORT		-4
#define	NETWORK_ERROR_SEND_RESPONSE	-5
#define	NETWORK_ERROR_SEND_FAILED	-6

#define	ACK(fd)	net_write(fd, "", 1);
#define	NACK(fd) net_write(fd, "\1", 1);

extern int	net_open(char *host, int timeout);
extern int	net_close(int nd);
extern int	net_read(int nd, char *buf, int len);
extern int	net_write(int nd, char *buf, int len);
extern int	net_printf(int nd, char *fmt, ...);
extern char	*net_gets(char *buf, int size, int nd);
extern int	net_send_message(int nd, char *fmt, ...);
extern int	net_response(int nd);
extern int	net_send_file(int nd, char *name, char *data, int data_len,
				int type);

#ifdef __cplusplus
}
#endif

#endif /* _NETWORK_H */
