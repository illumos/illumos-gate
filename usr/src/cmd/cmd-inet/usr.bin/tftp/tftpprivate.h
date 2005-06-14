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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TFTP_PRIVATE_H
#define	_TFTP_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Global definitions for the implementation of tftp(1).
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>

#include <setjmp.h>

extern struct sockaddr_in6	sin6;		/* filled in by main */
extern int			f;		/* the opened socket */
extern int			trace;
extern int			verbose;
extern int			rexmtval;
extern int			maxtimeout;
extern int			blksize;
extern int			srexmtval;
extern int			tsize_opt;
extern jmp_buf			toplevel;

extern void	tftp_sendfile(int, char *, char *);
extern void	tftp_recvfile(int, char *, char *);

#ifdef __cplusplus
}
#endif

#endif /* _TFTP_PRIVATE_H */
