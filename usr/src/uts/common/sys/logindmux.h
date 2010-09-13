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

#ifndef	_SYS_LOGINDMUX_H
#define	_SYS_LOGINDMUX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct protocol_arg {
	dev_t	dev;
	int	flag;
};

#ifdef _SYSCALL32
struct protocol_arg32 {
	dev32_t	dev;
	int32_t flag;
};
#endif

/*
 * Telnet magic cookie
 */
#define	M_CTL_MAGIC_NUMBER	70

/*
 * Ioctl to establish linkage between a pty master stream and a
 * network stream.
 */
#ifndef TELIOC
#define	TELIOC			('n' << 8) /* XXX.sparker fixme */
#endif
#define	LOGDMX_IOC_QEXCHANGE	(TELIOC|1) /* ioctl for Q pair exchange */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LOGINDMUX_H */
