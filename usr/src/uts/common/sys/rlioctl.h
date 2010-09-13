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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_RLIOCTL_H
#define	_SYS_RLIOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef TRUE
#define	TRUE	1
#endif

#ifndef	TIOCPKT_WINDOW
#define	TIOCPKT_WINDOW	0x80
#endif

#define	TIOCPKT_FLUSHWRITE	0x02	/* flush unprocessed data */
#define	TIOCPKT_NOSTOP		0x10	/* no more ^S, ^Q */
#define	TIOCPKT_DOSTOP		0x20	/* now do ^S, ^Q */

/*
 * Rlogin protocol requests begin with two bytes of "RLOGIN_MAGIC".
 * See RFC-1282.
 */
#define	RLOGIN_MAGIC	0xff

/*
 * RL_IOC_ENABLE starts the module, inserting any (optional) data passed to
 * it at the head of the read side queue.
 */
#define	RLIOC			('r' << 8)
#define	RL_IOC_ENABLE		(RLIOC|1)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RLIOCTL_H */
