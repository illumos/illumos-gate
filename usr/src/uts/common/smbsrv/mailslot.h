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

#ifndef _SMBSRV_MAILSLOT_H
#define	_SMBSRV_MAILSLOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Mailslots are a one-way, unreliable IPC mechanism that allows a
 * client to send or broadcast messages to a server. The names follow
 * the same universal naming convention (UNC) used with named pipes:
 * \\server\mailslot\name, \\.\mailslot\name etc. There is a good
 * overview of mailslots, including limitations of NT and Windows 2000,
 * in Network Programming for Microsoft Windows Chapter 3.
 *
 * Network Programming for Microsoft Windows
 * Anthony Jones and Jim Ohlund
 * Microsoft Press, ISBN 0-7356-0560-2
 *
 * This file defines pre-defined and system common mailslots.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Well-known or pre-defined mailslots.
 */
#define	MAILSLOT_LANMAN			"\\MAILSLOT\\LANMAN"
#define	MAILSLOT_MSBROWSE		"\\MAILSLOT\\MSBROWSE"
#define	MAILSLOT_BROWSE			"\\MAILSLOT\\BROWSE"
#define	MAILSLOT_NETLOGON		"\\MAILSLOT\\NET\\NETLOGON"
#define	MAILSLOT_NTLOGON		"\\MAILSLOT\\NET\\NTLOGON"


/*
 * System common mailslots. These should be dynamically assigned
 * at runtime but we don't support a full mailslot implementation
 * so we use a set of predefined values that appear to work.
 */
#define	MAILSLOT_NETLOGON_RDC		"\\MAILSLOT\\NET\\GETDC354"
#define	MAILSLOT_NETLOGON_MDC		"\\MAILSLOT\\NET\\GETDC576"
#define	MAILSLOT_NETLOGON_SAMLOGON_RDC	"\\MAILSLOT\\NET\\GETDC873"
#define	MAILSLOT_NETLOGON_SAMLOGON_MDC	"\\MAILSLOT\\NET\\GETDC875"


#ifdef __cplusplus
}
#endif


#endif /* _SMBSRV_MAILSLOT_H */
