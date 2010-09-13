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
 * Copyright (c) 1993 by Sun Microsystems Inc.
 */

#ifndef _SYS_TICOTSORD_H
#define	_SYS_TICOTSORD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4 1.5 */

#ifdef	__cplusplus
extern "C" {
#endif

#include	<sys/tl.h>

/*
 * Old error codes exposed in old man pages. Only for compatability.
 * Do not use in any new program.
 */
#define	TCOO_NOPEER ECONNREFUSED		/* no listener on dest addr */
#define	TCOO_PEERNOROOMONQ ECONNREFUSED	/* no room on incoming queue */
#define	TCOO_PEERBADSTATE ECONNREFUSED	/* peer in wrong state */
#define	TCOO_PEERINITIATED ECONNRESET	/* peer-initiated disconnect */
#define	TCOO_PROVIDERINITIATED ECONNRESET /* provider-initiated discon */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_TICOTSORD_H */
