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

#ifndef	_SYS_CTFS_H
#define	_SYS_CTFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/contract.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Location of the contract filesystem.
 */
#define	CTFS_ROOT	"/system/contract"

/*
 * CTFS ioctl constants
 */
#define	CTFS_PREFIX	('c' << 24 | 't' << 16)
#define	CTFS_IOC(x, y)	(CTFS_PREFIX | (x) << 8 | (y))

/*
 * Control codes for messages written to template files.
 */
#define	CTFS_TMPL(x)	CTFS_IOC('t', x)
#define	CT_TACTIVATE	CTFS_TMPL(0)	/* Activate template */
#define	CT_TCLEAR	CTFS_TMPL(1)	/* Clear active template */
#define	CT_TCREATE	CTFS_TMPL(2)	/* Create contract from template */
#define	CT_TSET		CTFS_TMPL(3)	/* Set parameter */
#define	CT_TGET		CTFS_TMPL(4)	/* Get parameter */

/*
 * Control codes for messages written to ctl files.
 */
#define	CTFS_CTL(x)	CTFS_IOC('c', x)
#define	CT_CABANDON	CTFS_CTL(0)	/* Abandon contract */
#define	CT_CACK		CTFS_CTL(1)	/* Ack a message */
#define	CT_CQREQ	CTFS_CTL(2)	/* Request an additional quantum */
#define	CT_CADOPT	CTFS_CTL(3)	/* Adopt a contract */
#define	CT_CNEWCT	CTFS_CTL(4)	/* Define new contract */
#define	CT_CNACK	CTFS_CTL(5)	/* nack a negotiation */

/*
 * Control codes for messages written to status files.
 */
#define	CTFS_STAT(x)	CTFS_IOC('s', x)
#define	CT_SSTATUS	CTFS_STAT(0)	/* Obtain contract status */

/*
 * Control codes for messages written to event endpoints.
 */
#define	CTFS_EVT(x)	CTFS_IOC('e', x)
#define	CT_ERESET	CTFS_EVT(0)	/* Reset event queue pointer */
#define	CT_ERECV	CTFS_EVT(1)	/* Read next event */
#define	CT_ECRECV	CTFS_EVT(2)	/* Read next critical event */
#define	CT_ENEXT	CTFS_EVT(3)	/* Skip current event */
#define	CT_ERELIABLE	CTFS_EVT(4)	/* Request reliable event receipt */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CTFS_H */
