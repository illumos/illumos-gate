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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CVC_H
#define	_CVC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	cvc_username		"ssp"
#define	CVCD_SERVICE		"cvc_hostd"
#define	CVC_CONN_SERVICE	"cvc"
#define	MAX_CVC_CONN		100
#define	MAXPKTSZ		4096

#define	TRUE			1
#define	FALSE			0

/*
 * Network Redirection driver ioctl to jump into debugger.
 */
#define	CVC	'N'
#define	CVC_BREAK	(CVC<<8)
#define	CVC_DISCONNECT	((CVC<<8)|0x1)

#define	CVC_CONN_BREAK		0x1	/* Break to OBP or kmdb */
#define	CVC_CONN_DIS		0x2	/* disconnect */
#define	CVC_CONN_STAT		0x4	/* status of CVC connects */
#define	CVC_CONN_WRITE		0x8	/* ask write permission */
#define	CVC_CONN_RELW		0x10    /* release write permission */
#define	CVC_CONN_WRLK		0x20    /* Lock the Write */
#define	CVC_CONN_PRIVATE	0x40    /* Only one session is allowed */
#define	CVC_CONN_SWITCH		0x41	/* Switch communication path */


#define	TCP_DEV		"/dev/tcp"
#define	CVCREDIR_DEV	"/devices/pseudo/cvcredir@0:cvcredir"

/*
 * Layout of BBSRAM input and output buffers:
 *
 *
 *         |---------------|
 * 0x1f400 | control msg   |  Receive buffer is reduced by two bytes to
 *         |    1 byte     |  accomodate a control msg area in which
 *         |---------------|  information is sent from obp_helper to the
 *         |  send buffer  |  cvc driver (e.g. break to obp) when
 *         |               |  communication is over BBSRAM.
 *         |  1020 bytes   |
 *         |---------------|
 *         | send  count   |
 * 0x1f7fe |  2 bytes      |
 *         |---------------|
 *         | receive buffer|
 *         |               |
 *         | 1022 bytes    |
 *         |---------------|
 *         | output count  |
 * 0x1fbfe |  2 bytes      |
 *         |---------------|
 *
 */

#define	BBSRAM_COUNT_SIZE	sizeof (short)
#define	CVC_IN_SIZE		256
#define	CVC_OUT_SIZE		1024
#define	MAX_XFER_INPUT		(CVC_IN_SIZE - BBSRAM_COUNT_SIZE)
#define	MAX_XFER_OUTPUT		(CVC_OUT_SIZE - BBSRAM_COUNT_SIZE)

#define	BBSRAM_OUTPUT_COUNT_OFF (CVC_OUT_SIZE - BBSRAM_COUNT_SIZE)
#define	BBSRAM_INPUT_COUNT_OFF  (CVC_OUT_SIZE + CVC_IN_SIZE - BBSRAM_COUNT_SIZE)

/*
 * Control msgs sent across BBSRAM from obp_helper to cvc driver
 */
#define	CVC_BBSRAM_BREAK	1
#define	CVC_BBSRAM_DISCONNECT	2
#define	CVC_BBSRAM_VIA_NET	3
#define	CVC_BBSRAM_VIA_BBSRAM	4
#define	CVC_BBSRAM_CLOSE_NET	5

#ifdef _KERNEL
extern void	cvc_assign_iocpu(int cpu_id);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _CVC_H */
