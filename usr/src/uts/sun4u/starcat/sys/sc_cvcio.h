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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SC_CVCIO_H
#define	_SYS_SC_CVCIO_H

#include <sys/sysmacros.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Layout of console IOSRAM chunks
 *         |---------------|
 *  CONC   |  cvc_ctl_t    |
 *         |  128 bytes    |
 *         |---------------|
 *
 *         |---------------|
 *  CONI   | input count   |
 *         |  2 bytes      |
 *         |---------------|
 *         | receive buffer|
 *         |  1022 bytes   |
 *         |---------------|
 *
 *         |---------------|
 *  CONO   | output count  |
 *         |  2 bytes      |
 *         |---------------|
 *         | send buffer   |
 *         | 1022 bytes    |
 *         |---------------|
 */

#define	IOSRAM_KEY_CONC 0x434F4E43
#define	IOSRAM_KEY_CONI 0x434F4E49
#define	IOSRAM_KEY_CONO 0x434F4E4F

#define	CONSBUF_IN_SIZE		1024
#define	CONSBUF_OUT_SIZE	1024
#define	CONSBUF_COUNT_SIZE	(sizeof (short))

#define	MAX_XFER_CINPUT		(CONSBUF_IN_SIZE - CONSBUF_COUNT_SIZE)
#define	MAX_XFER_COUTPUT	(CONSBUF_OUT_SIZE - CONSBUF_COUNT_SIZE)
#define	COUNT_OFFSET		0
#define	DATA_OFFSET		(CONSBUF_COUNT_SIZE)

#define	cvc_username		"sms"
#define	CVCD_SERVICE		"cvc_hostd"
#define	MAX_CONS_CONN		100
#define	MAXPKTSZ		4096

#define	TCP_DEV			"/dev/tcp"
#define	CVCREDIR_DEV		"/devices/pseudo/cvcredir@0:cvcredir"


/*
 * ioctl commands passed to cvcredir (and possibly on to cvc from there) by cvcd
 */
#define	CVC			'N'
#define	CVC_BREAK		((CVC<<8) | 0x00)
#define	CVC_DISCONNECT		((CVC<<8) | 0x01)

/*
 * DXS (the SC-side console traffic application) may send a few of these codes
 * to cvcd as expedited TLI traffic.  The rest are not used in domain-side
 * software, but SC-side software may use them.
 */
#define	CVC_CONN_BREAK		0x1	/* Break to OBP or kmdb */
#define	CVC_CONN_DIS		0x2	/* disconnect */
#define	CVC_CONN_STAT		0x4	/* status of CVC connects */
#define	CVC_CONN_WRITE		0x8	/* ask write permission */
#define	CVC_CONN_RELW		0x10    /* release write permission */
#define	CVC_CONN_WRLK		0x20    /* Lock the Write */
#define	CVC_CONN_PRIVATE	0x40    /* Only one session is allowed */
#define	CVC_CONN_SWITCH		0x41	/* Switch communication path */

/*
 * This structure represents the layout of control data in the CONC chunk.
 * It should NOT grow beyond 128 bytes, as that is the max size that was
 * identified for the CONC chunk.
 */
typedef struct cvc_ctl {
	uint8_t		command;	/* CVC_IOSRAM_BREAK, etc */
	uint8_t		version;	/* currently unused */
	uint8_t		unused1[2];	/* currently unused */
	uint16_t	winsize_rows;
	uint16_t	winsize_cols;
	uint16_t	winsize_xpixels;
	uint16_t	winsize_ypixels;
	uint8_t		unused2[116];	/* currently unused */
} cvc_ctl_t;

/*
 * These macros can be used to determine the offset or size of any field in the
 * CONC chunk.
 */
#define	CVC_CTL_OFFSET(field)  offsetof(cvc_ctl_t, field)
#define	CVC_CTL_SIZE(field)    (sizeof (((cvc_ctl_t *)0)->field))

/*
 * Commands sent across IOSRAM from domain_server to cvc driver
 */
#define	CVC_IOSRAM_BREAK	1
#define	CVC_IOSRAM_DISCONNECT	2
#define	CVC_IOSRAM_VIA_NET	3
#define	CVC_IOSRAM_VIA_IOSRAM	4
#define	CVC_IOSRAM_WIN_RESIZE	5

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SC_CVCIO_H */
