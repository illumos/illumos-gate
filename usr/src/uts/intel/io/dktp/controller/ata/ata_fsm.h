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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ATA_FSM_H
#define	_ATA_FSM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 *
 * The interrupt reason can be interpreted from other bits as follows:
 *
 *  IO  CoD  DRQ
 *  --  ---  ---
 *   0    0    1  == 1 Data to device
 *   0    1    0  == 2 Idle
 *   0    1    1  == 3 Send ATAPI CDB to device
 *   1    0    1  == 5 Data from device
 *   1    1    0  == 6 Status ready
 *   1    1    1  == 7 Future use
 *
 */

/*
 * This macro encodes the interrupt reason into a one byte
 * event code which is used to index the FSM tables
 */
#define	ATAPI_EVENT(drq, intr)	\
	(((unsigned char)((drq) & ATS_DRQ) >> 3) \
	| (((intr) & (ATI_IO | ATI_COD)) << 1))

/*
 * These are the names for the encoded ATAPI events
 */
#define	ATAPI_EVENT_0		0
#define	ATAPI_EVENT_IDLE	ATAPI_EVENT(0, ATI_COD)
#define	ATAPI_EVENT_2		2
#define	ATAPI_EVENT_STATUS	ATAPI_EVENT(0, ATI_IO | ATI_COD)
#define	ATAPI_EVENT_PIO_OUT	ATAPI_EVENT(ATS_DRQ, 0)
#define	ATAPI_EVENT_CDB		ATAPI_EVENT(ATS_DRQ, ATI_COD)
#define	ATAPI_EVENT_PIO_IN	ATAPI_EVENT(ATS_DRQ, ATI_IO)
#define	ATAPI_EVENT_UNKNOWN	ATAPI_EVENT(ATS_DRQ, (ATI_IO | ATI_COD))

#define	ATAPI_NEVENTS		8

/*
 * Actions for the ATAPI PIO FSM
 *
 */

enum {
	A_UNK,		/* invalid event detected */
	A_NADA,		/* do nothing */
	A_CDB,		/* send the CDB */
	A_IN,		/* transfer data out to the device */
	A_OUT,		/* transfer data in from the device */
	A_IDLE,		/* unexpected idle phase */
	A_RE,		/* read the error code register */
	A_REX		/* alternate read the error code register */
};

/*
 * States for the ATAPI PIO FSM
 */

enum {
	S_IDLE,		/* idle or fatal error state */
	S_CMD,		/* command byte sent */
	S_CDB,		/* CDB sent */
	S_IN,		/* transferring data in from device */
	S_OUT,		/* transferring data out to device */
	S_DMA,		/* dma transfer active */

	ATAPI_NSTATES
};

#define	S_X	S_IDLE	/* alias for idle */

/*
 * controller and device functions
 */
enum {
	ATA_FSM_START0,
	ATA_FSM_START1,
	ATA_FSM_INTR,
	ATA_FSM_FINI,
	ATA_FSM_RESET,

	ATA_CTLR_NFUNCS
};


/*
 * FSM return codes
 */
enum {
	ATA_FSM_RC_OKAY,
	ATA_FSM_RC_BUSY,
	ATA_FSM_RC_INTR,
	ATA_FSM_RC_FINI
};

/*
 * states for the controller FSM
 */
enum {
	AS_IDLE,
	AS_ACTIVE0,
	AS_ACTIVE1,

	ATA_CTLR_NSTATES
};

/*
 * actions for the controller FSM
 */
enum {
	AC_NADA,
	AC_START,
	AC_INTR,
	AC_FINI,
	AC_BUSY,
	AC_RESET_I,
	AC_RESET_A
};

#ifdef	__cplusplus
}
#endif

#endif /* _ATA_FSM_H */
