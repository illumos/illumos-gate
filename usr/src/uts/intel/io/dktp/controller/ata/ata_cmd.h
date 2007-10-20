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

#ifndef _ATA_CMD_H
#define	_ATA_CMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Common ATA commands.
 */
#define	ATC_DIAG	0x90    /* diagnose command 			*/
#define	ATC_RECAL	0x10	/* restore cmd, bottom 4 bits step rate */
#define	ATC_FORMAT	0x50	/* format track command 		*/
#define	ATC_SET_FEAT	0xef	/* set features				*/
#define	ATC_IDLE_IMMED	0xe1	/* idle immediate			*/
#define	ATC_STANDBY_IM	0xe0	/* standby immediate			*/
#define	ATC_DOOR_LOCK	0xde	/* door lock				*/
#define	ATC_DOOR_UNLOCK	0xdf	/* door unlock				*/
#define	ATC_IDLE	0xe3	/* idle					*/
#define	ATC_SLEEP	0xe6	/* sleep				*/

/*
 * ATA/ATAPI-4 disk commands.
 */
#define	ATC_DEVICE_RESET	0x08    /* ATAPI device reset */
#define	ATC_EJECT		0xed	/* media eject */
#define	ATC_FLUSH_CACHE		0xe7	/* flush write-cache */
#define	ATC_ID_DEVICE		0xec    /* IDENTIFY DEVICE */
#define	ATC_ID_PACKET_DEVICE	0xa1	/* ATAPI identify packet device */
#define	ATC_INIT_DEVPARMS	0x91	/* initialize device parameters */
#define	ATC_PACKET		0xa0	/* ATAPI packet */
#define	ATC_RDMULT		0xc4	/* read multiple */
#define	ATC_RDSEC		0x20    /* read sector */
#define	ATC_RDVER		0x40	/* read verify */
#define	ATC_READ_DMA		0xc8	/* read (multiple) w/DMA */
#define	ATC_SEEK		0x70    /* seek */
#define	ATC_SERVICE		0xa2	/* queued/overlap service */
#define	ATC_SETMULT		0xc6	/* set multiple mode */
#define	ATC_WRITE_DMA		0xca	/* write (multiple) w/DMA */
#define	ATC_WRMULT		0xc5	/* write multiple */
#define	ATC_WRSEC		0x30    /* write sector */

/*
 * Low bits for Read/Write commands...
 */
#define	ATCM_ECCRETRY	0x01    /* Enable ECC and RETRY by controller 	*/
				/* enabled if bit is CLEARED!!! 	*/
#define	ATCM_LONGMODE	0x02    /* Use Long Mode (get/send data & ECC) 	*/


/*
 * Obsolete ATA commands.
 */

#define	ATC_RDLONG	0x23    /* read long without retry	*/
#define	ATC_ACK_MC	0xdb	/* acknowledge media change		*/

#ifdef	__cplusplus
}
#endif

#endif /* _ATA_CMD_H */
