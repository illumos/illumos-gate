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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * PMC Compile Time Tunable Parameters
 */
#ifndef	_PMCS_PARAM_H
#define	_PMCS_PARAM_H
#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Maximum number of microseconds we will try to configure a PHY
 */
#define	PMCS_MAX_CONFIG_TIME	(60 * 1000000)

#define	PMCS_MAX_OQ		64	/* maximum number of OutBound Queues */
#define	PMCS_MAX_IQ		64	/* maximum number of InBound Queues */

#define	PMCS_MAX_PORTS		16	/* maximum port contexts */

#define	PMCS_MAX_XPND		16	/* 16 levels of expansion */

#define	PMCS_INDICES_SIZE	512

#define	PMCS_MIN_CHUNK_PAGES	512
#define	PMCS_ADDTL_CHUNK_PAGES	8

/*
 * Maximum amount of time (in milliseconds) we'll wait for writing one chunk
 * of firmware image data to the chip
 */
#define	PMCS_FLASH_WAIT_TIME	10000	/* 10 seconds */

/*
 * Scratch area has to hold Max SMP Request and Max SMP Response,
 * plus some slop.
 */
#define	PMCS_SCRATCH_SIZE	2304
#define	PMCS_INITIAL_DMA_OFF	PMCS_INDICES_SIZE+PMCS_SCRATCH_SIZE
#define	PMCS_CONTROL_SIZE	ptob(1)

/*
 * 2M bytes was allocated to firmware log and split between two logs
 */
#define	PMCS_FWLOG_SIZE		(2 << 20)
#define	PMCS_FWLOG_MAX		5	/* maximum logging level */
#define	PMCS_FWLOG_THRESH	75	/* Write to file when log this % full */

#define	SATLSIZE		1024

/*
 * PMCS_NQENTRY is tunable by setting pmcs-num-io-qentries
 */
#define	PMCS_NQENTRY		512	/* 512 entries per queue */
#define	PMCS_MIN_NQENTRY	32	/* No less than 32 entries per queue */
#define	PMCS_QENTRY_SIZE	64	/* 64 bytes per entry */
#define	PMCS_MSG_SIZE		(PMCS_QENTRY_SIZE >> 2)

/*
 * Watchdog interval, in usecs.
 * NB: Needs to be evenly divisible by 10
 */
#define	PMCS_WATCH_INTERVAL	250000	/* watchdog interval in us */

/*
 * Forward progress trigger. This is the number of times we run through
 * watchdog before checking for forward progress.  Implicitly bound to
 * PMCS_WATCH_INTERVAL above. For example, with a PMCS_WATCH_INTERVAL of
 * 250000, the watchdog will run every quarter second, so forward progress
 * will be checked every 16th watchdog fire, or every four seconds.
 */
#define	PMCS_FWD_PROG_TRIGGER	16

/*
 * Inbound Queue definitions
 */
#define	PMCS_NIQ		9	/* 9 Inbound Queues */
#define	PMCS_IO_IQ_MASK		7	/* IO queues are 0..7 */
#define	PMCS_IQ_OTHER		8	/* "Other" queue is 8 (HiPri) */
#define	PMCS_NON_HIPRI_QUEUES	PMCS_IO_IQ_MASK

/*
 * Outbound Queue definitions
 *
 * Note that the OQ definitions map to bits set in
 * the Outbound Doorbell register to indicate service
 * is needed on one of these queues.
 */
#define	PMCS_NOQ		3	/* 3 Outbound Queues */

#define	PMCS_OQ_IODONE		0	/* I/O completion Outbound Queue */
#define	PMCS_OQ_GENERAL		1	/* General Outbound Queue */
#define	PMCS_OQ_EVENTS		2	/* Event Outbound Queue */


/*
 * External Scatter Gather come in chunks- each this many deep.
 */
#define	PMCS_SGL_NCHUNKS	16	/* S/G List Chunk Size */
#define	PMCS_MAX_CHUNKS		32	/* max chunks per command */

/*
 * MSI/MSI-X related definitions.
 *
 * These are the maximum number of interrupt vectors we could use.
 */
#define	PMCS_MAX_MSIX		(PMCS_NOQ + 1)
#define	PMCS_MAX_MSI		PMCS_MAX_MSIX
#define	PMCS_MAX_FIXED		1

#define	PMCS_MSIX_IODONE	PMCS_OQ_IODONE	/* I/O Interrupt vector */
#define	PMCS_MSIX_GENERAL	PMCS_OQ_GENERAL	/* General Interrupt vector */
#define	PMCS_MSIX_EVENTS	PMCS_OQ_EVENTS	/* Events Interrupt vector */
#define	PMCS_MSIX_FATAL		(PMCS_MAX_MSIX-1)	/* Fatal Int vector */

#define	PMCS_FATAL_INTERRUPT	15	/* fatal interrupt OBDB bit */

/*
 * Blessed firmware version
 */
#define	PMCS_FIRMWARE_CODE_NAME		"firmware"
#define	PMCS_FIRMWARE_ILA_NAME		"ila"
#define	PMCS_FIRMWARE_SPCBOOT_NAME	"SPCBoot"
#define	PMCS_FIRMWARE_START_SUF		".bin_start"
#define	PMCS_FIRMWARE_END_SUF		".bin_end"
#define	PMCS_FIRMWARE_FILENAME		"misc/pmcs/pmcs8001fw"
#define	PMCS_FIRMWARE_VERSION_NAME	"pmcs8001_fwversion"

/*
 * These are offsets from the end of the image
 */
#define	PMCS_FW_VER_OFFSET		528
#define	PMCS_ILA_VER_OFFSET		528

#ifdef	__cplusplus
}
#endif
#endif	/* _PMCS_PARAM_H */
