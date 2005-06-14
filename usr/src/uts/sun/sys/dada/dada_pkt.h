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
 * Copyright 1996, 1999-2000, 2002 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DADA_DADA_PKT_H
#define	_SYS_DADA_DADA_PKT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dada/dada_types.h>

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * DCD pkt definition.
 *
 *	This structure defined the packet which is allocated by a library
 *	function and handed to a target driver. The target driver fills
 *	in some information, and passes it to the library for transport
 *	to an addressed DCD devices. The host adapter found by the library
 * 	fills in some other information as the command is processed. When
 *	the command completes (or can be taken  no further) the function
 *	specified in the pkt is called with a pointer to the packet as
 *	argument. For fields within the packet, the target driver can
 *	determine the success or failure of the command.
 */


struct	dcd_pkt	{
	uchar_t		*pkt_cdbp;		/* pointer to command block */
	uchar_t		*pkt_scbp;		/* ptr to status block */
	int		pkt_flags;		/* Pkt flags */
	int		pkt_time;		/* Completion timeout */
	int		pkt_scblen;		/* Scb length */
	int		pkt_cdblen;		/* Length of cdb */
	uint_t		pkt_state;		/* State of command */
	uint_t		pkt_statistics;		/* Statistics */
	uint_t		pkt_reason;		/* reason or error stat */
	uint_t		pkt_secleft;		/* remaining sectors */
	void		(*pkt_comp)();		/* Pkt Completion routine */
	ssize_t		pkt_resid;		/* bytes not transfered */
	daddr32_t	pkt_startsec;		/* Starting sector */
	ataopaque_t	pkt_private;		/* Target drivers priV data */
	ataopaque_t	pkt_ha_private;		/* HBA private data */
	ataopaque_t	pkt_passthru;		/* pass through command ptr */
	struct	dcd_address	pkt_address;	/* destination address */
	uint_t		version_no;		/* Version Number of this */
	ushort_t	reserved[2];		/* Reserved for future */
};

/*
 * definition for the pkt_flags field.
 */

/*
 * Following defines are generic.
 */

#define	FLAG_NOINTR	0x0001	/* Run command with no cmd completion */
				/* callback; command has been complted */
				/* up return from dcd_transport(9F)   */

#define	FLAG_NODICON	0x0002	/* Even is overlap is possible donot do it */
#define	FLAG_NOPARITY	0x0008	/* Run command without parity checking */
#define	FLAG_FORCENOINTR\
			0x0010	/* Force command with to run in polled mode */

#define	FLAG_IMMEDIATE_CB\
			0x0800	/* Immediate callback on command completion */


/*
 * The following flags are they needed ???
 */
#define	FLAG_SILENT	0x00010000
#define	FLAG_DIAGNOSE	0x00020000
#define	FLAG_ISOLATE	0x00040000


/*
 * Definitions for pkt_reason field.
 */

/*
 * Following defines are generic.
 */
#define	CMD_CMPLT	0	/* no transport errors - normal completion */
#define	CMD_INCOMPLETE	1	/* transport stopped with not normal state */
#define	CMD_DMA_DERR	2	/* dama direction error occurred */
#define	CMD_TRAN_ERR	3	/* Unspecified transport error */
#define	CMD_RESET	4	/* Target completed hard reset sequence */
#define	CMD_ABORTED	5 	/* Command transport aborted on request */
#define	CMD_TIMEOUT	6	/* Command timedout */
#define	CMD_DATA_OVR	7	/* Data Overrun */
#define	CMD_CMD_OVR	8	/* Command Overrun  - Not used */
#define	CMD_STS_OVR	9	/* Status Overrun - Not used */
#define	CMD_FATAL	10	/* There is a fatal error */


/*
 * definitions for pkt_state field.
 */
#define	STATE_SENT_CMD		0x04	/* Command successsully sent */
#define	STATE_XFERRED_DATA	0x08	/* Data Transfer took place */
#define	STATE_GOT_STATUS	0x10	/* Status got */


/*
 * Definitions for pkt_statistics field
 */

/*
 * Following defines are generic.
 */

#define	STAT_ATA_BUS_RESET	0x08	/* TBD */
#define	STAT_ATA_DEV_RESET	0x10	/* TBD */
#define	STAT_ATA_ABORTED	0x20	/* Command was aborted */
#define	STAT_ATA_TERMINATED 	0x80	/* Command was terminated */
#define	STAT_ATA_TIMEOUT	0x40	/* Command experienced a timeout */


/*
 * Following filds are appropriate depending on feature used.
 */
#define	STAT_ATA_DISCON	0x01	/* Command is doing overlap processing */
#define	STAT_ATA_SYNC	0x02	/* May be used for DMA transfers */
#define	STAT_ATA_PERR	0x04	/* Command experienced a parity error */


/*
 * Definitions for what dcd_transport returns
 */
#define	TRAN_ACCEPT	1
#define	TRAN_BUSY	0
#define	TRAN_BADPKT	-1
#define	TRAN_FATAL_ERROR -2	/* The hba cannot accept any pkt */


#ifdef _KERNEL
/*
 * Kernel function declarations
 */

#define	ata_pkt_transport	dcd_transport

#ifdef	__STDC__
extern int dcd_transport(struct dcd_pkt *);
#else	/* __STDC__ */
extern int dcd_transport();
#endif	/* __STDC__ */

#define	DCD_POLL_TIMEOUT	60

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DADA_DADA_PKT_H */
