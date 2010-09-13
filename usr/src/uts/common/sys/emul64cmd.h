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

#ifndef _SYS_SCSI_ADAPTERS_EMUL64CMD_H
#define	_SYS_SCSI_ADAPTERS_EMUL64CMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/scsi/scsi_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PKT2CMD(pkt)		((struct emul64_cmd *)(pkt)->pkt_ha_private)
#define	CMD2PKT(sp)		((sp)->cmd_pkt)

/*
 * Per-command EMUL64 private data
 *
 *	- Allocated at same time as scsi_pkt by scsi_hba_pkt_alloc(9E)
 *	- Pointed to by pkt_ha_private field in scsi_pkt
 */
struct emul64_cmd {

	struct scsi_pkt		*cmd_pkt;	/* scsi_pkt reference */
	struct emul64_cmd		*cmd_forw;	/* queue link */
	unsigned char		*cmd_addr;	/* b_un.b_addr */
	clock_t			cmd_deadline;	/* cmd completion time */
	uint32_t		cmd_flags;	/* private flags */
	uint32_t		cmd_count;	/* b_bcount */
	uint_t			cmd_cdblen;	/* length of cdb */
	uint_t			cmd_scblen;	/* length of scb */
	struct emul64		*cmd_emul64;
};



/*
 * These are the defined flags for this structure.
 */
#define	CFLAG_FINISHED		0x0001	/* command completed */
#define	CFLAG_COMPLETED		0x0002	/* completion routine called */
#define	CFLAG_IN_TRANSPORT	0x0004	/* in use by emul64 driver */
#define	CFLAG_TRANFLAG		0x000f	/* transport part of flags */
#define	CFLAG_DMAVALID		0x0010	/* dma mapping valid */
#define	CFLAG_DMASEND		0x0020	/* data is going 'out' */
#define	CFLAG_CMDIOPB		0x0040	/* this is an 'iopb' packet */
#define	CFLAG_FREE		0x0080	/* packet is on free list */
#define	CFLAG_DMA_PARTIAL	0x0100	/* partial xfer OK */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_ADAPTERS_EMUL64CMD_H */
