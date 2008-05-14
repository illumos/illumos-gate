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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_1394_TARGETS_SCSA1394_CMD_H
#define	_SYS_1394_TARGETS_SCSA1394_CMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * scsa1394 command
 */

#include <sys/scsi/scsi_types.h>
#include <sys/1394/targets/scsa1394/sbp2.h>
#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* preferred pkt_private length in 64-bit quantities */
#ifdef  _LP64
#define	SCSA1394_CMD_PRIV_SIZE	2
#else /* _ILP32 */
#define	SCSA1394_CMD_PRIV_SIZE	1
#endif
#define	SCSA1394_CMD_PRIV_LEN   (SCSA1394_CMD_PRIV_SIZE * sizeof (uint64_t))

/* entry describing a page table segment */
typedef struct scsa1394_cmd_seg {
	size_t			ss_len;
	uint64_t		ss_daddr;
	uint64_t		ss_baddr;
	t1394_addr_handle_t	ss_addr_hdl;
} scsa1394_cmd_seg_t;

/* command packet structure */
typedef struct scsa1394_cmd {
	sbp2_task_t		sc_task;	/* corresponding SBP-2 task */
	struct scsa1394_lun	*sc_lun;	/* lun it belongs to */
	int			sc_state;	/* command state */
	int			sc_flags;	/* command flags */
	struct buf		*sc_bp;		/* data buffer */
	struct scsi_pkt		*sc_pkt;	/* corresponding scsi pkt */
	size_t			sc_cdb_len;
	size_t			sc_cdb_actual_len;
	size_t			sc_scb_len;
	size_t			sc_priv_len;
	uchar_t			sc_cdb[SCSI_CDB_SIZE];
	uchar_t			sc_pkt_cdb[SCSI_CDB_SIZE];
	struct scsi_arq_status	sc_scb;
	uint64_t		sc_priv[SCSA1394_CMD_PRIV_SIZE];
	clock_t			sc_start_time;
	int			sc_timeout;

	/* DMA: command ORB */
	ddi_dma_handle_t	sc_orb_dma_hdl;
	ddi_acc_handle_t	sc_orb_acc_hdl;
	ddi_dma_cookie_t	sc_orb_dmac;
	t1394_addr_handle_t	sc_orb_addr_hdl;

	/* DMA: data buffer */
	ddi_dma_handle_t	sc_buf_dma_hdl;
	uint_t			sc_buf_nsegs;	/* # of segments/cookies */
	uint_t			sc_buf_nsegs_alloc; /* # of entries allocated */
	scsa1394_cmd_seg_t	*sc_buf_seg;	/* segment array */
	scsa1394_cmd_seg_t	sc_buf_seg_mem;	/* backstore for one segment */
	uint_t			sc_nwin;	/* # windows */
	uint_t			sc_curwin;	/* current window */
	off_t			sc_win_offset;	/* current window offset */
	size_t			sc_win_len;	/* current window length */
	size_t			sc_xfer_bytes;	/* current xfer byte count */
	size_t			sc_xfer_blks;	/* current xfer blk count */

	/* DMA: page table */
	ddi_dma_handle_t	sc_pt_dma_hdl;
	ddi_acc_handle_t	sc_pt_acc_hdl;
	ddi_dma_cookie_t	sc_pt_dmac;
	caddr_t			sc_pt_kaddr;
	uint64_t		sc_pt_baddr;
	t1394_addr_handle_t	sc_pt_addr_hdl;
	size_t			sc_pt_ent_alloc; /* # allocated entries */
	int			sc_pt_cmd_size;

	/* for symbios mode only */
	int			sc_lba;		/* start LBA */
	int			sc_blk_size;	/* xfer block size */
	size_t			sc_total_blks;	/* total xfer blocks */
	size_t			sc_resid_blks;	/* blocks left */

	struct scsi_pkt		sc_scsi_pkt;	/* must be last */
						/* embedded SCSI packet */
						/* ... scsi_pkt_size() */
} scsa1394_cmd_t;
#define	SCSA1394_CMD_SIZE	(sizeof (struct scsa1394_cmd) - \
				sizeof (struct scsi_pkt) + scsi_pkt_size())

_NOTE(SCHEME_PROTECTS_DATA("unique per task", { scsa1394_cmd scsa1394_cmd_seg
    scsi_pkt scsi_inquiry scsi_extended_sense scsi_cdb scsi_arq_status }))

#define	PKT2CMD(pktp)	((scsa1394_cmd_t *)((pktp)->pkt_ha_private))
#define	CMD2PKT(cmdp)	((struct scsi_pkt *)((cmdp)->sc_pkt))
#define	TASK2CMD(task)	((scsa1394_cmd_t *)(task)->ts_drv_priv)
#define	CMD2TASK(cmdp)	((sbp2_task_t *)&(cmdp)->sc_task)

/* state */
enum {
	SCSA1394_CMD_INIT,
	SCSA1394_CMD_START,
	SCSA1394_CMD_STATUS
};

/* flags */
enum {
	SCSA1394_CMD_CDB_EXT		= 0x0001,
	SCSA1394_CMD_PRIV_EXT		= 0x0002,
	SCSA1394_CMD_SCB_EXT		= 0x0004,
	SCSA1394_CMD_EXT		= (SCSA1394_CMD_CDB_EXT |
					    SCSA1394_CMD_PRIV_EXT |
					    SCSA1394_CMD_SCB_EXT),

	SCSA1394_CMD_DMA_CDB_VALID	= 0x0008,
	SCSA1394_CMD_DMA_BUF_BIND_VALID	= 0x0010,
	SCSA1394_CMD_DMA_BUF_PT_VALID	= 0x0020,
	SCSA1394_CMD_DMA_BUF_ADDR_VALID	= 0x0040,
	SCSA1394_CMD_DMA_BUF_VALID	= (SCSA1394_CMD_DMA_BUF_BIND_VALID |
					    SCSA1394_CMD_DMA_BUF_ADDR_VALID |
					    SCSA1394_CMD_DMA_BUF_PT_VALID),
	SCSA1394_CMD_DMA_BUF_MAPIN	= 0x0080,

	SCSA1394_CMD_READ		= 0x0100,
	SCSA1394_CMD_WRITE		= 0x0200,
	SCSA1394_CMD_RDWR		= (SCSA1394_CMD_READ |
					    SCSA1394_CMD_WRITE),

	SCSA1394_CMD_SYMBIOS_BREAKUP	= 0x400
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_TARGETS_SCSA1394_CMD_H */
