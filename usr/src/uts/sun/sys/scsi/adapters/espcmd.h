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

#ifndef	_SYS_SCSI_ADAPTERS_ESPCMD_H
#define	_SYS_SCSI_ADAPTERS_ESPCMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/isa_defs.h>
#include <sys/scsi/scsi_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * preferred pkt_private length in 64-bit quantities
 */
#ifdef	_LP64
#define	PKT_PRIV_SIZE	2
#define	PKT_PRIV_LEN	16	/* in bytes */
#else /* _ILP32 */
#define	PKT_PRIV_SIZE	1
#define	PKT_PRIV_LEN	8	/* in bytes */
#endif

/*
 * define size of extended scsi cmd pkt (ie. includes ARQ)
 */
#define	EXTCMDS_STATUS_SIZE  (sizeof (struct scsi_arq_status))

/*
 * esp_cmd is selectively zeroed.  During packet allocation, some
 * fields need zeroing, others will be initialized in esp_prepare_pkt()
 *
 * preferred cdb size is 12 since esp is a scsi2 HBA driver and rarely
 * needs 16 byte CDBs
 */
struct esp_cmd {
	struct esp_cmd		*cmd_forw;	/* ready fifo que link	*/
	uchar_t			*cmd_cdbp;	/* active command pointer */
	uchar_t			*cmd_scbp;	/* active status pointer */
	uint_t			cmd_flags;	/* private flags */

	uint32_t		cmd_data_count;	/* aggregate data count */
	uint32_t		cmd_cur_addr;	/* current dma address */

	ushort_t		cmd_nwin;	/* number of windows */
	ushort_t		cmd_cur_win;	/* current window */

	ushort_t		cmd_saved_win;	/* saved window */
	uint32_t		cmd_saved_data_count; /* saved aggr. count */
	uint32_t		cmd_saved_cur_addr; /* saved virt address */

	ddi_dma_handle_t	cmd_dmahandle;	/* dma handle */
	ddi_dma_cookie_t	cmd_dmacookie;	/* current dma cookie */
	uint32_t		cmd_dmacount;	/* total xfer count */

	clock_t			cmd_timeout;	/* command timeout */
	uchar_t			cmd_cdb[CDB_SIZE]; /* 12 byte cdb size */
	uint64_t		cmd_pkt_private[PKT_PRIV_SIZE];
	uchar_t			cmd_cdblen;	/* actual length of cdb */
	uchar_t			cmd_cdblen_alloc; /* length of cdb alloc'ed */
	uchar_t			cmd_qfull_retries; /* QFULL retry count */
	uint_t			cmd_scblen;	/* length of scb */
	uint_t			cmd_privlen;	/* length of tgt private */
	uchar_t			cmd_scb[EXTCMDS_STATUS_SIZE]; /* arq size  */
	ushort_t		cmd_age;	/* cmd age (tagged queing) */
	uchar_t			cmd_tag[2];	/* command tag */
	struct scsi_pkt		cmd_pkt;	/* must be last */
						/* the generic packet itself */
						/* ... scsi_pkt_size() */
};
#define	ESP_CMD_SIZE		(sizeof (struct esp_cmd) - \
				sizeof (struct scsi_pkt) + scsi_pkt_size())


/*
 * These are the defined flags for this structure.
 */
#define	CFLAG_CMDDISC		0x0001	/* cmd currently disconnected */
#define	CFLAG_WATCH		0x0002	/* watchdog time for this command */
#define	CFLAG_FINISHED		0x0004	/* command completed */
#define	CFLAG_COMPLETED		0x0010	/* completion routine called */
#define	CFLAG_PREPARED		0x0020	/* pkt has been init'ed */
#define	CFLAG_IN_TRANSPORT 	0x0040	/* in use by host adapter driver */
#define	CFLAG_RESTORE_PTRS	0x0080	/* implicit restore ptr on reconnect */
#define	CFLAG_TRANFLAG		0x00ff	/* covers transport part of flags */
#define	CFLAG_CMDPROXY		0x000100	/* cmd is a 'proxy' command */
#define	CFLAG_CMDARQ		0x000200	/* cmd is a 'rqsense' command */
#define	CFLAG_DMAVALID		0x000400	/* dma mapping valid */
#define	CFLAG_DMASEND		0x000800	/* data is going 'out' */
#define	CFLAG_CMDIOPB		0x001000	/* this is an 'iopb' packet */
#define	CFLAG_CDBEXTERN		0x002000	/* cdb kmem_alloc'd */
#define	CFLAG_SCBEXTERN		0x004000	/* scb kmem_alloc'd */
#define	CFLAG_FREE		0x008000	/* packet is on free list */
#define	CFLAG_PRIVEXTERN	0x020000 	/* kmem_alloc'd */
#define	CFLAG_DMA_PARTIAL	0x040000 	/* partial xfer OK */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_ADAPTERS_ESPCMD_H */
