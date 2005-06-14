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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_I2O_SCSI_CMD_H
#define	_I2O_SCSI_CMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PKT_PRIV_LEN		8	/* preferred pkt_private length */
#define	PKT2CMD(pkt)		((struct i2ohba_cmd *)(pkt)->pkt_ha_private)
#define	CMD2PKT(sp)		((sp)->cmd_pkt)

/*
 * These are the defined flags for this structure.
 */
#define	CFLAG_FINISHED		0x0001  /* command completed */
#define	CFLAG_COMPLETED		0x0002  /* completion routine called */
#define	CFLAG_IN_TRANSPORT	0x0004  /* in use by isp driver */
#define	CFLAG_DELAY_TIMEOUT	0x0008	/* delay timeout */
#define	CFLAG_TRANFLAG		0x000f  /* transport part of flags */
#define	CFLAG_DMAVALID		0x0010  /* dma mapping valid */
#define	CFLAG_DMASEND		0x0020  /* data is going 'out' */
#define	CFLAG_CMDIOPB		0x0040  /* this is an 'iopb' packet */
#define	CFLAG_FREE		0x0080  /* packet is on free list */
#define	CFLAG_DMA_PARTIAL	0x0100  /* partial xfer OK */


/*
 * I2O command struct to keep the request and response
 *
 * the preferred cbd size is 12, but I2O standard defined based on
 * SCSI 3.
 */

struct  i2ohba_cmd {
	i2o_scsi_scb_execute_message_t	*cmd_i2o_request;
	struct  scsi_pkt	*cmd_pkt;
	struct  i2ohba_cmd	*cmd_forw; /* forward ptr */
	struct	i2ohba_cmd	*cmd_backw; /* backward ptr */

	ddi_dma_handle_t	sglbuf_dmahandle; /* SGL chain buffer */
	ddi_acc_handle_t	sglbuf_dmaacchandle; /* SGL chain buffer */
	ddi_dma_cookie_t	sglbuf_dmacookie;
	i2o_sge_chain_element_t	*sglbuf; /* the buffer that holds the SGL */
	size_t			sglrlen; /* the buffer that holds the SGL */
	size_t			cmd_dmacount;	/* totl # of bytes transfer */
	size_t			cmd_xfercount;	/* cur # of bytes transfer */
	ddi_dma_handle_t	cmd_dmahandle;	/* dma handle */
	uint_t			cmd_cookie;	/* next cookie */
	uint_t			cmd_ncookies;	/* cookies per window */
	uint_t			cmd_cookiecnt;	/* cookies per sub-window */
	uint_t			cmd_nwin;	/* number of dma windows */
	uint_t			cmd_curwin;	/* current dma window */
	off_t			cmd_dma_offset;	/* current window offset */
	ulong_t			cmd_dma_len;	/* current window length */
	ddi_dma_cookie_t	cmd_dmacookies[I2OHBA_CMD_NSEGS];
						/* current dma cookies */
	clock_t			cmd_deadline;
	uint16_t		cmd_flags; /* Internal state flag */
	uint8_t			cmd_cdblen;
	uint_t			cmd_scblen;
	uchar_t			cmd_cdb[I2O_SCSI_CDB_LENGTH]; /* 16-SCSI3 */
	uint_t			cmd_privlen;
	uchar_t			cmd_pkt_private[PKT_PRIV_LEN];
};

#ifdef	__cplusplus
}
#endif

#endif /* _I2O_SCSI_CMD_H */
