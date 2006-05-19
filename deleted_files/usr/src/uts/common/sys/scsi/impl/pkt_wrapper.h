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

#ifndef	_SYS_SCSI_IMPL_PKT_WRAPPER_H
#define	_SYS_SCSI_IMPL_PKT_WRAPPER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The information in this file should be private to each
 * particular Host Bus Adapter implementation, and should
 * not be relied upon in any way.  This file will be removed
 * in a future release.
 */

/*
 * Implementation specific SCSI definitions for wrapping around
 * the generic scsi command packet. The transport layer (host adapter)
 * intimately understands and uses the definitions here.
 */

#include <sys/scsi/scsi_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SC_XPKTP(X)	((struct target_private *)((X)->pkt_private))
struct	target_private {
	struct scsi_pkt *x_fltpktp;	/* link to autosense packet	*/
	struct buf	*x_bp;		/* request buffer		*/
	union {
		struct buf	*xx_rqsbp; /* request sense buffer	*/
		struct uscsi_cmd *xx_scmdp; /* user scsi command 	*/
	} targ;

	daddr_t		x_srtsec;	/* starting sector		*/
	int		x_seccnt;	/* sector count			*/
	int		x_byteleft;	/* bytes left to do		*/
	int		x_bytexfer;	/* bytes xfered for this ops	*/
	int		x_tot_bytexfer;	/* total bytes xfered per cmd	*/

	ushort_t	x_cdblen;	/* cdb length			*/
	short		x_retry;	/* retry count			*/
	int		x_flags;	/* flags			*/

	opaque_t	x_sdevp;	/* backward ptr target unit	*/
	void		(*x_callback)(); /* target drv internal cb func	*/
};
#define	x_rqsbp 	targ.xx_rqsbp
#define	x_scmdp 	targ.xx_scmdp

#if defined(__sparc)
/*
 * Managing possibly discontiguous data segments
 *
 * It is theoretically possible for a SCSI target to
 * transfer data in a discontiguous fashion. In order
 * to manage this possibility in an efficient manner,
 * we'll define a bunch of structures for recording,
 * in various ways, the history of data transfers.
 *
 * The only time that this can get complicated is
 * when the target sends a MODIFY DATA POINTER message
 * that moves the active data pointer completely out
 * of bounds from a segment of data already transferred.
 *
 * The SAVE DATA POINTER and RESTORE POINTERS messages
 * typically only cause moving around within an already
 * defined segment.
 */

/*
 * An arbitrary structure that describes a data segment.
 * This simply has a zero based offset and a count. In
 * the case of a set of truly discontiguous transfers,
 * a list of these things will be constructed as the
 * transfer progresses. At the end of such a transfer
 * some sorting and merging will then be done to then
 * figure out how much data was actually moved.
 *
 * Please note that this is purely to do with counting
 * how much data was moved and must bear absolutely no
 * relationship whatsoever to pointer or DMA addresses.
 */

struct sd_seg {
	struct sd_seg *sd_next;	/* next in a null terminated list */
	ulong_t	sd_off;		/* offset from 0 for this segment */
	ulong_t	sd_cnt;		/* size of this segment */
};
#endif	/* defined(__sparc) */


/*
 * The transport layer deals with things in terms of the following structure.
 * Note that the target driver's view of things is the scsi_pkt that is
 * enfolded as the first element of the following structure.
 */

#if defined(__i386) || defined(__amd64)
#define	PKT_PRIV_LEN	(sizeof (struct target_private))
#define	SCMD_PKTP(X)	((struct scsi_cmd *)(X))
struct 	scsi_cmd {
	struct scsi_pkt	cmd_pkt;
	ulong_t		cmd_flags;	/* flags from scsi_init_pkt */
	uint_t		cmd_cflags;	/* private hba CFLAG flags */
	struct scsi_cmd *cmd_cblinkp;	/* link ptr for callback thread */
	ddi_dma_handle_t cmd_dmahandle;	/* dma handle 			*/
	union {
		ddi_dma_win_t	d_dmawin;	/* dma window		*/
		caddr_t		d_addr;		/* transfer address	*/
	} cm;
	ddi_dma_seg_t	cmd_dmaseg;
	opaque_t	cmd_private;
	uchar_t		cmd_cdblen;	/* length of cdb 		*/
	uchar_t		cmd_scblen;	/* length of scb 		*/
	uchar_t		cmd_privlen;	/* length of target private 	*/
	uchar_t		cmd_rqslen;	/* len of requested rqsense	*/
	long		cmd_totxfer;	/* total transfer for cmd	*/
/*	keep target private at the end for allocation			*/
	uchar_t		cmd_pkt_private[PKT_PRIV_LEN];

};
#define	cmd_dmawin		cm.d_dmawin
#define	cmd_addr		cm.d_addr

#else

#define	PKT_PRIV_LEN	8	/* preferred pkt_private length */
#define	SCMD_PKTP(X)		((struct scsi_cmd *)(X))

struct scsi_cmd {
	struct scsi_pkt		cmd_pkt;	/* the generic packet itself */
	uchar_t			*cmd_cdbp;	/* active command pointer */
	uchar_t			*cmd_scbp;	/* active status pointer */
	ulong_t			cmd_data;	/* active data 'pointer' */
	ulong_t			cmd_saved_data;	/* saved data 'pointer' */
	ulong_t			cmd_dmacount;
	struct sd_seg		*cmd_dsegp;	/* current data count seg */
	struct sd_seg		cmd_dsegs;	/* first data count segment */
	ddi_dma_handle_t	cmd_dmahandle;	/* dma handle */
	ddi_dma_cookie_t	cmd_dmacookie;	/* current dma cookie */
	long			cmd_timeout;	/* command timeout */
	union scsi_cdb		cmd_cdb_un;	/* 'generic' Sun cdb */
#define	cmd_cdb	cmd_cdb_un.cdb_opaque
	ulong_t			cmd_flags;	/* private flags */
	uchar_t			cmd_pkt_private[PKT_PRIV_LEN];
	uchar_t			cmd_cdblen;	/* length of cdb */
	uchar_t			cmd_scblen;	/* length of scb */
	uchar_t			cmd_privlen;	/* length of tgt private */
	uchar_t			cmd_scb[STATUS_SIZE];	/* 4 byte scb */
	uchar_t			cmd_reserved[1];
	struct scsi_cmd		*cmd_forw;	/* ready fifo que link */
	ushort_t		cmd_age;	/* cmd age (tagged queing) */
	uchar_t			cmd_tag[2];	/* command tag */
};
#endif	/* __i386 || __amd64 */

/*
 * A note about the data 'pointers':
 *
 *	XXXXXX
 *
 * A note about the cmd_cdb && cmd_scb structures:
 *
 * 	If the command allocation requested exceeds the size of CDB_SIZE,
 *	the cdb will be allocated outside this structure (via kmem_alloc)
 *	The same applies to cmd_scb.
 *
 */

#if defined(__sparc)

/*
 * define size of extended scsi cmd pkt (ie. includes ARQ)
 */
#define	EXTCMDS_STATUS_SIZE  (sizeof (struct scsi_arq_status))
#define	EXTCMDS_SIZE  (EXTCMDS_STATUS_SIZE + sizeof (struct scsi_cmd))
#endif	/* defined(__sparc) */

/*
 * These are the defined flags for this structure.
 *
 * The host adapter may not change the state of any
 * flags that fall within the CFLAG_RESERVED area.
 * The rest of the flag area can be used by the host
 * adapter to get its job done, and the defines made
 * here for that area are just suggested usages.
 */
#define	CFLAG_RESERVED	0xff00		/* reserved read only area */
#define	CFLAG_CMDDISC	0x0001		/* cmd currently disconnected */
#define	CFLAG_WATCH	0x0002		/* watchdog time for this command */
#define	CFLAG_FINISHED	0x0004		/* command completed */
#define	CFLAG_CHKSEG	0x0008		/* check cmd_data within seg */
#define	CFLAG_COMPLETED	0x0010		/* completion routine called */
#define	CFLAG_PREPARED	0x0020		/* pkt has been init'ed */
#define	CFLAG_IN_TRANSPORT 0x0040	/* in use by host adapter driver */
#define	CFLAG_TRANFLAG	0x00ff		/* covers transport part of flags */
#define	CFLAG_CMDPROXY	   0x000100	/* cmd is a 'proxy' command */
#define	CFLAG_CMDARQ	   0x000200	/* cmd is a 'rqsense' command */
#define	CFLAG_DMAVALID	   0x000400	/* dma mapping valid */
#define	CFLAG_DMASEND	   0x000800	/* data is going 'out' */
#define	CFLAG_CMDIOPB	   0x001000	/* this is an 'iopb' packet */
#define	CFLAG_CDBEXTERN	   0x002000	/* cdb kmem_alloc'd */
#define	CFLAG_SCBEXTERN	   0x004000	/* scb kmem_alloc'd */
#define	CFLAG_FREE	   0x008000	/* packet is on free list */
#define	CFLAG_EXTCMDS_ALLOC	0x10000	/* pkt has EXTCMDS_SIZE and */
					/* been fast alloc'ed */
#define	CFLAG_PRIVEXTERN   0x020000	/* target private kmem_alloc'd */
#define	CFLAG_DMA_PARTIAL  0x040000	/* partial xfer OK */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_IMPL_PKT_WRAPPER_H */
