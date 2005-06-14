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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_1394_ADAPTERS_HCI1394_IXL_H
#define	_SYS_1394_ADAPTERS_HCI1394_IXL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_ixl.h
 *    Structures and defines for IXL processing.
 *	1. Structures tracking per-command state [created during compilation
 *	    and stored in each command's compiler_privatep].
 *	2. Structures used for state tracking during IXL program compilation.
 *	3. Structures used during IXL dynamic update for assessment and the
 *	    performing the update itself.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/note.h>

#include <sys/1394/adapters/hci1394_def.h>
#include <sys/1394/adapters/hci1394_isoch.h>

/*
 * function return codes from hci1394_ixl_dma_sync()
 */
#define	HCI1394_IXL_INTR_NOERROR    (0) /* no error */
#define	HCI1394_IXL_INTR_INUPDATE   (1) /* update active at intr entry */
					/* (info only, not err) */
#define	HCI1394_IXL_INTR_DMASTOP    (2) /* encountered end of dma or stopped */
					/* (might be info only) */
#define	HCI1394_IXL_INTR_DMALOST   (-1) /* dma location indeterminate (lost) */
#define	HCI1394_IXL_INTR_NOADV	   (-2) /* dma non-advance retries exhausted */
					/* (stuck or lost) */
/* fatal internal errors from hci1394_ixl_dma_sync() */
#define	HCI1394_IXL_INTR_ININTR    (-3) /* interrupt active at intrrupt entry */
#define	HCI1394_IXL_INTR_INCALL    (-4) /* callback active at entry */
#define	HCI1394_IXL_INTR_STOP	   (-5) /* context is being stopped */

/*
 * maximum number of jump IXL commands permitted between two data transfer
 * commands.  This allows for several label and jump combinations to exist, but
 * also is used to detect when the label/jump complexity probably indicates
 * an infinite loop without any transfers.
 */
#define	HCI1394_IXL_MAX_SEQ_JUMPS   10

/*
 * xfer control structures - for execution and update control of compiled
 * ixl program.
 *
 * For pkt, buf and special xfer start ixl commands, address
 * of allocated xfer_ctl struct is set into ixl compiler_privatep.
 *
 * For pkt xfer non-start ixl commands, address of pkt xfer start ixl
 * command is set into compiler_privatep and the index [1-n] of
 * this non-start pkt xfer ixl command to its related component in the
 * generated descriptor block is set into compiler_resv.
 *
 * The xfer_ctl_dma struct array is needed because allocation of subsequent
 * descriptor blocks may be from different memory pages (i.e. not contiguous)
 * and thus, during update processing, subsequent descriptor block addrs
 * can't be calculated (e.g. change of buf addr or size or modification to
 * set tag&sync, setskipmode or jump cmds).
 */

#define	XCTL_LABELLED 1	/* flag: ixl xfer cmd initiated by ixl label cmd  */

typedef struct hci1394_xfer_ctl_dma {
	/*
	 * dma descriptor block's bound addr (with "Z" bits set); is used to
	 * fill jump/skip addrs of previous dma descriptor block (previous on
	 * exec path, not link path); Note:("Z" bits)*16 is size of this
	 * descriptor block; individual component's format depends on IXL cmd
	 * type;
	 */
	uint32_t dma_bound;

	/*
	 * kernel virtual (unbound) addr of last component of allocated
	 * descriptor block; start addr of descriptor block can be calculated
	 * by adding size of a descriptor block component(16) and subtracting
	 * ("Z" bits)*16;  Note: if ixl cmd is xmit_hdr_only, must add 2*desc
	 * block component(32), instead;
	 * used to determine current location during exec by examining/clearing
	 *    the status/timestamp value;
	 * used to obtain value for store timestamp cmd; used to set new
	 *    jump/skip addr on update calls;
	 * used to set new tag and sync on update calls;
	 */
	caddr_t dma_descp;

	/*
	 * pointer to the hci1394_buf_info_t structure corresponding to the
	 * mapped DMA memory into which this descriptor was written.  Contains
	 * the DMA handles necessary for ddi_dma_sync() and ddi_put32/get32()
	 * calls.
	 */
	hci1394_buf_info_t	*dma_buf;

} hci1394_xfer_ctl_dma_t;


typedef struct hci1394_xfer_ctl {
	struct hci1394_xfer_ctl	*ctl_nextp; /* next ixl xfer_ctl struct */
	ixl1394_command_t	*execp;	/* next ixlxfer cmd (along exec path) */
	ixl1394_set_skipmode_t	*skipmodep; /* associated skip cmd. if any */
	uint16_t		ctl_flags;  /* xctl flags defined above */
	uint16_t		cnt;	/* dma descriptor blocks alloc count */
					/* (for pkt=1) */
	hci1394_xfer_ctl_dma_t	dma[1];	/* addrs of descriptor blocks, cnt of */
					/* these are allocated */
} hci1394_xfer_ctl_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", hci1394_xfer_ctl))

/*
 * IXL Compiler temporary working variables for building IXL context program.
 * (i.e. converting IXL program to a list of hci descriptor blocks)
 */
typedef struct hci1394_comp_ixl_vars_s {
	/* COMMON RECV/XMIT COMPILE VALUES */
	hci1394_state_t		*soft_statep;	/* driver state */
	hci1394_iso_ctxt_t	*ctxtp;		/* current context */
	hci1394_xfer_ctl_t	*xcs_firstp;	/* 1st alloc xfer_ctl_t struc */
	hci1394_xfer_ctl_t	*xcs_currentp; /* last alloc xfer_ctl_t struc */

	hci1394_idma_desc_mem_t *dma_firstp;	/* 1st alloc descriptor mem */
	hci1394_idma_desc_mem_t *dma_currentp;	/* cur dma descriptor mem */

	int dma_bld_error;			/* compilation error code */
	uint_t ixl_io_mode;			/* I/O mode: 0=recv,1=xmit */

	ixl1394_command_t *ixl_cur_cmdp;	/* processing current ixl cmd */
	ixl1394_command_t *ixl_cur_xfer_stp;	/* currently buildng xfer cmd */
	ixl1394_command_t *ixl_cur_labelp;	/* set if xfer inited by labl */

	uint16_t	ixl_xfer_st_cnt; /* # of xfer start ixl cmds built */

	uint_t		xfer_state;	/* none, pkt, buf, skip, hdronly */
	uint_t		xfer_hci_flush;	/* updateable - xfer, jump, set */

	uint32_t	xfer_pktlen;
	uint32_t	xfer_bufp[HCI1394_DESC_MAX_Z];
	uint16_t	xfer_bufcnt;
	uint16_t	xfer_size[HCI1394_DESC_MAX_Z];

	uint16_t	descriptors;
	uint16_t	reserved;
	hci1394_desc_t	descriptor_block[HCI1394_DESC_MAX_Z];

	/* START RECV ONLY SECTION */
	uint16_t	ixl_setsyncwait_cnt;
	/* END RECV ONLY SECTION */

	/* START XMIT ONLY SECTION */
	ixl1394_set_tagsync_t	*ixl_settagsync_cmdp;
	ixl1394_set_skipmode_t	*ixl_setskipmode_cmdp;

	uint16_t		default_tag;
	uint16_t		default_sync;
	uint16_t		default_skipmode;   /* next, self, stop, jump */
	uint16_t		skipmode;	    /* next, self, stop, jump */
	ixl1394_command_t	*default_skiplabelp;
	ixl1394_command_t	*default_skipxferp;
	ixl1394_command_t	*skiplabelp;
	ixl1394_command_t	*skipxferp;

	uint32_t		xmit_pkthdr1;
	uint32_t		xmit_pkthdr2;
	uint32_t		storevalue_bufp;
	uint32_t		storevalue_data;
	/* END XMIT ONLY SECTION */
} hci1394_comp_ixl_vars_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", hci1394_comp_ixl_vars_s))

/*
 * hci1394_comp_ixl_vars.xfer_hci_flush - xfer descriptor block build hci
 * flush evaluation flags
 */
#define	UPDATEABLE_XFER	0x01	/* current xfer command is updateable */
#define	UPDATEABLE_JUMP	0x02	/* cur xfer is finalized by updateable jump */
#define	UPDATEABLE_SET	0x04	/* current xfer has associated updateable set */
#define	INITIATING_LBL  0x08	/* current xfer is initiated by a label cmd */

/* hci1394_comp_ixl_vars.xfer_state - xfer descriptr block build state values */
#define	XFER_NONE	0	/* build inactive */
#define	XFER_PKT	1	/* building xfer packet descriptor block */
#define	XFER_BUF	2	/* building xfer buffer descriptor blocks */
#define	XMIT_NOPKT	3	/* building skip cycle xmit descriptor block */
#define	XMIT_HDRONLY	4	/* building header only xmit descriptor block */

/*
 * IXL Dynamic Update  temporary working variables.
 * (used when assessing feasibility of an update based on where the hardware
 * is, and for performing the actual update.)
 */
#define	IXL_MAX_LOCN	4		/* extent of location array */

typedef struct hci1394_upd_locn_info {
	ixl1394_command_t *ixlp;
	uint_t ixldepth;
} hci1394_upd_locn_info_t;

typedef struct hci1394_ixl_update_vars {

	hci1394_state_t	*soft_statep;	/* driver state struct */
	hci1394_iso_ctxt_t *ctxtp;	/* current iso context */
	ixl1394_command_t *ixlnewp;	/* ixl cmd containing new values */
	ixl1394_command_t *ixloldp;	/* cmd to be updated with new vals */

	ixl1394_command_t *ixlxferp;	/* xfer cmd which is real targ of upd */
	ixl1394_command_t *skipxferp;	/* xfer cmd if mode is skip to label */

	/* currently exec xfer and MAX_LOCN-1 xfers following */
	hci1394_upd_locn_info_t locn_info[IXL_MAX_LOCN];

	uint_t	    ixldepth;	/* xferp depth at which to start upd */
	uint_t	    skipmode; 	/* set skip mode mode value */
	uint_t	    pkthdr1;	/* new pkt header 1 if tag or sync update */
	uint_t	    pkthdr2;	/* new pkt hdr 2 if send xfer size change */
	uint32_t    skipaddr;	/* bound skip destaddr (0=not skip to labl) */
	uint32_t    jumpaddr;	/* bound jump destaddr if jump update (w/Z) */
	uint32_t    bufaddr;	/* new buf addr if xfer buffr addr change */
	uint32_t    bufsize;	/* new buf size if xfer buffr size change */
	uint32_t    hcihdr;	/* new hci descriptor hdr field (cmd,int,cnt) */
	uint32_t    hcistatus;	/* new hci descrptr stat field (rescount) */
	int32_t	    hci_offset;	/* offset from xfer_ctl dma_descp to */
				/* hci changing */
	int	    hdr_offset; /* offset from xfer_ctl dma_descp to */
				/* pkthdrs hci */
	int	    upd_status; /* update completion return status value */

	uint_t	    risklevel;	/* caller risk override spec (unimplemented) */
	uint16_t    ixl_opcode; /* ixl update command code */
	uint16_t    ixlcount;	/* ixlxferp # of dma cmds to update */
} hci1394_ixl_update_vars_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", hci1394_ixl_update_vars))

int hci1394_compile_ixl(hci1394_state_t *soft_statep, hci1394_iso_ctxt_t *ctxtp,
    ixl1394_command_t *ixlp, int *resultp);
int hci1394_ixl_update(hci1394_state_t *soft_statep, hci1394_iso_ctxt_t *ctxtp,
    ixl1394_command_t *ixlnewp, ixl1394_command_t *ixloldp, uint_t riskoverride,
    int *resultp);
void hci1394_ixl_interrupt(hci1394_state_t *soft_statep,
    hci1394_iso_ctxt_t *ctxtp, boolean_t in_stop);
int hci1394_ixl_dma_sync(hci1394_state_t *soft_statep,
    hci1394_iso_ctxt_t *ctxtp);
int hci1394_ixl_set_start(hci1394_iso_ctxt_t *ctxtp, ixl1394_command_t *ixlstp);
void hci1394_ixl_reset_status(hci1394_iso_ctxt_t *ctxtp);
int hci1394_ixl_check_status(hci1394_xfer_ctl_dma_t *dma, uint16_t ixlopcode,
    uint16_t *timestamp, boolean_t do_status_reset);
int hci1394_ixl_find_next_exec_xfer(ixl1394_command_t *ixl_start,
    uint_t *callback_cnt, ixl1394_command_t **next_exec_ixlpp);
void hci1394_ixl_cleanup(hci1394_state_t *soft_statep,
    hci1394_iso_ctxt_t *ctxtp);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_IXL_H */
