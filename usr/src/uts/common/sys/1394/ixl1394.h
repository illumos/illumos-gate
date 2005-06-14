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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_1394_IXL1394_H
#define	_SYS_1394_IXL1394_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ixl1394.h
 *    Contains all defines and structures necessary for Isochronous Transfer
 *    Language (IXL) programs. IXL programs are used to specify the transmission
 *    or receipt of isochronous packets for an isochronous channel.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/note.h>

/*
 * Error codes for IXL program compilation and dynamic update
 * Comments indicate which are source of error
 * NOTE: Make sure IXL1394_COMP_ERR_LAST is updated if a new error code is
 * added. t1394_errmsg.c uses *FIRST and *LAST as bounds checks.
 */
#define	IXL1394_EMEM_ALLOC_FAIL		(-301)	/* compile only */
#define	IXL1394_EBAD_IXL_OPCODE		(-302)	/* compile only */
#define	IXL1394_EFRAGMENT_OFLO		(-303)	/* compile only */
#define	IXL1394_ENO_DATA_PKTS		(-304)	/* compile only */
#define	IXL1394_EMISPLACED_RECV		(-305)	/* compile only */
#define	IXL1394_EMISPLACED_SEND		(-306)	/* compile only */
#define	IXL1394_EPKT_HDR_MISSING	(-307)	/* compile & update */
#define	IXL1394_ENULL_BUFFER_ADDR	(-308)	/* compile only */
#define	IXL1394_EPKTSIZE_MAX_OFLO	(-309)	/* compile & update */
#define	IXL1394_EPKTSIZE_RATIO		(-310)	/* compile only */
#define	IXL1394_EUNAPPLIED_SET_CMD	(-311)	/* compile only */
#define	IXL1394_EDUPLICATE_SET_CMD	(-312)	/* compile only */
#define	IXL1394_EJUMP_NOT_TO_LABEL	(-313)	/* compile & update */
#define	IXL1394_EUPDATE_DISALLOWED	(-314)	/* compile & update */
#define	IXL1394_EBAD_SKIPMODE		(-315)	/* compile & update */
#define	IXL1394_EWRONG_XR_CMD_MODE	(-316)	/* compile only */
#define	IXL1394_EINTERNAL_ERROR		(-317)	/* compile & update */
#define	IXL1394_ENOT_IMPLEMENTED	(-318)	/* compile only */
#define	IXL1394_EOPCODE_MISMATCH	(-319)	/* update only */
#define	IXL1394_EOPCODE_DISALLOWED	(-320)	/* update only */
#define	IXL1394_EBAD_SKIP_LABEL		(-321)	/* update only */
#define	IXL1394_EXFER_BUF_MISSING	(-322)	/* update only */
#define	IXL1394_EXFER_BUF_CNT_DIFF	(-323)	/* update only */
#define	IXL1394_EORIG_IXL_CORRUPTED	(-324)	/* update only */
#define	IXL1394_ECOUNT_MISMATCH		(-325)	/* update only */
#define	IXL1394_EPRE_UPD_DMALOST	(-326)	/* update only */
#define	IXL1394_EPOST_UPD_DMALOST	(-327)	/* update only */
#define	IXL1394_ERISK_PROHIBITS_UPD	(-328)	/* update only */

#define	IXL1394_COMP_ERR_FIRST		IXL1394_EMEM_ALLOC_FAIL
#define	IXL1394_COMP_ERR_LAST		IXL1394_ERISK_PROHIBITS_UPD

#define	IXL1394_ENO_DMA_RESRCS		(-200)


/*
 * IXL command opcodes
 *
 * IXL opcodes contain a unique opcode identifier and various flags to
 * speed compilation.
 */

/* 5 flag bits at high end of opcode field. */
#define	IXL1394_OPF_MASK	0xF800
#define	IXL1394_OPF_UPDATE	0x8000	/* cmd update allowed during exec */
#define	IXL1394_OPF_ONRECV	0x4000	/* cmd is allowed on recv */
#define	IXL1394_OPF_ONXMIT	0x2000	/* cmd is allowed on xmit */
#define	IXL1394_OPF_ENDSXFER	0x1000	/* cmd ends cur pkt xfer build */
#define	IXL1394_OPF_ISXFER	0x0800	/* cmd is data transfer command */

/* Useful flag composites. */
#define	IXL1394_OPF_ONXFER	(IXL1394_OPF_ONXMIT | IXL1394_OPF_ONRECV)
#define	IXL1394_OPF_ONXFER_ENDS (IXL1394_OPF_ONXFER | IXL1394_OPF_ENDSXFER)
#define	IXL1394_OPF_ONRECV_ENDS (IXL1394_OPF_ONRECV | IXL1394_OPF_ENDSXFER)
#define	IXL1394_OPF_ONXMIT_ENDS (IXL1394_OPF_ONXMIT | IXL1394_OPF_ENDSXFER)

/* 2 type bits whose contents are interpreted based on isxr setting */
#define	IXL1394_OPTY_MASK		0x0600

/* type bits when isxfer == 0 */
#define	IXL1394_OPTY_OTHER		0x0000

/* type bits when isxr == 1 */
#define	IXL1394_OPTY_XFER_PKT		(0x0000 | IXL1394_OPF_ISXFER)
#define	IXL1394_OPTY_XFER_PKT_ST	(0x0200 | IXL1394_OPF_ISXFER)
#define	IXL1394_OPTY_XFER_BUF_ST	(0x0400 | IXL1394_OPF_ISXFER)
#define	IXL1394_OPTY_XFER_SPCL_ST	(0x0600 | IXL1394_OPF_ISXFER)

/*
 * IXL Command Opcodes.
 */
#define	IXL1394_OP_LABEL    (1 | IXL1394_OPTY_OTHER | IXL1394_OPF_ONXFER_ENDS)
#define	IXL1394_OP_JUMP	    (2 | IXL1394_OPTY_OTHER | IXL1394_OPF_ONXFER_ENDS)
#define	IXL1394_OP_CALLBACK (3 | IXL1394_OPTY_OTHER | IXL1394_OPF_ONXFER)
#define	IXL1394_OP_RECV_PKT (4 | IXL1394_OPTY_XFER_PKT | IXL1394_OPF_ONRECV)
#define	IXL1394_OP_RECV_PKT_ST \
		(5 | IXL1394_OPTY_XFER_PKT_ST |	IXL1394_OPF_ONRECV_ENDS)
#define	IXL1394_OP_RECV_BUF \
		(6 | IXL1394_OPTY_XFER_BUF_ST |	IXL1394_OPF_ONRECV_ENDS)
#define	IXL1394_OP_SEND_PKT (7 | IXL1394_OPTY_XFER_PKT | IXL1394_OPF_ONXMIT)
#define	IXL1394_OP_SEND_PKT_ST \
		(8 | IXL1394_OPTY_XFER_PKT_ST |	IXL1394_OPF_ONXMIT_ENDS)
#define	IXL1394_OP_SEND_PKT_WHDR_ST \
		(9  | IXL1394_OPTY_XFER_PKT_ST | IXL1394_OPF_ONXMIT_ENDS)
#define	IXL1394_OP_SEND_BUF \
		(10 | IXL1394_OPTY_XFER_BUF_ST | IXL1394_OPF_ONXMIT_ENDS)
#define	IXL1394_OP_SEND_HDR_ONLY \
		(12 | IXL1394_OPTY_XFER_SPCL_ST | IXL1394_OPF_ONXMIT_ENDS)
#define	IXL1394_OP_SEND_NO_PKT \
		(13 | IXL1394_OPTY_XFER_SPCL_ST | IXL1394_OPF_ONXMIT_ENDS)
#define	IXL1394_OP_STORE_TIMESTAMP \
		(14 | IXL1394_OPTY_OTHER | IXL1394_OPF_ONXFER)
#define	IXL1394_OP_SET_TAGSYNC \
		(15 | IXL1394_OPTY_OTHER | IXL1394_OPF_ONXMIT_ENDS)
#define	IXL1394_OP_SET_SKIPMODE \
		(16 | IXL1394_OPTY_OTHER | IXL1394_OPF_ONXMIT_ENDS)
#define	IXL1394_OP_SET_SYNCWAIT \
		(17 | IXL1394_OPTY_OTHER | IXL1394_OPF_ONRECV_ENDS)

/*
 * The dynamic UPDATE versions of each updatable command.
 */
#define	IXL1394_OP_JUMP_U	(IXL1394_OP_JUMP | IXL1394_OPF_UPDATE)
#define	IXL1394_OP_CALLBACK_U	(IXL1394_OP_CALLBACK | IXL1394_OPF_UPDATE)
#define	IXL1394_OP_RECV_PKT_U	(IXL1394_OP_RECV_PKT | IXL1394_OPF_UPDATE)
#define	IXL1394_OP_RECV_PKT_ST_U (IXL1394_OP_RECV_PKT_ST | IXL1394_OPF_UPDATE)
#define	IXL1394_OP_RECV_BUF_U	(IXL1394_OP_RECV_BUF | IXL1394_OPF_UPDATE)
#define	IXL1394_OP_SEND_PKT_U	(IXL1394_OP_SEND_PKT | IXL1394_OPF_UPDATE)
#define	IXL1394_OP_SEND_PKT_ST_U (IXL1394_OP_SEND_PKT_ST | IXL1394_OPF_UPDATE)
#define	IXL1394_OP_SEND_PKT_WHDR_ST_U (IXL1394_OP_SEND_PKT_WHDR_ST |	\
	    IXL1394_OPF_UPDATE)
#define	IXL1394_OP_SEND_BUF_U	(IXL1394_OP_SEND_BUF | IXL1394_OPF_UPDATE)
#define	IXL1394_OP_SET_TAGSYNC_U (IXL1394_OP_SET_TAGSYNC | IXL1394_OPF_UPDATE)
#define	IXL1394_OP_SET_SKIPMODE_U (IXL1394_OP_SET_SKIPMODE | IXL1394_OPF_UPDATE)


/* Opaque type for the ixl private data */
typedef struct ixl_priv_handle	*ixl1394_priv_t;

/* IXL1394_OP_SET_SKIPMODE values (used only with isoch transmit) */
typedef enum {
	IXL1394_SKIP_TO_SELF	= 0,
	IXL1394_SKIP_TO_NEXT	= 1,
	IXL1394_SKIP_TO_STOP	= 2,
	IXL1394_SKIP_TO_LABEL	= 3
} ixl1394_skip_t;

/*
 * IXL Program Command Primitives
 */

/* The general command format.  The operands vary depending on the opcode */
typedef struct ixl1394_command {
	struct ixl1394_command	*next_ixlp;
	ixl1394_priv_t		compiler_privatep;
	uint16_t		compiler_resv;
	uint16_t		ixl_opcode;
	uint32_t		operands[1];
} ixl1394_command_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	ixl1394_command::compiler_privatep \
	ixl1394_command::compiler_resv))

/*
 * command structure used for a DDI_DMA bound buffer. For portability,
 * set this _dmac_ll to the buffer's allocated and bound
 * ddi_dma_cookie_t's _dmac_ll.
 */
typedef union ixl1394_buf_u {
	uint64_t		_dmac_ll;	/* 64-bit DMA address */
	uint32_t		_dmac_la[2];	/* 2 x 32-bit address */
} ixl1394_buf_t;

/* shorthand access to IXL command buffers.  similar to defs in dditypes.h */
#define	ixldmac_laddr	_dmac_ll
#ifdef _LONG_LONG_HTOL
#define	ixldmac_notused	_dmac_la[0]
#define	ixldmac_addr	_dmac_la[1]
#else
#define	ixldmac_addr	_dmac_la[0]
#define	ixldmac_notused	_dmac_la[1]
#endif


/*
 * ixl1394_xfer_pkt
 * Specifies a packet fragment.
 * Used with IXL1394_OP_SEND_PKT_ST, IXL1394_OP_SEND_PKT_WHDR_ST,
 * IXL1394_OP_SEND_PKT, IXL1394_OP_RECV_PKT_ST and IXL1394_OP_RECV_PKT.
 */
typedef struct ixl1394_xfer_pkt {
	ixl1394_command_t	*next_ixlp;
	ixl1394_priv_t		compiler_privatep;
	uint16_t		compiler_resv;
	uint16_t		ixl_opcode;
	uint16_t		size;		/* bytes in ixl_buf */
	uint16_t		resv;
	ixl1394_buf_t		ixl_buf;	/* ddi_dma bound address */
	caddr_t			mem_bufp;	/* kernel virtual addr */
} ixl1394_xfer_pkt_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	ixl1394_xfer_pkt::ixl_buf._dmac_ll \
        ixl1394_xfer_pkt::ixl_buf._dmac_la \
        ixl1394_xfer_pkt::mem_bufp \
        ixl1394_xfer_pkt::size))

/*
 * ixl1394_xfer_buf
 * Specifies a buffer of multiple packets.
 * Used with IXL1394_OP_SEND_BUF and IXL1394_OP_RECV_BUF.
 */
typedef struct ixl1394_xfer_buf {
	ixl1394_command_t	*next_ixlp;
	ixl1394_priv_t		compiler_privatep;
	uint16_t		compiler_resv;
	uint16_t		ixl_opcode;
	uint16_t		size;		/* bytes in ixl_buf */
	uint16_t		pkt_size;	/* bytes in each packet */
	ixl1394_buf_t		ixl_buf;	/* ddi_dma bound address */
	caddr_t			mem_bufp;	/* kernel (not bound) addrss */
} ixl1394_xfer_buf_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	ixl1394_xfer_buf::compiler_privatep \
	ixl1394_xfer_buf::ixl_buf._dmac_ll \
	ixl1394_xfer_buf::ixl_buf._dmac_la \
	ixl1394_xfer_buf::mem_bufp \
	ixl1394_xfer_buf::pkt_size \
	ixl1394_xfer_buf::size))

/*
 * ixl1394_xmit_special
 * Specifies how many cycles are to be skipped before the next packet
 * is sent.  Specifies number of header only packets to be sent, next.
 * Used with IXL1394_OP_SEND_HDR_ONLY and IXL1394_OP_SEND_NO_PKT.
 */
typedef struct ixl1394_xmit_special {
	ixl1394_command_t	*next_ixlp;
	ixl1394_priv_t		compiler_privatep;
	uint16_t		compiler_resv;
	uint16_t		ixl_opcode;
	uint16_t		count;
	uint16_t		resv;
} ixl1394_xmit_special_t;

/*
 * ixl1394_callback
 * Specifies a callback function and callback data.
 * When the callback is invoked, it is passed the addr of this IXL
 * command, which it can use to retrieve the arg it has stored in
 * this struct. Used with IXL1394_OP_CALLBACK.
 */
typedef struct ixl1394_callback {
	ixl1394_command_t   *next_ixlp;
	ixl1394_priv_t	    compiler_privatep;
	uint16_t	    compiler_resv;
	uint16_t	    ixl_opcode;
	void		    (*callback)(opaque_t, struct ixl1394_callback *);
	opaque_t	    callback_arg;
} ixl1394_callback_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
        ixl1394_callback::callback \
	ixl1394_callback::callback_arg))

/*
 * ixl1394_label
 * Specifies a label (location) which can be used as the target of a jump.
 * Used with IXL1394_OP_LABEL.
 */
typedef struct ixl1394_label {
	ixl1394_command_t	*next_ixlp;
	ixl1394_priv_t		compiler_privatep;
	uint16_t		compiler_resv;
	uint16_t		ixl_opcode;
} ixl1394_label_t;

/*
 * ixl1394_jump
 * Specifies a label (location) which can then be used as the target of a jump.
 * Used with IXL1394_OP_JUMP.
 */
typedef struct ixl1394_jump {
	ixl1394_command_t	*next_ixlp;
	ixl1394_priv_t		compiler_privatep;
	uint16_t		compiler_resv;
	uint16_t		ixl_opcode;
	ixl1394_command_t	*label;
} ixl1394_jump_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	ixl1394_jump::label))

/*
 * ixl1394_set_tagsync
 * Specifies the tag and sync bits used for the port.
 * Used with IXL1394_OP_SET_TAGSYNC.
 */
typedef struct ixl1394_set_tagsync {
	ixl1394_command_t	*next_ixlp;
	ixl1394_priv_t		compiler_privatep;
	uint16_t		compiler_resv;
	uint16_t		ixl_opcode;
	uint16_t		tag;
	uint16_t		sync;
} ixl1394_set_tagsync_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	ixl1394_set_tagsync::sync \
	ixl1394_set_tagsync::tag))

/*
 * ixl1394_set_skipmode
 * Specifies the tag and sync bits used for the port.
 * Used with IXL1394_OP_SET_SKIPMODE.
 */
typedef struct ixl1394_set_skipmode {
	ixl1394_command_t	*next_ixlp;
	ixl1394_priv_t		compiler_privatep;
	uint16_t		compiler_resv;
	uint16_t		ixl_opcode;
	ixl1394_command_t 	*label;
	ixl1394_skip_t		skipmode;
} ixl1394_set_skipmode_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	ixl1394_set_skipmode::compiler_privatep \
	ixl1394_set_skipmode::label \
	ixl1394_set_skipmode::skipmode))

/*
 * ixl1394_set_syncwait
 * Specifies that next receive is to wait for sync before accepting input.
 * Used with IXL1394_OP_SET_SYNCWAIT.
 */
typedef struct ixl1394_set_syncwait {
	ixl1394_command_t	*next_ixlp;
	ixl1394_priv_t		compiler_privatep;
	uint16_t		compiler_resv;
	uint16_t		ixl_opcode;
} ixl1394_set_syncwait_t;

/*
 * ixl1394_store_timestamp
 * Specifies that the timestamp value of the most recently sent
 * packet be stored into the timestamp field of this ixl command.
 * Used with IXL1394_OP_STORE_TIMESTAMP.
 */
typedef struct ixl1394_store_timestamp {
	ixl1394_command_t	*next_ixlp;
	ixl1394_priv_t		compiler_privatep;
	uint16_t		compiler_resv;
	uint16_t		ixl_opcode;
	uint16_t		timestamp;
	uint16_t		resv;
} ixl1394_store_timestamp_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	ixl1394_store_timestamp::timestamp))

/*
 * Macros for extracting isochronous packet header fields when receiving
 * packets via IXL1394_OP_RECV_PKT_ST or IXL1394_OP_RECV_BUF with
 * ID1394_RECV_HEADERS mode enabled.
 * The argument to each macro is a quadlet of data.
 * Prior to using the macro, target drivers first retrieve this quadlet from
 * bound memory by using ddi_get32(9F).
 */

/*
 * timestamp is the first quadlet in an IXL1394_OP_RECV_PKT_ST packet, and is
 * the last quadlet (after the data payload) in an IXL1394_OP_RECV_BUF packet.
 */
#define	IXL1394_GET_IR_TIMESTAMP(PKT_QUADLET) ((PKT_QUADLET) & 0x0000FFFF)

/*
 * the following macros apply to the second quadlet in an
 * IXL1394_OP_RECV_PKT_ST packet, and the first quadlet in an
 * IXL1394_OP_RECV_BUF packet.
 */
#define	IXL1394_GET_IR_DATALEN(PKT_QUADLET) (((PKT_QUADLET) & 0xFFFF0000) >> 16)
#define	IXL1394_GET_IR_TAG(PKT_QUADLET)	    (((PKT_QUADLET) & 0x0000C000) >> 14)
#define	IXL1394_GET_IR_CHAN(PKT_QUADLET)    (((PKT_QUADLET) & 0x00003F00) >> 8)
#define	IXL1394_GET_IR_SYNC(PKT_QUADLET)    ((PKT_QUADLET) & 0x0000000F)

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_IXL1394_H */
