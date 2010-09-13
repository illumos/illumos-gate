/*
 * pppio.h - ioctl and other misc. definitions for STREAMS modules.
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * $Id: pppio.h,v 1.8 1996/08/28 06:36:51 paulus Exp $
 */

#ifndef __PPPIO_H
#define	__PPPIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	_PPPIO(n)	(('p' << 8) + (n))

#define	PPPIO_NEWPPA	_PPPIO(130)	/* allocate a new PPP unit */
#define	PPPIO_GETSTAT	_PPPIO(131)	/* get PPP statistics */
#define	PPPIO_GETCSTAT	_PPPIO(132)	/* get PPP compression stats */
#define	PPPIO_MTU	_PPPIO(133)	/* set max transmission unit */
#define	PPPIO_MRU	_PPPIO(134)	/* set max receive unit */
#define	PPPIO_CFLAGS	_PPPIO(135)	/* set/clear/get compression flags */
#define	PPPIO_XCOMP	_PPPIO(136)	/* alloc transmit compressor */
#define	PPPIO_RCOMP	_PPPIO(137)	/* alloc receive decompressor */
#define	PPPIO_XACCM	_PPPIO(138)	/* set transmit asyncmap */
#define	PPPIO_RACCM	_PPPIO(139)	/* set receive asyncmap */
#define	PPPIO_VJINIT	_PPPIO(140)	/* initialize VJ comp/decomp */
#define	PPPIO_ATTACH	_PPPIO(141)	/* attach to a ppa (without putmsg) */
#define	PPPIO_LASTMOD	_PPPIO(142)	/* mark last ppp module */
#define	PPPIO_GCLEAN	_PPPIO(143)	/* get 8-bit-clean flags */
#define	PPPIO_DEBUG	_PPPIO(144)	/* request debug information */
#define	PPPIO_BIND	_PPPIO(145)	/* bind to SAP */
#define	PPPIO_NPMODE	_PPPIO(146)	/* set mode for handling data pkts */
#define	PPPIO_GIDLE	_PPPIO(147)	/* get time since last data pkt */
#define	PPPIO_PASSFILT	_PPPIO(148)	/* set filter for packets to pass */
#define	PPPIO_ACTIVEFILT _PPPIO(149)	/* set filter for "link active" pkts */
#define	PPPIO_USETIMESTAMP _PPPIO(150)	/* enable packet time-stamp */
#define	PPPIO_DETACH	_PPPIO(151)	/* detach from a ppa (w/o putmsg ) */
#define	PPPIO_XFCS	_PPPIO(152)	/* set transmit FCS type */
#define	PPPIO_RFCS	_PPPIO(153)	/* set receive FCS type */
#define	PPPIO_COMPLEV	_PPPIO(154)	/* set compression effort level */
#define	PPPIO_GTYPE	_PPPIO(155)	/* get existing driver type */
#define	PPPIO_MUX	_PPPIO(156)	/* multiplexed frame */
#define	PPPIO_GETSTAT64	_PPPIO(157)	/* get PPP 64-bit statistics */
#define	PPPIO_BLOCKNP	_PPPIO(158)	/* block pkts with proto np in kernel */
#define	PPPIO_UNBLOCKNP	_PPPIO(159)	/* unblock pkts with proto np */

/* Values for PPPIO_MUX FLAGS */
#define	X_MUXMASK	0x10		/* transmit muxed frame option */
#define	R_MUXMASK	0x20		/* receive muxed frame option */

/*
 * Values for PPPIO_CFLAGS.  Data sent in is u_int32_t val[2], where
 * result is newflags = val[0] | (oldflags & ~val[1]).  Returned data
 * is a single u_int32_t, containing the current flags.
 */
#define	COMP_AC		0x1		/* compress address/control */
#define	DECOMP_AC	0x2		/* decompress address/control */
#define	COMP_PROT	0x4		/* compress PPP protocol */
#define	DECOMP_PROT	0x8		/* decompress PPP protocol */

#define	COMP_VJC	0x10		/* compress TCP/IP headers */
#define	COMP_VJCCID	0x20		/* compress connection ID as well */
#define	DECOMP_VJC	0x40		/* decompress TCP/IP headers */
#define	DECOMP_VJCCID	0x80		/* accept compressed connection ID */

#define	CCP_ISOPEN	0x100		/* look at CCP packets */
#define	CCP_ISUP	0x200		/* do packet comp/decomp */
#define	CCP_ERROR	0x400		/* (status) error in packet decomp */
#define	CCP_FATALERROR	0x800		/* (status) fatal error ditto */
#define	CCP_COMP_RUN	0x1000		/* (status) seen CCP ack sent */
#define	CCP_DECOMP_RUN	0x2000		/* (status) seen CCP ack rcvd */


/*
 * Values for PPPIO_XFCS/PPPIO_RFCS.  (Note that we don't support
 * simultaneous use of 16 bit and 32 bit CRCs.)
 */
#define	PPPFCS_16	0		/* The default, usually; CRC-16 */
#define	PPPFCS_32	1		/* CRC-32 */
#define	PPPFCS_NONE	2		/* No CRC */

/*
 * Values for 8-bit-clean flags.
 */
#define	RCV_B7_0	1		/* have rcvd char with bit 7 = 0 */
#define	RCV_B7_1	2		/* have rcvd char with bit 7 = 1 */
#define	RCV_EVNP	4		/* have rcvd char with even parity */
#define	RCV_ODDP	8		/* have rcvd char with odd parity */

/*
 * Values for the first byte of M_CTL messages passed between
 * PPP modules.
 */
#define	PPPCTL_OERROR	0xe0		/* output error [up] */
#define	PPPCTL_IERROR	0xe1		/* input error (e.g. FCS) [up] */
#define	PPPCTL_MTU	0xe2		/* set MTU [down] */
#define	PPPCTL_MRU	0xe3		/* set MRU [down] */
#define	PPPCTL_UNIT	0xe4		/* note PPP unit number [down] */

/*
 * Values for the u_int32_t argument to PPPIO_DEBUG.
 */
#define	PPPDBG_DUMP	0x10000		/* print out debug info now */
#define	PPPDBG_LOG	0x100		/* log various things */
#define	PPPDBG_DRIVER	0		/* identifies ppp driver as target */
#define	PPPDBG_IF	1		/* identifies ppp network i/f target */
#define	PPPDBG_COMP	2		/* identifies ppp compression target */
#define	PPPDBG_AHDLC	3		/* identifies ppp async hdlc target */

/*
 * Values for the u_int32_t return from PPPIO_GTYPE.  Only lastmod
 * should respond.  Current modules return PPPTYP_AHDLC (async
 * module), PPPTYP_HC (compression module) and PPPTYP_MUX (PPP
 * interface driver).
 */
#define	PPPTYP_HDLC	0		/* raw HDLC I/O; no PPP handling */
#define	PPPTYP_AHDLC	1		/* async HDLC; has [XR]ACCM */
#define	PPPTYP_HC	2		/* HDLC with ACFC and PFC support */
#define	PPPTYP_AHC	3		/* async with ACFC and PFC */
#define	PPPTYP_MUX	4		/* multiplexor */

#ifdef SOL2
/* Officially allocated module numbers */
#define	PPP_MOD_ID	2101	/* PPP multiplexor */
#define	COMP_MOD_ID	2102	/* Data and header compression */
#define	AHDLC_MOD_ID	2103	/* Asynchronous HDLC-like encapsulation */
#define	TUN_MOD_ID	2104	/* Tunneling protocols */
#define	MP_MOD_ID	2105	/* Multilink PPP */
#define	PPP_DRV_NAME	"sppp"
#define	AHDLC_MOD_NAME	"spppasyn"
#define	COMP_MOD_NAME	"spppcomp"
#define	TUN_MOD_NAME	"sppptun"
#define	MP_MOD_NAME	"spppmp"
#else
#define	PPP_MOD_ID	0xb1a6
#define	COMP_MOD_ID	0xbadf
#define	AHDLC_MOD_ID	0x7d23
#define	PPP_DRV_NAME	"ppp"
#define	AHDLC_MOD_NAME	"ppp_ahdl"
#define	COMP_MOD_NAME	"ppp_comp"
#endif
#define	PPP_DEV_NAME	"/dev/" PPP_DRV_NAME

#ifdef	__cplusplus
}
#endif

#endif /* __PPPIO_H */
