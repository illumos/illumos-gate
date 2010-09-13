/*
 * spppasyn.h - Solaris STREAMS PPP asynchronous HDLC module definitions
 *
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
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
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * This driver is derived from the original SVR4 STREAMS PPP driver
 * originally written by Paul Mackerras <paul.mackerras@cs.anu.edu.au>.
 *
 * Adi Masputra <adi.masputra@sun.com> rewrote and restructured the code
 * for improved performance and scalability.
 */

#ifndef __SPPPASYN_H
#define	__SPPPASYN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct spppasyn_kstats	{
	kstat_named_t	pks_ioctls;		/* total ioctl count */
	kstat_named_t	pks_ioctlsfwd;		/* forwarded down */
	kstat_named_t	pks_ioctlserr;		/* returned in error */
	kstat_named_t	pks_ctls;		/* total ctl count */
	kstat_named_t	pks_ctlsfwd;		/* forwarded down */
	kstat_named_t	pks_ctlserr;		/* discarded due to error */
	kstat_named_t	pks_inbadchars;		/* chars in recv accm */
	kstat_named_t	pks_inbadcharmask;	/* add to recv accm */
	kstat_named_t	pks_inaborts;		/* aborted (7D 7E) frames */
	kstat_named_t	pks_inrunts;		/* too short (<4) frames */
	kstat_named_t	pks_inallocfails;	/* out of STREAMS buffers */
	kstat_named_t	pks_intoolongs;		/* too long (>MRU) frames */
	kstat_named_t	pks_outrunts;		/* bugs in upper modules */
	kstat_named_t	pks_outallocfails;	/* out of STREAMS buffers */
	kstat_named_t	pks_incrcerrs;		/* bad input frames */
	kstat_named_t	pks_unknownwrs;		/* forwarded wput messages */
	kstat_named_t	pks_unknownrds;		/* forwarded rput messages */
	kstat_named_t	pks_hangups;		/* hang-up messages */
	kstat_named_t	pks_datain;		/* received from serial */
	kstat_named_t	pks_dataout;		/* sent to serial */
	kstat_named_t	pks_extrabufs;		/* extra buffers needed */
	kstat_named_t	pks_sentmux;		/* sent mux count */
	kstat_named_t	pks_recvmux;		/* received mux count */
	kstat_named_t	pks_inmuxerrs;		/* bad input mux frames */
#ifdef REPORT_CRC_TYPE
	kstat_named_t	pks_incrctype;		/* configured input CRC bits */
	kstat_named_t	pks_outcrctype;		/* configured output CRC */
#endif
} spppasyn_kstats_t;

/*
 * Per-stream state structure
 */
typedef struct sppp_ahdlc {
	uint32_t	sa_flags;		/* link flags */
	mblk_t		*sa_rx_buf;	/* ptr to receive buffer */
	ushort_t	sa_infcs16;	/* calculated rx HDLC FCS */
	ushort_t	sa_proto;	/* the last protocol in frame */
	uint32_t	sa_infcs32;	/* calculated rx HDLC FCS-32 */
	uint32_t	sa_xaccm[8];	/* 256-bit xmit ACCM */
	uint32_t	sa_raccm;	/* 32-bit rcv ACCM */
	int		sa_mru;		/* link MRU */
	int		sa_unit;	/* current PPP unit number */
	struct pppstat64 sa_stats;	/* statistic structure */
	hrtime_t	sa_hrtime;	/* last updated hrtime */
	mblk_t		*sa_mqhead;	/* pointer to the first message */
	mblk_t		*sa_mqtail;	/* pointer to the last message */
	size_t		sa_mqlen;	/* length of the frame so far */
	timeout_id_t	sa_timeout_id;	/* timeout id */
	uint32_t	sa_timeout_usec; /* value of the mux timer */
	kstat_t		*sa_ksp;	/* kernel statistics structure */
	spppasyn_kstats_t sa_kstats;	/* current statistics */
} sppp_ahdlc_t;

/*
 * Values for flags.  Note that bits 0-7 (0xFF) are used by RCV_* flags
 * and [XR]_MUXMASK in pppio.h.
 */
#define	SAF_ESCAPED	 0x00000100	/* last saw escape char on input */
#define	SAF_IFLUSH	 0x00000200	/* discarding due to hangup or error */
#define	SAF_XMITCRC32	 0x00000400	/* transmit 32 bit CRC */
#define	SAF_XMITCRCNONE	 0x00000800	/* transmit no CRC */
#define	SAF_RECVCRC32	 0x00001000	/* receive 32 bit CRC */
#define	SAF_RECVCRCNONE	 0x00002000	/* receive no CRC */
#define	SAF_XMITDUMP	 0x00004000	/* dump raw transmitted data */
#define	SAF_RECVDUMP	 0x00008000	/* dump raw received data */
#define	SAF_LASTMOD	 0x00010000	/* last PPP-aware module in stream */
#define	SAF_XCOMP_AC	 0x00100000	/* compress address/control */
#define	SAF_RDECOMP_AC	 0x00200000	/* decompress address/control */
#define	SAF_XCOMP_PROT	 0x00400000	/* compress PPP protocol */
#define	SAF_RDECOMP_PROT 0x00800000	/* decompress PPP protocol */

#ifdef	__cplusplus
}
#endif

#endif /* __SPPPASYN_H */
