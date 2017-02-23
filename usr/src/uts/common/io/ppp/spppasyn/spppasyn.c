/*
 * spppasyn.c - STREAMS module for doing PPP asynchronous HDLC.
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
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
 * $Id: ppp_ahdlc.c,v 1.16 2000/03/06 19:38:12 masputra Exp $
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/crc32.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>

#include <net/ppp_defs.h>
#include <net/pppio.h>

#include "s_common.h"

#ifdef DEBUG
#define	REPORT_CRC_TYPE
#endif
#include "spppasyn.h"

/*
 * This is used to tag official Solaris sources.  Please do not define
 * "INTERNAL_BUILD" when building this software outside of Sun
 * Microsystems.
 */
#ifdef INTERNAL_BUILD
/* MODINFO is limited to 32 characters. */
const char spppasyn_module_description[] = "PPP 4.0 AHDLC";
#else /* INTERNAL_BUILD */
const char spppasyn_module_description[] = "ANU PPP AHDLC $Revision: 1.16$";

/* LINTED */
static const char buildtime[] = "Built " __DATE__ " at " __TIME__
#ifdef DEBUG
" DEBUG"
#endif
"\n";
#endif /* INTERNAL_BUILD */

static int	spppasyn_open(queue_t *, dev_t *, int, int, cred_t *);
static int	spppasyn_close(queue_t *, int, cred_t *);
static int	spppasyn_wput(queue_t *, mblk_t *);
static int	spppasyn_rput(queue_t *, mblk_t *);
static mblk_t	*ahdlc_encode(queue_t *, mblk_t *);
static mblk_t	*ahdlc_decode(queue_t *, mblk_t *);
static void	spppasyn_timer(void *);
static mblk_t	*spppasyn_inpkt(queue_t *, mblk_t *);
static mblk_t	*spppasyn_muxencode(queue_t *, mblk_t *);

#define	RESET_MUX_VALUES(x)	{	\
	x->sa_mqhead = x->sa_mqtail = NULL;	\
	x->sa_proto = 0;			\
	x->sa_mqlen = 0;			\
}
#define	IS_XMUX_ENABLED(x)	\
	((x)->sa_flags & X_MUXMASK)
#define	IS_RMUX_ENABLED(x)	\
	((x)->sa_flags & R_MUXMASK)
#define	IS_COMP_AC(x)	\
	((x)->sa_flags & SAF_XCOMP_AC)
#define	IS_COMP_PROT(x)	\
	((x)->sa_flags & SAF_XCOMP_PROT)
#define	IS_DECOMP_PROT(x)	\
	((x)->sa_flags & SAF_RDECOMP_PROT)

/*
 * Don't send HDLC start flag if last transmit is within 1.5 seconds -
 * FLAG_TIME is defined in nanoseconds.
 */
#define	FLAG_TIME	1500000000ul

/*
 * The usual AHDLC implementation enables the default escaping for all
 * LCP frames.  LCP_USE_DFLT() is used in this implementation to
 * modify this rule slightly.  If the code number happens to be
 * Echo-Request, Echo-Reply, or Discard-Request (each of which may be
 * sent only when LCP is in Opened state), then one may also use the
 * negotiated ACCM; the RFC is silent on this.  The theory is that
 * pppd can construct Echo-Request messages that are guaranteed to
 * fail if the negotiated ACCM is bad.
 */
#define	LCP_USE_DFLT(mp)	((code = MSG_BYTE((mp), 4)) < 9 || code > 11)

/*
 * Extract bit c from map m, to determine if character c needs to be
 * escaped.  Map 'm' is a pointer to a 256 bit map; 8 words of 32 bits
 * each.
 */
#define	IN_TX_MAP(c, m)	\
	((m)[(c) >> 5] & (1 << ((c) & 0x1f)))

/*
 * Checks the 32-bit receive ACCM to see if the byte should have been
 * escaped by peer.
 */
#define	IN_RX_MAP(c, m)		(((c) < 0x20) && ((m) & (1 << (c))))

static struct module_info spppasyn_modinfo = {
	AHDLC_MOD_ID,		/* mi_idnum */
	AHDLC_MOD_NAME,		/* mi_idname */
	0,			/* mi_minpsz */
	INFPSZ,			/* mi_maxpsz */
	0,			/* mi_hiwat */
	0			/* mi_lowat */
};

static struct qinit spppasyn_rinit = {
	spppasyn_rput,		/* qi_putp */
	NULL,			/* qi_srvp */
	spppasyn_open,		/* qi_qopen */
	spppasyn_close,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&spppasyn_modinfo,	/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct qinit spppasyn_winit = {
	spppasyn_wput,		/* qi_putp */
	NULL,			/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&spppasyn_modinfo,	/* qi_minfo */
	NULL			/* qi_mstat */
};

struct streamtab spppasyn_tab = {
	&spppasyn_rinit,	/* st_rdinit */
	&spppasyn_winit,	/* st_wrinit */
	NULL,			/* st_muxrinit */
	NULL,			/* st_muxwinit */
};

/* Matches above structure. */
static const char *kstat_names[] = {
	"ioctls", "ioctlsfwd", "ioctlserr", "ctls",
	"ctlsfwd", "ctlserr", "inbadchars", "inbadcharmask",
	"inaborts", "inrunts", "inallocfails", "intoolongs",
	"outrunts", "outallocfails", "incrcerrs", "unknownwrs",
	"unknownrds", "hangups", "datain", "dataout",
	"extrabufs", "sentmux", "recvmux", "inmuxerrs",
#ifdef REPORT_CRC_TYPE
	"incrctype", "outcrctype",
#endif
};

/* So.  This is why we have optimizing compilers. */
#define	KVAL(vn)	state->sa_kstats.vn.value.ui32
#define	KSET(vn, v)	KVAL(vn) = (v)
#define	KADD(vn, v)	KSET(vn, KVAL(vn) + (v))
#define	KOR(vn, v)	KSET(vn, KVAL(vn) | (v))
#define	KINCR(vn)	KADD(vn, 1)

static void ppp_dump_frame(sppp_ahdlc_t *state, mblk_t *mptr,
    const char *msg);

/*
 * RCV_B7_1, etc., defined in net/pppio.h, are stored in flags also.
 */
#define	RCV_FLAGS	(RCV_B7_1 | RCV_B7_0 | RCV_ODDP | RCV_EVNP)

/*
 * FCS lookup table as calculated by genfcstab.
 */
static ushort_t fcstab[256] = {
	0x0000,	0x1189,	0x2312,	0x329b,	0x4624,	0x57ad,	0x6536,	0x74bf,
	0x8c48,	0x9dc1,	0xaf5a,	0xbed3,	0xca6c,	0xdbe5,	0xe97e,	0xf8f7,
	0x1081,	0x0108,	0x3393,	0x221a,	0x56a5,	0x472c,	0x75b7,	0x643e,
	0x9cc9,	0x8d40,	0xbfdb,	0xae52,	0xdaed,	0xcb64,	0xf9ff,	0xe876,
	0x2102,	0x308b,	0x0210,	0x1399,	0x6726,	0x76af,	0x4434,	0x55bd,
	0xad4a,	0xbcc3,	0x8e58,	0x9fd1,	0xeb6e,	0xfae7,	0xc87c,	0xd9f5,
	0x3183,	0x200a,	0x1291,	0x0318,	0x77a7,	0x662e,	0x54b5,	0x453c,
	0xbdcb,	0xac42,	0x9ed9,	0x8f50,	0xfbef,	0xea66,	0xd8fd,	0xc974,
	0x4204,	0x538d,	0x6116,	0x709f,	0x0420,	0x15a9,	0x2732,	0x36bb,
	0xce4c,	0xdfc5,	0xed5e,	0xfcd7,	0x8868,	0x99e1,	0xab7a,	0xbaf3,
	0x5285,	0x430c,	0x7197,	0x601e,	0x14a1,	0x0528,	0x37b3,	0x263a,
	0xdecd,	0xcf44,	0xfddf,	0xec56,	0x98e9,	0x8960,	0xbbfb,	0xaa72,
	0x6306,	0x728f,	0x4014,	0x519d,	0x2522,	0x34ab,	0x0630,	0x17b9,
	0xef4e,	0xfec7,	0xcc5c,	0xddd5,	0xa96a,	0xb8e3,	0x8a78,	0x9bf1,
	0x7387,	0x620e,	0x5095,	0x411c,	0x35a3,	0x242a,	0x16b1,	0x0738,
	0xffcf,	0xee46,	0xdcdd,	0xcd54,	0xb9eb,	0xa862,	0x9af9,	0x8b70,
	0x8408,	0x9581,	0xa71a,	0xb693,	0xc22c,	0xd3a5,	0xe13e,	0xf0b7,
	0x0840,	0x19c9,	0x2b52,	0x3adb,	0x4e64,	0x5fed,	0x6d76,	0x7cff,
	0x9489,	0x8500,	0xb79b,	0xa612,	0xd2ad,	0xc324,	0xf1bf,	0xe036,
	0x18c1,	0x0948,	0x3bd3,	0x2a5a,	0x5ee5,	0x4f6c,	0x7df7,	0x6c7e,
	0xa50a,	0xb483,	0x8618,	0x9791,	0xe32e,	0xf2a7,	0xc03c,	0xd1b5,
	0x2942,	0x38cb,	0x0a50,	0x1bd9,	0x6f66,	0x7eef,	0x4c74,	0x5dfd,
	0xb58b,	0xa402,	0x9699,	0x8710,	0xf3af,	0xe226,	0xd0bd,	0xc134,
	0x39c3,	0x284a,	0x1ad1,	0x0b58,	0x7fe7,	0x6e6e,	0x5cf5,	0x4d7c,
	0xc60c,	0xd785,	0xe51e,	0xf497,	0x8028,	0x91a1,	0xa33a,	0xb2b3,
	0x4a44,	0x5bcd,	0x6956,	0x78df,	0x0c60,	0x1de9,	0x2f72,	0x3efb,
	0xd68d,	0xc704,	0xf59f,	0xe416,	0x90a9,	0x8120,	0xb3bb,	0xa232,
	0x5ac5,	0x4b4c,	0x79d7,	0x685e,	0x1ce1,	0x0d68,	0x3ff3,	0x2e7a,
	0xe70e,	0xf687,	0xc41c,	0xd595,	0xa12a,	0xb0a3,	0x8238,	0x93b1,
	0x6b46,	0x7acf,	0x4854,	0x59dd,	0x2d62,	0x3ceb,	0x0e70,	0x1ff9,
	0xf78f,	0xe606,	0xd49d,	0xc514,	0xb1ab,	0xa022,	0x92b9,	0x8330,
	0x7bc7,	0x6a4e,	0x58d5,	0x495c,	0x3de3,	0x2c6a,	0x1ef1,	0x0f78
};

/*
 * Per-character flags for accumulating input errors.  Flags are
 * accumulated for bit 7 set to 0, bit 7 set to 1, even parity
 * characters, and odd parity characters.  The link should see all
 * four in the very first LCP Configure-Request if all is ok.  (C0 is
 * even parity and has bit 7 set to 1, and 23 is odd parity and has
 * bit 7 set to 0.)
 */
static uchar_t charflags[256] = {
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_ODDP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_0|RCV_EVNP,
	RCV_B7_0|RCV_EVNP, RCV_B7_0|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP,
	RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP,
	RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_EVNP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP, RCV_B7_1|RCV_ODDP, RCV_B7_1|RCV_ODDP,
	RCV_B7_1|RCV_EVNP
};

/*
 * Append two lists; preserve message boundaries.
 * Warning: uses b_next.
 */
static mblk_t *
sppp_mappend(mblk_t *m1, mblk_t *m2)
{
	mblk_t *mret;

	if (m1 == NULL)
		return (m2);
	if (m2 == NULL)
		return (m1);

	mret = m1;
	while (m1->b_next != NULL)
		m1 = m1->b_next;
	m1->b_next = m2;
	return (mret);
}

/*
 * Concatenate two mblk lists.
 */
static mblk_t *
sppp_mcat(mblk_t *m1, mblk_t *m2)
{
	mblk_t *mret;

	if (m1 == NULL)
		return (m2);
	if (m2 == NULL)
		return (m1);

	mret = m1;
	while (m1->b_cont != NULL)
		m1 = m1->b_cont;
	m1->b_cont = m2;
	return (mret);
}

/*
 * spppasyn_open()
 *
 * STREAMS module open (entry) point.  Called when spppasyn is pushed
 * onto an asynchronous serial stream.
 */
/* ARGSUSED */
static int
spppasyn_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	sppp_ahdlc_t	*state;

	ASSERT(q != NULL);

	if (q->q_ptr != NULL) {
		return (0);		/* return if already opened */
	}

	if (sflag != MODOPEN) {
		return (EINVAL);	/* only open as a module */
	}

	state = (sppp_ahdlc_t *)kmem_zalloc(sizeof (sppp_ahdlc_t), KM_SLEEP);
	ASSERT(state != NULL);

	q->q_ptr = (caddr_t)state;
	WR(q)->q_ptr = (caddr_t)state;

	state->sa_xaccm[0] = 0xffffffff;	/* escape 0x00 through 0x1f */
	state->sa_xaccm[3] = 0x60000000;   /* escape 0x7d and 0x7e */
	state->sa_mru = PPP_MRU;		/* default of 1500 bytes */

	qprocson(q);

	return (0);
}

/*
 * spppasyn_close()
 *
 * STREAMS module close (exit) point
 */
/* ARGSUSED */
static int
spppasyn_close(queue_t *q, int flag, cred_t *credp)
{
	sppp_ahdlc_t	*state;

	ASSERT(q != NULL);
	state = (sppp_ahdlc_t *)q->q_ptr;
	ASSERT(state != NULL);

	/* We're leaving now.  No more calls, please. */
	qprocsoff(q);

	if (state->sa_rx_buf != NULL) {
		freemsg(state->sa_rx_buf);
		state->sa_rx_buf = NULL;
	}

	if (state->sa_ksp != NULL) {
		kstat_delete(state->sa_ksp);
		state->sa_ksp = NULL;
	}

	if (state->sa_mqhead != NULL)
		freemsg(state->sa_mqhead);
	/* remove the time out routine */
	if (state->sa_timeout_id != 0)
		(void) quntimeout(q, state->sa_timeout_id);

	q->q_ptr = NULL;
	WR(q)->q_ptr = NULL;
	kmem_free(state, sizeof (sppp_ahdlc_t));

	return (0);
}

/*
 * Create the standard kernel statistics structure and attach it to
 * the current state structure.  This can be called only after
 * assigning the unit number.
 */
static void
create_kstats(sppp_ahdlc_t *state)
{
	kstat_t *ksp;
	char unitname[KSTAT_STRLEN];
	int nstat, i;
	kstat_named_t *knt;

	nstat = sizeof (state->sa_kstats) / sizeof (kstat_named_t);
	knt = (kstat_named_t *)&state->sa_kstats;
	for (i = 0; i < nstat; i++, knt++) {
#ifdef DEBUG
		/* Just in case I do something silly here. */
		if (i >= sizeof (kstat_names) / sizeof (kstat_names[0]))
			(void) sprintf(knt->name, "unknown%d", i);
		else
#endif
			(void) strncpy(knt->name, kstat_names[i],
			    sizeof (knt->name));
		knt->data_type = KSTAT_DATA_UINT32;
	}
	/*
	 * sprintf is known to be safe here because KSTAT_STRLEN is
	 * 31, the maximum module name length is 8, and the maximum
	 * string length from %d is 11.  This was once snprintf, but
	 * that's not backward-compatible with Solaris 2.6.
	 */
	(void) sprintf(unitname, "%s" "%d", AHDLC_MOD_NAME, state->sa_unit);
	ksp = kstat_create(AHDLC_MOD_NAME, state->sa_unit, unitname, "net",
	    KSTAT_TYPE_NAMED, nstat, KSTAT_FLAG_VIRTUAL);
	if (ksp != NULL) {
		ksp->ks_data = (void *)&state->sa_kstats;
		kstat_install(ksp);
	}
	state->sa_ksp = ksp;
#ifdef REPORT_CRC_TYPE
	KSET(pks_outcrctype, 16);
	KSET(pks_incrctype, 16);
#endif
}

/*
 * spppasyn_inner_ioctl
 *
 * MT-Perimeters:
 *	exclusive inner
 *
 * Handle state-affecting ioctls.
 */
static void
spppasyn_inner_ioctl(queue_t *q, mblk_t *mp)
{
	sppp_ahdlc_t		*state;
	struct iocblk		*iop;
	int			error;
	int			flagval;
	int			len;
	uint32_t		mux_flags;
	uint32_t		mask;
	int			flagmask;

	ASSERT(q != NULL && mp != NULL);
	state = (sppp_ahdlc_t *)q->q_ptr;
	iop = (struct iocblk *)mp->b_rptr;
	ASSERT(state != NULL && iop != NULL);

	error = EINVAL;
	len = 0;

	switch (iop->ioc_cmd) {
	case PPPIO_XFCS:
		/* Check for valid option length */
		if (iop->ioc_count != sizeof (uint32_t) || mp->b_cont == NULL)
			break;

		/* Grab flag value */
		flagval = *(uint32_t *)mp->b_cont->b_rptr;
		if (flagval < PPPFCS_16 || flagval > PPPFCS_NONE)
			break;
		state->sa_flags &= ~SAF_XMITCRC32 & ~SAF_XMITCRCNONE;
		if (flagval == PPPFCS_32) {
#ifdef REPORT_CRC_TYPE
			KSET(pks_outcrctype, 32);
#endif
			state->sa_flags |= SAF_XMITCRC32;
		} else if (flagval == PPPFCS_NONE) {
#ifdef REPORT_CRC_TYPE
			KSET(pks_outcrctype, 0);
#endif
			state->sa_flags |= SAF_XMITCRCNONE;
		}
#ifdef REPORT_CRC_TYPE
		else {
			KSET(pks_outcrctype, 16);
		}
#endif

		/* Return success */
		error = 0;
		break;

	case PPPIO_RFCS:
		/* Check for valid option length */
		if (iop->ioc_count != sizeof (uint32_t) || mp->b_cont == NULL)
			break;

		/* Grab flag value */
		flagval = *(uint32_t *)mp->b_cont->b_rptr;
		if (flagval < PPPFCS_16 || flagval > PPPFCS_NONE)
			break;
		state->sa_flags &= ~SAF_RECVCRC32 & ~SAF_RECVCRCNONE;
		if (flagval == PPPFCS_32) {
#ifdef REPORT_CRC_TYPE
			KSET(pks_incrctype, 32);
#endif
			state->sa_flags |= SAF_RECVCRC32;
		} else if (flagval == PPPFCS_NONE) {
#ifdef REPORT_CRC_TYPE
			KSET(pks_incrctype, 0);
#endif
			state->sa_flags |= SAF_RECVCRCNONE;
		}
#ifdef REPORT_CRC_TYPE
		else {
			KSET(pks_incrctype, 16);
		}
#endif

		/* Return success */
		error = 0;
		break;

	case PPPIO_XACCM:
		/* Check for valid asyncmap length */
		if (iop->ioc_count < sizeof (uint32_t) ||
		    iop->ioc_count > sizeof (ext_accm) ||
		    mp->b_cont == NULL)
			break;

		/* Copy user's asyncmap into our state structure. */
		bcopy((caddr_t)mp->b_cont->b_rptr,
		    (caddr_t)state->sa_xaccm, iop->ioc_count);

		state->sa_xaccm[2] &= ~0x40000000;	/* don't escape 0x5e */
		state->sa_xaccm[3] |= 0x60000000;	/* escape 0x7d, 0x7e */

		error = 0;
		break;

	case PPPIO_RACCM:
		/* Check for valid asyncmap length (only ctrl chars) */
		if (iop->ioc_count != sizeof (uint32_t) ||
		    mp->b_cont == NULL)
			break;

		state->sa_raccm = *(uint32_t *)mp->b_cont->b_rptr;

		error = 0;
		break;

	case PPPIO_LASTMOD:
		/* We already know this. */
		state->sa_flags |= SAF_LASTMOD;
		error = 0;
		break;

	case PPPIO_MUX:
		/* set the compression flags */
		if (iop->ioc_count != 2 * sizeof (uint32_t) ||
		    mp->b_cont == NULL)
			break;

		/* set the mux flags */
		mux_flags = ((uint32_t *)mp->b_cont->b_rptr)[0];
		mask = ((uint32_t *)mp->b_cont->b_rptr)[1];
		if (mux_flags != 0)
			state->sa_flags = (state->sa_flags & ~mask) | (mask);

		/* set the multiplexing timer value */
		if (mask & R_MUXMASK)
			state->sa_timeout_usec = mux_flags;

		error = 0;
		break;

	case PPPIO_CFLAGS:
		if (iop->ioc_count != 2 * sizeof (uint32_t) ||
		    mp->b_cont == NULL)
			break;

		flagval = (((uint32_t *)mp->b_cont->b_rptr)[0] << 20) &
		    (SAF_RDECOMP_PROT | SAF_RDECOMP_AC | SAF_XCOMP_PROT |
		    SAF_XCOMP_AC);
		flagmask = (((uint32_t *)mp->b_cont->b_rptr)[1] << 20) &
		    (SAF_RDECOMP_PROT | SAF_RDECOMP_AC | SAF_XCOMP_PROT |
		    SAF_XCOMP_AC);
		state->sa_flags = flagval | (state->sa_flags & ~flagmask);
		*(uint32_t *)mp->b_cont->b_rptr = state->sa_flags >> 20;
		len = sizeof (uint32_t);
		error = 0;
		break;

	case PPPIO_DEBUG:
		if (iop->ioc_count != sizeof (uint32_t) || mp->b_cont == NULL)
			break;

		flagval = *(uint32_t *)mp->b_cont->b_rptr;
		if (flagval != PPPDBG_LOG + PPPDBG_AHDLC) {
			putnext(q, mp);
			return;
		}
		cmn_err(CE_CONT, AHDLC_MOD_NAME "%d: debug log enabled\n",
		    state->sa_unit);
		state->sa_flags |= SAF_XMITDUMP | SAF_RECVDUMP;
		error = 0;
		break;
	}

	if (error == 0) {
		/* Success; tell the user */
		if (mp->b_cont == NULL)
			len = 0;
		else
			mp->b_cont->b_wptr = mp->b_cont->b_rptr + len;
		miocack(q, mp, len, 0);
	} else {
		/* Failure; send error back upstream. */
		KINCR(pks_ioctlserr);
		miocnak(q, mp, 0, error);
	}
}

/*
 * spppasyn_inner_mctl
 *
 * MT-Perimeters:
 *	exclusive inner
 *
 * Handle state-affecting M_CTL messages.
 */
static void
spppasyn_inner_mctl(queue_t *q, mblk_t *mp)
{
	sppp_ahdlc_t	*state;
	int		msglen;
	int		error;

	ASSERT(q != NULL && mp != NULL);
	state = (sppp_ahdlc_t *)q->q_ptr;
	ASSERT(state != NULL);

	msglen = MBLKL(mp);
	error = 0;
	switch (*mp->b_rptr) {
	case PPPCTL_MTU:
				/* Just ignore the MTU */
		break;

	case PPPCTL_MRU:
		if (msglen != 4)
			error = EINVAL;
		else
			state->sa_mru =
			    ((ushort_t *)mp->b_rptr)[1];
		break;

	case PPPCTL_UNIT:
		if (state->sa_ksp != NULL) {
			error = EINVAL;
			break;
		}
		if (msglen == 2)
			state->sa_unit = mp->b_rptr[1];
		else if (msglen == 8)
			state->sa_unit =
			    ((uint32_t *)mp->b_rptr)[1];
		else
			error = EINVAL;
		if (error == 0 && state->sa_ksp == NULL)
			create_kstats(state);
		break;
	}

	if (error > 0) {
		KINCR(pks_ctlserr);
	}
	if (state->sa_flags & SAF_LASTMOD) {
		freemsg(mp);
	} else {
		KINCR(pks_ctlsfwd);
		putnext(q, mp);
	}
}

/*
 * spppasyn_wput()
 *
 * MT-Perimeters:
 *	exclusive inner.
 *
 * Write side put routine.  This called by the modules above us (likely to
 * be the compression module) to transmit data or pass along ioctls.
 */
static int
spppasyn_wput(queue_t *q, mblk_t *mp)
{
	sppp_ahdlc_t		*state;
	struct iocblk		*iop;
	int			error;
	mblk_t			*np;
	struct ppp_stats64	*psp;
	int			msglen;

	ASSERT(q != NULL && mp != NULL);
	state = (sppp_ahdlc_t *)q->q_ptr;
	ASSERT(state != NULL);

	switch (MTYPE(mp)) {

	case M_DATA:
		/*
		 * A data packet - do character-stuffing and FCS, and
		 * send it onwards.  The blocks are freed as we go.
		 */
		if (IS_XMUX_ENABLED(state))
			mp = spppasyn_muxencode(q, mp);
		else
			mp = ahdlc_encode(q, mp);
		if (mp != NULL)
			putnext(q, mp);
		break;

	case M_IOCTL:

		KINCR(pks_ioctls);
		iop = (struct iocblk *)mp->b_rptr;

		msglen = 0;

		switch (iop->ioc_cmd) {
		case PPPIO_XFCS:
		case PPPIO_RFCS:
		case PPPIO_XACCM:
		case PPPIO_RACCM:
		case PPPIO_LASTMOD:
		case PPPIO_DEBUG:
		case PPPIO_MUX:
		case PPPIO_CFLAGS:
			spppasyn_inner_ioctl(q, mp);
			return (0);

		case PPPIO_GCLEAN:
			np = allocb(sizeof (uint32_t), BPRI_HI);
			if (np == NULL) {
				error = ENOSR;
				break;
			}
			if (mp->b_cont != NULL) {
				freemsg(mp->b_cont);
			}
			mp->b_cont = np;

			*(uint32_t *)np->b_wptr = state->sa_flags & RCV_FLAGS;

			msglen = sizeof (uint32_t);
			np->b_wptr += msglen;
			error = 0;
			break;

		case PPPIO_GETSTAT:
			error = EINVAL;
			break;

		case PPPIO_GETSTAT64:
			np = allocb(sizeof (*psp), BPRI_HI);
			if (np == NULL) {
				error = ENOSR;
				break;
			}
			if (mp->b_cont != NULL) {
				freemsg(mp->b_cont);
			}
			mp->b_cont = np;

			psp = (struct ppp_stats64 *)np->b_wptr;
			bzero((caddr_t)psp, sizeof (*psp));
			psp->p = state->sa_stats;

			msglen = sizeof (*psp);
			np->b_wptr += msglen;
			error = 0;
			break;

		case PPPIO_GTYPE:
			np = allocb(sizeof (uint32_t), BPRI_HI);
			if (np == NULL) {
				error = ENOSR;
				break;
			}
			if (mp->b_cont != NULL) {
				freemsg(mp->b_cont);
			}
			mp->b_cont = np;

			*(uint32_t *)np->b_wptr = PPPTYP_AHDLC;

			msglen = sizeof (uint32_t);
			np->b_wptr += msglen;
			error = 0;
			break;

		default:
			/* Unknown ioctl -- forward along */
			KINCR(pks_ioctlsfwd);
			putnext(q, mp);
			return (0);
		}

		if (error == 0) {
			/* Success; tell the user */
			miocack(q, mp, msglen, 0);
		} else {
			/* Failure; send error back upstream. */
			KINCR(pks_ioctlserr);
			miocnak(q, mp, 0, error);
		}

		break;

	case M_CTL:
		KINCR(pks_ctls);
		spppasyn_inner_mctl(q, mp);
		break;

	default:
		if (state->sa_flags & (SAF_XMITDUMP|SAF_RECVDUMP))
			cmn_err(CE_CONT,
			    "spppasyn_wpur:  unknown buffer type %d",
			    MTYPE(mp));
		KINCR(pks_unknownwrs);
		putnext(q, mp);
		break;
	}

	return (0);
}

/*
 * spppasyn_rput()
 *
 * MT-Perimeters:
 *	exclusive inner.
 *
 * Read side put routine.  This is called by the async serial driver
 * below us to handle received data and returned signals (like
 * hang-up).
 */
static int
spppasyn_rput(queue_t *q, mblk_t  *mp)
{
	sppp_ahdlc_t	*state;
	mblk_t		*mpnext;

	ASSERT(q != NULL && mp != NULL);
	state = (sppp_ahdlc_t *)q->q_ptr;
	ASSERT(state != NULL);

	switch (MTYPE(mp)) {

	case M_DATA:
		/* Note -- decoder frees the buffers */
		mp = ahdlc_decode(q, mp);
		while (mp != NULL) {
			mpnext = mp->b_next;
			mp->b_next = NULL;
			putnext(q, mp);
			mp = mpnext;
		}
		break;

	case M_HANGUP:
		KINCR(pks_hangups);
		state->sa_flags |= SAF_IFLUSH;
		putnext(q, mp);
		break;

	default:
		if (state->sa_flags & (SAF_XMITDUMP|SAF_RECVDUMP)) {
			if (MTYPE(mp) == M_IOCTL)
				cmn_err(CE_CONT,
				    "spppasyn_rput:  unexpected ioctl %X",
				    ((struct iocblk *)mp->b_rptr)->ioc_cmd);
			else
				cmn_err(CE_CONT,
				    "spppasyn_rput:  unknown buffer type %d",
				    MTYPE(mp));
		}
		KINCR(pks_unknownrds);
		putnext(q, mp);
		break;
	}

	return (0);
}

/*
 * ahdlc_encode
 *
 * Perform asynchronous HDLC framing on a given buffer and transmit
 * the result.  The state structure must be valid.  The input buffers
 * are freed as we go.
 *
 * This function is called by wput and just encodes the data.  Wput
 * then calls putnext directly.  There's no service routine for this
 * module, so flow control is asserted by the module below us up to
 * our caller by the STREAMS framework.  This is by design -- this
 * module does not queue anything so that other modules can make QoS
 * decisions.
 */
static mblk_t *
ahdlc_encode(queue_t *q, mblk_t	*mp)
{
	sppp_ahdlc_t	*state;
	uint32_t	loc_xaccm[8];
	ushort_t	fcs16;
	uint32_t	fcs32;
	size_t		msglen;
	size_t		outmp_len;
	mblk_t		*outmp;
	mblk_t		*curout;
	mblk_t		*tmp;
	uchar_t		*ep;
	uchar_t		*dp;
	uchar_t		*tp;
	uchar_t		*tpmax;
#if defined(lint) || defined(_lint)
	uchar_t		chr;	/* lint likes this */
#else
	int		chr;	/* not uchar_t; more efficient this way */
				/* with WorkShop compiler */
#endif
	int		is_lcp, is_ctrl;
	int		code;
	hrtime_t	hrtime;
	uint32_t	flags;	/* sampled copy of flags */

	state = (sppp_ahdlc_t *)q->q_ptr;

	/* Don't transmit anything obviously silly. */
	msglen = msgsize(mp);
	if (msglen < 4) {
		KINCR(pks_outrunts);
		freemsg(mp);
		(void) putnextctl1(RD(q), M_CTL, PPPCTL_OERROR);
		return (NULL);
	}

	/*
	 * Allocate an output buffer just large enough for most cases.
	 * Based on original work in the ppp-2.2 AIX PPP driver, we
	 * estimate the output size as 1.25 * input message length
	 * plus 16.  If this turns out to be too small, then we'll
	 * allocate exactly one additional buffer with two times the
	 * remaining input length (the maximum that could possibly be
	 * required).
	 */
	outmp_len = msglen + (msglen >> 2) + 16;
	outmp = allocb(outmp_len, BPRI_MED);
	if (outmp == NULL)
		goto outallocfail;

	tp = outmp->b_wptr;

	/*
	 * Check if our last transmit happened within FLAG_TIME, using
	 * the system's hrtime.
	 */
	hrtime = gethrtime();
	if (ABS(hrtime - state->sa_hrtime) > FLAG_TIME) {
		*tp++ = PPP_FLAG;
	}
	state->sa_hrtime = hrtime;
	bcopy((caddr_t)state->sa_xaccm, (caddr_t)loc_xaccm, sizeof (loc_xaccm));
	flags = state->sa_flags;

	/*
	 * LCP messages must be sent using the default escaping
	 * (ACCM).  We bend this rule a little to allow LCP
	 * Echo-Request through with the negotiated escaping so that
	 * we can detect bad negotiated ACCM values.  If the ACCM is
	 * bad, echos will fail and take down the link.
	 */
	is_lcp = is_ctrl = 0;
	code = MSG_BYTE(mp, 0);
	if (code == PPP_ALLSTATIONS) {
		if (MSG_BYTE(mp, 1) == PPP_UI) {
			code = MSG_BYTE(mp, 2);
			if (code == (PPP_LCP >> 8) &&
			    MSG_BYTE(mp, 3) == (PPP_LCP & 0xFF)) {
				if (LCP_USE_DFLT(mp))
					is_lcp = 2;
				else
					is_lcp = 1;	/* Echo-Request */
			} else if (!(code & 1) && code > 0x3F)
				is_ctrl = 1;
		}
	} else if (!(code & 1) && code > 0x3F)
		is_ctrl = 1;

	/*
	 * If it's LCP and not just an LCP Echo-Request, then we need
	 * to drop back to default escaping rules temporarily.
	 */
	if (is_lcp > 1) {
		/*
		 * force escape on 0x00 through 0x1f
		 * and, for RFC 1662 (and ISO 3309:1991), 0x80-0x9f.
		 */
		loc_xaccm[0] = 0xffffffff;
		loc_xaccm[4] = 0xffffffff;
	}

	fcs16 = PPPINITFCS16;		/* Initial FCS is 0xffff */
	fcs32 = PPPINITFCS32;

	/*
	 * Process this block and the rest (if any) attached to this
	 * one.  Note that we quite intentionally ignore the type of
	 * the buffer.  The caller has checked that the first buffer
	 * is M_DATA; all others must be so, and any that are not are
	 * harmless driver errors.
	 */
	curout = outmp;
	tpmax = outmp->b_datap->db_lim;
	do {
		dp = mp->b_rptr;
		while (dp < (ep = mp->b_wptr)) {
			/*
			 * Calculate maximum safe run length for inner loop,
			 * regardless of escaping.
			 */
			outmp_len = (tpmax - tp) / 2;
			if (dp + outmp_len < ep)
				ep = dp + outmp_len;

			/*
			 * Select out on CRC type here to make the
			 * inner byte loop more efficient.  (We could
			 * do both CRCs at all times if we wanted, but
			 * that ends up taking an extra 8 cycles per
			 * byte -- 47% overhead!)
			 */
			if (flags & SAF_XMITCRC32) {
				while (dp < ep) {
					chr = *dp++;
					fcs32 = PPPFCS32(fcs32, chr);
					if (IN_TX_MAP(chr, loc_xaccm)) {
						*tp++ = PPP_ESCAPE;
						chr ^= PPP_TRANS;
					}
					*tp++ = chr;
				}
			} else {
				while (dp < ep) {
					chr = *dp++;
					fcs16 = PPPFCS16(fcs16, chr);
					if (IN_TX_MAP(chr, loc_xaccm)) {
						*tp++ = PPP_ESCAPE;
						chr ^= PPP_TRANS;
					}
					*tp++ = chr;
				}
			}

			/*
			 * If we limited our run length and we're now low
			 * on output space, then allocate a new output buffer.
			 * This should rarely happen, unless the output data
			 * has a lot of escapes.
			 */
			if (ep != mp->b_wptr && tpmax - tp < 5) {
				KINCR(pks_extrabufs);
				/* Get remaining message length */
				outmp_len = (mp->b_wptr - dp) +
				    msgsize(mp->b_cont);
				/* Calculate maximum required space */
				outmp_len = (outmp_len + PPP_FCS32LEN) * 2 + 1;
				curout = allocb(outmp_len, BPRI_MED);
				if ((outmp->b_cont = curout) == NULL)
					goto outallocfail;
				outmp->b_wptr = tp;
				tp = curout->b_wptr;
				tpmax = curout->b_datap->db_lim;
			}
		}
		tmp = mp->b_cont;
		freeb(mp);
		mp = tmp;
	} while (mp != NULL);

	/*
	 * Make sure we have enough remaining room to add the CRC (if
	 * any) and a trailing flag byte.
	 */
	outmp_len = PPP_FCS32LEN * 2 + 1;
	if (tpmax - tp < outmp_len) {
		KINCR(pks_extrabufs);
		curout = allocb(outmp_len, BPRI_MED);
		if ((outmp->b_cont = curout) == NULL)
			goto outallocfail;
		outmp->b_wptr = tp;
		tp = curout->b_wptr;
		tpmax = curout->b_datap->db_lim;
	}

	/*
	 * Network layer data is the only thing that can be sent with
	 * no CRC at all.
	 */
	if ((flags & SAF_XMITCRCNONE) && !is_lcp && !is_ctrl)
		goto nocrc;

	if (!(flags & SAF_XMITCRC32))
		fcs32 = fcs16;

	/*
	 * Append the HDLC FCS, making sure that escaping is done on any
	 * necessary bytes. Note that the FCS bytes are in little-endian.
	 */
	fcs32 = ~fcs32;
	chr = fcs32 & 0xff;
	if (IN_TX_MAP(chr, loc_xaccm)) {
		*tp++ = PPP_ESCAPE;
		chr ^= PPP_TRANS;
	}
	*tp++ = chr;

	chr = (fcs32 >> 8) & 0xff;
	if (IN_TX_MAP(chr, loc_xaccm)) {
		*tp++ = PPP_ESCAPE;
		chr ^= PPP_TRANS;
	}
	*tp++ = chr;

	if (flags & SAF_XMITCRC32) {
		chr = (fcs32 >> 16) & 0xff;
		if (IN_TX_MAP(chr, loc_xaccm)) {
			*tp++ = PPP_ESCAPE;
			chr ^= PPP_TRANS;
		}
		*tp++ = chr;

		chr = (fcs32 >> 24) & 0xff;
		if (IN_TX_MAP(chr, loc_xaccm)) {
			*tp++ = PPP_ESCAPE;
			chr ^= PPP_TRANS;
		}
		*tp++ = chr;
	}

nocrc:
	/*
	 * And finally append the HDLC flag, and send it away
	 */
	*tp++ = PPP_FLAG;
	ASSERT(tp < tpmax);
	curout->b_wptr = tp;

	state->sa_stats.ppp_obytes += msgsize(outmp);
	state->sa_stats.ppp_opackets++;

	if (state->sa_flags & SAF_XMITDUMP)
		ppp_dump_frame(state, outmp, "sent");

	KINCR(pks_dataout);
	return (outmp);

outallocfail:
	KINCR(pks_outallocfails);
	state->sa_stats.ppp_oerrors++;
	freemsg(outmp);
	freemsg(mp);
	(void) putnextctl1(RD(q), M_CTL, PPPCTL_OERROR);
	return (NULL);
}

/*
 * Handle end-of-frame excitement.  This is here mostly because the Solaris
 * C style rules require tab for indent and prohibit excessive indenting.
 */
static mblk_t *
receive_frame(queue_t *q, mblk_t *outmp, ushort_t fcs16, uint32_t fcs32)
{
	sppp_ahdlc_t *state = (sppp_ahdlc_t *)q->q_ptr;
	uchar_t *cp, *ep;
	int is_lcp, is_ctrl, crclen;
	ushort_t 	proto;
	int i;

	cp = outmp->b_rptr;
	if (cp[0] == PPP_ALLSTATIONS && cp[1] == PPP_UI)
		cp += 2;
	proto = *cp++;
	if ((proto & 1) == 0)
		proto = (proto << 8) + *cp++;
	is_lcp = (proto == PPP_LCP);
	is_ctrl = (proto >= 0x4000);

	/*
	 * To allow for renegotiation, LCP accepts good CRCs of either
	 * type at any time.  Other control (non-network) packets must
	 * have either CRC-16 or CRC-32, as negotiated.  Network layer
	 * packets may additionally omit the CRC entirely, if that was
	 * negotiated.
	 */
	if ((is_lcp && (fcs16 == PPPGOODFCS16 || fcs32 == PPPGOODFCS32)) ||
	    ((fcs16 == PPPGOODFCS16 && !(state->sa_flags & SAF_RECVCRC32)) ||
	    (fcs32 == PPPGOODFCS32 &&
	    (state->sa_flags & SAF_RECVCRC32))) ||
	    (!is_ctrl && !is_lcp && (state->sa_flags & SAF_RECVCRCNONE))) {

		state->sa_stats.ppp_ipackets++;
		if (is_lcp) {
			crclen = (fcs16 == PPPGOODFCS16) ?
			    PPP_FCSLEN : PPP_FCS32LEN;
		} else {
			crclen = (state->sa_flags & SAF_RECVCRC32) ?
			    PPP_FCS32LEN : PPP_FCSLEN;
			if (!is_ctrl && (state->sa_flags & SAF_RECVCRCNONE))
				crclen = 0;
		}
		if (crclen != 0) {
			i = adjmsg(outmp, -crclen);
			ASSERT(i != 0);
#if defined(lint) || defined(_lint)
			/* lint is happier this way in a non-DEBUG build */
			i = i;
#endif
		}

		if (proto == PPP_MUX) {
			/* spppasyn_inpkt checks for PPP_MUX packets */
			KINCR(pks_recvmux);
			/* Remove headers */
			outmp->b_rptr = cp;
			return (spppasyn_inpkt(q, outmp));
		}

		/*
		 * Sniff the received data stream.  If we see an LCP
		 * Configure-Ack, then pick out the ACCM setting, if
		 * any, and configure now.  This allows us to stay in
		 * sync in case the peer is already out of Establish
		 * phase.
		 */
		if (is_lcp && *cp == 2) {
			ep = outmp->b_wptr;
			i = (cp[2] << 8) | cp[3];
			if (i > ep - cp)
				ep = cp;	/* Discard junk */
			else if (i < ep - cp)
				ep = cp + i;
			cp += 4;
			while (cp + 2 < ep) {
				if ((i = cp[1]) < 2)
					i = 2;
				if (cp + i > ep)
					i = ep - cp;
				if (cp[0] == 2 && i >= 6) {
					state->sa_raccm = (cp[2] << 24) |
					    (cp[3] << 16) | (cp[4] << 8) |
					    cp[5];
					break;
				}
				cp += i;
			}
		}
		return (outmp);
	} else {
		KINCR(pks_incrcerrs);
		cmn_err(CE_CONT, PPP_DRV_NAME "%d: bad fcs (len=%ld)\n",
		    state->sa_unit, msgsize(outmp));

		if (state->sa_flags & SAF_RECVDUMP)
			ppp_dump_frame(state, outmp, "bad data");

		freemsg(outmp);

		state->sa_stats.ppp_ierrors++;

		(void) putnextctl1(q, M_CTL, PPPCTL_IERROR);
		return (NULL);
	}
}

/*
 * ahdlc_decode()
 *
 * Process received characters.
 *
 * This is handled as exclusive inner so that we don't get confused
 * about the state.  Returns a list of packets linked by b_next.
 */
static mblk_t *
ahdlc_decode(queue_t *q, mblk_t  *mp)
{
	sppp_ahdlc_t	*state;
	mblk_t		*retmp;		/* list of packets to return */
	mblk_t		*outmp;		/* buffer for decoded data */
	mblk_t		*mpnext;	/* temporary ptr for unlinking */
	uchar_t		*dp;		/* pointer to input data */
	uchar_t		*dpend;		/* end of input data */
	uchar_t		*tp;		/* pointer to decoded output data */
	uchar_t		*tpmax;		/* output buffer limit */
	int		flagtmp;	/* temporary cache of flags */
#if defined(lint) || defined(_lint)
	uchar_t		chr;	/* lint likes this */
#else
	int		chr;	/* not uchar_t; more efficient this way */
				/* with WorkShop compiler */
#endif
	ushort_t	fcs16;		/* running CRC-16 */
	uint32_t	fcs32;		/* running CRC-32 */
#ifdef HANDLE_ZERO_LENGTH
	size_t		nprocessed;
#endif

	state = (sppp_ahdlc_t *)q->q_ptr;

	KINCR(pks_datain);

	state->sa_stats.ppp_ibytes += msgsize(mp);

	if (state->sa_flags & SAF_RECVDUMP)
		ppp_dump_frame(state, mp, "rcvd");

	flagtmp = state->sa_flags;
	fcs16 = state->sa_infcs16;
	fcs32 = state->sa_infcs32;
	outmp = state->sa_rx_buf;
	if (outmp == NULL) {
		tp = tpmax = NULL;
	} else {
		tp = outmp->b_wptr;
		tpmax = outmp->b_datap->db_lim;
	}
#ifdef HANDLE_ZERO_LENGTH
	nprocessed = 0;
#endif

	/*
	 * Main input processing loop.  Loop over received buffers and
	 * each byte in each buffer.  Note that we quite intentionally
	 * ignore the type of the buffer.  The caller has checked that
	 * the first buffer is M_DATA; all others must be so, and any
	 * that are not are harmless driver errors.
	 */
	retmp = NULL;
	while (mp != NULL) {

		/* Innermost loop -- examine bytes in buffer. */
		dpend = mp->b_wptr;
		dp = mp->b_rptr;
#ifdef HANDLE_ZERO_LENGTH
		nprocessed += dpend - dp;
#endif
		for (; dp < dpend; dp++) {
			chr = *dp;

			/*
			 * This should detect the lack of an 8-bit
			 * communication channel, which is necessary
			 * for PPP to work.
			 */
			flagtmp |= charflags[chr];

			/*
			 * So we have a HDLC flag ...
			 */
			if (chr == PPP_FLAG) {

				/*
				 * If there's no received buffer, then
				 * just ignore this frame marker.
				 */
				if ((flagtmp & SAF_IFLUSH) || outmp == NULL) {
					flagtmp &= ~SAF_IFLUSH & ~SAF_ESCAPED;
					continue;
				}

				/*
				 * Per RFC 1662 -- silently discard
				 * runt frames (fewer than 4 octets
				 * with 16 bit CRC) and frames that
				 * end in 7D 7E (abort sequence).
				 * These are not counted as errors.
				 *
				 * (We could just reset the pointers
				 * and reuse the buffer, but this is a
				 * rarely used error path and not
				 * worth the optimization.)
				 */
				if ((flagtmp & SAF_ESCAPED) ||
				    tp - outmp->b_rptr < 2 + PPP_FCSLEN) {
					if (flagtmp & SAF_ESCAPED)
						KINCR(pks_inaborts);
					else
						KINCR(pks_inrunts);
					if (state->sa_flags & SAF_RECVDUMP) {
						outmp->b_wptr = tp;
						ppp_dump_frame(state, outmp,
						    "runt");
					}
					freemsg(outmp);
					flagtmp &= ~SAF_ESCAPED;
				} else {
					/* Handle the received frame */
					outmp->b_wptr = tp;
					outmp = receive_frame(q, outmp, fcs16,
					    fcs32);
					retmp = sppp_mappend(retmp, outmp);
				}

				outmp = NULL;
				tp = tpmax = NULL;

				continue;
			}

			/* If we're waiting for a new frame, then drop data. */
			if (flagtmp & SAF_IFLUSH) {
				continue;
			}

			/*
			 * Start of new frame.  Allocate a receive
			 * buffer large enough to store a frame (after
			 * un-escaping) of at least 1500 octets plus
			 * the CRC.  If MRU is negotiated to be more
			 * than the default, then allocate that much.
			 * In addition, we add an extra 32-bytes for a
			 * fudge factor, in case the peer doesn't do
			 * arithmetic very well.
			 */
			if (outmp == NULL) {
				int maxlen;

				if ((maxlen = state->sa_mru) < PPP_MRU)
					maxlen = PPP_MRU;
				maxlen += PPP_FCS32LEN + 32;
				outmp = allocb(maxlen, BPRI_MED);

				/*
				 * If allocation fails, try again on
				 * the next frame.  (Go into discard
				 * mode.)
				 */
				if (outmp == NULL) {
					KINCR(pks_inallocfails);
					flagtmp |= SAF_IFLUSH;
					continue;
				}

				tp = outmp->b_wptr;
				tpmax = outmp->b_datap->db_lim;

				/* Neither flag can possibly be set here. */
				flagtmp &= ~(SAF_IFLUSH | SAF_ESCAPED);
				fcs16 = PPPINITFCS16;
				fcs32 = PPPINITFCS32;
			}

			/*
			 * If the peer sends us a character that's in
			 * our receive character map, then that's
			 * junk.  Discard it without changing state.
			 * If they previously sent us an escape
			 * character, then toggle this one and
			 * continue.  Otherwise, if they're now sending
			 * escape, set the flag for next time.
			 */
			if (IN_RX_MAP(chr, state->sa_raccm)) {
				KINCR(pks_inbadchars);
				KOR(pks_inbadcharmask, 1 << chr);
				continue;
			}
			if (flagtmp & SAF_ESCAPED) {
				chr ^= PPP_TRANS;
				flagtmp &= ~SAF_ESCAPED;
			} else if (chr == PPP_ESCAPE) {
				flagtmp |= SAF_ESCAPED;
				continue;
			}

			/*
			 * Unless the peer is confused about the
			 * negotiated MRU, we should never get a frame
			 * that is too long.  If it happens, toss it
			 * away and begin discarding data until we see
			 * the end of the frame.
			 */
			if (tp < tpmax) {
				fcs16 = PPPFCS16(fcs16, chr);
				fcs32 = PPPFCS32(fcs32, chr);
				*tp++ = chr;
			} else {
				KINCR(pks_intoolongs);
				cmn_err(CE_CONT, PPP_DRV_NAME
				    "%d: frame too long (%d bytes)\n",
				    state->sa_unit,
				    (int)(tpmax - outmp->b_rptr));

				freemsg(outmp);
				outmp = NULL;
				tp = tpmax = NULL;
				flagtmp |= SAF_IFLUSH;
			}
		}

		/*
		 * Free the buffer we just processed and move on to
		 * the next one.
		 */
		mpnext = mp->b_cont;
		freeb(mp);
		mp = mpnext;
	}
	state->sa_flags = flagtmp;
	if ((state->sa_rx_buf = outmp) != NULL)
		outmp->b_wptr = tp;
	state->sa_infcs16 = fcs16;
	state->sa_infcs32 = fcs32;

#ifdef HANDLE_ZERO_LENGTH
	if (nprocessed <= 0) {
		outmp = allocb(0, BPRI_MED);
		if (outmp != NULL) {
			outmp->b_datap->db_type = M_HANGUP;
			retmp = sppp_mappend(retmp, outmp);
		}
	}
#endif
	return (retmp);
}

/*
 * Nifty packet dumper; copied from AIX 4.1 port.  This routine dumps
 * the raw received and transmitted data through syslog.  This allows
 * debug of communications problems without resorting to a line
 * analyzer.
 *
 * The expression "3*BYTES_PER_LINE" used frequently here represents
 * the size of each hex value printed -- two hex digits and a space.
 */
#define	BYTES_PER_LINE	8
static void
ppp_dump_frame(sppp_ahdlc_t *state, mblk_t *mptr, const char *msg)
{
	/*
	 * Buffer is big enough for hex digits, two spaces, ASCII output,
	 * and one NUL byte.
	 */
	char buf[3 * BYTES_PER_LINE + 2 + BYTES_PER_LINE + 1];
	uchar_t *rptr, *eptr;
	int i, chr;
	char *bp;
	static const char digits[] = "0123456789abcdef";

	cmn_err(CE_CONT, "!ppp_async%d: %s %ld bytes\n", state->sa_unit,
	    msg, msgsize(mptr));
	i = 0;
	bp = buf;
	/* Add filler spaces between hex output and ASCII */
	buf[3 * BYTES_PER_LINE] = ' ';
	buf[3 * BYTES_PER_LINE + 1] = ' ';
	/* Add NUL byte at end */
	buf[sizeof (buf) - 1] = '\0';
	while (mptr != NULL) {
		rptr = mptr->b_rptr; /* get pointer to beginning  */
		eptr = mptr->b_wptr;
		while (rptr < eptr) {
			chr = *rptr++;
			/* convert byte to ascii hex */
			*bp++ = digits[chr >> 4];
			*bp++ = digits[chr & 0xf];
			*bp++ = ' ';
			/* Insert ASCII past hex output and filler */
			buf[3 * BYTES_PER_LINE + 2 + i] =
			    (chr >= 0x20 && chr <= 0x7E) ? (char)chr : '.';
			i++;
			if (i >= BYTES_PER_LINE) {
				cmn_err(CE_CONT, "!ppp%d: %s\n", state->sa_unit,
				    buf);
				bp = buf;
				i = 0;
			}
		}
		mptr = mptr->b_cont;
	}
	if (bp > buf) {
		/* fill over unused hex display positions */
		while (bp < buf + 3 * BYTES_PER_LINE)
			*bp++ = ' ';
		/* terminate ASCII string at right position */
		buf[3 * BYTES_PER_LINE + 2 + i] = '\0';
		cmn_err(CE_CONT, "!ppp%d: %s\n", state->sa_unit, buf);
	}
}

static mblk_t *
spppasyn_muxencode(queue_t *q, mblk_t *mp)
{
	sppp_ahdlc_t	*state = (sppp_ahdlc_t *)q->q_ptr;
	uint32_t	len;
	uint32_t	nlen;
	ushort_t	protolen;
	uint32_t	hdrlen;
	ushort_t	proto;
	mblk_t		*new_frame;
	mblk_t		*tmp;
	mblk_t		*send_frame;
	ushort_t	i;

	len = msgdsize(mp);
	i = 0;
	protolen = 1;
	proto = MSG_BYTE(mp, i);

	if (proto == PPP_ALLSTATIONS) {
		len -= 2;
		i += 2;
		proto = MSG_BYTE(mp, i);
	}

	++i;
	if ((proto & 1) == 0) {
		proto = (proto << 8) + MSG_BYTE(mp, i);
		protolen++;
	}

	hdrlen = i - 1;

	send_frame = NULL;
	if (len > PPP_MAX_MUX_LEN || (proto & 0x8000)) {

		/* send the queued frames */
		if (state->sa_mqhead != NULL) {
			/* increment counter if it is MUX pkt */
			if (state->sa_mqtail != NULL)
				KINCR(pks_sentmux);
			send_frame = ahdlc_encode(q, state->sa_mqhead);
		}

		/* send the current frame */
		mp = ahdlc_encode(q, mp);
		send_frame = sppp_mcat(send_frame, mp);

		/* reset the state values over here */
		RESET_MUX_VALUES(state);
		return (send_frame);
	}

	/* len + 1 , since we add the mux overhead */
	nlen = len + 1;
	/* subtract the protocol length if protocol matches */
	if (state->sa_proto == proto)
		nlen -= protolen;

	send_frame = NULL;
	if ((state->sa_mqlen + nlen) >= state->sa_mru) {

		/* send the existing queued frames */
		if (state->sa_mqhead != NULL) {
			/* increment counter if it is MUX pkt */
			if (state->sa_mqtail != NULL)
				KINCR(pks_sentmux);
			send_frame = ahdlc_encode(q, state->sa_mqhead);
		}

		/* reset state values */
		RESET_MUX_VALUES(state);
	}

	/* add the current frame to the queue */
	if (state->sa_mqhead != NULL) {

		if (state->sa_mqtail == NULL) {

			/*
			 * this is the first mblk in the queue create
			 * a new frame to hold the PPP MUX header
			 */
			if ((new_frame = allocb(PPP_HDRLEN+1,
			    BPRI_MED)) == NULL) {
				return (send_frame);
			}

			if (!IS_COMP_AC(state)) {
				/* add the header */
				*new_frame->b_wptr++ = PPP_ALLSTATIONS;
				*new_frame->b_wptr++ = PPP_UI;
			}

			/* do protocol compression */
			if (IS_COMP_PROT(state)) {
				*new_frame->b_wptr++ = PPP_MUX;
			} else {
				*new_frame->b_wptr++ = 0;
				*new_frame->b_wptr++ = PPP_MUX;
			}

			*new_frame->b_wptr++ = PFF |
			    (state->sa_mqlen - protolen - 1);

			if (DB_REF(mp) > 1) {
				tmp = copymsg(state->sa_mqhead);
				freemsg(state->sa_mqhead);
				if ((state->sa_mqhead = tmp) == NULL) {
					return (send_frame);
				}
			}

			if (state->sa_mqhead->b_rptr[0] == PPP_ALLSTATIONS)
				state->sa_mqhead->b_rptr += 2;

			linkb(new_frame, state->sa_mqhead);
			state->sa_mqtail = state->sa_mqhead;
			/* point mqtail to the last mblk_t */
			while (state->sa_mqtail->b_cont != NULL)
				state->sa_mqtail = state->sa_mqtail->b_cont;

			/* change state->sa_mqhead */
			state->sa_mqhead = new_frame;

		}

		if (state->sa_proto == proto) {

			/* Check if the mblk_t is being referenced */
			if (DB_REF(mp) > 1) {
				tmp = copymsg(mp);
				freemsg(mp);
				if ((mp = tmp) == NULL) {
					return (send_frame);
				}
			}

			/*
			 * match,can remove the protocol field
			 * and write data there
			 */
			mp->b_rptr += hdrlen;
			/*
			 * protolen - 1 ,because the the byte with
			 * the PFF bit and the length field have
			 * to added
			 */
			mp->b_rptr += (protolen - 1);
			*mp->b_rptr = (len - protolen) & 0xff;

		} else {
			/*
			 * no match, there are three options
			 * 1. write in mp
			 * 2. write in mqtail
			 * 3. alloc a new blk for just one byte
			 */
			/* Check if the mblk_t is being referenced */
			if (DB_REF(mp) > 1) {
				tmp = copymsg(mp);
				freemsg(mp);
				if ((mp = tmp) == NULL) {
					return (send_frame);
				}
			}

			if (hdrlen != 0) {

				mp->b_rptr += (hdrlen-1);
				*mp->b_rptr = PFF | (len);

			} else if (state->sa_mqtail->b_wptr <
			    DB_LIM(state->sa_mqtail)) {
					*state->sa_mqtail->b_wptr++ = PFF |len;
			} else {
				/* allocate a new mblk & add the byte */
				/* write the data */
				if ((new_frame = allocb(1, BPRI_MED))
				    == NULL) {
					freemsg(mp);
					return (send_frame);
				}
				*new_frame->b_wptr++ = PFF | (len);
				linkb(state->sa_mqtail, new_frame);
			}

			/* update proto */
			state->sa_proto = proto;
		}

		linkb(state->sa_mqtail, mp);
		state->sa_mqtail = mp;
		while (state->sa_mqtail->b_cont != NULL)
			state->sa_mqtail = state->sa_mqtail->b_cont;
		state->sa_mqlen += nlen;

	} else {
		state->sa_mqhead = mp;
		state->sa_mqlen = len + protolen + 1;
		state->sa_proto = proto;
	}

	if (state->sa_timeout_id == 0) {
		state->sa_timeout_id = qtimeout(q, spppasyn_timer, q,
		    (drv_usectohz(state->sa_timeout_usec)));
	}
	return (send_frame);
}

/*
 * Called from receive frame, this routine checks if it is a PPP_MUX
 * packet and demuxes it.  The returned pointer is a chain of mblks
 * using b_next and representing the demultiplexed packets.
 */
static mblk_t *
spppasyn_inpkt(queue_t *q, mblk_t *mp)
{
	sppp_ahdlc_t	*state = (sppp_ahdlc_t *)q->q_ptr;
	ushort_t	proto;
	ushort_t	prev_proto;
	uint32_t	len;		/* length of subframe */
	uchar_t		muxhdr;
	mblk_t		*hdrmp;
	mblk_t		*subframe;
	mblk_t		*retmp;

	if (!(mp->b_rptr[0] & PFF)) {
		KINCR(pks_inmuxerrs);
		(void) putnextctl1(q, M_CTL, PPPCTL_IERROR);
		freemsg(mp);
		return (NULL);
	}

	/* initialise the Last protocol and protocol length */
	prev_proto = 0;

	/*
	 * Taking into granted that the decoded frame is contiguous
	 */
	retmp = NULL;
	while (mp->b_rptr < mp->b_wptr) {

		/*
		 * get the last protocol, protocol length
		 * and the length of the message
		 */

		/* protocol field flag and length */
		muxhdr = mp->b_rptr[0];
		len = muxhdr & ~PFF;

		mp->b_rptr++;

		/* check if there and enough bytes left in pkt */
		if (MBLKL(mp) < len) {
			KINCR(pks_inmuxerrs);
			(void) putnextctl1(q, M_CTL, PPPCTL_IERROR);
			break;
		}

		/* allocate memory for the header length */
		if ((hdrmp = allocb(PPP_HDRLEN, BPRI_MED)) == NULL) {
			KINCR(pks_inallocfails);
			break;
		}

		/* add the ppp header to the pkt */
		*hdrmp->b_wptr++ = PPP_ALLSTATIONS;
		*hdrmp->b_wptr++ = PPP_UI;

		/* check if the protocol field flag is set */
		if (muxhdr & PFF) {

			/* get the protocol */
			proto = MSG_BYTE(mp, 0);
			if ((proto & 1) == 0)
				proto = (proto << 8) + MSG_BYTE(mp, 1);

			/* reset values */
			prev_proto = proto;
		} else {
			if (!IS_DECOMP_PROT(state))
				*hdrmp->b_wptr++ = prev_proto >> 8;
			*hdrmp->b_wptr++ = (prev_proto & 0xff);
		}

		/* get the payload from the MUXed packet */
		subframe = dupmsg(mp);
		subframe->b_wptr = mp->b_rptr + len;

		/* link the subframe to the new frame */
		linkb(hdrmp, subframe);

		/* do a putnext */
		retmp = sppp_mappend(retmp, hdrmp);

		/* move the read pointer beyond this subframe */
		mp->b_rptr += len;
	}

	freemsg(mp);
	return (retmp);
}


/*
 * timer routine which sends out the queued pkts *
 */
static void
spppasyn_timer(void *arg)
{
	queue_t *q;
	sppp_ahdlc_t *state;
	mblk_t *mp;

	ASSERT(arg);
	q = (queue_t *)arg;
	state = (sppp_ahdlc_t *)q->q_ptr;

	if (state->sa_mqhead != NULL) {
		/* increment counter */
		if (state->sa_mqtail != NULL)
			KINCR(pks_sentmux);
		if ((mp = ahdlc_encode(q, state->sa_mqhead)) != NULL)
			putnext(q, mp);
		/* reset the state values over here */
		RESET_MUX_VALUES(state);
	}
	/* clear timeout_id */
	state->sa_timeout_id = 0;
}
