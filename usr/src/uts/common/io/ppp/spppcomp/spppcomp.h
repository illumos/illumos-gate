/*
 * spppcomp.h - Solaris STREAMS PPP compression module definitions
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

#ifndef __SPPPCOMP_H
#define	__SPPPCOMP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Per-unit kstats.
 */
typedef struct spppcomp_kstats {
	kstat_named_t	vj_out_pkts;
	kstat_named_t	vj_out_pkts_comp;
	kstat_named_t	vj_cs_searches;
	kstat_named_t	vj_cs_misses;
	kstat_named_t	vj_in_pkts_uncomp;
	kstat_named_t	vj_in_pkts_comp;
	kstat_named_t	vj_in_error;
	kstat_named_t	vj_in_tossed;
	kstat_named_t	out_errors_low;
	kstat_named_t	out_uncomp_bytes;
	kstat_named_t	out_uncomp_pkts;
	kstat_named_t	out_comp_bytes;
	kstat_named_t	out_comp_pkts;
	kstat_named_t	out_incomp_bytes;
	kstat_named_t	out_incomp_pkts;
	kstat_named_t	in_errors_low;
	kstat_named_t	in_uncomp_bytes;
	kstat_named_t	in_uncomp_pkts;
	kstat_named_t	in_comp_bytes;
	kstat_named_t	in_comp_pkts;
	kstat_named_t	in_incomp_bytes;
	kstat_named_t	in_incomp_pkts;
#ifdef SPC_DEBUG
	kstat_named_t	in_msg_ccp_pulledup;
	kstat_named_t	in_msg_vj_pulledup;
	kstat_named_t	out_msg_pulledup;
	kstat_named_t	out_msg_copied;
	kstat_named_t	out_queued;
	kstat_named_t	out_handled;
	kstat_named_t	in_queued;
	kstat_named_t	in_handled;
#endif

	/* 64 bit entries */
	kstat_named_t	out_bytes;
	kstat_named_t	out_pkts;
	kstat_named_t	out_errors;
	kstat_named_t	in_bytes;
	kstat_named_t	in_pkts;
	kstat_named_t	in_errors;
} spppcomp_kstats_t;

#define	SPPPCOMP_KSTATS_NAMES \
	"vj_out_pkts", "vj_out_pkts_comp", "vj_cs_searches", \
	"vj_cs_misses", "vj_in_pkts_uncomp", "vj_in_pkts_comp", \
	"vj_in_error", "vj_in_tossed",  "out_errors_lower", \
	"out_uncomp_bytes", "out_uncomp_pkts", "out_comp_bytes", \
	"out_comp_pkts", "out_incomp_bytes", "out_incomp_pkts", \
	"in_errors_lower", "in_uncomp_bytes", "in_uncomp_pkts", \
	"in_comp_bytes", "in_comp_pkts", "in_incomp_bytes", \
	"in_incomp_pkts"

#ifdef SPC_DEBUG
#define	SPCDEBUG_KSTATS_NAMES \
	"in_msg_ccp_pulledup", "in_msg_vj_pulledup", "out_msg_pulledup", \
	"out_msg_copied", "out_queued", "out_handled", \
	"in_queued", "in_handled"
#endif

#define	SPPPCOMP_KSTATS64_NAMES \
	"out_bytes", "out_pkts", "out_errors", \
	"in_bytes", "in_pkts", 	"in_errors"

/*
 * Per-stream instance state information.
 *
 * Each instance is dynamically allocated at open() and freed at close().
 * Each per-Stream instance points to at most one per-unit kstats structure
 * using the cp_kstats field, which is allocated once per-Stream when
 * PPPCTL_UNIT is received from above.
 */
typedef struct sppp_comp {
	uint32_t		cp_flags;	/* miscellaneous flags */
	ushort_t		cp_mru;		/* link layer MRU */
	ushort_t		cp_mtu;		/* link layer MTU */
	uint32_t		cp_unit;	/* unique unit id */
	struct compressor	*cp_xcomp;	/* compressor structure */
	void			*cp_xstate;	/* compressor state */
	struct compressor	*cp_rcomp;	/* de-compressor structure */
	void			*cp_rstate;	/* de-compressor state */
	struct vjcompress	cp_vj;		/* VJ compression state */
	kmutex_t		cp_pair_lock;	/* lock for queue pair */
	hrtime_t		cp_lastfinish;	/* last decode finish time */
	int16_t			cp_effort;	/* configured effort level */
	int16_t			cp_nxslots;	/* VJ compress slots */
	uint16_t		cp_fastin;	/* count of fast inputs */
	ppp_counter_t		cp_vj_last_ierrors; /* last VJ input errors */
	struct pppstat64	cp_stats;	/* legacy stats structure */
	kstat_t			*cp_kstats;	/* ptr to kstats structure */
	uint32_t		cp_ierr_low;	/* in error from below */
	uint32_t		cp_oerr_low;	/* out error from below */
#ifdef SPC_DEBUG
	uint32_t		cp_imsg_ccp_pull; /* msgpullup on recv */
	uint32_t		cp_imsg_vj_pull;  /* msgpullup on recv */
	uint32_t		cp_omsg_pull;	/* msgpullup on send */
	uint32_t		cp_omsg_dcopy;	/* copymsg on send */
	uint32_t		cp_out_queued;	/* did putq */
	uint32_t		cp_out_handled;	/* did putnext */
	uint32_t		cp_in_queued;	/* did putq */
	uint32_t		cp_in_handled;	/* did putnext */
#endif
} sppp_comp_t;

/*
 * Bits in flags are as defined in pppio.h
 *      COMP_AC         0x00000001	compress address/control
 *      DECOMP_AC       0x00000002      decompress address/control
 *      COMP_PROT       0x00000004      compress PPP protocol
 *      DECOMP_PROT     0x00000008      decompress PPP protocol
 *      COMP_VJC        0x00000010      compress TCP/IP headers
 *      COMP_VJCCID     0x00000020      compress connection ID as well
 *      DECOMP_VJC      0x00000040      decompress TCP/IP headers
 *      DECOMP_VJCCID   0x00000080      accept compressed connection ID
 *      CCP_ISOPEN      0x00000100      look at CCP packets
 *      CCP_ISUP        0x00000200      do packet comp/decomp
 *      CCP_ERROR       0x00000400      (status) error in packet decomp
 *      CCP_FATALERROR  0x00000800      (status) fatal error ditto
 *      CCP_COMP_RUN    0x00001000      (status) seen CCP ack sent
 *      CCP_DECOMP_RUN  0x00002000      (status) seen CCP ack rcvd
 */
#define	CP_KDEBUG	0x02000000	/* log debugging stuff */
#define	CP_HASUNIT	0x04000000	/* PPPCTL_UNIT has been issued on */
#define	CP_LASTMOD	0x08000000	/* last PPP-aware module in stream */
#define	CCP_ERR		(CCP_ERROR | CCP_FATALERROR)

#define	IS_COMP_AC(x)	\
	((x)->cp_flags & COMP_AC)
#define	IS_DECOMP_AC(x)	\
	((x)->cp_flags & DECOMP_AC)
#define	IS_COMP_PROT(x)	\
	((x)->cp_flags & COMP_PROT)
#define	IS_DECOMP_PROT(x)	\
	((x)->cp_flags & DECOMP_PROT)
#define	IS_COMP_VJC(x)	\
	((x)->cp_flags & COMP_VJC)
#define	IS_COMP_VJCCID(x)	\
	((x)->cp_flags & COMP_VJCCID)
#define	IS_DECOMP_VJC(x)	\
	((x)->cp_flags & DECOMP_VJC)
#define	IS_DECOMP_VJCCID(x)	\
	((x)->cp_flags & DECOMP_VJCCID)
#define	IS_CCP_ISOPEN(x)	\
	((x)->cp_flags & CCP_ISOPEN)
#define	IS_CCP_ISUP(x)	\
	((x)->cp_flags & CCP_ISUP)
#define	IS_CCP_ERROR(x)	\
	((x)->cp_flags & CCP_ERROR)
#define	IS_CCP_FATALERROR(x)	\
	((x)->cp_flags & CCP_FATALERROR)
#define	IS_CCP_COMP_RUN(x)	\
	((x)->cp_flags & CCP_COMP_RUN)
#define	IS_CCP_DECOMP_RUN(x)	\
	((x)->cp_flags & CCP_DECOMP_RUN)
#define	IS_CP_KDEBUG(x)	\
	((x)->cp_flags & CP_KDEBUG)
#define	IS_CP_HASUNIT(x)	\
	((x)->cp_flags & CP_HASUNIT)
#define	IS_CP_LASTMOD(x)	\
	((x)->cp_flags & CP_LASTMOD)

/*
 * Bit format (octal based) string for cmn_err/printf, which
 * represents the flags.
 */
#define	CP_FLAGSSTR		\
	"\020"			\
	"\1comp_ac"		\
	"\2decomp_ac"		\
	"\3comp_prot"		\
	"\4decomp_prot"		\
	"\5comp_vjc"		\
	"\6comp_vjccid"		\
	"\7decomp_vjc"		\
	"\10decomp_vjccid"	\
	"\11ccp_isopen"		\
	"\12ccp_isup"		\
	"\13ccp_error"		\
	"\14ccp_fatalerror"	\
	"\15ccp_comp_run"	\
	"\16ccp_decomp_run"	\
	"\32kdebug"		\
	"\33hasunit"		\
	"\34lastmod"

#ifdef	__cplusplus
}
#endif

#endif /* __SPPPCOMP_H */
