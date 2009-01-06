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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * sppptun_impl.h - Internal sppptun data exposed for adb/mdb macros.
 */

#ifndef	_SPPPTUN_IMPL_H
#define	_SPPPTUN_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

/* For use with insque/remque (belongs in a system header!) */
struct qelem {
	struct qelem *q_forw;
	struct qelem *q_back;
};

typedef struct tunll_s tunll_t;
typedef struct tuncl_s tuncl_t;

typedef struct {
	kstat_named_t	lks_octrls;		/* sent control messages */
	kstat_named_t	lks_octrl_drop;		/* dropped control messages */
	kstat_named_t	lks_clients;		/* number of clients (tcls) */
	kstat_named_t	lks_walks;		/* PPPoE tcl walks */
	kstat_named_t	lks_in_nomatch;		/* input without match */
	kstat_named_t	lks_indata;		/* input data packets */
	kstat_named_t	lks_indata_drops;	/* input data packet drops */
	kstat_named_t	lks_inctrls;		/* input control packets */
	kstat_named_t	lks_inctrl_drops;	/* input control pkt drops */
} tll_kstats_t;

#define	TLL_KSTATS_NAMES \
	"octrls", "octrl_drop", "clients", "walks", "in_nomatch", \
	"indata", "indata_drops", "inctrls", "inctrl_drops"

typedef struct {
	kstat_named_t	cks_octrls;		/* sent control messages */
	kstat_named_t	cks_octrl_drop;		/* dropped control messages */
	kstat_named_t	cks_octrl_spec;		/* special control messages */
	kstat_named_t	cks_walks;		/* PPPoE tcl walks */
	kstat_named_t	cks_inctrls;		/* input control messages */
	kstat_named_t	cks_inctrl_drops;	/* input control pkt drops */
} tcl_kstats_t;

#define	TCL_KSTATS_NAMES \
	"octrls", "octrl_drop", "octrl_spec", "walks", "inctrls", \
	"inctrl_drops"

/*
 * Tunnel lower layer structure; module open; connects to output device.
 *
 * Note: tll_flags member carefully aligned to match with tcl_flags in
 * following structure so that we don't have to continually look at
 * q_next to determine context.  Do not move these around.
 *
 * Note: this is also defined in uts/adb/common/tunll.dbg; if you change
 * this structure, don't forget to change the adb/mdb macro.
 */
struct tunll_s {
	uint32_t tll_flags;		/* See TLLF_* below */
	void *tll_next, *tll_prev;

	int tll_error;
	queue_t *tll_wq;		/* Output data sent here */
	tuncl_t *tll_defcl;		/* Default client (daemon) */
	ppptun_atype tll_lcladdr;	/* Local address */

	tuncl_t *tll_lastcl;		/* Silly PPPoE optimization */

	ppptun_lname tll_name;
	int tll_index;
	int tll_muxid;
	int tll_style;			/* Interface type; PTS_* */
	int tll_alen;			/* Address length */

	int tll_msg_pending;
	mblk_t *tll_msg_deferred;

	mblk_t *tll_onclose;

	tll_kstats_t tll_kstats;	/* current statistics */
	kstat_t *tll_ksp;		/* pointer to kstats allocation */
};

/*
 * Tunnel client structure; used for each device open.
 *
 * There is one of these for each PPP session plus (perhaps) one for
 * each tunneling protocol server daemon.
 *
 * Note: this is also defined in uts/adb/common/tuncl.dbg; if you change
 * this structure, don't forget to change the adb/mdb macro.
 */
struct tuncl_s {
	uint32_t tcl_flags;		/* TCLF_ flags below */

	tunll_t *tcl_data_tll;		/* Pointer to data interface */
	tunll_t *tcl_ctrl_tll;		/* Pointer to control */

	queue_t *tcl_rq;		/* Received data sent here. */

	uint32_t tcl_seq;

	uint32_t tcl_ctlval;		/* Control distinguisher */

	uint_t	tcl_style;		/* Saved style */
	uint_t	tcl_ltunid;		/* Local Tunnel ID (L2F/L2TP) */
	uint_t	tcl_rtunid;		/* Remote Tunnel ID (L2F/L2TP) */
	uint_t	tcl_lsessid;		/* Local Session ID (minor node) */
	uint_t	tcl_rsessid;		/* Remote Session ID */
	ppptun_atype	tcl_address;

	int	tcl_unit;		/* PPP unit number (for debug) */
	struct pppstat64 tcl_stats;	/* Standard PPP statistics */
	tcl_kstats_t tcl_kstats;	/* current statistics */
	kstat_t *tcl_ksp;		/* pointer to kstats allocation */
};

#define	TO_TLL(p) \
	((tunll_t *)((caddr_t)(p) - offsetof(tunll_t, tll_next)))

#define	TLLF_NOTLOWER		0x00000001	/* never set */
#define	TLLF_CLOSING		0x00000002	/* driver detach initiated */
#define	TLLF_CLOSE_DONE		0x00000004	/* detach sent; waiting */
#define	TLLF_SHUTDOWN_DONE	0x00000008	/* detach done */

#define	TCLF_ISCLIENT		0x00000001	/* always set */
#define	TCLF_FASTPATH		0x00000004	/* enable fast path recv */
#define	TCLF_DAEMON		0x00000010	/* server side; session 0 */
#define	TCLF_SPEER_DONE		0x00000020	/* SPEER ioctl done */

#ifdef	__cplusplus
}
#endif

#endif /* _SPPPTUN_IMPL_H */
