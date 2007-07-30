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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * DLPI driver for RSMPI
 *
 * Based on scid.c 1.39 98/10/28 - from the SCI group/Sun Cluster code base.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/dlpi.h>
#include <sys/modctl.h>
#include <sys/kstat.h>
#include <sys/note.h>
#include <sys/disp.h>
#include <sys/callb.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>

#include <sys/rsm/rsm_common.h>
#include <sys/rsm/rsmpi.h>


#include <sys/tnf_probe.h>

#ifdef DEBUG
#define	DEBUG_WRSMD 1
#define	DEBUG_PRINTF 1
#define	DEBUG_LOG 1
#endif


#include <sys/wrsmd.h>			/* This driver's data structures */
#define	WRSM_NAME "wrsm"

/*
 * Lock hierarchy:
 *
 * ssp->ss_lock
 * wrsmdp->wrsmd_lock
 * wrsmddevlock
 *
 *	rd->rd_lock
 *	rd->rd_xmit_lock
 *	rd->rd_net_lock
 *
 *	wrsmd->wrsmd_dest_lock
 *	wrsmd->wrsmd_runq_lock
 *
 * wrsmdp->wrsmd_ipq_rwlock
 * wrsmdp->event_lock;
 * wrsmdstruplock
 * rd->rd_nlb_lock -- currently never taken while another lock is held
 * wrsmdattlock
 * wrsmddbglock
 */


/*
 * Defining DEBUG_WRSMD on the compile line (-DDEBUG_WRSMD) will compile
 * debugging code into the driver.  Whether any debug output actually gets
 * printed depends on the value of wrsmddbg, which determines the class of
 * messages that the user is interested in, and wrsmddbgmode, which
 * determines how the user wants the messages to be produced.
 *
 * See the #defines for D1(), D2(), etc.  below for which bits in wrsmddbg
 * cause which messages to get printed.
 *
 * There are two ways debug output may be produced.  The code to produce
 * these various types is also conditionally compiled, using the following
 * symbols:
 *
 * DEBUG_LOG		If this is defined, support for an internal circular
 * 			buffer of log entries is compiled in. The buffer may
 *			be dumped out by using the wrsmddumplog utility.
 *			This is currently the preferred trace method.
 *
 * DEBUG_PRINTF		If this is defined, support for kernel debug printfs
 *			is compiled in.  In many cases, this is not very
 *			useful since the sheer volume of tracing information
 *			overwhelms the console driver.  In particular, if a
 *			problem causes a panic, you will very often not see
 *			the last few debugging messages produced before the
 *			panic, which are probably the ones you really wanted
 *			to see.
 *
 * The various types of output are controlled by bits in wrsmddbgmode, as
 * follows.  Multiple types of output may be used at once, if desired.
 *
 * (wrsmddbgmode & 1)	Use debugging log.
 * (wrsmddbgmode & 2)	Use kernel printfs.
 */

#ifndef lint

#ifdef DEBUG_WRSMD

int wrsmddbg = 0x100;
int wrsmddbgmode = 0x3;
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmddbg))

/* Always print -- at least for now */
#define	D0	wrsmddebug


/* wrsmd function enter/exit, parameters, return values. */
#define	D1								\
	_NOTE(CONSTCOND)						\
	if (wrsmddbg & 0x01)						\
	    wrsmddebug

/* Additional function debugging. */
#define	D2								\
	_NOTE(CONSTCOND)						\
	if (wrsmddbg & 0x02) 						\
	    wrsmddebug

/* rsmpi interface routine enter/exit, parameters, return */
#define	D4								\
	_NOTE(CONSTCOND)						\
	if (wrsmddbg & 0x08) 						\
	    wrsmddebug

/* Latency timing output. */
#define	D5								\
	_NOTE(CONSTCOND)						\
	if (wrsmddbg & 0x10) 						\
	    wrsmddebug

/* Excessive debugging output */
#define	D6								\
	_NOTE(CONSTCOND)						\
	if (wrsmddbg & 0x20) 						\
	    wrsmddebug

/* outgoing packet tossed due to queue overflow */
#define	DERR								\
	_NOTE(CONSTCOND)						\
	if (wrsmddbg & 0x100) 						\
	    wrsmddebug

/* Dumps of incoming packets */
#define	D3D								\
	_NOTE(CONSTCOND)						\
	if (wrsmddbg & 0x04) wrsmdump

#else /* DEBUG_WRSMD */

#define	D0	if (0) printf
#define	D1	if (0) printf
#define	D2	if (0) printf
#define	D4	if (0) printf
#define	D5	if (0) printf
#define	D6	if (0) printf
#define	DERR	if (0) printf
#define	D3D(a, b)

#endif /* DEBUG_WRSMD */

#else /* lint */

#ifdef DEBUG_WRSMD
int wrsmddbg;
int wrsmddbgmode;
#endif

#define	D0	printf
#define	D1	printf
#define	D2	printf
#define	D4	printf
#define	D5	printf
#define	D6	printf
#define	DERR	printf
#define	D3D	wrsmdump
#endif /* lint */



/*
 * Function prototypes.
 */

static int	wrsmdprobe(dev_info_t *);
static int	wrsmdattach(dev_info_t *, ddi_attach_cmd_t);
static int	wrsmddetach(dev_info_t *, ddi_detach_cmd_t);
static int	wrsmdopen(queue_t *, dev_t *, int, int, cred_t *);
static int	wrsmdclose(queue_t *, int, cred_t *);
static int	wrsmdwput(queue_t *, mblk_t *);
static int	wrsmdwsrv(queue_t *);
static void	wrsmddumpqueue(wrsmd_t *, wrsmd_dest_t *);
static int	wrsmdcrexfer(wrsmd_t *, wrsmd_dest_t *);
static int	wrsmdsconn(wrsmd_t *, wrsmd_dest_t *, int);
static int	wrsmdconnxfer(wrsmd_t *, wrsmd_dest_t *);
static int	wrsmdsack(wrsmd_t *, wrsmd_dest_t *);
static int	wrsmdsaccept(wrsmd_t *wrsmdp, wrsmd_dest_t *rd);
static void	wrsmdproto(queue_t *, mblk_t *);
static void	wrsmdioctl(queue_t *, mblk_t *);
static int	wrsmdioctlimmediate(queue_t *, mblk_t *);
static void	wrsmd_dl_ioc_hdr_info(queue_t *, mblk_t *);
static void	wrsmdareq(queue_t *, mblk_t *);
static void	wrsmddreq(queue_t *, mblk_t *);
static void	wrsmddodetach(wrsmdstr_t *);
static void	wrsmdbreq(queue_t *, mblk_t *);
static void	wrsmdubreq(queue_t *, mblk_t *);
static void	wrsmdireq(queue_t *, mblk_t *);
static void	wrsmdponreq(queue_t *, mblk_t *);
static void	wrsmdpoffreq(queue_t *, mblk_t *);
static void	wrsmdpareq(queue_t *, mblk_t *);
static void	wrsmdudreq(queue_t *, mblk_t *);
static mblk_t	*wrsmdstrip(mblk_t *, dl_rsm_addr_t *, ushort_t *);
static void	wrsmdstart(wrsmd_t *, mblk_t *, dl_rsm_addr_t, ushort_t, int);
static wrsmd_dest_t *wrsmdmkdest(wrsmd_t *, rsm_addr_t);
static void	wrsmdsetupfqewait(wrsmd_t *, wrsmd_dest_t *);
static void	wrsmdxfer(wrsmd_t *, wrsmd_dest_t *);
static void	wrsmdfqetmo(void *);
static void	wrsmdsconntmo(void *);
static void	wrsmdacktmo(void *);
static void	wrsmdaccepttmo(void * arg);
static void	wrsmdfreedestevt(void *);
static void	wrsmdteardown_tmo(void * arg);

static void	wrsmd_event_thread(void *);
static void	wrsmd_process_event(wrsmd_t *);
static void	wrsmd_add_event(wrsmd_t *, int, void *);

static void	wrsmdmsghdlr_req_connect(wrsmd_dest_t *, wrsmd_msg_t *);
static void	wrsmdmsghdlr_con_accept(wrsmd_dest_t *, wrsmd_msg_t *);
static void	wrsmdmsghdlr_syncdqe(wrsmd_dest_t *, wrsmd_msg_t *);
static void 	wrsmdmsghdlr_syncdqe_evt(wrsmd_dest_t *rd);
static void	wrsmdmsghdlr_default(wrsmd_dest_t *, wrsmd_msg_t *);

static int	wrsmdisstate(wrsmd_dest_t *, int);
static int	wrsmdgetstate(wrsmd_dest_t *);
static void	wrsmdsetstate(wrsmd_dest_t *, int);
static void	wrsmdsetstate_nosrv(wrsmd_dest_t *, int);
static int	wrsmdmovestate(wrsmd_dest_t *, int, int newstate);
static int	wrsmdread(wrsmd_dest_t *, int, int, int, ushort_t sap);
static void	wrsmdsendup(wrsmd_t *, mblk_t *, dl_rsm_addr_t, dl_rsm_addr_t,
    ushort_t);
static void	wrsmdpromsendup(wrsmd_t *, mblk_t *, dl_rsm_addr_t,
    dl_rsm_addr_t, ushort_t);
static mblk_t	*wrsmdaddudind(wrsmd_t *, mblk_t *, dl_rsm_addr_t,
    dl_rsm_addr_t, ushort_t);
static mblk_t	*wrsmdaddhdr(wrsmd_t *, mblk_t *, dl_rsm_addr_t, dl_rsm_addr_t,
    ushort_t);
static int	wrsmdinit(wrsmd_t *);
static int	wrsmduninit(wrsmd_t *wrsmdp);
static boolean_t	wrsmddest_refcnt_0(wrsmd_dest_t *);
static void	wrsmdfreedest(wrsmd_t *, rsm_addr_t);

/* LINTED: E_STATIC_FUNC_CALLD_NOT_DEFINED */
static void	wrsmddebug(const char *, ...);
static void	wrsmderror(dev_info_t *,  const char *, ...);
static void	wrsmdkstatinit(wrsmd_t *);
static void	wrsmdkstatremove(wrsmd_t *wrsmdp);
static void	wrsmdgetparam(dev_info_t *, wrsmd_t *);
static void	wrsmdtakedown(wrsmd_t *, int);
static void	wrsmdsetipq(wrsmd_t *);

static void	wrsmdfreebuf(wrsmdbuf_t *);
static void	wrsmdputfqe(wrsmd_dest_t *, int);
static void	wrsmdsyncfqe(wrsmd_dest_t *);
static void	wrsmdputdqe(wrsmd_dest_t *, int, int, uint_t, ushort_t sap);
static void	wrsmdsyncdqe(wrsmd_dest_t *);
static int	wrsmdavailfqe(wrsmd_dest_t *);
static int	wrsmdgetfqe(wrsmd_dest_t *, int *);
static void	wrsmdungetfqe(wrsmd_dest_t *, int);
static int	wrsmdgetdqe(wrsmd_dest_t *, int *, int *, int *, ushort_t *);
static int	wrsmdsendmsg(wrsmd_dest_t *, uint8_t, wrsmd_msg_t *);
/* LINTED: E_STATIC_FUNC_CALLD_NOT_DEFINED */
static void	wrsmdump(uchar_t *, int);

static rsm_intr_hand_ret_t wrsmd_rsm_intr_handler(rsm_controller_object_t *,
    rsm_intr_q_op_t, rsm_addr_t, void *, size_t, rsm_intr_hand_arg_t);


#ifdef	_DDICT
#define	ENOSR	63	/* out of streams resources		*/
#endif


/*
 * The wrsmd driver implements a reference count scheme for destination
 * structures.  The idea behind the scheme is to prevent the driver from
 * deleting a destination structure while it is being used elsewhere, for
 * example in a message handling routine.  (Failures to protect against
 * this occurrence have led to a fair array of baffling bugs over the
 * lifetime of the driver.)
 *
 * The following set of macros implement the reference count scheme,
 * translation from RSM address to destination structure, and removal of
 * destinations from the run queue.  All must be intertwined, since
 * otherwise it would be possible to get a destination pointer from an RSM
 * address , or from the run queue, but have some other part of the driver
 * delete the destination before you could bump its reference count.  The
 * incorporation of reference count code in FINDDEST/MAKEDEST/GETRUNQ
 * solves this race condition.
 */

/*
 * FINDDEST attempts to find the destination with RSM address rsm_addr.  If the
 * destination exists, rd is set to point to it.  If the destination exists,
 * isdel is set to indicate whether the destination is currently being deleted
 * (nonzero implies a delete is in progress).  If the destination exists and
 * is not being deleted, its reference count is increased by one.
 */
#define	FINDDEST(rd, isdel, wrsmd, rsm_addr) {				\
	mutex_enter(&wrsmd->wrsmd_dest_lock);			\
	(rd) = (((rsm_addr) >= RSM_MAX_DESTADDR) ? NULL :		\
	    (wrsmd)->wrsmd_desttbl[(rsm_addr)]);			\
	if (rd)							\
		if (((isdel) = (rd)->rd_dstate) == 0) {		\
			(rd)->rd_refcnt++;			\
			D6("FINDDEST ctlr %d addr %ld refcnt++ is %d\n", \
			    wrsmd->wrsmd_ctlr_id, rsm_addr,	\
			    (rd)->rd_refcnt);			\
		}						\
	mutex_exit(&(wrsmd)->wrsmd_dest_lock);			\
	_NOTE(CONSTCOND);					\
}


/*
 * MAKEDEST attempts to find the destination with RSM address rsm_addr.  If the
 * destination exists, rd and isdel are set as in the description of FINDDEST,
 * above.  If the destination does not exist, a new destination structure is
 * allocated and installed, rd is set to point to it, and isnew is set to 1.
 */
#define	MAKEDEST(rd, isdel, isnew, wrsmd, rsm_addr) {		\
	mutex_enter(&(wrsmd)->wrsmd_dest_lock);			\
	(rd) = ((wrsmd)->wrsmd_desttbl[(rsm_addr)]);		\
	if (!(rd)) {						\
		(rd) = wrsmdmkdest((wrsmd), (rsm_addr));	\
		(isnew) = 1;					\
	}							\
	if (rd)							\
		if (((isdel) = (rd)->rd_dstate) == 0) {		\
			(rd)->rd_refcnt++;			\
			D6("MAKEDEST ctlr %d addr %ld refcnt++ is %d\n", \
			    wrsmd->wrsmd_ctlr_id, (uint64_t)rsm_addr,	\
			    (rd)->rd_refcnt);			\
		}						\
	mutex_exit(&(wrsmd)->wrsmd_dest_lock);			\
	_NOTE(CONSTCOND);					\
}


/*
 * GETRUNQ attempts to return the destination which is at the head of wrsmd's
 * run queue.  If the run queue is non-empty, the head of the queue is removed,
 * and rd is set to point to it; otherwise, rd is set to NULL.  If rd is
 * nonzero, isdel is set to 1 if the destination pointed to by rd is being
 * deleted, or to 0 otherwise.  Finally, if rd is nonzero, and isdel is zero,
 * then rd's reference count is increased by one.
 */
#define	GETRUNQ(rd, isdel, wrsmd) {				\
	mutex_enter(&(wrsmd)->wrsmd_dest_lock);			\
	mutex_enter(&(wrsmd)->wrsmd_runq_lock);			\
	rd = (wrsmd)->wrsmd_runq;				\
	if (rd) {						\
		(wrsmd)->wrsmd_runq = rd->rd_next;		\
		if (((isdel) = (rd)->rd_dstate) == 0) {		\
			(rd)->rd_refcnt++;			\
			D6("GETRUNQ ctlr %d addr %ld refcnt++ is %d\n", \
			    wrsmd->wrsmd_ctlr_id,		\
			    (rd)->rd_rsm_addr,			\
			    (rd)->rd_refcnt);			\
		}						\
	}							\
	mutex_exit(&(wrsmd)->wrsmd_runq_lock);			\
	mutex_exit(&(wrsmd)->wrsmd_dest_lock);			\
	_NOTE(CONSTCOND);					\
}


/*
 * REFDEST checks to see if the destination pointed to by rd is currently being
 * deleted.  If so, isdel is set to a nonzero value; otherwise, it is set to
 * zero, and the destination's reference count is incremented.
 */
#define	REFDEST(rd, isdel) {					\
	mutex_enter(&(rd)->rd_wrsmdp->wrsmd_dest_lock);		\
	if (((isdel) = (rd)->rd_dstate) == 0) {			\
		(rd)->rd_refcnt++;				\
		D6("REFDEST ctlr %d addr %ld refcnt++ is %d\n",	\
		    wrsmd->wrsmd_ctlr_id, rsm_addr,		\
		    (rd)->rd_refcnt);				\
	}							\
	mutex_exit(&(rd)->rd_wrsmdp->wrsmd_dest_lock);		\
	_NOTE(CONSTCOND);					\
}


/*
 * UNREFDEST decrements the reference count of the destination pointed to by
 * rd.  If the reference count becomes zero, we start the deletion process for
 * the destination.
 */
#define	UNREFDEST(rd) {						\
	mutex_enter(&(rd)->rd_wrsmdp->wrsmd_dest_lock);		\
	D6("UNREFDEST ctlr %d addr %ld refcnt-- is %d\n",	\
	    (rd)->rd_wrsmdp->wrsmd_ctlr_id, (rd)->rd_rsm_addr,	\
	    (rd)->rd_refcnt - 1);				\
	if (--(rd)->rd_refcnt <= 0) {				\
		mutex_exit(&(rd)->rd_wrsmdp->wrsmd_dest_lock);	\
		if (wrsmddest_refcnt_0(rd)) { rd = NULL; }	\
	} else							\
		mutex_exit(&(rd)->rd_wrsmdp->wrsmd_dest_lock);	\
	_NOTE(CONSTCOND);					\
}



/* Local Static def's */

/*
 * Lock and variable to allow attach routines to initialize global mutexes
 */

static kmutex_t wrsmdattlock;	/* Protects wrsmddbginit  */

/*
 * Linked list of "wrsmd" structures - one per physical device.
 */
static wrsmd_t *wrsmddev = NULL;	/* Head of list */
static kmutex_t wrsmddevlock;	/* Protects list contents */
static uint_t wrsmdminbuflen = 0; /* Smallest buf length we've seen; updated */
				/*  when we add a device to the list */
_NOTE(MUTEX_PROTECTS_DATA(wrsmddevlock,
    wrsmddev wrsmdminbuflen wrsmd::wrsmd_nextp))

/*
 * Linked list of active (inuse) driver Streams.
 */
static wrsmdstr_t *wrsmdstrup = NULL;	/* Head of list */
static krwlock_t wrsmdstruplock;		/* Protects list of streams */
_NOTE(RWLOCK_PROTECTS_DATA(wrsmdstruplock, wrsmdstrup wrsmdstr::ss_nextp))

/*
 * Our DL_INFO_ACK template.
 */
static dl_info_ack_t wrsmdinfoack = {
	DL_INFO_ACK,			/* dl_primitive */
	MEDIUM_MTU,			/* dl_max_sdu */
	0,				/* dl_min_sdu */
	WRSMD_DEVICE_ADDRL,		/* dl_addr_length */
	DL_ETHER,			/* dl_mac_type */
	0,				/* dl_reserved */
	0,				/* dl_current_state */
	-2,				/* dl_sap_length  - 2 bytes (short), */
					/* second component in DLSAP address */
	DL_CLDLS,			/* dl_service_mode */
	0,				/* dl_qos_length */
	0,				/* dl_qos_offset */
	0,				/* dl_range_length */
	0,				/* dl_range_offset */
	DL_STYLE2,			/* dl_provider_style */
	sizeof (dl_info_ack_t),		/* dl_addr_offset */
	DL_VERSION_2,			/* dl_version */
	WRSMD_BCAST_ADDRL,		/* dl_brdcst_addr_length */
	sizeof (dl_info_ack_t) + WRSMD_DEVICE_ADDRL, /* dl_brdcst_addr_offset */
	0				/* dl_growth */
};

/*
 * use standard ethernet broadcast address - all 1's
 */
static	struct ether_addr wrsmdbcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static	struct ether_addr wrsmdbadaddr = {
	0xB, 0xAD, 0xB, 0xAD, 0xB, 0xAD
};


_NOTE(READ_ONLY_DATA(wrsmdinfoack))
_NOTE(READ_ONLY_DATA(wrsmdbcastaddr))

static void *wrsmd_state;	/* opaque handle for soft state structs */


/*
 * ****************************************************************
 *                                                               *
 * B E G I N   BASIC MODULE BOILERPLATE                          *
 *                                                               *
 * ****************************************************************
 */

/* Standard Streams declarations */

static struct module_info wrsmdminfo = {
	WRSMDIDNUM,	/* mi_idnum */
	WRSMDNAME,	/* mi_idname */
	WRSMDMINPSZ,	/* mi_minpsz */
	WRSMDMAXPSZ,	/* mi_minpsz */
	WRSMDHIWAT,	/* mi_hiwat */
	WRSMDLOWAT,	/* mi_lowat */
};

static struct qinit wrsmdrinit = {
	0,		/* qi_putp */
	0,		/* qi_srvp */
	wrsmdopen,	/* qi_qopen */
	wrsmdclose,	/* qi_qclose */
	0,		/* qi_qadmin */
	&wrsmdminfo,	/* qi_minfo */
	NULL,		/* qi_mstat */
};

static struct qinit wrsmdwinit = {
	wrsmdwput,	/* qi_putp */
	wrsmdwsrv,	/* qi_srvp */
	0,		/* qi_qopen */
	0,		/* qi_qclose */
	0,		/* qi_qadmin */
	&wrsmdminfo,	/* qi_minfo */
	NULL,		/* qi_mstat */
};

static struct streamtab wrsmd_info = {
	&wrsmdrinit,	/* st_rdinit */
	&wrsmdwinit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL,		/* st_muxwrinit */
};


/* Module Loading/Unloading and Autoconfiguration declarations */

/*
 * cb_ops contains the driver entry points and is roughly equivalent
 * to the cdevsw and bdevsw  structures in previous releases.
 *
 * dev_ops contains, in addition to the pointer to cb_ops, the routines
 * that support loading and unloading our driver.
 *
 * Unsupported entry points are set to nodev, except for the poll
 * routine , which is set to nochpoll(), a routine that returns ENXIO.
 */

static struct cb_ops wrsmd_cb_ops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&wrsmd_info,		/* cb_stream */
	D_MP,			/* cb_flag */
};

static struct dev_ops wrsmd_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	ddi_no_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	wrsmdprobe,		/* devo_probe */
	wrsmdattach,		/* devo_attach */
	wrsmddetach,		/* devo_detach */
	nodev,			/* devo_reset */
	&wrsmd_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL	/* devo_bus_ops */
};


/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,		 /* Type of module.  This one is a driver */
	"RSMPI DLPI %I% %E%",	/* Description */
	&wrsmd_ops,		 /* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/*
 * Module Loading and Installation Routines.
 */

/*
 * Module Installation
 * Install the driver, initialize soft state system, initialize wrsmdattlock
 */

int
_init(void)
{
	int status;

	_NOTE(COMPETING_THREADS_NOW)
	_NOTE(NO_COMPETING_THREADS_NOW)
	status = ddi_soft_state_init(&wrsmd_state, sizeof (wrsmd_t), 1);
	if (status != 0) {
		_NOTE(CONSTCOND)
		D1("wrsmd:_init - soft_state_init failed: 0x%x\n", status);
		cmn_err(CE_CONT,
		    "wrsmd:_init - soft_state_init failed: 0x%x\n", status);
		return (status);
	}

	/* initialize global locks here */

	mutex_init(&wrsmdattlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&wrsmddevlock, NULL, MUTEX_DRIVER, NULL);
	rw_init(&wrsmdstruplock, NULL, RW_DRIVER, NULL);

	status = mod_install(&modlinkage);
	if (status != DDI_SUCCESS) {
		mutex_destroy(&wrsmdattlock);
		mutex_destroy(&wrsmddevlock);
		rw_destroy(&wrsmdstruplock);
	}
	return (status);
}

/*
 * Module Removal
 */

int
_fini(void)
{
	int status;

	/* LINTED possibly invalid annotation name */
	_NOTE(COMPETING_THREADS_NOW)
	_NOTE(NO_COMPETING_THREADS_NOW)

	if ((status = mod_remove(&modlinkage)) != 0) {
		D1("wrsmd_fini - mod_remove failed: 0x%x\n", status);
		return (status);
	}

	ddi_soft_state_fini(&wrsmd_state);

	mutex_destroy(&wrsmdattlock);
	mutex_destroy(&wrsmddevlock);
	rw_destroy(&wrsmdstruplock);

	return (status);
}

/*
 * Return Module Info.
 */

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}



/*
 * Autoconfiguration Routines
 */


/*
 * Probe to see if device exists.
 */
static int
wrsmdprobe(dev_info_t *dip)
{
	int inst = ddi_get_instance(dip);

	D1("wrsmdprobe: dip 0x%p, inst %d", (void *)dip, inst);

	return (DDI_PROBE_SUCCESS);
}

/*
 * Attach the device, create and fill in the device-specific structure.
 */

static int
wrsmdattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	wrsmd_t *wrsmdp;
	int instance;
	int progress = 0;

	D1("wrsmdattach: dip 0x%p, cmd %d", (void *)dip, cmd);
	TNF_PROBE_2(wrsmdattach_start, "RSMPI", "wrsmdattach start",
	    tnf_long, dip, (tnf_long_t)dip, tnf_long, command, cmd);

	if (cmd != DDI_ATTACH) {
		TNF_PROBE_2(wrsmdattach_end, "RSMPI",
		    "wrsmdattach end; failure 'cmd != DDI_ATTACH'",
		    tnf_string, failure, "cmd != DDI_ATTACH",
		    tnf_long, cmd, DDI_FAILURE);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate soft data structure
	 */

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(wrsmd_state, instance) != DDI_SUCCESS) {
		D1("wrsmdattach: bad state zalloc, returning DDI_FAILURE");
		TNF_PROBE_2(wrsmdattach_end, "RSMPI",
		    "wrsmdattach end; failure 'ddi_soft_state_zalloc'",
		    tnf_string, failure, "ddi_soft_state_zalloc",
		    tnf_long, rval, DDI_FAILURE);
		return (DDI_FAILURE);
	}

	wrsmdp = ddi_get_soft_state(wrsmd_state, instance);
	if (wrsmdp == NULL) {
		TNF_PROBE_2(wrsmdattach_end, "RSMPI",
		    "wrsmdattach end; failure get_soft_state",
		    tnf_string, failure, "get_soft_state",
		    tnf_long, cmd, DDI_FAILURE);
		return (DDI_FAILURE);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wrsmdp))

	/*
	 * Stuff private info into dip.
	 */
	rw_init(&wrsmdp->wrsmd_ipq_rwlock, NULL, RW_DRIVER, NULL);
	wrsmdp->wrsmd_dip = dip;
	ddi_set_driver_private(dip, wrsmdp);
	wrsmdp->wrsmd_ctlr_id = instance;

	/*
	 * Get device parameters from the device tree and save them in our
	 * per-device structure for later use.
	 */
	wrsmdgetparam(dip, wrsmdp);


	/*
	 * Initialize mutexes for this device.
	 */
	mutex_init(&wrsmdp->wrsmd_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&wrsmdp->wrsmd_dest_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&wrsmdp->wrsmd_runq_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&wrsmdp->event_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&wrsmdp->event_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&wrsmdp->event_thread_exit_cv, NULL, CV_DEFAULT, NULL);
	progress |= WRSMD_ATT_MUTEX;

	/*
	 * Initialize kernel statistics.
	 */
	wrsmdkstatinit(wrsmdp);
	progress |= WRSMD_ATT_KSTAT;

	/*
	 * Create the filesystem device node.
	 */
	if (ddi_create_minor_node(dip, "wrsmd", S_IFCHR,
	    ddi_get_instance(dip),
	    DDI_PSEUDO, CLONE_DEV) != DDI_SUCCESS) {
		D1("wrsmdattach: bad create_minor_node, returning "
		    "DDI_FAILURE");
		wrsmdtakedown(wrsmdp, progress);
		TNF_PROBE_2(wrsmdattach_end, "RSMPI",
		    "wrsmdattach end; failure 'ddi_create_minor_node'",
		    tnf_string, failure, "ddi_create_minor_node",
		    tnf_long, rval, DDI_FAILURE);
		return (DDI_FAILURE);
	}
	progress |= WRSMD_ATT_MINOR;

	/*
	 * Link this per-device structure in with the rest.
	 */
	mutex_enter(&wrsmddevlock);
	wrsmdp->wrsmd_nextp = wrsmddev;

	/*
	 * Update our idea of the smallest buffer size seen so far.  We do this
	 * because many clients do a get_info request before they've attached
	 * to a particular piece of hardware (ie, PPA).  We need to have
	 * something to give them for the MTU, and giving them a value that's
	 * bigger than the one used by the device they eventually attach to
	 * causes problems.
	 */
	if (wrsmddev == NULL)
		wrsmdminbuflen = wrsmdp->wrsmd_param.wrsmd_buffer_size;
	else if (wrsmdminbuflen > wrsmdp->wrsmd_param.wrsmd_buffer_size)
		wrsmdminbuflen = wrsmdp->wrsmd_param.wrsmd_buffer_size;

	wrsmddev = wrsmdp;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*wrsmdp))
	mutex_exit(&wrsmddevlock);
	progress |= WRSMD_ATT_LINKED;

	/*
	 * Start up event thread for this wrsmd device.
	 * This seems like as good a place as any...
	 */
	wrsmdp->stop_events = B_FALSE;
	wrsmdp->events = (wrsmd_event_t *)NULL;
	wrsmdp->event_thread = thread_create(NULL, 0, wrsmd_event_thread,
	    (void *)wrsmdp, 0, &p0, TS_RUN, maxclsyspri - 1);
	progress |= WRSMD_ATT_EVT_THREAD;

	ddi_report_dev(dip);

	D1("wrsmdattach: returning DDI_SUCCESS");
	TNF_PROBE_2(wrsmdattach_end, "RSMPI", "wrsmdattach end",
	    tnf_string, success, "",
	    tnf_long, rval, DDI_SUCCESS);
	return (DDI_SUCCESS);
}

/*
 * Detach - Free resources allocated in attach
 */

/*ARGSUSED*/
static int
wrsmddetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	wrsmd_t *wrsmdp;
	timeout_id_t tmoid, tmoid_orig;

	D1("wrsmddetach: dip 0x%p, cmd %d", (void *)dip, cmd);
	TNF_PROBE_2(wrsmddetach_start, "RSMPI", "wrsmddetach start",
	    tnf_long, dip, (tnf_long_t)dip, tnf_long, command, cmd);

	if (cmd != DDI_DETACH) {
		TNF_PROBE_1(wrsmddetach_end, "RSMPI",
		    "wrsmddetach end; failure 'cmd != DDI_DETACH'",
		    tnf_long, rval, DDI_FAILURE);
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	wrsmdp = ddi_get_soft_state(wrsmd_state, instance);
	if (wrsmdp == NULL) {
		TNF_PROBE_2(wrsmddetach_end, "RSMPI",
		    "wrsmddetach end; failure get_soft_state",
		    tnf_string, failure, "get_soft_state",
		    tnf_long, cmd, DDI_FAILURE);
		return (DDI_FAILURE);
	}


	mutex_enter(&wrsmdp->wrsmd_lock);

	/*
	 * The teardown timeout now reschedules itself, so we
	 * have to go to great lengths to kill it.
	 */
	tmoid_orig = tmoid = wrsmdp->wrsmd_teardown_tmo_id;

	while (tmoid) {
		/*
		 * A timeout is scheduled to teardown the
		 * device.  Cancel, as we intend to do this now.
		 */
		mutex_exit(&wrsmdp->wrsmd_lock);

		(void) untimeout(tmoid);
		/*
		 * untimeout guarantees the either the function was
		 * cancelled, or it has completed.  If timeout was
		 * cancelled before the function ran, the timout id will
		 * not have changed.
		 */
		mutex_enter(&wrsmdp->wrsmd_lock);

		if (tmoid == wrsmdp->wrsmd_teardown_tmo_id)
			wrsmdp->wrsmd_teardown_tmo_id = 0;
		tmoid = wrsmdp->wrsmd_teardown_tmo_id;
	}

	/*
	 * If we can't release all destination and RSMPI resources, we can't
	 * detach.  The user will have to try later to unload the driver.
	 */
	mutex_exit(&wrsmdp->wrsmd_lock);
	if (wrsmduninit(wrsmdp) != 0) {
		TNF_PROBE_1(wrsmddetach_end, "RSMPI",
		    "wrsmddettach end; failure 'wrsmduninit'",
		    tnf_long, rval, DDI_FAILURE);
		if (tmoid_orig) {
			/* restart cancelled timeout */
			mutex_enter(&wrsmdp->wrsmd_lock);
			wrsmdp->wrsmd_teardown_tmo_id =
			    timeout(wrsmdteardown_tmo,
			    (caddr_t)wrsmdp,
			    wrsmdp->wrsmd_param.wrsmd_teardown_tmo);
			mutex_exit(&wrsmdp->wrsmd_lock);
		}
		return (DDI_FAILURE);
	}

	/*
	 * Release all our resources. At this point, all attachment
	 * setup must have completed, so must all be torn down.
	 */
	wrsmdtakedown(wrsmdp, WRSMD_ATT_ALL);

	TNF_PROBE_0(wrsmddetach_end, "RSMPI", "wrsmddettach end");
	return (DDI_SUCCESS);
}

/*
 * Undo tasks done by wrsmdattach(), either because we're detaching or because
 * attach() got partly done then failed.  progress is a bitmap that tells
 * us what has been done so far.
 */
static void
wrsmdtakedown(
	wrsmd_t *wrsmdp,	/* WRSMD device (RSM controller) pointer */
	int progress)	/* Mask of RSMPI_ATT_xxx values */
{
	int instance;
	dev_info_t *dip;

	D1("wrsmdtakedown: wrsmdp 0x%p (ctlr %d), progress 0x%x",
	    (void *)wrsmdp, wrsmdp->wrsmd_ctlr_id, progress);
	TNF_PROBE_2(wrsmdtakedown_start, "RSMPI", "wrsmdtakedown start",
	    tnf_long, wrsmdp, (tnf_long_t)wrsmdp, tnf_long, progress, progress);

	ASSERT(wrsmdp);

	if (progress & WRSMD_ATT_EVT_THREAD) {
		mutex_enter(&wrsmdp->event_lock);
		wrsmdp->stop_events = B_TRUE;
		cv_broadcast(&wrsmdp->event_cv);
		cv_wait(&wrsmdp->event_thread_exit_cv, &wrsmdp->event_lock);
		wrsmdp->event_thread = (kthread_t *)NULL;
		mutex_exit(&wrsmdp->event_lock);

		progress &= ~WRSMD_ATT_EVT_THREAD;
	}

	if (progress & WRSMD_ATT_LINKED) {
		mutex_enter(&wrsmddevlock);

		if (wrsmddev == wrsmdp)
			wrsmddev = wrsmdp->wrsmd_nextp;
		else {
			wrsmd_t *ptr;

			for (ptr = wrsmddev; ptr->wrsmd_nextp; ptr =
			    ptr->wrsmd_nextp)
				if (ptr->wrsmd_nextp == wrsmdp) {
					ptr->wrsmd_nextp = wrsmdp->wrsmd_nextp;
					break;
				}
		}
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wrsmdp))
		mutex_exit(&wrsmddevlock);
		progress &= ~WRSMD_ATT_LINKED;
	}

	dip = wrsmdp->wrsmd_dip;
	instance = ddi_get_instance(dip);


	if (progress & WRSMD_ATT_KSTAT) {
		wrsmdkstatremove(wrsmdp);
		progress &= ~WRSMD_ATT_KSTAT;
	}

	if (progress & WRSMD_ATT_MINOR) {
		ddi_remove_minor_node(dip, NULL);
		progress &= ~WRSMD_ATT_MINOR;
	}

	if (progress & WRSMD_ATT_MUTEX) {
		mutex_destroy(&wrsmdp->wrsmd_lock);
		mutex_destroy(&wrsmdp->wrsmd_dest_lock);
		mutex_destroy(&wrsmdp->wrsmd_runq_lock);
		mutex_destroy(&wrsmdp->event_lock);
		cv_destroy(&wrsmdp->event_cv);
		cv_destroy(&wrsmdp->event_thread_exit_cv);
		progress &= ~WRSMD_ATT_MUTEX;
	}

	ASSERT(progress == 0);

	ddi_soft_state_free(wrsmd_state, instance);

	D1("wrsmdtakedown: returning DDI_SUCCESS");
	TNF_PROBE_1(wrsmdtakedown_end, "RSMPI", "wrsmdtakedown end",
	    tnf_long, rval, DDI_SUCCESS);
}

/*
 * Determine the device ipq pointer after a state change.  The device ipq
 * pointer is basically a performance hack; it is set to one of our attached
 * queues if, and only if, (a) that queue is the only one which has bound to
 * IP's SAP, i.e., has expressed interest in getting IP packets; and (b) there
 * is no stream attached to us which has gone into any sort of promiscuous mode,
 * i.e., has expressed interest in getting all packets.  The performance win
 * comes when ipq is set; if it is, we can just send all incoming IP packets
 * to that queue without having to traverse the entire list of queues attached
 * to us.
 */
static void
wrsmdsetipq(wrsmd_t *wrsmdp)	/* WRSMD device (RSM controller) pointer */
{
	struct	wrsmdstr	*ssp;
	queue_t	*ipq = NULL;

	/*
	 * Take ipq writer lock to prevent the fastpath from using the
	 * wrong ipq.  Note:  must take prior to taking struplock.
	 */
	rw_enter(&wrsmdp->wrsmd_ipq_rwlock, RW_WRITER);

	rw_enter(&wrsmdstruplock, RW_READER);

	for (ssp = wrsmdstrup; ssp; ssp = ssp->ss_nextp)
		if (ssp->ss_wrsmdp == wrsmdp) {
			if (ssp->ss_flags & WRSMD_SLALLSAP) {
				ipq = NULL;
				break;
			} else if (ssp->ss_sap == WRSMD_IP_SAP) {
				if ((ssp->ss_flags & WRSMD_SLFAST) == 0) {
					ipq = NULL;
					break;
				} else if (ipq == NULL) {
					ipq = ssp->ss_rq;
				} else {
					ipq = NULL;
					break;
				}
			}
		}

	wrsmdp->wrsmd_ipq = ipq;

	rw_exit(&wrsmdstruplock);
	rw_exit(&wrsmdp->wrsmd_ipq_rwlock);
}

/*
 * Hook a new stream onto the driver.  We create a wrsmdstr structure for the
 * new stream, and, if this is a clone open, allocate an unused minor device
 * number for it.
 */

/*ARGSUSED*/
static int
wrsmdopen(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	wrsmdstr_t *ssp;
	wrsmdstr_t **prevssp;
	minor_t	minordev;
	int rc = 0;

	D1("wrsmdopen: rq 0x%p, *dev 0x%lx, flag %d, sflag %d",
	    (void *)rq, *devp, flag, sflag);
	TNF_PROBE_4(wrsmdopen_start, "RSMPI", "wrsmdopen start",
	    tnf_long, rq, (tnf_long_t)rq, tnf_long, device, (tnf_long_t)devp,
	    tnf_long, flags, flag, tnf_long, sflags, sflag);

	ASSERT(sflag != MODOPEN);

	/*
	 * Serialize all driver open and closes.
	 */
	rw_enter(&wrsmdstruplock, RW_WRITER);

	/*
	 * Determine minor device number.
	 */
	prevssp = &wrsmdstrup;
	if (sflag == CLONEOPEN) {
		minordev = 0;
		for (; ((ssp = *prevssp) != NULL); prevssp = &ssp->ss_nextp) {
			if (minordev < ssp->ss_minor)
				break;
			minordev++;
		}
		*devp = makedevice(getmajor(*devp), minordev);
	} else
		minordev = getminor(*devp);

	if (rq->q_ptr == NULL) {
		ssp = (wrsmdstr_t *)kmem_zalloc(sizeof (wrsmdstr_t), KM_SLEEP);

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ssp))

		ssp->ss_minor = minordev;
		ssp->ss_rq = rq;
		ssp->ss_state = DL_UNATTACHED;
		ssp->ss_sap = 0;
		ssp->ss_flags = 0;
		ssp->ss_wrsmdp = NULL;
		mutex_init(&ssp->ss_lock, NULL, MUTEX_DRIVER, NULL);

		/*
		 * Link new entry into the list of active entries.
		 */
		ssp->ss_nextp = *prevssp;
		*prevssp = ssp;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*ssp))

		rq->q_ptr = WR(rq)->q_ptr = ssp;
	}

	rw_exit(&wrsmdstruplock);
	qprocson(rq);
	D1("wrsmdopen: returning %d", rc);
	TNF_PROBE_1(wrsmdopen_end, "RSMPI", "wrsmdopen end", tnf_long,
	    rval, rc);

	(void) qassociate(rq, -1);
	return (rc);
}

/*
 * Unhook a stream from the driver.  If it was attached to a specific physical
 * device, detach it from the device, then remove it from our list of streams.
 */

/*ARGSUSED*/
static int
wrsmdclose(queue_t *rq, int flag, cred_t *credp)
{
	wrsmdstr_t *ssp;
	wrsmdstr_t **prevssp;

	D1("wrsmdclose: rq 0x%p, flag %d", (void *)rq, flag);
	TNF_PROBE_2(wrsmdclose_start, "RSMPI", "wrsmdclose start",
	    tnf_long, rq, (tnf_long_t)rq, tnf_long, flags, flag);

	ASSERT(rq);

	/* Disable put/service routines */

	qprocsoff(rq);

	ASSERT(rq->q_ptr);

	ssp = (wrsmdstr_t *)rq->q_ptr;

	/* Detach Stream from interface */

	mutex_enter(&ssp->ss_lock);
	if (ssp->ss_wrsmdp)
		wrsmddodetach(ssp);
	mutex_exit(&ssp->ss_lock);

	rw_enter(&wrsmdstruplock, RW_WRITER);

	/* Unlink the per-Stream entry from the active list and free it */

	for (prevssp = &wrsmdstrup; ((ssp = *prevssp) != NULL);
	    prevssp = &ssp->ss_nextp)
		if (ssp == (wrsmdstr_t *)rq->q_ptr)
			break;
	ASSERT(ssp);
	*prevssp = ssp->ss_nextp;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ssp))

	mutex_destroy(&ssp->ss_lock);
	kmem_free(ssp, sizeof (wrsmdstr_t));

	rq->q_ptr = WR(rq)->q_ptr = NULL;

	rw_exit(&wrsmdstruplock);
	D1("wrsmdclose: returning 0");
	TNF_PROBE_1(wrsmdclose_end, "RSMPI", "wrsmdclose end",
	    tnf_long, rval, 0);

	(void) qassociate(rq, -1);
	return (0);
}

/*
 * ****************************************************************
 *                                                               *
 * E N D   BASIC MODULE BOILERPLATE                              *
 *                                                               *
 * ****************************************************************
 */


/*
 * ****************************************************************
 *                                                               *
 * B E G I N   STATUS REPORTING STUFF                            *
 *                                                               *
 * ****************************************************************
 */

/*
 * This routine makes the data in our kernel statistics structure reflect
 * the current state of the device; it's called whenever a user requests
 * the kstat data.  Basically, all we do is copy the stats from the RSMPI
 * controller structure, where they're maintained, to the kstat's data
 * portion.
 */
static int
wrsmdstat_kstat_update(
	kstat_t *ksp,	/* Pointer to kstat that will be updated */
	int rw)		/* Indicates read or write (we don't support write) */
{
	wrsmd_t *wrsmdp;
	wrsmd_stat_t *wrsmdsp;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	wrsmdp = (wrsmd_t *)ksp->ks_private;
	wrsmdsp = (wrsmd_stat_t *)ksp->ks_data;

	wrsmdsp->rsm_ipackets.value.ul =	(uint_t)wrsmdp->wrsmd_ipackets;
	wrsmdsp->rsm_ipackets64.value.ui64 =	wrsmdp->wrsmd_ipackets;
	wrsmdsp->rsm_ierrors.value.ul =		wrsmdp->wrsmd_ierrors;
	wrsmdsp->rsm_opackets.value.ul =	(uint_t)wrsmdp->wrsmd_opackets;
	wrsmdsp->rsm_opackets64.value.ui64 =	wrsmdp->wrsmd_opackets;
	wrsmdsp->rsm_oerrors.value.ul =		wrsmdp->wrsmd_oerrors;
	wrsmdsp->rsm_collisions.value.ul =	wrsmdp->wrsmd_collisions;

	wrsmdsp->rsm_xfers.value.ul =		wrsmdp->wrsmd_xfers;
	wrsmdsp->rsm_xfer_pkts.value.ul =	wrsmdp->wrsmd_xfer_pkts;
	wrsmdsp->rsm_syncdqes.value.ul =	wrsmdp->wrsmd_syncdqes;
	wrsmdsp->rsm_lbufs.value.ul =		wrsmdp->wrsmd_lbufs;
	wrsmdsp->rsm_nlbufs.value.ul =		wrsmdp->wrsmd_nlbufs;
	wrsmdsp->rsm_pullup.value.ul =		wrsmdp->wrsmd_pullup;
	wrsmdsp->rsm_pullup_fail.value.ul =	wrsmdp->wrsmd_pullup_fail;
	wrsmdsp->rsm_starts.value.ul =		wrsmdp->wrsmd_starts;
	wrsmdsp->rsm_start_xfers.value.ul =	wrsmdp->wrsmd_start_xfers;
	wrsmdsp->rsm_fqetmo_hint.value.ul =	wrsmdp->wrsmd_fqetmo_hint;
	wrsmdsp->rsm_fqetmo_drops.value.ul =	wrsmdp->wrsmd_fqetmo_drops;
	wrsmdsp->rsm_maxq_drops.value.ul =	wrsmdp->wrsmd_maxq_drops;
	wrsmdsp->rsm_errs.value.ul =		wrsmdp->wrsmd_errs;
	wrsmdsp->rsm_in_bytes.value.ul =	(uint_t)wrsmdp->wrsmd_in_bytes;
	wrsmdsp->rsm_in_bytes64.value.ui64 =	wrsmdp->wrsmd_in_bytes;
	wrsmdsp->rsm_out_bytes.value.ul =	(uint_t)wrsmdp->wrsmd_out_bytes;
	wrsmdsp->rsm_out_bytes64.value.ui64 =	wrsmdp->wrsmd_out_bytes;

	return (0);
}

/*
 * This routine initializes the kernel statistics structures for an
 * WRSMD device.
 */
static void
wrsmdkstatinit(
	wrsmd_t *wrsmdp)	/* WRSMD device (RSM controller) pointer */
{
	struct kstat *ksp;
	wrsmd_stat_t *wrsmdsp;

	/*
	 * We create a kstat for the device, then create a whole bunch of
	 * named stats inside that first kstat.
	 */
	if ((ksp = kstat_create("wrsmd", ddi_get_instance(wrsmdp->wrsmd_dip),
	    NULL, "net", KSTAT_TYPE_NAMED, sizeof (wrsmd_stat_t) /
	    sizeof (kstat_named_t), 0)) == NULL) {
		wrsmderror(wrsmdp->wrsmd_dip, "kstat_create failed");
		return;
	}
	wrsmdsp = (wrsmd_stat_t *)(ksp->ks_data);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wrsmdsp))

	/*
	 * The first five named stats we create have well-known names, and are
	 * used by standard SunOS utilities (e.g., netstat).  (There is actually
	 * a sixth well-known stat, called "queue", which we don't support.)
	 */
	kstat_named_init(&wrsmdsp->rsm_ipackets, "ipackets", KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_ierrors, "ierrors", KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_opackets, "opackets", KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_oerrors, "oerrors", KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_collisions, "collisions",
	    KSTAT_DATA_ULONG);

	/*
	 * MIB II kstat variables
	 */
	kstat_named_init(&wrsmdsp->rsm_in_bytes, "rbytes", KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_out_bytes, "obytes", KSTAT_DATA_ULONG);

	/*
	 * PSARC 1997/198
	 */
	kstat_named_init(&wrsmdsp->rsm_ipackets64, "ipackets64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&wrsmdsp->rsm_opackets64, "opackets64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&wrsmdsp->rsm_in_bytes64, "rbytes64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&wrsmdsp->rsm_out_bytes64, "obytes64",
		KSTAT_DATA_ULONGLONG);


	/*
	 * The remainder of the named stats are specific to our driver, and
	 * are extracted using the kstat utility.
	 */
	kstat_named_init(&wrsmdsp->rsm_xfers, "xfers", KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_xfer_pkts, "xfer_pkts",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_syncdqes, "syncdqes", KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_lbufs, "lbufs", KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_nlbufs, "nlbufs", KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_pullup, "pullup", KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_pullup_fail, "pullup_fail",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_starts, "starts", KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_start_xfers, "start_xfers",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_fqetmo_hint, "fqetmo_hint",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_fqetmo_drops, "fqetmo_drops",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_maxq_drops, "maxq_drops",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&wrsmdsp->rsm_errs, "errs", KSTAT_DATA_ULONG);

	ksp->ks_update = wrsmdstat_kstat_update;
	ksp->ks_private = (void *) wrsmdp;
	wrsmdp->wrsmd_ksp = ksp;
	kstat_install(ksp);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*wrsmdsp))
}

/*
 * This routine removes any kstats we might have created.
 */
static void
wrsmdkstatremove(
	wrsmd_t *wrsmdp)	/* WRSMD device (RSM controller) pointer */
{
	_NOTE(ASSUMING_PROTECTED(wrsmdp->wrsmd_ksp))

	if (wrsmdp->wrsmd_ksp)
		kstat_delete(wrsmdp->wrsmd_ksp);
}

static void
print_fqe(volatile wrsmd_fqe_t *fqep)
{
	D0("%02x %04x   ", fqep->s.fq_seqnum, fqep->s.fq_bufnum);
}

static void
print_dqe(volatile wrsmd_dqe_t *dqep)
{
	D0("%02x %04x   ", dqep->s.dq_seqnum, dqep->s.dq_bufnum);
}

/* Dump detailed information about the destination entry */
static void
dump_dest(rsm_addr_t rsm_addr)
{
	int found;
	wrsmd_t *wrsmd_dp;
	wrsmd_dest_t *rd, *nrd;
	volatile wrsmd_fqe_t *fqep;
	volatile wrsmd_dqe_t *dqep;
	int isdel;

	found = 0;
	mutex_enter(&wrsmddevlock);
	for (wrsmd_dp = wrsmddev; wrsmd_dp; wrsmd_dp = wrsmd_dp->wrsmd_nextp) {
		FINDDEST(rd, isdel, wrsmd_dp, rsm_addr);
		if (rd == NULL) continue;

		found = 1;
		D0("\nwrsmd: 0x%p\n", (void *) wrsmd_dp);
		D0("rsmaddr %ld\n",
		    wrsmd_dp->wrsmd_rsm_addr.m.rsm);
		D0("wrsmd_runq: ");
		for (nrd = wrsmd_dp->wrsmd_runq; nrd; nrd = nrd->rd_next)
			D0("(%ld, %d) ", nrd->rd_rsm_addr,
			nrd->rd_state);

		D0("sd 0x%p (%ld, %ld): state (%d, 0x%x, %d)  ref %d "
		    "nlb %d nlb_del %d\n",
		    (void *)rd, rsm_addr, rd->rd_rsm_addr, rd->rd_state,
		    rd->rd_sstate, rd->rd_dstate, rd->rd_refcnt,
		    rd->rd_nlb, rd->rd_nlb_del);

		D0("  numlbufs %d   nlb_del %d   rbuflen %d   "
		    "numrbuf %d, queueh %lx  tail %lx\n",
			rd->rd_numlbufs, rd->rd_nlb_del,
			rd->rd_rbuflen, rd->rd_numrbuf,
			(uintptr_t)rd->rd_queue_h, (uintptr_t)rd->rd_queue_t);

		D0("  stopq %d\n", rd->rd_stopq);

		if (isdel) continue; /* No need to UNREFDEST */

		mutex_enter(&rd->rd_xmit_lock);

		D0("  XMT: queue_len %d (max %d), tmo_int %d  tmo_tot %d "
		    "(max %d) tmo_id %lx\n",
		    rd->rd_queue_len,
		    wrsmd_dp->wrsmd_param.wrsmd_max_queued_pkts,
		    rd->rd_tmo_int, rd->rd_tmo_tot,
		    wrsmd_dp->wrsmd_param.wrsmd_nobuf_drop_tmo,
		    (uintptr_t)rd->rd_tmo_id);

		mutex_enter(&rd->rd_net_lock);

		D0("    FQR: cached %d  fqr_seq %04x  size %d, fqr f/l/n "
		    "= %lx %lx %lx\n",
		    rd->rd_cached_fqr_cnt, rd->rd_fqr_seq, rd->rd_num_fqrs,
		    (uintptr_t)rd->rd_fqr_f, (uintptr_t)rd->rd_fqr_l,
		    (uintptr_t)rd->rd_fqr_n);

		if ((fqep = rd->rd_fqr_n) != NULL) {
			do {
				print_fqe(fqep);
				if (fqep == rd->rd_fqr_l)
					D0("* ");
				fqep = (fqep == rd->rd_fqr_l) ?
				    rd->rd_fqr_f : fqep + 1;
			} while (fqep != rd->rd_fqr_n);
		}

		D0("\n    shadow DQ: dqeq f/l/i/o = %lx %lx %lx %lx\n",
			(uintptr_t)rd->rd_shdwdqw_f,
			(uintptr_t)rd->rd_shdwdqw_l,
			(uintptr_t)rd->rd_shdwdqw_i,
			(uintptr_t)rd->rd_shdwdqw_o);

		if ((dqep = rd->rd_shdwdqw_o) != NULL) {
			do {
				print_dqe(dqep);
				if (dqep == rd->rd_shdwdqw_l)
					D0("* ");
				dqep = (dqep == rd->rd_shdwdqw_l) ?
				    rd->rd_shdwdqw_f : dqep + 1;
			} while (dqep != rd->rd_shdwdqw_o);
		}

		D0("\n    remote DQ: dqw_seq %04x  size %d, "
		    "dqw f_off = %lx\n",
		    rd->rd_dqw_seq, rd->rd_num_dqws, rd->rd_dqw_f_off);

		D0("\n\n  RCV: rd_rbufoff %08lx, rbuflen %d, numrbuf %d\n",
			rd->rd_rbufoff, rd->rd_rbuflen, rd->rd_numrbuf);

		D0("    DQR: dqr_seq = %04x  size = %d, dqr f/l/n = "
		    "%lx %lx %lx\n",
		    rd->rd_dqr_seq, rd->rd_num_dqrs,
		    (uintptr_t)rd->rd_dqr_f, (uintptr_t)rd->rd_dqr_l,
		    (uintptr_t)rd->rd_dqr_n);

		if ((dqep = rd->rd_dqr_n) != NULL) {
			do {
				print_dqe(dqep);
				if (dqep == rd->rd_dqr_l)
					D0("* ");
				dqep = (dqep == rd->rd_dqr_l) ?
				    rd->rd_dqr_f : dqep + 1;
			} while (dqep != rd->rd_dqr_n);
		}

		D0("\n    shadow FQE: shdwfqw f/l/i/o = %lx %lx %lx %lx\n",
			(uintptr_t)rd->rd_shdwfqw_f,
			(uintptr_t)rd->rd_shdwfqw_l,
			(uintptr_t)rd->rd_shdwfqw_i,
			(uintptr_t)rd->rd_shdwfqw_o);

		if ((fqep = rd->rd_shdwfqw_o) != NULL) {
			do {
				print_fqe(fqep);
				if (fqep == rd->rd_shdwfqw_l)
					D0("* ");
				fqep = (fqep == rd->rd_shdwfqw_l) ?
				    rd->rd_shdwfqw_f : fqep + 1;
			} while (fqep != rd->rd_shdwfqw_o);
		}

		D0("\n    remote FQ: fqw_seq %04x  size %d, fqw f = %lx\n",
		    rd->rd_fqw_seq, rd->rd_num_fqws, rd->rd_fqw_f_off);

		mutex_exit(&rd->rd_net_lock);

		mutex_exit(&rd->rd_xmit_lock);

		UNREFDEST(rd);
	}
	mutex_exit(&wrsmddevlock);
	if (found == 0) D0("Sorry - entry for %ld not found\n",
	    rsm_addr);
}

/* Dump summary information about all destination entries */
static void
dump_ioctl(void)
{
	wrsmd_t *wrsmd_np;
	wrsmd_dest_t *rd;
	int dest;

	D0("..head of wrsmd structure list, wrsmddev: 0x%lx\n",
	    (uintptr_t)wrsmddev);

	mutex_enter(&wrsmddevlock);
	for (wrsmd_np = wrsmddev; wrsmd_np; wrsmd_np = wrsmd_np->wrsmd_nextp) {
		D0("\n    wrsmd: 0x%lx\n", (uintptr_t)wrsmd_np);
		D0("    next wrsmd pointer, wrsmd_nextp: 0x%lx\n",
			(uintptr_t)wrsmd_np->wrsmd_nextp);
		D0("    dev info pointer, wrsmd_dip: 0x%lx, ipq 0x%lx\n",
			(uintptr_t)wrsmd_np->wrsmd_dip,
			(uintptr_t)wrsmd_np->wrsmd_ipq);
		D0("    rsmaddr %ld\n",
			wrsmd_np->wrsmd_rsm_addr.m.rsm);

		mutex_enter(&wrsmd_np->wrsmd_dest_lock);
		for (dest = 0; dest < RSM_MAX_DESTADDR; dest++) {
			if ((rd = wrsmd_np->wrsmd_desttbl[dest]) == NULL)
				continue;
			D0("      rd 0x%p (%d, %ld): state (%d, "
			    "0x%x, %d)  ref %d  nlb %d nlb_del %d\n",
			    (void *)rd, dest, rd->rd_rsm_addr,
			    rd->rd_state, rd->rd_sstate, rd->rd_dstate,
			    rd->rd_refcnt, rd->rd_nlb, rd->rd_nlb_del);
		}
		mutex_exit(&wrsmd_np->wrsmd_dest_lock);
	}
	mutex_exit(&wrsmddevlock);
}

/*
 * Print an error message to the console.
 */
static void
wrsmderror(
	dev_info_t *dip,	/* Dev info for the device in question */
	const char *fmt,	/* Format of output */
	...)			/* Parameters for output */
{
	char name[16];
	char buf[1024];
	va_list ap;

	if (dip) {
		(void) sprintf(name, "%s%d", ddi_get_name(dip),
			ddi_get_instance(dip));
	} else {
		(void) sprintf(name, "wrsmd");
	}

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	D1("%s:\t%s", name, buf);
	cmn_err(CE_CONT, "%s:\t%s", name, buf);
}


#ifdef DEBUG_WRSMD

#ifdef DEBUG_LOG

/*
 * The following variables support the debug log buffer scheme.
 */

char wrsmddbgbuf[0x80000];	/* The log buffer */
int wrsmddbgsize = sizeof (wrsmddbgbuf);	/* Size of the log buffer */
int wrsmddbgnext;		/* Next byte to write in buffer (note */
				/*  this is an index, not a pointer */
int wrsmddbginit = 0;		/* Nonzero if wrsmddbglock's inited */
kmutex_t wrsmddbglock;

_NOTE(MUTEX_PROTECTS_DATA(wrsmdattlock, wrsmddbginit))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmddbginit))

_NOTE(MUTEX_PROTECTS_DATA(wrsmddbglock, wrsmddbgbuf wrsmddbgnext))

/*
 * Add the string str to the end of the debug log, followed by a newline.
 */
static void
wrsmddbglog(char *str)
{
	int length, remlen;

	/*
	 * If this is the first time we've written to the log, initialize it.
	 */
	if (!wrsmddbginit) {
		mutex_enter(&wrsmdattlock);
		if (!wrsmddbginit) {
			mutex_init(&wrsmddbglock, NULL, MUTEX_DRIVER,
			    NULL);
			bzero(wrsmddbgbuf, sizeof (wrsmddbgbuf));
			wrsmddbgnext = 0;
			wrsmddbginit = 1;
		}
		mutex_exit(&wrsmdattlock);
	}

	mutex_enter(&wrsmddbglock);

	/*
	 * Note the log is circular; if this string would run over the end,
	 * we copy the first piece to the end and then the last piece to
	 * the beginning of the log.
	 */
	length = strlen(str);

	remlen = sizeof (wrsmddbgbuf) - wrsmddbgnext;

	if (length > remlen) {
		if (remlen)
			bcopy(str, wrsmddbgbuf + wrsmddbgnext, remlen);
		str += remlen;
		length -= remlen;
		wrsmddbgnext = 0;
	}

	bcopy(str, wrsmddbgbuf + wrsmddbgnext, length);
	wrsmddbgnext += length;

	if (wrsmddbgnext >= sizeof (wrsmddbgbuf))
		wrsmddbgnext = 0;
	wrsmddbgbuf[wrsmddbgnext++] = '\n';

	mutex_exit(&wrsmddbglock);
}

#endif


/*
 * Add a printf-style message to whichever debug logs we're currently using.
 */
static void
wrsmddebug(const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

#ifdef DEBUG_LOG
	if (wrsmddbgmode & 0x1)
		wrsmddbglog(buf);
#endif

#ifdef DEBUG_PRINTF
	if (wrsmddbgmode & 0x2)
		cmn_err(CE_CONT, "%s\n", buf);
#endif
}

/*
 * Debugging routine, dumps data in hex.
 */
static void
wrsmdump(
	uchar_t *data,	/* Start of data */
	int length)	/* Bytes to dump */
{
	int bytesonline;
	int offset;
	char *lineptr;
	char line[80];

	lineptr = line;
	bytesonline = 0;
	offset = 0;


	wrsmddebug("wrsmdump: dump of %d bytes at 0x%p", length, (void *)data);

	while (length) {
		if (bytesonline == 0) {
			(void) sprintf(line, "%8x: ", offset);
			lineptr = line + strlen(line);
		}

		(void) sprintf(lineptr, "%2x ", *data++);
		length--;
		lineptr += 3;
		bytesonline++;

		if (bytesonline >= 16) {
			*lineptr = '\0';
			wrsmddebug("%s", line);
			bytesonline = 0;
			offset += 16;
		}

	}

	if (bytesonline) {
		*lineptr = '\0';
		wrsmddebug("%s", line);
	}
}

#endif


/*
 * ****************************************************************
 *                                                               *
 * E N D   STATUS REPORTING STUFF                                *
 *                                                               *
 * ****************************************************************
 */


/*
 * ****************************************************************
 *                                                               *
 * B E G I N   BASIC STREAMS OPERATIONS                          *
 *                                                               *
 * ****************************************************************
 */

/*
 * Process a new message being sent down one of our streams.
 */
static int
wrsmdwput(
	queue_t *wq,	/* Queue message was written on */
	mblk_t *mp)	/* The message itself */
{
	wrsmdstr_t *ssp =	/* Pointer to this stream's structure */
		(wrsmdstr_t *)wq->q_ptr;
	wrsmd_t *wrsmdp;	/* WRSMD device (RSM controller) pointer */

	D1("wrsmdwput: wq 0x%p, mp 0x%p, ssp 0x%p", (void *)wq,
	    (void *)mp, (void *)ssp);
	D5("wrsmdwput: time 0x%llx", gethrtime());
	TNF_PROBE_1(wrsmdwput_start, "RSMPI", "wrsmdwput start",
		tnf_long, length, msgdsize(mp));

	switch (DB_TYPE(mp)) {
		case M_DATA:
			/*
			 * This message is a raw data item.  Most messages
			 * end up in this case.
			 */

			/*
			 * It is possible that an interrupt thread handling
			 * incoming packets has taken wrsmdstruplock or
			 * ipq_rwlock, sent a packet upstream (usually to
			 * ar), then looped back down to here.  Meanwhile,
			 * a separate thread could be attempting to modify
			 * the ipq shortcut, which first takes
			 * ssp->ss_lock, then takes wrsmdstriplock.  This
			 * causes a deadlock.  Avoid this by enqueueing the
			 * message if the ssp->ss_lock can't be taken
			 * immediately.
			 */
			if (!mutex_tryenter(&ssp->ss_lock)) {
				(void) putq(wq, mp);
				break;
			}

			wrsmdp = ssp->ss_wrsmdp;

			/* If we're not supposed to get raw data, toss it. */

			if (((ssp->ss_flags &
			    (WRSMD_SLRAW | WRSMD_SLFAST)) == 0) ||
			    (ssp->ss_state != DL_IDLE) || (wrsmdp == NULL)) {
				merror(wq, mp, EPROTO);
				mutex_exit(&ssp->ss_lock);
				TNF_PROBE_1(wrsmdwput_end, "RSMPI",
				    "wrsmdwput end; type M_DATA",
				    tnf_string, type, "M_DATA");
				break;
			}

			/*
			 * If any msgs already enqueued or the interface will
			 * loop back up the message (due to wrsmd_promisc),
			 * then enqueue the msg.  (Can't handle promiscuous
			 * here because it takes wrsmdstruplock, which might
			 * cause a recursive rw_enter.) Otherwise just xmit it
			 * directly.
			 */
			if (wq->q_first || wrsmdp->wrsmd_promisc) {
				(void) putq(wq, mp);
			} else {
				dl_rsm_addr_t addr;
				ushort_t sap;

				if (mp = wrsmdstrip(mp, &addr, &sap))
					wrsmdstart(wrsmdp, mp, addr,
					    sap, 1);
			}

			mutex_exit(&ssp->ss_lock);
			TNF_PROBE_1(wrsmdwput_end, "RSMPI",
			    "wrsmdwput end; type M_DATA",
			    tnf_string, type, "M_DATA");
			break;

		case M_PROTO:
		case M_PCPROTO:
			/*
			 * This message is a DLPI control message.  In
			 * almost all cases, we just put this on the queue
			 * for the service routine to process.  Why?
			 * Basically, because processing of some of the
			 * M_PROTO/M_PCPROTO requests involves acquiring
			 * internal locks that are also held across
			 * upstream putnext calls.  For instance,
			 * wrsmdread() holds wrsmdstruplock and may
			 * hold wrsmdp->wrsmd_ipq_rwlock when it
			 * calls putnext().  In some cases, IP's or
			 * TCP's put routine, which was called from
			 * putnext() could immediately loop back, do a
			 * downward putnext() of a M_PROTO message, and end
			 * up right here.  If we were then to try and
			 * process that message, we could try to obtain
			 * wrsmdstruplock or wrsmd_ipq_rwlock, which we
			 * already have, thus leading to a recursive
			 * mutex_enter panic.
			 *
			 * To prevent this, we put the M_PROTO message on
			 * the service routine's queue.  When the service
			 * routine runs, it will be in a different context
			 * which can safely acquire the appropriate locks.
			 */

			(void) putq(wq, mp);
			TNF_PROBE_1(wrsmdwput_end, "RSMPI",
			    "wrsmdwput end; type M_PROTO",
			    tnf_string, type, "M_PROTO");
			break;

		case M_IOCTL:
			/*
			 * ARP may do a downward putnext() of an M_IOCTL
			 * stream in response to an ack sent upstream
			 * by this module while holding internal locks.
			 * As described above, we avoid a recursive mutex
			 * enter by handling it in the service routine.
			 * We do an immediate nak for unrecognized ioctls.
			 */
			if (!wrsmdioctlimmediate(wq, mp))
				(void) putq(wq, mp);

			TNF_PROBE_1(wrsmdwput_end, "RSMPI",
			    "wrsmdwput end; type M_IOCTL",
			    tnf_string, type, "M_IOCTL");
			break;

		case M_FLUSH:
			/*
			 * This message is asking us to flush our queues,
			 * probably in preparation for taking down the
			 * stream.
			 */
			if (*mp->b_rptr & FLUSHW) {
				flushq(wq, FLUSHALL);
				*mp->b_rptr &= ~FLUSHW;
			}
			if (*mp->b_rptr & FLUSHR)
				qreply(wq, mp);
			else
				freemsg(mp);
			TNF_PROBE_1(wrsmdwput_end, "RSMPI",
			    "wrsmdwput end; type M_FLUSH",
			    tnf_string, type, "M_FLUSH");
			break;

		default:
			freemsg(mp);
			TNF_PROBE_1(wrsmdwput_end, "RSMPI",
			    "wrsmdwput end; type unknown",
			    tnf_string, type, "UNKNOWN");
			break;
	}

	D1("wrsmdwput: returning 0");
	TNF_PROBE_1(wrsmdwput_end, "RSMPI", "wrsmdwput end",
	    tnf_long, rval, 0);
	return (0);
}

/*
 * Write service routine.  This routine processes any messages put on the queue
 * via a putq() in the write put routine.  It also handles any destinations put
 * on the destination run queue.
 */
static int
wrsmdwsrv(queue_t *wq)	/* Queue we should service */
{
	mblk_t *mp;
	wrsmdstr_t *ssp;
	wrsmd_t *wrsmdp;
	wrsmd_dest_t *rd;
	int isdel;

	D1("wrsmdwsrv: wq 0x%p", (void *)wq);
	D5("wrsmdwsrv: time 0x%llx", gethrtime());

	ssp = (wrsmdstr_t *)wq->q_ptr;
	wrsmdp = ssp->ss_wrsmdp;

	D1("wrsmdwsrv: ssp 0x%p, wrsmdp 0x%p (cltr %d)", (void *)ssp,
	    (void *)wrsmdp, wrsmdp ? wrsmdp->wrsmd_ctlr_id : -1);
	TNF_PROBE_0(wrsmdwsrv_start, "RSMPI", "wrsmdwsrv start");

	/*
	 * Process message queue.
	 */
	while (mp = getq(wq)) {
		switch (DB_TYPE(mp)) {
			case M_DATA:
				D5("wrsmdwsrv: got data time 0x%llx",
				    gethrtime());
				if (wrsmdp) {
					dl_rsm_addr_t addr;
					ushort_t sap;

					if (mp = wrsmdstrip(mp, &addr, &sap))
						wrsmdstart(wrsmdp, mp,
						    addr, sap, 0);
				} else
					freemsg(mp);
				TNF_PROBE_1(wrsmdwsrv_msg, "RSMPI",
				    "wrsmdwsrv qcount; type M_DATA",
				    tnf_string, type, "M_DATA");
				break;

			case M_PROTO:
			case M_PCPROTO:
				D5("wrsmdwsrv: got proto time 0x%llx",
				    gethrtime());
				wrsmdproto(wq, mp);
				wrsmdp = ssp->ss_wrsmdp;
				TNF_PROBE_1(wrsmdwsrv_msg, "RSMPI",
				    "wrsmdwsrv qcount; type M_PROTO",
				    tnf_string, type, "M_PROTO");
				break;

			case M_IOCTL:
				/*
				 * This message is an ioctl.
				 * We do not hold locks around the whole ioctl
				 * processing, as the holding of locks across a
				 * qreply() of ack or nak is a violation of the
				 * SVR4 DDI/DKI
				 */
				wrsmdioctl(wq, mp);

				TNF_PROBE_1(wrsmdwsrv_msg, "RSMPI",
				    "wrsmdwsrv msg; type M_IOCTL",
				    tnf_string, type, "M_IOCTL");
				break;


			default: /* nothing is working at ths point */
				TNF_PROBE_1(wrsmdwsrv_msg, "RSMPI",
				    "wrsmdwsrv qcount; type unknown",
				    tnf_string, type, "UNKNOWN");
				ASSERT(0);
				break;
		}
	}

	/*
	 * Traverse list of scheduled destinations, looking for work to do
	 */

	if (wrsmdp == NULL) {
		D1("wrsmdwsrv: wrsmdp NULL, returning 0");
		TNF_PROBE_0(wrsmdwsrv_end, "RSMPI", "wrsmdwsrv end");
		return (0);
	}

	/*
	 * rd's refcnt is incremented by GETRUNQ
	 */
	GETRUNQ(rd, isdel, wrsmdp);
	while (rd) {
		int oldstate, delete;

		if (isdel) {
			D2("wrsmdwsrv: dest 0x%p being deleted, ignored",
			    (void *)rd);
			GETRUNQ(rd, isdel, wrsmdp);
			continue;
		}

		mutex_enter(&rd->rd_lock);
		delete = 0;

		oldstate = wrsmdgetstate(rd);
		D5("wrsmdwsrv: running state %s time 0x%llx",
		    WRSMD_STATE_STR(oldstate), gethrtime());
		switch (oldstate) {

		case WRSMD_STATE_S_XFER: {
			mutex_enter(&rd->rd_xmit_lock);
			if (rd->rd_queue_h)
				wrsmdxfer(wrsmdp, rd);
			else
				wrsmdsetstate(rd, WRSMD_STATE_W_READY);
			mutex_exit(&rd->rd_xmit_lock);

			break;
		}

		case WRSMD_STATE_S_REQ_CONNECT: {
			if (wrsmdcrexfer(wrsmdp, rd) != 0 ||
			    wrsmdsconn(wrsmdp, rd, 0) != 0) {
				wrsmdsetstate(rd, WRSMD_STATE_DELETING);
				delete = 1;
			}
			break;
		}

		case WRSMD_STATE_S_NEWCONN: {
			if (wrsmdcrexfer(wrsmdp, rd) != 0 ||
			    wrsmdconnxfer(wrsmdp, rd) != 0 ||
			    wrsmdsaccept(wrsmdp, rd) != 0) {
				wrsmdsetstate(rd, WRSMD_STATE_DELETING);
				delete = 1;
			}
			break;
		}

		case WRSMD_STATE_S_CONNXFER_ACCEPT: {
			if (wrsmdconnxfer(wrsmdp, rd) != 0 ||
			    wrsmdsaccept(wrsmdp, rd) != 0) {
				wrsmdsetstate(rd, WRSMD_STATE_DELETING);
				delete = 1;
			}
			break;
		}

		case WRSMD_STATE_S_CONNXFER_ACK: {
			if (wrsmdconnxfer(wrsmdp, rd) != 0 ||
			    wrsmdsack(wrsmdp, rd) != 0) {
				wrsmdsetstate(rd, WRSMD_STATE_DELETING);
				delete = 1;
			}
			break;
		}

		/*
		 * Delete this connection.  This causes a message
		 * to be sent to the remote side when RSM_SENDQ_DESTROY
		 * is called, so there is no need to send an additional
		 * message.
		 */
		case WRSMD_STATE_S_DELETE: {
			wrsmdsetstate(rd, WRSMD_STATE_DELETING);
			delete = 1;

			break;
		}

		/*
		 * Retry the SCONN.
		 */
		case WRSMD_STATE_S_SCONN: {
			if (wrsmdsconn(wrsmdp, rd, 1) != 0) {
				wrsmdsetstate(rd, WRSMD_STATE_DELETING);
				delete = 1;
			}
			break;
		}

		default:
			D1("wrsmd: bad state %s in wsrv "
			    " for dest 0x%lx", WRSMD_STATE_STR(oldstate),
			    (uintptr_t)rd);
			cmn_err(CE_PANIC, "wrsmd: bad state %s in wsrv "
			    " for dest 0x%lx", WRSMD_STATE_STR(oldstate),
			    (uintptr_t)rd);
			break;
		}

		mutex_exit(&rd->rd_lock);

		if (delete)
			wrsmdfreedest(wrsmdp, rd->rd_rsm_addr);

		UNREFDEST(rd);

		GETRUNQ(rd, isdel, wrsmdp);
	}

	D1("wrsmdwsrv: returning 0");
	TNF_PROBE_0(wrsmdwsrv_end, "RSMPI", "wrsmdwsrv end");
	return (0);
}


/*
 * Discard all messages queued for output to this destination, updating
 * error statistics as appropriate.
 */
static void
wrsmddumpqueue(wrsmd_t *wrsmdp,	/* WRSMD device (RSM controller) pointer */
	wrsmd_dest_t *rd)	/* Destination pointer */
{
	mblk_t *mp, *nmp;

	ASSERT(MUTEX_HELD(&rd->rd_xmit_lock));

	D1("wrsmddumpqueue: wrsmdp 0x%p (ctlr %d), rd 0x%p (addr %ld)",
	    (void *)wrsmdp,
	    wrsmdp ? wrsmdp->wrsmd_ctlr_id : -1, (void *)rd, rd->rd_rsm_addr);
	TNF_PROBE_2(wrsmddumpqueue_start, "RSMPI",
	    "wrsmddumpqueue start",
	    tnf_long, wrsmdp, (tnf_long_t)wrsmdp, tnf_long, rd, (tnf_long_t)rd);

	mp = rd->rd_queue_h;
	rd->rd_queue_h = NULL;
	rd->rd_queue_len = 0;

	while (mp) {
		nmp = mp->b_next;
		mp->b_next = mp->b_prev = NULL;
		freemsg(mp);
		wrsmdp->wrsmd_oerrors++;
		mp = nmp;
	}
	D1("wrsmddumpqueue: done");
	TNF_PROBE_0(wrsmddumpqueue_end, "RSMPI", "wrsmddumpqueue end");
}

/*
 * Execute an ioctl request from the service routine.
 */
static void
wrsmdioctl(queue_t *wq, mblk_t *mp)
{

	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	wrsmdstr_t *ssp = (wrsmdstr_t *)wq->q_ptr;
	rsm_addr_t dest;

	D1("wrsmdioctl: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);

	switch (iocp->ioc_cmd) {
	case DLIOCRAW:		/* raw M_DATA mode */
		D1("wrsmdioctl: DLIOCRAW");
		mutex_enter(&ssp->ss_lock);
		ssp->ss_flags |= WRSMD_SLRAW;
		mutex_exit(&ssp->ss_lock);
		miocack(wq, mp, 0, 0);
		break;

	case DL_IOC_HDR_INFO:	/* M_DATA "fastpath" info request */
		D1("wrsmdioctl: DL_IOC_HDR_INFO");
		wrsmd_dl_ioc_hdr_info(wq, mp);
		break;

	case WRSMD_DUMP_IOCTL:
		mutex_enter(&ssp->ss_lock);
		dump_ioctl();
		mutex_exit(&ssp->ss_lock);
		miocack(wq, mp, 0, 0);
		break;

	case WRSMD_DUMP_DEST:
		if ((mp->b_cont == NULL) ||
			((mp->b_cont->b_wptr - mp->b_cont->b_rptr) !=
			    sizeof (dest))) {
			miocnak(wq, mp, 0, EINVAL);
			break;
		}

		bcopy(mp->b_cont->b_rptr, &dest, sizeof (dest));
		mutex_enter(&ssp->ss_lock);
		dump_dest(dest);
		mutex_exit(&ssp->ss_lock);
		miocack(wq, mp, 0, 0);
		break;

	default:
		D1("wrsmdioctl: unknown ioctl 0x%x", iocp->ioc_cmd);
		miocnak(wq, mp, 0, EINVAL);
		break;
	}
	D1("wrsmdioctl: done");
}

/*
 * Execute an immediate ioctl request from the put routine.
 * Does not take any locks.  Returns FALSE if not handled immediately.
 */
static int
wrsmdioctlimmediate(queue_t *wq, mblk_t *mp)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;

	D1("wrsmdioctlimmediate: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);

	switch (iocp->ioc_cmd) {
	case DLIOCRAW:		/* raw M_DATA mode */
	case DL_IOC_HDR_INFO:	/* M_DATA "fastpath" info request */
	case WRSMD_DUMP_IOCTL:
	case WRSMD_DUMP_DEST:
		/* handle from the service routine */
		return (B_FALSE);

	default:
		D1("wrsmdioctlimmediate: unknown ioctl 0x%x", iocp->ioc_cmd);
		miocnak(wq, mp, 0, EINVAL);
		break;
	}
	D1("wrsmdioctlimmediate: done");

	return (B_TRUE);
}

/*
 * M_DATA "fastpath" info request.
 * Following the M_IOCTL mblk should come a DL_UNITDATA_REQ mblk.  We ack with
 * an M_IOCACK pointing to the original DL_UNITDATA_REQ mblk, followed by an
 * mblk containing the raw medium header corresponding to the destination
 * address.  Subsequently, we may receive M_DATA msgs which start with this
 * header and may send up M_DATA msgs containing the network-layer data.
 * This is all selectable on a per-Stream basis.
 */
static void
wrsmd_dl_ioc_hdr_info(queue_t *wq, mblk_t *mp)
{
	mblk_t *nmp;
	wrsmdstr_t *ssp;
	wrsmddladdr_t *dlap;
	dl_unitdata_req_t *dludp;
	struct ether_header *headerp;
	wrsmd_t *wrsmdp;
	uint32_t off, len;
	int minsize;

	D1("wrsmd_dl_ioc_hdr_info: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);

	ssp = (wrsmdstr_t *)wq->q_ptr;
	minsize = sizeof (dl_unitdata_req_t) + WRSMD_DEVICE_ADDRL;

	mutex_enter(&ssp->ss_lock);

	/*
	 * Sanity check the request.
	 */
	if ((mp->b_cont == NULL) ||
	    (MBLKL(mp->b_cont) < minsize) ||
		(((union DL_primitives *)mp->b_cont->b_rptr)->dl_primitive !=
		    DL_UNITDATA_REQ) ||
	    ((wrsmdp = ssp->ss_wrsmdp) == NULL)) {
		mutex_exit(&ssp->ss_lock);
		miocnak(wq, mp, 0, EINVAL);
		D1("wrsmd_dl_ioc_hdr_info: bad req, done");
		return;
	}

	/*
	 * Sanity check the DL_UNITDATA_REQ destination address
	 * offset and length values.
	 */
	dludp = (dl_unitdata_req_t *)mp->b_cont->b_rptr;
	off = dludp->dl_dest_addr_offset;
	len = dludp->dl_dest_addr_length;
	if (!MBLKIN(mp->b_cont, off, len) || (len != WRSMD_DEVICE_ADDRL)) {
		mutex_exit(&ssp->ss_lock);
		miocnak(wq, mp, 0, EINVAL);
		D1("wrsmd_dl_ioc_hdr_info: bad addr, done");
		return;
	}

	dlap = (wrsmddladdr_t *)(mp->b_cont->b_rptr + off);

	/*
	 * Allocate a new mblk to hold the medium header.
	 */
	if ((nmp = allocb(sizeof (struct ether_header), BPRI_MED))
	    == NULL) {
		mutex_exit(&ssp->ss_lock);
		miocnak(wq, mp, 0, ENOMEM);
		D1("wrsmd_dl_ioc_hdr_info: ENOMEM, done");
		return;
	}
	nmp->b_wptr += sizeof (struct ether_header);

	/*
	 * Fill in the medium header.
	 */
	headerp = (struct ether_header *)nmp->b_rptr;

	ether_copy(&(dlap->dl_addr), &(headerp->ether_dhost));
	ether_copy(&(wrsmdp->wrsmd_rsm_addr.m.ether.addr),
	    &(headerp->ether_shost));
	headerp->ether_type = dlap->dl_sap;

	/*
	 * Link new mblk in after the "request" mblks.
	 */
	linkb(mp, nmp);

	ssp->ss_flags |= WRSMD_SLFAST;

	wrsmdsetipq(wrsmdp);

	mutex_exit(&ssp->ss_lock);

	miocack(wq, mp, MBLKL(mp->b_cont)+MBLKL(nmp), 0);

	D1("wrsmd_dl_ioc_hdr_info: done");
}

/*
 * ****************************************************************
 *                                                               *
 * E N D       BASIC STREAMS OPERATIONS                          *
 *                                                               *
 * ****************************************************************
 */



/*
 * ****************************************************************
 *                                                               *
 * B E G I N   DLPI OPERATIONS                                   *
 *                                                               *
 * ****************************************************************
 */

/*
 * Parse and execute a DLPI request.
 */
static void
wrsmdproto(
	queue_t *wq,	/* Queue the request came in on */
	mblk_t *mp)	/* The request message itself */
{
	union DL_primitives *dlp;
	wrsmdstr_t *ssp;
	uint32_t prim;

	D1("wrsmdproto: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);
	TNF_PROBE_2(wrsmdproto_start, "RSMPI", "wrsmdproto start",
	    tnf_long, wq, (tnf_long_t)wq, tnf_long, mp, (tnf_long_t)mp);

	ssp = (wrsmdstr_t *)wq->q_ptr;
	dlp = (union DL_primitives *)mp->b_rptr;
	/* Make sure we at least have dlp->dl_primitive */
	if ((caddr_t)mp->b_wptr <
	    (caddr_t)&dlp->dl_primitive + sizeof (dlp->dl_primitive)) {
		dlerrorack(wq, mp, 0xffff, DL_BADPRIM, 0);
		return;
	}
	prim = dlp->dl_primitive;

	mutex_enter(&ssp->ss_lock);

	switch (prim) {
		case DL_UNITDATA_REQ:
			TNF_PROBE_1(wrsmdproto_prim, "RSMPI",
			    "wrsmdproto prim",
			    tnf_string, DL_UNITDATA_REQ, "");
			wrsmdudreq(wq, mp);
			break;

		case DL_ATTACH_REQ:
			TNF_PROBE_1(wrsmdproto_prim, "RSMPI",
			    "wrsmdproto prim",
			    tnf_string, DL_ATTACH_REQ, "");
			wrsmdareq(wq, mp);
			break;

		case DL_DETACH_REQ:
			TNF_PROBE_1(wrsmdproto_prim, "RSMPI",
			    "wrsmdproto prim",
			    tnf_string, DL_DETACH_REQ, "");
			wrsmddreq(wq, mp);
			break;

		case DL_ENABMULTI_REQ:
			TNF_PROBE_1(wrsmdproto_prim, "RSMPI",
			    "wrsmdproto prim",
			    tnf_string, DL_ENABMULTI_REQ, "");
			/* Accept enable-multicast-request */
			dlokack(wq, mp, DL_ENABMULTI_REQ);
			break;

		case DL_DISABMULTI_REQ:
			TNF_PROBE_1(wrsmdproto_prim, "RSMPI",
			    "wrsmdproto prim",
			    tnf_string, DL_DISABMULTI_REQ, "");
			/* Accept disable-multicast-request */
			dlokack(wq, mp, DL_DISABMULTI_REQ);
			break;

		case DL_BIND_REQ:
			TNF_PROBE_1(wrsmdproto_prim, "RSMPI",
			    "wrsmdproto prim",
			    tnf_string, DL_BIND_REQ, "");
			wrsmdbreq(wq, mp);
			break;

		case DL_UNBIND_REQ:
			TNF_PROBE_1(wrsmdproto_prim, "RSMPI",
			    "wrsmdproto prim",
			    tnf_string, DL_UNBIND_REQ, "");
			wrsmdubreq(wq, mp);
			break;

		case DL_INFO_REQ:
			TNF_PROBE_1(wrsmdproto_prim, "RSMPI",
			    "wrsmdproto prim",
			    tnf_string, DL_INFO_REQ, "");
			wrsmdireq(wq, mp);
			break;

		case DL_PROMISCON_REQ:
			TNF_PROBE_1(wrsmdproto_prim, "RSMPI",
			    "wrsmdproto prim",
			    tnf_string, DL_PROMISCON_REQ, "");
			wrsmdponreq(wq, mp);
			break;

		case DL_PROMISCOFF_REQ:
			TNF_PROBE_1(wrsmdproto_prim, "RSMPI",
			    "wrsmdproto prim",
			    tnf_string, DL_PRIMISCOFF_REQ, "");
			wrsmdpoffreq(wq, mp);
			break;

		case DL_PHYS_ADDR_REQ:
			TNF_PROBE_1(wrsmdproto_prim, "RSMPI",
			    "wrsmdproto prim",
			    tnf_string, DL_PHYS_ADDR_REQ, "");
			wrsmdpareq(wq, mp);
			break;

		default:
			TNF_PROBE_1(wrsmdproto_prim, "RSMPI",
			    "wrsmdproto prim",
			    tnf_string, DL_UNSUPPORTED, "");
			dlerrorack(wq, mp, prim, DL_UNSUPPORTED, 0);
			break;
	}

	mutex_exit(&ssp->ss_lock);

	D1("wrsmdproto: done");
	TNF_PROBE_1(wrsmdproto_end, "RSMPI", "wrsmdproto end",
	    tnf_string, completed, "");
}

/*
 * START OF GENERIC DLPI INTERFACE ROUTINES
 */

/*
 * DLPI attach request (attach stream to physical device)
 *
 * The PPA is the RSM controller id, which equals the DLPI device instance
 * number.
 */
static void
wrsmdareq(queue_t *wq, mblk_t *mp)
{
	wrsmdstr_t *ssp;
	union DL_primitives *dlp;
	wrsmd_t *wrsmdp;
	uint32_t ppa;
	timeout_id_t tmoid;

	D1("wrsmdareq: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);

	ssp = (wrsmdstr_t *)wq->q_ptr;
	dlp = (union DL_primitives *)mp->b_rptr;

	if (MBLKL(mp) < DL_ATTACH_REQ_SIZE) {
		dlerrorack(wq, mp, DL_ATTACH_REQ, DL_BADPRIM, 0);
		D1("wrsmdareq: bad size, done");
		return;
	}

	if (ssp->ss_state != DL_UNATTACHED) {
		dlerrorack(wq, mp, DL_ATTACH_REQ, DL_OUTSTATE, 0);
		D1("wrsmdareq: bad state, done");
		return;
	}

	ppa = dlp->attach_req.dl_ppa;

	/*
	 * Valid ppa?
	 */
	if (ppa == -1 || qassociate(wq, ppa) != 0) {
		dlerrorack(wq, mp, dlp->dl_primitive, DL_BADPPA, 0);
		D1("wrsmdareq: bad ppa, done");
		return;
	}
	mutex_enter(&wrsmddevlock);
	for (wrsmdp = wrsmddev; wrsmdp;
	    wrsmdp = wrsmdp->wrsmd_nextp) {
		if (ppa == wrsmdp->wrsmd_ctlr_id) {
			break;
		}
	}
	mutex_exit(&wrsmddevlock);
	/* when qassociate() succeeds, ppa must be present */
	ASSERT(wrsmdp);

	/*
	 * The teardown timeout now reschedules itself, so we
	 * have to go to great lengths to kill it.
	 */
	mutex_enter(&wrsmdp->wrsmd_lock);
	tmoid = wrsmdp->wrsmd_teardown_tmo_id;

	while (tmoid) {
		/*
		 * A timeout is scheduled to teardown the device -
		 * cancel it, as device is once again in use.
		 */
		mutex_exit(&wrsmdp->wrsmd_lock);

		(void) untimeout(tmoid);
		/*
		 * untimeout guarantees the either the function was
		 * cancelled, or it has completed.  If timeout was
		 * cancelled before the function ran, the timout id will
		 * not have changed.
		 */
		mutex_enter(&wrsmdp->wrsmd_lock);

		if (tmoid == wrsmdp->wrsmd_teardown_tmo_id)
			wrsmdp->wrsmd_teardown_tmo_id = 0;
		tmoid = wrsmdp->wrsmd_teardown_tmo_id;
	}

	/*
	 * Has WRSMD device (RSM controller) been initialized?  Do so if
	 * necessary.
	 */
	if ((wrsmdp->wrsmd_flags & WRSMDREGHANDLER) == 0) {
		if (wrsmdinit(wrsmdp)) {
			mutex_exit(&wrsmdp->wrsmd_lock);
			dlerrorack(wq, mp, dlp->dl_primitive,
				DL_INITFAILED, 0);
			D1("wrsmdareq: init failed, done");
			/* dissociate on failure */
			(void) qassociate(wq, -1);
			return;
		}
	}
	if (ssp->ss_flags & WRSMD_SLALLPHYS)
		wrsmdp->wrsmd_promisc++;

	wrsmdp->wrsmd_attached_streams++;
	mutex_exit(&wrsmdp->wrsmd_lock);


	/*
	 * Save pointer to this queue if this destination doesn't already
	 * have one
	 */

	mutex_enter(&wrsmdp->wrsmd_runq_lock);
	if (wrsmdp->wrsmd_wq == NULL)
		wrsmdp->wrsmd_wq = wq;
	mutex_exit(&wrsmdp->wrsmd_runq_lock);

	/*
	 * Set link to WRSMD device (RSM controller) and update our state.
	 */
	ssp->ss_wrsmdp = wrsmdp;
	ssp->ss_state = DL_UNBOUND;

	dlokack(wq, mp, DL_ATTACH_REQ);

	D1("wrsmdareq: done");
}

/*
 * DLPI detach request (detach stream from physical device)
 */
static void
wrsmddreq(queue_t *wq, mblk_t *mp)
{
	wrsmdstr_t *ssp;

	D1("wrsmddreq: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);

	ssp = (wrsmdstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_DETACH_REQ_SIZE) {
		dlerrorack(wq, mp, DL_DETACH_REQ, DL_BADPRIM, 0);
		D1("wrsmddreq: bad size, done");
		return;
	}

	if (ssp->ss_state != DL_UNBOUND) {
		dlerrorack(wq, mp, DL_DETACH_REQ, DL_OUTSTATE, 0);
		D1("wrsmddreq: bad state, done");
		return;
	}

	wrsmddodetach(ssp);
	(void) qassociate(wq, -1);
	dlokack(wq, mp, DL_DETACH_REQ);

	D1("wrsmddreq: done");
}

/*
 * Detach a Stream from an interface.
 */
static void
wrsmddodetach(wrsmdstr_t *ssp)
{
	wrsmdstr_t *tslp;
	wrsmd_t *wrsmdp;

	D1("wrsmddodetach: ssp 0x%p", (void *)ssp);

	ASSERT(MUTEX_HELD(&ssp->ss_lock));
	ASSERT(ssp->ss_wrsmdp);

	wrsmdp = ssp->ss_wrsmdp;

	mutex_enter(&wrsmdp->wrsmd_lock);

	/*
	 * Need to protect this assignment with wrsmd_lock mutex in case
	 * of concurrent execution of detach for different streams, to avoid
	 * detaching device structure until all streams detached.
	 */
	ssp->ss_wrsmdp = NULL;

	wrsmdp->wrsmd_attached_streams--;

	if (ssp->ss_flags & WRSMD_SLALLPHYS)
		wrsmdp->wrsmd_promisc--;

	/*
	 * Detach from device structure.
	 * Uninit the device when no other streams are attached to it.
	 */
	rw_enter(&wrsmdstruplock, RW_READER);

	for (tslp = wrsmdstrup; tslp; tslp = tslp->ss_nextp)
		if (tslp->ss_wrsmdp == wrsmdp)
			break;

	mutex_enter(&wrsmdp->wrsmd_runq_lock);
	if (tslp)
		wrsmdp->wrsmd_wq = WR(tslp->ss_rq);
	else
		wrsmdp->wrsmd_wq = NULL;
	mutex_exit(&wrsmdp->wrsmd_runq_lock);

	/* Make sure teardown only scheduled once. */
	if (wrsmdp->wrsmd_attached_streams == 0) {
		/*
		 * Schedule a teardown.  This allows queues to destinations
		 * through this controller to drain, and keeps the data
		 * structures around in case a new connection to this
		 * device is about to occur.
		 */
		ASSERT(tslp == NULL);
		wrsmdp->wrsmd_teardown_tmo_id = timeout(wrsmdteardown_tmo,
		    (caddr_t)wrsmdp, wrsmdp->wrsmd_param.wrsmd_teardown_tmo);
	}

	rw_exit(&wrsmdstruplock);

	mutex_exit(&wrsmdp->wrsmd_lock);

	ssp->ss_state = DL_UNATTACHED;

	wrsmdsetipq(wrsmdp);

	D1("wrsmddodetach: done");
}

/*
 * DLPI bind request (register interest in a particular address & SAP)
 */
static void
wrsmdbreq(queue_t *wq, mblk_t *mp)
{
	wrsmdstr_t *ssp;
	union DL_primitives *dlp;
	wrsmd_t *wrsmdp;
	wrsmddladdr_t wrsmdaddr;
	ushort_t sap;
	uint32_t xidtest;

	D1("wrsmdbreq: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);

	ssp = (wrsmdstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_BIND_REQ_SIZE) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_BADPRIM, 0);
		D1("wrsmdbreq: bad size, done");
		return;
	}

	if (ssp->ss_state != DL_UNBOUND) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_OUTSTATE, 0);
		D1("wrsmdbreq: bad state, done");
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	wrsmdp = ssp->ss_wrsmdp;
	xidtest = dlp->bind_req.dl_xidtest_flg;

	ASSERT(wrsmdp);

	if (xidtest) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_NOAUTO, 0);
		D1("wrsmdbreq: bad xidtest, done");
		return;
	}

	if (dlp->bind_req.dl_service_mode != DL_CLDLS) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_UNSUPPORTED, 0);
		return;
	}

	if (dlp->bind_req.dl_sap > MEDIUMSAP_MAX) {
		dlerrorack(wq, mp, dlp->dl_primitive, DL_BADSAP, 0);
		D1("wrsmdbreq: bad sap, done");
		return;
	}
	sap = (ushort_t)dlp->bind_req.dl_sap;

	/*
	 * Save SAP value for this Stream and change state.
	 */
	ssp->ss_sap = sap;
	ssp->ss_state = DL_IDLE;

	wrsmdaddr.dl_sap = sap;
	wrsmdaddr.dl_addr = wrsmdp->wrsmd_rsm_addr.m.ether.addr;
	dlbindack(wq, mp, (t_scalar_t)sap, (caddr_t)&wrsmdaddr,
	    WRSMD_DEVICE_ADDRL, 0, 0);

	wrsmdsetipq(wrsmdp);

	D1("wrsmdbreq: done");
}

/*
 * DLPI unbind request (cancel interest in a particular local address & SAP)
 */
static void
wrsmdubreq(queue_t *wq, mblk_t *mp)
{
	wrsmdstr_t *ssp;

	D1("wrsmdubreq: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);

	ssp = (wrsmdstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_UNBIND_REQ_SIZE) {
		dlerrorack(wq, mp, DL_UNBIND_REQ, DL_BADPRIM, 0);
		D1("wrsmdubreq: bad size, done");
		return;
	}

	if (ssp->ss_state != DL_IDLE) {
		dlerrorack(wq, mp, DL_UNBIND_REQ, DL_OUTSTATE, 0);
		D1("wrsmdubreq: bad state, done");
		return;
	}

	ssp->ss_state = DL_UNBOUND;
	ssp->ss_sap = 0;

	(void) putnextctl1(RD(wq), M_FLUSH, FLUSHRW);

	dlokack(wq, mp, DL_UNBIND_REQ);

	wrsmdsetipq(ssp->ss_wrsmdp);

	D1("wrsmdubreq: done");
}

/*
 * DLPI device information request
 */
static void
wrsmdireq(queue_t *wq, mblk_t *mp)
{
	wrsmdstr_t *ssp;
	dl_info_ack_t *dlip;
	wrsmddladdr_t *dlap;
	void *dlbcastap;
	size_t size;

	D1("wrsmdireq: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);

	ssp = (wrsmdstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_INFO_REQ_SIZE) {
		dlerrorack(wq, mp, DL_INFO_REQ, DL_BADPRIM, 0);
		D1("wrsmdireq: bad size, done");
		return;
	}

	/*
	 * Exchange current msg for a DL_INFO_ACK.
	 */
	size = sizeof (dl_info_ack_t) + WRSMD_DEVICE_ADDRL + WRSMD_BCAST_ADDRL;
	if ((mp = mexchange(wq, mp, size, M_PCPROTO, DL_INFO_ACK)) == NULL) {
		D1("wrsmdireq: bad mexchange, done");
		return;
	}

	/*
	 * Fill in the DL_INFO_ACK fields and reply.
	 */
	dlip = (dl_info_ack_t *)mp->b_rptr;
	*dlip = wrsmdinfoack;
	dlip->dl_current_state = ssp->ss_state;

	/*
	 * fill in the local DLSAP address, if connected to a controller
	 */
	dlap = (wrsmddladdr_t *)(mp->b_rptr + dlip->dl_addr_offset);
	if (ssp->ss_wrsmdp) {
		ether_copy(&(ssp->ss_wrsmdp->wrsmd_rsm_addr.m.ether.addr),
		    &(dlap->dl_addr));
		dlip->dl_max_sdu =
		    ssp->ss_wrsmdp->wrsmd_param.wrsmd_buffer_size -
		    WRSMD_CACHELINE_SIZE;
	} else {
		ether_copy(&wrsmdbadaddr, &(dlap->dl_addr));
		mutex_enter(&wrsmddevlock);
		ASSERT(wrsmdminbuflen != 0);
		dlip->dl_max_sdu = wrsmdminbuflen - WRSMD_CACHELINE_SIZE;
		mutex_exit(&wrsmddevlock);
	}
	dlap->dl_sap = ssp->ss_sap;

	/*
	 * fill in the broadcast address; it's at least short aligned
	 */
	dlbcastap = (void *)(mp->b_rptr + dlip->dl_brdcst_addr_offset);
	ether_copy(&wrsmdbcastaddr, dlbcastap);

	ASSERT(((unsigned char *)dlbcastap + WRSMD_BCAST_ADDRL) ==
	    (mp->b_rptr + size));

	qreply(wq, mp);

	D1("wrsmdireq: done");
}

/*
 * DLPI enable promiscuous mode request
 *
 * We only snoop and deliver messages that are generated by this node
 * or received by this mode.  Unlike promiscuous mode on a bus-based
 * network, we do not see (and therefore cannot deliver) messages
 * destined for other nodes.
 */
static void
wrsmdponreq(queue_t *wq, mblk_t *mp)
{
	wrsmdstr_t *ssp;

	D1("wrsmdponreq: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);

	ssp = (wrsmdstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_PROMISCON_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PROMISCON_REQ, DL_BADPRIM, 0);
		D1("wrsmdponreq: bad size, done");
		return;
	}

	switch (((dl_promiscon_req_t *)mp->b_rptr)->dl_level) {
		case DL_PROMISC_PHYS:
			if (!(ssp->ss_flags & WRSMD_SLALLPHYS)) {
				ssp->ss_flags |= WRSMD_SLALLPHYS;
				if (ssp->ss_wrsmdp) {
					mutex_enter(
					    &ssp->ss_wrsmdp->wrsmd_lock);
					ssp->ss_wrsmdp->wrsmd_promisc++;
					mutex_exit(&ssp->ss_wrsmdp->wrsmd_lock);
				}
			}
			break;

		case DL_PROMISC_SAP:
			ssp->ss_flags |= WRSMD_SLALLSAP;
			break;

		default:
			dlerrorack(wq, mp, DL_PROMISCON_REQ,
				DL_NOTSUPPORTED, 0);
			D1("wrsmdponreq: option not supported, done");
			return;
	}

	if (ssp->ss_wrsmdp)
		wrsmdsetipq(ssp->ss_wrsmdp);

	dlokack(wq, mp, DL_PROMISCON_REQ);

	D1("wrsmdponreq: done");
}

/*
 * DLPI disable promiscuous mode request
 */
static void
wrsmdpoffreq(queue_t *wq, mblk_t *mp)
{
	wrsmdstr_t *ssp;
	int flag;

	D1("wrsmdpoffreq: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);

	ssp = (wrsmdstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_PROMISCOFF_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PROMISCOFF_REQ, DL_BADPRIM, 0);
		D1("wrsmdpoffreq: bad size, done");
		return;
	}

	switch (((dl_promiscoff_req_t *)mp->b_rptr)->dl_level) {
		case DL_PROMISC_PHYS:
			flag = WRSMD_SLALLPHYS;
			break;

		case DL_PROMISC_SAP:
			flag = WRSMD_SLALLSAP;
			break;

		default:
			dlerrorack(wq, mp, DL_PROMISCOFF_REQ,
				DL_NOTSUPPORTED, 0);
			D1("wrsmdpoffreq: option not supported, done");
			return;
	}

	if ((ssp->ss_flags & flag) == 0) {
		dlerrorack(wq, mp, DL_PROMISCOFF_REQ, DL_NOTENAB, 0);
		D1("wrsmdpoffreq: mode not on, done");
		return;
	}

	ssp->ss_flags &= ~flag;

	if ((flag & WRSMD_SLALLPHYS) && ssp->ss_wrsmdp) {
		mutex_enter(&ssp->ss_wrsmdp->wrsmd_lock);
		ssp->ss_wrsmdp->wrsmd_promisc--;
		mutex_exit(&ssp->ss_wrsmdp->wrsmd_lock);
	}

	if (ssp->ss_wrsmdp)
		wrsmdsetipq(ssp->ss_wrsmdp);

	dlokack(wq, mp, DL_PROMISCOFF_REQ);

	D1("wrsmdpoffreq: done");
}

/*
 * DLPI get physical address request
 *
 * Return the PPA (RSM hardware address) of the WRSMD device (RSM controller)
 * to which this stream is attached.
 */
static void
wrsmdpareq(queue_t *wq, mblk_t *mp)
{
	wrsmdstr_t *ssp;
	union DL_primitives *dlp;
	uint32_t type;
	wrsmd_t *wrsmdp;

	D1("wrsmdpareq: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);

	ssp = (wrsmdstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_PHYS_ADDR_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		D1("wrsmdpareq: bad size, done");
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	type = dlp->physaddr_req.dl_addr_type;
	wrsmdp = ssp->ss_wrsmdp;

	if (wrsmdp == NULL) {
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_OUTSTATE, 0);
		D1("wrsmdpareq: bad state, done");
		return;
	}

	switch (type) {
		case DL_FACT_PHYS_ADDR:
		case DL_CURR_PHYS_ADDR:
			dlphysaddrack(wq, mp,
			    (void *)&(wrsmdp->wrsmd_rsm_addr.m.ether.addr),
			    sizeof (wrsmdp->wrsmd_rsm_addr.m.ether.addr));
			D1("wrsmdpareq: done");
			return;

		default:
			dlerrorack(wq, mp, DL_PHYS_ADDR_REQ,
				DL_NOTSUPPORTED, 0);
			D1("wrsmdpoffreq: option not supported, done");
			return;
	}
}

/*
 * DLPI unit data send request
 */
static void
wrsmdudreq(queue_t *wq, mblk_t *mp)
{
	wrsmdstr_t *ssp;
	register wrsmd_t *wrsmdp;
	register dl_unitdata_req_t *dludp;
	mblk_t *nmp;
	wrsmddladdr_t *dlap;
	uint32_t off, len;

	ushort_t sap;
	dl_rsm_addr_t addr;

	D1("wrsmdudreq: wq 0x%p, mp 0x%p", (void *)wq, (void *)mp);

	ssp = (wrsmdstr_t *)wq->q_ptr;
	wrsmdp = ssp->ss_wrsmdp;

	if (wrsmdp == NULL) {
		dlerrorack(wq, mp, DL_UNITDATA_REQ, DL_OUTSTATE, 0);
		D1("wrsmdudreq: bad state, done");
		return;
	}

	dludp = (dl_unitdata_req_t *)mp->b_rptr;

	off = dludp->dl_dest_addr_offset;
	len = dludp->dl_dest_addr_length;

	/*
	 * Validate destination address format.
	 */
	if (!MBLKIN(mp, off, len) || (len != WRSMD_DEVICE_ADDRL)) {
		dluderrorind(wq, mp, (uchar_t *)(mp->b_rptr + off), len,
		    DL_BADADDR, 0);
#ifdef DEBUG_WRSMD
		dlap = (wrsmddladdr_t *)(mp->b_rptr + off);
		ether_copy(&(dlap->dl_addr), &(addr.m.ether.addr));
		addr.m.ether.zero = 0;
		sap = (uint16_t)((((uchar_t *)(&dlap->dl_sap))[0] << 8) |
					((uchar_t *)(&dlap->dl_sap))[1]);
		D2("wrsmdudreq bad addr: ADDRL %ld addr len %d, rsm addr 0x%lx "
		    "sap 0x%x",
		    WRSMD_DEVICE_ADDRL, len, addr.m.rsm, sap);
		D1("wrsmdudreq: bad addr, done");
#endif
		return;
	}

	/*
	 * Error if no M_DATA follows.
	 */
	nmp = mp->b_cont;
	if (nmp == NULL) {
		dluderrorind(wq, mp, (uchar_t *)(mp->b_rptr + off), len,
			DL_BADDATA, 0);
		D1("wrsmdudreq: bad data, done");
		return;
	}

	/* Extract address information. */

	dlap = (wrsmddladdr_t *)(mp->b_rptr + off);

	ether_copy(&(dlap->dl_addr), &(addr.m.ether.addr));
	addr.m.ether.zero = 0;
	sap = (uint16_t)((((uchar_t *)(&dlap->dl_sap))[0] << 8) |
				((uchar_t *)(&dlap->dl_sap))[1]);

	/* Discard DLPI header. */

	freeb(mp);

	/*
	 * Transmit message.
	 */
	wrsmdstart(wrsmdp, nmp, addr, sap, 0);

	D1("wrsmdudreq: done");
}



/*
 * ****************************************************************
 *                                                               *
 * E N D       DLPI OPERATIONS                                   *
 *                                                               *
 * ****************************************************************
 */


/*
 * ****************************************************************
 *                                                               *
 * B E G I N   HIGH LEVEL PROTOCOL INTERFACE AND UTILITIES       *
 *                                                               *
 * ****************************************************************
 */


/*
 * An outgoing raw packet has a header at the beginning, telling us the
 * destination address and SAP.  Since this header is not used by the
 * Wildcat hardware in this form, we call it the "fake hardware header".
 *
 * This routine parses the fake hardware header at the start of mp, strips
 * the header from mp then returns address and sap.  It returns a pointer
 * to the stripped mblk, which may or may not be the same pointer which was
 * passed in, or NULL if there's no data to send.
 */

static mblk_t *
wrsmdstrip(
	mblk_t *mp,		/* Packet to parse & strip header from */
	dl_rsm_addr_t *addrp,	/* Address packet addressed to (returned) */
	ushort_t *sapp)		/* SAP packet addressed to (returned) */
{
	D1("wrsmdstrip: mp 0x%p", (void *)mp);

	if (MBLKIN(mp, 0, sizeof (struct ether_header))) {
		struct ether_header *mh = (struct ether_header *)mp->b_rptr;

		/*
		 * Parse header; it's at least short aligned.
		 */

		ether_copy(&(mh->ether_dhost), &(addrp->m.ether.addr));
		addrp->m.ether.zero = 0;
		*sapp = mh->ether_type;

		/* Strip off header */

		mp->b_rptr += sizeof (struct ether_header);

		/*
		 * If there's nothing left in this mblk, and there are more
		 * following, get rid of it.  If there's nothing left, and
		 * there aren't more following, we have a zero-length
		 * message; return an error.  (A following mblk might
		 * conceivably be empty, giving us a zero-length message as
		 * well; we don't check for this.)
		 */
		if (mp->b_rptr == mp->b_wptr) {
			if (mp->b_cont != NULL) {
				mblk_t *nmp;

				nmp = mp->b_cont;
				freeb(mp);
				D1("wrsmdstrip: returning 1");
				return (nmp);
			} else {
				freemsg(mp);
				D1("wrsmdstrip: returning 0");
				return (NULL);
			}
		} else {
			D1("wrsmdstrip: returning 1");
			return (mp);
		}
	} else {
		D1("wrsmdstrip: returning 0");
		freemsg(mp);
		return (NULL);
	}
}



/*
 * Queue the message to the proper destination structure, creating the
 * destination if necessary.  Discard the message if required.
 * If from_put is true, and there are no other messages queued to this
 * destination or being transmitted, start this message transmitting.
 * Schedule destination for service, if necessary. The function returns
 * true is message was successfully queued.
 */
boolean_t
wrsmdqueuemsg(wrsmd_t *wrsmdp, mblk_t *orig_mp, dl_rsm_addr_t addr,
    ushort_t sap, int from_put, boolean_t copy)
{
	wrsmd_dest_t *rd;
	int isdel = 0;
	int isnew = 0;
	timeout_id_t tmoid;
	mblk_t *mp;

	if (copy) {
		mp = dupmsg(orig_mp);
		if (!mp)
			return (B_FALSE);
	} else {
		mp = orig_mp;
	}

	/* Find destination structure for this message */
	D1("wrsmdqueuemsg: ctlr %d\n", wrsmdp->wrsmd_ctlr_id);

	MAKEDEST(rd, isdel, isnew, wrsmdp, addr.m.wrsm.addr);

	if (isdel) {
		wrsmdp->wrsmd_oerrors++;
		if (copy) {
			freemsg(mp);
		}
		DERR("wrsmdqueuemsg: TOSS!!! dest being deleted, "
		    "toss packet, done");
		TNF_PROBE_1(wrsmdqueuemsg_end, "RSMPI",
		    "wrsmdqueuemsg end; failure destbeingdel",
		    tnf_string, failure, "destbeingdel");
		return (B_FALSE);
	} else if (isnew) {
		if (rd == NULL) {
			wrsmdp->wrsmd_oerrors++;
			if (copy) {
				freemsg(mp);
			}
			DERR("wrsmdqueuemsg: TOSS!!! can't mkdest, "
			    "toss packet, done");
			TNF_PROBE_1(wrsmdqueuemsg_end, "RSMPI",
			    "wrsmdqueuemsg end; failure cantmkdest",
			    tnf_string, failure, "cantmkdest");
			return (B_FALSE);
		}
	}

	/* if state was new, move to req_connect */
	(void) wrsmdmovestate(rd, WRSMD_STATE_NEW, WRSMD_STATE_S_REQ_CONNECT);

	mutex_enter(&rd->rd_xmit_lock);

	/* Make sure we don't have too many queued already */

	if (rd->rd_queue_len >=
	    wrsmdp->wrsmd_param.wrsmd_max_queued_pkts) {
		if (copy) {
			freemsg(mp);
		}
		wrsmdp->wrsmd_oerrors++;
		wrsmdp->wrsmd_maxq_drops++;
		DERR("wrsmdqueuemsg: TOSS!!! too many queued (%d), "
		    "toss packet, done",
		    rd->rd_queue_len);
		mutex_exit(&rd->rd_xmit_lock);
		UNREFDEST(rd);
		TNF_PROBE_1(wrsmdqueuemsg_end, "RSMPI",
		    "wrsmdqueuemsg end; failure 2manyqueued",
		    tnf_string, failure, "2manyqueued");
		return (B_FALSE);
	}

	if (rd->rd_queue_h == NULL)
		rd->rd_queue_h = mp;
	else
		rd->rd_queue_t->b_next = mp;
	rd->rd_queue_t = mp;
	rd->rd_queue_len++;

	/*
	 * Since we're making a singly-linked list of mblks hanging off the
	 * destination structure, we can get away with stashing the destination
	 * SAP in the b_prev pointer of the mblk.  This is pretty disgusting,
	 * but is much more efficient than the alternative: allocating a new
	 * structure with space for the SAP and a pointer to the mblk, and
	 * making a list of those instead.
	 */

	mp->b_prev = (mblk_t *)(uintptr_t)sap;

	wrsmdp->wrsmd_starts++;

	if (wrsmdisstate(rd, WRSMD_STATE_W_READY)) {
		if (from_put) {
			wrsmdp->wrsmd_start_xfers++;
			wrsmdxfer(wrsmdp, rd);
		} else
			wrsmdsetstate_nosrv(rd, WRSMD_STATE_S_XFER);

	} else if (wrsmdisstate(rd, WRSMD_STATE_W_FQE)) {
		if (wrsmdavailfqe(rd)) {
			tmoid = rd->rd_fqe_tmo_id;
			rd->rd_fqe_tmo_id = 0;
			rd->rd_tmo_int = 0;
			mutex_exit(&rd->rd_xmit_lock);
			if (tmoid)
				(void) untimeout(tmoid);
			mutex_enter(&rd->rd_xmit_lock);

			if (from_put) {
				wrsmdp->wrsmd_start_xfers++;
				wrsmdxfer(wrsmdp, rd);
			} else
				wrsmdsetstate_nosrv(rd, WRSMD_STATE_S_XFER);
		} else {
			/*
			 * no FQEs available, return to waiting state
			 */
			wrsmdsetstate(rd, WRSMD_STATE_W_FQE);
		}
	}

	mutex_exit(&rd->rd_xmit_lock);

	UNREFDEST(rd);

	return (B_TRUE);
}


/*
 * Verify whether this is a valid message.  Determine whether this is a
 * broadcast message; send message to each recipient.  Handle promiscuous
 * mode.
 */
static void
wrsmdstart(wrsmd_t *wrsmdp, mblk_t *mp, dl_rsm_addr_t addr, ushort_t sap,
    int from_put)
{
	int i;
	boolean_t retval;

	D1("wrsmdstart: wrsmdp 0x%p (cltr %d), mp 0x%p, rsmaddr %ld, sap 0x%x, "
	    "from_put %d", (void *)wrsmdp, wrsmdp ? wrsmdp->wrsmd_ctlr_id : -1,
	    (void *)mp, addr.m.rsm, sap, from_put);
	TNF_PROBE_5(wrsmdstart_start, "RSMPI", "wrsmdstart start",
	    tnf_ulong, wrsmdp, (ulong_t)wrsmdp, tnf_ulong, mp,
	    (ulong_t)mp, tnf_uint, addr.m.rsm, addr.m.rsm, tnf_uint,
	    sap, sap, tnf_int, from_put, from_put);

	/* Make sure we're not sending to ourselves */

	if (addr.m.rsm == wrsmdp->wrsmd_rsm_addr.m.rsm) {
		wrsmdp->wrsmd_oerrors++;
		freemsg(mp);
		DERR("wrsmdstart: TOSS!!! sending to ourselves, toss packet, "
		    "done");
		TNF_PROBE_1(wrsmdstart_end, "RSMPI",
		    "wrsmdstart end; failure sendtoself",
		    tnf_string, failure, "sendtoself");
		return;
	}

	/* Make sure message is contiguous in memory */

	if (mp->b_cont) {
		mblk_t *nmp;

		nmp = msgpullup(mp, -1);
		freemsg(mp);

		if (nmp == NULL) {
			wrsmdp->wrsmd_pullup_fail++;
			wrsmdp->wrsmd_oerrors++;
			DERR("wrsmdstart: TOSS!!! can't pullup message, "
			    "toss packet, "
			    "done");
			return;
		}
		wrsmdp->wrsmd_pullup++;
		mp = nmp;
	}

	/* Make sure message isn't too big */

	if (MBLKL(mp) > (wrsmdp->wrsmd_param.wrsmd_buffer_size -
	    WRSMD_CACHELINE_SIZE)) {
		wrsmdp->wrsmd_oerrors++;
		freemsg(mp);
		DERR("wrsmdstart: TOSS!!! message too big, toss packet, done");
		TNF_PROBE_1(wrsmdstart_end, "RSMPI",
		    "wrsmdstart end; failure msgtoobig",
		    tnf_string, failure, "msgtoobig");
		return;
	}

	/*
	 * Send message to each addressee (normally there is just one).
	 */

	/* Loop message back up if we're in promiscuous mode */
	if (wrsmdp->wrsmd_promisc) {
		mblk_t *nmp;

		if (nmp = dupmsg(mp))
			wrsmdpromsendup(wrsmdp, nmp, addr,
			    wrsmdp->wrsmd_rsm_addr, sap);
	}

	if (addr.m.rsm > RSM_MAX_DESTADDR) {
		/*
		 * handle broadcast and multicast messages
		 */
		rsm_addr_t addr_list[RSM_MAX_DESTADDR];
		uint_t num_addrs;
		boolean_t copy;

		D1("wrsmdstart: broadcast message; collect peers");

		if (RSM_GET_PEERS(wrsmdp->wrsmd_ctlr,
		    addr_list, RSM_MAX_DESTADDR, &num_addrs) != RSM_SUCCESS) {
			D1("wrsmdstart: cannot collect list of peers "
			    "for broadcast");
			wrsmdp->wrsmd_oerrors++;
			freemsg(mp);
			return;
		}

		ASSERT(num_addrs <= RSM_MAX_DESTADDR);

		/*
		 * Make a copy of the message for all but the last
		 * recipient.  Don't broadcast to the local node.
		 */
		for (i = 0; i < num_addrs; i++) {
			if (addr_list[i] == wrsmdp->wrsmd_rsm_addr.m.rsm)
				continue;
			/*
			 * If this is the last node or if this is the
			 * second to last and the last is ourselves,
			 * don't make a copy of the message.
			 */
			if ((i == (num_addrs - 1)) ||
			    ((i == (num_addrs - 2)) &&
			    addr_list[i+1] == wrsmdp->wrsmd_rsm_addr.m.rsm)) {
				copy = B_FALSE;
			} else {
				copy = B_TRUE;
			}
			addr.m.rsm = addr_list[i];
			retval = wrsmdqueuemsg(wrsmdp, mp, addr, sap,
			    from_put, copy);
			if (copy == B_FALSE && retval == B_FALSE) {
				freemsg(mp);
			}
		}

	} else {
		retval = wrsmdqueuemsg(wrsmdp, mp, addr, sap,
		    from_put, B_FALSE);
		if (retval == B_FALSE) {
			freemsg(mp);
		}
	}

	D1("wrsmdstart: done");
	TNF_PROBE_1(wrsmdstart_end, "RSMPI", "wrsmdstart end",
	    tnf_string, completed, "");
}


/*
 * These macros are used in several places in wrsmdsendup().
 */

/*
 * Return 1 if the stream pointed to by wrsmdstr is connected to wrsmdp and
 * interested in this sap.
 */
#define	WRSMDSAPMATCH(wrsmdp, wrsmdstr, sap)	\
	(((wrsmdstr)->ss_wrsmdp == wrsmdp) &&	\
	((wrsmdstr)->ss_sap == (sap) ||		\
	    ((wrsmdstr)->ss_flags & WRSMD_SLALLSAP)))

/*
 * Return 1 if the stream pointed to by wrsmdstr is connected to wrsmdp,
 * interested in all saps, and in physical promiscuous mode.
 */
#define	WRSMDPROMMATCH(wrsmdp, wrsmdstr)		\
	(((wrsmdstr)->ss_wrsmdp == wrsmdp) &&		\
	    ((wrsmdstr)->ss_flags & WRSMD_SLALLSAP) &&	\
	    ((wrsmdstr)->ss_flags & WRSMD_SLALLPHYS))
/*
 * Do appropriate processing to send message msg up stream wrsmdstr.
 * "name" is the name of the calling routine, used for debugging messages;
 * to, from and sap are the packet's to address, from address, and SAP.
 */
#define	WRSMDMSGPROC(wrsmdp, wrsmdstr, msg, name, to, from, sap) {	\
	D2(name " : checking msg 0x%p queue 0x%p",			\
	    (void *)(msg), (void *)(wrsmdstr)->ss_rq);			\
	if ((wrsmdstr)->ss_flags & WRSMD_SLFAST) {			\
		(void) putnext((wrsmdstr)->ss_rq, (msg));		\
	} else if ((wrsmdstr)->ss_flags & WRSMD_SLRAW) {		\
		if ((msg) = wrsmdaddhdr(wrsmdp, (msg), (to),		\
		    (from), (sap)))					\
			(void) putnext((wrsmdstr)->ss_rq,		\
			    (msg));					\
	} else if ((msg) = wrsmdaddudind(wrsmdp, (msg), (to),		\
	    (from), (sap))) {						\
		D2(name " : sending msg 0x%p up queue 0x%p",		\
		    (void *)(msg), (void *)(wrsmdstr)->ss_rq);		\
		(void) putnext((wrsmdstr)->ss_rq, (msg));		\
	}								\
}

/*
 * Send packet upstream.
 */
static void
wrsmdsendup(
	wrsmd_t *wrsmdp,	/* WRSMD device (RSM controller) pointer */
	mblk_t *mp,	/* Message to send up */
	dl_rsm_addr_t to,	/* Address packet was sent to */
	dl_rsm_addr_t from,	/* Address packet was received from */
	ushort_t sap)	/* Packet's SAP */
{
	wrsmdstr_t *ssp, *nssp;
	mblk_t *nmp;

	D1("wrsmdsendup: wrsmdp 0x%p (cltr %d), mp 0x%p, to %ld, from %ld, "
	    "sap 0x%x", (void *)wrsmdp, wrsmdp->wrsmd_ctlr_id, (void *)mp,
	    to.m.rsm, from.m.rsm, sap);
	TNF_PROBE_5(wrsmdsendup_start, "RSMPI", "wrsmdsendup start",
	    tnf_ulong, wrsmdp, (ulong_t)wrsmdp, tnf_ulong, mp, (ulong_t)mp,
	    tnf_long, to.m.rsm, to.m.rsm, tnf_long, from.m.rsm, from.m.rsm,
	    tnf_long, sap, sap);

	/*
	 * While holding a reader lock on the linked list of streams
	 * structures, attempt to match the address criteria for each stream
	 * and pass up the DL_UNITDATA_IND.
	 */

	rw_enter(&wrsmdstruplock, RW_READER);

	/*
	 * This is pretty tricky.  If there are multiple streams that want
	 * this packet, we have to make a new copy for all but one of them
	 * (we can send the original packet up one of the streams).  However,
	 * if we do things the straightforward way:
	 *
	 *	while (stream wants packet)
	 *		newmsg = copy (msg);
	 *		send newmsg up stream
	 *		go to next stream
	 *	free oldmsg
	 *
	 * we end up always doing a copy, even if (as is usually the case)
	 * the packet only goes to one stream.  This is bad.  Thus what we do
	 * is the following:
	 *
	 *	Find a stream that wants this packet.  If there aren't any,
	 *		we're done.
	 *	For each other stream that wants this packet, make a copy of
	 *		it and send it up.
	 *	Finally, send the original packet up the first stream we found.
	 */

	for (ssp = wrsmdstrup; ssp; ssp = ssp->ss_nextp) {
		D1("wrsmdsendup ssp->ss_sap 0x%x flags 0x%x", ssp->ss_sap,
		    ssp->ss_flags);
		if (WRSMDSAPMATCH(wrsmdp, ssp, sap))
			break;
	}

	if (ssp) {
		TNF_PROBE_3(wrsmdsendup_SMPfor, "RSMPI",
		    "wrsmdsendup SMPfor", tnf_long, to.m.rsm, to.m.rsm,
		    tnf_long, from.m.rsm, from.m.rsm, tnf_long, sap, sap);
		for (nssp = ssp->ss_nextp; nssp; nssp = nssp->ss_nextp) {
			D1("wrsmdsendup nssp->ss_sap 0x%x flags 0x%x",
			    nssp->ss_sap, ssp->ss_flags);
			if (WRSMDSAPMATCH(wrsmdp, nssp, sap) &&
			    canputnext((queue_t *)nssp->ss_rq) &&
			    (nmp = dupmsg(mp))) {
				WRSMDMSGPROC(wrsmdp, nssp, nmp, "wrsmdsendup",
				    to, from, sap);
			}
		}
		TNF_PROBE_1(wrsmdsendup_SMPforend, "RSMPI",
		    "wrsmdsendup SMPforend", tnf_string, completed, "");
		/*
		 * Do the last one.
		 */
		if (canputnext((queue_t *)ssp->ss_rq)) {
			TNF_PROBE_5(wrsmdsendup_SMPlast, "RSMPI",
			    "wrsmdsendup SMPlast", tnf_ulong, ssp, (ulong_t)ssp,
			    tnf_ulong, mp, (ulong_t)mp, tnf_long, to.m.rsm,
			    to.m.rsm, tnf_long, from.m.rsm, from.m.rsm,
			    tnf_long, sap, sap);
			WRSMDMSGPROC(wrsmdp, ssp, mp, "wrsmdsendup", to, from,
			    sap);
			TNF_PROBE_1(wrsmdsendup_SMPlastend, "RSMPI",
			    "wrsmdsendup SMPlastend", tnf_string, completed,
			    "");
		} else
			freemsg(mp);
	} else
		freemsg(mp);

	rw_exit(&wrsmdstruplock);

	D1("wrsmdsendup: done");
	TNF_PROBE_1(wrsmdsendup_end, "RSMPI", "wrsmdsendup end",
	    tnf_string, completed, "");
}

/*
 * Send outgoing packet upstream to promiscuous mode readers.  This routine
 * is an exact duplicate of wrsmdsendup(), above, except that we use
 * WRSMDPROMMATCH instead of WRSMDSAPMATCH.  (The difference is that
 * the latter only selects streams which are in promiscuous mode; this
 * keeps IP from getting its own packets back, since we don't check the
 * destination addresses when sending packets upstream.)
 */
static void
wrsmdpromsendup(
	wrsmd_t *wrsmdp,	/* WRSMD device (RSM controller) pointer */
	mblk_t *mp,	/* Message to send up */
	dl_rsm_addr_t to,	/* Address packet was sent to */
	dl_rsm_addr_t from,	/* Address packet was received from */
	ushort_t sap)	/* Packet's SAP */
{
	wrsmdstr_t *ssp, *nssp;
	mblk_t *nmp;

	D1("wrsmdpromsendup: wrsmdp 0x%p (cltr %d), mp 0x%p, to %ld, from %ld, "
	    "sap 0x%x", (void *)wrsmdp, wrsmdp ? wrsmdp->wrsmd_ctlr_id : -1,
	    (void *)mp, to.m.rsm,
	    from.m.rsm, sap);

	/*
	 * While holding a reader lock on the linked list of streams structures,
	 * attempt to match the address criteria for each stream
	 * and pass up the DL_UNITDATA_IND.
	 */

	rw_enter(&wrsmdstruplock, RW_READER);

	/*
	 * See explanation above of why this is somewhat less than
	 * straightforward.
	 */

	for (ssp = wrsmdstrup; ssp; ssp = ssp->ss_nextp) {
		if (WRSMDPROMMATCH(wrsmdp, ssp))
			break;
	}

	if (ssp) {
		for (nssp = ssp->ss_nextp; nssp; nssp = nssp->ss_nextp)
			if (WRSMDPROMMATCH(wrsmdp, nssp) &&
			    canputnext((queue_t *)nssp->ss_rq) &&
			    (nmp = dupmsg(mp)))
				WRSMDMSGPROC(wrsmdp, nssp, nmp,
				    "wrsmdpromsendup", to, from, sap);
		/*
		 * Do the last one.
		 */
		if (canputnext((queue_t *)ssp->ss_rq)) {
			WRSMDMSGPROC(wrsmdp, ssp, mp, "wrsmdpromsendup",
			    to, from, sap);
		} else
			freemsg(mp);
	} else
		freemsg(mp);

	rw_exit(&wrsmdstruplock);

	D1("wrsmdpromsendup: done");
}

/*
 * Prefix msg with a DL_UNITDATA_IND mblk and return the new msg.  If we
 * can't, free the msg and return NULL.
 */
static mblk_t *
wrsmdaddudind(
	wrsmd_t *wrsmdp,	/* WRSMD device (RSM controller) pointer */
	mblk_t *mp,		/* Message to add indication to */
	dl_rsm_addr_t to,	/* Address packet was sent to */
	dl_rsm_addr_t from,	/* Address packet was received from */
	ushort_t sap)	/* Packet's SAP */
{
	dl_unitdata_ind_t *dludindp;
	wrsmddladdr_t *dlap;
	mblk_t *nmp;
	size_t size;

	D1("wrsmdaddudind: wrsmdp 0x%p (cltr %d), mp 0x%p, to %ld, from %ld, "
	    "sap 0x%x", (void *)wrsmdp, wrsmdp->wrsmd_ctlr_id, (void *)mp,
	    to.m.rsm, from.m.rsm, sap);

	/*
	 * Allocate an M_PROTO mblk for the DL_UNITDATA_IND.
	 * Allocate enough room in mblk that IP/TCP can prepend their
	 * own headers as well.
	 */
	size = sizeof (dl_unitdata_ind_t) + WRSMD_DEVICE_ADDRL +
	    WRSMD_DEVICE_ADDRL;
	if ((nmp = allocb(WRSMDHEADROOM + size, BPRI_LO)) == NULL) {
		wrsmdp->wrsmd_ierrors++;
		freemsg(mp);
		D1("wrsmdaddudind: bad allocb, returning NULL");
		return (NULL);
	}
	DB_TYPE(nmp) = M_PROTO;
	nmp->b_wptr = nmp->b_datap->db_lim;
	nmp->b_rptr = nmp->b_wptr - size;

	/*
	 * Construct a DL_UNITDATA_IND primitive.
	 */
	dludindp = (dl_unitdata_ind_t *)nmp->b_rptr;
	dludindp->dl_primitive = DL_UNITDATA_IND;
	dludindp->dl_dest_addr_length = WRSMD_DEVICE_ADDRL;
	dludindp->dl_dest_addr_offset = sizeof (dl_unitdata_ind_t);
	dludindp->dl_src_addr_length = WRSMD_DEVICE_ADDRL;
	dludindp->dl_src_addr_offset = sizeof (dl_unitdata_ind_t) +
	    WRSMD_DEVICE_ADDRL;

	dludindp->dl_group_address = 0;

	/* plug in dest addr */
	dlap = (wrsmddladdr_t *)(nmp->b_rptr + sizeof (dl_unitdata_ind_t));
	ether_copy(&(to.m.ether.addr), &(dlap->dl_addr));
	dlap->dl_sap = sap;

	/* plug in src addr */
	dlap = (wrsmddladdr_t *)
	    (nmp->b_rptr + sizeof (dl_unitdata_ind_t) + WRSMD_DEVICE_ADDRL);
	ether_copy(&(from.m.ether.addr), &(dlap->dl_addr));
	dlap->dl_sap = 0; /* we don't have this info */

	/*
	 * Link the M_PROTO and M_DATA together.
	 */
	linkb(nmp, mp);

	D1("wrsmdaddudind: new header follows");

	D3D(nmp->b_rptr, MBLKL(nmp));
	D1("wrsmdaddudind: returning 0x%p", (void *)nmp);

	return (nmp);
}

/*
 * Prefix msg with a "fake hardware header" (either in-place, or in a
 * separate mblk)and return the new msg.  If we can't, free the msg and
 * return NULL.
 */
static mblk_t *
wrsmdaddhdr(
	wrsmd_t *wrsmdp,	/* WRSMD device (RSM controller) pointer */
	mblk_t *mp,		/* Message to add indication to */
	dl_rsm_addr_t to,	/* Address packet was sent to */
	dl_rsm_addr_t from,	/* Address packet was received from */
	ushort_t sap)		/* Packet's SAP */
{
	mblk_t *nmp;
	struct ether_header *headerp;

	D1("wrsmdaddhdr: wrsmdp 0x%p (cltr %d), mp 0x%p, to %ld, from %ld, "
	    "sap 0x%x", (void *)wrsmdp, wrsmdp ? wrsmdp->wrsmd_ctlr_id : -1,
	    (void *)mp, to.m.rsm, from.m.rsm, sap);

	/*
	 * Create link-level header by either prepending it onto the
	 * data if possible, or allocating a new mblk if not.
	 */
	if ((DB_REF(mp) == 1) &&
	    (MBLKHEAD(mp) >= sizeof (struct ether_header)) &&
	    (((uintptr_t)mp->b_rptr & 0x1) == 0)) {
		mp->b_rptr -= sizeof (struct ether_header);
		headerp = (struct ether_header *)mp->b_rptr;
	} else {
		/* Allocate an M_DATA mblk for the header. */
		if ((nmp = allocb(sizeof (struct ether_header),
		    BPRI_LO)) == NULL) {
			wrsmdp->wrsmd_ierrors++;
			freemsg(mp);
			D1("wrsmdaddhdr: bad allocb, returning NULL");
			return (NULL);
		}
		DB_TYPE(nmp) = M_DATA;
		linkb(nmp, mp);
		mp = nmp;
		headerp = (struct ether_header *)mp->b_rptr;
		mp->b_wptr += sizeof (*headerp);
	}

	/*
	 * Fill in header.  It is at least short aligned.
	 */

	ether_copy(&(to.m.ether.addr), &(headerp->ether_dhost));
	ether_copy(&(from.m.ether.addr), &(headerp->ether_shost));
	headerp->ether_type = sap;

	D1("wrsmdaddhdr: returning 0x%p", (void *)mp);

	return (mp);
}



/*
 * Callback routine, called when an desballoc'ed buffer is eventually freed.
 */
static void
wrsmdfreebuf(
	wrsmdbuf_t *rbp)	/* Structure describing freed buffer */
{
	wrsmd_dest_t *rd = rbp->rb_rd;
	int delflg, zerflg;

	D1("wrsmdfreebuf: rbp 0x%p", (void *)rbp);

	/*
	 * Find out if this is the last outstanding buffer, and whether we're
	 * being deleted.
	 */
	mutex_enter(&rd->rd_nlb_lock);

	rd->rd_nlb--;
	delflg = rd->rd_nlb_del;
	zerflg = (rd->rd_nlb == 0);

	mutex_exit(&rd->rd_nlb_lock);

	/*
	 * If we're being deleted, we don't put this buffer on the free queue.
	 * Also, if we're being deleted, and this was the last outstanding
	 * buffer, we do an UNREF.  Otherwise we send this buffer to the other
	 * system for reuse.
	 */
	if (delflg) {
		if (zerflg)
			UNREFDEST(rd);
	} else {
		wrsmdputfqe(rd, rbp->rb_bufnum);
		mutex_enter(&rd->rd_net_lock);
		wrsmdsyncfqe(rd);
		mutex_exit(&rd->rd_net_lock);
	}

	D1("wrsmdfreebuf: done");
}

/*
 * wrsmdread() takes the packet described by the arguments and sends it
 * upstream.
 */
static int
wrsmdread(
	wrsmd_dest_t *rd,	/* Destination pointer */
	int bufnum,	/* Index of buffer containing packet */
	int offset,	/* Offset of packet within buffer */
	int length,	/* Length of packet */
	ushort_t sap)	/* SAP for packet */
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;
	mblk_t *mp;
	dl_rsm_addr_t from;
	int canloan = B_FALSE;
	caddr_t bufptr;
	queue_t *ipq;
	int buffree = 0;

	D1("wrsmdread: rd 0x%p, bufnum %d, offset %d, length %d, sap 0x%x",
	    (void *)rd, bufnum, offset, length, sap);

	TNF_PROBE_5(wrsmdread_start, "RSMPI", "wrsmdread start",
	    tnf_long, rd, (tnf_long_t)rd, tnf_long, bufnum, bufnum,
	    tnf_long, offset, offset, tnf_long, length, length,
	    tnf_long, sap, sap);

	bufptr = (caddr_t)rd->rd_lbuf + (bufnum * rd->rd_lbuflen);
	from.m.rsm = rd->rd_rsm_addr;

	/* Figure out if we can loan this buffer up or not */

	mutex_enter(&rd->rd_nlb_lock);
	if (rd->rd_nlb < (wrsmdp->wrsmd_param.wrsmd_buffers -
	    wrsmdp->wrsmd_param.wrsmd_buffers_retained)) {
		rd->rd_nlb++;
		canloan = B_TRUE;
	}
	mutex_exit(&rd->rd_nlb_lock);


	if (canloan) {
		/*
		 * We make the mblk cover the whole buffer in case anybody
		 * wants the leading/trailing space; below we adjust the
		 * rptr/wptr to describe the actual packet.
		 */
		mp = desballoc((uchar_t *)bufptr, rd->rd_lbuflen,
		    BPRI_LO, &(rd->rd_bufbase+bufnum)->rb_frtn);

		if (mp == NULL) {
			mutex_enter(&rd->rd_nlb_lock);
			rd->rd_nlb--;
			mutex_exit(&rd->rd_nlb_lock);

			wrsmdputfqe(rd, bufnum);
			buffree = 1;

			wrsmdp->wrsmd_ierrors++;
			D1("wrsmdread: can't desballoc, done");
			TNF_PROBE_1(wrsmdread_end, "RSMPI",
			    "wrsmdread end; failure desballoc",
			    tnf_string, failure, "desballoc");
			return (1);
		}
		mp->b_rptr += offset;
		mp->b_wptr = mp->b_rptr + length;

		wrsmdp->wrsmd_lbufs++;
		D3D(mp->b_rptr, length);
	} else {
		/*
		 * We make the destination (within the new mblk) have the
		 * same address mod 64 as our source, so that the kernel
		 * bcopy is as efficient as possible.  (This is a sun4u
		 * bcopy optimization, not a Wildcat/RSM optimization.)
		 */
		mp = allocb(length + 0x40, BPRI_LO);
		if (mp) {
			intptr_t dstoffset = (intptr_t)mp->b_rptr;

			dstoffset = offset - (dstoffset & 0x3f);
			if (dstoffset < 0)
				dstoffset += 0x40;

			mp->b_rptr += dstoffset;
			mp->b_wptr = mp->b_rptr + length;
			bcopy((void *)(bufptr + offset), (void *)mp->b_rptr,
			    length);

			D3D(mp->b_rptr, length);

			wrsmdp->wrsmd_nlbufs++;
			wrsmdputfqe(rd, bufnum);
			buffree = 1;
		} else {
			wrsmdputfqe(rd, bufnum);
			buffree = 1;
			wrsmdp->wrsmd_ierrors++;
			D1("wrsmdread: can't allocb, done");
			TNF_PROBE_1(wrsmdread_end, "RSMPI",
			    "wrsmdread end; failure allocb",
			    tnf_string, failure, "allocb");
			return (1);
		}
	}

	wrsmdp->wrsmd_ipackets++;
	wrsmdp->wrsmd_in_bytes += length;


	/*
	 * IP shortcut
	 */
	rw_enter(&wrsmdp->wrsmd_ipq_rwlock, RW_READER);
	ipq = wrsmdp->wrsmd_ipq;

	if (ipq && (sap == WRSMD_IP_SAP)) {
		if (canputnext(ipq)) {
			TNF_PROBE_2(wrsmdread_IPscut, "RSMPI",
			    "wrsmdread IPscut", tnf_long, ipq, (tnf_long_t)ipq,
			    tnf_long, mp, (tnf_long_t)mp);
			putnext(ipq, mp);
			TNF_PROBE_1(wrsmdread_IPscutend, "RSMPI",
			    "wrsmdread IPscutend", tnf_string, completed, "");
		} else
			freemsg(mp);
	} else
		wrsmdsendup(wrsmdp, mp, wrsmdp->wrsmd_rsm_addr, from,
		    sap);

	rw_exit(&wrsmdp->wrsmd_ipq_rwlock);

	D1("wrsmdread: canloan was %d, done", canloan);
	TNF_PROBE_1(wrsmdread_end, "RSMPI", "wrsmdread end",
	    tnf_string, completed, "");

	return (buffree);
}

/*
 * ****************************************************************
 *                                                               *
 * E N D       HIGH LEVEL PROTOCOL INTERFACE AND UTILITIES       *
 *                                                               *
 * ****************************************************************
 */


/*
 * ****************************************************************
 *                                                               *
 * B E G I N   RSM SETUP/TAKEDOWN                                *
 *                                                               *
 * ****************************************************************
 */

/*
 * Initialize WRSMD resources.  Return 0 on success, nonzero on error.
 */
static int
wrsmdinit(wrsmd_t *wrsmdp)	/* WRSMD device (RSM controller) pointer */
{
	int stat;

	D1("wrsmdinit: wrsmdp 0x%p (cltr %d)", (void *)wrsmdp,
	    wrsmdp->wrsmd_ctlr_id);

	ASSERT(MUTEX_HELD(&wrsmdp->wrsmd_lock));

	/* LINTED: E_TRUE_LOGICAL_EXPR */
	ASSERT(sizeof (dl_rsm_addr_t) == sizeof (rsm_addr_t));

	wrsmdp->wrsmd_flags = 0;

	/*
	 * Preceding teardown may not have released controller.
	 * If so, do so now to avoid multiple reference counts.
	 */
	if (wrsmdp->wrsmd_flags & WRSMDGOTCTLR) {
		D1("wrsmdinit: controller still held, "
		    "call rsm_release_controller()");
		rsm_release_controller(WRSM_NAME, wrsmdp->wrsmd_ctlr_id,
		    &(wrsmdp->wrsmd_ctlr));
		wrsmdp->wrsmd_ctlr.handle = NULL;
		wrsmdp->wrsmd_flags &= ~WRSMDGOTCTLR;
	}

	if ((stat = rsm_get_controller(WRSM_NAME, wrsmdp->wrsmd_ctlr_id,
	    &(wrsmdp->wrsmd_ctlr), RSM_VERSION)) != RSM_SUCCESS) {
		D1("wrsmdinit: bad get_controller error %d", stat);
		return (1);
	}
	if ((stat = rsm_get_controller_attr(wrsmdp->wrsmd_ctlr.handle,
	    &(wrsmdp->wrsmd_ctlr_attr))) != RSM_SUCCESS) {
		D1("wrsmdinit: bad get_controller_attr error %d", stat);
		rsm_release_controller(WRSM_NAME, wrsmdp->wrsmd_ctlr_id,
		    &(wrsmdp->wrsmd_ctlr));
		wrsmdp->wrsmd_ctlr.handle = NULL;
		return (1);
	}

	/*
	 * We only support RSM addresses that fit into 6 bytes.  This
	 * will always be the case on Wildcat.  (Address range is 0-255.)
	 */
	ASSERT(wrsmdp->wrsmd_ctlr_attr->attr_controller_addr <=
	    (rsm_addr_t)0xffffffffffffLL);
	wrsmdp->wrsmd_rsm_addr.m.rsm =
	    wrsmdp->wrsmd_ctlr_attr->attr_controller_addr;
	/*
	 * Since this address is locally generated, turn on the locally
	 * administered bit in the ethernet address to comply with IEEE 802.
	 */
	wrsmdp->wrsmd_rsm_addr.m.ether.addr.ether_addr_octet[0] |= 0x02;

	wrsmdp->wrsmd_flags |= WRSMDGOTCTLR;

	if ((stat = RSM_REGISTER_HANDLER(wrsmdp->wrsmd_ctlr,
	    RSM_INTR_T_SUN_BASE, wrsmd_rsm_intr_handler,
	    (rsm_intr_hand_arg_t)wrsmdp, NULL, 0)) !=
	    RSM_SUCCESS) {
		D1("wrsmdinit: cannot register interrupt handler: %d", stat);
		rsm_release_controller(WRSM_NAME, wrsmdp->wrsmd_ctlr_id,
		    &(wrsmdp->wrsmd_ctlr));
		wrsmdp->wrsmd_ctlr.handle = NULL;
		wrsmdp->wrsmd_flags &= ~WRSMDGOTCTLR;
		return (1);
	}

	wrsmdp->wrsmd_flags |= WRSMDREGHANDLER;

	/*
	 * Clear any leftover junk from run queue.  (We could have destinations
	 * here if the user detached from a device, then reattached before
	 * the destinations got deleted.)  These destination structures will
	 * eventually be freed when the deletion process completes.
	 */
	mutex_enter(&wrsmdp->wrsmd_runq_lock);
	wrsmdp->wrsmd_runq = NULL;
	mutex_exit(&wrsmdp->wrsmd_runq_lock);

	D1("wrsmdinit: returning 0");

	return (0);
}

/*
 * Un-initialize WRSMD resources.  Returns 0 if completely successful.
 * Returns -1 if not in a state where uninitialize makes sense.  Returns >0
 * if uninitialize was started, but hasn't completed because not all
 * connections have been torn down yet.
 */
static int
wrsmduninit(wrsmd_t *wrsmdp)
{
	int dests_not_cleaned_up;
	int i;
	rsm_controller_object_t ctlr;

	D1("wrsmduninit: wrsmdp 0x%p (cltr %d)", (void *)wrsmdp,
	    wrsmdp->wrsmd_ctlr_id);

	mutex_enter(&wrsmdp->wrsmd_lock);

	if (wrsmdp->wrsmd_attached_streams) {
		/*
		 * don't uninitialize device while streams are attached to it
		 */
		D1("wrsmduninit: %d streams still attached, failing",
		    wrsmdp->wrsmd_attached_streams);
		mutex_exit(&wrsmdp->wrsmd_lock);
		return (-1);
	}

	if (wrsmdp->wrsmd_flags & WRSMDREGHANDLER) {
		/*
		 * Must release the mutex here to avoid a potential deadlock.
		 * The wrsm_unregister_handler() code acquires the wrsm
		 * service->handler_mutex.  If an inbound interrupt occurs,
		 * the wrsm service_callback grabs the service->handler_mutex,
		 * and calls back into the wrsmd_rsm_intr_handler() routine,
		 * which attempts to grab the wrsmdp->wrsmd_lock.  If at the
		 * time we invoke RSM_UNREGISTER_HANDLER() while holding the
		 * wrsmdp->wrsmd_lock, we get a circular lock deadlock.
		 */
		ctlr = wrsmdp->wrsmd_ctlr;
		mutex_exit(&wrsmdp->wrsmd_lock);
		RSM_UNREGISTER_HANDLER(ctlr, RSM_INTR_T_SUN_BASE,
		    wrsmd_rsm_intr_handler, (rsm_intr_hand_arg_t)wrsmdp);
		mutex_enter(&wrsmdp->wrsmd_lock);
		wrsmdp->wrsmd_flags &= ~WRSMDREGHANDLER;
	}

	for (i = 0; i < RSM_MAX_DESTADDR; i++)
		wrsmdfreedest(wrsmdp, i);

	mutex_enter(&wrsmdp->wrsmd_dest_lock);
	dests_not_cleaned_up = wrsmdp->wrsmd_numdest;
	mutex_exit(&wrsmdp->wrsmd_dest_lock);

	if ((wrsmdp->wrsmd_flags & WRSMDGOTCTLR) &&
	    (dests_not_cleaned_up == 0)) {
		/*
		 * there will be no more RSMPI calls, so
		 * it's safe to release the controller
		 */
		D1("wrsmduninit: call rsm_release_controller()");
		rsm_release_controller(WRSM_NAME, wrsmdp->wrsmd_ctlr_id,
		    &(wrsmdp->wrsmd_ctlr));
		wrsmdp->wrsmd_ctlr.handle = NULL;
		wrsmdp->wrsmd_flags &= ~WRSMDGOTCTLR;
	}
	mutex_exit(&wrsmdp->wrsmd_lock);

	D1("wrsmduninit: returning %d",
	    dests_not_cleaned_up);

	return (dests_not_cleaned_up);
}

/*
 * Get all the wrsmd parameters out of the device tree and store them in a
 * WRSMD device (RSM controller) structure.
 */
static void
wrsmdgetparam(
	dev_info_t *dip,	/* Device's info pointer */
	wrsmd_t *wrsmdp)	/* WRSMD device (RSM controller) pointer */
{
	struct wrsmd_param *sp = &wrsmdp->wrsmd_param;
	boolean_t modified_bufsize = B_FALSE;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sp))

	/* Get parameters */

	sp->wrsmd_buffers = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-buffers", WRSMD_BUFFERS_DFLT);
	sp->wrsmd_buffer_size = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-buffer-size", WRSMD_BUFFER_SIZE_DFLT);
	sp->wrsmd_queue_size = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-queue-size", WRSMD_QUEUE_SIZE_DFLT);
	sp->wrsmd_buffers_retained = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-buffers-retained", WRSMD_BUFFERS_RETAINED_DFLT);
	sp->wrsmd_idle_reclaim_time = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-idle-reclaim-time", WRSMD_IDLE_RECLAIM_TIME_DFLT);
	sp->wrsmd_err_retries = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-err-retries", WRSMD_ERR_RETRIES_DFLT);
	sp->wrsmd_max_queued_pkts = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-max-queued-pkts", WRSMD_MAX_QUEUED_PKTS_DFLT);
	sp->wrsmd_nobuf_init_tmo = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-nobuf-init-tmo", WRSMD_NOBUF_INIT_TMO_DFLT);
	sp->wrsmd_nobuf_max_tmo = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-nobuf-max-tmo", WRSMD_NOBUF_MAX_TMO_DFLT);
	sp->wrsmd_nobuf_drop_tmo = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-nobuf-drop-tmo", WRSMD_NOBUF_DROP_TMO_DFLT);
	sp->wrsmd_msg_init_tmo = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-msg-init-tmo", WRSMD_MSG_INIT_TMO_DFLT);
	sp->wrsmd_msg_max_tmo = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-msg-max-tmo", WRSMD_MSG_MAX_TMO_DFLT);
	sp->wrsmd_msg_drop_tmo = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-msg-drop-tmo", WRSMD_MSG_DROP_TMO_DFLT);
	sp->wrsmd_ack_tmo = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-ack-tmo", WRSMD_ACK_TMO_DFLT);
	sp->wrsmd_sync_tmo = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-sync-tmo", WRSMD_SYNC_TMO_DFLT);
	sp->wrsmd_teardown_tmo = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-teardown-tmo", WRSMD_TEARDOWN_TMO_DFLT);
	sp->wrsmd_train_size = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-train-size", WRSMD_TRAIN_SIZE_DFLT);
	sp->wrsmd_fqe_sync_size = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "wrsmd-fqe-sync-size", WRSMD_FQE_SYNC_SIZE_DFLT);

	/*
	 * Sanity check parameters, modify if needed.  Note that we mainly
	 * check to make sure parameters won't make the driver malfunction;
	 * we don't necessarily prevent them from being stupid.
	 */

	/* Need to have at least one buffer. */

	if (sp->wrsmd_buffers == 0)
		sp->wrsmd_buffers = 1;

#ifdef RESTRICT_MAX_BUFFER_SIZE
	/* Can't put more than 64K in a buffer (IP max packet length). */

	if (sp->wrsmd_buffer_size > (64 * 1024)) {
		sp->wrsmd_buffer_size = (64 * 1024);
		modified_bufsize = B_TRUE;
	}
#endif

	/*
	 * Have to be able to send at least a 576-byte packet (IP reqmnt).
	 * Add 2 cachelines so that packet will fit no matter how it is
	 * aligned.
	 */

	if (sp->wrsmd_buffer_size <
	    (576+WRSMD_CACHELINE_SIZE+WRSMD_CACHELINE_SIZE)) {
		sp->wrsmd_buffer_size =
		    576+WRSMD_CACHELINE_SIZE+WRSMD_CACHELINE_SIZE;
		modified_bufsize = B_TRUE;
	}

	/* Buffer length must be multiple of 64 (0x40). */

	if (sp->wrsmd_buffer_size & ~WRSMD_CACHELINE_MASK) {
		sp->wrsmd_buffer_size &= WRSMD_CACHELINE_MASK;
		modified_bufsize = B_TRUE;
	}

	if (modified_bufsize) {
		cmn_err(CE_NOTE, "adjusted wrsmd-buffer-size value from "
		    "wrsmd.conf to 0x%x", sp->wrsmd_buffer_size);
	}

	/*
	 * Must have at least one more queue element then the number of
	 * buffers.  This is so that we can track when all queue elements
	 * need to be flushed to remote.
	 */

	if (sp->wrsmd_queue_size <= sp->wrsmd_buffers) {
		sp->wrsmd_queue_size = sp->wrsmd_buffers + 1;
		cmn_err(CE_NOTE, "adjusted wrsmd-queue-size value from "
		    "wrsmd.conf to 0x%x", sp->wrsmd_queue_size);
	}

	/* Can't retain more buffers than we have. */

	if (sp->wrsmd_buffers_retained > sp->wrsmd_buffers) {
		sp->wrsmd_buffers_retained = sp->wrsmd_buffers;
		cmn_err(CE_NOTE, "adjusted wrsmd-buffers-retained value "
		    "from wrsmd.conf to 0x%x", sp->wrsmd_buffers_retained);
	}

	/* Have to be able to send at least 1 packet at a time. */

	if (sp->wrsmd_train_size < 1) {
		sp->wrsmd_train_size = 1;
		cmn_err(CE_NOTE, "adjusted wrsmd-train-size value "
		    "from wrsmd.conf to 0x%x", sp->wrsmd_train_size);
	}

	/* Have to be able to queue at least 1 packet. */

	if (sp->wrsmd_max_queued_pkts < 1) {
		sp->wrsmd_max_queued_pkts = 1;
		cmn_err(CE_NOTE, "adjusted wrsmd-max-queued-packets "
		    "value from wrsmd.conf to 0x%x",
		    sp->wrsmd_max_queued_pkts);
	}

	/*
	 * Convert timeout parameters in milliseconds to
	 * absolute clock ticks, depending on clock hertz.
	 */
	sp->wrsmd_idle_reclaim_time = WRSMD_TICKS(sp->wrsmd_idle_reclaim_time);
	sp->wrsmd_nobuf_init_tmo = WRSMD_TICKS(sp->wrsmd_nobuf_init_tmo);
	sp->wrsmd_nobuf_max_tmo = WRSMD_TICKS(sp->wrsmd_nobuf_max_tmo);
	sp->wrsmd_nobuf_drop_tmo = WRSMD_TICKS(sp->wrsmd_nobuf_drop_tmo);
	sp->wrsmd_msg_init_tmo = WRSMD_TICKS(sp->wrsmd_msg_init_tmo);
	sp->wrsmd_msg_max_tmo = WRSMD_TICKS(sp->wrsmd_msg_max_tmo);
	sp->wrsmd_msg_drop_tmo = WRSMD_TICKS(sp->wrsmd_msg_drop_tmo);
	sp->wrsmd_ack_tmo = WRSMD_TICKS(sp->wrsmd_ack_tmo);
	sp->wrsmd_sync_tmo = WRSMD_TICKS(sp->wrsmd_sync_tmo);
	sp->wrsmd_teardown_tmo = WRSMD_TICKS(sp->wrsmd_teardown_tmo);

	/* Can't sleep for less than 1 tick. */

	if (sp->wrsmd_nobuf_init_tmo < 1) {
		sp->wrsmd_nobuf_init_tmo = 1;
		cmn_err(CE_NOTE, "adjusted wrsm-nobuf-init-tmo "
		    "value from wrsmd.conf to 0x%x",
		    sp->wrsmd_nobuf_init_tmo);
	}
	if (sp->wrsmd_nobuf_max_tmo < 1) {
		sp->wrsmd_nobuf_max_tmo = 1;
		cmn_err(CE_NOTE, "adjusted wrsm-nobuf-max-tmo "
		    "value from wrsmd.conf to 0x%x",
		    sp->wrsmd_nobuf_max_tmo);
	}
	if (sp->wrsmd_msg_init_tmo < 1) {
		sp->wrsmd_msg_init_tmo = 1;
		cmn_err(CE_NOTE, "adjusted wrsm-msg-init-tmo "
		    "value from wrsmd.conf to 0x%x",
		    sp->wrsmd_msg_init_tmo);
	}
	if (sp->wrsmd_msg_max_tmo < 1) {
		sp->wrsmd_msg_max_tmo = 1;
		cmn_err(CE_NOTE, "adjusted wrsm-msg-max-tmo "
		    "value from wrsmd.conf to 0x%x",
		    sp->wrsmd_msg_max_tmo);
	}
	if (sp->wrsmd_ack_tmo < 1) {
		sp->wrsmd_ack_tmo = 1;
		cmn_err(CE_NOTE, "adjusted wrsm-ack-tmo "
		    "value from wrsmd.conf to 0x%x",
		    sp->wrsmd_ack_tmo);
	}
	if (sp->wrsmd_sync_tmo < 1) {
		sp->wrsmd_sync_tmo = 1;
		cmn_err(CE_NOTE, "adjusted wrsm-sync-tmo "
		    "value from wrsmd.conf to 0x%x",
		    sp->wrsmd_sync_tmo);
	}

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*sp))
}

/*
 * ****************************************************************
 *                                                               *
 * E N D       RSM SETUP/TAKEDOWN                                *
 *                                                               *
 * ****************************************************************
 */


/*
 * ****************************************************************
 *                                                               *
 * B E G I N   CONNECTION DATA STRUCTURE MANAGEMENT              *
 *                                                               *
 * ****************************************************************
 */


/*
 * Create the indicated destination structure, and return a pointer to it.
 * NOTE:  this should never be called directly; use the MAKEDEST macro
 * instead.  The macro checks that the destination structure does not yet
 * exist before calling this function.
 */
static wrsmd_dest_t *
wrsmdmkdest(wrsmd_t *wrsmdp,	/* WRSMD device (RSM controller) pointer */
    rsm_addr_t rsm_addr)	/* Address of destination to find/create */
{
	wrsmd_dest_t *rd;
	clock_t lbolt;

	D1("wrsmdmkdest: wrsmdp 0x%p (cltr %d), rsmaddr %ld", (void *)wrsmdp,
	    wrsmdp->wrsmd_ctlr_id, rsm_addr);

	/* Is the destination reasonable? */

	if (rsm_addr >= RSM_MAX_DESTADDR) {
		D1("wrsmdmkdest: too big, returning NULL");
		return (NULL);
	}

	if ((rd = wrsmdp->wrsmd_desttbl[rsm_addr]) != NULL) {
		return (rd);
	}

	ASSERT(MUTEX_HELD(&wrsmdp->wrsmd_dest_lock));

	if ((rd = kmem_zalloc(sizeof (*rd), KM_NOSLEEP)) == NULL) {
		D1("wrsmdmkdest: can't alloc, returning NULL");
		return (NULL);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rd));
	rd->rd_wrsmdp = wrsmdp;
	rd->rd_rsm_addr = rsm_addr;

	mutex_init(&rd->rd_net_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&rd->rd_xmit_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&rd->rd_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Use the time to generate a pseudo-random initial sequence
	 * number.
	 */
	(void) drv_getparm(LBOLT, &lbolt);
	rd->rd_nseq = (ushort_t)lbolt;

	rd->rd_state = WRSMD_STATE_NEW;
	rd->rd_refcnt = 1;

	wrsmdp->wrsmd_desttbl[rsm_addr] = rd;
	wrsmdp->wrsmd_numdest++;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*rd))

	D1("wrsmdmkdest: created new dest, returning 0x%p", (void *)rd);

	return (rd);
}

/*
 * Destination deletion
 *
 * As mentioned above (way above), we maintain a reference count on all
 * destinations, which is incremented and decremented around uses of the
 * destination structure.  When this reference count goes to zero, we delete
 * the destination.
 *
 * Because of the possibility of other threads trying to use the destination
 * while we're deleting it, deletion is actually a multiple-step process,
 * which works as follows.
 *
 * 1. When a destination is created, its dstate (deletion state) is set to
 *    zero, and its reference count is set to one.
 *
 * 2. When the service routine or some other routine decides that a destination
 *    should be deleted, it calls wrsmdfreedest().  That routine sets dstate
 *    to 1 and cancels any pending sync timeouts.  It then decrements the
 *    destination's reference count.  This deletes the reference set in
 *    wrsmdmkdest. (Note that since dstate is now 1, the FINDDEST and REFDEST
 *    macros will now note that the destination is being deleted; thus, any
 *    interrupt referring to the destination will no longer modify the
 *    reference count.)
 *
 * 3. Soon after this, wrsmddest_refcnt_0 is called.  (This may either be
 *    directly from wrsmdfreedest(), or perhaps from another routine if it
 *    was running concurrently with freedest() and its UNREF happened last).
 *    This routine sees that dstate is 1, and immediately queues an event
 *    which will execute wrsmdfreedestevt().  (This is necessary because we
 *    may not be able to do everything in the phase 1 deletion from the routine
 *    that we're currently in.)
 *
 * 4. wrsmdfreedestevt() runs, it checks if there are any outstanding
 *    loaned-up buffers.  If so, it sets a flag to cause the loan returning
 *    code to decrement the refcnt, and returns without performing cleanup.
 *    When all loaned buffers are returned and the refcnt is decremented, we
 *    go back to step 3, above.  When wrsmdfreedestevt() finally runs with
 *    no loaned buffers, gets rid of most of the WRSMD resources attached
 *    to the destination.  It also throws away any queued packets, gets
 *    rid of any allocated DVMA resources.  It changes dstate to 2, takes
 *    this destination structure out of the base-ID => destination table.
 *    It then decrements the reference count that had been added by
 *    wrsmddest_refcnt_0().
 *
 * 5. When the reference count becomes 0, wrsmddest_refcnt_0 is again called.
 *    It notices that dstate is 2, and frees the destination structure.
 */

/*
 * A destination's reference count went to 0, deal with it.
 */
static boolean_t
wrsmddest_refcnt_0(
	wrsmd_dest_t *rd)	/* Destination pointer */
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;
	boolean_t freed = B_FALSE;

	mutex_enter(&wrsmdp->wrsmd_dest_lock);

	D1("wrsmddest_refcnt_0: rd 0x%p (addr %ld ctlr %d), refcnt %d, "
	    "dstate %d",
	    (void *)rd, rd->rd_rsm_addr, wrsmdp->wrsmd_ctlr_id,
	    rd->rd_refcnt, rd->rd_dstate);

	if (rd->rd_dstate == 1) {
		rd->rd_refcnt++;	/* Inline REFDEST */

		/*
		 * We may be called from a routine that can't actually do the
		 * work that needs to be done, so we schedule an event
		 * to do the rest of the work.  This can not be a timeout.
		 */

		wrsmd_add_event(wrsmdp, WRSMD_EVT_FREEDEST, (void *)rd);

	} else if (rd->rd_dstate == 2) {

		/* Destroy all the mutexes */

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rd))

		mutex_destroy(&rd->rd_lock);
		mutex_destroy(&rd->rd_net_lock);
		mutex_destroy(&rd->rd_xmit_lock);
		mutex_destroy(&rd->rd_nlb_lock);

		/*
		 * Free any allocated memory hanging off the dest structure.
		 */

		if (rd->rd_cached_fqr) {
			kmem_free(rd->rd_cached_fqr,
			    sizeof (*rd->rd_cached_fqr) * rd->rd_num_fqrs);
		}
		if (rd->rd_shdwfqw_f_addr) {
			kmem_free(rd->rd_shdwfqw_f_addr,
			(sizeof (*rd->rd_shdwfqw_f_addr) * rd->rd_num_fqws) +
				WRSMD_CACHELINE_SIZE);
		}
		if (rd->rd_shdwdqw_f_addr) {
			kmem_free(rd->rd_shdwdqw_f_addr,
			(sizeof (*rd->rd_shdwdqw_f_addr) * rd->rd_num_dqws) +
				WRSMD_CACHELINE_SIZE);
		}
		if (rd->rd_bufbase) {
			kmem_free(rd->rd_bufbase,
			    wrsmdp->wrsmd_param.wrsmd_buffers *
			    sizeof (*rd->rd_bufbase));
		}
		if (rd->rd_rawmem_base_addr) {
			kmem_free(rd->rd_rawmem_base_addr,
			    rd->rd_rawmem_base_size);
		}

		/* Finally free the dest structure */

		kmem_free(rd, sizeof (*rd));
		freed = B_TRUE;

		wrsmdp->wrsmd_numdest--;

		D1("wrsmddest_refcnt_0: freed rd data structures");
	}

	mutex_exit(&wrsmdp->wrsmd_dest_lock);

	D1("wrsmddest_refcnt_0: done");

	return (freed);
}

/*
 * Do deletion work.
 */
static void
wrsmdfreedestevt(void * arg)
{
	wrsmd_dest_t *rd = (wrsmd_dest_t *)arg;
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;
	mblk_t *mp, *nmp;
	int err;
	int count = 0, tmpmask;

	D1("wrsmdfreedestevt: rd 0x%p (addr %ld ctlr %d)", (void *)rd,
	    rd->rd_rsm_addr, wrsmdp->wrsmd_ctlr_id);

	/* Get rid of any queued outgoing buffers */

	mutex_enter(&rd->rd_xmit_lock);

	mp = rd->rd_queue_h;
	rd->rd_queue_h = NULL;

	while (mp) {
		nmp = mp->b_next;
		mp->b_next = mp->b_prev = NULL;
		wrsmdp->wrsmd_oerrors++;
		freemsg(mp);
		mp = nmp;
	}
	rd->rd_queue_len = 0;

	mutex_exit(&rd->rd_xmit_lock);

	/*
	 * See if there are any more outstanding loaned buffers.  If so,
	 * set flag so that freebuf will eventually do an UNREF when it
	 * frees the last buffer.  This removes the reference added in
	 * wrsmddest_refcnt_0(), causing the count to again go to 0.
	 * wrsmddest_refcnt_0() will again be called, increment the refcnt
	 * and cause this routine to be called to complete cleanup.
	 */

	mutex_enter(&rd->rd_nlb_lock);

	rd->rd_nlb_del = 1;
	if (rd->rd_nlb != 0) {
		DERR("wrsmdfreedestevt: loaned buffers outstanding %d, dest "
		    "%ld", rd->rd_nlb, rd->rd_rsm_addr);
		mutex_exit(&rd->rd_nlb_lock);
		return;
	}

	mutex_exit(&rd->rd_nlb_lock);

	/*
	 * Retry for up to 10 times to clean up, pausing slightly each
	 * iteration.  This gives the remote side a chance to clean up
	 * in the case of unpublish, and allows us to catch other errors
	 * now as well.
	 */

	tmpmask = WRSMD_RSMS_RXFER_S | WRSMD_RSMS_RXFER_C |
		WRSMD_RSMS_LXFER_P | WRSMD_RSMS_LXFER_C;
	while ((count < 10) && (rd->rd_sstate & tmpmask)) {
		/*
		 * Perform the sendq destroy first -- this notifies the
		 * remote side that the connection is going away, so
		 * it can immediately start cleaning up.  This helps
		 * to avoid a situation where a segment is unpublished
		 * while there is still a connection to it (which is legal,
		 * but causes overhead in the Wildcat RSM driver).
		 */
		if (rd->rd_sstate & WRSMD_RSMS_RXFER_S) {
			ASSERT(rd->rsm_sendq);
			D1("wrsmdfreedestevt: destroying sendq\n");
				err = RSM_SENDQ_DESTROY(wrsmdp->wrsmd_ctlr,
							rd->rsm_sendq);
			if (err) {
				D1("RSM_SENDQ_DESTROY failed! err %d\n", err);
			} else {
				rd->rd_sstate &= ~WRSMD_RSMS_RXFER_S;
			}
		}

		if (rd->rd_sstate & WRSMD_RSMS_RXFER_C) {
			ASSERT(rd->rd_rxferhand);
			D1("wrsmdfreedestevt: disconn from remote segment\n");
			err = RSM_DISCONNECT(wrsmdp->wrsmd_ctlr,
				rd->rd_rxferhand);
			if (err) {
				D1("RSM_DISCONNECT failed! err %d\n", err);
			} else {
				rd->rd_sstate &= ~WRSMD_RSMS_RXFER_C;
			}
		}

		if (rd->rd_sstate & WRSMD_RSMS_LXFER_P) {
			ASSERT(rd->rd_lxferhand);
			D1("wrsmdfreedestevt: unpublishing local segment\n");
			err = RSM_UNPUBLISH(wrsmdp->wrsmd_ctlr,
					    rd->rd_lxferhand);
			if (err) {
				D1("RSM_UNPUBLISH failed! err %d\n", err);
			} else {
				rd->rd_sstate &= ~WRSMD_RSMS_LXFER_P;
			}
		}

		if (rd->rd_sstate & WRSMD_RSMS_LXFER_C) {
			ASSERT(rd->rd_lxferhand);
			D1("wrsmdfreedestevt: destroying local segment\n");
			err = RSM_SEG_DESTROY(wrsmdp->wrsmd_ctlr,
						rd->rd_lxferhand);
			if (err) {
				D1("RSM_SEG_DESTROY failed! err %d\n", err);
			} else {
				rd->rd_sstate &= ~WRSMD_RSMS_LXFER_C;
			}
		}

		count++;

		if (rd->rd_sstate & tmpmask) {
			D1("freedestevt: Pass %d, (sstate & mask)=0x%x\n",
				count, (rd->rd_sstate & tmpmask));

			/* Busy wait for a few microseconds */
			drv_usecwait(5000);
		}
	}

	if (count >= 10) {
		D1("freedestevt: sstate&mask !0 after %d tries. 0x%x\n",
			count, (rd->rd_sstate & tmpmask));
		D0("freedestevt: Clearing state but status != 0, stat=%x\n",
			(rd->rd_sstate & tmpmask));
		rd->rd_sstate &= ~tmpmask;
	}

	/* Take out of desttbl */

	mutex_enter(&wrsmdp->wrsmd_dest_lock);

	rd->rd_wrsmdp->wrsmd_desttbl[rd->rd_rsm_addr] = NULL;

	ASSERT(rd->rd_dstate == 1);
	rd->rd_dstate = 2;

	mutex_exit(&wrsmdp->wrsmd_dest_lock);


	/* Make sure dest isn't on service queue */

	mutex_enter(&wrsmdp->wrsmd_runq_lock);

	if (wrsmdp->wrsmd_runq == rd)
		wrsmdp->wrsmd_runq = rd->rd_next;
	else {
		wrsmd_dest_t *lastrd = wrsmdp->wrsmd_runq;

		while (lastrd) {
			if (lastrd->rd_next == rd) {
				lastrd->rd_next = rd->rd_next;
				break;
			}
			lastrd = lastrd->rd_next;
		}
	}

	mutex_exit(&wrsmdp->wrsmd_runq_lock);


	ASSERT(rd->rd_sstate == 0);

	/*
	 * Removes the reference added in wrsmddest_refcnt_0().
	 */
	UNREFDEST(rd);

	D1("wrsmdfreedestevt: done");
}


/*
 * Start the deletion process for a destination.
 */
static void
wrsmdfreedest(wrsmd_t *wrsmdp, rsm_addr_t rsm_addr)
{
	wrsmd_dest_t *rd;
	timeout_id_t tmoid, fqe_tmoid;

	D1("wrsmdfreedest: ctlr %d remote rsmaddr %ld",
	    wrsmdp->wrsmd_ctlr_id, rsm_addr);

	mutex_enter(&wrsmdp->wrsmd_dest_lock);

	rd = wrsmdp->wrsmd_desttbl[rsm_addr];
	if (rd == NULL || rd->rd_dstate != 0) {
		mutex_exit(&wrsmdp->wrsmd_dest_lock);
		return;
	}

	ASSERT((wrsmdp->wrsmd_attached_streams == 0) ||
	    (rd->rd_state == WRSMD_STATE_DELETING));

	D1("wrsmdfreedest: wrsmdp 0x%p (cltr %d) rsmaddr %ld", (void *)wrsmdp,
	    wrsmdp->wrsmd_ctlr_id, rsm_addr);

	rd->rd_dstate = 1;

	mutex_exit(&wrsmdp->wrsmd_dest_lock);

	/*
	 * Turn off any timeouts.  The sync timeout reschedules itself, so we
	 * have to go to great lengths to kill it.
	 */

	mutex_enter(&rd->rd_xmit_lock);
	tmoid = rd->rd_tmo_id;
	rd->rd_tmo_id = 0;

	fqe_tmoid = rd->rd_fqe_tmo_id;
	rd->rd_fqe_tmo_id = 0;

	mutex_exit(&rd->rd_xmit_lock);
	if (tmoid)
		(void) untimeout(tmoid);

	if (fqe_tmoid)
		(void) untimeout(fqe_tmoid);

	mutex_enter(&rd->rd_net_lock);

	/*
	 * Flush any outstanding events from the event thread.  Since the
	 * freedestevt() will be queued after any pending syncs, we
	 * should be OK; but will start the ball rolling just in case.
	 */

	mutex_enter(&wrsmdp->event_lock);
	cv_broadcast(&wrsmdp->event_cv);
	mutex_exit(&wrsmdp->event_lock);

	mutex_exit(&rd->rd_net_lock);

	D1("wrsmdfreedest: done");

	/* remove reference added in wrsmdmkdest() */
	UNREFDEST(rd);
}

/*
 * ****************************************************************
 *                                                               *
 * E N D       CONNECTION DATA STRUCTURE MANAGEMENT              *
 *                                                               *
 * ****************************************************************
 */




/*
 * ****************************************************************
 *                                                               *
 * B E G I N   MAIN STATE MACHINE                                *
 *                                                               *
 * ****************************************************************
 */


/*
 * We change a destination's state in a number of routines; we define these
 * macros to make sure it gets done the same way every time.
 */
#define	WRSMD_SETSTATE(rd, wrsmdp, routine, newstate)			\
	rd->rd_state = (ushort_t)newstate; 			\
		if (WRSMD_SCHED_STATE(newstate)) {		\
			rd->rd_next = wrsmdp->wrsmd_runq;		\
			wrsmdp->wrsmd_runq = rd;			\
			D1(routine ": added to runq");	        \
			if (wrsmdp->wrsmd_wq) {			\
				qenable(wrsmdp->wrsmd_wq);	\
				D1(routine ": enabled 0x%p",	\
				    (void *)wrsmdp->wrsmd_wq);	\
			}				        \
		}						\
  	_NOTE(CONSTCOND);


#define	WRSMD_SETSTATE_NOSRV(rd, wrsmdp, routine, newstate)	\
		rd->rd_state = (ushort_t)newstate;		\
		if (WRSMD_SCHED_STATE(newstate)) {		\
			rd->rd_next = wrsmdp->wrsmd_runq;		\
			wrsmdp->wrsmd_runq = rd;			\
			D1(routine ": added to runq");		\
		}       				        \
	_NOTE(CONSTCOND);


/*
 * This routine processes a notification that a destination has become
 * unreachable.  Delete our record of it, so that when it comes back up we
 * will re-establish our association.  We do this by changing its state to
 * S_DELETE; the service routine will then start the deletion
 * process.
 *
 * Since other parts of the driver may have operations in progress that
 * involve this destination, most of the time we cannot just whack the
 * state to the new value.  Instead, we record (in rd_estate) that the
 * connection was lost.  The next time someone else attempts to change the
 * state, the state change routines recognize that there is a pending event
 * and change the state to the one we wanted instead.  (There are
 * exceptions in cases where the new state indicates that we've enabled
 * some sort of timeout; in this case, we may wait until the following
 * state change to take note of the event.)
 */
static void
wrsmd_lostconn(wrsmd_dest_t *rd)
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;

	D1("wrsmd_lostconn: rd 0x%p (addr %ld ctlr %d)", (void *)rd,
	    rd->rd_rsm_addr, wrsmdp->wrsmd_ctlr_id);

	mutex_enter(&wrsmdp->wrsmd_runq_lock);
	if ((rd->rd_state == WRSMD_STATE_W_READY) ||
	    (rd->rd_state == WRSMD_STATE_NEW) ||
	    (rd->rd_state == WRSMD_STATE_W_ACCEPT) ||
	    (rd->rd_state == WRSMD_STATE_W_ACK) ||
	    (rd->rd_state == WRSMD_STATE_W_FQE)) {
		/* LINTED: E_CONSTANT_CONDITION */
		WRSMD_SETSTATE(rd, wrsmdp, "wrsmd_lostconn",
		    WRSMD_STATE_S_DELETE);
	} else {
		rd->rd_estate = WRSMD_STATE_S_DELETE;
	}
	D1("wrsmd_lostconn: state now %s, estate now %s",
	    WRSMD_STATE_STR(rd->rd_state), WRSMD_STATE_STR(rd->rd_estate));

	mutex_exit(&wrsmdp->wrsmd_runq_lock);

	/*
	 * Stop trying to flush queue entries to the other side.
	 *
	 * stopq doesn't really need a lock to protect its state, as the
	 * only thing that happens to it is that it is set to true just
	 * prior to deleting rd, and the only purpose of this is to avoid
	 * unnecessary work.  Other threads can read the state of this
	 * variable at any time, without taking a special lock.
	 *
	 * Note that rd itself is protected from going away from the
	 * REFDEST/FINDDEST performed by the caller of this routine.
	 */
	rd->rd_stopq = B_TRUE;

	D1("wrsmd_lostconn: done");
}


/*
 * Figure out what state transition should actually occur after an event
 * has happened.
 */
static int
wrsmdestate_newstate(wrsmd_dest_t *rd, int newstate)
{
	int retval = newstate;

	/*
	 * If we're going to a state where we've just set a timeout, don't
	 * mess with the state.  When the timeout happens, it will change
	 * state again, and we'll nab 'em there.  If we're about to delete
	 * rd, don't bother worrying about the event.
	 */
	switch (newstate) {
	case WRSMD_STATE_W_SCONNTMO:
	case WRSMD_STATE_W_ACCEPT:
	case WRSMD_STATE_W_ACK:
	case WRSMD_STATE_W_FQE:
	case WRSMD_STATE_DELETING:
	case WRSMD_STATE_S_DELETE:
		return (retval);
	}

	if (rd->rd_estate) {
		retval = rd->rd_estate;
		rd->rd_estate = WRSMD_STATE_NEW; /* clear event state */
	}

	D1("wrsmdestate_newstate: %d %d -> %d", rd->rd_estate,
	    newstate, retval);

	return (retval);
}


/*
 * If this destination's state is equal to state, set its state to INPROGRESS
 * and return 1, otherwise return 0.
 */
static int
wrsmdisstate(
	wrsmd_dest_t *rd,	/* Destination pointer */
	int state)	/* State to check for */
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;
	int retval;

	D1("wrsmdisstate: rd 0x%p, state %s", (void *)rd,
	    WRSMD_STATE_STR(state));

	/*
	 * We check first without the lock to save time in a common case,
	 * namely, we're called from the wrsmdmsghdlr_syncdqe() routine and
	 * we want to know if we're waiting for an FQE.
	 */

#ifndef __lock_lint
	if (state != rd->rd_state) {
		D1("wrsmdisstate: state was %s, returning 0",
		    WRSMD_STATE_STR(rd->rd_state));
		return (0);
	}
#endif /* __lock_lint */

	mutex_enter(&wrsmdp->wrsmd_runq_lock);

	if (state == rd->rd_state) {
		rd->rd_state = WRSMD_STATE_INPROGRESS;
		retval = 1;
		D1("wrsmdisstate: returning 1");
	} else {
		retval = 0;
		D1("wrsmdisstate: state was %s, returning 0",
		    WRSMD_STATE_STR(rd->rd_state));
	}

	mutex_exit(&wrsmdp->wrsmd_runq_lock);

	return (retval);
}

/*
 * Return destination's state, then set its state to INPROGRESS.
 */
static int
wrsmdgetstate(
	wrsmd_dest_t *rd)	/* Destination pointer */
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;
	int state;

	D1("wrsmdgetstate: rd 0x%p", (void *)rd);

	mutex_enter(&wrsmdp->wrsmd_runq_lock);

	state = rd->rd_state;
	rd->rd_state = WRSMD_STATE_INPROGRESS;

	mutex_exit(&wrsmdp->wrsmd_runq_lock);

	D1("wrsmdgetstate: returning %s", WRSMD_STATE_STR(state));

	return (state);
}

/*
 * Set destination's state; must be preceded by a getstate call.  (i.e.,
 * destination's current state must be INPROGRESS.)
 */
static void
wrsmdsetstate(
	wrsmd_dest_t *rd,	/* Destination pointer */
	int newstate)	/* State to set */
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;

	D1("wrsmdsetstate: rd 0x%p, newstate %s", (void *)rd,
	    WRSMD_STATE_STR(newstate));

	mutex_enter(&wrsmdp->wrsmd_runq_lock);

	if (rd->rd_state == WRSMD_STATE_INPROGRESS) {
		if (rd->rd_estate)
			newstate = wrsmdestate_newstate(rd, newstate);
		WRSMD_SETSTATE(rd, wrsmdp, "wrsmdsetstate", newstate);
	} else {
		D1("wrsmd: setstate without getstate");
		cmn_err(CE_PANIC, "wrsmd: setstate without getstate");
	}

	mutex_exit(&wrsmdp->wrsmd_runq_lock);

	D1("wrsmdsetstate: done");
}

/*
 * Special case of wrsmdsetstate, designed to be called from the service
 * routine. Does everything wrsmdsetstate does _except_ qenable the service
 * routine.
 */
static void
wrsmdsetstate_nosrv(
	wrsmd_dest_t *rd,	/* Destination pointer */
	int newstate)	/* State to set */
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;

	D1("wrsmdsetstate_nosrv: rd 0x%p, newstate %s", (void *)rd,
	    WRSMD_STATE_STR(newstate));

	mutex_enter(&wrsmdp->wrsmd_runq_lock);

	if (rd->rd_state == WRSMD_STATE_INPROGRESS) {
		if (rd->rd_estate)
			newstate = wrsmdestate_newstate(rd, newstate);
		WRSMD_SETSTATE_NOSRV(rd, wrsmdp, "wrsmdsetstate_nosrv",
		    newstate);
	} else {
		D1("wrsmd: setstate without getstate");
		cmn_err(CE_PANIC, "wrsmd: setstate without getstate");
	}

	mutex_exit(&wrsmdp->wrsmd_runq_lock);

	D1("wrsmdsetstate_nosrv: done");
}

/*
 * Set state to newstate iff state is oldstate.  Return 1 if move happened,
 * else 0.
 */
static int
wrsmdmovestate(
	wrsmd_dest_t *rd,	/* Destination pointer */
	int oldstate,	/* State to check against */
	int newstate)	/* State to set if check succeeds */
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;
	int retval;

	D1("wrsmdmovestate: rd 0x%p, oldstate %s, newstate %s",
	    (void *)rd, WRSMD_STATE_STR(oldstate), WRSMD_STATE_STR(newstate));

	mutex_enter(&wrsmdp->wrsmd_runq_lock);

	if (rd->rd_state == oldstate) {
		if (rd->rd_estate)
			newstate = wrsmdestate_newstate(rd, newstate);
		WRSMD_SETSTATE(rd, wrsmdp, "wrsmdmovestate", newstate);
		retval = 1;
		D1("wrsmdmovestate: state changed, returning 1");
	} else {
		retval = 0;
		D1("wrsmdmovestate: oldstate really %s, returning 0",
		    WRSMD_STATE_STR(rd->rd_state));
	}

	mutex_exit(&wrsmdp->wrsmd_runq_lock);

	return (retval);
}



/*
 * ****************************************************************
 *                                                               *
 * E N D       MAIN STATE MACHINE                                *
 *                                                               *
 * ****************************************************************
 */



/*
 * ****************************************************************
 *                                                               *
 * B E G I N      HANDLERS FOR INCOMING RSM MESSAGES             *
 *                                                               *
 * ****************************************************************
 */


/*
 * Handlers for the various messages that may arrive.  All of these happen
 * during interrupt handling, and will not actually use RSMPI calls.
 * Rather, they will schedule actions to happen.
 */


/*
 * Received CONNECT REQUEST message.  Cause this side to set up
 * connection to xfer segment and send back an ACCEPT message.
 *
 * We must have everything set up before sending the ACCEPT.
 * However, we must not transmit any data until we receive the ACK
 * of the ACCEPT.
 */
static void
wrsmdmsghdlr_req_connect(wrsmd_dest_t *rd, wrsmd_msg_t *msg)
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;
	boolean_t utmo = B_FALSE;
	timeout_id_t tmoid;

	D1("wrsmdmsghdlr_req_connect: rd 0x%p (addr %ld ctlr %d)",
	    (void *)rd, rd->rd_rsm_addr, rd->rd_wrsmdp->wrsmd_ctlr_id);

	/*
	 * xmit lock guarantees that timeout has really been set
	 * for any wait conditions.
	 */
	mutex_enter(&rd->rd_xmit_lock);
	mutex_enter(&wrsmdp->wrsmd_runq_lock);

	if (rd->rd_segid_valid) {
		/*
		 * Another connect message - is it a duplicate?
		 * If so, just ignore.  Otherwise, there is a
		 * problem, so force a connection teardown.
		 */

		mutex_exit(&wrsmdp->wrsmd_runq_lock);
		mutex_exit(&rd->rd_xmit_lock);

		if ((rd->rd_rxfersegid != msg->p.m.con_request.send_segid) ||
		    (rd->rd_lastconnmsg_seq != msg->p.hdr.seqno)) {
			/* Not the same connect request, drop connection */
			wrsmd_lostconn(rd);
		}

		return;
	}

	/* remember the message sequence number of this connection request */
	rd->rd_lastconnmsg_seq = msg->p.hdr.seqno;

	if (rd->rd_state == WRSMD_STATE_W_ACCEPT) {
		/*
		 * Crossed connection requests.  If we're the higher
		 * numbered address, cancel the ACCEPT timeout and accept
		 * the remote request.  If we're the lower numbered
		 * address, ignore this request because the remote side
		 * will accept ours.  If the W_ACCEPT timeout expires prior
		 * to cancelling the timeout, the timeout function will
		 * notice the state is no longer W_ACCEPT, and will not
		 * cause the connection to be torn down.  If the timeout
		 * has already occurred (and the rd state is S_DELETE),
		 * we're out of luck, and will have to wait for a new
		 * connection request from the remote side.
		 */
		if (rd->rd_rsm_addr > wrsmdp->wrsmd_rsm_addr.m.rsm) {
			rd->rd_segid_valid = B_TRUE;
			rd->rd_rxfersegid = msg->p.m.con_request.send_segid;
			/* LINTED: E_CONSTANT_CONDITION */
			WRSMD_SETSTATE(rd, wrsmdp, "wrsmdmsghdlr_req_connect",
			    WRSMD_STATE_S_CONNXFER_ACCEPT);
			utmo = B_TRUE;
			tmoid = rd->rd_tmo_id;
			rd->rd_tmo_id = 0;
			rd->rd_tmo_int = 0;
		}
	} else {

		/*
		 * Save away the connection information.  If possible,
		 * change the state to cause the request to be immediately
		 * acted upon.  If the state is currently INPROGRESS
		 * in the early stages of connection (during crexfer
		 * or the start of sconn), then this request will
		 * eventually be noticed when sconn() is called.  The
		 * sconn() function will notice that the segid is valid,
		 * and perform the CONNXER_ACCEPT tasks instead.
		 *
		 * If this rd's state was in a later stage of the
		 * connection dance (or after a connection exists), a
		 * previous connection request should have been received,
		 * the new connection request will not be expected, and
		 * this will have been caught by noticing the segid was
		 * already valid, and cause a failure, above.
		 */

		rd->rd_segid_valid = B_TRUE;
		rd->rd_rxfersegid = msg->p.m.con_request.send_segid;

		if (rd->rd_state == WRSMD_STATE_NEW) {
			/*
			 * No connection was in progress.  Start a new
			 * connection setup process.
			 */
			/* LINTED: E_CONSTANT_CONDITION */
			WRSMD_SETSTATE(rd, wrsmdp, "wrsmdmsghdlr_req_connect",
			    WRSMD_STATE_S_NEWCONN);

		} else if (rd->rd_state == WRSMD_STATE_W_SCONNTMO) {
			/*
			 * Accept this request instead of resending our
			 * connect request.  Cancel the timeout.  If the
			 * SCONNTMO timeout function is called prior to
			 * cancelling the timeout, it will notice the state
			 * is no longer W_SCONNTMO, and will not cause a
			 * new connection request to be sent.  If the
			 * timeout already occurred (and rd is in the
			 * S_SCONN state), the sconn() function will notice
			 * that the segid is valid, and perform the
			 * CONNXER_ACCEPT tasks instead.
			 */
			/* LINTED: E_CONSTANT_CONDITION */
			WRSMD_SETSTATE(rd, wrsmdp, "wrsmdmsghdlr_req_connect",
			    WRSMD_STATE_S_CONNXFER_ACCEPT);
			utmo = B_TRUE;
			tmoid = rd->rd_tmo_id;
			rd->rd_tmo_id = 0;
			rd->rd_tmo_int = 0;
		}
	}

	mutex_exit(&wrsmdp->wrsmd_runq_lock);
	mutex_exit(&rd->rd_xmit_lock);

	if (utmo)
		(void) untimeout(tmoid);
}



/*
 * Received ACCEPT message.  Cause this side to set up a connection
 * to the remote transfer segment and send back an ACK message.
 */
static void
wrsmdmsghdlr_con_accept(wrsmd_dest_t *rd, wrsmd_msg_t *msg)
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;
	boolean_t utmo = B_FALSE;
	timeout_id_t tmoid;

	D1("wrsmdmsghdlr_con_accept: rd 0x%p (addr %ld ctlr %d)",
	    (void *)rd, rd->rd_rsm_addr, rd->rd_wrsmdp->wrsmd_ctlr_id);

	/*
	 * xmit lock protects segid field
	 */
	mutex_enter(&rd->rd_xmit_lock);
	mutex_enter(&wrsmdp->wrsmd_runq_lock);

	if (rd->rd_state == WRSMD_STATE_W_ACCEPT &&
	    rd->rd_lxfersegid == msg->p.m.con_accept.rcv_segid) {
		rd->rd_segid_valid = B_TRUE;
		rd->rd_rxfersegid = msg->p.m.con_accept.send_segid;
		utmo = B_TRUE;
		tmoid = rd->rd_tmo_id;
		rd->rd_tmo_id = 0;
		/* LINTED: E_CONSTANT_CONDITION */
		WRSMD_SETSTATE(rd, wrsmdp, "wrsmdmsghdlr_con_accept",
		    WRSMD_STATE_S_CONNXFER_ACK);
		mutex_exit(&wrsmdp->wrsmd_runq_lock);
		mutex_exit(&rd->rd_xmit_lock);

		if (utmo)
			(void) untimeout(tmoid);
	} else {
		mutex_exit(&wrsmdp->wrsmd_runq_lock);
		mutex_exit(&rd->rd_xmit_lock);
		wrsmd_lostconn(rd);
		return;
	}

}


/*
 * Received ACK message.  Now ok to proceed with DLPI data transfer.
 */
static void
wrsmdmsghdlr_con_ack(wrsmd_dest_t *rd, wrsmd_msg_t *msg)
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;
	boolean_t utmo = B_FALSE;
	timeout_id_t tmoid;

	D1("wrsmdmsghdlr_con_ack: rd 0x%p (addr %ld ctlr %d)",
	    (void *)rd, rd->rd_rsm_addr, rd->rd_wrsmdp->wrsmd_ctlr_id);

	mutex_enter(&wrsmdp->wrsmd_runq_lock);

	if (rd->rd_state == WRSMD_STATE_W_ACK &&
		msg->p.m.con_ack.rcv_segid == rd->rd_lxfersegid &&
		msg->p.m.con_ack.send_segid == rd->rd_rxfersegid) {
		utmo = B_TRUE;
		tmoid = rd->rd_tmo_id;
		rd->rd_tmo_id = 0;
		/* LINTED: E_CONSTANT_CONDITION */
		WRSMD_SETSTATE(rd, wrsmdp, "wrsmdmsghdlr_con_ack",
		    WRSMD_STATE_S_XFER);
		mutex_exit(&wrsmdp->wrsmd_runq_lock);

		if (utmo)
			(void) untimeout(tmoid);
	} else {
		mutex_exit(&wrsmdp->wrsmd_runq_lock);
		wrsmd_lostconn(rd);
		return;
	}
}


/*
 * Remote side has just sync'ed up the local DQE with its copy, so there
 * may be buffers to deliver.
 */
static void
wrsmdmsghdlr_syncdqe(wrsmd_dest_t *rd, wrsmd_msg_t *msg)
{


	D1("wrsmdmsghdlr_syncdqe: rd 0x%p (addr %ld ctlr %d)",
	    (void *)rd, rd->rd_rsm_addr, rd->rd_wrsmdp->wrsmd_ctlr_id);

	TNF_PROBE_1(wrsmdmsghdlr_syncdqe_start, "RSMPI",
	    "wrsmdmsghdlr_syncdqe start",
	    tnf_long, rd, (tnf_long_t)rd);

	ASSERT(rd->rd_sstate == WRSMD_RSMS_ALL);

	/*
	 * message sanity check
	 */
	if (msg->p.m.syncdqe.rcv_segid != rd->rd_lxfersegid) {
		D1("wrsmdmsghdlr_syncdqe: bad rcv_segid");
		TNF_PROBE_1(wrsmdmsghdlr_syncdqe_end, "RSMPI",
		    "wrsmdmsghdlr_syncdqe end; failure bad msg",
		    tnf_string, failure, "bad msg");
		wrsmd_lostconn(rd);
		return;
	}

	/*
	 * Since we'll eventually call RSM_PUT, and we're
	 * in interrupt context, we need to process this
	 * from the event thread
	 */

	wrsmd_add_event(rd->rd_wrsmdp, WRSMD_EVT_SYNC_DQE, (void *)rd);

}


static void
wrsmdmsghdlr_syncdqe_evt(wrsmd_dest_t *rd)
{
	int bufnum, offset, length;
	ushort_t sap;
	timeout_id_t tmoid;
	int freebufs = 0;


	/* Loop through all valid DQE's and process their packets. */

	D5("msghdlr_syncdqe 1: time 0x%llx", gethrtime());
	while (wrsmdgetdqe(rd, &bufnum, &offset, &length, &sap)) {

		D5("msghdlr_syncdqe 2: time 0x%llx", gethrtime());

		/* Don't try to send up DQE with zero length */

		if (length)
			freebufs += wrsmdread(rd, bufnum, offset, length, sap);
		else {
			wrsmdputfqe(rd, bufnum);
			freebufs++;
		}
		D5("msghdlr_syncdqe 3: time 0x%llx", gethrtime());

		if (freebufs ==
		    rd->rd_wrsmdp->wrsmd_param.wrsmd_fqe_sync_size) {
			freebufs = 0;
			mutex_enter(&rd->rd_net_lock);
			wrsmdsyncfqe(rd);
			mutex_exit(&rd->rd_net_lock);
		}

	}
	if (freebufs) {
		mutex_enter(&rd->rd_net_lock);
		wrsmdsyncfqe(rd);
		mutex_exit(&rd->rd_net_lock);
	}

	mutex_enter(&rd->rd_xmit_lock);

	if (wrsmdisstate(rd, WRSMD_STATE_W_FQE)) {
		int avail = wrsmdavailfqe(rd);

		/*
		 * We hold xmit_lock to keep wrsmdfqetmo() from running while
		 * we're deciding what to do.  In the case where we're waiting
		 * for FQE's but don't have any, if we let fqetmo run before we
		 * set the state back to W_FQE, it won't do anything and we
		 * could hang in that state until another packet came in
		 * (which could be forever).
		 */

		if (avail) {
			tmoid = rd->rd_fqe_tmo_id;
			rd->rd_fqe_tmo_id = 0;
			rd->rd_tmo_int = 0;
			rd->rd_wrsmdp->wrsmd_fqetmo_hint++;
			mutex_exit(&rd->rd_xmit_lock);
			/*
			 * Note: since the fqetmo gets xmit_lock, we have
			 * to release it before we call untimeout() to prevent
			 * a deadlock from occurring.
			 */
			(void) untimeout(tmoid);
			wrsmdsetstate(rd, WRSMD_STATE_S_XFER);
		} else {
			wrsmdsetstate(rd, WRSMD_STATE_W_FQE);
			mutex_exit(&rd->rd_xmit_lock);
		}
	} else {
		mutex_exit(&rd->rd_xmit_lock);
	}

	D1("wrsmdmsghdlr_syncdqe: success");
	TNF_PROBE_0(wrsmd_msg_hdlr_syncdqe_end, "RSMPI",
	    "wrsmd_msg_hdlr_syncdqe end: success");
}


static void
wrsmdmsghdlr_default(wrsmd_dest_t *rd, wrsmd_msg_t *msg)
{
	wrsmderror(rd->rd_wrsmdp->wrsmd_dip, "Unknown message type %d",
	    msg->p.hdr.reqtype);
}


/*
 * Handler for connection-related RSMPI messages from remote WRSMD drivers
 */
/* ARGSUSED */
static rsm_intr_hand_ret_t
wrsmd_rsm_intr_handler(rsm_controller_object_t *controller,
    rsm_intr_q_op_t operation,
    rsm_addr_t sender,
    void *data,
    size_t size,
    rsm_intr_hand_arg_t handler_arg)
{
	wrsmd_t *wrsmdp = (wrsmd_t *)handler_arg;
	wrsmd_dest_t *rd;
	wrsmd_msg_t *msg;
	int isdel = 0;
	/* LINTED E_FUNC_SET_NOT_USED */
	int isnew = 0;
	dl_rsm_addr_t addr;


	/*
	 * We only handle RSM addresses that fit in 48 bits.
	 * This is no problem for Wildcat.
	 */
	ASSERT(sender <= (rsm_addr_t)0xffffffffffffLL);
	addr.m.rsm = sender;

	D1("wrsmd_intr_handle: wrsmdp 0x%p (cltr %d) sender-addr %ld",
	    (void *)wrsmdp,
	    wrsmdp ? wrsmdp->wrsmd_ctlr_id : -1, sender);
	TNF_PROBE_0(wrsmdintrhdlr_start, "RSMPI", "wrsmdintrhdlr start");

	/* Is this our interrupt? */
	mutex_enter(&wrsmdp->wrsmd_lock);
	if (controller->handle != wrsmdp->wrsmd_ctlr.handle) {
		mutex_exit(&wrsmdp->wrsmd_lock);
		D1("wrsmd_intr_handle: bad controller handle");
		return (RSM_INTR_HAND_UNCLAIMED);
	}
	mutex_exit(&wrsmdp->wrsmd_lock);

	/*
	 * We don't really care about anything but a received packet
	 * or a queue destroy
	 */
	switch (operation) {

	case RSM_INTR_Q_OP_CREATE: {
		/*
		 * Create a dest structure, on the assumption that
		 * somebody's about to communicate with us.
		 */
		MAKEDEST(rd, isdel, isnew, wrsmdp, addr.m.wrsm.addr);
		if (isdel || !rd) {
			TNF_PROBE_1(wrsmdintrhdlr_end, "RSMPI",
			    "wrsmdintrhdlr end; failure cantfindormkdest",
			    tnf_string, failure, "cantfindormkdest");
			return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);
		}
		UNREFDEST(rd);
		D1("wrsmd_intr_handle: op-create/config mkdset for addr %ld",
		    addr.m.rsm);
		TNF_PROBE_2(wrsmdintrhdlr_end, "RSMPI", "wrsmdintrhdlr end",
		    tnf_string, success, "queue created",
		    tnf_long, rval, DDI_SUCCESS);
		return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);
	}

	case RSM_INTR_Q_OP_CONFIGURE:
		/* ignore configure messages */
		return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);

	case RSM_INTR_Q_OP_DROP:
	case RSM_INTR_Q_OP_DESTROY: {
		/*
		 * The remote side has shut down the connection.  We need
		 * to shut local side of the connection down as well.
		 */
		FINDDEST(rd, isdel, wrsmdp, addr.m.rsm);
		if (isdel || !rd) {
			TNF_PROBE_1(wrsmdintrhdlr_end, "RSMPI",
			    "wrsmdintrhdlr end; failure cantfinddest",
			    tnf_string, failure, "cantfinddest");
			return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);
		}
		D1("wrsmd_intr_handle: op-destroy for addr %ld", addr.m.rsm);
		wrsmd_lostconn(rd);
		UNREFDEST(rd);
		TNF_PROBE_2(wrsmdintrhdlr_end, "RSMPI", "wrsmdintrhdlr end",
		    tnf_string, success, "queue destroyed",
		    tnf_long, rval, DDI_SUCCESS);
		return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);
	}

	case RSM_INTR_Q_OP_RECEIVE:
		/*
		 * A DLPI message from the remote node.  Handle in the main
		 * body.
		 */
		break;

	default:
		/* ignore */
		TNF_PROBE_0(wrsmdintrhdlr_end, "RSMPI",
		    "wrsmdintrhdlr end; unknown message type");
		return (RSM_INTR_HAND_UNCLAIMED);
	}

	/*
	 * Dest should already exist, having been created by the
	 * RSM_INTR_Q_OP_CREATE, above.
	 */

	FINDDEST(rd, isdel, wrsmdp, addr.m.rsm);
	if (isdel) {
		TNF_PROBE_1(wrsmdintrhdlr_end, "RSMPI",
		    "wrsmdintrhdlr end; failure dest deleting",
		    tnf_string, failure, "deleting");
		return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);
	} else if (rd == NULL) {
		D1("wrsmd_rsm_intr_handler: can't finddest");
		TNF_PROBE_1(wrsmdintrhdlr_end, "RSMPI",
		    "wrsmdintrhdlr end; failure cantfinddest",
		    tnf_string, failure, "cantfinddest");
		return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);
	}


	msg = (wrsmd_msg_t *)data;

	if (msg->p.hdr.wrsmd_version != WRSMD_VERSION) {
		/*
		 * Non-matching driver version!
		 * Toss message.
		 */
		wrsmderror(wrsmdp->wrsmd_dip,
		    "non-matching wrsmd version (%d) in "
		    "message", msg->p.hdr.wrsmd_version);
		UNREFDEST(rd);
		return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);
	}

	switch (msg->p.hdr.reqtype) {

	case WRSMD_MSG_REQ_CONNECT:
		wrsmdmsghdlr_req_connect(rd, msg);
		break;

	case WRSMD_MSG_CON_ACCEPT:
		wrsmdmsghdlr_con_accept(rd, msg);
		break;

	case WRSMD_MSG_CON_ACK:
		wrsmdmsghdlr_con_ack(rd, msg);
		break;

		/*
		 * Maybe scan the incoming queue at this time?
		 */
	case WRSMD_MSG_SYNC_DQE:
		wrsmdmsghdlr_syncdqe(rd, msg);
		break;

	default:
		wrsmdmsghdlr_default(rd, msg);
		break;
	}

	UNREFDEST(rd);

	TNF_PROBE_2(wrsmdintrhdlr_end, "RSMPI", "wrsmdintrhdlr end",
	    tnf_string, success, "",
	    tnf_long, rval, DDI_SUCCESS);
	return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);
}

/*
 * ****************************************************************
 *                                                               *
 * E N D       HANDLERS FOR INCOMING RSM MESSAGES                *
 *                                                               *
 * ****************************************************************
 */



/*
 * ****************************************************************
 *                                                               *
 * B E G I N   CONNECTION MANAGEMENT                             *
 *                                                               *
 * ****************************************************************
 */

/*
 * Create and initialize a transfer segment for the remote destination.  If
 * successful, return 0, else 1.  The destination's state must be
 * INPROGRESS.  In remains INPROGRESS during this function.
 */
static int
wrsmdcrexfer(wrsmd_t *wrsmdp, wrsmd_dest_t *rd)
{
	volatile wrsmd_xfer_hdr_t *xfer;
	wrsmd_fqe_t fqe;
	volatile wrsmd_fqe_t *fqep;
	wrsmd_dqe_t dqe;
	volatile wrsmd_dqe_t *dqep;
	wrsmdbuf_t *rbp;
	uint_t bufsize;
	int i, stat;
	uint32_t buf_offset, fq_offset, dq_offset;
	size_t xfer_size;
	caddr_t xfer_start;
	size_t roundup;
	size_t transport_pgsize = 0;
	rsm_access_entry_t perms;

	D1("wrsmdcrexfer: rd 0x%p (addr %ld ctlr %d)",
	    (void *)rd, rd->rd_rsm_addr, wrsmdp->wrsmd_ctlr_id);
	TNF_PROBE_2(wrsmdcrexfer_start, "RSMPI", "wrsmdcrexfer start",
	    tnf_long, wrsmdp, (tnf_long_t)wrsmdp, tnf_long, rd, (tnf_long_t)rd);

	ASSERT(rd->rd_rawmem_base_addr == NULL);
	ASSERT(rd->rd_rawmem_base_size == 0);

	bufsize = wrsmdp->wrsmd_param.wrsmd_buffer_size;

	for (i = 0; i <  (sizeof (size_t) * 8); i++) {
		if (wrsmdp->wrsmd_ctlr_attr->attr_page_size &
		    ((size_t)1 << i)) {
			transport_pgsize = 1024 << i;
			break;
		}
	}
	if (transport_pgsize == 0) {
		cmn_err(CE_CONT, "?wrsmd: crexfer, invalid transport "
		    "page sizes (attr_page_size is 0x%lx)",
		    wrsmdp->wrsmd_ctlr_attr->attr_page_size);
		return (1);
	}


	/*
	 * Make sure the remote side is responding before setting
	 * up the local xfer segment.
	 */
	stat = RSM_SENDQ_CREATE(wrsmdp->wrsmd_ctlr, rd->rd_rsm_addr,
	    RSM_INTR_T_SUN_BASE, RSM_DLPI_QPRI, RSM_DLPI_QDEPTH,
	    RSM_DLPI_QFLAGS, RSM_RESOURCE_DONTWAIT, 0, &(rd->rsm_sendq));

	if (stat != RSM_SUCCESS) {
		D1("wrsmdcrexfer: can't create send queue, stat 0x%x, "
		    "returning 1", stat);
		TNF_PROBE_2(wrsmdcrexfer_end, "RSMPI",
		    "wrsmdcrexfer end; failure RSM_SENDQ_CREATE",
		    tnf_string, failure, "RSM_SENDQ_CREATE",
		    tnf_long, stat, stat);
		cmn_err(CE_CONT, "?wrsmd: crexfer create send queue, "
		    "stat 0x%x", stat);
		return (1);
	}
	rd->rd_sstate |= WRSMD_RSMS_RXFER_S;


	/*
	 * Allocate memory for segment.  Allow for alignment of DQE list
	 * and FQE list.  Also allow buffers to be aligned on
	 * RSM-page-sized boundaries.
	 */
	xfer_size = sizeof (*xfer) + 64 +
	    (sizeof (wrsmd_dqe_t) * wrsmdp->wrsmd_param.wrsmd_queue_size)
	    + 64 +
	    (sizeof (wrsmd_fqe_t) * wrsmdp->wrsmd_param.wrsmd_queue_size)
	    + 64 +
	    (bufsize * wrsmdp->wrsmd_param.wrsmd_buffers)
	    + (transport_pgsize -1);

	xfer_start = kmem_alloc(xfer_size, KM_NOSLEEP);
	if (!xfer_start) {
		D1("wrsmdcrexfer: can't allocate memory, returning 1");
		TNF_PROBE_1(wrsmdcrexfer_end, "RSMPI",
		    "wrsmdcrexfer end; failure kmem_alloc",
		    tnf_string, failure, "kmem_alloc");
		cmn_err(CE_CONT, "?wrsmd: crexfer, failed to alloc");
		return (1);
	}
	rd->rd_rawmem_base_addr = xfer_start;
	rd->rd_rawmem_base_size = xfer_size;

	/*
	 * Round up memory pointer and round down size to allow alignment
	 * within the transport's supported page size.
	 */
	roundup = transport_pgsize - ((uint64_t)xfer_start &
	    (transport_pgsize -1));
	if (roundup != transport_pgsize) {
		xfer_size -= roundup;
		xfer_start += roundup;
	}
	xfer_size = xfer_size & ~(transport_pgsize - 1);
	rd->rd_memory.ms_type = RSM_MEM_VADDR;
	rd->rd_memory.ms_memory.vr.length = xfer_size;
	rd->rd_memory.ms_memory.vr.as = NULL;	/* kas */
	rd->rd_memory.ms_memory.vr.vaddr = xfer_start;

	D2("wrsmdcrexfer: rawsize 0x%lx rawmem 0x%p xfersize 0x%lx "
	    "xfermem 0x%p pgsize 0x%lx\n",
	    rd->rd_rawmem_base_size,
	    (void *)rd->rd_rawmem_base_addr,
	    xfer_size,
	    (void *)xfer_start,
	    transport_pgsize);

	xfer = (volatile struct wrsmd_xfer_hdr *)xfer_start;

	/* Force FQ to start on a 64-byte boundary. */
	fq_offset = sizeof (struct wrsmd_xfer_hdr);
	fq_offset = WRSMD_CACHELINE_ROUNDUP(fq_offset);

	/* Force DQ to start on a 64-byte boundary. */
	dq_offset = fq_offset + (sizeof (wrsmd_fqe_t) *
	    wrsmdp->wrsmd_param.wrsmd_queue_size);
	dq_offset = WRSMD_CACHELINE_ROUNDUP(dq_offset);

	/* Force buffers to start on a 64-byte boundary. */
	buf_offset = dq_offset + (sizeof (wrsmd_dqe_t) *
	    wrsmdp->wrsmd_param.wrsmd_queue_size);
	buf_offset = WRSMD_CACHELINE_ROUNDUP(buf_offset);

	/*
	 * Note that while we set the _f and _n queue pointers and the
	 * queue lengths here, the _l pointers will be set (and the lengths
	 * may be adjusted) when we connect to the remote xfer segment (see
	 * connxfer).
	 */
	mutex_enter(&rd->rd_net_lock);

	rd->rd_fqr_f = rd->rd_fqr_n = (volatile wrsmd_fqe_t *) (xfer_start +
	    fq_offset);
	rd->rd_fqr_seq = 1;
	rd->rd_num_fqrs = wrsmdp->wrsmd_param.wrsmd_queue_size;

	rd->rd_dqr_f = rd->rd_dqr_n = (volatile wrsmd_dqe_t *) (xfer_start +
	    dq_offset);
	rd->rd_dqr_seq = 1;
	rd->rd_num_dqrs = wrsmdp->wrsmd_param.wrsmd_queue_size;

	rd->rd_lbuf = xfer_start + buf_offset;
	rd->rd_lbuflen = bufsize;
	rd->rd_numlbufs = wrsmdp->wrsmd_param.wrsmd_buffers;

	/*
	 * Initialize the delivery and free queues:  elements in the free
	 * queue are valid, and elements in the delivery queue are invalid
	 * (seqno == 0).
	 */
	fqep = rd->rd_fqr_f;
	dqep = rd->rd_dqr_f;

	dqe.s.dq_seqnum = 0;
	dqe.s.dq_bufnum = (ushort_t)~0;

	fqe.s.fq_seqnum = 1;

	for (i = 0; i < wrsmdp->wrsmd_param.wrsmd_queue_size; i++) {
		fqe.s.fq_bufnum = (ushort_t)i;

		*fqep++ = fqe;
		*dqep++ = dqe;
	}

	mutex_exit(&rd->rd_net_lock);

	/*
	 * Allocate and init our structures to describe loaned-up buffers.
	 */

	rbp = rd->rd_bufbase = kmem_zalloc(wrsmdp->wrsmd_param.wrsmd_buffers *
	    sizeof (*rd->rd_bufbase), KM_NOSLEEP);

	if (rbp == NULL) {
		D1("wrsmdcrexfer: can't alloc rbp structs, returning 1");
		TNF_PROBE_2(wrsmdcrexfer_end, "RSMPI",
		    "wrsmdcrexfer end; failure kmem_zalloc bufbase",
		    tnf_string, failure, "kmem_zalloc",
		    tnf_long, stat, (tnf_long_t)rbp);
		cmn_err(CE_CONT, "?wrsmd: abuf");
		return (1);
	}

	for (i = 0; i < rd->rd_numlbufs; i++) {
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rbp))
		rbp->rb_rd = rd;
		rbp->rb_frtn.free_func = wrsmdfreebuf;
		rbp->rb_frtn.free_arg = (char *)rbp;
		rbp->rb_bufnum = i;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*rbp))
		rbp++;
	}

	mutex_init(&rd->rd_nlb_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&rd->rd_nlb_lock);
	rd->rd_nlb = 0;
	mutex_exit(&rd->rd_nlb_lock);

	/*
	 * Set everything in the header of the segment.
	 */

	xfer->rx_segsize = xfer_size;
	xfer->rx_buf_offset = buf_offset;
	xfer->rx_fq_offset = fq_offset;
	xfer->rx_dq_offset = dq_offset;
	xfer->rx_numbufs = rd->rd_numlbufs;
	xfer->rx_bufsize = rd->rd_lbuflen;
	xfer->rx_numfqes = rd->rd_num_fqrs;
	xfer->rx_numdqes = rd->rd_num_dqrs;

	D1("wrsmdcrexfer: rx_buf_offset 0x%x fq_offset 0x%x dq_offset 0x%x "
	    "rd_numlbufs 0x%x rd_lbuflen 0x%x rd_num_fqrs 0x%x "
	    "rd_num_dqrs 0x%x\n",
	    buf_offset,
	    fq_offset,
	    dq_offset,
	    rd->rd_numlbufs,
	    rd->rd_lbuflen,
	    rd->rd_num_fqrs,
	    rd->rd_num_dqrs);

	xfer->rx_cookie = WRSMD_XFER_COOKIE;

	/*
	 * Local xfer segment is now initialized; make it available to the
	 * remote node.
	 */

	stat = RSM_SEG_CREATE(wrsmdp->wrsmd_ctlr, &(rd->rd_lxferhand),
	    xfer_size, 0, &(rd->rd_memory), RSM_RESOURCE_DONTWAIT, 0);

	if (stat != RSM_SUCCESS) {
		D1("wrsmdcrexfer: can't create RSM segment, stat 0x%x, "
		    "return 1", stat);
		TNF_PROBE_2(wrsmdcrexfer_end, "RSMPI",
		    "wrsmdcrexfer end; failure RSM_SEG_CREATE",
		    tnf_string, failure, "RSM_SEG_CREATE",
		    tnf_long, stat, stat);
		cmn_err(CE_CONT, "?wrsmd: crexfer, stat 0x%x", stat);
		return (1);
	}
	rd->rd_sstate |= WRSMD_RSMS_LXFER_C;


	/*
	 * Publish this segment.  First try using an id that is likely
	 * to be unique.
	 */
	perms.ae_addr = rd->rd_rsm_addr;
	perms.ae_permission = RSM_PERM_RDWR;
	stat = RSMERR_SEGID_IN_USE;
	if (rd->rd_rsm_addr <= (RSM_DLPI_ID_END - RSM_DLPI_ID_BASE)) {
		rd->rd_lxfersegid = RSM_DLPI_ID_BASE +
		    (uint32_t)rd->rd_rsm_addr;
		stat = (RSM_PUBLISH(wrsmdp->wrsmd_ctlr, rd->rd_lxferhand,
		    &perms, 1, rd->rd_lxfersegid, NULL, 0));
	}
	if (stat == RSMERR_SEGID_IN_USE) {
		/* Couldn't use default id; try other ids in allowed range  */
		rd->rd_lxfersegid = RSM_DLPI_ID_BASE;
		while ((stat = (RSM_PUBLISH(wrsmdp->wrsmd_ctlr,
		    rd->rd_lxferhand,
		    &perms, 1, rd->rd_lxfersegid, NULL, 0))) ==
		    RSMERR_SEGID_IN_USE && rd->rd_lxfersegid < RSM_DLPI_ID_END)
			rd->rd_lxfersegid++;
	}

	if (stat != RSM_SUCCESS) {
		D1("wrsmdcrexfer: can't publish, stat 0x%x, returning 1",
		    stat);
		TNF_PROBE_2(wrsmdcrexfer_end, "RSMPI",
		    "wrsmdcrexfer end; failure wrsmd_export_segment",
		    tnf_string, failure, "wrsmd_export_segment",
		    tnf_long, stat, stat);
		cmn_err(CE_CONT, "?wrsmd: expxfer, stat 0x%x", stat);
		return (1);
	}
	rd->rd_sstate |= WRSMD_RSMS_LXFER_P;

	D1("wrsmdcrexfer: returning 0");
	TNF_PROBE_2(wrsmdcrexfer_end, "RSMPI", "wrsmdcrexfer end",
	    tnf_string, completed, "",
	    tnf_long, stat, 0);
	return (0);
}

/*
 * Send a connect request to the remote.
 *
 * If we've received a Connect message from the destination, connect to the
 * remote transfer segment.  Otherwise, send them a Connect Request
 * message.  On success, return 0.  If the connect fails return 1.  A
 * failure in sending a Connect Request message will result in a retry
 * timeout being scheduled, but will not return 1 unless the total timeout
 * period has expired.  Destination's state must be INPROGRESS when called.
 * Destination's state is set to a new state prior to returning.
 */
static int
wrsmdsconn(
	wrsmd_t *wrsmdp,	/* WRSMD device (RSM controller) pointer */
	wrsmd_dest_t *rd,	/* Destination pointer */
	int fromtmo)	/* 0 if this is our first attempt; nonzero if this */
			/*  is a retry, requested by a timeout routine. */
{
	int stat;

	D1("wrsmdsconn: rd 0x%p (addr %ld ctlr %d)",
	    (void *)rd, rd->rd_rsm_addr, wrsmdp->wrsmd_ctlr_id);
	TNF_PROBE_3(wrsmdsconn_start, "RSMPI", "wrsmdsconn start",
	    tnf_long, wrsmdp, (tnf_long_t)wrsmdp, tnf_long, rd, (tnf_long_t)rd,
	    tnf_long, fromtmo, fromtmo);

	if (rd->rd_segid_valid) {
		/*
		 * We've gotten a Connect Request from the remote side
		 * while in INPROGRESS state.  Don't send our request;
		 * instead, connect to the remote transfer segment.
		 */

		if ((stat = wrsmdconnxfer(wrsmdp, rd)) != 0) {
			return (stat);
		}
		return (wrsmdsaccept(wrsmdp, rd));
	}

	/*
	 * We haven't gotten a Connect Request from them, so we
	 * need to send one of our own.
	 */

	/*
	 * If this is a timeout retry, send the same Connect Request
	 * message we sent the first time.
	 */
	if (fromtmo) {
		stat = wrsmdsendmsg(rd, WRSMD_REXMIT, 0);
	} else {
		wrsmd_msg_t msg;
		msg.p.m.con_request.send_segid = rd->rd_lxfersegid;
		stat = wrsmdsendmsg(rd, WRSMD_MSG_REQ_CONNECT, &msg);
	}

	/*
	 * xmit lock guarantees new state and timeout setup both occur
	 * without an intervening state change.  See
	 * wrsmdmsghdlr_req_connect().
	 */
	mutex_enter(&rd->rd_xmit_lock);

	if (stat == RSM_SUCCESS) {	/* Success */
		/*
		 * Set up a timeout to remind us if an ACCEPT never
		 * shows up.  This is only a 1-time timeout, no
		 * backoff is needed.
		 */

		wrsmdsetstate(rd, WRSMD_STATE_W_ACCEPT);

		rd->rd_tmo_int = wrsmdp->wrsmd_param.wrsmd_ack_tmo;
		rd->rd_tmo_tot = 0;
		rd->rd_tmo_id = timeout(wrsmdaccepttmo, (caddr_t)rd,
		    rd->rd_tmo_int);
	} else {
		/*
		 * We couldn't send the message, set up a timeout to
		 * try again a little later.
		 */

		wrsmdsetstate(rd, WRSMD_STATE_W_SCONNTMO);

		if (!fromtmo) {
			rd->rd_tmo_int =
			    wrsmdp->wrsmd_param.wrsmd_msg_init_tmo;
			rd->rd_tmo_tot = 0;
			D2("wrsmdsconn: !fromtmo, tmo_int %d, "
			    "tmo_tot %d", rd->rd_tmo_int,
			    rd->rd_tmo_tot);
		} else {
			/* Do exponential backoff */

			rd->rd_tmo_tot += rd->rd_tmo_int;
			rd->rd_tmo_int *= 2;

			/* If we've waited too long, fail */

			if (rd->rd_tmo_tot >=
			    wrsmdp->wrsmd_param.wrsmd_msg_drop_tmo) {
				TNF_PROBE_2(wrsmdsconn_end, "RSMPI",
				    "wrsmdsconn end; failure timeout",
				    tnf_string, failure, "timeout",
				    tnf_long, stat, rd->rd_tmo_tot);
				mutex_exit(&rd->rd_xmit_lock);
				(void) wrsmdgetstate(rd);
				D1("wrsmdsconn: tmo limit reached, "
				    "returning 1");
				return (1);
			}

			/* Clip timeout to maximum */

			if (rd->rd_tmo_int >
			    wrsmdp->wrsmd_param.wrsmd_msg_max_tmo)
				rd->rd_tmo_int =
				    wrsmdp->wrsmd_param.wrsmd_msg_max_tmo;

			D2("wrsmdsconn: tmo_int %d, tmo_tot %d",
			    rd->rd_tmo_int, rd->rd_tmo_tot);
		}

		rd->rd_tmo_id = timeout(wrsmdsconntmo, (caddr_t)rd,
		    rd->rd_tmo_int);
	}

	mutex_exit(&rd->rd_xmit_lock);

	D1("wrsmdsconn: returning 0");
	TNF_PROBE_2(wrsmdsconn_end, "RSMPI", "wrsmdsconn end",
	    tnf_string, completed, "",
	    tnf_long, stat, 0);
	return (0);
}


/*
 * Connect to the transfer segment on the destination machine.  If an error
 * occurs, return 1.  Destination state must be INPROGRESS.  It remains
 * INPROGRESS during this function.
 */
static int
wrsmdconnxfer(wrsmd_t *wrsmdp, wrsmd_dest_t *rd)
{
	uint_t num_rbufs;
	int stat;
	int i;
	wrsmd_fqe_t fqe;
	volatile wrsmd_fqe_t *fqep;
	wrsmd_dqe_t dqe;
	volatile wrsmd_dqe_t *dqep;
	size_t segsize;

	D1("wrsmdconnxfer: rd 0x%p (addr %ld ctlr %d)",
	    (void *)rd, rd->rd_rsm_addr, wrsmdp->wrsmd_ctlr_id);
	TNF_PROBE_2(wrsmdconnxfer_start, "RSMPI", "wrsmdconnxfer start",
	    tnf_long, wrsmdp, (tnf_long_t)wrsmdp, tnf_long, rd, (tnf_long_t)rd);

	mutex_enter(&rd->rd_xmit_lock);

	stat = RSM_CONNECT(wrsmdp->wrsmd_ctlr, rd->rd_rsm_addr,
	    rd->rd_rxfersegid, &(rd->rd_rxferhand));
	if (stat != RSM_SUCCESS) {
		D1("wrsmdconnxfer: can't connxfer, stat 0x%x, returning 1",
		    stat);
		cmn_err(CE_CONT, "?wrsmd: connxfer, stat 0x%x", stat);
		TNF_PROBE_2(wrsmdconnxfer_end, "RSMPI",
		    "wrsmdconnxfer end; failure RSM_CONNECT",
		    tnf_string, failure, "RSM_CONNECT",
		    tnf_long, stat, stat);
		mutex_exit(&rd->rd_xmit_lock);
		return (1);
	}

	rd->rd_sstate |= WRSMD_RSMS_RXFER_C;


	/*
	 * Copy entire header struct into local memory
	 */

	stat = RSM_GET(wrsmdp->wrsmd_ctlr, rd->rd_rxferhand, 0,
	    &(rd->rd_rxferhdr), sizeof (wrsmd_xfer_hdr_t));
	if (stat != RSM_SUCCESS) {
		D1("wrsmdconnxfer: can't read xfer header, returning 1");
		TNF_PROBE_2(wrsmdconnxfer, "RSMPI",
		    "wrsmdconnxfer end; failure timeout",
		    tnf_string, failure, "timeout",
		    tnf_long, stat, 1);
		cmn_err(CE_CONT, "?wrsmd: read xfer header failed, err=%d",
			stat);
		mutex_exit(&rd->rd_xmit_lock);
		return (1);
	}



	/*
	 * Validate header structure, extract some values from it
	 */
	if (rd->rd_rxferhdr.rx_cookie != WRSMD_XFER_COOKIE) {
		D1("wrsmdconnxfer: badxfer, cookie 0x%x, returning 1",
		    rd->rd_rxferhdr.rx_cookie);
		TNF_PROBE_1(wrsmdconnxfer, "RSMPI",
		    "wrsmdconnxfer end; failure 'bad xfer'",
		    tnf_string, failure, "bad xfer");
		cmn_err(CE_CONT, "?wrsmd: badxfer, cookie 0x%x",
		    (uint_t)rd->rd_rxferhdr.rx_cookie);
		mutex_exit(&rd->rd_xmit_lock);
		return (1);
	}

	D1("wrsmdconnxfer: remote buf_offset 0x%x fq_offset 0x%x "
	    "dq_offset 0x%x rd_numbufs 0x%x rd_lbuflen 0x%x "
	    "rd_numfqes 0x%x rd_numdqes 0x%x\n",
		rd->rd_rxferhdr.rx_buf_offset,
		rd->rd_rxferhdr.rx_fq_offset,
		rd->rd_rxferhdr.rx_dq_offset,
		rd->rd_rxferhdr.rx_numbufs,
		rd->rd_rxferhdr.rx_bufsize,
		rd->rd_rxferhdr.rx_numfqes,
		rd->rd_rxferhdr.rx_numdqes);

	segsize = rd->rd_rxferhdr.rx_segsize;

	num_rbufs = rd->rd_rxferhdr.rx_numbufs;

	D1("num_rbufs 0x%x wrsmd_queue_size 0x%x\n", num_rbufs,
		wrsmdp->wrsmd_param.wrsmd_queue_size);
	/*
	 * Must be at least one more element in queue than the
	 * number of buffers, so that we can track when all queue
	 * elements need to be flushed to remote side.
	 */
	if (num_rbufs >= wrsmdp->wrsmd_param.wrsmd_queue_size)
		num_rbufs = wrsmdp->wrsmd_param.wrsmd_queue_size - 1;

	mutex_enter(&rd->rd_net_lock);

	rd->rd_rbufoff = rd->rd_rxferhdr.rx_buf_offset;
	rd->rd_rbuflen = rd->rd_rxferhdr.rx_bufsize;
	rd->rd_numrbuf = num_rbufs;
	if ((rd->rd_rbufoff + (rd->rd_rbuflen * num_rbufs)) > segsize) {
		D1("wrsmd: badxfer, rbufoff too big");
		cmn_err(CE_CONT, "?wrsmd: badxfer, rbufoff too big");
		mutex_exit(&rd->rd_net_lock);
		mutex_exit(&rd->rd_xmit_lock);
		return (1);
	}

	rd->rd_fqw_f_off = rd->rd_rxferhdr.rx_fq_offset;
	rd->rd_num_fqws = rd->rd_rxferhdr.rx_numfqes;

	if ((rd->rd_fqw_f_off + (sizeof (wrsmd_fqe_t) * rd->rd_num_fqws))
	    > segsize) {
		D1("wrsmd: badxfer, fqw_f_off too big");
		cmn_err(CE_CONT, "?wrsmd: badxfer, fqw_f_off too big");
		mutex_exit(&rd->rd_net_lock);
		mutex_exit(&rd->rd_xmit_lock);
		return (1);
	}

	rd->rd_dqw_f_off = rd->rd_rxferhdr.rx_dq_offset;
	rd->rd_num_dqws = rd->rd_rxferhdr.rx_numdqes;

	if ((rd->rd_dqw_f_off + (sizeof (wrsmd_dqe_t) * rd->rd_num_dqws))
	    > segsize) {
		D1("wrsmd: badxfer, dqw_f_off too big");
		cmn_err(CE_CONT, "?wrsmd: badxfer, dqw_f_off too big");
		mutex_exit(&rd->rd_net_lock);
		mutex_exit(&rd->rd_xmit_lock);
		return (1);
	}

	/*
	 * Now that we know the number of remote buffers and queue elements,
	 * shrink everything to fit and calculate the ends of all queues.
	 */


	D1("rd_numlbufs 0x%x rd_num_fqws 0x%x rd_num_dqrs 0x%x\n",
	    rd->rd_numlbufs, rd->rd_num_fqws, rd->rd_num_dqrs);
	rd->rd_numlbufs =
		min(rd->rd_numlbufs, min(rd->rd_num_fqws - 1,
		rd->rd_num_dqrs - 1));
	rd->rd_num_fqws = rd->rd_num_dqrs =
		min(rd->rd_numlbufs + 1, min(rd->rd_num_fqws, rd->rd_num_dqrs));

	D1("rd_numrbuf 0x%x rd_num_fqrs 0x%x rd_num_dqws 0x%x\n",
	    rd->rd_numrbuf, rd->rd_num_fqrs, rd->rd_num_dqws);
	rd->rd_numrbuf =
		min(rd->rd_numrbuf, min(rd->rd_num_fqrs - 1,
		rd->rd_num_dqws - 1));
	rd->rd_num_fqrs = rd->rd_num_dqws =
		min(rd->rd_numrbuf + 1, min(rd->rd_num_fqrs, rd->rd_num_dqws));

	rd->rd_fqr_l = rd->rd_fqr_f + rd->rd_num_fqrs - 1;
	/* mark last entry of free queue as invalid */
	rd->rd_fqr_l->s.fq_seqnum = 0;
	rd->rd_fqr_l->s.fq_bufnum = (ushort_t)~0;
	rd->rd_dqr_l = rd->rd_dqr_f + rd->rd_num_dqrs - 1;

	/* Create FQE cache, outgoing FQE/DQE queues */

	D1("wrsmdconnxfer: num_fqrs 0x%x num_fqws 0x%x num_dqws 0x%x",
	    rd->rd_num_fqrs, rd->rd_num_fqws, rd->rd_num_dqws);

	if ((rd->rd_rbufoff + (rd->rd_rbuflen * num_rbufs)) > segsize) {
		D1("wrsmd: badxfer, bufsize * num buf too big");
		cmn_err(CE_CONT, "?wrsmd: badxfer, bufsize * num buf too big");
		mutex_exit(&rd->rd_net_lock);
		mutex_exit(&rd->rd_xmit_lock);
		return (1);
	}
	if ((rd->rd_fqw_f_off + (sizeof (wrsmd_fqe_t) * rd->rd_num_fqws))
	    > segsize) {
		D1("wrsmd: badxfer, fqesize * num fqe too big");
		cmn_err(CE_CONT, "?wrsmd: badxfer, fqesize * num fqe too big");
		mutex_exit(&rd->rd_net_lock);
		mutex_exit(&rd->rd_xmit_lock);
		return (1);
	}
	if ((rd->rd_dqw_f_off + (sizeof (wrsmd_dqe_t) * rd->rd_num_dqws))
	    > segsize) {
		D1("wrsmd: badxfer, dqesize * num dqe too big");
		cmn_err(CE_CONT, "?wrsmd: badxfer, dqesize * num dqe too big");
		mutex_exit(&rd->rd_net_lock);
		mutex_exit(&rd->rd_xmit_lock);
		return (1);
	}

	rd->rd_cached_fqr = kmem_alloc(sizeof (*rd->rd_cached_fqr) *
		rd->rd_num_fqrs, KM_NOSLEEP);

	/*
	 * Make sure any local queue that will be transferred or sync'd is
	 * WRSMD_CACHLINE_SIZE'd aligned. This means that when the data is
	 * loaded into the FPU registers for transfer,it is already aligned.
	 * This is a minor optimisation. For FireLink, only the remote
	 * (destination) side needs to be aligned for interconnect
	 * performance.
	 */

	rd->rd_shdwfqw_f_addr = kmem_alloc((sizeof (wrsmd_fqe_t) *
		rd->rd_num_fqws) + WRSMD_CACHELINE_SIZE, KM_NOSLEEP);

	rd->rd_shdwdqw_f_addr = kmem_alloc((sizeof (wrsmd_dqe_t) *
		rd->rd_num_dqws) + WRSMD_CACHELINE_SIZE, KM_NOSLEEP);

	if (rd->rd_cached_fqr == NULL || rd->rd_shdwfqw_f_addr == NULL ||
	    rd->rd_shdwdqw_f_addr == NULL) {
		D1("wrsmdconnxfer: can't alloc memory for shadow queues, "
		    "returning 1");
		TNF_PROBE_2(wrsmdconnxfer, "RSMPI",
		    "wrsmdconnxfer end; failure kmem_alloc",
		    tnf_string, failure, "kmem_alloc",
		    tnf_long, stat, 1);
		cmn_err(CE_CONT, "?wrsmd: can't get memory in connxfer");
		mutex_exit(&rd->rd_net_lock);
		mutex_exit(&rd->rd_xmit_lock);
		return (1);
	}

	rd->rd_shdwfqw_f = (wrsmd_fqe_t *)
		WRSMD_CACHELINE_ROUNDUP(rd->rd_shdwfqw_f_addr);
	rd->rd_shdwdqw_f = (wrsmd_dqe_t *)
		WRSMD_CACHELINE_ROUNDUP(rd->rd_shdwdqw_f_addr);

	/*
	 * Initialize the shadow delivery and free queues:  all elements in
	 * the free queue are valid except the last entry, and all elements in
	 * the delivery queue are invalid.  It is necessary to initialize
	 * because when we do an wrsmdsyncfqe() or wrsmdsyncdqe(), we may do
	 * an RSM_PUT of more than the newly changed entries (because we
	 * round up/down to 64 byte boundaries).
	 */

	rd->rd_shdwfqw_l = rd->rd_shdwfqw_f + rd->rd_num_fqws - 1;
	rd->rd_shdwfqw_i = rd->rd_shdwfqw_o = rd->rd_shdwfqw_l;
	/* still in first round, on last element */
	rd->rd_fqw_seq = 1;

	fqep = rd->rd_shdwfqw_f;
	fqe.s.fq_seqnum = 1;
	i = 0;
	while (fqep <= rd->rd_shdwfqw_l - 1) {
		fqe.s.fq_bufnum = (ushort_t)i++;
		*fqep++ = fqe;
	}
	/* last entry is not valid */
	fqep->s.fq_seqnum = 0;
	fqep->s.fq_bufnum = (ushort_t)~0;

	rd->rd_shdwfqw_errflag = 0;

	D1("wrsmdconnxfer: initialized %d fqe shadow entries", i);


	rd->rd_shdwdqw_l = rd->rd_shdwdqw_f + rd->rd_num_dqws - 1;
	rd->rd_shdwdqw_i = rd->rd_shdwdqw_o = rd->rd_shdwdqw_f;
	/* in first round, on first element */
	rd->rd_dqw_seq = 1;

	dqep = rd->rd_shdwdqw_f;
	dqe.s.dq_seqnum = 0;
	dqe.s.dq_bufnum = (ushort_t)~0;
	while (dqep <= rd->rd_shdwdqw_l) {
		*dqep++ = dqe;
	}

	rd->rd_shdwdqw_errflag = 0;

	mutex_exit(&rd->rd_net_lock);


	D1("wrsmdconnxfer: returning 0");
	TNF_PROBE_2(wrsmdconnxfer_end, "RSMPI", "wrsmdconnxfer end",
	    tnf_string, completed, "", tnf_long, stat, 0);

	mutex_exit(&rd->rd_xmit_lock);
	return (0);
}



/*
 * Send an ACCEPT message to the destination.
 * Return 1 if this send fails, else set state to W_ACK and return 0.
 * Destination's state must be INPROGRESS.
 * Destination's state is set to a new state on success.
 */
static int
wrsmdsaccept(
	wrsmd_t *wrsmdp,	/* WRSMD device (RSM controller) pointer */
	wrsmd_dest_t *rd)	/* Destination pointer */
{
	int stat;
	wrsmd_msg_t msg;
	int retval = 0;

	D1("wrsmdsaccept: rd 0x%p (addr %ld ctlr %d)",
	    (void *)rd, rd->rd_rsm_addr, wrsmdp->wrsmd_ctlr_id);
	TNF_PROBE_2(wrsmdsaccept_start, "RSMPI", "wrsmdsaccept start",
	    tnf_long, wrsmdp, (tnf_long_t)wrsmdp, tnf_long, rd, (tnf_long_t)rd);

	msg.p.m.con_accept.send_segid = rd->rd_lxfersegid;
	msg.p.m.con_accept.rcv_segid = rd->rd_rxfersegid;
	stat = wrsmdsendmsg(rd, WRSMD_MSG_CON_ACCEPT, &msg);

	mutex_enter(&rd->rd_xmit_lock);

	if (stat == RSM_SUCCESS) {	/* Success */
		wrsmdsetstate(rd, WRSMD_STATE_W_ACK);

		rd->rd_tmo_int =
		    wrsmdp->wrsmd_param.wrsmd_ack_tmo;
		rd->rd_tmo_tot = 0;
		rd->rd_tmo_id = timeout(wrsmdacktmo, (caddr_t)rd,
			    rd->rd_tmo_int);

	} else {		/* Failure */
		retval = 1;
	}
	mutex_exit(&rd->rd_xmit_lock);

	D1("wrsmdsaccept: returning %d", retval);
	TNF_PROBE_2(wrsmdsaccept_end, "RSMPI", "wrsmdaccept end",
	    tnf_string, completed, "", tnf_long, stat, retval);
	return (retval);
}


/*
 * Send an ACK response to the destination.
 * Return 1 if this send fails, else set state to READY and return 0.
 * Destination's state must be INPROGRESS.
 * Destination's state is set to a new state on success.
 */
static int
wrsmdsack(
	wrsmd_t *wrsmdp,	/* WRSMD device (RSM controller) pointer */
	wrsmd_dest_t *rd)	/* Destination pointer */
{
	int stat;
	wrsmd_msg_t msg;
	int retval = 0;

	D1("wrsmdsack: rd 0x%p (addr %ld ctlr %d)",
	    (void *)rd, rd->rd_rsm_addr, wrsmdp->wrsmd_ctlr_id);
	TNF_PROBE_2(wrsmdsack_start, "RSMPI", "wrsmdsack start",
	    tnf_long, wrsmdp, (tnf_long_t)wrsmdp, tnf_long, rd, (tnf_long_t)rd);

	msg.p.m.con_ack.send_segid = rd->rd_lxfersegid;
	msg.p.m.con_ack.rcv_segid = rd->rd_rxfersegid;
	stat = wrsmdsendmsg(rd, WRSMD_MSG_CON_ACK, &msg);

	mutex_enter(&rd->rd_xmit_lock);

	if (stat == RSM_SUCCESS) {	/* Success */

		if (rd->rd_queue_h)
			wrsmdxfer(wrsmdp, rd);
		else
			wrsmdsetstate(rd, WRSMD_STATE_W_READY);

	} else {		/* Failure */
		retval = 1;
	}

	mutex_exit(&rd->rd_xmit_lock);

	D1("wrsmdsack: returning %d", retval);
	TNF_PROBE_2(wrsmdsack_end, "RSMPI", "wrsmdsack end",
	    tnf_string, completed, "", tnf_long, stat, retval);
	return (retval);
}

/*
 * ****************************************************************
 *                                                               *
 * E N D       CONNECTION MANAGEMENT                             *
 *                                                               *
 * ****************************************************************
 */



/*
 * ****************************************************************
 *                                                               *
 * B E G I N   FREE/DELIVERY QUEUE MANAGEMENT                    *
 *                                                               *
 * ****************************************************************
 */

/*
 * Queue an FQE with the specified buffer number onto the shadow FQ for
 * transmission to the remote system.
 */
static void
wrsmdputfqe(
	wrsmd_dest_t *rd,	/* Destination pointer */
	int bufnum)	/* Number of free buffer */
{
	wrsmd_fqe_t fqe;

	mutex_enter(&rd->rd_net_lock);

	D1("wrsmdputfqe: rd 0x%p (addr %ld ctlr %d), bufnum %d", (void *)rd,
	    rd->rd_rsm_addr, rd->rd_wrsmdp->wrsmd_ctlr_id, bufnum);
	D2("wrsmdputfqe: start shdwfqw_i 0x%p (index %ld) shdwfqw_f 0x%p "
	    "shdwfqw_l 0x%p",
	    (void *)rd->rd_shdwfqw_i,
	    ((char *)rd->rd_shdwfqw_i - (char *)rd->rd_shdwfqw_f)
	    / sizeof (fqe),
	    (void *)rd->rd_shdwfqw_f, (void *)rd->rd_shdwfqw_l);

	fqe.s.fq_filler = 0;
	fqe.s.fq_bufnum = (ushort_t)bufnum;

	*rd->rd_shdwfqw_i = fqe;

	rd->rd_shdwfqw_i = (rd->rd_shdwfqw_i == rd->rd_shdwfqw_l) ?
	    rd->rd_shdwfqw_f : rd->rd_shdwfqw_i + 1;

	ASSERT(rd->rd_shdwfqw_i != rd->rd_shdwfqw_o);

	D1("wrsmdputfqe: done");
	D2("wrsmdputfqe: end shdwfqw_i 0x%p shdwfqw_f 0x%p shdwfqw_l 0x%p",
	    (void *)rd->rd_shdwfqw_i, (void *)rd->rd_shdwfqw_f,
	    (void *)rd->rd_shdwfqw_l);

	mutex_exit(&rd->rd_net_lock);
}

/*
 * Flush any queued FQEs (free queue entries) from the local shadow copy to
 * the remote system's copy.
 */
static void
wrsmdsyncfqe(
	wrsmd_dest_t *rd)	/* Destination pointer */
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;
	uint64_t start_offset, end_offset;
	int stat = RSM_SUCCESS;

	ASSERT(MUTEX_HELD(&rd->rd_net_lock));

	D1("wrsmdsyncfqe: rd 0x%p (addr %ld ctlr %d) index %ld to %ld",
	    (void *)rd,
	    rd->rd_rsm_addr, rd->rd_wrsmdp->wrsmd_ctlr_id,
	    ((char *)rd->rd_shdwfqw_o - (char *)rd->rd_shdwfqw_f) /
	    sizeof (*(rd->rd_shdwfqw_o)),
	    ((char *)rd->rd_shdwfqw_i - (char *)rd->rd_shdwfqw_f) /
	    sizeof (*(rd->rd_shdwfqw_i)));
	D2("wrsmdsyncfqe: shdwfqw_i 0x%p shdwfqw_f 0x%p shdwfqw_l 0x%p",
	    (void *)rd->rd_shdwfqw_i, (void *)rd->rd_shdwfqw_f,
	    (void *)rd->rd_shdwfqw_l);

	/* If nothing's queued, nothing to do */

	if (rd->rd_shdwfqw_i == rd->rd_shdwfqw_o) {
		D1("wrsmdsyncfqe: no work, done");
		return;
	}

	/* If network down, nothing to do either */

	if (rd->rd_stopq) {
		D1("wrsmdsyncfqe: stopq on, done");
		return;
	}

	/*
	 * Send each element in the queue separately.  Since each
	 * element is WRSMD_CACHELINE_SIZE, then we know that
	 * each PUT is atomic, and we won't corrupt the remote
	 * side's free queue if we get a transient error and retry.
	 *
	 * If we try to put more then one element at a time, then it is
	 * possible for some elements to succeed while others fail.
	 * If this is the case then the remote side could possibly consume
	 * those new buffers before the local side retries the put, and
	 * thus the FQ could get corrupted (buffer listed as free when
	 * it really isn't).
	 *
	 */
	while (rd->rd_shdwfqw_o != rd->rd_shdwfqw_i) {

		/* Set the sequence number for this FQE */
		rd->rd_shdwfqw_o->s.fq_seqnum =
			rd->rd_fqw_seq & WRSMD_FQE_SEQ_MASK;

		/*
		 * Set the offset to transfer one fqe at a time.
		 *
		 * NOTE: We already know we are aligned because
		 * we allocated the remote buffer on a WRSMD_CACHELINE_SIZE'd
		 * boundary, and each fqe is WRSMD_CACHELINE_SIZE long.
		 */
		start_offset = (char *)rd->rd_shdwfqw_o -
		    (char *)rd->rd_shdwfqw_f;
		end_offset = start_offset + sizeof (wrsmd_fqe_t);

		/* Push FQE to remote side */
		stat = RSM_PUT(wrsmdp->wrsmd_ctlr, rd->rd_rxferhand,
		    rd->rd_fqw_f_off + start_offset,
		    (char *)rd->rd_shdwfqw_o, end_offset - start_offset);

		if (stat == RSM_SUCCESS) {
			/* Write was sucessful */
			if (rd->rd_shdwfqw_o == rd->rd_shdwfqw_l) {
				/*
				 * Wrap, and update sequence number if
				 * this the is the last fqe
				 */
				rd->rd_shdwfqw_o = rd->rd_shdwfqw_f;

				rd->rd_fqw_seq++;
				if (rd->rd_fqw_seq == 0)
					rd->rd_fqw_seq++;

			} else {
				rd->rd_shdwfqw_o ++;
			}

			rd->rd_shdwfqw_errflag = 0;

		} else {

			wrsmdp->wrsmd_errs++;
			D0("wrsmdsyncfqe: RSM_PUT failed error %d", stat);

			if (stat == RSMERR_CONN_ABORTED) {
				/* permanent connection loss */
				wrsmd_lostconn(rd);
			} else {
				/*
				 * Schedule an event to retry.  Can't do a
				 * timeout here because it would require
				 * calling RSM_PUT from a callback.
				 */

				wrsmd_add_event(wrsmdp, WRSMD_EVT_SYNC,
								(void *)rd);

				rd->rd_shdwfqw_errflag = 1;
			}

			return;
		}

	}

	D1("wrsmdsyncfqe: done");
	D2("wrsmdsyncfqe: shdwfqw_i 0x%p shdwfqw_f 0x%p shdwfqw_l 0x%p",
	    (void *)rd->rd_shdwfqw_i, (void *)rd->rd_shdwfqw_f,
	    (void *)rd->rd_shdwfqw_l);
}

/*
 * Queue a DQE with the specified buffer description onto the shadow DQ for
 * transmission to the remote system.
 */
static void
wrsmdputdqe(
	wrsmd_dest_t *rd,	/* Destination pointer */
	int bufnum,	/* Number of full buffer */
	int offset,	/* Offset of packet from start of buffer */
	uint_t length,	/* Length of packet */
	ushort_t sap)	/* Packet's SAP */
{
	wrsmd_dqe_t dqe;

	mutex_enter(&rd->rd_net_lock);

	D1("wrsmdputdqe: rd 0x%p (ctlr %d addr %ld), bufnum %d, offset %d, "
	    "length %d, sap 0x%x index %ld",
	    (void *)rd, rd->rd_wrsmdp->wrsmd_ctlr_id, rd->rd_rsm_addr,
	    bufnum, offset, length, sap,
	    ((char *)rd->rd_shdwdqw_i - (char *)rd->rd_shdwdqw_f) /
	    sizeof (dqe));
	D2("wrsmdputdqe: start shdwdqw_i 0x%p (index %ld) shdwdqw_f 0x%p "
	    "shdwdqw_l 0x%p",
	    (void *)rd->rd_shdwdqw_i,
	    ((char *)rd->rd_shdwdqw_i - (char *)rd->rd_shdwdqw_f) /
	    sizeof (dqe),
	    (void *)rd->rd_shdwdqw_f,
	    (void *)rd->rd_shdwdqw_l);

	dqe.s.dq_offset = (uchar_t)offset;
	dqe.s.dq_bufnum = (ushort_t)bufnum;
	dqe.s.dq_length = (ushort_t)length;
	dqe.s.dq_sap = sap;

	*rd->rd_shdwdqw_i = dqe;

	rd->rd_shdwdqw_i = (rd->rd_shdwdqw_i == rd->rd_shdwdqw_l) ?
	    rd->rd_shdwdqw_f : rd->rd_shdwdqw_i + 1;

	ASSERT(rd->rd_shdwdqw_i != rd->rd_shdwdqw_o);

	D1("wrsmdputdqe: done");
	D2("wrsmdputdqe: end shdwdqw_i 0x%p shdwdqw_o 0x%p shdwdqw_f 0x%p "
	    "shdwdqw_l 0x%p",
	    (void *)rd->rd_shdwdqw_i,
	    (void *)rd->rd_shdwdqw_o,
	    (void *)rd->rd_shdwdqw_f,
	    (void *)rd->rd_shdwdqw_l);

	mutex_exit(&rd->rd_net_lock);
}

/*
 * Flush any queued DQEs from local shadow copy to the remote system.
 */
static void
wrsmdsyncdqe(wrsmd_dest_t *rd)
{
	wrsmd_t *wrsmdp = rd->rd_wrsmdp;
	uint64_t start_offset, end_offset;
	int stat = RSM_SUCCESS;
	int any_transfers = 0;
	int old_error_flag;

	ASSERT(MUTEX_HELD(&rd->rd_net_lock));

	old_error_flag = rd->rd_shdwdqw_errflag;

	D1("wrsmdsyncdqe: rd 0x%p (addr %ld ctlr %d) index %ld to %ld",
	    (void *)rd, rd->rd_rsm_addr,
	    rd->rd_wrsmdp->wrsmd_ctlr_id,
	    ((char *)rd->rd_shdwdqw_o - (char *)rd->rd_shdwdqw_f) /
	    sizeof (*(rd->rd_shdwdqw_o)),
	    ((char *)rd->rd_shdwdqw_i - (char *)rd->rd_shdwdqw_f) /
	    sizeof (*(rd->rd_shdwdqw_i)));

	D2("wrsmdsyncdqe: shdwdqw_i 0x%p shdwdqw_o 0x%p shdwdqw_f 0x%p "
	    "shdwdqw_l 0x%p",
	    (void *)rd->rd_shdwdqw_i,
	    (void *)rd->rd_shdwdqw_o,
	    (void *)rd->rd_shdwdqw_f,
	    (void *)rd->rd_shdwdqw_l);

	/* If nothing's queued, nothing to do */

	if (rd->rd_shdwdqw_i == rd->rd_shdwdqw_o) {
		D1("wrsmdsyncdqe: no work, done");
		return;
	}

	/* If network down, nothing to do either */

	if (rd->rd_stopq) {
		D1("wrsmdsyncdqe: stopq on, done");
		return;
	}

	/*
	 * Send each element in the queue separately.  Since each
	 * element is WRSMD_CACHELINE_SIZE, then we know that
	 * each PUT is atomic, and we won't corrupt the remote
	 * side's free queue if we get a transient error and retry.
	 *
	 * (see explination in wrsmdsyncfqe() )
	 *
	 * This is needed on the DQ as well as the FQ because even though
	 * DQ sends an interrupt when it's complete, there is a small window
	 * of opportunity if the local side adds more DQ's with the same
	 * sequence number while the remote side is still consuming them.
	 *
	 */
	while (rd->rd_shdwdqw_o != rd->rd_shdwdqw_i) {

		/* Set the sequence number for this DQE */
		rd->rd_shdwdqw_o->s.dq_seqnum =
			rd->rd_dqw_seq & WRSMD_DQE_SEQ_MASK;

		/*
		 * Set the offset to transfer one dqe at a time.
		 *
		 * NOTE: We already know we are aligned because
		 * we allocated the remote buffer on a WRSMD_CACHELINE_SIZE'd
		 * boundary, and each dqe is WRSMD_CACHELINE_SIZE long.
		 */
		start_offset = (char *)rd->rd_shdwdqw_o -
		    (char *)rd->rd_shdwdqw_f;
		end_offset = start_offset + sizeof (wrsmd_dqe_t);

		/* Push FQE to remote side */
		stat = RSM_PUT(wrsmdp->wrsmd_ctlr, rd->rd_rxferhand,
		    rd->rd_dqw_f_off + start_offset,
		    (char *)rd->rd_shdwdqw_o, end_offset - start_offset);

		if (stat == RSM_SUCCESS) {
			/* Write was sucessful */

			any_transfers++;

			if (rd->rd_shdwdqw_o == rd->rd_shdwdqw_l) {
				/*
				 * Wrap, and update sequence number if
				 * this the is the last dqe
				 */
				rd->rd_shdwdqw_o = rd->rd_shdwdqw_f;

				rd->rd_dqw_seq++;
				if (rd->rd_dqw_seq == 0)
					rd->rd_dqw_seq++;

			} else {
				rd->rd_shdwdqw_o ++;
			}

			rd->rd_shdwdqw_errflag = 0;

		} else {

			wrsmdp->wrsmd_errs++;
			D0("wrsmdsyncdqe: RSM_PUT failed error %d", stat);

			if (stat == RSMERR_CONN_ABORTED) {
				/* permanent connection loss */
				wrsmd_lostconn(rd);
			} else {
				/*
				 * Schedule an event to retry.  Can't do a
				 * timeout here because it would require
				 * calling RSM_PUT from a callback.
				 */

				wrsmd_add_event(wrsmdp, WRSMD_EVT_SYNC,
								(void *)rd);

				rd->rd_shdwdqw_errflag = 1;
			}

			if (!any_transfers)
				return;
		}

	}

	/* If error flag was previously set, retry the interrupt */
	if (any_transfers || old_error_flag) {
		wrsmd_msg_t msg;
		msg.p.m.syncdqe.rcv_segid = rd->rd_rxfersegid;
		stat = wrsmdsendmsg(rd, WRSMD_MSG_SYNC_DQE, &msg);
		if (stat != RSM_SUCCESS) {	/* Failure */
			/* send failed */
			wrsmdp->wrsmd_errs++;

			if (stat == RSMERR_CONN_ABORTED) {
				/* permanent connection loss */
				wrsmd_lostconn(rd);
			} else {
				/*
				 * Schedule an event to retry.  Can't do a
				 * timeout here because it would require
				 * calling RSM_PUT from a callback.
				 */

				wrsmd_add_event(wrsmdp, WRSMD_EVT_SYNC,
								(void *)rd);

				rd->rd_shdwdqw_errflag = 1;
			}

		} else {
			wrsmdp->wrsmd_syncdqes++;
		}
	}
	D1("wrsmdsyncdqe: done");
	D2("wrsmdsyncdqe: shdwdqw_i 0x%p shdwdqw_o 0x%p shdwdqw_f 0x%p "
	    "shdwdqw_l 0x%p",
	    (void *)rd->rd_shdwdqw_i,
	    (void *)rd->rd_shdwdqw_o,
	    (void *)rd->rd_shdwdqw_f,
	    (void *)rd->rd_shdwdqw_l);
}

/*
 * Determine whether there are any available FQEs.  If so, return 1; if none
 * are available, return 0.
 */
static int
wrsmdavailfqe(
	wrsmd_dest_t *rd)	/* Destination pointer */
{
	wrsmd_fqe_t fqe;

	mutex_enter(&rd->rd_net_lock);

	D1("wrsmdavailfqe: rd 0x%p", (void *)rd);

	if (rd->rd_cached_fqr_cnt) {
		D1("wrsmdavailfqe: (cached) returning 1");

		mutex_exit(&rd->rd_net_lock);
		return (1);
	}

	fqe = *rd->rd_fqr_n;

	if (fqe.s.fq_seqnum == (rd->rd_fqr_seq & WRSMD_FQE_SEQ_MASK)) {
		D1("wrsmdavailfqe: returning 1");

		mutex_exit(&rd->rd_net_lock);
		return (1);
	} else {
		D1("wrsmdavailfqe: seq %d, expecting %d, returning 0",
		    fqe.s.fq_seqnum, rd->rd_fqr_seq & WRSMD_FQE_SEQ_MASK);

		mutex_exit(&rd->rd_net_lock);
		return (0);
	}
}

/*
 * Attempt to retrieve the next available FQE from the queue.  If successful,
 * return 1; if none are available, return 0.
 */
static int
wrsmdgetfqe(
	wrsmd_dest_t *rd,	/* Destination pointer */
	int *bufnum)	/* Set to number of free buffer, if we got one */
{
	wrsmd_fqe_t fqe;

	mutex_enter(&rd->rd_net_lock);

	D1("wrsmdgetfqe: rd 0x%p (addr %ld ctlr %d) index %ld", (void *)rd,
	    rd->rd_rsm_addr, rd->rd_wrsmdp->wrsmd_ctlr_id,
	    ((char *)rd->rd_fqr_n - (char *)rd->rd_fqr_f) / sizeof (fqe));

	/* If we have FQE's cached, return one of those */

	if (rd->rd_cached_fqr_cnt) {
		*bufnum = rd->rd_cached_fqr[--rd->rd_cached_fqr_cnt];
		D1("wrsmdgetfqe: (cached) returning 1, *bufnum %d",
		    *bufnum);

		mutex_exit(&rd->rd_net_lock);
		return (1);
	}

	D2("wrsmdgetfqe: start fqr_n 0x%p (index %ld) fqr_f 0x%p fqr_l 0x%p "
	    "fqr_seq %d",
	    (void *)rd->rd_fqr_n,
	    ((char *)rd->rd_fqr_n - (char *)rd->rd_fqr_f) / sizeof (fqe),
	    (void *)rd->rd_fqr_f, (void *)rd->rd_fqr_l,
	    rd->rd_fqr_seq & WRSMD_FQE_SEQ_MASK);

	/* Get next FQE */

	fqe = *rd->rd_fqr_n;

	/* Is it valid? */

	if (fqe.s.fq_seqnum == (rd->rd_fqr_seq & WRSMD_FQE_SEQ_MASK)) {
		/* Yup, return number */

		*bufnum = fqe.s.fq_bufnum;

		/* Bump pointer, wrap if needed */

		if (rd->rd_fqr_n == rd->rd_fqr_l) {
			rd->rd_fqr_n = rd->rd_fqr_f;
			rd->rd_fqr_seq++;
			if (rd->rd_fqr_seq == 0)
				rd->rd_fqr_seq++;
		} else
			rd->rd_fqr_n++;

		/* Exercise some paranoia */

		if (*bufnum >= rd->rd_numrbuf) {
			D1("wrsmdgetfqe: bogus buffer %d in FQE "
			    "at 0x%lx (max %d)", *bufnum,
			    (uintptr_t)rd->rd_fqr_n, rd->rd_numrbuf);
			cmn_err(CE_NOTE,
			    "wrsmdgetfqe: bogus buffer %d in FQE "
			    "at 0x%lx (max %d)", *bufnum,
			    (uintptr_t)rd->rd_fqr_n, rd->rd_numrbuf);
			mutex_exit(&rd->rd_net_lock);
			return (0);
		}

		D1("wrsmdgetfqe: returning 1, *bufnum %d", *bufnum);
		D2("wrsmdgetfqe: end fqr_n 0x%p fqr_f 0x%p fqr_l 0x%p "
		    "fqr_seq %d", (void *)rd->rd_fqr_n, (void *)rd->rd_fqr_f,
		    (void *)rd->rd_fqr_l, rd->rd_fqr_seq & WRSMD_FQE_SEQ_MASK);

		mutex_exit(&rd->rd_net_lock);
		return (1);
	} else {
		D1("wrsmdgetfqe: seq %d, expecting %d, returning 0",
		    fqe.s.fq_seqnum, rd->rd_fqr_seq & WRSMD_FQE_SEQ_MASK);
		D2("wrsmdgetfqe: end fqr_n 0x%p fqr_f 0x%p fqr_l 0x%p "
		    "fqr_seq %d", (void *)rd->rd_fqr_n, (void *)rd->rd_fqr_f,
		    (void *)rd->rd_fqr_l, rd->rd_fqr_seq);


		mutex_exit(&rd->rd_net_lock);
		return (0);
	}
}

/*
 * Unget an FQE, making it available to be gotten again.  Unlike the C
 * ungetc, there is guaranteed to be enough buffering to unget all of the
 * FQE's that the remote system can have available.  (We do this if we
 * get an FQE and then later find that we can't transmit the packet we wanted
 * to use it for; for example, if we can't get DMA resources.)
 */
static void
wrsmdungetfqe(
	wrsmd_dest_t *rd,	/* Destination pointer */
	int bufnum)	/* Number of buffer we want to save for later */
{
	mutex_enter(&rd->rd_net_lock);

	D1("wrsmdungetfqe: rd 0x%p, bufnum %d", (void *)rd, bufnum);

	rd->rd_cached_fqr[rd->rd_cached_fqr_cnt++] = (ushort_t)bufnum;

	D1("wrsmdungetfqe: done");

	mutex_exit(&rd->rd_net_lock);
}

/*
 * Attempt to retrieve the next available DQE from the queue.  If successful,
 * return 1; if none are available, return 0.
 */
static int
wrsmdgetdqe(
	wrsmd_dest_t *rd,	/* Destination pointer */
	int *bufnum,	/* Buffer number, set if we find a DQE */
	int *offset,	/* Packet offset, set if we find a DQE */
	int *length,	/* Packet length, set if we find a DQE */
	ushort_t *sap)	/* Packet SAP, set if we find a DQE */
{
	wrsmd_dqe_t dqe;


	mutex_enter(&rd->rd_net_lock);

	D1("wrsmdgetdqe: rd 0x%p (addr %ld ctlr %d) index %ld", (void *)rd,
	    rd->rd_rsm_addr, rd->rd_wrsmdp->wrsmd_ctlr_id,
	    ((char *)rd->rd_dqr_n - (char *)rd->rd_dqr_f) / sizeof (dqe));
	D2("wrsmdgetdqe: dqr_n 0x%p (index %ld) dqr_f 0x%p dqr_l 0x%p seq %d",
	    (void *)rd->rd_dqr_n,
	    ((char *)rd->rd_dqr_n - (char *)rd->rd_dqr_f) / sizeof (dqe),
	    (void *)rd->rd_dqr_f, (void *)rd->rd_dqr_l,
	    rd->rd_dqr_seq & WRSMD_DQE_SEQ_MASK);


	/* Get next DQE */

	dqe = *rd->rd_dqr_n;

	/* Is it valid? */

	if (dqe.s.dq_seqnum == (rd->rd_dqr_seq & WRSMD_DQE_SEQ_MASK)) {
		*bufnum = dqe.s.dq_bufnum;
		*offset = dqe.s.dq_offset;
		*length = dqe.s.dq_length;
		*sap = dqe.s.dq_sap;

		/* Exercise some paranoia */

		if (*bufnum >= rd->rd_numlbufs) {
			D1("wrsmdgetdqe: bogus buffer %d "
			    "in DQE at 0x%p (max %d)", *bufnum,
			    (void *) &dqe, rd->rd_numlbufs);
			cmn_err(CE_NOTE, "wrsmdgetdqe: bogus buffer %d "
			    "in DQE at 0x%p (max %d)", *bufnum,
			    (void *) &dqe, rd->rd_numlbufs);
			mutex_exit(&rd->rd_net_lock);
			return (0);
		}

		if (*offset > WRSMD_CACHELINE_OFFSET) {
			D1("wrsmdgetdqe: bogus offset %d "
			    "in DQE at 0x%lx (max %d)", *offset,
			    (uintptr_t)&dqe, WRSMD_CACHELINE_OFFSET);
			cmn_err(CE_NOTE, "wrsmdgetdqe: bogus offset %d "
			    "in DQE at 0x%lx (max %d)", *offset,
			    (uintptr_t)&dqe, WRSMD_CACHELINE_OFFSET);
			mutex_exit(&rd->rd_net_lock);
			return (0);
		}

		if (*offset + *length >= rd->rd_lbuflen) {
			D1("wrsmdgetdqe: bogus "
			    "offset+length %d+%d in DQE at 0x%lx (max %d)",
			    *offset, *length, (uintptr_t)&dqe,
			    rd->rd_lbuflen);
			cmn_err(CE_NOTE, "wrsmdgetdqe: bogus "
			    "offset+length %d+%d in DQE at 0x%lx (max %d)",
			    *offset, *length, (uintptr_t)&dqe,
			    rd->rd_lbuflen);
			mutex_exit(&rd->rd_net_lock);
			return (0);
		}

		if (rd->rd_dqr_n == rd->rd_dqr_l) {
			rd->rd_dqr_n = rd->rd_dqr_f;
			rd->rd_dqr_seq++;
			if (rd->rd_dqr_seq == 0)
				rd->rd_dqr_seq++;
		} else
			rd->rd_dqr_n++;

		D1("wrsmdgetdqe: returning 1, *bufnum %d, *offset %d, "
		    "*length %d, *sap 0x%x", *bufnum, *offset, *length, *sap);

		mutex_exit(&rd->rd_net_lock);
		return (1);
	} else {
		D1("wrsmdgetdqe: seq %d, expecting %d, returning 0",
		    dqe.s.dq_seqnum, rd->rd_dqr_seq & WRSMD_DQE_SEQ_MASK);

		mutex_exit(&rd->rd_net_lock);
		return (0);
	}
}

/*
 * We've tried to get an FQE and failed.  Set this destination up to retry
 * on a timeout.  Destination's state must be INPROGRESS.
 */
static void
wrsmdsetupfqewait(
	wrsmd_t *wrsmdp,	/* WRSMD device (RSM controller) pointer */
	wrsmd_dest_t *rd)	/* Destination pointer */
{
	wrsmdsetstate(rd, WRSMD_STATE_W_FQE);

	/* Do exponential backoff */

	if (rd->rd_tmo_int <= 0) {
		rd->rd_tmo_int =
		    wrsmdp->wrsmd_param.wrsmd_nobuf_init_tmo;
		rd->rd_tmo_tot = 0;
	} else {
		rd->rd_tmo_tot += rd->rd_tmo_int;
		rd->rd_tmo_int *= 2;
	}

	/* If we've waited too long, dump queue and drop connection */

	if (rd->rd_tmo_tot >= wrsmdp->wrsmd_param.wrsmd_nobuf_drop_tmo) {
		wrsmddumpqueue(wrsmdp, rd);

		wrsmdp->wrsmd_collisions++;

		wrsmd_lostconn(rd);

		/*
		 * If lostconn() couldn't go to S_DELETE directly,
		 * then this movestate call will get it noticed.
		 */
		(void) wrsmdmovestate(rd, WRSMD_STATE_W_FQE,
		    WRSMD_STATE_S_DELETE);

		return;
	}

	/* Clip timeout to maximum */

	if (rd->rd_tmo_int > wrsmdp->wrsmd_param.wrsmd_nobuf_max_tmo)
		rd->rd_tmo_int = wrsmdp->wrsmd_param.wrsmd_nobuf_max_tmo;

	/*
	 * Only schedule a timeout if there isn't one already.
	 * We hold rd_xmit_lock, so if the timeout has fired,
	 * it's blocked on the lock.
	 */
	if (rd->rd_fqe_tmo_id == 0)
		rd->rd_fqe_tmo_id = timeout(wrsmdfqetmo,
					    (caddr_t)rd, rd->rd_tmo_int);

	wrsmdp->wrsmd_collisions++;
}

/*
 * ****************************************************************
 *                                                               *
 * E N D       FREE/DELIVERY QUEUE MANAGEMENT                    *
 *                                                               *
 * ****************************************************************
 */



/*
 * ****************************************************************
 *                                                               *
 * B E G I N   COMMUNICATION                                     *
 *                                                               *
 * ****************************************************************
 */

/*
 * Attempt to send one or more packets, currently queued on a destination
 * structure, to their actual destination.  Destination's state must be
 * INPROGRESS.
 *
 * This function gets called holding rd_xmit_lock.
 * This code assumes implicit barriers for puts and gets.
 */
static void
wrsmdxfer(
	wrsmd_t *wrsmdp,	/* WRSMD device (RSM controller) pointer */
	wrsmd_dest_t *rd)	/* Destination pointer */
{
	int bufnum;
	int write_err;
	mblk_t *mp;
	uint_t pktlen;
	uint_t start_offset, end_offset;
	int pkts_queued = 0;

	D1("wrsmdxfer: rd 0x%p (addr %ld ctlr %d)",
	    (void *)rd, rd->rd_rsm_addr, wrsmdp->wrsmd_ctlr_id);
	D5("wrsmdxfer 1: time 0x%llx", gethrtime());
	TNF_PROBE_2(wrsmdxfer_start, "RSMPI", "wrsmdxfer start",
	    tnf_long, wrsmdp, (tnf_long_t)wrsmdp, tnf_long, rd, (tnf_long_t)rd);

	ASSERT(MUTEX_HELD(&rd->rd_xmit_lock));


	do {
		while ((mp = rd->rd_queue_h) != NULL) {
			ushort_t sap;
			uchar_t *srcaddr, *endaddr;
			int retries;
			pktlen = MBLKL(mp);

			/*
			 * Try to get an FQE.  If we can't, and this is the
			 * first packet we've tried to send on this
			 * invocation of wrsmdxfer then set up a timeout to
			 * try again.  If we've successfully prepped some
			 * packets for sending, then go ahead and finish
			 * the job, on the theory that when they're done
			 * there may be more FQEs available.
			 */
			if (wrsmdgetfqe(rd, &bufnum) == 0) {
				if (pkts_queued == 0) {
					wrsmdsetupfqewait(wrsmdp, rd);
					D1("wrsmdxfer: no FQEs, start timeout, "
					    "done");
					TNF_PROBE_1(wrsmdxfer_end, "RSMPI",
					    "wrsmdxfer end; failure noFQEs",
					    tnf_string, failure, "noFQEs");
					return;
				} else
					break;
			}

			/* Take packet off the queue. */

			rd->rd_queue_h = mp->b_next;
			rd->rd_queue_len--;
			sap = (ushort_t)(uintptr_t)mp->b_prev;
			mp->b_next = mp->b_prev = NULL;

			/*
			 * Adjust the start pointer and packet length so
			 * we're copying to and from a 64 byte aligned
			 * address, if it'll fit in the buffer that way.
			 * (Note -- this means we may actually be copying
			 * data that doesn't belong to us!!!)
			 */
			srcaddr = mp->b_rptr;
			start_offset = (uint_t)
			    ((uint64_t)srcaddr & WRSMD_CACHELINE_OFFSET);
			endaddr = srcaddr + pktlen;
			end_offset = (uint_t)
			    (WRSMD_CACHELINE_ROUNDUP(endaddr) -
			    (uint64_t)endaddr);

			if ((pktlen + start_offset + end_offset) >
			    rd->rd_rbuflen) {
				start_offset = 0;
			}
			ASSERT((pktlen + start_offset + end_offset) <=
			    rd->rd_rbuflen);

			D6("wrsmdxfer: srcaddr 0x%p endaddr 0x%p "
			    "start_offset 0x%x end_offset 0x%x pktlen 0x%x",
			    (void *)srcaddr, (void *)endaddr, start_offset,
			    end_offset, pktlen);
			TNF_PROBE_3(wrsmdxfer_XFERstart, "RSMPI",
			    "wrsmdxfer XFERstart",
			    tnf_long, srcaddr, (tnf_long_t)srcaddr,
			    tnf_long, pktlen, pktlen,
			    tnf_long, sap, sap);


			/* Do the packet copy, check for errors. */
			ASSERT(((rd->rd_rbufoff + (bufnum * rd->rd_rbuflen)) &
			    WRSMD_CACHELINE_OFFSET) == 0);

			for (retries = wrsmdp->wrsmd_param.wrsmd_err_retries,
			    write_err = ~RSM_SUCCESS;
			    retries >= 0 && write_err != RSM_SUCCESS;
			    retries--) {
				D6("wrsmdxfer: put 0x%x bytes at "
				    "segoffset 0x%lx from addr 0x%p",
				    pktlen + start_offset + end_offset,
				    rd->rd_rbufoff + (bufnum * rd->rd_rbuflen),
				    (void *)(srcaddr - start_offset));
				write_err = RSM_PUT(wrsmdp->wrsmd_ctlr,
				    rd->rd_rxferhand,
				    rd->rd_rbufoff + (bufnum * rd->rd_rbuflen),
				    srcaddr - start_offset,
				    pktlen + start_offset + end_offset);
				if (write_err != RSM_SUCCESS)
					wrsmdp->wrsmd_errs++;
				if (write_err == RSMERR_CONN_ABORTED)
					break;
			}

			if (write_err != RSM_SUCCESS) {
				wrsmdungetfqe(rd, bufnum);
				freemsg(mp);
				wrsmdp->wrsmd_oerrors++;
				TNF_PROBE_1(wrsmdxfer_XFERend,
				    "RSMPI", "wrsmdxfer XFERend",
				    tnf_string, failure, "XFER failed");
				D1("wrsmdxfer: RSM_PUT failed error %d",
				    write_err);

				if (write_err == RSMERR_CONN_ABORTED) {
					wrsmd_lostconn(rd);
					wrsmdsetstate(rd, WRSMD_STATE_S_DELETE);
					return;
				}
			} else {
				/*
				 * Ditch the spent packet, send a DQE,
				 * adjust stats.
				 */

				freemsg(mp);

				wrsmdputdqe(rd, bufnum, start_offset, pktlen,
				    sap);

				pkts_queued++;

				if (pkts_queued ==
				    wrsmdp->wrsmd_param.wrsmd_train_size) {
					pkts_queued = 0;
					mutex_enter(&rd->rd_net_lock);
					wrsmdsyncdqe(rd);
					mutex_exit(&rd->rd_net_lock);
				}

				wrsmdp->wrsmd_xfer_pkts++;
				wrsmdp->wrsmd_opackets++;
				wrsmdp->wrsmd_out_bytes += pktlen;

				TNF_PROBE_1(wrsmdxfer_XFERend, "RSMPI",
				    "wrsmdxfer XFERend", tnf_string,
				    completed, "");
			}
		}

		/*
		 * We've prepped all the packets we're going to, now finish
		 * up.
		 */
		if (pkts_queued) {
			mutex_enter(&rd->rd_net_lock);
			wrsmdsyncdqe(rd);
			mutex_exit(&rd->rd_net_lock);
		}

		/*
		 * If there are more packets to send, and FQE's have become
		 * available during wrsmdsyncdqe(), try sending them now.
		 */
	} while ((rd->rd_queue_h != NULL) && wrsmdavailfqe(rd));

	if (rd->rd_queue_h != NULL) {
		/*
		 * We weren't able to send all packets.
		 * Schedule a timeout to retry sending them.
		 */
		wrsmdsetupfqewait(wrsmdp, rd);
		D1("wrsmdxfer: no FQEs, start timeout, done");
		TNF_PROBE_1(wrsmdxfer_end, "RSMPI",
		    "wrsmdxfer end; failure noFQEs",
		    tnf_string, failure, "noFQEs");
	} else {
		wrsmdsetstate(rd, WRSMD_STATE_W_READY);
	}

	wrsmdp->wrsmd_xfers++;

	D1("wrsmdxfer: done");
	TNF_PROBE_1(wrsmdxfer_end, "RSMPI", "wrsmdxfer",
	    tnf_string, complete, "");
}


/*
 * Send a message to a remote system.  Returns the sequence number of the
 * message if one was successfully sent, or -1 if the caller needs to retry
 * later.  The special message type WRSMD_REXMIT causes us to retransmit the
 * last message we sent (unsuccessfully or successfully), without
 * incrementing the sequence number.  This cannot be called from an
 * interrupt.
 */
static int
wrsmdsendmsg(wrsmd_dest_t *rd, uint8_t msg_type, wrsmd_msg_t *msg)
{
	rsm_send_t send_obj;
	int status;

	if (msg_type == WRSMD_REXMIT) {
		if (rd->rsm_previous_msg_valid) {
			msg = &rd->rsm_previous_msg;
		} else {
			return (-2);
		}
	} else {
		bcopy(msg, &rd->rsm_previous_msg,
		    sizeof (rd->rsm_previous_msg));
		rd->rsm_previous_msg.p.hdr.reqtype = msg_type;
		/* rd_nseq is a ushort, and will wrap when it gets too big. */
		rd->rsm_previous_msg.p.hdr.seqno = rd->rd_nseq++;
		rd->rsm_previous_msg.p.hdr.wrsmd_version = WRSMD_VERSION;
	}

	/*
	 * Send fails immediately if message can't be queued.
	 * On Wildcat, message is sent as soon as it is queued, so
	 * network failures are reported immediately.
	 */
	send_obj.is_data = &rd->rsm_previous_msg;
	send_obj.is_size = sizeof (wrsmd_msg_t);
	send_obj.is_flags = (RSM_INTR_SEND_QUEUE | RSM_INTR_SEND_POLL);
	send_obj.is_wait = 1;

	status = RSM_SEND(rd->rd_wrsmdp->wrsmd_ctlr, rd->rsm_sendq,
	    &send_obj, NULL);

#ifdef DEBUG
	if (status != RSM_SUCCESS) {
		D1("wrsmdsendmsg RSM_SEND FAILED!! status %d\n", status);
	} else {
		D2("wrsmdsendmsg: succeeded\n");
	}
#endif

	return (status);
}

/*
 * ****************************************************************
 *                                                               *
 * E N D       COMMUNICATION                                     *
 *                                                               *
 * ****************************************************************
 */




/*
 * ****************************************************************
 *                                                               *
 * B E G I N   TIMEOUT-FUNCTIONS                                 *
 *                                                               *
 * ****************************************************************
 */

/*
 * Timeout functions
 */

/*
 * FQE timeout expired.  Try sending any packets that were waiting
 * for Free Queue Entries.
 */
static void
wrsmdfqetmo(void * arg)
{
	wrsmd_dest_t *rd = (wrsmd_dest_t *)arg;

	D1("wrsmdfqetmo: rd 0x%p (addr %ld ctlr %d)", (void *)rd,
	    rd->rd_rsm_addr, rd->rd_wrsmdp->wrsmd_ctlr_id);

	/*
	 * This mutex doesn't really protect a particular data item in this
	 * case, it just keeps the movestate from running while we have the
	 * state messed up in wrsmdmsghdlr_syncdqe().  See that routine for
	 * more explanation.
	 */
	mutex_enter(&rd->rd_xmit_lock);

	(void) wrsmdmovestate(rd, WRSMD_STATE_W_FQE, WRSMD_STATE_S_XFER);

	rd->rd_fqe_tmo_id = 0;

	mutex_exit(&rd->rd_xmit_lock);


	D1("wrsmdfqetmo: done");
}

/*
 * Connect retransmit backoff timer has expired.  Retransmit the connect
 * request.
 */
static void
wrsmdsconntmo(void * arg)
{
	wrsmd_dest_t *rd = (wrsmd_dest_t *)arg;

	D1("wrsmdsconntmo: rd 0x%p (addr %ld ctlr %d)", (void *)rd,
	    rd->rd_rsm_addr, rd->rd_wrsmdp->wrsmd_ctlr_id);

	rd->rd_tmo_id = 0;

	/*
	 * If the timeout was cancelled, the state will have also change
	 * from W_SCONNTMO, and wrsmdmovestate() will have no effect.
	 */
	(void) wrsmdmovestate(rd, WRSMD_STATE_W_SCONNTMO,
	    WRSMD_STATE_S_SCONN);

	D1("wrsmdsconntmo: done");
}


/*
 * Timer to wait for ACCEPT message from remote has expired.
 * This indicates the remote side is not reachable, so tear
 * down the WRSMD device (controller).
 */
static void
wrsmdaccepttmo(void * arg)
{
	wrsmd_dest_t *rd = (wrsmd_dest_t *)arg;

	D1("wrsmdaccepttmo: rd 0x%p (addr %ld ctlr %d)", (void *)rd,
	    rd->rd_rsm_addr, rd->rd_wrsmdp->wrsmd_ctlr_id);

	rd->rd_tmo_id = 0;

	/*
	 * If the timeout was cancelled, the state will have also changed
	 * from W_ACCEPT, and wrsmdmovestate() will have no effect.
	 */
	(void) wrsmdmovestate(rd, WRSMD_STATE_W_ACCEPT,
	    WRSMD_STATE_S_DELETE);

	D1("wrsmdaccepttmo: done");
}



/*
 * Timer to wait for ACK message from remote expired.
 * This indicates the remote side is not reachable, so tear
 * down the WRSMD device (controller).
 */
static void
wrsmdacktmo(void * arg)
{
	wrsmd_dest_t *rd = (wrsmd_dest_t *)arg;

	D1("wrsmdacktmo: rd 0x%p (addr %ld ctlr %d)", (void *)rd,
	    rd->rd_rsm_addr, rd->rd_wrsmdp->wrsmd_ctlr_id);

	rd->rd_tmo_id = 0;

	/*
	 * If the timeout was cancelled, the state will have also changed
	 * from W_ACK, and wrsmdmovestate() will have no effect.
	 */
	(void) wrsmdmovestate(rd, WRSMD_STATE_W_ACK,
	    WRSMD_STATE_S_DELETE);

	D1("wrsmdacktmo: done");
}


/*
 * Timer to teardown the WRSMD device (RSM controller) has expired.
 * Tear down the connection.
 */
static void
wrsmdteardown_tmo(void * arg)
{
	wrsmd_t *wrsmdp = (wrsmd_t *)arg;

	D1("wrsmdteardown_tmo:  wrsmd 0x%p (ctlr %d)", (void *)wrsmdp,
	    wrsmdp->wrsmd_ctlr_id);

	mutex_enter(&wrsmdp->wrsmd_lock);
	if (wrsmdp->wrsmd_teardown_tmo_id != 0) {
		mutex_exit(&wrsmdp->wrsmd_lock);
		if (wrsmduninit(wrsmdp) != 0) {
			/*
			 * If wrsmduninit() does not complete,
			 * reschedule timeout to retry later.
			 */
			mutex_enter(&wrsmdp->wrsmd_lock);
			wrsmdp->wrsmd_teardown_tmo_id =
			    timeout(wrsmdteardown_tmo,
			    (caddr_t)wrsmdp,
			    wrsmdp->wrsmd_param.wrsmd_teardown_tmo);
		} else {
			mutex_enter(&wrsmdp->wrsmd_lock);
			wrsmdp->wrsmd_teardown_tmo_id = 0;
		}
	}
	mutex_exit(&wrsmdp->wrsmd_lock);

	D1("wrsmdteardown_tmo: done");
}


/*
 * ****************************************************************
 *                                                               *
 * E N D       TIMEOUT-FUNCTIONS                                 *
 *                                                               *
 * ****************************************************************
 */

/*
 * ****************************************************************
 *                                                                *
 * B E G I N   EVENT-FUNCTIONS                                    *
 *                                                                *
 * ****************************************************************
 */

/*
 * The wrsmd event thread.  We can't make RSM_ calls that can block
 * from either callbacks (timeouts) or interrupts.  Use this thread
 * (one thread/wrsmd device) to make those calls for us.  Currently
 * handles freedest and sync events
 */
static void
wrsmd_event_thread(void *arg)
{
	wrsmd_t *wrsmdp = (wrsmd_t *)arg;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, &wrsmdp->event_lock,
			callb_generic_cpr, "wrsmd_event_thread");

	/* LINTED: E_CONSTANT_CONDITION */
	while (1) {
		wrsmd_process_event(wrsmdp);

		mutex_enter(&wrsmdp->event_lock);
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(&wrsmdp->event_cv, &wrsmdp->event_lock);
		CALLB_CPR_SAFE_END(&cprinfo, &wrsmdp->event_lock);
		mutex_exit(&wrsmdp->event_lock);

		if (wrsmdp->stop_events) {
			wrsmd_process_event(wrsmdp);

			mutex_enter(&wrsmdp->event_lock);
			cv_broadcast(&wrsmdp->event_thread_exit_cv);

			/*
			 * CALLB_CPR_EXIT() calls mutex_exit() on the
			 * lock passed into CALLB_CPR_INIT() above, therefore
			 * we don't want to call mutex_exit() here. See
			 * common/sys/callb.h and common/sys/cpr.h.
			 */
			CALLB_CPR_EXIT(&cprinfo);

			thread_exit();
			return;
		}
	}
}

/*
 * Helper thread to process events off of the queue.  Handles both sync and
 * freedest events.
 */
static void
wrsmd_process_event(wrsmd_t *wrsmdp)
{
	wrsmd_event_t	*evt;
	wrsmd_dest_t	*rd;

	mutex_enter(&wrsmdp->event_lock);

	while (wrsmdp->events) {
		evt = wrsmdp->events;
		mutex_exit(&wrsmdp->event_lock);

		switch (evt->type) {
			case WRSMD_EVT_SYNC:
				rd = (wrsmd_dest_t *)evt->arg;

				mutex_enter(&rd->rd_net_lock);
				/* Try sync'ing again */
				wrsmdsyncdqe(rd);
				wrsmdsyncfqe(rd);
				mutex_exit(&rd->rd_net_lock);

				break;

			case WRSMD_EVT_SYNC_DQE:
				rd = (wrsmd_dest_t *)evt->arg;
				wrsmdmsghdlr_syncdqe_evt(rd);
				break;

			case WRSMD_EVT_FREEDEST:

				wrsmdfreedestevt(evt->arg);

				break;
			default:
				break;
		}

		mutex_enter(&wrsmdp->event_lock);
		wrsmdp->events = evt->next;
		kmem_free(evt, sizeof (wrsmd_event_t));
	}

	mutex_exit(&wrsmdp->event_lock);
}

/* Allocates and adds an event to the event queue */
static void
wrsmd_add_event(wrsmd_t *wrsmdp, int type, void *arg)
{
	wrsmd_event_t *evt, *newevt;

	mutex_enter(&wrsmdp->event_lock);

	if (wrsmdp->stop_events) {
		mutex_exit(&wrsmdp->event_lock);
		return;
	}

	newevt = kmem_alloc(sizeof (wrsmd_event_t), KM_SLEEP);
	newevt->type = type;
	newevt->arg = arg;
	newevt->next = (wrsmd_event_t *)NULL;

	evt = wrsmdp->events;
	if (evt) {
		while (evt->next)
			evt = evt->next;

		evt->next = newevt;
	} else {
		wrsmdp->events = newevt;
	}

	cv_broadcast(&wrsmdp->event_cv);
	mutex_exit(&wrsmdp->event_lock);
}

/*
 * ****************************************************************
 *                                                                *
 * E N D       EVENT-FUNCTIONS                                    *
 *                                                                *
 * ****************************************************************
 */


#ifdef __lock_lint

void
freemsg(mblk_t *mp)
{
	freeb(mp);
}

void
freeb(mblk_t *bp)
{
	wrsmdbuf_t z;

	wrsmdfreebuf(&z);
}

#endif	/* __lock_lint */
