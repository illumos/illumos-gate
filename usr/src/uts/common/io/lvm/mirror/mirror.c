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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/t_lock.h>
#include <sys/buf.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/kmem.h>
#include <vm/page.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/dklabel.h>
#include <vm/hat.h>
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_mirror.h>
#include <sys/lvm/md_convert.h>
#include <sys/lvm/md_mddb.h>
#include <sys/esunddi.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>
#include <sys/lvm/mdmn_commd.h>
#include <sys/avl.h>

md_ops_t		mirror_md_ops;
#ifndef	lint
md_ops_t		*md_interface_ops = &mirror_md_ops;
#endif

extern mdq_anchor_t	md_done_daemon;
extern mdq_anchor_t	md_mstr_daemon;
extern mdq_anchor_t	md_mirror_daemon;
extern mdq_anchor_t	md_mirror_io_daemon;
extern mdq_anchor_t	md_mirror_rs_daemon;
extern mdq_anchor_t	md_mhs_daemon;

extern unit_t		md_nunits;
extern set_t		md_nsets;
extern md_set_t		md_set[];

extern int		md_status;
extern clock_t		md_hz;

extern md_krwlock_t	md_unit_array_rw;
extern kmutex_t		md_mx;
extern kcondvar_t	md_cv;
extern int		md_mtioctl_cnt;

daemon_request_t	mirror_timeout;
static daemon_request_t	hotspare_request;
static daemon_request_t	mn_hs_request[MD_MAXSETS];	/* Multinode hs req */

int	md_mirror_mcs_buf_off;

/* Flags for mdmn_ksend_message to allow debugging */
int	md_mirror_msg_flags;

#ifdef DEBUG
/* Flag to switch on debug messages */
int	mirror_debug_flag = 0;
#endif

/*
 * Struct used to hold count of DMR reads and the timestamp of last DMR read
 * It is used to verify, using a debugger, that the DMR read ioctl has been
 * executed.
 */
dmr_stats_t	mirror_dmr_stats = {0, 0};

/*
 * Mutex protecting list of non-failfast drivers.
 */
static kmutex_t	non_ff_drv_mutex;
extern char	**non_ff_drivers;

extern major_t	md_major;

/*
 * Write-On-Write memory pool.
 */
static void		copy_write_cont(wowhdr_t *wowhdr);
static kmem_cache_t	*mirror_wowblk_cache = NULL;
static int		md_wowbuf_size = 16384;
static size_t		md_wowblk_size;

/*
 * This is a flag that allows:
 *	- disabling the write-on-write mechanism.
 *	- logging occurrences of write-on-write
 *	- switching wow handling procedure processing
 * Counter for occurences of WOW.
 */
static uint_t	md_mirror_wow_flg = 0;
static int	md_mirror_wow_cnt = 0;

/*
 * Tunable to enable/disable dirty region
 * processing when closing down a mirror.
 */
static int	new_resync = 1;
kmem_cache_t	*mirror_parent_cache = NULL;
kmem_cache_t	*mirror_child_cache = NULL;

extern int	md_ff_disable;		/* disable failfast */

static int	mirror_map_write(mm_unit_t *, md_mcs_t *, md_mps_t *, int);
static void	mirror_read_strategy(buf_t *, int, void *);
static void	mirror_write_strategy(buf_t *, int, void *);
static void	become_owner(daemon_queue_t *);
static int	mirror_done(struct buf *cb);
static int	mirror_done_common(struct buf *cb);
static void	clear_retry_error(struct buf *cb);

/*
 * patchables
 */
int	md_min_rr_size	= 200;	/* 2000 blocks, or 100k */
int	md_def_num_rr	= 1000;	/* Default number of dirty regions */

/*
 * patchable to change delay before rescheduling mirror ownership request.
 * Value is clock ticks, default 0.5 seconds
 */
clock_t	md_mirror_owner_to = 500000;

/*ARGSUSED1*/
static int
mirror_parent_constructor(void *p, void *d1, int d2)
{
	mutex_init(&((md_mps_t *)p)->ps_mx, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

static void
mirror_parent_init(md_mps_t *ps)
{
	bzero(ps, offsetof(md_mps_t, ps_mx));
	bzero(&ps->ps_overlap_node, sizeof (avl_node_t));
}

/*ARGSUSED1*/
static void
mirror_parent_destructor(void *p, void *d)
{
	mutex_destroy(&((md_mps_t *)p)->ps_mx);
}

/*ARGSUSED1*/
static int
mirror_child_constructor(void *p, void *d1, int d2)
{
	bioinit(&((md_mcs_t *)p)->cs_buf);
	return (0);
}

void
mirror_child_init(md_mcs_t *cs)
{
	cs->cs_ps = NULL;
	cs->cs_mdunit = 0;
	md_bioreset(&cs->cs_buf);
}

/*ARGSUSED1*/
static void
mirror_child_destructor(void *p, void *d)
{
	biofini(&((md_mcs_t *)p)->cs_buf);
}

static void
mirror_wowblk_init(wowhdr_t *p)
{
	bzero(p, md_wowblk_size);
}

static void
send_poke_hotspares_msg(daemon_request_t *drq)
{
	int			rval;
	int			nretries = 0;
	md_mn_msg_pokehsp_t	pokehsp;
	md_mn_kresult_t		*kresult;
	set_t			setno = (set_t)drq->dq.qlen;

	pokehsp.pokehsp_setno = setno;

	kresult = kmem_alloc(sizeof (md_mn_kresult_t), KM_SLEEP);

retry_sphmsg:
	rval = mdmn_ksend_message(setno, MD_MN_MSG_POKE_HOTSPARES,
	    MD_MSGF_NO_LOG | MD_MSGF_NO_BCAST, 0, (char *)&pokehsp,
	    sizeof (pokehsp), kresult);

	if (!MDMN_KSEND_MSG_OK(rval, kresult)) {
		mdmn_ksend_show_error(rval, kresult, "POKE_HOTSPARES");
		/* If we're shutting down already, pause things here. */
		if (kresult->kmmr_comm_state == MDMNE_RPC_FAIL) {
			while (!md_mn_is_commd_present()) {
				delay(md_hz);
			}
			/*
			 * commd has become reachable again, so retry once.
			 * If this fails we'll panic as the system is in an
			 * unexpected state.
			 */
			if (nretries++ == 0)
				goto retry_sphmsg;
		}
		cmn_err(CE_PANIC,
		    "ksend_message failure: POKE_HOTSPARES");
	}
	kmem_free(kresult, sizeof (md_mn_kresult_t));

	/* Allow further requests to use this set's queue structure */
	mutex_enter(&drq->dr_mx);
	drq->dr_pending = 0;
	mutex_exit(&drq->dr_mx);
}

/*
 * Send a poke_hotspares message to the master node. To avoid swamping the
 * commd handler with requests we only send a message if there is not one
 * already outstanding. We punt the request to a separate thread context as
 * cannot afford to block waiting on the request to be serviced. This is
 * essential when a reconfig cycle is in progress as any open() of a multinode
 * metadevice may result in a livelock.
 */
static void
send_poke_hotspares(set_t setno)
{
	daemon_request_t	*drq = &mn_hs_request[setno];

	mutex_enter(&drq->dr_mx);
	if (drq->dr_pending == 0) {
		drq->dr_pending = 1;
		drq->dq.qlen = (int)setno;
		daemon_request(&md_mhs_daemon,
		    send_poke_hotspares_msg, (daemon_queue_t *)drq, REQ_OLD);
	}
	mutex_exit(&drq->dr_mx);
}

void
mirror_set_sm_state(
	mm_submirror_t		*sm,
	mm_submirror_ic_t	*smic,
	sm_state_t		newstate,
	int			force)
{
	int			compcnt;
	int			i;
	int			errcnt;
	sm_state_t		origstate;
	md_m_shared_t		*shared;

	if (force) {
		sm->sm_state = newstate;
		uniqtime32(&sm->sm_timestamp);
		return;
	}

	origstate = newstate;

	compcnt = (*(smic->sm_get_component_count))(sm->sm_dev, sm);
	for (i = 0, errcnt = 0; i < compcnt; i++) {
		shared = (md_m_shared_t *)(*(smic->sm_shared_by_indx))
		    (sm->sm_dev, sm, i);
		if (shared->ms_state & (CS_ERRED | CS_LAST_ERRED))
			newstate |= SMS_COMP_ERRED;
		if (shared->ms_state & (CS_RESYNC))
			newstate |= SMS_COMP_RESYNC;
		if (shared->ms_state & CS_ERRED)
			errcnt++;
	}

	if ((newstate & (SMS_COMP_ERRED | SMS_COMP_RESYNC)) != 0)
		newstate &= ~origstate;

	if (errcnt == compcnt)
		newstate |= SMS_ALL_ERRED;
	else
		newstate &= ~SMS_ALL_ERRED;

	sm->sm_state = newstate;
	uniqtime32(&sm->sm_timestamp);
}

static int
mirror_geterror(mm_unit_t *un, int *smi, int *cip, int clr_error,
							int frm_probe)
{
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	md_m_shared_t		*shared;
	int			ci;
	int			i;
	int			compcnt;
	int			open_comp; /* flag for open component */

	for (i = *smi; i < NMIRROR; i++) {
		sm = &un->un_sm[i];
		smic = &un->un_smic[i];

		if (!SMS_IS(sm, SMS_INUSE))
			continue;

		compcnt = (*(smic->sm_get_component_count)) (sm->sm_dev, un);
		for (ci = *cip; ci < compcnt; ci++) {
			shared = (md_m_shared_t *)(*(smic->sm_shared_by_indx))
			    (sm->sm_dev, sm, ci);
			/*
			 * if called from any routine but probe, we check for
			 * MDM_S_ISOPEN flag. Since probe does a pseduo open,
			 * it sets MDM_S_PROBEOPEN flag and we test for this
			 * flag. They are both exclusive tests.
			 */
			open_comp = (frm_probe) ?
			    (shared->ms_flags & MDM_S_PROBEOPEN):
			    (shared->ms_flags & MDM_S_ISOPEN);
			if (((shared->ms_flags & MDM_S_IOERR || !open_comp) &&
			    ((shared->ms_state == CS_OKAY) ||
			    (shared->ms_state == CS_RESYNC))) ||
			    (!open_comp &&
			    (shared->ms_state == CS_LAST_ERRED))) {
				if (clr_error) {
					shared->ms_flags &= ~MDM_S_IOERR;
				}
				*cip = ci;
				*smi = i;
				return (1);
			}

			if (clr_error && (shared->ms_flags & MDM_S_IOERR)) {
				shared->ms_flags &= ~MDM_S_IOERR;
			}
		}

		*cip = 0;
	}
	return (0);
}

/*ARGSUSED*/
static void
mirror_run_queue(void *d)
{
	if (!(md_status & MD_GBL_DAEMONS_LIVE))
		md_daemon(1, &md_done_daemon);
}
/*
 * check_comp_4_hotspares
 *
 * This function attempts to allocate a hotspare for this component if the
 * component is in error. In a MN set, the function can be called in 2 modes.
 * It can be called either when a component error has been detected or when a
 * new hotspare has been allocated. In this case, MD_HOTSPARE_XMIT is set
 * in flags and the request is sent to all nodes.
 * The handler on each of the nodes then calls this function with
 * MD_HOTSPARE_XMIT unset and the hotspare allocation is then performed.
 *
 * For non-MN sets the function simply attempts to allocate a hotspare.
 *
 * On entry, the following locks are held
 *	mirror_md_ops.md_link_rw (if flags has MD_HOTSPARE_LINKHELD set)
 *	md_unit_writerlock
 *
 * Returns	0 if ok
 *		1 if the unit containing the component has been cleared while
 *		  the mdmn_ksend_message() was being executed
 */
extern int
check_comp_4_hotspares(
	mm_unit_t	*un,
	int		smi,
	int		ci,
	uint_t		flags,
	mddb_recid_t	hs_id,	/* Only used by MN disksets */
	IOLOCK		*lockp	/* can be NULL */
)
{
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	md_m_shared_t		*shared;
	mddb_recid_t		recids[6];
	minor_t			mnum;
	intptr_t		(*hs_dev)();
	void			(*hs_done)();
	void			*hs_data;
	md_error_t		mde = mdnullerror;
	set_t			setno;
	md_mn_msg_allochsp_t	allochspmsg;
	md_mn_kresult_t		*kresult;
	mm_unit_t		*new_un;
	int			rval;
	int			nretries = 0;

	mnum = MD_SID(un);
	setno = MD_UN2SET(un);
	sm = &un->un_sm[smi];
	smic = &un->un_smic[smi];
	shared = (md_m_shared_t *)(*(smic->sm_shared_by_indx))
	    (sm->sm_dev, sm, ci);

	if (shared->ms_state != CS_ERRED)
		return (0);

	/* Don't start a new component resync if a resync is already running. */
	if (MD_STATUS(un) & MD_UN_RESYNC_ACTIVE)
		return (0);

	if (MD_MNSET_SETNO(setno) && (flags & MD_HOTSPARE_XMIT)) {
		uint_t		msgflags;
		md_mn_msgtype_t	msgtype;

		/* Send allocate hotspare message to all nodes */

		allochspmsg.msg_allochsp_mnum = un->c.un_self_id;
		allochspmsg.msg_allochsp_sm = smi;
		allochspmsg.msg_allochsp_comp = ci;
		allochspmsg.msg_allochsp_hs_id = shared->ms_hs_id;

		/*
		 * Before calling mdmn_ksend_message(), release locks
		 * Can never be in the context of an ioctl.
		 */
		md_unit_writerexit(MDI_UNIT(mnum));
		if (flags & MD_HOTSPARE_LINKHELD)
			rw_exit(&mirror_md_ops.md_link_rw.lock);
#ifdef DEBUG
		if (mirror_debug_flag)
			printf("send alloc hotspare, flags="
			    "0x%x %x, %x, %x, %x\n", flags,
			    allochspmsg.msg_allochsp_mnum,
			    allochspmsg.msg_allochsp_sm,
			    allochspmsg.msg_allochsp_comp,
			    allochspmsg.msg_allochsp_hs_id);
#endif
		if (flags & MD_HOTSPARE_WMUPDATE) {
			msgtype  = MD_MN_MSG_ALLOCATE_HOTSPARE2;
			/*
			 * When coming from an update of watermarks, there
			 * must already be a message logged that triggered
			 * this action. So, no need to log this message, too.
			 */
			msgflags = MD_MSGF_NO_LOG;
		} else {
			msgtype  = MD_MN_MSG_ALLOCATE_HOTSPARE;
			msgflags = MD_MSGF_DEFAULT_FLAGS;
		}

		kresult = kmem_alloc(sizeof (md_mn_kresult_t), KM_SLEEP);

cc4hs_msg:
		rval = mdmn_ksend_message(setno, msgtype, msgflags, 0,
		    (char *)&allochspmsg, sizeof (allochspmsg),
		    kresult);

		if (!MDMN_KSEND_MSG_OK(rval, kresult)) {
#ifdef DEBUG
			if (mirror_debug_flag)
				mdmn_ksend_show_error(rval, kresult,
				    "ALLOCATE HOTSPARE");
#endif
			/*
			 * If message is sent ok but exitval indicates an error
			 * it must be because the mirror has been cleared. In
			 * this case re-obtain lock and return an error
			 */
			if ((rval == 0) && (kresult->kmmr_exitval != 0)) {
				if (flags & MD_HOTSPARE_LINKHELD) {
					rw_enter(&mirror_md_ops.md_link_rw.lock,
					    RW_READER);
				}
				kmem_free(kresult, sizeof (md_mn_kresult_t));
				return (1);
			}
			/* If we're shutting down already, pause things here. */
			if (kresult->kmmr_comm_state == MDMNE_RPC_FAIL) {
				while (!md_mn_is_commd_present()) {
					delay(md_hz);
				}
				/*
				 * commd has become reachable again, so retry
				 * once. If this fails we'll panic as the
				 * system is in an unexpected state.
				 */
				if (nretries++ == 0)
					goto cc4hs_msg;
			}
			cmn_err(CE_PANIC,
			    "ksend_message failure: ALLOCATE_HOTSPARE");
		}
		kmem_free(kresult, sizeof (md_mn_kresult_t));

		/*
		 * re-obtain the locks
		 */
		if (flags & MD_HOTSPARE_LINKHELD)
			rw_enter(&mirror_md_ops.md_link_rw.lock, RW_READER);
		new_un = md_unit_writerlock(MDI_UNIT(mnum));

		/*
		 * As we had to release the locks in order to send the
		 * message to all nodes, we need to check to see if the
		 * unit has changed. If it has we release the writerlock
		 * and return fail.
		 */
		if ((new_un != un) || (un->c.un_type != MD_METAMIRROR)) {
			md_unit_writerexit(MDI_UNIT(mnum));
			return (1);
		}
	} else {
		if (MD_MNSET_SETNO(setno)) {
			/*
			 * If 2 or more nodes simultaneously see a
			 * component failure, these nodes will each
			 * send an ALLOCATE_HOTSPARE[2] message.
			 * The first message will allocate the hotspare
			 * and the subsequent messages should do nothing.
			 *
			 * If a slave node doesn't have a hotspare allocated
			 * at the time the message is initiated, then the
			 * passed in hs_id will be 0.  If the node
			 * executing this routine has a component shared
			 * ms_hs_id of non-zero, but the message shows a
			 * hs_id of 0, then just return since a hotspare
			 * has already been allocated for this failing
			 * component.  When the slave node returns from
			 * the ksend_message the hotspare will have
			 * already been allocated.
			 *
			 * If the slave node does send an hs_id of non-zero,
			 * and the slave node's hs_id matches this node's
			 * ms_hs_id, then the hotspare has error'd and
			 * should be replaced.
			 *
			 * If the slave node sends an hs_id of non-zero and
			 * this node has a different shared ms_hs_id, then
			 * just return since this hotspare has already
			 * been hotspared.
			 */
			if (shared->ms_hs_id != 0) {
				if (hs_id == 0) {
#ifdef DEBUG
					if (mirror_debug_flag) {
						printf("check_comp_4_hotspares"
						    "(NOXMIT), short circuit "
						    "hs_id=0x%x, "
						    "ms_hs_id=0x%x\n",
						    hs_id, shared->ms_hs_id);
					}
#endif
					return (0);
				}
				if (hs_id != shared->ms_hs_id) {
#ifdef DEBUG
					if (mirror_debug_flag) {
						printf("check_comp_4_hotspares"
						    "(NOXMIT), short circuit2 "
						    "hs_id=0x%x, "
						    "ms_hs_id=0x%x\n",
						    hs_id, shared->ms_hs_id);
					}
#endif
					return (0);
				}
			}
		}

		sm = &un->un_sm[smi];
		hs_dev = md_get_named_service(sm->sm_dev, 0,
		    "hotspare device", 0);
		if ((*hs_dev)(sm->sm_dev, 0, ci, recids, 6, &hs_done,
		    &hs_data) != 0)
			return (0);

		/*
		 * set_sm_comp_state() commits the modified records.
		 * As we don't transmit the changes, no need to drop the lock.
		 */
		set_sm_comp_state(un, smi, ci, CS_RESYNC, recids,
		    MD_STATE_NO_XMIT, (IOLOCK *)NULL);

		(*hs_done)(sm->sm_dev, hs_data);

		mirror_check_failfast(mnum);

		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_HOTSPARED, SVM_TAG_METADEVICE,
		    setno, MD_SID(un));

		/*
		 * For a multi-node set we need to reset the un_rs_type,
		 * un_rs_resync_done and un_rs_resync_2_do fields as the
		 * hot-spare resync must copy all applicable data.
		 */
		if (MD_MNSET_SETNO(setno)) {
			un->un_rs_type = MD_RS_NONE;
			un->un_rs_resync_done = 0;
			un->un_rs_resync_2_do = 0;
		}

		/*
		 * Must drop writer lock since mirror_resync_unit will
		 * open devices and must be able to grab readerlock.
		 * Don't need to drop IOLOCK since any descendent routines
		 * calling ksend_messages will drop the IOLOCK as needed.
		 *
		 */
		if (lockp) {
			md_ioctl_writerexit(lockp);
		} else {
			md_unit_writerexit(MDI_UNIT(mnum));
		}

		/* start resync */
		(void) mirror_resync_unit(mnum, NULL, &mde, lockp);

		if (lockp) {
			new_un = md_ioctl_writerlock(lockp, MDI_UNIT(mnum));
		} else {
			new_un = md_unit_writerlock(MDI_UNIT(mnum));
		}
	}
	return (0);
}

/*
 * check_unit_4_hotspares
 *
 * For a given mirror, allocate hotspares, if available for any components
 * that are in error
 *
 * Returns	0 if ok
 *		1 if check_comp_4_hotspares returns non-zero. This will only
 *		  happen for a MN unit where the unit has been cleared while
 *		  the allocate hotspare message is sent to all nodes.
 */
static int
check_unit_4_hotspares(mm_unit_t *un, int flags)
{
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	int			ci;
	int			i;
	int			compcnt;

	if (MD_STATUS(un) & MD_UN_RESYNC_ACTIVE)
		return (0);

	for (i = 0; i < NMIRROR; i++) {
		sm = &un->un_sm[i];
		smic = &un->un_smic[i];
		if (!SMS_IS(sm, SMS_INUSE))
			continue;
		compcnt = (*(smic->sm_get_component_count)) (sm->sm_dev, sm);
		for (ci = 0; ci < compcnt; ci++) {
			md_m_shared_t		*shared;

			shared = (md_m_shared_t *)
			    (*(smic->sm_shared_by_indx))(sm->sm_dev, sm, ci);
			/*
			 * Never called from ioctl context, so pass in
			 * (IOLOCK *)NULL.  Pass through flags from calling
			 * routine, also setting XMIT flag.
			 */
			if (check_comp_4_hotspares(un, i, ci,
			    (MD_HOTSPARE_XMIT | flags),
			    shared->ms_hs_id, (IOLOCK *)NULL) != 0)
				return (1);
		}
	}
	return (0);
}

static void
check_4_hotspares(daemon_request_t *drq)
{
	mdi_unit_t	*ui;
	mm_unit_t	*un;
	md_link_t	*next;
	int		x;

	mutex_enter(&drq->dr_mx);	/* clear up front so can poke */
	drq->dr_pending = 0;		/* again in low level routine if */
	mutex_exit(&drq->dr_mx);	/* something found to do	*/

	/*
	 * Used to have a problem here. The disksets weren't marked as being
	 * MNHOLD. This opened a window where we could be searching for
	 * hotspares and have the disk set unloaded (released) from under
	 * us causing a panic in stripe_component_count().
	 * The way to prevent that is to mark the set MNHOLD which prevents
	 * any diskset from being released while we are scanning the mirrors,
	 * submirrors and components.
	 */

	for (x = 0; x < md_nsets; x++)
		md_holdset_enter(x);

	rw_enter(&mirror_md_ops.md_link_rw.lock, RW_READER);
	for (next = mirror_md_ops.md_head; next != NULL; next = next->ln_next) {
		ui = MDI_UNIT(next->ln_id);

		un = (mm_unit_t *)md_unit_readerlock(ui);

		/*
		 * Only check the unit if we are the master for this set
		 * For an MN set, poke_hotspares() is only effective on the
		 * master
		 */
		if (MD_MNSET_SETNO(MD_UN2SET(un)) &&
		    md_set[MD_UN2SET(un)].s_am_i_master == 0) {
			md_unit_readerexit(ui);
			continue;
		}
		if (MD_STATUS(un) & MD_UN_RESYNC_ACTIVE) {
			md_unit_readerexit(ui);
			continue;
		}
		md_unit_readerexit(ui);

		un = (mm_unit_t *)md_unit_writerlock(ui);
		/*
		 * check_unit_4_hotspares will exit 1 if the unit has been
		 * removed during the process of allocating the hotspare.
		 * This can only happen for a MN metadevice. If unit no longer
		 * exists, no need to release writerlock
		 */
		if (check_unit_4_hotspares(un, MD_HOTSPARE_LINKHELD) == 0)
			md_unit_writerexit(ui);
		else {
			/*
			 * If check_unit_4_hotspares failed, queue another
			 * request and break out of this one
			 */
			(void) poke_hotspares();
			break;
		}
	}
	rw_exit(&mirror_md_ops.md_link_rw.lock);

	for (x = 0; x < md_nsets; x++)
		md_holdset_exit(x);
}

/*
 * poke_hotspares
 *
 * If there is not a pending poke_hotspares request pending, queue a requent
 * to call check_4_hotspares(). This will scan all mirrors and attempt to
 * allocate hotspares for all components in error.
 */
int
poke_hotspares()
{
	mutex_enter(&hotspare_request.dr_mx);
	if (hotspare_request.dr_pending == 0) {
		hotspare_request.dr_pending = 1;
		daemon_request(&md_mhs_daemon,
		    check_4_hotspares, (daemon_queue_t *)&hotspare_request,
		    REQ_OLD);
	}
	mutex_exit(&hotspare_request.dr_mx);
	return (0);
}

static void
free_all_ecomps(err_comp_t *ecomp)
{
	err_comp_t	*d;

	while (ecomp != NULL) {
		d = ecomp;
		ecomp = ecomp->ec_next;
		kmem_free(d, sizeof (err_comp_t));
	}
}

/*
 * NAME: mirror_openfail_console_info
 *
 * DESCRIPTION: Prints a informative message to the console when mirror
 *		cannot be opened.
 *
 * PARAMETERS: mm_unit_t	un - pointer to mirror unit structure
 *	       int		smi - submirror index
 *	       int		ci - component index
 */

void
mirror_openfail_console_info(mm_unit_t *un, int smi, int ci)
{
	void (*get_dev)();
	ms_cd_info_t cd;
	md_dev64_t tmpdev;

	tmpdev = un->un_sm[smi].sm_dev;
	get_dev = (void (*)())md_get_named_service(tmpdev, 0, "get device", 0);
	if (get_dev != NULL) {
		(void) (*get_dev)(tmpdev, smi, ci, &cd);
		cmn_err(CE_WARN, "md %s: open error on %s",
		    md_shortname(MD_SID(un)), md_devname(MD_UN2SET(un),
		    cd.cd_dev, NULL, 0));
	} else {
		cmn_err(CE_WARN, "md %s: open error",
		    md_shortname(MD_SID(un)));
	}
}

static int
mirror_close_all_devs(mm_unit_t *un, int md_cflags)
{
	int i;
	md_dev64_t dev;

	for (i = 0; i < NMIRROR; i++) {
		if (!SMS_BY_INDEX_IS(un, i, SMS_INUSE))
			continue;
		dev = un->un_sm[i].sm_dev;
		md_layered_close(dev, md_cflags);
	}
	return (0);
}

/*
 * Keep track of drivers that don't support failfast.  We use this so that
 * we only log one diagnostic message for each of these drivers, no matter
 * how many times we run the mirror_check_failfast function.
 * Return 1 if this is a new driver that does not support failfast,
 * return 0 if we have already seen this non-failfast driver.
 */
static int
new_non_ff_driver(const char *s)
{
	mutex_enter(&non_ff_drv_mutex);
	if (non_ff_drivers == NULL) {
		non_ff_drivers = (char **)kmem_alloc(2 * sizeof (char *),
		    KM_NOSLEEP);
		if (non_ff_drivers == NULL) {
			mutex_exit(&non_ff_drv_mutex);
			return (1);
		}

		non_ff_drivers[0] = (char *)kmem_alloc(strlen(s) + 1,
		    KM_NOSLEEP);
		if (non_ff_drivers[0] == NULL) {
			kmem_free(non_ff_drivers, 2 * sizeof (char *));
			non_ff_drivers = NULL;
			mutex_exit(&non_ff_drv_mutex);
			return (1);
		}

		(void) strcpy(non_ff_drivers[0], s);
		non_ff_drivers[1] = NULL;

	} else {
		int i;
		char **tnames;
		char **tmp;

		for (i = 0; non_ff_drivers[i] != NULL; i++) {
			if (strcmp(s, non_ff_drivers[i]) == 0) {
				mutex_exit(&non_ff_drv_mutex);
				return (0);
			}
		}

		/* allow for new element and null */
		i += 2;
		tnames = (char **)kmem_alloc(i * sizeof (char *), KM_NOSLEEP);
		if (tnames == NULL) {
			mutex_exit(&non_ff_drv_mutex);
			return (1);
		}

		for (i = 0; non_ff_drivers[i] != NULL; i++)
			tnames[i] = non_ff_drivers[i];

		tnames[i] = (char *)kmem_alloc(strlen(s) + 1, KM_NOSLEEP);
		if (tnames[i] == NULL) {
			/* adjust i so that it is the right count to free */
			kmem_free(tnames, (i + 2) * sizeof (char *));
			mutex_exit(&non_ff_drv_mutex);
			return (1);
		}

		(void) strcpy(tnames[i++], s);
		tnames[i] = NULL;

		tmp = non_ff_drivers;
		non_ff_drivers = tnames;
		/* i now represents the count we previously alloced */
		kmem_free(tmp, i * sizeof (char *));
	}
	mutex_exit(&non_ff_drv_mutex);

	return (1);
}

/*
 * Check for the "ddi-failfast-supported" devtree property on each submirror
 * component to indicate if we should do I/O to that submirror with the
 * B_FAILFAST flag set or not.  This check is made at various state transitions
 * in the mirror code (e.g. open, enable, hotspare, etc.).  Sometimes we
 * only need to check one drive (e.g. hotspare) but since the check is
 * fast and infrequent and sometimes needs to be done on all components we
 * just check all components on each call.
 */
void
mirror_check_failfast(minor_t mnum)
{
	int		i;
	mm_unit_t	*un;

	if (md_ff_disable)
		return;

	un = MD_UNIT(mnum);

	for (i = 0; i < NMIRROR; i++) {
		int			ci;
		int			cnt;
		int			ff = 1;
		mm_submirror_t		*sm;
		mm_submirror_ic_t	*smic;
		void			(*get_dev)();

		if (!SMS_BY_INDEX_IS(un, i, SMS_INUSE))
			continue;

		sm = &un->un_sm[i];
		smic = &un->un_smic[i];

		get_dev = (void (*)())md_get_named_service(sm->sm_dev, 0,
		    "get device", 0);

		cnt = (*(smic->sm_get_component_count))(sm->sm_dev, sm);
		for (ci = 0; ci < cnt; ci++) {
			int		found = 0;
			dev_t		ci_dev;
			major_t		major;
			dev_info_t	*devi;
			ms_cd_info_t	cd;

			/*
			 * this already returns the hs
			 * dev if the device is spared
			 */
			(void) (*get_dev)(sm->sm_dev, sm, ci, &cd);

			ci_dev = md_dev64_to_dev(cd.cd_dev);
			major = getmajor(ci_dev);

			if (major == md_major) {
				/*
				 * this component must be a soft
				 * partition; get the real dev
				 */
				minor_t	dev_mnum;
				mdi_unit_t	*ui;
				mp_unit_t	*un;
				set_t	setno;
				side_t	side;
				md_dev64_t	tmpdev;

				ui = MDI_UNIT(getminor(ci_dev));

				/* grab necessary lock */
				un = (mp_unit_t *)md_unit_readerlock(ui);

				dev_mnum = MD_SID(un);
				setno = MD_MIN2SET(dev_mnum);
				side = mddb_getsidenum(setno);

				tmpdev = un->un_dev;

				/* Get dev by device id */
				if (md_devid_found(setno, side,
				    un->un_key) == 1) {
					tmpdev = md_resolve_bydevid(dev_mnum,
					    tmpdev, un->un_key);
				}

				md_unit_readerexit(ui);

				ci_dev = md_dev64_to_dev(tmpdev);
				major = getmajor(ci_dev);
			}

			if (ci_dev != NODEV32 &&
			    (devi = e_ddi_hold_devi_by_dev(ci_dev, 0))
			    != NULL) {
				ddi_prop_op_t	prop_op = PROP_LEN_AND_VAL_BUF;
				int		propvalue = 0;
				int		proplength = sizeof (int);
				int		error;
				struct cb_ops	*cb;

				if ((cb = devopsp[major]->devo_cb_ops) !=
				    NULL) {
					error = (*cb->cb_prop_op)
					    (DDI_DEV_T_ANY, devi, prop_op,
					    DDI_PROP_NOTPROM|DDI_PROP_DONTPASS,
					    "ddi-failfast-supported",
					    (caddr_t)&propvalue, &proplength);

					if (error == DDI_PROP_SUCCESS)
						found = 1;
				}

				if (!found && new_non_ff_driver(
				    ddi_driver_name(devi))) {
					cmn_err(CE_NOTE, "!md: B_FAILFAST I/O"
					    "disabled on %s",
					    ddi_driver_name(devi));
				}

				ddi_release_devi(devi);
			}

			/*
			 * All components must support
			 * failfast in the submirror.
			 */
			if (!found) {
				ff = 0;
				break;
			}
		}

		if (ff) {
			sm->sm_flags |= MD_SM_FAILFAST;
		} else {
			sm->sm_flags &= ~MD_SM_FAILFAST;
		}
	}
}

/*
 * Return true if the submirror is unavailable.
 * If any of the submirror components are opened then the submirror cannot
 * be unavailable (MD_INACCESSIBLE).
 * If any of the components are already in the errored state, then the submirror
 * cannot be unavailable (MD_INACCESSIBLE).
 */
static bool_t
submirror_unavailable(mm_unit_t *un, int smi, int from_probe)
{
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	md_m_shared_t		*shared;
	int			ci;
	int			compcnt;

	sm = &un->un_sm[smi];
	smic = &un->un_smic[smi];

	compcnt = (*(smic->sm_get_component_count)) (sm->sm_dev, un);
	for (ci = 0; ci < compcnt; ci++) {
		shared = (md_m_shared_t *)(*(smic->sm_shared_by_indx))
		    (sm->sm_dev, sm, ci);
		if (from_probe) {
			if (shared->ms_flags & MDM_S_PROBEOPEN)
				return (B_FALSE);
		} else {
			if (shared->ms_flags & MDM_S_ISOPEN)
				return (B_FALSE);
		}
		if (shared->ms_state == CS_ERRED ||
		    shared->ms_state == CS_LAST_ERRED)
			return (B_FALSE);
	}

	return (B_TRUE);
}

static int
mirror_open_all_devs(minor_t mnum, int md_oflags, IOLOCK *lockp)
{
	int		i;
	mm_unit_t	*un;
	mdi_unit_t	*ui;
	int		err;
	int		smi;
	int		ci;
	err_comp_t	*c;
	err_comp_t	*ecomps = NULL;
	int		smmask = 0;
	set_t		setno;
	int		sm_cnt;
	int		sm_unavail_cnt;

	mirror_check_failfast(mnum);

	un = MD_UNIT(mnum);
	ui = MDI_UNIT(mnum);
	setno = MD_UN2SET(un);

	for (i = 0; i < NMIRROR; i++) {
		md_dev64_t tmpdev = un->un_sm[i].sm_dev;

		if (!SMS_BY_INDEX_IS(un, i, SMS_INUSE))
			continue;
		if (md_layered_open(mnum, &tmpdev, md_oflags))
			smmask |= SMI2BIT(i);
		un->un_sm[i].sm_dev = tmpdev;
	}

	/*
	 * If smmask is clear, all submirrors are accessible. Clear the
	 * MD_INACCESSIBLE bit in this case.  This bit is also cleared for the
	 * mirror device.   If smmask is set, we have to determine which of the
	 * submirrors are in error. If no submirror is accessible we mark the
	 * whole mirror as MD_INACCESSIBLE.
	 */
	if (smmask == 0) {
		if (lockp) {
			md_ioctl_readerexit(lockp);
			(void) md_ioctl_writerlock(lockp, ui);
		} else {
			md_unit_readerexit(ui);
			(void) md_unit_writerlock(ui);
		}
		ui->ui_tstate &= ~MD_INACCESSIBLE;
		if (lockp) {
			md_ioctl_writerexit(lockp);
			(void) md_ioctl_readerlock(lockp, ui);
		} else {
			md_unit_writerexit(ui);
			(void) md_unit_readerlock(ui);
		}

		for (i = 0; i < NMIRROR; i++) {
			md_dev64_t	tmpdev;
			mdi_unit_t	*sm_ui;

			if (!SMS_BY_INDEX_IS(un, i, SMS_INUSE))
				continue;

			tmpdev = un->un_sm[i].sm_dev;
			sm_ui = MDI_UNIT(getminor(md_dev64_to_dev(tmpdev)));
			(void) md_unit_writerlock(sm_ui);
			sm_ui->ui_tstate &= ~MD_INACCESSIBLE;
			md_unit_writerexit(sm_ui);
		}

		return (0);
	}

	for (i = 0; i < NMIRROR; i++) {
		md_dev64_t tmpdev;

		if (!(smmask & SMI2BIT(i)))
			continue;

		tmpdev = un->un_sm[i].sm_dev;
		err = md_layered_open(mnum, &tmpdev, MD_OFLG_CONT_ERRS);
		un->un_sm[i].sm_dev = tmpdev;
		ASSERT(err == 0);
	}

	if (lockp) {
		md_ioctl_readerexit(lockp);
		un = (mm_unit_t *)md_ioctl_writerlock(lockp, ui);
	} else {
		md_unit_readerexit(ui);
		un = (mm_unit_t *)md_unit_writerlock(ui);
	}

	/*
	 * We want to make sure the unavailable flag is not masking a real
	 * error on the submirror.
	 * For each submirror,
	 *    if all of the submirror components couldn't be opened and there
	 *    are no errors on the submirror, then set the unavailable flag
	 *    otherwise, clear unavailable.
	 */
	sm_cnt = 0;
	sm_unavail_cnt = 0;
	for (i = 0; i < NMIRROR; i++) {
		md_dev64_t	tmpdev;
		mdi_unit_t	*sm_ui;

		if (!SMS_BY_INDEX_IS(un, i, SMS_INUSE))
			continue;

		sm_cnt++;
		tmpdev = un->un_sm[i].sm_dev;
		sm_ui = MDI_UNIT(getminor(md_dev64_to_dev(tmpdev)));

		(void) md_unit_writerlock(sm_ui);
		if (submirror_unavailable(un, i, 0)) {
			sm_ui->ui_tstate |= MD_INACCESSIBLE;
			sm_unavail_cnt++;
		} else {
			sm_ui->ui_tstate &= ~MD_INACCESSIBLE;
		}
		md_unit_writerexit(sm_ui);
	}

	/*
	 * If all of the submirrors are unavailable, the mirror is also
	 * unavailable.
	 */
	if (sm_cnt == sm_unavail_cnt) {
		ui->ui_tstate |= MD_INACCESSIBLE;
	} else {
		ui->ui_tstate &= ~MD_INACCESSIBLE;
	}

	smi = 0;
	ci = 0;
	while (mirror_geterror(un, &smi, &ci, 1, 0) != 0) {
		if (mirror_other_sources(un, smi, ci, 1) == 1) {

			free_all_ecomps(ecomps);
			(void) mirror_close_all_devs(un, md_oflags);
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_OPEN_FAIL,
			    SVM_TAG_METADEVICE, setno, MD_SID(un));
			mirror_openfail_console_info(un, smi, ci);
			if (lockp) {
				md_ioctl_writerexit(lockp);
				(void) md_ioctl_readerlock(lockp, ui);
			} else {
				md_unit_writerexit(ui);
				(void) md_unit_readerlock(ui);
			}
			return (ENXIO);
		}

		/* track all component states that need changing */
		c = (err_comp_t *)kmem_alloc(sizeof (err_comp_t), KM_SLEEP);
		c->ec_next = ecomps;
		c->ec_smi = smi;
		c->ec_ci = ci;
		ecomps = c;
		ci++;
	}

	/* Make all state changes and commit them */
	for (c = ecomps; c != NULL; c = c->ec_next) {
		/*
		 * If lockp is set, then entering kernel through ioctl.
		 * For a MN set, the only ioctl path is via a commd message
		 * (ALLOCATE_HOTSPARE or *RESYNC* messages) that is already
		 * being sent to each node.
		 * In this case, set NO_XMIT so that set_sm_comp_state
		 * won't attempt to send a message on a message.
		 *
		 * In !MN sets, the xmit flag is ignored, so it doesn't matter
		 * which flag is passed.
		 */
		if (lockp) {
			set_sm_comp_state(un, c->ec_smi, c->ec_ci, CS_ERRED, 0,
			    MD_STATE_NO_XMIT, lockp);
		} else {
			set_sm_comp_state(un, c->ec_smi, c->ec_ci, CS_ERRED, 0,
			    (MD_STATE_XMIT | MD_STATE_OCHELD), lockp);
		}
		/*
		 * For a MN set, the NOTIFY is done when the state change is
		 * processed on each node
		 */
		if (!MD_MNSET_SETNO(setno)) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ERRED,
			    SVM_TAG_METADEVICE, setno, MD_SID(un));
		}
	}

	if (lockp) {
		md_ioctl_writerexit(lockp);
		(void) md_ioctl_readerlock(lockp, ui);
	} else {
		md_unit_writerexit(ui);
		(void) md_unit_readerlock(ui);
	}

	free_all_ecomps(ecomps);

	/* allocate hotspares for all errored components */
	if (MD_MNSET_SETNO(setno)) {
		/*
		 * If we're called from an ioctl (lockp set) then we cannot
		 * directly call send_poke_hotspares as this will block until
		 * the message gets despatched to all nodes. If the cluster is
		 * going through a reconfig cycle then the message will block
		 * until the cycle is complete, and as we originate from a
		 * service call from commd we will livelock.
		 */
		if (lockp == NULL) {
			md_unit_readerexit(ui);
			send_poke_hotspares(setno);
			(void) md_unit_readerlock(ui);
		}
	} else {
		(void) poke_hotspares();
	}
	return (0);
}

void
mirror_overlap_tree_remove(md_mps_t *ps)
{
	mm_unit_t	*un;

	if (panicstr)
		return;

	VERIFY(ps->ps_flags & MD_MPS_ON_OVERLAP);
	un = ps->ps_un;

	mutex_enter(&un->un_overlap_tree_mx);
	avl_remove(&un->un_overlap_root, ps);
	ps->ps_flags &= ~MD_MPS_ON_OVERLAP;
	if (un->un_overlap_tree_flag != 0) {
		un->un_overlap_tree_flag = 0;
		cv_broadcast(&un->un_overlap_tree_cv);
	}
	mutex_exit(&un->un_overlap_tree_mx);
}


/*
 * wait_for_overlaps:
 * -----------------
 * Check that given i/o request does not cause an overlap with already pending
 * i/o. If it does, block until the overlapped i/o completes.
 *
 * The flag argument has MD_OVERLAP_ALLOW_REPEAT set if it is ok for the parent
 * structure to be already in the overlap tree and MD_OVERLAP_NO_REPEAT if
 * it must not already be in the tree.
 */
static void
wait_for_overlaps(md_mps_t *ps, int flags)
{
	mm_unit_t	*un;
	avl_index_t	where;
	md_mps_t	*ps1;

	if (panicstr)
		return;

	un = ps->ps_un;
	mutex_enter(&un->un_overlap_tree_mx);
	if ((flags & MD_OVERLAP_ALLOW_REPEAT) &&
	    (ps->ps_flags & MD_MPS_ON_OVERLAP)) {
		mutex_exit(&un->un_overlap_tree_mx);
		return;
	}

	VERIFY(!(ps->ps_flags & MD_MPS_ON_OVERLAP));

	do {
		ps1 = avl_find(&un->un_overlap_root, ps, &where);
		if (ps1 == NULL) {
			/*
			 * The candidate range does not overlap with any
			 * range in the tree.  Insert it and be done.
			 */
			avl_insert(&un->un_overlap_root, ps, where);
			ps->ps_flags |= MD_MPS_ON_OVERLAP;
		} else {
			/*
			 * The candidate range would overlap.  Set the flag
			 * indicating we need to be woken up, and sleep
			 * until another thread removes a range.  If upon
			 * waking up we find this mps was put on the tree
			 * by another thread, the loop terminates.
			 */
			un->un_overlap_tree_flag = 1;
			cv_wait(&un->un_overlap_tree_cv,
			    &un->un_overlap_tree_mx);
		}
	} while (!(ps->ps_flags & MD_MPS_ON_OVERLAP));
	mutex_exit(&un->un_overlap_tree_mx);
}

/*
 * This function is called from mirror_done to check whether any pages have
 * been modified while a mirrored write was in progress.  Returns 0 if
 * all pages associated with bp are clean, 1 otherwise.
 */
static int
any_pages_dirty(struct buf *bp)
{
	int	rval;

	rval = biomodified(bp);
	if (rval == -1)
		rval = 0;

	return (rval);
}

#define	MAX_EXTRAS 10

void
mirror_commit(
	mm_unit_t	*un,
	int		smmask,
	mddb_recid_t	*extras
)
{
	mm_submirror_t		*sm;
	md_unit_t		*su;
	int			i;

	/* 2=mirror,null id */
	mddb_recid_t		recids[NMIRROR+2+MAX_EXTRAS];

	int			ri = 0;

	if (md_get_setstatus(MD_UN2SET(un)) & MD_SET_STALE)
		return;

	/* Add two, this includes the mirror unit and the null recid */
	if (extras != NULL) {
		int	nrecids = 0;
		while (extras[nrecids] != 0) {
			nrecids++;
		}
		ASSERT(nrecids <= MAX_EXTRAS);
	}

	if (un != NULL)
		recids[ri++] = un->c.un_record_id;
	for (i = 0;  i < NMIRROR; i++) {
		if (!(smmask & SMI2BIT(i)))
			continue;
		sm = &un->un_sm[i];
		if (!SMS_IS(sm, SMS_INUSE))
			continue;
		if (md_getmajor(sm->sm_dev) != md_major)
			continue;
		su =  MD_UNIT(md_getminor(sm->sm_dev));
		recids[ri++] = su->c.un_record_id;
	}

	if (extras != NULL)
		while (*extras != 0) {
			recids[ri++] = *extras;
			extras++;
		}

	if (ri == 0)
		return;
	recids[ri] = 0;

	/*
	 * Ok to hold ioctl lock across record commit to mddb as
	 * long as the record(s) being committed aren't resync records.
	 */
	mddb_commitrecs_wrapper(recids);
}


/*
 * This routine is used to set a bit in the writable_bm bitmap
 * which represents each submirror in a metamirror which
 * is writable. The first writable submirror index is assigned
 * to the sm_index.  The number of writable submirrors are returned in nunits.
 *
 * This routine returns the submirror's unit number.
 */

static void
select_write_units(struct mm_unit *un, md_mps_t *ps)
{

	int		i;
	unsigned	writable_bm = 0;
	unsigned	nunits = 0;

	for (i = 0; i < NMIRROR; i++) {
		if (SUBMIRROR_IS_WRITEABLE(un, i)) {
			/* set bit of all writable units */
			writable_bm |= SMI2BIT(i);
			nunits++;
		}
	}
	ps->ps_writable_sm = writable_bm;
	ps->ps_active_cnt = nunits;
	ps->ps_current_sm = 0;
}

static
unsigned
select_write_after_read_units(struct mm_unit *un, md_mps_t *ps)
{

	int		i;
	unsigned	writable_bm = 0;
	unsigned	nunits = 0;

	for (i = 0; i < NMIRROR; i++) {
		if (SUBMIRROR_IS_WRITEABLE(un, i) &&
		    un->un_sm[i].sm_flags & MD_SM_RESYNC_TARGET) {
			writable_bm |= SMI2BIT(i);
			nunits++;
		}
	}
	if ((writable_bm & ps->ps_allfrom_sm) != 0) {
		writable_bm &= ~ps->ps_allfrom_sm;
		nunits--;
	}
	ps->ps_writable_sm = writable_bm;
	ps->ps_active_cnt = nunits;
	ps->ps_current_sm = 0;
	return (nunits);
}

static md_dev64_t
select_read_unit(
	mm_unit_t	*un,
	diskaddr_t	blkno,
	u_longlong_t	reqcount,
	u_longlong_t	*cando,
	int		must_be_opened,
	md_m_shared_t	**shared,
	md_mcs_t	*cs)
{
	int			i;
	md_m_shared_t		*s;
	uint_t			lasterrcnt = 0;
	md_dev64_t		dev = 0;
	u_longlong_t		cnt;
	u_longlong_t		mincnt;
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	mdi_unit_t		*ui;

	mincnt = reqcount;
	for (i = 0; i < NMIRROR; i++) {
		if (!SUBMIRROR_IS_READABLE(un, i))
			continue;
		sm = &un->un_sm[i];
		smic = &un->un_smic[i];
		cnt = reqcount;

		/*
		 * If the current submirror is marked as inaccessible, do not
		 * try to access it.
		 */
		ui = MDI_UNIT(getminor(expldev(sm->sm_dev)));
		(void) md_unit_readerlock(ui);
		if (ui->ui_tstate & MD_INACCESSIBLE) {
			md_unit_readerexit(ui);
			continue;
		}
		md_unit_readerexit(ui);

		s = (md_m_shared_t *)(*(smic->sm_shared_by_blk))
		    (sm->sm_dev, sm, blkno, &cnt);

		if (must_be_opened && !(s->ms_flags & MDM_S_ISOPEN))
			continue;
		if (s->ms_state == CS_OKAY) {
			*cando = cnt;
			if (shared != NULL)
				*shared = s;

			if (un->un_sm[i].sm_flags & MD_SM_FAILFAST &&
			    cs != NULL) {
				cs->cs_buf.b_flags |= B_FAILFAST;
			}

			return (un->un_sm[i].sm_dev);
		}
		if (s->ms_state != CS_LAST_ERRED)
			continue;

		/* don't use B_FAILFAST since we're Last Erred */

		if (mincnt > cnt)
			mincnt = cnt;
		if (s->ms_lasterrcnt > lasterrcnt) {
			lasterrcnt = s->ms_lasterrcnt;
			if (shared != NULL)
				*shared = s;
			dev = un->un_sm[i].sm_dev;
		}
	}
	*cando = mincnt;
	return (dev);
}

/*
 * Given a 32-bit bitmap, this routine will return the bit number
 * of the nth bit set.	The nth bit set is passed via the index integer.
 *
 * This routine is used to run through the writable submirror bitmap
 * and starting all of the writes.  See the value returned is the
 * index to appropriate submirror structure, in the md_sm
 * array for metamirrors.
 */
static int
md_find_nth_unit(uint_t mask, int index)
{
	int	bit, nfound;

	for (bit = -1, nfound = -1; nfound != index; bit++) {
		ASSERT(mask != 0);
		nfound += (mask & 1);
		mask >>= 1;
	}
	return (bit);
}

static int
fast_select_read_unit(md_mps_t *ps, md_mcs_t *cs)
{
	mm_unit_t	*un;
	buf_t		*bp;
	int		i;
	unsigned	nunits = 0;
	int		iunit;
	uint_t		running_bm = 0;
	uint_t		sm_index;

	bp = &cs->cs_buf;
	un = ps->ps_un;

	for (i = 0; i < NMIRROR; i++) {
		if (!SMS_BY_INDEX_IS(un, i, SMS_RUNNING))
			continue;
		running_bm |= SMI2BIT(i);
		nunits++;
	}
	if (nunits == 0)
		return (1);

	/*
	 * For directed mirror read (DMR) we only use the specified side and
	 * do not compute the source of the read.
	 * If we're running with MD_MPS_DIRTY_RD set we always return the
	 * first mirror side (this prevents unnecessary ownership switching).
	 * Otherwise we return the submirror according to the mirror read option
	 */
	if (ps->ps_flags & MD_MPS_DMR) {
		sm_index = un->un_dmr_last_read;
	} else if (ps->ps_flags & MD_MPS_DIRTY_RD) {
		sm_index = md_find_nth_unit(running_bm, 0);
	} else {
		/* Normal (non-DMR) operation */
		switch (un->un_read_option) {
		case RD_GEOMETRY:
			iunit = (int)(bp->b_lblkno /
			    howmany(un->c.un_total_blocks, nunits));
			sm_index = md_find_nth_unit(running_bm, iunit);
			break;
		case RD_FIRST:
			sm_index = md_find_nth_unit(running_bm, 0);
			break;
		case RD_LOAD_BAL:
			/* this is intentional to fall into the default */
		default:
			un->un_last_read = (un->un_last_read + 1) % nunits;
			sm_index = md_find_nth_unit(running_bm,
			    un->un_last_read);
			break;
		}
	}
	bp->b_edev = md_dev64_to_dev(un->un_sm[sm_index].sm_dev);
	ps->ps_allfrom_sm = SMI2BIT(sm_index);

	if (un->un_sm[sm_index].sm_flags & MD_SM_FAILFAST) {
		bp->b_flags |= B_FAILFAST;
	}

	return (0);
}

static
int
mirror_are_submirrors_available(mm_unit_t *un)
{
	int i;
	for (i = 0; i < NMIRROR; i++) {
		md_dev64_t tmpdev = un->un_sm[i].sm_dev;

		if ((!SMS_BY_INDEX_IS(un, i, SMS_INUSE)) ||
		    md_getmajor(tmpdev) != md_major)
			continue;

		if ((MD_MIN2SET(md_getminor(tmpdev)) >= md_nsets) ||
		    (MD_MIN2UNIT(md_getminor(tmpdev)) >= md_nunits))
			return (0);

		if (MDI_UNIT(md_getminor(tmpdev)) == NULL)
			return (0);
	}
	return (1);
}

void
build_submirror(mm_unit_t *un, int i, int snarfing)
{
	struct mm_submirror	*sm;
	struct mm_submirror_ic	*smic;
	md_unit_t		*su;
	set_t			setno;

	sm = &un->un_sm[i];
	smic = &un->un_smic[i];

	sm->sm_flags = 0; /* sometime we may need to do more here */

	setno = MD_UN2SET(un);

	if (!SMS_IS(sm, SMS_INUSE))
		return;
	if (snarfing) {
		sm->sm_dev = md_getdevnum(setno, mddb_getsidenum(setno),
		    sm->sm_key, MD_NOTRUST_DEVT);
	} else {
		if (md_getmajor(sm->sm_dev) == md_major) {
			su = MD_UNIT(md_getminor(sm->sm_dev));
			un->c.un_flag |= (su->c.un_flag & MD_LABELED);
			/* submirror can no longer be soft partitioned */
			MD_CAPAB(su) &= (~MD_CAN_SP);
		}
	}
	smic->sm_shared_by_blk = md_get_named_service(sm->sm_dev,
	    0, "shared by blk", 0);
	smic->sm_shared_by_indx = md_get_named_service(sm->sm_dev,
	    0, "shared by indx", 0);
	smic->sm_get_component_count = (int (*)())md_get_named_service(
	    sm->sm_dev, 0, "get component count", 0);
	smic->sm_get_bcss = (int (*)())md_get_named_service(sm->sm_dev, 0,
	    "get block count skip size", 0);
	sm->sm_state &= ~SMS_IGNORE;
	if (SMS_IS(sm, SMS_OFFLINE))
		MD_STATUS(un) |= MD_UN_OFFLINE_SM;
	md_set_parent(sm->sm_dev, MD_SID(un));
}

static void
mirror_cleanup(mm_unit_t *un)
{
	mddb_recid_t	recid;
	int		smi;
	sv_dev_t	sv[NMIRROR];
	int		nsv = 0;

	/*
	 * If a MN diskset and this node is not the master, do
	 * not delete any records on snarf of the mirror records.
	 */
	if (MD_MNSET_SETNO(MD_UN2SET(un)) &&
	    md_set[MD_UN2SET(un)].s_am_i_master == 0) {
		return;
	}

	for (smi = 0; smi < NMIRROR; smi++) {
		if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE))
			continue;
		sv[nsv].setno = MD_UN2SET(un);
		sv[nsv++].key = un->un_sm[smi].sm_key;
	}

	recid = un->un_rr_dirty_recid;
	mddb_deleterec_wrapper(un->c.un_record_id);
	if (recid > 0)
		mddb_deleterec_wrapper(recid);

	md_rem_names(sv, nsv);
}

/*
 * Comparison function for the avl tree which tracks
 * outstanding writes on submirrors.
 *
 * Returns:
 *	-1: ps1 < ps2
 *	 0: ps1 and ps2 overlap
 *	 1: ps1 > ps2
 */
static int
mirror_overlap_compare(const void *p1, const void *p2)
{
	const md_mps_t *ps1 = (md_mps_t *)p1;
	const md_mps_t *ps2 = (md_mps_t *)p2;

	if (ps1->ps_firstblk < ps2->ps_firstblk) {
		if (ps1->ps_lastblk >= ps2->ps_firstblk)
			return (0);
		return (-1);
	}

	if (ps1->ps_firstblk > ps2->ps_firstblk) {
		if (ps1->ps_firstblk <= ps2->ps_lastblk)
			return (0);
		return (1);
	}

	return (0);
}

/*
 * Collapse any sparse submirror entries snarfed from the on-disk replica.
 * Only the in-core entries are updated. The replica will be updated on-disk
 * when the in-core replica is committed on shutdown of the SVM subsystem.
 */
static void
collapse_submirrors(mm_unit_t *un)
{
	int			smi, nremovals, smiremove;
	mm_submirror_t		*sm, *new_sm, *old_sm;
	mm_submirror_ic_t	*smic;
	int			nsmidx = un->un_nsm - 1;

rescan:
	nremovals = 0;
	smiremove = -1;

	for (smi = 0; smi <= nsmidx; smi++) {
		sm = &un->un_sm[smi];

		/*
		 * Check to see if this submirror is marked as in-use.
		 * If it isn't then it is a potential sparse entry and
		 * may need to be cleared from the configuration.
		 * The records should _already_ have been cleared by the
		 * original mirror_detach() code, but we need to shuffle
		 * any NULL entries in un_sm[] to the end of the array.
		 * Any NULL un_smic[] entries need to be reset to the underlying
		 * submirror/slice accessor functions.
		 */
		if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE)) {
			nremovals++;
			smiremove = smi;
			break;
		}
	}

	if (nremovals == 0) {
		/*
		 * Ensure that we have a matching contiguous set of un_smic[]
		 * entries for the corresponding un_sm[] entries
		 */
		for (smi = 0; smi <= nsmidx; smi++) {
			smic = &un->un_smic[smi];
			sm = &un->un_sm[smi];

			smic->sm_shared_by_blk =
			    md_get_named_service(sm->sm_dev, 0,
			    "shared by_blk", 0);
			smic->sm_shared_by_indx =
			    md_get_named_service(sm->sm_dev, 0,
			    "shared by indx", 0);
			smic->sm_get_component_count =
			    (int (*)())md_get_named_service(sm->sm_dev, 0,
			    "get component count", 0);
			smic->sm_get_bcss =
			    (int (*)())md_get_named_service(sm->sm_dev, 0,
			    "get block count skip size", 0);
		}
		return;
	}

	/*
	 * Reshuffle the submirror devices so that we do not have a dead record
	 * in the middle of the array. Once we've done this we need to rescan
	 * the mirror to check for any other holes.
	 */
	for (smi = 0; smi < NMIRROR; smi++) {
		if (smi < smiremove)
			continue;
		if (smi > smiremove) {
			old_sm = &un->un_sm[smi];
			new_sm = &un->un_sm[smi - 1];
			bcopy(old_sm, new_sm, sizeof (mm_submirror_t));
			bzero(old_sm, sizeof (mm_submirror_t));
		}
	}

	/*
	 * Now we need to rescan the array to find the next potential dead
	 * entry.
	 */
	goto rescan;
}

/* Return a -1 if optimized record unavailable and set should be released */
int
mirror_build_incore(mm_unit_t *un, int snarfing)
{
	int		i;

	if (MD_STATUS(un) & MD_UN_BEING_RESET) {
		mddb_setrecprivate(un->c.un_record_id, MD_PRV_PENDCLEAN);
		return (1);
	}

	if (mirror_are_submirrors_available(un) == 0)
		return (1);

	if (MD_UNIT(MD_SID(un)) != NULL)
		return (0);

	MD_STATUS(un) = 0;

	/* pre-4.1 didn't define CAN_META_CHILD capability */
	MD_CAPAB(un) = MD_CAN_META_CHILD | MD_CAN_PARENT | MD_CAN_SP;

	un->un_overlap_tree_flag = 0;
	avl_create(&un->un_overlap_root, mirror_overlap_compare,
	    sizeof (md_mps_t), offsetof(md_mps_t, ps_overlap_node));

	/*
	 * We need to collapse any sparse submirror entries into a non-sparse
	 * array. This is to cover the case where we have an old replica image
	 * which has not been updated (i.e. snarfed) since being modified.
	 * The new code expects all submirror access to be sequential (i.e.
	 * both the un_sm[] and un_smic[] entries correspond to non-empty
	 * submirrors.
	 */

	collapse_submirrors(un);

	for (i = 0; i < NMIRROR; i++)
		build_submirror(un, i, snarfing);

	if (unit_setup_resync(un, snarfing) != 0) {
		if (snarfing) {
			mddb_setrecprivate(un->c.un_record_id, MD_PRV_GOTIT);
			/*
			 * If a MN set and set is not stale, then return -1
			 * which will force the caller to unload the set.
			 * The MN diskset nodes will return failure if
			 * unit_setup_resync fails so that nodes won't
			 * get out of sync.
			 *
			 * If set is STALE, the master node can't allocate
			 * a resync record (if needed), but node needs to
			 * join the set so that user can delete broken mddbs.
			 * So, if set is STALE, just continue on.
			 */
			if (MD_MNSET_SETNO(MD_UN2SET(un)) &&
			    !(md_get_setstatus(MD_UN2SET(un)) & MD_SET_STALE)) {
				return (-1);
			}
		} else
			return (1);
	}

	mutex_init(&un->un_overlap_tree_mx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&un->un_overlap_tree_cv, NULL, CV_DEFAULT, NULL);

	un->un_suspend_wr_flag = 0;
	mutex_init(&un->un_suspend_wr_mx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&un->un_suspend_wr_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * Allocate mutexes for mirror-owner and resync-owner changes.
	 * All references to the owner message state field must be guarded
	 * by this mutex.
	 */
	mutex_init(&un->un_owner_mx, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Allocate mutex and condvar for resync thread manipulation. These
	 * will be used by mirror_resync_unit/mirror_ioctl_resync
	 */
	mutex_init(&un->un_rs_thread_mx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&un->un_rs_thread_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * Allocate mutex and condvar for resync progress thread manipulation.
	 * This allows resyncs to be continued across an intervening reboot.
	 */
	mutex_init(&un->un_rs_progress_mx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&un->un_rs_progress_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * Allocate mutex and condvar for Directed Mirror Reads (DMR). This
	 * provides synchronization between a user-ioctl and the resulting
	 * strategy() call that performs the read().
	 */
	mutex_init(&un->un_dmr_mx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&un->un_dmr_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * Allocate rwlocks for un_pernode_dirty_bm accessing.
	 */
	for (i = 0; i < MD_MNMAXSIDES; i++) {
		rw_init(&un->un_pernode_dirty_mx[i], NULL, RW_DEFAULT, NULL);
	}

	/* place various information in the in-core data structures */
	md_nblocks_set(MD_SID(un), un->c.un_total_blocks);
	MD_UNIT(MD_SID(un)) = un;

	return (0);
}


void
reset_mirror(struct mm_unit *un, minor_t mnum, int removing)
{
	mddb_recid_t	recid, vtoc_id;
	size_t		bitcnt;
	size_t		shortcnt;
	int		smi;
	sv_dev_t	sv[NMIRROR];
	int		nsv = 0;
	uint_t		bits = 0;
	minor_t		selfid;
	md_unit_t	*su;
	int		i;

	md_destroy_unit_incore(mnum, &mirror_md_ops);

	shortcnt = un->un_rrd_num * sizeof (short);
	bitcnt = howmany(un->un_rrd_num, NBBY);

	if (un->un_outstanding_writes)
		kmem_free((caddr_t)un->un_outstanding_writes, shortcnt);
	if (un->un_goingclean_bm)
		kmem_free((caddr_t)un->un_goingclean_bm, bitcnt);
	if (un->un_goingdirty_bm)
		kmem_free((caddr_t)un->un_goingdirty_bm, bitcnt);
	if (un->un_resync_bm)
		kmem_free((caddr_t)un->un_resync_bm, bitcnt);
	if (un->un_pernode_dirty_sum)
		kmem_free((caddr_t)un->un_pernode_dirty_sum, un->un_rrd_num);

	/*
	 * Destroy the taskq for deferred processing of DRL clean requests.
	 * This taskq will only be present for Multi Owner mirrors.
	 */
	if (un->un_drl_task != NULL)
		ddi_taskq_destroy(un->un_drl_task);

	md_nblocks_set(mnum, -1ULL);
	MD_UNIT(mnum) = NULL;

	/*
	 * Attempt release of its minor node
	 */
	md_remove_minor_node(mnum);

	if (!removing)
		return;

	for (smi = 0; smi < NMIRROR; smi++) {
		if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE))
			continue;
		/* reallow soft partitioning of submirror and reset parent */
		su = MD_UNIT(md_getminor(un->un_sm[smi].sm_dev));
		MD_CAPAB(su) |= MD_CAN_SP;
		md_reset_parent(un->un_sm[smi].sm_dev);
		reset_comp_states(&un->un_sm[smi], &un->un_smic[smi]);

		sv[nsv].setno = MD_MIN2SET(mnum);
		sv[nsv++].key = un->un_sm[smi].sm_key;
		bits |= SMI2BIT(smi);
	}

	MD_STATUS(un) |= MD_UN_BEING_RESET;
	recid = un->un_rr_dirty_recid;
	vtoc_id = un->c.un_vtoc_id;
	selfid = MD_SID(un);

	mirror_commit(un, bits, 0);

	avl_destroy(&un->un_overlap_root);

	/* Destroy all mutexes and condvars before returning. */
	mutex_destroy(&un->un_suspend_wr_mx);
	cv_destroy(&un->un_suspend_wr_cv);
	mutex_destroy(&un->un_overlap_tree_mx);
	cv_destroy(&un->un_overlap_tree_cv);
	mutex_destroy(&un->un_owner_mx);
	mutex_destroy(&un->un_rs_thread_mx);
	cv_destroy(&un->un_rs_thread_cv);
	mutex_destroy(&un->un_rs_progress_mx);
	cv_destroy(&un->un_rs_progress_cv);
	mutex_destroy(&un->un_dmr_mx);
	cv_destroy(&un->un_dmr_cv);

	for (i = 0; i < MD_MNMAXSIDES; i++) {
		rw_destroy(&un->un_pernode_dirty_mx[i]);
		if (un->un_pernode_dirty_bm[i])
			kmem_free((caddr_t)un->un_pernode_dirty_bm[i], bitcnt);
	}

	/*
	 * Remove self from the namespace
	 */
	if (un->c.un_revision & MD_FN_META_DEV) {
		(void) md_rem_selfname(un->c.un_self_id);
	}

	/* This frees the unit structure. */
	mddb_deleterec_wrapper(un->c.un_record_id);

	if (recid != 0)
		mddb_deleterec_wrapper(recid);

	/* Remove the vtoc, if present */
	if (vtoc_id)
		mddb_deleterec_wrapper(vtoc_id);

	md_rem_names(sv, nsv);

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_DELETE, SVM_TAG_METADEVICE,
	    MD_MIN2SET(selfid), selfid);
}

int
mirror_internal_open(
	minor_t		mnum,
	int		flag,
	int		otyp,
	int		md_oflags,
	IOLOCK		*lockp		/* can be NULL */
)
{
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	int		err = 0;

tryagain:
	/* single thread */
	if (lockp) {
		/*
		 * If ioctl lock is held, use openclose_enter
		 * routine that will set the ioctl flag when
		 * grabbing the readerlock.
		 */
		(void) md_ioctl_openclose_enter(lockp, ui);
	} else {
		(void) md_unit_openclose_enter(ui);
	}

	/*
	 * The mirror_open_all_devs routine may end up sending a STATE_UPDATE
	 * message in a MN diskset and this requires that the openclose
	 * lock is dropped in order to send this message.  So, another
	 * flag (MD_UL_OPENINPROGRESS) is used to keep another thread from
	 * attempting an open while this thread has an open in progress.
	 * Call the *_lh version of the lock exit routines since the ui_mx
	 * mutex must be held from checking for OPENINPROGRESS until
	 * after the cv_wait call.
	 */
	mutex_enter(&ui->ui_mx);
	if (ui->ui_lock & MD_UL_OPENINPROGRESS) {
		if (lockp) {
			(void) md_ioctl_openclose_exit_lh(lockp);
		} else {
			md_unit_openclose_exit_lh(ui);
		}
		cv_wait(&ui->ui_cv, &ui->ui_mx);
		mutex_exit(&ui->ui_mx);
		goto tryagain;
	}

	ui->ui_lock |= MD_UL_OPENINPROGRESS;
	mutex_exit(&ui->ui_mx);

	/* open devices, if necessary */
	if (! md_unit_isopen(ui) || (ui->ui_tstate & MD_INACCESSIBLE)) {
		if ((err = mirror_open_all_devs(mnum, md_oflags, lockp)) != 0)
			goto out;
	}

	/* count open */
	if ((err = md_unit_incopen(mnum, flag, otyp)) != 0)
		goto out;

	/* unlock, return success */
out:
	mutex_enter(&ui->ui_mx);
	ui->ui_lock &= ~MD_UL_OPENINPROGRESS;
	mutex_exit(&ui->ui_mx);

	if (lockp) {
		/*
		 * If ioctl lock is held, use openclose_exit
		 * routine that will clear the lockp reader flag.
		 */
		(void) md_ioctl_openclose_exit(lockp);
	} else {
		md_unit_openclose_exit(ui);
	}
	return (err);
}

int
mirror_internal_close(
	minor_t		mnum,
	int		otyp,
	int		md_cflags,
	IOLOCK		*lockp		/* can be NULL */
)
{
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	mm_unit_t	*un;
	int		err = 0;

	/* single thread */
	if (lockp) {
		/*
		 * If ioctl lock is held, use openclose_enter
		 * routine that will set the ioctl flag when
		 * grabbing the readerlock.
		 */
		un = (mm_unit_t *)md_ioctl_openclose_enter(lockp, ui);
	} else {
		un = (mm_unit_t *)md_unit_openclose_enter(ui);
	}

	/* count closed */
	if ((err = md_unit_decopen(mnum, otyp)) != 0)
		goto out;

	/* close devices, if necessary */
	if (! md_unit_isopen(ui) || (md_cflags & MD_OFLG_PROBEDEV)) {
		/*
		 * Clean up dirty bitmap for this unit. Do this
		 * before closing the underlying devices to avoid
		 * race conditions with reset_mirror() as a
		 * result of a 'metaset -r' command running in
		 * parallel. This might cause deallocation of
		 * dirty region bitmaps; with underlying metadevices
		 * in place this can't happen.
		 * Don't do this if a MN set and ABR not set
		 */
		if (new_resync && !(MD_STATUS(un) & MD_UN_KEEP_DIRTY)) {
			if (!MD_MNSET_SETNO(MD_UN2SET(un)) ||
			    !(ui->ui_tstate & MD_ABR_CAP))
				mirror_process_unit_resync(un);
		}
		(void) mirror_close_all_devs(un, md_cflags);

		/*
		 * For a MN set with transient capabilities (eg ABR/DMR) set,
		 * clear these capabilities on the last open in the cluster.
		 * To do this we send a message to all nodes to see of the
		 * device is open.
		 */
		if (MD_MNSET_SETNO(MD_UN2SET(un)) &&
		    (ui->ui_tstate & (MD_ABR_CAP|MD_DMR_CAP))) {
			if (lockp) {
				(void) md_ioctl_openclose_exit(lockp);
			} else {
				md_unit_openclose_exit(ui);
			}

			/*
			 * if we are in the context of an ioctl, drop the
			 * ioctl lock.
			 * Otherwise, no other locks should be held.
			 */
			if (lockp) {
				IOLOCK_RETURN_RELEASE(0, lockp);
			}

			mdmn_clear_all_capabilities(mnum);

			/* if dropped the lock previously, regain it */
			if (lockp) {
				IOLOCK_RETURN_REACQUIRE(lockp);
			}
			return (0);
		}
		/* unlock and return success */
	}
out:
	/* Call whether lockp is NULL or not. */
	if (lockp) {
		md_ioctl_openclose_exit(lockp);
	} else {
		md_unit_openclose_exit(ui);
	}
	return (err);
}

/*
 * When a component has completed resyncing and is now ok, check if the
 * corresponding component in the other submirrors is in the Last Erred
 * state.  If it is, we want to change that to the Erred state so we stop
 * using that component and start using this good component instead.
 *
 * This is called from set_sm_comp_state and recursively calls
 * set_sm_comp_state if it needs to change the Last Erred state.
 */
static void
reset_lasterred(mm_unit_t *un, int smi, mddb_recid_t *extras, uint_t flags,
	IOLOCK *lockp)
{
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	int			ci;
	int			i;
	int			compcnt;
	int			changed = 0;

	for (i = 0; i < NMIRROR; i++) {
		sm = &un->un_sm[i];
		smic = &un->un_smic[i];

		if (!SMS_IS(sm, SMS_INUSE))
			continue;

		/* ignore the submirror that we just made ok */
		if (i == smi)
			continue;

		compcnt = (*(smic->sm_get_component_count)) (sm->sm_dev, un);
		for (ci = 0; ci < compcnt; ci++) {
			md_m_shared_t	*shared;

			shared = (md_m_shared_t *)(*(smic->sm_shared_by_indx))
			    (sm->sm_dev, sm, ci);

			if ((shared->ms_state & CS_LAST_ERRED) &&
			    !mirror_other_sources(un, i, ci, 1)) {

				set_sm_comp_state(un, i, ci, CS_ERRED, extras,
				    flags, lockp);
				changed = 1;
			}
		}
	}

	/* maybe there is a hotspare for this newly erred component */
	if (changed) {
		set_t	setno;

		setno = MD_UN2SET(un);
		if (MD_MNSET_SETNO(setno)) {
			send_poke_hotspares(setno);
		} else {
			(void) poke_hotspares();
		}
	}
}

/*
 * set_sm_comp_state
 *
 * Set the state of a submirror component to the specified new state.
 * If the mirror is in a multi-node set, send messages to all nodes to
 * block all writes to the mirror and then update the state and release the
 * writes. These messages are only sent if MD_STATE_XMIT is set in flags.
 * MD_STATE_XMIT will be unset in 2 cases:
 * 1. When the state is changed to CS_RESYNC as this state change
 * will already have been updated on each node by the processing of the
 * distributed metasync command, hence no need to xmit.
 * 2. When the state is change to CS_OKAY after a resync has completed. Again
 * the resync completion will already have been processed on each node by
 * the processing of the MD_MN_MSG_RESYNC_PHASE_DONE message for a component
 * resync, hence no need to xmit.
 *
 * In case we are called from the updates of a watermark,
 * (then MD_STATE_WMUPDATE will be set in the ps->flags) this is due to
 * a metainit or similar. In this case the message that we sent to propagate
 * the state change must not be a class1 message as that would deadlock with
 * the metainit command that is still being processed.
 * This we achieve by creating a class2 message MD_MN_MSG_STATE_UPDATE2
 * instead. This also makes the submessage generator to create a class2
 * submessage rather than a class1 (which would also block)
 *
 * On entry, unit_writerlock is held
 * If MD_STATE_OCHELD is set in flags, then unit_openclose lock is
 * also held.
 */
void
set_sm_comp_state(
	mm_unit_t	*un,
	int		smi,
	int		ci,
	int		newstate,
	mddb_recid_t	*extras,
	uint_t		flags,
	IOLOCK		*lockp
)
{
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	md_m_shared_t		*shared;
	int			origstate;
	void			(*get_dev)();
	ms_cd_info_t		cd;
	char			devname[MD_MAX_CTDLEN];
	int			err;
	set_t			setno = MD_UN2SET(un);
	md_mn_msg_stch_t	stchmsg;
	mdi_unit_t		*ui = MDI_UNIT(MD_SID(un));
	md_mn_kresult_t		*kresult;
	int			rval;
	uint_t			msgflags;
	md_mn_msgtype_t		msgtype;
	int			save_lock = 0;
	mdi_unit_t		*ui_sm;
	int			nretries = 0;

	sm = &un->un_sm[smi];
	smic = &un->un_smic[smi];

	/* If we have a real error status then turn off MD_INACCESSIBLE. */
	ui_sm = MDI_UNIT(getminor(md_dev64_to_dev(sm->sm_dev)));
	if (newstate & (CS_ERRED | CS_RESYNC | CS_LAST_ERRED) &&
	    ui_sm->ui_tstate & MD_INACCESSIBLE) {
		ui_sm->ui_tstate &= ~MD_INACCESSIBLE;
	}

	shared = (md_m_shared_t *)(*(smic->sm_shared_by_indx))
	    (sm->sm_dev, sm, ci);
	origstate = shared->ms_state;

	/*
	 * If the new state is an error and the old one wasn't, generate
	 * a console message. We do this before we send the state to other
	 * nodes in a MN set because the state change may change the component
	 * name  if a hotspare is allocated.
	 */
	if ((! (origstate & (CS_ERRED|CS_LAST_ERRED))) &&
	    (newstate & (CS_ERRED|CS_LAST_ERRED))) {

		get_dev = (void (*)())md_get_named_service(sm->sm_dev, 0,
		    "get device", 0);
		(void) (*get_dev)(sm->sm_dev, sm, ci, &cd);

		err = md_getdevname(setno, mddb_getsidenum(setno), 0,
		    cd.cd_dev, devname, sizeof (devname));

		if (err == ENOENT) {
			(void) md_devname(setno, cd.cd_dev, devname,
			    sizeof (devname));
		}

		cmn_err(CE_WARN, "md: %s: %s needs maintenance",
		    md_shortname(md_getminor(sm->sm_dev)), devname);

		if (newstate & CS_LAST_ERRED) {
			cmn_err(CE_WARN, "md: %s: %s last erred",
			    md_shortname(md_getminor(sm->sm_dev)),
			    devname);

		} else if (shared->ms_flags & MDM_S_ISOPEN) {
			/*
			 * Close the broken device and clear the open flag on
			 * it.  Closing the device means the RCM framework will
			 * be able to unconfigure the device if required.
			 *
			 * We have to check that the device is open, otherwise
			 * the first open on it has resulted in the error that
			 * is being processed and the actual cd.cd_dev will be
			 * NODEV64.
			 *
			 * If this is a multi-node mirror, then the multinode
			 * state checks following this code will cause the
			 * slave nodes to close the mirror in the function
			 * mirror_set_state().
			 */
			md_layered_close(cd.cd_dev, MD_OFLG_NULL);
			shared->ms_flags &= ~MDM_S_ISOPEN;
		}

	} else if ((origstate & CS_LAST_ERRED) && (newstate & CS_ERRED) &&
	    (shared->ms_flags & MDM_S_ISOPEN)) {
		/*
		 * Similar to logic above except no log messages since we
		 * are just transitioning from Last Erred to Erred.
		 */
		get_dev = (void (*)())md_get_named_service(sm->sm_dev, 0,
		    "get device", 0);
		(void) (*get_dev)(sm->sm_dev, sm, ci, &cd);

		md_layered_close(cd.cd_dev, MD_OFLG_NULL);
		shared->ms_flags &= ~MDM_S_ISOPEN;
	}

	if ((MD_MNSET_SETNO(setno)) && (origstate != newstate) &&
	    (flags & MD_STATE_XMIT) && !(ui->ui_tstate & MD_ERR_PENDING)) {
		/*
		 * For a multi-node mirror, send the state change to the
		 * master, which broadcasts to all nodes, including this
		 * one. Once the message is received, the state is set
		 * in-core and the master commits the change to disk.
		 * There is a case, comp_replace,  where this function
		 * can be called from within an ioctl and therefore in this
		 * case, as the ioctl will already be called on each node,
		 * there is no need to xmit the state change to the master for
		 * distribution to the other nodes. MD_STATE_XMIT flag is used
		 * to indicate whether a xmit is required. The mirror's
		 * transient state is set to MD_ERR_PENDING to avoid sending
		 * multiple messages.
		 */
		if (newstate & (CS_ERRED|CS_LAST_ERRED))
			ui->ui_tstate |= MD_ERR_PENDING;

		/*
		 * Send a state update message to all nodes. This message
		 * will generate 2 submessages, the first one to suspend
		 * all writes to the mirror and the second to update the
		 * state and resume writes.
		 */
		stchmsg.msg_stch_mnum = un->c.un_self_id;
		stchmsg.msg_stch_sm = smi;
		stchmsg.msg_stch_comp = ci;
		stchmsg.msg_stch_new_state = newstate;
		stchmsg.msg_stch_hs_id = shared->ms_hs_id;
#ifdef DEBUG
		if (mirror_debug_flag)
			printf("send set state, %x, %x, %x, %x, %x\n",
			    stchmsg.msg_stch_mnum, stchmsg.msg_stch_sm,
			    stchmsg.msg_stch_comp, stchmsg.msg_stch_new_state,
			    stchmsg.msg_stch_hs_id);
#endif
		if (flags & MD_STATE_WMUPDATE) {
			msgtype  = MD_MN_MSG_STATE_UPDATE2;
			/*
			 * When coming from an update of watermarks, there
			 * must already be a message logged that triggered
			 * this action. So, no need to log this message, too.
			 */
			msgflags = MD_MSGF_NO_LOG;
		} else {
			msgtype  = MD_MN_MSG_STATE_UPDATE;
			msgflags = MD_MSGF_DEFAULT_FLAGS;
		}

		/*
		 * If we are in the context of an ioctl, drop the ioctl lock.
		 * lockp holds the list of locks held.
		 *
		 * Otherwise, increment the appropriate reacquire counters.
		 * If openclose lock is *held, then must reacquire reader
		 * lock before releasing the openclose lock.
		 * Do not drop the ARRAY_WRITER lock as we may not be able
		 * to reacquire it.
		 */
		if (lockp) {
			if (lockp->l_flags & MD_ARRAY_WRITER) {
				save_lock = MD_ARRAY_WRITER;
				lockp->l_flags &= ~MD_ARRAY_WRITER;
			} else if (lockp->l_flags & MD_ARRAY_READER) {
				save_lock = MD_ARRAY_READER;
				lockp->l_flags &= ~MD_ARRAY_READER;
			}
			IOLOCK_RETURN_RELEASE(0, lockp);
		} else {
			if (flags & MD_STATE_OCHELD) {
				md_unit_writerexit(ui);
				(void) md_unit_readerlock(ui);
				md_unit_openclose_exit(ui);
			} else {
				md_unit_writerexit(ui);
			}
		}

		kresult = kmem_alloc(sizeof (md_mn_kresult_t), KM_SLEEP);
sscs_msg:
		rval = mdmn_ksend_message(setno, msgtype, msgflags, 0,
		    (char *)&stchmsg, sizeof (stchmsg), kresult);

		if (!MDMN_KSEND_MSG_OK(rval, kresult)) {
			mdmn_ksend_show_error(rval, kresult, "STATE UPDATE");
			/* If we're shutting down already, pause things here. */
			if (kresult->kmmr_comm_state == MDMNE_RPC_FAIL) {
				while (!md_mn_is_commd_present()) {
					delay(md_hz);
				}
				/*
				 * commd is now available; retry the message
				 * one time. If that fails we fall through and
				 * panic as the system is in an unexpected state
				 */
				if (nretries++ == 0)
					goto sscs_msg;
			}
			cmn_err(CE_PANIC,
			    "ksend_message failure: STATE_UPDATE");
		}
		kmem_free(kresult, sizeof (md_mn_kresult_t));

		/* if dropped the lock previously, regain it */
		if (lockp) {
			IOLOCK_RETURN_REACQUIRE(lockp);
			lockp->l_flags |= save_lock;
		} else {
			/*
			 * Reacquire dropped locks and update acquirecnts
			 * appropriately.
			 */
			if (flags & MD_STATE_OCHELD) {
				/*
				 * openclose also grabs readerlock.
				 */
				(void) md_unit_openclose_enter(ui);
				md_unit_readerexit(ui);
				(void) md_unit_writerlock(ui);
			} else {
				(void) md_unit_writerlock(ui);
			}
		}

		ui->ui_tstate &= ~MD_ERR_PENDING;
	} else {
		shared->ms_state = newstate;
		uniqtime32(&shared->ms_timestamp);

		if (newstate == CS_ERRED)
			shared->ms_flags |= MDM_S_NOWRITE;
		else
			shared->ms_flags &= ~MDM_S_NOWRITE;

		shared->ms_flags &= ~MDM_S_IOERR;
		un->un_changecnt++;
		shared->ms_lasterrcnt = un->un_changecnt;

		mirror_set_sm_state(sm, smic, SMS_RUNNING, 0);
		mirror_commit(un, SMI2BIT(smi), extras);
	}

	if ((origstate & CS_RESYNC) && (newstate & CS_OKAY)) {
		/*
		 * Resetting the Last Erred state will recursively call back
		 * into this function (set_sm_comp_state) to update the state.
		 */
		reset_lasterred(un, smi, extras, flags, lockp);
	}
}

static int
find_another_logical(
	mm_unit_t		*un,
	mm_submirror_t		*esm,
	diskaddr_t		blk,
	u_longlong_t		cnt,
	int			must_be_open,
	int			state,
	int			err_cnt)
{
	u_longlong_t	cando;
	md_dev64_t	dev;
	md_m_shared_t	*s;

	esm->sm_state |= SMS_IGNORE;
	while (cnt != 0) {
		u_longlong_t	 mcnt;

		mcnt = MIN(cnt, lbtodb(1024 * 1024 * 1024));	/* 1 Gig Blks */

		dev = select_read_unit(un, blk, mcnt, &cando,
		    must_be_open, &s, NULL);
		if (dev == (md_dev64_t)0)
			break;

		if ((state == CS_LAST_ERRED) &&
		    (s->ms_state == CS_LAST_ERRED) &&
		    (err_cnt > s->ms_lasterrcnt))
			break;

		cnt -= cando;
		blk += cando;
	}
	esm->sm_state &= ~SMS_IGNORE;
	return (cnt != 0);
}

int
mirror_other_sources(mm_unit_t *un, int smi, int ci, int must_be_open)
{
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	size_t			count;
	diskaddr_t		block;
	u_longlong_t		skip;
	u_longlong_t		size;
	md_dev64_t		dev;
	int			cnt;
	md_m_shared_t		*s;
	int			not_found;

	sm = &un->un_sm[smi];
	smic = &un->un_smic[smi];
	dev = sm->sm_dev;

	/*
	 * Make sure every component of the submirror
	 * has other sources.
	 */
	if (ci < 0) {
		/* Find the highest lasterrcnt */
		cnt = (*(smic->sm_get_component_count))(dev, sm);
		for (ci = 0; ci < cnt; ci++) {
			not_found = mirror_other_sources(un, smi, ci,
			    must_be_open);
			if (not_found)
				return (1);
		}
		return (0);
	}

	/*
	 * Make sure this component has other sources
	 */
	(void) (*(smic->sm_get_bcss))
	    (dev, sm, ci, &block, &count, &skip, &size);

	if (count == 0)
		return (1);

	s = (md_m_shared_t *)(*(smic->sm_shared_by_indx))(dev, sm, ci);

	while (count--) {
		if (block >= un->c.un_total_blocks)
			return (0);

		if ((block + size) > un->c.un_total_blocks)
			size = un->c.un_total_blocks - block;

		not_found = find_another_logical(un, sm, block, size,
		    must_be_open, s->ms_state, s->ms_lasterrcnt);
		if (not_found)
			return (1);

		block += size + skip;
	}
	return (0);
}

static void
finish_error(md_mps_t *ps)
{
	struct buf	*pb;
	mm_unit_t	*un;
	mdi_unit_t	*ui;
	uint_t		new_str_flags;

	pb = ps->ps_bp;
	un = ps->ps_un;
	ui = ps->ps_ui;

	/*
	 * Must flag any error to the resync originator if we're performing
	 * a Write-after-Read. This corresponds to an i/o error on a resync
	 * target device and in this case we ought to abort the resync as there
	 * is nothing that can be done to recover from this without operator
	 * intervention. If we don't set the B_ERROR flag we will continue
	 * reading from the mirror but won't write to the target (as it will
	 * have been placed into an errored state).
	 * To handle the case of multiple components within a submirror we only
	 * set the B_ERROR bit if explicitly requested to via MD_MPS_FLAG_ERROR.
	 * The originator of the resync read will cause this bit to be set if
	 * the underlying component count is one for a submirror resync. All
	 * other resync types will have the flag set as there is no underlying
	 * resync which can be performed on a contained metadevice for these
	 * resync types (optimized or component).
	 */

	if (ps->ps_flags & MD_MPS_WRITE_AFTER_READ) {
		if (ps->ps_flags & MD_MPS_FLAG_ERROR)
			pb->b_flags |= B_ERROR;
		md_kstat_done(ui, pb, (ps->ps_flags & MD_MPS_WRITE_AFTER_READ));
		MPS_FREE(mirror_parent_cache, ps);
		md_unit_readerexit(ui);
		md_biodone(pb);
		return;
	}
	/*
	 * Set the MD_IO_COUNTED flag as we are retrying the same I/O
	 * operation therefore this I/O request has already been counted,
	 * the I/O count variable will be decremented by mirror_done()'s
	 * call to md_biodone().
	 */
	if (ps->ps_changecnt != un->un_changecnt) {
		new_str_flags = MD_STR_NOTTOP | MD_IO_COUNTED;
		if (ps->ps_flags & MD_MPS_WOW)
			new_str_flags |= MD_STR_WOW;
		if (ps->ps_flags & MD_MPS_MAPPED)
			new_str_flags |= MD_STR_MAPPED;
		/*
		 * If this I/O request was a read that was part of a resync,
		 * set MD_STR_WAR for the retried read to ensure that the
		 * resync write (i.e. write-after-read) will be performed
		 */
		if (ps->ps_flags & MD_MPS_RESYNC_READ)
			new_str_flags |= MD_STR_WAR;
		md_kstat_done(ui, pb, (ps->ps_flags & MD_MPS_WRITE_AFTER_READ));
		MPS_FREE(mirror_parent_cache, ps);
		md_unit_readerexit(ui);
		(void) md_mirror_strategy(pb, new_str_flags, NULL);
		return;
	}

	pb->b_flags |= B_ERROR;
	md_kstat_done(ui, pb, (ps->ps_flags & MD_MPS_WRITE_AFTER_READ));
	MPS_FREE(mirror_parent_cache, ps);
	md_unit_readerexit(ui);
	md_biodone(pb);
}

static void
error_update_unit(md_mps_t *ps)
{
	mm_unit_t		*un;
	mdi_unit_t		*ui;
	int			smi;	/* sub mirror index */
	int			ci;	/* errored component */
	set_t			setno;
	uint_t			flags;	/* for set_sm_comp_state() */
	uint_t			hspflags; /* for check_comp_4_hotspares() */

	ui = ps->ps_ui;
	un = (mm_unit_t *)md_unit_writerlock(ui);
	setno = MD_UN2SET(un);

	/* All of these updates have to propagated in case of MN set */
	flags = MD_STATE_XMIT;
	hspflags = MD_HOTSPARE_XMIT;

	/* special treatment if we are called during updating watermarks */
	if (ps->ps_flags & MD_MPS_WMUPDATE) {
		flags |= MD_STATE_WMUPDATE;
		hspflags |= MD_HOTSPARE_WMUPDATE;
	}
	smi = 0;
	ci = 0;
	while (mirror_geterror(un, &smi, &ci, 1, 0) != 0) {
		if (mirror_other_sources(un, smi, ci, 0) == 1) {

			/* Never called from ioctl context, so (IOLOCK *)NULL */
			set_sm_comp_state(un, smi, ci, CS_LAST_ERRED, 0, flags,
			    (IOLOCK *)NULL);
			/*
			 * For a MN set, the NOTIFY is done when the state
			 * change is processed on each node
			 */
			if (!MD_MNSET_SETNO(MD_UN2SET(un))) {
				SE_NOTIFY(EC_SVM_STATE, ESC_SVM_LASTERRED,
				    SVM_TAG_METADEVICE, setno, MD_SID(un));
			}
			continue;
		}
		/* Never called from ioctl context, so (IOLOCK *)NULL */
		set_sm_comp_state(un, smi, ci, CS_ERRED, 0, flags,
		    (IOLOCK *)NULL);
		/*
		 * For a MN set, the NOTIFY is done when the state
		 * change is processed on each node
		 */
		if (!MD_MNSET_SETNO(MD_UN2SET(un))) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ERRED,
			    SVM_TAG_METADEVICE, setno, MD_SID(un));
		}
		smi = 0;
		ci = 0;
	}

	md_unit_writerexit(ui);
	if (MD_MNSET_SETNO(setno)) {
		send_poke_hotspares(setno);
	} else {
		(void) poke_hotspares();
	}
	(void) md_unit_readerlock(ui);

	finish_error(ps);
}

/*
 * When we have a B_FAILFAST IO error on a Last Erred component we need to
 * retry the IO without B_FAILFAST set so that we try to ensure that the
 * component "sees" each IO.
 */
static void
last_err_retry(md_mcs_t *cs)
{
	struct buf	*cb;
	md_mps_t	*ps;
	uint_t		flags;

	cb = &cs->cs_buf;
	cb->b_flags &= ~B_FAILFAST;

	/* if we're panicing just let this I/O error out */
	if (panicstr) {
		(void) mirror_done(cb);
		return;
	}

	/* reissue the I/O */

	ps = cs->cs_ps;

	bioerror(cb, 0);

	mutex_enter(&ps->ps_mx);

	flags = MD_STR_NOTTOP;
	if (ps->ps_flags & MD_MPS_MAPPED)
		flags |= MD_STR_MAPPED;
	if (ps->ps_flags & MD_MPS_NOBLOCK)
		flags |= MD_NOBLOCK;

	mutex_exit(&ps->ps_mx);

	clear_retry_error(cb);

	cmn_err(CE_NOTE, "!md: %s: Last Erred, retry I/O without B_FAILFAST",
	    md_shortname(getminor(cb->b_edev)));

	md_call_strategy(cb, flags, NULL);
}

static void
mirror_error(md_mps_t *ps)
{
	int		smi;	/* sub mirror index */
	int		ci;	/* errored component */

	if (panicstr) {
		finish_error(ps);
		return;
	}

	if (ps->ps_flags & MD_MPS_ON_OVERLAP)
		mirror_overlap_tree_remove(ps);

	smi = 0;
	ci = 0;
	if (mirror_geterror(ps->ps_un, &smi, &ci, 0, 0) != 0) {
		md_unit_readerexit(ps->ps_ui);
		daemon_request(&md_mstr_daemon, error_update_unit,
		    (daemon_queue_t *)ps, REQ_OLD);
		return;
	}

	finish_error(ps);
}

static int
copy_write_done(struct buf *cb)
{
	md_mps_t	*ps;
	buf_t		*pb;
	char		*wowbuf;
	wowhdr_t	*wowhdr;
	ssize_t		wow_resid;

	/* get wowbuf ans save structure */
	wowbuf = cb->b_un.b_addr;
	wowhdr = WOWBUF_HDR(wowbuf);
	ps = wowhdr->wow_ps;
	pb = ps->ps_bp;

	/* Save error information, then free cb */
	if (cb->b_flags & B_ERROR)
		pb->b_flags |= B_ERROR;

	if (cb->b_flags & B_REMAPPED)
		bp_mapout(cb);

	freerbuf(cb);

	/* update residual and continue if needed */
	if ((pb->b_flags & B_ERROR) == 0) {
		wow_resid = pb->b_bcount - wowhdr->wow_offset;
		pb->b_resid = wow_resid;
		if (wow_resid > 0)  {
			daemon_request(&md_mstr_daemon, copy_write_cont,
			    (daemon_queue_t *)wowhdr, REQ_OLD);
			return (1);
		}
	}

	/* Write is complete, release resources. */
	kmem_cache_free(mirror_wowblk_cache, wowhdr);
	ASSERT(!(ps->ps_flags & MD_MPS_ON_OVERLAP));
	md_kstat_done(ps->ps_ui, pb, (ps->ps_flags & MD_MPS_WRITE_AFTER_READ));
	MPS_FREE(mirror_parent_cache, ps);
	md_biodone(pb);
	return (0);
}

static void
copy_write_cont(wowhdr_t *wowhdr)
{
	buf_t		*pb;
	buf_t		*cb;
	char		*wowbuf;
	int		wow_offset;
	size_t		wow_resid;
	diskaddr_t	wow_blkno;

	wowbuf = WOWHDR_BUF(wowhdr);
	pb = wowhdr->wow_ps->ps_bp;

	/* get data on current location */
	wow_offset = wowhdr->wow_offset;
	wow_resid = pb->b_bcount - wow_offset;
	wow_blkno = pb->b_lblkno + lbtodb(wow_offset);

	/* setup child buffer */
	cb = getrbuf(KM_SLEEP);
	cb->b_flags = B_WRITE;
	cb->b_edev = pb->b_edev;
	cb->b_un.b_addr = wowbuf;	/* change to point at WOWBUF */
	cb->b_bufsize = md_wowbuf_size; /* change to wowbuf_size */
	cb->b_iodone = copy_write_done;
	cb->b_bcount = MIN(md_wowbuf_size, wow_resid);
	cb->b_lblkno = wow_blkno;

	/* move offset to next section */
	wowhdr->wow_offset += cb->b_bcount;

	/* copy and setup write for current section */
	bcopy(&pb->b_un.b_addr[wow_offset], wowbuf, cb->b_bcount);

	/* do it */
	/*
	 * Do not set the MD_IO_COUNTED flag as this is a new I/O request
	 * that handles the WOW condition. The resultant increment on the
	 * I/O count variable is cleared by copy_write_done()'s call to
	 * md_biodone().
	 */
	(void) md_mirror_strategy(cb, MD_STR_NOTTOP | MD_STR_WOW
	    | MD_STR_MAPPED, NULL);
}

static void
md_mirror_copy_write(md_mps_t *ps)
{
	wowhdr_t	*wowhdr;

	wowhdr = kmem_cache_alloc(mirror_wowblk_cache, MD_ALLOCFLAGS);
	mirror_wowblk_init(wowhdr);
	wowhdr->wow_ps = ps;
	wowhdr->wow_offset = 0;
	copy_write_cont(wowhdr);
}

static void
handle_wow(md_mps_t *ps)
{
	buf_t		*pb;

	pb = ps->ps_bp;

	bp_mapin(pb);

	md_mirror_wow_cnt++;
	if (!(pb->b_flags & B_PHYS) && (md_mirror_wow_flg & WOW_LOGIT)) {
		cmn_err(CE_NOTE,
		    "md: %s, blk %lld, cnt %ld: Write on write %d occurred",
		    md_shortname(getminor(pb->b_edev)),
		    (longlong_t)pb->b_lblkno, pb->b_bcount, md_mirror_wow_cnt);
	}

	/*
	 * Set the MD_IO_COUNTED flag as we are retrying the same I/O
	 * operation therefore this I/O request has already been counted,
	 * the I/O count variable will be decremented by mirror_done()'s
	 * call to md_biodone().
	 */
	if (md_mirror_wow_flg & WOW_NOCOPY)
		(void) md_mirror_strategy(pb, MD_STR_NOTTOP | MD_STR_WOW |
		    MD_STR_MAPPED | MD_IO_COUNTED, ps);
	else
		md_mirror_copy_write(ps);
}

/*
 * Return true if the specified submirror is either in the Last Erred
 * state or is transitioning into the Last Erred state.
 */
static bool_t
submirror_is_lasterred(mm_unit_t *un, int smi)
{
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	md_m_shared_t		*shared;
	int			ci;
	int			compcnt;

	sm = &un->un_sm[smi];
	smic = &un->un_smic[smi];

	compcnt = (*(smic->sm_get_component_count)) (sm->sm_dev, un);
	for (ci = 0; ci < compcnt; ci++) {
		shared = (md_m_shared_t *)(*(smic->sm_shared_by_indx))
		    (sm->sm_dev, sm, ci);

		if (shared->ms_state == CS_LAST_ERRED)
			return (B_TRUE);

		/*
		 * It is not currently Last Erred, check if entering Last Erred.
		 */
		if ((shared->ms_flags & MDM_S_IOERR) &&
		    ((shared->ms_state == CS_OKAY) ||
		    (shared->ms_state == CS_RESYNC))) {
			if (mirror_other_sources(un, smi, ci, 0) == 1)
				return (B_TRUE);
		}
	}

	return (B_FALSE);
}


static int
mirror_done(struct buf *cb)
{
	md_mps_t	*ps;
	md_mcs_t	*cs;

	/*LINTED*/
	cs = (md_mcs_t *)((caddr_t)cb - md_mirror_mcs_buf_off);
	ps = cs->cs_ps;

	mutex_enter(&ps->ps_mx);

	/* check if we need to retry an errored failfast I/O */
	if (cb->b_flags & B_ERROR) {
		struct buf *pb = ps->ps_bp;

		if (cb->b_flags & B_FAILFAST) {
			int		i;
			mm_unit_t	*un = ps->ps_un;

			for (i = 0; i < NMIRROR; i++) {
				if (!SMS_BY_INDEX_IS(un, i, SMS_INUSE))
					continue;

				if (cb->b_edev ==
				    md_dev64_to_dev(un->un_sm[i].sm_dev)) {

					/*
					 * This is the submirror that had the
					 * error.  Check if it is Last Erred.
					 */
					if (submirror_is_lasterred(un, i)) {
						daemon_queue_t *dqp;

						mutex_exit(&ps->ps_mx);
						dqp = (daemon_queue_t *)cs;
						dqp->dq_prev = NULL;
						dqp->dq_next = NULL;
						daemon_request(&md_done_daemon,
						    last_err_retry, dqp,
						    REQ_OLD);
						return (1);
					}
					break;
				}
			}
		}

		/* continue to process the buf without doing a retry */
		ps->ps_flags |= MD_MPS_ERROR;
		pb->b_error = cb->b_error;
	}

	return (mirror_done_common(cb));
}

/*
 * Split from the original mirror_done function so we can handle bufs after a
 * retry.
 * ps->ps_mx is already held in the caller of this function and the cb error
 * has already been checked and handled in the caller.
 */
static int
mirror_done_common(struct buf *cb)
{
	struct buf	*pb;
	mm_unit_t	*un;
	mdi_unit_t	*ui;
	md_mps_t	*ps;
	md_mcs_t	*cs;
	size_t		end_rr, start_rr, current_rr;

	/*LINTED*/
	cs = (md_mcs_t *)((caddr_t)cb - md_mirror_mcs_buf_off);
	ps = cs->cs_ps;
	pb = ps->ps_bp;

	if (cb->b_flags & B_REMAPPED)
		bp_mapout(cb);

	ps->ps_frags--;
	if (ps->ps_frags != 0) {
		mutex_exit(&ps->ps_mx);
		kmem_cache_free(mirror_child_cache, cs);
		return (1);
	}
	un = ps->ps_un;
	ui = ps->ps_ui;

	/*
	 * Do not update outstanding_writes if we're running with ABR
	 * set for this mirror or the write() was issued with MD_STR_ABR set.
	 * Also a resync initiated write() has no outstanding_writes update
	 * either.
	 */
	if (((cb->b_flags & B_READ) == 0) &&
	    (un->un_nsm >= 2) &&
	    (ps->ps_call == NULL) &&
	    !((ui->ui_tstate & MD_ABR_CAP) || (ps->ps_flags & MD_MPS_ABR)) &&
	    !(ps->ps_flags & MD_MPS_WRITE_AFTER_READ)) {
		BLK_TO_RR(end_rr, ps->ps_lastblk, un);
		BLK_TO_RR(start_rr, ps->ps_firstblk, un);
		mutex_enter(&un->un_resync_mx);
		for (current_rr = start_rr; current_rr <= end_rr; current_rr++)
			un->un_outstanding_writes[current_rr]--;
		mutex_exit(&un->un_resync_mx);
	}
	kmem_cache_free(mirror_child_cache, cs);
	mutex_exit(&ps->ps_mx);

	if (ps->ps_call != NULL) {
		daemon_request(&md_done_daemon, ps->ps_call,
		    (daemon_queue_t *)ps, REQ_OLD);
		return (1);
	}

	if ((ps->ps_flags & MD_MPS_ERROR)) {
		daemon_request(&md_done_daemon, mirror_error,
		    (daemon_queue_t *)ps, REQ_OLD);
		return (1);
	}

	if (ps->ps_flags & MD_MPS_ON_OVERLAP)
		mirror_overlap_tree_remove(ps);

	/*
	 * Handle Write-on-Write problem.
	 * Skip In case of Raw and Direct I/O as they are
	 * handled earlier.
	 *
	 */
	if (!(md_mirror_wow_flg & WOW_DISABLE) &&
	    !(pb->b_flags & B_READ) &&
	    !(ps->ps_flags & MD_MPS_WOW) &&
	    !(pb->b_flags & B_PHYS) &&
	    any_pages_dirty(pb)) {
		md_unit_readerexit(ps->ps_ui);
		daemon_request(&md_mstr_daemon, handle_wow,
		    (daemon_queue_t *)ps, REQ_OLD);
		return (1);
	}

	md_kstat_done(ui, pb, (ps->ps_flags & MD_MPS_WRITE_AFTER_READ));
	MPS_FREE(mirror_parent_cache, ps);
	md_unit_readerexit(ui);
	md_biodone(pb);
	return (0);
}

/*
 * Clear error state in submirror component if the retry worked after
 * a failfast error.
 */
static void
clear_retry_error(struct buf *cb)
{
	int			smi;
	md_mcs_t		*cs;
	mm_unit_t		*un;
	mdi_unit_t		*ui_sm;
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	u_longlong_t		cnt;
	md_m_shared_t		*shared;

	/*LINTED*/
	cs = (md_mcs_t *)((caddr_t)cb - md_mirror_mcs_buf_off);
	un = cs->cs_ps->ps_un;

	for (smi = 0; smi < NMIRROR; smi++) {
		if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE))
			continue;

		if (cb->b_edev == md_dev64_to_dev(un->un_sm[smi].sm_dev))
			break;
	}

	if (smi >= NMIRROR)
		return;

	sm = &un->un_sm[smi];
	smic = &un->un_smic[smi];
	cnt = cb->b_bcount;

	ui_sm = MDI_UNIT(getminor(cb->b_edev));
	(void) md_unit_writerlock(ui_sm);

	shared = (md_m_shared_t *)(*(smic->sm_shared_by_blk))(sm->sm_dev, sm,
	    cb->b_blkno, &cnt);

	if (shared->ms_flags & MDM_S_IOERR) {
		shared->ms_flags &= ~MDM_S_IOERR;

	} else {
		/* the buf spans components and the first one is not erred */
		int	cnt;
		int	i;

		cnt = (*(smic->sm_get_component_count))(sm->sm_dev, un);
		for (i = 0; i < cnt; i++) {
			shared = (md_m_shared_t *)(*(smic->sm_shared_by_indx))
			    (sm->sm_dev, sm, i);

			if (shared->ms_flags & MDM_S_IOERR &&
			    shared->ms_state == CS_OKAY) {

				shared->ms_flags &= ~MDM_S_IOERR;
				break;
			}
		}
	}

	md_unit_writerexit(ui_sm);
}

static size_t
mirror_map_read(
	md_mps_t *ps,
	md_mcs_t *cs,
	diskaddr_t blkno,
	u_longlong_t	count
)
{
	mm_unit_t	*un;
	buf_t		*bp;
	u_longlong_t	cando;

	bp = &cs->cs_buf;
	un = ps->ps_un;

	bp->b_lblkno = blkno;
	if (fast_select_read_unit(ps, cs) == 0) {
		bp->b_bcount = ldbtob(count);
		return (0);
	}
	bp->b_edev = md_dev64_to_dev(select_read_unit(un, blkno,
	    count, &cando, 0, NULL, cs));
	bp->b_bcount = ldbtob(cando);
	if (count != cando)
		return (cando);
	return (0);
}

static void
write_after_read(md_mps_t *ps)
{
	struct buf	*pb;
	int		flags;

	if (ps->ps_flags & MD_MPS_ERROR) {
		mirror_error(ps);
		return;
	}

	pb = ps->ps_bp;
	md_kstat_done(ps->ps_ui, pb, (ps->ps_flags & MD_MPS_WRITE_AFTER_READ));
	ps->ps_call = NULL;
	ps->ps_flags |= MD_MPS_WRITE_AFTER_READ;
	flags = MD_STR_NOTTOP | MD_STR_WAR;
	if (ps->ps_flags & MD_MPS_MAPPED)
		flags |= MD_STR_MAPPED;
	if (ps->ps_flags & MD_MPS_NOBLOCK)
		flags |= MD_NOBLOCK;
	if (ps->ps_flags & MD_MPS_DIRTY_RD)
		flags |= MD_STR_DIRTY_RD;
	(void) mirror_write_strategy(pb, flags, ps);
}

static void
continue_serial(md_mps_t *ps)
{
	md_mcs_t	*cs;
	buf_t		*cb;
	mm_unit_t	*un;
	int		flags;

	un = ps->ps_un;
	cs = kmem_cache_alloc(mirror_child_cache, MD_ALLOCFLAGS);
	mirror_child_init(cs);
	cb = &cs->cs_buf;
	ps->ps_call = NULL;
	ps->ps_frags = 1;
	(void) mirror_map_write(un, cs, ps, 0);
	flags = MD_STR_NOTTOP;
	if (ps->ps_flags & MD_MPS_MAPPED)
		flags |= MD_STR_MAPPED;
	md_call_strategy(cb, flags, NULL);
}

static int
mirror_map_write(mm_unit_t *un, md_mcs_t *cs, md_mps_t *ps, int war)
{
	int i;
	dev_t		dev;	/* needed for bioclone, so not md_dev64_t */
	buf_t		*cb;
	buf_t		*pb;
	diskaddr_t	blkno;
	size_t		bcount;
	off_t		offset;

	pb = ps->ps_bp;
	cb = &cs->cs_buf;
	cs->cs_ps = ps;

	i = md_find_nth_unit(ps->ps_writable_sm, ps->ps_current_sm);

	dev = md_dev64_to_dev(un->un_sm[i].sm_dev);

	blkno = pb->b_lblkno;
	bcount = pb->b_bcount;
	offset = 0;
	if (war && (blkno == 0) && (un->c.un_flag & MD_LABELED)) {
		blkno = DK_LABEL_LOC + 1;
		/*
		 * This handles the case where we're requesting
		 * a write to block 0 on a label partition
		 * and the request size was smaller than the
		 * size of the label.  If this is the case
		 * then we'll return -1.  Failure to do so will
		 * either cause the calling thread to hang due to
		 * an ssd bug, or worse if the bcount were allowed
		 * to go negative (ie large).
		 */
		if (bcount <= DEV_BSIZE*(DK_LABEL_LOC + 1))
			return (-1);
		bcount -= (DEV_BSIZE*(DK_LABEL_LOC + 1));
		offset = (DEV_BSIZE*(DK_LABEL_LOC + 1));
	}

	cb = md_bioclone(pb, offset, bcount, dev, blkno, mirror_done,
	    cb, KM_NOSLEEP);
	if (war)
		cb->b_flags = (cb->b_flags & ~B_READ) | B_WRITE;

	/*
	 * If the submirror is in the erred stated, check if any component is
	 * in the Last Erred state.  If so, we don't want to use the B_FAILFAST
	 * flag on the IO.
	 *
	 * Provide a fast path for the non-erred case (which should be the
	 * normal case).
	 */
	if (un->un_sm[i].sm_flags & MD_SM_FAILFAST) {
		if (un->un_sm[i].sm_state & SMS_COMP_ERRED) {
			mm_submirror_t		*sm;
			mm_submirror_ic_t	*smic;
			int			ci;
			int			compcnt;

			sm = &un->un_sm[i];
			smic = &un->un_smic[i];

			compcnt = (*(smic->sm_get_component_count))
			    (sm->sm_dev, un);
			for (ci = 0; ci < compcnt; ci++) {
				md_m_shared_t	*shared;

				shared = (md_m_shared_t *)
				    (*(smic->sm_shared_by_indx))(sm->sm_dev,
				    sm, ci);

				if (shared->ms_state == CS_LAST_ERRED)
					break;
			}
			if (ci >= compcnt)
				cb->b_flags |= B_FAILFAST;

		} else {
			cb->b_flags |= B_FAILFAST;
		}
	}

	ps->ps_current_sm++;
	if (ps->ps_current_sm != ps->ps_active_cnt) {
		if (un->un_write_option == WR_SERIAL) {
			ps->ps_call = continue_serial;
			return (0);
		}
		return (1);
	}
	return (0);
}

/*
 * directed_read_done:
 * ------------------
 * Completion routine called when a DMR request has been returned from the
 * underlying driver. Wake-up the original ioctl() and return the data to
 * the user.
 */
static void
directed_read_done(md_mps_t *ps)
{
	mm_unit_t	*un;
	mdi_unit_t	*ui;

	un = ps->ps_un;
	ui = ps->ps_ui;

	md_unit_readerexit(ui);
	md_kstat_done(ui, ps->ps_bp, (ps->ps_flags & MD_MPS_WRITE_AFTER_READ));
	ps->ps_call = NULL;

	mutex_enter(&un->un_dmr_mx);
	cv_signal(&un->un_dmr_cv);
	mutex_exit(&un->un_dmr_mx);

	/* release the parent structure */
	kmem_cache_free(mirror_parent_cache, ps);
}

/*
 * daemon_io:
 * ------------
 * Called to issue a mirror_write_strategy() or mirror_read_strategy
 * call from a blockable context. NOTE: no mutex can be held on entry to this
 * routine
 */
static void
daemon_io(daemon_queue_t *dq)
{
	md_mps_t	*ps = (md_mps_t *)dq;
	int		flag = MD_STR_NOTTOP;
	buf_t		*pb = ps->ps_bp;

	if (ps->ps_flags & MD_MPS_MAPPED)
		flag |= MD_STR_MAPPED;
	if (ps->ps_flags & MD_MPS_WOW)
		flag |= MD_STR_WOW;
	if (ps->ps_flags & MD_MPS_WRITE_AFTER_READ)
		flag |= MD_STR_WAR;
	if (ps->ps_flags & MD_MPS_ABR)
		flag |= MD_STR_ABR;
	if (ps->ps_flags & MD_MPS_BLOCKABLE_IO)
		flag |= MD_STR_BLOCK_OK;

	/*
	 * If this is a resync read, ie MD_STR_DIRTY_RD not set, set
	 * MD_STR_WAR before calling mirror_read_strategy
	 */
	if (pb->b_flags & B_READ) {
		if (!(ps->ps_flags & MD_MPS_DIRTY_RD))
			flag |= MD_STR_WAR;
		mirror_read_strategy(pb, flag, ps);
	} else
		mirror_write_strategy(pb, flag, ps);
}

/*
 * update_resync:
 * -------------
 * Called to update the in-core version of the resync record with the latest
 * version that was committed to disk when the previous mirror owner
 * relinquished ownership. This call is likely to block as we must hold-off
 * any current resync processing that may be occurring.
 * On completion of the resync record update we issue the mirror_write_strategy
 * call to complete the i/o that first started this sequence. To remove a race
 * condition between a new write() request which is submitted and the resync
 * record update we acquire the writerlock. This will hold off all i/o to the
 * mirror until the resync update has completed.
 * NOTE: no mutex can be held on entry to this routine
 */
static void
update_resync(daemon_queue_t *dq)
{
	md_mps_t	*ps = (md_mps_t *)dq;
	buf_t		*pb = ps->ps_bp;
	mdi_unit_t	*ui = ps->ps_ui;
	mm_unit_t	*un = MD_UNIT(ui->ui_link.ln_id);
	set_t		setno;
	int		restart_resync;

	mutex_enter(&un->un_rrp_inflight_mx);
	(void) md_unit_writerlock(ui);
	ps->ps_un = un;
	setno = MD_MIN2SET(getminor(pb->b_edev));
	if (mddb_reread_rr(setno, un->un_rr_dirty_recid) == 0) {
		/*
		 * Synchronize our in-core view of what regions need to be
		 * resync'd with the on-disk version.
		 */
		mirror_copy_rr(howmany(un->un_rrd_num, NBBY), un->un_resync_bm,
		    un->un_dirty_bm);

		/* Region dirty map is now up to date */
	}
	restart_resync = (un->un_rs_thread_flags & MD_RI_BLOCK_OWNER) ? 1 : 0;
	md_unit_writerexit(ui);
	mutex_exit(&un->un_rrp_inflight_mx);

	/* Restart the resync thread if it was previously blocked */
	if (restart_resync) {
		mutex_enter(&un->un_rs_thread_mx);
		un->un_rs_thread_flags &= ~MD_RI_BLOCK_OWNER;
		cv_signal(&un->un_rs_thread_cv);
		mutex_exit(&un->un_rs_thread_mx);
	}
	/* Continue with original deferred i/o */
	daemon_io(dq);
}

/*
 * owner_timeout:
 * -------------
 * Called if the original mdmn_ksend_message() failed and the request is to be
 * retried. Reattempt the original ownership change.
 *
 * NOTE: called at interrupt context (see timeout(9f)).
 */
static void
owner_timeout(void *arg)
{
	daemon_queue_t	*dq = (daemon_queue_t *)arg;

	daemon_request(&md_mirror_daemon, become_owner, dq, REQ_OLD);
}

/*
 * become_owner:
 * ------------
 * Called to issue RPC request to become the owner of the mirror
 * associated with this i/o request. We assume that the ownership request
 * is synchronous, so if it succeeds we will issue the request via
 * mirror_write_strategy().
 * If multiple i/o's are outstanding we will be called from the mirror_daemon
 * service thread.
 * NOTE: no mutex should be held on entry to this routine.
 */
static void
become_owner(daemon_queue_t *dq)
{
	md_mps_t	*ps = (md_mps_t *)dq;
	mm_unit_t	*un = ps->ps_un;
	buf_t		*pb = ps->ps_bp;
	set_t		setno;
	md_mn_kresult_t	*kres;
	int		msg_flags = md_mirror_msg_flags;
	md_mps_t	*ps1;

	ASSERT(dq->dq_next == NULL && dq->dq_prev == NULL);

	/*
	 * If we're already the mirror owner we do not need to send a message
	 * but can simply process the i/o request immediately.
	 * If we've already sent the request to become owner we requeue the
	 * request as we're waiting for the synchronous ownership message to
	 * be processed.
	 */
	if (MD_MN_MIRROR_OWNER(un)) {
		/*
		 * As the strategy() call will potentially block we need to
		 * punt this to a separate thread and complete this request
		 * as quickly as possible. Note: if we're a read request
		 * this must be a resync, we cannot afford to be queued
		 * behind any intervening i/o requests. In this case we put the
		 * request on the md_mirror_rs_daemon queue.
		 */
		if (pb->b_flags & B_READ) {
			daemon_request(&md_mirror_rs_daemon, daemon_io, dq,
			    REQ_OLD);
		} else {
			daemon_request(&md_mirror_io_daemon, daemon_io, dq,
			    REQ_OLD);
		}
	} else {
		mutex_enter(&un->un_owner_mx);
		if ((un->un_owner_state & MM_MN_OWNER_SENT) == 0) {
			md_mn_req_owner_t	*msg;
			int			rval = 0;

			/*
			 * Check to see that we haven't exceeded the maximum
			 * retry count. If we have we fail the i/o as the
			 * comms mechanism has become wedged beyond recovery.
			 */
			if (dq->qlen++ >= MD_OWNER_RETRIES) {
				mutex_exit(&un->un_owner_mx);
				cmn_err(CE_WARN,
				    "md_mirror: Request exhausted ownership "
				    "retry limit of %d attempts", dq->qlen);
				pb->b_error = EIO;
				pb->b_flags |= B_ERROR;
				pb->b_resid = pb->b_bcount;
				kmem_cache_free(mirror_parent_cache, ps);
				md_biodone(pb);
				return;
			}

			/*
			 * Issue request to change ownership. The call is
			 * synchronous so when it returns we can complete the
			 * i/o (if successful), or enqueue it again so that
			 * the operation will be retried.
			 */
			un->un_owner_state |= MM_MN_OWNER_SENT;
			mutex_exit(&un->un_owner_mx);

			msg = kmem_zalloc(sizeof (md_mn_req_owner_t), KM_SLEEP);
			setno = MD_MIN2SET(getminor(pb->b_edev));
			msg->mnum = MD_SID(un);
			msg->owner = md_mn_mynode_id;
			msg_flags |= MD_MSGF_NO_LOG;
			/*
			 * If this IO is triggered by updating a watermark,
			 * it might be issued by the creation of a softpartition
			 * while the commd subsystem is suspended.
			 * We don't want this message to block.
			 */
			if (ps->ps_flags & MD_MPS_WMUPDATE) {
				msg_flags |= MD_MSGF_OVERRIDE_SUSPEND;
			}

			kres = kmem_alloc(sizeof (md_mn_kresult_t), KM_SLEEP);
			rval = mdmn_ksend_message(setno,
			    MD_MN_MSG_REQUIRE_OWNER, msg_flags, 0,
			    (char *)msg, sizeof (md_mn_req_owner_t), kres);

			kmem_free(msg, sizeof (md_mn_req_owner_t));

			if (MDMN_KSEND_MSG_OK(rval, kres)) {
				dq->qlen = 0;
				/*
				 * Successfully changed owner, reread the
				 * resync record so that we have a valid idea of
				 * any previously committed incomplete write()s.
				 * NOTE: As we need to acquire the resync mutex
				 * this may block, so we defer it to a separate
				 * thread handler. This makes us (effectively)
				 * non-blocking once the ownership message
				 * handling has completed.
				 */
				mutex_enter(&un->un_owner_mx);
				if (un->un_owner_state & MM_MN_BECOME_OWNER) {
					un->un_mirror_owner = md_mn_mynode_id;
					/* Sets owner of un_rr_dirty record */
					if (un->un_rr_dirty_recid)
						(void) mddb_setowner(
						    un->un_rr_dirty_recid,
						    md_mn_mynode_id);
					un->un_owner_state &=
					    ~MM_MN_BECOME_OWNER;
					/*
					 * Release the block on the current
					 * resync region if it is blocked
					 */
					ps1 = un->un_rs_prev_overlap;
					if ((ps1 != NULL) &&
					    (ps1->ps_flags & MD_MPS_ON_OVERLAP))
						mirror_overlap_tree_remove(ps1);
					mutex_exit(&un->un_owner_mx);

					/*
					 * If we're a read, this must be a
					 * resync request, issue
					 * the i/o request on the
					 * md_mirror_rs_daemon queue. This is
					 * to avoid a deadlock between the
					 * resync_unit thread and
					 * subsequent i/o requests that may
					 * block on the resync region.
					 */
					if (pb->b_flags & B_READ) {
						daemon_request(
						    &md_mirror_rs_daemon,
						    update_resync, dq, REQ_OLD);
					} else {
						daemon_request(
						    &md_mirror_io_daemon,
						    update_resync, dq, REQ_OLD);
					}
					kmem_free(kres,
					    sizeof (md_mn_kresult_t));
					return;
				} else {
					/*
					 * Some other node has beaten us to
					 * obtain ownership. We need to
					 * reschedule our ownership request
					 */
					mutex_exit(&un->un_owner_mx);
				}
			} else {
				mdmn_ksend_show_error(rval, kres,
				    "MD_MN_MSG_REQUIRE_OWNER");
				/*
				 * Message transport failure is handled by the
				 * comms layer. If the ownership change request
				 * does not succeed we need to flag the error to
				 * the initiator of the i/o. This is handled by
				 * the retry logic above. As the request failed
				 * we do not know _who_ the owner of the mirror
				 * currently is. We reset our idea of the owner
				 * to None so that any further write()s will
				 * attempt to become the owner again. This stops
				 * multiple nodes writing to the same mirror
				 * simultaneously.
				 */
				mutex_enter(&un->un_owner_mx);
				un->un_owner_state &=
				    ~(MM_MN_OWNER_SENT|MM_MN_BECOME_OWNER);
				un->un_mirror_owner = MD_MN_MIRROR_UNOWNED;
				mutex_exit(&un->un_owner_mx);
			}
			kmem_free(kres, sizeof (md_mn_kresult_t));
		} else
			mutex_exit(&un->un_owner_mx);

		/*
		 * Re-enqueue this request on the deferred i/o list. Delay the
		 * request for md_mirror_owner_to usecs to stop thrashing.
		 */
		(void) timeout(owner_timeout, dq,
		    drv_usectohz(md_mirror_owner_to));
	}
}

static void
mirror_write_strategy(buf_t *pb, int flag, void *private)
{
	md_mps_t	*ps;
	md_mcs_t	*cs;
	int		more;
	mm_unit_t	*un;
	mdi_unit_t	*ui;
	buf_t		*cb;		/* child buf pointer */
	set_t		setno;
	int		rs_on_overlap = 0;

	ui = MDI_UNIT(getminor(pb->b_edev));
	un = (mm_unit_t *)MD_UNIT(getminor(pb->b_edev));


	md_kstat_waitq_enter(ui);

	/*
	 * If a state change is in progress for this mirror in a MN set,
	 * suspend all non-resync writes until the state change is complete.
	 * The objective of this suspend is to ensure that it is not
	 * possible for one node to read data from a submirror that another node
	 * has not written to because of the state change. Therefore we
	 * suspend all writes until the state change has been made. As it is
	 * not possible to read from the target of a resync, there is no need
	 * to suspend resync writes.
	 * Note that we only block here if the caller can handle a busy-wait.
	 * The MD_STR_BLOCK_OK flag is set for daemon_io originated i/o only.
	 */

	if (!(flag & MD_STR_WAR)) {
		if (flag & MD_STR_BLOCK_OK) {
			mutex_enter(&un->un_suspend_wr_mx);
			while (un->un_suspend_wr_flag) {
				cv_wait(&un->un_suspend_wr_cv,
				    &un->un_suspend_wr_mx);
			}
			mutex_exit(&un->un_suspend_wr_mx);
		}
		(void) md_unit_readerlock(ui);
	}

	if (!(flag & MD_STR_NOTTOP)) {
		if (md_checkbuf(ui, (md_unit_t *)un, pb)) {
			md_kstat_waitq_exit(ui);
			return;
		}
	}

	setno = MD_MIN2SET(getminor(pb->b_edev));

	/* If an ABR write has been requested, set MD_STR_ABR flag */
	if (MD_MNSET_SETNO(setno) && (pb->b_flags & B_ABRWRITE))
		flag |= MD_STR_ABR;

	if (private == NULL) {
		ps = kmem_cache_alloc(mirror_parent_cache, MD_ALLOCFLAGS);
		mirror_parent_init(ps);
	} else {
		ps = private;
		private = NULL;
	}
	if (flag & MD_STR_MAPPED)
		ps->ps_flags |= MD_MPS_MAPPED;

	if (flag & MD_STR_WOW)
		ps->ps_flags |= MD_MPS_WOW;

	if (flag & MD_STR_ABR)
		ps->ps_flags |= MD_MPS_ABR;

	if (flag & MD_STR_WMUPDATE)
		ps->ps_flags |= MD_MPS_WMUPDATE;

	/*
	 * Save essential information from the original buffhdr
	 * in the md_save structure.
	 */
	ps->ps_un = un;
	ps->ps_ui = ui;
	ps->ps_bp = pb;
	ps->ps_addr = pb->b_un.b_addr;
	ps->ps_firstblk = pb->b_lblkno;
	ps->ps_lastblk = pb->b_lblkno + lbtodb(pb->b_bcount) - 1;
	ps->ps_changecnt = un->un_changecnt;

	/*
	 * Check for suspended writes here. This is where we can defer the
	 * write request to the daemon_io queue which will then call us with
	 * the MD_STR_BLOCK_OK flag set and we'll busy-wait (if necessary) at
	 * the top of this routine.
	 */
	if (!(flag & MD_STR_WAR) && !(flag & MD_STR_BLOCK_OK)) {
		mutex_enter(&un->un_suspend_wr_mx);
		if (un->un_suspend_wr_flag) {
			ps->ps_flags |= MD_MPS_BLOCKABLE_IO;
			mutex_exit(&un->un_suspend_wr_mx);
			md_unit_readerexit(ui);
			daemon_request(&md_mirror_daemon, daemon_io,
			    (daemon_queue_t *)ps, REQ_OLD);
			return;
		}
		mutex_exit(&un->un_suspend_wr_mx);
	}

	/*
	 * If not MN owner and this is an ABR write, make sure the current
	 * resync region is in the overlaps tree
	 */
	mutex_enter(&un->un_owner_mx);
	if (MD_MNSET_SETNO(setno) && (!(MD_MN_MIRROR_OWNER(un))) &&
	    ((ui->ui_tstate & MD_ABR_CAP) || (flag & MD_STR_ABR))) {
		md_mps_t	*ps1;
		/* Block the current resync region, if not already blocked */
		ps1 = un->un_rs_prev_overlap;

		if ((ps1 != NULL) && ((ps1->ps_firstblk != 0) ||
		    (ps1->ps_lastblk != 0))) {
			/* Drop locks to avoid deadlock */
			mutex_exit(&un->un_owner_mx);
			md_unit_readerexit(ui);
			wait_for_overlaps(ps1, MD_OVERLAP_ALLOW_REPEAT);
			rs_on_overlap = 1;
			(void) md_unit_readerlock(ui);
			mutex_enter(&un->un_owner_mx);
			/*
			 * Check to see if we have obtained ownership
			 * while waiting for overlaps. If we have, remove
			 * the resync_region entry from the overlap tree
			 */
			if (MD_MN_MIRROR_OWNER(un) &&
			    (ps1->ps_flags & MD_MPS_ON_OVERLAP)) {
				mirror_overlap_tree_remove(ps1);
				rs_on_overlap = 0;
			}
		}
	}
	mutex_exit(&un->un_owner_mx);


	/*
	 * following keep write after read from writing to the
	 * source in the case where it all came from one place
	 */
	if (flag & MD_STR_WAR) {
		int	abort_write = 0;
		/*
		 * We are perfoming a write-after-read. This is either as a
		 * result of a resync read or as a result of a read in a
		 * dirty resync region when the optimized resync is not
		 * complete. If in a MN set and a resync generated i/o,
		 * if the current block is not in the current
		 * resync region terminate the write as another node must have
		 * completed this resync region
		 */
		if ((MD_MNSET_SETNO(MD_UN2SET(un))) &&
		    (!(flag & MD_STR_DIRTY_RD))) {
			if (!IN_RESYNC_REGION(un, ps))
				abort_write = 1;
		}
		if ((select_write_after_read_units(un, ps) == 0) ||
		    (abort_write)) {
#ifdef DEBUG
			if (mirror_debug_flag)
				printf("Abort resync write on %x, block %lld\n",
				    MD_SID(un), ps->ps_firstblk);
#endif
			if (ps->ps_flags & MD_MPS_ON_OVERLAP)
				mirror_overlap_tree_remove(ps);
			kmem_cache_free(mirror_parent_cache, ps);
			md_kstat_waitq_exit(ui);
			md_unit_readerexit(ui);
			md_biodone(pb);
			return;
		}
	} else {
		select_write_units(un, ps);

		/* Drop readerlock to avoid deadlock */
		md_unit_readerexit(ui);
		wait_for_overlaps(ps, MD_OVERLAP_NO_REPEAT);
		un = md_unit_readerlock(ui);
		/*
		 * For a MN set with an ABR write, if we are now the
		 * owner and we have a resync region in the overlap
		 * tree, remove the entry from overlaps and retry the write.
		 */

		if (MD_MNSET_SETNO(setno) &&
		    ((ui->ui_tstate & MD_ABR_CAP) || (flag & MD_STR_ABR))) {
			mutex_enter(&un->un_owner_mx);
			if (((MD_MN_MIRROR_OWNER(un))) && rs_on_overlap) {
				mirror_overlap_tree_remove(ps);
				md_kstat_waitq_exit(ui);
				mutex_exit(&un->un_owner_mx);
				md_unit_readerexit(ui);
				daemon_request(&md_mirror_daemon, daemon_io,
				    (daemon_queue_t *)ps, REQ_OLD);
				return;
			}
			mutex_exit(&un->un_owner_mx);
		}
	}

	/*
	 * For Multinode mirrors with no owner and a Resync Region (not ABR)
	 * we need to become the mirror owner before continuing with the
	 * write(). For ABR mirrors we check that we 'own' the resync if
	 * we're in write-after-read mode. We do this _after_ ensuring that
	 * there are no overlaps to ensure that once we know that we are
	 * the owner, the readerlock will not be released until the write is
	 * complete. As a change of ownership in a MN set requires the
	 * writerlock, this ensures that ownership cannot be changed until
	 * the write is complete.
	 */
	if (MD_MNSET_SETNO(setno) && (!((ui->ui_tstate & MD_ABR_CAP) ||
	    (flag & MD_STR_ABR)) || (flag & MD_STR_WAR))) {
		if (MD_MN_NO_MIRROR_OWNER(un))  {
			if (ps->ps_flags & MD_MPS_ON_OVERLAP)
				mirror_overlap_tree_remove(ps);
			md_kstat_waitq_exit(ui);
			ASSERT(!(flag & MD_STR_WAR));
			md_unit_readerexit(ui);
			daemon_request(&md_mirror_daemon, become_owner,
			    (daemon_queue_t *)ps, REQ_OLD);
			return;
		}
	}

	/*
	 * Mark resync region if mirror has a Resync Region _and_ we are not
	 * a resync initiated write(). Don't mark region if we're flagged as
	 * an ABR write.
	 */
	if (!((ui->ui_tstate & MD_ABR_CAP) || (flag & MD_STR_ABR)) &&
	    !(flag & MD_STR_WAR)) {
		if (mirror_mark_resync_region(un, ps->ps_firstblk,
		    ps->ps_lastblk, md_mn_mynode_id)) {
			pb->b_flags |= B_ERROR;
			pb->b_resid = pb->b_bcount;
			if (ps->ps_flags & MD_MPS_ON_OVERLAP)
				mirror_overlap_tree_remove(ps);
			kmem_cache_free(mirror_parent_cache, ps);
			md_kstat_waitq_exit(ui);
			md_unit_readerexit(ui);
			md_biodone(pb);
			return;
		}
	}

	ps->ps_childbflags = pb->b_flags | B_WRITE;
	ps->ps_childbflags &= ~B_READ;
	if (flag & MD_STR_MAPPED)
		ps->ps_childbflags &= ~B_PAGEIO;

	if (!(flag & MD_STR_NOTTOP) && panicstr)
		/* Disable WOW and don't free ps */
		ps->ps_flags |= (MD_MPS_WOW|MD_MPS_DONTFREE);

	md_kstat_waitq_to_runq(ui);

	/*
	 * Treat Raw and Direct I/O as Write-on-Write always
	 */

	if (!(md_mirror_wow_flg & WOW_DISABLE) &&
	    (md_mirror_wow_flg & WOW_PHYS_ENABLE) &&
	    (pb->b_flags & B_PHYS) &&
	    !(ps->ps_flags & MD_MPS_WOW)) {
		if (ps->ps_flags & MD_MPS_ON_OVERLAP)
			mirror_overlap_tree_remove(ps);
		md_unit_readerexit(ui);
		daemon_request(&md_mstr_daemon, handle_wow,
		    (daemon_queue_t *)ps, REQ_OLD);
		return;
	}

	ps->ps_frags = 1;
	do {
		cs = kmem_cache_alloc(mirror_child_cache, MD_ALLOCFLAGS);
		mirror_child_init(cs);
		cb = &cs->cs_buf;
		more = mirror_map_write(un, cs, ps, (flag & MD_STR_WAR));

		/*
		 * This handles the case where we're requesting
		 * a write to block 0 on a label partition.  (more < 0)
		 * means that the request size was smaller than the
		 * size of the label.  If so this request is done.
		 */
		if (more < 0) {
			if (ps->ps_flags & MD_MPS_ON_OVERLAP)
				mirror_overlap_tree_remove(ps);
			md_kstat_runq_exit(ui);
			kmem_cache_free(mirror_child_cache, cs);
			kmem_cache_free(mirror_parent_cache, ps);
			md_unit_readerexit(ui);
			md_biodone(pb);
			return;
		}
		if (more) {
			mutex_enter(&ps->ps_mx);
			ps->ps_frags++;
			mutex_exit(&ps->ps_mx);
		}
		md_call_strategy(cb, flag, private);
	} while (more);

	if (!(flag & MD_STR_NOTTOP) && panicstr) {
		while (!(ps->ps_flags & MD_MPS_DONE)) {
			md_daemon(1, &md_done_daemon);
			drv_usecwait(10);
		}
		kmem_cache_free(mirror_parent_cache, ps);
	}
}

static void
mirror_read_strategy(buf_t *pb, int flag, void *private)
{
	md_mps_t	*ps;
	md_mcs_t	*cs;
	size_t		more;
	mm_unit_t	*un;
	mdi_unit_t	*ui;
	size_t		current_count;
	diskaddr_t	current_blkno;
	off_t		current_offset;
	buf_t		*cb;		/* child buf pointer */
	set_t		setno;

	ui = MDI_UNIT(getminor(pb->b_edev));

	md_kstat_waitq_enter(ui);

	un = (mm_unit_t *)md_unit_readerlock(ui);

	if (!(flag & MD_STR_NOTTOP)) {
		if (md_checkbuf(ui, (md_unit_t *)un, pb)) {
			md_kstat_waitq_exit(ui);
			return;
		}
	}

	if (private == NULL) {
		ps = kmem_cache_alloc(mirror_parent_cache, MD_ALLOCFLAGS);
		mirror_parent_init(ps);
	} else {
		ps = private;
		private = NULL;
	}

	if (flag & MD_STR_MAPPED)
		ps->ps_flags |= MD_MPS_MAPPED;
	if (flag & MD_NOBLOCK)
		ps->ps_flags |= MD_MPS_NOBLOCK;
	if (flag & MD_STR_WMUPDATE)
		ps->ps_flags |= MD_MPS_WMUPDATE;

	/*
	 * Check to see if this is a DMR driven read. If so we need to use the
	 * specified side (in un->un_dmr_last_read) for the source of the data.
	 */
	if (flag & MD_STR_DMR)
		ps->ps_flags |= MD_MPS_DMR;

	/*
	 * Save essential information from the original buffhdr
	 * in the md_save structure.
	 */
	ps->ps_un = un;
	ps->ps_ui = ui;
	ps->ps_bp = pb;
	ps->ps_addr = pb->b_un.b_addr;
	ps->ps_firstblk = pb->b_lblkno;
	ps->ps_lastblk = pb->b_lblkno + lbtodb(pb->b_bcount) - 1;
	ps->ps_changecnt = un->un_changecnt;

	current_count = btodb(pb->b_bcount);
	current_blkno = pb->b_lblkno;
	current_offset = 0;

	/*
	 * If flag has MD_STR_WAR set this means that the read is issued by a
	 * resync thread which may or may not be an optimised resync.
	 *
	 * If MD_UN_OPT_NOT_DONE is set this means that the optimized resync
	 * code has not completed; either a resync has not started since snarf,
	 * or there is an optimized resync in progress.
	 *
	 * We need to generate a write after this read in the following two
	 * cases,
	 *
	 * 1. Any Resync-Generated read
	 *
	 * 2. Any read to a DIRTY REGION if there is an optimized resync
	 *    pending or in progress.
	 *
	 * The write after read is done in these cases to ensure that all sides
	 * of the mirror are in sync with the read data and that it is not
	 * possible for an application to read the same block multiple times
	 * and get different data.
	 *
	 * This would be possible if the block was in a dirty region.
	 *
	 * If we're performing a directed read we don't write the data out as
	 * the application is responsible for restoring the mirror to a known
	 * state.
	 */
	if (((MD_STATUS(un) & MD_UN_OPT_NOT_DONE) || (flag & MD_STR_WAR)) &&
	    !(flag & MD_STR_DMR)) {
		size_t	start_rr, i, end_rr;
		int	region_dirty = 1;

		/*
		 * We enter here under three circumstances,
		 *
		 * MD_UN_OPT_NOT_DONE	MD_STR_WAR
		 * 0			1
		 * 1			0
		 * 1			1
		 *
		 * To be optimal we only care to explicitly check for dirty
		 * regions in the second case since if MD_STR_WAR is set we
		 * always do the write after read.
		 */
		if (!(flag & MD_STR_WAR)) {
			BLK_TO_RR(end_rr, ps->ps_lastblk, un);
			BLK_TO_RR(start_rr, ps->ps_firstblk, un);

			for (i = start_rr; i <= end_rr; i++)
				if ((region_dirty = IS_KEEPDIRTY(i, un)) != 0)
					break;
		}

		if ((region_dirty) &&
		    !(md_get_setstatus(MD_UN2SET(un)) & MD_SET_STALE)) {
			ps->ps_call = write_after_read;
			/*
			 * Mark this as a RESYNC_READ in ps_flags.
			 * This is used if the read fails during a
			 * resync of a 3-way mirror to ensure that
			 * the retried read to the remaining
			 * good submirror has MD_STR_WAR set. This
			 * is needed to ensure that the resync write
			 * (write-after-read) takes place.
			 */
			ps->ps_flags |= MD_MPS_RESYNC_READ;

			/*
			 * If MD_STR_FLAG_ERR is set in the flags we
			 * set MD_MPS_FLAG_ERROR so that an error on the resync
			 * write (issued by write_after_read) will be flagged
			 * to the biowait'ing resync thread. This allows us to
			 * avoid issuing further resync requests to a device
			 * that has had a write failure.
			 */
			if (flag & MD_STR_FLAG_ERR)
				ps->ps_flags |= MD_MPS_FLAG_ERROR;

			setno = MD_UN2SET(un);
			/*
			 * Drop the readerlock to avoid
			 * deadlock
			 */
			md_unit_readerexit(ui);
			wait_for_overlaps(ps, MD_OVERLAP_NO_REPEAT);
			un = md_unit_readerlock(ui);
			/*
			 * Ensure that we are owner
			 */
			if (MD_MNSET_SETNO(setno)) {
				/*
				 * For a non-resync read that requires a
				 * write-after-read to be done, set a flag
				 * in the parent structure, so that the
				 * write_strategy routine can omit the
				 * test that the write is still within the
				 * resync region
				 */
				if (!(flag & MD_STR_WAR))
					ps->ps_flags |= MD_MPS_DIRTY_RD;

				/*
				 * Before reading the buffer, see if
				 * there is an owner.
				 */
				if (MD_MN_NO_MIRROR_OWNER(un))  {
					ps->ps_call = NULL;
					mirror_overlap_tree_remove(ps);
					md_kstat_waitq_exit(ui);
					md_unit_readerexit(ui);
					daemon_request(
					    &md_mirror_daemon,
					    become_owner,
					    (daemon_queue_t *)ps,
					    REQ_OLD);
					return;
				}
				/*
				 * For a resync read, check to see if I/O is
				 * outside of the current resync region, or
				 * the resync has finished. If so
				 * just terminate the I/O
				 */
				if ((flag & MD_STR_WAR) &&
				    (!(un->c.un_status & MD_UN_WAR) ||
				    (!IN_RESYNC_REGION(un, ps)))) {
#ifdef DEBUG
					if (mirror_debug_flag)
						printf("Abort resync read "
						    "%x: %lld\n",
						    MD_SID(un),
						    ps->ps_firstblk);
#endif
					mirror_overlap_tree_remove(ps);
					kmem_cache_free(mirror_parent_cache,
					    ps);
					md_kstat_waitq_exit(ui);
					md_unit_readerexit(ui);
					md_biodone(pb);
					return;
				}
			}
		}
	}

	if (flag & MD_STR_DMR) {
		ps->ps_call = directed_read_done;
	}

	if (!(flag & MD_STR_NOTTOP) && panicstr)
		ps->ps_flags |= MD_MPS_DONTFREE;

	md_kstat_waitq_to_runq(ui);

	ps->ps_frags++;
	do {
		cs = kmem_cache_alloc(mirror_child_cache, MD_ALLOCFLAGS);
		mirror_child_init(cs);
		cb = &cs->cs_buf;
		cs->cs_ps = ps;

		cb = md_bioclone(pb, current_offset, current_count, NODEV,
		    current_blkno, mirror_done, cb, KM_NOSLEEP);

		more = mirror_map_read(ps, cs, current_blkno,
		    (u_longlong_t)current_count);
		if (more) {
			mutex_enter(&ps->ps_mx);
			ps->ps_frags++;
			mutex_exit(&ps->ps_mx);
		}

		/*
		 * Do these calculations now,
		 *  so that we pickup a valid b_bcount from the chld_bp.
		 */
		current_count -= more;
		current_offset += cb->b_bcount;
		current_blkno +=  more;
		md_call_strategy(cb, flag, private);
	} while (more);

	if (!(flag & MD_STR_NOTTOP) && panicstr) {
		while (!(ps->ps_flags & MD_MPS_DONE)) {
			md_daemon(1, &md_done_daemon);
			drv_usecwait(10);
		}
		kmem_cache_free(mirror_parent_cache, ps);
	}
}

void
md_mirror_strategy(buf_t *bp, int flag, void *private)
{
	set_t	setno = MD_MIN2SET(getminor(bp->b_edev));

	/*
	 * When doing IO to a multi owner meta device, check if set is halted.
	 * We do this check without the needed lock held, for performance
	 * reasons.
	 * If an IO just slips through while the set is locked via an
	 * MD_MN_SUSPEND_SET, we don't care about it.
	 * Only check for suspension if we are a top-level i/o request
	 * (MD_STR_NOTTOP is cleared in 'flag').
	 */
	if ((md_set[setno].s_status & (MD_SET_HALTED | MD_SET_MNSET)) ==
	    (MD_SET_HALTED | MD_SET_MNSET)) {
		if ((flag & MD_STR_NOTTOP) == 0) {
			mutex_enter(&md_mx);
			/* Here we loop until the set is no longer halted */
			while (md_set[setno].s_status & MD_SET_HALTED) {
				cv_wait(&md_cv, &md_mx);
			}
			mutex_exit(&md_mx);
		}
	}

	if ((flag & MD_IO_COUNTED) == 0) {
		if ((flag & MD_NOBLOCK) == 0) {
			if (md_inc_iocount(setno) != 0) {
				bp->b_flags |= B_ERROR;
				bp->b_error = ENXIO;
				bp->b_resid = bp->b_bcount;
				biodone(bp);
				return;
			}
		} else {
			md_inc_iocount_noblock(setno);
		}
	}

	if (bp->b_flags & B_READ)
		mirror_read_strategy(bp, flag, private);
	else
		mirror_write_strategy(bp, flag, private);
}

/*
 * mirror_directed_read:
 * --------------------
 * Entry-point for the DKIOCDMR ioctl. We issue a read to a specified sub-mirror
 * so that the application can determine what (if any) resync needs to be
 * performed. The data is copied out to the user-supplied buffer.
 *
 * Parameters:
 *	mdev	- dev_t for the mirror device
 *	vdr	- directed read parameters specifying location and submirror
 *		  to perform the read from
 *	mode	- used to ddi_copyout() any resulting data from the read
 *
 * Returns:
 *	0	success
 *	!0	error code
 *		EINVAL - invalid request format
 */
int
mirror_directed_read(dev_t mdev, vol_directed_rd_t *vdr, int mode)
{
	buf_t		*bp;
	minor_t		mnum = getminor(mdev);
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	mm_unit_t	*un;
	mm_submirror_t	*sm;
	char		*sm_nm;
	uint_t		next_side;
	void		*kbuffer;

	if (ui == NULL)
		return (ENXIO);

	if (!(vdr->vdr_flags & DKV_DMR_NEXT_SIDE)) {
		return (EINVAL);
	}

	/* Check for aligned block access. We disallow non-aligned requests. */
	if (vdr->vdr_offset % DEV_BSIZE) {
		return (EINVAL);
	}

	/*
	 * Allocate kernel buffer for target of read(). If we had a reliable
	 * (sorry functional) DDI this wouldn't be needed.
	 */
	kbuffer = kmem_alloc(vdr->vdr_nbytes, KM_NOSLEEP);
	if (kbuffer == NULL) {
		cmn_err(CE_WARN, "mirror_directed_read: couldn't allocate %lx"
		    " bytes\n", vdr->vdr_nbytes);
		return (ENOMEM);
	}

	bp = getrbuf(KM_SLEEP);

	bp->b_un.b_addr = kbuffer;
	bp->b_flags = B_READ;
	bp->b_bcount = vdr->vdr_nbytes;
	bp->b_lblkno = lbtodb(vdr->vdr_offset);
	bp->b_edev = mdev;

	un = md_unit_readerlock(ui);

	/*
	 * If DKV_SIDE_INIT is set we need to determine the first available
	 * side to start reading from. If it isn't set we increment to the
	 * next readable submirror.
	 * If there are no readable submirrors we error out with DKV_DMR_ERROR.
	 * Note: we check for a readable submirror on completion of the i/o so
	 * we should _always_ have one available. If this becomes unavailable
	 * we have missed the 'DKV_DMR_DONE' opportunity. This could happen if
	 * a metadetach is made between the completion of one DKIOCDMR ioctl
	 * and the start of the next (i.e. a sys-admin 'accident' occurred).
	 * The chance of this is small, but not non-existent.
	 */
	if (vdr->vdr_side == DKV_SIDE_INIT) {
		next_side = 0;
	} else {
		next_side = vdr->vdr_side + 1;
	}
	while ((next_side < NMIRROR) &&
	    !SUBMIRROR_IS_READABLE(un, next_side))
		next_side++;
	if (next_side >= NMIRROR) {
		vdr->vdr_flags |= DKV_DMR_ERROR;
		freerbuf(bp);
		vdr->vdr_bytesread = 0;
		md_unit_readerexit(ui);
		return (0);
	}

	/* Set the side to read from */
	un->un_dmr_last_read = next_side;

	md_unit_readerexit(ui);

	/*
	 * Save timestamp for verification purposes. Can be read by debugger
	 * to verify that this ioctl has been executed and to find the number
	 * of DMR reads and the time of the last DMR read.
	 */
	uniqtime(&mirror_dmr_stats.dmr_timestamp);
	mirror_dmr_stats.dmr_count++;

	/* Issue READ request and wait for completion */
	mirror_read_strategy(bp, MD_STR_DMR|MD_NOBLOCK|MD_STR_NOTTOP, NULL);

	mutex_enter(&un->un_dmr_mx);
	cv_wait(&un->un_dmr_cv, &un->un_dmr_mx);
	mutex_exit(&un->un_dmr_mx);

	/*
	 * Check to see if we encountered an error during the read. If so we
	 * can make no guarantee about any possibly returned data.
	 */
	if ((bp->b_flags & B_ERROR) == 0) {
		vdr->vdr_flags &= ~DKV_DMR_ERROR;
		if (bp->b_resid) {
			vdr->vdr_flags |= DKV_DMR_SHORT;
			vdr->vdr_bytesread = vdr->vdr_nbytes - bp->b_resid;
		} else {
			vdr->vdr_flags |= DKV_DMR_SUCCESS;
			vdr->vdr_bytesread = vdr->vdr_nbytes;
		}
		/* Copy the data read back out to the user supplied buffer */
		if (ddi_copyout(kbuffer, vdr->vdr_data, vdr->vdr_bytesread,
		    mode)) {
			kmem_free(kbuffer, vdr->vdr_nbytes);
			return (EFAULT);
		}

	} else {
		/* Error out with DKV_DMR_ERROR */
		vdr->vdr_flags |= DKV_DMR_ERROR;
		vdr->vdr_flags &= ~(DKV_DMR_SUCCESS|DKV_DMR_SHORT|DKV_DMR_DONE);
	}
	/*
	 * Update the DMR parameters with the side and name of submirror that
	 * we have just read from (un->un_dmr_last_read)
	 */
	un = md_unit_readerlock(ui);

	vdr->vdr_side = un->un_dmr_last_read;
	sm = &un->un_sm[un->un_dmr_last_read];
	sm_nm = md_shortname(md_getminor(sm->sm_dev));

	(void) strncpy(vdr->vdr_side_name, sm_nm, sizeof (vdr->vdr_side_name));

	/*
	 * Determine if we've completed the read cycle. This is true iff the
	 * next computed submirror (side) equals or exceeds NMIRROR. We cannot
	 * use un_nsm as we need to handle a sparse array of submirrors (which
	 * can occur if a submirror is metadetached).
	 */
	next_side = un->un_dmr_last_read + 1;
	while ((next_side < NMIRROR) &&
	    !SUBMIRROR_IS_READABLE(un, next_side))
		next_side++;
	if (next_side >= NMIRROR) {
		/* We've finished */
		vdr->vdr_flags |= DKV_DMR_DONE;
	}

	md_unit_readerexit(ui);
	freerbuf(bp);
	kmem_free(kbuffer, vdr->vdr_nbytes);

	return (0);
}

/*
 * mirror_resync_message:
 * ---------------------
 * Handle the multi-node resync messages that keep all nodes within a given
 * disk-set in sync with their view of a mirror's resync status.
 *
 * The message types dealt with are:
 * MD_MN_MSG_RESYNC_STARTING	- start a resync thread for a unit
 * MD_MN_MSG_RESYNC_NEXT	- specified next region to be resynced
 * MD_MN_MSG_RESYNC_FINISH	- stop the resync thread for a unit
 * MD_MN_MSG_RESYNC_PHASE_DONE	- end of a resync phase, opt, submirror or comp
 *
 * Returns:
 *	0	Success
 *	>0	Failure error number
 */
int
mirror_resync_message(md_mn_rs_params_t *p, IOLOCK *lockp)
{
	mdi_unit_t		*ui;
	mm_unit_t		*un;
	set_t			setno;
	int			is_ABR;
	int			smi;
	int			ci;
	sm_state_t		state;
	int			broke_out;
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	md_m_shared_t		*shared;
	md_error_t		mde = mdnullerror;
	md_mps_t		*ps;
	int			rs_active;
	int			rr, rr_start, rr_end;

	/* Check that the given device is part of a multi-node set */
	setno = MD_MIN2SET(p->mnum);
	if (setno >= md_nsets) {
		return (ENXIO);
	}
	if (!MD_MNSET_SETNO(setno)) {
		return (EINVAL);
	}

	if ((un = mirror_getun(p->mnum, &p->mde, NO_LOCK, NULL)) == NULL)
		return (EINVAL);
	if ((ui = MDI_UNIT(p->mnum)) == NULL)
		return (EINVAL);
	is_ABR = (ui->ui_tstate & MD_ABR_CAP);

	/* Obtain the current resync status */
	(void) md_ioctl_readerlock(lockp, ui);
	rs_active = (MD_STATUS(un) & MD_UN_RESYNC_ACTIVE) ? 1 : 0;
	md_ioctl_readerexit(lockp);

	switch ((md_mn_msgtype_t)p->msg_type) {
	case MD_MN_MSG_RESYNC_STARTING:
		/* Start the resync thread for the mirror */
		(void) mirror_resync_unit(p->mnum, NULL, &p->mde, lockp);
		break;

	case MD_MN_MSG_RESYNC_NEXT:
		/*
		 * We have to release any previously marked overlap regions
		 * so that i/o can resume. Then we need to block the region
		 * from [rs_start..rs_start+rs_size) * so that no i/o is issued.
		 * Update un_rs_resync_done and un_rs_resync_2_do.
		 */
		(void) md_ioctl_readerlock(lockp, ui);
		/*
		 * Ignore the message if there is no active resync thread or
		 * if it is for a resync type that we have already completed.
		 * un_resync_completed is set to the last resync completed
		 * when processing a PHASE_DONE message.
		 */
		if (!rs_active || (p->rs_type == un->un_resync_completed))
			break;
		/*
		 * If this message is for the same resync and is for an earlier
		 * resync region, just ignore it. This can only occur if this
		 * node has progressed on to the next resync region before
		 * we receive this message. This can occur if the class for
		 * this message is busy and the originator has to retry thus
		 * allowing this node to move onto the next resync_region.
		 */
		if ((p->rs_type == un->un_rs_type) &&
		    (p->rs_start < un->un_resync_startbl))
			break;
		ps = un->un_rs_prev_overlap;

		/* Allocate previous overlap reference if needed */
		if (ps == NULL) {
			ps = kmem_cache_alloc(mirror_parent_cache,
			    MD_ALLOCFLAGS);
			ps->ps_un = un;
			ps->ps_ui = ui;
			ps->ps_firstblk = 0;
			ps->ps_lastblk = 0;
			ps->ps_flags = 0;
			md_ioctl_readerexit(lockp);
			(void) md_ioctl_writerlock(lockp, ui);
			un->un_rs_prev_overlap = ps;
			md_ioctl_writerexit(lockp);
		} else
			md_ioctl_readerexit(lockp);

		if (p->rs_originator != md_mn_mynode_id) {
			/*
			 * Clear our un_resync_bm for the regions completed.
			 * The owner (originator) will take care of itself.
			 */
			BLK_TO_RR(rr_end, ps->ps_lastblk, un);
			BLK_TO_RR(rr_start, p->rs_start, un);
			if (ps->ps_lastblk && rr_end < rr_start) {
				BLK_TO_RR(rr_start, ps->ps_firstblk, un);
				mutex_enter(&un->un_resync_mx);
				/*
				 * Update our resync bitmap to reflect that
				 * another node has synchronized this range.
				 */
				for (rr = rr_start; rr <= rr_end; rr++) {
					CLR_KEEPDIRTY(rr, un);
				}
				mutex_exit(&un->un_resync_mx);
			}

			/*
			 * On all but the originating node, first update
			 * the resync state, then unblock the previous
			 * region and block the next one. No need
			 * to do this if the region is already blocked.
			 * Update the submirror state and flags from the
			 * originator. This keeps the cluster in sync with
			 * regards to the resync status.
			 */

			(void) md_ioctl_writerlock(lockp, ui);
			un->un_rs_resync_done = p->rs_done;
			un->un_rs_resync_2_do = p->rs_2_do;
			un->un_rs_type = p->rs_type;
			un->un_resync_startbl = p->rs_start;
			md_ioctl_writerexit(lockp);
			/*
			 * Use un_owner_mx to ensure that an ownership change
			 * cannot happen at the same time as this message
			 */
			mutex_enter(&un->un_owner_mx);
			if (MD_MN_MIRROR_OWNER(un)) {
				ps->ps_firstblk = p->rs_start;
				ps->ps_lastblk = ps->ps_firstblk +
				    p->rs_size - 1;
			} else {
				if ((ps->ps_firstblk != p->rs_start) ||
				    (ps->ps_lastblk != p->rs_start +
				    p->rs_size - 1)) {
					/* Remove previous overlap range */
					if (ps->ps_flags & MD_MPS_ON_OVERLAP)
						mirror_overlap_tree_remove(ps);

					ps->ps_firstblk = p->rs_start;
					ps->ps_lastblk = ps->ps_firstblk +
					    p->rs_size - 1;

					mutex_exit(&un->un_owner_mx);
					/* Block this range from all i/o. */
					if (ps->ps_firstblk != 0 ||
					    ps->ps_lastblk != 0)
						wait_for_overlaps(ps,
						    MD_OVERLAP_ALLOW_REPEAT);
					mutex_enter(&un->un_owner_mx);
					/*
					 * Check to see if we have obtained
					 * ownership while waiting for
					 * overlaps. If we have, remove
					 * the resync_region entry from the
					 * overlap tree
					 */
					if (MD_MN_MIRROR_OWNER(un) &&
					    (ps->ps_flags & MD_MPS_ON_OVERLAP))
						mirror_overlap_tree_remove(ps);
				}
			}
			mutex_exit(&un->un_owner_mx);

			/*
			 * If this is the first RESYNC_NEXT message (i.e.
			 * MD_MN_RS_FIRST_RESYNC_NEXT set in p->rs_flags),
			 * issue RESYNC_START NOTIFY event
			 */
			if (p->rs_flags & MD_MN_RS_FIRST_RESYNC_NEXT) {
				SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_START,
				    SVM_TAG_METADEVICE, MD_UN2SET(un),
				    MD_SID(un));
			}

			/* Ensure that our local resync thread is running */
			if (un->un_rs_thread == NULL) {
				(void) mirror_resync_unit(p->mnum, NULL,
				    &p->mde, lockp);
			}
		}

		break;
	case MD_MN_MSG_RESYNC_FINISH:
		/*
		 * Complete the resync by stopping the resync thread.
		 * Also release the previous overlap region field.
		 * Update the resync_progress_thread by cv_signal'ing it so
		 * that we mark the end of the resync as soon as possible. This
		 * stops an unnecessary delay should be panic after resync
		 * completion.
		 */
#ifdef DEBUG
		if (!rs_active) {
			if (mirror_debug_flag)
				printf("RESYNC_FINISH (mnum = %x), "
				    "Resync *NOT* active",
				    p->mnum);
		}
#endif

		if ((un->c.un_status & MD_UN_RESYNC_ACTIVE) &&
		    (p->rs_originator != md_mn_mynode_id)) {
			mutex_enter(&un->un_rs_thread_mx);
			un->c.un_status &= ~MD_UN_RESYNC_CANCEL;
			un->un_rs_thread_flags |= MD_RI_SHUTDOWN;
			un->un_rs_thread_flags &=
			    ~(MD_RI_BLOCK|MD_RI_BLOCK_OWNER);
			cv_signal(&un->un_rs_thread_cv);
			mutex_exit(&un->un_rs_thread_mx);
		}
		if (is_ABR) {
			/* Resync finished, if ABR set owner to NULL */
			mutex_enter(&un->un_owner_mx);
			un->un_mirror_owner = 0;
			mutex_exit(&un->un_owner_mx);
		}
		(void) md_ioctl_writerlock(lockp, ui);
		ps = un->un_rs_prev_overlap;
		if (ps != NULL) {
			/* Remove previous overlap range */
			if (ps->ps_flags & MD_MPS_ON_OVERLAP)
				mirror_overlap_tree_remove(ps);
			/*
			 * Release the overlap range reference
			 */
			un->un_rs_prev_overlap = NULL;
			kmem_cache_free(mirror_parent_cache,
			    ps);
		}
		md_ioctl_writerexit(lockp);

		/* Mark the resync as complete in the metadb */
		un->un_rs_resync_done = p->rs_done;
		un->un_rs_resync_2_do = p->rs_2_do;
		un->un_rs_type = p->rs_type;
		mutex_enter(&un->un_rs_progress_mx);
		cv_signal(&un->un_rs_progress_cv);
		mutex_exit(&un->un_rs_progress_mx);

		un = md_ioctl_writerlock(lockp, ui);
		un->c.un_status &= ~MD_UN_RESYNC_ACTIVE;
		/* Deal with any pending grow_unit */
		if (un->c.un_status & MD_UN_GROW_PENDING) {
			if ((mirror_grow_unit(un, &mde) != 0) ||
			    (! mdismderror(&mde, MDE_GROW_DELAYED))) {
				un->c.un_status &= ~MD_UN_GROW_PENDING;
			}
		}
		md_ioctl_writerexit(lockp);
		break;

	case MD_MN_MSG_RESYNC_PHASE_DONE:
		/*
		 * A phase of the resync, optimized. component or
		 * submirror is complete. Update mirror status.
		 * If the flag CLEAR_OPT_NOT_DONE is set, it means that the
		 * mirror owner is peforming a resync. If we have just snarfed
		 * this set, then we must clear any of the flags set at snarf
		 * time by unit_setup_resync().
		 * Note that unit_setup_resync() sets up these flags to
		 * indicate that an optimized resync is required. These flags
		 * need to be reset because if we get here,  the mirror owner
		 * will have handled the optimized resync.
		 * The flags that must be cleared are MD_UN_OPT_NOT_DONE and
		 * MD_UN_WAR. In addition, for each submirror,
		 * MD_SM_RESYNC_TARGET must be cleared and SMS_OFFLINE_RESYNC
		 * set to SMS_OFFLINE.
		 */
#ifdef DEBUG
		if (mirror_debug_flag)
			printf("phase done mess received from %d, mnum=%x,"
			    "type=%x, flags=%x\n", p->rs_originator, p->mnum,
			    p->rs_type, p->rs_flags);
#endif
		/*
		 * Ignore the message if there is no active resync thread.
		 */
		if (!rs_active)
			break;

		broke_out = p->rs_flags & MD_MN_RS_ERR;
		switch (RS_TYPE(p->rs_type)) {
		case MD_RS_OPTIMIZED:
			un = md_ioctl_writerlock(lockp, ui);
			if (p->rs_flags & MD_MN_RS_CLEAR_OPT_NOT_DONE) {
				/* If we are originator, just clear rs_type */
				if (p->rs_originator == md_mn_mynode_id) {
					SET_RS_TYPE_NONE(un->un_rs_type);
					md_ioctl_writerexit(lockp);
					break;
				}
				/*
				 * If CLEAR_OPT_NOT_DONE is set, only clear the
				 * flags if OPT_NOT_DONE is set *and* rs_type
				 * is MD_RS_NONE.
				 */
				if ((un->c.un_status & MD_UN_OPT_NOT_DONE) &&
				    (RS_TYPE(un->un_rs_type) == MD_RS_NONE)) {
					/* No resync in progress */
					un->c.un_status &= ~MD_UN_OPT_NOT_DONE;
					un->c.un_status &= ~MD_UN_WAR;
				} else {
					/*
					 * We are in the middle of an
					 * optimized resync and this message
					 * should be ignored.
					 */
					md_ioctl_writerexit(lockp);
					break;
				}
			} else {
				/*
				 * This is the end of an optimized resync,
				 * clear the OPT_NOT_DONE and OFFLINE_SM flags
				 */

				un->c.un_status &= ~MD_UN_KEEP_DIRTY;
				if (!broke_out)
					un->c.un_status &= ~MD_UN_WAR;

				/*
				 * Clear our un_resync_bm for the regions
				 * completed.  The owner (originator) will
				 * take care of itself.
				 */
				if (p->rs_originator != md_mn_mynode_id &&
				    (ps = un->un_rs_prev_overlap) != NULL) {
					BLK_TO_RR(rr_start, ps->ps_firstblk,
					    un);
					BLK_TO_RR(rr_end, ps->ps_lastblk, un);
					mutex_enter(&un->un_resync_mx);
					for (rr = rr_start; rr <= rr_end;
					    rr++) {
						CLR_KEEPDIRTY(rr, un);
					}
					mutex_exit(&un->un_resync_mx);
				}
			}

			/*
			 * Set resync_completed to last resync type and then
			 * clear resync_type to indicate no resync in progress
			 */
			un->un_resync_completed = un->un_rs_type;
			SET_RS_TYPE_NONE(un->un_rs_type);

			/*
			 * If resync is as a result of a submirror ONLINE,
			 * reset the submirror state to SMS_RUNNING if the
			 * resync was ok else set back to SMS_OFFLINE.
			 */
			for (smi = 0; smi < NMIRROR; smi++) {
				un->un_sm[smi].sm_flags &=
				    ~MD_SM_RESYNC_TARGET;
				if (SMS_BY_INDEX_IS(un, smi,
				    SMS_OFFLINE_RESYNC)) {
					if (p->rs_flags &
					    MD_MN_RS_CLEAR_OPT_NOT_DONE) {
						state = SMS_OFFLINE;
					} else {
						state = (broke_out ?
						    SMS_OFFLINE : SMS_RUNNING);
					}
					mirror_set_sm_state(
					    &un->un_sm[smi],
					    &un->un_smic[smi], state,
					    broke_out);
					mirror_commit(un, NO_SUBMIRRORS,
					    0);
				}
				/*
				 * If we still have an offline submirror, reset
				 * the OFFLINE_SM flag in the mirror status
				 */
				if (SMS_BY_INDEX_IS(un, smi,
				    SMS_OFFLINE))
					un->c.un_status |=
					    MD_UN_OFFLINE_SM;
			}
			md_ioctl_writerexit(lockp);
			break;
		case MD_RS_SUBMIRROR:
			un = md_ioctl_writerlock(lockp, ui);
			smi = RS_SMI(p->rs_type);
			sm = &un->un_sm[smi];
			smic = &un->un_smic[smi];
			/* Clear RESYNC target */
			un->un_sm[smi].sm_flags &= ~MD_SM_RESYNC_TARGET;
			/*
			 * Set resync_completed to last resync type and then
			 * clear resync_type to indicate no resync in progress
			 */
			un->un_resync_completed = un->un_rs_type;
			SET_RS_TYPE_NONE(un->un_rs_type);
			/*
			 * If the resync completed ok reset the submirror
			 * state to SMS_RUNNING else reset it to SMS_ATTACHED
			 */
			state = (broke_out ?
			    SMS_ATTACHED : SMS_RUNNING);
			mirror_set_sm_state(sm, smic, state, broke_out);
			un->c.un_status &= ~MD_UN_WAR;
			mirror_commit(un, SMI2BIT(smi), 0);
			md_ioctl_writerexit(lockp);
			break;
		case MD_RS_COMPONENT:
			un = md_ioctl_writerlock(lockp, ui);
			smi = RS_SMI(p->rs_type);
			ci = RS_CI(p->rs_type);
			sm = &un->un_sm[smi];
			smic = &un->un_smic[smi];
			shared = (md_m_shared_t *)
			    (*(smic->sm_shared_by_indx))
			    (sm->sm_dev, sm, ci);
			un->c.un_status &= ~MD_UN_WAR;
			/* Clear RESYNC target */
			un->un_sm[smi].sm_flags &= ~MD_SM_RESYNC_TARGET;
			/*
			 * Set resync_completed to last resync type and then
			 * clear resync_type to indicate no resync in progress
			 */
			un->un_resync_completed = un->un_rs_type;
			SET_RS_TYPE_NONE(un->un_rs_type);

			/*
			 * If the resync completed ok, set the component state
			 * to CS_OKAY.
			 */
			if (broke_out)
				shared->ms_flags |= MDM_S_RS_TRIED;
			else {
				/*
				 * As we don't transmit the changes,
				 * no need to drop the lock.
				 */
				set_sm_comp_state(un, smi, ci, CS_OKAY, 0,
				    MD_STATE_NO_XMIT, (IOLOCK *)NULL);
			}
			md_ioctl_writerexit(lockp);
		default:
			break;
		}
		/*
		 * If the purpose of this PHASE_DONE message is just to
		 * indicate to all other nodes that the optimized resync
		 * required (OPT_NOT_DONE) flag is to be cleared, there is
		 * no need to generate a notify event as there has not
		 * actually been a resync.
		 */
		if (!(p->rs_flags & MD_MN_RS_CLEAR_OPT_NOT_DONE)) {
			if (broke_out) {
				SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_FAILED,
				    SVM_TAG_METADEVICE, MD_UN2SET(un),
				    MD_SID(un));
			} else {
				SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_DONE,
				    SVM_TAG_METADEVICE, MD_UN2SET(un),
				    MD_SID(un));
			}
		}
		break;

	default:
#ifdef DEBUG
		cmn_err(CE_PANIC, "mirror_resync_message: Unknown message type"
		    " %x\n", p->msg_type);
#endif
		return (EINVAL);
	}
	return (0);
}

/* Return a -1 if snarf of optimized record failed and set should be released */
static int
mirror_snarf(md_snarfcmd_t cmd, set_t setno)
{
	mddb_recid_t	recid;
	int		gotsomething;
	int		all_mirrors_gotten;
	mm_unit_t	*un;
	mddb_type_t	typ1;
	mddb_de_ic_t    *dep;
	mddb_rb32_t	*rbp;
	size_t		newreqsize;
	mm_unit_t	*big_un;
	mm_unit32_od_t	*small_un;
	int		retval;
	mdi_unit_t	*ui;

	if (cmd == MD_SNARF_CLEANUP) {
		if (md_get_setstatus(setno) & MD_SET_STALE)
			return (0);

		recid = mddb_makerecid(setno, 0);
		typ1 = (mddb_type_t)md_getshared_key(setno,
		    mirror_md_ops.md_driver.md_drivername);
		while ((recid = mddb_getnextrec(recid, typ1, MIRROR_REC)) > 0) {
			if (mddb_getrecprivate(recid) & MD_PRV_CLEANUP) {
				un = (mm_unit_t *)mddb_getrecaddr(recid);
				mirror_cleanup(un);
				recid = mddb_makerecid(setno, 0);
			}
		}
		return (0);
	}

	all_mirrors_gotten = 1;
	gotsomething = 0;

	recid = mddb_makerecid(setno, 0);
	typ1 = (mddb_type_t)md_getshared_key(setno,
	    mirror_md_ops.md_driver.md_drivername);

	while ((recid = mddb_getnextrec(recid, typ1, MIRROR_REC)) > 0) {
		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;

		dep = mddb_getrecdep(recid);
		dep->de_flags = MDDB_F_MIRROR;
		rbp = dep->de_rb;

		switch (rbp->rb_revision) {
		case MDDB_REV_RB:
		case MDDB_REV_RBFN:
			if ((rbp->rb_private & MD_PRV_CONVD) == 0) {
				/*
				 * This means, we have an old and small
				 * record and this record hasn't already
				 * been converted.  Before we create an
				 * incore metadevice from this we have to
				 * convert it to a big record.
				 */
				small_un =
				    (mm_unit32_od_t *)mddb_getrecaddr(recid);
				newreqsize = sizeof (mm_unit_t);
				big_un = (mm_unit_t *)kmem_zalloc(newreqsize,
				    KM_SLEEP);
				mirror_convert((caddr_t)small_un,
				    (caddr_t)big_un, SMALL_2_BIG);
				kmem_free(small_un, dep->de_reqsize);

				/*
				 * Update userdata and incore userdata
				 * incores are at the end of un
				 */
				dep->de_rb_userdata_ic = big_un;
				dep->de_rb_userdata = big_un;
				dep->de_icreqsize = newreqsize;
				un = big_un;
				rbp->rb_private |= MD_PRV_CONVD;
			} else {
				/*
				 * Unit already converted, just get the
				 * record address.
				 */
				un = (mm_unit_t *)mddb_getrecaddr_resize(recid,
				    sizeof (*un), 0);
			}
			un->c.un_revision &= ~MD_64BIT_META_DEV;
			break;
		case MDDB_REV_RB64:
		case MDDB_REV_RB64FN:
			/* Big device */
			un = (mm_unit_t *)mddb_getrecaddr_resize(recid,
			    sizeof (*un), 0);
			un->c.un_revision |= MD_64BIT_META_DEV;
			un->c.un_flag |= MD_EFILABEL;
			break;
		}
		MDDB_NOTE_FN(rbp->rb_revision, un->c.un_revision);

		/*
		 * Create minor device node for snarfed entry.
		 */
		(void) md_create_minor_node(setno, MD_SID(un));

		if (MD_UNIT(MD_SID(un)) != NULL) {
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);
			continue;
		}
		all_mirrors_gotten = 0;
		retval = mirror_build_incore(un, 1);
		if (retval == 0) {
			mddb_setrecprivate(recid, MD_PRV_GOTIT);
			md_create_unit_incore(MD_SID(un), &mirror_md_ops, 0);
			resync_start_timeout(setno);
			gotsomething = 1;
		} else {
			return (retval);
		}
		/*
		 * Set flag to indicate that the mirror has not yet
		 * been through a reconfig. This flag is used for MN sets
		 * when determining whether to update the mirror state from
		 * the Master node.
		 */
		if (MD_MNSET_SETNO(setno)) {
			ui = MDI_UNIT(MD_SID(un));
			ui->ui_tstate |= MD_RESYNC_NOT_DONE;
		}
	}

	if (!all_mirrors_gotten)
		return (gotsomething);

	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, typ1, RESYNC_REC)) > 0)
		if (!(mddb_getrecprivate(recid) & MD_PRV_GOTIT))
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);

	return (0);
}

static int
mirror_halt(md_haltcmd_t cmd, set_t setno)
{
	unit_t		i;
	mdi_unit_t	*ui;
	minor_t		mnum;
	int		reset_mirror_flag = 0;

	if (cmd == MD_HALT_CLOSE)
		return (0);

	if (cmd == MD_HALT_OPEN)
		return (0);

	if (cmd == MD_HALT_UNLOAD)
		return (0);

	if (cmd == MD_HALT_CHECK) {
		for (i = 0; i < md_nunits; i++) {
			mnum = MD_MKMIN(setno, i);
			if ((ui = MDI_UNIT(mnum)) == NULL)
				continue;
			if (ui->ui_opsindex != mirror_md_ops.md_selfindex)
				continue;
			if (md_unit_isopen(ui))
				return (1);
		}
		return (0);
	}

	if (cmd != MD_HALT_DOIT)
		return (1);

	for (i = 0; i < md_nunits; i++) {
		mnum = MD_MKMIN(setno, i);
		if ((ui = MDI_UNIT(mnum)) == NULL)
			continue;
		if (ui->ui_opsindex != mirror_md_ops.md_selfindex)
			continue;
		reset_mirror((mm_unit_t *)MD_UNIT(mnum), mnum, 0);

		/* Set a flag if there is at least one mirror metadevice. */
		reset_mirror_flag = 1;
	}

	/*
	 * Only wait for the global dr_timeout to finish
	 *  - if there are mirror metadevices in this diskset or
	 *  - if this is the local set since an unload of the md_mirror
	 *    driver could follow a successful mirror halt in the local set.
	 */
	if ((reset_mirror_flag != 0) || (setno == MD_LOCAL_SET)) {
		while ((mirror_md_ops.md_head == NULL) &&
		    (mirror_timeout.dr_timeout_id != 0))
			delay(md_hz);
	}

	return (0);
}

/*ARGSUSED3*/
static int
mirror_open(dev_t *dev, int flag, int otyp, cred_t *cred_p, int md_oflags)
{
	IOLOCK	lock;
	minor_t		mnum = getminor(*dev);
	set_t		setno;

	/*
	 * When doing an open of a multi owner metadevice, check to see if this
	 * node is a starting node and if a reconfig cycle is underway.
	 * If so, the system isn't sufficiently set up enough to handle the
	 * open (which involves I/O during sp_validate), so fail with ENXIO.
	 */
	setno = MD_MIN2SET(mnum);
	if ((md_set[setno].s_status & (MD_SET_MNSET | MD_SET_MN_START_RC)) ==
	    (MD_SET_MNSET | MD_SET_MN_START_RC)) {
			return (ENXIO);
	}

	if (md_oflags & MD_OFLG_FROMIOCTL) {
		/*
		 * This indicates that the caller is an ioctl service routine.
		 * In this case we initialise our stack-based IOLOCK and pass
		 * this into the internal open routine. This allows multi-owner
		 * metadevices to avoid deadlocking if an error is encountered
		 * during the open() attempt. The failure case is:
		 * s-p -> mirror -> s-p (with error). Attempting to metaclear
		 * this configuration would deadlock as the mirror code has to
		 * send a state-update to the other nodes when it detects the
		 * failure of the underlying submirror with an errored soft-part
		 * on it. As there is a class1 message in progress (metaclear)
		 * set_sm_comp_state() cannot send another class1 message;
		 * instead we do not send a state_update message as the
		 * metaclear is distributed and the failed submirror will be
		 * cleared from the configuration by the metaclear.
		 */
		IOLOCK_INIT(&lock);
		return (mirror_internal_open(getminor(*dev), flag, otyp,
		    md_oflags, &lock));
	} else {
		return (mirror_internal_open(getminor(*dev), flag, otyp,
		    md_oflags, (IOLOCK *)NULL));
	}
}


/*ARGSUSED1*/
static int
mirror_close(dev_t dev, int flag, int otyp, cred_t *cred_p, int md_cflags)
{
	return (mirror_internal_close(getminor(dev), otyp, md_cflags,
	    (IOLOCK *)NULL));
}


/*
 * This routine dumps memory to the disk.  It assumes that the memory has
 * already been mapped into mainbus space.  It is called at disk interrupt
 * priority when the system is in trouble.
 *
 */
static int
mirror_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	mm_unit_t	*un;
	dev_t		mapdev;
	int		result;
	int		smi;
	int		any_succeed = 0;
	int		save_result = 0;

	/*
	 * Don't need to grab the unit lock.
	 * Cause nothing else is suppose to be happenning.
	 * Also dump is not suppose to sleep.
	 */
	un = (mm_unit_t *)MD_UNIT(getminor(dev));

	if ((diskaddr_t)blkno >= un->c.un_total_blocks)
		return (EINVAL);

	if ((diskaddr_t)blkno + nblk > un->c.un_total_blocks)
		return (EINVAL);

	for (smi = 0; smi < NMIRROR; smi++) {
		if (!SUBMIRROR_IS_WRITEABLE(un, smi))
			continue;
		mapdev = md_dev64_to_dev(un->un_sm[smi].sm_dev);
		result = bdev_dump(mapdev, addr, blkno, nblk);
		if (result)
			save_result = result;

		if (result == 0)
			any_succeed++;
	}

	if (any_succeed)
		return (0);

	return (save_result);
}

/*
 * NAME: mirror_probe_dev
 *
 * DESCRITPION: force opens every component of a mirror.
 *
 * On entry the unit writerlock is held
 */
static int
mirror_probe_dev(mdi_unit_t *ui, minor_t mnum)
{
	int		i;
	int		smi;
	int		ci;
	mm_unit_t	*un;
	int		md_devopen = 0;
	set_t		setno;
	int		sm_cnt;
	int		sm_unavail_cnt;

	if (md_unit_isopen(ui))
		md_devopen++;

	un = MD_UNIT(mnum);
	setno = MD_UN2SET(un);

	sm_cnt = 0;
	sm_unavail_cnt = 0;
	for (i = 0; i < NMIRROR; i++) {
		md_dev64_t tmpdev;
		mdi_unit_t	*sm_ui;

		if (!SMS_BY_INDEX_IS(un, i, SMS_INUSE)) {
			continue;
		}

		sm_cnt++;
		tmpdev = un->un_sm[i].sm_dev;
		(void) md_layered_open(mnum, &tmpdev,
		    MD_OFLG_CONT_ERRS | MD_OFLG_PROBEDEV);
		un->un_sm[i].sm_dev = tmpdev;

		sm_ui = MDI_UNIT(getminor(md_dev64_to_dev(tmpdev)));

		/*
		 * Logic similar to that in mirror_open_all_devs.  We set or
		 * clear the submirror Unavailable bit.
		 */
		(void) md_unit_writerlock(sm_ui);
		if (submirror_unavailable(un, i, 1)) {
			sm_ui->ui_tstate |= MD_INACCESSIBLE;
			sm_unavail_cnt++;
		} else {
			sm_ui->ui_tstate &= ~MD_INACCESSIBLE;
		}
		md_unit_writerexit(sm_ui);
	}

	/*
	 * If all of the submirrors are unavailable, the mirror is also
	 * unavailable.
	 */
	if (sm_cnt == sm_unavail_cnt) {
		ui->ui_tstate |= MD_INACCESSIBLE;
	} else {
		ui->ui_tstate &= ~MD_INACCESSIBLE;
	}

	/*
	 * Start checking from probe failures. If failures occur we
	 * set the appropriate erred state only if the metadevice is in
	 * use. This is specifically to prevent unnecessary resyncs.
	 * For instance if the disks were accidentally disconnected when
	 * the system booted up then until the metadevice is accessed
	 * (like file system mount) the user can shutdown, recable and
	 * reboot w/o incurring a potentially huge resync.
	 */

	smi = 0;
	ci = 0;
	while (mirror_geterror(un, &smi, &ci, 1, 1) != 0) {

		if (mirror_other_sources(un, smi, ci, 0) == 1) {
			/*
			 * Note that for a MN set, there is no need to call
			 * SE_NOTIFY as that is done when processing the
			 * state change
			 */
			if (md_devopen) {
				/*
				 * Never called from ioctl context,
				 * so (IOLOCK *)NULL
				 */
				set_sm_comp_state(un, smi, ci, CS_LAST_ERRED,
				    0, MD_STATE_XMIT, (IOLOCK *)NULL);
				if (!MD_MNSET_SETNO(setno)) {
					SE_NOTIFY(EC_SVM_STATE,
					    ESC_SVM_LASTERRED,
					    SVM_TAG_METADEVICE, setno,
					    MD_SID(un));
				}
				continue;
			} else {
				(void) mirror_close_all_devs(un,
				    MD_OFLG_PROBEDEV);
				if (!MD_MNSET_SETNO(setno)) {
					SE_NOTIFY(EC_SVM_STATE,
					    ESC_SVM_OPEN_FAIL,
					    SVM_TAG_METADEVICE, setno,
					    MD_SID(un));
				}
				mirror_openfail_console_info(un, smi, ci);
				return (ENXIO);
			}
		}

		/*
		 * Note that for a MN set, there is no need to call
		 * SE_NOTIFY as that is done when processing the
		 * state change
		 */
		if (md_devopen) {
			/* Never called from ioctl context, so (IOLOCK *)NULL */
			set_sm_comp_state(un, smi, ci, CS_ERRED, 0,
			    MD_STATE_XMIT, (IOLOCK *)NULL);
			if (!MD_MNSET_SETNO(setno)) {
				SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ERRED,
				    SVM_TAG_METADEVICE, setno,
				    MD_SID(un));
			}
		}
		mirror_openfail_console_info(un, smi, ci);
		ci++;
	}

	if (MD_MNSET_SETNO(setno)) {
		send_poke_hotspares(setno);
	} else {
		(void) poke_hotspares();
	}
	(void) mirror_close_all_devs(un, MD_OFLG_PROBEDEV);

	return (0);
}


static int
mirror_imp_set(
	set_t	setno
)
{

	mddb_recid_t	recid;
	int		gotsomething, i;
	mddb_type_t	typ1;
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;
	mm_unit32_od_t	*un32;
	mm_unit_t	*un64;
	md_dev64_t	self_devt;
	minor_t		*self_id;	/* minor needs to be updated */
	md_parent_t	*parent_id;	/* parent needs to be updated */
	mddb_recid_t	*record_id;	/* record id needs to be updated */
	mddb_recid_t	*optrec_id;
	md_dev64_t	tmpdev;


	gotsomething = 0;

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    mirror_md_ops.md_driver.md_drivername);
	recid = mddb_makerecid(setno, 0);

	while ((recid = mddb_getnextrec(recid, typ1, MIRROR_REC)) > 0) {
		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;

		dep = mddb_getrecdep(recid);
		rbp = dep->de_rb;

		switch (rbp->rb_revision) {
		case MDDB_REV_RB:
		case MDDB_REV_RBFN:
			/*
			 * Small device
			 */
			un32 = (mm_unit32_od_t *)mddb_getrecaddr(recid);
			self_id = &(un32->c.un_self_id);
			parent_id = &(un32->c.un_parent);
			record_id = &(un32->c.un_record_id);
			optrec_id = &(un32->un_rr_dirty_recid);

			for (i = 0; i < un32->un_nsm; i++) {
				tmpdev = md_expldev(un32->un_sm[i].sm_dev);
				un32->un_sm[i].sm_dev = md_cmpldev
				    (md_makedevice(md_major, MD_MKMIN(setno,
				    MD_MIN2UNIT(md_getminor(tmpdev)))));

				if (!md_update_minor(setno, mddb_getsidenum
				    (setno), un32->un_sm[i].sm_key))
				goto out;
			}
			break;
		case MDDB_REV_RB64:
		case MDDB_REV_RB64FN:
			un64 = (mm_unit_t *)mddb_getrecaddr(recid);
			self_id = &(un64->c.un_self_id);
			parent_id = &(un64->c.un_parent);
			record_id = &(un64->c.un_record_id);
			optrec_id = &(un64->un_rr_dirty_recid);

			for (i = 0; i < un64->un_nsm; i++) {
				tmpdev = un64->un_sm[i].sm_dev;
				un64->un_sm[i].sm_dev = md_makedevice
				    (md_major, MD_MKMIN(setno, MD_MIN2UNIT
				    (md_getminor(tmpdev))));

				if (!md_update_minor(setno, mddb_getsidenum
				    (setno), un64->un_sm[i].sm_key))
				goto out;
			}
			break;
		}

		/*
		 * If this is a top level and a friendly name metadevice,
		 * update its minor in the namespace.
		 */
		if ((*parent_id == MD_NO_PARENT) &&
		    ((rbp->rb_revision == MDDB_REV_RBFN) ||
		    (rbp->rb_revision == MDDB_REV_RB64FN))) {

			self_devt = md_makedevice(md_major, *self_id);
			if (!md_update_top_device_minor(setno,
			    mddb_getsidenum(setno), self_devt))
				goto out;
		}

		/*
		 * Update unit with the imported setno
		 *
		 */
		mddb_setrecprivate(recid, MD_PRV_GOTIT);

		*self_id = MD_MKMIN(setno, MD_MIN2UNIT(*self_id));
		if (*parent_id != MD_NO_PARENT)
			*parent_id = MD_MKMIN(setno, MD_MIN2UNIT(*parent_id));
		*record_id = MAKERECID(setno, DBID(*record_id));
		*optrec_id = MAKERECID(setno, DBID(*optrec_id));

		gotsomething = 1;
	}

out:
	return (gotsomething);
}

/*
 * NAME: mirror_check_offline
 *
 * DESCRIPTION: return offline_status = 1 if any submirrors are offline
 *
 * Called from ioctl, so access to MD_UN_OFFLINE_SM in un_status is
 * protected by the global ioctl lock as it is only set by the MD_IOCOFFLINE
 * ioctl.
 */
int
mirror_check_offline(md_dev64_t dev, int *offline_status)
{
	mm_unit_t		*un;
	md_error_t		mde = mdnullerror;

	if ((un = mirror_getun(getminor(dev), &mde, NO_LOCK, NULL)) == NULL)
		return (EINVAL);
	*offline_status = 0;
	if (un->c.un_status & MD_UN_OFFLINE_SM)
		*offline_status = 1;
	return (0);
}

/*
 * NAME: mirror_inc_abr_count
 *
 * DESCRIPTION: increment the count of layered soft parts with ABR set
 *
 * Called from ioctl, so access to un_abr_count is protected by the global
 * ioctl lock. It is only referenced in the MD_IOCOFFLINE ioctl.
 */
int
mirror_inc_abr_count(md_dev64_t dev)
{
	mm_unit_t		*un;
	md_error_t		mde = mdnullerror;

	if ((un = mirror_getun(getminor(dev), &mde, NO_LOCK, NULL)) == NULL)
		return (EINVAL);
	un->un_abr_count++;
	return (0);
}

/*
 * NAME: mirror_dec_abr_count
 *
 * DESCRIPTION: decrement the count of layered soft parts with ABR set
 *
 * Called from ioctl, so access to un_abr_count is protected by the global
 * ioctl lock. It is only referenced in the MD_IOCOFFLINE ioctl.
 */
int
mirror_dec_abr_count(md_dev64_t dev)
{
	mm_unit_t		*un;
	md_error_t		mde = mdnullerror;

	if ((un = mirror_getun(getminor(dev), &mde, NO_LOCK, NULL)) == NULL)
		return (EINVAL);
	un->un_abr_count--;
	return (0);
}

static md_named_services_t mirror_named_services[] = {
	{(intptr_t (*)()) poke_hotspares,		"poke hotspares"    },
	{(intptr_t (*)()) mirror_rename_listkids,	MDRNM_LIST_URKIDS   },
	{mirror_rename_check,				MDRNM_CHECK	    },
	{(intptr_t (*)()) mirror_renexch_update_kids,	MDRNM_UPDATE_KIDS   },
	{(intptr_t (*)()) mirror_exchange_parent_update_to,
			MDRNM_PARENT_UPDATE_TO},
	{(intptr_t (*)()) mirror_exchange_self_update_from_down,
			MDRNM_SELF_UPDATE_FROM_DOWN },
	{(intptr_t (*)())mirror_probe_dev,		"probe open test" },
	{(intptr_t (*)())mirror_check_offline,		MD_CHECK_OFFLINE },
	{(intptr_t (*)())mirror_inc_abr_count,		MD_INC_ABR_COUNT },
	{(intptr_t (*)())mirror_dec_abr_count,		MD_DEC_ABR_COUNT },
	{ NULL,						0		    }
};

md_ops_t mirror_md_ops = {
	mirror_open,		/* open */
	mirror_close,		/* close */
	md_mirror_strategy,	/* strategy */
	NULL,			/* print */
	mirror_dump,		/* dump */
	NULL,			/* read */
	NULL,			/* write */
	md_mirror_ioctl,	/* mirror_ioctl, */
	mirror_snarf,		/* mirror_snarf */
	mirror_halt,		/* mirror_halt */
	NULL,			/* aread */
	NULL,			/* awrite */
	mirror_imp_set,		/* import set */
	mirror_named_services
};

/* module specific initilization */
static void
init_init()
{
	md_mirror_mcs_buf_off = sizeof (md_mcs_t) - sizeof (buf_t);

	/* Initialize the parent and child save memory pools */
	mirror_parent_cache = kmem_cache_create("md_mirror_parent",
	    sizeof (md_mps_t), 0, mirror_parent_constructor,
	    mirror_parent_destructor, mirror_run_queue, NULL, NULL,
	    0);

	mirror_child_cache = kmem_cache_create("md_mirror_child",
	    sizeof (md_mcs_t) - sizeof (buf_t) + biosize(), 0,
	    mirror_child_constructor, mirror_child_destructor,
	    mirror_run_queue, NULL, NULL, 0);

	/*
	 * Insure wowbuf_size is a multiple of DEV_BSIZE,
	 * then initialize wowbuf memory pool.
	 */
	md_wowbuf_size = roundup(md_wowbuf_size, DEV_BSIZE);
	if (md_wowbuf_size <= 0)
		md_wowbuf_size = 2 * DEV_BSIZE;
	if (md_wowbuf_size > (32 * DEV_BSIZE))
		md_wowbuf_size = (32 * DEV_BSIZE);

	md_wowblk_size = md_wowbuf_size + sizeof (wowhdr_t);
	mirror_wowblk_cache = kmem_cache_create("md_mirror_wow",
	    md_wowblk_size, 0, NULL, NULL, NULL, NULL, NULL, 0);

	mutex_init(&mirror_timeout.dr_mx, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&hotspare_request.dr_mx, NULL, MUTEX_DEFAULT, NULL);

	mutex_init(&non_ff_drv_mutex, NULL, MUTEX_DEFAULT, NULL);
}

/* module specific uninitilization (undo init_init()) */
static void
fini_uninit()
{
	kmem_cache_destroy(mirror_parent_cache);
	kmem_cache_destroy(mirror_child_cache);
	kmem_cache_destroy(mirror_wowblk_cache);
	mirror_parent_cache = mirror_child_cache =
	    mirror_wowblk_cache = NULL;

	mutex_destroy(&mirror_timeout.dr_mx);
	mutex_destroy(&hotspare_request.dr_mx);
	mutex_destroy(&non_ff_drv_mutex);
}

/* define the module linkage */
MD_PLUGIN_MISC_MODULE("mirrors module", init_init(), fini_uninit())
