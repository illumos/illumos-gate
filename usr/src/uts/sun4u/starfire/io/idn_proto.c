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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Inter-Domain Network
 *
 * IDN Protocol functions to support domain link/unlink/reconfig.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/machparam.h>
#include <sys/debug.h>
#include <sys/cpuvar.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/stropts.h>
#include <sys/sema_impl.h>
#include <sys/membar.h>
#include <sys/utsname.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <netinet/in.h>
#include <sys/vm_machparam.h>
#include <sys/x_call.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <vm/as.h>		/* kas decl */

#include <sys/idn.h>
#include <sys/idn_xf.h>

#define	IDNBUG_CPUPERBOARD

extern pri_t		maxclsyspri;
extern u_longlong_t	gettick();

clock_t	idn_xmit_monitor_freq = 50;

static int	idn_connect(int domid);
static int	idn_disconnect(int domid, idn_fin_t fintype,
				idn_finarg_t finarg, idn_finsync_t finsync);
static void	idn_deconfig(int domid);
static void	idn_unlink_domainset(domainset_t domset, idn_fin_t fintype,
				idn_finarg_t finarg, idn_finopt_t finopt,
				boardset_t idnset);
static void	idn_retry_execute(void *arg);
static void	idn_retry_submit(void (*func)(uint_t token, void *arg),
				void *arg, uint_t token, clock_t ticks);
static void	idn_shutdown_datapath(domainset_t domset, int force);
static mblk_t	*idn_fill_buffer(caddr_t bufp, int size, mblk_t *mp,
				uchar_t **data_rptrp);
static ushort_t	idn_cksum(register ushort_t *hdrp, register int count);
static int	idn_mark_awol(int domid, clock_t *atime);

static void	idn_recv_proto(idn_protomsg_t *hp);
static void	idn_send_config(int domid, int phase);
static void	idn_recv_config(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static int	idn_send_master_config(int domid, int phase);
static int	idn_send_slave_config(int domid, int phase);
static uint_t	idn_check_master_config(int domid, uint_t *exp, uint_t *act);
static uint_t	idn_check_slave_config(int domid, uint_t *exp, uint_t *act);
static int	idn_recv_config_done(int domid);
static void	idn_nego_cleanup_check(int domid, int new_masterid,
				int new_cpuid);
static void	idn_recv_cmd(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static int	idn_recv_data(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static int	idn_send_data_loopback(idn_netaddr_t dst_netaddr,
				queue_t *wq, mblk_t *mp);
static void	idn_send_dataresp(int domid, idn_nack_t nacktype);
static int	idn_send_mboxdata(int domid, struct idn *sip, int channel,
				caddr_t bufp);
static int	idn_recv_mboxdata(int channel, caddr_t bufp);
static int	idn_program_hardware(int domid);
static int	idn_deprogram_hardware(int domid);

static void	idn_send_cmd_nackresp(int domid, idn_msgtype_t *mtp,
			idn_cmd_t cmdtype, idn_nack_t nacktype);
static void	idn_local_cmd(idn_cmd_t cmdtype, uint_t arg1,
				uint_t arg2, uint_t arg3);
static void	idn_terminate_cmd(int domid, int serrno);
static void	idn_mboxarea_init(idn_mboxtbl_t *mtp, register int ntbls);
static void	idn_mainmbox_activate(int domid);
static void	idn_mainmbox_deactivate(ushort_t domset);
static void	idn_mainmbox_chan_register(int domid,
				idn_mainmbox_t *send_mmp,
				idn_mainmbox_t *recv_mmp, int channel);
static int	idn_mainmbox_chan_unregister(ushort_t domset, int channel);
static int	idn_mainmbox_flush(int domid, idn_mainmbox_t *mmp);
static void	idn_mainmbox_reset(int domid, idn_mainmbox_t *cmp);
static int	idn_activate_channel(idn_chanset_t chanset,
				idn_chanop_t chanop);
static void	idn_deactivate_channel(idn_chanset_t chanset,
				idn_chanop_t chanop);
static int	idn_deactivate_channel_services(int channel,
				idn_chanop_t chanop);
static int	idn_activate_channel_services(int channel);
static void	idn_chan_server(idn_chansvr_t **cspp);
#if 0
static void	idn_chan_flush(idn_chansvr_t *csp);
#endif /* 0 */
static void	idn_chan_action(int channel, idn_chanaction_t chanaction,
				int wait);
static void	idn_chan_addmbox(int channel, ushort_t domset);
static void	idn_chan_delmbox(int channel, ushort_t domset);
static void	idn_submit_chanactivate_job(int channel);
static void	idn_exec_chanactivate(void *chn);

static void	idn_link_established(void *arg);
static void	idn_prealloc_slab(int nslabs);
static void	idn_recv_slaballoc_req(int domid, idn_msgtype_t *mtp,
				uint_t slab_size);
static void	idn_send_slaballoc_resp(int domid, idn_msgtype_t *mtp,
				uint_t slab_offset, uint_t slab_size,
				int serrno);
static void	idn_recv_slaballoc_resp(int domid, smr_offset_t slab_offset,
				uint_t slab_size, int serrno);
static void	idn_recv_slabreap_req(int domid, idn_msgtype_t *mtp,
				int nslabs);
static void	idn_recv_slabreap_resp(int domid, int nslabs, int serrno);
static void	idn_send_slabreap_resp(int domid, idn_msgtype_t *mtp,
				int nslabs, int serrno);
static void	idn_recv_slabfree_req(int domid, idn_msgtype_t *mtp,
				smr_offset_t slab_offset, uint_t slab_size);
static void	idn_recv_slabfree_resp(int domid, uint_t slab_offset,
				uint_t slab_size, int serrno);
static void	idn_send_slabfree_resp(int domid, idn_msgtype_t *mtp,
				uint_t slab_offset, uint_t slab_size,
				int serrno);
static void	idn_retry_nodename_req(void *arg);
static void	idn_send_nodename_req(int domid);
static void	idn_send_nodename_resp(int domid, idn_msgtype_t *mtp,
				uint_t bufoffset, int serrno);
static void	idn_recv_nodename_req(int domid, idn_msgtype_t *mtp,
				uint_t bufoffset);
static void	idn_recv_nodename_resp(int domid, uint_t bufoffset,
				int serrno);

static void	idn_protocol_server(int *id);
static void	idn_protocol_server_killall();
static void	idn_protojob_free(idn_protojob_t *jp);

static int	idn_xstate_transfunc(int domid, void *transarg);
static int	idn_xphase_transition(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_sync_enter(int domid, idn_synccmd_t cmd,
				domainset_t xset, domainset_t rset,
				int (*transfunc)(), void *transarg);
static domainset_t
		idn_sync_register(int domid, idn_synccmd_t cmd,
				domainset_t ready_set, idn_syncreg_t regtype);
static void	idn_sync_register_awol(int domid);
static int	idn_verify_config_mbox(int domid);
static int	idn_select_master(int domid, int rmasterid, int rcpuid);

static int	valid_mtu(uint_t mtu);
static int	valid_bufsize(uint_t bufsize);
static int	valid_slabsize(int slabsize);
static int	valid_nwrsize(int nwrsize);

static int	idn_master_init();
static void	idn_master_deinit();

static void	idn_send_acknack(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);

static int	idn_send_nego(int domid, idn_msgtype_t *mtp,
				domainset_t conset);
static void	idn_retry_nego(uint_t token, void *arg);
static int	idn_check_nego(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_action_nego_pend(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_error_nego(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_action_nego_sent(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_action_nego_rcvd(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_final_nego(int domid);
static void	idn_exit_nego(int domid, uint_t msgtype);

static int	idn_send_con(int domid, idn_msgtype_t *mtp,
				idn_con_t contype, domainset_t conset);
static void	idn_retry_con(uint_t token, void *arg);
static int	idn_check_con(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_action_con_pend(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_error_con(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_action_con_sent(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_action_con_rcvd(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_final_con(int domid);
static void	idn_exit_con(int domid, uint_t msgtype);

static int	idn_send_fin(int domid, idn_msgtype_t *mtp, idn_fin_t fintype,
				idn_finarg_t finarg, idn_finopt_t finopt,
				domainset_t finset, uint_t finmaster);
static void	idn_retry_fin(uint_t token, void *arg);
static int	idn_check_fin_pend(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_action_fin_pend(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_error_fin_pend(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static int	idn_check_fin_sent(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_action_fin_sent(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_error_fin_sent(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_action_fin_rcvd(int domid, idn_msgtype_t *mtp,
				idn_xdcargs_t xargs);
static void	idn_final_fin(int domid);
static void	idn_exit_fin(int domid, uint_t msgtype);

/*
 * We keep a small cache of protojob structures just
 * in case allocation within idn_handler comes back
 * with nothing from the land of kmem.
 */
idn_protojob_t	idn_protojob_cache[IDN_DMV_PENDING_MAX];
idn_protojob_t	*idn_protojob_cache_list;
kmutex_t	idn_protojob_cache_lock;

/*
 *	- receive message.
 *	- call check-function for current state.
 *	- if (check-function == ok) then
 *		call action-function for current state.
 *	  else
 *		call error-function for current state.
 *	- transition state based on check results.
 *	- if (next state == final state) then
 *		call final-function.
 */
static idn_xphase_t xphase_nego = {
	IDNP_NEGO,
	{
		{ IDNDS_NEGO_PEND,
			idn_check_nego,
			idn_action_nego_pend,
			idn_error_nego},
		{ IDNDS_NEGO_SENT,
			idn_check_nego,
			idn_action_nego_sent,
			idn_error_nego},
		{ IDNDS_NEGO_RCVD,
			NULL,
			idn_action_nego_rcvd,
			NULL },
		{ IDNDS_CONFIG, NULL, NULL, NULL },
	},
	idn_final_nego,
	idn_exit_nego
};

static idn_xphase_t xphase_con = {
	IDNP_CON,
	{
		{ IDNDS_CON_PEND,
			idn_check_con,
			idn_action_con_pend,
			idn_error_con},
		{ IDNDS_CON_SENT,
			idn_check_con,
			idn_action_con_sent,
			idn_error_con},
		{ IDNDS_CON_RCVD,
			NULL,
			idn_action_con_rcvd,
			NULL },
		{ IDNDS_CON_READY, NULL, NULL, NULL },
	},
	idn_final_con,
	idn_exit_con
};

static idn_xphase_t xphase_fin = {
	IDNP_FIN,
	{
		{ IDNDS_FIN_PEND,
			idn_check_fin_pend,
			idn_action_fin_pend,
			idn_error_fin_pend },
		{ IDNDS_FIN_SENT,
			idn_check_fin_sent,
			idn_action_fin_sent,
			idn_error_fin_sent },
		{ IDNDS_FIN_RCVD,
			NULL,
			idn_action_fin_rcvd,
			NULL },
		{ IDNDS_DMAP, NULL, NULL, NULL },
	},
	idn_final_fin,
	idn_exit_fin
};

static int idnxs_state_table[4][5][2] = {
	{			/* IDNXS_PEND */
		{ IDNXS_SENT,	IDNXS_PEND },	/* 0 */
		{ IDNXS_RCVD,	IDNXS_PEND },	/* msg */
		{ IDNXS_NIL,	IDNXS_PEND },	/* msg+ack */
		{ IDNXS_PEND,	IDNXS_NIL },	/* ack */
		{ IDNXS_PEND,	IDNXS_NIL },	/* nack */
	},
	{			/* IDNXS_SENT */
		{ IDNXS_NIL,	IDNXS_NIL },	/* 0 */
		{ IDNXS_RCVD,	IDNXS_PEND },	/* msg */
		{ IDNXS_FINAL,	IDNXS_PEND },	/* msg+ack */
		{ IDNXS_NIL,	IDNXS_NIL },	/* ack */
		{ IDNXS_PEND,	IDNXS_NIL },	/* nack */
	},
	{			/* IDNXS_RCVD */
		{ IDNXS_NIL,	IDNXS_NIL },	/* 0 */
		{ IDNXS_NIL,	IDNXS_NIL },	/* msg */
		{ IDNXS_FINAL,	IDNXS_NIL },	/* msg+ack */
		{ IDNXS_FINAL,	IDNXS_NIL },	/* ack */
		{ IDNXS_PEND,	IDNXS_NIL },	/* nack */
	},
	{			/* IDNXS_FINAL */
		{ IDNXS_NIL,	IDNXS_NIL },	/* 0 */
		{ IDNXS_NIL,	IDNXS_NIL },	/* msg */
		{ IDNXS_NIL,	IDNXS_NIL },	/* msg+ack */
		{ IDNXS_NIL,	IDNXS_NIL },	/* ack */
		{ IDNXS_NIL,	IDNXS_NIL },	/* nack */
	}
};

/*
 * NONE		Respective domain does not have a master.
 * OTHER	Respective domain has a master different
 *		than either local or remote.
 * LOCAL	Respective domain has chosen local as master.
 * REMOTE	Respective domain has chosen remote as master.
 *
 * Actions:
 *	VOTE		Compare votes and select one.
 *	VOTE_RCFG	Compare votes and Reconfigure
 *			if necessary, i.e. remote won.
 *	CONNECT		Connect to remote's OTHER if different
 *			than our local master.
 *	LOCAL		Local domain is winner.
 *	REMOTE		Remote domain is winner.
 *	WAIT		Wait for remote to connect to our
 *			master if theirs is different.
 *	ERROR		An impossible condition.
 *
 * Index:
 *	0 = Local
 *	1 = Remote
 */
static idn_master_select_t master_select_table[4][4] = {
	{				/* local	remote	*/
		MASTER_SELECT_VOTE,	/* NONE		NONE	*/
		MASTER_SELECT_CONNECT,	/* NONE		OTHER	*/
		MASTER_SELECT_LOCAL,	/* NONE		LOCAL	*/
		MASTER_SELECT_REMOTE	/* NONE		REMOTE	*/
	},
	{
		MASTER_SELECT_WAIT,	/* OTHER	NONE	*/
		MASTER_SELECT_CONNECT,	/* OTHER	OTHER	*/
		MASTER_SELECT_WAIT,	/* OTHER	LOCAL	*/
		MASTER_SELECT_WAIT	/* OTHER	REMOTE	*/
	},
	{
		MASTER_SELECT_LOCAL,	/* LOCAL	NONE	*/
		MASTER_SELECT_CONNECT,	/* LOCAL	OTHER	*/
		MASTER_SELECT_LOCAL,	/* LOCAL	LOCAL	*/
		MASTER_SELECT_VOTE_RCFG	/* LOCAL	REMOTE	*/
	},
	{
		MASTER_SELECT_REMOTE,	/* REMOTE	NONE	*/
		MASTER_SELECT_CONNECT,	/* REMOTE	OTHER	*/
		MASTER_SELECT_ERROR,	/* REMOTE	LOCAL	*/
		MASTER_SELECT_REMOTE	/* REMOTE	REMOTE	*/
	}
};

void
idn_assign_cookie(int domid)
{
	static ushort_t	num = 0;
	ushort_t	cookie;
	procname_t	proc = "idn_assign_cookie";

	if ((cookie = idn_domain[domid].dcookie_recv) != 0)
		return;

	cookie = (ushort_t)(((uint64_t)&idn_domain[domid] >> 8) & 0xff);
	while ((cookie ^= num++ & 0xff) == 0)
		;

	PR_PROTO("%s:%d: assigned RECV cookie 0x%x\n", proc, domid, cookie);

	idn_domain[domid].dcookie_recv = cookie;
}

void
idn_update_priority(int domid, int pri)
{
	idn_domain_t	*dp;
	procname_t	proc = "idn_update_priority";

	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	dp = &idn_domain[domid];

	if (pri >= IDNVOTE_MINPRI) {
		dp->dvote.v.priority = pri & IDNVOTE_PRI_MASK;

		PR_PROTO("%s:%d: SETTING PRIORITY to req(%d) "
		    "(localpri = 0x%x)\n",
		    proc, domid, pri, IDNVOTE_PRIVALUE(dp->dvote));
	} else {
		PR_PROTO("%s:%d: PRIORITIES UNCHANGED (pri = 0x%x)\n",
		    proc, domid, IDNVOTE_PRIVALUE(dp->dvote));
	}
}

/*
 * Initiate a link between the local domain and the remote domain
 * containing the given cpuid.
 */
int
idn_link(int domid, int cpuid, int pri, int waittime, idnsb_error_t *sep)
{
	int		rv;
	idn_domain_t	*dp;
	void		*opcookie;
	procname_t	proc = "idn_link";

	if ((cpuid < 0) || (cpuid >= NCPU)) {
		cmn_err(CE_WARN,
		    "IDN: 201: (LINK) invalid CPU ID (%d)", cpuid);
		return (EINVAL);
	}
	if (waittime < 0) {
		cmn_err(CE_WARN,
		    "IDN: 202: (LINK) invalid time-out value (%d)",
		    waittime);
		return (EINVAL);
	}
	if (!VALID_DOMAINID(domid)) {
		cmn_err(CE_WARN,
		    "IDN: 203: (LINK) invalid domain ID (%d)",
		    domid);
		return (EINVAL);
	}
	if (domid == idn.localid)
		return (0);

	IDN_SYNC_LOCK();
	IDN_DLOCK_EXCL(domid);

	dp = &idn_domain[domid];

	switch (dp->dstate) {
	case IDNDS_CLOSED:
		break;

	case IDNDS_CONNECTED:
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "!IDN: domain %d (CPU ID %d) already connected",
		    domid, cpuid);
#endif /* DEBUG */
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return (0);

	default:
		cmn_err(CE_WARN,
		    "IDN: 204: domain %d state (%s) inappropriate",
		    domid, idnds_str[dp->dstate]);
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return (EINVAL);
	}

	rv = idn_open_domain(domid, cpuid, 0);
	if (rv != 0) {
		cmn_err(CE_WARN,
		    "IDN: 205: (%s) failed to open-domain(%d,%d)",
		    proc, domid, cpuid);
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return (EIO);
	}


	IDN_DLOCK_EXCL(idn.localid);
	idn_update_priority(idn.localid, pri);
	IDN_DUNLOCK(idn.localid);

	if (waittime > 0)
		opcookie = idn_init_op(IDNOP_CONNECTED, DOMAINSET(domid), sep);

	(void) idn_connect(domid);

	IDN_DUNLOCK(domid);
	IDN_SYNC_UNLOCK();

	PR_PROTO("%s:%d: ALLOCATED idn_link(%d)\n", proc, domid, cpuid);

	if (waittime > 0) {
		boardset_t	domset = 0;
		/*
		 * Well we've successfully allocated a domain id,
		 * but the link may not be fully established yet.
		 * Need to wait since it happens asynchronously.
		 */
		PR_PROTO("%s:%d: WAITING for op(%s) for (domset 0%x)...\n",
		    proc, domid, idnop_str[IDNOP_CONNECTED],
		    DOMAINSET(domid));

		rv = idn_wait_op(opcookie, &domset, waittime);
	}

#ifdef DEBUG
	if (rv == 0) {
		if (waittime > 0) {
			PR_PROTO("%s:%d: connect SUCCEEDED (cpu %d)\n",
			    proc, domid, cpuid);
		} else {
			PR_PROTO("%s:%d: connect KICKED OFF (cpu %d)\n",
			    proc, domid, cpuid);
		}
	} else {
		PR_PROTO("%s:%d: connect FAILED (cpu %d)\n",
		    proc, domid, cpuid);
	}
#endif /* DEBUG */

	return (rv);
}

/*
 * Unlink the given domain from any domain cluster of
 * which it might be a member.  Force indicates that domain
 * should not go AWOL and if it's currently AWOL to close
 * and remove it.
 * IMPORTANT: If the (hard) force flag is set, the caller is
 *	      assumed to GUARANTEE that the given domain will
 *	      not attempt to communicate with the local domain
 *	      in any manner.
 */
int
idn_unlink(int domid, boardset_t idnset, idn_fin_t fintype,
		idn_finopt_t finopt, int waittime, idnsb_error_t *sep)
{
	int		rv = 0;
	domainset_t	domset;
	void		*opcookie;
	procname_t	proc = "idn_unlink";


	if (waittime < 0) {
		cmn_err(CE_WARN,
		    "IDN: 202: (UNLINK) invalid time-out value (%d)",
		    waittime);
		SET_IDNKERR_IDNERR(sep, IDNKERR_INVALID_WTIME);
		SET_IDNKERR_PARAM0(sep, waittime);
		return (EINVAL);
	}
	if (!VALID_DOMAINID(domid)) {
		cmn_err(CE_WARN,
		    "IDN: 203: (UNLINK) invalid domain ID (%d)",
		    domid);
		SET_IDNKERR_IDNERR(sep, IDNKERR_INVALID_DOMAIN);
		SET_IDNKERR_PARAM0(sep, domid);
		SET_IDNKERR_PARAM1(sep, -1);
		return (EINVAL);
	}
	if (idn.localid == IDN_NIL_DOMID) {
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "!IDN: %s: local domain not connected to an IDNnet",
		    proc);
#endif /* DEBUG */
		return (0);
	}

	/*
	 * Lock ordering protocols requires that we grab the
	 * global lock _before_ the local domain's lock.
	 * However, non-local domains must have their lock
	 * grabbed _before_ the global lock.
	 */
	IDN_SYNC_LOCK();
	IDN_GLOCK_EXCL();
	domset = idn.domset.ds_trans_on | idn.domset.ds_trans_off;
	if ((idn.state == IDNGS_OFFLINE) && !domset) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "!IDN: %s: local domain not connected to an IDNnet",
		    proc);
#endif /* DEBUG */
		IDN_GUNLOCK();
		IDN_SYNC_UNLOCK();
		return (0);
	}

	if ((domid == IDN_NIL_DOMID) || (domid == idn.localid)) {
		domid = idn.localid;
		IDN_GSTATE_TRANSITION(IDNGS_DISCONNECT);
		IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);
		domset = DOMAINSET_ALL;
		DOMAINSET_DEL(domset, idn.localid);
	} else {
		domset = DOMAINSET(domid);
	}
	IDN_GUNLOCK();

	if (waittime > 0)
		opcookie = idn_init_op(IDNOP_DISCONNECTED, domset, sep);

	idn_unlink_domainset(domset, fintype, IDNFIN_ARG_NONE, finopt, idnset);

	IDN_SYNC_UNLOCK();

	if (waittime > 0) {
		/*
		 * Well the unlink has successfully kicked off.
		 * Since process is asynchronous we need to wait
		 * for it to complete.
		 */
		PR_PROTO("%s:%d: WAITING for op(%s) for (domset 0%x)...\n",
		    proc, domid, idnop_str[IDNOP_DISCONNECTED],
		    domset);

		rv = idn_wait_op(opcookie, &domset, waittime);
	}

	if (rv == 0) {
		if (waittime > 0) {
			PR_PROTO("%s:%d: disconnect SUCCEEDED\n",
			    proc, domid);
		} else {
			PR_PROTO("%s:%d: disconnect KICKED OFF\n",
			    proc, domid);
		}
	} else {
		PR_PROTO("%s:%d: disconnect FAILED\n", proc, domid);
	}

	return (rv);
}

static void
idn_unlink_domainset(domainset_t domset, idn_fin_t fintype,
			idn_finarg_t finarg, idn_finopt_t finopt,
			boardset_t idnset)
{
	int		d;
	domainset_t	offset;
	procname_t	proc = "idn_unlink_domainset";

	ASSERT(IDN_SYNC_IS_LOCKED());

	/*
	 * Determine subset for which we have
	 * no active connections.
	 */
	offset = domset & ~(idn.domset.ds_trans_on |
	    idn.domset.ds_connected |
	    idn.domset.ds_trans_off |
	    idn.domset.ds_relink);
	/*
	 * Determine subset that are really candidates.
	 * Note that we include those already down the path
	 * since it's possible a request came in to upgrade
	 * their fintype (e.g. NORMAL->FORCE_SOFT).
	 */
	domset &= ~offset;

	if (offset)
		idn_update_op(IDNOP_DISCONNECTED, offset, NULL);

	IDN_GLOCK_EXCL();
	if ((finopt == IDNFIN_OPT_RELINK) && (idn.state != IDNGS_DISCONNECT)) {
		/*
		 * Don't add domains already transitioning off.
		 * If they caught on an earlier Reconfig wave then
		 * they'll already be in ds_relink anyway.  Otherwise,
		 * once a domain is transition off we can't upgrade
		 * him to a RELINK.
		 */
#ifdef DEBUG
		if (idn.domset.ds_hitlist & domset) {
			PR_HITLIST("%s: domset=%x, hitlist=%x, trans_off=%x "
			    "-> relink = %x -> %x\n",
			    proc, domset, idn.domset.ds_hitlist,
			    idn.domset.ds_relink, idn.domset.ds_trans_off,
			    idn.domset.ds_relink |
			    (domset & ~idn.domset.ds_trans_off));
		}
#endif /* DEBUG */

		domset &= ~idn.domset.ds_trans_off;
		idn.domset.ds_relink |= domset;
	} else {
		idn.domset.ds_relink &= ~domset;
	}
	/*
	 * Update the ds_trans_on/off so we don't waste
	 * time talking to these folks.
	 */
	idn.domset.ds_trans_on  &= ~domset;
	idn.domset.ds_trans_off |= domset;

	if (domset == 0) {
		if ((idn.domset.ds_trans_on |
		    idn.domset.ds_connected |
		    idn.domset.ds_trans_off |
		    idn.domset.ds_relink) == 0) {
			PR_HITLIST("%s:%x: HITLIST %x -> 0\n",
			    proc, domset, idn.domset.ds_hitlist);
			idn.domset.ds_hitlist = 0;
			IDN_GSTATE_TRANSITION(IDNGS_OFFLINE);
		}
		IDN_GUNLOCK();
		return;
	}
	IDN_GUNLOCK();

	for (d = 0; d < MAX_DOMAINS; d++) {
		idn_domain_t	*dp;
		idn_fin_t	ftype;

		if (!DOMAIN_IN_SET(domset, d))
			continue;

		dp = &idn_domain[d];
		IDN_DLOCK_EXCL(d);
		IDN_HISTORY_LOG(IDNH_RELINK, d, dp->dstate,
		    idn.domset.ds_relink);
		ftype = fintype;
		if ((dp->dcpu != IDN_NIL_DCPU) && dp->dhw.dh_boardset) {
			/*
			 * If domain is not in the IDNSET passed
			 * down then we need to upgrade this to
			 * hard-force in order to prevent possible
			 * system failures (arbstop).  This is simply
			 * extra protection beyond that checked by
			 * the SSP.  IDNSET contains the set of boards
			 * that have a "link" to the local domain,
			 * including the SMD regs.
			 */
			if ((idnset & dp->dhw.dh_boardset) == 0) {
				PR_PROTO("%s:%d: boardset 0x%x "
				    "NOT in IDNSET 0x%x\n",
				    proc, d, dp->dhw.dh_boardset,
				    idnset);
				if (ftype != IDNFIN_FORCE_HARD)
					cmn_err(CE_NOTE,
					    "!IDN: 222: no IDN linkage "
					    "found (b=0x%x, i=0x%x) "
					    "upgrading unlink %s to %s",
					    dp->dhw.dh_boardset,
					    idnset, idnfin_str[ftype],
					    idnfin_str[IDNFIN_FORCE_HARD]);

				ftype = IDNFIN_FORCE_HARD;
			} else {
				PR_PROTO("%s:%d: boardset 0x%x "
				    "FOUND in IDNSET 0x%x\n",
				    proc, d, dp->dhw.dh_boardset,
				    idnset);
			}
		}
		(void) idn_disconnect(d, ftype, finarg, IDNDS_SYNC_TYPE(dp));
		IDN_DUNLOCK(d);
	}
}

/*
 * Return w/locks held.
 */
static int
idn_connect(int domid)
{
	idn_xdcargs_t	xargs;
	idn_domain_t	*dp = &idn_domain[domid];
	procname_t	proc = "idn_connect";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	ASSERT(dp->dcpu != IDN_NIL_DCPU);

	if (dp->dstate != IDNDS_CLOSED) {
		if (DOMAIN_IN_SET(idn.domset.ds_trans_on |
		    idn.domset.ds_connected, domid)) {
			PR_PROTO("%s:%d: already connected or "
			    "in-progress\n", proc, domid);
		} else {
			PR_PROTO("%s:%d: current state (%s) != "
			    "CLOSED\n", proc, domid,
			    idnds_str[dp->dstate]);
		}
		return (-1);
	}

	ASSERT(!DOMAIN_IN_SET(idn.domset.ds_connected, domid));
	ASSERT(!DOMAIN_IN_SET(idn.domset.ds_trans_off, domid));

	dp->dxp = &xphase_nego;
	IDN_XSTATE_TRANSITION(dp, IDNXS_PEND);

	(void) idn_xphase_transition(domid, NULL, xargs);

	return (0);
}

/*
 * Return w/locks held.
 */
static int
idn_disconnect(int domid, idn_fin_t fintype, idn_finarg_t finarg,
    idn_finsync_t finsync)
{
	int		new_masterid, new_cpuid = IDN_NIL_DCPU;
	uint_t		token;
	uint_t		finmaster;
	idn_xdcargs_t	xargs;
	idn_finopt_t	finopt;
	idn_domain_t	*dp = &idn_domain[domid];
	procname_t	proc = "idn_disconnect";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (dp->dstate == IDNDS_CLOSED) {
		PR_PROTO("%s:%d: already CLOSED\n", proc, domid);
		idn_update_op(IDNOP_DISCONNECTED, DOMAINSET(domid), NULL);
		return (-1);
	}

	/*
	 * Terminate any outstanding commands that were
	 * targeted towards this domain.
	 */
	idn_terminate_cmd(domid, ECANCELED);

	/*
	 * Terminate any and all retries that may have
	 * outstanding for this domain.
	 */
	token = IDN_RETRY_TOKEN(domid, IDN_RETRY_TYPEALL);
	(void) idn_retry_terminate(token);

	/*
	 * Stop all outstanding message timers for
	 * this guy.
	 */
	IDN_MSGTIMER_STOP(domid, 0, 0);

	dp->dxp = &xphase_fin;
	IDN_XSTATE_TRANSITION(dp, IDNXS_PEND);
	if ((int)dp->dfin < (int)fintype) {
		/*
		 * You can only upgrade a fin type.
		 * We don't allow it to be downgraded
		 * as it's too dangerous since some
		 * state may have been blown away while
		 * we were fin'ing at a higher level.
		 */
		IDN_FSTATE_TRANSITION(dp, fintype);
	}

	dp->dfin_sync = finsync;
	PR_PROTO("%s:%d: disconnect synchronously = %s\n",
	    proc, domid, (finsync == IDNFIN_SYNC_OFF) ? "OFF" :
	    (finsync == IDNFIN_SYNC_NO) ? "NO" : "YES");

	IDN_GLOCK_SHARED();
	if (DOMAIN_IN_SET(idn.domset.ds_relink, domid) &&
	    (idn.state != IDNGS_DISCONNECT)) {
		finopt = IDNFIN_OPT_RELINK;
	} else {
		finopt = IDNFIN_OPT_UNLINK;
		PR_HITLIST("%s:%d: HITLIST %x -> %x\n",
		    proc, domid, idn.domset.ds_hitlist,
		    idn.domset.ds_hitlist | DOMAINSET(domid));
		DOMAINSET_ADD(idn.domset.ds_hitlist, domid);
	}

	CLR_XARGS(xargs);
	SET_XARGS_FIN_TYPE(xargs, dp->dfin);
	SET_XARGS_FIN_ARG(xargs, finarg);
	SET_XARGS_FIN_OPT(xargs, finopt);
	SET_XARGS_FIN_DOMSET(xargs, 0);		/* unused when msg = 0 */
	new_masterid = IDN_GET_NEW_MASTERID();
	IDN_GUNLOCK();
	if (new_masterid != IDN_NIL_DOMID)
		new_cpuid = idn_domain[new_masterid].dcpu;
	finmaster = MAKE_FIN_MASTER(new_masterid, new_cpuid);
	SET_XARGS_FIN_MASTER(xargs, finmaster);

	(void) idn_xphase_transition(domid, NULL, xargs);

	return (0);
}

static int
idn_next_xstate(idn_xstate_t o_xstate, int err, uint_t msg)
{
	int		index;
	procname_t	proc = "idn_next_xstate";

	ASSERT(((int)o_xstate >= 0) && ((int)o_xstate <= 4));

	if (!msg)
		index = 0;
	else if ((msg & IDNP_MSGTYPE_MASK) == 0)
		index = (msg & IDNP_ACK) ? 3 : (msg & IDNP_NACK) ? 4 : -1;
	else
		index = (msg & IDNP_ACK) ? 2 :
		    !(msg & IDNP_ACKNACK_MASK) ? 1 : -1;

	if (index == -1) {
		STRING(str);

		INUM2STR(msg, str);
		PR_PROTO("%s: (msg = 0x%x(%s))\n", proc, msg, str);
		return (IDNXS_NIL);
	}

	if (err == -1) {
		int	n_xstate;
		/*
		 * Caller is just interested in querying is this
		 * is a valid message to receive in the current
		 * xstate.  A return value of IDNXS_NIL indicates
		 * that it's not.  A return value of non-IDNXS_NIL
		 * indicates it's cool.  An invalid message is
		 * determined by both err & !err states being IDNXS_NIL.
		 */
		n_xstate = idnxs_state_table[(int)o_xstate][index][0];
		if (n_xstate != IDNXS_NIL)
			return (n_xstate);
		else
			return (idnxs_state_table[(int)o_xstate][index][1]);
	} else {
		return (idnxs_state_table[(int)o_xstate][index][err ? 1 : 0]);
	}
}

static int
idn_select_candidate(domainset_t master_set)
{
	int		d, best_id = IDN_NIL_DOMID;
	uint_t		best_vote = 0;
	idn_domain_t	*dp;
	procname_t	proc = "idn_select_candidate";

	ASSERT(IDN_SYNC_IS_LOCKED());

	if (master_set == 0) {
		PR_PROTO("%s: %x -> %d\n", proc, master_set, IDN_NIL_DOMID);
		return (IDN_NIL_DOMID);
	}

	for (d = 0; d < MAX_DOMAINS; d++) {
		uint_t		vote;
		idn_vote_t	v;

		if (!DOMAIN_IN_SET(master_set, d))
			continue;

		dp = &idn_domain[d];

		if ((dp->domid == IDN_NIL_DOMID) ||
		    (dp->dcpu == IDN_NIL_DCPU) ||
		    ((v.ticket = dp->dvote.ticket) == 0))
			continue;

		vote = IDNVOTE_ELECT(v);

		if (vote > best_vote) {
			best_vote = vote;
			best_id = d;
		}
	}

	PR_PROTO("%s: %x -> %d\n", proc, master_set, best_id);

	return (best_id);
}

/*
 * If a non-zero value is returned then GLOCK will have been dropped.
 * Otherwise, routine returns with all incoming locks still held.
 */
static int
idn_select_master(int domid, int rmasterid, int rcpuid)
{
	char		*sel;
	int		lmasterid, masterid;
	int		do_reconfig = 0;
	int		lindex, rindex;
	idn_domain_t	*ldp, *rdp;
	uint_t		rvote, lvote;
	idn_master_select_t	select;
	procname_t	proc = "idn_select_master";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_GLOCK_IS_EXCL());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	PR_PROTO("%s:%d: lmasterid = %d, rmasterid = %d, rcpuid = %d\n",
	    proc, domid, IDN_GET_MASTERID(), rmasterid, rcpuid);

	IDN_DLOCK_EXCL(idn.localid);

	ldp = &idn_domain[idn.localid];
	rdp = &idn_domain[domid];

	/*
	 * Clear master bits since mastership is derived from
	 * other information (local/remote idn.masterid/idn.new_masterid)
	 * and we don't want the vote master bit to confuse matters.
	 */
	lvote = IDNVOTE_ELECT(ldp->dvote);
	rvote = IDNVOTE_ELECT(rdp->dvote);

	lmasterid = IDN_GET_MASTERID();

	lindex = (lmasterid == IDN_NIL_DOMID) ? MASTER_IS_NONE :
	    (lmasterid == idn.localid) ? MASTER_IS_LOCAL :
	    (lmasterid == domid) ? MASTER_IS_REMOTE :
	    MASTER_IS_OTHER;

	rindex = (rmasterid == IDN_NIL_DOMID) ? MASTER_IS_NONE :
	    (rmasterid == domid) ? MASTER_IS_REMOTE :
	    (rmasterid == idn.localid) ? MASTER_IS_LOCAL :
	    MASTER_IS_OTHER;

	select = master_select_table[lindex][rindex];

	masterid = IDN_NIL_DOMID;

	/*
	 * Each case is responsible for dropping DLOCK(localid)
	 * and GLOCK if it doesn't select a master, unless a
	 * reconfig is necessary.
	 */
	switch (select) {
	case MASTER_SELECT_VOTE_RCFG:
		sel = "VOTE_RECONFIG";
		if (lvote > rvote) {
			/*
			 * If the local domain is the winner then remote
			 * domain will have to Reconfig.  We'll continue
			 * through the connection process anyway.  The
			 * remote domains will tell us to back-off while
			 * Reconfigs, but that's okay as we'll keep retrying.
			 */
			masterid = idn.localid;
		} else if (lvote < rvote) {
			do_reconfig = 1;
			/*
			 * GLOCK will get dropped once reconfig
			 * is kicked off.
			 */
		} else {
			cmn_err(CE_WARN,
			    "IDN: 206: cannot link domains "
			    "with equal votes (L(%d),R(%d),0x%x)",
			    idn.localid, domid, rvote);
			IDN_GUNLOCK();
		}
		IDN_DUNLOCK(idn.localid);
		break;

	case MASTER_SELECT_VOTE:
		sel = "VOTE";
		if (lvote > rvote) {
			masterid = idn.localid;
			ldp->dvote.v.master = 1;
			rdp->dvote.v.master = 0;
		} else if (lvote < rvote) {
			masterid = domid;
			ldp->dvote.v.master = 0;
			rdp->dvote.v.master = 1;
		} else {
			cmn_err(CE_WARN,
			    "IDN: 206: cannot link domains "
			    "with equal votes (L(%d),R(%d),0x%x)",
			    idn.localid, domid, rvote);
		}
		ASSERT(IDN_GET_MASTERID() == IDN_NIL_DOMID);
		if (masterid != IDN_NIL_DOMID) {
			IDN_SET_MASTERID(masterid);
			IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);
		} else {
			IDN_GUNLOCK();
		}
		IDN_DUNLOCK(idn.localid);
		break;

	case MASTER_SELECT_REMOTE:
		sel = "REMOTE";
		masterid = domid;
		if (IDN_GET_MASTERID() == IDN_NIL_DOMID) {
			IDN_SET_MASTERID(masterid);
			IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);
			ldp->dvote.v.master = 0;
			rdp->dvote.v.master = 1;
		}
		ASSERT(IDN_GET_MASTERID() == domid);
		IDN_DUNLOCK(idn.localid);
		break;

	case MASTER_SELECT_LOCAL:
		sel = "LOCAL";
		masterid = idn.localid;
		if (IDN_GET_MASTERID() == IDN_NIL_DOMID) {
			IDN_SET_MASTERID(masterid);
			IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);
			ldp->dvote.v.master = 1;
			rdp->dvote.v.master = 0;
		}
		ASSERT(IDN_GET_MASTERID() == idn.localid);
		IDN_DUNLOCK(idn.localid);
		break;

	case MASTER_SELECT_CONNECT:
		sel = "CONNECT";
		if (rmasterid == lmasterid) {
			/*
			 * Local and remote have same master,
			 * let him come onboard.
			 */
			masterid = lmasterid;
			IDN_DUNLOCK(idn.localid);

		} else {
			int	rv;

			IDN_DUNLOCK(idn.localid);
			IDN_GUNLOCK();
			IDN_DLOCK_EXCL(rmasterid);
			PR_PROTO("%s:%d: attempting connect w/remote "
			    "master %d\n",
			    proc, domid, rmasterid);
			rv = idn_open_domain(rmasterid, rcpuid, 0);
			if (rv == 0) {
				(void) idn_connect(rmasterid);
			} else if (rv < 0) {
				cmn_err(CE_WARN,
				    "IDN: 205: (%s) failed to "
				    "open-domain(%d,%d)",
				    proc, rmasterid, rcpuid);
			} else {
				/*
				 * Must already have a connection going.
				 */
				PR_PROTO("%s:%d: failed "
				    "idn_open_domain(%d,%d,0) "
				    "(rv = %d)\n",
				    proc, domid, rmasterid,
				    rcpuid, rv);
			}
			IDN_DUNLOCK(rmasterid);
		}
		break;

	case MASTER_SELECT_WAIT:
		sel = "WAIT";
		/*
		 * If the remote domain has the same master as the local
		 * domain then there's no need to wait.
		 */
		if (rmasterid == lmasterid) {
			masterid = lmasterid;
		} else {
			IDN_GUNLOCK();
		}
		IDN_DUNLOCK(idn.localid);
		break;

	case MASTER_SELECT_ERROR:
		sel = "ERROR";
		/*
		 * Hit impossible condition.
		 */
		cmn_err(CE_WARN,
		    "IDN: 207: local/remote master-id conflict "
		    "(%d.lmasterid = %d, %d.rmasterid = %d)",
		    idn.localid, lmasterid, domid, rmasterid);
		IDN_GUNLOCK();
		IDN_DUNLOCK(idn.localid);
		break;

	default:
		cmn_err(CE_WARN,
		    "IDN: 208: %s: unknown case (%d)",
		    proc, (int)select);
		IDN_GUNLOCK();
		IDN_DUNLOCK(idn.localid);
		ASSERT(0);
		break;
	}

	if (masterid == IDN_NIL_DOMID) {
		PR_PROTO("%s:%d: NO MASTER SELECTED (rmstr=%d) sel=%s\n",
		    proc, domid, rmasterid, sel);
	} else {
		PR_PROTO("%s:%d: MASTER SELECTED = %d (%s)\n",
		    proc, domid, masterid,
		    (masterid == idn.localid) ? "LOCAL" :
		    (masterid == domid) ? "REMOTE" : "OTHER");
	}

	if (do_reconfig) {
		domainset_t	dis_set;

		/*
		 * Local domain already has a master.
		 * Need to dismantle all connections
		 * and reestablish one with new master.
		 */
		IDN_GKSTAT_GLOBAL_EVENT(gk_reconfigs, gk_reconfig_last);

		PR_PROTO("%s:%d: RECONFIG new masterid = %d\n",
		    proc, domid, domid);

		IDN_GSTATE_TRANSITION(IDNGS_RECONFIG);
		IDN_SET_NEW_MASTERID(domid);
		IDN_GUNLOCK();

		dis_set = idn.domset.ds_trans_on | idn.domset.ds_connected;
		DOMAINSET_DEL(dis_set, domid);

		idn_unlink_domainset(dis_set, IDNFIN_NORMAL, IDNFIN_ARG_NONE,
		    IDNFIN_OPT_RELINK, BOARDSET_ALL);
	}

	return ((masterid == IDN_NIL_DOMID) ? -1 : 0);
}

/*ARGSUSED1*/
static void
idn_retry_query(uint_t token, void *arg)
{
	idn_retry_t	rtype = IDN_RETRY_TOKEN2TYPE(token);
	int		d, domid = IDN_RETRY_TOKEN2DOMID(token);
	idn_domain_t	*dp = &idn_domain[domid];
	idn_synccmd_t	sync_cmd;
	domainset_t	query_set, my_ready_set;
	procname_t	proc = "idn_retry_query";

	IDN_SYNC_LOCK();
	IDN_DLOCK_EXCL(domid);

	switch (rtype) {
	case IDNRETRY_CONQ:
		sync_cmd = IDNSYNC_CONNECT;
		my_ready_set = idn.domset.ds_ready_on | idn.domset.ds_connected;
		my_ready_set &= ~idn.domset.ds_trans_off;
		DOMAINSET_ADD(my_ready_set, idn.localid);
		break;

	case IDNRETRY_FINQ:
		sync_cmd = IDNSYNC_DISCONNECT;
		my_ready_set = idn.domset.ds_ready_off |
		    ~idn.domset.ds_connected;
		break;

	default:
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return;
	}

	if (dp->dsync.s_cmd == sync_cmd)
		my_ready_set |= dp->dsync.s_set_rdy;

	query_set = idn_sync_register(domid, sync_cmd, 0, IDNSYNC_REG_QUERY);

	PR_PROTO("%s:%d: query_set = 0x%x\n", proc, domid, query_set);

	if (query_set == 0) {
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return;
	}

	for (d = 0; d < MAX_DOMAINS; d++) {
		if (!DOMAIN_IN_SET(query_set, d))
			continue;

		dp = &idn_domain[d];
		if (d != domid)
			IDN_DLOCK_EXCL(d);

		if ((dp->dsync.s_cmd == sync_cmd) ||
		    (!dp->dcookie_send &&
		    (rtype == IDNRETRY_CONQ))) {
			if (d != domid)
				IDN_DUNLOCK(d);
			continue;
		}

		IDN_SYNC_QUERY_UPDATE(domid, d);

		if (rtype == IDNRETRY_CONQ)
			(void) idn_send_con(d, NULL, IDNCON_QUERY,
			    my_ready_set);
		else
			(void) idn_send_fin(d, NULL, IDNFIN_QUERY,
			    IDNFIN_ARG_NONE, IDNFIN_OPT_NONE, my_ready_set,
			    NIL_FIN_MASTER);
		if (d != domid)
			IDN_DUNLOCK(d);
	}

	IDN_DUNLOCK(domid);
	IDN_SYNC_UNLOCK();
}

static int
idn_send_nego(int domid, idn_msgtype_t *mtp, domainset_t conset)
{
	idn_domain_t	*ldp, *dp;
	int		d, masterid;
	uint_t		dmask;
	uint_t		acknack;
	uint_t		ticket;
	idnneg_dset_t	dset;
	idn_msgtype_t	mt;
	procname_t	proc = "idn_send_nego";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (mtp) {
		acknack = mtp->mt_mtype & IDNP_ACKNACK_MASK;
		mt.mt_mtype = mtp->mt_mtype;
		mt.mt_atype = mtp->mt_atype;
		mt.mt_cookie = mtp->mt_cookie;
	} else {
		acknack = 0;
		mt.mt_mtype = IDNP_NEGO;
		mt.mt_atype = 0;
		mt.mt_cookie = IDN_TIMER_PUBLIC_COOKIE;
	}

	IDN_GLOCK_SHARED();

	dp = &idn_domain[domid];
	ldp = &idn_domain[idn.localid];

	if ((idn.state == IDNGS_RECONFIG) ||
	    ((masterid = IDN_GET_MASTERID()) == IDN_NIL_DOMID)) {
		masterid = IDN_GET_NEW_MASTERID();
		if ((masterid == idn.localid) || (masterid == domid)) {
			/*
			 * We only send the new-master "hint" to
			 * "other" domains.  If the new-master is
			 * ourself or we're talking to the new-master
			 * then we need to be accurate about our
			 * real master so that the correct master
			 * is selected.
			 */
			masterid = IDN_NIL_DOMID;
		}
	}

	DOMAINSET_DEL(conset, idn.localid);
	DOMAINSET_DEL(conset, domid);
	/*
	 * Exclude domains from conset that are on
	 * remote domain's hitlist.  He's not interested
	 * in hearing about them.  SSP is probably requesting
	 * such domains be unlinked - will eventually get to
	 * local domain.
	 */
	conset &= ~idn.domset.ds_hitlist;
	if ((masterid != IDN_NIL_DOMID) &&
	    DOMAIN_IN_SET(idn.domset.ds_hitlist, masterid)) {
		PR_PROTO("%s:%d: masterid(%d) on hitlist(0x%x) -> -1\n",
		    proc, domid, masterid, idn.domset.ds_hitlist);
		/*
		 * Yikes, our chosen master is on the hitlist!
		 */
		masterid = IDN_NIL_DOMID;
	}

	dmask = IDNNEG_DSET_MYMASK();
	IDNNEG_DSET_INIT(dset, dmask);
	for (d = 0; d < MAX_DOMAINS; d++) {
		int	cpuid;

		if (!DOMAIN_IN_SET(conset, d))
			continue;

		if ((cpuid = idn_domain[d].dcpu) == IDN_NIL_DCPU) {
			ASSERT(d != masterid);
			continue;
		}

		IDNNEG_DSET_SET(dset, d, cpuid, dmask);
	}
	IDNNEG_DSET_SET_MASTER(dset, domid, masterid);
	ASSERT((masterid != IDN_NIL_DOMID) ?
	    (idn_domain[masterid].dcpu != IDN_NIL_DCPU) : 1);
	IDN_GUNLOCK();

	IDN_DLOCK_SHARED(idn.localid);
	ticket = IDNVOTE_BASICS(ldp->dvote);
	/*
	 * We just want to send basic vote components without an
	 * indication of mastership (master bit) since that's primarily
	 * for local domain's usage.  There is more correct master
	 * indications in the DSET.  Recall that if we were in a
	 * Reconfig we would have transmitted the "new_masterid"
	 * which might conflict with the local domain's vote.v.master
	 * bit if he was originally the master prior to the Reconfig.
	 */

	PR_PROTO("%s:%d: sending nego%sto (cpu %d) "
	    "[v=0x%x, cs=0x%x, mstr=%d]\n",
	    proc, domid,
	    (acknack & IDNP_ACK) ? "+ack " :
	    (acknack & IDNP_NACK) ? "+nack " : " ",
	    dp->dcpu, ticket, conset, masterid);

	IDN_MSGTIMER_START(domid, IDNP_NEGO, 0,
	    idn_msg_waittime[IDNP_NEGO], &mt.mt_cookie);

	IDNXDC(domid, &mt, ticket, dset[0], dset[1], dset[2]);

	IDN_DUNLOCK(idn.localid);

	return (0);
}

static int
idn_recv_nego(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs,
    ushort_t dcookie)
{
	uint_t		msg = mtp->mt_mtype;
	idn_msgtype_t	mt;
	idn_domain_t	*dp = &idn_domain[domid];
	idn_xdcargs_t	nargs;
	procname_t	proc = "idn_recv_nego";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	mt.mt_cookie = mtp->mt_cookie;

#ifdef DEBUG
	if (DOMAIN_IN_SET(idn.domset.ds_hitlist, domid)) {
		PR_HITLIST("%s:%d: dcpu=%d, dstate=%s, msg=%x, "
		    "hitlist=%x\n",
		    proc, domid, dp->dcpu, idnds_str[dp->dstate],
		    msg, idn.domset.ds_hitlist);
	}
#endif /* DEBUG */

	if (dp->dcpu == IDN_NIL_DCPU) {
		int		cpuid;
		uint_t		ticket;
		/*
		 * Brandnew link.  Need to open a new domain entry.
		 */
		ticket = GET_XARGS_NEGO_TICKET(xargs);
		cpuid = dp->dcpu_last;
		ASSERT(VALID_CPUID(cpuid));

		if (idn_open_domain(domid, cpuid, ticket) != 0) {
			PR_PROTO("%s:%d: FAILED to open doamin "
			    "(ticket = 0x%x)\n",
			    proc, domid, ticket);
			return (-1);
		}
	}

	if ((msg & IDNP_MSGTYPE_MASK) == IDNP_NEGO) {
		PR_PROTO("%s:%d: assigned SEND cookie 0x%x\n",
		    proc, domid, dcookie);
		dp->dcookie_send = dcookie;
	}

	if ((dp->dxp == NULL) && IDNDS_IS_CLOSED(dp)) {
		dp->dxp = &xphase_nego;
		IDN_XSTATE_TRANSITION(dp, IDNXS_PEND);
	} else if (dp->dxp != &xphase_nego) {
		if (msg & IDNP_MSGTYPE_MASK) {
			/*
			 * If we already have a connection to somebody
			 * trying to initiate a connection to us, then
			 * possibly we've awaken from a coma or he did.
			 * In any case, dismantle current connection
			 * and attempt to establish a new one.
			 */
			if (dp->dstate == IDNDS_CONNECTED) {
				DOMAINSET_ADD(idn.domset.ds_relink, domid);
				IDN_HISTORY_LOG(IDNH_RELINK, domid,
				    dp->dstate, idn.domset.ds_relink);
				(void) idn_disconnect(domid, IDNFIN_NORMAL,
				    IDNFIN_ARG_NONE, IDNFIN_SYNC_YES);
			} else {
				mt.mt_mtype = IDNP_NACK;
				mt.mt_atype = msg;

				CLR_XARGS(nargs);

				if (DOMAIN_IN_SET(idn.domset.ds_hitlist,
				    domid)) {
					SET_XARGS_NACK_TYPE(nargs,
					    IDNNACK_EXIT);
				} else {
					int	new_masterid;
					int	new_cpuid = IDN_NIL_DCPU;

					SET_XARGS_NACK_TYPE(nargs,
					    IDNNACK_RETRY);
					IDN_GLOCK_SHARED();
					new_masterid = IDN_GET_NEW_MASTERID();
					if (new_masterid == IDN_NIL_DOMID)
						new_masterid =
						    IDN_GET_MASTERID();
					if (new_masterid != IDN_NIL_DOMID) {
						idn_domain_t	*mdp;

						mdp = &idn_domain[new_masterid];
						new_cpuid = mdp->dcpu;
					}
					SET_XARGS_NACK_ARG1(nargs,
					    new_masterid);
					SET_XARGS_NACK_ARG2(nargs, new_cpuid);
					IDN_GUNLOCK();
				}
				idn_send_acknack(domid, &mt, nargs);
			}
		}
		return (0);
	}

	(void) idn_xphase_transition(domid, mtp, xargs);

	return (0);
}

/*ARGSUSED1*/
static void
idn_retry_nego(uint_t token, void *arg)
{
	int		domid = IDN_RETRY_TOKEN2DOMID(token);
	int		new_masterid;
	idn_domain_t	*dp = &idn_domain[domid];
	idn_xdcargs_t	xargs;
	procname_t	proc = "idn_retry_nego";

	ASSERT(IDN_RETRY_TOKEN2TYPE(token) == IDNRETRY_NEGO);

	IDN_SYNC_LOCK();
	IDN_DLOCK_EXCL(domid);

	if (dp->dxp != &xphase_nego) {
		STRING(str);

#ifdef DEBUG
		if (dp->dxp) {
			INUM2STR(dp->dxp->xt_msgtype, str);
		}
#endif /* DEBUG */

		PR_PROTO("%s:%d: dxp(%s) != NEGO...bailing...\n",
		    proc, domid, dp->dxp ? str : "NULL");
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return;
	}

	if (dp->dxstate != IDNXS_PEND) {
		PR_PROTO("%s:%d: xstate(%s) != %s...bailing\n",
		    proc, domid, idnxs_str[dp->dxstate],
		    idnxs_str[IDNXS_PEND]);
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return;
	}

	IDN_GLOCK_SHARED();
	if (idn.state == IDNGS_RECONFIG) {
		/*
		 * Have to try again later after
		 * reconfig has completed.
		 */
		PR_PROTO("%s:%d: reconfig in-progress...try later\n",
		    proc, domid);
		idn_retry_submit(idn_retry_nego, NULL, token,
		    idn_msg_retrytime[IDNP_NEGO]);
		IDN_GUNLOCK();
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return;
	}
	new_masterid = IDN_GET_NEW_MASTERID();
	if ((idn.state == IDNGS_CONNECT) &&
	    (new_masterid != IDN_NIL_DOMID) &&
	    (domid != new_masterid) &&
	    (idn.localid != new_masterid)) {
		/*
		 * We have a new master pending and this
		 * guy isn't it.  Wait until the local domain
		 * has a chance to connect with the new
		 * master before going forward with this
		 * guy.
		 */
		PR_PROTO("%s:%d: waiting for connect to new master %d\n",
		    proc, domid, IDN_GET_NEW_MASTERID());
		idn_retry_submit(idn_retry_nego, NULL, token,
		    idn_msg_retrytime[IDNP_NEGO]);
		IDN_GUNLOCK();
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return;
	}
	IDN_GUNLOCK();

	(void) idn_xphase_transition(domid, NULL, xargs);

	IDN_DUNLOCK(domid);
	IDN_SYNC_UNLOCK();
}

static int
idn_check_nego(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	int		d, new_masterid, masterid;
	int		cpuid, m_cpuid = -1;
	uint_t		dmask;
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	idn_domain_t	*dp, *ldp;
	domainset_t	con_set, pending_set;
	idnneg_dset_t	dset;
	procname_t	proc = "idn_check_nego";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	dp = &idn_domain[domid];
	ldp = &idn_domain[idn.localid];

	if (msg & IDNP_NACK) {
		if (GET_XARGS_NACK_TYPE(xargs) == IDNNACK_EXIT) {
			PR_HITLIST("%s:%d(%s): (msg=%x) EXIT received, "
			    "adding to hitlist %x -> %x\n",
			    proc, domid, idnds_str[dp->dstate], msg,
			    idn.domset.ds_hitlist,
			    idn.domset.ds_hitlist | DOMAINSET(domid));

			DOMAINSET_ADD(idn.domset.ds_hitlist, domid);
			return (-1);
		} else {
			return (0);
		}
	}

	if (DOMAIN_IN_SET(idn.domset.ds_hitlist, domid)) {
		PR_HITLIST("%s:%d(%s): (msg=%x) domain in hitlist (%x) - "
		    "exiting phase\n",
		    proc, domid, idnds_str[dp->dstate], msg,
		    idn.domset.ds_hitlist);
		return (-1);
	}

	if ((dp->dstate == IDNDS_NEGO_PEND) && (msg & IDNP_MSGTYPE_MASK) &&
	    (msg & IDNP_ACK))		/* nego+ack */
		return (1);

	dmask = (uint_t)-1;

	IDN_GLOCK_EXCL();
	if (idn.state == IDNGS_DISCONNECT) {
		PR_PROTO("%s:%d: DISCONNECT in-progress >>> EXIT\n",
		    proc, domid);
		IDN_GUNLOCK();
		return (-1);
	} else if (idn.state == IDNGS_OFFLINE) {
		IDN_GSTATE_TRANSITION(IDNGS_CONNECT);
		IDN_PREP_HWINIT();
		IDN_DLOCK_EXCL(idn.localid);
		ldp->dvote.v.connected = 0;
		IDN_DUNLOCK(idn.localid);
	}

	if (!DOMAIN_IN_SET(idn.domset.ds_trans_on, domid)) {
		DOMAINSET_ADD(idn.domset.ds_trans_on, domid);
		IDN_HISTORY_LOG(IDNH_NEGO, domid,
		    idn.domset.ds_trans_on,
		    idn.domset.ds_connected);
	}

	switch (idn.state) {
	case IDNGS_RECONFIG:
		PR_PROTO("%s:%d: RECONFIG in-progress >>> RETRY\n",
		    proc, domid);
		IDN_GUNLOCK();
		return (1);

	case IDNGS_CONNECT:
		new_masterid = IDN_GET_NEW_MASTERID();
		if ((new_masterid != IDN_NIL_DOMID) &&
		    (domid != new_masterid) &&
		    (idn.localid != new_masterid)) {
			PR_PROTO("%s:%d: waiting for connect to "
			    "new master %d\n",
			    proc, domid, IDN_GET_NEW_MASTERID());
			IDN_GUNLOCK();
			return (1);
		}
		break;

	default:
		break;
	}

	ASSERT((idn.state == IDNGS_CONNECT) || (idn.state == IDNGS_ONLINE));

	con_set = 0;

	if (msg) {
		idn_domain_t	*mdp;
		idn_vote_t	vote;

		vote.ticket = GET_XARGS_NEGO_TICKET(xargs);
		/*
		 * Sender should note have set master bit,
		 * but just in case clear it so local domain
		 * doesn't get confused.
		 */
		vote.v.master = 0;
		dp->dvote.ticket = vote.ticket;
		GET_XARGS_NEGO_DSET(xargs, dset);
		/*LINTED*/
		IDNNEG_DSET_GET_MASK(dset, domid, dmask);
		IDNNEG_DSET_GET_MASTER(dset, new_masterid);
		if (new_masterid == IDNNEG_NO_MASTER) {
			new_masterid = IDN_NIL_DOMID;
		} else {
			/*
			 * Remote domain has a master.  Find
			 * his cpuid in the dset.  We may need
			 * it to initiate a connection.
			 */
			if (new_masterid == domid) {
				m_cpuid = dp->dcpu;
			} else {
				IDNNEG_DSET_GET(dset, new_masterid, m_cpuid,
				    dmask);
				if (m_cpuid == -1) {
					/*
					 * Something is bogus if remote domain
					 * is reporting a valid masterid, but
					 * doesn't have the cpuid for it.
					 */
					cmn_err(CE_WARN,
					    "IDN: 209: remote domain (ID "
					    "%d, CPU %d) reporting master "
					    "(ID %d) without CPU ID",
					    domid, dp->dcpu, new_masterid);
					DOMAINSET_ADD(idn.domset.ds_hitlist,
					    domid);
					IDN_GUNLOCK();
					return (-1);
				}
			}
		}

		for (d = 0; d < MAX_DOMAINS; d++) {
			if ((d == idn.localid) || (d == domid))
				continue;
			IDNNEG_DSET_GET(dset, d, cpuid, dmask);
			if (cpuid != -1) {
				DOMAINSET_ADD(con_set, d);
			}
		}

#ifdef DEBUG
		if (idn.domset.ds_hitlist) {
			PR_HITLIST("%s:%d: con_set %x -> %x (hitlist = %x)\n",
			    proc, domid, con_set,
			    con_set & ~idn.domset.ds_hitlist,
			    idn.domset.ds_hitlist);
		}
#endif /* DEBUG */

		con_set &= ~idn.domset.ds_hitlist;

		ASSERT(!DOMAIN_IN_SET(con_set, idn.localid));
		ASSERT(!DOMAIN_IN_SET(con_set, domid));

		if ((new_masterid != IDN_NIL_DOMID) &&
		    DOMAIN_IN_SET(idn.domset.ds_hitlist, new_masterid)) {
			PR_HITLIST("%s:%d: new_mstr %d -> -1 (hitlist = %x)\n",
			    proc, domid, new_masterid,
			    idn.domset.ds_hitlist);
			IDN_GUNLOCK();
			return (1);
		}

		if (idn_select_master(domid, new_masterid, m_cpuid) < 0) {
			/*
			 * Returns w/GLOCK dropped if error.
			 */
			return (1);
		}

		masterid = IDN_GET_MASTERID();
		ASSERT(masterid != IDN_NIL_DOMID);

		if (idn.state == IDNGS_CONNECT) {
			/*
			 * This is the initial connection for
			 * the local domain.
			 */
			IDN_DLOCK_EXCL(idn.localid);

			if (masterid == idn.localid) {
				if (idn_master_init() < 0) {
					cmn_err(CE_WARN,
					    "IDN: 210: failed to init "
					    "MASTER context");
					ldp->dvote.v.master = 0;
					IDN_DUNLOCK(idn.localid);
					IDN_GSTATE_TRANSITION(IDNGS_DISCONNECT);
					IDN_SET_MASTERID(IDN_NIL_DOMID);
					IDN_GUNLOCK();
					return (-1);
				}
				DSLAB_LOCK_EXCL(idn.localid);
				ldp->dslab_state = DSLAB_STATE_LOCAL;
				DSLAB_UNLOCK(idn.localid);
				ldp->dvote.v.connected = 1;
			} else {
				/*
				 * Either the remote domain is the
				 * master or its a new slave trying
				 * to connect to us.  We can't allow
				 * further progress until we've
				 * sync'd up with the master.
				 */
				if (masterid != domid) {
					IDN_DUNLOCK(idn.localid);
					IDN_GUNLOCK();
					return (1);
				}
				DSLAB_LOCK_EXCL(idn.localid);
				ldp->dslab_state = DSLAB_STATE_REMOTE;
				DSLAB_UNLOCK(idn.localid);
			}
			IDN_DUNLOCK(idn.localid);
			/*
			 * We've sync'd up with the new master.
			 */
			IDN_GSTATE_TRANSITION(IDNGS_ONLINE);
		}

		mdp = &idn_domain[masterid];

		if ((masterid != domid) && !IDNDS_CONFIG_DONE(mdp)) {
			/*
			 * We can't progress any further with
			 * other domains until we've exchanged all
			 * the necessary CFG info with the master,
			 * i.e. until we have a mailbox area from
			 * which we can allocate mailboxes to
			 * other domains.
			 */
			PR_PROTO("%s:%d: still exchanging CFG "
			    "w/master(%d)\n", proc, domid, masterid);
			IDN_GUNLOCK();
			return (1);
		}

		DSLAB_LOCK_EXCL(domid);
		dp->dslab_state = ldp->dslab_state;
		DSLAB_UNLOCK(domid);
		if (idn.state != IDNGS_ONLINE) {
			IDN_GSTATE_TRANSITION(IDNGS_ONLINE);
		}
	}

	IDN_GUNLOCK();

	pending_set = con_set;
	pending_set &= ~(idn.domset.ds_trans_on | idn.domset.ds_connected);
	idn.domset.ds_trans_on |= pending_set;

	con_set |= idn.domset.ds_trans_on | idn.domset.ds_connected;
	con_set &= ~idn.domset.ds_trans_off;
	DOMAINSET_ADD(con_set, idn.localid);

	if (dp->dsync.s_cmd != IDNSYNC_CONNECT) {
		idn_sync_exit(domid, IDNSYNC_DISCONNECT);
		idn_sync_enter(domid, IDNSYNC_CONNECT,
		    con_set, DOMAINSET(idn.localid), idn_xstate_transfunc,
		    (void *)IDNP_CON);
	}

	/*
	 * Get this domain registered as an expected domain on
	 * the remaining domains in the CONNECT synchronization.
	 */
	(void) idn_sync_register(domid, IDNSYNC_CONNECT, 0, IDNSYNC_REG_NEW);

	/*
	 * Note that if (msg == 0), i.e. then there will be
	 * no dset and also pending_set will be 0.
	 * So, the following loop will never attempt to
	 * look at the dset unless (msg != 0), implying
	 * that we've been through the initial code above
	 * and have initialized dmask.
	 */
	ASSERT(pending_set ? (dmask != (uint_t)-1) : 1);

	for (d = 0; d < MAX_DOMAINS; d++) {
		int	rv;

		if (!DOMAIN_IN_SET(pending_set, d))
			continue;

		ASSERT((d != idn.localid) && (d != domid));

		dp = &idn_domain[d];

		IDNNEG_DSET_GET(dset, d, cpuid, dmask);
		if (cpuid == -1) {
			PR_PROTO("%s:%d: failed to get cpuid from dset "
			    "for domain %d (pset = 0x%x)\n",
			    proc, domid, d, pending_set);
			DOMAINSET_DEL(idn.domset.ds_trans_on, d);
			continue;
		}

		IDN_DLOCK_EXCL(d);
		if ((rv = idn_open_domain(d, cpuid, 0)) != 0) {
			PR_PROTO("%s:%d: failed "
			    "idn_open_domain(%d,%d,0) (rv = %d)\n",
			    proc, domid, d, cpuid, rv);
			if (rv < 0) {
				cmn_err(CE_WARN,
				    "IDN: 205: (%s) failed to "
				    "open-domain(%d,%d)",
				    proc, d, cpuid);
				DOMAINSET_DEL(idn.domset.ds_trans_on, d);
			} else if (DOMAIN_IN_SET(idn.domset.ds_trans_off, d)) {
				/*
				 * We've requested to connect to a domain
				 * from which we're disconnecting.  We
				 * better mark this guy for relinking.
				 */
				DOMAINSET_ADD(idn.domset.ds_relink, d);
				IDN_HISTORY_LOG(IDNH_RELINK, d, dp->dstate,
				    idn.domset.ds_relink);
			}
			IDN_DUNLOCK(d);
			continue;
		}

		(void) idn_connect(d);

		IDN_DUNLOCK(d);
	}

	return (0);
}

/*ARGSUSED*/
static void
idn_action_nego_pend(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	idn_msgtype_t	mt;
	domainset_t	con_set;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	con_set = idn.domset.ds_trans_on | idn.domset.ds_connected;
	con_set &= ~idn.domset.ds_trans_off;

	if (!msg) {
		(void) idn_send_nego(domid, NULL, con_set);
	} else {
		mt.mt_mtype = IDNP_NEGO | IDNP_ACK;
		mt.mt_atype = 0;
		mt.mt_cookie = mtp->mt_cookie;
		(void) idn_send_nego(domid, &mt, con_set);
	}
}

/*ARGSUSED*/
static void
idn_error_nego(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	int	new_masterid, new_cpuid;
	int	retry = 1;
	uint_t	msg = mtp ? mtp->mt_mtype : 0;
	uint_t	token;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (msg & IDNP_NACK) {
		idn_nack_t	nack;

		nack = GET_XARGS_NACK_TYPE(xargs);
		switch (nack) {
		case IDNNACK_RETRY:
			new_masterid = (int)GET_XARGS_NACK_ARG1(xargs);
			new_cpuid    = (int)GET_XARGS_NACK_ARG2(xargs);
			break;

		case IDNNACK_EXIT:
			retry = 0;
			/*FALLTHROUGH*/

		default:
			new_masterid = IDN_NIL_DOMID;
			new_cpuid    = IDN_NIL_DCPU;
			break;
		}
		idn_nego_cleanup_check(domid, new_masterid, new_cpuid);
	}

	if (msg & IDNP_MSGTYPE_MASK) {
		idn_msgtype_t	mt;
		idn_xdcargs_t	nargs;

		mt.mt_mtype = IDNP_NACK;
		mt.mt_atype = msg;
		mt.mt_cookie = mtp->mt_cookie;
		CLR_XARGS(nargs);
		SET_XARGS_NACK_TYPE(nargs, IDNNACK_RETRY);
		IDN_GLOCK_SHARED();
		new_masterid = IDN_GET_NEW_MASTERID();
		if (new_masterid == IDN_NIL_DOMID)
			new_masterid = IDN_GET_MASTERID();
		if (new_masterid != IDN_NIL_DOMID)
			new_cpuid = idn_domain[new_masterid].dcpu;
		else
			new_cpuid = IDN_NIL_DCPU;
		SET_XARGS_NACK_ARG1(nargs, new_masterid);
		SET_XARGS_NACK_ARG2(nargs, new_cpuid);
		IDN_GUNLOCK();
		idn_send_acknack(domid, &mt, nargs);
	}

	if (retry) {
		token = IDN_RETRY_TOKEN(domid, IDNRETRY_NEGO);
		idn_retry_submit(idn_retry_nego, NULL, token,
		    idn_msg_retrytime[(int)IDNRETRY_NEGO]);
	} else {
		DOMAINSET_DEL(idn.domset.ds_relink, domid);
		IDN_RESET_COOKIES(domid);
		(void) idn_disconnect(domid, IDNFIN_NORMAL, IDNFIN_ARG_NONE,
		    IDNDS_SYNC_TYPE(&idn_domain[domid]));
	}
}

/*ARGSUSED*/
static void
idn_action_nego_sent(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	domainset_t	conset;
	idn_msgtype_t	mt;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	mt.mt_cookie = mtp ? mtp->mt_cookie : 0;

	conset = idn.domset.ds_trans_on | idn.domset.ds_connected;
	conset &= ~idn.domset.ds_trans_off;

	if ((msg & IDNP_ACKNACK_MASK) == 0) {
		/*
		 * nego
		 */
		mt.mt_mtype = IDNP_NEGO | IDNP_ACK;
		mt.mt_atype = 0;
		(void) idn_send_nego(domid, &mt, conset);
	} else if (msg & IDNP_MSGTYPE_MASK) {
		int		d;
		idn_xdcargs_t	nargs;
		idnneg_dset_t	dset;
		uint_t		dmask;
		idn_vote_t	vote;

		mt.mt_mtype = IDNP_ACK;
		mt.mt_atype = msg;
		DOMAINSET_DEL(conset, idn.localid);
		DOMAINSET_DEL(conset, domid);

		dmask = IDNNEG_DSET_MYMASK();
		IDNNEG_DSET_INIT(dset, dmask);
		for (d = 0; d < MAX_DOMAINS; d++) {
			int	cpuid;

			if (!DOMAIN_IN_SET(conset, d))
				continue;

			if ((cpuid = idn_domain[d].dcpu) == IDN_NIL_DCPU)
				continue;

			IDNNEG_DSET_SET(dset, d, cpuid, dmask);
		}
		IDNNEG_DSET_SET_MASTER(dset, domid, IDN_GET_MASTERID());
		ASSERT((IDN_GET_MASTERID() != IDN_NIL_DOMID) ?
		    (idn_domain[IDN_GET_MASTERID()].dcpu != IDN_NIL_DCPU) : 1);
		vote.ticket = idn_domain[idn.localid].dvote.ticket;
		vote.v.master = 0;
		CLR_XARGS(nargs);
		SET_XARGS_NEGO_TICKET(nargs, vote.ticket);
		SET_XARGS_NEGO_DSET(nargs, dset);
		/*
		 * nego+ack
		 */
		idn_send_acknack(domid, &mt, nargs);
	} else {
		uint_t		token;
		int		new_masterid, new_cpuid;
		int		retry = 1;
		idn_nack_t	nack;
		/*
		 * nack - retry
		 *
		 * It's possible if we've made it this far that
		 * we may have already chosen a master and this
		 * dude might be it!  If it is we need to clean up.
		 */
		nack = GET_XARGS_NACK_TYPE(xargs);
		switch (nack) {
		case IDNNACK_RETRY:
			new_masterid = (int)GET_XARGS_NACK_ARG1(xargs);
			new_cpuid = (int)GET_XARGS_NACK_ARG2(xargs);
			break;

		case IDNNACK_EXIT:
			retry = 0;
			/*FALLTHROUGH*/

		default:
			new_masterid = IDN_NIL_DOMID;
			new_cpuid = IDN_NIL_DCPU;
			break;
		}

		idn_nego_cleanup_check(domid, new_masterid, new_cpuid);

		if (retry) {
			token = IDN_RETRY_TOKEN(domid, IDNRETRY_NEGO);
			idn_retry_submit(idn_retry_nego, NULL, token,
			    idn_msg_retrytime[(int)IDNRETRY_NEGO]);
		} else {
			DOMAINSET_DEL(idn.domset.ds_relink, domid);
			IDN_RESET_COOKIES(domid);
			(void) idn_disconnect(domid, IDNFIN_NORMAL,
			    IDNFIN_ARG_NONE,
			    IDNDS_SYNC_TYPE(&idn_domain[domid]));
		}
	}
}

/*ARGSUSED*/
static void
idn_action_nego_rcvd(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t	msg = mtp ? mtp->mt_mtype : 0;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (msg & IDNP_NACK) {
		uint_t		token;
		int		new_masterid, new_cpuid;
		int		retry = 1;
		idn_nack_t	nack;
		/*
		 * nack - retry.
		 *
		 * At this stage of receiving a nack we need to
		 * check whether we need to start over again with
		 * selecting a new master.
		 */
		nack = GET_XARGS_NACK_TYPE(xargs);
		switch (nack) {
		case IDNNACK_RETRY:
			new_masterid = (int)GET_XARGS_NACK_ARG1(xargs);
			new_cpuid = (int)GET_XARGS_NACK_ARG2(xargs);
			break;

		case IDNNACK_EXIT:
			retry = 0;
			/*FALLTHROUGH*/

		default:
			new_masterid = IDN_NIL_DOMID;
			new_cpuid = IDN_NIL_DCPU;
			break;
		}

		idn_nego_cleanup_check(domid, new_masterid, new_cpuid);

		if (retry) {
			token = IDN_RETRY_TOKEN(domid, IDNRETRY_NEGO);
			idn_retry_submit(idn_retry_nego, NULL, token,
			    idn_msg_retrytime[(int)IDNRETRY_NEGO]);
		} else {
			DOMAINSET_DEL(idn.domset.ds_relink, domid);
			IDN_RESET_COOKIES(domid);
			(void) idn_disconnect(domid, IDNFIN_NORMAL,
			    IDNFIN_ARG_NONE,
			    IDNDS_SYNC_TYPE(&idn_domain[domid]));
		}
	}
}

static void
idn_final_nego(int domid)
{
	idn_domain_t	*dp = &idn_domain[domid];

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	(void) idn_retry_terminate(IDN_RETRY_TOKEN(domid, IDNRETRY_NEGO));

	ASSERT(dp->dstate == IDNDS_CONFIG);

	dp->dxp = NULL;
	IDN_XSTATE_TRANSITION(dp, IDNXS_NIL);

	idn_send_config(domid, 1);
}

/*
 */
/*ARGSUSED1*/
static void
idn_exit_nego(int domid, uint_t msgtype)
{
	idn_domain_t	*dp;
	idn_fin_t	fintype;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	dp = &idn_domain[domid];

	fintype = msgtype ? IDNFIN_NORMAL : IDNFIN_FORCE_HARD;

	(void) idn_retry_terminate(IDN_RETRY_TOKEN(domid, IDNRETRY_NEGO));

	ASSERT(!DOMAIN_IN_SET(idn.domset.ds_connected, domid));
	ASSERT(!DOMAIN_IN_SET(idn.domset.ds_ready_on, domid));
	ASSERT(dp->dxp == &xphase_nego);

	idn_nego_cleanup_check(domid, IDN_NIL_DOMID, IDN_NIL_DCPU);

	IDN_GLOCK_SHARED();
	if ((idn.state != IDNGS_DISCONNECT) &&
	    !DOMAIN_IN_SET(idn.domset.ds_hitlist, domid)) {
		DOMAINSET_ADD(idn.domset.ds_relink, domid);
		IDN_HISTORY_LOG(IDNH_RELINK, domid, dp->dstate,
		    idn.domset.ds_relink);
	} else {
		idn_update_op(IDNOP_ERROR, DOMAINSET(domid), NULL);
		DOMAINSET_DEL(idn.domset.ds_relink, domid);
	}
	IDN_GUNLOCK();
	/*
	 * Reset send cookie to 0 so that receiver does not validate
	 * cookie.  This is necessary since at this early stage it's
	 * possible we may not have exchanged appropriate cookies.
	 */
	IDN_RESET_COOKIES(domid);
	(void) idn_disconnect(domid, fintype, IDNFIN_ARG_NONE,
	    IDNDS_SYNC_TYPE(dp));
}

static void
idn_nego_cleanup_check(int domid, int new_masterid, int new_cpuid)
{
	idn_domain_t	*ldp, *dp;
	procname_t	proc = "idn_nego_cleanup_check";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	dp = &idn_domain[domid];
	ldp = &idn_domain[idn.localid];

	IDN_GLOCK_EXCL();

	if (((idn.state == IDNGS_ONLINE) && !idn.domset.ds_connected) ||
	    (idn.state == IDNGS_CONNECT)) {
		domainset_t	trans_on;
		int		masterid;
		int		retry_domid = IDN_NIL_DOMID;
		int		rv;

		IDN_DLOCK_EXCL(idn.localid);
		masterid = (idn.state == IDNGS_ONLINE) ?
		    IDN_GET_MASTERID() : IDN_GET_NEW_MASTERID();
		trans_on = idn.domset.ds_trans_on;
		DOMAINSET_DEL(trans_on, domid);
		if (trans_on == 0) {
			int		d;
			domainset_t	relink = idn.domset.ds_relink;
			/*
			 * This was the only guy we were trying
			 * to connect with.
			 */
			ASSERT((idn.state == IDNGS_ONLINE) ?
			    ((idn.localid == masterid) ||
			    (domid == masterid)) : 1);
			if (idn.localid == masterid)
				idn_master_deinit();
			ldp->dvote.v.connected = 0;
			ldp->dvote.v.master = 0;
			dp->dvote.v.master = 0;
			IDN_SET_MASTERID(IDN_NIL_DOMID);
			IDN_SET_NEW_MASTERID(new_masterid);
			IDN_GSTATE_TRANSITION(IDNGS_CONNECT);
			IDN_PREP_HWINIT();
			IDN_DUNLOCK(idn.localid);
			IDN_GUNLOCK();
			/*
			 * If there's a new master available then
			 * just try and relink with him unless
			 * it's ourself.
			 */
			if ((new_masterid != IDN_NIL_DOMID) &&
			    (new_masterid != idn.localid) &&
			    (new_masterid != domid)) {
				IDN_DLOCK_EXCL(new_masterid);
				rv = idn_open_domain(new_masterid,
				    new_cpuid, 0);
				if (rv < 0) {
					cmn_err(CE_WARN,
					    "IDN: 205: (%s) failed to "
					    "open-domain(%d,%d)",
					    proc, new_masterid, new_cpuid);
					IDN_GLOCK_EXCL();
					IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);
					IDN_GUNLOCK();
				} else {
					relink = DOMAINSET(new_masterid);
				}
				IDN_DUNLOCK(new_masterid);
			}
			DOMAINSET_DEL(relink, domid);
			if (relink)
				for (d = 0; d < MAX_DOMAINS; d++) {
					if (!DOMAIN_IN_SET(relink, d))
						continue;
					retry_domid = d;
					break;
				}
		} else if (domid == masterid) {
			/*
			 * There are other domains we were trying
			 * to connect to.  As long as the chosen
			 * master was somebody other then this
			 * domain that nack'd us, life is cool, but
			 * if it was this remote domain we'll need
			 * to start over.
			 */
			IDN_DUNLOCK(idn.localid);
			dp->dvote.v.master = 0;
			IDN_SET_MASTERID(IDN_NIL_DOMID);
			IDN_SET_NEW_MASTERID(new_masterid);

			if (idn.state == IDNGS_ONLINE) {
				IDN_GKSTAT_GLOBAL_EVENT(gk_reconfigs,
				    gk_reconfig_last);
				IDN_GSTATE_TRANSITION(IDNGS_RECONFIG);
				IDN_GUNLOCK();
				idn_unlink_domainset(trans_on, IDNFIN_NORMAL,
				    IDNFIN_ARG_NONE,
				    IDNFIN_OPT_RELINK,
				    BOARDSET_ALL);
			} else if ((new_masterid != IDN_NIL_DOMID) &&
			    (new_masterid != idn.localid) &&
			    (new_masterid != domid) &&
			    !DOMAIN_IN_SET(trans_on, new_masterid)) {
				IDN_GUNLOCK();
				IDN_DLOCK_EXCL(new_masterid);
				rv = idn_open_domain(new_masterid,
				    new_cpuid, 0);
				IDN_GLOCK_EXCL();
				IDN_DUNLOCK(new_masterid);
				if (rv < 0) {
					cmn_err(CE_WARN,
					    "IDN: 205: (%s) failed to "
					    "open-domain(%d,%d)",
					    proc, new_masterid,
					    new_cpuid);
					IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);
					new_masterid = IDN_NIL_DOMID;
				} else {
					retry_domid = new_masterid;
				}
				IDN_GUNLOCK();
			} else {
				IDN_GUNLOCK();
			}
		} else {
			IDN_DUNLOCK(idn.localid);
			IDN_GUNLOCK();
		}
		if (retry_domid != IDN_NIL_DOMID) {
			uint_t		token;
			idn_domain_t	*rdp = &idn_domain[retry_domid];

			IDN_DLOCK_EXCL(retry_domid);
			rdp->dxp = &xphase_nego;
			IDN_XSTATE_TRANSITION(rdp, IDNXS_PEND);
			IDN_DUNLOCK(retry_domid);
			token = IDN_RETRY_TOKEN(retry_domid, IDNRETRY_NEGO);
			idn_retry_submit(idn_retry_nego, NULL, token,
			    idn_msg_retrytime[(int)IDNRETRY_NEGO]);
		}
	} else {
		IDN_GUNLOCK();
	}
}

static int
idn_send_con(int domid, idn_msgtype_t *mtp, idn_con_t contype, domainset_t
    conset)
{
	idn_msgtype_t	mt;
	uint_t		acknack;
	procname_t	proc = "idn_send_con";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (mtp) {
		acknack = mtp->mt_mtype & IDNP_ACKNACK_MASK;
		mt.mt_mtype = mtp->mt_mtype;
		mt.mt_atype = mtp->mt_atype;
		mt.mt_cookie = mtp->mt_cookie;
	} else {
		acknack = 0;
		mt.mt_mtype = IDNP_CON;
		mt.mt_atype = 0;
		/*
		 * For simple CON queries we want a unique
		 * timer assigned.  For others, they
		 * effectively share one.
		 */
		if (contype == IDNCON_QUERY)
			mt.mt_cookie = 0;
		else
			mt.mt_cookie = IDN_TIMER_PUBLIC_COOKIE;
	}

	ASSERT((contype == IDNCON_QUERY) ? idn_domain[domid].dcookie_send : 1);

	PR_PROTO("%s:%d: sending con%sto (cpu %d) [ct=%s, cs=0x%x]\n",
	    proc, domid,
	    (acknack & IDNP_ACK) ? "+ack " :
	    (acknack & IDNP_NACK) ? "+nack " : " ",
	    idn_domain[domid].dcpu,
	    idncon_str[contype], conset);

	IDN_MSGTIMER_START(domid, IDNP_CON, (ushort_t)contype,
	    idn_msg_waittime[IDNP_CON], &mt.mt_cookie);

	IDNXDC(domid, &mt, (uint_t)contype, (uint_t)conset, 0, 0);

	return (0);
}

/*
 * Must leave w/DLOCK dropped and SYNC_LOCK held.
 */
static int
idn_recv_con(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	uint_t		msgarg = mtp ? mtp->mt_atype : 0;
	idn_con_t	contype;
	domainset_t	my_ready_set, ready_set;
	idn_msgtype_t	mt;
	idn_domain_t	*dp = &idn_domain[domid];
	idn_xdcargs_t	aargs;
	procname_t	proc = "idn_recv_con";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	mt.mt_cookie = mtp ? mtp->mt_cookie : 0;

	contype   = GET_XARGS_CON_TYPE(xargs);
	ready_set = GET_XARGS_CON_DOMSET(xargs);

	CLR_XARGS(aargs);

	if (!(msg & IDNP_NACK) && (contype == IDNCON_QUERY)) {
		domainset_t	query_set;

		query_set = idn_sync_register(domid, IDNSYNC_CONNECT,
		    ready_set, IDNSYNC_REG_REG);

		my_ready_set = idn.domset.ds_connected | idn.domset.ds_ready_on;
		my_ready_set &= ~idn.domset.ds_trans_off;
		DOMAINSET_ADD(my_ready_set, idn.localid);

		if (msg & IDNP_MSGTYPE_MASK) {
			mt.mt_mtype = IDNP_ACK;
			mt.mt_atype = IDNP_CON;
			SET_XARGS_CON_TYPE(aargs, contype);
			SET_XARGS_CON_DOMSET(aargs, my_ready_set);
			idn_send_acknack(domid, &mt, aargs);
		}

		if (query_set) {
			uint_t	token;

			token = IDN_RETRY_TOKEN(domid, IDNRETRY_CONQ);
			idn_retry_submit(idn_retry_query, NULL, token,
			    idn_msg_retrytime[(int)IDNRETRY_CONQ]);
		}

		return (0);
	}

	if (dp->dxp == NULL) {
		STRING(mstr);
		STRING(lstr);
		/*
		 * Must have received an inappropriate error
		 * message as we should already be registered
		 * by the time we reach here.
		 */
		INUM2STR(msg, mstr);
		INUM2STR(msgarg, lstr);

		PR_PROTO("%s:%d: ERROR: NOT YET REGISTERED (%s/%s)\n",
		    proc, domid, mstr, lstr);

		if (msg & IDNP_MSGTYPE_MASK) {
			mt.mt_mtype = IDNP_NACK;
			mt.mt_atype = msg;
			SET_XARGS_NACK_TYPE(aargs, IDNNACK_RETRY);
			idn_send_acknack(domid, &mt, aargs);
		}

		return (-1);
	}

	(void) idn_xphase_transition(domid, mtp, xargs);

	return (0);
}

/*ARGSUSED1*/
static void
idn_retry_con(uint_t token, void *arg)
{
	int		domid = IDN_RETRY_TOKEN2DOMID(token);
	idn_domain_t	*dp = &idn_domain[domid];
	idn_xdcargs_t	xargs;
	procname_t	proc = "idn_retry_con";

	ASSERT(IDN_RETRY_TOKEN2TYPE(token) == IDNRETRY_CON);

	IDN_SYNC_LOCK();
	IDN_DLOCK_EXCL(domid);

	if (dp->dxp != &xphase_con) {
		STRING(str);

#ifdef DEBUG
		if (dp->dxp) {
			INUM2STR(dp->dxp->xt_msgtype, str);
		}
#endif /* DEBUG */

		PR_PROTO("%s:%d: dxp(%s) != CON...bailing...\n",
		    proc, domid, dp->dxp ? str : "NULL");
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return;
	}

	if ((dp->dsync.s_cmd != IDNSYNC_CONNECT) ||
	    (dp->dxstate != IDNXS_PEND)) {
		PR_PROTO("%s:%d: cmd (%s) and/or xstate (%s) not "
		    "expected (%s/%s)\n",
		    proc, domid, idnsync_str[dp->dsync.s_cmd],
		    idnxs_str[dp->dxstate], idnsync_str[IDNSYNC_CONNECT],
		    idnxs_str[IDNXS_PEND]);
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return;
	}

	(void) idn_xphase_transition(domid, NULL, xargs);

	IDN_DUNLOCK(domid);
	IDN_SYNC_UNLOCK();
}

static int
idn_check_con(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	int		ready;
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	idn_domain_t	*dp = &idn_domain[domid];
	domainset_t	ready_set, my_ready_set, query_set;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (msg & IDNP_NACK)
		return (0);

	if ((dp->dstate == IDNDS_CON_PEND) &&
	    (msg & IDNP_MSGTYPE_MASK) && (msg & IDNP_ACK))	/* con+ack */
		return (1);

	if (msg == 0) {
		ready_set = idn.domset.ds_connected &
		    ~idn.domset.ds_trans_off;
	} else {
		ready_set = GET_XARGS_CON_DOMSET(xargs);
		DOMAINSET_ADD(idn.domset.ds_ready_on, domid);
	}

	DOMAINSET_ADD(ready_set, idn.localid);

	query_set = idn_sync_register(domid, IDNSYNC_CONNECT,
	    ready_set, IDNSYNC_REG_REG);
	/*
	 * No need to query this domain as he's already
	 * in the CON sequence.
	 */
	DOMAINSET_DEL(query_set, domid);

	ready = (dp->dsync.s_set_exp == dp->dsync.s_set_rdy) ? 1 : 0;
	if (ready) {
		DOMAINSET_DEL(idn.domset.ds_ready_on, domid);
		DOMAINSET_ADD(idn.domset.ds_connected, domid);
	}

	if (query_set) {
		int	d;

		my_ready_set = idn.domset.ds_ready_on |
		    idn.domset.ds_connected;
		my_ready_set &= ~idn.domset.ds_trans_off;
		DOMAINSET_ADD(my_ready_set, idn.localid);

		for (d = 0; d < MAX_DOMAINS; d++) {
			if (!DOMAIN_IN_SET(query_set, d))
				continue;

			dp = &idn_domain[d];

			IDN_DLOCK_EXCL(d);
			if ((dp->dsync.s_cmd == IDNSYNC_CONNECT) ||
			    !dp->dcookie_send) {
				IDN_DUNLOCK(d);
				continue;
			}

			IDN_SYNC_QUERY_UPDATE(domid, d);

			(void) idn_send_con(d, NULL, IDNCON_QUERY,
			    my_ready_set);
			IDN_DUNLOCK(d);
		}
	}

	return (!msg ? 0 : (ready ? 0 : 1));
}

/*ARGSUSED2*/
static void
idn_error_con(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t	token;
	uint_t	msg = mtp ? mtp->mt_mtype : 0;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (msg & IDNP_MSGTYPE_MASK) {
		idn_msgtype_t	mt;
		idn_xdcargs_t	nargs;

		mt.mt_mtype = IDNP_NACK;
		mt.mt_atype = msg;
		mt.mt_cookie = mtp->mt_cookie;
		CLR_XARGS(nargs);
		SET_XARGS_NACK_TYPE(nargs, IDNNACK_RETRY);
		idn_send_acknack(domid, &mt, nargs);
	}

	token = IDN_RETRY_TOKEN(domid, IDNRETRY_CON);
	idn_retry_submit(idn_retry_con, NULL, token,
	    idn_msg_retrytime[(int)IDNRETRY_CON]);
}

/*ARGSUSED*/
static void
idn_action_con_pend(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	idn_domain_t	*dp = &idn_domain[domid];
	idn_msgtype_t	mt;
	domainset_t	my_ready_set;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	my_ready_set = dp->dsync.s_set_rdy | idn.domset.ds_ready_on |
	    idn.domset.ds_connected;
	my_ready_set &= ~idn.domset.ds_trans_off;
	DOMAINSET_ADD(my_ready_set, idn.localid);

	if (!msg) {
		(void) idn_send_con(domid, NULL, IDNCON_NORMAL, my_ready_set);
	} else {
		mt.mt_mtype = IDNP_CON | IDNP_ACK;
		mt.mt_atype = 0;
		mt.mt_cookie = mtp->mt_cookie;
		(void) idn_send_con(domid, &mt, IDNCON_NORMAL, my_ready_set);
	}
}

static void
idn_action_con_sent(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	idn_domain_t	*dp = &idn_domain[domid];
	idn_con_t	contype;
	domainset_t	my_ready_set;
	idn_msgtype_t	mt;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	mt.mt_cookie = mtp ? mtp->mt_cookie : 0;

	my_ready_set = dp->dsync.s_set_rdy | idn.domset.ds_ready_on |
	    idn.domset.ds_connected;
	my_ready_set &= ~idn.domset.ds_trans_off;
	DOMAINSET_ADD(my_ready_set, idn.localid);

	contype = GET_XARGS_CON_TYPE(xargs);

	if ((msg & IDNP_ACKNACK_MASK) == 0) {
		/*
		 * con
		 */
		mt.mt_mtype = IDNP_CON | IDNP_ACK;
		mt.mt_atype = 0;
		(void) idn_send_con(domid, &mt, contype, my_ready_set);
	} else if (msg & IDNP_MSGTYPE_MASK) {
		idn_xdcargs_t	cargs;

		mt.mt_mtype = IDNP_ACK;
		mt.mt_atype = msg;
		CLR_XARGS(cargs);
		SET_XARGS_CON_TYPE(cargs, contype);
		SET_XARGS_CON_DOMSET(cargs, my_ready_set);
		/*
		 * con+ack
		 */
		idn_send_acknack(domid, &mt, cargs);
	} else {
		uint_t	token;
		/*
		 * nack - retry
		 */
		token = IDN_RETRY_TOKEN(domid, IDNRETRY_CON);
		idn_retry_submit(idn_retry_con, NULL, token,
		    idn_msg_retrytime[(int)IDNRETRY_CON]);
	}
}

/*ARGSUSED*/
static void
idn_action_con_rcvd(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t	msg = mtp ? mtp->mt_mtype : 0;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (msg & IDNP_NACK) {
		uint_t	token;
		/*
		 * nack - retry
		 */
		token = IDN_RETRY_TOKEN(domid, IDNRETRY_CON);
		idn_retry_submit(idn_retry_con, NULL, token,
		    idn_msg_retrytime[(int)IDNRETRY_CON]);
	}
}

static void
idn_final_con(int domid)
{
	uint_t		targ;
	uint_t		token = IDN_RETRY_TOKEN(domid, IDNRETRY_CON);
	idn_domain_t	*dp = &idn_domain[domid];
	procname_t	proc = "idn_final_con";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	(void) idn_retry_terminate(token);

	dp->dxp = NULL;
	IDN_XSTATE_TRANSITION(dp, IDNXS_NIL);

	idn_sync_exit(domid, IDNSYNC_CONNECT);

	CHECKPOINT_OPENED(IDNSB_CHKPT_LINK, dp->dhw.dh_boardset, 1);

	DOMAINSET_DEL(idn.domset.ds_trans_on, domid);
	DOMAINSET_DEL(idn.domset.ds_relink, domid);
	IDN_FSTATE_TRANSITION(dp, IDNFIN_OFF);

	PR_PROTO("%s:%d: CONNECTED\n", proc, domid);

	if (idn.domset.ds_trans_on == 0) {
		if ((idn.domset.ds_trans_off | idn.domset.ds_relink) == 0) {
			PR_HITLIST("%s:%d: HITLIST %x -> 0\n",
			    proc, domid, idn.domset.ds_hitlist);
			idn.domset.ds_hitlist = 0;
		}
		PR_PROTO("%s:%d: ALL CONNECTED ************ "
		    "(0x%x + 0x%x) = 0x%x\n", proc, domid,
		    DOMAINSET(idn.localid), idn.domset.ds_connected,
		    DOMAINSET(idn.localid) | idn.domset.ds_connected);
	} else {
		PR_PROTO("%s:%d: >>> ds_trans_on = 0x%x, ds_ready_on = 0x%x\n",
		    proc, domid,
		    idn.domset.ds_trans_on, idn.domset.ds_ready_on);
	}

	if (idn_verify_config_mbox(domid)) {
		idnsb_error_t	idnerr;
		/*
		 * Mailbox is not cool. Need to disconnect.
		 */
		INIT_IDNKERR(&idnerr);
		SET_IDNKERR_ERRNO(&idnerr, EPROTO);
		SET_IDNKERR_IDNERR(&idnerr, IDNKERR_SMR_CORRUPTED);
		SET_IDNKERR_PARAM0(&idnerr, domid);
		idn_update_op(IDNOP_ERROR, DOMAINSET(domid), &idnerr);
		/*
		 * We cannot disconnect from an individual domain
		 * unless all domains are attempting to disconnect
		 * from him also, especially now since we touched
		 * the SMR and now we have a potential cache conflicts
		 * with the other domains with respect to this
		 * domain.  Disconnect attempt will effectively
		 * shutdown connection with respective domain
		 * which is the effect we really want anyway.
		 */
		(void) idn_disconnect(domid, IDNFIN_NORMAL, IDNFIN_ARG_SMRBAD,
		    IDNFIN_SYNC_YES);

		return;
	}

	if (lock_try(&idn.first_swlink)) {
		/*
		 * This is our first connection.  Need to
		 * kick some stuff into gear.
		 */
		idndl_dlpi_init();
		(void) idn_activate_channel(CHANSET_ALL, IDNCHAN_ONLINE);

		targ = 0xf0;
	} else {
		targ = 0;
	}

	idn_mainmbox_activate(domid);

	idn_update_op(IDNOP_CONNECTED, DOMAINSET(domid), NULL);

	IDN_GKSTAT_GLOBAL_EVENT(gk_links, gk_link_last);

	membar_stst_ldst();

	IDN_DSTATE_TRANSITION(dp, IDNDS_CONNECTED);
	/*
	 * Need to kick off initial commands in background.
	 * We do not want to do them within the context of
	 * a protocol server because they may sleep and thus
	 * cause the protocol server to incur a soft-deadlock,
	 * i.e. he's sleeping waiting in the slab-waiting area
	 * for a response that will arrive on his protojob
	 * queue, but which he obviously can't process since
	 * he's not waiting on his protojob queue.
	 */
	targ |= domid & 0x0f;
	(void) timeout(idn_link_established, (void *)(uintptr_t)targ, 50);

	cmn_err(CE_NOTE,
	    "!IDN: 200: link (domain %d, CPU %d) connected",
	    dp->domid, dp->dcpu);
}

static void
idn_exit_con(int domid, uint_t msgtype)
{
	idn_domain_t	*dp = &idn_domain[domid];
	idn_fin_t	fintype;
	procname_t	proc = "idn_exit_con";
	STRING(str);

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	INUM2STR(msgtype, str);
	PR_PROTO("%s:%d: msgtype = 0x%x(%s)\n", proc, domid, msgtype, str);

	fintype = msgtype ? IDNFIN_NORMAL : IDNFIN_FORCE_HARD;

	IDN_GLOCK_SHARED();
	if (idn.state != IDNGS_DISCONNECT) {
		DOMAINSET_ADD(idn.domset.ds_relink, domid);
		IDN_HISTORY_LOG(IDNH_RELINK, domid, dp->dstate,
		    idn.domset.ds_relink);
	} else {
		DOMAINSET_DEL(idn.domset.ds_relink, domid);
	}
	IDN_GUNLOCK();

	(void) idn_disconnect(domid, fintype, IDNFIN_ARG_NONE,
	    IDNDS_SYNC_TYPE(dp));
}

static int
idn_send_fin(int domid, idn_msgtype_t *mtp, idn_fin_t fintype, idn_finarg_t
    finarg, idn_finopt_t finopt, domainset_t finset, uint_t finmaster)
{
	int		need_timer = 1;
	uint_t		acknack;
	uint_t		fintypearg = 0;
	idn_msgtype_t	mt;
	idn_domain_t	*dp = &idn_domain[domid];
	procname_t	proc = "idn_send_fin";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_HELD(domid));

	ASSERT((fintype != IDNFIN_QUERY) ? (finopt != IDNFIN_OPT_NONE) : 1);

	if (mtp) {
		acknack = mtp->mt_mtype & IDNP_ACKNACK_MASK;
		mt.mt_mtype = mtp->mt_mtype;
		mt.mt_atype = mtp->mt_atype;
		mt.mt_cookie = mtp->mt_cookie;
	} else {
		acknack = 0;
		mt.mt_mtype = IDNP_FIN;
		mt.mt_atype = 0;
		/*
		 * For simple FIN queries we want a unique
		 * timer assigned.  For others, they
		 * effectively share one.
		 */
		if (fintype == IDNFIN_QUERY)
			mt.mt_cookie = 0;
		else
			mt.mt_cookie = IDN_TIMER_PUBLIC_COOKIE;
	}

	PR_PROTO("%s:%d: sending fin%sto (cpu %d) "
	    "[ft=%s, fa=%s, fs=0x%x, fo=%s, fm=(%d,%d)]\n",
	    proc, domid,
	    (acknack & IDNP_ACK) ? "+ack " :
	    (acknack & IDNP_NACK) ? "+nack " : " ",
	    dp->dcpu, idnfin_str[fintype], idnfinarg_str[finarg],
	    (int)finset, idnfinopt_str[finopt],
	    FIN_MASTER_DOMID(finmaster), FIN_MASTER_CPUID(finmaster));

	if (need_timer) {
		IDN_MSGTIMER_START(domid, IDNP_FIN, (ushort_t)fintype,
		    idn_msg_waittime[IDNP_FIN], &mt.mt_cookie);
	}

	SET_FIN_TYPE(fintypearg, fintype);
	SET_FIN_ARG(fintypearg, finarg);

	IDNXDC(domid, &mt, fintypearg, (uint_t)finset, (uint_t)finopt,
	    finmaster);

	return (0);
}

/*
 * Must leave w/DLOCK dropped and SYNC_LOCK held.
 */
static int
idn_recv_fin(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	idn_fin_t	fintype;
	idn_finarg_t	finarg;
	idn_finopt_t	finopt;
	domainset_t	my_ready_set, ready_set;
	idn_msgtype_t	mt;
	idn_domain_t	*dp = &idn_domain[domid];
	idn_xdcargs_t	aargs;
	procname_t	proc = "idn_recv_fin";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	mt.mt_cookie = mtp ? mtp->mt_cookie : 0;

	fintype   = GET_XARGS_FIN_TYPE(xargs);
	finarg    = GET_XARGS_FIN_ARG(xargs);
	ready_set = GET_XARGS_FIN_DOMSET(xargs);
	finopt    = GET_XARGS_FIN_OPT(xargs);

	CLR_XARGS(aargs);

	if (msg & IDNP_NACK) {
		PR_PROTO("%s:%d: received NACK (type = %s)\n",
		    proc, domid, idnnack_str[xargs[0]]);
	} else {
		PR_PROTO("%s:%d: fintype = %s, finopt = %s, "
		    "finarg = %s, ready_set = 0x%x\n",
		    proc, domid, idnfin_str[fintype],
		    idnfinopt_str[finopt],
		    idnfinarg_str[finarg], ready_set);
	}

	if (!(msg & IDNP_NACK) && (fintype == IDNFIN_QUERY)) {
		domainset_t	query_set;

		query_set = idn_sync_register(domid, IDNSYNC_DISCONNECT,
		    ready_set, IDNSYNC_REG_REG);

		my_ready_set = ~idn.domset.ds_connected |
		    idn.domset.ds_ready_off;

		if (msg & IDNP_MSGTYPE_MASK) {
			mt.mt_mtype = IDNP_ACK;
			mt.mt_atype = IDNP_FIN;
			SET_XARGS_FIN_TYPE(aargs, fintype);
			SET_XARGS_FIN_ARG(aargs, finarg);
			SET_XARGS_FIN_DOMSET(aargs, my_ready_set);
			SET_XARGS_FIN_OPT(aargs, IDNFIN_OPT_NONE);
			SET_XARGS_FIN_MASTER(aargs, NIL_FIN_MASTER);
			idn_send_acknack(domid, &mt, aargs);
		}

		if (query_set) {
			uint_t	token;

			token = IDN_RETRY_TOKEN(domid, IDNRETRY_FINQ);
			idn_retry_submit(idn_retry_query, NULL, token,
			    idn_msg_retrytime[(int)IDNRETRY_FINQ]);
		}

		return (0);
	}

	if (dp->dxp != &xphase_fin) {
		uint_t	token;

		if (IDNDS_IS_CLOSED(dp)) {
			PR_PROTO("%s:%d: domain already closed (%s)\n",
			    proc, domid, idnds_str[dp->dstate]);
			if (msg & IDNP_MSGTYPE_MASK) {
				/*
				 * fin or fin+ack.
				 */
				mt.mt_mtype = IDNP_NACK;
				mt.mt_atype = msg;
				SET_XARGS_NACK_TYPE(aargs, IDNNACK_NOCONN);
				idn_send_acknack(domid, &mt, aargs);
			}
			return (0);
		}
		dp->dfin_sync = IDNDS_SYNC_TYPE(dp);

		/*
		 * Need to do some clean-up ala idn_disconnect().
		 *
		 * Terminate any outstanding commands that were
		 * targeted towards this domain.
		 */
		idn_terminate_cmd(domid, ECANCELED);

		/*
		 * Terminate any and all retries that may have
		 * outstanding for this domain.
		 */
		token = IDN_RETRY_TOKEN(domid, IDN_RETRY_TYPEALL);
		(void) idn_retry_terminate(token);

		/*
		 * Stop all outstanding message timers for
		 * this guy.
		 */
		IDN_MSGTIMER_STOP(domid, 0, 0);

		dp->dxp = &xphase_fin;
		IDN_XSTATE_TRANSITION(dp, IDNXS_PEND);
	}

	if (msg & IDNP_NACK) {
		idn_nack_t	nack;

		nack = GET_XARGS_NACK_TYPE(xargs);
		if (nack == IDNNACK_NOCONN) {
			/*
			 * We're trying to FIN with somebody we're
			 * already disconnected from.  Need to
			 * speed this guy through.
			 */
			DOMAINSET_ADD(idn.domset.ds_ready_off, domid);
			(void) idn_sync_register(domid, IDNSYNC_DISCONNECT,
			    DOMAINSET_ALL, IDNSYNC_REG_REG);
			ready_set = (uint_t)DOMAINSET_ALL;
			/*
			 * Need to transform message to allow us to
			 * pass this guy right through and not waste time
			 * talking to him.
			 */
			IDN_FSTATE_TRANSITION(dp, IDNFIN_FORCE_HARD);

			switch (dp->dstate) {
			case IDNDS_FIN_PEND:
				mtp->mt_mtype = 0;
				mtp->mt_atype = 0;
				break;

			case IDNDS_FIN_SENT:
				mtp->mt_mtype = IDNP_FIN | IDNP_ACK;
				mtp->mt_atype = 0;
				break;

			case IDNDS_FIN_RCVD:
				mtp->mt_mtype = IDNP_ACK;
				mtp->mt_atype = IDNP_FIN | IDNP_ACK;
				break;

			default:
#ifdef DEBUG
				cmn_err(CE_PANIC,
				    "%s:%d: UNEXPECTED state = %s",
				    proc, domid,
				    idnds_str[dp->dstate]);
#endif /* DEBUG */
				break;
			}
		}
		fintype = (uint_t)dp->dfin;
		finopt = DOMAIN_IN_SET(idn.domset.ds_relink, domid) ?
		    IDNFIN_OPT_RELINK : IDNFIN_OPT_UNLINK;

		CLR_XARGS(xargs);
		SET_XARGS_FIN_TYPE(xargs, fintype);
		SET_XARGS_FIN_ARG(xargs, finarg);
		SET_XARGS_FIN_DOMSET(xargs, ready_set);
		SET_XARGS_FIN_OPT(xargs, finopt);
		SET_XARGS_FIN_MASTER(xargs, NIL_FIN_MASTER);
	}

	(void) idn_xphase_transition(domid, mtp, xargs);

	return (0);
}

/*ARGSUSED1*/
static void
idn_retry_fin(uint_t token, void *arg)
{
	int		domid = IDN_RETRY_TOKEN2DOMID(token);
	int		new_masterid, new_cpuid = IDN_NIL_DCPU;
	uint_t		finmaster;
	idn_domain_t	*dp = &idn_domain[domid];
	idn_xdcargs_t	xargs;
	idn_finopt_t	finopt;
	procname_t	proc = "idn_retry_fin";

	ASSERT(IDN_RETRY_TOKEN2TYPE(token) == IDNRETRY_FIN);

	IDN_SYNC_LOCK();
	IDN_DLOCK_EXCL(domid);

	if (dp->dxp != &xphase_fin) {
		PR_PROTO("%s:%d: dxp(0x%p) != xstate_fin(0x%p)...bailing\n",
		    proc, domid, (void *)dp->dxp, (void *)&xphase_fin);
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return;
	}

	if (dp->dxstate != IDNXS_PEND) {
		PR_PROTO("%s:%d: xstate(%s) != %s...bailing\n",
		    proc, domid, idnxs_str[dp->dxstate],
		    idnxs_str[IDNXS_PEND]);
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		return;
	}

	finopt = DOMAIN_IN_SET(idn.domset.ds_relink, domid) ?
	    IDNFIN_OPT_RELINK : IDNFIN_OPT_UNLINK;

	CLR_XARGS(xargs);
	SET_XARGS_FIN_TYPE(xargs, dp->dfin);
	/*LINTED*/
	SET_XARGS_FIN_ARG(xargs, IDNFIN_ARG_NONE);
	SET_XARGS_FIN_OPT(xargs, finopt);
	SET_XARGS_FIN_DOMSET(xargs, 0);		/* unused when msg == 0 */
	IDN_GLOCK_SHARED();
	new_masterid = IDN_GET_NEW_MASTERID();
	IDN_GUNLOCK();
	if (new_masterid != IDN_NIL_DOMID)
		new_cpuid = idn_domain[new_masterid].dcpu;
	finmaster = MAKE_FIN_MASTER(new_masterid, new_cpuid);
	SET_XARGS_FIN_MASTER(xargs, finmaster);

	(void) idn_xphase_transition(domid, NULL, xargs);

	IDN_DUNLOCK(domid);
	IDN_SYNC_UNLOCK();
}

static int
idn_check_fin_pend(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	idn_domain_t	*dp = &idn_domain[domid];
	idn_fin_t	fintype;
	idn_finopt_t	finopt;
	idn_finarg_t	finarg;
	int		ready;
	int		finmasterid;
	int		fincpuid;
	uint_t		finmaster;
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	domainset_t	query_set, ready_set, conn_set;
	domainset_t	my_ready_set, shutdown_set;
	procname_t	proc = "idn_check_fin_pend";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (msg & IDNP_NACK)
		return (0);

	if ((dp->dstate == IDNDS_FIN_PEND) && (msg & IDNP_MSGTYPE_MASK) &&
	    (msg & IDNP_ACK))		/* fin+ack */
		return (1);

	query_set = 0;

	if (!DOMAIN_IN_SET(idn.domset.ds_trans_off, domid)) {
		/*
		 * Can't remove domain from ds_connected yet,
		 * since he's still officially connected until
		 * we get an ACK from him.
		 */
		DOMAINSET_DEL(idn.domset.ds_trans_on, domid);
		DOMAINSET_ADD(idn.domset.ds_trans_off, domid);
	}

	IDN_GLOCK_SHARED();
	conn_set = (idn.domset.ds_connected | idn.domset.ds_trans_on) &
	    ~idn.domset.ds_trans_off;
	if ((idn.state == IDNGS_DISCONNECT) ||
	    (idn.state == IDNGS_RECONFIG) ||
	    (domid == IDN_GET_MASTERID()) || !conn_set) {
		/*
		 * If we're disconnecting, reconfiguring,
		 * unlinking from the master, or unlinking
		 * the last of our connections, then we need
		 * to shutdown all the channels.
		 */
		shutdown_set = DOMAINSET_ALL;
	} else {
		shutdown_set = DOMAINSET(domid);
	}
	IDN_GUNLOCK();

	idn_shutdown_datapath(shutdown_set, (dp->dfin == IDNFIN_FORCE_HARD));

	IDN_GLOCK_EXCL();
	/*
	 * Remap the SMR back to our local space if the remote
	 * domain going down is the master.  We do this now before
	 * flushing caches.  This will help guarantee that any
	 * accidental accesses to the SMR after the cache flush
	 * will only go to local memory.
	 */
	if ((domid == IDN_GET_MASTERID()) && (idn.smr.rempfn != PFN_INVALID)) {
		PR_PROTO("%s:%d: deconfiging CURRENT MASTER - SMR remap\n",
		    proc, domid);
		IDN_DLOCK_EXCL(idn.localid);
		/*
		 * We're going to remap the SMR,
		 * so gotta blow away our local
		 * pointer to the mbox table.
		 */
		idn_domain[idn.localid].dmbox.m_tbl = NULL;
		IDN_DUNLOCK(idn.localid);

		idn.smr.rempfn = PFN_INVALID;
		idn.smr.rempfnlim = PFN_INVALID;

		smr_remap(&kas, idn.smr.vaddr, idn.smr.locpfn, IDN_SMR_SIZE);
	}
	IDN_GUNLOCK();

	if (DOMAIN_IN_SET(idn.domset.ds_flush, domid)) {
		idnxf_flushall_ecache();
		CHECKPOINT_CLOSED(IDNSB_CHKPT_CACHE, dp->dhw.dh_boardset, 2);
		DOMAINSET_DEL(idn.domset.ds_flush, domid);
	}

	fintype   = GET_XARGS_FIN_TYPE(xargs);
	finarg    = GET_XARGS_FIN_ARG(xargs);
	ready_set = GET_XARGS_FIN_DOMSET(xargs);
	finopt    = GET_XARGS_FIN_OPT(xargs);

	ASSERT(fintype != IDNFIN_QUERY);
	if (!VALID_FIN(fintype)) {
		/*
		 * If for some reason remote domain
		 * sent us an invalid FIN type,
		 * override it to a  NORMAL fin.
		 */
		PR_PROTO("%s:%d: WARNING invalid fintype (%d) -> %s(%d)\n",
		    proc, domid, (int)fintype,
		    idnfin_str[IDNFIN_NORMAL], (int)IDNFIN_NORMAL);
		fintype = IDNFIN_NORMAL;
	}

	if (!VALID_FINOPT(finopt)) {
		PR_PROTO("%s:%d: WARNING invalid finopt (%d) -> %s(%d)\n",
		    proc, domid, (int)finopt,
		    idnfinopt_str[IDNFIN_OPT_UNLINK],
		    (int)IDNFIN_OPT_UNLINK);
		finopt = IDNFIN_OPT_UNLINK;
	}

	finmaster = GET_XARGS_FIN_MASTER(xargs);
	finmasterid = FIN_MASTER_DOMID(finmaster);
	fincpuid = FIN_MASTER_CPUID(finmaster);

	if ((finarg != IDNFIN_ARG_NONE) &&
	    !DOMAIN_IN_SET(idn.domset.ds_hitlist, domid)) {
		idnsb_error_t	idnerr;

		INIT_IDNKERR(&idnerr);
		SET_IDNKERR_ERRNO(&idnerr, EPROTO);
		SET_IDNKERR_IDNERR(&idnerr, FINARG2IDNKERR(finarg));
		SET_IDNKERR_PARAM0(&idnerr, domid);

		if (IDNFIN_ARG_IS_FATAL(finarg)) {
			finopt = IDNFIN_OPT_UNLINK;
			DOMAINSET_DEL(idn.domset.ds_relink, domid);
			DOMAINSET_ADD(idn.domset.ds_hitlist, domid);

			if (idn.domset.ds_connected == 0) {
				domainset_t	domset;

				IDN_GLOCK_EXCL();
				domset = ~idn.domset.ds_relink;
				if (idn.domset.ds_relink == 0) {
					IDN_GSTATE_TRANSITION(IDNGS_DISCONNECT);
				}
				domset &= ~idn.domset.ds_hitlist;
				/*
				 * The primary domain we were trying to
				 * connect to fin'd us with a fatal argument.
				 * Something isn't cool in our IDN environment,
				 * e.g. corrupted SMR or non-compatible CONFIG
				 * parameters.  In any case we need to dismantle
				 * ourselves completely.
				 */
				IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);
				IDN_GUNLOCK();
				IDN_DUNLOCK(domid);

				DOMAINSET_DEL(domset, idn.localid);
				DOMAINSET_DEL(domset, domid);

				idn_update_op(IDNOP_ERROR, DOMAINSET_ALL,
				    &idnerr);

				PR_HITLIST("%s:%d: unlink_domainset(%x) "
				    "due to CFG error (relink=%x, "
				    "hitlist=%x)\n", proc, domid, domset,
				    idn.domset.ds_relink,
				    idn.domset.ds_hitlist);

				idn_unlink_domainset(domset, IDNFIN_NORMAL,
				    finarg, IDNFIN_OPT_UNLINK, BOARDSET_ALL);
				IDN_DLOCK_EXCL(domid);
			}
			PR_HITLIST("%s:%d: CFG error, (conn=%x, relink=%x, "
			    "hitlist=%x)\n",
			    proc, domid, idn.domset.ds_connected,
			    idn.domset.ds_relink, idn.domset.ds_hitlist);
		}
		idn_update_op(IDNOP_ERROR, DOMAINSET(domid), &idnerr);
	}

	if ((finmasterid != IDN_NIL_DOMID) && (!VALID_DOMAINID(finmasterid) ||
	    DOMAIN_IN_SET(idn.domset.ds_hitlist, domid))) {
		PR_HITLIST("%s:%d: finmasterid = %d -> -1, relink=%x, "
		    "hitlist=%x\n",
		    proc, domid, finmasterid, idn.domset.ds_relink,
		    idn.domset.ds_hitlist);
		PR_PROTO("%s:%d: WARNING invalid finmasterid (%d) -> -1\n",
		    proc, domid, finmasterid);
		finmasterid = IDN_NIL_DOMID;
	}

	IDN_GLOCK_EXCL();

	if ((finopt == IDNFIN_OPT_RELINK) && (idn.state != IDNGS_DISCONNECT)) {
		DOMAINSET_ADD(idn.domset.ds_relink, domid);
		IDN_HISTORY_LOG(IDNH_RELINK, domid, dp->dstate,
		    idn.domset.ds_relink);
	} else {
		DOMAINSET_DEL(idn.domset.ds_relink, domid);
		DOMAINSET_ADD(idn.domset.ds_hitlist, domid);
	}

	if ((domid == IDN_GET_NEW_MASTERID()) &&
	    !DOMAIN_IN_SET(idn.domset.ds_relink, domid)) {
		IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);
	}

	if ((idn.state != IDNGS_DISCONNECT) && (idn.state != IDNGS_RECONFIG) &&
	    (domid == IDN_GET_MASTERID())) {
		domainset_t	dis_set, master_candidates;

		IDN_GKSTAT_GLOBAL_EVENT(gk_reconfigs, gk_reconfig_last);

		IDN_GSTATE_TRANSITION(IDNGS_RECONFIG);
		IDN_GUNLOCK();

		if ((finmasterid != IDN_NIL_DOMID) &&
		    (finmasterid != idn.localid)) {
			if (finmasterid != domid)
				IDN_DLOCK_EXCL(finmasterid);
			if (idn_open_domain(finmasterid, fincpuid, 0) < 0) {
				cmn_err(CE_WARN,
				    "IDN: 205: (%s) failed to "
				    "open-domain(%d,%d)",
				    proc, finmasterid, fincpuid);
				if (finmasterid != domid)
					IDN_DUNLOCK(finmasterid);
				finmasterid = IDN_NIL_DOMID;
			}
			if (finmasterid != domid)
				IDN_DUNLOCK(finmasterid);
		}

		IDN_GLOCK_EXCL();
		if (finmasterid == IDN_NIL_DOMID) {
			int	m;

			master_candidates = idn.domset.ds_trans_on |
			    idn.domset.ds_connected |
			    idn.domset.ds_relink;
			master_candidates &= ~(idn.domset.ds_trans_off &
			    ~idn.domset.ds_relink);
			DOMAINSET_DEL(master_candidates, domid);
			/*
			 * Local domain gets to participate also.
			 */
			DOMAINSET_ADD(master_candidates, idn.localid);

			m = idn_select_candidate(master_candidates);
			IDN_SET_NEW_MASTERID(m);
		} else {
			IDN_SET_NEW_MASTERID(finmasterid);
		}
		IDN_GUNLOCK();

		dis_set = idn.domset.ds_trans_on | idn.domset.ds_connected;
		DOMAINSET_DEL(dis_set, domid);

		idn_unlink_domainset(dis_set, IDNFIN_NORMAL, IDNFIN_ARG_NONE,
		    IDNFIN_OPT_RELINK, BOARDSET_ALL);
	} else {
		IDN_GUNLOCK();
	}

	/*
	 * My local ready-set are those domains from which I
	 * have confirmed no datapaths exist.
	 */
	my_ready_set = ~idn.domset.ds_connected;

	switch (dp->dfin) {
	case IDNFIN_NORMAL:
	case IDNFIN_FORCE_SOFT:
	case IDNFIN_FORCE_HARD:
		if (fintype < dp->dfin) {
			/*
			 * Remote domain has requested a
			 * FIN of lower priority than what
			 * we're currently running.  Just
			 * leave the priority where it is.
			 */
			break;
		}
		/*FALLTHROUGH*/

	default:
		IDN_FSTATE_TRANSITION(dp, fintype);
		break;
	}

	ASSERT(dp->dfin_sync != IDNFIN_SYNC_OFF);

	if (msg == 0) {
		/*
		 * Local domain is initiating a FIN sequence
		 * to remote domid.  Note that remote domain
		 * remains in ds_connected even though he's
		 * in thet ready-set from the local domain's
		 * perspective.  We can't remove him from
		 * ds_connected until we get a confirmed message
		 * from him indicating he has ceased communication.
		 */
		ready_set = my_ready_set;
	} else {
		/*
		 * Remote domain initiated a FIN sequence
		 * to local domain.  This implies that he
		 * has shutdown his datapath to us.  Since
		 * we shutdown our datapath to him, we're
		 * effectively now in his ready-set.
		 */
		DOMAINSET_ADD(ready_set, idn.localid);
		/*
		 * Since we know both sides of the connection
		 * have ceased, this remote domain is effectively
		 * considered disconnected.
		 */
		DOMAINSET_ADD(idn.domset.ds_ready_off, domid);
	}

	if (dp->dfin == IDNFIN_FORCE_HARD) {
		/*
		 * If we're doing a hard disconnect
		 * of this domain then we want to
		 * blow straight through and not
		 * waste time trying to talk to the
		 * remote domain nor to domains we
		 * believe are AWOL.  Although we will
		 * try and do it cleanly with
		 * everybody else.
		 */
		DOMAINSET_ADD(my_ready_set, domid);
		my_ready_set |= idn.domset.ds_awol;
		ready_set = DOMAINSET_ALL;

	} else if (dp->dfin_sync == IDNFIN_SYNC_NO) {
		/*
		 * If we're not fin'ing this domain
		 * synchronously then the only
		 * expected domain set is himself.
		 */
		ready_set |= ~DOMAINSET(domid);
		my_ready_set |= ~DOMAINSET(domid);
	}

	if (dp->dsync.s_cmd != IDNSYNC_DISCONNECT) {
		idn_sync_exit(domid, IDNSYNC_CONNECT);
		idn_sync_enter(domid, IDNSYNC_DISCONNECT, DOMAINSET_ALL,
		    my_ready_set, idn_xstate_transfunc,	(void *)IDNP_FIN);
	}

	query_set = idn_sync_register(domid, IDNSYNC_DISCONNECT, ready_set,
	    IDNSYNC_REG_REG);

	/*
	 * No need to query this domain as he's already
	 * in the FIN sequence.
	 */
	DOMAINSET_DEL(query_set, domid);

	ready = (dp->dsync.s_set_exp == dp->dsync.s_set_rdy) ? 1 : 0;
	if (ready) {
		DOMAINSET_DEL(idn.domset.ds_ready_off, domid);
		DOMAINSET_DEL(idn.domset.ds_connected, domid);
	}

	if (query_set) {
		int	d;

		my_ready_set = idn.domset.ds_ready_off |
		    ~idn.domset.ds_connected;

		for (d = 0; d < MAX_DOMAINS; d++) {
			if (!DOMAIN_IN_SET(query_set, d))
				continue;

			dp = &idn_domain[d];

			IDN_DLOCK_EXCL(d);

			if (dp->dsync.s_cmd == IDNSYNC_DISCONNECT) {
				IDN_DUNLOCK(d);
				continue;
			}

			IDN_SYNC_QUERY_UPDATE(domid, d);

			(void) idn_send_fin(d, NULL, IDNFIN_QUERY,
			    IDNFIN_ARG_NONE, IDNFIN_OPT_NONE, my_ready_set,
			    NIL_FIN_MASTER);
			IDN_DUNLOCK(d);
		}
	}

	return (!msg ? 0 : (ready ? 0 : 1));
}

/*ARGSUSED*/
static void
idn_error_fin_pend(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t	msg = mtp ? mtp->mt_mtype : 0;
	uint_t	token;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_HELD(domid));

	/*
	 * Don't communicate with domains that
	 * we're forcing a hard disconnect.
	 */
	if ((idn_domain[domid].dfin != IDNFIN_FORCE_HARD) &&
	    (msg & IDNP_MSGTYPE_MASK)) {
		idn_msgtype_t	mt;
		idn_xdcargs_t	nargs;

		mt.mt_mtype = IDNP_NACK;
		mt.mt_atype = msg;
		mt.mt_cookie = mtp->mt_cookie;
		CLR_XARGS(nargs);
		SET_XARGS_NACK_TYPE(nargs, IDNNACK_RETRY);
		idn_send_acknack(domid, &mt, nargs);
	}

	token = IDN_RETRY_TOKEN(domid, IDNRETRY_FIN);
	idn_retry_submit(idn_retry_fin, NULL, token,
	    idn_msg_retrytime[(int)IDNRETRY_FIN]);
}

static void
idn_action_fin_pend(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	idn_domain_t	*dp = &idn_domain[domid];
	domainset_t	my_ready_set;
	idn_finopt_t	finopt;
	idn_finarg_t	finarg;
	uint_t		finmaster;
	int		new_masterid, new_cpuid = IDN_NIL_DCPU;
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	idn_msgtype_t	mt;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_HELD(domid));

	my_ready_set = dp->dsync.s_set_rdy | idn.domset.ds_ready_off |
	    ~idn.domset.ds_connected;

	ASSERT(xargs[0] != (uint_t)IDNFIN_QUERY);

	finarg = GET_XARGS_FIN_ARG(xargs);
	finopt = DOMAIN_IN_SET(idn.domset.ds_relink, domid) ?
	    IDNFIN_OPT_RELINK : IDNFIN_OPT_UNLINK;

	mt.mt_cookie = mtp ? mtp->mt_cookie : 0;

	IDN_GLOCK_SHARED();
	new_masterid = IDN_GET_NEW_MASTERID();
	IDN_GUNLOCK();
	if (new_masterid != IDN_NIL_DOMID)
		new_cpuid = idn_domain[new_masterid].dcpu;
	finmaster = MAKE_FIN_MASTER(new_masterid, new_cpuid);

	if (dp->dfin == IDNFIN_FORCE_HARD) {
		ASSERT(IDN_DLOCK_IS_EXCL(domid));

		if (!msg) {
			mt.mt_mtype = IDNP_FIN | IDNP_ACK;
			mt.mt_atype = 0;
		} else {
			mt.mt_mtype = IDNP_ACK;
			mt.mt_atype = IDNP_FIN | IDNP_ACK;
		}
		(void) idn_xphase_transition(domid, &mt, xargs);
	} else if (!msg) {
		(void) idn_send_fin(domid, NULL, dp->dfin, finarg,
		    finopt, my_ready_set, finmaster);
	} else if ((msg & IDNP_ACKNACK_MASK) == 0) {
		/*
		 * fin
		 */
		mt.mt_mtype = IDNP_FIN | IDNP_ACK;
		mt.mt_atype = 0;
		(void) idn_send_fin(domid, &mt, dp->dfin, finarg,
		    finopt, my_ready_set, finmaster);
	} else {
		uint_t	token;
		/*
		 * nack - retry
		 */
		token = IDN_RETRY_TOKEN(domid, IDNRETRY_FIN);
		idn_retry_submit(idn_retry_fin, NULL, token,
		    idn_msg_retrytime[(int)IDNRETRY_FIN]);
	}
}

static int
idn_check_fin_sent(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	int		ready;
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	idn_fin_t	fintype;
	idn_finopt_t	finopt;
	idn_domain_t	*dp = &idn_domain[domid];
	domainset_t	query_set, ready_set;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (msg & IDNP_NACK)
		return (0);

	fintype   = GET_XARGS_FIN_TYPE(xargs);
	ready_set = GET_XARGS_FIN_DOMSET(xargs);
	finopt    = GET_XARGS_FIN_OPT(xargs);

	ASSERT(fintype != IDNFIN_QUERY);
	if (!VALID_FIN(fintype)) {
		/*
		 * If for some reason remote domain
		 * sent us an invalid FIN type,
		 * override it to a  NORMAL fin.
		 */
		fintype = IDNFIN_NORMAL;
	}

	if (!VALID_FINOPT(finopt)) {
		finopt = IDNFIN_OPT_UNLINK;
	}
	IDN_GLOCK_SHARED();
	if ((finopt == IDNFIN_OPT_RELINK) && (idn.state != IDNGS_DISCONNECT)) {
		DOMAINSET_ADD(idn.domset.ds_relink, domid);
		IDN_HISTORY_LOG(IDNH_RELINK, domid, dp->dstate,
		    idn.domset.ds_relink);
	} else {
		DOMAINSET_DEL(idn.domset.ds_relink, domid);
	}
	IDN_GUNLOCK();

	switch (dp->dfin) {
	case IDNFIN_NORMAL:
	case IDNFIN_FORCE_SOFT:
	case IDNFIN_FORCE_HARD:
		if (fintype < dp->dfin) {
			/*
			 * Remote domain has requested a
			 * FIN of lower priority than what
			 * we're current running.  Just
			 * leave the priority where it is.
			 */
			break;
		}
		/*FALLTHROUGH*/

	default:
		IDN_FSTATE_TRANSITION(dp, fintype);
		break;
	}

	if (dp->dfin == IDNFIN_FORCE_HARD) {
		/*
		 * If we're doing a hard disconnect
		 * of this domain then we want to
		 * blow straight through and not
		 * waste time trying to talk to the
		 * remote domain.  By registering him
		 * as ready with respect to all
		 * possible domains he'll transition
		 * immediately.  Note that we'll still
		 * try and do it coherently with
		 * other domains to which we're connected.
		 */
		ready_set = DOMAINSET_ALL;
	} else {
		DOMAINSET_ADD(ready_set, idn.localid);
	}

	DOMAINSET_ADD(idn.domset.ds_ready_off, domid);

	query_set = idn_sync_register(domid, IDNSYNC_DISCONNECT,
	    ready_set, IDNSYNC_REG_REG);
	/*
	 * No need to query this domain as he's already
	 * in the FIN sequence.
	 */
	DOMAINSET_DEL(query_set, domid);

	ready = (dp->dsync.s_set_exp == dp->dsync.s_set_rdy) ? 1 : 0;
	if (ready) {
		DOMAINSET_DEL(idn.domset.ds_ready_off, domid);
		DOMAINSET_DEL(idn.domset.ds_connected, domid);
	}

	if (query_set) {
		int		d;
		domainset_t	my_ready_set;

		my_ready_set = idn.domset.ds_ready_off |
		    ~idn.domset.ds_connected;

		for (d = 0; d < MAX_DOMAINS; d++) {
			if (!DOMAIN_IN_SET(query_set, d))
				continue;

			dp = &idn_domain[d];

			IDN_DLOCK_EXCL(d);

			if (dp->dsync.s_cmd == IDNSYNC_DISCONNECT) {
				IDN_DUNLOCK(d);
				continue;
			}

			IDN_SYNC_QUERY_UPDATE(domid, d);

			(void) idn_send_fin(d, NULL, IDNFIN_QUERY,
			    IDNFIN_ARG_NONE, IDNFIN_OPT_NONE, my_ready_set,
			    NIL_FIN_MASTER);
			IDN_DUNLOCK(d);
		}
	}

	return ((ready > 0) ? 0 : 1);
}

/*ARGSUSED*/
static void
idn_error_fin_sent(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t	msg = mtp ? mtp->mt_mtype : 0;
	uint_t	token;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	/*
	 * Don't communicate with domains that
	 * we're forcing a hard disconnect.
	 */
	if ((idn_domain[domid].dfin != IDNFIN_FORCE_HARD) &&
	    (msg & IDNP_MSGTYPE_MASK)) {
		idn_msgtype_t	mt;
		idn_xdcargs_t	nargs;

		mt.mt_mtype = IDNP_NACK;
		mt.mt_atype = msg;
		mt.mt_cookie = mtp->mt_cookie;
		CLR_XARGS(nargs);
		SET_XARGS_NACK_TYPE(nargs, IDNNACK_RETRY);
		idn_send_acknack(domid, &mt, nargs);
	}

	token = IDN_RETRY_TOKEN(domid, IDNRETRY_FIN);
	idn_retry_submit(idn_retry_fin, NULL, token,
	    idn_msg_retrytime[(int)IDNRETRY_FIN]);
}

static void
idn_action_fin_sent(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	int		new_masterid, new_cpuid = IDN_NIL_DCPU;
	uint_t		finmaster;
	idn_msgtype_t	mt;
	idn_finopt_t	finopt;
	idn_finarg_t	finarg;
	domainset_t	my_ready_set;
	idn_domain_t	*dp = &idn_domain[domid];

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	mt.mt_cookie = mtp ? mtp->mt_cookie : 0;

	finopt = DOMAIN_IN_SET(idn.domset.ds_relink, domid) ?
	    IDNFIN_OPT_RELINK : IDNFIN_OPT_UNLINK;

	finarg = GET_XARGS_FIN_ARG(xargs);

	my_ready_set = dp->dsync.s_set_rdy | idn.domset.ds_ready_off |
	    ~idn.domset.ds_connected;

	IDN_GLOCK_SHARED();
	new_masterid = IDN_GET_NEW_MASTERID();
	IDN_GUNLOCK();
	if (new_masterid != IDN_NIL_DOMID)
		new_cpuid = idn_domain[new_masterid].dcpu;
	finmaster = MAKE_FIN_MASTER(new_masterid, new_cpuid);

	if ((msg & IDNP_ACKNACK_MASK) == 0) {
		/*
		 * fin
		 */
		if (dp->dfin == IDNFIN_FORCE_HARD) {
			mt.mt_mtype = IDNP_ACK;
			mt.mt_atype = IDNP_FIN | IDNP_ACK;
			(void) idn_xphase_transition(domid, &mt, xargs);
		} else {
			mt.mt_mtype = IDNP_FIN | IDNP_ACK;
			mt.mt_atype = 0;
			(void) idn_send_fin(domid, &mt, dp->dfin, finarg,
			    finopt, my_ready_set, finmaster);
		}
	} else if (msg & IDNP_MSGTYPE_MASK) {
		/*
		 * fin+ack
		 */
		if (dp->dfin != IDNFIN_FORCE_HARD) {
			idn_xdcargs_t	fargs;

			mt.mt_mtype = IDNP_ACK;
			mt.mt_atype = msg;
			CLR_XARGS(fargs);
			SET_XARGS_FIN_TYPE(fargs, dp->dfin);
			SET_XARGS_FIN_ARG(fargs, finarg);
			SET_XARGS_FIN_DOMSET(fargs, my_ready_set);
			SET_XARGS_FIN_OPT(fargs, finopt);
			SET_XARGS_FIN_MASTER(fargs, finmaster);
			idn_send_acknack(domid, &mt, fargs);
		}
	} else {
		uint_t	token;
		/*
		 * nack - retry
		 */
		token = IDN_RETRY_TOKEN(domid, IDNRETRY_FIN);
		idn_retry_submit(idn_retry_fin, NULL, token,
		    idn_msg_retrytime[(int)IDNRETRY_FIN]);
	}
}

/*ARGSUSED*/
static void
idn_action_fin_rcvd(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t	msg = mtp ? mtp->mt_mtype : 0;

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (msg & IDNP_NACK) {
		uint_t	token;
		/*
		 * nack - retry.
		 */
		token = IDN_RETRY_TOKEN(domid, IDNRETRY_FIN);
		idn_retry_submit(idn_retry_fin, NULL, token,
		    idn_msg_retrytime[(int)IDNRETRY_FIN]);
	}
}

static void
idn_final_fin(int domid)
{
	int		do_relink;
	int		rv, d, new_masterid = IDN_NIL_DOMID;
	idn_gstate_t	next_gstate;
	domainset_t	relinkset;
	uint_t		token = IDN_RETRY_TOKEN(domid, IDNRETRY_FIN);
	idn_domain_t	*ldp, *dp = &idn_domain[domid];
	procname_t	proc = "idn_final_fin";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));
	ASSERT(dp->dstate == IDNDS_DMAP);

	(void) idn_retry_terminate(token);

	dp->dxp = NULL;
	IDN_XSTATE_TRANSITION(dp, IDNXS_NIL);

	idn_sync_exit(domid, IDNSYNC_DISCONNECT);

	DOMAINSET_DEL(idn.domset.ds_trans_off, domid);

	do_relink = DOMAIN_IN_SET(idn.domset.ds_relink, domid) ? 1 : 0;

	/*
	 * idn_deconfig will idn_close_domain.
	 */
	idn_deconfig(domid);

	PR_PROTO("%s:%d: DISCONNECTED\n", proc, domid);

	IDN_GLOCK_EXCL();
	/*
	 * It's important that this update-op occur within
	 * the context of holding the glock(EXCL).  There is
	 * still some additional state stuff to cleanup which
	 * will be completed once the glock is dropped in
	 * this flow.  Which means anybody that's doing a
	 * SSI_INFO and waiting on glock will not actually
	 * run until the clean-up is completed, which is what
	 * we want.  Recall that a separate thread processes
	 * the SSI_LINK/UNLINK calls and when they complete
	 * (i.e. are awakened) they will immediately SSI_INFO
	 * and we don't want them to prematurely pick up stale
	 * information.
	 */
	idn_update_op(IDNOP_DISCONNECTED, DOMAINSET(domid), NULL);

	ASSERT(idn.state != IDNGS_OFFLINE);
	ASSERT(!DOMAIN_IN_SET(idn.domset.ds_trans_on, domid));

	if (domid == IDN_GET_MASTERID()) {
		IDN_SET_MASTERID(IDN_NIL_DOMID);
		dp->dvote.v.master = 0;
	}

	if ((domid == IDN_GET_NEW_MASTERID()) && !do_relink) {
		IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);
	}

	if (idn.state == IDNGS_RECONFIG)
		new_masterid = IDN_GET_NEW_MASTERID();

	if ((idn.domset.ds_trans_on | idn.domset.ds_trans_off |
	    idn.domset.ds_relink) == 0) {
		PR_HITLIST("%s:%d: HITLIST %x -> 0\n",
		    proc, domid, idn.domset.ds_hitlist);
		idn.domset.ds_hitlist = 0;
	}

	if (idn.domset.ds_connected || idn.domset.ds_trans_off) {
		PR_PROTO("%s:%d: ds_connected = 0x%x, ds_trans_off = 0x%x\n",
		    proc, domid, idn.domset.ds_connected,
		    idn.domset.ds_trans_off);
		IDN_GUNLOCK();
		goto fin_done;
	}

	IDN_DLOCK_EXCL(idn.localid);
	ldp = &idn_domain[idn.localid];

	if (idn.domset.ds_trans_on != 0) {
		ASSERT((idn.state != IDNGS_DISCONNECT) &&
		    (idn.state != IDNGS_OFFLINE));

		switch (idn.state) {
		case IDNGS_CONNECT:
			if (idn.localid == IDN_GET_MASTERID()) {
				idn_master_deinit();
				IDN_SET_MASTERID(IDN_NIL_DOMID);
				ldp->dvote.v.master = 0;
			}
			/*FALLTHROUGH*/
		case IDNGS_ONLINE:
			next_gstate = idn.state;
			break;

		case IDNGS_RECONFIG:
			if (idn.localid == IDN_GET_MASTERID()) {
				idn_master_deinit();
				IDN_SET_MASTERID(IDN_NIL_DOMID);
				ldp->dvote.v.master = 0;
			}
			ASSERT(IDN_GET_MASTERID() == IDN_NIL_DOMID);
			next_gstate = IDNGS_CONNECT;
			ldp->dvote.v.connected = 0;
			/*
			 * Need to do HWINIT since we won't
			 * be transitioning through OFFLINE
			 * which would normally be caught in
			 * idn_check_nego() when we
			 * initially go to CONNECT.
			 */
			IDN_PREP_HWINIT();
			break;

		case IDNGS_DISCONNECT:
		case IDNGS_OFFLINE:
			cmn_err(CE_WARN,
			    "IDN: 211: disconnect domain %d, "
			    "unexpected Gstate (%s)",
			    domid, idngs_str[idn.state]);
			IDN_DUNLOCK(idn.localid);
			IDN_GUNLOCK();
			goto fin_done;

		default:
			/*
			 * XXX
			 * Go into FATAL state?
			 */
			cmn_err(CE_PANIC,
			    "IDN: 212: disconnect domain %d, "
			    "bad Gstate (%d)",
			    domid, idn.state);
			/* not reached */
			break;
		}
	} else {
		if (idn.localid == IDN_GET_MASTERID()) {
			idn_master_deinit();
			IDN_SET_MASTERID(IDN_NIL_DOMID);
			ldp->dvote.v.master = 0;
		}
		next_gstate = IDNGS_OFFLINE;
		if (idn.domset.ds_relink == 0) {
			IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);
		}
	}
	IDN_DUNLOCK(idn.localid);

	/*
	 * If we reach here we've effectively disconnected all
	 * existing links, however new ones may be pending.
	 */
	PR_PROTO("%s:%d: ALL DISCONNECTED *****************\n", proc, domid);

	IDN_GSTATE_TRANSITION(next_gstate);

	ASSERT((idn.state == IDNGS_OFFLINE) ?
	    (IDN_GET_MASTERID() == IDN_NIL_DOMID) : 1);

	IDN_GUNLOCK();

	/*
	 * If we have no new masterid and yet there are relinkers
	 * out there, then force us to attempt to link with one
	 * of them.
	 */
	if ((new_masterid == IDN_NIL_DOMID) && idn.domset.ds_relink)
		new_masterid = idn.localid;

	if (new_masterid != IDN_NIL_DOMID) {
		/*
		 * If the local domain is the selected
		 * master then we'll want to initiate
		 * a link with one of the other candidates.
		 * If not, then we want to initiate a link
		 * with the master only.
		 */
		relinkset = (new_masterid == idn.localid) ?
		    idn.domset.ds_relink : DOMAINSET(new_masterid);

		DOMAINSET_DEL(relinkset, idn.localid);

		for (d = 0; d < MAX_DOMAINS; d++) {
			int	lock_held;

			if (!DOMAIN_IN_SET(relinkset, d))
				continue;

			if (d == domid) {
				do_relink = 0;
				lock_held = 0;
			} else {
				IDN_DLOCK_EXCL(d);
				lock_held = 1;
			}

			rv = idn_open_domain(d, -1, 0);
			if (rv == 0) {
				rv = idn_connect(d);
				if (lock_held)
					IDN_DUNLOCK(d);
				/*
				 * If we're able to kick off at
				 * least one connect then that's
				 * good enough for now.  The others
				 * will fall into place normally.
				 */
				if (rv == 0)
					break;
			} else if (rv < 0) {
				if (lock_held)
					IDN_DUNLOCK(d);
				cmn_err(CE_WARN,
				    "IDN: 205: (%s.1) failed to "
				    "open-domain(%d,%d)",
				    proc, domid, -1);
				DOMAINSET_DEL(idn.domset.ds_relink, d);
			} else {
				if (lock_held)
					IDN_DUNLOCK(d);
				PR_PROTO("%s:%d: failed to "
				    "re-open domain %d "
				    "(cpu %d) [rv = %d]\n",
				    proc, domid, d, idn_domain[d].dcpu,
				    rv);
			}
		}
	}

fin_done:
	if (do_relink) {
		ASSERT(IDN_DLOCK_IS_EXCL(domid));

		rv = idn_open_domain(domid, -1, 0);
		if (rv == 0) {
			(void) idn_connect(domid);
		} else if (rv < 0) {
			cmn_err(CE_WARN,
			    "IDN: 205: (%s.2) failed to "
			    "open-domain(%d,%d)",
			    proc, domid, -1);
			DOMAINSET_DEL(idn.domset.ds_relink, domid);
		}
	}
}

static void
idn_exit_fin(int domid, uint_t msgtype)
{
	idn_domain_t	*dp = &idn_domain[domid];
	uint_t		token;
	procname_t	proc = "idn_exit_fin";
	STRING(str);

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	INUM2STR(msgtype, str);
	PR_PROTO("%s:%d: msgtype = 0x%x(%s)\n", proc, domid, msgtype, str);

	token = IDN_RETRY_TOKEN(domid, IDNRETRY_FIN);
	(void) idn_retry_terminate(token);

	DOMAINSET_DEL(idn.domset.ds_ready_off, domid);

	dp->dxp = &xphase_fin;
	IDN_XSTATE_TRANSITION(dp, IDNXS_PEND);

	idn_retry_submit(idn_retry_fin, NULL, token,
	    idn_msg_retrytime[(int)IDNRETRY_FIN]);
}

/*
 * Must return w/locks held.
 */
static int
idn_xphase_transition(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	uint_t		msgarg = mtp ? mtp->mt_atype : 0;
	idn_xphase_t	*xp;
	idn_domain_t	*dp;
	int		(*cfunc)(int, idn_msgtype_t *, idn_xdcargs_t);
	void		(*ffunc)(int);
	void		(*afunc)(int, idn_msgtype_t *, idn_xdcargs_t);
	void		(*efunc)(int, idn_msgtype_t *, idn_xdcargs_t);
	void		(*xfunc)(int, uint_t);
	int		err = 0;
	uint_t		msgtype;
	idn_xstate_t	o_xstate, n_xstate;
	procname_t	proc = "idn_xphase_transition";
	STRING(mstr);
	STRING(astr);

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	INUM2STR(msg, mstr);
	INUM2STR(msgarg, astr);

	dp = &idn_domain[domid];
	if ((xp = dp->dxp) == NULL) {
		PR_PROTO("%s:%d: WARNING: domain xsp is NULL (msg = %s, "
		    "msgarg = %s) <<<<<<<<<<<<\n",
		    proc, domid, mstr, astr);
		return (-1);
	}
	o_xstate = dp->dxstate;

	xfunc = xp->xt_exit;

	if ((msgtype = (msg & IDNP_MSGTYPE_MASK)) == 0)
		msgtype = msgarg & IDNP_MSGTYPE_MASK;

	if ((o_xstate == IDNXS_PEND) && msg &&
	    ((msg & IDNP_ACKNACK_MASK) == msg)) {
		PR_PROTO("%s:%d: unwanted acknack received (o_xstate = %s, "
		    "msg = %s/%s - dropping message\n",
		    proc, domid, idnxs_str[(int)o_xstate], mstr, astr);
		return (0);
	}

	/*
	 * Validate that message received is following
	 * the expected protocol for the current state.
	 */
	if (idn_next_xstate(o_xstate, -1, msg) == IDNXS_NIL) {
		PR_PROTO("%s:%d: WARNING: o_xstate = %s, msg = %s -> NIL "
		    "<<<<<<<<<\n",
		    proc, domid, idnxs_str[(int)o_xstate], mstr);
		if (xfunc)
			(*xfunc)(domid, msgtype);
		return (-1);
	}

	if (msg || msgarg) {
		/*
		 * Verify that message type is correct for
		 * the given xstate.
		 */
		if (msgtype != xp->xt_msgtype) {
			STRING(xstr);
			STRING(tstr);

			INUM2STR(xp->xt_msgtype, xstr);
			INUM2STR(msgtype, tstr);
			PR_PROTO("%s:%d: WARNING: msg expected %s(0x%x), "
			    "actual %s(0x%x) [msg=%s(0x%x), "
			    "msgarg=%s(0x%x)]\n",
			    proc, domid, xstr, xp->xt_msgtype,
			    tstr, msgtype, mstr, msg, astr, msgarg);
			if (xfunc)
				(*xfunc)(domid, msgtype);
			return (-1);
		}
	}

	cfunc = xp->xt_trans[(int)o_xstate].t_check;

	if (cfunc && ((err = (*cfunc)(domid, mtp, xargs)) < 0)) {
		if (o_xstate != IDNXS_PEND) {
			IDN_XSTATE_TRANSITION(dp, IDNXS_PEND);
		}
		if (xfunc)
			(*xfunc)(domid, msgtype);
		return (-1);
	}

	n_xstate = idn_next_xstate(o_xstate, err, msg);

	if (n_xstate == IDNXS_NIL) {
		PR_PROTO("%s:%d: WARNING: n_xstate = %s, msg = %s -> NIL "
		    "<<<<<<<<<\n",
		    proc, domid, idnxs_str[(int)n_xstate], mstr);
		if (xfunc)
			(*xfunc)(domid, msgtype);
		return (-1);
	}

	if (n_xstate != o_xstate) {
		IDN_XSTATE_TRANSITION(dp, n_xstate);
	}

	if (err) {
		if ((efunc = xp->xt_trans[(int)o_xstate].t_error) != NULL)
			(*efunc)(domid, mtp, xargs);
	} else if ((afunc = xp->xt_trans[(int)o_xstate].t_action) != NULL) {
		(*afunc)(domid, mtp, xargs);
	}

	if ((n_xstate == IDNXS_FINAL) && ((ffunc = xp->xt_final) != NULL))
		(*ffunc)(domid);

	return (0);
}

/*
 * Entered and returns w/DLOCK & SYNC_LOCK held.
 */
static int
idn_xstate_transfunc(int domid, void *transarg)
{
	uint_t		msg = (uint_t)(uintptr_t)transarg;
	uint_t		token;
	procname_t	proc = "idn_xstate_transfunc";

	ASSERT(IDN_SYNC_IS_LOCKED());

	switch (msg) {
	case IDNP_CON:
		DOMAINSET_ADD(idn.domset.ds_connected, domid);
		break;

	case IDNP_FIN:
		DOMAINSET_DEL(idn.domset.ds_connected, domid);
		break;

	default:
		PR_PROTO("%s:%d: ERROR: unknown msg (0x%x) <<<<<<<<\n",
		    proc, domid, msg);
		return (0);
	}

	token = IDN_RETRY_TOKEN(domid, (msg == IDNP_CON) ?
	    IDNRETRY_CON : IDNRETRY_FIN);
	if (msg == IDNP_CON)
		idn_retry_submit(idn_retry_con, NULL, token,
		    idn_msg_retrytime[(int)IDNRETRY_CON]);
	else
		idn_retry_submit(idn_retry_fin, NULL, token,
		    idn_msg_retrytime[(int)IDNRETRY_FIN]);

	return (1);
}

/*
 * Entered and returns w/DLOCK & SYNC_LOCK held.
 */
static void
idn_sync_enter(int domid, idn_synccmd_t cmd, domainset_t xset,
    domainset_t rset, int (*transfunc)(), void *transarg)
{
	int		z;
	idn_syncop_t	*sp;
	idn_synczone_t	*zp;
	procname_t	proc = "idn_sync_enter";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	z = IDN_SYNC_GETZONE(cmd);
	ASSERT(z >= 0);
	zp = &idn.sync.sz_zone[z];

	PR_SYNC("%s:%d: cmd=%s(%d), z=%d, xs=0x%x, rx=0x%x, cnt=%d\n",
	    proc, domid, idnsync_str[cmd], cmd, z, xset, rset, zp->sc_cnt);

	sp = &idn_domain[domid].dsync;

	sp->s_domid = domid;
	sp->s_cmd = cmd;
	sp->s_msg = 0;
	sp->s_set_exp = xset;
	sp->s_set_rdy = rset;
	sp->s_transfunc = transfunc;
	sp->s_transarg = transarg;
	IDN_SYNC_QUERY_INIT(domid);

	sp->s_next = zp->sc_op;
	zp->sc_op = sp;
	zp->sc_cnt++;
}

/*
 * Entered and returns w/DLOCK & SYNC_LOCK held.
 */
void
idn_sync_exit(int domid, idn_synccmd_t cmd)
{
	int		d, z, zone, tot_queries, tot_domains;
	idn_syncop_t	*sp;
	idn_synczone_t	*zp = NULL;
	procname_t	proc = "idn_sync_exit";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	sp = &idn_domain[domid].dsync;

	z = IDN_SYNC_GETZONE(sp->s_cmd);

	zone = IDN_SYNC_GETZONE(cmd);

	PR_SYNC("%s:%d: cmd=%s(%d) (z=%d, zone=%d)\n",
	    proc, domid, idnsync_str[cmd], cmd, z, zone);

#ifdef DEBUG
	if (z != -1) {
		tot_queries = tot_domains = 0;

		for (d = 0; d < MAX_DOMAINS; d++) {
			int	qv;

			if ((qv = sp->s_query[d]) > 0) {
				tot_queries += qv;
				tot_domains++;
				PR_SYNC("%s:%d: query_count = %d\n",
				    proc, domid, qv);
			}
		}
		PR_SYNC("%s:%d: tot_queries = %d, tot_domaines = %d\n",
		    proc, domid, tot_queries, tot_domains);
	}
#endif /* DEBUG */

	zp = (z != -1) ? &idn.sync.sz_zone[z] : NULL;

	if (zp) {
		idn_syncop_t	**spp;

		for (spp = &zp->sc_op; *spp; spp = &((*spp)->s_next)) {
			if (*spp == sp) {
				*spp = sp->s_next;
				sp->s_next = NULL;
				zp->sc_cnt--;
				break;
			}
		}
	}

	sp->s_cmd = IDNSYNC_NIL;

	for (z = 0; z < IDN_SYNC_NUMZONE; z++) {
		idn_syncop_t	**spp, **nspp;

		if ((zone != -1) && (z != zone))
			continue;

		zp = &idn.sync.sz_zone[z];

		for (spp = &zp->sc_op; *spp; spp = nspp) {
			sp = *spp;
			nspp = &sp->s_next;

			if (!DOMAIN_IN_SET(sp->s_set_exp, domid))
				continue;

			DOMAINSET_DEL(sp->s_set_exp, domid);
			DOMAINSET_DEL(sp->s_set_rdy, domid);

			if ((sp->s_set_exp == sp->s_set_rdy) &&
			    sp->s_transfunc) {
				int	delok;

				ASSERT(sp->s_domid != domid);

				PR_SYNC("%s:%d invoking transfunc "
				    "for domain %d\n",
				    proc, domid, sp->s_domid);
				delok = (*sp->s_transfunc)(sp->s_domid,
				    sp->s_transarg);
				if (delok) {
					*spp = sp->s_next;
					sp->s_next = NULL;
					zp->sc_cnt--;
					nspp = spp;
				}
			}
		}
	}
}

/*
 * Entered and returns w/DLOCK & SYNC_LOCK held.
 */
static domainset_t
idn_sync_register(int domid, idn_synccmd_t cmd, domainset_t ready_set,
    idn_syncreg_t regtype)
{
	int		z;
	idn_synczone_t	*zp;
	idn_syncop_t	*sp, **spp, **nspp;
	domainset_t	query_set = 0, trans_set;
	procname_t	proc = "idn_sync_register";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if ((z = IDN_SYNC_GETZONE(cmd)) == -1) {
		PR_SYNC("%s:%d: ERROR: unexpected sync cmd(%d)\n",
		    proc, domid, cmd);
		return (0);
	}

	/*
	 * Find out what domains are in transition with respect
	 * to given command.  There will be no need to query
	 * these folks.
	 */
	trans_set = IDN_SYNC_GETTRANS(cmd);

	zp = &idn.sync.sz_zone[z];

	PR_SYNC("%s:%d: cmd=%s(%d), z=%d, rset=0x%x, "
	    "regtype=%s(%d), sc_op=%s\n",
	    proc, domid, idnsync_str[cmd], cmd, z, ready_set,
	    idnreg_str[regtype], regtype,
	    zp->sc_op ? idnsync_str[zp->sc_op->s_cmd] : "NULL");

	for (spp = &zp->sc_op; *spp; spp = nspp) {
		sp = *spp;
		nspp = &sp->s_next;

		if (regtype == IDNSYNC_REG_NEW) {
			DOMAINSET_ADD(sp->s_set_exp, domid);
			PR_SYNC("%s:%d: adding new to %d (exp=0x%x)\n",
			    proc, domid, sp->s_domid, sp->s_set_exp);
		} else if (regtype == IDNSYNC_REG_QUERY) {
			query_set |= ~sp->s_set_rdy & sp->s_set_exp;
			continue;
		}

		if (!DOMAIN_IN_SET(sp->s_set_exp, domid))
			continue;

		if (!DOMAIN_IN_SET(ready_set, sp->s_domid)) {
			/*
			 * Given domid doesn't have a desired
			 * domain in his ready-set.  We'll need
			 * to query him again.
			 */
			DOMAINSET_ADD(query_set, domid);
			continue;
		}

		/*
		 * If we reach here, then an expected domain
		 * has marked its respective datapath to
		 * sp->s_domid as down (i.e. in his ready_set).
		 */
		DOMAINSET_ADD(sp->s_set_rdy, domid);

		PR_SYNC("%s:%d: mark READY for domain %d "
		    "(r=0x%x, x=0x%x)\n",
		    proc, domid, sp->s_domid,
		    sp->s_set_rdy, sp->s_set_exp);

		query_set |= ~sp->s_set_rdy & sp->s_set_exp;

		if (sp->s_set_exp == sp->s_set_rdy) {
#ifdef DEBUG
			if (sp->s_msg == 0) {
				sp->s_msg = 1;
				PR_SYNC("%s:%d: >>>>>>>>>>> DOMAIN %d "
				    "ALL CHECKED IN (0x%x)\n",
				    proc, domid, sp->s_domid,
				    sp->s_set_exp);
			}
#endif /* DEBUG */

			if ((sp->s_domid != domid) && sp->s_transfunc) {
				int	delok;

				PR_SYNC("%s:%d invoking transfunc "
				    "for domain %d\n",
				    proc, domid, sp->s_domid);
				delok = (*sp->s_transfunc)(sp->s_domid,
				    sp->s_transarg);
				if (delok) {
					*spp = sp->s_next;
					sp->s_next = NULL;
					zp->sc_cnt--;
					nspp = spp;
				}
			}
		}
	}

	PR_SYNC("%s:%d: trans_set = 0x%x, query_set = 0x%x -> 0x%x\n",
	    proc, domid, trans_set, query_set, query_set & ~trans_set);

	query_set &= ~trans_set;

	return (query_set);
}

static void
idn_sync_register_awol(int domid)
{
	int		z;
	idn_synccmd_t	cmd = IDNSYNC_DISCONNECT;
	idn_synczone_t	*zp;
	idn_syncop_t	*sp;
	procname_t	proc = "idn_sync_register_awol";

	ASSERT(IDN_SYNC_IS_LOCKED());

	if ((z = IDN_SYNC_GETZONE(cmd)) == -1) {
		PR_SYNC("%s:%d: ERROR: unexpected sync cmd(%d)\n",
		    proc, domid, cmd);
		return;
	}

	zp = &idn.sync.sz_zone[z];

	PR_SYNC("%s:%d: cmd=%s(%d), z=%d (domain %d = AWOL)\n",
	    proc, domid, idnsync_str[cmd], cmd, z, domid);

	for (sp = zp->sc_op; sp; sp = sp->s_next) {
		idn_domain_t	*dp;

		dp = &idn_domain[sp->s_domid];
		if (dp->dfin == IDNFIN_FORCE_HARD) {
			DOMAINSET_ADD(sp->s_set_rdy, domid);
			PR_SYNC("%s:%d: adding new to %d (rdy=0x%x)\n",
			    proc, domid, sp->s_domid, sp->s_set_rdy);
		}
	}
}

static void
idn_link_established(void *arg)
{
	int	first_link;
	int	domid, masterid;
	uint_t	info = (uint_t)(uintptr_t)arg;

	first_link = (int)(info & 0xf0);
	domid = (int)(info & 0x0f);

	IDN_GLOCK_SHARED();
	masterid = IDN_GET_MASTERID();
	if ((masterid == IDN_NIL_DOMID) ||
	    (idn_domain[masterid].dstate != IDNDS_CONNECTED)) {
		/*
		 * No point in doing this unless we're connected
		 * to the master.
		 */
		if ((masterid != IDN_NIL_DOMID) &&
		    (idn.state == IDNGS_ONLINE)) {
			/*
			 * As long as we're still online keep
			 * trying.
			 */
			(void) timeout(idn_link_established, arg, 50);
		}
		IDN_GUNLOCK();
		return;
	}
	IDN_GUNLOCK();

	if (first_link && IDN_SLAB_PREALLOC)
		idn_prealloc_slab(IDN_SLAB_PREALLOC);

	/*
	 * No guarantee, but it might save a little
	 * time.
	 */
	if (idn_domain[domid].dstate == IDNDS_CONNECTED) {
		/*
		 * Get the remote domain's dname.
		 */
		idn_send_nodename_req(domid);
	}

	/*
	 * May have had some streams backed up waiting for
	 * this connection.  Prod them.
	 */
	rw_enter(&idn.struprwlock, RW_READER);
	mutex_enter(&idn.sipwenlock);
	idndl_wenable(NULL);
	mutex_exit(&idn.sipwenlock);
	rw_exit(&idn.struprwlock);
}

/*
 * Send the following chunk of data received from above onto
 * the IDN wire.  This is raw data as far as the IDN driver
 * is concerned.
 * Returns:
 *	IDNXMIT_LOOP	- Msg handled in loopback and thus
 *			  still active (i.e. don't free).
 *	IDNXMIT_OKAY	- Data handled (freemsg).
 *	IDNXMIT_DROP	- Packet should be dropped.
 *	IDNXMIT_RETRY	- Packet should be requeued and retried.
 *	IDNXMIT_REQUEUE	- Packet should be requeued, but not
 *			  immediatetly retried.
 */
int
idn_send_data(int dst_domid, idn_netaddr_t dst_netaddr, queue_t *wq, mblk_t *mp)
{
	int		pktcnt = 0;
	int		msglen;
	int		rv = IDNXMIT_OKAY;
	int		xfersize = 0;
	caddr_t		iobufp, iodatap;
	uchar_t		*data_rptr;
	int		cpuindex;
	int		serrno;
	int		channel;
	int		retry_reclaim;
	idn_chansvr_t	*csp = NULL;
	uint_t		netports = 0;
	struct idnstr	*stp;
	struct idn	*sip;
	idn_domain_t	*dp;
	struct ether_header	*ehp;
	smr_pkthdr_t	*hdrp;
	idn_msgtype_t	mt;
	procname_t	proc = "idn_send_data";
#ifdef DEBUG
	size_t		orig_msglen = msgsize(mp);
#endif /* DEBUG */

	ASSERT(DB_TYPE(mp) == M_DATA);

	mt.mt_mtype = IDNP_DATA;
	mt.mt_atype = 0;
	mt.mt_cookie = 0;

	channel = (int)dst_netaddr.net.chan;

	msglen = msgdsize(mp);
	PR_DATA("%s:%d: (netaddr 0x%x) msgsize=%ld, msgdsize=%d\n",
	    proc, dst_domid, dst_netaddr.netaddr, msgsize(mp), msglen);

	ASSERT(wq->q_ptr);

	stp = (struct idnstr *)wq->q_ptr;
	sip = stp->ss_sip;
	ASSERT(sip);

	if (msglen < 0) {
		/*
		 * No data to send.  That was easy!
		 */
		PR_DATA("%s:%d: BAD msg length (%d) (netaddr 0x%x)\n",
		    proc, dst_domid, msglen, dst_netaddr.netaddr);
		return (IDNXMIT_DROP);
	}

	ASSERT(RW_READ_HELD(&stp->ss_rwlock));

	if (dst_domid == IDN_NIL_DOMID) {
		cmn_err(CE_WARN,
		    "IDN: 213: no destination specified "
		    "(d=%d, c=%d, n=0x%x)",
		    dst_domid, dst_netaddr.net.chan,
		    dst_netaddr.net.netid);
		IDN_KSTAT_INC(sip, si_nolink);
		IDN_KSTAT_INC(sip, si_macxmt_errors);
		rv = IDNXMIT_DROP;
		goto nocando;
	}

	ehp = (struct ether_header *)mp->b_rptr;
	PR_DATA("%s:%d: destination channel = %d\n", proc, dst_domid, channel);

#ifdef DEBUG
	{
		uchar_t	echn;

		echn = (uchar_t)
		    ehp->ether_shost.ether_addr_octet[IDNETHER_CHANNEL];
		ASSERT((uchar_t)channel == echn);
	}
#endif /* DEBUG */
	ASSERT(msglen <= IDN_DATA_SIZE);

	dp = &idn_domain[dst_domid];
	/*
	 * Get reader lock.  We hold for the duration
	 * of the transfer so that our state doesn't
	 * change during this activity.  Note that since
	 * we grab the reader lock, we can still permit
	 * simultaneous tranfers from different threads
	 * to the same domain.
	 * Before we waste a bunch of time gathering locks, etc.
	 * do a an unprotected check to make sure things are
	 * semi-copesetic.  If these values are in flux,
	 * that's okay.
	 */
	if ((dp->dstate != IDNDS_CONNECTED) || (idn.state != IDNGS_ONLINE)) {
		IDN_KSTAT_INC(sip, si_linkdown);
		if (idn.state != IDNGS_ONLINE) {
			rv = IDNXMIT_REQUEUE;
		} else {
			IDN_KSTAT_INC(sip, si_macxmt_errors);
			rv = IDNXMIT_DROP;
		}
		goto nocando;
	}

	if (idn.chan_servers[channel].ch_send.c_checkin) {
		/*
		 * Gotta bail, somethin' s'up.
		 */
		rv = IDNXMIT_REQUEUE;
		goto nocando;
	}

	csp = &idn.chan_servers[channel];
	IDN_CHAN_LOCK_SEND(csp);

	if (dst_netaddr.net.netid == IDN_BROADCAST_ALLNETID) {
		/*
		 * We're doing a broadcast.  Need to set
		 * up IDN netaddr's one at a time.
		 * We set the ethernet destination to the same
		 * instance as the sending address.  The instance
		 * numbers effectively represent subnets.
		 */
		dst_netaddr.net.netid = dp->dnetid;

		(void) idndl_domain_etheraddr(dst_domid, channel,
		    &ehp->ether_dhost);

		if (dst_domid == idn.localid) {
			mblk_t	*nmp;
			/*
			 * If this is a broadcast and going to
			 * the local domain, then we need to make
			 * a private copy of the message since
			 * the current one will be reused when
			 * transmitting to other domains.
			 */
			PR_DATA("%s:%d: dup broadcast msg for local domain\n",
			    proc, dst_domid);
			if ((nmp = copymsg(mp)) == NULL) {
				/*
				 * Couldn't get a duplicate copy.
				 */
				IDN_CHAN_UNLOCK_SEND(csp);
				csp = NULL;
				IDN_KSTAT_INC(sip, si_allocbfail);
				IDN_KSTAT_INC(sip, si_noxmtbuf);
				rv = IDNXMIT_DROP;
				goto nocando;
			}
			mp = nmp;
		}
	}

	if (dp->dnetid != dst_netaddr.net.netid) {
		PR_DATA("%s:%d: dest netid (0x%x) != expected (0x%x)\n",
		    proc, dst_domid, (uint_t)dst_netaddr.net.netid,
		    (uint_t)dp->dnetid);
		IDN_CHAN_UNLOCK_SEND(csp);
		csp = NULL;
		IDN_KSTAT_INC(sip, si_nolink);
		IDN_KSTAT_INC(sip, si_macxmt_errors);
		rv = IDNXMIT_DROP;
		goto nocando;
	}

	if (dst_domid == idn.localid) {
		int	lbrv;
		/*
		 * Sending to our local domain! Loopback.
		 * Note that idn_send_data_loop returning 0
		 * does not mean the message can now be freed.
		 * We need to return (-1) so that caller doesn't
		 * try to free mblk.
		 */
		IDN_CHAN_UNLOCK_SEND(csp);
		rw_exit(&stp->ss_rwlock);
		lbrv = idn_send_data_loopback(dst_netaddr, wq, mp);
		rw_enter(&stp->ss_rwlock, RW_READER);
		if (lbrv == 0) {
			return (IDNXMIT_LOOP);
		} else {
			IDN_KSTAT_INC(sip, si_macxmt_errors);
			return (IDNXMIT_DROP);
		}
	}

	if (dp->dstate != IDNDS_CONNECTED) {
		/*
		 * Can't send data unless a link has already been
		 * established with the target domain.  Normally,
		 * a user cannot set the remote netaddr unless a
		 * link has already been established, however it
		 * is possible the connection may have become
		 * disconnected since that time.
		 */
		IDN_CHAN_UNLOCK_SEND(csp);
		csp = NULL;
		IDN_KSTAT_INC(sip, si_linkdown);
		IDN_KSTAT_INC(sip, si_macxmt_errors);
		rv = IDNXMIT_DROP;
		goto nocando;
	}

	/*
	 * Need to make sure the channel is active and that the
	 * domain to which we're sending is allowed to receive stuff.
	 */
	if (!IDN_CHANNEL_IS_SEND_ACTIVE(csp)) {
		int	not_active;
		/*
		 * See if we can activate channel.
		 */
		IDN_CHAN_UNLOCK_SEND(csp);
		not_active = idn_activate_channel(CHANSET(channel),
		    IDNCHAN_OPEN);
		if (!not_active) {
			/*
			 * Only grab the lock for a recheck if we were
			 * able to activate the channel.
			 */
			IDN_CHAN_LOCK_SEND(csp);
		}
		/*
		 * Verify channel still active now that we have the lock.
		 */
		if (not_active || !IDN_CHANNEL_IS_SEND_ACTIVE(csp)) {
			if (!not_active) {
				/*
				 * Only need to drop the lock if it was
				 * acquired while we thought we had
				 * activated the channel.
				 */
				IDN_CHAN_UNLOCK_SEND(csp);
			}
			ASSERT(!IDN_CHAN_SEND_IS_LOCKED(csp));
			/*
			 * Damn!   Must have went inactive during the window
			 * before we regrabbed the send lock.  Oh well, can't
			 * spend all day doing this, bail out.  Set csp to
			 * NULL to prevent inprogress update at bottom.
			 */
			csp = NULL;
			/*
			 * Channel is not active, should not be used.
			 */
			PR_DATA("%s:%d: dest channel %d NOT ACTIVE\n",
			    proc, dst_domid, channel);
			IDN_KSTAT_INC(sip, si_linkdown);
			rv = IDNXMIT_REQUEUE;
			goto nocando;
		}
		ASSERT(IDN_CHAN_SEND_IS_LOCKED(csp));
	}
	/*
	 * If we made it here then the channel is active
	 * Make sure the target domain is registered to receive stuff,
	 * i.e. we're still linked.
	 */
	if (!IDN_CHAN_DOMAIN_IS_REGISTERED(csp, dst_domid)) {
		/*
		 * If domain is not even registered with this channel
		 * then we have no business being here.  Doesn't matter
		 * whether it's active or not.
		 */
		PR_DATA("%s:%d: domain not registered with channel %d\n",
		    proc, dst_domid, channel);
		/*
		 * Set csp to NULL to prevent in-progress update below.
		 */
		IDN_CHAN_UNLOCK_SEND(csp);
		csp = NULL;
		IDN_KSTAT_INC(sip, si_linkdown);
		IDN_KSTAT_INC(sip, si_macxmt_errors);
		rv = IDNXMIT_DROP;
		goto nocando;
	}

	IDN_CHAN_SEND_INPROGRESS(csp);
	IDN_CHAN_UNLOCK_SEND(csp);

	/*
	 * Find a target cpu to send interrupt to if
	 * it becomes necessary (i.e. remote channel
	 * server is idle).
	 */
	cpuindex = dp->dcpuindex;

	/*
	 * dcpuindex is atomically incremented, but other than
	 * that is not well protected and that's okay.  The
	 * intention is to simply spread around the interrupts
	 * at the destination domain, however we don't have to
	 * anal about it.  If we hit the same cpu multiple times
	 * in a row that's okay, it will only be for a very short
	 * period anyway before the cpuindex is incremented
	 * to the next cpu.
	 */
	if (cpuindex < NCPU) {
		ATOMIC_INC(dp->dcpuindex);
	}
	if (dp->dcpuindex >= NCPU)
		dp->dcpuindex = 0;

	IDN_ASSIGN_DCPU(dp, cpuindex);

#ifdef XXX_DLPI_UNFRIENDLY
	{
		ushort_t	dstport = (ushort_t)dp->dcpu;

		/*
		 * XXX
		 * This is not DLPI friendly, but we need some way
		 * of distributing our XDC interrupts to the cpus
		 * on the remote domain in a relatively random fashion
		 * while trying to remain constant for an individual
		 * network connection.  Don't want the target network
		 * appl pinging around cpus thrashing the caches.
		 * So, we'll pick target cpus based on the destination
		 * TCP/IP port (socket).  The (simple) alternative to
		 * this is to simply send all messages destined for
		 * particular domain to the same cpu (dcpu), but
		 * will lower our bandwidth and introduce a lot of
		 * contention on that target cpu.
		 */
		if (ehp->ether_type == ETHERTYPE_IP) {
			ipha_t	*ipha;
			uchar_t	*dstporta;
			int	hdr_length;
			mblk_t	*nmp = mp;
			uchar_t	*rptr = mp->b_rptr +
			    sizeof (struct ether_header);
			if (nmp->b_wptr <= rptr) {
				/*
				 * Only the ethernet header was contained
				 * in the first block.  Check for the
				 * next packet.
				 */
				if ((nmp = mp->b_cont) != NULL)
					rptr = nmp->b_rptr;
			}
			/*
			 * If we still haven't found the IP header packet
			 * then don't bother.  Can't search forever.
			 */
			if (nmp &&
			    ((nmp->b_wptr - rptr) >= IP_SIMPLE_HDR_LENGTH)) {
				ipha = (ipha_t *)ALIGN32(rptr);

				ASSERT(DB_TYPE(mp) == M_DATA);
				hdr_length = IPH_HDR_LENGTH(ipha);

				switch (ipha->ipha_protocol) {
				case IPPROTO_UDP:
				case IPPROTO_TCP:
					/*
					 * TCP/UDP Protocol Header (1st word)
					 * 0	    15,16	31
					 * -----------------------
					 * | src port | dst port |
					 * -----------------------
					 */
					dstporta = (uchar_t *)ipha + hdr_length;
					netports = *(uint_t *)dstporta;
					dstporta += 2;
					dstport  = *(ushort_t *)dstporta;
					break;
				default:
					break;
				}
			}

		}
		IDN_ASSIGN_DCPU(dp, dstport);

		PR_DATA("%s:%d: (dstport %d) assigned %d\n",
		    proc, dst_domid, (int)dstport, dp->dcpu);
	}
#endif /* XXX_DLPI_UNFRIENDLY */

	data_rptr = mp->b_rptr;

	ASSERT(dp->dcpu != IDN_NIL_DCPU);

	ASSERT(idn_domain[dst_domid].dmbox.m_send);

	retry_reclaim = 1;
retry:
	if ((dp->dio >= IDN_RECLAIM_MIN) || dp->diowanted) {
		int	reclaim_req;
		/*
		 * Reclaim however many outstanding buffers
		 * there are up to IDN_RECLAIM_MAX if it's set.
		 */
		reclaim_req = dp->diowanted ? -1 : IDN_RECLAIM_MAX ?
		    MIN(dp->dio, IDN_RECLAIM_MAX) : dp->dio;
		(void) idn_reclaim_mboxdata(dst_domid, channel,
		    reclaim_req);
	}

	if (dp->dio >= IDN_WINDOW_EMAX) {

		if (lock_try(&dp->diocheck)) {
			IDN_MSGTIMER_START(dst_domid, IDNP_DATA, 0,
			    idn_msg_waittime[IDNP_DATA],
			    &mt.mt_cookie);
			/*
			 * We have exceeded the minimum window for
			 * outstanding I/O buffers to this domain.
			 * Need to start the MSG timer to check for
			 * possible response from remote domain.
			 * The remote domain may be hung.  Send a
			 * wakeup!  Specify all channels for given
			 * domain since we don't know precisely which
			 * is backed up (dio is global).
			 */
			IDNXDC(dst_domid, &mt,
			    (uint_t)dst_netaddr.net.chan, 0, 0, 0);
		}

		/*
		 * Yikes!  We have exceeded the maximum window
		 * which means no more packets going to remote
		 * domain until he frees some up.
		 */
		IDN_KSTAT_INC(sip, si_txmax);
		IDN_KSTAT_INC(sip, si_macxmt_errors);
		rv = IDNXMIT_DROP;
		goto nocando;
	}

	/*
	 * Allocate a SMR I/O buffer and send it.
	 */
	if (msglen == 0) {
		/*
		 * A zero length messages is effectively a signal
		 * to just send an interrupt to the remote domain.
		 */
		IDN_MSGTIMER_START(dst_domid, IDNP_DATA, 0,
		    idn_msg_waittime[IDNP_DATA],
		    &mt.mt_cookie);
		IDNXDC(dst_domid, &mt,
		    (uint_t)dst_netaddr.net.chan, 0, 0, 0);
	}
	for (; (msglen > 0) && mp; msglen -= xfersize) {
		int		xrv;
		smr_offset_t	bufoffset;
#ifdef DEBUG
		int		n_xfersize;
#endif /* DEBUG */

		ASSERT(msglen <= IDN_DATA_SIZE);
		xfersize = msglen;

		serrno = smr_buf_alloc(dst_domid, xfersize, &iobufp);
		if (serrno) {
			PR_DATA("%s:%d: failed to alloc SMR I/O buffer "
			    "(serrno = %d)\n",
			    proc, dst_domid, serrno);
			/*
			 * Failure is either due to a timeout waiting
			 * for the master to give us a slab, OR the
			 * local domain exhausted its slab quota!
			 * In either case we'll have to bail from
			 * here and let higher layers decide what
			 * to do.
			 * We also could have had locking problems.
			 * A negative serrno indicates we lost the lock
			 * on dst_domid, so no need in dropping lock.
			 */

			if (lock_try(&dp->diowanted) && retry_reclaim) {
				/*
				 * We were the first to acquire the
				 * lock indicating that it wasn't
				 * set on entry to idn_send_data.
				 * So, let's go back and see if we
				 * can't reclaim some buffers and
				 * try again.
				 * It's very likely diowanted will be
				 * enough to prevent us from looping
				 * on retrying here, however to protect
				 * against the small window where a
				 * race condition might exist, we use
				 * the retry_reclaim flag so that we
				 * don't retry more than once.
				 */
				retry_reclaim = 0;
				goto retry;
			}

			rv = (serrno > 0) ? serrno : -serrno;
			IDN_KSTAT_INC(sip, si_notbufs);
			IDN_KSTAT_INC(sip, si_noxmtbuf);	/* MIB II */
			switch (rv) {
			case ENOMEM:
			case EBUSY:
			case ENOLCK:
			case ETIMEDOUT:
			case EDQUOT:
				/*
				 * These are all transient conditions
				 * which should be recoverable over
				 * time.
				 */
				rv = IDNXMIT_REQUEUE;
				break;

			default:
				rv = IDNXMIT_DROP;
				break;
			}
			goto nocando;
		}

		lock_clear(&dp->diowanted);

		hdrp = IDN_BUF2HDR(iobufp);
		bufoffset = (smr_offset_t)IDN_ALIGNPTR(sizeof (smr_pkthdr_t),
		    data_rptr);
		/*
		 * If the alignment of bufoffset took us pass the
		 * length of a smr_pkthdr_t then we need to possibly
		 * lower xfersize since it was calulated based on
		 * a perfect alignment.  However, if we're in DLPI
		 * mode then shouldn't be necessary since the length
		 * of the incoming packet (mblk) should have already
		 * taken into consideration this possible adjustment.
		 */
#ifdef DEBUG
		if (bufoffset != sizeof (smr_pkthdr_t))
			PR_DATA("%s:%d: offset ALIGNMENT (%lu -> %u) "
			    "(data_rptr = %p)\n",
			    proc, dst_domid, sizeof (smr_pkthdr_t),
			    bufoffset, (void *)data_rptr);

		n_xfersize = MIN(xfersize, (IDN_SMR_BUFSIZE - bufoffset));
		if (xfersize != n_xfersize) {
			PR_DATA("%s:%d: xfersize ADJUST (%d -> %d)\n",
			    proc, dst_domid, xfersize, n_xfersize);
			cmn_err(CE_WARN, "%s: ERROR (xfersize = %d, > "
			    "bufsize(%d)-bufoffset(%d) = %d)",
			    proc, xfersize, IDN_SMR_BUFSIZE,
			    bufoffset,
			    IDN_SMR_BUFSIZE - bufoffset);
		}
#endif /* DEBUG */
		xfersize = MIN(xfersize, (int)(IDN_SMR_BUFSIZE - bufoffset));

		iodatap = IDN_BUF2DATA(iobufp, bufoffset);
		mp = idn_fill_buffer(iodatap, xfersize, mp, &data_rptr);

		hdrp->b_netaddr  = dst_netaddr.netaddr;
		hdrp->b_netports = netports;
		hdrp->b_offset   = bufoffset;
		hdrp->b_length   = xfersize;
		hdrp->b_next	 = IDN_NIL_SMROFFSET;
		hdrp->b_rawio	 = 0;
		hdrp->b_cksum    = IDN_CKSUM_PKT(hdrp);

		xrv = idn_send_mboxdata(dst_domid, sip, channel, iobufp);
		if (xrv) {
			/*
			 * Reclaim packet.
			 * Return error on this packet so it can be retried
			 * (putbq).  Note that it should be safe to assume
			 * that this for-loop is only executed once when in
			 * DLPI mode and so no need to worry about fractured
			 * mblk packet.
			 */
			PR_DATA("%s:%d: DATA XFER to chan %d FAILED "
			    "(ret=%d)\n",
			    proc, dst_domid, channel, xrv);
			(void) smr_buf_free(dst_domid, iobufp, xfersize);

			PR_DATA("%s:%d: (line %d) dec(dio) -> %d\n",
			    proc, dst_domid, __LINE__, dp->dio);

			rv = IDNXMIT_DROP;
			IDN_KSTAT_INC(sip, si_macxmt_errors);
			goto nocando;
		} else {
			pktcnt++;
			/*
			 * Packet will get freed on a subsequent send
			 * when we reclaim buffers that the receivers
			 * has finished consuming.
			 */
		}
	}

#ifdef DEBUG
	if (pktcnt > 1)
		cmn_err(CE_WARN,
		    "%s: ERROR: sent multi-pkts (%d), len = %ld",
		    proc, pktcnt, orig_msglen);
#endif /* DEBUG */

	PR_DATA("%s:%d: SENT %d packets (%d @ 0x%x)\n",
	    proc, dst_domid, pktcnt, dst_netaddr.net.chan,
	    dst_netaddr.net.netid);

	IDN_CHAN_LOCK_SEND(csp);
	IDN_CHAN_SEND_DONE(csp);
	IDN_CHAN_UNLOCK_SEND(csp);

	return (IDNXMIT_OKAY);

nocando:

	if (csp) {
		IDN_CHAN_LOCK_SEND(csp);
		IDN_CHAN_SEND_DONE(csp);
		IDN_CHAN_UNLOCK_SEND(csp);
	}

	if (rv == IDNXMIT_REQUEUE) {
		/*
		 * Better kick off monitor to check when
		 * it's ready to reenable the queues for
		 * this channel.
		 */
		idn_xmit_monitor_kickoff(channel);
	}

	return (rv);
}

/*
 * Function to support local loopback testing of IDN driver.
 * Primarily geared towards measuring stream-head and IDN driver
 * overhead with respect to data messages.  Setting idn_strhead_only
 * allows routine to focus on stream-head overhead by simply putting
 * the message straight to the 'next' queue of the destination
 * read-queue.  Current implementation puts the message directly to
 * the read-queue thus sending the message right back to the IDN driver
 * as though the data came in off the wire.  No need to worry about
 * any IDN layers attempting to ack data as that's normally handled
 * by idnh_recv_data.
 *
 * dst_netaddr = destination port-n-addr on local domain.
 * wq          = write queue from whence message came.
 * mp          = the (data-only) message.
 *
 * Returns 0		Indicates data handled.
 *	   errno	EAGAIN indicates data can be retried.
 *			Other errno's indicate failure to handle.
 */
static int
idn_send_data_loopback(idn_netaddr_t dst_netaddr, queue_t *wq, mblk_t *mp)
{
	register struct idnstr	*stp;
	struct idn	*sip;
	int		rv = 0;
	procname_t	proc = "idn_send_data_loopback";

	if (dst_netaddr.net.netid != idn_domain[idn.localid].dnetid) {
		PR_DATA("%s: dst_netaddr.net.netid 0x%x != local 0x%x\n",
		    proc, dst_netaddr.net.netid,
		    idn_domain[idn.localid].dnetid);
		rv = EADDRNOTAVAIL;
		goto done;
	}
	stp = (struct idnstr *)wq->q_ptr;
	if (!stp || !stp->ss_rq) {
		rv = EDESTADDRREQ;
		goto done;
	}
	sip = stp->ss_sip;

	idndl_read(sip, mp);
	rv = 0;

done:
	return (rv);
}

/*
 * Fill bufp with as much data as possible from the message pointed
 * to by mp up to size bytes.
 * Save our current read pointer in the variable parameter (data_rptrp)
 * so we know where to start on the next go around.  Don't want to
 * bump the actual b_rptr in the mblk because the mblk may need to
 * be reused, e.g. broadcast.
 * Return the mblk pointer to the position we had to stop.
 */
static mblk_t *
idn_fill_buffer(caddr_t bufp, int size, mblk_t *mp, uchar_t **data_rptrp)
{
	int	copysize;

	ASSERT(bufp && size);

	if (mp == NULL)
		return (NULL);

	while ((size > 0) && mp) {

		copysize = MIN(mp->b_wptr - (*data_rptrp), size);

		if (copysize > 0) {
			/*
			 * If there's data to copy, do it.
			 */
			bcopy((*data_rptrp), bufp, copysize);
			(*data_rptrp) += copysize;
			bufp += copysize;
			size -= copysize;
		}
		if (mp->b_wptr <= (*data_rptrp)) {
			/*
			 * If we emptied the mblk, then
			 * move on to the next one.
			 */
			for (mp = mp->b_cont;
			    mp && (mp->b_datap->db_type != M_DATA);
			    mp = mp->b_cont)
				;
			if (mp)
				*data_rptrp = mp->b_rptr;
		}
	}
	return (mp);
}

/*
 * Messages received here do NOT arrive on a stream, but are
 * instead handled via the idn_protocol_servers.  This routine
 * is effectively the job processor for the protocol servers.
 */
static void
idn_recv_proto(idn_protomsg_t *hp)
{
	int		domid, cpuid;
	int		sync_lock = 0;
	idn_domain_t	*dp;
	register uint_t	mtype;
	register uint_t	msgtype, acktype;
	idn_msgtype_t	mt;
	ushort_t	dcookie, tcookie;
	procname_t	proc = "idn_recv_proto";


	if (idn.state == IDNGS_IGNORE) {
		/*
		 * Fault injection to simulate non-responsive domain.
		 */
		return;
	}

	domid   = hp->m_domid;
	cpuid   = hp->m_cpuid;
	msgtype = hp->m_msgtype;
	acktype = hp->m_acktype;
	dcookie = IDN_DCOOKIE(hp->m_cookie);
	tcookie = IDN_TCOOKIE(hp->m_cookie);
	/*
	 * msgtype =	Is the type of message we received,
	 *		e.g. nego, ack, nego+ack, etc.
	 *
	 * acktype =	If we received a pure ack or nack
	 *		then this variable is set to the
	 *		type of message that was ack/nack'd.
	 */
	if ((mtype = msgtype & IDNP_MSGTYPE_MASK) == 0) {
		/*
		 * Received a pure ack/nack.
		 */
		mtype = acktype & IDNP_MSGTYPE_MASK;
	}

	if (!VALID_MSGTYPE(mtype)) {
		PR_PROTO("%s:%d: ERROR: invalid message type (0x%x)\n",
		    proc, domid, mtype);
		return;
	}
	if (!VALID_CPUID(cpuid)) {
		PR_PROTO("%s:%d: ERROR: invalid cpuid (%d)\n",
		    proc, domid, cpuid);
		return;
	}

	/*
	 * No pure data packets should reach this level.
	 * Data+ack messages will reach here, but only
	 * for the purpose of stopping the timer which
	 * happens by default when this routine is called.
	 */
	ASSERT(msgtype != IDNP_DATA);

	/*
	 * We should never receive a request from ourself,
	 * except for commands in the case of broadcasts!
	 */
	if ((domid == idn.localid) && (mtype != IDNP_CMD)) {
		char	str[15];

		inum2str(hp->m_msgtype, str);

		cmn_err(CE_WARN,
		    "IDN: 214: received message (%s[0x%x]) from self "
		    "(domid %d)",
		    str, hp->m_msgtype, domid);
		return;
	}

	IDN_SYNC_LOCK();
	/*
	 * Set a flag indicating whether we really need
	 * SYNC-LOCK.  We'll drop it in a little bit if
	 * we really don't need it.
	 */
	switch (mtype) {
	case IDNP_CON:
	case IDNP_FIN:
	case IDNP_NEGO:
		sync_lock = 1;
		break;

	default:
		break;
	}

	dp = &idn_domain[domid];
	IDN_DLOCK_EXCL(domid);

	/*
	 * The only messages we do _not_ check the cookie are:
	 *	nego
	 *	nego+ack
	 *	fin	 - if received cookie is 0.
	 *	fin+ack	 - if received cookie is 0.
	 *	ack/fin	 - if received cookie is 0.
	 *	nack/fin - if received cookie is 0.
	 */
	if (((msgtype & IDNP_MSGTYPE_MASK) != IDNP_NEGO) &&
	    ((mtype != IDNP_FIN) || (dcookie && dp->dcookie_recv))) {
		if (dp->dcookie_recv != dcookie) {
			dp->dcookie_errcnt++;
			if (dp->dcookie_err == 0) {
				/*
				 * Set cookie error to prevent a
				 * possible flood of bogus cookies
				 * and thus error messages.
				 */
				dp->dcookie_err = 1;
				cmn_err(CE_WARN,
				    "IDN: 215: invalid cookie (0x%x) "
				    "for message (0x%x) from domain %d",
				    dcookie, hp->m_msgtype, domid);

				PR_PROTO("%s:%d: received cookie (0x%x), "
				    "expected (0x%x) [errcnt = %d]\n",
				    proc, domid, dcookie,
				    dp->dcookie_recv, dp->dcookie_errcnt);
			}
			IDN_DUNLOCK(domid);
			IDN_SYNC_UNLOCK();
			return;
		}
	}
	dp->dcookie_err = 0;
	IDN_GLOCK_EXCL();

	idn_clear_awol(domid);

	IDN_GUNLOCK();
	if (!sync_lock)		/* really don't need SYNC-LOCK past here */
		IDN_SYNC_UNLOCK();

	/*
	 * Stop any timers that may have been outstanding for
	 * this domain, for this particular message type.
	 * Note that CFG timers are directly managed by
	 * config recv/send code.
	 */
	if ((mtype != IDNP_CFG) && (msgtype & IDNP_ACKNACK_MASK) && tcookie) {
		IDN_MSGTIMER_STOP(domid, mtype, tcookie);
	}

	/*
	 * Keep track of the last cpu to send us a message.
	 * If the domain has not yet been assigned, we'll need
	 * this cpuid in order to send back a respond.
	 */
	dp->dcpu_last = cpuid;

	mt.mt_mtype = (ushort_t)msgtype;
	mt.mt_atype = (ushort_t)acktype;
	mt.mt_cookie = tcookie;

	switch (mtype) {
	case IDNP_NEGO:
		(void) idn_recv_nego(domid, &mt, hp->m_xargs, dcookie);
		break;

	case IDNP_CFG:
		idn_recv_config(domid, &mt, hp->m_xargs);
		break;

	case IDNP_CON:
		(void) idn_recv_con(domid, &mt, hp->m_xargs);
		break;

	case IDNP_FIN:
		(void) idn_recv_fin(domid, &mt, hp->m_xargs);
		break;

	case IDNP_CMD:
		idn_recv_cmd(domid, &mt, hp->m_xargs);
		break;

	case IDNP_DATA:
		ASSERT(msgtype & IDNP_ACKNACK_MASK);
		/*
		 * When doing the fast track we simply process
		 * possible nack error conditions.  The actual
		 * processing of the SMR data buffer is taken
		 * care of in idnh_recv_dataack.  When NOT doing
		 * the fast track, we do all the processing here
		 * in the protocol server.
		 */
		(void) idn_recv_data(domid, &mt, hp->m_xargs);
		break;

	default:
		/*
		 * Should be receiving 0 inum and 0 acknack.
		 */
#ifdef DEBUG
		cmn_err(CE_PANIC,
#else /* DEBUG */
		    cmn_err(CE_WARN,
#endif /* DEBUG */
			/* CSTYLED */
			"IDN: 216: (0x%x)msgtype/(0x%x)acktype rcvd from "
			/* CSTYLED */
			"domain %d", msgtype, acktype, domid);
		break;
	}

	IDN_DUNLOCK(domid);
	/*
	 * All receiving routines are responsible for dropping drwlock.
	 */

	if (sync_lock)
		IDN_SYNC_UNLOCK();
}

/*
 * Once the CONFIG state is hit we immediately blast out all
 * of our config info.  This guarantees that the CONFIG state
 * effectively signifies that the sender has sent _all_ of
 * their config info.
 */
static void
idn_send_config(int domid, int phase)
{
	idn_domain_t	*dp;
	int		rv;
	clock_t		cfg_waittime = idn_msg_waittime[IDNP_CFG];
	procname_t	proc = "idn_send_config";

	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	dp = &idn_domain[domid];

	ASSERT(dp->dstate == IDNDS_CONFIG);

	if (phase == 1) {
		/*
		 * Reset stuff in dtmp to 0:
		 *	dcfgphase
		 *	dcksum
		 *	dncfgitems
		 *	dmaxnets
		 *	dmboxpernet
		 */
		dp->dtmp = 0;
	}

	if (dp->dcfgsnddone) {
		if (!dp->dcfgrcvdone) {
			IDN_MSGTIMER_START(domid, IDNP_CFG, 0,
			    cfg_waittime, NULL);
		}
		return;
	}

	IDN_DLOCK_SHARED(idn.localid);

	PR_PROTO("%s:%d: sending %s config (phase %d)\n",
	    proc, domid,
	    idn_domain[idn.localid].dvote.v.master ? "MASTER" : "SLAVE",
	    phase);

	if (idn_domain[idn.localid].dvote.v.master)
		rv = idn_send_master_config(domid, phase);
	else
		rv = idn_send_slave_config(domid, phase);

	IDN_DUNLOCK(idn.localid);

	if (rv >= 0) {

		if (rv == 1) {
			dp->dcfgsnddone = 1;
			PR_PROTO("%s:%d: SEND config DONE\n", proc, domid);
			if (!dp->dcfgrcvdone) {
				IDN_MSGTIMER_START(domid, IDNP_CFG, 0,
				    cfg_waittime, NULL);
			}
		} else {
			IDN_MSGTIMER_START(domid, IDNP_CFG, 0,
			    cfg_waittime, NULL);
		}
	}
}

/*
 * Clear out the mailbox table.
 * NOTE: This routine touches the SMR.
 */
static void
idn_reset_mboxtbl(idn_mboxtbl_t *mtp)
{
	int		qi;
	idn_mboxmsg_t	*mp = &mtp->mt_queue[0];

	qi = 0;
	do {
		mp[qi].ms_bframe = 0;
		mp[qi].ms_owner = 0;
		mp[qi].ms_flag = 0;
		IDN_MMBOXINDEX_INC(qi);
	} while (qi);
}

static int
idn_get_mbox_config(int domid, int *mindex, smr_offset_t *mtable,
    smr_offset_t *mdomain)
{
	idn_domain_t	*dp, *ldp;

	dp = &idn_domain[domid];
	ldp = &idn_domain[idn.localid];

	ASSERT(IDN_DLOCK_IS_EXCL(domid));
	ASSERT(IDN_DLOCK_IS_SHARED(idn.localid));
	ASSERT(IDN_GET_MASTERID() != IDN_NIL_DOMID);

	/*
	 * Get SMR offset of receive mailbox assigned
	 * to respective domain.  If I'm a slave then
	 * my dmbox.m_tbl will not have been assigned yet.
	 * Instead of sending the actual offset I send
	 * the master his assigned index.  Since the
	 * master knows what offset it will assign to
	 * me he can determine his assigned (recv) mailbox
	 * based on the offset and given index.  The local
	 * domain can also use this information once the
	 * dmbox.m_tbl is received to properly assign the
	 * correct mbox offset to the master.
	 */
	if (ldp->dmbox.m_tbl == NULL) {
		/*
		 * Local domain has not yet been assigned a
		 * (recv) mailbox table.  This must be the
		 * initial connection of this domain.
		 */
		ASSERT(dp->dvote.v.master && !ldp->dvote.v.master);
		ASSERT(mindex);
		*mindex = domid;
	} else {
		idn_mboxtbl_t	*mtp;

		mtp = IDN_MBOXTBL_PTR(ldp->dmbox.m_tbl, domid);

		ASSERT(mdomain);
		*mdomain = IDN_ADDR2OFFSET(mtp);

		if (ldp->dvote.v.master) {
			/*
			 * Need to calculate mailbox table to
			 * assign to the given domain.  Since
			 * I'm the master his mailbox is in
			 * the (all-domains) mailbox table.
			 */
			mtp = IDN_MBOXAREA_BASE(idn.mboxarea, domid);
			ASSERT(mtable);
			*mtable = IDN_ADDR2OFFSET(mtp);

			dp->dmbox.m_tbl = mtp;
		}
	}

	return (0);
}

/*
 * RETURNS:
 *	1	Unexpected/unnecessary phase.
 *	0	Successfully handled, timer needed.
 */
static int
idn_send_master_config(int domid, int phase)
{
	idn_cfgsubtype_t	cfg_subtype;
	int		rv = 0;
	idn_domain_t	*dp, *ldp;
	idn_msgtype_t	mt;
	int		nmcadr;
	uint_t		barpfn, larpfn;
	uint_t		cpus_u32, cpus_l32;
	uint_t		mcadr[3];
	smr_offset_t	mbox_table, mbox_domain;
	register int	b, p, m;
	procname_t	proc = "idn_send_master_config";

	ASSERT(IDN_DLOCK_IS_EXCL(domid));
	ASSERT(IDN_DLOCK_IS_SHARED(idn.localid));

	dp = &idn_domain[domid];
	ldp = &idn_domain[idn.localid];

	ASSERT(dp->dstate == IDNDS_CONFIG);
	ASSERT(dp->dvote.v.master == 0);
	ASSERT(ldp->dvote.v.master == 1);

	mt.mt_mtype = IDNP_CFG;
	mt.mt_atype = 0;
	mt.mt_cookie = 0;
	m = 0;
	mcadr[0] = mcadr[1] = mcadr[2] = 0;
	cfg_subtype.val = 0;

	switch (phase) {

	case 1:
		mbox_table = mbox_domain = IDN_NIL_SMROFFSET;
		(void) idn_get_mbox_config(domid, NULL, &mbox_table,
		    &mbox_domain);
		/*
		 * ----------------------------------------------------
		 * Send: SLABSIZE, DATAMBOX.DOMAIN, DATAMBOX.TABLE
		 * ----------------------------------------------------
		 */
		cfg_subtype.param.p[0] = IDN_CFGPARAM(IDNCFG_SIZE,
		    IDNCFGARG_SIZE_SLAB);
		cfg_subtype.param.p[1] = IDN_CFGPARAM(IDNCFG_DATAMBOX,
		    IDNCFGARG_DATAMBOX_DOMAIN);
		cfg_subtype.param.p[2] = IDN_CFGPARAM(IDNCFG_DATAMBOX,
		    IDNCFGARG_DATAMBOX_TABLE);
		cfg_subtype.info.num = 3;
		cfg_subtype.info.phase = phase;
		dp->dcfgphase = phase;

		ASSERT(mbox_domain != IDN_NIL_SMROFFSET);
		ASSERT(mbox_table != IDN_NIL_SMROFFSET);

		PR_PROTO("%s:%d:%d: sending SLABSIZE (%d), "
		    "DATAMBOX.DOMAIN (0x%x), DATAMBOX.TABLE (0x%x)\n",
		    proc, domid, phase, IDN_SLAB_BUFCOUNT, mbox_domain,
		    mbox_table);

		IDNXDC(domid, &mt, cfg_subtype.val, IDN_SLAB_BUFCOUNT,
		    mbox_domain, mbox_table);
		break;

	case 2:
		barpfn = idn.smr.locpfn;
		larpfn = barpfn + (uint_t)btop(MB2B(IDN_SMR_SIZE));
		/*
		 * ----------------------------------------------------
		 * Send: NETID, BARLAR
		 * ----------------------------------------------------
		 */
		cfg_subtype.param.p[0] = IDN_CFGPARAM(IDNCFG_NETID, 0);
		cfg_subtype.param.p[1] = IDN_CFGPARAM(IDNCFG_BARLAR,
		    IDNCFGARG_BARLAR_BAR);
		cfg_subtype.param.p[2] = IDN_CFGPARAM(IDNCFG_BARLAR,
		    IDNCFGARG_BARLAR_LAR);
		cfg_subtype.info.num = 3;
		cfg_subtype.info.phase = phase;
		dp->dcfgphase = phase;

		PR_PROTO("%s:%d:%d: sending NETID (%d), "
		    "BARPFN/LARPFN (0x%x/0x%x)\n",
		    proc, domid, phase, ldp->dnetid, barpfn, larpfn);

		IDNXDC(domid, &mt, cfg_subtype.val,
		    (uint_t)ldp->dnetid, barpfn, larpfn);
		break;

	case 3:
		nmcadr = ldp->dhw.dh_nmcadr;
		cpus_u32 = UPPER32_CPUMASK(ldp->dcpuset);
		cpus_l32 = LOWER32_CPUMASK(ldp->dcpuset);
		/*
		 * ----------------------------------------------------
		 * Send: CPUSET, NMCADR
		 * ----------------------------------------------------
		 */
		cfg_subtype.param.p[0] = IDN_CFGPARAM(IDNCFG_CPUSET,
		    IDNCFGARG_CPUSET_UPPER);
		cfg_subtype.param.p[1] = IDN_CFGPARAM(IDNCFG_CPUSET,
		    IDNCFGARG_CPUSET_LOWER);
		cfg_subtype.param.p[2] = IDN_CFGPARAM(IDNCFG_NMCADR, 0);
		cfg_subtype.info.num = 3;
		cfg_subtype.info.phase = phase;
		dp->dcfgphase = phase;

		PR_PROTO("%s:%d:%d: sending CPUSET (0x%x.%x), NMCADR (%d)\n",
		    proc, domid, phase, cpus_u32, cpus_l32, nmcadr);

		IDNXDC(domid, &mt, cfg_subtype.val,
		    cpus_u32, cpus_l32, nmcadr);
		break;

	case 4:
		/*
		 * ----------------------------------------------------
		 * Send: BOARDSET, MTU, BUFSIZE
		 * ----------------------------------------------------
		 */
		cfg_subtype.param.p[0] = IDN_CFGPARAM(IDNCFG_BOARDSET, 0);
		cfg_subtype.param.p[1] = IDN_CFGPARAM(IDNCFG_SIZE,
		    IDNCFGARG_SIZE_MTU);
		cfg_subtype.param.p[2] = IDN_CFGPARAM(IDNCFG_SIZE,
		    IDNCFGARG_SIZE_BUF);
		cfg_subtype.info.num = 3;
		cfg_subtype.info.phase = phase;
		dp->dcfgphase = phase;

		PR_PROTO("%s:%d:%d: sending BOARDSET (0x%x), MTU (0x%lx), "
		    "BUFSIZE (0x%x)\n", proc, domid, phase,
		    ldp->dhw.dh_boardset, IDN_MTU, IDN_SMR_BUFSIZE);

		IDNXDC(domid, &mt, cfg_subtype.val,
		    ldp->dhw.dh_boardset, IDN_MTU, IDN_SMR_BUFSIZE);
		break;

	case 5:
		/*
		 * ----------------------------------------------------
		 * Send: MAXNETS, MBOXPERNET, CKSUM
		 * ----------------------------------------------------
		 */
		cfg_subtype.param.p[0] = IDN_CFGPARAM(IDNCFG_DATASVR,
		    IDNCFGARG_DATASVR_MAXNETS);
		cfg_subtype.param.p[1] = IDN_CFGPARAM(IDNCFG_DATASVR,
		    IDNCFGARG_DATASVR_MBXPERNET);
		cfg_subtype.param.p[2] = IDN_CFGPARAM(IDNCFG_OPTIONS,
		    IDNCFGARG_CHECKSUM);
		cfg_subtype.info.num = 3;
		cfg_subtype.info.phase = phase;
		dp->dcfgphase = phase;

		PR_PROTO("%s:%d:%d: sending MAXNETS (%d), "
		    "MBOXPERNET (%d), CKSUM (%d)\n",
		    proc, domid, phase,
		    IDN_MAX_NETS, IDN_MBOX_PER_NET,
		    IDN_CHECKSUM);

		IDNXDC(domid, &mt, cfg_subtype.val,
		    IDN_MAX_NETS, IDN_MBOX_PER_NET, IDN_CHECKSUM);
		break;

	case 6:
		/*
		 * ----------------------------------------------------
		 * Send: NWRSIZE (piggyback on MCADRs)
		 * ----------------------------------------------------
		 */
		cfg_subtype.param.p[0] = IDN_CFGPARAM(IDNCFG_SIZE,
		    IDNCFGARG_SIZE_NWR);
		mcadr[0] = IDN_NWR_SIZE;
		m = 1;

		/*FALLTHROUGH*/

	default:	/* case 7 and above */
		/*
		 * ----------------------------------------------------
		 * Send: MCADR's
		 * ----------------------------------------------------
		 * First need to figure how many we've already sent
		 * based on what phase of CONFIG we're in.
		 * ----------------------------------------------------
		 */
		if (phase > 6) {
			p = ((phase - 7) * 3) + 2;
			for (b = 0; (b < MAX_BOARDS) && (p > 0); b++)
				if (ldp->dhw.dh_mcadr[b])
					p--;
		} else {
			b = 0;
		}

		for (; (b < MAX_BOARDS) && (m < 3); b++) {
			if (ldp->dhw.dh_mcadr[b] == 0)
				continue;
			mcadr[m] = ldp->dhw.dh_mcadr[b];
			cfg_subtype.param.p[m] = IDN_CFGPARAM(IDNCFG_MCADR, b);
			m++;
		}
		if (m > 0) {
			if (phase == 6) {
				PR_PROTO("%s:%d:%d: sending NWRSIZE (%d), "
				    "MCADRs (0x%x, 0x%x)\n",
				    proc, domid, phase,
				    mcadr[0], mcadr[1], mcadr[2]);
			} else {
				PR_PROTO("%s:%d:%d: sending MCADRs "
				    "(0x%x, 0x%x, 0x%x)\n",
				    proc, domid, phase,
				    mcadr[0], mcadr[1], mcadr[2]);
			}
			cfg_subtype.info.num = m;
			cfg_subtype.info.phase = phase;
			dp->dcfgphase = phase;

			IDNXDC(domid, &mt, cfg_subtype.val,
			    mcadr[0], mcadr[1], mcadr[2]);
		} else {
			rv = 1;
		}
		break;
	}

	return (rv);
}

/*
 * RETURNS:
 *	1	Unexpected/unnecessary phase.
 *	0	Successfully handled.
 */
static int
idn_send_slave_config(int domid, int phase)
{
	idn_cfgsubtype_t	cfg_subtype;
	int		rv = 0;
	idn_domain_t	*dp, *ldp;
	smr_offset_t	mbox_domain;
	idn_msgtype_t	mt;
	int		mbox_index;
	uint_t		cpus_u32, cpus_l32;
	procname_t	proc = "idn_send_slave_config";

	ASSERT(IDN_DLOCK_IS_EXCL(domid));
	ASSERT(IDN_DLOCK_IS_SHARED(idn.localid));

	mt.mt_mtype = IDNP_CFG;
	mt.mt_atype = 0;
	dp = &idn_domain[domid];
	ldp = &idn_domain[idn.localid];

	ASSERT(dp->dstate == IDNDS_CONFIG);
	ASSERT(ldp->dvote.v.master == 0);

	switch (phase) {

	case 1:
		mbox_index = IDN_NIL_DOMID;
		mbox_domain = IDN_NIL_SMROFFSET;
		(void) idn_get_mbox_config(domid, &mbox_index, NULL,
		    &mbox_domain);
		/*
		 * ----------------------------------------------------
		 * Send: DATAMBOX.DOMAIN or DATAMBOX.INDEX,
		 *	 DATASVR.MAXNETS, DATASVR.MBXPERNET
		 * ----------------------------------------------------
		 */
		cfg_subtype.val = 0;
		if (mbox_index == IDN_NIL_DOMID) {
			ASSERT(mbox_domain != IDN_NIL_SMROFFSET);
			cfg_subtype.param.p[0] = IDN_CFGPARAM(IDNCFG_DATAMBOX,
			    IDNCFGARG_DATAMBOX_DOMAIN);
		} else {
			/*
			 * Should only be sending Index to
			 * the master and not another slave.
			 */
			ASSERT(dp->dvote.v.master);
			ASSERT(mbox_domain == IDN_NIL_SMROFFSET);
			cfg_subtype.param.p[0] = IDN_CFGPARAM(IDNCFG_DATAMBOX,
			    IDNCFGARG_DATAMBOX_INDEX);
		}
		cfg_subtype.param.p[1] = IDN_CFGPARAM(IDNCFG_DATASVR,
		    IDNCFGARG_DATASVR_MAXNETS);
		cfg_subtype.param.p[2] = IDN_CFGPARAM(IDNCFG_DATASVR,
		    IDNCFGARG_DATASVR_MBXPERNET);
		cfg_subtype.info.num = 3;
		cfg_subtype.info.phase = phase;
		dp->dcfgphase = phase;

		PR_PROTO("%s:%d:%d: sending DATAMBOX.%s (0x%x), "
		    "MAXNETS (%d), MBXPERNET (%d)\n",
		    proc, domid, phase,
		    (IDN_CFGPARAM_ARG(cfg_subtype.param.p[0])
		    == IDNCFGARG_DATAMBOX_INDEX) ? "INDEX" : "DOMAIN",
		    (mbox_index == IDN_NIL_DOMID) ? mbox_domain : mbox_index,
		    IDN_MAX_NETS, IDN_MBOX_PER_NET);

		IDNXDC(domid, &mt, cfg_subtype.val,
		    ((mbox_index == IDN_NIL_DOMID) ? mbox_domain : mbox_index),
		    IDN_MAX_NETS, IDN_MBOX_PER_NET);
		break;

	case 2:
		cpus_u32 = UPPER32_CPUMASK(ldp->dcpuset);
		cpus_l32 = LOWER32_CPUMASK(ldp->dcpuset);
		/*
		 * ----------------------------------------------------
		 * Send: NETID, CPUSET
		 * ----------------------------------------------------
		 */
		cfg_subtype.val = 0;
		cfg_subtype.param.p[0] = IDN_CFGPARAM(IDNCFG_NETID, 0);
		cfg_subtype.param.p[1] = IDN_CFGPARAM(IDNCFG_CPUSET,
		    IDNCFGARG_CPUSET_UPPER);
		cfg_subtype.param.p[2] = IDN_CFGPARAM(IDNCFG_CPUSET,
		    IDNCFGARG_CPUSET_LOWER);
		cfg_subtype.info.num = 3;
		cfg_subtype.info.phase = phase;
		dp->dcfgphase = phase;

		PR_PROTO("%s:%d:%d: sending NETID (%d), "
		    "CPUSET (0x%x.%x)\n", proc, domid, phase,
		    ldp->dnetid, cpus_u32, cpus_l32);

		IDNXDC(domid, &mt, cfg_subtype.val,
		    (uint_t)ldp->dnetid, cpus_u32, cpus_l32);
		break;

	case 3:
		/*
		 * ----------------------------------------------------
		 * Send: BOARDSET, MTU, BUFSIZE
		 * ----------------------------------------------------
		 */
		cfg_subtype.val = 0;
		cfg_subtype.param.p[0] = IDN_CFGPARAM(IDNCFG_BOARDSET, 0);
		cfg_subtype.param.p[1] = IDN_CFGPARAM(IDNCFG_SIZE,
		    IDNCFGARG_SIZE_MTU);
		cfg_subtype.param.p[2] = IDN_CFGPARAM(IDNCFG_SIZE,
		    IDNCFGARG_SIZE_BUF);
		cfg_subtype.info.num = 3;
		cfg_subtype.info.phase = phase;
		dp->dcfgphase = phase;

		PR_PROTO("%s:%d:%d: sending BOARDSET (0x%x), MTU (0x%lx), "
		    "BUFSIZE (0x%x)\n",
		    proc, domid, phase, ldp->dhw.dh_boardset, IDN_MTU,
		    IDN_SMR_BUFSIZE);

		IDNXDC(domid, &mt, cfg_subtype.val,
		    ldp->dhw.dh_boardset, IDN_MTU, IDN_SMR_BUFSIZE);
		break;

	case 4:
		/*
		 * ----------------------------------------------------
		 * Send: SLABSIZE, OPTIONS.CHECKSUM, NWR_SIZE
		 * ----------------------------------------------------
		 */
		cfg_subtype.val = 0;
		cfg_subtype.param.p[0] = IDN_CFGPARAM(IDNCFG_SIZE,
		    IDNCFGARG_SIZE_SLAB);
		cfg_subtype.param.p[1] = IDN_CFGPARAM(IDNCFG_OPTIONS,
		    IDNCFGARG_CHECKSUM);
		cfg_subtype.param.p[2] = IDN_CFGPARAM(IDNCFG_SIZE,
		    IDNCFGARG_SIZE_NWR);
		cfg_subtype.info.num = 3;
		cfg_subtype.info.phase = phase;
		dp->dcfgphase = phase;

		PR_PROTO("%s:%d:%d: sending SLABSIZE (%d), CKSUM (%d), "
		    "NWRSIZE (%d)\n",
		    proc, domid, phase, IDN_SLAB_BUFCOUNT,
		    IDN_CHECKSUM, IDN_NWR_SIZE);

		IDNXDC(domid, &mt, cfg_subtype.val,
		    IDN_SLAB_BUFCOUNT, IDN_CHECKSUM, IDN_NWR_SIZE);
		break;

	default:
		rv = 1;
		break;
	}

	return (rv);
}

#define	CFG_FATAL	((uint_t)-1)	/* reset link */
#define	CFG_CONTINUE	0x0000		/* looking for more */
#define	CFG_DONE	0x0001		/* got everything expected */
#define	CFG_ERR_MTU	0x0002
#define	CFG_ERR_BUF	0x0004
#define	CFG_ERR_SLAB	0x0008
#define	CFG_ERR_NWR	0x0010
#define	CFG_ERR_NETS	0x0020
#define	CFG_ERR_MBOX	0x0040
#define	CFG_ERR_NMCADR	0x0080
#define	CFG_ERR_MCADR	0x0100
#define	CFG_ERR_CKSUM	0x0200
#define	CFG_ERR_SMR	0x0400
#define	CFG_MAX_ERRORS	16

#define	CFGERR2IDNKERR(ce) \
	(((ce) & CFG_ERR_MTU)	? IDNKERR_CONFIG_MTU 	: \
	((ce) & CFG_ERR_BUF)	? IDNKERR_CONFIG_BUF 	: \
	((ce) & CFG_ERR_SLAB)	? IDNKERR_CONFIG_SLAB 	: \
	((ce) & CFG_ERR_NWR)	? IDNKERR_CONFIG_NWR 	: \
	((ce) & CFG_ERR_NETS)	? IDNKERR_CONFIG_NETS 	: \
	((ce) & CFG_ERR_MBOX)	? IDNKERR_CONFIG_MBOX 	: \
	((ce) & CFG_ERR_NMCADR)	? IDNKERR_CONFIG_NMCADR	: \
	((ce) & CFG_ERR_MCADR)	? IDNKERR_CONFIG_MCADR	: \
	((ce) & CFG_ERR_CKSUM)	? IDNKERR_CONFIG_CKSUM	: \
	((ce) & CFG_ERR_SMR)	? IDNKERR_CONFIG_SMR	: 0)

#define	CFGERR2FINARG(ce) \
	(((ce) & CFG_ERR_MTU)	? IDNFIN_ARG_CFGERR_MTU    : \
	((ce) & CFG_ERR_BUF)	? IDNFIN_ARG_CFGERR_BUF    : \
	((ce) & CFG_ERR_SLAB)	? IDNFIN_ARG_CFGERR_SLAB   : \
	((ce) & CFG_ERR_NWR)	? IDNFIN_ARG_CFGERR_NWR    : \
	((ce) & CFG_ERR_NETS)	? IDNFIN_ARG_CFGERR_NETS   : \
	((ce) & CFG_ERR_MBOX)	? IDNFIN_ARG_CFGERR_MBOX   : \
	((ce) & CFG_ERR_NMCADR)	? IDNFIN_ARG_CFGERR_NMCADR : \
	((ce) & CFG_ERR_MCADR)	? IDNFIN_ARG_CFGERR_MCADR  : \
	((ce) & CFG_ERR_CKSUM)	? IDNFIN_ARG_CFGERR_CKSUM  : \
	((ce) & CFG_ERR_SMR)	? IDNFIN_ARG_CFGERR_SMR	   : IDNFIN_ARG_NONE)

/*
 * Called when some CFG messages arrive.  We use dncfgitems to count the
 * total number of items received so far since we'll receive multiple CFG
 * messages during the CONFIG phase.  Note that dncfgitems is initialized
 * in idn_send_config.
 */
static void
idn_recv_config(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t		msg = mtp->mt_mtype;
	uint_t		rv, rv_expected, rv_actual;
	int		pnum;
	int		phase;
	register int	p;
	register int	c;
	idn_mainmbox_t	*mmp;
	register uint_t	subtype, subtype_arg;
	idn_domain_t	*dp;
	int		index;
	idn_domain_t	*ldp = &idn_domain[idn.localid];
	idn_mboxtbl_t	*mbtp;
	idn_cfgsubtype_t	cfg_subtype;
	idn_xdcargs_t	cfg_arg;
	idn_msgtype_t	mt;
	idnsb_error_t	idnerr;
	procname_t	proc = "idn_recv_config";

	ASSERT(domid != idn.localid);

	GET_XARGS(xargs, &cfg_subtype.val, &cfg_arg[0], &cfg_arg[1],
	    &cfg_arg[2]);
	cfg_arg[3] = 0;

	dp = &idn_domain[domid];

	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (dp->dstate != IDNDS_CONFIG) {
		/*
		 * Not ready to receive config info.
		 * Drop whatever he sent us.  Let the
		 * timer continue and timeout if needed.
		 */
		PR_PROTO("%s:%d: WARNING state(%s) != CONFIG\n",
		    proc, domid, idnds_str[dp->dstate]);
		return;
	}

	if ((msg & IDNP_ACKNACK_MASK) || dp->dcfgsnddone) {
		IDN_MSGTIMER_STOP(domid, IDNP_CFG, 0);
	}

	if (msg & IDNP_ACKNACK_MASK) {
		/*
		 * ack/cfg
		 */
		phase = GET_XARGS_CFG_PHASE(xargs);

		PR_PROTO("%s:%d: received ACK for CFG phase %d\n",
		    proc, domid, phase);
		if (phase != (int)dp->dcfgphase) {
			/*
			 * Phase is not what we were
			 * expecting.  Something got lost
			 * in the shuffle.  Restart the
			 * timer and let it timeout if necessary
			 * and reestablish the connection.
			 */
			IDN_MSGTIMER_START(domid, IDNP_CFG, dp->dcfgphase,
			    idn_msg_waittime[IDNP_CFG], NULL);
		} else {
			idn_send_config(domid, phase + 1);

			if (dp->dcfgsnddone && dp->dcfgrcvdone) {
				IDN_DUNLOCK(domid);
				IDN_SYNC_LOCK();
				IDN_DLOCK_EXCL(domid);
				if (dp->dstate == IDNDS_CONFIG) {
					dp->dxp = &xphase_con;
					IDN_XSTATE_TRANSITION(dp, IDNXS_PEND);
					bzero(xargs, sizeof (xargs));

					(void) idn_xphase_transition(domid,
					    NULL, xargs);
				}
				IDN_SYNC_UNLOCK();
			}
		}
		return;
	}

	pnum = (int)cfg_subtype.info.num;
	phase = (int)cfg_subtype.info.phase;

	for (p = 0; p < pnum; p++) {
		int	board;
#ifdef DEBUG
		uint_t	val;
		char	*str;

		val = 0;
		str = NULL;
#define	RCVCFG(s, v)	{ str = (s); val = (v); }
#else
#define	RCVCFG(s, v)	{}
#endif /* DEBUG */

		subtype	    = IDN_CFGPARAM_TYPE(cfg_subtype.param.p[p]);
		subtype_arg = IDN_CFGPARAM_ARG(cfg_subtype.param.p[p]);

		switch (subtype) {

		case IDNCFG_BARLAR:
			IDN_GLOCK_EXCL();
			switch (subtype_arg) {

			case IDNCFGARG_BARLAR_BAR:
				if (idn.smr.rempfn == PFN_INVALID) {
					idn.smr.rempfn = (pfn_t)cfg_arg[p];
					dp->dncfgitems++;
					RCVCFG("BARLAR_BAR", cfg_arg[p]);
				}
				break;

			case IDNCFGARG_BARLAR_LAR:
				if (idn.smr.rempfnlim == PFN_INVALID) {
					idn.smr.rempfnlim = (pfn_t)cfg_arg[p];
					dp->dncfgitems++;
					RCVCFG("BARLAR_LAR", cfg_arg[p]);
				}
				break;

			default:
				cmn_err(CE_WARN,
				    "IDN 217: unknown CFGARG type (%d) "
				    "from domain %d",
				    subtype_arg, domid);
				break;
			}
			IDN_GUNLOCK();
			break;

		case IDNCFG_MCADR:
			board = subtype_arg;
			if ((board >= 0) && (board < MAX_BOARDS) &&
			    (dp->dhw.dh_mcadr[board] == 0)) {
				dp->dhw.dh_mcadr[board] = cfg_arg[p];
				dp->dncfgitems++;
				RCVCFG("MCADR", cfg_arg[p]);
			}
			break;

		case IDNCFG_NMCADR:
			if (dp->dhw.dh_nmcadr == 0) {
				dp->dhw.dh_nmcadr = cfg_arg[p];
				dp->dncfgitems++;
				RCVCFG("NMCADR", cfg_arg[p]);
			}
			break;

		case IDNCFG_CPUSET:
			switch (subtype_arg) {

			case IDNCFGARG_CPUSET_UPPER:
			{
				cpuset_t	tmpset;

				MAKE64_CPUMASK(tmpset, cfg_arg[p], 0);
				CPUSET_OR(dp->dcpuset, tmpset);
				dp->dncfgitems++;
				RCVCFG("CPUSET_UPPER", cfg_arg[p]);
				break;
			}
			case IDNCFGARG_CPUSET_LOWER:
			{
				cpuset_t	tmpset;

				MAKE64_CPUMASK(tmpset, 0, cfg_arg[p]);
				CPUSET_OR(dp->dcpuset, tmpset);
				dp->dncfgitems++;
				RCVCFG("CPUSET_LOWER", cfg_arg[p]);
				break;
			}
			default:
				ASSERT(0);
				break;
			}
			break;

		case IDNCFG_NETID:
			if (dp->dnetid == (ushort_t)-1) {
				dp->dnetid = (ushort_t)cfg_arg[p];
				dp->dncfgitems++;
				RCVCFG("NETID", cfg_arg[p]);
			}
			break;

		case IDNCFG_BOARDSET:
			if ((dp->dhw.dh_boardset & cfg_arg[p])
			    == dp->dhw.dh_boardset) {
				/*
				 * Boardset better include what we
				 * already know about.
				 */
				dp->dhw.dh_boardset = cfg_arg[p];
				dp->dncfgitems++;
				RCVCFG("BOARDSET", cfg_arg[p]);
			}
			break;

		case IDNCFG_SIZE:
			switch (subtype_arg) {

			case IDNCFGARG_SIZE_MTU:
				if (dp->dmtu == 0) {
					dp->dmtu = cfg_arg[p];
					dp->dncfgitems++;
					RCVCFG("MTU", cfg_arg[p]);
				}
				break;

			case IDNCFGARG_SIZE_BUF:
				if (dp->dbufsize == 0) {
					dp->dbufsize = cfg_arg[p];
					dp->dncfgitems++;
					RCVCFG("BUFSIZE", cfg_arg[p]);
				}
				break;

			case IDNCFGARG_SIZE_SLAB:
				if (dp->dslabsize == 0) {
					dp->dslabsize = (short)cfg_arg[p];
					dp->dncfgitems++;
					RCVCFG("SLABSIZE", cfg_arg[p]);
				}
				break;

			case IDNCFGARG_SIZE_NWR:
				if (dp->dnwrsize == 0) {
					dp->dnwrsize = (short)cfg_arg[p];
					dp->dncfgitems++;
					RCVCFG("NWRSIZE", cfg_arg[p]);
				}
				break;

			default:
				ASSERT(0);
				break;
			}
			break;

		case IDNCFG_DATAMBOX:
			switch (subtype_arg) {

			case IDNCFGARG_DATAMBOX_TABLE:
				if (ldp->dmbox.m_tbl ||
				    !dp->dvote.v.master ||
				    !VALID_NWROFFSET(cfg_arg[p], 4)) {
					/*
					 * Only a master should be
					 * sending us a datambox table.
					 */
					break;
				}
				IDN_DLOCK_EXCL(idn.localid);
				ldp->dmbox.m_tbl = (idn_mboxtbl_t *)
				    IDN_OFFSET2ADDR(cfg_arg[p]);
				IDN_DUNLOCK(idn.localid);
				dp->dncfgitems++;
				RCVCFG("DATAMBOX.TABLE", cfg_arg[p]);
				break;

			case IDNCFGARG_DATAMBOX_DOMAIN:
				if (dp->dmbox.m_send->mm_smr_mboxp ||
				    !VALID_NWROFFSET(cfg_arg[p], 4))
					break;
				mbtp = (idn_mboxtbl_t *)
				    IDN_OFFSET2ADDR(cfg_arg[p]);
				mmp = dp->dmbox.m_send;
				for (c = 0; c < IDN_MAX_NETS; c++) {

					mutex_enter(&mmp[c].mm_mutex);
					mmp[c].mm_smr_mboxp = mbtp;
					mutex_exit(&mmp[c].mm_mutex);

					IDN_MBOXTBL_PTR_INC(mbtp);
				}
				if (c <= 0)
					break;
				dp->dncfgitems++;
				RCVCFG("DATAMBOX.DOMAIN", cfg_arg[p]);
				break;

			case IDNCFGARG_DATAMBOX_INDEX:
				if (!ldp->dvote.v.master ||
				    dp->dmbox.m_send->mm_smr_mboxp) {
					/*
					 * If I'm not the master then
					 * I can't handle processing a
					 * mailbox index.
					 * OR, if I already have the send
					 * mailbox, I'm done with this
					 * config item.
					 */
					break;
				}
				ASSERT(dp->dmbox.m_tbl);
				index = (int)cfg_arg[p];
				/*
				 * The given index is the local domain's
				 * index into the remote domain's mailbox
				 * table that contains the mailbox that
				 * remote domain wants the local domain to
				 * use as the send mailbox for messages
				 * destined for the remote domain.
				 * I.e. from the remote domain's
				 *	perspective, this is his receive
				 *	mailbox.
				 */
				mbtp = IDN_MBOXTBL_PTR(dp->dmbox.m_tbl, index);
				mmp = dp->dmbox.m_send;
				for (c = 0; c < IDN_MAX_NETS; c++) {

					mutex_enter(&mmp[c].mm_mutex);
					mmp[c].mm_smr_mboxp = mbtp;
					mutex_exit(&mmp[c].mm_mutex);

					IDN_MBOXTBL_PTR_INC(mbtp);
				}
				if (c <= 0)
					break;
				dp->dncfgitems++;
				RCVCFG("DATAMBOX.INDEX", cfg_arg[p]);
				break;

			default:
				ASSERT(0);
				break;
			}
			break;

		case IDNCFG_DATASVR:
			switch (subtype_arg) {

			case IDNCFGARG_DATASVR_MAXNETS:
				if (dp->dmaxnets)
					break;
				dp->dmaxnets = (uint_t)(cfg_arg[p] & 0x3f);
				dp->dncfgitems++;
				RCVCFG("DATASVR.MAXNETS", cfg_arg[p]);
				break;

			case IDNCFGARG_DATASVR_MBXPERNET:
				if (dp->dmboxpernet)
					break;
				dp->dmboxpernet = (uint_t)(cfg_arg[p] & 0x1ff);
				dp->dncfgitems++;
				RCVCFG("DATASVR.MBXPERNET", cfg_arg[p]);
				break;

			default:
				ASSERT(0);
				break;
			}
			break;

		case IDNCFG_OPTIONS:
			switch (subtype_arg) {

			case IDNCFGARG_CHECKSUM:
				if (dp->dcksum)
					break;
				if ((cfg_arg[p] & 0xff) == 0)
					dp->dcksum = 1;		/* off */
				else
					dp->dcksum = 2;		/* on */
				dp->dncfgitems++;
				RCVCFG("OPTIONS.CHECKSUM", cfg_arg[p]);
				break;

			default:
				ASSERT(0);
				break;
			}

		default:
			break;
		}
#ifdef DEBUG
		PR_PROTO("%s:%d: received %s (0x%x)\n",
		    proc, domid, str ? str : "<empty>", val);
#endif /* DEBUG */
	}

	mt.mt_mtype = IDNP_ACK;
	mt.mt_atype = IDNP_CFG;
	mt.mt_cookie = mtp->mt_cookie;
	CLR_XARGS(cfg_arg);
	SET_XARGS_CFG_PHASE(cfg_arg, phase);
	idn_send_acknack(domid, &mt, cfg_arg);

	rv_expected = rv_actual = 0;

	if (dp->dvote.v.master == 0) {
		/*
		 * Remote domain is a slave, check if we've received
		 * all that we were expecting, and if so transition to
		 * the next state.
		 */
		rv = idn_check_slave_config(domid, &rv_expected, &rv_actual);
	} else {
		/*
		 * Remote domain is a master, check if this slave has
		 * received all that it was expecting, and if so
		 * transition to the next state.
		 */
		rv = idn_check_master_config(domid, &rv_expected, &rv_actual);
	}

	switch (rv) {
	case CFG_DONE:
		/*
		 * All config info received that was expected, wrap up.
		 */
		if (!idn_recv_config_done(domid) && dp->dvote.v.master) {
			IDN_DLOCK_EXCL(idn.localid);
			ldp->dvote.v.connected = 1;
			IDN_DUNLOCK(idn.localid);
		}
		break;

	case CFG_CONTINUE:
		/*
		 * If we're not done sending our own config, then
		 * there's no need to set a timer since one will
		 * automatically be set when we send a config
		 * message waiting for an acknowledgement.
		 */
		if (dp->dcfgsnddone) {
			/*
			 * We haven't yet received all the config
			 * information we were expecting.  Need to
			 * restart CFG timer if we've sent everything..
			 */
			IDN_MSGTIMER_START(domid, IDNP_CFG, 0,
			    idn_msg_waittime[IDNP_CFG], NULL);
		}
		break;

	case CFG_FATAL:
		/*
		 * Fatal error occurred during config exchange.
		 * We need to shutdown connection in this
		 * case, so initiate a (non-relink) FIN.
		 * so let's get the show on the road.
		 */
		IDN_DUNLOCK(domid);
		IDN_SYNC_LOCK();
		IDN_DLOCK_EXCL(domid);
		/*
		 * If the state has changed from CONFIG
		 * then somebody else has taken over
		 * control of this domain so we can just
		 * bail out.
		 */
		if (dp->dstate == IDNDS_CONFIG) {
			INIT_IDNKERR(&idnerr);
			SET_IDNKERR_ERRNO(&idnerr, EPROTO);
			SET_IDNKERR_IDNERR(&idnerr, IDNKERR_CONFIG_FATAL);
			SET_IDNKERR_PARAM0(&idnerr, domid);
			idn_update_op(IDNOP_ERROR, DOMAINSET(domid), &idnerr);
			/*
			 * Keep this guy around so we can try again.
			 */
			DOMAINSET_ADD(idn.domset.ds_relink, domid);
			IDN_HISTORY_LOG(IDNH_RELINK, domid, dp->dstate,
			    idn.domset.ds_relink);
			(void) idn_disconnect(domid, IDNFIN_NORMAL,
			    IDNFIN_ARG_CFGERR_FATAL,
			    IDNFIN_SYNC_NO);
		}
		IDN_SYNC_UNLOCK();
		break;

	default:	/* parameter conflict */
		IDN_DUNLOCK(domid);
		IDN_SYNC_LOCK();
		IDN_DLOCK_EXCL(domid);
		if (dp->dstate != IDNDS_CONFIG) {
			/*
			 * Hmmm...changed in the short period
			 * we had dropped the lock, oh well.
			 */
			IDN_SYNC_UNLOCK();
			break;
		}
		c = 0;
		for (p = 0; p < CFG_MAX_ERRORS; p++)
			if (rv & (1 << p))
				c++;
		INIT_IDNKERR(&idnerr);
		SET_IDNKERR_ERRNO(&idnerr, EINVAL);
		SET_IDNKERR_PARAM0(&idnerr, domid);
		if (c > 1) {
			SET_IDNKERR_IDNERR(&idnerr, IDNKERR_CONFIG_MULTIPLE);
			SET_IDNKERR_PARAM1(&idnerr, c);
		} else {
			SET_IDNKERR_IDNERR(&idnerr, CFGERR2IDNKERR(rv));
			SET_IDNKERR_PARAM1(&idnerr, rv_expected);
			SET_IDNKERR_PARAM2(&idnerr, rv_actual);
		}
		/*
		 * Any parameter conflicts are grounds for dismissal.
		 */
		if (idn.domset.ds_connected == 0) {
			domainset_t	domset;
			/*
			 * We have no other connections yet.
			 * We must blow out of here completely
			 * unless we have relinkers left from
			 * a RECONFIG.
			 */
			IDN_GLOCK_EXCL();
			domset = ~idn.domset.ds_relink;
			if (idn.domset.ds_relink == 0) {
				IDN_GSTATE_TRANSITION(IDNGS_DISCONNECT);
			}
			domset &= ~idn.domset.ds_hitlist;
			IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);
			IDN_GUNLOCK();
			IDN_DUNLOCK(domid);

			DOMAINSET_DEL(domset, idn.localid);

			idn_update_op(IDNOP_ERROR, DOMAINSET_ALL, &idnerr);

			PR_HITLIST("%s:%d: unlink_domainset(%x) due to "
			    "CFG error (relink=%x, hitlist=%x)\n",
			    proc, domid, domset, idn.domset.ds_relink,
			    idn.domset.ds_hitlist);

			idn_unlink_domainset(domset, IDNFIN_NORMAL,
			    CFGERR2FINARG(rv),
			    IDNFIN_OPT_UNLINK,
			    BOARDSET_ALL);
			IDN_SYNC_UNLOCK();
			IDN_DLOCK_EXCL(domid);
		} else {
			PR_HITLIST("%s:%d: idn_disconnect(%d) due to CFG "
			    "error (conn=%x, relink=%x, hitlist=%x)\n",
			    proc, domid, domid, idn.domset.ds_connected,
			    idn.domset.ds_relink, idn.domset.ds_hitlist);
			/*
			 * If we have other connections then
			 * we're only going to blow away this
			 * single connection.
			 */
			idn_update_op(IDNOP_ERROR, DOMAINSET(domid), &idnerr);

			DOMAINSET_DEL(idn.domset.ds_relink, domid);
			(void) idn_disconnect(domid, IDNFIN_NORMAL,
			    CFGERR2FINARG(rv), IDNFIN_SYNC_NO);
			IDN_SYNC_UNLOCK();
		}
		break;
	}
}

/*
 * Called by master or slave which expects exactly the following
 * with respect to config info received from a SLAVE:
 * 	IDNCFG_CPUSET
 *	IDNCFG_NETID
 *	IDNCFG_BOARDSET
 *	IDNCFG_SIZE (MTU, BUF, SLAB, NWR)
 *	IDNCFG_DATAMBOX (DOMAIN or INDEX if caller is master)
 *	IDNCFG_DATASVR (MAXNETS, MBXPERNET)
 *	IDNCFG_OPTIONS (CHECKSUM)
 */
static uint_t
idn_check_slave_config(int domid, uint_t *exp, uint_t *act)
{
	uint_t		rv = 0;
	idn_domain_t	*ldp, *dp;
	procname_t	proc = "idn_check_slave_config";

	dp = &idn_domain[domid];
	ldp = &idn_domain[idn.localid];

	ASSERT(domid != idn.localid);
	ASSERT(IDN_DLOCK_IS_EXCL(domid));
	ASSERT(dp->dstate == IDNDS_CONFIG);

	PR_PROTO("%s:%d: number received %d, number expected %d\n",
	    proc, domid, (int)dp->dncfgitems, IDN_SLAVE_NCFGITEMS);

	if ((int)dp->dncfgitems < IDN_SLAVE_NCFGITEMS)
		return (CFG_CONTINUE);

	if ((dp->dnetid == (ushort_t)-1) ||
	    CPUSET_ISNULL(dp->dcpuset) ||
	    (dp->dhw.dh_boardset == 0) ||
	    (dp->dmbox.m_send->mm_smr_mboxp == NULL) ||
	    (dp->dmaxnets == 0) ||
	    (dp->dmboxpernet == 0) ||
	    (dp->dcksum == 0) ||
	    (dp->dmtu == 0) ||
	    (dp->dbufsize == 0) ||
	    (dp->dslabsize == 0) ||
	    (dp->dnwrsize == 0)) {
		/*
		 * We received our IDN_SLAVE_NCFGITEMS config items,
		 * but not all what we were expecting!  Gotta nack and
		 * close connection.
		 */
		cmn_err(CE_WARN,
		    "IDN: 218: missing some required config items from "
		    "domain %d", domid);

		rv = CFG_FATAL;
		goto done;
	}

	if (!valid_mtu(dp->dmtu)) {
		cmn_err(CE_WARN,
		    "IDN: 219: remote domain %d MTU (%d) invalid "
		    "(local.mtu = %d)", dp->domid, dp->dmtu, ldp->dmtu);

		*exp = (uint_t)ldp->dmtu;
		*act = (uint_t)dp->dmtu;
		rv |= CFG_ERR_MTU;
	}
	if (!valid_bufsize(dp->dbufsize)) {
		cmn_err(CE_WARN,
		    "IDN: 220: remote domain %d BUFSIZE (%d) invalid "
		    "(local.bufsize = %d)", dp->domid, dp->dbufsize,
		    ldp->dbufsize);

		*exp = (uint_t)ldp->dbufsize;
		*act = (uint_t)dp->dbufsize;
		rv |= CFG_ERR_BUF;
	}
	if (!valid_slabsize((int)dp->dslabsize)) {
		cmn_err(CE_WARN,
		    "IDN: 221: remote domain %d SLABSIZE (%d) invalid "
		    "(local.slabsize = %d)",
		    dp->domid, dp->dslabsize, ldp->dslabsize);

		*exp = (uint_t)ldp->dslabsize;
		*act = (uint_t)dp->dslabsize;
		rv |= CFG_ERR_SLAB;
	}
	if (!valid_nwrsize((int)dp->dnwrsize)) {
		cmn_err(CE_WARN,
		    "IDN: 223: remote domain %d NWRSIZE (%d) invalid "
		    "(local.nwrsize = %d)",
		    dp->domid, dp->dnwrsize, ldp->dnwrsize);

		*exp = (uint_t)ldp->dnwrsize;
		*act = (uint_t)dp->dnwrsize;
		rv |= CFG_ERR_NWR;
	}
	if ((int)dp->dmaxnets != IDN_MAX_NETS) {
		cmn_err(CE_WARN,
		    "IDN: 224: remote domain %d MAX_NETS (%d) invalid "
		    "(local.maxnets = %d)",
		    dp->domid, (int)dp->dmaxnets, IDN_MAX_NETS);

		*exp = (uint_t)IDN_MAX_NETS;
		*act = (uint_t)dp->dmaxnets;
		rv |= CFG_ERR_NETS;
	}
	if ((int)dp->dmboxpernet != IDN_MBOX_PER_NET) {
		cmn_err(CE_WARN,
		    "IDN: 225: remote domain %d MBOX_PER_NET (%d) "
		    "invalid (local.mboxpernet = %d)",
		    dp->domid, (int)dp->dmboxpernet, IDN_MBOX_PER_NET);

		*exp = (uint_t)IDN_MBOX_PER_NET;
		*act = (uint_t)dp->dmboxpernet;
		rv |= CFG_ERR_MBOX;
	}
	if ((dp->dcksum - 1) != (uchar_t)IDN_CHECKSUM) {
		cmn_err(CE_WARN,
		    "IDN: 226: remote domain %d CHECKSUM flag (%d) "
		    "mismatches local domain's (%d)",
		    dp->domid, (int)dp->dcksum - 1, IDN_CHECKSUM);

		*exp = (uint_t)IDN_CHECKSUM;
		*act = (uint_t)(dp->dcksum - 1);
		rv |= CFG_ERR_CKSUM;
	}

done:

	return (rv ? rv : CFG_DONE);
}

/*
 * Called by slave ONLY which expects exactly the following
 * config info from the MASTER:
 *	IDNCFG_BARLAR
 *	IDNCFG_MCADR
 *	IDNCFG_NMCADR
 * 	IDNCFG_CPUSET
 *	IDNCFG_NETID
 *	IDNCFG_BOARDSET
 *	IDNCFG_SIZE (MTU, BUF, SLAB, NWR)
 *	IDNCFG_DATAMBOX (TABLE, DOMAIN)
 *	IDNCFG_DATASVR (MAXNETS, MBXPERNET)
 *	IDNCFG_OPTIONS (CHECKSUM)
 */
static uint_t
idn_check_master_config(int domid, uint_t *exp, uint_t *act)
{
	uint_t		rv = 0;
	int		nmcadr;
	int		total_expitems;
	int		p, m, err;
	idn_domain_t	*dp;
	idn_domain_t	*ldp = &idn_domain[idn.localid];
	procname_t	proc = "idn_check_master_config";

	dp = &idn_domain[domid];

	ASSERT(IDN_GET_MASTERID() != idn.localid);
	ASSERT(domid != idn.localid);
	ASSERT(IDN_DLOCK_IS_EXCL(domid));
	ASSERT(dp->dstate == IDNDS_CONFIG);

	PR_PROTO("%s:%d: number received %d, minimum number expected %d\n",
	    proc, domid, (int)dp->dncfgitems, IDN_MASTER_NCFGITEMS);

	if ((int)dp->dncfgitems < IDN_MASTER_NCFGITEMS)
		return (CFG_CONTINUE);

	/*
	 * We have at least IDN_MASTER_NCFGITEMS items which
	 * means we have at least one MCADR.  Need to make sure
	 * we have all that we're expecting, NMCADR.
	 */
	total_expitems = IDN_MASTER_NCFGITEMS + dp->dhw.dh_nmcadr - 1;
	if ((dp->dhw.dh_nmcadr == 0) ||
	    ((int)dp->dncfgitems < total_expitems)) {
		/*
		 * We have not yet received all the MCADRs
		 * we're expecting.
		 */
		PR_PROTO("%s:%d: haven't received all MCADRs yet.\n",
		    proc, domid);
		return (CFG_CONTINUE);
	}

	nmcadr = 0;
	for (p = 0; p < MAX_BOARDS; p++)
		if (dp->dhw.dh_mcadr[p] != 0)
			nmcadr++;

	IDN_GLOCK_SHARED();
	if ((idn.smr.rempfn == PFN_INVALID) ||
	    (idn.smr.rempfnlim == PFN_INVALID) ||
	    (dp->dnetid == (ushort_t)-1) ||
	    CPUSET_ISNULL(dp->dcpuset) ||
	    (dp->dhw.dh_boardset == 0) ||
	    (nmcadr != dp->dhw.dh_nmcadr) ||
	    (dp->dmbox.m_send->mm_smr_mboxp == NULL) ||
	    (ldp->dmbox.m_tbl == NULL) ||
	    (dp->dmaxnets == 0) ||
	    (dp->dmboxpernet == 0) ||
	    (dp->dcksum == 0) ||
	    (dp->dmtu == 0) ||
	    (dp->dbufsize == 0) ||
	    (dp->dnwrsize == 0)) {

		IDN_GUNLOCK();
		/*
		 * We received all of our config items, but not
		 * all what we were expecting!  Gotta reset and
		 * close connection.
		 */
		cmn_err(CE_WARN,
		    "IDN: 227: missing some required config items from "
		    "domain %d", domid);

		rv = CFG_FATAL;
		goto done;
	}
	if ((idn.smr.rempfnlim - idn.smr.rempfn) > btop(MB2B(IDN_SMR_SIZE))) {
		/*
		 * The master's SMR region is larger than
		 * mine!  This means that this domain may
		 * receive I/O buffers which are out of the
		 * range of this local domain's SMR virtual
		 * address space.  The master SMR has to be
		 * no larger than the local SMR in order to
		 * guarantee enough local virtual addresses
		 * to see all of the SMR space.
		 * XXX - Possibly add negotiating SMR size.
		 *	 Try to create a new virtual mapping.
		 *	 Could let domains negotiate SMR size.
		 *	 Winning size would have to be smallest
		 *	 in DC.  If so, how to handle incoming
		 *	 domains with even smaller SMRs?
		 *	 - Could either disallow connection
		 *	 - Could reconfigure to use smaller SMR.
		 */
		cmn_err(CE_WARN,
		    "IDN: 228: master's SMR (%ld) larger than "
		    "local's SMR (%ld)",
		    idn.smr.rempfnlim - idn.smr.rempfn,
		    btop(MB2B(IDN_SMR_SIZE)));

		*exp = (uint_t)IDN_SMR_SIZE;
		*act = (uint_t)B2MB(ptob(idn.smr.rempfnlim - idn.smr.rempfn));
		rv |= CFG_ERR_SMR;
	}
	IDN_GUNLOCK();

	if (!valid_mtu(dp->dmtu)) {
		cmn_err(CE_WARN,
		    "IDN: 219: remote domain %d MTU (%d) invalid "
		    "(local.mtu = %d)", dp->domid, dp->dmtu, ldp->dmtu);

		*exp = (uint_t)ldp->dmtu;
		*act = (uint_t)dp->dmtu;
		rv |= CFG_ERR_MTU;
	}
	if (!valid_bufsize(dp->dbufsize)) {
		cmn_err(CE_WARN,
		    "IDN: 220: remote domain %d BUFSIZE (%d) invalid "
		    "(local.bufsize = %d)", dp->domid, dp->dbufsize,
		    ldp->dbufsize);

		*exp = (uint_t)ldp->dbufsize;
		*act = (uint_t)dp->dbufsize;
		rv |= CFG_ERR_BUF;
	}
	if (!valid_nwrsize((int)dp->dnwrsize)) {
		cmn_err(CE_WARN,
		    "IDN: 223: remote domain %d NWRSIZE (%d) invalid "
		    "(local.nwrsize = %d)",
		    dp->domid, dp->dnwrsize, ldp->dnwrsize);

		*exp = (uint_t)ldp->dnwrsize;
		*act = (uint_t)dp->dnwrsize;
		rv |= CFG_ERR_NWR;
	}
	if ((int)dp->dmaxnets != IDN_MAX_NETS) {
		cmn_err(CE_WARN,
		    "IDN: 224: remote domain %d MAX_NETS (%d) invalid "
		    "(local.maxnets = %d)",
		    dp->domid, (int)dp->dmaxnets, IDN_MAX_NETS);

		*exp = (uint_t)IDN_MAX_NETS;
		*act = (uint_t)dp->dmaxnets;
		rv |= CFG_ERR_NETS;
	}
	if ((int)dp->dmboxpernet != IDN_MBOX_PER_NET) {
		cmn_err(CE_WARN,
		    "IDN: 225: remote domain %d MBOX_PER_NET (%d) "
		    "invalid (local.mboxpernet = %d)",
		    dp->domid, (int)dp->dmboxpernet, IDN_MBOX_PER_NET);

		*exp = (uint_t)IDN_MBOX_PER_NET;
		*act = (uint_t)dp->dmboxpernet;
		rv |= CFG_ERR_MBOX;
	}
	if ((dp->dcksum - 1) != (uchar_t)IDN_CHECKSUM) {
		cmn_err(CE_WARN,
		    "IDN: 226: remote domain %d CHECKSUM flag (%d) "
		    "mismatches local domain's (%d)",
		    dp->domid, (int)dp->dcksum - 1, IDN_CHECKSUM);

		*exp = (uint_t)IDN_CHECKSUM;
		*act = (uint_t)(dp->dcksum - 1);
		rv |= CFG_ERR_CKSUM;
	}
	nmcadr = 0;
	err = 0;
	for (m = 0; m < MAX_BOARDS; m++) {
		if (!BOARD_IN_SET(dp->dhw.dh_boardset, m) &&
		    dp->dhw.dh_mcadr[m]) {
			cmn_err(CE_WARN,
			    "IDN: 229: remote domain %d boardset (0x%x) "
			    "conflicts with MCADR(board %d) [0x%x]",
			    dp->domid, (uint_t)dp->dhw.dh_boardset, m,
			    dp->dhw.dh_mcadr[m]);
			err++;
		}
		if (dp->dhw.dh_mcadr[m])
			nmcadr++;
	}
	if (err) {
		*exp = 0;
		*act = err;
		rv |= CFG_ERR_MCADR;
	} else if (nmcadr != dp->dhw.dh_nmcadr) {
		cmn_err(CE_WARN,
		    "IDN: 230: remote domain %d reported number of "
		    "MCADRs (%d) mismatches received (%d)",
		    dp->domid, dp->dhw.dh_nmcadr, nmcadr);
		*exp = (uint_t)dp->dhw.dh_nmcadr;
		*act = (uint_t)nmcadr;
		rv |= CFG_ERR_NMCADR;
	}

done:

	return (rv ? rv : CFG_DONE);
}

static int
idn_recv_config_done(int domid)
{
	boardset_t		b_conflicts;
	cpuset_t		p_conflicts;
	register int		p, i;
	register idn_domain_t	*dp;
	idnsb_error_t		idnerr;
	procname_t		proc = "idn_recv_config_done";

	ASSERT(domid != IDN_NIL_DOMID);
	dp = &idn_domain[domid];
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	/*
	 * Well, we received all that we were expecting
	 * so stop any CFG timers we had going.
	 */
	IDN_MSGTIMER_STOP(domid, IDNP_CFG, 0);

	dp->dncpus = 0;
	for (p = 0; p < NCPU; p++)
		if (CPU_IN_SET(dp->dcpuset, p))
			dp->dncpus++;
	dp->dhw.dh_nboards = 0;
	for (p = 0; p < MAX_BOARDS; p++)
		if (BOARD_IN_SET(dp->dhw.dh_boardset, p))
			dp->dhw.dh_nboards++;

	IDN_GLOCK_EXCL();
	/*
	 * Verify dcpuset and dhw.dh_boardset don't
	 * conflict with any existing DC member.
	 */
	b_conflicts = idn.dc_boardset & dp->dhw.dh_boardset;
	CPUSET_ZERO(p_conflicts);
	CPUSET_OR(p_conflicts, idn.dc_cpuset);
	CPUSET_AND(p_conflicts, dp->dcpuset);

	if (b_conflicts || !CPUSET_ISNULL(p_conflicts)) {
		if (b_conflicts) {
			cmn_err(CE_WARN,
			    "IDN: 231: domain %d boardset "
			    "(0x%x) conflicts with existing "
			    "IDN boardset (0x%x)",
			    domid, dp->dhw.dh_boardset,
			    b_conflicts);
		}
		if (!CPUSET_ISNULL(p_conflicts)) {
			cmn_err(CE_WARN,
			    "IDN: 232: domain %d cpuset "
			    "(0x%x.%0x) conflicts with existing "
			    "IDN cpuset (0x%x.%0x)", domid,
			    UPPER32_CPUMASK(dp->dcpuset),
			    LOWER32_CPUMASK(dp->dcpuset),
			    UPPER32_CPUMASK(p_conflicts),
			    LOWER32_CPUMASK(p_conflicts));
		}
		IDN_GUNLOCK();
		/*
		 * Need to disconnect and not retry with this guy.
		 */
		IDN_DUNLOCK(domid);
		IDN_SYNC_LOCK();
		DOMAINSET_DEL(idn.domset.ds_relink, domid);
		IDN_DLOCK_EXCL(domid);

		INIT_IDNKERR(&idnerr);
		SET_IDNKERR_ERRNO(&idnerr, EPROTO);
		SET_IDNKERR_IDNERR(&idnerr, IDNKERR_CONFIG_FATAL);
		SET_IDNKERR_PARAM0(&idnerr, domid);
		idn_update_op(IDNOP_ERROR, DOMAINSET(domid), &idnerr);

		(void) idn_disconnect(domid, IDNFIN_FORCE_HARD,
		    IDNFIN_ARG_CFGERR_FATAL, IDNFIN_SYNC_NO);
		IDN_SYNC_UNLOCK();

		return (-1);
	}

	idn_mainmbox_reset(domid, dp->dmbox.m_send);
	idn_mainmbox_reset(domid, dp->dmbox.m_recv);

#ifdef IDNBUG_CPUPERBOARD
	/*
	 * We only allow connections to domains whose (mem) boards
	 * all have at least one cpu.  This is necessary so that
	 * we can program the CICs of that respective board.  This
	 * is primarily only a requirement if the remote domain
	 * is the master _and_ has the SMR in that particular board.
	 * To simplify the checking we simply restrict connections to
	 * domains that have at least one cpu on all boards that
	 * contain memory.
	 */
	if (!idn_cpu_per_board((void *)NULL, dp->dcpuset, &dp->dhw)) {
		cmn_err(CE_WARN,
		    "IDN: 233: domain %d missing CPU per "
		    "memory boardset (0x%x), CPU boardset (0x%x)",
		    domid, dp->dhw.dh_boardset,
		    cpuset2boardset(dp->dcpuset));

		IDN_GUNLOCK();
		/*
		 * Need to disconnect and not retry with this guy.
		 */
		IDN_DUNLOCK(domid);
		IDN_SYNC_LOCK();
		DOMAINSET_DEL(idn.domset.ds_relink, domid);
		IDN_DLOCK_EXCL(domid);

		INIT_IDNKERR(&idnerr);
		SET_IDNKERR_ERRNO(&idnerr, EINVAL);
		SET_IDNKERR_IDNERR(&idnerr, IDNKERR_CPU_CONFIG);
		SET_IDNKERR_PARAM0(&idnerr, domid);
		idn_update_op(IDNOP_ERROR, DOMAINSET(domid), &idnerr);

		(void) idn_disconnect(domid, IDNFIN_FORCE_HARD,
		    IDNFIN_ARG_CPUCFG, IDNFIN_SYNC_NO);
		IDN_SYNC_UNLOCK();

		return (-1);
	}
#endif /* IDNBUG_CPUPERBOARD */

	CPUSET_OR(idn.dc_cpuset, dp->dcpuset);
	idn.dc_boardset |= dp->dhw.dh_boardset;

	IDN_GUNLOCK();

	/*
	 * Set up the portmap for this domain.
	 */
	i = -1;
	for (p = 0; p < NCPU; p++) {
		BUMP_INDEX(dp->dcpuset, i);
		dp->dcpumap[p] = (uchar_t)i;
	}

	/*
	 * Got everything we need from the remote
	 * domain, now we can program hardware as needed.
	 */
	if (idn_program_hardware(domid) != 0) {
		domainset_t	domset;
		/*
		 * Yikes!  Failed to program hardware.
		 * Gotta bail.
		 */
		cmn_err(CE_WARN,
		    "IDN: 234: failed to program hardware for domain %d "
		    "(boardset = 0x%x)",
		    domid, dp->dhw.dh_boardset);

		IDN_DUNLOCK(domid);
		/*
		 * If we're having problems programming our
		 * hardware we better unlink completely from
		 * the IDN before things get really bad.
		 */
		IDN_SYNC_LOCK();
		IDN_GLOCK_EXCL();
		IDN_GSTATE_TRANSITION(IDNGS_DISCONNECT);
		domset = DOMAINSET_ALL;
		DOMAINSET_DEL(domset, idn.localid);
		IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);
		IDN_GUNLOCK();

		INIT_IDNKERR(&idnerr);
		SET_IDNKERR_ERRNO(&idnerr, EINVAL);
		SET_IDNKERR_IDNERR(&idnerr, IDNKERR_HW_ERROR);
		SET_IDNKERR_PARAM0(&idnerr, domid);
		idn_update_op(IDNOP_ERROR, DOMAINSET_ALL, &idnerr);

		idn_unlink_domainset(domset, IDNFIN_NORMAL, IDNFIN_ARG_HWERR,
		    IDNFIN_OPT_UNLINK, BOARDSET_ALL);

		IDN_SYNC_UNLOCK();
		IDN_DLOCK_EXCL(domid);

		return (-1);
	}

	/*
	 * Now that hardware has been programmed we can
	 * remap the SMR into our local space, if necessary.
	 */
	IDN_GLOCK_EXCL();
	if (domid == IDN_GET_MASTERID()) {
		/*
		 * No need to worry about disabling the data
		 * server since at this stage there is only
		 * one and he doesn't go active until his
		 * mailbox (dmbox.m_recv->mm_smr_mboxp) is set up.
		 */
		smr_remap(&kas, idn.smr.vaddr, idn.smr.rempfn, IDN_SMR_SIZE);
	}
	IDN_GUNLOCK();

	/*
	 * There is no need to ACK the CFG messages since remote
	 * domain would not progress to the next state (CON_SENT)
	 * unless he has received everything.
	 */

	dp->dcfgrcvdone = 1;
	PR_PROTO("%s:%d: RECV config DONE\n", proc, domid);

	if (dp->dcfgsnddone) {
		idn_xdcargs_t	xargs;
		/*
		 * Well, we've received all that we were expecting,
		 * but we don't know if the remote domain has
		 * received all that it was expecting from us,
		 * although we know we transferred everything
		 * so let's get the show on the road.
		 */
		IDN_DUNLOCK(domid);
		IDN_SYNC_LOCK();
		IDN_DLOCK_EXCL(domid);
		/*
		 * If the state has changed from CONFIG
		 * then somebody else has taken over
		 * control of this domain so we can just
		 * bail out.
		 */
		if (dp->dstate == IDNDS_CONFIG) {
			dp->dxp = &xphase_con;
			IDN_XSTATE_TRANSITION(dp, IDNXS_PEND);
			bzero(xargs, sizeof (xargs));

			(void) idn_xphase_transition(domid, NULL, xargs);
		}
		IDN_SYNC_UNLOCK();
	}

	return (0);
}

static int
idn_verify_config_mbox(int domid)
{
	idn_domain_t	*ldp, *dp;
	idn_mainmbox_t	*mmp;
	idn_mboxtbl_t	*mtp;
	int		c, rv = 0;
	uint_t		activeptr, readyptr;
	ushort_t	mbox_csum;

	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	dp = &idn_domain[domid];
	ldp = &idn_domain[idn.localid];

	/*
	 * The master will have assigned us the dmbox.m_tbl
	 * from which we assign our receive mailboxes.
	 * The first (0) entry contains the cookie used
	 * for verification.
	 */
	IDN_DLOCK_SHARED(idn.localid);
	/*
	 * Now that we have an assigned mboxtbl from the
	 * master, we can determine which receive mailbox
	 * we indirectly assigned to him at the time we
	 * sent him his MBOX_INDEX.  Prep it, however note
	 * that the master will have not been able to
	 * validate it because of the chicken 'n egg
	 * problem between a master and slave.  Thus we
	 * need to reset the cookie after the prep.
	 */
	mmp = dp->dmbox.m_recv;
	mtp = IDN_MBOXTBL_PTR(ldp->dmbox.m_tbl, domid);
	for (c = 0; c < IDN_MAX_NETS; c++) {
		mutex_enter(&mmp[c].mm_mutex);
		ASSERT(!mmp[c].mm_smr_mboxp);

		mmp[c].mm_smr_mboxp = mtp;
		mbox_csum = IDN_CKSUM_MBOX(&mtp->mt_header);
		if (!VALID_MBOXHDR(&mtp->mt_header, c, mbox_csum)) {
			cmn_err(CE_WARN,
			    "IDN: 235: [recv] mailbox (domain %d, "
			    "channel %d) SMR CORRUPTED - RELINK",
			    domid, c);
			cmn_err(CE_CONT,
			    "IDN: 235: [recv] expected (cookie 0x%x, "
			    "cksum 0x%x) actual (cookie 0x%x, "
			    "cksum 0x%x)\n",
			    IDN_GET_MBOXHDR_COOKIE(&mtp->mt_header),
			    (int)mtp->mt_header.mh_cksum,
			    IDN_MAKE_MBOXHDR_COOKIE(0, 0, c),
			    (int)mbox_csum);
			mutex_exit(&mmp[c].mm_mutex);
			rv = -1;
			break;
		}
		activeptr = mtp->mt_header.mh_svr_active_ptr;
		readyptr = mtp->mt_header.mh_svr_ready_ptr;
		/*
		 * Verify pointers are valid.
		 */
		if (!activeptr || !VALID_NWROFFSET(activeptr, 2) ||
		    !readyptr || !VALID_NWROFFSET(readyptr, 2)) {
			cmn_err(CE_WARN,
			    "IDN: 235: [recv] mailbox (domain %d, "
			    "channel %d) SMR CORRUPTED - RELINK",
			    domid, c);
			cmn_err(CE_CONT,
			    "IDN: 235: [recv] activeptr (0x%x), "
			    "readyptr (0x%x)\n",
			    activeptr, readyptr);
			mutex_exit(&mmp[c].mm_mutex);
			rv = -1;
			break;
		}
		mmp[c].mm_smr_activep =	(ushort_t *)IDN_OFFSET2ADDR(activeptr);
		mmp[c].mm_smr_readyp =	(ushort_t *)IDN_OFFSET2ADDR(readyptr);
		mutex_exit(&mmp[c].mm_mutex);
		IDN_MBOXTBL_PTR_INC(mtp);
	}

	IDN_DUNLOCK(idn.localid);

	if (rv)
		return (rv);

	/*
	 * Now we need to translate SMR offsets for send mailboxes
	 * to actual virtual addresses.
	 */
	mmp = dp->dmbox.m_send;
	for (c = 0; c < IDN_MAX_NETS; mmp++, c++) {
		mutex_enter(&mmp->mm_mutex);
		if ((mtp = mmp->mm_smr_mboxp) == NULL) {
			mutex_exit(&mmp->mm_mutex);
			rv = -1;
			break;
		}

		mbox_csum = IDN_CKSUM_MBOX(&mtp->mt_header);

		if (!VALID_MBOXHDR(&mtp->mt_header, c, mbox_csum)) {
			cmn_err(CE_WARN,
			    "IDN: 235: [send] mailbox (domain %d, "
			    "channel %d) SMR CORRUPTED - RELINK",
			    domid, c);
			cmn_err(CE_CONT,
			    "IDN: 235: [send] expected (cookie 0x%x, "
			    "cksum 0x%x) actual (cookie 0x%x, "
			    "cksum 0x%x)\n",
			    IDN_GET_MBOXHDR_COOKIE(&mtp->mt_header),
			    (int)mtp->mt_header.mh_cksum,
			    IDN_MAKE_MBOXHDR_COOKIE(0, 0, c),
			    (int)mbox_csum);
			mutex_exit(&mmp->mm_mutex);
			rv = -1;
			break;
		}
		activeptr = mtp->mt_header.mh_svr_active_ptr;
		readyptr = mtp->mt_header.mh_svr_ready_ptr;
		/*
		 * Paranoid check.
		 */
		if (!activeptr || !VALID_NWROFFSET(activeptr, 2) ||
		    !readyptr || !VALID_NWROFFSET(readyptr, 2)) {
			cmn_err(CE_WARN,
			    "IDN: 235: [send] mailbox (domain %d, "
			    "channel %d) SMR CORRUPTED - RELINK",
			    domid, c);
			cmn_err(CE_CONT,
			    "IDN: 235: [send] activeptr (0x%x), "
			    "readyptr (0x%x)\n",
			    activeptr, readyptr);
			mutex_exit(&mmp->mm_mutex);
			rv = -1;
			break;
		}
		mmp->mm_smr_activep = (ushort_t *)IDN_OFFSET2ADDR(activeptr);
		mmp->mm_smr_readyp = (ushort_t *)IDN_OFFSET2ADDR(readyptr);
		idn_reset_mboxtbl(mtp);
		mutex_exit(&mmp->mm_mutex);
		IDN_MBOXTBL_PTR_INC(mtp);
	}

	return (rv);
}

/*
 * The BUFSIZEs between domains have to be equal so that slave buffers
 * and the master's slabpool are consistent.
 * The MTUs between domains have to be equal so they can transfer
 * packets consistently without possible data truncation.
 *
 * ZZZ - Perhaps these could be negotiated?
 */
static int
valid_mtu(uint_t mtu)
{
	return ((mtu == idn_domain[idn.localid].dmtu) && mtu);
}

static int
valid_bufsize(uint_t bufsize)
{
	return ((bufsize == idn_domain[idn.localid].dbufsize) && bufsize);
}

static int
valid_slabsize(int slabsize)
{
	return ((slabsize == idn_domain[idn.localid].dslabsize) && slabsize);
}

static int
valid_nwrsize(int nwrsize)
{
	return ((nwrsize == idn_domain[idn.localid].dnwrsize) && nwrsize);
}

static int
idn_program_hardware(int domid)
{
	int		rv, is_master;
	idn_domain_t	*dp;
	uint_t		*mcadrp;
	pfn_t		rem_pfn, rem_pfnlimit;
	procname_t	proc = "idn_program_hardware";

	PR_PROTO("%s:%d: program hw in domain %d w.r.t remote domain %d\n",
	    proc, domid, idn.localid, domid);

	dp = &idn_domain[domid];

	ASSERT(domid != idn.localid);
	ASSERT(IDN_DLOCK_IS_EXCL(domid));
	ASSERT(dp->dstate == IDNDS_CONFIG);

	IDN_GLOCK_EXCL();

	if (DOMAIN_IN_SET(idn.domset.ds_hwlinked, domid)) {
		IDN_GUNLOCK();
		return (0);
	}

	DOMAINSET_ADD(idn.domset.ds_flush, domid);
	CHECKPOINT_OPENED(IDNSB_CHKPT_CACHE, dp->dhw.dh_boardset, 1);

	if (domid != IDN_GET_MASTERID()) {
		/*
		 * If the remote domain is a slave, then
		 * all we have to program is the CIC sm_mask.
		 */
		is_master = 0;
		if ((idn.localid == IDN_GET_MASTERID()) &&
		    lock_try(&idn.first_hwlink)) {
			/*
			 * This is our first HW link and I'm the
			 * master, which means we need to program
			 * our local bar/lar.
			 */
			ASSERT(idn.first_hwmasterid == (short)IDN_NIL_DOMID);
			idn.first_hwmasterid = (short)idn.localid;
			rem_pfn = idn.smr.locpfn;
			rem_pfnlimit = idn.smr.locpfn +
			    btop(MB2B(IDN_SMR_SIZE));
		} else {
			/*
			 * Otherwise, just a slave linking to
			 * another slave.  No bar/lar updating
			 * necessary.
			 */
			rem_pfn = rem_pfnlimit = PFN_INVALID;
		}
		mcadrp = NULL;
	} else {
		/*
		 * If the remote domain is a master, then
		 * we need to program the CIC sm_mask/sm_bar/sm_lar,
		 * and PC's.
		 */
		is_master = 1;
		rem_pfn = idn.smr.rempfn;
		rem_pfnlimit = idn.smr.rempfnlim;
		mcadrp = dp->dhw.dh_mcadr;
		ASSERT(idn.first_hwmasterid == (short)IDN_NIL_DOMID);
		idn.first_hwmasterid = (short)domid;
	}

	PR_PROTO("%s:%d: ADD bset (0x%x)\n", proc, domid, dp->dhw.dh_boardset);

	rv = idnxf_shmem_add(is_master, dp->dhw.dh_boardset,
	    rem_pfn, rem_pfnlimit, mcadrp);

	if (rv == 0) {
		DOMAINSET_ADD(idn.domset.ds_hwlinked, domid);
	} else {
		if (rem_pfn == idn.smr.locpfn)
			lock_clear(&idn.first_hwlink);

		if (idn.first_hwmasterid == (short)domid)
			idn.first_hwmasterid = (short)IDN_NIL_DOMID;

		(void) idnxf_shmem_sub(is_master, dp->dhw.dh_boardset);
	}

	IDN_GUNLOCK();

	return (rv);
}

static int
idn_deprogram_hardware(int domid)
{
	int		rv, is_master;
	idn_domain_t	*dp;
	procname_t	proc = "idn_deprogram_hardware";


	dp = &idn_domain[domid];

	ASSERT(domid != idn.localid);
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	/*
	 * Need to take into consideration what boards remote
	 * domain was connected to.  If we don't have a connection to
	 * them ourself, then we better remove them now , otherwise
	 * they'll never be removed (unless we link to them at some point).
	 */
#if 0
	DEBUG_USECDELAY(500000);
#endif /* 0 */

	IDN_GLOCK_EXCL();

	if (!DOMAIN_IN_SET(idn.domset.ds_hwlinked, domid)) {
		IDN_GUNLOCK();
		return (0);
	}

	PR_PROTO("%s:%d: DEprogram hw in domain %d w.r.t remote domain %d\n",
	    proc, domid, idn.localid, domid);

	/*
	 * It's possible to come through this flow for domains that
	 * have not been programmed, i.e. not in idn.hwlinked_domset,
	 * so don't bother asserting that they might be in there.
	 * This can occur if we lose a domain during the config/syn
	 * sequence.  If this occurs we won't know whether the remote
	 * domain has programmed its hardware or not.  If it has then
	 * it will have to go through the DMAP sequence and thus we
	 * have to go through it also.  So, if we reach at least the
	 * CONFIG state, we need to go through the DMAP handshake.
	 */

	PR_PROTO("%s:%d: SUB bset (0x%x)\n", proc, domid, dp->dhw.dh_boardset);

	if (idn.first_hwmasterid == (short)domid) {
		is_master = 1;
		idn.first_hwmasterid = (short)IDN_NIL_DOMID;
	} else {
		is_master = 0;
	}
	rv = idnxf_shmem_sub(is_master, dp->dhw.dh_boardset);

	if (rv == 0)
		DOMAINSET_DEL(idn.domset.ds_hwlinked, domid);

	IDN_GUNLOCK();

	return (rv);
}

/*
 * Remember can't send slabs back to master at this point.
 * Entered with write-drwlock held.
 * Returns with drwlock dropped.
 */
static void
idn_deconfig(int domid)
{
	idn_domain_t	*dp, *ldp;
	smr_slab_t	*sp;
	int		c, masterid;
	procname_t	proc = "idn_deconfig";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));
	ASSERT(domid != idn.localid);

	ldp = &idn_domain[idn.localid];
	dp = &idn_domain[domid];

	ASSERT(dp->dstate == IDNDS_DMAP);

	PR_PROTO("%s:%d: (dio=%d, dioerr=%d, dnslabs=%d)\n",
	    proc, domid, dp->dio, dp->dioerr, dp->dnslabs);

	IDN_GLOCK_EXCL();
	masterid = IDN_GET_MASTERID();

	idn.dc_boardset &= ~dp->dhw.dh_boardset;
	for (c = 0; c < NCPU; c++) {
		if (CPU_IN_SET(dp->dcpuset, c)) {
			CPUSET_DEL(idn.dc_cpuset, c);
		}
	}

	IDN_GUNLOCK();

	(void) smr_buf_free_all(domid);

	if (idn.localid == masterid) {
		/*
		 * Since I'm the master there may
		 * have been slabs in this domain's
		 * idn_domain[] entry.
		 */
		DSLAB_LOCK_EXCL(domid);
		if ((sp = dp->dslab) != NULL) {
			PR_PROTO("%s:%d: freeing up %d dead slabs\n",
			    proc, domid, dp->dnslabs);
			smr_slab_free(domid, sp);
			dp->dslab = NULL;
			dp->dnslabs = 0;
			dp->dslab_state = DSLAB_STATE_UNKNOWN;
		}
		DSLAB_UNLOCK(domid);
	} else if (domid == masterid) {
		/*
		 * We're shutting down the master!
		 * We need to blow away our local slab
		 * data structures.
		 * Since I'm not the master, there should
		 * be no slab structures in the given
		 * domain's idn_domain[] entry.  They should
		 * only exist in the local domain's entry.
		 */
		DSLAB_LOCK_EXCL(idn.localid);
		ASSERT(dp->dslab == NULL);
#ifdef DEBUG
		{
			int	nbusy = 0;
			uint_t	dommask = 0;
			for (sp = ldp->dslab; sp; sp = sp->sl_next) {
				smr_slabbuf_t *bp;

				if (!smr_slab_busy(sp))
					continue;
				nbusy++;
				for (bp = sp->sl_inuse; bp; bp = bp->sb_next)
					if (bp->sb_domid != IDN_NIL_DOMID)
						DOMAINSET_ADD(dommask,
						    bp->sb_domid);
			}
			if (nbusy)
				PR_PROTO("%s:%d: found %d busy slabs "
				    "(dommask = 0x%x)\n",
				    proc, domid, nbusy, dommask);
		}
#endif /* DEBUG */
		if ((sp = ldp->dslab) != NULL) {
			PR_PROTO("%s:%d: freeing up %d local slab "
			    "structs\n", proc, domid, ldp->dnslabs);
			smr_slab_garbage_collection(sp);
			ldp->dslab = NULL;
			ldp->dnslabs = 0;
			ldp->dslab_state = DSLAB_STATE_UNKNOWN;
		}
		DSLAB_UNLOCK(idn.localid);
	}
	if (dp->dio) {
		PR_PROTO("%s:%d: reset dio (%d) to 0\n", proc, domid, dp->dio);
		dp->dio = 0;
	}
	dp->dioerr = 0;

	PR_PROTO("%s:%d: reset diocheck (%x) to 0\n",
	    proc, domid, dp->diocheck);
	lock_clear(&dp->diocheck);

	CHECKPOINT_CLOSED(IDNSB_CHKPT_LINK, dp->dhw.dh_boardset, 2);

	/*
	 * Should have already flush our memory before
	 * reaching this stage.  The issue is that by the
	 * time we reach here the remote domains may have
	 * already reprogrammed their hardware and so flushing
	 * out caches now could result in a arbstop/hang
	 * if we have data that needs to go back to one
	 * of the remote domains that has already reprogrammed
	 * its hardware.
	 */
	ASSERT(!DOMAIN_IN_SET(idn.domset.ds_flush, domid));

	(void) idn_deprogram_hardware(domid);
	/*
	 * XXX - what to do if we
	 *	 fail to program hardware
	 *	 probably should panic since
	 *	 demise of system may be near?
	 *	 Sufficient to just shutdown network?
	 */

	IDN_DSTATE_TRANSITION(dp, IDNDS_CLOSED);

	idn_close_domain(domid);
}

/*
 * If we're sending a Reset we better make sure we don't have any
 * references or traffic headed in the direction of this guy, since
 * when he receives the reset, he'll start shutting down which means
 * we effectively have to shutdown _before_ sending the reset.
 * DO NOT HOLD ANY DOMAIN RWLOCKS ON ENTRY.  Could result in deadlock
 * due to channel server looping back through STREAMs and attempting
 * to acquire domain lock, i.e. channel server will never "stop".
 */
static void
idn_shutdown_datapath(domainset_t domset, int force)
{
	int		do_allchan;
	idn_domain_t	*dp;
	register int	d;
	procname_t	proc = "idn_shutdown_datapath";


	PR_CHAN("%s: domset = 0x%x\n", proc, (uint_t)domset);

	do_allchan = (domset == DOMAINSET_ALL) ? 1 : 0;

	DOMAINSET_DEL(domset, idn.localid);

	if (do_allchan) {
		/*
		 * Need to stop all outgoing and
		 * incoming SMR references.
		 */
		idn_deactivate_channel(CHANSET_ALL, IDNCHAN_OFFLINE);
	}

	/*
	 * If force is set then we don't want to reference
	 * the SMR at all, so deactivate the domains from
	 * channels first.  This will result in the mainmbox-flush
	 * routines to just clean up without referencing the
	 * SMR space.
	 */
	if (force)
		idn_mainmbox_deactivate(domset);

	/*
	 * Flush out mailboxes (clear smr reference).
	 */
	for (d = 0; d < MAX_DOMAINS; d++) {
		if (!DOMAIN_IN_SET(domset, d))
			continue;

		dp = &idn_domain[d];
		if ((dp->dmbox.m_send == NULL) && (dp->dmbox.m_recv == NULL))
			continue;

		IDN_MBOX_LOCK(d);
		if (dp->dmbox.m_send)
			(void) idn_mainmbox_flush(d, dp->dmbox.m_send);
		if (dp->dmbox.m_recv)
			(void) idn_mainmbox_flush(d, dp->dmbox.m_recv);
		IDN_MBOX_UNLOCK(d);
	}
	/*
	 * Deactivate all domain references also.
	 * Only necessary if it wasn't already done above.
	 */
	if (!force)
		idn_mainmbox_deactivate(domset);
}

void
idn_send_cmd(int domid, idn_cmd_t cmdtype, uint_t arg1, uint_t arg2, uint_t
    arg3)
{
	idn_msgtype_t	mt;
	procname_t	proc = "idn_send_cmd";

	mt.mt_mtype = IDNP_CMD;
	mt.mt_atype = 0;
	mt.mt_cookie = 0;

	ASSERT(IDN_DLOCK_IS_HELD(domid));

	PR_PROTO("%s:%d: sending command %s\n", proc, domid,
	    VALID_IDNCMD(cmdtype) ? idncmd_str[cmdtype] : "unknown");

	IDN_MSGTIMER_START(domid, IDNP_CMD, (ushort_t)cmdtype,
	    idn_msg_waittime[IDNP_CMD], &mt.mt_cookie);

	IDNXDC(domid, &mt, (uint_t)cmdtype, arg1, arg2, arg3);
}

void
idn_send_cmdresp(int domid, idn_msgtype_t *mtp, idn_cmd_t cmdtype, uint_t arg1,
    uint_t arg2, uint_t cerrno)
{
	idn_msgtype_t	mt;

	ASSERT(IDN_DLOCK_IS_HELD(domid));

	if (domid == idn.localid) {
		/*
		 * It's possible local domain received a command
		 * from itself.  However, we cannot send a normal
		 * "ack" response (XDC) to ourself.
		 */
		return;
	}

	mt.mt_mtype = IDNP_CMD | IDNP_ACK;
	mt.mt_atype = 0;
	mt.mt_cookie = mtp->mt_cookie;

	IDNXDC(domid, &mt, (uint_t)cmdtype, arg1, arg2, cerrno);
}

static void
idn_send_cmd_nackresp(int domid, idn_msgtype_t *mtp, idn_cmd_t cmdtype,
    idn_nack_t nacktype)
{
	idn_msgtype_t	mt;

	if (domid == idn.localid)
		return;

	mt.mt_mtype = IDNP_CMD | IDNP_NACK;
	mt.mt_atype = 0;
	mt.mt_cookie = mtp->mt_cookie;

	(void) IDNXDC(domid, &mt, (uint_t)cmdtype, (uint_t)nacktype, 0, 0);
}

void
idn_broadcast_cmd(idn_cmd_t cmdtype, uint_t arg1, uint_t arg2, uint_t arg3)
{
	idn_msgtype_t	mt;
	domainset_t	domset;
	procname_t	proc = "idn_broadcast_cmd";

	IDN_GLOCK_SHARED();

	domset = idn.domset.ds_connected;
	DOMAINSET_DEL(domset, idn.localid);

	PR_PROTO("%s: broadcasting command (%s) to domainset 0x%x\n",
	    proc, VALID_IDNCMD(cmdtype) ? idncmd_str[cmdtype] : "unknown",
	    domset);

	mt.mt_mtype = IDNP_CMD;
	mt.mt_atype = 0;
	mt.mt_cookie = 0;

	IDNXDC_BROADCAST(domset, &mt, (uint_t)cmdtype, arg1, arg2, arg3);

	IDN_GUNLOCK();
	/*
	 * This is a broadcast which means local domain needs
	 * to process it also.  Since we can't XDC to ourselves
	 * we simply call a local function.
	 */
	idn_local_cmd(cmdtype, arg1, arg2, arg3);
}

/*
 * Since xargs[0] contains the cmdtype, only xargs[1], xargs[2], xargs[3]
 * are valid possible response arguments.
 */
static void
idn_recv_cmd(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	uint_t			msg = mtp->mt_mtype;
	register idn_domain_t	*dp;
	idn_cmd_t		cmdtype;
	uint_t			acknack;
	uint_t			cmdarg1, cmdarg2, cmdarg3;
	int			islocal;
	int			unsup_cmd_sent, unsup_cmd_recvd;
	procname_t		proc = "idn_recv_cmd";

	acknack = msg & IDNP_ACKNACK_MASK;
	GET_XARGS(xargs, &cmdtype, &cmdarg1, &cmdarg2, &cmdarg3);

	dp = &idn_domain[domid];
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	IDN_GLOCK_SHARED();

	islocal = (domid == idn.localid);

	ASSERT(!acknack || (acknack & IDNP_ACKNACK_MASK));

	PR_PROTO("%s:%d: (local=%d) acknack=0x%x, cmdtype=%s(%d), "
	    "a1=0x%x, a2=0x%x, a3=0x%x\n",
	    proc, domid, islocal, acknack,
	    VALID_IDNCMD(cmdtype) ? idncmd_str[cmdtype] : "unknown",
	    cmdtype, cmdarg1, cmdarg2, cmdarg3);

	unsup_cmd_sent = unsup_cmd_recvd = 0;

	if ((IDN_GET_MASTERID() == IDN_NIL_DOMID) ||
	    (dp->dstate != IDNDS_CONNECTED)) {
		/*
		 * Commands cannot be handled without a valid
		 * master.  If this is a request then nack him.
		 */
		PR_PROTO("%s:%d: cannot process CMD w/o master (%d, %s)\n",
		    proc, domid, IDN_GET_MASTERID(),
		    idnds_str[dp->dstate]);

		if (!islocal && !(acknack & IDNP_ACKNACK_MASK))
			idn_send_cmd_nackresp(domid, mtp, cmdtype,
			    IDNNACK_NOCONN);
		IDN_GUNLOCK();
		return;
	}
	IDN_GUNLOCK();

	if (acknack & IDNP_ACKNACK_MASK) {
		idn_nack_t	nack;
		/*
		 * Receiving a cmd+ack or cmd+nack in response to some
		 * earlier command we must have issued.
		 * If the response is a nack, there are two possibilites:
		 *
		 *	1. Remote domain failed to allocate due
		 *	   to limited resources.
		 *
		 *	2. Remote domain does not support this
		 *	   particular command.
		 *
		 * In the case of #2, the argument immediately after
		 * the cmdtype (xargs[1]) will be (-1).
		 */
		nack = (idn_nack_t)cmdarg1;
		if ((acknack & IDNP_NACK) && (nack == IDNNACK_BADCMD))
			unsup_cmd_sent++;

		if (islocal) {
			/*
			 * Shouldn't be receiving local commands w/acks.
			 */
			cmdtype = (idn_cmd_t)0;
		}

		switch (cmdtype) {
		case IDNCMD_SLABALLOC:
			idn_recv_slaballoc_resp(domid, cmdarg1, cmdarg2,
			    cmdarg3);
			break;

		case IDNCMD_SLABFREE:
			idn_recv_slabfree_resp(domid, cmdarg1, cmdarg2,
			    cmdarg3);
			break;

		case IDNCMD_SLABREAP:
			/*
			 * We only care if successful.
			 */
			if (acknack & IDNP_ACK)
				idn_recv_slabreap_resp(domid, cmdarg1, cmdarg3);
			break;

		case IDNCMD_NODENAME:
			if ((acknack & IDNP_NACK) == 0) {
				idn_recv_nodename_resp(domid, cmdarg1, cmdarg3);
				break;
			}
			switch (nack) {
			case IDNNACK_NOCONN:
			case IDNNACK_RETRY:
				/*
				 * Remote domain was not quite
				 * ready, try again.
				 */
				PR_PROTO("%s:%d: remote not ready "
				    "for %s - retrying "
				    "[dstate=%s]\n",
				    proc, domid,
				    idncmd_str[IDNCMD_NODENAME],
				    idnds_str[dp->dstate]);

				if (dp->dstate == IDNDS_CONNECTED)
					(void) timeout(idn_retry_nodename_req,
					    (void *)(uintptr_t)domid, hz);
			default:
				break;
			}
			break;

		default:
			/*
			 * Unsupported command.
			 */
			unsup_cmd_recvd++;
			break;
		}
		if (unsup_cmd_sent) {
			PR_PROTO("%s:%d: unsupported command "
			    "requested (0x%x)\n",
			    proc, domid, cmdtype);
		}
		if (unsup_cmd_recvd) {
			PR_PROTO("%s:%d: unsupported command "
			    "response (0x%x)\n",
			    proc, domid, cmdtype);
		}
	} else {
		/*
		 * Receiving a regular cmd from a remote domain.
		 */
		switch (cmdtype) {
		case IDNCMD_SLABALLOC:
			idn_recv_slaballoc_req(domid, mtp, cmdarg1);
			break;

		case IDNCMD_SLABFREE:
			idn_recv_slabfree_req(domid, mtp, cmdarg1, cmdarg2);
			break;

		case IDNCMD_SLABREAP:
			idn_recv_slabreap_req(domid, mtp, cmdarg1);
			break;

		case IDNCMD_NODENAME:
			idn_recv_nodename_req(domid, mtp, cmdarg1);
			break;

		default:
			/*
			 * Unsupported command.
			 */
			unsup_cmd_recvd++;
			break;
		}
		if (!islocal && unsup_cmd_recvd) {
			/*
			 * Received an unsupported IDN command.
			 */
			idn_send_cmd_nackresp(domid, mtp, cmdtype,
			    IDNNACK_BADCMD);
		}
	}
}

/*
 * This is a supporting routine for idn_broadcast_cmd() to
 * handle processing of the requested command for the local
 * domain.  Currently the only support broadcast command
 * supported is reaping.
 */
/*ARGSUSED2*/
static void
idn_local_cmd(idn_cmd_t cmdtype, uint_t arg1, uint_t arg2, uint_t arg3)
{
	idn_protojob_t	*jp;
	idn_domain_t	*ldp = &idn_domain[idn.localid];
	procname_t	proc = "idn_local_cmd";

	PR_PROTO("%s: submitting local command %s on domain %d\n",
	    proc, VALID_IDNCMD(cmdtype) ? idncmd_str[cmdtype] : "unknown",
	    idn.localid);


	jp = idn_protojob_alloc(KM_SLEEP);

	jp->j_msg.m_domid    = ldp->domid;
	jp->j_msg.m_msgtype  = IDNP_CMD;
	jp->j_msg.m_cookie   = ldp->dcookie_recv;
	SET_XARGS(jp->j_msg.m_xargs, cmdtype, arg1, arg2, arg3);

	idn_protojob_submit(ldp->domid, jp);
}

/*
 * Terminate any outstanding commands that may have
 * been targeted for the given domain.  A command is
 * designated as outstanding if it has an active timer.
 *
 * serrno = ECANCELED.
 */
static void
idn_terminate_cmd(int domid, int serrno)
{
	idn_domain_t	*dp;
	idn_timer_t	*tplist = NULL, *tp;
	procname_t	proc = "idn_terminate_cmd";

	dp = &idn_domain[domid];

	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	IDN_MSGTIMER_GET(dp, IDNP_CMD, tplist, 0);
	/*
	 * At this point the timers are effectively terminated
	 * since when they're t_onq indication is set false.
	 */
	if (tplist == NULL) {
		PR_PROTO("%s:%d: no outstanding cmds found\n",
		    proc, domid);
		/*
		 * There is a window where we may have caught a
		 * request just prior to issuing the actual
		 * command (SLABALLOC).  We're guaranteed if there
		 * was, then he will have at least registered.
		 * So, if we abort the command now, he'll catch
		 * it before going to sleep.
		 * Drop through.
		 */
	}
	ASSERT(tplist ? (tplist->t_back->t_forw == NULL) : 1);

	for (tp = tplist; tp; tp = tp->t_forw) {
		ASSERT(tp->t_type == IDNP_CMD);

		PR_PROTO("%s:%d: found outstanding cmd: %s\n",
		    proc, domid, idncmd_str[tp->t_subtype]);

		switch (tp->t_subtype) {
		case IDNCMD_SLABALLOC:
			/*
			 * Outstanding slaballoc request may have
			 * slab waiters hanging around.  Need to
			 * tell them to bail out.  The given domain
			 * must be the master if we have an outstanding
			 * command to him.  This also presumes that
			 * if there are any waiters they're only in
			 * the local domain's waiting area (i.e. we're
			 * a slave).
			 */
#ifdef DEBUG
			IDN_GLOCK_SHARED();
			ASSERT(domid == IDN_GET_MASTERID());
			ASSERT(idn.localid != IDN_GET_MASTERID());
			IDN_GUNLOCK();
#endif /* DEBUG */
			(void) smr_slabwaiter_abort(idn.localid, serrno);
			break;

		case IDNCMD_SLABFREE:
		case IDNCMD_SLABREAP:
		case IDNCMD_NODENAME:
			/*
			 * Nothing really waiting for these operations
			 * so no biggy if we just drop.
			 * Note that NODENAME may have an outstanding
			 * buffer, however that will be reclaimed
			 * when we actually unlink from domain.
			 */
			break;

		default:
			ASSERT(0);
			break;
		}
	}
	/*
	 * As mentioned before the timers are effectively no-op'd
	 * once they're dequeued, however let's cleanup house and
	 * get rid of the useless entries in the timeout queue.
	 */
	if (tplist) {
		IDN_TIMER_STOPALL(tplist);
	}

	if (idn_domain[idn.localid].dvote.v.master) {
		/*
		 * I'm the master so it's possible I had
		 * outstanding commands (SLABALLOC) waiting
		 * to be satisfied for the given domain.
		 * Since we're forcing an error it's okay
		 * to continue holding onto the drwlock.
		 */
		PR_PROTO("%s:%d: abort slaballoc waiters\n", proc, domid);
		(void) smr_slabwaiter_abort(domid, serrno);

	} else if (dp->dvote.v.master) {
		PR_PROTO("%s:%d: abort (local domain) slaballoc waiters\n",
		    proc, domid);
		(void) smr_slabwaiter_abort(idn.localid, serrno);
	}
}

static void
idn_send_acknack(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
	idn_domain_t	*dp = &idn_domain[domid];
	procname_t	proc = "idn_send_acknack";

	ASSERT(mtp ? (mtp->mt_mtype & IDNP_ACKNACK_MASK) : 1);
	ASSERT(domid != IDN_NIL_DOMID);

#ifdef DEBUG
	{
		STRING(mstr);
		STRING(astr);

		INUM2STR(mtp->mt_mtype, mstr);
		INUM2STR(mtp->mt_atype, astr);

		if (mtp->mt_mtype & IDNP_ACK) {
			PR_PROTO("%s:%d: dstate=%s, msg=(%s/%s), "
			    "a1=0x%x, a2=0x%x, a3=0x%x, a4 = 0x%x\n",
			    proc, domid, idnds_str[dp->dstate],
			    astr, mstr, xargs[0], xargs[1],
			    xargs[2], xargs[3]);
		} else {
			idn_nack_t	nack;

			nack = GET_XARGS_NACK_TYPE(xargs);
			PR_PROTO("%s:%d: dstate=%s, msg=(%s/%s), "
			    "nack=%s(0x%x)\n",
			    proc, domid, idnds_str[dp->dstate],
			    astr, mstr, idnnack_str[nack],
			    (uint_t)nack);
		}
	}
#endif /* DEBUG */

	(void) IDNXDC(domid, mtp, xargs[0], xargs[1], xargs[2], xargs[3]);
}

/*ARGSUSED0*/
static void
idn_prealloc_slab(int nslabs)
{
	register int	s, serrno;
	smr_slab_t	*sp;
	idn_domain_t	*ldp = &idn_domain[idn.localid];
	procname_t	proc = "idn_prealloc_slab";

	IDN_GLOCK_SHARED();
	DSLAB_LOCK_SHARED(idn.localid);
	if ((idn.state != IDNGS_ONLINE) || (ldp->dnslabs > 0)) {
		/*
		 * Not in the proper state or slab already allocated.
		 */
		DSLAB_UNLOCK(idn.localid);
		IDN_GUNLOCK();
		return;
	}
	IDN_GUNLOCK();
	ASSERT(!ldp->dslab);

	serrno = 0;
	for (s = 0; (s < nslabs) && ((int)ldp->dnslabs < nslabs); s++) {
		/*
		 * Returns with ldp->drwlock dropped.
		 */
		serrno = smr_slab_alloc(idn.localid, &sp);
		if (serrno != 0) {
			PR_PROTO("%s: FAILED to pre-alloc'd "
			    "slab (serrno = %d)\n", proc, serrno);
			break;
		}
		/*
		 * State may have changed since smr_slab_alloc
		 * temporarily drops drwlock.  Make sure we're
		 * still connected.
		 */
		PR_PROTO("%s: SUCCESSFULLY pre-alloc'd slab\n", proc);

		if (idn.state != IDNGS_ONLINE) {
			PR_PROTO("%s: Lost connection..leaving\n", proc);
			break;
		}
	}

	DSLAB_UNLOCK(idn.localid);
}

/*
 * Received a request from a remote domain to
 * allocate a slab from the master SMR for him.
 * Allocate slab and return the response.
 */
static void
idn_recv_slaballoc_req(int domid, idn_msgtype_t *mtp, uint_t slab_size)
{
	register idn_domain_t	*dp;
	procname_t		proc = "idn_recv_slaballoc_req";

	PR_PROTO("%s: slaballoc req from domain %d (size=0x%x)\n",
	    proc, domid, slab_size);

	dp = &idn_domain[domid];

	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	IDN_GLOCK_SHARED();

	if (idn.localid != IDN_GET_MASTERID()) {
		IDN_GUNLOCK();
		/*
		 * It's a fatal error if the remote domain thinks
		 * we're the master.
		 */
		idn_send_slaballoc_resp(domid, mtp, 0, 0, EACCES);

	} else if (dp->dstate != IDNDS_CONNECTED) {

		IDN_GUNLOCK();
		/*
		 * It's a fatal error if we don't yet have a
		 * connection established with the requestor.
		 */
		idn_send_slaballoc_resp(domid, mtp, 0, 0, ENOLINK);
	} else {
		int		serrno;
		smr_slab_t	*sp;
		smr_offset_t	slab_offset;

		IDN_GUNLOCK();
		DSLAB_LOCK_SHARED(domid);
		IDN_DUNLOCK(domid);
		/*
		 * We're connected and we're the master.
		 * smr_slab_alloc() returns with dp->drwlock dropped.
		 */
		if ((serrno = smr_slab_alloc(domid, &sp)) == 0) {
			/*
			 * Successfully allocated slab for remote slave.
			 */
			slab_offset = IDN_ADDR2OFFSET(sp->sl_start);
			slab_size   = sp->sl_end - sp->sl_start;
			ASSERT((slab_offset != 0) && (slab_size != 0));
		} else {
			slab_offset = slab_size = 0;
		}
		DSLAB_UNLOCK(domid);
		/*
		 * The drwlock is dropped during smr_slab_alloc.
		 * During that time our connection with the given
		 * domain may have changed.  Better check again.
		 */
		IDN_DLOCK_SHARED(domid);
		if ((dp->dstate != IDNDS_CONNECTED) && !serrno) {
			/*
			 * Connection broke.  Keep the slab here.
			 */
			DSLAB_LOCK_EXCL(domid);
			IDN_DUNLOCK(domid);
			smr_slab_free(domid, sp);
			DSLAB_UNLOCK(domid);
			slab_offset = slab_size = 0;
			serrno = ECANCELED;
			IDN_DLOCK_SHARED(domid);
		}
		/*
		 * Send response.
		 * Note that smr_slab_alloc automatically installs
		 * slab into domains respective idn_domain entry
		 * to be associated with that domain.
		 */
		idn_send_slaballoc_resp(domid, mtp, slab_offset, slab_size,
		    serrno);
	}
}

static void
idn_send_slaballoc_resp(int domid, idn_msgtype_t *mtp, smr_offset_t slab_offset,
    uint_t slab_size, int serrno)
{
	procname_t	proc = "idn_send_slaballoc_resp";

	PR_PROTO("%s: slaballoc resp to domain %d (off=0x%x, size=0x%x) "
	    "[serrno = %d]\n",
	    proc, domid, slab_offset, slab_size, serrno);

	idn_send_cmdresp(domid, mtp, IDNCMD_SLABALLOC, slab_offset, slab_size,
	    serrno);
}

/*
 * Received the ack or nack to a previous allocation request
 * made by the local domain to the master for a slab.  Need
 * to "put" the response into the waiting area for any
 * waiters.
 */
static void
idn_recv_slaballoc_resp(int domid, smr_offset_t slab_offset, uint_t slab_size,
    int serrno)
{
	smr_slab_t		*sp = NULL;
	int			rv;
	procname_t		proc = "idn_recv_slaballoc_resp";


	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	PR_PROTO("%s: slaballoc resp from domain %d (off=0x%x, size=0x%x) "
	    "[serrno = %d]\n",
	    proc, domid, slab_offset, slab_size, serrno);

	if (!serrno) {
		IDN_GLOCK_SHARED();
		if (domid != IDN_GET_MASTERID()) {
			/*
			 * We should only be receiving responses from
			 * our master.  This is either a bogus message
			 * or an old response.  In either case dump it.
			 */
			PR_PROTO("%s: BOGUS slaballoc resp from domid %d "
			    "(master = %d)\n",
			    proc, domid, IDN_GET_MASTERID());
			serrno = EPROTO;
		}
		IDN_GUNLOCK();

		if (!serrno &&
		    !VALID_NWROFFSET(slab_offset, IDN_SMR_BUFSIZE)) {
			PR_PROTO("%s: slab offset (0x%x) out of range "
			    "(0-0x%lx)\n",
			    proc, slab_offset, MB2B(IDN_NWR_SIZE));
			serrno = EPROTO;
		} else if (!serrno) {
			sp = GETSTRUCT(smr_slab_t, 1);
			sp->sl_start = IDN_OFFSET2ADDR(slab_offset);
			sp->sl_end   = sp->sl_start + slab_size;
			smr_alloc_buflist(sp);
		}
	}

	/*
	 * Always "put" slabs back to yourself since you're a slave.
	 * Note that we set the forceflag so that even if there are
	 * no waiters we still install the slab for the domain.
	 */
	if (!serrno) {
		DSLAB_LOCK_EXCL(idn.localid);
	}
	rv = smr_slaballoc_put(idn.localid, sp, 1, serrno);
	if (!serrno) {
		DSLAB_UNLOCK(idn.localid);
	}

	if (rv < 0) {
		/*
		 * Some kind of error trying to install response.
		 * If there was a valid slab sent to us, we'll
		 * just have to send it back.
		 */
		PR_PROTO("%s: failed to install response in waiting area\n",
		    proc);
		if (slab_size != 0) {
			PR_PROTO("%s: sending slab back to domain %d "
			    "(master = %d)\n",
			    proc, domid, IDN_GET_MASTERID());
			idn_send_cmd(domid, IDNCMD_SLABFREE, slab_offset,
			    slab_size, 0);
		}
		if (sp) {
			smr_free_buflist(sp);
			FREESTRUCT(sp, smr_slab_t, 1);
		}
	}
}

/*
 * Note that slab reaping is effectively performed asynchronously
 * since the request will be received a protocol server.
 */
static void
idn_recv_slabreap_req(int domid, idn_msgtype_t *mtp, int nslabs)
{
	procname_t	proc = "idn_recv_slabreap_req";

	PR_PROTO("%s: slab reap request (nslabs = %d)\n", proc, nslabs);

	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	IDN_GLOCK_SHARED();
	if (domid != IDN_GET_MASTERID()) {
		/*
		 * Only the master can request that slabs be reaped.
		 */
		IDN_GUNLOCK();
		PR_PROTO("%s: only master can request slab reaping\n", proc);

		idn_send_cmdresp(domid, mtp, IDNCMD_SLABREAP, 0, 0, EACCES);

		return;
	}
	IDN_GUNLOCK();

	if (nslabs != 0) {
		IDN_DUNLOCK(domid);
		smr_slab_reap(idn.localid, &nslabs);
		IDN_DLOCK_SHARED(domid);
	}

	PR_PROTO("%s: slab reap result (nslabs = %d)\n", proc, nslabs);

	/*
	 * Go ahead and send the reap response back before we start
	 * free'ing off the individual slabs.
	 */
	idn_send_slabreap_resp(domid, mtp, nslabs, 0);
}

static void
idn_recv_slabreap_resp(int domid, int nslabs, int serrno)
{
	procname_t	proc = "idn_recv_slabreap_resp";

	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if ((idn.localid != IDN_GET_MASTERID()) || (idn.localid == domid)) {
		PR_PROTO("%s: unexpected slabreap resp received "
		    "(domid = %d)\n", proc, domid);
		ASSERT(0);
		return;
	}
	PR_PROTO("%s: recvd reap response from domain %d for %d slabs "
	    "[serrno = %d]\n", proc, domid, nslabs, serrno);
}

/*
 * Not really necessary to send slabreap response.
 * XXX - perhaps useful to master for accounting or
 *	 throttling of further reaping?
 */
static void
idn_send_slabreap_resp(int domid, idn_msgtype_t *mtp, int nslabs, int serrno)
{
	idn_send_cmdresp(domid, mtp, IDNCMD_SLABREAP, nslabs, 0, serrno);
}

/*
 * Slave -> Master ONLY
 * Master never sends slabfree request to itself.
 */
static void
idn_recv_slabfree_req(int domid, idn_msgtype_t *mtp, smr_offset_t slab_offset,
    uint_t slab_size)
{
	smr_slab_t	*sp;
	int		serrno;
	caddr_t		s_start, s_end;
	procname_t	proc = "idn_recv_slabfree_req";

	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (domid == IDN_GET_MASTERID()) {
		PR_PROTO("%s: unexpected slabfree req received (domid = %d)\n",
		    proc, domid);
		idn_send_slabfree_resp(domid, mtp, slab_offset, slab_size,
		    EACCES);
		return;
	}
	if (slab_size > IDN_SLAB_SIZE) {
		PR_PROTO("%s: unexpected slab size. exp %d, recvd %d\n",
		    proc, IDN_SLAB_SIZE, slab_size);
		idn_send_slabfree_resp(domid, mtp, slab_offset, slab_size,
		    EINVAL);
		return;
	}
	s_start = IDN_OFFSET2ADDR(slab_offset);
	s_end   = s_start + slab_size;
	/*
	 * Master has received a SLABFREE request (effectively a response
	 * to some earlier SLABREAP request.
	 * Find the slab associated with this slab and free it up.
	 */
	DSLAB_LOCK_EXCL(domid);
	if ((sp = smr_slaballoc_get(domid, s_start, s_end)) != NULL) {
		smr_slab_free(domid, sp);
		serrno = 0;
	} else {
		serrno = EINVAL;
	}
	DSLAB_UNLOCK(domid);

	idn_send_slabfree_resp(domid, mtp, slab_offset, slab_size, serrno);
}

/*
 * Master -> Slave ONLY
 */
static void
idn_recv_slabfree_resp(int domid, uint_t slab_offset, uint_t slab_size, int
    serrno)
{
	procname_t	proc = "idn_recv_slabfree_resp";

	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (domid != IDN_GET_MASTERID()) {
		PR_PROTO("%s: unexpected slabfree resp received (domid = %d)\n",
		    proc, domid);
		ASSERT(0);
		return;
	}
	if (slab_size > IDN_SLAB_SIZE) {
		PR_PROTO("%s: unexpected slab size. exp %d, recvd %d\n",
		    proc, IDN_SLAB_SIZE, slab_size);
		ASSERT(0);
		return;
	}
	PR_PROTO("%s: recvd free resp from dom %d "
	    "- slab (off/size) 0x%x/0x%x [serrno = %d]\n",
	    proc, domid, slab_offset, slab_size, serrno);
}

static void
idn_send_slabfree_resp(int domid, idn_msgtype_t *mtp, uint_t slab_offset,
    uint_t slab_size, int serrno)
{
	idn_send_cmdresp(domid, mtp, IDNCMD_SLABFREE, slab_offset, slab_size,
	    serrno);
}

static void
idn_retry_nodename_req(void *arg)
{
	int	domid = (int)(uintptr_t)arg;

	idn_send_nodename_req(domid);
}

static void
idn_send_nodename_req(int domid)
{
	caddr_t		b_bufp;
	smr_offset_t	bufoffset;
	int		serrno;
	idn_domain_t	*dp = &idn_domain[domid];
	procname_t	proc = "idn_send_nodename_req";

	/*
	 * Need to drop domain lock across
	 * SMR allocation.
	 */
	serrno = smr_buf_alloc(domid, MAXDNAME+1, &b_bufp);

	IDN_DLOCK_SHARED(domid);
	if (dp->dstate != IDNDS_CONNECTED) {
		/*
		 * Lost connection.
		 */
		PR_PROTO("%s:%d: connection lost [dstate = %s]\n",
		    proc, domid, idnds_str[dp->dstate]);
		IDN_DUNLOCK(domid);
		if (!serrno)
			(void) smr_buf_free(domid, b_bufp, MAXDNAME+1);
		return;
	}
	if (serrno) {
		/*
		 * Failed to allocate buffer, but still have
		 * connection so keep trying.  We may have queried
		 * the master a little too earlier.
		 */
		PR_PROTO("%s:%d: buffer alloc failed [dstate = %s]\n",
		    proc, domid, idnds_str[dp->dstate]);
		(void) timeout(idn_retry_nodename_req, (void *)(uintptr_t)domid,
		    hz);
		IDN_DUNLOCK(domid);
		return;
	}

	*b_bufp = (char)MAXDNAME;
	bufoffset = IDN_ADDR2OFFSET(b_bufp);

	idn_send_cmd(domid, IDNCMD_NODENAME, bufoffset, 0, 0);
	IDN_DUNLOCK(domid);
}

static void
idn_send_nodename_resp(int domid, idn_msgtype_t *mtp, smr_offset_t bufoffset,
    int serrno)
{
	idn_send_cmdresp(domid, mtp, IDNCMD_NODENAME, (uint_t)bufoffset, 0,
	    serrno);
}

static void
idn_recv_nodename_req(int domid, idn_msgtype_t *mtp, smr_offset_t bufoffset)
{
	caddr_t		b_bufp;
	int		length;
	idn_domain_t	*ldp = &idn_domain[idn.localid];
	procname_t	proc = "idn_recv_nodename_req";

	IDN_DLOCK_EXCL(idn.localid);
	if (!strlen(ldp->dname)) {
		if (!strlen(utsname.nodename)) {
			/*
			 * Local domain's nodename hasn't been
			 * set yet.
			 */
			IDN_DUNLOCK(idn.localid);
			idn_send_cmd_nackresp(domid, mtp, IDNCMD_NODENAME,
			    IDNNACK_RETRY);
			return;
		}
		(void) strncpy(ldp->dname, utsname.nodename, MAXDNAME - 1);
	}
	IDN_DLOCK_DOWNGRADE(idn.localid);

	if (!VALID_NWROFFSET(bufoffset, IDN_SMR_BUFSIZE)) {
		PR_PROTO("%s:%d: invalid SMR offset received (0x%x)\n",
		    proc, domid, bufoffset);
		IDN_DUNLOCK(idn.localid);
		idn_send_nodename_resp(domid, mtp, bufoffset, EINVAL);
		return;
	}

	b_bufp = IDN_OFFSET2ADDR(bufoffset);
	length = (int)(*b_bufp++ & 0xff);

	if (length < strlen(ldp->dname)) {
		PR_PROTO("%s:%d: buffer not big enough (req %lu, got %d)\n",
		    proc, domid, strlen(ldp->dname), length);
		IDN_DUNLOCK(idn.localid);
		idn_send_nodename_resp(domid, mtp, bufoffset, EINVAL);
		return;
	}

	(void) strncpy(b_bufp, ldp->dname, MAXDNAME);
	b_bufp[MAXDNAME-1] = 0;
	IDN_DUNLOCK(idn.localid);

	idn_send_nodename_resp(domid, mtp, bufoffset, 0);
}

static void
idn_recv_nodename_resp(int domid, smr_offset_t bufoffset, int serrno)
{
	caddr_t		b_bufp;
	idn_domain_t	*dp = &idn_domain[domid];
	procname_t	proc = "idn_recv_nodename_resp";

	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (!VALID_NWROFFSET(bufoffset, IDN_SMR_BUFSIZE)) {
		PR_PROTO("%s:%d: invalid SMR offset received (0x%x)\n",
		    proc, domid, bufoffset);
		return;
	}

	if (serrno == 0) {
		b_bufp = IDN_OFFSET2ADDR(bufoffset) + 1;
		b_bufp[MAXDNAME-1] = 0;

		if (strlen(b_bufp) > 0) {
			(void) strncpy(dp->dname, b_bufp, MAXDNAME);
			PR_PROTO("%s:%d: received nodename(%s)\n",
			    proc, domid, dp->dname);
		}
	}

	(void) smr_buf_free(domid, b_bufp - 1, MAXDNAME + 1);
}

/*
 * The master allocations the SMR management structures.
 */
static int
idn_master_init()
{
	idn_domain_t	*ldp = &idn_domain[idn.localid];
	size_t		reserved_size = 0;
	caddr_t		reserved_area = NULL;
	procname_t	proc = "idn_master_init";

	ASSERT(IDN_GLOCK_IS_EXCL());
	ASSERT(IDN_DLOCK_IS_EXCL(idn.localid));

	if (idn.mboxarea != NULL) {
		PR_PROTO("%s: master data already initialized\n", proc);
		return (0);
	}

	PR_PROTO("%s: initializing master data (domid = %d)\n",
	    proc, idn.localid);

	/*
	 * Reserve an area of the SMR for mailbox usage.
	 * This area is allocated to other domains via
	 * the master.  Round it up to IDN_SMR_BUFSIZE multiple.
	 */
	reserved_size = IDNROUNDUP(IDN_MBOXAREA_SIZE, IDN_SMR_BUFSIZE);

	PR_PROTO("%s: reserving %lu bytes for mailbox area\n",
	    proc, reserved_size);

#ifdef DEBUG
	if (reserved_size > (size_t)IDN_SLAB_SIZE) {
		PR_PROTO("%s: WARNING mbox area (%ld) > slab size (%d)\n",
		    proc, reserved_size, IDN_SLAB_SIZE);
	}
#endif /* DEBUG */
	/*
	 * Initialize the pool of slabs and SMR I/O buffers.
	 */
	if (smr_slabpool_init(reserved_size, &reserved_area) != 0) {
		idn_master_deinit();
		return (-1);
	}

	ASSERT(idn.mboxarea == NULL);
	ASSERT(reserved_area);

	bzero(reserved_area, reserved_size);

	idn.mboxarea = (idn_mboxtbl_t *)reserved_area;
	ldp->dmbox.m_tbl = IDN_MBOXAREA_BASE(idn.mboxarea, idn.localid);
	/*
	 * Initialize the SMR pointers in the entire
	 * mailbox table.
	 */
	idn_mboxarea_init(idn.mboxarea, IDN_MBOXAREA_SIZE / IDN_MBOXTBL_SIZE);

	return (0);
}

static void
idn_master_deinit()
{
	idn_domain_t	*ldp;
	smr_slab_t	*sp;
	procname_t	proc = "idn_master_deinit";

	ASSERT(IDN_GLOCK_IS_EXCL());
	ASSERT(IDN_DLOCK_IS_EXCL(idn.localid));

	if (idn.mboxarea == NULL) {
		PR_PROTO("%s: master data already deinitialized\n", proc);
		return;
	}

	ldp = &idn_domain[idn.localid];

	PR_PROTO("%s: deinitializing master data (domid = %d)\n",
	    proc, idn.localid);

	ldp->dmbox.m_tbl = NULL;
	idn.mboxarea = NULL;
	/*
	 * Master may still be holding onto slabs of his own.
	 */
	DSLAB_LOCK_EXCL(idn.localid);
	sp = ldp->dslab;
	ldp->dslab = NULL;
	ldp->dnslabs = 0;
	if (sp)
		smr_slab_free(idn.localid, sp);
	ldp->dslab_state = DSLAB_STATE_UNKNOWN;
	DSLAB_UNLOCK(idn.localid);

	smr_slabpool_deinit();
}

static int
idn_mark_awol(int domid, clock_t *atime)
{
	clock_t		awol;
	idn_domain_t	*dp = &idn_domain[domid];

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_GLOCK_IS_EXCL());

	if (!DOMAIN_IN_SET(idn.domset.ds_awol, domid)) {
		DOMAINSET_ADD(idn.domset.ds_awol, domid);
		idn.nawols++;
	}
	awol = ddi_get_lbolt();
	if (dp->dawol.a_count++ == 0)
		dp->dawol.a_time = awol;
	dp->dawol.a_last = awol;
	if ((awol - dp->dawol.a_msg) >= (clock_t)(idn_awolmsg_interval * hz))
		dp->dawol.a_msg = awol;
	else
		awol = 0;

	*atime = awol;

	idn_awol_event_set(dp->dhw.dh_boardset);

	return (dp->dawol.a_count);
}

void
idn_clear_awol(int domid)
{
	idn_domain_t	*dp = &idn_domain[domid];

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_GLOCK_IS_EXCL());
	if (DOMAIN_IN_SET(idn.domset.ds_awol, domid)) {
		DOMAINSET_DEL(idn.domset.ds_awol, domid);
		idn.nawols--;
	}
	if (dp->dawol.a_count > 0) {
		dp->dawol.a_count = 0;
		dp->dawol.a_last = dp->dawol.a_time;
		dp->dawol.a_time = 0;
		dp->dawol.a_msg = 0;

		idn_awol_event_clear(dp->dhw.dh_boardset);
	}
}

/*
 * A timer expired.
 */
void
idn_timer_expired(void *arg)
{
	idn_domain_t	*dp;
	char		*op = "UNKNOWN";
	clock_t		awol = 0;
	int		awolcount, dcpu, domid;
	idn_timer_t	*tp = (idn_timer_t *)arg;
	idn_timerq_t	*tq = NULL;
	uint_t		token;
	char		dname[MAXDNAME];
	procname_t	proc = "idn_timer_expired";
	STRING(str);

	tq = tp->t_q;

	ASSERT(tp->t_domid != IDN_NIL_DOMID);

	IDN_TIMERQ_LOCK(tq);

	INUM2STR(tp->t_type, str);

	if (tp->t_onq == 0) {
		PR_TIMER("%s: timer CAUGHT TERMINATION (type = %s)\n",
		    proc, str);
		/*
		 * Timer was dequeued.  Somebody is trying
		 * to shut it down.
		 */
		IDN_TIMERQ_UNLOCK(tq);
		return;
	}

	IDN_TIMER_DEQUEUE(tq, tp);

	IDN_TIMERQ_UNLOCK(tq);

	IDN_SYNC_LOCK();
	IDN_DLOCK_EXCL(tp->t_domid);

	domid = tp->t_domid;

	dp = &idn_domain[domid];
	(void) strcpy(dname, dp->dname);
	dcpu = dp->dcpu;

	IDN_TIMER_EXEC(tp);

#ifdef DEBUG
	PR_TIMER("%s:%d: [%s] timer EXPIRED (C=0x%x, P=0x%llx, X=0x%llx)\n",
	    proc, tp->t_domid, str, tp->t_cookie,
	    tp->t_posttime, tp->t_exectime);
#endif /* DEBUG */

	/*
	 * IMPORTANT:
	 * Each case is responsible for dropping SYNC_LOCK & DLOCK.
	 */
	switch (tp->t_type) {
	case IDNP_DATA:
		IDN_SYNC_UNLOCK();
		/*
		 * Timed out waiting for a data packet response.
		 * We can't close domain since he may just be
		 * temporarily AWOL.
		 * Note that dio and diocheck do not get cleared.
		 * This is taken care of when the domain restarts
		 * or is fatally closed.
		 * We only need a reader lock for this.
		 */
		IDN_DLOCK_DOWNGRADE(domid);
		if (dp->diocheck && dp->dmbox.m_send) {
			(void) idn_reclaim_mboxdata(domid, 0, -1);
			if (dp->dio >= IDN_WINDOW_EMAX) {
				idn_msgtype_t	mt;
				/*
				 * Restart timer for another
				 * go around.
				 */
				IDN_MSGTIMER_START(domid, IDNP_DATA, 0,
				    idn_msg_waittime[IDNP_DATA],
				    &mt.mt_cookie);
			} else {
				lock_clear(&dp->diocheck);
			}
		}
		IDN_DUNLOCK(domid);
		break;

	case IDNP_NEGO:
		/*
		 * If we're not in a NEGO transition, then
		 * just ignore this timeout.
		 */
		if (dp->dxp == &xphase_nego) {
			uint_t		token;

			IDN_GLOCK_EXCL();
			op = "CONNECT";
			awolcount = idn_mark_awol(domid, &awol);
			IDN_GUNLOCK();

			idn_nego_cleanup_check(domid, IDN_NIL_DOMID,
			    IDN_NIL_DCPU);

			IDN_XSTATE_TRANSITION(dp, IDNXS_PEND);
			token = IDN_RETRY_TOKEN(domid, IDNRETRY_NEGO);
			idn_retry_submit(idn_retry_nego, NULL, token,
			    idn_msg_retrytime[(int)IDNRETRY_NEGO]);
		}
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		break;

	case IDNP_CMD:
		/*
		 * Timeouts on commands typically mean that the
		 * the master is not responding.  Furthermore, we
		 * can't FORCE a FIN disconnect since at this stage
		 * we are CONNECTED and thus other domains may
		 * have cache entries that we're sharing with them.
		 * Only choice is to completely disconnect from
		 * IDN and try to reestablish connection.
		 *
		 * However, timeouts attempting to get nodename
		 * are not fatal.  Although we don't want to retry
		 * either since each timeout is a lost buffer to
		 * the remote domain.
		 */
		if (tp->t_subtype == (ushort_t)IDNCMD_NODENAME) {
			PR_PROTO("%s:%d: timedout waiting for nodename\n",
			    proc, domid);
			IDN_DUNLOCK(domid);
			IDN_SYNC_UNLOCK();
			break;
		}

		IDN_GLOCK_EXCL();
		if (idn.state == IDNGS_ONLINE) {
			domainset_t	domset;
			int		masterid = IDN_GET_MASTERID();

			IDN_GKSTAT_GLOBAL_EVENT(gk_reconfigs,
			    gk_reconfig_last);

			PR_PROTO("%s:%d: RECONFIG trying old masterid = %d\n",
			    proc, domid, masterid);

			IDN_GSTATE_TRANSITION(IDNGS_RECONFIG);
			IDN_SET_NEW_MASTERID(masterid);
			IDN_GUNLOCK();
			IDN_DUNLOCK(domid);

			domset = idn.domset.ds_trans_on |
			    idn.domset.ds_connected;

			idn_unlink_domainset(domset, IDNFIN_NORMAL,
			    IDNFIN_ARG_NONE, IDNFIN_OPT_RELINK,	BOARDSET_ALL);
		} else {
			IDN_GUNLOCK();
			IDN_DUNLOCK(domid);
		}
		IDN_SYNC_UNLOCK();
		break;

	case IDNP_CON:
		if (tp->t_subtype == (ushort_t)IDNCON_QUERY) {
			/*
			 * Timed out sending a CON-query.  This is
			 * non-fatal.  We simply need to retry.
			 */
			IDN_GLOCK_EXCL();
			op = "CONNECT";
			awolcount = idn_mark_awol(domid, &awol);
			IDN_GUNLOCK();
			token = IDN_RETRY_TOKEN(domid, IDNRETRY_CONQ);
			idn_retry_submit(idn_retry_query, NULL, token,
			    idn_msg_retrytime[(int)IDNRETRY_CONQ]);
			IDN_DUNLOCK(domid);
			IDN_SYNC_UNLOCK();
			break;
		}
		/*FALLTHROUGH*/
	case IDNP_CFG:
		/*
		 * Any timeouts here we simply try to disconnect
		 * and reestablish the link.  Since we haven't
		 * reached the connected state w.r.t. this domain
		 * we put his fin state to FORCE-HARD in order
		 * to shoot right through without involving other
		 * domains.  Recall that other domains may have
		 * established connections with the given domain
		 * which means any FIN queries to them will always
		 * return connected to the given domain.  Since
		 * neither the given domain nor the local domain
		 * plan on disconnecting from the IDN the connection
		 * to the other domains will remain thereby preventing
		 * the local FIN from ever completing.  Recall that
		 * a FIN depends on all member domains FIN'ing also.
		 */
		IDN_GLOCK_EXCL();
		op = "CONNECT";
		awolcount = idn_mark_awol(domid, &awol);
		IDN_GUNLOCK();
		DOMAINSET_ADD(idn.domset.ds_relink, domid);
		IDN_HISTORY_LOG(IDNH_RELINK, domid, dp->dstate,
		    idn.domset.ds_relink);
		(void) idn_disconnect(domid, IDNFIN_FORCE_SOFT,
		    IDNFIN_ARG_NONE, IDNFIN_SYNC_NO);
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		break;

	case IDNP_FIN:
		/*
		 * Timeouts here simply try to retry.
		 */
		IDN_GLOCK_EXCL();
		op = "DISCONNECT";
		awolcount = idn_mark_awol(domid, &awol);
		IDN_GUNLOCK();
		if (tp->t_subtype == (ushort_t)IDNFIN_QUERY) {
			int		d;
			domainset_t	rdyset;
			/*
			 * Timed out sending a FIN-query.  This is
			 * non-fatal.  We simply need to retry.
			 * If we were doing a forced unlink of any
			 * domains, we don't want this awol guy
			 * to hold us up.  Looks for any forced
			 * unlinks and make them "ready" with
			 * respect to this awol domain.
			 */
			rdyset = 0;
			for (d = 0; d < MAX_DOMAINS; d++) {
				if (FIN_IS_FORCE(idn_domain[d].dfin)) {
					DOMAINSET_ADD(rdyset, d);
				}
			}
			if (rdyset)
				(void) idn_sync_register(domid,
				    IDNSYNC_DISCONNECT,
				    rdyset, IDNSYNC_REG_REG);

			token = IDN_RETRY_TOKEN(domid, IDNRETRY_FINQ);
			idn_retry_submit(idn_retry_query, NULL, token,
			    idn_msg_retrytime[(int)IDNRETRY_FINQ]);
			IDN_DUNLOCK(domid);
			IDN_SYNC_UNLOCK();
			break;
		}

		if (dp->dfin == IDNFIN_FORCE_SOFT) {
			IDN_FSTATE_TRANSITION(dp, IDNFIN_FORCE_HARD);
		}
		/*
		 * Anybody that was waiting on this domain and
		 * had a hard-force in action gets this guy for
		 * free in their base ready-set.
		 */
		idn_sync_register_awol(domid);

		dp->dxp = &xphase_fin;
		IDN_XSTATE_TRANSITION(dp, IDNXS_PEND);
		token = IDN_RETRY_TOKEN(domid, IDNRETRY_FIN);
		idn_retry_submit(idn_retry_fin, NULL, token,
		    idn_msg_retrytime[(int)IDNRETRY_FIN]);
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		break;

	default:

		ASSERT(0);
		IDN_DUNLOCK(domid);
		IDN_SYNC_UNLOCK();
		break;
	}

	IDN_TIMER_FREE(tp);

	if (awol) {
		if (strlen(dname) > 0) {
			cmn_err(CE_WARN,
			    "IDN: 236: domain (%s) [ID %d] not "
			    "responding to %s [#%d]",
			    dname, domid, op, awolcount);
		} else {
			cmn_err(CE_WARN,
			    "IDN: 236: domain [ID %d, CPU %d] not "
			    "responding to %s [#%d]",
			    domid, dcpu, op, awolcount);
		}
	}
}

#if 0
static int
idn_retry_check(uint_t token)
{
	int			i, count = 0;
	int			domid = IDN_RETRY_TOKEN2DOMID(token);
	int			key = IDN_RETRY_TOKEN2TYPE(token);
	idn_retry_job_t		*rp;
	idn_retry_queue_t	*qp;

	qp = &idn.retryqueue;

	mutex_enter(&qp->rq_mutex);

	for (i = 0, rp = qp->rq_jobs; i < qp->rq_count; i++, rp = rp->rj_next)
		if ((domid == IDN_RETRY_TOKEN2DOMID(rp->rj_token)) &&
		    ((key == IDN_RETRY_TYPEALL) || (rp->rj_token == token)))
			count++;

	mutex_exit(&qp->rq_mutex);

	return (count);
}
#endif /* 0 */

static void
idn_retry_execute(void *arg)
{
	idn_retry_job_t		*rp = (idn_retry_job_t *)arg;
	idn_retry_queue_t	*qp;

	qp = &idn.retryqueue;

	mutex_enter(&qp->rq_mutex);
	if (rp->rj_onq == 0) {
		/*
		 * Job has already been claimed by
		 * retry termination routine.
		 * Bail out.
		 */
		mutex_exit(&qp->rq_mutex);
		return;
	}
	rp->rj_next->rj_prev = rp->rj_prev;
	rp->rj_prev->rj_next = rp->rj_next;
	if (--(qp->rq_count) == 0)
		qp->rq_jobs = NULL;
	else if (qp->rq_jobs == rp)
		qp->rq_jobs = rp->rj_next;
	mutex_exit(&qp->rq_mutex);

	(*rp->rj_func)(rp->rj_token, rp->rj_arg);

	IDNRETRY_FREEJOB(rp);
}

/*
 *
 */
static void
idn_retry_submit(void (*func)(uint_t token, void *arg), void *arg, uint_t token,
    clock_t ticks)
{
	idn_retry_job_t		*rp, *cp;
	idn_retry_queue_t	*qp;
	int			c;
	procname_t		proc = "idn_retry_submit";

	if (ticks < 0) {
		PR_PROTO("%s: (token = 0x%x) WARNING ticks = %ld\n",
		    proc, token, ticks);
		return;
	}
	if (ticks == 0)		/* At least one tick to get into background */
		ticks++;

	PR_PROTO("%s: token = 0x%x\n", proc, token);

	qp = &idn.retryqueue;

	mutex_enter(&qp->rq_mutex);
	for (c = 0, cp = qp->rq_jobs; c < qp->rq_count; cp = cp->rj_next, c++) {
		if (cp->rj_token == token) {
			PR_PROTO("%s: token = (%d,0x%x) already present\n",
			    proc, IDN_RETRY_TOKEN2DOMID(token),
			    IDN_RETRY_TOKEN2TYPE(token));
			break;
		}
	}

	if (c < qp->rq_count) {
		mutex_exit(&qp->rq_mutex);
		return;
	}

	rp = IDNRETRY_ALLOCJOB();
	rp->rj_func = func;
	rp->rj_arg = arg;
	rp->rj_token = token;
	rp->rj_prev = rp->rj_next = rp;

	if (qp->rq_jobs == NULL) {
		qp->rq_jobs = rp;
	} else {
		rp->rj_next = qp->rq_jobs;
		rp->rj_prev = qp->rq_jobs->rj_prev;
		rp->rj_next->rj_prev = rp;
		rp->rj_prev->rj_next = rp;
	}
	rp->rj_onq = 1;
	qp->rq_count++;
	rp->rj_id = timeout(idn_retry_execute, (caddr_t)rp, ticks);
	mutex_exit(&qp->rq_mutex);
}

int
idn_retry_terminate(uint_t token)
{
	int			i, domid;
	uint_t			key, count;
	idn_retry_job_t		*rp, *nrp, *fp;
	idn_retry_queue_t	*qp;
	procname_t		proc = "idn_retry_terminate";

	key = IDN_RETRY_TOKEN2TYPE(token);
	domid = IDN_RETRY_TOKEN2DOMID(token);
	fp = NULL;
	qp = &idn.retryqueue;

	mutex_enter(&qp->rq_mutex);
	for (i = count = 0, rp = qp->rq_jobs; i < qp->rq_count; i++) {
		nrp = rp->rj_next;
		if ((domid == IDN_RETRY_TOKEN2DOMID(rp->rj_token)) &&
		    ((key == IDN_RETRY_TYPEALL) ||
		    (rp->rj_token == token))) {
			/*
			 * Turn off onq field as a signal to
			 * the execution routine that this
			 * retry has been terminated.  This
			 * is necessary since we can't untimeout
			 * while holding the rq_mutex otherwise
			 * we'll deadlock with the execution
			 * routine.  We'll untimeout these guys
			 * _after_ we drop rq_mutex.
			 */
			rp->rj_onq = 0;
			rp->rj_next->rj_prev = rp->rj_prev;
			rp->rj_prev->rj_next = rp->rj_next;
			if (qp->rq_jobs == rp)
				qp->rq_jobs = rp->rj_next;
			rp->rj_next = fp;
			fp = rp;
			count++;
		}
		rp = nrp;
	}

	if ((qp->rq_count -= count) == 0)
		qp->rq_jobs = NULL;

	mutex_exit(&qp->rq_mutex);

	PR_PROTO("%s: token = (%d,0x%x), dequeued = %d\n",
	    proc, domid, key, count);

	for (; fp; fp = nrp) {
		(void) untimeout(fp->rj_id);

		nrp = fp->rj_next;
		IDNRETRY_FREEJOB(fp);
	}

	return (count);
}

/*
 * -----------------------------------------------------------------------
 * The sole purpose of the idn_protocol_server is to manage the IDN
 * protocols between the various domains.  These messages do _not_ go
 * through the regular streams queues since they are not dependent on
 * any user process or module necessarily having the IDN driver open.
 * There may be multiple instances of these servers to enhance performance
 * of domain management.  Each server is assigned a idn_protoqueue_t
 * from which to obtain the work they need to do.
 * -----------------------------------------------------------------------
 */
int
idn_protocol_init(int nservers)
{
	int		i;
	idn_protojob_t	*jp;
	register idn_protoqueue_t	*protoq;

	if (nservers <= 0) {
		cmn_err(CE_WARN,
		    "IDN: 237: invalid number (%d) of protocol servers",
		    nservers);
		return (-1);
	}

	idn.protocol.p_jobpool = kmem_cache_create("idn_protocol_jobcache",
	    sizeof (idn_protojob_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	if (idn.protocol.p_jobpool == NULL) {
		cmn_err(CE_WARN,
		    "IDN: 238: kmem_cache_create(jobcache) failed");
		return (-1);
	}

	/*
	 * Initialize static cache for protojob.
	 */
	mutex_init(&idn_protojob_cache_lock, NULL, MUTEX_DRIVER, NULL);
	jp = &idn_protojob_cache[0];
	for (i = 1; i < IDN_DMV_PENDING_MAX; jp = jp->j_next, i++) {
		jp->j_cache = 1;
		jp->j_next = &idn_protojob_cache[i];
	}
	jp->j_cache = 1;
	jp->j_next = NULL;
	idn_protojob_cache_list = &idn_protojob_cache[0];

	/*
	 * Init morgue semaphore.
	 */
	sema_init(&idn.protocol.p_morgue, 0, NULL, SEMA_DEFAULT, NULL);
	/*
	 * Alloc server queues.
	 */
	idn.protocol.p_serverq = GETSTRUCT(idn_protoqueue_t, nservers);

	/*
	 * Init server queues.
	 */
	protoq = idn.protocol.p_serverq;
	for (i = 0; i < nservers; protoq++, i++) {
		mutex_init(&protoq->q_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&protoq->q_cv, NULL, CV_DEFAULT, NULL);
		protoq->q_id	  = i;
		protoq->q_joblist = NULL;
		protoq->q_joblist_tail = NULL;
		protoq->q_die	  = 0;
		protoq->q_morgue  = &idn.protocol.p_morgue;
		/*
		 * Create protocol server thread.
		 */
		protoq->q_threadp = thread_create(NULL, 0,
		    idn_protocol_server, (caddr_t)&i, sizeof (i), &p0,
		    TS_RUN, maxclsyspri);
	}
	/*
	 * The servers are kept in the p_server[] array, however
	 * we'll build a linked list of them to facilitate debugging.
	 */
	protoq = idn.protocol.p_serverq;
	for (i = 0; i < (nservers - 1); protoq++, i++)
		protoq->q_next = (protoq + 1);
	protoq->q_next = NULL;

	idn.nservers = nservers;

	return (idn.nservers);
}

void
idn_protocol_deinit()
{
	register int	i;
	int		nservers;
	register idn_protoqueue_t	*protoq;

	nservers = idn.nservers;

	if (nservers <= 0)
		return;

	/*
	 * Make sure the servers are dead.
	 */
	idn_protocol_server_killall();
	ASSERT(idn.nservers == 0);
	/*
	 * Destroy the mutexes.
	 */
	protoq = idn.protocol.p_serverq;
	for (i = 0; i < nservers; protoq++, i++) {
		mutex_destroy(&protoq->q_mutex);
		cv_destroy(&protoq->q_cv);
	}
	/*
	 * Free up the protoqueue memory.
	 */
	FREESTRUCT(idn.protocol.p_serverq, idn_protoqueue_t, nservers);
	idn.protocol.p_serverq = NULL;
	/*
	 * Destroy the morgue semaphore.
	 */
	sema_destroy(&idn.protocol.p_morgue);

	if (idn.protocol.p_jobpool) {
		kmem_cache_destroy(idn.protocol.p_jobpool);
		idn.protocol.p_jobpool = NULL;
	}
}

static void
idn_protocol_server(int *id)
{
	idn_protoqueue_t	*pq;
	idn_protojob_t		*jl;
	register idn_protojob_t	*jp;
	procname_t		proc = "idn_protocol_server";

	if (id == NULL) {
		PR_PROTO("%s: id == NULL, thread exiting\n", proc);
		return;
	}
	ASSERT((*id >= 0) && (*id < idn_protocol_nservers));

	pq = &idn.protocol.p_serverq[*id];

	ASSERT(pq->q_id == *id);

	PR_PROTO("%s: id %d starting up (pq = 0x%p)\n",
	    proc, pq->q_id, (void *)pq);

	/*CONSTCOND*/
	while (1) {
		mutex_enter(&pq->q_mutex);

		while (((jl = pq->q_joblist) == NULL) && !pq->q_die)
			cv_wait(&pq->q_cv, &pq->q_mutex);

		pq->q_joblist = pq->q_joblist_tail = NULL;

		if (pq->q_die) {
			/*
			 * We've been killed.  Need to check-in
			 * at the morgue.
			 */
			pq->q_threadp = NULL;
			mutex_exit(&pq->q_mutex);
			PR_PROTO("%s: thread (%d) killed...bye bye\n",
			    proc, pq->q_id);
			for (jp = jl; jp; jp = jl) {
				jl = jp->j_next;
				idn_protojob_free(jp);
			}
			sema_v(pq->q_morgue);
			thread_exit();
			/*NOTREACHED*/
		}
		mutex_exit(&pq->q_mutex);

		/*
		 * We can process the jobs asynchronously while more are
		 * put on.
		 */
		for (jp = jl; jp; jp = jl) {
			jl = jp->j_next;
			idn_recv_proto(&(jp->j_msg));
			idn_protojob_free(jp);
		}
	}
}

/*
 * Kill off all the protocol servers.
 */
static void
idn_protocol_server_killall()
{
	register idn_protoqueue_t	*pq;
	int		i;
	procname_t	proc = "idn_protocol_server_killall";

	PR_PROTO("%s: killing off %d protocol servers\n",
	    proc, idn.nservers);

	pq = idn.protocol.p_serverq;
	for (i = 0; i < idn.nservers; pq++, i++) {
		mutex_enter(&pq->q_mutex);
		pq->q_die = 1;
		cv_signal(&pq->q_cv);
		mutex_exit(&pq->q_mutex);
	}

	while (idn.nservers > 0) {
		sema_p(&idn.protocol.p_morgue);
		idn.nservers--;
	}
}

idn_protojob_t *
idn_protojob_alloc(int kmflag)
{
	idn_protojob_t	*jp;

	jp = kmem_cache_alloc(idn.protocol.p_jobpool, kmflag);
	if (jp == NULL) {
		mutex_enter(&idn_protojob_cache_lock);
		if ((jp = idn_protojob_cache_list) != NULL)
			idn_protojob_cache_list = jp->j_next;
		mutex_exit(&idn_protojob_cache_lock);
	} else {
		jp->j_cache = 0;
	}

	return (jp);
}

static void
idn_protojob_free(idn_protojob_t *jp)
{
	ASSERT(jp);

	if (jp->j_cache) {
		mutex_enter(&idn_protojob_cache_lock);
		jp->j_next = idn_protojob_cache_list;
		idn_protojob_cache_list = jp;
		mutex_exit(&idn_protojob_cache_lock);
	} else {
		kmem_cache_free(idn.protocol.p_jobpool, (void *)jp);
	}
}

void
idn_protojob_submit(int cookie, idn_protojob_t *jp)
{
	idn_protoqueue_t	*pq;
	int			serverid;
	procname_t		proc = "idn_protojob_submit";
	STRING(str);

	if (jp == NULL)
		return;

	serverid = IDN_PROTOCOL_SERVER_HASH(cookie);

	pq = &idn.protocol.p_serverq[serverid];

	INUM2STR(jp->j_msg.m_msgtype, str);
	PR_PROTO("%s: job (d=%d, m=0x%x, %s) submitted to "
	    "protocol server %d\n", proc, jp->j_msg.m_domid,
	    jp->j_msg.m_msgtype, str, serverid);

	mutex_enter(&pq->q_mutex);
	/*
	 * Can't submit jobs to dying servers.
	 */
	if (!pq->q_die) {
		if (pq->q_joblist_tail) {
			pq->q_joblist_tail->j_next = jp;
			pq->q_joblist_tail = jp;
		} else {
			pq->q_joblist = pq->q_joblist_tail = jp;
		}
		jp->j_next = NULL;
		cv_signal(&pq->q_cv);
	} else {
		PR_PROTO("%s: protocol server dead.  freeing protojob\n",
		    proc);
		idn_protojob_free(jp);
	}
	mutex_exit(&pq->q_mutex);
}

static void
idn_mboxarea_init(idn_mboxtbl_t *mtp, register int ntbls)
{
	register int	d;
	caddr_t		state_ptr = NULL, mtbasep = (caddr_t)mtp;
	idn_mboxtbl_t	*amtp;
	procname_t	proc = "idn_mboxarea_init";

	ASSERT(mtp && (ntbls > 0));

	PR_PROTO("%s: init mboxtbl (0x%p) ntbls = %d\n",
	    proc, (void *)mtp, ntbls);

	for (d = 0; d < ntbls; d++) {
		register int	pd, sd;
		register int	ch;

		mtp->mt_header.mh_svr_active = 0;
		mtp->mt_header.mh_svr_ready = 0;
		/*
		 * Initialize the header of each mbox table
		 * with a cookie for identity.
		 */
		/*
		 * Format: 0xc0c0DSCC
		 *	 D = primary domain
		 *	 S = sub-domain of primary
		 *	CC = channel of sub-domain.
		 */
		pd = (d / MAX_DOMAINS) / IDN_MAX_NETS;
		sd = (d / IDN_MAX_NETS) % MAX_DOMAINS;
		ch = d % IDN_MAX_NETS;

		/*
		 * We point all sub-domains in the same channel
		 * to the same active sync flag since a single server
		 * services all domains in the same channel.
		 */
		amtp = IDN_MBOXTBL_ABS_PTR(mtbasep, pd, 0, ch);

		state_ptr = (caddr_t)&amtp->mt_header.mh_svr_active;
		mtp->mt_header.mh_svr_active_ptr = IDN_ADDR2OFFSET(state_ptr);

		state_ptr = (caddr_t)&amtp->mt_header.mh_svr_ready;
		mtp->mt_header.mh_svr_ready_ptr = IDN_ADDR2OFFSET(state_ptr);

		mtp->mt_header.mh_cookie = IDN_MAKE_MBOXHDR_COOKIE(pd, sd, ch);

		mtp->mt_header.mh_cksum = IDN_CKSUM_MBOX(&mtp->mt_header);

		IDN_MBOXTBL_PTR_INC(mtp);
	}
	/*
	 * Now that the master has initialized the entire mailbox
	 * region the referenced memory may not necessarily be up-to-date
	 * with respect to the actual SMR memory due to caching.
	 * In order to make sure future connecting domains get a
	 * consistent picture of the mailbox region, it's necessary
	 * for the master to flush its caches.
	 */
	PR_PROTO("%s: flushing ecache's of local (master) domain\n", proc);

	idnxf_flushall_ecache();
}

idn_mainmbox_t *
idn_mainmbox_init(int domid, int mbx)
{
	idn_mainmbox_t	*mmp;
	int		c;
	idn_mainmbox_t	*cmp;
	procname_t	proc = "idn_mainmbox_init";

	ASSERT(idn_domain[domid].dcpu != IDN_NIL_DCPU);
	ASSERT(IDN_DLOCK_IS_HELD(domid));

	PR_PROTO("%s: initializing main %s mailbox for domain %d\n",
	    proc, IDNMBOX_IS_RECV(mbx) ? "RECV" : "SEND", domid);

	cmp = GETSTRUCT(idn_mainmbox_t, IDN_MAX_NETS);
	for (c = 0; c < IDN_MAX_NETS; c++) {
		mmp = &cmp[c];
		mmp->mm_channel = (short)c;
		mutex_init(&mmp->mm_mutex, NULL, MUTEX_DRIVER, NULL);
		mmp->mm_domid = (short)domid;
		mmp->mm_type = mbx;
	}
	mmp = cmp;
	/*
	 * The actual SMR mailbox (mmp->mm_smr_mboxp) gets setup
	 * when the SMR is setup.
	 */

	return (mmp);
}

static void
idn_mainmbox_reset(int domid, idn_mainmbox_t *cmp)
{
	idn_mainmbox_t	*mmp;
	int		c;
	procname_t	proc = "idn_mainmbox_reset";

	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	PR_PROTO("%s: reseting main %s mailbox for domain %d\n",
	    proc, IDNMBOX_IS_RECV(cmp->mm_type) ? "RECV" : "SEND", domid);

	for (c = 0; c < IDN_MAX_NETS; c++) {
		mmp = &cmp[c];

		mmp->mm_channel = (short)c;
		mmp->mm_domid = (short)domid;
		mmp->mm_count = 0;
		mmp->mm_flags = 0;
		mmp->mm_qiget = mmp->mm_qiput = 0;
		mmp->mm_csp = NULL;
		ASSERT(mmp->mm_type == cmp->mm_type);
	}
}

void
idn_mainmbox_deinit(int domid, idn_mainmbox_t *mmp)
{
	procname_t	proc = "idn_mainmbox_deinit";

	ASSERT(IDN_DLOCK_IS_HELD(domid));

	PR_PROTO("%s: deinitializing main %s mailbox for domain %d\n",
	    proc, IDNMBOX_IS_RECV(mmp->mm_type) ? "RECV" : "SEND", domid);

	ASSERT(idn_domain_is_registered(domid, -1, NULL) == 0);

	FREESTRUCT(mmp, idn_mainmbox_t, IDN_MAX_NETS);
}

static void
idn_mainmbox_activate(int domid)
{
	register int	c;
	idn_domain_t	*dp = &idn_domain[domid];
	procname_t	proc = "idn_mainmbox_activate";

	ASSERT(IDN_DLOCK_IS_HELD(domid));

	PR_PROTO("%s:%d: activating main mailbox\n", proc, domid);

	for (c = 0; c < IDN_MAX_NETS; c++)
		idn_mainmbox_chan_register(domid, &dp->dmbox.m_send[c],
		    &dp->dmbox.m_recv[c], c);
}

/*
 * Called upon disabling the SMR to deactivate all the mailboxes
 * so that they no longer reference the SMR that's going away.
 *
 * stopall - Indicates to stop all channel services, across the board.
 */
static void
idn_mainmbox_deactivate(ushort_t domset)
{
	int		svr_count;
	procname_t	proc = "idn_mainmbox_deactivate";


	if (domset == 0)
		return;

	PR_PROTO("%s: %s deactivating main mailboxes for domset 0x%x\n",
	    proc, (domset == (ushort_t)-1) ? "STOP-ALL" : "NORMAL", domset);

	svr_count = idn_mainmbox_chan_unregister(domset, -1);

	PR_PROTO("%s: deactivated %d chansvrs (domset 0x%x)\n",
	    proc, svr_count, domset);
}

static void
idn_mainmbox_chan_register(int domid, idn_mainmbox_t *send_mmp,
    idn_mainmbox_t *recv_mmp, int channel)
{
	ASSERT(IDN_DLOCK_IS_HELD(domid));

	/*
	 * Obtain receive mailbox lock first.
	 */
	mutex_enter(&recv_mmp->mm_mutex);
	mutex_enter(&send_mmp->mm_mutex);

	ASSERT(recv_mmp->mm_channel == (short)channel);
	ASSERT(send_mmp->mm_channel == (short)channel);

	recv_mmp->mm_csp = &idn.chan_servers[channel];
	recv_mmp->mm_count = 0;
	recv_mmp->mm_dropped = 0;
	recv_mmp->mm_flags = 0;

	send_mmp->mm_csp = &idn.chan_servers[channel];
	send_mmp->mm_count = 0;
	send_mmp->mm_dropped = 0;
	send_mmp->mm_flags = 0;

	mutex_exit(&send_mmp->mm_mutex);
	mutex_exit(&recv_mmp->mm_mutex);

	/*
	 * We have to add ourselves to the respective
	 * channel server's service table.
	 * Note that the channel may not necessarily be
	 * active at this time.
	 */
	ASSERT(idn.chan_servers);
	/*
	 * Have to get the channel server under
	 * control so we can add ourselves.
	 * Returns w/c_mutex.
	 */
	IDN_CHAN_LOCK_GLOBAL(&idn.chan_servers[channel]);
	/*
	 * Add the following domain (mailbox) for monitoring
	 * by the respective channel server.
	 */
	idn_chan_addmbox(channel, DOMAINSET(domid));

	IDN_CHAN_UNLOCK_GLOBAL(&idn.chan_servers[channel]);
}

/*
 * Unregister the given domain from the specified channel(s) for monitoring.
 */
static int
idn_mainmbox_chan_unregister(ushort_t domset, int channel)
{
	int		c, dd_count;
	int		min_chan, max_chan;
	procname_t	proc = "idn_mainmbox_chan_unregister";

	PR_CHAN("%s: deactivating main mailboxes (channel %d) "
	    "for domset 0x%x\n", proc, channel, domset);

	if (channel == -1) {
		min_chan = 0;
		max_chan = IDN_MAX_NETS - 1;
	} else {
		min_chan = max_chan = channel;
	}
	/*
	 * Point all the data dispatchers to the same morgue
	 * so we can kill them all at once.
	 */
	dd_count = 0;
	for (c = min_chan; c <= max_chan; c++) {

		/*
		 * Have to get the channel server under
		 * control so we can remove ourselves.
		 * Returns w/c_mutex held.
		 */
		IDN_CHAN_LOCK_GLOBAL(&idn.chan_servers[c]);
		/*
		 * Delete the following domain (mailbox) from
		 * monitoring by the respective channel server.
		 */
		idn_chan_delmbox(c, (ushort_t)domset);

		IDN_CHAN_UNLOCK_GLOBAL(&idn.chan_servers[c]);
		dd_count++;
	}
	PR_CHAN("%s: deactivated %d channel mboxes for domset 0x%x, chan %d\n",
	    proc, dd_count, domset, channel);
	return (dd_count);
}

/*
 * Check if the given domain is registered with the given channel(s).
 */
int
idn_domain_is_registered(int domid, int channel, idn_chanset_t *chansetp)
{
	int		regcount;
	int		c, min_chan, max_chan;
	idn_chanset_t	chanset;
	procname_t	proc = "idn_domain_is_registered";

	CHANSET_ZERO(chanset);

	if (idn.chan_servers == NULL) {
		PR_CHAN("%s: idn.chan_servers == NULL!!\n", proc);
		return (0);
	}

	if (channel == -1) {
		min_chan = 0;
		max_chan = IDN_MAX_NETS - 1;
	} else {
		min_chan = max_chan = channel;
	}

	regcount = 0;

	for (c = min_chan; c <= max_chan; c++) {
		idn_chansvr_t	*csp;

		csp = &idn.chan_servers[c];
		IDN_CHAN_LOCK_SEND(csp);
		/*
		 * Don't really need recv side lock since registeration
		 * can't change while we're holding send side.
		 * No need to wait for send side to actually suspend
		 * since all we want to do is prevent the registered
		 * information from changing.
		 */
		if (IDN_CHAN_DOMAIN_IS_REGISTERED(csp, domid)) {
			regcount++;
			CHANSET_ADD(chanset, c);
		}

		IDN_CHAN_UNLOCK_SEND(csp);
	}

	PR_CHAN("%s: domid %d mbox reg'd with %d channels [0x%x] (req=%d)\n",
	    proc, domid, regcount, chanset, channel);

	if (chansetp)
		*chansetp = chanset;

	return (regcount);
}

static int
idn_mainmbox_flush(int domid, idn_mainmbox_t *mmp)
{
	register int		qi;
	register idn_mboxmsg_t	*mqp;
	int		total_count = 0;
	int		c, count;
	int		mbox_type;
	char		*mbox_str;
	int		lost_io, total_lost_io = 0;
	idn_chanset_t	chanset;
	procname_t	proc = "idn_mainmbox_flush";


	if (mmp == NULL)
		return (0);

	CHANSET_ZERO(chanset);

	mbox_type = mmp->mm_type;
	ASSERT((mbox_type == IDNMMBOX_TYPE_SEND) ||
	    (mbox_type == IDNMMBOX_TYPE_RECV));

	mbox_str = (mbox_type == IDNMMBOX_TYPE_SEND) ? "SEND" : "RECV";

	/*
	 * Determine which channels this domain is registered
	 * with.  If he's not registered with any, then we
	 * can't touch the SMR.
	 */
	(void) idn_domain_is_registered(domid, -1, &chanset);

	for (c = 0; c < IDN_MAX_NETS; c++) {
		ushort_t	mbox_csum;

		if (mmp[c].mm_smr_mboxp == NULL)
			continue;
		mutex_enter(&mmp[c].mm_mutex);
		ASSERT(mmp[c].mm_type == mbox_type);
		if (CHAN_IN_SET(chanset, c) == 0) {
			/*
			 * Domain is no longer registered.
			 * DON'T TOUCH THE SMR - IT'S POISON!
			 */
			if (mmp[c].mm_smr_mboxp) {
				PR_CHAN("%s:%d:%s: domain unregistered "
				    "w/chan %d - DUMPING SMR reference\n",
				    proc, domid, mbox_str, c);
				lost_io = IDN_MMBOXINDEX_DIFF(mmp[c].mm_qiput,
				    mmp[c].mm_qiget);
#ifdef DEBUG
				if (mbox_type == IDNMMBOX_TYPE_RECV) {
					PR_CHAN("%s:%d:%s: blowing away %d "
					    "incoming pkts\n",
					    proc, domid, mbox_str, lost_io);
				} else {
					PR_CHAN("%s:%d:%s: blowing away %d/%d "
					    "outstanding pkts\n",
					    proc, domid, mbox_str, lost_io,
					    idn_domain[domid].dio);
				}
#endif /* DEBUG */
			}
			mmp[c].mm_qiput = mmp[c].mm_qiget = 0;
			mmp[c].mm_smr_mboxp = NULL;
			total_lost_io += lost_io;
		}
		if (mmp[c].mm_smr_mboxp) {
			mbox_csum =
			    IDN_CKSUM_MBOX(&mmp[c].mm_smr_mboxp->mt_header);
			if (!VALID_NWRADDR(mmp[c].mm_smr_mboxp, 4) ||
			    !VALID_MBOXHDR(&mmp[c].mm_smr_mboxp->mt_header,
			    c, mbox_csum)) {
				lost_io = IDN_MMBOXINDEX_DIFF(mmp[c].mm_qiput,
				    mmp[c].mm_qiget);
#ifdef DEBUG
				if (mbox_type == IDNMMBOX_TYPE_RECV) {
					PR_CHAN("%s:%d:%s: bad mbox.  blowing "
					    "away %d incoming pkts\n",
					    proc, domid, mbox_str, lost_io);
				} else {
					PR_CHAN("%s:%d:%s: bad mbox.  blowing "
					    "away %d/%d outstanding pkts\n",
					    proc, domid, mbox_str, lost_io,
					    idn_domain[domid].dio);
				}
#endif /* DEBUG */
				mmp[c].mm_smr_mboxp = NULL;
				mmp[c].mm_qiput = mmp[c].mm_qiget = 0;
				total_lost_io += lost_io;
			}
		}
		if (mmp[c].mm_smr_mboxp == NULL) {
			mutex_exit(&mmp[c].mm_mutex);
			continue;
		}
		mqp = &mmp[c].mm_smr_mboxp->mt_queue[0];
		qi = 0;
		count = 0;
		/*
		 * It's quite possible the remote domain may be accessing
		 * these mailbox entries at the exact same time we're
		 * clearing the owner bit.  That's okay.  All we're trying
		 * to do at this point is to minimize the number of packets
		 * the remote domain might try to process unnecessarily.
		 */
		do {
			if (mqp[qi].ms_owner)
				count++;
			mqp[qi].ms_owner = 0;
			IDN_MMBOXINDEX_INC(qi);
		} while (qi);

		lost_io = IDN_MMBOXINDEX_DIFF(mmp[c].mm_qiput, mmp[c].mm_qiget);
		total_lost_io += lost_io;

		mmp[c].mm_qiput = mmp[c].mm_qiget = 0;
		mmp[c].mm_smr_mboxp = NULL;
		mutex_exit(&mmp[c].mm_mutex);

		total_count += count;

		PR_CHAN("%s:%d:%s: flushed out %d mbox entries for chan %d\n",
		    proc, domid, mbox_str, count, c);
	}

	if (total_lost_io && (mbox_type == IDNMMBOX_TYPE_SEND)) {
		int	lost_bufs;
		/*
		 * If we lost all our outstanding I/O.  We could
		 * possible could have slabs now with mistakenly
		 * outstanding I/O buffers.  Need to clean them up.
		 * Clean up of leftovers our self.
		 */
		lost_bufs = smr_buf_free_all(domid);

		PR_CHAN("%s:%d:%s: flushed %d/%d buffers from slabs\n",
		    proc, domid, mbox_str, lost_bufs, total_lost_io);
	}

	PR_CHAN("%s:%d:%s: flushed total of %d mailbox entries (lost %d)\n",
	    proc, domid, mbox_str, total_count, total_lost_io);

	return (total_count);
}

void
idn_chanserver_bind(int net, int cpuid)
{
	int		ocpuid;
	cpu_t		*cp;
	idn_chansvr_t	*csp;
	kthread_id_t	tp;
	procname_t	proc = "idn_chanserver_bind";

	csp = &idn.chan_servers[net];
	IDN_CHAN_LOCK_GLOBAL(csp);

	mutex_enter(&cpu_lock);		/* protect checking cpu_ready_set */
	ocpuid = csp->ch_bound_cpuid;
	cp = cpu_get(cpuid);
	if ((cpuid != -1) && ((cp == NULL) || !cpu_is_online(cp))) {
		mutex_exit(&cpu_lock);
		cmn_err(CE_WARN,
		    "IDN: 239: invalid CPU ID (%d) specified for "
		    "IDN net %d",
		    cpuid, net);
		IDN_CHAN_UNLOCK_GLOBAL(csp);
		return;
	}
	if ((tp = csp->ch_recv_threadp) == NULL) {
		/*
		 * Thread is not yet active.  Set ch_bound_cpuid
		 * so when thread activates it will automatically
		 * bind itself.
		 */
		csp->ch_bound_cpuid = -1;
		csp->ch_bound_cpuid_pending = cpuid;
	} else {
		if (ocpuid != -1) {
			thread_affinity_clear(tp);
			csp->ch_bound_cpuid = -1;
		}
		if (cpuid >= 0) {
			thread_affinity_set(tp, cpuid);
			csp->ch_bound_cpuid = cpuid;
		}
		csp->ch_bound_cpuid_pending = -1;
	}
	mutex_exit(&cpu_lock);

	PR_CHAN("%s: bound net/channel (%d) from cpuid %d to%scpuid %d\n",
	    proc, net, ocpuid, tp ? " " : " (pending) ", cpuid);

	IDN_CHAN_UNLOCK_GLOBAL(csp);
}

#ifdef DEBUG
static idn_mboxhdr_t	*prev_mhp[IDN_MAXMAX_NETS];
#endif /* DEBUG */
/*
 * Get access to the respective channel server's synchronization
 * header which resides in SMR space.
 */
static idn_mboxhdr_t *
idn_chan_server_syncheader(int channel)
{
	idn_domain_t	*ldp = &idn_domain[idn.localid];
	idn_mboxtbl_t	*mtp;
	idn_mboxhdr_t	*mhp;
	ushort_t	mbox_csum;
	procname_t	proc = "idn_chan_server_syncheader";

	ASSERT(IDN_CHAN_RECV_IS_LOCKED(&idn.chan_servers[channel]));

	IDN_DLOCK_SHARED(idn.localid);

	if (ldp->dmbox.m_tbl == NULL) {
		PR_CHAN("%s: local dmbox.m_tbl == NULL\n", proc);
		IDN_DUNLOCK(idn.localid);
		return (NULL);
	}

	mtp = IDN_MBOXTBL_PTR_CHAN(ldp->dmbox.m_tbl, channel);
	mhp = &mtp->mt_header;
	mbox_csum = IDN_CKSUM_MBOX(&mtp->mt_header);

#ifdef DEBUG
	if (mhp != prev_mhp[channel]) {
		prev_mhp[channel] = mhp;
		PR_CHAN("%s: chan_server (%d) cookie = 0x%x (exp 0x%x)\n",
		    proc, channel, IDN_GET_MBOXHDR_COOKIE(mhp),
		    IDN_MAKE_MBOXHDR_COOKIE(0, 0, channel));
		PR_CHAN("%s: chan_server (%d) actv_ptr = 0x%x (exp 0x%x)\n",
		    proc, channel, mhp->mh_svr_active_ptr,
		    IDN_ADDR2OFFSET(&mhp->mh_svr_active));
		PR_CHAN("%s: chan_server (%d) ready_ptr = 0x%x (exp 0x%x)\n",
		    proc, channel, mhp->mh_svr_ready_ptr,
		    IDN_ADDR2OFFSET(&mhp->mh_svr_ready));
		PR_CHAN("%s: chan_server (%d) mbox_cksum = 0x%x (exp 0x%x)\n",
		    proc, channel, (int)mhp->mh_cksum, (int)mbox_csum);
	}
#endif /* DEBUG */

	if ((IDN_ADDR2OFFSET(&mhp->mh_svr_active) !=
	    mhp->mh_svr_active_ptr) ||
	    (IDN_ADDR2OFFSET(&mhp->mh_svr_ready) != mhp->mh_svr_ready_ptr) ||
	    !VALID_MBOXHDR(mhp, channel, mbox_csum)) {
		idn_chansvr_t	*csp;

		csp = &idn.chan_servers[channel];
		if (IDN_CHANNEL_IS_RECV_CORRUPTED(csp) == 0) {
			IDN_CHANSVC_MARK_RECV_CORRUPTED(csp);

			cmn_err(CE_WARN,
			    "IDN: 240: (channel %d) SMR CORRUPTED "
			    "- RELINK", channel);
			cmn_err(CE_CONT,
			    "IDN: 240: (channel %d) cookie "
			    "(expected 0x%x, actual 0x%x)\n",
			    channel,
			    IDN_MAKE_MBOXHDR_COOKIE(0, 0, channel),
			    mhp->mh_cookie);
			cmn_err(CE_CONT,
			    "IDN: 240: (channel %d) actv_flg "
			    "(expected 0x%x, actual 0x%x)\n",
			    channel, mhp->mh_svr_active_ptr,
			    IDN_ADDR2OFFSET(&mhp->mh_svr_active));
			cmn_err(CE_CONT,
			    "IDN: 240: (channel %d) ready_flg "
			    "(expected 0x%x, actual 0x%x)\n",
			    channel, mhp->mh_svr_ready_ptr,
			    IDN_ADDR2OFFSET(&mhp->mh_svr_ready));
		}

		mhp = NULL;
	}
	IDN_DUNLOCK(idn.localid);

	PR_CHAN("%s: channel(%d) mainhp = 0x%p\n", proc, channel, (void *)mhp);

	return (mhp);
}

#define	CHANSVR_SYNC_CACHE(csp, mmp, chan) \
{ \
	ASSERT(IDN_CHAN_RECV_IS_LOCKED(csp)); \
	if ((csp)->ch_recv_changed) { \
		register int _d; \
		(csp)->ch_recv_scanset = (csp)->ch_recv_scanset_pending; \
		(csp)->ch_recv_domset = (csp)->ch_recv_domset_pending; \
		for (_d = 0; _d < MAX_DOMAINS; _d++) { \
			if (DOMAIN_IN_SET((csp)->ch_recv_domset, _d)) { \
				(mmp)[_d] = \
				    &idn_domain[_d].dmbox.m_recv[chan]; \
			} else { \
				(mmp)[_d] = NULL; \
			} \
		} \
		(csp)->ch_recv_changed = 0; \
	} \
}
#define	CHANSVR_NEXT_DOMID(csp, i, d) \
{ \
	(i) = ((i) + 1) & (MAX_DOMAINS - 1); \
	(d) = (int)(((csp)->ch_recv_scanset >> ((i) << 2)) & 0xf); \
}
#define	CHANSVR_RESET_INDEX(i)	((i) = -1)

#ifdef DEBUG
static idn_mainmbox_t	*Mmp[IDN_MAXMAX_NETS][MAX_DOMAINS];
#endif /* DEBUG */

static void
idn_chan_server(idn_chansvr_t **cspp)
{
	idn_mboxhdr_t	*mainhp;
	register idn_chansvr_t		*csp;
	register idn_mboxmsg_t		*mqp;
#ifdef DEBUG
	idn_mainmbox_t			**mmp;
#else
	idn_mainmbox_t			*mmp[MAX_DOMAINS];
#endif /* DEBUG */
	register int	qi;
	struct idn	*sip;
	int		channel;
	int		cpuid;
	int		empty;
	int		tot_pktcount, tot_dropcount;
	register int	index;
	register int	domid;
	register int	idleloops;
	procname_t	proc = "idn_chan_server";


#ifdef DEBUG
	mmp = &Mmp[(*cspp)->ch_id][0];
	bzero(mmp, MAX_DOMAINS * sizeof (idn_mainmbox_t *));
#else /* DEBUG */
	bzero(mmp, sizeof (mmp));
#endif /* DEBUG */

	tot_pktcount = tot_dropcount = 0;

	ASSERT(cspp && *cspp);

	csp = *cspp;
	channel = csp->ch_id;
	sip = IDN_INST2SIP(channel);
	ASSERT(sip);

	PR_CHAN("%s: CHANNEL SERVER (channel %d) GOING ACTIVE...\n",
	    proc, channel);

	IDN_CHAN_LOCK_RECV(csp);
	IDN_CHAN_RECV_INPROGRESS(csp);
	ASSERT(csp->ch_recv_threadp == curthread);
	mutex_enter(&cpu_lock);
	if ((cpuid = csp->ch_bound_cpuid_pending) != -1) {
		cpu_t	*cp = cpu_get(cpuid);
		/*
		 * We've been requested to bind to
		 * a particular cpu.
		 */
		if ((cp == NULL) || !cpu_is_online(cp)) {
			/*
			 * Cpu seems to have gone away or gone offline
			 * since originally requested.
			 */
			mutex_exit(&cpu_lock);
			cmn_err(CE_WARN,
			    "IDN: 239: invalid CPU ID (%d) specified for "
			    "IDN net %d",
			    cpuid, channel);
		} else {
			csp->ch_bound_cpuid = cpuid;
			affinity_set(csp->ch_bound_cpuid);
			mutex_exit(&cpu_lock);
		}
		csp->ch_bound_cpuid_pending = -1;
	} else {
		mutex_exit(&cpu_lock);
	}
	if (csp->ch_bound_cpuid != -1) {
		PR_CHAN("%s: thread bound to cpuid %d\n",
		    proc, csp->ch_bound_cpuid);
	}
	/*
	 * Only the first (main) mbox header is used for
	 * synchronization with data delivery since there is
	 * only data server for all mailboxes for this
	 * given channel.
	 */
	CHANSVR_SYNC_CACHE(csp, mmp, channel);

	mainhp = ((csp->ch_recv_domcount > 0) &&
	    IDN_CHANNEL_IS_RECV_ACTIVE(csp))
	    ? idn_chan_server_syncheader(channel) : NULL;

	if (mainhp && IDN_CHANNEL_IS_RECV_ACTIVE(csp))
		mainhp->mh_svr_active = 1;

	ASSERT(csp->ch_recv_domcount ?
	    (csp->ch_recv_scanset && csp->ch_recv_domset) : 1);

	IDN_CHAN_UNLOCK_RECV(csp);

	empty = 0;
	idleloops = 0;
	CHANSVR_RESET_INDEX(index);

	/*
	 * ---------------------------------------------
	 */
	/*CONSTCOND*/
	while (1) {
		register int	pktcount;
		register int	dropcount;
		ushort_t		mbox_csum;
		idn_mboxtbl_t	*smr_mboxp;	/* points to SMR space */
		register smr_offset_t	bufoffset;
#ifdef DEBUG
		register smr_pkthdr_t	*hdrp;
		idn_netaddr_t		netaddr;
#endif /* DEBUG */

		/*
		 * Speed through and find the next available domid.
		 */
		CHANSVR_NEXT_DOMID(csp, index, domid);

		if (!index) {
			/*
			 * We only check state changes when
			 * we wrap around.  Done for performance.
			 */
			if (!IDN_CHANNEL_IS_RECV_ACTIVE(csp) ||
			    csp->ch_recv.c_checkin ||
			    (idn.state != IDNGS_ONLINE)) {

				PR_DATA("%s: (channel %d) %s\n",
				    proc, channel,
				    IDN_CHANNEL_IS_DETACHED(csp)
				    ? "DEAD" :
				    IDN_CHANNEL_IS_PENDING(csp)
				    ? "IDLED" :
				    IDN_CHANNEL_IS_ACTIVE(csp)
				    ? "ACTIVE" : "DISABLED");
				goto cc_sleep;
			}
		}
		if (csp->ch_recv.c_checkin)
			goto cc_sleep;

		if (empty == csp->ch_recv_domcount) {
			empty = 0;
			goto cc_slowdown;
		}

		ASSERT(mmp[domid] != NULL);

		mutex_enter(&mmp[domid]->mm_mutex);
		if ((smr_mboxp = mmp[domid]->mm_smr_mboxp) == NULL) {
			/*
			 * Somebody is trying to shut things down.
			 */
			empty++;
			mutex_exit(&mmp[domid]->mm_mutex);
			continue;
		}
		ASSERT(mmp[domid]->mm_channel == (short)channel);
		/*
		 * We don't care if the mm_smr_mboxp is nullified
		 * after this point.  The thread attempting to shut
		 * us down has to formally pause this channel before
		 * anything is official anyway.  So, we can continue
		 * with our local SMR reference until the thread
		 * shutting us down really stops us.
		 *
		 * Need to get the qiget index _before_ we drop the
		 * lock since it might get flushed (idn_mainmbox_flush)
		 * once we drop the mm_mutex.
		 *
		 * We prefer not to hold the mm_mutex across the
		 * idn_recv_mboxdata() call since that may be time-
		 * consuming.
		 */
		qi  = mmp[domid]->mm_qiget;

		/*
		 * Check the mailbox header if checksum is turned on.
		 */
		mbox_csum = IDN_CKSUM_MBOX(&smr_mboxp->mt_header);
		if (!VALID_MBOXHDR(&smr_mboxp->mt_header, channel, mbox_csum)) {
			IDN_KSTAT_INC(sip, si_mboxcrc);
			IDN_KSTAT_INC(sip, si_ierrors);
			if (!(mmp[domid]->mm_flags & IDNMMBOX_FLAG_CORRUPTED)) {
				cmn_err(CE_WARN,
				    "IDN: 241: [recv] (domain %d, "
				    "channel %d) SMR CORRUPTED - RELINK",
				    domid, channel);
				mmp[domid]->mm_flags |= IDNMMBOX_FLAG_CORRUPTED;
			}
			empty = 0;
			mutex_exit(&mmp[domid]->mm_mutex);
			goto cc_sleep;
		}
		mutex_exit(&mmp[domid]->mm_mutex);
		mqp = &smr_mboxp->mt_queue[0];

		pktcount = dropcount = 0;

		if (mqp[qi].ms_owner == 0)
			goto cc_next;

		bufoffset = IDN_BFRAME2OFFSET(mqp[qi].ms_bframe);

		if (!VALID_NWROFFSET(bufoffset, IDN_SMR_BUFSIZE)) {
			/* ASSERT(0); */
			mqp[qi].ms_flag |= IDN_MBOXMSG_FLAG_ERR_BADOFFSET;
			mqp[qi].ms_owner = 0;
			IDN_MMBOXINDEX_INC(qi);
			dropcount++;

			IDN_KSTAT_INC(sip, si_smraddr);
			IDN_KSTAT_INC(sip, si_ierrors);

		} else {
			PR_DATA("%s: (channel %d) pkt (off 0x%x, "
			    "qiget %d) from domain %d\n",
			    proc, channel, bufoffset, qi, domid);
#ifdef DEBUG

			hdrp = IDN_BUF2HDR(IDN_OFFSET2ADDR(bufoffset));
			netaddr.netaddr = hdrp->b_netaddr;
			ASSERT(netaddr.net.chan == (ushort_t)channel);
#endif /* DEBUG */

			if (idn_recv_mboxdata(channel,
			    IDN_OFFSET2ADDR(bufoffset)) < 0) {
				mutex_enter(&mmp[domid]->mm_mutex);
				if (!(mmp[domid]->mm_flags &
				    IDNMMBOX_FLAG_CORRUPTED)) {
					cmn_err(CE_WARN,
					    "IDN: 241: [recv] (domain "
					    "%d, channel %d) SMR "
					    "CORRUPTED - RELINK",
					    domid, channel);
					mmp[domid]->mm_flags |=
					    IDNMMBOX_FLAG_CORRUPTED;
				}
				mutex_exit(&mmp[domid]->mm_mutex);
			}

			mqp[qi].ms_owner = 0;
			IDN_MMBOXINDEX_INC(qi);
			pktcount++;
		}

cc_next:

		mutex_enter(&mmp[domid]->mm_mutex);
		if (mmp[domid]->mm_smr_mboxp) {
			if (dropcount)
				mmp[domid]->mm_dropped += dropcount;
			mmp[domid]->mm_qiget = qi;
			mmp[domid]->mm_count += pktcount;
		}
		mutex_exit(&mmp[domid]->mm_mutex);

		if (pktcount == 0) {
			empty++;
		} else {
			csp->ch_recv_waittime = IDN_NETSVR_WAIT_MIN;
			empty = 0;
			idleloops = 0;

			PR_DATA("%s: (channel %d) dom=%d, pktcnt=%d\n",
			    proc, channel, domid, pktcount);
		}

		continue;

cc_slowdown:

#ifdef DEBUG
		if (idleloops == 0) {
			PR_DATA("%s: (channel %d) going SOFT IDLE...\n",
			    proc, channel);
		}
#endif /* DEBUG */
		if (idleloops++ < IDN_NETSVR_SPIN_COUNT) {
			/*
			 * At this level we only busy-wait.
			 * Get back into action.
			 */
			continue;
		}
		idleloops = 0;

cc_sleep:

		if (mainhp)
			mainhp->mh_svr_active = 0;

		IDN_CHAN_LOCK_RECV(csp);

cc_die:

		ASSERT(IDN_CHAN_RECV_IS_LOCKED(csp));

		if (!IDN_CHANNEL_IS_RECV_ACTIVE(csp) &&
		    IDN_CHANNEL_IS_DETACHED(csp)) {
			/*
			 * Time to die...
			 */
			PR_CHAN("%s: (channel %d) serviced %d "
			    "packets, drop = %d\n", proc, channel,
			    tot_pktcount, tot_dropcount);
			PR_CHAN("%s: (channel %d) TERMINATING\n",
			    proc, channel);
			PR_CHAN("%s: (channel %d) ch_morguep = %p\n",
			    proc, channel, (void *)csp->ch_recv_morguep);

			csp->ch_recv_threadp = NULL;
#ifdef DEBUG
			for (index = 0; index < csp->ch_recv_domcount;
			    index++) {
				if ((int)((csp->ch_recv_scanset >>
				    (index*4)) & 0xf) == domid) {
					PR_DATA("%s: WARNING (channel %d) "
					    "DROPPING domid %d...\n",
					    proc, channel, domid);
				}
			}
#endif /* DEBUG */
			IDN_CHAN_RECV_DONE(csp);

			sema_v(csp->ch_recv_morguep);

			IDN_CHAN_UNLOCK_RECV(csp);

			thread_exit();
			/* not reached */
		}

		do {
			if (IDN_CHANNEL_IS_DETACHED(csp)) {
				PR_CHAN("%s: (channel %d) going to DIE...\n",
				    proc, channel);
				goto cc_die;
			}
#ifdef DEBUG
			if (IDN_CHANNEL_IS_RECV_ACTIVE(csp) &&
			    (csp->ch_recv_waittime <= IDN_NETSVR_WAIT_MAX)) {
				PR_CHAN("%s: (channel %d) going SOFT IDLE "
				    "(waittime = %d ticks)...\n",
				    proc, channel,
				    csp->ch_recv_waittime);
			} else {
				PR_CHAN("%s: (channel %d) going "
				    "HARD IDLE...\n", proc, channel);
			}
#endif /* DEBUG */
			IDN_CHAN_RECV_DONE(csp);

			/*
			 * If we're being asked to check-in then
			 * go into a hard sleep.  Want to give the
			 * thread requesting us to checkin a chance.
			 */
			while (csp->ch_recv.c_checkin)
				cv_wait(&csp->ch_recv_cv,
				    &csp->ch_recv.c_mutex);

			if (csp->ch_recv_waittime > IDN_NETSVR_WAIT_MAX)
				cv_wait(&csp->ch_recv_cv,
				    &csp->ch_recv.c_mutex);
			else
				(void) cv_reltimedwait(&csp->ch_recv_cv,
				    &csp->ch_recv.c_mutex,
				    csp->ch_recv_waittime, TR_CLOCK_TICK);

			IDN_CHAN_RECV_INPROGRESS(csp);

			IDN_KSTAT_INC(sip, si_sigsvr);

			if (csp->ch_recv_waittime <= IDN_NETSVR_WAIT_MAX)
				csp->ch_recv_waittime <<=
				    IDN_NETSVR_WAIT_SHIFT;

		} while (!IDN_CHANNEL_IS_RECV_ACTIVE(csp));

		/*
		 * Before we see the world (and touch SMR space),
		 * see if we've been told to die.
		 */
		mainhp = NULL;
		/*
		 * The world may have changed since we were
		 * asleep.  Need to resync cache and check for a
		 * new syncheader.
		 *
		 * Reset chansvr cache against any changes in
		 * mbox fields we need (mm_qiget).
		 */
		CHANSVR_SYNC_CACHE(csp, mmp, channel);
		if (csp->ch_recv_domcount <= 0) {
			/*
			 * Everybody disappeared on us.
			 * Go back to sleep.
			 */
			goto cc_die;
		}
		ASSERT(csp->ch_recv_scanset && csp->ch_recv_domset);

		mainhp = idn_chan_server_syncheader(channel);
		if (mainhp == NULL) {
			/*
			 * Bummer...we're idling...
			 */
			goto cc_die;
		}

		mainhp->mh_svr_active = 1;

		IDN_CHAN_UNLOCK_RECV(csp);
		/*
		 * Reset the domid index after sleeping.
		 */
		CHANSVR_RESET_INDEX(index);

		empty = 0;
		idleloops = 0;
	}
}

#if 0
/*
 * We maintain a separate function for flushing the STREAMs
 * queue of a channel because it must be done outside the
 * context of the idn_chan_action routine.  The streams flush
 * cannot occur inline with the idn_chan_action because
 * the act of flushing may cause IDN send functions to be called
 * directly and thus locks to be obtained which could result
 * in deadlocks.
 */
static void
idn_chan_flush(idn_chansvr_t *csp)
{
	queue_t		*rq;
	struct idn	*sip;
	int		flush_type = 0;
	idn_chaninfo_t	*csend, *crecv;
	procname_t	proc = "idn_chan_flush";

	csend = &csp->ch_send;
	crecv = &csp->ch_recv;

	mutex_enter(&crecv->c_mutex);
	mutex_enter(&csend->c_mutex);

	if (crecv->c_state & IDN_CHANSVC_STATE_FLUSH)
		flush_type |= FLUSHR;

	if (csend->c_state & IDN_CHANSVC_STATE_FLUSH)
		flush_type |= FLUSHW;

	if (flush_type) {
		rq = NULL;
		rw_enter(&idn.struprwlock, RW_READER);
		if ((sip = IDN_INST2SIP(csp->ch_id)) != NULL)
			rq = sip->si_ipq;
		rw_exit(&idn.struprwlock);
		if (rq) {
			/*
			 * Flush the STREAM if possible
			 * to get the channel server coherent
			 * enough to respond to us.
			 */
			PR_CHAN("%s: sending FLUSH (%x) to channel %d\n",
			    proc, flush_type, csp->ch_id);

			(void) putnextctl1(rq, M_FLUSH, flush_type);
		}
		crecv->c_state &= ~IDN_CHANSVC_STATE_FLUSH;
		csend->c_state &= ~IDN_CHANSVC_STATE_FLUSH;

		if (crecv->c_waiters)
			cv_broadcast(&crecv->c_cv);
	}

	mutex_exit(&csend->c_mutex);
	mutex_exit(&crecv->c_mutex);
}
#endif /* 0 */

/*
 * Locks are with respect to SEND/RECV locks (c_mutex).
 *
 * STOP/SUSPEND/DETACH
 *	- Entered with locks dropped, leave with locks held.
 *	  DETACH - lock dropped manually.
 * RESTART/RESUME
 *	- Entered with locks held, leave with locks dropped.
 * ATTACH
 *	- both enter and leave with locks dropped.
 */
static void
idn_chan_action(int channel, idn_chanaction_t chanaction, int wait)
{
	uchar_t		clr_state, set_state;
	uint_t		is_running;
	domainset_t	closed_slabwaiters = 0;
	struct idn	*sip;
	idn_chansvr_t	*csp;
	idn_chaninfo_t	*csend, *crecv;
	procname_t	proc = "idn_chan_action";

	ASSERT((channel >= 0) && (channel < IDN_MAX_NETS));
	ASSERT(idn.chan_servers);

	csp = &idn.chan_servers[channel];

	PR_CHAN("%s: requesting %s for channel %d\n",
	    proc, chanaction_str[(int)chanaction], channel);

	csend = &csp->ch_send;
	crecv = &csp->ch_recv;

	ASSERT(IDN_CHAN_GLOBAL_IS_LOCKED(csp));

	clr_state = set_state = 0;

	switch (chanaction) {
	case IDNCHAN_ACTION_DETACH:
		clr_state = IDN_CHANSVC_STATE_MASK;
		/*FALLTHROUGH*/

	case IDNCHAN_ACTION_STOP:
		clr_state |= IDN_CHANSVC_STATE_ENABLED;
		/*FALLTHROUGH*/

	case IDNCHAN_ACTION_SUSPEND:
		clr_state |= IDN_CHANSVC_STATE_ACTIVE;

		/*
		 * Must maintain this locking order.
		 * Set asynchronous check-in flags.
		 */
		crecv->c_checkin = 1;
		csend->c_checkin = 1;

		is_running = 0;
		if ((csend->c_inprogress || crecv->c_inprogress) &&
		    wait && (csp->ch_recv_threadp != curthread)) {

			rw_enter(&idn.struprwlock, RW_READER);
			if ((sip = IDN_INST2SIP(channel)) != NULL) {
				/*
				 * Temporarily turn off the STREAM
				 * to give a chance to breath.
				 */
				is_running = sip->si_flags & IDNRUNNING;
				if (is_running)
					sip->si_flags &= ~IDNRUNNING;
			}
			rw_exit(&idn.struprwlock);
		}

		mutex_enter(&crecv->c_mutex);
		crecv->c_state &= ~clr_state;

		mutex_enter(&csend->c_mutex);
		csend->c_state &= ~clr_state;

		/*
		 * It's possible the channel server could come
		 * through this flow itself due to putting data upstream
		 * that ultimately turned around and came back down for
		 * sending.  If this is the case we certainly don't
		 * want to cv_wait, otherwise we'll obviously deadlock
		 * waiting for ourself.  So, only block if somebody
		 * other than the channel server we're attempting to
		 * suspend/stop.
		 */
		if (wait && (csp->ch_recv_threadp != curthread)) {
			int	do_flush = 0;

			if (csend->c_inprogress || crecv->c_inprogress)
				do_flush++;

			if (do_flush) {
				rw_enter(&idn.struprwlock, RW_READER);
				if ((sip = IDN_INST2SIP(channel)) != NULL) {
					/*
					 * Temporarily turn off the STREAM
					 * to give a chance to breath.
					 */
					if (sip->si_flags & IDNRUNNING) {
						is_running = 1;
						sip->si_flags &= ~IDNRUNNING;
					}
				}
				rw_exit(&idn.struprwlock);
			}

			/*
			 * If we have any senders in-progress
			 * it's possible they're stuck waiting
			 * down in smr_buf_alloc which may never
			 * arrive if we're in an unlink process.
			 * Rather than wait for it to timeout
			 * let's be proactive so we can disconnect
			 * asap.
			 */
			closed_slabwaiters = csp->ch_reg_domset;
			DOMAINSET_ADD(closed_slabwaiters, idn.localid);
			if (closed_slabwaiters)
				smr_slabwaiter_close(closed_slabwaiters);

			do {
				/*
				 * It's possible due to a STREAMs
				 * loopback from read queue to write queue
				 * that receiver and sender may be same
				 * thread, i.e. receiver's inprogress
				 * flag will never clear until sender's
				 * inprogress flag clears.  So, we wait
				 * for sender's inprogress first.
				 */
				while (csend->c_inprogress) {
					mutex_exit(&crecv->c_mutex);
					while (csend->c_inprogress) {
						csend->c_waiters++;
						cv_wait(&csend->c_cv,
						    &csend->c_mutex);
						csend->c_waiters--;
					}
					/*
					 * Maintain lock ordering.
					 * Eventually we will catch
					 * him due to the flag settings.
					 */
					mutex_exit(&csend->c_mutex);
					mutex_enter(&crecv->c_mutex);
					mutex_enter(&csend->c_mutex);
				}
				if (crecv->c_inprogress) {
					mutex_exit(&csend->c_mutex);
					while (crecv->c_inprogress) {
						crecv->c_waiters++;
						cv_wait(&crecv->c_cv,
						    &crecv->c_mutex);
						crecv->c_waiters--;
					}
					mutex_enter(&csend->c_mutex);
				}
			} while (csend->c_inprogress);
		}

		if (is_running) {
			/*
			 * Restore the IDNRUNNING bit in
			 * the flags to let them know the
			 * channel is still alive.
			 */
			rw_enter(&idn.struprwlock, RW_READER);
			if ((sip = IDN_INST2SIP(channel)) != NULL)
				sip->si_flags |= IDNRUNNING;
			rw_exit(&idn.struprwlock);
		}

		if (closed_slabwaiters) {
			/*
			 * We can reopen now since at this point no new
			 * slabwaiters will attempt to come in and wait.
			 */
			smr_slabwaiter_open(csp->ch_reg_domset);
		}

		crecv->c_checkin = 0;
		csend->c_checkin = 0;

		/*
		 * ALL leave with locks held.
		 */
		PR_CHAN("%s: action (%s) for channel %d - COMPLETED\n",
		    proc, chanaction_str[(int)chanaction], channel);
		break;

	case IDNCHAN_ACTION_ATTACH:
		mutex_enter(&crecv->c_mutex);
		mutex_enter(&csend->c_mutex);
		set_state |= csp->ch_state & IDN_CHANSVC_STATE_ATTACHED;
		/*FALLTHROUGH*/

	case IDNCHAN_ACTION_RESTART:
		set_state |= csp->ch_state & IDN_CHANSVC_STATE_ENABLED;
		/*FALLTHROUGH*/

	case IDNCHAN_ACTION_RESUME:
		ASSERT(IDN_CHAN_LOCAL_IS_LOCKED(csp));
		set_state |= csp->ch_state & IDN_CHANSVC_STATE_ACTIVE;

		crecv->c_state |= set_state;
		csend->c_state |= set_state;

		/*
		 * The channel server itself could come through this
		 * flow, so obviously no point in attempting to wake
		 * ourself up!.
		 */
		if (csp->ch_recv_threadp && (csp->ch_recv_threadp != curthread))
			cv_signal(&csp->ch_recv_cv);

		PR_CHAN("%s: action (%s) for channel %d - COMPLETED\n",
		    proc, chanaction_str[(int)chanaction], channel);

		/*
		 * Leaves with lock released.
		 */
		mutex_exit(&csend->c_mutex);
		mutex_exit(&crecv->c_mutex);
		break;

	default:
		ASSERT(0);
		break;
	}
}

static void
idn_chan_addmbox(int channel, ushort_t domset)
{
	idn_chansvr_t	*csp;
	register int	d;
	procname_t	proc = "idn_chan_addmbox";

	PR_CHAN("%s: adding domset 0x%x main mailboxes to channel %d\n",
	    proc, domset, channel);

	ASSERT(idn.chan_servers);

	csp = &idn.chan_servers[channel];

	/*
	 * Adding domains to a channel can be
	 * asynchonous, so we don't bother waiting.
	 */
	IDN_CHANNEL_SUSPEND(channel, 0);

	/*
	 * Now we have the sending and receiving sides blocked
	 * for this channel.
	 */
	for (d = 0; d < MAX_DOMAINS; d++) {
		if (!DOMAIN_IN_SET(domset, d))
			continue;
		if (IDN_CHAN_DOMAIN_IS_REGISTERED(csp, d)) {
			DOMAINSET_DEL(domset, d);
			continue;
		}
		IDN_CHANSVR_SCANSET_ADD_PENDING(csp, d);
		DOMAINSET_ADD(csp->ch_recv_domset_pending, d);
		IDN_CHAN_DOMAIN_REGISTER(csp, d);

		PR_CHAN("%s: domain %d (channel %d) RECV (pending) "
		    "scanset = 0x%lx\n", proc, d, channel,
		    csp->ch_recv_scanset_pending);
		PR_CHAN("%s: domain %d (channel %d) domset = 0x%x\n",
		    proc, d, channel, (uint_t)csp->ch_reg_domset);

		CHECKPOINT_OPENED(IDNSB_CHKPT_CHAN,
		    idn_domain[d].dhw.dh_boardset, 1);
	}
	if (domset)
		csp->ch_recv_changed = 1;

	IDN_CHANNEL_RESUME(channel);
}

static void
idn_chan_delmbox(int channel, ushort_t domset)
{
	idn_chansvr_t	*csp;
	register int	d;
	procname_t	proc = "idn_chan_delmbox";

	PR_CHAN("%s: deleting domset 0x%x main mailboxes from channel %d\n",
	    proc, domset, channel);

	ASSERT(idn.chan_servers);

	csp = &idn.chan_servers[channel];

	/*
	 * Here we have to wait for the channel server
	 * as it's vital that we don't return without guaranteeing
	 * that the given domset is no longer registered.
	 */
	IDN_CHANNEL_SUSPEND(channel, 1);

	/*
	 * Now we have the sending and receiving sides blocked
	 * for this channel.
	 */
	for (d = 0; d < MAX_DOMAINS; d++) {
		if (!DOMAIN_IN_SET(domset, d))
			continue;
		if (!IDN_CHAN_DOMAIN_IS_REGISTERED(csp, d)) {
			DOMAINSET_DEL(domset, d);
			continue;
		}
		/*
		 * This domain has a mailbox hanging on this channel.
		 * Get him out.
		 *
		 * First remove him from the receive side.
		 */
		ASSERT(csp->ch_recv_domcount > 0);
		IDN_CHANSVR_SCANSET_DEL_PENDING(csp, d);
		DOMAINSET_DEL(csp->ch_recv_domset_pending, d);
		IDN_CHAN_DOMAIN_UNREGISTER(csp, d);

		PR_CHAN("%s: domain %d (channel %d) RECV (pending) "
		    "scanset = 0x%lx\n", proc, d, channel,
		    csp->ch_recv_scanset_pending);
		PR_CHAN("%s: domain %d (channel %d) domset = 0x%x\n",
		    proc, d, channel, (uint_t)csp->ch_reg_domset);

		CHECKPOINT_CLOSED(IDNSB_CHKPT_CHAN,
		    idn_domain[d].dhw.dh_boardset, 2);

	}
	if (domset)
		csp->ch_recv_changed = 1;

	IDN_CHANNEL_RESUME(channel);
}

static int
idn_valid_etherheader(struct ether_header *ehp)
{
	uchar_t	*eap;

	eap = &ehp->ether_dhost.ether_addr_octet[0];

	if ((eap[IDNETHER_ZERO] != 0) && (eap[IDNETHER_ZERO] != 0xff))
		return (0);

	if ((eap[IDNETHER_COOKIE1] != IDNETHER_COOKIE1_VAL) &&
	    (eap[IDNETHER_COOKIE1] != 0xff))
		return (0);

	if ((eap[IDNETHER_COOKIE2] != IDNETHER_COOKIE2_VAL) &&
	    (eap[IDNETHER_COOKIE2] != 0xff))
		return (0);

	if ((eap[IDNETHER_RESERVED] != IDNETHER_RESERVED_VAL) &&
	    (eap[IDNETHER_RESERVED] != 0xff))
		return (0);

	if (!VALID_UCHANNEL(eap[IDNETHER_CHANNEL]) &&
	    (eap[IDNETHER_CHANNEL] != 0xff))
		return (0);

	if (!VALID_UDOMAINID(IDN_NETID2DOMID(eap[IDNETHER_NETID])) &&
	    (eap[IDNETHER_NETID] != 0xff))
		return (0);

	return (1);
}

/*
 * Packet header has already been filled in.
 * RETURNS:	0
 *		ENOLINK
 *		EPROTO
 *		ENOSPC
 */
/*ARGSUSED*/
static int
idn_send_mboxdata(int domid, struct idn *sip, int channel, caddr_t bufp)
{
	idn_mainmbox_t	*mmp;
	idn_mboxmsg_t	*mqp;
	smr_pkthdr_t	*hdrp;
	smr_offset_t	bufoffset;
	idn_netaddr_t	dst;
	ushort_t		mbox_csum;
	int		rv = 0;
	int		pktlen, qi;
	procname_t	proc = "idn_send_mboxdata";

	mmp = idn_domain[domid].dmbox.m_send;
	if (mmp == NULL) {
		PR_DATA("%s: dmbox.m_send == NULL\n", proc);
		IDN_KSTAT_INC(sip, si_linkdown);
		return (ENOLINK);
	}

	mmp += channel;
	mutex_enter(&mmp->mm_mutex);

	if (mmp->mm_smr_mboxp == NULL) {
		PR_DATA("%s: (d %d, chn %d) mm_smr_mboxp == NULL\n",
		    proc, domid, channel);
		IDN_KSTAT_INC(sip, si_linkdown);
		rv = ENOLINK;
		goto send_err;
	}
	mbox_csum = IDN_CKSUM_MBOX(&mmp->mm_smr_mboxp->mt_header);
	if (mbox_csum != mmp->mm_smr_mboxp->mt_header.mh_cksum) {
		PR_DATA("%s: (d %d, chn %d) mbox hdr cksum (%d) "
		    "!= actual (%d)\n",
		    proc, domid, channel, mbox_csum,
		    mmp->mm_smr_mboxp->mt_header.mh_cksum);
		if ((mmp->mm_flags & IDNMMBOX_FLAG_CORRUPTED) == 0) {
			cmn_err(CE_WARN,
			    "IDN: 241: [send] (domain %d, "
			    "channel %d) SMR CORRUPTED - RELINK",
			    domid, channel);
			mmp->mm_flags |= IDNMMBOX_FLAG_CORRUPTED;
		}
		IDN_KSTAT_INC(sip, si_mboxcrc);
		IDN_KSTAT_INC(sip, si_oerrors);
		rv = EPROTO;
		goto send_err;
	}

	bufoffset = IDN_ADDR2OFFSET(bufp);
	hdrp	  = IDN_BUF2HDR(bufp);
	pktlen    = hdrp->b_length;
	dst.netaddr = hdrp->b_netaddr;
	ASSERT(dst.net.chan == (ushort_t)channel);

	mqp = &mmp->mm_smr_mboxp->mt_queue[0];
	qi  = mmp->mm_qiput;

	if (mqp[qi].ms_owner) {
		PR_DATA("%s: mailbox FULL (qiput=%d, qiget=%d)\n",
		    proc, mmp->mm_qiput, mmp->mm_qiget);
		IDN_KSTAT_INC(sip, si_txfull);
		rv = ENOSPC;
		goto send_err;
	}
	if (mqp[qi].ms_flag & IDN_MBOXMSG_FLAG_RECLAIM) {
		smr_offset_t	recl_bufoffset;
		/*
		 * Remote domain finished with mailbox entry,
		 * however it has not been reclaimed yet.  A reclaim
		 * was done before coming into this routine, however
		 * timing may have been such that the entry became
		 * free just after the reclamation, but before
		 * entry into here.  Go ahead and reclaim this entry.
		 */
		recl_bufoffset = IDN_BFRAME2OFFSET(mqp[qi].ms_bframe);

		PR_DATA("%s: attempting reclaim (domain %d) "
		    "(qiput=%d, b_off=0x%x)\n",
		    proc, domid, qi, recl_bufoffset);

		if (VALID_NWROFFSET(recl_bufoffset, IDN_SMR_BUFSIZE)) {
			int		recl;
			caddr_t		b_bufp;
			smr_pkthdr_t	*b_hdrp;

			b_bufp = IDN_OFFSET2ADDR(recl_bufoffset);
			b_hdrp = IDN_BUF2HDR(b_bufp);

			if (IDN_CKSUM_PKT(b_hdrp) != b_hdrp->b_cksum) {
				IDN_KSTAT_INC(sip, si_crc);
				IDN_KSTAT_INC(sip, si_fcs_errors);
				IDN_KSTAT_INC(sip, si_reclaim);
				IDN_KSTAT_INC(sip, si_oerrors);
			}

			recl = smr_buf_free(domid, b_bufp, b_hdrp->b_length);
#ifdef DEBUG
			if (recl == 0) {
				PR_DATA("%s: SUCCESSFULLY reclaimed buf "
				    "(domain %d)\n", proc, domid);
			} else {
				PR_DATA("%s: WARNING: reclaim failed (FREE) "
				    "(domain %d)\n", proc, domid);
			}
#endif /* DEBUG */
		} else {
			IDN_KSTAT_INC(sip, si_smraddr);
			IDN_KSTAT_INC(sip, si_reclaim);
			PR_DATA("%s: WARNING: reclaim failed (BAD OFFSET) "
			    "(domain %d)\n", proc, domid);
		}
	}

	if (*mmp->mm_smr_readyp == 0) {
		mmp->mm_qiput = qi;
		IDN_KSTAT_INC(sip, si_linkdown);
		rv = ENOLINK;
		goto send_err;
	}

	mqp[qi].ms_flag = IDN_MBOXMSG_FLAG_RECLAIM;
	mqp[qi].ms_bframe = IDN_OFFSET2BFRAME(bufoffset);
	/* membar_stst(); */
	mqp[qi].ms_owner = 1;

	IDN_MMBOXINDEX_INC(qi);

	mmp->mm_qiput = qi;

	mmp->mm_count++;

	if ((*mmp->mm_smr_readyp) && !(*mmp->mm_smr_activep)) {
		idn_msgtype_t	mt;

		mt.mt_mtype = IDNP_DATA;
		mt.mt_atype = 0;
		IDN_KSTAT_INC(sip, si_xdcall);
		(void) IDNXDC(domid, &mt, (uint_t)dst.net.chan, 0, 0, 0);
	}
	mutex_exit(&mmp->mm_mutex);
	IDN_KSTAT_INC(sip, si_opackets);
	IDN_KSTAT_INC(sip, si_opackets64);
	IDN_KSTAT_ADD(sip, si_xmtbytes, pktlen);
	IDN_KSTAT_ADD(sip, si_obytes64, (uint64_t)pktlen);

	return (0);

send_err:
	mmp->mm_dropped++;

	mutex_exit(&mmp->mm_mutex);

	return (rv);
}

static int
idn_recv_mboxdata(int channel, caddr_t bufp)
{
	smr_pkthdr_t	*hdrp;
	struct idn	*sip;
	mblk_t		*mp = nilp(mblk_t);
	int		pktlen;
	int		apktlen;
	int		rv = 0;
	smr_offset_t	bufoffset;
	ushort_t	csum;
	idn_netaddr_t	dst, daddr;
	procname_t	proc = "idn_recv_mboxdata";

	hdrp = IDN_BUF2HDR(bufp);

	csum = IDN_CKSUM_PKT(hdrp);

	sip = IDN_INST2SIP(channel);
	if (sip == NULL) {
		/*LINTED*/
		sip = IDN_INST2SIP(0);
	}
	ASSERT(sip);

	if (csum != hdrp->b_cksum) {
		PR_DATA("%s: bad checksum(%x) != expected(%x)\n",
		    proc, (uint_t)csum, (uint_t)hdrp->b_cksum);
		IDN_KSTAT_INC(sip, si_crc);
		IDN_KSTAT_INC(sip, si_fcs_errors);
		rv = -1;
		goto recv_err;
	}

	daddr.net.chan = (ushort_t)channel;
	daddr.net.netid = (ushort_t)idn.localid;

	dst.netaddr = hdrp->b_netaddr;
	bufoffset = hdrp->b_offset;

	if (dst.netaddr != daddr.netaddr) {
		PR_DATA("%s: wrong dest netaddr (0x%x), expected (0x%x)\n",
		    proc, dst.netaddr, daddr.netaddr);
		IDN_KSTAT_INC(sip, si_nolink);
		IDN_KSTAT_INC(sip, si_macrcv_errors);
		goto recv_err;
	}
	pktlen  = hdrp->b_length;
	apktlen = pktlen;

	if ((pktlen <= 0) || (pktlen > IDN_DATA_SIZE)) {
		PR_DATA("%s: invalid packet length (%d) <= 0 || > %lu\n",
		    proc, pktlen, IDN_DATA_SIZE);
		IDN_KSTAT_INC(sip, si_buff);
		IDN_KSTAT_INC(sip, si_toolong_errors);
		goto recv_err;
	}

	mp = allocb(apktlen + IDN_ALIGNSIZE, BPRI_LO);
	if (mp == nilp(mblk_t)) {
		PR_DATA("%s: allocb(pkt) failed\n", proc);
		IDN_KSTAT_INC(sip, si_allocbfail);
		IDN_KSTAT_INC(sip, si_norcvbuf);	/* MIB II */
		goto recv_err;
	}
	ASSERT(DB_TYPE(mp) == M_DATA);
	/*
	 * Copy data packet into its streams buffer.
	 * Align pointers for maximum bcopy performance.
	 */
	mp->b_rptr = (uchar_t *)IDN_ALIGNPTR(mp->b_rptr, bufoffset);
	bcopy(IDN_BUF2DATA(bufp, bufoffset), mp->b_rptr, apktlen);
	mp->b_wptr = mp->b_rptr + pktlen;

	if (IDN_CHECKSUM &&
		!idn_valid_etherheader((struct ether_header *)mp->b_rptr)) {
		freeb(mp);
		mp = nilp(mblk_t);
		PR_DATA("%s: etherheader CORRUPTED\n", proc);
		IDN_KSTAT_INC(sip, si_crc);
		IDN_KSTAT_INC(sip, si_fcs_errors);
		rv = -1;
		goto recv_err;
	}

	idndl_read(NULL, mp);

recv_err:

	if (mp == nilp(mblk_t)) {
		IDN_KSTAT_INC(sip, si_ierrors);
	}

	return (rv);
}

/*
 * When on shutdown path (idn_active_resources) must call
 * idn_mainmbox_flush() _BEFORE_ calling idn_reclaim_mboxdata()
 * for any final data.  This is necessary incase the mailboxes
 * have been unregistered.  If they have then idn_mainmbox_flush()
 * will set mm_smr_mboxp to NULL which prevents us from touching
 * poison SMR space.
 */
int
idn_reclaim_mboxdata(int domid, int channel, int nbufs)
{
	idn_mainmbox_t	*mmp;
	idn_mboxmsg_t	*mqp;
	smr_pkthdr_t	*hdrp;
	idn_domain_t	*dp;
	int		qi;
	int		mi;
	int		reclaim_cnt = 0;
	int		free_cnt;
	ushort_t	csum;
	struct idn	*sip;
	smr_offset_t	reclaim_list, curr, prev;
	procname_t	proc = "idn_reclaim_mboxdata";


	sip = IDN_INST2SIP(channel);
	if (sip == NULL) {
		/*LINTED*/
		sip = IDN_INST2SIP(0);
	}
	ASSERT(sip);

	dp = &idn_domain[domid];

	PR_DATA("%s: requested %d buffers from domain %d\n",
	    proc, nbufs, domid);

	if (lock_try(&dp->dreclaim_inprogress) == 0) {
		/*
		 * Reclaim is already in progress, don't
		 * bother.
		 */
		PR_DATA("%s: reclaim already in progress\n", proc);
		return (0);
	}

	if (dp->dmbox.m_send == NULL)
		return (0);

	reclaim_list = curr = prev = IDN_NIL_SMROFFSET;

	mi = (int)dp->dreclaim_index;
	do {
		ushort_t	mbox_csum;

		mmp = &dp->dmbox.m_send[mi];
		/* do-while continues down */
		ASSERT(mmp);
		if (mutex_tryenter(&mmp->mm_mutex) == 0) {
			/*
			 * This channel is busy, move on.
			 */
			IDN_MBOXCHAN_INC(mi);
			continue;
		}

		if (mmp->mm_smr_mboxp == NULL) {
			PR_DATA("%s: no smr pointer for domid %d, chan %d\n",
			    proc, domid, (int)mmp->mm_channel);
			ASSERT(mmp->mm_qiget == mmp->mm_qiput);
			mutex_exit(&mmp->mm_mutex);
			IDN_MBOXCHAN_INC(mi);
			continue;
		}
		mbox_csum = IDN_CKSUM_MBOX(&mmp->mm_smr_mboxp->mt_header);
		if (mbox_csum != mmp->mm_smr_mboxp->mt_header.mh_cksum) {
			PR_DATA("%s: (d %d, chn %d) mbox hdr "
			    "cksum (%d) != actual (%d)\n",
			    proc, domid, (int)mmp->mm_channel, mbox_csum,
			    mmp->mm_smr_mboxp->mt_header.mh_cksum);
			IDN_KSTAT_INC(sip, si_mboxcrc);
			IDN_KSTAT_INC(sip, si_oerrors);
			mutex_exit(&mmp->mm_mutex);
			IDN_MBOXCHAN_INC(mi);
			continue;
		}
		mqp = &mmp->mm_smr_mboxp->mt_queue[0];
		qi  = mmp->mm_qiget;

		while (!mqp[qi].ms_owner &&
		    (mqp[qi].ms_flag & IDN_MBOXMSG_FLAG_RECLAIM) &&
		    nbufs) {
			idn_mboxmsg_t	*msp;
			int		badbuf;

			badbuf = 0;
			msp = &mqp[qi];

			if (msp->ms_flag & IDN_MBOXMSG_FLAG_ERRMASK) {
				PR_DATA("%s: msg.flag ERROR(0x%x) (off=0x%x, "
				    "domid=%d, qiget=%d)\n", proc,
				    (uint_t)(msp->ms_flag &
				    IDN_MBOXMSG_FLAG_ERRMASK),
				    IDN_BFRAME2OFFSET(msp->ms_bframe),
				    domid, qi);
			}
			prev = curr;
			curr = IDN_BFRAME2OFFSET(mqp[qi].ms_bframe);

			if (!VALID_NWROFFSET(curr, IDN_SMR_BUFSIZE)) {
				badbuf = 1;
				IDN_KSTAT_INC(sip, si_reclaim);
			} else {
				/*
				 * Put the buffers onto a list that will be
				 * formally reclaimed down below.  This allows
				 * us to free up mboxq entries as fast as
				 * possible.
				 */
				hdrp = IDN_BUF2HDR(IDN_OFFSET2ADDR(curr));
				csum = IDN_CKSUM_PKT(hdrp);

				if (csum != hdrp->b_cksum) {
					badbuf = 1;
					IDN_KSTAT_INC(sip, si_crc);
					IDN_KSTAT_INC(sip, si_fcs_errors);
					IDN_KSTAT_INC(sip, si_reclaim);
					if (!(mmp->mm_flags &
					    IDNMMBOX_FLAG_CORRUPTED)) {
						cmn_err(CE_WARN,
						    "IDN: 241: [send] "
						    "(domain %d, channel "
						    "%d) SMR CORRUPTED - "
						    "RELINK",
						    domid, channel);
						mmp->mm_flags |=
						    IDNMMBOX_FLAG_CORRUPTED;
					}

				} else if (reclaim_list == IDN_NIL_SMROFFSET) {
					reclaim_list = curr;
				} else {
					caddr_t	bufp;

					bufp = IDN_OFFSET2ADDR(prev);
					hdrp = IDN_BUF2HDR(bufp);
					hdrp->b_next = curr;
				}
			}

			mqp[qi].ms_flag = 0;

			IDN_MMBOXINDEX_INC(qi);

			if (!badbuf) {
				nbufs--;
				reclaim_cnt++;
			}

			if (qi == mmp->mm_qiget)
				break;
		}
		mmp->mm_qiget = qi;

		mutex_exit(&mmp->mm_mutex);

		IDN_MBOXCHAN_INC(mi);

	} while ((mi != (int)dp->dreclaim_index) && nbufs);

	dp->dreclaim_index = (uchar_t)mi;

	if (reclaim_list != IDN_NIL_SMROFFSET) {
		hdrp = IDN_BUF2HDR(IDN_OFFSET2ADDR(curr));
		hdrp->b_next = IDN_NIL_SMROFFSET;
	}

	PR_DATA("%s: reclaimed %d buffers from domain %d\n",
	    proc, reclaim_cnt, domid);

	if (reclaim_cnt == 0) {
		lock_clear(&dp->dreclaim_inprogress);
		return (0);
	}

	/*
	 * Now actually go and reclaim (free) the buffers.
	 */
	free_cnt = 0;

	for (curr = reclaim_list; curr != IDN_NIL_SMROFFSET; ) {
		caddr_t		bufp;

		bufp = IDN_OFFSET2ADDR(curr);
		hdrp = IDN_BUF2HDR(bufp);
		csum = IDN_CKSUM_PKT(hdrp);
		if (csum != hdrp->b_cksum) {
			/*
			 * Once corruption is detected we
			 * can't trust our list any further.
			 * These buffers are effectively lost.
			 */
			cmn_err(CE_WARN,
			    "IDN: 241: [send] (domain %d, channel %d) SMR "
			    "CORRUPTED - RELINK", domid, channel);
			break;
		}

		curr = hdrp->b_next;

		if (!smr_buf_free(domid, bufp, hdrp->b_length))
			free_cnt++;
	}

	if ((dp->dio < IDN_WINDOW_EMAX) && dp->diocheck) {
		lock_clear(&dp->diocheck);
		IDN_MSGTIMER_STOP(domid, IDNP_DATA, 0);
	}

#ifdef DEBUG
	if (free_cnt != reclaim_cnt) {
		PR_DATA("%s: *** WARNING *** freecnt(%d) != reclaim_cnt (%d)\n",
		    proc, free_cnt, reclaim_cnt);
	}
#endif /* DEBUG */

	lock_clear(&dp->dreclaim_inprogress);

	return (reclaim_cnt);
}

void
idn_signal_data_server(int domid, ushort_t channel)
{
	idn_nack_t	nacktype = 0;
	idn_domain_t	*dp;
	idn_chansvr_t	*csp;
	int		c, min_chan, max_chan;
	idn_mainmbox_t	*mmp;
	procname_t	proc = "idn_signal_data_server";


	if (domid == IDN_NIL_DOMID)
		return;

	dp = &idn_domain[domid];

	if (dp->dawol.a_count > 0) {
		/*
		 * Domain was previously AWOL, but no longer.
		 */
		IDN_SYNC_LOCK();
		IDN_GLOCK_EXCL();
		idn_clear_awol(domid);
		IDN_GUNLOCK();
		IDN_SYNC_UNLOCK();
	}
	/*
	 * Do a precheck before wasting time trying to acquire the lock.
	 */
	if ((dp->dstate != IDNDS_CONNECTED) || !IDN_DLOCK_TRY_SHARED(domid)) {
		/*
		 * Either we're not connected or somebody is busy working
		 * on the domain.  Bail on the signal for now, we'll catch
		 * it on the next go around.
		 */
		return;
	}
	/*
	 * We didn't have the drwlock on the first check of dstate,
	 * but now that we do, make sure the world hasn't changed!
	 */
	if (dp->dstate != IDNDS_CONNECTED) {
		/*
		 * If we reach here, then no connection.
		 * Send no response if this is the case.
		 */
		nacktype = IDNNACK_NOCONN;
		goto send_dresp;
	}

	/*
	 * No need to worry about locking mainmbox
	 * because we're already holding reader
	 * lock on domain, plus we're just reading
	 * fields in the mainmbox which only change
	 * (or go away) when the writer lock is
	 * held on the domain.
	 */
	if ((mmp = dp->dmbox.m_recv) == NULL) {
		/*
		 * No local mailbox.
		 */
		nacktype = IDNNACK_BADCFG;
		goto send_dresp;
	}
	if ((channel != IDN_BROADCAST_ALLCHAN) && (channel >= IDN_MAX_NETS)) {
		nacktype = IDNNACK_BADCHAN;
		goto send_dresp;
	}
	if (channel == IDN_BROADCAST_ALLCHAN) {
		PR_DATA("%s: requested signal to ALL channels on domain %d\n",
		    proc, domid);
		min_chan = 0;
		max_chan = IDN_MAX_NETS - 1;
	} else {
		PR_DATA("%s: requested signal to channel %d on domain %d\n",
		    proc, channel, domid);
		min_chan = max_chan = (int)channel;
	}
	mmp += min_chan;
	for (c = min_chan; c <= max_chan; mmp++, c++) {

		/*
		 * We do a quick check for a pending channel.
		 * If pending it will need activation and we rather
		 * do that through a separate (proto) thread.
		 */
		csp = &idn.chan_servers[c];

		if (csp->ch_recv.c_checkin) {
			PR_DATA("%s: chansvr (%d) for domid %d CHECK-IN\n",
			    proc, c, domid);
			continue;
		}

		if (IDN_CHAN_TRYLOCK_RECV(csp) == 0) {
			/*
			 * Failed to grab lock, server must be active.
			 */
			PR_DATA("%s: chansvr (%d) for domid %d already actv\n",
			    proc, c, domid);
			continue;
		}

		if (IDN_CHANNEL_IS_PENDING(csp)) {
			/*
			 * Lock is pending.  Submit asynchronous
			 * job to activate and move-on.
			 */
			IDN_CHAN_UNLOCK_RECV(csp);
			idn_submit_chanactivate_job(c);
			continue;
		}

		/*
		 * If he ain't active, we ain't talkin'.
		 */
		if (IDN_CHANNEL_IS_RECV_ACTIVE(csp) == 0) {
			IDN_CHAN_UNLOCK_RECV(csp);
			PR_DATA("%s: chansvr (%d) for domid %d inactive\n",
			    proc, c, domid);
			continue;
		}

		if (mutex_tryenter(&mmp->mm_mutex) == 0) {
			IDN_CHAN_UNLOCK_RECV(csp);
			continue;
		}

		if (mmp->mm_csp != csp) {
			/*
			 * Not registered.
			 */
			mutex_exit(&mmp->mm_mutex);
			IDN_CHAN_UNLOCK_RECV(csp);
			continue;

		}
		if (mmp->mm_smr_mboxp == NULL) {
			/*
			 * No SMR mailbox.
			 */
			mutex_exit(&mmp->mm_mutex);
			IDN_CHAN_UNLOCK_RECV(csp);
			continue;
		}
		mutex_exit(&mmp->mm_mutex);

		if (csp->ch_recv.c_inprogress) {
			/*
			 * Data server is already active.
			 */
			IDN_CHAN_UNLOCK_RECV(csp);
			PR_DATA("%s: chansvr (%d) for domid %d already actv\n",
			    proc, c, domid);
			continue;
		}
		ASSERT(csp == &idn.chan_servers[c]);


		PR_DATA("%s: signaling data dispatcher for chan %d dom %d\n",
		    proc, c, domid);
		ASSERT(csp);
		cv_signal(&csp->ch_recv_cv);
		IDN_CHAN_UNLOCK_RECV(csp);
	}

	if (!nacktype || (channel == IDN_BROADCAST_ALLCHAN)) {
		/*
		 * If there were no real errors or we were
		 * handling multiple channels, then just
		 * return.
		 */
		IDN_DUNLOCK(domid);
		return;
	}

send_dresp:

	PR_DATA("%s: sending NACK (%s) back to domain %d (cpu %d)\n",
	    proc, idnnack_str[nacktype], domid, idn_domain[domid].dcpu);

	idn_send_dataresp(domid, nacktype);

	IDN_DUNLOCK(domid);
}

/*ARGSUSED*/
static int
idn_recv_data(int domid, idn_msgtype_t *mtp, idn_xdcargs_t xargs)
{
#ifdef DEBUG
	uint_t		msg = mtp ? mtp->mt_mtype : 0;
	uint_t		msgarg = mtp ? mtp->mt_atype : 0;
	procname_t	proc = "idn_recv_data";

	PR_PROTO("%s:%d: DATA message received (msg = 0x%x, msgarg = 0x%x)\n",
	    proc, domid, msg, msgarg);
	PR_PROTO("%s:%d: xargs = (0x%x, 0x%x, 0x%x, 0x%x)\n",
	    proc, domid, xargs[0], xargs[1], xargs[2], xargs[3]);
#endif /* DEBUG */

	return (0);
}

/*
 * Only used when sending a negative response.
 */
static void
idn_send_dataresp(int domid, idn_nack_t nacktype)
{
	idn_msgtype_t	mt;

	ASSERT(IDN_DLOCK_IS_HELD(domid));

	if (idn_domain[domid].dcpu == IDN_NIL_DCPU)
		return;

	mt.mt_mtype = IDNP_NACK;
	mt.mt_atype = IDNP_DATA;

	(void) IDNXDC(domid, &mt, (uint_t)nacktype, 0, 0, 0);
}

/*
 * Checksum routine used in checksum smr_pkthdr_t and idn_mboxhdr_t.
 */
static ushort_t
idn_cksum(register ushort_t *hdrp, register int count)
{
	register int		i;
	register ushort_t	sum = 0;

	for (i = 0; i < count; i++)
		sum += hdrp[i];

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (~sum);
}

/*
 * ------------------------------------------------
 */

int
idn_open_channel(int channel)
{
	int		masterid;
	idn_chansvr_t	*csp;
	struct idn	*sip;
	procname_t	proc = "idn_open_channel";

	if (channel >= IDN_MAX_NETS) {
		cmn_err(CE_WARN,
		    "IDN: 242: maximum channels (%d) already open",
		    IDN_MAX_NETS);
		return (-1);
	}
	IDN_GLOCK_EXCL();

	ASSERT(idn.chan_servers != NULL);

	csp = &idn.chan_servers[channel];

	IDN_CHAN_LOCK_GLOBAL(csp);

	if (IDN_CHANNEL_IS_ATTACHED(csp)) {
		PR_CHAN("%s: channel %d already open\n", proc, channel);
		IDN_CHAN_UNLOCK_GLOBAL(csp);
		IDN_GUNLOCK();
		return (0);
	}

	/*
	 * Need to zero out the kstats now that we're activating
	 * this channel.
	 */
	for (sip = idn.sip; sip; sip = sip->si_nextp) {
		if (sip->si_dip && (ddi_get_instance(sip->si_dip) == channel)) {
			bzero(&sip->si_kstat, sizeof (sip->si_kstat));
			break;
		}
	}

	IDN_CHANSVC_MARK_ATTACHED(csp);
	idn.nchannels++;
	CHANSET_ADD(idn.chanset, channel);
	IDN_CHANNEL_ATTACH(channel);

	IDN_CHAN_UNLOCK_GLOBAL(csp);

	/*
	 * We increase our window threshold each time a channel
	 * is opened.
	 */
	ASSERT(idn.nchannels > 0);
	IDN_WINDOW_EMAX = IDN_WINDOW_MAX +
	    ((idn.nchannels - 1) * IDN_WINDOW_INCR);

	PR_CHAN("%s: channel %d is OPEN (nchannels = %d)\n",
	    proc, channel, idn.nchannels);

	masterid = IDN_GET_MASTERID();
	IDN_GUNLOCK();

	/*
	 * Check if there is an active master to which
	 * we're connected.  If so, then activate channel.
	 */
	if (masterid != IDN_NIL_DOMID) {
		idn_domain_t	*dp;

		dp = &idn_domain[masterid];
		IDN_DLOCK_SHARED(masterid);
		if (dp->dvote.v.master && (dp->dstate == IDNDS_CONNECTED))
			(void) idn_activate_channel(CHANSET(channel),
			    IDNCHAN_ONLINE);
		IDN_DUNLOCK(masterid);
	}

	return (0);
}

void
idn_close_channel(int channel, idn_chanop_t chanop)
{
	idn_chansvr_t	*csp;
	procname_t	proc = "idn_close_channel";


	ASSERT(idn.chan_servers != NULL);

	csp = &idn.chan_servers[channel];

	IDN_GLOCK_EXCL();

	IDN_CHAN_LOCK_GLOBAL(csp);
	if (IDN_CHANNEL_IS_DETACHED(csp)) {
		PR_CHAN("%s: channel %d already closed\n", proc, channel);
		IDN_CHAN_UNLOCK_GLOBAL(csp);
		IDN_GUNLOCK();
		return;
	}
	IDN_CHAN_UNLOCK_GLOBAL(csp);

	idn_deactivate_channel(CHANSET(channel), chanop);

	IDN_CHAN_LOCK_GLOBAL(csp);

	if (chanop == IDNCHAN_HARD_CLOSE) {
		idn.nchannels--;
		CHANSET_DEL(idn.chanset, channel);
		/*
		 * We increase our window threshold each time a channel
		 * is opened.
		 */
		if (idn.nchannels <= 0)
			IDN_WINDOW_EMAX = 0;
		else
			IDN_WINDOW_EMAX = IDN_WINDOW_MAX +
			    ((idn.nchannels - 1) * IDN_WINDOW_INCR);
	}

	PR_CHAN("%s: channel %d is (%s) CLOSED (nchannels = %d)\n",
	    proc, channel,
	    (chanop == IDNCHAN_SOFT_CLOSE) ? "SOFT"
	    : (chanop == IDNCHAN_HARD_CLOSE) ? "HARD" : "OFFLINE",
	    idn.nchannels);

	IDN_CHAN_UNLOCK_GLOBAL(csp);
	IDN_GUNLOCK();
}

static int
idn_activate_channel(idn_chanset_t chanset, idn_chanop_t chanop)
{
	int		c, rv = 0;
	procname_t	proc = "idn_activate_channel";

	PR_CHAN("%s: chanset = 0x%x, chanop = %s\n",
	    proc, chanset, chanop_str[chanop]);

	if (idn.state != IDNGS_ONLINE) {
		/*
		 * Can't activate any channels unless local
		 * domain is connected and thus has a master.
		 */
		PR_CHAN("%s: local domain not connected.  no data servers\n",
		    proc);
		return (-1);
	}

	for (c = 0; c < IDN_MAX_NETS; c++) {
		idn_chansvr_t	*csp;
		idn_mboxhdr_t	*mainhp;
		struct idn	*sip;

		if (!CHAN_IN_SET(chanset, c))
			continue;
		csp = &idn.chan_servers[c];

		if (chanop == IDNCHAN_ONLINE) {
			IDN_CHAN_LOCK_GLOBAL(csp);
		} else {
			/*
			 * We don't wait to grab the global lock
			 * if IDNCHAN_OPEN since these occur along
			 * critical data paths and will be retried
			 * anyway if needed.
			 */
			if (IDN_CHAN_TRYLOCK_GLOBAL(csp) == 0) {
				PR_CHAN("%s: failed to acquire global "
				    "lock for channel %d\n",
				    proc, c);
				continue;
			}
		}

		if (!IDN_CHANNEL_IS_ATTACHED(csp)) {
			PR_CHAN("%s: channel %d NOT open\n", proc, c);
			IDN_CHAN_UNLOCK_GLOBAL(csp);
			continue;

		}

		if (IDN_CHANNEL_IS_ACTIVE(csp)) {

			PR_CHAN("%s: channel %d already active\n", proc, c);
			rv++;
			IDN_CHAN_UNLOCK_GLOBAL(csp);
			continue;

		}
		/*
		 * Channel activation can happen asynchronously.
		 */
		IDN_CHANNEL_SUSPEND(c, 0);

		if (IDN_CHANNEL_IS_PENDING(csp) && (chanop == IDNCHAN_OPEN)) {

			PR_CHAN("%s: ACTIVATING channel %d\n", proc, c);

			if (idn_activate_channel_services(c) >= 0) {
				PR_CHAN("%s: Setting channel %d ACTIVE\n",
				    proc, c);
				IDN_CHANSVC_MARK_ACTIVE(csp);
				rv++;
			}
		} else if (!IDN_CHANNEL_IS_PENDING(csp) &&
		    (chanop == IDNCHAN_ONLINE)) {
			PR_CHAN("%s: Setting channel %d PENDING\n", proc, c);

			IDN_CHANSVC_MARK_PENDING(csp);
		}
		/*
		 * Don't syncheader (i.e. touch SMR) unless
		 * channel is at least ENABLED.  For a DISABLED
		 * channel, the SMR may be invalid so do NOT
		 * touch it.
		 */
		if (IDN_CHANNEL_IS_ENABLED(csp) &&
		    ((mainhp = idn_chan_server_syncheader(c)) != NULL)) {
			PR_CHAN("%s: marking chansvr (mhp=0x%p) %d READY\n",
			    proc, (void *)mainhp, c);
			mainhp->mh_svr_ready = 1;
		}

		IDN_CHANNEL_RESUME(c);
		sip = IDN_INST2SIP(c);
		ASSERT(sip);
		if (sip->si_wantw) {
			mutex_enter(&idn.sipwenlock);
			idndl_wenable(sip);
			mutex_exit(&idn.sipwenlock);
		}
		IDN_CHAN_UNLOCK_GLOBAL(csp);

	}
	/*
	 * Returns "not active", i.e. value of 0 indicates
	 * no channels are activated.
	 */
	return (rv == 0);
}

static void
idn_deactivate_channel(idn_chanset_t chanset, idn_chanop_t chanop)
{
	int		c;
	procname_t	proc = "idn_deactivate_channel";

	PR_CHAN("%s: chanset = 0x%x, chanop = %s\n",
	    proc, chanset, chanop_str[chanop]);

	for (c = 0; c < IDN_MAX_NETS; c++) {
		idn_chansvr_t	*csp;
		idn_mboxhdr_t	*mainhp;

		if (!CHAN_IN_SET(chanset, c))
			continue;

		csp = &idn.chan_servers[c];

		IDN_CHAN_LOCK_GLOBAL(csp);

		if (((chanop == IDNCHAN_SOFT_CLOSE) &&
		    !IDN_CHANNEL_IS_ACTIVE(csp)) ||
		    ((chanop == IDNCHAN_HARD_CLOSE) &&
		    IDN_CHANNEL_IS_DETACHED(csp)) ||
		    ((chanop == IDNCHAN_OFFLINE) &&
		    !IDN_CHANNEL_IS_ENABLED(csp))) {

			ASSERT(!IDN_CHANNEL_IS_RECV_ACTIVE(csp));
			ASSERT(!IDN_CHANNEL_IS_SEND_ACTIVE(csp));

			PR_CHAN("%s: channel %d already deactivated\n",
			    proc, c);
			IDN_CHAN_UNLOCK_GLOBAL(csp);
			continue;
		}

		switch (chanop) {
		case IDNCHAN_OFFLINE:
			IDN_CHANSVC_MARK_IDLE(csp);
			IDN_CHANSVC_MARK_DISABLED(csp);
			IDN_CHANNEL_STOP(c, 1);
			mainhp = idn_chan_server_syncheader(c);
			if (mainhp != NULL)
				mainhp->mh_svr_ready = 0;
			break;

		case IDNCHAN_HARD_CLOSE:
			IDN_CHANSVC_MARK_DETACHED(csp);
			IDN_CHANNEL_DETACH(c, 1);
			mainhp = idn_chan_server_syncheader(c);
			if (mainhp != NULL)
				mainhp->mh_svr_ready = 0;
			break;

		default:
			IDN_CHANSVC_MARK_IDLE(csp);
			IDN_CHANNEL_SUSPEND(c, 1);
			ASSERT(IDN_CHANNEL_IS_ATTACHED(csp));
			break;
		}

		lock_clear(&csp->ch_actvlck);
		lock_clear(&csp->ch_initlck);

		PR_CHAN("%s: DEACTIVATING channel %d (%s)\n", proc, c,
		    chanop_str[chanop]);
		PR_CHAN("%s: removing chanset 0x%x data svrs for "
		    "each domain link\n", proc, chanset);

		(void) idn_deactivate_channel_services(c, chanop);
	}
	/*
	 * Returns with channels unlocked.
	 */
}

/*
 * The priority of the channel server must be less than that
 * of the protocol server since the protocol server tasks
 * are (can be) of more importance.
 *
 * Possible range: 60-99.
 */
static pri_t	idn_chansvr_pri = (7 * MAXCLSYSPRI) / 8;

static int
idn_activate_channel_services(int channel)
{
	idn_chansvr_t	*csp;
	procname_t	proc = "idn_activate_channel_services";


	ASSERT((channel >= 0) && (channel < IDN_MAX_NETS));

	csp = &idn.chan_servers[channel];

	ASSERT(IDN_CHAN_GLOBAL_IS_LOCKED(csp));
	ASSERT(IDN_CHAN_LOCAL_IS_LOCKED(csp));

	if (csp->ch_recv_threadp) {
		/*
		 * There's an existing dispatcher!
		 * Must have been idle'd during an earlier
		 * stint.
		 */
		ASSERT(csp->ch_id == (uchar_t)channel);
		PR_CHAN("%s: existing chansvr FOUND for (c=%d)\n",
		    proc, channel);

		if (IDN_CHANNEL_IS_PENDING(csp) == 0)
			return (-1);

		PR_CHAN("%s: chansvr (c=%d) Rstate = 0x%x, Sstate = 0x%x\n",
		    proc, channel, csp->ch_recv.c_state,
		    csp->ch_send.c_state);

		cv_signal(&csp->ch_recv_cv);

		return (0);
	}

	if (IDN_CHANNEL_IS_PENDING(csp) == 0)
		return (-1);

	csp->ch_id = (uchar_t)channel;

	PR_CHAN("%s: init channel %d server\n", proc, channel);

	csp->ch_recv_morguep = GETSTRUCT(ksema_t, 1);
	sema_init(csp->ch_recv_morguep, 0, NULL, SEMA_DRIVER, NULL);

	csp->ch_recv.c_inprogress = 0;
	csp->ch_recv.c_waiters = 0;
	csp->ch_recv.c_checkin = 0;
	csp->ch_recv_changed = 1;

	csp->ch_recv_domset = csp->ch_reg_domset;

	csp->ch_recv_waittime = IDN_NETSVR_WAIT_MIN;

	csp->ch_recv_threadp = thread_create(NULL, 0,
	    idn_chan_server, &csp, sizeof (csp), &p0, TS_RUN, idn_chansvr_pri);

	csp->ch_send.c_inprogress = 0;
	csp->ch_send.c_waiters = 0;
	csp->ch_send.c_checkin = 0;

	return (0);
}

/*
 * This routine can handle terminating a set of channel
 * servers all at once, however currently only used
 * for serial killing, i.e. one-at-a-time.
 *
 * Entered with RECV locks held on chanset.
 * Acquires SEND locks if needed.
 * Leaves with all RECV and SEND locks dropped.
 */
static int
idn_deactivate_channel_services(int channel, idn_chanop_t chanop)
{
	idn_chansvr_t	*csp;
	int		cs_count;
	int		c;
	idn_chanset_t	chanset;
	ksema_t		*central_morguep = NULL;
	procname_t	proc = "idn_deactivate_channel_services";


	ASSERT(idn.chan_servers);

	PR_CHAN("%s: deactivating channel %d services\n", proc, channel);

	/*
	 * XXX
	 * Old code allowed us to deactivate multiple channel
	 * servers at once.  Keep for now just in case.
	 */
	chanset = CHANSET(channel);

	/*
	 * Point all the data dispatchers to the same morgue
	 * so we can kill them all at once.
	 */
	cs_count = 0;
	for (c = 0; c < IDN_MAX_NETS; c++) {
		if (!CHAN_IN_SET(chanset, c))
			continue;

		csp = &idn.chan_servers[c];
		ASSERT(IDN_CHAN_GLOBAL_IS_LOCKED(csp));
		ASSERT(IDN_CHAN_LOCAL_IS_LOCKED(csp));

		if (csp->ch_recv_threadp == NULL) {
			/*
			 * No channel server home.
			 * But we're still holding the c_mutex.
			 * At mark him idle incase we start him up.
			 */
			PR_CHAN("%s: no channel server found for chan %d\n",
			    proc, c);
			IDN_CHAN_UNLOCK_LOCAL(csp);
			IDN_CHAN_UNLOCK_GLOBAL(csp);
			continue;
		}
		ASSERT(csp->ch_id == (uchar_t)c);

		/*
		 * Okay, now we've blocked the send and receive sides.
		 */

		if ((chanop == IDNCHAN_SOFT_CLOSE) ||
		    (chanop == IDNCHAN_OFFLINE)) {
			/*
			 * We set turned off the ACTIVE flag, but there's
			 * no guarantee he stopped because of it.  He may
			 * have already been sleeping.  We need to be
			 * sure he recognizes the IDLE, so we need to
			 * signal him and give him a chance to see it.
			 */
			cv_signal(&csp->ch_recv_cv);
			IDN_CHAN_UNLOCK_LOCAL(csp);
			IDN_CHAN_UNLOCK_GLOBAL(csp);
			cs_count++;
			continue;
		}

		PR_CHAN("%s: pointing chansvr %d to morgue (0x%p)\n",
		    proc, c, central_morguep ? (void *)central_morguep
		    : (void *)(csp->ch_recv_morguep));

		if (central_morguep == NULL) {
			central_morguep = csp->ch_recv_morguep;
		} else {
			sema_destroy(csp->ch_recv_morguep);
			FREESTRUCT(csp->ch_recv_morguep, ksema_t, 1);

			csp->ch_recv_morguep = central_morguep;
		}
		cv_signal(&csp->ch_recv_cv);
		if (csp->ch_recv.c_waiters > 0)
			cv_broadcast(&csp->ch_recv.c_cv);
		/*
		 * Save any existing binding for next reincarnation.
		 * Note that we're holding the local and global
		 * locks so we're protected against others touchers
		 * of the ch_bound_cpuid fields.
		 */
		csp->ch_bound_cpuid_pending = csp->ch_bound_cpuid;
		csp->ch_bound_cpuid = -1;
		IDN_CHAN_UNLOCK_LOCAL(csp);
		IDN_CHAN_UNLOCK_GLOBAL(csp);
		cs_count++;
	}
	PR_CHAN("%s: signaled %d chansvrs for chanset 0x%x\n",
	    proc, cs_count, chanset);

	if ((chanop == IDNCHAN_SOFT_CLOSE) || (chanop == IDNCHAN_OFFLINE))
		return (cs_count);

	PR_CHAN("%s: waiting for %d (chnset=0x%x) chan svrs to term\n",
	    proc, cs_count, chanset);
	PR_CHAN("%s: morguep = 0x%p\n", proc, (void *)central_morguep);

	ASSERT((cs_count > 0) ? (central_morguep != NULL) : 1);
	while (cs_count-- > 0)
		sema_p(central_morguep);

	if (central_morguep) {
		sema_destroy(central_morguep);
		FREESTRUCT(central_morguep, ksema_t, 1);
	}

	return (cs_count);
}

int
idn_chanservers_init()
{
	int		c;
	idn_chansvr_t	*csp;


	if (idn.chan_servers)
		return (0);

	idn.chan_servers = GETSTRUCT(idn_chansvr_t, IDN_MAXMAX_NETS);

	for (c = 0; c < IDN_MAXMAX_NETS; c++) {
		csp = &idn.chan_servers[c];
		mutex_init(&csp->ch_send.c_mutex, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&csp->ch_recv.c_mutex, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&csp->ch_send.c_cv, NULL, CV_DRIVER, NULL);
		cv_init(&csp->ch_recv.c_cv, NULL, CV_DRIVER, NULL);
		cv_init(&csp->ch_recv_cv, NULL, CV_DRIVER, NULL);
		csp->ch_bound_cpuid = -1;
		csp->ch_bound_cpuid_pending = -1;
	}

	return (c);
}

void
idn_chanservers_deinit()
{
	int		c;
	idn_chansvr_t	*csp;


	if (idn.chan_servers == NULL)
		return;

	for (c = 0; c < IDN_MAXMAX_NETS; c++) {
		csp = &idn.chan_servers[c];

		mutex_destroy(&csp->ch_send.c_mutex);
		mutex_destroy(&csp->ch_recv.c_mutex);
		cv_destroy(&csp->ch_send.c_cv);
		cv_destroy(&csp->ch_recv.c_cv);
		cv_destroy(&csp->ch_recv_cv);
	}

	FREESTRUCT(idn.chan_servers, idn_chansvr_t, IDN_MAXMAX_NETS);
	idn.chan_servers = NULL;
}

static void
idn_exec_chanactivate(void *chn)
{
	int		not_active, channel;
	idn_chansvr_t	*csp;

	channel = (int)(uintptr_t)chn;

	IDN_GLOCK_SHARED();
	if (idn.chan_servers == NULL) {
		IDN_GUNLOCK();
		return;
	}
	csp = &idn.chan_servers[channel];

	if (IDN_CHAN_TRYLOCK_GLOBAL(csp) == 0) {
		/*
		 * If we can't grab the global lock, then
		 * something is up, skip out.
		 */
		IDN_GUNLOCK();
		return;
	}
	IDN_GUNLOCK();

	if (IDN_CHANNEL_IS_PENDING(csp) && lock_try(&csp->ch_actvlck)) {
		IDN_CHAN_UNLOCK_GLOBAL(csp);
		not_active = idn_activate_channel(CHANSET(channel),
		    IDNCHAN_OPEN);
		if (not_active)
			lock_clear(&csp->ch_actvlck);
	} else {
		IDN_CHAN_UNLOCK_GLOBAL(csp);
	}
}

/*
 * Delayed activation of channel.  We don't want to do this within
 * idn_signal_data_server() since that's called within the context
 * of an XDC handler so we submit it as a timeout() call to be short
 * as soon as possible.
 * The ch_initlck & ch_actvlck are used to synchronize activation
 * of the channel so that we don't have multiple idn_activate_channel's
 * attempting to activate the same channel.
 */
static void
idn_submit_chanactivate_job(int channel)
{
	idn_chansvr_t	*csp;

	if (idn.chan_servers == NULL)
		return;
	csp = &idn.chan_servers[channel];

	if (lock_try(&csp->ch_initlck) == 0)
		return;

	(void) timeout(idn_exec_chanactivate, (caddr_t)(uintptr_t)channel, 1);
}

/*ARGSUSED0*/
static void
idn_xmit_monitor(void *unused)
{
	int		c, d;
	idn_chansvr_t	*csp;
	idn_chanset_t	wake_set;
	domainset_t	conset;
	smr_slab_t	*sp;
	procname_t	proc = "idn_xmit_monitor";

	CHANSET_ZERO(wake_set);

	mutex_enter(&idn.xmit_lock);
	if ((idn.xmit_tid == NULL) || !idn.xmit_chanset_wanted) {
		idn.xmit_tid = NULL;
		mutex_exit(&idn.xmit_lock);
		PR_XMON("%s: bailing out\n", proc);
		return;
	}

	/*
	 * No point in transmitting unless state
	 * is ONLINE.
	 */
	if (idn.state != IDNGS_ONLINE)
		goto retry;

	conset = idn.domset.ds_connected;

	/*
	 * Try and reclaim some buffers if possible.
	 */
	for (d = 0; d < MAX_DOMAINS; d++) {
		if (!DOMAIN_IN_SET(conset, d))
			continue;

		if (!IDN_DLOCK_TRY_SHARED(d))
			continue;

		if (idn_domain[d].dcpu != IDN_NIL_DCPU)
			(void) idn_reclaim_mboxdata(d, 0, -1);

		IDN_DUNLOCK(d);
	}

	/*
	 * Now check if we were successful in getting
	 * any buffers.
	 */
	DSLAB_LOCK_SHARED(idn.localid);
	sp = idn_domain[idn.localid].dslab;
	for (; sp; sp = sp->sl_next)
		if (sp->sl_free)
			break;
	DSLAB_UNLOCK(idn.localid);

	/*
	 * If there are no buffers available,
	 * no point in reenabling the queues.
	 */
	if (sp == NULL)
		goto retry;

	CHANSET_ZERO(wake_set);
	for (c = 0; c < IDN_MAX_NETS; c++) {
		int		pending_bits;
		struct idn	*sip;

		if (!CHAN_IN_SET(idn.xmit_chanset_wanted, c))
			continue;

		csp = &idn.chan_servers[c];
		if (!IDN_CHAN_TRYLOCK_GLOBAL(csp))
			continue;

		pending_bits = csp->ch_state & IDN_CHANSVC_PENDING_BITS;

		sip = IDN_INST2SIP(c);

		if (!csp->ch_send.c_checkin &&
		    (pending_bits == IDN_CHANSVC_PENDING_BITS) &&
		    sip && (sip->si_flags & IDNRUNNING)) {

			IDN_CHAN_UNLOCK_GLOBAL(csp);
			CHANSET_ADD(wake_set, c);

			PR_XMON("%s: QENABLE for channel %d\n", proc, c);

			rw_enter(&idn.struprwlock, RW_READER);
			mutex_enter(&idn.sipwenlock);
			idndl_wenable(sip);
			mutex_exit(&idn.sipwenlock);
			rw_exit(&idn.struprwlock);
		} else {
			IDN_CHAN_UNLOCK_GLOBAL(csp);
		}
	}

	/*
	 * Clear the channels we enabled.
	 */
	idn.xmit_chanset_wanted &= ~wake_set;

retry:

	if (idn.xmit_chanset_wanted == 0)
		idn.xmit_tid = NULL;
	else
		idn.xmit_tid = timeout(idn_xmit_monitor, NULL,
		    idn_xmit_monitor_freq);

	mutex_exit(&idn.xmit_lock);
}

void
idn_xmit_monitor_kickoff(int chan_wanted)
{
	procname_t	proc = "idn_xmit_monitor_kickoff";

	mutex_enter(&idn.xmit_lock);

	if (chan_wanted < 0) {
		/*
		 * Wants all channels.
		 */
		idn.xmit_chanset_wanted = CHANSET_ALL;
	} else {
		CHANSET_ADD(idn.xmit_chanset_wanted, chan_wanted);
	}

	if (idn.xmit_tid != (timeout_id_t)NULL) {
		/*
		 * A monitor is already running, so
		 * he will catch the new "wants" when
		 * he comes around.
		 */
		mutex_exit(&idn.xmit_lock);
		return;
	}

	PR_XMON("%s: xmit_mon kicked OFF (chanset = 0x%x)\n",
	    proc, idn.xmit_chanset_wanted);

	idn.xmit_tid = timeout(idn_xmit_monitor, NULL, idn_xmit_monitor_freq);

	mutex_exit(&idn.xmit_lock);
}
