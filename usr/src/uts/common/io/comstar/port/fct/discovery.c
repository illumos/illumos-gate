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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/disp.h>
#include <sys/byteorder.h>
#include <sys/varargs.h>
#include <sys/atomic.h>
#include <sys/sdt.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/fct.h>
#include <sys/fctio.h>

#include "fct_impl.h"
#include "discovery.h"

disc_action_t fct_handle_local_port_event(fct_i_local_port_t *iport);
disc_action_t fct_walk_discovery_queue(fct_i_local_port_t *iport);
disc_action_t fct_process_els(fct_i_local_port_t *iport,
    fct_i_remote_port_t *irp);
fct_status_t fct_send_accrjt(fct_cmd_t *cmd, uint8_t accrjt,
    uint8_t reason, uint8_t expl);
disc_action_t fct_link_init_complete(fct_i_local_port_t *iport);
fct_status_t fct_complete_previous_li_cmd(fct_i_local_port_t *iport);
fct_status_t fct_sol_plogi(fct_i_local_port_t *iport, uint32_t id,
    fct_cmd_t **ret_ppcmd, int implicit);
fct_status_t fct_sol_ct(fct_i_local_port_t *iport, uint32_t id,
    fct_cmd_t **ret_ppcmd, uint16_t opcode);
fct_status_t fct_ns_scr(fct_i_local_port_t *iport, uint32_t id,
    fct_cmd_t **ret_ppcmd);
static disc_action_t fct_check_cmdlist(fct_i_local_port_t *iport);
static disc_action_t fct_check_solcmd_queue(fct_i_local_port_t *iport);
static void fct_rscn_verify(fct_i_local_port_t *iport,
    uint8_t *rscn_req_payload, uint32_t rscn_req_size);
void fct_gid_cb(fct_i_cmd_t *icmd);

char *fct_els_names[] = { 0, "LS_RJT", "ACC", "PLOGI", "FLOGI", "LOGO",
				"ABTX", "RCS", "RES", "RSS", "RSI", "ESTS",
				"ESTC", "ADVC", "RTV", "RLS",
	/* 0x10 */		"ECHO", "TEST", "RRQ", "REC", "SRR", 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0x20 */		"PRLI", "PRLO", "SCN", "TPLS",
				"TPRLO", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0x30 */		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0x40 */		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0x50 */		"PDISC", "FDISC", "ADISC", "RNC", "FARP",
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0x60 */		"FAN", "RSCN", "SCR", 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0,
	/* 0x70 */		"LINIT", "LPC", "LSTS", 0, 0, 0, 0, 0,
				"RNID", "RLIR", "LIRR", 0, 0, 0, 0, 0
		};

extern uint32_t fct_rscn_options;

/*
 * NOTE: if anybody drops the iport_worker_lock then they should not return
 * DISC_ACTION_NO_WORK. Which also means, dont drop the lock if you have
 * nothing to do. Or else return DISC_ACTION_RESCAN or DISC_ACTION_DELAY_RESCAN.
 * But you cannot be infinitly returning those so have some logic to
 * determine that there is nothing to do without dropping the lock.
 */
void
fct_port_worker(void *arg)
{
	fct_local_port_t	*port = (fct_local_port_t *)arg;
	fct_i_local_port_t	*iport = (fct_i_local_port_t *)
	    port->port_fct_private;
	disc_action_t		suggested_action;
	clock_t			dl, short_delay, long_delay;
	int64_t			tmp_delay;

	iport->iport_cmdcheck_clock = ddi_get_lbolt() +
	    drv_usectohz(FCT_CMDLIST_CHECK_SECONDS * 1000000);
	short_delay = drv_usectohz(10000);
	long_delay = drv_usectohz(1000000);

	stmf_trace(iport->iport_alias, "iport is %p", iport);
	/* Discovery loop */
	mutex_enter(&iport->iport_worker_lock);
	atomic_or_32(&iport->iport_flags, IPORT_WORKER_RUNNING);
	while ((iport->iport_flags & IPORT_TERMINATE_WORKER) == 0) {
		suggested_action = DISC_ACTION_NO_WORK;
		/*
		 * Local port events are of the highest prioriy
		 */
		if (iport->iport_event_head) {
			suggested_action |= fct_handle_local_port_event(iport);
		}

		/*
		 * We could post solicited ELSes to discovery queue.
		 * solicited CT will be processed inside fct_check_solcmd_queue
		 */
		if (iport->iport_solcmd_queue) {
			suggested_action |= fct_check_solcmd_queue(iport);
		}

		/*
		 * All solicited and unsolicited ELS will be handled here
		 */
		if (iport->iport_rpwe_head) {
			suggested_action |= fct_walk_discovery_queue(iport);
		}

		/*
		 * We only process it when there's no outstanding link init CMD
		 */
		if ((iport->iport_link_state ==	PORT_STATE_LINK_INIT_START) &&
		    !(iport->iport_li_state & (LI_STATE_FLAG_CMD_WAITING |
		    LI_STATE_FLAG_NO_LI_YET))) {
			suggested_action |= fct_process_link_init(iport);
		}

		/*
		 * We process cmd aborting in the end
		 */
		if (iport->iport_abort_queue) {
			suggested_action |= fct_cmd_terminator(iport);
		}

		/*
		 * Check cmd max/free
		 */
		if (iport->iport_cmdcheck_clock <= ddi_get_lbolt()) {
			suggested_action |= fct_check_cmdlist(iport);
			iport->iport_cmdcheck_clock = ddi_get_lbolt() +
			    drv_usectohz(FCT_CMDLIST_CHECK_SECONDS * 1000000);
			iport->iport_max_active_ncmds = 0;
		}

		if (iport->iport_offline_prstate != FCT_OPR_DONE) {
			suggested_action |= fct_handle_port_offline(iport);
		}

		if (suggested_action & DISC_ACTION_RESCAN) {
			continue;
		} else if (suggested_action & DISC_ACTION_DELAY_RESCAN) {
			/*
			 * This is not very optimum as whoever returned
			 * DISC_ACTION_DELAY_RESCAN must have dropped the lock
			 * and more things might have queued up. But since
			 * we are only doing small delays, it only delays
			 * things by a few ms, which is okey.
			 */
			if (suggested_action & DISC_ACTION_USE_SHORT_DELAY) {
				dl = short_delay;
			} else {
				dl = long_delay;
			}
			atomic_or_32(&iport->iport_flags,
			    IPORT_WORKER_DOING_TIMEDWAIT);
			(void) cv_reltimedwait(&iport->iport_worker_cv,
			    &iport->iport_worker_lock, dl, TR_CLOCK_TICK);
			atomic_and_32(&iport->iport_flags,
			    ~IPORT_WORKER_DOING_TIMEDWAIT);
		} else {
			atomic_or_32(&iport->iport_flags,
			    IPORT_WORKER_DOING_WAIT);
			tmp_delay = (int64_t)(iport->iport_cmdcheck_clock -
			    ddi_get_lbolt());
			if (tmp_delay < 0) {
				tmp_delay = (int64_t)short_delay;
			}
			(void) cv_reltimedwait(&iport->iport_worker_cv,
			    &iport->iport_worker_lock, (clock_t)tmp_delay,
			    TR_CLOCK_TICK);
			atomic_and_32(&iport->iport_flags,
			    ~IPORT_WORKER_DOING_WAIT);
		}
	}

	atomic_and_32(&iport->iport_flags, ~IPORT_WORKER_RUNNING);
	mutex_exit(&iport->iport_worker_lock);
}

static char *topologies[] = { "Unknown", "Direct Pt-to-Pt", "Private Loop",
				"Unknown", "Unknown", "Fabric Pt-to-Pt",
				"Public Loop" };

void
fct_li_to_txt(fct_link_info_t *li, char *topology, char *speed)
{
	uint8_t s = li->port_speed;

	if (li->port_topology > PORT_TOPOLOGY_PUBLIC_LOOP) {
		(void) sprintf(topology, "Invalid %02x", li->port_topology);
	} else {
		(void) strcpy(topology, topologies[li->port_topology]);
	}

	if ((s == 0) || ((s & 0xf00) != 0) || ((s & (s - 1)) != 0)) {
		speed[0] = '?';
	} else if (s == PORT_SPEED_10G) {
		speed[0] = '1';
		speed[1] = '0';
		speed[2] = 'G';
		speed[3] = 0;
	} else {
		speed[0] = '0' + li->port_speed;
		speed[1] = 'G';
		speed[2] = 0;
	}
}

/*
 * discovery lock held.
 * XXX: Implement command cleanup upon Link down.
 * XXX: Implement a clean start and FC-GS registrations upon Link up.
 *
 * ================ Local Port State Machine ============
 * <hba fatal>		 <Link up>---|
 *   |				     v
 *   |	      <Start>--->[LINK_DOWN]--->[LINK_INIT_START]--->[LINK_INIT_DONE]
 *   |			  ^    ^		  ^    |		   |
 *   |		      |---|    |  |--<Link down>  |-|  |---><Link Reset><--|
 *   |		      |	       |  v		    |	       v
 *   |->[FATAL_CLEANING]  [LINK_DOWN_CLEANING]--->[LINK_UP_CLEANING]
 *					       ^
 *					       |--<Link up>
 * =======================================================
 * An explicit port_online() is only allowed in LINK_DOWN state.
 * An explicit port_offline() is only allowed in LINKDOWN and
 * LINK_INIT_DONE state.
 */
disc_action_t
fct_handle_local_port_event(fct_i_local_port_t *iport)
{
	disc_action_t	ret = DISC_ACTION_RESCAN;
	fct_i_event_t	*in;
	uint16_t	old_state, new_state, new_bits;
	int		dqueue_and_free = 1;
	int		retry_implicit_logo = 0;

	if (iport->iport_event_head == NULL)
		return (DISC_ACTION_NO_WORK);
	in = iport->iport_event_head;
	mutex_exit(&iport->iport_worker_lock);

	rw_enter(&iport->iport_lock, RW_WRITER);

	if (in->event_type == FCT_EVENT_LINK_UP) {
		DTRACE_FC_1(link__up, fct_i_local_port_t, iport);
	} else if (in->event_type == FCT_EVENT_LINK_DOWN) {
		DTRACE_FC_1(link__down, fct_i_local_port_t, iport);
	}

	/* Calculate new state */
	new_state = iport->iport_link_state;

	if (in->event_type == FCT_EVENT_LINK_DOWN) {
		new_state = PORT_STATE_LINK_DOWN_CLEANING;
	} else if (in->event_type == FCT_EVENT_LINK_UP) {
		if (iport->iport_link_state == PORT_STATE_LINK_DOWN_CLEANING)
			new_state = PORT_STATE_LINK_UP_CLEANING;
		else if (iport->iport_link_state == PORT_STATE_LINK_DOWN)
			new_state = PORT_STATE_LINK_INIT_START;
		else { /* This should not happen */
			stmf_trace(iport->iport_alias,
			    "Link up received when link state was"
			    "%x, Ignoring...", iport->iport_link_state);
		}
	} else if (in->event_type == FCT_I_EVENT_CLEANUP_POLL) {
		if (!fct_local_port_cleanup_done(iport)) {
			if (iport->iport_link_cleanup_retry >= 3) {
				iport->iport_link_cleanup_retry = 0;
				retry_implicit_logo = 1;
			} else {
				iport->iport_link_cleanup_retry++;
			}
			dqueue_and_free = 0;
			ret = DISC_ACTION_DELAY_RESCAN;
		} else {
			if (iport->iport_link_state ==
			    PORT_STATE_LINK_DOWN_CLEANING) {
				new_state = PORT_STATE_LINK_DOWN;
			} else if (iport->iport_link_state ==
			    PORT_STATE_LINK_UP_CLEANING) {
				new_state = PORT_STATE_LINK_INIT_START;
			} else { /* This should not have happened */
				cmn_err(CE_WARN, "port state changed to %x "
				    "during cleanup", iport->iport_link_state);
				new_state = PORT_STATE_LINK_DOWN;
			}
		}
	} else if (in->event_type == FCT_EVENT_LINK_RESET) {
		/* Link reset is only allowed when we are Online */
		if (iport->iport_link_state & S_LINK_ONLINE) {
			new_state = PORT_STATE_LINK_UP_CLEANING;
		}
	} else if (in->event_type == FCT_I_EVENT_LINK_INIT_DONE) {
		if (iport->iport_link_state == PORT_STATE_LINK_INIT_START) {
			new_state = PORT_STATE_LINK_INIT_DONE;
			iport->iport_li_state = LI_STATE_START;
		}
	} else {
		ASSERT(0);
	}
	new_bits = iport->iport_link_state ^
	    (iport->iport_link_state | new_state);
	old_state = iport->iport_link_state;
	iport->iport_link_state = new_state;
	rw_exit(&iport->iport_lock);

	stmf_trace(iport->iport_alias, "port state change from %x to %x",
	    old_state, new_state);

	if (new_bits & S_PORT_CLEANUP) {
		(void) fct_implicitly_logo_all(iport, 0);
		fct_handle_event(iport->iport_port,
		    FCT_I_EVENT_CLEANUP_POLL, 0, 0);
	}
	if (retry_implicit_logo) {
		(void) fct_implicitly_logo_all(iport, 1);
	}
	if (new_bits & S_INIT_LINK) {
		fct_link_info_t *li = &iport->iport_link_info;
		fct_status_t li_ret;
		iport->iport_li_state |= LI_STATE_FLAG_NO_LI_YET;
		bzero(li, sizeof (*li));
		if ((li_ret = iport->iport_port->port_get_link_info(
		    iport->iport_port, li)) != FCT_SUCCESS) {
			stmf_trace(iport->iport_alias, "iport-%p: "
			    "port_get_link_info failed, ret %llx, forcing "
			    "link down.", iport, li_ret);
			fct_handle_event(iport->iport_port,
			    FCT_EVENT_LINK_DOWN, 0, 0);
		} else {
			iport->iport_login_retry = 0;
			/* This will reset LI_STATE_FLAG_NO_LI_YET */
			iport->iport_li_state = LI_STATE_START;
			atomic_or_32(&iport->iport_flags,
			    IPORT_ALLOW_UNSOL_FLOGI);
		}
		fct_log_local_port_event(iport->iport_port,
		    ESC_SUNFC_PORT_ONLINE);
	} else if (new_bits & S_RCVD_LINK_DOWN) {
		fct_log_local_port_event(iport->iport_port,
		    ESC_SUNFC_PORT_OFFLINE);
	}

	mutex_enter(&iport->iport_worker_lock);
	if (in && dqueue_and_free) {
		iport->iport_event_head = in->event_next;
		if (iport->iport_event_head == NULL)
			iport->iport_event_tail = NULL;
		kmem_free(in, sizeof (*in));
	}
	return (ret);
}

int
fct_lport_has_bigger_wwn(fct_i_local_port_t *iport)
{
	uint8_t *l, *r;
	int i;
	uint64_t wl, wr;

	l = iport->iport_port->port_pwwn;
	r = iport->iport_link_info.port_rpwwn;

	for (i = 0, wl = 0; i < 8; i++) {
		wl <<= 8;
		wl |= l[i];
	}
	for (i = 0, wr = 0; i < 8; i++) {
		wr <<= 8;
		wr |= r[i];
	}

	if (wl > wr) {
		return (1);
	}

	return (0);
}

void
fct_do_flogi(fct_i_local_port_t *iport)
{
	fct_flogi_xchg_t fx;
	fct_status_t ret;
	int force_link_down = 0;
	int do_retry = 0;

	DTRACE_FC_1(fabric__login__start, fct_i_local_port_t, iport);

	bzero(&fx, sizeof (fx));
	fx.fx_op = ELS_OP_FLOGI;
	if (iport->iport_login_retry == 0) {
		fx.fx_sec_timeout = 2;
	} else {
		fx.fx_sec_timeout = 5;
	}
	if (iport->iport_link_info.port_topology & PORT_TOPOLOGY_PRIVATE_LOOP) {
		fx.fx_sid = iport->iport_link_info.portid & 0xFF;
	}
	fx.fx_did = 0xFFFFFE;
	bcopy(iport->iport_port->port_nwwn, fx.fx_nwwn, 8);
	bcopy(iport->iport_port->port_pwwn, fx.fx_pwwn, 8);
	mutex_exit(&iport->iport_worker_lock);
	ret = iport->iport_port->port_flogi_xchg(iport->iport_port, &fx);
	mutex_enter(&iport->iport_worker_lock);
	if (IPORT_FLOGI_DONE(iport)) {
		/* The unsolicited path finished it. */
		goto done;
	}
	if (ret == FCT_NOT_FOUND) {
		if (iport->iport_link_info.port_topology &
		    PORT_TOPOLOGY_PRIVATE_LOOP) {
			/* This is a private loop. There is no switch. */
			iport->iport_link_info.port_no_fct_flogi = 1;
			goto done;
		}
		/*
		 * This is really an error. This means we cannot init the
		 * link. Lets force the link to go down.
		 */
		force_link_down = 1;
	} else if ((ret == FCT_SUCCESS) && (fx.fx_op == ELS_OP_LSRJT)) {
		if ((fx.fx_rjt_reason == 5) || (fx.fx_rjt_reason == 0xe) ||
		    ((fx.fx_rjt_reason == 9) && (fx.fx_rjt_expl == 0x29))) {
			do_retry = 1;
		} else {
			force_link_down = 1;
		}
	} else if (ret == STMF_TIMEOUT) {
		do_retry = 1;
	} else if (ret != FCT_SUCCESS) {
		force_link_down = 1;
	}

	if (do_retry) {
		iport->iport_login_retry++;
		if (iport->iport_login_retry >= 5)
			force_link_down = 1;
		goto done;
	}

	if (force_link_down) {
		stmf_trace(iport->iport_alias, "iport-%p: flogi xchg failed. "
		    "Forcing link down, ret=%llx login_retry=%d ret_op=%d "
		    "reason=%d expl=%d", iport, ret, iport->iport_login_retry,
		    fx.fx_op, fx.fx_rjt_reason, fx.fx_rjt_expl);
		mutex_exit(&iport->iport_worker_lock);
		fct_handle_event(iport->iport_port, FCT_EVENT_LINK_DOWN, 0, 0);
		mutex_enter(&iport->iport_worker_lock);
		goto done;
	}

	/* FLOGI succeeded. Update local port state */
	ASSERT(fx.fx_op == ELS_OP_ACC);
	bcopy(fx.fx_nwwn, iport->iport_link_info.port_rnwwn, 8);
	bcopy(fx.fx_pwwn, iport->iport_link_info.port_rpwwn, 8);
	if (fx.fx_fport) {
		iport->iport_link_info.port_topology |=
		    PORT_TOPOLOGY_FABRIC_BIT;
		iport->iport_link_info.portid = fx.fx_did;
	}
	iport->iport_link_info.port_fct_flogi_done = 1;

done:
	DTRACE_FC_1(fabric__login__end,
	    fct_i_local_port_t, iport);
}

/*
 * Called by FCAs to handle unsolicited FLOGIs.
 */
fct_status_t
fct_handle_rcvd_flogi(fct_local_port_t *port, fct_flogi_xchg_t *fx)
{
	fct_i_local_port_t *iport;
	uint32_t t;

	iport = (fct_i_local_port_t *)port->port_fct_private;
	if ((iport->iport_flags & IPORT_ALLOW_UNSOL_FLOGI) == 0) {
		return (FCT_FAILURE);
	}

	mutex_enter(&iport->iport_worker_lock);
	if (((iport->iport_flags & IPORT_ALLOW_UNSOL_FLOGI) == 0) ||
	    (iport->iport_link_state !=	PORT_STATE_LINK_INIT_START) ||
	    ((iport->iport_li_state & LI_STATE_MASK) > LI_STATE_N2N_PLOGI)) {
		mutex_exit(&iport->iport_worker_lock);
		return (FCT_FAILURE);
	}

	if (iport->iport_link_info.port_fct_flogi_done == 0) {
		iport->iport_link_info.port_fct_flogi_done = 1;
		bcopy(fx->fx_pwwn, iport->iport_link_info.port_rpwwn, 8);
		bcopy(fx->fx_nwwn, iport->iport_link_info.port_rnwwn, 8);
	}

	fx->fx_op = ELS_OP_ACC;
	t = fx->fx_sid;
	fx->fx_sid = fx->fx_did;
	fx->fx_did = t;
	bcopy(iport->iport_port->port_pwwn, fx->fx_pwwn, 8);
	bcopy(iport->iport_port->port_nwwn, fx->fx_nwwn, 8);
	mutex_exit(&iport->iport_worker_lock);

	return (FCT_SUCCESS);
}

/*
 * iport_li_state can only be changed here and local_event
 */
disc_action_t
fct_process_link_init(fct_i_local_port_t *iport)
{
	fct_cmd_t	*cmd	  = NULL;
	char		*pname	  = NULL;
	uint8_t		 elsop	  = 0;
	uint16_t	 ctop	  = 0;
	uint32_t	 wkdid	  = 0;
	int		 implicit = 0;
	int		force_login = 0;
	disc_action_t	 ret	  = DISC_ACTION_RESCAN;
	fct_link_info_t *li = &iport->iport_link_info;
	char		topo[24], speed[4];

	ASSERT(MUTEX_HELD(&iport->iport_worker_lock));

check_state_again:
	switch (iport->iport_li_state & LI_STATE_MASK) {
	case LI_STATE_DO_FLOGI:
		/* Is FLOGI even needed or already done ? */
		if ((iport->iport_link_info.port_no_fct_flogi) ||
		    (IPORT_FLOGI_DONE(iport))) {
			iport->iport_li_state++;
			goto check_state_again;
		}
		fct_do_flogi(iport);
		break;

	case LI_STATE_FINI_TOPOLOGY:
		fct_li_to_txt(li, topo, speed);
		cmn_err(CE_NOTE, "%s LINK UP, portid %x, topology %s,"
		    "speed %s", iport->iport_alias, li->portid,
		    topo, speed);
		if (li->port_topology !=
		    iport->iport_link_old_topology) {
			if (iport->iport_nrps) {
				/*
				 * rehash it if change from fabric to
				 * none fabric, vice versa
				 */
				if ((li->port_topology ^
				    iport->iport_link_old_topology) &
				    PORT_TOPOLOGY_FABRIC_BIT) {
					mutex_exit(&iport->iport_worker_lock);
					fct_rehash(iport);
					mutex_enter(&iport->iport_worker_lock);
				}
			}
			iport->iport_link_old_topology = li->port_topology;
		}
		/* Skip next level if topo is not N2N */
		if (li->port_topology != PORT_TOPOLOGY_PT_TO_PT) {
			iport->iport_li_state += 2;
			atomic_and_32(&iport->iport_flags,
			    ~IPORT_ALLOW_UNSOL_FLOGI);
		} else {
			iport->iport_li_state++;
			iport->iport_login_retry = 0;
			iport->iport_li_cmd_timeout = ddi_get_lbolt() +
			    drv_usectohz(25 * 1000000);
		}
		goto check_state_again;

	case LI_STATE_N2N_PLOGI:
		ASSERT(IPORT_FLOGI_DONE(iport));
		ASSERT(iport->iport_link_info.port_topology ==
		    PORT_TOPOLOGY_PT_TO_PT);
		if (iport->iport_li_state & LI_STATE_FLAG_CMD_RETCHECK) {
			iport->iport_li_state &= ~LI_STATE_FLAG_CMD_RETCHECK;
			if (iport->iport_li_comp_status != FCT_SUCCESS) {
				iport->iport_login_retry++;
				if (iport->iport_login_retry >= 3) {
					stmf_trace(iport->iport_alias, "Failing"
					    " to PLOGI to remote port in N2N "
					    " ret=%llx, forcing link down",
					    iport->iport_li_comp_status);
					mutex_exit(&iport->iport_worker_lock);
					fct_handle_event(iport->iport_port,
					    FCT_EVENT_LINK_DOWN, 0, 0);
					mutex_enter(&iport->iport_worker_lock);
				}
			}
		}
		/* Find out if we need to do PLOGI at all */
		if (iport->iport_nrps_login) {
			iport->iport_li_state++;
			atomic_and_32(&iport->iport_flags,
			    ~IPORT_ALLOW_UNSOL_FLOGI);
			goto check_state_again;
		}
		if ((ddi_get_lbolt() >= iport->iport_li_cmd_timeout) &&
		    (!fct_lport_has_bigger_wwn(iport))) {
			/* Cant wait forever */
			stmf_trace(iport->iport_alias, "N2N: Remote port is "
			    "not logging in, forcing from our side");
			force_login = 1;
		} else {
			force_login = 0;
		}
		if (force_login || fct_lport_has_bigger_wwn(iport)) {
			elsop	 = ELS_OP_PLOGI;
			wkdid	 = 1;
			iport->iport_link_info.portid = 0xEF;
			implicit = 0;
			iport->iport_li_state |= LI_STATE_FLAG_CMD_RETCHECK;
		} else {
			ret = DISC_ACTION_DELAY_RESCAN;
		}
		break;

	case LI_STATE_DO_FCLOGIN:
		if (iport->iport_li_state & LI_STATE_FLAG_CMD_RETCHECK) {
			iport->iport_li_state &= ~LI_STATE_FLAG_CMD_RETCHECK;
			if (iport->iport_li_comp_status != FCT_SUCCESS) {
				/*
				 * Fabric controller login failed. Just skip all
				 * the fabric controller related cmds.
				 */
				iport->iport_li_state = LI_STATE_DO_SCR + 1;
			} else {
				/*
				 * Good. Now lets go to next state
				 */
				iport->iport_li_state++;
			}
			goto check_state_again;
		}
		if (!IPORT_IN_NS_TOPO(iport)) {
			iport->iport_li_state = LI_STATE_DO_SCR + 1;
			goto check_state_again;
		}

		elsop	 = ELS_OP_PLOGI;
		wkdid	 = FS_FABRIC_CONTROLLER;
		implicit = 1;

		/*
		 * We want to come back in the same state and check its ret
		 * We can't modify the state here
		 */
		iport->iport_li_state |= LI_STATE_FLAG_CMD_RETCHECK;
		break;

	case LI_STATE_DO_SCR:
		elsop = ELS_OP_SCR;
		wkdid = FS_FABRIC_CONTROLLER;

		/*
		 * We dont care about success of this state. Just go to
		 * next state upon completion.
		 */
		iport->iport_li_state++;
		break;

	case LI_STATE_DO_NSLOGIN:
		if (iport->iport_li_state & LI_STATE_FLAG_CMD_RETCHECK) {
			iport->iport_li_state &= ~LI_STATE_FLAG_CMD_RETCHECK;
			if (iport->iport_li_comp_status != FCT_SUCCESS) {
				iport->iport_li_state = LI_STATE_DO_RSNN + 1;
			} else {
				iport->iport_li_state++;
			}
			goto check_state_again;
		}

		if (!IPORT_IN_NS_TOPO(iport)) {
			iport->iport_li_state = LI_STATE_DO_RSNN + 1;
			goto check_state_again;
		}

		elsop			= ELS_OP_PLOGI;
		wkdid			= FS_NAME_SERVER;
		iport->iport_li_state	|= LI_STATE_FLAG_CMD_RETCHECK;
		break;

		/*
		 * CT state
		 */
	case LI_STATE_DO_RNN:
		ctop = NS_RNN_ID;
		iport->iport_li_state++;
		break;

	case LI_STATE_DO_RCS:
		ctop = NS_RCS_ID;
		iport->iport_li_state++;
		break;

	case LI_STATE_DO_RFT:
		ctop = NS_RFT_ID;
		iport->iport_li_state++;
		break;

	case LI_STATE_DO_RSPN:
		/*
		 * Check if we need skip the state
		 */
		pname = iport->iport_port->port_sym_port_name !=
		    NULL ? iport->iport_port->port_sym_port_name : NULL;
		if (pname == NULL) {
			pname = iport->iport_port->port_default_alias !=
			    NULL ? iport->iport_port->port_default_alias : NULL;
			iport->iport_port->port_sym_port_name = pname;
		}

		if (pname == NULL) {
			iport->iport_li_state++;
			goto check_state_again;
		}

		ctop = NS_RSPN_ID;
		iport->iport_li_state++;
		break;

	case LI_STATE_DO_RSNN:
		ctop = NS_RSNN_NN;
		iport->iport_li_state++;
		break;

	case LI_STATE_MAX:
		mutex_exit(&iport->iport_worker_lock);

		fct_handle_event(iport->iport_port,
		    FCT_I_EVENT_LINK_INIT_DONE, 0, 0);

		mutex_enter(&iport->iport_worker_lock);
		break;

	default:
		ASSERT(0);
	}

	if (elsop != 0) {
		cmd = fct_create_solels(iport->iport_port, NULL, implicit,
		    elsop, wkdid, fct_link_init_cb);
	} else if (ctop != 0) {
		cmd = fct_create_solct(iport->iport_port, NULL, ctop,
		    fct_link_init_cb);
	}

	if (cmd) {
		iport->iport_li_state |= LI_STATE_FLAG_CMD_WAITING;
		mutex_exit(&iport->iport_worker_lock);

		fct_post_to_solcmd_queue(iport->iport_port, cmd);

		mutex_enter(&iport->iport_worker_lock);
	}

	return (ret);
}

/*
 * Handles both solicited and unsolicited elses. Can be called inside
 * interrupt context.
 */
void
fct_handle_els(fct_cmd_t *cmd)
{
	fct_local_port_t	*port = cmd->cmd_port;
	fct_i_local_port_t *iport =
	    (fct_i_local_port_t *)port->port_fct_private;
	fct_i_cmd_t		*icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;
	fct_els_t		*els  = (fct_els_t *)cmd->cmd_specific;
	fct_remote_port_t	*rp;
	fct_i_remote_port_t	*irp;
	uint16_t		 cmd_slot;
	uint8_t			 op;

	op = els->els_req_payload[0];
	icmd->icmd_start_time = ddi_get_lbolt();
	if (cmd->cmd_type == FCT_CMD_RCVD_ELS) {
		icmd->icmd_flags |= ICMD_KNOWN_TO_FCA;
	}
	stmf_trace(iport->iport_alias, "Posting %ssol ELS %x (%s) rp_id=%x"
	    " lp_id=%x", (cmd->cmd_type == FCT_CMD_RCVD_ELS) ? "un" : "",
	    op, FCT_ELS_NAME(op), cmd->cmd_rportid,
	    cmd->cmd_lportid);

	rw_enter(&iport->iport_lock, RW_READER);
start_els_posting:;
	/* Make sure local port is sane */
	if ((iport->iport_link_state & S_LINK_ONLINE) == 0) {
		rw_exit(&iport->iport_lock);
		stmf_trace(iport->iport_alias, "ELS %x not posted becasue"
		    "port state was %x", els->els_req_payload[0],
		    iport->iport_link_state);
		fct_queue_cmd_for_termination(cmd, FCT_LOCAL_PORT_OFFLINE);
		return;
	}

	/* Weed out any bad initiators in case of N2N topology */
	if ((cmd->cmd_type == FCT_CMD_RCVD_ELS) &&
	    (els->els_req_payload[0] == ELS_OP_PLOGI) &&
	    (iport->iport_link_state == PORT_STATE_LINK_INIT_START) &&
	    (iport->iport_link_info.port_topology == PORT_TOPOLOGY_PT_TO_PT)) {
		int state;
		int killit = 0;

		mutex_enter(&iport->iport_worker_lock);
		state = iport->iport_li_state & LI_STATE_MASK;
		/*
		 * We dont allow remote port to plogi in N2N if we have not yet
		 * resolved the topology.
		 */
		if (state <= LI_STATE_FINI_TOPOLOGY) {
			killit = 1;
			stmf_trace(iport->iport_alias, "port %x is trying to "
			    "PLOGI in N2N topology, While we have not resolved"
			    " the topology. Dropping...", cmd->cmd_rportid);
		} else if (state <= LI_STATE_N2N_PLOGI) {
			if (fct_lport_has_bigger_wwn(iport)) {
				killit = 1;
				stmf_trace(iport->iport_alias, "port %x is "
				    "trying to PLOGI in N2N topology, even "
				    "though it has smaller PWWN",
				    cmd->cmd_rportid);
			} else {
				/*
				 * Remote port is assigning us a PORTID as
				 * a part of PLOGI.
				 */
				iport->iport_link_info.portid =
				    cmd->cmd_lportid;
			}
		}
		mutex_exit(&iport->iport_worker_lock);
		if (killit) {
			rw_exit(&iport->iport_lock);
			fct_queue_cmd_for_termination(cmd,
			    FCT_LOCAL_PORT_OFFLINE);
			return;
		}
	}

	/*
	 * For all unsolicited ELSes that are not FLOGIs, our portid
	 * has been established by now. Sometimes port IDs change due to
	 * link resets but remote ports may still send ELSes using the
	 * old IDs. Kill those right here.
	 */
	if ((cmd->cmd_type == FCT_CMD_RCVD_ELS) &&
	    (els->els_req_payload[0] != ELS_OP_FLOGI)) {
		if (cmd->cmd_lportid != iport->iport_link_info.portid) {
			rw_exit(&iport->iport_lock);
			stmf_trace(iport->iport_alias, "Rcvd %s with "
			    "wrong lportid %x, expecting %x. Killing ELS.",
			    FCT_ELS_NAME(op), cmd->cmd_lportid,
			    iport->iport_link_info.portid);
			fct_queue_cmd_for_termination(cmd,
			    FCT_NOT_FOUND);
			return;
		}
	}

	/*
	 * We always lookup by portid. port handles are too
	 * unreliable at this stage.
	 */
	irp = fct_portid_to_portptr(iport, cmd->cmd_rportid);
	if (els->els_req_payload[0] == ELS_OP_PLOGI) {
		if (irp == NULL) {
			/* drop the lock while we do allocations */
			rw_exit(&iport->iport_lock);
			rp = fct_alloc(FCT_STRUCT_REMOTE_PORT,
			    port->port_fca_rp_private_size, 0);
			if (rp == NULL) {
				fct_queue_cmd_for_termination(cmd,
				    FCT_ALLOC_FAILURE);
				return;
			}
			irp = (fct_i_remote_port_t *)rp->rp_fct_private;
			rw_init(&irp->irp_lock, 0, RW_DRIVER, 0);
			irp->irp_rp = rp;
			irp->irp_portid = cmd->cmd_rportid;
			rp->rp_port = port;
			rp->rp_id = cmd->cmd_rportid;
			rp->rp_handle = FCT_HANDLE_NONE;
			/*
			 * Grab port lock as writer since we are going
			 * to modify the local port struct.
			 */
			rw_enter(&iport->iport_lock, RW_WRITER);
			/* Make sure nobody created the struct except us */
			if (fct_portid_to_portptr(iport, cmd->cmd_rportid)) {
				/* Oh well, free it */
				fct_free(rp);
			} else {
				fct_queue_rp(iport, irp);
			}
			rw_downgrade(&iport->iport_lock);
			/* Start over becasue we dropped the lock */
			goto start_els_posting;
		}

		/* A PLOGI is by default a logout of previous session */
		irp->irp_deregister_timer = ddi_get_lbolt() +
		    drv_usectohz(USEC_DEREG_RP_TIMEOUT);
		irp->irp_dereg_count = 0;
		fct_post_to_discovery_queue(iport, irp, NULL);

		/* A PLOGI also invalidates any RSCNs related to this rp */
		atomic_inc_32(&irp->irp_rscn_counter);
	} else {
		/*
		 * For everything else, we have (or be able to lookup) a
		 * valid port pointer.
		 */
		if (irp == NULL) {
			rw_exit(&iport->iport_lock);
			if (cmd->cmd_type == FCT_CMD_RCVD_ELS) {
				/* XXX Throw a logout to the initiator */
				stmf_trace(iport->iport_alias, "ELS %x "
				    "received from %x without a session",
				    els->els_req_payload[0], cmd->cmd_rportid);
			} else {
				stmf_trace(iport->iport_alias, "Sending ELS %x "
				    "to %x without a session",
				    els->els_req_payload[0], cmd->cmd_rportid);
			}
			fct_queue_cmd_for_termination(cmd, FCT_NOT_LOGGED_IN);
			return;
		}
	}
	cmd->cmd_rp = rp = irp->irp_rp;

	/*
	 * Lets get a slot for this els
	 */
	if (!(icmd->icmd_flags & ICMD_IMPLICIT)) {
		cmd_slot = fct_alloc_cmd_slot(iport, cmd);
		if (cmd_slot == FCT_SLOT_EOL) {
			/* This should not have happened */
			rw_exit(&iport->iport_lock);
			stmf_trace(iport->iport_alias,
			    "ran out of xchg resources");
			fct_queue_cmd_for_termination(cmd,
			    FCT_NO_XCHG_RESOURCE);
			return;
		}
	} else {
		/*
		 * Tell the framework that fct_cmd_free() can decrement the
		 * irp_nonfcp_xchg_count variable.
		 */
		atomic_or_32(&icmd->icmd_flags, ICMD_IMPLICIT_CMD_HAS_RESOURCE);
	}
	atomic_inc_16(&irp->irp_nonfcp_xchg_count);

	/*
	 * Grab the remote port lock while we modify the port state.
	 * we should not drop the fca port lock (as a reader) until we
	 * modify the remote port state.
	 */
	rw_enter(&irp->irp_lock, RW_WRITER);
	if ((op == ELS_OP_PLOGI) || (op == ELS_OP_PRLI) ||
	    (op == ELS_OP_LOGO) || (op == ELS_OP_PRLO) ||
	    (op == ELS_OP_TPRLO)) {
		uint32_t rf = IRP_PRLI_DONE;
		if ((op == ELS_OP_PLOGI) || (op == ELS_OP_LOGO)) {
			rf |= IRP_PLOGI_DONE;
			if (irp->irp_flags & IRP_PLOGI_DONE)
				atomic_dec_32(&iport->iport_nrps_login);
		}
		atomic_inc_16(&irp->irp_sa_elses_count);
		atomic_and_32(&irp->irp_flags, ~rf);
		atomic_or_32(&icmd->icmd_flags, ICMD_SESSION_AFFECTING);
	} else {
		atomic_inc_16(&irp->irp_nsa_elses_count);
	}

	fct_post_to_discovery_queue(iport, irp, icmd);

	rw_exit(&irp->irp_lock);
	rw_exit(&iport->iport_lock);
}

/*
 * Cleanup I/Os for a rport. ttc is a bit Mask of cmd types to clean.
 * No locks held.
 */
int
fct_trigger_rport_cleanup(fct_i_remote_port_t *irp, int ttc)
{
	fct_remote_port_t	*rp = irp->irp_rp;
	fct_local_port_t	*port = rp->rp_port;
	fct_i_local_port_t	*iport =
	    (fct_i_local_port_t *)port->port_fct_private;
	fct_cmd_t		*cmd;
	fct_i_cmd_t		*icmd;
	int			i;
	int			ret;
	uint16_t		total, cleaned, skipped, unhandled;

	rw_enter(&iport->iport_lock, RW_WRITER);
	rw_enter(&irp->irp_lock, RW_WRITER);
	mutex_enter(&iport->iport_worker_lock);
	total = port->port_max_xchges - iport->iport_nslots_free;
	cleaned = skipped = unhandled = 0;

	for (i = 0; i < port->port_max_xchges; i++) {
		if (iport->iport_cmd_slots[i].slot_cmd == NULL)
			continue;
		icmd = iport->iport_cmd_slots[i].slot_cmd;
		if (icmd->icmd_flags & ICMD_IN_TRANSITION) {
			unhandled++;
			continue;
		}

		if (icmd->icmd_flags & ICMD_CMD_COMPLETE) {
			unhandled++;
			continue;
		}

		cmd = icmd->icmd_cmd;
		if (cmd->cmd_rp != rp) {
			skipped++;
			continue;
		}
		if (cmd->cmd_type & ttc) {
			if (cmd->cmd_type == FCT_CMD_FCP_XCHG)
				fct_queue_scsi_task_for_termination(cmd,
				    FCT_ABORTED);
			else
				fct_q_for_termination_lock_held(iport, icmd,
				    FCT_ABORTED);
			cleaned++;
		} else {
			skipped++;
		}
	}
	if (((cleaned + skipped) == total) && (unhandled == 0)) {
		ret = 1;
	} else {
		/*
		 * XXX: handle this situation.
		 */
		stmf_trace(iport->iport_alias, "Clean up trouble for irp"
		    " %p, c/s/u/t = %d/%d/%d/%d", irp, cleaned, skipped,
		    unhandled, total);
		ret = 0;
	}
	if ((cleaned) && IS_WORKER_SLEEPING(iport))
		cv_signal(&iport->iport_worker_cv);
	mutex_exit(&iport->iport_worker_lock);
	rw_exit(&irp->irp_lock);
	rw_exit(&iport->iport_lock);
	return (ret);
}

void
fct_dequeue_els(fct_i_remote_port_t *irp)
{
	fct_i_cmd_t *icmd;

	rw_enter(&irp->irp_lock, RW_WRITER);
	icmd = irp->irp_els_list;
	irp->irp_els_list = icmd->icmd_next;
	atomic_and_32(&icmd->icmd_flags, ~ICMD_IN_IRP_QUEUE);
	rw_exit(&irp->irp_lock);
}

fct_status_t
fct_register_remote_port(fct_local_port_t *port, fct_remote_port_t *rp,
				fct_cmd_t *cmd)
{
	fct_status_t ret;
	fct_i_local_port_t	*iport;
	fct_i_remote_port_t	*irp;
	int			i;
	char			info[FCT_INFO_LEN];

	iport = (fct_i_local_port_t *)port->port_fct_private;
	irp = (fct_i_remote_port_t *)rp->rp_fct_private;

	if ((ret = port->port_register_remote_port(port, rp, cmd)) !=
	    FCT_SUCCESS)
		return (ret);

	rw_enter(&iport->iport_lock, RW_WRITER);
	rw_enter(&irp->irp_lock, RW_WRITER);
	if (rp->rp_handle != FCT_HANDLE_NONE) {
		if (rp->rp_handle >= port->port_max_logins) {
			(void) snprintf(info, sizeof (info),
			    "fct_register_remote_port: FCA "
			    "returned a	handle (%d) for portid %x which is "
			    "out of range (max logins = %d)", rp->rp_handle,
			    rp->rp_id, port->port_max_logins);
			goto hba_fatal_err;
		}
		if ((iport->iport_rp_slots[rp->rp_handle] != NULL) &&
		    (iport->iport_rp_slots[rp->rp_handle] != irp)) {
			fct_i_remote_port_t *t_irp =
			    iport->iport_rp_slots[rp->rp_handle];
			(void) snprintf(info, sizeof (info),
			    "fct_register_remote_port: "
			    "FCA returned a handle %d for portid %x "
			    "which was already in use for a different "
			    "portid (%x)", rp->rp_handle, rp->rp_id,
			    t_irp->irp_rp->rp_id);
			goto hba_fatal_err;
		}
	} else {
		/* Pick a handle for this port */
		for (i = 0; i < port->port_max_logins; i++) {
			if (iport->iport_rp_slots[i] == NULL) {
				break;
			}
		}
		if (i == port->port_max_logins) {
			/* This is really pushing it. */
			(void) snprintf(info, sizeof (info),
			    "fct_register_remote_port "
			    "Cannot register portid %x because all the "
			    "handles are used up", rp->rp_id);
			goto hba_fatal_err;
		}
		rp->rp_handle = i;
	}
	/* By this time rport_handle is valid */
	if ((irp->irp_flags & IRP_HANDLE_OPENED) == 0) {
		iport->iport_rp_slots[rp->rp_handle] = irp;
		atomic_or_32(&irp->irp_flags, IRP_HANDLE_OPENED);
	}
	atomic_inc_64(&iport->iport_last_change);
	fct_log_remote_port_event(port, ESC_SUNFC_TARGET_ADD,
	    rp->rp_pwwn, rp->rp_id);

register_rp_done:;
	rw_exit(&irp->irp_lock);
	rw_exit(&iport->iport_lock);
	return (FCT_SUCCESS);

hba_fatal_err:;
	rw_exit(&irp->irp_lock);
	rw_exit(&iport->iport_lock);
	/*
	 * XXX Throw HBA fatal error event
	 */
	(void) fct_port_shutdown(iport->iport_port,
	    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);
	return (FCT_FAILURE);
}

fct_status_t
fct_deregister_remote_port(fct_local_port_t *port, fct_remote_port_t *rp)
{
	fct_status_t		 ret   = FCT_SUCCESS;
	fct_i_local_port_t	*iport = PORT_TO_IPORT(port);
	fct_i_remote_port_t	*irp   = RP_TO_IRP(rp);

	if (irp->irp_snn) {
		kmem_free(irp->irp_snn, strlen(irp->irp_snn) + 1);
		irp->irp_snn = NULL;
	}
	if (irp->irp_spn) {
		kmem_free(irp->irp_spn, strlen(irp->irp_spn) + 1);
		irp->irp_spn = NULL;
	}

	if ((ret = port->port_deregister_remote_port(port, rp)) !=
	    FCT_SUCCESS) {
		return (ret);
	}

	if (irp->irp_flags & IRP_HANDLE_OPENED) {
		atomic_and_32(&irp->irp_flags, ~IRP_HANDLE_OPENED);
		iport->iport_rp_slots[rp->rp_handle] = NULL;
	}
	atomic_inc_64(&iport->iport_last_change);
	fct_log_remote_port_event(port, ESC_SUNFC_TARGET_REMOVE,
	    rp->rp_pwwn, rp->rp_id);

	return (FCT_SUCCESS);
}

fct_status_t
fct_send_accrjt(fct_cmd_t *cmd, uint8_t accrjt, uint8_t reason, uint8_t expl)
{
	fct_local_port_t *port = (fct_local_port_t *)cmd->cmd_port;
	fct_els_t *els = (fct_els_t *)cmd->cmd_specific;

	els->els_resp_size = els->els_resp_alloc_size = 8;
	els->els_resp_payload = (uint8_t *)kmem_zalloc(8, KM_SLEEP);
	els->els_resp_payload[0] = accrjt;
	if (accrjt == 1) {
		els->els_resp_payload[5] = reason;
		els->els_resp_payload[6] = expl;
	} else {
		els->els_resp_size = 4;
	}

	return (port->port_send_cmd_response(cmd, 0));
}


disc_action_t
fct_walk_discovery_queue(fct_i_local_port_t *iport)
{
	char			info[FCT_INFO_LEN];
	fct_i_remote_port_t	**pirp;
	fct_i_remote_port_t	*prev_irp = NULL;
	disc_action_t		suggested_action = DISC_ACTION_NO_WORK;
	fct_i_remote_port_t	*irp_dereg_list = NULL;
	fct_i_remote_port_t	*irp_cur_item = NULL;

	for (pirp = &iport->iport_rpwe_head; *pirp != NULL; ) {
		fct_i_remote_port_t *irp = *pirp;
		disc_action_t ret = DISC_ACTION_NO_WORK;
		int do_deregister = 0;
		int irp_deregister_timer = 0;

		if (irp->irp_els_list) {
			ret |= fct_process_els(iport, irp);
		}

		irp_deregister_timer = irp->irp_deregister_timer;
		if (irp_deregister_timer) {
			if (ddi_get_lbolt() >= irp_deregister_timer) {
				do_deregister = 1;
			} else {
				ret |= DISC_ACTION_DELAY_RESCAN;
			}
		}
		suggested_action |= ret;

		if (irp->irp_els_list == NULL) {
			mutex_exit(&iport->iport_worker_lock);
			rw_enter(&iport->iport_lock, RW_WRITER);
			rw_enter(&irp->irp_lock, RW_WRITER);
			mutex_enter(&iport->iport_worker_lock);
			if (irp->irp_els_list == NULL) {
				if (!irp_deregister_timer ||
				    (do_deregister &&
				    !irp->irp_sa_elses_count &&
				    !irp->irp_nsa_elses_count &&
				    !irp->irp_fcp_xchg_count &&
				    !irp->irp_nonfcp_xchg_count)) {
					/* dequeue irp from discovery queue */
					atomic_and_32(&irp->irp_flags,
					    ~IRP_IN_DISCOVERY_QUEUE);
					*pirp = irp->irp_discovery_next;
					if (iport->iport_rpwe_head == NULL)
						iport->iport_rpwe_tail = NULL;
					else if (irp == iport->iport_rpwe_tail)
						iport->iport_rpwe_tail =
						    prev_irp;

					irp->irp_discovery_next = NULL;
					if (do_deregister) {
						fct_deque_rp(iport, irp);
						rw_exit(&irp->irp_lock);
						/* queue irp for deregister */
						irp->irp_next = NULL;
						if (!irp_dereg_list) {
							irp_dereg_list =
							    irp_cur_item = irp;
						} else {
							irp_cur_item->irp_next =
							    irp;
							irp_cur_item = irp;
						}
					} else {
						rw_exit(&irp->irp_lock);
					}
					rw_exit(&iport->iport_lock);
					if ((irp = *pirp) == NULL)
						break;
				} else {
					/*
					 * wait for another scan until
					 * deregister timeout
					 */
					rw_exit(&irp->irp_lock);
					rw_exit(&iport->iport_lock);
				}
			} else {
				rw_exit(&irp->irp_lock);
				rw_exit(&iport->iport_lock);
				/*
				 * When we dropped the lock,
				 * something went in.
				 */
				suggested_action |= DISC_ACTION_RESCAN;
			}
		}
		pirp = &(irp->irp_discovery_next);
		prev_irp = irp;
	}
	/* do deregister */
	if (irp_dereg_list) {
		fct_i_remote_port_t *irp_next_item;
		/* drop the lock */
		mutex_exit(&iport->iport_worker_lock);

		for (irp_cur_item = irp_dereg_list; irp_cur_item != NULL; ) {
			irp_next_item = irp_cur_item->irp_next;
			if (fct_deregister_remote_port(iport->iport_port,
			    irp_cur_item->irp_rp) == FCT_SUCCESS) {
				fct_free(irp_cur_item->irp_rp);
			} else if (++irp_cur_item->irp_dereg_count >= 5) {
				irp_cur_item->irp_deregister_timer = 0;
				irp_cur_item->irp_dereg_count = 0;

				/*
				 * It looks like we can't deregister it in the
				 * normal way, so we have to use extrem way
				 */
				(void) snprintf(info, sizeof (info),
				    "fct_walk_discovery_queue: "
				    "iport-%p, can't deregister irp-%p after "
				    "trying 5 times", (void *)iport,
				    (void *)irp_cur_item);
				(void) fct_port_shutdown(iport->iport_port,
				    STMF_RFLAG_FATAL_ERROR |
				    STMF_RFLAG_RESET, info);
				suggested_action |= DISC_ACTION_RESCAN;
				break;
			} else {
				/* grab the iport_lock */
				rw_enter(&iport->iport_lock, RW_WRITER);
				/* recover */
				irp_cur_item->irp_deregister_timer =
				    ddi_get_lbolt() +
				    drv_usectohz(USEC_DEREG_RP_INTERVAL);
				fct_post_to_discovery_queue(iport,
				    irp_cur_item, NULL);
				fct_queue_rp(iport, irp_cur_item);
				rw_exit(&iport->iport_lock);
				suggested_action |= DISC_ACTION_DELAY_RESCAN;
			}
			irp_cur_item = irp_next_item;
		}
		mutex_enter(&iport->iport_worker_lock);
	}
	return (suggested_action);
}

disc_action_t
fct_process_plogi(fct_i_cmd_t *icmd)
{
	fct_cmd_t		*cmd = icmd->icmd_cmd;
	fct_remote_port_t	*rp = cmd->cmd_rp;
	fct_local_port_t	*port = cmd->cmd_port;
	fct_i_local_port_t	*iport = (fct_i_local_port_t *)
	    port->port_fct_private;
	fct_els_t		*els = (fct_els_t *)
	    cmd->cmd_specific;
	fct_i_remote_port_t	*irp = (fct_i_remote_port_t *)
	    rp->rp_fct_private;
	uint8_t			*p;
	fct_status_t		 ret;
	uint8_t			 cmd_type   = cmd->cmd_type;
	uint32_t		 icmd_flags = icmd->icmd_flags;
	clock_t			 end_time;
	char			 info[FCT_INFO_LEN];

	DTRACE_FC_4(rport__login__start,
	    fct_cmd_t, cmd,
	    fct_local_port_t, port,
	    fct_i_remote_port_t, irp,
	    int, (cmd_type != FCT_CMD_RCVD_ELS));

	/* Drain I/Os */
	if ((irp->irp_nonfcp_xchg_count + irp->irp_fcp_xchg_count) > 1) {
		/* Trigger cleanup if necessary */
		if ((irp->irp_flags & IRP_SESSION_CLEANUP) == 0) {
			stmf_trace(iport->iport_alias, "handling PLOGI rp_id"
			    " %x. Triggering cleanup", cmd->cmd_rportid);
			/* Cleanup everything except elses */
			if (fct_trigger_rport_cleanup(irp, ~(cmd->cmd_type))) {
				atomic_or_32(&irp->irp_flags,
				    IRP_SESSION_CLEANUP);
			} else {
				/* XXX: handle this */
				/* EMPTY */
			}
		}

		end_time = icmd->icmd_start_time +
		    drv_usectohz(USEC_ELS_TIMEOUT);
		if (ddi_get_lbolt() > end_time) {
			(void) snprintf(info, sizeof (info),
			    "fct_process_plogi: unable to "
			    "clean up I/O. iport-%p, icmd-%p", (void *)iport,
			    (void *)icmd);
			(void) fct_port_shutdown(iport->iport_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);

			return (DISC_ACTION_DELAY_RESCAN);
		}

		if ((ddi_get_lbolt() & 0x7f) == 0) {
			stmf_trace(iport->iport_alias, "handling"
			    " PLOGI rp_id %x, waiting for cmds to"
			    " drain", cmd->cmd_rportid);
		}
		return (DISC_ACTION_DELAY_RESCAN);
	}
	atomic_and_32(&irp->irp_flags, ~IRP_SESSION_CLEANUP);

	/* Session can only be terminated after all the I/Os have drained */
	if (irp->irp_flags & IRP_SCSI_SESSION_STARTED) {
		stmf_deregister_scsi_session(iport->iport_port->port_lport,
		    irp->irp_session);
		stmf_free(irp->irp_session);
		irp->irp_session = NULL;
		atomic_and_32(&irp->irp_flags, ~IRP_SCSI_SESSION_STARTED);
	}

	if (cmd->cmd_type == FCT_CMD_RCVD_ELS) {
		els->els_resp_size = els->els_req_size;
		p = els->els_resp_payload = (uint8_t *)kmem_zalloc(
		    els->els_resp_size, KM_SLEEP);
		els->els_resp_alloc_size = els->els_resp_size;
		bcopy(els->els_req_payload, p, els->els_resp_size);
		p[0] = ELS_OP_ACC;
		bcopy(p+20, rp->rp_pwwn, 8);
		bcopy(p+28, rp->rp_nwwn, 8);
		bcopy(port->port_pwwn, p+20, 8);
		bcopy(port->port_nwwn, p+28, 8);
		fct_wwn_to_str(rp->rp_pwwn_str, rp->rp_pwwn);
		fct_wwn_to_str(rp->rp_nwwn_str, rp->rp_nwwn);
		fct_wwn_to_str(port->port_pwwn_str, port->port_pwwn);
		fct_wwn_to_str(port->port_nwwn_str, port->port_nwwn);

		stmf_wwn_to_devid_desc((scsi_devid_desc_t *)irp->irp_id,
		    rp->rp_pwwn, PROTOCOL_FIBRE_CHANNEL);
	}

	ret = fct_register_remote_port(port, rp, cmd);
	fct_dequeue_els(irp);
	if ((ret == FCT_SUCCESS) && !(icmd->icmd_flags & ICMD_IMPLICIT)) {
		if (cmd->cmd_type == FCT_CMD_RCVD_ELS) {
			ret = port->port_send_cmd_response(cmd, 0);
			if ((ret == FCT_SUCCESS) && IPORT_IN_NS_TOPO(iport) &&
			    !FC_WELL_KNOWN_ADDR(irp->irp_portid)) {
				fct_cmd_t *ct_cmd = fct_create_solct(port,
				    rp, NS_GSNN_NN, fct_gsnn_cb);
				if (ct_cmd) {
					fct_post_to_solcmd_queue(port, ct_cmd);
				}
				ct_cmd = fct_create_solct(port, rp,
				    NS_GSPN_ID, fct_gspn_cb);
				if (ct_cmd)
					fct_post_to_solcmd_queue(port, ct_cmd);
				ct_cmd = fct_create_solct(port, rp,
				    NS_GCS_ID, fct_gcs_cb);
				if (ct_cmd)
					fct_post_to_solcmd_queue(port, ct_cmd);
				ct_cmd = fct_create_solct(port, rp,
				    NS_GFT_ID, fct_gft_cb);
				if (ct_cmd)
					fct_post_to_solcmd_queue(port, ct_cmd);
			}
		} else {
			/*
			 * The reason we set this flag is to prevent
			 * killing a PRLI while we have not yet processed
			 * a response to PLOGI. Because the initiator
			 * will send a PRLI as soon as it responds to PLOGI.
			 * Check fct_process_els() for more info.
			 */
			atomic_or_32(&irp->irp_flags,
			    IRP_SOL_PLOGI_IN_PROGRESS);
			atomic_or_32(&icmd->icmd_flags, ICMD_KNOWN_TO_FCA);
			ret = port->port_send_cmd(cmd);
			if (ret != FCT_SUCCESS) {
				atomic_and_32(&icmd->icmd_flags,
				    ~ICMD_KNOWN_TO_FCA);
				atomic_and_32(&irp->irp_flags,
				    ~IRP_SOL_PLOGI_IN_PROGRESS);
			}
		}
	}
	atomic_dec_16(&irp->irp_sa_elses_count);

	if (ret == FCT_SUCCESS) {
		if (cmd_type == FCT_CMD_RCVD_ELS) {
			atomic_or_32(&irp->irp_flags, IRP_PLOGI_DONE);
			atomic_inc_32(&iport->iport_nrps_login);
			if (irp->irp_deregister_timer)
				irp->irp_deregister_timer = 0;
		}
		if (icmd_flags & ICMD_IMPLICIT) {
			DTRACE_FC_5(rport__login__end,
			    fct_cmd_t, cmd,
			    fct_local_port_t, port,
			    fct_i_remote_port_t, irp,
			    int, (cmd_type != FCT_CMD_RCVD_ELS),
			    int, FCT_SUCCESS);

			p = els->els_resp_payload;
			p[0] = ELS_OP_ACC;
			cmd->cmd_comp_status = FCT_SUCCESS;
			fct_send_cmd_done(cmd, FCT_SUCCESS, FCT_IOF_FCA_DONE);
		}
	} else {
		DTRACE_FC_5(rport__login__end,
		    fct_cmd_t, cmd,
		    fct_local_port_t, port,
		    fct_i_remote_port_t, irp,
		    int, (cmd_type != FCT_CMD_RCVD_ELS),
		    int, ret);

		fct_queue_cmd_for_termination(cmd, ret);
	}

	/* Do not touch cmd here as it may have been freed */

	return (DISC_ACTION_RESCAN);
}

uint8_t fct_prli_temp[] = { 0x20, 0x10, 0, 0x14, 8, 0, 0x20, 0, 0, 0, 0, 0,
				0, 0, 0, 0 };

disc_action_t
fct_process_prli(fct_i_cmd_t *icmd)
{
	fct_cmd_t		*cmd   = icmd->icmd_cmd;
	fct_remote_port_t	*rp    = cmd->cmd_rp;
	fct_local_port_t	*port  = cmd->cmd_port;
	fct_i_local_port_t	*iport = (fct_i_local_port_t *)
	    port->port_fct_private;
	fct_els_t		*els   = (fct_els_t *)
	    cmd->cmd_specific;
	fct_i_remote_port_t	*irp   = (fct_i_remote_port_t *)
	    rp->rp_fct_private;
	stmf_scsi_session_t	*ses   = NULL;
	fct_status_t		 ret;
	clock_t			 end_time;
	char			 info[FCT_INFO_LEN];

	/* We dont support solicited PRLIs yet */
	ASSERT(cmd->cmd_type == FCT_CMD_RCVD_ELS);

	if (irp->irp_flags & IRP_SOL_PLOGI_IN_PROGRESS) {
		/*
		 * Dont process the PRLI yet. Let the framework process the
		 * PLOGI completion 1st. This should be very quick because
		 * the reason we got the PRLI is because the initiator
		 * has responded to PLOGI already.
		 */
		/* XXX: Probably need a timeout here */
		return (DISC_ACTION_DELAY_RESCAN);
	}
	/* The caller has made sure that login is done */

	/* Make sure the process is fcp in this case */
	if ((els->els_req_size != 20) || (bcmp(els->els_req_payload,
	    fct_prli_temp, 16))) {
		if (els->els_req_payload[4] != 0x08)
			stmf_trace(iport->iport_alias, "PRLI received from"
			    " %x for unknown FC-4 type %x", cmd->cmd_rportid,
			    els->els_req_payload[4]);
		else
			stmf_trace(iport->iport_alias, "Rejecting PRLI from %x "
			    " pld sz %d, prli_flags %x", cmd->cmd_rportid,
			    els->els_req_size, els->els_req_payload[6]);

		fct_dequeue_els(irp);
		atomic_dec_16(&irp->irp_sa_elses_count);
		ret = fct_send_accrjt(cmd, ELS_OP_LSRJT, 3, 0x2c);
		goto prli_end;
	}

	if (irp->irp_fcp_xchg_count) {
		/* Trigger cleanup if necessary */
		if ((irp->irp_flags & IRP_FCP_CLEANUP) == 0) {
			stmf_trace(iport->iport_alias, "handling PRLI from"
			    " %x. Triggering cleanup", cmd->cmd_rportid);
			if (fct_trigger_rport_cleanup(irp, FCT_CMD_FCP_XCHG)) {
				atomic_or_32(&irp->irp_flags, IRP_FCP_CLEANUP);
			} else {
				/* XXX: handle this */
				/* EMPTY */
			}
		}

		end_time = icmd->icmd_start_time +
		    drv_usectohz(USEC_ELS_TIMEOUT);
		if (ddi_get_lbolt() > end_time) {
			(void) snprintf(info, sizeof (info),
			    "fct_process_prli: unable to clean "
			    "up I/O. iport-%p, icmd-%p", (void *)iport,
			    (void *)icmd);
			(void) fct_port_shutdown(iport->iport_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);

			return (DISC_ACTION_DELAY_RESCAN);
		}

		if ((ddi_get_lbolt() & 0x7f) == 0) {
			stmf_trace(iport->iport_alias, "handling"
			    " PRLI from %x, waiting for cmds to"
			    " drain", cmd->cmd_rportid);
		}
		return (DISC_ACTION_DELAY_RESCAN);
	}
	atomic_and_32(&irp->irp_flags, ~IRP_FCP_CLEANUP);

	/* Session can only be terminated after all the I/Os have drained */
	if (irp->irp_flags & IRP_SCSI_SESSION_STARTED) {
		stmf_deregister_scsi_session(iport->iport_port->port_lport,
		    irp->irp_session);
		stmf_free(irp->irp_session);
		irp->irp_session = NULL;
		atomic_and_32(&irp->irp_flags, ~IRP_SCSI_SESSION_STARTED);
	}

	/* All good, lets start a session */
	ses = (stmf_scsi_session_t *)stmf_alloc(STMF_STRUCT_SCSI_SESSION, 0, 0);
	if (ses) {
		ses->ss_port_private = irp;
		ses->ss_rport_id = (scsi_devid_desc_t *)irp->irp_id;
		ses->ss_lport = port->port_lport;
		if (stmf_register_scsi_session(port->port_lport, ses) !=
		    STMF_SUCCESS) {
			stmf_free(ses);
			ses = NULL;
		} else {
			irp->irp_session = ses;
			irp->irp_session->ss_rport_alias = irp->irp_snn;

			/*
			 * The reason IRP_SCSI_SESSION_STARTED is different
			 * from IRP_PRLI_DONE is that we clear IRP_PRLI_DONE
			 * inside interrupt context. We dont want to deregister
			 * the session from an interrupt.
			 */
			atomic_or_32(&irp->irp_flags, IRP_SCSI_SESSION_STARTED);
		}
	}

	fct_dequeue_els(irp);
	atomic_dec_16(&irp->irp_sa_elses_count);
	if (ses == NULL) {
		/* fail PRLI */
		ret = fct_send_accrjt(cmd, ELS_OP_LSRJT, 3, 0);
	} else {
		/* accept PRLI */
		els->els_resp_payload = (uint8_t *)kmem_zalloc(20, KM_SLEEP);
		bcopy(fct_prli_temp, els->els_resp_payload, 20);
		els->els_resp_payload[0] = 2;
		els->els_resp_payload[6] = 0x21;

		/* XXX the two bytes below need to set as per capabilities */
		els->els_resp_payload[18] = 0;
		els->els_resp_payload[19] = 0x12;

		els->els_resp_size = els->els_resp_alloc_size = 20;
		if ((ret = port->port_send_cmd_response(cmd, 0)) !=
		    FCT_SUCCESS) {
			stmf_deregister_scsi_session(port->port_lport, ses);
			stmf_free(irp->irp_session);
			irp->irp_session = NULL;
			atomic_and_32(&irp->irp_flags,
			    ~IRP_SCSI_SESSION_STARTED);
		} else {
			/* Mark that PRLI is done */
			atomic_or_32(&irp->irp_flags, IRP_PRLI_DONE);
		}
	}

prli_end:;
	if (ret != FCT_SUCCESS)
		fct_queue_cmd_for_termination(cmd, ret);

	return (DISC_ACTION_RESCAN);
}

disc_action_t
fct_process_logo(fct_i_cmd_t *icmd)
{
	fct_cmd_t		*cmd   = icmd->icmd_cmd;
	fct_remote_port_t	*rp    = cmd->cmd_rp;
	fct_local_port_t	*port  = cmd->cmd_port;
	fct_i_local_port_t	*iport = (fct_i_local_port_t *)
	    port->port_fct_private;
	fct_i_remote_port_t	*irp   = (fct_i_remote_port_t *)
	    rp->rp_fct_private;
	fct_status_t		 ret;
	char			 info[FCT_INFO_LEN];
	clock_t			 end_time;

	DTRACE_FC_4(rport__logout__start,
	    fct_cmd_t, cmd,
	    fct_local_port_t, port,
	    fct_i_remote_port_t, irp,
	    int, (cmd->cmd_type != FCT_CMD_RCVD_ELS));

	/* Drain I/Os */
	if ((irp->irp_nonfcp_xchg_count + irp->irp_fcp_xchg_count) > 1) {
		/* Trigger cleanup if necessary */
		if ((irp->irp_flags & IRP_SESSION_CLEANUP) == 0) {
			stmf_trace(iport->iport_alias, "handling LOGO rp_id"
			    " %x. Triggering cleanup", cmd->cmd_rportid);
			/* Cleanup everything except elses */
			if (fct_trigger_rport_cleanup(irp, ~(cmd->cmd_type))) {
				atomic_or_32(&irp->irp_flags,
				    IRP_SESSION_CLEANUP);
			} else {
				/* XXX: need more handling */
				return (DISC_ACTION_DELAY_RESCAN);
			}
		}

		end_time = icmd->icmd_start_time +
		    drv_usectohz(USEC_ELS_TIMEOUT);
		if (ddi_get_lbolt() > end_time) {
			(void) snprintf(info, sizeof (info),
			    "fct_process_logo: unable to clean "
			    "up I/O. iport-%p, icmd-%p", (void *)iport,
			    (void *)icmd);
			(void) fct_port_shutdown(iport->iport_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);

			return (DISC_ACTION_DELAY_RESCAN);
		}

		if ((ddi_get_lbolt() & 0x7f) == 0) {
			stmf_trace(iport->iport_alias, "handling"
			    " LOGO rp_id %x, waiting for cmds to"
			    " drain", cmd->cmd_rportid);
		}
		return (DISC_ACTION_DELAY_RESCAN);
	}
	atomic_and_32(&irp->irp_flags, ~IRP_SESSION_CLEANUP);

	/* Session can only be terminated after all the I/Os have drained */
	if (irp->irp_flags & IRP_SCSI_SESSION_STARTED) {
		stmf_deregister_scsi_session(iport->iport_port->port_lport,
		    irp->irp_session);
		stmf_free(irp->irp_session);
		irp->irp_session = NULL;
		atomic_and_32(&irp->irp_flags, ~IRP_SCSI_SESSION_STARTED);
	}

	fct_dequeue_els(irp);
	atomic_dec_16(&irp->irp_sa_elses_count);

	/* don't send response if this is an implicit logout cmd */
	if (!(icmd->icmd_flags & ICMD_IMPLICIT)) {
		if (cmd->cmd_type == FCT_CMD_RCVD_ELS) {
			ret = fct_send_accrjt(cmd, ELS_OP_ACC, 0, 0);
		} else {
			atomic_or_32(&icmd->icmd_flags, ICMD_KNOWN_TO_FCA);
			ret = port->port_send_cmd(cmd);
			if (ret != FCT_SUCCESS) {
				atomic_and_32(&icmd->icmd_flags,
				    ~ICMD_KNOWN_TO_FCA);
			}
		}

		if (ret != FCT_SUCCESS) {
			fct_queue_cmd_for_termination(cmd, ret);
		}

		DTRACE_FC_4(rport__logout__end,
		    fct_cmd_t, cmd,
		    fct_local_port_t, port,
		    fct_i_remote_port_t, irp,
		    int, (cmd->cmd_type != FCT_CMD_RCVD_ELS));

	} else {
		DTRACE_FC_4(rport__logout__end,
		    fct_cmd_t, cmd,
		    fct_local_port_t, port,
		    fct_i_remote_port_t, irp,
		    int, (cmd->cmd_type != FCT_CMD_RCVD_ELS));

		fct_cmd_free(cmd);
	}

	irp->irp_deregister_timer = ddi_get_lbolt() +
	    drv_usectohz(USEC_DEREG_RP_TIMEOUT);
	irp->irp_dereg_count = 0;

	/* Do not touch cmd here as it may have been freed */

	ASSERT(irp->irp_flags & IRP_IN_DISCOVERY_QUEUE);

	return (DISC_ACTION_RESCAN);
}

disc_action_t
fct_process_prlo(fct_i_cmd_t *icmd)
{
	fct_cmd_t		*cmd   = icmd->icmd_cmd;
	fct_remote_port_t	*rp    = cmd->cmd_rp;
	fct_local_port_t	*port  = cmd->cmd_port;
	fct_i_local_port_t	*iport = (fct_i_local_port_t *)
	    port->port_fct_private;
	fct_i_remote_port_t	*irp   = (fct_i_remote_port_t *)
	    rp->rp_fct_private;
	fct_status_t		 ret;
	clock_t			 end_time;
	char			 info[FCT_INFO_LEN];

	/* We do not support solicited PRLOs yet */
	ASSERT(cmd->cmd_type == FCT_CMD_RCVD_ELS);

	/* Drain I/Os */
	if (irp->irp_fcp_xchg_count) {
		/* Trigger cleanup if necessary */
		if ((irp->irp_flags & IRP_FCP_CLEANUP) == 0) {
			stmf_trace(iport->iport_alias, "handling LOGO from"
			    " %x. Triggering cleanup", cmd->cmd_rportid);
			/* Cleanup everything except elses */
			if (fct_trigger_rport_cleanup(irp, FCT_CMD_FCP_XCHG)) {
				atomic_or_32(&irp->irp_flags,
				    IRP_FCP_CLEANUP);
			} else {
				/* XXX: need more handling */
				return (DISC_ACTION_DELAY_RESCAN);
			}
		}

		end_time = icmd->icmd_start_time +
		    drv_usectohz(USEC_ELS_TIMEOUT);
		if (ddi_get_lbolt() > end_time) {
			(void) snprintf(info, sizeof (info),
			    "fct_process_prlo: unable to "
			    "clean up I/O. iport-%p, icmd-%p", (void *)iport,
			    (void *)icmd);
			(void) fct_port_shutdown(iport->iport_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);

			return (DISC_ACTION_DELAY_RESCAN);
		}

		if ((ddi_get_lbolt() & 0x7f) == 0) {
			stmf_trace(iport->iport_alias, "handling"
			    " PRLO from %x, waiting for cmds to"
			    " drain", cmd->cmd_rportid);
		}
		return (DISC_ACTION_DELAY_RESCAN);
	}
	atomic_and_32(&irp->irp_flags, ~IRP_FCP_CLEANUP);

	/* Session can only be terminated after all the I/Os have drained */
	if (irp->irp_flags & IRP_SCSI_SESSION_STARTED) {
		stmf_deregister_scsi_session(iport->iport_port->port_lport,
		    irp->irp_session);
		stmf_free(irp->irp_session);
		irp->irp_session = NULL;
		atomic_and_32(&irp->irp_flags, ~IRP_SCSI_SESSION_STARTED);
	}

	fct_dequeue_els(irp);
	atomic_dec_16(&irp->irp_sa_elses_count);
	ret = fct_send_accrjt(cmd, ELS_OP_ACC, 0, 0);
	if (ret != FCT_SUCCESS)
		fct_queue_cmd_for_termination(cmd, ret);

	return (DISC_ACTION_RESCAN);
}

disc_action_t
fct_process_rcvd_adisc(fct_i_cmd_t *icmd)
{
	fct_cmd_t		*cmd = icmd->icmd_cmd;
	fct_remote_port_t	*rp = cmd->cmd_rp;
	fct_local_port_t	*port = cmd->cmd_port;
	fct_i_local_port_t	*iport = (fct_i_local_port_t *)
	    port->port_fct_private;
	fct_els_t		*els = (fct_els_t *)
	    cmd->cmd_specific;
	fct_i_remote_port_t	*irp = (fct_i_remote_port_t *)
	    rp->rp_fct_private;
	uint8_t			*p;
	uint32_t		*q;
	fct_status_t		ret;

	fct_dequeue_els(irp);
	atomic_dec_16(&irp->irp_nsa_elses_count);

	/* Validate the adisc request */
	p = els->els_req_payload;
	q = (uint32_t *)p;
	if ((els->els_req_size != 28) || (bcmp(rp->rp_pwwn, p + 8, 8)) ||
	    (bcmp(rp->rp_nwwn, p + 16, 8))) {
		ret = fct_send_accrjt(cmd, ELS_OP_LSRJT, 3, 0);
	} else {
		rp->rp_hard_address = BE_32(q[1]);
		els->els_resp_size = els->els_resp_alloc_size = 28;
		els->els_resp_payload = (uint8_t *)kmem_zalloc(28, KM_SLEEP);
		bcopy(p, els->els_resp_payload, 28);
		p = els->els_resp_payload;
		q = (uint32_t *)p;
		p[0] = ELS_OP_ACC;
		q[1] = BE_32(port->port_hard_address);
		bcopy(port->port_pwwn, p + 8, 8);
		bcopy(port->port_nwwn, p + 16, 8);
		q[6] = BE_32(iport->iport_link_info.portid);
		ret = port->port_send_cmd_response(cmd, 0);
	}
	if (ret != FCT_SUCCESS) {
		fct_queue_cmd_for_termination(cmd, ret);
	}

	return (DISC_ACTION_RESCAN);
}

disc_action_t
fct_process_unknown_els(fct_i_cmd_t *icmd)
{
	fct_i_local_port_t	*iport = ICMD_TO_IPORT(icmd);
	fct_status_t		 ret   = FCT_FAILURE;
	uint8_t			 op    = 0;

	ASSERT(icmd->icmd_cmd->cmd_type == FCT_CMD_RCVD_ELS);
	fct_dequeue_els(ICMD_TO_IRP(icmd));
	atomic_dec_16(&ICMD_TO_IRP(icmd)->irp_nsa_elses_count);
	op = ICMD_TO_ELS(icmd)->els_req_payload[0];
	stmf_trace(iport->iport_alias, "Rejecting unknown unsol els %x (%s)",
	    op, FCT_ELS_NAME(op));
	ret = fct_send_accrjt(icmd->icmd_cmd, ELS_OP_LSRJT, 1, 0);
	if (ret != FCT_SUCCESS) {
		fct_queue_cmd_for_termination(icmd->icmd_cmd, ret);
	}

	return (DISC_ACTION_RESCAN);
}

disc_action_t
fct_process_rscn(fct_i_cmd_t *icmd)
{
	fct_i_local_port_t	*iport = ICMD_TO_IPORT(icmd);
	fct_status_t		 ret   = FCT_FAILURE;
	uint8_t			 op    = 0;
	uint8_t			*rscn_req_payload;
	uint32_t		 rscn_req_size;

	fct_dequeue_els(ICMD_TO_IRP(icmd));
	atomic_dec_16(&ICMD_TO_IRP(icmd)->irp_nsa_elses_count);
	if (icmd->icmd_cmd->cmd_type == FCT_CMD_RCVD_ELS) {
		op = ICMD_TO_ELS(icmd)->els_req_payload[0];
		stmf_trace(iport->iport_alias, "Accepting RSCN %x (%s)",
		    op, FCT_ELS_NAME(op));
		rscn_req_size = ICMD_TO_ELS(icmd)->els_req_size;
		rscn_req_payload = kmem_alloc(rscn_req_size, KM_SLEEP);
		bcopy(ICMD_TO_ELS(icmd)->els_req_payload, rscn_req_payload,
		    rscn_req_size);
		ret = fct_send_accrjt(icmd->icmd_cmd, ELS_OP_ACC, 1, 0);
		if (ret != FCT_SUCCESS) {
			fct_queue_cmd_for_termination(icmd->icmd_cmd, ret);
		} else {
			if (fct_rscn_options & RSCN_OPTION_VERIFY) {
				fct_rscn_verify(iport, rscn_req_payload,
				    rscn_req_size);
			}
		}

		kmem_free(rscn_req_payload, rscn_req_size);
	} else {
		ASSERT(0);
	}

	return (DISC_ACTION_RESCAN);
}

disc_action_t
fct_process_els(fct_i_local_port_t *iport, fct_i_remote_port_t *irp)
{
	fct_i_cmd_t	*cmd_to_abort = NULL;
	fct_i_cmd_t	**ppcmd, *icmd;
	fct_cmd_t	*cmd;
	fct_els_t	*els;
	int		dq;
	disc_action_t	ret = DISC_ACTION_NO_WORK;
	uint8_t		op;

	mutex_exit(&iport->iport_worker_lock);

	/*
	 * Do some cleanup based on the following.
	 * - We can only have one session affecting els pending.
	 * - If any session affecting els is pending no other els is allowed.
	 * - If PLOGI is not done, nothing except PLOGI or LOGO is allowed.
	 * NOTE: If port is down the cleanup is done outside of this
	 *	function.
	 * NOTE: There is a side effect, if a sa ELS (non PLOGI) is received
	 * while a PLOGI is pending, it will kill itself and the PLOGI.
	 * which is probably ok.
	 */
	rw_enter(&irp->irp_lock, RW_WRITER);
	ppcmd = &irp->irp_els_list;
	while ((*ppcmd) != NULL) {
		int special_prli_cond = 0;
		dq = 0;

		els = (fct_els_t *)((*ppcmd)->icmd_cmd)->cmd_specific;

		if (((*ppcmd)->icmd_cmd->cmd_type == FCT_CMD_RCVD_ELS) &&
		    (els->els_req_payload[0] == ELS_OP_PRLI) &&
		    (irp->irp_flags & IRP_SOL_PLOGI_IN_PROGRESS)) {
			/*
			 * The initiator sent a PRLI right after responding
			 * to PLOGI and we have not yet finished processing
			 * the PLOGI completion. We should not kill the PRLI
			 * as the initiator may not retry it.
			 */
			special_prli_cond = 1;
		}

		if ((*ppcmd)->icmd_flags & ICMD_BEING_ABORTED) {
			dq = 1;
		} else if (irp->irp_sa_elses_count > 1) {
			dq = 1;
			/* This els might have set the CLEANUP flag */
			atomic_and_32(&irp->irp_flags, ~IRP_SESSION_CLEANUP);
			stmf_trace(iport->iport_alias, "Killing ELS %x cond 1",
			    els->els_req_payload[0]);
		} else if (irp->irp_sa_elses_count &&
		    (((*ppcmd)->icmd_flags & ICMD_SESSION_AFFECTING) == 0)) {
			stmf_trace(iport->iport_alias, "Killing ELS %x cond 2",
			    els->els_req_payload[0]);
			dq = 1;
		} else if (((irp->irp_flags & IRP_PLOGI_DONE) == 0) &&
		    (els->els_req_payload[0] != ELS_OP_PLOGI) &&
		    (els->els_req_payload[0] != ELS_OP_LOGO) &&
		    (special_prli_cond == 0)) {
			stmf_trace(iport->iport_alias, "Killing ELS %x cond 3",
			    els->els_req_payload[0]);
			dq = 1;
		}

		if (dq) {
			fct_i_cmd_t *c = (*ppcmd)->icmd_next;

			if ((*ppcmd)->icmd_flags & ICMD_SESSION_AFFECTING)
				atomic_dec_16(&irp->irp_sa_elses_count);
			else
				atomic_dec_16(&irp->irp_nsa_elses_count);
			(*ppcmd)->icmd_next = cmd_to_abort;
			cmd_to_abort = *ppcmd;
			*ppcmd = c;
		} else {
			ppcmd = &((*ppcmd)->icmd_next);
		}
	}
	rw_exit(&irp->irp_lock);

	while (cmd_to_abort) {
		fct_i_cmd_t *c = cmd_to_abort->icmd_next;

		atomic_and_32(&cmd_to_abort->icmd_flags, ~ICMD_IN_IRP_QUEUE);
		fct_queue_cmd_for_termination(cmd_to_abort->icmd_cmd,
		    FCT_ABORTED);
		cmd_to_abort = c;
	}

	/*
	 * pick from the top of the queue
	 */
	icmd = irp->irp_els_list;
	if (icmd == NULL) {
		/*
		 * The cleanup took care of everything.
		 */

		mutex_enter(&iport->iport_worker_lock);
		return (DISC_ACTION_RESCAN);
	}

	cmd = icmd->icmd_cmd;
	els = ICMD_TO_ELS(icmd);
	op = els->els_req_payload[0];
	if ((icmd->icmd_flags & ICMD_ELS_PROCESSING_STARTED) == 0) {
		stmf_trace(iport->iport_alias, "Processing %ssol ELS %x (%s) "
		    "rp_id=%x", (cmd->cmd_type == FCT_CMD_RCVD_ELS) ? "un" : "",
		    op, FCT_ELS_NAME(op), cmd->cmd_rportid);
		atomic_or_32(&icmd->icmd_flags, ICMD_ELS_PROCESSING_STARTED);
	}

	if (op == ELS_OP_PLOGI) {
		ret |= fct_process_plogi(icmd);
	} else if (op == ELS_OP_PRLI) {
		ret |= fct_process_prli(icmd);
	} else if (op == ELS_OP_LOGO) {
		ret |= fct_process_logo(icmd);
	} else if ((op == ELS_OP_PRLO) || (op == ELS_OP_TPRLO)) {
		ret |= fct_process_prlo(icmd);
	} else if (cmd->cmd_type == FCT_CMD_SOL_ELS) {
		fct_status_t s;
		fct_local_port_t *port = iport->iport_port;

		fct_dequeue_els(irp);
		atomic_dec_16(&irp->irp_nsa_elses_count);
		atomic_or_32(&icmd->icmd_flags, ICMD_KNOWN_TO_FCA);
		if ((s = port->port_send_cmd(cmd)) != FCT_SUCCESS) {
			atomic_and_32(&icmd->icmd_flags, ~ICMD_KNOWN_TO_FCA);
			fct_queue_cmd_for_termination(cmd, s);
			stmf_trace(iport->iport_alias, "Solicited els "
			    "transport failed, ret = %llx", s);
		}
	} else if (op == ELS_OP_ADISC) {
		ret |= fct_process_rcvd_adisc(icmd);
	} else if (op == ELS_OP_RSCN) {
		(void) fct_process_rscn(icmd);
	} else {
		(void) fct_process_unknown_els(icmd);
	}

	/*
	 * This if condition will be false if a sa ELS trigged a cleanup
	 * and set the ret = DISC_ACTION_DELAY_RESCAN. In that case we should
	 * keep it that way.
	 */
	if (ret == DISC_ACTION_NO_WORK) {
		/*
		 * Since we dropped the lock, we will force a rescan. The
		 * only exception is if someone returned
		 * DISC_ACTION_DELAY_RESCAN, in which case that should be the
		 * return value.
		 */
		ret = DISC_ACTION_RESCAN;
	}

	mutex_enter(&iport->iport_worker_lock);
	return (ret);
}

void
fct_handle_sol_els_completion(fct_i_local_port_t *iport, fct_i_cmd_t *icmd)
{
	fct_i_remote_port_t	*irp = NULL;
	fct_els_t		*els = ICMD_TO_ELS(icmd);
	uint8_t			 op  = els->els_req_payload[0];

	if (icmd->icmd_cmd->cmd_rp) {
		irp = ICMD_TO_IRP(icmd);
	}
	if (icmd->icmd_cmd->cmd_rp &&
	    (icmd->icmd_cmd->cmd_comp_status == FCT_SUCCESS) &&
	    (els->els_req_payload[0] == ELS_OP_PLOGI)) {
		bcopy(els->els_resp_payload + 20, irp->irp_rp->rp_pwwn, 8);
		bcopy(els->els_resp_payload + 28, irp->irp_rp->rp_nwwn, 8);

		stmf_wwn_to_devid_desc((scsi_devid_desc_t *)irp->irp_id,
		    irp->irp_rp->rp_pwwn, PROTOCOL_FIBRE_CHANNEL);
		atomic_or_32(&irp->irp_flags, IRP_PLOGI_DONE);
		atomic_inc_32(&iport->iport_nrps_login);
		if (irp->irp_deregister_timer) {
			irp->irp_deregister_timer = 0;
			irp->irp_dereg_count = 0;
		}
	}

	if (irp && (els->els_req_payload[0] == ELS_OP_PLOGI)) {
		atomic_and_32(&irp->irp_flags, ~IRP_SOL_PLOGI_IN_PROGRESS);
	}
	atomic_or_32(&icmd->icmd_flags, ICMD_CMD_COMPLETE);
	stmf_trace(iport->iport_alias, "Sol ELS %x (%s) completed with "
	    "status %llx, did/%x", op, FCT_ELS_NAME(op),
	    icmd->icmd_cmd->cmd_comp_status, icmd->icmd_cmd->cmd_rportid);
}

static disc_action_t
fct_check_cmdlist(fct_i_local_port_t *iport)
{
	int		num_to_release, ndx;
	fct_i_cmd_t	*icmd;
	uint32_t	total, max_active;

	ASSERT(MUTEX_HELD(&iport->iport_worker_lock));

	total = iport->iport_total_alloced_ncmds;
	max_active = iport->iport_max_active_ncmds;

	if (total <= max_active)
		return (DISC_ACTION_NO_WORK);
	/*
	 * Everytime, we release half of the difference
	 */
	num_to_release = (total + 1 - max_active) / 2;

	mutex_exit(&iport->iport_worker_lock);
	for (ndx = 0; ndx < num_to_release; ndx++) {
		mutex_enter(&iport->iport_cached_cmd_lock);
		icmd = iport->iport_cached_cmdlist;
		if (icmd == NULL) {
			mutex_exit(&iport->iport_cached_cmd_lock);
			break;
		}
		iport->iport_cached_cmdlist = icmd->icmd_next;
		iport->iport_cached_ncmds--;
		mutex_exit(&iport->iport_cached_cmd_lock);
		atomic_dec_32(&iport->iport_total_alloced_ncmds);
		fct_free(icmd->icmd_cmd);
	}
	mutex_enter(&iport->iport_worker_lock);
	return (DISC_ACTION_RESCAN);
}

/*
 * The efficiency of handling solicited commands is very low here. But
 * fortunately, we seldom send solicited commands. So it will not hurt
 * the system performance much.
 */
static disc_action_t
fct_check_solcmd_queue(fct_i_local_port_t *iport)
{
	fct_i_cmd_t	*icmd	    = NULL;
	fct_i_cmd_t	*prev_icmd  = NULL;
	fct_i_cmd_t	*next_icmd  = NULL;

	ASSERT(mutex_owned(&iport->iport_worker_lock));
	for (icmd = iport->iport_solcmd_queue; icmd; icmd = next_icmd) {
		ASSERT(icmd->icmd_flags | ICMD_IN_SOLCMD_QUEUE);
		next_icmd = icmd->icmd_solcmd_next;
		if (icmd->icmd_flags & ICMD_SOLCMD_NEW) {
			/*
			 * This solicited cmd is new.
			 * Dispatch ELSes to discovery queue to make use of
			 * existent framework.
			 */
			icmd->icmd_flags &= ~ICMD_SOLCMD_NEW;
			mutex_exit(&iport->iport_worker_lock);

			if (icmd->icmd_cmd->cmd_type == FCT_CMD_SOL_ELS) {
				fct_handle_els(icmd->icmd_cmd);
			} else {
				fct_handle_solct(icmd->icmd_cmd);
			}

			mutex_enter(&iport->iport_worker_lock);
		} else if (icmd->icmd_flags & ICMD_CMD_COMPLETE) {
			/*
			 * To make fct_check_solcmd simple and flexible,
			 * We need only call callback to finish post-handling.
			 */
			if (icmd->icmd_cb) {
				/*
				 * mutex ???
				 */
				icmd->icmd_cb(icmd);
			}


			/*
			 * Release resources for this solicited cmd
			 */
			if (iport->iport_solcmd_queue == icmd) {
				iport->iport_solcmd_queue = next_icmd;
			} else {
				prev_icmd = iport->iport_solcmd_queue;
				while (prev_icmd->icmd_solcmd_next != icmd) {
					prev_icmd = prev_icmd->icmd_solcmd_next;
				}
				prev_icmd->icmd_solcmd_next = next_icmd;
			}

			icmd->icmd_cb = NULL;
			mutex_exit(&iport->iport_worker_lock);
			fct_cmd_free(icmd->icmd_cmd);
			mutex_enter(&iport->iport_worker_lock);
		} else {
			/*
			 * This solicited cmd is still ongoing.
			 * We need check if it's time to abort this cmd
			 */
			if (((icmd->icmd_start_time + drv_usectohz(
			    USEC_SOL_TIMEOUT)) < ddi_get_lbolt()) &&
			    !(icmd->icmd_flags & ICMD_BEING_ABORTED)) {
				fct_q_for_termination_lock_held(iport,
				    icmd, FCT_ABORTED);
			}
		}
	}

	return (DISC_ACTION_DELAY_RESCAN);
}

void
fct_handle_solct(fct_cmd_t *cmd)
{
	fct_status_t		 ret	  = FCT_SUCCESS;
	fct_i_cmd_t		*icmd	  = CMD_TO_ICMD(cmd);
	fct_i_local_port_t	*iport	  = ICMD_TO_IPORT(icmd);
	fct_i_remote_port_t	*irp	  = ICMD_TO_IRP(icmd);

	ASSERT(cmd->cmd_type == FCT_CMD_SOL_CT);
	rw_enter(&iport->iport_lock, RW_READER);
	/*
	 * Let's make sure local port is sane
	 */
	if ((iport->iport_link_state & S_LINK_ONLINE) == 0) {
		rw_exit(&iport->iport_lock);

		stmf_trace(iport->iport_alias, "fct_transport_solct: "
		    "solcmd-%p transport failed, becasue port state was %x",
		    cmd, iport->iport_link_state);
		fct_queue_cmd_for_termination(cmd, FCT_LOCAL_PORT_OFFLINE);
		return;
	}

	/*
	 * Let's make sure we have plogi-ed to name server
	 */
	rw_enter(&irp->irp_lock, RW_READER);
	if (!(irp->irp_flags & IRP_PLOGI_DONE)) {
		rw_exit(&irp->irp_lock);
		rw_exit(&iport->iport_lock);

		stmf_trace(iport->iport_alias, "fct_transport_solct: "
		    "Must login to name server first - cmd-%p", cmd);
		fct_queue_cmd_for_termination(cmd, FCT_NOT_LOGGED_IN);
		return;
	}

	/*
	 * Let's get a slot for this solcmd
	 */
	if (fct_alloc_cmd_slot(iport, cmd) == FCT_SLOT_EOL) {
		rw_exit(&irp->irp_lock);
		rw_exit(&iport->iport_lock);

		stmf_trace(iport->iport_alias, "fct_transport_solcmd: "
		    "ran out of xchg resources - cmd-%p", cmd);
		fct_queue_cmd_for_termination(cmd, FCT_NO_XCHG_RESOURCE);
		return;
	}

	if (fct_netbuf_to_value(ICMD_TO_CT(icmd)->ct_req_payload + 8, 2) ==
	    NS_GID_PN) {
		fct_i_remote_port_t	*query_irp = NULL;

		query_irp = fct_lookup_irp_by_portwwn(iport,
		    ICMD_TO_CT(icmd)->ct_req_payload + 16);
		if (query_irp) {
			atomic_and_32(&query_irp->irp_flags, ~IRP_RSCN_QUEUED);
		}
	}
	rw_exit(&irp->irp_lock);
	rw_exit(&iport->iport_lock);

	atomic_inc_16(&irp->irp_nonfcp_xchg_count);
	atomic_or_32(&icmd->icmd_flags, ICMD_KNOWN_TO_FCA);
	icmd->icmd_start_time = ddi_get_lbolt();
	ret = iport->iport_port->port_send_cmd(cmd);
	if (ret != FCT_SUCCESS) {
		atomic_and_32(&icmd->icmd_flags, ~ICMD_KNOWN_TO_FCA);
		fct_queue_cmd_for_termination(cmd, ret);
	}
}

void
fct_logo_cb(fct_i_cmd_t *icmd)
{
	ASSERT(!(icmd->icmd_flags & ICMD_IMPLICIT));
	if (!FCT_IS_ELS_ACC(icmd)) {
		stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias, "fct_logo_cb: "
		    "solicited LOGO is not accepted - icmd/%p", icmd);
	}
}

void
fct_gsnn_cb(fct_i_cmd_t *icmd)
{
	int			 snlen	   = 0;
	char			*sn	   = NULL;
	fct_i_remote_port_t	*query_irp = NULL;

	if (!FCT_IS_CT_ACC(icmd)) {
		stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias, "fct_gsnn_cb: "
		    "GSNN is not accepted by NS - icmd/%p", icmd);
		return;
	}
	mutex_exit(&ICMD_TO_IPORT(icmd)->iport_worker_lock);

	rw_enter(&ICMD_TO_IPORT(icmd)->iport_lock, RW_READER);
	mutex_enter(&ICMD_TO_IPORT(icmd)->iport_worker_lock);
	query_irp = fct_lookup_irp_by_nodewwn(ICMD_TO_IPORT(icmd),
	    ICMD_TO_CT(icmd)->ct_req_payload + 16);

	if (!query_irp) {
		stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias, "fct_gsnn_cb: "
		    "can't get rp icmd-%p", icmd);
		goto exit_gsnn_cb;
	} else {
		snlen = ICMD_TO_CT(icmd)->ct_resp_payload[16];
	}

	if (query_irp && snlen) {
		/*
		 * Release previous resource, then allocate needed resource
		 */
		sn = query_irp->irp_snn;
		if (sn) {
			kmem_free(sn, strlen(sn) + 1);
		}

		query_irp->irp_snn = NULL;
		sn = kmem_zalloc(snlen + 1, KM_SLEEP);
		(void) strncpy(sn, (char *)
		    ICMD_TO_CT(icmd)->ct_resp_payload + 17, snlen);
		if (strlen(sn) != snlen) {
			stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias,
			    "fct_gsnn_cb: %s, but len=%d", sn, snlen);
			kmem_free(sn, snlen + 1);
			sn = NULL;
		}

		/*
		 * Update symbolic node name
		 */
		query_irp->irp_snn = sn;
		if ((query_irp->irp_flags & IRP_SCSI_SESSION_STARTED) &&
		    (query_irp->irp_session)) {
			query_irp->irp_session->ss_rport_alias =
			    query_irp->irp_snn;
		}
	} else {
		stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias, "fct_gsnn_cb: "
		    "irp/%p, snlen/%d", query_irp, snlen);
	}

exit_gsnn_cb:
	rw_exit(&ICMD_TO_IPORT(icmd)->iport_lock);
}

void
fct_link_init_cb(fct_i_cmd_t *icmd)
{
	fct_i_local_port_t	*iport = ICMD_TO_IPORT(icmd);

	iport->iport_li_state &= ~LI_STATE_FLAG_CMD_WAITING;
	if (icmd->icmd_cmd->cmd_comp_status != FCT_SUCCESS) {
		stmf_trace(iport->iport_alias, "fct_link_init_cb: ELS-%x failed"
		    "comp_status- %llx", ICMD_TO_ELS(icmd)->els_req_payload[0],
		    icmd->icmd_cmd->cmd_comp_status);
		iport->iport_li_comp_status = icmd->icmd_cmd->cmd_comp_status;
	} else if (icmd->icmd_cmd->cmd_type == FCT_CMD_SOL_ELS) {
		if (!FCT_IS_ELS_ACC(icmd)) {
			stmf_trace(iport->iport_alias,
			    "fct_link_init_cb: ELS-%x is rejected",
			    ICMD_TO_ELS(icmd)->els_req_payload[0]);
			iport->iport_li_comp_status = FCT_REJECT_STATUS(
			    ICMD_TO_ELS(icmd)->els_resp_payload[1],
			    ICMD_TO_ELS(icmd)->els_resp_payload[2]);
		} else {
			iport->iport_li_comp_status = FCT_SUCCESS;
		}
	} else {
		ASSERT(icmd->icmd_cmd->cmd_type == FCT_CMD_SOL_CT);
		if (!FCT_IS_CT_ACC(icmd)) {
			stmf_trace(iport->iport_alias,
			    "fct_link_init_cb: CT-%02x%02x is rejected",
			    ICMD_TO_CT(icmd)->ct_req_payload[8],
			    ICMD_TO_CT(icmd)->ct_req_payload[9]);
			iport->iport_li_comp_status = FCT_REJECT_STATUS(
			    ICMD_TO_CT(icmd)->ct_resp_payload[8],
			    ICMD_TO_CT(icmd)->ct_resp_payload[9]);
		} else {
			iport->iport_li_comp_status = FCT_SUCCESS;
		}
	}
}

void
fct_gcs_cb(fct_i_cmd_t *icmd)
{
	fct_sol_ct_t		*ct	   = ICMD_TO_CT(icmd);
	fct_i_remote_port_t	*query_irp = NULL;
	fct_i_local_port_t	*iport	   = ICMD_TO_IPORT(icmd);
	uint32_t		 query_portid;
	uint8_t			*resp;
	uint8_t			*req;

	if (!FCT_IS_CT_ACC(icmd)) {
		stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias, "fct_gcs_cb: "
		    "GCS_ID is not accepted by NS - icmd/%p", icmd);
		return;
	}
	mutex_exit(&iport->iport_worker_lock);

	resp = ct->ct_resp_payload;
	req = ct->ct_req_payload;
	query_portid = (req[17] << 16) | (req[18] << 8) | req[19];

	rw_enter(&iport->iport_lock, RW_READER);
	mutex_enter(&iport->iport_worker_lock);
	query_irp = fct_portid_to_portptr(iport, query_portid);

	if (query_irp) {
		query_irp->irp_cos = (resp[16] << 27) | (resp[17] << 18) |
		    (resp[18] << 8) | resp[19];
	}
	rw_exit(&iport->iport_lock);
}

void
fct_gft_cb(fct_i_cmd_t *icmd)
{
	fct_sol_ct_t		*ct	   = ICMD_TO_CT(icmd);
	fct_i_remote_port_t	*query_irp = NULL;
	fct_i_local_port_t	*iport	   = ICMD_TO_IPORT(icmd);
	uint32_t		 query_portid;
	uint8_t			*resp;
	uint8_t			*req;

	if (!FCT_IS_CT_ACC(icmd)) {
		stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias, "fct_gft_cb: "
		    "GFT_ID is not accepted by NS - icmd/%p", icmd);
		return;
	}
	mutex_exit(&iport->iport_worker_lock);

	resp = ct->ct_resp_payload;
	req = ct->ct_req_payload;
	query_portid = (req[17] << 16) | (req[18] << 8) | req[19];

	rw_enter(&iport->iport_lock, RW_READER);
	mutex_enter(&iport->iport_worker_lock);
	query_irp = fct_portid_to_portptr(iport, query_portid);

	if (query_irp) {
		(void) memcpy(query_irp->irp_fc4types, resp + 16, 32);
	}
	rw_exit(&iport->iport_lock);
}

void
fct_gid_cb(fct_i_cmd_t *icmd)
{
	fct_cmd_t		*cmd	   = NULL;
	fct_i_remote_port_t	*query_irp = NULL;
	uint32_t		 nsportid  = 0;
	int			 do_logo   = 0;

	mutex_exit(&ICMD_TO_IPORT(icmd)->iport_worker_lock);

	rw_enter(&ICMD_TO_IPORT(icmd)->iport_lock, RW_READER);
	mutex_enter(&ICMD_TO_IPORT(icmd)->iport_worker_lock);
	query_irp = fct_lookup_irp_by_portwwn(ICMD_TO_IPORT(icmd),
	    ICMD_TO_CT(icmd)->ct_req_payload + 16);

	if (!query_irp || (query_irp &&
	    (PTR2INT(icmd->icmd_cb_private, uint32_t) !=
	    query_irp->irp_rscn_counter))) {
		stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias, "fct_gid_cb: "
		    "new RSCN arrived - query_irp/%p, private-%x", query_irp,
		    PTR2INT(icmd->icmd_cb_private, uint32_t));
		goto exit_gid_cb;
	}

	if ((query_irp->irp_flags & IRP_RSCN_QUEUED) ||
	    (!(query_irp->irp_flags & IRP_PLOGI_DONE)))	{
		stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias, "fct_gid_cb: "
		    "not proper irp_flags - query_irp/%p", query_irp);
		goto exit_gid_cb;
	}

	if (!FCT_IS_CT_ACC(icmd)) {
		/*
		 * Check if it has disappeared
		 */
		stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias, "fct_gid_cb: "
		    "GPN_ID is not accepted by NS - icmd/%p", icmd);
		do_logo = 1;
	} else {
		/*
		 * Check if its portid has changed
		 */
		nsportid = fct_netbuf_to_value(
		    ICMD_TO_CT(icmd)->ct_resp_payload + 17, 3);
		if (nsportid != query_irp->irp_rp->rp_id) {
			stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias,
			    "portid has changed - query_irp/%p", query_irp);
			do_logo = 1;
		}
	}

	if (do_logo) {
		cmd = fct_create_solels(ICMD_TO_PORT(icmd),
		    query_irp->irp_rp, 1, ELS_OP_LOGO, 0, fct_logo_cb);
		if (cmd) {
			mutex_exit(&ICMD_TO_IPORT(icmd)->iport_worker_lock);
			fct_post_implicit_logo(cmd);
			mutex_enter(&ICMD_TO_IPORT(icmd)->iport_worker_lock);
		}
	}

exit_gid_cb:
	rw_exit(&ICMD_TO_IPORT(icmd)->iport_lock);
}

void
fct_gspn_cb(fct_i_cmd_t *icmd)
{
	fct_sol_ct_t		*ct	   = ICMD_TO_CT(icmd);
	fct_i_remote_port_t	*query_irp = NULL;
	fct_i_local_port_t	*iport	   = ICMD_TO_IPORT(icmd);
	uint32_t		 query_portid;
	uint8_t			*resp;
	uint8_t			*req;
	uint8_t			 spnlen;

	if (!FCT_IS_CT_ACC(icmd)) {
		stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias, "fct_gspn_cb: "
		    "GSPN_ID is not accepted by NS - icmd/%p", icmd);
		return;
	}
	mutex_exit(&iport->iport_worker_lock);

	resp = ct->ct_resp_payload;
	req = ct->ct_req_payload;
	query_portid = (req[17] << 16) | (req[18] << 8) | req[19];

	rw_enter(&iport->iport_lock, RW_READER);
	mutex_enter(&iport->iport_worker_lock);
	query_irp = fct_portid_to_portptr(iport, query_portid);
	if (query_irp) {
		spnlen = resp[16];
		if (spnlen > 0) {
			if (query_irp->irp_spn) {
				kmem_free(query_irp->irp_spn,
				    strlen(query_irp->irp_spn) + 1);
			}
			query_irp->irp_spn = kmem_zalloc(spnlen + 1, KM_SLEEP);
			(void) strncpy(query_irp->irp_spn,
			    (char *)resp + 17, spnlen);
		}
	}
	rw_exit(&iport->iport_lock);
}

void
fct_rls_cb(fct_i_cmd_t *icmd)
{
	fct_els_t		*els = ICMD_TO_ELS(icmd);
	uint8_t			*resp;
	fct_rls_cb_data_t	*rls_cb_data = NULL;
	fct_port_link_status_t	*rls_resp;
	fct_i_local_port_t	*iport = ICMD_TO_IPORT(icmd);

	rls_cb_data = icmd->icmd_cb_private;

	if (!FCT_IS_ELS_ACC(icmd)) {
		stmf_trace(ICMD_TO_IPORT(icmd)->iport_alias, "fct_rls_cb: "
		    "solicited RLS is not accepted - icmd/%p", icmd);
		if (rls_cb_data) {
			rls_cb_data->fct_els_res = FCT_FAILURE;
			sema_v(&iport->iport_rls_sema);
		}
		return;
	}

	if (!rls_cb_data) {
		sema_v(&iport->iport_rls_sema);
		return;
	}

	resp = els->els_resp_payload;

	rls_cb_data = icmd->icmd_cb_private;

	/* Get the response and store it somewhere */
	rls_resp = (fct_port_link_status_t *)rls_cb_data->fct_link_status;
	rls_resp->LinkFailureCount = BE_32(*((uint32_t *)(resp + 4)));
	rls_resp->LossOfSyncCount = BE_32(*((uint32_t *)(resp + 8)));
	rls_resp->LossOfSignalsCount = BE_32(*((uint32_t *)(resp + 12)));
	rls_resp->PrimitiveSeqProtocolErrorCount =
	    BE_32(*((uint32_t *)(resp + 16)));
	rls_resp->InvalidTransmissionWordCount =
	    BE_32(*((uint32_t *)(resp + 20)));
	rls_resp->InvalidCRCCount = BE_32(*((uint32_t *)(resp + 24)));

	rls_cb_data->fct_els_res = FCT_SUCCESS;
	sema_v(&iport->iport_rls_sema);
	icmd->icmd_cb_private = NULL;
}

/*
 * For lookup functions, we move locking up one level
 */
fct_i_remote_port_t *
fct_lookup_irp_by_nodewwn(fct_i_local_port_t *iport, uint8_t *nodewwn)
{
	fct_i_remote_port_t	*irp = NULL;
	int			 idx = 0;

	for (idx = 0; idx < FCT_HASH_TABLE_SIZE; idx++) {
		for (irp = iport->iport_rp_tb[idx]; irp;
		    irp = irp->irp_next) {
			if (bcmp(irp->irp_rp->rp_nwwn, nodewwn, FC_WWN_LEN)) {
				continue;
			} else {
				return (irp);
			}
		}
	}

	return (NULL);
}

fct_i_remote_port_t *
fct_lookup_irp_by_portwwn(fct_i_local_port_t *iport, uint8_t *portwwn)
{
	fct_i_remote_port_t	*irp = NULL;
	int			 idx = 0;

	for (idx = 0; idx < FCT_HASH_TABLE_SIZE; idx++) {
		for (irp = iport->iport_rp_tb[idx]; irp;
		    irp = irp->irp_next) {
			if (bcmp(irp->irp_rp->rp_pwwn, portwwn, FC_WWN_LEN)) {
				continue;
			} else {
				return (irp);
			}
		}
	}

	return (NULL);
}

#ifdef	lint
#define	FCT_VERIFY_RSCN()	_NOTE(EMPTY)
#else
#define	FCT_VERIFY_RSCN()						\
do {									\
	ct_cmd = fct_create_solct(port, irp->irp_rp, NS_GID_PN,		\
	    fct_gid_cb);						\
	if (ct_cmd) {							\
		uint32_t cnt;						\
		cnt = atomic_inc_32_nv(&irp->irp_rscn_counter);	\
		CMD_TO_ICMD(ct_cmd)->icmd_cb_private =			\
		    INT2PTR(cnt, void *);				\
		irp->irp_flags |= IRP_RSCN_QUEUED;			\
		fct_post_to_solcmd_queue(port, ct_cmd);			\
	}								\
} while (0)
#endif

/* ARGSUSED */
static void
fct_rscn_verify(fct_i_local_port_t *iport, uint8_t *rscn_req_payload,
    uint32_t rscn_req_size)
{
	int			idx		= 0;
	uint8_t			page_format	= 0;
	uint32_t		page_portid	= 0;
	uint8_t			*page_buf	= NULL;
	uint8_t			*last_page_buf	= NULL;
#ifndef	lint
	fct_cmd_t		*ct_cmd		= NULL;
	fct_local_port_t	*port		= NULL;
#endif
	fct_i_remote_port_t	*irp		= NULL;

	page_buf = rscn_req_payload + 4;
	last_page_buf = rscn_req_payload +
	    fct_netbuf_to_value(rscn_req_payload + 2, 2) - 4;
#ifndef	lint
	port = iport->iport_port;
#endif
	for (; page_buf <= last_page_buf; page_buf += 4) {
		page_format = 0x03 & page_buf[0];
		page_portid = fct_netbuf_to_value(page_buf + 1, 3);

		DTRACE_FC_2(rscn__receive,
		    fct_i_local_port_t, iport,
		    int, page_portid);

		rw_enter(&iport->iport_lock, RW_READER);
		if (!page_format) {
			irp = fct_portid_to_portptr(iport, page_portid);
			if (!(irp && !(irp->irp_flags & IRP_RSCN_QUEUED))) {
				rw_exit(&iport->iport_lock);

				continue; /* try next page */
			}

			if (FC_WELL_KNOWN_ADDR(irp->irp_portid) ||
			    !(irp->irp_flags & IRP_PLOGI_DONE)) {
				rw_exit(&iport->iport_lock);

				continue; /* try next page */
			}

			FCT_VERIFY_RSCN();
		} else {
			for (idx = 0; idx < FCT_HASH_TABLE_SIZE; idx++) {
				for (irp = iport->iport_rp_tb[idx];
				    irp; irp = irp->irp_next) {
					if (FC_WELL_KNOWN_ADDR(irp->irp_portid))
						continue; /* try next irp */

					if (!(irp->irp_flags & IRP_PLOGI_DONE))
						continue; /* try next irp */

					if (irp->irp_flags & IRP_RSCN_QUEUED) {
						continue; /* try next irp */
					}
#ifndef	lint
					if (!((0xFFFFFF << (page_format * 8)) &
					    (page_portid ^ irp->irp_portid))) {
						FCT_VERIFY_RSCN();
					}
#endif
				}
			}
		}
		rw_exit(&iport->iport_lock);
	}
}
