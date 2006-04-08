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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scfd/scfparam.h>
#include <sys/scfd/scfdscpif.h>

static struct driver_minor_data {
	char	*name;
	int	type;
	int	minor_num;
} scf_minor[] = {
	{ "pwrctl", S_IFCHR, SCF_USER_INSTANCE },
	{ "rasctl", S_IFCHR, SCF_USER_INSTANCE },
	{ "rcictl", S_IFCHR, SCF_USER_INSTANCE },
	SCF_DBG_IOMP_INSTANCE
	{ NULL, 0}
};


/*
 * Function list
 */
void	scf_resource_free_dev(scf_state_t *statep);
void	scf_reload_conf(scf_state_t *statep);

/*
 * External function
 */
extern	void	scf_dscp_init(void);
extern	void	scf_dscp_fini(void);

/*
 * External value
 */
extern	int	scf_devbusy_wait_time;
extern	int	scf_cmdend_wait_time;
extern	int	scf_online_wait_time;
extern	int	scf_rxbuff_wait_time;
extern	int	scf_dscp_ack_wait_time;
extern	int	scf_dscp_end_wait_time;
extern	int	scf_dscp_txbusy_time;
extern	int	scf_dscp_callback_time;
extern	int	scf_shutdown_wait_time;
extern	int	scf_poff_wait_time;
extern	int	scf_halt_wait_time;


/*
 * scf_attach()
 *
 * Description: Driver attach() entry processing.
 *
 */
int
scf_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
#define	SCF_FUNC_NAME		"scf_attach() "
	scf_state_t		*statep;
	int			instance;
	struct driver_minor_data *dmdp;
	int			ret = DDI_FAILURE;
	char			wk_pathname[MAXPATHLEN];
	timeout_id_t		save_tmids[SCF_TIMERCD_MAX];
	int			tm_stop_cnt;

	SCFDBGMSG2(SCF_DBGFLAG_DDI,
		SCF_FUNC_NAME ": start instance = %d name = %s",
		ddi_get_instance(dip), ddi_get_name(dip));
	SC_DBG_DRV_TRACE(TC_ATTACH|TC_IN, __LINE__, &cmd,
		sizeof (ddi_attach_cmd_t));

	if (strcmp(ddi_get_name(dip), SCF_DRIVER_NAME) == 0) {
		/* pseudo device */
		if (cmd == DDI_ATTACH) {
			SCFDBGMSG(SCF_DBGFLAG_DDI, "pseudo attach proc");
			mutex_enter(&scf_comtbl.attach_mutex);

			/* get instance number */
			instance = ddi_get_instance(dip);

			/* allocate softstate */
			if (ddi_soft_state_zalloc(scfstate, instance) !=
				DDI_SUCCESS) {
				SC_DBG_DRV_TRACE(TC_ATTACH|TC_ERR, __LINE__,
					"attach  ", 8);
				cmn_err(CE_WARN,
					"%s: scf_attach: "
					"ddi_soft_state_zalloc failed.\n",
						scf_driver_name);

				mutex_exit(&scf_comtbl.attach_mutex);
				goto END_attach;
			}

			/* get softstate */
			if ((statep = ddi_get_soft_state(scfstate, instance)) ==
				NULL) {
				SC_DBG_DRV_TRACE(TC_ATTACH|TC_ERR, __LINE__,
					"attach  ", 8);
				cmn_err(CE_WARN,
					"%s: scf_attach: "
					"ddi_get_soft_state failed.\n",
						scf_driver_name);
				ddi_soft_state_free(scfstate, instance);

				mutex_exit(&scf_comtbl.attach_mutex);
				goto END_attach;
			}

			/* retain dip in soft state */
			statep->dip = dip;

			/* create minor node */
			for (dmdp = scf_minor; dmdp->name != NULL; dmdp++) {
				if (ddi_create_minor_node(dip, dmdp->name,
					dmdp->type, dmdp->minor_num,
					DDI_PSEUDO, 0) == DDI_FAILURE) {
					SC_DBG_DRV_TRACE(TC_ATTACH|TC_ERR,
						__LINE__, "attach  ", 8);
					cmn_err(CE_WARN,
						"%s: scf_attach: "
						"ddi_create_minor_node "
						"failed.\n",
							scf_driver_name);

					/* remove minor node */
					if (scf_comtbl.resource_flag &
						DID_MNODE) {
						ddi_remove_minor_node(dip,
							NULL);
						scf_comtbl.resource_flag &=
							(~DID_MNODE);
					}

					/* soft state free */
					ddi_soft_state_free(scfstate, instance);

					mutex_exit(&scf_comtbl.attach_mutex);
					goto END_attach;
				}
				scf_comtbl.resource_flag |= DID_MNODE;
				SCFDBGMSG(SCF_DBGFLAG_DDI,
					"ddi_create_minor_node() is success");
			}

			scf_comtbl.scf_pseudo_p = statep;

			mutex_exit(&scf_comtbl.attach_mutex);
		}
		ret = DDI_SUCCESS;
		goto END_attach;
	}

	/* get SCF Driver mutex */
	mutex_enter(&scf_comtbl.attach_mutex);

	if (!(scf_comtbl.resource_flag & DID_MUTEX_ALL)) {

		if (ddi_get_iblock_cookie(dip, 0, &scf_comtbl.iblock_cookie) !=
			DDI_SUCCESS) {
			SC_DBG_DRV_TRACE(TC_ATTACH|TC_ERR, __LINE__,
				"attach  ", 8);
			cmn_err(CE_WARN,
				"%s: scf_attach: "
				"ddi_get_iblock_cookie failed.\n",
					scf_driver_name);

			mutex_exit(&scf_comtbl.attach_mutex);
			goto END_attach;
		}

		mutex_init(&scf_comtbl.all_mutex, NULL, MUTEX_DRIVER,
			scf_comtbl.iblock_cookie);
		scf_comtbl.resource_flag |= DID_MUTEX_ALL;
	}
	if (!(scf_comtbl.resource_flag & DID_MUTEX_SI)) {

		if (ddi_get_soft_iblock_cookie(dip, SCF_EVENT_PRI,
			&scf_comtbl.soft_iblock_cookie) !=
			DDI_SUCCESS) {
			SC_DBG_DRV_TRACE(TC_ATTACH|TC_ERR, __LINE__,
				"attach  ", 8);
			cmn_err(CE_WARN,
				"%s: scf_attach: "
				"ddi_get_soft_iblock_cookie failed.\n",
					scf_driver_name);

			mutex_exit(&scf_comtbl.attach_mutex);
			goto END_attach;
		}

		mutex_init(&scf_comtbl.si_mutex, NULL, MUTEX_DRIVER,
			scf_comtbl.soft_iblock_cookie);
		scf_comtbl.resource_flag |= DID_MUTEX_SI;
	}
	/* add software interrupt handler */
	if (!(scf_comtbl.resource_flag & DID_SOFTINTR)) {
		if (ddi_add_softintr(dip, SCF_EVENT_PRI,
			&scf_comtbl.scf_softintr_id, NULL, NULL,
			&scf_softintr, NULL) != DDI_SUCCESS) {
			SC_DBG_DRV_TRACE(TC_ATTACH | TC_ERR, __LINE__,
				"attach  ", 8);
			cmn_err(CE_WARN,
				"%s: scf_attach: ddi_add_softintr failed.",
				scf_driver_name);
			goto ATTACH_failed;
		}
		scf_comtbl.resource_flag |= DID_SOFTINTR;
	}
	/* kstat resource initialize */
	if (!(scf_comtbl.resource_flag & DID_KSTAT)) {
		scf_kstat_init();
		scf_comtbl.resource_flag |= DID_KSTAT;
	}

	mutex_exit(&scf_comtbl.attach_mutex);

	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	/* get instance number */
	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
	/* DDI_ATTACH */
		SCFDBGMSG(SCF_DBGFLAG_DDI, "attach proc");
		/* allocate softstate */
		if (ddi_soft_state_zalloc(scfstate, instance) != DDI_SUCCESS) {
			SC_DBG_DRV_TRACE(TC_ATTACH|TC_ERR, __LINE__,
				"attach  ", 8);
			cmn_err(CE_WARN,
				"%s: scf_attach: "
				"ddi_soft_state_zalloc failed.\n",
					scf_driver_name);

			/* Unlock driver mutex */
			mutex_exit(&scf_comtbl.all_mutex);
			goto END_attach;
		}

		/* get softstate */
		if ((statep = ddi_get_soft_state(scfstate, instance)) == NULL) {
			SC_DBG_DRV_TRACE(TC_ATTACH|TC_ERR, __LINE__,
				"attach  ", 8);
			cmn_err(CE_WARN,
				"%s: scf_attach: ddi_get_soft_state failed.\n",
				scf_driver_name);
			ddi_soft_state_free(scfstate, instance);

			/* Unlock driver mutex */
			mutex_exit(&scf_comtbl.all_mutex);
			goto END_attach;
		}

		/* pathname get (use cmn_err) */
		if (ddi_pathname(dip, &wk_pathname[0]) != 0) {
			sprintf(&statep->pathname[0], "%s(%s%d)",
				&wk_pathname[0], ddi_get_name(dip), instance);
		} else {
			sprintf(&statep->pathname[0], "(%s%d)",
				ddi_get_name(dip), instance);
		}

		/* retain dip in soft state */
		statep->dip = dip;

		/* create minor node */
		sprintf(wk_pathname, "%s%d", ddi_get_name(dip), instance);
		if (ddi_create_minor_node(dip, wk_pathname, S_IFCHR, instance,
			DDI_PSEUDO, 0) == DDI_FAILURE) {
			SC_DBG_DRV_TRACE(TC_ATTACH|TC_ERR, __LINE__,
				"attach  ", 8);
			cmn_err(CE_WARN,
				"%s: scf_attach: "
				"ddi_create_minor_node failed.\n",
					scf_driver_name);
			goto ATTACH_failed;
		}
		statep->resource_flag |= S_DID_MNODE;

		statep->instance = instance;

		/* get configuration file */
		scf_reload_conf(statep);

		/* map SCF registers */
		if (scf_map_regs(dip, statep) != 0) {
			SC_DBG_DRV_TRACE(TC_ATTACH|TC_ERR, __LINE__,
				"attach  ", 8);
			goto ATTACH_failed;
		}

		/* add interrupt handler */
		if (ddi_add_intr(dip, 0, NULL, 0, &scf_intr, (caddr_t)statep) !=
			DDI_SUCCESS) {
			SC_DBG_DRV_TRACE(TC_ATTACH|TC_ERR, __LINE__,
				"attach  ", 8);
			cmn_err(CE_WARN,
				"%s: scf_attach: ddi_add_intr failed.\n",
				scf_driver_name);
			goto ATTACH_failed;
		}
		statep->resource_flag |= S_DID_INTR;

		SCF_DBG_IOMP_ADD(statep);

		/* DSCP inteface initialize */
		if (!(scf_comtbl.resource_flag & DID_DSCPINIT)) {
			scf_dscp_init();
			scf_comtbl.resource_flag |= DID_DSCPINIT;
		}

		/* permit SCF intr */
		scf_permit_intr(statep, 1);

		/* first attach */
		if ((scf_comtbl.scf_path_p == NULL) &&
			(scf_comtbl.scf_exec_p == NULL)) {
			/* no execute scf device */
			if (scf_comtbl.watchdog_after_resume) {
				scf_comtbl.alive_running = SCF_ALIVE_START;
				scf_comtbl.watchdog_after_resume = 0;
			}
			scf_chg_scf(statep, PATH_STAT_ACTIVE);
			scf_comtbl.scf_pchg_event_sub = EVENT_SUB_PCHG_WAIT;
			scf_next_cmd_check(statep);
		} else {
			/* exists execute scf device */
			scf_chg_scf(statep, PATH_STAT_STANDBY);
		}
		scf_comtbl.attach_count++;

		ddi_report_dev(dip);

		/* Collect the timers which need to be stopped */
		tm_stop_cnt = scf_timer_stop_collect(save_tmids,
			SCF_TIMERCD_MAX);

		/* Unlock driver mutex */
		mutex_exit(&scf_comtbl.all_mutex);

		/* Timer stop */
		if (tm_stop_cnt != 0) {
			scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
		}

		ret = DDI_SUCCESS;
		goto END_attach;

	case DDI_RESUME:
		SCFDBGMSG(SCF_DBGFLAG_DDI, "resume proc");
		/* get softstate */
		if ((statep = ddi_get_soft_state(scfstate, instance)) == NULL) {
			SC_DBG_DRV_TRACE(TC_ATTACH|TC_ERR, __LINE__,
				"attach  ", 8);
			cmn_err(CE_WARN,
				"%s: scf_attach: ddi_get_soft_state failed.\n",
				scf_driver_name);

			/* Unlock driver mutex */
			mutex_exit(&scf_comtbl.all_mutex);
			goto END_attach;
		}

		/* Transmitting stop release by SUSPEND */
		scf_comtbl.scf_suspend_sendstop = 0;
		/* queue update */
		scf_del_queue(statep);
		if ((statep->old_path_status == PATH_STAT_ACTIVE) ||
			(statep->old_path_status == PATH_STAT_STANDBY)) {
			if ((scf_comtbl.scf_path_p == NULL) &&
				(scf_comtbl.scf_exec_p == NULL)) {
				scf_comtbl.suspend_flag = 0;
				if (scf_comtbl.watchdog_after_resume) {
					scf_comtbl.alive_running =
						SCF_ALIVE_START;
					scf_comtbl.watchdog_after_resume = 0;
				}
				/* permit SCF intr */
				scf_permit_intr(statep, 1);
				scf_chg_scf(statep, PATH_STAT_ACTIVE);
				scf_comtbl.scf_pchg_event_sub =
					EVENT_SUB_PCHG_WAIT;
				scf_next_cmd_check(statep);
				scf_comtbl.scf_report_event_sub =
					EVENT_SUB_REPORT_RUN_WAIT;
			} else {
				/* exists execute SCF device */
				scf_chg_scf(statep, PATH_STAT_STANDBY);
				/* permit SCF intr */
				scf_permit_intr(statep, 1);
			}
		} else {
			scf_chg_scf(statep, statep->old_path_status);
		}

		/* Collect the timers which need to be stopped */
		tm_stop_cnt = scf_timer_stop_collect(save_tmids,
			SCF_TIMERCD_MAX);

		/* Unlock driver mutex */
		mutex_exit(&scf_comtbl.all_mutex);

		/* Timer stop */
		if (tm_stop_cnt != 0) {
			scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
		}

		ret = DDI_SUCCESS;
		goto END_attach;

	default:
		SC_DBG_DRV_TRACE(TC_ATTACH|TC_ERR, __LINE__, "attach  ", 8);
		/* Unlock driver mutex */
		mutex_exit(&scf_comtbl.all_mutex);
		goto END_attach;
	}

/*
 * ATTACH_failed
 */
	ATTACH_failed:

	scf_resource_free_dev(statep);

	if ((scf_comtbl.scf_exec_p == NULL) &&
		(scf_comtbl.scf_path_p == NULL) &&
		(scf_comtbl.scf_wait_p == NULL) &&
		(scf_comtbl.scf_suspend_p == NULL) &&
		(scf_comtbl.scf_stop_p == NULL) &&
		(scf_comtbl.scf_disc_p == NULL) &&
		(scf_comtbl.scf_err_p == NULL)) {
		/* last SCF device */

		/* DSCP interface area release */
		if (scf_comtbl.resource_flag & DID_DSCPINIT) {
			scf_dscp_fini();
			scf_comtbl.resource_flag &= (~DID_DSCPINIT);
		}

		/* All timer stop */
		scf_timer_all_stop();

		/* Collect the timers which need to be stopped */
		tm_stop_cnt =
			scf_timer_stop_collect(save_tmids, SCF_TIMERCD_MAX);

		/* Unlock driver mutex */
		mutex_exit(&scf_comtbl.all_mutex);

		/* Timer stop */
		if (tm_stop_cnt != 0) {
			scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
		}

		mutex_enter(&scf_comtbl.attach_mutex);

		/* destroy kstat resources */
		if (scf_comtbl.resource_flag & DID_KSTAT) {
			scf_kstat_fini();
			scf_comtbl.resource_flag &= (~DID_KSTAT);
		}

		mutex_exit(&scf_comtbl.attach_mutex);
	} else {
		/* Unlock driver mutex */
		mutex_exit(&scf_comtbl.all_mutex);
	}

	ddi_soft_state_free(scfstate, instance);

/*
 * END_attach
 */
	END_attach:

	SC_DBG_DRV_TRACE(TC_ATTACH|TC_OUT, __LINE__, &ret, sizeof (int));
	SCFDBGMSG1(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_detach()
 *
 * Description: Driver detach() entry processing.
 *
 */
int
scf_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_detach() "
	scf_state_t		*statep;
	int			instance;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;
	int			ret = DDI_FAILURE;
	scf_state_t		*next_path = 0;
	int			cv_ret;
	clock_t			wk_time;
	timeout_id_t		save_tmids[SCF_TIMERCD_MAX];
	int			tm_stop_cnt;

	SCFDBGMSG2(SCF_DBGFLAG_DDI,
		SCF_FUNC_NAME ": start instance = %d name = %s",
		ddi_get_instance(dip), ddi_get_name(dip));
	SC_DBG_DRV_TRACE(TC_DETACH|TC_IN, __LINE__, &cmd,
		sizeof (ddi_detach_cmd_t));

	if (strcmp(ddi_get_name(dip), SCF_DRIVER_NAME) == 0) {
		if (cmd == DDI_DETACH) {
			SCFDBGMSG(SCF_DBGFLAG_DDI, "pseudo detach proc");
			mutex_enter(&scf_comtbl.attach_mutex);

			/* get instance number */
			instance = ddi_get_instance(dip);

			/* remove minor node */
			if (scf_comtbl.resource_flag & DID_MNODE) {
				ddi_remove_minor_node(dip, NULL);
				scf_comtbl.resource_flag &= (~DID_MNODE);
				SCFDBGMSG(SCF_DBGFLAG_DDI,
					"ddi_remove_minor_node() is success");
			}

			/* soft state free */
			ddi_soft_state_free(scfstate, instance);

			scf_comtbl.scf_pseudo_p = NULL;

			mutex_exit(&scf_comtbl.attach_mutex);
		}
		ret = DDI_SUCCESS;
		goto END_detach;
	}
	bzero((void *)&sbuf.b[0], SCF_S_CNT_16);

	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	switch (cmd) {
	case DDI_DETACH:
		SCFDBGMSG(SCF_DBGFLAG_DDI, "detach proc");
		/* get instance number */
		instance = ddi_get_instance(dip);

		/* get softstate */
		if ((statep = ddi_get_soft_state(scfstate, instance)) == NULL) {
			SC_DBG_DRV_TRACE(TC_DETACH|TC_ERR, __LINE__,
				"detach  ", 8);
			cmn_err(CE_WARN,
				"%s: scf_detach: ddi_get_soft_state failed.\n",
				scf_driver_name);

			/* Unlock driver mutex */
			mutex_exit(&scf_comtbl.all_mutex);
			goto END_detach;
		}

		if ((scf_comtbl.scf_exec_p == statep) ||
			(scf_comtbl.scf_path_p == statep)) {
			if ((next_path = scf_comtbl.scf_wait_p) == 0) {
				if (scf_last_detach_mode == 0) {
					/* Last deveice detach is error */
					SC_DBG_DRV_TRACE(TC_DETACH|TC_MSG,
						__LINE__, "detach  ", 8);
					/* Unlock driver mutex */
					mutex_exit(&scf_comtbl.all_mutex);
					goto END_detach;
				}
			}
		}

		/* SCF command transmit sync stop */
		(void) scf_make_send_cmd(&scf_cmd, SCF_USE_STOP);

		scf_del_queue(statep);
		scf_comtbl.attach_count--;

		/* forbid interrupt */
		scf_forbid_intr(statep);

		if (next_path) {
			/* SCF path change */
			scf_comtbl.scf_wait_p = next_path->next;
			scf_chg_scf(next_path, PATH_STAT_ACTIVE);
			scf_comtbl.scf_pchg_event_sub = EVENT_SUB_PCHG_WAIT;
			scf_next_cmd_check(next_path);
		}
		/* SCF command sync start */
		(void) scf_make_send_cmd(&scf_cmd, SCF_USE_START);
		SCF_DBG_IOMP_DEL(statep);

		scf_resource_free_dev(statep);

		/* free resources allocated in driver */
		if ((scf_comtbl.scf_exec_p == NULL) &&
			(scf_comtbl.scf_path_p == NULL) &&
			(scf_comtbl.scf_wait_p == NULL) &&
			(scf_comtbl.scf_suspend_p == NULL) &&
			(scf_comtbl.scf_stop_p == NULL) &&
			(scf_comtbl.scf_disc_p == NULL) &&
			(scf_comtbl.scf_err_p == NULL)) {
			/* last device */

			/* DSCP interface area release */
			if (scf_comtbl.resource_flag & DID_DSCPINIT) {
				scf_dscp_fini();
				scf_comtbl.resource_flag &= (~DID_DSCPINIT);
			}

			/* All timer stop */
			scf_timer_all_stop();

			/* Collect the timers which need to be stopped */
			tm_stop_cnt = scf_timer_stop_collect(save_tmids,
				SCF_TIMERCD_MAX);

			/* Unlock driver mutex */
			mutex_exit(&scf_comtbl.all_mutex);

			/* Timer stop */
			if (tm_stop_cnt != 0) {
				scf_timer_untimeout(save_tmids,
					SCF_TIMERCD_MAX);
			}

			SCF_DBG_TEST_TIMER_STOP;

			mutex_enter(&scf_comtbl.attach_mutex);

			/* destroy kstat resources */
			if (scf_comtbl.resource_flag & DID_KSTAT) {
				scf_kstat_fini();
				scf_comtbl.resource_flag &= (~DID_KSTAT);
			}

			mutex_exit(&scf_comtbl.attach_mutex);
		} else {
			/* Collect the timers which need to be stopped */
			tm_stop_cnt = scf_timer_stop_collect(save_tmids,
				SCF_TIMERCD_MAX);

			/* Unlock driver mutex */
			mutex_exit(&scf_comtbl.all_mutex);

			/* Timer stop */
			if (tm_stop_cnt != 0) {
				scf_timer_untimeout(save_tmids,
					SCF_TIMERCD_MAX);
			}
		}

		/* soft state free */
		ddi_soft_state_free(scfstate, instance);

		ret = DDI_SUCCESS;
		goto END_detach;

	case DDI_SUSPEND:
		SCFDBGMSG(SCF_DBGFLAG_DDI, "suspend proc");

		/* get instance number */
		instance = ddi_get_instance(dip);

		/* get softstate */
		if ((statep = ddi_get_soft_state(scfstate, instance)) == NULL) {
			SC_DBG_DRV_TRACE(TC_DETACH|TC_ERR, __LINE__,
				"detach  ", 8);
			cmn_err(CE_WARN,
				"%s: scf_detach: ddi_get_soft_state failed.\n",
				scf_driver_name);

			/* Unlock driver mutex */
			mutex_exit(&scf_comtbl.all_mutex);
			goto END_detach;
		}

		if ((scf_comtbl.scf_exec_p == statep) ||
			(scf_comtbl.scf_path_p == statep)) {
			/* report "Shutdown start" to SCF */
			scf_comtbl.suspend_flag = 1;

			/*
			 * if watching cpu stop it, but set flag for
			 * restart after resume
			 */
			if (scf_comtbl.alive_running == SCF_ALIVE_START) {
				scf_comtbl.watchdog_after_resume = 1;
				scf_comtbl.alive_running = SCF_ALIVE_STOP;
			}
			scf_comtbl.scf_alive_event_sub = EVENT_SUB_ALSP_WAIT;
			scf_next_cmd_check(statep);
			/* SUSPEND wait state */
			wk_time = drv_usectohz(SCF_MIL2MICRO(scf_timer_value_get
				(SCF_TIMERCD_CMDEND)) + ddi_get_lbolt());
			scf_comtbl.suspend_wait = 1;
			while (scf_comtbl.suspend_wait != 0) {
				cv_ret = cv_timedwait_sig
					(&scf_comtbl.suspend_wait_cv,
						&scf_comtbl.all_mutex, wk_time);
				if (cv_ret == 0) {
					scf_comtbl.suspend_wait = 0;
					SC_DBG_DRV_TRACE(TC_KILL, __LINE__,
						&scf_comtbl.suspend_wait_cv,
						sizeof (kcondvar_t));
					break;
				} else if (cv_ret == (-1)) {
					scf_comtbl.suspend_wait = 0;
					SC_DBG_DRV_TRACE(TC_DETACH|TC_ERR,
						__LINE__, "detach  ", 8);
					break;
				}
			}
		}

		scf_del_queue(statep);
		scf_chg_scf(statep, PATH_STAT_EMPTY);

		/* forbid interrupt */
		scf_forbid_intr(statep);

		/* Collect the timers which need to be stopped */
		tm_stop_cnt =
			scf_timer_stop_collect(save_tmids, SCF_TIMERCD_MAX);

		/* Unlock driver mutex */
		mutex_exit(&scf_comtbl.all_mutex);

		/* Timer stop */
		if (tm_stop_cnt != 0) {
			scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
		}

		ret = DDI_SUCCESS;
		goto END_detach;

	default:
		SC_DBG_DRV_TRACE(TC_DETACH|TC_ERR, __LINE__, "detach  ", 8);
		/* Unlock driver mutex */
		mutex_exit(&scf_comtbl.all_mutex);
		break;

	}

/*
 * END_detach
 */
	END_detach:

	SC_DBG_DRV_TRACE(TC_DETACH|TC_OUT, __LINE__, &ret, sizeof (int));
	SCFDBGMSG1(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_resource_free_dev()
 *
 * Description: Release processing of device resources.
 *
 */
void
scf_resource_free_dev(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_resource_free_dev() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": start");

	/* remove intr */
	if (statep->resource_flag & S_DID_INTR) {
		ddi_remove_intr(statep->dip, 0, scf_comtbl.iblock_cookie);
		statep->resource_flag &= (~S_DID_INTR);
		SCFDBGMSG(SCF_DBGFLAG_DDI, "ddi_remove_intr() is success");
	}

	/* remove minor node */
	if (statep->resource_flag & S_DID_MNODE) {
		ddi_remove_minor_node(statep->dip, NULL);
		statep->resource_flag &= (~S_DID_MNODE);
		SCFDBGMSG(SCF_DBGFLAG_DDI,
			"ddi_remove_minor_node() is success");
	}

	/* unmap SCF registers */
	scf_unmap_regs(statep);

	SCFDBGMSG(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": end");
}


/*
 * scf_getinfo()
 *
 * Description: Driver getinfo() entry processing.
 *
 */
/* ARGSUSED */
int
scf_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_getinfo() "
	scf_state_t		*statep;
	int			ret;
	int			instance;

	SCFDBGMSG1(SCF_DBGFLAG_OPCLS, SCF_FUNC_NAME ": start instance = %d",
		getminor((dev_t)arg));

	instance = getminor((dev_t)arg);
	if (SCF_CHECK_INSTANCE(instance)) {
		instance = SCF_USER_INSTANCE;
	}

	switch (cmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)instance;
		ret = DDI_SUCCESS;
		goto END_getinfo;
	case DDI_INFO_DEVT2DEVINFO:
		statep = (scf_state_t *)ddi_get_soft_state(scfstate, instance);
		if (statep != NULL) {
			*resultp = statep->dip;
			ret = DDI_SUCCESS;
			goto END_getinfo;
		}
	default:
		SC_DBG_DRV_TRACE(TC_GETINFO|TC_ERR, __LINE__, "getinfo ", 8);
		*resultp = NULL;
		ret = DDI_FAILURE;
	}

/*
 * END_getinfo
 */
	END_getinfo:

	SC_DBG_DRV_TRACE(TC_GETINFO|TC_OUT, __LINE__, &ret, sizeof (int));
	SCFDBGMSG1(SCF_DBGFLAG_OPCLS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_reload_conf()
 *
 * Description: Read in processing of driver configuration file.
 *
 */
void
scf_reload_conf(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_reload_conf() "
	dev_info_t		*dip;
	int			get_prm;
	char			*wkcharp = NULL;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": start");

	if (scf_comtbl.reload_conf_flag == FLAG_OFF) {
		dip = statep->dip;

		/*
		 * get driver control mode value
		 */

		/* SCFHALT after processing  mode */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_halt_proc_mode", (-1));
		if (get_prm != (-1)) {
			scf_halt_proc_mode = (uint_t)get_prm;
		}

		/*
		 * get alive check function parameter value
		 */
		/* Operation of alive check function */
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf-alive-check-function", &wkcharp) ==
			DDI_PROP_SUCCESS) {
			if (strcmp(wkcharp, SCF_ALIVE_FUNC_ON) == 0) {
				scf_comtbl.alive_running = SCF_ALIVE_START;
			} else if (strcmp(wkcharp, SCF_ALIVE_FUNC_OFF) == 0) {
				scf_comtbl.alive_running = SCF_ALIVE_STOP;
			}
			ddi_prop_free(wkcharp);
		}

		/* Interrupt interval time */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf-alive-interval-time", (-1));
		if (get_prm != (-1)) {
			SCF_MIN_TO_10SEC(get_prm);
			scf_alive_interval_time = (uchar_t)get_prm;
		}
		/* Monitoring timeout */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf-alive-monitor-time", (-1));
		if (get_prm != (-1)) {
			SCF_MIN_TO_10SEC(get_prm);
			scf_alive_monitor_time = (uchar_t)get_prm;
		}
		/* Panic timeout */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf-alive-panic-time", (-1));
		if (get_prm != (-1)) {
			SCF_MIN_TO_10SEC(get_prm);
			scf_alive_panic_time = (ushort_t)get_prm;
		}

		if ((scf_alive_interval_time < INTERVAL_TIME_MIN) ||
			(scf_alive_interval_time > INTERVAL_TIME_MAX) ||
			(scf_alive_monitor_time < MONITOR_TIME_MIN) ||
			(scf_alive_monitor_time > MONITOR_TIME_MAX) ||
			((scf_alive_panic_time != PANIC_TIME_NONE) &&
			(scf_alive_panic_time < PANIC_TIME_MIN)) ||
			(scf_alive_panic_time > PANIC_TIME_MAX)) {
			scf_alive_interval_time = INTERVAL_TIME_DEF;
			scf_alive_monitor_time = MONITOR_TIME_DEF;
			scf_alive_panic_time = PANIC_TIME_DEF;
		}
		if (scf_alive_interval_time >= scf_alive_monitor_time) {
			scf_alive_monitor_time =
				scf_alive_interval_time + MONITOR_TIME_CORRECT;
		}

		/*
		 * get system interface control value
		 */

		/* SCFIOCRDCTRL wait timer value */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_rdctrl_sense_wait", (-1));
		if ((get_prm >= SCF_SEC2MICRO(1)) &&
			(get_prm <= SCF_SEC2MICRO(120))) {
			scf_rdctrl_sense_wait = (uint_t)get_prm;
		}

		/* Buff full wait retry timer value */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_buf_ful_rtime", (-1));
		if (get_prm >= 0) {
			scf_buf_ful_rtime = (uint_t)get_prm;
		}

		/* RCI busy wait retry timer value */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_rci_busy_rtime", (-1));
		if (get_prm >= 0) {
			scf_rci_busy_rtime = (uint_t)get_prm;
		}

		/* Tx sum retry counter */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_tesum_rcnt", (-1));
		if (get_prm >= 0) {
			scf_tesum_rcnt = (uint_t)get_prm;
		}

		/* Rx sum retry counter */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_resum_rcnt", (-1));
		if (get_prm >= 0) {
			scf_resum_rcnt = (uint_t)get_prm;
		}

		/* Command to retry counter */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_cmd_to_rcnt", (-1));
		if (get_prm >= 0) {
			scf_cmd_to_rcnt = (uint_t)get_prm;
		}

		/* Command device busy retry counter */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_devbusy_wait_rcnt", (-1));
		if (get_prm >= 0) {
			scf_devbusy_wait_rcnt = (uint_t)get_prm;
		}

		/* SCF online retry counter */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_online_wait_rcnt", (-1));
		if (get_prm >= 0) {
			scf_online_wait_rcnt = (uint_t)get_prm;
		}

		/* SCF path change retry counter */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_path_change_max", (-1));
		if (get_prm >= 0) {
			scf_path_change_max = (uint_t)get_prm;
		}

		/*
		 * get timer control value
		 */

		/* SCF command busy watch timer value */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_devbusy_wait_time", (-1));
		if (get_prm >= 0) {
			scf_devbusy_wait_time = (uint_t)get_prm;
		}

		/* SCF command completion watch value */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_cmdend_wait_time", (-1));
		if (get_prm >= 0) {
			scf_cmdend_wait_time = (uint_t)get_prm;
		}

		/* SCF online watch timer value */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_online_wait_time", (-1));
		if (get_prm >= 0) {
			scf_online_wait_time = (uint_t)get_prm;
		}

		/* Next receive wait timer value */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_rxbuff_wait_time", (-1));
		if (get_prm >= 0) {
			scf_rxbuff_wait_time = (uint_t)get_prm;
		}

		/* DSCP interface TxACK watch timer value */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_dscp_ack_wait_time", (-1));
		if (get_prm >= 0) {
			scf_dscp_ack_wait_time = (uint_t)get_prm;
		}

		/* DSCP interface TxEND watch timer value */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_dscp_end_wait_time", (-1));
		if (get_prm >= 0) {
			scf_dscp_end_wait_time = (uint_t)get_prm;
		}

		/* DSCP interface busy watch timer value */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_dscp_txbusy_time", (-1));
		if (get_prm >= 0) {
			scf_dscp_txbusy_time = (uint_t)get_prm;
		}

		/* DSCP interface callback timer value */
		get_prm = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			"scf_dscp_callback_time", (-1));
		if (get_prm >= 0) {
			scf_dscp_callback_time = (uint_t)get_prm;
		}

		/* Timer value set */
		scf_timer_init();

		scf_comtbl.reload_conf_flag = FLAG_ON;
	}

	SCFDBGMSG(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": end");
}
