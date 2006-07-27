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

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scfd/scfparam.h>
#include <sys/scfd/scfio32.h>

/*
 * Function list
 */
int	scf_open(dev_t *devp, int flag, int otyp, cred_t *cred_p);
int	scf_close(dev_t dev, int flag, int otyp, cred_t *cred_p);
int	scf_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
	int *rval_p);
int	scf_ioc_reportstat(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_clearlcd(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_wrlcd(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_getdiskled(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_setdiskled(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_getsdownreason(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_optiondisp(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_getpciconfig(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_hac(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_hstadrsinfo(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_rdclistmax(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_rdclistx(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_rdctrl(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_opecall(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_getreport(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_rcipwr(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_panicreq(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_panicchk(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_parmset(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_parmget(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_autopwrset(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_autopwrget(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_autopwrclr(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_autopwrfpoff(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_autopwrexset(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_autopwrexget(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_dr(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_eventlist(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_getevent(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_setmadmevent(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_remcscmd(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_remcsfile(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_sparecmd(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_ioc_setphpinfo(intptr_t arg, int mode, int *rval_p, int u_mode);
int	scf_push_reportsense(unsigned int rci_addr, unsigned char *sense,
	time_t timestamp);
int	scf_pop_reportsense(scfreport_t *rsense);
int	scf_push_getevent(unsigned char *event_p);
int	scf_pop_getevent(scfevent_t *event_p);
int	scf_valid_date(int year, int month, int date);
int	scf_check_pon_time(scfautopwrtime_t *ptime);
int	scf_check_poff_time(scfautopwrtime_t *ptime);

/*
 * scf_open()
 *
 * Description: Driver open() entry processing.
 *
 */
/* ARGSUSED */
int
scf_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
#define	SCF_FUNC_NAME		"scf_open() "
	int			ret = 0;
	int			instance;

	SCFDBGMSG1(SCF_DBGFLAG_OPCLS, SCF_FUNC_NAME ": start instance = %d",
		getminor(*devp));
	SC_DBG_DRV_TRACE(TC_OPEN|TC_IN, __LINE__, NULL, 0);

	/* get instance */
	instance = getminor(*devp);
	if (SCF_CHECK_INSTANCE(instance)) {
		/* is the device character ? */
		if (otyp != OTYP_CHR) {
			SC_DBG_DRV_TRACE(TC_OPEN|TC_ERR, __LINE__,
				"open    ", 8);
			ret = EINVAL;
		}
	} else {
		SC_DBG_DRV_TRACE(TC_OPEN|TC_ERR, __LINE__, "open    ", 8);
		ret = EINVAL;
	}

	SC_DBG_DRV_TRACE(TC_OPEN|TC_OUT, __LINE__, &ret, sizeof (int));
	SCFDBGMSG1(SCF_DBGFLAG_OPCLS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * close entry
 */
/* ARGSUSED */
int
scf_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_close() "
	int			ret = 0;

	SCFDBGMSG1(SCF_DBGFLAG_OPCLS, SCF_FUNC_NAME ": start instance = %d",
		getminor(dev));
	SC_DBG_DRV_TRACE(TC_CLOSE|TC_IN, __LINE__, NULL, 0);

	SC_DBG_DRV_TRACE(TC_CLOSE|TC_OUT, __LINE__, &ret, sizeof (int));
	SCFDBGMSG(SCF_DBGFLAG_OPCLS, SCF_FUNC_NAME ": end");
	return (ret);
}


/*
 * scf_ioctl()
 *
 * Description: Driver ioctl() entry processing.
 *
 */
int
scf_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
	int *rval_p)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioctl() "
	int			ret = 0;
	int			instance;
	int			u_mode;
	timeout_id_t		save_tmids[SCF_TIMERCD_MAX];
	int			tm_stop_cnt;

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start instance = %d",
		getminor(dev));
	SC_DBG_DRV_TRACE(TC_IOCTL|TC_IN, __LINE__, &cmd, sizeof (int));

#ifdef _MULTI_DATAMODEL
	/* DDI_MODEL_ILP32: SCF driver 64bit, upper 32bit */
	/* DDI_MODEL_NONE : SCF driver64bit, upper 64bit */
	u_mode = ddi_model_convert_from(mode & FMODELS);
#else /* ! _MULTI_DATAMODEL */
	/* DDI_MODEL_NONE : SCF driver 32bit, upper 32bit */
	u_mode = DDI_MODEL_NONE;
#endif /* _MULTI_DATAMODEL */

	/* get instance */
	instance = getminor(dev);

	SCF_DBG_IOMP_PROC;

	if (instance == SCF_USER_INSTANCE) {

		mutex_enter(&scf_comtbl.attach_mutex);
		if (!(scf_comtbl.resource_flag & DID_MUTEX_ALL)) {
			/* Not attach device */
			SCFDBGMSG(SCF_DBGFLAG_IOCTL, "Not attach device");
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			mutex_exit(&scf_comtbl.attach_mutex);
			ret = ENXIO;
			goto END_ioctl;
		}
		mutex_exit(&scf_comtbl.attach_mutex);

		if (drv_priv(cred_p) != 0) {
			/* Not super-user */
			if ((cmd != SCFIOCHSTADRSINFO) &&
				(cmd != SCFIOCRDCLISTMAX) &&
				(cmd != SCFIOCRDCLISTX)) {
				SCFDBGMSG(SCF_DBGFLAG_IOCTL, "Not super-user");
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"ioctl   ", 8);
				ret = EPERM;
				goto END_ioctl;
			}
		}
		mutex_enter(&scf_comtbl.all_mutex);

		/* Suspend flag check */
		if (scf_comtbl.suspend_flag) {
			SCFDBGMSG(SCF_DBGFLAG_IOCTL, "suspend execute");
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			mutex_exit(&scf_comtbl.all_mutex);
			ret = EBUSY;
			goto END_ioctl;
		}

		mutex_exit(&scf_comtbl.all_mutex);

		SCF_DBG_IOCTL_PROC;

		switch ((uint_t)cmd) {
		/*
		 * RAS control interface
		 */
		case SCFIOCREPORTSTAT:
			ret = scf_ioc_reportstat(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCCLEARLCD:
			ret = scf_ioc_clearlcd(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCWRLCD:
			ret = scf_ioc_wrlcd(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCGETDISKLED:
			ret = scf_ioc_getdiskled(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCSETDISKLED:
			ret = scf_ioc_setdiskled(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCGETSDOWNREASON:
			ret = scf_ioc_getsdownreason(arg, mode, rval_p, u_mode);
			break;

		/*
		 * System infomarion interface
		 */
		case SCFIOCOPTIONDISP:
			ret = scf_ioc_optiondisp(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCGETPCICONFIG:
			ret = scf_ioc_getpciconfig(arg, mode, rval_p, u_mode);
			break;

		/*
		 * RCI control interface
		 */
		case SCFIOCHAC:
			ret = scf_ioc_hac(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCHSTADRSINFO:
			ret = scf_ioc_hstadrsinfo(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCRDCLISTMAX:
			ret = scf_ioc_rdclistmax(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCRDCLISTX:
			ret = scf_ioc_rdclistx(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCRDCTRL:
			ret = scf_ioc_rdctrl(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCOPECALL:
			ret = scf_ioc_opecall(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCGETREPORT:
			ret = scf_ioc_getreport(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCRCIPWR:
			ret = scf_ioc_rcipwr(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCPANICREQ:
			ret = scf_ioc_panicreq(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCPANICCHK:
			ret = scf_ioc_panicchk(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCPARMSET:
			ret = scf_ioc_parmset(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCPARMGET:
			ret = scf_ioc_parmget(arg, mode, rval_p, u_mode);
			break;

		/*
		 * APCS control interface
		 */
		case SCFIOCAUTOPWRSET:
			ret = scf_ioc_autopwrset(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCAUTOPWRGET:
		case SCFIOCSYSAUTOPWRGET:
			ret = scf_ioc_autopwrget(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCSYSAUTOPWRCLR:
			ret = scf_ioc_autopwrclr(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCAUTOPWRFPOFF:
			ret = scf_ioc_autopwrfpoff(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCAUTOPWREXSET:
			ret = scf_ioc_autopwrexset(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCAUTOPWREXGET:
			ret = scf_ioc_autopwrexget(arg, mode, rval_p, u_mode);
			break;

		/*
		 * FJDR control interface
		 */
		case SCFIOCDR:
			ret = scf_ioc_dr(arg, mode, rval_p, u_mode);
			break;

		/*
		 * MADM REMCS interface
		 */
		case SCFIOCEVENTLIST:
			ret = scf_ioc_eventlist(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCGETEVENT:
			ret = scf_ioc_getevent(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCSETMADMEVENT:
			ret = scf_ioc_setmadmevent(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCREMCSCMD:
			ret = scf_ioc_remcscmd(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCREMCSFILE:
			ret = scf_ioc_remcsfile(arg, mode, rval_p, u_mode);
			break;

		case SCFIOCSPARECMD:
			ret = scf_ioc_sparecmd(arg, mode, rval_p, u_mode);
			break;

		/*
		 * Kernel interface
		 */
		case SCFIOCSETPHPINFO:
			ret = scf_ioc_setphpinfo(arg, mode, rval_p, u_mode);
			break;

		default:
			SCFDBGMSG(SCF_DBGFLAG_IOCTL, "undefined ioctl command");
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = ENOTTY;
			break;
		}
	} else {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = ENXIO;
	}

/*
 * END_ioctl
 */
	END_ioctl:

	if (scf_comtbl.resource_flag & DID_MUTEX_ALL) {
		/*
		 * untimeout() processing of the timer which stopped a timer by
		 * ioctl processing
		 * Call of driver mutex status is prohibited.
		 */
		/* Lock driver mutex */
		mutex_enter(&scf_comtbl.all_mutex);

		/* Collect the timers which need to be stopped */
		tm_stop_cnt = scf_timer_stop_collect(save_tmids,
			SCF_TIMERCD_MAX);

		/* Unlock driver mutex */
		mutex_exit(&scf_comtbl.all_mutex);

		/* Timer stop */
		if (tm_stop_cnt != 0) {
			scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
		}
	}

	SC_DBG_DRV_TRACE(TC_IOCTL|TC_OUT, __LINE__, &ret, sizeof (int));
	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_reportstat()
 *
 * Description: SCFIOCREPORTSTAT ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_reportstat(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_reportstat() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;
	scf_state_t		*wk_statep;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	bzero((void *)&sbuf.b[0], SCF_S_CNT_16);
	switch (arg) {
	case SCF_SHUTDOWN_START:
		mutex_enter(&scf_comtbl.all_mutex);

		scf_comtbl.shutdown_start_reported = 1;
		sbuf.b[0] = REPORT_STAT_SHUTDOWN_START;
		sbuf.b[1] = scf_poff_factor[scf_comtbl.poff_factor][0];
		sbuf.b[2] = scf_poff_factor[scf_comtbl.poff_factor][1];
		sbuf.b[3] = scf_poff_factor[scf_comtbl.poff_factor][2];
		break;

	case SCF_SYSTEM_RUNNING:
		mutex_enter(&scf_comtbl.all_mutex);

		sbuf.b[0] = REPORT_STAT_SYSTEM_RUNNING;
		sbuf.b[1] = 0;
		sbuf.b[2] = 0;
		sbuf.b[3] = 0;
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_reportstat;
	}

	if ((scf_comtbl.scf_report_event_sub == EVENT_SUB_REPORT_RUN_WAIT) ||
		(scf_comtbl.scf_report_event_sub ==
		EVENT_SUB_REPORT_SHUT_WAIT)) {
		scf_comtbl.scf_report_event_sub = EVENT_SUB_NONE;
	}

	scf_cmd.cmd = CMD_REPORT;
	scf_cmd.subcmd = SUB_SYSTEM_STATUS_RPT;
	scf_cmd.scount = SCF_S_CNT_15;
	scf_cmd.sbuf = &sbuf.b[0];
	scf_cmd.rcount = 0;
	scf_cmd.flag = SCF_USE_S_BUF;
	scf_comtbl.scf_last_report = arg;

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	if ((ret == EBUSY) &&
		(scf_cmd.stat0 == SCF_STAT0_NOT_PATH) &&
		(arg == SCF_SHUTDOWN_START)) {
		wk_statep = scf_comtbl.scf_stop_p;
		ret = EIO;
		if (wk_statep != NULL) {
			scf_del_queue(wk_statep);
			/* Interrupt enable */
			scf_permit_intr(wk_statep, 1);
			scf_chg_scf(wk_statep, PATH_STAT_ACTIVE);
			scf_comtbl.scf_exec_p = wk_statep;
			/* SCF command send sync stop */
			ret = scf_make_send_cmd(&scf_cmd, SCF_USE_STOP);
			if (ret == 0) {
				/* new report shutdown */
				scf_cmd.subcmd = SUB_SYSTEM_STATUS_RPT_NOPATH;
				scf_cmd.flag = (SCF_USE_S_BUF | SCF_USE_SP);
				ret = scf_send_cmd_check_bufful(&scf_cmd);
				if (ret == 0) {
					/*
					 * SCF command send sync re-stop
					 */
					ret = scf_make_send_cmd(&scf_cmd,
						SCF_USE_STOP);
				}
			}
			/* FIOMPSTART exec status */
			if ((wk_statep == scf_comtbl.scf_exec_p) ||
				(wk_statep == scf_comtbl.scf_path_p)) {
				if (scf_comtbl.watchdog_after_resume) {
					/*
					 * Alive check status recovery
					 */
					scf_comtbl.alive_running =
						SCF_ALIVE_START;
					scf_comtbl.watchdog_after_resume = 0;
				}
				scf_chg_scf(wk_statep, PATH_STAT_ACTIVE);
				/* SCF path change send */
				scf_comtbl.scf_exec_p = 0;
				scf_comtbl.scf_path_p = 0;
				scf_comtbl.scf_pchg_event_sub =
					EVENT_SUB_PCHG_WAIT;
				scf_next_cmd_check(wk_statep);
			}
			/* SCF command send sync start */
			(void) scf_make_send_cmd(&scf_cmd, SCF_USE_START);
		}
	}

	mutex_exit(&scf_comtbl.all_mutex);

/*
 * END_reportstat
 */
	END_reportstat:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_clearlcd()
 *
 * Description: SCFIOCCLEARLCD ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_clearlcd(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_clearlcd() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;
	int			ii;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scf_cmd.cmd = CMD_PHASE;
	scf_cmd.rcount = 0;
	scf_cmd.flag = SCF_USE_L_BUF;

	switch (arg) {
	case SCF_CLRLCD_SEQ:
		scf_cmd.subcmd = SUB_PHASE_PRINT;
		scf_cmd.scount = 1;
		scf_cmd.sbuf = &sbuf.b[0];

		mutex_enter(&scf_comtbl.all_mutex);

		for (ii = 0; ii < SCF_WRLCD_MAX; ii++) {
			scf_comtbl.lcd_seq_mes[ii] = '\0';
			sbuf.b[ii] = '\0';
		}

		ret = scf_send_cmd_check_bufful(&scf_cmd);

		mutex_exit(&scf_comtbl.all_mutex);
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		break;
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_wrlcd()
 *
 * Description: SCFIOCWRLCD ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_wrlcd(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_wrlcd() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;
	scfwrlcd_t		scfwrlcd;
	scfwrlcd32_t		scfwrlcd32;
	int			ii;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (u_mode == DDI_MODEL_ILP32) {
		/* DDI_MODEL_ILP32 */
		if (ddi_copyin((void *)arg, (void *)&scfwrlcd32,
			sizeof (scfwrlcd32_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
			goto END_wrlcd;
		}
		scfwrlcd.lcd_type = scfwrlcd32.lcd_type;
		scfwrlcd.length = scfwrlcd32.length;
		scfwrlcd.string = (unsigned char *)(uintptr_t)scfwrlcd32.string;
	} else {
		/* DDI_MODEL_NONE */
		if (ddi_copyin((void *)arg, (void *)&scfwrlcd,
			sizeof (scfwrlcd_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
			goto END_wrlcd;
		}
	}

	if (scfwrlcd.length < 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_wrlcd;
	}
	if (scfwrlcd.length > SCF_WRLCD_MAX) {
		scfwrlcd.length = SCF_WRLCD_MAX;
	}
	for (ii = 0; ii < SCF_WRLCD_MAX + 1; ii++) {
		sbuf.b[ii] = '\0';
	}
	sbuf.b[scfwrlcd.length] = '\0';

	if (ddi_copyin((void *)scfwrlcd.string, (void *)&sbuf.b[0],
		(size_t)scfwrlcd.length, mode)) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_wrlcd;
	}

	scf_cmd.cmd = CMD_PHASE;
	scf_cmd.scount = scfwrlcd.length + 1;
	scf_cmd.sbuf = &sbuf.b[0];
	scf_cmd.rcount = 0;
	scf_cmd.flag = SCF_USE_L_BUF;

	switch (scfwrlcd.lcd_type) {
	case SCF_WRLCD_SEQ:
		scf_cmd.subcmd = SUB_PHASE_PRINT;

		mutex_enter(&scf_comtbl.all_mutex);
		bcopy((void *)&sbuf.b[0], (void *)&scf_comtbl.lcd_seq_mes[0],
			SCF_WRLCD_MAX);

		ret = scf_send_cmd_check_bufful(&scf_cmd);

		mutex_exit(&scf_comtbl.all_mutex);
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		break;
	}

/*
 * END_wrlcd
 */
	END_wrlcd:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_getdiskled()
 *
 * Description: SCFIOCGETDISKLED ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_getdiskled(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_getdiskled() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	rbuf;
	scfiocgetdiskled_t	*scfiocgetdiskled_p = NULL;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scfiocgetdiskled_p = kmem_zalloc((size_t)(sizeof (scfiocgetdiskled_t)),
		KM_SLEEP);

	if (ddi_copyin((void *)arg, (void *)scfiocgetdiskled_p,
		sizeof (scfiocgetdiskled_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_getdiskled;
	}

	scf_cmd.cmd = CMD_DOMAIN_INFO;
	scf_cmd.subcmd = SUB_DISK_LED_DISP;
	scf_cmd.sbuf = &scfiocgetdiskled_p->path[0];
	scf_cmd.scount = SCF_DISK_LED_PATH_MAX;
	scf_cmd.rbuf = &rbuf.b[0];
	scf_cmd.rcount = SCF_S_CNT_15;
	scf_cmd.flag = SCF_USE_LSBUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

	if (ret == 0) {
		scfiocgetdiskled_p->led = rbuf.b[0];

		if (ddi_copyout((void *)scfiocgetdiskled_p, (void *)arg,
			sizeof (scfiocgetdiskled_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

/*
 * END_getdiskled
 */
	END_getdiskled:

	if (scfiocgetdiskled_p) {
		kmem_free((void *)scfiocgetdiskled_p,
			(size_t)(sizeof (scfiocgetdiskled_t)));
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_setdiskled()
 *
 * Description: SCFIOCSETDISKLED ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_setdiskled(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_setdiskled() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scfiocgetdiskled_t	*scfiocgetdiskled_p = NULL;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scfiocgetdiskled_p = kmem_zalloc((size_t)(sizeof (scfiocgetdiskled_t)),
		KM_SLEEP);

	if (ddi_copyin((void *)arg, (void *)scfiocgetdiskled_p,
		sizeof (scfiocgetdiskled_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_setdiskled;
	}

	switch (scfiocgetdiskled_p->led) {
	case SCF_DISK_LED_ON:
		scf_cmd.subcmd = SUB_DISK_LED_ON;
		break;

	case SCF_DISK_LED_BLINK:
		scf_cmd.subcmd = SUB_DISK_LED_BLINK;
		break;

	case SCF_DISK_LED_OFF:
		scf_cmd.subcmd = SUB_DISK_LED_OFF;
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_setdiskled;
	}

	scf_cmd.cmd = CMD_DOMAIN_INFO;
	scf_cmd.sbuf = &scfiocgetdiskled_p->path[0];
	scf_cmd.scount = SCF_DISK_LED_PATH_MAX;
	scf_cmd.rcount = 0;
	scf_cmd.flag = SCF_USE_L_BUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

/*
 * END_setdiskled
 */
	END_setdiskled:

	if (scfiocgetdiskled_p) {
		kmem_free((void *)scfiocgetdiskled_p,
			(size_t)(sizeof (scfiocgetdiskled_t)));
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_getsdownreason()
 *
 * Description: SCFIOCGETSDOWNREASON ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_getsdownreason(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_getsdownreason() "
	int			ret = 0;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (ddi_copyout((void *)&scf_comtbl.scf_shutdownreason,
		(void *)arg, sizeof (int), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_optiondisp()
 *
 * Description: SCFIOCOPTIONDISP ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_optiondisp(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_optiondisp() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scfoption_t		scfoption;
	scf_short_buffer_t	sbuf;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	bzero((void *)&scfoption, sizeof (scfoption_t));
	bzero((void *)&sbuf.b[0], SCF_S_CNT_16);

	scf_cmd.cmd = CMD_DOMAIN_INFO;
	scf_cmd.subcmd = SUB_OPTION_DISP;
	sbuf.b[13] = (uchar_t)(scf_scfd_comif_version >> 8);
	sbuf.b[14] = (uchar_t)scf_scfd_comif_version;
	scf_cmd.sbuf = &sbuf.b[0];
	scf_cmd.scount = SCF_S_CNT_15;
	scf_cmd.rbuf = &scfoption.rbuf[0];
	scf_cmd.rcount = SCF_S_CNT_15;
	scf_cmd.flag = SCF_USE_SSBUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

	if (ret == 0) {
		/* Set XSCF version */
		bcopy((void *)&scfoption.rbuf[13],
			(void *)&scf_xscf_comif_version, 2);

		if (ddi_copyout((void *)&scfoption, (void *)arg,
			sizeof (scfoption_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_getpciconfig()
 *
 * Description: SCFIOCGETPCICONFIG ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_getpciconfig(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_getpciconfig() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scfiocgetpciconfig_t	*scfiocgetpciconfig_p = NULL;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scfiocgetpciconfig_p =
		kmem_zalloc((size_t)(sizeof (scfiocgetpciconfig_t)), KM_SLEEP);

	if (ddi_copyin((void *)arg, (void *)scfiocgetpciconfig_p,
		sizeof (scfiocgetpciconfig_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_getpciconfig;
	}

	scf_cmd.cmd = CMD_DOMAIN_INFO;
	scf_cmd.subcmd = SUB_PCI_DISP;
	scf_cmd.sbuf = &scfiocgetpciconfig_p->sbuf[0];
	scf_cmd.scount = SCF_S_CNT_15;
	scf_cmd.rbuf = &scfiocgetpciconfig_p->rbuf[0];
	scf_cmd.rcount = SCF_L_CNT_MAX;
	scf_cmd.flag = SCF_USE_SLBUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

	if (ret == 0) {
		if (ddi_copyout((void *)scfiocgetpciconfig_p,
			(void *)arg, sizeof (scfiocgetpciconfig_t),
			mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

/*
 * END_getpciconfig
 */
	END_getpciconfig:

	if (scfiocgetpciconfig_p) {
		kmem_free((void *)scfiocgetpciconfig_p,
			(size_t)(sizeof (scfiocgetpciconfig_t)));
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_hac()
 *
 * Description: SCFIOCHAC ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_hac(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_hac() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;
	scfhac_t		scfhac;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (ddi_copyin((void *)arg, (void *)&scfhac,
		sizeof (scfhac_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_hac;
	}

	if (scfhac.sub_command == SUB_HOSTADDR_DISP2) {
		mutex_enter(&scf_comtbl.all_mutex);
		if (scf_save_hac_flag != 0) {
			mutex_exit(&scf_comtbl.all_mutex);
			if (ddi_copyout((void *)&scf_save_hac, (void *)arg,
				sizeof (scfhac_t), mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"ioctl   ", 8);
				ret = EFAULT;
			}
			goto END_hac;
		} else {
			mutex_exit(&scf_comtbl.all_mutex);
		}
		scfhac.sub_command = SUB_HOSTADDR_DISP;
	}
	scf_cmd.cmd = CMD_RCI_CTL;
	scf_cmd.subcmd = scfhac.sub_command;
	scf_cmd.sbuf = &scfhac.sbuf[0];
	scf_cmd.scount = SCF_S_CNT_15;
	scf_cmd.rbuf = &scfhac.rbuf[0];
	scf_cmd.rcount = SCF_S_CNT_15;

	switch (scfhac.sub_command) {
	case SUB_REMOTE_POWCTL_SET:
		scf_cmd.flag = SCF_USE_S_BUF;
		break;

	case SCF_SUB_REMOTE_POWCTL_SET:
		bzero((void *)&sbuf.b[0], SCF_S_CNT_16);
		sbuf.b[0] = scfhac.sbuf[6];
		sbuf.b[1] = scfhac.sbuf[7];
		scf_cmd.sbuf = &sbuf.b[0];
		scf_cmd.subcmd = SUB_REMOTE_POWCTL_SET;
		scf_cmd.flag = SCF_USE_S_BUF;
		break;

	case SUB_HOSTADDR_DISP:
	case SUB_DEVICE_INFO:
		scf_cmd.flag = SCF_USE_SSBUF;
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_hac;
	}

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	if (ret == 0) {
		if (scfhac.sub_command == SUB_HOSTADDR_DISP) {
			bcopy((void *)&scfhac, (void *)&scf_save_hac,
				sizeof (scfhac_t));
			scf_save_hac_flag = 1;
		}

		mutex_exit(&scf_comtbl.all_mutex);

		if (ddi_copyout((void *)&scfhac, (void *)arg, sizeof (scfhac_t),
			mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	} else {
		mutex_exit(&scf_comtbl.all_mutex);
	}

/*
 * END_hac
 */
	END_hac:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_hstadrsinfo()
 *
 * Description: SCFIOCHSTADRSINFO ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_hstadrsinfo(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_hstadrsinfo() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	rbuf;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scf_cmd.cmd = CMD_RCI_CTL;
	scf_cmd.subcmd = SUB_HOSTADDR_DISP;
	scf_cmd.scount = 0;
	scf_cmd.rbuf = &rbuf.b[0];
	scf_cmd.rcount = SCF_S_CNT_12;
	scf_cmd.flag = SCF_USE_SSBUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	if (ret == 0) {
		bcopy((void *)&rbuf.b[0], (void *)&scf_save_hac.rbuf[0],
			SCF_S_CNT_12);
		scf_save_hac_flag = 1;

		mutex_exit(&scf_comtbl.all_mutex);

		if (ddi_copyout((void *)&rbuf.b[0], (void *)arg, SCF_S_CNT_12,
			mode) < 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	} else {
		mutex_exit(&scf_comtbl.all_mutex);
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_rdclistmax()
 *
 * Description: SCFIOCRDCLISTMAX ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_rdclistmax(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_rdclistmax() "
	int			ret = 0;
	int			scfrdclistmax;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scfrdclistmax = (scf_rci_max * SCF_DEVLIST_MAXCNT);

	if (ddi_copyout((void *)&scfrdclistmax, (void *)arg, sizeof (int),
		mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_rdclistx()
 *
 * Description: SCFIOCRDCLISTX ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_rdclistx(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_rdclistx() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;
	scfrdclistx_t		*rdclistxp = NULL;
	scfrdclistx_t		*rdclistxp_wk = NULL;
	union wk_buffer {
		uchar_t		b[8];
		uint_t		four_bytes_access[2];
	}			*rbuf_wk;
	int			ii;
	int			jj;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	mutex_enter(&scf_comtbl.all_mutex);

	rdclistxp =
		(scfrdclistx_t *)kmem_zalloc((size_t)(sizeof (scfrdclistx_t) *
		scf_rci_max * SCF_DEVLIST_MAXCNT), KM_SLEEP);
	rdclistxp_wk =
		(scfrdclistx_t *)kmem_zalloc((size_t)(sizeof (scfrdclistx_t) *
		scf_rci_max), KM_SLEEP);

	bzero((void *)&sbuf.b[0], SCF_S_CNT_16);

	/* set device class */
	sbuf.four_bytes_access[0] = 0x00000fff;
	sbuf.b[4] = 0;					/* 0 system */

	scf_cmd.cmd = CMD_RCI_CTL;
	scf_cmd.subcmd = SUB_DEVICE_LIST;
	scf_cmd.scount = SCF_S_CNT_15;
	scf_cmd.sbuf = &sbuf.b[0];
	scf_cmd.rcount = scf_rci_max * SCF_DEVLIST_ENTSIZE;
	scf_cmd.rbuf = (uchar_t *)rdclistxp_wk;
	scf_cmd.flag = SCF_USE_SLBUF;

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	if (ret != 0) {
		mutex_exit(&scf_comtbl.all_mutex);
		goto END_rdclistx;
	}

	rbuf_wk = (union wk_buffer *)rdclistxp_wk;
	for (jj = 0; jj < (scf_cmd.rbufleng / SCF_DEVLIST_ENTSIZE);
		jj++) {
		if (rbuf_wk->four_bytes_access[0] == NULL) {
			break;
		}
		rdclistxp[jj].rci_addr = rbuf_wk->four_bytes_access[0];
		rdclistxp[jj].status = rbuf_wk->b[4];
		rdclistxp[jj].dev_class =
			((ushort_t)rbuf_wk->b[5] << 8) +
			(ushort_t)rbuf_wk->b[6];
		rdclistxp[jj].sub_class = rbuf_wk->b[7];
		rbuf_wk++;
	}

	/* set device class */
	sbuf.four_bytes_access[0] = 0x00000fff;
	sbuf.b[4] = 1;					/* 1 system */

	scf_cmd.cmd = CMD_RCI_CTL;
	scf_cmd.subcmd = SUB_DEVICE_LIST;
	scf_cmd.scount = SCF_S_CNT_15;
	scf_cmd.sbuf = &sbuf.b[0];
	scf_cmd.rcount = scf_rci_max * SCF_DEVLIST_ENTSIZE;
	scf_cmd.rbuf = (uchar_t *)rdclistxp_wk;
	scf_cmd.flag = SCF_USE_SLBUF;

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	if (ret != 0) {
		mutex_exit(&scf_comtbl.all_mutex);
		goto END_rdclistx;
	}

	mutex_exit(&scf_comtbl.all_mutex);

	rbuf_wk = (union wk_buffer *)rdclistxp_wk;
	for (ii = 0; ii < (scf_cmd.rbufleng / SCF_DEVLIST_ENTSIZE); ii++) {
		if (rbuf_wk->four_bytes_access[0] == NULL) {
			break;
		}
		rdclistxp[ii + jj].rci_addr = rbuf_wk->four_bytes_access[0];
		rdclistxp[ii + jj].status = rbuf_wk->b[4];
		rdclistxp[ii + jj].dev_class =
			((ushort_t)rbuf_wk->b[5] << 8) +
			(ushort_t)rbuf_wk->b[6];
		rdclistxp[ii + jj].sub_class = rbuf_wk->b[7];
		rbuf_wk++;
	}

	/* return number of data */
	*rval_p = (ii + jj);

	if (ii + jj) {
		if (ddi_copyout((void *)rdclistxp, (void *)arg,
			(size_t)(sizeof (scfrdclistx_t) * (ii + jj)),
			mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

/*
 * END_rdclistx
 */
	END_rdclistx:

	if (rdclistxp) {
		kmem_free((void *)rdclistxp, (size_t)(sizeof (scfrdclistx_t) *
			scf_rci_max * SCF_DEVLIST_MAXCNT));
	}
	if (rdclistxp_wk) {
		kmem_free((void *)rdclistxp_wk,
			(size_t)(sizeof (scfrdclistx_t) * scf_rci_max));
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_rdctrl()
 *
 * Description: SCFIOCRDCTRL ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_rdctrl(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_rdctrl() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scfrdctrl_t		scfrdctrl;
	int			got_sense = 0;
	clock_t			lb;
	int			ii;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (ddi_copyin((void *)arg, (void *)&scfrdctrl,
		sizeof (scfrdctrl_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_rdctrl;
	}
	if ((scfrdctrl.sub_cmd != SUB_DEVICE_STATUS_RPT) &&
		(scfrdctrl.sub_cmd != SCF_SUB_DEVICE_STATUS_RPT) &&
		((scfrdctrl.sub_cmd | SCF_RCI_PATH_PARITY) !=
		SCF_RCI_PATH_40)) {
		/* wrong sub_cmd */
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_rdctrl;
	}

	mutex_enter(&scf_comtbl.all_mutex);

	while (scf_comtbl.rdctrl_busy) {
		SC_DBG_DRV_TRACE(TC_W_SIG, __LINE__, &scf_comtbl.rdctrl_cv,
			sizeof (kcondvar_t));
		if (cv_wait_sig(&scf_comtbl.rdctrl_cv,
			&scf_comtbl.all_mutex) == 0) {
			SC_DBG_DRV_TRACE(TC_KILL, __LINE__,
				&scf_comtbl.rdctrl_cv, sizeof (kcondvar_t));
			mutex_exit(&scf_comtbl.all_mutex);
			ret = EINTR;
			goto END_rdctrl;
		}
	}
	scf_comtbl.rdctrl_busy = 1;

	for (ii = scfrdctrl.scount; ii < SCF_S_CNT_32; ii++) {
		scfrdctrl.sbuf[ii] = 0;
	}
	if ((scfrdctrl.sub_cmd == SUB_DEVICE_STATUS_RPT) ||
		(scfrdctrl.sub_cmd == SCF_SUB_DEVICE_STATUS_RPT)) {
		scf_cmd.flag = SCF_USE_S_BUF;
	} else {
		/* SUB_RCI_PATH_4* */
		scf_cmd.flag = SCF_USE_L_BUF;
		/* Parameter size set */
		if (scfrdctrl.scount > 6) {
			scfrdctrl.sbuf[5] = (scfrdctrl.scount - 6);
		} else {
			scfrdctrl.sbuf[5] = 0;
		}
	}
	scf_cmd.cmd = CMD_RCI_CTL;
	if (scfrdctrl.sub_cmd == SCF_SUB_DEVICE_STATUS_RPT) {
		scf_cmd.subcmd = SUB_DEVICE_STATUS_RPT;
	} else if (scfrdctrl.sub_cmd ==
		(SCF_RCI_PATH_40 & (~SCF_RCI_PATH_PARITY))) {
		scf_cmd.subcmd = SCF_RCI_PATH_40;
	} else {
		scf_cmd.subcmd = scfrdctrl.sub_cmd;
	}
	scf_comtbl.rdctrl_sense_category_code = 0;
	scf_cmd.sbuf = &scfrdctrl.sbuf[0];
	scf_cmd.scount = SCF_S_CNT_32;
	scf_cmd.rcount = 0;
	ret = scf_send_cmd_check_bufful(&scf_cmd);

	if (ret != 0) {
		goto END_rdctrl_signal;
	}

	/* wait for sense */
	lb = ddi_get_lbolt();
	while (scf_comtbl.rdctrl_sense_category_code == 0) {
		SC_DBG_DRV_TRACE(TC_T_WAIT, __LINE__, &scf_comtbl.rdcsense_cv,
			sizeof (kcondvar_t));
		scf_comtbl.rdctrl_end_wait = 1;
		if (cv_timedwait(&scf_comtbl.rdcsense_cv, &scf_comtbl.all_mutex,
			drv_usectohz(scf_rdctrl_sense_wait) + lb) == (-1)) {
			/* time out */
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = ENODATA;
			goto END_rdctrl_signal;
		}
	}

	/* check RCI-addr and category code */
	if ((bcmp((void *)&scf_comtbl.rdctrl_sense[0],
		(void *)&scfrdctrl.sbuf[0], 4) == 0) &&
		(((scf_comtbl.rdctrl_sense_category_code) ==
		(scfrdctrl.sub_cmd & (~SCF_RCI_PATH_PARITY))) ||
		((scf_comtbl.rdctrl_sense_category_code ==
		DEV_SENSE_STATUS_RPT) &&
		((scfrdctrl.sub_cmd == SUB_DEVICE_STATUS_RPT) ||
		(scfrdctrl.sub_cmd == SCF_SUB_DEVICE_STATUS_RPT))))) {
		bcopy((void *)&scf_comtbl.rdctrl_sense[0],
			(void *)&scfrdctrl.sense[0], 4);
		bcopy((void *)&scf_comtbl.rdctrl_sense[8],
			(void *)&scfrdctrl.sense[4], (SCF_INT_REASON_SIZE - 4));
		got_sense = 1;
	} else {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = ENODATA;
	}

/*
 * END_rdctrl_signal
 */
	END_rdctrl_signal:

	scf_comtbl.rdctrl_end_wait = 0;
	scf_comtbl.rdctrl_busy = 0;
	cv_signal(&scf_comtbl.rdctrl_cv);
	SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__, &scf_comtbl.rdctrl_cv,
		sizeof (kcondvar_t));
	mutex_exit(&scf_comtbl.all_mutex);
	if (got_sense) {
		if (ddi_copyout((void *)&scfrdctrl, (void *)arg,
			sizeof (scfrdctrl_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

/*
 * END_rdctrl
 */
	END_rdctrl:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_opecall()
 *
 * Description: SCFIOCOPECALL ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_opecall(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_opecall() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scfhac_t		scfhac;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (ddi_copyin((void *)arg, (void *)&scfhac, sizeof (scfhac_t),
		mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_opecall;
	}

	scf_cmd.cmd = CMD_REPORT;
	scf_cmd.subcmd = scfhac.sub_command;
	scf_cmd.scount = SCF_S_CNT_15;
	scf_cmd.sbuf = &scfhac.sbuf[0];
	scf_cmd.rcount = SCF_S_CNT_15;
	scf_cmd.rbuf = &scfhac.rbuf[0];

	switch (scfhac.sub_command) {
	case SUB_OPECALL_ON_SET:
	case SUB_OPECALL_OFF_SET:
		scf_cmd.flag = SCF_USE_S_BUF;
		break;

	case SUB_OPECALL_DISP:
		scf_cmd.flag = SCF_USE_SSBUF;
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_opecall;
	}

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

	if (ret == 0) {
		if (ddi_copyout((void *)&scfhac, (void *)arg, sizeof (scfhac_t),
			mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

/*
 * END_opecall
 */
	END_opecall:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_getreport()
 *
 * Description: SCFIOCGETREPORT ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_getreport(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_getreport() "
	scfreport_t		scfreport;
	scfreport32_t		scfreport32;
	scfreport_t		*scfreport_p;
	int			ret = 0;
	int			loop_flag = 1;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (u_mode == DDI_MODEL_ILP32) {
		/* DDI_MODEL_ILP32 */
		if (ddi_copyin((void *)arg, (void *)&scfreport32,
			sizeof (scfreport32_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
			goto END_getreport;
		}
		scfreport.flag = scfreport32.flag;
	} else {
		/* DDI_MODEL_NONE */
		if (ddi_copyin((void *)arg, (void *)&scfreport,
			sizeof (scfreport_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
			goto END_getreport;
		}
	}

	switch (scfreport.flag) {
	case GETREPORT_WAIT:
	case GETREPORT_WAIT_AND_RCIDWN:
		mutex_enter(&scf_comtbl.all_mutex);

		scfreport_p = (scfreport_t *)&scf_comtbl.scfreport_rcidown.flag;
		while (loop_flag) {
			if (scf_pop_reportsense(&scfreport) == 0) {
				break;
			}
			if ((scfreport.flag == GETREPORT_WAIT_AND_RCIDWN) &&
				(scf_comtbl.rcidown_event_flag)) {
				scfreport.rci_addr = scfreport_p->rci_addr;
				scfreport.report_sense[0] =
					scfreport_p->report_sense[0];
				scfreport.report_sense[1] =
					scfreport_p->report_sense[1];
				scfreport.report_sense[2] =
					scfreport_p->report_sense[2];
				scfreport.report_sense[3] =
					scfreport_p->report_sense[3];
				scfreport.timestamp = scfreport_p->timestamp;
				scf_comtbl.rcidown_event_flag = 0;
				break;
			}
			SC_DBG_DRV_TRACE(TC_W_SIG, __LINE__,
				&scf_comtbl.rsense_cv, sizeof (kcondvar_t));
			if (cv_wait_sig(&scf_comtbl.rsense_cv,
				&scf_comtbl.all_mutex) == 0) {
				SC_DBG_DRV_TRACE(TC_KILL, __LINE__,
					&scf_comtbl.rsense_cv,
					sizeof (kcondvar_t));

				mutex_exit(&scf_comtbl.all_mutex);
				ret = EINTR;
				goto END_getreport;
			}
		}

		mutex_exit(&scf_comtbl.all_mutex);
		break;

	case GETREPORT_NOWAIT:
		mutex_enter(&scf_comtbl.all_mutex);

		if (scf_pop_reportsense(&scfreport) < 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			mutex_exit(&scf_comtbl.all_mutex);
			ret = ENODATA;
			goto END_getreport;
		}

		mutex_exit(&scf_comtbl.all_mutex);
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_getreport;
	}

	if (u_mode == DDI_MODEL_ILP32) {
		/* DDI_MODEL_ILP32 */
		if ((scfreport.timestamp < INT32_MIN) ||
			(scfreport.timestamp > INT32_MAX)) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EOVERFLOW;
			goto END_getreport;
		}

		scfreport32.rci_addr = scfreport.rci_addr;
		scfreport32.report_sense[0] = scfreport.report_sense[0];
		scfreport32.report_sense[1] = scfreport.report_sense[1];
		scfreport32.report_sense[2] = scfreport.report_sense[2];
		scfreport32.report_sense[3] = scfreport.report_sense[3];
		scfreport32.timestamp = (time32_t)scfreport.timestamp;

		if (ddi_copyout((void *)&scfreport32, (void *)arg,
			sizeof (scfreport32_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	} else {
		/* DDI_MODEL_NONE */
		if (ddi_copyout((void *)&scfreport, (void *)arg,
			sizeof (scfreport_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

/*
 * END_getreport
 */
	END_getreport:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_rcipwr()
 *
 * Description: SCFIOCRCIPWR ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_rcipwr(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_rcipwr() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;
	scf_short_buffer_t	rbuf;
	scfrcipwr_t		scfrcipwr;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (ddi_copyin((void *)arg, (void *)&scfrcipwr,
		sizeof (scfrcipwr_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_rcipwr;
	}

	scf_cmd.cmd = CMD_RCI_CTL;
	scf_cmd.subcmd = SUB_HOSTADDR_DISP;
	scf_cmd.scount = 0;
	scf_cmd.rbuf = &rbuf.b[0];
	scf_cmd.rcount = SCF_S_CNT_12;
	scf_cmd.flag = SCF_USE_SSBUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	if (ret != 0) {
		mutex_exit(&scf_comtbl.all_mutex);
		goto END_rcipwr;
	}

	/* check RCI-address */
	if ((scfrcipwr.rci_addr == rbuf.four_bytes_access[0]) ||
		(scfrcipwr.rci_addr == SCF_CMD_SYSTEM_ADDR)) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		mutex_exit(&scf_comtbl.all_mutex);
		ret = EINVAL;
		goto END_rcipwr;
	}

	bzero((void *)&sbuf.b[0], SCF_S_CNT_16);

	switch (scfrcipwr.sub_cmd) {
	case RCI_PWR_ON:
		scf_cmd.subcmd = SUB_PON;
		break;

	case RCI_PWR_OFF:
		scf_cmd.subcmd = SUB_FPOFF;
		break;

	case RCI_SYS_RESET:
		scf_cmd.subcmd = SUB_RESET;
		break;

	case RCI_PWR_NOR_OFF:
		scf_cmd.subcmd = SUB_POFF;
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		mutex_exit(&scf_comtbl.all_mutex);
		ret = EINVAL;
		goto END_rcipwr;
	}

	scf_cmd.cmd = CMD_PART_POW_CTR;
	scf_cmd.scount = SCF_S_CNT_15;
	sbuf.four_bytes_access[0] = scfrcipwr.rci_addr;
	scf_cmd.sbuf = &sbuf.b[0];
	scf_cmd.rcount = 0;
	scf_cmd.flag = SCF_USE_S_BUF;

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

/*
 * END_rcipwr
 */
	END_rcipwr:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_panicreq()
 *
 * Description: SCFIOCPANICREQ ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_panicreq(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_panicreq() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;
	scf_short_buffer_t	rbuf;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scf_cmd.cmd = CMD_RCI_CTL;
	scf_cmd.subcmd = SUB_HOSTADDR_DISP;
	scf_cmd.scount = 0;
	scf_cmd.rbuf = &rbuf.b[0];
	scf_cmd.rcount = SCF_S_CNT_12;
	scf_cmd.flag = SCF_USE_SSBUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	if (ret != 0) {
		mutex_exit(&scf_comtbl.all_mutex);
		goto END_panicreq;
	}

	/* check RCI-address */
	if (((uint_t)arg == rbuf.four_bytes_access[0]) ||
		(arg == SCF_CMD_SYSTEM_ADDR)) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		mutex_exit(&scf_comtbl.all_mutex);
		ret = EINVAL;
		goto END_panicreq;
	}

	bzero((void *)&sbuf.b[0], SCF_S_CNT_16);
	sbuf.four_bytes_access[0] = (unsigned int)arg;
	scf_cmd.cmd = CMD_RCI_CTL;
	scf_cmd.subcmd = SUB_PANIC;
	scf_cmd.scount = SCF_S_CNT_15;
	scf_cmd.sbuf = &sbuf.b[0];
	scf_cmd.rcount = 0;
	scf_cmd.flag = SCF_USE_S_BUF;

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

/*
 * END_panicreq
 */
	END_panicreq:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_panicchk()
 *
 * Description: SCFIOCPANICCHK ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_panicchk(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_panicchk() "
	int			ret = 0;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (ddi_copyout((void *)&scf_panic_exec_flag2, (void *)arg,
		sizeof (int), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_parmset()
 *
 * Description: SCFIOCPARMSET ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_parmset(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_parmset() "
	int			ret = 0;
	scfparam_t		scfparam;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (ddi_copyin((void *)arg, (void *)&scfparam,
		sizeof (scfparam_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_parmset;
	}

	switch (scfparam.parm) {
	case SCF_PARM_RDCTRL_TIMER:
		if ((scfparam.value >= SCF_SEC2MICRO(1)) &&
			(scfparam.value <= SCF_SEC2MICRO(120))) {
			mutex_enter(&scf_comtbl.all_mutex);
			scf_rdctrl_sense_wait =
				scfparam.value - (scfparam.value % 500000);
			mutex_exit(&scf_comtbl.all_mutex);
		} else {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EINVAL;
			goto END_parmset;
		}
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_parmset;
	}

	if (ddi_copyout((void *)&scfparam, (void *)arg,
		sizeof (scfparam_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
	}

/*
 * END_parmset
 */
	END_parmset:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_parmget()
 *
 * Description: SCFIOCPARMGET ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_parmget(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_parmget() "
	int			ret = 0;
	scfparam_t		scfparam;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (ddi_copyin((void *)arg, (void *)&scfparam,
		sizeof (scfparam_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_parmget;
	}

	switch (scfparam.parm) {
	case SCF_PARM_RDCTRL_TIMER:
		mutex_enter(&scf_comtbl.all_mutex);
		scfparam.value = scf_rdctrl_sense_wait;
		mutex_exit(&scf_comtbl.all_mutex);

		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_parmget;
	}

	if (ddi_copyout((void *)&scfparam, (void *)arg,
		sizeof (scfparam_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
	}

/*
 * END_parmget
 */
	END_parmget:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_autopwrset()
 *
 * Description: SCFIOCAUTOPWRSET ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_autopwrset(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_autopwrset() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;
	scfautopwr_t		scfautopwr;
	int			ii;
	int			jj;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (ddi_copyin((void *)arg, (void *)&scfautopwr,
		sizeof (scfautopwr_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_autopwrset;
	}

	if ((scfautopwr.valid_entries < 0) || (scfautopwr.valid_entries > 5)) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_autopwrset;
	}

	bzero((void *)&sbuf.b[0], 5 * SCF_S_CNT_16);

	for (ii = 0, jj = 0; ii < scfautopwr.valid_entries; ii++,
		jj = ii * SCF_S_CNT_16) {
		/* check pon time */
		if (scf_check_pon_time(&scfautopwr.ptime[ii]) < 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EINVAL;
			goto END_autopwrset;
		}

		if (scf_check_poff_time(&scfautopwr.ptime[ii]) < 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EINVAL;
			goto END_autopwrset;
		}

		sbuf.b[jj] = (uchar_t)(scfautopwr.ptime[ii].pon_year >> 8);
		sbuf.b[jj + 1] = (uchar_t)scfautopwr.ptime[ii].pon_year;
		sbuf.b[jj + 2] = (uchar_t)scfautopwr.ptime[ii].pon_month;
		sbuf.b[jj + 3] = (uchar_t)scfautopwr.ptime[ii].pon_date;
		sbuf.b[jj + 4] = (uchar_t)scfautopwr.ptime[ii].pon_hour;
		sbuf.b[jj + 5] = (uchar_t)scfautopwr.ptime[ii].pon_minute;
		sbuf.b[jj + 6] = 0;
		sbuf.b[jj + 7] = 0;

		sbuf.b[jj + 8] = (uchar_t)(scfautopwr.ptime[ii].poff_year >> 8);
		sbuf.b[jj + 9] = (uchar_t)scfautopwr.ptime[ii].poff_year;
		sbuf.b[jj + 10] = (uchar_t)scfautopwr.ptime[ii].poff_month;
		sbuf.b[jj + 11] = (uchar_t)scfautopwr.ptime[ii].poff_date;
		sbuf.b[jj + 12] = (uchar_t)scfautopwr.ptime[ii].poff_hour;
		sbuf.b[jj + 13] = (uchar_t)scfautopwr.ptime[ii].poff_minute;
		sbuf.b[jj + 14] = 0;
		sbuf.b[jj + 15] = 0;
	}

	scf_cmd.cmd = CMD_SYS_AUTOPOW;
	scf_cmd.subcmd = SUB_SYS_AUTO_ONOFF_SET;
	scf_cmd.scount = 5 * SCF_S_CNT_16;
	scf_cmd.sbuf = &sbuf.b[0];
	scf_cmd.rcount = 0;
	scf_cmd.flag = SCF_USE_L_BUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

/*
 * END_autopwrset
 */
	END_autopwrset:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_autopwrget()
 *
 * Description: SCFIOCAUTOPWRGET or SCFIOCSYSAUTOPWRGET
 *              ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_autopwrget(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_autopwrget() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	rbuf;
	scfautopwr_t		scfautopwr;
	int			ii;
	int			jj;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	bzero((void *)&scfautopwr, sizeof (scfautopwr_t));

	scf_cmd.cmd = CMD_SYS_AUTOPOW;
	scf_cmd.subcmd = SUB_SYS_AUTO_ONOFF_DISP;
	scf_cmd.scount = 0;
	scf_cmd.rbuf = &rbuf.b[0];
	scf_cmd.rcount = 5 * SCF_S_CNT_16;
	scf_cmd.flag = SCF_USE_SLBUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

	if (ret != 0) {
		goto END_autopwrget;
	}

	for (ii = 0, jj = 0; ii < (scf_cmd.rbufleng / SCF_S_CNT_16);
		ii++, jj = ii * SCF_S_CNT_16) {
		scfautopwr.ptime[ii].pon_year =
			(int)(rbuf.b[jj] << 8) | (int)rbuf.b[jj + 1];
		scfautopwr.ptime[ii].pon_month = (int)rbuf.b[jj + 2];
		scfautopwr.ptime[ii].pon_date = (int)rbuf.b[jj + 3];
		scfautopwr.ptime[ii].pon_hour = (int)rbuf.b[jj + 4];
		scfautopwr.ptime[ii].pon_minute = (int)rbuf.b[jj + 5];

		scfautopwr.ptime[ii].poff_year =
			(int)(rbuf.b[jj + 8] << 8) | (int)rbuf.b[jj + 9];
		scfautopwr.ptime[ii].poff_month = (int)rbuf.b[jj + 10];
		scfautopwr.ptime[ii].poff_date = (int)rbuf.b[jj + 11];
		scfautopwr.ptime[ii].poff_hour = (int)rbuf.b[jj + 12];
		scfautopwr.ptime[ii].poff_minute = (int)rbuf.b[jj + 13];
	}
	scfautopwr.valid_entries = 5;

	if (ddi_copyout((void *)&scfautopwr, (void *)arg,
		sizeof (scfautopwr_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
	}

/*
 * END_autopwrget
 */
	END_autopwrget:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_autopwrclr()
 *
 * Description: SCFIOCSYSAUTOPWRCLR ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_autopwrclr(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_autopwrclr() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scf_cmd.cmd = CMD_SYS_AUTOPOW;
	scf_cmd.subcmd = SUB_SYS_AUTO_ONOFF_CLRAR;
	scf_cmd.scount = 0;
	scf_cmd.rcount = 0;
	scf_cmd.flag = SCF_USE_S_BUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_autopwrfpoff()
 *
 * Description: SCFIOCAUTOPWRFPOFF ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_autopwrfpoff(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_autopwrfpoff() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;
	scfautopwrtime_t	scfautopwrtime;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (ddi_copyin((void *)arg, (void *)&scfautopwrtime,
		sizeof (scfautopwrtime_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_autopwrfpoff;
	}
	bzero((void *)&sbuf.b[0], 5 * SCF_S_CNT_16);
	if (scf_check_poff_time(&scfautopwrtime) < 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_autopwrfpoff;
	}
	sbuf.b[0] = (uchar_t)(scfautopwrtime.poff_year >> 8);
	sbuf.b[1] = (uchar_t)scfautopwrtime.poff_year;
	sbuf.b[2] = (uchar_t)scfautopwrtime.poff_month;
	sbuf.b[3] = (uchar_t)scfautopwrtime.poff_date;
	sbuf.b[4] = (uchar_t)scfautopwrtime.poff_hour;
	sbuf.b[5] = (uchar_t)scfautopwrtime.poff_minute;

	scf_cmd.cmd = CMD_SYS_AUTOPOW;
	scf_cmd.subcmd = SUB_FORCED_POFF_SET;
	scf_cmd.scount = SCF_S_CNT_15;
	scf_cmd.sbuf = &sbuf.b[0];
	scf_cmd.rcount = 0;
	scf_cmd.flag = SCF_USE_S_BUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

/*
 * END_autopwrfpoff
 */
	END_autopwrfpoff:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_autopwrexset()
 *
 * Description: SCFIOCAUTOPWREXSET ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_autopwrexset(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_autopwrexset() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;
	scfautopwrex_t		scfautopwrex;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	bzero((void *)&sbuf.b[0], SCF_S_CNT_16);
	if (ddi_copyin((void *)arg, (void *)&scfautopwrex,
		sizeof (scfautopwrex_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_autopwrexset;
	}

	switch (scfautopwrex.rpwr_mode) {
	case AUTOPWREX_RESTORE:
	case AUTOPWREX_NOPON:
	case AUTOPWREX_AUTOPON:
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_autopwrexset;
	}

	scf_cmd.cmd = CMD_SYS_AUTOPOW;
	scf_cmd.subcmd = SUB_PRESET_MODE_SET;
	scf_cmd.scount = SCF_S_CNT_15;
	sbuf.b[0] = (unsigned char)scfautopwrex.rpwr_mode;
	scf_cmd.sbuf = &sbuf.b[0];
	scf_cmd.rcount = 0;
	scf_cmd.flag = SCF_USE_S_BUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

/*
 * END_autopwrexset
 */
	END_autopwrexset:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_autopwrexget()
 *
 * Description: SCFIOCAUTOPWREXGET ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_autopwrexget(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_autopwrexget() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	rbuf;
	scfautopwrex_t		scfautopwrex;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	bzero((void *)&scfautopwrex, sizeof (scfautopwrex_t));

	scf_cmd.cmd = CMD_SYS_AUTOPOW;
	scf_cmd.subcmd = SUB_PRESET_MODE_DISP;
	scf_cmd.scount = 0;
	scf_cmd.rcount = SCF_S_CNT_15;
	scf_cmd.rbuf = &rbuf.b[0];
	scf_cmd.flag = SCF_USE_SSBUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

	if (ret == 0) {
		scfautopwrex.rpwr_mode = (int)rbuf.b[0];

		if (ddi_copyout((void *)&scfautopwrex, (void *)arg,
			sizeof (scfautopwrex_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_dr()
 *
 * Description: SCFIOCDR ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_dr(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_dr() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scfdr_t			*scfdr_p = NULL;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scfdr_p = kmem_zalloc((size_t)(sizeof (scfdr_t)), KM_SLEEP);

	if (ddi_copyin((void *)arg, (void *)scfdr_p, sizeof (scfdr_t),
		mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_dr;
	}

	scf_cmd.cmd = CMD_DR;
	scf_cmd.subcmd = scfdr_p->sub_command;
	scf_cmd.sbuf = &scfdr_p->sbuf[0];
	scf_cmd.scount = SCF_S_CNT_15;

	switch (scfdr_p->sub_command) {
	case SUB_SB_CONF_CHG:
		scf_cmd.rbuf = &scfdr_p->rbuf[0];
		scf_cmd.rcount = SCF_S_CNT_16;
		scf_cmd.flag = SCF_USE_S_BUF;
		break;

	case SUB_SB_BUILD_COMP:
		scf_cmd.rcount = 0;
		scf_cmd.flag = SCF_USE_S_BUF;
		break;

	case SUB_SB_SENSE_ALL:
		scf_cmd.rbuf = &scfdr_p->rbuf[0];
		scf_cmd.rcount = sizeof (scfdr_p->rbuf);
		scf_cmd.flag = SCF_USE_SLBUF;
		break;

	case SUB_SB_SENSE:
		scf_cmd.rbuf = &scfdr_p->rbuf[0];
		scf_cmd.rcount = SCF_S_CNT_15;
		scf_cmd.flag = SCF_USE_SSBUF;
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_dr;
	}

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

	if (ret != 0) {
		if (scf_cmd.stat0 == E_PARAM) {
			ret = EINVAL;
		} else {
			goto END_dr;
		}
	}

	if (ddi_copyout((void *)scfdr_p, (void *)arg, sizeof (scfdr_t),
		mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
	}

/*
 * END_dr
 */
	END_dr:

	if (scfdr_p) {
		kmem_free((void *)scfdr_p, (size_t)(sizeof (scfdr_t)));
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_eventlist()
 *
 * Description: SCFIOCEVENTLIST ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_eventlist(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_eventlist() "
	int			ret = 0;
	scfeventlist_t		*scfeventlist_p = NULL;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scfeventlist_p = kmem_zalloc((size_t)(sizeof (scfeventlist_t)),
		KM_SLEEP);

	if (ddi_copyin((void *)arg, (void *)scfeventlist_p,
		sizeof (scfeventlist_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_eventlist;
	}
	if (scfeventlist_p->listcnt > SCF_EVENTLIST_MAX) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_eventlist;
	}

	mutex_enter(&scf_comtbl.all_mutex);

	bcopy((void *)scfeventlist_p, (void *)&scf_comtbl.getevent_tbl.listcnt,
		sizeof (scfeventlist_t));

	mutex_exit(&scf_comtbl.all_mutex);

/*
 * END_eventlist
 */
	END_eventlist:

	if (scfeventlist_p) {
		kmem_free((void *)scfeventlist_p,
			(size_t)(sizeof (scfeventlist_t)));
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_getevent()
 *
 * Description: SCFIOCGETEVENT ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_getevent(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_getevent() "
	int			ret = 0;
	scfevent_t		scfevent;
	scfevent32_t		scfevent32;
	int			loop_flag = 1;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (u_mode == DDI_MODEL_ILP32) {
		/* DDI_MODEL_ILP32 */
		if (ddi_copyin((void *)arg, (void *)&scfevent32,
			sizeof (scfevent32_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
			goto END_getevent;
		}
		scfevent.flag = scfevent32.flag;
	} else {
		/* DDI_MODEL_NONE */
		if (ddi_copyin((void *)arg, (void *)&scfevent,
			sizeof (scfevent_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
			goto END_getevent;
		}
	}

	switch (scfevent.flag) {
	case GETEVENT_WAIT:
		mutex_enter(&scf_comtbl.all_mutex);

		while (loop_flag) {
			if (scf_pop_getevent(&scfevent) == 0) {
				break;
			}
			SC_DBG_DRV_TRACE(TC_W_SIG, __LINE__,
				&scf_comtbl.getevent_cv, sizeof (kcondvar_t));
			if (cv_wait_sig(&scf_comtbl.getevent_cv,
				&scf_comtbl.all_mutex) == 0) {
				SC_DBG_DRV_TRACE(TC_KILL, __LINE__,
					&scf_comtbl.getevent_cv,
					sizeof (kcondvar_t));

				mutex_exit(&scf_comtbl.all_mutex);
				ret = EINTR;
				goto END_getevent;
			}
		}

		mutex_exit(&scf_comtbl.all_mutex);
		break;

	case GETEVENT_NOWAIT:
		mutex_enter(&scf_comtbl.all_mutex);

		if (scf_pop_getevent(&scfevent) < 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);

			mutex_exit(&scf_comtbl.all_mutex);
			ret = ENODATA;
			goto END_getevent;
		}

		mutex_exit(&scf_comtbl.all_mutex);
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_getevent;
	}

	if (u_mode == DDI_MODEL_ILP32) {
		/* DDI_MODEL_ILP32 */
		if ((scfevent.timestamp < INT32_MIN) ||
			(scfevent.timestamp > INT32_MAX)) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EOVERFLOW;
			goto END_getevent;
		}
		bcopy((void *)&scfevent.rci_addr, (void *)&scfevent32.rci_addr,
			SCF_INT_REASON_SIZE);
		scfevent32.timestamp = (time32_t)scfevent.timestamp;

		if (ddi_copyout((void *)&scfevent32, (void *)arg,
			sizeof (scfevent32_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	} else {
		/* DDI_MODEL_NONE */
		if (ddi_copyout((void *)&scfevent, (void *)arg,
			sizeof (scfevent_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

/*
 * END_getevent
 */
	END_getevent:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_setmadmevent()
 *
 * Description: SCFIOCSETMADMEVENT ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_setmadmevent(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_setmadmevent() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scfiocsetmadmevent_t	*scfiocsetmadmevent_p = NULL;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scfiocsetmadmevent_p =
		kmem_zalloc((size_t)(sizeof (scfiocsetmadmevent_t)),
		KM_SLEEP);

	if (ddi_copyin((void *)arg, (void *)scfiocsetmadmevent_p,
		sizeof (scfiocsetmadmevent_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_setmadmevent;
	}

	if (scfiocsetmadmevent_p->size > SCF_L_CNT_MAX) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_setmadmevent;
	}

	scf_cmd.cmd = CMD_ERRLOG;
	scf_cmd.subcmd = SUB_ERRLOG_SET_MADMIN;
	scf_cmd.sbuf = &scfiocsetmadmevent_p->buf[0];
	scf_cmd.scount = scfiocsetmadmevent_p->size;
	scf_cmd.rcount = 0;
	scf_cmd.flag = SCF_USE_L_BUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

/*
 * END_setmadmevent
 */
	END_setmadmevent:

	if (scfiocsetmadmevent_p) {
		kmem_free((void *)scfiocsetmadmevent_p,
			(size_t)(sizeof (scfiocsetmadmevent_t)));
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_remcscmd()
 *
 * Description: SCFIOCREMCSCMD ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_remcscmd(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_remcscmd() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	rbuf;
	scfiocremcscmd_t	scfiocremcscmd;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (ddi_copyin((void *)arg, (void *)&scfiocremcscmd,
		sizeof (scfiocremcscmd_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_remcscmd;
	}

	if (scfiocremcscmd.size > SCF_S_CNT_15) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_remcscmd;
	}

	scf_cmd.cmd = CMD_REMCS_SPT;

	switch (scfiocremcscmd.sub_command) {
	case SUB_CMD_EX_REMCS:
		scf_cmd.subcmd = scfiocremcscmd.sub_command;
		scf_cmd.scount = scfiocremcscmd.size;
		scf_cmd.sbuf = &scfiocremcscmd.buf[0];
		scf_cmd.rcount = SCF_S_CNT_15;
		scf_cmd.rbuf = &rbuf.b[0];
		scf_cmd.flag = SCF_USE_SSBUF;
		break;
	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_remcscmd;
	}

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

	if (ret == 0) {
		scfiocremcscmd.size = scf_cmd.rbufleng;
		if (scfiocremcscmd.size != 0) {
			bcopy((void *)&rbuf.b[0],
				(void *)&scfiocremcscmd.buf[0],
				scfiocremcscmd.size);
		}

		if (ddi_copyout((void *)&scfiocremcscmd, (void *)arg,
			sizeof (scfiocremcscmd_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

/*
 * END_remcscmd
 */
	END_remcscmd:

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_remcsfile()
 *
 * Description: SCFIOCREMCSFILE ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_remcsfile(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_remcsfile() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	rbuf;
	scfiocremcsfile_t	*scfiocremcsfile_p = NULL;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scfiocremcsfile_p = kmem_zalloc((size_t)(sizeof (scfiocremcsfile_t)),
		KM_SLEEP);

	if (ddi_copyin((void *)arg, (void *)scfiocremcsfile_p,
		sizeof (scfiocremcsfile_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_remcsfile;
	}

	if (scfiocremcsfile_p->size > SCF_L_CNT_MAX) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_remcsfile;
	}

	scf_cmd.cmd = CMD_FILE_DOWNLOAD;
	scf_cmd.subcmd = scfiocremcsfile_p->sub_command;

	switch (scfiocremcsfile_p->sub_command) {
	case SUB_FILEUP_READY:
		if (scfiocremcsfile_p->size > SCF_L_CNT_MAX) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EINVAL;
			goto END_remcsfile;
		}
		scf_cmd.scount = scfiocremcsfile_p->size;
		scf_cmd.sbuf = &scfiocremcsfile_p->buf[0];
		scf_cmd.rcount = SCF_S_CNT_15;
		scf_cmd.rbuf = &rbuf.b[0];
		scf_cmd.flag = SCF_USE_LSBUF;
		break;

	case SUB_FILEUP_SET:
		scf_cmd.scount = scfiocremcsfile_p->size;
		scf_cmd.sbuf = &scfiocremcsfile_p->buf[0];
		scf_cmd.rcount = 0;
		scf_cmd.flag = SCF_USE_L_BUF;
		break;

	case SUB_TRANSFER_STOP:
		scf_cmd.scount = 0;
		scf_cmd.rcount = 0;
		scf_cmd.flag = SCF_USE_S_BUF;
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_remcsfile;
	}

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

	if (ret == 0) {
		scfiocremcsfile_p->size = scf_cmd.rbufleng;
		if (scfiocremcsfile_p->size != 0) {
			bcopy((void *)&rbuf.b[0],
				(void *)&scfiocremcsfile_p->buf[0],
				scfiocremcsfile_p->size);
		}

		if (ddi_copyout((void *)scfiocremcsfile_p, (void *)arg,
			sizeof (scfiocremcsfile_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

/*
 * END_remcsfile
 */
	END_remcsfile:

	if (scfiocremcsfile_p) {
		kmem_free((void *)scfiocremcsfile_p,
			(size_t)(sizeof (scfiocremcsfile_t)));
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_sparecmd()
 *
 * Description: SCFIOCSPARECMD ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_sparecmd(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_sparecmd() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scfiocsparecmd_t	*scfiocsparecmd_p = NULL;
	uint_t			madm_scount;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scfiocsparecmd_p = kmem_zalloc((size_t)(sizeof (scfiocsparecmd_t)),
		KM_SLEEP);

	if (ddi_copyin((void *)arg, (void *)scfiocsparecmd_p,
		sizeof (scfiocsparecmd_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_sparecmd;
	}

	if (scfiocsparecmd_p->size > SCF_L_CNT_MAX) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_sparecmd;
	}

	scf_cmd.cmd = CMD_SPARE;
	scf_cmd.subcmd = scfiocsparecmd_p->spare_sub_command;
	scf_cmd.sbuf = &scfiocsparecmd_p->buf[0];
	scf_cmd.rbuf = &scfiocsparecmd_p->buf[0];
	scf_cmd.cexr[0] = scfiocsparecmd_p->command;
	scf_cmd.cexr[1] = scfiocsparecmd_p->sub_command;

	switch (scfiocsparecmd_p->spare_sub_command) {
	case SUB_SPARE_SS:
		scf_cmd.scount = SCF_S_CNT_12;
		scf_cmd.rcount = SCF_S_CNT_12;
		scf_cmd.flag = SCF_USE_SSBUF;
		break;

	case SUB_SPARE_SL:
		scf_cmd.scount = SCF_S_CNT_12;
		scf_cmd.rcount = SCF_L_CNT_MAX;
		scf_cmd.flag = SCF_USE_SLBUF;
		break;

	case SUB_SPARE_LS:
		madm_scount = (scfiocsparecmd_p->size + SCF_S_CNT_15) &
			SCF_LENGTH_16BYTE_CNV;
		scf_cmd.scount = madm_scount;
		scf_cmd.rcount = SCF_S_CNT_12;
		scf_cmd.flag = SCF_USE_LSBUF;
		break;

	default:
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_sparecmd;
	}

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

	if (ret == 0) {
		scfiocsparecmd_p->size = scf_cmd.rbufleng;
		if (ddi_copyout((void *)scfiocsparecmd_p, (void *)arg,
			sizeof (scfiocsparecmd_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

/*
 * END_sparecmd
 */
	END_sparecmd:

	if (scfiocsparecmd_p) {
		kmem_free((void *)scfiocsparecmd_p,
			(size_t)(sizeof (scfiocsparecmd_t)));
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_ioc_setphpinfo()
 *
 * Description: SCFIOCSETPHPINFO ioctl command processing.
 *
 */
/* ARGSUSED */
int
scf_ioc_setphpinfo(intptr_t arg, int mode, int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_ioc_setphpinfo() "
	int			ret = 0;
	struct scf_cmd		scf_cmd;
	scfsetphpinfo_t		*scfsetphpinfo_p = NULL;

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	scfsetphpinfo_p = kmem_zalloc((size_t)(sizeof (scfsetphpinfo_t)),
		KM_SLEEP);

	if (ddi_copyin((void *)arg, (void *)scfsetphpinfo_p,
		sizeof (scfsetphpinfo_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_setphpinfo;
	}

	if (scfsetphpinfo_p->size > SCF_L_CNT_MAX) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EINVAL;
		goto END_setphpinfo;
	}

	scf_cmd.cmd = CMD_DOMAIN_INFO;
	scf_cmd.subcmd = SUB_PCI_HP_CONFIG;
	scf_cmd.sbuf = &scfsetphpinfo_p->buf[0];
	scf_cmd.scount = scfsetphpinfo_p->size;
	scf_cmd.rcount = 0;
	scf_cmd.flag = SCF_USE_L_BUF;

	mutex_enter(&scf_comtbl.all_mutex);

	ret = scf_send_cmd_check_bufful(&scf_cmd);

	mutex_exit(&scf_comtbl.all_mutex);

/*
 * END_setphpinfo
 */
	END_setphpinfo:

	if (scfsetphpinfo_p) {
		kmem_free((void *)scfsetphpinfo_p,
			(size_t)(sizeof (scfsetphpinfo_t)));
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_push_reportsense()
 *
 * Description: Set processing of SCFIOCGETREPORT information.
 *
 */
int
scf_push_reportsense(unsigned int rci_addr, unsigned char *sense,
	time_t timestamp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_push_reportsense() "
	int			top = scf_comtbl.report_sense_top;
	scfreport_t		*rsensep = scf_comtbl.report_sensep;
	int			overflow = 0;
	int			ret = 0;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (rsensep[top].flag != 0) {
		SCFDBGMSG(SCF_DBGFLAG_IOCTL, "reportsense overflow");
		overflow = 1;
		/* increment counter */
		scf_comtbl.scf_rsense_overflow++;
	}

	rsensep[top].flag = 1;
	rsensep[top].rci_addr = rci_addr;
	bcopy((void *)&sense[0], (void *)&rsensep[top].report_sense[0], 4);
	rsensep[top].timestamp = timestamp;

	scf_comtbl.report_sense_top =
		((scf_report_sense_pool_max - 1) == top) ? 0 : top + 1;

	if (overflow) {
		scf_comtbl.report_sense_oldest = scf_comtbl.report_sense_top;
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL,
		SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_pop_reportsense()
 *
 * Description: Get processing of SCFIOCGETREPORT information.
 *
 */
int
scf_pop_reportsense(scfreport_t *rsense)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_pop_reportsense() "
	int			oldest = scf_comtbl.report_sense_oldest;
	scfreport_t		*drv_rsensep = scf_comtbl.report_sensep;
	int			ret = (-1);

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (drv_rsensep[oldest].flag != 0) {
		rsense->rci_addr = drv_rsensep[oldest].rci_addr;
		bcopy((void *)&drv_rsensep[oldest].report_sense[0],
			(void *)&rsense->report_sense[0], 4);
		rsense->timestamp = drv_rsensep[oldest].timestamp;
		/* clear flag */
		drv_rsensep[oldest].flag = 0;
		scf_comtbl.report_sense_oldest =
			((scf_report_sense_pool_max - 1) == oldest)
			? 0 : oldest + 1;
		ret = 0;
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL,
		SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_push_getevent()
 *
 * Description: Set processing of SCFIOCGETEVENT information.
 *
 */
int
scf_push_getevent(unsigned char *event_p)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_push_getevent() "
	int			top = scf_comtbl.getevent_sense_top;
	scfevent_t		*scfevent_p = scf_comtbl.getevent_sensep;
	int			overflow = 0;
	int			ii;
	time_t			timestamp;
	int			ret = 1;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	/* Event check */
	for (ii = 0; ii < scf_comtbl.getevent_tbl.listcnt; ii++) {
		if (event_p[4] == scf_comtbl.getevent_tbl.codelist[ii]) {
			ret = 0;
			break;
		}
	}
	if (ret == 0) {
		/* Event set */
		if (scfevent_p[top].flag != 0) {
			SCFDBGMSG(SCF_DBGFLAG_IOCTL, "getevent overflow");
			overflow = 1;
			/* increment counter */
			scf_comtbl.scf_getevent_overflow++;
		}
		timestamp = ddi_get_time();
		scfevent_p[top].flag = 1;
		bcopy((void *)event_p, (void *)&scfevent_p[top].rci_addr,
			SCF_INT_REASON_SIZE);
		scfevent_p[top].timestamp = timestamp;
		scf_comtbl.getevent_sense_top =
			((scf_getevent_pool_max - 1) == top) ? 0 : top + 1;
		if (overflow) {
			scf_comtbl.getevent_sense_oldest =
				scf_comtbl.getevent_sense_top;
		}
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL,
		SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_pop_reportsense()
 *
 * Description: Get processing of SCFIOCGETEVENT information.
 *
 */
int
scf_pop_getevent(scfevent_t *event_p)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_pop_getevent() "
	int			oldest = scf_comtbl.getevent_sense_oldest;
	scfevent_t		*scfevent_p = scf_comtbl.getevent_sensep;
	int			ret = (-1);

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if (scfevent_p[oldest].flag != 0) {
		bcopy((void *)&scfevent_p[oldest].rci_addr,
			(void *)&event_p->rci_addr, SCF_INT_REASON_SIZE);
		event_p->timestamp = scfevent_p[oldest].timestamp;
		/* clear flag */
		scfevent_p[oldest].flag = 0;
		scf_comtbl.getevent_sense_oldest =
			((scf_getevent_pool_max - 1) == oldest)
			? 0 : oldest + 1;
		ret = 0;
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL,
		SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_valid_date()
 *
 * Description: Validity check processing of date.
 *
 */
int
scf_valid_date(int year, int month, int date)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_valid_date() "
	int			leap = 0;
	int			ret = 0;
	static int		scf_m2d[2][12] = {
		{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
		{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
	};

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	if ((year % 400) == 0) {
		leap = 1;
	} else {
		if ((year % 100) == 0) {
			leap = 0;
		} else {
			if ((year % 4) == 0) {
				leap = 1;
			}
		}
	}
	if (scf_m2d[leap][month - 1] < date) {
		ret = 1;
	}

	SCFDBGMSG1(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_check_pon_time()
 *
 * Description: Power-on time range check processing.
 *
 */
int
scf_check_pon_time(scfautopwrtime_t *ptime)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_check_pon_time() "
	int			ret = (-1);

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	/* check date, time */
	if ((ptime->pon_year == 0) && (ptime->pon_month == 0) &&
		(ptime->pon_date == 0) && (ptime->pon_hour == 0) &&
		(ptime->pon_minute == 0)) {
		ret = 0;
		goto END_check_pon_time;
	}

	/* check date, time */
	if ((ptime->pon_year < 1970) || (ptime->pon_year > 9999)) {
		goto END_check_pon_time;
	}
	if ((ptime->pon_month < 1) || (ptime->pon_month > 12)) {
		goto END_check_pon_time;
	}
	if (ptime->pon_date < 1) {
		goto END_check_pon_time;
	}
	if ((ptime->pon_hour < 0) || (ptime->pon_hour > 23)) {
		goto END_check_pon_time;
	}
	if ((ptime->pon_minute < 0) || (ptime->pon_minute > 59)) {
		goto END_check_pon_time;
	}
	if (scf_valid_date(ptime->pon_year,
		ptime->pon_month, ptime->pon_date)) {
		goto END_check_pon_time;
	}
	ret = 0;

/*
 * END_check_pon_time
 */
	END_check_pon_time:
	SCFDBGMSG1(SCF_DBGFLAG_IOCTL,
		SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_check_poff_time()
 *
 * Description: Power-off time range check processing.
 *
 */
int
scf_check_poff_time(scfautopwrtime_t *ptime)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_check_poff_time() "
	int			ret = (-1);

	SCFDBGMSG(SCF_DBGFLAG_IOCTL, SCF_FUNC_NAME ": start");

	/* all zero? */
	if ((ptime->poff_year == 0) && (ptime->poff_month == 0) &&
		(ptime->poff_date == 0) && (ptime->poff_hour == 0) &&
		(ptime->poff_minute == 0)) {
		if ((ptime->flag != 0) || (ptime->sarea != 0)) {
			goto END_check_poff_time;
		}
		ret = 0;
		goto END_check_poff_time;
	}

	/* check date, time */
	if ((ptime->poff_year < 1970) || (ptime->poff_year > 9999)) {
		goto END_check_poff_time;
	}
	if ((ptime->poff_month < 1) || (ptime->poff_month > 12)) {
		goto END_check_poff_time;
	}
	if (ptime->poff_date < 1) {
		goto END_check_poff_time;
	}
	if ((ptime->poff_hour < 0) || (ptime->poff_hour > 23)) {
		goto END_check_poff_time;
	}
	if ((ptime->poff_minute < 0) || (ptime->poff_minute > 59)) {
		goto END_check_poff_time;
	}
	if (scf_valid_date(ptime->poff_year, ptime->poff_month,
		ptime->poff_date)) {
		goto END_check_poff_time;
	}
	ret = 0;

/*
 * END_check_poff_time
 */
	END_check_poff_time:
	SCFDBGMSG1(SCF_DBGFLAG_IOCTL,
		SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}
