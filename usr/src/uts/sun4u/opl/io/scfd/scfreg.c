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

#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scfd/scfparam.h>


/*
 * SCF command send control area save
 */
struct scf_cmd		scfcmd_save;
uchar_t			scf_sbuf_save[SCF_L_CNT_MAX];
uchar_t			scf_rbuf_save[SCF_L_CNT_MAX];

/*
 * Function list
 */
int	scf_map_regs(dev_info_t *dip, scf_state_t *statep);
void	scf_unmap_regs(scf_state_t *statep);
int	scf_send_cmd_check_bufful(struct scf_cmd *scfcmdp);
int	scf_send_cmd(struct scf_cmd *scfcmdp);
void	scf_i_send_cmd(struct scf_cmd *scfcmdp, struct scf_state *statep);
void	scf_p_send_cmd(struct scf_cmd *scfcmdp, struct scf_state *statep);
int	scf_path_check(scf_state_t **statep);
int	scf_offline_check(scf_state_t *statep, uint_t timer_exec_flag);
int	scf_cmdbusy_check(scf_state_t *statep);
void	scf_alivecheck_start(scf_state_t *statep);
void	scf_alivecheck_stop(scf_state_t *statep);
void	scf_forbid_intr(struct scf_state *statep);
void	scf_permit_intr(struct scf_state *statep, int flag);
int	scf_check_state(scf_state_t *statep);
void	scf_chg_scf(scf_state_t *statep, int status);
void	scf_del_queue(scf_state_t *statep);
int	scf_make_send_cmd(struct scf_cmd *scfcmdp, uint_t flag);
void	scf_sram_trace_init(struct scf_state *statep);
void	scf_sram_trace(struct scf_state *statep, uint8_t log_id);

/*
 * External function
 */
extern	void	scf_dscp_stop(uint32_t factor);


/*
 * scf_map_regs()
 *
 * Description: Register and SRAM map processing.
 *
 */
int
scf_map_regs(dev_info_t *dip, scf_state_t *statep)
{
#define	SCF_FUNC_NAME		"scf_map_regs() "
	int			ret = 1;
	uint32_t		wkoffset = 0;

	ddi_device_acc_attr_t	access_attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_STRUCTURE_BE_ACC,
		DDI_STRICTORDER_ACC
	};

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	SCF_DBG_TEST_MAP_REGS(statep);

	/* map register 1 : SCF register */
	if (ddi_regs_map_setup(dip, REG_INDEX_SCF,
		(caddr_t *)&statep->scf_regs, 0, 0, &access_attr,
		&statep->scf_regs_handle) != DDI_SUCCESS) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "map_regs", 8);
		cmn_err(CE_WARN,
			"%s: scf_map_regs: ddi_regs_map_setup failed.\n",
			scf_driver_name);
		goto END_map_regs;
	}
	statep->resource_flag |= S_DID_REG1;

	/* map register 2 : SCF contorol register */
	if (ddi_regs_map_setup(dip, REG_INDEX_SCFCNTL,
		(caddr_t *)&statep->scf_regs_c, 0, 0, &access_attr,
		&statep->scf_regs_c_handle) != DDI_SUCCESS) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "map_regs", 8);
		cmn_err(CE_WARN,
			"%s: scf_map_regs: ddi_regs_map_setup failed.\n",
			scf_driver_name);
		goto END_map_regs;
	}
	statep->resource_flag |= S_DID_REG2;

	/* get size of register 3 : SCF DSCP SRAM */
	if (ddi_dev_regsize(dip, REG_INDEX_DSCPSRAM,
		&statep->scf_dscp_sram_len) != DDI_SUCCESS) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "map_regs", 8);
		cmn_err(CE_WARN,
			"%s: scf_map_regs: ddi_dev_regsize failed.\n",
			scf_driver_name);
		goto END_map_regs;
	}
	/* check size */
	if (statep->scf_dscp_sram_len < SRAM_MAX_DSCP) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "map_regs", 8);
		cmn_err(CE_WARN,
			"%s: scf_map_regs: ddi_dev_regsize failed.\n",
			scf_driver_name);
		goto END_map_regs;
	} else if (statep->scf_dscp_sram_len > SRAM_MAX_DSCP) {
		statep->scf_dscp_sram_len = SRAM_MAX_DSCP;
	}
	/* map register 3 : SCF DSCP SRAM */
	if (ddi_regs_map_setup(dip, REG_INDEX_DSCPSRAM,
		(caddr_t *)&statep->scf_dscp_sram, 0,
		(offset_t)statep->scf_dscp_sram_len, &access_attr,
		&statep->scf_dscp_sram_handle) != DDI_SUCCESS) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "map_regs", 8);
		cmn_err(CE_WARN,
			"%s: scf_map_regs: ddi_regs_map_setup failed.\n",
			scf_driver_name);
		goto END_map_regs;
	}
	statep->resource_flag |= S_DID_REG3;

	/* get size of register 4 : SCF system SRAM */
	if (ddi_dev_regsize(dip, REG_INDEX_SYSTEMSRAM,
		&statep->scf_sys_sram_len) != DDI_SUCCESS) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "map_regs", 8);
		cmn_err(CE_WARN,
			"%s: scf_map_regs: ddi_dev_regsize failed.\n",
			scf_driver_name);
		goto END_map_regs;
	}
	/* check size */
	if (statep->scf_sys_sram_len < SRAM_MAX_SYSTEM) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "map_regs", 8);
		cmn_err(CE_WARN,
			"%s: scf_map_regs: ddi_dev_regsize failed.\n",
			scf_driver_name);
		goto END_map_regs;
	} else if (statep->scf_sys_sram_len > SRAM_MAX_SYSTEM) {
		statep->scf_sys_sram_len = SRAM_MAX_SYSTEM;
	}
	/* map register 4 : SCF system SRAM */
	if (ddi_regs_map_setup(dip, REG_INDEX_SYSTEMSRAM,
		(caddr_t *)&statep->scf_sys_sram, 0,
		(offset_t)statep->scf_sys_sram_len, &access_attr,
		&statep->scf_sys_sram_handle) != DDI_SUCCESS) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "map_regs", 8);
		cmn_err(CE_WARN,
			"%s: scf_map_regs: ddi_regs_map_setup failed.\n",
			scf_driver_name);
		goto END_map_regs;
	}
	statep->resource_flag |= S_DID_REG4;

	/* get size of register 5 : SCF interface block */
	if (ddi_dev_regsize(dip, REG_INDEX_INTERFACE,
		&statep->scf_interface_len) != DDI_SUCCESS) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "map_regs", 8);
		cmn_err(CE_WARN,
			"%s: scf_map_regs: ddi_dev_regsize failed.\n",
			scf_driver_name);
		goto END_map_regs;
	}
	/* check size */
	if (statep->scf_interface_len < sizeof (scf_interface_t)) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "map_regs", 8);
		cmn_err(CE_WARN,
			"%s: scf_map_regs: ddi_dev_regsize failed.\n",
			scf_driver_name);
		goto END_map_regs;
	} else  {
		statep->scf_interface_len = sizeof (scf_interface_t);
	}
	/* map register 5 : SCF interface block */
	if (ddi_regs_map_setup(dip, REG_INDEX_INTERFACE,
		(caddr_t *)&statep->scf_interface, 0,
		(offset_t)statep->scf_interface_len, &access_attr,
		&statep->scf_interface_handle) != DDI_SUCCESS) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "map_regs", 8);
		cmn_err(CE_WARN,
			"%s: scf_map_regs: ddi_regs_map_setup failed.\n",
			scf_driver_name);
		goto END_map_regs;
	}
	statep->resource_flag |= S_DID_REG5;

	/* get size of register : SRAM driver trace */
	wkoffset = SCF_DDI_GET32(statep, statep->scf_interface_handle,
		&statep->scf_interface->DRVTRC_OFFSET);
	statep->scf_reg_drvtrc_len =
		SCF_DDI_GET32(statep, statep->scf_interface_handle,
		&statep->scf_interface->DRVTRC_SIZE);

	if ((wkoffset != 0) && (statep->scf_reg_drvtrc_len != 0)) {
		/* map register : SRAM driver trace */
		if (ddi_regs_map_setup(dip, REG_INDEX_INTERFACE,
			(caddr_t *)&statep->scf_reg_drvtrc, wkoffset,
			(offset_t)statep->scf_reg_drvtrc_len, &access_attr,
			&statep->scf_reg_drvtrc_handle) != DDI_SUCCESS) {
			SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "map_regs", 8);
			cmn_err(CE_WARN,
				"%s: scf_map_regs: "
				"ddi_regs_map_setup failed.\n",
					scf_driver_name);
			goto END_map_regs;
		}
		statep->resource_flag |= S_DID_REG6;
	}

	/* SRAM trace initialize */
	scf_sram_trace_init(statep);

	ret = 0;

/*
 * END_map_regs
 */
	END_map_regs:

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_unmap_regs()
 *
 * Description: Register and SRAM un-map processing.
 *
 */
void
scf_unmap_regs(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_unmap_regs() "
	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	SCF_DBG_TEST_UNMAP_REGS(statep);

	/* Register and SRAM un-map */
	if (statep->resource_flag & S_DID_REG1) {
		ddi_regs_map_free(&statep->scf_regs_handle);
		statep->resource_flag &= ~S_DID_REG1;
	}

	if (statep->resource_flag & S_DID_REG2) {
		ddi_regs_map_free(&statep->scf_regs_c_handle);
		statep->resource_flag &= ~S_DID_REG2;
	}

	if (statep->resource_flag & S_DID_REG3) {
		ddi_regs_map_free(&statep->scf_dscp_sram_handle);
		statep->resource_flag &= ~S_DID_REG3;
	}

	if (statep->resource_flag & S_DID_REG4) {
		ddi_regs_map_free(&statep->scf_sys_sram_handle);
		statep->resource_flag &= ~S_DID_REG4;
	}

	if (statep->resource_flag & S_DID_REG5) {
		ddi_regs_map_free(&statep->scf_interface_handle);
		statep->resource_flag &= ~S_DID_REG5;
	}

	if (statep->resource_flag & S_DID_REG6) {
		ddi_regs_map_free(&statep->scf_reg_drvtrc_handle);
		statep->resource_flag &= ~S_DID_REG6;
	}

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * scf_send_cmd_check_bufful()
 *
 * Description: SCF command send and buffer busy check processing.
 *
 */
int
scf_send_cmd_check_bufful(struct scf_cmd *scfcmdp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_send_cmd_check_bufful() "
	int			ret = 0;
	int			buf_ful_cnt = scf_buf_ful_rcnt;
	int			rci_busy_cnt = scf_rci_busy_rcnt;
	clock_t			lb;
	struct scf_state	*statep;
	int			cv_ret;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	ret = scf_send_cmd(scfcmdp);

	while (((scfcmdp->stat0 == BUF_FUL) && (buf_ful_cnt != 0)) ||
		((scfcmdp->stat0 == RCI_BUSY) && (rci_busy_cnt != 0))) {
		if (scfcmdp->stat0 == BUF_FUL) {
			buf_ful_cnt--;
			lb = ddi_get_lbolt();
			lb += drv_usectohz(SCF_MIL2MICRO(scf_buf_ful_rtime));
			cv_ret = 0;
			while (cv_ret != (-1)) {
				SC_DBG_DRV_TRACE(TC_T_WAIT, __LINE__,
					&scf_comtbl.cmdbusy_cv,
					sizeof (kcondvar_t));
				if ((cv_ret =
					cv_timedwait_sig(&scf_comtbl.cmdbusy_cv,
					&scf_comtbl.all_mutex, lb)) == 0) {
					SC_DBG_DRV_TRACE(TC_KILL, __LINE__,
						&scf_comtbl.cmdbusy_cv,
						sizeof (kcondvar_t));
					ret = EINTR;
					goto END_send_cmd_check_bufful;
				}
			}
		} else if (scfcmdp->stat0 == RCI_BUSY) {
			rci_busy_cnt--;
			lb = ddi_get_lbolt();
			lb += drv_usectohz(SCF_MIL2MICRO(scf_rci_busy_rtime));
			cv_ret = 0;
			while (cv_ret != (-1)) {
				SC_DBG_DRV_TRACE(TC_T_WAIT, __LINE__,
					&scf_comtbl.cmdbusy_cv,
					sizeof (kcondvar_t));
				if ((cv_ret =
					cv_timedwait_sig(&scf_comtbl.cmdbusy_cv,
					&scf_comtbl.all_mutex, lb)) == 0) {
					SC_DBG_DRV_TRACE(TC_KILL, __LINE__,
						&scf_comtbl.cmdbusy_cv,
						sizeof (kcondvar_t));
					ret = EINTR;
					goto END_send_cmd_check_bufful;
				}
			}
		} else {
			break;
		}
		ret = scf_send_cmd(scfcmdp);
	}

	if (scf_comtbl.scf_exec_p) {
		statep = scf_comtbl.scf_exec_p;
	} else if (scf_comtbl.scf_path_p) {
		statep = scf_comtbl.scf_path_p;
	}
	if (statep != NULL) {
		if ((scfcmdp->stat0 == BUF_FUL) && (buf_ful_cnt == 0)) {
			cmn_err(CE_WARN,
				"%s,Buffer busy occurred in XSCF. "
				"SCF command = 0x%02x%02x\n",
					&statep->pathname[0],
					scfcmdp->subcmd, scfcmdp->cmd);
		} else if ((scfcmdp->stat0 == RCI_BUSY) &&
			(rci_busy_cnt == 0)) {
			cmn_err(CE_WARN,
				"%s,RCI busy occurred in XSCF. "
				"SCF command = 0x%02x%02x\n",
					&statep->pathname[0],
					scfcmdp->subcmd, scfcmdp->cmd);
		}
	}

/*
 * END_send_cmd_check_bufful
 */
	END_send_cmd_check_bufful:

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);

}


/*
 * scf_send_cmd()
 *
 * Description: Synchronized SCF command send processing.
 *
 */
int
scf_send_cmd(struct scf_cmd *scfcmdp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_send_cmd() "
	struct scf_state	*statep;
	int			ret = 0;
	int			offline_ret;
	int			cmdbusy_ret;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	scfcmdp->stat0 = 0;
	/* Check SCF command send sync re-start */
	if (scfcmdp->flag == SCF_USE_START) {
		if (scf_comtbl.path_stop_flag != 0) {
			/* Check path stop */
			scf_comtbl.path_stop_flag = 0;
			goto END_scf_send_cmd;
		}
		goto END_scf_send_cmd99;
	}
	/* Check SCF command send sync re-stop */
	if ((scfcmdp->flag == SCF_USE_STOP) &&
		(scf_comtbl.path_stop_flag != 0)) {
		goto STOP_scf_send_cmd;
	}
	/* Check SCF command send sync stop status */
	if ((scfcmdp->flag & SCF_USE_SP) != 0) {
		goto SP_scf_send_cmd;
	}
	/* IOCTL/DETACH/SUSPEND send sync */
	while (scf_comtbl.cmd_busy != 0) {
		scf_comtbl.cmd_wait += 1;
		SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__, &scf_comtbl.cmd_cv,
			sizeof (kcondvar_t));
		if (cv_wait_sig(&scf_comtbl.cmd_cv,
			&scf_comtbl.all_mutex) == 0) {
			SC_DBG_DRV_TRACE(TC_KILL, __LINE__, &scf_comtbl.cmd_cv,
				sizeof (kcondvar_t));
			scf_comtbl.cmd_wait -= 1;
			ret = EINTR;
			goto END_scf_send_cmd99;
		}
		scf_comtbl.cmd_wait -= 1;
	}
	scf_comtbl.cmd_busy = 1;

/*
 * STOP_scf_send_cmd
 */
	STOP_scf_send_cmd:

	/* Check SUSPEND flag */
	if (scf_comtbl.suspend_flag) {
		ret = EBUSY;
		scfcmdp->stat0 = SCF_STAT0_NOT_PATH;
		goto END_scf_send_cmd;
	}

	(void) scf_path_check(&statep);
	if (statep == NULL) {
		/* not exec SCF device */
		ret = EIO;
		scfcmdp->stat0 = SCF_STAT0_NOT_PATH;
		goto END_scf_send_cmd;
	}

	offline_ret = scf_offline_check(statep, FLAG_ON);
	cmdbusy_ret = scf_cmdbusy_check(statep);

	/* send comannd for interrupt */
	while ((scf_comtbl.scf_cmd_exec_flag != 0) ||
		(offline_ret != SCF_PATH_ONLINE) ||
		(cmdbusy_ret != SCF_COMMAND_READY)) {
		scf_comtbl.cmd_busy_wait = 1;
		SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__, &scf_comtbl.cmdwait_cv,
			sizeof (kcondvar_t));
		if (cv_wait_sig(&scf_comtbl.cmdwait_cv,
			&scf_comtbl.all_mutex) == 0) {
			SC_DBG_DRV_TRACE(TC_KILL, __LINE__,
				&scf_comtbl.cmdwait_cv, sizeof (kcondvar_t));
			scf_comtbl.cmd_busy_wait = 0;
			ret = EINTR;
			goto END_scf_send_cmd;
		}
		scf_comtbl.cmd_busy_wait = 0;

		(void) scf_path_check(&statep);
		if (statep == NULL) {
			/* not exec SCF device */
			ret = EIO;
			scfcmdp->stat0 = SCF_STAT0_NOT_PATH;
			goto END_scf_send_cmd;
		}

		offline_ret = scf_offline_check(statep, FLAG_ON);
		cmdbusy_ret = scf_cmdbusy_check(statep);

		if ((scf_comtbl.scf_cmd_exec_flag == 0) &&
			(offline_ret != SCF_PATH_ONLINE)) {
			scf_timer_stop(SCF_TIMERCD_CMDBUSY);
			scf_timer_stop(SCF_TIMERCD_ONLINE);
			ret = EBUSY;
			scfcmdp->stat0 = SCF_STAT0_NOT_PATH;
			goto END_scf_send_cmd;
		}
	}

/*
 * SP_scf_send_cmd
 */
	SP_scf_send_cmd:

	/* Check SUSPEND flag */
	if (scf_comtbl.suspend_flag) {
		ret = EBUSY;
		scfcmdp->stat0 = SCF_STAT0_NOT_PATH;
		goto END_scf_send_cmd;
	}
	if ((statep = scf_comtbl.scf_exec_p)  == 0) {
		ret = EIO;
		scfcmdp->stat0 = SCF_STAT0_NOT_PATH;
		goto END_scf_send_cmd;
	}

	if (scfcmdp->flag == SCF_USE_STOP) {
		/* SCF command send sync stop */
		scf_comtbl.path_stop_flag = 1;
		goto END_scf_send_cmd99;
	}

	bcopy((char *)scfcmdp, (char *)&scfcmd_save, sizeof (struct scf_cmd));
	if (scfcmdp->sbuf != NULL) {
		scfcmd_save.sbuf = &scf_sbuf_save[0];
		if (scfcmdp->scount) {
			bcopy(scfcmdp->sbuf, scf_sbuf_save, scfcmdp->scount);
		}
	}
	if (scfcmdp->rbuf != NULL) {
		scfcmd_save.rbuf = &scf_rbuf_save[0];
	}
	scfcmd_save.flag &= (~SCF_USE_SP);
	scf_i_send_cmd(&scfcmd_save, statep);
	scf_comtbl.scf_cmdp = &scfcmd_save;

	scf_comtbl.scf_exec_cmd_id = 1;

	scf_comtbl.cmd_end_wait = 1;
	while (scf_comtbl.cmd_end_wait != 0) {
		SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__, &scf_comtbl.cmdend_cv,
			sizeof (kcondvar_t));
		if (cv_wait_sig(&scf_comtbl.cmdend_cv,
			&scf_comtbl.all_mutex) == 0) {
			SC_DBG_DRV_TRACE(TC_KILL, __LINE__,
				&scf_comtbl.cmdend_cv, sizeof (kcondvar_t));
			scf_comtbl.cmd_end_wait = 0;
			ret = EINTR;
			goto END_scf_send_cmd;
		}
	}
	scfcmdp->stat0 = scfcmd_save.stat0;
	scfcmdp->rbufleng = scfcmd_save.rbufleng;
	scfcmdp->status = scfcmd_save.status;
	if (scfcmdp->rbuf != NULL) {
		if (scfcmdp->rbufleng < scfcmdp->rcount) {
			bcopy(&scf_rbuf_save[0], scfcmdp->rbuf,
				scfcmdp->rbufleng);
		} else {
			bcopy(&scf_rbuf_save[0], scfcmdp->rbuf,
				scfcmdp->rcount);
		}
	}
	scf_comtbl.cmd_end_wait = 0;

	switch (scfcmdp->stat0) {
	case NORMAL_END:
		break;

	case E_NOT_SUPPORT:
	case RCI_NS:
		ret = ENOTSUP;
		break;

	default:
		/* BUF_FUL/RCI_BUSY/other */
		ret = EIO;
	}

	if ((scfcmdp->flag & SCF_USE_SP) != 0) {
		goto END_scf_send_cmd99;
	}

/*
 * END_scf_send_cmd
 */
	END_scf_send_cmd:

	scf_comtbl.cmd_busy = 0;
	if (scf_comtbl.cmd_wait) {
		cv_signal(&scf_comtbl.cmd_cv);
		SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__, &scf_comtbl.cmd_cv,
			sizeof (kcondvar_t));
	}

	if ((scfcmdp->flag & SCF_USE_SP) != 0) {
		scf_comtbl.path_stop_flag = 0;
	}

/*
 * END_scf_send_cmd99
 */
	END_scf_send_cmd99:

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_i_send_cmd()
 *
 * Description: SCF command send processing. (for hard access)
 *
 */
void
scf_i_send_cmd(struct scf_cmd *scfcmdp, struct scf_state *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_i_send_cmd() "
	uint8_t			sdata[16];
	uint8_t			*wk_charp;
	uint8_t			sum = SCF_MAGICNUMBER_S;
	uint32_t		sum4 = SCF_MAGICNUMBER_L;
	int			scount;
	int			wkleng;
	int			ii;
	uint8_t			*wk_in_p;
	uint8_t			*wk_out_p;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	bzero((void *)sdata, 16);

	switch (scfcmdp->flag) {
	case SCF_USE_S_BUF:
	case SCF_USE_SSBUF:
	case SCF_USE_SLBUF:
		/*
		 * Use Tx data register, Not use Tx buffer data
		 */
		/* Set Tx data register memo */
		wk_charp = (uint8_t *)&scfcmdp->sbuf[0];
		if (scfcmdp->scount < SCF_S_CNT_16) {
			scount = scfcmdp->scount;
		} else {
			scount = SCF_S_CNT_15;
		}
		for (ii = 0; ii < scount; ii++, wk_charp++) {
			sdata[ii] = *wk_charp;
		}

		/* Set CMD_SPARE data */
		if (scfcmdp->cmd == CMD_SPARE) {
			sdata[12] = scfcmdp->cexr[0];
			sdata[13] = scfcmdp->cexr[1];
		}

		break;

	case SCF_USE_L_BUF:
	case SCF_USE_LSBUF:
		/*
		 * Use Tx data register, Use Tx buffer data
		 */
		/* Make Tx buffer data sum */
		for (ii = 0; ii < (scfcmdp->scount / 4); ii++) {
			sum4 += ((scfcmdp->sbuf[ii * 4 + 0] << 24) |
				(scfcmdp->sbuf[ii * 4 + 1] << 16) |
				(scfcmdp->sbuf[ii * 4 + 2] <<  8) |
				(scfcmdp->sbuf[ii * 4 + 3]));
		}
		if ((scfcmdp->scount % 4) == 3) {
			sum4 += ((scfcmdp->sbuf[ii * 4 + 0] << 24) |
				(scfcmdp->sbuf[ii * 4 + 1] << 16) |
				(scfcmdp->sbuf[ii * 4 + 2] <<  8));
		} else if ((scfcmdp->scount % 4) == 2) {
			sum4 += ((scfcmdp->sbuf[ii * 4 + 0] << 24) |
				(scfcmdp->sbuf[ii * 4 + 1] << 16));
		} else if ((scfcmdp->scount % 4) == 1) {
			sum4 += (scfcmdp->sbuf[ii * 4 + 0] << 24);
		}

		/* Set Tx data register memo : data length */
		wk_charp = (uint8_t *)&scfcmdp->scount;
		for (ii = 0; ii < 4; ii++, wk_charp++) {
			sdata[ii] = *wk_charp;
		}

		/* Set Tx data register memo : sum */
		wk_charp = (uint8_t *)&sum4;
		for (ii = 8; ii < 12; ii++, wk_charp++) {
			sdata[ii] = *wk_charp;
		}

		/* Set CMD_SPARE data */
		if (scfcmdp->cmd == CMD_SPARE) {
			sdata[12] = scfcmdp->cexr[0];
			sdata[13] = scfcmdp->cexr[1];
		}

		/* SRAM data write */
		wk_in_p = (uint8_t *)scfcmdp->sbuf;
		wk_out_p = (uint8_t *)&statep->scf_sys_sram->DATA[0];
		for (ii = 0; ii < scfcmdp->scount;
			ii++, wk_in_p++, wk_out_p++) {
			SCF_DDI_PUT8(statep, statep->scf_sys_sram_handle,
				wk_out_p, *wk_in_p);
		}

		break;
	}

	/* Make Tx data sum */
	for (ii = 0; ii < SCF_S_CNT_15; ii++) {
		sum += sdata[ii];
	}
	/* Set Tx data sum */
	sdata[15] = sum;

	/* TxDATA register set */
	statep->reg_tdata[0] =
		(sdata[0] << 24) | (sdata[1] << 16) |
		(sdata[2] << 8) | sdata[3];
	SCF_DDI_PUT32(statep, statep->scf_regs_handle,
		&statep->scf_regs->TDATA0, statep->reg_tdata[0]);

	statep->reg_tdata[1] =
		(sdata[4] << 24) | (sdata[5] << 16) |
		(sdata[6] << 8) | sdata[7];
	SCF_DDI_PUT32(statep, statep->scf_regs_handle,
		&statep->scf_regs->TDATA1, statep->reg_tdata[1]);

	SC_DBG_DRV_TRACE(TC_W_TDATA0, __LINE__, &statep->reg_tdata[0],
		sizeof (statep->reg_tdata[0]) + sizeof (statep->reg_tdata[1]));

	statep->reg_tdata[2] =
		(sdata[8] << 24) | (sdata[9] << 16) |
		(sdata[10] << 8) | sdata[11];
	SCF_DDI_PUT32(statep, statep->scf_regs_handle,
		&statep->scf_regs->TDATA2, statep->reg_tdata[2]);

	statep->reg_tdata[3] =
		(sdata[12] << 24) | (sdata[13] << 16) |
		(sdata[14] << 8) | sdata[15];
	SCF_DDI_PUT32(statep, statep->scf_regs_handle,
		&statep->scf_regs->TDATA3, statep->reg_tdata[3]);

	SC_DBG_DRV_TRACE(TC_W_TDATA2, __LINE__, &statep->reg_tdata[2],
		sizeof (statep->reg_tdata[2]) + sizeof (statep->reg_tdata[3]));

	/* SCF command extendedregister set */
	if (scf_comtbl.scf_cmd_resend_flag == 0) {
		statep->reg_command_exr = 0x00;
	} else {
		scf_comtbl.scf_cmd_resend_flag = 0;
		statep->reg_command_exr = COMMAND_ExR_RETRY;
	}
	SCF_DDI_PUT8(statep, statep->scf_regs_handle,
		&statep->scf_regs->COMMAND_ExR, statep->reg_command_exr);
	SC_DBG_DRV_TRACE(TC_W_COMMAND_ExR, __LINE__, &statep->reg_command_exr,
		sizeof (statep->reg_command_exr));

	/* SCF command register set */
	statep->reg_command = ((scfcmdp->subcmd << 8) | scfcmdp->cmd);

	/* Set sub command code */
	SCF_DDI_PUT8(statep, statep->scf_regs_handle,
		(uint8_t *)&statep->scf_regs->COMMAND,
		(uint8_t)(statep->reg_command >> 8));
	/* Set command code : SCF interrupt */
	SCF_DDI_PUT8(statep, statep->scf_regs_handle,
		(uint8_t *)&statep->scf_regs->COMMAND + 1,
		(uint8_t)statep->reg_command);

	SC_DBG_DRV_TRACE(TC_W_COMMAND, __LINE__, &statep->reg_command,
		sizeof (statep->reg_command));
	/* Register read sync */
	scf_rs16 = SCF_DDI_GET16(statep, statep->scf_regs_handle,
		&statep->scf_regs->COMMAND);

	SCFDBGMSG2(SCF_DBGFLAG_REG, "CMD = 0x%04x CMDExR = 0x%02x",
		statep->reg_command, statep->reg_command_exr);
	SCFDBGMSG4(SCF_DBGFLAG_REG, "TxDR = 0x%08x 0x%08x 0x%08x 0x%08x",
		statep->reg_tdata[0], statep->reg_tdata[1],
		statep->reg_tdata[2], statep->reg_tdata[3]);

	scf_comtbl.scf_cmd_exec_flag = 1;
	scf_comtbl.scf_exec_cmd_id = 0;

	/* SCF command timer start */
	scf_timer_start(SCF_TIMERCD_CMDEND);

	/* SRAM trace */
	SCF_SRAM_TRACE(statep, DTC_CMD);
	SCF_SRAM_TRACE(statep, DTC_SENDDATA);

	if (((scfcmdp->flag == SCF_USE_L_BUF) ||
		(scfcmdp->flag == SCF_USE_LSBUF)) &&
		(scfcmdp->scount != 0)) {
		if (scfcmdp->scount > scf_sram_trace_data_size) {
			scount = scf_sram_trace_data_size;
		} else {
			scount = scfcmdp->scount;
		}
		wk_in_p = (uint8_t *)scfcmdp->sbuf;
		while (scount != 0) {
			bzero((void *)&statep->memo_scf_drvtrc.INFO[0],
				sizeof (statep->memo_scf_drvtrc.INFO));
			wk_out_p = (uint8_t *)&statep->memo_scf_drvtrc.INFO[0];
			if (scount > sizeof (statep->memo_scf_drvtrc.INFO)) {
				wkleng = sizeof (statep->memo_scf_drvtrc.INFO);
			} else {
				wkleng = scount;
			}
			scount -= wkleng;
			bcopy(wk_in_p, wk_out_p, wkleng);
			SCF_SRAM_TRACE(statep, DTC_SENDDATA_SRAM);
			wk_in_p += wkleng;
		}
	}

	SC_DBG_DRV_TRACE(TC_SEND, __LINE__, &scfcmdp->flag, 8);
	SC_DBG_DRV_TRACE(TC_SEND, __LINE__, &scfcmdp->scount, 8);

	SCF_DBG_TEST_SEND_CMD(statep, scfcmdp);

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * panic send cmd function
 */
void
scf_p_send_cmd(struct scf_cmd *scfcmdp, struct scf_state *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_p_send_cmd() "
	uint8_t			sdata[16];
	uint8_t			*wk_charp;
	uint8_t			sum = SCF_MAGICNUMBER_S;
	uint32_t		sum4 = SCF_MAGICNUMBER_L;
	int			scount;
	int			ii;
	uint8_t			*wk_in_p;
	uint8_t			*wk_out_p;
	uint16_t		wk_int16;

	SCFDBGMSG(SCF_DBGFLAG_FOCK, SCF_FUNC_NAME ": start");

	bzero((void *)sdata, 16);

	switch (scfcmdp->flag) {
	case SCF_USE_S_BUF:
	case SCF_USE_SSBUF:
	case SCF_USE_SLBUF:
		/*
		 * Use Tx data register, Not use Tx buffer data
		 */
		/* Set Tx data register memo */
		wk_charp = (uint8_t *)&scfcmdp->sbuf[0];
		if (scfcmdp->scount < SCF_S_CNT_16) {
			scount = scfcmdp->scount;
		} else {
			scount = SCF_S_CNT_15;
		}
		for (ii = 0; ii < scount; ii++, wk_charp++) {
			sdata[ii] = *wk_charp;
		}

		break;

	case SCF_USE_L_BUF:
	case SCF_USE_LSBUF:
		/*
		 * Use Tx data register, Use Tx buffer data
		 */
		/* Make Tx buffer data sum */
		for (ii = 0; ii < (scfcmdp->scount / 4); ii++) {
			sum4 += ((scfcmdp->sbuf[ii * 4 + 0] << 24) |
				(scfcmdp->sbuf[ii * 4 + 1] << 16) |
				(scfcmdp->sbuf[ii * 4 + 2] <<  8) |
				(scfcmdp->sbuf[ii * 4 + 3]));
		}
		if ((scfcmdp->scount % 4) == 3) {
			sum4 += ((scfcmdp->sbuf[ii * 4 + 0] << 24) |
				(scfcmdp->sbuf[ii * 4 + 1] << 16) |
				(scfcmdp->sbuf[ii * 4 + 2] <<  8));
		} else if ((scfcmdp->scount % 4) == 2) {
			sum4 += ((scfcmdp->sbuf[ii * 4 + 0] << 24) |
				(scfcmdp->sbuf[ii * 4 + 1] << 16));
		} else if ((scfcmdp->scount % 4) == 1) {
			sum4 += (scfcmdp->sbuf[ii * 4 + 0] << 24);
		}

		/* Set Tx data register memo : data length */
		wk_charp = (uint8_t *)&scfcmdp->scount;
		for (ii = 0; ii < 4; ii++, wk_charp++) {
			sdata[ii] = *wk_charp;
		}

		/* Set Tx data register memo : sum */
		wk_charp = (uint8_t *)&sum4;
		for (ii = 8; ii < 12; ii++, wk_charp++) {
			sdata[ii] = *wk_charp;
		}

		/* Set CMD_SPARE data */
		if (scfcmdp->cmd == CMD_SPARE) {
			sdata[12] = scfcmdp->cexr[0];
			sdata[13] = scfcmdp->cexr[1];
		}

		/* SRAM data write */
		wk_in_p = (uint8_t *)scfcmdp->sbuf;
		wk_out_p = (uint8_t *)&statep->scf_sys_sram->DATA[0];
		for (ii = 0; ii < scfcmdp->scount;
			ii++, wk_in_p++, wk_out_p++) {
			SCF_P_DDI_PUT8(statep->scf_sys_sram_handle,
				wk_out_p, *wk_in_p);
		}

		break;
	}

	/* Make Tx data sum */
	for (ii = 0; ii < SCF_S_CNT_15; ii++) {
		sum += sdata[ii];
	}
	/* Set Tx data sum */
	sdata[15] = sum;

	/* TxDATA register set */
	SCF_P_DDI_PUT32(statep->scf_regs_handle, &statep->scf_regs->TDATA0,
		(sdata[0] << 24) | (sdata[1] << 16) |
		(sdata[2] << 8) | sdata[3]);
	SCF_P_DDI_PUT32(statep->scf_regs_handle, &statep->scf_regs->TDATA1,
		(sdata[4] << 24) | (sdata[5] << 16) |
		(sdata[6] << 8) | sdata[7]);
	SCF_P_DDI_PUT32(statep->scf_regs_handle, &statep->scf_regs->TDATA2,
		(sdata[8] << 24) | (sdata[9] << 16) |
		(sdata[10] << 8) | sdata[11]);
	SCF_P_DDI_PUT32(statep->scf_regs_handle, &statep->scf_regs->TDATA3,
		(sdata[12] << 24) | (sdata[13] << 16) |
		(sdata[14] << 8) | sdata[15]);

	/* SCF command extendedregister set */
	SCF_P_DDI_PUT8(statep->scf_regs_handle,
		&statep->scf_regs->COMMAND_ExR, 0x00);

	/* SCF command register set */
	SCF_P_DDI_PUT8(statep->scf_regs_handle,
		(uint8_t *)&statep->scf_regs->COMMAND,
		(uint8_t)scfcmdp->subcmd);
	SCF_P_DDI_PUT8(statep->scf_regs_handle,
		(uint8_t *)&statep->scf_regs->COMMAND + 1,
		(uint8_t)scfcmdp->cmd);
	/* Register read sync */
	wk_int16 = SCF_P_DDI_GET16(statep->scf_regs_handle,
		&statep->scf_regs->COMMAND);
	scf_panic_trc_command = wk_int16;

	SCFDBGMSG(SCF_DBGFLAG_FOCK, SCF_FUNC_NAME ": end");
}


/*
 * SCF path status check
 */
int
scf_path_check(scf_state_t **statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_path_check() "
	int			ret;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	if (scf_comtbl.scf_exec_p != NULL) {
		/* SCF path exec status */
		if (statep != NULL) {
			*statep = scf_comtbl.scf_exec_p;
		}

		ret = scf_offline_check(scf_comtbl.scf_exec_p, FLAG_ON);

	} else if (scf_comtbl.scf_path_p != NULL) {
		/* SCF path change status */
		if (statep != NULL) {
			*statep = scf_comtbl.scf_path_p;
		}

		ret = scf_offline_check(scf_comtbl.scf_path_p, FLAG_ON);

		if (ret == SCF_PATH_ONLINE) {
			SCFDBGMSG(SCF_DBGFLAG_SYS, "SCF path change status");
			ret = SCF_PATH_CHANGE;
		}

	} else {
		/* SCF path halt status */
		if (statep != NULL) {
			*statep = NULL;
		}

		SCFDBGMSG(SCF_DBGFLAG_SYS, "SCF path halt status");
		ret = SCF_PATH_HALT;

	}

	SCF_DBG_MAKE_PATH_CHECK(ret);

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * ESCF offline check
 */
int
scf_offline_check(scf_state_t *statep, uint_t timer_exec_flag)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_offline_check() "
	int			ret;
	uint8_t			scf_unit;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Get SCF Status extended register */
	statep->reg_status_exr = SCF_DDI_GET32(statep, statep->scf_regs_handle,
		&statep->scf_regs->STATUS_ExR);
	SC_DBG_DRV_TRACE(TC_R_STATUS_ExR, __LINE__, &statep->reg_status_exr,
		sizeof (statep->reg_status_exr));

	SCF_DBG_MAKE_ONLINE(statep->reg_status_exr);

	/* Check SCF online */
	if ((statep->reg_status_exr & STATUS_SCF_STATUS) == STATUS_SCF_ONLINE) {
		if (scf_comtbl.scf_status == SCF_STATUS_OFFLINE) {
			cmn_err(CE_NOTE, "%s: SCF online.\n", scf_driver_name);
		}
		scf_comtbl.scf_status = SCF_STATUS_ONLINE;

		if (timer_exec_flag == FLAG_ON) {
			/* Check online wait timer exec */
			if (scf_timer_check(SCF_TIMERCD_ONLINE) ==
				SCF_TIMER_NOT_EXEC) {
				ret = SCF_PATH_ONLINE;
			} else {
				ret = SCF_PATH_OFFLINE_DRV;
			}
		} else {
			ret = SCF_PATH_ONLINE;
		}
	} else {
		if (scf_comtbl.scf_status != SCF_STATUS_OFFLINE) {
			if (statep->reg_status_exr & STATUS_SCF_NO) {
				scf_unit = 1;
			} else {
				scf_unit = 0;
			}
			cmn_err(CE_WARN,
				"%s: SCF went to offline mode. unit=%d",
				scf_driver_name, scf_unit);
		}
		scf_comtbl.scf_status = SCF_STATUS_OFFLINE;

		if (timer_exec_flag == FLAG_ON) {
			/* Check online wait timer exec */
			if (scf_timer_check(SCF_TIMERCD_ONLINE) ==
				SCF_TIMER_NOT_EXEC) {
				/* DCSP interface stop */
				scf_dscp_stop(FACTOR_OFFLINE);

				/* SCF online timer start */
				statep->online_to_rcnt = 0;
				scf_timer_start(SCF_TIMERCD_ONLINE);
			}
		}
		SCFDBGMSG(SCF_DBGFLAG_SYS, "SCF path offline");
		ret = SCF_PATH_OFFLINE;
	}

	SCF_DBG_MAKE_OFFLINE_CHECK(ret);

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * SCF command busy check
 */
int
scf_cmdbusy_check(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_cmdbusy_check() "
	int			ret;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	SCF_DBG_RTN_MAKE_CMD_READY;

	/* Get SCF command register */
	statep->reg_command = SCF_DDI_GET16(statep, statep->scf_regs_handle,
		&statep->scf_regs->COMMAND);
	SC_DBG_DRV_TRACE(TC_R_COMMAND, __LINE__, &statep->reg_command,
		sizeof (statep->reg_command));
	statep->reg_command_exr = SCF_DDI_GET8(statep, statep->scf_regs_handle,
		&statep->scf_regs->COMMAND_ExR);
	SC_DBG_DRV_TRACE(TC_R_COMMAND_ExR, __LINE__, &statep->reg_command_exr,
		sizeof (statep->reg_command_exr));

	SCF_DBG_MAKE_CMD_BUSY(statep->reg_command, statep->reg_command_exr);

	/* Check busy flag */
	if (((statep->reg_command & COMMAND_BUSY) == 0x0000) &&
		((statep->reg_command_exr & COMMAND_ExR_BUSY) == 0x00)) {
		/* Check busy timer exec */
		if (scf_timer_check(SCF_TIMERCD_CMDBUSY) ==
			SCF_TIMER_NOT_EXEC) {
			ret = SCF_COMMAND_READY;
			SCFDBGMSG(SCF_DBGFLAG_SYS, "SCF command busy");
		} else {
			ret = SCF_COMMAND_BUSY_DRV;
			SCFDBGMSG(SCF_DBGFLAG_SYS, "SCF command exr busy");
		}
	} else {
		if (scf_comtbl.scf_cmd_exec_flag == FLAG_OFF) {
			/* Check busy timer exec */
			if (scf_timer_check(SCF_TIMERCD_CMDBUSY) ==
				SCF_TIMER_NOT_EXEC) {
				/* busy timer start */
				statep->devbusy_to_rcnt = 0;
				scf_timer_start(SCF_TIMERCD_CMDBUSY);
			}
		}
		ret = SCF_COMMAND_BUSY;
	}

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


void
scf_alivecheck_start(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_alivecheck_start() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Check alive check exec */
	if (scf_comtbl.alive_running == SCF_ALIVE_START) {
		/* Alive check value initialize */
		scf_acr_phase_code = 0;
		scf_comtbl.scf_alive_int_count = scf_alive_interval_time / 3;

		/* Alive timer register initialize */
		statep->reg_atr = ATR_INTERVAL_STOP;
		SCF_DDI_PUT8(statep, statep->scf_regs_handle,
			&statep->scf_regs->ATR, statep->reg_atr);
		SC_DBG_DRV_TRACE(TC_W_ATR, __LINE__, &statep->reg_atr,
			sizeof (statep->reg_atr));
		/* Register read sync */
		scf_rs8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
			&statep->scf_regs->ATR);

		/* Alive Interrupt enable */
		statep->reg_control |= CONTROL_ALIVEINE;
		SCF_DDI_PUT16(statep, statep->scf_regs_c_handle,
			&statep->scf_regs_c->CONTROL, statep->reg_control);
		SC_DBG_DRV_TRACE(TC_W_CONTROL, __LINE__, &statep->reg_control,
			sizeof (statep->reg_control));
		/* Register read sync */
		scf_rs16 = SCF_DDI_GET16(statep, statep->scf_regs_c_handle,
			&statep->scf_regs_c->CONTROL);

		/* Alive timer register set */
		statep->reg_atr = ATR_INTERVAL_30S;
		SCF_DDI_PUT8(statep, statep->scf_regs_handle,
			&statep->scf_regs->ATR, statep->reg_atr);
		SC_DBG_DRV_TRACE(TC_W_ATR, __LINE__, &statep->reg_atr,
			sizeof (statep->reg_atr));
		/* Register read sync */
		scf_rs8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
			&statep->scf_regs->ATR);

		/* Alive check register set */
		statep->reg_acr = scf_acr_phase_code | ACR_ALIVE_INT;
		SCF_DDI_PUT8(statep, statep->scf_regs_handle,
			&statep->scf_regs->ACR, statep->reg_acr);
		SC_DBG_DRV_TRACE(TC_W_ACR, __LINE__, &statep->reg_acr,
			sizeof (statep->reg_acr));
		/* Register read sync */
		scf_rs8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
			&statep->scf_regs->ACR);

		SCFDBGMSG1(SCF_DBGFLAG_REG, "ACR = 0x%02x", statep->reg_acr);

		scf_acr_phase_code++;

		SCF_DBG_TEST_ALIVE_START(statep);
	}

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


void
scf_alivecheck_stop(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_alivecheck_stop() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Alive Interrupt disable */
	statep->reg_control &= (~CONTROL_ALIVEINE);
	SCF_DDI_PUT16(statep, statep->scf_regs_c_handle,
		&statep->scf_regs_c->CONTROL, statep->reg_control);
	SC_DBG_DRV_TRACE(TC_W_CONTROL, __LINE__, &statep->reg_control,
		sizeof (statep->reg_control));
	/* Register read sync */
	scf_rs16 = SCF_DDI_GET16(statep, statep->scf_regs_c_handle,
		&statep->scf_regs_c->CONTROL);

	/* Alive timer register clear */
	statep->reg_atr = ATR_INTERVAL_STOP;
	SCF_DDI_PUT8(statep, statep->scf_regs_handle,
		&statep->scf_regs->ATR, statep->reg_atr);
	SC_DBG_DRV_TRACE(TC_W_ATR, __LINE__, &statep->reg_atr,
		sizeof (statep->reg_atr));
	/* Register read sync */
	scf_rs8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
		&statep->scf_regs->ATR);

	SCF_DBG_TEST_ALIVE_STOP(statep);

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * forbid SCF interrupt
 */
void
scf_forbid_intr(struct scf_state *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_forbid_intr() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Interrupt disable */
	statep->reg_control = CONTROL_DISABLE;
	SCF_DDI_PUT16(statep, statep->scf_regs_c_handle,
		&statep->scf_regs_c->CONTROL, statep->reg_control);
	SC_DBG_DRV_TRACE(TC_W_CONTROL, __LINE__, &statep->reg_control,
		sizeof (statep->reg_control));
	/* Register read sync */
	scf_rs16 = SCF_DDI_GET16(statep, statep->scf_regs_c_handle,
		&statep->scf_regs_c->CONTROL);

	scf_alivecheck_stop(statep);

	statep->resource_flag &= (~S_DID_REGENB);

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * permit SCF interrupt
 */
void
scf_permit_intr(struct scf_state *statep, int flag)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_permit_intr() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	if (flag) {
		/* SCF Status register interrupt clear */
		SCF_DDI_PUT16(statep, statep->scf_regs_handle,
			&statep->scf_regs->STATUS, 0xffff);
		/* Register read sync */
		scf_rs16 = SCF_DDI_GET16(statep, statep->scf_regs_handle,
			&statep->scf_regs->STATUS);

		/* SCF Status extended register interrupt clear */
		SCF_DDI_PUT32(statep, statep->scf_regs_handle,
			&statep->scf_regs->STATUS_ExR, 0xffffffff);
		/* Register read sync */
		scf_rs32 = SCF_DDI_GET32(statep, statep->scf_regs_handle,
			&statep->scf_regs->STATUS_ExR);

		/* DSCP buffer status register interrupt clear */
		SCF_DDI_PUT8(statep, statep->scf_regs_handle,
			&statep->scf_regs->DSR, 0xff);
		/* Register read sync */
		scf_rs8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
			&statep->scf_regs->DSR);

		/* SCF interrupt status register interrupt clear */
		SCF_DDI_PUT16(statep, statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST,
			(INT_ST_PATHCHGIE | CONTROL_ALIVEINE));
		/* Register read sync */
		scf_rs16 = SCF_DDI_GET16(statep, statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST);
	}

	/* Interrupt enable */
	statep->reg_control = CONTROL_ENABLE;
	SCF_DDI_PUT16(statep, statep->scf_regs_c_handle,
		&statep->scf_regs_c->CONTROL, statep->reg_control);
	SC_DBG_DRV_TRACE(TC_W_CONTROL, __LINE__, &statep->reg_control,
		sizeof (statep->reg_control));
	/* Register read sync */
	scf_rs16 = SCF_DDI_GET16(statep, statep->scf_regs_c_handle,
		&statep->scf_regs_c->CONTROL);

	statep->resource_flag |= S_DID_REGENB;

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * Path status check
 */
int
scf_check_state(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_check_state() "
	scf_state_t		*wkstatep;
	int			ret;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	if (statep != NULL) {
		if ((statep == scf_comtbl.scf_exec_p) ||
			(statep == scf_comtbl.scf_path_p)) {
			/* PATH_STAT_ACTIVE status */
			ret = PATH_STAT_ACTIVE;
		} else {
			wkstatep = scf_comtbl.scf_wait_p;
			while (wkstatep) {
				if (statep == wkstatep) {
					/* PATH_STAT_STANDBY status */
					ret = PATH_STAT_STANDBY;
					goto END_check_state;
				} else {
					wkstatep = wkstatep->next;
				}
			}
			wkstatep = scf_comtbl.scf_stop_p;
			while (wkstatep) {
				if (statep == wkstatep) {
					/* PATH_STAT_STOP status */
					ret = PATH_STAT_STOP;
					goto END_check_state;
				} else {
					wkstatep = wkstatep->next;
				}
			}
			wkstatep = scf_comtbl.scf_err_p;
			while (wkstatep) {
				if (statep == wkstatep) {
					/* PATH_STAT_FAIL status */
					ret = PATH_STAT_FAIL;
					goto END_check_state;
				} else {
					wkstatep = wkstatep->next;
				}
			}
			wkstatep = scf_comtbl.scf_disc_p;
			while (wkstatep) {
				if (statep == wkstatep) {
					/* PATH_STAT_DISCON status */
					ret = PATH_STAT_DISCON;
					goto END_check_state;
				} else {
					wkstatep = wkstatep->next;
				}
			}
			/* scf_comtbl.scf_suspend_p queue */
			/* PATH_STAT_DISCON status */
			ret = PATH_STAT_EMPTY;
		}
	} else {
		/* PATH_STAT_DISCON status */
		ret = PATH_STAT_EMPTY;
	}

/*
 * END_check_state
 */
	END_check_state:

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * Multi path status change and queue change
 */
void
scf_chg_scf(scf_state_t *statep, int status)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_chg_scf() "
	scf_state_t		*wkstatep;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG2(SCF_DBGFLAG_SYS,
		SCF_FUNC_NAME ": start instance = %d status = %d",
		statep->instance, statep->path_status);

	/* Set path status */
	if (statep->path_status != status) {
		statep->old_path_status = statep->path_status;
		statep->path_status = status;
	}
	switch (status) {
	case PATH_STAT_ACTIVE:
		/* Not queue change */
		break;

	case PATH_STAT_EMPTY:
		/* Change empty queue */
		if (scf_comtbl.scf_suspend_p) {
			wkstatep = scf_comtbl.scf_suspend_p;
			while (wkstatep->next) {
				wkstatep = wkstatep->next;
			}
			wkstatep->next = statep;
		} else {
			scf_comtbl.scf_suspend_p = statep;
		}
		statep->next = 0;
		break;

	case PATH_STAT_STANDBY:
		/* Change standby queue */
		if (scf_comtbl.scf_wait_p) {
			wkstatep = scf_comtbl.scf_wait_p;
			while (wkstatep->next) {
				wkstatep = wkstatep->next;
			}
			wkstatep->next = statep;
		} else {
			scf_comtbl.scf_wait_p = statep;
		}
		statep->next = 0;
		break;

	case PATH_STAT_STOP:
		/* Change stop queue */
		if (scf_comtbl.scf_stop_p) {
			wkstatep = scf_comtbl.scf_stop_p;
			while (wkstatep->next) {
				wkstatep = wkstatep->next;
			}
			wkstatep->next = statep;
		} else {
			scf_comtbl.scf_stop_p = statep;
		}
		statep->next = 0;
		break;

	case PATH_STAT_FAIL:
		/* Change fail queue */
		if (scf_comtbl.scf_err_p) {
			wkstatep = scf_comtbl.scf_err_p;
			while (wkstatep->next) {
				wkstatep = wkstatep->next;
			}
			wkstatep->next = statep;
		} else {
			scf_comtbl.scf_err_p = statep;
		}
		statep->next = 0;
		break;

	case PATH_STAT_DISCON:
		/* Change disconnect queue */
		if (scf_comtbl.scf_disc_p) {
			wkstatep = scf_comtbl.scf_disc_p;
			while (wkstatep->next) {
				wkstatep = wkstatep->next;
			}
			wkstatep->next = statep;
		} else {
			scf_comtbl.scf_disc_p = statep;
		}
		statep->next = 0;
		break;
	}
	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end status = %d",
		statep->path_status);
}

/*
 * Multi path  queue check and delete queue
 */
void
scf_del_queue(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_del_queue() "
	scf_state_t		*wkstatep;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start instance = %d",
		statep->instance);

	if ((wkstatep = scf_comtbl.scf_exec_p) == statep) {
		/* Delete active(exec) queue */
		scf_comtbl.scf_exec_p = NULL;
		return;
	} else if ((wkstatep = scf_comtbl.scf_path_p) == statep) {
		/* Delete active(path change) queue */
		scf_comtbl.scf_path_p = NULL;
		return;
	} else {
		if ((wkstatep = scf_comtbl.scf_suspend_p) != 0) {
			/* Delete empty(suspend) queue */
			if (wkstatep == statep) {
				scf_comtbl.scf_suspend_p = wkstatep->next;
				return;
			} else {
				while (wkstatep->next) {
					if (wkstatep->next == statep) {
						wkstatep->next = statep->next;
						return;
					}
					wkstatep = wkstatep->next;
				}
			}
		}
		if ((wkstatep = scf_comtbl.scf_wait_p) != 0) {
			/* Delete standby(wait) queue */
			if (wkstatep == statep) {
				scf_comtbl.scf_wait_p = wkstatep->next;
				return;
			} else {
				while (wkstatep->next) {
					if (wkstatep->next == statep) {
						wkstatep->next = statep->next;
						return;
					}
					wkstatep = wkstatep->next;
				}
			}
		}
		if ((wkstatep = scf_comtbl.scf_err_p) != 0) {
			/* Delete fail(error) queue */
			if (wkstatep == statep) {
				scf_comtbl.scf_err_p = wkstatep->next;
				return;
			} else {
				while (wkstatep->next) {
					if (wkstatep->next == statep) {
						wkstatep->next = statep->next;
						return;
					}
					wkstatep = wkstatep->next;
				}
			}
		}
		if ((wkstatep = scf_comtbl.scf_stop_p) != 0) {
			/* Delete stop queue */
			if (wkstatep == statep) {
				scf_comtbl.scf_stop_p = wkstatep->next;
				return;
			} else {
				while (wkstatep->next) {
					if (wkstatep->next == statep) {
						wkstatep->next = statep->next;
						return;
					}
					wkstatep = wkstatep->next;
				}
			}
		}
		if ((wkstatep = scf_comtbl.scf_disc_p) != 0) {
			/* Delete disconnect queue */
			if (wkstatep == statep) {
				scf_comtbl.scf_disc_p = wkstatep->next;
				return;
			} else {
				while (wkstatep->next) {
					if (wkstatep->next == statep) {
						wkstatep->next = statep->next;
						return;
					}
					wkstatep = wkstatep->next;
				}
			}
		}
	}
	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * SCF command send sync
 */
int
scf_make_send_cmd(struct scf_cmd *scfcmdp, uint_t flag)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_make_send_cmd() "
	/* falg = SCF_USE_STOP  : SCF command stop wait */
	/* falg = SCF_USE_START : SCF_USE_STOP signal  */

	int					ret;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start flag = 0x%08x",
		flag);

	scfcmdp->cmd = 0;
	scfcmdp->subcmd = 0;
	scfcmdp->scount = 0;
	scfcmdp->sbuf = NULL;
	scfcmdp->rcount = 0;
	scfcmdp->rbuf = NULL;
	scfcmdp->flag = flag;
	ret = scf_send_cmd_check_bufful(scfcmdp);

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_sram_trace_init()
 *
 * SRAM trace initialize processing.
 *
 */
void
scf_sram_trace_init(struct scf_state *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_sram_trace_init() "
	uint8_t			wk_drv_id;
	uint32_t		wk_data_top;
	uint32_t		wk_data_last;
	uint32_t		wk_data_write;
	off_t			min_len;
	uint8_t			*wk_in_p;
	uint8_t			*wk_out_p;
	int			wk_leng;
	int			ii;
	uint8_t			drv_name[DRV_ID_SIZE];
	uint8_t			*wk_drv_vl = (uint8_t *)SCF_DRIVER_VERSION;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_TRACE, SCF_FUNC_NAME ": start");

	/* Check SRAM map */
	if (statep->resource_flag & S_DID_REG6) {
		wk_drv_id =
			SCF_DDI_GET8(statep, statep->scf_reg_drvtrc_handle,
			&statep->scf_reg_drvtrc->DRV_ID[0]);
		wk_data_top =
			SCF_DDI_GET32(statep, statep->scf_reg_drvtrc_handle,
			&statep->scf_reg_drvtrc->DATA_TOP);
		wk_data_last =
			SCF_DDI_GET32(statep, statep->scf_reg_drvtrc_handle,
			&statep->scf_reg_drvtrc->DATA_LAST);
		wk_data_write =
			SCF_DDI_GET32(statep, statep->scf_reg_drvtrc_handle,
			&statep->scf_reg_drvtrc->DATA_WRITE);
		if ((wk_drv_id == 0) ||
			(wk_data_top != statep->memo_DATA_TOP) ||
			(wk_data_last != statep->memo_DATA_LAST) ||
			((wk_data_write >= wk_data_top) &&
			(wk_data_write <= wk_data_last))) {
			/* Make SRAM driver trace header */
			min_len = (off_t)(sizeof (scf_if_drvtrc_t) +
				sizeof (scf_drvtrc_ent_t));
			if (statep->scf_reg_drvtrc_len >= min_len) {
				statep->memo_DATA_TOP =
					(uint32_t)(sizeof (scf_if_drvtrc_t));
				statep->memo_DATA_WRITE =
					(uint32_t)(sizeof (scf_if_drvtrc_t));
				statep->memo_DATA_LAST =
					(uint32_t)(statep->scf_reg_drvtrc_len -
					sizeof (scf_drvtrc_ent_t));
			} else {
				statep->memo_DATA_TOP = 0;
				statep->memo_DATA_WRITE = 0;
				statep->memo_DATA_LAST = 0;
			}
			SCF_DDI_PUT32(statep, statep->scf_reg_drvtrc_handle,
				&statep->scf_reg_drvtrc->DATA_TOP,
				statep->memo_DATA_TOP);
			SCF_DDI_PUT32(statep, statep->scf_reg_drvtrc_handle,
				&statep->scf_reg_drvtrc->DATA_WRITE,
				statep->memo_DATA_WRITE);
			SCF_DDI_PUT32(statep, statep->scf_reg_drvtrc_handle,
				&statep->scf_reg_drvtrc->DATA_LAST,
				statep->memo_DATA_LAST);
		} else {
			statep->memo_DATA_TOP = SCF_DDI_GET32(statep,
				statep->scf_reg_drvtrc_handle,
				&statep->scf_reg_drvtrc->DATA_TOP);
			statep->memo_DATA_WRITE = SCF_DDI_GET32(statep,
				statep->scf_reg_drvtrc_handle,
				&statep->scf_reg_drvtrc->DATA_WRITE);
			statep->memo_DATA_LAST = SCF_DDI_GET32(statep,
				statep->scf_reg_drvtrc_handle,
				&statep->scf_reg_drvtrc->DATA_LAST);
		}

		wk_leng = sizeof (SCF_DRIVER_VERSION);
		if (wk_leng > DRV_ID_SIZE) {
			wk_leng = DRV_ID_SIZE;
		}
		wk_in_p = wk_drv_vl;
		wk_out_p = (uint8_t *)&drv_name[0];
		for (ii = 0; ii < wk_leng; ii++, wk_in_p++, wk_out_p++) {
			*wk_out_p = *wk_in_p;
		}
		for (; ii < DRV_ID_SIZE; ii++, wk_out_p++) {
			*wk_out_p = ' ';
		}
		wk_in_p = (uint8_t *)&drv_name[0];
		wk_out_p = (uint8_t *)&statep->scf_reg_drvtrc->DRV_ID[0];
		for (ii = 0; ii < DRV_ID_SIZE; ii++, wk_in_p++, wk_out_p++) {
			SCF_DDI_PUT8(statep, statep->scf_reg_drvtrc_handle,
				wk_out_p, *wk_in_p);
		}
	} else {
		statep->memo_DATA_TOP = 0;
		statep->memo_DATA_WRITE = 0;
		statep->memo_DATA_LAST = 0;
	}

	SCFDBGMSG(SCF_DBGFLAG_TRACE, SCF_FUNC_NAME ": end");
}


/*
 * scf_sram_trace()
 *
 * SRAM trace get processing.
 *
 */
void
scf_sram_trace(struct scf_state *statep, uint8_t log_id)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_sram_trace() "
	uint8_t			*wk_in_p;
	uint8_t			*wk_out_p;
	clock_t			clock_val;
	uint32_t		log_time;
	uint8_t			wk_log_id;
	int			ii;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_TRACE, SCF_FUNC_NAME ": start");

	if (statep->memo_DATA_WRITE) {
		statep->memo_scf_drvtrc.LOG_ID = log_id;
		clock_val = ddi_get_lbolt();
		log_time = (uint32_t)(drv_hztousec(clock_val) / 100000);
		statep->memo_scf_drvtrc.LOG_TIME[0] = (uint8_t)(log_time >> 16);
		statep->memo_scf_drvtrc.LOG_TIME[1] = (uint8_t)(log_time >> 8);
		statep->memo_scf_drvtrc.LOG_TIME[2] = (uint8_t)(log_time);

		if ((log_id & DTC_MASK_HIGH) == DTC_ERRRTN) {
			wk_log_id = DTC_ERRRTN;
		} else {
			wk_log_id = log_id;
		}

		/* Check log id */
		switch (wk_log_id) {
		case DTC_ONLINETO:		/* SCF online timeout */
		case DTC_ONLINE:		/* SCF online start */
		case DTC_OFFLINE:		/* SCF offline start */
			SCF_SET_SRAM_DATA2_2(0, statep->reg_control,
				statep->reg_int_st);
			SCF_SET_SRAM_DATA2_2(4, statep->reg_command,
				statep->reg_status);
			SCF_SET_SRAM_DATA4_1(8, statep->reg_status_exr);
			break;

		case DTC_SENDDATA:		/* SCF send command data */
			SCF_SET_SRAM_DATA4_3(0, statep->reg_tdata[0],
				statep->reg_tdata[2], statep->reg_tdata[3]);
			break;

		case DTC_RECVDATA:		/* SCF recv command data */
			SCF_SET_SRAM_DATA4_3(0, statep->reg_rdata[0],
				statep->reg_rdata[2], statep->reg_rdata[3]);
			break;

		case DTC_ERRRTN:		/* SCF command retuen error */
			SCF_SET_SRAM_DATA4_3(0, statep->reg_tdata[0],
				statep->reg_tdata[1], statep->reg_tdata[2]);
			break;


		case DTC_RSUMERR:	/* SCF command receive sum error */
			SCF_SET_SRAM_DATA4_3(0, statep->reg_rdata[0],
				statep->reg_rdata[1], statep->reg_rdata[2]);
			break;

		case DTC_DSCP_TXREQ:		/* DSCP TxREQ request */
			SCF_SET_SRAM_DATA2_2(0, statep->reg_control,
				statep->reg_int_st);
			SCF_SET_SRAM_DATA1_2(4, statep->reg_dcr,
				statep->reg_dsr);
			SCF_SET_SRAM_DATA2_1(6, statep->reg_txdcr_c_flag);
			SCF_SET_SRAM_DATA4_1(8, statep->reg_txdcr_c_length);
			break;

		case DTC_DSCP_RXACK:		/* DSCP RxACK request */
			SCF_SET_SRAM_DATA2_2(0, statep->reg_control,
				statep->reg_int_st);
			SCF_SET_SRAM_DATA1_2(4, statep->reg_dcr,
				statep->reg_dsr);
			SCF_SET_SRAM_DATA2_1(6, statep->reg_rxdcr_c_flag);
			SCF_SET_SRAM_DATA2_2(8, statep->reg_rxdcr_c_offset, 0);
			break;

		case DTC_DSCP_RXEND:		/* DSCP RxEND request */
			SCF_SET_SRAM_DATA2_2(0, statep->reg_control,
				statep->reg_int_st);
			SCF_SET_SRAM_DATA1_2(4, statep->reg_dcr,
				statep->reg_dsr);
			SCF_SET_SRAM_DATA2_1(6, statep->reg_rxdsr_c_flag);
			SCF_SET_SRAM_DATA2_2(8, statep->reg_rxdsr_c_offset, 0);
			break;

		case DTC_DSCP_RXREQ:
			SCF_SET_SRAM_DATA2_2(0, statep->reg_control,
				statep->reg_int_st);
			SCF_SET_SRAM_DATA1_2(4, statep->reg_dcr,
				statep->reg_dsr);
			SCF_SET_SRAM_DATA2_1(6, statep->reg_rxdcr_c_flag);
			SCF_SET_SRAM_DATA4_1(8, statep->reg_rxdcr_c_length);
			break;


		case DTC_DSCP_TXACK:		/* DSCP TxACK interrupt */
		case DTC_DSCP_ACKTO:		/* DSCP ACK timeout */
		case DTC_DSCP_ENDTO:		/* DSCP END timeout */
			SCF_SET_SRAM_DATA2_2(0, statep->reg_control,
				statep->reg_int_st);
			SCF_SET_SRAM_DATA1_2(4, statep->reg_dcr,
				statep->reg_dsr);
			SCF_SET_SRAM_DATA2_1(6, statep->reg_txdcr_c_flag);
			SCF_SET_SRAM_DATA2_2(8, statep->reg_txdcr_c_offset, 0);
			break;

		case DTC_DSCP_TXEND:		/* DSCP TxEND interrupt */
			SCF_SET_SRAM_DATA2_2(0, statep->reg_control,
				statep->reg_int_st);
			SCF_SET_SRAM_DATA1_2(4, statep->reg_dcr,
				statep->reg_dsr);
			SCF_SET_SRAM_DATA2_1(6, statep->reg_txdsr_c_flag);
			SCF_SET_SRAM_DATA2_2(8, statep->reg_txdsr_c_offset, 0);
			break;

		case DTC_SENDDATA_SRAM:	/* SCF send command data for SRAM */
		case DTC_RECVDATA_SRAM:	/* SCF recv command data for SRAM */
		case DTC_DSCP_SENDDATA:		/* DSCP send data */
		case DTC_DSCP_RECVDATA:		/* DSCP send data */
			/* Information is already set */
			break;

		case DTC_CMD:			/* SCF command start */
		case DTC_INT:			/* SCF interrupt */
		case DTC_CMDTO:			/* SCF command timeout */
		case DTC_CMDBUSYTO:		/* SCF command busy timeout */
		default:
			SCF_SET_SRAM_DATA2_2(0, statep->reg_control,
				statep->reg_int_st);
			SCF_SET_SRAM_DATA2_2(4, statep->reg_command,
				statep->reg_status);
			SCF_SET_SRAM_DATA1_2(8, statep->reg_command_exr,
				(statep->reg_status_exr >> 24));
			SCF_SET_SRAM_DATA1_2(10, statep->reg_acr,
				statep->reg_atr);
			break;
		}
		/* Set trace data */
		wk_in_p = (uint8_t *)&statep->memo_scf_drvtrc.LOG_ID;
		wk_out_p = (uint8_t *)statep->scf_reg_drvtrc +
			statep->memo_DATA_WRITE;
		for (ii = 0; ii < sizeof (scf_drvtrc_ent_t);
			ii++, wk_in_p++, wk_out_p++) {
			SCF_DDI_PUT8(statep, statep->scf_reg_drvtrc_handle,
				wk_out_p, *wk_in_p);
		}

		/* Next offset update */
		statep->memo_DATA_WRITE += sizeof (scf_drvtrc_ent_t);
		if (statep->memo_DATA_WRITE > statep->memo_DATA_LAST) {
			statep->memo_DATA_WRITE = statep->memo_DATA_TOP;
		}
		SCF_DDI_PUT32(statep, statep->scf_reg_drvtrc_handle,
			&statep->scf_reg_drvtrc->DATA_WRITE,
			statep->memo_DATA_WRITE);
	}

	SCFDBGMSG(SCF_DBGFLAG_TRACE, SCF_FUNC_NAME ": end");
}
