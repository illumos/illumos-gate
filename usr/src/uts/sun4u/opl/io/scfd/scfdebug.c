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

#include <sys/ksynch.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scfd/scfparam.h>
#include <sys/scfd/scfdscp.h>

#ifdef DEBUG
/*
 * Debug control value and flag
 */
uint_t	scf_debug_test_sys_int_flag = SCF_DBF_SYS_INTR_OFF;
uint_t	scf_debug_test_rxbuff_nosum_check_flag = SCF_DBF_RXBUFF_NOSUM_CHECK_OFF;
uint_t	scf_debug_test_sys_event_flag = SCF_DBF_SYS_EVENT_OFF;
uint_t	scf_debug_test_sys_poff_flag = SCF_DBF_SYS_POFF_OFF;
uint_t	scf_debug_test_dscp_int_flag = SCF_DBF_DSCP_INT_OFF;
uint_t	scf_debug_test_cmdr_busy = SCF_DBC_CMDR_BUSY_CLEAR;
uint_t	scf_debug_test_cmdexr_busy = SCF_DBC_CMDEXR_BUSY_CLEAR;
uint_t	scf_debug_test_path_check = SCF_DBC_PATH_CHECK_CLEAR;
uint_t	scf_debug_test_path_check_rtn = SCF_DBC_PATH_CHECK_RTN_CLEAR;
uint_t	scf_debug_test_offline_check = SCF_DBC_OFFLINE_CHECK_CLEAR;
uint_t	scf_debug_test_offline_check_rtn = SCF_DBC_OFFLINE_CHECK_RTN_CLEAR;
uint_t	scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_OFF;
uint_t	scf_debug_test_osescf_call_flag = SCF_DBF_OSESCF_CALL_OFF;

uint_t	scf_no_make_sum_s = SCF_DBF_NO_MAKE_SUM_S_OFF;
uint_t	scf_no_make_sum_l = SCF_DBF_NO_MAKE_SUM_L_OFF;

uint_t	scf_debug_nofirm_sys = SCF_DBF_NOFIRM_SYS_OFF;
uint_t	scf_debug_scfint_time = SCF_DBT_SCFINT_TIME_100MS;
uint_t	scf_debug_nofirm_dscp = SCF_DBF_NOFIRM_DSCP_OFF;
uint_t	scf_debug_idbcint_time = SCF_DBT_IDBCINT_TIME_100MS;
uint_t	scf_debug_test_dscp_loopback = SCF_DBF_DSCP_LOOPBACK_OFF;
uint_t	scf_debug_nooffline_check = SCF_DBF_NOOFFLINE_CHECK_OFF;
uint_t	scf_debug_no_dscp_path = SCF_DBF_NO_DSCP_PATH_OFF;
uint_t	scf_debug_no_alive = SCF_DBF_NO_ALIVE_OFF;
uint_t	scf_debug_norxsum_check = SCF_DBF_NORXSUM_CHECK_OFF;
uint_t	scf_debug_no_int_reason = SCF_DBF_NO_INT_REASON_OFF;

uint_t	scf_debug_no_device = SCF_DBF_NO_DEVICE_OFF;

scf_regs_t	*scf_debug_scf_regs;
scf_regs_c_t	*scf_debug_scf_regs_c;
scf_dscp_sram_t	*scf_debug_scf_dscp_sram;
scf_sys_sram_t	*scf_debug_scf_sys_sram;
scf_interface_t	*scf_debug_scf_interface;
scf_if_drvtrc_t	*scf_debug_scf_reg_drvtrc;

scf_regs_t	scf_debug_scf_regs_tbl;
scf_regs_c_t	scf_debug_scf_regs_c_tbl;
scf_dscp_sram_t	scf_debug_scf_dscp_sram_tbl;
scf_sys_sram_t	scf_debug_scf_sys_sram_tbl;
scf_interface_t	scf_debug_scf_interface_tbl;
struct {
	uint8_t		data[0x00001000];

} scf_debug_scf_reg_drvtrc_tbl;

struct {
	uint16_t	STATUS;
	uint16_t	INT_ST;
	uint32_t	STATUS_ExR;
	uint32_t	rxsize;
	uint32_t	RDATA0;
	uint32_t	RDATA1;
	uint32_t	RDATA2;
	uint32_t	RDATA3;
	uint32_t	POFF_FACTOR;
	uint32_t	EVENT[8 * 4];
} scf_debug_test_sys_int_tbl;

struct {
	uint8_t		DSR;
	uint8_t		rev01;
	uint16_t	TxDSR_C_FLAG;
	uint16_t	TxDSR_OFFSET;
	uint32_t	rxsize;
	uint16_t	RxDCR_C_FLAG;
	uint16_t	RxDCR_OFFSET;
	uint32_t	RxDCR_LENGTH;
	uint32_t	rsv14;
	uint32_t	rsv18;
} scf_debug_test_dscp_int_tbl;

uint32_t	scf_debug_rdata[4] = {0, 0, 0, 0};

timeout_id_t	scf_debug_test_intr_id = 0;
timeout_id_t	scf_debug_test_alive_id = 0;
uint_t		scf_debug_test_alive_flag = FLAG_OFF;

/*
 * Function list
 */
int	scf_debug_cmdthrough(intptr_t arg, int mode);
int	scf_debug_test(intptr_t arg, int mode);
void	scf_debug_test_intr_tout(void *arg);
void	scf_debug_test_intr(scf_state_t *statep);
void	scf_debug_test_intr_scfint(scf_state_t *statep);
void	scf_debug_test_intr_cmdend(scf_state_t *statep);
void	scf_debug_test_intr_poff(void);
void	scf_debug_test_dsens(struct scf_cmd *scfcmdp, scf_int_reason_t *int_rp,
	int len);
void	scf_debug_test_intr_dscp_dsr(scf_state_t *statep);
void	scf_debug_test_intr_dscp_rxtx(scf_state_t *statep, uint8_t dsr);
void	scf_debug_test_alive_start(scf_state_t *statep);
void	scf_debug_test_alive_stop(scf_state_t *statep);
void	scf_debug_test_alive_intr_tout(void *arg);
void	scf_debug_test_send_cmd(struct scf_state *statep,
	struct scf_cmd *scfcmdp);
void	scf_debug_test_txreq_send(scf_state_t *statep, scf_dscp_dsc_t *dsc_p);
void	scf_debug_test_event_handler(scf_event_t mevent, void *arg);
void	scf_debug_test_timer_stop(void);
void	scf_debug_test_map_regs(scf_state_t *statep);
void	scf_debug_test_unmap_regs(scf_state_t *statep);

/*
 * External function
 */
extern int	scf_dscp_init(void);
extern void	scf_dscp_fini(void);
extern void	scf_dscp_start(uint32_t factor);
extern void	scf_dscp_stop(uint32_t factor);
extern int	scf_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
extern int	scf_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

extern int	scf_fmem_start(int s_bd, int t_bd);
extern int	scf_fmem_end(void);
extern int	scf_fmem_cancel(void);

int
scf_debug_cmdthrough(intptr_t arg, int mode)
{
#define	SCF_FUNC_NAME		"scf_debug_cmdthrough() "
	int			ret = 0;
	scfcmdthrough_t		*scfcmdthrough_p = NULL;
	struct scf_cmd		scf_cmd;

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	scfcmdthrough_p =
		kmem_zalloc((size_t)(sizeof (scfcmdthrough_t)),
		KM_SLEEP);
	if (ddi_copyin((void *)arg, (void *)scfcmdthrough_p,
		sizeof (scfcmdthrough_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "dbg_cmdt", 8);
		ret = EFAULT;
		goto END_cmdthrough;
	}

	mutex_enter(&scf_comtbl.all_mutex);

	switch (scfcmdthrough_p->mode) {
	case SCF_CMDTHROUGH_START:
		scf_comtbl.debugxscf_flag = 1;

		mutex_exit(&scf_comtbl.all_mutex);
		break;

	case SCF_CMDTHROUGH_STOP:
		scf_comtbl.debugxscf_flag = 0;

		mutex_exit(&scf_comtbl.all_mutex);
		break;

	case SCF_CMDTHROUGH_CMD:
		if (!scf_comtbl.debugxscf_flag) {
			SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "dbg_cmdt", 8);
			mutex_exit(&scf_comtbl.all_mutex);
			ret = EINVAL;
			goto END_cmdthrough;
		}
		scf_cmd.cmd = (unsigned char)scfcmdthrough_p->code;
		scf_cmd.subcmd = (unsigned char)(scfcmdthrough_p->code >> 8);

		switch (scfcmdthrough_p->cmdtype) {
		case SCF_CMDTHROUGH_TYPE_NN:
		case SCF_CMDTHROUGH_TYPE_NS:
		case SCF_CMDTHROUGH_TYPE_NL:
			scf_cmd.scount = 0;
			break;

		case SCF_CMDTHROUGH_TYPE_SN:
		case SCF_CMDTHROUGH_TYPE_SS:
		case SCF_CMDTHROUGH_TYPE_SL:
			if (scfcmdthrough_p->sbufleng > SCF_S_CNT_16) {
				SC_DBG_DRV_TRACE(TC_ERR, __LINE__,
					"dbg_cmdt", 8);
				mutex_exit(&scf_comtbl.all_mutex);
				ret = EINVAL;
				goto END_cmdthrough;
			}
			scf_cmd.scount = scfcmdthrough_p->sbufleng;
			break;

		case SCF_CMDTHROUGH_TYPE_LN:
		case SCF_CMDTHROUGH_TYPE_LS:
			if (scfcmdthrough_p->sbufleng > SCF_L_CNT_MAX) {
				SC_DBG_DRV_TRACE(TC_ERR, __LINE__,
					"dbg_cmdt", 8);
				mutex_exit(&scf_comtbl.all_mutex);
				ret = EINVAL;
				goto END_cmdthrough;
			}
			scf_cmd.scount = scfcmdthrough_p->sbufleng;
			break;

		default:
			SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "dbg_cmdt", 8);
			mutex_exit(&scf_comtbl.all_mutex);
			ret = EINVAL;
			goto END_cmdthrough;
		}

		switch (scfcmdthrough_p->cmdtype) {
		case SCF_CMDTHROUGH_TYPE_NN:
		case SCF_CMDTHROUGH_TYPE_SN:
			scf_cmd.flag = SCF_USE_S_BUF;
			break;

		case SCF_CMDTHROUGH_TYPE_NS:
		case SCF_CMDTHROUGH_TYPE_SS:
			scf_cmd.flag = SCF_USE_SSBUF;
			break;

		case SCF_CMDTHROUGH_TYPE_NL:
		case SCF_CMDTHROUGH_TYPE_SL:
			scf_cmd.flag = SCF_USE_SLBUF;
			break;

		case SCF_CMDTHROUGH_TYPE_LN:
			scf_cmd.flag = SCF_USE_L_BUF;
			break;

		case SCF_CMDTHROUGH_TYPE_LS:
			scf_cmd.flag = SCF_USE_LSBUF;
			break;
		}
		scf_cmd.sbuf = &scfcmdthrough_p->sbuf[0];
		scf_cmd.scount = scfcmdthrough_p->sbufleng;
		scf_cmd.rbuf = &scfcmdthrough_p->rbuf[0];
		scf_cmd.rcount = SCF_L_CNT_MAX;
		scf_cmd.rbufleng = 0;
		scf_cmd.status = 0;

		ret = scf_send_cmd_check_bufful(&scf_cmd);

		scfcmdthrough_p->rbufleng = scf_cmd.rbufleng;
		scfcmdthrough_p->status = scf_cmd.status;

		mutex_exit(&scf_comtbl.all_mutex);

		if (ret != 0) {
			SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "dbg_cmdt", 8);
			goto END_cmdthrough;
		}
		if (ddi_copyout((void *)scfcmdthrough_p, (void *)arg,
			sizeof (scfcmdthrough_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "dbg_cmdt", 8);
			ret = EFAULT;
		}
		break;

	default:
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "dbg_cmdt", 8);
		mutex_exit(&scf_comtbl.all_mutex);
		ret = EINVAL;
	}

/*
 * END_cmdthrough
 */
	END_cmdthrough:

	if (scfcmdthrough_p) {
		kmem_free((void *)scfcmdthrough_p,
			(size_t)(sizeof (scfcmdthrough_t)));
	}
	SCFDBGMSG1(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


int
scf_debug_test(intptr_t arg, int mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test() "
	scf_state_t		*statep;
	int			func_ret = 0;
	int			ret = 0;

	scf_scfioctest_t	*test_p = NULL;
	caddr_t			data_addr = NULL;
	caddr_t			msc_dptr = NULL;
	uint32_t		msc_len;
	uint8_t			*wk_out_p;
	int			ii;
	int			jj;

	target_id_t		target_id;
	mkey_t			mkey;
	uint_t			func_arg;
	uint32_t		data_len;
	uint32_t		num_sg;
	mscat_gath_t		*sgp = NULL;
	mflush_type_t		flush_type;
	uint32_t		op;

	uint32_t		key;
	uint8_t			type;
	uint32_t		transid;
	uint32_t		length;
	uint16_t		offset_low;
	uint16_t		offset_hight;
	int			kmem_size = 0;
	int			kmem_size2 = 0;
	timeout_id_t		save_tmids[SCF_TIMERCD_MAX];
	int			tm_stop_cnt;

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	test_p = kmem_zalloc((size_t)(sizeof (scf_scfioctest_t)), KM_SLEEP);
	if (ddi_copyin((void *)arg, (void *)test_p,
		sizeof (scf_scfioctest_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "ioctl   ", 8);
		ret = EFAULT;
		goto END_test;
	}

	mutex_enter(&scf_comtbl.all_mutex);

	if (scf_comtbl.scf_exec_p != NULL) {
		statep = scf_comtbl.scf_exec_p;
	} else if (scf_comtbl.scf_path_p != NULL) {
		statep = scf_comtbl.scf_path_p;
	} else if (scf_comtbl.scf_wait_p != NULL) {
		statep = scf_comtbl.scf_wait_p;
	} else if (scf_comtbl.scf_err_p != NULL) {
		statep = scf_comtbl.scf_err_p;
	}

	test_p->scf_debugxscf = scf_comtbl.debugxscf_flag;

	switch (test_p->mode & TEST_MODE_MASK_LOW) {
	case TEST_NONE:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_NONE");
		break;

	case TEST_CONF_RESET:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_CONF_RESET");

		/* Not use info */
		scf_debug_test_sys_int_flag = SCF_DBF_SYS_INTR_OFF;
		scf_debug_test_rxbuff_nosum_check_flag =
			SCF_DBF_RXBUFF_NOSUM_CHECK_OFF;
		scf_debug_test_dscp_int_flag = SCF_DBF_DSCP_INT_OFF;
		scf_debug_test_cmdr_busy = SCF_DBC_CMDR_BUSY_CLEAR;
		scf_debug_test_cmdexr_busy = SCF_DBC_CMDEXR_BUSY_CLEAR;
		scf_debug_test_path_check = SCF_DBC_PATH_CHECK_CLEAR;
		scf_debug_test_path_check_rtn = SCF_DBC_PATH_CHECK_RTN_CLEAR;
		scf_debug_test_offline_check = SCF_DBC_OFFLINE_CHECK_CLEAR;
		scf_debug_test_offline_check_rtn =
			SCF_DBC_OFFLINE_CHECK_RTN_CLEAR;
		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_OFF;
		scf_debug_test_osescf_call_flag = SCF_DBF_OSESCF_CALL_OFF;
		break;

	case TEST_CONF_DEBUG_MSG:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_CONF_DEBUG_MSG");

		/*
		 * IN:
		 *	info[0] : trace massege flag
		 */
		scf_trace_msg_flag = test_p->info[0];
		break;

	case TEST_CONF_CMD_BUSY:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_CONF_CMD_BUSY");

		/*
		 * IN:
		 *	info[0] : command busy count
		 *	info[1] : command ex busy count
		 */
		scf_debug_test_cmdr_busy = test_p->info[0];
		scf_debug_test_cmdexr_busy = test_p->info[1];
		break;

	case TEST_CONF_SCF_PATH:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_CONF_SCF_PATH");

		/*
		 * IN:
		 *	info[0] : scf_path_check count
		 *	info[1] : scf_path_check return
		 *	info[2] : scf_offline_check count
		 *	info[3] : scf_offline_check return
		 */
		scf_debug_test_path_check = test_p->info[0];
		scf_debug_test_path_check_rtn = test_p->info[1];
		scf_debug_test_offline_check = test_p->info[2];
		scf_debug_test_offline_check_rtn = test_p->info[3];
		break;

	case TEST_CONF_DSCP_LOOPBACK:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_CONF_DSCP_LOOPBACK");

		/*
		 * IN:
		 *	info[0] : loopback mode
		 */
		scf_debug_test_dscp_loopback =
			(test_p->info[0]) ?
			SCF_DBF_DSCP_LOOPBACK_ON : SCF_DBF_DSCP_LOOPBACK_OFF;
		break;

	case TEST_INT_SYS:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_INT_SYS");

		/*
		 * IN:
		 *	info[0] : STR/ISR register
		 *	info[1] : STExR register
		 *	info[2] : receive data size
		 *	info[3] : RxDR register 0
		 *	info[4] : RxDR register 1
		 *	info[5] : RxDR register 2
		 *	info[6] : RxDR register 3
		 */
		if (scf_debug_scfint_time != 0) {
			if (scf_debug_test_sys_int_flag ==
				SCF_DBF_SYS_INTR_OFF) {
				if (statep != NULL) {
					scf_debug_test_sys_int_flag =
						SCF_DBF_SYS_INTR_ON;

					scf_debug_test_sys_int_tbl.STATUS =
						(uint16_t)
						(test_p->info[0] >> 16);
					scf_debug_test_sys_int_tbl.INT_ST |=
						(uint16_t)test_p->info[0];
					scf_debug_test_sys_int_tbl.STATUS_ExR =
						test_p->info[1];
					scf_debug_test_sys_int_tbl.rxsize =
						test_p->info[2];
					scf_debug_test_sys_int_tbl.RDATA0 =
						test_p->info[3];
					scf_debug_test_sys_int_tbl.RDATA1 =
						test_p->info[4];
					scf_debug_test_sys_int_tbl.RDATA2 =
						test_p->info[5];
					scf_debug_test_sys_int_tbl.RDATA3 =
						test_p->info[6];

					if (scf_debug_test_intr_id == 0) {
		scf_debug_test_intr_id =
			timeout((void (*)())scf_debug_test_intr_tout,
			(void *)statep,
			drv_usectohz(SCF_MIL2MICRO(scf_debug_scfint_time)));
					}
				} else {
					SC_DBG_DRV_TRACE(TC_ERR, __LINE__,
						"dbg_test", 8);
					ret = EIO;
				}
			} else {
				SC_DBG_DRV_TRACE(TC_ERR, __LINE__,
					"dbg_test", 8);
				ret = EBUSY;
			}
		}
		break;

	case TEST_INT_SYS_POFF:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_INT_SYS_POFF");

		/*
		 * IN:
		 *	info[0] : POFF factor
		 */
		if (scf_debug_test_sys_poff_flag == SCF_DBF_SYS_POFF_OFF) {
			if (statep != NULL) {
				scf_debug_test_sys_poff_flag =
					SCF_DBF_SYS_POFF_ON;

				scf_debug_test_sys_int_tbl.POFF_FACTOR =
					test_p->info[0];
			} else {
				SC_DBG_DRV_TRACE(TC_ERR, __LINE__,
					"dbg_test", 8);
				ret = EIO;
			}
		} else {
			SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "dbg_test", 8);
			ret = EBUSY;
		}
		break;

	case TEST_INT_SYS_EVENT:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_INT_SYS_EVENT");

		/*
		 * IN:
		 *	info[0]  - info[7]  : Event 0
		 *	info[8]  - info[15] : Event 1
		 *	info[16] - info[23] : Event 2
		 *	info[24] - info[31] : Event 3
		 */
		if (scf_debug_test_sys_event_flag == FLAG_OFF) {
			if (statep != NULL) {
				scf_debug_test_sys_event_flag =
					SCF_DBF_SYS_EVENT_ON;

				for (ii = 0; ii < TEST_INFO_MAX; ii++) {
					scf_debug_test_sys_int_tbl.EVENT[ii] =
						test_p->info[ii];
				}
			} else {
				SC_DBG_DRV_TRACE(TC_ERR, __LINE__,
					"dbg_test", 8);
				ret = EIO;
			}
		} else {
			SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "dbg_test", 8);
			ret = EBUSY;
		}
		break;

	case TEST_INT_DSCP:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_INT_DSCP");

		/*
		 * IN:
		 *	info[0] : DSR/ISR register
		 *	info[1] : TxDSR_C_FLAG/TxDSR_OFFSET register
		 *	info[2] : RxDCR_C_FLAG/RxDCR_OFFSET register
		 *	info[3] : RxDCR_LENGTH register
		 */
		if (scf_debug_idbcint_time != 0) {
			if (scf_debug_test_dscp_int_flag ==
				SCF_DBF_DSCP_INT_OFF) {
				if (statep != NULL) {
	scf_debug_test_dscp_int_flag = SCF_DBF_DSCP_INT_ON;
	scf_debug_test_sys_int_flag = SCF_DBF_SYS_INTR_ON;

	scf_debug_test_dscp_int_tbl.DSR = (uint8_t)(test_p->info[0] >> 16);
	scf_debug_test_sys_int_tbl.INT_ST |= (uint16_t)test_p->info[0];
	scf_debug_test_dscp_int_tbl.TxDSR_C_FLAG =
		(uint16_t)(test_p->info[1] >> 16);
	scf_debug_test_dscp_int_tbl.TxDSR_OFFSET =
		(uint16_t)test_p->info[1];
	scf_debug_test_dscp_int_tbl.RxDCR_C_FLAG =
		(uint16_t)(test_p->info[2] >> 16);

	offset_low = SCF_TXBUFFSIZE * SCF_TX_SRAM_MAXCOUNT / DSC_OFFSET_CONVERT;
	offset_hight = offset_low +
		SCF_RXBUFFSIZE * SCF_RX_SRAM_MAXCOUNT / DSC_OFFSET_CONVERT;
	if ((test_p->info[2] >= offset_low) &&
		(test_p->info[2] < offset_hight)) {
		scf_debug_test_dscp_int_tbl.RxDCR_OFFSET =
			(uint16_t)test_p->info[2];
	} else {
		scf_debug_test_dscp_int_tbl.RxDCR_OFFSET = offset_low;
	}
	scf_debug_test_dscp_int_tbl.RxDCR_LENGTH = test_p->info[3];

	if ((scf_debug_test_dscp_int_tbl.RxDCR_OFFSET >= offset_low) &&
		(scf_debug_test_dscp_int_tbl.RxDCR_LENGTH != 0)) {
		/* Data copy to SRAM */
		ii = scf_debug_test_dscp_int_tbl.RxDCR_OFFSET *
			DSC_OFFSET_CONVERT;
		wk_out_p =
			(uint8_t *)&statep->scf_dscp_sram->DATA[ii];
		for (ii = 0; ii < scf_debug_test_dscp_int_tbl.RxDCR_LENGTH;
			ii++, wk_out_p++) {
			SCF_DDI_PUT8(statep, statep->scf_dscp_sram_handle,
				wk_out_p, (uint8_t)ii);
		}
	}

	if (scf_debug_test_intr_id == 0) {
		scf_debug_test_intr_id =
			timeout((void (*)())scf_debug_test_intr_tout,
			(void *)statep,
			drv_usectohz(SCF_MIL2MICRO(scf_debug_idbcint_time)));
	}
				} else {
					SC_DBG_DRV_TRACE(TC_ERR, __LINE__,
						"dbg_test", 8);
					ret = EIO;
				}
			} else {
				SC_DBG_DRV_TRACE(TC_ERR, __LINE__,
					"dbg_test", 8);
				ret = EBUSY;
			}
		}
		break;

	case TEST_SYS_CALL_INT:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_SYS_CALL_INT");

		/* Not use info */
		if (scf_debug_scfint_time != 0) {
			if (statep != NULL) {
				if (scf_debug_test_intr_id == 0) {
		scf_debug_test_intr_id =
			timeout((void (*)())scf_debug_test_intr_tout,
			(void *)statep,
			drv_usectohz(SCF_MIL2MICRO(scf_debug_scfint_time)));
				}
			} else {
				SC_DBG_DRV_TRACE(TC_ERR, __LINE__,
					"dbg_test", 8);
				ret = EIO;
			}
		}
		break;

	case TEST_DSCP_CALL_RESET:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_DSCP_CALL_RESET");

		/* Not use info */

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_OFF;
		break;


	case TEST_DSCP_CALL_INIT:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_DSCP_CALL_INIT");

		/*
		 * IN:
		 *	info[0] : target_id
		 *	info[1] : mkey
		 */
		target_id = (target_id_t)test_p->info[0];
		mkey = (mkey_t)test_p->info[1];

		/*
		 * scf_mb_init(target_id_t target_id, mkey_t mkey,
		 * void (*event_handler) (scf_event_t mevent, void *arg),
		 * void *arg);
		 */

		func_arg = 0x01020304;

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_ON;

		mutex_exit(&scf_comtbl.all_mutex);
		if (test_p->data[0] == 1) {
			func_ret = scf_mb_init(target_id, mkey, NULL,
				(void *)&func_arg);
		} else {
			func_ret = scf_mb_init(target_id, mkey,
				scf_debug_test_event_handler,
				(void *)&func_arg);
		}
		mutex_enter(&scf_comtbl.all_mutex);

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_OFF;
		break;

	case TEST_DSCP_CALL_FINI:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_DSCP_CALL_FINI");

		/*
		 * IN:
		 *	info[0] : target_id
		 *	info[1] : mkey
		 */
		target_id = (target_id_t)test_p->info[0];
		mkey = (mkey_t)test_p->info[1];

		/* scf_mb_fini(target_id_t target_id, mkey_t mkey); */

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_ON;

		mutex_exit(&scf_comtbl.all_mutex);
		func_ret = scf_mb_fini(target_id, mkey);
		mutex_enter(&scf_comtbl.all_mutex);

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_OFF;
		break;

	case TEST_DSCP_CALL_PUTMSG:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_DSCP_CALL_PUTMSG");

		/*
		 * IN:
		 *	info[0] : target_id
		 *	info[1] : mkey
		 *	info[2] : data_len
		 *	info[3] : num_sg
		 */
		target_id = (target_id_t)test_p->info[0];
		mkey = (mkey_t)test_p->info[1];
		data_len = (uint32_t)test_p->info[2];
		num_sg = (uint32_t)test_p->info[3];

		/*
		 * scf_mb_putmsg(target_id_t target_id, mkey_t mkey,
		 * uint32_t data_len, uint32_t num_sg, mscat_gath_t *sgp,
		 * clock_t timeout);
		 */


		if (data_len != 0) {
			kmem_size = data_len;
			data_addr = (caddr_t)kmem_zalloc(kmem_size, KM_SLEEP);
		}
		if (num_sg != 0) {
			kmem_size2 = sizeof (mscat_gath_t) * num_sg;
			sgp = (mscat_gath_t *)kmem_zalloc(kmem_size2, KM_SLEEP);
		}

		msc_dptr = data_addr;
		msc_len = data_len;
		for (ii = 0; ii < num_sg; ii++) {
			if (msc_len != 0) {
				sgp[ii].msc_dptr = msc_dptr;
				if ((msc_len < 0x00000010) ||
					(ii == (num_sg - 1))) {
					sgp[ii].msc_len = msc_len;
				} else {
					sgp[ii].msc_len = 0x00000010;
				}
				msc_len -= sgp[ii].msc_len;
				for (jj = 0; jj < sgp[ii].msc_len; jj++,
					msc_dptr++) {
					*msc_dptr = jj;
				}
			} else {
				sgp[ii].msc_dptr = NULL;
				sgp[ii].msc_len = 0;
			}
		}

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_ON;

		mutex_exit(&scf_comtbl.all_mutex);
		if (test_p->data[0] == 1) {
			func_ret = scf_mb_putmsg(target_id, mkey, data_len,
				num_sg, NULL, 0);
		} else if (test_p->data[0] == 2) {
			sgp->msc_len = 0x00000010;
			sgp->msc_dptr = NULL;
			func_ret = scf_mb_putmsg(target_id, mkey, data_len,
				num_sg, sgp, 0);
		} else if (test_p->data[0] == 3) {
			sgp->msc_len += 1;
			func_ret = scf_mb_putmsg(target_id, mkey, data_len,
				num_sg, sgp, 0);
		} else {
			func_ret = scf_mb_putmsg(target_id, mkey, data_len,
				num_sg, sgp, 0);
		}
		mutex_enter(&scf_comtbl.all_mutex);

		if (data_len != 0)
			bcopy((void *)data_addr, (void *)&test_p->rdata[0],
				data_len);

		if (data_addr != NULL) kmem_free(data_addr, kmem_size);
		if (sgp != NULL) kmem_free(sgp, kmem_size2);

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_OFF;
		break;

	case TEST_DSCP_CALL_CANGET:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_DSCP_CALL_CANGET");

		/*
		 * IN:
		 *	info[0] : target_id
		 *	info[1] : mkey
		 * OUT:
		 *	info[2] : data_len
		 */
		target_id = (target_id_t)test_p->info[0];
		mkey = (mkey_t)test_p->info[1];
		data_len = 0xffffffff;

		/*
		 * scf_mb_canget(target_id_t target_id, mkey_t mkey,
		 * uint32_t *data_lenp);
		 */

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_ON;

		mutex_exit(&scf_comtbl.all_mutex);
		if (test_p->data[0] == 1) {
			func_ret = scf_mb_canget(target_id, mkey, NULL);
		} else {
			func_ret = scf_mb_canget(target_id, mkey,
				(uint32_t *)&data_len);
		}
		mutex_enter(&scf_comtbl.all_mutex);

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_OFF;

		test_p->info[2] = (uint_t)data_len;

		break;

	case TEST_DSCP_CALL_GETMSG:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_DSCP_CALL_GETMSG");

		/*
		 * IN:
		 *	info[0] : target_id
		 *	info[1] : mkey
		 *	info[2] : data_len
		 *	info[3] : num_sg
		 */
		target_id = (target_id_t)test_p->info[0];
		mkey = (mkey_t)test_p->info[1];
		data_len = (uint32_t)test_p->info[2];
		num_sg = (uint32_t)test_p->info[3];

		/*
		 * scf_mb_getmsg(target_id_t target_id, mkey_t mkey,
		 * uint32_t data_len, uint32_t num_sg, mscat_gath_t *sgp,
		 * clock_t timeout);
		 */

		if (data_len != 0) {
			kmem_size = data_len;
			data_addr = (caddr_t)kmem_zalloc(kmem_size, KM_SLEEP);
		}
		if (num_sg != 0) {
			kmem_size2 = sizeof (mscat_gath_t) * num_sg;
			sgp = (mscat_gath_t *)kmem_zalloc(kmem_size2, KM_SLEEP);
		}

		msc_dptr = data_addr;
		msc_len = data_len;
		for (ii = 0; ii < num_sg; ii++) {
			if (msc_len != 0) {
				sgp[ii].msc_dptr = msc_dptr;
				if ((msc_len < 0x00000010) ||
					(ii == (num_sg - 1))) {
					sgp[ii].msc_len = msc_len;
				} else {
					sgp[ii].msc_len = 0x00000010;
				}
				msc_len -= sgp[ii].msc_len;
				for (jj = 0; jj < sgp[ii].msc_len; jj++,
					msc_dptr++) {
					*msc_dptr = jj;
				}
			} else {
				sgp[ii].msc_dptr = NULL;
				sgp[ii].msc_len = 0;
			}
		}

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_ON;

		mutex_exit(&scf_comtbl.all_mutex);
		if (test_p->data[0] == 1) {
			func_ret = scf_mb_getmsg(target_id, mkey, data_len,
				num_sg, NULL, 0);
		} else if (test_p->data[0] == 2) {
			sgp->msc_len = 0x00000010;
			sgp->msc_dptr = NULL;
			func_ret = scf_mb_getmsg(target_id, mkey, data_len,
				num_sg, sgp, 0);
		} else if (test_p->data[0] == 3) {
			sgp->msc_len += 1;
			func_ret = scf_mb_getmsg(target_id, mkey, data_len,
				num_sg, sgp, 0);
		} else {
			func_ret = scf_mb_getmsg(target_id, mkey, data_len,
				num_sg, sgp, 0);
		}
		mutex_enter(&scf_comtbl.all_mutex);

		if (data_len != 0)
			bcopy((void *)data_addr, (void *)&test_p->rdata[0],
				data_len);

		if (data_addr != NULL) kmem_free(data_addr, kmem_size);
		if (sgp != NULL) kmem_free(sgp, kmem_size2);

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_OFF;
		break;

	case TEST_DSCP_CALL_FLUSH:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_DSCP_CALL_FLUSH");

		/*
		 * IN:
		 *	info[0] : target_id
		 *	info[1] : mkey
		 *	info[2] : flush_type
		 */
		target_id = (target_id_t)test_p->info[0];
		mkey = (mkey_t)test_p->info[1];
		flush_type = (mflush_type_t)test_p->info[2];

		/*
		 * scf_mb_flush(target_id_t target_id, mkey_t mkey,
		 * mflush_type_t flush_type);
		 */

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_ON;

		mutex_exit(&scf_comtbl.all_mutex);
		func_ret = scf_mb_flush(target_id, mkey, flush_type);
		mutex_enter(&scf_comtbl.all_mutex);

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_OFF;
		break;

	case TEST_DSCP_CALL_CTRL:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_DSCP_CALL_CTRL");

		/*
		 * IN:
		 *	info[0] : target_id
		 *	info[1] : mkey
		 *	info[2] : op
		 * OUT:
		 *	info[3] : arg
		 */
		target_id = (target_id_t)test_p->info[0];
		mkey = (mkey_t)test_p->info[1];
		op = test_p->info[2];

		/*
		 * scf_mb_ctrl(target_id_t target_id, mkey_t mkey,
		 *	uint32_t op, void *arg);
		 */

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_ON;

		mutex_exit(&scf_comtbl.all_mutex);
		if (test_p->data[0] == 1) {
			func_ret = scf_mb_ctrl(target_id, mkey, op, NULL);
		} else {
			func_ret = scf_mb_ctrl(target_id, mkey, op,
				(void *)&func_arg);
		}
		mutex_enter(&scf_comtbl.all_mutex);

		scf_debug_test_dscp_call_flag = SCF_DBF_DSCP_CALL_OFF;

		test_p->info[3] = (uint_t)func_arg;

		break;

	case TEST_DSCP_CALL_OTHER:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_DSCP_CALL_OTHER");

		/*
		 * IN:
		 *	info[0] : function code
		 *	info[1] : factor
		 * OUT:
		 *	info[3] : return code
		 */
		switch (test_p->info[0]) {
		case 0x00000001:
			test_p->info[3] = scf_dscp_init();
			break;

		case 0x00000002:
			scf_dscp_fini();
			break;

		case 0x00000003:
			scf_dscp_start(test_p->info[1]);
			break;

		case 0x00000004:
			scf_dscp_stop(test_p->info[1]);
			break;

		case 0x00000101:
			if (test_p->info[1] == 0xffffffff) {
				for (ii = 0; ii < SCF_TIMERCD_MAX; ii++) {
					scf_timer_start(ii);
				}
			} else {
				scf_timer_start(test_p->info[1]);
			}
			break;

		case 0x00000102:
			if (test_p->info[1] == 0xffffffff) {
				scf_timer_all_stop();
			} else {
				scf_timer_stop(test_p->info[1]);
			}
			break;

		case 0x00000103:
			func_ret = scf_timer_check(test_p->info[1]);
			break;

		case 0x00000104:
			func_ret = scf_timer_value_get(test_p->info[1]);
			break;

		case 0x00000200:
			if (statep != NULL) {
				SCF_SRAM_TRACE(statep, DTC_ONLINETO);
				SCF_SRAM_TRACE(statep, DTC_ONLINE);
				SCF_SRAM_TRACE(statep, DTC_OFFLINE);

				SCF_SRAM_TRACE(statep, DTC_SENDDATA);

				SCF_SRAM_TRACE(statep, DTC_RECVDATA);

				SCF_SRAM_TRACE(statep, DTC_ERRRTN);
				SCF_SRAM_TRACE(statep, DTC_RCI_BUF_FUL);
				SCF_SRAM_TRACE(statep, DTC_RCI_BUSY);
				SCF_SRAM_TRACE(statep, DTC_INTERFACE);
				SCF_SRAM_TRACE(statep, DTC_E_NOT_SUPPORT);
				SCF_SRAM_TRACE(statep, DTC_E_PARAM);
				SCF_SRAM_TRACE(statep, DTC_E_SCFC_PATH);
				SCF_SRAM_TRACE(statep, DTC_E_RCI_ACCESS);
				SCF_SRAM_TRACE(statep, DTC_E_SEQUENCE);

				SCF_SRAM_TRACE(statep, DTC_RSUMERR);

				SCF_SRAM_TRACE(statep, DTC_DSCP_TXREQ);

				SCF_SRAM_TRACE(statep, DTC_DSCP_RXACK);

				SCF_SRAM_TRACE(statep, DTC_DSCP_RXEND);

				SCF_SRAM_TRACE(statep, DTC_DSCP_RXREQ);

				SCF_SRAM_TRACE(statep, DTC_DSCP_TXACK);
				SCF_SRAM_TRACE(statep, DTC_DSCP_ACKTO);
				SCF_SRAM_TRACE(statep, DTC_DSCP_ENDTO);

				SCF_SRAM_TRACE(statep, DTC_DSCP_TXEND);

				SCF_SRAM_TRACE(statep, DTC_SENDDATA_SRAM);
				SCF_SRAM_TRACE(statep, DTC_RECVDATA_SRAM);
				SCF_SRAM_TRACE(statep, DTC_DSCP_SENDDATA);
				SCF_SRAM_TRACE(statep, DTC_DSCP_RECVDATA);

				SCF_SRAM_TRACE(statep, DTC_CMD);
				SCF_SRAM_TRACE(statep, DTC_INT);
				SCF_SRAM_TRACE(statep, DTC_CMDTO);
				SCF_SRAM_TRACE(statep, DTC_CMDBUSYTO);
				SCF_SRAM_TRACE(statep, 0x99);
			}
			break;

		case 0x00010000:
			if (statep != NULL) {
				mutex_exit(&scf_comtbl.all_mutex);
				func_ret = scf_detach(statep->dip, DDI_SUSPEND);
				func_ret =
					scf_detach(scf_comtbl.scf_pseudo_p->dip,
					DDI_SUSPEND);

				drv_usecwait(5000000);

				func_ret =
					scf_attach(scf_comtbl.scf_pseudo_p->dip,
					DDI_RESUME);
				func_ret = scf_attach(statep->dip, DDI_RESUME);
				mutex_enter(&scf_comtbl.all_mutex);
			}
			break;

		case 0x00019990:
		case 0x00019991:
			mutex_exit(&scf_comtbl.all_mutex);
			mutex_enter(&scf_comtbl.si_mutex);
			if (test_p->info[0] & 0x00000001) {
				scf_comtbl.scf_softintr_dscp_kicked = FLAG_ON;
			} else {
				scf_comtbl.scf_softintr_dscp_kicked = FLAG_OFF;
			}
			mutex_exit(&scf_comtbl.si_mutex);
			scf_softintr(NULL);
			mutex_enter(&scf_comtbl.all_mutex);
			break;

		case 0x00019998:
			mutex_exit(&scf_comtbl.all_mutex);
			scf_panic_callb(1);
			mutex_enter(&scf_comtbl.all_mutex);
			break;

		case 0x00019999:
			mutex_exit(&scf_comtbl.all_mutex);
			scf_shutdown_callb(1);
			mutex_enter(&scf_comtbl.all_mutex);
			break;

		case 0x00020000:
			func_ret = scf_offline_check(statep, FLAG_OFF);
			func_ret = scf_offline_check(statep, FLAG_ON);
			func_ret = scf_cmdbusy_check(statep);
			break;

		default:
			break;
		}
		break;

	case TEST_OSESCF_CALL_RESET:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_OSESCF_CALL_RESET");

		/* Not use info */
		scf_debug_test_osescf_call_flag = SCF_DBF_OSESCF_CALL_OFF;
		break;

	case TEST_OSESCF_CALL_PUTINFO:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_OSESCF_CALL_PUTINFO");

		/*
		 * IN:
		 *	info[0] : key
		 *	info[1] : type
		 *	info[2] : transid
		 *	info[3] : length
		 */
		key = (uint32_t)test_p->info[0];
		type = (uint8_t)test_p->info[1];
		transid = (uint32_t)test_p->info[2];
		length = (uint32_t)test_p->info[3];

		/*
		 * scf_service_putinfo(uint32_t key, uint8_t type,
		 * uint32_t transid, uint32_t length, void *datap);
		 */

		if (length != 0) {
			kmem_size = length;
			data_addr = (caddr_t)kmem_zalloc(kmem_size, KM_SLEEP);
		}

		msc_dptr = data_addr;
		for (ii = 0; ii < length; ii++, msc_dptr++) {
			*msc_dptr = ii;
		}

		scf_debug_test_osescf_call_flag = SCF_DBF_OSESCF_CALL_ON;

		mutex_exit(&scf_comtbl.all_mutex);
		if (test_p->data[0] == 1) {
			func_ret = scf_service_putinfo(key, type, transid,
				length, NULL);
		} else {
			func_ret = scf_service_putinfo(key, type, transid,
				length, (void *)data_addr);
		}
		mutex_enter(&scf_comtbl.all_mutex);

		if (length != 0)
			bcopy((void *)data_addr, (void *)&test_p->rdata[0],
				length);

		if (data_addr != NULL) kmem_free(data_addr, kmem_size);

		scf_debug_test_osescf_call_flag = SCF_DBF_OSESCF_CALL_OFF;

		break;

	case TEST_OSESCF_CALL_GETINFO:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_OSESCF_CALL_GETINFO");

		/*
		 * IN:
		 *	info[0] : key
		 *	info[1] : type
		 *	info[2] : transid
		 *	info[3] : length
		 * OUT:
		 *	info[3] : length
		 */
		key = (uint32_t)test_p->info[0];
		type = (uint8_t)test_p->info[1];
		transid = (uint32_t)test_p->info[2];
		length = (uint32_t)test_p->info[3];

		/*
		 * scf_service_getinfo(uint32_t key, uint8_t type,
		 * uint32_t transid, uint32_t *lengthp, void *datap);
		 */
		if (length != 0) {
			kmem_size = length;
			data_addr = (caddr_t)kmem_zalloc(kmem_size, KM_SLEEP);
		}

		msc_dptr = data_addr;
		for (ii = 0; ii < length; ii++, msc_dptr++) {
			*msc_dptr = 0x7f;
		}

		scf_debug_test_osescf_call_flag = SCF_DBF_OSESCF_CALL_ON;

		mutex_exit(&scf_comtbl.all_mutex);
		if (test_p->data[0] == 1) {
			func_ret = scf_service_getinfo(key, type, transid,
				(uint32_t *)&length, NULL);
		} else if (test_p->data[0] == 2) {
			func_ret = scf_service_getinfo(key, type, transid,
				NULL, (void *)data_addr);
		} else {
			func_ret = scf_service_getinfo(key, type, transid,
				(uint32_t *)&length, (void *)data_addr);
		}
		mutex_enter(&scf_comtbl.all_mutex);

		if (scf_debug_nofirm_sys == SCF_DBF_NOFIRM_SYS_ON) {
			length = kmem_size;
			msc_dptr = data_addr;
			for (ii = 0; ii < length; ii++, msc_dptr++) {
				*msc_dptr = ii;
			}
		}
		if (length != 0)
			bcopy((void *)data_addr, (void *)&test_p->rdata[0],
				length);

		if (data_addr != NULL) kmem_free(data_addr, kmem_size);

		scf_debug_test_osescf_call_flag = SCF_DBF_OSESCF_CALL_OFF;

		test_p->info[3] = (uint_t)length;
		break;

	case TEST_FMEM_START:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_FMEM_START");

		/*
		 * IN:
		 *	info[0] : lsb_1
		 *	info[1] : lsb_2
		 */

		/*
		 * scf_fmem_start(int s_bd, int t_bd);
		 */

		mutex_exit(&scf_comtbl.all_mutex);
		func_ret = scf_fmem_start(test_p->info[0], test_p->info[1]);
		mutex_enter(&scf_comtbl.all_mutex);
		break;

	case TEST_FMEM_END:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_FMEM_END");

		/*
		 * scf_fmem_end(void);
		 */

		mutex_exit(&scf_comtbl.all_mutex);
		func_ret = scf_fmem_end();
		mutex_enter(&scf_comtbl.all_mutex);

		break;

	case TEST_FMEM_CANCEL:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "TEST_FMEM_CANCEL");

		/*
		 * scf_fmem_cancel(void);
		 */

		mutex_exit(&scf_comtbl.all_mutex);
		func_ret = scf_fmem_cancel();
		mutex_enter(&scf_comtbl.all_mutex);

		break;

	default:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "Undefine mod");

		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "dbg_test", 8);
		ret = EINVAL;
		break;
	}

	test_p->rtncode = func_ret;

	/* Collect the timers which need to be stopped */
	tm_stop_cnt = scf_timer_stop_collect(save_tmids, SCF_TIMERCD_MAX);

	/* Unlock driver mutex */
	mutex_exit(&scf_comtbl.all_mutex);

	/* Timer stop */
	if (tm_stop_cnt != 0) {
		scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
	}

	if (ret == 0) {
		if (ddi_copyout((void *)test_p, (void *)arg,
			sizeof (scf_scfioctest_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"ioctl   ", 8);
			ret = EFAULT;
		}
	}

/*
 * END_test
 */
	END_test:

	if (test_p) {
		kmem_free((void *)test_p,
			(size_t)(sizeof (scf_scfioctest_t)));
	}

	SCFDBGMSG1(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


void
scf_debug_test_intr_tout(void *arg)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_intr_tout() "

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	mutex_enter(&scf_comtbl.all_mutex);

	if (scf_debug_test_intr_id != 0) {
		scf_debug_test_intr_id = 0;

		mutex_exit(&scf_comtbl.all_mutex);

		scf_intr(arg);
	} else {
		mutex_exit(&scf_comtbl.all_mutex);
	}

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_intr(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_intr() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	statep->reg_int_st = scf_debug_test_sys_int_tbl.INT_ST;

	if (SCF_DBG_CHECK_NODEVICE) {
		SCF_DDI_PUT16(statep, statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST, statep->reg_int_st);
	}

	SCFDBGMSG1(SCF_DBGFLAG_DBG, "set ISR = 0x%04x", statep->reg_int_st);

	scf_debug_test_sys_int_tbl.INT_ST = 0;

	if ((statep->reg_int_st & INT_ST_IDBCINT) == 0) {
		scf_debug_test_dscp_int_flag = SCF_DBF_DSCP_INT_OFF;
	}
	if ((statep->reg_int_st & INT_ST_SCFINT) == 0) {
		scf_debug_test_sys_int_flag = SCF_DBF_SYS_INTR_OFF;
	}

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_intr_scfint(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_intr_scfint() "
	uint16_t		wk_STATUS;
	uint32_t		wk_STATUS_ExR;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	if ((scf_debug_test_sys_int_tbl.STATUS & STATUS_MODE_CHANGED) == 0) {
		wk_STATUS =
			statep->reg_status &
			(STATUS_SECURE_MODE | STATUS_BOOT_MODE);
		scf_debug_test_sys_int_tbl.STATUS &=
			~(STATUS_SECURE_MODE | STATUS_BOOT_MODE);
		scf_debug_test_sys_int_tbl.STATUS |= wk_STATUS;
	}
	statep->reg_status = scf_debug_test_sys_int_tbl.STATUS;

	if (SCF_DBG_CHECK_NODEVICE) {
		SCF_DDI_PUT16(statep, statep->scf_regs_handle,
			&statep->scf_regs->STATUS, statep->reg_status);
	}

	SCFDBGMSG1(SCF_DBGFLAG_DBG, "set STR = 0x%04x", statep->reg_status);

	scf_debug_test_sys_int_tbl.STATUS = 0;

	if ((scf_debug_test_sys_int_tbl.STATUS_ExR &
		STATUS_SCF_STATUS_CHANGE) == 0) {
		wk_STATUS_ExR = statep->reg_status_exr &
			(STATUS_SCF_STATUS | STATUS_SCF_NO);
		scf_debug_test_sys_int_tbl.STATUS_ExR &=
			~(STATUS_SCF_STATUS | STATUS_SCF_NO);
		scf_debug_test_sys_int_tbl.STATUS_ExR |= wk_STATUS_ExR;
	}
	statep->reg_status_exr = scf_debug_test_sys_int_tbl.STATUS_ExR;

	if (SCF_DBG_CHECK_NODEVICE) {
		SCF_DDI_PUT32(statep, statep->scf_regs_handle,
			&statep->scf_regs->STATUS_ExR, statep->reg_status_exr);
	}

	SCFDBGMSG1(SCF_DBGFLAG_DBG, "set STExR = 0x%08x",
		statep->reg_status_exr);

	scf_debug_test_sys_int_tbl.STATUS_ExR = 0;

	if ((statep->reg_status & STATUS_CMD_COMPLETE) == 0) {
		scf_debug_test_sys_int_flag = SCF_DBF_SYS_INTR_OFF;
	}

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_intr_cmdend(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_intr_cmdend() "
	uint_t			ii;
	uint8_t			*wk_charp;
	uint8_t			sum = SCF_MAGICNUMBER_S;
	uint32_t		sum4 = SCF_MAGICNUMBER_L;
	uint32_t		wk_data;
	uint8_t			*wk_out_p;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	if (scf_debug_test_sys_int_tbl.rxsize < SCF_S_CNT_16) {
		if ((scf_debug_rdata[0] == 0) &&
			(scf_debug_rdata[1] == 0) &&
			(scf_debug_rdata[2] == 0) &&
			(scf_debug_rdata[3] == 0)) {
			statep->reg_rdata[0] =
				scf_debug_test_sys_int_tbl.RDATA0;
			statep->reg_rdata[1] =
				scf_debug_test_sys_int_tbl.RDATA1;
			statep->reg_rdata[2] =
				scf_debug_test_sys_int_tbl.RDATA2;
			statep->reg_rdata[3] =
				scf_debug_test_sys_int_tbl.RDATA3;
		} else {
			statep->reg_rdata[0] = scf_debug_rdata[0];
			statep->reg_rdata[1] = scf_debug_rdata[1];
			statep->reg_rdata[2] = scf_debug_rdata[2];
			statep->reg_rdata[3] = scf_debug_rdata[3];
		}
	} else {
		statep->reg_rdata[0] = scf_debug_test_sys_int_tbl.rxsize;
		statep->reg_rdata[1] = 0;
		if (scf_debug_test_sys_int_tbl.RDATA2 != 0) {
			statep->reg_rdata[2] =
				scf_debug_test_sys_int_tbl.RDATA2;
			scf_debug_test_rxbuff_nosum_check_flag =
				SCF_DBF_RXBUFF_NOSUM_CHECK_OFF;
		} else {
			statep->reg_rdata[2] = 0;
			scf_debug_test_rxbuff_nosum_check_flag =
				SCF_DBF_RXBUFF_NOSUM_CHECK_ON;
		}
		statep->reg_rdata[3] = scf_debug_test_sys_int_tbl.RDATA3;

		if ((scf_comtbl.scf_exec_cmd_id == 0) &&
			(scf_comtbl.scf_cmd_intr.cmd == CMD_INT_REASON)) {
			wk_out_p = (uint8_t *)&statep->scf_sys_sram->DATA[0];
			for (ii = 0; ii < scf_debug_test_sys_int_tbl.rxsize;
				ii++, wk_out_p++) {
				SCF_DDI_PUT8(statep,
					statep->scf_sys_sram_handle, wk_out_p,
					0x00);
			}
		} else {
			wk_data = 0x00010203;
			wk_out_p = (uint8_t *)&statep->scf_sys_sram->DATA[0];
			for (ii = 0; ii < scf_debug_test_sys_int_tbl.rxsize;
				ii++, wk_out_p++) {
				SCF_DDI_PUT8(statep,
					statep->scf_sys_sram_handle, wk_out_p,
					ii);
				if ((ii % 4) == 0) {
					wk_data = (ii & 0x000000ff) << 24;
				} else if ((ii % 4) == 1) {
					wk_data |= (ii & 0x000000ff) << 16;
				} else if ((ii % 4) == 2) {
					wk_data |= (ii & 0x000000ff) << 8;
				} else {
					wk_data |= (ii & 0x000000ff);
					sum4 += wk_data;
				}
			}
		}

		if (scf_no_make_sum_l == SCF_DBF_NO_MAKE_SUM_L_OFF) {
			statep->reg_rdata[2] = sum4;
		}
	}

	wk_charp = (uint8_t *)&statep->reg_rdata[0];
	for (ii = 0; ii < SCF_S_CNT_15; ii++, wk_charp++) {
		sum += (*wk_charp);
	}

	if (scf_no_make_sum_s == SCF_DBF_NO_MAKE_SUM_S_OFF) {
		*wk_charp = sum;
	}

	SCFDBGMSG4(SCF_DBGFLAG_DBG, "set RxDR = 0x%08x 0x%08x 0x%08x 0x%08x",
		statep->reg_rdata[0], statep->reg_rdata[1],
		statep->reg_rdata[2], statep->reg_rdata[3]);

	scf_debug_test_sys_int_flag = SCF_DBF_SYS_INTR_OFF;

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_intr_poff(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_intr_poff() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	scf_comtbl.scf_poff_id = scf_debug_test_sys_int_tbl.POFF_FACTOR;

	SCFDBGMSG1(SCF_DBGFLAG_DBG, "set POFF factor = 0x%02x",
		scf_comtbl.scf_poff_id);

	scf_debug_test_sys_poff_flag = SCF_DBF_SYS_POFF_OFF;

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}

void
scf_debug_test_dsens(struct scf_cmd *scfcmdp, scf_int_reason_t *int_rp, int len)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_dsens() "
	int			wk_len = len;
	uint8_t			*wk_in_p;
	uint8_t			*wk_out_p;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	if (wk_len == 0) {
		wk_len = SCF_INT_CNT_MAX;
		scfcmdp->rbufleng = wk_len;
	}

	wk_in_p = (uint8_t *)&scf_debug_test_sys_int_tbl.EVENT[0];
	wk_out_p = (uint8_t *)int_rp;
	bcopy((void *)wk_in_p, (void *)wk_out_p, wk_len);

	scf_debug_test_sys_event_flag = SCF_DBF_SYS_EVENT_OFF;

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_intr_dscp_dsr(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_intr_dscp_dsr() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	statep->reg_dsr = scf_debug_test_dscp_int_tbl.DSR;

	if (SCF_DBG_CHECK_NODEVICE) {
		SCF_DDI_PUT8(statep, statep->scf_regs_handle,
			&statep->scf_regs->DSR, statep->reg_dsr);
	}

	SCFDBGMSG1(SCF_DBGFLAG_DBG, "set DSR = 0x%02x", statep->reg_dsr);

	scf_debug_test_dscp_int_tbl.DSR = 0;

	if ((statep->reg_dsr & (DSR_RxREQ | DSR_TxACK | DSR_TxEND)) == 0) {
		scf_debug_test_dscp_int_flag = SCF_DBF_DSCP_INT_OFF;
	}

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_intr_dscp_rxtx(scf_state_t *statep, uint8_t dsr)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_intr_dscp_rxtx() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	if (dsr & DSR_RxREQ) {
		statep->reg_rxdcr_c_flag =
			(scf_debug_test_dscp_int_tbl.RxDCR_C_FLAG |
			DSC_FLAG_DEFAULT);
		statep->reg_rxdcr_c_length =
			scf_debug_test_dscp_int_tbl.RxDCR_LENGTH;
		if (scf_debug_test_dscp_int_tbl.RxDCR_LENGTH != 0) {
			if (scf_debug_test_dscp_int_tbl.RxDCR_OFFSET !=
				DSC_OFFSET_NOTHING) {
			statep->reg_rxdcr_c_offset =
				scf_debug_test_dscp_int_tbl.RxDCR_OFFSET;
			} else {
				statep->reg_rxdcr_c_offset =
					(SCF_TX_SRAM_MAXCOUNT * SCF_RXBUFFSIZE /
					DSC_OFFSET_CONVERT);
			}
		} else {
			statep->reg_rxdcr_c_offset = DSC_OFFSET_NOTHING;
		}

		SCFDBGMSG3(SCF_DBGFLAG_DBG,
			"set RxDCR = 0x%04x 0x%04x 0x%08x",
			statep->reg_rxdcr_c_flag,
			statep->reg_rxdcr_c_offset,
			statep->reg_rxdcr_c_length);

		if ((dsr & DSR_TxEND) == 0) {
			scf_debug_test_dscp_int_flag = SCF_DBF_DSCP_INT_OFF;
		}

	} else  if (dsr == DSR_TxEND) {
		statep->reg_txdsr_c_flag =
			(statep->reg_txdcr_c_flag & 0xff00) |
			scf_debug_test_dscp_int_tbl.TxDSR_C_FLAG;
		if (scf_debug_test_dscp_int_tbl.TxDSR_OFFSET == 0) {
			statep->reg_txdsr_c_offset = statep->reg_txdcr_c_offset;
		} else {
			statep->reg_txdsr_c_offset =
				scf_debug_test_dscp_int_tbl.TxDSR_OFFSET;
		}

		SCFDBGMSG2(SCF_DBGFLAG_DBG, "set TxDSR = 0x%04x 0x%04x",
			statep->reg_rxdcr_c_flag,
			statep->reg_rxdcr_c_offset);

		scf_debug_test_dscp_int_flag = SCF_DBF_DSCP_INT_OFF;
	}

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_alive_start(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_alive_start() "
	uint8_t			wk_int8;
	uint_t			alive_timer;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	wk_int8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
		&statep->scf_regs->ATR);

	switch (wk_int8 & ATR_INTERVAL) {
	case ATR_INTERVAL_30S:
		alive_timer = 30000;
		break;

	case ATR_INTERVAL_60S:
		alive_timer = 60000;
		break;

	case ATR_INTERVAL_120S:
		alive_timer = 120000;
		break;

	default:
		alive_timer = 0;
		break;
	}
	if ((alive_timer != 0) && (scf_debug_test_alive_id == 0)) {
		scf_debug_test_sys_int_flag = SCF_DBF_SYS_INTR_ON;
		scf_debug_test_sys_int_tbl.INT_ST |= INT_ST_ALIVEINT;
		scf_debug_test_alive_id =
			timeout((void (*)())scf_debug_test_alive_intr_tout,
			(void *)statep,
			drv_usectohz(SCF_MIL2MICRO(alive_timer)));
		scf_debug_test_alive_flag = FLAG_ON;
	}

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


/* ARGSUSED */
void
scf_debug_test_alive_stop(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_alive_stop() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	scf_debug_test_alive_flag = FLAG_OFF;

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_alive_intr_tout(void *arg)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_alive_intr_tout() "

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	mutex_enter(&scf_comtbl.all_mutex);

	scf_debug_test_alive_id = 0;

	if (scf_debug_test_alive_flag == FLAG_ON) {
		scf_debug_test_alive_start(arg);

		mutex_exit(&scf_comtbl.all_mutex);

		scf_intr(arg);
	} else {
		mutex_exit(&scf_comtbl.all_mutex);
	}


	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_send_cmd(scf_state_t *statep, struct scf_cmd *scfcmdp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_send_cmd() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	if (scf_debug_scfint_time != 0) {
		scf_debug_test_sys_int_flag = SCF_DBF_SYS_INTR_ON;
		scf_debug_test_sys_int_tbl.INT_ST |= INT_ST_SCFINT;

		scf_debug_test_sys_int_tbl.STATUS = STATUS_CMD_COMPLETE;
		scf_debug_test_sys_int_tbl.STATUS_ExR = 0;

		switch (scfcmdp->flag) {
		case SCF_USE_SSBUF:
		case SCF_USE_LSBUF:
			scf_debug_test_sys_int_tbl.rxsize = scfcmdp->rcount;
			scf_debug_test_sys_int_tbl.RDATA0 = 0x00010203;
			scf_debug_test_sys_int_tbl.RDATA1 = 0x04050607;
			scf_debug_test_sys_int_tbl.RDATA2 = 0x08090a0b;
			scf_debug_test_sys_int_tbl.RDATA3 = 0x0c0d0e0f;
			break;

		case SCF_USE_SLBUF:
			scf_debug_test_sys_int_tbl.rxsize = scfcmdp->rcount;
			scf_debug_test_sys_int_tbl.RDATA0 = scfcmdp->rcount;
			scf_debug_test_sys_int_tbl.RDATA1 = 0;
			scf_debug_test_sys_int_tbl.RDATA2 = 0;
			scf_debug_test_sys_int_tbl.RDATA3 = 0;
			break;

		default:
			scf_debug_test_sys_int_tbl.rxsize = 0;
			scf_debug_test_sys_int_tbl.RDATA0 = 0;
			scf_debug_test_sys_int_tbl.RDATA1 = 0;
			scf_debug_test_sys_int_tbl.RDATA2 = 0;
			scf_debug_test_sys_int_tbl.RDATA3 = 0;
			break;
		}

		if (scf_debug_test_intr_id == 0) {
		scf_debug_test_intr_id =
			timeout((void (*)())scf_debug_test_intr_tout,
			(void *)statep,
			drv_usectohz(SCF_MIL2MICRO(scf_debug_scfint_time)));
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_txreq_send(scf_state_t *statep, scf_dscp_dsc_t *dsc_p)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_txreq_send() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	if (scf_debug_idbcint_time != 0) {
		scf_debug_test_dscp_int_flag = SCF_DBF_DSCP_INT_ON;
		scf_debug_test_sys_int_tbl.INT_ST |= INT_ST_IDBCINT;

		if (dsc_p->dinfo.base.length != 0) {
			if (scf_debug_test_dscp_loopback ==
				SCF_DBF_DSCP_LOOPBACK_ON) {
				scf_debug_test_dscp_int_tbl.DSR =
					(DSR_RxREQ | DSR_TxACK | DSR_TxEND);

				scf_debug_test_dscp_int_tbl.RxDCR_C_FLAG =
					dsc_p->dinfo.base.c_flag;
				scf_debug_test_dscp_int_tbl.RxDCR_OFFSET =
					dsc_p->dinfo.base.offset;
				scf_debug_test_dscp_int_tbl.RxDCR_LENGTH =
					dsc_p->dinfo.base.length;
			} else {
				scf_debug_test_dscp_int_tbl.DSR =
					(DSR_TxACK | DSR_TxEND);
			}
		} else {
			scf_debug_test_dscp_int_tbl.DSR = DSR_TxEND;
		}

		scf_debug_test_dscp_int_tbl.TxDSR_C_FLAG =
			(dsc_p->dinfo.base.c_flag & 0xff00) | DSC_STATUS_NORMAL;
		scf_debug_test_dscp_int_tbl.TxDSR_OFFSET =
			dsc_p->dinfo.base.offset;

		if (scf_debug_test_intr_id == 0) {
		scf_debug_test_intr_id =
			timeout((void (*)())scf_debug_test_intr_tout,
			(void *)statep,
			drv_usectohz(SCF_MIL2MICRO(scf_debug_idbcint_time)));
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


/* ARGSUSED */
void
scf_debug_test_event_handler(scf_event_t mevent, void *arg)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_event_handler() "

	SCFDBGMSG1(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start mevent = %d",
		mevent);
	SCFDBGMSG(SCF_DBGFLAG_DBG, "=======================================");

	switch (mevent) {
	case SCF_MB_CONN_OK:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "SCF_MB_CONN_OK");
		break;
	case SCF_MB_MSG_DATA:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "SCF_MB_MSG_DATA");
		break;
	case SCF_MB_SPACE:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "SCF_MB_SPACE");
		break;
	case SCF_MB_DISC_ERROR:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "SCF_MB_DISC_ERROR");
		break;
	default:
		SCFDBGMSG(SCF_DBGFLAG_DBG, "Undefine event code");
		break;
	}

	SCFDBGMSG(SCF_DBGFLAG_DBG, "=======================================");
	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_timer_stop()
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_timer_stop() "
	timeout_id_t		save_tmid[4];
	int			timer_cnt = 0;
	int			ii;

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	mutex_enter(&scf_comtbl.all_mutex);

	if (scf_debug_test_intr_id != 0) {
		save_tmid[timer_cnt] = scf_debug_test_intr_id;
		scf_debug_test_intr_id = 0;
		timer_cnt++;
	}
	if (scf_debug_test_alive_id != 0) {
		save_tmid[timer_cnt] = scf_debug_test_alive_id;
		scf_debug_test_alive_id = 0;
		timer_cnt++;
	}

	mutex_exit(&scf_comtbl.all_mutex);

	for (ii = 0; ii < timer_cnt; ii++) {
		(void) untimeout(save_tmid[ii]);
	}

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_map_regs(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_map_regs() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	statep->scf_regs = &scf_debug_scf_regs_tbl;
	statep->scf_regs_c = &scf_debug_scf_regs_c_tbl;
	statep->scf_dscp_sram = &scf_debug_scf_dscp_sram_tbl;
	statep->scf_sys_sram = &scf_debug_scf_sys_sram_tbl;
	statep->scf_interface = &scf_debug_scf_interface_tbl;
	statep->scf_reg_drvtrc = (void *)&scf_debug_scf_reg_drvtrc_tbl;
	statep->scf_reg_drvtrc_len =
		(off_t)sizeof (scf_debug_scf_reg_drvtrc_tbl);

	statep->resource_flag |=
		(S_DID_REG1 | S_DID_REG2 | S_DID_REG3 |
		S_DID_REG4 | S_DID_REG5 | S_DID_REG6);

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}


void
scf_debug_test_unmap_regs(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_debug_test_unmap_regs() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": start");

	statep->scf_regs = NULL;
	statep->scf_regs_c = NULL;
	statep->scf_dscp_sram = NULL;
	statep->scf_sys_sram = NULL;
	statep->scf_interface = NULL;
	statep->scf_reg_drvtrc = NULL;

	statep->resource_flag &=
		~(S_DID_REG1 | S_DID_REG2 | S_DID_REG3 |
		S_DID_REG4 | S_DID_REG5 | S_DID_REG6);

	SCFDBGMSG(SCF_DBGFLAG_DBG, SCF_FUNC_NAME ": end");
}
#endif /* DEBUG */
