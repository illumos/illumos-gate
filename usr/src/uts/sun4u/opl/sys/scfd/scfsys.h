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

#ifndef _SCFSYS_H
#define	_SCFSYS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scfd/opcio.h>
#include <sys/scfd/scfstate.h>
#include <sys/scfd/scftimer.h>
#include <sys/scfd/scfkstat.h>
#include <sys/scfd/scfostoescf.h>

#ifndef	TRUE
#define	TRUE			(1)
#endif

#ifndef	FALSE
#define	FALSE			(0)
#endif

#define	FLAG_ON			(1)
#define	FLAG_OFF		(0)

#define	SCF_DRIVER_VERSION	"SCF driver 1.6"
#define	SCF_DRIVER_NAME		"scfd"
#define	SCF_DEVICE_NAME		"scfc"

/* instance number */
#define	SCF_USER_INSTANCE	200	/* instance */

#define	SCF_MAX_INSTANCE	80	/* Max instance */

/* SCFHALT after processing  mode define */
#define	HALTPROC_STOP		0	/* processing stop mode (default) */
#define	HALTPROC_SHUTDOWN	1	/* processing shutdown mode */
#define	HALTPROC_PANIC		2	/* processing panic mode */

/*
 * External function
 */
extern int	scf_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
extern int	scf_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
extern void	scf_resource_free_dev(scf_state_t *statep);
extern int	scf_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
			void *arg, void **resultp);
extern void	scf_reload_conf(scf_state_t *statep);

extern int	scf_open(dev_t *devp, int flag, int otyp, cred_t *cred_p);
extern int	scf_close(dev_t dev, int flag, int otyp, cred_t *cred_p);
extern int	scf_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
			cred_t *cred_p, int *rval_p);
extern int	scf_ioc_reportstat(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_clearlcd(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_wrlcd(intptr_t arg, int mode, int *rval_p, int u_mode);
extern int	scf_ioc_getdiskled(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_setdiskled(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_getsdownreason(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_optiondisp(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_getpciconfig(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_hac(intptr_t arg, int mode, int *rval_p, int u_mode);
extern int	scf_ioc_hstadrsinfo(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_rdclistmax(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_rdclistx(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_rdctrl(intptr_t arg, int mode, int *rval_p, int u_mode);
extern int	scf_ioc_opecall(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_getreport(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_rcipwr(intptr_t arg, int mode, int *rval_p, int u_mode);
extern int	scf_ioc_panicreq(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_panicchk(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_parmset(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_parmget(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_autopwrset(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_autopwrget(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_autopwrclr(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_autopwrfpoff(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_autopwrexset(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_autopwrexget(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_dr(intptr_t arg, int mode, int *rval_p, int u_mode);
extern int	scf_ioc_eventlist(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_getevent(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_setmadmevent(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_remcscmd(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_remcsfile(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_sparecmd(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_ioc_setphpinfo(intptr_t arg, int mode, int *rval_p,
			int u_mode);
extern int	scf_push_reportsense(unsigned int rci_addr,
			unsigned char *sense, time_t timestamp);
extern int	scf_pop_reportsense(scfreport_t *rsense);
extern int	scf_push_getevent(unsigned char *event_p);
extern int	scf_pop_getevent(scfevent_t *event_p);
extern int	scf_valid_date(int year, int month, int date);
extern int	scf_check_pon_time(scfautopwrtime_t *ptime);
extern int	scf_check_poff_time(scfautopwrtime_t *ptime);

extern uint_t	scf_intr(caddr_t arg);
extern int	scf_intr_cmdcmp(scf_state_t *statep);
extern void	scf_intr_cmdcmp_driver(scf_state_t *statep,
			struct scf_cmd *scfcmdp);
extern int	scf_intr_dsens(struct scf_cmd *scfcmdp,
			scf_int_reason_t *int_rp, int len);
extern void	scf_status_change(scf_state_t *statep);
extern void	scf_next_cmd_check(scf_state_t *statep);
extern void	scf_next_rxdata_get(void);
extern void	scf_online_wait_tout(void);
extern void	scf_cmdbusy_tout(void);
extern void	scf_cmdend_tout(void);
extern void	scf_report_send_wait_tout(void);
extern void	scf_alivecheck_intr(scf_state_t *statep);
extern void	scf_path_change(scf_state_t *statep);
extern void	scf_halt(uint_t mode);
extern void	scf_panic_callb(int code);
extern void	scf_shutdown_callb(int code);
extern uint_t	scf_softintr(caddr_t arg);
extern void	scf_cmdwait_status_set(void);

extern int	scf_map_regs(dev_info_t *dip, scf_state_t *statep);
extern void	scf_unmap_regs(scf_state_t *statep);
extern int	scf_send_cmd_check_bufful(struct scf_cmd *scfcmdp);
extern int	scf_send_cmd(struct scf_cmd *scfcmdp);
extern void	scf_i_send_cmd(struct scf_cmd *scfcmdp,
			struct scf_state *statep);
extern void	scf_p_send_cmd(struct scf_cmd *scfcmdp,
			struct scf_state *statep);
extern int	scf_path_check(scf_state_t **statep);
extern int	scf_offline_check(scf_state_t *statep, uint_t timer_exec_flag);
extern int	scf_cmdbusy_check(scf_state_t *statep);
extern void	scf_alivecheck_start(scf_state_t *statep);
extern void	scf_alivecheck_stop(scf_state_t *statep);
extern void	scf_forbid_intr(struct scf_state *statep);
extern void	scf_permit_intr(struct scf_state *statep, int flag);
extern int	scf_check_state(scf_state_t *statep);
extern void	scf_chg_scf(scf_state_t *statep, int status);
extern void	scf_del_queue(scf_state_t *statep);
extern int	scf_make_send_cmd(struct scf_cmd *scfcmdp, uint_t flag);
extern void	scf_sram_trace_init(struct scf_state *statep);
extern void	scf_sram_trace(struct scf_state *statep, uint8_t log_id);

#ifdef	DEBUG
#include <sys/scfd/scftrace.h>
#include <sys/scfd/iomp_drv.h>
#include <sys/scfd/scfdebug.h>
#include <sys/scfd/scfsnap.h>

#define	SCF_META_INSTANCE	(SCF_USER_INSTANCE + 1)
				/* meta management instance */
#define	SCF_INST_INSTANCE	(SCF_USER_INSTANCE + 2)
				/* instance management instance */

extern void	scf_add_scf(scf_state_t *statep);
extern void	scf_del_scf(scf_state_t *statep);
extern int	scf_meta_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
			cred_t *cred_p, int *rval_p, int u_mode);
extern int	scf_inst_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
			cred_t *cred_p, int *rval_p, int u_mode);
extern void	scf_inst_getstat32(scf_state_t *statep,
			struct fiompstatus_32 *status32_p, char *message_p,
			int flag);
extern void	scf_inst_getstat(scf_state_t *statep,
			struct fiompstatus *status_p, char *message_p,
			int flag);

#define	SCF_DDI_PUT8(a, b, c, d)					\
	if (scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) {		\
		uint8_t		*cp = (uint8_t *)c;			\
		*cp = d;						\
	} else {							\
		ddi_put8(b, c, d);					\
	}

#define	SCF_DDI_PUT16(a, b, c, d)					\
	if (scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) {		\
		uint16_t	*cp = (uint16_t *)c;			\
		*cp = d;						\
	} else {							\
		ddi_put16(b, c, d);					\
	}

#define	SCF_DDI_PUT32(a, b, c, d)					\
	if (scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) {		\
		uint32_t	*cp = (uint32_t *)c;			\
		*cp = d;						\
	} else {							\
		ddi_put32(b, c, d);					\
	}

#define	SCF_DDI_GET8(a, b, c)						\
	(scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) ?			\
		*((uint8_t *)c) : ddi_get8(b, c)

#define	SCF_DDI_GET16(a, b, c)						\
	(scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) ?			\
		*((uint16_t *)c) : ddi_get16(b, c)

#define	SCF_DDI_GET32(a, b, c)						\
	(scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) ?			\
		*((uint32_t *)c) : ddi_get32(b, c)

#define	SCF_P_DDI_PUT8(a, b, c)						\
	if (scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) {		\
		uint8_t		*bp = (uint8_t *)b;			\
		*bp = c;						\
	} else {							\
		ddi_put8(a, b, c);					\
	}

#define	SCF_P_DDI_PUT16(a, b, c)					\
	if (scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) {		\
		uint16_t	*bp = (uint16_t *)b;			\
		*bp = c;						\
	} else {							\
		ddi_put16(a, b, c);					\
	}

#define	SCF_P_DDI_PUT32(a, b, c)					\
	if (scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) {		\
		uint32_t	*bp = (uint32_t *)b;			\
		*bp = c;						\
	} else {							\
		ddi_put32(a, b, c);					\
	}

#define	SCF_P_DDI_GET8(a, b)						\
	(scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) ?			\
		*((uint8_t *)b) : ddi_get8(a, b)

#define	SCF_P_DDI_GET16(a, b)						\
	(scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) ?			\
		*((uint16_t *)b) : ddi_get16(a, b)

#define	SCF_P_DDI_GET32(a, b)						\
	(scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) ?			\
		*((uint32_t *)b) : ddi_get32(a, b)

#define	SCF_CHECK_INSTANCE(a)						\
	(a == SCF_USER_INSTANCE) ||					\
	(a == SCF_META_INSTANCE) ||					\
	(a == SCF_INST_INSTANCE)

#define	SCF_DBG_DRV_TRACE_TBL						\
	scf_trctbl_t	*trace_f;					\
	scf_trctbl_t	*trace_l;					\
	scf_trctbl_t	*trace_w;					\
	scf_trctbl_t	*err_trace_f;					\
	scf_trctbl_t	*err_trace_l;					\
	scf_trctbl_t	*err_trace_w;					\
	scf_trctbl_t	trace_table[TC_NRM_CNT];			\
	scf_trctbl_t	err_trace_table[TC_ERR_CNT];			\
	int		path_num;					\
	int		alloc_size;					\
	scf_state_t	**iomp_scf;

#define	SC_DBG_DRV_TRACE(a, b, c, d)					\
	scf_trace((ushort_t)(a), (ushort_t)(b), (uchar_t *)(c), (ushort_t)(d))

#define	SCF_DBG_DRV_TRACE_INIT						\
	scf_comtbl.trace_f = (scf_trctbl_t *)&scf_comtbl.trace_table[0]; \
	scf_comtbl.trace_l						\
	= (scf_trctbl_t *)&scf_comtbl.trace_table[TC_NRM_CNT];		\
	scf_comtbl.trace_w = (scf_trctbl_t *)&scf_comtbl.trace_table[0]; \
	scf_comtbl.err_trace_f						\
	= (scf_trctbl_t *)&scf_comtbl.err_trace_table[0];		\
	scf_comtbl.err_trace_l						\
	= (scf_trctbl_t *)&scf_comtbl.err_trace_table[TC_ERR_CNT];	\
	scf_comtbl.err_trace_w						\
	= (scf_trctbl_t *)&scf_comtbl.err_trace_table[0];

#define	SCFDBGMSG(f, s) if (f & scf_trace_msg_flag)			\
	cmn_err(CE_CONT, "scfd:debug:%04d: " s, __LINE__)
#define	SCFDBGMSG1(f, s, a) if (f & scf_trace_msg_flag)			\
	cmn_err(CE_CONT, "scfd:debug:%04d: " s, __LINE__, a)
#define	SCFDBGMSG2(f, s, a, b) if (f & scf_trace_msg_flag)		\
	cmn_err(CE_CONT, "scfd:debug:%04d: " s, __LINE__, a, b)
#define	SCFDBGMSG3(f, s, a, b, c) if (f & scf_trace_msg_flag)		\
	cmn_err(CE_CONT, "scfd:debug:%04d: " s, __LINE__, a, b, c)
#define	SCFDBGMSG4(f, s, a, b, c, d) if (f & scf_trace_msg_flag)	\
	cmn_err(CE_CONT, "scfd:debug:%04d: " s, __LINE__, a, b, c, d)

#define	SCF_DBG_IOMP_INSTANCE						\
	{ "mscf0", S_IFCHR, SCF_INST_INSTANCE },			\
	{ "mscf", S_IFCHR, SCF_META_INSTANCE },

#define	SCF_DBG_IOMP_PROC						\
	if (instance == SCF_META_INSTANCE) {				\
		if (drv_priv(cred_p) != 0) {				\
			ret = EPERM;					\
			goto END_ioctl;					\
		}							\
		ret = scf_meta_ioctl(dev, cmd, arg, mode, cred_p, rval_p, \
			u_mode);					\
		goto END_ioctl;						\
	} else if (instance == SCF_INST_INSTANCE) {			\
		if (drv_priv(cred_p) != 0) {				\
			ret = EPERM;					\
			goto END_ioctl;					\
		}							\
		ret = scf_inst_ioctl(dev, cmd, arg, mode, cred_p, rval_p, \
			u_mode);					\
		goto END_ioctl;						\
	}

#define	SCF_DBG_IOMP_ADD(a)						\
	{								\
	scf_add_scf(a);							\
	}

#define	SCF_DBG_IOMP_DEL(a)						\
	{								\
	scf_del_scf(a);							\
	}

#define	SCF_DBG_IOMP_FREE						\
	{								\
	if (scf_comtbl.iomp_scf != NULL) {				\
		kmem_free((void *)scf_comtbl.iomp_scf,			\
			(size_t)scf_comtbl.alloc_size);			\
		scf_comtbl.iomp_scf = NULL;				\
		scf_comtbl.alloc_size = 0;				\
		scf_comtbl.path_num = 0;				\
	}								\
	}

#define	SCF_DBG_IOCTL_PROC						\
	if ((uint_t)cmd == SCFIOCCMDTHROUGH) {				\
		ret = scf_debug_cmdthrough(arg, mode);			\
		goto END_ioctl;						\
	} else if ((uint_t)cmd == SCFIOCTEST) {				\
		ret = scf_debug_test(arg, mode);			\
		goto END_ioctl;						\
	} else if ((uint_t)cmd == SCFIOCSNAPSHOTSIZE) {			\
		ret = scf_snapshotsize(arg, mode);			\
		goto END_ioctl;						\
	} else if ((uint_t)cmd == SCFIOCSNAPSHOT) {			\
		ret = scf_snapshot(arg, mode);				\
		goto END_ioctl;						\
	}

#define	SCF_DBG_TEST_TIMER_STOP						\
	{								\
	scf_debug_test_timer_stop();					\
	}

#define	SCF_DBG_TEST_INTR(a)						\
	{								\
	if ((scf_debug_test_sys_int_flag == SCF_DBF_SYS_INTR_ON) ||	\
		(scf_debug_test_dscp_int_flag == SCF_DBF_DSCP_INT_ON))	\
		scf_debug_test_intr(a);					\
	}

#define	SCF_DBG_TEST_INTR_SCFINT(a)					\
	{								\
	if (scf_debug_test_sys_int_flag == SCF_DBF_SYS_INTR_ON)		\
		scf_debug_test_intr_scfint(a);				\
	}

#define	SCF_DBG_TEST_INTR_CMDEND(a)					\
	{								\
	if (scf_debug_test_sys_int_flag == SCF_DBF_SYS_INTR_ON)		\
		scf_debug_test_intr_cmdend(a);				\
	}

#define	SCF_DBG_MAKE_RXSUM(a, b)					\
	{								\
	if (scf_debug_norxsum_check != SCF_DBF_NORXSUM_CHECK_OFF)	\
		a = b;							\
	}

#define	SCF_DBG_MAKE_RXSUM_L(a, b)					\
	{								\
	if (scf_debug_test_rxbuff_nosum_check_flag ==			\
		SCF_DBF_RXBUFF_NOSUM_CHECK_ON) {			\
		a = b;							\
		scf_debug_test_rxbuff_nosum_check_flag			\
		= SCF_DBF_RXBUFF_NOSUM_CHECK_OFF;			\
	}								\
	}

#define	SCF_DBG_NO_INT_REASON						\
	{								\
	if (scf_debug_no_int_reason)					\
		scf_comtbl.scf_event_flag &= (~STATUS_EVENT);		\
	}

#define	SCF_DBG_TEST_INTR_POFF						\
	{								\
	if (scf_debug_test_sys_poff_flag == SCF_DBF_NO_INT_REASON_ON)	\
		scf_debug_test_intr_poff();				\
	}

#define	SCF_DBG_TEST_DSENS(a, b, c)					\
	{								\
	if (scf_debug_test_sys_event_flag == SCF_DBF_SYS_EVENT_ON)	\
		scf_debug_test_dsens(a, b, c);				\
	}

#define	SCF_DBG_TEST_SEND_CMD(a, b)					\
	{								\
	if (scf_debug_nofirm_sys == SCF_DBF_NOFIRM_SYS_ON)		\
		scf_debug_test_send_cmd(a, b);				\
	}

#define	SCF_DBG_MAKE_PATH_CHECK(a)					\
	{								\
	if (scf_debug_test_path_check != SCF_DBC_PATH_CHECK_CLEAR) {	\
		scf_debug_test_path_check--;				\
		if (scf_debug_test_path_check == SCF_DBC_PATH_CHECK_CLEAR) \
			a = scf_debug_test_path_check_rtn;		\
	}								\
	}

#define	SCF_DBG_MAKE_ONLINE(a)						\
	{								\
	if (scf_debug_nooffline_check != SCF_DBF_NOOFFLINE_CHECK_OFF)	\
		a = STATUS_SCF_ONLINE;					\
	}

#define	SCF_DBG_MAKE_OFFLINE_CHECK(a)					\
	{								\
	if (scf_debug_test_offline_check != SCF_DBC_OFFLINE_CHECK_CLEAR) { \
		scf_debug_test_offline_check--;				\
		if (scf_debug_test_offline_check			\
			== SCF_DBC_OFFLINE_CHECK_CLEAR)			\
			a = scf_debug_test_offline_check_rtn;		\
	}								\
	}

#define	SCF_DBG_RTN_MAKE_CMD_READY					\
	{								\
	if (scf_debug_nofirm_sys == SCF_DBF_NOFIRM_SYS_ON)		\
		return (SCF_COMMAND_READY);				\
	}

#define	SCF_DBG_MAKE_CMD_BUSY(a, b)					\
	{								\
	if (scf_debug_test_cmdr_busy != SCF_DBC_CMDR_BUSY_CLEAR) {	\
		scf_debug_test_cmdr_busy--;				\
		if (scf_debug_test_cmdr_busy == SCF_DBC_CMDR_BUSY_CLEAR) \
			a |= COMMAND_BUSY;				\
	}								\
	if (scf_debug_test_cmdexr_busy != SCF_DBC_CMDEXR_BUSY_CLEAR) {	\
		scf_debug_test_cmdexr_busy--;				\
		if (scf_debug_test_cmdexr_busy == SCF_DBC_CMDEXR_BUSY_CLEAR) \
			b |= COMMAND_ExR_BUSY;				\
	}								\
	}

#define	SCF_DBG_TEST_ALIVE_START(a)					\
	{								\
	if (scf_debug_no_alive == SCF_DBF_NO_ALIVE_ON)			\
		scf_debug_test_alive_start(a);				\
	}

#define	SCF_DBG_TEST_ALIVE_STOP(a)					\
	{								\
	if (scf_debug_no_alive == SCF_DBF_NO_ALIVE_ON)			\
		scf_debug_test_alive_stop(a);				\
	}

#define	SCF_DBG_TEST_INTR_DSCP_DSR(a)					\
	{								\
	if (scf_debug_test_dscp_int_flag == SCF_DBF_DSCP_INT_ON)	\
		scf_debug_test_intr_dscp_dsr(a);			\
	}

#define	SCF_DBG_TEST_INTR_DSCP_RXTX(a, b)				\
	{								\
	if (scf_debug_test_dscp_int_flag == SCF_DBF_DSCP_INT_ON)	\
		scf_debug_test_intr_dscp_rxtx(a, b);			\
	}

#define	SCF_DBG_MAKE_LOOPBACK(a)					\
	{								\
	if (scf_debug_test_dscp_loopback == SCF_DBF_DSCP_LOOPBACK_ON)	\
		a = 0;							\
	}

#define	SCF_DBG_MAKE_NO_DSCP_PATH(a)					\
	{								\
	if (scf_debug_no_dscp_path == SCF_DBF_NO_DSCP_PATH_ON)		\
		a = FLAG_OFF;						\
	}

#define	SCF_DBG_TEST_TXREQ_SEND(a, b)					\
	{								\
	if (scf_debug_nofirm_dscp == SCF_DBF_NOFIRM_DSCP_ON)		\
		scf_debug_test_txreq_send(a, b);			\
	}

#define	SCF_DBG_TEST_MAP_REGS(a)					\
	{								\
	if (scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) {		\
		scf_debug_test_map_regs(a);				\
		scf_sram_trace_init(a);					\
		ret = 0;						\
		goto END_map_regs;					\
	}								\
	}

#define	SCF_DBG_TEST_UNMAP_REGS(a)					\
	{								\
	if (scf_debug_no_device == SCF_DBF_NO_DEVICE_ON) {		\
		scf_debug_test_unmap_regs(a);				\
		SCFDBGMSG(SCF_DBGFLAG_SYS, "scf_unmap_regs(): end");	\
		return;							\
	}								\
	}

#define	SCF_DBG_XSCF_SET_STATUS						\
	if (scf_comtbl.debugxscf_flag) {				\
		if (scfcmdp->stat0 != NORMAL_END) {			\
			scfcmdp->rbufleng = 0;				\
			scfcmdp->stat0 = NORMAL_END;			\
		}							\
	}

#define	SCF_DBG_XSCF_SET_LENGTH						\
	if (scf_comtbl.debugxscf_flag) {				\
		if (((scfcmdp->status & STATUS_CMD_RTN_CODE) >> 4) !=	\
			NORMAL_END) {					\
			scfcmdp->rbufleng = 0;				\
			break;						\
		}							\
	}

#define	SCF_DBG_CHECK_NODEVICE						\
	scf_debug_no_device == SCF_DBF_NO_DEVICE_ON

#else	/* DEBUG */

#define	SCF_DDI_PUT8(a, b, c, d)	ddi_put8(b, c, d)
#define	SCF_DDI_PUT16(a, b, c, d)	ddi_put16(b, c, d)
#define	SCF_DDI_PUT32(a, b, c, d)	ddi_put32(b, c, d)
#define	SCF_DDI_GET8(a, b, c)		ddi_get8(b, c)
#define	SCF_DDI_GET16(a, b, c)		ddi_get16(b, c)
#define	SCF_DDI_GET32(a, b, c)		ddi_get32(b, c)

#define	SCF_P_DDI_PUT8(a, b, c)		ddi_put8(a, b, c)
#define	SCF_P_DDI_PUT16(a, b, c)	ddi_put16(a, b, c)
#define	SCF_P_DDI_PUT32(a, b, c)	ddi_put32(a, b, c)
#define	SCF_P_DDI_GET8(a, b)		ddi_get8(a, b)
#define	SCF_P_DDI_GET16(a, b)		ddi_get16(a, b)
#define	SCF_P_DDI_GET32(a, b)		ddi_get32(a, b)

#define	SCF_CHECK_INSTANCE(a)		(a == SCF_USER_INSTANCE)

#define	SCF_DBG_DRV_TRACE_TBL
#define	SC_DBG_DRV_TRACE(a, b, c, d)
#define	SCF_DBG_DRV_TRACE_INIT

#define	SCFDBGMSG(f, s)
#define	SCFDBGMSG1(f, s, a)
#define	SCFDBGMSG2(f, s, a, b)
#define	SCFDBGMSG3(f, s, a, b, c)
#define	SCFDBGMSG4(f, s, a, b, c, d)

#define	SCF_DBG_INIT
#define	SCF_DBG_IOMP_INSTANCE
#define	SCF_DBG_IOMP_PROC
#define	SCF_DBG_IOCTL_PROC
#define	SCF_DBG_IOMP_ADD(a)
#define	SCF_DBG_IOMP_DEL(a)
#define	SCF_DBG_IOMP_FREE
#define	SCF_DBG_TEST_TIMER_STOP
#define	SCF_DBG_TEST_INTR(a)
#define	SCF_DBG_TEST_INTR_SCFINT(a)
#define	SCF_DBG_TEST_INTR_CMDEND(a)
#define	SCF_DBG_MAKE_RXSUM(a, b)
#define	SCF_DBG_MAKE_RXSUM_L(a, b)
#define	SCF_DBG_NO_INT_REASON
#define	SCF_DBG_TEST_INTR_POFF
#define	SCF_DBG_TEST_DSENS(a, b, c)
#define	SCF_DBG_TEST_SEND_CMD(a, b)
#define	SCF_DBG_MAKE_PATH_CHECK(a)
#define	SCF_DBG_MAKE_ONLINE(a)
#define	SCF_DBG_MAKE_OFFLINE_CHECK(a)
#define	SCF_DBG_RTN_MAKE_CMD_READY
#define	SCF_DBG_MAKE_CMD_BUSY(a, b)
#define	SCF_DBG_TEST_ALIVE_START(a)
#define	SCF_DBG_TEST_ALIVE_STOP(a)
#define	SCF_DBG_TEST_INTR_DSCP_DSR(a)
#define	SCF_DBG_TEST_INTR_DSCP_RXTX(a, b)
#define	SCF_DBG_MAKE_LOOPBACK(a)
#define	SCF_DBG_MAKE_NO_DSCP_PATH(a)
#define	SCF_DBG_TEST_TXREQ_SEND(a, b)
#define	SCF_DBG_TEST_MAP_REGS(a)
#define	SCF_DBG_TEST_UNMAP_REGS(a)
#define	SCF_DBG_DDI_PUT(a, b)
#define	SCF_DBG_DDI_GET(a)
#define	SCF_DBG_XSCF_SET_STATUS
#define	SCF_DBG_XSCF_SET_LENGTH

#endif	/* DEBUG */

/*
 * SCF driver common table
 */
typedef struct scf_comtbl {
	/* mutex resource */
	kmutex_t	all_mutex;	/* scf driver mutex */
	kmutex_t	trc_mutex;	/* scf driver trace mutex */
	kmutex_t	attach_mutex;	/* attach mutex */
	kmutex_t	si_mutex;	/* softintr mutex */

	/* cookie */
	ddi_iblock_cookie_t	iblock_cookie;		/* SCFI-Interrupt */
	ddi_iblock_cookie_t	soft_iblock_cookie;	/* softintr cookie */

	/* condition variables */
	kcondvar_t	cmd_cv;		/* command send */
	kcondvar_t	cmdwait_cv;	/* command send wait */
	kcondvar_t	cmdend_cv;	/* command send end */
	kcondvar_t	cmdbusy_cv;	/* command busy send wait */
	kcondvar_t	rsense_cv;	/* report sense */
	kcondvar_t	rdcsense_cv;	/* SCFIOCRDCTRL & sense */
	kcondvar_t	rdctrl_cv;	/* SCFIOCRDCTRL command */
	kcondvar_t	getevent_cv;	/* SCFIOCGETEVENT */
	kcondvar_t	suspend_wait_cv; /* suspend cv */

	/* ID */
	ddi_softintr_t	scf_softintr_id; /* softintr id */

	/* SCF state table address */
	scf_state_t	*scf_pseudo_p;	/* pseudo device state */
	scf_state_t	*scf_exec_p;	/* SCF exec state */
	scf_state_t	*scf_path_p;	/* SCF path change state */
	scf_state_t	*scf_wait_p;	/* Standby state */
	scf_state_t	*scf_stop_p;	/* Stop state */
	scf_state_t	*scf_err_p;	/* error state */
	scf_state_t	*scf_disc_p;	/* Disconnect state */
	scf_state_t	*scf_suspend_p;	/* Suspend stste */

	/* flag and counter */
	uint_t	resource_flag;		/* resource allocate flag */
	uint_t	scf_event_flag;		/* SCF event flag */
	uint_t	poff_factor;		/* Shutdown factor */
	uint_t	cmd_busy;		/* cmd send busy flag */
	uint_t	cmd_wait;		/* cmd send wait counter */
	uint_t	cmd_busy_wait;		/* cmd busy send wait flag */
	uint_t	cmd_end_wait;		/* cmd send end wait flag */
	uint_t	rdctrl_busy;		/* SCFIOCRDCTRL busy flag */
	uint_t	rdctrl_end_wait;	/* SCFIOCRDCTRL cmd end wait flag */
	uint_t	alive_running;		/* Alive check exec flag */
	uint_t	watchdog_after_resume;	/* watch cpu after resume flag */
	uint_t	scf_shutdown_exec_flag;	/* SCFIOCSHUTDOWN call flag */
	uint_t	shutdown_start_reported; /* SCFIOCREPORTSTAT(shutdown) call */
	uint_t	scf_exec_cmd_id;	/* SCF command exec id */
	uint_t	scf_cmd_exec_flag;	/* SCF command exec flag */
	uint_t	putinfo_exec_flag;	/* scf_service_putinfo() exec flag */
	uint_t	getinfo_exec_flag;	/* scf_service_getinfo() exec flag */
	uint_t	debugxscf_flag;		/* SCFIOCCMDTHROUGH exec flag */
	uint_t	suspend_wait;		/* Suspend wait flag */
	uint_t	suspend_flag;		/* Suspend flag */
	uint_t	scf_suspend_sendstop;	/* Suspend send stop flag */
	uint_t	scf_softintr_dscp_kicked; /* Softintr DSCP kick flag */
	uint_t	int_reason_retry;	/* INT_REASON retry flag */
	uint_t	scf_alive_int_count;	/* Alive check interrupt counter */
	uint_t	reload_conf_flag;	/* configuration file load flag */
	uint_t	scf_cmd_resend_flag;	/* SCF command re send flag */
	uint_t	scf_cmd_resend_req;	/* SCF command re send flag */
	uint_t	path_stop_flag;		/* command send stop flag */

	uint_t	report_buf_ful_rcnt;	/* Report command BUF_FUL */
					/* retry counter */
	uint_t	report_rci_busy_rcnt;	/* Report command RCI_BUSY */
					/* retry counter */
	uint_t	path_change_rcnt;	/* SCF path change retry counter */

	/* status information */
	ushort_t scf_mode_sw;		/* Mode switch status */
	uchar_t	scf_poff_id;		/* POFF interrupt id */
	uint_t	scf_shutdownreason;	/* Shutdown reason */
	uint_t	scf_status;		/* XSCF status */

	/* SCF command control code */
	uint_t	scf_pchg_event_sub;	/* SCF path change status */
	uint_t	scf_poff_event_sub;	/* POFF event status */
	uint_t	scf_shut_event_sub;	/* SHUTDOWN event status */
	uint_t	scf_alive_event_sub;	/* ALIVE event status */
	uint_t	scf_report_event_sub;	/* REPORT processing status */

	/* SCF command control */
	scf_cmd_t	*scf_cmdp;	/* SCF command table address */
	uint_t	scf_last_report;	/* Last report */
	uint_t	scf_rem_rxbuff_size;	/* remainder receive data size */

	/* SCF command interrupt area */
	scf_cmd_t	scf_cmd_intr;	/* SCF comand table(Interrupt use) */
	uchar_t	scf_sbuf[SCF_S_CNT_16];	/* Tx Small buffer table */
	uchar_t	scf_rbuf[SCF_INT_CNT_MAX]; /* Rx Large buffer table */
	uchar_t	last_event[SCF_INT_REASON_SIZE]; /* Last event table */

	/* ioctl control area */
	scfreport_t	*report_sensep;	/* SCFIOCGETREPORT save address */
	int	report_sense_top;	/* SCFIOCGETREPORT save offset(push) */
	int	report_sense_oldest;	/* SCFIOCGETREPORT save offset(pop) */
	uint_t	rcidown_event_flag;	/* SCFIOCGETREPORT rci down flag */
	scfreport_t	scfreport_rcidown; /* SCFIOCGETREPORT rci down area */

	scfevent_t	*getevent_sensep; /* SCFIOCGETEVENT save address */
	int	getevent_sense_top;	/* SCFIOCGETEVENT save offset(push) */
	int	getevent_sense_oldest;	/* SCFIOCGETEVENT save offset(pop) */

	scfeventlist_t	getevent_tbl;	/* SCFIOCEVENTLIST list table */

	uchar_t	lcd_seq_mes[SCF_WRLCD_MAX];
				/* SCFIOCCLEARLCD and SCFIOCWRLCD message */

	uchar_t	rdctrl_sense_category_code;	/* SCFIOCRDCTL sub command */
	uchar_t	rdctrl_sense[SCF_SBUFR_SIZE];	/* SCFIOCRDCTL information */

	/* memo counter */
	uint_t	attach_count;		/* SCF attach count */

	/* error memo counter */
	uint_t	memo_cmd_to_cnt;	/* CMD timeout memo */
	uint_t	scf_rsense_overflow;	/* SCFIOCGETREPORT overflow memo */
	uint_t	scf_getevent_overflow;	/* SCFIOCGETEVENT overflow memo */

	/* Unclaimed interrupt register log */
	uint_t	scf_unclamed_cnt;	/* Unclaimed interrupt counter */
	struct {
		uint16_t	CONTROL; /* SCF Control register */
		uint16_t	INT_ST;	/* SCF Interrupt Status register */
		uint16_t	COMMAND; /* SCF command register */
		uint16_t	STATUS;	/* SCF status register */
		uint32_t	STATUS_ExR; /* SCFI status extended register */
		uint8_t		DSR;	/* DSCP buffer status register */
	} scf_unclamed;

	/* kstat private area */
	scf_kstat_private_t	*kstat_private;	/* for kstat area */

	SCF_DBG_DRV_TRACE_TBL		/* SCF driver trace */
} scf_comtbl_t;


/*
 * (resource_flag) macro for resource allocate flag
 */
#define	DID_MUTEX_ATH		(1 << 0)
#define	DID_MUTEX_ALL		(1 << 1)
#define	DID_MUTEX_TRC		(1 << 2)
#define	DID_MUTEX_SI		(1 << 3)

#define	DID_CV			(1 << 4)
#define	DID_KSTAT		(1 << 5)
#define	DID_ALLOCBUF		(1 << 6)
#define	DID_ALIVECHECK		(1 << 7)

#define	DID_MNODE		(1 << 8)
#define	DID_SOFTINTR		(1 << 9)

#define	DID_DSCPINIT		(1 << 10)

/*
 * XSCF status defaine (scf_status)
 */
#define	SCF_STATUS_OFFLINE	0	/* XSCF status is offline */
#define	SCF_STATUS_ONLINE	1	/* XSCF status is online */
#define	SCF_STATUS_UNKNOWN	2	/* XSCF status is unknown */

/*
 * SCF command control status
 */
#define	EVENT_SUB_NONE		0	/* None status */
/* (scf_pchg_event_sub) SCF path change status */
#define	EVENT_SUB_PCHG_WAIT	1	/* SCF path change command wait */
#define	EVENT_SUB_PCHG_EXEC	2	/* SCF path change command exec */
/* (scf_poff_event_sub) POFF event status */
#define	EVENT_SUB_POFF_WAIT	1	/* POFF factor command wait */
#define	EVENT_SUB_POFF_EXEC	2	/* POFF factor command exec */
/* (scf_shut_event_sub) SHUTDOWN event status */
#define	EVENT_SUB_SHUT_WAIT	1	/* command wait (SHUTDOWN) */
#define	EVENT_SUB_SHUT_EXEC	2	/* command exec (SHUTDOWN) */
#define	EVENT_SUB_WAIT		3	/* command wait (EVENT) */
#define	EVENT_SUB_EXEC		4	/* command exec (EVENT) */
/* (scf_alive_event_sub) ALIVE event status */
#define	EVENT_SUB_ALST_WAIT	1	/* Alive start command wait */
#define	EVENT_SUB_ALST_EXEC	2	/* Alive start command exec */
#define	EVENT_SUB_ALSP_WAIT	3	/* Alive stop command wait */
#define	EVENT_SUB_ALSP_EXEC	4	/* Alive stop command exec */
/* (scf_report_event_sub) REPORT processing status */
#define	EVENT_SUB_REPORT_RUN_WAIT	1 /* Report (runnning) send wait */
#define	EVENT_SUB_REPORT_RUN_EXEC	2 /* Report (runnning) send exec */
#define	EVENT_SUB_REPORT_SHUT_WAIT	3 /* Report (shutdown) send wait */
#define	EVENT_SUB_REPORT_SHOT_EXEC	4 /* Report (shutdown) send exec */

/* (scf_last_report) define */
#define	NOT_SEND_REPORT		0xffffffff	/* Not report send */

/* scf_cmd_resend_req define */
#define	RESEND_IOCTL		(1 << 0) /* Comand from ioctl */
#define	RESEND_PCHG		(1 << 1) /* SCF Path change command */
#define	RESEND_POFF		(1 << 2) /* Power supply control command */
#define	RESEND_SHUT		(1 << 3) /* Event information command */
#define	RESEND_ALST		(1 << 4) /* Alive check command (start) */
#define	RESEND_ALSP		(1 << 5) /* Alive check command (stop) */
#define	RESEND_REPORT_RUN	(1 << 6) /* Report command (system running) */
#define	RESEND_REPORT_SHUT	(1 << 7) /* Report command (shutdown start) */

#ifdef	__cplusplus
}
#endif

#endif /* _SCFSYS_H */
