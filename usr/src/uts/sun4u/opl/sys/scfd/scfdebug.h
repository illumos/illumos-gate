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

#ifndef	_SCFDEBUG_H
#define	_SCFDEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scfd/scfdscp.h>

/*
 * ioctl
 */
#define	SCFIOCDEBUG		'd'<<8

/*
 * ioctl
 */
#define	SCFIOCCMDTHROUGH	(SCFIOC|1|0xf0000000)
#define	SCFIOCTEST		(SCFIOCDEBUG|2|0x80040000)

/* SCFIOCCMDTHROUGH */
typedef struct scfcmdthrough {
	unsigned short	mode;
	unsigned short	cmdtype;
	unsigned short	code;
	unsigned int	sbufleng;
	unsigned int	rbufleng;
	unsigned short	status;
	unsigned char	sbuf[65536 + 16];
	unsigned char	rbuf[1024 * 512];
} scfcmdthrough_t;
/* for mode field */
#define	SCF_CMDTHROUGH_START	0	/* command through start */
#define	SCF_CMDTHROUGH_STOP	1	/* command through stop */
#define	SCF_CMDTHROUGH_CMD	2	/* command through */
/* for cmdtype field */
#define	SCF_CMDTHROUGH_TYPE_NN	0	/* WRITE:Nothing READ:Nothing */
#define	SCF_CMDTHROUGH_TYPE_NS	1	/* WRITE:Nothing READ:Small   */
#define	SCF_CMDTHROUGH_TYPE_NL	2	/* WRITE:Nothing READ:Larg    */
#define	SCF_CMDTHROUGH_TYPE_SN	3	/* WRITE:Small	 READ:Nothing */
#define	SCF_CMDTHROUGH_TYPE_SS	4	/* WRITE:Small	 READ:Small   */
#define	SCF_CMDTHROUGH_TYPE_SL	5	/* WRITE:Small	 READ:Larg    */
#define	SCF_CMDTHROUGH_TYPE_LN	6	/* WRITE:Larg	 READ:Nothing */
#define	SCF_CMDTHROUGH_TYPE_LS	7	/* WRITE:Larg	 READ:Small   */

#define	TEST_INFO_MAX		32

/* SCFIOCTEST */
typedef struct scf_scfioctest_tbl {
	uint_t		mode;
	uint_t		rci_addr;
	uint_t    	data[2];
	uint_t    	rsv1;
	uint_t    	rsc2;
	uint_t    	scf_debugxscf;
	uint_t    	rtncode;
	uint_t		info[TEST_INFO_MAX];
	uint8_t		rdata[SRAM_MAX_SYSTEM];
} scf_scfioctest_t;
/* for mode field (Low 2byte) */
#define	TEST_MODE_MASK_HIGHT		0xffff0000
#define	TEST_MODE_MASK_LOW		0x0000ffff
#define	TEST_NONE			0x00000000

/* Config mode : for mode field (Low 2byte) */
#define	TEST_CONF			0x00000100
#define	TEST_CONF_RESET			0x00000100
#define	TEST_CONF_DEBUG_MSG		0x00000101
#define	TEST_CONF_CMD_BUSY		0x00000181
#define	TEST_CONF_DSCP_LOOPBACK		0x00000182
#define	TEST_CONF_SCF_PATH		0x00000183

/* Interrupt mode : for mode field (Low 2byte) */
#define	TEST_INT			0x00000200
#define	TEST_INT_RESET			0x00000200
#define	TEST_INT_SYS			0x00000201
#define	TEST_INT_SYS_POFF		0x00000202
#define	TEST_INT_SYS_EVENT		0x00000203
#define	TEST_INT_DSCP			0x00000204

/* SYS func call mode : for mode field (Low 2byte) */
#define	TEST_SYS_CALL			0x00001000
#define	TEST_SYS_CALL_RESET		0x00001000
#define	TEST_SYS_CALL_INT		0x00001001

/* DSCP func call mode : for mode field (Low 2byte) */
#define	TEST_DSCP_CALL			0x00001100
#define	TEST_DSCP_CALL_RESET		0x00001100
#define	TEST_DSCP_CALL_INIT		0x00001101
#define	TEST_DSCP_CALL_FINI		0x00001102
#define	TEST_DSCP_CALL_PUTMSG		0x00001103
#define	TEST_DSCP_CALL_CANGET		0x00001104
#define	TEST_DSCP_CALL_GETMSG		0x00001105
#define	TEST_DSCP_CALL_FLUSH		0x00001106
#define	TEST_DSCP_CALL_CTRL		0x00001107
#define	TEST_DSCP_CALL_OTHER		0x00001108

/* OSESCF func callmode : for mode field (Low 2byte) */
#define	TEST_OSESCF_CALL		0x00001200
#define	TEST_OSESCF_CALL_RESET		0x00001200
#define	TEST_OSESCF_CALL_PUTINFO	0x00001201
#define	TEST_OSESCF_CALL_GETINFO	0x00001202

/* FMEM OSESCF func callmode : for mode field (Low 2byte) */
#define	TEST_FMEM_START			0x00001211
#define	TEST_FMEM_END			0x00001212
#define	TEST_FMEM_CANCEL		0x00001213

/*
 * External vwlue
 */
extern uint_t	scf_debug_test_sys_int_flag;
extern uint_t	scf_debug_test_rxbuff_nosum_check_flag;
extern uint_t	scf_debug_test_sys_event_flag;
extern uint_t	scf_debug_test_sys_poff_flag;
extern uint_t	scf_debug_test_dscp_int_flag;
extern uint_t	scf_debug_test_cmdr_busy;
extern uint_t	scf_debug_test_cmdexr_busy;
extern uint_t	scf_debug_test_copyin;
extern uint_t	scf_debug_test_copyout;
extern uint_t	scf_debug_test_kmem;
extern uint_t	scf_debug_test_path_check;
extern uint_t	scf_debug_test_path_check_rtn;
extern uint_t	scf_debug_test_offline_check;
extern uint_t	scf_debug_test_offline_check_rtn;
extern uint_t	scf_debug_test_dscp_call_flag;
extern uint_t	scf_debug_test_osescf_call_flag;

extern uint_t	scf_no_make_sum_s;
extern uint_t	scf_no_make_sum_l;

extern uint_t	scf_debug_nofirm_sys;
extern uint_t	scf_debug_scfint_time;
extern uint_t	scf_debug_nofirm_dscp;
extern uint_t	scf_debug_idbcint_time;
extern uint_t	scf_debug_test_dscp_loopback;
extern uint_t	scf_debug_nooffline_check;
extern uint_t	scf_debug_no_dscp_path;
extern uint_t	scf_debug_no_alive;
extern uint_t	scf_debug_norxsum_check;
extern uint_t	scf_debug_no_int_reason;
extern uint_t	scf_debug_no_device;

/*
 * External function
 */
extern int	scf_debug_cmdthrough(intptr_t arg, int mode);
extern int	scf_debug_test(intptr_t arg, int mode);
extern void	scf_debug_test_intr_tout(void *arg);
extern void	scf_debug_test_intr(scf_state_t *statep);
extern void	scf_debug_test_intr_scfint(scf_state_t *statep);
extern void	scf_debug_test_intr_cmdend(scf_state_t *statep);
extern void	scf_debug_test_intr_poff(void);
extern void	scf_debug_test_dsens(struct scf_cmd *scfcmdp,
	scf_int_reason_t *int_rp, int len);
extern void	scf_debug_test_intr_dscp_dsr(scf_state_t *statep);
extern void	scf_debug_test_intr_dscp_rxtx(scf_state_t *statep, uint8_t dsr);
extern void	scf_debug_test_alive_start(scf_state_t *statep);
extern void	scf_debug_test_alive_stop(scf_state_t *statep);
extern void	scf_debug_test_alive_intr_tout(void *arg);
extern void	scf_debug_test_send_cmd(struct scf_state *statep,
	struct scf_cmd *scfcmdp);
extern void	scf_debug_test_txreq_send(scf_state_t *statep,
	scf_dscp_dsc_t *dsc_p);
extern void	scf_debug_test_event_handler(scf_event_t mevent, void *arg);
extern void	scf_debug_test_timer_stop(void);
extern void	scf_debug_test_map_regs(scf_state_t *statep);
extern void	scf_debug_test_unmap_regs(scf_state_t *statep);

/*
 * Debug flag and value define
 */
/* scf_debug_test_sys_int_flag */
#define	SCF_DBF_SYS_INTR_OFF		0
#define	SCF_DBF_SYS_INTR_ON		1

/* scf_debug_test_rxbuff_nosum_check_flag */
#define	SCF_DBF_RXBUFF_NOSUM_CHECK_OFF	0
#define	SCF_DBF_RXBUFF_NOSUM_CHECK_ON	1

/* scf_debug_test_sys_event_flag */
#define	SCF_DBF_SYS_EVENT_OFF		0
#define	SCF_DBF_SYS_EVENT_ON		1

/* scf_debug_test_sys_poff_flag */
#define	SCF_DBF_SYS_POFF_OFF		0
#define	SCF_DBF_SYS_POFF_ON		1

/* scf_debug_test_dscp_int_flag */
#define	SCF_DBF_DSCP_INT_OFF		0
#define	SCF_DBF_DSCP_INT_ON		1

/* scf_debug_test_cmdr_busy */
#define	SCF_DBC_CMDR_BUSY_CLEAR		0x00000000

/* scf_debug_test_cmdexr_busy */
#define	SCF_DBC_CMDEXR_BUSY_CLEAR	0x00000000

/* scf_debug_test_copyin */
#define	SCF_DBC_COPYIN_CLEAR		0x00000000

/* scf_debug_test_copyout */
#define	SCF_DBC_COPYOUT_CLEAR		0x00000000

/* scf_debug_test_kmem */
#define	SCF_DBC_KMEM_CLEAR		0x00000000

/* scf_debug_test_path_check */
#define	SCF_DBC_PATH_CHECK_CLEAR	0x00000000

/* scf_debug_test_path_check_rtn */
#define	SCF_DBC_PATH_CHECK_RTN_CLEAR	0x00000000

/* scf_debug_test_offline_check */
#define	SCF_DBC_OFFLINE_CHECK_CLEAR	0x00000000

/* scf_debug_test_offline_check_rtn */
#define	SCF_DBC_OFFLINE_CHECK_RTN_CLEAR	0x00000000

/* scf_debug_test_dscp_call_flag */
#define	SCF_DBF_DSCP_CALL_OFF		0
#define	SCF_DBF_DSCP_CALL_ON		1

/* scf_debug_test_osescf_call_flag */
#define	SCF_DBF_OSESCF_CALL_OFF		0
#define	SCF_DBF_OSESCF_CALL_ON		1

/* scf_no_make_sum_s */
#define	SCF_DBF_NO_MAKE_SUM_S_OFF	0
#define	SCF_DBF_NO_MAKE_SUM_S_ON	1

/* scf_no_make_sum_l */
#define	SCF_DBF_NO_MAKE_SUM_L_OFF	0
#define	SCF_DBF_NO_MAKE_SUM_L_ON	1

/* scf_debug_nofirm_sys */
#define	SCF_DBF_NOFIRM_SYS_OFF		0
#define	SCF_DBF_NOFIRM_SYS_ON		1

/* scf_debug_scfint_time */
#define	SCF_DBT_SCFINT_TIME_100MS	100

/* scf_debug_nofirm_dscp */
#define	SCF_DBF_NOFIRM_DSCP_OFF		0
#define	SCF_DBF_NOFIRM_DSCP_ON		1

/* scf_debug_idbcint_time */
#define	SCF_DBT_IDBCINT_TIME_100MS	100

/* scf_debug_test_dscp_loopback */
#define	SCF_DBF_DSCP_LOOPBACK_OFF	0
#define	SCF_DBF_DSCP_LOOPBACK_ON	1

/* scf_debug_nooffline_check */
#define	SCF_DBF_NOOFFLINE_CHECK_OFF	0
#define	SCF_DBF_NOOFFLINE_CHECK_ON	1

/* scf_debug_no_dscp_path */
#define	SCF_DBF_NO_DSCP_PATH_OFF	0
#define	SCF_DBF_NO_DSCP_PATH_ON		1

/* scf_debug_no_alive */
#define	SCF_DBF_NO_ALIVE_OFF		0
#define	SCF_DBF_NO_ALIVE_ON		1

/* scf_debug_norxsum_check */
#define	SCF_DBF_NORXSUM_CHECK_OFF	0
#define	SCF_DBF_NORXSUM_CHECK_ON	1

/* scf_debug_no_int_reason */
#define	SCF_DBF_NO_INT_REASON_OFF	0
#define	SCF_DBF_NO_INT_REASON_ON	1

/* scf_debug_no_device */
#define	SCF_DBF_NO_DEVICE_OFF		0
#define	SCF_DBF_NO_DEVICE_ON		1

#ifdef	__cplusplus
}
#endif

#endif /* _SCFDEBUG_H */
