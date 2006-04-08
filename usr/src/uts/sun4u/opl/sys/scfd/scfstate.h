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

#ifndef	_SCFSTATE_H
#define	_SCFSTATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scfd/scfreg.h>

/*
 * SCF driver's software state structure
 */
typedef struct scf_state {
	/* SCF device infomation pointer */
	dev_info_t	*dip;			/* device infomation */

	/* SCF state table address */
	struct scf_state	*next;		/* next state addr */

	/* flag */
	uint_t		resource_flag;		/* resource allocate flag */
	uint_t		scf_herr;		/* Hard error flag */

	/* Register hardware register */
	scf_regs_t	*scf_regs;		/* SCF register */
	scf_regs_c_t	*scf_regs_c;		/* SCF contorol register */
	scf_dscp_sram_t	*scf_dscp_sram;		/* SCF DSCP SRAM */
	scf_sys_sram_t	*scf_sys_sram;		/* SCF system SRAM */
	scf_interface_t	*scf_interface;		/* SCF interface block */
	scf_if_drvtrc_t	*scf_reg_drvtrc;	/* SRAM driver trace */

	/* Register data access handle */
	ddi_acc_handle_t scf_regs_handle;	/* SCF register */
	ddi_acc_handle_t scf_regs_c_handle;	/* SCF contorol register */
	ddi_acc_handle_t scf_dscp_sram_handle;	/* SCF DSCP SRAM */
	ddi_acc_handle_t scf_sys_sram_handle;	/* SCF system SRAM */
	ddi_acc_handle_t scf_interface_handle;	/* SCF interface block */
	ddi_acc_handle_t scf_reg_drvtrc_handle;	/* SRAM driver trace block */

	/* Register size */
	off_t		scf_dscp_sram_len;	/* SCF system SRAM */
	off_t		scf_sys_sram_len;	/* SCF DSCP SRAM */
	off_t		scf_interface_len;	/* SCF interface block */
	off_t		scf_reg_drvtrc_len;	/* SRAM driver trace */

	/* error retry count */
	uint_t		tesum_rcnt;		/* Send sum check error */
	uint_t		resum_rcnt;		/* Recv sum check error */
	uint_t		cmd_to_rcnt;		/* Command timeout error */
	uint_t		devbusy_to_rcnt;	/* Command busy timeout error */
	uint_t		online_to_rcnt;		/* SCF online timeout error */

	/* error counter memo */
	uint_t		memo_cmd_to_cnt;	/* CMD timeout counter */
	uint_t		no_int_dsr_cnt;		/* DSR no interrupt counter */
	uint_t		fail_count;		/* SCF path fail counter */

	/* IOMP control area */
	int		instance;		/* instance */
	int		path_status;		/* IOMP path status */
	int		old_path_status;	/* IOMP old path status */

	/* Register memo */
	uint16_t	reg_control;		/* SCF INT control */
	uint16_t	reg_int_st;		/* SCF INT status */
	uint16_t	reg_command;		/* SCF command */
	uint16_t	reg_status;		/* SCF status */
	uint32_t	reg_tdata[4];		/* SCF Tx data */
	uint32_t	reg_rdata[4];		/* SCF Rx data0 */
	uint8_t		reg_command_exr;	/* SCF command extended */
	uint32_t	reg_status_exr;		/* SCF status extended */
	uint8_t		reg_acr;		/* Alive check */
	uint8_t		reg_atr;		/* Alive timer */
	uint8_t		reg_dcr;		/* DSCP buffer control */
	uint8_t		reg_dsr;		/* DSCP buffer status */
	uint16_t	reg_txdcr_c_flag;	/* DSCP Tx descriptor control */
	uint16_t	reg_txdcr_c_offset;	/* DSCP Tx descriptor control */
	uint32_t	reg_txdcr_c_length;	/* DSCP Tx descriptor control */
	uint16_t	reg_txdsr_c_flag;	/* DSCP Tx descriptor status */
	uint16_t	reg_txdsr_c_offset;	/* DSCP Tx descriptor status */
	uint16_t	reg_rxdcr_c_flag;	/* DSCP Rx descriptor control */
	uint16_t	reg_rxdcr_c_offset;	/* DSCP Rx descriptor control */
	uint32_t	reg_rxdcr_c_length;	/* DSCP Rx descriptor control */
	uint16_t	reg_rxdsr_c_flag;	/* DSCP Rx descriptor status */
	uint16_t	reg_rxdsr_c_offset;	/* DSCP Rx descriptor status */

	/* SRAM driver trace memo */
	uint32_t	memo_DATA_TOP;		/* trace data top offset */
	uint32_t	memo_DATA_LAST;		/* trace data last offset */
	uint32_t	memo_DATA_WRITE;	/* trace data write offset */
	scf_drvtrc_ent_t	memo_scf_drvtrc; /* SRAM driver trace */

	/* SCF device value */
	char		pathname[256];		/* SCFC pathname */
} scf_state_t;

/*
 * (resource_flag) macro for resource allocate flag
 */
#define	S_DID_REG1		(1 << 0)
#define	S_DID_REG2		(1 << 1)
#define	S_DID_REG3		(1 << 2)
#define	S_DID_REG4		(1 << 3)
#define	S_DID_REG5		(1 << 4)
#define	S_DID_REG6		(1 << 5)

#define	S_DID_INTR		(1 << 8)
#define	S_DID_MNODE		(1 << 9)

#define	S_DID_REGENB		((uint_t)1 << 31)

/*
 * (scf_herr) hard error code
 */
#define	HERR_TESUM		(1 << 0)
#define	HERR_RESUM		(1 << 1)
#define	HERR_CMD_RTO		(1 << 2)
#define	HERR_BUSY_RTO		(1 << 3)

#define	HERR_DSCP_INTERFACE	(1 << 8)
#define	HERR_DSCP_ACKTO		(1 << 9)
#define	HERR_DSCP_ENDTO		(1 << 10)

#define	HERR_EXEC		((uint_t)1 << 31)

/* ddi_dev_regsize(), ddi_regs_map_setup register index number define */
#define	REG_INDEX_SCF		0	/* SCF register */
#define	REG_INDEX_SCFCNTL	1	/* SCF contorol register */
#define	REG_INDEX_DSCPSRAM	2	/* SCF DSCP SRAM */
#define	REG_INDEX_SYSTEMSRAM	3	/* SCF system SRAM  */
#define	REG_INDEX_INTERFACE	4	/* SCF interface block(driver trace) */

/*
 * scf_path_check()/scf_offline_check() return code
 */
#define	SCF_PATH_ONLINE		0	/* SCF path exec state */
#define	SCF_PATH_OFFLINE	1	/* SCF path offline state */
#define	SCF_PATH_OFFLINE_DRV	2	/* SCF path offline-drv state */
#define	SCF_PATH_CHANGE		3	/* SCF path change state */
#define	SCF_PATH_HALT		(-1)	/* SCF path halt state */

/*
 * scf_cmdbusy_check() return code
 */
#define	SCF_COMMAND_READY	0	/* SCF command ready state */
#define	SCF_COMMAND_BUSY	1	/* SCF command busy state */
#define	SCF_COMMAND_BUSY_DRV	2	/* SCF command busy-drv state */

/*
 * scf_dscp_start()/scf_dscp_stop() arg "factor" value
 */
#define	FACTOR_ONLINE		0	/* Factor SCF online */
#define	FACTOR_OFFLINE		1	/* Factor SCF offline */
#define	FACTOR_PATH_CHG		2	/* Factor SCF path change */
#define	FACTOR_PATH_STOP	3	/* Factor IOMP all path stop */
#define	FACTOR_PATH_HALT	4	/* Factor SCF path halt */

/* path status (path_status) */
#define	PATH_STAT_ACTIVE	1
#define	PATH_STAT_STANDBY	2
#define	PATH_STAT_STOP		3
#define	PATH_STAT_FAIL		4
#define	PATH_STAT_DISCON	5
#define	PATH_STAT_ENCAP		6
#define	PATH_STAT_EMPTY		0

#ifdef	__cplusplus
}
#endif

#endif	/* _SCFSTATE_H */
