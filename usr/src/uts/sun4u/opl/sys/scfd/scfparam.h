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

#ifndef _SCFPARAM_H
#define	_SCFPARAM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scfd/scfsys.h>
#include <sys/scfd/scfostoescf.h>

/*
 * Common table
 */
extern scf_comtbl_t	scf_comtbl;	/* SCF driver common table */
extern void	*scfstate;		/* root of soft state */
extern char	*scf_driver_name;	/* SCF driver name */

/*
 * SCF driver control mode
 */
extern uint_t	scf_halt_proc_mode;	/* SCFHALT after processing mode */
extern uint_t	scf_last_detach_mode;	/* Last detach mode */

/*
 * SRAM trace data size
 */
extern uint_t	scf_sram_trace_data_size;	/* Get SRAM trace data size */
extern uint_t	scf_trace_rxdata_size;	/* Rx data trace size */

/*
 * Wait timer value (Micro-second)
 */
extern uint_t	scf_rdctrl_sense_wait;
				/* SCFIOCRDCTRL wait timer value (60s) */

/*
 * Wait timer value
 */
extern uint_t	scf_buf_ful_rtime;
				/* Buff full wait retry timer value (500ms) */
extern uint_t	scf_rci_busy_rtime;
				/* RCI busy wait retry timer value (3s) */

/*
 * Re-try counter
 */
extern uint_t	scf_buf_ful_rcnt;	/* Buff full retry counter */
extern uint_t	scf_rci_busy_rcnt;	/* RCI busy retry counter */
extern uint_t	scf_tesum_rcnt;		/* Tx sum retry counter */
extern uint_t	scf_resum_rcnt;		/* Rx sum retry counter */
extern uint_t	scf_cmd_to_rcnt;	/* Command to retry counter */
extern uint_t	scf_devbusy_wait_rcnt;	/* Command device busy retry counter */
extern uint_t	scf_online_wait_rcnt;	/* SCF online retry counter */
extern uint_t	scf_path_change_max;	/* SCF path change retry counter */

/*
 * Max value
 */
extern uint_t	scf_report_sense_pool_max; /* Report sense max */
extern uint_t	scf_getevent_pool_max;	/* SCFIOCGETEVENT max */
extern uint_t	scf_rci_max;		/* RCI device max */
extern uint_t	scf_rxbuff_max_size;	/* SCF command data division max size */

/*
 * Poff factor (reported on shutdown start)
 */
unsigned char	scf_poff_factor[2][3];
#define	SCF_POFF_FACTOR_NORMAL	0
#define	SCF_POFF_FACTOR_PFAIL	1

/*
 * Alive check parameter
 */
extern uchar_t	scf_alive_watch_code;	/* Watch code for SCF driver */
extern uchar_t	scf_alive_phase_code;	/* Watch phase code */
extern uchar_t	scf_alive_interval_time;	/* interval time */
extern uchar_t	scf_alive_monitor_time;		/* monitor timeout */
extern ushort_t	scf_alive_panic_time;		/* panic timeout */

extern uchar_t	scf_acr_phase_code;	/* Alive check register phase code */

/*
 * FMEMA interface
 */
extern caddr_t	scf_avail_cmd_reg_vaddr; /* SCF Command register address */

/*
 * Send break interface
 */
extern int	scf_dm_secure_mode;	/* secure mode */

/*
 * SCF driver version interface
 */
extern ushort_t	scf_scfd_comif_version;	/* SCF driver version */

/*
 * XSCF version interface
 */
extern ushort_t	scf_xscf_comif_version;	/* XSCF version */

/*
 * ioctl control value and flag
 */
extern int	scf_save_hac_flag;	/* Host address disp flag */
extern scfhac_t scf_save_hac;		/* Host address disp save */

/*
 * Register read sync value
 */
extern uint8_t	scf_rs8;
extern uint16_t	scf_rs16;
extern uint32_t	scf_rs32;

/*
 * Panic value
 */
extern uint_t	scf_panic_reported;	/* Panic report after */
extern uint_t	scf_panic_report_maxretry; /* Same as busy_maxretry */
extern uint_t	scf_cmdend_wait_time_panic;
				/* SCF command end wait timer value (1s) */
extern uint_t	scf_cmdend_wait_rcnt_panic; /* SCF command end retry counter */

extern uint_t	scf_panic_exec_wait_time; /* Panic wait timer value (100ms) */
extern uint_t	scf_panic_exec_flag;	/* Panic exec flag */
extern uint_t	scf_panic_exec_flag2;	/* Panic exec flag (report send) */

/*
 * Panic trace
 */
extern ushort_t	scf_panic_trc_w_off;	/* Panic trcae next write offset */
extern uint16_t scf_panic_trc_command;	/* Panic SCF command register memo */
extern uint16_t	scf_panic_trc_status;	/* Panic SCF status register memo */
extern ushort_t	scf_panic_trc[16];	/* Panic trace area */
#define	SCF_PANIC_TRACE(x)						\
	(scf_panic_trc[scf_panic_trc_w_off++ & 0x000f] = (ushort_t)x)

#ifdef	__cplusplus
}
#endif

#endif /* _SCFPARAM_H */
