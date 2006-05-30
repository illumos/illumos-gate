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
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scfd/scfsys.h>

/*
 * Common table
 */
scf_comtbl_t	scf_comtbl;			/* SCF driver common table */
void	*scfstate;				/* root of soft state */
char	*scf_driver_name = SCF_DRIVER_NAME;	/* SCF driver name */

/*
 * SCF driver control mode
 */
uint_t	scf_halt_proc_mode = HALTPROC_STOP; /* SCFHALT after processing mode */
uint_t	scf_last_detach_mode = 0;		/* Last detach mode */

/*
 * SRAM trace date size
 */
uint_t	scf_sram_trace_data_size = 12;		/* Get SRAM trace data size */

/*
 * Wait timer value (Micro-second)
 */
uint_t	scf_rdctrl_sense_wait = 60000000;
				/* SCFIOCRDCTRL wait timer value (60s) */

/*
 * Wait timer value (Milli-second)
 */
uint_t	scf_buf_ful_rtime = 500;
				/* Buff full wait retry timer value (500ms) */
uint_t	scf_rci_busy_rtime = 3000; /* RCI busy wait retry timer value (3s) */

/*
 * Re-try counter
 */
uint_t	scf_buf_ful_rcnt = 10;		/* Buff full retry counter */
uint_t	scf_rci_busy_rcnt = 15;		/* RCI busy retry counter */
uint_t	scf_tesum_rcnt = 1;		/* Tx sum retry counter */
uint_t	scf_resum_rcnt = 1;		/* Rx sum retry counter */
uint_t	scf_cmd_to_rcnt = 1;		/* Command to retry counter */
uint_t	scf_devbusy_wait_rcnt = 6;	/* Command device busy retry counter */
uint_t	scf_online_wait_rcnt = 6;	/* SCF online retry counter */
uint_t	scf_path_change_max = 4;	/* SCF path change retry counter */

/*
 * Max value
 */
uint_t	scf_report_sense_pool_max = 96;	/* Report sense max */
uint_t	scf_getevent_pool_max = 96;	/* SCFIOCGETEVENT max */
uint_t	scf_rci_max = 32 + 94;		/* RCI device max */
uint_t	scf_rxbuff_max_size = 4096;	/* SCF command data division max size */

/*
 * Poff factor (reported on shutdown start)
 */
unsigned char	scf_poff_factor[2][3] = {
		{ 0x00, 0x00, 0x00 },	/* Shutdown (except pfail) */
		{ 0x01, 0x00, 0x00 }};	/* Shutdown by pfail */

/*
 * Alive check parameter
 */
uchar_t	scf_alive_watch_code = 0x10;	/* alive code for SCF driver */
uchar_t	scf_alive_phase_code = 0x00;	/* alive phase code */
uchar_t	scf_alive_interval_time = INTERVAL_TIME_DEF;	/* interval time */
uchar_t	scf_alive_monitor_time = MONITOR_TIME_DEF;	/* monitor timeout */
ushort_t	scf_alive_panic_time = PANIC_TIME_DEF;	/* panic timeout */

uchar_t	scf_acr_phase_code = 0x00;	/* Alive check register phase code */

/*
 * FMEMA interface
 */
caddr_t	scf_avail_cmd_reg_vaddr = 0;	/* SCF Command register address */

/*
 * Send break interface
 */
int	scf_dm_secure_mode = 0;		/* secure mode */

/*
 * SCF driver version interface
 */
ushort_t	scf_scfd_comif_version = 0x0000;	/* SCF driver version */

/*
 * XSCF version interface
 */
ushort_t	scf_xscf_comif_version = 0xffff;	/* XSCF version */

/*
 * ioctl control value and flag
 */
int	scf_save_hac_flag = 0;		/* Host address disp flag */
scfhac_t scf_save_hac;			/* Host address disp save */

/*
 * Register read sync value
 */
uint8_t		scf_rs8;
uint16_t	scf_rs16;
uint32_t	scf_rs32;

/*
 * Panic value
 */
uint_t	scf_panic_reported = 0;		/* Panic report after */
uint_t	scf_panic_report_maxretry = 15;	/* Same as busy_maxretry */
uint_t	scf_cmdend_wait_time_panic = 1000;
				/* SCF command end wait timer value (1s) */
uint_t	scf_cmdend_wait_rcnt_panic = 4;	/* SCF command end retry counter */

uint_t	scf_panic_exec_wait_time = 100;	/* Panic wait timer value (100ms) */
uint_t	scf_panic_exec_flag = 0;	/* Panic exec flag */
uint_t	scf_panic_exec_flag2 = 0;	/* Panic exec flag (report send) */

/*
 * Panic trace
 */
ushort_t scf_panic_trc_w_off = 0;	/* Panic trcae next write offset */
uint16_t scf_panic_trc_command = 0;	/* Panic SCF command register memo */
uint16_t scf_panic_trc_status = 0;	/* Panic SCF status register memo */
ushort_t	scf_panic_trc[16];		/* Panic trace area */
