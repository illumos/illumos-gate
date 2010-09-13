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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#ifndef	_SBD_IOCTL_H
#define	_SBD_IOCTL_H

#ifndef	_ASM
#include <sys/types.h>
#include <sys/obpdefs.h>
#include <sys/processor.h>
#include <sys/param.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM
typedef enum {
	SBD_COMP_NONE,
	SBD_COMP_CPU,
	SBD_COMP_MEM,
	SBD_COMP_IO,
	SBD_COMP_CMP,
	SBD_COMP_UNKNOWN
} sbd_comp_type_t;

typedef enum {
	SBD_STAT_NONE = 0,
	SBD_STAT_EMPTY,
	SBD_STAT_DISCONNECTED,
	SBD_STAT_CONNECTED,
	SBD_STAT_UNCONFIGURED,
	SBD_STAT_CONFIGURED
} sbd_state_t;

typedef enum {
	SBD_COND_UNKNOWN = 0,
	SBD_COND_OK,
	SBD_COND_FAILING,
	SBD_COND_FAILED,
	SBD_COND_UNUSABLE
} sbd_cond_t;

typedef	int	sbd_busy_t;

#define	SBD_MAX_UNSAFE		16
#define	SBD_TYPE_LEN		12
#define	SBD_NULL_UNIT		-1

typedef struct {
	sbd_comp_type_t	c_type;
	int		c_unit;
	char		c_name[OBP_MAXPROPNAME];
} sbd_comp_id_t;

typedef struct {
	sbd_comp_id_t	c_id;
	sbd_state_t	c_ostate;
	sbd_cond_t	c_cond;
	sbd_busy_t	c_busy;
	uint_t		c_sflags;
	time_t		c_time;
} sbd_cm_stat_t;

#define	ci_type		c_id.c_type
#define	ci_unit		c_id.c_unit
#define	ci_name		c_id.c_name

typedef struct {
	sbd_cm_stat_t	cs_cm;
	int		cs_isbootproc;
	processorid_t	cs_cpuid;
	int		cs_speed;
	int		cs_ecache;
} sbd_cpu_stat_t;

#define	cs_type		cs_cm.ci_type
#define	cs_unit		cs_cm.ci_unit
#define	cs_name		cs_cm.ci_name
#define	cs_ostate	cs_cm.c_ostate
#define	cs_cond		cs_cm.c_cond
#define	cs_busy		cs_cm.c_busy
#define	cs_suspend	cs_cm.c_sflags
#define	cs_time		cs_cm.c_time

typedef struct {
	sbd_cm_stat_t	ms_cm;
	int		ms_interleave;
	pfn_t		ms_basepfn;
	pgcnt_t		ms_totpages;
	pgcnt_t		ms_detpages;
	pgcnt_t		ms_pageslost;
	pgcnt_t		ms_managed_pages;
	pgcnt_t		ms_noreloc_pages;
	pgcnt_t		ms_noreloc_first;
	pgcnt_t		ms_noreloc_last;
	int		ms_cage_enabled;
	int		ms_peer_is_target;	/* else peer is source */
	char		ms_peer_ap_id[MAXPATHLEN];	/* board's AP name */
} sbd_mem_stat_t;

#define	ms_type		ms_cm.ci_type
#define	ms_unit		ms_cm.ci_unit
#define	ms_name		ms_cm.ci_name
#define	ms_ostate	ms_cm.c_ostate
#define	ms_cond		ms_cm.c_cond
#define	ms_busy		ms_cm.c_busy
#define	ms_suspend	ms_cm.c_sflags
#define	ms_time		ms_cm.c_time

typedef struct {
	sbd_cm_stat_t	is_cm;
	int		is_referenced;
	int		is_unsafe_count;
	int		is_unsafe_list[SBD_MAX_UNSAFE];
	char		is_pathname[MAXPATHLEN];
} sbd_io_stat_t;

#define	is_type		is_cm.ci_type
#define	is_unit		is_cm.ci_unit
#define	is_name		is_cm.ci_name
#define	is_ostate	is_cm.c_ostate
#define	is_cond		is_cm.c_cond
#define	is_busy		is_cm.c_busy
#define	is_suspend	is_cm.c_sflags
#define	is_time		is_cm.c_time

/* This constant must be the max of the max cores on all platforms */
#define	SBD_MAX_CORES_PER_CMP	64

typedef struct {
	sbd_cm_stat_t	ps_cm;
	processorid_t	ps_cpuid[SBD_MAX_CORES_PER_CMP];
	int		ps_ncores;
	int		ps_speed;
	int		ps_ecache;
} sbd_cmp_stat_t;

#define	ps_type		ps_cm.ci_type
#define	ps_unit		ps_cm.ci_unit
#define	ps_name		ps_cm.ci_name
#define	ps_ostate	ps_cm.c_ostate
#define	ps_cond		ps_cm.c_cond
#define	ps_busy		ps_cm.c_busy
#define	ps_suspend	ps_cm.c_sflags
#define	ps_time		ps_cm.c_time

typedef union {
	sbd_cm_stat_t	d_cm;
	sbd_cpu_stat_t	d_cpu;
	sbd_mem_stat_t	d_mem;
	sbd_io_stat_t	d_io;
	sbd_cmp_stat_t	d_cmp;
} sbd_dev_stat_t;

#define	ds_type		d_cm.ci_type
#define	ds_unit		d_cm.ci_unit
#define	ds_name		d_cm.ci_name
#define	ds_ostate	d_cm.c_ostate
#define	ds_cond		d_cm.c_cond
#define	ds_busy		d_cm.c_busy
#define	ds_suspend	d_cm.c_sflags
#define	ds_time		d_cm.c_time

#define	SBD_MAX_INFO	256

typedef struct {
	int		s_board;
	char		s_type[SBD_TYPE_LEN];
	char		s_info[SBD_MAX_INFO];
	sbd_state_t	s_rstate;
	sbd_state_t	s_ostate;
	sbd_cond_t	s_cond;
	sbd_busy_t	s_busy;
	time_t		s_time;
	uint_t		s_power:1;
	uint_t		s_assigned:1;
	uint_t		s_platopts;
	int		s_nstat;
	sbd_dev_stat_t	s_stat[1];
} sbd_stat_t;

typedef struct {
	sbd_comp_id_t	c_id;
	uint_t		c_flags;
	int		c_len;
	caddr_t		c_opts;
} sbd_cm_cmd_t;

typedef struct {
	sbd_cm_cmd_t	g_cm;
	int		g_ncm;
} sbd_getncm_cmd_t;

typedef struct {
	sbd_cm_cmd_t	s_cm;
	int		s_nbytes;
	caddr_t		s_statp;
} sbd_stat_cmd_t;

typedef union {
	sbd_cm_cmd_t		cmd_cm;
	sbd_getncm_cmd_t	cmd_getncm;
	sbd_stat_cmd_t		cmd_stat;
} sbd_cmd_t;

typedef struct {
	int		e_code;
	char		e_rsc[MAXPATHLEN];
} sbd_error_t;

typedef struct {
	sbd_cmd_t	i_cmd;
	sbd_error_t	i_err;
} sbd_ioctl_arg_t;

typedef struct {
	int		t_base;
	int		t_bnd;
	char		**t_text;
} sbd_etab_t;

#define	i_flags		i_cmd.cmd_cm.c_flags
#define	i_len		i_cmd.cmd_cm.c_len
#define	i_opts		i_cmd.cmd_cm.c_opts
#define	ic_type		i_cmd.cmd_cm.ci_type
#define	ic_name		i_cmd.cmd_cm.ci_name
#define	ic_unit		i_cmd.cmd_cm.ci_unit
#define	ie_code		i_err.e_code
#define	ie_rsc		i_err.e_rsc

#define	_SBD_IOC		(('D' << 16) | ('R' << 8))

#define	SBD_CMD_ASSIGN		(_SBD_IOC | 0x01)
#define	SBD_CMD_UNASSIGN	(_SBD_IOC | 0x02)
#define	SBD_CMD_POWERON		(_SBD_IOC | 0x03)
#define	SBD_CMD_POWEROFF	(_SBD_IOC | 0x04)
#define	SBD_CMD_TEST		(_SBD_IOC | 0x05)
#define	SBD_CMD_CONNECT		(_SBD_IOC | 0x06)
#define	SBD_CMD_CONFIGURE	(_SBD_IOC | 0x07)
#define	SBD_CMD_UNCONFIGURE	(_SBD_IOC | 0x08)
#define	SBD_CMD_DISCONNECT	(_SBD_IOC | 0x09)
#define	SBD_CMD_STATUS		(_SBD_IOC | 0x0a)
#define	SBD_CMD_GETNCM		(_SBD_IOC | 0x0b)
#define	SBD_CMD_PASSTHRU	(_SBD_IOC | 0x0c)

#define	SBD_CHECK_SUSPEND(cmd, c_sflags) \
		(((c_sflags) >> (((cmd) & 0xf) - 1)) & 0x01)

#define	SBD_SET_SUSPEND(cmd, c_sflags) \
		((c_sflags) |= (0x01 << (((cmd) & 0xf) - 1)))

#define	SBD_CHECK_PLATOPTS(cmd, c_platopts) \
		(((c_platopts) >> (((cmd) & 0xf) - 1)) & 0x01)

#define	SBD_SET_PLATOPTS(cmd, c_platopts) \
		((c_platopts) &= ~(0x01 << (((cmd) & 0xf) - 1)))

#define	SBD_FLAG_FORCE		0x1
#define	SBD_FLAG_ALLCMP		0x2
#define	SBD_FLAG_QUIESCE_OKAY	0x4

#if defined(_SYSCALL32)

typedef struct {
	int32_t		c_type;
	int32_t		c_unit;
	char		c_name[OBP_MAXPROPNAME];
} sbd_comp_id32_t;

typedef struct {
	sbd_comp_id32_t	c_id;
	int32_t		c_ostate;
	int32_t		c_cond;
	int32_t		c_busy;
	uint32_t	c_sflags;
	time32_t	c_time;
} sbd_cm_stat32_t;

typedef struct {
	sbd_cm_stat32_t	cs_cm;
	int32_t		cs_isbootproc;
	int32_t		cs_cpuid;
	int32_t		cs_speed;
	int32_t		cs_ecache;
} sbd_cpu_stat32_t;

typedef struct {
	sbd_cm_stat32_t	ms_cm;
	int32_t		ms_interleave;
	uint32_t	ms_basepfn;
	uint32_t	ms_totpages;
	uint32_t	ms_detpages;
	int32_t		ms_pageslost;
	uint32_t	ms_managed_pages;
	uint32_t	ms_noreloc_pages;
	uint32_t	ms_noreloc_first;
	uint32_t	ms_noreloc_last;
	int32_t		ms_cage_enabled;
	int32_t		ms_peer_is_target;
	char		ms_peer_ap_id[MAXPATHLEN];
} sbd_mem_stat32_t;

typedef struct {
	sbd_cm_stat32_t	is_cm;
	int32_t		is_referenced;
	int32_t		is_unsafe_count;
	int32_t		is_unsafe_list[SBD_MAX_UNSAFE];
	char		is_pathname[MAXPATHLEN];
} sbd_io_stat32_t;

typedef struct {
	sbd_cm_stat32_t	ps_cm;
	int32_t		ps_cpuid[SBD_MAX_CORES_PER_CMP];
	int32_t		ps_ncores;
	int32_t		ps_speed;
	int32_t		ps_ecache;
} sbd_cmp_stat32_t;

typedef union {
	sbd_cm_stat32_t		d_cm;
	sbd_cpu_stat32_t	d_cpu;
	sbd_mem_stat32_t	d_mem;
	sbd_io_stat32_t		d_io;
	sbd_cmp_stat32_t	d_cmp;
} sbd_dev_stat32_t;

typedef struct {
	int32_t			s_board;
	char			s_type[SBD_TYPE_LEN];
	char			s_info[SBD_MAX_INFO];
	int32_t			s_rstate;
	int32_t			s_ostate;
	int32_t			s_cond;
	int32_t			s_busy;
	time32_t		s_time;
	uint32_t		s_power:1;
	uint32_t		s_assigned:1;
	uint32_t		s_platopts;
	int32_t			s_nstat;
	sbd_dev_stat32_t	s_stat[1];
} sbd_stat32_t;

typedef struct {
	int32_t			e_code;
	char			e_rsc[MAXPATHLEN];
} sbd_error32_t;

typedef struct {
	sbd_comp_id32_t		c_id;
	uint32_t		c_flags;
	int32_t			c_len;
	caddr32_t		c_opts;
} sbd_cm_cmd32_t;

typedef struct {
	sbd_cm_cmd32_t	g_cm;
	int32_t		g_ncm;
} sbd_getncm_cmd32_t;

typedef struct {
	sbd_cm_cmd32_t	s_cm;
	int32_t		s_nbytes;
	caddr32_t	s_statp;
} sbd_stat_cmd32_t;

typedef union {
	sbd_cm_cmd32_t		cmd_cm;
	sbd_getncm_cmd32_t	cmd_getncm;
	sbd_stat_cmd32_t	cmd_stat;
} sbd_cmd32_t;

typedef struct {
	sbd_cmd32_t		i_cmd;
	sbd_error32_t		i_err;
} sbd_ioctl_arg32_t;

typedef struct {
	int32_t			t_base;
	int32_t			t_bnd;
	char			**t_text;
} sbd_etab32_t;

#endif	/* _SYSCALL32 */
#endif	/* _ASM */

/* Common error codes */

#define	ESBD_NOERROR		0	/* no error */
#define	ESBD_INTERNAL		1	/* Internal error */
#define	ESBD_NOMEM		2	/* Insufficient memory */
#define	ESBD_PROTO		3	/* Protocol error */
#define	ESBD_BUSY		4	/* Device busy */
#define	ESBD_NODEV		5	/* No such device */
#define	ESBD_ALREADY		6	/* Operation already in progress */
#define	ESBD_IO			7	/* I/O error */
#define	ESBD_FAULT		8	/* Bad address */
#define	ESBD_EMPTY_BD		9	/* No device(s) on board */
#define	ESBD_INVAL		10	/* Invalid argument */
#define	ESBD_STATE		11	/* Invalid state transition */
#define	ESBD_FATAL_STATE	12	/* Device in fatal state */
#define	ESBD_OUTSTANDING	13	/* Outstanding error */
#define	ESBD_SUSPEND		14	/* Device failed to suspend */
#define	ESBD_RESUME		15	/* Device failed to resume */
#define	ESBD_UTHREAD		16	/* Cannot stop user thread */
#define	ESBD_RTTHREAD		17	/* Cannot quiesce realtime thread */
#define	ESBD_KTHREAD		18	/* Cannot stop kernel thread  */
#define	ESBD_OFFLINE		19	/* Failed to off-line */
#define	ESBD_ONLINE		20	/* Failed to on-line */
#define	ESBD_CPUSTART		21	/* Failed to start CPU */
#define	ESBD_CPUSTOP		22	/* Failed to stop CPU */
#define	ESBD_INVAL_COMP		23	/* Invalid component type */
#define	ESBD_KCAGE_OFF		24	/* Kernel cage is disabled */
#define	ESBD_NO_TARGET		25	/* No available memory target */
#define	ESBD_HW_PROGRAM		26	/* Hardware programming error */
#define	ESBD_MEM_NOTVIABLE	27	/* VM viability test failed */
#define	ESBD_MEM_REFUSED	28	/* Memory operation refused */
#define	ESBD_MEM_NONRELOC	29	/* Non-relocatable pages in span */
#define	ESBD_MEM_CANCELLED	30	/* Memory operation cancelled */
#define	ESBD_MEMFAIL		31	/* Memory operation failed */
#define	ESBD_MEMONLINE		32	/* Can't unconfig cpu if mem online */
#define	ESBD_QUIESCE_REQD	33
	/* Operator confirmation for quiesce is required */
#define	ESBD_MEMINTLV		34
	/* Memory is interleaved across boards */
#define	ESBD_CPUONLINE		35
	/* Can't config memory if not all cpus are online */
#define	ESBD_UNSAFE		36	/* Unsafe driver present */
#define	ESBD_INVAL_OPT		37	/* option invalid */

/* Starcat error codes */

#define	ESTC_NONE		1000	/* No error */
#define	ESTC_GETPROP		1001	/* Cannot read property value */
#define	ESTC_BNUM		1002	/* Invalid board number */
#define	ESTC_CONFIGBUSY		1003
	/* Cannot proceed; Board is configured or busy */
#define	ESTC_PROBE		1004	/* Solaris failed to probe */
#define	ESTC_DEPROBE		1005	/* Solaris failed to deprobe */
#define	ESTC_MOVESIGB		1006	/* Firmware move-cpu0 failed */
#define	ESTC_SUPPORT		1007	/* Operation not supported */
#define	ESTC_DRVFAIL		1008	/* Device driver failure */
#define	ESTC_UNKPTCMD		1012	/* Unrecognized platform command */
#define	ESTC_NOTID		1013
	/* drmach parameter is not a valid ID */
#define	ESTC_INAPPROP		1014
	/* drmach parameter is inappropriate for operation */
#define	ESTC_INTERNAL		1015	/* Unexpected internal condition */
#define	ESTC_MBXRQST		1016
	/* Mailbox framework failure: outgoing */
#define	ESTC_MBXRPLY		1017
	/* Mailbox framework failure: incoming */
#define	ESTC_NOACL		1018	/* Board is not in domain ACL */
#define	ESTC_NOT_ASSIGNED	1019	/* Board is not assigned to domain */
#define	ESTC_NOT_ACTIVE		1020	/* Board is not active */
#define	ESTC_EMPTY_SLOT		1021	/* Slot is empty */
#define	ESTC_POWER_OFF		1022	/* Board is powered off */
#define	ESTC_TEST_IN_PROGRESS	1023	/* Board is already being tested */
#define	ESTC_TESTING_BUSY	1024
	/* Wait: All SC test resources are in use */
#define	ESTC_TEST_REQUIRED	1025	/* Board requires test prior to use */
#define	ESTC_TEST_ABORTED	1026	/* Board test has been aborted */
#define	ESTC_MBOX_UNKNOWN	1027
	/* Unknown error type received from SC */
#define	ESTC_TEST_STATUS_UNKNOWN	1028
	/* Test completed with unknown status */
#define	ESTC_TEST_RESULT_UNKNOWN	1029
	/* Unknown test result returned by SC */
#define	ESTC_TEST_FAILED	1030
	/* SMS hpost reported error, see POST log for details */
#define	ESTC_UNAVAILABLE	1031	/* Slot is unavailable to the domain */
#define	ESTC_NZ_LPA		1032	/* Nonzero LPA not yet supported */
#define	ESTC_IOSWITCH		1033
	/* Cannot unconfigure I/O board: tunnel switch failed */
#define	ESTC_IOCAGE_NO_CPU_AVAIL	1034
	/* No CPU available for I/O cage test. */
#define	ESTC_SMS_ERR_RECOVERABLE	1035
	/* SMS reported recoverable error: check SMS status and Retry */
#define	ESTC_SMS_ERR_UNRECOVERABLE	1036
	/* SMS reported unrecoverable error: Board is Unusable */
#define	ESTC_NWSWITCH		1037
	/* Cannot unconfigure I/O board: network switch failed */

/* Starfire error codes */

#define	ESTF_NONE		2000	/* No error */
#define	ESTF_GETPROP		2001	/* Cannot read property value */
#define	ESTF_GETPROPLEN		2002	/* Cannot determine property length */
#define	ESTF_BNUM		2003	/* Invalid board number */
#define	ESTF_CONFIGBUSY		2004
	/* Cannot proceed; Board is configured or busy */
#define	ESTF_NOCPUID		2005	/* No CPU specified for connect */
#define	ESTF_PROBE		2006	/* Firmware probe failed */
#define	ESTF_DEPROBE		2007	/* Firmware deprobe failed */
#define	ESTF_MOVESIGB		2008	/* Firmware move-cpu0 failed */
#define	ESTF_JUGGLE		2009	/* Cannot move SIGB assignment */
#define	ESTF_HASSIGB		2010
	/* Cannot disconnect CPU; SIGB is currently assigned */
#define	ESTF_SUPPORT		2011	/* Operation not supported */
#define	ESTF_DRVFAIL		2012	/* Device driver failure */
#define	ESTF_SETCPUVAL		2013
	/* Must specify a CPU on the given board */
#define	ESTF_NODEV		2014	/* No such device */
#define	ESTF_INTERBOARD		2015
	/* Memory configured with inter-board interleaving */
#define	ESTF_UNKPTCMD		2016	/* Unrecognized platform command */
#define	ESTF_NOTID		2017	/* drmach parameter is not a valid ID */
#define	ESTF_INAPPROP		2018
	/* drmach parameter is inappropriate for operation */
#define	ESTF_INTERNAL		2019	/* Unexpected internal condition */

/* Daktari error codes */

#define	EDAK_NONE		3000	/* no error */
#define	EDAK_INTERNAL		3001	/* Internal error */
#define	EDAK_NOFRUINFO		3002	/* Didn't receive fru info */
#define	EDAK_NONDR_BOARD	3003
	/* DR is not supported on this board type */
#define	EDAK_POWERON		3004	/* Power on request failed */
#define	EDAK_POWEROK		3005	/* Failed to power on */
#define	EDAK_INTERRUPTED	3006	/* Operation interrupted */
#define	EDAK_BOARDINIT		3007	/* Board initialization failed */
#define	EDAK_CPUINIT		3008	/* CPU intialization failed */
#define	EDAK_MEMFAIL		3009	/* Memory operation failed */

/* Serengeti error codes */

#define	ESGT_NONE		4000	/* no error */
#define	ESGT_INTERNAL		4001	/* Internal error */
#define	ESGT_INVAL		4002	/* Invalid argument */
#define	ESGT_MEMFAIL		4003	/* Memory operation failed */
#define	ESGT_PROBE		4004	/* Board probe failed */
#define	ESGT_DEPROBE		4005	/* Board deprobe failed */
#define	ESGT_JUGGLE_BOOTPROC	4006	/* Failed to juggle bootproc */
#define	ESGT_NOT_CPUTYPE	4007	/* Not a cpu device */
#define	ESGT_NO_DEV_TYPE	4008	/* Cannot find device type */
#define	ESGT_BAD_PORTID		4009	/* Bad port id */
#define	ESGT_RESUME		4010	/* Failed to resume device */
#define	ESGT_SUSPEND		4011	/* Failed to suspend device */
#define	ESGT_KTHREAD		4012	/* failed to stop kernel thd */
#define	ESGT_UNSAFE		4013	/* unsafe */
#define	ESGT_RTTHREAD		4014	/* real time threads */
#define	ESGT_UTHREAD		4015	/* failed to stop user thd */
#define	ESGT_PROM_ATTACH	4016	/* prom failed attach board */
#define	ESGT_PROM_DETACH	4017	/* prom failed detach board */
#define	ESGT_SC_ERR		4018	/* sc return a failure */
#define	ESGT_GET_BOARD_STAT	4019	/* Failed to obtain board information */
#define	ESGT_WAKEUPCPU		4020	/* Failed to wake up cpu */
#define	ESGT_STOPCPU		4021	/* Failed to stop cpu */
/* Serengeti SC return codes */
#define	ESGT_HW_FAIL		4022	/* Hardware Failure */
#define	ESGT_BD_ACCESS		4023	/* Board access denied */
#define	ESGT_STALE_CMP		4024	/* Stale components */
#define	ESGT_STALE_OBJ		4025	/* Stale objects */
#define	ESGT_NO_SEPROM_SPACE	4026	/* No SEPROM space */
#define	ESGT_NOT_SUPP		4027	/* Operation not supported */
#define	ESGT_NO_MEM		4028	/* No Memory */

/* OPL error codes */

#define	EOPL_GETPROP		5001	/* Cannot read property value */
#define	EOPL_BNUM		5002	/* Invalid board number */
#define	EOPL_CONFIGBUSY		5003
	/* Cannot proceed; Board is configured or busy */
#define	EOPL_PROBE		5004	/* Firmware probe failed */
#define	EOPL_DEPROBE		5005	/* Firmware deprobe failed */
#define	EOPL_SUPPORT		5006	/* Operation not supported */
#define	EOPL_DRVFAIL		5007	/* Device driver failure */
#define	EOPL_UNKPTCMD		5008	/* Unrecognized platform command */
#define	EOPL_NOTID		5009	/* drmach parameter is not a valid ID */
#define	EOPL_INAPPROP		5010
	/* drmach parameter is inappropriate for operation */
#define	EOPL_INTERNAL		5011	/* Unexpected internal condition */
#define	EOPL_FINDDEVICE		5012	/* Firmware cannot find node. */
#define	EOPL_MC_SETUP		5013	/* Cannot setup memory node */
#define	EOPL_CPU_STATE		5014	/* Invalid CPU/core state */
#define	EOPL_MC_OPL		5015	/* Cannot find mc-opl interface */
#define	EOPL_SCF_FMEM		5016	/* Cannot find scf_fmem interface */
#define	EOPL_FMEM_SETUP		5017	/* Error setting up FMEM buffer */
#define	EOPL_SCF_FMEM_START	5018	/* scf_fmem_start error */
#define	EOPL_FMEM_ERROR		5019	/* FMEM error */
#define	EOPL_SCF_FMEM_CANCEL	5020	/* scf_fmem_cancel error */
#define	EOPL_FMEM_XC_TIMEOUT	5021	/* xcall timeout */
#define	EOPL_FMEM_COPY_TIMEOUT	5022	/* DR parellel copy timeout */
#define	EOPL_FMEM_SCF_BUSY	5023	/* SCF busy */
#define	EOPL_FMEM_RETRY_OUT	5024	/* SCF IO Retry Error */
#define	EOPL_FMEM_TIMEOUT	5025	/* FMEM command timeout */
#define	EOPL_FMEM_HW_ERROR	5026	/* Hardware error */
#define	EOPL_FMEM_TERMINATE	5027	/* FMEM operation Terminated */
#define	EOPL_FMEM_COPY_ERROR	5028	/* Memory copy error */
#define	EOPL_FMEM_SCF_ERR	5029	/* SCF error */
#define	EOPL_MIXED_CPU		5030
	/* Cannot add SPARC64-VI to domain booted with all SPARC64-VII CPUs */
#define	EOPL_FMEM_SCF_OFFLINE	5031	/* SCF OFFLINE */

/* X86 error codes */

#define	EX86_GETPROP		10001	/* Cannot read property value */
#define	EX86_BNUM		10002	/* Invalid board number */
#define	EX86_NOTID		10003	/* drmach parameter is not a valid ID */
#define	EX86_INAPPROP		10004
	/* drmach parameter is inappropriate for operation */
#define	EX86_PROBE		10005	/* Firmware probe failed */
#define	EX86_DEPROBE		10006	/* Firmware deprobe failed */
#define	EX86_SUPPORT		10007	/* Operation not supported */
#define	EX86_INTERNAL		10008	/* Unexpected internal condition */
#define	EX86_CONFIGBUSY		10009
	/* Cannot proceed, board is configured or busy */
#define	EX86_POWERBUSY		10010	/* Cannot proceed, board is powered */
#define	EX86_CONNECTBUSY	10011	/* Cannot proceed, board is connected */
#define	EX86_INVALID_ARG	10012	/* Invalid argument */
#define	EX86_DRVFAIL		10013	/* Device driver failure */
#define	EX86_UNKPTCMD		10014	/* Unrecognized platform command */
#define	EX86_ALLOC_CPUID	10015	/* Failed to allocate processor id */
#define	EX86_FREE_CPUID		10016	/* Failed to release processor id */
#define	EX86_POWERON		10017	/* Failed to power on board */
#define	EX86_POWEROFF		10018	/* Failed to power off board */
#define	EX86_MC_SETUP		10019	/* Cannot setup memory node */
#define	EX86_ACPIWALK		10020	/* Cannot walk ACPI namespace */
#define	EX86_WALK_DEPENDENCY	10021
	/* Failed to check dependency for board */
#define	EX86_IN_FAILURE		10022	/* Board is in failure state */

#ifdef	__cplusplus
}
#endif

#endif	/* _SBD_IOCTL_H */
