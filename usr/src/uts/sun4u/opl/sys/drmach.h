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

#ifndef _SYS_DRMACH_H_
#define	_SYS_DRMACH_H_

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/processor.h>
#include <sys/cpuvar.h>
#include <sys/sbd_ioctl.h>
#include <sys/sysevent.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pte.h>
#include <sys/opl.h>
#endif


#define	MAX_BOARDS		plat_max_boards()
#define	MAX_CPU_UNITS_PER_BOARD	plat_max_cpu_units_per_board()
#define	MAX_MEM_UNITS_PER_BOARD	plat_max_mem_units_per_board()
#define	MAX_IO_UNITS_PER_BOARD	plat_max_io_units_per_board()
#define	MAX_CMP_UNITS_PER_BOARD	plat_max_cmp_units_per_board()
/*
 * DR uses MAX_CORES_PER_CMP as number of virtual CPU within a CMP
 */
#define	MAX_CORES_PER_CMP	OPL_MAX_CPU_PER_CMP


/* returned with drmach_board_find_devices callback */
#define	DRMACH_DEVTYPE_CPU	"cpu"
#define	DRMACH_DEVTYPE_MEM	"memory"
#define	DRMACH_DEVTYPE_PCI	"pci"

#define	FMEM_LOOP_START		1
#define	FMEM_LOOP_COPY_READY	2
#define	FMEM_LOOP_COPY_DONE	3
#define	FMEM_LOOP_FMEM_READY	4
#define	FMEM_LOOP_RENAME_DONE	5
#define	FMEM_LOOP_DONE		6
#define	FMEM_LOOP_EXIT		7

#define	SCF_CMD_BUSY		0x8000
#define	SCF_STATUS_READY	0x8000
#define	SCF_STATUS_SHUTDOWN	0x4000
#define	SCF_STATUS_POFF		0x2000
#define	SCF_STATUS_EVENT	0x1000
#define	SCF_STATUS_TIMER_ADJUST	0x0800
#define	SCF_STATUS_ALIVE	0x0400
#define	SCF_STATUS_MODE_CHANGED	0x0200
#define	SCF_STATUS_CMD_U_PARITY	0x0100
#define	SCF_STATUS_CMD_RTN_CODE	0x00f0
#define	SCF_STATUS_MODE_SWITCH	0x000c
#define	SCF_STATUS_CMD_COMPLETE	0x0002
#define	SCF_STATUS_CMD_L_PARITY	0x0001
#define	SCF_STATUS_EX_ONLINE	0x20000000

#define	SCF_RETRY_CNT		15

/*
 * dynamic memory blocks cannot be added back to phys_install
 * safely if the alignment is smaller than the largest
 * physical page size the OS supports.  The VM subsystem
 * will try to coalesce smaller pages together and
 * it assumes that the page structures are contiguous.
 * That assumption does not hold so we have to work around it.
 * On OPL, the largest page size is 256MB so we can just
 * add such memory block back.  For everything else,
 * we round them up to 4MB boundaries and make sure
 * they are disjoint from phys_install.
 */

#define	MH_MPSS_ALIGNMENT	(256 * 1024 * 1024)
#define	MH_MIN_ALIGNMENT	(4 * 1024 * 1024)
#define	rounddown(x, y)		((x) & ~(y - 1))

#define	SCF_SB_INFO_OFFSET	0x80020
#define	SCF_SB_INFO_BUSY	0x40

#ifndef _ASM

/*
 * OPL platform specific routines currently only defined
 * in opl.c and referenced by DR.
 */

typedef void *drmachid_t;

/*
 *	There are several requirements to do copy rename:
 *	1 There should be no subroutine calls/TLBmiss
 *	  once the copying has begun.
 *	2 There should be no external memory access by the CPU
 *	  during the memory rename programming.
 *
 *	All data and instruction pages used in the copy rename
 *	procedure are kept in locked pages to satisfy 1 and 2.
 *	However that is not enough.  To satisfy 2, we must keep
 *	all the data and instructions in the 2 assembly routines
 *	drmach_fmem_loop_script and drmach_fmem_exec_script
 *	in the same contiguous page.  They are packed into
 *	the 2nd 8K page of the buffer as shown in the diagram
 *	below.
 *
 *	Note that it is important to keep the "critical"
 *	data in one 8K page to avoid any cache line
 *	contention.   The assembly routines read all the
 *	critical data into the cache so that there is no
 *	external memory access during FMEM operation.
 *
 *	layout of the FMEM buffers:
 *	They are all locked in TLB and the critical data
 *	used in drmach_fmem_xxx assembly code are all
 *	packed in the second page.
 *
 *	1st 8k page
 *	+--------------------------------+
 *	|drmach_copy_rename_program_t    |
 *	+--------------------------------+
 *	|drmach_copy_rename_data_t       |
 *	|                                |
 *	+--------------------------------+
 *
 *	2nd 8k page
 *	+--------------------------------+
 *	|drmach_copy_rename_critical_t   |
 *	|                                |
 *	+--------------------------------+
 *	|run (drmach_copy_rename_prog__relocatable)
 *	|(roundup boundary to 1K)        |
 *	+--------------------------------+
 *	| fmem_script                    |
 *	|(roundup boundary to 1K)        |
 *	+--------------------------------+
 *	|loop_script                     |
 *	|                                |
 *	+--------------------------------+
 *	|at least 1K NOP/0's             |
 *	|                                |
 *	+--------------------------------+
 *
 *	3rd 8k page
 *	+--------------------------------+
 *	|memlist_buffer (free_mlist)     |
 *	|                                |
 *	+--------------------------------+
 *
 *	4th 8k page - drmach_cr_stat_t.
 *
 */

typedef struct {
	int16_t	scf_command;
	int8_t	scf_rsv1[2];
	int16_t	scf_status;
	int8_t	scf_rsv2[2];
	int8_t	scf_version;
	int8_t	scf_rsv3[3];
	int8_t	scf_rsv4[4];
	uint8_t	scf_tdata[16];
	uint8_t	scf_rdata[16];
	int8_t	scf_rsv5[36];
	int32_t	scf_status_ex;
} drmach_scf_regs_t;


typedef struct {
	volatile uint_t	stat;
	volatile uint_t	error;
	int	op;
#define	OPL_FMEM_SCF_START 	0x1
#define	OPL_FMEM_MC_SUSPEND	0x2
} drmach_fmem_mbox_t;

typedef struct {
	uint64_t		scf_reg_base;
	uint8_t			scf_td[16];
	uint64_t		save_log[8];
	uint64_t		save_local[8];
	uint64_t		pstate;
	uint64_t		delay;
	int			(*run)(void *arg, int cpuid);
	int			(*fmem)(void *arg, size_t sz);
	int			(*loop)(void *arg1, size_t sz, void *arg2);
	void			(*loop_rtn)(void *arg);
	uint64_t		inst_loop_ret;
	int			fmem_issued;
	volatile uchar_t 	stat[NCPU];
} drmach_copy_rename_critical_t;

typedef struct {
	uint64_t		s_copybasepa;
	uint64_t		t_copybasepa;
	drmachid_t		s_mem;
	drmachid_t		t_mem;
	cpuset_t		cpu_ready_set;
	cpuset_t		cpu_slave_set;
	cpuset_t		cpu_copy_set;
	processorid_t		cpuid;
	drmach_fmem_mbox_t	fmem_status;
	volatile ushort_t 	error[NCPU];
	struct memlist		*c_ml;
	struct memlist		*cpu_ml[NCPU];
	void			(*mc_resume)(void);
	int			(*scf_fmem_end)(void);
	int			(*scf_fmem_cancel)(void);
	uint64_t		(*scf_get_base_addr)(void);
	uint64_t		copy_delay;
	uint64_t		stick_freq;
	uint64_t		copy_wait_time;
	processorid_t		slowest_cpuid;
	int			copy_rename_count;
} drmach_copy_rename_data_t;

typedef struct {
	uint64_t	nbytes[NCPU];
} drmach_cr_stat_t;

typedef struct drmach_copy_rename_program {
	drmach_copy_rename_critical_t		*critical;
	struct drmach_copy_rename_program	*locked_prog;
	struct drmach_copy_rename_program	*prog;
	drmach_copy_rename_data_t		*data;
	caddr_t					memlist_buffer;
	struct memlist				*free_mlist;
	drmach_cr_stat_t			*stat;
} drmach_copy_rename_program_t;

#define	DRMACH_FMEM_LOCKED_PAGES	4
#define	DRMACH_FMEM_DATA_PAGE		0
#define	DRMACH_FMEM_CRITICAL_PAGE	1
#define	DRMACH_FMEM_MLIST_PAGE		2
#define	DRMACH_FMEM_STAT_PAGE		3

typedef struct {
	boolean_t	assigned;
	boolean_t	powered;
	boolean_t	configured;
	boolean_t	busy;
	boolean_t	empty;
	sbd_cond_t	cond;
	char		type[MAXNAMELEN];
	char		info[MAXPATHLEN];	/* TODO: what size? */
} drmach_status_t;

typedef struct {
	int	size;
	char	*copts;
} drmach_opts_t;

typedef struct {
	uint64_t mi_basepa;
	uint64_t mi_size;
	uint64_t mi_slice_size;
	uint64_t mi_alignment_mask;
} drmach_mem_info_t;

extern sbd_error_t	*drmach_mem_get_info(drmachid_t, drmach_mem_info_t *);
extern int		drmach_board_is_floating(drmachid_t);

extern sbd_error_t	*drmach_copy_rename_init(
				drmachid_t dst_id,
				drmachid_t src_id, struct memlist *src_copy_ml,
				drmachid_t *pgm_id);
extern sbd_error_t	*drmach_copy_rename_fini(drmachid_t id);
extern void		 drmach_copy_rename(drmachid_t id);

extern sbd_error_t	*drmach_pre_op(int cmd, drmachid_t id,
						drmach_opts_t *opts);
extern sbd_error_t	*drmach_post_op(int cmd, drmachid_t id,
						drmach_opts_t *opts);

extern sbd_error_t	*drmach_board_assign(int bnum, drmachid_t *id);
extern sbd_error_t	*drmach_board_connect(drmachid_t id,
						drmach_opts_t *opts);
extern sbd_error_t	*drmach_board_deprobe(drmachid_t id);
extern sbd_error_t	*drmach_board_disconnect(drmachid_t id,
						drmach_opts_t *opts);
extern sbd_error_t	*drmach_board_find_devices(drmachid_t id, void *a,
		sbd_error_t *(*found)(void *a, const char *, int, drmachid_t));
extern int		drmach_board_lookup(int bnum, drmachid_t *id);
extern sbd_error_t	*drmach_passthru(drmachid_t id,
						drmach_opts_t *opts);

extern sbd_error_t	*drmach_board_name(int bnum, char *buf, int buflen);

extern sbd_error_t	*drmach_board_poweroff(drmachid_t id);
extern sbd_error_t	*drmach_board_poweron(drmachid_t id);
extern sbd_error_t	*drmach_board_test(drmachid_t id, drmach_opts_t *opts,
				int force);

extern sbd_error_t	*drmach_board_unassign(drmachid_t id);

extern sbd_error_t	*drmach_configure(drmachid_t id, int flags);

extern sbd_error_t	*drmach_cpu_disconnect(drmachid_t id);
extern sbd_error_t	*drmach_cpu_get_id(drmachid_t id, processorid_t *cpuid);
extern sbd_error_t	*drmach_cpu_get_impl(drmachid_t id, int *ip);
extern void		 drmach_cpu_flush_ecache_sync(void);

extern sbd_error_t	*drmach_get_dip(drmachid_t id, dev_info_t **dip);

extern sbd_error_t	*drmach_io_is_attached(drmachid_t id, int *yes);
extern sbd_error_t	*drmach_io_post_attach(drmachid_t id);
extern sbd_error_t	*drmach_io_post_release(drmachid_t id);
extern sbd_error_t	*drmach_io_pre_release(drmachid_t id);
extern sbd_error_t	*drmach_io_unrelease(drmachid_t id);

extern sbd_error_t	*drmach_mem_add_span(drmachid_t id,
				uint64_t basepa, uint64_t size);
extern sbd_error_t	*drmach_mem_del_span(drmachid_t id,
				uint64_t basepa, uint64_t size);
extern sbd_error_t	*drmach_mem_disable(drmachid_t id);
extern sbd_error_t	*drmach_mem_enable(drmachid_t id);
extern sbd_error_t	*drmach_mem_get_base_physaddr(drmachid_t id,
				uint64_t *pa);
extern sbd_error_t	*drmach_mem_get_memlist(drmachid_t id,
				struct memlist **ml);
extern sbd_error_t	*drmach_mem_get_slice_size(drmachid_t, uint64_t *);

extern sbd_error_t	*drmach_release(drmachid_t id);
extern sbd_error_t	*drmach_status(drmachid_t id, drmach_status_t *stat);
extern sbd_error_t	*drmach_unconfigure(drmachid_t id, int flags);
extern int		drmach_log_sysevent(int board, char *hint, int flag,
					    int verbose);

extern int		drmach_verify_sr(dev_info_t *dip, int sflag);
extern void		drmach_suspend_last();
extern void		drmach_resume_first();

#endif

#ifdef __cplusplus
}
#endif

#endif /* _SYS_DRMACH_H_ */
