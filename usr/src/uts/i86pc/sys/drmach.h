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

#ifndef _SYS_DRMACH_H_
#define	_SYS_DRMACH_H_
#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sysevent.h>
#include <sys/x86_archext.h>
#include <sys/sbd_ioctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_BOARDS		drmach_max_boards()
#define	MAX_MEM_UNITS_PER_BOARD	drmach_max_mem_units_per_board()
#define	MAX_IO_UNITS_PER_BOARD	drmach_max_io_units_per_board()
#define	MAX_CMP_UNITS_PER_BOARD	drmach_max_cmp_units_per_board()

/* DR uses MAX_CORES_PER_CMP as number of logical CPUs within a CMP. */
#define	MAX_CORES_PER_CMP	drmach_max_core_per_cmp()

/* Maximum possible logical CPUs per board. */
#define	MAX_CPU_UNITS_PER_BOARD	(MAX_CMP_UNITS_PER_BOARD * MAX_CORES_PER_CMP)

/* Check whether CPU is CMP. True if chip has more than one core/thread. */
#define	CPU_IMPL_IS_CMP(impl)	(MAX_CORES_PER_CMP > 1)

/* CPU implementation ID for Intel Nehalem CPU. */
#define	X86_CPU_IMPL_NEHALEM_EX	0x062E0000
#define	X86_CPU_IMPL_UNKNOWN	0x00000000

/* returned with drmach_board_find_devices callback */
#define	DRMACH_DEVTYPE_CPU	"cpu"
#define	DRMACH_DEVTYPE_MEM	"memory"
#define	DRMACH_DEVTYPE_PCI	"pci"

/*
 * x86 platform specific routines currently only defined
 * in drmach_acpi.c and referenced by DR.
 */

typedef void *drmachid_t;

typedef struct {
	boolean_t	assigned;
	boolean_t	powered;
	boolean_t	configured;
	boolean_t	busy;
	boolean_t	empty;
	sbd_cond_t	cond;
	char		type[SBD_TYPE_LEN];
	char		info[SBD_MAX_INFO];
} drmach_status_t;

typedef struct {
	int	size;
	char	*copts;
} drmach_opts_t;

typedef struct {
	uint64_t mi_basepa;
	uint64_t mi_size;
	uint64_t mi_slice_base;
	uint64_t mi_slice_top;
	uint64_t mi_slice_size;
	uint64_t mi_alignment_mask;
} drmach_mem_info_t;

extern uint_t		drmach_max_boards(void);
extern uint_t		drmach_max_io_units_per_board(void);
extern uint_t		drmach_max_cmp_units_per_board(void);
extern uint_t		drmach_max_mem_units_per_board(void);
extern uint_t		drmach_max_core_per_cmp(void);

extern sbd_error_t	*drmach_get_dip(drmachid_t id, dev_info_t **dip);
extern sbd_error_t	*drmach_release(drmachid_t id);
extern sbd_error_t	*drmach_pre_op(int cmd, drmachid_t id,
				drmach_opts_t *opts, void *devsetp);
extern sbd_error_t	*drmach_post_op(int cmd, drmachid_t id,
				drmach_opts_t *opts, int rv);
extern sbd_error_t	*drmach_configure(drmachid_t id, int flags);
extern sbd_error_t	*drmach_unconfigure(drmachid_t id, int flags);
extern sbd_error_t	*drmach_status(drmachid_t id, drmach_status_t *stat);
extern sbd_error_t	*drmach_passthru(drmachid_t id,
						drmach_opts_t *opts);

extern sbd_error_t	*drmach_board_find_devices(drmachid_t id, void *a,
		sbd_error_t *(*found)(void *a, const char *, int, drmachid_t));
extern int		drmach_board_lookup(int bnum, drmachid_t *id);
extern sbd_error_t	*drmach_board_name(int bnum, char *buf, int buflen);
extern sbd_error_t	*drmach_board_assign(int bnum, drmachid_t *id);
extern sbd_error_t	*drmach_board_unassign(drmachid_t id);
extern sbd_error_t	*drmach_board_poweroff(drmachid_t id);
extern sbd_error_t	*drmach_board_poweron(drmachid_t id);
extern sbd_error_t	*drmach_board_test(drmachid_t id, drmach_opts_t *opts,
						int force);
extern sbd_error_t	*drmach_board_connect(drmachid_t id,
						drmach_opts_t *opts);
extern sbd_error_t	*drmach_board_disconnect(drmachid_t id,
						drmach_opts_t *opts);
extern sbd_error_t	*drmach_board_deprobe(drmachid_t id);
extern int		drmach_board_is_floating(drmachid_t);

extern sbd_error_t	*drmach_cpu_get_id(drmachid_t id, processorid_t *cpuid);
extern sbd_error_t	*drmach_cpu_get_impl(drmachid_t id, int *ip);
extern sbd_error_t	*drmach_cpu_disconnect(drmachid_t id);

extern sbd_error_t	*drmach_io_is_attached(drmachid_t id, int *yes);
extern sbd_error_t	*drmach_io_post_attach(drmachid_t id);
extern sbd_error_t	*drmach_io_pre_release(drmachid_t id);
extern sbd_error_t	*drmach_io_unrelease(drmachid_t id);
extern sbd_error_t	*drmach_io_post_release(drmachid_t id);

extern sbd_error_t	*drmach_mem_get_slice_info(drmachid_t id,
				uint64_t *basepa, uint64_t *endpa,
				uint64_t *sizep);
extern sbd_error_t	*drmach_mem_get_memlist(drmachid_t id,
				struct memlist **ml);
extern sbd_error_t	*drmach_mem_get_info(drmachid_t, drmach_mem_info_t *);
extern sbd_error_t	*drmach_mem_enable(drmachid_t id);
extern sbd_error_t	*drmach_mem_disable(drmachid_t id);
extern sbd_error_t	*drmach_mem_add_span(drmachid_t id,
				uint64_t basepa, uint64_t size);
extern sbd_error_t	*drmach_mem_del_span(drmachid_t id,
				uint64_t basepa, uint64_t size);
extern sbd_error_t	*drmach_copy_rename_init(
				drmachid_t dst_id, drmachid_t src_id,
				struct memlist *src_copy_ml,
				drmachid_t *pgm_id);
extern sbd_error_t	*drmach_copy_rename_fini(drmachid_t id);
extern void		drmach_copy_rename(drmachid_t id);
extern int		drmach_copy_rename_need_suspend(drmachid_t id);

extern int		drmach_log_sysevent(int board, char *hint, int flag,
					    int verbose);

extern int		drmach_verify_sr(dev_info_t *dip, int sflag);
extern void		drmach_suspend_last();
extern void		drmach_resume_first();

#ifdef __cplusplus
}
#endif

#endif /* _SYS_DRMACH_H_ */
