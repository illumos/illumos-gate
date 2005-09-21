/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DRMACH_H_
#define	_SYS_DRMACH_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/processor.h>
#include <sys/sbd_ioctl.h>
#include <sys/sysevent.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Starcat platform specific routines currently only defined
 * in starcat.c and referenced by DR.
 */
extern int	plat_max_boards();
extern int	plat_max_cpu_units_per_board();
extern int	plat_max_io_units_per_board();

#define	MAX_BOARDS		plat_max_boards()
#define	MAX_CPU_UNITS_PER_BOARD	plat_max_cpu_units_per_board()
#define	MAX_MEM_UNITS_PER_BOARD	1
#define	MAX_IO_UNITS_PER_BOARD	plat_max_io_units_per_board()
#define	MAX_CMP_UNITS_PER_BOARD	4
#define	MAX_CORES_PER_CMP	2

/* flags for drmach_configure() and drmach_unconfigure() */
#define	DRMACH_DEVI_FORCE	1
#define	DRMACH_DEVI_REMOVE	2

/* returned with drmach_board_find_devices callback */
#define	DRMACH_DEVTYPE_CMP	"cmp"
#define	DRMACH_DEVTYPE_CPU	"cpu"
#define	DRMACH_DEVTYPE_MEM	"memory"
#define	DRMACH_DEVTYPE_PCI	"pci"
#define	DRMACH_DEVTYPE_SBUS	"sbus"
#define	DRMACH_DEVTYPE_WCI	"wci"

/* number of bytes in smallest coherency unit of this machine */
#define	DRMACH_COHERENCY_UNIT	64

typedef void *drmachid_t;

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

extern sbd_error_t	*drmach_copy_rename_init(
				drmachid_t dst_id, uint64_t dst_slice_offset,
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
extern sbd_error_t	*drmach_mem_get_alignment(drmachid_t id, uint64_t *pa);
extern sbd_error_t	*drmach_mem_get_base_physaddr(drmachid_t id,
				uint64_t *pa);
extern sbd_error_t	*drmach_mem_get_memlist(drmachid_t id,
				struct memlist **ml);
extern sbd_error_t	*drmach_mem_get_size(drmachid_t id, uint64_t *bytes);
extern sbd_error_t	*drmach_mem_get_slice_size(drmachid_t id,
				uint64_t *bytes);
extern processorid_t	 drmach_mem_cpu_affinity(drmachid_t id);
extern int		 drmach_allow_memrange_modify(drmachid_t id);

extern sbd_error_t	*drmach_release(drmachid_t id);
extern sbd_error_t	*drmach_status(drmachid_t id, drmach_status_t *stat);
extern sbd_error_t	*drmach_unconfigure(drmachid_t id, int flags);
extern int		drmach_log_sysevent(int board, char *hint, int flag,
					    int verbose);

extern int		drmach_verify_sr(dev_info_t *dip, int sflag);
extern void		drmach_suspend_last();
extern void		drmach_resume_first();

#ifdef __cplusplus
}
#endif

#endif /* _SYS_DRMACH_H_ */
