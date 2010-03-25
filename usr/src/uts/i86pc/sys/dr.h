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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#ifndef _SYS_DR_H
#define	_SYS_DR_H
#include <sys/types.h>
#include <sys/note.h>
#include <sys/processor.h>
#include <sys/obpdefs.h>
#include <sys/memlist.h>
#include <sys/mem_config.h>
#include <sys/param.h>			/* for MAXPATHLEN */
#include <sys/varargs.h>
#include <sys/sbd_ioctl.h>
#include <sys/dr_util.h>
#include <sys/drmach.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * helper macros for constructing and reporting internal error messages.
 * NOTE: each module which uses one or more this these macros is expected
 * to supply a char *dr_ie_fmt string containing the SCCS filename
 * expansion macro (percent M percent) and a sprintf %d to render the
 * line number argument.
 */
#define	DR_INTERNAL_ERROR(hp)				\
	drerr_new(1, ESBD_INTERNAL, dr_ie_fmt, __LINE__)

#define	DR_OP_INTERNAL_ERROR(hp)			\
	drerr_set_c(CE_WARN, &(hp)->h_err,		\
		ESBD_INTERNAL, dr_ie_fmt, __LINE__)

#define	DR_DEV_INTERNAL_ERROR(cp)			\
	drerr_set_c(CE_WARN, &(cp)->sbdev_error,	\
		ESBD_INTERNAL, dr_ie_fmt, __LINE__)

/*
 * Macros for keeping an error code and an associated list of integers.
 */
#define	DR_MAX_ERR_INT		(32)
#define	DR_GET_E_CODE(sep)	((sep)->e_code)
#define	DR_SET_E_CODE(sep, en)	((sep)->e_code = (en))
#define	DR_GET_E_RSC(sep)	((sep)->e_rsc)

/* Number of device node types. */
#define	DR_MAXNUM_NT		3

/* used to map sbd_comp_type_t to array index */
#define	DEVSET_NIX(t)					\
	(((t) == SBD_COMP_CPU) ? 0 :			\
	((t) == SBD_COMP_MEM) ? 1 :			\
	((t) == SBD_COMP_IO) ? 2 :			\
	((t) == SBD_COMP_CMP) ? 0 : DR_MAXNUM_NT)

/*
 * Format of dr_devset_t bit masks:
 *
 * 64    56        48        40        32        24        16        8         0
 *  |....|IIII|IIII|IIII|IIII|MMMM|MMMM|CCCC|CCCC|CCCC|CCCC|CCCC|CCCC|CCCC|CCCC|
 *
 * 1 = indicates respective component present/attached.
 * I = I/O, M = Memory, C = CPU.
 */
#define	DEVSET_CPU_OFFSET	0
#define	DEVSET_CPU_NUMBER	32
#define	DEVSET_MEM_OFFSET	(DEVSET_CPU_OFFSET + DEVSET_CPU_NUMBER)
#define	DEVSET_MEM_NUMBER	8
#define	DEVSET_IO_OFFSET	(DEVSET_MEM_OFFSET + DEVSET_MEM_NUMBER)
#define	DEVSET_IO_NUMBER	16
#define	DEVSET_MAX_BITS		(DEVSET_IO_OFFSET + DEVSET_IO_NUMBER)

#define	DEVSET_BIX(t)					\
	(((t) == SBD_COMP_CPU) ? DEVSET_CPU_OFFSET :	\
	((t) == SBD_COMP_MEM) ? DEVSET_MEM_OFFSET :	\
	((t) == SBD_COMP_IO) ? DEVSET_IO_OFFSET :	\
	((t) == SBD_COMP_CMP) ? DEVSET_CPU_OFFSET : 0)

#define	DEVSET_NT2DEVPOS(t, u)	(((t) == SBD_COMP_CMP) ?\
	(DEVSET_BIX(t) + (u) * MAX_CORES_PER_CMP) : DEVSET_BIX(t) + (u))

#if (DEVSET_MAX_BITS <= 64)
typedef uint64_t		dr_devset_t;

#define	DEVSET_ONEUNIT		((dr_devset_t)1)
#define	DEVSET_ANYUNIT		((dr_devset_t)(-1))
#define	DEVSET_CPU_NMASK	((dr_devset_t)((1ULL << DEVSET_CPU_NUMBER) - 1))
#define	DEVSET_MEM_NMASK	((dr_devset_t)((1ULL << DEVSET_MEM_NUMBER) - 1))
#define	DEVSET_IO_NMASK		((dr_devset_t)((1ULL << DEVSET_IO_NUMBER) - 1))
#define	DEVSET_CMP_NMASK	((dr_devset_t)((1ULL << MAX_CORES_PER_CMP) - 1))

#define	DEVSET_NMASK(t)					\
	(((t) == SBD_COMP_CPU) ? DEVSET_CPU_NMASK :	\
	((t) == SBD_COMP_MEM) ? DEVSET_MEM_NMASK :	\
	((t) == SBD_COMP_IO) ? DEVSET_IO_NMASK :	\
	((t) == SBD_COMP_CMP) ? DEVSET_CPU_NMASK : 0)

#define	DEVSET_MASK					\
	((DEVSET_CPU_NMASK << DEVSET_CPU_OFFSET) | 	\
	(DEVSET_MEM_NMASK << DEVSET_MEM_OFFSET) | 	\
	(DEVSET_IO_NMASK << DEVSET_IO_OFFSET))

#define	DEVSET(t, u) \
	(((u) == DEVSET_ANYUNIT) ? \
		((DEVSET_NMASK(t) << DEVSET_NT2DEVPOS((t), 0)) & \
		DEVSET_MASK) : \
	((t) == SBD_COMP_CMP) ? \
		(DEVSET_CMP_NMASK << DEVSET_NT2DEVPOS((t), (u))) : \
		(DEVSET_ONEUNIT << DEVSET_NT2DEVPOS((t), (u))))

#define	DEVSET_IS_NULL(ds)	((ds) == 0)
#define	DEVSET_IN_SET(ds, t, u)	(((ds) & DEVSET((t), (u))) != 0)
#define	DEVSET_ADD(ds, t, u)	((ds) |= DEVSET((t), (u)))
#define	DEVSET_DEL(ds, t, u)	((ds) &= ~DEVSET((t), (u)))
#define	DEVSET_AND(ds1, ds2)	((ds1) & (ds2))
#define	DEVSET_OR(ds1, ds2)	((ds1) | (ds2))
#define	DEVSET_NAND(ds1, ds2)	((ds1) & ~(ds2))
#define	DEVSET_GET_UNITSET(ds, t) \
	(((ds) & DEVSET((t), DEVSET_ANYUNIT)) >> DEVSET_NT2DEVPOS((t), 0))
#define	DEVSET_FMT_STR		"0x%" PRIx64 ""
#define	DEVSET_FMT_ARG(ds)	(ds)
#else	/* DEVSET_MAX_BITS <= 64 */
#error please implement devset with bitmap to support more 64 devices
#endif	/* DEVSET_MAX_BITS <= 64 */

/*
 * Ops for dr_board_t.b_dev_*
 */
#define	DR_DEV_IS(ds, cp)	DEVSET_IN_SET( \
					(cp)->sbdev_bp->b_dev_##ds, \
					(cp)->sbdev_type, \
					(cp)->sbdev_unum)

#define	DR_DEV_ADD(ds, cp)	DEVSET_ADD( \
					(cp)->sbdev_bp->b_dev_##ds, \
					(cp)->sbdev_type, \
					(cp)->sbdev_unum)

#define	DR_DEV_DEL(ds, cp)	DEVSET_DEL( \
					(cp)->sbdev_bp->b_dev_##ds, \
					(cp)->sbdev_type, \
					(cp)->sbdev_unum)

/*
 * Ops for dr_board_t.b_dev_present
 */
#define	DR_DEV_IS_PRESENT(cp)		DR_DEV_IS(present, cp)
#define	DR_DEV_SET_PRESENT(cp)		DR_DEV_ADD(present, cp)
#define	DR_DEV_CLR_PRESENT(cp)		DR_DEV_DEL(present, cp)

/*
 * Ops for dr_board_t.b_dev_attached
 */
#define	DR_DEV_IS_ATTACHED(cp)		DR_DEV_IS(attached, cp)
#define	DR_DEV_SET_ATTACHED(cp)		DR_DEV_ADD(attached, cp)
#define	DR_DEV_CLR_ATTACHED(cp)		DR_DEV_DEL(attached, cp)

/*
 * Ops for dr_board_t.b_dev_released
 */
#define	DR_DEV_IS_RELEASED(cp)		DR_DEV_IS(released, cp)
#define	DR_DEV_SET_RELEASED(cp)		DR_DEV_ADD(released, cp)
#define	DR_DEV_CLR_RELEASED(cp)		DR_DEV_DEL(released, cp)

/*
 * Ops for dr_board_t.b_dev_unreferenced
 */
#define	DR_DEV_IS_UNREFERENCED(cp)	DR_DEV_IS(unreferenced, cp)
#define	DR_DEV_SET_UNREFERENCED(cp)	DR_DEV_ADD(unreferenced, cp)
#define	DR_DEV_CLR_UNREFERENCED(cp)	DR_DEV_DEL(unreferenced, cp)

#define	DR_DEVS_PRESENT(bp) \
			((bp)->b_dev_present)
#define	DR_DEVS_ATTACHED(bp) \
			((bp)->b_dev_attached)
#define	DR_DEVS_RELEASED(bp) \
			((bp)->b_dev_released)
#define	DR_DEVS_UNREFERENCED(bp) \
			((bp)->b_dev_unreferenced)
#define	DR_DEVS_UNATTACHED(bp) \
			((bp)->b_dev_present & ~(bp)->b_dev_attached)
#define	DR_DEVS_CONFIGURE(bp, devs) \
			((bp)->b_dev_attached = (devs))
#define	DR_DEVS_DISCONNECT(bp, devs) \
			((bp)->b_dev_present &= ~(devs))
#define	DR_DEVS_CANCEL(bp, devs) \
			((bp)->b_dev_released &= ~(devs), \
			(bp)->b_dev_unreferenced &= ~(devs))

/*
 * CMP Specific Helpers
 */
#define	DR_CMP_CORE_UNUM(cmp, core)	((cmp) * MAX_CORES_PER_CMP + (core))

/*
 * For CPU and CMP devices, DR_UNUM2SBD_UNUM is used to extract the physical
 * CPU/CMP id from the device id.
 */
#define	DR_UNUM2SBD_UNUM(n, d)		\
	((d) == SBD_COMP_CPU ? ((n) / MAX_CORES_PER_CMP) : \
	(d) == SBD_COMP_CMP ? ((n) / MAX_CORES_PER_CMP) : (n))

/*
 * Some stuff to assist in debug.
 */
#ifdef DEBUG
#define	DRDBG_STATE	0x00000001
#define	DRDBG_QR	0x00000002
#define	DRDBG_CPU	0x00000004
#define	DRDBG_MEM	0x00000008
#define	DRDBG_IO	0x00000010

#define	PR_ALL		if (dr_debug)			printf
#define	PR_STATE	if (dr_debug & DRDBG_STATE)	printf
#define	PR_QR		if (dr_debug & DRDBG_QR)	prom_printf
#define	PR_CPU		if (dr_debug & DRDBG_CPU)	printf
#define	PR_MEM		if (dr_debug & DRDBG_MEM)	printf
#define	PR_IO		if (dr_debug & DRDBG_IO)	printf
#define	PR_MEMLIST_DUMP	if (dr_debug & DRDBG_MEM)	MEMLIST_DUMP

extern uint_t	dr_debug;
#else /* DEBUG */
#define	PR_ALL		_NOTE(CONSTANTCONDITION) if (0) printf
#define	PR_STATE	PR_ALL
#define	PR_QR		PR_ALL
#define	PR_CPU		PR_ALL
#define	PR_MEM		PR_ALL
#define	PR_IO		PR_ALL
#define	PR_MEMLIST_DUMP	_NOTE(CONSTANTCONDITION) if (0) MEMLIST_DUMP

#endif /* DEBUG */

/*
 * dr_board_t b_sflags.
 */
#define	DR_BSLOCK	0x01	/* for blocking status (protected by b_slock) */

typedef const char	*fn_t;

/*
 * Unsafe devices based on dr.conf prop "unsupported-io-drivers"
 */
typedef struct {
	char	**devnames;
	uint_t	ndevs;
} dr_unsafe_devs_t;

/*
 * Device states.
 * PARTIAL state is really only relevant for board state.
 */
typedef enum {
	DR_STATE_EMPTY = 0,
	DR_STATE_OCCUPIED,
	DR_STATE_CONNECTED,
	DR_STATE_UNCONFIGURED,
	DR_STATE_PARTIAL,		/* part connected, part configured */
	DR_STATE_CONFIGURED,
	DR_STATE_RELEASE,
	DR_STATE_UNREFERENCED,
	DR_STATE_FATAL,
	DR_STATE_MAX
} dr_state_t;

typedef struct dr_handle {
	struct dr_board	*h_bd;
	sbd_error_t	*h_err;
	int		h_op_intr;	/* nz if op interrupted */
	dev_t		h_dev;		/* dev_t of opened device */
	int		h_cmd;		/* PIM ioctl argument */
	int		h_mode;		/* device open mode */
	sbd_cmd_t 	h_sbdcmd;	/* copied-in ioctl cmd struct */
	sbd_ioctl_arg_t	*h_iap;		/* ptr to caller-space cmd struct */
	dr_devset_t	h_devset;	/* based on h_dev */
	uint_t		h_ndi;
	drmach_opts_t	h_opts;		/* command-line platform options */
} dr_handle_t;

typedef struct dr_common_unit {
	dr_state_t		sbdev_state;
	sbd_state_t		sbdev_ostate;
	sbd_cond_t		sbdev_cond;
	time_t			sbdev_time;
	int			sbdev_busy;
	struct dr_board		*sbdev_bp;
	int			sbdev_unum;
	sbd_comp_type_t		sbdev_type;
	drmachid_t		sbdev_id;
	char			sbdev_path[MAXNAMELEN];
	sbd_error_t		*sbdev_error;
} dr_common_unit_t;

typedef struct dr_mem_unit {
	dr_common_unit_t	sbm_cm;		/* mem-unit state */
	uint_t			sbm_flags;
	pfn_t			sbm_basepfn;
	pgcnt_t			sbm_npages;
	pgcnt_t			sbm_pageslost;
	struct memlist		*sbm_dyn_segs;	/* kphysm_add_dynamic segs */
	/*
	 * The following fields are used during
	 * the memory detach process only. sbm_mlist
	 * will be used to store the board memlist
	 * following a detach.  The memlist will be
	 * used to re-attach the board when configuring
	 * the unit directly after an unconfigure.
	 */
	struct dr_mem_unit	*sbm_peer;
	struct memlist		*sbm_mlist;
	struct memlist		*sbm_del_mlist;
	memhandle_t		sbm_memhandle;
	uint64_t		sbm_alignment_mask;
	uint64_t		sbm_slice_base;
	uint64_t		sbm_slice_top;
	uint64_t		sbm_slice_size;
} dr_mem_unit_t;

/*
 * Currently only maintain state information for individual
 * components.
 */
typedef struct dr_cpu_unit {
	dr_common_unit_t	sbc_cm;		/* cpu-unit state */
	processorid_t		sbc_cpu_id;
	cpu_flag_t		sbc_cpu_flags;	/* snapshot of CPU flags */
	ushort_t		sbc_pad1;	/* padded for compatibility */
	int			sbc_speed;
	int			sbc_ecache;
	int			sbc_cpu_impl;
} dr_cpu_unit_t;

typedef struct dr_io_unit {
	dr_common_unit_t	sbi_cm;		/* io-unit state */
} dr_io_unit_t;

typedef union {
	dr_common_unit_t	du_common;
	dr_mem_unit_t		du_mem;
	dr_cpu_unit_t		du_cpu;
	dr_io_unit_t		du_io;
} dr_dev_unit_t;

typedef struct dr_board {
	kmutex_t	b_lock;		/* lock for this board struct */
	kmutex_t	b_slock;	/* lock for status on the board */
	kcondvar_t	b_scv;		/* condvar for status on the board */
	int		b_sflags;	/* for serializing status */
	sbd_state_t	b_rstate;	/* board's cfgadm receptacle state */
	sbd_state_t	b_ostate;	/* board's cfgadm occupant state */
	sbd_cond_t	b_cond;		/* cfgadm condition */
	int		b_busy;
	int		b_assigned;
	time_t		b_time;		/* time of last board operation */
	char		b_type[MAXNAMELEN];
	drmachid_t	b_id;
	int		b_num;			/* board number */
	int		b_ndev;			/* # of devices on board */
	dev_info_t	*b_dip;			/* dip for make-nodes */
	dr_state_t	b_state;		/* board DR state */
	dr_devset_t	b_dev_present;		/* present mask */
	dr_devset_t	b_dev_attached;		/* attached mask */
	dr_devset_t	b_dev_released;		/* released mask */
	dr_devset_t	b_dev_unreferenced;	/* unreferenced mask */
	char		b_path[MAXNAMELEN];
	dr_dev_unit_t	*b_dev[DR_MAXNUM_NT];
} dr_board_t;

/*
 * dr_quiesce.c interfaces
 */
struct dr_sr_handle;
typedef struct dr_sr_handle dr_sr_handle_t;

extern dr_sr_handle_t	*dr_get_sr_handle(dr_handle_t *handle);
extern void		dr_release_sr_handle(dr_sr_handle_t *srh);
extern int		dr_suspend(dr_sr_handle_t *srh);
extern void		dr_resume(dr_sr_handle_t *srh);
extern void		dr_check_devices(dev_info_t *dip, int *refcount,
			    dr_handle_t *handle, uint64_t *arr, int *idx,
			    int len, int *refcount_non_gldv3);
extern int		dr_pt_test_suspend(dr_handle_t *hp);

/*
 * dr_cpu.c interface
 */
extern void		dr_init_cpu_unit(dr_cpu_unit_t *cp);
extern int		dr_pre_attach_cpu(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern void		dr_attach_cpu(dr_handle_t *hp, dr_common_unit_t *cp);
extern int		dr_post_attach_cpu(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern int		dr_pre_release_cpu(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern int		dr_pre_detach_cpu(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern void		dr_detach_cpu(dr_handle_t *hp, dr_common_unit_t *cp);
extern int		dr_post_detach_cpu(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern int		dr_cpu_status(dr_handle_t *hp, dr_devset_t devset,
					sbd_dev_stat_t *dsp);
extern int		dr_cancel_cpu(dr_cpu_unit_t *cp);
extern int		dr_disconnect_cpu(dr_cpu_unit_t *cp);


/*
 * dr_mem.c interface
 */
extern void		dr_init_mem_unit(dr_mem_unit_t *mp);
extern int		dr_pre_attach_mem(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern void		dr_attach_mem(dr_handle_t *hp, dr_common_unit_t *cp);
extern int		dr_post_attach_mem(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern int		dr_pre_release_mem(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern void		dr_release_mem(dr_common_unit_t *cp);
extern void		dr_release_mem_done(dr_common_unit_t *cp);
extern int		dr_pre_detach_mem(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern void		dr_detach_mem(dr_handle_t *, dr_common_unit_t *);
extern int		dr_post_detach_mem(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern int		dr_mem_status(dr_handle_t *hp, dr_devset_t devset,
					sbd_dev_stat_t *dsp);
extern int		dr_cancel_mem(dr_mem_unit_t *mp);
extern int		dr_disconnect_mem(dr_mem_unit_t *mp);

/*
 * dr_io.c interface
 */
extern void		dr_init_io_unit(dr_io_unit_t *io);
extern int		dr_pre_attach_io(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern void		dr_attach_io(dr_handle_t *hp, dr_common_unit_t *cp);
extern int		dr_post_attach_io(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern int		dr_pre_release_io(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern int		dr_pre_detach_io(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern void		dr_detach_io(dr_handle_t *hp, dr_common_unit_t *cp);
extern int		dr_post_detach_io(dr_handle_t *hp,
				dr_common_unit_t **devlist, int devnum);
extern int		dr_io_status(dr_handle_t *hp, dr_devset_t devset,
					sbd_dev_stat_t *dsp);
extern int		dr_disconnect_io(dr_io_unit_t *ip);


/*
 * dr.c interface
 */
extern void dr_op_err(int ce, dr_handle_t *hp, int code, char *fmt, ...);
extern void dr_dev_err(int ce, dr_common_unit_t *cp, int code);

extern dr_cpu_unit_t	*dr_get_cpu_unit(dr_board_t *bp, int unit_num);
extern dr_mem_unit_t	*dr_get_mem_unit(dr_board_t *bp, int unit_num);
extern dr_io_unit_t	*dr_get_io_unit(dr_board_t *bp, int unit_num);

extern dr_board_t	*dr_lookup_board(int board_num);
extern int		dr_release_dev_done(dr_common_unit_t *cp);
extern char		*dr_nt_to_dev_type(int type);
extern void		dr_device_transition(dr_common_unit_t *cp,
				dr_state_t new_state);
extern void		dr_lock_status(dr_board_t *bp);
extern void		dr_unlock_status(dr_board_t *bp);
extern int		dr_cmd_flags(dr_handle_t *hp);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DR_H */
