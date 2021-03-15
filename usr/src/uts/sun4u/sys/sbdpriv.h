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

#ifndef _SYS_SBDPRIV_H
#define	_SYS_SBDPRIV_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/processor.h>
#include <sys/obpdefs.h>
#include <sys/memlist.h>
#include <sys/sbd_ioctl.h>
#include <sys/mem_config.h>
#include <sys/sbd.h>
#ifdef DEBUG
#include <sys/promif.h>
#endif


/*
 * This structure passes the information when the caller requests to
 * reserve a portion of unconfigured memory. It is also used to release
 * previously reserved memory
 */
struct sbd_mres {
	uint64_t	new_base_pa;	/* new base addr for physintalled */
	uint64_t	reserved_pa;	/* addr of the reserved mem */
	uint64_t	size;		/* size of the reserved chunk. */
};

int sbd_memory_reserve(dev_info_t *, uint64_t, struct sbd_mres *);
int sbd_memory_release(dev_info_t *, uint64_t, struct sbd_mres *);

/*	This error type is used inside sbd only */
typedef struct {
	int	e_errno;
	int	e_code;
	char	e_rsc[MAXPATHLEN];
} sbderror_t;

#include <sys/sbd.h>
#include <sys/sbd_error.h>

typedef enum {
	SBD_STATE_EMPTY = 0,
	SBD_STATE_OCCUPIED,
	SBD_STATE_CONNECTED,
	SBD_STATE_UNCONFIGURED,
	SBD_STATE_PARTIAL,
	SBD_STATE_CONFIGURED,
	SBD_STATE_RELEASE,
	SBD_STATE_UNREFERENCED,
	SBD_STATE_FATAL,
	SBD_STATE_MAX
} sbd_istate_t;

typedef struct {
	sbderror_t	*errp;
	sbd_flags_t	flags;
} sbd_treeinfo_t;

/*
 * generic flags (sbd_handle.h_flags)
 */
#define	SBD_FLAG_DEVI_FORCE	0x00000001

/* mirror of SBD_FLAG_FORCE from sbd_ioctl.h */
#define	SBD_IOCTL_FLAG_FORCE	0x00000004

#define	SBD_USER_FLAG_MASK	0x0000ffff

#define	SBD_KERN_FLAG_MASK	0xffff0000	/* no flags in use */

/*
 * Translation macros for sbd->sbdp flags
 */
#define	SBD_2_SBDP_FLAGS(f) (((f) & SBD_IOCTL_FLAG_FORCE) ? \
				SBDP_IOCTL_FLAG_FORCE : 0)

typedef struct sbd_handle {
	void		*h_sbd;
	sbderror_t	*h_err;
	dev_t		h_dev;		/* dev_t of opened device */
	int		h_cmd;		/* ioctl argument */
	int		h_mode;		/* device open mode */
	sbd_flags_t	h_flags;
	sbd_ioctl_arg_t	*h_iap;		/* points to kernel copy of ioargs */
	sbdp_opts_t	h_opts;		/* points to the platform options */
} sbd_handle_t;

#define	SBD_HD2ERR(hd)		((hd)->h_err)
#define	SBD_GET_ERR(ep)		((ep)->e_code)
#define	SBD_SET_ERR(ep, ec)	((ep)->e_code = (ec))
#define	SBD_GET_ERRNO(ep)	((ep)->e_errno)
#define	SBD_SET_ERRNO(ep, en)	((ep)->e_errno = (en))
#define	SBD_GET_ERRSTR(ep)	((ep)->e_rsc)

#define	SBD_SET_ERRSTR(ep, es)	\
{ \
	if ((es) && (*(es) != '\0')) \
		(void) strncpy((ep)->e_rsc, (es), MAXPATHLEN); \
}

#define	SBD_SET_IOCTL_ERR(ierr, code, rsc) \
{ \
	(ierr)->e_code = (int)(code); \
	if ((rsc) && (*(rsc) != '\0')) \
		bcopy((caddr_t)(rsc), \
			(caddr_t)(ierr)->e_rsc, \
			sizeof ((ierr)->e_rsc)); \
}

#define	SBD_FREE_ERR(ep) \
	((ep)->e_rsc[0] = '\0')

#define	SBD_GET_PERR(spe, ep) \
{ \
	(ep)->e_errno = EIO; \
	(ep)->e_code = (spe)->e_code; \
	if (*((spe)->e_rsc) != '\0') \
		bcopy((caddr_t)((spe)->e_rsc), \
			(caddr_t)((ep))->e_rsc, \
			sizeof (((ep))->e_rsc)); \
}

/*
 * dev_t is shared by PIM and PSM layers.
 *
 * Format = 31......16,15.......0
 *	    |   PIM   |   PSM   |
 */
#define	_SBD_DEVPIM_SHIFT	16
#define	_SBD_DEVPIM_MASK		0xffff
#define	_SBD_DEVPSM_MASK		0xffff

#define	SBD_GET_MINOR2INST(d)	(((d) >> _SBD_DEVPIM_SHIFT) & _SBD_DEVPIM_MASK)
#define	SBD_MAKE_MINOR(i, m) \
			((((i) & _SBD_DEVPIM_MASK) << _SBD_DEVPIM_SHIFT) | \
			((m) & _SBD_DEVPSM_MASK))

#define	GETSTRUCT(t, n) \
		((t *)kmem_zalloc((size_t)(n) * sizeof (t), KM_SLEEP))
#define	FREESTRUCT(p, t, n) \
		(kmem_free((caddr_t)(p), sizeof (t) * (size_t)(n)))

#define	GET_SOFTC(i)		ddi_get_soft_state(sbd_g.softsp, (i))
#define	ALLOC_SOFTC(i)		ddi_soft_state_zalloc(sbd_g.softsp, (i))
#define	FREE_SOFTC(i)		ddi_soft_state_free(sbd_g.softsp, (i))

/*
 * Per instance soft-state structure.
 */
typedef struct sbd_softstate {
	void		*sbd_boardlist;
	int		max_boards;
	int		wnode;
} sbd_softstate_t;

/*
 * dr Global data elements
 */
typedef struct {
	sbd_softstate_t	*softsp;	/* pointer to initialize soft state */
} sbd_global;

typedef struct {
	sbderror_t	dv_error;
	dev_info_t	*dv_dip;
} sbd_devlist_t;

extern int	plat_max_io_units_per_board();
extern int	plat_max_cmp_units_per_board();
extern int	plat_max_cpu_units_per_board();
extern int	plat_max_mem_units_per_board();
#define	MAX_IO_UNITS_PER_BOARD		plat_max_io_units_per_board()
#define	MAX_CMP_UNITS_PER_BOARD		plat_max_cmp_units_per_board()
#define	MAX_CPU_UNITS_PER_BOARD		plat_max_cpu_units_per_board()
#define	MAX_MEM_UNITS_PER_BOARD		plat_max_mem_units_per_board()
#define	SBD_MAX_UNITS_PER_BOARD		8
/* If any of the max units exceeds 5, this must be adjusted	*/

#define	SBD_MAX_INSTANCES		16

#define	SBD_NUM_STATES		((int)SBD_STATE_MAX)

#ifdef DEBUG
#define	SBD_DEVICE_TRANSITION(sb, nt, un, st) \
{ \
	int	_ostate, _nstate; \
	_ostate = (int)((sb)->sb_dev[NIX(nt)][un].u_common.sbdev_state); \
	_nstate = (int)(st); \
	PR_STATE("BOARD %d (%s.%d) STATE: %s(%d) -> %s(%d)\n", \
		(sb)->sb_num, \
		sbd_ct_str[nt], (un), \
		sbd_state_str[_ostate], _ostate, \
		sbd_state_str[_nstate], _nstate); \
	(void) drv_getparm(TIME, \
	(void *)&(sb)->sb_dev[NIX(nt)][un].u_common.sbdev_time); \
	(sb)->sb_dev[NIX(nt)][un].u_common.sbdev_state = (st); \
	(sb)->sb_dev[NIX(nt)][un].u_common.sbdev_ostate = ostate_cvt(st); \
	send_event = 1; \
}
#define	SBD_BOARD_TRANSITION(sb, st) \
{ \
	PR_STATE("BOARD %d STATE: %s(%d) -> %s(%d)\n", \
		(sb)->sb_num, \
		sbd_state_str[(int)(sb)->sb_state], (int)(sb)->sb_state, \
		sbd_state_str[(int)(st)], (int)(st)); \
	(sb)->sb_pstate = (sb)->sb_state; \
	(sb)->sb_state = (st); \
	send_event = 1; \
}
#else /* DEBUG */
#define	SBD_DEVICE_TRANSITION(sb, nt, un, st) \
{ \
	(sb)->sb_dev[NIX(nt)][un].u_common.sbdev_state = (st); \
	(sb)->sb_dev[NIX(nt)][un].u_common.sbdev_ostate = ostate_cvt(st); \
	(void) drv_getparm(TIME, \
		(void *)&(sb)->sb_dev[NIX(nt)][un].u_common.sbdev_time); \
	send_event = 1; \
}
#define	SBD_BOARD_TRANSITION(sb, st) \
		((sb)->sb_pstate = (sb)->sb_state, (sb)->sb_state = (st),  \
		send_event = 1)
#endif /* DEBUG */

#define	SBD_DEVICE_STATE(sb, nt, un) \
		((sb)->sb_dev[NIX(nt)][un].u_common.sbdev_state)
#define	SBD_BOARD_STATE(sb) \
		((sb)->sb_state)
#define	SBD_BOARD_PSTATE(sb) \
		((sb)->sb_pstate)

typedef uint32_t sbd_devset_t;

/*
 * sbd_priv_handle_t MUST appear first.
 */
typedef struct sbd_priv_handle {
	sbd_handle_t		sh_handle;
	void			*sh_arg;	/* raw ioctl arg */
	sbd_devset_t		sh_devset;	/* based on h_dev */
	sbd_devset_t		sh_orig_devset;	/* what client requested */
	sbderror_t		sh_err;
	struct sbd_priv_handle	*sh_next;
} sbd_priv_handle_t;

#define	SBD_MAXNUM_NT		3
#define	NIX(t)			(((t) == SBD_COMP_CPU) ? 0 : \
				((t) == SBD_COMP_MEM) ? 1 : \
				((t) == SBD_COMP_IO) ? 2 : \
				((t) == SBD_COMP_CMP) ? 0 : SBD_MAXNUM_NT)

#define	SBD_NUM_MC_PER_BOARD	4


typedef struct sbd_common_unit {
	sbd_istate_t		sbdev_state;
	sbd_cond_t		sbdev_cond;
	sbd_state_t		sbdev_ostate;
	time_t			sbdev_time;
	int			sbdev_busy;
	void			*sbdev_sbp;
	int			sbdev_unum;
	sbd_comp_type_t		sbdev_type;
	dev_info_t		*sbdev_dip;
} sbd_common_unit_t;

typedef struct sbd_mem_unit {
	sbd_common_unit_t	sbm_cm;
	sbd_istate_t		sbm_state;	/* mem-unit state */
	uint_t			sbm_flags;
	pfn_t			sbm_basepfn;
	pgcnt_t			sbm_npages;
	pgcnt_t			sbm_pageslost;
	/*
	 * The following fields are used during
	 * the memory detach process only. sbm_mlist
	 * will be used to store the board memlist
	 * following a detach. The memlist will be
	 * used to re-attach the board when configuring
	 * the unit directly after an unconfigure.
	 */
	struct sbd_mem_unit	*sbm_peer;
	struct memlist		*sbm_mlist;
	struct memlist		*sbm_del_mlist;
	memhandle_t		sbm_memhandle;
	pfn_t			sbm_alignment_mask;
	pfn_t			sbm_slice_offset;
	/*
	 * The following field is used to support the
	 * representation of all memory controllers on
	 * a board with one sbd_mem_unit_t.
	 */
	dev_info_t		*sbm_dip[SBD_NUM_MC_PER_BOARD];
	/*
	 * The following field determines if the memory on this board
	 * is part of an interleave across boards
	 */
	int			sbm_interleave;
} sbd_mem_unit_t;

/*
 * Currently only maintain state information for individual
 * components.
 */
typedef struct sbd_cpu_unit {
	sbd_common_unit_t	sbc_cm;		/* cpu-unit state */
	processorid_t		sbc_cpu_id;
	cpu_flag_t		sbc_cpu_flags;
	ushort_t		sbc_pad1;
	int			sbc_cpu_impl;
	int			sbc_speed;
	int			sbc_ecache;
} sbd_cpu_unit_t;

typedef struct sbd_io_unit {
	sbd_common_unit_t	sbi_cm;		/* io-unit state */
} sbd_io_unit_t;

typedef union {
	sbd_common_unit_t	u_common;
	sbd_mem_unit_t		_mu;
	sbd_cpu_unit_t		_cu;
	sbd_io_unit_t		_iu;
} sbd_dev_unit_t;

typedef struct {
	sbd_priv_handle_t	*sb_handle;
	int			sb_ref;		/* # of handle references */
	int			sb_num;		/* board number */
	void			*sb_softsp;	/* pointer to soft state */
	dev_info_t		*sb_topdip;	/* top devinfo of instance */
	sbd_istate_t		sb_state;	/* (current) board state */
	sbd_istate_t		sb_pstate;	/* previous board state */
	sbd_cond_t		sb_cond;	/* condition		*/
	sbd_state_t		sb_rstate;	/* receptacle state	*/
	sbd_state_t		sb_ostate;	/* occupant state	*/
		/*
		 * 0=CPU, 1=MEM, 2=IO, 3=NULL
		 */
	dev_info_t		**sb_devlist[SBD_MAXNUM_NT + 1];

	sbd_devset_t	sb_dev_present;		/* present mask */
	sbd_devset_t	sb_dev_attached;	/* attached mask */
	sbd_devset_t	sb_dev_released;	/* released mask */
	sbd_devset_t	sb_dev_unreferenced;	/* unreferenced mask */
	sbd_dev_unit_t	*sb_dev[SBD_MAXNUM_NT];

	char		*sb_cpupath[SBD_MAX_UNITS_PER_BOARD];
	char		*sb_mempath[SBD_MAX_UNITS_PER_BOARD];
	char		*sb_iopath[SBD_MAX_UNITS_PER_BOARD];

	int		sb_ndev;		/* number of devs */
	int		sb_errno;		/* store errno */
	int		sb_busy;		/* drain in progress */
	int		sb_assigned;
	int		sb_flags;
	kmutex_t	sb_flags_mutex;		/* mutex to protect flags */
	int		sb_wnode;
	int		sb_memaccess_ok;
	sbd_stat_t	sb_stat;		/* cached board status */
	processorid_t	sb_cpuid;		/* for starfire connect */
	time_t		sb_time;		/* time of last board op */
	kmutex_t	sb_mutex;
	kmutex_t	sb_slock;		/* status - unconfig, discon */
} sbd_board_t;

/* definitions for sb_flags */
#define	SBD_BOARD_STATUS_CACHED	1

#define	SBD_GET_BOARD_MEMUNIT(sb, un) \
			(&((sb)->sb_dev[NIX(SBD_COMP_MEM)][un]._mu))
#define	SBD_GET_BOARD_CPUUNIT(sb, un) \
			(&((sb)->sb_dev[NIX(SBD_COMP_CPU)][un]._cu))
#define	SBD_GET_BOARD_IOUNIT(sb, un) \
			(&((sb)->sb_dev[NIX(SBD_COMP_IO)][un]._iu))

typedef ushort_t	boardset_t;	/* assumes 16 boards max */

#define	BOARDSET(b)		((boardset_t)(1 << (b)))
#define	BOARD_IN_SET(bs, b)	(((bs) & BOARDSET(b)) != 0)
#define	BOARD_ADD(bs, b)	((bs) |= BOARDSET(b))
#define	BOARD_DEL(bs, b)	((bs) &= ~BOARDSET(b))

/*
 * Format of sbd_devset_t bit masks:
 *
 *	32		   16        8    4    0
 *	|....|....|...I|IIII|....|...M|CCCC|CCCC|
 * 1 = indicates respective component present/attached.
 * I = I/O, M = Memory, C = CPU.
 */
#define	DEVSET_ANYUNIT		(-1)
#define	_NT2DEVPOS(t, u)	((NIX(t) << 3) + (u))
#define	_DEVSET_MASK		0x001f01ff
#define	_CMP_DEVSET_MASK	0x11
#define	DEVSET(t, u) \
	(((u) == DEVSET_ANYUNIT) ? \
	    (sbd_devset_t)((0xff << _NT2DEVPOS((t), 0)) & _DEVSET_MASK) : \
	(((t) == SBD_COMP_CMP) ? \
	    (sbd_devset_t)(_CMP_DEVSET_MASK << _NT2DEVPOS((t), (u))) : \
	(sbd_devset_t)(1 << _NT2DEVPOS((t), (u)))))

#define	DEVSET_IN_SET(ds, t, u)	(((ds) & DEVSET((t), (u))) != 0)
#define	DEVSET_ADD(ds, t, u)	((ds) |= DEVSET((t), (u)))
#define	DEVSET_DEL(ds, t, u)	((ds) &= ~DEVSET((t), (u)))
#define	DEVSET_GET_UNITSET(ds, t) \
	(((ds) & DEVSET((t), DEVSET_ANYUNIT)) >> _NT2DEVPOS((t), 0))
/*
 * Ops for sbd_board_t.sb_dev_present
 */
#define	SBD_DEV_IS_PRESENT(bp, nt, un) \
			DEVSET_IN_SET((bp)->sb_dev_present, (nt), (un))
#define	SBD_DEV_SET_PRESENT(bp, nt, un) \
			DEVSET_ADD((bp)->sb_dev_present, (nt), (un))
#define	SBD_DEV_CLR_PRESENT(bp, nt, un) \
			DEVSET_DEL((bp)->sb_dev_present, (nt), (un))
/*
 * Ops for sbd_board_t.sb_dev_attached
 */
#define	SBD_DEV_IS_ATTACHED(bp, nt, un) \
			DEVSET_IN_SET((bp)->sb_dev_attached, (nt), (un))
#define	SBD_DEV_SET_ATTACHED(bp, nt, un) \
			DEVSET_ADD((bp)->sb_dev_attached, (nt), (un))
#define	SBD_DEV_CLR_ATTACHED(bp, nt, un) \
			DEVSET_DEL((bp)->sb_dev_attached, (nt), (un))
/*
 * Ops for sbd_board_t.sb_dev_released
 */
#define	SBD_DEV_IS_RELEASED(bp, nt, un) \
			DEVSET_IN_SET((bp)->sb_dev_released, (nt), (un))
#define	SBD_DEV_SET_RELEASED(bp, nt, un) \
			DEVSET_ADD((bp)->sb_dev_released, (nt), (un))
#define	SBD_DEV_CLR_RELEASED(bp, nt, un) \
			DEVSET_DEL((bp)->sb_dev_released, (nt), (un))
/*
 * Ops for sbd_board_t.sb_dev_unreferenced
 */
#define	SBD_DEV_IS_UNREFERENCED(bp, nt, un) \
			DEVSET_IN_SET((bp)->sb_dev_unreferenced, (nt), (un))
#define	SBD_DEV_SET_UNREFERENCED(bp, nt, un) \
			DEVSET_ADD((bp)->sb_dev_unreferenced, (nt), (un))
#define	SBD_DEV_CLR_UNREFERENCED(bp, nt, un) \
			DEVSET_DEL((bp)->sb_dev_unreferenced, (nt), (un))

#define	SBD_DEVS_PRESENT(bp) \
			((bp)->sb_dev_present)
#define	SBD_DEVS_ATTACHED(bp) \
			((bp)->sb_dev_attached)
#define	SBD_DEVS_RELEASED(bp) \
			((bp)->sb_dev_released)
#define	SBD_DEVS_UNREFERENCED(bp) \
			((bp)->sb_dev_unreferenced)
#define	SBD_DEVS_UNATTACHED(bp) \
			((bp)->sb_dev_present & ~(bp)->sb_dev_attached)
#define	SBD_DEVS_CONFIGURE(bp, devs) \
			((bp)->sb_dev_attached = (devs))
#define	SBD_DEVS_DISCONNECT(bp, devs) \
			((bp)->sb_dev_present &= ~(devs))
#define	SBD_DEVS_CANCEL(bp, devs) \
			((bp)->sb_dev_released &= ~(devs), \
			(bp)->sb_dev_unreferenced &= ~(devs))

/*
 * return values from sbd_cancel_cpu
 */
#define	SBD_CPUERR_NONE		0
#define	SBD_CPUERR_RECOVERABLE	-1
#define	SBD_CPUERR_FATAL	-2

/*
 * sbd_board_t.sbmem[].sbm_flags
 */
#define	SBD_MFLAG_RESERVED	0x01	/* mem unit reserved for delete */
#define	SBD_MFLAG_SOURCE	0x02	/* source brd of copy/rename op */
#define	SBD_MFLAG_TARGET	0x04	/* board selected as target */
#define	SBD_MFLAG_MEMUPSIZE	0x08	/* move from big to small board */
#define	SBD_MFLAG_MEMDOWNSIZE	0x10	/* move from small to big board */
#define	SBD_MFLAG_MEMRESIZE	0x18	/* move to different size board */
#define	SBD_MFLAG_RELOWNER	0x20	/* memory release (delete) owner */
#define	SBD_MFLAG_RELDONE	0x40

typedef struct {
	int	sfio_cmd;
	void	*sfio_arg;
} sbd_ioctl_t;

/*
 * 32bit support for sbd_ioctl_t.
 */
typedef struct {
	int32_t		sfio_cmd;
	uint32_t	sfio_arg;
} sbd_ioctl32_t;

/*
 * PSM-DR layers are only allowed to use lower 16 bits of dev_t.
 * B    - bottom 4 bits are for the slot number.
 * D    - device type chosen (0 = indicates all devices in slot).
 * U	- unit number if specific device type chosen.
 * X    - not used.
 *
 * Upper      Lower
 * XXXXUUUUDDDDBBBB
 *
 * Note that this format only allows attachment points to
 * either represent all the units on a board or one particular
 * unit.  A more general specification would permit any combination
 * of specific units and types to be represented by individual
 * attachment points.
 */
#define	SBD_DEV_SLOTMASK	0x000f
/*
 * These device level definitions are primarily for unit testing.
 */
#define	SBD_DEV_UNITMASK	0x0f00
#define	SBD_DEV_UNITSHIFT	8
#define	SBD_DEV_CPU		0x0010
#define	SBD_DEV_MEM		0x0020
#define	SBD_DEV_IO		0x0040
#define	SBD_DEV_TYPEMASK	(SBD_DEV_CPU | SBD_DEV_MEM | SBD_DEV_IO)
#define	SBD_DEV_TYPESHIFT	4

/*
 * Slot, Instance, and Minor number Macro definitions
 */
#define	SLOT2DEV(s)		((s) & SBD_DEV_SLOTMASK)
#define	SBDGETSLOT(unit)	((unit) & SBD_DEV_SLOTMASK)
/*
 * The following is primarily for unit testing.
 */
#define	ALLCPU2DEV(s)		(SBD_DEV_CPU | SLOT2DEV(s))
#define	ALLMEM2DEV(s)		(SBD_DEV_MEM | SLOT2DEV(s))
#define	ALLIO2DEV(s)		(SBD_DEV_IO | SLOT2DEV(s))
#define	_UNIT2DEV(u)		(((u) << SBD_DEV_UNITSHIFT) & \
					SBD_DEV_UNITMASK)
#define	CPUUNIT2DEV(s, c)	(_UNIT2DEV(c) | ALLCPU2DEV(s))
#define	MEMUNIT2DEV(s, m)	(_UNIT2DEV(m) | ALLMEM2DEV(s))
#define	IOUNIT2DEV(s, i)	(_UNIT2DEV(i) | ALLIO2DEV(s))

#define	DEV_IS_ALLUNIT(d)	(((d) & SBD_DEV_UNITMASK) == 0)
#define	_DEV_IS_ALLTYPE(d)	(((d) & SBD_DEV_TYPEMASK) == 0)
#define	DEV_IS_ALLBOARD(d)	(DEV_IS_ALLUNIT(d) && _DEV_IS_ALLTYPE(d))
#define	DEV_IS_CPU(d)		((d) & SBD_DEV_CPU)
#define	DEV_IS_MEM(d)		((d) & SBD_DEV_MEM)
#define	DEV_IS_IO(d)		((d) & SBD_DEV_IO)
#define	DEV_IS_ALLCPU(d)	(DEV_IS_ALLUNIT(d) && DEV_IS_CPU(d))
#define	DEV_IS_ALLMEM(d)	(DEV_IS_ALLUNIT(d) && DEV_IS_MEM(d))
#define	DEV_IS_ALLIO(d)		(DEV_IS_ALLUNIT(d) && DEV_IS_IO(d))
#define	DEV2UNIT(d) \
		((((d) & SBD_DEV_UNITMASK) >> SBD_DEV_UNITSHIFT) - 1)
#define	DEV2NT(d) \
		(DEV_IS_MEM(d) ? SBD_COMP_MEM : \
		DEV_IS_CPU(d) ? SBD_COMP_CPU : \
		DEV_IS_IO(d) ? SBD_COMP_IO : SBD_COMP_UNKNOWN)

/*
 * Macros to cast between PIM and PSM layers of the following
 * structures:
 *	board_t		<-> sbd_board_t
 *	sbd_handle_t	<-> sbd_priv_handle_t
 *	sbderror_t	<-> sbderror_t
 *	slot		-> board_t
 *	slot		-> sbd_board_t
 *	sbd_board_t	-> sbd_handle_t
 *	sbd_handle	-> sbderror_t
 */
#define	SBDH2BD(bd)		((sbd_board_t *)(bd))

#define	HD2MACHHD(hd)		((sbd_priv_handle_t *)(hd))
#define	MACHHD2HD(mhd)		((sbd_handle_t *)&((mhd)->sh_handle))

#define	ERR2MACHERR(err)	((sbderror_t *)(err))
#define	MACHERR2ERR(merr)	((sbderror_t *)(merr))

#define	BSLOT2MACHBD(b)		(&(sbd_boardlist[b]))
#define	BSLOT2BD(slot)		MACHBD2BD(BSLOT2MACHBD(slot))

#define	MACHBD2HD(sbp)		MACHHD2HD((sbp)->sb_handle)

#define	HD2MACHERR(hd)		ERR2MACHERR(SBD_HD2ERR(hd))

#define	MACHSRHD2HD(srh)	((srh)->sr_dr_handlep)

/*
 * CMP Specific Helpers
 */
#define	MAX_CORES_PER_CMP		2
#define	SBD_CMP_CORE_UNUM(cmp, core)	((cmp + (core * 512))
#define	SBD_CMP_NUM(unum)		(unum & 0x3)

/*
 * Some stuff to assist in debug.
 */
#ifdef DEBUG
#define	SBD_DBG_STATE	0x00000001
#define	SBD_DBG_QR	0x00000002
#define	SBD_DBG_CPU	0x00000004
#define	SBD_DBG_MEM	0x00000008
#define	SBD_DBG_IO	0x00000010
#define	SBD_DBG_HW	0x00000020
#define	SBD_DBG_BYP	0x00000040

#define	PR_ALL		if (sbd_debug)			printf
#define	PR_STATE	if (sbd_debug & SBD_DBG_STATE)	printf
#define	PR_QR		if (sbd_debug & SBD_DBG_QR)	prom_printf
#define	PR_CPU		if (sbd_debug & SBD_DBG_CPU)	printf
#define	PR_MEM		if (sbd_debug & SBD_DBG_MEM)	printf
#define	PR_IO		if (sbd_debug & SBD_DBG_IO)	printf
#define	PR_HW		if (sbd_debug & SBD_DBG_HW)	printf
#define	PR_BYP		if (sbd_debug & SBD_DBG_BYP)	prom_printf

#define	SBD_MEMLIST_DUMP(ml)	memlist_dump(ml)

extern uint_t	sbd_debug;
#else /* DEBUG */
#define	PR_ALL		if (0) printf
#define	PR_STATE	PR_ALL
#define	PR_QR		PR_ALL
#define	PR_CPU		PR_ALL
#define	PR_MEM		PR_ALL
#define	PR_IO		PR_ALL
#define	PR_HW		PR_ALL
#define	PR_BYP		PR_ALL

#define	SBD_MEMLIST_DUMP(ml)
#endif /* DEBUG */
extern char	*sbd_state_str[];
extern char	*sbd_ct_str[];

/*
 * event flag
 */
extern char send_event;

/*
 * IMPORTANT:
 * The following two defines are also coded into OBP, so if they
 * need to change here, don't forget to change OBP also.
 */
#define	SBD_OBP_PROBE_GOOD	0
#define	SBD_OBP_PROBE_BAD	1

extern int		sbd_setup_instance(int, dev_info_t *, int, int,
				caddr_t);
extern int		sbd_teardown_instance(int, caddr_t);
extern int		sbd_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
				char *event);

extern sbd_comp_type_t	sbd_cm_type(char *name);
extern sbd_state_t	ostate_cvt(sbd_istate_t state);
extern void		sbd_cpu_set_prop(sbd_cpu_unit_t *cp, dev_info_t *dip);
extern int		sbd_cpu_flags(sbd_handle_t *hp, sbd_devset_t devset,
				sbd_dev_stat_t *dsp);
extern int		sbd_disconnect_cpu(sbd_handle_t *hp, int unit);
extern int		sbd_connect_cpu(sbd_board_t *sbp, int unit);
extern int		sbd_disconnect_mem(sbd_handle_t *hp, int unit);

extern int		sbd_pre_detach_mem(sbd_handle_t *hp,
				sbd_devlist_t *devlist, int devnum);
extern int		sbd_post_attach_mem(sbd_handle_t *,
				sbd_devlist_t *, int);
extern int		sbd_post_detach_mem(sbd_handle_t *,
				sbd_devlist_t *, int);
extern int		sbd_post_attach_cpu(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int devnum);
extern int		sbd_pre_release_cpu(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int devnum);
extern int		sbd_pre_detach_cpu(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int devnum);
extern int		sbd_post_detach_cpu(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int devnum);
extern int		sbd_pre_attach_mem(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int devnum);
extern int		sbd_pre_release_mem(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int devnum);
extern int		sbd_disconnect_io(sbd_handle_t *hp, int unit);
extern void		sbd_check_devices(dev_info_t *dip, int *refcount,
					sbd_handle_t *handle);
extern struct memlist	*sbd_get_memlist(sbd_mem_unit_t *mp, sbderror_t *ep);
extern void		sbd_init_mem_unit(sbd_board_t *sbp, int unit,
					sbderror_t *ep);
extern void		sbd_release_mem_done(sbd_handle_t *hp, int unit);
extern void		sbd_release_cleanup(sbd_handle_t *hp);
extern int		sbd_cancel_cpu(sbd_handle_t *hp, int unit);
extern void		sbd_init_err(sbderror_t *ep);
extern int		sbd_cancel_mem(sbd_handle_t *hp, int unit);
extern sbd_comp_type_t	sbd_get_devtype(sbd_handle_t *hp, dev_info_t *dip);
extern int		sbd_get_board(dev_info_t *dip);
extern int		sfhw_get_base_physaddr(dev_info_t *dip,
					uint64_t *basepa);
extern int		sbd_pre_attach_cpu(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int devnum);
extern int		sbd_move_memory(sbd_handle_t *hp, sbd_board_t
				*s_bp, sbd_board_t *t_bp);
extern void		memlist_delete(struct memlist *mlist);
extern struct memlist	*memlist_dup(struct memlist *mlist);
extern void		memlist_dump(struct memlist *mlist);
extern int		memlist_intersect(struct memlist *alist,
					struct memlist *blist);
extern int		sbd_juggle_bootproc(sbd_handle_t *hp,
					processorid_t cpuid);

extern sbd_cond_t	sbd_get_comp_cond(dev_info_t *);
void			sbd_attach_mem(sbd_handle_t *hp, sbderror_t *ep);
int			sbd_release_mem(sbd_handle_t *hp, dev_info_t *dip,
					int unit);

int			sbd_get_memhandle(sbd_handle_t *hp, dev_info_t *dip,
					memhandle_t *mhp);
int			sbd_detach_memory(sbd_handle_t *hp, sbderror_t *ep,
					sbd_mem_unit_t *s_mp, int unit);
void			sbd_release_memory_done(void *arg, int error);
int			sbd_set_err_in_hdl(sbd_handle_t *hp, sbderror_t *ep);
sbdp_handle_t		*sbd_get_sbdp_handle(sbd_board_t *sbp,
					sbd_handle_t *hp);
void			sbd_release_sbdp_handle(sbdp_handle_t *hp);
void			sbd_reset_error_sbdph(sbdp_handle_t *hp);
extern int		sbd_is_cmp_child(dev_info_t *dip);

typedef const char *const fn_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SBDPRIV_H */
