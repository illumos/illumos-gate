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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MC_OPL_H
#define	_SYS_MC_OPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/note.h>

#ifdef	DEBUG
#define	MC_LOG	if (oplmc_debug) printf
extern int oplmc_debug;
#else
#define	MC_LOG		_NOTE(CONSTANTCONDITION) if (0) printf
#endif

/*
 * load/store MAC register
 */
extern uint32_t mc_ldphysio(uint64_t);
extern void mc_stphysio(uint64_t, uint32_t);
#define	LD_MAC_REG(paddr)	mc_ldphysio(paddr)
#define	ST_MAC_REG(paddr, data)	mc_stphysio((paddr), (data))

#define	BANKNUM_PER_SB	8

typedef	struct scf_log {
	struct scf_log	*sl_next;
	int		sl_bank;
	uint32_t	sl_err_add;
	uint32_t	sl_err_log;
} scf_log_t;

typedef struct mc_opl_state {
	struct mc_opl_state *next;
	dev_info_t *mc_dip;
	uint32_t mc_status;
#define	MC_POLL_RUNNING	0x1
#define	MC_SOFT_SUSPENDED	0x2	/* suspended by DR */
#define	MC_DRIVER_SUSPENDED	0x4	/* DDI_SUSPEND */
	uint32_t mc_board_num;		/* board# */
	uint64_t mc_start_address;	/* sb-mem-ranges */
	uint64_t mc_size;
	struct mc_bank {
		uint32_t  mcb_status;
#define	BANK_INSTALLED		0x80000000
#define	BANK_MIRROR_MODE	0x40000000	/* 0: normal  1: mirror */
#define	BANK_PTRL_RUNNING	0x00000001
		uint64_t  mcb_reg_base;
		uint32_t  mcb_ptrl_cntl;
	} mc_bank[BANKNUM_PER_SB];
	uchar_t		mc_trans_table[2][64];	/* csX-mac-pa-trans-table */
	clock_t		mc_interval_hz;
	timeout_id_t	mc_tid;
	kmutex_t	mc_lock;
	scf_log_t	*mc_scf_log;
	scf_log_t	*mc_scf_log_tail;
	int		mc_scf_total;
#define	MAX_SCF_LOGS	64
	struct mc_inst_list *mc_list;
	struct memlist	*mlist;
	int		mc_scf_retry[BANKNUM_PER_SB];
	int		mc_last_error;
#define	MAX_SCF_RETRY	10
	uint64_t	mc_period;	/* number of times memory scanned */
} mc_opl_t;

typedef	struct mc_inst_list {
	struct mc_inst_list	*next;
	mc_opl_t		*mc_opl;
	uint32_t		mc_board_num;
	uint64_t		mc_start_address;
	uint64_t		mc_size;
} mc_inst_list_t;

#define	IS_MIRROR(mcp, bn)	((mcp)->mc_bank[bn].mcb_status\
				& BANK_MIRROR_MODE)
typedef struct mc_addr {
	int ma_bd;		/* board number */
	int ma_bank;		/* bank number */
	uint32_t ma_dimm_addr;	/* DIMM address (same format as ERR_ADD) */
} mc_addr_t;

typedef struct mc_addr_info {
	struct mc_addr	mi_maddr;
	int		mi_valid;
	int		mi_advance;
} mc_addr_info_t;

typedef struct mc_flt_stat {
	uint32_t  mf_type;		/* fault type */
#define	FLT_TYPE_CMPE			0x0001
#define	FLT_TYPE_UE			0x0002
#define	FLT_TYPE_PERMANENT_CE		0x0003
#define	FLT_TYPE_INTERMITTENT_CE	0x0004
#define	FLT_TYPE_SUE			0x0005
#define	FLT_TYPE_MUE			0x0006
	uint32_t  mf_cntl;		/* MAC_BANKm_PTRL_CNTL Register */
	uint32_t  mf_err_add;	/* MAC_BANKm_{PTRL|MI}_ERR_ADD Register */
	uint32_t  mf_err_log;	/* MAC_BANKm_{PTRL|MI}_ERR_LOG Register */
	uint32_t  mf_synd;
	uchar_t   mf_errlog_valid;
	uchar_t   mf_dimm_slot;
	uchar_t   mf_dram_place;
	uint64_t  mf_flt_paddr;		/* faulty physical address */
	mc_addr_t mf_flt_maddr;		/* faulty DIMM address */
} mc_flt_stat_t;

typedef struct mc_aflt {
	uint64_t mflt_id;		/* gethrtime() at time of fault */
	mc_opl_t *mflt_mcp;		/* mc-opl structure */
	char *mflt_erpt_class;		/* ereport class name */
	int mflt_is_ptrl;		/* detected by PTRL or MI */
	int mflt_nflts;			/* 1 or 2 */
	int mflt_pr;			/* page retire flags */
	mc_flt_stat_t *mflt_stat[2];	/* fault status */
} mc_aflt_t;

#define	MAC_PTRL_STAT(mcp, i)		(mcp->mc_bank[i].mcb_reg_base)
#define	MAC_PTRL_CNTL(mcp, i)		(mcp->mc_bank[i].mcb_reg_base + 0x10)
#define	MAC_PTRL_ERR_ADD(mcp, i)	(mcp->mc_bank[i].mcb_reg_base + 0x20)
#define	MAC_PTRL_ERR_LOG(mcp, i)	(mcp->mc_bank[i].mcb_reg_base + 0x24)
#define	MAC_MI_ERR_ADD(mcp, i)		(mcp->mc_bank[i].mcb_reg_base + 0x28)
#define	MAC_MI_ERR_LOG(mcp, i)		(mcp->mc_bank[i].mcb_reg_base + 0x2c)
#define	MAC_STATIC_ERR_ADD(mcp, i)	(mcp->mc_bank[i].mcb_reg_base + 0x30)
#define	MAC_STATIC_ERR_LOG(mcp, i)	(mcp->mc_bank[i].mcb_reg_base + 0x34)
#define	MAC_RESTART_ADD(mcp, i)		(mcp->mc_bank[i].mcb_reg_base + 0x40)
#define	MAC_REWRITE_ADD(mcp, i)		(mcp->mc_bank[i].mcb_reg_base + 0x44)
#define	MAC_EG_ADD(mcp, i)		(mcp->mc_bank[i].mcb_reg_base + 0x48)
#define	MAC_EG_CNTL(mcp, i)		(mcp->mc_bank[i].mcb_reg_base + 0x4c)
#define	MAC_MIRR(mcp, i)		(mcp->mc_bank[i].mcb_reg_base + 0x50)

/* use PA[37:6] */
#define	MAC_RESTART_PA(pa)		((pa >> 6) & 0xffffffff)
/*
 * MAC_BANKm_PTRL_STAT_Register
 */
#define	MAC_STAT_PTRL_CE	0x00000020
#define	MAC_STAT_PTRL_UE	0x00000010
#define	MAC_STAT_PTRL_CMPE	0x00000008
#define	MAC_STAT_MI_CE		0x00000004
#define	MAC_STAT_MI_UE		0x00000002
#define	MAC_STAT_MI_CMPE	0x00000001

#define	MAC_STAT_PTRL_ERRS	(MAC_STAT_PTRL_CE|MAC_STAT_PTRL_UE\
				|MAC_STAT_PTRL_CMPE)
#define	MAC_STAT_MI_ERRS	(MAC_STAT_MI_CE|MAC_STAT_MI_UE\
				|MAC_STAT_MI_CMPE)

/*
 * MAC_BANKm_PTRL_CTRL_Register
 */
#define	MAC_CNTL_PTRL_START		0x80000000
#define	MAC_CNTL_USE_RESTART_ADD	0x40000000
#define	MAC_CNTL_PTRL_STOP		0x20000000
#define	MAC_CNTL_PTRL_INTERVAL		0x1c000000
#define	MAC_CNTL_PTRL_RESET		0x02000000
#define	MAC_CNTL_PTRL_STATUS		0x01000000
#define	MAC_CNTL_REW_REQ		0x00800000
#define	MAC_CNTL_REW_RESET		0x00400000
#define	MAC_CNTL_CS0_DEG_MODE		0x00200000
#define	MAC_CNTL_PTRL_CE		0x00008000
#define	MAC_CNTL_PTRL_UE		0x00004000
#define	MAC_CNTL_PTRL_CMPE		0x00002000
#define	MAC_CNTL_MI_CE			0x00001000
#define	MAC_CNTL_MI_UE			0x00000800
#define	MAC_CNTL_MI_CMPE		0x00000400
#define	MAC_CNTL_REW_CE			0x00000200
#define	MAC_CNTL_REW_UE			0x00000100
#define	MAC_CNTL_REW_END		0x00000080
#define	MAC_CNTL_PTRL_ADD_MAX		0x00000040
#define	MAC_CNTL_REW_CMPE		0x00000020

#define	MAC_CNTL_PTRL_PRESERVE_BITS	(MAC_CNTL_PTRL_INTERVAL)

#define	MAC_CNTL_PTRL_ERRS	(MAC_CNTL_PTRL_CE|MAC_CNTL_PTRL_UE\
				|MAC_CNTL_PTRL_CMPE)
#define	MAC_CNTL_MI_ERRS	(MAC_CNTL_MI_CE|MAC_CNTL_MI_UE\
				|MAC_CNTL_MI_CMPE)
#define	MAC_CNTL_REW_ERRS	(MAC_CNTL_REW_CE|MAC_CNTL_REW_CMPE|\
				MAC_CNTL_REW_UE|MAC_CNTL_REW_END)
#define	MAC_CNTL_ALL_ERRS	(MAC_CNTL_PTRL_ERRS|\
				MAC_CNTL_MI_ERRS|MAC_CNTL_REW_ERRS)

#define	MAC_ERRLOG_SYND_SHIFT		16
#define	MAC_ERRLOG_SYND_MASK		0xffff
#define	MAC_ERRLOG_DIMMSLOT_SHIFT	13
#define	MAC_ERRLOG_DIMMSLOT_MASK	0x7
#define	MAC_ERRLOG_DRAM_PLACE_SHIFT	8
#define	MAC_ERRLOG_DRAM_PLACE_MASK	0x1f

#define	MAC_SET_ERRLOG_INFO(flt_stat)				\
	(flt_stat)->mf_errlog_valid = 1;			\
	(flt_stat)->mf_synd = ((flt_stat)->mf_err_log >>	\
		MAC_ERRLOG_SYND_SHIFT) &			\
		MAC_ERRLOG_SYND_MASK;				\
	(flt_stat)->mf_dimm_slot = ((flt_stat)->mf_err_log >>	\
		MAC_ERRLOG_DIMMSLOT_SHIFT) &			\
		MAC_ERRLOG_DIMMSLOT_MASK;			\
	(flt_stat)->mf_dram_place = ((flt_stat)->mf_err_log >>	\
		MAC_ERRLOG_DRAM_PLACE_SHIFT) &			\
		MAC_ERRLOG_DRAM_PLACE_MASK;

extern void mc_write_cntl(mc_opl_t *, int, uint32_t);
#define	MAC_CMD(mcp, i, cmd)	mc_write_cntl(mcp, i, cmd)

#define	MAC_PTRL_START_ADD(mcp, i)	MAC_CMD((mcp), (i),\
				MAC_CNTL_PTRL_START|MAC_CNTL_USE_RESTART_ADD)
#define	MAC_PTRL_START(mcp, i)	MAC_CMD((mcp), (i), MAC_CNTL_PTRL_START)
#define	MAC_PTRL_STOP(mcp, i)	MAC_CMD((mcp), (i), MAC_CNTL_PTRL_STOP)
#define	MAC_PTRL_RESET(mcp, i)	MAC_CMD((mcp), (i), MAC_CNTL_PTRL_RESET)
#define	MAC_REW_REQ(mcp, i)	MAC_CMD((mcp), (i), MAC_CNTL_REW_REQ)
#define	MAC_REW_RESET(mcp, i)	MAC_CMD((mcp), (i), MAC_CNTL_REW_RESET)
#define	MAC_CLEAR_ERRS(mcp, i, errs)	MAC_CMD((mcp), (i), errs)
#define	MAC_CLEAR_ALL_ERRS(mcp, i)	MAC_CMD((mcp), (i),\
					MAC_CNTL_ALL_ERRS)
#define	MAC_CLEAR_MAX(mcp, i)	\
	MAC_CMD((mcp), (i), MAC_CNTL_PTRL_ADD_MAX)


/*
 * MAC_BANKm_PTRL/MI_ERR_ADD/LOG_Register
 */
#define	MAC_ERR_ADD_INVALID	0x80000000
#define	MAC_ERR_LOG_INVALID	0x00000080

/*
 * MAC_BANKm_STATIC_ERR_ADD_Register
 */
#define	MAC_STATIC_ERR_VLD	0x80000000

/*
 * MAC_BANKm_MIRR_Register
 */
#define	MAC_MIRR_MIRROR_MODE	0x80000000
#define	MAC_MIRR_BANK_EXCLUSIVE	0x40000000

#define	OPL_BOARD_MAX	16
#define	OPL_BANK_MAX	8

/*
 * MAC_BANKm_EG_ADD_Register
 */
#define	MAC_EG_ADD_MASK		0x7ffffffc
/*
 * To set the EG_CNTL register, bit[26-25] and
 * bit[21-20] must be cleared.  Then the other
 * control bit should be set.  Then the bit[26-25]
 * and bit[21-20] should be set while other bits
 * should be the same as before.
 */
#define	MAC_EG_CNTL_MASK	0x06300000

#define	MAC_EG_ADD_FIX		0x80000000
#define	MAC_EG_FORCE_DERR00	0x40000000
#define	MAC_EG_FORCE_DERR16	0x20000000
#define	MAC_EG_FORCE_DERR64	0x10000000
#define	MAC_EG_FORCE_DERR80	0x08000000
#define	MAC_EG_DERR_ALWAYS	0x02000000
#define	MAC_EG_DERR_ONCE	0x04000000
#define	MAC_EG_DERR_NOP		0x06000000
#define	MAC_EG_FORCE_READ00	0x00800000
#define	MAC_EG_FORCE_READ16	0x00400000
#define	MAC_EG_RDERR_ALWAYS	0x00100000
#define	MAC_EG_RDERR_ONCE	0x00200000
#define	MAC_EG_RDERR_NOP	0x00300000

#define	MAC_EG_SETUP_MASK	0xf9cfffff

/* For MAC-PA translation */
#define	MC_ADDRESS_BITS	31
#define	PA_BITS_FOR_MAC	39
#define	INDEX_OF_BANK_SUPPLEMENT_BIT	39
#define	MP_NONE		128
#define	MP_BANK_0	129
#define	MP_BANK_1	130
#define	MP_BANK_2	131

#define	CS_SHIFT	29
#define	MC_TT_ENTRIES	64
#define	MC_TT_CS	2


#define	MAX_MC_LOOP_COUNT	100

/* export interface for error injection */
extern int mc_inject_error(int error_type, uint64_t pa, uint32_t flags);

#define	MC_INJECT_NOP			0x0
#define	MC_INJECT_INTERMITTENT_CE	0x1
#define	MC_INJECT_PERMANENT_CE		0x2
#define	MC_INJECT_UE			0x3
#define	MC_INJECT_INTERMITTENT_MCE	0x11
#define	MC_INJECT_PERMANENT_MCE		0x12
#define	MC_INJECT_SUE			0x13
#define	MC_INJECT_MUE			0x14
#define	MC_INJECT_CMPE			0x15

#define	MC_INJECT_MIRROR_MODE		0x10
#define	MC_INJECT_MIRROR(x)		(x & MC_INJECT_MIRROR_MODE)

#define	MC_INJECT_FLAG_NO_TRAP	0x1
#define	MC_INJECT_FLAG_RESTART	0x2
#define	MC_INJECT_FLAG_POLL	0x4
#define	MC_INJECT_FLAG_RESET	0x8
#define	MC_INJECT_FLAG_OTHER	0x10
#define	MC_INJECT_FLAG_LD	0x20
#define	MC_INJECT_FLAG_ST	0x40
#define	MC_INJECT_FLAG_PATH	0x80

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_MC_OPL_H */
