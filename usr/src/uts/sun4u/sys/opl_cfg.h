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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_OPL_CFG_H
#define	_SYS_OPL_CFG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Hardware Descriptor.
 */

#include <sys/opl_hwdesc.h>

#define	OPL_PSB_MODE	0x0
#define	OPL_XSB_MODE	0x1

#define	OPL_LSBID_MASK	0x1f

/*
 * CPU device portid:
 *
 *	  1  0  0  0  0  0  0  0   0  0    0
 *	  0  9  8  7  6  5  4  3   2  1    0
 *      ---------------------------------------
 *	| 1 |   LSB ID    | CHIP | CORE | CPU |
 * 	---------------------------------------
 */
#define	OPL_CPUID_TO_LSB(devid)	((devid >> 5) & OPL_LSBID_MASK)
#define	OPL_CPU_CHIP(devid)	((devid >> 3) & 0x3)
#define	OPL_CORE(devid)		((devid >> 1) & 0x3)
#define	OPL_CPU(devid)		((devid & 0x001))

#define	OPL_PORTID(board, chip)		((1 << 10) | (board << 5) | (chip << 3))

#define	OPL_CPUID(board, chip, core, cpu)				\
									\
	((board << 5) | (chip << 3) | (core << 1) | (cpu))

/*
 * Dummy address space for a chip.
 */
#define	OPL_PROC_AS(board, chip)					\
									\
	((1ULL << 46) | ((uint64_t)board << 40) | (1ULL << 39) | 	\
		(1ULL << 33) | ((uint64_t)chip << 4))

/*
 * pseudo-mc portid:
 *
 *	  1   0   0  0  0  0  0   0  0  0  0
 *	  0   9   8  7  6  5  4   3  2  1  0
 *      -------------------------------------
 *	| 0 | 1 |     LSB ID    |    0      |
 * 	-------------------------------------
 */
#define	OPL_LSB_TO_PSEUDOMC_PORTID(board)	((1 << 9) | (board << 4))

/*
 * Dummy address space for a pseudo memory node
 */
#define	OPL_MC_AS(board)						\
									\
	((1ULL << 46) | ((uint64_t)board << 40) | (1ULL << 39) | 	\
		(1ULL << 33))

/*
 * Defines used by the Jupiter bus-specific library (lfc_jupiter.so).
 * This library gets loaded into the user-level fcode interpreter
 * and provides bus-specific methods that are used by the Oberon
 * and the CMU-channel fcode drivers.
 */
/*
 *
 * IO port id:
 *
 *	  1  0  0  0  0  0  0  0   0  0    0
 *	  0  9  8  7  6  5  4  3   2  1    0
 *      ---------------------------------------
 *	| 0  0 |   LSB ID    | IO CHAN | LEAF |
 * 	---------------------------------------
 */
#define	OPL_PORTID_MASK			0x7FF
#define	OPL_IO_PORTID_TO_LSB(portid)	(((portid) >> 4) & OPL_LSBID_MASK)
#define	OPL_PORTID_TO_CHANNEL(portid)	(((portid) >> 1) & 0x7)
#define	OPL_PORTID_TO_LEAF(portid)	((portid) & 0x1)
#define	OPL_IO_PORTID(lsb, ch, leaf)	\
	(((lsb & OPL_LSBID_MASK) << 4) | ((ch & 0x7) << 1) | (leaf & 0x1))

#define	OPL_ADDR_TO_LSB(hi)		(((hi) >> 8) & OPL_LSBID_MASK)
#define	OPL_ADDR_TO_CHANNEL(hi)		(((hi) >> 5) & 0x7)
#define	OPL_ADDR_TO_LEAF(hi, lo)	\
		(!(((hi) >> 7) & 0x1) && (((lo) >> 20) == 0x7))

#define	OPL_ADDR_HI(lsb, ch)		\
		((1 << 14) | ((lsb & OPL_LSBID_MASK) << 8) | ((ch & 0x7) << 5))

#define	OPL_CMU_CHANNEL	4
#define	OPL_OBERON_CHANNEL(ch)	((ch >= 0) && (ch <= 3))
#define	OPL_VALID_CHANNEL(ch)	((ch >= 0) && (ch <= 4))
#define	OPL_VALID_LEAF(leaf)	((leaf == 0) || (leaf == 1))

#if defined(_KERNEL)

/*
 * We store the pointers to the following device nodes in this structure:
 *	"pseudo-mc"
 *	"cmp"
 *	"pci"
 *
 * These nodes represent the different branches we create in the device
 * tree for each board during probe. We store them so that when a board
 * is unprobed, we can easily locate the branches and destroy them.
 */
typedef struct {
	dev_info_t		*cfg_pseudo_mc;
	dev_info_t		*cfg_cpu_chips[HWD_CPU_CHIPS_PER_CMU];
	dev_info_t		*cfg_cmuch_leaf;
	fco_handle_t		cfg_cmuch_handle;
	char			*cfg_cmuch_probe_str;
	dev_info_t		*cfg_pcich_leaf[HWD_PCI_CHANNELS_PER_SB]
						[HWD_LEAVES_PER_PCI_CHANNEL];
	fco_handle_t		cfg_pcich_handle[HWD_PCI_CHANNELS_PER_SB]
						[HWD_LEAVES_PER_PCI_CHANNEL];
	char			*cfg_pcich_probe_str[HWD_PCI_CHANNELS_PER_SB]
						[HWD_LEAVES_PER_PCI_CHANNEL];
	void			*cfg_hwd;
} opl_board_cfg_t;

/*
 * Prototypes for the callback functions used in the DDI functions
 * used to perform device tree operations.
 *
 * init functions are used to find device nodes that are created
 * by Solaris during boot.
 *
 * create functions are used to initialize device nodes during DR.
 */
typedef int	(*opl_init_func_t)(dev_info_t *, char *, int);
typedef int	(*opl_create_func_t)(dev_info_t *, void *, uint_t);

/*
 * The following probe structure carries all the information required
 * at various points during probe. This structure serves two purposes:
 *
 *	1. It allows us to streamline functions and have them accept just
 *	   a single argument.
 *
 *	2. It allows us to pass information to the DDI callbacks. DDI
 *	   callbacks are allowed only one argument. It also allows
 *	   us to return information from those callbacks.
 *
 * The probe structure carries a snapshot of the hardware descriptor
 * taken at the beginning of a probe.
 */
typedef struct {
	hwd_header_t		*pr_hdr;
	hwd_sb_status_t		*pr_sb_status;
	hwd_domain_info_t	*pr_dinfo;
	hwd_sb_t		*pr_sb;

	int			pr_board;
	int			pr_cpu_chip;
	int			pr_core;
	int			pr_cpu;
	int			pr_channel;
	int			pr_channel_status;
	int			pr_leaf;
	int			pr_leaf_status;

	opl_create_func_t	pr_create;
	dev_info_t		*pr_parent;
	dev_info_t		*pr_node;
	int			pr_hold;
	unsigned		pr_cpu_impl;
} opl_probe_t;

#define	OPL_STR_LEN	256

#define	OPL_HI(value)	((uint32_t)((uint64_t)(value) >> 32))
#define	OPL_LO(value)	((uint32_t)(value))

typedef struct {
	uint32_t	addr_hi;
	uint32_t	addr_lo;
} opl_addr_t;

typedef struct {
	uint32_t	rg_addr_hi;
	uint32_t	rg_addr_lo;
	uint32_t	rg_size_hi;
	uint32_t	rg_size_lo;
} opl_range_t;

typedef struct {
	int		mc_bank;
	uint32_t	mc_hi;
	uint32_t	mc_lo;
} opl_mc_addr_t;

/*
 * Convenience macros for DDI property operations. The functions that
 * DDI provides for getting and updating properties are not symmetric
 * either in their names or in the number of arguments. These macros
 * hide the gory details and provide a symmetric way to get and
 * set properties.
 */
#define	opl_prop_get_string(dip, name, bufp, lenp)			\
	ddi_getlongprop(DDI_DEV_T_ANY, dip,				\
			DDI_PROP_DONTPASS, name, (caddr_t)bufp, lenp)

#define	opl_prop_get_int(dip, name, value, defvalue)			\
(									\
	*(value) = ddi_getprop(DDI_DEV_T_ANY, dip,			\
			DDI_PROP_DONTPASS, name, defvalue),		\
	(*(value) == defvalue) ? DDI_PROP_NOT_FOUND : DDI_PROP_SUCCESS	\
)

#define	opl_prop_get_int_array(dip, name, data, nelems)			\
	ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,			\
	DDI_PROP_DONTPASS, name, (int **)&data, (uint_t *)&nelems)

#define	OPL_GET_PROP(type, dip, name, value, arg)			\
	opl_prop_get_##type(dip, name, value, arg)

#define	OPL_GET_PROP_ARRAY(type, dip, name, values, nvalues)		\
	opl_prop_get_##type##_array(dip, name, values, nvalues)

#define	OPL_FREE_PROP(data)						\
	ddi_prop_free((void *)data)

#define	OPL_UPDATE_PROP_ERR(ret, name)					\
	if (ret != DDI_PROP_SUCCESS) {					\
		cmn_err(CE_WARN, "%s (%d): %s update property error (%d)",\
			__FILE__, __LINE__, name, ret);			\
		return (DDI_WALK_ERROR);				\
	}

#define	OPL_UPDATE_PROP(type, dip, name, value)				\
	ret = ndi_prop_update_##type(DDI_DEV_T_NONE, dip, name, value);	\
	OPL_UPDATE_PROP_ERR(ret, name)


#define	OPL_UPDATE_PROP_ARRAY(type, dip, name, values, nvalues)		\
	ret = ndi_prop_update_##type##_array(DDI_DEV_T_NONE, dip,	\
						name, values, nvalues);	\
	OPL_UPDATE_PROP_ERR(ret, name)

/*
 * Node names for the different nodes supported in OPL.
 */
#define	OPL_PSEUDO_MC_NODE	"pseudo-mc"
#define	OPL_CPU_CHIP_NODE	"cmp"
#define	OPL_CORE_NODE		"core"
#define	OPL_CPU_NODE		"cpu"
#define	OPL_PCI_LEAF_NODE	"pci"

typedef struct {
	char		*fc_service;
	fc_ops_t	*fc_op;
} opl_fc_ops_t;

/*
 * Functions used by drmach
 */
extern int	opl_probe_sb(int, unsigned *);
extern int	opl_unprobe_sb(int);
extern int	opl_read_hwd(int, hwd_header_t **, hwd_sb_status_t **,
				hwd_domain_info_t **, hwd_sb_t **);
extern void	opl_hold_devtree(void);
extern void	opl_release_devtree(void);
extern int	oplcfg_pa_swap(int from, int to);
extern int	opl_init_cfg();

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_OPL_CFG_H */
