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
 * Copyright 2020 Peter Tribble.
 */

#ifndef	_SYS_LIBPRTDIAG_H
#define	_SYS_LIBPRTDIAG_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/openpromio.h>
#include <sys/cheetahregs.h>
#include "pdevinfo.h"
#include "display.h"
#include "pdevinfo_sun4u.h"
#include "display_sun4u.h"

#ifdef DEBUG
#define	D_PRINTF printf
#else
#define	D_PRINTF
#endif

#define	EXIT_MSG(msg, err) \
	{ printf("\n%s failed with %d\n", msg, err); exit(err); }

/* global data */
#define	PCI_DEVICE(x)		((x  >> 11) & 0x1f)
#define	PCI_REG_TO_DEV(x)	((x & 0xf800) >> 11)
#define	PCI_REG_TO_FUNC(x)	((x & 0x700) >> 8)
#define	BUS_TYPE		"UPA"
#define	MAX_SLOTS_PER_IO_BD	8


int	sys_clk;  /* System clock freq. (in MHz) */

/*
 * Defines for identifying PCI devices
 */
#define	PCI_BRIDGE_CLASS		0x6
#define	PCI_CLASS_SHIFT			0x10
#define	PCI_PCI_BRIDGE_SUBCLASS		0x4
#define	PCI_SUBCLASS_SHIFT		0x8
#define	PCI_SUBCLASS_MASK		0xFF00
#define	PCI_SUBCLASS_OTHER		0x80

#define	CLASS_REG_TO_SUBCLASS(class)	(((class) & PCI_SUBCLASS_MASK) \
						>> PCI_SUBCLASS_SHIFT)
#define	CLASS_REG_TO_CLASS(class)	((class) >> PCI_CLASS_SHIFT)

/*
 * display functions
 */
int	error_check(Sys_tree *tree, struct system_kstat_data *kstats);
int	disp_fail_parts(Sys_tree *tree);
void	display_hp_fail_fault(Sys_tree *tree, struct system_kstat_data *kstats);
void	display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
	    struct system_kstat_data *kstats);
void	resolve_board_types(Sys_tree *);
void	display_boardnum(int num);
void	display_platform_specific_header(void);

/*
 * cpu functions
 */
void	display_cpu_devices(Sys_tree *);
void	display_cpus(Board_node *);
void	display_mid(int mid);
uint_t	get_cpu_freq(Prom_node *);
int	get_ecache_size(Prom_node *);

/*
 * io functions
 */
Prom_node *find_pci_bus(Prom_node *, int, int);
int	get_pci_bus(Prom_node *);
int	get_pci_device(Prom_node *);
int	get_pci_to_pci_device(Prom_node *);
void	free_io_cards(struct io_card *);
struct	io_card *insert_io_card(struct io_card *, struct io_card *);
char	*fmt_manf_id(unsigned int, char *);
int	get_sbus_slot(Prom_node *);
void	display_io_devices(Sys_tree *tree);
void	display_pci(Board_node *bnode);
void	display_io_cards(struct io_card *);
void	display_ffb(Board_node *, int);
void	display_sbus(Board_node *);
int	populate_slot_name_arr(Prom_node *pci, int *slot_name_bits,
	char **slot_name_arr, int num_slots);
int	get_card_frequency(Prom_node *pci);
void	get_dev_func_num(Prom_node *card_node, int *dev_no, int *func_no);
void	get_pci_class_codes(Prom_node *card_node, int *class_code,
	int *subclass_code);
int	is_pci_bridge(Prom_node *card_node, char *name);
int	is_pci_bridge_other(Prom_node *card_node, char *name);
void	get_pci_card_model(Prom_node *card_node, char *model);
void	create_io_card_name(Prom_node *card_node, char *name,
	char *card_name);
void	display_psycho_pci(Board_node *bnode);
void	get_slot_number_str(struct io_card *card, char **slot_name_arr,
	int slot_name_bits);
void	distinguish_identical_io_cards(char *name, Prom_node *node,
		struct io_card *card);
void	decode_qlc_card_model_prop(Prom_node *card_node, struct io_card *card);

/*
 * kstat functions
 */
void	read_platform_kstats(Sys_tree *tree,
	    struct system_kstat_data *sys_kstat,
	    struct envctrl_kstat_data *ep);
void	read_sun4u_kstats(Sys_tree *, struct system_kstat_data *);

/*
 * memory functions
 */
void	display_memorysize(Sys_tree *tree, struct system_kstat_data *kstats,
	    struct mem_total *memory_total);
void	display_memoryconf(Sys_tree *tree);

/*
 * prom functions
 */
void	platform_disp_prom_version(Sys_tree *);
void	disp_prom_version(Prom_node *);
void	add_node(Sys_tree *, Prom_node *);
Prom_node *find_device(Board_node *, int, char *);
Prom_node *walk(Sys_tree *, Prom_node *, int);
int	get_pci_class_code_reg(Prom_node *);

/*
 * libdevinfo functions
 */
int	do_devinfo(int, char *, int, int);

/*
 * mc-us3 memory functions and structs
 */
typedef struct memory_bank {
	int			id;
	int			portid;
	ushort_t		valid;
	ushort_t		uk;
	uint_t			um;
	uchar_t			lk;
	uchar_t			lm;
	uint64_t		bank_size;
	char			*bank_status;
	struct memory_bank	*next;		/* mc in the devtree */
	struct memory_bank	*seg_next;	/* in the segment */
} memory_bank_t;

typedef struct memory_seg {
	int			id;
	int			intlv;  /* interleave for this segment */
	uint64_t		base;   /* base address for this segment */
	uint64_t		size;   /* size of this segment */
	int			nbanks; /* number of banks in this segment */
	memory_bank_t		*banks; /* pointer to the banks of this seg */
	struct memory_seg	*next;
} memory_seg_t;

#define	NUM_MBANKS_PER_MC		4

int	get_us3_mem_regs(Board_node *bnode);
void	display_us3_banks(void);
int	display_us3_failed_banks(int system_failed);
void    print_us3_memory_line(int portid, int bank_id, uint64_t bank_size,
	    char *bank_status, uint64_t dimm_size, uint32_t intlv, int seg_id);
void	print_us3_failed_memory_line(int portid, int bank_id,
	    char *bank_status);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LIBPRTDIAG_H */
