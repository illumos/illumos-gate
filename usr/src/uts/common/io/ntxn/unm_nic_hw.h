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
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _UNM_NIC_HW_
#define	_UNM_NIC_HW_

#include "unm_inc.h"

/* Hardware memory size of 128 meg */
#define	BAR0_SIZE (128 * 1024 * 1024)
/*
 * It can be calculated by looking at the first 1 bit of the BAR0 addr after
 * bit 4 For us lets assume that BAR0 is D8000008, then the size is 0x8000000,
 * 8 represents first bit containing 1.   FSL temp notes....pg 162 of PCI
 * systems arch...
 */

#define	UNM_NIC_HW_BLOCK_WRITE_64(DATA_PTR, ADDR, NUM_WORDS)        \
{                                                           \
	int i;                                              \
	u64 *a = (u64 *) (DATA_PTR);                        \
	u64 *b = (u64 *) (ADDR);                            \
	u64 tmp;					    \
	for (i = 0; i < (NUM_WORDS); i++, a++, b++) {       \
		tmp = UNM_NIC_PCI_READ_64(a);		    \
		UNM_NIC_PCI_WRITE_64(tmp, b);		    \
	}						    \
}

#define	UNM_NIC_HW_BLOCK_READ_64(DATA_PTR, ADDR, NUM_WORDS)           \
{                                                             \
	int i;                                                \
	u64 *a = (u64 *) (DATA_PTR);                          \
	u64 *b = (u64 *) (ADDR);                              \
	u64 tmp;					      \
	for (i = 0; i < (NUM_WORDS); i++, a++, b++) {            \
		tmp = UNM_NIC_PCI_READ_64(b);		      \
		UNM_NIC_PCI_WRITE_64(tmp, a);		      \
	}                                                     \
}

#define	UNM_PCI_MAPSIZE_BYTES  (UNM_PCI_MAPSIZE << 20)

#define	UNM_NIC_LOCKED_READ_REG(X, Y)   \
	addr = (void *)(pci_base_offset(adapter, (X)));     \
	*(uint32_t *)(Y) = UNM_NIC_PCI_READ_32(addr);

#define	UNM_NIC_LOCKED_WRITE_REG(X, Y)   \
	addr = (void *)(pci_base_offset(adapter, (X))); \
	UNM_NIC_PCI_WRITE_32(*(uint32_t *)(Y), addr);

/* For Multicard support */
#define	UNM_CRB_READ_VAL_ADAPTER(ADDR, ADAPTER) \
	unm_crb_read_val_adapter((ADDR), (struct unm_adapter_s *)ADAPTER)

#define	UNM_CRB_READ_CHECK_ADAPTER(ADDR, VALUE, ADAPTER)		\
	{								\
		if (unm_crb_read_adapter(ADDR, VALUE,			\
		    (struct unm_adapter_s *)ADAPTER)) return -1;	\
	}

#define	UNM_CRB_WRITELIT_ADAPTER(ADDR, VALUE, ADAPTER)			\
	{								\
		adapter->unm_crb_writelit_adapter(			\
		    (struct unm_adapter_s *)ADAPTER,			\
		    (unsigned long)ADDR, (int)VALUE);			\
	}

struct unm_adapter_s;
void unm_nic_set_link_parameters(struct unm_adapter_s *adapter);
long xge_mdio_init(struct unm_adapter_s *adapter);
void unm_nic_flash_print(struct unm_adapter_s *adapter);
void unm_nic_get_serial_num(struct unm_adapter_s *adapter);

typedef struct {
	unsigned valid;
	unsigned start_128M;
	unsigned end_128M;
	unsigned start_2M;
} crb_128M_2M_sub_block_map_t;

typedef struct {
	crb_128M_2M_sub_block_map_t sub_block[16];
} crb_128M_2M_block_map_t;

#endif /* _UNM_NIC_HW_ */
