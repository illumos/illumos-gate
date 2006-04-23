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

#ifndef	_SYS_DB21554_CTRL_H
#define	_SYS_DB21554_CTRL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* definitions for device state */
#define	DB_SECONDARY_NEXUS	0x80000000	/* secondary towards host */
#define	DB_PRIMARY_NEXUS	0x40000000	/* primary towards host */
#define	DB_ATTACHED		0x00000001	/* driver attached */
#define	DB_SUSPENDED		0x00100000
#define	DB_DEBUG_MODE_ON	0x01000000

#define	DB_PCI_CONF_RNUMBER	0
#define	DB_PCI_CONF_OFFSET	0
#define	DB_CSR_MEMBAR_RNUMBER	1
#define	DB_CSR_MEM_OFFSET	0
#define	DB_CSR_SIZE		0x1000	/* 4K CSR space */
#define	DB_CSR_IOBAR_RNUMBER	2
#define	DB_CSR_IO_OFFSET	0
#define	DB_PCI_TIMEOUT		10000	/* 10 ms */
#define	DB_PCI_WAIT_MS		0
#define	DB_CONF_FAILURE		-1

#define	DB_PIF_SECONDARY_TO_HOST	0x80
#define	DB_PIF_PRIMARY_TO_HOST		0x40

/*
 * the  following definition is used to save the state of all PCI children
 * under us.
 */
typedef struct db_cfg_state {
	dev_info_t *dip;
	uchar_t cache_line_size;
	uchar_t latency_timer;
	uchar_t header_type;
	uchar_t sec_latency_timer;
	ushort_t command;
	ushort_t bridge_control;
} db_cfg_state_t;

/* the main control structure of our device */
typedef struct db_ctrl {
	dev_info_t	*dip;
	uint32_t	dev_state;	/* device state */
	caddr_t		csr_mem;	/* pointer to CSR map in memory space */
	caddr_t		csr_io;		/* pointer to CSR map in IO space */
	caddr_t		conf_io;	/* pointer to Conf indirect map */

	/* our bus range information */
	pci_bus_range_t	range;

	/* any device tuning parameters here. */
	uint16_t	p_command;
	uint16_t	s_command;
	int8_t		p_latency_timer;
	int8_t		p_cache_line_size;
	int8_t		s_latency_timer;
	int8_t		s_cache_line_size;
	int8_t		p_pwrite_threshold;
	int8_t		s_pwrite_threshold;
	int8_t		p_dread_threshold;
	int8_t		s_dread_threshold;
	int8_t		delayed_trans_order;
	int8_t		serr_fwd_enable;

	/* for child initialization */
	uint8_t		latency_timer;
	uint8_t		cache_line_size;

	/* error holders */
	uint32_t	db_pci_err_count; /* indirect cycle timeout count */
#ifdef DEBUG
	uint32_t	db_pci_max_wait_count; /* indirect cycle wait count */
#endif
	/* cpr related. */
	uint_t config_state_index;
	db_cfg_state_t *db_config_state_p;

	/* all map handles below */
	ddi_acc_handle_t csr_mem_handle;    /* CSR memory handle */
	ddi_acc_handle_t csr_io_handle;    /* CSR IO handle */
	ddi_acc_handle_t conf_handle;    /* config space handle */
	ddi_iblock_cookie_t	i_block_cookie;	/* interrupt cookie */
	kmutex_t		db_busown;	/* bus config own mutex */
	kmutex_t db_mutex;
	uint_t db_soft_state;
#define	DB_SOFT_STATE_CLOSED		0x00
#define	DB_SOFT_STATE_OPEN		0x01
#define	DB_SOFT_STATE_OPEN_EXCL		0x02
	int fm_cap;
	ddi_iblock_cookie_t fm_ibc;
}db_ctrl_t;

typedef struct db_acc_cfg_addr {
	uchar_t c_busnum;		/* bus number */
	uchar_t c_devnum;		/* device number */
	uchar_t c_funcnum;		/* function number */
	uchar_t c_fill;			/* reserve field */
} db_acc_cfg_addr_t;

typedef struct db_acc_pvt {
	db_acc_cfg_addr_t	dev_addr;	/* pci device address */
	uint32_t	*addr;	/* upstream/downstream config addr */
	uint32_t	*data;	/* upstream/downstream config data */
	uint8_t		*bus_own;	/* reg to check if bus owned */
	uint8_t		*bus_release;	/* reg to check if bus released */
	uint8_t		mask;		/* bitmask for upstream/downstream */
	ushort_t	access_mode;	/* access through IO or Config */
	db_ctrl_t	*dbp;
	ddi_acc_handle_t handle;	/* handle for bus access DDI calls */
} db_acc_pvt_t;

/* We can use the following modes for generating indirect PCI transcations */
#define	DB_IO_MAP_DIRECT		1 /* memory mapped IO */
#define	DB_IO_MAP_INDIRECT		2 /* indirect map IO */
#define	DB_CONF_MAP_INDIRECT_CONF	4 /* access config via config regs */
#define	DB_CONF_MAP_INDIRECT_IO		8 /* access config via IO regs */
#define	DB_PCI_CONF_CYCLE_TYPE0		0x100	/* type 0 conf cycle */
#define	DB_PCI_CONF_CYCLE_TYPE1		0x200	/* type 1 conf cycle */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DB21554_CTRL_H */
