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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_DB21554_CONFIG_H
#define	_SYS_DB21554_CONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/pci.h>

#define	DB_PCONF_PRI_HDR_OFF		0x00 /* primary offset on primary */
#define	DB_PCONF_SEC_HDR_OFF		0x40 /* secondary offset on sec */
#define	DB_SCONF_PRI_HDR_OFF		0x40 /* primary offset on sec */
#define	DB_SCONF_SEC_HDR_OFF		0x00 /* secondary offset on sec */
#define	DB_CONF_REGS			0x80 /* configuration regs after hdrs */
#define	DB_SCONF_HDR_OFF		0x40 /* second config hdr offset */

/*
 * Some register definitions for configuration header.
 */
#define	DB_PCONF_MEM_CSR		PCI_CONF_BASE0
#define	DB_PCONF_IO_CSR			PCI_CONF_BASE1
#define	DB_PCONF_DS_IO_MEM1		PCI_CONF_BASE2
#define	DB_PCONF_DS_MEM2		PCI_CONF_BASE3
#define	DB_PCONF_DS_MEM3		PCI_CONF_BASE4
#define	DB_PCONF_DS_UMEM3		PCI_CONF_BASE5
#define	DB_PCONF_EXP_ROM		PCI_CONF_ROM
#define	DB_PCONF_US_IO_MEM0		DB_PCONF_SEC_HDR_OFF+PCI_CONF_BASE2
#define	DB_PCONF_US_MEM1		DB_PCONF_SEC_HDR_OFF+PCI_CONF_BASE3
#define	DB_PCONF_US_MEM2		DB_PCONF_SEC_HDR_OFF+PCI_CONF_BASE4

#define	DB_SCONF_MEM_CSR		PCI_CONF_BASE0
#define	DB_SCONF_IO_CSR			PCI_CONF_BASE1
#define	DB_SCONF_US_IO_MEM0		PCI_CONF_BASE2
#define	DB_SCONF_US_MEM1		PCI_CONF_BASE3
#define	DB_SCONF_US_MEM2		PCI_CONF_BASE4
#define	DB_SCONF_DS_IO_MEM1		DB_SCONF_PRI_HDR_OFF+PCI_CONF_BASE2
#define	DB_SCONF_DS_MEM2		DB_SCONF_PRI_HDR_OFF+PCI_CONF_BASE3
#define	DB_SCONF_DS_MEM3		DB_PCONF_PRI_HDR_OFF+PCI_CONF_BASE4
#define	DB_SCONF_DS_UMEM3		DB_PCONF_PRI_HDR_OFF+PCI_CONF_BASE5

#define	DB_IO_BIT			0x00000001

/* register definitions in configuration space after primary/sec. header */

#define	DB_CONF_DS_CONF_ADDR		0x80 /* downstream config address */
#define	DB_CONF_DS_CONF_DATA		0x84 /* downstream config data */
#define	DB_CONF_US_CONF_ADDR		0x88 /* upstream config address */
#define	DB_CONF_US_CONF_DATA		0x8C /* upstream config data */
#define	DB_CONF_CONF_OWN		0x90 /* config own bits - word reg */
#define	DB_CONF8_DS_CONF_OWN		0x90 /* config own bits - byte reg */
#define	DB_CONF8_US_CONF_OWN		0x91 /* config own bits - byte reg */
#define	DB_CONF_CONF_CSR		0x92 /* config control status - word */
#define	DB_CONF8_DS_CONF_CSR		0x92 /* config DS CSR - byte reg */
#define	DB_CONF8_US_CONF_CSR		0x93 /* config US CSR - byte reg */
#define	DB_CONF_DS_MEM0_TR_BASE		0x94 /* DS memory 0 translated base */
#define	DB_CONF_DS_IO_MEM1_TR_BASE	0x98 /* DS IO or mem 1 trans base */
#define	DB_CONF_DS_MEM2_TR_BASE		0x9C /* DS memory 2 translated base */
#define	DB_CONF_DS_MEM3_TR_BASE		0xA0 /* DS memory 3 translated base */
#define	DB_CONF_US_IO_MEM0_TR_BASE	0xA4 /* DS IO or mem0 trans base */
#define	DB_CONF_US_MEM1_TR_BASE		0xA8 /* US memory 1 translated base */
#define	DB_CONF_DS_MEM0_SETUP		0xAC /* DS memory 0 setup */
#define	DB_CONF_DS_IO_MEM1_SETUP	0xB0 /* DS IO or memory 1 setup */
#define	DB_CONF_DS_MEM2_SETUP		0xB4 /* DS memory 2 setup */
#define	DB_CONF_DS_MEM3_SETUP		0xB8 /* DS memory 3 setup */
#define	DB_CONF_DS_UP32_MEM3_SETUP	0xBC /* Upper 32bits DS mem3 setup */
#define	DB_CONF_PRIM_EXP_ROM_SETUP	0xC0 /* Primary Expansion ROM setup */
#define	DB_CONF_US_IO_MEM0_SETUP	0xC4 /* Upstream IO or memory 0 setup */
#define	DB_CONF_US_MEM1_SETUP		0xC8 /* upstream memory 1 setup */
#define	DB_CONF_CHIP_CTRL0		0xCC /* chip control 0 */
#define	DB_CONF_CHIP_CTRL1		0xCE /* chip control 1 */
#define	DB_CONF_STATUS			0xD0 /* chip status */
#define	DB_CONF_ARBITER_CTRL		0xD2 /* Arbiter control */
#define	DB_CONF_PRIM_SERR_DISABLES	0xD4 /* primary SERR# disables */
#define	DB_CONF_SEC_SERR_DISABLES	0xD5 /* Secondary SERR# disables */
#define	DB_CONF_RESET_CTRL		0xD8 /* Reset Control */
#define	DB_CONF_CAP_ID_1		0xDC /* Capabilities ID */
#define	DB_CONF_NEXT_ITEM_PTR_1		0xDD /* Next Item Pointer */
#define	DB_CONF_PM_CAP			0xDE /* Power Management Capabilities */
#define	DB_CONF_PM_CSR			0xE0 /* Power Management CSR */
#define	DB_CONF_PM_CSR_BSE		0xE2 /* PMCSR Bridge Support Exts */
#define	DB_CONF_PM_DATA			0xE3 /* Power Management data */
#define	DB_CONF_CAP_ID_2		0xE4 /* Capabilities ID */
#define	DB_CONF_NEXT_ITEM_PTR_2		0xE5 /* Next Item Pointer */
#define	DB_CONF_VPD_ADDRESS		0xE6 /* VPD Address */
#define	DB_CONF_VPD_DATA		0xE8 /* VPD Data */
#define	DB_CONF_CAP_ID_3		0xEC /* Capabilities ID */
#define	DB_CONF_NEXT_ITEM_PTR_3		0xED /* Next Item Pointer */
#define	DB_CONF_HS_CSR			0xEE /* Hotswap control status */

#define	DB_VENDOR_ID		0x1011
#define	DB_DEVICE_ID		0x46
#define	DB_INVAL_VEND		0xffff

/* configuration own register bits : Register offset 0x90-91 */
#define	DS_CONF_OWN		0x0001 /* master owns DSconfig address/data */
#define	US_CONF_OWN		0x0100 /* master owns USconfig address/data */
/* the following is a 8-bit register version definition. */
#define	DS8_CONF_OWN		0x01
#define	US8_CONF_OWN		0x01

/* configuration control status register bits: Register offset 0x92-93 */
#define	DS_OWN_STAT		0x0001 /* downstream config own status */
#define	DS_ENABLE		0x0002 /* enable downstream config cycles */
#define	US_OWN_STAT		0x0100 /* upstream config own status */
#define	US_ENABLE		0x0200 /* enable upstream config cycles */

/* chip control 0 register bits: Register Offset 0xcc-cd */
#define	DELAYED_TRANS_ORDER	0x0040 /* delayed transaction order control */
#define	SERR_FWD		0x0080 /* forward SERR# from sec to prim */
#define	PLOCKOUT		0x0400 /* primary lockout set */
#define	SEC_CLK_DIS		0x0800 /* disable secondary clock */

/* chip control 1 register bits: Register Offset 0xce-cf */
#define	P_PW_THRESHOLD		0x0001
#define	S_PW_THRESHOLD		0x0002
#define	P_DREAD_THRESHOLD_MASK	0x000C
#define	S_DREAD_THRESHOLD_MASK	0x0030
#define	DREAD_THRESHOLD_VALBITS	0x3

#define	US_MEM2_DISABLE		0x0000 /* disable USmem2 BAR */
#define	PAGESIZE_256		0x0100
#define	PAGESIZE_512		0x0200
#define	PAGESIZE_1K		0x0300
#define	PAGESIZE_2K		0x0400
#define	PAGESIZE_4K		0x0500
#define	PAGESIZE_8K		0x0600
#define	PAGESIZE_16K		0x0700
#define	PAGESIZE_32K		0x0800
#define	PAGESIZE_64K		0x0900
#define	PAGESIZE_128K		0x0A00
#define	PAGESIZE_256K		0x0B00
#define	PAGESIZE_512K		0x0C00
#define	PAGESIZE_1M		0x0D00
#define	PAGESIZE_2M		0x0E00
#define	PAGESIZE_4M		0x0F00

#define	GET_PAGESIZE(chip_ctrl1)	(((chip_ctrl1) & 0x0F00) >> 8)

/* chip reset control register bits : Register Offset 0xd8-db */
#define	RESET_CTRL_RST_SEC	0x01 /* reset secondary */
#define	RESET_CTRL_RST		0x02 /* reset chip */
#define	RESET_CTRL_LSTAT	0x08 /* when set, l_stat is high */

/* chip status register bits : Register Offset 0xd0-d1 */
#define	DS_DEL_MTO		0x0001 /* DS delayed master TO */
#define	DS_DEL_RD_DISCARD	0x0002 /* DS delayed read discard */
#define	DS_DEL_WR_DISCARD	0x0004 /* DS delayed write discard */
#define	DS_POST_WRDATA_DISCA	0x0008
#define	US_DEL_MTO		0x0100 /* US delayed trans master TO */
#define	US_DEL_RD_DISCARD	0x0200 /* US delayed trans.read disc */
#define	US_DEL_WR_DISCARD	0x0400 /* US delayed trans.writ disc */
#define	US_POST_WRDATA_DISCA	0x0800

#define	DB_PCI_REG_ADDR(bus, device, function, reg) \
	(((bus) & 0xff) << 16) | (((device & 0x1f)) << 11) \
		    | (((function) & 0x7) << 8) | ((reg) & 0xff)

/* form a type 0 configuration address */
#define	DB_PCI_REG_ADDR_TYPE0(bus, device, function, reg) \
	(((1 << (device & 0x1f)) << 11) \
		    | (((function) & 0x7) << 8) | \
		    ((reg) & 0xfc))

/* form a type 1 configuration address */
#define	DB_PCI_REG_ADDR_TYPE1(bus, device, function, reg) \
	((((bus) & 0xff) << 16) | (((device & 0x1f)) << 11) \
		    | (((function) & 0x7) << 8) | ((reg) & 0xfc))


#define	DB_ENABLE_PCI_CONF_CYCLE_TYPE0	0
#define	DB_ENABLE_PCI_CONF_CYCLE_TYPE1	1

/*
 * add local address offsets and get the right config address double
 * word aligned type 0 format addresses.
 */
#define	DB_PCI_CONF_CYCLE_TYPE0_ADDR(conf_addr) \
	(((conf_addr) & 0xfffffffc) | DB_ENABLE_PCI_CONF_CYCLE_TYPE0)

/*
 * add local address offsets and get the right config address double
 * word aligned type 1 format addresses.
 */
#define	DB_PCI_CONF_CYCLE_TYPE1_ADDR(conf_addr) \
	(((conf_addr)  & 0xfffffffc) | DB_ENABLE_PCI_CONF_CYCLE_TYPE1)

#define	PCI_HDR_SIZE	64

typedef struct db_pci_header {
	uint16_t 	venid;
	uint16_t	devid;
	uint16_t	command;
	uint16_t	status;
	uint8_t		revid;
	uint8_t		pif;
	uint8_t		subclass;
	uint8_t		class;
	uint8_t		cacheline;
	uint8_t		lat;
	uint8_t		hdr_type;
	uint8_t		bist;
	uint32_t	bar0;
	uint32_t	bar1;
	uint32_t	bar2;
	uint32_t	bar3;
	uint32_t	bar4;
	uint32_t	bar5;
	uint32_t	cardbus_cisp;
	uint16_t 	sub_venid;
	uint16_t 	sub_devid;
	uint32_t	exprom_bar;
	uint32_t	res1;
	uint32_t	res2;
	uint8_t		int_line;
	uint8_t		int_pin;
	uint8_t		min_gnt;
	uint8_t		max_lat;
} db_pci_header_t;

typedef struct db_conf_regs {
	uint32_t	ds_mem0_tr_base; /* DS memory 0 translated base */
	uint32_t	ds_io_mem1_tr_base; /* DS IO or memory1 trans base */
	uint32_t	ds_mem2_tr_base; /* DS memory 2 trans base */
	uint32_t	ds_mem3_tr_base; /* DS memory 3 trans base */
	uint32_t	us_io_mem0_tr_base; /* US IO or memory0 trans base */
	uint32_t	us_mem1_tr_base; /* US memory 1 translated base */
	uint32_t	ds_mem0_setup_reg; /* DS memory 0 setup reg */
	uint32_t	ds_io_mem1_setup_reg; /* DS IO or memory1 setup reg */
	uint32_t	ds_mem2_setup_reg; /* DS memory 2 setup reg */
	uint64_t	ds_mem3_setup_reg; /* DS memory 3 setup reg */
	uint32_t	p_exp_rom_setup; /* primary expansion ROM setup reg */
	uint32_t	us_io_mem0_setup_reg; /* US IO or memory 0 setup reg */
	uint32_t	us_mem1_setup_reg; /* US memory 1 setup reg */
	ushort_t	chip_control0;	/* chip control 0 */
	ushort_t	chip_control1;	/* chip control 1 */
	ushort_t	chip_status;	/* chip status */
	ushort_t	arb_control;	/* arbiter control */
	uchar_t		p_serr_disables; /* primary SERR# disables */
	uchar_t		s_serr_disables; /* secondary SERR# disables */
	ushort_t	config_csr;	/* configuration control and status */
	uint32_t	reset_control;	/* reset control */
	ushort_t	pm_cap;		/* power management capabilities reg */
	ushort_t	pm_csr;		/* power management control status */
	uint8_t		hs_csr;		/* hotswap control status */
} db_conf_regs_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DB21554_CONFIG_H */
