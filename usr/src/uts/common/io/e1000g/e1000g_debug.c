/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2009 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

/*
 * **********************************************************************
 *									*
 * Module Name:								*
 * 	e1000g_debug.c							*
 *									*
 * Abstract:								*
 *	This module includes the debug routines				*
 *									*
 * **********************************************************************
 */
#ifdef GCC
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#define	_SYS_VARARGS_H
#endif

#include "e1000g_debug.h"
#include "e1000g_sw.h"
#ifdef E1000G_DEBUG
#include <sys/pcie.h>
#endif

#ifdef E1000G_DEBUG
#define	WPL		8	/* 8 16-bit words per line */
#define	NUM_REGS	155	/* must match the array initializer */
typedef struct {
	char		name[10];
	uint32_t	offset;
} Regi_t;

int e1000g_debug = E1000G_WARN_LEVEL;
#endif	/* E1000G_DEBUG */
int e1000g_log_mode = E1000G_LOG_PRINT;

void
e1000g_log(void *instance, int level, char *fmt, ...)
{
	struct e1000g *Adapter = (struct e1000g *)instance;
	auto char name[NAMELEN];
	auto char buf[BUFSZ];
	va_list ap;

	switch (level) {
#ifdef E1000G_DEBUG
	case E1000G_VERBOSE_LEVEL:	/* 16 or 0x010 */
		if (e1000g_debug < E1000G_VERBOSE_LEVEL)
			return;
		level = CE_CONT;
		break;

	case E1000G_TRACE_LEVEL:	/* 8 or 0x008 */
		if (e1000g_debug < E1000G_TRACE_LEVEL)
			return;
		level = CE_CONT;
		break;

	case E1000G_INFO_LEVEL:		/* 4 or 0x004 */
		if (e1000g_debug < E1000G_INFO_LEVEL)
			return;
		level = CE_CONT;
		break;

	case E1000G_WARN_LEVEL:		/* 2 or 0x002 */
		if (e1000g_debug < E1000G_WARN_LEVEL)
			return;
		level = CE_CONT;
		break;

	case E1000G_ERRS_LEVEL:		/* 1 or 0x001 */
		level = CE_CONT;
		break;
#else
	case CE_CONT:
	case CE_NOTE:
	case CE_WARN:
	case CE_PANIC:
		break;
#endif
	default:
		level = CE_CONT;
		break;
	}

	if (Adapter != NULL) {
		(void) sprintf(name, "%s - e1000g[%d] ",
		    ddi_get_name(Adapter->dip), ddi_get_instance(Adapter->dip));
	} else {
		(void) sprintf(name, "e1000g");
	}
	/*
	 * va_start uses built in macro __builtin_va_alist from the
	 * compiler libs which requires compiler system to have
	 * __BUILTIN_VA_ARG_INCR defined.
	 */
	/*
	 * Many compilation systems depend upon the use of special functions
	 * built into the the compilation system to handle variable argument
	 * lists and stack allocations.  The method to obtain this in SunOS
	 * is to define the feature test macro "__BUILTIN_VA_ARG_INCR" which
	 * enables the following special built-in functions:
	 *	__builtin_alloca
	 *	__builtin_va_alist
	 *	__builtin_va_arg_incr
	 * It is intended that the compilation system define this feature test
	 * macro, not the user of the system.
	 *
	 * The tests on the processor type are to provide a transitional period
	 * for existing compilation systems, and may be removed in a future
	 * release.
	 */
	/*
	 * Using GNU gcc compiler it doesn't expand to va_start....
	 */
	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	if ((e1000g_log_mode & E1000G_LOG_ALL) == E1000G_LOG_ALL)
		cmn_err(level, "%s: %s", name, buf);
	else if (e1000g_log_mode & E1000G_LOG_DISPLAY)
		cmn_err(level, "^%s: %s", name, buf);
	else if (e1000g_log_mode & E1000G_LOG_PRINT)
		cmn_err(level, "!%s: %s", name, buf);
	else /* if they are not set properly then do both */
		cmn_err(level, "%s: %s", name, buf);
}



#ifdef E1000G_DEBUG
extern kmutex_t e1000g_nvm_lock;

void
eeprom_dump(void *instance)
{
	struct e1000g *Adapter = (struct e1000g *)instance;
	struct e1000_hw *hw = &Adapter->shared;
	uint16_t eeprom[WPL], size_field;
	int i, ret, sign, size, lines, offset = 0;
	int ee_size[] =
	    {128, 256, 512, 1024, 2048, 4096, 16 * 1024, 32 * 1024, 64 * 1024};

	mutex_enter(&e1000g_nvm_lock);

	if (ret = e1000_read_nvm(hw, 0x12, 1, &size_field)) {
		e1000g_log(Adapter, CE_WARN,
		    "e1000_read_nvm failed to read size: %d", ret);
		goto eeprom_dump_end;
	}

	sign = (size_field & 0xc000) >> 14;
	if (sign != 1) {
		e1000g_log(Adapter, CE_WARN,
		    "eeprom_dump invalid signature: %d", sign);
	}

	size = (size_field & 0x3c00) >> 10;
	if (size < 0 || size > 11) {
		e1000g_log(Adapter, CE_WARN,
		    "eeprom_dump invalid size: %d", size);
	}

	e1000g_log(Adapter, CE_CONT,
	    "eeprom_dump size field: %d  eeprom bytes: %d\n",
	    size, ee_size[size]);

	e1000g_log(Adapter, CE_CONT,
	    "e1000_read_nvm hebs: %d\n", ((size_field & 0x000f) >> 10));

	lines = ee_size[size] / WPL / 2;
	e1000g_log(Adapter, CE_CONT,
	    "dump eeprom %d lines of %d words per line\n", lines, WPL);

	for (i = 0; i < lines; i++) {
		if (ret = e1000_read_nvm(hw, offset, WPL, eeprom)) {
			e1000g_log(Adapter, CE_WARN,
			    "e1000_read_nvm failed: %d", ret);
			goto eeprom_dump_end;
		}

		e1000g_log(Adapter, CE_CONT,
		    "0x%04x    %04x %04x %04x %04x %04x %04x %04x %04x\n",
		    offset,
		    eeprom[0], eeprom[1], eeprom[2], eeprom[3],
		    eeprom[4], eeprom[5], eeprom[6], eeprom[7]);
		offset += WPL;
	}

eeprom_dump_end:
	mutex_exit(&e1000g_nvm_lock);
}

/*
 * phy_dump - dump important phy registers
 */
void
phy_dump(void *instance)
{
	struct e1000g *Adapter = (struct e1000g *)instance;
	struct e1000_hw *hw = &Adapter->shared;
	/* offset to each phy register */
	int32_t offset[] =
	    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
	    30, 31, 0x1796, 0x187A, 0x1895, 0x1F30, 0x1F35, 0x1F3E, 0x1F54,
	    0x1F55, 0x1F56, 0x1F72, 0x1F76, 0x1F77, 0x1F78, 0x1F79, 0x1F98,
	    0x2010, 0x2011, 0x20DC, 0x20DD, 0x20DE, 0x28B4, 0x2F52, 0x2F5B,
	    0x2F70, 0x2F90, 0x2FB1, 0x2FB2 };
	uint16_t value;	/* register value */
	uint32_t stat;	/* status from e1000_read_phy_reg */
	int i;

	e1000g_log(Adapter, CE_CONT, "Begin PHY dump\n");
	for (i = 0; i < ((sizeof (offset)) / sizeof (offset[0])); i++) {

		stat = e1000_read_phy_reg(hw, offset[i], &value);
		if (stat == 0) {
			e1000g_log(Adapter, CE_CONT,
			    "phyreg offset: %d   value: 0x%x\n",
			    offset[i], value);
		} else {
			e1000g_log(Adapter, CE_WARN,
			    "phyreg offset: %d   ERROR: 0x%x\n",
			    offset[i], stat);
		}
	}
}

uint32_t
e1000_read_reg(struct e1000_hw *hw, uint32_t offset)
{
	return (ddi_get32(((struct e1000g_osdep *)(hw)->back)->reg_handle,
	    (uint32_t *)((uintptr_t)(hw)->hw_addr + offset)));
}


/*
 * mac_dump - dump important mac registers
 */
void
mac_dump(void *instance)
{
	struct e1000g *Adapter = (struct e1000g *)instance;
	struct e1000_hw *hw = &Adapter->shared;
	int i;

	/* {name, offset} for each mac register */
	Regi_t macreg[NUM_REGS] = {
	    {"CTRL",	E1000_CTRL},	{"STATUS",	E1000_STATUS},
	    {"EECD",	E1000_EECD},	{"EERD",	E1000_EERD},
	    {"CTRL_EXT", E1000_CTRL_EXT}, {"FLA",	E1000_FLA},
	    {"MDIC",	E1000_MDIC},	{"SCTL",	E1000_SCTL},
	    {"FCAL",	E1000_FCAL},	{"FCAH",	E1000_FCAH},
	    {"FCT",	E1000_FCT},	{"VET",		E1000_VET},
	    {"ICR",	E1000_ICR},	{"ITR",		E1000_ITR},
	    {"ICS",	E1000_ICS},	{"IMS",		E1000_IMS},
	    {"IMC",	E1000_IMC},	{"IAM",		E1000_IAM},
	    {"RCTL",	E1000_RCTL},	{"FCTTV",	E1000_FCTTV},
	    {"TXCW",	E1000_TXCW},	{"RXCW",	E1000_RXCW},
	    {"TCTL",	E1000_TCTL},	{"TIPG",	E1000_TIPG},
	    {"AIT",	E1000_AIT},	{"LEDCTL",	E1000_LEDCTL},
	    {"PBA",	E1000_PBA},	{"PBS",		E1000_PBS},
	    {"EEMNGCTL", E1000_EEMNGCTL}, {"ERT",	E1000_ERT},
	    {"FCRTL",	E1000_FCRTL},	{"FCRTH",	E1000_FCRTH},
	    {"PSRCTL",	E1000_PSRCTL},	{"RDBAL(0)",	E1000_RDBAL(0)},
	    {"RDBAH(0)", E1000_RDBAH(0)}, {"RDLEN(0)",	E1000_RDLEN(0)},
	    {"RDH(0)",	E1000_RDH(0)},	{"RDT(0)",	E1000_RDT(0)},
	    {"RDTR",	E1000_RDTR},	{"RXDCTL(0)",	E1000_RXDCTL(0)},
	    {"RADV",	E1000_RADV},	{"RDBAL(1)",	E1000_RDBAL(1)},
	    {"RDBAH(1)", E1000_RDBAH(1)}, {"RDLEN(1)",	E1000_RDLEN(1)},
	    {"RDH(1)",	E1000_RDH(1)},	{"RDT(1)",	E1000_RDT(1)},
	    {"RXDCTL(1)", E1000_RXDCTL(1)}, {"RSRPD",	E1000_RSRPD},
	    {"RAID",	E1000_RAID},	{"CPUVEC",	E1000_CPUVEC},
	    {"TDFH",	E1000_TDFH},	{"TDFT",	E1000_TDFT},
	    {"TDFHS",	E1000_TDFHS},	{"TDFTS",	E1000_TDFTS},
	    {"TDFPC",	E1000_TDFPC},	{"TDBAL(0)",	E1000_TDBAL(0)},
	    {"TDBAH(0)", E1000_TDBAH(0)}, {"TDLEN(0)",	E1000_TDLEN(0)},
	    {"TDH(0)",	E1000_TDH(0)},	{"TDT(0)",	E1000_TDT(0)},
	    {"TIDV",	E1000_TIDV},	{"TXDCTL(0)",	E1000_TXDCTL(0)},
	    {"TADV",	E1000_TADV},	{"TARC(0)",	E1000_TARC(0)},
	    {"TDBAL(1)", E1000_TDBAL(1)}, {"TDBAH(1)",	E1000_TDBAH(1)},
	    {"TDLEN(1)", E1000_TDLEN(1)}, {"TDH(1)",	E1000_TDH(1)},
	    {"TDT(1)",	E1000_TDT(1)},	{"TXDCTL(1)",	E1000_TXDCTL(1)},
	    {"TARC(1)",	E1000_TARC(1)},	{"ALGNERRC",	E1000_ALGNERRC},
	    {"RXERRC",	E1000_RXERRC},	{"MPC",		E1000_MPC},
	    {"SCC",	E1000_SCC},	{"ECOL",	E1000_ECOL},
	    {"MCC",	E1000_MCC},	{"LATECOL",	E1000_LATECOL},
	    {"COLC",	E1000_COLC},	{"DC",		E1000_DC},
	    {"TNCRS",	E1000_TNCRS},	{"SEC",		E1000_SEC},
	    {"CEXTERR",	E1000_CEXTERR},	{"RLEC",	E1000_RLEC},
	    {"XONRXC",	E1000_XONRXC},	{"XONTXC",	E1000_XONTXC},
	    {"XOFFRXC",	E1000_XOFFRXC},	{"XOFFTXC",	E1000_XOFFTXC},
	    {"FCRUC",	E1000_FCRUC},	{"PRC64",	E1000_PRC64},
	    {"PRC127",	E1000_PRC127},	{"PRC255",	E1000_PRC255},
	    {"PRC511",	E1000_PRC511},	{"PRC1023",	E1000_PRC1023},
	    {"PRC1522",	E1000_PRC1522},	{"GPRC",	E1000_GPRC},
	    {"BPRC",	E1000_BPRC},	{"MPRC",	E1000_MPRC},
	    {"GPTC",	E1000_GPTC},	{"GORCL",	E1000_GORCL},
	    {"GORCH",	E1000_GORCH},	{"GOTCL",	E1000_GOTCL},
	    {"GOTCH",	E1000_GOTCH},	{"RNBC",	E1000_RNBC},
	    {"RUC",	E1000_RUC},	{"RFC",		E1000_RFC},
	    {"ROC",	E1000_ROC},	{"RJC",		E1000_RJC},
	    {"MGTPRC",	E1000_MGTPRC},	{"MGTPDC",	E1000_MGTPDC},
	    {"MGTPTC",	E1000_MGTPTC},	{"TORL",	E1000_TORL},
	    {"TORH",	E1000_TORH},	{"TOTL",	E1000_TOTL},
	    {"TOTH",	E1000_TOTH},	{"TPR",		E1000_TPR},
	    {"TPT",	E1000_TPT},	{"PTC64",	E1000_PTC64},
	    {"PTC127",	E1000_PTC127},	{"PTC255",	E1000_PTC255},
	    {"PTC511",	E1000_PTC511},	{"PTC1023",	E1000_PTC1023},
	    {"PTC1522",	E1000_PTC1522},	{"MPTC",	E1000_MPTC},
	    {"BPTC",	E1000_BPTC},	{"TSCTC",	E1000_TSCTC},
	    {"TSCTFC",	E1000_TSCTFC},	{"IAC",		E1000_IAC},
	    {"ICRXPTC",	E1000_ICRXPTC},	{"ICRXATC",	E1000_ICRXATC},
	    {"ICTXPTC",	E1000_ICTXPTC},	{"ICTXATC",	E1000_ICTXATC},
	    {"ICTXQEC",	E1000_ICTXQEC},	{"ICTXQMTC",	E1000_ICTXQMTC},
	    {"ICRXDMTC", E1000_ICRXDMTC}, {"ICRXOC",	E1000_ICRXOC},
	    {"RXCSUM",	E1000_RXCSUM},	{"RFCTL",	E1000_RFCTL},
	    {"WUC",	E1000_WUC},	{"WUFC",	E1000_WUFC},
	    {"WUS",	E1000_WUS},	{"MRQC",	E1000_MRQC},
	    {"MANC",	E1000_MANC},	{"IPAV",	E1000_IPAV},
	    {"MANC2H",	E1000_MANC2H},	{"RSSIM",	E1000_RSSIM},
	    {"RSSIR",	E1000_RSSIR},	{"WUPL",	E1000_WUPL},
	    {"GCR",	E1000_GCR},	{"GSCL_1",	E1000_GSCL_1},
	    {"GSCL_2",	E1000_GSCL_2},	{"GSCL_3",	E1000_GSCL_3},
	    {"GSCL_4",	E1000_GSCL_4},	{"FACTPS",	E1000_FACTPS},
	    {"FWSM",	E1000_FWSM},
	};

	e1000g_log(Adapter, CE_CONT, "Begin MAC dump\n");

	for (i = 0; i < NUM_REGS; i++) {
		e1000g_log(Adapter, CE_CONT,
		    "macreg %10s offset: 0x%x   value: 0x%x\n",
		    macreg[i].name, macreg[i].offset,
		    e1000_read_reg(hw, macreg[i].offset));
	}
}

void
pciconfig_dump(void *instance)
{
	struct e1000g *Adapter = (struct e1000g *)instance;
	ddi_acc_handle_t handle;
	uint8_t cap_ptr;
	uint8_t next_ptr;
	off_t offset;

	handle = Adapter->osdep.cfg_handle;

	e1000g_log(Adapter, CE_CONT, "Begin dump PCI config space\n");

	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_VENID:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_VENID));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_DEVID:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_DEVID));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_COMMAND:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_COMM));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_STATUS:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_STAT));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_REVID:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_REVID));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_PROG_CLASS:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_PROGCLASS));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_SUB_CLASS:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_SUBCLASS));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_BAS_CLASS:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_BASCLASS));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_CACHE_LINESZ:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_CACHE_LINESZ));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_LATENCY_TIMER:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_LATENCY_TIMER));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_HEADER_TYPE:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_HEADER));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_BIST:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_BIST));

	pciconfig_bar(Adapter, PCI_CONF_BASE0, "PCI_CONF_BASE0");
	pciconfig_bar(Adapter, PCI_CONF_BASE1, "PCI_CONF_BASE1");
	pciconfig_bar(Adapter, PCI_CONF_BASE2, "PCI_CONF_BASE2");
	pciconfig_bar(Adapter, PCI_CONF_BASE3, "PCI_CONF_BASE3");
	pciconfig_bar(Adapter, PCI_CONF_BASE4, "PCI_CONF_BASE4");
	pciconfig_bar(Adapter, PCI_CONF_BASE5, "PCI_CONF_BASE5");

	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_CIS:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_CIS));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_SUBVENID:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_SUBVENID));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_SUBSYSID:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_SUBSYSID));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_ROM:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_ROM));

	cap_ptr = pci_config_get8(handle, PCI_CONF_CAP_PTR);

	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_CAP_PTR:\t0x%x\n", cap_ptr);
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_ILINE:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_ILINE));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_IPIN:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_IPIN));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_MIN_G:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_MIN_G));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_CONF_MAX_L:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_MAX_L));

	/* Power Management */
	offset = cap_ptr;

	e1000g_log(Adapter, CE_CONT,
	    "PCI_PM_CAP_ID:\t0x%x\n",
	    pci_config_get8(handle, offset));

	next_ptr = pci_config_get8(handle, offset + 1);

	e1000g_log(Adapter, CE_CONT,
	    "PCI_PM_NEXT_PTR:\t0x%x\n", next_ptr);
	e1000g_log(Adapter, CE_CONT,
	    "PCI_PM_CAP:\t0x%x\n",
	    pci_config_get16(handle, offset + PCI_PMCAP));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_PM_CSR:\t0x%x\n",
	    pci_config_get16(handle, offset + PCI_PMCSR));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_PM_CSR_BSE:\t0x%x\n",
	    pci_config_get8(handle, offset + PCI_PMCSR_BSE));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_PM_DATA:\t0x%x\n",
	    pci_config_get8(handle, offset + PCI_PMDATA));

	/* MSI Configuration */
	offset = next_ptr;

	e1000g_log(Adapter, CE_CONT,
	    "PCI_MSI_CAP_ID:\t0x%x\n",
	    pci_config_get8(handle, offset));

	next_ptr = pci_config_get8(handle, offset + 1);

	e1000g_log(Adapter, CE_CONT,
	    "PCI_MSI_NEXT_PTR:\t0x%x\n", next_ptr);
	e1000g_log(Adapter, CE_CONT,
	    "PCI_MSI_CTRL:\t0x%x\n",
	    pci_config_get16(handle, offset + PCI_MSI_CTRL));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_MSI_ADDR:\t0x%x\n",
	    pci_config_get32(handle, offset + PCI_MSI_ADDR_OFFSET));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_MSI_ADDR_HI:\t0x%x\n",
	    pci_config_get32(handle, offset + 0x8));
	e1000g_log(Adapter, CE_CONT,
	    "PCI_MSI_DATA:\t0x%x\n",
	    pci_config_get16(handle, offset + 0xC));

	/* PCI Express Configuration */
	offset = next_ptr;

	e1000g_log(Adapter, CE_CONT,
	    "PCIE_CAP_ID:\t0x%x\n",
	    pci_config_get8(handle, offset + PCIE_CAP_ID));

	next_ptr = pci_config_get8(handle, offset + PCIE_CAP_NEXT_PTR);

	e1000g_log(Adapter, CE_CONT,
	    "PCIE_CAP_NEXT_PTR:\t0x%x\n", next_ptr);
	e1000g_log(Adapter, CE_CONT,
	    "PCIE_PCIECAP:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_PCIECAP));
	e1000g_log(Adapter, CE_CONT,
	    "PCIE_DEVCAP:\t0x%x\n",
	    pci_config_get32(handle, offset + PCIE_DEVCAP));
	e1000g_log(Adapter, CE_CONT,
	    "PCIE_DEVCTL:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_DEVCTL));
	e1000g_log(Adapter, CE_CONT,
	    "PCIE_DEVSTS:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_DEVSTS));
	e1000g_log(Adapter, CE_CONT,
	    "PCIE_LINKCAP:\t0x%x\n",
	    pci_config_get32(handle, offset + PCIE_LINKCAP));
	e1000g_log(Adapter, CE_CONT,
	    "PCIE_LINKCTL:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_LINKCTL));
	e1000g_log(Adapter, CE_CONT,
	    "PCIE_LINKSTS:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_LINKSTS));
}

void
pciconfig_bar(void *instance, uint32_t offset, char *name)
{
	struct e1000g *Adapter = (struct e1000g *)instance;
	ddi_acc_handle_t handle = Adapter->osdep.cfg_handle;
	uint32_t base = pci_config_get32(handle, offset);
	uint16_t comm = pci_config_get16(handle, PCI_CONF_COMM);
	uint32_t size;		/* derived size of the region */
	uint32_t bits_comm;	/* command word bits to disable */
	uint32_t size_mask;	/* mask for size extraction */
	char tag_type[32];	/* tag to show memory vs. i/o */
	char tag_mem[32];	/* tag to show memory characteristiccs */

	/* base address zero, simple print */
	if (base == 0) {
		e1000g_log(Adapter, CE_CONT, "%s:\t0x%x\n", name, base);

	/* base address non-zero, get size */
	} else {
		/* i/o factors that decode from the base address */
		if (base & PCI_BASE_SPACE_IO) {
			bits_comm = PCI_COMM_IO;
			size_mask = PCI_BASE_IO_ADDR_M;
			(void) strcpy(tag_type, "i/o port size:");
			(void) strcpy(tag_mem, "");
		/* memory factors that decode from the base address */
		} else {
			bits_comm = PCI_COMM_MAE;
			size_mask = PCI_BASE_M_ADDR_M;
			(void) strcpy(tag_type, "memory size:");
			if (base & PCI_BASE_TYPE_ALL)
				(void) strcpy(tag_mem, "64bit ");
			else
				(void) strcpy(tag_mem, "32bit ");
			if (base & PCI_BASE_PREF_M)
				(void) strcat(tag_mem, "prefetchable");
			else
				(void) strcat(tag_mem, "non-prefetchable");
		}

		/* disable memory decode */
		pci_config_put16(handle, PCI_CONF_COMM, (comm & ~bits_comm));

		/* write to base register */
		pci_config_put32(handle, offset, 0xffffffff);

		/* read back & compute size */
		size = pci_config_get32(handle, offset);
		size &= size_mask;
		size = (~size) + 1;

		/* restore base register */
		pci_config_put32(handle, offset, base);

		/* re-enable memory decode */
		pci_config_put16(handle, PCI_CONF_COMM, comm);

		/* print results */
		e1000g_log(Adapter, CE_CONT, "%s:\t0x%x %s 0x%x %s\n",
		    name, base, tag_type, size, tag_mem);
	}
}
#endif	/* E1000G_DEBUG */
