/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_ADAPTERS_H
#define	_EMLXS_ADAPTERS_H

#ifdef	__cplusplus
extern "C" {
#endif

/* Unique id for each adapter model */
typedef enum emlxs_adapter
{
	UNKNOWN_ADAPTER = 0,

	/* DragonFly (1) */
	LP8000S,	/* SBUS */
	LP8000,		/* Generic Single Channel */
	LP8000DC,	/* Generic Dual Channel */

	/* Centaur (4) */
	LP9002S,	/* SBUS */
	LP9002L,
	LP9002C,
	LP9002DC,
	LP9402DC,

	/* Pegasus (9) */
	LP9802,		/* Generic Single Channel */
	LP9802DC,	/* Generic Dual Channel */

	/* Thor (11) */
	LP10000,	/* Generic Single Channel */
	LP10000DC,	/* Generic Dual Channel */
	LP10000_O,	/* Oracle branded */
	LP10000DC_O,	/* Oracle branded */
	LP10000ExDC,
	BLADE_2G,

	/* Helios (17) */
	LP11000,	/* Generic Single Channel */
	LP11002,	/* Generic Dual Channel */
	LP11000_O,	/* Oracle branded */
	LP11002_O,	/* Oracle branded */
	LP11000_SP,	/* Spare */
	LP11002_SP,	/* Spare */

	/* Zephyr (23) */
	LPe11000,	/* Generic Single Channel */
	LPe1100X,	/* Generic Multi Channel */
	LPe11000_O,	/* Oracle branded */
	LPe11002_O,	/* Oracle branded */
	LPem11002_O,	/* Oracle branded */
	LPe11020_O,	/* Oracle branded */
	LPeA11002_O,	/* Oracle branded */
	LPem11002E_O,	/* Oracle branded */

	/* Hornet (31) */
	LP21000,	/* Generic Single Channel */
	LP21002,	/* Generic Dual Channel */

	/* Saturn (33) */
	LPe12000,	/* Generic Single Channel */
	LPe12002,	/* Generic Dual Channel */
	LPe12000_O,	/* Oracle branded */
	LPe12002_O,	/* Oracle branded */
	LPem12002_O,	/* Oracle branded */
	LPem12002E_O,	/* Oracle branded */
	LPe12000_SP,	/* Spare */
	LPe12002_SP,	/* Spare */

	/* BE2 (41) */
	OCe10101,	/* Generic Single Channel */
	OCe10102,	/* Generic Dual Channel */

	/* BE3 (43) */
	OCe11101,	/* Generic Single Channel */
	OCe11102,	/* Generic Dual Channel */

	/* Lancer FC (45) */
	LPe16000,	/* Generic Single Channel FC */
	LPe1600X,	/* Generic Multi Channel FC */
	LPem16002_FC_O,	/* Oracle branded */
	LPe16002_FC_O,	/* Oracle branded */
	LPe16002_FC_SP1, /* Oracle excluded - Spare */
	LPe16002_FC_SP2, /* Oracle excluded - Spare */

	/* Lancer FCoE (51) */
	OCe15100,	/* Generic Single Channel FCOE */
	OCe1510X,	/* Generic Multi Channel FCOE */
	LPem16002_FE_O,	/* Oracle branded */
	LPe16002_FE_O,	/* Oracle branded */
	LPe16002_FE_SP1, /* Oracle excluded - Spare */
	LPe16002_FE_SP2, /* Oracle excluded - Spare */

	/* BE4 (57) */
	OCe12104	/* 4-Port 2xNIC +2xFCoE */

} emlxs_adapter_t;


#define	PCI_VENDOR_ID_EMULEX		0x10df

/* Subsystem Vendor IDs */
#define	PCI_SSVID_EMULEX		0x10df
#define	PCI_SSVID_HP			0x103c
#define	PCI_SSVID_IBM			0x1014
#define	PCI_SSVID_FUJITSU		0x1734
#define	PCI_SSVID_CISCO			0x1137
#define	PCI_SSVID_HITACHI		0x1054


/* PCI_DEVICE_IDs & PCI_SSDIDs */
/* F800: Dragonfly */
#define	PCI_DEVICE_ID_DRAGONFLY		0xf800
#define	PCI_SSDID_LP8000		0xf800
#define	PCI_SSDID_LP8000DC		0xf800	/* Identified by VPD PN */

/* F085: Dragonfly SBUS */
#define	PCI_DEVICE_ID_DRAGONFLY_SBUS	0xf085	/* Identified by "lpfs" */
#define	PCI_SSDID_LP8000S		0xf085


/* F900: Centaur */
#define	PCI_DEVICE_ID_CENTAUR		0xf900
#define	PCI_SSDID_LP9002L		0xf900
#define	PCI_SSDID_LP9002DC		0xf900	/* Identified by VPD PN */
#define	PCI_SSDID_LP9002C		0xf900	/* Identified by VPD PN */
#define	PCI_SSDID_LP9402DC		0xf900	/* Identified by VPD PN */

/* F095: Centaur SBUS */
#define	PCI_DEVICE_ID_CENTAUR_SBUS	0xf095	/* Identified by "lpfs" */
#define	PCI_SSDID_LP9002S		0xf095


/* F980: Pegasus */
#define	PCI_DEVICE_ID_PEGASUS		0xf980
#define	PCI_SSDID_LP9802		0xf980
#define	PCI_SSDID_LP9802DC		0xf980	/* Identified by RAM size */


/* FA00: Thor */
#define	PCI_DEVICE_ID_THOR		0xfa00
#define	PCI_SSDID_LP10000		0xfa00
#define	PCI_SSDID_LP10000DC		0xfa00	/* Identified by VPD PN and */
						/* by cache_line */
#define	PCI_SSDID_LP10000ExDC		0xfa00	/* Identified by VPD PN and */
						/* by cache_line */
/* F0A5: Thor Blade */
#define	PCI_DEVICE_ID_THOR_BLADE	0xf0a5
#define	PCI_SSDID_BLADE_2G		0xf0a5

/* FC00: Thor Oracle */
#define	PCI_DEVICE_ID_THOR_O		0xfc00
#define	PCI_SSDID_LP10000_O		0xfc00
#define	PCI_SSDID_LP10000DC_O		0xfc00	/* Identified by cache_line */


/* FD00: Helios */
#define	PCI_DEVICE_ID_HELIOS		0xfd00
#define	PCI_SSDID_LP11000		0xfd00
#define	PCI_SSDID_LP11002		0xfd00	/* Identified by cache_line */

/* FD11: Helios Spare */
#define	PCI_DEVICE_ID_LP11000_SP	0xfd11
#define	PCI_SSDID_LP11000_SP		0xfd11

/* FD12: Helios Spare */
#define	PCI_DEVICE_ID_LP11002_SP	0xfd12
#define	PCI_SSDID_LP11002_SP		0xfd12

/* FC10: Helios Oracle */
#define	PCI_DEVICE_ID_HELIOS_O		0xfc10
#define	PCI_SSDID_LP11000_O		0xfc11
#define	PCI_SSDID_LP11002_O		0xfc12


/* FE00: Zephyr */
#define	PCI_DEVICE_ID_ZEPHYR		0xfe00
#define	PCI_SSDID_LPe11000		0xfe00
#define	PCI_SSDID_LPe1100X		0xfe00	/* Identified by cache_line */


/* FC20: Zephyr Oracle */
#define	PCI_DEVICE_ID_ZEPHYR_O		0xfc20
#define	PCI_SSDID_LPe11000_O		0xfc21
#define	PCI_SSDID_LPe11002_O		0xfc22
#define	PCI_SSDID_LPem11002E_O		0xfc23
#define	PCI_SSDID_LPe11020_O		0xfc2a
#define	PCI_SSDID_LPeA11002_O		0xfc2d
#define	PCI_SSDID_LPem11002_O		0xfc2e


/* FE05: Hornet */
#define	PCI_DEVICE_ID_HORNET		0xfe05
#define	PCI_SSDID_LP21000		0xfe05
#define	PCI_SSDID_LP21002		0xfe05  /* Identified by cache_line */


/* F100: Saturn */
#define	PCI_DEVICE_ID_SATURN		0xf100
#define	PCI_SSDID_LPe12000		0xf100
#define	PCI_SSDID_LPe12002		0xf100 /* Identified by cache_line */

/* F111: Saturn Spare */
#define	PCI_DEVICE_ID_LPe12000_SP	0xf111
#define	PCI_SSDID_LPe12000_SP		0xf111

/* F112: Saturn Spare */
#define	PCI_DEVICE_ID_LPe12002_SP	0xf112
#define	PCI_SSDID_LPe12002_SP		0xf112

/* FC40: Saturn Oracle */
#define	PCI_DEVICE_ID_SATURN_O		0xfc40
#define	PCI_SSDID_LPe12000_O		0xfc41
#define	PCI_SSDID_LPe12002_O		0xfc42
#define	PCI_SSDID_LPem12002_O		0xfc4e
#define	PCI_SSDID_LPem12002E_O		0xfc43


/* 0704: BE2 (TigerShark) */
#define	PCI_DEVICE_ID_BE2		0x0704
#define	PCI_SSDID_OCe10101		0x0704
#define	PCI_SSDID_OCe10102		0x0704 /* Identified by cache_line */


/* 0714: BE3 (TomCat) */
#define	PCI_DEVICE_ID_BE3		0x0714
#define	PCI_SSDID_OCe11101		0x0714
#define	PCI_SSDID_OCe11102		0x0714 /* Identified by cache_line */

/* 0724: BE4 (Skyhawk) */
#define	PCI_DEVICE_ID_BE4		0x0724
#define	PCI_SSDID_OCe12104		0xEF81

/* E200: Lancer FC */
#define	PCI_DEVICE_ID_LANCER_FC		0xE200
#define	PCI_SSDID_LPe16000		0xE200
#define	PCI_SSDID_LPe1600X		0xE200 /* Identified by cache_line */
#define	PCI_SSDID_LPem16002_FC_O	0xE20C
#define	PCI_SSDID_LPe16002_FC_O		0xE20E
#define	PCI_SSDID_LPe16002_FC_SP1	0xE217
#define	PCI_SSDID_LPe16002_FC_SP2	0xE219

/* E260: Lancer FCoE */
#define	PCI_DEVICE_ID_LANCER_FE		0xE260
#define	PCI_SSDID_OCe15100		0xE260
#define	PCI_SSDID_OCe1510X		0xE260 /* Identified by cache_line */
#define	PCI_SSDID_LPem16002_FE_O	0xE20C
#define	PCI_SSDID_LPe16002_FE_O		0xE20E
#define	PCI_SSDID_LPe16002_FE_SP1	0xE217
#define	PCI_SSDID_LPe16002_FE_SP2	0xE219



/* JEDEC codes */
#define	FIREFLY_JEDEC_ID	0x1ACC
#define	SUPERFLY_JEDEC_ID	0x0020
#define	DRAGONFLY_JEDEC_ID	0x0021
#define	DRAGONFLY_V2_JEDEC_ID	0x0025
#define	CENTAUR_2G_JEDEC_ID	0x0026
#define	CENTAUR_1G_JEDEC_ID	0x0028
#define	HELIOS_4G_JEDEC_ID	0x0364
#define	ZEPHYR_4G_JEDEC_ID	0x0577
#define	NEPTUNE_4G_JEDEC_ID	0x0510
#define	SATURN_8G_JEDEC_ID	0x1004
#define	PROTEUS_8G_JEDEC_ID	0x2634
#define	JEDEC_ID_MASK		0x0FFFF000
#define	JEDEC_ID_SHIFT		12
#define	FC_JEDEC_ID(id)		((id & JEDEC_ID_MASK) >> JEDEC_ID_SHIFT)


typedef struct emlxs_model
{
	emlxs_adapter_t id;
	uint16_t	device_id;
	uint16_t	ssdid;

	char		model[32];
	char		model_desc[80];
	char		manufacturer[80];
	uint32_t	flags;

	/* flags */
#define	EMLXS_INTX_SUPPORTED	0x00000001
#define	EMLXS_MSI_SUPPORTED	0x00000002
#define	EMLXS_MSIX_SUPPORTED	0x00000004
#define	EMLXS_E2E_SUPPORTED	0x00000010 /* End-to-end authentication */
#define	EMLXS_ORACLE_BRANDED	0x10000000
#define	EMLXS_ORACLE_EXCLUDED	0x20000000
#define	EMLXS_NOT_SUPPORTED	0x80000000

	uint32_t	chip;

	/* chip */
#define	EMLXS_UNKNOWN_CHIP	0x00000000
#define	EMLXS_DRAGONFLY_CHIP	0x00000001
#define	EMLXS_CENTAUR_CHIP	0x00000002
#define	EMLXS_PEGASUS_CHIP	0x00000004
#define	EMLXS_THOR_CHIP		0x00000008
#define	EMLXS_HELIOS_CHIP	0x00000010
#define	EMLXS_ZEPHYR_CHIP	0x00000020
#define	EMLXS_NEPTUNE_CHIP	0x00000040
#define	EMLXS_SATURN_CHIP	0x00000080
#define	EMLXS_PROTEUS_CHIP	0x00000100
#define	EMLXS_BE2_CHIP		0x00000200
#define	EMLXS_BE3_CHIP		0x00000400
#define	EMLXS_BE4_CHIP		0x00000800
#define	EMLXS_BE_CHIPS		(EMLXS_BE2_CHIP|EMLXS_BE3_CHIP|EMLXS_BE4_CHIP)
#define	EMLXS_LANCER_CHIP	0x00001000

	emlxs_fwid_t	fwid;
	uint32_t	intr_limit;

#define	EMLXS_INTR_NO_LIMIT	0x00000000
#define	EMLXS_INTR_LIMIT1	0x00000001
#define	EMLXS_INTR_LIMIT2	0x00000002
#define	EMLXS_INTR_LIMIT4	0x00000004
#define	EMLXS_INTR_LIMIT8	0x00000008
#define	EMLXS_INTR_LIMIT16	0x00000010

	uint32_t	sli_mask;

#define	EMLXS_SLI0_MASK		0x00000000
#define	EMLXS_SLI2_MASK		0x00000002
#define	EMLXS_SLI3_MASK		0x00000004
#define	EMLXS_SLI4_MASK		0x00000008

#define	EMLXS_SLI_MASK(_mode)  ((_mode < 2) ? 0 : (1 << _mode))

	uint32_t	channels;
#define	EMLXS_SINGLE_CHANNEL	1
#define	EMLXS_MULTI_CHANNEL	2

	uint8_t		pt_2[8];	/* stub */
	uint8_t		pt_3[8];	/* boot */
	uint8_t		pt_6[8];	/* SLI1 */
	uint8_t		pt_7[8];	/* SLI2 */
	uint8_t		pt_A[8];	/* SBUS FCODE */
	uint8_t		pt_B[8];	/* SLI3 */
	uint8_t		pt_E[8];	/* SLI4 (old) */
	uint8_t		pt_FF[8];	/* kern */
	uint8_t		pt_20[8];
#define	NULL_PROG_TYPES		{0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}

} emlxs_model_t;

#ifdef EMLXS_MODEL_DEF

/* Define the SBUS adapter database */
emlxs_model_t   emlxs_sbus_model[] =
{
	/* Unknown */
	{
		UNKNOWN_ADAPTER,
		0,
		0,
		"unknown",
		"Unknown Emulex LightPulse FC HBA",
		"Emulex",
		EMLXS_NOT_SUPPORTED,
		EMLXS_UNKNOWN_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK,
		0,
		NULL_PROG_TYPES,
	},

	/* Dragonfly midrange (QFLY) */
	{
		LP8000S,
		PCI_DEVICE_ID_DRAGONFLY_SBUS,
		PCI_SSDID_LP8000S,
		"LP8000S",
		"Emulex LP8000S 1Gb 1-port SBUS FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_DRAGONFLY_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0x21, 0xB0, 0},
		{0},
		{0x31, 0},
		{0x31, 0x39, 0},
		{0x01, 0},
		{0},
		{0},
		{0x30, 0},
		{0}, /* T20 */
	},

	/* Centaur mid-range (RFLY, Rtaur) */
	{
		LP9002S,
		PCI_DEVICE_ID_CENTAUR_SBUS,
		PCI_SSDID_LP9002S,
		"LP9002S",
		"Emulex LP9002S 2Gb 1-port SBUS FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_CENTAUR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0x41, 0xD0, 0},
		{0},
		{0x51, 0},
		{0x51, 0},
		{0x02, 0},
		{0},
		{0},
		{0x50, 0},
		{0}, /* T20 */
	},

};	/* emlxs_sbus_model[] */

#define	EMLXS_SBUS_MODEL_COUNT \
	(sizeof (emlxs_sbus_model) / sizeof (emlxs_model_t))


/* Define the PCI adapter database */
emlxs_model_t   emlxs_pci_model[] =
{
	/* Unknown */
	{
		UNKNOWN_ADAPTER,
		0,
		0,
		"unknown",
		"Unknown Emulex LightPulse FC HBA",
		"Emulex",
		EMLXS_NOT_SUPPORTED,
		EMLXS_UNKNOWN_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK,
		0,
		NULL_PROG_TYPES,
	},

	/* Dragonfly */
	{
		LP8000,
		PCI_DEVICE_ID_DRAGONFLY,
		PCI_SSDID_LP8000,
		"LP8000",
		"Emulex LP8000 1Gb 1-port PCI FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_DRAGONFLY_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0x21, 0x22, 0x23, 0xA0, 0},
		{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0},
		{0x21, 0x22, 0x23, 0},
		{0x21, 0x22, 0x23, 0},
		{0},
		{0},
		{0},
		{0x20, 0},
		{0}, /* T20 */
	},

	/* Dragonfly DC */
	/* !! Must always follow the single channel entry in list */
	{
		LP8000DC,
		PCI_DEVICE_ID_DRAGONFLY,
		PCI_SSDID_LP8000DC,
		"LP8000DC",
		"Emulex LP8000DC 1Gb 2-port PCI FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_DRAGONFLY_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x21, 0x22, 0x23, 0xA0, 0},
		{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0},
		{0x21, 0x22, 0x23, 0},
		{0x21, 0x22, 0x23, 0},
		{0},
		{0},
		{0},
		{0x20, 0},
		{0}, /* T20 */
	},

	/* Centaur PCI */
	{
		LP9002L,
		PCI_DEVICE_ID_CENTAUR,
		PCI_SSDID_LP9002L,
		"LP9002L",
		"Emulex LP9002L 2Gb 1-port PCI FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_CENTAUR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0x41, 0x43, 0xC0, 0},
		{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0},
		{0x41, 0x43, 0},
		{0x41, 0x43, 0},
		{0},
		{0},
		{0},
		{0x40, 0},
		{0}, /* T20 */
	},

	/* Centaur cPCI */
	{
		LP9002C,
		PCI_DEVICE_ID_CENTAUR,
		PCI_SSDID_LP9002C,
		"LP9002C",
		"Emulex LP9002C 2Gb 1-port cPCI FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_CENTAUR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0x41, 0x43, 0xC0, 0},
		{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0},
		{0x41, 0x43, 0},
		{0x41, 0x43, 0},
		{0},
		{0},
		{0},
		{0x40, 0},
		{0}, /* T20 */
	},

	/* Centaur DC PCI */
	/* !! Must always follow the single channel entry in list */
	{
		LP9002DC,
		PCI_DEVICE_ID_CENTAUR,
		PCI_SSDID_LP9002DC,
		"LP9002DC",
		"Emulex LP9002DC 2Gb 2-port PCI FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_CENTAUR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x41, 0x43, 0xC0, 0},
		{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0},
		{0x41, 0x43, 0},
		{0x41, 0x43, 0},
		{0},
		{0},
		{0},
		{0x40, 0},
		{0}, /* T20 */
	},

	/* Centaur DC PCI-X */
	/* !! Must always follow the single channel entry in list */
	{
		LP9402DC,
		PCI_DEVICE_ID_CENTAUR,
		PCI_SSDID_LP9402DC,
		"LP9402DC",
		"Emulex LP9402DC 2Gb 2-port PCI-X FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_CENTAUR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x41, 0x43, 0xC0, 0},
		{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0},
		{0x41, 0x43, 0},
		{0x41, 0x43, 0},
		{0},
		{0},
		{0},
		{0x40, 0},
		{0}, /* T20 */
	},

	/* Pegasus */
	{
		LP9802,
		PCI_DEVICE_ID_PEGASUS,
		PCI_SSDID_LP9802,
		"LP9802",
		"Emulex LP9802 2Gb 1-port PCI-X FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_PEGASUS_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0x63, 0xE0, 0},
		{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0},
		{0x63, 0},
		{0x63, 0},
		{0},
		{0x63, 0},
		{0},
		{0x60, 0},
		{0}, /* T20 */
	},

	/* Pegasus DC */
	/* !! Must always follow the single channel entry in list */
	{
		LP9802DC,
		PCI_DEVICE_ID_PEGASUS,
		PCI_SSDID_LP9802DC,
		"LP9802DC",
		"Emulex LP9802DC 2Gb 2-port PCI-X FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_PEGASUS_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x61, 0xE0, 0},
		{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0},
		{0x61, 0},
		{0x61, 0},
		{0},
		{0x61, 0},
		{0},
		{0x60, 0},
		{0}, /* T20 */
	},

	/* Thor */
	{
		LP10000,
		PCI_DEVICE_ID_THOR,
		PCI_SSDID_LP10000,
		"LP10000",
		"Emulex LP10000 2Gb 1-port PCI-X FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_THOR_CHIP,
		LP10000_FW,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0x81, 0x83, 0x88, 0},
		{0x81, 0x82, 0x83, 0x85, 0x86, 0x87, 0},
		{0x81, 0x83, 0},
		{0x81, 0x83, 0},
		{0},
		{0x81, 0x83, 0},
		{0},
		{0x80, 0},
		{0}, /* T20 */
	},

	/* Thor DC */
	/* !! Must always follow the single channel entry in list */
	{
		LP10000DC,
		PCI_DEVICE_ID_THOR,
		PCI_SSDID_LP10000DC,
		"LP10000DC",
		"Emulex LP10000DC 2Gb 2-port PCI-X FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_THOR_CHIP,
		LP10000_FW,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x81, 0x83, 0x88, 0},
		{0x81, 0x82, 0x83, 0x85, 0x86, 0x87, 0},
		{0x81, 0x83, 0},
		{0x81, 0x83, 0},
		{0},
		{0x81, 0x83, 0},
		{0},
		{0x80, 0},
		{0}, /* T20 */
	},

	/* Thor DC express */
	/* !! Must always follow the single channel entry in list */
	{
		LP10000ExDC,
		PCI_DEVICE_ID_THOR,
		PCI_SSDID_LP10000ExDC,
		"LP10000ExDC",
		"Emulex LP10000ExDC 2Gb 2-port PCIe FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_THOR_CHIP,
		LP10000_FW,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x81, 0x83, 0x88, 0},
		{0x81, 0x82, 0x83, 0x85, 0x86, 0x87, 0},
		{0x81, 0x83, 0},
		{0x81, 0x83, 0},
		{0},
		{0x81, 0x83, 0},
		{0},
		{0x80, 0},
		{0}, /* T20 */
	},

	/* Thor (Oracle Rainbow-E1) */
	{
		LP10000_O,
		PCI_DEVICE_ID_THOR_O,
		PCI_SSDID_LP10000_O,
		"LP10000-S",
		"Emulex LP10000-S 2Gb 1-port PCI-X FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED,
		EMLXS_THOR_CHIP,
		LP10000_FW,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0x83, 0x88, 0},
		{0x82, 0x84, 0},
		{0x83, 0},
		{0x83, 0},
		{0},
		{0x83, 0},
		{0},
		{0x80, 0},
		{0}, /* T20 */
	},

	/* Thor DC (Oracle Rainbow-E2) */
	/* !! Must always follow the single channel entry in list */
	{
		LP10000DC_O,
		PCI_DEVICE_ID_THOR_O,
		PCI_SSDID_LP10000DC_O,
		"LP10000DC-S",
		"Emulex LP10000DC-S 2Gb 2-port PCI-X FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED,
		EMLXS_THOR_CHIP,
		LP10000_FW,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x83, 0x88, 0},
		{0x82, 0x84, 0},
		{0x83, 0},
		{0x83, 0},
		{0},
		{0x83, 0},
		{0},
		{0x80, 0},
		{0}, /* T20 */
	},

	/* Thor mid-range (MiniThor) */
	{
		BLADE_2G,
		PCI_DEVICE_ID_THOR_BLADE,
		PCI_SSDID_BLADE_2G,
		"2G Blade Adapter",
		"Emulex 2G 2-port Blade PCI-X FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_THOR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x98, 0},
		{0x91, 0x92, 0x93, 0x95, 0x96, 0x97, 0},
		{0x91, 0},
		{0x91, 0},
		{0},
		{0x91, 0},
		{0},
		{0x90, 0},
		{0}, /* T20 */
	},

	/* Helios */
	{
		LP11000,
		PCI_DEVICE_ID_HELIOS,
		PCI_SSDID_LP11000,
		"LP11000",
		"Emulex LP11000 4Gb 1-port PCI-X2 FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_HELIOS_CHIP,
		LP11000_FW,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0xC3, 0xC8, 0},
		{0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0},
		{0xC3, 0},
		{0xC3, 0},
		{0},
		{0xC3, 0},
		{0},
		{0xC0, 0},
		{0}, /* T20 */
	},

	/* Helios DC */
	/* !! Must always follow the single channel entry in list */
	{
		LP11002,
		PCI_DEVICE_ID_HELIOS,
		PCI_SSDID_LP11002,
		"LP11002",
		"Emulex LP11002 4Gb 2-port PCI-X2 FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_HELIOS_CHIP,
		LP11002_FW,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0xC1, 0xC8, 0},
		{0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0},
		{0xC1, 0},
		{0xC1, 0},
		{0},
		{0xC1, 0},
		{0},
		{0xC0, 0},
		{0}, /* T20 */
	},

	/* Helios (Oracle Pyramid-E1) */
	{
		LP11000_O,
		PCI_DEVICE_ID_HELIOS_O,
		PCI_SSDID_LP11000_O,
		"LP11000-S",
		"Emulex LP11000-S 4Gb 1-port PCI-X2 FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED,
		EMLXS_HELIOS_CHIP,
		LP11000_FW,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0xC3, 0xC8, 0},
		{0xC4, 0},
		{0xC3, 0},
		{0xC3, 0},
		{0},
		{0xC3, 0},
		{0},
		{0xC0, 0},
		{0}, /* T20 */
	},

	/* Helios DC (Oracle Pyramid-E2) */
	{
		LP11002_O,
		PCI_DEVICE_ID_HELIOS_O,
		PCI_SSDID_LP11002_O,
		"LP11002-S",
		"Emulex LP11002-S 4Gb 2-port PCI-X2 FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED,
		EMLXS_HELIOS_CHIP,
		LP11002_FW,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0xC1, 0xC8, 0},
		{0xC4, 0},
		{0xC1, 0},
		{0xC1, 0},
		{0},
		{0xC1, 0},
		{0},
		{0xC0, 0},
		{0}, /* T20 */
	},

	/* Helios Enterprise (Spare) */
	{
		LP11000_SP,
		PCI_DEVICE_ID_LP11000_SP,
		PCI_SSDID_LP11000_SP,
		"LP11000",
		"Emulex LP11000 4Gb 1-port PCI-X2 FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_HELIOS_CHIP,
		LP11000_FW,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0xC3, 0xC8, 0},
		{0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0},
		{0xC3, 0},
		{0xC3, 0},
		{0},
		{0xC3, 0},
		{0},
		{0xC0, 0},
		{0}, /* T20 */
	},

	/* Helios DC Enterprise (Spare) */
	{
		LP11002_SP,
		PCI_DEVICE_ID_LP11002_SP,
		PCI_SSDID_LP11002_SP,
		"LP11002",
		"Emulex LP11002 4Gb 2-port PCI-X2 FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_HELIOS_CHIP,
		LP11002_FW,
		EMLXS_INTR_LIMIT1,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0xC1, 0xC8, 0},
		{0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0},
		{0xC1, 0},
		{0xC1, 0},
		{0},
		{0xC1, 0},
		{0},
		{0xC0, 0},
		{0}, /* T20 */
	},

	/* Zephyr */
	{
		LPe11000,
		PCI_DEVICE_ID_ZEPHYR,
		PCI_SSDID_LPe11000,
		"LPe11000",
		"Emulex LPe11000 4Gb 1-port PCIe FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_ZEPHYR_CHIP,
		LPe11000_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0xE3, 0xE8, 0},
		{0xE1, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7, 0},
		{0xE3, 0},
		{0xE3, 0},
		{0},
		{0xE3, 0},
		{0},
		{0xE0, 0},
		{0}, /* T20 */
	},

	/* Zephyr */
	/* !! Must always follow the single channel entry in list */
	{
		LPe1100X,
		PCI_DEVICE_ID_ZEPHYR,
		PCI_SSDID_LPe1100X,
		"LPe11000",
		"Emulex LPe11000 4Gb Multi-port PCIe FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0xE1, 0xE8, 0},
		{0xE1, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
		{0}, /* T20 */
	},

	/* Zephyr Hornet */
	{
		LP21000,
		PCI_DEVICE_ID_HORNET,
		PCI_SSDID_LP21000,
		"LP21000",
		"Emulex LP21000 10GE 1-port PCIe FCoE HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_ZEPHYR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0x50, 0},
		{0x59, 0x5A, 0x5B, 0x5D, 0x5E, 0x5F, 0},
		{0},
		{0x53, 0x59, 0},
		{0},
		{0x53, 0x59, 0},
		{0},
		{0x58, 0},
		{0}, /* T20 */
	},

	/* Zephyr Hornet DC */
	/* !! Must always follow the single channel entry in list */
	{
		LP21002,
		PCI_DEVICE_ID_HORNET,
		PCI_SSDID_LP21002,
		"LP21002",
		"Emulex LP21002 10GE 2-port PCIe FCoE HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_ZEPHYR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x50, 0},
		{0x59, 0x5A, 0x5B, 0x5D, 0x5E, 0x5F, 0},
		{0},
		{0x53, 0x59, 0},
		{0},
		{0x53, 0x59, 0},
		{0},
		{0x58, 0},
		{0}, /* T20 */
	},

	/* Zephyr (Oracle Summit-E1) */
	{
		LPe11000_O,
		PCI_DEVICE_ID_ZEPHYR_O,
		PCI_SSDID_LPe11000_O,
		"LPe11000-S",
		"Emulex LPe11000-S 4Gb 1-port PCIe FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED,
		EMLXS_ZEPHYR_CHIP,
		LPe11000_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0xE3, 0xE8, 0},
		{0xE4, 0},
		{0xE3, 0},
		{0xE3, 0},
		{0},
		{0xE3, 0},
		{0},
		{0xE0, 0},
		{0}, /* T20 */
	},

	/* Zephyr DC (Oracle Summit-E2) */
	/* !! Must always follow the single channel entry in list */
	{
		LPe11002_O,
		PCI_DEVICE_ID_ZEPHYR_O,
		PCI_SSDID_LPe11002_O,
		"LPe11002-S",
		"Emulex LPe11002-S 4Gb 2-port PCIe FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED,
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0xE1, 0xE8, 0},
		{0xE4, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
		{0}, /* T20 */
	},

	/* Zephyr NEM (Oracle Janus) */
	/* !! Must always follow the single channel entry in list */
	{
		LPe11020_O,
		PCI_DEVICE_ID_ZEPHYR_O,
		PCI_SSDID_LPe11020_O,
		"LPe11020-S",
		"Emulex LPe11020-S 4Gb 20-port PCIe FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED,
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0xE1, 0xE8, 0},
		{0xE4, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
		{0}, /* T20 */
	},

	/* Zephyr Express Module (Oracle TitanE) */
	/* !! Must always follow the single channel entry in list */
	{
		LPem11002_O,
		PCI_DEVICE_ID_ZEPHYR_O,
		PCI_SSDID_LPem11002_O,
		"LPem11002-S",
		"Emulex LPem11002-S 4Gb 2-port PCIe FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED,
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0xE1, 0xE8, 0},
		{0xE4, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
		{0}, /* T20 */
	},

	/* Zephyr Express Module (Oracle Elara) */
	/* !! Must always follow the single channel entry in list */
	{
		LPem11002E_O,
		PCI_DEVICE_ID_ZEPHYR_O,
		PCI_SSDID_LPem11002E_O,
		"LPem11002E-S",
		"Emulex LPem11002E-S 4Gb 2-port FC & 2-port 1GE PCIe HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED,
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0xE1, 0xE8, 0},
		{0xE4, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
		{0}, /* T20 */
	},

	/* Zephyr AMC (Oracle Helene/Dione) */
	/* !! Must always follow the single channel entry in list */
	{
		LPeA11002_O,
		PCI_DEVICE_ID_ZEPHYR_O,
		PCI_SSDID_LPeA11002_O,
		"LPeA11002-S",
		"Emulex LPeA11002-S 4Gb 2-port PCIe FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED,
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0xE1, 0xE8, 0},
		{0xE4, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
		{0}, /* T20 */
	},

	/* Saturn */
	{
		LPe12000,
		PCI_DEVICE_ID_SATURN,
		PCI_SSDID_LPe12000,
		"LPe12000",
		"Emulex LPe12000 8Gb 1-port PCIe FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x73, 0x79, 0},
		{0},
		{0x73, 0x79, 0},
		{0},
		{0x78, 0},
		{0}, /* T20 */
	},

	/* Saturn DC */
	/* !! Must always follow the single channel entry in list */
	{
		LPe12002,
		PCI_DEVICE_ID_SATURN,
		PCI_SSDID_LPe12002,
		"LPe12002",
		"Emulex LPe12002 8Gb 2-port PCIe FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x73, 0x79, 0},
		{0},
		{0x73, 0x79, 0},
		{0},
		{0x78, 0},
		{0}, /* T20 */
	},

	/* Saturn (Oracle) */
	{
		LPe12000_O,
		PCI_DEVICE_ID_SATURN_O,
		PCI_SSDID_LPe12000_O,
		"LPe12000-S",
		"Emulex LPe12000-S 8Gb 1-port PCIe FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED |
			EMLXS_E2E_SUPPORTED,
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0x78, 0},
		{0x7C, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
		{0}, /* T20 */
	},

	/* Saturn DC (Oracle) */
	{
		LPe12002_O,
		PCI_DEVICE_ID_SATURN_O,
		PCI_SSDID_LPe12002_O,
		"LPe12002-S",
		"Emulex LPe12002-S 8Gb 2-port PCIe FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED |
			EMLXS_E2E_SUPPORTED,
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x78, 0},
		{0x7C, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
		{0}, /* T20 */
	},

	/* Saturn Express Module (Oracle) */
	{
		LPem12002_O,
		PCI_DEVICE_ID_SATURN_O,
		PCI_SSDID_LPem12002_O,
		"LPem12002-S",
		"Emulex LPem12002-S 8Gb 2-port PCIe FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED |
			EMLXS_E2E_SUPPORTED,
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x78, 0},
		{0x7C, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
		{0}, /* T20 */
	},

	/* Saturn Express Module (Oracle Metis) */
	{
		LPem12002E_O,
		PCI_DEVICE_ID_SATURN_O,
		PCI_SSDID_LPem12002E_O,
		"LPem12002E-S",
		"Emulex LPem12002E-S 8Gb 2-port PCIe FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED |
			EMLXS_E2E_SUPPORTED,
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x78, 0},
		{0x7C, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
		{0}, /* T20 */
	},

	/* Saturn */
	{
		LPe12000_SP,
		PCI_DEVICE_ID_LPe12000_SP,
		PCI_SSDID_LPe12000_SP,
		"LPe12000",
		"Emulex LPe12000 8Gb 1-port PCIe FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_SINGLE_CHANNEL,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
		{0}, /* T20 */
	},

	/* Saturn DC */
	{
		LPe12002_SP,
		PCI_DEVICE_ID_LPe12002_SP,
		PCI_SSDID_LPe12002_SP,
		"LPe12002",
		"Emulex LPe12002 8Gb 2-port PCIe FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI2_MASK | EMLXS_SLI3_MASK,
		EMLXS_MULTI_CHANNEL,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
		{0}, /* T20 */
	},

	/* BE2 (Tigershark) */
	{
		OCe10101,
		PCI_DEVICE_ID_BE2,
		PCI_SSDID_OCe10101,
		"OCe10101",
		"Emulex OneConnect OCe10101 10Gb 1-port FCoE HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_BE2_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_SINGLE_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* BE2 DC (Tigershark) */
	/* !! Must always follow the single channel entry in list */
	{
		OCe10102,
		PCI_DEVICE_ID_BE2,
		PCI_SSDID_OCe10102,
		"OCe10102",
		"Emulex OneConnect OCe10102 10Gb 2-port FCoE HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_BE2_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* BE3 (TomCat) */
	{
		OCe11101,
		PCI_DEVICE_ID_BE3,
		PCI_SSDID_OCe11101,
		"OCe11101",
		"Emulex OneConnect OCe11101 10Gb 1-port FCoE HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_BE3_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_SINGLE_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* BE3 DC (Tomcat) */
	/* !! Must always follow the single channel entry in list */
	{
		OCe11102,
		PCI_DEVICE_ID_BE3,
		PCI_SSDID_OCe11102,
		"OCe11102",
		"Emulex OneConnect OCe11102 10Gb 2-port FCoE HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_BE3_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* Lancer FC (Generic) */
	{
		LPe16000,
		PCI_DEVICE_ID_LANCER_FC,
		PCI_SSDID_LPe16000,
		"LPe16000",
		"Emulex LightPulse LPe16000 16Gb 1-port FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_LANCER_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_SINGLE_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* Lancer FC (Generic Multi-Channel) */
	/* !! Must always follow the single channel entry in list */
	{
		LPe1600X,
		PCI_DEVICE_ID_LANCER_FC,
		PCI_SSDID_LPe1600X,
		"LPe16000",
		"Emulex LightPulse LPe16000 16Gb Multi-port FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_LANCER_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* Lancer FC DC Express Module (Oracle Ganymede) */
	{
		LPem16002_FC_O,
		PCI_DEVICE_ID_LANCER_FC,
		PCI_SSDID_LPem16002_FC_O,
		"LPem16002-M6-O",
		"Emulex LightPulse LPem16002-M6-O 16Gb 2-port FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED |
			EMLXS_E2E_SUPPORTED,
		EMLXS_LANCER_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* Lancer FC DC (Oracle Ganymede) */
	{
		LPe16002_FC_O,
		PCI_DEVICE_ID_LANCER_FC,
		PCI_SSDID_LPe16002_FC_O,
		"LPe16002-M6-O",
		"Emulex LightPulse LPe16002-M6-O 16Gb 2-port FC HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED |
			EMLXS_E2E_SUPPORTED,
		EMLXS_LANCER_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* Lancer FC DC (Oracle Excluded - Spare 1) */
	{
		LPe16002_FC_SP1,
		PCI_DEVICE_ID_LANCER_FC,
		PCI_SSDID_LPe16002_FC_SP1,
		"LPe16002",
		"Emulex LightPulse LPe16002 16Gb 2-port FC HBA",
		"Emulex",
		EMLXS_ORACLE_EXCLUDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED |
			EMLXS_E2E_SUPPORTED,
		EMLXS_LANCER_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* Lancer FC DC (Oracle Excluded - Spare 2) */
	{
		LPe16002_FC_SP2,
		PCI_DEVICE_ID_LANCER_FC,
		PCI_SSDID_LPe16002_FC_SP2,
		"LPe16002",
		"Emulex LightPulse LPe16002 16Gb 2-port FC HBA",
		"Emulex",
		EMLXS_ORACLE_EXCLUDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED |
			EMLXS_E2E_SUPPORTED,
		EMLXS_LANCER_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* Lancer FCOE (Generic) */
	{
		OCe15100,
		PCI_DEVICE_ID_LANCER_FE,
		PCI_SSDID_OCe15100,
		"OCe15100",
		"Emulex OneConnect OCe15100 10Gb 1-port FCoE HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_LANCER_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_SINGLE_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* Lancer FCOE (Generic Multi-Channel) */
	/* !! Must always follow the single channel entry in list */
	{
		OCe1510X,
		PCI_DEVICE_ID_LANCER_FE,
		PCI_SSDID_OCe1510X,
		"OCe15100",
		"Emulex OneConnect OCe15100 10Gb Multi-port FCoE HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_LANCER_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* Lancer FCOE DC Express Module (Oracle Ganymede) */
	{
		LPem16002_FE_O,
		PCI_DEVICE_ID_LANCER_FE,
		PCI_SSDID_LPem16002_FE_O,
		"LPem16002-M6-O",
		"Emulex OneConnect LPem16002-M6-O 10Gb 2-port FCoE HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED |
			EMLXS_E2E_SUPPORTED,
		EMLXS_LANCER_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* Lancer FCOE DC (Oracle Ganymede) */
	{
		LPe16002_FE_O,
		PCI_DEVICE_ID_LANCER_FE,
		PCI_SSDID_LPe16002_FE_O,
		"LPe16002-M6-O",
		"Emulex OneConnect LPe16002-M6-O 10Gb 2-port FCoE HBA",
		"Emulex",
		EMLXS_ORACLE_BRANDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED |
			EMLXS_E2E_SUPPORTED,
		EMLXS_LANCER_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* Lancer FCOE DC (Oracle Excluded - Spare 1) */
	{
		LPe16002_FE_SP1,
		PCI_DEVICE_ID_LANCER_FE,
		PCI_SSDID_LPe16002_FE_SP1,
		"LPe16002",
		"Emulex OneConnect LPe16002 10Gb 2-port FCoE HBA",
		"Emulex",
		EMLXS_ORACLE_EXCLUDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED |
			EMLXS_E2E_SUPPORTED,
		EMLXS_LANCER_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* Lancer FCOE DC (Oracle Excluded - Spare 2) */
	{
		LPe16002_FE_SP2,
		PCI_DEVICE_ID_LANCER_FE,
		PCI_SSDID_LPe16002_FE_SP2,
		"LPe16002",
		"Emulex OneConnect LPe16002 10Gb 2-port FCoE HBA",
		"Emulex",
		EMLXS_ORACLE_EXCLUDED | EMLXS_INTX_SUPPORTED |
			EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED |
			EMLXS_E2E_SUPPORTED,
		EMLXS_LANCER_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

	/* BE4 (Skyhawk) */
	{
		OCe12104,
		PCI_DEVICE_ID_BE4,
		PCI_SSDID_OCe12104,
		"OCe12104",
		"Emulex OneConnect OCe12104 10Gb 2-port FCoE HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
		EMLXS_BE4_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		EMLXS_SLI4_MASK,
		EMLXS_MULTI_CHANNEL,
		NULL_PROG_TYPES,
	},

};	/* emlxs_pci_model[] */

int emlxs_pci_model_count =
	(sizeof (emlxs_pci_model) / sizeof (emlxs_model_t));

#endif	/* EMLXS_MODEL_DEF */

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_ADAPTERS_H */
