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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#ifndef _EMLXS_ADAPTERS_H
#define	_EMLXS_ADAPTERS_H

#ifdef	__cplusplus
extern "C" {
#endif

/* Unique id for each adapter model */
typedef enum emlxs_adapter {
	UNKNOWN_ADAPTER = 0,

	/* Dragon Fly (1) */
	LP8000S,
	LP8000,
	LP8000DC,

	/* Centaur (4) */
	LP9002S,
	LP9002L,
	LP9002C,
	LP9002DC,
	LP9402DC,

	/* Pegasus (9) */
	LP9802,
	LP9802DC,

	/* Thor (11) */
	LP10000,
	LP10000_S,
	LP10000DC,
	LP10000DC_S,
	LP10000ExDC,
	BLADE_2G,

	/* Helios (17) */
	LP11000,
	LP11000_S,
	LP11002,
	LP11002_S,
	LP11000_SP,
	LP11002_SP,

	/* Zephyr (23) */
	LPe11000_M4,
	LPe11000_S,
	LPe11002_M4,
	LPe11002_S,
	LPe1105_HP,
	LPe1105_M,
	LPe1105_M4,

	LPem11002_M4,
	LPem11002_S,
	BX600_FC42E,
	LPe11020_S,
	LPeA11002_S,
	LPe11000_SP,
	LPe11002_SP,
	LPe1105_SP,
	LPem11002E_S,
	LPe11004_M4,

	LP21000_M,
	LP21002_M,
	LP21000_C,
	LP21002_C,

	/* Neptune (44) */
	LPe1000_F4,
	LPe1002_F4,
	LPe1000_SP,
	LPe1002_SP,

	/* Saturn (48) */
	LPe12000_M8,
	LPe12002_M8,
	LPe12000_S,
	LPe12002_S,
	LPe12020_S,
	LPem12002_M8,
	LPem12002_S,
	LPe1205_BC,
	LPe1205_BU,
	LPe1205_M8,
	LPe1205_N,
	LPe1205_HP,
	BX900_FC82E,
	LPe12000_SP,
	LPe12002_SP,
	LPe1205_SP1,
	LPe1205_SP2,
	LPe1205_SP3

} emlxs_adapter_t;

/* Unique id for each firmware image */
/* These will match the generic adapter id */
typedef enum emlxs_firmware {
	FW_NOT_PROVIDED = 0,
	LP10000_FW = LP10000,
	LP11000_FW = LP11000,
	LP11002_FW = LP11002,
	LPe11000_FW = LPe11000_M4,
	LPe11002_FW = LPe11002_M4,
	LPe12000_FW = LPe12000_M8

} emlxs_firmware_t;


#define	PCI_VENDOR_ID_EMULEX		0x10df

/* PCI Device IDs */
#define	PCI_DEVICE_ID_LP8000		0xf800
#define	PCI_DEVICE_ID_LP8000DC		0xf800	/* Identified by VPD PN */
#define	  PCI_SSDID_LP8000		0xf800
#define	  PCI_SSDID_LP8000DC		0xf800

#define	PCI_DEVICE_ID_LP8000S		0xf085	/* Identified by "lpfs" */
						/* driver alias */
#define	  PCI_SSDID_LP8000S		0xf085

#define	PCI_DEVICE_ID_LP9002L		0xf900
#define	PCI_DEVICE_ID_LP9002DC		0xf900	/* Identified by VPD PN */
#define	PCI_DEVICE_ID_LP9002C		0xf900	/* Identified by VPD PN */
#define	PCI_DEVICE_ID_LP9402DC		0xf900	/* Identified by VPD PN */
#define	  PCI_SSDID_LP9002L		0xf900
#define	  PCI_SSDID_LP9002DC		0xf900
#define	  PCI_SSDID_LP9002C		0xf900
#define	  PCI_SSDID_LP9402DC		0xf900

#define	PCI_DEVICE_ID_LP9002S		0xf095	/* Identified by "lpfs" */
						/* driver alias */
#define	  PCI_SSDID_LP9002S		0xf095

#define	PCI_DEVICE_ID_LP9802		0xf980
#define	PCI_DEVICE_ID_LP9802DC		0xf980	/* Identified by RAM size */
#define	  PCI_SSDID_LP9802		0xf980
#define	  PCI_SSDID_LP9802DC		0xf980

#define	PCI_DEVICE_ID_LP10000		0xfa00
#define	PCI_DEVICE_ID_LP10000DC		0xfa00	/* Identified by VPD PN and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LP10000ExDC	0xfa00	/* Identified by VPD PN and */
						/* cache_line reg */
#define	  PCI_SSDID_LP10000		0xfa00
#define	  PCI_SSDID_LP10000DC		0xfa00
#define	  PCI_SSDID_LP10000ExDC		0xfa00

#define	PCI_DEVICE_ID_BLADE_2G		0xf0a5
#define	  PCI_SSDID_BLADE_2G		0xf0a5

#define	PCI_DEVICE_ID_LP11000		0xfd00
#define	PCI_DEVICE_ID_LP11002		0xfd00	/* Identified by cache_line */
						/* reg */
#define	  PCI_SSDID_LP11000		0xfd00
#define	  PCI_SSDID_LP11002		0xfd00

#define	PCI_DEVICE_ID_LPe11000_M4	0xfe00
#define	PCI_DEVICE_ID_LPe11002_M4	0xfe00	/* Identified cache_line reg */
#define	PCI_DEVICE_ID_LPe11004_M4	0xfe00	/* Unable to differentiate */
						/* from LPe11002 */
#define	PCI_DEVICE_ID_LPe1105_HP	0xfe00	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPe1105_M		0xfe00	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPe1105_M4	0xfe00	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_BX600_FC42E	0xfe00	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPem11002_M4	0xfe00	/* Identified by SSDID and */
						/* cache_line reg */
#define	  PCI_SSDID_LPe11000_M4		0xfe00
#define	  PCI_SSDID_LPe11002_M4		0xfe00
#define	  PCI_SSDID_LPe11004_M4		0xfe00
#define	  PCI_SSDID_LPe1105_HP		0x1708
#define	  PCI_SSDID_LPe1105_M		0xfe22
#define	  PCI_SSDID_BX600_FC42E		0xfe23
#define	  PCI_SSDID_LPe1105_M4		0xfe24
#define	  PCI_SSDID_LPem11002_M4	0xfe2e

#define	PCI_DEVICE_ID_LP21000_M		0xfe05
#define	PCI_DEVICE_ID_LP21002_M		0xfe05	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LP21000_C		0xfe05	/* Unable to differentiate */
						/* from LP21000_M */
#define	PCI_DEVICE_ID_LP21002_C		0xfe05	/* Unable to differentiate */
						/* from LP21002_M */
#define	  PCI_SSDID_LP21000_M		0xfe05
#define	  PCI_SSDID_LP21002_M		0xfe05
#define	  PCI_SSDID_LP21000_C		0xfe05
#define	  PCI_SSDID_LP21002_C		0xfe05

#define	PCI_DEVICE_ID_LPe1000_F4	0xf0f5
#define	PCI_DEVICE_ID_LPe1002_F4	0xf0f5	/* Identified by cache_line */
						/* reg */
#define	  PCI_SSDID_LPe1000_F4		0xf0f5
#define	  PCI_SSDID_LPe1002_F4		0xf0f5

#define	PCI_DEVICE_ID_LPe12000_M8	0xf100
#define	PCI_DEVICE_ID_LPe12002_M8	0xf100	/* Identified cache_line reg */
#define	PCI_DEVICE_ID_LPem12002_M8	0xf100	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPe1205_BC	0xf100	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPe1205_BU	0xf100	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPe1205_M8	0xf100	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPe1205_N		0xf100	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPe1205_HP	0xf100	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_BX900_FC82E	0xf100	/* Identified by SSDID and */
						/* cache_line reg */
#define	  PCI_SSDID_LPe12000_M8		0xf100
#define	  PCI_SSDID_LPe12002_M8		0xf100
#define	  PCI_SSDID_LPem12002_M8	0xf12e
#define	  PCI_SSDID_LPe1205_BC		0xf124
#define	  PCI_SSDID_LPe1205_BU		0xf125
#define	  PCI_SSDID_LPe1205_M8		0xf126
#define	  PCI_SSDID_LPe1205_N		0xf127
#define	  PCI_SSDID_LPe1205_HP		0x1719
#define	  PCI_SSDID_BX900_FC82E		0x113c


/* Sun branded adapters */
#define	PCI_DEVICE_ID_LP10000_S		0xfc00
#define	PCI_DEVICE_ID_LP10000DC_S	0xfc00	/* Identified by cache_line */
						/* reg */
#define	  PCI_SSDID_LP10000_S		0xfc00
#define	  PCI_SSDID_LP10000DC_S		0xfc00

#define	PCI_DEVICE_ID_LP11000_S		0xfc10
#define	PCI_DEVICE_ID_LP11002_S		0xfc10	/* Identified by SSDID and */
						/* cache_line reg */
#define	  PCI_SSDID_LP11000_S		0xfc11
#define	  PCI_SSDID_LP11002_S		0xfc12

#define	PCI_DEVICE_ID_LPe11000_S	0xfc20
#define	PCI_DEVICE_ID_LPe11002_S	0xfc20	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPe11020_S	0xfc20	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPeA11002_S	0xfc20	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPem11002_S	0xfc20	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPem11002E_S	0xfc20	/* Identified by SSDID and */
						/* cache_line reg */
#define	  PCI_SSDID_LPe11000_S		0xfc21
#define	  PCI_SSDID_LPe11002_S		0xfc22
#define	  PCI_SSDID_LPem11002E_S	0xfc23
#define	  PCI_SSDID_LPe11020_S		0xfc2a
#define	  PCI_SSDID_LPeA11002_S		0xfc2d
#define	  PCI_SSDID_LPem11002_S		0xfc2e

#define	PCI_DEVICE_ID_LPe12000_S	0xfc40
#define	PCI_DEVICE_ID_LPe12002_S	0xfc40	/* Identified cache_line reg */
#define	PCI_DEVICE_ID_LPem12002_S	0xfc40	/* Identified by SSDID and */
						/* cache_line reg */
#define	PCI_DEVICE_ID_LPe12020_S	0xfc40	/* Identified by SSDID and */
						/* cache_line reg */
#define	  PCI_SSDID_LPe12000_S		0xfc41
#define	  PCI_SSDID_LPe12002_S		0xfc42
#define	  PCI_SSDID_LPe12020_S		0xfc4a
#define	  PCI_SSDID_LPem12002_S		0xfc4e


/* Spare IDs */
#define	PCI_DEVICE_ID_LPe1000_SP	0xf0f6
#define	  PCI_SSDID_LPe1000_SP		0xf0f6

#define	PCI_DEVICE_ID_LPe1002_SP	0xf0f7
#define	  PCI_SSDID_LPe1002_SP		0xf0f7

#define	PCI_DEVICE_ID_LP11000_SP	0xfd11
#define	  PCI_SSDID_LP11000_SP		0xfd11

#define	PCI_DEVICE_ID_LP11002_SP	0xfd12
#define	  PCI_SSDID_LP11002_SP		0xfd12

#define	PCI_DEVICE_ID_LPe1105_SP	0xfe25
#define	  PCI_SSDID_LPe1105_SP		0xfe25

#define	PCI_DEVICE_ID_LPe11000_SP	0xfe11
#define	  PCI_SSDID_LPe11000_SP		0xfe11

#define	PCI_DEVICE_ID_LPe11002_SP	0xfe12
#define	  PCI_SSDID_LPe11002_SP		0xfe12

#define	PCI_DEVICE_ID_LPe12000_SP	0xf111
#define	PCI_DEVICE_ID_LPe12002_SP	0xf112
#define	  PCI_SSDID_LPe12000_SP		0xf111
#define	  PCI_SSDID_LPe12002_SP		0xf112

#define	PCI_DEVICE_ID_LPe1205_SP1	0xf100
#define	PCI_DEVICE_ID_LPe1205_SP2	0xf100
#define	PCI_DEVICE_ID_LPe1205_SP3	0xf100
#define	  PCI_SSDID_LPe1205_SP1		0xf12a
#define	  PCI_SSDID_LPe1205_SP2		0xf12b
#define	  PCI_SSDID_LPe1205_SP3		0xf12c


/* JEDEC codes */
#define	FIREFLY_JEDEC_ID		0x1ACC
#define	SUPERFLY_JEDEC_ID		0x0020
#define	DRAGONFLY_JEDEC_ID		0x0021
#define	DRAGONFLY_V2_JEDEC_ID		0x0025
#define	CENTAUR_2G_JEDEC_ID		0x0026
#define	CENTAUR_1G_JEDEC_ID		0x0028
#define	HELIOS_4G_JEDEC_ID		0x0364
#define	ZEPHYR_4G_JEDEC_ID		0x0577
#define	NEPTUNE_4G_JEDEC_ID		0x0510
#define	SATURN_8G_JEDEC_ID		0x1004
#define	JEDEC_ID_MASK			0x0FFFF000
#define	JEDEC_ID_SHIFT			12
#define	FC_JEDEC_ID(id)			((id & JEDEC_ID_MASK) >> JEDEC_ID_SHIFT)



typedef struct emlxs_model {
	emlxs_adapter_t id;
	uint16_t device_id;
	uint16_t ssdid;

	char model[32];
	char model_desc[80];
	char manufacturer[80];
	uint32_t flags;

	/* flags */
#define	EMLXS_INTX_SUPPORTED		0x00000001
#define	EMLXS_MSI_SUPPORTED		0x00000002
#define	EMLXS_MSIX_SUPPORTED		0x00000004
#define	EMLXS_E2E_SUPPORTED		0x00000010 /* End-to-end auth */
#define	EMLXS_SUN_BRANDED		0x10000000
#define	EMLXS_NOT_SUPPORTED		0x80000000

	uint32_t chip;

	/* chip */
#define	EMLXS_UNKNOWN_CHIP		0x00000000
#define	EMLXS_DRAGONFLY_CHIP		0x00000001
#define	EMLXS_CENTAUR_CHIP		0x00000002
#define	EMLXS_PEGASUS_CHIP		0x00000004
#define	EMLXS_THOR_CHIP			0x00000008
#define	EMLXS_HELIOS_CHIP		0x00000010
#define	EMLXS_ZEPHYR_CHIP		0x00000020
#define	EMLXS_NEPTUNE_CHIP		0x00000040
#define	EMLXS_SATURN_CHIP		0x00000080

	emlxs_firmware_t fwid;
	uint32_t intr_limit;

#define	EMLXS_INTR_NO_LIMIT		0x00000000
#define	EMLXS_INTR_LIMIT1		0x00000001
#define	EMLXS_INTR_LIMIT2		0x00000002
#define	EMLXS_INTR_LIMIT4		0x00000004
#define	EMLXS_INTR_LIMIT8		0x00000008
#define	EMLXS_INTR_LIMIT16		0x00000010

	uint32_t channels;
	uint8_t pt_2[8];
	uint8_t pt_3[8];
	uint8_t pt_6[8];
	uint8_t pt_7[8];
	uint8_t pt_A[8];
	uint8_t pt_B[8];
	uint8_t pt_E[8];
	uint8_t pt_FF[8];

} emlxs_model_t;

typedef struct emlxs_image {
	emlxs_firmware_t id;
	char *label;
	uint8_t *buffer;
	uint32_t size;
	uint32_t kern;
	uint32_t stub;
	uint32_t sli1;
	uint32_t sli2;
	uint32_t sli3;
	uint32_t sli4;

} emlxs_image_t;

extern emlxs_image_t emlxs_fw_image[];


#ifdef EMLXS_MODEL_DEF

/* Define the firmware image database */
#include <fw_lp10000.h>
#include <fw_lp11000.h>
#include <fw_lp11002.h>

#ifdef S10S11
#include <fw_lpe11000.h>
#include <fw_lpe11002.h>
#include <fw_lpe12000.h>
#endif	/* S10S11 */

emlxs_image_t emlxs_fw_image[] = {

	/* LP10000 */
	{
		LP10000_FW,
		emlxs_lp10000_fw,
		emlxs_lp10000_image,
		emlxs_lp10000_size,
		emlxs_lp10000_kern,
		emlxs_lp10000_stub,
		emlxs_lp10000_sli1,
		emlxs_lp10000_sli2,
		emlxs_lp10000_sli3,
		0
	},

	/* LP11000 */
	{
		LP11000_FW,
		emlxs_lp11000_fw,
		emlxs_lp11000_image,
		emlxs_lp11000_size,
		emlxs_lp11000_kern,
		emlxs_lp11000_stub,
		emlxs_lp11000_sli1,
		emlxs_lp11000_sli2,
		emlxs_lp11000_sli3,
		0
	},

	/* LP11002 */
	{
		LP11002_FW,
		emlxs_lp11002_fw,
		emlxs_lp11002_image,
		emlxs_lp11002_size,
		emlxs_lp11002_kern,
		emlxs_lp11002_stub,
		emlxs_lp11002_sli1,
		emlxs_lp11002_sli2,
		emlxs_lp11002_sli3,
		0
	},

#ifdef S10S11
	/* LPe11000 */
	{
		LPe11000_FW,
		emlxs_lpe11000_fw,
		emlxs_lpe11000_image,
		emlxs_lpe11000_size,
		emlxs_lpe11000_kern,
		emlxs_lpe11000_stub,
		emlxs_lpe11000_sli1,
		emlxs_lpe11000_sli2,
		emlxs_lpe11000_sli3,
		0
	},

	/* LPe11002 */
	{
		LPe11002_FW,
		emlxs_lpe11002_fw,
		emlxs_lpe11002_image,
		emlxs_lpe11002_size,
		emlxs_lpe11002_kern,
		emlxs_lpe11002_stub,
		emlxs_lpe11002_sli1,
		emlxs_lpe11002_sli2,
		emlxs_lpe11002_sli3,
		0
	},

	/* LPe12000 */
	{
		LPe12000_FW,
		emlxs_lpe12000_fw,
		emlxs_lpe12000_image,
		emlxs_lpe12000_size,
		emlxs_lpe12000_kern,
		emlxs_lpe12000_stub,
		emlxs_lpe12000_sli1,
		emlxs_lpe12000_sli2,
		emlxs_lpe12000_sli3,
		0
	},
#endif	/* S10S11 */

	/* NULL Terminated list */
	{
		UNKNOWN_ADAPTER,
		NULL,
		NULL,
		0,
		0,
		0,
		0,
		0,
		0,
		0
	},

}; /* emlxs_fw_image[] */

#define	EMLXS_IMAGE_COUNT \
	((sizeof (emlxs_fw_image) / sizeof (emlxs_image_t)) - 1)



/* Define the SBUS adapter database */
emlxs_model_t emlxs_sbus_model[] = {

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
		0,
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
	},

	/* Dragonfly midrange (QFLY) */
	{
		LP8000S,
		PCI_DEVICE_ID_LP8000S,
		PCI_SSDID_LP8000S,
		"LP8000S",
		"Emulex LP8000S 1Gb 1-port SBUS FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_DRAGONFLY_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		1,
		{0x21, 0xB0, 0},
		{0},
		{0x31, 0},
		{0x31, 0x39, 0},
		{0x01, 0},
		{0},
		{0},
		{0x30, 0},
	},

	/* Centaur mid-range (RFLY, Rtaur) */
	{
		LP9002S,
		PCI_DEVICE_ID_LP9002S,
		PCI_SSDID_LP9002S,
		"LP9002S",
		"Emulex LP9002S 2Gb 1-port SBUS FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_CENTAUR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		1,
		{0x41, 0xD0, 0},
		{0},
		{0x51, 0},
		{0x51, 0},
		{0x02, 0},
		{0},
		{0},
		{0x50, 0},
	},


};	/* emlxs_sbus_model[] */

#define	EMLXS_SBUS_MODEL_COUNT \
	(sizeof (emlxs_sbus_model) / sizeof (emlxs_model_t))


/* Define the PCI adapter database */
emlxs_model_t emlxs_pci_model[] = {

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
		0,
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
	},

	/* Dragonfly */
	{
		LP8000,
		PCI_DEVICE_ID_LP8000,
		PCI_SSDID_LP8000,
		"LP8000",
		"Emulex LP8000 1Gb 1-port PCI FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_DRAGONFLY_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		1,
		{0x21, 0x22, 0x23, 0xA0, 0},
		{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0},
		{0x21, 0x22, 0x23, 0},
		{0x21, 0x22, 0x23, 0},
		{0},
		{0},
		{0},
		{0x20, 0},
	},

	/* Dragonfly DC */
	/* !! Must always follow the single channel entry in list */
	{
		LP8000DC,
		PCI_DEVICE_ID_LP8000DC,
		PCI_SSDID_LP8000DC,
		"LP8000DC",
		"Emulex LP8000DC 1Gb 2-port PCI FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_DRAGONFLY_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		2,
		{0x21, 0x22, 0x23, 0xA0, 0},
		{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0},
		{0x21, 0x22, 0x23, 0},
		{0x21, 0x22, 0x23, 0},
		{0},
		{0},
		{0},
		{0x20, 0},
	},

	/* Centaur PCI */
	{
		LP9002L,
		PCI_DEVICE_ID_LP9002L,
		PCI_SSDID_LP9002L,
		"LP9002L",
		"Emulex LP9002L 2Gb 1-port PCI FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_CENTAUR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		1,
		{0x41, 0x43, 0xC0, 0},
		{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0},
		{0x41, 0x43, 0},
		{0x41, 0x43, 0},
		{0},
		{0},
		{0},
		{0x40, 0},
	},

	/* Centaur cPCI */
	{
		LP9002C,
		PCI_DEVICE_ID_LP9002C,
		PCI_SSDID_LP9002C,
		"LP9002C",
		"Emulex LP9002C 2Gb 1-port cPCI FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_CENTAUR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		1,
		{0x41, 0x43, 0xC0, 0},
		{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0},
		{0x41, 0x43, 0},
		{0x41, 0x43, 0},
		{0},
		{0},
		{0},
		{0x40, 0},
	},

	/* Centaur DC PCI */
	/* !! Must always follow the single channel entry in list */
	{
		LP9002DC,
		PCI_DEVICE_ID_LP9002DC,
		PCI_SSDID_LP9002DC,
		"LP9002DC",
		"Emulex LP9002DC 2Gb 2-port PCI FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_CENTAUR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		2,
		{0x41, 0x43, 0xC0, 0},
		{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0},
		{0x41, 0x43, 0},
		{0x41, 0x43, 0},
		{0},
		{0},
		{0},
		{0x40, 0},
	},

	/* Centaur DC PCI-X */
	/* !! Must always follow the single channel entry in list */
	{
		LP9402DC,
		PCI_DEVICE_ID_LP9402DC,
		PCI_SSDID_LP9402DC,
		"LP9402DC",
		"Emulex LP9402DC 2Gb 2-port PCI-X FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_CENTAUR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		2,
		{0x41, 0x43, 0xC0, 0},
		{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0},
		{0x41, 0x43, 0},
		{0x41, 0x43, 0},
		{0},
		{0},
		{0},
		{0x40, 0},
	},

	/* Pegasus */
	{
		LP9802,
		PCI_DEVICE_ID_LP9802,
		PCI_SSDID_LP9802,
		"LP9802",
		"Emulex LP9802 2Gb 1-port PCI-X FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_PEGASUS_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		1,
		{0x63, 0xE0, 0},
		{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0},
		{0x63, 0},
		{0x63, 0},
		{0},
		{0x63, 0},
		{0},
		{0x60, 0},
	},

	/* Pegasus DC */
	/* !! Must always follow the single channel entry in list */
	{
		LP9802DC,
		PCI_DEVICE_ID_LP9802DC,
		PCI_SSDID_LP9802DC,
		"LP9802DC",
		"Emulex LP9802DC 2Gb 2-port PCI-X FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED,
		EMLXS_PEGASUS_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		2,
		{0x61, 0xE0, 0},
		{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0},
		{0x61, 0},
		{0x61, 0},
		{0},
		{0x61, 0},
		{0},
		{0x60, 0},
	},

	/* Thor */
	{
		LP10000,
		PCI_DEVICE_ID_LP10000,
		PCI_SSDID_LP10000,
		"LP10000",
		"Emulex LP10000 2Gb 1-port PCI-X FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_THOR_CHIP,
		LP10000_FW,
		EMLXS_INTR_LIMIT1,
		1,
		{0x81, 0x83, 0x88, 0},
		{0x81, 0x82, 0x83, 0x85, 0x86, 0x87, 0},
		{0x81, 0x83, 0},
		{0x81, 0x83, 0},
		{0},
		{0x81, 0x83, 0},
		{0},
		{0x80, 0},
	},

	/* Thor DC */
	/* !! Must always follow the single channel entry in list */
	{
		LP10000DC,
		PCI_DEVICE_ID_LP10000DC,
		PCI_SSDID_LP10000DC,
		"LP10000DC",
		"Emulex LP10000DC 2Gb 2-port PCI-X FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_THOR_CHIP,
		LP10000_FW,
		EMLXS_INTR_LIMIT1,
		2,
		{0x81, 0x83, 0x88, 0},
		{0x81, 0x82, 0x83, 0x85, 0x86, 0x87, 0},
		{0x81, 0x83, 0},
		{0x81, 0x83, 0},
		{0},
		{0x81, 0x83, 0},
		{0},
		{0x80, 0},
	},

	/* Thor DC express */
	/* !! Must always follow the single channel entry in list */
	{
		LP10000ExDC,
		PCI_DEVICE_ID_LP10000ExDC,
		PCI_SSDID_LP10000ExDC,
		"LP10000ExDC",
		"Emulex LP10000ExDC 2Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_THOR_CHIP,
		LP10000_FW,
		EMLXS_INTR_LIMIT1,
		2,
		{0x81, 0x83, 0x88, 0},
		{0x81, 0x82, 0x83, 0x85, 0x86, 0x87, 0},
		{0x81, 0x83, 0},
		{0x81, 0x83, 0},
		{0},
		{0x81, 0x83, 0},
		{0},
		{0x80, 0},
	},

	/* Thor (Sun Rainbow-E1) */
	{
		LP10000_S,
		PCI_DEVICE_ID_LP10000_S,
		PCI_SSDID_LP10000_S,
		"LP10000-S",
		"Emulex LP10000-S 2Gb 1-port PCI-X FC HBA",
		"Emulex",
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_THOR_CHIP,
		LP10000_FW,
		EMLXS_INTR_LIMIT1,
		1,
		{0x83, 0x88, 0},
		{0x82, 0x84, 0},
		{0x83, 0},
		{0x83, 0},
		{0},
		{0x83, 0},
		{0},
		{0x80, 0},
	},

	/* Thor DC (Sun Rainbow-E2) */
	/* !! Must always follow the single channel entry in list */
	{
		LP10000DC_S,
		PCI_DEVICE_ID_LP10000DC_S,
		PCI_SSDID_LP10000DC_S,
		"LP10000DC-S",
		"Emulex LP10000DC-S 2Gb 2-port PCI-X FC HBA",
		"Emulex",
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_THOR_CHIP,
		LP10000_FW,
		EMLXS_INTR_LIMIT1,
		2,
		{0x83, 0x88, 0},
		{0x82, 0x84, 0},
		{0x83, 0},
		{0x83, 0},
		{0},
		{0x83, 0},
		{0},
		{0x80, 0},
	},

	/* Thor mid-range (MiniThor) */
	{
		BLADE_2G,
		PCI_DEVICE_ID_BLADE_2G,
		PCI_SSDID_BLADE_2G,
		"2G Blade Adapter",
		"Emulex 2G 2-port Blade PCI-X FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_THOR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_LIMIT1,
		2,
		{0x98, 0},
		{0x91, 0x92, 0x93, 0x95, 0x96, 0x97, 0},
		{0x91, 0},
		{0x91, 0},
		{0},
		{0x91, 0},
		{0},
		{0x90, 0},
	},

	/* Helios */
	{
		LP11000,
		PCI_DEVICE_ID_LP11000,
		PCI_SSDID_LP11000,
		"LP11000",
		"Emulex LP11000 4Gb 1-port PCI-X2 FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_HELIOS_CHIP,
		LP11000_FW,
		EMLXS_INTR_LIMIT1,
		1,
		{0xC3, 0xC8, 0},
		{0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0},
		{0xC3, 0},
		{0xC3, 0},
		{0},
		{0xC3, 0},
		{0},
		{0xC0, 0},
	},

	/* Helios DC */
	/* !! Must always follow the single channel entry in list */
	{
		LP11002,
		PCI_DEVICE_ID_LP11002,
		PCI_SSDID_LP11002,
		"LP11002",
		"Emulex LP11002 4Gb 2-port PCI-X2 FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_HELIOS_CHIP,
		LP11002_FW,
		EMLXS_INTR_LIMIT1,
		2,
		{0xC1, 0xC8, 0},
		{0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0},
		{0xC1, 0},
		{0xC1, 0},
		{0},
		{0xC1, 0},
		{0},
		{0xC0, 0},
	},

	/* Helios (Sun Pyramid-E1) */
	{
		LP11000_S,
		PCI_DEVICE_ID_LP11000_S,
		PCI_SSDID_LP11000_S,
		"LP11000-S",
		"Emulex LP11000-S 4Gb 1-port PCI-X2 FC HBA",
		"Emulex",
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_HELIOS_CHIP,
		LP11000_FW,
		EMLXS_INTR_LIMIT1,
		1,
		{0xC3, 0xC8, 0},
		{0xC4, 0},
		{0xC3, 0},
		{0xC3, 0},
		{0},
		{0xC3, 0},
		{0},
		{0xC0, 0},
	},

	/* Helios DC (Sun Pyramid-E2) */
	/* !! Must always follow the single channel entry in list */
	{
		LP11002_S,
		PCI_DEVICE_ID_LP11002_S,
		PCI_SSDID_LP11002_S,
		"LP11002-S",
		"Emulex LP11002-S 4Gb 2-port PCI-X2 FC HBA",
		"Emulex",
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_HELIOS_CHIP,
		LP11002_FW,
		EMLXS_INTR_LIMIT1,
		2,
		{0xC1, 0xC8, 0},
		{0xC4, 0},
		{0xC1, 0},
		{0xC1, 0},
		{0},
		{0xC1, 0},
		{0},
		{0xC0, 0},
	},

	/* Zephyr  */
	{
		LPe11000_M4,
		PCI_DEVICE_ID_LPe11000_M4,
		PCI_SSDID_LPe11000_M4,
		"LPe11000-M4",
		"Emulex LPe11000-M4 4Gb 1-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11000_FW,
		EMLXS_INTR_NO_LIMIT,
		1,
		{0xE3, 0xE8, 0},
		{0xE1, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7, 0},
		{0xE3, 0},
		{0xE3, 0},
		{0},
		{0xE3, 0},
		{0},
		{0xE0, 0},
	},

	/* Zephyr DC */
	/* !! Must always follow the single channel entry in list */
	{
		LPe11002_M4,
		PCI_DEVICE_ID_LPe11002_M4,
		PCI_SSDID_LPe11002_M4,
		"LPe11002-M4",
		"Emulex LPe11002-M4 4Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE1, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},


	/* Zephyr DC Blade */
	/* !! Must always follow the single channel entry in list */
	{
		LPe1105_M,
		PCI_DEVICE_ID_LPe1105_M,
		PCI_SSDID_LPe1105_M,
		"LPe1105-M",
		"Emulex LPe1105-M 2Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE1, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},


	/* FSC Zephyr DC Blade */
	/* !! Must always follow the single channel entry in list */
	{
		BX600_FC42E,
		PCI_DEVICE_ID_BX600_FC42E,
		PCI_SSDID_BX600_FC42E,
		"BX600-FC42E",
		"Emulex BX600-FC42E 4Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE1, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},

	/* HP Zephyr DC Blade */
	/* !! Must always follow the single channel entry in list */
	{
		LPe1105_HP,
		PCI_DEVICE_ID_LPe1105_HP,
		PCI_SSDID_LPe1105_HP,
		"LPe1105-HP",
		"Emulex LPe1105-HP 4Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE1, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},


	/* Dell Zephyr DC Blade */
	/* !! Must always follow the single channel entry in list */
	{
		LPe1105_M4,
		PCI_DEVICE_ID_LPe1105_M4,
		PCI_SSDID_LPe1105_M4,
		"LPe1105-M4",
		"Dell LPe1105-M4 4Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE1, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},

	/* Zephyr Express Module */
	/* !! Must always follow the single channel entry in list */
	{
		LPem11002_M4,
		PCI_DEVICE_ID_LPem11002_M4,
		PCI_SSDID_LPem11002_M4,
		"LPem11002-M4",
		"Emulex LPem11002-M4 4Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE1, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},

	/* Zephyr (Hornet) */
	{
		LP21000_M,
		PCI_DEVICE_ID_LP21000_M,
		PCI_SSDID_LP21000_M,
		"LP21000-M",
		"Emulex LP21000_M 10GE 1-port PCIe FCoE HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		1,
		{0x50, 0},
		{0x59, 0x5A, 0x5B, 0x5D, 0x5E, 0x5F, 0},
		{0},
		{0x53, 0},
		{0},
		{0x53, 0},
		{0},
		{0x58, 0},
	},

	/* Zephyr (Hornet Copper) */
	{
		LP21000_C,
		PCI_DEVICE_ID_LP21000_C,
		PCI_SSDID_LP21000_C,
		"LP21000-C",
		"Emulex LP21000_C 10GE 1-port PCIe FCoE HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		1,
		{0x50, 0},
		{0x59, 0x5A, 0x5B, 0x5D, 0x5E, 0x5F, 0},
		{0},
		{0x53, 0},
		{0},
		{0x53, 0},
		{0},
		{0x58, 0},
	},

	/* Zephyr DC (Hornet) */
	{
		LP21002_M,
		PCI_DEVICE_ID_LP21002_M,
		PCI_SSDID_LP21002_M,
		"LP21002-M",
		"Emulex LP21002_M 10GE 2-port PCIe FCoE HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x50, 0},
		{0x59, 0x5A, 0x5B, 0x5D, 0x5E, 0x5F, 0},
		{0},
		{0x59, 0},
		{0},
		{0x59, 0},
		{0},
		{0x58, 0},
	},

	/* Zephyr DC (Hornet Copper) */
	{
		LP21002_C,
		PCI_DEVICE_ID_LP21002_C,
		PCI_SSDID_LP21002_C,
		"LP21002-C",
		"Emulex LP21002_C 10GE 2-port PCIe FCoE HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x50, 0},
		{0x59, 0x5A, 0x5B, 0x5D, 0x5E, 0x5F, 0},
		{0},
		{0x59, 0},
		{0},
		{0x59, 0},
		{0},
		{0x58, 0},
	},

	/* Zephyr (Sun Summit-E1) */
	{
		LPe11000_S,
		PCI_DEVICE_ID_LPe11000_S,
		PCI_SSDID_LPe11000_S,
		"LPe11000-S",
		"Emulex LPe11000-S 4Gb 1-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11000_FW,
		EMLXS_INTR_NO_LIMIT,
		1,
		{0xE3, 0xE8, 0},
		{0xE4, 0},
		{0xE3, 0},
		{0xE3, 0},
		{0},
		{0xE3, 0},
		{0},
		{0xE0, 0},
	},

	/* Zephyr DC (Sun Summit-E2) */
	/* !! Must always follow the single channel entry in list */
	{
		LPe11002_S,
		PCI_DEVICE_ID_LPe11002_S,
		PCI_SSDID_LPe11002_S,
		"LPe11002-S",
		"Emulex LPe11002-S 4Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE4, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},

	/* Zephyr NEM (Sun Janus) */
	/* !! Must always follow the single channel entry in list */
	{
		LPe11020_S,
		PCI_DEVICE_ID_LPe11020_S,
		PCI_SSDID_LPe11020_S,
		"LPe11020-S",
		"Emulex LPe11020-S 4Gb 20-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE4, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},

	/* Zephyr Express Module (Sun TitanE) */
	/* !! Must always follow the single channel entry in list */
	{
		LPem11002_S,
		PCI_DEVICE_ID_LPem11002_S,
		PCI_SSDID_LPem11002_S,
		"LPem11002-S",
		"Emulex LPem11002-S 4Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE4, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},

	/* Zephyr Express Module (Sun Elara) */
	/* !! Must always follow the single channel entry in list */
	{
		LPem11002E_S,
		PCI_DEVICE_ID_LPem11002E_S,
		PCI_SSDID_LPem11002E_S,
		"LPem11002E-S",
		"Emulex LPem11002E-S 4Gb 2-port FC & 2-port 1GE PCIe HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE4, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},

	/* Zephyr AMC (Sun Helene/Dione) */
	/* !! Must always follow the single channel entry in list */
	{
		LPeA11002_S,
		PCI_DEVICE_ID_LPeA11002_S,
		PCI_SSDID_LPeA11002_S,
		"LPeA11002-S",
		"Emulex LPeA11002-S 4Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE4, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},

	/* Neptune  */
	{
		LPe1000_F4,
		PCI_DEVICE_ID_LPe1000_F4,
		PCI_SSDID_LPe1000_F4,
		"LPe1000-F4",
		"Emulex LPe1000 4Gb 1-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_NEPTUNE_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		1,
		{0x38, 0},
		{0x39, 0x3A, 0x3B, 0x3D, 0x3E, 0x3F, 0},
		{0x32, 0},
		{0x32, 0},
		{0},
		{0x32, 0},
		{0},
		{0x38, 0},
	},

	/* Neptune DC  */
	{
		LPe1002_F4,
		PCI_DEVICE_ID_LPe1002_F4,
		PCI_SSDID_LPe1002_F4,
		"LPe1002-F4",
		"Emulex LPe1002-F4 4Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_NEPTUNE_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x38, 0},
		{0x39, 0x3A, 0x3B, 0x3D, 0x3E, 0x3F, 0},
		{0x32, 0},
		{0x32, 0},
		{0},
		{0x32, 0},
		{0},
		{0x38, 0},
	},

	/* Saturn */
	{
		LPe12000_M8,
		PCI_DEVICE_ID_LPe12000_M8,
		PCI_SSDID_LPe12000_M8,
		"LPe12000-M8",
		"Emulex LPe12000-M8 8Gb 1-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		1,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
	},

	/* Saturn DC */
	{
		LPe12002_M8,
		PCI_DEVICE_ID_LPe12002_M8,
		PCI_SSDID_LPe12002_M8,
		"LPe12002-M8",
		"Emulex LPe12002-M8 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
	},

	/* Saturn Express Module */
	{
		LPem12002_M8,
		PCI_DEVICE_ID_LPem12002_M8,
		PCI_SSDID_LPem12002_M8,
		"LPem12002-M8",
		"Emulex LPem12002-M8 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
	},


	/* IBM Saturn Blade (CFF) */
	{
		LPe1205_BC,
		PCI_DEVICE_ID_LPe1205_BC,
		PCI_SSDID_LPe1205_BC,
		"LPe1205-BC",
		"IBM LPe1205-BC 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x79, 0},
		{0},
		{0x79, 0},
		{0},
		{0x78, 0},
	},

	/* Saturn Blade Universal (CFF) */
	{
		LPe1205_BU,
		PCI_DEVICE_ID_LPe1205_BU,
		PCI_SSDID_LPe1205_BU,
		"LPe1205-BU",
		"Emulex LPe1205-BU 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x79, 0},
		{0},
		{0x79, 0},
		{0},
		{0x78, 0},
	},

	/* Dell Saturn Blade DC */
	{
		LPe1205_M8,
		PCI_DEVICE_ID_LPe1205_M8,
		PCI_SSDID_LPe1205_M8,
		"LPe1205-M8",
		"Dell LPe1205-M8 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x79, 0},
		{0},
		{0x79, 0},
		{0},
		{0x78, 0},
	},

	/* NEC Saturn Blade DC */
	{
		LPe1205_N,
		PCI_DEVICE_ID_LPe1205_N,
		PCI_SSDID_LPe1205_N,
		"LPe1205-N",
		"NEC LPe1205-N 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x79, 0},
		{0},
		{0x79, 0},
		{0},
		{0x78, 0},
	},

	/* HP Saturn Blade DC */
	{
		LPe1205_HP,
		PCI_DEVICE_ID_LPe1205_HP,
		PCI_SSDID_LPe1205_HP,
		"LPe1205-HP",
		"HP LPe1205-HP 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x79, 0},
		{0},
		{0x79, 0},
		{0},
		{0x78, 0},
	},

	/* FSC Saturn Blade DC */
	{
		BX900_FC82E,
		PCI_DEVICE_ID_BX900_FC82E,
		PCI_SSDID_BX900_FC82E,
		"BX900-FC82E",
		"FSC BX900-FC82E 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x79, 0},
		{0},
		{0x79, 0},
		{0},
		{0x78, 0},
	},

	/* Saturn (Sun Pallene) */
	{
		LPe12000_S,
		PCI_DEVICE_ID_LPe12000_S,
		PCI_SSDID_LPe12000_S,
		"LPe12000-S",
		"Emulex LPe12000-S 8Gb 1-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		1,
		{0x78, 0},
		{0x7C, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
	},

	/* Saturn DC (Sun Pallene) */
	{
		LPe12002_S,
		PCI_DEVICE_ID_LPe12002_S,
		PCI_SSDID_LPe12002_S,
		"LPe12002-S",
		"Emulex LPe12002-S 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x7C, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
	},

	/* Saturn Express Module (Sun Pallene) */
	{
		LPem12002_S,
		PCI_DEVICE_ID_LPem12002_S,
		PCI_SSDID_LPem12002_S,
		"LPem12002-S",
		"Emulex LPem12002-S 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_SUN_BRANDED | EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x7C, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
	},


	/*
	 * ************************************ SPARE IDs
	 *
	 * Helios Enterprise Spare Id
	 */
	{
		LP11000_SP,
		PCI_DEVICE_ID_LP11000_SP,
		PCI_SSDID_LP11000_SP,
		"LP11000-SP",
		"Emulex LP11000-SP 4Gb 1-port PCI-X2 FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_HELIOS_CHIP,
		LP11000_FW,
		EMLXS_INTR_LIMIT1,
		1,
		{0xC3, 0xC8, 0},
		{0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0},
		{0xC3, 0},
		{0xC3, 0},
		{0},
		{0xC3, 0},
		{0},
		{0xC0, 0},
	},

	/* Helios DC Enterprise Spare Id  */
	{
		LP11002_SP,
		PCI_DEVICE_ID_LP11002_SP,
		PCI_SSDID_LP11002_SP,
		"LP11002-SP",
		"Emulex LP11002-SP 4Gb 2-port PCI-X2 FC HBA",
		"Emulex",
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
		EMLXS_HELIOS_CHIP,
		LP11002_FW,
		EMLXS_INTR_LIMIT1,
		2,
		{0xC1, 0xC8, 0},
		{0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0},
		{0xC1, 0},
		{0xC1, 0},
		{0},
		{0xC1, 0},
		{0},
		{0xC0, 0},
	},

	/* Zephyr Enterprise Spare Id  */
	{
		LPe11000_SP,
		PCI_DEVICE_ID_LPe11000_SP,
		PCI_SSDID_LPe11000_SP,
		"LPe11000-SP",
		"Emulex LPe11000-SP 4Gb 1-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11000_FW,
		EMLXS_INTR_NO_LIMIT,
		1,
		{0xE3, 0xE8, 0},
		{0xE1, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7, 0},
		{0xE3, 0},
		{0xE3, 0},
		{0},
		{0xE3, 0},
		{0},
		{0xE0, 0},
	},

	/* Zephyr DC Enterprise Spare Id  */
	{
		LPe11002_SP,
		PCI_DEVICE_ID_LPe11002_SP,
		PCI_SSDID_LPe11002_SP,
		"LPe11002-SP",
		"Emulex LPe11002-SP 4Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE1, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},

	/* Zephyr DC Blade (Spare) */
	{
		LPe1105_SP,
		PCI_DEVICE_ID_LPe1105_SP,
		PCI_SSDID_LPe1105_SP,
		"LPe1105-SP",
		"Emulex LPe1105-SP 2Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_ZEPHYR_CHIP,
		LPe11002_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0xE1, 0xE8, 0},
		{0xE1, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7, 0},
		{0xE1, 0},
		{0xE1, 0},
		{0},
		{0xE1, 0},
		{0},
		{0xE0, 0},
	},

	/* Neptune Enterprise (Spare) */
	{
		LPe1000_SP,
		PCI_DEVICE_ID_LPe1000_SP,
		PCI_SSDID_LPe1000_SP,
		"LPe1000-SP",
		"Emulex LPe1000-SP 4Gb 1-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_NEPTUNE_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		1,
		{0x38, 0},
		{0x39, 0x3A, 0x3B, 0x3D, 0x3E, 0x3F, 0},
		{0x32, 0},
		{0x32, 0},
		{0},
		{0x32, 0},
		{0},
		{0x38, 0},
	},

	/* Neptune DC Enterprise Spare Id  */
	{
		LPe1002_SP,
		PCI_DEVICE_ID_LPe1002_SP,
		PCI_SSDID_LPe1002_SP,
		"LPe1002-SP",
		"Emulex LPe1002-SP 4Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_NEPTUNE_CHIP,
		FW_NOT_PROVIDED,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x38, 0},
		{0x39, 0x3A, 0x3B, 0x3D, 0x3E, 0x3F, 0},
		{0x32, 0},
		{0x32, 0},
		{0},
		{0x32, 0},
		{0},
		{0x38, 0},
	},

	/* Saturn  */
	{
		LPe12000_SP,
		PCI_DEVICE_ID_LPe12000_SP,
		PCI_SSDID_LPe12000_SP,
		"LPe12000-SP",
		"Emulex LPe12000-SP 8Gb 1-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED |
		EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		1,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
	},

	/* Saturn DC */
	{
		LPe12002_SP,
		PCI_DEVICE_ID_LPe12002_SP,
		PCI_SSDID_LPe12002_SP,
		"LPe12002-SP",
		"Emulex LPe12002-SP 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED |
		EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x73, 0},
		{0},
		{0x73, 0},
		{0},
		{0x78, 0},
	},

	/* Saturn Blade 1 */
	{
		LPe1205_SP1,
		PCI_DEVICE_ID_LPe1205_SP1,
		PCI_SSDID_LPe1205_SP1,
		"LPe1205-SP1",
		"Emulex LPe1205-SP1 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x79, 0},
		{0},
		{0x79, 0},
		{0},
		{0x78, 0},
	},

	/* Saturn Blade 2 */
	{
		LPe1205_SP2,
		PCI_DEVICE_ID_LPe1205_SP2,
		PCI_SSDID_LPe1205_SP2,
		"LPe1205-SP2",
		"Emulex LPe1205-SP2 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x79, 0},
		{0},
		{0x79, 0},
		{0},
		{0x78, 0},
	},

	/* Saturn Blade 3 */
	{
		LPe1205_SP3,
		PCI_DEVICE_ID_LPe1205_SP3,
		PCI_SSDID_LPe1205_SP3,
		"LPe1205-SP3",
		"Emulex LPe1205-SP3 8Gb 2-port PCIe FC HBA",
		"Emulex",
#ifdef S10S11
		EMLXS_INTX_SUPPORTED | EMLXS_MSI_SUPPORTED |
			EMLXS_MSIX_SUPPORTED | EMLXS_E2E_SUPPORTED,
#else
		EMLXS_NOT_SUPPORTED,
#endif	/* S10S11 */
		EMLXS_SATURN_CHIP,
		LPe12000_FW,
		EMLXS_INTR_NO_LIMIT,
		2,
		{0x78, 0},
		{0x79, 0x7A, 0x7B, 0x7D, 0x7E, 0x7F, 0},
		{0},
		{0x79, 0},
		{0},
		{0x79, 0},
		{0},
		{0x78, 0},
	}

};	/* emlxs_pci_model[] */

#define	EMLXS_PCI_MODEL_COUNT \
	(sizeof (emlxs_pci_model) / sizeof (emlxs_model_t))


#endif	/* EMLXS_MODEL_DEF */

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_ADAPTERS_H */
