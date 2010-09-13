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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SGFRUTYPES_H
#define	_SYS_SGFRUTYPES_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * sgfrutypes.h - Serengeti/WildCat/Lightweight8 common FRU definitions
 *
 * This header file contains the common FRU-ID definitions and macros for the
 * Serengeti, WildCat and Lightweight8 platforms.
 *
 *	- definitions of the various FRU types.
 *	- macros to generate FRU names.
 *
 * (Not to be confused with the header files for the SGFRU driver)
 */

/*
 * Known HPU/FRU types
 *
 * These FRU definitions are common to both the Serengeti and LightWeight8
 * platforms. They are used by various macros used by both platforms as well
 * as the LW8 specific SGENV (environmentals) driver.
 */
#define	SG_HPU_TYPE_SYSTEM_CONTROLLER_BOARD			(0x101)
#define	SG_HPU_TYPE_SYSTEM_CONTROLLER_BOARD_STR  \
			"System Controller Board"
#define	SG_HPU_TYPE_SYSTEM_CONTROLLER_BOARD_ID			"SSC"
#define	SG_HPU_TYPE_SYSTEM_CONTROLLER_BOARD_SHORTNAME		"SSC"

#define	SG_HPU_TYPE_SYSTEM_CONTROLLER_BOARD_F3800		(0x102)
#define	SG_HPU_TYPE_SYSTEM_CONTROLLER_BOARD_F3800_STR  \
			"System Controller Board (F3800)"
#define	SG_HPU_TYPE_SYSTEM_CONTROLLER_BOARD_F3800_ID		"SSC"
#define	SG_HPU_TYPE_SYSTEM_CONTROLLER_BOARD_F3800_SHORTNAME	"SSC"


#define	SG_HPU_TYPE_CPU_BOARD			(0x201)
#define	SG_HPU_TYPE_CPU_BOARD_STR		"CPU Board"
#define	SG_HPU_TYPE_CPU_BOARD_ID		"SB"
#define	SG_HPU_TYPE_CPU_BOARD_SHORTNAME		"CPU"

#define	SG_HPU_TYPE_WIB_BOARD			(0x202)
#define	SG_HPU_TYPE_WIB_BOARD_STR		"WIB Board"
#define	SG_HPU_TYPE_WIB_BOARD_ID		"SB"
#define	SG_HPU_TYPE_WIB_BOARD_SHORTNAME		"WIB"

#define	SG_HPU_TYPE_ZULU_BOARD			(0x203)
#define	SG_HPU_TYPE_ZULU_BOARD_STR		"Zulu Board"
#define	SG_HPU_TYPE_ZULU_BOARD_ID		"SB"
#define	SG_HPU_TYPE_ZULU_BOARD_SHORTNAME	"GPX"


#define	SG_HPU_TYPE_REPEATER_BOARD			(0x301)
#define	SG_HPU_TYPE_REPEATER_BOARD_STR			"Repeater Board"
#define	SG_HPU_TYPE_REPEATER_BOARD_ID			"RP"

#define	SG_HPU_TYPE_LOGIC_ANALYZER_BOARD		(0x302)
#define	SG_HPU_TYPE_LOGIC_ANALYZER_BOARD_STR		"Logic Analyzer Board"
#define	SG_HPU_TYPE_LOGIC_ANALYZER_BOARD_ID		"RP"

#define	SG_HPU_TYPE_REPEATER_BOARD_F3800		(0x303)
#define	SG_HPU_TYPE_REPEATER_BOARD_F3800_STR		"Repeater Board (F3800)"
#define	SG_HPU_TYPE_REPEATER_BOARD_F3800_ID		"RP"
#define	SG_HPU_TYPE_REPEATER_BOARD_F3800_SHORTNAME	"RP"


#define	SG_HPU_TYPE_FAN_TRAY_F6800_IO			(0x401)
#define	SG_HPU_TYPE_FAN_TRAY_F6800_IO_STR		"Fan Tray (F6800, I/O)"
#define	SG_HPU_TYPE_FAN_TRAY_F6800_IO_ID		"FT"
#define	SG_HPU_TYPE_FAN_TRAY_F6800_IO_SHORTNAME		"FAN"

#define	SG_HPU_TYPE_FAN_TRAY_F6800_CPU			(0x402)
#define	SG_HPU_TYPE_FAN_TRAY_F6800_CPU_STR		"Fan Tray (F6800, CPU)"
#define	SG_HPU_TYPE_FAN_TRAY_F6800_CPU_ID		"FT"
#define	SG_HPU_TYPE_FAN_TRAY_F6800_CPU_SHORTNAME	"FAN"

#define	SG_HPU_TYPE_FAN_TRAY_RACK			(0x403)
#define	SG_HPU_TYPE_FAN_TRAY_RACK_STR			"Fan Tray (Rack)"
#define	SG_HPU_TYPE_FAN_TRAY_RACK_ID			"FT"
#define	SG_HPU_TYPE_FAN_TRAY_RACK_SHORTNAME		"RACKFAN"

#define	SG_HPU_TYPE_FAN_TRAY_F4810			(0x404)
#define	SG_HPU_TYPE_FAN_TRAY_F4810_STR			"Fan Tray (F4810)"
#define	SG_HPU_TYPE_FAN_TRAY_F4810_ID			"FT"
#define	SG_HPU_TYPE_FAN_TRAY_F4810_SHORTNAME		"FAN"

#define	SG_HPU_TYPE_FAN_TRAY_F4800_IO			(0x405)
#define	SG_HPU_TYPE_FAN_TRAY_F4800_IO_STR		"Fan Tray (F4800, I/O)"
#define	SG_HPU_TYPE_FAN_TRAY_F4800_IO_ID		"FT"
#define	SG_HPU_TYPE_FAN_TRAY_F4800_IO_SHORTNAME		"FAN"

#define	SG_HPU_TYPE_FAN_TRAY_F4800_CPU			(0x406)
#define	SG_HPU_TYPE_FAN_TRAY_F4800_CPU_STR		"Fan Tray (F4800, CPU)"
#define	SG_HPU_TYPE_FAN_TRAY_F4800_CPU_ID		"FT"
#define	SG_HPU_TYPE_FAN_TRAY_F4800_CPU_SHORTNAME	"FAN"

#define	SG_HPU_TYPE_FAN_TRAY_F4800_TOP_IO		(0x407)
#define	SG_HPU_TYPE_FAN_TRAY_F4800_TOP_IO_STR  \
			"Fan Tray (F4800, Top I/O)"
#define	SG_HPU_TYPE_FAN_TRAY_F4800_TOP_IO_ID		"FT"
#define	SG_HPU_TYPE_FAN_TRAY_F4800_TOP_IO_SHORTNAME	"FAN"

#define	SG_HPU_TYPE_FAN_TRAY_F3800			(0x408)
#define	SG_HPU_TYPE_FAN_TRAY_F3800_STR			"Fan Tray (F3800)"
#define	SG_HPU_TYPE_FAN_TRAY_F3800_ID			"FT"
#define	SG_HPU_TYPE_FAN_TRAY_F3800_SHORTNAME		"FAN"

#define	SG_HPU_TYPE_FAN_TRAY_F4800_BOTTOM_IO		(0x409)
#define	SG_HPU_TYPE_FAN_TRAY_F4800_BOTTOM_IO_STR \
			"Fan Tray (F4800, Bottom I/O)"
#define	SG_HPU_TYPE_FAN_TRAY_F4800_BOTTOM_IO_ID		"FT"
#define	SG_HPU_TYPE_FAN_TRAY_F4800_BOTTOM_IO_SHORTNAME	"FAN"


#define	SG_HPU_TYPE_PCI_IO_BOARD		(0x501)
#define	SG_HPU_TYPE_PCI_IO_BOARD_STR		"PCI I/O Board"
#define	SG_HPU_TYPE_PCI_IO_BOARD_ID		"IB"
#define	SG_HPU_TYPE_PCI_IO_BOARD_SHORTNAME	"PCIB"

#define	SG_HPU_TYPE_CPCI_IO_BOARD		(0x502)
#define	SG_HPU_TYPE_CPCI_IO_BOARD_STR		"CPCI I/O board"
#define	SG_HPU_TYPE_CPCI_IO_BOARD_ID		"IB"
#define	SG_HPU_TYPE_CPCI_IO_BOARD_SHORTNAME	"CPCB"

#define	SG_HPU_TYPE_CPCI_IO_BOARD_F3800		(0x503)
#define	SG_HPU_TYPE_CPCI_IO_BOARD_F3800_STR	"CPCI I/O board (F3800)"
#define	SG_HPU_TYPE_CPCI_IO_BOARD_F3800_ID	"IB"

#define	SG_HPU_TYPE_WCI_CPCI_IO_BOARD		(0x504)
#define	SG_HPU_TYPE_WCI_CPCI_IO_BOARD_STR	"WCI cPCI I/O Board"
#define	SG_HPU_TYPE_WCI_CPCI_IO_BOARD_ID	"IB"

#define	SG_HPU_TYPE_WCI_CPCI_IO_BOARD_F3800	(0x505)
#define	SG_HPU_TYPE_WCI_CPCI_IO_BOARD_F3800_STR	"WCI cPCI I/O Board (F3800)"
#define	SG_HPU_TYPE_WCI_CPCI_IO_BOARD_F3800_ID	"IB"


#define	SG_HPU_TYPE_A123_POWER_SUPPLY		(0x601)
#define	SG_HPU_TYPE_A123_POWER_SUPPLY_STR	"A123 Power Supply"
#define	SG_HPU_TYPE_A123_POWER_SUPPLY_ID	"PS"
#define	SG_HPU_TYPE_A123_POWER_SUPPLY_SHORTNAME	"PS"

#define	SG_HPU_TYPE_A138_POWER_SUPPLY		(0x602)
#define	SG_HPU_TYPE_A138_POWER_SUPPLY_STR	"A138 Power Supply"
#define	SG_HPU_TYPE_A138_POWER_SUPPLY_ID	"PS"
#define	SG_HPU_TYPE_A138_POWER_SUPPLY_SHORTNAME	"PS"

#define	SG_HPU_TYPE_A145_POWER_SUPPLY		(0x603)
#define	SG_HPU_TYPE_A145_POWER_SUPPLY_STR	"A145 Power Supply"
#define	SG_HPU_TYPE_A145_POWER_SUPPLY_ID	"PS"
#define	SG_HPU_TYPE_A145_POWER_SUPPLY_SHORTNAME	"PS"

#define	SG_HPU_TYPE_A152_POWER_SUPPLY		(0x604)
#define	SG_HPU_TYPE_A152_POWER_SUPPLY_STR	"A152 Power Supply"
#define	SG_HPU_TYPE_A152_POWER_SUPPLY_ID	"PS"
#define	SG_HPU_TYPE_A152_POWER_SUPPLY_SHORTNAME	"PS"

#define	SG_HPU_TYPE_A153_POWER_SUPPLY		(0x605)
#define	SG_HPU_TYPE_A153_POWER_SUPPLY_STR	"A153 Power Supply"
#define	SG_HPU_TYPE_A153_POWER_SUPPLY_ID	"PS"
#define	SG_HPU_TYPE_A153_POWER_SUPPLY_SHORTNAME	"PS"


#define	SG_HPU_TYPE_SUN_FIRE_3800_CENTERPLANE	(0x701)	/* 0x701 */
#define	SG_HPU_TYPE_SUN_FIRE_3800_CENTERPLANE_STR  \
			"Sun Fire 3800 Centerplane"
#define	SG_HPU_TYPE_SUN_FIRE_3800_CENTERPLANE_ID	"ID"
#define	SG_HPU_TYPE_SUN_FIRE_3800_CENTERPLANE_SHORTNAME	"ID"

#define	SG_HPU_TYPE_SUN_FIRE_6800_CENTERPLANE	(0x702)	/* 0x702 */
#define	SG_HPU_TYPE_SUN_FIRE_6800_CENTERPLANE_STR  \
			"Sun Fire 6800 Centerplane"
#define	SG_HPU_TYPE_SUN_FIRE_6800_CENTERPLANE_ID	"ID"
#define	SG_HPU_TYPE_SUN_FIRE_6800_CENTERPLANE_SHORTNAME	"ID"

#define	SG_HPU_TYPE_SUN_FIRE_4810_CENTERPLANE	(0x703)	/* 0x703 */
#define	SG_HPU_TYPE_SUN_FIRE_4810_CENTERPLANE_STR  \
			"Sun Fire 4810 Centerplane"
#define	SG_HPU_TYPE_SUN_FIRE_4810_CENTERPLANE_ID	"ID"
#define	SG_HPU_TYPE_SUN_FIRE_4810_CENTERPLANE_SHORTNAME	"ID"

#define	SG_HPU_TYPE_SUN_FIRE_4800_CENTERPLANE	(0x704)	/* 0x704 */
#define	SG_HPU_TYPE_SUN_FIRE_4800_CENTERPLANE_STR  \
			"Sun Fire 4800 Centerplane"
#define	SG_HPU_TYPE_SUN_FIRE_4800_CENTERPLANE_ID	"ID"
#define	SG_HPU_TYPE_SUN_FIRE_4800_CENTERPLANE_SHORTNAME	"ID"

#define	SG_HPU_TYPE_SUN_FIRE_3800_REPLACEMENT_CENTERPLANE	(0x705)
#define	SG_HPU_TYPE_SUN_FIRE_3800_REPLACEMENT_CENTERPLANE_STR  \
			"Sun Fire 3800 Replacement Centerplane"
#define	SG_HPU_TYPE_SUN_FIRE_3800_REPLACEMENT_CENTERPLANE_ID	"ID"
#define	SG_HPU_TYPE_SUN_FIRE_3800_REPLACEMENT_CENTERPLANE_SHORTNAME	"ID"

#define	SG_HPU_TYPE_SUN_FIRE_6800_REPLACEMENT_CENTERPLANE	(0x706)
#define	SG_HPU_TYPE_SUN_FIRE_6800_REPLACEMENT_CENTERPLANE_STR  \
			"Sun Fire 6800 Replacement Centerplane"
#define	SG_HPU_TYPE_SUN_FIRE_6800_REPLACEMENT_CENTERPLANE_ID	"ID"
#define	SG_HPU_TYPE_SUN_FIRE_6800_REPLACEMENT_CENTERPLANE_SHORTNAME	"ID"

#define	SG_HPU_TYPE_SUN_FIRE_4810_REPLACEMENT_CENTERPLANE	(0x707)
#define	SG_HPU_TYPE_SUN_FIRE_4810_REPLACEMENT_CENTERPLANE_STR  \
			"Sun Fire 4810 Replacement Centerplane"
#define	SG_HPU_TYPE_SUN_FIRE_4810_REPLACEMENT_CENTERPLANE_ID		"ID"
#define	SG_HPU_TYPE_SUN_FIRE_4810_REPLACEMENT_CENTERPLANE_SHORTNAME	"ID"

#define	SG_HPU_TYPE_SUN_FIRE_4800_REPLACEMENT_CENTERPLANE	(0x708)
#define	SG_HPU_TYPE_SUN_FIRE_4800_REPLACEMENT_CENTERPLANE_STR  \
			"Sun Fire 4800 Replacement Centerplane"
#define	SG_HPU_TYPE_SUN_FIRE_4800_REPLACEMENT_CENTERPLANE_ID		"ID"
#define	SG_HPU_TYPE_SUN_FIRE_4800_REPLACEMENT_CENTERPLANE_SHORTNAME	"ID"

#define	SG_HPU_TYPE_SUN_FIRE_REPLACEMENT_ID_BOARD	(0x709)	/* 0x709 */
#define	SG_HPU_TYPE_SUN_FIRE_REPLACEMENT_ID_BOARD_STR  \
			"Sun Fire Replacement ID Board"
#define	SG_HPU_TYPE_SUN_FIRE_REPLACEMENT_ID_BOARD_ID	"ID"
#define	SG_HPU_TYPE_SUN_FIRE_REPLACEMENT_ID_BOARD_SHORTNAME	"ID"


#define	SG_HPU_TYPE_AC_SEQUENCER		(0x900)
#define	SG_HPU_TYPE_AC_SEQUENCER_STR		"AC Sequencer"
#define	SG_HPU_TYPE_AC_SEQUENCER_ID		"AC"
#define	SG_HPU_TYPE_AC_SEQUENCER_SHORTNAME	"AC"


#define	SG_HPU_TYPE_2MB_ECACHE_MODULE	((10<<8)|1)	/* 0xA01 */
#define	SG_HPU_TYPE_2MB_ECACHE_MODULE_STR  \
			"2MB Ecache module"

#define	SG_HPU_TYPE_2MB_ECACHE_MODULE_SHORTNAME	"ECACHE"

#define	SG_HPU_TYPE_4MB_ECACHE_MODULE	((10<<8)|2)	/* 0xA02 */
#define	SG_HPU_TYPE_4MB_ECACHE_MODULE_STR  \
			"4MB Ecache module"

#define	SG_HPU_TYPE_4MB_ECACHE_MODULE_SHORTNAME	"ECACHE"

#define	SG_HPU_TYPE_DRAM_SLOT	((11<<8)|0)	/* 0xB00 */
#define	SG_HPU_TYPE_DRAM_SLOT_STR  \
			"DRAM slot"

#define	SG_HPU_TYPE_DRAM_SLOT_SHORTNAME	"DIMM"

#define	SG_HPU_TYPE_128MB_DRAM_MODULE	((11<<8)|1)	/* 0xB01 */
#define	SG_HPU_TYPE_128MB_DRAM_MODULE_STR  \
			"128MB DRAM module"

#define	SG_HPU_TYPE_128MB_DRAM_MODULE_SHORTNAME	"DIMM"

#define	SG_HPU_TYPE_256MB_DRAM_MODULE	((11<<8)|2)	/* 0xB02 */
#define	SG_HPU_TYPE_256MB_DRAM_MODULE_STR  \
			"256MB DRAM module"

#define	SG_HPU_TYPE_256MB_DRAM_MODULE_SHORTNAME	"DIMM"

#define	SG_HPU_TYPE_512MB_DRAM_MODULE	((11<<8)|3)	/* 0xB03 */
#define	SG_HPU_TYPE_512MB_DRAM_MODULE_STR  \
			"512MB DRAM module"

#define	SG_HPU_TYPE_512MB_DRAM_MODULE_SHORTNAME	"DIMM"

#define	SG_HPU_TYPE_1GB_DRAM_MODULE	((11<<8)|4)	/* 0xB04 */
#define	SG_HPU_TYPE_1GB_DRAM_MODULE_STR  \
			"1GB DRAM module"

#define	SG_HPU_TYPE_1GB_DRAM_MODULE_SHORTNAME	"DIMM"

/*
 * These macros are used to generate the FRU Names of the various boards etc.
 * A string is passed in to each macro and by calling a number of the
 * macros a FRU name in the HLLN format can be built up.
 *
 * Note: The string needs to be initialized to an empty string before the
 *       first of these macros is called to generate a FRU Name.
 */
#define	MAX_FRU_NAME_LEN		20

#define	SG_SET_FRU_NAME_NODE(str, num) \
{ \
	char tmp_str[MAX_FRU_NAME_LEN]; \
	(void) sprintf(tmp_str, "/N%d", num); \
	(void) strcat(str, tmp_str); \
}

#define	SG_SET_FRU_NAME_CPU_BOARD(str, num) \
{ \
	char tmp_str[MAX_FRU_NAME_LEN]; \
	(void) sprintf(tmp_str, "/%s%d", SG_HPU_TYPE_CPU_BOARD_ID, num); \
	(void) strcat(str, tmp_str); \
}

#define	SG_SET_FRU_NAME_IO_BOARD(str, num) \
{ \
	char tmp_str[MAX_FRU_NAME_LEN]; \
	(void) sprintf(tmp_str, "/%s%d", SG_HPU_TYPE_PCI_IO_BOARD_ID, num); \
	(void) strcat(str, tmp_str); \
}

#define	SG_SET_FRU_NAME_MODULE(str, num) \
{ \
	char tmp_str[MAX_FRU_NAME_LEN]; \
	(void) sprintf(tmp_str, "/P%d", num); \
	(void) strcat(str, tmp_str); \
}

#define	SG_SET_FRU_NAME_CORE(str, num) \
{ \
	char tmp_str[MAX_FRU_NAME_LEN]; \
	(void) sprintf(tmp_str, "/C%d", num); \
	(void) strcat(str, tmp_str); \
}

#define	SG_SET_FRU_NAME_BANK(str, num) \
{ \
	char tmp_str[MAX_FRU_NAME_LEN]; \
	(void) sprintf(tmp_str, "/B%d", num); \
	(void) strcat(str, tmp_str); \
}

#define	SG_SET_FRU_NAME_DIMM(str, num) \
{ \
	char tmp_str[MAX_FRU_NAME_LEN]; \
	(void) sprintf(tmp_str, "/D%d", num); \
	(void) strcat(str, tmp_str); \
}


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SGFRUTYPES_H */
