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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SGENV_TAG_H
#define	_SYS_SGENV_TAG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>


/*
 * We generate #define's for every possible HPU, however the SC only
 * returns data for some of these HPUs. These are #defined in serengeti.h
 * as they are common to both Serengeti and LightWeight8 platforms.
 * However we keep track of the HPUs which return environmental data here
 * as that info is SGENV specific.
 *
 * Below is a list of the HPU's which return environmental data.
 *
 *	SG_HPU_TYPE_CPU_BOARD
 *
 *	SG_HPU_TYPE_PCI_IO_BOARD
 *	SG_HPU_TYPE_CPCI_IO_BOARD
 *	SG_HPU_TYPE_CPCI_IO_BOARD_F3800
 *
 *	SG_HPU_TYPE_REPEATER_BOARD
 *	SG_HPU_TYPE_LOGIC_ANALYZER_BOARD
 *	SG_HPU_TYPE_REPEATER_BOARD_F3800
 *
 *	SG_HPU_TYPE_SYSTEM_CONTROLLER_BOARD
 *	SG_HPU_TYPE_SYSTEM_CONTROLLER_BOARD_F3800
 *
 *	SG_HPU_TYPE_A123_POWER_SUPPLY
 *	SG_HPU_TYPE_A138_POWER_SUPPLY
 *	SG_HPU_TYPE_A145_POWER_SUPPLY
 *	SG_HPU_TYPE_A152_POWER_SUPPLY
 *	SG_HPU_TYPE_A153_POWER_SUPPLY
 *
 *	SG_HPU_TYPE_FAN_TRAY_F6800_IO
 *	SG_HPU_TYPE_FAN_TRAY_F6800_CPU
 *	SG_HPU_TYPE_FAN_TRAY_RACK
 *	SG_HPU_TYPE_FAN_TRAY_F4810
 *	SG_HPU_TYPE_FAN_TRAY_F4800_IO
 *	SG_HPU_TYPE_FAN_TRAY_F4800_CPU
 *	SG_HPU_TYPE_FAN_TRAY_F4800_TOP_IO
 *	SG_HPU_TYPE_FAN_TRAY_F3800
 *	SG_HPU_TYPE_FAN_TRAY_F3800_ID
 *	SG_HPU_TYPE_FAN_TRAY_F4800_BOTTOM_IO
 *
 * The following are obsolete and have been superseded by entries in the
 * list above and should not be used. They are simply present to support
 * existing clients and will be deleted at some stage in the future.
 *
 *	SG_HPU_TYPE_SP_CPCI_IO_BOARD
 *	SG_HPU_TYPE_SP_SYSTEM_CONTROLLER_BOARD
 *	SG_HPU_TYPE_L2_REPEATER_BOARD
 *	SG_HPU_TYPE_RACK_FAN_TRAY
 *	SG_HPU_TYPE_SP_FAN_TRAY
 *	SG_HPU_TYPE_MD_TOP_IO_FAN_TRAY
 *	SG_HPU_TYPE_MD_BOTTOM_IO_FAN_TRAY
 *	SG_HPU_TYPE_R12_THREE_FAN_TRAY
 *	SG_HPU_TYPE_K12_IO_ONE_FAN_TRAY
 *	SG_HPU_TYPE_K12_CPU_THREE_FAN_TRAY
 *	SG_HPU_TYPE_R24_IO_FOUR_FAN_TRAY
 *	SG_HPU_TYPE_R24_CPU_SIX_FAN_TRAY
 */

typedef union sensor_id {
	struct {
		uint32_t  \
			hpu_type	: 16,
			hpu_slot	: 8,
			sensor_part	: 8,
			sensor_partnum	: 8,
			sensor_type	: 8,
			sensor_typenum	: 8,
			node_id	: 4,
			_pad	: 4;
	} id;
	uint64_t tag_id;
} sensor_id_t;


/*
 * Known sensor parts (sensor_part)
 */

#define	SG_SENSOR_PART_SBBC	0x1
#define	SG_SENSOR_PART_SBBC_STR	"SBBC"

#define	SG_SENSOR_PART_SDC	0x2
#define	SG_SENSOR_PART_SDC_STR	"SDC"

#define	SG_SENSOR_PART_AR	0x3
#define	SG_SENSOR_PART_AR_STR	"AR"

#define	SG_SENSOR_PART_CBH	0x4
#define	SG_SENSOR_PART_CBH_STR	"CBH"

#define	SG_SENSOR_PART_DX	0x5
#define	SG_SENSOR_PART_DX_STR	"DX"

#define	SG_SENSOR_PART_CHEETAH	0x6
#define	SG_SENSOR_PART_CHEETAH_STR	"Cheetah"

#define	SG_SENSOR_PART_1_5_VDC	0x7
#define	SG_SENSOR_PART_1_5_VDC_STR	"1.5 VDC"

#define	SG_SENSOR_PART_3_3_VDC	0x8
#define	SG_SENSOR_PART_3_3_VDC_STR	"3.3 VDC"

#define	SG_SENSOR_PART_5_VDC	0x9
#define	SG_SENSOR_PART_5_VDC_STR	"5 VDC"

#define	SG_SENSOR_PART_12_VDC	0xA
#define	SG_SENSOR_PART_12_VDC_STR	"12 VDC"

#define	SG_SENSOR_PART_48_VDC	0xB
#define	SG_SENSOR_PART_48_VDC_STR	"48 VDC"

#define	SG_SENSOR_PART_CURRENT	0xC
#define	SG_SENSOR_PART_CURRENT_STR	"Current"

#define	SG_SENSOR_PART_BOARD	0xD
#define	SG_SENSOR_PART_BOARD_STR	"Board"

#define	SG_SENSOR_PART_SCAPP	0xE
#define	SG_SENSOR_PART_SCAPP_STR	"SC-APP"

#define	SG_SENSOR_PART_SCHIZO	0xF
#define	SG_SENSOR_PART_SCHIZO_STR	"Schizo"

#define	SG_SENSOR_PART_FAN	0x10
#define	SG_SENSOR_PART_FAN_STR	"Fan"

#define	SG_SENSOR_PART_INPUT	0x11
#define	SG_SENSOR_PART_INPUT_STR	"Input"

/*
 * Known sensor types (sensor_type)
 * Scaling factors (when applicable)
 * N.b. Warning zone ranges are scaled, and
 *      the ..._RANGE definitions below are superceded
 *      by the scaled <sd_lo_warn> and <sd_hi_warn>
 *      fields in env_sensor_t.
 */

#define	SG_SENSOR_TYPE_CURRENT	0x2	/* Current */
#define	SG_SENSOR_TYPE_CURRENT_STR	"Current"
#define	SG_SENSOR_TYPE_CURRENT_UNITS	"Amps"
#define	SG_CURRENT_SCALE		100

#define	SG_SENSOR_TYPE_TEMPERATURE	0x3	/* Temp. */
#define	SG_SENSOR_TYPE_TEMPERATURE_STR	"Temp."
#define	SG_SENSOR_TYPE_TEMPERATURE_UNITS	"Degrees C"
#define	SG_TEMPERATURE_SCALE		100
#define	SG_TEMPERATURE_RANGE		1000

#define	SG_SENSOR_TYPE_COOLING	0x4	/* Cooling */
#define	SG_SENSOR_TYPE_COOLING_STR	"Cooling"
#define	SG_SENSOR_TYPE_COOLING_UNITS	""

#define	SG_SENSOR_TYPE_1_5_VDC	0x5	/* 1.5 VDC */
#define	SG_SENSOR_TYPE_1_5_VDC_STR	"1.5 VDC"
#define	SG_SENSOR_TYPE_1_5_VDC_UNITS	"Volts DC"
#define	SG_1_5_VDC_SCALE		100
#define	SG_1_5_VDC_RANGE		0

#define	SG_SENSOR_TYPE_1_8_VDC	0x6	/* 1.8 VDC */
#define	SG_SENSOR_TYPE_1_8_VDC_STR	"1.8 VDC"
#define	SG_SENSOR_TYPE_1_8_VDC_UNITS	"Volts DC"
#define	SG_1_8_VDC_SCALE		100
#define	SG_1_8_VDC_RANGE		0

#define	SG_SENSOR_TYPE_3_3_VDC	0x7	/* 3.3 VDC */
#define	SG_SENSOR_TYPE_3_3_VDC_STR	"3.3 VDC"
#define	SG_SENSOR_TYPE_3_3_VDC_UNITS	"Volts DC"
#define	SG_3_3_VDC_SCALE		100
#define	SG_3_3_VDC_RANGE		0

#define	SG_SENSOR_TYPE_5_VDC	0x8	/* 5 VDC */
#define	SG_SENSOR_TYPE_5_VDC_STR	"5 VDC"
#define	SG_SENSOR_TYPE_5_VDC_UNITS	"Volts DC"
#define	SG_5_VDC_SCALE		100
#define	SG_5_VDC_RANGE		0

#define	SG_SENSOR_TYPE_12_VDC	0x9	/* 12 VDC */
#define	SG_SENSOR_TYPE_12_VDC_STR	"12 VDC"
#define	SG_SENSOR_TYPE_12_VDC_UNITS	"Volts DC"
#define	SG_12_VDC_SCALE		100
#define	SG_12_VDC_RANGE		0

#define	SG_SENSOR_TYPE_48_VDC	0xA	/* 48 VDC */
#define	SG_SENSOR_TYPE_48_VDC_STR	"48 VDC"
#define	SG_SENSOR_TYPE_48_VDC_UNITS	"Volts DC"
#define	SG_48_VDC_SCALE		100
#define	SG_48_VDC_RANGE		0

#define	SG_SENSOR_TYPE_ENVDB	0xB	/* Env. */
#define	SG_SENSOR_TYPE_ENVDB_STR	"Env."
#define	SG_SENSOR_TYPE_ENVDB_UNITS	"Gen."

#define	SG_SENSOR_TYPE_2_5_VDC	0xC	/* 2.5 VDC */
#define	SG_SENSOR_TYPE_2_5_VDC_STR	"2.5 VDC"
#define	SG_SENSOR_TYPE_2_5_VDC_UNITS	"Volts DC"
#define	SG_2_5_VDC_SCALE		100
#define	SG_2_5_VDC_RANGE		0

/*
 * If we have to change the names of any of the #defines in the future,
 * then we simply will define the old name to point to the new name.
 * That way the clients do not know about the change and do not need
 * to change their code.
 */
#define	SG_HPU_TYPE_UNKNOWN		(0x0)
#define	SG_HPU_TYPE_UNKNOWN_STR		"Unknown"
#define	SG_HPU_TYPE_UNKNOWN_ID		"UNK"

/* generic power supply FRUID string */
#define	SG_HPU_TYPE_POWER_SUPPLY_ID	"PS"


/*
 * The following are obsolete and have been superseded by entries in the
 * list above and should not be used. They are simply present to support
 * existing clients.
 */
#define	SG_HPU_TYPE_SP_SYSTEM_CONTROLLER_BOARD	((1<<8)|2)	/* 0x102 */
#define	SG_HPU_TYPE_SP_SYSTEM_CONTROLLER_BOARD_STR  \
			"SP System Controller Board"
#define	SG_HPU_TYPE_SP_SYSTEM_CONTROLLER_BOARD_ID	"SSC"
#define	SG_HPU_TYPE_SP_SYSTEM_CONTROLLER_BOARD_SHORTNAME	"SSC"

#define	SG_HPU_TYPE_L2_REPEATER_BOARD			(0x301)
#define	SG_HPU_TYPE_L2_REPEATER_BOARD_STR		"L2 Repeater Board"
#define	SG_HPU_TYPE_L2_REPEATER_BOARD_ID		"RP"
#define	SG_HPU_TYPE_L2_REPEATER_BOARD_SHORTNAME		"RP"

#define	SG_HPU_TYPE_SP_L2_REPEATER_BOARD	((3<<8)|3)	/* 0x303 */
#define	SG_HPU_TYPE_SP_L2_REPEATER_BOARD_STR  \
			"SP L2 Repeater Board"
#define	SG_HPU_TYPE_SP_L2_REPEATER_BOARD_ID	"RP"
#define	SG_HPU_TYPE_SP_L2_REPEATER_BOARD_SHORTNAME	"RP"

#define	SG_HPU_TYPE_FAN_TRAY_BAY	((4<<8)|0)	/* 0x400 */
#define	SG_HPU_TYPE_FAN_TRAY_BAY_STR  \
			"Fan Tray Bay"
#define	SG_HPU_TYPE_FAN_TRAY_BAY_ID	"FT"

#define	SG_HPU_TYPE_R24_IO_FOUR_FAN_TRAY	((4<<8)|1)	/* 0x401 */
#define	SG_HPU_TYPE_R24_IO_FOUR_FAN_TRAY_STR  \
			"R24 IO Four Fan Tray"
#define	SG_HPU_TYPE_R24_IO_FOUR_FAN_TRAY_ID	"FT"
#define	SG_HPU_TYPE_R24_IO_FOUR_FAN_TRAY_SHORTNAME	"FAN"

#define	SG_HPU_TYPE_R24_CPU_SIX_FAN_TRAY	((4<<8)|2)	/* 0x402 */
#define	SG_HPU_TYPE_R24_CPU_SIX_FAN_TRAY_STR  \
			"R24 CPU Six Fan Tray"
#define	SG_HPU_TYPE_R24_CPU_SIX_FAN_TRAY_ID	"FT"
#define	SG_HPU_TYPE_R24_CPU_SIX_FAN_TRAY_SHORTNAME	"FAN"

#define	SG_HPU_TYPE_RACK_FAN_TRAY	((4<<8)|3)	/* 0x403 */
#define	SG_HPU_TYPE_RACK_FAN_TRAY_STR  \
			"Rack Fan Tray"
#define	SG_HPU_TYPE_RACK_FAN_TRAY_ID	"FT"
#define	SG_HPU_TYPE_RACK_FAN_TRAY_SHORTNAME	"RACKFAN"

#define	SG_HPU_TYPE_R12_THREE_FAN_TRAY	((4<<8)|4)	/* 0x404 */
#define	SG_HPU_TYPE_R12_THREE_FAN_TRAY_STR  \
			"R12 Three Fan Tray"
#define	SG_HPU_TYPE_R12_THREE_FAN_TRAY_ID	"FT"
#define	SG_HPU_TYPE_R12_THREE_FAN_TRAY_SHORTNAME	"FAN"

#define	SG_HPU_TYPE_K12_IO_ONE_FAN_TRAY	((4<<8)|5)	/* 0x405 */
#define	SG_HPU_TYPE_K12_IO_ONE_FAN_TRAY_STR  \
			"K12 IO One Fan Tray"
#define	SG_HPU_TYPE_K12_IO_ONE_FAN_TRAY_ID	"FT"
#define	SG_HPU_TYPE_K12_IO_ONE_FAN_TRAY_SHORTNAME	"FAN"

#define	SG_HPU_TYPE_K12_CPU_THREE_FAN_TRAY	((4<<8)|6)	/* 0x406 */
#define	SG_HPU_TYPE_K12_CPU_THREE_FAN_TRAY_STR  \
			"K12 CPU Three Fan Tray"
#define	SG_HPU_TYPE_K12_CPU_THREE_FAN_TRAY_ID	"FT"
#define	SG_HPU_TYPE_K12_CPU_THREE_FAN_TRAY_SHORTNAME	"FAN"

#define	SG_HPU_TYPE_MD_TOP_IO_FAN_TRAY	((4<<8)|7)	/* 0x407 */
#define	SG_HPU_TYPE_MD_TOP_IO_FAN_TRAY_STR  \
			"MD Top I/O Fan Tray"
#define	SG_HPU_TYPE_MD_TOP_IO_FAN_TRAY_ID	"FT"
#define	SG_HPU_TYPE_MD_TOP_IO_FAN_TRAY_SHORTNAME	"FAN"

#define	SG_HPU_TYPE_SP_FAN_TRAY	((4<<8)|8)	/* 0x408 */
#define	SG_HPU_TYPE_SP_FAN_TRAY_STR  \
			"SP Fan Tray"
#define	SG_HPU_TYPE_SP_FAN_TRAY_ID	"FT"
#define	SG_HPU_TYPE_SP_FAN_TRAY_SHORTNAME	"FAN"

#define	SG_HPU_TYPE_MD_BOTTOM_IO_FAN_TRAY	((4<<8)|9)	/* 0x409 */
#define	SG_HPU_TYPE_MD_BOTTOM_IO_FAN_TRAY_STR  \
			"MD Bottom I/O Fan Tray"
#define	SG_HPU_TYPE_MD_BOTTOM_IO_FAN_TRAY_ID	"FT"
#define	SG_HPU_TYPE_MD_BOTTOM_IO_FAN_TRAY_SHORTNAME	"FAN"

#define	SG_HPU_TYPE_SP_CPCI_IO_BOARD	((5<<8)|3)	/* 0x503 */
#define	SG_HPU_TYPE_SP_CPCI_IO_BOARD_STR  \
			"SP CPCI I/O board"
#define	SG_HPU_TYPE_SP_CPCI_IO_BOARD_ID	"IB"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SGENV_TAG_H */
