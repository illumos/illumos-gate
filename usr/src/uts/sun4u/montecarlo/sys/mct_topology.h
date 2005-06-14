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
 * Copyright (c) 1999, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MONTECARLO_SYS_MCT_TOPOLOGY_H
#define	_MONTECARLO_SYS_MCT_TOPOLOGY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * mct_topology.h
 * MonteCarlo / Tonga topology structures and types for the scsb driver
 * and its kstat structure "env_topology", to be available to applications
 * like envmond and snmp agents.
 */
/*
 * SCB information also defined in scsb.h, which file is not available to
 * applications.
 */
#define	SCB_P10_NOK_LED_REGS	4
#define	SCB_P10_OK_LED_REGS	4
#define	SCB_P10_BLINK_LED_REGS	2
#define	SCB_P10_LED_REGS	10
#define	SCB_P15_NOK_LED_REGS	3
#define	SCB_P15_OK_LED_REGS	3
#define	SCB_P15_BLINK_LED_REGS	3
#define	SCB_P15_LED_REGS	9

/* Save this existing definition, but use it as the MAX */
#define	SCSB_LEDDATA_REGISTERS	SCB_P10_LED_REGS

#define	MC_MAX_SLOTS		8	/* CPU, ALRM, cPCI Slots */
#define	MC_MAX_FAN		2
#define	MC_MAX_PDU		2
#define	MC_MAX_PS		2
#define	MC_MAX_DISK		3
#define	MC_MAX_SCB		1
#define	MC_MAX_AC		1
#define	MC_MAX_CFTM		1
#define	MC_MAX_CRTM		1
#define	MC_MAX_PRTM		1

#define	TG_MAX_SLOTS		5	/* CPU, ALRM, cPCI Slots */
#define	TG_MAX_FAN		2
#define	TG_MAX_PS		1
#define	TG_MAX_PDU		1
#define	TG_MAX_DISK		1
#define	TG_MAX_SCB		1
#define	TG_MAX_AC		1
#define	TG_MAX_CFTM		1
#define	TG_MAX_CRTM		1
#define	TG_MAX_PRTM		1

/*
 * Maximum number of FRUs in MCT systems,
 * used for sizeof fru_id_table[] and index check
 */
#define	MCT_MAX_FRUS		32

/*
 * The I2C addresses of System I2C devices
 * from "MonteCarlo: Programming Interface Specifications" Version 0.9
 */
#define	MCT_I2C_CPUPWR		0x72
#define	MCT_I2C_FAN1		0x74
#define	MCT_I2C_FAN2		0x76
#define	MCT_I2C_FAN3		0x78
#define	MCT_I2C_PS1		0x7c
#define	MCT_I2C_PS2		0x7e
#define	MCT_I2C_SCB		0x80
#define	MCT_I2C_CPUTEMP		0x9e

/*
 * CFG1_MPID masks
 */
#define	SCTRL_MPID_MASK			0xf
#define	SCTRL_MPID_HALF			0x0
#define	SCTRL_MPID_QUARTER		0x1
#define	SCTRL_MPID_QUARTER_NODSK	0x3

/*
 * Interrupt Event Codes
 * Also used by "scsb" to locate fruid_table index,
 * so the order is very important.
 */
#define	SCTRL_EVENT_NONE		0x0000
#define	SCTRL_EVENT_SLOT1		0x00000001
#define	SCTRL_EVENT_SLOT2		0x00000002
#define	SCTRL_EVENT_SLOT3		0x00000004
#define	SCTRL_EVENT_SLOT4		0x00000008
#define	SCTRL_EVENT_SLOT5		0x00000010
#define	SCTRL_EVENT_SLOT6		0x00000020
#define	SCTRL_EVENT_SLOT7		0x00000040
#define	SCTRL_EVENT_SLOT8		0x00000080
#define	SCTRL_EVENT_SLOT9		0x00000100
#define	SCTRL_EVENT_SLOT10		0x00000200
#define	SCTRL_EVENT_PDU1		0x00000400
#define	SCTRL_EVENT_PDU2		0x00000800
#define	SCTRL_EVENT_PS1			0x00001000
#define	SCTRL_EVENT_PS2			0x00002000
#define	SCTRL_EVENT_DISK1		0x00004000
#define	SCTRL_EVENT_DISK2		0x00008000
#define	SCTRL_EVENT_DISK3		0x00010000
#define	SCTRL_EVENT_FAN1		0x00020000
#define	SCTRL_EVENT_FAN2		0x00040000
#define	SCTRL_EVENT_FAN3		0x00080000
#define	SCTRL_EVENT_ALARM		0x00100000
#define	SCTRL_EVENT_SCB			0x00200000
#define	SCTRL_EVENT_SSB			0x00400000
#define	SCTRL_EVENT_CRTM		0x00800000
#define	SCTRL_EVENT_CFTM		0x01000000
#define	SCTRL_EVENT_PRTM		0x02000000
#define	SCTRL_EVENT_PWRDWN		0x04000000
#define	SCTRL_EVENT_REPLACE		0x08000000
#define	SCTRL_EVENT_ALARM_INT		0x10000000
#define	SCTRL_EVENT_ALARM_INSERTION	0x20000000
#define	SCTRL_EVENT_ALARM_REMOVAL	0x40000000
#define	SCTRL_EVENT_OTHER		0x80000000



typedef	uchar_t		topo_id_t;
typedef	uchar_t		fru_id_t;
typedef	uint16_t	fru_version_t;
typedef	uint16_t	fru_max_t;
typedef	uint16_t	scsb_unum_t;

typedef	enum {
	MCT_HEALTH_NA	= 0,
	MCT_HEALTH_OK	= 1,
	MCT_HEALTH_NOK	= 2
} fru_health_t;

/*
 * Known MC/Tg Slot occupants, and UNKN for unknown
 * NOTE: the CTC occupant is the CFTM FRU type on MonteCarlo
 */
typedef enum {
	OC_UNKN	= 0,
	OC_CPU	= 1,
	OC_AC	= 2,
	OC_BHS	= 3,
	OC_FHS	= 4,
	OC_HAHS	= 5,
	OC_QFE	= 6,
	OC_FRCH	= 7,
	OC_COMBO = 8,
	OC_PMC	= 9,
	OC_ATM	= 10,
	OC_CTC	= 11
} mct_slot_occupant_t;

typedef enum {
	SLOT	= 0,
	PDU	= 1,
	PS	= 2,
	DISK	= 3,
	FAN	= 4,
	ALARM	= 5,
	SCB	= 6,
	SSB	= 7,
	CFTM	= 8,
	CRTM	= 9,
	PRTM	= 10,
	MIDPLANE = 11
} scsb_utype_t;

#define	SCSB_UNIT_TYPES		11	/* w/o MIDPLANE	*/

typedef enum scsb_fru_status {
	FRU_NOT_PRESENT,
	FRU_PRESENT,
	FRU_NOT_AVAILABLE
} scsb_fru_status_t;

typedef enum {
	SWAP_NOT, SWAP_BASIC, SWAP_FULL, SWAP_HA
} cpci_swap_type_t;

typedef struct fru_options {
	char			*board_name;
	cpci_swap_type_t	swap_type;
	struct fru_options	*next;
} fru_options_t;

typedef struct fru_i2c_info {
	uchar_t		syscfg_reg;
	uchar_t		syscfg_bit;
	uchar_t		ledata_reg;
	uchar_t		ledata_bit;
	uchar_t		blink_reg;
	uchar_t		blink_bit;
} fru_i2c_info_t;

typedef struct fru_info {
	scsb_fru_status_t fru_status;	/* FRU present status		*/
	scsb_unum_t	fru_unit;	/* FRU external unit number	*/
	scsb_utype_t	fru_type;	/* also an index to FRU lists	*/
	fru_id_t	fru_id;		/* I2C address, SCSIID, Slot Num */
	fru_version_t	fru_version;	/* version number where possible */
	fru_options_t	*type_list;	/* list of possible boards for slots */
	fru_i2c_info_t	*i2c_info;	/* for I2C devices		*/
	struct fru_info	*next;
} fru_info_t;

struct system_info {
	fru_info_t	mid_plane;	/* one always present		*/
	fru_max_t	max_units[SCSB_UNIT_TYPES];
	fru_info_t	*fru_info_list[SCSB_UNIT_TYPES];
};

/*
 * scsb kstat types
 */
#define	SCSB_KS_LEDDATA		"scsb_leddata"
#define	SCSB_KS_STATE		"scsb_state"
#define	SCSB_KS_EVC_REGISTER	"scsb_evc_register"
#define	SCSB_KS_TOPOLOGY	"env_topology"

typedef struct ks_fru_info {
	scsb_fru_status_t fru_status;	/* FRU presence/availability status  */
	scsb_unum_t	fru_unit;	/* FRU external unit number	*/
	scsb_utype_t	fru_type;	/* and occupant type for solts	*/
	fru_id_t	fru_id;		/* I2C address, SCSIID, Slot Num */
	fru_version_t	fru_version;	/* version number where possible */
	fru_health_t	fru_health;	/* From NOK LED, if available	*/
} ks_fru_info_t;

typedef union scsb_leddata {
	uchar_t		scb_led_regs[SCSB_LEDDATA_REGISTERS];
	union {
		struct {
			uchar_t	nok_leds[SCB_P10_NOK_LED_REGS];
			uchar_t	 ok_leds[SCB_P10_OK_LED_REGS];
			uchar_t	blink_leds[SCB_P10_BLINK_LED_REGS];
		} p10;
		struct {
			uchar_t	nok_leds[SCB_P15_NOK_LED_REGS];
			uchar_t	 ok_leds[SCB_P15_OK_LED_REGS];
			uchar_t	blink_leds[SCB_P15_BLINK_LED_REGS];
		} p15;
	} leds;
} scsb_ks_leddata_t;

typedef struct {
	uint8_t		scb_present;		/* SCB is present	  */
	uint8_t		ssb_present;		/* SSB is present	  */
	uint8_t		scsb_frozen;		/* SCB swap state	  */
	uint8_t		scsb_mode;		/* driver access mode	  */
	uint8_t		unused_1;
	uint8_t		unused_2;
	uint8_t		unused_3;
	uint8_t		unused_4;
	uint32_t	event_code;		/* event code bit map	  */
} scsb_ks_state_t;

typedef struct {
	ks_fru_info_t	mid_plane;
	fru_max_t	max_units[SCSB_UNIT_TYPES];
	ks_fru_info_t	mct_slots[MC_MAX_SLOTS];
	ks_fru_info_t	mct_pdu[MC_MAX_PDU];
	ks_fru_info_t	mct_ps[MC_MAX_PS];
	ks_fru_info_t	mct_disk[MC_MAX_DISK];
	ks_fru_info_t	mct_fan[MC_MAX_FAN];
	ks_fru_info_t	mct_scb[MC_MAX_SCB];
	ks_fru_info_t	mct_ssb[MC_MAX_SCB];
	ks_fru_info_t	mct_alarm[MC_MAX_AC];
	ks_fru_info_t	mct_cftm[MC_MAX_CFTM];
	ks_fru_info_t	mct_crtm[MC_MAX_CRTM];
	ks_fru_info_t	mct_prtm[MC_MAX_PRTM];
} mct_topology_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _MONTECARLO_SYS_MCT_TOPOLOGY_H */
