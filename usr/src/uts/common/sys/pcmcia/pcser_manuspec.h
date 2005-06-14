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

#ifndef _PCSER_MANUSPEC_H
#define	_PCSER_MANUSPEC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file describes any manufacturer-specific capabilities of the
 *	card.  These capabilities are stored in an array of structures
 *	and are keyed off of the card's manufacturer and card IDs; these
 *	come from the CISTPL_MANFID tuple.
 * We need this file since some cards have additional features that can
 *	not be specified in the CIS since there are not tuples to do so
 *	while other cards have a broken CIS which prevents them from
 *	being initialized properly.
 */

/*
 * Property used to provide manufacturer-specific parameter overrides.
 *	This property is typically specified in a .conf file.
 */
#define	PCSER_MODIFY_MANSPEC_PARAMS	"pcser_modify_manspec_params"

#define	PCSPP_DEBUG_PARSE_LINE		0x00000001
#define	PCSPP_DEBUG_SET_MSP		0x00000002
#define	PCSPP_DSPMATCH			0x00000004
#define	PCSPP_DISPLAY			0x10000000
#define	PCSPP_COMMENT			0x20000000

#define	PCSER_PARSE_QUOTE	'\''
#define	PCSER_PARSE_COMMENT	'#'
#define	PCSER_PARSE_ESCAPE	'\\'
#define	PCSER_PARSE_UNDERSCORE	'_'

/*
 * state defines for the valued variable state machine
 */
#define	PT_STATE_UNKNOWN	0
#define	PT_STATE_TOKEN		1
#define	PT_STATE_STRING_VAR	2
#define	PT_STATE_HEX_VAR	3
#define	PT_STATE_DEC_VAR	4
#define	PT_STATE_ESCAPE		5

/*
 * Flags for pcser_manuspec_t.flags
 *
 * Matching flags
 */
#define	PCSER_MATCH_MANUFACTURER	0x00000001	/* match manf ID */
#define	PCSER_MATCH_CARD		0x00000002	/* match card ID */
#define	PCSER_MATCH_VERS_1		0x00000004	/* match vers_1 */
#define	PCSER_MATCH_MASK		0x00000fff

/*
 * Parameter override flags
 */
#define	PCSER_MANSPEC_TXBUFSIZE		0x00001000	/* txbufsize valid */
#define	PCSER_MANSPEC_RXBUFSIZE		0x00002000	/* rxbufsize valid */
#define	PCSER_MANSPEC_FIFO_ENABLE	0x00004000	/* Tx/Rx FIFO valid */
#define	PCSER_MANSPEC_FIFO_DISABLE	0x00008000	/* Tx/Rx FIFO valid */
#define	PCSER_MANSPEC_AUTO_RTS		0x00010000	/* auto_rts valid */
#define	PCSER_MANSPEC_AUTO_CTS		0x00020000	/* auto_cts valid */
#define	PCSER_MANSPEC_READY_DELAY_1	0x00040000	/* delay before cfg */
#define	PCSER_MANSPEC_READY_DELAY_2	0x00080000	/* delay after cfg */
#define	PCSER_MANSPEC_CONFIG_INDEX	0x00100000	/* config index */
#define	PCSER_MANSPEC_CONFIG_ADDR	0x00200000	/* config address */
#define	PCSER_MANSPEC_CONFIG_PRESENT	0x00400000	/* regs present mask */
#define	PCSER_MANSPEC_NUM_IO_LINES	0x00800000	/* IO addr lines */
#define	PCSER_MANSPEC_NUM_IO_PORTS	0x01000000	/* num IO ports */
#define	PCSER_MANSPEC_IO_ADDR		0x02000000	/* IO address */
#define	PCSER_MANSPEC_CD_TIME		0x04000000	/* CD ignore time */
#define	PCSER_MANSPEC_IGN_CD_ON_OPEN	0x08000000	/* CD timer on open */

typedef struct pcser_manuspec_parse_tree_t {
	char		*token;	/* token to look for */
	int		state;	/* state machine state */
	unsigned	flags;	/* flags to set in manuspec struc */
	unsigned	ctl;	/* control flags */
	int		fmt;	/* data format type */
	void		*var;	/* pointer to manuspec struct var */
} pcser_manuspec_parse_tree_t;

typedef struct pcser_manuspec_t {
	uint32_t	flags;		/* matching flags */
	uint32_t	manufacturer;	/* manufacturer ID */
	uint32_t	card;		/* card ID */
	uint32_t	txbufsize;	/* Tx FIFO buffer size */
	uint32_t	rxbufsize;	/* Rx FIFO buffer size */
	uint32_t	fifo_enable;	/* Tx/Rx FIFO enable code */
	uint32_t	fifo_disable;	/* Tx/Rx FIFO disable code */
	uint32_t	auto_rts;	/* Auto RTS enable code */
	uint32_t	auto_cts;	/* Auto CTS enable code */
	uint32_t	ready_delay_1;	/* READY delay before config in mS */
	uint32_t	ready_delay_2;	/* READY delay after config in mS */
	uint32_t	config_index;	/* config index */
	uint32_t	config_address;	/* config regs address */
	uint32_t	present;	/* config regs present mask */
	uint32_t	addr_lines;	/* IO addr lines decoded */
	uint32_t	length;		/* length of IO range */
	uint32_t	modem_base;	/* base of UART registers */
	uint32_t	CD_ignore_time;	/* mS to ignore CD changes */
	char		*vers_1;	/* VERS_1 string */
} pcser_manuspec_t;

pcser_manuspec_t pcser_manuspec[] = {
	/* Sun/USRobotics Worldport modem */
	{	(PCSER_MATCH_MANUFACTURER |	/* matching flags */
			PCSER_MATCH_CARD |
			PCSER_MANSPEC_TXBUFSIZE |
			PCSER_MANSPEC_RXBUFSIZE |
			PCSER_MANSPEC_FIFO_ENABLE |
			PCSER_MANSPEC_FIFO_DISABLE |
			PCSER_MANSPEC_AUTO_RTS),
		0x0115,	/* manufacturer ID */
		0x3330,	/* card ID */
		64,	/* Tx FIFO buffer size */
		64,	/* Rx FIFO buffer size */
		0x0e1,	/* Tx/Rx FIFO enable code */
		0,	/* Tx/Rx FIFO disable code */
		0x010,	/* Auto RTS enable code */
		0,	/* Auto CTS enable code */
		0,	/* READY_1 delay before config in mS */
		0,	/* READY_2 delay after config in mS */
		0,	/* config index */
		0,	/* config regs address */
		0,	/* config regs present mask */
		0,	/* IO addr lines decoded */
		0,	/* length of IO range */
		0,	/* base of UART registers */
		0,	/* mS to ignore CD changes */
		NULL	/* VERS_1 string */
	},
	/* USRobotics Worldport modem with broken CIS */
	{	(PCSER_MATCH_VERS_1 |	/* matching flags */
			PCSER_MANSPEC_TXBUFSIZE |
			PCSER_MANSPEC_RXBUFSIZE |
			PCSER_MANSPEC_READY_DELAY_1),
		0,	/* manufacturer ID */
		0,	/* card ID */
		1,	/* Tx FIFO buffer size */
		1,	/* Rx FIFO buffer size */
		0,	/* Tx/Rx FIFO enable code */
		0,	/* Tx/Rx FIFO disable code */
		0,	/* Auto RTS enable code */
		0,	/* Auto CTS enable code */
		10000,	/* READY_1 delay before config in mS */
		0,	/* READY_2 delay after config in mS */
		0,	/* config index */
		0,	/* config regs address */
		0,	/* config regs present mask */
		0,	/* IO addr lines decoded */
		0,	/* length of IO range */
		0,	/* base of UART registers */
		0,	/* mS to ignore CD changes */
		"Intel MODEM 2400+ iNC110US A-0"	/* VERS_1 string */
	},
};

#define	PT_VAR_OFFSET(v)	((void *)&(((pcser_manuspec_t *)0)->v))
/*
 * The PT_VAR_* values specify what type of variable should be
 *	extracted from the token parameters. We know how to
 *	extract hex and decimal unsigned values and strings.
 */
#define	PT_VAR_HEX		0x0001
#define	PT_VAR_DEC		0x0002
#define	PT_VAR_STRING		0x0003
#define	PT_VAR_BOOL		0x0004
#define	PT_VAR_HEX_CTL		0x0005

/*
 * PT_VAR_BOOL has several sub-modes defined below
 */
#define	PT_VAR_BOOL_NONE		0x0000
#define	PT_VAR_BOOL_DISPLAY_ON		0x0001
#define	PT_VAR_BOOL_DISPLAY_OFF		0x0002
#define	PT_VAR_HEX_CTL_DEBUG		0x0003
#define	PT_VAR_BOOL_DEBUG_STAT		0x0004
#define	PT_VAR_BOOL_COMMENT_ON		0x0005
#define	PT_VAR_BOOL_COMMENT_OFF		0x0006
#define	PT_VAR_HEX_CTL_PCSER_DEBUG	0x0007
#define	PT_VAR_BOOL_DSPMATCH_ON		0x0008
#define	PT_VAR_BOOL_DSPMATCH_OFF	0x0009
#define	PT_VAR_BOOL_CD_IGN		0x000a

/*
 * Initialize the parse tree structure
 */
pcser_manuspec_parse_tree_t pcser_manuspec_parse_tree[] = {

	{	"flags",		PT_STATE_HEX_VAR,
		0,				PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(flags)		},
	{	"manufacturer",		PT_STATE_HEX_VAR,
		PCSER_MATCH_MANUFACTURER,	PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(manufacturer)	},
	{	"card",			PT_STATE_HEX_VAR,
		PCSER_MATCH_CARD,		PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(card)		},
	{	"vers_1",		PT_STATE_STRING_VAR,
		PCSER_MATCH_VERS_1,		PT_VAR_BOOL_NONE,
		PT_VAR_STRING,		PT_VAR_OFFSET(vers_1)		},
	{	"txbufsize",		PT_STATE_HEX_VAR,
		PCSER_MANSPEC_TXBUFSIZE,	PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(txbufsize)	},
	{	"rxbufsize",		PT_STATE_HEX_VAR,
		PCSER_MANSPEC_RXBUFSIZE,	PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(rxbufsize)	},
	{	"fifo_enable",		PT_STATE_HEX_VAR,
		PCSER_MANSPEC_FIFO_ENABLE,	PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(fifo_enable)	},
	{	"fifo_disable",		PT_STATE_HEX_VAR,
		PCSER_MANSPEC_FIFO_DISABLE,	PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(fifo_disable)	},
	{	"auto_rts",		PT_STATE_HEX_VAR,
		PCSER_MANSPEC_AUTO_RTS,		PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(auto_rts)		},
	{	"auto_cts",		PT_STATE_HEX_VAR,
		PCSER_MANSPEC_AUTO_CTS,		PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(auto_cts)		},
	{	"ready_delay_1",	PT_STATE_DEC_VAR,
		PCSER_MANSPEC_READY_DELAY_1,	PT_VAR_BOOL_NONE,
		PT_VAR_DEC,		PT_VAR_OFFSET(ready_delay_1)	},
	{	"ready_delay_2",	PT_STATE_DEC_VAR,
		PCSER_MANSPEC_READY_DELAY_2,	PT_VAR_BOOL_NONE,
		PT_VAR_DEC,		PT_VAR_OFFSET(ready_delay_2)	},
	{	"config_index",		PT_STATE_HEX_VAR,
		PCSER_MANSPEC_CONFIG_INDEX,	PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(config_index)	},
	{	"config_address",	PT_STATE_HEX_VAR,
		PCSER_MANSPEC_CONFIG_ADDR,	PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(config_address)	},
	{	"config_regs_present",	PT_STATE_HEX_VAR,
		PCSER_MANSPEC_CONFIG_PRESENT,	PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(present)	},
	{	"IO_addr_lines",	PT_STATE_HEX_VAR,
		PCSER_MANSPEC_NUM_IO_LINES,	PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(addr_lines)	},
	{	"IO_num_ports",		PT_STATE_HEX_VAR,
		PCSER_MANSPEC_NUM_IO_PORTS,	PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(length)		},
	{	"IO_base_addr",		PT_STATE_HEX_VAR,
		PCSER_MANSPEC_IO_ADDR,		PT_VAR_BOOL_NONE,
		PT_VAR_HEX,		PT_VAR_OFFSET(modem_base)	},
	{	"CD_ignore_time",	PT_STATE_DEC_VAR,
		PCSER_MANSPEC_CD_TIME,		PT_VAR_BOOL_NONE,
		PT_VAR_DEC,		PT_VAR_OFFSET(CD_ignore_time)	},
	{	"ignore_CD_on_open",	PT_STATE_TOKEN,
		PCSER_MANSPEC_IGN_CD_ON_OPEN,	PT_VAR_BOOL_CD_IGN,
		PT_VAR_BOOL,		0				},
	{	"display_on",		PT_STATE_TOKEN,
		0,				PT_VAR_BOOL_DISPLAY_ON,
		PT_VAR_BOOL,		0				},
	{	"display_match_on",	PT_STATE_TOKEN,
		0,				PT_VAR_BOOL_DSPMATCH_ON,
		PT_VAR_BOOL,		0				},
	{	"comment_on",		PT_STATE_TOKEN,
		0,				PT_VAR_BOOL_COMMENT_ON,
		PT_VAR_BOOL,		0				},
	{	"display_off",		PT_STATE_TOKEN,
		0,				PT_VAR_BOOL_DISPLAY_OFF,
		PT_VAR_BOOL,		0				},
	{	"display_match_off",	PT_STATE_TOKEN,
		0,				PT_VAR_BOOL_DSPMATCH_OFF,
		PT_VAR_BOOL,		0				},
	{	"comment_off",		PT_STATE_TOKEN,
		0,				PT_VAR_BOOL_COMMENT_OFF,
		PT_VAR_BOOL,		0				},
	{	"debug_stat",		PT_STATE_TOKEN,
		0,				PT_VAR_BOOL_DEBUG_STAT,
		PT_VAR_BOOL,		0				},
	{	"debug",		PT_STATE_HEX_VAR,
		0,				PT_VAR_HEX_CTL_DEBUG,
		PT_VAR_HEX_CTL,		0				},
	{	"pcser_debug",		PT_STATE_HEX_VAR,
		0,				PT_VAR_HEX_CTL_PCSER_DEBUG,
		PT_VAR_HEX_CTL,		0				},
};

#ifdef	__cplusplus
}
#endif

#endif	/* _PCSER_MANUSPEC_H */
