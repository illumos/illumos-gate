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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Platform Power Management
 *
 * Register and bit definitions of the power-related parts
 */

#ifndef	_SYS_XCALPPM_REG_H
#define	_SYS_XCALPPM_REG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Registers accessed by the ppm driver.  These registers actually come
 * from different ASICs on the system and are collected for us
 * by the prom into a single device node.  These registers are:
 *
 *	BBC E* Control Register (other registers like E* Assert Change Time
 *	    or E* PLL Settle Time are offseted from this address)
 *	Mode Auxio Register
 *	SuperI/O Configuration Register
 *	SuperI/O GPIO Registers
 */
struct xcppmreg {
	volatile uint16_t *bbc_estar_ctrl;	/* set cpu clock rate */
	volatile uint32_t *bbc_assert_change;	/* set t1 cpu trans time */
	volatile uint32_t *bbc_pll_settle;	/* set t4 cpu trans time */
	volatile uint32_t *rio_mode_auxio;	/* transition cpu clock */
	volatile uint8_t *gpio_bank_sel_index;	/* index GPIO bank sel. */
	volatile uint8_t *gpio_bank_sel_data;	/* data GPIO bank select */
	volatile uint8_t *gpio_port1_data;	/* set LED */
	volatile uint8_t *gpio_port2_data;	/* set DC-DC, 1394, FET */
};

struct xcppmhndl {
	ddi_acc_handle_t	bbc_estar_ctrl;
	ddi_acc_handle_t	rio_mode_auxio;
	ddi_acc_handle_t	gpio_bank_select;
	ddi_acc_handle_t	gpio_data_ports;
};

/*
 * Register offsets
 */
#define	BBC_ESTAR_CTRL_OFFSET		0x0
#define	BBC_ASSERT_CHANGE_OFFSET	0x2
#define	BBC_PLL_SETTLE_OFFSET		0xa

#define	GPIO_BANK_SEL_INDEX_OFFSET	0x0
#define	GPIO_BANK_SEL_DATA_OFFSET	0x1

#define	GPIO_PORT1_DATA_OFFSET		0x0
#define	GPIO_PORT2_DATA_OFFSET		0x4

/*
 * Definitions for the RIO Mode Auxio register
 */
#define	RIO_BBC_ESTAR_MODE		0x800

/*
 * Index for SuperIO Configuration 2 register
 */
#define	SIO_CONFIG2_INDEX		0x22

/*
 * GPIO Data Port 1 bit assignments
 */
#define	LED	0x02		/* Controls front panel LED */

/*
 * GPIO Data Port 2 bit assignments
 */
#define	CPEN	0x02		/* Controls 1394 cable power [1 = on] */
#define	HIGHPWR	0x08		/* Enter/Leave low pwr mode [1 = high pwr] */
#define	DRVON	0x10		/* Controls pwr to internal drives [1 = on] */

/*
 * BBC timing registers are set according to "bbc_delay" variable
 * and adjusted based on current clock speed.
 */
extern int bbc_delay;				/* microsec */
#define	BBC_DELAY	(bbc_delay * 1000000)	/* nanosec */
#define	EXCAL_CLOCK	10			/* 10 nsec or 100 MHz */
#define	BBC_CLOCK	(2 * EXCAL_CLOCK)	/* BBC clock is half speed */

#define	XCPPM_BBC_DELAY(index)				\
	(index == 0) ? (BBC_DELAY/(BBC_CLOCK * 32)) :	\
	((index == 1) ? (BBC_DELAY/(BBC_CLOCK * 2)) :	\
	BBC_DELAY/BBC_CLOCK)

/*
 * BBC E* Control Reg bit masks
 */
#define	BBC_ESTAR_SLOW		0x20		/* 1/32 speed */
#define	BBC_ESTAR_MEDIUM	0x2		/* 1/2  speed */
#define	BBC_ESTAR_FAST		0x1		/* full speed */

/*
 * register access IO
 */
#define	XCPPM_CLRBIT		0x0
#define	XCPPM_SETBIT		0x1
#define	XCPPM_GETBIT		0x2

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_XCALPPM_REG_H */
