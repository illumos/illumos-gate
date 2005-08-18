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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PCF8584_H
#define	_PCF8584_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/promif.h>

/*
 * S1 control
 */
#define	S1_ACK	0x01
#define	S1_STO	0x02
#define	S1_STA	0x04
#define	S1_ENI	0x08
#define	S1_ES2	0x10
#define	S1_ES1	0x20
#define	S1_ESO	0x40

/*
 * S1 status
 */
#define	S1_BBN	0x01
#define	S1_LAB	0x02
#define	S1_AAS	0x04
#define	S1_AD0	0x08
#define	S1_LRB	0x08
#define	S1_BER	0x10
#define	S1_STS	0x20

/*
 * S1 control/status
 */

#define	S1_PIN	0x80

/*
 * This has to be OR'ed in with the address for
 * I2C read transactions.
 */
#define	I2C_READ	0x01

/*
 * S0 initialization bytes
 */

#define	S0_OWN 0x55
#define	S0_CLK 0x1C		/* System clock = 12 MHz, SCL = 90 KHz) */

#define	PCF8584_INIT_WAIT 200000	/* 200 ms */
#define	DUMMY_ADDR 0x20
#define	DUMMY_DATA 0x00

#define	MONITOR_ADDRESS	0x0

#define	S1_START	(S1_PIN | S1_ESO | S1_STA | S1_ACK)
#define	S1_STOP		(S1_PIN | S1_ESO | S1_STO | S1_ACK)
#define	S1_START2	(S1_ESO | S1_STA | S1_ACK)

/*
 * printing levels
 */
#define	PRT_SELECT	0x01
#define	PRT_INTR	0x02
#define	PRT_INIT	0x04
#define	PRT_TRAN	0x08
#define	PRT_POLL	0x10
#define	PRT_BUFFONLY	0x100
#define	PRT_PROM	0x200

/*
 * states for the I2C state machine.
 */
enum tran_state {
	TRAN_STATE_NULL,
	TRAN_STATE_WR,
	TRAN_STATE_RD,
	TRAN_STATE_WR_RD,
	TRAN_STATE_START,
	TRAN_STATE_DUMMY_DATA,
	TRAN_STATE_DUMMY_RD
};

/*
 * different implementations of pcf8584
 */
enum impl_type {
	GENERIC,
	BBC,
	PIC16F747
};

typedef struct pcf8584_regs {
	uint8_t *pcf8584_regs_s0;
	uint8_t *pcf8584_regs_s1;
} pcf8584_regs_t;

typedef struct pcf8584 {
	dev_info_t		*pcf8584_dip;
	int			pcf8584_attachflags;
	kcondvar_t		pcf8584_cv;
	kmutex_t		pcf8584_imutex;
	kcondvar_t		pcf8584_icv;
	ddi_iblock_cookie_t	pcf8584_icookie;
	int			pcf8584_mode;
	int			pcf8584_open;
	int			pcf8584_busy;
	int			pcf8584_bus;
	int			pcf8584_cur_status;
	dev_info_t		*pcf8584_nexus_dip;
	i2c_transfer_t		*pcf8584_cur_tran;
	dev_info_t		*pcf8584_cur_dip;
	pcf8584_regs_t		pcf8584_regs;
	ddi_acc_handle_t	pcf8584_rhandle;
	uint8_t			*pcf8584_b_reg;
	ddi_acc_handle_t	pcf8584_b_rhandle;
	enum tran_state		pcf8584_tran_state;
	char			pcf8584_name[12];
	enum impl_type		pcf8584_impl_type;
	uint32_t		pcf8584_impl_delay;
} pcf8584_t;

/*
 * i2c_parent_pvt contains info that is chip specific
 * and is stored on the child's devinfo parent private data.
 */
typedef struct pcf8584_ppvt {
	int pcf8584_ppvt_bus; /* xcal's bbc implmentation multiplexes */
			    /* multiple I2C busses on a single set of */
			    /* registers.  this tells it what bus to */
			    /* use  */
	int pcf8584_ppvt_addr; /* address of I2C device */
} pcf8584_ppvt_t;

#define	PCF8584_PIL			4
#define	PCF8584_POLL_MODE		1
#define	PCF8584_INTR_MODE		2
#define	PCF8584_INITIAL_SOFT_SPACE	4
#define	PCF8584_GENERIC_DELAY		0
#define	PCF8584_PIC16F747_DELAY		10

/*
 * generic interrupt return values
 */
#define	I2C_COMPLETE	2
#define	I2C_PENDING	3

/*
 * Transfer status values
 */
#define	PCF8584_TRANSFER_NEW	1
#define	PCF8584_TRANSFER_ON	2
#define	PCF8584_TRANSFER_OVER	3

/*
 * Attach flags
 */
#define	ADD_INTR	0x01
#define	ADD_PVT		0x02
#define	SETUP_REGS	0x04
#define	NEXUS_REGISTER	0x08
#define	PROP_CREATE	0x10
#define	IMUTEX		0x20
#define	ALLOCATE_PVT	0x40
#define	MINOR_NODE	0x80

#ifdef	__cplusplus
}
#endif

#endif /* _PCF8584_H */
