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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_BBC_BEEP_H
#define	_SYS_BBC_BEEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * bbc_beep.h : BBC beep driver's header file.
 */

/* Keyboard Beep Control Register values */
#define	BBC_BEEP_ON		0x01
#define	BBC_BEEP_OFF		0x00

/*
 * Keyboard Beep Counter Register value :
 * The most significant of [18..10] selects the bit of
 * the BBC free running counter (updated on half the system
 * clock) that is used to generate the audio signal. So, bit[10]
 * generates a signal at 1/(2^12) the system frequency, and
 * bit[18], at 1/(2^20). So if s = system frequency(in MHz),
 * it can generate frequencies in the range (s >> 10) Hz to
 * (s >> 2) Hz.
 */
#define	BBC_BEEP_MIN_SHIFT	20
#define	BBC_BEEP_MAX_SHIFT	12
#define	BBC_BEEP_MSBIT		18

typedef volatile struct bbc_beep_regs {

	/* Beep ON/OFF register */
	uint8_t		bbc_beep_control;

	/* Reserved */
	uint8_t		reserved;

	/* Register to set the frequency */
	uint8_t		bbc_beep_counter[4];

} bbc_beep_regs_t;

/*
 * Beep driver state structure
 */
typedef struct bbc_beep_state {

	/* Dip of bbc_beep device */
	dev_info_t		*bbc_beep_dip;

	/* Beep registers */
	bbc_beep_regs_t		*bbc_beep_regsp;

	/* Register handle */
	ddi_acc_handle_t	bbc_beep_regs_handle;

	/* If beeper is active or not */
	int			bbc_beep_mode;

	} bbc_beep_state_t;

#define	BEEP_WRITE_CTRL_REG(val) ddi_put8(bbc_beeptr->bbc_beep_regs_handle, \
		((uint8_t *)&bbc_beeptr->bbc_beep_regsp->bbc_beep_control), \
					((int8_t)(val)))
#define	BEEP_WRITE_COUNTER_REG(no, val) \
		ddi_put8(bbc_beeptr->bbc_beep_regs_handle, \
	((uint8_t *)&bbc_beeptr->bbc_beep_regsp->bbc_beep_counter[no]), \
					((int8_t)(val)))

#define	BEEP_UNIT(dev)	(getminor((dev)))

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BBC_BEEP_H */
