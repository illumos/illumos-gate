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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_GRBEEP_H
#define	_SYS_GRBEEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * grbeep.h : Grover beep driver header file.
 */

/*
 * beeper start and stop values
 */
#define	GRBEEP_START		0x03
#define	GRBEEP_STOP		0x00

/*
 * beeper control register value
 */
#define	GRBEEP_CONTROL		0xb6

/*
 * beeper 8354 input frequency is 1.193 Mhz.
 * The value to be written in the timer
 * register is the frequency divisor.
 * The formula to find freq. divisoer would be
 *
 * 	divisor = GRBEEP_INPUT_FREQ / freq
 *
 */
#define	GRBEEP_INPUT_FREQ	1193000
#define	GRBEEP_DIVISOR_MAX	1193000
#define	GRBEEP_DIVISOR_MIN	18

/* Mode values */
#define	GRBEEP_ON		0x01
#define	GRBEEP_OFF		0x00

typedef volatile struct grbeep_freq_regs {

	/* Frequency divisor register */
	uint8_t		grbeep_freq_regs_divisor;

	/* Freqquency control register */
	uint8_t		grbeep_freq_regs_control;

} grbeep_freq_regs_t;


/*
 * Beep driver state structure
 */
typedef struct grbeep_state {

	/* Dip of grbeep device */
	dev_info_t		*grbeep_dip;

	/* Frequency control and frequency divisor registers */
	grbeep_freq_regs_t	*grbeep_freq_regs;

	/* Frequency control and frequency divisor reg handle */
	ddi_acc_handle_t	grbeep_freq_regs_handle;

	/* Beep start/stop register */
	uint8_t			*grbeep_start_stop_reg;

	/* Beep start/stop register handle */
	ddi_acc_handle_t	grbeep_start_stop_reg_handle;

	/* If beeper is active or not */
	int			grbeep_mode;

} grbeep_state_t;

#define	GRBEEP_WRITE_FREQ_CONTROL_REG(val) \
	ddi_put8(grbeeptr->grbeep_freq_regs_handle, \
	((uint8_t *)&grbeeptr->grbeep_freq_regs->grbeep_freq_regs_control), \
		((int8_t)(val)))

#define	GRBEEP_WRITE_FREQ_DIVISOR_REG(val) \
	ddi_put8(grbeeptr->grbeep_freq_regs_handle, \
	((uint8_t *)&grbeeptr->grbeep_freq_regs->grbeep_freq_regs_divisor), \
		((int8_t)(val)))

#define	GRBEEP_WRITE_START_STOP_REG(val) \
	ddi_put8(grbeeptr->grbeep_start_stop_reg_handle, \
		((uint8_t *)grbeeptr->grbeep_start_stop_reg), \
		((int8_t)(val)))

#define	GRBEEP_UNIT(dev)	(getminor((dev)))

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GRBEEP_H */
