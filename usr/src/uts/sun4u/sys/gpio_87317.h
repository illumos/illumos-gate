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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_GPIO_87317_H
#define	_SYS_GPIO_87317_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/* ioctl commands - ioctl(..., int request, ...) */
#define	GPIO_CMD_SET_BITS	0 /* gpio_reg[bank][offset] |= gpio_data */
#define	GPIO_CMD_CLR_BITS	1 /* gpio_reg[bank][offset] &= ~gpio_data */
#define	GPIO_CMD_GET		2 /* gpio_data = gpio_reg[bank][offset] */
#define	GPIO_CMD_SET		3 /* gpio_reg[bank][offset] = gpio_data */

/* SuperIO gpio bank 0 (gpio_bank=0) register offsets (gpio_offset) */
#define	GPIO_87317_PORT1_DATA		0	/* port 1 data */
#define	GPIO_87317_PORT1_DIR		1	/* port 1 direction */
#define	GPIO_87317_PORT1_OUT		2	/* port 1 output type */
#define	GPIO_87317_PORT1_CTRL		3	/* port 1 pull-up control */
#define	GPIO_87317_PORT2_DATA		4	/* port 2 data */
#define	GPIO_87317_PORT2_DIR		5	/* port 2 direction */
#define	GPIO_87317_PORT2_OUT		6	/* port 2 output type */
#define	GPIO_87317_PORT2_CTRL		7	/* port 2 pull-up control */

/* SuperIO gpio bank 1 (gpio_bank=1) register offsets (gpio_offset) */
#define	GPIO_87317_PORT1_LOCK		0	/* port 1 lock */
#define	GPIO_87317_PORT1_POLARITY	1	/* port 1 polarity */
#define	GPIO_87317_PORT1_IN2OUT		2	/* port 1 in to out */
/* offset 3 is reserved */
#define	GPIO_87317_PORT3_DATA		4	/* port 3 data */
#define	GPIO_87317_PORT3_DIR		5	/* port 3 direction */
#define	GPIO_87317_PORT3_OUT		6	/* port 3 output type */
#define	GPIO_87317_PORT3_CTRL		7	/* port 3 pull-up control */

/* ioctl operation structure - ioctl(..., void *arg) */
typedef struct gpio_87317_op_s {
	int	gpio_bank;	/* identify gpio bank: 0 or 1 */
	uint8_t	gpio_offset;	/* offset of gpio register: 0-7 */
	uint8_t	gpio_data;	/* bits to set/clear; or data to read/write */
} gpio_87317_op_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_GPIO_87317_H */
