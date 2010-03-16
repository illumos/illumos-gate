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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Purpose: Definitions for the CS 4281 AC97 driver
 */
/*
 * This file is part of Open Sound System
 *
 * Copyright (C) 4Front Technologies 1996-2009.
 *
 * This software is released under CDDL 1.0 source license.
 * See the COPYING file included in the main directory of this source
 * distribution for the license terms and conditions.
 */
#ifndef	AUDIOP16X_H
#define	AUDIOP16X_H

#define	P16X_NAME		"audiop16x"

#define	P16X_NUM_PORT	2

#define	CREATIVE_VENDOR_ID	0x1102
#define	SB_P16X_ID		0x0006

typedef struct _p16x_dev_t p16x_dev_t;
typedef struct _p16x_port_t p16x_port_t;

struct _p16x_port_t
{
	p16x_dev_t 		*dev;
	audio_engine_t 		*engine;

	caddr_t			base;

	int			port_num;
#define	P16X_PLAY		0
#define	P16X_REC		1
	ddi_dma_handle_t	buf_dmah;	/* dma for buffers */
	ddi_acc_handle_t	buf_acch;
	uint32_t		buf_paddr;
	caddr_t			buf_kaddr;
	size_t			buf_size;
	uint32_t		buf_frames;
	int			syncdir;
	int			nchan;
	uint64_t		count;
	uint32_t		offset;
};

struct _p16x_dev_t
{
	dev_info_t		*dip;
	audio_dev_t		*adev;
	ac97_t			*ac97;
	boolean_t		suspended;
	ddi_acc_handle_t	pcih;
	ddi_acc_handle_t	regsh;
	caddr_t			base;
	kmutex_t		mutex;	/* For low level routines */

	p16x_port_t 		*port[P16X_NUM_PORT];
};

#define	INL(dev, reg)	\
	ddi_get32(dev->regsh, (void *)((char *)dev->base+(reg)))
#define	INW(dev, reg)	\
	ddi_get16(dev->regsh, (void *)((char *)dev->base+(reg)))
#define	INB(dev, reg)	\
	ddi_get8(dev->regsh, (void *)((char *)dev->base+(reg)))

#define	OUTL(dev, val, reg)	\
	ddi_put32(dev->regsh, (void *)((char *)dev->base+(reg)), (val))
#define	OUTW(dev, val, reg)	\
	ddi_put16(dev->regsh, (void *)((char *)dev->base+(reg)), (val))
#define	OUTB(dev, val, reg)	\
	ddi_put8(dev->regsh, (void *)((char *)dev->base+(reg)), (val))

/*
 * SB P16X Registers
 */

#define	PTR 	0x00
#define	DR	0x04
#define	IP	0x08
#define	IE	0x0C
#define	HC	0x14
#define	GPIO	0x18
#define	AC97D	0x1C
#define	AC97A	0x1E

/*
 * Indirect registers
 */

#define	PTBA	0x000
#define	PTBS	0x001
#define	PTCA	0x002
#define	PFBA	0x004
#define	PFBS	0x005
#define	CPFA	0x006
#define	PFEA	0x007
#define	CPCAV	0x008
#define	RFBA	0x010
#define	RFBS	0x011
#define	CRFA	0x012
#define	CRCAV	0x013
#define	CDL	0x020
#define	CDR	0x030
#define	SA	0x040
#define	EA_aux	0x041
#define	SCS0	0x042
#define	SCS1	0x043
#define	SCS2	0x044
#define	SPC	0x045
#define	WMARK	0x046
#define	MUDAT	0x047
#define	MUCMD	0x048
#define	RCD	0x050

/*
 * Interrupt bits
 */

#define	INTR_RFF	(1<<19)
#define	INTR_RFH	(1<<16)
#define	INTR_PFF	(3<<11)
#define	INTR_PFH	(3<<8)
#define	INTR_EAI	(1<<29)
#define	INTR_PCI	1
#define	INTR_UART_RX	2
#define	INTR_UART_TX	4
#define	INTR_AC97	0x10
#define	INTR_GPIO	0x40
#define	INTR_PLAY	(INTR_PFF | INTR_PFH)
#define	INTR_REC	(INTR_RFF | INTR_RFH)
#define	INTR_ALL	(INTR_PLAY | INTR_REC | INTR_PCI)

#endif /* AUDIOP16X_H */
