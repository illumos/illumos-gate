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
 * Purpose: Definitions for the Creative Audigy LS driver
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
#ifndef	AUDIGYLS_H
#define	AUDIGYLS_H

#define	AUDIGYLS_NAME		"audiols"

#define	AUDIGYLS_NUM_PORT	2
#define	AUDIGYLS_PLAY_PORT	0
#define	AUDIGYLS_REC_PORT	1

#define	PCI_VENDOR_ID_CREATIVE 		0x1102
#define	PCI_DEVICE_ID_CREATIVE_AUDIGYLS 0x0007

/*
 * PCI registers
 */

#define	PR 	0x00
#define	DR	0x04
#define	IPR	0x08
#define	IER	0x0C
#define		INTR_PCI	(1 << 0)
#define		INTR_TXA	(1 << 1)	/* midi-a tx */
#define		INTR_RXA	(1 << 2)	/* midi-a rx */
#define		INTR_IT2	(1 << 3)	/* timer 2, 44.1 kHz */
#define		INTR_IT1	(1 << 4)	/* timer 1, 192 kHz */
#define		INTR_SS_	(1 << 5)	/* spdif status */
#define		INTR_SRT	(1 << 6)	/* sample rate status */
#define		INTR_GP		(1 << 7)
#define		INTR_AI		(1 << 8)	/* audio pending interrupt */
#define		INTR_I2CDAC	(1 << 9)
#define		INTR_I2CEE	(1 << 10)
#define		INTR_SPI	(1 << 11)
#define		INTR_SPF	(1 << 12)
#define		INTR_SUO	(1 << 13)
#define		INTR_SUI	(1 << 14)
#define		INTR_TXB	(1 << 16)	/* midi-b tx */
#define		INTR_RXB	(1 << 17)	/* midi-b rx */

#define	HC	0x14
#define		HC_PF		(1 << 11)	/* play fmt 1 = 32b, 0 = 16b */
#define		HC_RF		(1 << 10)	/* rec fmt 1 = 32b, 0 = 16b */
#define		HC_AC97		(1 << 3)
#define		HC_AEN		(1 << 0)	/* audio enable */

#define	GPIO	0x18
#define	AC97D	0x1C
#define	AC97A	0x1E
/*
 * Indirect registers
 */

#define	PTBA		0x000	/* gather play table base address */
#define	PTBS		0x001	/* gather play table buffer size */
#define	PTCA		0x002	/* gather play table current addr ptr */
#define	PFBA		0x004	/* play fifo base address */
#define	PFBS		0x005	/* play fifo buffer size */
#define	CPFA		0x006	/* current play fifo address */
#define	PFEA		0x007	/* play fifo end address */
#define	CPCAV		0x008	/* current play fifo offset/cache sz valid */
#define	RFBA		0x010	/* record fifo base address */
#define	RFBS		0x011	/* record fifo buffer size */
#define	CRFA		0x012	/* current record fifo address */
#define	CRCAV		0x013	/* current record fifo offset/cache sz valid */
#define	CDL		0x020	/* play fifo cache data, 0x20-0x2f */
#define	SA		0x040	/* start audio */
#define	SCS3		0x041
#define	SCS0		0x042
#define	SCS1		0x043
#define	SCS2		0x044
#define	SPC		0x045	/* spdif output control */
#define	WMARK		0x046	/* test purposes only */
#define	SPSC		0x049	/* spdif input control */
#define	RCD		0x050	/* record cache data, 0x50-0x5f */
#define	P17RECSEL	0x060	/* record fifo map address */
#define	P17RECVOLL	0x061	/* record fifo volume control (lo) */
#define	P17RECVOLH	0x062	/* record fifo volume control (hi) */

#define	HMIXMAP_SPDIF	0x063	/* spdif router map address */
#define	SMIXMAP_SPDIF	0x064	/* spdif router map address */
#define	MIXCTL_SPDIF	0x065	/* spdif mixer control */
#define	MIXVOL_SPDIF	0x066	/* spdif mixer input volume control */
#define	HMIXMAP_I2S	0x067	/* i2s router map address */
#define	SMIXMAP_I2S	0x068	/* i2s router map address */
#define	MIXCTL_I2S	0x069	/* i2s mixer control */
#define	MIXVOL_I2S	0x06a	/* i2s mixer input volume control */

/* MIDI UART */
#define	MUDATA		0x06c	/* midi uart a data */
#define	MUCMDA		0x06d	/* midi uart a command/status */
#define	MUDATB		0x06e	/* midi uart b data */
#define	MUCMDB		0x06f	/* midi uart b command/status */

#define	SRT		0x070	/* sample rate tracker status */
#define	SRCTL		0x071	/* sample rate control */
#define	AUDCTL		0x072	/* audio output control */
#define	CHIP_ID		0x074	/* chip id */
#define	AIE		0x075	/* audio interrupt enable */
#define	AIP		0x076	/* audio interrupt */
#define	WALL192		0x077	/* wall clock @ 192 kHz */
#define	WALL441		0x078	/* wall clock @ 44.1 kHz */
#define	IT		0x079	/* interval timer */
#define	SPI		0x07a	/* spi interface */
#define	I2C_A		0x07b	/* i2c address */
#define	I2C_0		0x07c	/* i2c data */
#define	I2C_1		0x07d	/* i2c data */

/*
 * Audio interrupt bits
 */

#define	AI_PFH		0x00000001	/* playback fifo half loop */
#define	AI_PFF		0x00000010	/* playback fifo loop */
#define	AI_TFH		0x00000100	/* playback table half loop */
#define	AI_TFF		0x00001000	/* playback table loop */
#define	AI_RFH		0x00010000	/* capture table half loop */
#define	AI_RFF		0x00100000	/* capture fifo loop */
#define	AI_EAI		0x01000000	/* enables audio end interrupt */

#define	SA_48K		0
#define	SA_44K		1
#define	SA_96K		2
#define	SA_192K		3

#define	SA_MIX_OUT_EN(ch)	(1 << ((ch) + 28))
#define	SA_MIX_IN_EN(ch)	(1 << ((ch) + 24))
#define	SA_PLAY_RATE(ch, rate)	((rate) << (((ch) * 2) + 16))
#define	SA_PLAY_START(ch)	(1 << (ch))
#define	SA_RECORD_START(ch)	(1 << ((ch) + 8))

#define	SA_SPA(ch)	(1U << (ch))
#define	SA_SRA(ch)	(1U << ((ch) + 8))

#define	RECSEL_SPDIFOUT	0
#define	RECSEL_I2SOUT	1
#define	RECSEL_SPDIFIN	2
#define	RECSEL_I2SIN	3
#define	RECSEL_AC97	4
#define	RECSEL_SRC	5

typedef struct _audigyls_dev_t audigyls_dev_t;
typedef struct _audigyls_port_t audigyls_port_t;

typedef enum {
	CTL_FRONT = 0,
	CTL_SURROUND,
	CTL_CENTER,
	CTL_LFE,
	CTL_RECORDVOL,
	CTL_MONGAIN,
	CTL_RECSRC,
	CTL_SPREAD,
	CTL_LOOP,
	CTL_NUM		/* must be last */
} audigyls_ctrl_num_t;

typedef struct audigyls_ctrl
{
	audigyls_dev_t		*dev;
	audio_ctrl_t		*ctrl;
	audigyls_ctrl_num_t	num;
	uint64_t		val;
} audigyls_ctrl_t;

struct _audigyls_port_t
{
	audigyls_dev_t *dev;
	audio_engine_t *engine;

	int			direction;

	unsigned		nchan;

	ddi_dma_handle_t	buf_dmah;	/* dma for buffers */
	ddi_acc_handle_t	buf_acch;
	uint32_t		buf_paddr;
	caddr_t			buf_kaddr;
	uint32_t		buf_size;
	uint32_t		buf_frames;	/* Buffer size in frames */
	uint32_t		offset;
	int			syncdir;
	uint64_t		count;
};

struct _audigyls_dev_t
{
	dev_info_t		*dip;
	audio_dev_t		*adev;
	ac97_t			*ac97;

	int			nactive;	/* Num active ports */
	char			digital_enable;	/* Orange combo-jack mode */

	ddi_acc_handle_t	pcih;
	ddi_acc_handle_t	regsh;
	caddr_t			base;
	kmutex_t		mutex;		/* For normal locking */
	kmutex_t		low_mutex;	/* For low level routines */

	audigyls_port_t		*port[AUDIGYLS_NUM_PORT];
	audigyls_ctrl_t		controls[CTL_NUM];

	ac97_ctrl_t		*ac97_recgain;
	ac97_ctrl_t		*ac97_recsrc;
	uint64_t		recmask;
};

#define	INB(dev, reg)		\
	ddi_get8(dev->regsh, (void *)(dev->base + reg))
#define	OUTB(dev, reg, val)	\
	ddi_put8(dev->regsh, (void *)(dev->base + reg), (val))

#define	INW(dev, reg)		\
	ddi_get16(dev->regsh, (void *)(dev->base + reg))
#define	OUTW(dev, reg, val)	\
	ddi_put16(dev->regsh, (void *)(dev->base + reg), (val))

#define	INL(dev, reg)		\
	ddi_get32(dev->regsh, (void *)(dev->base + reg))
#define	OUTL(dev, reg, val)	\
	ddi_put32(dev->regsh, (void *)(dev->base + reg), (val))

#endif /* AUDIGYLS_H */
