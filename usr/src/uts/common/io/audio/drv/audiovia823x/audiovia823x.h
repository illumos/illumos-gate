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
 * Purpose: Definitions for the via8233 driver
 */
/*
 * This file is part of Open Sound System
 *
 * Copyright (C) 4Front Technologies 1996-2008.
 *
 * This software is released under CDDL 1.0 source license.
 * See the COPYING file included in the main directory of this source
 * distribution for the license terms and conditions.
 */
#ifndef	AUDIOVIA823X_H
#define	AUDIOVIA823X_H

#define	AUVIA_NAME		"audiovia823x"

#define	VIA_VENDOR_ID		0x1106
#define	VIA_8233_ID		0x3059
#define	VIA_8233A_ID		0x7059

/* pci configuration registers */
#define	AUVIA_PCICFG		0x40		/* Via chip specific cfg reg */
#define	AUVIA_PCICFG_LEGACY	0x00ff0000	/* legacy enables mask */
#define	AUVIA_PCICFG_ACLINKEN	0x00008000	/* AC'97 link enable */
#define	AUVIA_PCICFG_NRST	0x00004000	/* inverse of AC'97 reset */
#define	AUVIA_PCICFG_ACSYNC	0x00002000	/* AC'97 sync */
#define	AUVIA_PCICFG_SRCEN	0x00000800	/* sample rate converter en */
#define	AUVIA_PCICFG_SGDEN	0x00000400	/* SGD enable */
#define	AUVIA_PCICFG_FMEN	0x00000200 	/* FM synth enable (legacy) */
#define	AUVIA_PCICFG_SBEN	0x00000100	/* SB compat enable (legacy) */
#define	AUVIA_PCICFG_PRIVALID	0x00000001	/* primary codec ready */

#define	AUVIA_PLAY_SGD_NUM	1
#define	AUVIA_REC_SGD_NUM	0
#define	AUVIA_NUM_PORTC		2
#define	AUVIA_NUM_SGD		16	/* number of fragments */

#define	AUVIA_SGD_EOL		0x80000000
#define	AUVIA_SGD_FLAG		0x40000000

#define	CODEC_TIMEOUT_COUNT		500

#define	REG_PLAYBASE		0x40	/* Multichannel SGD */
#define	REG_RECBASE		0x60
#define	REG_CODEC		0x80	/* Access AC97 Codec */
#define	REG_GSTAT		0x84	/* Global status */

/* REG_CODEC */
#define	CODEC_IN_CMD		0x01000000	/* busy in sending */
#define	CODEC_STA_VALID		0x02000000	/* 1:status data is valid */
#define	CODEC_RD		0x00800000	/* Read CODEC status */
#define	CODEC_WR		0x00000000	/* Write CODEC status */
#define	CODEC_INDEX		0x007F0000	/* Index of command register */
#define	CODEC_DATA		0x0000FFFF	/* AC97 status register data */

/* registers that are offsets relative to a port */
#define	OFF_STATUS		0x00
#define	OFF_CTRL		0x01
#define	OFF_PLAYFMT		0x02
#define	OFF_RECFIFO		0x02
#define	OFF_DMA			0x04
#define	OFF_CHANNELS		0x08
#define	OFF_RECFMT		0x08
#define	OFF_COUNT		0x0C

/* bits for above offsets */
#define	STATUS_INTR		0x3

#define	CTRL_START		0x80
#define	CTRL_TERMINATE		0x40
#define	CTRL_AUTOSTART		0x20
#define	CTRL_MULTICHORDER	0x10	/* SGD 0x40 only, Center/LFE order */
#define	CTRL_FLAG		0x01

#define	PLAYFMT_16BIT		0x80
#define	PLAYFMT_STEREO		0x20	/* Num channels (1-6), upper nybble */
#define	PLAYFMT_6CH		0x60
#define	PLAYFMT_4CH		0x40

#define	RECFIFO_ENABLE		0x40

#define	RECFMT_48K		0x00ffffff
#define	RECFMT_STEREO		0x00100000
#define	RECFMT_16BIT		0x00200000


typedef struct {
	unsigned int phaddr;
	unsigned int flags;
} SGD_entry;

typedef struct auvia_portc auvia_portc_t;
typedef struct auvia_devc auvia_devc_t;

struct auvia_portc {
	auvia_devc_t		*devc;
	audio_engine_t		*engine;
	caddr_t			base;		/* base for registers */
	int			nchan;

	ddi_dma_handle_t	sgd_dmah;	/* dma for descriptors */
	ddi_acc_handle_t	sgd_acch;
	uint32_t		sgd_paddr;
	caddr_t			sgd_kaddr;

	ddi_dma_handle_t	buf_dmah;	/* dma for buffers */
	ddi_acc_handle_t	buf_acch;
	uint32_t		buf_paddr;
	caddr_t			buf_kaddr;
	size_t			buf_size;
	int			syncdir;

	unsigned		nframes;
	unsigned		pos;

	uint64_t		count;

	/* helper functions */
	void			(*reset)(auvia_portc_t *);
};


struct auvia_devc {
	dev_info_t		*dip;
	audio_dev_t		*adev;
	ac97_t			*ac97;

	char			*chip_name;
	int			chip_type;
#define	CHIP_8233		0
#define	CHIP_8233A		1

	/* registers */
	ddi_acc_handle_t	pcih;
	ddi_acc_handle_t	regsh;
	caddr_t			base;

	auvia_portc_t		*portc[AUVIA_NUM_PORTC];
};

#define	AUVIA_KIOP(X)	((kstat_intr_t *)(X->ksp->ks_data))

#define	INL(devc, reg)		ddi_get32(devc->regsh, (void *)(reg))

#define	INB(devc, reg)		ddi_get8(devc->regsh, (void *)(reg))

#define	OUTL(devc, reg, val)	ddi_put32(devc->regsh, (void *)(reg), (val))

#define	OUTB(devc, reg, val)	ddi_put8(devc->regsh, (void *)(reg), (val))

#endif /* AUDIOVIA823X_H */
