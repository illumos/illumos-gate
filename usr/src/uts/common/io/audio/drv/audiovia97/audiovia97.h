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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Purpose: Definitions for the VIA VT82C686A AC97 driver
 */
/*
 * Copyright (C) 4Front Technologies 1996-2009.
 */
#ifndef	AUDIOVIA97_H
#define	AUDIOVIA97_H

#define	VIA97_NAME		"audiovia97"

#define	VIA97_NUM_PORTC		2
#define	VIA97_PLAY_SGD_NUM	0
#define	VIA97_REC_SGD_NUM	1
#define	VIA97_NUM_SGD	512		/* Max number of SGD entries (4k/8) */

#define	VIA_VENDOR_ID		0x1106
#define	VIA_82C686		0x3058

#define	VIA97_MAX_INTRS		256
#define	VIA97_MIN_INTRS		24
#define	VIA97_INTRS		175

#define	CODEC_TIMEOUT_COUNT	500
#define	AC97CODEC	0x80	/* Access AC97 Codec */
#define	IN_CMD		0x01000000	/* busy in sending */
#define	STA_VALID	0x02000000	/* 1:status data is valid */
#define	CODEC_RD	0x00800000	/* Read CODEC status */
#define	CODEC_INDEX	0x007F0000	/* Index of command register */
#define	CODEC_DATA	0x0000FFFF	/* AC97 status register data */

typedef struct _via97_devc_t via97_devc_t;
typedef struct _via97_portc_t via97_portc_t;

struct _via97_portc_t
{
	via97_devc_t *devc;
	audio_engine_t *engine;

	int started;
	unsigned		intrs;
	unsigned		fragfr;
	unsigned		fragsz;
	unsigned		cur_frag;
	unsigned		resid;
	caddr_t			base;

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
	uint64_t		count;
};

struct _via97_devc_t
{
	dev_info_t		*dip;
	audio_dev_t		*adev;
	ac97_t			*ac97;
	kstat_t			*ksp;

	boolean_t		suspended;
	ddi_acc_handle_t	pcih;
	ddi_acc_handle_t	regsh;
	caddr_t			base;
	kmutex_t		mutex;		/* For normal locking */
	kmutex_t		low_mutex;	/* For low level routines */
	ddi_intr_handle_t	ih;

	via97_portc_t *portc[VIA97_NUM_PORTC];
};

#define	INL(devc, reg)		ddi_get32(devc->regsh, (void *)(reg))

#define	INB(devc, reg)		ddi_get8(devc->regsh, (void *)(reg))

#define	OUTL(devc, reg, val)	ddi_put32(devc->regsh, (void *)(reg), (val))

#define	OUTB(devc, reg, val)	ddi_put8(devc->regsh, (void *)(reg), (val))
#define	VIA97_KIOP(X)	((kstat_intr_t *)(X->ksp->ks_data))

#endif /* AUDIOVIA97_H */
