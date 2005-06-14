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
 * Copyright (c) 1988,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SBUSDEV_MEMFB_H
#define	_SYS_SBUSDEV_MEMFB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Sbus memory frame buffer definitions
 */

/* frame buffer address offsets */
#define	MFB_OFF_ID	0		/* ID register/ROM */
#define	MFB_OFF_REG	0x400000	/* video registers */
#define	MFB_OFF_FB	0x800000	/* frame buffer */
#define	MFB_OFF_DUMMY	0xC00000	/* reserved area */

#define	MFB_ID_MASK	0xFFFFFFF0
#define	MFB_ID_VALUE	0xFE010100

/* colormap (Bt458) */
struct mfb_cmap {
	uchar_t addr;		/* address register */
	uchar_t :8, :8, :8;
	uchar_t cmap;		/* color map data register */
	uchar_t :8, :8, :8;
	uchar_t ctrl;		/* control register */
	uchar_t :8, :8, :8;
	uchar_t omap;		/* overlay map data register */
	uchar_t :8, :8, :8;
};

/* number of colormap entries */
#define	MFB_CMAP_ENTRIES	256

/* video registers */
struct mfb_reg {
	struct mfb_cmap cmap;
	uchar_t control;
	uchar_t status;
	uchar_t cursor_start;
	uchar_t cursor_end;
	uchar_t h_blank_set;
	uchar_t h_blank_clear;
	uchar_t h_sync_set;
	uchar_t h_sync_clear;
	uchar_t comp_sync_clear;
	uchar_t v_blank_set_high;
	uchar_t v_blank_set_low;
	uchar_t v_blank_clear;
	uchar_t v_sync_set;
	uchar_t v_sync_clear;
	uchar_t xfer_holdoff_set;
	uchar_t xfer_holdoff_clear;
};

/* control register bits (read-write) */
#define	MFB_CR_INTEN		0x80	/* interrupt enable */
#define	MFB_CR_VIDEO		0x40	/* video enable */
#define	MFB_CR_MASTER		0x20	/* master timing enable */
#define	MFB_CR_CURSOR		0x10	/* cursor compare enable */
#define	MFB_CR_X0		0x00	/* crystal 0 select */
#define	MFB_CR_X1		0x04	/* crystal 1 select */
#define	MFB_CR_X2		0x08	/* crystal 2 select */
#define	MFB_CR_TEST		0x0C	/* test mode */
#define	MFB_CR_DIV1		0x00	/* divide by 1 */
#define	MFB_CR_DIV2		0x01	/* divide by 2 */
#define	MFB_CR_DIV3		0x02	/* divide by 3 */
#define	MFB_CR_DIV4		0x03	/* divide by 4 */

/* status register bits (read-only, write to clear interrupt) */
#define	MFB_SR_INT		0x80	/* interrupt pending */

#define	MFB_SR_RES_MASK		0x70	/* monitor sense bits */
#define	MFB_SR_1024_768		0x10
#define	MFB_SR_1152_900		0x30
#define	MFB_SR_1280_1024	0x40
#define	MFB_SR_1600_1280	0x50

#define	MFB_SR_ID_MASK		0x0F	/* memory mode/board ID bits */
#define	MFB_SR_ID_COLOR		0x01
#define	MFB_SR_ID_MONO		0x02
#define	MFB_SR_ID_MONO_ECL	0x03

/* set video enable */
#define	mfb_set_video(mp, on) \
	((mp)->control = (mp)->control & ~MFB_CR_VIDEO | \
		((on) ? MFB_CR_VIDEO : 0))

/* get video enable */
#define	mfb_get_video(mp)	((mp)->control & MFB_CR_VIDEO)

/* interrupt enable */
#define	mfb_int_enable(mp)	((mp)->control |= MFB_CR_INTEN)

/* interrupt disable */
#define	mfb_int_disable(mp) \
		((mp)->control &= ~MFB_CR_INTEN, (mp)->status = 0)

/* is interrupt pending? */
#define	mfb_int_pending(mp)	((mp)->status & MFB_SR_INT)


/* mmap offset for registers (superuser only) */
#define	MFB_REG_MMAP_OFFSET	0x10000000

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SBUSDEV_MEMFB_H */
