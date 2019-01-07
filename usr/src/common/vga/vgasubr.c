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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018 Toomas Soome <tsoome@me.com>
 */

/*
 * Support routines for VGA drivers
 */

#if defined(_KERNEL)
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/buf.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/conf.h>

#include <sys/cmn_err.h>

#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/sunddi.h>

#include <sys/modctl.h>

#define	PUTB(reg, off, v)	ddi_put8(reg->handle, reg->addr + (off), v)
#define	GETB(reg, off)		ddi_get8(reg->handle, reg->addr + (off))

#elif defined(_STANDALONE)

#include <stand.h>
#include <machine/cpufunc.h>

#define	PUTB(reg, off, v)	outb(reg + (off), v)
#define	GETB(reg, off)		inb(reg + (off))
#endif

#include <sys/vgareg.h>
#include <sys/vgasubr.h>

#define	GET_HORIZ_END(c)	vga_get_crtc(c, VGA_CRTC_H_D_END)
#define	GET_VERT_END(c)	(vga_get_crtc(c, VGA_CRTC_VDE) \
	+ (((vga_get_crtc(c, VGA_CRTC_OVFL_REG) >> \
	    VGA_CRTC_OVFL_REG_VDE8) & 1) << 8) \
	+ (((vga_get_crtc(c, VGA_CRTC_OVFL_REG) >> \
	    VGA_CRTC_OVFL_REG_VDE9) & 1) << 9))

#define	GET_VERT_X2(c)	\
	(vga_get_crtc(c, VGA_CRTC_CRT_MD) & VGA_CRTC_CRT_MD_VT_X2)

unsigned char VGA_CRTC_TEXT[NUM_CRTC_REG] = {
	0x5f, 0x4f, 0x50, 0x82, 0x55, 0x81, 0xbf, 0x1f,
	0x00, 0x4f, 0x0d, 0x0e, 0x00, 0x00, 0x05, 0x00,
	0x9c, 0x8e, 0x8f, 0x28, 0x1f, 0x96, 0xb9, 0xa3,
	0xff };
unsigned char VGA_SEQ_TEXT[NUM_SEQ_REG] = {
	0x03, 0x00, 0x03, 0x00, 0x02 };
unsigned char VGA_GRC_TEXT[NUM_GRC_REG] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x00, 0xff };
unsigned char VGA_ATR_TEXT[NUM_ATR_REG] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0x0c, 0x00, 0x0f, 0x08, 0x00 };

void
vga_get_hardware_settings(vgaregmap_t reg, int *width, int *height)
{
	*width = (GET_HORIZ_END(reg)+1)*8;
	*height = GET_VERT_END(reg)+1;
	if (GET_VERT_X2(reg)) *height *= 2;
}

int
vga_get_reg(vgaregmap_t reg, int indexreg)
{
	return (GETB(reg, indexreg));
}

void
vga_set_reg(vgaregmap_t reg, int indexreg, int v)
{
	PUTB(reg, indexreg, v);
}

int
vga_get_crtc(vgaregmap_t reg, int i)
{
	return (vga_get_indexed(reg, VGA_CRTC_ADR, VGA_CRTC_DATA, i));
}

void
vga_set_crtc(vgaregmap_t reg, int i, int v)
{
	vga_set_indexed(reg, VGA_CRTC_ADR, VGA_CRTC_DATA, i, v);
}

int
vga_get_seq(vgaregmap_t reg, int i)
{
	return (vga_get_indexed(reg, VGA_SEQ_ADR, VGA_SEQ_DATA, i));
}

void
vga_set_seq(vgaregmap_t reg, int i, int v)
{
	vga_set_indexed(reg, VGA_SEQ_ADR, VGA_SEQ_DATA, i, v);
}

int
vga_get_grc(vgaregmap_t reg, int i)
{
	return (vga_get_indexed(reg, VGA_GRC_ADR, VGA_GRC_DATA, i));
}

void
vga_set_grc(vgaregmap_t reg, int i, int v)
{
	vga_set_indexed(reg, VGA_GRC_ADR, VGA_GRC_DATA, i, v);
}

int
vga_get_atr(vgaregmap_t reg, int i)
{
	int ret;

	(void) GETB(reg, CGA_STAT);
	PUTB(reg, VGA_ATR_AD, i);
	ret = GETB(reg, VGA_ATR_DATA);

	(void) GETB(reg, CGA_STAT);
	PUTB(reg, VGA_ATR_AD, VGA_ATR_ENB_PLT);

	return (ret);
}

void
vga_set_atr(vgaregmap_t reg, int i, int v)
{
	(void) GETB(reg, CGA_STAT);
	PUTB(reg, VGA_ATR_AD, i);
	PUTB(reg, VGA_ATR_AD, v);

	(void) GETB(reg, CGA_STAT);
	PUTB(reg, VGA_ATR_AD, VGA_ATR_ENB_PLT);
}

void
vga_set_indexed(
	vgaregmap_t reg,
	int indexreg,
	int datareg,
	unsigned char index,
	unsigned char val)
{
	PUTB(reg, indexreg, index);
	PUTB(reg, datareg, val);
}

int
vga_get_indexed(
	vgaregmap_t reg,
	int indexreg,
	int datareg,
	unsigned char index)
{
	PUTB(reg, indexreg, index);
	return (GETB(reg, datareg));
}

/*
 * VGA DAC access functions
 * Note:  These assume a VGA-style 6-bit DAC.  Some DACs are 8 bits
 * wide.  These functions are not appropriate for those DACs.
 */
void
vga_put_cmap(
	vgaregmap_t reg,
	int index,
	unsigned char r,
	unsigned char g,
	unsigned char b)
{

	PUTB(reg, VGA_DAC_WR_AD, index);
	PUTB(reg, VGA_DAC_DATA, r >> 2);
	PUTB(reg, VGA_DAC_DATA, g >> 2);
	PUTB(reg, VGA_DAC_DATA, b >> 2);
}

void
vga_get_cmap(
	vgaregmap_t reg,
	int index,
	unsigned char *r,
	unsigned char *g,
	unsigned char *b)
{
	PUTB(reg, VGA_DAC_RD_AD, index);
	*r = GETB(reg, VGA_DAC_DATA) << 2;
	*g = GETB(reg, VGA_DAC_DATA) << 2;
	*b = GETB(reg, VGA_DAC_DATA) << 2;
}

#ifdef	DEBUG

void
vga_dump_regs(vgaregmap_t reg, int maxseq, int maxcrtc, int maxatr, int maxgrc)
{
	int i, j;

	printf("Sequencer regs:\n");
	for (i = 0; i < maxseq; i += 0x10) {
		printf("%2x:  ", i);
		for (j = 0; j < 0x08; j++) {
			printf("%2x ", vga_get_seq(reg, i+j));
		}
		printf("- ");
		for (; j < 0x10; j++) {
			printf("%2x ", vga_get_seq(reg, i+j));
		}
		printf("\n");
	}
	printf("\nCRT Controller regs:\n");
	for (i = 0; i < maxcrtc; i += 0x10) {
		printf("%2x:  ", i);
		for (j = 0; j < 0x08; j++) {
			printf("%2x ", vga_get_crtc(reg, i+j));
		}
		printf("- ");
		for (; j < 0x10; j++) {
			printf("%2x ", vga_get_crtc(reg, i+j));
		}
		printf("\n");
	}
	printf("\nAttribute Controller regs:\n");
	for (i = 0; i < maxatr; i += 0x10) {
		printf("%2x:  ", i);
		for (j = 0; j < 0x08; j++) {
			printf("%2x ", vga_get_atr(reg, i+j));
		}
		printf("- ");
		for (; j < 0x10; j++) {
			printf("%2x ", vga_get_atr(reg, i+j));
		}
		printf("\n");
	}
	printf("\nGraphics Controller regs:\n");
	for (i = 0; i < maxgrc; i += 0x10) {
		printf("%2x:  ", i);
		for (j = 0; j < 0x08; j++) {
			printf("%2x ", vga_get_grc(reg, i+j));
		}
		printf("- ");
		for (; j < 0x10; j++) {
			printf("%2x ", vga_get_grc(reg, i+j));
		}
		printf("\n");
	}
}
#endif	/* DEBUG */

/*
 * VGA 80X25 text mode standard palette
 */
unsigned char VGA_TEXT_PALETTES[64][3] = {
	{ 0x00, 0x00, 0x00 },
	{ 0x00, 0x00, 0x2A },
	{ 0x00, 0x2A, 0x00 },
	{ 0x00, 0x2A, 0x2A },
	{ 0x2A, 0x00, 0x00 },
	{ 0x2A, 0x00, 0x2A },
	{ 0x2A, 0x2A, 0x00 },
	{ 0x2A, 0x2A, 0x2A },
	{ 0x00, 0x00, 0x15 },
	{ 0x00, 0x00, 0x3F },
	{ 0x00, 0x2A, 0x15 },
	{ 0x00, 0x2A, 0x3F },
	{ 0x2A, 0x00, 0x15 },
	{ 0x2A, 0x00, 0x3F },
	{ 0x2A, 0x2A, 0x15 },
	{ 0x2A, 0x2A, 0x3F },
	{ 0x00, 0x15, 0x00 },
	{ 0x00, 0x15, 0x2A },
	{ 0x00, 0x3F, 0x00 },
	{ 0x00, 0x3F, 0x2A },
	{ 0x2A, 0x15, 0x00 },
	{ 0x2A, 0x15, 0x2A },
	{ 0x2A, 0x3F, 0x00 },
	{ 0x2A, 0x3F, 0x2A },
	{ 0x00, 0x15, 0x15 },
	{ 0x00, 0x15, 0x3F },
	{ 0x00, 0x3F, 0x15 },
	{ 0x00, 0x3F, 0x3F },
	{ 0x2A, 0x15, 0x15 },
	{ 0x2A, 0x15, 0x3F },
	{ 0x2A, 0x3F, 0x15 },
	{ 0x2A, 0x3F, 0x3F },
	{ 0x15, 0x00, 0x00 },
	{ 0x15, 0x00, 0x2A },
	{ 0x15, 0x2A, 0x00 },
	{ 0x15, 0x2A, 0x2A },
	{ 0x3F, 0x00, 0x00 },
	{ 0x3F, 0x00, 0x2A },
	{ 0x3F, 0x2A, 0x00 },
	{ 0x3F, 0x2A, 0x2A },
	{ 0x15, 0x00, 0x15 },
	{ 0x15, 0x00, 0x3F },
	{ 0x15, 0x2A, 0x15 },
	{ 0x15, 0x2A, 0x3F },
	{ 0x3F, 0x00, 0x15 },
	{ 0x3F, 0x00, 0x3F },
	{ 0x3F, 0x2A, 0x15 },
	{ 0x3F, 0x2A, 0x3F },
	{ 0x15, 0x15, 0x00 },
	{ 0x15, 0x15, 0x2A },
	{ 0x15, 0x3F, 0x00 },
	{ 0x15, 0x3F, 0x2A },
	{ 0x3F, 0x15, 0x00 },
	{ 0x3F, 0x15, 0x2A },
	{ 0x3F, 0x3F, 0x00 },
	{ 0x3F, 0x3F, 0x2A },
	{ 0x15, 0x15, 0x15 },
	{ 0x15, 0x15, 0x3F },
	{ 0x15, 0x3F, 0x15 },
	{ 0x15, 0x3F, 0x3F },
	{ 0x3F, 0x15, 0x15 },
	{ 0x3F, 0x15, 0x3F },
	{ 0x3F, 0x3F, 0x15 },
	{ 0x3F, 0x3F, 0x3F }
};
