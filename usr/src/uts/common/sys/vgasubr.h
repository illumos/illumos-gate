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

#ifndef	_SYS_VGASUBR_H
#define	_SYS_VGASUBR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS4.1 1.11 */

#ifdef	__cplusplus
extern "C" {
#endif

struct vgaregmap {
	uint8_t			*addr;
	ddi_acc_handle_t	handle;
	boolean_t		mapped;
};

extern int vga_get_reg(struct vgaregmap *reg, int i);
extern void vga_set_reg(struct vgaregmap *reg, int i, int v);
extern int vga_get_crtc(struct vgaregmap *reg, int i);
extern void vga_set_crtc(struct vgaregmap *reg, int i, int v);
extern int vga_get_seq(struct vgaregmap *reg, int i);
extern void vga_set_seq(struct vgaregmap *reg, int i, int v);
extern int vga_get_grc(struct vgaregmap *reg, int i);
extern void vga_set_grc(struct vgaregmap *reg, int i, int v);
extern int vga_get_atr(struct vgaregmap *reg, int i);
extern void vga_set_atr(struct vgaregmap *reg, int i, int v);
extern void vga_put_cmap(struct vgaregmap *reg,
	int index, unsigned char r, unsigned char g, unsigned char b);
extern void vga_get_cmap(struct vgaregmap *reg,
	int index, unsigned char *r, unsigned char *g, unsigned char *b);
extern void vga_get_hardware_settings(struct vgaregmap *reg,
	int *width, int *height);
extern void vga_set_indexed(struct vgaregmap *reg, int indexreg,
	int datareg, unsigned char index, unsigned char val);
extern int vga_get_indexed(struct vgaregmap *reg, int indexreg,
	int datareg, unsigned char index);

#define	VGA_MISC_TEXT	0x67
#define	NUM_CRTC_REG	25
#define	NUM_SEQ_REG    	5
#define	NUM_GRC_REG	9
#define	NUM_ATR_REG	21

extern unsigned char VGA_ATR_TEXT[NUM_ATR_REG];
extern unsigned char VGA_SEQ_TEXT[NUM_SEQ_REG];
extern unsigned char VGA_CRTC_TEXT[NUM_CRTC_REG];
extern unsigned char VGA_GRC_TEXT[NUM_GRC_REG];
extern unsigned char VGA_TEXT_PALETTES[64][3];

#if	defined(DEBUG)
extern void vga_dump_regs(struct vgaregmap *reg,
	int maxseq, int maxcrtc, int maxatr, int maxgrc);
#endif


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_VGASUBR_H */
