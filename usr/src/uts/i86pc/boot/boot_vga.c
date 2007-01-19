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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Miniature VGA driver for bootstrap.
 */

#include <sys/archsystm.h>
#include <sys/vgareg.h>

#include "boot_vga.h"

#if defined(_BOOT)
#include "../dboot/dboot_xboot.h"
#endif

#define	VGA_COLOR_CRTC_INDEX	0x3d4
#define	VGA_COLOR_CRTC_DATA	0x3d5
#define	VGA_SCREEN		((unsigned short *)0xb8000)

static void vga_set_crtc(int index, unsigned char val);
static unsigned char vga_get_crtc(int index);

void
vga_clear(int color)
{
	unsigned short val;
	int i;

	val = (color << 8) | ' ';

	for (i = 0; i < VGA_TEXT_ROWS * VGA_TEXT_COLS; i++) {
		VGA_SCREEN[i] = val;
	}
}

void
vga_drawc(int c, int color)
{
	int row;
	int col;

	vga_getpos(&row, &col);
	VGA_SCREEN[row*VGA_TEXT_COLS + col] = (color << 8) | c;
}

void
vga_scroll(int color)
{
	unsigned short val;
	int i;

	val = (color << 8) | ' ';

	for (i = 0; i < (VGA_TEXT_ROWS-1)*VGA_TEXT_COLS; i++) {
		VGA_SCREEN[i] = VGA_SCREEN[i + VGA_TEXT_COLS];
	}
	for (; i < VGA_TEXT_ROWS * VGA_TEXT_COLS; i++) {
		VGA_SCREEN[i] = val;
	}
}

void
vga_setpos(int row, int col)
{
	int off;

	off = row * VGA_TEXT_COLS + col;
	vga_set_crtc(VGA_CRTC_CLAH, off >> 8);
	vga_set_crtc(VGA_CRTC_CLAL, off & 0xff);
}

void
vga_getpos(int *row, int *col)
{
	int off;

	off = (vga_get_crtc(VGA_CRTC_CLAH) << 8) +
		vga_get_crtc(VGA_CRTC_CLAL);
	*row = off / VGA_TEXT_COLS;
	*col = off % VGA_TEXT_COLS;
}

static void
vga_set_crtc(int index, unsigned char val)
{
	outb(VGA_COLOR_CRTC_INDEX, index);
	outb(VGA_COLOR_CRTC_DATA, val);
}


static unsigned char
vga_get_crtc(int index)
{
	outb(VGA_COLOR_CRTC_INDEX, index);
	return (inb(VGA_COLOR_CRTC_DATA));
}
