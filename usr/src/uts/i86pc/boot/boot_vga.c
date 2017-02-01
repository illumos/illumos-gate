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

/*
 * Miniature VGA driver for bootstrap.
 */

#include <sys/archsystm.h>
#include <sys/vgareg.h>
#include <sys/framebuffer.h>
#include <sys/boot_console.h>
#include <sys/rgb.h>
#include "boot_console_impl.h"

#include "boot_console_impl.h"
#if defined(_BOOT)
#include "../dboot/dboot_asm.h"
#include "../dboot/dboot_xboot.h"
#endif

#if defined(__xpv) && defined(_BOOT)

/*
 * Device memory address
 *
 * In dboot under the hypervisor we don't have any memory mappings
 * for the first meg of low memory so we can't access devices there.
 * Intead we've mapped the device memory that we need to access into
 * a local variable within dboot so we can access the device memory
 * there.
 */
extern unsigned short *video_fb;
#define	VGA_SCREEN		(video_fb)

#else /* __xpv && _BOOT */

/* Device memory address */
#define	VGA_SCREEN	((uint16_t *)(VGA_MEM_ADDR + VGA_COLOR_BASE))

#endif /* __xpv && _BOOT */

static int cons_color = CONS_COLOR;

static void vga_init(void);
static void vga_drawc(int);
static void vga_setpos(int, int);
static void vga_getpos(int *, int *);
static void vga_scroll(int);
static void vga_clear(int);
static void vga_shiftline(int);
static void vga_eraseline(void);
static void vga_cursor_display(boolean_t);

static void vga_set_crtc(int index, unsigned char val);
static unsigned char vga_get_crtc(int index);
static void vga_set_atr(int index, unsigned char val);
static unsigned char vga_get_atr(int index);

static int
get_vga_color(void)
{
	int color;
	uint32_t fg, bg;

	boot_get_color(&fg, &bg);
	color = solaris_color_to_pc_color[bg] << 4;
	color |= solaris_color_to_pc_color[fg];
	return (color);
}

void
boot_vga_init(bcons_dev_t *bcons_dev)
{
	fb_info.terminal.x = VGA_TEXT_COLS;
	fb_info.terminal.y = VGA_TEXT_ROWS;
	cons_color = get_vga_color();

#if defined(_BOOT)
	/*
	 * Note that we have to enable the cursor before clearing the
	 * screen since the cursor position is dependant upon the cursor
	 * skew, which is initialized by vga_cursor_display()
	 */
	vga_init();
	fb_info.cursor.visible = B_FALSE;
	vga_cursor_display(B_TRUE);

	/*
	 * In general we should avoid resetting the display during the boot,
	 * we may have valueable messages there, this why the "native" loader
	 * boot does pass the console state down to kernel and we do try to
	 * pick the state. However, the loader is not the only way to boot.
	 * The non-native boot loaders do not implement the smooth console.
	 * If we have no information about cursor location, we will get value
	 * (0, 0) and that means we better clear the screen.
	 */
	if (fb_info.cursor.pos.x == 0 && fb_info.cursor.pos.y == 0)
		vga_clear(cons_color);
	vga_setpos(fb_info.cursor.pos.y, fb_info.cursor.pos.x);
#endif /* _BOOT */

	bcons_dev->bd_putchar = vga_drawc;
	bcons_dev->bd_eraseline = vga_eraseline;
	bcons_dev->bd_cursor = vga_cursor_display;
	bcons_dev->bd_setpos = vga_setpos;
	bcons_dev->bd_shift = vga_shiftline;
}

static void
vga_init(void)
{
	unsigned char val;

	/* set 16bit colors */
	val = vga_get_atr(VGA_ATR_MODE);
	val &= ~VGA_ATR_MODE_BLINK;
	val &= ~VGA_ATR_MODE_9WIDE;
	vga_set_atr(VGA_ATR_MODE, val);
}

static void
vga_cursor_display(boolean_t visible)
{
	unsigned char val, msl;

	if (fb_info.cursor.visible == visible)
		return;

	/*
	 * Figure out the maximum scan line value.  We need this to set the
	 * cursor size.
	 */
	msl = vga_get_crtc(VGA_CRTC_MAX_S_LN) & 0x1f;

	/*
	 * Enable the cursor and set it's size.  Preserve the upper two
	 * bits of the control register.
	 * - Bits 0-4 are the starting scan line of the cursor.
	 *   Scanning is done from top-to-bottom.  The top-most scan
	 *   line is 0 and the bottom most scan line is the maximum scan
	 *   line value.
	 * - Bit 5 is the cursor disable bit.
	 */
	val = vga_get_crtc(VGA_CRTC_CSSL) & 0xc0;

	if (visible == B_FALSE)
		val |= (1 << 5);

	vga_set_crtc(VGA_CRTC_CSSL, val);

	/*
	 * Continue setting the cursors size.
	 * - Bits 0-4 are the ending scan line of the cursor.
	 *   Scanning is done from top-to-bottom.  The top-most scan
	 *   line is 0 and the bottom most scan line is the maximum scan
	 *   line value.
	 * - Bits 5-6 are the cursor skew.
	 */
	vga_set_crtc(VGA_CRTC_CESL, msl);
}

static void
vga_eraseline_impl(int x, int y, int color)
{
	unsigned short val, *buf;
	int i;

	buf = VGA_SCREEN + x + y * VGA_TEXT_COLS;
	val = (color << 8) | ' ';
	for (i = x; i < VGA_TEXT_COLS; i++)
		buf[i] = val;
}

static void
vga_eraseline(void)
{
	int x, y;

	x = fb_info.cursor.pos.x;
	y = fb_info.cursor.pos.y;
	vga_eraseline_impl(x, y, cons_color);
}

static void
vga_shiftline(int chars)
{
	unsigned short *src, *dst;
	int x, y, len;

	x = fb_info.cursor.pos.x;
	y = fb_info.cursor.pos.y;
	len = VGA_TEXT_COLS - x - chars;
	if (len <= 0)
		return;

	src = VGA_SCREEN + x + y * VGA_TEXT_COLS;
	dst = src + chars;
	if (dst <= src) {
		do {
			*dst++ = *src++;
		} while (--len != 0);
	} else {
		dst += len;
		src += len;
		do {
			*--dst = *--src;
		} while (--len != 0);
	}
}

static void
vga_clear(int color)
{
	int i;

	for (i = 0; i < VGA_TEXT_ROWS; i++)
		vga_eraseline_impl(0, i, color);
}

static void
vga_drawc(int c)
{
	int row;
	int col;

	vga_getpos(&row, &col);

	if (c == '\n') {
		if (row < fb_info.terminal.y - 1)
			vga_setpos(row + 1, col);
		else
			vga_scroll(cons_color);
		return;
	}

	/*
	 * VGA_SCREEN is an array of 16-bit unsigned ints, we do let
	 * the compiler to take care of truncation here.
	 */
	VGA_SCREEN[row * VGA_TEXT_COLS + col] = (cons_color << 8) | c;

	if (col < VGA_TEXT_COLS - 1)
		vga_setpos(row, col + 1);
	else if (row < VGA_TEXT_ROWS - 1)
		vga_setpos(row + 1, 0);
	else {
		vga_setpos(row, 0);
		vga_scroll(cons_color);
	}
}

static void
vga_scroll(int color)
{
	int i;

	for (i = 0; i < (VGA_TEXT_ROWS - 1) * VGA_TEXT_COLS; i++) {
		VGA_SCREEN[i] = VGA_SCREEN[i + VGA_TEXT_COLS];
	}
	vga_eraseline_impl(0, VGA_TEXT_ROWS - 1, color);
}

static void
vga_setpos(int row, int col)
{
	int off;

	if (row < 0)
		row = 0;
	if (row >= fb_info.terminal.y)
		row = fb_info.terminal.y - 1;
	if (col < 0)
		col = 0;
	if (col >= fb_info.terminal.x)
		col = fb_info.terminal.x - 1;

	off = row * VGA_TEXT_COLS + col;
	vga_set_crtc(VGA_CRTC_CLAH, off >> 8);
	vga_set_crtc(VGA_CRTC_CLAL, off & 0xff);

	fb_info.cursor.pos.y = row;
	fb_info.cursor.pos.x = col;
}

static void
vga_getpos(int *row, int *col)
{
	int off;

	off = (vga_get_crtc(VGA_CRTC_CLAH) << 8) + vga_get_crtc(VGA_CRTC_CLAL);
	*row = off / VGA_TEXT_COLS;
	*col = off % VGA_TEXT_COLS;
}

static void
vga_set_atr(int index, unsigned char val)
{
	(void) inb(VGA_REG_ADDR + CGA_STAT);
	outb(VGA_REG_ADDR + VGA_ATR_AD, index);
	outb(VGA_REG_ADDR + VGA_ATR_AD, val);

	(void) inb(VGA_REG_ADDR + CGA_STAT);
	outb(VGA_REG_ADDR + VGA_ATR_AD, VGA_ATR_ENB_PLT);
}

static unsigned char
vga_get_atr(int index)
{
	unsigned char val;

	(void) inb(VGA_REG_ADDR + CGA_STAT);
	outb(VGA_REG_ADDR + VGA_ATR_AD, index);
	val = inb(VGA_REG_ADDR + VGA_ATR_DATA);

	(void) inb(VGA_REG_ADDR + CGA_STAT);
	outb(VGA_REG_ADDR + VGA_ATR_AD, VGA_ATR_ENB_PLT);

	return (val);
}

static void
vga_set_crtc(int index, unsigned char val)
{
	outb(VGA_REG_ADDR + VGA_CRTC_ADR, index);
	outb(VGA_REG_ADDR + VGA_CRTC_DATA, val);
}

static unsigned char
vga_get_crtc(int index)
{
	outb(VGA_REG_ADDR + VGA_CRTC_ADR, index);
	return (inb(VGA_REG_ADDR + VGA_CRTC_DATA));
}
