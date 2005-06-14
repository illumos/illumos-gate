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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/psw.h>
#include <sys/memlist.h>
#include <sys/bootvfs.h>
#include "graphics.h"
#include "biosint.h"
#include "vga.h"
#include "util.h"
#include "multiboot.h"
#include "console.h"
#include "standalloc.h"
#include "debug.h"

typedef int (*func_t)();
extern int openfile(char *, char *);
extern int close(int);
extern int console;

int saved_videomode;
unsigned char *font8x16;

int graphics_inited = 0;
static char splashimage[64];

#define	VSHADOW VSHADOW1
unsigned char VSHADOW1[38400];
unsigned char VSHADOW2[38400];
unsigned char VSHADOW4[38400];
unsigned char VSHADOW8[38400];

#define	dprintf	if (debug & D_GRAPHICS) printf

/*
 * constants to define the viewable area
 */
const int x0 = 0;
const int x1 = 80;
const int y0 = 0;
const int y1 = 30;

/*
 * text buffer has to be kept around so that we can write things as we
 * scroll and the like
 */
unsigned short text[80 * 30];

/*
 * why do these have to be kept here?
 */
int foreground = (63 << 16) | (63 << 8) | (63), background = 0, border = 0;

/*
 * current position
 */

static int fontx = 0;
static int fonty = 10;

/*
 * global state so that we don't try to recursively scroll or cursor
 */
static int no_scroll = 0;

/*
 * color state
 */
static int graphics_standard_color = A_NORMAL;
static int graphics_normal_color = A_NORMAL;
static int graphics_highlight_color = A_REVERSE;
static int graphics_current_color = A_NORMAL;
static color_state graphics_color_state = COLOR_STATE_STANDARD;


/*
 * graphics local functions
 */
static void graphics_setxy(int col, int row);
static void graphics_scroll();
static void graphics_memcpy(void *dest, const void *src, int len);
static int graphics_memcmp(const char *s1, const char *s2, int n);
static int read_image(char *s);
static int hex(int v);

extern uchar_t inb(int);
extern void outb(int, uchar_t);

static void MapMask(int value) {
	outb(0x3c4, 2);
	outb(0x3c5, value);
}

/* bit mask register */
static void BitMask(int value) {
	outb(0x3ce, 8);
	outb(0x3cf, value);
}

/* Set the splash image */
int graphics_set_splash(char *splashfile) {
	/* filename can only be 64 characters due to our buffer size */
	if (strlen(splashfile) > 63)
		return (0);
	strcpy(splashimage, splashfile);
		return (1);
}

/* Get the current splash image */
char *
graphics_get_splash(void)
{
	return (splashimage);
}

/*
 * Initialize a vga16 graphics display with the palette based off of
 * the image in splashimage.  If the image doesn't exist, leave graphics
 * mode.
 */
int
graphics_init()
{
	int fail_n = 0;

	if (!graphics_inited) {
		saved_videomode = set_videomode(0x12);
		if (saved_videomode == -1) {
			fail_n = 1;
			goto fail;
		}
	}

	if (!graphics_set_splash("boot/solaris.xpm")) {
		fail_n = 2;
		goto fail;
	}

	if (!read_image(splashimage)) {
		fail_n = 3;
		goto fail;
	}

	font8x16 = (unsigned char *)graphics_get_font();
	if (!font8x16) {
		fail_n = 4;
		goto fail;
	}

	graphics_inited = 1;

	/* make sure that the highlight color is set correctly */
	graphics_highlight_color = ((graphics_normal_color >> 4) |
				((graphics_normal_color & 0xf) << 4));

	graphics_cursor(0);
	graphics_setxy(fontx, fonty);
	graphics_cursor(1);
	graphics_cls();

	return (1);

fail :
	console = CONS_SCREEN_TEXT;
	text_init();
	switch (fail_n) {
	case 1:
		printf("Failed to set graphics video mode\n");
		break;
	case 2:
		printf("Splash image file name is too long\n");
		break;
	case 3:
		printf("Failed to read splash image\n");
		break;
	case 4:
		printf("Failed to get font address\n");
	}

	return (0);
}

/*
 * int set_videomode(mode)
 * BIOS call "INT 10H Function 0h" to set video mode
 *	Call with	%ah = 0x0
 *			%al = video mode
 *	Return		correct : old videomode
 *			error	: -1
 */
int
set_videomode(int mode)
{
	int ret;
	struct int_pb ic = {0};

	ic.ax = 0x0f00;
	ret = bios_doint(0x10, &ic); /* Get Current Video mode */
	if (ret & PS_C) {
		dprintf("bios_doint returned: %d\r\n", ret);
		return (-1);
	}
	ret = ic.ax & 0xFF; /* al is the current mode */

	ic.ax = mode & 0xFF; /* ah = 0, al = mode */
	if (bios_doint(0x10, &ic) & PS_C) {
		dprintf("bios_doint returned: %d\r\n", ret);
		return (-1);
	} /* Set Video mode */

	return (ret);
}

/*
 * unsigned char * graphics_get_font()
 * BIOS call "INT 10H Function 11h" to set font
 *	Call with	%ah = 0x11
 *	Return 		correct : font address
 *			error	: 0
 */
unsigned char *
graphics_get_font()
{
	int ret;
	struct int_pb ic = {0};

	ic.ax = 0x1130;
	ic.bx = 0x0600; /* font 8x16 */
	ret = bios_doint(0x10, &ic); /* get font address */
	if (ret & PS_C) {
		dprintf("bios_doint returned: %d\r\n", ret);
		return (0);
	}

	ret = (ic.es << 4) + ic.bp;
	return ((unsigned char *) ret);
}

/*
 * int graphics_set_palette(unsigned index, unsigned red,
 *		unsigned green,unsigned blue)
 * BIOS call "INT 10H Function 10h" to set individual dac register
 *	Call with	%ah = 0x10
 *			%bx = register number
 *			%ch = new value for green (0-63)
 *			%cl = new value for blue (0-63)
 *			%dh = new value for red (0-63)
 *	Return 		correct : 1
 *			error	: 0
 */
int
graphics_set_palette(int index, int red, int green, int blue)
{
	int ret;
	struct int_pb ic = {0};
	/* wait vertical active display */
	while (((inb(VGA_IO_IS) & 0x8)) == 0x8) {}
	/* wait vertical retrace */
	while (((inb(VGA_IO_IS) & 0x8)) == 0x8) {}

	outb(VGA_IO_WMR, (index & 0xFF));
	outb(VGA_IO_DR, (red & 0xFF));
	outb(VGA_IO_DR, (green & 0xFF));
	outb(VGA_IO_DR, (blue & 0xFF));

	ic.ax = 0x1000;
	ic.bx = ((index & 0xFF) <<8) | (index & 0xFF); /* ?? */
	ic.cx = ((green & 0xFF) <<8) | (blue & 0xFF);
	ic.dx = (red & 0xFF) <<8;
	ret = bios_doint(0x10, &ic); /* set palette registert */
	if (ret & PS_C) {
		dprintf("bios_doint returned: %d\r\n", ret);
		return (0);
	} else
	return (1);
}

/* Leave graphics mode */
void
graphics_end(void)
{
	if (graphics_inited) {
		set_videomode(saved_videomode);
		graphics_inited = 0;
	}
}

/* Print ch on the screen.  Handle any needed scrolling or the like */
void
graphics_putchar(int ch)
{
	ch &= 0xff;

	graphics_cursor(0);

	if (ch == '\n') {
		if (fonty + 1 < y1)
			graphics_setxy(fontx, fonty + 1);
		else
			graphics_scroll();
		graphics_cursor(1);
		return;
	} else if (ch == '\r') {
		graphics_setxy(x0, fonty);
		graphics_cursor(1);
		return;
	}

	graphics_cursor(0);

	text[fonty * 80 + fontx] = ch;
	text[fonty * 80 + fontx] &= 0x00ff;
	if (graphics_current_color & 0xf0)
		text[fonty * 80 + fontx] |= 0x100;

	graphics_cursor(0);

	if ((fontx + 1) >= x1) {
		graphics_setxy(x0, fonty);
		if (fonty + 1 < y1)
			graphics_setxy(x0, fonty + 1);
		else
			graphics_scroll();
	} else {
		graphics_setxy(fontx + 1, fonty);
	}

	graphics_cursor(1);
}

/* get the current location of the cursor */
int
graphics_getxy(void)
{
	return ((fontx << 8) | fonty);
}

void
graphics_gotoxy(int x, int y)
{
	graphics_cursor(0);

	graphics_setxy(x, y);

	graphics_cursor(1);
}

void
graphics_cls(void)
{
	int i;
	unsigned char *mem, *s1, *s2, *s4, *s8;

	graphics_cursor(0);
	graphics_gotoxy(x0, y0);

	mem = (unsigned char *)VIDEOMEM;
	s1 = (unsigned char *)VSHADOW1;
	s2 = (unsigned char *)VSHADOW2;
	s4 = (unsigned char *)VSHADOW4;
	s8 = (unsigned char *)VSHADOW8;

	for (i = 0; i < 80 * 30; i++)
		text[i] = ' ';
	graphics_cursor(1);

	BitMask(0xff);

	/* plano 1 */
	MapMask(1);
	graphics_memcpy(mem, s1, 38400);

	/* plano 2 */
	MapMask(2);
	graphics_memcpy(mem, s2, 38400);

	/* plano 3 */
	MapMask(4);
	graphics_memcpy(mem, s4, 38400);

	/* plano 4 */
	MapMask(8);
	graphics_memcpy(mem, s8, 38400);

	MapMask(15);
}

void
graphics_setcolorstate(color_state state)
{
	switch (state) {
	case COLOR_STATE_STANDARD:
		graphics_current_color = graphics_standard_color;
		break;
	case COLOR_STATE_NORMAL:
		graphics_current_color = graphics_normal_color;
		break;
	case COLOR_STATE_HIGHLIGHT:
		graphics_current_color = graphics_highlight_color;
		break;
	default:
		graphics_current_color = graphics_standard_color;
		break;
	}

	graphics_color_state = state;
}

void
graphics_setcolor(int normal_color, int highlight_color)
{
	graphics_normal_color = normal_color;
	graphics_highlight_color = highlight_color;

	graphics_setcolorstate(graphics_color_state);
}

void
graphics_setcursor(int on)
{
	/* FIXME: we don't have a cursor in graphics */
}

/*
 * Read in the splashscreen image and set the palette up appropriately.
 * Format of splashscreen is an xpm (can be gzipped) with 16 colors and
 * 640x480.
 */
static int
read_image(char *s)
{
	char buf[32], pal[16];
	unsigned char c, base, mask, *s1, *s2, *s4, *s8;
	unsigned i, len, idx, colors, x, y, width, height;
	int fd;
	ssize_t count;

	fd = openfile(s, 0);
	if (fd == -1) {
			dprintf("error opening %s\n", s);
			return (0);
	}

	/* read header */
	count = read(fd, (char *)&buf, 10);
	if ((count < 10) || graphics_memcmp(buf, "/* XPM */\n", 10)) {
	close(fd);
	dprintf("read header error\n");
	return (0);
	}

	/* parse info */
	while (read(fd, &c, 1)) {
	if (c == '"')
		break;
	}

	while (read(fd, &c, 1) && (c == ' ' || c == '\t'))
		;

	i = 0;
	width = c - '0';
	while (read(fd, &c, 1)) {
		if (c >= '0' && c <= '9')
			width = width * 10 + c - '0';
		else
			break;
	}
	while (read(fd, &c, 1) && (c == ' ' || c == '\t'))
		;

	height = c - '0';
	while (read(fd, &c, 1)) {
		if (c >= '0' && c <= '9')
			height = height * 10 + c - '0';
		else
			break;
	}
	while (read(fd, &c, 1) && (c == ' ' || c == '\t'))
		;

	colors = c - '0';
	while (read(fd, &c, 1)) {
		if (c >= '0' && c <= '9')
			colors = colors * 10 + c - '0';
		else
			break;
	}

	base = 0;
	while (read(fd, &c, 1) && c != '"')
		;
	/* palette */
	for (i = 0, idx = 1; i < colors; i++) {
		len = 0;

		while (read(fd, &c, 1) && c != '"')
			;
		read(fd, &c, 1);	   /* char */
		base = c;
		read(fd, buf, 4);	  /* \t c # */

		while (read(fd, &c, 1) && c != '"') {
			if (len < sizeof (buf))
				buf[len++] = c;
		}

		if (len == 6 && idx < 15) {
			int r = ((hex(buf[0]) << 4) | hex(buf[1])) >> 2;
			int g = ((hex(buf[2]) << 4) | hex(buf[3])) >> 2;
			int b = ((hex(buf[4]) << 4) | hex(buf[5])) >> 2;
			pal[idx] = base;
			graphics_set_palette(idx, r, g, b);
			++idx;
		}
	}

	x = y = len = 0;

	s1 = (unsigned char *)VSHADOW1;
	s2 = (unsigned char *)VSHADOW2;
	s4 = (unsigned char *)VSHADOW4;
	s8 = (unsigned char *)VSHADOW8;

	for (i = 0; i < 38400; i++)
		s1[i] = s2[i] = s4[i] = s8[i] = 0;

	/* parse xpm data */
	while (y < height) {
		while (1) {
			if (!read(fd, &c, 1)) {
				close(fd);
				return (0);
			}
			if (c == '"')
				break;
		}

		while (read(fd, &c, 1) && c != '"') {
			for (i = 1; i < 15; i++)
				if (pal[i] == c) {
					c = i;
					break;
				}

			mask = 0x80 >> (x & 7);
			if (c & 1)
				s1[len + (x >> 3)] |= mask;
			if (c & 2)
				s2[len + (x >> 3)] |= mask;
			if (c & 4)
				s4[len + (x >> 3)] |= mask;
			if (c & 8)
				s8[len + (x >> 3)] |= mask;

			if (++x >= 640) {
				x = 0;

				if (y < 480)
					len += 80;
				++y;
			}
		}
	}

	close(fd);

	graphics_set_palette(0, (background >> 16), (background >> 8) & 63,
				background & 63);
	graphics_set_palette(15, (foreground >> 16), (foreground >> 8) & 63,
				foreground & 63);
	graphics_set_palette(0x11, (border >> 16), (border >> 8) & 63,
				border & 63);

	return (1);
}

/* Convert a character which is a hex digit to the appropriate integer */
static int
hex(int v)
{
	if (v >= 'A' && v <= 'F')
		return (v - 'A' + 10);
	if (v >= 'a' && v <= 'f')
		return (v - 'a' + 10);
	return (v - '0');
}


/* move the graphics cursor location to col, row */
static void
graphics_setxy(int col, int row)
{
	if (col >= x0 && col < x1) {
		fontx = col;
		cursorX = col << 3;
	}
	if (row >= y0 && row < y1) {
		fonty = row;
		cursorY = row << 4;
	}
}

static void
graphics_memcpy(void *dest, const void *src, int len)
{
	int i;
	register char *d = (char *)dest, *s = (char *)src;

	for (i = 0; i < len; i++)
		d[i] = s[i];
}

static int
graphics_memcmp(const char *s1, const char *s2, int n)
{
	while (n) {
		if (*s1 < *s2)
			return (-1);
		else if (*s1 > *s2)
			return (1);
		s1++;
		s2++;
		n--;
	}

	return (0);
}

/* scroll the screen */
static void
graphics_scroll()
{
	int i, j;

	/* we don't want to scroll recursively... that would be bad */
	if (no_scroll)
		return;
	no_scroll = 1;

	/* move everything up a line */
	for (j = y0 + 1; j < y1; j++) {
		graphics_gotoxy(x0, j - 1);
		for (i = x0; i < x1; i++) {
			graphics_putchar(text[j * 80 + i]);
		}
	}

	/* last line should be blank */
	graphics_gotoxy(x0, y1 - 1);
	for (i = x0; i < x1; i++)
		graphics_putchar(' ');
	graphics_setxy(x0, y1 - 1);

	no_scroll = 0;
}


void graphics_cursor(int set) {
	unsigned char *pat, *mem, *ptr, chr[16 << 2];
	int i, ch, invert, offset;

	if (set && no_scroll)
		return;

	offset = cursorY * 80 + fontx;
	ch = text[fonty * 80 + fontx] & 0xff;
	invert = (text[fonty * 80 + fontx] & 0xff00) != 0;
	pat = font8x16 + (ch << 4);

	mem = (unsigned char *)VIDEOMEM + offset;

	if (set) {
		MapMask(15);
		ptr = mem;
		for (i = 0; i < 16; i++, ptr += 80) {
			cursorBuf[i] = pat[i];
			*ptr = ~pat[i];
		}
		return;
	}

	for (i = 0; i < 16; i++) {
		unsigned char mask = pat[i];

		if (!invert) {
			chr[i	 ] = ((unsigned char *)VSHADOW1)[offset];
			chr[16 + i] = ((unsigned char *)VSHADOW2)[offset];
			chr[32 + i] = ((unsigned char *)VSHADOW4)[offset];
			chr[48 + i] = ((unsigned char *)VSHADOW8)[offset];

			chr[i	 ] |= mask;
			chr[16 + i] |= mask;
			chr[32 + i] |= mask;
			chr[48 + i] |= mask;

			offset += 80;
		} else {
			chr[i	 ] = mask;
			chr[16 + i] = mask;
			chr[32 + i] = mask;
			chr[48 + i] = mask;
		}
	}

	offset = 0;
	for (i = 1; i < 16; i <<= 1, offset += 16) {
		int j;

		MapMask(i);
		ptr = mem;
		for (j = 0; j < 16; j++, ptr += 80)
			*ptr = chr[j + offset];
	}

	MapMask(15);
}
