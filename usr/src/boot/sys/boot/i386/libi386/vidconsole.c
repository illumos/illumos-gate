/*
 * Copyright (c) 1998 Michael Smith (msmith@freebsd.org)
 * Copyright (c) 1997 Kazutaka YOKOTA (yokota@zodiac.mech.utsunomiya-u.ac.jp)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	Id: probe_keyboard.c,v 1.13 1997/06/09 05:10:55 bde Exp
 */

#include <sys/cdefs.h>

#include <stand.h>
#include <bootstrap.h>
#include <sys/tem_impl.h>
#include <sys/visual_io.h>
#include <sys/multiboot2.h>
#include <btxv86.h>
#include <machine/psl.h>
#include <machine/metadata.h>
#include "libi386.h"
#include "vbe.h"
#include <gfx_fb.h>
#include <sys/vgareg.h>
#include <sys/vgasubr.h>
#include <machine/cpufunc.h>

#if KEYBOARD_PROBE

static int	probe_keyboard(void);
#endif
static void	vidc_probe(struct console *cp);
static int	vidc_init(struct console *cp, int arg);
static void	vidc_putchar(struct console *cp, int c);
static int	vidc_getchar(struct console *cp);
static int	vidc_ischar(struct console *cp);
static int	vidc_ioctl(struct console *cp, int cmd, void *data);
static void	vidc_biosputchar(int c);

static int vidc_vbe_devinit(struct vis_devinit *);
static void vidc_cons_cursor(struct vis_conscursor *);
static int vidc_vbe_cons_put_cmap(struct vis_cmap *);

static int vidc_text_devinit(struct vis_devinit *);
static int vidc_text_cons_clear(struct vis_consclear *);
static void vidc_text_cons_copy(struct vis_conscopy *);
static void vidc_text_cons_display(struct vis_consdisplay *);
static void vidc_text_set_cursor(screen_pos_t, screen_pos_t, boolean_t);
static void vidc_text_get_cursor(screen_pos_t *, screen_pos_t *);
static int vidc_text_cons_put_cmap(struct vis_cmap *);

static int vidc_started;
static uint16_t	*vgatext;

/* mode change callback and argument from tem */
static vis_modechg_cb_t modechg_cb;
static struct vis_modechg_arg *modechg_arg;
static tem_vt_state_t tem;

#define	KEYBUFSZ	10
#define DEFAULT_FGCOLOR	7
#define DEFAULT_BGCOLOR	0

static uint8_t	keybuf[KEYBUFSZ];	/* keybuf for extended codes */

struct console text = {
	.c_name = "text",
	.c_desc = "internal video/keyboard",
	.c_flags = 0,
	.c_probe = vidc_probe,
	.c_init = vidc_init,
	.c_out = vidc_putchar,
	.c_in = vidc_getchar,
	.c_ready = vidc_ischar,
	.c_ioctl = vidc_ioctl,
	.c_private = NULL
};

static struct vis_identifier fb_ident = { "vidc_fb" };
static struct vis_identifier text_ident = { "vidc_text" };

struct visual_ops fb_ops = {
	.ident = &fb_ident,
	.kdsetmode = NULL,
	.devinit = vidc_vbe_devinit,
	.cons_copy = NULL,
	.cons_display = NULL,
	.cons_cursor = vidc_cons_cursor,
	.cons_clear = NULL,
	.cons_put_cmap = vidc_vbe_cons_put_cmap
};

struct visual_ops text_ops = {
	.ident = &text_ident,
	.kdsetmode = NULL,
	.devinit = vidc_text_devinit,
	.cons_copy = vidc_text_cons_copy,
	.cons_display = vidc_text_cons_display,
	.cons_cursor = vidc_cons_cursor,
	.cons_clear = vidc_text_cons_clear,
	.cons_put_cmap = vidc_text_cons_put_cmap
};

/*
 * platform specific functions for tem
 */
int
plat_stdout_is_framebuffer(void)
{
	if (vbe_available() && VBE_VALID_MODE(vbe_get_mode())) {
		return (1);
	}
        return (0);
}

void
plat_tem_hide_prom_cursor(void)
{
	vidc_text_set_cursor(0, 0, B_FALSE);
}

void
plat_tem_get_prom_pos(uint32_t *row, uint32_t *col)
{
	screen_pos_t x, y;

	if (plat_stdout_is_framebuffer()) {
		*row = 0;
		*col = 0;
	} else {
		vidc_text_get_cursor(&y, &x);
		*row = (uint32_t) y;
		*col = (uint32_t) x;
	}
}

/*
 * plat_tem_get_prom_size() is supposed to return screen size
 * in chars. Return real data for text mode and TEM defaults for graphical
 * mode, so the tem can compute values based on default and font.
 */
void
plat_tem_get_prom_size(size_t *height, size_t *width)
{
	if (plat_stdout_is_framebuffer()) {
		*height = TEM_DEFAULT_ROWS;
		*width = TEM_DEFAULT_COLS;
	} else {
		*height = TEXT_ROWS;
		*width = TEXT_COLS;
	}
}

void
plat_cons_update_mode(int mode __unused)
{
	struct vis_devinit devinit;

	if (tem == NULL)	/* tem is not set up */
		return;

	if (plat_stdout_is_framebuffer()) {
		devinit.version = VIS_CONS_REV;
		devinit.width = gfx_fb.framebuffer_common.framebuffer_width;
		devinit.height = gfx_fb.framebuffer_common.framebuffer_height;
		devinit.depth = gfx_fb.framebuffer_common.framebuffer_bpp;
		devinit.linebytes = gfx_fb.framebuffer_common.framebuffer_pitch;
		devinit.color_map = gfx_fb_color_map;
		devinit.mode = VIS_PIXEL;
		text.c_private = &fb_ops;
	} else {
		devinit.version = VIS_CONS_REV;
		devinit.width = TEXT_COLS;
		devinit.height = TEXT_ROWS;
		devinit.depth = 4;
		devinit.linebytes = TEXT_COLS;
		devinit.color_map = NULL;
		devinit.mode = VIS_TEXT;
		text.c_private = &text_ops;
	}

	modechg_cb(modechg_arg, &devinit);
}

static int
vidc_vbe_devinit(struct vis_devinit *devinit)
{
	if (plat_stdout_is_framebuffer() == 0)
		return (1);

	devinit->version = VIS_CONS_REV;
	devinit->width = gfx_fb.framebuffer_common.framebuffer_width;
	devinit->height = gfx_fb.framebuffer_common.framebuffer_height;
	devinit->depth = gfx_fb.framebuffer_common.framebuffer_bpp;
	devinit->linebytes = gfx_fb.framebuffer_common.framebuffer_pitch;
	devinit->color_map = gfx_fb_color_map;
	devinit->mode = VIS_PIXEL;

	modechg_cb = devinit->modechg_cb;
	modechg_arg = devinit->modechg_arg;

	return (0);
}

static int
vidc_text_devinit(struct vis_devinit *devinit)
{
	if (plat_stdout_is_framebuffer())
		return (1);

	devinit->version = VIS_CONS_REV;
	devinit->width = TEXT_COLS;
	devinit->height = TEXT_ROWS;
	devinit->depth = 4;
	devinit->linebytes = TEXT_COLS;
	devinit->color_map = NULL;
	devinit->mode = VIS_TEXT;

	modechg_cb = devinit->modechg_cb;
	modechg_arg = devinit->modechg_arg;

	return (0);
}

static int
vidc_text_cons_clear(struct vis_consclear *ca)
{
	uint16_t val;
	int i;

	val = (solaris_color_to_pc_color[ca->bg_color & 0xf] << 4) |
	    DEFAULT_FGCOLOR;
	val = (val << 8) | ' ';

	for (i = 0; i < TEXT_ROWS * TEXT_COLS; i++)
		vgatext[i] = val;

	return (0);
}

static void
vidc_text_cons_copy(struct vis_conscopy *ma)
{
	uint16_t  *from;
	uint16_t *to;
	int cnt;
	screen_size_t chars_per_row;
	uint16_t *to_row_start;
	uint16_t *from_row_start;
	screen_size_t rows_to_move;
	uint16_t *base;

	/*
	 * Sanity checks.  Note that this is a last-ditch effort to avoid
	 * damage caused by broken-ness or maliciousness above.
	 */
	if (ma->s_col < 0 || ma->s_col >= TEXT_COLS ||
	    ma->s_row < 0 || ma->s_row >= TEXT_ROWS ||
	    ma->e_col < 0 || ma->e_col >= TEXT_COLS ||
	    ma->e_row < 0 || ma->e_row >= TEXT_ROWS ||
	    ma->t_col < 0 || ma->t_col >= TEXT_COLS ||
	    ma->t_row < 0 || ma->t_row >= TEXT_ROWS ||
	    ma->s_col > ma->e_col ||
	    ma->s_row > ma->e_row)
		return;

	/*
	 * Remember we're going to copy shorts because each
	 * character/attribute pair is 16 bits.
	 */
	chars_per_row = ma->e_col - ma->s_col + 1;
	rows_to_move = ma->e_row - ma->s_row + 1;

	/* More sanity checks. */
	if (ma->t_row + rows_to_move > TEXT_ROWS ||
	    ma->t_col + chars_per_row > TEXT_COLS)
		return;

	base = vgatext;

	to_row_start = base + ((ma->t_row * TEXT_COLS) + ma->t_col);
	from_row_start = base + ((ma->s_row * TEXT_COLS) + ma->s_col);

	if (to_row_start < from_row_start) {
		while (rows_to_move-- > 0) {
			to = to_row_start;
			from = from_row_start;
			to_row_start += TEXT_COLS;
			from_row_start += TEXT_COLS;
			for (cnt = chars_per_row; cnt-- > 0; )
				*to++ = *from++;
		}
	} else {
		/*
		 * Offset to the end of the region and copy backwards.
		 */
		cnt = rows_to_move * TEXT_COLS + chars_per_row;
		to_row_start += cnt;
		from_row_start += cnt;

		while (rows_to_move-- > 0) {
			to_row_start -= TEXT_COLS;
			from_row_start -= TEXT_COLS;
			to = to_row_start;
			from = from_row_start;
			for (cnt = chars_per_row; cnt-- > 0; )
				*--to = *--from;
		}
	}
}

/*
 * Binary searchable table for Unicode to CP437 conversion.
 */
struct unicp437 {
	uint16_t	unicode_base;
	uint8_t		cp437_base;
	uint8_t		length;
};

static const struct unicp437 cp437table[] = {
	{ 0x0020, 0x20, 0x5e }, { 0x00a0, 0x20, 0x00 },
	{ 0x00a1, 0xad, 0x00 }, { 0x00a2, 0x9b, 0x00 },
	{ 0x00a3, 0x9c, 0x00 }, { 0x00a5, 0x9d, 0x00 },
	{ 0x00a7, 0x15, 0x00 }, { 0x00aa, 0xa6, 0x00 },
	{ 0x00ab, 0xae, 0x00 }, { 0x00ac, 0xaa, 0x00 },
	{ 0x00b0, 0xf8, 0x00 }, { 0x00b1, 0xf1, 0x00 },
	{ 0x00b2, 0xfd, 0x00 }, { 0x00b5, 0xe6, 0x00 },
	{ 0x00b6, 0x14, 0x00 }, { 0x00b7, 0xfa, 0x00 },
	{ 0x00ba, 0xa7, 0x00 }, { 0x00bb, 0xaf, 0x00 },
	{ 0x00bc, 0xac, 0x00 }, { 0x00bd, 0xab, 0x00 },
	{ 0x00bf, 0xa8, 0x00 }, { 0x00c4, 0x8e, 0x01 },
	{ 0x00c6, 0x92, 0x00 }, { 0x00c7, 0x80, 0x00 },
	{ 0x00c9, 0x90, 0x00 }, { 0x00d1, 0xa5, 0x00 },
	{ 0x00d6, 0x99, 0x00 }, { 0x00dc, 0x9a, 0x00 },
	{ 0x00df, 0xe1, 0x00 }, { 0x00e0, 0x85, 0x00 },
	{ 0x00e1, 0xa0, 0x00 }, { 0x00e2, 0x83, 0x00 },
	{ 0x00e4, 0x84, 0x00 }, { 0x00e5, 0x86, 0x00 },
	{ 0x00e6, 0x91, 0x00 }, { 0x00e7, 0x87, 0x00 },
	{ 0x00e8, 0x8a, 0x00 }, { 0x00e9, 0x82, 0x00 },
	{ 0x00ea, 0x88, 0x01 }, { 0x00ec, 0x8d, 0x00 },
	{ 0x00ed, 0xa1, 0x00 }, { 0x00ee, 0x8c, 0x00 },
	{ 0x00ef, 0x8b, 0x00 }, { 0x00f0, 0xeb, 0x00 },
	{ 0x00f1, 0xa4, 0x00 }, { 0x00f2, 0x95, 0x00 },
	{ 0x00f3, 0xa2, 0x00 }, { 0x00f4, 0x93, 0x00 },
	{ 0x00f6, 0x94, 0x00 }, { 0x00f7, 0xf6, 0x00 },
	{ 0x00f8, 0xed, 0x00 }, { 0x00f9, 0x97, 0x00 },
	{ 0x00fa, 0xa3, 0x00 }, { 0x00fb, 0x96, 0x00 },
	{ 0x00fc, 0x81, 0x00 }, { 0x00ff, 0x98, 0x00 },
	{ 0x0192, 0x9f, 0x00 }, { 0x0393, 0xe2, 0x00 },
	{ 0x0398, 0xe9, 0x00 }, { 0x03a3, 0xe4, 0x00 },
	{ 0x03a6, 0xe8, 0x00 }, { 0x03a9, 0xea, 0x00 },
	{ 0x03b1, 0xe0, 0x01 }, { 0x03b4, 0xeb, 0x00 },
	{ 0x03b5, 0xee, 0x00 }, { 0x03bc, 0xe6, 0x00 },
	{ 0x03c0, 0xe3, 0x00 }, { 0x03c3, 0xe5, 0x00 },
	{ 0x03c4, 0xe7, 0x00 }, { 0x03c6, 0xed, 0x00 },
	{ 0x03d5, 0xed, 0x00 }, { 0x2010, 0x2d, 0x00 },
	{ 0x2014, 0x2d, 0x00 }, { 0x2018, 0x60, 0x00 },
	{ 0x2019, 0x27, 0x00 }, { 0x201c, 0x22, 0x00 },
	{ 0x201d, 0x22, 0x00 }, { 0x2022, 0x07, 0x00 },
	{ 0x203c, 0x13, 0x00 }, { 0x207f, 0xfc, 0x00 },
	{ 0x20a7, 0x9e, 0x00 }, { 0x20ac, 0xee, 0x00 },
	{ 0x2126, 0xea, 0x00 }, { 0x2190, 0x1b, 0x00 },
	{ 0x2191, 0x18, 0x00 }, { 0x2192, 0x1a, 0x00 },
	{ 0x2193, 0x19, 0x00 }, { 0x2194, 0x1d, 0x00 },
	{ 0x2195, 0x12, 0x00 }, { 0x21a8, 0x17, 0x00 },
	{ 0x2202, 0xeb, 0x00 }, { 0x2208, 0xee, 0x00 },
	{ 0x2211, 0xe4, 0x00 }, { 0x2212, 0x2d, 0x00 },
	{ 0x2219, 0xf9, 0x00 }, { 0x221a, 0xfb, 0x00 },
	{ 0x221e, 0xec, 0x00 }, { 0x221f, 0x1c, 0x00 },
	{ 0x2229, 0xef, 0x00 }, { 0x2248, 0xf7, 0x00 },
	{ 0x2261, 0xf0, 0x00 }, { 0x2264, 0xf3, 0x00 },
	{ 0x2265, 0xf2, 0x00 }, { 0x2302, 0x7f, 0x00 },
	{ 0x2310, 0xa9, 0x00 }, { 0x2320, 0xf4, 0x00 },
	{ 0x2321, 0xf5, 0x00 }, { 0x2500, 0xc4, 0x00 },
	{ 0x2502, 0xb3, 0x00 }, { 0x250c, 0xda, 0x00 },
	{ 0x2510, 0xbf, 0x00 }, { 0x2514, 0xc0, 0x00 },
	{ 0x2518, 0xd9, 0x00 }, { 0x251c, 0xc3, 0x00 },
	{ 0x2524, 0xb4, 0x00 }, { 0x252c, 0xc2, 0x00 },
	{ 0x2534, 0xc1, 0x00 }, { 0x253c, 0xc5, 0x00 },
	{ 0x2550, 0xcd, 0x00 }, { 0x2551, 0xba, 0x00 },
	{ 0x2552, 0xd5, 0x00 }, { 0x2553, 0xd6, 0x00 },
	{ 0x2554, 0xc9, 0x00 }, { 0x2555, 0xb8, 0x00 },
	{ 0x2556, 0xb7, 0x00 }, { 0x2557, 0xbb, 0x00 },
	{ 0x2558, 0xd4, 0x00 }, { 0x2559, 0xd3, 0x00 },
	{ 0x255a, 0xc8, 0x00 }, { 0x255b, 0xbe, 0x00 },
	{ 0x255c, 0xbd, 0x00 }, { 0x255d, 0xbc, 0x00 },
	{ 0x255e, 0xc6, 0x01 }, { 0x2560, 0xcc, 0x00 },
	{ 0x2561, 0xb5, 0x00 }, { 0x2562, 0xb6, 0x00 },
	{ 0x2563, 0xb9, 0x00 }, { 0x2564, 0xd1, 0x01 },
	{ 0x2566, 0xcb, 0x00 }, { 0x2567, 0xcf, 0x00 },
	{ 0x2568, 0xd0, 0x00 }, { 0x2569, 0xca, 0x00 },
	{ 0x256a, 0xd8, 0x00 }, { 0x256b, 0xd7, 0x00 },
	{ 0x256c, 0xce, 0x00 }, { 0x2580, 0xdf, 0x00 },
	{ 0x2584, 0xdc, 0x00 }, { 0x2588, 0xdb, 0x00 },
	{ 0x258c, 0xdd, 0x00 }, { 0x2590, 0xde, 0x00 },
	{ 0x2591, 0xb0, 0x02 }, { 0x25a0, 0xfe, 0x00 },
	{ 0x25ac, 0x16, 0x00 }, { 0x25b2, 0x1e, 0x00 },
	{ 0x25ba, 0x10, 0x00 }, { 0x25bc, 0x1f, 0x00 },
	{ 0x25c4, 0x11, 0x00 }, { 0x25cb, 0x09, 0x00 },
	{ 0x25d8, 0x08, 0x00 }, { 0x25d9, 0x0a, 0x00 },
	{ 0x263a, 0x01, 0x01 }, { 0x263c, 0x0f, 0x00 },
	{ 0x2640, 0x0c, 0x00 }, { 0x2642, 0x0b, 0x00 },
	{ 0x2660, 0x06, 0x00 }, { 0x2663, 0x05, 0x00 },
	{ 0x2665, 0x03, 0x01 }, { 0x266a, 0x0d, 0x00 },
	{ 0x266c, 0x0e, 0x00 }
};

static uint8_t
vga_get_cp437(tem_char_t c)
{
	int min, mid, max;

	min = 0;
	max = (sizeof(cp437table) / sizeof(struct unicp437)) - 1;

	if (c < cp437table[0].unicode_base ||
	    c > cp437table[max].unicode_base + cp437table[max].length)
		return ('?');

	while (max >= min) {
		mid = (min + max) / 2;
		if (c < cp437table[mid].unicode_base)
			max = mid - 1;
		else if (c > cp437table[mid].unicode_base +
		    cp437table[mid].length)
			min = mid + 1;
                else
			return (c - cp437table[mid].unicode_base +
			    cp437table[mid].cp437_base);
        }

	return ('?');
}

static void
vidc_text_cons_display(struct vis_consdisplay *da)
{
	int i;
	uint8_t attr;
	tem_char_t *data;
	struct cgatext {
		uint8_t ch;
		uint8_t attr;
	} *addr;

	data = (tem_char_t *)da->data;
	attr = (solaris_color_to_pc_color[da->bg_color & 0xf] << 4) |
	    solaris_color_to_pc_color[da->fg_color & 0xf];
	addr = (struct cgatext *) vgatext + (da->row * TEXT_COLS + da->col);

	for (i = 0; i < da->width; i++) {
		addr[i].ch = vga_get_cp437(data[i]);
		addr[i].attr = attr;
	}
}

static void
vidc_text_set_cursor(screen_pos_t row, screen_pos_t col, boolean_t visible)
{
	uint16_t addr;
	uint8_t msl, s, e;

	msl = vga_get_crtc(VGA_REG_ADDR, VGA_CRTC_MAX_S_LN) & 0x1f;
	s = vga_get_crtc(VGA_REG_ADDR, VGA_CRTC_CSSL) & 0xC0;
	e = vga_get_crtc(VGA_REG_ADDR, VGA_CRTC_CESL);

	if (visible == B_TRUE) {
		addr = row * TEXT_COLS + col;
		vga_set_crtc(VGA_REG_ADDR, VGA_CRTC_CLAH, addr >> 8);
		vga_set_crtc(VGA_REG_ADDR, VGA_CRTC_CLAL, addr & 0xff);
		e = msl;
	} else {
		s |= (1<<5);
	}
	vga_set_crtc(VGA_REG_ADDR, VGA_CRTC_CSSL, s);
	vga_set_crtc(VGA_REG_ADDR, VGA_CRTC_CESL, e);
}

static void
vidc_text_get_cursor(screen_pos_t *row, screen_pos_t *col)
{
	uint16_t addr;

	addr = (vga_get_crtc(VGA_REG_ADDR, VGA_CRTC_CLAH) << 8) +
	    vga_get_crtc(VGA_REG_ADDR, VGA_CRTC_CLAL);

	*row = addr / TEXT_COLS;
	*col = addr % TEXT_COLS;
}

static void
vidc_cons_cursor(struct vis_conscursor *cc)
{
	switch (cc->action) {
	case VIS_HIDE_CURSOR:
		if (plat_stdout_is_framebuffer())
			gfx_fb_display_cursor(cc);
		else
			vidc_text_set_cursor(cc->row, cc->col, B_FALSE);
		break;
	case VIS_DISPLAY_CURSOR:
		if (plat_stdout_is_framebuffer())
			gfx_fb_display_cursor(cc);
		else
			vidc_text_set_cursor(cc->row, cc->col, B_TRUE);
		break;
	case VIS_GET_CURSOR:
		if (plat_stdout_is_framebuffer()) {
			cc->row = 0;
			cc->col = 0;
		} else {
			vidc_text_get_cursor(&cc->row, &cc->col);
		}
		break;
	}
}

static uint8_t
c24_to_vga(uint8_t c, uint8_t mask)
{
	switch (c) {
	case 0x40:
		return (0x15 & mask);
	case 0x80:
		return (0x2A & mask);
	case 0xFF:
		return (c & mask);
	default:
		return (0);
	}
}

static int
vidc_vbe_cons_put_cmap(struct vis_cmap *cm)
{
	int i, bits, rc = 0;
	struct paletteentry pe;

	bits = 1;	/* get DAC palette width */
	rc = biosvbe_palette_format(&bits);
	if (rc != VBE_SUCCESS)
		return (rc);

	bits = 0xFF >> (8 - (bits >> 8));
	pe.Alignment = 0;
	for (i = 0; i < cm->count; i++) {
		pe.Red = c24_to_vga(cm->red[i], bits);
		pe.Green = c24_to_vga(cm->green[i], bits);
		pe.Blue = c24_to_vga(cm->blue[i], bits);
		rc = vbe_set_palette(&pe,
		    solaris_color_to_pc_color[cm->index + i]);
		if (rc != 0)
			break;
	}
	return (rc);
}

static int
vidc_text_cons_put_cmap(struct vis_cmap *cm __unused)
{
	return (1);
}

static int
vidc_ioctl(struct console *cp, int cmd, void *data)
{
	struct visual_ops *ops = cp->c_private;

	switch (cmd) {
	case VIS_GETIDENTIFIER:
		memmove(data, ops->ident, sizeof (struct vis_identifier));
		break;
	case VIS_DEVINIT:
		return (ops->devinit(data));
	case VIS_CONSCLEAR:
		return (ops->cons_clear(data));
	case VIS_CONSCOPY:
		ops->cons_copy(data);
		break;
	case VIS_CONSDISPLAY:
		ops->cons_display(data);
		break;
	case VIS_CONSCURSOR:
		ops->cons_cursor(data);
		break;
	case VIS_PUTCMAP:
		ops->cons_put_cmap(data);
		break;
	case VIS_GETCMAP:
	default:
		return (EINVAL);
	}
	return (0);
}

static void
vidc_probe(struct console *cp)
{

	/* look for a keyboard */
#if KEYBOARD_PROBE
	if (probe_keyboard())
#endif
	{
		cp->c_flags |= C_PRESENTIN;
	}

	/* XXX for now, always assume we can do BIOS screen output */
	cp->c_flags |= C_PRESENTOUT;
	vbe_init();
	tem = NULL;
}

static int
vidc_init(struct console *cp, int arg)
{
	int i, rc;

	if (vidc_started && arg == 0)
		return (0);

	vidc_started = 1;

	/*
	 * Check Miscellaneous Output Register (Read at 3CCh, Write at 3C2h)
	 * for bit 1 (Input/Output Address Select), which means
	 * color/graphics adapter.
	 */
	if (vga_get_reg(VGA_REG_ADDR, VGA_MISC_R) & VGA_MISC_IOA_SEL)
		vgatext = (uint16_t *) PTOV(VGA_MEM_ADDR + VGA_COLOR_BASE);
	else
		vgatext = (uint16_t *) PTOV(VGA_MEM_ADDR + VGA_MONO_BASE);

	/* set 16bit colors */
	i = vga_get_atr(VGA_REG_ADDR, VGA_ATR_MODE);
	i &= ~VGA_ATR_MODE_BLINK;
	i &= ~VGA_ATR_MODE_9WIDE;
	vga_set_atr(VGA_REG_ADDR, VGA_ATR_MODE, i);

	plat_tem_hide_prom_cursor();

	memset(keybuf, 0, KEYBUFSZ);

	/* default to text mode */
	cp->c_private = &text_ops;

	if (vbe_available()) {
		rc = vbe_default_mode();
		/* if rc is not legal VBE mode, use text mode */
		if (VBE_VALID_MODE(rc)) {
			if (vbe_set_mode(rc) == 0)
				cp->c_private = &fb_ops;
			else
				bios_set_text_mode(VGA_TEXT_MODE);
		}
	}

	gfx_framework_init(&fb_ops);
	rc = tem_info_init(cp);

	if (rc != 0) {
		bios_set_text_mode(3);
		cp->c_private = &text_ops;
		rc = tem_info_init(cp); /* try again */
	}
	if (rc == 0 && tem == NULL) {
		tem = tem_init();
		if (tem != NULL)
			tem_activate(tem, B_TRUE);
	}

	for (i = 0; i < 10 && vidc_ischar(cp); i++)
		(void)vidc_getchar(cp);

	return (0);	/* XXX reinit? */
}

static void
vidc_biosputchar(int c)
{
	v86.ctl = 0;
	v86.addr = 0x10;
	v86.eax = 0xe00 | (c & 0xff);
	v86.ebx = 0x7;
	v86int();
}

static void
vidc_putchar(struct console *cp __unused, int c)
{
	uint8_t buf = c;

	/* make sure we have some console output, support for panic() */
	if (tem == NULL)
		vidc_biosputchar(c);
	else
		tem_write(tem, &buf, sizeof (buf));
}

static int
vidc_getchar(struct console *cp)
{
	int i, c;

	for (i = 0; i < KEYBUFSZ; i++) {
		if (keybuf[i] != 0) {
			c = keybuf[i];
			keybuf[i] = 0;
			return (c);
		}
	}

	if (vidc_ischar(cp)) {
		v86.ctl = 0;
		v86.addr = 0x16;
		v86.eax = 0x0;
		v86int();
		if ((v86.eax & 0xff) != 0) {
			return (v86.eax & 0xff);
		}

		/* extended keys */
		switch (v86.eax & 0xff00) {
		case 0x4800:	/* up */
			keybuf[0] = '[';
			keybuf[1] = 'A';
			return (0x1b);	/* esc */
		case 0x4b00:	/* left */
			keybuf[0] = '[';
			keybuf[1] = 'D';
			return (0x1b);	/* esc */
		case 0x4d00:	/* right */
			keybuf[0] = '[';
			keybuf[1] = 'C';
			return (0x1b);	/* esc */
		case 0x5000:	/* down */
			keybuf[0] = '[';
			keybuf[1] = 'B';
			return (0x1b);	/* esc */
		default:
			return (-1);
		}
	} else {
		return (-1);
	}
}

static int
vidc_ischar(struct console *cp __unused)
{
	int i;

	for (i = 0; i < KEYBUFSZ; i++) {
		if (keybuf[i] != 0) {
			return (1);
		}
	}

	v86.ctl = V86_FLAGS;
	v86.addr = 0x16;
	v86.eax = 0x100;
	v86int();
	return (!V86_ZR(v86.efl));
}

#if KEYBOARD_PROBE

#define PROBE_MAXRETRY	5
#define PROBE_MAXWAIT	400
#define IO_DUMMY	0x84
#define IO_KBD		0x060		/* 8042 Keyboard */

/* selected defines from kbdio.h */
#define	KBD_STATUS_PORT		4	/* status port, read */
#define KBD_DATA_PORT		0	/* data port, read/write
					 * also used as keyboard command
					 * and mouse command port
					 */
#define KBDC_ECHO		0x00ee
#define KBDS_ANY_BUFFER_FULL	0x0001
#define KBDS_INPUT_BUFFER_FULL	0x0002
#define KBD_ECHO		0x00ee

/* 7 microsec delay necessary for some keyboard controllers */
static void
delay7(void)
{
	/*
	 * I know this is broken, but no timer is available yet at this stage...
	 * See also comments in `delay1ms()'.
	 */
	inb(IO_DUMMY); inb(IO_DUMMY);
	inb(IO_DUMMY); inb(IO_DUMMY);
	inb(IO_DUMMY); inb(IO_DUMMY);
}

/*
 * This routine uses an inb to an unused port, the time to execute that
 * inb is approximately 1.25uS.  This value is pretty constant across
 * all CPU's and all buses, with the exception of some PCI implentations
 * that do not forward this I/O address to the ISA bus as they know it
 * is not a valid ISA bus address, those machines execute this inb in
 * 60 nS :-(.
 *
 */
static void
delay1ms(void)
{
	int i = 800;
	while (--i >= 0)
		(void)inb(0x84);
}

/*
 * We use the presence/absence of a keyboard to determine whether the internal
 * console can be used for input.
 *
 * Perform a simple test on the keyboard; issue the ECHO command and see
 * if the right answer is returned. We don't do anything as drastic as
 * full keyboard reset; it will be too troublesome and take too much time.
 */
static int
probe_keyboard(void)
{
	int retry = PROBE_MAXRETRY;
	int wait;
	int i;

	while (--retry >= 0) {
		/* flush any noise */
		while (inb(IO_KBD + KBD_STATUS_PORT) & KBDS_ANY_BUFFER_FULL) {
			delay7();
			inb(IO_KBD + KBD_DATA_PORT);
			delay1ms();
		}

		/* wait until the controller can accept a command */
		for (wait = PROBE_MAXWAIT; wait > 0; --wait) {
			if (((i = inb(IO_KBD + KBD_STATUS_PORT)) &
			    (KBDS_INPUT_BUFFER_FULL | KBDS_ANY_BUFFER_FULL))
			    == 0)
				break;
			if (i & KBDS_ANY_BUFFER_FULL) {
				delay7();
				inb(IO_KBD + KBD_DATA_PORT);
			}
			delay1ms();
		}
		if (wait <= 0)
			continue;

		/* send the ECHO command */
		outb(IO_KBD + KBD_DATA_PORT, KBDC_ECHO);

		/* wait for a response */
		for (wait = PROBE_MAXWAIT; wait > 0; --wait) {
			if (inb(IO_KBD + KBD_STATUS_PORT) &
			    KBDS_ANY_BUFFER_FULL)
				break;
			delay1ms();
		}
		if (wait <= 0)
			continue;

		delay7();
		i = inb(IO_KBD + KBD_DATA_PORT);
#ifdef PROBE_KBD_BEBUG
		printf("probe_keyboard: got 0x%x.\n", i);
#endif
		if (i == KBD_ECHO) {
			/* got the right answer */
			return (1);
		}
	}

	return (0);
}
#endif /* KEYBOARD_PROBE */
