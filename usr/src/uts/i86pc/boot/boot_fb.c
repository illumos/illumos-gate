/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

/*
 * dboot and early kernel needs simple putchar(int) interface to implement
 * printf() support. So we implement simple interface on top of
 * linear frame buffer, since we can not use tem directly, we are
 * just borrowing bits from it.
 *
 * Note, this implementation is assuming UEFI linear frame buffer and
 * 32-bit depth, which should not be issue as GOP is supposed to provide those.
 * At the time of writing, this is the only case for frame buffer anyhow.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/multiboot2.h>
#include <sys/framebuffer.h>
#include <sys/bootinfo.h>
#include <sys/boot_console.h>
#include <sys/bootconf.h>

#define	P2ROUNDUP(x, align)	(-(-(x) & -(align)))
#define	MIN(a, b)		((a) < (b) ? (a) : (b))

/*
 * Simplified visual_io data structures from visual_io.h
 */

struct vis_consdisplay {
	uint16_t row;		/* Row to display data at */
	uint16_t col;		/* Col to display data at */
	uint16_t width;		/* Width of data */
	uint16_t height;	/* Height of data */
	uint8_t  *data;		/* Data to display */
};

struct vis_conscopy {
	uint16_t s_row;		/* Starting row */
	uint16_t s_col;		/* Starting col */
	uint16_t e_row;		/* Ending row */
	uint16_t e_col;		/* Ending col */
	uint16_t t_row;		/* Row to move to */
	uint16_t t_col;		/* Col to move to */
};

/* we have built in fonts 12x22, 6x10, 7x14 and depth 32. */
#define	MAX_GLYPH	(12 * 22 * 4)

static struct font	boot_fb_font; /* set by set_font() */
static uint8_t		glyph[MAX_GLYPH];
static uint32_t		last_line_size;
static fb_info_pixel_coord_t last_line;

/* color translation */
typedef struct {
	uint8_t red[16];
	uint8_t green[16];
	uint8_t blue[16];
} text_cmap_t;

/* BEGIN CSTYLED */
/*                             Bk  Rd  Gr  Br  Bl  Mg  Cy  Wh */
static uint8_t dim_xlate[] = {  1,  5,  3,  7,  2,  6,  4,  8 };
static uint8_t brt_xlate[] = {  9, 13, 11, 15, 10, 14, 12,  0 };
/* END CSTYLED */

static text_cmap_t cmap4_to_24 = {
/* BEGIN CSTYLED */
/* 0    1    2    3    4    5    6    7    8    9   10   11   12   13   14   15
  Wh+  Bk   Bl   Gr   Cy   Rd   Mg   Br   Wh   Bk+  Bl+  Gr+  Cy+  Rd+  Mg+  Yw */
  0xff,0x00,0x00,0x00,0x00,0x80,0x80,0x80,0x80,0x40,0x00,0x00,0x00,0xff,0xff,0xff,
  0xff,0x00,0x00,0x80,0x80,0x00,0x00,0x80,0x80,0x40,0x00,0xff,0xff,0x00,0x00,0xff,
  0xff,0x00,0x80,0x00,0x80,0x00,0x80,0x00,0x80,0x40,0xff,0x00,0xff,0x00,0xff,0x00
/* END CSTYLED */
};

/*
 * extract data from MB2 framebuffer tag and set up initial frame buffer.
 */
boolean_t
xbi_fb_init(struct xboot_info *xbi)
{
	multiboot_tag_framebuffer_t *tag;
	boot_framebuffer_t *xbi_fb;

	xbi_fb = (boot_framebuffer_t *)(uintptr_t)xbi->bi_framebuffer;
	if (xbi_fb == NULL)
		return (B_FALSE);

#if !defined(_BOOT)
	/* For early kernel, we get cursor position from dboot. */
	fb_info.cursor.origin.x = xbi_fb->cursor.origin.x;
	fb_info.cursor.origin.y = xbi_fb->cursor.origin.y;
	fb_info.cursor.pos.x = xbi_fb->cursor.pos.x;
	fb_info.cursor.pos.y = xbi_fb->cursor.pos.y;
	fb_info.cursor.visible = xbi_fb->cursor.visible;
#endif

	tag = (multiboot_tag_framebuffer_t *)(uintptr_t)xbi_fb->framebuffer;
	if (tag == NULL) {
		return (B_FALSE);
	}

	fb_info.paddr = tag->framebuffer_common.framebuffer_addr;
	fb_info.pitch = tag->framebuffer_common.framebuffer_pitch;
	fb_info.depth = tag->framebuffer_common.framebuffer_bpp;
	fb_info.bpp = P2ROUNDUP(fb_info.depth, 8) >> 3;
	fb_info.screen.x = tag->framebuffer_common.framebuffer_width;
	fb_info.screen.y = tag->framebuffer_common.framebuffer_height;
	fb_info.fb_size = fb_info.screen.y * fb_info.pitch;

	if (fb_info.paddr == 0)
		fb_info.fb_type = FB_TYPE_UNKNOWN;

	switch (tag->framebuffer_common.framebuffer_type) {
	case MULTIBOOT_FRAMEBUFFER_TYPE_EGA_TEXT:
		fb_info.fb_type = FB_TYPE_EGA_TEXT;
		return (B_FALSE);

	case MULTIBOOT_FRAMEBUFFER_TYPE_INDEXED:
		if (fb_info.paddr != 0)
			fb_info.fb_type = FB_TYPE_INDEXED;
		return (B_TRUE);

	case MULTIBOOT_FRAMEBUFFER_TYPE_RGB:
		if (fb_info.paddr != 0)
			fb_info.fb_type = FB_TYPE_RGB;
		break;

	default:
		return (B_FALSE);
	}

	fb_info.rgb.red.size = tag->u.fb2.framebuffer_red_mask_size;
	fb_info.rgb.red.pos = tag->u.fb2.framebuffer_red_field_position;
	fb_info.rgb.green.size = tag->u.fb2.framebuffer_green_mask_size;
	fb_info.rgb.green.pos = tag->u.fb2.framebuffer_green_field_position;
	fb_info.rgb.blue.size = tag->u.fb2.framebuffer_blue_mask_size;
	fb_info.rgb.blue.pos = tag->u.fb2.framebuffer_blue_field_position;

	return (B_TRUE);
}

/* set font and pass the data to fb_info */
static void
boot_fb_set_font(uint16_t height, uint16_t width)
{
	short h, w;

	h = MIN(height, 4096);
	w = MIN(width, 4096);

	set_font(&boot_fb_font, (short *)&fb_info.terminal.y,
	    (short *)&fb_info.terminal.x, h, w);
	fb_info.font_width = boot_fb_font.width;
	fb_info.font_height = boot_fb_font.height;
}

/* fill framebuffer */
static void
boot_fb_fill(uint8_t *dst, uint32_t data, uint32_t len)
{
	uint16_t *dst16;
	uint32_t *dst32;
	uint32_t i;

	switch (fb_info.depth) {
	case 24:
	case 8:
		for (i = 0; i < len; i++)
			dst[i] = (uint8_t)data;
		break;
	case 15:
	case 16:
		dst16 = (uint16_t *)dst;
		len /= 2;
		for (i = 0; i < len; i++) {
			dst16[i] = (uint16_t)data;
		}
		break;
	case 32:
		dst32 = (uint32_t *)dst;
		len /= 4;
		for (i = 0; i < len; i++) {
			dst32[i] = data;
		}
		break;
	}
}

/* copy data to framebuffer */
static void
boot_fb_cpy(uint8_t *dst, uint8_t *src, uint32_t len)
{
	uint16_t *dst16, *src16;
	uint32_t *dst32, *src32;
	uint32_t i;

	switch (fb_info.depth) {
	case 24:
	case 8:
		for (i = 0; i < len; i++)
			dst[i] = src[i];
		break;
	case 15:
	case 16:
		dst16 = (uint16_t *)dst;
		src16 = (uint16_t *)src;
		for (i = 0; i < len >> 1; i++) {
			dst16[i] = src16[i];
		}
		break;
	case 32:
		dst32 = (uint32_t *)dst;
		src32 = (uint32_t *)src;
		for (i = 0; i < len >> 2; i++) {
			dst32[i] = src32[i];
		}
		break;
	}
}

/*
 * Allocate shadow frame buffer, called from fakebop.c when early boot
 * allocator is ready.
 */
void
boot_fb_shadow_init(bootops_t *bops)
{
	if (boot_console_type(NULL) != CONS_FRAMEBUFFER)
		return;			/* nothing to do */

	fb_info.shadow_fb = (uint8_t *)bops->bsys_alloc(NULL, NULL,
	    fb_info.fb_size, MMU_PAGESIZE);

	if (fb_info.shadow_fb == NULL)
		return;

	/* Copy FB to shadow */
	boot_fb_cpy(fb_info.shadow_fb, fb_info.fb, fb_info.fb_size);
}

/*
 * Translate ansi color based on inverses and brightness.
 */
static void
boot_get_color(uint32_t *fg, uint32_t *bg)
{
	/* ansi to solaris colors, see also boot_console.c */
	if (fb_info.inverse == B_TRUE ||
	    fb_info.inverse_screen == B_TRUE) {
		*bg = dim_xlate[fb_info.fg_color];
		*fg = brt_xlate[fb_info.bg_color];
	} else {
		if (fb_info.bg_color == 7)
			*bg = brt_xlate[fb_info.bg_color];
		else
			*bg = dim_xlate[fb_info.bg_color];
		*fg = dim_xlate[fb_info.fg_color];
	}
}

/*
 * Map indexed color to RGB value.
 */
static uint32_t
boot_color_map(uint8_t index)
{
	uint8_t c;
	int pos, size;
	uint32_t color;

	/* 8bit depth is for indexed colors */
	if (fb_info.depth == 8)
		return (index);

	if (index >= sizeof (cmap4_to_24.red))
		index = 0;

	c = cmap4_to_24.red[index];
	pos = fb_info.rgb.red.pos;
	size = fb_info.rgb.red.size;
	color = ((c >> 8 - size) & ((1 << size) - 1)) << pos;

	c = cmap4_to_24.green[index];
	pos = fb_info.rgb.green.pos;
	size = fb_info.rgb.green.size;
	color |= ((c >> 8 - size) & ((1 << size) - 1)) << pos;

	c = cmap4_to_24.blue[index];
	pos = fb_info.rgb.blue.pos;
	size = fb_info.rgb.blue.size;
	color |= ((c >> 8 - size) & ((1 << size) - 1)) << pos;

	return (color);
}

/* set up out simple console. */
/*ARGSUSED*/
void
boot_fb_init(int console)
{
	fb_info_pixel_coord_t window;

	/* frame buffer address is mapped in dboot. */
	fb_info.fb = (uint8_t *)(uintptr_t)fb_info.paddr;

	boot_fb_set_font(fb_info.screen.y, fb_info.screen.x);
	window.x =
	    (fb_info.screen.x - fb_info.terminal.x * boot_fb_font.width) / 2;
	window.y =
	    (fb_info.screen.y - fb_info.terminal.y * boot_fb_font.height) / 2;
	fb_info.terminal_origin.x = window.x;
	fb_info.terminal_origin.y = window.y;

#if defined(_BOOT)
	/*
	 * Being called from dboot, we can have cursor terminal
	 * position passed from boot loader. In such case, fix the
	 * cursor screen coords.
	 */
	if (fb_info.cursor.pos.x != 0 || fb_info.cursor.pos.y != 0) {
		fb_info.cursor.origin.x = window.x +
		    fb_info.cursor.pos.x * boot_fb_font.width;
		fb_info.cursor.origin.y = window.y +
		    fb_info.cursor.pos.y * boot_fb_font.height;
	}
#endif

	/* If the cursor terminal position is 0,0 just reset screen coords */
	if (fb_info.cursor.pos.x == 0 && fb_info.cursor.pos.y == 0) {
		fb_info.cursor.origin.x = window.x;
		fb_info.cursor.origin.y = window.y;
	}

	/*
	 * Validate cursor coords with screen/terminal dimensions,
	 * if anything is off, reset to 0,0
	 */
	if (fb_info.cursor.pos.x > fb_info.terminal.x ||
	    fb_info.cursor.pos.y > fb_info.terminal.y ||
	    fb_info.cursor.origin.x > fb_info.screen.x ||
	    fb_info.cursor.origin.y > fb_info.screen.y) {

		fb_info.cursor.origin.x = window.x;
		fb_info.cursor.origin.y = window.y;
		fb_info.cursor.pos.x = 0;
		fb_info.cursor.pos.y = 0;
	}

#if defined(_BOOT)
	/* clear the screen if cursor is set to 0,0 */
	fb_info.cursor.pos.x = fb_info.cursor.pos.y = 0;
	if (console == CONS_FRAMEBUFFER &&
	    fb_info.cursor.pos.x == 0 && fb_info.cursor.pos.y == 0) {
		uint32_t fg, bg;
		int i;

		boot_get_color(&fg, &bg);
		bg = boot_color_map(bg);

		for (i = 0; i < fb_info.screen.y; i++) {
			uint8_t *dest = fb_info.fb + i * fb_info.pitch;
			boot_fb_fill(dest, bg, fb_info.pitch);
		}
	}
#endif
	/* set up pre-calculated last line */
	last_line_size = fb_info.terminal.x * boot_fb_font.width *
	    fb_info.bpp;
	last_line.x = window.x;
	last_line.y = window.y + (fb_info.terminal.y - 1) * boot_fb_font.height;

}

/* copy rectangle to framebuffer. */
static void
boot_fb_blit(struct vis_consdisplay *rect)
{
	uint32_t size;	/* write size per scanline */
	uint8_t *fbp, *sfbp;	/* fb + calculated offset */
	int i;

	/* make sure we will not write past FB */
	if (rect->col >= fb_info.screen.x ||
	    rect->row >= fb_info.screen.y ||
	    rect->col + rect->width >= fb_info.screen.x ||
	    rect->row + rect->height >= fb_info.screen.y)
		return;

	size = rect->width * fb_info.bpp;
	fbp = fb_info.fb + rect->col * fb_info.bpp +
	    rect->row * fb_info.pitch;
	if (fb_info.shadow_fb != NULL) {
		sfbp = fb_info.shadow_fb + rect->col * fb_info.bpp +
		    rect->row * fb_info.pitch;
	} else {
		sfbp = NULL;
	}

	/* write all scanlines in rectangle */
	for (i = 0; i < rect->height; i++) {
		uint8_t *dest = fbp + i * fb_info.pitch;
		uint8_t *src = rect->data + i * size;
		boot_fb_cpy(dest, src, size);
		if (sfbp != NULL) {
			dest = sfbp + i * fb_info.pitch;
			boot_fb_cpy(dest, src, size);
		}
	}
}

static void
bit_to_pix(uchar_t c)
{
	uint32_t fg, bg;

	boot_get_color(&fg, &bg);
	fg = boot_color_map(fg);
	bg = boot_color_map(bg);

	switch (fb_info.depth) {
	case 8:
		font_bit_to_pix8(&boot_fb_font, (uint8_t *)glyph, c, fg, bg);
		break;
	case 15:
	case 16:
		font_bit_to_pix16(&boot_fb_font, (uint16_t *)glyph, c,
		    (uint16_t)fg, (uint16_t)bg);
		break;
	case 24:
		font_bit_to_pix24(&boot_fb_font, (uint8_t *)glyph, c, fg, bg);
		break;
	case 32:
		font_bit_to_pix32(&boot_fb_font, (uint32_t *)glyph, c, fg, bg);
		break;
	}
}

/*
 * move the terminal window lines [1..y] to [0..y-1] and clear last line.
 */
static void
boot_fb_scroll(void)
{
	struct vis_conscopy c_copy;
	uint32_t soffset, toffset;
	uint32_t width, height;
	uint32_t fg, bg;
	uint8_t *src, *dst, *sdst;
	int i;

	boot_get_color(&fg, &bg);
	bg = boot_color_map(bg);

	/* support for scrolling. set up the console copy data and last line */
	c_copy.s_row = fb_info.terminal_origin.y + boot_fb_font.height;
	c_copy.s_col = fb_info.terminal_origin.x;
	c_copy.e_row = fb_info.screen.y - fb_info.terminal_origin.y;
	c_copy.e_col = fb_info.screen.x - fb_info.terminal_origin.x;
	c_copy.t_row = fb_info.terminal_origin.y;
	c_copy.t_col = fb_info.terminal_origin.x;

	soffset = c_copy.s_col * fb_info.bpp + c_copy.s_row * fb_info.pitch;
	toffset = c_copy.t_col * fb_info.bpp + c_copy.t_row * fb_info.pitch;
	if (fb_info.shadow_fb != NULL) {
		src = fb_info.shadow_fb + soffset;
		sdst = fb_info.shadow_fb + toffset;
	} else {
		src = fb_info.fb + soffset;
		sdst = NULL;
	}
	dst = fb_info.fb + toffset;

	width = (c_copy.e_col - c_copy.s_col + 1) * fb_info.bpp;
	height = c_copy.e_row - c_copy.s_row + 1;
	for (i = 0; i < height; i++) {
		uint32_t increment = i * fb_info.pitch;
		boot_fb_cpy(dst + increment, src + increment, width);
		if (sdst != NULL)
			boot_fb_cpy(sdst + increment, src + increment, width);
	}

	/* now clean up the last line */
	toffset = last_line.x * fb_info.bpp + last_line.y * fb_info.pitch;
	dst = fb_info.fb + toffset;
	if (fb_info.shadow_fb != NULL)
		sdst = fb_info.shadow_fb + toffset;

	for (i = 0; i < boot_fb_font.height; i++) {
		uint8_t *dest = dst + i * fb_info.pitch;
		if (fb_info.fb + fb_info.fb_size >= dest + last_line_size)
			boot_fb_fill(dest, bg, last_line_size);
		if (sdst != NULL) {
			dest = sdst + i * fb_info.pitch;
			if (fb_info.shadow_fb + fb_info.fb_size >=
			    dest + last_line_size) {
				boot_fb_fill(dest, bg, last_line_size);
			}
		}
	}
}

/*
 * Very simple block cursor. Save space below the cursor and restore
 * when cursor is invisible.
 */
void
boot_fb_cursor(boolean_t visible)
{
	uint32_t offset, size;
	uint32_t *fb32, *sfb32 = NULL;
	uint32_t fg, bg;
	uint16_t *fb16, *sfb16 = NULL;
	uint8_t *fb8, *sfb8 = NULL;
	int i, pitch;

	if (fb_info.cursor.visible == visible)
		return;

	boot_get_color(&fg, &bg);
	fg = boot_color_map(fg);
	bg = boot_color_map(bg);

	fb_info.cursor.visible = visible;
	pitch = fb_info.pitch;
	size = boot_fb_font.width * fb_info.bpp;

	/*
	 * Build cursor image. We are building mirror image of data on
	 * frame buffer by (D xor FG) xor BG.
	 */
	offset = fb_info.cursor.origin.x * fb_info.bpp +
	    fb_info.cursor.origin.y * pitch;
	switch (fb_info.depth) {
	case 8:
		for (i = 0; i < boot_fb_font.height; i++) {
			fb8 = fb_info.fb + offset + i * pitch;
			if (fb_info.shadow_fb != NULL)
				sfb8 = fb_info.shadow_fb + offset + i * pitch;
			for (uint32_t j = 0; j < size; j += 1) {
				fb8[j] = (fb8[j] ^ (fg & 0xff)) ^ (bg & 0xff);

				if (sfb8 == NULL)
					continue;

				sfb8[j] = (sfb8[j] ^ (fg & 0xff)) ^ (bg & 0xff);
			}
		}
		break;
	case 15:
	case 16:
		for (i = 0; i < boot_fb_font.height; i++) {
			fb16 = (uint16_t *)(fb_info.fb + offset + i * pitch);
			if (fb_info.shadow_fb != NULL)
				sfb16 = (uint16_t *)
				    (fb_info.shadow_fb + offset + i * pitch);
			for (int j = 0; j < boot_fb_font.width; j++) {
				fb16[j] = (fb16[j] ^ (fg & 0xffff)) ^
				    (bg & 0xffff);

				if (sfb16 == NULL)
					continue;

				sfb16[j] = (sfb16[j] ^ (fg & 0xffff)) ^
				    (bg & 0xffff);
			}
		}
		break;
	case 24:
		for (i = 0; i < boot_fb_font.height; i++) {
			fb8 = fb_info.fb + offset + i * pitch;
			if (fb_info.shadow_fb != NULL)
				sfb8 = fb_info.shadow_fb + offset + i * pitch;
			for (uint32_t j = 0; j < size; j += 3) {
				fb8[j] = (fb8[j] ^ ((fg >> 16) & 0xff)) ^
				    ((bg >> 16) & 0xff);
				fb8[j+1] = (fb8[j+1] ^ ((fg >> 8) & 0xff)) ^
				    ((bg >> 8) & 0xff);
				fb8[j+2] = (fb8[j+2] ^ (fg & 0xff)) ^
				    (bg & 0xff);

				if (sfb8 == NULL)
					continue;

				sfb8[j] = (sfb8[j] ^ ((fg >> 16) & 0xff)) ^
				    ((bg >> 16) & 0xff);
				sfb8[j+1] = (sfb8[j+1] ^ ((fg >> 8) & 0xff)) ^
				    ((bg >> 8) & 0xff);
				sfb8[j+2] = (sfb8[j+2] ^ (fg & 0xff)) ^
				    (bg & 0xff);
			}
		}
		break;
	case 32:
		for (i = 0; i < boot_fb_font.height; i++) {
			fb32 = (uint32_t *)(fb_info.fb + offset + i * pitch);
			if (fb_info.shadow_fb != NULL) {
				sfb32 = (uint32_t *)
				    (fb_info.shadow_fb + offset + i * pitch);
			}
			for (int j = 0; j < boot_fb_font.width; j++) {
				fb32[j] = (fb32[j] ^ fg) ^ bg;

				if (sfb32 == NULL)
					continue;

				sfb32[j] = (sfb32[j] ^ fg) ^ bg;
			}
		}
		break;
	}
}

static void
set_cursor_row(void)
{
	fb_info.cursor.pos.y++;
	fb_info.cursor.pos.x = 0;
	fb_info.cursor.origin.x = fb_info.terminal_origin.x;

	if (fb_info.cursor.pos.y < fb_info.terminal.y &&
	    fb_info.cursor.origin.y + boot_fb_font.height < fb_info.screen.y) {
		fb_info.cursor.origin.y += boot_fb_font.height;
	} else {
		fb_info.cursor.pos.y = fb_info.terminal.y - 1;
		/* fix the cursor origin y */
		fb_info.cursor.origin.y = fb_info.terminal_origin.y +
		    boot_fb_font.height * fb_info.cursor.pos.y;
		boot_fb_scroll();
	}
}

static void
set_cursor_col(void)
{
	fb_info.cursor.pos.x++;
	if (fb_info.cursor.pos.x < fb_info.terminal.x &&
	    fb_info.cursor.origin.x + boot_fb_font.width < fb_info.screen.x) {
		fb_info.cursor.origin.x += boot_fb_font.width;
	} else {
		fb_info.cursor.pos.x = 0;
		fb_info.cursor.origin.x = fb_info.terminal_origin.x;
		set_cursor_row();
	}
}

void
boot_fb_putchar(uint8_t c)
{
	struct vis_consdisplay display;
	boolean_t bs = B_FALSE;

	/* early tem startup will switch cursor off, if so, keep it off  */
	boot_fb_cursor(B_FALSE);	/* cursor off */
	switch (c) {
	case '\n':
		set_cursor_row();
		boot_fb_cursor(B_TRUE);
		return;
	case '\r':
		fb_info.cursor.pos.x = 0;
		fb_info.cursor.origin.x = fb_info.terminal_origin.x;
		boot_fb_cursor(B_TRUE);
		return;
	case '\b':
		if (fb_info.cursor.pos.x > 0) {
			fb_info.cursor.pos.x--;
			fb_info.cursor.origin.x -= boot_fb_font.width;
		}
		c = ' ';
		bs = B_TRUE;
		break;
	}

	bit_to_pix(c);
	display.col = fb_info.cursor.origin.x;
	display.row = fb_info.cursor.origin.y;
	display.width = boot_fb_font.width;
	display.height = boot_fb_font.height;
	display.data = glyph;

	boot_fb_blit(&display);
	if (bs == B_FALSE)
		set_cursor_col();
	boot_fb_cursor(B_TRUE);
}
