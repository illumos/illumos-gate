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
#include <sys/rgb.h>
#include "boot_console_impl.h"

#define	P2ROUNDUP(x, align)	(-(-(x) & -(align)))
#define	MIN(a, b)		((a) < (b) ? (a) : (b))
#define	nitems(x)		(sizeof ((x)) / sizeof ((x)[0]))

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

/*
 * We have largest font 16x32 with depth 32. This will allocate 2048
 * bytes from BSS.
 */
#define	MAX_GLYPH	(16 * 32 * 4)

struct fontlist		cf_fontlist;
static bitmap_data_t	cf_data;
static struct font	cf_font;

static struct font	boot_fb_font; /* set by set_font() */
static uint8_t		glyph[MAX_GLYPH];

static void boot_fb_putchar(int);
static void boot_fb_eraseline(void);
static void boot_fb_setpos(int, int);
static void boot_fb_shiftline(int);
static void boot_fb_eraseline_impl(uint16_t, uint16_t);

static void
xbi_init_font(struct xboot_info *xbi)
{
	uint32_t i, checksum = 0;
	struct boot_modules *modules;
	struct font_info *fi;
	uintptr_t ptr;

	modules = (struct boot_modules *)(uintptr_t)xbi->bi_modules;
	for (i = 0; i < xbi->bi_module_cnt; i++) {
		if (modules[i].bm_type == BMT_FONT)
			break;
	}
	if (i == xbi->bi_module_cnt)
		return;

	ptr = (uintptr_t)modules[i].bm_addr;
	fi = (struct font_info *)ptr;

	/*
	 * Compute and verify checksum. The total sum of all the fields
	 * must be 0. Note, the return from this point means we will
	 * use default font.
	 */
	checksum += fi->fi_width;
	checksum += fi->fi_height;
	checksum += fi->fi_bitmap_size;
	for (i = 0; i < VFNT_MAPS; i++)
		checksum += fi->fi_map_count[i];
	if (checksum + fi->fi_checksum != 0)
		return;

	cf_data.width = fi->fi_width;
	cf_data.height = fi->fi_height;
	cf_data.uncompressed_size = fi->fi_bitmap_size;
	cf_data.font = &cf_font;

	ptr += sizeof (struct font_info);
	ptr = P2ROUNDUP(ptr, 8);

	cf_font.vf_width = fi->fi_width;
	cf_font.vf_height = fi->fi_height;
	for (i = 0; i < VFNT_MAPS; i++) {
		if (fi->fi_map_count[i] == 0)
			continue;
		cf_font.vf_map_count[i] = fi->fi_map_count[i];
		cf_font.vf_map[i] = (struct font_map *)ptr;
		ptr += (fi->fi_map_count[i] * sizeof (struct font_map));
		ptr = P2ROUNDUP(ptr, 8);
	}
	cf_font.vf_bytes = (uint8_t *)ptr;
	cf_fontlist.font_name = NULL;
	cf_fontlist.font_flags = FONT_BOOT;
	cf_fontlist.font_data = &cf_data;
	cf_fontlist.font_load = NULL;
	STAILQ_INSERT_HEAD(&fonts, &cf_fontlist, font_next);
}

/*
 * extract data from MB2 framebuffer tag and set up initial frame buffer.
 */
boolean_t
xbi_fb_init(struct xboot_info *xbi, bcons_dev_t *bcons_dev)
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

	xbi_init_font(xbi);

	fb_info.paddr = tag->framebuffer_common.framebuffer_addr;
	fb_info.pitch = tag->framebuffer_common.framebuffer_pitch;
	fb_info.depth = tag->framebuffer_common.framebuffer_bpp;
	fb_info.bpp = P2ROUNDUP(fb_info.depth, 8) >> 3;
	fb_info.screen.x = tag->framebuffer_common.framebuffer_width;
	fb_info.screen.y = tag->framebuffer_common.framebuffer_height;
	fb_info.fb_size = fb_info.screen.y * fb_info.pitch;

	bcons_dev->bd_putchar = boot_fb_putchar;
	bcons_dev->bd_eraseline = boot_fb_eraseline;
	bcons_dev->bd_cursor = boot_fb_cursor;
	bcons_dev->bd_setpos = boot_fb_setpos;
	bcons_dev->bd_shift = boot_fb_shiftline;

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
	bitmap_data_t *bp;
	int i;

	h = MIN(height, 4096);
	w = MIN(width, 4096);

	bp = set_font((short *)&fb_info.terminal.y,
	    (short *)&fb_info.terminal.x, h, w);

	boot_fb_font.vf_bytes = bp->font->vf_bytes;
	boot_fb_font.vf_width = bp->font->vf_width;
	boot_fb_font.vf_height = bp->font->vf_height;
	for (i = 0; i < VFNT_MAPS; i++) {
		boot_fb_font.vf_map[i] = bp->font->vf_map[i];
		boot_fb_font.vf_map_count[i] = bp->font->vf_map_count[i];
	}

	fb_info.font_width = boot_fb_font.vf_width;
	fb_info.font_height = boot_fb_font.vf_height;
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
		for (i = 0; i < len; i++)
			dst16[i] = (uint16_t)data;
		break;
	case 32:
		dst32 = (uint32_t *)dst;
		len /= 4;
		for (i = 0; i < len; i++)
			dst32[i] = data;
		break;
	}
}

/* copy data to framebuffer */
static void
boot_fb_cpy(uint8_t *dst, uint8_t *src, uint32_t len)
{
	uint16_t *dst16, *src16;
	uint32_t *dst32, *src32;

	switch (fb_info.depth) {
	case 24:
	case 8:
	default:
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
		break;
	case 15:
	case 16:
		dst16 = (uint16_t *)dst;
		src16 = (uint16_t *)src;
		len /= 2;
		if (dst16 <= src16) {
			do {
				*dst16++ = *src16++;
			} while (--len != 0);
		} else {
			dst16 += len;
			src16 += len;
			do {
				*--dst16 = *--src16;
			} while (--len != 0);
		}
		break;
	case 32:
		dst32 = (uint32_t *)dst;
		src32 = (uint32_t *)src;
		len /= 4;
		if (dst32 <= src32) {
			do {
				*dst32++ = *src32++;
			} while (--len != 0);
		} else {
			dst32 += len;
			src32 += len;
			do {
				*--dst32 = *--src32;
			} while (--len != 0);
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
void
boot_get_color(uint32_t *fg, uint32_t *bg)
{
	/* ansi to solaris colors, see also boot_console.c */
	if (fb_info.inverse == B_TRUE ||
	    fb_info.inverse_screen == B_TRUE) {
		if (fb_info.fg_color < 16)
			*bg = dim_xlate[fb_info.fg_color];
		else
			*bg = fb_info.fg_color;

		if (fb_info.bg_color < 16)
			*fg = brt_xlate[fb_info.bg_color];
		else
			*fg = fb_info.bg_color;
	} else {
		if (fb_info.bg_color < 16) {
			if (fb_info.bg_color == 7)
				*bg = brt_xlate[fb_info.bg_color];
			else
				*bg = dim_xlate[fb_info.bg_color];
		} else {
			*bg = fb_info.bg_color;
		}
		if (fb_info.fg_color < 16)
			*fg = dim_xlate[fb_info.fg_color];
		else
			*fg = fb_info.fg_color;
	}
}

/*
 * Map indexed color to RGB value.
 */
uint32_t
boot_color_map(uint8_t index)
{
	if (fb_info.fb_type != FB_TYPE_RGB) {
		if (index < nitems(solaris_color_to_pc_color))
			return (solaris_color_to_pc_color[index]);
		else
			return (index);
	}

	return (rgb_color_map(&fb_info.rgb, index));
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
	window.x = (fb_info.screen.x -
	    fb_info.terminal.x * boot_fb_font.vf_width) / 2;
	window.y = (fb_info.screen.y -
	    fb_info.terminal.y * boot_fb_font.vf_height) / 2;
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
		    fb_info.cursor.pos.x * boot_fb_font.vf_width;
		fb_info.cursor.origin.y = window.y +
		    fb_info.cursor.pos.y * boot_fb_font.vf_height;
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
	if (fb_info.cursor.pos.x == 0 && fb_info.cursor.pos.y == 0) {
		uint32_t fg, bg, toffset;
		uint16_t y;

		boot_get_color(&fg, &bg);
		bg = boot_color_map(bg);

		toffset = 0;
		for (y = 0; y < fb_info.screen.y; y++) {
			uint8_t *dest = fb_info.fb + toffset;

			boot_fb_fill(dest, bg, fb_info.pitch);
			toffset += fb_info.pitch;
		}
	}
#endif
}

/* copy rectangle to framebuffer. */
static void
boot_fb_blit(struct vis_consdisplay *rect)
{
	uint32_t offset, size;		/* write size per scanline */
	uint8_t *fbp, *sfbp = NULL;	/* fb + calculated offset */
	int i;

	/* make sure we will not write past FB */
	if (rect->col >= fb_info.screen.x ||
	    rect->row >= fb_info.screen.y ||
	    rect->col + rect->width >= fb_info.screen.x ||
	    rect->row + rect->height >= fb_info.screen.y)
		return;

	size = rect->width * fb_info.bpp;
	offset = rect->col * fb_info.bpp + rect->row * fb_info.pitch;
	fbp = fb_info.fb + offset;
	if (fb_info.shadow_fb != NULL)
		sfbp = fb_info.shadow_fb + offset;

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

static void
boot_fb_eraseline_impl(uint16_t x, uint16_t y)
{
	uint32_t toffset, size;
	uint32_t fg, bg;
	uint8_t *dst, *sdst;
	int i;

	boot_get_color(&fg, &bg);
	bg = boot_color_map(bg);

	size = fb_info.terminal.x * boot_fb_font.vf_width * fb_info.bpp;

	toffset = x * fb_info.bpp + y * fb_info.pitch;
	dst = fb_info.fb + toffset;
	sdst = fb_info.shadow_fb + toffset;

	for (i = 0; i < boot_fb_font.vf_height; i++) {
		uint8_t *dest = dst + i * fb_info.pitch;
		if (fb_info.fb + fb_info.fb_size >= dest + size)
			boot_fb_fill(dest, bg, size);
		if (fb_info.shadow_fb != NULL) {
			dest = sdst + i * fb_info.pitch;
			if (fb_info.shadow_fb + fb_info.fb_size >=
			    dest + size) {
				boot_fb_fill(dest, bg, size);
			}
		}
	}
}

static void
boot_fb_eraseline(void)
{
	boot_fb_eraseline_impl(fb_info.cursor.origin.x,
	    fb_info.cursor.origin.y);
}

/*
 * Copy rectangle from console to console.
 * If shadow buffer is available, use shadow as source.
 */
static void
boot_fb_conscopy(struct vis_conscopy *c_copy)
{
	uint32_t soffset, toffset;
	uint32_t width, height, increment;
	uint8_t *src, *dst, *sdst = NULL;
	int i;

	soffset = c_copy->s_col * fb_info.bpp + c_copy->s_row * fb_info.pitch;
	toffset = c_copy->t_col * fb_info.bpp + c_copy->t_row * fb_info.pitch;

	src = fb_info.fb + soffset;
	dst = fb_info.fb + toffset;

	if (fb_info.shadow_fb != NULL) {
		src = fb_info.shadow_fb + soffset;
		sdst = fb_info.shadow_fb + toffset;
	}

	width = (c_copy->e_col - c_copy->s_col + 1) * fb_info.bpp;
	height = c_copy->e_row - c_copy->s_row + 1;

	for (i = 0; i < height; i++) {
		increment = i * fb_info.pitch;

		/* Make sure we fit into FB size. */
		if (soffset + increment + width >= fb_info.fb_size ||
		    toffset + increment + width >= fb_info.fb_size)
			break;

		boot_fb_cpy(dst + increment, src + increment, width);

		if (sdst != NULL)
			boot_fb_cpy(sdst + increment, src + increment, width);
	}
}

/* Shift the line content by chars. */
static void
boot_fb_shiftline(int chars)
{
	struct vis_conscopy c_copy;

	c_copy.s_col = fb_info.cursor.origin.x;
	c_copy.s_row = fb_info.cursor.origin.y;

	c_copy.e_col = (fb_info.terminal.x - chars) * boot_fb_font.vf_width;
	c_copy.e_col += fb_info.terminal_origin.x;
	c_copy.e_row = c_copy.s_row + boot_fb_font.vf_height;

	c_copy.t_col = fb_info.cursor.origin.x + chars * boot_fb_font.vf_width;
	c_copy.t_row = fb_info.cursor.origin.y;

	boot_fb_conscopy(&c_copy);
}

/*
 * move the terminal window lines [1..y] to [0..y-1] and clear last line.
 */
static void
boot_fb_scroll(void)
{
	struct vis_conscopy c_copy;

	/* support for scrolling. set up the console copy data and last line */
	c_copy.s_row = fb_info.terminal_origin.y + boot_fb_font.vf_height;
	c_copy.s_col = fb_info.terminal_origin.x;
	c_copy.e_row = fb_info.screen.y - fb_info.terminal_origin.y;
	c_copy.e_col = fb_info.screen.x - fb_info.terminal_origin.x;
	c_copy.t_row = fb_info.terminal_origin.y;
	c_copy.t_col = fb_info.terminal_origin.x;

	boot_fb_conscopy(&c_copy);

	/* now clean up the last line */
	boot_fb_eraseline_impl(fb_info.terminal_origin.x,
	    fb_info.terminal_origin.y +
	    (fb_info.terminal.y - 1) * boot_fb_font.vf_height);
}

/*
 * Very simple block cursor. Save space below the cursor and restore
 * when cursor is invisible.
 */
void
boot_fb_cursor(boolean_t visible)
{
	uint32_t offset, size, j;
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
	size = boot_fb_font.vf_width * fb_info.bpp;

	/*
	 * Build cursor image. We are building mirror image of data on
	 * frame buffer by (D xor FG) xor BG.
	 */
	offset = fb_info.cursor.origin.x * fb_info.bpp +
	    fb_info.cursor.origin.y * pitch;
	switch (fb_info.depth) {
	case 8:
		for (i = 0; i < boot_fb_font.vf_height; i++) {
			fb8 = fb_info.fb + offset + i * pitch;
			if (fb_info.shadow_fb != NULL)
				sfb8 = fb_info.shadow_fb + offset + i * pitch;
			for (j = 0; j < size; j += 1) {
				fb8[j] = (fb8[j] ^ (fg & 0xff)) ^ (bg & 0xff);

				if (sfb8 == NULL)
					continue;

				sfb8[j] = (sfb8[j] ^ (fg & 0xff)) ^ (bg & 0xff);
			}
		}
		break;
	case 15:
	case 16:
		for (i = 0; i < boot_fb_font.vf_height; i++) {
			fb16 = (uint16_t *)(fb_info.fb + offset + i * pitch);
			if (fb_info.shadow_fb != NULL)
				sfb16 = (uint16_t *)
				    (fb_info.shadow_fb + offset + i * pitch);
			for (j = 0; j < boot_fb_font.vf_width; j++) {
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
		for (i = 0; i < boot_fb_font.vf_height; i++) {
			fb8 = fb_info.fb + offset + i * pitch;
			if (fb_info.shadow_fb != NULL)
				sfb8 = fb_info.shadow_fb + offset + i * pitch;
			for (j = 0; j < size; j += 3) {
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
		for (i = 0; i < boot_fb_font.vf_height; i++) {
			fb32 = (uint32_t *)(fb_info.fb + offset + i * pitch);
			if (fb_info.shadow_fb != NULL) {
				sfb32 = (uint32_t *)
				    (fb_info.shadow_fb + offset + i * pitch);
			}
			for (j = 0; j < boot_fb_font.vf_width; j++) {
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
boot_fb_setpos(int row, int col)
{
	if (row < 0)
		row = 0;
	if (row >= fb_info.terminal.y)
		row = fb_info.terminal.y - 1;
	if (col < 0)
		col = 0;
	if (col >= fb_info.terminal.x)
		col = fb_info.terminal.x - 1;

	fb_info.cursor.pos.x = col;
	fb_info.cursor.pos.y = row;
	fb_info.cursor.origin.x = fb_info.terminal_origin.x;
	fb_info.cursor.origin.x += col * boot_fb_font.vf_width;
	fb_info.cursor.origin.y = fb_info.terminal_origin.y;
	fb_info.cursor.origin.y += row * boot_fb_font.vf_height;
}

static void
boot_fb_putchar(int c)
{
	struct vis_consdisplay display;
	int rows, cols;

	rows = fb_info.cursor.pos.y;
	cols = fb_info.cursor.pos.x;

	if (c == '\n') {
		if (rows < fb_info.terminal.y - 1)
			boot_fb_setpos(rows + 1, cols);
		else
			boot_fb_scroll();
		return;
	}

	bit_to_pix(c);
	display.col = fb_info.cursor.origin.x;
	display.row = fb_info.cursor.origin.y;
	display.width = boot_fb_font.vf_width;
	display.height = boot_fb_font.vf_height;
	display.data = glyph;

	boot_fb_blit(&display);
	if (cols < fb_info.terminal.x - 1)
		boot_fb_setpos(rows, cols + 1);
	else if (rows < fb_info.terminal.y - 1)
		boot_fb_setpos(rows + 1, 0);
	else {
		boot_fb_setpos(rows, 0);
		boot_fb_scroll();
	}
}
