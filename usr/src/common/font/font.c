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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2017 Toomas Soome <tsoome@me.com>
 */

/*
 * Generic font related data and functions shared by early boot console
 * in dboot, kernel startup and full kernel.
 */
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/tem_impl.h>
#include <sys/rgb.h>
#include <sys/font.h>
#include <sys/sysmacros.h>

/*
 * To simplify my life, I am "temporarily" collecting the commonly used
 * color bits here. The bits shared between loader, dboot, early boot, tem.
 * This data would need some sort of API, but I am in no condition to figure
 * something out right now.
 */

/* ANSI color to sun color translation. */
/* BEGIN CSTYLED */
/*                            Bk  Rd  Gr  Br  Bl  Mg  Cy  Wh */
const uint8_t dim_xlate[] = {  1,  5,  3,  7,  2,  6,  4,  8 };
const uint8_t brt_xlate[] = {  9, 13, 11, 15, 10, 14, 12,  0 };

const uint8_t solaris_color_to_pc_color[16] = {
	pc_brt_white,		/*  0 - brt_white	*/
	pc_black,		/*  1 - black		*/
	pc_blue,		/*  2 - blue		*/
	pc_green,		/*  3 - green		*/
	pc_cyan,		/*  4 - cyan		*/
	pc_red,			/*  5 - red		*/
	pc_magenta,		/*  6 - magenta		*/
	pc_brown,		/*  7 - brown		*/
	pc_white,		/*  8 - white		*/
	pc_grey,		/*  9 - gery		*/
	pc_brt_blue,		/* 10 - brt_blue	*/
	pc_brt_green,		/* 11 - brt_green	*/
	pc_brt_cyan,		/* 12 - brt_cyan	*/
	pc_brt_red,		/* 13 - brt_red		*/
	pc_brt_magenta,		/* 14 - brt_magenta	*/
	pc_yellow		/* 15 - yellow		*/
};

/* 4-bit to 24-bit color translation. */
const text_cmap_t cmap4_to_24 = {
/* 0    1    2    3    4    5    6    7    8    9   10   11   12   13   14   15
  Wh+  Bk   Bl   Gr   Cy   Rd   Mg   Br   Wh   Bk+  Bl+  Gr+  Cy+  Rd+  Mg+  Yw */
  .red = {
 0xff,0x00,0x00,0x00,0x00,0x80,0x80,0x80,0x80,0x40,0x00,0x00,0x00,0xff,0xff,0xff
},
  .green = {
 0xff,0x00,0x00,0x80,0x80,0x00,0x00,0x80,0x80,0x40,0x00,0xff,0xff,0x00,0x00,0xff
},
  .blue = {
 0xff,0x00,0x80,0x00,0x80,0x00,0x80,0x00,0x80,0x40,0xff,0x00,0xff,0x00,0xff,0x00
}
};
/* END CSTYLED */

/*
 * Fonts are statically linked with this module. At some point an
 * RFE might be desireable to allow dynamic font loading.  The
 * original intention to facilitate dynamic fonts can be seen
 * by examining the data structures and set_font().  As much of
 * the original code is retained but modified to be suited for
 * traversing a list of static fonts.
 */

/*
 * Must be sorted by font size in descending order
 */
font_list_t fonts = STAILQ_HEAD_INITIALIZER(fonts);

bitmap_data_t *
set_font(short *rows, short *cols, short h, short w)
{
	bitmap_data_t *font = NULL;
	struct fontlist	*fl;
	unsigned height = h;
	unsigned width = w;

	/*
	 * First check for manually loaded font.
	 */
	STAILQ_FOREACH(fl, &fonts, font_next) {
		if (fl->font_flags == FONT_MANUAL ||
		    fl->font_flags == FONT_BOOT) {
			font = fl->font_data;
			if (font->font == NULL && fl->font_load != NULL &&
			    fl->font_name != NULL) {
				font = fl->font_load(fl->font_name);
			}
			if (font == NULL || font->font == NULL)
				font = NULL;
			break;
		}
	}

	if (font != NULL) {
		*rows = (height - BORDER_PIXELS) / font->height;
		*cols = (width - BORDER_PIXELS) / font->width;
		return (font);
	}

	/*
	 * Find best font for these dimensions, or use default
	 *
	 * A 1 pixel border is the absolute minimum we could have
	 * as a border around the text window (BORDER_PIXELS = 2),
	 * however a slightly larger border not only looks better
	 * but for the fonts currently statically built into the
	 * emulator causes much better font selection for the
	 * normal range of screen resolutions.
	 */
	STAILQ_FOREACH(fl, &fonts, font_next) {
		font = fl->font_data;
		if ((((*rows * font->height) + BORDER_PIXELS) <= height) &&
		    (((*cols * font->width) + BORDER_PIXELS) <= width)) {
			if (font->font == NULL) {
				if (fl->font_load != NULL &&
				    fl->font_name != NULL) {
					font = fl->font_load(fl->font_name);
				}
				if (font == NULL)
					continue;
			}
			*rows = (height - BORDER_PIXELS) / font->height;
			*cols = (width - BORDER_PIXELS) / font->width;
			break;
		}
		font = NULL;
	}

	if (font == NULL) {
		/*
		 * We have fonts sorted smallest last, try it before
		 * falling back to builtin.
		 */
		fl = STAILQ_LAST(&fonts, fontlist, font_next);
		if (fl != NULL && fl->font_load != NULL &&
		    fl->font_name != NULL) {
			font = fl->font_load(fl->font_name);
		}
		if (font == NULL)
			font = &DEFAULT_FONT_DATA;

		*rows = (height - BORDER_PIXELS) / font->height;
		*cols = (width - BORDER_PIXELS) / font->width;
	}

	return (font);
}

/* Binary search for the glyph. Return 0 if not found. */
static uint16_t
font_bisearch(const struct font_map *map, uint32_t len, uint32_t src)
{
	unsigned min, mid, max;

	min = 0;
	max = len - 1;

	/* Empty font map. */
	if (len == 0)
		return (0);
	/* Character below minimal entry. */
	if (src < map[0].font_src)
		return (0);
	/* Optimization: ASCII characters occur very often. */
	if (src <= map[0].font_src + map[0].font_len)
		return (src - map[0].font_src + map[0].font_dst);
	/* Character above maximum entry. */
	if (src > map[max].font_src + map[max].font_len)
		return (0);

	/* Binary search. */
	while (max >= min) {
		mid = (min + max) / 2;
		if (src < map[mid].font_src)
			max = mid - 1;
		else if (src > map[mid].font_src + map[mid].font_len)
			min = mid + 1;
		else
			return (src - map[mid].font_src + map[mid].font_dst);
	}

	return (0);
}

/*
 * Return glyph bitmap. If glyph is not found, we will return bitmap
 * for the first (offset 0) glyph.
 */
const uint8_t *
font_lookup(const struct font *vf, uint32_t c)
{
	uint32_t src;
	uint16_t dst;
	size_t stride;

	src = TEM_CHAR(c);

	/* Substitute bold with normal if not found. */
	if (TEM_CHAR_ATTR(c) & TEM_ATTR_BOLD) {
		dst = font_bisearch(vf->vf_map[VFNT_MAP_BOLD],
		    vf->vf_map_count[VFNT_MAP_BOLD], src);
		if (dst != 0)
			goto found;
	}
	dst = font_bisearch(vf->vf_map[VFNT_MAP_NORMAL],
	    vf->vf_map_count[VFNT_MAP_NORMAL], src);

found:
	stride = howmany(vf->vf_width, 8) * vf->vf_height;
	return (&vf->vf_bytes[dst * stride]);
}

/*
 * bit_to_pix4 is for 4-bit frame buffers.  It will write one output byte
 * for each 2 bits of input bitmap.  It inverts the input bits before
 * doing the output translation, for reverse video.
 *
 * Assuming foreground is 0001 and background is 0000...
 * An input data byte of 0x53 will output the bit pattern
 * 00000001 00000001 00000000 00010001.
 */

void
font_bit_to_pix4(
    struct font *f,
    uint8_t *dest,
    uint32_t c,
    uint8_t fg_color,
    uint8_t bg_color)
{
	uint32_t row;
	int	byte;
	int	i;
	const uint8_t *cp, *ul;
	uint8_t	data;
	uint8_t	nibblett;
	int	bytes_wide;

	if (TEM_CHAR_ATTR(c) & TEM_ATTR_UNDERLINE)
		ul = font_lookup(f, 0x0332);	/* combining low line */
	else
		ul = NULL;

	cp = font_lookup(f, c);
	bytes_wide = (f->vf_width + 7) / 8;

	for (row = 0; row < f->vf_height; row++) {
		for (byte = 0; byte < bytes_wide; byte++) {
			if (ul == NULL)
				data = *cp++;
			else
				data = *cp++ | *ul++;
			for (i = 0; i < 4; i++) {
				nibblett = (data >> ((3-i) * 2)) & 0x3;
				switch (nibblett) {
				case 0x0:
					*dest++ = bg_color << 4 | bg_color;
					break;
				case 0x1:
					*dest++ = bg_color << 4 | fg_color;
					break;
				case 0x2:
					*dest++ = fg_color << 4 | bg_color;
					break;
				case 0x3:
					*dest++ = fg_color << 4 | fg_color;
					break;
				}
			}
		}
	}
}

/*
 * bit_to_pix8 is for 8-bit frame buffers.  It will write one output byte
 * for each bit of input bitmap.  It inverts the input bits before
 * doing the output translation, for reverse video.
 *
 * Assuming foreground is 00000001 and background is 00000000...
 * An input data byte of 0x53 will output the bit pattern
 * 0000000 000000001 00000000 00000001 00000000 00000000 00000001 00000001.
 */

void
font_bit_to_pix8(
    struct font *f,
    uint8_t *dest,
    uint32_t c,
    uint8_t fg_color,
    uint8_t bg_color)
{
	uint32_t row;
	int	byte;
	int	i;
	const uint8_t *cp, *ul;
	uint8_t	data;
	int	bytes_wide;
	uint8_t	mask;
	int	bitsleft, nbits;

	if (TEM_CHAR_ATTR(c) & TEM_ATTR_UNDERLINE)
		ul = font_lookup(f, 0x0332);	/* combining low line */
	else
		ul = NULL;

	cp = font_lookup(f, c);
	bytes_wide = (f->vf_width + 7) / 8;

	for (row = 0; row < f->vf_height; row++) {
		bitsleft = f->vf_width;
		for (byte = 0; byte < bytes_wide; byte++) {
			if (ul == NULL)
				data = *cp++;
			else
				data = *cp++ | *ul++;
			mask = 0x80;
			nbits = MIN(8, bitsleft);
			bitsleft -= nbits;
			for (i = 0; i < nbits; i++) {
				*dest++ = (data & mask ? fg_color: bg_color);
				mask = mask >> 1;
			}
		}
	}
}

/*
 * bit_to_pix16 is for 16-bit frame buffers.  It will write two output bytes
 * for each bit of input bitmap.  It inverts the input bits before
 * doing the output translation, for reverse video.
 *
 * Assuming foreground is 11111111 11111111
 * and background is 00000000 00000000
 * An input data byte of 0x53 will output the bit pattern
 *
 * 00000000 00000000
 * 11111111 11111111
 * 00000000 00000000
 * 11111111 11111111
 * 00000000 00000000
 * 00000000 00000000
 * 11111111 11111111
 * 11111111 11111111
 *
 */

void
font_bit_to_pix16(
    struct font *f,
    uint16_t *dest,
    uint32_t c,
    uint16_t fg_color16,
    uint16_t bg_color16)
{
	uint32_t row;
	int	byte;
	int	i;
	const uint8_t *cp, *ul;
	uint16_t data, d;
	int	bytes_wide;
	int	bitsleft, nbits;

	if (TEM_CHAR_ATTR(c) & TEM_ATTR_UNDERLINE)
		ul = font_lookup(f, 0x0332);	/* combining low line */
	else
		ul = NULL;

	cp = font_lookup(f, c);
	bytes_wide = (f->vf_width + 7) / 8;

	for (row = 0; row < f->vf_height; row++) {
		bitsleft = f->vf_width;
		for (byte = 0; byte < bytes_wide; byte++) {
			if (ul == NULL)
				data = *cp++;
			else
				data = *cp++ | *ul++;
			nbits = MIN(8, bitsleft);
			bitsleft -= nbits;
			for (i = 0; i < nbits; i++) {
				d = ((data << i) & 0x80 ?
				    fg_color16 : bg_color16);
				*dest++ = d;
			}
		}
	}
}

/*
 * bit_to_pix24 is for 24-bit frame buffers.  It will write three output bytes
 * for each bit of input bitmap.  It inverts the input bits before
 * doing the output translation, for reverse video.
 *
 * Assuming foreground is 11111111 11111111 11111111
 * and background is 00000000 00000000 00000000
 * An input data byte of 0x53 will output the bit pattern
 *
 * 00000000 00000000 00000000
 * 11111111 11111111 11111111
 * 00000000 00000000 00000000
 * 11111111 11111111 11111111
 * 00000000 00000000 00000000
 * 00000000 00000000 00000000
 * 11111111 11111111 11111111
 * 11111111 11111111 11111111
 *
 */

void
font_bit_to_pix24(
    struct font *f,
    uint8_t *dest,
    uint32_t c,
    uint32_t fg_color32,
    uint32_t bg_color32)
{
	uint32_t row;
	int	byte;
	int	i;
	const uint8_t *cp, *ul;
	uint32_t data, d;
	int	bytes_wide;
	int	bitsleft, nbits;

	if (TEM_CHAR_ATTR(c) & TEM_ATTR_UNDERLINE)
		ul = font_lookup(f, 0x0332);	/* combining low line */
	else
		ul = NULL;

	cp = font_lookup(f, c);
	bytes_wide = (f->vf_width + 7) / 8;

	for (row = 0; row < f->vf_height; row++) {
		bitsleft = f->vf_width;
		for (byte = 0; byte < bytes_wide; byte++) {
			if (ul == NULL)
				data = *cp++;
			else
				data = *cp++ | *ul++;

			nbits = MIN(8, bitsleft);
			bitsleft -= nbits;
			for (i = 0; i < nbits; i++) {
				d = ((data << i) & 0x80 ?
				    fg_color32 : bg_color32);
				*dest++ = d & 0xff;
				*dest++ = (d >> 8) & 0xff;
				*dest++ = (d >> 16) & 0xff;
			}
		}
	}
}

/*
 * bit_to_pix32 is for 32-bit frame buffers.  It will write four output bytes
 * for each bit of input bitmap.  It inverts the input bits before
 * doing the output translation, for reverse video.  Note that each
 * 24-bit RGB value is finally stored in a 32-bit unsigned int, with the
 * high-order byte set to zero.
 *
 * Assuming foreground is 00000000 11111111 11111111 11111111
 * and background is 00000000 00000000 00000000 00000000
 * An input data byte of 0x53 will output the bit pattern
 *
 * 00000000 00000000 00000000 00000000
 * 00000000 11111111 11111111 11111111
 * 00000000 00000000 00000000 00000000
 * 00000000 11111111 11111111 11111111
 * 00000000 00000000 00000000 00000000
 * 00000000 00000000 00000000 00000000
 * 00000000 11111111 11111111 11111111
 * 00000000 11111111 11111111 11111111
 *
 */

void
font_bit_to_pix32(
    struct font *f,
    uint32_t *dest,
    uint32_t c,
    uint32_t fg_color32,
    uint32_t bg_color32)
{
	uint32_t row;
	int	byte;
	int	i;
	const uint8_t *cp, *ul;
	uint32_t data;
	int	bytes_wide;
	int	bitsleft, nbits;

	if (TEM_CHAR_ATTR(c) & TEM_ATTR_UNDERLINE)
		ul = font_lookup(f, 0x0332);	/* combining low line */
	else
		ul = NULL;

	cp = font_lookup(f, c);
	bytes_wide = (f->vf_width + 7) / 8;

	for (row = 0; row < f->vf_height; row++) {
		bitsleft = f->vf_width;
		for (byte = 0; byte < bytes_wide; byte++) {
			if (ul == NULL)
				data = *cp++;
			else
				data = *cp++ | *ul++;
			nbits = MIN(8, bitsleft);
			bitsleft -= nbits;
			for (i = 0; i < nbits; i++) {
				*dest++ = ((data << i) & 0x80 ?
				    fg_color32 : bg_color32);
			}
		}
	}
}
