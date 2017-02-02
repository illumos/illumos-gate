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
#include <sys/font.h>
#include <sys/sysmacros.h>

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
struct fontlist fonts[] = {
	{  &font_data_12x22,	NULL  },
	{  &font_data_8x16,	NULL  },
	{  &font_data_7x14,	NULL  },
	{  &font_data_6x10,	NULL  },
	{  NULL, NULL  }
};

void
set_font(struct font *f, short *rows, short *cols, short height, short width)
{
	bitmap_data_t	*font_selected = NULL;
	struct fontlist	*fl;
	int i;

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
	for (fl = fonts; fl->data; fl++) {
		if ((((*rows * fl->data->height) + BORDER_PIXELS) <= height) &&
		    (((*cols * fl->data->width) + BORDER_PIXELS) <= width)) {
			font_selected = fl->data;
			break;
		}
	}
	/*
	 * The minus 2 is to make sure we have at least a 1 pixel
	 * border around the entire screen.
	 */
	if (font_selected == NULL) {
		if (((*rows * DEFAULT_FONT_DATA.height) > height) ||
		    ((*cols * DEFAULT_FONT_DATA.width) > width)) {
			*rows = (height - 2) / DEFAULT_FONT_DATA.height;
			*cols = (width - 2) / DEFAULT_FONT_DATA.width;
		}
		font_selected = &DEFAULT_FONT_DATA;
	}

	f->width = font_selected->width;
	f->height = font_selected->height;

	for (i = 0; i < ENCODED_CHARS; i++)
		f->char_ptr[i] = font_selected->encoding[i];

	f->image_data = font_selected->image;

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
    uint8_t c,
    uint8_t fg_color,
    uint8_t bg_color)
{
	int	row;
	int	byte;
	int	i;
	uint8_t	*cp;
	uint8_t	data;
	uint8_t	nibblett;
	int	bytes_wide;

	cp = f->char_ptr[c];
	bytes_wide = (f->width + 7) / 8;

	for (row = 0; row < f->height; row++) {
		for (byte = 0; byte < bytes_wide; byte++) {
			data = *cp++;
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
    uint8_t c,
    uint8_t fg_color,
    uint8_t bg_color)
{
	int	row;
	int	byte;
	int	i;
	uint8_t	*cp;
	uint8_t	data;
	int	bytes_wide;
	uint8_t	mask;
	int	bitsleft, nbits;

	cp = f->char_ptr[c];
	bytes_wide = (f->width + 7) / 8;

	for (row = 0; row < f->height; row++) {
		bitsleft = f->width;
		for (byte = 0; byte < bytes_wide; byte++) {
			data = *cp++;
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
 * bit_to_pix24 is for 24-bit frame buffers.  It will write four output bytes
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
font_bit_to_pix24(
    struct font *f,
    uint32_t *dest,
    uint8_t c,
    uint32_t fg_color32,
    uint32_t bg_color32)
{
	int	row;
	int	byte;
	int	i;
	uint8_t	*cp;
	uint32_t data;
	int	bytes_wide;
	int	bitsleft, nbits;

	cp = f->char_ptr[c];
	bytes_wide = (f->width + 7) / 8;

	for (row = 0; row < f->height; row++) {
		bitsleft = f->width;
		for (byte = 0; byte < bytes_wide; byte++) {
			data = *cp++;
			nbits = MIN(8, bitsleft);
			bitsleft -= nbits;
			for (i = 0; i < nbits; i++) {
				*dest++ = ((data << i) & 0x80 ?
				    fg_color32 : bg_color32);
			}
		}
	}
}
