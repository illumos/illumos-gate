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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FONT_H
#define	_SYS_FONT_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Number of chars encoded in font data. Bundled fonts are generated
 * from bdf files and this constant depends on the data in the bdf file.
 * If more entries are added to the bdf files, then this number must be
 * increased.
 */
#define	ENCODED_CHARS	256

struct font {
	short	width;
	short	height;
	uchar_t	*char_ptr[ENCODED_CHARS];
	void	*image_data;
};

typedef	struct  bitmap_data {
	short		width;
	short		height;
	unsigned char	*image;
	unsigned char	**encoding;
} bitmap_data_t;

struct fontlist {
	bitmap_data_t	*data;
	bitmap_data_t   *(*fontload)(char *);
};

extern struct fontlist fonts[];

#define	DEFAULT_FONT_DATA	font_data_12x22
#define	BORDER_PIXELS		10	/* space from screen border */
/*
 * Built in fonts.
 */
extern bitmap_data_t font_data_12x22;
extern bitmap_data_t font_data_8x16;
extern bitmap_data_t font_data_7x14;
extern bitmap_data_t font_data_6x10;

void set_font(struct font *, short *, short *, short, short);
void font_bit_to_pix4(struct font *, uint8_t *, uchar_t, uint8_t, uint8_t);
void font_bit_to_pix8(struct font *, uint8_t *, uchar_t, uint8_t, uint8_t);
void font_bit_to_pix24(struct font *, uint32_t *, uchar_t, uint32_t, uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* !_SYS_FONT_H */
