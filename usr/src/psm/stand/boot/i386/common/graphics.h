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

#ifndef	_GRAPHICS_H
#define	_GRAPHICS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* magic constant */
#define	VIDEOMEM 0xA0000

/* code for getchar */
#define	A_NORMAL 0x7
#define	A_REVERSE 0x70

/* These are used to represent the various color states we use */
typedef enum
{
/*
 * represents the color used to display all text that does not use the user
 * defined colors below
 */
COLOR_STATE_STANDARD,
/* represents the user defined colors for normal text */
COLOR_STATE_NORMAL,
/* represents the user defined colors for highlighted text */
COLOR_STATE_HIGHLIGHT
} color_state;

void graphics_cursor(int set);
void graphics_putchar(int c);
int graphics_getxy(void);
void graphics_gotoxy(int x, int y);
void graphics_cls(void);
void graphics_setcolorstate(color_state state);
void graphics_setcolor(int normal_color, int highlight_color);
void graphics_setcursor(int on);
int set_videomode(int mode);
int graphics_init(void);
void graphics_end(void);
unsigned char *graphics_get_font(void);
int graphics_set_palette(int idx, int red, int green, int blue);
int graphics_set_splash(char *splashfile);

short cursorX, cursorY;
char cursorBuf[16];

#ifdef	__cplusplus
}
#endif

#endif	/* _GRAPHICS_H */
