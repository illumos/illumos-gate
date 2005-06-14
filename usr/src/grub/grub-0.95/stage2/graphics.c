/* graphics.c - graphics mode support for GRUB */
/* Implemented as a terminal type by Jeremy Katz <katzj@redhat.com> based
 * on a patch by Paulo César Pereira de Andrade <pcpa@conectiva.com.br>
 */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2001,2002  Red Hat, Inc.
 *  Portions copyright (C) 2000  Conectiva, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */



#ifdef SUPPORT_GRAPHICS

#include <term.h>
#include <shared.h>
#include <graphics.h>

int saved_videomode;
unsigned char *font8x16;

int graphics_inited = 0;
static char splashimage[64];

#define VSHADOW VSHADOW1
unsigned char VSHADOW1[38400];
unsigned char VSHADOW2[38400];
unsigned char VSHADOW4[38400];
unsigned char VSHADOW8[38400];

/* constants to define the viewable area */
const int x0 = 0;
const int x1 = 80;
const int y0 = 0;
const int y1 = 30;

/* text buffer has to be kept around so that we can write things as we
 * scroll and the like */
unsigned short text[80 * 30];

/* why do these have to be kept here? */
int foreground = (63 << 16) | (63 << 8) | (63), background = 0, border = 0;

/* current position */
static int fontx = 0;
static int fonty = 0;

/* global state so that we don't try to recursively scroll or cursor */
static int no_scroll = 0;

/* color state */
static int graphics_standard_color = A_NORMAL;
static int graphics_normal_color = A_NORMAL;
static int graphics_highlight_color = A_REVERSE;
static int graphics_current_color = A_NORMAL;
static color_state graphics_color_state = COLOR_STATE_STANDARD;


/* graphics local functions */
static void graphics_setxy(int col, int row);
static void graphics_scroll();

/* FIXME: where do these really belong? */
static inline void outb(unsigned short port, unsigned char val)
{
    __asm __volatile ("outb %0,%1"::"a" (val), "d" (port));
}

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
void graphics_set_splash(char *splashfile) {
    grub_strcpy(splashimage, splashfile);
}

/* Get the current splash image */
char *graphics_get_splash(void) {
    return splashimage;
}

/* Initialize a vga16 graphics display with the palette based off of
 * the image in splashimage.  If the image doesn't exist, leave graphics
 * mode.  */
int graphics_init()
{
    if (!graphics_inited) {
        saved_videomode = set_videomode(0x12);
    }

    if (!read_image(splashimage)) {
        set_videomode(saved_videomode);
        grub_printf("failed to read image\n");
        return 0;
    }

    font8x16 = (unsigned char*)graphics_get_font();

    graphics_inited = 1;

    /* make sure that the highlight color is set correctly */
    graphics_highlight_color = ((graphics_normal_color >> 4) | 
				((graphics_normal_color & 0xf) << 4));

    return 1;
}

/* Leave graphics mode */
void graphics_end(void)
{
    if (graphics_inited) {
        set_videomode(saved_videomode);
        graphics_inited = 0;
    }
}

/* Print ch on the screen.  Handle any needed scrolling or the like */
void graphics_putchar(int ch) {
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
int graphics_getxy(void) {
    return (fontx << 8) | fonty;
}

void graphics_gotoxy(int x, int y) {
    graphics_cursor(0);

    graphics_setxy(x, y);

    graphics_cursor(1);
}

void graphics_cls(void) {
    int i;
    unsigned char *mem, *s1, *s2, *s4, *s8;

    graphics_cursor(0);
    graphics_gotoxy(x0, y0);

    mem = (unsigned char*)VIDEOMEM;
    s1 = (unsigned char*)VSHADOW1;
    s2 = (unsigned char*)VSHADOW2;
    s4 = (unsigned char*)VSHADOW4;
    s8 = (unsigned char*)VSHADOW8;

    for (i = 0; i < 80 * 30; i++)
        text[i] = ' ';
    graphics_cursor(1);

    BitMask(0xff);

    /* plano 1 */
    MapMask(1);
    grub_memcpy(mem, s1, 38400);

    /* plano 2 */
    MapMask(2);
    grub_memcpy(mem, s2, 38400);

    /* plano 3 */
    MapMask(4);
    grub_memcpy(mem, s4, 38400);

    /* plano 4 */
    MapMask(8);
    grub_memcpy(mem, s8, 38400);

    MapMask(15);
 
}

void graphics_setcolorstate (color_state state) {
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

void graphics_setcolor (int normal_color, int highlight_color) {
    graphics_normal_color = normal_color;
    graphics_highlight_color = highlight_color;

    graphics_setcolorstate (graphics_color_state);
}

int graphics_setcursor (int on) {
    /* FIXME: we don't have a cursor in graphics */
    return 1;
}

/* Read in the splashscreen image and set the palette up appropriately.
 * Format of splashscreen is an xpm (can be gzipped) with 16 colors and
 * 640x480. */
int read_image(char *s)
{
    char buf[32], pal[16];
    unsigned char c, base, mask, *s1, *s2, *s4, *s8;
    unsigned i, len, idx, colors, x, y, width, height;

    if (!grub_open(s))
        return 0;

    /* read header */
    if (!grub_read((char*)&buf, 10) || grub_memcmp(buf, "/* XPM */\n", 10)) {
        grub_close();
        return 0;
    }
    
    /* parse info */
    while (grub_read(&c, 1)) {
        if (c == '"')
            break;
    }

    while (grub_read(&c, 1) && (c == ' ' || c == '\t'))
        ;

    i = 0;
    width = c - '0';
    while (grub_read(&c, 1)) {
        if (c >= '0' && c <= '9')
            width = width * 10 + c - '0';
        else
            break;
    }
    while (grub_read(&c, 1) && (c == ' ' || c == '\t'))
        ;

    height = c - '0';
    while (grub_read(&c, 1)) {
        if (c >= '0' && c <= '9')
            height = height * 10 + c - '0';
        else
            break;
    }
    while (grub_read(&c, 1) && (c == ' ' || c == '\t'))
        ;

    colors = c - '0';
    while (grub_read(&c, 1)) {
        if (c >= '0' && c <= '9')
            colors = colors * 10 + c - '0';
        else
            break;
    }

    base = 0;
    while (grub_read(&c, 1) && c != '"')
        ;

    /* palette */
    for (i = 0, idx = 1; i < colors; i++) {
        len = 0;

        while (grub_read(&c, 1) && c != '"')
            ;
        grub_read(&c, 1);       /* char */
        base = c;
        grub_read(buf, 4);      /* \t c # */

        while (grub_read(&c, 1) && c != '"') {
            if (len < sizeof(buf))
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

    s1 = (unsigned char*)VSHADOW1;
    s2 = (unsigned char*)VSHADOW2;
    s4 = (unsigned char*)VSHADOW4;
    s8 = (unsigned char*)VSHADOW8;

    for (i = 0; i < 38400; i++)
        s1[i] = s2[i] = s4[i] = s8[i] = 0;

    /* parse xpm data */
    while (y < height) {
        while (1) {
            if (!grub_read(&c, 1)) {
                grub_close();
                return 0;
            }
            if (c == '"')
                break;
        }

        while (grub_read(&c, 1) && c != '"') {
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

    grub_close();

    graphics_set_palette(0, (background >> 16), (background >> 8) & 63, 
                background & 63);
    graphics_set_palette(15, (foreground >> 16), (foreground >> 8) & 63, 
                foreground & 63);
    graphics_set_palette(0x11, (border >> 16), (border >> 8) & 63, 
                         border & 63);

    return 1;
}


/* Convert a character which is a hex digit to the appropriate integer */
int hex(int v)
{
    if (v >= 'A' && v <= 'F')
        return (v - 'A' + 10);
    if (v >= 'a' && v <= 'f')
        return (v - 'a' + 10);
    return (v - '0');
}


/* move the graphics cursor location to col, row */
static void graphics_setxy(int col, int row) {
    if (col >= x0 && col < x1) {
        fontx = col;
        cursorX = col << 3;
    }
    if (row >= y0 && row < y1) {
        fonty = row;
        cursorY = row << 4;
    }
}

/* scroll the screen */
static void graphics_scroll() {
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

    mem = (unsigned char*)VIDEOMEM + offset;

    if (!set) {
        for (i = 0; i < 16; i++) {
            unsigned char mask = pat[i];

            if (!invert) {
                chr[i     ] = ((unsigned char*)VSHADOW1)[offset];
                chr[16 + i] = ((unsigned char*)VSHADOW2)[offset];
                chr[32 + i] = ((unsigned char*)VSHADOW4)[offset];
                chr[48 + i] = ((unsigned char*)VSHADOW8)[offset];

                /* FIXME: if (shade) */
                if (1) {
                    if (ch == DISP_VERT || ch == DISP_LL ||
                        ch == DISP_UR || ch == DISP_LR) {
                        unsigned char pmask = ~(pat[i] >> 1);

                        chr[i     ] &= pmask;
                        chr[16 + i] &= pmask;
                        chr[32 + i] &= pmask;
                        chr[48 + i] &= pmask;
                    }
                    if (i > 0 && ch != DISP_VERT) {
                        unsigned char pmask = ~(pat[i - 1] >> 1);

                        chr[i     ] &= pmask;
                        chr[16 + i] &= pmask;
                        chr[32 + i] &= pmask;
                        chr[48 + i] &= pmask;
                        if (ch == DISP_HORIZ || ch == DISP_UR || ch == DISP_LR) {
                            pmask = ~pat[i - 1];

                            chr[i     ] &= pmask;
                            chr[16 + i] &= pmask;
                            chr[32 + i] &= pmask;
                            chr[48 + i] &= pmask;
                        }
                    }
                }
                chr[i     ] |= mask;
                chr[16 + i] |= mask;
                chr[32 + i] |= mask;
                chr[48 + i] |= mask;

                offset += 80;
            }
            else {
                chr[i     ] = mask;
                chr[16 + i] = mask;
                chr[32 + i] = mask;
                chr[48 + i] = mask;
            }
        }
    }
    else {
        MapMask(15);
        ptr = mem;
        for (i = 0; i < 16; i++, ptr += 80) {
            cursorBuf[i] = pat[i];
            *ptr = ~pat[i];
        }
        return;
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

#endif /* SUPPORT_GRAPHICS */
