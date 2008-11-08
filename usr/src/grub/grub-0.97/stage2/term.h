/* term.h - definitions for terminal handling */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002  Free Software Foundation, Inc.
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

#ifndef GRUB_TERM_HEADER
#define GRUB_TERM_HEADER	1

/* These are used to represent the various color states we use */
typedef enum
{
  /* represents the color used to display all text that does not use the user
   * defined colors below
   */
  COLOR_STATE_STANDARD,
  /* represents the user defined colors for normal text */
  COLOR_STATE_NORMAL,
  /* represents the user defined colors for highlighted text */
  COLOR_STATE_HIGHLIGHT
} color_state;

#ifndef STAGE1_5

/* Flags for representing the capabilities of a terminal.  */
/* Some notes about the flags:
   - These flags are used by higher-level functions but not terminals
   themselves.
   - If a terminal is dumb, you may assume that only putchar, getkey and
   checkkey are called.
   - Some fancy features (nocursor, setcolor, and highlight) can be set to
   NULL.  */

/* Set when input characters shouldn't be echoed back.  */
#define TERM_NO_ECHO		(1 << 0)
/* Set when the editing feature should be disabled.  */
#define TERM_NO_EDIT		(1 << 1)
/* Set when the terminal cannot do fancy things.  */
#define TERM_DUMB		(1 << 2)
/* Set when the terminal needs to be initialized.  */
#define TERM_NEED_INIT		(1 << 16)

struct term_entry
{
  /* The name of a terminal.  */
  const char *name;
  /* The feature flags defined above.  */
  unsigned long flags;
  /* Default for maximum number of lines if not specified */
  unsigned short max_lines;
  /* Put a character.  */
  void (*putchar) (int c);
  /* Check if any input character is available.  */
  int (*checkkey) (void);
  /* Get a character.  */
  int (*getkey) (void);
  /* Get the cursor position. The return value is ((X << 8) | Y).  */
  int (*getxy) (void);
  /* Go to the position (X, Y).  */
  void (*gotoxy) (int x, int y);
  /* Clear the screen.  */
  void (*cls) (void);
  /* Set the current color to be used */
  void (*setcolorstate) (color_state state);
  /* Set the normal color and the highlight color. The format of each
     color is VGA's.  */
  void (*setcolor) (int normal_color, int highlight_color);
  /* Turn on/off the cursor.  */
  int (*setcursor) (int on);

  /* function to start a terminal */
  int (*startup) (void);
  /* function to use to shutdown a terminal */
  void (*shutdown) (void);
};

/* This lists up available terminals.  */
extern struct term_entry term_table[];
/* This points to the current terminal. This is useful, because only
   a single terminal is enabled normally.  */
extern struct term_entry *current_term;

#endif /* ! STAGE1_5 */

/* The console stuff.  */
extern int console_current_color;
void console_putchar (int c);

#ifndef STAGE1_5
int console_checkkey (void);
int console_getkey (void);
int console_getxy (void);
void console_gotoxy (int x, int y);
void console_cls (void);
void console_setcolorstate (color_state state);
void console_setcolor (int normal_color, int highlight_color);
int console_setcursor (int on);
#endif

#ifdef SUPPORT_SERIAL
void serial_putchar (int c);
int serial_checkkey (void);
int serial_getkey (void);
int serial_getxy (void);
void serial_gotoxy (int x, int y);
void serial_cls (void);
void serial_setcolorstate (color_state state);
#endif

#ifdef SUPPORT_HERCULES
void hercules_putchar (int c);
int hercules_getxy (void);
void hercules_gotoxy (int x, int y);
void hercules_cls (void);
void hercules_setcolorstate (color_state state);
void hercules_setcolor (int normal_color, int highlight_color);
int hercules_setcursor (int on);
#endif

#ifdef SUPPORT_GRAPHICS
extern int foreground, background, border, graphics_inited;

void graphics_set_splash(char *splashfile);
int set_videomode (int mode);
void graphics_putchar (int c);
int graphics_getxy(void);
void graphics_gotoxy(int x, int y);
void graphics_cls(void);
void graphics_setcolorstate (color_state state);
void graphics_setcolor (int normal_color, int highlight_color);
int graphics_setcursor (int on);
int graphics_init(void);
void graphics_end(void);

int hex(int v);
void graphics_set_palette(int idx, int red, int green, int blue);
#endif /* SUPPORT_GRAPHICS */

#endif /* ! GRUB_TERM_HEADER */
