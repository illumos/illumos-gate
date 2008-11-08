/* terminfo.h - read a terminfo entry from the command line */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2004  Free Software Foundation, Inc.
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

#ifndef GRUB_TERMCAP_HEADER
#define GRUB_TERMCAP_HEADER	1

#define TERMINFO_LEN 40

typedef struct terminfo
{
  char name[TERMINFO_LEN];
  char cursor_address[TERMINFO_LEN];
  char clear_screen[TERMINFO_LEN];
  char enter_standout_mode[TERMINFO_LEN];
  char exit_standout_mode[TERMINFO_LEN];
}
terminfo;


/* Function prototypes.  */
char *ti_escape_memory (const char *in, const char *end);
char *ti_escape_string (const char *in);
char *ti_unescape_memory (const char *in, const char *end);
char *ti_unescape_string (const char *in);

void ti_set_term (const struct terminfo *new);
void ti_get_term (struct terminfo *copy);

void ti_cursor_address (int x, int y);
void ti_clear_screen (void);
void ti_enter_standout_mode (void);
void ti_exit_standout_mode (void);

#endif /* ! GRUB_TERMCAP_HEADER */
