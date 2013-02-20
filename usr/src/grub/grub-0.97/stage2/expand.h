/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (c) 2013 Joyent, Inc.  All rights reserved.
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

#ifndef	_GRUB_EXPAND_H
#define	_GRUB_EXPAND_H

#define	EV_NAMELEN	32

extern void init_variables(void);
extern int set_variable(const char *, const char *);
extern const char *get_variable(const char *);
extern int expand_string(const char *, char *, unsigned int);
extern void dump_variables(void);

#endif
