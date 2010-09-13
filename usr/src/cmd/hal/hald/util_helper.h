/***************************************************************************
 *
 * util_helper.h - HAL utilities for helper (as e.g. prober/addons) et al.
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/


#ifndef UTIL_HELPER_H
#define UTIL_HELPER_H

void drop_privileges (int keep_auxgroups);
void hal_set_proc_title_init (int argc, char *argv[]);
void hal_set_proc_title (const char *format, ...);

#endif /* UTIL_HELPER_H */
