/* nbi.h - definitions for Net Boot Image */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2000  Free Software Foundation, Inc.
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

#ifndef GRUB_NBI_HEADER
#define GRUB_NBI_HEADER

#define NBI_MAGIC		0x1B031336
#define NBI_DEST_ADDR		0x10000
#define NBI_DEST_SEG		0x1000
#define NBI_DEST_OFF		0x0000
#define RELOCATED_ADDR		0x8000
#define RELOCATED_SEG		0x0800
#define RELOCATED_OFF		0x0000
#define STAGE2_START_ADDR	0x8200

#endif /* ! GRUB_NBI_HEADER */
