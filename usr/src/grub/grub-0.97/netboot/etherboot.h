/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004  Free Software Foundation, Inc.
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

/* 
 * Transport layer to use Etherboot NIC drivers in GRUB.
 */

#ifndef ETHERBOOT_H
#define ETHERBOOT_H

#include "shared.h"
#include "osdep.h"
#include "if_ether.h"
#include "in.h"

/* Link configuration time in tenths of a second */
#ifndef VALID_LINK_TIMEOUT
#define VALID_LINK_TIMEOUT	100 /* 10.0 seconds */
#endif

#ifndef	NULL
#define NULL	((void *)0)
#endif


#define gateA20_set() gateA20(1)
#define gateA20_unset() gateA20(0)
#if !defined(__sun)
#define EBDEBUG 0
#endif
/* The 'rom_info' maybe arch depended. It must be moved to some other
 * place */
struct rom_info {
	unsigned short	rom_segment;
	unsigned short	rom_length;
};

extern void poll_interruptions P((void));

/* For UNDI drivers */
extern uint32_t get_free_base_memory ( void );
extern void *allot_base_memory ( size_t );
extern void forget_base_memory ( void*, size_t );
extern void free_unused_base_memory ( void );

#endif /* ETHERBOOT_H */
