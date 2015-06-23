/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2005,2006   Free Software Foundation, Inc.
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

#ifndef _GPT_H
#define _GPT_H

typedef signed char grub_int8_t;
typedef signed short grub_int16_t;
typedef signed int grub_int32_t;
typedef signed long long int grub_int64_t;
typedef unsigned char grub_uint8_t;
typedef unsigned short grub_uint16_t;
typedef unsigned int grub_uint32_t;
typedef unsigned long long int grub_uint64_t;

struct grub_gpt_header
{
  grub_uint64_t magic;
  grub_uint32_t version;
  grub_uint32_t headersize;
  grub_uint32_t crc32;
  grub_uint32_t unused1;
  grub_uint64_t primary;
  grub_uint64_t backup;
  grub_uint64_t start;
  grub_uint64_t end;
  grub_uint8_t guid[16];
  grub_uint64_t partitions;
  grub_uint32_t maxpart;
  grub_uint32_t partentry_size;
  grub_uint32_t partentry_crc32;
} __attribute__ ((packed));

struct grub_gpt_partentry
{
  grub_uint64_t type1;
  grub_uint64_t type2;
  grub_uint8_t guid[16];
  grub_uint64_t start;
  grub_uint64_t end;
  grub_uint8_t attrib;
  char name[72];
} __attribute__ ((packed));

#define GPT_HEADER_MAGIC       0x5452415020494645ULL

#define        GPT_ENTRY_SECTOR(size,entry)                                    \
       ((((entry) * (size) + 1) & ~(SECTOR_SIZE - 1)) >> SECTOR_BITS)
#define        GPT_ENTRY_INDEX(size,entry)                                     \
       ((((entry) * (size) + 1) & (SECTOR_SIZE - 1)) - 1)

#endif /* _GPT_H */
