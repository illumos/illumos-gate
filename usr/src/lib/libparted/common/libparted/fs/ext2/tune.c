/*
    tune.c -- tuneable stuff
    Copyright (C) 1998-2000, 2007 Free Software Foundation, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <config.h>

#ifndef DISCOVER_ONLY

/*
 * maybe i'll make this all command-line configurable one day
 */

/* The size of the buffer cache in kilobytes. Note that this is only
   the actual buffer memory. On top of this amount additional memory
   will be allocated for buffer cache bookkeeping. */
int ext2_buffer_cache_pool_size = 512;

/* The size of the buffer cache hash table (log2 of # of buckets). */
int ext2_hash_bits = 8;

/* The block/inode relocator pool size in kilobytes. Make this as big
   as you can. The smaller this is, the more disk I/O is required for
   doing relocations. */
int ext2_relocator_pool_size = 4096;
#endif /* !DISCOVER_ONLY */
