/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2000, 2001  Free Software Foundation, Inc.
 *  Copyright (c) 2004  Valery Hromov
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
 * Elements of this file were originally from the FreeBSD "biosboot"
 * bootloader file "disk.c" dated 4/12/95.
 *
 * The license and header comments from that file are included here.
 */

/*
 * Mach Operating System
 * Copyright (c) 1992, 1991 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 *
 *	from: Mach, Revision 2.2  92/04/04  11:35:49  rpd
 *	$Id: fsys_ufs2.c,v 1.2 2004/06/19 12:17:52 okuji Exp $
 */

#ifdef FSYS_UFS2

#include "shared.h"
#include "filesys.h"

#include "ufs2.h"

/* used for filesystem map blocks */
static int mapblock;
static int mapblock_offset;
static int mapblock_bsize;

static int sblock_try[] = SBLOCKSEARCH;
static ufs2_daddr_t sblockloc;
static int type;

/* pointer to superblock */
#define SUPERBLOCK ((struct fs *) ( FSYS_BUF + 8192 ))

#define INODE_UFS2 ((struct ufs2_dinode *) ( FSYS_BUF + 16384 ))

#define MAPBUF ( FSYS_BUF + 24576 )
#define MAPBUF_LEN 8192

int
ufs2_mount (void)
{
  int retval = 0;
  int i;

  sblockloc = -1;
  type = 0;
  
  if (! (((current_drive & 0x80) || (current_slice != 0))
	 && ! IS_PC_SLICE_TYPE_BSD_WITH_FS (current_slice, FS_BSDFFS)))
    {
      for (i = 0; sblock_try[i] != -1; ++i)
	{
	  if (! (part_length < (sblock_try[i] + (SBLOCKSIZE / DEV_BSIZE))
		 || ! devread (0, sblock_try[i], SBLOCKSIZE, (char *) SUPERBLOCK)))
	    {
	      if (SUPERBLOCK->fs_magic == FS_UFS2_MAGIC /* &&
							   (SUPERBLOCK->fs_sblockloc == sblockloc ||
						     (SUPERBLOCK->fs_old_flags & FS_FLAGS_UPDATED) == 0)*/)
		{
		  type = 2;
		}
	      else
		{
		  continue;
		}
	      
	      retval = 1;
	      sblockloc = sblock_try[i];
	      break;
	    }
	}
    }
  
  mapblock = -1;
  mapblock_offset = -1;
  
  return retval;
}

static grub_int64_t
block_map (int file_block)
{
  int bnum, offset, bsize;
  
  if (file_block < NDADDR)
    return (INODE_UFS2->di_db[file_block]);
  
  /* If the blockmap loaded does not include FILE_BLOCK,
     load a new blockmap.  */

  if ((bnum = fsbtodb (SUPERBLOCK, INODE_UFS2->di_ib[0])) != mapblock
      || (mapblock_offset <= bnum && bnum <= mapblock_offset + mapblock_bsize))
    {
      if (MAPBUF_LEN < SUPERBLOCK->fs_bsize)
	{
	  offset = ((file_block - NDADDR) % NINDIR (SUPERBLOCK));
	  bsize = MAPBUF_LEN;
	  
	  if (offset + MAPBUF_LEN > SUPERBLOCK->fs_bsize)
	    offset = (SUPERBLOCK->fs_bsize - MAPBUF_LEN) / sizeof (int);
	}
      else
	{
	  bsize = SUPERBLOCK->fs_bsize;
	  offset = 0;
	}
      
      if (! devread (bnum, offset * sizeof (int), bsize, (char *) MAPBUF))
	{
	  mapblock = -1;
	  mapblock_bsize = -1;
	  mapblock_offset = -1;
	  errnum = ERR_FSYS_CORRUPT;
	  return -1;
	}
      
      mapblock = bnum;
      mapblock_bsize = bsize;
      mapblock_offset = offset;
    }
  
  return (((grub_int64_t *) MAPBUF)[((file_block - NDADDR) % NINDIR (SUPERBLOCK))
				    - mapblock_offset]);
}

int
ufs2_read (char *buf, int len)
{
  int logno, off, size, ret = 0;
  grub_int64_t map;

  while (len && !errnum)
    {
      off = blkoff (SUPERBLOCK, filepos);
      logno = lblkno (SUPERBLOCK, filepos);
      size = blksize (SUPERBLOCK, INODE_UFS2, logno);

      if ((map = block_map (logno)) < 0)
	break; 

      size -= off;

      if (size > len)
	size = len;

      disk_read_func = disk_read_hook;

      devread (fsbtodb (SUPERBLOCK, map), off, size, buf);

      disk_read_func = NULL;

      buf += size;
      len -= size;
      filepos += size;
      ret += size;
    }

  if (errnum)
    ret = 0;

  return ret;
}

int
ufs2_dir (char *dirname)
{
  char *rest, ch;
  int block, off, loc, ino = ROOTINO;
  grub_int64_t map;
  struct direct *dp;

/* main loop to find destination inode */
loop:

  /* load current inode (defaults to the root inode) */

    if (!devread (fsbtodb (SUPERBLOCK, ino_to_fsba (SUPERBLOCK, ino)),
	    ino % (SUPERBLOCK->fs_inopb) * sizeof (struct ufs2_dinode),
	    sizeof (struct ufs2_dinode), (char *) INODE_UFS2))
		    return 0;			/* XXX what return value? */

  /* if we have a real file (and we're not just printing possibilities),
     then this is where we want to exit */

  if (!*dirname || isspace (*dirname))
    {
      if ((INODE_UFS2->di_mode & IFMT) != IFREG)
	{
	  errnum = ERR_BAD_FILETYPE;
	  return 0;
	}

      filemax = INODE_UFS2->di_size;

      /* incomplete implementation requires this! */
      fsmax = (NDADDR + NINDIR (SUPERBLOCK)) * SUPERBLOCK->fs_bsize;
      return 1;
    }

  /* continue with file/directory name interpretation */

  while (*dirname == '/')
    dirname++;

  if (!(INODE_UFS2->di_size) || ((INODE_UFS2->di_mode & IFMT) != IFDIR))
    {
      errnum = ERR_BAD_FILETYPE;
      return 0;
    }

  for (rest = dirname; (ch = *rest) && !isspace (ch) && ch != '/'; rest++);

  *rest = 0;
  loc = 0;

  /* loop for reading a the entries in a directory */

  do
    {
      if (loc >= INODE_UFS2->di_size)
	{
	  if (print_possibilities < 0)
	    return 1;

	  errnum = ERR_FILE_NOT_FOUND;
	  *rest = ch;
	  return 0;
	}

      if (!(off = blkoff (SUPERBLOCK, loc)))
	{
	  block = lblkno (SUPERBLOCK, loc);

	  if ((map = block_map (block)) < 0
	      || !devread (fsbtodb (SUPERBLOCK, map), 0,
			   blksize (SUPERBLOCK, INODE_UFS2, block),
			   (char *) FSYS_BUF))
	    {
	      errnum = ERR_FSYS_CORRUPT;
	      *rest = ch;
	      return 0;
	    }
	}

      dp = (struct direct *) (FSYS_BUF + off);
      loc += dp->d_reclen;

#ifndef STAGE1_5
      if (dp->d_ino && print_possibilities && ch != '/'
	  && (!*dirname || substring (dirname, dp->d_name) <= 0))
	{
	  if (print_possibilities > 0)
	    print_possibilities = -print_possibilities;

	  print_a_completion (dp->d_name);
	}
#endif /* STAGE1_5 */
    }
  while (!dp->d_ino || (substring (dirname, dp->d_name) != 0
			|| (print_possibilities && ch != '/')));

  /* only get here if we have a matching directory entry */

  ino = dp->d_ino;
  *(dirname = rest) = ch;

  /* go back to main loop at top of function */
  goto loop;
}

int
ufs2_embed (unsigned long long *start_sector, int needed_sectors)
{
  /* XXX: I don't know if this is really correct. Someone who is
     familiar with BSD should check for this.  */
  if (needed_sectors > 14)
    return 0;
  
  *start_sector = 1;
#if 1
  /* FIXME: Disable the embedding in FFS until someone checks if
     the code above is correct.  */
  return 0;
#else
  return 1;
#endif
}

#endif /* FSYS_UFS2 */
