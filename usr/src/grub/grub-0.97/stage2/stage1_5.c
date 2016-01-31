/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2001,2002  Free Software Foundation, Inc.
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
 * Copyright 2016 Nexenta Systems, Inc.
 */

#include "shared.h"

static unsigned long long saved_sector = (unsigned long long)-1;

static void
disk_read_savesect_func (unsigned long long sector, int offset, int length)
{
  saved_sector = sector;
}

void
cmain (void)
{
  grub_printf ("\n\nGRUB loading, please wait...\n");

  /*
   *  Here load the true second-stage boot-loader.
   */

  if (grub_open (config_file))
    {
      int ret;

      disk_read_hook = disk_read_savesect_func;
      grub_read ((char *) 0x8000, SECTOR_SIZE * 2);
      disk_read_hook = NULL;

      /* Sanity check: catch an internal error.  */
      if (saved_sector == (unsigned int)-1)
	{
	  grub_printf ("internal error: the second sector of Stage 2 is unknown.");
	  stop ();
	}
      
      ret = grub_read ((char *) 0x8000 + SECTOR_SIZE * 2, -1);
      
      grub_close ();

      if (ret)
	chain_stage2 (0, 0x8200, saved_sector);
    }

  /*
   *  If not, then print error message and die.
   */

  print_error ();

  stop ();
}
