/* bios.c - implement C part of low-level BIOS disk input and output */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2003,2004  Free Software Foundation, Inc.
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


/* These are defined in asm.S, and never be used elsewhere, so declare the
   prototypes here.  */
extern int biosdisk_int13_extensions (int ax, int drive, void *dap);
extern int biosdisk_standard (int ah, int drive,
			      int coff, int hoff, int soff,
			      int nsec, int segment);
extern int check_int13_extensions (int drive);
extern int get_diskinfo_standard (int drive,
				  unsigned long *cylinders,
				  unsigned long *heads,
				  unsigned long *sectors);
#if 0
extern int get_diskinfo_floppy (int drive,
				unsigned long *cylinders,
				unsigned long *heads,
				unsigned long *sectors);
#endif


/* Read/write NSEC sectors starting from SECTOR in DRIVE disk with GEOMETRY
   from/into SEGMENT segment. If READ is BIOSDISK_READ, then read it,
   else if READ is BIOSDISK_WRITE, then write it. If an geometry error
   occurs, return BIOSDISK_ERROR_GEOMETRY, and if other error occurs, then
   return the error number. Otherwise, return 0.  */
int
biosdisk (int read, int drive, struct geometry *geometry,
	  unsigned long long sector, int nsec, int segment)
{

  int err;
  
  if (geometry->flags & BIOSDISK_FLAG_LBA_EXTENSION)
    {
      struct disk_address_packet
      {
	unsigned char length;
	unsigned char reserved;
	unsigned short blocks;
	unsigned long buffer;
	unsigned long long block;
      } __attribute__ ((packed)) dap;

      /* XXX: Don't check the geometry by default, because some buggy
	 BIOSes don't return the number of total sectors correctly,
	 even if they have working LBA support. Hell.  */
#ifdef NO_BUGGY_BIOS_IN_THE_WORLD
      if (sector >= geometry->total_sectors)
	return BIOSDISK_ERROR_GEOMETRY;
#endif /* NO_BUGGY_BIOS_IN_THE_WORLD */

      /* FIXME: sizeof (DAP) must be 0x10. Should assert that the compiler
	 can't add any padding.  */
      dap.length = sizeof (dap);
      dap.block = sector;
      dap.blocks = nsec;
      dap.reserved = 0;
      /* This is undocumented part. The address is formated in
	 SEGMENT:ADDRESS.  */
      dap.buffer = segment << 16;
      err = biosdisk_int13_extensions ((read + 0x42) << 8, drive, &dap);
      /*
       * Try to report errors upwards when the bios has read only part of
       * the requested buffer, but didn't return an error code.
       */
      if (err == 0 && dap.blocks != nsec)
	err = BIOSDISK_ERROR_SHORT_IO;

/* #undef NO_INT13_FALLBACK */
#ifndef NO_INT13_FALLBACK
      if (err)
	{
	  if (geometry->flags & BIOSDISK_FLAG_CDROM)
	    return err;
	  
	  geometry->flags &= ~BIOSDISK_FLAG_LBA_EXTENSION;
	  geometry->total_sectors = ((unsigned long long)geometry->cylinders
				     * geometry->heads
				     * geometry->sectors);
	  return biosdisk (read, drive, geometry, sector, nsec, segment);
	}
#endif /* ! NO_INT13_FALLBACK */
      
    }
  else
    {
      int cylinder_offset, head_offset, sector_offset;
      int head;
      /* SECTOR_OFFSET is counted from one, while HEAD_OFFSET and
	 CYLINDER_OFFSET are counted from zero.  */
      sector_offset = sector % geometry->sectors + 1;
      head = sector / geometry->sectors;
      head_offset = head % geometry->heads;
      cylinder_offset = head / geometry->heads;
      
      if (cylinder_offset >= geometry->cylinders)
	return BIOSDISK_ERROR_GEOMETRY;

      err = biosdisk_standard (read + 0x02, drive,
			       cylinder_offset, head_offset, sector_offset,
			       nsec, segment);
    }

  return err;
}

/* Check bootable CD-ROM emulation status.  */
static int
get_cdinfo (int drive, struct geometry *geometry)
{
  int err;
  struct iso_spec_packet
  {
    unsigned char size;
    unsigned char media_type;
    unsigned char drive_no;
    unsigned char controller_no;
    unsigned long image_lba;
    unsigned short device_spec;
    unsigned short cache_seg;
    unsigned short load_seg;
    unsigned short length_sec512;
    unsigned char cylinders;
    unsigned char sectors;
    unsigned char heads;
    
    unsigned char dummy[16];
  } __attribute__ ((packed)) cdrp;
  
  grub_memset (&cdrp, 0, sizeof (cdrp));
  cdrp.size = sizeof (cdrp) - sizeof (cdrp.dummy);
  err = biosdisk_int13_extensions (0x4B01, drive, &cdrp);
  if (! err && cdrp.drive_no == drive)
    {
      if ((cdrp.media_type & 0x0F) == 0)
        {
          /* No emulation bootable CD-ROM */
          geometry->flags = BIOSDISK_FLAG_LBA_EXTENSION | BIOSDISK_FLAG_CDROM;
          geometry->cylinders = 0;
          geometry->heads = 1;
          geometry->sectors = 15;
          geometry->sector_size = 2048;
          geometry->total_sectors = MAXUINT;
          return 1;
        }
      else
        {
	  /* Floppy or hard-disk emulation */
          geometry->cylinders
	    = ((unsigned int) cdrp.cylinders
	       + (((unsigned int) (cdrp.sectors & 0xC0)) << 2));
          geometry->heads = cdrp.heads;
          geometry->sectors = cdrp.sectors & 0x3F;
          geometry->sector_size = SECTOR_SIZE;
          geometry->total_sectors = ((unsigned long long)geometry->cylinders
				     * geometry->heads
				     * geometry->sectors);
          return -1;
        }
    }

  /*
   * If this is the boot_drive, default to non-emulation bootable CD-ROM.
   *
   * Some BIOS (Tecra S1) fails the int13 call above. If we return
   * failure here, GRUB will run, but cannot see the boot drive,
   * not a very good situation. Defaulting to non-emulation mode
   * is a last-ditch effort.
   */
  if (drive >= 0x88 && drive == boot_drive)
    {
      geometry->flags = BIOSDISK_FLAG_LBA_EXTENSION | BIOSDISK_FLAG_CDROM;
      geometry->cylinders = 0;
      geometry->heads = 1;
      geometry->sectors = 15;
      geometry->sector_size = 2048;
      geometry->total_sectors = MAXUINT;
      return 1;
    }
  return 0;
}

/* Return the geometry of DRIVE in GEOMETRY. If an error occurs, return
   non-zero, otherwise zero.  */
int
get_diskinfo (int drive, struct geometry *geometry)
{
  int err;
  int gotchs = 0;

  /* Clear the flags.  */
  geometry->flags = 0;
  
  if (drive & 0x80)
    {
      /* hard disk or CD-ROM */
      int version;
      unsigned long long total_sectors = 0;
      
      version = check_int13_extensions (drive);

      if (drive >= 0x88 || version)
	{
	  /* Possible CD-ROM - check the status.  */
	  if (get_cdinfo (drive, geometry))
	    return 0;
	}

      /* Don't pass GEOMETRY directly, but pass each element instead,
	 so that we can change the structure easily.  */
      err = get_diskinfo_standard (drive,
				   &geometry->cylinders,
				   &geometry->heads,
				   &geometry->sectors);
      if (err == 0)
	gotchs = 1;
      /* get_diskinfo_standard returns 0x60 if the BIOS call actually
	 succeeded but returned 0 sectors -- in this case don't
	 return yet but continue to check the LBA geom */
      else if (err != 0x60)
	return err;
      
      if (version)
	{
	  struct drive_parameters
	  {
	    unsigned short size;
	    unsigned short flags;
	    unsigned long cylinders;
	    unsigned long heads;
	    unsigned long sectors;
	    unsigned long long total_sectors;
	    unsigned short bytes_per_sector;
	    /* ver 2.0 or higher */
	    unsigned long EDD_configuration_parameters;
	    /* ver 3.0 or higher */
	    unsigned short signature_dpi;
	    unsigned char length_dpi;
	    unsigned char reserved[3];
	    unsigned char name_of_host_bus[4];
	    unsigned char name_of_interface_type[8];
	    unsigned char interface_path[8];
	    unsigned char device_path[8];
	    unsigned char reserved2;
	    unsigned char checksum;

	    /* XXX: This is necessary, because the BIOS of Thinkpad X20
	       writes a garbage to the tail of drive parameters,
	       regardless of a size specified in a caller.  */
	    unsigned char dummy[16];
	  } __attribute__ ((packed)) drp;

	  /* It is safe to clear out DRP.  */
	  grub_memset (&drp, 0, sizeof (drp));
	  
	  /* PhoenixBIOS 4.0 Revision 6.0 for ZF Micro might understand 
	     the greater buffer size for the "get drive parameters" int 
	     0x13 call in its own way.  Supposedly the BIOS assumes even 
	     bigger space is available and thus corrupts the stack.  
	     This is why we specify the exactly necessary size of 0x42 
	     bytes. */
	  drp.size = sizeof (drp) - sizeof (drp.dummy);
	  
	  err = biosdisk_int13_extensions (0x4800, drive, &drp);
	  if (! err)
	    {
	      /* Set the LBA flag.  */
	      geometry->flags = BIOSDISK_FLAG_LBA_EXTENSION;

	      /* I'm not sure if GRUB should check the bit 1 of DRP.FLAGS,
		 so I omit the check for now. - okuji  */
	      /* if (drp.flags & (1 << 1)) */

	      /* If we didn't get valid CHS info from the standard call,
		 then we should fill it out here */
	      if (! gotchs)
		{
		  geometry->cylinders = drp.cylinders;

		  if (drp.sectors > 0 && drp.heads > 0)
		    {
		      geometry->heads = drp.heads;
		      geometry->sectors = drp.sectors;
		    }
		  else
		    {
		      /* Return fake geometry. This disk reports that it
			 supports LBA, so all the other routines will use LBA
			 to talk to it and not look at this geometry. However,
			 some of the partition-finding routines still need
			 non-zero values in these fields. */
		      geometry->heads = 16;
		      geometry->sectors = 63;
		    }
		  gotchs = 1;
		}
	       
	      if (drp.total_sectors)
		total_sectors = drp.total_sectors;
	      else
		/* Some buggy BIOSes doesn't return the total sectors
		   correctly but returns zero. So if it is zero, compute
		   it by C/H/S returned by the LBA BIOS call.  */
		total_sectors = (unsigned long long)drp.cylinders *
		    drp.heads * drp.sectors;
	    }
	}

      /* In case we got the 0x60 return code from _standard on a disk that
	 didn't support LBA (or was somehow invalid), return that error now */
      if (! gotchs)
	return 0x60;

      if (! total_sectors)
	{
	  total_sectors = ((unsigned long long)geometry->cylinders
			   * geometry->heads
			   * geometry->sectors);
	}
      geometry->total_sectors = total_sectors;
      geometry->sector_size = SECTOR_SIZE;
    }
  else
    {
      /* floppy disk */

      /* First, try INT 13 AH=8h call.  */
      err = get_diskinfo_standard (drive,
				   &geometry->cylinders,
				   &geometry->heads,
				   &geometry->sectors);

#if 0
      /* If fails, then try floppy-specific probe routine.  */
      if (err)
	err = get_diskinfo_floppy (drive,
				   &geometry->cylinders,
				   &geometry->heads,
				   &geometry->sectors);
#endif
      
      if (err)
	return err;

      geometry->total_sectors = ((unsigned long long)geometry->cylinders
				 * geometry->heads
				 * geometry->sectors);
      geometry->sector_size = SECTOR_SIZE;
    }

  return 0;
}
