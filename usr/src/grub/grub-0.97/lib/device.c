/* device.c - Some helper functions for OS devices and BIOS drives */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2005  Free Software Foundation, Inc.
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

/* Try to use glibc's transparant LFS support. */
#define _LARGEFILE_SOURCE       1
/* lseek becomes synonymous with lseek64.  */
#define _FILE_OFFSET_BITS       64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>

#ifdef __linux__
# if !defined(__GLIBC__) || \
        ((__GLIBC__ < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ < 1)))
/* Maybe libc doesn't have large file support.  */
#  include <linux/unistd.h>     /* _llseek */
# endif /* (GLIBC < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR < 1)) */
# include <sys/ioctl.h>		/* ioctl */
# ifndef HDIO_GETGEO
#  define HDIO_GETGEO	0x0301	/* get device geometry */
/* If HDIO_GETGEO is not defined, it is unlikely that hd_geometry is
   defined.  */
struct hd_geometry
{
  unsigned char heads;
  unsigned char sectors;
  unsigned short cylinders;
  unsigned long start;
};
# endif /* ! HDIO_GETGEO */
# ifndef FLOPPY_MAJOR
#  define FLOPPY_MAJOR	2	/* the major number for floppy */
# endif /* ! FLOPPY_MAJOR */
# ifndef MAJOR
#  define MAJOR(dev)	\
  ({ \
     unsigned long long __dev = (dev); \
     (unsigned) ((__dev >> 8) & 0xfff) \
                 | ((unsigned int) (__dev >> 32) & ~0xfff); \
  })
# endif /* ! MAJOR */
# ifndef CDROM_GET_CAPABILITY
#  define CDROM_GET_CAPABILITY	0x5331	/* get capabilities */
# endif /* ! CDROM_GET_CAPABILITY */
# ifndef BLKGETSIZE
#  define BLKGETSIZE	_IO(0x12,96)	/* return device size */
# endif /* ! BLKGETSIZE */
#endif /* __linux__ */

/* Use __FreeBSD_kernel__ instead of __FreeBSD__ for compatibility with
   kFreeBSD-based non-FreeBSD systems (e.g. GNU/kFreeBSD) */
#if defined(__FreeBSD__) && ! defined(__FreeBSD_kernel__)
# define __FreeBSD_kernel__
#endif
#ifdef __FreeBSD_kernel__
  /* Obtain version of kFreeBSD headers */
# include <osreldate.h>
# ifndef __FreeBSD_kernel_version
#  define __FreeBSD_kernel_version __FreeBSD_version
# endif

  /* Runtime detection of kernel */
# include <sys/utsname.h>
int
get_kfreebsd_version ()
{
  struct utsname uts;
  int major; int minor, v[2];

  uname (&uts);
  sscanf (uts.release, "%d.%d", &major, &minor);

  if (major >= 9)
    major = 9;
  if (major >= 5)
    {
      v[0] = minor/10; v[1] = minor%10;
    }
  else
    {
      v[0] = minor%10; v[1] = minor/10;
    }
  return major*100000+v[0]*10000+v[1]*1000;
}
#endif /* __FreeBSD_kernel__ */

#if defined(__FreeBSD_kernel__) || defined(__NetBSD__) || defined(__OpenBSD__)
# include <sys/ioctl.h>		/* ioctl */
# include <sys/disklabel.h>
# include <sys/cdio.h>		/* CDIOCCLRDEBUG */
# if defined(__FreeBSD_kernel__)
#  include <sys/param.h>
#  if __FreeBSD_kernel_version >= 500040
#   include <sys/disk.h>
#  endif
# endif /* __FreeBSD_kernel__ */
#endif /* __FreeBSD_kernel__ || __NetBSD__ || __OpenBSD__ */

#if defined(__sun)
# include <sys/dkio.h>
#endif /* __sun */

#ifdef HAVE_OPENDISK
# include <util.h>
#endif /* HAVE_OPENDISK */

#define WITHOUT_LIBC_STUBS	1
#include <shared.h>
#include <device.h>

/* Get the geometry of a drive DRIVE.  */
void
get_drive_geometry (struct geometry *geom, char **map, int drive)
{
  int fd;

  if (geom->flags == -1)
    {
      fd = open (map[drive], O_RDONLY);
      assert (fd >= 0);
    }
  else
    fd = geom->flags;

  /* XXX This is the default size.  */
  geom->sector_size = SECTOR_SIZE;
  
#if defined(__linux__)
  /* Linux */
  {
    struct hd_geometry hdg;
    unsigned long nr;
    
    if (ioctl (fd, HDIO_GETGEO, &hdg))
      goto fail;

    if (ioctl (fd, BLKGETSIZE, &nr))
      goto fail;
    
    /* Got the geometry, so save it. */
    geom->cylinders = hdg.cylinders;
    geom->heads = hdg.heads;
    geom->sectors = hdg.sectors;
    geom->total_sectors = nr;
    
    goto success;
  }

#elif defined(__FreeBSD_kernel__) || defined(__NetBSD__) || defined(__OpenBSD__)
# if defined(__FreeBSD_kernel__) && __FreeBSD_kernel_version >= 500040
  /* kFreeBSD version 5 or later */
  if (get_kfreebsd_version () >= 500040)
  {
    unsigned int sector_size;
    off_t media_size;
    unsigned int tmp;
    
    if(ioctl (fd, DIOCGSECTORSIZE, &sector_size) != 0)
      sector_size = 512;
    
    if (ioctl (fd, DIOCGMEDIASIZE, &media_size) != 0)
      goto fail;

    geom->total_sectors = media_size / sector_size;
    
    if (ioctl (fd, DIOCGFWSECTORS, &tmp) == 0)
      geom->sectors = tmp;
    else
      geom->sectors = 63;
    if (ioctl (fd, DIOCGFWHEADS, &tmp) == 0)
      geom->heads = tmp;
    else if (geom->total_sectors <= 63 * 1 * 1024)
      geom->heads = 1;
    else if (geom->total_sectors <= 63 * 16 * 1024)
      geom->heads = 16;
    else
      geom->heads = 255;

    geom->cylinders = (geom->total_sectors
			   / geom->heads
			   / geom->sectors);
    
    goto success;
  }
  else
#endif /* defined(__FreeBSD_kernel__) && __FreeBSD_kernel_version >= 500040 */

  /* kFreeBSD < 5, NetBSD or OpenBSD */
  {
    struct disklabel hdg;
    if (ioctl (fd, DIOCGDINFO, &hdg))
      goto fail;
    
    geom->cylinders = hdg.d_ncylinders;
    geom->heads = hdg.d_ntracks;
    geom->sectors = hdg.d_nsectors;
    geom->total_sectors = hdg.d_secperunit;

    goto success;
  }
  
#elif defined(__sun)
  /* Solaris */
  {
    struct dk_geom dkg;

    if (ioctl(fd, DKIOCG_PHYGEOM, &dkg))
      goto fail;
    geom->cylinders = dkg.dkg_ncyl;
    geom->heads = dkg.dkg_nhead;
    geom->sectors = dkg.dkg_nsect;
    geom->total_sectors = dkg.dkg_ncyl * dkg.dkg_nhead * dkg.dkg_nsect;

    goto success;
  }

#else
  /* Notably, defined(__GNU__) */
# warning "Automatic detection of geometries will be performed only \
partially. This is not fatal."
#endif

 fail:
  {
    struct stat st;

    /* FIXME: It would be nice to somehow compute fake C/H/S settings,
       given a proper st_blocks size. */
    if (drive & 0x80)
      {
	geom->cylinders = DEFAULT_HD_CYLINDERS;
	geom->heads = DEFAULT_HD_HEADS;
	geom->sectors = DEFAULT_HD_SECTORS;
      }
    else
      {
	geom->cylinders = DEFAULT_FD_CYLINDERS;
	geom->heads = DEFAULT_FD_HEADS;
	geom->sectors = DEFAULT_FD_SECTORS;
      }

    /* Set the total sectors properly, if we can. */
    if (! fstat (fd, &st) && st.st_blocks)
      geom->total_sectors = st.st_blocks >> SECTOR_BITS;
    else
      geom->total_sectors = geom->cylinders * geom->heads * geom->sectors;
  }

 success:
  if (geom->flags == -1)
    close (fd);
}

#ifdef __linux__
/* Check if we have devfs support.  */
static int
have_devfs (void)
{
  static int dev_devfsd_exists = -1;
  
  if (dev_devfsd_exists < 0)
    {
      struct stat st;
      
      dev_devfsd_exists = stat ("/dev/.devfsd", &st) == 0;
    }
  
  return dev_devfsd_exists;
}
#endif /* __linux__ */

/* These three functions are quite different among OSes.  */
static void
get_floppy_disk_name (char *name, int unit)
{
#if defined(__linux__)
  /* GNU/Linux */
  if (have_devfs ())
    sprintf (name, "/dev/floppy/%d", unit);
  else
    sprintf (name, "/dev/fd%d", unit);
#elif defined(__GNU__)
  /* GNU/Hurd */
  sprintf (name, "/dev/fd%d", unit);
#elif defined(__FreeBSD_kernel__)
  /* kFreeBSD */
  if (get_kfreebsd_version () >= 400000)
    sprintf (name, "/dev/fd%d", unit);
  else
    sprintf (name, "/dev/rfd%d", unit);
#elif defined(__NetBSD__)
  /* NetBSD */
  /* opendisk() doesn't work for floppies.  */
  sprintf (name, "/dev/rfd%da", unit);
#elif defined(__OpenBSD__)
  /* OpenBSD */
  sprintf (name, "/dev/rfd%dc", unit);
#elif defined(__QNXNTO__)
  /* QNX RTP */
  sprintf (name, "/dev/fd%d", unit);
#elif defined(__sun)
  /* Solaris */
  sprintf (name, "/dev/rdiskette%d", unit);
#else
# warning "BIOS floppy drives cannot be guessed in your operating system."
  /* Set NAME to a bogus string.  */
  *name = 0;
#endif
}

static void
get_ide_disk_name (char *name, int unit)
{
#if defined(__linux__)
  /* GNU/Linux */
  sprintf (name, "/dev/hd%c", unit + 'a');
#elif defined(__GNU__)
  /* GNU/Hurd */
  sprintf (name, "/dev/hd%d", unit);
#elif defined(__FreeBSD_kernel__)
  /* kFreeBSD */
  if (get_kfreebsd_version () >= 400000)
    sprintf (name, "/dev/ad%d", unit);
  else
    sprintf (name, "/dev/rwd%d", unit);
#elif defined(__NetBSD__) && defined(HAVE_OPENDISK)
  /* NetBSD */
  char shortname[16];
  int fd;
  
  sprintf (shortname, "wd%d", unit);
  fd = opendisk (shortname, O_RDONLY, name,
		 16,	/* length of NAME */
		 0	/* char device */
		 );
  close (fd);
#elif defined(__OpenBSD__)
  /* OpenBSD */
  sprintf (name, "/dev/rwd%dc", unit);
#elif defined(__QNXNTO__)
  /* QNX RTP */
  /* Actually, QNX RTP doesn't distinguish IDE from SCSI, so this could
     contain SCSI disks.  */
  sprintf (name, "/dev/hd%d", unit);
#elif defined(__sun)
  *name = 0;		/* FIXME */
#else
# warning "BIOS IDE drives cannot be guessed in your operating system."
  /* Set NAME to a bogus string.  */
  *name = 0;
#endif
}

static void
get_scsi_disk_name (char *name, int unit)
{
#if defined(__linux__)
  /* GNU/Linux */
  sprintf (name, "/dev/sd%c", unit + 'a');
#elif defined(__GNU__)
  /* GNU/Hurd */
  sprintf (name, "/dev/sd%d", unit);
#elif defined(__FreeBSD_kernel__)
  /* kFreeBSD */
  if (get_kfreebsd_version () >= 400000)
    sprintf (name, "/dev/da%d", unit);
  else
    sprintf (name, "/dev/rda%d", unit);
#elif defined(__NetBSD__) && defined(HAVE_OPENDISK)
  /* NetBSD */
  char shortname[16];
  int fd;
  
  sprintf (shortname, "sd%d", unit);
  fd = opendisk (shortname, O_RDONLY, name,
		 16,	/* length of NAME */
		 0	/* char device */
		 );
  close (fd);
#elif defined(__OpenBSD__)
  /* OpenBSD */
  sprintf (name, "/dev/rsd%dc", unit);
#elif defined(__QNXNTO__)
  /* QNX RTP */
  /* QNX RTP doesn't distinguish SCSI from IDE, so it is better to
     disable the detection of SCSI disks here.  */
  *name = 0;
#elif defined(__sun)
  *name = 0;		/* FIXME */
#else
# warning "BIOS SCSI drives cannot be guessed in your operating system."
  /* Set NAME to a bogus string.  */
  *name = 0;
#endif
}

#ifdef __linux__
static void
get_dac960_disk_name (char *name, int controller, int drive)
{
  sprintf (name, "/dev/rd/c%dd%d", controller, drive);
}

static void
get_ataraid_disk_name (char *name, int unit)
{
  sprintf (name, "/dev/ataraid/d%c", unit + '0');
}
#endif

/* Check if DEVICE can be read. If an error occurs, return zero,
   otherwise return non-zero.  */
int
check_device (const char *device)
{
  char buf[512];
  FILE *fp;

  /* If DEVICE is empty, just return 1.  */
  if (*device == 0)
    return 1;
  
  fp = fopen (device, "r");
  if (! fp)
    {
      switch (errno)
	{
#ifdef ENOMEDIUM
	case ENOMEDIUM:
# if 0
	  /* At the moment, this finds only CDROMs, which can't be
	     read anyway, so leave it out. Code should be
	     reactivated if `removable disks' and CDROMs are
	     supported.  */
	  /* Accept it, it may be inserted.  */
	  return 1;
# endif
	  break;
#endif /* ENOMEDIUM */
	default:
	  /* Break case and leave.  */
	  break;
	}
      /* Error opening the device.  */
      return 0;
    }
  
  /* Make sure CD-ROMs don't get assigned a BIOS disk number 
     before SCSI disks!  */
#ifdef __linux__
# ifdef CDROM_GET_CAPABILITY
  if (ioctl (fileno (fp), CDROM_GET_CAPABILITY, 0) >= 0)
    return 0;
# else /* ! CDROM_GET_CAPABILITY */
  /* Check if DEVICE is a CD-ROM drive by the HDIO_GETGEO ioctl.  */
  {
    struct hd_geometry hdg;
    struct stat st;

    if (fstat (fileno (fp), &st))
      return 0;

    /* If it is a block device and isn't a floppy, check if HDIO_GETGEO
       succeeds.  */
    if (S_ISBLK (st.st_mode)
	&& MAJOR (st.st_rdev) != FLOPPY_MAJOR
	&& ioctl (fileno (fp), HDIO_GETGEO, &hdg))
      return 0;
  }
# endif /* ! CDROM_GET_CAPABILITY */
#endif /* __linux__ */

#if defined(__FreeBSD_kernel__) || defined(__NetBSD__) || defined(__OpenBSD__)
# ifdef CDIOCCLRDEBUG
  if (ioctl (fileno (fp), CDIOCCLRDEBUG, 0) >= 0)
    return 0;
# endif /* CDIOCCLRDEBUG */
#endif /* __FreeBSD_kernel__ || __NetBSD__ || __OpenBSD__ */
  
  /* Attempt to read the first sector.  */
  if (fread (buf, 1, 512, fp) != 512)
    {
      fclose (fp);
      return 0;
    }
  
  fclose (fp);
  return 1;
}

/* Read mapping information from FP, and write it to MAP.  */
static int
read_device_map (FILE *fp, char **map, const char *map_file)
{
  auto void show_error (int no, const char *msg);
  auto void show_warning (int no, const char *msg, ...);

  auto void show_error (int no, const char *msg)
    {
      fprintf (stderr, "%s:%d: error: %s\n", map_file, no, msg);
    }
  
  auto void show_warning (int no, const char *msg, ...)
    {
      va_list ap;
      
      va_start (ap, msg);
      fprintf (stderr, "%s:%d: warning: ", map_file, no);
      vfprintf (stderr, msg, ap);
      va_end (ap);
    }
  
  /* If there is the device map file, use the data in it instead of
     probing devices.  */
  char buf[1024];		/* XXX */
  int line_number = 0;
  
  while (fgets (buf, sizeof (buf), fp))
    {
      char *ptr, *eptr;
      int drive;
      int is_floppy = 0;
      
      /* Increase the number of lines.  */
      line_number++;
      
      /* If the first character is '#', skip it.  */
      if (buf[0] == '#')
	continue;
      
      ptr = buf;
      /* Skip leading spaces.  */
      while (*ptr && isspace (*ptr))
	ptr++;

      /* Skip empty lines.  */
      if (! *ptr)
	continue;
      
      if (*ptr != '(')
	{
	  show_error (line_number, "No open parenthesis found");
	  return 0;
	}
      
      ptr++;
      if ((*ptr != 'f' && *ptr != 'h') || *(ptr + 1) != 'd')
	{
	  show_error (line_number, "Bad drive name");
	  return 0;
	}
      
      if (*ptr == 'f')
	is_floppy = 1;
      
      ptr += 2;
      drive = strtoul (ptr, &ptr, 10);
      if (drive < 0)
	{
	  show_error (line_number, "Bad device number");
	  return 0;
	}
      else if (drive > 127)
	{
	  show_warning (line_number,
			"Ignoring %cd%d due to a BIOS limitation",
			is_floppy ? 'f' : 'h', drive);
	  continue;
	}
      
      if (! is_floppy)
	drive += 0x80;
      
      if (*ptr != ')')
	{
	  show_error (line_number, "No close parenthesis found");
	  return 0;
	}
      
      ptr++;
      /* Skip spaces.  */
      while (*ptr && isspace (*ptr))
	ptr++;
      
      if (! *ptr)
	{
	  show_error (line_number, "No filename found");
	  return 0;
	}
      
      /* Terminate the filename.  */
      eptr = ptr;
      while (*eptr && ! isspace (*eptr))
	eptr++;
      *eptr = 0;

      /* Multiple entries for a given drive is not allowed.  */
      if (map[drive])
	{
	  show_error (line_number, "Duplicated entry found");
	  return 0;
	}
      
      map[drive] = strdup (ptr);
      assert (map[drive]);
    }
  
  return 1;
}

/* Initialize the device map MAP. *MAP will be allocated from the heap
   space. If MAP_FILE is not NULL, then read mappings from the file
   MAP_FILE if it exists, otherwise, write guessed mappings to the file.
   FLOPPY_DISKS is the number of floppy disk drives which will be probed.
   If it is zero, don't probe any floppy at all. If it is one, probe one
   floppy. If it is two, probe two floppies. And so on.  */
int
init_device_map (char ***map, const char *map_file, int floppy_disks)
{
  int i;
  int num_hd = 0;
  FILE *fp = 0;

  assert (map);
  assert (*map == 0);
  *map = malloc (NUM_DISKS * sizeof (char *));
  assert (*map);
  
  /* Probe devices for creating the device map.  */
  
  /* Initialize DEVICE_MAP.  */
  for (i = 0; i < NUM_DISKS; i++)
    (*map)[i] = 0;
  
  if (map_file)
    {
      /* Open the device map file.  */
      fp = fopen (map_file, "r");
      if (fp)
	{
	  int ret;

	  ret = read_device_map (fp, *map, map_file);
	  fclose (fp);
	  return ret;
	}
    }
  
  /* Print something so that the user does not think GRUB has been
     crashed.  */
  fprintf (stderr,
	   "Probing devices to guess BIOS drives. "
	   "This may take a long time.\n");
  
  if (map_file)
    /* Try to open the device map file to write the probed data.  */
    fp = fopen (map_file, "w");
  
  /* Floppies.  */
  for (i = 0; i < floppy_disks; i++)
    {
      char name[16];
      
      get_floppy_disk_name (name, i);
      /* In floppies, write the map, whether check_device succeeds
	 or not, because the user just does not insert floppies.  */
      if (fp)
	fprintf (fp, "(fd%d)\t%s\n", i, name);
      
      if (check_device (name))
	{
	  (*map)[i] = strdup (name);
	  assert ((*map)[i]);
	}
    }
  
#ifdef __linux__
  if (have_devfs ())
    {
      while (1)
	{
	  char discn[32];
	  char name[PATH_MAX];
	  struct stat st;

	  /* Linux creates symlinks "/dev/discs/discN" for convenience.
	     The way to number disks is the same as GRUB's.  */
	  sprintf (discn, "/dev/discs/disc%d", num_hd);
	  if (stat (discn, &st) < 0)
	    break;
	  
	  if (realpath (discn, name))
	    {
	      strcat (name, "/disc");
	      (*map)[num_hd + 0x80] = strdup (name);
	      assert ((*map)[num_hd + 0x80]);
	      
	      /* If the device map file is opened, write the map.  */
	      if (fp)
		fprintf (fp, "(hd%d)\t%s\n", num_hd, name);
	    }
	  
	  num_hd++;
	}
      
      /* OK, close the device map file if opened.  */
      if (fp)
	fclose (fp);
      
      return 1;
    }
#endif /* __linux__ */
    
  /* IDE disks.  */
  for (i = 0; i < 8; i++)
    {
      char name[16];
      
      get_ide_disk_name (name, i);
      if (check_device (name))
	{
	  (*map)[num_hd + 0x80] = strdup (name);
	  assert ((*map)[num_hd + 0x80]);
	  
	  /* If the device map file is opened, write the map.  */
	  if (fp)
	    fprintf (fp, "(hd%d)\t%s\n", num_hd, name);
	  
	  num_hd++;
	}
    }
  
#ifdef __linux__
  /* ATARAID disks.  */
  for (i = 0; i < 8; i++)
    {
      char name[20];

      get_ataraid_disk_name (name, i);
      if (check_device (name))
        {
          (*map)[num_hd + 0x80] = strdup (name);
          assert ((*map)[num_hd + 0x80]);

          /* If the device map file is opened, write the map.  */
          if (fp)
            fprintf (fp, "(hd%d)\t%s\n", num_hd, name);

          num_hd++;
        }
    }
#endif /* __linux__ */

  /* The rest is SCSI disks.  */
  for (i = 0; i < 16; i++)
    {
      char name[16];
      
      get_scsi_disk_name (name, i);
      if (check_device (name))
	{
	  (*map)[num_hd + 0x80] = strdup (name);
	  assert ((*map)[num_hd + 0x80]);
	  
	  /* If the device map file is opened, write the map.  */
	  if (fp)
	    fprintf (fp, "(hd%d)\t%s\n", num_hd, name);
	  
	  num_hd++;
	}
    }
  
#ifdef __linux__
  /* This is for DAC960 - we have
     /dev/rd/c<controller>d<logical drive>p<partition>.
     
     DAC960 driver currently supports up to 8 controllers, 32 logical
     drives, and 7 partitions.  */
  {
    int controller, drive;
    
    for (controller = 0; controller < 8; controller++)
      {
	for (drive = 0; drive < 15; drive++)
	  {
	    char name[24];
	    
	    get_dac960_disk_name (name, controller, drive);
	    if (check_device (name))
	      {
		(*map)[num_hd + 0x80] = strdup (name);
		assert ((*map)[num_hd + 0x80]);
		
		/* If the device map file is opened, write the map.  */
		if (fp)
		  fprintf (fp, "(hd%d)\t%s\n", num_hd, name);
		
		num_hd++;
	      }
	  }
      }
  }
#endif /* __linux__ */
  
  /* OK, close the device map file if opened.  */
  if (fp)
    fclose (fp);

  return 1;
}

/* Restore the memory consumed for MAP.  */
void
restore_device_map (char **map)
{
  int i;

  for (i = 0; i < NUM_DISKS; i++)
    if (map[i])
      free (map[i]);

  free (map);
}

#ifdef __linux__
/* Linux-only functions, because Linux has a bug that the disk cache for
   a whole disk is not consistent with the one for a partition of the
   disk.  */
int
is_disk_device (char **map, int drive)
{
  struct stat st;
  
  assert (map[drive] != 0);
  assert (stat (map[drive], &st) == 0);
  /* For now, disk devices under Linux are all block devices.  */
  return S_ISBLK (st.st_mode);
}

int
write_to_partition (char **map, int drive, int partition,
		    int sector, int size, const char *buf)
{
  char dev[PATH_MAX];	/* XXX */
  int fd;
  
  if ((partition & 0x00FF00) != 0x00FF00)
    {
      /* If the partition is a BSD partition, it is difficult to
	 obtain the representation in Linux. So don't support that.  */
      errnum = ERR_DEV_VALUES;
      return 1;
    }
  
  assert (map[drive] != 0);
  
  strcpy (dev, map[drive]);
  if (have_devfs ())
    {
      if (strcmp (dev + strlen(dev) - 5, "/disc") == 0)
	strcpy (dev + strlen(dev) - 5, "/part");
    }
  sprintf (dev + strlen(dev), "%d", ((partition >> 16) & 0xFF) + 1);
  
  /* Open the partition.  */
  fd = open (dev, O_RDWR);
  if (fd < 0)
    {
      errnum = ERR_NO_PART;
      return 0;
    }
  
#if defined(__linux__) && (!defined(__GLIBC__) || \
        ((__GLIBC__ < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ < 1))))
  /* Maybe libc doesn't have large file support.  */
  {
    loff_t offset, result;
    static int _llseek (uint filedes, ulong hi, ulong lo,
                        loff_t *res, uint wh);
    _syscall5 (int, _llseek, uint, filedes, ulong, hi, ulong, lo,
               loff_t *, res, uint, wh);

    offset = (loff_t) sector * (loff_t) SECTOR_SIZE;
    if (_llseek (fd, offset >> 32, offset & 0xffffffff, &result, SEEK_SET))
      {
	errnum = ERR_DEV_VALUES;
	return 0;
      }
  }
#else
  {
    off_t offset = (off_t) sector * (off_t) SECTOR_SIZE;

    if (lseek (fd, offset, SEEK_SET) != offset)
      {
	errnum = ERR_DEV_VALUES;
	return 0;
      }
  }
#endif
  
  if (write (fd, buf, size * SECTOR_SIZE) != (size * SECTOR_SIZE))
    {
      close (fd);
      errnum = ERR_WRITE;
      return 0;
    }
  
  sync ();	/* Paranoia.  */
  close (fd);
  
  return 1;
}
#endif /* __linux__ */
