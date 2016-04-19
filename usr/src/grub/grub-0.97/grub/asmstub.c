/* asmstub.c - a version of shared_src/asm.S that works under Unix */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2004  Free Software Foundation, Inc.
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

/* Try to use glibc's transparant LFS support. */
#define _LARGEFILE_SOURCE	1
/* lseek becomes synonymous with lseek64.  */
#define _FILE_OFFSET_BITS	64

/* Simulator entry point. */
int grub_stage2 (void);

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <setjmp.h>
#include <sys/time.h>
#include <termios.h>
#include <signal.h>

#ifdef __linux__
# include <sys/ioctl.h>		/* ioctl */
# if !defined(__GLIBC__) || \
	((__GLIBC__ < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ < 1)))
/* Maybe libc doesn't have large file support.  */
#  include <linux/unistd.h>	/* _llseek */
# endif /* (GLIBC < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR < 1)) */
# ifndef BLKFLSBUF
#  define BLKFLSBUF	_IO (0x12,97)	/* flush buffer cache */
# endif /* ! BLKFLSBUF */
#endif /* __linux__ */

/* We want to prevent any circularararity in our stubs, as well as
   libc name clashes. */
#define WITHOUT_LIBC_STUBS 1
#include <shared.h>
#include <device.h>
#include <serial.h>
#include <term.h>

/* Simulated memory sizes. */
#define EXTENDED_MEMSIZE (64 * 1024 * 1024)	/* 64MB */
#define CONVENTIONAL_MEMSIZE (640 * 1024)	/* 640kB */

unsigned long install_partition = 0x20000;
unsigned long boot_drive = 0;
int saved_entryno = 0;
char version_string[] = VERSION;
char config_file[128] = "/boot/grub/menu.lst"; /* FIXME: arbitrary */
unsigned long linux_text_len = 0;
char *linux_data_tmp_addr = 0;
char *linux_data_real_addr = 0;
unsigned short io_map[IO_MAP_SIZE];
struct apm_info apm_bios_info;

/* Emulation requirements. */
char *grub_scratch_mem = 0;

struct geometry *disks = 0;

/* The map between BIOS drives and UNIX device file names.  */
char **device_map = 0;

/* The jump buffer for exiting correctly.  */
static jmp_buf env_for_exit;

/* The current color for console.  */
int console_current_color = A_NORMAL;

/* The file descriptor for a serial device.  */
static int serial_fd = -1;

/* The file name of a serial device.  */
static char *serial_device = 0;

#ifdef SIMULATE_SLOWNESS_OF_SERIAL
/* The speed of a serial device.  */
static unsigned int serial_speed;
#endif /* SIMULATE_SLOWNESS_OF_SERIAL */

/* The main entry point into this mess. */
int
grub_stage2 (void)
{
  /* These need to be static, because they survive our stack transitions. */
  static int status = 0;
  static char *realstack;
  char *scratch, *simstack;
  int i;

  auto void doit (void);

  /* We need a nested function so that we get a clean stack frame,
     regardless of how the code is optimized. */
  void doit ()
    {
      /* Make sure our stack lives in the simulated memory area. */
      asm volatile ("movl %%esp, %0\n\tmovl %1, %%esp\n"
		    : "=&r" (realstack) : "r" (simstack));

      /* Do a setjmp here for the stop command.  */
      if (! setjmp (env_for_exit))
	{
	  /* Actually enter the generic stage2 code.  */
	  status = 0;
	  init_bios_info ();
	}
      else
	{
	  /* If ERRNUM is non-zero, then set STATUS to non-zero.  */
	  if (errnum)
	    status = 1;
	}

      /* Replace our stack before we use any local variables. */
      asm volatile ("movl %0, %%esp\n" : : "r" (realstack));
    }

  assert (grub_scratch_mem == 0);
  scratch = malloc (0x100000 + EXTENDED_MEMSIZE + 15);
  assert (scratch);
  grub_scratch_mem = (char *) ((((int) scratch) >> 4) << 4);

  /* FIXME: simulate the memory holes using mprot, if available. */

  assert (disks == 0);
  disks = malloc (NUM_DISKS * sizeof (*disks));
  assert (disks);
  /* Initialize DISKS.  */
  for (i = 0; i < NUM_DISKS; i++)
    disks[i].flags = -1;

  if (! init_device_map (&device_map, device_map_file, floppy_disks))
    return 1;
  
  /* Check some invariants. */
  assert ((SCRATCHSEG << 4) == SCRATCHADDR);
  assert ((BUFFERSEG << 4) == BUFFERADDR);
  assert (BUFFERADDR + BUFFERLEN == SCRATCHADDR);
  assert (FSYS_BUF % 16 == 0);
  assert (FSYS_BUF + FSYS_BUFLEN == BUFFERADDR);

#ifdef HAVE_LIBCURSES
  /* Get into char-at-a-time mode. */
  if (use_curses)
    {
      initscr ();
      cbreak ();
      noecho ();
      nonl ();
      scrollok (stdscr, TRUE);
      keypad (stdscr, TRUE);
      wtimeout (stdscr, 100);
      signal (SIGWINCH, SIG_IGN);
    }
#endif

  /* Make sure that actual writing is done.  */
  sync ();

  /* Set our stack, and go for it. */
  simstack = (char *) PROTSTACKINIT;
  doit ();

  /* I don't know if this is necessary really.  */
  sync ();

#ifdef HAVE_LIBCURSES
  if (use_curses)
    endwin ();
#endif

  /* Close off the file descriptors we used. */
  for (i = 0; i < NUM_DISKS; i ++)
    if (disks[i].flags != -1)
      {
#ifdef __linux__
	/* In Linux, invalidate the buffer cache. In other OSes, reboot
	   is one of the solutions...  */
	ioctl (disks[i].flags, BLKFLSBUF, 0);
#elif defined(__sun)
	/* FIXME */
#else
# warning "In your operating system, the buffer cache will not be flushed."
#endif
	close (disks[i].flags);
      }

  if (serial_fd >= 0)
    close (serial_fd);
  
  /* Release memory. */
  restore_device_map (device_map);
  device_map = 0;
  free (disks);
  disks = 0;
  free (scratch);
  grub_scratch_mem = 0;

  if (serial_device)
    free (serial_device);
  serial_device = 0;
  
  /* Ahh... at last we're ready to return to caller. */
  return status;
}

/* Assign DRIVE to a device name DEVICE.  */
void
assign_device_name (int drive, const char *device)
{
  /* If DRIVE is already assigned, free it.  */
  if (device_map[drive])
    free (device_map[drive]);

  /* If the old one is already opened, close it.  */
  if (disks[drive].flags != -1)
    {
      close (disks[drive].flags);
      disks[drive].flags = -1;
    }

  /* Assign DRIVE to DEVICE.  */
  if (! device)
    device_map[drive] = 0;
  else
    device_map[drive] = strdup (device);
}

void
stop (void)
{
#ifdef HAVE_LIBCURSES
  if (use_curses)
    endwin ();
#endif

  /* Jump to doit.  */
  longjmp (env_for_exit, 1);
}

void
grub_reboot (void)
{
  stop ();
}

void
grub_halt (int no_apm)
{
  stop ();
}

/* calls for direct boot-loader chaining */
void
chain_stage1 (unsigned long segment, unsigned long offset,
	      unsigned long part_table_addr)
{
  stop ();
}


void
chain_stage2 (unsigned long segment, unsigned long offset, int second_sector)
{
  stop ();
}


/* do some funky stuff, then boot linux */
void
linux_boot (void)
{
  stop ();
}


/* For bzImage kernels. */
void
big_linux_boot (void)
{
  stop ();
}


/* booting a multiboot executable */
void
multi_boot (int start, int mb_info)
{
  stop ();
}

/* sets it to linear or wired A20 operation */
void
gateA20 (int linear)
{
  /* Nothing to do in the simulator. */
}

/* Set up the int15 handler.  */
void
set_int15_handler (void)
{
  /* Nothing to do in the simulator.  */
}

/* Restore the original int15 handler.  */
void
unset_int15_handler (void)
{
  /* Nothing to do in the simulator.  */
}

/* The key map.  */
unsigned short bios_key_map[KEY_MAP_SIZE + 1];
unsigned short ascii_key_map[KEY_MAP_SIZE + 1];

/* Copy MAP to the drive map and set up the int13 handler.  */
void
set_int13_handler (unsigned short *map)
{
  /* Nothing to do in the simulator.  */
}

int
get_code_end (void)
{
  /* Just return a little area for simulation. */
  return BOOTSEC_LOCATION + (60 * 1024);
}


/* memory probe routines */
int
get_memsize (int type)
{
  if (! type)
    return CONVENTIONAL_MEMSIZE >> 10;
  else
    return EXTENDED_MEMSIZE >> 10;
}


/* get_eisamemsize() :  return packed EISA memory map, lower 16 bits is
 *		memory between 1M and 16M in 1K parts, upper 16 bits is
 *		memory above 16M in 64K parts.  If error, return -1.
 */
int
get_eisamemsize (void)
{
  return (EXTENDED_MEMSIZE >> 10);
}


#define MMAR_DESC_TYPE_AVAILABLE 1 /* available to OS */
#define MMAR_DESC_TYPE_RESERVED 2 /* not available */
#define MMAR_DESC_TYPE_ACPI_RECLAIM 3 /* usable by OS after reading ACPI */
#define MMAR_DESC_TYPE_ACPI_NVS 4 /* required to save between NVS sessions */

#define MMAR_DESC_LENGTH	20

/* Fetch the next entry in the memory map and return the continuation
   value.  DESC is a pointer to the descriptor buffer, and CONT is the
   previous continuation value (0 to get the first entry in the
   map).  */
int
get_mmap_entry (struct mmar_desc *desc, int cont)
{
  /* Record the memory map statically.  */
  static struct mmar_desc desc_table[] =
  {
    /* The conventional memory.  */
    {
      MMAR_DESC_LENGTH,
      0,
      CONVENTIONAL_MEMSIZE,
      MMAR_DESC_TYPE_AVAILABLE
    },
    /* BIOS RAM and ROM (such as video memory).  */
    {
      MMAR_DESC_LENGTH,
      CONVENTIONAL_MEMSIZE,
      0x100000 - CONVENTIONAL_MEMSIZE,
      MMAR_DESC_TYPE_RESERVED
    },
    /* The extended memory.  */
    {
      MMAR_DESC_LENGTH,
      0x100000,
      EXTENDED_MEMSIZE,
      MMAR_DESC_TYPE_AVAILABLE
    }
  };
  
  int num = sizeof (desc_table) / sizeof (*desc_table);

  if (cont < 0 || cont >= num)
    {
      /* Should not happen.  */
      desc->desc_len = 0;
    }
  else
    {
      /* Copy the entry.  */
      *desc = desc_table[cont++];

      /* If the next entry exists, return the index.  */
      if (cont < num)
	return cont;
    }
  
  return 0;
}

/* Track the int13 handler.  */
void
track_int13 (int drive)
{
  /* Nothing to do in the simulator.  */
}

/* Get the ROM configuration table.  */
unsigned long
get_rom_config_table (void)
{
  return 0;
}

/* Get APM BIOS information.  */
void
get_apm_info (void)
{
  /* Nothing to do in the simulator.  */
}

/* Get VBE controller information.  */
int
get_vbe_controller_info (struct vbe_controller *controller)
{
  /* Always fails.  */
  return 0;
}

/* Get VBE mode information.  */
int
get_vbe_mode_info (int mode_number, struct vbe_mode *mode)
{
  /* Always fails.  */
  return 0;
}

/* Set VBE mode.  */
int
set_vbe_mode (int mode_number)
{
  /* Always fails.  */
  return 0;
}

/* low-level timing info */
int
getrtsecs (void)
{
  /* FIXME: exact value is not important, so just return time_t for now. */
  return time (0);
}

int
currticks (void)
{
  struct timeval tv;
  long csecs;
  int ticks_per_csec, ticks_per_usec;

  /* Note: 18.2 ticks/sec.  */

  /* Get current time.  */
  gettimeofday (&tv, 0);

  /* Compute centiseconds.  */
  csecs = tv.tv_sec / 10;

  /* Ticks per centisecond.  */
  ticks_per_csec = csecs * 182;

  /* Ticks per microsecond.  */
  ticks_per_usec = (((tv.tv_sec - csecs * 10) * 1000000 + tv.tv_usec)
		    * 182 / 10000000);

  /* Sum them.  */
  return ticks_per_csec + ticks_per_usec;
}

/* displays an ASCII character.  IBM displays will translate some
   characters to special graphical ones */
void
console_putchar (int c)
{
  /* Curses doesn't have VGA fonts.  */
  switch (c)
    {
    case DISP_UL:
      c = ACS_ULCORNER;
      break;
    case DISP_UR:
      c = ACS_URCORNER;
      break;
    case DISP_LL:
      c = ACS_LLCORNER;
      break;
    case DISP_LR:
      c = ACS_LRCORNER;
      break;
    case DISP_HORIZ:
      c = ACS_HLINE;
      break;
    case DISP_VERT:
      c = ACS_VLINE;
      break;
    case DISP_LEFT:
      c = ACS_LARROW;
      break;
    case DISP_RIGHT:
      c = ACS_RARROW;
      break;
    case DISP_UP:
      c = ACS_UARROW;
      break;
    case DISP_DOWN:
      c = ACS_DARROW;
      break;
    default:
      break;
    }

#ifdef HAVE_LIBCURSES
  if (use_curses)
    {
      /* In ncurses, a newline is treated badly, so we emulate it in our
	 own way.  */
      if (c == '\n')
	{
	  int x, y;

	  getyx (stdscr, y, x);
	  if (y + 1 == LINES)
	    scroll (stdscr);
	  else
	    move (y + 1, x);
	}
      else if (isprint (c))
	{
	  int x, y;

	  getyx (stdscr, y, x);
	  if (x + 1 == COLS)
	    {
	      console_putchar ('\r');
	      console_putchar ('\n');
	    }
	  addch (c | console_current_color);
	}
      else
	{
	  addch (c);
	}
      
#ifdef REFRESH_IMMEDIATELY
      refresh ();
#endif
    }
  else
#endif
    {
      /* CR is not used in Unix.  */
      if (c != '\r')
	putchar (c);
    }
}

/* The store for ungetch simulation. This is necessary, because
   ncurses-1.9.9g is still used in the world and its ungetch is
   completely broken.  */
#ifdef HAVE_LIBCURSES
static int save_char = ERR;
#endif

static int
console_translate_key (int c)
{
  switch (c)
    {
    case KEY_LEFT:
      return 2;
    case KEY_RIGHT:
      return 6;
    case KEY_UP:
      return 16;
    case KEY_DOWN:
      return 14;
    case KEY_DC:
      return 4;
    case KEY_BACKSPACE:
      return 8;
    case KEY_HOME:
      return 1;
    case KEY_END:
      return 5;
    case KEY_PPAGE:
      return 7;
    case KEY_NPAGE:
      return 3;
    default:
      break;
    }

  return c;
}

/* like 'getkey', but doesn't wait, returns -1 if nothing available */
int
console_checkkey (void)
{
#ifdef HAVE_LIBCURSES
  if (use_curses)
    {
      int c;

      /* Check for SAVE_CHAR. This should not be true, because this
	 means checkkey is called twice continuously.  */
      if (save_char != ERR)
	return save_char;

      c = getch ();
      /* If C is not ERR, then put it back in the input queue.  */
      if (c != ERR)
	save_char = c;
      return console_translate_key (c);
    }
#endif

  /* Just pretend they hit the space bar, then read the real key when
     they call getkey. */
  return ' ';
}

/* returns packed BIOS/ASCII code */
int
console_getkey (void)
{
  int c;

#ifdef HAVE_LIBCURSES
  if (use_curses)
    {
      /* If checkkey has already got a character, then return it.  */
      if (save_char != ERR)
	{
	  c = save_char;
	  save_char = ERR;
	  return console_translate_key (c);
	}

      wtimeout (stdscr, -1);
      c = getch ();
      wtimeout (stdscr, 100);
    }
  else
#endif
    c = getchar ();

  /* Quit if we get EOF. */
  if (c == -1)
    stop ();
  
  return console_translate_key (c);
}

/* returns packed values, LSB+1 is x, LSB is y */
int
console_getxy (void)
{
  int y, x;
#ifdef HAVE_LIBCURSES
  if (use_curses)
    getyx (stdscr, y, x);
  else
#endif
  y = x = 0;
  return (x << 8) | (y & 0xff);
}

void
console_gotoxy (int x, int y)
{
#ifdef HAVE_LIBCURSES
  if (use_curses)
    move (y, x);
#endif
}

/* low-level character I/O */
void
console_cls (void)
{
#ifdef HAVE_LIBCURSES
  if (use_curses)
    clear ();
#endif
}

void
console_setcolorstate (color_state state)
{
  console_current_color = 
    (state == COLOR_STATE_HIGHLIGHT) ? A_REVERSE : A_NORMAL;
}

void
console_setcolor (int normal_color, int highlight_color)
{
  /* Nothing to do.  */
}

int
console_setcursor (int on)
{
  return 1;
}

/* Low-level disk I/O.  Our stubbed version just returns a file
   descriptor, not the actual geometry. */
int
get_diskinfo (int drive, struct geometry *geometry)
{
  /* FIXME: this function is truly horrid.  We try opening the device,
     then severely abuse the GEOMETRY->flags field to pass a file
     descriptor to biosdisk.  Thank God nobody's looking at this comment,
     or my reputation would be ruined. --Gord */

  /* See if we have a cached device. */
  if (disks[drive].flags == -1)
    {
      /* The unpartitioned device name: /dev/XdX */
      char *devname = device_map[drive];
      char buf[512];

      if (! devname)
	return -1;

      if (verbose)
	grub_printf ("Attempt to open drive 0x%x (%s)\n",
		     drive, devname);

      /* Open read/write, or read-only if that failed. */
      if (! read_only)
	disks[drive].flags = open (devname, O_RDWR);

      if (disks[drive].flags == -1)
	{
	  if (read_only || errno == EACCES || errno == EROFS || errno == EPERM)
	    {
	      disks[drive].flags = open (devname, O_RDONLY);
	      if (disks[drive].flags == -1)
		{
		  assign_device_name (drive, 0);
		  return -1;
		}
	    }
	  else
	    {
	      assign_device_name (drive, 0);
	      return -1;
	    }
	}

      /* Attempt to read the first sector.  */
      if (read (disks[drive].flags, buf, 512) != 512)
	{
	  close (disks[drive].flags);
	  disks[drive].flags = -1;
	  assign_device_name (drive, 0);
	  return -1;
	}

      if (disks[drive].flags != -1)
	get_drive_geometry (&disks[drive], device_map, drive);
    }

  if (disks[drive].flags == -1)
    return -1;

#ifdef __linux__
  /* In Linux, invalidate the buffer cache, so that left overs
     from other program in the cache are flushed and seen by us */
  ioctl (disks[drive].flags, BLKFLSBUF, 0);
#endif

  *geometry = disks[drive];
  return 0;
}

/* Read LEN bytes from FD in BUF. Return less than or equal to zero if an
   error occurs, otherwise return LEN.  */
static int
nread (int fd, char *buf, size_t len)
{
  int size = len;

  while (len)
    {
      int ret = read (fd, buf, len);

      if (ret <= 0)
	{
	  if (errno == EINTR)
	    continue;
	  else
	    return ret;
	}

      len -= ret;
      buf += ret;
    }

  return size;
}

/* Write LEN bytes from BUF to FD. Return less than or equal to zero if an
   error occurs, otherwise return LEN.  */
static int
nwrite (int fd, char *buf, size_t len)
{
  int size = len;

  while (len)
    {
      int ret = write (fd, buf, len);

      if (ret <= 0)
	{
	  if (errno == EINTR)
	    continue;
	  else
	    return ret;
	}

      len -= ret;
      buf += ret;
    }

  return size;
}

/* Dump BUF in the format of hexadecimal numbers.  */
static void
hex_dump (void *buf, size_t size)
{
  /* FIXME: How to determine which length is readable?  */
#define MAX_COLUMN	70

  /* use unsigned char for numerical computations */
  unsigned char *ptr = buf;
  /* count the width of the line */
  int column = 0;
  /* how many bytes written */
  int count = 0;

  while (size > 0)
    {
      /* high 4 bits */
      int hi = *ptr >> 4;
      /* low 4 bits */
      int low = *ptr & 0xf;

      /* grub_printf does not handle prefix number, such as %2x, so
	 format the number by hand...  */
      grub_printf ("%x%x", hi, low);
      column += 2;
      count++;
      ptr++;
      size--;

      /* Insert space or newline with the interval 4 bytes.  */
      if (size != 0 && (count % 4) == 0)
	{
	  if (column < MAX_COLUMN)
	    {
	      grub_printf (" ");
	      column++;
	    }
	  else
	    {
	      grub_printf ("\n");
	      column = 0;
	    }
	}
    }

  /* Add a newline at the end for readability.  */
  grub_printf ("\n");
}

int
biosdisk (int subfunc, int drive, struct geometry *geometry,
	  unsigned long long sector, int nsec, int segment)
{
  char *buf;
  int fd = geometry->flags;

  /* Get the file pointer from the geometry, and make sure it matches. */
  if (fd == -1 || fd != disks[drive].flags)
    return BIOSDISK_ERROR_GEOMETRY;

  /* Seek to the specified location. */
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
      return -1;
  }
#else
  {
    off_t offset = (off_t) sector * (off_t) SECTOR_SIZE;

    if (lseek (fd, offset, SEEK_SET) != offset)
      return -1;
  }
#endif

  buf = (char *) (segment << 4);

  switch (subfunc)
    {
    case BIOSDISK_READ:
#ifdef __linux__
      if (sector == 0 && nsec > 1)
	{
	  /* Work around a bug in linux's ez remapping.  Linux remaps all
	     sectors that are read together with the MBR in one read.  It
	     should only remap the MBR, so we split the read in two 
	     parts. -jochen  */
	  if (nread (fd, buf, SECTOR_SIZE) != SECTOR_SIZE)
	    return -1;
	  buf += SECTOR_SIZE;
	  nsec--;
	}
#endif
      if (nread (fd, buf, nsec * SECTOR_SIZE) != nsec * SECTOR_SIZE)
	return -1;
      break;

    case BIOSDISK_WRITE:
      if (verbose)
	{
	  grub_printf ("Write %d sectors starting from %u sector"
		       " to drive 0x%x (%s)\n",
		       nsec, sector, drive, device_map[drive]);
	  hex_dump (buf, nsec * SECTOR_SIZE);
	}
      if (! read_only)
	if (nwrite (fd, buf, nsec * SECTOR_SIZE) != nsec * SECTOR_SIZE)
	  return -1;
      break;

    default:
      grub_printf ("unknown subfunc %d\n", subfunc);
      break;
    }

  return 0;
}


void
stop_floppy (void)
{
  /* NOTUSED */
}

/* Fetch a key from a serial device.  */
int
serial_hw_fetch (void)
{
  fd_set fds;
  struct timeval to;
  char c;

  /* Wait only for the serial device.  */
  FD_ZERO (&fds);
  FD_SET (serial_fd, &fds);

  to.tv_sec = 0;
  to.tv_usec = 0;
  
  if (select (serial_fd + 1, &fds, 0, 0, &to) > 0)
    {
      if (nread (serial_fd, &c, 1) != 1)
	stop ();

      return c;
    }
  
  return -1;
}

/* Put a character to a serial device.  */
void
serial_hw_put (int c)
{
  char ch = (char) c;
  
  if (nwrite (serial_fd, &ch, 1) != 1)
    stop ();
}

void
serial_hw_delay (void)
{
#ifdef SIMULATE_SLOWNESS_OF_SERIAL
  struct timeval otv, tv;

  gettimeofday (&otv, 0);

  while (1)
    {
      long delta;
      
      gettimeofday (&tv, 0);
      delta = tv.tv_usec - otv.tv_usec;
      if (delta < 0)
	delta += 1000000;
      
      if (delta >= 1000000 / (serial_speed >> 3))
	break;
    }
#endif /* SIMULATE_SLOWNESS_OF_SERIAL */
}

static speed_t
get_termios_speed (int speed)
{
  switch (speed)
    {
    case 2400: return B2400;
    case 4800: return B4800;
    case 9600: return B9600;
    case 19200: return B19200;
    case 38400: return B38400;
#ifdef B57600
    case 57600: return B57600;
#endif
#ifdef B115200      
    case 115200: return B115200;
#endif
    }

  return B0;
}

/* Get the port number of the unit UNIT. In the grub shell, this doesn't
   make sense.  */
unsigned short
serial_hw_get_port (int unit)
{
  return 0;
}

/* Initialize a serial device. In the grub shell, PORT is unused.  */
int
serial_hw_init (unsigned short port, unsigned int speed,
		int word_len, int parity, int stop_bit_len)
{
  struct termios termios;
  speed_t termios_speed;
  int i;
  
  /* Check if the file name is specified.  */
  if (! serial_device)
    return 0;

  /* If a serial device is already opened, close it first.  */
  if (serial_fd >= 0)
    close (serial_fd);
  
  /* Open the device file.  */
  serial_fd = open (serial_device,
		    O_RDWR | O_NOCTTY
#if defined(O_SYNC)
		    /* O_SYNC is used in Linux (and some others?).  */
		    | O_SYNC
#elif defined(O_FSYNC)
		    /* O_FSYNC is used in FreeBSD.  */
		    | O_FSYNC
#endif
		    );
  if (serial_fd < 0)
    return 0;

  /* Get the termios parameters.  */
  if (tcgetattr (serial_fd, &termios))
    goto fail;

  /* Raw mode.  */
#if defined(__sun)
  termios.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
  termios.c_oflag &= ~OPOST;
  termios.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
  termios.c_cflag &= ~(CSIZE|PARENB);
  termios.c_cflag |= CS8;
#else
  cfmakeraw (&termios);
#endif

  /* Set the speed.  */
  termios_speed = get_termios_speed (speed);
  if (termios_speed == B0)
    goto fail;
  
  cfsetispeed (&termios, termios_speed);
  cfsetospeed (&termios, termios_speed);

  /* Set the word length.  */
  termios.c_cflag &= ~CSIZE;
  switch (word_len)
    {
    case UART_5BITS_WORD:
      termios.c_cflag |= CS5;
      break;
    case UART_6BITS_WORD:
      termios.c_cflag |= CS6;
      break;
    case UART_7BITS_WORD:
      termios.c_cflag |= CS7;
      break;
    case UART_8BITS_WORD:
      termios.c_cflag |= CS8;
      break;
    default:
      goto fail;
    }

  /* Set the parity.  */
  switch (parity)
    {
    case UART_NO_PARITY:
      termios.c_cflag &= ~PARENB;
      break;
    case UART_ODD_PARITY:
      termios.c_cflag |= PARENB;
      termios.c_cflag |= PARODD;
      break;
    case UART_EVEN_PARITY:
      termios.c_cflag |= PARENB;
      termios.c_cflag &= ~PARODD;
      break;
    default:
      goto fail;
    }

  /* Set the length of stop bit.  */
  switch (stop_bit_len)
    {
    case UART_1_STOP_BIT:
      termios.c_cflag &= ~CSTOPB;
      break;
    case UART_2_STOP_BITS:
      termios.c_cflag |= CSTOPB;
      break;
    default:
      goto fail;
    }

  /* Set the parameters.  */
  if (tcsetattr (serial_fd, TCSANOW, &termios))
    goto fail;

#ifdef SIMULATE_SLOWNESS_OF_SERIAL
  serial_speed = speed;
#endif /* SIMUATE_SLOWNESS_OF_SERIAL */

  /* Get rid of the flag TERM_NEED_INIT from the serial terminal.  */
  for (i = 0; term_table[i].name; i++)
    {
      if (strcmp (term_table[i].name, "serial") == 0)
	{
	  term_table[i].flags &= ~(TERM_NEED_INIT);
	  break;
	}
    }
  
  return 1;

 fail:
  close (serial_fd);
  serial_fd = -1;
  return 0;
}

/* Set the file name of a serial device (or a pty device). This is a
   function specific to the grub shell.  */
void
serial_set_device (const char *device)
{
  if (serial_device)
    free (serial_device);
  
  serial_device = strdup (device);
}

/* There is no difference between console and hercules in the grub shell.  */
void
hercules_putchar (int c)
{
  console_putchar (c);
}

int
hercules_getxy (void)
{
  return console_getxy ();
}

void
hercules_gotoxy (int x, int y)
{
  console_gotoxy (x, y);
}

void
hercules_cls (void)
{
  console_cls ();
}

void
hercules_setcolorstate (color_state state)
{
  console_setcolorstate (state);
}

void
hercules_setcolor (int normal_color, int highlight_color)
{
  console_setcolor (normal_color, highlight_color);
}

int
hercules_setcursor (int on)
{
  return 1;
}

uint32_t amd64_cpuid_supported(void)
{
  /* Nothing to do in the simulator. */
	return (1);
}

void amd64_cpuid_insn(uint32_t i, void * r)
{
  /* Nothing to do in the simulator. */
}

void amd64_rdmsr(uint32_t i, uint64_t * p)
{
  /* Nothing to do in the simulator. */
}

void amd64_wrmsr(uint32_t i, const uint64_t * p)
{
  /* Nothing to do in the simulator. */
}

int get_target_operating_mode(void)
{
  /* Nothing to do in the simulator. */
	return (1);
}
