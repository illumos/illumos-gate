/* main.c - experimental GRUB stage2 that runs under Unix */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002  Free Software Foundation, Inc.
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

/* Simulator entry point. */
int grub_stage2 (void);

#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <setjmp.h>

#define WITHOUT_LIBC_STUBS 1
#include <shared.h>
#include <term.h>

char *program_name = 0;
int use_config_file = 1;
int use_preset_menu = 0;
#ifdef HAVE_LIBCURSES
int use_curses = 1;
#else
int use_curses = 0;
#endif
int verbose = 0;
int read_only = 0;
int floppy_disks = 1;
char *device_map_file = 0;
static int default_boot_drive;
static int default_install_partition;
static char *default_config_file;

#define OPT_HELP		-2
#define OPT_VERSION		-3
#define OPT_HOLD		-4
#define OPT_CONFIG_FILE		-5
#define OPT_INSTALL_PARTITION	-6
#define OPT_BOOT_DRIVE		-7
#define OPT_NO_CONFIG_FILE	-8
#define OPT_NO_CURSES		-9
#define OPT_BATCH		-10
#define OPT_VERBOSE		-11
#define OPT_READ_ONLY		-12
#define OPT_PROBE_SECOND_FLOPPY	-13
#define OPT_NO_FLOPPY		-14
#define OPT_DEVICE_MAP		-15
#define OPT_PRESET_MENU		-16
#define OPT_NO_PAGER		-17
#define OPTSTRING ""

static struct option longopts[] =
{
  {"batch", no_argument, 0, OPT_BATCH},
  {"boot-drive", required_argument, 0, OPT_BOOT_DRIVE},
  {"config-file", required_argument, 0, OPT_CONFIG_FILE},
  {"device-map", required_argument, 0, OPT_DEVICE_MAP},
  {"help", no_argument, 0, OPT_HELP},
  {"hold", optional_argument, 0, OPT_HOLD},
  {"install-partition", required_argument, 0, OPT_INSTALL_PARTITION},
  {"no-config-file", no_argument, 0, OPT_NO_CONFIG_FILE},
  {"no-curses", no_argument, 0, OPT_NO_CURSES},
  {"no-floppy", no_argument, 0, OPT_NO_FLOPPY},
  {"no-pager", no_argument, 0, OPT_NO_PAGER},
  {"preset-menu", no_argument, 0, OPT_PRESET_MENU},
  {"probe-second-floppy", no_argument, 0, OPT_PROBE_SECOND_FLOPPY},
  {"read-only", no_argument, 0, OPT_READ_ONLY},
  {"verbose", no_argument, 0, OPT_VERBOSE},
  {"version", no_argument, 0, OPT_VERSION},
  {0},
};


static void
usage (int status)
{
  if (status)
    fprintf (stderr, "Try ``grub --help'' for more information.\n");
  else
    printf ("\
Usage: grub [OPTION]...\n\
\n\
Enter the GRand Unified Bootloader command shell.\n\
\n\
    --batch                  turn on batch mode for non-interactive use\n\
    --boot-drive=DRIVE       specify stage2 boot_drive [default=0x%x]\n\
    --config-file=FILE       specify stage2 config_file [default=%s]\n\
    --device-map=FILE        use the device map file FILE\n\
    --help                   display this message and exit\n\
    --hold                   wait until a debugger will attach\n\
    --install-partition=PAR  specify stage2 install_partition [default=0x%x]\n\
    --no-config-file         do not use the config file\n\
    --no-curses              do not use curses\n\
    --no-floppy              do not probe any floppy drive\n\
    --no-pager               do not use internal pager\n\
    --preset-menu            use the preset menu\n\
    --probe-second-floppy    probe the second floppy drive\n\
    --read-only              do not write anything to devices\n\
    --verbose                print verbose messages\n\
    --version                print version information and exit\n\
\n\
Report bugs to <bug-grub@gnu.org>.\n\
",
	    default_boot_drive, default_config_file,
	    default_install_partition);

  exit (status);
}


int
main (int argc, char **argv)
{
  int c;
  int hold = 0;

  /* First of all, call sync so that all in-core data is scheduled to be
     actually written to disks. This is very important because GRUB does
     not use ordinary stdio interface but raw devices.  */
  sync ();
  
  program_name = argv[0];
  default_boot_drive = boot_drive;
  default_install_partition = install_partition;
  if (config_file)
    default_config_file = config_file;
  else
    default_config_file = "NONE";
  
  /* Parse command-line options. */
  do
    {
      c = getopt_long (argc, argv, OPTSTRING, longopts, 0);
      switch (c)
	{
	case EOF:
	  /* Fall through the bottom of the loop. */
	  break;

	case OPT_HELP:
	  usage (0);
	  break;

	case OPT_VERSION:
	  printf ("grub (GNU GRUB " VERSION ")\n");
	  exit (0);
	  break;

	case OPT_HOLD:
	  if (! optarg)
	    hold = -1;
	  else
	    hold = atoi (optarg);
	  break;

	case OPT_CONFIG_FILE:
	  strncpy (config_file, optarg, 127); /* FIXME: arbitrary */
	  config_file[127] = '\0';
	  break;

	case OPT_INSTALL_PARTITION:
	  install_partition = strtoul (optarg, 0, 0);
	  if (install_partition == ULONG_MAX)
	    {
	      perror ("strtoul");
	      exit (1);
	    }
	  break;

	case OPT_BOOT_DRIVE:
	  boot_drive = strtoul (optarg, 0, 0);
	  if (boot_drive == ULONG_MAX)
	    {
	      perror ("strtoul");
	      exit (1);
	    }
	  break;

	case OPT_NO_CONFIG_FILE:
	  use_config_file = 0;
	  break;

	case OPT_NO_CURSES:
	  use_curses = 0;
	  break;

	case OPT_NO_PAGER:
	  use_pager = 0;
	  break;

	case OPT_BATCH:
	  /* This is the same as "--no-config-file --no-curses --no-pager".  */
	  use_config_file = 0;
	  use_curses = 0;
	  use_pager = 0;
	  break;

	case OPT_READ_ONLY:
	  read_only = 1;
	  break;

	case OPT_VERBOSE:
	  verbose = 1;
	  break;

	case OPT_NO_FLOPPY:
	  floppy_disks = 0;
	  break;

	case OPT_PROBE_SECOND_FLOPPY:
	  floppy_disks = 2;
	  break;

	case OPT_DEVICE_MAP:
	  device_map_file = strdup (optarg);
	  break;

	case OPT_PRESET_MENU:
	  use_preset_menu = 1;
	  break;
	  
	default:
	  usage (1);
	}
    }
  while (c != EOF);

  /* Wait until the HOLD variable is cleared by an attached debugger. */
  if (hold && verbose)
    printf ("Run \"gdb %s %d\", and set HOLD to zero.\n",
	    program_name, (int) getpid ());
  while (hold)
    {
      if (hold > 0)
	hold--;
      
      sleep (1);
    }

  /* If we don't have curses (!HAVE_LIBCURSES or --no-curses or
     --batch) put terminal to dumb for better handling of line i/o */
  if (! use_curses)
    current_term->flags = TERM_NO_EDIT | TERM_DUMB;

  /* Transfer control to the stage2 simulator. */
  exit (grub_stage2 ());
}
