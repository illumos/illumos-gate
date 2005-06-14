/* mbchk - a simple checker for the format of a Multiboot kernel */
/*
 *  Copyright (C) 1999,2001,2002  Free Software Foundation, Inc.
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <multiboot.h>

static int quiet = 0;
static char *optstring = "hvq";
static struct option longopts[] =
{
  {"help", no_argument, 0, 'h'},
  {"version", no_argument, 0, 'v'},
  {"quiet", no_argument, 0, 'q'},
  {0}
};

static void
usage (int status)
{
  if (status)
    fprintf (stderr, "Try ``mbchk --help'' for more information.\n");
  else
    printf ("Usage: mbchk [OPTION]... [FILE]...\n"
	    "Check if the format of FILE complies with the Multiboot Specification.\n"
	    "\n"
	    "-q, --quiet                suppress all normal output\n"
	    "-h, --help                 display this help and exit\n"
	    "-v, --version              output version information and exit.\n"
	    "\n"
	    "Report bugs to <bug-grub@gnu.org>.\n");

  exit (status);
}

static int
check_multiboot (const char *filename, FILE *fp)
{
  multiboot_header_t *mbh = 0;
  int i;
  char buf[8192];

  if (fread (buf, 1, 8192, fp) < 0)
    {
      fprintf (stderr, "%s: Read error.\n", filename);
      return 0;
    }

  for (i = 0; i < 8192 - sizeof (multiboot_header_t); i++)
    {
      unsigned long magic = *((unsigned long *) (buf + i));

      if (magic == MULTIBOOT_HEADER_MAGIC)
	{
	  mbh = (multiboot_header_t *) (buf + i);
	  break;
	}
    }

  if (! mbh)
    {
      fprintf (stderr, "%s: No Multiboot header.\n", filename);
      return 0;
    }

  if (! quiet)
    printf ("%s: The Multiboot header is found at the offset %d.\n",
	    filename, i);

  /* Check for the checksum.  */
  if (mbh->magic + mbh->flags + mbh->checksum != 0)
    {
      fprintf (stderr,
	       "%s: Bad checksum (0x%lx).\n",
	       filename, mbh->checksum);
      return 0;
    }

  /* Reserved flags must be zero.  */
  if (mbh->flags & ~0x00010003)
    {
      fprintf (stderr,
	       "%s: Non-zero is found in reserved flags (0x%lx).\n",
	       filename, mbh->flags);
      return 0;
    }

  if (! quiet)
    {
      printf ("%s: Page alignment is turned %s.\n",
	      filename, (mbh->flags & 0x1)? "on" : "off");
      printf ("%s: Memory information is turned %s.\n",
	      filename, (mbh->flags & 0x2)? "on" : "off");
      printf ("%s: Address fields is turned %s.\n",
	      filename, (mbh->flags & 0x10000)? "on" : "off");
    }

  /* Check for the address fields.  */
  if (mbh->flags & 0x10000)
    {
      if (mbh->header_addr < mbh->load_addr)
	{
	  fprintf (stderr,
		   "%s: header_addr is less than "
		   "load_addr (0x%lx > 0x%lx).\n",
		   filename, mbh->header_addr, mbh->load_addr);
	  return 0;
	}

      if (mbh->load_end_addr && mbh->load_addr >= mbh->load_end_addr)
	{
	  fprintf (stderr,
		   "%s: load_addr is not less than load_end_addr"
		   " (0x%lx >= 0x%lx).\n",
		   filename, mbh->load_addr, mbh->load_end_addr);
	  return 0;
	}

      if (mbh->bss_end_addr && mbh->load_end_addr > mbh->bss_end_addr)
	{
	  fprintf (stderr,
		   "%s: load_end_addr is greater than bss_end_addr"
		   " (0x%lx > 0x%lx).\n",
		   filename, mbh->load_end_addr, mbh->bss_end_addr);
	  return 0;
	}

      if (mbh->load_addr > mbh->entry_addr)
	{
	  fprintf (stderr,
		   "%s: load_addr is greater than entry_addr"
		   " (0x%lx > 0x%lx).\n",
		   filename, mbh->load_addr, mbh->entry_addr);
	  return 0;
	}

      /* FIXME: It is better to check if the entry address is within the
	 file, especially when the load end address is zero.  */
      if (mbh->load_end_addr && mbh->load_end_addr <= mbh->entry_addr)
	{
	  fprintf (stderr,
		   "%s: load_end_addr is not greater than entry_addr"
		   " (0x%lx <= 0x%lx).\n",
		   filename, mbh->load_end_addr, mbh->entry_addr);
	  return 0;
	}

      /* This is a GRUB-specific limitation.  */
      if (mbh->load_addr < 0x100000)
	{
	  fprintf (stderr,
		   "%s: Cannot be loaded at less than 1MB by GRUB"
		   " (0x%lx).\n",
		   filename, mbh->load_addr);
	  return 0;
	}
    }

  if (! quiet)
    printf ("%s: All checks passed.\n", filename);

  return 1;
}

int
main (int argc, char *argv[])
{
  int c;

  do
    {
      c = getopt_long (argc, argv, optstring, longopts, 0);
      switch (c)
	{
	case EOF:
	  break;

	case 'h':
	  usage (0);
	  break;

	case 'v':
	  printf ("mbchk (GNU GRUB " VERSION ")\n");
	  exit (0);
	  break;

	case 'q':
	  quiet = 1;
	  break;

	default:
	  usage (1);
	  break;
	}
    }
  while (c != EOF);

  if (optind < argc)
    {
      while (optind < argc)
	{
	  FILE *fp;

	  fp = fopen (argv[optind], "r");
	  if (! fp)
	    {
	      fprintf (stderr, "%s: No such file.\n", argv[optind]);
	      exit (1);
	    }

	  if (! check_multiboot (argv[optind], fp))
	    exit (1);

	  fclose (fp);
	  optind++;
	}
    }
  else
    {
      if (! check_multiboot ("<stdin>", stdin))
	exit (1);
    }

  return 0;
}
