/* cmdline.c - the device-independent GRUB text command line */
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

#include <shared.h>
#include <term.h>

extern struct term_entry *current_term;

#ifdef SUPPORT_DISKLESS
# include <grub.h>
#endif

grub_jmp_buf restart_cmdline_env;

/* Find the next word from CMDLINE and return the pointer. If
   AFTER_EQUAL is non-zero, assume that the character `=' is treated as
   a space. Caution: this assumption is for backward compatibility.  */
char *
skip_to (int after_equal, char *cmdline)
{
  /* Skip until we hit whitespace, or maybe an equal sign. */
  while (*cmdline && *cmdline != ' ' && *cmdline != '\t' &&
	 ! (after_equal && *cmdline == '='))
    cmdline ++;

  /* Skip whitespace, and maybe equal signs. */
  while (*cmdline == ' ' || *cmdline == '\t' ||
	 (after_equal && *cmdline == '='))
    cmdline ++;

  return cmdline;
}

/* Print a helpful message for the command-line interface.  */
void
print_cmdline_message (int forever)
{
  printf (" [ Minimal BASH-like line editing is supported.  For the first word, TAB\n"
	  "   lists possible command completions.  Anywhere else TAB lists the possible\n"
	  "   completions of a device/filename.%s ]\n",
	  (forever ? "" : "  ESC at any time exits."));
}

/* Find the builtin whose command name is COMMAND and return the
   pointer. If not found, return 0.  */
struct builtin *
find_command (char *command)
{
  char *ptr;
  char c;
  struct builtin **builtin;

  /* Find the first space and terminate the command name.  */
  ptr = command;
  while (*ptr && *ptr != ' ' && *ptr != '\t' && *ptr != '=')
    ptr ++;

  c = *ptr;
  *ptr = 0;

  /* Seek out the builtin whose command name is COMMAND.  */
  for (builtin = builtin_table; *builtin != 0; builtin++)
    {
      int ret = grub_strcmp (command, (*builtin)->name);

      if (ret == 0)
	{
	  /* Find the builtin for COMMAND.  */
	  *ptr = c;
	  return *builtin;
	}
      else if (ret < 0)
	break;
    }

  /* Cannot find COMMAND.  */
  errnum = ERR_UNRECOGNIZED;
  *ptr = c;
  return 0;
}

/* Initialize the data for the command-line.  */
static void
init_cmdline (void)
{
  /* Initialization.  */
  saved_drive = boot_drive;
  saved_partition = install_partition;
  current_drive = GRUB_INVALID_DRIVE;
  errnum = 0;
  count_lines = -1;
  
  /* Restore memory probe state.  */
  mbi.mem_upper = saved_mem_upper;
  if (mbi.mmap_length)
    mbi.flags |= MB_INFO_MEM_MAP;

  /* Initialize the data for the builtin commands.  */
  init_builtins ();
}

/* Enter the command-line interface. HEAP is used for the command-line
   buffer. Return only if FOREVER is nonzero and get_cmdline returns
   nonzero (ESC is pushed).  */
void
enter_cmdline (char *heap, int forever)
{
  /* Initialize the data and print a message.  */
  init_cmdline ();
  grub_setjmp (restart_cmdline_env);
  init_page ();
#ifdef SUPPORT_DISKLESS
  print_network_configuration ();
  grub_putchar ('\n');
#endif
  print_cmdline_message (forever);
  
  while (1)
    {
      struct builtin *builtin;
      char *arg;

      *heap = 0;
      print_error ();
      errnum = ERR_NONE;

      /* Get the command-line with the minimal BASH-like interface.  */
      if (get_cmdline (PACKAGE "> ", heap, 2048, 0, 1))
	return;

      /* If there was no command, grab a new one. */
      if (! heap[0])
	continue;

      /* Find a builtin.  */
      builtin = find_command (heap);
      if (! builtin)
	continue;

      /* If BUILTIN cannot be run in the command-line, skip it.  */
      if (! (builtin->flags & BUILTIN_CMDLINE))
	{
	  errnum = ERR_UNRECOGNIZED;
	  continue;
	}

      /* Invalidate the cache, because the user may exchange removable
	 disks.  */
      buf_drive = -1;

      /* Start to count lines, only if the internal pager is in use.  */
      if (use_pager)
	count_lines = 0;
      
      /* Run BUILTIN->FUNC.  */
      arg = skip_to (1, heap);
      (builtin->func) (arg, BUILTIN_CMDLINE);

      /* Finish the line count.  */
      count_lines = -1;
    }
}

/* Run an entry from the script SCRIPT. HEAP is used for the
   command-line buffer. If an error occurs, return non-zero, otherwise
   return zero.  */
int
run_script (char *script, char *heap)
{
  char *old_entry;
  char *cur_entry = script;

  /* Initialize the data.  */
  init_cmdline ();

  while (1)
    {
      struct builtin *builtin;
      char *arg;

      print_error ();

      if (errnum)
	{
	  errnum = ERR_NONE;

          /*
           * At this point something must have gone wrong, so dump the
           * buffer and flip output back on.
           */
          builtin = find_command("verbose");
          (builtin->func) ("on", BUILTIN_SCRIPT);

	  /* If a fallback entry is defined, don't prompt a user's
	     intervention.  */
	  if (fallback_entryno < 0)
	    {
	      grub_printf ("\nPress any key to continue...");
	      (void) getkey ();
	    }
	  
	  return 1;
	}

      /* Copy the first string in CUR_ENTRY to HEAP.  */
      old_entry = cur_entry;
      while (*cur_entry++)
	;

      grub_memmove (heap, old_entry, (int) cur_entry - (int) old_entry);
      if (! *heap)
	{
	  /* If there is no more command in SCRIPT...  */

	  /* If any kernel is not loaded, just exit successfully.  */
	  if (kernel_type == KERNEL_TYPE_NONE)
	    return 0;

          if (reset_term)
            if (current_term->shutdown) {
              (*current_term->shutdown)();
              current_term = term_table; /* assumption: console is first */
            }


	  /* Otherwise, the command boot is run implicitly.  */
	  grub_memmove (heap, "boot", 5);
	}

      /* Find a builtin.  */
      builtin = find_command (heap);
      if (! builtin)
	{
	  grub_printf ("%s\n", old_entry);
	  continue;
	}

      if (! (builtin->flags & BUILTIN_NO_ECHO))
	grub_printf ("%s\n", old_entry);

      /* If BUILTIN cannot be run in the command-line, skip it.  */
      if (! (builtin->flags & BUILTIN_CMDLINE))
	{
	  errnum = ERR_UNRECOGNIZED;
	  continue;
	}

      /* Invalidate the cache, because the user may exchange removable
	 disks.  */
      buf_drive = -1;

      /* Run BUILTIN->FUNC.  */
      arg = skip_to (1, heap);
      (builtin->func) (arg, BUILTIN_SCRIPT);
    }
}
