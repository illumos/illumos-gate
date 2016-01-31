/* builtins.c - the GRUB builtin commands */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004  Free Software Foundation, Inc.
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

/* Include stdio.h before shared.h, because we can't define
   WITHOUT_LIBC_STUBS here.  */
#ifdef GRUB_UTIL
# include <stdio.h>
#endif

#include <shared.h>
#include <filesys.h>
#include <term.h>

#ifdef SUPPORT_NETBOOT
# include <grub.h>
#endif

#ifdef SUPPORT_SERIAL
# include <serial.h>
# include <terminfo.h>
#endif

#ifdef GRUB_UTIL
# include <device.h>
#else /* ! GRUB_UTIL */
# include <apic.h>
# include <smp-imps.h>
#endif /* ! GRUB_UTIL */

#ifdef USE_MD5_PASSWORDS
# include <md5.h>
#endif

#include <cpu.h>
#include <expand.h>

/* The type of kernel loaded.  */
kernel_t kernel_type;
/* The boot device.  */
static int bootdev;
/* True when the debug mode is turned on, and false
   when it is turned off.  */
int debug = 0;
/* The default entry.  */
int default_entry = 0;
/* The fallback entry.  */
int fallback_entryno;
int fallback_entries[MAX_FALLBACK_ENTRIES];
/* The number of current entry.  */
int current_entryno;
/* The address for Multiboot command-line buffer.  */
static char *mb_cmdline;
/* The password.  */
char *password;
/* The password type.  */
password_t password_type;
/* The flag for indicating that the user is authoritative.  */
int auth = 0;
/* The timeout.  */
int grub_timeout = -1;
/* Whether to show the menu or not.  */
int show_menu = 1;
/* The BIOS drive map.  */
static unsigned short bios_drive_map[DRIVE_MAP_SIZE + 1];

/* Prototypes for allowing straightfoward calling of builtins functions
   inside other functions.  */
static int configfile_func (char *arg, int flags);
#ifdef SUPPORT_NETBOOT
static void solaris_config_file (void);
#endif

unsigned int min_mem64 = 0;

#if defined(__sun) && !defined(GRUB_UTIL)
extern void __enable_execute_stack (void *);
void
__enable_execute_stack (void *addr)
{
}
#endif /* __sun && !GRUB_UTIL */

/* Initialize the data for builtins.  */
void
init_builtins (void)
{
  kernel_type = KERNEL_TYPE_NONE;
  /* BSD and chainloading evil hacks!  */
  bootdev = set_bootdev (0);
  mb_cmdline = (char *) MB_CMDLINE_BUF;
}

/* Initialize the data for the configuration file.  */
void
init_config (void)
{
  default_entry = 0;
  password = 0;
  fallback_entryno = -1;
  fallback_entries[0] = -1;
  grub_timeout = -1;
  current_rootpool[0] = '\0';
  current_bootfs[0] = '\0';
  current_bootpath[0] = '\0';
  current_bootfs_obj = 0;
  current_devid[0] = '\0';
  is_zfs_mount = 0;
}

/* Check a password for correctness.  Returns 0 if password was
   correct, and a value != 0 for error, similarly to strcmp. */
int
check_password (char *entered, char* expected, password_t type)
{
  switch (type)
    {
    case PASSWORD_PLAIN:
      return strcmp (entered, expected);

#ifdef USE_MD5_PASSWORDS
    case PASSWORD_MD5:
      return check_md5_password (entered, expected);
#endif
    default: 
      /* unsupported password type: be secure */
      return 1;
    }
}

/* Print which sector is read when loading a file.  */
static void
disk_read_print_func(unsigned long long sector, int offset, int length)
{
  grub_printf ("[%llu,%d,%d]", sector, offset, length);
}


/* blocklist */
static int
blocklist_func (char *arg, int flags)
{
  char *dummy = (char *) RAW_ADDR (0x100000);
  unsigned long long start_sector = 0;
  int num_sectors = 0;
  int num_entries = 0;
  int last_length = 0;

  auto void disk_read_blocklist_func (unsigned long long sector, int offset,
      int length);

  /* Collect contiguous blocks into one entry as many as possible,
     and print the blocklist notation on the screen.  */
  auto void disk_read_blocklist_func (unsigned long long sector, int offset,
      int length)
    {
      if (num_sectors > 0)
	{
	  if (start_sector + num_sectors == sector
	      && offset == 0 && last_length == SECTOR_SIZE)
	    {
	      num_sectors++;
	      last_length = length;
	      return;
	    }
	  else
	    {
	      if (last_length == SECTOR_SIZE)
		grub_printf ("%s%lld+%d", num_entries ? "," : "",
			     start_sector - part_start, num_sectors);
	      else if (num_sectors > 1)
		grub_printf ("%s%lld+%d,%lld[0-%d]", num_entries ? "," : "",
			     start_sector - part_start, num_sectors-1,
			     start_sector + num_sectors-1 - part_start, 
			     last_length);
	      else
		grub_printf ("%s%;lld[0-%d]", num_entries ? "," : "",
			     start_sector - part_start, last_length);
	      num_entries++;
	      num_sectors = 0;
	    }
	}

      if (offset > 0)
	{
	  grub_printf("%s%llu[%d-%d]", num_entries ? "," : "",
		      sector-part_start, offset, offset+length);
	  num_entries++;
	}
      else
	{
	  start_sector = sector;
	  num_sectors = 1;
	  last_length = length;
	}
    }

  /* Open the file.  */
  if (! grub_open (arg))
    return 1;

  /* Print the device name.  */
  grub_printf ("(%cd%d",
	       (current_drive & 0x80) ? 'h' : 'f',
	       current_drive & ~0x80);
  
  if ((current_partition & 0xFF0000) != 0xFF0000)
    grub_printf (",%d", (current_partition >> 16) & 0xFF);
  
  if ((current_partition & 0x00FF00) != 0x00FF00)
    grub_printf (",%c", 'a' + ((current_partition >> 8) & 0xFF));
  
  grub_printf (")");

  /* Read in the whole file to DUMMY.  */
  disk_read_hook = disk_read_blocklist_func;
  if (! grub_read (dummy, -1))
    goto fail;

  /* The last entry may not be printed yet.  Don't check if it is a
   * full sector, since it doesn't matter if we read too much. */
  if (num_sectors > 0)
    grub_printf ("%s%lld+%d", num_entries ? "," : "",
		 start_sector - part_start, num_sectors);

  grub_printf ("\n");
  
 fail:
  disk_read_hook = 0;
  grub_close ();
  return errnum;
}

static struct builtin builtin_blocklist =
{
  "blocklist",
  blocklist_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "blocklist FILE",
  "Print the blocklist notation of the file FILE."
};

/* boot */
static int
boot_func (char *arg, int flags)
{
  /* Clear the int15 handler if we can boot the kernel successfully.
     This assumes that the boot code never fails only if KERNEL_TYPE is
     not KERNEL_TYPE_NONE. Is this assumption is bad?  */
  if (kernel_type != KERNEL_TYPE_NONE)
    unset_int15_handler ();

#ifdef SUPPORT_NETBOOT
  /* Shut down the networking.  */
  cleanup_net ();
#endif
  
  switch (kernel_type)
    {
    case KERNEL_TYPE_FREEBSD:
    case KERNEL_TYPE_NETBSD:
      /* *BSD */
      bsd_boot (kernel_type, bootdev, (char *) mbi.cmdline);
      break;

    case KERNEL_TYPE_LINUX:
      /* Linux */
      linux_boot ();
      break;

    case KERNEL_TYPE_BIG_LINUX:
      /* Big Linux */
      big_linux_boot ();
      break;

    case KERNEL_TYPE_CHAINLOADER:
      /* Chainloader */
      
      /* Check if we should set the int13 handler.  */
      if (bios_drive_map[0] != 0)
	{
	  int i;
	  
	  /* Search for SAVED_DRIVE.  */
	  for (i = 0; i < DRIVE_MAP_SIZE; i++)
	    {
	      if (! bios_drive_map[i])
		break;
	      else if ((bios_drive_map[i] & 0xFF) == saved_drive)
		{
		  /* Exchage SAVED_DRIVE with the mapped drive.  */
		  saved_drive = (bios_drive_map[i] >> 8) & 0xFF;
		  break;
		}
	    }
	  
	  /* Set the handler. This is somewhat dangerous.  */
	  set_int13_handler (bios_drive_map);
	}
      
      gateA20 (0);
      boot_drive = saved_drive;
      chain_stage1 (0, BOOTSEC_LOCATION, boot_part_addr);
      break;

    case KERNEL_TYPE_MULTIBOOT:
      /* Multiboot */
#ifdef SUPPORT_NETBOOT
#ifdef SOLARIS_NETBOOT
      if (current_drive == NETWORK_DRIVE) {
    	/*
	 *  XXX Solaris hack: use drive_info to pass network information
	 *  Turn off the flag bit to the loader is technically
	 *  multiboot compliant.
	 */
    	mbi.flags &= ~MB_INFO_DRIVE_INFO;
  	mbi.drives_length = dhcpack_length;
  	mbi.drives_addr = dhcpack_buf;
      }
#endif /* SOLARIS_NETBOOT */
#endif
      multi_boot ((int) entry_addr, (int) &mbi);
      break;

    default:
      errnum = ERR_BOOT_COMMAND;
      return 1;
    }

  return 0;
}

static struct builtin builtin_boot =
{
  "boot",
  boot_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "boot",
  "Boot the OS/chain-loader which has been loaded."
};


#ifdef SUPPORT_NETBOOT
/* bootp */
static int
bootp_func (char *arg, int flags)
{
  int with_configfile = 0;

  if (grub_memcmp (arg, "--with-configfile", sizeof ("--with-configfile") - 1)
      == 0)
    {
      with_configfile = 1;
      arg = skip_to (0, arg);
    }
  
  if (! bootp ())
    {
      if (errnum == ERR_NONE)
	errnum = ERR_DEV_VALUES;

      return 1;
    }

  /* Notify the configuration.  */
  print_network_configuration ();

  /* XXX: this can cause an endless loop, but there is no easy way to
     detect such a loop unfortunately.  */
  if (with_configfile)
    configfile_func (config_file, flags);
  
  return 0;
}

static struct builtin builtin_bootp =
{
  "bootp",
  bootp_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST,
  "bootp [--with-configfile]",
  "Initialize a network device via BOOTP. If the option `--with-configfile'"
  " is given, try to load a configuration file specified by the 150 vendor"
  " tag."
};
#endif /* SUPPORT_NETBOOT */


/* cat */
static int
cat_func (char *arg, int flags)
{
  char c;

  if (! grub_open (arg))
    return 1;

  while (grub_read (&c, 1))
    {
      /* Because running "cat" with a binary file can confuse the terminal,
	 print only some characters as they are.  */
      if (grub_isspace (c) || (c >= ' ' && c <= '~'))
	grub_putchar (c);
      else
	grub_putchar ('?');
    }
  
  grub_close ();
  return 0;
}

static struct builtin builtin_cat =
{
  "cat",
  cat_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "cat FILE",
  "Print the contents of the file FILE."
};


/* chainloader */
static int
chainloader_func (char *arg, int flags)
{
  int force = 0;
  char *file = arg;

  /* If the option `--force' is specified?  */
  if (substring ("--force", arg) <= 0)
    {
      force = 1;
      file = skip_to (0, arg);
    }

  /* Open the file.  */
  if (! grub_open (file))
    {
      kernel_type = KERNEL_TYPE_NONE;
      return 1;
    }

  /* Read the first block.  */
  if (grub_read ((char *) BOOTSEC_LOCATION, SECTOR_SIZE) != SECTOR_SIZE)
    {
      grub_close ();
      kernel_type = KERNEL_TYPE_NONE;

      /* This below happens, if a file whose size is less than 512 bytes
	 is loaded.  */
      if (errnum == ERR_NONE)
	errnum = ERR_EXEC_FORMAT;
      
      return 1;
    }

  /* If not loading it forcibly, check for the signature.  */
  if (! force
      && (*((unsigned short *) (BOOTSEC_LOCATION + BOOTSEC_SIG_OFFSET))
	  != BOOTSEC_SIGNATURE))
    {
      grub_close ();
      errnum = ERR_EXEC_FORMAT;
      kernel_type = KERNEL_TYPE_NONE;
      return 1;
    }

  grub_close ();
  kernel_type = KERNEL_TYPE_CHAINLOADER;

  /* XXX: Windows evil hack. For now, only the first five letters are
     checked.  */
  if (IS_PC_SLICE_TYPE_FAT (current_slice)
      && ! grub_memcmp ((char *) BOOTSEC_LOCATION + BOOTSEC_BPB_SYSTEM_ID,
			"MSWIN", 5))
    *((unsigned long *) (BOOTSEC_LOCATION + BOOTSEC_BPB_HIDDEN_SECTORS))
      = part_start;

  errnum = ERR_NONE;
  
  return 0;
}

static struct builtin builtin_chainloader =
{
  "chainloader",
  chainloader_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "chainloader [--force] FILE",
  "Load the chain-loader FILE. If --force is specified, then load it"
  " forcibly, whether the boot loader signature is present or not."
};


/* This function could be used to debug new filesystem code. Put a file
   in the new filesystem and the same file in a well-tested filesystem.
   Then, run "cmp" with the files. If no output is obtained, probably
   the code is good, otherwise investigate what's wrong...  */
/* cmp FILE1 FILE2 */
static int
cmp_func (char *arg, int flags)
{
  /* The filenames.  */
  char *file1, *file2;
  /* The addresses.  */
  char *addr1, *addr2;
  int i;
  /* The size of the file.  */
  int size;

  /* Get the filenames from ARG.  */
  file1 = arg;
  file2 = skip_to (0, arg);
  if (! *file1 || ! *file2)
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }

  /* Terminate the filenames for convenience.  */
  nul_terminate (file1);
  nul_terminate (file2);

  /* Read the whole data from FILE1.  */
  addr1 = (char *) RAW_ADDR (0x100000);
  if (! grub_open (file1))
    return 1;
  
  /* Get the size.  */
  size = filemax;
  if (grub_read (addr1, -1) != size)
    {
      grub_close ();
      return 1;
    }
  
  grub_close ();

  /* Read the whole data from FILE2.  */
  addr2 = addr1 + size;
  if (! grub_open (file2))
    return 1;

  /* Check if the size of FILE2 is equal to the one of FILE2.  */
  if (size != filemax)
    {
      grub_printf ("Differ in size: 0x%x [%s], 0x%x [%s]\n",
		   size, file1, filemax, file2);
      grub_close ();
      return 0;
    }
  
  if (! grub_read (addr2, -1))
    {
      grub_close ();
      return 1;
    }
  
  grub_close ();

  /* Now compare ADDR1 with ADDR2.  */
  for (i = 0; i < size; i++)
    {
      if (addr1[i] != addr2[i])
	grub_printf ("Differ at the offset %d: 0x%x [%s], 0x%x [%s]\n",
		     i, (unsigned) addr1[i], file1,
		     (unsigned) addr2[i], file2);
    }
  
  return 0;
}

static struct builtin builtin_cmp =
{
  "cmp",
  cmp_func,
  BUILTIN_CMDLINE,
  "cmp FILE1 FILE2",
  "Compare the file FILE1 with the FILE2 and inform the different values"
  " if any."
};


/* color */
/* Set new colors used for the menu interface. Support two methods to
   specify a color name: a direct integer representation and a symbolic
   color name. An example of the latter is "blink-light-gray/blue".  */
static int
color_func (char *arg, int flags)
{
  char *normal;
  char *highlight;
  int new_normal_color;
  int new_highlight_color;
  static char *color_list[16] =
  {
    "black",
    "blue",
    "green",
    "cyan",
    "red",
    "magenta",
    "brown",
    "light-gray",
    "dark-gray",
    "light-blue",
    "light-green",
    "light-cyan",
    "light-red",
    "light-magenta",
    "yellow",
    "white"
  };

  auto int color_number (char *str);

  /* Convert the color name STR into the magical number.  */
  auto int color_number (char *str)
    {
      char *ptr;
      int i;
      int color = 0;
      
      /* Find the separator.  */
      for (ptr = str; *ptr && *ptr != '/'; ptr++)
	;

      /* If not found, return -1.  */
      if (! *ptr)
	return -1;

      /* Terminate the string STR.  */
      *ptr++ = 0;

      /* If STR contains the prefix "blink-", then set the `blink' bit
	 in COLOR.  */
      if (substring ("blink-", str) <= 0)
	{
	  color = 0x80;
	  str += 6;
	}
      
      /* Search for the color name.  */
      for (i = 0; i < 16; i++)
	if (grub_strcmp (color_list[i], str) == 0)
	  {
	    color |= i;
	    break;
	  }

      if (i == 16)
	return -1;

      str = ptr;
      nul_terminate (str);

      /* Search for the color name.  */      
      for (i = 0; i < 8; i++)
	if (grub_strcmp (color_list[i], str) == 0)
	  {
	    color |= i << 4;
	    break;
	  }

      if (i == 8)
	return -1;

      return color;
    }
      
  normal = arg;
  highlight = skip_to (0, arg);

  new_normal_color = color_number (normal);
  if (new_normal_color < 0 && ! safe_parse_maxint (&normal, &new_normal_color))
    return 1;
  
  /* The second argument is optional, so set highlight_color
     to inverted NORMAL_COLOR.  */
  if (! *highlight)
    new_highlight_color = ((new_normal_color >> 4)
			   | ((new_normal_color & 0xf) << 4));
  else
    {
      new_highlight_color = color_number (highlight);
      if (new_highlight_color < 0
	  && ! safe_parse_maxint (&highlight, &new_highlight_color))
	return 1;
    }

  if (current_term->setcolor)
    current_term->setcolor (new_normal_color, new_highlight_color);
  
  return 0;
}

static struct builtin builtin_color =
{
  "color",
  color_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST,
  "color NORMAL [HIGHLIGHT]",
  "Change the menu colors. The color NORMAL is used for most"
  " lines in the menu, and the color HIGHLIGHT is used to highlight the"
  " line where the cursor points. If you omit HIGHLIGHT, then the"
  " inverted color of NORMAL is used for the highlighted line."
  " The format of a color is \"FG/BG\". FG and BG are symbolic color names."
  " A symbolic color name must be one of these: black, blue, green,"
  " cyan, red, magenta, brown, light-gray, dark-gray, light-blue,"
  " light-green, light-cyan, light-red, light-magenta, yellow and white."
  " But only the first eight names can be used for BG. You can prefix"
  " \"blink-\" to FG if you want a blinking foreground color."
};


/* configfile */
static int
configfile_func (char *arg, int flags)
{
  char *new_config = config_file;

  /* Check if the file ARG is present.  */
  if (! grub_open (arg))
    return 1;

  grub_close ();
  
  /* Copy ARG to CONFIG_FILE.  */
  while ((*new_config++ = *arg++) != 0)
    ;

#ifdef GRUB_UTIL
  /* Force to load the configuration file.  */
  use_config_file = 1;
#endif

  /* Make sure that the user will not be authoritative.  */
  auth = 0;
  
  /* Restart cmain.  */
  grub_longjmp (restart_env, 0);

  /* Never reach here.  */
  return 0;
}

static struct builtin builtin_configfile =
{
  "configfile",
  configfile_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "configfile FILE",
  "Load FILE as the configuration file."
};


/* debug */
static int
debug_func (char *arg, int flags)
{
  if (debug)
    {
      debug = 0;
      grub_printf (" Debug mode is turned off\n");
    }
  else
    {
      debug = 1;
      grub_printf (" Debug mode is turned on\n");
    }

  return 0;
}

static struct builtin builtin_debug =
{
  "debug",
  debug_func,
  BUILTIN_CMDLINE,
  "debug",
  "Turn on/off the debug mode."
};


/* default */
static int
default_func (char *arg, int flags)
{
#ifndef SUPPORT_DISKLESS
  if (grub_strcmp (arg, "saved") == 0)
    {
      default_entry = saved_entryno;
      return 0;
    }
#endif /* SUPPORT_DISKLESS */
  
  if (! safe_parse_maxint (&arg, &default_entry))
    return 1;

  return 0;
}

static struct builtin builtin_default =
{
  "default",
  default_func,
  BUILTIN_MENU,
#if 0
  "default [NUM | `saved']",
  "Set the default entry to entry number NUM (if not specified, it is"
  " 0, the first entry) or the entry number saved by savedefault."
#endif
};


#ifdef GRUB_UTIL
/* device */
static int
device_func (char *arg, int flags)
{
  char *drive = arg;
  char *device;

  /* Get the drive number from DRIVE.  */
  if (! set_device (drive))
    return 1;

  /* Get the device argument.  */
  device = skip_to (0, drive);
  
  /* Terminate DEVICE.  */
  nul_terminate (device);

  if (! *device || ! check_device (device))
    {
      errnum = ERR_FILE_NOT_FOUND;
      return 1;
    }

  assign_device_name (current_drive, device);
  
  return 0;
}

static struct builtin builtin_device =
{
  "device",
  device_func,
  BUILTIN_MENU | BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "device DRIVE DEVICE",
  "Specify DEVICE as the actual drive for a BIOS drive DRIVE. This command"
  " can be used only in the grub shell."
};
#endif /* GRUB_UTIL */

#ifdef SUPPORT_NETBOOT
/* Debug Function for RPC */
#ifdef RPC_DEBUG
/* portmap */
static int
portmap_func (char *arg, int flags)
{
	int port, prog, ver;
	if (! grub_eth_probe ()){
		grub_printf ("No ethernet card found.\n");
		errnum = ERR_DEV_VALUES;
		return 1;
	}
	if ((prog = getdec(&arg)) == -1){
		grub_printf("Error prog number\n");
		return 1;
	}
	arg = skip_to (0, arg);
	if ((ver = getdec(&arg)) == -1){
		grub_printf("Error ver number\n");
		return 1;
	}
	port = __pmapudp_getport(ARP_SERVER, prog, ver);
	printf("portmap getport %d", port);
	return 0;
}

static struct builtin builtin_portmap =
{
	"portmap",
	portmap_func,
	BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
	"portmap prog_number vers_number",
	"Do portmap with the prog_number and vers_number"
};
#endif /* RPC_DEBUG */

/* dhcp */
static int
dhcp_func (char *arg, int flags)
{
  int with_configfile = 0;

  if (grub_memcmp (arg, "--with-configfile", sizeof ("--with-configfile") - 1)
      == 0)
    {
      with_configfile = 1;
      arg = skip_to (0, arg);
    }
  
  if (! dhcp ())
    {
      if (errnum == ERR_NONE)
	errnum = ERR_DEV_VALUES;

      return 1;
    }

  /* Notify the configuration.  */
  print_network_configuration ();

  /* XXX: this can cause an endless loop, but there is no easy way to
     detect such a loop unfortunately.  */
  if (with_configfile)
    configfile_func (config_file, flags);
  else
    solaris_config_file();
  
  return 0;
}

static int
test_config_file(char *menufile)
{
	int err;

	/*
	 * If the file exists, make it the default. Else, fallback
	 * to what it was.  Make sure we don't change errnum in the
	 * process.
	 */
	err = errnum;
	if (grub_open(menufile)) {
		grub_strcpy(config_file, menufile);
		grub_close();
		errnum = err;
		return (1);
	}
	errnum = err;
	return (0);
}

static void solaris_config_file (void)
{
	static char menufile[64];
	static char hexdigit[] = "0123456789ABCDEF";
	char *c = menufile;
	int i;

	/*
	 * if DHCP option 150 has been provided, config_file will
	 * already contain the string, try it.
	 */
	if (configfile_origin == CFG_150) {
		if (test_config_file(config_file))
			return;
	}

	/*
	 * try to find host (MAC address) specific configfile:
	 * menu.lst.01<ether_addr>
	 */
	grub_strcpy(c, "menu.lst.01");
	c += grub_strlen(c);
	for (i = 0; i < ETH_ALEN; i++) {
		unsigned char b = arptable[ARP_CLIENT].node[i];
		*c++ = hexdigit[b >> 4];
		*c++ = hexdigit[b & 0xf];
	}
	*c = 0;
	configfile_origin = CFG_MAC;
	if (test_config_file(menufile))
		return;

	/*
	 * try to find a configfile derived from the DHCP/bootp
	 * BootFile string: menu.lst.<BootFile>
	 */
	if (bootfile != NULL && bootfile[0] != 0) {
		c = menufile;
		grub_strcpy(c, "menu.lst.");
		c += grub_strlen("menu.lst.");
		i = grub_strlen("pxegrub.");
		if (grub_memcmp(bootfile, "pxegrub.", i) == 0)
			grub_strcpy(c, bootfile + i);
		else
			grub_strcpy(c, bootfile);
		configfile_origin = CFG_BOOTFILE;
		if (test_config_file(menufile))
			return;
	}

	/*
	 * Default to hard coded "/boot/grub/menu.lst" config file.
	 * This is the last resort, so there's no need to test it,
	 * as there's nothing else to try.
	 */
	char *cp = config_file;
	/* skip leading slashes for tftp */
	while (*cp == '/')
		++cp;
  	grub_memmove (config_file, cp, strlen(cp) + 1);
	configfile_origin = CFG_HARDCODED;
}

static struct builtin builtin_dhcp =
{
  "dhcp",
  dhcp_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST,
  "dhcp",
  "Initialize a network device via DHCP."
};
#endif /* SUPPORT_NETBOOT */

static int terminal_func (char *arg, int flags);

static int verbose_func(char *arg, int flags) {

    if (grub_strcmp(arg, "off") == 0) {
      silent.status = DEFER_SILENT;
      return;
    } else
        if (flags == BUILTIN_CMDLINE) {
          silent.status = DEFER_VERBOSE;
          return;
        }

  silent.status = VERBOSE;

  /* get back to text console */
  if (current_term->shutdown) {
    (*current_term->shutdown)();
    current_term = term_table; /* assumption: console is first */
  }

  /* dump the buffer */
  if (!silent.looped) {
    /* if the buffer hasn't looped, just print it */
    printf("%s", silent.buffer);
  } else {
    /*
     * If the buffer has looped, first print the oldest part of the buffer,
     * which is one past the current null. Then print the newer part which
     * starts at the beginning of the buffer.
     */
    printf("%s", silent.buffer_start + 1);
    printf("%s", silent.buffer);
  }

  return 0;
}

static struct builtin builtin_verbose =
{
  "verbose",
  verbose_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_SCRIPT | BUILTIN_HELP_LIST,
  "verbose",
  "Verbose output during menu entry (script) execution."
};

#ifdef SUPPORT_GRAPHICS

static int splashimage_func(char *arg, int flags) {
    char splashimage[64];
    int i;

    /* filename can only be 64 characters due to our buffer size */
    if (strlen(arg) > 63)
	return 1;

    if (flags == BUILTIN_SCRIPT)
        flags = BUILTIN_CMDLINE;

    if (flags == BUILTIN_CMDLINE) {
	if (!grub_open(arg))
	    return 1;
	grub_close();
    }

    strcpy(splashimage, arg);

    /* get rid of TERM_NEED_INIT from the graphics terminal. */
    for (i = 0; term_table[i].name; i++) {
	if (grub_strcmp (term_table[i].name, "graphics") == 0) {
	    term_table[i].flags &= ~TERM_NEED_INIT;
	    break;
	}
    }

    graphics_set_splash(splashimage);

    if (flags == BUILTIN_CMDLINE && graphics_inited) {
	/*
	 * calling graphics_end() here flickers the screen black. OTOH not
	 * calling it gets us odd plane interlacing / early palette switching ?
	 * ideally one should figure out how to double buffer and switch...
	 */
	graphics_end();
	graphics_init();
	graphics_cls();
    }

    /* 
     * This call does not explicitly initialize graphics mode, but rather
     * simply sets the terminal type unless we're in command line mode and
     * call this function while in terminal mode.
     */
    terminal_func("graphics", flags);

    reset_term = 0;

    return 0;
}

static struct builtin builtin_splashimage =
{
  "splashimage",
  splashimage_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_SCRIPT | BUILTIN_HELP_LIST,
  "splashimage FILE",
  "Load FILE as the background image when in graphics mode."
};


/* foreground */
static int
foreground_func(char *arg, int flags)
{
    if (grub_strlen(arg) == 6) {
	int r = ((hex(arg[0]) << 4) | hex(arg[1])) >> 2;
	int g = ((hex(arg[2]) << 4) | hex(arg[3])) >> 2;
	int b = ((hex(arg[4]) << 4) | hex(arg[5])) >> 2;

	foreground = (r << 16) | (g << 8) | b;
	if (graphics_inited)
	    graphics_set_palette(15, r, g, b);

	return (0);
    }

    return (1);
}

static struct builtin builtin_foreground =
{
  "foreground",
  foreground_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST | BUILTIN_SCRIPT,
  "foreground RRGGBB",
  "Sets the foreground color when in graphics mode."
  "RR is red, GG is green, and BB blue. Numbers must be in hexadecimal."
};


/* background */
static int
background_func(char *arg, int flags)
{
    if (grub_strlen(arg) == 6) {
	int r = ((hex(arg[0]) << 4) | hex(arg[1])) >> 2;
	int g = ((hex(arg[2]) << 4) | hex(arg[3])) >> 2;
	int b = ((hex(arg[4]) << 4) | hex(arg[5])) >> 2;

	background = (r << 16) | (g << 8) | b;
	if (graphics_inited)
	    graphics_set_palette(0, r, g, b);
	return (0);
    }

    return (1);
}

static struct builtin builtin_background =
{
  "background",
  background_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST | BUILTIN_SCRIPT, 
  "background RRGGBB",
  "Sets the background color when in graphics mode."
  "RR is red, GG is green, and BB blue. Numbers must be in hexadecimal."
};

#endif /* SUPPORT_GRAPHICS */


/* clear */
static int 
clear_func() 
{
  if (current_term->cls)
    current_term->cls();

  return 0;
}

static struct builtin builtin_clear =
{
  "clear",
  clear_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "clear",
  "Clear the screen"
};

/* displayapm */
static int
displayapm_func (char *arg, int flags)
{
  if (mbi.flags & MB_INFO_APM_TABLE)
    {
      grub_printf ("APM BIOS information:\n"
		   " Version:          0x%x\n"
		   " 32-bit CS:        0x%x\n"
		   " Offset:           0x%x\n"
		   " 16-bit CS:        0x%x\n"
		   " 16-bit DS:        0x%x\n"
		   " 32-bit CS length: 0x%x\n"
		   " 16-bit CS length: 0x%x\n"
		   " 16-bit DS length: 0x%x\n",
		   (unsigned) apm_bios_info.version,
		   (unsigned) apm_bios_info.cseg,
		   apm_bios_info.offset,
		   (unsigned) apm_bios_info.cseg_16,
		   (unsigned) apm_bios_info.dseg_16,
		   (unsigned) apm_bios_info.cseg_len,
		   (unsigned) apm_bios_info.cseg_16_len,
		   (unsigned) apm_bios_info.dseg_16_len);
    }
  else
    {
      grub_printf ("No APM BIOS found or probe failed\n");
    }

  return 0;
}

static struct builtin builtin_displayapm =
{
  "displayapm",
  displayapm_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "displayapm",
  "Display APM BIOS information."
};


/* displaymem */
static int
displaymem_func (char *arg, int flags)
{
  if (get_eisamemsize () != -1)
    grub_printf (" EISA Memory BIOS Interface is present\n");
  if (get_mmap_entry ((void *) SCRATCHADDR, 0) != 0
      || *((int *) SCRATCHADDR) != 0)
    grub_printf (" Address Map BIOS Interface is present\n");

  grub_printf (" Lower memory: %uK, "
	       "Upper memory (to first chipset hole): %uK\n",
	       mbi.mem_lower, mbi.mem_upper);

  if (min_mem64 != 0)
  	grub_printf (" Memory limit for 64-bit ISADIR expansion: %uMB\n",
	    min_mem64);

  if (mbi.flags & MB_INFO_MEM_MAP)
    {
      struct AddrRangeDesc *map = (struct AddrRangeDesc *) mbi.mmap_addr;
      int end_addr = mbi.mmap_addr + mbi.mmap_length;

      grub_printf (" [Address Range Descriptor entries "
		   "immediately follow (values are 64-bit)]\n");
      while (end_addr > (int) map)
	{
	  char *str;

	  if (map->Type == MB_ARD_MEMORY)
	    str = "Usable RAM";
	  else
	    str = "Reserved";
	  grub_printf ("   %s:  Base Address:  0x%x X 4GB + 0x%x,\n"
		"      Length:   0x%x X 4GB + 0x%x bytes\n",
		str,
		(unsigned long) (map->BaseAddr >> 32),
		(unsigned long) (map->BaseAddr & 0xFFFFFFFF),
		(unsigned long) (map->Length >> 32),
		(unsigned long) (map->Length & 0xFFFFFFFF));

	  map = ((struct AddrRangeDesc *) (((int) map) + 4 + map->size));
	}
    }

  return 0;
}

static struct builtin builtin_displaymem =
{
  "displaymem",
  displaymem_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "displaymem",
  "Display what GRUB thinks the system address space map of the"
  " machine is, including all regions of physical RAM installed."
};


/* dump FROM TO */
#ifdef GRUB_UTIL
static int
dump_func (char *arg, int flags)
{
  char *from, *to;
  FILE *fp;
  char c;
  
  from = arg;
  to = skip_to (0, arg);
  if (! *from || ! *to)
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }

  nul_terminate (from);
  nul_terminate (to);
  
  if (! grub_open (from))
    return 1;

  fp = fopen (to, "w");
  if (! fp)
    {
      errnum = ERR_WRITE;
      return 1;
    }

  while (grub_read (&c, 1))
    if (fputc (c, fp) == EOF)
      {
	errnum = ERR_WRITE;
	fclose (fp);
	return 1;
      }

  if (fclose (fp) == EOF)
    {
      errnum = ERR_WRITE;
      return 1;
    }

  grub_close ();
  return 0;
}

static struct builtin builtin_dump =
  {
    "dump",
    dump_func,
    BUILTIN_CMDLINE,
    "dump FROM TO",
    "Dump the contents of the file FROM to the file TO. FROM must be"
    " a GRUB file and TO must be an OS file."
  };
#endif /* GRUB_UTIL */


static char embed_info[32];
/* embed */
/* Embed a Stage 1.5 in the first cylinder after MBR or in the
   bootloader block in a FFS.  */
static int
embed_func (char *arg, int flags)
{
  char *stage1_5;
  char *device;
  char *stage1_5_buffer = (char *) RAW_ADDR (0x100000);
  int len, size;
  int sector;
  
  stage1_5 = arg;
  device = skip_to (0, stage1_5);

  /* Open a Stage 1.5.  */
  if (! grub_open (stage1_5))
    return 1;

  /* Read the whole of the Stage 1.5.  */
  len = grub_read (stage1_5_buffer, -1);
  grub_close ();
  
  if (errnum)
    return 1;
  
  size = (len + SECTOR_SIZE - 1) / SECTOR_SIZE;
  
  /* Get the device where the Stage 1.5 will be embedded.  */
  set_device (device);
  if (errnum)
    return 1;

  if (current_partition == 0xFFFFFF)
    {
      /* Embed it after the MBR.  */
      
      char mbr[SECTOR_SIZE];
      char ezbios_check[2*SECTOR_SIZE];
      int i;
      
      /* Open the partition.  */
      if (! open_partition ())
	return 1;

      /* No floppy has MBR.  */
      if (! (current_drive & 0x80))
	{
	  errnum = ERR_DEV_VALUES;
	  return 1;
	}
      
      /* Read the MBR of CURRENT_DRIVE.  */
      if (! rawread (current_drive, PC_MBR_SECTOR, 0, SECTOR_SIZE, mbr))
	return 1;
      
      /* Sanity check.  */
      if (! PC_MBR_CHECK_SIG (mbr))
	{
	  errnum = ERR_BAD_PART_TABLE;
	  return 1;
	}

      /* Check if the disk can store the Stage 1.5.  */
      for (i = 0; i < 4; i++)
	if (PC_SLICE_TYPE (mbr, i) && PC_SLICE_START (mbr, i) - 1 < size)
	  {
	    errnum = ERR_NO_DISK_SPACE;
	    return 1;
	  }
      
      /* Check for EZ-BIOS signature. It should be in the third
       * sector, but due to remapping it can appear in the second, so
       * load and check both.  
       */
      if (! rawread (current_drive, 1, 0, 2 * SECTOR_SIZE, ezbios_check))
	return 1;

      if (! memcmp (ezbios_check + 3, "AERMH", 5)
	  || ! memcmp (ezbios_check + 512 + 3, "AERMH", 5))
	{
	  /* The space after the MBR is used by EZ-BIOS which we must 
	   * not overwrite.
	   */
	  errnum = ERR_NO_DISK_SPACE;
	  return 1;
	}

      sector = 1;
    }
  else
    {
      /* Embed it in the bootloader block in the filesystem.  */
      int start_sector;
      
      /* Open the partition.  */
      if (! open_device ())
	return 1;

      /* Check if the current slice supports embedding.  */
      if (fsys_table[fsys_type].embed_func == 0
	  || ! fsys_table[fsys_type].embed_func (&start_sector, size))
	{
	  errnum = ERR_DEV_VALUES;
	  return 1;
	}

      sector = part_start + start_sector;
    }

  /* Clear the cache.  */
  buf_track = BUF_CACHE_INVALID;

  /* Now perform the embedding.  */
  if (! devwrite (sector - part_start, size, stage1_5_buffer))
    return 1;
  
  grub_printf (" %d sectors are embedded.\n", size);
  grub_sprintf (embed_info, "%d+%d", sector - part_start, size);
  return 0;
}

static struct builtin builtin_embed =
{
  "embed",
  embed_func,
  BUILTIN_CMDLINE,
  "embed STAGE1_5 DEVICE",
  "Embed the Stage 1.5 STAGE1_5 in the sectors after MBR if DEVICE"
  " is a drive, or in the \"bootloader\" area if DEVICE is a FFS partition."
  " Print the number of sectors which STAGE1_5 occupies if successful."
};


/* fallback */
static int
fallback_func (char *arg, int flags)
{
  int i = 0;

  while (*arg)
    {
      int entry;
      int j;
      
      if (! safe_parse_maxint (&arg, &entry))
	return 1;

      /* Remove duplications to prevent infinite looping.  */
      for (j = 0; j < i; j++)
	if (entry == fallback_entries[j])
	  break;
      if (j != i)
	continue;
      
      fallback_entries[i++] = entry;
      if (i == MAX_FALLBACK_ENTRIES)
	break;
      
      arg = skip_to (0, arg);
    }

  if (i < MAX_FALLBACK_ENTRIES)
    fallback_entries[i] = -1;

  fallback_entryno = (i == 0) ? -1 : 0;
  
  return 0;
}

static struct builtin builtin_fallback =
{
  "fallback",
  fallback_func,
  BUILTIN_MENU,
#if 0
  "fallback NUM...",
  "Go into unattended boot mode: if the default boot entry has any"
  " errors, instead of waiting for the user to do anything, it"
  " immediately starts over using the NUM entry (same numbering as the"
  " `default' command). This obviously won't help if the machine"
  " was rebooted by a kernel that GRUB loaded."
#endif
};



void
set_root (char *root, unsigned long drive, unsigned long part)
{
  int bsd_part = (part >> 8) & 0xFF;
  int pc_slice = part >> 16;

  if (bsd_part == 0xFF) {
    grub_sprintf (root, "(hd%d,%d)\n", drive - 0x80, pc_slice);
  } else {
    grub_sprintf (root, "(hd%d,%d,%c)\n",
		 drive - 0x80, pc_slice, bsd_part + 'a');
  }
}

static int
find_common (char *arg, char *root, int for_root, int flags)
{
  char *filename = NULL;
  static char argpart[32];
  static char device[32];
  char *tmp_argpart = NULL;
  unsigned long drive;
  unsigned long tmp_drive = saved_drive;
  unsigned long tmp_partition = saved_partition;
  int got_file = 0;
  static char bootsign[BOOTSIGN_LEN];

  /*
   * If argument has partition information (findroot command only), then
   * it can't be a floppy
   */
  if (for_root && arg[0] == '(') {
	tmp_argpart = grub_strchr(arg + 1, ',');
        if (tmp_argpart == NULL)
		goto out;
	grub_strcpy(argpart, tmp_argpart);
	*tmp_argpart = '\0';
	arg++;
        grub_sprintf(bootsign, "%s/%s", BOOTSIGN_DIR, arg);
	filename = bootsign;
	goto harddisk;
  } else if (for_root && !grub_strchr(arg, '/')) {
	/* Boot signature without partition/slice information */
        grub_sprintf(bootsign, "%s/%s", BOOTSIGN_DIR, arg);
	filename = bootsign;
  } else {
	/* plain vanilla find cmd */
	filename = arg;
  }
  
  /* Floppies.  */
  for (drive = 0; drive < 8; drive++)
    {
      current_drive = drive;
      current_partition = 0xFFFFFF;
      
      if (open_device ())
	{
	  saved_drive = current_drive;
	  saved_partition = current_partition;
	  if (grub_open (filename))
	    {
	      grub_close ();
	      got_file = 1;
	      if (for_root) {
		 grub_sprintf(root, "(fd%d)", drive);
		 goto out;
	      } else
	         grub_printf (" (fd%d)\n", drive);
	    }
	}

      errnum = ERR_NONE;
    }

harddisk:
  /* Hard disks.  */
  for (drive = 0x80; drive < 0x88; drive++)
    {
      unsigned long part = 0xFFFFFF;
      unsigned long long start, len, offset, ext_offset, gpt_offset;
      int type, entry, gpt_count, gpt_size;
      char buf[SECTOR_SIZE];

      if (for_root && tmp_argpart) {
	grub_sprintf(device, "(hd%d%s", drive - 0x80, argpart);
	set_device(device);
        errnum = ERR_NONE;
	part = current_partition;
	if (open_device ()) {
	   saved_drive = current_drive;
	   saved_partition = current_partition;
           errnum = ERR_NONE;
	   if (grub_open (filename)) {
	      grub_close ();
	      got_file = 1;
	      if (is_zfs_mount == 0) {
	        set_root(root, current_drive, current_partition);
	        goto out;
	      } else {
		best_drive = current_drive;
		best_part = current_partition;
	      }
           }
	}
        errnum = ERR_NONE;
	continue;
      }
      current_drive = drive;
      while (next_partition (drive, 0xFFFFFF, &part, &type,
			     &start, &len, &offset, &entry,
			     &ext_offset, &gpt_offset,
			     &gpt_count, &gpt_size, buf))
	{
	  if (type != PC_SLICE_TYPE_NONE
	      && ! IS_PC_SLICE_TYPE_BSD (type)
	      && ! IS_PC_SLICE_TYPE_EXTENDED (type))
	    {
	      current_partition = part;
	      if (open_device ())
		{
		  saved_drive = current_drive;
		  saved_partition = current_partition;
		  if (grub_open (filename))
		    {
		      char tmproot[32];

		      grub_close ();
		      got_file = 1;
		      set_root(tmproot, drive, part);
		      if (for_root) {
		 	grub_memcpy(root, tmproot, sizeof(tmproot));
			if (is_zfs_mount == 0) {
			      goto out;
			} else {
			      best_drive = current_drive;
			      best_part = current_partition;
			}
		      } else {
			grub_printf("%s", tmproot);
		      }
		    }
		}
	    }

	  /* We want to ignore any error here.  */
	  errnum = ERR_NONE;
	}

      /* next_partition always sets ERRNUM in the last call, so clear
	 it.  */
      errnum = ERR_NONE;
    }

out:
  if (is_zfs_mount && for_root) {
        set_root(root, best_drive, best_part);
	buf_drive = -1;
  } else {
	saved_drive = tmp_drive;
	saved_partition = tmp_partition;
  }
  if (tmp_argpart)
	*tmp_argpart = ',';

  if (got_file)
    {
      errnum = ERR_NONE;
      return 0;
    }

  errnum = ERR_FILE_NOT_FOUND;
  return 1;
}

/* find */
/* Search for the filename ARG in all of partitions.  */
static int
find_func (char *arg, int flags)
{
	return (find_common(arg, NULL, 0, flags));
}

static struct builtin builtin_find =
{
  "find",
  find_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "find FILENAME",
  "Search for the filename FILENAME in all of partitions and print the list of"
  " the devices which contain the file."
};


/* fstest */
static int
fstest_func (char *arg, int flags)
{
  if (disk_read_hook)
    {
      disk_read_hook = NULL;
      printf (" Filesystem tracing is now off\n");
    }
  else
    {
      disk_read_hook = disk_read_print_func;
      printf (" Filesystem tracing is now on\n");
    }

  return 0;
}

static struct builtin builtin_fstest =
{
  "fstest",
  fstest_func,
  BUILTIN_CMDLINE,
  "fstest",
  "Toggle filesystem test mode."
};


/* geometry */
static int
geometry_func (char *arg, int flags)
{
  struct geometry geom;
  char *msg;
  char *device = arg;
#ifdef GRUB_UTIL
  char *ptr;
#endif

  /* Get the device number.  */
  set_device (device);
  if (errnum)
    return 1;

  /* Check for the geometry.  */
  if (get_diskinfo (current_drive, &geom))
    {
      errnum = ERR_NO_DISK;
      return 1;
    }

  /* Attempt to read the first sector, because some BIOSes turns out not
     to support LBA even though they set the bit 0 in the support
     bitmap, only after reading something actually.  */
  if (biosdisk (BIOSDISK_READ, current_drive, &geom, 0, 1, SCRATCHSEG))
    {
      errnum = ERR_READ;
      return 1;
    }

#ifdef GRUB_UTIL
  ptr = skip_to (0, device);
  if (*ptr)
    {
      char *cylinder, *head, *sector, *total_sector;
      int num_cylinder, num_head, num_sector, num_total_sector;

      cylinder = ptr;
      head = skip_to (0, cylinder);
      sector = skip_to (0, head);
      total_sector = skip_to (0, sector);
      if (! safe_parse_maxint (&cylinder, &num_cylinder)
	  || ! safe_parse_maxint (&head, &num_head)
	  || ! safe_parse_maxint (&sector, &num_sector))
	return 1;

      disks[current_drive].cylinders = num_cylinder;
      disks[current_drive].heads = num_head;
      disks[current_drive].sectors = num_sector;

      if (safe_parse_maxint (&total_sector, &num_total_sector))
	disks[current_drive].total_sectors = num_total_sector;
      else
	disks[current_drive].total_sectors
	  = num_cylinder * num_head * num_sector;
      errnum = 0;

      geom = disks[current_drive];
      buf_drive = -1;
    }
#endif /* GRUB_UTIL */

#ifdef GRUB_UTIL
  msg = device_map[current_drive];
#else
  if (geom.flags & BIOSDISK_FLAG_LBA_EXTENSION)
    msg = "LBA";
  else
    msg = "CHS";
#endif

  grub_printf ("drive 0x%x: C/H/S = %d/%d/%d, "
	       "The number of sectors = %llu, %s\n",
	       current_drive,
	       geom.cylinders, geom.heads, geom.sectors,
	       geom.total_sectors, msg);
  real_open_partition (1);

  return 0;
}

static struct builtin builtin_geometry =
{
  "geometry",
  geometry_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "geometry DRIVE [CYLINDER HEAD SECTOR [TOTAL_SECTOR]]",
  "Print the information for a drive DRIVE. In the grub shell, you can"
  " set the geometry of the drive arbitrarily. The number of the cylinders,"
  " the one of the heads, the one of the sectors and the one of the total"
  " sectors are set to CYLINDER, HEAD, SECTOR and TOTAL_SECTOR,"
  " respectively. If you omit TOTAL_SECTOR, then it will be calculated based"
  " on the C/H/S values automatically."
};


/* halt */
static int
halt_func (char *arg, int flags)
{
  int no_apm;

  no_apm = (grub_memcmp (arg, "--no-apm", 8) == 0);
  grub_halt (no_apm);
  
  /* Never reach here.  */
  return 1;
}

static struct builtin builtin_halt =
{
  "halt",
  halt_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "halt [--no-apm]",
  "Halt your system. If APM is avaiable on it, turn off the power using"
  " the APM BIOS, unless you specify the option `--no-apm'."
};


/* help */
#define MAX_SHORT_DOC_LEN	39
#define MAX_LONG_DOC_LEN	66

static int
help_func (char *arg, int flags)
{
  int all = 0;
  
  if (grub_memcmp (arg, "--all", sizeof ("--all") - 1) == 0)
    {
      all = 1;
      arg = skip_to (0, arg);
    }
  
  if (! *arg)
    {
      /* Invoked with no argument. Print the list of the short docs.  */
      struct builtin **builtin;
      int left = 1;

      for (builtin = builtin_table; *builtin != 0; builtin++)
	{
	  int len;
	  int i;

	  /* If this cannot be used in the command-line interface,
	     skip this.  */
	  if (! ((*builtin)->flags & BUILTIN_CMDLINE))
	    continue;
	  
	  /* If this doesn't need to be listed automatically and "--all"
	     is not specified, skip this.  */
	  if (! all && ! ((*builtin)->flags & BUILTIN_HELP_LIST))
	    continue;

	  len = grub_strlen ((*builtin)->short_doc);
	  /* If the length of SHORT_DOC is too long, truncate it.  */
	  if (len > MAX_SHORT_DOC_LEN - 1)
	    len = MAX_SHORT_DOC_LEN - 1;

	  for (i = 0; i < len; i++)
	    grub_putchar ((*builtin)->short_doc[i]);

	  for (; i < MAX_SHORT_DOC_LEN; i++)
	    grub_putchar (' ');

	  if (! left)
	    grub_putchar ('\n');

	  left = ! left;
	}

      /* If the last entry was at the left column, no newline was printed
	 at the end.  */
      if (! left)
	grub_putchar ('\n');
    }
  else
    {
      /* Invoked with one or more patterns.  */
      do
	{
	  struct builtin **builtin;
	  char *next_arg;

	  /* Get the next argument.  */
	  next_arg = skip_to (0, arg);

	  /* Terminate ARG.  */
	  nul_terminate (arg);

	  for (builtin = builtin_table; *builtin; builtin++)
	    {
	      /* Skip this if this is only for the configuration file.  */
	      if (! ((*builtin)->flags & BUILTIN_CMDLINE))
		continue;

	      if (substring (arg, (*builtin)->name) < 1)
		{
		  char *doc = (*builtin)->long_doc;

		  /* At first, print the name and the short doc.  */
		  grub_printf ("%s: %s\n",
			       (*builtin)->name, (*builtin)->short_doc);

		  /* Print the long doc.  */
		  while (*doc)
		    {
		      int len = grub_strlen (doc);
		      int i;

		      /* If LEN is too long, fold DOC.  */
		      if (len > MAX_LONG_DOC_LEN)
			{
			  /* Fold this line at the position of a space.  */
			  for (len = MAX_LONG_DOC_LEN; len > 0; len--)
			    if (doc[len - 1] == ' ')
			      break;
			}

		      grub_printf ("    ");
		      for (i = 0; i < len; i++)
			grub_putchar (*doc++);
		      grub_putchar ('\n');
		    }
		}
	    }

	  arg = next_arg;
	}
      while (*arg);
    }

  return 0;
}

static struct builtin builtin_help =
{
  "help",
  help_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "help [--all] [PATTERN ...]",
  "Display helpful information about builtin commands. Not all commands"
  " aren't shown without the option `--all'."
};


/* hiddenmenu */
static int
hiddenmenu_func (char *arg, int flags)
{
  show_menu = 0;
  return 0;
}

static struct builtin builtin_hiddenmenu =
{
  "hiddenmenu",
  hiddenmenu_func,
  BUILTIN_MENU,
#if 0
  "hiddenmenu",
  "Hide the menu."
#endif
};


/* hide */
static int
hide_func (char *arg, int flags)
{
  if (! set_device (arg))
    return 1;

  if (! set_partition_hidden_flag (1))
    return 1;

  return 0;
}

static struct builtin builtin_hide =
{
  "hide",
  hide_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST,
  "hide PARTITION",
  "Hide PARTITION by setting the \"hidden\" bit in"
  " its partition type code."
};


#ifdef SUPPORT_NETBOOT
/* ifconfig */
static int
ifconfig_func (char *arg, int flags)
{
  char *svr = 0, *ip = 0, *gw = 0, *sm = 0;
  
  if (! grub_eth_probe ())
    {
      grub_printf ("No ethernet card found.\n");
      errnum = ERR_DEV_VALUES;
      return 1;
    }
  
  while (*arg) 
    {
      if (! grub_memcmp ("--server=", arg, sizeof ("--server=") - 1))
	svr = arg + sizeof("--server=") - 1;
      else if (! grub_memcmp ("--address=", arg, sizeof ("--address=") - 1))
	ip = arg + sizeof ("--address=") - 1;
      else if (! grub_memcmp ("--gateway=", arg, sizeof ("--gateway=") - 1))
	gw = arg + sizeof ("--gateway=") - 1;
      else if (! grub_memcmp ("--mask=", arg, sizeof("--mask=") - 1))
	sm = arg + sizeof ("--mask=") - 1;
      else
	{
	  errnum = ERR_BAD_ARGUMENT;
	  return 1;
	}
      
      arg = skip_to (0, arg);
    }
  
  if (! ifconfig (ip, sm, gw, svr))
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }
  
  print_network_configuration ();
  return 0;
}

static struct builtin builtin_ifconfig =
{
  "ifconfig",
  ifconfig_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST,
  "ifconfig [--address=IP] [--gateway=IP] [--mask=MASK] [--server=IP]",
  "Configure the IP address, the netmask, the gateway and the server"
  " address or print current network configuration."
};
#endif /* SUPPORT_NETBOOT */


/* impsprobe */
static int
impsprobe_func (char *arg, int flags)
{
#ifdef GRUB_UTIL
  /* In the grub shell, we cannot probe IMPS.  */
  errnum = ERR_UNRECOGNIZED;
  return 1;
#else /* ! GRUB_UTIL */
  if (!imps_probe ())
    printf (" No MPS information found or probe failed\n");

  return 0;
#endif /* ! GRUB_UTIL */
}

static struct builtin builtin_impsprobe =
{
  "impsprobe",
  impsprobe_func,
  BUILTIN_CMDLINE,
  "impsprobe",
  "Probe the Intel Multiprocessor Specification 1.1 or 1.4"
  " configuration table and boot the various CPUs which are found into"
  " a tight loop."
};

/* initrd */
static int
initrd_func (char *arg, int flags)
{
  switch (kernel_type)
    {
    case KERNEL_TYPE_LINUX:
    case KERNEL_TYPE_BIG_LINUX:
      if (! load_initrd (arg))
	return 1;
      break;

    default:
      errnum = ERR_NEED_LX_KERNEL;
      return 1;
    }

  return 0;
}

static struct builtin builtin_initrd =
{
  "initrd",
  initrd_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "initrd FILE [ARG ...]",
  "Load an initial ramdisk FILE for a Linux format boot image and set the"
  " appropriate parameters in the Linux setup area in memory."
};


/* install */
static int
install_func (char *arg, int flags)
{
  char *stage1_file, *dest_dev, *file, *addr;
  char *stage1_buffer = (char *) RAW_ADDR (0x100000);
  char *stage2_buffer = stage1_buffer + SECTOR_SIZE;
  char *old_sect = stage2_buffer + SECTOR_SIZE;
  char *stage2_first_buffer = old_sect + SECTOR_SIZE;
  char *stage2_second_buffer = stage2_first_buffer + SECTOR_SIZE;
  /* XXX: Probably SECTOR_SIZE is reasonable.  */
  char *config_filename = stage2_second_buffer + SECTOR_SIZE;
  char *dummy = config_filename + SECTOR_SIZE;
  int new_drive = GRUB_INVALID_DRIVE;
  int dest_drive, dest_partition;
  unsigned int dest_sector;
  int src_drive, src_partition, src_part_start;
  int i;
  struct geometry dest_geom, src_geom;
  unsigned long long saved_sector;
  unsigned long long stage2_first_sector, stage2_second_sector;
  char *ptr;
  int installaddr, installlist;
  /* Point to the location of the name of a configuration file in Stage 2.  */
  char *config_file_location;
  /* If FILE is a Stage 1.5?  */
  int is_stage1_5 = 0;
  /* Must call grub_close?  */
  int is_open = 0;
  /* If LBA is forced?  */
  int is_force_lba = 0;
  /* Was the last sector full? */
  int last_length = SECTOR_SIZE;
  
#ifdef GRUB_UTIL
  /* If the Stage 2 is in a partition mounted by an OS, this will store
     the filename under the OS.  */
  char *stage2_os_file = 0;
#endif /* GRUB_UTIL */
  
  auto void disk_read_savesect_func (unsigned long long sector, int offset,
      int length);
  auto void disk_read_blocklist_func (unsigned long long sector, int offset,
      int length);

  /* Save the first sector of Stage2 in STAGE2_SECT.  */
  auto void disk_read_savesect_func (unsigned long long sector, int offset,
      int length)
    {
      if (debug)
	printf ("[%llu]", sector);

      /* ReiserFS has files which sometimes contain data not aligned
         on sector boundaries.  Returning an error is better than
         silently failing. */
      if (offset != 0 || length != SECTOR_SIZE)
	errnum = ERR_UNALIGNED;

      saved_sector = sector;
    }

  /* Write SECTOR to INSTALLLIST, and update INSTALLADDR and
     INSTALLSECT.  */
  auto void disk_read_blocklist_func (unsigned long long sector, int offset,
      int length)
    {
      if (debug)
	printf("[%llu]", sector);

      if (offset != 0 || last_length != SECTOR_SIZE)
	{
	  /* We found a non-sector-aligned data block. */
	  errnum = ERR_UNALIGNED;
	  return;
	}

      last_length = length;

      if (*((unsigned long *) (installlist - 4))
	  + *((unsigned short *) installlist) != sector
	  || installlist == (int) stage2_first_buffer + SECTOR_SIZE + 4)
	{
	  installlist -= 8;

	  if (*((unsigned long *) (installlist - 8)))
	    errnum = ERR_WONT_FIT;
	  else
	    {
	      *((unsigned short *) (installlist + 2)) = (installaddr >> 4);
	      *((unsigned long *) (installlist - 4)) = sector;
	    }
	}

      *((unsigned short *) installlist) += 1;
      installaddr += 512;
    }

  /* First, check the GNU-style long option.  */
  while (1)
    {
      if (grub_memcmp ("--force-lba", arg, sizeof ("--force-lba") - 1) == 0)
	{
	  is_force_lba = 1;
	  arg = skip_to (0, arg);
	}
#ifdef GRUB_UTIL
      else if (grub_memcmp ("--stage2=", arg, sizeof ("--stage2=") - 1) == 0)
	{
	  stage2_os_file = arg + sizeof ("--stage2=") - 1;
	  arg = skip_to (0, arg);
	  nul_terminate (stage2_os_file);
	}
#endif /* GRUB_UTIL */
      else
	break;
    }
  
  stage1_file = arg;
  dest_dev = skip_to (0, stage1_file);
  if (*dest_dev == 'd')
    {
      new_drive = 0;
      dest_dev = skip_to (0, dest_dev);
    }
  file = skip_to (0, dest_dev);
  addr = skip_to (0, file);

  /* Get the installation address.  */
  if (! safe_parse_maxint (&addr, &installaddr))
    {
      /* ADDR is not specified.  */
      installaddr = 0;
      ptr = addr;
      errnum = 0;
    }
  else
    ptr = skip_to (0, addr);

#ifndef NO_DECOMPRESSION
  /* Do not decompress Stage 1 or Stage 2.  */
  no_decompression = 1;
#endif

  /* Read Stage 1.  */
  is_open = grub_open (stage1_file);
  if (! is_open
      || ! grub_read (stage1_buffer, SECTOR_SIZE) == SECTOR_SIZE)
    goto fail;

  /* Read the old sector from DEST_DEV.  */
  if (! set_device (dest_dev)
      || ! open_partition ()
      || ! devread (0, 0, SECTOR_SIZE, old_sect))
    goto fail;

  /* Store the information for the destination device.  */
  dest_drive = current_drive;
  dest_partition = current_partition;
  dest_geom = buf_geom;
  dest_sector = part_start;

  /* Copy the possible DOS BPB, 59 bytes at byte offset 3.  */
  grub_memmove (stage1_buffer + BOOTSEC_BPB_OFFSET,
		old_sect + BOOTSEC_BPB_OFFSET,
		BOOTSEC_BPB_LENGTH);

  /* If for a hard disk, copy the possible MBR/extended part table.  */
  if (dest_drive & 0x80)
    grub_memmove (stage1_buffer + STAGE1_WINDOWS_NT_MAGIC,
		  old_sect + STAGE1_WINDOWS_NT_MAGIC,
		  STAGE1_PARTEND - STAGE1_WINDOWS_NT_MAGIC);

  /* Check for the version and the signature of Stage 1.  */
  if (*((short *)(stage1_buffer + STAGE1_VER_MAJ_OFFS)) != COMPAT_VERSION
      || (*((unsigned short *) (stage1_buffer + BOOTSEC_SIG_OFFSET))
	  != BOOTSEC_SIGNATURE))
    {
      errnum = ERR_BAD_VERSION;
      goto fail;
    }

  /* This below is not true any longer. But should we leave this alone?  */
  
  /* If DEST_DRIVE is a floppy, Stage 2 must have the iteration probe
     routine.  */
  if (! (dest_drive & 0x80)
      && (*((unsigned char *) (stage1_buffer + BOOTSEC_PART_OFFSET)) == 0x80
	  || stage1_buffer[BOOTSEC_PART_OFFSET] == 0))
    {
      errnum = ERR_BAD_VERSION;
      goto fail;
    }

  grub_close ();
  
  /* Open Stage 2.  */
  is_open = grub_open (file);
  if (! is_open)
    goto fail;

  src_drive = current_drive;
  src_partition = current_partition;
  src_part_start = part_start;
  src_geom = buf_geom;
  
  if (! new_drive)
    new_drive = src_drive;
  else if (src_drive != dest_drive)
    grub_printf ("Warning: the option `d' was not used, but the Stage 1 will"
		 " be installed on a\ndifferent drive than the drive where"
		 " the Stage 2 resides.\n");

  /* Set the boot drive.  */
  *((unsigned char *) (stage1_buffer + STAGE1_BOOT_DRIVE)) = new_drive;

  /* Set the "force LBA" flag.  */
  *((unsigned char *) (stage1_buffer + STAGE1_FORCE_LBA)) = is_force_lba;

  /* If DEST_DRIVE is a hard disk, enable the workaround, which is
     for buggy BIOSes which don't pass boot drive correctly. Instead,
     they pass 0x00 or 0x01 even when booted from 0x80.  */
  if (dest_drive & BIOS_FLAG_FIXED_DISK)
    /* Replace the jmp (2 bytes) with double nop's.  */
    *((unsigned short *) (stage1_buffer + STAGE1_BOOT_DRIVE_CHECK))
      = 0x9090;

  /* Read the first sector of Stage 2.  */
  disk_read_hook = disk_read_savesect_func;
  if (grub_read (stage2_first_buffer, SECTOR_SIZE) != SECTOR_SIZE)
    goto fail;

  stage2_first_sector = saved_sector;
  if (stage2_first_sector >= 0xffffffffUL) {
    grub_printf ("Error: stage2 first sector must be below 2TB\n");
    goto fail;
  }
  
  /* Read the second sector of Stage 2.  */
  if (grub_read (stage2_second_buffer, SECTOR_SIZE) != SECTOR_SIZE)
    goto fail;

  stage2_second_sector = saved_sector;
  
  /* Check for the version of Stage 2.  */
  if (*((short *) (stage2_second_buffer + STAGE2_VER_MAJ_OFFS))
      != COMPAT_VERSION)
    {
      errnum = ERR_BAD_VERSION;
      goto fail;
    }

  /* Check for the Stage 2 id.  */
  if (stage2_second_buffer[STAGE2_STAGE2_ID] != STAGE2_ID_STAGE2)
    is_stage1_5 = 1;

  /* If INSTALLADDR is not specified explicitly in the command-line,
     determine it by the Stage 2 id.  */
  if (! installaddr)
    {
      if (! is_stage1_5)
	/* Stage 2.  */
	installaddr = 0x8000;
      else
	/* Stage 1.5.  */
	installaddr = 0x2000;
    }

  *((unsigned long *) (stage1_buffer + STAGE1_STAGE2_SECTOR))
    = stage2_first_sector;
  *((unsigned short *) (stage1_buffer + STAGE1_STAGE2_ADDRESS))
    = installaddr;
  *((unsigned short *) (stage1_buffer + STAGE1_STAGE2_SEGMENT))
    = installaddr >> 4;

  i = (int) stage2_first_buffer + SECTOR_SIZE - 4;
  while (*((unsigned long *) i))
    {
      if (i < (int) stage2_first_buffer
	  || (*((int *) (i - 4)) & 0x80000000)
	  || *((unsigned short *) i) >= 0xA00
	  || *((short *) (i + 2)) == 0)
	{
	  errnum = ERR_BAD_VERSION;
	  goto fail;
	}

      *((int *) i) = 0;
      *((int *) (i - 4)) = 0;
      i -= 8;
    }

  installlist = (int) stage2_first_buffer + SECTOR_SIZE + 4;
  installaddr += SECTOR_SIZE;
  
  /* Read the whole of Stage2 except for the first sector.  */
  grub_seek (SECTOR_SIZE);

  disk_read_hook = disk_read_blocklist_func;
  if (! grub_read (dummy, -1))
    goto fail;
  
  disk_read_hook = 0;
  
  /* Find a string for the configuration filename.  */
  config_file_location = stage2_second_buffer + STAGE2_VER_STR_OFFS;
  while (*(config_file_location++))
    ;

  /* Set the "force LBA" flag for Stage2.  */
  *((unsigned char *) (stage2_second_buffer + STAGE2_FORCE_LBA))
    = is_force_lba;
  
  if (*ptr == 'p')
    {
      *((long *) (stage2_second_buffer + STAGE2_INSTALLPART))
	= src_partition;
      if (is_stage1_5)
	{
	  /* Reset the device information in FILE if it is a Stage 1.5.  */
	  unsigned long device = 0xFFFFFFFF;

	  grub_memmove (config_file_location, (char *) &device,
			sizeof (device));
	}

      ptr = skip_to (0, ptr);
    }

  if (*ptr)
    {
      grub_strcpy (config_filename, ptr);
      nul_terminate (config_filename);
	
      if (! is_stage1_5)
	/* If it is a Stage 2, just copy PTR to CONFIG_FILE_LOCATION.  */
	grub_strcpy (config_file_location, ptr);
      else
	{
	  char *real_config;
	  unsigned long device;

	  /* Translate the external device syntax to the internal device
	     syntax.  */
	  if (! (real_config = set_device (ptr)))
	    {
	      /* The Stage 2 PTR does not contain the device name, so
		 use the root device instead.  */
	      errnum = ERR_NONE;
	      current_drive = saved_drive;
	      current_partition = saved_partition;
	      real_config = ptr;
	    }
	  
	  if (current_drive == src_drive)
	    {
	      /* If the drive where the Stage 2 resides is the same as
		 the one where the Stage 1.5 resides, do not embed the
		 drive number.  */
	      current_drive = GRUB_INVALID_DRIVE;
	    }

	  device = (current_drive << 24) | current_partition;
	  grub_memmove (config_file_location, (char *) &device,
			sizeof (device));
	  grub_strcpy (config_file_location + sizeof (device),
		       real_config);
	}

      /* If a Stage 1.5 is used, then we need to modify the Stage2.  */
      if (is_stage1_5)
	{
	  char *real_config_filename = skip_to (0, ptr);
	  
	  is_open = grub_open (config_filename);
	  if (! is_open)
	    goto fail;

	  /* Skip the first sector.  */
	  grub_seek (SECTOR_SIZE);
	  
	  disk_read_hook = disk_read_savesect_func;
	  if (grub_read (stage2_buffer, SECTOR_SIZE) != SECTOR_SIZE)
	    goto fail;
	  
	  disk_read_hook = 0;
	  grub_close ();
	  is_open = 0;
	  
	  /* Sanity check.  */
	  if (*(stage2_buffer + STAGE2_STAGE2_ID) != STAGE2_ID_STAGE2)
	    {
	      errnum = ERR_BAD_VERSION;
	      goto fail;
	    }

	  /* Set the "force LBA" flag for Stage2.  */
	  *(stage2_buffer + STAGE2_FORCE_LBA) = is_force_lba;

	  /* If REAL_CONFIG_FILENAME is specified, copy it to the Stage2.  */
	  if (*real_config_filename)
	    {
	      /* Specified */
	      char *location;
	      
	      /* Find a string for the configuration filename.  */
	      location = stage2_buffer + STAGE2_VER_STR_OFFS;
	      while (*(location++))
		;
	      
	      /* Copy the name.  */
	      grub_strcpy (location, real_config_filename);
	    }
	  
	  /* Write it to the disk.  */
	  buf_track = BUF_CACHE_INVALID;

#ifdef GRUB_UTIL
	  /* In the grub shell, access the Stage 2 via the OS filesystem
	     service, if possible.  */
	  if (stage2_os_file)
	    {
	      FILE *fp;

	      fp = fopen (stage2_os_file, "r+");
	      if (! fp)
		{
		  errnum = ERR_FILE_NOT_FOUND;
		  goto fail;
		}

	      if (fseek (fp, SECTOR_SIZE, SEEK_SET) != 0)
		{
		  fclose (fp);
		  errnum = ERR_BAD_VERSION;
		  goto fail;
		}

	      if (fwrite (stage2_buffer, 1, SECTOR_SIZE, fp)
		  != SECTOR_SIZE)
		{
		  fclose (fp);
		  errnum = ERR_WRITE;
		  goto fail;
		}

	      fclose (fp);
	    }
	  else
#endif /* GRUB_UTIL */
	    {
	      if (! devwrite (saved_sector - part_start, 1, stage2_buffer))
		goto fail;
	    }
	}
    }

  /* Clear the cache.  */
  buf_track = BUF_CACHE_INVALID;

  /* Write the modified sectors of Stage2 to the disk.  */
#ifdef GRUB_UTIL
  if (! is_stage1_5 && stage2_os_file)
    {
      FILE *fp;

      fp = fopen (stage2_os_file, "r+");
      if (! fp)
	{
	  errnum = ERR_FILE_NOT_FOUND;
	  goto fail;
	}

      if (fwrite (stage2_first_buffer, 1, SECTOR_SIZE, fp) != SECTOR_SIZE)
	{
	  fclose (fp);
	  errnum = ERR_WRITE;
	  goto fail;
	}

      if (fwrite (stage2_second_buffer, 1, SECTOR_SIZE, fp) != SECTOR_SIZE)
	{
	  fclose (fp);
	  errnum = ERR_WRITE;
	  goto fail;
	}

      fclose (fp);
    }
  else
#endif /* GRUB_UTIL */
    {
      /* The first.  */
      current_drive = src_drive;
      current_partition = src_partition;

      if (! open_partition ())
	goto fail;

      if (! devwrite (stage2_first_sector - src_part_start, 1,
		      stage2_first_buffer))
	goto fail;

      if (! devwrite (stage2_second_sector - src_part_start, 1,
		      stage2_second_buffer))
	goto fail;
    }
  
  /* Write the modified sector of Stage 1 to the disk.  */
  current_drive = dest_drive;
  current_partition = dest_partition;
  if (! open_partition ())
    goto fail;

  devwrite (0, 1, stage1_buffer);

 fail:
  if (is_open)
    grub_close ();
  
  disk_read_hook = 0;
  
#ifndef NO_DECOMPRESSION
  no_decompression = 0;
#endif

  return errnum;
}

static struct builtin builtin_install =
{
  "install",
  install_func,
  BUILTIN_CMDLINE,
  "install [--stage2=STAGE2_FILE] [--force-lba] STAGE1 [d] DEVICE STAGE2 [ADDR] [p] [CONFIG_FILE] [REAL_CONFIG_FILE]",
  "Install STAGE1 on DEVICE, and install a blocklist for loading STAGE2"
  " as a Stage 2. If the option `d' is present, the Stage 1 will always"
  " look for the disk where STAGE2 was installed, rather than using"
  " the booting drive. The Stage 2 will be loaded at address ADDR, which"
  " will be determined automatically if you don't specify it. If"
  " the option `p' or CONFIG_FILE is present, then the first block"
  " of Stage 2 is patched with new values of the partition and name"
  " of the configuration file used by the true Stage 2 (for a Stage 1.5,"
  " this is the name of the true Stage 2) at boot time. If STAGE2 is a Stage"
  " 1.5 and REAL_CONFIG_FILE is present, then the Stage 2 CONFIG_FILE is"
  " patched with the configuration filename REAL_CONFIG_FILE."
  " If the option `--force-lba' is specified, disable some sanity checks"
  " for LBA mode. If the option `--stage2' is specified, rewrite the Stage"
  " 2 via your OS's filesystem instead of the raw device."
};


/* ioprobe */
static int
ioprobe_func (char *arg, int flags)
{
#ifdef GRUB_UTIL
  
  errnum = ERR_UNRECOGNIZED;
  return 1;
  
#else /* ! GRUB_UTIL */
  
  unsigned short *port;
  
  /* Get the drive number.  */
  set_device (arg);
  if (errnum)
    return 1;

  /* Clean out IO_MAP.  */
  grub_memset ((char *) io_map, 0, IO_MAP_SIZE * sizeof (unsigned short));

  /* Track the int13 handler.  */
  track_int13 (current_drive);
  
  /* Print out the result.  */
  for (port = io_map; *port != 0; port++)
    grub_printf (" 0x%x", (unsigned int) *port);

  return 0;
  
#endif /* ! GRUB_UTIL */
}

static struct builtin builtin_ioprobe =
{
  "ioprobe",
  ioprobe_func,
  BUILTIN_CMDLINE,
  "ioprobe DRIVE",
  "Probe I/O ports used for the drive DRIVE."
};


/* kernel */
static int
kernel_func (char *arg, int flags)
{
  int len;
  kernel_t suggested_type = KERNEL_TYPE_NONE;
  unsigned long load_flags = 0;

#ifndef AUTO_LINUX_MEM_OPT
  load_flags |= KERNEL_LOAD_NO_MEM_OPTION;
#endif

  /* Deal with GNU-style long options.  */
  while (1)
    {
      /* If the option `--type=TYPE' is specified, convert the string to
	 a kernel type.  */
      if (grub_memcmp (arg, "--type=", 7) == 0)
	{
	  arg += 7;
	  
	  if (grub_memcmp (arg, "netbsd", 6) == 0)
	    suggested_type = KERNEL_TYPE_NETBSD;
	  else if (grub_memcmp (arg, "freebsd", 7) == 0)
	    suggested_type = KERNEL_TYPE_FREEBSD;
	  else if (grub_memcmp (arg, "openbsd", 7) == 0)
	    /* XXX: For now, OpenBSD is identical to NetBSD, from GRUB's
	       point of view.  */
	    suggested_type = KERNEL_TYPE_NETBSD;
	  else if (grub_memcmp (arg, "linux", 5) == 0)
	    suggested_type = KERNEL_TYPE_LINUX;
	  else if (grub_memcmp (arg, "biglinux", 8) == 0)
	    suggested_type = KERNEL_TYPE_BIG_LINUX;
	  else if (grub_memcmp (arg, "multiboot", 9) == 0)
	    suggested_type = KERNEL_TYPE_MULTIBOOT;
	  else
	    {
	      errnum = ERR_BAD_ARGUMENT;
	      return 1;
	    }
	}
      /* If the `--no-mem-option' is specified, don't pass a Linux's mem
	 option automatically. If the kernel is another type, this flag
	 has no effect.  */
      else if (grub_memcmp (arg, "--no-mem-option", 15) == 0)
	load_flags |= KERNEL_LOAD_NO_MEM_OPTION;
      else
	break;

      /* Try the next.  */
      arg = skip_to (0, arg);
    }
      
  len = grub_strlen (arg);

  /* Reset MB_CMDLINE.  */
  mb_cmdline = (char *) MB_CMDLINE_BUF;
  if (len + 1 > MB_CMDLINE_BUFLEN)
    {
      errnum = ERR_WONT_FIT;
      return 1;
    }

  /* Copy the command-line to MB_CMDLINE.  */
  grub_memmove (mb_cmdline, arg, len + 1);
  kernel_type = load_image (arg, mb_cmdline, suggested_type, load_flags);
  if (kernel_type == KERNEL_TYPE_NONE)
    return 1;

  mb_cmdline += grub_strlen(mb_cmdline) + 1;
  return 0;
}

static struct builtin builtin_kernel =
{
  "kernel",
  kernel_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "kernel [--no-mem-option] [--type=TYPE] FILE [ARG ...]",
  "Attempt to load the primary boot image from FILE. The rest of the"
  " line is passed verbatim as the \"kernel command line\".  Any modules"
  " must be reloaded after using this command. The option --type is used"
  " to suggest what type of kernel to be loaded. TYPE must be either of"
  " \"netbsd\", \"freebsd\", \"openbsd\", \"linux\", \"biglinux\" and"
  " \"multiboot\". The option --no-mem-option tells GRUB not to pass a"
  " Linux's mem option automatically."
};

int
min_mem64_func(char *arg, int flags)
{
	if (!safe_parse_maxint(&arg, &min_mem64))
		return (1);
}

static struct builtin builtin_min_mem64 =
{
	"min_mem64",
	min_mem64_func,
	BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_SCRIPT | BUILTIN_HELP_LIST,
	"min_mem64 <memory in MB>",
	"Sets minimum memory (in MB) required for $ISADIR to expand to amd64, "
	"even on 64-bit capable hardware."
};

static int
kernel_dollar_func (char *arg, int flags)
{
  int err;
  char newarg[MAX_CMDLINE];

  /*
   * We're going to expand the arguments twice.  The first expansion, which
   * occurs without the benefit of knowing the ZFS object ID of the filesystem
   * we're booting from (if we're booting from ZFS, of course), must be
   * sufficient to find and read the kernel.  The second expansion will
   * then overwrite the command line actually set in the multiboot header with
   * the newly-expanded one.  Since $ZFS-BOOTFS expands differently after
   * zfs_open() has been called (kernel_func() -> load_image() -> grub_open() ->
   * zfs_open()), we need to do the second expansion so that the kernel is
   * given the right object ID argument.  Note that the pointer to the
   * command line set in the multiboot header is always MB_CMDLINE_BUF.
   */
  grub_printf("loading '%s' ...\n", arg);
  if ((err = expand_string(arg, newarg, MAX_CMDLINE)) != 0) {
    errnum = err;
    return (1);
  }

  if ((err = kernel_func(newarg, flags)) != 0)
    return (err);

  mb_cmdline = (char *)MB_CMDLINE_BUF;
  if ((err = expand_string(arg, mb_cmdline, MAX_CMDLINE)) != 0) {
    errnum = err;
    return (1);
  }

  grub_printf("loading '%s' ...\n", mb_cmdline);
  mb_cmdline += grub_strlen(mb_cmdline) + 1;
  return (0);
}

static struct builtin builtin_kernel_dollar =
{
  "kernel$",
  kernel_dollar_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "kernel$ [--no-mem-option] [--type=TYPE] FILE [ARG ...]",
  " Just like kernel, but with variable expansion, including the legacy"
  " (and nonconforming) variables $ISADIR and $ZFS-BOOTFS."
};


/* lock */
static int
lock_func (char *arg, int flags)
{
  if (! auth && password)
    {
      errnum = ERR_PRIVILEGED;
      return 1;
    }

  return 0;
}

static struct builtin builtin_lock =
{
  "lock",
  lock_func,
  BUILTIN_CMDLINE,
  "lock",
  "Break a command execution unless the user is authenticated."
};
  

/* makeactive */
static int
makeactive_func (char *arg, int flags)
{
  if (! make_saved_active ())
    return 1;

  return 0;
}

static struct builtin builtin_makeactive =
{
  "makeactive",
  makeactive_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "makeactive",
  "Set the active partition on the root disk to GRUB's root device."
  " This command is limited to _primary_ PC partitions on a hard disk."
};


/* map */
/* Map FROM_DRIVE to TO_DRIVE.  */
static int
map_func (char *arg, int flags)
{
  char *to_drive;
  char *from_drive;
  unsigned long to, from;
  int i;
  
  to_drive = arg;
  from_drive = skip_to (0, arg);

  /* Get the drive number for TO_DRIVE.  */
  set_device (to_drive);
  if (errnum)
    return 1;
  to = current_drive;

  /* Get the drive number for FROM_DRIVE.  */
  set_device (from_drive);
  if (errnum)
    return 1;
  from = current_drive;

  /* Search for an empty slot in BIOS_DRIVE_MAP.  */
  for (i = 0; i < DRIVE_MAP_SIZE; i++)
    {
      /* Perhaps the user wants to override the map.  */
      if ((bios_drive_map[i] & 0xff) == from)
	break;
      
      if (! bios_drive_map[i])
	break;
    }

  if (i == DRIVE_MAP_SIZE)
    {
      errnum = ERR_WONT_FIT;
      return 1;
    }

  if (to == from)
    /* If TO is equal to FROM, delete the entry.  */
    grub_memmove ((char *) &bios_drive_map[i], (char *) &bios_drive_map[i + 1],
		  sizeof (unsigned short) * (DRIVE_MAP_SIZE - i));
  else
    bios_drive_map[i] = from | (to << 8);
  
  return 0;
}

static struct builtin builtin_map =
{
  "map",
  map_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "map TO_DRIVE FROM_DRIVE",
  "Map the drive FROM_DRIVE to the drive TO_DRIVE. This is necessary"
  " when you chain-load some operating systems, such as DOS, if such an"
  " OS resides at a non-first drive."
};


#ifdef USE_MD5_PASSWORDS
/* md5crypt */
static int
md5crypt_func (char *arg, int flags)
{
  char crypted[36];
  char key[32];
  unsigned int seed;
  int i;
  const char *const seedchars =
    "./0123456789ABCDEFGHIJKLMNOPQRST"
    "UVWXYZabcdefghijklmnopqrstuvwxyz";
  
  /* First create a salt.  */

  /* The magical prefix.  */
  grub_memset (crypted, 0, sizeof (crypted));
  grub_memmove (crypted, "$1$", 3);

  /* Create the length of a salt.  */
  seed = currticks ();

  /* Generate a salt.  */
  for (i = 0; i < 8 && seed; i++)
    {
      /* FIXME: This should be more random.  */
      crypted[3 + i] = seedchars[seed & 0x3f];
      seed >>= 6;
    }

  /* A salt must be terminated with `$', if it is less than 8 chars.  */
  crypted[3 + i] = '$';

#ifdef DEBUG_MD5CRYPT
  grub_printf ("salt = %s\n", crypted);
#endif
  
  /* Get a password.  */
  grub_memset (key, 0, sizeof (key));
  get_cmdline ("Password: ", key, sizeof (key) - 1, '*', 0);

  /* Crypt the key.  */
  make_md5_password (key, crypted);

  grub_printf ("Encrypted: %s\n", crypted);
  return 0;
}

static struct builtin builtin_md5crypt =
{
  "md5crypt",
  md5crypt_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "md5crypt",
  "Generate a password in MD5 format."
};
#endif /* USE_MD5_PASSWORDS */


/* module */
static int
module_func (char *arg, int flags)
{
  int len = grub_strlen (arg);

  switch (kernel_type)
    {
    case KERNEL_TYPE_MULTIBOOT:
      if (mb_cmdline + len + 1 > (char *) MB_CMDLINE_BUF + MB_CMDLINE_BUFLEN)
	{
	  errnum = ERR_WONT_FIT;
	  return 1;
	}
      grub_memmove (mb_cmdline, arg, len + 1);
      if (! load_module (arg, mb_cmdline))
	return 1;

      mb_cmdline += grub_strlen(mb_cmdline) + 1;
      break;

    case KERNEL_TYPE_LINUX:
    case KERNEL_TYPE_BIG_LINUX:
      if (! load_initrd (arg))
	return 1;
      break;

    default:
      errnum = ERR_NEED_MB_KERNEL;
      return 1;
    }

  return 0;
}

static struct builtin builtin_module =
{
  "module",
  module_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "module FILE [ARG ...]",
  "Load a boot module FILE for a Multiboot format boot image (no"
  " interpretation of the file contents is made, so users of this"
  " command must know what the kernel in question expects). The"
  " rest of the line is passed as the \"module command line\", like"
  " the `kernel' command."
};

/* module$ */
static int
module_dollar_func (char *arg, int flags)
{
  char newarg[MAX_CMDLINE];
  char *cmdline_sav = mb_cmdline;
  int err;

  grub_printf("loading '%s' ...\n", arg);
  if ((err = expand_string(arg, newarg, MAX_CMDLINE)) != 0) {
    errnum = err;
    return (1);
  }

  if ((err = module_func(newarg, flags)) != 0)
    return (err);

  if ((err = expand_string(arg, cmdline_sav, MAX_CMDLINE)) != 0) {
    errnum = err;
    return (1);
  }

  grub_printf("loading '%s' ...\n", cmdline_sav);
  mb_cmdline += grub_strlen(cmdline_sav) + 1;
  return (0);
}

static struct builtin builtin_module_dollar =
{
  "module$",
  module_dollar_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "module FILE [ARG ...]",
  " Just like module, but with $ISADIR expansion."
};


/* modulenounzip */
static int
modulenounzip_func (char *arg, int flags)
{
  int ret;

#ifndef NO_DECOMPRESSION
  no_decompression = 1;
#endif

  ret = module_func (arg, flags);

#ifndef NO_DECOMPRESSION
  no_decompression = 0;
#endif

  return ret;
}

static struct builtin builtin_modulenounzip =
{
  "modulenounzip",
  modulenounzip_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "modulenounzip FILE [ARG ...]",
  "The same as `module', except that automatic decompression is"
  " disabled."
};


/* pager [on|off] */
static int
pager_func (char *arg, int flags)
{
  /* If ARG is empty, toggle the flag.  */
  if (! *arg)
    use_pager = ! use_pager;
  else if (grub_memcmp (arg, "on", 2) == 0)
    use_pager = 1;
  else if (grub_memcmp (arg, "off", 3) == 0)
    use_pager = 0;
  else
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }

  grub_printf (" Internal pager is now %s\n", use_pager ? "on" : "off");
  return 0;
}

static struct builtin builtin_pager =
{
  "pager",
  pager_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST,
  "pager [FLAG]",
  "Toggle pager mode with no argument. If FLAG is given and its value"
  " is `on', turn on the mode. If FLAG is `off', turn off the mode."
};


/* partnew PART TYPE START LEN */
static int
partnew_func (char *arg, int flags)
{
  int new_type, new_start, new_len;
  int start_cl, start_ch, start_dh;
  int end_cl, end_ch, end_dh;
  int entry;
  char mbr[512];

  /* Convert a LBA address to a CHS address in the INT 13 format.  */
  auto void lba_to_chs (int lba, int *cl, int *ch, int *dh);
  void lba_to_chs (int lba, int *cl, int *ch, int *dh)
    {
      int cylinder, head, sector;

      sector = lba % buf_geom.sectors + 1;
      head = (lba / buf_geom.sectors) % buf_geom.heads;
      cylinder = lba / (buf_geom.sectors * buf_geom.heads);

      if (cylinder >= buf_geom.cylinders)
	cylinder = buf_geom.cylinders - 1;
      
      *cl = sector | ((cylinder & 0x300) >> 2);
      *ch = cylinder & 0xFF;
      *dh = head;
    }
      
  /* Get the drive and the partition.  */
  if (! set_device (arg))
    return 1;

  /* The drive must be a hard disk.  */
  if (! (current_drive & 0x80))
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }

  /* The partition must a primary partition.  */
  if ((current_partition >> 16) > 3
      || (current_partition & 0xFFFF) != 0xFFFF)
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }

  entry = current_partition >> 16;
  
  /* Get the new partition type.  */
  arg = skip_to (0, arg);
  if (! safe_parse_maxint (&arg, &new_type))
    return 1;

  /* The partition type is unsigned char.  */
  if (new_type > 0xFF)
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }

  /* Get the new partition start.  */
  arg = skip_to (0, arg);
  if (! safe_parse_maxint (&arg, &new_start))
    return 1;
  
  /* Get the new partition length.  */
  arg = skip_to (0, arg);
  if (! safe_parse_maxint (&arg, &new_len))
    return 1;

  /* Read the MBR.  */
  if (! rawread (current_drive, 0, 0, SECTOR_SIZE, mbr))
    return 1;

  /* Store the partition information in the MBR.  */
  lba_to_chs (new_start, &start_cl, &start_ch, &start_dh);
  lba_to_chs (new_start + new_len - 1, &end_cl, &end_ch, &end_dh);

  PC_SLICE_FLAG (mbr, entry) = 0;
  PC_SLICE_HEAD (mbr, entry) = start_dh;
  PC_SLICE_SEC (mbr, entry) = start_cl;
  PC_SLICE_CYL (mbr, entry) = start_ch;
  PC_SLICE_TYPE (mbr, entry) = new_type;
  PC_SLICE_EHEAD (mbr, entry) = end_dh;
  PC_SLICE_ESEC (mbr, entry) = end_cl;
  PC_SLICE_ECYL (mbr, entry) = end_ch;
  PC_SLICE_START (mbr, entry) = new_start;
  PC_SLICE_LENGTH (mbr, entry) = new_len;

  /* Make sure that the MBR has a valid signature.  */
  PC_MBR_SIG (mbr) = PC_MBR_SIGNATURE;
  
  /* Write back the MBR to the disk.  */
  buf_track = BUF_CACHE_INVALID;
  if (! rawwrite (current_drive, 0, mbr))
    return 1;

  return 0;
}

static struct builtin builtin_partnew =
{
  "partnew",
  partnew_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST,
  "partnew PART TYPE START LEN",
  "Create a primary partition at the starting address START with the"
  " length LEN, with the type TYPE. START and LEN are in sector units."
};


/* parttype PART TYPE */
static int
parttype_func (char *arg, int flags)
{
  int new_type;
  unsigned long part = 0xFFFFFF;
  unsigned long long start, len, offset, ext_offset, gpt_offset;
  int entry, type, gpt_count, gpt_size;
  char mbr[512];

  /* Get the drive and the partition.  */
  if (! set_device (arg))
    return 1;

  /* The drive must be a hard disk.  */
  if (! (current_drive & 0x80))
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }
  
  /* The partition must be a PC slice.  */
  if ((current_partition >> 16) == 0xFF
      || (current_partition & 0xFFFF) != 0xFFFF)
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }

  /* Get the new partition type.  */
  arg = skip_to (0, arg);
  if (! safe_parse_maxint (&arg, &new_type))
    return 1;

  /* The partition type is unsigned char.  */
  if (new_type > 0xFF)
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }

  /* Look for the partition.  */
  while (next_partition (current_drive, 0xFFFFFF, &part, &type,
			 &start, &len, &offset, &entry,
			 &ext_offset, &gpt_offset, &gpt_count, &gpt_size, mbr))
    {
	  /* The partition may not be a GPT partition.  */
	  if (gpt_offset != 0)
	    {
		errnum = ERR_BAD_ARGUMENT;
		return 1;
	    }

      if (part == current_partition)
	{
	  /* Found.  */

	  /* Set the type to NEW_TYPE.  */
	  PC_SLICE_TYPE (mbr, entry) = new_type;
	  
	  /* Write back the MBR to the disk.  */
	  buf_track = BUF_CACHE_INVALID;
	  if (! rawwrite (current_drive, offset, mbr))
	    return 1;

	  /* Succeed.  */
	  return 0;
	}
    }

  /* The partition was not found.  ERRNUM was set by next_partition.  */
  return 1;
}

static struct builtin builtin_parttype =
{
  "parttype",
  parttype_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST,
  "parttype PART TYPE",
  "Change the type of the partition PART to TYPE."
};


/* password */
static int
password_func (char *arg, int flags)
{
  int len;
  password_t type = PASSWORD_PLAIN;

#ifdef USE_MD5_PASSWORDS
  if (grub_memcmp (arg, "--md5", 5) == 0)
    {
      type = PASSWORD_MD5;
      arg = skip_to (0, arg);
    }
#endif
  if (grub_memcmp (arg, "--", 2) == 0)
    {
      type = PASSWORD_UNSUPPORTED;
      arg = skip_to (0, arg);
    }

  if ((flags & (BUILTIN_CMDLINE | BUILTIN_SCRIPT)) != 0)
    {
      /* Do password check! */
      char entered[32];
      
      /* Wipe out any previously entered password */
      entered[0] = 0;
      get_cmdline ("Password: ", entered, 31, '*', 0);

      nul_terminate (arg);
      if (check_password (entered, arg, type) != 0)
	{
	  errnum = ERR_PRIVILEGED;
	  return 1;
	}
    }
  else
    {
      len = grub_strlen (arg);
      
      /* PASSWORD NUL NUL ... */
      if (len + 2 > PASSWORD_BUFLEN)
	{
	  errnum = ERR_WONT_FIT;
	  return 1;
	}
      
      /* Copy the password and clear the rest of the buffer.  */
      password = (char *) PASSWORD_BUF;
      grub_memmove (password, arg, len);
      grub_memset (password + len, 0, PASSWORD_BUFLEN - len);
      password_type = type;
    }
  return 0;
}

static struct builtin builtin_password =
{
  "password",
  password_func,
  BUILTIN_MENU | BUILTIN_CMDLINE | BUILTIN_NO_ECHO,
  "password [--md5] PASSWD [FILE]",
  "If used in the first section of a menu file, disable all"
  " interactive editing control (menu entry editor and"
  " command line). If the password PASSWD is entered, it loads the"
  " FILE as a new config file and restarts the GRUB Stage 2. If you"
  " omit the argument FILE, then GRUB just unlocks privileged"
  " instructions.  You can also use it in the script section, in"
  " which case it will ask for the password, before continueing."
  " The option --md5 tells GRUB that PASSWD is encrypted with"
  " md5crypt."
};


/* pause */
static int
pause_func (char *arg, int flags)
{
  printf("%s\n", arg);

  /* If ESC is returned, then abort this entry.  */
  if (ASCII_CHAR (getkey ()) == 27)
    return 1;

  return 0;
}

static struct builtin builtin_pause =
{
  "pause",
  pause_func,
  BUILTIN_CMDLINE | BUILTIN_NO_ECHO,
  "pause [MESSAGE ...]",
  "Print MESSAGE, then wait until a key is pressed."
};


#ifdef GRUB_UTIL
/* quit */
static int
quit_func (char *arg, int flags)
{
  stop ();
  
  /* Never reach here.  */
  return 0;
}

static struct builtin builtin_quit =
{
  "quit",
  quit_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "quit",
  "Exit from the GRUB shell."
};
#endif /* GRUB_UTIL */


#ifdef SUPPORT_NETBOOT
/* rarp */
static int
rarp_func (char *arg, int flags)
{
  if (! rarp ())
    {
      if (errnum == ERR_NONE)
	errnum = ERR_DEV_VALUES;

      return 1;
    }

  /* Notify the configuration.  */
  print_network_configuration ();
  return 0;
}

static struct builtin builtin_rarp =
{
  "rarp",
  rarp_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST,
  "rarp",
  "Initialize a network device via RARP."
};
#endif /* SUPPORT_NETBOOT */


static int
read_func (char *arg, int flags)
{
  int addr;

  if (! safe_parse_maxint (&arg, &addr))
    return 1;

  grub_printf ("Address 0x%x: Value 0x%x\n",
	       addr, *((unsigned *) RAW_ADDR (addr)));
  return 0;
}

static struct builtin builtin_read =
{
  "read",
  read_func,
  BUILTIN_CMDLINE,
  "read ADDR",
  "Read a 32-bit value from memory at address ADDR and"
  " display it in hex format."
};


/* reboot */
static int
reboot_func (char *arg, int flags)
{
  grub_reboot ();

  /* Never reach here.  */
  return 1;
}

static struct builtin builtin_reboot =
{
  "reboot",
  reboot_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "reboot",
  "Reboot your system."
};


/* Print the root device information.  */
static void
print_root_device (void)
{
  if (saved_drive == NETWORK_DRIVE)
    {
      /* Network drive.  */
      grub_printf (" (nd):");
    }
  else if (saved_drive & 0x80)
    {
      /* Hard disk drive.  */
      grub_printf (" (hd%d", saved_drive - 0x80);
      
      if ((saved_partition & 0xFF0000) != 0xFF0000)
	grub_printf (",%d", saved_partition >> 16);

      if ((saved_partition & 0x00FF00) != 0x00FF00)
	grub_printf (",%c", ((saved_partition >> 8) & 0xFF) + 'a');

      grub_printf ("):");
    }
  else
    {
      /* Floppy disk drive.  */
      grub_printf (" (fd%d):", saved_drive);
    }

  /* Print the filesystem information.  */
  current_partition = saved_partition;
  current_drive = saved_drive;
  print_fsys_type ();
}

static int
real_root_func (char *arg, int attempt_mount)
{
  int hdbias = 0;
  char *biasptr;
  char *next;

  /* If ARG is empty, just print the current root device.  */
  if (! *arg)
    {
      print_root_device ();
      return 0;
    }
  
  /* Call set_device to get the drive and the partition in ARG.  */
  next = set_device (arg);
  if (! next)
    return 1;

  /* Ignore ERR_FSYS_MOUNT.  */
  if (attempt_mount)
    {
      if (! open_device () && errnum != ERR_FSYS_MOUNT)
	return 1;
    }
  else
    {
      /* This is necessary, because the location of a partition table
	 must be set appropriately.  */
      if (open_partition ())
	{
	  set_bootdev (0);
	  if (errnum)
	    return 1;
	}
    }
  
  /* Clear ERRNUM.  */
  errnum = 0;
  saved_partition = current_partition;
  saved_drive = current_drive;

  if (attempt_mount)
    {
      /* BSD and chainloading evil hacks !!  */
      biasptr = skip_to (0, next);
      safe_parse_maxint (&biasptr, &hdbias);
      errnum = 0;
      bootdev = set_bootdev (hdbias);
      if (errnum)
	return 1;
      
      /* Print the type of the filesystem.  */
      print_fsys_type ();
    }
  
  return 0;
}

static int
root_func (char *arg, int flags)
{
  is_zfs_mount = 0;
  return real_root_func (arg, 1);
}

static struct builtin builtin_root =
{
  "root",
  root_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "root [DEVICE [HDBIAS]]",
  "Set the current \"root device\" to the device DEVICE, then"
  " attempt to mount it to get the partition size (for passing the"
  " partition descriptor in `ES:ESI', used by some chain-loaded"
  " bootloaders), the BSD drive-type (for booting BSD kernels using"
  " their native boot format), and correctly determine "
  " the PC partition where a BSD sub-partition is located. The"
  " optional HDBIAS parameter is a number to tell a BSD kernel"
  " how many BIOS drive numbers are on controllers before the current"
  " one. For example, if there is an IDE disk and a SCSI disk, and your"
  " FreeBSD root partition is on the SCSI disk, then use a `1' for HDBIAS."
};


/* findroot */
int
findroot_func (char *arg, int flags)
{
  int ret;
  char root[32];

  if (grub_strlen(arg) >= BOOTSIGN_ARGLEN) {
  	errnum = ERR_BAD_ARGUMENT;
	return 1;
  }

  if (arg[0] == '\0') {
  	errnum = ERR_BAD_ARGUMENT;
	return 1;
  }

  find_best_root = 1;
  best_drive = 0;
  best_part = 0;
  ret = find_common(arg, root, 1, flags);
  if (ret != 0)
	return (ret);
  find_best_root = 0;

  return real_root_func (root, 1);
}

static struct builtin builtin_findroot =
{
  "findroot",
  findroot_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "findroot  <SIGNATURE | (SIGNATURE,partition[,slice])>",
  "Searches across all partitions for the file name SIGNATURE."
  " GRUB looks only in the directory /boot/grub/bootsign for the"
  " filename and it stops as soon as it finds the first instance of"
  " the file - so to be useful the name of the signature file must be"
  " unique across all partitions. Once the signature file is found,"
  " GRUB invokes the \"root\" command on that partition."
  " An optional partition and slice may be specified to optimize the search."
};


/*
 * COMMAND to override the default root filesystem for ZFS
 *	bootfs pool/fs
 */
static int
bootfs_func (char *arg, int flags)
{
	int hdbias = 0;
	char *biasptr;
	char *next;

	if (! *arg) {
	    if (current_bootfs[0] != '\0')
		grub_printf ("The zfs boot filesystem is set to '%s'.\n",
				current_bootfs);
	    else if (current_rootpool[0] != 0 && current_bootfs_obj != 0)
		grub_printf("The zfs boot filesystem is <default: %s/%u>.",
				current_rootpool, current_bootfs_obj);
	    else
		grub_printf ("The zfs boot filesystem will be derived from "
			"the default bootfs pool property.\n");

	    return (1);
	}

	/* Verify the zfs filesystem name */
	if (arg[0] == '/' || arg[0] == '\0') {
		errnum = ERR_BAD_ARGUMENT;
		return 0;
	}
	if (current_rootpool[0] != 0 && grub_strncmp(arg,
	    current_rootpool, strlen(current_rootpool))) {
		errnum = ERR_BAD_ARGUMENT;
		return 0;
	}

	grub_memmove(current_bootfs, arg, MAXNAMELEN);

	return (1);
}

static struct builtin builtin_bootfs =
{
  "bootfs",
  bootfs_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "bootfs [ZFSBOOTFS]",
  "Set the current zfs boot filesystem to ZFSBOOTFS (rootpool/rootfs)."
};


/* rootnoverify */
static int
rootnoverify_func (char *arg, int flags)
{
  return real_root_func (arg, 0);
}

static struct builtin builtin_rootnoverify =
{
  "rootnoverify",
  rootnoverify_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "rootnoverify [DEVICE [HDBIAS]]",
  "Similar to `root', but don't attempt to mount the partition. This"
  " is useful for when an OS is outside of the area of the disk that"
  " GRUB can read, but setting the correct root device is still"
  " desired. Note that the items mentioned in `root' which"
  " derived from attempting the mount will NOT work correctly."
};


/* savedefault */
static int
savedefault_func (char *arg, int flags)
{
#if !defined(SUPPORT_DISKLESS) && !defined(GRUB_UTIL)
  unsigned long tmp_drive = saved_drive;
  unsigned long tmp_partition = saved_partition;
  char *default_file = (char *) DEFAULT_FILE_BUF;
  char buf[10];
  char sect[SECTOR_SIZE];
  int entryno;
  int sector_count = 0;
  unsigned long long saved_sectors[2];
  int saved_offsets[2];
  int saved_lengths[2];

  /* not supported for zfs root */
  if (is_zfs_mount == 1) {
	return (0); /* no-op */
  }

  /* Save sector information about at most two sectors.  */
  auto void disk_read_savesect_func (unsigned long long sector, int offset,
      int length);
  void disk_read_savesect_func (unsigned long long sector, int offset, int length)
    {
      if (sector_count < 2)
	{
	  saved_sectors[sector_count] = sector;
	  saved_offsets[sector_count] = offset;
	  saved_lengths[sector_count] = length;
	}
      sector_count++;
    }
  
  /* This command is only useful when you boot an entry from the menu
     interface.  */
  if (! (flags & BUILTIN_SCRIPT))
    {
      errnum = ERR_UNRECOGNIZED;
      return 1;
    }

  /* Determine a saved entry number.  */
  if (*arg)
    {
      if (grub_memcmp (arg, "fallback", sizeof ("fallback") - 1) == 0)
	{
	  int i;
	  int index = 0;
	  
	  for (i = 0; i < MAX_FALLBACK_ENTRIES; i++)
	    {
	      if (fallback_entries[i] < 0)
		break;
	      if (fallback_entries[i] == current_entryno)
		{
		  index = i + 1;
		  break;
		}
	    }
	  
	  if (index >= MAX_FALLBACK_ENTRIES || fallback_entries[index] < 0)
	    {
	      /* This is the last.  */
	      errnum = ERR_BAD_ARGUMENT;
	      return 1;
	    }

	  entryno = fallback_entries[index];
	}
      else if (! safe_parse_maxint (&arg, &entryno))
	return 1;
    }
  else
    entryno = current_entryno;

  /* Open the default file.  */
  saved_drive = boot_drive;
  saved_partition = install_partition;
  if (grub_open (default_file))
    {
      int len;
      
      disk_read_hook = disk_read_savesect_func;
      len = grub_read (buf, sizeof (buf));
      disk_read_hook = 0;
      grub_close ();
      
      if (len != sizeof (buf))
	{
	  /* This is too small. Do not modify the file manually, please!  */
	  errnum = ERR_READ;
	  goto fail;
	}

      if (sector_count > 2)
	{
	  /* Is this possible?! Too fragmented!  */
	  errnum = ERR_FSYS_CORRUPT;
	  goto fail;
	}
      
      /* Set up a string to be written.  */
      grub_memset (buf, '\n', sizeof (buf));
      grub_sprintf (buf, "%d", entryno);
      
      if (saved_lengths[0] < sizeof (buf))
	{
	  /* The file is anchored to another file and the first few bytes
	     are spanned in two sectors. Uggh...  */
	  if (! rawread (current_drive, saved_sectors[0], 0, SECTOR_SIZE,
			 sect))
	    goto fail;
	  grub_memmove (sect + saved_offsets[0], buf, saved_lengths[0]);
	  if (! rawwrite (current_drive, saved_sectors[0], sect))
	    goto fail;

	  if (! rawread (current_drive, saved_sectors[1], 0, SECTOR_SIZE,
			 sect))
	    goto fail;
	  grub_memmove (sect + saved_offsets[1],
			buf + saved_lengths[0],
			sizeof (buf) - saved_lengths[0]);
	  if (! rawwrite (current_drive, saved_sectors[1], sect))
	    goto fail;
	}
      else
	{
	  /* This is a simple case. It fits into a single sector.  */
	  if (! rawread (current_drive, saved_sectors[0], 0, SECTOR_SIZE,
			 sect))
	    goto fail;
	  grub_memmove (sect + saved_offsets[0], buf, sizeof (buf));
	  if (! rawwrite (current_drive, saved_sectors[0], sect))
	    goto fail;
	}

      /* Clear the cache.  */
      buf_track = BUF_CACHE_INVALID;
    }

 fail:
  saved_drive = tmp_drive;
  saved_partition = tmp_partition;
  return errnum;
#else /* ! SUPPORT_DISKLESS && ! GRUB_UTIL */
  errnum = ERR_UNRECOGNIZED;
  return 1;
#endif /* ! SUPPORT_DISKLESS && ! GRUB_UTIL */
}

static struct builtin builtin_savedefault =
{
  "savedefault",
  savedefault_func,
  BUILTIN_CMDLINE,
  "savedefault [NUM | `fallback']",
  "Save the current entry as the default boot entry if no argument is"
  " specified. If a number is specified, this number is saved. If"
  " `fallback' is used, next fallback entry is saved."
};


#ifdef SUPPORT_SERIAL
/* serial */
static int
serial_func (char *arg, int flags)
{
  unsigned short port = serial_hw_get_port (0);
  unsigned int speed = 9600;
  int word_len = UART_8BITS_WORD;
  int parity = UART_NO_PARITY;
  int stop_bit_len = UART_1_STOP_BIT;

  /* Process GNU-style long options.
     FIXME: We should implement a getopt-like function, to avoid
     duplications.  */
  while (1)
    {
      if (grub_memcmp (arg, "--unit=", sizeof ("--unit=") - 1) == 0)
	{
	  char *p = arg + sizeof ("--unit=") - 1;
	  int unit;
	  
	  if (! safe_parse_maxint (&p, &unit))
	    return 1;
	  
	  if (unit < 0 || unit > 3)
	    {
	      errnum = ERR_DEV_VALUES;
	      return 1;
	    }

	  port = serial_hw_get_port (unit);
	}
      else if (grub_memcmp (arg, "--speed=", sizeof ("--speed=") - 1) == 0)
	{
	  char *p = arg + sizeof ("--speed=") - 1;
	  int num;
	  
	  if (! safe_parse_maxint (&p, &num))
	    return 1;

	  speed = (unsigned int) num;
	}
      else if (grub_memcmp (arg, "--port=", sizeof ("--port=") - 1) == 0)
	{
	  char *p = arg + sizeof ("--port=") - 1;
	  int num;
	  
	  if (! safe_parse_maxint (&p, &num))
	    return 1;

	  port = (unsigned short) num;
	}
      else if (grub_memcmp (arg, "--word=", sizeof ("--word=") - 1) == 0)
	{
	  char *p = arg + sizeof ("--word=") - 1;
	  int len;
	  
	  if (! safe_parse_maxint (&p, &len))
	    return 1;

	  switch (len)
	    {
	    case 5: word_len = UART_5BITS_WORD; break;
	    case 6: word_len = UART_6BITS_WORD; break;
	    case 7: word_len = UART_7BITS_WORD; break;
	    case 8: word_len = UART_8BITS_WORD; break;
	    default:
	      errnum = ERR_BAD_ARGUMENT;
	      return 1;
	    }
	}
      else if (grub_memcmp (arg, "--stop=", sizeof ("--stop=") - 1) == 0)
	{
	  char *p = arg + sizeof ("--stop=") - 1;
	  int len;
	  
	  if (! safe_parse_maxint (&p, &len))
	    return 1;

	  switch (len)
	    {
	    case 1: stop_bit_len = UART_1_STOP_BIT; break;
	    case 2: stop_bit_len = UART_2_STOP_BITS; break;
	    default:
	      errnum = ERR_BAD_ARGUMENT;
	      return 1;
	    }
	}
      else if (grub_memcmp (arg, "--parity=", sizeof ("--parity=") - 1) == 0)
	{
	  char *p = arg + sizeof ("--parity=") - 1;

	  if (grub_memcmp (p, "no", sizeof ("no") - 1) == 0)
	    parity = UART_NO_PARITY;
	  else if (grub_memcmp (p, "odd", sizeof ("odd") - 1) == 0)
	    parity = UART_ODD_PARITY;
	  else if (grub_memcmp (p, "even", sizeof ("even") - 1) == 0)
	    parity = UART_EVEN_PARITY;
	  else
	    {
	      errnum = ERR_BAD_ARGUMENT;
	      return 1;
	    }
	}
# ifdef GRUB_UTIL
      /* In the grub shell, don't use any port number but open a tty
	 device instead.  */
      else if (grub_memcmp (arg, "--device=", sizeof ("--device=") - 1) == 0)
	{
	  char *p = arg + sizeof ("--device=") - 1;
	  char dev[256];	/* XXX */
	  char *q = dev;
	  
	  while (*p && ! grub_isspace (*p))
	    *q++ = *p++;
	  
	  *q = 0;
	  serial_set_device (dev);
	}
# endif /* GRUB_UTIL */
      else
	break;

      arg = skip_to (0, arg);
    }

  /* Initialize the serial unit.  */
  if (! serial_hw_init (port, speed, word_len, parity, stop_bit_len))
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }
  
  return 0;
}

static struct builtin builtin_serial =
{
  "serial",
  serial_func,
  BUILTIN_MENU | BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "serial [--unit=UNIT] [--port=PORT] [--speed=SPEED] [--word=WORD] [--parity=PARITY] [--stop=STOP] [--device=DEV]",
  "Initialize a serial device. UNIT is a digit that specifies which serial"
  " device is used (e.g. 0 == COM1). If you need to specify the port number,"
  " set it by --port. SPEED is the DTE-DTE speed. WORD is the word length,"
  " PARITY is the type of parity, which is one of `no', `odd' and `even'."
  " STOP is the length of stop bit(s). The option --device can be used only"
  " in the grub shell, which specifies the file name of a tty device. The"
  " default values are COM1, 9600, 8N1."
};
#endif /* SUPPORT_SERIAL */


/* setkey */
struct keysym
{
  char *unshifted_name;			/* the name in unshifted state */
  char *shifted_name;			/* the name in shifted state */
  unsigned char unshifted_ascii;	/* the ascii code in unshifted state */
  unsigned char shifted_ascii;		/* the ascii code in shifted state */
  unsigned char keycode;		/* keyboard scancode */
};

/* The table for key symbols. If the "shifted" member of an entry is
   NULL, the entry does not have shifted state.  */
static struct keysym keysym_table[] =
{
  {"escape",		0,		0x1b,	0,	0x01},
  {"1",			"exclam",	'1',	'!',	0x02},
  {"2",			"at",		'2',	'@',	0x03},
  {"3",			"numbersign",	'3',	'#',	0x04},
  {"4",			"dollar",	'4',	'$',	0x05},
  {"5",			"percent",	'5',	'%',	0x06},
  {"6",			"caret",	'6',	'^',	0x07},
  {"7",			"ampersand",	'7',	'&',	0x08},
  {"8",			"asterisk",	'8',	'*',	0x09},
  {"9",			"parenleft",	'9',	'(',	0x0a},
  {"0",			"parenright",	'0',	')',	0x0b},
  {"minus",		"underscore",	'-',	'_',	0x0c},
  {"equal",		"plus",		'=',	'+',	0x0d},
  {"backspace",		0,		'\b',	0,	0x0e},
  {"tab",		0,		'\t',	0,	0x0f},
  {"q",			"Q",		'q',	'Q',	0x10},
  {"w",			"W",		'w',	'W',	0x11},
  {"e",			"E",		'e',	'E',	0x12},
  {"r",			"R",		'r',	'R',	0x13},
  {"t",			"T",		't',	'T',	0x14},
  {"y",			"Y",		'y',	'Y',	0x15},
  {"u",			"U",		'u',	'U',	0x16},
  {"i",			"I",		'i',	'I',	0x17},
  {"o",			"O",		'o',	'O',	0x18},
  {"p",			"P",		'p',	'P',	0x19},
  {"bracketleft",	"braceleft",	'[',	'{',	0x1a},
  {"bracketright",	"braceright",	']',	'}',	0x1b},
  {"enter",		0,		'\n',	0,	0x1c},
  {"control",		0,		0,	0,	0x1d},
  {"a",			"A",		'a',	'A',	0x1e},
  {"s",			"S",		's',	'S',	0x1f},
  {"d",			"D",		'd',	'D',	0x20},
  {"f",			"F",		'f',	'F',	0x21},
  {"g",			"G",		'g',	'G',	0x22},
  {"h",			"H",		'h',	'H',	0x23},
  {"j",			"J",		'j',	'J',	0x24},
  {"k",			"K",		'k',	'K',	0x25},
  {"l",			"L",		'l',	'L',	0x26},
  {"semicolon",		"colon",	';',	':',	0x27},
  {"quote",		"doublequote",	'\'',	'"',	0x28},
  {"backquote",		"tilde",	'`',	'~',	0x29},
  {"shift",		0,		0,	0,	0x2a},
  {"backslash",		"bar",		'\\',	'|',	0x2b},
  {"z",			"Z",		'z',	'Z',	0x2c},
  {"x",			"X",		'x',	'X',	0x2d},
  {"c",			"C",		'c',	'C',	0x2e},
  {"v",			"V",		'v',	'V',	0x2f},
  {"b",			"B",		'b',	'B',	0x30},
  {"n",			"N",		'n',	'N',	0x31},
  {"m",			"M",		'm',	'M',	0x32},
  {"comma",		"less",		',',	'<',	0x33},
  {"period",		"greater",	'.',	'>',	0x34},
  {"slash",		"question",	'/',	'?',	0x35},
  {"alt",		0,		0,	0,	0x38},
  {"space",		0,		' ',	0,	0x39},
  {"capslock",		0,		0,	0,	0x3a},
  {"F1",		0,		0,	0,	0x3b},
  {"F2",		0,		0,	0,	0x3c},
  {"F3",		0,		0,	0,	0x3d},
  {"F4",		0,		0,	0,	0x3e},
  {"F5",		0,		0,	0,	0x3f},
  {"F6",		0,		0,	0,	0x40},
  {"F7",		0,		0,	0,	0x41},
  {"F8",		0,		0,	0,	0x42},
  {"F9",		0,		0,	0,	0x43},
  {"F10",		0,		0,	0,	0x44},
  /* Caution: do not add NumLock here! we cannot deal with it properly.  */
  {"delete",		0,		0x7f,	0,	0x53}
};

static int
setkey_func (char *arg, int flags)
{
  char *to_key, *from_key;
  int to_code, from_code;
  int map_in_interrupt = 0;
  
  auto int find_key_code (char *key);
  auto int find_ascii_code (char *key);

  auto int find_key_code (char *key)
    {
      int i;

      for (i = 0; i < sizeof (keysym_table) / sizeof (keysym_table[0]); i++)
	{
	  if (keysym_table[i].unshifted_name &&
	      grub_strcmp (key, keysym_table[i].unshifted_name) == 0)
	    return keysym_table[i].keycode;
	  else if (keysym_table[i].shifted_name &&
		   grub_strcmp (key, keysym_table[i].shifted_name) == 0)
	    return keysym_table[i].keycode;
	}
      
      return 0;
    }
  
  auto int find_ascii_code (char *key)
    {
      int i;
      
      for (i = 0; i < sizeof (keysym_table) / sizeof (keysym_table[0]); i++)
	{
	  if (keysym_table[i].unshifted_name &&
	      grub_strcmp (key, keysym_table[i].unshifted_name) == 0)
	    return keysym_table[i].unshifted_ascii;
	  else if (keysym_table[i].shifted_name &&
		   grub_strcmp (key, keysym_table[i].shifted_name) == 0)
	    return keysym_table[i].shifted_ascii;
	}
      
      return 0;
    }
  
  to_key = arg;
  from_key = skip_to (0, to_key);

  if (! *to_key)
    {
      /* If the user specifies no argument, reset the key mappings.  */
      grub_memset (bios_key_map, 0, KEY_MAP_SIZE * sizeof (unsigned short));
      grub_memset (ascii_key_map, 0, KEY_MAP_SIZE * sizeof (unsigned short));

      return 0;
    }
  else if (! *from_key)
    {
      /* The user must specify two arguments or zero argument.  */
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }
  
  nul_terminate (to_key);
  nul_terminate (from_key);
  
  to_code = find_ascii_code (to_key);
  from_code = find_ascii_code (from_key);
  if (! to_code || ! from_code)
    {
      map_in_interrupt = 1;
      to_code = find_key_code (to_key);
      from_code = find_key_code (from_key);
      if (! to_code || ! from_code)
	{
	  errnum = ERR_BAD_ARGUMENT;
	  return 1;
	}
    }
  
  if (map_in_interrupt)
    {
      int i;
      
      /* Find an empty slot.  */
      for (i = 0; i < KEY_MAP_SIZE; i++)
	{
	  if ((bios_key_map[i] & 0xff) == from_code)
	    /* Perhaps the user wants to overwrite the map.  */
	    break;
	  
	  if (! bios_key_map[i])
	    break;
	}
      
      if (i == KEY_MAP_SIZE)
	{
	  errnum = ERR_WONT_FIT;
	  return 1;
	}
      
      if (to_code == from_code)
	/* If TO is equal to FROM, delete the entry.  */
	grub_memmove ((char *) &bios_key_map[i],
		      (char *) &bios_key_map[i + 1],
		      sizeof (unsigned short) * (KEY_MAP_SIZE - i));
      else
	bios_key_map[i] = (to_code << 8) | from_code;
      
      /* Ugly but should work.  */
      unset_int15_handler ();
      set_int15_handler ();
    }
  else
    {
      int i;
      
      /* Find an empty slot.  */
      for (i = 0; i < KEY_MAP_SIZE; i++)
	{
	  if ((ascii_key_map[i] & 0xff) == from_code)
	    /* Perhaps the user wants to overwrite the map.  */
	    break;
	  
	  if (! ascii_key_map[i])
	    break;
	}
      
      if (i == KEY_MAP_SIZE)
	{
	  errnum = ERR_WONT_FIT;
	  return 1;
	}
      
      if (to_code == from_code)
	/* If TO is equal to FROM, delete the entry.  */
	grub_memmove ((char *) &ascii_key_map[i],
		      (char *) &ascii_key_map[i + 1],
		      sizeof (unsigned short) * (KEY_MAP_SIZE - i));
      else
	ascii_key_map[i] = (to_code << 8) | from_code;
    }
      
  return 0;
}

static struct builtin builtin_setkey =
{
  "setkey",
  setkey_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST,
  "setkey [TO_KEY FROM_KEY]",
  "Change the keyboard map. The key FROM_KEY is mapped to the key TO_KEY."
  " A key must be an alphabet, a digit, or one of these: escape, exclam,"
  " at, numbersign, dollar, percent, caret, ampersand, asterisk, parenleft,"
  " parenright, minus, underscore, equal, plus, backspace, tab, bracketleft,"
  " braceleft, bracketright, braceright, enter, control, semicolon, colon,"
  " quote, doublequote, backquote, tilde, shift, backslash, bar, comma,"
  " less, period, greater, slash, question, alt, space, capslock, FX (X"
  " is a digit), and delete. If no argument is specified, reset key"
  " mappings."
};


/* setup */
static int
setup_func (char *arg, int flags)
{
  /* Point to the string of the installed drive/partition.  */
  char *install_ptr;
  /* Point to the string of the drive/parition where the GRUB images
     reside.  */
  char *image_ptr;
  unsigned long installed_drive, installed_partition;
  unsigned long image_drive, image_partition;
  unsigned long tmp_drive, tmp_partition;
  char stage1[64];
  char stage2[64];
  char config_filename[64];
  char real_config_filename[64];
  char cmd_arg[256];
  char device[16];
  char *buffer = (char *) RAW_ADDR (0x100000);
  int is_force_lba = 0;
  char *stage2_arg = 0;
  char *prefix = 0;

  auto int check_file (char *file);
  auto void sprint_device (int drive, int partition);
  auto int embed_stage1_5 (char * stage1_5, int drive, int partition);
  
  /* Check if the file FILE exists like Autoconf.  */
  int check_file (char *file)
    {
      int ret;
      
      grub_printf (" Checking if \"%s\" exists... ", file);
      ret = grub_open (file);
      if (ret)
	{
	  grub_close ();
	  grub_printf ("yes\n");
	}
      else
	grub_printf ("no\n");

      return ret;
    }
  
  /* Construct a device name in DEVICE.  */
  void sprint_device (int drive, int partition)
    {
      grub_sprintf (device, "(%cd%d",
		    (drive & 0x80) ? 'h' : 'f',
		    drive & ~0x80);
      if ((partition & 0xFF0000) != 0xFF0000)
	{
	  char tmp[16];
	  grub_sprintf (tmp, ",%d", (partition >> 16) & 0xFF);
	  grub_strncat (device, tmp, sizeof (device));
	}
      if ((partition & 0x00FF00) != 0x00FF00)
	{
	  char tmp[16];
	  grub_sprintf (tmp, ",%c", 'a' + ((partition >> 8) & 0xFF));
	  grub_strncat (device, tmp, sizeof (device));
	}
      grub_strncat (device, ")", sizeof (device));
    }
  
  int embed_stage1_5 (char *stage1_5, int drive, int partition)
    {
      /* We install GRUB into the MBR, so try to embed the
	 Stage 1.5 in the sectors right after the MBR.  */
      sprint_device (drive, partition);
      grub_sprintf (cmd_arg, "%s %s", stage1_5, device);
	      
      /* Notify what will be run.  */
      grub_printf (" Running \"embed %s\"... ", cmd_arg);
      
      embed_func (cmd_arg, flags);
      if (! errnum)
	{
	  /* Construct the blocklist representation.  */
	  grub_sprintf (buffer, "%s%s", device, embed_info);
	  grub_printf ("succeeded\n");
	  return 1;
	}
      else
	{
	  grub_printf ("failed (this is not fatal)\n");
	  return 0;
	}
    }
	  
  struct stage1_5_map {
    char *fsys;
    char *name;
  };
  struct stage1_5_map stage1_5_map[] =
  {
    {"ext2fs",   "/e2fs_stage1_5"},
    {"fat",      "/fat_stage1_5"},
    {"ufs2",     "/ufs2_stage1_5"},
    {"ffs",      "/ffs_stage1_5"},
    {"iso9660",  "/iso9660_stage1_5"},
    {"jfs",      "/jfs_stage1_5"},
    {"minix",    "/minix_stage1_5"},
    {"reiserfs", "/reiserfs_stage1_5"},
    {"vstafs",   "/vstafs_stage1_5"},
    {"xfs",      "/xfs_stage1_5"},
    {"ufs",      "/ufs_stage1_5"}
  };

  tmp_drive = saved_drive;
  tmp_partition = saved_partition;

  /* Check if the user specifies --force-lba.  */
  while (1)
    {
      if (grub_memcmp ("--force-lba", arg, sizeof ("--force-lba") - 1) == 0)
	{
	  is_force_lba = 1;
	  arg = skip_to (0, arg);
	}
      else if (grub_memcmp ("--prefix=", arg, sizeof ("--prefix=") - 1) == 0)
	{
	  prefix = arg + sizeof ("--prefix=") - 1;
	  arg = skip_to (0, arg);
	  nul_terminate (prefix);
	}
#ifdef GRUB_UTIL
      else if (grub_memcmp ("--stage2=", arg, sizeof ("--stage2=") - 1) == 0)
	{
	  stage2_arg = arg;
	  arg = skip_to (0, arg);
	  nul_terminate (stage2_arg);
	}
#endif /* GRUB_UTIL */
      else
	break;
    }
  
  install_ptr = arg;
  image_ptr = skip_to (0, install_ptr);

  /* Make sure that INSTALL_PTR is valid.  */
  set_device (install_ptr);
  if (errnum)
    return 1;

  installed_drive = current_drive;
  installed_partition = current_partition;
  
  /* Mount the drive pointed by IMAGE_PTR.  */
  if (*image_ptr)
    {
      /* If the drive/partition where the images reside is specified,
	 get the drive and the partition.  */
      set_device (image_ptr);
      if (errnum)
	return 1;
    }
  else
    {
      /* If omitted, use SAVED_PARTITION and SAVED_DRIVE.  */
      current_drive = saved_drive;
      current_partition = saved_partition;
    }

  image_drive = saved_drive = current_drive;
  image_partition = saved_partition = current_partition;

  /* Open it.  */
  if (! open_device ())
    goto fail;

  /* Check if stage1 exists. If the user doesn't specify the option
     `--prefix', attempt /boot/grub and /grub.  */
  /* NOTE: It is dangerous to run this command without `--prefix' in the
     grub shell, since that affects `--stage2'.  */
  if (! prefix)
    {
      prefix = "/boot/grub";
      grub_sprintf (stage1, "%s%s", prefix, "/stage1");
      if (! check_file (stage1))
	{
	  errnum = ERR_NONE;
	  prefix = "/grub";
	  grub_sprintf (stage1, "%s%s", prefix, "/stage1");
	  if (! check_file (stage1))
	    goto fail;
	}
    }
  else
    {
      grub_sprintf (stage1, "%s%s", prefix, "/stage1");
      if (! check_file (stage1))
	goto fail;
    }

  /* The prefix was determined.  */
  grub_sprintf (stage2, "%s%s", prefix, "/stage2");
  grub_sprintf (config_filename, "%s%s", prefix, "/menu.lst");
  *real_config_filename = 0;

  /* Check if stage2 exists.  */
  if (! check_file (stage2))
    goto fail;

  {
    char *fsys = fsys_table[fsys_type].name;
    int i;
    int size = sizeof (stage1_5_map) / sizeof (stage1_5_map[0]);
    
    /* Iterate finding the same filesystem name as FSYS.  */
    for (i = 0; i < size; i++)
      if (grub_strcmp (fsys, stage1_5_map[i].fsys) == 0)
	{
	  /* OK, check if the Stage 1.5 exists.  */
	  char stage1_5[64];
	  
	  grub_sprintf (stage1_5, "%s%s", prefix, stage1_5_map[i].name);
	  if (check_file (stage1_5))
	    {
	      if (embed_stage1_5 (stage1_5, 
				    installed_drive, installed_partition)
		  || embed_stage1_5 (stage1_5, 
				     image_drive, image_partition))
		{
		  grub_strcpy (real_config_filename, config_filename);
		  sprint_device (image_drive, image_partition);
		  grub_sprintf (config_filename, "%s%s", device, stage2);
		  grub_strcpy (stage2, buffer);
		}
	    }
	  errnum = 0;
	  break;
	}
  }

  /* Construct a string that is used by the command "install" as its
     arguments.  */
  sprint_device (installed_drive, installed_partition);
  
#if 1
  /* Don't embed a drive number unnecessarily.  */
  grub_sprintf (cmd_arg, "%s%s%s%s %s%s %s p %s %s",
		is_force_lba? "--force-lba " : "",
		stage2_arg? stage2_arg : "",
		stage2_arg? " " : "",
		stage1,
		(installed_drive != image_drive) ? "d " : "",
		device,
		stage2,
		config_filename,
		real_config_filename);
#else /* NOT USED */
  /* This code was used, because we belived some BIOSes had a problem
     that they didn't pass a booting drive correctly. It turned out,
     however, stage1 could trash a booting drive when checking LBA support,
     because some BIOSes modified the register %dx in INT 13H, AH=48H.
     So it becamed unclear whether GRUB should use a pre-defined booting
     drive or not. If the problem still exists, it would be necessary to
     switch back to this code.  */
  grub_sprintf (cmd_arg, "%s%s%s%s d %s %s p %s %s",
		is_force_lba? "--force-lba " : "",
		stage2_arg? stage2_arg : "",
		stage2_arg? " " : "",
		stage1,
		device,
		stage2,
		config_filename,
		real_config_filename);
#endif /* NOT USED */
  
  /* Notify what will be run.  */
  grub_printf (" Running \"install %s\"... ", cmd_arg);

  /* Make sure that SAVED_DRIVE and SAVED_PARTITION are identical
     with IMAGE_DRIVE and IMAGE_PARTITION, respectively.  */
  saved_drive = image_drive;
  saved_partition = image_partition;
  
  /* Run the command.  */
  if (! install_func (cmd_arg, flags))
    grub_printf ("succeeded\nDone.\n");
  else
    grub_printf ("failed\n");

 fail:
  saved_drive = tmp_drive;
  saved_partition = tmp_partition;
  return errnum;
}

static struct builtin builtin_setup =
{
  "setup",
  setup_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "setup [--prefix=DIR] [--stage2=STAGE2_FILE] [--force-lba] INSTALL_DEVICE [IMAGE_DEVICE]",
  "Set up the installation of GRUB automatically. This command uses"
  " the more flexible command \"install\" in the backend and installs"
  " GRUB into the device INSTALL_DEVICE. If IMAGE_DEVICE is specified,"
  " then find the GRUB images in the device IMAGE_DEVICE, otherwise"
  " use the current \"root device\", which can be set by the command"
  " \"root\". If you know that your BIOS should support LBA but GRUB"
  " doesn't work in LBA mode, specify the option `--force-lba'."
  " If you install GRUB under the grub shell and you cannot unmount the"
  " partition where GRUB images reside, specify the option `--stage2'"
  " to tell GRUB the file name under your OS."
};


#if defined(SUPPORT_SERIAL) || defined(SUPPORT_HERCULES) || defined(SUPPORT_GRAPHICS)
/* terminal */
static int
terminal_func (char *arg, int flags)
{
  /* The index of the default terminal in TERM_TABLE.  */
  int default_term = -1;
  struct term_entry *prev_term = current_term;
  int to = -1;
  int lines = 0;
  int no_message = 0;
  unsigned long term_flags = 0;
  /* XXX: Assume less than 32 terminals.  */
  unsigned long term_bitmap = 0;

  /* Get GNU-style long options.  */
  while (1)
    {
      if (grub_memcmp (arg, "--dumb", sizeof ("--dumb") - 1) == 0)
	term_flags |= TERM_DUMB;
      else if (grub_memcmp (arg, "--no-echo", sizeof ("--no-echo") - 1) == 0)
	/* ``--no-echo'' implies ``--no-edit''.  */
	term_flags |= (TERM_NO_ECHO | TERM_NO_EDIT);
      else if (grub_memcmp (arg, "--no-edit", sizeof ("--no-edit") - 1) == 0)
	term_flags |= TERM_NO_EDIT;
      else if (grub_memcmp (arg, "--timeout=", sizeof ("--timeout=") - 1) == 0)
	{
	  char *val = arg + sizeof ("--timeout=") - 1;
	  
	  if (! safe_parse_maxint (&val, &to))
	    return 1;
	}
      else if (grub_memcmp (arg, "--lines=", sizeof ("--lines=") - 1) == 0)
	{
	  char *val = arg + sizeof ("--lines=") - 1;

	  if (! safe_parse_maxint (&val, &lines))
	    return 1;

	  /* Probably less than four is meaningless....  */
	  if (lines < 4)
	    {
	      errnum = ERR_BAD_ARGUMENT;
	      return 1;
	    }
	}
      else if (grub_memcmp (arg, "--silent", sizeof ("--silent") - 1) == 0)
	no_message = 1;
      else
	break;

      arg = skip_to (0, arg);
    }
  
  /* If no argument is specified, show current setting.  */
  if (! *arg)
    {
      grub_printf ("%s%s%s%s\n",
		   current_term->name,
		   current_term->flags & TERM_DUMB ? " (dumb)" : "",
		   current_term->flags & TERM_NO_EDIT ? " (no edit)" : "",
		   current_term->flags & TERM_NO_ECHO ? " (no echo)" : "");
      return 0;
    }

  while (*arg)
    {
      int i;
      char *next = skip_to (0, arg);
      
      nul_terminate (arg);

      for (i = 0; term_table[i].name; i++)
	{
	  if (grub_strcmp (arg, term_table[i].name) == 0)
	    {
	      if (term_table[i].flags & TERM_NEED_INIT)
		{
		  errnum = ERR_DEV_NEED_INIT;
		  return 1;
		}
	      
	      if (default_term < 0)
		default_term = i;

	      term_bitmap |= (1 << i);
	      break;
	    }
	}

      if (! term_table[i].name)
	{
	  errnum = ERR_BAD_ARGUMENT;
	  return 1;
	}

      arg = next;
    }

  /* If multiple terminals are specified, wait until the user pushes any
     key on one of the terminals.  */
  if (term_bitmap & ~(1 << default_term))
    {
      int time1, time2 = -1;

      /* XXX: Disable the pager.  */
      count_lines = -1;
      
      /* Get current time.  */
      while ((time1 = getrtsecs ()) == 0xFF)
	;

      /* Wait for a key input.  */
      while (to)
	{
	  int i;

	  for (i = 0; term_table[i].name; i++)
	    {
	      if (term_bitmap & (1 << i))
		{
		  if (term_table[i].checkkey () >= 0)
		    {
		      (void) term_table[i].getkey ();
		      default_term = i;
		      
		      goto end;
		    }
		}
	    }
	  
	  /* Prompt the user, once per sec.  */
	  if ((time1 = getrtsecs ()) != time2 && time1 != 0xFF)
	    {
	      if (! no_message)
		{
		  /* Need to set CURRENT_TERM to each of selected
		     terminals.  */
		  for (i = 0; term_table[i].name; i++)
		    if (term_bitmap & (1 << i))
		      {
			current_term = term_table + i;
			grub_printf ("\rPress any key to continue.\n");
		      }
		  
		  /* Restore CURRENT_TERM.  */
		  current_term = prev_term;
		}
	      
	      time2 = time1;
	      if (to > 0)
		to--;
	    }
	}
    }

 end:
  current_term = term_table + default_term;
  current_term->flags = term_flags;

  if (lines)
    max_lines = lines;
  else
    max_lines = current_term->max_lines;

  /* If the interface is currently the command-line,
     restart it to repaint the screen.  */
  if ((current_term != prev_term) && (flags & BUILTIN_CMDLINE)){
    if (prev_term->shutdown)
      prev_term->shutdown();
    if (current_term->startup)
      current_term->startup();
    grub_longjmp (restart_cmdline_env, 0);
  }
  
  return 0;
}

static struct builtin builtin_terminal =
{
  "terminal",
  terminal_func,
  BUILTIN_MENU | BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "terminal [--dumb] [--no-echo] [--no-edit] [--timeout=SECS] [--lines=LINES] [--silent] [console] [serial] [hercules] [graphics] [composite]",
  "Select a terminal. When multiple terminals are specified, wait until"
  " you push any key to continue. If both console and serial are specified,"
  " the terminal to which you input a key first will be selected. If no"
  " argument is specified, print current setting. To accomodate systems"
  " where console redirection may or may not be present, the composite"
  " console will direct output to the serial and BIOS consoles, and accept"
  " input from either one, without requiring selection. The option --dumb"
  " specifies that your terminal is dumb, otherwise, vt100-compatibility"
  " is assumed. If you specify --no-echo, input characters won't be echoed."
  " If you specify --no-edit, the BASH-like editing feature will be disabled."
  " If --timeout is present, this command will wait at most for SECS"
  " seconds. The option --lines specifies the maximum number of lines."
  " The option --silent is used to suppress messages."
};
#endif /* SUPPORT_SERIAL || SUPPORT_HERCULES || SUPPORT_GRAPHICS */


#ifdef SUPPORT_SERIAL
static int
terminfo_func (char *arg, int flags)
{
  struct terminfo term;

  if (*arg)
    {
      struct
      {
	const char *name;
	char *var;
      }
      options[] =
	{
	  {"--name=", term.name},
	  {"--cursor-address=", term.cursor_address},
	  {"--clear-screen=", term.clear_screen},
	  {"--enter-standout-mode=", term.enter_standout_mode},
	  {"--exit-standout-mode=", term.exit_standout_mode}
	};

      grub_memset (&term, 0, sizeof (term));
      
      while (*arg)
	{
	  int i;
	  char *next = skip_to (0, arg);
	      
	  nul_terminate (arg);
	  
	  for (i = 0; i < sizeof (options) / sizeof (options[0]); i++)
	    {
	      const char *name = options[i].name;
	      int len = grub_strlen (name);
	      
	      if (! grub_memcmp (arg, name, len))
		{
		  grub_strcpy (options[i].var, ti_unescape_string (arg + len));
		  break;
		}
	    }

	  if (i == sizeof (options) / sizeof (options[0]))
	    {
	      errnum = ERR_BAD_ARGUMENT;
	      return errnum;
	    }

	  arg = next;
	}

      if (term.name[0] == 0 || term.cursor_address[0] == 0)
	{
	  errnum = ERR_BAD_ARGUMENT;
	  return errnum;
	}

      ti_set_term (&term);
    }
  else
    {
      /* No option specifies printing out current settings.  */
      ti_get_term (&term);

      grub_printf ("name=%s\n",
		   ti_escape_string (term.name));
      grub_printf ("cursor_address=%s\n",
		   ti_escape_string (term.cursor_address));
      grub_printf ("clear_screen=%s\n",
		   ti_escape_string (term.clear_screen));
      grub_printf ("enter_standout_mode=%s\n",
		   ti_escape_string (term.enter_standout_mode));
      grub_printf ("exit_standout_mode=%s\n",
		   ti_escape_string (term.exit_standout_mode));
    }

  return 0;
}

static struct builtin builtin_terminfo =
{
  "terminfo",
  terminfo_func,
  BUILTIN_MENU | BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "terminfo [--name=NAME --cursor-address=SEQ [--clear-screen=SEQ]"
  " [--enter-standout-mode=SEQ] [--exit-standout-mode=SEQ]]",
  
  "Define the capabilities of your terminal. Use this command to"
  " define escape sequences, if it is not vt100-compatible."
  " You may use \\e for ESC and ^X for a control character."
  " If no option is specified, the current settings are printed."
};
#endif /* SUPPORT_SERIAL */
	  

/* testload */
static int
testload_func (char *arg, int flags)
{
  int i;

  kernel_type = KERNEL_TYPE_NONE;

  if (! grub_open (arg))
    return 1;

  disk_read_hook = disk_read_print_func;

  /* Perform filesystem test on the specified file.  */
  /* Read whole file first. */
  grub_printf ("Whole file: ");

  grub_read ((char *) RAW_ADDR (0x100000), -1);

  /* Now compare two sections of the file read differently.  */

  for (i = 0; i < 0x10ac0; i++)
    {
      *((unsigned char *) RAW_ADDR (0x200000 + i)) = 0;
      *((unsigned char *) RAW_ADDR (0x300000 + i)) = 1;
    }

  /* First partial read.  */
  grub_printf ("\nPartial read 1: ");

  grub_seek (0);
  grub_read ((char *) RAW_ADDR (0x200000), 0x7);
  grub_read ((char *) RAW_ADDR (0x200007), 0x100);
  grub_read ((char *) RAW_ADDR (0x200107), 0x10);
  grub_read ((char *) RAW_ADDR (0x200117), 0x999);
  grub_read ((char *) RAW_ADDR (0x200ab0), 0x10);
  grub_read ((char *) RAW_ADDR (0x200ac0), 0x10000);

  /* Second partial read.  */
  grub_printf ("\nPartial read 2: ");

  grub_seek (0);
  grub_read ((char *) RAW_ADDR (0x300000), 0x10000);
  grub_read ((char *) RAW_ADDR (0x310000), 0x10);
  grub_read ((char *) RAW_ADDR (0x310010), 0x7);
  grub_read ((char *) RAW_ADDR (0x310017), 0x10);
  grub_read ((char *) RAW_ADDR (0x310027), 0x999);
  grub_read ((char *) RAW_ADDR (0x3109c0), 0x100);

  grub_printf ("\nHeader1 = 0x%x, next = 0x%x, next = 0x%x, next = 0x%x\n",
	       *((int *) RAW_ADDR (0x200000)),
	       *((int *) RAW_ADDR (0x200004)),
	       *((int *) RAW_ADDR (0x200008)),
	       *((int *) RAW_ADDR (0x20000c)));

  grub_printf ("Header2 = 0x%x, next = 0x%x, next = 0x%x, next = 0x%x\n",
	       *((int *) RAW_ADDR (0x300000)),
	       *((int *) RAW_ADDR (0x300004)),
	       *((int *) RAW_ADDR (0x300008)),
	       *((int *) RAW_ADDR (0x30000c)));

  for (i = 0; i < 0x10ac0; i++)
    if (*((unsigned char *) RAW_ADDR (0x200000 + i))
	!= *((unsigned char *) RAW_ADDR (0x300000 + i)))
      break;

  grub_printf ("Max is 0x10ac0: i=0x%x, filepos=0x%x\n", i, filepos);
  disk_read_hook = 0;
  grub_close ();
  return 0;
}

static struct builtin builtin_testload =
{
  "testload",
  testload_func,
  BUILTIN_CMDLINE,
  "testload FILE",
  "Read the entire contents of FILE in several different ways and"
  " compares them, to test the filesystem code. The output is somewhat"
  " cryptic, but if no errors are reported and the final `i=X,"
  " filepos=Y' reading has X and Y equal, then it is definitely"
  " consistent, and very likely works correctly subject to a"
  " consistent offset error. If this test succeeds, then a good next"
  " step is to try loading a kernel."
};


/* testvbe MODE */
static int
testvbe_func (char *arg, int flags)
{
  int mode_number;
  struct vbe_controller controller;
  struct vbe_mode mode;
  
  if (! *arg)
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }

  if (! safe_parse_maxint (&arg, &mode_number))
    return 1;

  /* Preset `VBE2'.  */
  grub_memmove (controller.signature, "VBE2", 4);

  /* Detect VBE BIOS.  */
  if (get_vbe_controller_info (&controller) != 0x004F)
    {
      grub_printf (" VBE BIOS is not present.\n");
      return 0;
    }
  
  if (controller.version < 0x0200)
    {
      grub_printf (" VBE version %d.%d is not supported.\n",
		   (int) (controller.version >> 8),
		   (int) (controller.version & 0xFF));
      return 0;
    }

  if (get_vbe_mode_info (mode_number, &mode) != 0x004F
      || (mode.mode_attributes & 0x0091) != 0x0091)
    {
      grub_printf (" Mode 0x%x is not supported.\n", mode_number);
      return 0;
    }

  /* Now trip to the graphics mode.  */
  if (set_vbe_mode (mode_number | (1 << 14)) != 0x004F)
    {
      grub_printf (" Switching to Mode 0x%x failed.\n", mode_number);
      return 0;
    }

  /* Draw something on the screen...  */
  {
    unsigned char *base_buf = (unsigned char *) mode.phys_base;
    int scanline = controller.version >= 0x0300
      ? mode.linear_bytes_per_scanline : mode.bytes_per_scanline;
    /* FIXME: this assumes that any depth is a modulo of 8.  */
    int bpp = mode.bits_per_pixel / 8;
    int width = mode.x_resolution;
    int height = mode.y_resolution;
    int x, y;
    unsigned color = 0;

    /* Iterate drawing on the screen, until the user hits any key.  */
    while (checkkey () == -1)
      {
	for (y = 0; y < height; y++)
	  {
	    unsigned char *line_buf = base_buf + scanline * y;
	    
	    for (x = 0; x < width; x++)
	      {
		unsigned char *buf = line_buf + bpp * x;
		int i;

		for (i = 0; i < bpp; i++, buf++)
		  *buf = (color >> (i * 8)) & 0xff;
	      }

	    color++;
	  }
      }

    /* Discard the input.  */
    getkey ();
  }
  
  /* Back to the default text mode.  */
  if (set_vbe_mode (0x03) != 0x004F)
    {
      /* Why?!  */
      grub_reboot ();
    }

  return 0;
}

static struct builtin builtin_testvbe =
{
  "testvbe",
  testvbe_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "testvbe MODE",
  "Test the VBE mode MODE. Hit any key to return."
};


#ifdef SUPPORT_NETBOOT
/* tftpserver */
static int
tftpserver_func (char *arg, int flags)
{
  if (! *arg || ! ifconfig (0, 0, 0, arg))
    {
      errnum = ERR_BAD_ARGUMENT;
      return 1;
    }

  print_network_configuration ();
  return 0;
}

static struct builtin builtin_tftpserver =
{
  "tftpserver",
  tftpserver_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST,
  "tftpserver IPADDR",
  "Override the TFTP server address."
};
#endif /* SUPPORT_NETBOOT */


/* timeout */
static int
timeout_func (char *arg, int flags)
{
  if (! safe_parse_maxint (&arg, &grub_timeout))
    return 1;

  return 0;
}

static struct builtin builtin_timeout =
{
  "timeout",
  timeout_func,
  BUILTIN_MENU,
#if 0
  "timeout SEC",
  "Set a timeout, in SEC seconds, before automatically booting the"
  " default entry (normally the first entry defined)."
#endif
};


/* title */
static int
title_func (char *arg, int flags)
{
  /* This function is not actually used at least currently.  */
  return 0;
}

static struct builtin builtin_title =
{
  "title",
  title_func,
  BUILTIN_TITLE,
#if 0
  "title [NAME ...]",
  "Start a new boot entry, and set its name to the contents of the"
  " rest of the line, starting with the first non-space character."
#endif
};


/* unhide */
static int
unhide_func (char *arg, int flags)
{
  if (! set_device (arg))
    return 1;

  if (! set_partition_hidden_flag (0))
    return 1;

  return 0;
}

static struct builtin builtin_unhide =
{
  "unhide",
  unhide_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_HELP_LIST,
  "unhide PARTITION",
  "Unhide PARTITION by clearing the \"hidden\" bit in its"
  " partition type code."
};


/* uppermem */
static int
uppermem_func (char *arg, int flags)
{
  if (! safe_parse_maxint (&arg, (int *) &mbi.mem_upper))
    return 1;

  mbi.flags &= ~MB_INFO_MEM_MAP;
  return 0;
}

static struct builtin builtin_uppermem =
{
  "uppermem",
  uppermem_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "uppermem KBYTES",
  "Force GRUB to assume that only KBYTES kilobytes of upper memory are"
  " installed.  Any system address range maps are discarded."
};


/* vbeprobe */
static int
vbeprobe_func (char *arg, int flags)
{
  struct vbe_controller controller;
  unsigned short *mode_list;
  int mode_number = -1;
  
  auto unsigned long vbe_far_ptr_to_linear (unsigned long);
  
  unsigned long vbe_far_ptr_to_linear (unsigned long ptr)
    {
      unsigned short seg = (ptr >> 16);
      unsigned short off = (ptr & 0xFFFF);

      return (seg << 4) + off;
    }
  
  if (*arg)
    {
      if (! safe_parse_maxint (&arg, &mode_number))
	return 1;
    }
  
  /* Set the signature to `VBE2', to obtain VBE 3.0 information.  */
  grub_memmove (controller.signature, "VBE2", 4);
  
  if (get_vbe_controller_info (&controller) != 0x004F)
    {
      grub_printf (" VBE BIOS is not present.\n");
      return 0;
    }

  /* Check the version.  */
  if (controller.version < 0x0200)
    {
      grub_printf (" VBE version %d.%d is not supported.\n",
		   (int) (controller.version >> 8),
		   (int) (controller.version & 0xFF));
      return 0;
    }

  /* Print some information.  */
  grub_printf (" VBE version %d.%d\n",
	       (int) (controller.version >> 8),
	       (int) (controller.version & 0xFF));

  /* Iterate probing modes.  */
  for (mode_list
	 = (unsigned short *) vbe_far_ptr_to_linear (controller.video_mode);
       *mode_list != 0xFFFF;
       mode_list++)
    {
      struct vbe_mode mode;
      
      if (get_vbe_mode_info (*mode_list, &mode) != 0x004F)
	continue;

      /* Skip this, if this is not supported or linear frame buffer
	 mode is not support.  */
      if ((mode.mode_attributes & 0x0081) != 0x0081)
	continue;

      if (mode_number == -1 || mode_number == *mode_list)
	{
	  char *model;
	  switch (mode.memory_model)
	    {
	    case 0x00: model = "Text"; break;
	    case 0x01: model = "CGA graphics"; break;
	    case 0x02: model = "Hercules graphics"; break;
	    case 0x03: model = "Planar"; break;
	    case 0x04: model = "Packed pixel"; break;
	    case 0x05: model = "Non-chain 4, 256 color"; break;
	    case 0x06: model = "Direct Color"; break;
	    case 0x07: model = "YUV"; break;
	    default: model = "Unknown"; break;
	    }
	  
	  grub_printf ("  0x%x: %s, %ux%ux%u\n",
		       (unsigned) *mode_list,
		       model,
		       (unsigned) mode.x_resolution,
		       (unsigned) mode.y_resolution,
		       (unsigned) mode.bits_per_pixel);
	  
	  if (mode_number != -1)
	    break;
	}
    }

  if (mode_number != -1 && mode_number != *mode_list)
    grub_printf ("  Mode 0x%x is not found or supported.\n", mode_number);
  
  return 0;
}

static struct builtin builtin_vbeprobe =
{
  "vbeprobe",
  vbeprobe_func,
  BUILTIN_CMDLINE | BUILTIN_HELP_LIST,
  "vbeprobe [MODE]",
  "Probe VBE information. If the mode number MODE is specified, show only"
  " the information about only the mode."
};

static int
variable_func(char *arg, int flags)
{
	char name[EV_NAMELEN];
	char *val;
	int err;

	if (*arg == '\0') {
		dump_variables();
		return (0);
	}

	if ((val = grub_strchr(arg, ' ')) != NULL) {
		if (val - arg >= sizeof (name)) {
			errnum = ERR_WONT_FIT;
			return (1);
		}
		(void) grub_memcpy(name, arg, (val - arg));
		name[val - arg] = '\0';
		val = skip_to(0, arg);
	} else {
		if (grub_strlen(arg) >= sizeof (name)) {
			errnum = ERR_WONT_FIT;
			return (1);
		}
		(void) grub_strcpy(name, arg);
	}

	if ((err = set_variable(name, val)) != 0) {
		errnum = err;
		return (1);
	}

	return (0);
}

static struct builtin builtin_variable =
{
  "variable",
  variable_func,
  BUILTIN_CMDLINE | BUILTIN_MENU | BUILTIN_SCRIPT | BUILTIN_HELP_LIST,
  "variable NAME [VALUE]",
  "Set the variable NAME to VALUE, or to the empty string if no value is"
  " given. NAME must contain no spaces. There is no quoting mechanism"
  " and nested variable references are not allowed. Variable values may"
  " be substituted into the kernel$ and module$ commands using ${NAME}."
};
  

/* The table of builtin commands. Sorted in dictionary order.  */
struct builtin *builtin_table[] =
{
#ifdef SUPPORT_GRAPHICS
  &builtin_background,
#endif
  &builtin_blocklist,
  &builtin_boot,
  &builtin_bootfs,
#ifdef SUPPORT_NETBOOT
  &builtin_bootp,
#endif /* SUPPORT_NETBOOT */
  &builtin_cat,
  &builtin_chainloader,
  &builtin_clear,
  &builtin_cmp,
  &builtin_color,
  &builtin_configfile,
  &builtin_debug,
  &builtin_default,
#ifdef GRUB_UTIL
  &builtin_device,
#endif /* GRUB_UTIL */
#ifdef SUPPORT_NETBOOT
  &builtin_dhcp,
#endif /* SUPPORT_NETBOOT */
  &builtin_displayapm,
  &builtin_displaymem,
#ifdef GRUB_UTIL
  &builtin_dump,
#endif /* GRUB_UTIL */
  &builtin_embed,
  &builtin_fallback,
  &builtin_find,
  &builtin_findroot,
#ifdef SUPPORT_GRAPHICS
  &builtin_foreground,
#endif
  &builtin_fstest,
  &builtin_geometry,
  &builtin_halt,
  &builtin_help,
  &builtin_hiddenmenu,
  &builtin_hide,
#ifdef SUPPORT_NETBOOT
  &builtin_ifconfig,
#endif /* SUPPORT_NETBOOT */
  &builtin_impsprobe,
  &builtin_initrd,
  &builtin_install,
  &builtin_ioprobe,
  &builtin_kernel,
  &builtin_kernel_dollar,
  &builtin_lock,
  &builtin_makeactive,
  &builtin_map,
#ifdef USE_MD5_PASSWORDS
  &builtin_md5crypt,
#endif /* USE_MD5_PASSWORDS */
  &builtin_min_mem64,
  &builtin_module,
  &builtin_module_dollar,
  &builtin_modulenounzip,
  &builtin_pager,
  &builtin_partnew,
  &builtin_parttype,
  &builtin_password,
  &builtin_pause,
#if defined(RPC_DEBUG) && defined(SUPPORT_NETBOOT)
  &builtin_portmap,
#endif /* RPC_DEBUG && SUPPORT_NETBOOT */
#ifdef GRUB_UTIL
  &builtin_quit,
#endif /* GRUB_UTIL */
#ifdef SUPPORT_NETBOOT
  &builtin_rarp,
#endif /* SUPPORT_NETBOOT */
  &builtin_read,
  &builtin_reboot,
  &builtin_root,
  &builtin_rootnoverify,
  &builtin_savedefault,
#ifdef SUPPORT_SERIAL
  &builtin_serial,
#endif /* SUPPORT_SERIAL */
  &builtin_setkey,
  &builtin_setup,
#ifdef SUPPORT_GRAPHICS
  &builtin_splashimage,
#endif /* SUPPORT_GRAPHICS */
#if defined(SUPPORT_SERIAL) || defined(SUPPORT_HERCULES) || defined(SUPPORT_GRAPHICS)
  &builtin_terminal,
#endif /* SUPPORT_SERIAL || SUPPORT_HERCULES || SUPPORT_GRAPHICS */
#ifdef SUPPORT_SERIAL
  &builtin_terminfo,
#endif /* SUPPORT_SERIAL */
  &builtin_testload,
  &builtin_testvbe,
#ifdef SUPPORT_NETBOOT
  &builtin_tftpserver,
#endif /* SUPPORT_NETBOOT */
  &builtin_timeout,
  &builtin_title,
  &builtin_unhide,
  &builtin_uppermem,
  &builtin_variable,
  &builtin_vbeprobe,
  &builtin_verbose,
  0
};
