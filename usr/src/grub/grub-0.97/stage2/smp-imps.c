/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2005,2005  Free Software Foundation, Inc.
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
 *  <Insert copyright here : it must be BSD-like so anyone can use it>
 *
 *  Author:  Erich Boleyn  <erich@uruk.org>   http://www.uruk.org/~erich/
 *
 *  Source file implementing Intel MultiProcessor Specification (MPS)
 *  version 1.1 and 1.4 SMP hardware control for Intel Architecture CPUs,
 *  with hooks for running correctly on a standard PC without the hardware.
 *
 *  This file was created from information in the Intel MPS version 1.4
 *  document, order number 242016-004, which can be ordered from the
 *  Intel literature center.
 *
 *  General limitations of this code:
 *
 *   (1) : This code has never been tested on an MPS-compatible system with
 *           486 CPUs, but is expected to work.
 *   (2) : Presumes "int", "long", and "unsigned" are 32 bits in size, and
 *	     that 32-bit pointers and memory addressing is used uniformly.
 */

#define _SMP_IMPS_C


/*
 *  XXXXX  The following absolutely must be defined!!!
 *
 *  The "KERNEL_PRINT" could be made a null macro with no danger, of
 *  course, but pretty much nothing would work without the other
 *  ones defined.
 */

#if 0
#define KERNEL_PRINT(x)		/* some kind of print function */
#define CMOS_WRITE_BYTE(x,y)	/* write unsigned char "y" at CMOS loc "x" */
#define CMOS_READ_BYTE(x)	/* read unsigned char at CMOS loc "x" */
#define PHYS_TO_VIRTUAL(x)	/* convert physical address "x" to virtual */
#define VIRTUAL_TO_PHYS(x)	/* convert virtual address "x" to physical */
#endif


/*
 *  This is the Intel MultiProcessor Spec debugging/display code.
 */

#define IMPS_DEBUG
#define KERNEL_PRINT(x)         printf x
#define CMOS_WRITE_BYTE(x, y)	cmos_write_byte(x, y)
#define CMOS_READ_BYTE(x)	cmos_read_byte(x)
#define PHYS_TO_VIRTUAL(x)	(x)
#define VIRTUAL_TO_PHYS(x)	(x)

static inline unsigned char
inb (unsigned short port)
{
  unsigned char data;

  __asm __volatile ("inb %1,%0" :"=a" (data):"d" (port));
  return data;
}

static inline void
outb (unsigned short port, unsigned char val)
{
  __asm __volatile ("outb %0,%1"::"a" (val), "d" (port));
}


static inline void
cmos_write_byte (int loc, int val)
{
  outb (0x70, loc);
  outb (0x71, val);
}

static inline unsigned
cmos_read_byte (int loc)
{
  outb (0x70, loc);
  return inb (0x71);
}


/*
 *  Includes here
 */

#include "shared.h"
#include "apic.h"
#include "smp-imps.h"


/*
 *  Defines that are here so as not to be in the global header file.
 */
#define EBDA_SEG_ADDR			0x40E
#define BIOS_RESET_VECTOR		0x467
#define LAPIC_ADDR_DEFAULT		0xFEE00000uL
#define IOAPIC_ADDR_DEFAULT		0xFEC00000uL
#define CMOS_RESET_CODE			0xF
#define		CMOS_RESET_JUMP		0xa
#define CMOS_BASE_MEMORY		0x15


/*
 *  Static defines here for SMP use.
 */

#define DEF_ENTRIES	23

static int lapic_dummy = 0;
static struct
  {
    imps_processor proc[2];
    imps_bus bus[2];
    imps_ioapic ioapic;
    imps_interrupt intin[16];
    imps_interrupt lintin[2];
  }
defconfig =
{
  {
    {
      IMPS_BCT_PROCESSOR, 0, 0, 0, 0, 0
    }
    ,
    {
      IMPS_BCT_PROCESSOR, 1, 0, 0, 0, 0
    }
  }
  ,
  {
    {
      IMPS_BCT_BUS, 0,
      {
	'E', 'I', 'S', 'A', ' ', ' '
      }
    }
    ,
    {
      255, 1,
      {
	'P', 'C', 'I', ' ', ' ', ' '
      }
    }
  }
  ,
  {
    IMPS_BCT_IOAPIC, 0, 0, IMPS_FLAG_ENABLED, IOAPIC_ADDR_DEFAULT
  }
  ,
  {
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_EXTINT, 0, 0, 0, 0xFF, 0
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 1, 0xFF, 1
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 0, 0xFF, 2
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 3, 0xFF, 3
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 4, 0xFF, 4
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 5, 0xFF, 5
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 6, 0xFF, 6
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 7, 0xFF, 7
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 8, 0xFF, 8
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 9, 0xFF, 9
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 10, 0xFF, 10
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 11, 0xFF, 11
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 12, 0xFF, 12
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 13, 0xFF, 13
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 14, 0xFF, 14
    }
    ,
    {
      IMPS_BCT_IO_INTERRUPT, IMPS_INT_INT, 0, 0, 15, 0xFF, 15
    }
  }
  ,
  {
    {
      IMPS_BCT_LOCAL_INTERRUPT, IMPS_INT_EXTINT, 0, 0, 15, 0xFF, 0
    }
    ,
    {
      IMPS_BCT_LOCAL_INTERRUPT, IMPS_INT_NMI, 0, 0, 15, 0xFF, 1
    }
  }
};

/*
 *  Exported globals here.
 */

/*
 *  "imps_any_new_apics" is non-zero if any of the APICS (local or I/O)
 *  are *not* an 82489DX.  This is useful to determine if more than 15
 *  CPUs can be supported (true if zero).
 */
static int imps_any_new_apics = 0;
#if 0
volatile int imps_release_cpus = 0;
#endif
/*
 *  "imps_enabled" is non-zero if the probe sequence found IMPS
 *  information and was successful.
 */
static int imps_enabled = 0;
/*
 * This represents the number of CPUs found.
 */
static int imps_num_cpus = 1;
/*
 * This contains the local APIC hardware address.
 */
static unsigned imps_lapic_addr = ((unsigned) (&lapic_dummy)) - LAPIC_ID;
/*
 * These map from virtual cpu numbers to APIC id's and back.
 */
static unsigned char imps_cpu_apic_map[IMPS_MAX_CPUS];
static unsigned char imps_apic_cpu_map[IMPS_MAX_CPUS];


/*
 *  MPS checksum function
 *
 *  Function finished.
 */

static int
get_checksum (unsigned start, int length)
{
  unsigned sum = 0;

  while (length-- > 0)
    {
      sum += *((unsigned char *) (start++));
    }

  return (sum & 0xFF);
}


/*
 *  Primary function for booting individual CPUs.
 *
 *  This must be modified to perform whatever OS-specific initialization
 *  that is required.
 */

static int
boot_cpu (imps_processor * proc)
{
  unsigned bootaddr, accept_status;
  unsigned bios_reset_vector = PHYS_TO_VIRTUAL (BIOS_RESET_VECTOR);

  /* %%%%% ESB */
  extern char patch_code[];
  bootaddr = 256 * 1024;
  memmove ((char *) bootaddr, patch_code, 32);

  /*
   *  Generic CPU startup sequence starts here.
   */

  /* set BIOS reset vector */
  CMOS_WRITE_BYTE (CMOS_RESET_CODE, CMOS_RESET_JUMP);
  *((volatile unsigned *) bios_reset_vector) = bootaddr << 12;

  /* clear the error register */
  if (proc->apic_ver & 0x10)
    {
      IMPS_LAPIC_WRITE (LAPIC_ESR, 0);
      accept_status = IMPS_LAPIC_READ (LAPIC_ESR);
    }

#if 0
  /* assert INIT IPI */
  cfg = IMPS_LAPIC_READ (LAPIC_ICR + 1);
  cfg &= LAPIC_DEST_MASK;
  IMPS_LAPIC_WRITE (LAPIC_ICR + 1, cfg);
  cfg = IMPS_LAPIC_READ (LAPIC_ACR);
  cfg &=;

  /* %%%%% ESB finish adding startup sequence */
#endif

  /* clean up BIOS reset vector */
  CMOS_WRITE_BYTE (CMOS_RESET_CODE, 0);
  *((volatile unsigned *) bios_reset_vector) = 0;

  /*
   *  Generic CPU startup sequence ends here.
   */

  KERNEL_PRINT (("\n"));

  return 1;

  /* XXXXX add OS-specific initialization here! */
}


/*
 *  read bios stuff and fill tables
 */

static void
add_processor (imps_processor * proc)
{
  int apicid = proc->apic_id;

  KERNEL_PRINT (("  Processor [APIC id %d ver %d]:  ",
		 apicid, proc->apic_ver));
  if (!(proc->flags & IMPS_FLAG_ENABLED))
    {
      KERNEL_PRINT (("DISABLED\n"));
      return;
    }
  if (proc->apic_ver > 0xF)
    {
      imps_any_new_apics = 1;
    }
  if (proc->flags & (IMPS_CPUFLAG_BOOT))
    {
      KERNEL_PRINT (("#0  Bootstrap Processor (BSP)\n"));
      return;
    }
  imps_cpu_apic_map[imps_num_cpus] = apicid;
  imps_apic_cpu_map[apicid] = imps_num_cpus;
  if (boot_cpu (proc))
    {

      /*  XXXXX  add OS-specific setup for secondary CPUs here */

      imps_num_cpus++;
    }
}


static void
add_bus (imps_bus * bus)
{
  char str[8];

  memmove (str, bus->bus_type, 6);
  str[6] = 0;
  KERNEL_PRINT (("  Bus id %d is %s\n", bus->id, str));

  /*  XXXXX  add OS-specific code here */
}


static void
add_ioapic (imps_ioapic * ioapic)
{
  KERNEL_PRINT (("  I/O APIC id %d ver %d, address: 0x%x  ",
		 ioapic->id, ioapic->ver, ioapic->addr));
  if (!(ioapic->flags & IMPS_FLAG_ENABLED))
    {
      KERNEL_PRINT (("DISABLED\n"));
      return;
    }
  KERNEL_PRINT (("\n"));

  /*  XXXXX  add OS-specific code here */
}


static void
imps_read_config_table (unsigned start, int count)
{
  while (count-- > 0)
    {
      switch (*((unsigned char *) start))
	{
	case IMPS_BCT_PROCESSOR:
	  add_processor ((imps_processor *) start);
	  start += 12;		/* 20 total */
	  break;
	case IMPS_BCT_BUS:
	  add_bus ((imps_bus *) start);
	  break;
	case IMPS_BCT_IOAPIC:
	  add_ioapic ((imps_ioapic *) start);
	  break;
#if 0				/*  XXXXX  uncomment this if "add_io_interrupt" is implemented */
	case IMPS_BCT_IO_INTERRUPT:
	  add_io_interrupt ((imps_interrupt *) start);
	  break;
#endif
#if 0				/*  XXXXX  uncomment this if "add_local_interrupt" is implemented */
	case IMPS_BCT_LOCAL_INTERRUPT:
	  add_local_interupt ((imps_interrupt *) start);
	  break;
#endif
	default:
	  break;
	}
      start += 8;
    }
}


static int
imps_bad_bios (imps_fps * fps_ptr)
{
  int sum;
  imps_cth *local_cth_ptr
  = (imps_cth *) PHYS_TO_VIRTUAL (fps_ptr->cth_ptr);

  if (fps_ptr->feature_info[0] > IMPS_FPS_DEFAULT_MAX)
    {
      KERNEL_PRINT (("    Invalid MP System Configuration type %d\n",
		     fps_ptr->feature_info[0]));
      return 1;
    }

  if (fps_ptr->cth_ptr)
    {
      sum = get_checksum ((unsigned) local_cth_ptr,
			  local_cth_ptr->base_length);
      if (local_cth_ptr->sig != IMPS_CTH_SIGNATURE || sum)
	{
	  KERNEL_PRINT
			(("    Bad MP Config Table sig 0x%x and/or checksum 0x%x\n",
			(unsigned) (fps_ptr->cth_ptr), sum));
	  return 1;
	}
      if (local_cth_ptr->spec_rev != fps_ptr->spec_rev)
	{
	  KERNEL_PRINT (("    Bad MP Config Table sub-revision # %d\n", local_cth_ptr->spec_rev));
	  return 1;
	}
      if (local_cth_ptr->extended_length)
	{
	  sum = (get_checksum (((unsigned) local_cth_ptr)
			       + local_cth_ptr->base_length,
			       local_cth_ptr->extended_length)
		 + local_cth_ptr->extended_checksum) & 0xFF;
	  if (sum)
	    {
	      KERNEL_PRINT
			    (("    Bad Extended MP Config Table checksum 0x%x\n", sum));
	      return 1;
	    }
	}
    }
  else if (!fps_ptr->feature_info[0])
    {
      KERNEL_PRINT (("    Missing configuration information\n"));
      return 1;
    }

  return 0;
}


static void
imps_read_bios (imps_fps * fps_ptr)
{
  int apicid;
  unsigned cth_start, cth_count;
  imps_cth *local_cth_ptr
  = (imps_cth *) PHYS_TO_VIRTUAL (fps_ptr->cth_ptr);
  char *str_ptr;

  KERNEL_PRINT (("Intel MultiProcessor Spec 1.%d BIOS support detected\n",
		 fps_ptr->spec_rev));

  /*
   *  Do all checking of errors which would definitely
   *  lead to failure of the SMP boot here.
   */

  if (imps_bad_bios (fps_ptr))
    {
      KERNEL_PRINT (("    Disabling MPS support\n"));
      return;
    }

  if (fps_ptr->feature_info[1] & IMPS_FPS_IMCRP_BIT)
    {
      str_ptr = "IMCR and PIC";
    }
  else
    {
      str_ptr = "Virtual Wire";
    }
  if (fps_ptr->cth_ptr)
    {
      imps_lapic_addr = local_cth_ptr->lapic_addr;
    }
  else
    {
      imps_lapic_addr = LAPIC_ADDR_DEFAULT;
    }
  KERNEL_PRINT
		(("    APIC config: \"%s mode\"    Local APIC address: 0x%x\n",
		 str_ptr, imps_lapic_addr));
  imps_lapic_addr = PHYS_TO_VIRTUAL (imps_lapic_addr);

  /*
   *  Setup primary CPU.
   */
  apicid = IMPS_LAPIC_READ (LAPIC_SPIV);
  IMPS_LAPIC_WRITE (LAPIC_SPIV, apicid | LAPIC_SPIV_ENABLE_APIC);
  imps_any_new_apics = IMPS_LAPIC_READ (LAPIC_VER) & 0xF0;
  apicid = IMPS_APIC_ID (IMPS_LAPIC_READ (LAPIC_ID));
  imps_cpu_apic_map[0] = apicid;
  imps_apic_cpu_map[apicid] = 0;

  if (fps_ptr->cth_ptr)
    {
      char str1[16], str2[16];
      memcpy (str1, local_cth_ptr->oem_id, 8);
      str1[8] = 0;
      memcpy (str2, local_cth_ptr->prod_id, 12);
      str2[12] = 0;
      KERNEL_PRINT (("  OEM id: %s  Product id: %s\n", str1, str2));
      cth_start = ((unsigned) local_cth_ptr) + sizeof (imps_cth);
      cth_count = local_cth_ptr->entry_count;
    }
  else
    {
      *((volatile unsigned *) IOAPIC_ADDR_DEFAULT) = IOAPIC_ID;
      defconfig.ioapic.id
	= IMPS_APIC_ID (*((volatile unsigned *)
			  (IOAPIC_ADDR_DEFAULT + IOAPIC_RW)));
      *((volatile unsigned *) IOAPIC_ADDR_DEFAULT) = IOAPIC_VER;
      defconfig.ioapic.ver
	= APIC_VERSION (*((volatile unsigned *)
			  (IOAPIC_ADDR_DEFAULT + IOAPIC_RW)));
      defconfig.proc[apicid].flags
	= IMPS_FLAG_ENABLED | IMPS_CPUFLAG_BOOT;
      defconfig.proc[!apicid].flags = IMPS_FLAG_ENABLED;
      imps_num_cpus = 2;
      if (fps_ptr->feature_info[0] == 1
	  || fps_ptr->feature_info[0] == 5)
	{
	  memcpy (defconfig.bus[0].bus_type, "ISA   ", 6);
	}
      if (fps_ptr->feature_info[0] == 4
	  || fps_ptr->feature_info[0] == 7)
	{
	  memcpy (defconfig.bus[0].bus_type, "MCA   ", 6);
	}
      if (fps_ptr->feature_info[0] > 4)
	{
	  defconfig.proc[0].apic_ver = 0x10;
	  defconfig.proc[1].apic_ver = 0x10;
	  defconfig.bus[1].type = IMPS_BCT_BUS;
	}
      if (fps_ptr->feature_info[0] == 2)
	{
	  defconfig.intin[2].type = 255;
	  defconfig.intin[13].type = 255;
	}
      if (fps_ptr->feature_info[0] == 7)
	{
	  defconfig.intin[0].type = 255;
	}
      cth_start = (unsigned) &defconfig;
      cth_count = DEF_ENTRIES;
    }
  imps_read_config_table (cth_start, cth_count);

  /* %%%%% ESB read extended entries here */

  imps_enabled = 1;
}


/*
 *  Given a region to check, this actually looks for the "MP Floating
 *  Pointer Structure".  The return value indicates if the correct
 *  signature and checksum for a floating pointer structure of the
 *  appropriate spec revision was found.  If so, then do not search
 *  further.
 *
 *  NOTE:  The memory scan will always be in the bottom 1 MB.
 *
 *  This function presumes that "start" will always be aligned to a 16-bit
 *  boundary.
 *
 *  Function finished.
 */

static int
imps_scan (unsigned start, unsigned length)
{
  IMPS_DEBUG_PRINT (("Scanning from 0x%x for %d bytes\n",
		     start, length));

  while (length > 0)
    {
      imps_fps *fps_ptr = (imps_fps *) PHYS_TO_VIRTUAL (start);

      if (fps_ptr->sig == IMPS_FPS_SIGNATURE
	  && fps_ptr->length == 1
	  && (fps_ptr->spec_rev == 1 || fps_ptr->spec_rev == 4)
	  && !get_checksum (start, 16))
	{
	  IMPS_DEBUG_PRINT (("Found MP Floating Structure Pointer at %x\n", start));
	  imps_read_bios (fps_ptr);
	  return 1;
	}

      length -= 16;
      start += 16;
    }

  return 0;
}


/*
 *  This is the primary function for probing for MPS compatible hardware
 *  and BIOS information.  Call this during the early stages of OS startup,
 *  before memory can be messed up.
 *
 *  The probe looks for the "MP Floating Pointer Structure" at locations
 *  listed at the top of page 4-2 of the spec.
 *
 *  Environment requirements from the OS to run:
 *
 *   (1) : A non-linear virtual to physical memory mapping is probably OK,
 *	     as (I think) the structures all fall within page boundaries,
 *	     but a linear mapping is recommended.  Currently assumes that
 *	     the mapping will remain identical over time (which should be
 *	     OK since it only accesses memory which shouldn't be munged
 *	     by the OS anyway).
 *   (2) : The OS only consumes memory which the BIOS says is OK to use,
 *	     and not any of the BIOS standard areas (the areas 0x400 to
 *	     0x600, the EBDA, 0xE0000 to 0xFFFFF, and unreported physical
 *	     RAM).  Sometimes a small amount of physical RAM is not
 *	     reported by the BIOS, to be used to store MPS and other
 *	     information.
 *   (3) : It must be possible to read the CMOS.
 *   (4) : There must be between 512K and 640K of lower memory (this is a
 *	     sanity check).
 *
 *  Function finished.
 */

int
imps_probe (void)
{
  /*
   *  Determine possible address of the EBDA
   */
  unsigned ebda_addr = *((unsigned short *)
			 PHYS_TO_VIRTUAL (EBDA_SEG_ADDR)) << 4;

  /*
   *  Determine amount of installed lower memory (not *available*
   *  lower memory).
   *
   *  NOTE:  This should work reliably as long as we verify the
   *         machine is at least a system that could possibly have
   *         MPS compatibility to begin with.
   */
  unsigned mem_lower = ((CMOS_READ_BYTE (CMOS_BASE_MEMORY + 1) << 8)
			| CMOS_READ_BYTE (CMOS_BASE_MEMORY)) << 10;

#ifdef IMPS_DEBUG
  imps_enabled = 0;
  imps_num_cpus = 1;
#endif

  /*
   *  Sanity check : if this isn't reasonable, it is almost impossibly
   *    unlikely to be an MPS compatible machine, so return failure.
   */
  if (mem_lower < 512 * 1024 || mem_lower > 640 * 1024)
    {
      return 0;
    }

  if (ebda_addr > mem_lower - 1024
      || ebda_addr + *((unsigned char *) PHYS_TO_VIRTUAL (ebda_addr))
      * 1024 > mem_lower)
    {
      ebda_addr = 0;
    }

  if (((ebda_addr && imps_scan (ebda_addr, 1024))
       || (!ebda_addr && imps_scan (mem_lower - 1024, 1024))
       || imps_scan (0xF0000, 0x10000)) && imps_enabled)
    {
      return 1;
    }

  /*
   *  If no BIOS info on MPS hardware is found, then return failure.
   */

  return 0;
}
