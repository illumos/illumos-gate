/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/promif.h>
#include <sys/salib.h>
#include "ramdisk.h"

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/obpdefs.h>
#include <sys/reboot.h>
#include <sys/promif.h>
#include <sys/stat.h>
#include <sys/bootvfs.h>
#include <sys/platnames.h>
#include <sys/salib.h>
#include <sys/elf.h>
#include <sys/link.h>
#include <sys/auxv.h>
#include <sys/boot_policy.h>
#include <sys/boot_redirect.h>
#include <sys/bootconf.h>
#include <sys/boot.h>
#include "boot_plat.h"


static char ramdisk_preamble_fth[] =

": find-abort ( name$ -- ) "
"   .\" Can't find \" type abort "
"; "

": get-package ( pkg$ -- ph ) "
"   2dup  find-package 0=  if "
"      find-abort "
"   then                       ( pkg$ ph ) "
"   nip nip                    ( ph ) "
"; "

"\" /openprom/client-services\" get-package  constant cif-ph "

"instance defer cif-open     ( dev$ -- ihandle|0 ) "
"instance defer cif-close    ( ihandle -- ) "

": find-cif-method ( adr,len -- acf ) "
"   2dup  cif-ph find-method 0=  if    ( adr,len ) "
"      find-abort "
"   then                               ( adr,len acf ) "
"   nip nip                            ( acf ) "
"; "

"\" open\"     find-cif-method to cif-open "
"\" close\"    find-cif-method to cif-close "

"0 value dev-ih "

"d# 100 buffer: open-cstr "

": dev-open ( dev$ -- okay? ) "
/* copy to C string for open  */
"   0  over open-cstr +  c! "
"   open-cstr swap  move "
"   open-cstr  cif-open dup  if "
"      dup to dev-ih "
"   then "
"; "

": dev-close ( -- ) "
"   dev-ih cif-close "
"   0 to dev-ih "
"; "

": open-abort  ( file$ -- ) "
"   .\" Can't open \"  type  abort "
"; "
;

static char ramdisk_fth[] =

"\" /\" get-package  push-package "

"new-device "
"   \" %s\" device-name "
"    "
"   \" block\"          device-type "
"   \" SUNW,ramdisk\"	encode-string \" compatible\"  property"

"   0 instance value current-offset "
"    "
"   0 value ramdisk-base-va "
"   0 value ramdisk-size "
"   0 value alloc-size "
"    "
"   : set-props "
"      ramdisk-size     encode-int  \" size\"        property "
"      ramdisk-base-va  encode-int  \" address\"     property "
"      alloc-size       encode-int  \" alloc-size\"  property "
"   ; "
"   set-props "
"    "
"   : current-va  ( -- adr )  ramdisk-base-va current-offset +  ; "
"    "
"   external "
"    "
"   : open  ( -- okay? ) "
/* " .\" ramdisk-open\" cr " */
"      true "
"   ; "
"    "
"   : close  ( -- ) "
"   ; "
"    "
"   : seek  ( off.low off.high -- error? ) "
/* " 2dup .\" ramdisk-seek: \" .x .x " */
"      drop  dup  ramdisk-size  >  if "
/* " .\" fail\" cr " */
"         drop true  exit         ( failed ) "
"      then "
"      to current-offset  false   ( succeeded ) "
/* " .\" OK\" cr " */
"   ; "
"    "
"   : read  ( addr len -- actual-len ) "
/* " 2dup .\" ramdisk-read: \" .x .x " */
"      dup  current-offset  +            ( addr len new-off ) "
"      dup  ramdisk-size  >  if "
"         ramdisk-size -  -              ( addr len' ) "
"         ramdisk-size                   ( addr len new-off ) "
"      then  -rot                        ( new-off addr len ) "
"      tuck  current-va  -rot  move      ( new-off len ) "
"      swap  to current-offset           ( len ) "
/* " dup .x cr " */
"   ; "
"    "
"   : create ( alloc-sz base size -- ) "
"      to ramdisk-size "
"      to ramdisk-base-va "
"      to alloc-size "
"      set-props "
"   ; "
"    "
"finish-device "
"pop-package "

"\" /%s\" 2dup  dev-open  0=  if "
"   open-abort "
"then 2drop "

/* %x %x %x will be replaced by alloc-sz, base, size respectively */
"h# %x h# %x h# %x ( alloc-sz base size ) "
"\" create\" dev-ih  $call-method  (  ) "
"dev-close "

;

char ramdisk_bootable[] =

"\" /chosen\" get-package  push-package "
"   \" nfs\"             encode-string  \" fstype\"  property "
"   \" /%s\"	  	 encode-string  \" bootarchive\"  property "
"pop-package "

"   h# %x d# 512 +  to load-base init-program "
;

#define	BOOT_ARCHIVE_ALLOC_SIZE	(32 * 1024 * 1024)	/* 32 MB */
#define	BOOTFS_VIRT		((caddr_t)0x50f00000)
#define	ROOTFS_VIRT		((caddr_t)0x52000000)

struct ramdisk_attr {
	char *rd_name;
	caddr_t rd_base;
	size_t rd_size;
} ramdisk_attr[] = {
	RD_BOOTFS,	BOOTFS_VIRT,	0,
	RD_ROOTFS,	ROOTFS_VIRT,	0,
	0
};

static struct ramdisk_attr *
ramdisk_lookup(char *ramdisk_name)
{
	int i;

	for (i = 0; ramdisk_attr[i].rd_name != 0; i++) {
		if (strcmp(ramdisk_name, ramdisk_attr[i].rd_name) == 0) {
			return (&ramdisk_attr[i]);
		}
	}
	return (NULL);
}

static void
ramdisk_free_mem(caddr_t addr, size_t size)
{
	caddr_t	end_addr;

	for (end_addr = addr + size; addr < end_addr;
	    addr += BOOT_ARCHIVE_ALLOC_SIZE) {
		prom_free(addr, MIN(BOOT_ARCHIVE_ALLOC_SIZE, end_addr - addr));
	}
}

/*
 * Allocate memory for ramdisk image.
 */
static caddr_t
ramdisk_alloc_mem(caddr_t addr, size_t size)
{
	caddr_t virt = addr;
	caddr_t	end_addr;

	for (end_addr = virt + size; virt < end_addr;
	    virt += BOOT_ARCHIVE_ALLOC_SIZE) {
		if (prom_alloc(virt,
		    MIN(BOOT_ARCHIVE_ALLOC_SIZE, end_addr - virt),
		    1) == NULL) {
			ramdisk_free_mem(addr, virt - addr);
			return (NULL);
		}
	}
	return (addr);
}

caddr_t
create_ramdisk(char *ramdisk_name, size_t size, char **devpath)
{
	char	*fth_buf;
	size_t	buf_size;
	struct ramdisk_attr *rdp;
	char tdevpath[80];
	caddr_t virt;
	static int need_preamble = 1;

	/*
	 * lookup ramdisk name.
	 */
	if ((rdp = ramdisk_lookup(ramdisk_name)) == NULL)
		prom_panic("invalid ramdisk name");

	virt = rdp->rd_base;

	/*
	 * Allocate memory.
	 */
	size = roundup(size, PAGESIZE);
	if (ramdisk_alloc_mem(virt, size) == NULL)
		prom_panic("can't alloc ramdisk memory");

	rdp->rd_size = size;

	if (need_preamble) {
		prom_interpret(ramdisk_preamble_fth, 0, 0, 0, 0, 0);
		need_preamble = 0;
	}

	/*
	 * add some space to the size to accommodate a few words in the
	 * snprintf() below.
	 */
	buf_size = sizeof (ramdisk_fth) + 80;

	fth_buf = bkmem_alloc(buf_size);
	if (fth_buf == NULL)
		prom_panic("unable to allocate Forth buffer for ramdisk");

	(void) snprintf(fth_buf, buf_size, ramdisk_fth,
	    ramdisk_name, ramdisk_name,
	    BOOT_ARCHIVE_ALLOC_SIZE, virt, size);

	prom_interpret(fth_buf, 0, 0, 0, 0, 0);
	bkmem_free(fth_buf, buf_size);

	if (devpath != NULL) {
		(void) snprintf(tdevpath, sizeof (tdevpath), "/%s:nolabel",
		    ramdisk_name);
		*devpath = strdup(tdevpath);
	}

	return (virt);
}

void
destroy_ramdisk(char *ramdisk_name)
{
	struct ramdisk_attr *rdp;

	/*
	 * lookup ramdisk name.
	 */
	if ((rdp = ramdisk_lookup(ramdisk_name)) == NULL)
		prom_panic("invalid ramdisk name");

	ramdisk_free_mem(rdp->rd_base, rdp->rd_size);
	rdp->rd_size = 0;
}

/*
 * change cwp! to drop in the 2nd word of (init-program) - really
 * init-c-stack, but that word has no header.
 * (you are not expected to undertsnad this)
 */
char obpfix[] = "' drop ' cwp!  ' (init-program) >body ta1+ token@ (patch";
char obpver[OBP_MAXPROPNAME];
const char badver[] = "OBP 4.27.";


void
boot_ramdisk(char *ramdisk_name)
{
	char	*fth_buf;
	size_t	buf_size;
	struct ramdisk_attr *rdp;
	void do_sg_go(void);

	/*
	 * OBP revs 4.27.0 to 4.27.8 started using
	 * windowed regs for the forth kernel, but
	 * init-program still blindly 0'd %cwp, which
	 * causes predictably disaterous consequences
	 * when called with %cwp != 0.
	 *
	 * We detect and fix this here
	 */
	if (prom_version_name(obpver, OBP_MAXPROPNAME) != -1 &&
	    strncmp(obpver, badver, sizeof (badver) - 1) == 0) {
		char ch = obpver[sizeof (badver) - 1];

		if (ch >= '0' && ch <= '8') {
			prom_interpret(obpfix, 0, 0, 0, 0, 0);
		}
	}

	/* close all open devices */
	closeall(1);

	/*
	 * lookup ramdisk name.
	 */
	if ((rdp = ramdisk_lookup(ramdisk_name)) == NULL)
		prom_panic("invalid ramdisk name");

	/*
	 * add some space to the size to accommodate a few words in the
	 * snprintf() below.
	 */
	buf_size = sizeof (ramdisk_bootable) + 80;

	fth_buf = bkmem_alloc(buf_size);
	if (fth_buf == NULL)
		prom_panic("unable to allocate Forth buffer for ramdisk");

	(void) snprintf(fth_buf, buf_size, ramdisk_bootable,
	    ramdisk_name, rdp->rd_base);

	prom_interpret(fth_buf, 0, 0, 0, 0, 0);

	/*
	 * Ugh  Serengeti proms don't execute C programs
	 * in init-program, and 'go' doesn't work when
	 * launching a second C program (inetboot itself
	 * was launched as the 1st C program).  Nested fcode
	 * programs work, but that doesn't help the kernel.
	 */
	do_sg_go();
}

void
do_sg_go()
{
	pnode_t chosen = prom_chosennode();
	Elf64_Ehdr *ehdr;
	Elf64_Addr entry;
	uint32_t eadr;
	extern int is_sg;
	extern caddr_t sg_addr;
	extern size_t sg_len;

	if (!is_sg)
		prom_panic("do_sg_go");

	/*
	 * The ramdisk bootblk left a pointer to the elf image
	 * in 'elfheader-address'  Use it to find the kernel's
	 * entry point.
	 */
	if (prom_getprop(chosen, "elfheader-address", (caddr_t)&eadr) == -1)
		prom_panic("no elf header property");
	ehdr = (Elf64_Ehdr *)(uintptr_t)eadr;
	if (ehdr->e_machine != EM_SPARCV9)
		prom_panic("bad ELF header");
	entry = ehdr->e_entry;

	/*
	 * free extra bootmem
	 */
	prom_free(sg_addr, sg_len);

	/*
	 * Use pre-newboot's exitto64() to launch the kernel
	 */
	exitto64((int (*)())entry, NULL);
	prom_panic("exitto returned");
}
