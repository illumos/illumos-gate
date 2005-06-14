/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This program is loaded and executed by GRUB on x86 platforms.
 * It is responsible for interpreting the miniroot archive
 * loaded by GRUB, read unix and krtld, and jump to the kernel.
 *
 * Currently the kernel (_kobj_boot) expects a syscall vector,
 * bootops, and elfbootvec. So we oblige by providing the
 * same services for now.
 */

#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/reboot.h>
#include "multiboot.h"
#include "debug.h"
#include "standalloc.h"
#include "bootprop.h"
#include "util.h"
#include "console.h"

typedef int (*func_t)();
extern void setup_bootops();
extern void setup_memlists();
extern void init_paging(void);
extern int mountroot(char *);
extern int openfile(char *, char *);
extern int close(int);
extern void console_init(char *);
extern void kmem_init(void);
extern void init_biosprog();
extern func_t readfile(int fd, int print);
extern void exitto(func_t);

static void print_mbinfo(void);

int debug;

#define	dprintf	if (debug & D_MBOOT) printf

multiboot_info_t *mbi;
multiboot_header_t *mbh;
void *elfbootvec;	/* XXX dummy for 32-bit exitto */

char *bootfile_prop = NULL;
char *inputdevice_prop = NULL;
char *outputdevice_prop = NULL;
char *console_prop = NULL;

extern uint_t bpd_loc;
extern char *bootfile;
extern char *module_path;
extern int boot_verbose;
int is_amd64;

#ifdef	BOOTAMD64
extern void amd64_handoff(uint64_t);
extern int amd64_config_cpu();

int amd64_elf64;
uint64_t elf64_go2;
#endif	/* BOOTAMD64 */

extern int get_bootenv_props(void);
extern void vga_probe(void);

void
main(ulong_t magic, ulong_t addr, ulong_t header)
{
	int fd;
	char *grub_bootstr;
	int (*entry)();

	if (magic != MB_BOOTLOADER_MAGIC) {
		/* printf isn't working, so we return to loader */
		return;
	}

	/* Set MBI to the address of the Multiboot information structure. */
	mbi = (multiboot_info_t *)addr;
	mbh = (multiboot_header_t *)header;

	grub_bootstr = (char *)mbi->cmdline;
	console_init(grub_bootstr);	/* so we can do printf */
	kmem_init();		/* initialize memory allocator */
	setup_memlists();	/* memory core for the allocator */

	get_grub_bootargs(grub_bootstr);	/* get grub cmd options */
	if (debug & D_MBINFO)
		print_mbinfo();
	setup_bootops();	/* 32-bit memory ops and lists */
	init_paging();		/* turn on paging to before loading kernel */

	if (mountroot("boot") != 0) {	/* mount the ramdisk */
		panic("cannot mount boot archive\n");
	} else if (verbosemode) {
		printf("mountroot succeeded\n");
	}

	init_biosprog();	/* install bios service program */
	get_bootenv_props();	/* read bootenv.rc properties */
	vga_probe();		/* probe bios for vga */

	/*
	 * Set console as per eeprom(1M) if not yet specified.
	 * May set graphics mode, for which bios support is required.
	 */
	console_init2(inputdevice_prop, outputdevice_prop,
		console_prop);

#ifdef  BOOTAMD64
	/* Test to see if this CPU is an AMD64 */
	is_amd64 = amd64_config_cpu();
	if (verbosemode && is_amd64)
		printf("cpu is amd64 capable\n");
	if (is_amd64 == 0)
		bsetprop(NULL, "CPU_not_amd64", "true", sizeof ("true"));
#endif  /* BOOTAMD64 */

	/*
	 * Determine the boot file
	 *    precedence given to what's specified via grub,
	 *    fall back to boot-file property set by eeprom(1M).
	 *    If boot-file not set, fall back to defaults
	 */
	if (bootfile == NULL) {
		get_eeprom_bootargs(bootfile_prop);
		if (bootfile == NULL) {
			bootfile = is_amd64 ?
			    "kernel/amd64/unix" : "kernel/unix";
		}
	}
	setup_bootprop();	/* set up boot properties for the kernel */

	printf("\n");
	fd = openfile(bootfile, 0);	/* open the kernel file */
	if (fd == -1) {
		panic("cannot open %s\n", bootfile);
	} else {
		extern char filename[];
		(void) bsetprop(NULL, "whoami", filename, strlen(filename) + 1);
		if (verbosemode)
			printf("open kernel file: %s\n", filename);
	}

	entry = readfile(fd, verbosemode);
	(void) close(fd);
	if (module_path) {
		(void) bsetprop(NULL, "module-path", module_path,
		    strlen(module_path) + 1);
		if (verbosemode)
			printf("module_path set to: %s\n", module_path);
	}
	if (entry == (int (*)())-1) {
		panic("no entry point in %s\n", bootfile);
	}

#ifdef	BOOTAMD64
	if (amd64_elf64) {
		if (verbosemode)
			printf("Boot about to exit to AMD64 image at 0x%llx.\n",
			    (uint64_t)elf64_go2);
		amd64_handoff(elf64_go2);
	}
#endif

	if (verbosemode)
		printf("Boot about to exit to 32-bit kernel image at 0x%x.\n",
		    entry);
	exitto(entry);

	panic("failed to boot %s\n", bootfile);
}

static void
print_mbinfo(void)
{
	int tmp;

	/* multiboot header */
	printf("header_addr = 0x%x\n", mbh->header_addr);
	printf("load_addr = 0x%x, end = 0x%x, bss_end = 0x%x\n",
	    mbh->load_addr, mbh->load_end_addr, mbh->bss_end_addr);
	printf("entry_addr = 0x%x\n", mbh->entry_addr);

	/* multiboot info location */
	printf("mbi = 0x%x, size = 0x%x\n", mbi, sizeof (*mbi));

	/* flags */
	printf("flags = 0x%x\n", (unsigned)mbi->flags);

	/* memory range */
	if (MB_CHECK_FLAG(mbi->flags, 0))
		printf("mem_lower = %uKB, mem_upper = %uKB\n",
		    (unsigned)mbi->mem_lower, (unsigned)mbi->mem_upper);

	/* Is boot_device valid? */
	if (MB_CHECK_FLAG(mbi->flags, 1)) {
		tmp = ((mbi->boot_device >> 24) & 0xff);
		printf("boot_device = 0x%x", tmp);
		tmp = ((mbi->boot_device >> 16) & 0xff);
		printf(", part1 = 0x%x", tmp);
		tmp = ((mbi->boot_device >> 8) & 0xff);
		printf(", part2 = 0x%x", tmp);
		tmp = (mbi->boot_device & 0xff);
		printf(", part3 = 0x%x\n", tmp);
	}

	/* Is the command line passed? */
	if (MB_CHECK_FLAG(mbi->flags, 2))
		printf("cmdline = %s\n", (char *)mbi->cmdline);

	/* Are mods_* valid? */
	if (MB_CHECK_FLAG(mbi->flags, 3)) {
		mb_module_t *mod;
		int i;

		printf("mods_count = %d, mods_addr = 0x%x\n",
		    (int)mbi->mods_count, (int)mbi->mods_addr);
		for (i = 0, mod = (mb_module_t *)mbi->mods_addr;
		    i < mbi->mods_count; i++, mod++) {
			printf(
			    " mod_start = 0x%x, mod_end = 0x%x, string = %s\n",
			    (unsigned)mod->mod_start,
			    (unsigned)mod->mod_end, (char *)mod->string);
		}
	}

	/* make sure we are not a.out */
	if (MB_CHECK_FLAG(mbi->flags, 4)) {
		printf("Bit 4 is set, we shouldn't be using a.out format.\n");
		return;
	}

	/* Is the section header table of ELF valid? */
	if (MB_CHECK_FLAG(mbi->flags, 5)) {
		mb_elf_shtable_t *elf_sec = &(mbi->elf_sec);

		printf("elf_sec: num = %u, size = 0x%x,"
		    " addr = 0x%x, shndx = 0x%x\n",
		    (unsigned)elf_sec->num, (unsigned)elf_sec->size,
		    (unsigned)elf_sec->addr, (unsigned)elf_sec->shndx);
	}

	/* print drives info */
	if (MB_CHECK_FLAG(mbi->flags, 7)) {
		printf("drives length %d, driver addr 0x%x\n",
		    mbi->drives_length, mbi->drives_addr);
	}
}

/*ARGSUSED*/
void
trap(int trapno, int err)
{
	printf("trap type %d\n", trapno);
	panic("unexpected trap in boot loader\n");
}
