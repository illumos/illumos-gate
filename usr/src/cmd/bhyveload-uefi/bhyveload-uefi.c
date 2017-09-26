/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Pluribus Networks Inc.
 */

#include <sys/types.h>

#include <machine/vmm.h>

#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>

#include <vmmapi.h>

#define	KB	(1024UL)
#define	MB	(1024 * 1024UL)
#define	GB	(1024 * 1024 * 1024UL)

#define	UEFI_ROM_ADDR	0xFFE00000
#define	UEFI_ROM_SIZE	(2 * MB)
/*
 * N.B. the UEFI code zeros the first page in memory so use the second.
 */
#define	BHYVE_HOB_ADDR		0x00002000
#define	BHYVE_BO_HOB_ADDR	0x00002080

#define	UEFI_ROM_PATH	"/usr/share/bhyve/uefi-rom.bin"

struct platform_info {
	uint32_t	ncpus;
};

/*
 * Boot order code:
 * 0 - EFI_CD_HD
 * 1 - EFI_CD
 * 2 - EFI_HD_CD
 * 3 - EFI_HD
 * 4 - EFI_NET
 * 5 - EFI_NET_CD_HD
 * 6 - EFI_HD_HD_CD
 * 7 - LEGACY_CD_HD
 * 8 - LEGACY_CD
 * 9 - LEGACY_HD_CD
 * 10 - LEGACY_HD
 * 11 - EFI_SHELL
 */

struct bootorder_info {
	uint32_t	guestbootorder;
};

static char *vmname, *progname;
static struct vmctx *ctx;

static void
usage(void)
{
	printf("usage: %s "
	       "[-c vcpus] [-m mem-size] [-b bootorder]"
	       "<vmname>\n", progname);
	exit(1);
}

int
main(int argc, char** argv)
{
	int opt, error, fd;
	int guest_ncpus;
	int guest_bootorder = 0;
	uint64_t mem_size;
	char *membase, *rombase;
	struct platform_info *pi;
	struct bootorder_info *bi;

	progname = argv[0];

	guest_ncpus = 1;
	mem_size = 256 * MB;

	while ((opt = getopt(argc, argv, "c:m:b:")) != -1) {
		switch (opt) {
		case 'c':
			guest_ncpus = atoi(optarg);
			break;
		case 'm':
			error = vm_parse_memsize(optarg, &mem_size);
			if (error != 0 || mem_size == 0)
				errx(EX_USAGE, "Invalid memsize '%s'", optarg);
			break;
		case 'b':
			guest_bootorder = atoi(optarg);
			if (guest_bootorder < 0 || guest_bootorder > 11) {
				errx(EX_USAGE, "Invalid bootoption: %d\n"
		 		    "\tBoot order code:\n"
 				    "\t0 - EFI_CD_HD\n"
 				    "\t1 - EFI_CD\n"
 				    "\t2 - EFI_HD_CD\n"
				    "\t3 - EFI_HD\n"
				    "\t4 - EFI_NET\n"
				    "\t5 - EFI_NET_CD_HD\n"
				    "\t6 - EFI_HD_HD_CD\n"
				    "\t7 - LEGACY_CD_HD\n"
				    "\t8 - LEGACY_CD\n"
				    "\t9 - LEGACY_HD_CD\n"
				    "\t10 - LEGACY_HD\n"
 				    "\t11 - EFI_SHELL\n", guest_bootorder);
				exit(1);
			}
			break;
		case '?':
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	vmname = argv[0];
	error = vm_create(vmname);
	if (error != 0 && errno != EEXIST) {
		perror("vm_create");
		exit(1);

	}

	ctx = vm_open(vmname);
	if (ctx == NULL) {
		perror("vm_open");
		exit(1);
	}

	error = vm_set_capability(ctx, 0, VM_CAP_UNRESTRICTED_GUEST, 1);
	if (error) {
		perror("vm_set_capability(VM_CAP_UNRESTRICTED_GUEST)");
	}

	error = vm_setup_memory(ctx, mem_size, VM_MMAP_ALL);
	if (error) {
		perror("vm_setup_memory");
		exit(1);
	}
	membase = vm_map_gpa(ctx, 0, 8 * KB);

	error = vm_setup_rom(ctx, UEFI_ROM_ADDR, UEFI_ROM_SIZE);
	if (error) {
		perror("vm_setup_rom");
		exit(1);
	}
	rombase = vm_map_gpa(ctx, UEFI_ROM_ADDR, UEFI_ROM_SIZE);

	fd = open(UEFI_ROM_PATH, O_RDONLY);
	if (fd == -1) {
		perror("open");
		exit(1);
	}
	read(fd, rombase, UEFI_ROM_SIZE);
	close(fd);

	pi = (struct platform_info *)(membase + BHYVE_HOB_ADDR);
	pi->ncpus = guest_ncpus;
	bi = (struct bootorder_info *)(membase + BHYVE_BO_HOB_ADDR);
	bi->guestbootorder = guest_bootorder;

	error = vcpu_reset(ctx, 0);
	if (error) {
		perror("vcpu_reset");
		exit(1);
	}

	return (0);
}
