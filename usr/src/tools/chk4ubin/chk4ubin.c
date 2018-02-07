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

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <stdlib.h>
#include <errno.h>
#include <malloc.h>
#include <memory.h>
#include <libelf.h>
#include <gelf.h>

/*
 * Tool to inspect a sun4u bootable module for a symbol table size
 * that will trigger a fatal error on older versions of OBP.
 *
 * The failure mode when booting is recorded in CR 6828121
 * and appears as follows:
 *
 *	Executing last command: boot
 *	Boot device: /pci@1f,0/pci@1/scsi@8/disk@0,0:a  File and args: kmdb
 *
 *	Error in Fcode execution !!!
 *	Evaluating: to load-base init-program
 *	Out of memory
 *	Warning: Fcode sequence resulted in a net stack depth change of 1
 *
 *	Error in Fcode execution !!!
 *	Evaluating: to load-base init-program
 *
 *	Evaluating: to load-base init-program
 *	The file just loaded does not appear to be executable.
 *	ok
 *
 * The OBP bug is CR 4777088, fixed in OBP versions 4.12.1 and forward.
 *
 * The OBP memory allocator for the memory into which the module's
 * symbol table is read fails for a specific memory range on
 * each page, where the size &= 0x1fff is > 0x1fe1 && <= 0x1ff0.
 * Note the symbol table size is the size of both the SYMTAB
 * and the STRTAB ELF sections.
 *
 * To prevent this problem on a given machine, update or patch the OBP.
 *
 * If this tool reports that a module has a symbol table size in
 * the failing range, that build will not boot on any machine with
 * this OBP problem.  The only known work-around is to make some
 * source change to add or remove symbols to adjust the symbol table
 * size outside the triggering range.
 *
 * Each sun4u bootable module is in theory affected by this, including
 * cprboot, bootlst, and each unix module.  Although the serengeti
 * (Sun-Fire) and opl (SPARC-Enterprise) OBP implementations never
 * included this bug.  The bug only occurs for allocations
 * pagesize or greater, and the only such OBP allocation is for a
 * module's symbol table, for the sum of the SYMTAB and STRTAB
 * sections.  The inetboot binary does not include these sections
 * and is therefore also unaffected.
 */

static char	*whoami;
static int	verbose		= 0;
static int	inject_err	= 0;
static int	no_err		= 0;
static int	exitcode	= 0;
static uint_t	pagemask	= 0x1fff;

static char *sun4u_bootables[] = {
	"platform/sun4u/kernel/sparcv9/unix",
	"platform/SUNW,Ultra-Enterprise-10000/kernel/sparcv9/unix",
	"platform/SUNW,Sun-Fire-15000/kernel/sparcv9/unix",
	"platform/sun4u/cprboot",
	"platform/sun4u/bootlst"
};
static int nsun4ubootables = sizeof (sun4u_bootables) / sizeof (char *);

/*
 * size check should be:
 *	size &= 0x1fff, size > 0x1fe1 && size <= 0x1ff0
 */
static uint_t toxic_start	= 0x1fe2;
static uint_t toxic_end		= 0x1ff0;

/*
 * Tag each error message so it shows up in the build summary mail
 */
static char *detailed_error_msg =
	"ERROR: This binary will not boot on any machine with an older\n"
	"ERROR: version of OBP.  See CR 4777088 and 6828121 for more details.\n"
	"ERROR: No work-around is possible other than making changes to\n"
	"ERROR: add/remove symbols from the module to move the symbol\n"
	"ERROR: table size outside the toxic range.\n";


static int
chk4ubin(char *root, char *binary)
{
	int  		fd;
	Elf		*elf;
	Elf_Scn		*symscn;
	Elf_Scn		*strscn;
	GElf_Shdr	symhdr;
	GElf_Shdr	strhdr;
	int64_t		symtab_size;
	int64_t		strtab_size;
	int64_t		total;
	int		found_symtab = 0;
	int		found_strtab = 0;
	uint_t		off;
	int		rv = 1;
	char		path[MAXPATHLEN];

	if (root == NULL) {
		(void) snprintf(path, sizeof (path), "%s", binary);
	} else {
		(void) snprintf(path, sizeof (path), "%s/%s", root, binary);
	}

	if ((fd = open(path, O_RDONLY)) == -1) {
		(void) printf("%s: cannot open %s - %s\n",
		    whoami, path, strerror(errno));
		return (1);
	}

	elf_version(EV_CURRENT);
	elf = elf_begin(fd, ELF_C_READ, NULL);

	symscn = NULL;
	while ((symscn = elf_nextscn(elf, symscn)) != NULL) {
		gelf_getshdr(symscn, &symhdr);
		switch (symhdr.sh_type) {
		case SHT_SYMTAB:
			found_symtab = 1;
			symtab_size = symhdr.sh_size;
			strscn = elf_getscn(elf, symhdr.sh_link);
			if (strscn != NULL) {
				gelf_getshdr(strscn, &strhdr);
				strtab_size = strhdr.sh_size;
				found_strtab = 1;
			}
			break;
		}
		if (found_symtab && found_strtab)
			break;
	}

	elf_end(elf);
	(void) close(fd);

	if (found_symtab && found_strtab) {
		int err;
		total = symtab_size + strtab_size;
		off = total & pagemask;
		err = (off >= toxic_start && off <= toxic_end);
		if (inject_err || err) {
			(void) printf("%s: ERROR: %s\n", whoami, binary);
			(void) printf("ERROR: symbol table size 0x%llx is "
			    "in toxic range (0x%x - 0x%x)!\n",
			    total, toxic_start, toxic_end);
			(void) printf("%s", detailed_error_msg);
		} else {
			rv = 0;
			(void) printf("%s: %s ok\n", whoami, binary);
			if (verbose) {
				(void) printf("symbol table size 0x%llx "
				    "not in toxic range (0x%x - 0x%x)\n",
				    total, toxic_start, toxic_end);
			}
		}
		if (verbose) {
			(void) printf(".symtab size: 0x%llx\n",
			    symtab_size);
			(void) printf(".strtab size: 0x%llx\n",
			    strtab_size);
			(void) printf("total:        0x%llx "
			    "(0x%llx, 0x%llx)\n", total, (total & ~pagemask),
			    (total & pagemask));
		}
		if (verbose || err || inject_err)
			(void) printf("\n");
	} else {
		if (!found_symtab && !found_strtab) {
			(void) fprintf(stderr,
			    "%s: %s - no symtab or strtab section found\n",
			    whoami, binary);
		} else if (!found_symtab) {
			(void) fprintf(stderr,
			    "%s: %s - no symtab section found\n",
			    whoami, binary);
		} else if (!found_strtab) {
			(void) fprintf(stderr,
			    "%s: %s - no strtab section found\n",
			    whoami, binary);
		}
	}

	return (rv);
}

static void
usage()
{
	int i;

	(void) fprintf(stderr,
	    "usage: %s [-n] [-v] [-r <root>] [<binary>] ...\n", whoami);
	(void) fprintf(stderr,
	    "    -n: exit with 0 even with an error detected to allow\n");
	(void) fprintf(stderr,
	    "        a build to succeed even with a failing binary\n");
	(void) fprintf(stderr,
	    "The default list of binaries checked if none supplied is:\n");
	for (i = 0; i < nsun4ubootables; i++) {
		(void) fprintf(stderr, "    %s\n", sun4u_bootables[i]);
	}
	exit(0);
}

int
main(int argc, char *argv[])
{
	int	i;
	char	*root = NULL;

	whoami = basename(argv[0]);

	opterr = 0;
	while ((i = getopt(argc, argv, "enr:R:v")) != -1) {
		switch (i) {
		case 'v':
			verbose = 1;
			break;
		case 'e':
			inject_err = 1;
			break;
		case 'n':
			no_err = 1;
			break;
		case 'r':
		case 'R':
			root = optarg;
			break;
		default:
			usage();
			break;
		}
	}

	if (optind < argc) {
		for (i = optind; i < argc; i++) {
			if (chk4ubin(root, argv[i]) != 0)
				exitcode = 1;
		}
	} else {
		for (i = 0; i < nsun4ubootables; i++) {
			if (root == NULL)
				root = "/";
			if (chk4ubin(root, sun4u_bootables[i]) != 0)
				exitcode = 1;
		}
	}

	return (no_err ? 0 : exitcode);
}
