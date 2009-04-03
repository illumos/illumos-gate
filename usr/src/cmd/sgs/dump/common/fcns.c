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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<string.h>
#include	<libelf.h>
#include	<limits.h>
#include	"conv.h"
#include	"dump.h"

extern int	p_flag;
extern char	*prog_name;


/*
 * Print the symbols in the archive symbol table.
 */
void
ar_sym_read(Elf *elf, char *filename)
{
	Elf_Arsym *	arsym;
	size_t		cnt, ptr;

	if ((arsym = elf_getarsym(elf, &ptr)) == NULL) {
		(void) fprintf(stderr, "%s: %s: no archive symbol table\n",
		    prog_name, filename);
		return;
	}

	(void) printf("%s:\n", filename);

	if (!p_flag) {
		(void) printf("     **** ARCHIVE SYMBOL TABLE ****\n");
		(void) printf("%-8s %s\n\n", "Offset", "Name");
	}
	for (cnt = 0; cnt < ptr; cnt++, arsym++) {
		if (arsym->as_off) {
			/* LINTED */
			(void) printf("%-8.8x %s\n", (int)arsym->as_off,
			    (arsym->as_name ? arsym->as_name : ""));
		}
	}
}

/*
 * Print the program execution header.  Input is an opened ELF object file, the
 * number of structure instances in the header as recorded in the ELF header,
 * and the filename.
 */
void
dump_exec_header(Elf *elf_file, unsigned nseg, char *filename)
{
	GElf_Ehdr ehdr;
	GElf_Phdr p_phdr;
	int counter;
	int field;
	extern int v_flag, p_flag;
	extern char *prog_name;

	if (gelf_getclass(elf_file) == ELFCLASS64)
		field = 16;
	else
		field = 12;

	if (!p_flag) {
		(void) printf(" ***** PROGRAM EXECUTION HEADER *****\n");
		(void) printf("%-*s%-*s%-*s%s\n",
		    field, "Type", field, "Offset",
		    field, "Vaddr", "Paddr");
		(void) printf("%-*s%-*s%-*s%s\n\n",
		    field, "Filesz", field, "Memsz",
		    field, "Flags", "Align");
	}

	if ((gelf_getehdr(elf_file, &ehdr) == 0) || (ehdr.e_phnum == 0)) {
		return;
	}

	for (counter = 0; counter < nseg; counter++) {

		if (gelf_getphdr(elf_file, counter, &p_phdr) == 0) {
			(void) fprintf(stderr,
			    "%s: %s: premature EOF on program exec header\n",
			    prog_name, filename);
			return;
		}

		if (!v_flag) {
			(void) printf(
	"%-*d%-#*llx%-#*llx%-#*llx\n%-#*llx%-#*llx%-*u%-#*llx\n\n",
			    field, EC_WORD(p_phdr.p_type),
			    field, EC_OFF(p_phdr.p_offset),
			    field, EC_ADDR(p_phdr.p_vaddr),
			    field, EC_ADDR(p_phdr.p_paddr),
			    field, EC_XWORD(p_phdr.p_filesz),
			    field, EC_XWORD(p_phdr.p_memsz),
			    field, EC_WORD(p_phdr.p_flags),
			    field, EC_XWORD(p_phdr.p_align));
		} else {
			Conv_inv_buf_t	inv_buf;

			(void) printf("%-*s", field,
			    conv_phdr_type(ehdr.e_ident[EI_OSABI],
			    ehdr.e_machine, p_phdr.p_type, DUMP_CONVFMT,
			    &inv_buf));
			(void) printf(
			    "%-#*llx%-#*llx%-#*llx\n%-#*llx%-#*llx",
			    field, EC_OFF(p_phdr.p_offset),
			    field, EC_ADDR(p_phdr.p_vaddr),
			    field, EC_ADDR(p_phdr.p_paddr),
			    field, EC_XWORD(p_phdr.p_filesz),
			    field, EC_XWORD(p_phdr.p_memsz));

			switch (p_phdr.p_flags) {
			case 0: (void) printf("%-*s", field, "---"); break;
			case PF_X:
				(void) printf("%-*s", field, "--x");
				break;
			case PF_W:
				(void) printf("%-*s", field, "-w-");
				break;
			case PF_W+PF_X:
				(void) printf("%-*s", field, "-wx");
				break;
			case PF_R:
				(void) printf("%-*s", field, "r--");
				break;
			case PF_R+PF_X:
				(void) printf("%-*s", field, "r-x");
				break;
			case PF_R+PF_W:
				(void) printf("%-*s", field, "rw-");
				break;
			case PF_R+PF_W+PF_X:
				(void) printf("%-*s", field, "rwx");
				break;
			default:
				(void) printf("%-*d", field, p_phdr.p_flags);
				break;
			}
			(void) printf(
			    "%-#*llx\n\n", field, EC_XWORD(p_phdr.p_align));
		}
	}
}
