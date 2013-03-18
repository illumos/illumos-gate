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
 * Copyright (c) 2011, Joyent, Inc. All rights reserved.
 * Copyright (c) 2011, Robert Mustacchi, Inc. All rights reserved.
 * Copyright 2013, Richard Lowe.
 */

#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libctf.h>
#include <saveargs.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

extern const char *__progname;

typedef struct symtab_sym {
	GElf_Sym ss_sym;
	char *ss_name;
	ctf_funcinfo_t ss_finfo;
	uint8_t *ss_data;
	size_t ss_size;
} symtab_sym_t;

static void
walk_symtab(Elf *elf, char *fname, ctf_file_t *fp,
    void (*callback)(ctf_file_t *, symtab_sym_t *))
{
	Elf_Scn *stab = NULL;
	Elf_Scn *text = NULL;
	Elf_Data *stabdata = NULL;
	Elf_Data *textdata = NULL;
	GElf_Ehdr ehdr;
	GElf_Shdr stabshdr;
	GElf_Shdr textshdr;
	int foundtext = 0, foundstab = 0;
	symtab_sym_t ss;

	if ((gelf_getehdr(elf, &ehdr)) == NULL)
		errx(1, "could not read ELF header from %s\n",
		    fname);

	while ((stab = elf_nextscn(elf, stab)) != NULL) {
		(void) gelf_getshdr(stab, &stabshdr);

		if (stabshdr.sh_type == SHT_SYMTAB) {
			foundstab = 1;
			break;
		}
	}

	while ((text = elf_nextscn(elf, text)) != NULL) {
		(void) gelf_getshdr(text, &textshdr);

		if (strcmp(".text", elf_strptr(elf,
		    ehdr.e_shstrndx, (size_t)textshdr.sh_name)) == 0) {
			foundtext = 1;
			break;
		}
	}

	if (!foundstab || !foundtext)
		return;

	stabdata = elf_getdata(stab, NULL);
	textdata = elf_rawdata(text,  NULL);
	for (unsigned symdx = 0;
	    symdx < (stabshdr.sh_size / stabshdr.sh_entsize);
	    symdx++) {
		(void) gelf_getsym(stabdata, symdx, &ss.ss_sym);

		if ((GELF_ST_TYPE(ss.ss_sym.st_info) != STT_FUNC) ||
		    (ss.ss_sym.st_shndx == SHN_UNDEF))
			continue;

		ss.ss_name = elf_strptr(elf, stabshdr.sh_link,
		    ss.ss_sym.st_name);
		ss.ss_data = ((uint8_t *)(textdata->d_buf)) +
		    (ss.ss_sym.st_value - textshdr.sh_addr);

		if (ctf_func_info(fp, symdx, &ss.ss_finfo) == CTF_ERR) {
			fprintf(stderr, "failed to get funcinfo for: %s\n",
			    ss.ss_name);
			continue;
		}

		(void) callback(fp, &ss);
	}
}

void
check_sym(ctf_file_t *ctfp, symtab_sym_t *ss)
{
	int rettype = ctf_type_kind(ctfp, ss->ss_finfo.ctc_return);
	int start_index = 0;

	if (ss->ss_finfo.ctc_argc == 0) /* No arguments, no point */
		return;

	if (((rettype == CTF_K_STRUCT) || (rettype == CTF_K_UNION)) &&
	    ctf_type_size(ctfp, ss->ss_finfo.ctc_return) > 16)
		start_index = 1;

	if (saveargs_has_args(ss->ss_data, ss->ss_sym.st_size,
	    ss->ss_finfo.ctc_argc, start_index) != SAVEARGS_NO_ARGS)
		printf("%s has %d saved args\n", ss->ss_name,
		    ss->ss_finfo.ctc_argc);
}

int
main(int argc, char **argv)
{
	Elf		*elf;
	ctf_file_t	*ctfp;
	int errp, fd;

	if (ctf_version(CTF_VERSION) == -1)
		errx(1, "mismatched libctf versions\n");

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(1, "mismatched libelf versions\n");

	if (argc != 2)
		errx(2, "usage: %s <file>\n", __progname);

	if ((ctfp = ctf_open(argv[1], &errp)) == NULL)
		errx(1, "failed to ctf_open file: %s: %s\n", argv[1],
		    ctf_errmsg(errp));

	if ((fd = open(argv[1], O_RDONLY)) == -1)
		errx(1, "could not open %s\n", argv[1]);

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		errx(1, "could not interpret ELF from %s\n",
		    argv[1]);

	walk_symtab(elf, argv[1], ctfp, check_sym);

	(void) elf_end(elf);
	(void) close(fd);

	return (0);
}
