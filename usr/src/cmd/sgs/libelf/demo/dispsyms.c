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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * dispsyms: Display Symbols
 *
 * This program demonstrates the use of the libelf interface to
 * read an ELF file.  dispsyms will open an ELF file using
 * elf_begin(ELF_C_READ) and examine search the ELF file
 * for a symbol table (SHT_SYMTAB, SHT_DYNSYM, or SHT_SUNW_LDYNSYM).
 * It will display the contents of any symbol tables it finds.
 *
 * Note:  This program also understands about the use
 *	  of 'Extended ELF Section indexes' and will
 *	  decode a corresponding SHT_SYMTAB_SHNDX
 *	  section if required.
 */


#include <stdio.h>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static const char *symbind[STB_NUM] = {
/* STB_LOCL */		"LOCL",
/* STB_GLOBAL */	"GLOB",
/* STB_WEAK */		"WEAK"
};

static const char *symtype[STT_NUM] = {
/* STT_NOTYPE */	"NOTY",
/* STT_OBJECT */	"OBJT",
/* STT_FUNC */		"FUNC",
/* STT_SECTION */	"SECT",
/* STT_FILE */		"FILE",
/* STT_COMMON */	"COMM",
/* STT_TLS */		"TLS"
};


#define	INTSTRLEN	32


static void
print_symtab(Elf *elf, const char *file)
{
	Elf_Scn		*scn;
	GElf_Shdr	shdr;
	GElf_Ehdr	ehdr;
	size_t		shstrndx;


	if (gelf_getehdr(elf, &ehdr) == 0) {
		(void) fprintf(stderr, "%s: elf_getehdr() failed: %s\n",
			file, elf_errmsg(0));
		return;
	}

	if (elf_getshstrndx(elf, &shstrndx) == 0) {
		(void) fprintf(stderr, "%s: elf_getshstrndx() failed: %s\n",
			file, elf_errmsg(0));
		return;
	}

	scn = 0;
	while ((scn = elf_nextscn(elf, scn)) != 0) {
		uint_t		symcnt;
		uint_t		ndx;
		uint_t		nosymshndx;
		Elf_Data	*symdata;
		Elf_Data	*shndxdata;

		if (gelf_getshdr(scn, &shdr) == 0) {
			(void) fprintf(stderr,
				"%s: elf_getshdr() failed: %s\n",
				file, elf_errmsg(0));
			return;
		}
		if ((shdr.sh_type != SHT_SYMTAB) &&
		    (shdr.sh_type != SHT_DYNSYM) &&
		    (shdr.sh_type != SHT_SUNW_LDYNSYM))
			continue;

		/*
		 * Get the data associated with the Symbol
		 * section.
		 */
		if ((symdata = elf_getdata(scn, 0)) == 0) {
			(void) fprintf(stderr,
				"%s: elf_getdata() failed: %s\n",
				file, elf_errmsg(0));
			return;
		}

		/*
		 * Print symbol table title and header for symbol display
		 */
		(void) printf("\nSymTab: %s:%s\n", file,
			elf_strptr(elf, shstrndx, shdr.sh_name));
		(void) printf("  index   value    size     type "
			"bind  oth shndx name\n");

		/*
		 * We now iterate over the full symbol table printing
		 * the symbols as we go.
		 */
		shndxdata = 0;
		nosymshndx = 0;
		symcnt = shdr.sh_size / shdr.sh_entsize;
		for (ndx = 0; ndx < symcnt; ndx++) {
			GElf_Sym	sym;
			Elf32_Word	shndx;
			uint_t		type;
			uint_t		bind;
			uint_t		specshndx;
			char		bindbuf[INTSTRLEN];
			char		typebuf[INTSTRLEN];
			char		shndxbuf[INTSTRLEN];
			const char	*bindstr;
			const char	*typestr;
			const char	*shndxstr;

			/*
			 * Get a symbol entry
			 */
			if (gelf_getsymshndx(symdata, shndxdata, ndx,
			    &sym, &shndx) == NULL) {
				(void) fprintf(stderr,
					"%s: gelf_getsymshndx() failed: %s\n",
					file, elf_errmsg(0));
				return;
			}
			/*
			 * Check to see if this symbol's st_shndx
			 * is using the 'Extended SHNDX table' for
			 * a SYMTAB.
			 *
			 * If it is - and we havn't searched before,
			 * go find the associated SHT_SYMTAB_SHNDX
			 * section.
			 */
			if ((sym.st_shndx == SHN_XINDEX) &&
			    (shndxdata == 0) && (nosymshndx == 0)) {
				Elf_Scn		*_scn;
				GElf_Shdr	_shdr;
				GElf_Word	symscnndx;
				_scn = 0;
				specshndx = 0;
				symscnndx = elf_ndxscn(scn);

				while ((_scn = elf_nextscn(elf, _scn)) != 0) {
					if (gelf_getshdr(_scn, &_shdr) == 0)
						break;
					/*
					 * We've found the Symtab SHNDX table
					 * if it's of type SHT_SYMTAB_SHNDX
					 * and it's shdr.sh_link points to the
					 * section index for the current symbol
					 * table.
					 */
					if ((_shdr.sh_type ==
					    SHT_SYMTAB_SHNDX) &&
					    (_shdr.sh_link == symscnndx)) {
						if ((shndxdata =
						    elf_getdata(_scn, 0)) != 0)
							break;
					}
				}
				/*
				 * Get a symbol entry
				 */
				if (shndxdata &&
				    (gelf_getsymshndx(symdata, shndxdata, ndx,
				    &sym, &shndx) == NULL)) {
					(void) fprintf(stderr,
						"%s: gelf_getsymshndx() "
						"failed: %s\n",
						file, elf_errmsg(0));
					return;
				}
				/*
				 * No Symtab SHNDX table was found.  We could
				 * give a fatal error here - instead we'll
				 * just mark that fact and display as much of
				 * the symbol table as we can.  Any symbol
				 * displayed with a XINDX section index has
				 * a bogus value.
				 */
				if (shndxdata == 0)
					nosymshndx = 1;
			}

			/*
			 * Decode the type & binding information
			 */
			type = GELF_ST_TYPE(sym.st_info);
			bind = GELF_ST_BIND(sym.st_info);

			if (type < STT_NUM)
				typestr = symtype[type];
			else {
				(void) snprintf(typebuf, INTSTRLEN,
					"%d", type);
				typestr = typebuf;
			}

			if (bind < STB_NUM)
				bindstr = symbind[bind];
			else {
				(void) snprintf(bindbuf, INTSTRLEN,
					"%d", bind);
				bindstr = bindbuf;
			}


			specshndx = 0;
			if (sym.st_shndx <  SHN_LORESERVE)
				shndx = sym.st_shndx;
			else if ((sym.st_shndx != SHN_XINDEX) ||
			    (shndxdata == NULL)) {
				shndx = sym.st_shndx;
				specshndx = 1;
			}

			if (shndx == SHN_UNDEF) {
				shndxstr = (const char *)"UNDEF";

			} else if (specshndx) {
				if (shndx == SHN_ABS)
					shndxstr = (const char *)"ABS";
				else if (shndx == SHN_COMMON)
					shndxstr = (const char *)"COMM";
				else if (shndx == SHN_XINDEX)
					shndxstr = (const char *)"XIND";
				else {
					(void) snprintf(shndxbuf, INTSTRLEN,
						"%ld", shndx);
					shndxstr = shndxbuf;
				}
			} else {
				(void) snprintf(shndxbuf, INTSTRLEN,
					"%ld", shndx);
				shndxstr = shndxbuf;
			}

			/*
			 * Display the symbol entry.
			 */
			(void) printf("[%3d] 0x%08llx 0x%08llx %-4s "
				"%-6s %2d %5s %s\n",
				ndx, sym.st_value, sym.st_size,
				typestr, bindstr, sym.st_other, shndxstr,
				elf_strptr(elf, shdr.sh_link, sym.st_name));
		}
	}
}


static void
process_elf(Elf *elf, char *file, int fd, int member)
{
	Elf_Cmd	cmd;
	Elf	*_elf;

	switch (elf_kind(elf)) {
	case ELF_K_ELF:
		/*
		 * This is an ELF file, now attempt to find it's
		 * .comment section and to display it.
		 */
		print_symtab(elf, file);
		break;
	case ELF_K_AR:
		/*
		 * Archives contain multiple ELF files, which can each
		 * in turn be examined with libelf.
		 *
		 * The below loop will iterate over each member of the
		 * archive and recursivly call process_elf() for processing.
		 */
		cmd = ELF_C_READ;
		while ((_elf = elf_begin(fd, cmd, elf)) != 0) {
			Elf_Arhdr	*arhdr;
			char		buffer[1024];

			arhdr = elf_getarhdr(_elf);

			/*
			 * Build up file names based off of
			 * 'archivename(membername)'.
			 */
			(void) snprintf(buffer, 1024, "%s(%s)",
				file, arhdr->ar_name);

			/*
			 * recursivly process the ELF members.
			 */
			process_elf(_elf, buffer, fd, 1);
			cmd = elf_next(_elf);
			(void) elf_end(_elf);
		}
		break;
	default:
		if (!member)
			(void) fprintf(stderr,
				"%s: unexpected elf_kind(): 0x%x\n",
				file, elf_kind(elf));
		return;
	}
}


int
main(int argc, char **argv)
{
	int	i;


	if (argc < 2) {
		(void) printf("usage: %s elf_file ...\n", argv[0]);
		return (1);
	}

	/*
	 * Initialize the elf library, must be called before elf_begin()
	 * can be called.
	 */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr,
			"elf_version() failed: %s\n", elf_errmsg(0));
		return (1);
	}

	for (i = 1; i < argc; i++) {
		int	fd;
		Elf	*elf;
		char	*elf_fname;

		elf_fname = argv[i];
		if ((fd = open(elf_fname, O_RDONLY)) == -1) {
			perror("open");
			continue;
		}

		/*
		 * Attempt to open an Elf descriptor Read-Only
		 * for each file.
		 */
		if ((elf = elf_begin(fd, ELF_C_READ, 0)) == NULL) {
			(void) fprintf(stderr, "elf_begin() failed: %s\n",
			    elf_errmsg(0));
			(void) close(fd);
			continue;
		}

		/*
		 * Process each elf descriptor.
		 */
		process_elf(elf, elf_fname, fd, 0);
		(void) elf_end(elf);
		(void) close(fd);
	}

	return (0);
}
