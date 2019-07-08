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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T */
/*	  All Rights Reserved	*/

/* Copyright 2011 Nexenta Systems, Inc. All rights reserved. */


/* ------------------------------------------------------------------------ */
/* include headers */
/* ------------------------------------------------------------------------ */

#include "static_prof.h"

/* ========== elf_hash ==================================================== */
/*
 * DESCRIPTION:
 * The hash function copied from libelf.so.1
 */
/* ======================================================================== */

static unsigned long
my_elf_hash(const char *name)
{
	unsigned long g, h = 0;
	const unsigned char *nm = (unsigned char *) name;

	while (*nm != '\0') {
		h = (h << 4) + *nm++;
		if ((g = h & MASK) != 0)
			h ^= g >> 24;
		h &= ~MASK;
	}
	return (h);
}

/* ========== output_dtneeded ============================================= */
/*
 * DESCRIPTION:
 * Outputs all the dt_needed entries if any.
 */
/* ======================================================================== */

static void
output_dtneeded(dt_list * list)
{

	dt_list		*p = list;

	(void) fprintf(OUTPUT_FD, "#dtneeded:");
	if (!p) {
		(void) fprintf(OUTPUT_FD, "\n");
		return;
	} else {
		while (p != NULL) {
			(void) fprintf(OUTPUT_FD,
			    " %s",
			    p->libname);
			p = p->next;
		}
		(void) fprintf(OUTPUT_FD, "\n");
	}
}

/* ========== store_binding =============================================== */
/*
 * DESCRIPTION:
 * Read in the symbol binding information from the symbol table and
 * store them into the hash table of buckets.
 */
/* ======================================================================== */

static void
store_binding(binding_bucket * bind)
{
	unsigned long   bktno;
	unsigned long   orig_bktno;

	bktno = my_elf_hash(bind->sym) % DEFBKTS;
	orig_bktno = bktno;

	while (bkts[bktno].sym != NULL) {
		bktno = (bktno + 1) % DEFBKTS;

		if (bktno == orig_bktno)
			exit(1);
	}

	bkts[bktno].sym = bind->sym;
	bkts[bktno].obj = bind->obj;
	bkts[bktno].ref_lib = bind->ref_lib;
	bkts[bktno].def_lib = bind->def_lib;
	bkts[bktno].section = bind->section;
	bkts[bktno].stbind = bind->stbind;
	bkts[bktno].sttype = bind->sttype;
}


/* ========== check_store_binding ========================================= */
/*
 * DESCRIPTION:
 * Check what's already on the hash table with the new symbol binding
 * information from the dependencies and record it into the bucket.
 */
/* ======================================================================== */

static void
check_store_binding(binding_bucket * bind)
{
	unsigned long   bktno;
	unsigned long   orig_bktno;
	unsigned long   i;

	bktno = my_elf_hash(bind->sym) % DEFBKTS;
	orig_bktno = bktno;

	if (!bkts[bktno].sym)
		return;
	if (bkts[bktno].sym && (strcmp(bkts[bktno].sym, bind->sym)) == 0) {
		if (strcmp(bkts[bktno].ref_lib, "<Unknown>") == 0)
			if (strcmp(bkts[bktno].obj, bind->obj))
				bkts[bktno].ref_lib = bind->obj;
	} else {
		bktno = (bktno + 1) % DEFBKTS;
		for (i = bktno; i < DEFBKTS; i = (i + 1) % DEFBKTS) {
			if (i == orig_bktno)
				break;
			if (!bkts[i].sym)
				continue;
			if (bkts[i].sym &&
			    (strcmp(bkts[i].sym, bind->sym)) == 0) {
				if (strcmp(bkts[i].ref_lib, "<Unknown>") == 0)
					if (strcmp(bkts[i].obj, bind->obj))
						bkts[i].ref_lib = bind->obj;
				break;
			}
		}
	}
}

/* ========== stringcompare =============================================== */
/*
 * DESCRIPTION:
 * Compares two strings for qsort().
 */
/* ======================================================================== */

static int
stringcompare(binding_bucket * a,
    binding_bucket * b)
{
	char		*x = "\0";
	char		*y = "\0";
	int		retcode;

	if (a->sym)
		x = a->sym;

	if (b->sym)
		y = b->sym;

	retcode = strcoll(x, y);
	return (retcode);
}

/* ========== profile_binding ============================================= */
/*
 * DESCRIPTION:
 * Output the bindings directly to stdout or a file.
 */
/* ======================================================================== */

static void
profile_binding(binding_bucket * bind)
{
	char		*ref_lib_ptr;

	if (bind->sym && strcmp(bind->ref_lib, "<Unknown>")) {
		if (ref_lib_ptr = strrchr(bind->ref_lib, (int)'/')) {
			ref_lib_ptr++;
			if (bind->stbind)
				(void) fprintf(OUTPUT_FD,
				    "%s|%s|%s|%s|%s|%s|%s\n",
				    ref_lib_ptr,
				    bind->section,
				    bind->stbind,
				    bind->sttype,
				    bind->sym,
				    bind->def_lib,
				    bind->obj);
		} else if (bind->stbind)
			(void) fprintf(OUTPUT_FD,
			    "%s|%s|%s|%s|%s|%s|%s\n",
			    bind->ref_lib,
			    bind->section,
			    bind->stbind,
			    bind->sttype,
			    bind->sym,
			    bind->def_lib,
			    bind->obj);
	} else if (bind->sym && bind->stbind)
		(void) fprintf(OUTPUT_FD,
		    "%s|%s|%s|%s|%s\n",
		    bind->obj,
		    bind->section,
		    bind->stbind,
		    bind->sttype,
		    bind->sym);
}

/* ========== output_binding ============================================== */
/*
 * DESCRIPTION:
 * Output the hash table to either stdout or a file.
 */
/* ======================================================================== */

static void
output_binding(char *prog_name,
    char *target)
{
	int		i;
	char		*ref_lib_ptr;

	qsort(bkts,
	    DEFBKTS,
	    sizeof (binding_bucket),
	    (int (*) (const void *, const void *)) stringcompare);

	if (oflag) {
		if ((OUTPUT_FD = fopen(outputfile, "w")) == NULL) {
			if (sflag)
				(void) fprintf(stderr,
				    "\nfopen failed to open <%s>...\n\n",
				    outputfile);
			exit(1);
		}
	}
	/* generates profile report */
	(void) fprintf(OUTPUT_FD,
	    "#generated by %s\n",
	    prog_name);
	(void) fprintf(OUTPUT_FD,
	    "#profiling symbols in .text section of %s\n",
	    target);
	output_dtneeded(dt_needed);

	for (i = 0; i < DEFBKTS; i++) {
		if (bkts[i].sym && strcmp(bkts[i].ref_lib, "<Unknown>")) {
			if (ref_lib_ptr = strrchr(bkts[i].ref_lib, (int)'/')) {
				ref_lib_ptr++;
				if (bkts[i].stbind)
					(void) fprintf(OUTPUT_FD,
					    "%s|%s|%s|%s|%s|%s|%s\n",
					    ref_lib_ptr,
					    bkts[i].section,
					    bkts[i].stbind,
					    bkts[i].sttype,
					    bkts[i].sym,
					    bkts[i].def_lib,
					    bkts[i].obj);
			} else if (bkts[i].stbind)
				(void) fprintf(OUTPUT_FD,
				    "%s|%s|%s|%s|%s|%s|%s\n",
				    bkts[i].ref_lib,
				    bkts[i].section,
				    bkts[i].stbind,
				    bkts[i].sttype,
				    bkts[i].sym,
				    bkts[i].def_lib,
				    bkts[i].obj);
		} else if (bkts[i].sym && bkts[i].stbind)
			(void) fprintf(OUTPUT_FD,
			    "%s|%s|%s|%s|%s\n",
			    bkts[i].obj,
			    bkts[i].section,
			    bkts[i].stbind,
			    bkts[i].sttype,
			    bkts[i].sym);
	}
}

/* ========== obj_init ==================================================== */
/*
 * DESCRIPTION:
 * Open (object) file, get ELF descriptor, and verify that the file is
 * an ELF file.
 */
/* ======================================================================== */

static int
obj_init(obj_list * c)
{
	int		mode = O_RDONLY;

	/* open the file */
	if ((c->obj->fd = open(c->obj->ename, mode)) < 0) {
		if (sflag) {
			if (errno == ENOENT)
				(void) fprintf(stderr,
				    "Cannot open <<%s>> : \
				    No such file or directory.\n",
				    c->obj->ename);
			else if (errno == EMFILE)
				(void) fprintf(stderr,
				    "File <<%s>> : Already opened.\n",
				    c->obj->ename);
		}
		c->obj->fd = 0;
		return (FAIL);
	}
	/*
	 * queries the ELF library's internal version.
	 * Passing ver equal to EV_NONE causes elf_version() to return
	 * the library's internal version, without altering the working
	 * version.  If ver is a version known to the library,
	 * elf_version() returns the previous or initial working
	 * version number.  Otherwise, the working version remains
	 * unchanged and elf_version() returns EV_NONE.
	 */

	/* check if libelf.so is at the right level */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		if (sflag)
			(void) fprintf(stderr,
			    "Library out of date in ELF access routines.\n");
		return (FAIL);
	}
	/*
	 * Before the first call to elf_begin(), it must call
	 * elf_version() to coordinate versions.
	 */

	/*
	 * get elf descriptor just to examine the contents of an existing
	 * file
	 */
	if ((c->obj->elf = elf_begin(c->obj->fd, ELF_C_READ, (Elf *) 0))
	    == (Elf *) 0) {
		if (sflag)
			(void) fprintf(stderr,
			    "File is not in executable and \
			    linking format(ELF).\n");
		return (FAIL);
	}
	/* Rule out COFF, a.out and shell script files */
	if (elf_kind(c->obj->elf) == ELF_K_COFF) {
		if (sflag) {
			(void) fprintf(stderr,
			    "File is not in executable \
			    and linking format(ELF) or archive.\n");
		}
		return (FAIL);
	}
	if (elf_kind(c->obj->elf) != ELF_K_AR &&
	    elf_kind(c->obj->elf) != ELF_K_ELF) {
		if (sflag) {
			(void) fprintf(stderr,
			    "File is not in executable and linking \
			    format(ELF) or archive.\n");
		}
		return (FAIL);
	}
	return (SUCCEED);
}

/* ========== obj_elf_hdr ================================================= */
/*
 * DESCRIPTION:
 * Obtain the elf header, verify elf header information
 */
/* ======================================================================== */

static int
obj_elf_hdr(obj_list * c)
{
#if	defined(_LP64)
	Elf64_Ehdr	*ptr;
#else
	Elf32_Ehdr	*ptr;
#endif

	/*
	 * get the elf header if one is available for the ELF descriptor
	 * c->elf
	 */
#if	defined(_LP64)
	if ((ptr = elf64_getehdr(c->obj->elf)) == (Elf64_Ehdr *) 0) {
		if (sflag)
			(void) fprintf(stderr,
			    "File is not in 64-bit format.\n");
		return (FAIL);
	}
#else
	if ((ptr = elf32_getehdr(c->obj->elf)) == (Elf32_Ehdr *) 0) {
		if (sflag)
			(void) fprintf(stderr,
			    "File is not in 32-bit format.\n");
		return (FAIL);
	}
#endif

	/* if there is elf header, save the pointer */
#if defined(_LP64)
	c->obj->ehdr = (Elf64_Ehdr *) ptr;
#else
	c->obj->ehdr = (Elf32_Ehdr *) ptr;
#endif

	/* e_ident[] is identification index which holds values */
	/*
	 * we could also use elf_getident() to retrieve file identification
	 * data.
	 */

	/*
	 * e_ident[EI_CLASS] identifies the file's class:
	 * ELFCLASSNONE - invalid class
	 * ELFCLASS32   - 32-bit objects
	 * ELFCLASS64   - 64-bit objects
	 */

#if	defined(_LP64)
	if (ptr->e_ident[EI_CLASS] != ELFCLASS64) {
		if (sflag)
			(void) fprintf(stderr,
			    "File is not in 64-bit format.\n");
		return (FAIL);
	}
#else
	if (ptr->e_ident[EI_CLASS] != ELFCLASS32) {
		if (sflag)
			(void) fprintf(stderr,
			    "File is not in 32-bit format.\n");
		return (FAIL);
	}
#endif
	/*
	 * e_ident[EI_DATA] specifies the data encoding of the
	 * processor-specific data in the object file:
	 * ELFDATANONE - invalid data encoding
	 * ELFDATA2LSB - specifies 2's complement values, with the least
	 * significant byte occupying the lowest address
	 * ELFDATA2MSB - specifies 2's complement values, with the most
	 * significant byte occupying the lowest address
	 */

	/*
	 * e_ident[EI_VERSION] specifies the ELF header version number.
	 * Currently, this value must be EV_CURRENT.
	 */

	if (!(ptr->e_ident[EI_VERSION] == EV_CURRENT) &&
	    (ptr->e_version == EV_CURRENT)) {
		if (sflag)
			(void) fprintf(stderr,
			    "File is recorded in an \
			    incompatible ELF version.\n");
		return (FAIL);
	}
	/* only interested in relocatable, shared object, or executable file */
	switch (ptr->e_type) {
	case ET_REL:
	case ET_EXEC:
	case ET_DYN:
		break;
	default:
		if (sflag) {
			(void) fprintf(stderr,
			    "File is not relocatable, ");
			(void) fprintf(stderr,
			    "executable, or shared object.\n");
		}
		return (FAIL);
	}

	/*
	 * e_machine's value specifies the required architecture for an
	 * individual file
	 */

#if defined(__sparcv9)
	if (ptr->e_machine != EM_SPARCV9) {
		if (sflag)
			(void) fprintf(stderr,
			    "File is not for 64-bit \
			    SPARC machine architecture.\n");
		return (FAIL);
	}
#elif defined(__amd64)
	if (ptr->e_machine != EM_AMD64) {
		if (sflag)
			(void) fprintf(stderr,
			    "File is not for 64-bit \
			    amd64 machine architecture.\n");
		return (FAIL);
	}
#elif defined(__i386)
	if (ptr->e_machine != EM_386) {
		if (sflag)
			(void) fprintf(stderr,
			    "File is not for 32-bit \
			    i386 machine architecture.\n");
		return (FAIL);
	}
#else
	if (ptr->e_machine != EM_SPARC) {
		if (sflag)
			(void) fprintf(stderr,
			    "File is not for 32-bit \
			    SPARC machine architecture.\n");
		return (FAIL);
	}
#endif
	return (SUCCEED);
}

/* ========== obj_prog_hdr ============================================= */
/*
 * DESCRIPTION:
 * For executable files and shared objects only, check if it has
 * a program header table.
 */
/* ===================================================================== */

static int
obj_prog_hdr(obj_list * c)
{
	/*
	 * Assume:  the elf header has already been read, and the file
	 * has already been determined to be
	 * executable, shared object, or relocatable
	 */

	/*
	 * Program headers are meaningful only for executable and shared
	 * object files.  It is an array of structures, each describing a
	 * segment or other information needs to prepare the program for
	 * execution.
	 */

	/* skip if file is not executable or shared object */
	/* e_type == ET_REL meaning Relocatable file */
	if (c->obj->ehdr->e_type == ET_REL)
		return (SUCCEED);

	/*
	 * ehdr->e_phoff holds the program header table's file offset in
	 * bytes.
	 */
	/* If the file has no program header table, this member holds zero. */
	/*
	 * ehdr->e_phnum holds the number of entries in the program header
	 * table.
	 */
	/*
	 * If a file has no program header table, e_phnum holds the value
	 * zero.
	 */

	/* make sure there's a program header table */
	if ((c->obj->ehdr->e_phoff == 0) ||
	    (c->obj->ehdr->e_phnum == 0)) {
		if (sflag)
			(void) fprintf(stderr,
			    "File has no program header table.\n");
		return (FAIL);
	}
	return (SUCCEED);
}

/* ========== find_dynamic_sect ========================================== */
/*
 * DESCRIPTION:
 * Find the dynamic section.
 */
/* ======================================================================= */

static int
find_dynamic_sect(obj_list * c)
{
#if	defined(_LP64)
	Elf64_Shdr	*scurrent;	/* temp 64 bit section pointer */
#else
	Elf32_Shdr	*scurrent;	/* temp 32 bit section pointer */
#endif
	Elf_Scn		*scn;	/* temp section header pointer */
	Elf_Data	*ddata;	/* temp data header pointer */
	size_t		index;	/* temp section header table index */

	c->obj->dynnames = NULL; /* init of dynamic string table ptr */
	c->obj->dynsect = NULL;	/* init of dynamic section ptr */
	c->obj->ddata = NULL;	/* init of dynamic strtab data ptr */

	/* only process executables and shared objects */
	if (c->obj->ehdr->e_type != ET_EXEC && c->obj->ehdr->e_type != ET_DYN)
		return (SUCCEED);

	if ((c->obj->ehdr->e_shoff == 0) || (c->obj->ehdr->e_shnum == 0)) {
		/* there are no sections */
		return (SUCCEED);
	}
	/* search the section header table for dynamic section */

	/* start with null section; section index = 0 */
	scn = 0;

	while ((scn = elf_nextscn(c->obj->elf, scn)) != 0) {
		/* retrieve the section header */
#if	defined(_LP64)
		scurrent = elf64_getshdr(scn);
#else
		scurrent = elf32_getshdr(scn);
#endif

		/* check for dynamic section; (i.e., .dynamic) */
		if (scurrent->sh_type == SHT_DYNAMIC) {
			ddata = 0;
			if ((ddata = elf_getdata(scn, ddata)) == 0 ||
			    (ddata->d_size == 0))
				return (SUCCEED);

			/* now, we got data of dynamic section */
			c->obj->dynsect = ddata->d_buf;

			/* index to section header for dynamic string table */
			index = scurrent->sh_link;
			/* get scn descriptor of dynamic string table */
			scn = elf_getscn(c->obj->elf, index);
			/* get dynamic string table section header */
#if	defined(_LP64)
			scurrent = elf64_getshdr(scn);
#else
			scurrent = elf32_getshdr(scn);
#endif
			/* get the dynamic string table data descriptor */
			c->obj->ddata = elf_getdata(scn, (c->obj->ddata));
			/* save the pointer to dynamic string table data */
			c->obj->dynnames = c->obj->ddata->d_buf;
			/*
			 * now, we got dynamic strtab and dynamic section
			 * information
			 */
			break;
		}
	}
	return (SUCCEED);
}

/* ========== find_symtabs ================================================ */
/*
 * DESCRIPTION:
 * Find and check symbol tables for an application file
 */
/* ======================================================================== */

static int
find_symtabs(obj_list * c)
{
#if	defined(_LP64)
	Elf64_Shdr	*shdr;
#else
	Elf32_Shdr	*shdr;
#endif
	Elf_Scn		*scn, *scn2;
	Elf_Data	*data;

	c->obj->sym_tab = NULL;
	c->obj->sym_num = 0;
	c->obj->sym_names = NULL;
	c->obj->dsym_tab = NULL;
	c->obj->dsym_num = 0;
	c->obj->dsym_names = NULL;
	c->obj->sym_data = NULL;
	c->obj->dsym_data = NULL;
	scn = 0;

	/*
	 * loop through the section header table looking for symbol tables.
	 * There must be one or two:  .symtab and .dynsym
	 * upon finding a symbol table, save its pointer in obj_com.
	 */

	/* get section descriptor */
	while ((scn = elf_nextscn(c->obj->elf, scn)) != 0) {
#if	defined(_LP64)
		Elf64_Sym	*syms;
#else
		Elf32_Sym	*syms;
#endif
		int		symn;
		char		*strs;

		/* point to section header */
#if	defined(_LP64)
		shdr = elf64_getshdr(scn);
#else
		shdr = elf32_getshdr(scn);
#endif

		if (shdr == 0)
			return (FAIL);

		/* skip if this section is not a symbol table */
		if ((shdr->sh_type != SHT_DYNSYM) &&
		    (shdr->sh_type != SHT_SYMTAB))
			continue;

		/* get data descriptor for the symbol table itself */
		data = elf_getdata(scn, NULL);
		if (data == NULL)
			continue;

		/* save pointer to symbol table */
#if	defined(_LP64)
		syms = (Elf64_Sym *) data->d_buf;
#else
		syms = (Elf32_Sym *) data->d_buf;
#endif

		/*
		 * now start looking for the string table associated with
		 * this symbol table section
		 */

		/* get section descriptor first */
		scn2 = elf_getscn(c->obj->elf, shdr->sh_link);
		if (scn2 == NULL)
			continue;

		/* get data descriptor for the string table section */
		data = elf_getdata(scn2, NULL);
		if (data == NULL)
			continue;

		/* save pointer to name string table */
		strs = data->d_buf;
		symn = shdr->sh_size / shdr->sh_entsize;

		/* save information in obj_com */
		if (shdr->sh_type == SHT_SYMTAB) {
			c->obj->sym_tab = syms;
			c->obj->sym_num = symn;
			c->obj->sym_names = strs;
			c->obj->sym_data = data;
		} else {	/* must be the dynamic linking symbol table */
			c->obj->dsym_tab = syms;
			c->obj->dsym_num = symn;
			c->obj->dsym_names = strs;
			c->obj->dsym_data = data;
		}		/* end if */
	}			/* end while */
	return (SUCCEED);
}

/* ========== obj_app_symtab ============================================== */
/*
 * DESCRIPTION:
 * Check existence of application's symbol tables.
 */
/* ======================================================================== */

static int
obj_app_symtab(obj_list * c)
{
	/* issue error if a relocatable file has no symbol table */
	if (c->obj->sym_tab == NULL) {
		if (c->obj->ehdr->e_type == ET_REL) {
			if (sflag)
				(void) fprintf(stderr,
				    "ELF error: no symbol \
				    table in object file.\n");
			return (FAIL);
		} else {
			if (c->obj->dsym_tab == NULL) {
				if (sflag) {
					(void) fprintf(stderr,
					    "Warning: Binary is \
					    completely statically \
					    linked and stripped.\n");
				}
				return (FAIL);
			}
			if (sflag)
				(void) fprintf(stderr,
				    "Binary is stripped.\n");
		}
	}
	return (SUCCEED);
}

/* ========== obj_finis =================================================== */
/*
 * DESCRIPTION:
 * It checks the c->fd and c->elf pointers.  If they are not NULL,
 * close the file descriptor and ELF descriptor.
 */
/* ======================================================================== */

static void
obj_finis(obj_list * c)
{
	obj_list	*p;

	if (c) {
		while (c) {
			if (c->obj->elf != (Elf *) 0)
				(void) elf_end(c->obj->elf);
			if (c->obj->fd != 0)
				(void) close(c->obj->fd);
			p = c;
			c = c->next;
			free(p->obj);
			free(p);
		}
	}
}

/* ========= is_text_section ============================================== */
/*
 * DESCRIPTION:
 * Scan through every section and returns TRUE(1) if the given section
 * is ".text", otherwise, returns FALSE(0).
 * INPUTS:        shndx - section header index
 * elf_file - ELF descriptor of the object file under test
 * ehdr - ELF header of the object file under test
 */
/* ======================================================================== */

static int
is_text_section(int shndx,
    Elf * elf_file,
#if	defined(_LP64)
    Elf64_Ehdr * ehdr)
#else
    Elf32_Ehdr * ehdr)
#endif
{
	char		*sym_name;
	Elf_Scn		*scn = elf_getscn(elf_file, shndx);

	if (scn != NULL) {
#if	defined(_LP64)
		Elf64_Shdr	*shdr;
		shdr = elf64_getshdr(scn);
#else
		Elf32_Shdr	*shdr;
		shdr = elf32_getshdr(scn);
#endif
		sym_name = elf_strptr(elf_file,
				    ehdr->e_shstrndx,
				    shdr->sh_name);
		if (strcmp(sym_name, ".text") == 0)
			return (1);
	}
	return (0);
}

/* ========== scan_archive_symbols ======================================= */
/*
 * DESCRIPTION:
 * Scan through the archive symbol tables and write them out.
 * INPUTS:        syms - pointer to application symbol table
 * symn - number of entries in application symbol table
 * buf  - first byte of application string table
 */
/* ======================================================================= */

static void
scan_archive_symbols(obj_list * c,
#if	defined(_LP64)
    Elf64_Sym * syms,
#else
    Elf32_Sym * syms,
#endif
    int symn,
    char *buf,
    Elf * elf_file,
#if	defined(_LP64)
    Elf64_Ehdr * ehdr)
#else
    Elf32_Ehdr * ehdr)
#endif
{
#if	defined(_LP64)
	Elf64_Sym	*symtab_entry;
#else
	Elf32_Sym	*symtab_entry;
#endif
	int		i;
	char		*sym_name;
	int		sttype;
	int		stbind;

	symtab_entry = syms;
	for (i = 0; i < symn; i++, symtab_entry++) {
		binding_bucket *binding;
		/* look only at .text section symbols */
		if (!is_text_section(symtab_entry->st_shndx, elf_file, ehdr))
			continue;

		/* look only at weak and global symbols */
#if	defined(_LP64)
		stbind = ELF64_ST_BIND(symtab_entry->st_info);
#else
		stbind = ELF32_ST_BIND(symtab_entry->st_info);
#endif
		if (stbind != STB_GLOBAL) {
			if (stbind != STB_WEAK)
				continue;
		}
		/* look only at functions and objects */
#if	defined(_LP64)
		sttype = ELF64_ST_TYPE(symtab_entry->st_info);
#else
		sttype = ELF32_ST_TYPE(symtab_entry->st_info);
#endif
		if (sttype != STT_FUNC) {
			if (sttype != STT_OBJECT)
				continue;
		}
		sym_name = buf + symtab_entry->st_name;
		binding = (struct binding_bucket *)
			    malloc(sizeof (binding_bucket));
		binding->sym = sym_name;
		binding->obj = c->obj->ename;
		binding->section = "TEXT";
		binding->ref_lib = "<Unknown>";
		binding->def_lib = "*DIRECT*";
		if (stbind == STB_GLOBAL)
			binding->stbind = "GLOB";
		else if (stbind == STB_WEAK)
			binding->stbind = "WEAK";
		if (sttype == STT_FUNC)
			binding->sttype = "FUNC";
		else if (sttype == STT_OBJECT)
			binding->sttype = "OBJT";
		if (pflag)
			profile_binding(binding);
		else
			store_binding(binding);
	}			/* end for */
}

/* ========== scan_symbols ================================================ */
/*
 * DESCRIPTION:
 * Scan through the symbol table and write them out.
 * INPUTS:        syms - pointer to application symbol table
 * symn - number of entries in application symbol table
 * buf  - first byte of application string table
 */
/* ======================================================================== */

static void
scan_symbols(obj_list * c,
#if	defined(_LP64)
    Elf64_Sym * syms,
#else
    Elf32_Sym * syms,
#endif
    int symn,
    char *buf)
{
#if	defined(_LP64)
	Elf64_Sym	*symtab_entry;
#else
	Elf32_Sym	*symtab_entry;
#endif
	int		i;
	char		*sym_name;
	int		sttype;
	int		stbind;

	symtab_entry = syms;
	if (pflag) {
		(void) fprintf(OUTPUT_FD,
		    "#profiling symbols in .text section of %s\n",
		    c->obj->ename);
		output_dtneeded(dt_needed);
	}
	for (i = 0; i < symn; i++, symtab_entry++) {
		binding_bucket *binding;
		/* look only at .text section symbols */
		if (!is_text_section(symtab_entry->st_shndx,
		    c->obj->elf, c->obj->ehdr))
			continue;

		/* look only at weak and global symbols */
#if	defined(_LP64)
		stbind = ELF64_ST_BIND(symtab_entry->st_info);
#else
		stbind = ELF32_ST_BIND(symtab_entry->st_info);
#endif
		if (stbind != STB_GLOBAL) {
			if (stbind != STB_WEAK)
				continue;
		}
		/* look only at functions and objects */
#if	defined(_LP64)
		sttype = ELF64_ST_TYPE(symtab_entry->st_info);
#else
		sttype = ELF32_ST_TYPE(symtab_entry->st_info);
#endif
		if (sttype != STT_FUNC) {
			if (sttype != STT_OBJECT)
				continue;
		}
		sym_name = buf + symtab_entry->st_name;
		binding = (struct binding_bucket *)
		    malloc(sizeof (binding_bucket));
		binding->sym = sym_name;
		binding->obj = c->obj->ename;
		binding->section = "TEXT";
		binding->ref_lib = "<Unknown>";
		binding->def_lib = "*DIRECT*";
		if (stbind == STB_GLOBAL)
			binding->stbind = "GLOB";
		else if (stbind == STB_WEAK)
			binding->stbind = "WEAK";
		if (sttype == STT_FUNC)
			binding->sttype = "FUNC";
		else if (sttype == STT_OBJECT)
			binding->sttype = "OBJT";
		if (pflag)
			profile_binding(binding);
		else
			store_binding(binding);
	}			/* end for */
}

/* ========= bind_symbols ================================================= */
/*
 * DESCRIPTION:
 * Scan through the dynamic symbol table and write them out.
 * INPUTS:        syms - pointer to application symbol table
 * symn - number of entries in application symbol table
 * buf  - first byte of application string table
 */
/* ======================================================================== */

static void
bind_symbols(obj_list * c,
#if	defined(_LP64)
    Elf64_Sym * syms,
#else
    Elf32_Sym * syms,
#endif
    int symn,
    char *buf)
{
#if	defined(_LP64)
	Elf64_Sym	*symtab_entry;
#else
	Elf32_Sym	*symtab_entry;
#endif
	int		i;
	char		*sym_name;
	binding_bucket	*binding;
	int		sttype;
	int		stbind;

	symtab_entry = syms;
	for (i = 0; i < symn; i++, symtab_entry++) {
		/* look only at global symbols */
#if	defined(_LP64)
		stbind = ELF64_ST_BIND(symtab_entry->st_info);
#else
		stbind = ELF32_ST_BIND(symtab_entry->st_info);
#endif
		if (symtab_entry->st_shndx == SHN_UNDEF)
			continue;
		if (symtab_entry->st_shndx == SHN_ABS)
			continue;
		if (stbind != STB_GLOBAL) {
			if (stbind != STB_WEAK)
				continue;
		}
		/* look only at functions and objects */
#if	defined(_LP64)
		sttype = ELF64_ST_TYPE(symtab_entry->st_info);
#else
		sttype = ELF32_ST_TYPE(symtab_entry->st_info);
#endif
		if (sttype != STT_FUNC) {
			if (sttype != STT_OBJECT)
				continue;
		}
		sym_name = buf + symtab_entry->st_name;
		binding = (binding_bucket *) malloc(sizeof (binding_bucket));
		binding->obj = c->obj->ename;
		binding->sym = sym_name;
		if (!pflag)
			check_store_binding(binding);
	}			/* end for */
}

/* ========== get_scnfd =================================================== */
/*
 * DESCRIPTION:
 * Gets section descriptor for the associated string table
 * and verifies that the type of the section pointed to is
 * indeed of type STRTAB.  Returns a valid section descriptor
 * or NULL on error.
 */
/* ======================================================================== */

static Elf_Scn *
get_scnfd(Elf * e_file,
    int shstrtab,
    int SCN_TYPE)
{
	Elf_Scn		*scn_fd;
#if	defined(_LP64)
	Elf64_Shdr	*shdr;
#else
	Elf32_Shdr	*shdr;
#endif

	if ((scn_fd = elf_getscn(e_file, shstrtab)) == NULL)
		return (NULL);

#if	defined(_LP64)
	shdr = elf64_getshdr(scn_fd);
#else
	shdr = elf32_getshdr(scn_fd);
#endif

	if (shdr->sh_type != SCN_TYPE)
		return (NULL);
	return (scn_fd);
}

/* ========== print_symtab ================================================ */
/*
 * DESCRIPTION:
 * Outputs symbol bindings from symbol table to hash table.
 */
/* ======================================================================== */

static void
print_symtab(obj_list * com,
    Elf * elf_file,
#if	defined(_LP64)
    Elf64_Ehdr * ehdr,
    Elf64_Shdr * shdr,
#else
    Elf32_Ehdr * ehdr,
    Elf32_Shdr * shdr,
#endif
    Elf_Scn * p_sd,
    char *filename)
{
#if	defined(_LP64)
	Elf64_Sym	*syms;
#else
	Elf32_Sym	*syms;
#endif
	Elf_Data	*data;
	Elf_Scn		*scn;
	int		count = 0;
	char		*strs, *fullname;
	obj_list	*c;

	c = (obj_list *) malloc(sizeof (obj_list));
	c->obj = (obj_com *) malloc(sizeof (obj_com));
	fullname = (char *)malloc(strlen(com->obj->ename)
	    + strlen(filename) + 2);
	(void *) strcpy(fullname, com->obj->ename);
	(void *) strcat(fullname, "(");
	(void *) strcat(fullname, filename);
	(void *) strcat(fullname, ")");
	c->obj->ename = fullname;

	if ((data = elf_getdata(p_sd, NULL)) == NULL) {
		if (sflag)
			(void) fprintf(stderr,
			    "%s - No symbol table data\n",
			    c->obj->ename);
		return;
	}
#if	defined(_LP64)
	syms = (Elf64_Sym *) data->d_buf;
#else
	syms = (Elf32_Sym *) data->d_buf;
#endif

	scn = elf_getscn(elf_file, shdr->sh_link);
	if (scn == NULL)
		return;
	data = elf_getdata(scn, NULL);
	if (data == NULL)
		return;
	strs = data->d_buf;
	count = shdr->sh_size / shdr->sh_entsize;
	if (syms == NULL) {
		if (sflag)
			(void) fprintf(stderr,
			    "%s: Problem reading symbol data\n",
			    c->obj->ename);
		return;
	}
	c->obj->sym_tab = syms;
	c->obj->sym_num = count;
	c->obj->sym_names = strs;

	if (aflag)
		(void) scan_archive_symbols(c,
		    c->obj->sym_tab,
		    c->obj->sym_num,
		    c->obj->sym_names,
		    elf_file,
		    ehdr);
	else
		(void) bind_symbols(c,
		    c->obj->sym_tab,
		    c->obj->sym_num,
		    c->obj->sym_names);
	free(c->obj);
	free(c);
}

/* ========== get_symtab ================================================== */
/*
 * DESCRIPTION:
 * Gets the symbol table.  This function does not output the contents
 * of the symbol table but sets up the parameters and then calls
 * print_symtab() to output the symbol bindings.
 */
/* ======================================================================== */

static void
get_symtab(obj_list * c,
    Elf * elf_file,
#if	defined(_LP64)
    Elf64_Ehdr * ehdr,
#else
    Elf32_Ehdr * ehdr,
#endif
    char *filename)
{
	Elf_Scn		*scn, *scnfd;
	Elf_Data	*data;
#if	defined(_LP64)
	Elf64_Word	symtabtype;
#else
	Elf32_Word	symtabtype;
#endif

	/* get section header string table */
	scnfd = get_scnfd(elf_file, ehdr->e_shstrndx, SHT_STRTAB);
	if (scnfd == NULL) {
		if (sflag)
			(void) fprintf(stderr,
			    "%s: Could not get string table\n",
			    filename);
		return;
	}
	data = elf_getdata(scnfd, NULL);
	if (data->d_size == 0) {
		if (sflag)
			(void) fprintf(stderr,
			    "%s: No data in string table\n",
			    filename);
		return;
	}
	symtabtype = SHT_SYMTAB;
	scn = 0;
	while ((scn = elf_nextscn(elf_file, scn)) != 0) {
#if	defined(_LP64)
		Elf64_Shdr	*shdr;
		if ((shdr = elf64_getshdr(scn)) == NULL)
#else
		Elf32_Shdr	*shdr;
		if ((shdr = elf32_getshdr(scn)) == NULL)
#endif
		{
			if (sflag)
				(void) fprintf(stderr,
				    "%s: %s:\n",
				    filename,
				    elf_errmsg(-1));
			return;
		}
		if (shdr->sh_type == symtabtype)
			print_symtab(c, elf_file, ehdr, shdr, scn, filename);
	}			/* end while */
}

/* ========== process ===================================================== */
/*
 * DESCRIPTION:
 * Gets the ELF header and, if it exists, call get_symtab() to begin
 * processing of the file; otherwise, returns with a warning.
 */
/* ======================================================================== */

static void
process(obj_list * c,
    Elf * elf_file,
    char *filename)
{
#if	defined(_LP64)
	Elf64_Ehdr	*ehdr;
#else
	Elf32_Ehdr	*ehdr;
#endif

#if	defined(_LP64)
	if ((ehdr = elf64_getehdr(elf_file)) == NULL)
#else
	if ((ehdr = elf32_getehdr(elf_file)) == NULL)
#endif
	{
		if (sflag)
			(void) fprintf(stderr,
			    "%s: %s\n",
			    filename, elf_errmsg(-1));
		return;
	}
	get_symtab(c, elf_file, ehdr, filename);
}

/* ========== process_archive ============================================= */
/*
 * DESCRIPTION:
 * Processes member files of an archive.  This function provides
 * a loop through an archive equivalent the processing of each_file
 * for individual object file.
 */
/* ======================================================================== */

static int
process_archive(obj_list * c)
{
	Elf_Arhdr	*p_ar;
	Elf		*arf;
	Elf_Cmd		cmd = ELF_C_READ;

	while ((arf = elf_begin(c->obj->fd, cmd, c->obj->elf)) != 0) {
		p_ar = elf_getarhdr(arf);
		if (p_ar == NULL) {
			if (sflag)
				(void) fprintf(stderr,
				    "%s: %s\n",
				    c->obj->filename, elf_errmsg(-1));
			return (FAIL);
		}
		if ((int)strncmp(p_ar->ar_name, "/", 1) == 0) {
			cmd = elf_next(arf);
			(void) elf_end(arf);
			continue;
		}
		if (elf_kind(arf) == ELF_K_ELF) {
			process(c, arf, p_ar->ar_name);
		} else {
			cmd = elf_next(arf);
			(void) elf_end(arf);
			continue;
		}
		cmd = elf_next(arf);
		(void) elf_end(arf);
	}			/* end while */
	return (SUCCEED);
}

/* ========== add_dtneeded ================================================ */
/*
 * DESCRIPTION:
 * Inserts a new node into the linked list.  It is basically for
 * generating a simple linked list of DT_NEEDED entries.
 */
/* ======================================================================== */

static dt_list *
add_dtneeded(dt_list * p,
    dt_list * node)
{
	dt_list		*head = p, *tail;

	if (!head)
		head = node;
	else {
		tail = head;
		if (strcmp(tail->libname, node->libname) == 0) {
			free(node);
			return (head);
		}
		while (tail->next != NULL) {
			tail = tail->next;
			if (strcmp(tail->libname, node->libname) == 0) {
				free(node);
				return (head);
			}
		}
		tail->next = node;
	}
	return (head);
}

/* ========== find_dtneeded =============================================== */
/*
 * DESCRIPTION:
 * Find the DT_NEEDED, DT_FILTER, and DT_AUXILIARY entries, and save
 * them to link list.
 */
/* ======================================================================== */

static void
find_dtneeded(obj_list * c)
{
#if	defined(_LP64)
	Elf64_Dyn	*dcurrent; /* temp 64 bit dynamic table entry ptr */
#else
	Elf32_Dyn	*dcurrent; /* temp 32 bit dynamic table entry ptr */
#endif
	dt_list		*tmp_lib;

	dcurrent = c->obj->dynsect;
	if (!dcurrent)
		return;

	/*
	 * If there are any DT_NEEDED
	 * entries, add them to the dt_needed list.
	 */

	while (dcurrent->d_tag != DT_NULL) {
		if (dcurrent->d_tag == DT_NEEDED) {
			tmp_lib = (dt_list *) malloc(sizeof (dt_list));
			tmp_lib->libname = c->obj->dynnames +
			    dcurrent->d_un.d_val;
			tmp_lib->d_tag = dcurrent->d_tag;
			tmp_lib->next = NULL;
			dt_needed = add_dtneeded(dt_needed, tmp_lib);
		}
		dcurrent++;
	}
}

/* ========= obj_elfcheck ================================================= */
/*
 * DESCRIPTION:
 * It checks the elf header and saves its pointer if succeeds.
 * It checks the program header and saves its pointer if succeed.
 * It checks the section header table and saves its pointer to
 * section header table and section header string table if it
 * succeeds.  It finds dynsym symbol table and saves its pointer.
 * It finds symtab and saves its pointers.
 */
/* ======================================================================== */

static int
obj_elfcheck(obj_list * c)
{
	/* open the file and ELF descriptor */
	if (obj_init(c) == FAIL) {
		obj_finis(c);
		return (FAIL);
	}
	/* if it is an archive library */
	if (elf_kind(c->obj->elf) == ELF_K_AR) {
		if (process_archive(c) == SUCCEED)
			return (SUCCEED);
		else
			return (FAIL);
	}
	/* get the ELF header information */
	if (obj_elf_hdr(c) == FAIL) {
		obj_finis(c);
		return (FAIL);
	}
	/* get the program header for dynamic, etc. */
	if (obj_prog_hdr(c) == FAIL) {
		obj_finis(c);
		return (FAIL);
	}
	/* find and save pointers to application symbol tables */
	if (find_symtabs(c) == FAIL) {
		obj_finis(c);
		return (FAIL);
	}
	/* check the existence of application's symbol tables */
	if (obj_app_symtab(c) == FAIL) {
		obj_finis(c);
		return (FAIL);
	}
	/* find and save pointers to the dynamic section */
	if (find_dynamic_sect(c) == FAIL) {
		obj_finis(c);
		return (FAIL);
	}
	/*
	 * find the DT_NEEDED entries and save the name to dt_needed link
	 * list
	 */
	(void) find_dtneeded(c);

	return (SUCCEED);
}

/* ========= analyze_dependency ========================================== */
/*
 * DESCRIPTION:
 * Read in an dependency object file and analyze it.
 * INPUTS:        dep_file - dependency object file name
 */
/* ======================================================================= */

static int
analyze_dependency(char *dep_file)
{
	obj_list	*dep_obj;

	if (!dep_file)
		return (SUCCEED);

	dep_obj = (obj_list *) malloc(sizeof (obj_list));
	(void) memset(dep_obj, 0, sizeof (obj_list));
	dep_obj->obj = (obj_com *) malloc(sizeof (obj_com));
	(void) memset(dep_obj->obj, 0, sizeof (obj_com));
	dep_obj->next = NULL;
	dep_obj->obj->filename = dep_file;
	dep_obj->obj->ename = dep_obj->obj->filename;

	if (obj_elfcheck(dep_obj) == FAIL)
		return (FAIL);

	if (dep_obj->obj->dsym_names != NULL)
		bind_symbols(dep_obj,
		    dep_obj->obj->dsym_tab,
		    dep_obj->obj->dsym_num,
		    dep_obj->obj->dsym_names);

	if (dep_obj->obj->sym_names != NULL)
		bind_symbols(dep_obj,
		    dep_obj->obj->sym_tab,
		    dep_obj->obj->sym_num,
		    dep_obj->obj->sym_names);
	return (SUCCEED);
}

/* ========= analyze_main =============================================== */
/*
 * DESCRIPTION:
 * Read in an object file and analyze it.
 */
/* ====================================================================== */

static void
analyze_main(obj_list * c)
{
	int	i;

	if (obj_elfcheck(c) == FAIL)
		exit(1);

	aflag = FALSE;

	if (c->obj->sym_names != NULL)
		scan_symbols(c,
		    c->obj->sym_tab,
		    c->obj->sym_num,
		    c->obj->sym_names);
	else if (c->obj->dsym_names != NULL)
		scan_symbols(c,
		    c->obj->dsym_tab,
		    c->obj->dsym_num,
		    c->obj->dsym_names);

	if (c->obj->numfiles == 0)
		return;

	for (i = 0; i < c->obj->numfiles; i++)
		(void) analyze_dependency(c->obj->filenames[i]);
}

/* ========= analyze_args ================================================= */
/*
 * DESCRIPTION:
 * Analyze the command-line options.
 */
/* ======================================================================== */

static int
analyze_args(obj_list * c,
    int argc,
    char *argv[])
{
	extern char	*optarg;
	extern int	optind;
	int		option;
	int		i;
	char		*nameptr;
	char		slash = '/';
	int		errflg = 0;

	if ((nameptr = strrchr(argv[0], slash)) != NULL)
		nameptr++;
	else
		nameptr = argv[0];

	while ((option = getopt(argc, argv, "pso:a")) != EOF) {
		switch (option) {
		case 'p':	/* just do profiling; write to stdout */
			pflag = 1;
			break;
		case 's':	/* silent mode to turn off stderr messages */
			sflag = 0;
			break;
		case 'o':	/* redirects the output */
			outputfile = optarg;
			oflag = 1;
			break;
		case 'a':	/* processes archive as input */
			aflag = 1;
			break;
		case '?':
		default:
			errflg++;
		}		/* end switch */
	}			/* end while */

	/* exit if there are no files to process */
	if (optind >= argc)
		errflg++;
	if (errflg) {
		(void) fprintf(stderr,
		    "usage: %s [-p] [-s] [-o outputfile] ", nameptr);
		(void) fprintf(stderr,
		    "<archive>|<binary_executable>\n");
		(void) fprintf(stderr,
		    "\t\t   [<archive>|<dynamic library>...]\n");
		return (FALSE);
	}			/* end if */
	c->obj->filename = argv[optind++];
	c->obj->ename = c->obj->filename;

	/* compute number of files and save their pointers */
	c->obj->numfiles = argc - optind;

	if (c->obj->numfiles > 0) {
		i = 0;
		c->obj->filenames = (char **)
		    malloc(sizeof (char *) * (c->obj->numfiles + 1));
		for (; optind < argc; i++, optind++)
			c->obj->filenames[i] = argv[optind];
	}
	return (TRUE);
}

/* ======================================================================= */
/*
 * Here starts the main ()
 */
/* ======================================================================= */

int
main(int argc, char *argv[])
{
	obj_list	*main_obj;
	dt_list		*q;

	main_obj = (obj_list *) malloc(sizeof (obj_list));
	(void) memset(main_obj, 0, sizeof (obj_list));
	main_obj->obj = (obj_com *) malloc(sizeof (obj_com));
	(void) memset(main_obj->obj, 0, sizeof (obj_com));
	main_obj->next = NULL;

	if (!analyze_args(main_obj, argc, argv))
		exit(1);

	if (oflag && pflag) {
		if ((OUTPUT_FD = fopen(outputfile, "w")) == NULL) {
			if (sflag)
				(void) fprintf(stderr,
				    "\nfopen failed to open <%s>...\n\n",
				    outputfile);
			exit(1);
		}
	}
	/* generates profile report if pflag is set */
	if (pflag)
		(void) fprintf(OUTPUT_FD,
		    "#generated by %s\n",
		    argv[0]);

	/* analyze the input file */
	analyze_main(main_obj);

	/* generates profile report */
	if (!pflag)
		output_binding(argv[0], main_obj->obj->ename);

	/* close the library .so file descriptor and ELF descriptor */
	obj_finis(main_obj);

	/* de-allocates the dt_needed link list */
	if (dt_needed) {
		while (dt_needed) {
			q = dt_needed;
			dt_needed = dt_needed->next;
			free(q);
		}
	}
	/* close the output redirect file descriptor */
	if (oflag)
		(void) fclose(OUTPUT_FD);

	return (0);
}
