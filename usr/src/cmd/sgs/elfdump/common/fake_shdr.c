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
 * Generate a cache of section header information for an ELF
 * object from the information found in its program headers.
 *
 * Malicious code can remove or corrupt section headers. The
 * resulting program will be difficult to analyze, but is still
 * runnable. Hence, scribbling on the section headers or removing
 * them is an effective form of obfuscation. On the other hand,
 * program headers must be accurate or the program will not run.
 * Section headers derived from them will necessarily lack information
 * found in the originals (particularly for non-allocable sections),
 * but will provide essential symbol information. The focus is on
 * recovering information that elfdump knows how to display, and that
 * might be interesting in a forensic situation.
 *
 * There are some things we don't attempt to create sections for:
 *
 *	plt, got
 *		We have no way to determine the length of either of
 *		these sections from the information available via
 *		the program headers or dynamic section. The data in
 *		the PLT is of little use to elfdump. The data in the
 *		GOT might be somewhat more interesting, especially as
 *		it pertains to relocations. However, the sizing issue
 *		remains.
 *
 *	text, data, bss
 *		Although we could create these, there is little value
 *		to doing so. elfdump cannot display the arbitrary
 *		data in these sections, so this would amount to a
 *		simple repetition of the information already displayed
 *		in the program headers, with no additional benefit.
 */



#include	<machdep.h>
#include	<sys/elf_amd64.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<errno.h>
#include	<string.h>
#include	<strings.h>
#include	<conv.h>
#include	<msg.h>
#include	<_elfdump.h>



/*
 * Common information about the object that is needed by
 * all the routines in this module.
 */
typedef struct {
	const char	*file;
	int		fd;
	Ehdr		*ehdr;
	Phdr		*phdr;
	size_t		phnum;
} FSTATE;



/*
 * These values uniquely identify the sections that we know
 * how to recover.
 *
 * Note: We write the sections to the cache array in this same order.
 * It simplifies this code if the dynamic, dynstr, dynsym, and ldynsym
 * sections occupy known slots in the cache array. Other sections reference
 * them by index, and if they are at a known spot, there is no need
 * for a fixup pass. Putting them in positions [1-4] solves this.
 *
 * The order they are in was chosen such that if any one of them exists,
 * all of the ones before it must also exist. This means that if the
 * desired section exists, it will end up in the desired index in the
 * cache array.
 *
 * The order of the other sections is arbitrary. I've arranged them
 * in roughly related groups.
 */
typedef enum {
	SINFO_T_NULL =		0,
	SINFO_T_DYN =		1,
	SINFO_T_DYNSTR = 	2,
	SINFO_T_DYNSYM =	3,
	SINFO_T_LDYNSYM =	4,

	SINFO_T_HASH =		5,
	SINFO_T_SYMINFO =	6,
	SINFO_T_SYMSORT =	7,
	SINFO_T_TLSSORT =	8,
	SINFO_T_VERNEED =	9,
	SINFO_T_VERDEF =	10,
	SINFO_T_VERSYM =	11,
	SINFO_T_INTERP =	12,
	SINFO_T_CAP =		13,
	SINFO_T_UNWIND =	14,
	SINFO_T_MOVE =		15,
	SINFO_T_REL =		16,
	SINFO_T_RELA =		17,
	SINFO_T_PREINITARR =	18,
	SINFO_T_INITARR =	19,
	SINFO_T_FINIARR =	20,
	SINFO_T_NOTE =		21,

	SINFO_T_NUM =		22 /* Count of items. Must come last */
} SINFO_TYPE;



/*
 * Table of per-section constant data used to set up the section
 * header cache and the various sub-parts it references. Indexed by
 * SINFO_T value.
 *
 * note: The sh_flags value should be either SHF_ALLOC, or 0.
 *	get_data() sets SHF_WRITE if the program header containing the
 *	section is writable. The other flags require information that
 *	the program headers don't contain (i.e. SHF_STRINGS, etc) so
 *	we don't set them.
 */
typedef struct {
	const char	*name;
	Word		sh_type;
	Word		sh_flags;
	Word		sh_addralign;
	Word		sh_entsize;
	Elf_Type	libelf_type;
} SINFO_DATA;

static SINFO_DATA sinfo_data[SINFO_T_NUM] = {
	/* SINFO_T_NULL */
	{ 0 },

	/* SINFO_T_DYN */
	{ MSG_ORIG(MSG_PHDRNAM_DYN), SHT_DYNAMIC, SHF_ALLOC,
	    M_WORD_ALIGN, sizeof (Dyn), ELF_T_DYN },

	/* SINFO_T_DYNSTR */
	{ MSG_ORIG(MSG_PHDRNAM_DYNSTR), SHT_STRTAB, SHF_ALLOC,
	    1, 0, ELF_T_BYTE },

	/* SINFO_T_DYNSYM */
	{ MSG_ORIG(MSG_PHDRNAM_DYNSYM), SHT_DYNSYM, SHF_ALLOC,
	    M_WORD_ALIGN, sizeof (Sym), ELF_T_SYM },

	/* SINFO_T_LDYNSYM */
	{ MSG_ORIG(MSG_PHDRNAM_LDYNSYM), SHT_SUNW_LDYNSYM, SHF_ALLOC,
	    M_WORD_ALIGN, sizeof (Sym), ELF_T_SYM },

	/* SINFO_T_HASH */
	{ MSG_ORIG(MSG_PHDRNAM_HASH), SHT_HASH, SHF_ALLOC,
	    M_WORD_ALIGN, sizeof (Word), ELF_T_WORD },

	/* SINFO_T_SYMINFO */
	{ MSG_ORIG(MSG_PHDRNAM_SYMINFO),  SHT_SUNW_syminfo, SHF_ALLOC,
	    M_WORD_ALIGN, sizeof (Syminfo), ELF_T_SYMINFO },

	/* SINFO_T_SYMSORT */
	{ MSG_ORIG(MSG_PHDRNAM_SYMSORT), SHT_SUNW_symsort, SHF_ALLOC,
	    M_WORD_ALIGN, sizeof (Word), ELF_T_WORD },

	/* SINFO_T_TLSSORT */
	{ MSG_ORIG(MSG_PHDRNAM_TLSSORT), SHT_SUNW_tlssort, SHF_ALLOC,
	    M_WORD_ALIGN, sizeof (Word), ELF_T_WORD },

	/* SINFO_T_VERNEED */
	{ MSG_ORIG(MSG_PHDRNAM_VER), SHT_SUNW_verneed, SHF_ALLOC,
	    M_WORD_ALIGN, 1, ELF_T_VNEED },

	/* SINFO_T_VERDEF */
	{ MSG_ORIG(MSG_PHDRNAM_VER), SHT_SUNW_verdef, SHF_ALLOC,
	    M_WORD_ALIGN, 1, ELF_T_VDEF },

	/* SINFO_T_VERSYM */
	{ MSG_ORIG(MSG_PHDRNAM_VER), SHT_SUNW_versym, SHF_ALLOC,
	    M_WORD_ALIGN, sizeof (Versym), ELF_T_HALF },

	/* SINFO_T_INTERP */
	{ MSG_ORIG(MSG_PHDRNAM_INTERP), SHT_PROGBITS, SHF_ALLOC,
	    1, 0, ELF_T_BYTE },

	/* SINFO_T_CAP */
	{ MSG_ORIG(MSG_PHDRNAM_CAP), SHT_SUNW_cap, SHF_ALLOC,
	    sizeof (Addr), sizeof (Cap), ELF_T_CAP },

	/* SINFO_T_UNWIND */
	{ MSG_ORIG(MSG_PHDRNAM_UNWIND), SHT_AMD64_UNWIND, SHF_ALLOC,
	    sizeof (Addr), 0, ELF_T_BYTE },

	/* SINFO_T_MOVE */
	{ MSG_ORIG(MSG_PHDRNAM_MOVE), SHT_SUNW_move, SHF_ALLOC,
	    sizeof (Lword), sizeof (Move),  ELF_T_MOVE },

	/* SINFO_T_REL */
	{ MSG_ORIG(MSG_PHDRNAM_REL), SHT_REL, SHF_ALLOC,
	    M_WORD_ALIGN, sizeof (Rel), ELF_T_REL },

	/* SINFO_T_RELA */
	{ MSG_ORIG(MSG_PHDRNAM_RELA), SHT_RELA, SHF_ALLOC,
	    M_WORD_ALIGN, sizeof (Rela), ELF_T_RELA },

	/* SINFO_T_PREINITARR */
	{ MSG_ORIG(MSG_PHDRNAM_PREINITARR), SHT_PREINIT_ARRAY, SHF_ALLOC,
	    sizeof (Addr), sizeof (Addr), ELF_T_ADDR },

	/* SINFO_T_INITARR */
	{ MSG_ORIG(MSG_PHDRNAM_INITARR), SHT_INIT_ARRAY, SHF_ALLOC,
	    sizeof (Addr), sizeof (Addr),  ELF_T_ADDR },

	/* SINFO_T_FINIARR */
	{ MSG_ORIG(MSG_PHDRNAM_FINIARR), SHT_FINI_ARRAY, SHF_ALLOC,
	    sizeof (Addr), sizeof (Addr), ELF_T_ADDR },

	/* SINFO_T_NOTE */
	{ MSG_ORIG(MSG_PHDRNAM_NOTE), SHT_NOTE, 0,
	    M_WORD_ALIGN, 1, ELF_T_NOTE }
};





/*
 * As we read program headers and dynamic elements, we build up
 * the data for our fake section headers in variables of the
 * SINFO type. SINFO is used to track the sections that can only
 * appear a fixed number of times (usually once).
 *
 * SINFO_LISTELT is used for sections that can occur an arbitrary
 * number of times. They are kept in a doubly linked circular
 * buffer.
 */
typedef struct {
	SINFO_TYPE	type;	/* Our type code for the section */
	Addr		vaddr;	/* Virtual memory address */
	Off		offset;	/* File offset of data. Ignored unless */
				/*	vaddr is 0. Used by program headers */
	size_t		size;	/* # bytes in section */
	size_t		vercnt;	/* Used by verdef and verneed to hold count */
	Shdr		*shdr;	/* Constructed shdr */
	Elf_Data	*data;	/* Constructed data descriptor */
} SINFO;

typedef struct _sinfo_listelt {
	struct _sinfo_listelt	*next;
	struct _sinfo_listelt	*prev;
	SINFO			sinfo;
} SINFO_LISTELT;



/*
 * Free dynamic memory used by SINFO structures.
 *
 * entry:
 *	sinfo - Address of first SINFO structure to free
 *	n - # of structures to clear
 *
 * exit:
 *	For each SINFO struct, the section header, data descriptor,
 *	and data buffer are freed if non-NULL. The relevant
 *	fields are set to NULL, and the type is set to SINFO_T_NULL.
 */
static void
sinfo_free(SINFO *sinfo, size_t n)
{
	for (; n-- > 0; sinfo++) {
		if (sinfo->data != NULL) {
			if (sinfo->data->d_buf != NULL)
				free(sinfo->data->d_buf);
			free(sinfo->data);
			sinfo->data = NULL;
		}

		if (sinfo->shdr) {
			free(sinfo->shdr);
			sinfo->shdr = NULL;
		}
		sinfo->type = SINFO_T_NULL;
	}
}



/*
 * Allocate a new SINFO_LISTELT and put it at the end of the
 * doubly linked list anchored by the given list root node.
 *
 * On success, a new node has been put at the end of the circular
 * doubly linked list, and a pointer to the SINFO sub-structure is
 * returned. On failure, an error is printed, and NULL is returned.
 */

static SINFO *
sinfo_list_alloc(FSTATE *fstate, SINFO_LISTELT *root)
{
	SINFO_LISTELT *elt;

	if ((elt = malloc(sizeof (*elt))) == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
		    fstate->file, strerror(err));
		return (0);
	}

	elt->next = root;
	elt->prev = root->prev;

	root->prev = elt;
	elt->prev->next = elt;

	bzero(&elt->sinfo, sizeof (elt->sinfo));
	return (&elt->sinfo);
}



/*
 * Release the memory used by the given list, restoring it to
 * an empty list.
 */
static void
sinfo_list_free_all(SINFO_LISTELT *root)
{
	SINFO_LISTELT *elt;

	for (elt = root->next; elt != root; elt = elt->next)
		sinfo_free(&elt->sinfo, 1);

	root->next = root->prev = root;
}



/*
 * Given a virtual address and desired size of the data to be found
 * at that address, look through the program headers for the PT_LOAD
 * segment that contains it and return the offset within the ELF file
 * at which it resides.
 *
 * entry:
 *	fstate - Object state
 *	addr - virtual address to be translated
 *	size - Size of the data to be found at that address, in bytes
 *	zero_bytes - NULL, or address to receive the number of data
 *		bytes at the end of the data that are not contained
 *		in the file, and which must be zero filled by the caller.
 *		If zero_bytes is NULL, the file must contain all of the
 *		desired data. If zero_bytes is not NULL, then the program
 *		header must reserve the space for all of the data (p_memsz)
 *		but it is acceptable for only part of the data to be in
 *		the file (p_filesz). *zero_bytes is set to the difference
 *		in size, and is the number of bytes the caller must
 *		set to 0 rather than reading from the file.
 *	phdr_ret - NULL, or address of variable to receive pointer
 *		to program header that contains offset.
 * exit:
 *	On success: If zero_bytes is non-NULL, it is updated. If phdr_ret
 *	is non-NULL, it is updated. The file offset is returned.
 *
 *	On failure, 0 is returned. Since any ELF file we can understand
 *	must start with an ELF magic number, 0 cannot be a valid file
 *	offset for a virtual address, and is therefore unambiguous as
 *	a failure indication.
 */
static Off
map_addr_to_offset(FSTATE *fstate, Addr addr, size_t size, size_t *zero_bytes,
    Phdr **phdr_ret)
{
	Off	offset;
	Addr	end_addr = addr + size;
	size_t	avail_file;
	Phdr	*phdr = fstate->phdr;
	size_t	phnum = fstate->phnum;

	for (; phnum--; phdr++) {
		if (phdr->p_type != PT_LOAD)
			continue;

		if ((addr >= phdr->p_vaddr) &&
		    (end_addr <= (phdr->p_vaddr + phdr->p_memsz))) {
			/*
			 * Subtract segment virtual address, leaving the
			 * offset relative to the segment (not the file).
			 */
			offset = addr - phdr->p_vaddr;
			avail_file = phdr->p_filesz - offset;

			/*
			 * The addr/size are in bounds for this segment.
			 * Is there enough data in the file to satisfy
			 * the request? If zero_bytes is NULL, it must
			 * all be in the file. Otherwise it can be
			 * zero filled.
			 */
			if (zero_bytes == NULL) {
				if (size > avail_file)
					continue;
			} else {
				*zero_bytes = (size > avail_file) ?
				    (size - avail_file) : 0;
			}

			if (phdr_ret != NULL)
				*phdr_ret = phdr;

			/* Add segment file offset, giving overall offset */
			return (phdr->p_offset + offset);
		}
	}

	/* If we get here, the mapping failed */
	return (0);
}



/*
 * This routine is the same thing as map_addr_to_offset(), except that
 * it goes the other way, mapping from offset to virtual address.
 *
 * The comments for map_addr_to_offset() are applicable if you
 * reverse offset and address.
 */

static Addr
map_offset_to_addr(FSTATE *fstate, Off offset, size_t size, size_t *zero_bytes,
    Phdr **phdr_ret)
{
	Off	end_offset = offset + size;
	size_t	avail_file;
	Phdr	*phdr = fstate->phdr;
	size_t	phnum = fstate->phnum;

	for (; phnum--; phdr++) {
		if (phdr->p_type != PT_LOAD)
			continue;

		if ((offset >= phdr->p_offset) &&
		    (end_offset <= (phdr->p_offset + phdr->p_memsz))) {
			/*
			 * Subtract segment offset, leaving the
			 * offset relative to the segment (not the file).
			 */
			offset -= phdr->p_offset;
			avail_file = phdr->p_filesz - offset;

			/*
			 * The offset/size are in bounds for this segment.
			 * Is there enough data in the file to satisfy
			 * the request? If zero_bytes is NULL, it must
			 * all be in the file. Otherwise it can be
			 * zero filled.
			 */
			if (zero_bytes == NULL) {
				if (size > avail_file)
					continue;
			} else {
				*zero_bytes = (size > avail_file) ?
				    (size - avail_file) : 0;
			}

			if (phdr_ret != NULL)
				*phdr_ret = phdr;

			/* Add segment virtual address, giving overall addr */
			return (phdr->p_vaddr + offset);
		}
	}

	/* If we get here, the mapping failed */
	return (0);
}



/*
 * Use elf_xlatetom() to convert the bytes in buf from their
 * in-file representation to their in-memory representation.
 *
 * Returns True(1) for success. On failure, an error message is printed
 * and False(0) is returned.
 */
static int
xlate_data(FSTATE *fstate, void *buf, size_t nbyte, Elf_Type xlate_type)
{
	Elf_Data	data;

	data.d_type = xlate_type;
	data.d_size = nbyte;
	data.d_off = 0;
	data.d_align = 0;
	data.d_version = fstate->ehdr->e_version;
	data.d_buf = buf;

	if (elf_xlatetom(&data, &data,
	    fstate->ehdr->e_ident[EI_DATA]) == NULL) {
		failure(fstate->file, MSG_ORIG(MSG_ELF_XLATETOM));
		return (0);
	}

	return (1);
}


/*
 * Read nbytes of data into buf, starting at the specified offset
 * within the ELF file.
 *
 * entry:
 *	fstate - Object state
 *	offset - Offset within the file at which desired data resides.
 *	buf - Buffer to receive the data
 *	nbyte - # of bytes to read into buf
 *	xlate_type - An ELF xlate type, specifying the type of data
 *		being input. If xlate_type is ELF_T_BYTE, xlate is not
 *		done. Otherwise, xlate_data() is called to convert the
 *		data into its in-memory representation.
 * exit:
 *	On success, the data has been written into buf, xlate_data()
 *	called on it if required, and True(1) is returned. Otherwise
 *	False(0) is returned.
 *
 * note:
 *	This routine does not move the file pointer.
 */
static int
read_data(FSTATE *fstate, Off offset, void *buf, size_t nbyte,
    Elf_Type xlate_type)
{
	if (pread(fstate->fd, buf, nbyte, offset) != nbyte) {
		int err = errno;

		(void) fprintf(stderr, MSG_INTL(MSG_ERR_READ),
		    fstate->file, strerror(err));
		return (0);
	}

	if (xlate_type != ELF_T_BYTE)
		return (xlate_data(fstate, buf, nbyte, xlate_type));

	return (1);
}



/*
 * Read the hash nbucket/nchain values from the start of the hash
 * table found at the given virtual address in the mapped ELF object.
 *
 * On success, *nbucket, and *nchain have been filled in with their
 * values, *total contains the number of elements in the hash table,
 * and this routine returns True (1).
 *
 * On failure, False (0) is returned.
 */
static int
hash_size(FSTATE *fstate, SINFO *hash_sinfo,
    Word *nbucket, Word *nchain, size_t *total)
{
	Off		offset;
	Word		buf[2];

	offset = map_addr_to_offset(fstate, hash_sinfo->vaddr,
	    sizeof (buf), NULL, NULL);
	if (offset == 0)
		return (0);

	if (read_data(fstate, offset, buf, sizeof (buf), ELF_T_WORD) == 0)
		return (0);

	*nbucket = buf[0];
	*nchain = buf[1];
	*total = 2 + *nbucket + *nchain;
	return (1);
}



/*
 * Read a Verdef structure at the specified file offset and return
 * its vd_cnt, vd_aux, and vd_next fields.
 */
static int
read_verdef(FSTATE *fstate, Off offset, Half *cnt, Word *aux, Word *next)
{
	Verdef		verdef;

	if (read_data(fstate, offset, &verdef, sizeof (verdef),
	    ELF_T_BYTE) == 0)
		return (0);

	/* xlate vd_cnt */
	if (xlate_data(fstate, &verdef.vd_cnt, sizeof (verdef.vd_cnt),
	    ELF_T_HALF) == 0)
		return (0);

	/*
	 * xlate vd_aux and vd_next. These items are adjacent and are
	 * both Words, so they can be handled in a single operation.
	 */
	if (xlate_data(fstate, &verdef.vd_aux,
	    2 * sizeof (Word), ELF_T_WORD) == 0)
		return (0);

	*cnt = verdef.vd_cnt;
	*aux = verdef.vd_aux;
	*next = verdef.vd_next;

	return (1);
}



/*
 * Read a Verdaux structure at the specified file offset and return
 * its vda_next field.
 */
static int
read_verdaux(FSTATE *fstate, Off offset, Word *next)
{
	Verdaux		verdaux;

	if (read_data(fstate, offset, &verdaux, sizeof (verdaux),
	    ELF_T_BYTE) == 0)
		return (0);

	/* xlate vda_next */
	if (xlate_data(fstate, &verdaux.vda_next, sizeof (verdaux.vda_next),
	    ELF_T_WORD) == 0)
		return (0);

	*next = verdaux.vda_next;

	return (1);
}



/*
 * Read a Verneed structure at the specified file offset and return
 * its vn_cnt, vn_aux, and vn_next fields.
 */
static int
read_verneed(FSTATE *fstate, Off offset, Half *cnt, Word *aux, Word *next)
{
	Verneed		verneed;

	if (read_data(fstate, offset, &verneed, sizeof (verneed),
	    ELF_T_BYTE) == 0)
		return (0);

	/* xlate vn_cnt */
	if (xlate_data(fstate, &verneed.vn_cnt, sizeof (verneed.vn_cnt),
	    ELF_T_HALF) == 0)
		return (0);

	/*
	 * xlate vn_aux and vn_next. These items are adjacent and are
	 * both Words, so they can be handled in a single operation.
	 */
	if (xlate_data(fstate, &verneed.vn_aux,
	    2 * sizeof (Word), ELF_T_WORD) == 0)
		return (0);

	*cnt = verneed.vn_cnt;
	*aux = verneed.vn_aux;
	*next = verneed.vn_next;

	return (1);
}



/*
 * Read a Vernaux structure at the specified file offset and return
 * its vna_next field.
 */
static int
read_vernaux(FSTATE *fstate, Off offset, Word *next)
{
	Vernaux		vernaux;

	if (read_data(fstate, offset, &vernaux, sizeof (vernaux),
	    ELF_T_BYTE) == 0)
		return (0);

	/* xlate vna_next */
	if (xlate_data(fstate, &vernaux.vna_next, sizeof (vernaux.vna_next),
	    ELF_T_WORD) == 0)
		return (0);

	*next = vernaux.vna_next;

	return (1);
}



/*
 * Compute the size of Verdef and Verneed sections. Both of these
 * sections are made up of interleaved main nodes (Verdef and Verneed)
 * and auxiliary blocks (Verdaux and Vernaux). These nodes refer to
 * each other by relative offsets. The linker has a lot of flexibility
 * in how it lays out these items, and we cannot assume a standard
 * layout. To determine the size of the section, we must read each
 * main node and compute the high water mark of the memory it and its
 * auxiliary structs access.
 *
 * Although Verdef/Verdaux and Verneed/Vernaux are different types,
 * their logical organization is the same. Each main block has
 * a cnt field that tells how many auxiliary blocks it has, an
 * aux field that gives the offset of the first auxiliary block, and
 * an offset to the next main block. Each auxiliary block contains
 * an offset to the next auxiliary block. By breaking the type specific
 * code into separate sub-functions, we can process both Verdef and
 * sections Verdaux from a single routine.
 *
 * entry:
 *	fstate - Object state
 *	sec - Section to be processed (SINFO_T_VERDEF or SINFO_T_VERNEED).
 *
 * exit:
 *	On success, sec->size is set to the section size in bytes, and
 *	True (1) is returned. On failure, False (0) is returned.
 */
static int
verdefneed_size(FSTATE *fstate, SINFO *sec)
{
	int (* read_main)(FSTATE *, Off, Half *, Word *, Word *);
	int (* read_aux)(FSTATE *, Off, Word *);
	size_t	size_main, size_aux;

	Off	offset, aux_offset;
	Off	highwater, extent;
	size_t	num_main = sec->vercnt;
	Half	v_cnt;
	Word	v_aux, v_next, va_next;


	/*
	 * Set up the function pointers to the type-specific code
	 * for fetching data from the main and auxiliary blocks.
	 */
	if (sec->type == SINFO_T_VERDEF) {
		read_main = read_verdef;
		read_aux = read_verdaux;
		size_main = sizeof (Verdef);
		size_aux = sizeof (Verdaux);
	} else {			/* SINFO_T_VERNEED */
		read_main = read_verneed;
		read_aux = read_vernaux;
		size_main = sizeof (Verneed);
		size_aux = sizeof (Vernaux);
	}

	/*
	 * Map starting address to file offset. Save the starting offset
	 * in the SINFO size field. Once we have the high water offset, we
	 * can subtract this from it to get the size.
	 *
	 * Note: The size argument set here is a lower bound --- the
	 * size of the main blocks without any auxiliary ones. It's
	 * the best we can do until the size has been determined for real.
	 */
	offset = highwater = map_addr_to_offset(fstate, sec->vaddr,
	    size_main * num_main, NULL, NULL);
	if (offset == 0)
		return (0);
	sec->size = offset;

	for (; num_main-- > 0; offset += v_next) {
		/* Does this move the high water mark up? */
		extent = offset + size_main;
		if (extent > highwater)
			highwater = extent;

		if ((*read_main)(fstate, offset, &v_cnt, &v_aux, &v_next) == 0)
			return (0);

		/*
		 * If there are auxiliary structures referenced,
		 * check their position to see if it pushes
		 * the high water mark.
		 */
		aux_offset = offset + v_aux;
		for (; v_cnt-- > 0; aux_offset += va_next) {
			extent = aux_offset + size_aux;
			if (extent > highwater)
				highwater = extent;

			if ((*read_aux)(fstate, aux_offset, &va_next) == 0)
				return (0);
		}
	}

	sec->size = highwater - sec->size;
	return (1);
}


/*
 * Allocate and fill in a fake section header, data descriptor,
 * and data buffer for the given section. Fill them in and read
 * the associated data into the buffer.
 *
 * entry:
 *	fstate - Object state
 *	sec - Section information
 *
 * exit:
 *	On success, the actions described above are complete, and
 *	True (1) is returned.
 *
 *	On failure, an error is reported, all resources used by sec
 *	are released, and sec->type is set to SINFO_T_NULL, effectively
 *	eliminating its contents from any further use. False (0) is
 *	returned.
 */
static int
get_data(FSTATE *fstate, SINFO *sec)
{

	SINFO_DATA	*tinfo;
	size_t		read_bytes, zero_bytes;
	Phdr		*phdr = NULL;

	/*
	 * If this is a NULL section, or if we've already processed
	 * this item, then we are already done.
	 */
	if ((sec->type == SINFO_T_NULL) || (sec->shdr != NULL))
		return (1);

	if (((sec->shdr = malloc(sizeof (*sec->shdr))) == NULL) ||
	    ((sec->data = malloc(sizeof (*sec->data))) == NULL)) {
		int err = errno;
		sinfo_free(sec, 1);
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
		    fstate->file, strerror(err));
		return (0);
	}
	tinfo = &sinfo_data[sec->type];



	/*
	 * Fill in fake section header
	 *
	 * sh_name should be the offset of the name in the shstrtab
	 * section referenced by the ELF header. There is no
	 * value to elfdump in creating shstrtab, so we set
	 * sh_name to 0, knowing that elfdump doesn't look at it.
	 */
	sec->shdr->sh_name = 0;
	sec->shdr->sh_type = tinfo->sh_type;
	sec->shdr->sh_flags = tinfo->sh_flags;
	if ((tinfo->sh_flags & SHF_ALLOC) == 0) {
		/*
		 * Non-allocable section: Pass the addr (which is probably
		 * 0) and offset through without inspection.
		 */
		sec->shdr->sh_addr = sec->vaddr;
		sec->shdr->sh_offset = sec->offset;
		zero_bytes = 0;
	} else if (sec->vaddr == 0) {
		/*
		 * Allocable section with a 0 vaddr. Figure out the
		 * real address by mapping the offset to it using the
		 * program headers.
		 */
		sec->shdr->sh_addr = map_offset_to_addr(fstate, sec->offset,
		    sec->size, &zero_bytes, &phdr);
		sec->shdr->sh_offset = sec->offset;
	} else {
		/*
		 * Allocable section with non-0 vaddr. Use the vaddr
		 * to derive the offset.
		 */
		sec->shdr->sh_addr = sec->vaddr;
		sec->shdr->sh_offset = map_addr_to_offset(fstate,
		    sec->vaddr, sec->size, &zero_bytes, &phdr);
	}
	if (sec->shdr->sh_offset == 0) {
		sinfo_free(sec, 1);
		return (0);
	}
	/*
	 * If the program header has its write flags set, then set
	 * the section write flag.
	 */
	if (phdr && ((phdr->p_flags & PF_W) != 0))
		sec->shdr->sh_flags |= SHF_WRITE;
	sec->shdr->sh_size = sec->size;
	sec->shdr->sh_link = 0;
	sec->shdr->sh_info = 0;
	sec->shdr->sh_addralign = tinfo->sh_addralign;
	sec->shdr->sh_entsize = tinfo->sh_entsize;

	/*
	 * Some sections define special meanings for sh_link and sh_info.
	 */
	switch (tinfo->sh_type) {
	case SHT_DYNAMIC:
		sec->shdr->sh_link = SINFO_T_DYNSTR;
		break;

	case SHT_DYNSYM:
		sec->shdr->sh_link = SINFO_T_DYNSTR;
		sec->shdr->sh_info = 1;	/* First global symbol */
		break;

	case SHT_SUNW_LDYNSYM:
		sec->shdr->sh_link = SINFO_T_DYNSTR;
		/*
		 * ldynsym is all local symbols, so the index of the
		 * first global is equivalent to the number of symbols.
		 */
		sec->shdr->sh_info = sec->shdr->sh_size / sizeof (Sym);
		break;

	case SHT_HASH:
	case SHT_SUNW_move:
	case SHT_REL:
	case SHT_RELA:
	case SHT_SUNW_versym:
		sec->shdr->sh_link = SINFO_T_DYNSYM;
		break;

	case SHT_SUNW_verdef:
	case SHT_SUNW_verneed:
		sec->shdr->sh_link = SINFO_T_DYNSTR;
		sec->shdr->sh_info = sec->vercnt;
		break;

	case SHT_SUNW_syminfo:
		sec->shdr->sh_link = SINFO_T_DYNSYM;
		sec->shdr->sh_info = SINFO_T_DYN;
		break;

	case SHT_SUNW_symsort:
	case SHT_SUNW_tlssort:
		sec->shdr->sh_link = SINFO_T_LDYNSYM;
		break;
	}



	/* Fill in fake Elf_Data descriptor */
	sec->data->d_type = tinfo->libelf_type;
	sec->data->d_size = sec->size;
	sec->data->d_off = 0;
	sec->data->d_align = tinfo->sh_addralign;
	sec->data->d_version = fstate->ehdr->e_version;

	if (sec->size == 0) {
		sec->data->d_buf = NULL;
		return (1);
	}

	if ((sec->data->d_buf = malloc(sec->size)) == NULL) {
		int err = errno;

		sinfo_free(sec, 1);
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
		    fstate->file, strerror(err));
		return (0);
	}

	read_bytes = sec->size - zero_bytes;
	if ((read_bytes > 0) &&
	    (read_data(fstate, sec->shdr->sh_offset, sec->data->d_buf,
	    read_bytes, ELF_T_BYTE) == 0)) {
		sinfo_free(sec, 1);
		return (0);
	}
	if (zero_bytes > 0)
		bzero(read_bytes + (char *)sec->data->d_buf, zero_bytes);

	if ((tinfo->libelf_type != ELF_T_BYTE) &&
	    (elf_xlatetom(sec->data, sec->data,
	    fstate->ehdr->e_ident[EI_DATA]) == NULL)) {
		sinfo_free(sec, 1);
		failure(fstate->file, MSG_ORIG(MSG_ELF_XLATETOM));
		return (0);
	}

	return (1);
}



/*
 * Generate a section header cache made up of information derived
 * from the program headers.
 *
 * entry:
 *	file - Name of object
 *	fd - Open file handle for object
 *	elf - ELF descriptor
 *	ehdr - Elf header
 *	cache, shnum - Addresses of variables to receive resulting
 *		cache and number of sections.
 *
 * exit:
 *	On success, *cache and *shnum are set, and True (1) is returned.
 *	On failure, False (0) is returned.
 *
 * note:
 *	The cache returned by this routine must be freed using
 *	fake_shdr_cache_free(), and not by a direct call to free().
 *	Otherwise, memory will leak.
 */
int
fake_shdr_cache(const char *file, int fd, Elf *elf, Ehdr *ehdr,
    Cache **cache, size_t *shnum)
{
	/*
	 * The C language guarantees that a structure of homogeneous
	 * items will receive exactly the same layout in a structure
	 * as a plain array of the same type. Hence, this structure, which
	 * gives us by-name or by-index access to the various section
	 * info descriptors we maintain.
	 *
	 * We use this for sections where
	 *	- Only one instance is allowed
	 *	- We need to be able to access them easily by
	 *		name (for instance, when mining the .dynamic
	 *		section for information to build them up.
	 *
	 * NOTE: These fields must be in the same order as the
	 * SINFO_T_ type codes that correspond to them. Otherwise,
	 * they will end up in the wrong order in the cache array,
	 * and the sh_link/sh_info fields may be wrong.
	 */
	struct {
		/* Note: No entry is needed for SINFO_T_NULL */
		SINFO	dyn;
		SINFO	dynstr;
		SINFO	dynsym;
		SINFO	ldynsym;

		SINFO	hash;
		SINFO	syminfo;
		SINFO	symsort;
		SINFO	tlssort;
		SINFO	verneed;
		SINFO	verdef;
		SINFO	versym;
		SINFO	interp;
		SINFO	cap;
		SINFO	unwind;
		SINFO	move;
		SINFO	rel;
		SINFO	rela;
		SINFO	preinitarr;
		SINFO	initarr;
		SINFO	finiarr;
	} sec;
	static const size_t sinfo_n = sizeof (sec) / sizeof (sec.dyn);
	SINFO *secarr = (SINFO *) &sec;

	/*
	 * Doubly linked circular list, used to track sections
	 * where multiple sections of a given type can exist.
	 * seclist is the root of the list. Its sinfo field is not
	 * used --- it serves to anchor the root of the list, allowing
	 * rapid access to the first and last element in the list.
	 */
	SINFO_LISTELT	seclist;

	FSTATE		fstate;
	size_t		ndx;
	size_t		num_sinfo, num_list_sinfo;
	SINFO		*sinfo;
	SINFO_LISTELT	*sinfo_list;
	Cache		*_cache;


	fstate.file = file;
	fstate.fd = fd;
	fstate.ehdr = ehdr;
	if (elf_getphnum(elf, &fstate.phnum) == 0) {
		failure(file, MSG_ORIG(MSG_ELF_GETPHNUM));
		return (0);
	}
	if ((fstate.phdr = elf_getphdr(elf)) == NULL) {
		failure(file, MSG_ORIG(MSG_ELF_GETPHDR));
		return (0);
	}

	bzero(&sec, sizeof (sec));	/* Initialize "by-name" sec info */
	seclist.next = seclist.prev = &seclist;	  /* Empty circular list */

	/*
	 * Go through the program headers and look for information
	 * we can use to synthesize section headers. By far the most
	 * valuable thing is a dynamic section, the contents of
	 * which point at all sections used by ld.so.1.
	 */
	for (ndx = 0; ndx < fstate.phnum; ndx++) {
		/*
		 * A program header with no file size does
		 * not have a backing section.
		 */
		if (fstate.phdr[ndx].p_filesz == 0)
			continue;


		switch (fstate.phdr[ndx].p_type) {
		default:
			/* Header we can't use. Move on to next one */
			continue;

		case PT_DYNAMIC:
			sec.dyn.type = SINFO_T_DYN;
			sinfo = &sec.dyn;
			break;

		case PT_INTERP:
			sec.interp.type = SINFO_T_INTERP;
			sinfo = &sec.interp;
			break;

		case PT_NOTE:
			if ((sinfo = sinfo_list_alloc(&fstate, &seclist)) ==
			    NULL)
				continue;
			sinfo->type = SINFO_T_NOTE;
			break;

		case PT_SUNW_UNWIND:
			sec.unwind.type = SINFO_T_UNWIND;
			sinfo = &sec.unwind;
			break;

		case PT_SUNWCAP:
			sec.cap.type = SINFO_T_CAP;
			sinfo = &sec.cap;
			break;
		}

		/*
		 * Capture the position/extent information for
		 * the header in the SINFO struct set up by the
		 * switch statement above.
		 */
		sinfo->vaddr = fstate.phdr[ndx].p_vaddr;
		sinfo->offset = fstate.phdr[ndx].p_offset;
		sinfo->size = fstate.phdr[ndx].p_filesz;
	}

	/*
	 * If we found a dynamic section, look through it and
	 * gather information about the sections it references.
	 */
	if (sec.dyn.type == SINFO_T_DYN)
		(void) get_data(&fstate, &sec.dyn);
	if ((sec.dyn.type == SINFO_T_DYN) && (sec.dyn.data->d_buf != NULL)) {
		Dyn *dyn;
		for (dyn = sec.dyn.data->d_buf; dyn->d_tag != DT_NULL; dyn++) {
			switch (dyn->d_tag) {
			case DT_HASH:
				sec.hash.type = SINFO_T_HASH;
				sec.hash.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_STRTAB:
				sec.dynstr.type = SINFO_T_DYNSTR;
				sec.dynstr.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_SYMTAB:
				sec.dynsym.type = SINFO_T_DYNSYM;
				sec.dynsym.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_RELA:
				sec.rela.type = SINFO_T_RELA;
				sec.rela.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_RELASZ:
				sec.rela.size = dyn->d_un.d_val;
				break;

			case DT_STRSZ:
				sec.dynstr.size = dyn->d_un.d_val;
				break;

			case DT_REL:
				sec.rel.type = SINFO_T_REL;
				sec.rel.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_RELSZ:
				sec.rel.size = dyn->d_un.d_val;
				break;

			case DT_INIT_ARRAY:
				sec.initarr.type = SINFO_T_INITARR;
				sec.initarr.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_INIT_ARRAYSZ:
				sec.initarr.size = dyn->d_un.d_val;
				break;

			case DT_FINI_ARRAY:
				sec.finiarr.type = SINFO_T_FINIARR;
				sec.finiarr.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_FINI_ARRAYSZ:
				sec.finiarr.size = dyn->d_un.d_val;
				break;

			case DT_PREINIT_ARRAY:
				sec.preinitarr.type = SINFO_T_PREINITARR;
				sec.preinitarr.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_PREINIT_ARRAYSZ:
				sec.preinitarr.size = dyn->d_un.d_val;
				break;

			case DT_SUNW_SYMTAB:
				sec.ldynsym.type = SINFO_T_LDYNSYM;
				sec.ldynsym.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_SUNW_SYMSZ:
				sec.ldynsym.size = dyn->d_un.d_val;
				break;

			case DT_SUNW_SYMSORT:
				sec.symsort.type = SINFO_T_SYMSORT;
				sec.symsort.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_SUNW_SYMSORTSZ:
				sec.symsort.size = dyn->d_un.d_val;
				break;

			case DT_SUNW_TLSSORT:
				sec.tlssort.type = SINFO_T_TLSSORT;
				sec.tlssort.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_SUNW_TLSSORTSZ:
				sec.tlssort.size = dyn->d_un.d_val;
				break;

			case DT_MOVETAB:
				sec.move.type = SINFO_T_MOVE;
				sec.move.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_MOVESZ:
				sec.move.size = dyn->d_un.d_val;
				break;

			case DT_SYMINFO:
				sec.syminfo.type = SINFO_T_SYMINFO;
				sec.syminfo.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_SYMINSZ:
				sec.syminfo.size = dyn->d_un.d_val;
				break;

			case DT_VERSYM:
				sec.versym.type = SINFO_T_VERSYM;
				sec.versym.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_VERDEF:
				sec.verdef.type = SINFO_T_VERDEF;
				sec.verdef.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_VERDEFNUM:
				sec.verdef.vercnt = dyn->d_un.d_val;
				sec.verdef.size = sizeof (Verdef) *
				    dyn->d_un.d_val;
				break;

			case DT_VERNEED:
				sec.verneed.type = SINFO_T_VERNEED;
				sec.verneed.vaddr = dyn->d_un.d_ptr;
				break;

			case DT_VERNEEDNUM:
				sec.verneed.vercnt = dyn->d_un.d_val;
				sec.verneed.size = sizeof (Verneed) *
				    dyn->d_un.d_val;
				break;
			}
		}
	}

	/*
	 * Different sections depend on each other, and are meaningless
	 * without them. For instance, even if a .dynsym exists,
	 * no use can be made of it without a dynstr. These relationships
	 * fan out: Disqualifying the .dynsym will disqualify the hash
	 * section, and so forth.
	 *
	 * Disqualify sections that don't have the necessary prerequisites.
	 */

	/* Things that need the dynamic string table */
	if (sec.dynstr.size == 0)
		sec.dynstr.type = SINFO_T_NULL;
	if (sec.dynstr.type != SINFO_T_DYNSTR) {
		sinfo_free(&sec.dyn, 1);	/* Data already fetched */
		sec.dynsym.type =  SINFO_T_NULL;
		sec.dynsym.type =  SINFO_T_NULL;
		sec.verdef.type =  SINFO_T_NULL;
		sec.verneed.type =  SINFO_T_NULL;
	}

	/*
	 * The length of the hash section is encoded in its first two
	 * elements (nbucket, and nchain). The length of the dynsym,
	 * ldynsym, and versym are not given in the dynamic section,
	 * but are known to be the same as nchain.
	 *
	 * If we don't have a hash table, or cannot read nbuckets and
	 * nchain, we have to invalidate all of these.
	 */
	if (sec.hash.type == SINFO_T_HASH) {
		Word nbucket;
		Word nchain;
		size_t total;

		if (hash_size(&fstate, &sec.hash,
		    &nbucket, &nchain, &total) == 0) {
			sec.hash.type = SINFO_T_NULL;
		} else {
			/* Use these counts to set sizes for related sections */
			sec.hash.size = total * sizeof (Word);
			sec.dynsym.size = nchain * sizeof (Sym);
			sec.versym.size = nchain * sizeof (Versym);

			/*
			 * The ldynsym size received the DT_SUNW_SYMSZ
			 * value, which is the combined size of .dynsym
			 * and .ldynsym. Now that we have the dynsym size,
			 * use it to lower the ldynsym size to its real size.
			 */
			if (sec.ldynsym.size > sec.dynsym.size)
				sec.ldynsym.size  -= sec.dynsym.size;
		}
	}
	/*
	 * If the hash table is not present, or if the call to
	 * hash_size() failed, then discard the sections that
	 * need it to determine their length.
	 */
	if (sec.hash.type != SINFO_T_HASH) {
		sec.dynsym.type = SINFO_T_NULL;
		sec.ldynsym.type = SINFO_T_NULL;
		sec.versym.type = SINFO_T_NULL;
	}

	/*
	 * The runtime linker does not receive size information for
	 * Verdef and Verneed sections. We have to read their data
	 * in pieces and calculate it.
	 */
	if ((sec.verdef.type == SINFO_T_VERDEF) &&
	    (verdefneed_size(&fstate, &sec.verdef) == 0))
		sec.verdef.type = SINFO_T_NULL;
	if ((sec.verneed.type == SINFO_T_VERNEED) &&
	    (verdefneed_size(&fstate, &sec.verneed) == 0))
		sec.verneed.type = SINFO_T_NULL;

	/* Discard any section with a zero length */
	ndx = sinfo_n;
	for (sinfo = secarr; ndx-- > 0; sinfo++)
		if ((sinfo->type != SINFO_T_NULL) && (sinfo->size == 0))
			sinfo->type = SINFO_T_NULL;

	/* Things that need the dynamic symbol table */
	if (sec.dynsym.type != SINFO_T_DYNSYM) {
		sec.ldynsym.type = SINFO_T_NULL;
		sec.hash.type = SINFO_T_NULL;
		sec.syminfo.type = SINFO_T_NULL;
		sec.versym.type = SINFO_T_NULL;
		sec.move.type = SINFO_T_NULL;
		sec.rel.type = SINFO_T_NULL;
		sec.rela.type = SINFO_T_NULL;
	}

	/* Things that need the dynamic local symbol table */
	if (sec.ldynsym.type != SINFO_T_DYNSYM) {
		sec.symsort.type = SINFO_T_NULL;
		sec.tlssort.type = SINFO_T_NULL;
	}

	/*
	 * Look through the results and fetch the data for any sections
	 * we have found. At the same time, count the number.
	 */
	num_sinfo = num_list_sinfo = 0;
	ndx = sinfo_n;
	for (sinfo = secarr; ndx-- > 0; sinfo++) {
		if ((sinfo->type != SINFO_T_NULL) && (sinfo->data == NULL))
			(void) get_data(&fstate, sinfo);
		if (sinfo->data != NULL)
			num_sinfo++;
	}
	for (sinfo_list = seclist.next; sinfo_list != &seclist;
	    sinfo_list = sinfo_list->next) {
		sinfo = &sinfo_list->sinfo;
		if ((sinfo->type != SINFO_T_NULL) && (sinfo->data == NULL))
			(void) get_data(&fstate, sinfo);
		if (sinfo->data != NULL)
			num_list_sinfo++;
	}

	/*
	 * Allocate the cache array and fill it in. The cache array
	 * ends up taking all the dynamic memory we've allocated
	 * to build up sec and seclist, so on success, we have nothing
	 * left to clean up. If we can't allocate the cache array
	 * though, we have to free up everything else.
	 */
	*shnum = num_sinfo + num_list_sinfo + 1; /* Extra for 1st NULL sec. */
	if ((*cache = _cache = malloc((*shnum) * sizeof (Cache))) == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
		    file, strerror(err));
		sinfo_free(secarr, num_sinfo);
		sinfo_list_free_all(&seclist);
		return (0);
	}
	*_cache = cache_init;
	_cache++;
	ndx = 1;
	for (sinfo = secarr; num_sinfo > 0; sinfo++) {
		if (sinfo->data != NULL) {
			_cache->c_scn = NULL;
			_cache->c_shdr = sinfo->shdr;
			_cache->c_data = sinfo->data;
			_cache->c_name = (char *)sinfo_data[sinfo->type].name;
			_cache->c_ndx = ndx++;
			_cache++;
			num_sinfo--;
		}
	}
	for (sinfo_list = seclist.next; num_list_sinfo > 0;
	    sinfo_list = sinfo_list->next) {
		sinfo = &sinfo_list->sinfo;
		if (sinfo->data != NULL) {
			_cache->c_scn = NULL;
			_cache->c_shdr = sinfo->shdr;
			_cache->c_data = sinfo->data;
			_cache->c_name = (char *)sinfo_data[sinfo->type].name;
			_cache->c_ndx = ndx++;
			_cache++;
			num_list_sinfo--;
		}
	}

	return (1);
}





/*
 * Release all the memory referenced by a cache array allocated
 * by fake_shdr_cache().
 */
void
fake_shdr_cache_free(Cache *cache, size_t shnum)
{
	Cache *_cache;

	for (_cache = cache; shnum--; _cache++) {
		if (_cache->c_data != NULL) {
			if (_cache->c_data->d_buf != NULL)
				free(_cache->c_data->d_buf);
			free(_cache->c_data);
		}
		if (_cache->c_shdr)
			free(_cache->c_shdr);
	}

	free(cache);
}
