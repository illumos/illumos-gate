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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <ar.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <libelf.h>
#include "decl.h"
#include "msg.h"
#include "member.h"

#define	MANGLE	'\177'


/*
 * Archive processing
 *	When processing an archive member, two things can happen
 *	that are a little tricky.
 *
 * Sliding
 *	Sliding support is left in for backward compatibility and for
 *	support of Archives produced on other systems.  The bundled
 *	ar(1) produces archives with all members on a 4 byte boundry,
 *	so current archives should need no sliding.
 *
 *	Archive members that are only 2-byte aligned within the file will
 *	be slid.  To reuse the file's memory image, the library slides an
 *	archive member into its header to align the bytes.  This means
 *	the header must be disposable.
 *
 * Header reuse
 *	Because the library can trample the header, it must be preserved to
 *	avoid restrictions on archive member reuse.  That is, if the member
 *	header changes, the library may see garbage the next time it looks
 *	at the header.  After extracting the original header, the library
 *	appends it to the parents `ed_memlist' list, thus future lookups first
 *	check this list to determine if a member has previously been processed
 *	and whether sliding occured.
 */


/*
 * Size check
 *	If the header is too small, the following generates a negative
 *	subscript for x.x and fails to compile.
 *
 * The check is based on sizeof (Elf64) because that's always going
 * to be at least as big as Elf32.
 */

struct	x
{
	char	x[sizeof (struct ar_hdr) - 3 * sizeof (Elf64) - 1];
};



static const char	fmag[] = ARFMAG;


/*
 * Convert a string starting at 'p' and ending at 'end' into
 * an integer.  Base is the base of the number being converted
 * (either 8 or 10).
 *
 * Returns the converted integer of the string being scaned.
 */
unsigned long
_elf_number(char *p, char *end, int base)
{
	register unsigned	c;
	register unsigned long	n = 0;

	while (p < end) {
		if ((c = *p - '0') >= base) {
			while (*p++ == ' ')
				if (p >= end)
					return (n);
			return (0);
		}
		n *= base;
		n += c;
		++p;
	}
	return (n);
}


/*
 * Convert ar_hdr to Member
 *	Converts ascii file representation to the binary memory values.
 */
Member *
_elf_armem(Elf *elf, char *file, size_t fsz)
{
	register struct ar_hdr	*f = (struct ar_hdr *)file;
	register Member		*m;
	register Memlist	*l, * ol;
	register Memident	*i;

	if (fsz < sizeof (struct ar_hdr)) {
		_elf_seterr(EFMT_ARHDRSZ, 0);
		return (0);
	}

	/*
	 * Determine in this member has already been processed
	 */
	for (l = elf->ed_memlist, ol = l; l; ol = l, l = l->m_next)
		for (i = (Memident *)(l + 1); i < l->m_free; i++)
			if (i->m_offset == file)
				return (i->m_member);

	if (f->ar_fmag[0] != fmag[0] || f->ar_fmag[1] != fmag[1]) {
		_elf_seterr(EFMT_ARFMAG, 0);
		return (0);
	}

	/*
	 * Allocate a new member structure and assign it to the next free
	 * free memlist ident.
	 */
	if ((m = (Member *)malloc(sizeof (Member))) == 0) {
		_elf_seterr(EMEM_ARMEM, errno);
		return (0);
	}
	if ((elf->ed_memlist == 0) || (ol->m_free == ol->m_end)) {
		if ((l = (Memlist *)malloc(sizeof (Memlist) +
		    (sizeof (Memident) * MEMIDENTNO))) == 0) {
			_elf_seterr(EMEM_ARMEM, errno);
			free(m);
			return (0);
		}
		l->m_next = 0;
		l->m_free = (Memident *)(l + 1);
		l->m_end = (Memident *)((uintptr_t)l->m_free +
		    (sizeof (Memident) * MEMIDENTNO));

		if (elf->ed_memlist == 0)
			elf->ed_memlist = l;
		else
			ol->m_next = l;
		ol = l;
	}
	ol->m_free->m_offset = file;
	ol->m_free->m_member = m;
	ol->m_free++;

	m->m_err = 0;
	(void) memcpy(m->m_name, f->ar_name, ARSZ(ar_name));
	m->m_name[ARSZ(ar_name)] = '\0';
	m->m_hdr.ar_name = m->m_name;
	(void) memcpy(m->m_raw, f->ar_name, ARSZ(ar_name));
	m->m_raw[ARSZ(ar_name)] = '\0';
	m->m_hdr.ar_rawname = m->m_raw;
	m->m_slide = 0;

	/*
	 * Classify file name.
	 * If a name error occurs, delay until getarhdr().
	 */

	if (f->ar_name[0] != '/') {	/* regular name */
		register char	*p;

		p = &m->m_name[sizeof (m->m_name)];
		while (*--p != '/')
			if (p <= m->m_name)
				break;
		*p = '\0';
	} else if (f->ar_name[1] >= '0' && f->ar_name[1] <= '9') { /* strtab */
		register unsigned long	j;

		j = _elf_number(&f->ar_name[1],
		    &f->ar_name[ARSZ(ar_name)], 10);
		if (j < elf->ed_arstrsz)
			m->m_hdr.ar_name = elf->ed_arstr + j;
		else {
			m->m_hdr.ar_name = 0;
			/*LINTED*/ /* MSG_INTL(EFMT_ARSTRNM) */
			m->m_err = (int)EFMT_ARSTRNM;
		}
	} else if (f->ar_name[1] == ' ')			/* "/" */
		m->m_name[1] = '\0';
	else if (f->ar_name[1] == '/' && f->ar_name[2] == ' ')	/* "//" */
		m->m_name[2] = '\0';
	else if (f->ar_name[1] == 'S' && f->ar_name[2] == 'Y' &&
	    f->ar_name[3] == 'M' && f->ar_name[4] == '6' &&
	    f->ar_name[5] == '4' && f->ar_name[6] == '/' &&
	    f->ar_name[7] == ' ')				/* "/SYM64/" */
		m->m_name[7] = '\0';
	else {							/* "/?" */
		m->m_hdr.ar_name = 0;
		/*LINTED*/ /* MSG_INTL(EFMT_ARUNKNM) */
		m->m_err = (int)EFMT_ARUNKNM;
	}

	m->m_hdr.ar_date = (time_t)_elf_number(f->ar_date,
	    &f->ar_date[ARSZ(ar_date)], 10);
	/* LINTED */
	m->m_hdr.ar_uid = (uid_t)_elf_number(f->ar_uid,
	    &f->ar_uid[ARSZ(ar_uid)], 10);
	/* LINTED */
	m->m_hdr.ar_gid = (gid_t)_elf_number(f->ar_gid,
	    &f->ar_gid[ARSZ(ar_gid)], 10);
	/* LINTED */
	m->m_hdr.ar_mode = (mode_t)_elf_number(f->ar_mode,
	    &f->ar_mode[ARSZ(ar_mode)], 8);
	m->m_hdr.ar_size = (off_t)_elf_number(f->ar_size,
	    &f->ar_size[ARSZ(ar_size)], 10);

	return (m);
}


/*
 * Initial archive processing
 *	An archive may have two special members.
 *
 *	A symbol table, named / or /SYM64/, must be first if it is present.
 *	Both forms use the same layout differing in the width of the
 *	integer type used (32 or 64-bit respectively).
 *
 *	A long name string table, named //, must precede all "normal"
 *	members. This string table is used to hold the names of archive
 *	members with names that are longer than 15 characters. It should not
 *	be confused with the string table found at the end of the symbol
 *	table, which is used to hold symbol names.
 *
 *	This code "peeks" at headers but doesn't change them.
 *	Later processing wants original headers.
 *
 *	String table is converted, changing '/' name terminators
 *	to nulls.  The last byte in the string table, which should
 *	be '\n', is set to nil, guaranteeing null termination.  That
 *	byte should be '\n', but this code doesn't check.
 *
 *	The symbol table conversion is delayed until needed.
 */
void
_elf_arinit(Elf * elf)
{
	char				*base = elf->ed_ident;
	register char			*end = base + elf->ed_fsz;
	register struct ar_hdr		*a;
	register char			*hdr = base + SARMAG;
	register char			*mem;
	int				j;
	size_t				sz = SARMAG;

	elf->ed_status = ES_COOKED;
	elf->ed_nextoff = SARMAG;
	for (j = 0; j < 2; ++j)	 {	/* 2 special members */
		unsigned long	n;

		if (((end - hdr) < sizeof (struct ar_hdr)) ||
		    (_elf_vm(elf, (size_t)(SARMAG),
		    sizeof (struct ar_hdr)) != OK_YES))
			return;

		a = (struct ar_hdr *)hdr;
		mem = (char *)a + sizeof (struct ar_hdr);
		n = _elf_number(a->ar_size, &a->ar_size[ARSZ(ar_size)], 10);
		if ((end - mem < n) || (a->ar_name[0] != '/') ||
		    ((sz = n) != n)) {
			return;
		}

		hdr = mem + sz;
		if (a->ar_name[1] == ' ') {	/* 32-bit symbol table */
			elf->ed_arsym = mem;
			elf->ed_arsymsz = sz;
			elf->ed_arsymoff = (char *)a - base;
		} else if (a->ar_name[1] == '/' && a->ar_name[2] == ' ') {
						/* Long name string table */
			int	k;

			if (_elf_vm(elf, (size_t)(mem - elf->ed_ident),
			    sz) != OK_YES)
				return;
			if (elf->ed_vm == 0) {
				char	*nmem;
				if ((nmem = malloc(sz)) == 0) {
					_elf_seterr(EMEM_ARSTR, errno);
					return;
				}
				(void) memcpy(nmem, mem, sz);
				elf->ed_myflags |= EDF_ASTRALLOC;
				mem = nmem;
			}

			elf->ed_arstr = mem;
			elf->ed_arstrsz = sz;
			elf->ed_arstroff = (char *)a - base;
			for (k = 0; k < sz; k++) {
				if (*mem == '/')
					*mem = '\0';
				++mem;
			}
			*(mem - 1) = '\0';
		} else if (a->ar_name[1] == 'S' && a->ar_name[2] == 'Y' &&
		    a->ar_name[3] == 'M' && a->ar_name[4] == '6' &&
		    a->ar_name[5] == '4' && a->ar_name[6] == '/' &&
		    a->ar_name[7] == ' ') {
						/* 64-bit symbol table */
			elf->ed_arsym = mem;
			elf->ed_arsymsz = sz;
			elf->ed_arsymoff = (char *)a - base;
			elf->ed_myflags |= EDF_ARSYM64;
		} else {
			return;
		}
		hdr += sz & 1;
	}
}
