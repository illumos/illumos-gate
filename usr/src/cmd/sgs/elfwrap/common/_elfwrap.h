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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__ELFWRAP_H
#define	__ELFWRAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Local include file for elfwrap.
 */
#include <libelf.h>
#include <alist.h>
#include <_machelf.h>

/*
 * Define a target descriptor to hold target specific information.
 */
typedef struct {
	uchar_t		td_class;	/* target class (32-bit/64-bit) */
	uchar_t		td_data;	/* target data (LSB/MSB) */
	ushort_t	td_mach;	/* target machine (sparc, i386, etc.) */
	size_t		td_align;	/* target data buffer alignment */
	size_t		td_symsz;	/* target symbol table entry size */
} TargDesc_t;

/*
 * Define a descriptor for each ELF section being output to the new file.
 */
typedef struct {
	const char	*os_name;	/* section name */
	Word		os_type;	/* section type */
	Xword		os_flags;	/* section flags */
	size_t		os_ndx;		/* section index (input file) */
	off_t		os_size;	/* section size (input file) */
	void		*os_addr;	/* section address (input file) */
	Shdr		*os_shdr;	/* section header (output file) */
	Elf_Data	*os_data;	/* section data (output file) */
} OutSec_t;

#define	AL_CNT_WOSECS	10		/* default number of input sections */

/*
 * Define a standard section descriptor.
 */
typedef struct {
	const char	*ss_name;	/* section name */
	Word		ss_type;	/* section type */
	Xword		ss_flags;	/* section flags */
} StdSec_t;

/*
 * Define a descriptor to maintain section information.
 */
typedef struct {
	Alist		*od_outsecs;	/* list of output sections */
	size_t		od_symtabno;	/* number of symbol table entries */
	size_t		od_strtabsz;	/* string table size */
	size_t		od_shstrtabsz; 	/* section header string table size */
} ObjDesc_t;

/*
 * Define all external interfaces.
 */
extern	int	input32(int, char **, const char *, const char *, ObjDesc_t *);
extern	int	input64(int, char **, const char *, const char *, ObjDesc_t *);
extern	int	output32(const char *, int, const char *, ushort_t,
		    ObjDesc_t *);
extern	int	output64(const char *, int, const char *, ushort_t,
		    ObjDesc_t *);

#if	defined(lint)
extern	void	target_init(TargDesc_t *);
#else
extern	void	target_init_sparc(TargDesc_t *);
extern	void	target_init_sparcv9(TargDesc_t *);
extern	void	target_init_i386(TargDesc_t *);
extern	void	target_init_amd64(TargDesc_t *);
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* __ELFWRAP_H */
