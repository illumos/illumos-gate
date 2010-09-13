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
 * Copyright (c) 1998-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_STATIC_PROF_H
#define	_STATIC_PROF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * include headers
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <link.h>
#include <sys/elf_SPARC.h>
#include <sys/utsname.h>
#include <errno.h>

/*
 * Declaration of global variables
 */

#define	DEFBKTS		24997	/* 3571 nice big prime number */
#define	MASK		(~(unsigned long)0<<28)

/*
 * bucket struct of hash table
 */
typedef struct binding_bucket
{
	char			*sym;
	char			*ref_lib;
	char			*def_lib;
	char			*obj;
	char			*section;
	char			*sttype;
	char			*stbind;
} binding_bucket;

static binding_bucket	bkts[DEFBKTS];

/*
 * data structure for linked list of DT_NEEDED entries
 */
typedef struct dt_list_tag
{
	char			*libname;
#if	defined(_LP64)
	Elf64_Sword		d_tag;
#else
	Elf32_Sword		d_tag;
#endif
	struct dt_list_tag	*next;
} dt_list;

static dt_list		*dt_needed = NULL; /* ptr to link list of dtneeded */

/*
 * struct for the binary object under test
 */
typedef struct obj_com
{
	char		**filenames;	/* name of application file */
	char		*filename;
	int		numfiles;	/* number of applications to check */
	/* ---Current application ELF file information--- */
	char		*ename;	/* name of current ELF file */
	int		fd;	/* file descriptor for current file */
	Elf		*elf;	/* elf descriptor for current file */
#if	defined(_LP64)
	Elf64_Ehdr	*ehdr;	/* 64 bit elf header for current file */
	Elf64_Phdr	*phdr;	/* 64 bit prog header for current file */
	Elf64_Dyn	*dynsect;	/* pointer to 64 bit dynamic section */
#else
	Elf32_Ehdr    	*ehdr;	/* 32 bit elf header for current file */
	Elf32_Phdr    	*phdr;	/* 32 bit prog header for current file */
	Elf32_Dyn	*dynsect;	/* ptr to 64 bit dynamic section */
#endif
	Elf_Data	*ddata;	/* ptr to dstring table data descriptor */
	char		*dynnames; /* pointer to dynamic string table */
	/* ---ELF file symbol table information--- */
	/* dynamic symbol table */
#if	defined(_LP64)
	Elf64_Sym	*dsym_tab;
#else
	Elf32_Sym	*dsym_tab;
#endif
	Elf_Data	*dsym_data;
	int		dsym_num;
	char		*dsym_names;
	/* regular symbol table */
#if	defined(_LP64)
	Elf64_Sym	*sym_tab;
#else
	Elf32_Sym	*sym_tab;
#endif
	Elf_Data	*sym_data;
	int		sym_num;
	char		*sym_names;
} obj_com;

/*
 * struct of the linked list of object files
 */
typedef struct obj_list_tag
{
	obj_com		*obj;
	struct obj_list_tag	*next;
} obj_list;

static int	oflag = 0;		/* flag for redirecting output */
static int	pflag = 0;		/* flag for profiling to stdout */
static int	sflag = 1;		/* flag for silent mode */
static int	aflag = 1;		/* flag for read input as archive */
extern int	errno;			/* file opening error return code */
static FILE	*OUTPUT_FD = stdout;	/* output fd: default as stdout */
static char	*outputfile;		/* full pathname of output file */

#define	SUCCEED		0
#define	FAIL		1

#define	TRUE		1
#define	FALSE		0

#ifdef	__cplusplus
}
#endif

#endif	/* _STATIC_PROF_H */
