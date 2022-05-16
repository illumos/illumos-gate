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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef	_MCS_H
#define	_MCS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <libelf.h>
#include <ar.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <memory.h>
#include <locale.h>
#include <sys/mman.h>
#include "sgs.h"
#include "gelf.h"

#define	FORMAT	"%-16s%-12ld%-6u%-6u%-8o%-10ld%-2s"
#define	ROUNDUP(x)	(((x) + 1) & ~1)
#define	TMPDIR	"/tmp"

#define	DELETED	-1	/* The section will be removed */
#define	NULLED  -2	/* The section will be nulled */
#define	EXPANDED -3	/* The size of the section expanded */
#define	SHRUNK -4	/* The section shrinked */

#define	ACT_NOP		0x00000000
#define	ACT_DELETE	0x00000001
#define	ACT_PRINT	0x00000002
#define	ACT_COMPRESS	0x00000003
#define	ACT_APPEND	0x00000004
#define	ACT_ZAP		0x00000005
#define	SET_ACTION(x, y)	x = (x & 0xfffffff0) | y
#define	GET_ACTION(x)		(x & 0x0000000f)

#define	NOSEG		0x00000010
#define	IN		0x00000020 /* section is IN a segment */
#define	PRIOR		0x00000030 /* section is PRIOR to a segment */
#define	AFTER		0x00000040 /* section is AFTER a segment */
#define	SET_LOC(x, y)	x = (x & 0xffffff0f) | y
#define	GET_LOC(x)	(x & 0x000000f0)

#define	CANDIDATE	0x00000100
#define	MOVING		0x00000200
#define	MODIFIED	0x00000400

#define	UNSET_CANDIDATE(x)	x = x & ~CANDIDATE
#define	SET_CANDIDATE(x)	x = x | CANDIDATE
#define	ISCANDIDATE(x)		(x & CANDIDATE)
#define	SET_MOVING(x)		x = (x | MOVING)
#define	GET_MOVING(x)		(x & MOVING)
#define	SET_MODIFIED(x)		x = (x | MODIFIED)
#define	GET_MODIFIED(x)		(x & MODIFIED)

#define	FAILURE 1
#define	SUCCESS 0

#define	DONT_BUILD 3 /* this code is used to prevent building a new file */
		/* because mcs was given only -p */


#define	MCS	1
#define	STRIP	2
#define	STR_STRIP	"strip"

/*
 * Structure to hold section information.
 */
typedef struct section_info_table {
	/*
	 * Section information.
	 */
	Elf_Scn		*scn;		/* Section */
	Elf_Data	*data;		/* Original data */
	Elf_Data	*mdata;		/* Modified data */
	char		*name;		/* Section name, or NULL if unknown */
	char		*rel_name;
	GElf_Shdr	shdr;
	GElf_Word	secno;		/* The new index */
	GElf_Word	osecno;		/* The original index */
	GElf_Word	rel_scn_index;
	GElf_Xword	si_flags;
	GElf_Xword	rel_loc;
} section_info_table;

/*
 * Structure to hold action information
 */
typedef struct action {
	int a_action;		/* Which action to take ? */
	int a_cnt;		/* Am I applied ? */
	char *a_string;		/* The string to be added. */
} action;

/*
 * Structure to hold the section names specified.
 */
typedef struct s_name {
	char		*name;
	struct s_name	*next;
	unsigned char	flags;
} S_Name;
#define	SECT_NAME	sect_head->name
#define	SNAME_FLG_STRNCMP	0x01	/* Use strncmp() instead of strcmp() */
					/* for section name comparison. */

/*
 * Structure to hold command information
 */
typedef struct cmd_info {
	APlist	*sh_groups;	/* list of SHT_GROUP sections */
	int	no_of_append;
	int	no_of_delete;
	int	no_of_nulled;
	int	no_of_compressed;
	int	no_of_moved;
	size_t	str_size;	/* size of string to be appended */
	int	ci_flags;	/* Various flags */
} Cmd_Info;

#define	MIGHT_CHG	0x0001
#define	aFLAG		0x0002
#define	cFLAG		0x0004
#define	dFLAG		0x0008
#define	lFLAG		0x0010
#define	pFLAG		0x0020
#define	xFLAG		0x0040
#define	VFLAG		0x0080
#define	zFLAG		0x0100
#define	I_AM_STRIP	0x0200
#define	SHF_GROUP_MOVE	0x0400	/* SHF_GROUP section moves */
#define	SHF_GROUP_DEL	0x0800	/* SHF_GROUP section deleted */

#define	CHK_OPT(_x, _y)	(((_x)->ci_flags & (_y)) != 0)
#define	SET_OPT(_x, _y)	((_x)->ci_flags |= (_y))

/*
 * Segment Table
 */
typedef struct seg_table {
	GElf_Off	p_offset;
	GElf_Xword	p_memsz;
	GElf_Xword	p_filesz;
} Seg_Table;

/*
 * Temporary files
 */
typedef struct {
	const char	*tmp_name;	/* NULL, or name of temp file */
	int		tmp_unlink;   /* True if should unlink prior to exit */
} Tmp_File;

/*
 * Function prototypes.
 */
int		apply_action(section_info_table *, char *, Cmd_Info *);
int		each_file(char *, Cmd_Info *);
void		error_message(int, ...);
void		mcs_exit(int);
int		sectcmp(char *);
void		free_tempfile(Tmp_File *);

/*
 * Error messages
 */
#define	MALLOC_ERROR		0
#define	USAGE_ERROR		1
#define	ELFVER_ERROR		2
#define	OPEN_ERROR		3
#define	LIBELF_ERROR		4
#define	OPEN_TEMP_ERROR		5
#define	WRITE_ERROR		6
#define	GETARHDR_ERROR		7
#define	FILE_TYPE_ERROR		8
#define	NOT_MANIPULATED_ERROR	9
#define	WRN_MANIPULATED_ERROR	10
#define	NO_SECT_TABLE_ERROR	11
#define	READ_ERROR		12
#define	READ_MANI_ERROR		13
#define	WRITE_MANI_ERROR	14
#define	LSEEK_MANI_ERROR	15
#define	SYM_TAB_AR_ERROR	16
#define	EXEC_AR_ERROR		17
#define	READ_SYS_ERROR		18
#define	OPEN_WRITE_ERROR	19
#define	ACT_PRINT_ERROR		20
#define	ACT_DELETE1_ERROR	21
#define	ACT_DELETE2_ERROR	22
#define	ACT_APPEND1_ERROR	23
#define	ACT_APPEND2_ERROR	24
#define	ACT_COMPRESS1_ERROR	25
#define	ACT_COMPRESS2_ERROR	26
#define	ACCESS_ERROR		27
#define	WRITE_MANI_ERROR2	28

#define	PLAIN_ERROR	0
#define	LIBelf_ERROR	1
#define	SYSTEM_ERROR	2

#ifdef	__cplusplus
}
#endif

#endif	/* _MCS_H */
