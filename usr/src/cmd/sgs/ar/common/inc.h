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
 *	Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 */

#ifndef	_INC_H
#define	_INC_H

#include <stdio.h>
#include <sys/param.h>
#include <ar.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include "sgs.h"
#include <stdarg.h>
#include <sys/mman.h>

#ifndef	UID_NOBODY
#define	UID_NOBODY	60001
#endif

#ifndef GID_NOBODY
#define	GID_NOBODY	60001
#endif

#include <stdlib.h>

#include "libelf.h"

#include <signal.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include <time.h>
#include <locale.h>

#define	SUID	04000
#define	SGID	02000
#define	ROWN	0400
#define	WOWN	0200
#define	XOWN	0100
#define	RGRP	040
#define	WGRP	020
#define	XGRP	010
#define	ROTH	04
#define	WOTH	02
#define	XOTH	01
#define	STXT	01000

#define	opt_FLAG(_x, ch)	((_x->opt_flgs & ch))
#define	CHUNK		500
#define	SYMCHUNK	1000
#define	SNAME		16
#define	ROUNDUP(x)	(((x) + 1) & ~1)

#define	LONGDIRNAME	"//              "
#define	SYMDIRNAME	"/               "	/* symbol directory filename */
#define	FNFORMAT	"%-16s"				/* filename format */
#define	TLFORMAT	"%-12ld%-6u%-6u%-8o%-10ld%-2s"	/* trailer format */
#define	FORMAT		FNFORMAT TLFORMAT
#define	DATESIZE	60	 /*  sizeof (struct ar_hdr)  */

#define	PLAIN_ERROR	0
#define	LIBELF_ERROR	1
#define	SYSTEM_ERROR	2

typedef struct arfile ARFILE;
typedef ARFILE * ARFILEP;

#define	AR_MAX_BYTES_IN_MEM		0x20000000 /* 512 Mb */

struct arfile
{
	char	ar_name[SNAME];		/* info from archive member header */
	time_t	ar_date;
	int	ar_uid;
	int	ar_gid;
	unsigned long	ar_mode;
	long	ar_size;
	char    *ar_longname;
	char    *ar_rawname;
	Elf 	*ar_elf;		/* My elf descriptor */
	char	*ar_pathname;
	char	*ar_contents;
	long	ar_offset;		/* The member offset */
	unsigned char ar_flag;
	unsigned char ar_padding;	/* padding for CLASS64 */
	ARFILE	*ar_next;
};

typedef struct cmd_info {
	char *arnam;	/* Archive file name */
	int afd;	/* fd for the archive file */
	Elf *arf;	/* Elf descriptor for the archive */
	char *ponam;
	char **namv;
	int namc;
	int opt_flgs;	/* lower case options */
	int OPT_flgs;	/* upper case options */
	int (*comfun)();
	int modified;
	unsigned long bytes_in_mem;
} Cmd_info;

/*
 * options
 */
#define	a_FLAG	0x0001
#define	b_FLAG	0x0002
#define	c_FLAG	0x0004
#define	d_FLAG	0x0008
#define	l_FLAG	0x0020
#define	m_FLAG	0x0040
#define	p_FLAG	0x0080
#define	q_FLAG	0x0100
#define	r_FLAG	0x0200
#define	s_FLAG	0x0400
#define	t_FLAG	0x0800
#define	u_FLAG	0x1000
#define	v_FLAG	0x2000
#define	x_FLAG	0x4000
#define	z_FLAG	0x8000

#define	C_FLAG	0x0001
#define	M_FLAG	0x0002
#define	T_FLAG	0x0004

/*
 * Where is the file contents from ?
 */
#define	F_ELFRAW	0x01		/* Mmaped via elf_raw() */
#define	F_MMAPED	0x02		/* Mmaped file contents */
#define	F_MALLOCED	0x04		/* Malloced file contents */
#define	F_CLASS32	0x08		/* This is ELFCLASS32 */
#define	F_CLASS64	0x10		/* This is ELFCLASS64 */

/*
 * Function prototypes
 */
int qcmd(Cmd_info *);
int rcmd(Cmd_info *);
int dcmd(Cmd_info *);
int xcmd(Cmd_info *);
int pcmd(Cmd_info *);
int mcmd(Cmd_info *);
int tcmd(Cmd_info *);

int getaf(Cmd_info *);
char *writefile(Cmd_info *cmd_info);
void error_message(int, ...);

ARFILE *getfile(Cmd_info *);
ARFILE *newfile();

char *trim(char *);

/*
 * Error definitions
 */
#define	MALLOC_ERROR		0
#define	USAGE_01_ERROR		1
#define	NOT_FOUND_01_ERROR	2
#define	USAGE_02_ERROR		3
#define	USAGE_03_ERROR		4
#define	USAGE_04_ERROR		5
#define	SYS_OPEN_ERROR		6
#define	SYS_READ_ERROR		7
#define	NOT_FOUND_02_ERROR	8
#define	PATHCONF_ERROR		9
#define	SYS_WRITE_ERROR		10
#define	LOCALTIME_ERROR		11
#define	USAGE_05_ERROR		12
#define	ELF_VERSION_ERROR	13
#define	NOT_ARCHIVE_ERROR 	14
#define	USAGE_06_ERROR		15
#define	ELF_MALARCHIVE_ERROR	16
#define	SYS_LSEEK_ERROR		17
#define	NOT_FOUND_03_ERROR	18
#define	SYS_LSEEK_02_ERROR	19
#define	SYS_LSEEK_03_ERROR	20
#define	SYS_LSEEK_04_ERROR	21
#define	DEBUG_INFO_01_ERROR	22
#define	DEBUG_INFO_02_ERROR	23
#define	ELF_INTERNAL_RAND_ERROR	24
#define	ELF_BEGIN_01_ERROR	25
#define	DEBUG_INFO_03_ERROR	26
#define	ELF_BEGIN_02_ERROR	27
#define	ELF_BEGIN_03_ERROR	28
#define	ARCHIVE_IN_ARCHIVE_ERROR	29
#define	ARCHIVE_USAGE_ERROR	30
#define	INTERNAL_01_ERROR	31
#define	ELF_GETSCN_01_ERROR	32
#define	ELF_GETSCN_02_ERROR	33
#define	ELF_GETDATA_01_ERROR	34
#define	ELF_GETDATA_02_ERROR	35
#define	W_ELF_NO_DATA_01_ERROR	36
#define	W_ELF_NO_DATA_02_ERROR	37
#define	INTERNAL_02_ERROR	38
#define	DIAG_01_ERROR		39
#define	BER_MES_CREATE_ERROR	40
#define	SYS_CREATE_01_ERROR	41
#define	SYS_WRITE_02_ERROR	42
#define	BER_MES_WRITE_ERROR	43
#define	SYS_WRITE_03_ERROR	44
#define	SBROW_01_ERROR		45
#define	SBROW_02_ERROR		46
#define	SBROW_03_ERROR		47
#define	SYMTAB_01_ERROR		48
#define	SYMTAB_02_ERROR		49
#define	SYMTAB_03_ERROR		50
#define	SYMTAB_04_ERROR		51
#define	SYMTAB_05_ERROR		52
#define	SYMTAB_06_ERROR		53
#define	SYMTAB_07_ERROR		54
#define	ELF_01_ERROR		55
#define	ELF_02_ERROR		56
#define	OVERRIDE_WARN_ERROR	57
#define	SYS_WRITE_04_ERROR	58
#define	WARN_USER_ERROR		59
#define	ELF_RAWFILE_ERROR	60

#endif	/* _INC_H */
