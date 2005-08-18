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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "inc.h"

static const char *msg[] = {
/* MALLOC_ERROR */
"ar: could not allocate memory.\n",
/* USAGE_01_ERROR */
"ar: one of [drqtpmx] must be specified\n",
/* NOT_FOUND_01_ERROR */
"ar: archive, %s, not found\n",
/* USAGE_02_ERROR */
"ar: -%c requires an operand\n",
/* USAGE_03_ERROR */
"ar: bad option `%c'\n",
/* USAGE_04_ERROR */
"ar: only one of [drqtpmx] allowed\n",
/* SYS_OPEN_ERROR */
"ar: cannot open %s\n",
/* SYS_READ_ERROR */
"ar: cannot read %s\n",
/* NOT_FOUND_02_ERROR */
"ar: posname, %s, not found\n",
/* PATHCONF_ERROR */
"ar: -T failed to calculate file name length.\n",
/* SYS_WRITE_ERROR */
"ar: %s: cannot write\n",
/* LOCALTIME_ERROR */
"ar: don't have enough space to store the date\n",
/* USAGE_05_ERROR */
"ar: abi not allowed with q\n",
/* ELF_VERSION_ERROR */
"ar: libelf.a out of date\n",
/* NOT_ARCHIVE_ERROR */
"ar: %s not in archive format\n",
/* USAGE_06_ERROR */
"ar: %s taken as mandatory 'posname' with keys 'abi'\n",
/* ELF_MALARCHIVE_ERROR */
"ar: %s: malformed archive (at %ld)\n",
/* SYS_LSEEK_ERROR */
"ar: cannot lseek\n",
/* NOT_FOUND_03_ERROR */
"ar: %s not found\n",
/* SYS_LSEEK_02_ERROR */
"ar: lseek(current) errno=%d\n",
/* SYS_LSEEK_03_ERROR */
"ar: lseek(f->offset) errno=%d\n",
/* SYS_LSEEK_04_ERROR */
"ar: Problem seeking\n",
/* DEBUG_INFO_01_ERROR */
"ar: currentloc %d intendedloc %d resultingloc %d\n",
/* DEBUG_INFO_02_ERROR */
"ar: ar_name '%s' longname '%s'\n",
/* ELF_INTERNAL_RAND_ERROR */
"ar: internal or system error; archive file has been scribbled\n",
/* ELF_BEGIN_01_ERROR */
"ar: archive is corrupted/possible end-of-archive\n",
/* DEBUG_INFO_03_ERROR */
"ar: can not find member'%s' at offset 0x%x\n",
/* ELF_BEGIN_02_ERROR */
"ar: cannot elf_begin() %s.\n",
/* ELF_BEGIN_03_ERROR */
"ar: cannot elf_begin().\n",
/* ARCHIVE_IN_ARCHIVE_ERROR */
"ar: %s is in archive format - embedded archives are not allowed\n",
/* ARCHIVE_USAGE_ERROR */
"ar: embedded archives are not allowed.\n",
/* INTERNAL_01_ERROR */
"ar: internal error - cannot tell whether file is included in archive or not\n",
/* ELF_GETSCN_01_ERROR */
"ar: %s has no section header or bad elf format.\n",
/* ELF_GETSCN_02_ERROR */
"ar: no section header or bad elf format.\n",
/* ELF_GETDATA_01_ERROR */
"ar: %s has bad elf format.\n",
/* ELF_GETDATA_02_ERROR */
"ar: bad elf format.\n",
/* W_ELF_NO_DATA_01_ERROR */
"ar: %s has no data in section header table.\n",
/* W_ELF_NO_DATA_02_ERROR */
"ar: No data in section header table.\n",
/* INTERNAL_02_ERROR */
"ar: internal header generation error\n",
/* DIAG_01_ERROR */
"ar: diagnosis: ERRNO=%d\n",
/* BER_MES_CREATE_ERROR */
"ar: creating %s\n",
/* SYS_CREATE_01_ERROR */
"ar: cannot create %s\n",
/* SYS_WRITE_02_ERROR */
"ar: cannot write %s\n",
/* BER_MES_WRITE_ERROR */
"ar: writing %s\n",
/* SYS_WRITE_03_ERROR */
"ar: cannot write archive\n",
/* SBROW_01_ERROR */
"ar: No data in stab table.\n",
/* SBROW_02_ERROR */
"ar: No data in stab string table.\n",
/* SBROW_03_ERROR */
"ar: No data in stab table - size is 0\n",
/* SYMTAB_01_ERROR */
"ar: Symbol table entry size is 0!\n",
/* SYMTAB_02_ERROR */
"ar: %s has no string table for symbol names\n",
/* SYMTAB_03_ERROR */
"ar: No string table for symbol names\n",
/* SYMTAB_04_ERROR */
"ar: %s has no data in string table\n",
/* SYMTAB_05_ERROR */
"ar: No data in string table\n",
/* SYMTAB_06_ERROR */
"ar: %s has no data in string table - size is 0\n",
/* SYMTAB_07_ERROR */
"ar: No data in string table - size is 0\n",
/* ELF_01_ERROR */
"ar: %s caused libelf error: %s\n",
/* ELF_02_ERROR */
"ar: libelf error: %s\n",
/* OVERRIDE_WARN_ERROR */
"ar: %s already exists. Will not be extracted\n",
/* SYS_WRITE_04_ERROR */
"ar: writing to %s failed.\n",
/* WARN_USER_ERROR */
"\tThe original archive is destroyed.\n",
/* ELF_RAWFILE_ERROR */
"ar: elf_rawfile() failed.\n",
};

void
error_message(int args, ...)
{
	int mes = args;
	char *message = gettext((char *)msg[mes]);
	int flag;
	char *sys_mes;
	va_list ap;
	va_start(ap, args);

	flag = va_arg(ap, int);
	sys_mes = va_arg(ap, char *);

	switch (mes) {
	case MALLOC_ERROR:
	case USAGE_01_ERROR:
	case USAGE_04_ERROR:
	case PATHCONF_ERROR:
	case LOCALTIME_ERROR:
	case USAGE_05_ERROR:
	case ARCHIVE_USAGE_ERROR:
	case INTERNAL_01_ERROR:
	case INTERNAL_02_ERROR:
	case SBROW_01_ERROR:
	case SBROW_02_ERROR:
	case SBROW_03_ERROR:
	case SYMTAB_01_ERROR:
	case SYMTAB_03_ERROR:
	case SYMTAB_05_ERROR:
	case SYMTAB_07_ERROR:
		/* LINTED: variable format */
		(void) fprintf(stderr, message);
		break;
	case ARCHIVE_IN_ARCHIVE_ERROR:
	case NOT_FOUND_01_ERROR:
	case NOT_FOUND_02_ERROR:
	case NOT_FOUND_03_ERROR:
	case NOT_ARCHIVE_ERROR:
	case USAGE_06_ERROR:
	case BER_MES_CREATE_ERROR:
	case BER_MES_WRITE_ERROR:
	case SYMTAB_02_ERROR:
	case SYMTAB_04_ERROR:
	case SYMTAB_06_ERROR:
	case OVERRIDE_WARN_ERROR:
		/* LINTED: variable format */
		(void) fprintf(stderr, message, va_arg(ap, char *));
		break;
	case USAGE_02_ERROR:
	case USAGE_03_ERROR:
		/* LINTED: variable format */
		(void) fprintf(stderr, message, va_arg(ap, int));
		break;
	case DIAG_01_ERROR:
		/* LINTED: variable format */
		(void) fprintf(stderr, message, va_arg(ap, int));
		break;
	case DEBUG_INFO_01_ERROR: {
		int	a1, a2, a3;

		a1 = va_arg(ap, int);
		a2 = va_arg(ap, int);
		a3 = va_arg(ap, int);
		/* LINTED: variable format */
		(void) fprintf(stderr, message, a1, a2, a3);
		break;
	}
	case DEBUG_INFO_02_ERROR: {
		char	*a1, *a2;

		a1 = va_arg(ap, char *);
		a2 = va_arg(ap, char *);
		/* LINTED: variable format */
		(void) fprintf(stderr, message, a1, a2);
		break;
	}
	case DEBUG_INFO_03_ERROR: {
		char	*a1;
		int	a2;

		a1 = va_arg(ap, char *);
		a2 = va_arg(ap, int);
		/* LINTED: variable format */
		(void) fprintf(stderr, message, a1, a2);
		break;
	}
	/*
	 * system call failure
	 */
	case SYS_LSEEK_ERROR:
	case SYS_LSEEK_04_ERROR:
	case SYS_WRITE_03_ERROR:
		/* LINTED: variable format */
		(void) fprintf(stderr, message);
		break;
	case SYS_OPEN_ERROR:
	case SYS_READ_ERROR:
	case SYS_WRITE_ERROR:
	case SYS_WRITE_02_ERROR:
	case SYS_CREATE_01_ERROR:
		/* LINTED: variable format */
		(void) fprintf(stderr, message, va_arg(ap, char *));
		break;
	case SYS_LSEEK_02_ERROR:
	case SYS_LSEEK_03_ERROR:
		/* LINTED: variable format */
		(void) fprintf(stderr, message, va_arg(ap, int));
		break;
	/*
	 * Elf related errors
	 */
	case ELF_VERSION_ERROR:
	case ELF_INTERNAL_RAND_ERROR:
	case ELF_BEGIN_02_ERROR:
	case ELF_GETSCN_02_ERROR:
	case ELF_GETDATA_02_ERROR:
	case W_ELF_NO_DATA_02_ERROR:
	case ELF_RAWFILE_ERROR:
		/* LINTED: variable format */
		(void) fprintf(stderr, message);
		break;
	case ELF_BEGIN_01_ERROR:
	case ELF_GETSCN_01_ERROR:
	case ELF_GETDATA_01_ERROR:
	case W_ELF_NO_DATA_01_ERROR:
	case ELF_02_ERROR:
		/* LINTED: variable format */
		(void) fprintf(stderr, message, va_arg(ap, char *));
		break;
	case ELF_01_ERROR: {
		char	*a1, *a2;

		a1 = va_arg(ap, char *);
		a2 = va_arg(ap, char *);
		/* LINTED: variable format */
		(void) fprintf(stderr, message, a1, a2);
		break;
	}
	case ELF_MALARCHIVE_ERROR: {
		char	*a1;
		long	a2;

		a1 = va_arg(ap, char *);
		a2 = va_arg(ap, long);
		/* LINTED: variable format */
		(void) fprintf(stderr, message, a1, a2);
		break;
	}
	default:
		(void) fprintf(stderr, "internal error: error_message(%d)\n",
			mes);
		exit(100);
	}

	if (flag != PLAIN_ERROR)
		(void) fprintf(stderr, "\t%s\n", sys_mes);
	va_end(ap);
}
