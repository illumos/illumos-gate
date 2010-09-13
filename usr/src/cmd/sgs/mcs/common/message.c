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
 *	Copyright(c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include "mcs.h"

static const char *msg[] = {
/* MALLOC_ERROR */
"%s: malloc memory allocation failure.\n",
/* USAGE_ERROR */
"%s: multiple -n only allowed for -d option.\n",
/* ELFVER_ERROR */
"%s: elf_version() failed - libelf.a out of date.\n",
/* OPEN_ERROR */
"%s: %s: cannot open file.\n",
/* LIBELF_ERROR */
"%s: libelf error.\n",
/* OPEN_TEMP_ERROR */
"%s: %s: cannot open temporary file\n",
/* WRITE_ERROR */
"%s: %s: write system failure: %s: file not manipulated.\n",
/* GETARHDR_ERROR */
"%s: %s: malformed archive at %ld\n",
/* FILE_TYPE_ERROR */
"%s: %s: invalid file type\n",
/* NOT_MANIPULATED_ERROR */
"%s: %s: file not manipulated\n",
/* WRN_MANIPULATED_ERROR */
"%s: WARNING: %s: Cannot manipulate file.\n",
/* NO_SECT_TABLE_ERROR */
"%s: %s: no section header table.\n",
/* READ_ERROR */
"%s: %s: trouble reading file\n",
/* READ_MANI_ERROR */
"%s: %s: read system failure: %s: file not manipulated.\n",
/* WRITE_MANI_ERROR */
"%s: %s: write system failure: %s: file not manipulated.\n",
/* LSEEK_MANI_ERROR */
"%s: %s: lseek system failure: %s: file not manipulated.\n",
/* SYM_TAB_AR_ERROR */
"%s: WARNING: %s: symbol table deleted from archive \n",
/* EXEC_AR_ERROR */
"execute  `ar -ts %s` to restore symbol table.\n",
/* READ_SYS_ERROR */
"%s: %s: read system failure\n",
/* OPEN_WRITE_ERROR */
"%s: %s: can't open file for writing\n",
/* ACT_PRINT_ERROR */
"%s: %s: Cannot print contents of a NOBITS section (%s)\n",
/* ACT_DELETE1_ERROR */
"%s: %s: Warning: Cannot delete section (%s)\n\t\tfrom a segment.\n",
/* ACT_DELETE2_ERROR */
"%s: %s: Warning: Cannot delete section (%s)\n"
"\t\tbecause its relocation section (%s) is in a segment\n",
/* ACT_APPEND1_ERROR */
"%s: %s: Cannot append to a NOBITS section (%s)\n",
/* ACT_APPEND2_ERROR */
"%s: %s: Warning: Cannot append to section (%s)\n\t\tin a segment\n",
/* ACT_COMPRESS1_ERROR */
"%s: %s: Cannot compress a NOBITS section (%s)\n",
/* ACT_COMPRESS2_ERROR */
"%s: %s: Warning: Cannot compress a section (%s)\n\t\tin a segment\n",
/* ACCESS_ERROR */
"%s: %s: access error.\n",
/* WRITE_MANI_ERROR2 */
"%s: /ftruncate/lseek/write system failure: %s: file may be destroyed.\n"
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
	case USAGE_ERROR:
	case ELFVER_ERROR:
	case EXEC_AR_ERROR:
	case LIBELF_ERROR:
		/* LINTED */
		(void) fprintf(stderr, message, va_arg(ap, char *));
		break;
	case OPEN_ERROR:
	case ACCESS_ERROR:
	case OPEN_TEMP_ERROR:
	case FILE_TYPE_ERROR:
	case NOT_MANIPULATED_ERROR:
	case WRN_MANIPULATED_ERROR:
	case NO_SECT_TABLE_ERROR:
	case READ_ERROR:
	case SYM_TAB_AR_ERROR:
	case READ_SYS_ERROR:
	case OPEN_WRITE_ERROR:
		/* LINTED */
		(void) fprintf(stderr, message, va_arg(ap, char *),
		    va_arg(ap, char *));
		break;
	case WRITE_ERROR:
	case READ_MANI_ERROR:
	case WRITE_MANI_ERROR:
	case LSEEK_MANI_ERROR:
	case ACT_PRINT_ERROR:
	case ACT_DELETE1_ERROR:
	case ACT_APPEND1_ERROR:
	case ACT_APPEND2_ERROR:
	case ACT_COMPRESS1_ERROR:
	case ACT_COMPRESS2_ERROR: {
		char *a = va_arg(ap, char *);
		char *b = va_arg(ap, char *);
		char *c = va_arg(ap, char *);
		/* LINTED */
		(void) fprintf(stderr, message, a, b, c);
		break;
	}
	case ACT_DELETE2_ERROR: {
		char *a = va_arg(ap, char *);
		char *b = va_arg(ap, char *);
		char *c = va_arg(ap, char *);
		char *d = va_arg(ap, char *);
		/* LINTED */
		(void) fprintf(stderr, message, a, b, c, d);
		break;
	}
	case GETARHDR_ERROR: {
		char *a = va_arg(ap, char *);
		char *b = va_arg(ap, char *);
		long c = va_arg(ap, long);
		/* LINTED */
		(void) fprintf(stderr, message, a, b, c);
		break;
	}
	default:
		(void) fprintf(stderr, "internal error: error_message(%d)\n",
		    mes);
		mcs_exit(100);
	}

	if (flag != PLAIN_ERROR)
		(void) fprintf(stderr, "\t%s\n", sys_mes);
	va_end(ap);
}
