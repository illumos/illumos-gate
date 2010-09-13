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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SUN_MSGFMT_H
#define	_SUN_MSGFMT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <locale.h>
#include <stdio.h>
#include <wchar.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <malloc.h>
#include <libintl.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "../../lib/libc/inc/msgfmt.h"
#include "common.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DOMAIN_TOKEN	L"domain"	/* domain token in po file  */
#define	DOMAIN_LEN	6
#define	MSGID_TOKEN	L"msgid"	/* msg id token in po file  */
#define	MSGID_LEN	5
#define	MSGSTR_TOKEN	L"msgstr"	/* target str token in po file */
#define	MSGSTR_LEN	6

#ifdef	DEBUG_MMAP
#define	MAX_VALUE_LEN		3	/* size of msg id and target str */
#define	LINE_SIZE	1
#else
#define	MAX_VALUE_LEN		512	/* size of msg id and target str */
#define	LINE_SIZE	512
#endif

/*
 * check if the next character is possible valid character.
 */
#define	CK_NXT_CH(a, l)	\
	((a[(l) - 1] == L' ') || (a[(l) - 1] == L'\t') || \
	(a[(l) - 1] == L'\n') || (a[(l) - 1] == L'\0'))

struct msg_chain {
	char	*msgid;		/* msg id string */
	char	*msgstr;	/* msg target string */
	int	msgid_offset;	/* msg id offset in mo file */
	int	msgstr_offset;	/* msg target string offset in mo file */
	struct  msg_chain *next;	/* next node */
};

struct  domain_struct {
	char			*domain;	/* domain name */
	struct msg_chain	*first_elem;	/* head of msg link list */
	struct msg_chain	*current_elem;	/* most recently used msg */
	struct domain_struct	*next;		/* next domain node */
};

#define	ERR_EXEC_FAILED \
	"failed to execute %s.\n"

#define	ERR_USAGE \
	"Usage: msgfmt [-D dir | --directory=dir] [-f | --use-fuzzy]\n" \
	"               [-g] [-o outfile | --output-file=outfile]\n" \
	"               [-s] [--strict] [-v] [--verbose] files ...\n"

#define	ERR_GNU_ON_SUN \
	"-g and -s are mutually exclusive.\n"

#define	ERR_STAT_FAILED \
	"stat failed for %s.\n"

#define	ERR_MMAP_FAILED \
	"mmap failed for %s.\n"

#define	ERR_MUNMAP_FAILED \
	"munmap failed for %s.\n"

#define	ERR_NOSPC \
	"Error, No space after directive at line number %d.\n"

#define	ERR_EXITING \
	"Exiting...\n"

#define	WARN_NO_MSGSTR \
	"Consecutive MSGID tokens " \
	"encountered at line number: %d, ignored.\n"

#define	WARN_NO_MSGID \
	"Consecutive MSGSTR tokens " \
	"encountered at line number: %d, ignored.\n"

#define	WARN_SYNTAX_ERR \
	"Syntax at line number: %d, " \
	"line ignored\n"

#define	WARN_MISSING_QUOTE \
	"Syntax at line number: %d, " \
	"Missing \", ignored\n"

#define	WARN_MISSING_QUOTE_AT_EOL \
	"Syntax at line number: %d, " \
	"Missing \" at EOL, ignored\n"

#define	WARN_INVALID_STRING \
	"the string after closing \" " \
	"is ignored at line number %d.\n"

#define	WARN_DUP_MSG \
	"Duplicate id \"%s\" at line number: " \
	"%d, line ignored\n"

#define	DIAG_GNU_FOUND \
	"GNU PO file found.\n"

#define	DIAG_INVOKING_GNU \
	"Generating the MO file in the GNU MO format.\n"

#ifdef	__cplusplus
}
#endif

#endif /* _SUN_MSGFMT_H */
