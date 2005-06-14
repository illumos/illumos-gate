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

#ifndef	_ERRMSG_H
#define	_ERRMSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	ERR_USAGE \
	"Usage: %s [-D dir | --directory=dir] [-f | --use-fuzzy]\n" \
	"               [-g] [-o outfile | --output-file=outfile]\n" \
	"               [--strict] [-v | --verbose] files ...\n"
#define	ERR_SUN_ON_GNU \
	"-s option cannot be specified to %s.\n"

#define	ERR_PRIME \
	"Internal error: no prime number under 1100 found for %d.\n"

#define	ERR_ERROR_FOUND \
	"%d error(s) found.\n"

#define	ERR_INVALID_CHAR \
	"Line %d (%s): Invalid character found.\n"

#define	ERR_INTERNAL \
	"Line %d (%s): Internal error.\n"

#define	ERR_LOCATION \
	"Line %d (%s): "

#define	ERR_NO_MSGSTR \
	"Line %d (%s): missing \"msgstr\" corresponding to \"msgid\".\n"

#define	ERR_NO_MSGSTRS \
	"Line %d (%s): missing \"msgstr[]\" corresponding to \"msgid\".\n"

#define	ERR_NO_MSGID_PLURAL \
	"Line %d (%s): missing \"msgid_plural\" corresponding to \"msgid\".\n"

#define	ERR_INVALID_PLURALS \
	"Line %d (%s): invalid index for \"msgstr[]\".\n"

#define	ERR_UNEXP_EOF \
	"Line %d (%s): unexpected EOF found.\n"

#define	ERR_UNEXP_EOL \
	"Line %d (%s): unexpected EOL found.\n"

#define	ERR_DUP_ENTRIES \
	"Lines %d (%s), %d (%s): " \
	"duplicate \"msgid\" entries found.\n"

#define	ERR_BEGIN_NEWLINE_1 \
	"Lines %d, %d (%s): \"msgid\" begins with newline, " \
	"but \"msgstr\" doesn't.\n"

#define	ERR_BEGIN_NEWLINE_2 \
	"Lines %d, %d (%s): \"msgstr\" begins with newline, " \
	"but \"msgid\" doesn't.\n"

#define	ERR_BEGIN_NEWLINE_3 \
	"Lines %d, %d (%s): \"msgid\" begins with newline, " \
	"but \"msgid_plural\" doesn't.\n"

#define	ERR_BEGIN_NEWLINE_4 \
	"Lines %d, %d (%s): \"msgid_plural\" begins with newline, " \
	"but \"msgid\" doesn't.\n"

#define	ERR_BEGIN_NEWLINE_5 \
	"Lines %d, %d (%s): \"msgid\" begins with newline, " \
	"but \"msgidstr[%d]\" doesn't.\n"

#define	ERR_BEGIN_NEWLINE_6 \
	"Lines %d, %d (%s): \"msgstr[%d]\" begins with newline, " \
	"but \"msgid\" doesn't.\n"

#define	ERR_END_NEWLINE_1 \
	"Lines %d, %d (%s): \"msgid\" ends with newline, " \
	"but \"msgstr\" doesn't.\n"

#define	ERR_END_NEWLINE_2 \
	"Lines %d, %d (%s): \"msgstr\" ends with newline, " \
	"but \"msgid\" doesn't.\n"

#define	ERR_END_NEWLINE_3 \
	"Lines %d, %d (%s): \"msgid\" ends with newline, " \
	"but \"msgid_plural\" doesn't.\n"

#define	ERR_END_NEWLINE_4 \
	"Lines %d, %d (%s): \"msgid_plural\" ends with newline, " \
	"but \"msgid\" doesn't.\n"

#define	ERR_END_NEWLINE_5 \
	"Lines %d, %d (%s): \"msgid\" ends with newline, " \
	"but \"msgstr[%d]\" doesn't.\n"

#define	ERR_END_NEWLINE_6 \
	"Lines %d, %d (%s): \"msgstr[%d]\" ends with newline, " \
	"but \"msgid\" doesn't.\n"

#define	ERR_INVALID_FMT \
	"Lines %d (%s): invalid printf-format.\n"

#define	ERR_INCMP_FMT \
	"Lines %d, %d (%s): incompatible printf-format.\n"

#define	ERR_INCMP_FMT_DIFF_1 \
	"     %d format specifier(s) in \"msgid\", but " \
	"%d format specifier(s) in \"msgstr\".\n"

#define	ERR_INCMP_FMT_DIFF_2 \
	"     format specifier mismatch in the argument (#%d).\n"

#define	WARN_NOCHARSET \
	"Line %d (%s): charset specification is missing " \
	"in the header entry.\n" \
	"Using the default charset.\n"

#define	WARN_NOCONV \
	"Line %d (%s): No iconv conversion from \"%s\" to \"%s\" is " \
	"supported.\n" \
	"Using the default charset.\n"

#define	WARN_DUP_ENTRIES \
	"Lines %d (%s), %d (%s): " \
	"duplicate \"msgid\" and \"msgstr\" entries found.\n"

#define	DIAG_IGNORE_DOMAIN \
	"Line %d (%s): `domain %s' directive ignored.\n"

#define	DIAG_RESULTS \
	"%d translated message(s), %d fuzzy translation(s), " \
	"%d untranslated message(s).\n"

#ifdef	__cplusplus
}
#endif

#endif	/* _ERRMSG_H */
