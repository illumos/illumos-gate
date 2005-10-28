/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1997 by Massachusetts Institute of Technology
 *
 * Copyright 1987, 1988 by MIT Student Information Processing Board
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purpose and without fee is
 * hereby granted, provided that the above copyright notice
 * appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation,
 * and that the names of M.I.T. and the M.I.T. S.I.P.B. not be
 * used in advertising or publicity pertaining to distribution
 * of the software without specific, written prior permission.
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. and the M.I.T. S.I.P.B. make no representations about
 * the suitability of this software for any purpose.  It is
 * provided "as is" without express or implied warranty.
 */


#include <stdio.h>
#include <string.h>
#include <locale.h>

#include "com_err.h"
#include "error_table.h"

#if defined(_MSDOS) || defined(_WIN32)
#include <io.h>
#endif
#ifdef macintosh
#include "icons.h"
static void MacMessageBox(char *errbuf);
#endif

static et_old_error_hook_func com_err_hook = 0;

static void default_com_err_proc
(const char  *whoami, errcode_t code,
	const char  *fmt, va_list ap);

/* Solaris Kerberos specific fix start --------------------------- */

#define gettext(X)	X

struct msg_map {
	char *msgid;
	char *c_msgstr;
};

struct msg_map msgmap[] = {

#define	MSG_WHILE 0
	{ gettext("%s\n## com_err msg of format: 'while ...'"),
		"%s\n" },

#define	MSG_ERROR_MSG 1
	{ gettext("%s\n## com_err message of format: 'error msg ...'"),
		"%s\n" },

#define	MSG_ERROR_MSG_WHILE 2
	{ gettext("%1$s %2$s\n## com_err message of format: "
		"'error msg ... while ...'"),
		"%1$s %2$s\n" },

#define	MSG_WHOAMI_WHILE 3
	{ gettext("%1$s: %2$s\n## com_err msg of format: 'whoami: while ...'"),
		"%1$s: %2$s\n" },

#define	MSG_WHOAMI_ERROR_MSG 4
	{ gettext("%1$s: %2$s\n## com_err message of format: "
		"'whoami: error msg ...'"),
		"%1$s: %2$s\n" },

#define	MSG_WHOAMI_ERROR_MSG_WHILE 5
	{ gettext("%1$s: %2$s %3$s\n## com_err message of format: "
		"'whoami: error msg ... while ...'"),
		"%1$s: %2$s %3$s\n" },

#define	MSG_WHOAMI 6
	{ gettext("%s:\n ## com_err message of format: "
		"'whoami: with no error msg or while ...'"),
		"%s:\n " }
};

#undef gettext

/*
 * The idea is that we provide a unique message id that contains extra junk
 * that we never want to display in the C locale. If dgettext() returns
 * a string that is equal to the message id, then we return the c_msgstr,
 * for display in the locale.
 */
static char *
my_gettext(int msg_idx)
{
	char *msgid = msgmap[msg_idx].msgid;
	char *c_msgstr = msgmap[msg_idx].c_msgstr;
	char *msgstr = dgettext(TEXT_DOMAIN, msgid);

	if (strcmp(msgstr, msgid) == 0)
		return (c_msgstr);
	else
		return (msgstr);
}

/* Solaris Kerberos specific fix end --------------------------- */

/* Solaris Kerberos:  this code is significantly altered from
 * the MIT 1.2.1 version to work with internationalization */
static void default_com_err_proc(whoami, code, fmt, ap)
	const char  *whoami;
	errcode_t code;
	const char  *fmt;
	va_list ap;
{
	char whilebuf[1024] = "";

	*whilebuf = '\0';

	/*
	 * Because 'while ...' message could contain a format string
	 * we have to intepret it now, in a buffer. We need to put it
	 * into a buffer so that the message can be juxtaposed in a locale
	 * meaningful manner. In some natural languages, the 'while ...' phrase
	 * must be first.
	 */
	if (fmt) {
		vsprintf(whilebuf, fmt, ap);
	}

	/*
	 * There are 8 possible combinations here depending on whether
	 * a whoami string was provided, error code is non-zero, and if a
	 * a 'while ...' messge was provided.
	 */
	if (!whoami) {

		if ((!code) && fmt) {

			fprintf(stderr, my_gettext(MSG_WHILE),
				whilebuf);

		} else if (code && !fmt) {

			fprintf(stderr, my_gettext(MSG_ERROR_MSG),
				error_message(code));

		} else if (code && fmt) {

			fprintf(stderr, my_gettext(MSG_ERROR_MSG_WHILE),
				error_message(code), whilebuf);
		} else
			return;

	} else {

		if ((!code) && fmt) {

			fprintf(stderr, my_gettext(MSG_WHOAMI_WHILE),
				whoami, whilebuf);

		} else if (code && !fmt) {

			fprintf(stderr, my_gettext(MSG_WHOAMI_ERROR_MSG),
				whoami, error_message(code));

		} else if (code && fmt) {

			fprintf(stderr,
				my_gettext(MSG_WHOAMI_ERROR_MSG_WHILE),
				whoami, error_message(code), whilebuf);
		} else {

			fprintf(stderr,
				my_gettext(MSG_WHOAMI),
				whoami);
		}
	}

	fflush(stderr);
}

void KRB5_CALLCONV com_err_va(whoami, code, fmt, ap)
	const char  *whoami;
	errcode_t code;
	const char  *fmt;
	va_list ap;
{
	if (!com_err_hook)
		default_com_err_proc(whoami, code, fmt, ap);
	else
	  (com_err_hook)(whoami, code, fmt, ap);
}


#ifndef ET_VARARGS
void KRB5_CALLCONV_C com_err(const char  *whoami,
					 errcode_t code,
					 const char  *fmt, ...)
#else
void KRB5_CALLCONV_C com_err(whoami, code, fmt, va_alist)
	const char  *whoami;
	errcode_t code;
	const char  *fmt;
	va_dcl
#endif
{
	va_list ap;

#ifdef ET_VARARGS
	va_start(ap);
#else
	va_start(ap, fmt);
#endif
	com_err_va(whoami, code, fmt, ap);
	va_end(ap);
}

#if !(defined(_MSDOS)||defined(_WIN32))
et_old_error_hook_func set_com_err_hook (new_proc)
	et_old_error_hook_func new_proc;
{
	et_old_error_hook_func x = com_err_hook;

	com_err_hook = new_proc;
	return x;
}

et_old_error_hook_func reset_com_err_hook ()
{
	et_old_error_hook_func x = com_err_hook;

	com_err_hook = 0;
	return x;
}
#endif
