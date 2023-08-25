/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


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
#include <stdlib.h>
#include <locale.h>

#include "com_err.h"
#include "error_table.h"

#if defined(_WIN32)
#include <io.h>
#endif

k5_mutex_t com_err_hook_lock = K5_MUTEX_PARTIAL_INITIALIZER;

static void default_com_err_proc
(const char  *whoami, errcode_t code,
	const char  *fmt, va_list ap);

#if defined(_WIN32)
BOOL  isGuiApp() {
	DWORD mypid;
	HANDLE myprocess;
	mypid = GetCurrentProcessId();
	myprocess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, mypid);
	return GetGuiResources(myprocess, 1) > 0;
	}
#endif

/*
 * Solaris Kerberos:
 * It is sometimes desirable to have more than a single hook called
 * when com_err() is invoked. A number of new functions have been
 * added which allow hooks to be added and removed:
 *    add_com_err_hook()
 *    add_default_com_err_hook()
 *    remove_com_err_hook()
 *    remove_default_com_err_hook()
 * The existing functions:
 *    set_com_err_hook()
 *    reset_com_err_hook()
 *    com_err()
 * have been modified to work with the new scheme. Applications using
 * the original function calls are not affected.
 */
#define	MAX_HOOKS 3
static et_old_error_hook_func com_err_hook[MAX_HOOKS] = { default_com_err_proc,
    NULL, NULL };
static int hook_count = 1;

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

static void default_com_err_proc (const char *whoami, errcode_t code,
				  const char *fmt, va_list ap)
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

void KRB5_CALLCONV com_err_va(const char *whoami,
			      errcode_t code,
			      const char *fmt,
			      va_list ap)
{
    int err;
    int i;
    err = com_err_finish_init();
    if (err)
	goto best_try;
    err = k5_mutex_lock(&com_err_hook_lock);
    if (err)
	goto best_try;
    for (i = 0; i < hook_count; i++) {
	(com_err_hook[i])(whoami, code, fmt, ap);
    }
    k5_mutex_unlock(&com_err_hook_lock);
    return;

best_try:
    /* Yikes.  Our library initialization failed or we couldn't lock
       the lock we want.  We could be in trouble.  Gosh, we should
       probably print an error message.  Oh, wait.  That's what we're
       trying to do.  In fact, if we're losing on initialization here,
       there's a good chance it has to do with failed initialization
       of the caller.  */

    for (i = 0; i < hook_count; i++) {
	(com_err_hook[i])(whoami, code, fmt, ap);
    }
    assert(err == 0);
    abort();
}


void KRB5_CALLCONV_C com_err(const char *whoami,
			     errcode_t code,
			     const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	com_err_va(whoami, code, fmt, ap);
	va_end(ap);
}

/* Make a separate function because the assert invocations below
   use the macro expansion on some platforms, which may be insanely
   long and incomprehensible.  */
static int com_err_lock_hook_handle(void)
{
    return k5_mutex_lock(&com_err_hook_lock);
}

et_old_error_hook_func set_com_err_hook (et_old_error_hook_func new_proc)
{
	int i;
	et_old_error_hook_func x;

	/* Broken initialization?  What can we do?  */
	assert(com_err_finish_init() == 0);
	assert(com_err_lock_hook_handle() == 0);

	x = com_err_hook[0];

	for (i = 0; i < hook_count; i++)
		com_err_hook[i] = NULL;

	com_err_hook[0] = new_proc;
	hook_count = 1;

	k5_mutex_unlock(&com_err_hook_lock);
	return x;
}

et_old_error_hook_func reset_com_err_hook ()
{
	int i;
	et_old_error_hook_func x;

	/* Broken initialization?  What can we do?  */
	assert(com_err_finish_init() == 0);
	assert(com_err_lock_hook_handle() == 0);
	x = com_err_hook[0];
	for (i = 0; i < hook_count; i++)
		com_err_hook[i] = NULL;

	com_err_hook[0] = default_com_err_proc;
	hook_count = 1;
	k5_mutex_unlock(&com_err_hook_lock);
	return x;
}

/*
 * Solaris Kerberos:
 * Register a hook which will be called every time
 * com_err() is called.
 */
void add_com_err_hook(et_old_error_hook_func f) {
	int i;
	if (hook_count < MAX_HOOKS) {
		for (i = 0; i < hook_count; i++) {
			if (com_err_hook[i] == NULL)
				break;
		}
		com_err_hook[i] = f;
		hook_count++;
	}
}

/*
 * Solaris Kerberos:
 * Remove a logging hook. The first hook matching 'f' will
 * be removed.
 */
void rem_com_err_hook(et_old_error_hook_func f) {
	int i, j;

	for (i = 0; i < hook_count; i++) {
		if (com_err_hook[i] == f) {
			for (j = i; j < hook_count - 1; j++) {
				com_err_hook[j] = com_err_hook[j+1];
			}
			com_err_hook[j] = NULL;
			hook_count--;
		}
	}
}

/*
 * Solaris Kerberos:
 * Remove the default hook.
 */
void rem_default_com_err_hook() {
	rem_com_err_hook(default_com_err_proc);
}

/*
 * Solaris Kerberos:
 * Add back the default hook
 */
void add_default_com_err_hook() {
	add_com_err_hook(default_com_err_proc);
}
