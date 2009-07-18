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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Error handling support for directory lookup.
 * Actually, this is intended to be a very generic and extensible error
 * reporting mechanism.
 */

#include <stdio.h>
#include <stdlib.h>
#include <thread.h>
#include <errno.h>
#include <stdarg.h>
#include <malloc.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <idmap_impl.h>
#include <rpcsvc/idmap_prot.h>
#include <libintl.h>
#include "directory.h"

/*
 * This is the actual implementation of the opaque directory_error_t structure.
 */
struct directory_error {
	/*
	 * True if this directory_error_t is statically allocated.  Used to
	 * handle out of memory errors during error reporting.
	 */
	boolean_t	is_static;

	/*
	 * The error code.  This is a locale-independent string that
	 * represents the precise error (to some level of granularity)
	 * that occurred.  Internationalization processing could map it
	 * to an message.  Errors may be subclassed by appending a dot
	 * and a name for the subclass.
	 *
	 * Note that this code plus the parameters allows for structured
	 * processing of error results.
	 */
	char		*code;

	/*
	 * The default (in the absence of internationalization) format for
	 * the error message.  %n interposes params[n - 1].
	 */
	char		*fmt;

	/*
	 * Parameters to the error message.  Note that subclasses are
	 * required to have the same initial parameters as their superclasses,
	 * so that code that processes the superclass can work on the subclass.
	 */
	int		nparams;
	char		**params;

	/*
	 * Cached printable form (that is, with params[] interpolated into
	 * fmt) of the error message.  Created when requested.
	 */
	char		*printable;
};

static directory_error_t directory_error_internal_error(int err);

/*
 * For debugging, reference count of directory_error instances still in
 * existence.  When the system is idle, this should be zero.
 * Note that no attempt is made to make this MT safe, so it is not reliable
 * in an MT environment.
 */
static int directory_errors_outstanding = 0;

/*
 * Free the specified directory_error_t.  Note that this invalidates all strings
 * returned based on it.
 *
 * Does nothing when de==NULL.
 */
void
directory_error_free(directory_error_t de)
{
	int i;

	if (de == NULL)
		return;

	/* Don't free our internal static directory_error_ts! */
	if (de->is_static)
		return;

	free(de->code);
	de->code = NULL;
	free(de->fmt);
	de->fmt = NULL;

	/* Free parameters, if any */
	if (de->params != NULL) {
		for (i = 0; i < de->nparams; i++) {
			free(de->params[i]);
			de->params[i] = NULL;
		}
		free(de->params);
		de->params = NULL;
	}

	/* Free cached printable */
	free(de->printable);
	de->printable = NULL;

	free(de);

	directory_errors_outstanding--;
}

/*
 * de = directory_error(code, fmt [, arg1 ... ]);
 * Code, fmt, and arguments must be strings and will be copied.
 */
directory_error_t
directory_error(const char *code, const char *fmt, ...)
{
	directory_error_t de = NULL;
	va_list va;
	int i;

	de = calloc(1, sizeof (*de));
	if (de == NULL)
		goto nomem;

	directory_errors_outstanding++;

	de->is_static = B_FALSE;

	de->code = strdup(code);
	if (de->code == NULL)
		goto nomem;

	de->fmt = strdup(fmt);
	if (de->fmt == NULL)
		goto nomem;

	/* Count our parameters */
	va_start(va, fmt);
	for (i = 0; va_arg(va, char *) != NULL; i++)
		/* LOOP */;
	va_end(va);

	de->nparams = i;

	/*
	 * Note that we do not copy the terminating NULL because we have
	 * a count.
	 */
	de->params = calloc(de->nparams, sizeof (char *));
	if (de->params == NULL)
		goto nomem;

	va_start(va, fmt);
	for (i = 0; i < de->nparams; i++) {
		de->params[i] = strdup((char *)va_arg(va, char *));
		if (de->params[i] == NULL) {
			va_end(va);
			goto nomem;
		}
	}
	va_end(va);

	return (de);

nomem:;
	int err = errno;
	directory_error_free(de);
	return (directory_error_internal_error(err));
}

/*
 * Transform a directory_error returned by RPC into a directory_error_t.
 */
directory_error_t
directory_error_from_rpc(directory_error_rpc *de_rpc)
{
	directory_error_t de;
	int i;

	de = calloc(1, sizeof (*de));
	if (de == NULL)
		goto nomem;

	directory_errors_outstanding++;

	de->is_static = B_FALSE;
	de->code = strdup(de_rpc->code);
	if (de->code == NULL)
		goto nomem;
	de->fmt = strdup(de_rpc->fmt);
	if (de->fmt == NULL)
		goto nomem;

	de->nparams = de_rpc->params.params_len;

	de->params = calloc(de->nparams, sizeof (char *));
	if (de->params == NULL)
		goto nomem;

	for (i = 0; i < de->nparams; i++) {
		de->params[i] = strdup(de_rpc->params.params_val[i]);
		if (de->params[i] == NULL)
			goto nomem;
	}

	return (de);

nomem:;
	int err = errno;
	directory_error_free(de);
	return (directory_error_internal_error(err));
}

/*
 * Convert a directory_error_t into a directory_error to send over RPC.
 *
 * Returns TRUE on successful conversion, FALSE on failure.
 *
 * Frees the directory_error_t.
 *
 * Note that most functions in this suite return boolean_t, as defined
 * by types.h.  This function is intended to be used directly as the
 * return value from an RPC service function, and so it returns bool_t.
 */
bool_t
directory_error_to_rpc(directory_error_rpc *de_rpc, directory_error_t de)
{
	int i;
	idmap_utf8str *params;

	de_rpc->code = strdup(de->code);
	if (de_rpc->code == NULL)
		goto nomem;

	de_rpc->fmt = strdup(de->fmt);
	if (de_rpc->fmt == NULL)
		goto nomem;

	params = calloc(de->nparams, sizeof (idmap_utf8str));
	if (params == NULL)
		goto nomem;
	de_rpc->params.params_val = params;
	de_rpc->params.params_len = de->nparams;

	for (i = 0; i < de->nparams; i++) {
		params[i] = strdup(de->params[i]);
		if (params[i] == NULL)
			goto nomem;
	}

	directory_error_free(de);
	return (TRUE);

nomem:
	logger(LOG_ERR, "Warning:  failed to convert error for RPC\n"
	    "Original error:  %s\n"
	    "Conversion error:  %s\n",
	    strerror(errno),
	    directory_error_printable(de));
	directory_error_free(de);
	return (FALSE);
}

/*
 * Determines whether this directory_error_t is an instance of the
 * particular error, or a subclass of that error.
 */
boolean_t
directory_error_is_instance_of(directory_error_t de, char *code)
{
	int len;

	if (de == NULL || de->code == NULL)
		return (B_FALSE);

	len = strlen(code);

	if (strncasecmp(de->code, code, len) != 0)
		return (B_FALSE);

	if (de->code[len] == '\0' || de->code[len] == '.')
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Expand the directory_error_t in de into buf, returning the size of the
 * resulting string including terminating \0.  If buf is NULL, just
 * return the size.
 *
 * Return -1 if there are no substitutions, so that the caller can
 * avoid memory allocation.
 */
static
int
directory_error_expand(char *buf, directory_error_t de)
{
	int bufsiz;
	boolean_t has_subst;
	const char *p;
	char c;
	long n;
	const char *s;
	char *newp;

	bufsiz = 0;
	has_subst = B_FALSE;

	for (p = dgettext(TEXT_DOMAIN, de->fmt); *p != '\0'; ) {
		c = *p++;
		if (c == '%') {
			has_subst = B_TRUE;
			if (isdigit(*p)) {
				n = strtol(p, &newp, 10);
				p = newp;
				if (de->params == NULL ||
				    n < 1 ||
				    n > de->nparams)
					s = dgettext(TEXT_DOMAIN, "(missing)");
				else
					s = de->params[n - 1];
				if (buf != NULL)
					(void) strcpy(buf + bufsiz, s);
				bufsiz += strlen(s);
				continue;
			}
		}
		if (buf != NULL)
			buf[bufsiz] = c;
		bufsiz++;
	}

	if (buf != NULL)
		buf[bufsiz] = '\0';
	bufsiz++;

	return (has_subst ? bufsiz : -1);
}

/*
 * Returns a printable version of this directory_error_t, suitable for
 * human consumption.
 *
 * The value returned is valid as long as the directory_error_t is valid,
 * and is freed when the directory_error_t is freed.
 */
const char *
directory_error_printable(directory_error_t de)
{
	char *s;
	int bufsiz;

	if (de->printable != NULL)
		return (de->printable);

	bufsiz = directory_error_expand(NULL, de);

	/*
	 * Short circuit case to avoid memory allocation when there is
	 * no parameter substitution.
	 */
	if (bufsiz < 0)
		return (dgettext(TEXT_DOMAIN, de->fmt));

	s = malloc(bufsiz);
	if (s == NULL) {
		return (dgettext(TEXT_DOMAIN,
		    "Out of memory while expanding directory_error_t"));
	}

	(void) directory_error_expand(s, de);

	/*
	 * Stash the expansion away for later free, and to short-circuit
	 * repeated expansions.
	 */
	de->printable = s;

	return (de->printable);
}

/*
 * Returns the error code for the particular error, as a string.
 * Note that this function should not normally be used to answer
 * the question "did error X happen", since the value returned
 * could be a subclass of X.  directory_error_is_instance_of is intended
 * to answer that question.
 *
 * The value returned is valid as long as the directory_error_t is valid,
 * and is freed when the directory_error_t is freed.
 */
const char *
directory_error_code(directory_error_t de)
{
	return (de->code);
}

/*
 * Returns one of the parameters of the directory_error_t, or NULL if
 * the parameter does not exist.
 *
 * Note that it is required that error subclasses have initial parameters
 * the same as their superclasses.
 *
 * The value returned is valid as long as the directory_error_t is valid,
 * and is freed when the directory_error_t is freed.
 */
const char *
directory_error_param(directory_error_t de, int param)
{
	if (param >= de->nparams)
		return (NULL);
	return (de->params[param]);
}

/*
 * Here are some (almost) constant directory_error_t structures
 * for use in reporting errors encountered while creating a
 * directory_error_t structure.  Unfortunately, the original error
 * report is lost.
 */
#define	gettext(x)	x	/* let xgettext see these messages */
static struct directory_error directory_error_ENOMEM = {
	B_TRUE,
	"ENOMEM.directory_error_t",
	gettext("Out of memory while creating a directory_error_t"),
	0, NULL,
	NULL,
};

static struct directory_error directory_error_EAGAIN = {
	B_TRUE,
	"EAGAIN.directory_error_t",
	gettext("Out of resources while creating a directory_error_t"),
	0, NULL,
	NULL,
};

/* 40 is big enough for even 128 bits */
static char directory_error_unknown_errno[40] = "0";
static char *directory_error_unknown_params[] = {
    directory_error_unknown_errno
};
static struct directory_error directory_error_unknown = {
	B_TRUE,
	"Unknown.directory_error_t",
	gettext("Unknown error (%1) while creating a directory_error_t"),
	1, directory_error_unknown_params,
	NULL,
};
#undef	gettext

static
directory_error_t
directory_error_internal_error(int err)
{
	switch (err) {
	case ENOMEM:	return (&directory_error_ENOMEM);
	case EAGAIN:	return (&directory_error_EAGAIN);
	default:
		/* Pray that we don't have a reentrancy problem ... */
		(void) sprintf(directory_error_unknown_errno, "%u", err);
		return (&directory_error_unknown);
	}
}
