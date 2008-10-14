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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libintl.h>
#include <locale.h>
#include <sys/varargs.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "mms_parser.h"
#include "mms_strapp.h"
#include "mms_trace.h"
#include "mms_sym.h"
#include "msg_sub.h"
#include "mms_cat.h"

static char	*_SrcFile = __FILE__;

/*
 * Message Catalog
 */


/*
 * Gettext is not redefined here so the C preprocessor output from
 * this file can be used for mms message catalog generation. The
 * MMS_CAT define is a C preprocessor flag.
 */
#ifndef MMS_CAT
#define	gettext(s) s
#endif

/*
 * Get the messsageids and message format strings when the message
 * header files are included below.
 */
#define	MM_MSG(n, s)		s, n,
#define	MMS_API_MSG(n, s)	s, n,
#define	WCR_MSG(n, s)		s, n,
#define	DM_MSG(n, s)		s, n,
#define	LM_MSG(n, s)		s, n,

/*
 * Message array used to lookup a message format string by messageid.
 */
static mms_sym_t	_mms_msg_cat[] = {
/*
 * Message header files
 */
#include <mms_mm_msg.h>
#include <mms_api_msg.h>
#include <mms_wcr_msg.h>
#include <mms_dm_msg.h>
#include <mms_lm_msg.h>
	NULL, 0
};

/*
 * Gettext is once again used to localize the message format string.
 */
#ifndef MMS_CAT
#undef gettext
#endif

static mms_sym_t	*mms_msg_cat = _mms_msg_cat;
static int	mms_msg_cat_num = sizeof (_mms_msg_cat) / sizeof (mms_sym_t);

void
mms_cat_open(void)
{
	/*
	 * Locale is "C" so the API, WCR, DM and LM use the
	 * English (EN) language. MM will reset locale based
	 * on client application preference.
	 */
	(void) setlocale(LC_MESSAGES, "C");

	/*
	 * Set the message catalog file name.
	 */
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Sort the message format strings.
	 */
	mms_sort_sym_code(mms_msg_cat, mms_msg_cat_num);
}

char *
mms_get_cat_msg(int msgid)
{
	mms_sym_t	*mms_sym;
	char		*fmt;

	mms_sym = mms_lookup_sym_code(msgid, mms_msg_cat, mms_msg_cat_num);
	if (mms_sym != NULL && mms_sym->sym_token != NULL) {
		fmt = gettext(mms_sym->sym_token);
	} else {
		fmt = NULL;
	}

	return (fmt);
}

char *
mms_get_msg(mms_par_node_t *message)
{
	int	msgid;

	char	*p;
	char	*fmt;
	char	*text = NULL;
	char	*man;
	char	*model;
	char	err_msg[128];

	mms_par_node_t	*clause;
	mms_par_node_t	*arg;
	mms_par_node_t	*name;
	mms_par_node_t	*value;
	mms_par_node_t	*loc;

	/*
	 * Parse and localize command's message-clause
	 */

	MMS_PN_LOOKUP(arg, message, "id", MMS_PN_CLAUSE, NULL);
	loc = NULL;
	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_STRING, &loc);
	man = value->pn_string;

	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_STRING, &loc);
	model = value->pn_string;

	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_STRING, &loc);
	msgid = atoi(value->pn_string);


	/* lookup localized message */
	fmt = mms_get_cat_msg(msgid);
	if (fmt == NULL || fmt[0] == '\0') {
			/* No message found in catalog, obtain loctext */
			/* if one exists and output it */
		goto get_loctext;
	}

		/* Make copy so args can be substituted */
	text = strdup(fmt);

		/* Get any arguments for message */
	if (arg = mms_pn_lookup(message, "arguments", MMS_PN_CLAUSE,
	    NULL)) {
			/* Substitute each argument with value in message */
		mms_list_pair_foreach(&arg->pn_arglist, name, value) {

			if (name == NULL || value == NULL)
				goto get_loctext;

			if ((p = mms_msg_sub(text, name->pn_string,
			    value->pn_string)) == NULL) {
				mms_trace(MMS_ERR, "mms_get_msg: message "
				    "argument substitution failed");
				free(text);
				goto get_loctext;
			}
			free(text);
			text = p;
		}
	}

	mms_trace(MMS_DEBUG,
	    "mms_get_msg: %s %s %d - %s", man, model, msgid, text);
	return (text);

not_found:
	mms_trace(MMS_ERR, "mms_get_msg: Missing components to message clause");
	return (NULL);

get_loctext:
	clause = mms_pn_lookup(message, "loctext", MMS_PN_CLAUSE, NULL);
	if (clause != NULL) {
		loc = NULL;
		value = mms_pn_lookup(clause, NULL, MMS_PN_STRING, &loc);
		value = mms_pn_lookup(clause, NULL, MMS_PN_STRING, &loc);
		if (value != NULL) {
			if ((text = value->pn_string) != NULL) {
				mms_trace(MMS_OPER, "mms_get_msg: loctext "
				    "message is:\n%s", text);
				return (text);
			}
		}
	}
	mms_trace(MMS_OPER, "mms_get_msg: No message found in catalog and "
	    "no loctext found in message");
	(void) snprintf(err_msg, sizeof (err_msg),
	    "Unknown Message: Manufacturer: %s, Model: %s, "
	    "Messageid: %d", man, model, msgid);
	text = strdup(err_msg);
	return (text);
}

static char *
mms_get_locale(char *locale, int len)
{
	char	*lang;
	int	i;

	locale[0] = '\0';
	lang = setlocale(LC_MESSAGES, NULL);
	if (lang == NULL || lang[0] == 'C') {
		(void) snprintf(locale, len, "EN");
	} else {
		for (i = 0; i < len - 1 && islower(lang[i]); i++) {
			locale[i] = (char)toupper(lang[i]);
			locale[i+1] = '\0';
		}
	}
	return (locale);
}

char *
mms_get_msgcl(int msgid, ...)
{
	char	*msg;
	va_list	args;

	va_start(args, msgid);
	msg = mms_bld_msgcl(msgid, args);
	va_end(args);
	return (msg);
}

char *
mms_buf_msgcl(char *buf, int len, int msgid, ...)
{
	char	*msg;
	va_list	args;

	if (buf != NULL && len > 0) {
		va_start(args, msgid);
		msg = mms_bld_msgcl(msgid, args);
		va_end(args);

		buf[0] = '\0';
		if (msg != NULL) {
			(void) snprintf(buf, len, "%s", msg);
			free(msg);
		}
	}
	return (buf);
}

char *
mms_bld_msgcl(int msgid, va_list args)
{
	char		*msgcl = NULL;
	char		*msgfmt;
	char		*arg_key;
	char		*arg_text;
	char		*loctext = NULL;
	char		*argcl = NULL;
	char		*arglist = NULL;
	va_list		argscp;
	char		lang[20];

	/*
	 * Get language
	 */
	(void) mms_get_locale(lang, sizeof (lang));

	/*
	 * Get message format string
	 */
	msgfmt = mms_get_cat_msg(msgid);
	if (msgfmt == NULL || msgfmt[0] == '\0') {
		/* Undefined message */
		mms_trace(MMS_ERR, "Undefined message id '%d'", msgid);
		return (msgcl);
	}

	/*
	 * Create argument list
	 */
	va_copy(argscp, args);
	while ((arg_key = va_arg(argscp, char *)) != NULL) {
		if ((arg_text = va_arg(argscp, char *)) == NULL) {
			break;
		}
		arglist = mms_strapp(arglist, "'%s' '%s' ", arg_key, arg_text);
	}
	va_end(argscp);

	if (arglist) {
		argcl = mms_strnew("arguments [ %s ] ", arglist);
		free(arglist);
	} else {
		argcl = strdup("");
	}

	/*
	 * Localize message
	 */
	if ((loctext = mms_get_locstr(msgid, args)) == NULL) {
		loctext = strdup("\0");
	}

	/*
	 * Build message clause
	 */
	msgcl = mms_strapp(msgcl, "message [ id [ 'SUNW' 'MMS' '%d' ] %s "
	    "loctext [ '%s' '%s' ]] ", msgid, argcl, lang, loctext);
	free(argcl);
	free(loctext);
	return (msgcl);
}

char *
mms_get_locstr(int msgid, va_list args)
{
	char	*s1;
	char	*s2;
	char	*arg_key;
	char	*arg_text;
	char	*msgfmt;

	/*
	 * Get localized message format string.
	 */
	msgfmt = mms_get_cat_msg(msgid);
	if (msgfmt == NULL || msgfmt[0] == '\0') {
		/* Undefined message */
		mms_trace(MMS_ERR, "Undefined message id '%d'", msgid);
		return (NULL);
	}

	/*
	 * Substitute message arguments into message format string
	 * to create a localized message string.
	 */
	s1 = strdup(msgfmt);
	while ((arg_key = va_arg(args, char *)) != NULL) {
		if ((arg_text = va_arg(args, char *)) == NULL) {
			break;
		}
		s2 = mms_msg_sub(s1, arg_key, arg_text);
		free(s1);
		s1 = s2;
	}
	return (s1);
}
