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


#include <nl_types.h>
#include <mms.h>
#include "msg_sub.h"

static char	*_SrcFile = __FILE__;

/*
 * Message Catalog Functions
 */

#define	MMS_MSG_CAT_FILE "mm.cat"
#define	MMS_MSG_CAT_PATH "/usr/lib/mms/"

static nl_catd mms_mm_msg_catd = (nl_catd)-1;

int
mms_msg_cat_open(void)
{
	/* open message catalog */
	mms_mm_msg_catd = catopen(MMS_MSG_CAT_FILE, NL_CAT_LOCALE);
	if (mms_mm_msg_catd == (nl_catd)-1 ||
	    mms_mm_msg_catd->__content == NULL) {
		if (mms_mm_msg_catd != (nl_catd)-1) {
			(void) catclose(mms_mm_msg_catd);
		}
		mms_mm_msg_catd = catopen(MMS_MSG_CAT_PATH MMS_MSG_CAT_FILE,
		    NL_CAT_LOCALE);
		if (mms_mm_msg_catd == (nl_catd)-1 ||
		    mms_mm_msg_catd->__content == NULL) {
			if (mms_mm_msg_catd != (nl_catd)-1) {
				(void) catclose(mms_mm_msg_catd);
			}
			return (1);
		}
	}
	return (0);
}

void
mms_msg_cat_close(void)
{
	if (mms_mm_msg_catd != (nl_catd)-1) {
		(void) catclose(mms_mm_msg_catd);
		mms_mm_msg_catd = (nl_catd)-1;
	}
}

char *
mms_get_cat_msg(int msgid)
{
	char	*fmt;

	if (mms_msg_cat_open()) {
		mms_trace(MMS_ERR, "mms_get_cat_msg: Unable to open mms "
		    "message catalog");
		return (NULL);
	}

	fmt = catgets(mms_mm_msg_catd, 1, msgid, "\0");

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

	mms_msg_cat_close();

		/* Get any arguments for message */
	if (arg = mms_pn_lookup(message, "arguments", MMS_PN_CLAUSE,
	    NULL)) {
			/* Substitue each argument with value in message */
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
