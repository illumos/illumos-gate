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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * From	"tsol_tndb_parser.c	7.24	01/09/05 SMI; TSOL 2.x"
 *
 * These functions parse entries in the "tnrhtp" (remote host template) file.
 * Each entry in this file has two fields, separated by a colon.  The first
 * field is the template name.  The second is a list of "key=value" attributes,
 * separated by semicolons.
 *
 * In order to help preserve sanity, we do not allow more than one unescaped
 * colon in a line, nor any unescaped '=' or ';' characters in the template
 * name.  Such things are indicative of typing errors, not intentional
 * configuration.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <libtsnet.h>
#include <tsol/label.h>
#include <sys/tsol/label_macro.h>
#include <sys/types.h>
#include <nss.h>
#include <secdb.h>
#include <errno.h>

static int
get_tn_doi(tsol_tpent_t *tpentp, kva_t *kv)
{
	char	*cp;
	char	*val = NULL;

	val = kva_match(kv, TP_DOI);
	if (val == NULL)
		return (LTSNET_NO_DOI);

	errno = 0;
	tpentp->tp_doi = strtol(val, &cp, 0);
	if (errno != 0)
		return (LTSNET_SYSERR);
	if (*cp != '\0')
		return (LTSNET_ILL_DOI);

	return (0);
}

static int
get_tn_sl_range(brange_t *range, char *min, char *max)
{
	int	err = 0;

	if (min == NULL && max == NULL)
		return (LTSNET_NO_RANGE);
	if (min == NULL)
		return (LTSNET_NO_LOWERBOUND);
	if (max == NULL)
		return (LTSNET_NO_UPPERBOUND);

	if (stobsl(min, &range->lower_bound, NO_CORRECTION, &err) == 0)
		return (LTSNET_ILL_LOWERBOUND);
	if (stobsl(max, &range->upper_bound, NO_CORRECTION, &err) == 0)
		return (LTSNET_ILL_UPPERBOUND);
	if (!bldominates(&range->upper_bound, &range->lower_bound))
		return (LTSNET_ILL_RANGE);

	return (0);
}

static int
get_tn_sl_set(blset_t *labelset, char *setstr)
{
	int		sc, err;
	char		*tokp, *finally;
	bslabel_t	*labels;

	(void) memset(labelset, 0, sizeof (blset_t));
	labels = (bslabel_t *)labelset;
	tokp = strtok_r(setstr, TNDB_COMMA, &finally);
	for (sc = 0; tokp != NULL && sc < NSLS_MAX; sc++) {
		if (stobsl(tokp, &labels[sc], NO_CORRECTION, &err) == 0)
			return (LTSNET_ILL_LABEL);
		tokp = strtok_r(NULL, TNDB_COMMA, &finally);
	}
	if (tokp != NULL && sc >= NSLS_MAX)
		return (LTSNET_SET_TOO_BIG);

	return (0);
}

static int
parse_remainder(tsol_tpent_t *tpentp, kva_t *kv)
{
	int	err = 0;
	char	*val = NULL;
	char	*val2 = NULL;

	val = kva_match(kv, TP_HOSTTYPE);

	if (val == NULL)
		return (LTSNET_NO_HOSTTYPE);
	if (strcasecmp(val, TP_UNLABELED) == 0)
		tpentp->host_type = UNLABELED;
	else if (strcasecmp(val, TP_CIPSO) == 0)
		tpentp->host_type = SUN_CIPSO;
	else
		return (LTSNET_ILL_HOSTTYPE);

	/*
	 * parse fields by host type -
	 * add on to the following if statement for each new host type.
	 */
	if (tpentp->host_type == UNLABELED) {
		tpentp->tp_mask_unl = 0;
		/*
		 * doi
		 */
		if ((err = get_tn_doi(tpentp, kv)) != 0)
			return (err);
		tpentp->tp_mask_unl |= TSOL_MSK_CIPSO_DOI;
		/*
		 * default label
		 */
		val = kva_match(kv, TP_DEFLABEL);
		if (val == NULL)
			return (LTSNET_NO_LABEL);
		if (stobsl(val, &tpentp->tp_def_label, NO_CORRECTION,
		    &err) == 0)
			return (LTSNET_ILL_LABEL);
		tpentp->tp_mask_unl |= TSOL_MSK_DEF_LABEL;
		/*
		 * check label range
		 */
		val = kva_match(kv, TP_MINLABEL);
		val2 = kva_match(kv, TP_MAXLABEL);
		if (val == NULL && val2 == NULL) {
			/*
			 * This is the old format.  Use ADMIN_LOW to SL of the
			 * default label as the gw_sl_range.
			 */
			bsllow(&tpentp->tp_gw_sl_range.lower_bound);
			tpentp->tp_gw_sl_range.upper_bound =
			    tpentp->tp_def_label;
		} else {
			err = get_tn_sl_range(&tpentp->tp_gw_sl_range, val,
			    val2);
			if (err != 0)
				return (err);
		}
		tpentp->tp_mask_unl |= TSOL_MSK_SL_RANGE_TSOL;

		/*
		 * also label set, if present.  (optional)
		 */
		val = kva_match(kv, TP_SET);
		if (val != NULL) {
			err = get_tn_sl_set(&tpentp->tp_gw_sl_set, val);
			if (err != 0)
				return (err);
			tpentp->tp_mask_cipso |= TSOL_MSK_SL_RANGE_TSOL;
		}
	} else {
		tpentp->tp_mask_cipso = 0;
		/*
		 * doi
		 */
		if ((err = get_tn_doi(tpentp, kv)) != 0)
			return (err);
		tpentp->tp_mask_cipso |= TSOL_MSK_CIPSO_DOI;
		/*
		 * label range
		 */
		val = kva_match(kv, TP_MINLABEL);
		val2 = kva_match(kv, TP_MAXLABEL);
		err = get_tn_sl_range(&tpentp->tp_sl_range_cipso, val, val2);
		if (err != 0)
			return (err);
		tpentp->tp_mask_cipso |= TSOL_MSK_SL_RANGE_TSOL;
		/*
		 * also label set, if present.  (optional)
		 */
		val = kva_match(kv, TP_SET);
		if (val != NULL) {
			err = get_tn_sl_set(&tpentp->tp_sl_set_cipso, val);
			if (err != 0)
				return (err);
			tpentp->tp_mask_cipso |= TSOL_MSK_SL_RANGE_TSOL;
		}

		/* CIPSO entries don't support default labels */
		val = kva_match(kv, TP_DEFLABEL);
		if (val != NULL)
			return (LTSNET_BAD_TYPE);
	}

	return (0);
}

tsol_tpent_t *
tpstr_to_ent(tsol_tpstr_t *tpstrp, int *errp, char **errstrp)
{
	int		err = 0;
	char		*errstr;
	char		*template = tpstrp->template;
	char		*attrs = tpstrp->attrs;
	kva_t		*kv;
	tsol_tpent_t	*tpentp = NULL;

	/*
	 * The user can specify NULL pointers for these.  Make sure that we
	 * don't have to deal with checking for NULL everywhere by just
	 * pointing to our own variables if the user gives NULL.
	 */
	if (errp == NULL)
		errp = &err;
	if (errstrp == NULL)
		errstrp = &errstr;
	/* The default, unless we find a more specific error locus. */
	*errstrp = template;

	if (template == NULL || *template == '#' || *template == '\n') {
		*errp = LTSNET_EMPTY;
		if (attrs && *attrs != '\0' && *attrs != '#' && *attrs != '\n')
			*errstrp = attrs;
		else if (template == NULL)
			*errstrp = "   ";
		goto err_ret;
	}
	if (*template == '\0') {
		*errp = LTSNET_NO_NAME;
		if (attrs && *attrs != '\0' && *attrs != '#' && *attrs != '\n')
		    *errstrp = attrs;
		goto err_ret;
	}
	if (attrs == NULL || *attrs == '\0' || *attrs == '#' ||
	    *attrs == '\n') {
		*errp = LTSNET_NO_ATTRS;
		goto err_ret;
	}
	if ((tpentp = calloc(1, sizeof (*tpentp))) == NULL) {
		*errp = LTSNET_SYSERR;
		return (NULL);
	}
	if ((strlcpy(tpentp->name, template, sizeof (tpentp->name)) >=
	    sizeof (tpentp->name)) ||
	    strpbrk(tpentp->name, TN_RESERVED) != NULL) {
		*errp = LTSNET_ILL_NAME;
		goto err_ret;
	}
	kv = _str2kva(attrs, KV_ASSIGN, KV_DELIMITER);
	*errp = parse_remainder(tpentp, kv);
	_kva_free(kv);
	if (*errp == 0) {
#ifdef	DEBUG
		(void) fprintf(stdout, "tpstr_to_ent: %s:%s\n", tpentp->name,
		    attrs);
#endif	/* DEBUG */

		return (tpentp);
	}

err_ret:
	err = errno;
	tsol_freetpent(tpentp);
	errno = err;
#ifdef	DEBUG
	(void) fprintf(stderr, "\ntpstr_to_ent: %s:%s\n",
	    *errstrp, (char *)tsol_strerror(*errp, errno));
#endif	/* DEBUG */

	return (NULL);
}

void
tsol_freetpent(tsol_tpent_t *tp)
{
	if (tp != NULL)
		free(tp);
}
