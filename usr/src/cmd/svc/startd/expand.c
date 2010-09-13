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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>

#include "startd.h"

/*
 * Return an allocated copy of str, with the Bourne shell's metacharacters
 * escaped by '\'.  Returns NULL on (allocation) failure.
 */
static char *
quote_for_shell(const char *str)
{
	const char *sp;
	char *dst, *dp;
	size_t dst_len;

	const char * const metachars = ";&()|^<>\n \t\\\"\'`";

	dst_len = 0;
	for (sp = str; *sp != '\0'; ++sp) {
		++dst_len;

		if (strchr(metachars, *sp) != NULL)
			++dst_len;
	}

	if (sp - str == dst_len)
		return (safe_strdup(str));

	dst = malloc(dst_len + 1);
	if (dst == NULL)
		return (NULL);

	for (dp = dst, sp = str; *sp != '\0'; ++dp, ++sp) {
		if (strchr(metachars, *sp) != NULL)
			*dp++ = '\\';

		*dp = *sp;
	}
	*dp = '\0';

	return (dst);
}

/*
 * Return an allocated string representation of the value v.
 * Return NULL on error.
 */
static char *
val_to_str(scf_value_t *v)
{
	char *buf;
	ssize_t buflen, ret;

	buflen = scf_value_get_as_string(v, NULL, 0);
	assert(buflen >= 0);

	buf = malloc(buflen + 1);
	if (buf == NULL)
		return (NULL);

	ret = scf_value_get_as_string(v, buf, buflen + 1);
	assert(ret == buflen);

	return (buf);
}

/*
 * Look up a property in the given snapshot, or the editing one
 * if not found. Returns scf_error() on failure, or 0 otherwise.
 */
static int
get_prop(const scf_instance_t *inst, scf_snapshot_t *snap,
    const char *pgn, const char *pn, scf_propertygroup_t *pg,
    scf_property_t *prop)
{
	int ret;

	ret = scf_instance_get_pg_composed(inst, snap, pgn, pg);
	if (ret != 0) {
		snap = NULL;
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			ret = scf_instance_get_pg_composed(inst, snap, pgn, pg);
		if (ret != 0)
			return (scf_error());
	}

	if (scf_pg_get_property(pg, pn, prop) == 0)
		return (0);

	if (snap == NULL)
		return (scf_error());

	ret = scf_instance_get_pg_composed(inst, NULL, pgn, pg);
	if (ret != 0)
		return (scf_error());

	if (scf_pg_get_property(pg, pn, prop) == 0)
		return (0);

	return (scf_error());
}

/*
 * Get an allocated string representation of the values of the property
 * specified by inst & prop_spec and store it in *retstr.  prop_spec may
 * be a full property FMRI, or a "property-group/property" pair relative
 * to inst, or the name of a property in inst's "application" property
 * group.  In the latter two cases, the property is looked up in inst's
 * snap snapshot.  In the first case, the target instance's running
 * snapshot will be used.  In any case, if the property or its group
 * can't be found, the "editing" snapshot will be checked.  Multiple
 * values will be separated by sep.
 *
 * On error, non-zero is returned, and *retstr is set to an error
 * string.
 *
 * *retstr should always be freed by the caller.
 */
static int
get_prop_val_str(const scf_instance_t *inst, scf_snapshot_t *snap,
    const char *prop_spec, char sep, char **retstr)
{
	scf_handle_t *h = scf_instance_handle(inst);
	scf_scope_t *scope = NULL;
	scf_service_t *svc = NULL;
	scf_instance_t *tmpinst = NULL;
	scf_snapshot_t *tmpsnap = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_iter_t *iter = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;
	char *spec;
	char *str, *qstr;
	size_t strl;
	int ret;

	spec = safe_strdup(prop_spec);

	if (strstr(spec, ":properties") != NULL) {
		const char *scn, *sn, *in, *pgn, *pn;

		if (scf_parse_svc_fmri(spec, &scn, &sn, &in, &pgn,
		    &pn) != 0)
			goto scferr;

		if (sn == NULL || pgn == NULL || pn == NULL) {
			free(spec);
			*retstr = safe_strdup("parse error");
			return (-1);
		}

		if ((scope = scf_scope_create(h)) == NULL ||
		    (svc = scf_service_create(h)) == NULL ||
		    (pg = scf_pg_create(h)) == NULL ||
		    (prop = scf_property_create(h)) == NULL)
			goto scferr;

		if (scf_handle_get_scope(h, scn == NULL ? SCF_SCOPE_LOCAL : scn,
		    scope) != 0)
			goto properr;

		if (scf_scope_get_service(scope, sn, svc) != 0)
			goto properr;

		if (in == NULL) {
			if (scf_service_get_pg(svc, pgn, pg) != 0)
				goto properr;
			if (scf_pg_get_property(pg, pn, prop) != 0)
				goto properr;
		} else {
			if ((tmpinst = scf_instance_create(h)) == NULL)
				goto scferr;
			if (scf_service_get_instance(svc, in, tmpinst) != 0)
				goto properr;

			tmpsnap = libscf_get_running_snapshot(tmpinst);
			if (tmpsnap == NULL)
				goto scferr;

			if (get_prop(tmpinst, tmpsnap, pgn, pn, pg, prop) != 0)
				goto properr;
		}
	} else {
		char *slash, *pgn, *pn;

		/* Try prop or pg/prop in inst. */

		prop = scf_property_create(h);
		if (prop == NULL)
			goto scferr;

		pg = scf_pg_create(h);
		if (pg == NULL)
			goto scferr;

		slash = strchr(spec, '/');
		if (slash == NULL) {
			pgn = "application";
			pn = spec;
		} else {
			*slash = '\0';
			pgn = spec;
			pn = slash + 1;
		}

		if (get_prop(inst, snap, pgn, pn, pg, prop) != 0)
			goto properr;
	}

	iter = scf_iter_create(h);
	if (iter == NULL)
		goto scferr;


	if (scf_iter_property_values(iter, prop) == -1)
		goto scferr;

	val = scf_value_create(h);
	if (val == NULL)
		goto scferr;

	ret = scf_iter_next_value(iter, val);
	if (ret == 0) {
		*retstr = safe_strdup("");
		goto out;
	} else if (ret == -1) {
		goto scferr;
	}

	str = val_to_str(val);
	if (str == NULL)
		goto err;

	qstr = quote_for_shell(str);
	free(str);
	str = qstr;
	if (qstr == NULL)
		goto err;

	strl = strlen(str);

	while ((ret = scf_iter_next_value(iter, val)) == 1) {
		char *nv, *qnv;
		size_t nl;
		void *p;

		/* Append sep & val_to_str(val) to str. */

		nv = val_to_str(val);
		if (nv == NULL) {
			free(str);
			goto err;
		}
		qnv = quote_for_shell(nv);
		free(nv);
		if (qnv == NULL) {
			free(str);
			goto err;
		}
		nv = qnv;

		nl = strl + 1 + strlen(nv);
		p = realloc(str, nl + 1);
		if (p == NULL) {
			free(str);
			free(nv);
			goto err;
		}
		str = p;

		str[strl] = sep;
		(void) strcpy(&str[strl + 1], nv);

		free(nv);

		strl = nl;
	}
	if (ret == -1) {
		free(str);
		goto scferr;
	}

	*retstr = str;

out:
	scf_value_destroy(val);
	scf_iter_destroy(iter);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_instance_destroy(tmpinst);
	scf_snapshot_destroy(tmpsnap);
	scf_service_destroy(svc);
	scf_scope_destroy(scope);
	free(spec);
	return (ret);
scferr:
	*retstr = safe_strdup(scf_strerror(scf_error()));
	ret = -1;
	goto out;
properr:
	ret = -1;
	if (scf_error() != SCF_ERROR_NOT_FOUND)
		goto scferr;
	*retstr = uu_msprintf("property \"%s\" not found", prop_spec);
	if (*retstr != NULL)
		goto out;
err:
	*retstr = safe_strdup(strerror(errno));
	ret = -1;
	goto out;
}

/*
 * Interpret the token at the beginning of str (which should be just
 * after the escape character), and set *retstr to point at it.  Returns
 * the number of characters swallowed.  On error, this returns -1, and
 * *retstr is set to an error string.
 *
 * *retstr should always be freed by the caller.
 */
static int
expand_token(const char *str, scf_instance_t *inst, scf_snapshot_t *snap,
    int method_type, char **retstr)
{
	scf_handle_t *h = scf_instance_handle(inst);

	switch (str[0]) {
	case 's': {		/* service */
		scf_service_t *svc;
		char *sname;
		ssize_t sname_len, szret;
		int ret;

		svc = scf_service_create(h);
		if (svc == NULL) {
			*retstr = safe_strdup(strerror(scf_error()));
			return (-1);
		}

		ret = scf_instance_get_parent(inst, svc);
		if (ret != 0) {
			int err = scf_error();
			scf_service_destroy(svc);
			*retstr = safe_strdup(scf_strerror(err));
			return (-1);
		}

		sname_len = scf_service_get_name(svc, NULL, 0);
		if (sname_len < 0) {
			int err = scf_error();
			scf_service_destroy(svc);
			*retstr = safe_strdup(scf_strerror(err));
			return (-1);
		}

		sname = malloc(sname_len + 1);
		if (sname == NULL) {
			int err = scf_error();
			scf_service_destroy(svc);
			*retstr = safe_strdup(scf_strerror(err));
			return (-1);
		}

		szret = scf_service_get_name(svc, sname, sname_len + 1);

		if (szret < 0) {
			int err = scf_error();
			free(sname);
			scf_service_destroy(svc);
			*retstr = safe_strdup(scf_strerror(err));
			return (-1);
		}

		scf_service_destroy(svc);
		*retstr = sname;
		return (1);
	}

	case 'i': {	/* instance */
		char *iname;
		ssize_t iname_len, szret;

		iname_len = scf_instance_get_name(inst, NULL, 0);
		if (iname_len < 0) {
			*retstr = safe_strdup(scf_strerror(scf_error()));
			return (-1);
		}

		iname = malloc(iname_len + 1);
		if (iname == NULL) {
			*retstr = safe_strdup(strerror(errno));
			return (-1);
		}

		szret = scf_instance_get_name(inst, iname, iname_len + 1);
		if (szret < 0) {
			free(iname);
			*retstr = safe_strdup(scf_strerror(scf_error()));
			return (-1);
		}

		*retstr = iname;
		return (1);
	}

	case 'f': {	/* fmri */
		char *fmri;
		ssize_t fmri_len;
		int ret;

		fmri_len = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
		if (fmri_len == -1) {
			*retstr = safe_strdup(scf_strerror(scf_error()));
			return (-1);
		}

		fmri = malloc(fmri_len + 1);
		if (fmri == NULL) {
			*retstr = safe_strdup(strerror(errno));
			return (-1);
		}

		ret = scf_instance_to_fmri(inst, fmri, fmri_len + 1);
		if (ret == -1) {
			free(fmri);
			*retstr = safe_strdup(scf_strerror(scf_error()));
			return (-1);
		}

		*retstr = fmri;
		return (1);
	}

	case 'm': {	/* method */
		char *str = NULL;
		switch (method_type) {
		case METHOD_START:
			str = "start";
			break;
		case METHOD_STOP:
			str = "stop";
			break;
		case METHOD_REFRESH:
			str = "refresh";
			break;
		default:
			assert(0);
			return (-1);
		}
		*retstr = safe_strdup(str);
		return (1);
	}

	case 'r':	/* restarter */
		*retstr = safe_strdup("svc.startd");
		return (1);

	case '{': {
		/* prop_spec[,:]?  See get_prop_val_str() for prop_spec. */

		char *close;
		size_t len;
		char *buf;
		char sep;
		int ret;
		int skip;

		close = strchr(str + 1, '}');
		if (close == NULL) {
			*retstr = safe_strdup("parse error");
			return (-1);
		}

		len = close - (str + 1);	/* between the {}'s */
		skip = len + 2;			/* including the {}'s */

		/*
		 * If the last character is , or :, use it as the separator.
		 * Otherwise default to space.
		 */
		sep = *(close - 1);
		if (sep == ',' || sep == ':')
			--len;
		else
			sep = ' ';

		buf = malloc(len + 1);
		if (buf == NULL) {
			*retstr = safe_strdup(strerror(errno));
			return (-1);
		}

		(void) strlcpy(buf, str + 1, len + 1);

		ret = get_prop_val_str(inst, snap, buf, sep, retstr);

		if (ret != 0) {
			free(buf);
			return (-1);
		}

		free(buf);
		return (skip);
	}

	default:
		*retstr = safe_strdup("unknown method token");
		return (-1);
	}
}

/*
 * Expand method tokens in the given string, and place the result in
 * *retstr.  Tokens begin with the ESCAPE character.  Returns 0 on
 * success.  On failure, returns -1 and an error string is placed in
 * *retstr.  Caller should free *retstr.
 */
#define	ESCAPE	'%'

int
expand_method_tokens(const char *str, scf_instance_t *inst,
    scf_snapshot_t *snap, int method_type, char **retstr)
{
	char *expanded;
	size_t exp_sz;
	const char *sp;
	int ei;

	if (scf_instance_handle(inst) == NULL) {
		*retstr = safe_strdup(scf_strerror(scf_error()));
		return (-1);
	}

	exp_sz = strlen(str) + 1;
	expanded = malloc(exp_sz);
	if (expanded == NULL) {
		*retstr = safe_strdup(strerror(errno));
		return (-1);
	}

	/*
	 * Copy str into expanded, expanding %-tokens & realloc()ing as we go.
	 */

	sp = str;
	ei = 0;

	for (;;) {
		char *esc;
		size_t len;

		esc = strchr(sp, ESCAPE);
		if (esc == NULL) {
			(void) strcpy(expanded + ei, sp);
			*retstr = expanded;
			return (0);
		}

		/* Copy up to the escape character. */
		len = esc - sp;

		(void) strncpy(expanded + ei, sp, len);

		sp += len;
		ei += len;

		if (sp[1] == '\0') {
			expanded[ei] = '\0';
			*retstr = expanded;
			return (0);
		}

		if (sp[1] == ESCAPE) {
			expanded[ei] = ESCAPE;

			sp += 2;
			ei++;
		} else {
			char *tokval;
			int skip;
			char *p;

			skip = expand_token(sp + 1, inst, snap,
			    method_type, &tokval);
			if (skip == -1) {
				free(expanded);
				*retstr = tokval;
				return (-1);
			}

			len = strlen(tokval);
			exp_sz += len;
			p = realloc(expanded, exp_sz);
			if (p == NULL) {
				*retstr = safe_strdup(strerror(errno));
				free(expanded);
				free(tokval);
				return (-1);
			}
			expanded = p;

			(void) strcpy(expanded + ei, tokval);
			sp += 1 + skip;
			ei += len;

			free(tokval);
		}
	}

	/* NOTREACHED */
}
