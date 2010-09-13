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

#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <alloca.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>

#include <fmd_conf.h>
#include <fmd_alloc.h>
#include <fmd_error.h>
#include <fmd_subr.h>
#include <fmd_string.h>
#include <fmd.h>

const char FMD_PROP_SUBSCRIPTIONS[] = "_subscriptions";
const char FMD_PROP_DICTIONARIES[] = "_dictionaries";

/*
 * The property formals defined in _fmd_conf_defv[] are added to every config
 * dictionary that is created.  Here we define several special FMD_PROP_*
 * properties that are used to implement the config file keyword actions, as
 * well as properties that should be inherited by fmd_conf_t's from fmd.d_conf.
 */
static const fmd_conf_formal_t _fmd_conf_defv[] = {
	{ FMD_PROP_SUBSCRIPTIONS, &fmd_conf_list, "" },
	{ FMD_PROP_DICTIONARIES, &fmd_conf_list, "" },
	{ "fmd.isaname", &fmd_conf_parent, "isaname" },
	{ "fmd.machine", &fmd_conf_parent, "machine" },
	{ "fmd.platform", &fmd_conf_parent, "platform" },
	{ "fmd.rootdir", &fmd_conf_parent, "rootdir" },
};

static const int _fmd_conf_defc =
    sizeof (_fmd_conf_defv) / sizeof (_fmd_conf_defv[0]);

static int
set_bool(fmd_conf_param_t *pp, const char *s)
{
	if (strcasecmp(s, "true") == 0)
		pp->cp_value.cpv_num = 1;
	else if (strcasecmp(s, "false") == 0)
		pp->cp_value.cpv_num = 0;
	else
		return (fmd_set_errno(EFMD_CONF_INVAL));

	return (0);
}

static void
get_bool(const fmd_conf_param_t *pp, void *ptr)
{
	*((int *)ptr) = (int)pp->cp_value.cpv_num;
}

static int
set_i32x(fmd_conf_param_t *pp, const char *s, int64_t min, int64_t max)
{
	int64_t val;
	char *end;

	errno = 0;
	val = strtoll(s, &end, 0);

	if (errno == EOVERFLOW || val < min || val > max)
		return (fmd_set_errno(EFMD_CONF_OVERFLOW));

	if (errno != 0 || end == s || *end != '\0')
		return (fmd_set_errno(EFMD_CONF_INVAL));

	pp->cp_value.cpv_num = val;
	return (0);
}

static int
set_i8(fmd_conf_param_t *pp, const char *s)
{
	return (set_i32x(pp, s, INT8_MIN, INT8_MAX));
}

static int
set_i16(fmd_conf_param_t *pp, const char *s)
{
	return (set_i32x(pp, s, INT16_MIN, INT16_MAX));
}

static int
set_i32(fmd_conf_param_t *pp, const char *s)
{
	return (set_i32x(pp, s, INT32_MIN, INT32_MAX));
}

static void
get_i32(const fmd_conf_param_t *pp, void *ptr)
{
	*((int32_t *)ptr) = (int32_t)pp->cp_value.cpv_num;
}

static int
set_ui32x(fmd_conf_param_t *pp, const char *s, uint64_t max)
{
	uint64_t val;
	char *end;

	errno = 0;
	val = strtoull(s, &end, 0);

	if (errno == EOVERFLOW || val > max)
		return (fmd_set_errno(EFMD_CONF_OVERFLOW));

	if (errno != 0 || end == s || *end != '\0')
		return (fmd_set_errno(EFMD_CONF_INVAL));

	pp->cp_value.cpv_num = val;
	return (0);
}

static int
set_ui8(fmd_conf_param_t *pp, const char *s)
{
	return (set_ui32x(pp, s, UINT8_MAX));
}

static int
set_ui16(fmd_conf_param_t *pp, const char *s)
{
	return (set_ui32x(pp, s, UINT16_MAX));
}

static int
set_ui32(fmd_conf_param_t *pp, const char *s)
{
	return (set_ui32x(pp, s, UINT32_MAX));
}

static void
get_ui32(const fmd_conf_param_t *pp, void *ptr)
{
	*((uint32_t *)ptr) = (uint32_t)pp->cp_value.cpv_num;
}

static int
set_i64(fmd_conf_param_t *pp, const char *s)
{
	int64_t val;
	char *end;

	errno = 0;
	val = strtoll(s, &end, 0);

	if (errno == EOVERFLOW)
		return (fmd_set_errno(EFMD_CONF_OVERFLOW));

	if (errno != 0 || end == s || *end != '\0')
		return (fmd_set_errno(EFMD_CONF_INVAL));

	pp->cp_value.cpv_num = val;
	return (0);
}

static void
get_i64(const fmd_conf_param_t *pp, void *ptr)
{
	*((int64_t *)ptr) = (int64_t)pp->cp_value.cpv_num;
}

static int
set_ui64(fmd_conf_param_t *pp, const char *s)
{
	uint64_t val;
	char *end;

	errno = 0;
	val = strtoull(s, &end, 0);

	if (errno == EOVERFLOW)
		return (fmd_set_errno(EFMD_CONF_OVERFLOW));

	if (errno != 0 || end == s || *end != '\0')
		return (fmd_set_errno(EFMD_CONF_INVAL));

	pp->cp_value.cpv_num = val;
	return (0);
}

static void
get_ui64(const fmd_conf_param_t *pp, void *ptr)
{
	*((uint64_t *)ptr) = pp->cp_value.cpv_num;
}

static int
set_str(fmd_conf_param_t *pp, const char *s)
{
	fmd_strfree(pp->cp_value.cpv_str);
	pp->cp_value.cpv_str = fmd_strdup(s, FMD_SLEEP);
	return (0);
}

static void
get_str(const fmd_conf_param_t *pp, void *ptr)
{
	*((const char **)ptr) = pp->cp_value.cpv_str;
}

static void
free_str(fmd_conf_param_t *pp)
{
	fmd_strfree(pp->cp_value.cpv_str);
	pp->cp_value.cpv_str = NULL;
}

static int
set_path(fmd_conf_param_t *pp, const char *value)
{
	size_t len = strlen(value);
	char *s = alloca(len + 1);

	char **patv = alloca(sizeof (char *) * len / 2);
	int patc = 0;

	static const char *const percent_sign = "%";
	char *p, *q;
	int c, i;

	static const struct fmd_conf_token {
		char tok_tag;
		const char *const *tok_val;
	} tokens[] = {
		{ 'i', &fmd.d_platform },
		{ 'm', &fmd.d_machine },
		{ 'p', &fmd.d_isaname },
		{ 'r', &fmd.d_rootdir },
		{ '%', &percent_sign },
		{ 0, NULL }
	};

	const struct fmd_conf_token *tok;
	fmd_conf_path_t *pap;

	pp->cp_formal->cf_ops->co_free(pp);
	(void) strcpy(s, value);

	for (p = strtok_r(s, ":", &q); p != NULL; p = strtok_r(NULL, ":", &q))
		patv[patc++] = p;

	pap = fmd_alloc(sizeof (fmd_conf_path_t), FMD_SLEEP);
	pap->cpa_argv = fmd_alloc(sizeof (char *) * patc, FMD_SLEEP);
	pap->cpa_argc = patc;

	for (i = 0; i < patc; i++) {
		for (len = 0, p = patv[i]; (c = *p) != '\0'; p++, len++) {
			if (c != '%' || (c = p[1]) == '\0')
				continue;

			for (tok = tokens; tok->tok_tag != 0; tok++) {
				if (c == tok->tok_tag) {
					len += strlen(*tok->tok_val) - 1;
					p++;
					break;
				}
			}
		}

		pap->cpa_argv[i] = q = fmd_alloc(len + 1, FMD_SLEEP);
		q[len] = '\0';

		for (p = patv[i]; (c = *p) != '\0'; p++) {
			if (c != '%' || (c = p[1]) == '\0') {
				*q++ = c;
				continue;
			}

			for (tok = tokens; tok->tok_tag != 0; tok++) {
				if (c == tok->tok_tag) {
					(void) strcpy(q, *tok->tok_val);
					q += strlen(q);
					p++;
					break;
				}
			}

			if (tok->tok_tag == 0)
				*q++ = c;
		}
	}

	pp->cp_value.cpv_ptr = pap;
	return (0);
}

static int
set_lst(fmd_conf_param_t *pp, const char *value)
{
	fmd_conf_path_t *old;

	old = pp->cp_value.cpv_ptr;
	pp->cp_value.cpv_ptr = NULL;

	if (set_path(pp, value) != 0) {
		pp->cp_value.cpv_ptr = old;
		return (-1); /* errno is set for us */
	}

	if (old != NULL) {
		fmd_conf_path_t *new = pp->cp_value.cpv_ptr;
		int i, totc = old->cpa_argc + new->cpa_argc;

		int new_argc = new->cpa_argc;
		const char **new_argv = new->cpa_argv;

		new->cpa_argc = 0;
		new->cpa_argv = fmd_alloc(sizeof (char *) * totc, FMD_SLEEP);

		for (i = 0; i < old->cpa_argc; i++)
			new->cpa_argv[new->cpa_argc++] = old->cpa_argv[i];

		for (i = 0; i < new_argc; i++)
			new->cpa_argv[new->cpa_argc++] = new_argv[i];

		ASSERT(new->cpa_argc == totc);

		fmd_free(new_argv, sizeof (char *) * new_argc);
		fmd_free(old->cpa_argv, sizeof (char *) * old->cpa_argc);
		fmd_free(old, sizeof (fmd_conf_path_t));
	}

	return (0);
}

static int
del_lst(fmd_conf_param_t *pp, const char *value)
{
	fmd_conf_path_t *pap = pp->cp_value.cpv_ptr;
	const char **new_argv;
	int i, new_argc;

	for (i = 0; i < pap->cpa_argc; i++) {
		if (strcmp(pap->cpa_argv[i], value) == 0)
			break;
	}

	if (i == pap->cpa_argc)
		return (fmd_set_errno(ENOENT));

	fmd_strfree((char *)pap->cpa_argv[i]);
	pap->cpa_argv[i] = NULL;

	new_argc = 0;
	new_argv = fmd_alloc(sizeof (char *) * (pap->cpa_argc - 1), FMD_SLEEP);

	for (i = 0; i < pap->cpa_argc; i++) {
		if (pap->cpa_argv[i] != NULL)
			new_argv[new_argc++] = pap->cpa_argv[i];
	}

	fmd_free(pap->cpa_argv, sizeof (char *) * pap->cpa_argc);
	pap->cpa_argv = new_argv;
	pap->cpa_argc = new_argc;

	return (0);
}

static void
get_path(const fmd_conf_param_t *pp, void *ptr)
{
	*((fmd_conf_path_t **)ptr) = (fmd_conf_path_t *)pp->cp_value.cpv_ptr;
}

static void
free_path(fmd_conf_param_t *pp)
{
	fmd_conf_path_t *pap = pp->cp_value.cpv_ptr;
	int i;

	if (pap == NULL)
		return; /* no value was ever set */

	for (i = 0; i < pap->cpa_argc; i++)
		fmd_strfree((char *)pap->cpa_argv[i]);

	fmd_free(pap->cpa_argv, sizeof (char *) * pap->cpa_argc);
	fmd_free(pap, sizeof (fmd_conf_path_t));
	pp->cp_value.cpv_ptr = NULL;
}

static int
set_time(fmd_conf_param_t *pp, const char *s)
{
	static const struct {
		const char *name;
		hrtime_t mul;
	} suffix[] = {
		{ "ns", 	NANOSEC / NANOSEC },
		{ "nsec",	NANOSEC / NANOSEC },
		{ "us",		NANOSEC / MICROSEC },
		{ "usec",	NANOSEC / MICROSEC },
		{ "ms",		NANOSEC / MILLISEC },
		{ "msec",	NANOSEC / MILLISEC },
		{ "s",		NANOSEC / SEC },
		{ "sec",	NANOSEC / SEC },
		{ "m",		NANOSEC * (hrtime_t)60 },
		{ "min",	NANOSEC * (hrtime_t)60 },
		{ "h",		NANOSEC * (hrtime_t)(60 * 60) },
		{ "hour",	NANOSEC * (hrtime_t)(60 * 60) },
		{ "d",		NANOSEC * (hrtime_t)(24 * 60 * 60) },
		{ "day",	NANOSEC * (hrtime_t)(24 * 60 * 60) },
		{ "hz",		0 },
		{ NULL }
	};

	hrtime_t val, mul = 1;
	char *end;
	int i;

	errno = 0;
	val = strtoull(s, &end, 0);

	if (errno == EOVERFLOW)
		return (fmd_set_errno(EFMD_CONF_OVERFLOW));

	if (errno != 0 || end == s)
		return (fmd_set_errno(EFMD_CONF_INVAL));

	for (i = 0; suffix[i].name != NULL; i++) {
		if (strcasecmp(suffix[i].name, end) == 0) {
			mul = suffix[i].mul;
			break;
		}
	}

	if (suffix[i].name == NULL && *end != '\0')
		return (fmd_set_errno(EFMD_CONF_INVAL));

	if (mul == 0) {
		if (val != 0)
			val = NANOSEC / val; /* compute val as value per sec */
	} else
		val *= mul;

	pp->cp_value.cpv_num = val;
	return (0);
}

static int
set_size(fmd_conf_param_t *pp, const char *s)
{
	size_t len = strlen(s);
	uint64_t val, mul = 1;
	char *end;

	switch (s[len - 1]) {
	case 't':
	case 'T':
		mul *= 1024;
		/*FALLTHRU*/
	case 'g':
	case 'G':
		mul *= 1024;
		/*FALLTHRU*/
	case 'm':
	case 'M':
		mul *= 1024;
		/*FALLTHRU*/
	case 'k':
	case 'K':
		mul *= 1024;
		/*FALLTHRU*/
	default:
		break;
	}

	errno = 0;
	val = strtoull(s, &end, 0) * mul;

	if (errno == EOVERFLOW)
		return (fmd_set_errno(EFMD_CONF_OVERFLOW));

	if ((mul != 1 && end != &s[len - 1]) ||
	    (mul == 1 && *end != '\0') || errno != 0)
		return (fmd_set_errno(EFMD_CONF_INVAL));

	pp->cp_value.cpv_num = val;
	return (0);
}

static int
set_sig(fmd_conf_param_t *pp, const char *s)
{
	int sig;

	if (strncasecmp(s, "SIG", 3) == 0)
		s += 3; /* be friendlier than strsig() and permit the prefix */

	if (str2sig(s, &sig) != 0)
		return (fmd_set_errno(EFMD_CONF_INVAL));

	pp->cp_value.cpv_num = sig;
	return (0);
}

static void
get_par(const fmd_conf_param_t *pp, void *ptr)
{
	if (fmd_conf_getprop(fmd.d_conf, pp->cp_formal->cf_default, ptr) != 0) {
		fmd_panic("fmd.d_conf does not define '%s' (inherited as %s)\n",
		    (char *)pp->cp_formal->cf_default, pp->cp_formal->cf_name);
	}
}

/*ARGSUSED*/
static int
set_par(fmd_conf_param_t *pp, const char *s)
{
	return (fmd_set_errno(EFMD_CONF_RDONLY));
}

/*
 * Utility routine for callers who define custom ops where a list of string
 * tokens are translated into a bitmask.  'cmp' should be set to point to an
 * array of fmd_conf_mode_t's where the final element has cm_name == NULL.
 */
int
fmd_conf_mode_set(const fmd_conf_mode_t *cma,
    fmd_conf_param_t *pp, const char *value)
{
	const fmd_conf_mode_t *cmp;
	char *p, *q, *s = fmd_strdup(value, FMD_SLEEP);
	size_t len = value ? strlen(value) + 1 : 0;
	uint_t mode = 0;

	if (s == NULL) {
		pp->cp_value.cpv_num = 0;
		return (0);
	}

	for (p = strtok_r(s, ",", &q); p != NULL; p = strtok_r(NULL, ",", &q)) {
		for (cmp = cma; cmp->cm_name != NULL; cmp++) {
			if (strcmp(cmp->cm_name, p) == 0) {
				mode |= cmp->cm_bits;
				break;
			}
		}

		if (cmp->cm_name == NULL) {
			fmd_free(s, len);
			return (fmd_set_errno(EFMD_CONF_INVAL));
		}
	}

	pp->cp_value.cpv_num = mode;
	fmd_free(s, len);
	return (0);
}

void
fmd_conf_mode_get(const fmd_conf_param_t *pp, void *ptr)
{
	*((uint_t *)ptr) = (uint_t)pp->cp_value.cpv_num;
}

/*ARGSUSED*/
int
fmd_conf_notsup(fmd_conf_param_t *pp, const char *value)
{
	return (fmd_set_errno(ENOTSUP));
}

/*ARGSUSED*/
void
fmd_conf_nop(fmd_conf_param_t *pp)
{
	/* no free required for integer-type parameters */
}

#define	CONF_DEFINE(name, a, b, c, d) \
	const fmd_conf_ops_t name = { a, b, c, d }

CONF_DEFINE(fmd_conf_bool, set_bool, get_bool, fmd_conf_notsup, fmd_conf_nop);
CONF_DEFINE(fmd_conf_int8, set_i8, get_i32, fmd_conf_notsup, fmd_conf_nop);
CONF_DEFINE(fmd_conf_uint8, set_ui8, get_ui32, fmd_conf_notsup, fmd_conf_nop);
CONF_DEFINE(fmd_conf_int16, set_i16, get_i32, fmd_conf_notsup, fmd_conf_nop);
CONF_DEFINE(fmd_conf_uint16, set_ui16, get_ui32, fmd_conf_notsup, fmd_conf_nop);
CONF_DEFINE(fmd_conf_int32, set_i32, get_i32, fmd_conf_notsup, fmd_conf_nop);
CONF_DEFINE(fmd_conf_uint32, set_ui32, get_ui32, fmd_conf_notsup, fmd_conf_nop);
CONF_DEFINE(fmd_conf_int64, set_i64, get_i64, fmd_conf_notsup, fmd_conf_nop);
CONF_DEFINE(fmd_conf_uint64, set_ui64, get_ui64, fmd_conf_notsup, fmd_conf_nop);
CONF_DEFINE(fmd_conf_string, set_str, get_str, fmd_conf_notsup, free_str);
CONF_DEFINE(fmd_conf_path, set_path, get_path, fmd_conf_notsup, free_path);
CONF_DEFINE(fmd_conf_list, set_lst, get_path, del_lst, free_path);
CONF_DEFINE(fmd_conf_time, set_time, get_ui64, fmd_conf_notsup, fmd_conf_nop);
CONF_DEFINE(fmd_conf_size, set_size, get_ui64, fmd_conf_notsup, fmd_conf_nop);
CONF_DEFINE(fmd_conf_signal, set_sig, get_i32, fmd_conf_notsup, fmd_conf_nop);
CONF_DEFINE(fmd_conf_parent, set_par, get_par, fmd_conf_notsup, fmd_conf_nop);

static char *
fmd_conf_skipstr(char *s)
{
	int c;

	while ((c = *s) != '\0') {
		if (c == '\\')
			s++;
		else if (c == '"')
			break;
		s++;
	}

	return (s);
}

static char *
fmd_conf_skipnws(char *s)
{
	while (strchr("\f\n\r\t\v ", *s) == NULL)
		s++;

	return (s);
}

static int
fmd_conf_tokenize(char *s, char *tokv[])
{
	int c, tokc = 0;

	while ((c = *s) != '\0') {
		switch (c) {
		case '"':
			tokv[tokc] = s + 1;
			s = fmd_conf_skipstr(s + 1);
			*s++ = '\0';
			(void) fmd_stresc2chr(tokv[tokc++]);
			continue;
		case '\f': case '\n': case '\r':
		case '\t': case '\v': case ' ':
			s++;
			continue;
		default:
			tokv[tokc++] = s;
			s = fmd_conf_skipnws(s);
			*s++ = '\0';
		}
	}

	return (tokc);
}

static int
fmd_conf_exec_setprop(fmd_conf_t *cfp, int argc, char *argv[])
{
	if (argc != 2)
		return (fmd_set_errno(EFMD_CONF_USAGE));

	return (fmd_conf_setprop(cfp, argv[0], argv[1]));
}

static int
fmd_conf_exec_subscribe(fmd_conf_t *cfp, int argc, char *argv[])
{
	if (argc != 1)
		return (fmd_set_errno(EFMD_CONF_USAGE));

	return (fmd_conf_setprop(cfp, FMD_PROP_SUBSCRIPTIONS, argv[0]));
}

static int
fmd_conf_exec_dictionary(fmd_conf_t *cfp, int argc, char *argv[])
{
	if (argc != 1)
		return (fmd_set_errno(EFMD_CONF_USAGE));

	return (fmd_conf_setprop(cfp, FMD_PROP_DICTIONARIES, argv[0]));
}

static int
fmd_conf_parse(fmd_conf_t *cfp, const char *file)
{
	static const fmd_conf_verb_t verbs[] = {
		{ "setprop", fmd_conf_exec_setprop },
		{ "subscribe", fmd_conf_exec_subscribe },
		{ "dictionary", fmd_conf_exec_dictionary },
		{ NULL, NULL }
	};

	int line, errs = 0;
	char buf[BUFSIZ];
	FILE *fp;

	if ((fp = fopen(file, "r")) == NULL) {
		if (errno == EMFILE)
			fmd_error(EFMD_EXIT, "failed to open %s: %s\n",
			    file, fmd_strerror(errno));
		else
			fmd_error(EFMD_CONF_OPEN, "failed to open %s: %s\n",
			    file, fmd_strerror(errno));
		return (fmd_set_errno(EFMD_CONF_OPEN));
	}

	for (line = 1; fgets(buf, sizeof (buf), fp) != NULL; line++) {
		char *tokv[sizeof (buf) / 2 + 1];
		int tokc = fmd_conf_tokenize(buf, tokv);
		const fmd_conf_verb_t *vp;

		if (tokc == 0 || tokv[0][0] == '#')
			continue; /* skip blank lines and comment lines */

		for (vp = verbs; vp->cv_name != NULL; vp++) {
			if (strcmp(tokv[0], vp->cv_name) == 0)
				break;
		}

		if (vp->cv_name == NULL) {
			fmd_error(EFMD_CONF_KEYWORD, "\"%s\", line %d: "
			    "invalid configuration file keyword: %s\n",
			    file, line, tokv[0]);
			errs++;
			continue;
		}

		if (vp->cv_exec(cfp, tokc - 1, tokv + 1) != 0) {
			fmd_error(errno, "\"%s\", line %d", file, line);
			errs++;
			continue;
		}
	}

	if (ferror(fp) != 0 || fclose(fp) != 0)
		return (fmd_set_errno(EFMD_CONF_IO));

	if (errs != 0)
		return (fmd_set_errno(EFMD_CONF_ERRS));

	return (0);
}

static void
fmd_conf_fill(fmd_conf_t *cfp, fmd_conf_param_t *ppbuf,
    int argc, const fmd_conf_formal_t *argv, int checkid)
{
	int i;

	for (i = 0; i < argc; i++, argv++) {
		fmd_conf_param_t *op, *pp = ppbuf + i;
		const char *name = argv->cf_name;
		ulong_t h = fmd_strhash(name) % cfp->cf_parhashlen;

		if (fmd_strbadid(name, checkid) != NULL) {
			fmd_error(EFMD_CONF_PROPNAME, "ignoring invalid formal "
			    "property %s\n", name);
			continue;
		}

		for (op = cfp->cf_parhash[h]; op != NULL; op = op->cp_next) {
			if (strcmp(op->cp_formal->cf_name, name) == 0) {
				fmd_error(EFMD_CONF_PROPDUP, "ignoring "
				    "duplicate formal property %s\n", name);
				break;
			}
		}

		if (op != NULL)
			continue;

		pp->cp_formal = argv;
		pp->cp_next = cfp->cf_parhash[h];
		cfp->cf_parhash[h] = pp;

		if (argv->cf_default && argv->cf_ops != &fmd_conf_parent &&
		    fmd_conf_setprop(cfp, name, argv->cf_default) != 0) {
			fmd_error(EFMD_CONF_DEFAULT, "ignoring invalid default "
			    "<%s> for property %s: %s\n", argv->cf_default,
			    name, fmd_strerror(errno));
		}
	}
}

fmd_conf_t *
fmd_conf_open(const char *file, int argc,
    const fmd_conf_formal_t *argv, uint_t flag)
{
	fmd_conf_t *cfp = fmd_alloc(sizeof (fmd_conf_t), FMD_SLEEP);

	(void) pthread_rwlock_init(&cfp->cf_lock, NULL);
	cfp->cf_argv = argv;
	cfp->cf_argc = argc;
	cfp->cf_flag = flag;

	cfp->cf_params = fmd_zalloc(
	    sizeof (fmd_conf_param_t) * (_fmd_conf_defc + argc), FMD_SLEEP);

	cfp->cf_parhashlen = fmd.d_str_buckets;
	cfp->cf_parhash = fmd_zalloc(
	    sizeof (fmd_conf_param_t *) * cfp->cf_parhashlen, FMD_SLEEP);

	cfp->cf_defer = NULL;

	fmd_conf_fill(cfp, cfp->cf_params, _fmd_conf_defc, _fmd_conf_defv, 0);
	fmd_conf_fill(cfp, cfp->cf_params + _fmd_conf_defc, argc, argv, 1);

	if (file != NULL && fmd_conf_parse(cfp, file) != 0) {
		fmd_conf_close(cfp);
		return (NULL);
	}

	return (cfp);
}

void
fmd_conf_merge(fmd_conf_t *cfp, const char *file)
{
	(void) fmd_conf_parse(cfp, file);
}

void
fmd_conf_propagate(fmd_conf_t *src, fmd_conf_t *dst, const char *scope)
{
	size_t len = strlen(scope);
	fmd_conf_defer_t *cdp;

	(void) pthread_rwlock_rdlock(&src->cf_lock);

	for (cdp = src->cf_defer; cdp != NULL; cdp = cdp->cd_next) {
		if (len == (size_t)(strchr(cdp->cd_name, ':') - cdp->cd_name) &&
		    strncmp(cdp->cd_name, scope, len) == 0 && fmd_conf_setprop(
		    dst, cdp->cd_name + len + 1, cdp->cd_value) != 0) {
			fmd_error(EFMD_CONF_DEFER,
			    "failed to apply deferred property %s to %s: %s\n",
			    cdp->cd_name, scope, fmd_strerror(errno));
		}
	}

	(void) pthread_rwlock_unlock(&src->cf_lock);
}

void
fmd_conf_close(fmd_conf_t *cfp)
{
	fmd_conf_param_t *pp = cfp->cf_params;
	int i, nparams = _fmd_conf_defc + cfp->cf_argc;
	fmd_conf_defer_t *cdp, *ndp;

	for (cdp = cfp->cf_defer; cdp != NULL; cdp = ndp) {
		ndp = cdp->cd_next;
		fmd_strfree(cdp->cd_name);
		fmd_strfree(cdp->cd_value);
		fmd_free(cdp, sizeof (fmd_conf_defer_t));
	}

	fmd_free(cfp->cf_parhash,
	    sizeof (fmd_conf_param_t *) * cfp->cf_parhashlen);

	for (i = 0; i < nparams; i++, pp++) {
		if (pp->cp_formal != NULL)
			pp->cp_formal->cf_ops->co_free(pp);
	}

	fmd_free(cfp->cf_params, sizeof (fmd_conf_param_t) * nparams);
	fmd_free(cfp, sizeof (fmd_conf_t));
}

static fmd_conf_param_t *
fmd_conf_getparam(fmd_conf_t *cfp, const char *name)
{
	ulong_t h = fmd_strhash(name) % cfp->cf_parhashlen;
	fmd_conf_param_t *pp = cfp->cf_parhash[h];

	ASSERT(RW_LOCK_HELD(&cfp->cf_lock));

	for (; pp != NULL; pp = pp->cp_next) {
		if (strcmp(name, pp->cp_formal->cf_name) == 0)
			return (pp);
	}

	return (NULL);
}

/*
 * String-friendly version of fmd_conf_getprop(): return the string as our
 * return value, and return NULL if the string is the empty string.
 */
const char *
fmd_conf_getnzstr(fmd_conf_t *cfp, const char *name)
{
	const fmd_conf_param_t *pp;
	char *s = NULL;

	(void) pthread_rwlock_rdlock(&cfp->cf_lock);

	if ((pp = fmd_conf_getparam(cfp, name)) != NULL) {
		ASSERT(pp->cp_formal->cf_ops == &fmd_conf_string);
		pp->cp_formal->cf_ops->co_get(pp, &s);
	} else
		(void) fmd_set_errno(EFMD_CONF_NOPROP);

	(void) pthread_rwlock_unlock(&cfp->cf_lock);

	if (s != NULL && s[0] == '\0') {
		(void) fmd_set_errno(EFMD_CONF_UNDEF);
		s = NULL;
	}

	return (s);
}

const fmd_conf_ops_t *
fmd_conf_gettype(fmd_conf_t *cfp, const char *name)
{
	const fmd_conf_param_t *pp;
	const fmd_conf_ops_t *ops = NULL;

	(void) pthread_rwlock_rdlock(&cfp->cf_lock);

	if ((pp = fmd_conf_getparam(cfp, name)) != NULL) {
		if ((ops = pp->cp_formal->cf_ops) == &fmd_conf_parent) {
			ops = fmd_conf_gettype(fmd.d_conf,
			    pp->cp_formal->cf_default);
		}
	} else
		(void) fmd_set_errno(EFMD_CONF_NOPROP);

	(void) pthread_rwlock_unlock(&cfp->cf_lock);
	return (ops);
}

int
fmd_conf_getprop(fmd_conf_t *cfp, const char *name, void *data)
{
	const fmd_conf_param_t *pp;
	int err = 0;

	(void) pthread_rwlock_rdlock(&cfp->cf_lock);

	if ((pp = fmd_conf_getparam(cfp, name)) != NULL)
		pp->cp_formal->cf_ops->co_get(pp, data);
	else
		err = fmd_set_errno(EFMD_CONF_NOPROP);

	(void) pthread_rwlock_unlock(&cfp->cf_lock);
	return (err);
}

static int
fmd_conf_setdefer(fmd_conf_t *cfp, const char *name, const char *value)
{
	fmd_conf_defer_t *cdp;

	if (!(cfp->cf_flag & FMD_CONF_DEFER))
		return (fmd_set_errno(EFMD_CONF_NODEFER));

	(void) pthread_rwlock_wrlock(&cfp->cf_lock);

	for (cdp = cfp->cf_defer; cdp != NULL; cdp = cdp->cd_next) {
		if (strcmp(name, cdp->cd_name) == 0) {
			fmd_strfree(cdp->cd_value);
			cdp->cd_value = fmd_strdup(value, FMD_SLEEP);
			goto out;
		}
	}

	cdp = fmd_alloc(sizeof (fmd_conf_defer_t), FMD_SLEEP);

	cdp->cd_name = fmd_strdup(name, FMD_SLEEP);
	cdp->cd_value = fmd_strdup(value, FMD_SLEEP);
	cdp->cd_next = cfp->cf_defer;

	cfp->cf_defer = cdp;
out:
	(void) pthread_rwlock_unlock(&cfp->cf_lock);
	return (0);
}

int
fmd_conf_setprop(fmd_conf_t *cfp, const char *name, const char *value)
{
	fmd_conf_param_t *pp;
	int err;

	if (strchr(name, ':') != NULL)
		return (fmd_conf_setdefer(cfp, name, value));

	(void) pthread_rwlock_wrlock(&cfp->cf_lock);

	if ((pp = fmd_conf_getparam(cfp, name)) != NULL)
		err = pp->cp_formal->cf_ops->co_set(pp, value);
	else
		err = fmd_set_errno(EFMD_CONF_NOPROP);

	(void) pthread_rwlock_unlock(&cfp->cf_lock);
	return (err);
}

int
fmd_conf_delprop(fmd_conf_t *cfp, const char *name, const char *value)
{
	fmd_conf_param_t *pp;
	int err;

	(void) pthread_rwlock_wrlock(&cfp->cf_lock);

	if ((pp = fmd_conf_getparam(cfp, name)) != NULL)
		err = pp->cp_formal->cf_ops->co_del(pp, value);
	else
		err = fmd_set_errno(EFMD_CONF_NOPROP);

	(void) pthread_rwlock_unlock(&cfp->cf_lock);
	return (err);
}
