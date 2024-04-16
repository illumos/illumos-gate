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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <libintl.h>
#include <libnvpair.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "notify_params.h"

static struct events {
	const char *s;
	int32_t c;
} smf_st_events[] = {
	{ "to-uninitialized", SCF_TRANS(0, SCF_STATE_UNINIT) },
	{ "from-uninitialized",	SCF_TRANS(SCF_STATE_UNINIT, 0) },
	{ "uninitialized", SCF_TRANS(SCF_STATE_UNINIT, SCF_STATE_UNINIT) },
	{ "to-maintenance", SCF_TRANS(0, SCF_STATE_MAINT) },
	{ "from-maintenance", SCF_TRANS(SCF_STATE_MAINT, 0) },
	{ "maintenance", SCF_TRANS(SCF_STATE_MAINT, SCF_STATE_MAINT) },
	{ "to-offline", SCF_TRANS(0, SCF_STATE_OFFLINE) },
	{ "from-offline", SCF_TRANS(SCF_STATE_OFFLINE, 0) },
	{ "offline", SCF_TRANS(SCF_STATE_OFFLINE, SCF_STATE_OFFLINE) },
	{ "to-disabled", SCF_TRANS(0, SCF_STATE_DISABLED) },
	{ "from-disabled", SCF_TRANS(SCF_STATE_DISABLED, 0) },
	{ "disabled", SCF_TRANS(SCF_STATE_DISABLED, SCF_STATE_DISABLED) },
	{ "to-online", SCF_TRANS(0, SCF_STATE_ONLINE) },
	{ "from-online", SCF_TRANS(SCF_STATE_ONLINE, 0) },
	{ "online", SCF_TRANS(SCF_STATE_ONLINE, SCF_STATE_ONLINE) },
	{ "to-degraded", SCF_TRANS(0, SCF_STATE_DEGRADED) },
	{ "from-degraded", SCF_TRANS(SCF_STATE_DEGRADED, 0) },
	{ "degraded", SCF_TRANS(SCF_STATE_DEGRADED, SCF_STATE_DEGRADED) },
	{ "to-all", SCF_TRANS(0, SCF_STATE_ALL) },
	{ "from-all", SCF_TRANS(SCF_STATE_ALL, 0) },
	{ "all", SCF_TRANS(SCF_STATE_ALL, SCF_STATE_ALL) },
	{ NULL, 0 }
};

static struct fma_tags {
	const char *t;
	const char *s;
} fma_tags[] = {
	{ "problem-diagnosed", "list.suspect" },
	{ "problem-updated", "list.updated" },
	{ "problem-repaired", "list.repaired" },
	{ "problem-resolved", "list.resolved" },
	{ NULL, NULL }
};

static char *fma_classes[] = {
	"list.",
	"ireport.",
	NULL
};

/*
 * get_fma_tag()
 * return a pointer to the fma tag at the passed index. NULL if no entry exist
 * for index
 */
const char *
get_fma_tag(uint32_t index)
{
	if (index >= (sizeof (fma_tags) / sizeof (struct fma_tags)))
		return (NULL);

	return (fma_tags[index].t);
}

/*
 * get_fma_class()
 * return a pointer to the fma class at the passed index. NULL if no entry exist
 * for index
 */
const char *
get_fma_class(uint32_t index)
{
	if (index >= (sizeof (fma_tags) / sizeof (struct fma_tags)))
		return (NULL);

	return (fma_tags[index].s);
}

/*
 * is_fma_token()
 * check if the parameter is an fma token by comparing with the
 * fma_classes[] and the fma_tags[] arrays.
 */
int
is_fma_token(const char *t)
{
	int i;

	for (i = 0; fma_classes[i]; ++i)
		if (strncmp(t, fma_classes[i], strlen(fma_classes[i])) == 0)
			return (1);

	for (i = 0; fma_tags[i].t; ++i)
		if (strcmp(t, fma_tags[i].t) == 0)
			return (1);

	return (0);
}

/*
 * has_fma_tag()
 * returns 1 if there is an fma tag for the passed class, 0 otherwise
 */
int
has_fma_tag(const char *c)
{
	int i;

	for (i = 0; fma_tags[i].s; ++i)
		if (strcmp(c, fma_tags[i].s) == 0)
			return (1);

	return (0);
}

const char *
de_tag(const char *tag)
{
	int i;

	for (i = 0; fma_tags[i].t; ++i)
		if (strcmp(tag, fma_tags[i].t) == 0)
			return (fma_tags[i].s);

	return (tag);
}

const char *
re_tag(const char *fma_event)
{
	int i;

	for (i = 0; fma_tags[i].s; ++i)
		if (strcmp(fma_event, fma_tags[i].s) == 0)
			return (fma_tags[i].t);

	return (fma_event);
}

int32_t
string_to_tset(const char *str)
{
	int i;

	for (i = 0; smf_st_events[i].s != NULL; ++i) {
		if (strcmp(str, smf_st_events[i].s) == 0)
			return (smf_st_events[i].c);
	}

	return (0);
}

const char *
tset_to_string(int32_t t)
{
	int i;

	for (i = 0; smf_st_events[i].s != NULL; ++i) {
		if (smf_st_events[i].c == t)
			return (smf_st_events[i].s);
	}

	return (NULL);
}

void
safe_printf(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	if (vprintf(fmt, va) < 0)
		uu_die(gettext("Error writing to stdout"));
	va_end(va);
}

static uint32_t
notify_params_get_version(nvlist_t *nvl)
{
	uint32_t v;

	if (nvl == NULL)
		return (0xFFFFFFFFU);

	if (nvlist_lookup_uint32(nvl, SCF_NOTIFY_NAME_VERSION, &v) != 0)
		return (0xFFFFFFFFU);
	else
		return (v);
}

static void
nvpair_print(nvpair_t *p)
{
	char **v;
	uint_t n;
	int i;

	safe_printf("            %s:", nvpair_name(p));
	(void) nvpair_value_string_array(p, &v, &n);
	for (i = 0; i < n; ++i) {
		safe_printf(" %s", v[i]);
	}
	safe_printf("\n");
}

static void
params_type_print(nvlist_t *p, const char *name, const char *fmri)
{
	nvpair_t *tnvp, *nvp;
	nvlist_t *nvl;
	boolean_t *a;
	uint_t n;
	int has_output = 0;

	/* for each event e print all notification parameters */
	for (tnvp = nvlist_next_nvpair(p, NULL); tnvp != NULL;
	    tnvp = nvlist_next_nvpair(p, tnvp)) {
		/* We only want the NVLIST memebers */
		if (nvpair_type(tnvp) != DATA_TYPE_NVLIST)
			continue;

		if (nvpair_value_nvlist(tnvp, &nvl) != 0)
			uu_die("nvpair_value_nvlist");

		if (!has_output) {
			if (fmri == NULL) {
				safe_printf(gettext("    Event: %s\n"), name);
			} else {
				safe_printf(gettext(
				    "    Event: %s (source: %s)\n"),
				    name, fmri);
			}
		}

		has_output = 1;

		safe_printf(gettext("        Notification Type: %s\n"),
		    nvpair_name(tnvp));

		if (nvlist_lookup_boolean_array(nvl, PARAM_ACTIVE, &a, &n) != 0)
			uu_warn(gettext("Missing 'active' property"));
		else
			safe_printf(gettext("            Active: %s\n"),
			    *a ? "true" : "false");

		for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(nvl, nvp)) {
			if (nvpair_type(nvp) != DATA_TYPE_STRING_ARRAY)
				continue;
			nvpair_print(nvp);
		}
		safe_printf("\n");
	}
}

void
listnotify_print(nvlist_t *nvl, const char *event)
{
	char *fmri;
	nvlist_t **params;
	size_t n;
	int32_t tset;
	int i;

	/*
	 * Check the nvl we got is from a version we understand
	 */
	if (nvl != NULL && notify_params_get_version(nvl) !=
	    SCF_NOTIFY_PARAMS_VERSION)
		uu_die(gettext("libscf(3LIB) mismatch\n"));

	if (nvl != NULL && nvlist_lookup_nvlist_array(nvl, SCF_NOTIFY_PARAMS,
	    &params, &n) != 0)
		/* Sanity check. If we get here nvl is bad! */
		uu_die(gettext("nvlist_lookup_nvlist_array\n"));

	if (event == NULL) {
		/* this is an SMF state transition nvlist */
		for (i = 0; i < n; ++i) {
			nvlist_t *p = *(params + i);

			if (nvlist_lookup_string(p,
			    SCF_NOTIFY_PARAMS_SOURCE_NAME, &fmri) != 0)
				fmri = NULL;
			if (nvlist_lookup_int32(p, SCF_NOTIFY_NAME_TSET,
			    &tset) != 0)
				uu_die("nvlist_lookup_int32");
			params_type_print(p, tset_to_string(tset), fmri);
		}
	} else {
		/* this is FMA event nvlist */
		if (nvl == NULL) { /* preferences not found */
			return;
		}
		for (i = 0; i < n; ++i) {
			nvlist_t *p = *(params + i);

			if (nvlist_lookup_string(p,
			    SCF_NOTIFY_PARAMS_SOURCE_NAME, &fmri) != 0)
				fmri = NULL;
			params_type_print(p, event, fmri);
		}
	}
}
