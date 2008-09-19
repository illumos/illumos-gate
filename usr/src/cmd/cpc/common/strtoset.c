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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <errno.h>
#include <libintl.h>

#include "libcpc.h"

/*
 * Takes a string and converts it to a cpc_set_t.
 *
 * While processing the string using getsubopt(), we will use an array of
 * requests to hold the data, and a proprietary representation of attributes
 * which allow us to avoid a realloc()/bcopy() dance every time we come across
 * a new attribute.
 *
 * Not until after the string has been processed in its entirety do we
 * allocate and specify a request set properly.
 */

/*
 * Leave enough room in token strings for picn, nousern, or sysn where n is
 * picnum.
 */
#define	TOK_SIZE	10

typedef struct __tmp_attr {
	char			*name;
	uint64_t		val;
	struct __tmp_attr	*next;
} tmp_attr_t;

typedef struct __tok_info {
	char			*name;
	int			picnum;
} tok_info_t;

typedef struct __request_t {
	char			cr_event[CPC_MAX_EVENT_LEN];
	uint_t			cr_flags;
	uint_t			cr_nattrs;	/* # CPU-specific attrs */
} request_t;

static void strtoset_cleanup(void);
static void smt_special(int picnum);
static void *emalloc(size_t n);

/*
 * Clients of cpc_strtoset may set this to specify an error handler during
 * string parsing.
 */
cpc_errhndlr_t		*strtoset_errfn = NULL;

static request_t	*reqs;
static int		nreqs;
static int		ncounters;

static tmp_attr_t	**attrs;
static int		ntoks;
static char		**toks;
static tok_info_t	*tok_info;
static int		(*(*tok_funcs))(int, char *);
static char		**attrlist;	/* array of ptrs to toks in attrlistp */
static int		nattrs;
static cpc_t		*cpc;
static int		found;

static void
strtoset_err(const char *fmt, ...)
{
	va_list ap;

	if (strtoset_errfn == NULL)
		return;

	va_start(ap, fmt);
	(*strtoset_errfn)("cpc_strtoset", -1, fmt, ap);
	va_end(ap);
}

/*ARGSUSED*/
static void
event_walker(void *arg, uint_t picno, const char *event)
{
	if (strncmp(arg, event, CPC_MAX_EVENT_LEN) == 0)
		found = 1;
}

static int
event_valid(int picnum, char *event)
{
	char *end_event;
	found = 0;


	cpc_walk_events_pic(cpc, picnum, event, event_walker);

	if (found)
		return (1);

	cpc_walk_generic_events_pic(cpc, picnum, event, event_walker);

	if (found)
		return (1);

	/*
	 * Before assuming this is an invalid event, see if we have been given
	 * a raw event code. An event code of '0' is not recognized, as it
	 * already has a corresponding event name in existing backends and it
	 * is the only reasonable way to know if strtol() succeeded.
	 * Check the second argument of strtol() to ensure invalid events
	 * beginning with number do not go through.
	 */
	if ((strtol(event, &end_event, 0) != 0) && (*end_event == '\0'))
		/*
		 * Success - this is a valid raw code in hex, decimal, or octal.
		 */
		return (1);

	return (0);
}

/*
 * An unknown token was encountered; check here if it is an implicit event
 * name. We allow users to omit the "picn=" portion of the event spec, and
 * assign such events to available pics in order they are returned from
 * getsubopt(3C). We start our search for an available pic _after_ the highest
 * picnum to be assigned. This ensures that the event spec can never be out of
 * order; i.e. if the event string is "eventa,eventb" we must ensure that the
 * picnum counting eventa is less than the picnum counting eventb.
 */
static int
find_event(char *event)
{
	int i;

	/*
	 * Event names cannot have '=' in them. If present here, it means we
	 * have encountered an unknown token (foo=bar, for example).
	 */
	if (strchr(event, '=') != NULL)
		return (0);

	/*
	 * Find the first unavailable pic, after which we must start our search.
	 */
	for (i = ncounters - 1; i >= 0; i--) {
		if (reqs[i].cr_event[0] != '\0')
			break;
	}
	/*
	 * If the last counter has been assigned, we cannot place this event.
	 */
	if (i == ncounters - 1)
		return (0);

	/*
	 * If none of the counters have been assigned yet, i is -1 and we will
	 * begin our search at 0. Else we begin our search at the counter after
	 * the last one currently assigned.
	 */
	i++;

	for (; i < ncounters; i++) {
		if (event_valid(i, event) == 0)
			continue;

		nreqs++;
		(void) strncpy(reqs[i].cr_event, event, CPC_MAX_EVENT_LEN);
		return (1);
	}

	return (0);
}

static int
pic(int tok, char *val)
{
	int picnum = tok_info[tok].picnum;
	/*
	 * Make sure the each pic only appears in the spec once.
	 */
	if (reqs[picnum].cr_event[0] != '\0') {
		strtoset_err(gettext("repeated 'pic%d' token\n"), picnum);
		return (-1);
	}

	if (val == NULL || val[0] == '\0') {
		strtoset_err(gettext("missing 'pic%d' value\n"), picnum);
		return (-1);
	}

	if (event_valid(picnum, val) == 0) {
		strtoset_err(gettext("pic%d cannot measure event '%s' on this "
		    "cpu\n"), picnum, val);
		return (-1);
	}

	nreqs++;
	(void) strncpy(reqs[picnum].cr_event, val, CPC_MAX_EVENT_LEN);
	return (0);
}

/*
 * We explicitly ignore any value provided for these tokens, as their
 * mere presence signals us to turn on or off the relevant flags.
 */
/*ARGSUSED*/
static int
flag(int tok, char *val)
{
	int i;
	int picnum = tok_info[tok].picnum;

	/*
	 * If picnum is -1, this flag should be applied to all reqs.
	 */
	for (i = (picnum == -1) ? 0 : picnum; i < ncounters; i++) {
		if (strcmp(tok_info[tok].name, "nouser") == 0)
			reqs[i].cr_flags &= ~CPC_COUNT_USER;
		else if (strcmp(tok_info[tok].name, "sys") == 0)
			reqs[i].cr_flags |= CPC_COUNT_SYSTEM;
		else
			return (-1);

		if (picnum != -1)
			break;
	}

	return (0);
}

static int
doattr(int tok, char *val)
{
	int		i;
	int		picnum = tok_info[tok].picnum;
	tmp_attr_t	*tmp;
	char		*endptr;

	/*
	 * If picnum is -1, this attribute should be applied to all reqs.
	 */
	for (i = (picnum == -1) ? 0 : picnum; i < ncounters; i++) {
		tmp = (tmp_attr_t *)emalloc(sizeof (tmp_attr_t));
		tmp->name = tok_info[tok].name;
		if (val != NULL) {
			tmp->val = strtoll(val, &endptr, 0);
			if (endptr == val) {
				strtoset_err(gettext("invalid value '%s' for "
				    "attribute '%s'\n"), val, tmp->name);
				free(tmp);
				return (-1);
			}
		} else
			/*
			 * No value was provided for this attribute,
			 * so specify a default value of 1.
			 */
			tmp->val = 1;

		tmp->next = attrs[i];
		attrs[i] = tmp;
		reqs[i].cr_nattrs++;

		if (picnum != -1)
			break;
	}

	return (0);
}

/*ARGSUSED*/
static void
attr_count_walker(void *arg, const char *attr)
{
	/*
	 * We don't allow picnum to be specified by the user.
	 */
	if (strncmp(attr, "picnum", 7) == 0)
		return;
	(*(int *)arg)++;
}

static int
cpc_count_attrs(cpc_t *cpc)
{
	int nattrs = 0;

	cpc_walk_attrs(cpc, &nattrs, attr_count_walker);

	return (nattrs);
}

static void
attr_walker(void *arg, const char *attr)
{
	int *i = arg;

	if (strncmp(attr, "picnum", 7) == 0)
		return;

	if ((attrlist[(*i)++] = strdup(attr)) == NULL) {
		strtoset_err(gettext("no memory available\n"));
		exit(0);
	}
}

cpc_set_t *
cpc_strtoset(cpc_t *cpcin, const char *spec, int smt)
{
	cpc_set_t		*set;
	cpc_attr_t		*req_attrs;
	tmp_attr_t		*tmp;
	size_t			toklen;
	int			i;
	int			j;
	int			x;
	char			*opts;
	char			*val;

	cpc = cpcin;
	nattrs = 0;

	ncounters = cpc_npic(cpc);

	reqs = (request_t *)emalloc(ncounters * sizeof (request_t));

	attrs = (tmp_attr_t **)emalloc(ncounters * sizeof (tmp_attr_t *));

	for (i = 0; i < ncounters; i++) {
		reqs[i].cr_event[0] = '\0';
		reqs[i].cr_flags = CPC_COUNT_USER;
		/*
		 * Each pic will have at least one attribute: the physical pic
		 * assignment via the "picnum" attribute. Set that up here for
		 * each request.
		 */
		reqs[i].cr_nattrs = 1;
		attrs[i] = emalloc(sizeof (tmp_attr_t));
		attrs[i]->name = "picnum";
		attrs[i]->val = i;
		attrs[i]->next = NULL;
	}

	/*
	 * Build up a list of acceptable tokens.
	 *
	 * Permitted tokens are
	 * picn=event
	 * nousern
	 * sysn
	 * attrn=val
	 * nouser
	 * sys
	 * attr=val
	 *
	 * Where n is a counter number, and attr is any attribute supported by
	 * the current processor.
	 *
	 * If a token appears without a counter number, it applies to all
	 * counters in the request set.
	 *
	 * The number of tokens is:
	 *
	 * picn: ncounters
	 * generic flags: 2 * ncounters (nouser, sys)
	 * attrs: nattrs * ncounters
	 * attrs with no picnum: nattrs
	 * generic flags with no picnum: 2 (nouser, sys)
	 * NULL token to signify end of list to getsubopt(3C).
	 *
	 * Matching each token's index in the token table is a function which
	 * process that token; these are in tok_funcs.
	 */

	/*
	 * Count the number of valid attributes.
	 * Set up the attrlist array to point to the attributes in attrlistp.
	 */
	nattrs = cpc_count_attrs(cpc);
	attrlist = (char **)emalloc(nattrs * sizeof (char *));

	i = 0;
	cpc_walk_attrs(cpc, &i, attr_walker);

	ntoks = ncounters + (2 * ncounters) + (nattrs * ncounters) + nattrs + 3;
	toks = (char **)emalloc(ntoks * sizeof (char *));
	tok_info = (tok_info_t *)emalloc(ntoks * sizeof (tok_info_t));

	tok_funcs = (int (**)(int, char *))emalloc(ntoks *
	    sizeof (int (*)(char *)));

	for (i = 0; i < ntoks; i++) {
		toks[i] = NULL;
		tok_funcs[i] = NULL;
	}

	x = 0;
	for (i = 0; i < ncounters; i++) {
		toks[x] = (char *)emalloc(TOK_SIZE);
		(void) snprintf(toks[x], TOK_SIZE, "pic%d", i);
		tok_info[x].name = "pic";
		tok_info[i].picnum = i;
		tok_funcs[x] = pic;
		x++;
	}

	for (i = 0; i < ncounters; i++) {
		toks[x] = (char *)emalloc(TOK_SIZE);
		(void) snprintf(toks[x], TOK_SIZE, "nouser%d", i);
		tok_info[x].name = "nouser";
		tok_info[x].picnum = i;
		tok_funcs[x] = flag;
		x++;
	}

	for (i = 0; i < ncounters; i++) {
		toks[x] = (char *)emalloc(TOK_SIZE);
		(void) snprintf(toks[x], TOK_SIZE, "sys%d", i);
		tok_info[x].name = "sys";
		tok_info[x].picnum = i;
		tok_funcs[x] = flag;
		x++;
	}
	for (j = 0; j < nattrs; j++) {
		toklen = strlen(attrlist[j]) + 3;
		for (i = 0; i < ncounters; i++) {
			toks[x] = (char *)emalloc(toklen);
			(void) snprintf(toks[x], toklen, "%s%d", attrlist[j],
			    i);
			tok_info[x].name = attrlist[j];
			tok_info[x].picnum = i;
			tok_funcs[x] = doattr;
			x++;
		}

		/*
		 * Now create a token for this attribute with no picnum; if used
		 * it will be applied to all reqs.
		 */
		toks[x] = (char *)emalloc(toklen);
		(void) snprintf(toks[x], toklen, "%s", attrlist[j]);
		tok_info[x].name = attrlist[j];
		tok_info[x].picnum = -1;
		tok_funcs[x] = doattr;
		x++;
	}

	toks[x] = "nouser";
	tok_info[x].name = "nouser";
	tok_info[x].picnum = -1;
	tok_funcs[x] = flag;
	x++;

	toks[x] = "sys";
	tok_info[x].name = "sys";
	tok_info[x].picnum = -1;
	tok_funcs[x] = flag;
	x++;

	toks[x] = NULL;

	opts = strcpy(alloca(strlen(spec) + 1), spec);
	while (*opts != '\0') {
		int idx = getsubopt(&opts, toks, &val);

		if (idx == -1) {
			if (find_event(val) == 0) {
				strtoset_err(gettext("bad token '%s'\n"), val);
				goto inval;
			} else
				continue;
		}

		if (tok_funcs[idx](idx, val) == -1)
			goto inval;
	}

	/*
	 * The string has been processed. Now count how many PICs were used,
	 * create a request set, and specify each request properly.
	 */

	if ((set = cpc_set_create(cpc)) == NULL) {
		strtoset_err(gettext("no memory available\n"));
		exit(0);
	}

	for (i = 0; i < ncounters; i++) {
		if (reqs[i].cr_event[0] == '\0')
			continue;

		/*
		 * If the caller wishes to measure events on the physical CPU,
		 * we need to add SMT attributes to each request.
		 */
		if (smt)
			smt_special(i);

		req_attrs = (cpc_attr_t *)emalloc(reqs[i].cr_nattrs *
		    sizeof (cpc_attr_t));

		j = 0;
		for (tmp = attrs[i]; tmp != NULL; tmp = tmp->next) {
			req_attrs[j].ca_name = tmp->name;
			req_attrs[j].ca_val = tmp->val;
			j++;
		}

		if (cpc_set_add_request(cpc, set, reqs[i].cr_event, 0,
		    reqs[i].cr_flags, reqs[i].cr_nattrs, req_attrs) == -1) {
			free(req_attrs);
			(void) cpc_set_destroy(cpc, set);
			strtoset_err(
			    gettext("cpc_set_add_request() failed: %s\n"),
			    strerror(errno));
			goto inval;
		}

		free(req_attrs);
	}

	strtoset_cleanup();

	return (set);

inval:
	strtoset_cleanup();
	errno = EINVAL;
	return (NULL);
}

static void
strtoset_cleanup(void)
{
	int		i;
	tmp_attr_t	*tmp, *p;

	for (i = 0; i < nattrs; i++)
		free(attrlist[i]);
	free(attrlist);

	for (i = 0; i < ncounters; i++) {
		for (tmp = attrs[i]; tmp != NULL; tmp = p) {
			p = tmp->next;
			free(tmp);
		}
	}
	free(attrs);

	for (i = 0; i < ntoks - 3; i++)
		/*
		 * We free all but the last three tokens: "nouser", "sys", NULL
		 */
		free(toks[i]);
	free(toks);
	free(reqs);
	free(tok_info);
	free(tok_funcs);
}

/*
 * The following is called to modify requests so that they count events on
 * behalf of a physical processor, instead of a logical processor. It duplicates
 * the request flags for the sibling processor (i.e. if the request counts user
 * events, add an attribute to count user events on the sibling processor also).
 */
static void
smt_special(int picnum)
{
	tmp_attr_t *attr;

	if (reqs[picnum].cr_flags & CPC_COUNT_USER) {
		attr = (tmp_attr_t *)emalloc(sizeof (tmp_attr_t));
		attr->name = "count_sibling_usr";
		attr->val = 1;
		attr->next = attrs[picnum];
		attrs[picnum] = attr;
		reqs[picnum].cr_nattrs++;
	}

	if (reqs[picnum].cr_flags & CPC_COUNT_SYSTEM) {
		attr = (tmp_attr_t *)emalloc(sizeof (tmp_attr_t));
		attr->name = "count_sibling_sys";
		attr->val = 1;
		attr->next = attrs[picnum];
		attrs[picnum] = attr;
		reqs[picnum].cr_nattrs++;
	}
}

/*
 * If we ever fail to get memory, we print an error message and exit.
 */
static void *
emalloc(size_t n)
{
	void *p = malloc(n);

	if (p == NULL) {
		strtoset_err(gettext("no memory available\n"));
		exit(0);
	}

	return (p);
}
