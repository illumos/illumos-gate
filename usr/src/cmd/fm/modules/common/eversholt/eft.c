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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <fm/fmd_api.h>
#include <libnvpair.h>
#include <fm/libtopo.h>
#include "out.h"
#include "stats.h"
#include "alloc.h"
#include "stable.h"
#include "literals.h"
#include "lut.h"
#include "esclex.h"
#include "tree.h"
#include "ipath.h"
#include "itree.h"
#include "iexpr.h"
#include "ptree.h"
#include "check.h"
#include "version.h"
#include "fme.h"
#include "eval.h"
#include "config.h"
#include "platform.h"

/*
 * eversholt diagnosis engine (eft.so) main entry points
 */

fmd_hdl_t *Hdl;		/* handle in global for platform.c */

int Debug = 1;	/* turn on here and let fmd_hdl_debug() decide if really on */
char *Autoclose;	/* close cases automatically after solving */
hrtime_t Hesitate;	/* hesitation time in ns */
char *Serd_Override;	/* override for Serd engines */
int Verbose;
int Estats;
int Warn;	/* zero -- eft.so should not issue language warnings */
char **Efts;
int Max_fme;		/* Maximum number of open FMEs */

/* stuff exported by yacc-generated parsers */
extern void yyparse(void);
extern int yydebug;

extern struct lut *Dicts;

extern void literals_init(void);
extern void literals_fini(void);

struct eftsubr {
	const char *prefix;
	void (*hdlr)(fmd_hdl_t *, fmd_event_t *, nvlist_t *, const char *);
} eftsubrs[] = {
	{ "ereport.",		fme_receive_external_report },
	{ "list.repaired",	fme_receive_repair_list },
	{ NULL,			NULL }
};

/*ARGSUSED*/
static void
eft_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	struct eftsubr *sp = eftsubrs;

	while (sp->prefix != NULL) {
		if (strncmp(class, sp->prefix, strlen(sp->prefix)) == 0)
			break;
		sp++;
	}

	if (sp->prefix != NULL) {
		(sp->hdlr)(hdl, ep, nvl, class);
	} else {
		out(O_DIE,
		    "eft_recv: event class \"%s\" does not match our "
		    "subscriptions", class);
	}
}

/*ARGSUSED*/
static void
eft_timeout(fmd_hdl_t *hdl, id_t tid, void *arg)
{
	out(O_ALTFP|O_STAMP,
	    "\neft.so timer %ld fired with arg %p", tid, arg);

	if (arg == NULL)
		return;

	fme_timer_fired(arg, tid);
}

static void
eft_close(fmd_hdl_t *hdl, fmd_case_t *fmcase)
{
	out(O_ALTFP, "eft_close called for case %s",
	    fmd_case_uuid(hdl, fmcase));
	fme_close_case(hdl, fmcase);
}

/*
 * The "serd_override" property allows the N and T parameters of specified serd
 * engines to be overridden. The property is a string consisting of one or more
 * space separated triplets. Each triplet is of the form "name,N,T" where "name"
 * is the name of the serd engine and N and T are the new paremeters to use.
 * For example "serd.io.device.nonfatal,5,3h" would set the parameters for the
 * serd.io.device.nonfatal engine to 5 in 3 hours.
 */
static const fmd_prop_t eft_props[] = {
	{ "autoclose", FMD_TYPE_STRING, NULL },
	{ "estats", FMD_TYPE_BOOL, "false" },
	{ "hesitate", FMD_TYPE_INT64, "10000000000" },
	{ "serd_override", FMD_TYPE_STRING, NULL },
	{ "verbose", FMD_TYPE_INT32, "0" },
	{ "warn", FMD_TYPE_BOOL, "false" },
	{ "status", FMD_TYPE_STRING, NULL },
	{ "maxfme", FMD_TYPE_INT32, "0" },
	{ NULL, 0, NULL }
};

/*ARGSUSED*/
static void
eft_topo_change(fmd_hdl_t *hdl, topo_hdl_t *thp)
{
	fme_receive_topology_change();
}

static const fmd_hdl_ops_t eft_ops = {
	eft_recv,	/* fmdo_recv */
	eft_timeout,	/* fmdo_timeout */
	eft_close,	/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
	NULL,		/* fmdo_send */
	eft_topo_change	/* fmdo_topo_change */
};

#define	xstr(s) str(s)
#define	str(s) #s

static const fmd_hdl_info_t fmd_info = {
	"eft diagnosis engine",
	xstr(VERSION_MAJOR) "." xstr(VERSION_MINOR),
	&eft_ops, eft_props
};

/*
 * ename_strdup -- like strdup but ename comes in and class string goes out
 */
static char *
ename_strdup(struct node *np)
{
	struct node *mynp;
	int len;
	char *buf;

	/* calculate length of buffer required */
	len = 0;
	for (mynp = np; mynp; mynp = mynp->u.name.next)
		len += strlen(mynp->u.name.s) + 1;	/* +1 for dot or NULL */

	buf = MALLOC(len);
	buf[0] = '\0';

	/* now build the string */
	while (np) {
		(void) strcat(buf, np->u.name.s);
		np = np->u.name.next;
		if (np)
			(void) strcat(buf, ".");
	}

	return (buf);
}

/*ARGSUSED*/
static void
dosubscribe(struct node *lhs, struct node *rhs, void *arg)
{
	char *ename = ename_strdup(lhs);

	out(O_DEBUG, "subscribe: \"%s\"", ename);
	fmd_hdl_subscribe(Hdl, ename);
	FREE(ename);
}

extern struct stats *Filecount;

/*
 * Call all of the _fini() routines to clean up the exiting DE
 */
void
call_finis(void)
{
	platform_free_eft_files(Efts);
	Efts = NULL;
	platform_fini();
	fme_fini();
	itree_fini();
	ipath_fini();
	iexpr_fini();
	istat_fini();
	serd_fini();
	lex_free();
	check_fini();
	tree_fini();
	lut_fini();
	literals_fini();
	stable_fini();
	stats_fini();
	out_fini();
	alloc_fini();
}

/*ARGSUSED*/
static void
doopendict(const char *lhs, void *rhs, void *arg)
{
	out(O_DEBUG, "opendict: \"%s\"", lhs);
	fmd_hdl_opendict(Hdl, lhs);
}

void
_fmd_init(fmd_hdl_t *hdl)
{
	fmd_case_t *casep = NULL;
	int count;
	char *fname;

	(void) fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info);

	/* keep handle for routines like out() which need it */
	Hdl = hdl;

	Estats = fmd_prop_get_int32(hdl, "estats");

	alloc_init();
	out_init("eft");
	stats_init(Estats);
	stable_init(0);
	literals_init();
	platform_init();
	lut_init();
	tree_init();
	ipath_init();
	iexpr_init();
	Efts = platform_get_eft_files();
	lex_init(Efts, NULL, 0);
	check_init();

	/*
	 *  If we read no .eft files, we can't do any
	 *  diagnosing, so we just unload ourselves
	 */
	if (stats_counter_value(Filecount) == 0) {
		(void) lex_fini();
		call_finis();
		fmd_hdl_debug(hdl, "no fault trees provided.");
		fmd_hdl_unregister(hdl);
		return;
	}

	yyparse();
	(void) lex_fini();
	tree_report();
	if (count = out_errcount())
		out(O_DIE, "%d language error%s encountered, exiting.",
		    OUTS(count));

	/* subscribe to events we expect to consume */
	lut_walk(Ereportenames, (lut_cb)dosubscribe, NULL);

	/* subscribe to repair events so we can clear state on repair */
	fmd_hdl_subscribe(hdl, "list.repaired");

	/* open dictionaries referenced by all .eft files */
	lut_walk(Dicts, (lut_cb)doopendict, (void *)0);

	Verbose = fmd_prop_get_int32(hdl, "verbose");
	Warn = fmd_prop_get_int32(hdl, "warn");
	Autoclose = fmd_prop_get_string(hdl, "autoclose");
	Hesitate = fmd_prop_get_int64(hdl, "hesitate");
	Serd_Override = fmd_prop_get_string(hdl, "serd_override");
	Max_fme = fmd_prop_get_int32(hdl, "maxfme");

	if ((fname = fmd_prop_get_string(hdl, "status")) != NULL) {
		FILE *fp;

		if ((fp = fopen(fname, "a")) == NULL) {
			fmd_prop_free_string(hdl, fname);
			out(O_DIE|O_SYS, "status property file: %s", fname);
		}

		(void) setlinebuf(fp);
		out_altfp(fp);

		out(O_DEBUG, "appending status changes to \"%s\"", fname);
		fmd_prop_free_string(hdl, fname);

		out(O_ALTFP|O_STAMP, "\neft.so startup");
	}

	out(O_DEBUG, "initialized, verbose %d warn %d autoclose %s "
	    "maxfme %d", Verbose, Warn, Autoclose == NULL ? "(NULL)" :
	    Autoclose, Max_fme);

	fme_istat_load(hdl);
	fme_serd_load(hdl);

	out(O_DEBUG, "reconstituting any existing fmes");
	while ((casep = fmd_case_next(hdl, casep)) != NULL) {
		fme_restart(hdl, casep);
	}
}

/*ARGSUSED*/
void
_fmd_fini(fmd_hdl_t *hdl)
{
	fmd_prop_free_string(hdl, Autoclose);
	Autoclose = NULL;
	call_finis();
}
