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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * config.c -- system configuration cache module
 *
 * this module caches the system configuration in a format useful
 * to eft.  the information is loaded into this module by
 * config_snapshot() at the beginning of each FME.  config_snapshot()
 * calls the platform-specific platform_config_snapshot() to get
 * the configuration information loaded up.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <fm/topo_hc.h>
#include "alloc.h"
#include "out.h"
#include "literals.h"
#include "stable.h"
#include "lut.h"
#include "tree.h"
#include "itree.h"
#include "ipath.h"
#include "ptree.h"
#include "eval.h"
#include "config.h"
#include "fme.h"
#include "platform.h"

/*
 * private data structure for storing config.  all access to
 * to this information happens using the config.h interfaces.
 */
struct config {
	struct config *next;
	struct config *child;
	struct config *parent;
	const char *s;
	int num;
	struct lut *props;
};

static const char *config_lastcomp;

/*
 * newcnode -- local function to allocate new config node
 */
static struct config *
newcnode(const char *s, int num)
{
	struct config *retval;

	retval = MALLOC(sizeof (struct config));

	retval->s = s;
	retval->num = num;
	retval->next = NULL;
	retval->props = NULL;
	retval->child = retval->parent = NULL;

	return (retval);
}

/*
 * If we need to cache certain types of nodes for reverse look-up or
 * somesuch, do it here.  Currently we need to cache nodes representing
 * cpus.
 */
static void
config_node_cache(struct cfgdata *cdata, struct config *n)
{
	if (n->s != stable("cpu"))
		return;
	cdata->cpucache = lut_add(cdata->cpucache,
	    (void *)n->num, (void *)n, NULL);
}

/*
 * config_lookup -- lookup/add components in configuration cache
 */
struct config *
config_lookup(struct config *croot, char *path, int add)
{
	char *pathbegin = path;
	struct config *parent = croot;
	struct config *cp;
	struct config *lastcp;
	struct config *newnode;
	char *thiscom;	/* this component */
	char *nextcom;	/* next component */
	char svdigit;
	int len;
	int num;
	const char *s;
	int exists;

	if (parent == NULL)
		out(O_DIE, "uninitialized configuration");

	while (*path) {
		if ((nextcom = strchr(path, '/')) != NULL)
			*nextcom = '\0';
		if ((len = strlen(path)) == 0)
			out(O_DIE, "config_lookup: zero length component");
		/* start at end of string and work backwards */
		thiscom = &path[len - 1];
		if (!isdigit(*thiscom))
			out(O_DIE, "config_lookup: "
			    "component \"%s\" has no number following it",
			    path);
		while (thiscom > path && isdigit(*thiscom))
			thiscom--;
		if (thiscom == path && isdigit(*thiscom))
			out(O_DIE, "config_lookup: "
			    "component \"%s\" has no name part", path);
		thiscom++;	/* move to first numeric character */
		num = atoi(thiscom);
		svdigit = *thiscom;
		*thiscom = '\0';
		s = stable(path);
		if (add)
			config_lastcomp = s;
		*thiscom = svdigit;

		if (nextcom != NULL)
			*nextcom++ = '/';

		/* now we have s & num, figure out if it exists already */
		exists = 0;
		lastcp = NULL;
		for (cp = parent->child; cp; lastcp = cp, cp = cp->next)
			if (cp->s == s && cp->num == num) {
				exists = 1;
				parent = cp;
			}

		if (!exists) {
			/* creating new node */
			if (!add) {
				/*
				 * indicate component not found by copying
				 * it to path (allows better error messages
				 * in the caller).
				 */
				(void) strcpy(pathbegin, s);
				return (NULL);
			}

			newnode = newcnode(s, num);

			if (lastcp)
				lastcp->next = newnode;
			else
				parent->child = newnode;

			newnode->parent = parent;
			parent = newnode;
		}

		if (nextcom == NULL)
			return (parent);	/* all done */

		/* move on to next component */
		path = nextcom;
	}
	return (parent);
}

/*
 * addconfigprop -- add a config prop to a config cache entry
 */
static void
addconfigprop(const char *lhs, struct node *rhs, void *arg)
{
	struct config *cp = (struct config *)arg;

	ASSERT(cp != NULL);
	ASSERT(lhs != NULL);
	ASSERT(rhs != NULL);
	ASSERT(rhs->t == T_QUOTE);

	config_setprop(cp, lhs, STRDUP(rhs->u.quote.s));
}

/*
 * addconfig -- add a config from parse tree to given configuration cache
 */
/*ARGSUSED*/
static void
addconfig(struct node *lhs, struct node *rhs, void *arg)
{
	struct config *parent = (struct config *)arg;
	struct config *cp;
	const char *s;
	int num;
	struct config *lastcp;
	struct config *newnode;
	int exists;
	struct lut *lutp;

	ASSERT(rhs->t == T_CONFIG);

	lutp = rhs->u.stmt.lutp;
	rhs = rhs->u.stmt.np;
	while (rhs != NULL) {
		ASSERT(rhs->t == T_NAME);
		ASSERT(rhs->u.name.child->t == T_NUM);
		s = rhs->u.name.s;
		num = rhs->u.name.child->u.ull;

		/* now we have s & num, figure out if it exists already */
		exists = 0;
		lastcp = NULL;
		for (cp = parent->child; cp; lastcp = cp, cp = cp->next)
			if (cp->s == s && cp->num == num) {
				exists = 1;
				parent = cp;
			}

		if (!exists) {
			/* creating new node */

			newnode = newcnode(s, num);

			if (lastcp)
				lastcp->next = newnode;
			else
				parent->child = newnode;

			newnode->parent = parent;
			parent = newnode;
		}

		/* move on to next component */
		rhs = rhs->u.name.next;
	}

	/* add configuration properties */
	lut_walk(lutp, (lut_cb)addconfigprop, (void *)parent);
}

/*
 * config_cook -- convert raw config strings to eft internal representation
 */
void
config_cook(struct cfgdata *cdata)
{
	struct config *newnode;
	char *cfgstr, *equals;
	const char *pn, *sv;
	char *pv;
	const char *ptr;
	extern struct lut *Usedprops;
	extern struct lut *Usednames;

	cdata->cooked = newcnode(NULL, 0);

	if ((cfgstr = cdata->begin) == cdata->nextfree) {
		out(O_ALTFP|O_VERB, "Platform provided no config data.");
		goto eftcfgs;
	}

	/*
	 * add the following properties to the "usedprops" table as they
	 * are used internally by eft
	 */
	ptr = stable("module");
	Usedprops = lut_add(Usedprops, (void *)ptr, (void *)ptr, NULL);
	ptr = stable("resource");
	Usedprops = lut_add(Usedprops, (void *)ptr, (void *)ptr, NULL);
	ptr = stable("ASRU");
	Usedprops = lut_add(Usedprops, (void *)ptr, (void *)ptr, NULL);
	ptr = stable("FRU");
	Usedprops = lut_add(Usedprops, (void *)ptr, (void *)ptr, NULL);

	out(O_ALTFP|O_VERB3, "Raw config data follows:");
	out(O_ALTFP|O_VERB3|O_NONL,
	    "nextfree is %p\n%p ", (void *)cdata->nextfree, (void *)cfgstr);
	while (cfgstr < cdata->nextfree) {
		if (!*cfgstr)
			out(O_ALTFP|O_VERB3|O_NONL, "\n%p ",
			    (void *)(cfgstr + 1));
		else
			out(O_ALTFP|O_VERB3|O_NONL, "%c", *cfgstr);
		cfgstr++;
	}
	out(O_ALTFP|O_VERB3, NULL);

	cfgstr = cdata->begin;
	while (cfgstr < cdata->nextfree) {
		while (*cfgstr == '/' && cfgstr < cdata->nextfree) {
			out(O_ALTFP|O_VERB3,
			    "next string (%p) is %s", (void *)cfgstr, cfgstr);
			/* skip the initial slash from libtopo */
			newnode = config_lookup(cdata->cooked, cfgstr + 1, 1);
			/*
			 * Note we'll only cache nodes that have
			 * properties on them.  Intermediate nodes
			 * will have been added to the config tree,
			 * but we don't have easy means of accessing
			 * them except if we climb the tree from this
			 * newnode to the root.
			 *
			 * Luckily, the nodes we care to cache
			 * (currently just cpus) always have some
			 * properties attached to them
			 * so we don't bother climbing the tree.
			 */
			config_node_cache(cdata, newnode);
			cfgstr += strlen(cfgstr) + 1;
		}

		if (cfgstr >= cdata->nextfree)
			break;

		out(O_ALTFP|O_VERB3, "next string (%p) is %s", (void *)cfgstr,
		    cfgstr);
		if ((equals = strchr(cfgstr, '=')) == NULL) {
			out(O_ALTFP|O_VERB3, "raw config data bad (%p); "
			    "property missing equals.\n", (void *)cfgstr);
			break;
		}

		*equals = '\0';
		pn = stable(cfgstr);

		/*
		 * only actually add the props if the rules use them (saves
		 * memory)
		 */
		if ((lut_lookup(Usedprops, (void *)pn, NULL) != NULL ||
		    strncmp(pn, "serd_", 5) == 0) && lut_lookup(Usednames,
		    (void *)config_lastcomp, NULL) != NULL) {
			pv = STRDUP(equals + 1);
			out(O_ALTFP|O_VERB3, "add prop (%s) val %p", pn,
			    (void *)pv);
			config_setprop(newnode, pn, pv);
		}

		/*
		 * If this property is a device path, cache it for quick lookup
		 */
		if (pn == stable(TOPO_IO_DEV)) {
			sv = stable(equals + 1);
			out(O_ALTFP|O_VERB3, "caching %s\n", sv);
			cdata->devcache = lut_add(cdata->devcache,
			    (void *)sv, (void *)newnode, NULL);
		}

		*equals = '=';
		cfgstr += strlen(cfgstr) + 1;
	}

eftcfgs:
	/* now run through Configs table, adding to config cache */
	lut_walk(Configs, (lut_cb)addconfig, (void *)cdata->cooked);
}

/*
 * config_snapshot -- gather a snapshot of the current configuration
 */
struct cfgdata *
config_snapshot(void)
{
	struct cfgdata *rawcfg;

	rawcfg = platform_config_snapshot();
	config_cook(rawcfg);
	return (rawcfg);
}

/*
 * prop_destructor -- free a prop value
 */
/*ARGSUSED*/
static void
prop_destructor(void *left, void *right, void *arg)
{
	FREE(right);
}

/*
 * structconfig_free -- free a struct config pointer and all its relatives
 */
void
structconfig_free(struct config *cp)
{
	if (cp == NULL)
		return;

	structconfig_free(cp->child);
	structconfig_free(cp->next);
	lut_free(cp->props, prop_destructor, NULL);
	FREE(cp);
}

/*
 * config_free -- free a configuration snapshot
 */
void
config_free(struct cfgdata *cp)
{
	if (cp == NULL)
		return;

	if (--cp->raw_refcnt == 0) {
		if (cp->devcache != NULL)
			lut_free(cp->devcache, NULL, NULL);
		cp->devcache = NULL;
		if (cp->cpucache != NULL)
			lut_free(cp->cpucache, NULL, NULL);
		cp->cpucache = NULL;
		if (cp->begin != NULL)
			FREE(cp->begin);
		FREE(cp);
	}
}

/*
 * config_next -- get the "next" config node
 */
struct config *
config_next(struct config *cp)
{
	ASSERT(cp != NULL);

	return ((struct config *)((struct config *)cp)->next);
}


/*
 * config_child -- get the "child" of a config node
 */
struct config *
config_child(struct config *cp)
{
	ASSERT(cp != NULL);

	return ((struct config *)((struct config *)cp)->child);
}

/*
 * config_parent -- get the "parent" of a config node
 */
struct config *
config_parent(struct config *cp)
{
	ASSERT(cp != NULL);

	return ((struct config *)((struct config *)cp)->parent);
}

/*
 * config_setprop -- add a property to a config node
 */
void
config_setprop(struct config *cp, const char *propname, const char *propvalue)
{
	const char *pn = stable(propname);

	cp->props = lut_add(cp->props, (void *)pn, (void *)propvalue, NULL);
}

/*
 * config_getprop -- lookup a config property
 */
const char *
config_getprop(struct config *cp, const char *propname)
{
	return (lut_lookup(cp->props, (void *) stable(propname), NULL));
}

/*
 * config_getcompname -- get the component name of a config node
 */
void
config_getcompname(struct config *cp, char **name, int *inst)
{
	ASSERT(cp != NULL);

	if (name != NULL)
		*name = (char *)cp->s;
	if (inst != NULL)
		*inst = cp->num;
}

/*
 * config_nodeize -- convert the config element represented by cp to struct
 *		     node format
 */
static struct node *
config_nodeize(struct config *cp)
{
	struct node *tmpn, *ptmpn;
	struct node *numn;
	const char *sname;

	if (cp == NULL || cp->s == NULL)
		return (NULL);

	sname = stable(cp->s);
	numn = newnode(T_NUM, NULL, 0);
	numn->u.ull = cp->num;

	tmpn = tree_name_iterator(tree_name(sname, IT_VERTICAL, NULL, 0), numn);
	if ((ptmpn = config_nodeize(cp->parent)) == NULL)
		return (tmpn);
	return (tree_name_append(ptmpn, tmpn));
}

/*ARGSUSED*/
static void
prtdevcache(void *lhs, void *rhs, void *arg)
{
	out(O_ALTFP|O_VERB3, "%s -> %p", (char *)lhs, rhs);
}

/*ARGSUSED*/
static void
prtcpucache(void *lhs, void *rhs, void *arg)
{
	out(O_ALTFP|O_VERB, "%u -> %p", (uint32_t)lhs, rhs);
}

/*
 * config_bydev_lookup -- look up the path in our DEVcache lut.  If we find
 * it return the config path, but as a struct node.
 */
struct node *
config_bydev_lookup(struct cfgdata *fromcfg, const char *path)
{
	struct config *find;
	struct node *np;

	out(O_ALTFP|O_VERB3, "Device path cache:");
	lut_walk(fromcfg->devcache, (lut_cb)prtdevcache, NULL);

	if ((find = lut_lookup(fromcfg->devcache,
	    (void *) stable(path), NULL)) == NULL)
		return (NULL);

	np = config_nodeize(find);
	if (np != NULL) {
		out(O_ALTFP|O_VERB, "Matching config entry:");
		ptree_name_iter(O_ALTFP|O_VERB|O_NONL, np);
		out(O_ALTFP|O_VERB, NULL);
	}
	return (np);
}

/*
 * config_bycpuid_lookup -- look up the cpu id in our CPUcache lut.
 * If we find it return the config path, but as a struct node.
 */
struct node *
config_bycpuid_lookup(struct cfgdata *fromcfg, uint32_t id)
{
	struct config *find;
	struct node *np;

	out(O_ALTFP|O_VERB, "Cpu cache:");
	lut_walk(fromcfg->cpucache, (lut_cb)prtcpucache, NULL);

	if ((find = lut_lookup(fromcfg->cpucache,
	    (void *)id, NULL)) == NULL)
		return (NULL);

	np = config_nodeize(find);
	if (np != NULL) {
		out(O_ALTFP|O_VERB3, "Matching config entry:");
		ptree_name_iter(O_ALTFP|O_VERB3|O_NONL, np);
		out(O_ALTFP|O_VERB3, NULL);
	}
	return (np);
}

/*
 * printprop -- print prop associated with config node
 */
static void
printprop(const char *lhs, const char *rhs, void *arg)
{
	int flags = (int)arg;

	out(flags, "\t%s=%s", lhs, rhs);
}

/*
 * pconf -- internal printing function to recurse through the tree
 */
static void
pconf(int flags, struct config *cp, char *buf, int offset, int limit)
{
	char *sep = "/";

	if (offset)
		sep = "/";
	else
		sep = "";
	(void) snprintf(&buf[offset], limit - offset, "%s%s%d",
	    sep, cp->s, cp->num);
	if (cp->child == NULL) {
		out(flags, "%s", buf);
		lut_walk(cp->props, (lut_cb)printprop, (void *)flags);
	} else
		pconf(flags, cp->child, buf, strlen(buf), limit);
	if (cp->next)
		pconf(flags, cp->next, buf, offset, limit);
}

/*
 * config_print -- spew the current configuration cache
 */

#define	MAXCONFLINE 4096

void
config_print(int flags, struct config *croot)
{
	char buf[MAXCONFLINE];

	if (croot == NULL)
		out(flags, "empty configuration");
	else
		pconf(flags, croot->child, buf, 0, MAXCONFLINE);
}
