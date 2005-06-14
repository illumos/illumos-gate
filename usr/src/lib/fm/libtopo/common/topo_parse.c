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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <alloca.h>
#include <sys/param.h>
#include "topo_impl.h"
#include "topo_enum.h"

#define	TOPO_FILE	"platform.topo"

void (*Outmethod)(const char *);

void
topo_init(int npaths, const char **paths)
{
	topo_mem_init();
	topo_paths_init(npaths, paths);
	topo_enum_init();
}

void
topo_fini(void)
{
	topo_driver_fini();
	topo_paths_fini();
	topo_enum_fini();
	topo_mem_fini();
}

void
topo_reset(void)
{
	topo_enum_fini();
	topo_enum_init();
}

void
topo_tree_release(tnode_t *node)
{
	tnode_t *ar = node;	/* actual root node */

	if (ar->state != TOPO_ROOT)
		ar = ar->root;

	if (ar->extend != NULL)
		tnode_hash_destroy((struct tnode_hash *)ar->extend);

	tnode_destroy(ar);
}

/*
 * The PLATFRU property is special.  It is inherited by static nodes
 * automatically from their parent, if it is not set within the .topo
 * file.  For the root node, the node name itself is the PLATFRU value.
 */
static void
topo_inherits(tnode_t *root)
{
	const char *pv;
	tnode_t *tmp = NULL;
	char *pbuf = NULL;
	int inst;

	topo_out(TOPO_DEBUG, "topo_inherits: [%p]\n", (void *)root);

	while ((tmp = topo_next_child(root, tmp)) != NULL) {
		topo_out(TOPO_DEBUG, "    [%p]", (void *)tmp);
		if (topo_get_prop(tmp, "NOINHERIT") != NULL) {
			topo_out(TOPO_DEBUG, " declines inheritance\n");
			continue;
		}
		if ((pv = topo_get_prop(tmp, PLATFRU)) != NULL) {
			topo_out(TOPO_DEBUG, PLATFRU " already set\n");
			continue;
		}
		if ((inst = topo_get_instance_num(tmp)) < 0) {
			topo_out(TOPO_DEBUG, " not enumerated\n");
			continue;
		}
		if (root->state == TOPO_ROOT) {
			if (pbuf == NULL)
				pbuf = alloca(MAXPATHLEN);
			(void) snprintf(pbuf,
			    MAXPATHLEN, "hc:///%s=%d", topo_name(tmp), inst);
			(void) topo_set_prop(tmp, PLATFRU, pbuf);
			topo_out(TOPO_DEBUG, "set to %s\n", pbuf);
			topo_inherits(tmp);
		} else if ((pv = topo_get_prop(root, PLATFRU)) != NULL) {
			(void) topo_set_prop(tmp, PLATFRU, pv);
			topo_out(TOPO_DEBUG, "set to %s\n", pv);
			topo_inherits(tmp);
		} else {
			topo_out(TOPO_DEBUG, "no prop value to inherit\n");
		}

	}
}

struct tnode *
topo_root(void)
{
	struct tnode *root = topo_create(NULL, "");

	if (topo_parse(root, TOPO_FILE) == NULL)
		return (root);

	topo_inherits(root);

	topo_walk(root, TOPO_VISIT_SELF_FIRST, NULL, tnode_print);
	topo_enum(root);
	return (root);
}

static struct tnode *chew(char *, struct tnode *, struct tnode *);
static void syntax_error(const char *, int);
static void toolong_error(const char *, int);
int Empty = 0;

struct tnode *
topo_parse(struct tnode *root, const char *filename)
{
	struct tnode *leaf, *newleaf;
	FILE *fp;
	char *parsebuf;
	int line = 0;

	topo_out(TOPO_DEBUG, "topo_parse(%s)\n", filename);

	if (root == NULL)
		return (NULL);

	if ((fp = topo_open(filename)) == NULL)
		return (NULL);

	parsebuf = alloca(MAXPATHLEN);

	leaf = NULL;
	while (fgets(parsebuf, MAXPATHLEN, fp) != NULL) {
		line++;
		if (*parsebuf == '\0' ||
		    parsebuf[strlen(parsebuf) - 1] != '\n') {
			int c;
			while ((c = getc(fp)) != EOF && (c != '\n'))
				;
			toolong_error(filename, line);
			continue;
		}
		newleaf = chew(parsebuf, root, leaf);
		if (newleaf == NULL && Empty != 1) {
			syntax_error(filename, line);
		} else if (newleaf != NULL) {
			topo_walk(root, TOPO_VISIT_SELF_FIRST, NULL,
			    tnode_print);
			leaf = newleaf;
		}
	}

	topo_close(fp);
	return (root);
}

struct tnode *
topo_load(const char *basename, struct tnode *subroot)
{
	char *filenmbuf = alloca(MAXPATHLEN);

	(void) snprintf(filenmbuf, MAXPATHLEN, "%s.topo", basename);
	return (topo_parse(subroot, filenmbuf));
}

#define	UPPER_MAX_RECURSE	10
#define	DFLT_MAX_RECURSE	3
int Topo_max_recurse = DFLT_MAX_RECURSE;

void
topo_set_recurse_depth(int newdepth)
{
	if (newdepth < 0 || newdepth > UPPER_MAX_RECURSE) {
		topo_out(TOPO_ERR, "bogus max recurse depth %d ignored.\n",
		    newdepth);
		return;
	}
	Topo_max_recurse = newdepth;
}

void
topo_subtree_parse(struct tnode *subroot)
{
	static int recurse_depth = 0;
	char *filenmbuf;

	if (++recurse_depth > Topo_max_recurse) {
		recurse_depth--;
		return;
	}

	filenmbuf = alloca(MAXPATHLEN);

	(void) snprintf(filenmbuf, MAXPATHLEN, "%s.topo", topo_name(subroot));
	(void) topo_parse(subroot, filenmbuf);

	recurse_depth--;
}

/*
 * Declare a syntax error on the current line
 */
void
syntax_error(const char *pathname, int lineno)
{
	topo_out(TOPO_ERR, "%s: syntax error on line %d\n", pathname, lineno);
}

/*
 * Declare the current line too long
 */
void
toolong_error(const char *pathname, int lineno)
{
	topo_out(TOPO_ERR, "%s: line %d too long, ignored\n", pathname, lineno);
}

/*
 * Skip whitespace, return pointer to start of next token
 */
char *
topo_whiteskip(char *srcbuf)
{
	char *t;

	if ((t = srcbuf) == NULL)
		return (NULL);

	while (*t == ' ' || *t == '\t')
		t++;

	if (*t == '\0' || *t == '#' || *t == '\n')
		return (NULL);
	else
		return (t);
}

int
topo_inst_from_str(char *src, int *min, int *max, int *instno)
{
	char *b;
	char *e;
	char s;
	long l;

	*min = *max = *instno = -1;

	if (isdigit(*src) != 0) {
		errno = 0;
		l = strtol(src, NULL, 10);
		if (errno != 0)
			return (-1);
		*instno = (int)l;
		return (0);
	}

	if (*src++ != '[')
		return (-1);

	b = src;
	e = b;
	while (isdigit(*e) != 0)
		e++;
	s = *e;
	*e = '\0';
	errno = 0;
	l = strtol(b, NULL, 10);
	*e = s;
	if (errno != 0)
		return (-1);

	if (*e == ']') {
		*min = *max = (int)l;
		return (0);
	}

	if (*e++ != '-')
		return (-1);
	*min = (int)l;
	b = e;
	while (isdigit(*e) != 0)
		e++;
	s = *e;
	*e = '\0';
	errno = 0;
	l = strtol(b, NULL, 10);
	*e = s;
	if (errno != 0)
		return (-1);
	if (*e++ != ']')
		return (-1);
	if (*e != '\0')
		return (-1);
	*max = (int)l;
	return (0);
}

char *
topo_component_from_path(char *src, char **name, char **inst)
{
	char *copybuf;
	char *b = src;
	char *e;
	char s;

	if (src == NULL || *src == '\0')
		return (NULL);

	b++;	/* skip leading slash */
	e = b;
	while (isalpha(*e) != 0 || *e == '_')
		e++;

	if (*e == '\0' || *e == '\n')
		return (NULL);

	copybuf = alloca(MAXPATHLEN);

	s = *e;
	*e = '\0';
	(void) strlcpy(copybuf, b, MAXPATHLEN);
	*e = s;
	*name = topo_strdup(copybuf);

	/* rest up to next slash is instance part */
	b = e;
	while (*e != '\0' && *e != '\n' && *e != '/')
		e++;
	s = *e;
	*e = '\0';
	(void) strlcpy(copybuf, b, MAXPATHLEN);
	*e = s;
	*inst = topo_strdup(copybuf);

	return (e);
}

static int
prop_from_inbuf(char *src, char **name, char **val)
{
	char *copybuf;
	char *b = src;
	char *e;
	char s;
	int quoted = 0;

	b = e = src;

	/* property name must start with alpha character, _ or . */
	if (isalpha(*e) == 0 && *e != '_' && *e != '.')
		return (-1);

	e++;
	while (isalnum(*e) != 0 || *e == '_' || *e == '.' || *e == '-')
		e++;

	if (*e == '\0' || *e == '\n')
		return (-1);

	copybuf = alloca(MAXPATHLEN);

	s = *e;
	*e = '\0';
	(void) strlcpy(copybuf, b, MAXPATHLEN);
	*e = s;
	*name = topo_strdup(copybuf);

	b = topo_whiteskip(e);
	if (b == NULL || *b != '=') {
		topo_free(*name);
		return (-1);
	}
	b = topo_whiteskip(++b);
	if (*b == '"') {
		b++;
		quoted++;
	}
	e = b;
	if (quoted) {
		while (*e != '"' && *e != '\0' && *e != '\n')
			e++;
		if (*e != '"') {
			topo_free(*name);
			return (-1);
		}
	} else {
		while (*e != '\0' && *e != '\n' && *e != ' ' && *e != '\t')
			e++;
	}
	s = *e;
	*e = '\0';
	(void) strlcpy(copybuf, b, MAXPATHLEN);
	*e = s;
	*val = topo_strdup(copybuf);

	if (quoted)
		e++;
	b = topo_whiteskip(e);
	if (b != NULL) {
		topo_free(*name);
		topo_free(*val);
		return (-1);
	}

	return (0);
}

/*
 * Add a child to 'parent' with name and instance number
 * described by 'name' and 'inst'.  If one already exists,
 * just return a pointer to the existing one.
 */
static struct tnode *
new_child(struct tnode *parent, char *name, char *inst)
{
	tnode_t *tmp = NULL;
	int min, max, instno;

	if (topo_inst_from_str(inst, &min, &max, &instno) != 0)
		return (NULL);

	while ((tmp = topo_next_child(parent, tmp)) != NULL) {
		if (strcmp(name, topo_name(tmp)) != 0)
			continue;
		if (instno >= 0 && tmp->state == TOPO_INST &&
		    tmp->u.inst == instno)
			break;
		if (min >= 0 && tmp->state == TOPO_RANGE &&
		    tmp->u.range.min == min && tmp->u.range.max == max)
			break;
	}

	if (tmp != NULL)
		topo_out(TOPO_DEBUG, "child %s%s of %p present, = %p\n",
		    name, inst, (void *)parent, (void *)tmp);

	if (tmp != NULL)
		return (tmp);

	tmp = topo_create(parent, name);
	if (instno >= 0)
		(void) topo_set_instance_num(tmp, instno);
	else
		(void) topo_set_instance_range(tmp, min, max);

	topo_out(TOPO_DEBUG, "child %s%s of %p created = %p\n",
	    name, inst, (void *)parent, (void *)tmp);

	return (tmp);
}

static struct tnode *
grow_path(char *buf, struct tnode *root)
{
	struct tnode *n;
	char *name = NULL;
	char *inst = NULL;
	char *cont;

	topo_out(TOPO_DEBUG, "grow_path: %s\n", buf);
	cont = topo_component_from_path(buf, &name, &inst);

	if (cont == NULL) {
		if (name != NULL)
			topo_free(name);
		if (inst != NULL)
			topo_free(inst);
		return (root);
	}

	if ((n = new_child(root, name, inst)) == NULL) {
		topo_free(name);
		topo_free(inst);
		return (NULL);
	}

	/*
	 * If the node specifies a dynamic range, there may be a .topo
	 * file associated with the node type describing a hierarchy
	 * of possible nodes under this node.
	 */
	if (topo_get_instance_num(n) < 0)
		topo_subtree_parse(n);

	topo_free(name);
	topo_free(inst);

	return (grow_path(cont, n));
}

struct tnode *
consume_prop(char *buf, struct tnode *addto)
{
	char *name, *val;

	if (addto == NULL)
		return (NULL);

	if (prop_from_inbuf(buf, &name, &val) != 0)
		return (NULL);

	topo_out(TOPO_DEBUG, "setting prop on %p: %s = %s\n", (void *)addto,
	    name, val);
	(void) topo_set_prop(addto, name, val);

	topo_free(name);
	topo_free(val);

	return (addto);
}

struct tnode *
chew(char *buf, struct tnode *root, struct tnode *lastleaf)
{
	char *t;

	topo_out(TOPO_DEBUG, "chew:%s [%p]\n", buf, (void *)root);
	if ((t = topo_whiteskip(buf)) == NULL) {
		Empty = 1;
		return (NULL);
	}
	Empty = 0;

	if (*t == '/')
		/* a new path to add, growpath returns the leaf node */
		return (grow_path(t, root));

	return (consume_prop(t, lastleaf));
}
