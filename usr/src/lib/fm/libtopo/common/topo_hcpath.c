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
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <fm/libtopo.h>
#include "topo_impl.h"

static char tmpbuf[MAXPATHLEN];
static char numbuf[MAXINSTLEN];

static int
intsize(int i)
{
	int r;
	for (r = 1; i > 0; r++)
		i = i/10;
	return (r);
}

static const char *
tnode_as_str(tnode_t *node)
{
	if (node->state == TOPO_ROOT) {
		tmpbuf[0] = '\0';
		return (tmpbuf);
	}

	(void) strcpy(tmpbuf, "/");
	if (node->state == TOPO_LIMBO) {
		(void) strcat(tmpbuf, "?");
		(void) strlcat(tmpbuf, node->name, MAXPATHLEN);
		(void) strlcat(tmpbuf, "?", MAXPATHLEN);
		return (tmpbuf);
	}

	(void) strlcat(tmpbuf, node->name, MAXPATHLEN);
	if (node->state == TOPO_RANGE) {
		(void) strlcat(tmpbuf, "[", MAXPATHLEN);
		if (node->u.range.min == node->u.range.max) {
			(void) snprintf(numbuf, MAXINSTLEN, "%d",
			    node->u.range.min);
			(void) strlcat(tmpbuf, numbuf, MAXPATHLEN);
			(void) strlcat(tmpbuf, "]", MAXPATHLEN);
			return (tmpbuf);
		}
		(void) snprintf(numbuf, MAXINSTLEN, "%d", node->u.range.min);
		(void) strlcat(tmpbuf, numbuf, MAXPATHLEN);
		(void) strlcat(tmpbuf, "-", MAXPATHLEN);
		(void) snprintf(numbuf, MAXINSTLEN, "%d", node->u.range.max);
		(void) strlcat(tmpbuf, numbuf, MAXPATHLEN);
		(void) strlcat(tmpbuf, "]", MAXPATHLEN);
		return (tmpbuf);
	}
	(void) snprintf(numbuf, MAXINSTLEN, "%d", node->u.inst);
	(void) strlcat(tmpbuf, numbuf, MAXPATHLEN);
	return (tmpbuf);
}

static int
tnode_strlen(tnode_t *node)
{
	int len;

	if (node == NULL)
		return (0);

	len = strlen(node->name);

	switch (node->state) {
	case TOPO_LIMBO:
		len += 2; /* ? before and after */
		break;
	case TOPO_RANGE:
		len += 2; /* open and close brackets */
		if (node->u.range.min == node->u.range.max) {
			len += intsize(node->u.range.max);
			break;
		}
		len++;	/* - between range elements */
		len += intsize(node->u.range.min);
		len += intsize(node->u.range.max);
		break;
	case TOPO_INST:
		len += intsize(node->u.inst);
	}

	len++;	/* leading slash */

	return (len);
}

static void
build_path(tnode_t *n, char **buf, int *len)
{
	const char *s;

	if (n == NULL) {
		if (*len > 0) {
			(*len)++; /* trailing null byte */
			*buf = topo_zalloc(*len);
		}
		return;
	} else {
		(*len) += tnode_strlen(n);
		build_path(topo_parent(n), buf, len);
	}

	if (*buf == NULL)
		return;

	s = tnode_as_str(n);
	(void) strlcat(*buf, s, *len);
}

char *
topo_hc_path(tnode_t *tothisnode)
{
	char *buf = NULL;
	int len = 0;

	build_path(tothisnode, &buf, &len);
	return (buf);
}

tnode_t *
topo_find_path(tnode_t *anchor, char *hcpath)
{
	tnode_t *root, *cn = NULL;
	char *name = NULL;
	char *inst = NULL;
	char *cont;
	int ignore;
	int instno;

	if (anchor == NULL || hcpath == NULL ||
	    (root = topo_getroot(anchor)) == NULL)
		return (NULL);

	cont = topo_whiteskip(hcpath);
	while ((cont = topo_component_from_path(cont, &name, &inst)) != NULL) {

		if (topo_inst_from_str(inst, &ignore, &ignore, &instno) != 0) {
			topo_out(TOPO_DEBUG, "failed instno extract from %s\n",
			    inst);
			return (NULL);
		}

		while ((cn = topo_next_child(root, cn)) != NULL) {
			topo_out(TOPO_DEBUG, "%s%d ?= %s%d\n", topo_name(cn),
			    topo_get_instance_num(cn), name, instno);
			if (strcmp(topo_name(cn), name) == 0 &&
			    topo_get_instance_num(cn) == instno)
				break;
		}

		if (cn == NULL)
			return (NULL);

		root = cn;
		cn = NULL;

		topo_free(name);
		topo_free(inst);
		name = inst = NULL;
	}
	return (root);
}
