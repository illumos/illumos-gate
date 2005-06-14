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

#include	<stdlib.h>
#include	<string.h>
#include	"vold.h"

/*
 * Functions to get, put, and delete generic properties.
 * It is illegal (and not checked) for either attributes or
 * values to have '=' or '; ' in them.
 */

/*
 * The user uses an opaque string and asks for the get, put,
 * and del operations to be performed on it.  The model
 * is attribute = value, and is represented in the string
 * as "attribute=value; attribute1=value1; ...".
 */


struct prop {
	char	*attr;
	char	*value;
	int	seen;
};

static struct prop 	*make_prop(char *);
static void		free_prop(struct prop *ps);

#ifndef	NULLC
#define	NULLC	'\0'
#endif


/*
 * Return the "value" for an "attribute" from a "property" string.
 * Returns NULL if the named attribute does not exist in the string.
 */
char *
prop_attr_get(char *props, char *attr)
{
	struct prop 	*ps;
	struct prop 	*op = make_prop(props);
	char		*rv;

	ps = op;
	while (ps->attr) {
		if (strcmp(ps->attr, attr) == 0) {
			rv = vold_strdup(ps->value);
			free_prop(op);
			return (rv);
		}
		ps++;
	}
	free_prop(op);
	return (NULL);
}

/*
 * Return a new "property" string with the "attribute" and "value" in
 * it. I Free the old one.  If the named "attribute" already exists,
 * it is modified,  if it does not, the new <attribute, value> pair
 * is appended to the end of the list.
 *
 * if the input value for the specified attribute is a null pointer
 * or null string, then delete that attribute
 */
char *
prop_attr_put(char *props, char *attr, char *value)
{
	char		*prop_attr_del(char *, char *);
	struct prop	*ps, *lp;
	int		found;
	size_t		plen;
	char		*rp;

	/* if the attribute is to be cleared our job is simpler */
	if (value == NULL || *value == NULLC) {
		rp = prop_attr_del(props, attr);
		return (rp);
	}

	ps = make_prop(props);

	/* scan through attribute list, looking for one we want to set */
	for (lp = ps, found = 0; lp->attr != NULL; lp++) {
		if (strcmp(lp->attr, attr) == 0) {
			/* found our attr -- set it to new value */
			found++;
			free(lp->value);
			lp->value = vold_strdup(value);
			break;
		}
	}

	/* get length of all current attrubute strings */
	plen = 0;
	for (lp = ps; lp->attr != NULL; lp++) {
		plen += strlen(lp->attr);
		plen += strlen(lp->value);
		plen += 2; 	/* '=' and '; ' */
	}

	/* if not found then we have to add in room for new attr=value pari */
	if (!found) {
		plen += strlen(attr);
		plen += strlen(value);
		plen += 2;	/* '=' and '; ' */
	}

	/* allocate room for a string and fill it in */
	rp = vold_calloc(plen+1, sizeof (char));
	for (lp = ps; lp->attr != NULL; lp++) {
		(void) strcat(rp, lp->attr);
		(void) strcat(rp, "=");
		(void) strcat(rp, lp->value);
		(void) strcat(rp, ";");
	}
	if (!found) {
		(void) strcat(rp, attr);
		(void) strcat(rp, "=");
		(void) strcat(rp, value);
		(void) strcat(rp, ";");
	}

	free(props);
	free_prop(ps);
	return (rp);
}

/*
 * remove an attribute from the property list.
 */
char *
prop_attr_del(char *props, char *attr)
{
	struct prop	*ps, *lp;
	size_t		plen;
	char		*rp;

	ps = make_prop(props);
	plen = 0;

	for (lp = ps; lp->attr != NULL; lp++) {
		if (strcmp(lp->attr, attr) == 0) {
			continue;
		}
		plen += strlen(lp->attr);
		plen += strlen(lp->value);
		plen += 2; 	/* '=' and '; ' */
	}

	rp = vold_calloc(plen+1, sizeof (char));

	for (lp = ps; lp->attr != NULL; lp++) {
		if (strcmp(lp->attr, attr) == 0) {
			continue;
		}
		(void) strcat(rp, lp->attr);
		(void) strcat(rp, "=");
		(void) strcat(rp, lp->value);
		(void) strcat(rp, ";");
	}

	free(props);
	free_prop(ps);
	return (rp);
}

char *
prop_attr_merge(char *to, char *from)
{
	struct prop	*p_from, *p_to;
	struct prop	*pf, *pt;
	int		plen;
	char		*rp;

	p_from = make_prop(from);
	p_to = make_prop(to);

	for (pt = p_to; pt->attr != NULL; pt++) {
		for (pf = p_from; pf->attr != NULL; pf++) {
			if (strcmp(pf->attr, pt->attr) == 0) {
				/* found one */
				free(pt->value);
				pt->value = vold_strdup(pf->value);
				pf->seen++;
			}
		}
	}
	plen = 0;

	/* the "to" array */
	for (pt = p_to; pt->attr != NULL; pt++) {
		plen += strlen(pt->attr);
		plen += strlen(pt->value);
		plen += 2;
	}
	/* the "from" array */
	for (pf = p_from; pf->attr != NULL; pf++) {
		if (pf->seen) {
			continue;
		}
		plen += strlen(pf->attr);
		plen += strlen(pf->value);
		plen += 2;
	}

	rp = vold_calloc(plen + 1, sizeof (char));

	/* the "to" array */
	for (pt = p_to; pt->attr != NULL; pt++) {
		(void) strcat(rp, pt->attr);
		(void) strcat(rp, "=");
		(void) strcat(rp, pt->value);
		(void) strcat(rp, ";");
	}

	/* the "from" array */
	for (pf = p_from; pf->attr != NULL; pf++) {
		if (pf->seen) {
			continue;
		}
		(void) strcat(rp, pf->attr);
		(void) strcat(rp, "=");
		(void) strcat(rp, pf->value);
		(void) strcat(rp, ";");
	}
	free_prop(p_from);
	free_prop(p_to);
	return (rp);
}

static struct prop *
make_prop(char *props)
{
	char 		*s;
	char 		*p;
	int		pcnt;
	int		i;
	struct prop 	*ps;

	if (props == NULL) {
		return (vold_calloc(1, sizeof (struct prop)));
	}

	/*
	 * Count the number for attribute=value pairs.
	 */
	s = props;
	pcnt = 0;
	while ((*s != NULLC) && ((s = strchr(s, '=')) != NULL)) {
		pcnt++;
		s++;
	}

	ps = vold_calloc(pcnt+1, sizeof (struct prop));

	for (i = 0, s = props; i < pcnt; i++) {

		if ((p = strchr(s, '=')) == NULL) {
			break;
		}
		*p = NULLC;
		ps[i].attr = vold_strdup(s);
		*p = '=';
		s = p;
		if ((p = strchr(s, ';')) != NULL) {
			*p = NULLC;
		}
		ps[i].value = vold_strdup(s+1);
		if (p == NULL) {
			break;
		}
		*p++ = ';';
		s = p;
	}
	return (ps);
}


static void
free_prop(struct prop *ps)
{
	struct prop *lp = ps;

	while (lp->attr != NULL) {
		free(lp->attr);
		free(lp->value);
		lp++;
	}
	free(ps);
}
