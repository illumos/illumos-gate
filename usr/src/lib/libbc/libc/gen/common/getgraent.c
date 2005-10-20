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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <grp.h>
#include <grpadj.h>
#include <rpcsvc/ypclnt.h>
#include <string.h>
#include <malloc.h>

extern void rewind();
extern long strtol();
extern int fclose();

void	setgraent(void);
void	endgraent(void);

static struct gradata {
	char	*domain;
	FILE	*grfa;
	char	*yp;
	int	yplen;
	char	*oldyp;
	int	oldyplen;
	struct list {
		char *name;
		struct list *nxt;
	} *minuslist;			/* list of - items */
	struct	group_adjunct interpgra;
	char	interpline[BUFSIZ+1];
	struct	group_adjunct *sv;
} *gradata, *_gradata(void);

static char *GROUPADJ = "/etc/security/group.adjunct";

static struct group_adjunct	*interpret(char *, int);
static struct group_adjunct	*interpretwithsave(char *, int,
    struct group_adjunct *);
static struct group_adjunct	*save(struct group_adjunct *);
static struct group_adjunct	*getnamefromyellow(char *,
    struct group_adjunct *);
static int	onminuslist(struct group_adjunct *);
static int	matchname(char [], struct group_adjunct **, char *);
static void	freeminuslist(void);
static void	getnextfromyellow(void);
static void	getfirstfromyellow(void);
static void	addtominuslist(char *);


static struct gradata *
_gradata(void)
{
	struct gradata *g = gradata;

	if (g == 0) {
		g = (struct gradata *)calloc(1, sizeof (struct gradata));
		gradata = g;
	}
	return (g);
}

struct group_adjunct *
getgranam(char *name)
{
	struct gradata *g = _gradata();
	struct group_adjunct *gra;
	char line[BUFSIZ+1];

	setgraent();
	if (g == 0)
		return (0);
	if (!g->grfa)
		return (NULL);
	while (fgets(line, BUFSIZ, g->grfa) != NULL) {
		if ((gra = interpret(line, strlen(line))) == NULL)
			continue;
		if (matchname(line, &gra, name)) {
			endgraent();
			return (gra);
		}
	}
	endgraent();
	return (NULL);
}

void
setgraent(void)
{
	struct gradata *g = _gradata();

	if (g == NULL)
		return;
	if (g->domain == NULL)
		(void) yp_get_default_domain(&g->domain);
	if (!g->grfa)
		g->grfa = fopen(GROUPADJ, "r");
	else
		rewind(g->grfa);
	if (g->yp)
		free(g->yp);
	g->yp = NULL;
	freeminuslist();
}

void
endgraent(void)
{
	struct gradata *g = _gradata();

	if (g == 0)
		return;
	if (g->grfa) {
		(void) fclose(g->grfa);
		g->grfa = NULL;
	}
	if (g->yp)
		free(g->yp);
	g->yp = NULL;
	freeminuslist();
}

struct group_adjunct *
fgetgraent(FILE *f)
{
	char line1[BUFSIZ+1];

	if(fgets(line1, BUFSIZ, f) == NULL)
		return (NULL);
	return (interpret(line1, strlen(line1)));
}

static char *
grskip(char *p, int c)
{
	while(*p && *p != c && *p != '\n') ++p;
	if (*p == '\n')
		*p = '\0';
	else if (*p != '\0')
		*p++ = '\0';
	return (p);
}

struct group_adjunct *
getgraent(void)
{
	struct gradata *g = _gradata();
	char line1[BUFSIZ+1];
	static struct group_adjunct *savegra;
	struct group_adjunct *gra;

	if (g == 0)
		return (0);
	if (g->domain == NULL) {
		(void) yp_get_default_domain(&g->domain);
	}
	if(!g->grfa && !(g->grfa = fopen(GROUPADJ, "r")))
		return (NULL);
  again:
	if (g->yp) {
		gra = interpretwithsave(g->yp, g->yplen, savegra);
		free(g->yp);
		if (gra == NULL)
			return (NULL);
		getnextfromyellow();
		if (onminuslist(gra))
			goto again;
		else
			return (gra);
	}
	else if (fgets(line1, BUFSIZ, g->grfa) == NULL)
		return (NULL);
	if ((gra = interpret(line1, strlen(line1))) == NULL)
		return (NULL);
	switch(line1[0]) {
		case '+':
			if (strcmp(gra->gra_name, "+") == 0) {
				getfirstfromyellow();
				savegra = save(gra);
				goto again;
			}
			/* 
			 * else look up this entry in NIS
			 */
			savegra = save(gra);
			gra = getnamefromyellow(gra->gra_name+1, savegra);
			if (gra == NULL)
				goto again;
			else if (onminuslist(gra))
				goto again;
			else
				return (gra);
			break;
		case '-':
			addtominuslist(gra->gra_name+1);
			goto again;
			break;
		default:
			if (onminuslist(gra))
				goto again;
			return (gra);
			break;
	}
	/* NOTREACHED */
}

static struct group_adjunct *
interpret(char *val, int len)
{
	struct gradata *g = _gradata();
	char *p;

	if (g == 0)
		return (0);
	strncpy(g->interpline, val, len);
	p = g->interpline;
	g->interpline[len] = '\n';
	g->interpline[len+1] = 0;
	g->interpgra.gra_name = p;
	p = grskip(p,':');
        if (strcmp(g->interpgra.gra_name, "+") == 0) {
                /* we are going to the NIS - fix the
                 * rest of the struct as much as is needed
                 */
                g->interpgra.gra_passwd = "";
		return (&g->interpgra);
        }
	g->interpgra.gra_passwd = p;
        while(*p && *p != '\n') p++;
        *p = '\0';
	return (&g->interpgra);
}

static void
freeminuslist(void)
{
	struct gradata *g = _gradata();
	struct list *ls;
	
	if (g == 0)
		return;
	for (ls = g->minuslist; ls != NULL; ls = ls->nxt) {
		free(ls->name);
		free(ls);
	}
	g->minuslist = NULL;
}

static struct group_adjunct *
interpretwithsave(char *val, int len, struct group_adjunct *savegra)
{
	struct gradata *g = _gradata();
	struct group_adjunct *gra;
	
	if (g == 0)
		return (0);
	if ((gra = interpret(val, len)) == NULL)
		return (NULL);
	if (savegra->gra_passwd && *savegra->gra_passwd)
		gra->gra_passwd =  savegra->gra_passwd;
	return (gra);
}

static int
onminuslist(struct group_adjunct *gra)
{
	struct gradata *g = _gradata();
	struct list *ls;
	char *nm;
	
	if (g == 0)
		return (0);
	nm = gra->gra_name;
	for (ls = g->minuslist; ls != NULL; ls = ls->nxt)
		if (strcmp(ls->name, nm) == 0)
			return (1);
	return (0);
}

static void
getnextfromyellow(void)
{
	struct gradata *g = _gradata();
	int reason;
	char *key = NULL;
	int keylen;
	
	if (g == 0)
		return;
	if (reason = yp_next(g->domain, "group.adjunct.byname",
	    g->oldyp, g->oldyplen, &key, &keylen,
	    &g->yp, &g->yplen)) {
#ifdef DEBUG
fprintf(stderr, "reason yp_next failed is %d\n", reason);
#endif
		g->yp = NULL;
	}
	if (g->oldyp)
		free(g->oldyp);
	g->oldyp = key;
	g->oldyplen = keylen;
}

static void
getfirstfromyellow(void)
{
	struct gradata *g = _gradata();
	int reason;
	char *key = NULL;
	int keylen;
	
	if (g == 0)
		return;
	if (reason =  yp_first(g->domain, "group.adjunct.byname",
	    &key, &keylen, &g->yp, &g->yplen)) {
#ifdef DEBUG
fprintf(stderr, "reason yp_first failed is %d\n", reason);
#endif
		g->yp = NULL;
	}
	if (g->oldyp)
		free(g->oldyp);
	g->oldyp = key;
	g->oldyplen = keylen;
}

static struct group_adjunct *
getnamefromyellow(char *name, struct group_adjunct *savegra)
{
	struct gradata *g = _gradata();
	struct group_adjunct *gra;
	int reason;
	char *val;
	int vallen;
	
	if (g == 0)
		return (NULL);
	if (reason = yp_match(g->domain, "group.adjunct.byname",
	    name, strlen(name), &val, &vallen)) {
#ifdef DEBUG
fprintf(stderr, "reason yp_next failed is %d\n", reason);
#endif
		return (NULL);
	}
	else {
		gra = interpret(val, vallen);
		free(val);
		if (gra == NULL)
			return (NULL);
		if (savegra->gra_passwd && *savegra->gra_passwd)
			gra->gra_passwd =  savegra->gra_passwd;
		return (gra);
	}
}

static void
addtominuslist(char *name)
{
	struct gradata *g = _gradata();
	struct list *ls;
	char *buf;
	
	if (g == 0)
		return;
	ls = (struct list *)malloc(sizeof(struct list));
	buf = (char *)malloc(strlen(name) + 1);
	(void) strcpy(buf, name);
	ls->name = buf;
	ls->nxt = g->minuslist;
	g->minuslist = ls;
}

/* 
 * save away psswd field, which is the only
 * one which can be specified in a local + entry to override the
 * value in the NIS
 */
static struct group_adjunct *
save(struct group_adjunct *gra)
{
	struct gradata *g = _gradata();
	
	if (g == 0)
		return (0);
	/* 
	 * free up stuff from last time around
	 */
	if (g->sv) {
		free(g->sv->gra_passwd);
		free(g->sv);
	}
	g->sv = (struct group_adjunct *)calloc(1, sizeof(struct group_adjunct));
	g->sv->gra_passwd = (char *)malloc(strlen(gra->gra_passwd) + 1);
	(void) strcpy(g->sv->gra_passwd, gra->gra_passwd);
	return (g->sv);
}

static int
matchname(char line1[], struct group_adjunct **grap, char *name)
{
	struct group_adjunct *savegra;
	struct group_adjunct *gra = *grap;

	switch (line1[0]) {
		case '+':
			if (strcmp(gra->gra_name, "+") == 0) {
				savegra = save(gra);
				gra = getnamefromyellow(name, savegra);
				if (gra) {
					*grap = gra;
					return (1);
				}
				else
					return (0);
			}
			if (strcmp(gra->gra_name+1, name) == 0) {
				savegra = save(gra);
				gra = getnamefromyellow(gra->gra_name+1, savegra);
				if (gra) {
					*grap = gra;
					return (1);
				}
				else
					return (0);
			}
			break;
		case '-':
			if (strcmp(gra->gra_name+1, name) == 0) {
				*grap = NULL;
				return (1);
			}
			break;
		default:
			if (strcmp(gra->gra_name, name) == 0)
				return (1);
	}
	return (0);
}
