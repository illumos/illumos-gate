/*
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "tip.h"

#define	MIDDLE	35

static value_t *vlookup(char *);
static int col = 0;

extern char	*interp(char *);

static void	vtoken(char *);
static void	vprint(value_t *);
static int	vaccess(unsigned, unsigned);

/*
 * Variable manipulation
 */
void
vinit(void)
{
	value_t *p;
	char *cp;
	FILE *f;
	char file[1024];

	for (p = vtable; p->v_name != NULL; p++) {
		if (p->v_type&ENVIRON)
			if (cp = getenv(p->v_name))
				p->v_value = cp;
		if (p->v_type&IREMOTE)
			number(p->v_value) = *address(p->v_value);
	}
	/*
	 * Read the .tiprc file in the HOME directory
	 *  for sets
	 */
	if ((cp = value(HOME)) == NULL)
		cp = "";
	(void) strlcpy(file, cp, sizeof (file));
	(void) strlcat(file, "/.tiprc", sizeof (file));
	if ((f = fopen(file, "r")) != NULL) {
		char *tp;

		while (fgets(file, sizeof (file)-1, f) != NULL) {
			if (file[0] == '#')
				continue;
			if (vflag)
				(void) printf("set %s", file);
			if (tp = strrchr(file, '\n'))
				*tp = '\0';
			vlex(file);
		}
		(void) fclose(f);
	}
	/*
	 * To allow definition of exception prior to fork
	 */
	vtable[EXCEPTIONS].v_access &= ~(WRITE<<PUBLIC);
}

/*VARARGS1*/
void
vassign(value_t *p, char *v)
{

	if (!vaccess(p->v_access, WRITE)) {
		(void) printf("access denied\r\n");
		return;
	}
	switch (p->v_type&TMASK) {

	case STRING:
		if (p->v_value != (char *)NULL) {
			if (equal(p->v_value, v))
				return;
			if (!(p->v_type&(ENVIRON|INIT)))
				free(p->v_value);
		}
		if ((p->v_value = malloc(strlen(v)+1)) == NOSTR) {
			(void) printf("out of core\r\n");
			return;
		}
		p->v_type &= ~(ENVIRON|INIT);
		(void) strcpy(p->v_value, v);
		break;

	case NUMBER:
		if (number(p->v_value) == number(v))
			return;
		number(p->v_value) = number(v);
		break;

	case BOOL:
		if (boolean(p->v_value) == (*v != '!'))
			return;
		boolean(p->v_value) = (*v != '!');
		break;

	case CHAR:
		if (character(p->v_value) == *v)
			return;
		character(p->v_value) = *v;
	}
	p->v_access |= CHANGED;
}

void
vlex(char *s)
{
	value_t *p;

	if (equal(s, "all")) {
		for (p = vtable; p->v_name; p++)
			if (vaccess(p->v_access, READ))
				vprint(p);
	} else {
		char *cp;

		do {
			if (cp = vinterp(s, ' '))
				cp++;
			vtoken(s);
			s = cp;
		} while (s);
	}
	if (col > 0) {
		(void) printf("\r\n");
		col = 0;
	}
}

static void
vtoken(char *s)
{
	value_t *p;
	char *cp, *cp2;

	if (cp = strchr(s, '=')) {
		*cp = '\0';
		if (p = vlookup(s)) {
			cp++;
			if (p->v_type&NUMBER)
				vassign(p, (char *)atoi(cp));
			else {
				if (strcmp(s, "record") == 0)
					if ((cp2 = expand(cp)) != NOSTR)
						cp = cp2;
				vassign(p, cp);
			}
			return;
		}
	} else if (cp = strchr(s, '?')) {
		*cp = '\0';
		if ((p = vlookup(s)) != NULL && vaccess(p->v_access, READ)) {
			vprint(p);
			return;
		}
	} else {
		if (*s != '!')
			p = vlookup(s);
		else
			p = vlookup(s+1);
		if (p != NOVAL) {
			if (p->v_type&BOOL)
				vassign(p, s);
			else
				(void) printf("%s: no value specified\r\n", s);
			return;
		}
	}
	(void) printf("%s: unknown variable\r\n", s);
}

static void
vprint(value_t *p)
{
	char *cp;

	if (col > 0 && col < MIDDLE)
		while (col++ < MIDDLE)
			(void) putchar(' ');
	col += strlen(p->v_name);
	switch (p->v_type&TMASK) {

	case BOOL:
		if (boolean(p->v_value) == FALSE) {
			col++;
			(void) putchar('!');
		}
		(void) printf("%s", p->v_name);
		break;

	case STRING:
		(void) printf("%s=", p->v_name);
		col++;
		if (p->v_value) {
			cp = interp(p->v_value);
			col += strlen(cp);
			(void) printf("%s", cp);
		}
		break;

	case NUMBER:
		col += 6;
		(void) printf("%s=%-5d", p->v_name, number(p->v_value));
		break;

	case CHAR:
		(void) printf("%s=", p->v_name);
		col++;
		if (p->v_value) {
			cp = ctrl(character(p->v_value));
			col += strlen(cp);
			(void) printf("%s", cp);
		}
		break;
	}
	if (col >= MIDDLE) {
		col = 0;
		(void) printf("\r\n");
		return;
	}
}


static int
vaccess(unsigned mode, unsigned rw)
{
	if (mode & (rw<<PUBLIC))
		return (1);
	if (mode & (rw<<PRIVATE))
		return (1);
	return ((mode & (rw<<ROOT)) && uid == 0);
}

static value_t *
vlookup(char *s)
{
	value_t *p;

	for (p = vtable; p->v_name; p++)
		if (equal(p->v_name, s) || (p->v_abrev && equal(p->v_abrev, s)))
			return (p);
	return (NULL);
}

char *
vinterp(char *s, char stop)
{
	char *p = s, c;
	int num;

	while ((c = *s++) != 0 && c != stop)
		switch (c) {

		case '^':
			if (*s)
				*p++ = *s++ - 0100;
			else
				*p++ = c;
			break;

		case '\\':
			num = 0;
			c = *s++;
			if (c >= '0' && c <= '7')
				num = (num<<3)+(c-'0');
			else {
				char *q = "n\nr\rt\tb\bf\f";

				for (; *q; q++)
					if (c == *q++) {
						*p++ = *q;
						goto cont;
					}
				*p++ = c;
			cont:
				break;
			}
			if ((c = *s++) >= '0' && c <= '7') {
				num = (num<<3)+(c-'0');
				if ((c = *s++) >= '0' && c <= '7')
					num = (num<<3)+(c-'0');
				else
					s--;
			} else
				s--;
			*p++ = num;
			break;

		default:
			*p++ = c;
		}
	*p = '\0';
	return (c == stop ? s-1 : NULL);
}

/*
 * assign variable s with value v (for NUMBER or STRING or CHAR types)
 */
int
vstring(char *s, char *v)
{
	value_t *p;
	char *v2;

	p = vlookup(s);
	if (p == 0)
		return (1);
	if (p->v_type&NUMBER)
		vassign(p, (char *)atoi(v));
	else {
		if (strcmp(s, "record") == 0)
			if ((v2 = expand(v)) != NOSTR)
				v = v2;
		vassign(p, v);
	}
	return (0);
}
