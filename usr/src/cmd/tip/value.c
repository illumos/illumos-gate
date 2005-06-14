/*
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/* from UCB 4.5 6/25/83 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "tip.h"

#define	MIDDLE	35

static value_t *vlookup();
static int col = 0;

/*
 * Variable manipulation
 */
vinit()
{
	register value_t *p;
	register char *cp;
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
	strlcpy(file, cp, sizeof (file));
	strlcat(file, "/.tiprc", sizeof (file));
	if ((f = fopen(file, "r")) != NULL) {
		register char *tp;

		while (fgets(file, sizeof (file)-1, f) != NULL) {
			if (file[0] == '#')
				continue;
			if (vflag)
				printf("set %s", file);
			if (tp = strrchr(file, '\n'))
				*tp = '\0';
			vlex(file);
		}
		fclose(f);
	}
	/*
	 * To allow definition of exception prior to fork
	 */
	vtable[EXCEPTIONS].v_access &= ~(WRITE<<PUBLIC);
}

/*VARARGS1*/
vassign(p, v)
	register value_t *p;
	char *v;
{

	if (!vaccess(p->v_access, WRITE)) {
		printf("access denied\r\n");
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
			printf("out of core\r\n");
			return;
		}
		p->v_type &= ~(ENVIRON|INIT);
		strcpy(p->v_value, v);
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

vlex(s)
	register char *s;
{
	register value_t *p;

	if (equal(s, "all")) {
		for (p = vtable; p->v_name; p++)
			if (vaccess(p->v_access, READ))
				vprint(p);
	} else {
		register char *cp;

		do {
			if (cp = vinterp(s, ' '))
				cp++;
			vtoken(s);
			s = cp;
		} while (s);
	}
	if (col > 0) {
		printf("\r\n");
		col = 0;
	}
}

static int
vtoken(s)
	register char *s;
{
	register value_t *p;
	register char *cp, *cp2;
	char *expand();

	if (cp = strchr(s, '=')) {
		*cp = '\0';
		if (p = vlookup(s)) {
			cp++;
			if (p->v_type&NUMBER)
				vassign(p, atoi(cp));
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
		if ((p = vlookup(s)) && vaccess(p->v_access, READ)) {
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
				printf("%s: no value specified\r\n", s);
			return;
		}
	}
	printf("%s: unknown variable\r\n", s);
}

static int
vprint(p)
	register value_t *p;
{
	register char *cp;
	extern char *interp(), *ctrl();

	if (col > 0 && col < MIDDLE)
		while (col++ < MIDDLE)
			putchar(' ');
	col += strlen(p->v_name);
	switch (p->v_type&TMASK) {

	case BOOL:
		if (boolean(p->v_value) == FALSE) {
			col++;
			putchar('!');
		}
		printf("%s", p->v_name);
		break;

	case STRING:
		printf("%s=", p->v_name);
		col++;
		if (p->v_value) {
			cp = interp(p->v_value, NULL);
			col += strlen(cp);
			printf("%s", cp);
		}
		break;

	case NUMBER:
		col += 6;
		printf("%s=%-5d", p->v_name, number(p->v_value));
		break;

	case CHAR:
		printf("%s=", p->v_name);
		col++;
		if (p->v_value) {
			cp = ctrl(character(p->v_value));
			col += strlen(cp);
			printf("%s", cp);
		}
		break;
	}
	if (col >= MIDDLE) {
		col = 0;
		printf("\r\n");
		return;
	}
}


static int
vaccess(mode, rw)
	register unsigned mode, rw;
{
	if (mode & (rw<<PUBLIC))
		return (1);
	if (mode & (rw<<PRIVATE))
		return (1);
	return ((mode & (rw<<ROOT)) && uid == 0);
}

static value_t *
vlookup(s)
	register char *s;
{
	register value_t *p;

	for (p = vtable; p->v_name; p++)
		if (equal(p->v_name, s) || (p->v_abrev && equal(p->v_abrev, s)))
			return (p);
	return (NULL);
}

char *
vinterp(s, stop)
	register char *s;
	char stop;
{
	register char *p = s, c;
	int num;

	while ((c = *s++) && c != stop)
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
				register char *q = "n\nr\rt\tb\bf\f";

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

vstring(s, v)
	register char *s;
	register char *v;
{
	register value_t *p;
	char *v2;
	char *expand();

	p = vlookup(s);
	if (p == 0)
		return (1);
	if (p->v_type&NUMBER)
		vassign(p, atoi(v));
	else {
		if (strcmp(s, "record") == 0)
			if ((v2 = expand(v)) != NOSTR)
				v = v2;
		vassign(p, v);
	}
	return (0);
}
