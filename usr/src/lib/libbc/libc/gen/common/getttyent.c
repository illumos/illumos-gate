/*
 * Copyright (c) 1985 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <strings.h>
#include <ttyent.h>

static char *TTYFILE = "/etc/ttytab";
#define LINE 256
static struct _ttyentjunk {
	char	zapchar;
	FILE	*tf;
	char	line[LINE];
	struct	ttyent tty;
} *__ttyentjunk, *_ttyentjunk(void);

static struct _ttyentjunk *
_ttyentjunk(void)
{

	if (__ttyentjunk == 0)
		__ttyentjunk = (struct _ttyentjunk *)calloc(1, sizeof (struct _ttyentjunk));
	return (__ttyentjunk);
}

void
setttyent(void)
{
	struct _ttyentjunk *t = _ttyentjunk();

	if (t == 0)
		return;
	if (t->tf == NULL)
		t->tf = fopen(TTYFILE, "r");
	else
		rewind(t->tf);
}

void
endttyent(void)
{
	struct _ttyentjunk *t = _ttyentjunk();

	if (t == 0)
		return;
	if (t->tf != NULL) {
		(void) fclose(t->tf);
		t->tf = NULL;
	}
}

#define QUOTED	1

/*
 * Skip over the current field, removing quotes,
 * and return a pointer to the next field.
 */
static char *
skip(char *p)
{
	struct _ttyentjunk *t = _ttyentjunk();
	char *cp = p;
	int c;
	int q = 0;

	if (t == 0)
		return (0);
	for (; (c = *p) != '\0'; p++) {
		if (c == '"') {
			q ^= QUOTED;	/* obscure, but nice */
			continue;
		}
		if (q == QUOTED && *p == '\\' && *(p+1) == '"')
			p++;
		*cp++ = *p;
		if (q == QUOTED)
			continue;
		if (c == '#') {
			t->zapchar = c;
			*p = 0;
			break;
		}
		if (c == '\t' || c == ' ' || c == '\n') {
			t->zapchar = c;
			*p++ = 0;
			while ((c = *p) == '\t' || c == ' ' || c == '\n')
				p++;
			break;
		}
	}
	*--cp = '\0';
	return (p);
}

static char *
value(char *p)
{
	if ((p = index(p,'=')) == 0)
		return (NULL);
	p++;			/* get past the = sign */
	return (p);
}

struct ttyent *
getttyent(void)
{
	struct _ttyentjunk *t = _ttyentjunk();
	char *p;
	int c;

	if (t == 0)
		return (NULL);
	if (t->tf == NULL) {
		if ((t->tf = fopen(TTYFILE, "r")) == NULL)
			return (NULL);
	}
	do {
		p = fgets(t->line, LINE, t->tf);
		if (p == NULL)
			return (NULL);
		while ((c = *p) == '\t' || c == ' ' || c == '\n')
			p++;
	} while (c == '\0' || c == '#');
	t->zapchar = 0;
	t->tty.ty_name = p;
	p = skip(p);
	t->tty.ty_getty = p;
	p = skip(p);
	t->tty.ty_type = p;
	p = skip(p);
	t->tty.ty_status = 0;
	t->tty.ty_window = NULL;
	for (; *p; p = skip(p)) {
#define space(x) ((c = p[x]) == ' ' || c == '\t' || c == '\n')
		if (strncmp(p, "on", 2) == 0 && space(2))
			t->tty.ty_status |= TTY_ON;
		else if (strncmp(p, "off", 3) == 0 && space(3))
			t->tty.ty_status &= ~TTY_ON;
		else if (strncmp(p, "secure", 6) == 0 && space(6))
			t->tty.ty_status |= TTY_SECURE;
		else if (strncmp(p, "local", 5) == 0 && space(5))
			t->tty.ty_status |= TTY_LOCAL;
		else if (strncmp(p, "window=", 7) == 0)
			t->tty.ty_window = value(p);
		else
			break;
	}
	if (t->zapchar == '#' || *p == '#')
		while ((c = *++p) == ' ' || c == '\t')
			;
	t->tty.ty_comment = p;
	if (*p == 0)
		t->tty.ty_comment = 0;
	if (p = index(p, '\n'))
		*p = '\0';
	return (&t->tty);
}
