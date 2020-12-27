/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * fmtmsg implementation
 */

#include <ast.h>

#if _lib_fmtmsg

NoN(fmtmsg)

#else

#define MM_TABLES

#include <fmtmsg.h>

#define INIT_VERB	0x1
#define INIT_CONSOLE	0x2

static struct
{
	int		console;
	unsigned int	init;
	unsigned int	mask;
} mm;

const MM_table_t	mm_class[] =
{
	"null",		0,		0,
	"hard",		"HARDWARE",	MM_HARD,
	"soft",		"SOFTWARE",	MM_SOFT,
	"firm",		"FIRMWARE",	MM_FIRM,
	"appl",		"APPLICATION",	MM_APPL,
	"util",		"UTILITY",	MM_UTIL,
	"opsys",	"KERNEL",	MM_OPSYS,
	"print",	0,		MM_PRINT,
	"console",	0,		MM_CONSOLE,
	"recov",	"RECOVERABLE",	MM_RECOVER,
	"nrecov",	"PANIC",	MM_NRECOV,
	0,		0,		0
};

static const MM_table_t	mm_severity_init[] =
{
	"nosev",	0,		MM_NOSEV,
	"halt",		"HALT",		MM_HALT,
	"error",	"ERROR",	MM_ERROR,
	"warn",		"WARNING",	MM_WARNING,
	"info",		"INFO",		MM_INFO,
	0,		0,		0
};

const MM_table_t	mm_verb[] =
{
	"all",		0,		MM_all,
	"action",	0,		MM_action,
	"class",	0,		MM_class,
	"default",	0,		MM_default,
	"label",	0,		MM_label,
	"severity",	0,		MM_severity,
	"source",	0,		MM_source,
	"tag",		0,		MM_tag,
	"text",		0,		MM_text,
	0,		0,		0
};

const MM_table_t*
_mm_severity(void)
{
	static MM_table_t*	severity;

	if (!severity)
	{
		register char*		s;
		register MM_table_t*	p;
		register int		n;
		register int		c;
		char*			e;
		MM_table_t*		q;

		n = 0;
		if ((s = getenv(MM_SEVERITY_ENV)) && *s)
		{
			e = s;
			c = 0;
			for (;;)
			{
				switch (*s++)
				{
				case 0:
					break;
				case ',':
					if (++c > 2)
					{
						n = 0;
						break;
					}
					continue;
				case ':':
					if (c != 2)
					{
						n = 0;
						break;
					}
					c = 0;
					n++;
					continue;
				default:
					continue;
				}
				break;
			}
			if (c == 2)
				n++;
			else n = 0;
			if (n)
			{
				for (p = (MM_table_t*)mm_severity_init; p->name; p++);
				n += p - (MM_table_t*)mm_severity_init + 1;
				if (severity = newof(0, MM_table_t, n, s - e))
				{
					s = (char*)severity + n * sizeof(MM_table_t);
					strcpy(s, e);
					p = severity;
					for (q = (MM_table_t*)mm_severity_init; q->name; q++)
						*p++ = *q;
					p->name = s;
					c = 0;
					for (;;)
					{
						switch (*s++)
						{
						case 0:
							break;
						case ',':
							switch (c++)
							{
							case 0:
								*(s - 1) = 0;
								p->value = strtol(s, NiL, 0);
								break;
							case 1:
								p->display = s;
								break;
							}
							continue;
						case ':':
							c = 0;
							*(s - 1) = 0;
							(++p)->name = s;
							continue;
						default:
							continue;
						}
						break;
					}
				}
			}
		}
		if (!severity)
			severity = (MM_table_t*)mm_severity_init;
	}
	return (const MM_table_t*)severity;
}

static char*
display(register const MM_table_t* tab, int value, int mask)
{
	while (tab->name)
	{
		if (value == tab->value || mask && (value & tab->value))
			return (char*)tab->display;
		tab++;
	}
	return 0;
}

int
fmtmsg(long classification, const char* label, int severity, const char* text, const char* action, const char* tag)
{
	register int		c;
	register char*		s;
	register char*		t;
	register MM_table_t*	p;
	int			n;
	int			m;
	int			r;
	int			fd;
	unsigned int		mask;
	Sfio_t*			sp;
	char			lab[MM_LABEL_1_MAX + MM_LABEL_2_MAX + 3];

	if (!mm.init)
	{
		mm.init = INIT_VERB;
		if (!(s = getenv(MM_VERB_ENV)))
			mm.mask = MM_default;
		else for (;;)
		{
			if (t = strchr(s, ':'))
				*t = 0;
			if (!(p = (MM_table_t*)strlook(mm_verb, sizeof(MM_table_t), s)))
			{
				mm.mask = MM_default;
				if (t)
					*t = ':';
				break;
			}
			mm.mask |= p->value;
			if (!t)
				break;
			*t++ = ':';
			s = t;
		}
	}
	if (!(classification & (MM_CONSOLE|MM_PRINT)))
		return 0;
	if (!(sp = sfstropen()))
		return MM_NOTOK;
	r = 0;
	if (s = (char*)label)
	{
		if (t = strchr(s, ':'))
		{
			if ((n = t - s) > MM_LABEL_1_MAX)
				n = MM_LABEL_1_MAX;
			sfprintf(sp, "%*.*s:", n, n, s);
			s = ++t;
			if ((n = strlen(t)) > MM_LABEL_2_MAX)
				n = MM_LABEL_2_MAX;
			sfprintf(sp, "%*.*s", n, n, s);
		}
		else
		{
			if ((n = strlen(t)) > MM_LABEL_1_MAX)
				n = MM_LABEL_1_MAX;
			sfprintf(sp, "%*.*s", n, n, s);
		}
		if (!(s = sfstruse(sp)))
		{
			sfstrclose(sp);
			return MM_NOTOK;
		}
		strcpy(lab, s);
	}
	for (;;)
	{
		if (classification & MM_CONSOLE)
		{
			classification &= ~MM_CONSOLE;
			if (!(mm.init & INIT_CONSOLE))
				mm.console = open("/dev/console", O_WRONLY|O_APPEND|O_NOCTTY);
			if (mm.console < 0)
			{
				r |= MM_NOCON;
				continue;
			}
			c = MM_NOCON;
			fd = mm.console;
			mask = MM_all;
		}
		else if (classification & MM_PRINT)
		{
			classification &= ~MM_PRINT;
			c = MM_NOMSG;
			fd = 2;
			mask = mm.mask;
		}
		else break;
		if ((mask & MM_label) && label)
			sfprintf(sp, "%s: ", lab);
		if ((mask & MM_severity) && (s = display(mm_severity, severity, 0)))
			sfprintf(sp, "%s: ", s);
		n = sfstrtell(sp);
		if ((mask & MM_text) && text)
			sfprintf(sp, "%s\n", text);
		else sfputc(sp, '\n');
		if ((mask & MM_action) && action || (mask & MM_tag) && (label || tag))
		{
			if (fd != mm.console && (n -= 8) > 0)
				sfprintf(sp, "%*.*s", n, n, "");
			sfprintf(sp, "TO FIX:");
			if ((mask & MM_action) && action)
				sfprintf(sp, " %s", action);
			if ((mask & MM_tag) && (label || tag))
			{
				sfprintf(sp, "  ");
				if (!tag || label && !strchr(tag, ':'))
					sfprintf(sp, "%s%s", lab, tag ? ":" : "");
				if (tag)
					sfprintf(sp, "%s", tag);
			}
			if (mask & (MM_class|MM_source|MM_status))
			{
				sfputc(sp, ' ');
				if ((mask & MM_source) && (m = classification & (MM_APPL|MM_UTIL|MM_OPSYS)) && (s = display(mm_class, m, 1)))
					sfprintf(sp, " %s", s);
				if ((mask & MM_class) && (m = classification & (MM_HARD|MM_SOFT|MM_FIRM)) && (s = display(mm_class, m, 1)))
					sfprintf(sp, " %s", s);
				if ((mask & MM_status) && (m = classification & (MM_RECOVER|MM_NRECOV)) && (s = display(mm_class, m, 1)))
					sfprintf(sp, " %s", s);
			}
			sfputc(sp, '\n');
		}
		n = sfstrtell(sp);
		if (!(s = sfstruse(sp)) || write(fd, s, n) != n)
			r |= c;
	}
	sfstrclose(sp);
	return r;
}

#endif
