/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 2000-2008 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 */

static const char usage[] =
"[-?\n@(#)$Id: msgcvt (AT&T Research) 2000-05-01 $\n]"
USAGE_LICENSE
"[+NAME?msgcvt - convert message file to/from html]"
"[+DESCRIPTION?\bmsgcvt\b reads a \bgencat\b(1) format file on the standard"
"	input and converts it to \bhtml\b on the standard output. The input"
"	file must contain the control statement \b$quote \"\b and use the \""
"	character to quote message text. The output is in a form suitable for"
"	automatic translation by web sites like"
"	\bhttp://babelfish.altavista.com/\b or filters like"
"	\btranslate\b(1).]"
"[h:html?Generate \bhtml\b from \bgencat\b(1) input. This is the default.]"
"[m:msg?Generate a \bgencat\b(1) message file from (presumably translated)"
"	\bhtml\b. Wide characters are UTF-8 encoded.]"
"[r:raw?The message file is raw message text, one message per line, with no"
"	quoting or line numbering.]"
"[+SEE ALSO?\bgencat\b(1), \bmsgcc\b(1), \bmsggen\b(1), \btranslate\b(1)]"
;

#include <ast.h>
#include <ctype.h>
#include <error.h>

#define MSG_RAW		(1<<0)
#define MSG_SPLICE	(1<<1)

#define SPACE(s)	(isspace(*s)&&(s+=1)||*s=='\\'&&(*(s+1)=='n'||*(s+1)=='t')&&(s+=2))

typedef void (*Convert_f)(Sfio_t*, Sfio_t*, int);

typedef struct
{
	const char*	name;
	int		code;
} Code_t;

static const Code_t	codes[] =
{
	"aacute",	225,
	"Aacute",	193,
	"acirc",	226,
	"Acirc",	194,
	"aelig",	230,
	"AElig",	198,
	"agrave",	224,
	"Agrave",	192,
	"amp",		'&',
	"aring",	229,
	"Aring",	197,
	"atilde",	227,
	"Atilde",	195,
	"auml",		228,
	"Auml",		196,
	"ccedil",	231,
	"Ccedil",	199,
	"copy",		169,
	"eacute",	233,
	"Eacute",	201,
	"ecirc",	234,
	"Ecirc",	202,
	"egrave",	232,
	"Egrave",	200,
	"euml",		235,
	"Euml",		203,
	"gt",		'>',
	"iacute",	237,
	"Iacute",	205,
	"icirc",	238,
	"Icirc",	206,
	"igrave",	236,
	"Igrave",	204,
	"iuml",		239,
	"Iuml",		207,
	"lt",		'<',
	"nbsp",		' ',
	"ntilde",	241,
	"Ntilde",	209,
	"oacute",	243,
	"Oacute",	211,
	"ocirc",	244,
	"Ocirc",	212,
	"ograve",	242,
	"Ograve",	210,
	"oslash",	248,
	"Oslash",	216,
	"otilde",	245,
	"Otilde",	213,
	"ouml",		246,
	"Ouml",		214,
	"quot",		'"',
	"reg",		174,
	"szlig",	223,
	"uacute",	250,
	"Uacute",	218,
	"ucirc",	251,
	"Ucirc",	219,
	"ugrave",	249,
	"Ugrave",	217,
	"uuml",		252,
	"Uuml",		220,
	"yuml",		255,
};

static int
decode(Sfio_t* ip)
{
	register int	c;
	register int	i;
	char		name[32];

	if ((c = sfgetc(ip)) == EOF)
		return '&';
	name[0] = c;
	i = 1;
	if (c != '#' && !isalpha(c))
		goto bad;
	while ((c = sfgetc(ip)) != EOF && c != ';')
	{
		if (c == '&')
			i = 0;
		else
		{
			name[i++] = c;
			if (!isalnum(c) && (i > 1 || c != '#') || i >= (elementsof(name) - 1))
				goto bad;
		}
	}
	name[i] = 0;
	if (name[0] == '#')
	{
		switch (c = strtol(name + 1, NiL, 10))
		{
		case 91:
			c = '[';
			break;
		case 93:
			c = ']';
			break;
		}
	}
	else
	{
		for (i = 0; i < elementsof(codes); i++)
			if (streq(codes[i].name, name))
			{
				c = codes[i].code;
				break;
			}
		if (i >= elementsof(codes))
			goto bad;
	}
	return c;
 bad:
	name[i] = 0;
	if (c == ';')
		error(1, "&%s: unknown HTML special character -- & assumed", name);
	else
		error(1, "&%s: invalid HTML special character -- & assumed", name);
	while (i--)
		sfungetc(ip, name[i]);
	return '&';
}

static int
sfpututf(Sfio_t* op, register int w)
{
	if (!(w & ~0x7F))
		return sfputc(op, w);
	else if (!(w & ~0x7FF))
		sfputc(op, 0xC0 + (w >> 6));
	else if (!(w & ~0xFFFF))
	{
		sfputc(op, 0xE0 + (w >> 12));
		sfputc(op, 0x80 + (w >> 6 ) & 0x3F);
	}
	else
		return sfputc(op, '?');
	return sfputc(op, 0x80 + (w & 0x3F));
}

static int
sfnext(Sfio_t* ip)
{
	register int	c;

	while (isspace(c = sfgetc(ip)));
	return c;
}

static void
html2msg(register Sfio_t* ip, register Sfio_t* op, int flags)
{
	register int	c;
	register int	q;

 again:
	while ((c = sfgetc(ip)) != EOF)
		if (c == '<')
		{
			if ((c = sfnext(ip)) == 'O' &&
			    (c = sfnext(ip)) == 'L' &&
			    isspace(c = sfgetc(ip)) &&
			    (c = sfnext(ip)) == 'S' &&
			    (c = sfnext(ip)) == 'T' &&
			    (c = sfnext(ip)) == 'A' &&
			    (c = sfnext(ip)) == 'R' &&
			    (c = sfnext(ip)) == 'T' &&
			    (c = sfnext(ip)) == '=' &&
			    (c = sfnext(ip)) == '"' &&
			    (c = sfnext(ip)) == '5' &&
			    (c = sfnext(ip)) == '5' &&
			    (c = sfnext(ip)) == '0' &&
			    (c = sfnext(ip)) == '7' &&
			    (c = sfnext(ip)) == '1' &&
			    (c = sfnext(ip)) == '7' &&
			    (c = sfnext(ip)) == '"' &&
			    (c = sfnext(ip)) == '>')
				break;
			while (c != EOF && c != '>')
				c = sfgetc(ip);
		}
	if ((c = sfnext(ip)) != EOF)
		sfungetc(ip, c);
	q = 0;
	for (;;)
	{
		switch (c = sfgetc(ip))
		{
		case EOF:
			break;
		case '&':
			c = decode(ip);
			sfpututf(op, c);
			if (isspace(c))
			{
				while (isspace(c = sfgetc(ip)));
				if (c == EOF)
					break;
				sfungetc(ip, c);
			}
			continue;
		case '<':
			switch (c = sfnext(ip))
			{
			case '/':
				if ((c = sfnext(ip)) == 'O' &&
				    (c = sfgetc(ip)) == 'L' &&
				    (c = sfnext(ip)) == '>')
				{
					if (q)
					{
						sfputc(op, q);
						q = '"';
					}
					goto again;
				}
				break;
			case 'B':
				if ((c = sfgetc(ip)) == 'R' &&
				    (c = sfnext(ip)) == '>')
					sfputc(op, ' ');
				break;
			case 'L':
				if ((c = sfgetc(ip)) == 'I' &&
				    (c = sfnext(ip)) == '>' &&
				     isdigit(c = sfnext(ip)))
				{
					if (q)
						sfputc(op, q);
					else
						q = '"';
					sfputc(op, '\n');
					do
					{
						sfputc(op, c);
					} while (isdigit(c = sfgetc(ip)));
					if (c == EOF)
						break;
					sfputc(op, ' ');
					sfputc(op, '"');
					if (isspace(c))
						c = sfnext(ip);
					if (c == '<' &&
					    (c = sfnext(ip)) == 'L' &&
					    (c = sfgetc(ip)) == 'I' &&
					    (c = sfnext(ip)) == '>')
						/* great */;
					continue;
				}
				break;
			case 'P':
				if ((c = sfnext(ip)) == '>')
					sfputc(op, '\n');
				else if (c == 'C' &&
					 (c = sfgetc(ip)) == 'L' &&
					 (c = sfgetc(ip)) == 'A' &&
					 (c = sfgetc(ip)) == 'S' &&
					 (c = sfgetc(ip)) == 'S' &&
					 (c = sfnext(ip)) == '=' &&
					 (c = sfnext(ip)) == '"')
					for (;;)
					{
						switch (c = sfgetc(ip))
						{
						case EOF:
						case '"':
							break;
						case '&':
							c = decode(ip);
							sfpututf(op, c);
							continue;
						default:
							sfpututf(op, c);
							continue;
						}
						break;
					}
				break;
			}
			while (c != EOF && c != '>')
				c = sfgetc(ip);
			if (c == EOF || (c = sfgetc(ip)) == EOF)
				break;
			sfungetc(ip, c);
			continue;
		case '"':
			if (!flags)
				sfputc(op, '\\');
			sfputc(op, c);
			continue;
		case '\n':
			if (flags)
			{
				sfputc(op, c);
				continue;
			}
			/*FALLTHROUGH*/
		case ' ':
		case '\t':
			while ((c = sfgetc(ip)) != EOF)
				if (c == '&')
				{
					c = decode(ip);
					if (!isspace(c))
						sfputc(op, ' ');
					sfpututf(op, c);
					break;
				}
				else if (!isspace(c))
				{
					if (c == '<')
					{
						c = sfgetc(ip);
						if (c == EOF)
							break;
						sfungetc(ip, c);
						sfungetc(ip, '<');
						if (c != 'L' && c != '/')
							sfputc(op, ' ');
					}
					else
					{
						if (c != EOF)
							sfungetc(ip, c);
						sfputc(op, ' ');
					}
					break;
				}
			continue;
		case '\r':
		case '[':
		case ']':
			continue;
		default:
			sfpututf(op, c);
			continue;
		}
		break;
	}
	if (q)
		sfputc(op, q);
	sfputc(op, '\n');
}

static void
encode(Sfio_t* op, register int c)
{
	if (c == '<')
		sfprintf(op, "&lt;");
	else if (c == '>')
		sfprintf(op, "&gt;");
	else if (c == '"')
		sfprintf(op, "&quot;");
	else if (c == '&')
		sfprintf(op, "&amp;");
	else if (c == '[')
		sfprintf(op, "&#091;");
	else if (c == ']')
		sfprintf(op, "&#093;");
	else
		sfputc(op, c);
}

static void
msg2html(register Sfio_t* ip, register Sfio_t* op, register int flags)
{
	register char*	s;
	register int	c;
	register int	q;
	register int	p;

	sfprintf(op, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\"><HTML><HEAD><!-- text massaged for external translation --></HEAD><BODY>\n");
	sfprintf(op, "<OL START=\"550717\">\n");
	p = q = 0;
	while (s = sfgetr(ip, '\n', 1))
	{
		error_info.line++;
		if (flags)
			sfprintf(op, "<P>");
		else
		{
			if (*s == '$')
			{
				if (p)
					sfprintf(op, "<P>");
				else
					p = 1;
				sfprintf(op, "<P CLASS=\"", s);
				while (c = *s++)
					encode(op, c);
				sfprintf(op, "\">\n");
				continue;
			}
			p = 0;
			if (!isdigit(*s))
				continue;
			sfprintf(op, "<LI>");
			while (isdigit(c = *s++))
				sfputc(op, c);
			sfprintf(op, "<LI>");
			while (c && c != '"')
				c = *s++;
			if (!c)
				s--;
			else if (isspace(*s))
			{
				s++;
				sfprintf(op, "<BR>");
			}
		}
		for (;;)
		{
			switch (c = *s++)
			{
			case 0:
				flags &= ~MSG_SPLICE;
				if (q)
				{
					q = 0;
					sfprintf(op, "\">");
				}
				sfputc(op, '\n');
				break;
			case '<':
				sfprintf(op, "&lt;");
				continue;
			case '>':
				sfprintf(op, "&gt;");
				continue;
			case '&':
				sfprintf(op, "&amp;");
				continue;
			case '[':
				sfprintf(op, "&#091;");
				continue;
			case ']':
				sfprintf(op, "&#093;");
				continue;
			case '$':
				if (!q)
				{
					q = 1;
					sfprintf(op, "<P CLASS=\"");
				}
				sfputc(op, c);
				while (isalnum(c = *s++))
					sfputc(op, c);
				s--;
				continue;
			case '%':
				if (!q)
				{
					q = 1;
					sfprintf(op, "<P CLASS=\"");
				}
				sfputc(op, c);
				if (*s == '%')
					sfputc(op, *s++);
				else
					do
					{
						if (!(c = *s++) || c == '"')
						{
							s--;
							break;
						}
						encode(op, c);
					} while (!isalpha(c) || (!islower(c) || c == 'h' || c == 'l') && isalpha(*s));
				if (SPACE(s))
					sfprintf(op, "&nbsp;");
				continue;
			case '"':
				if (!(flags & MSG_RAW))
				{
					s = "";
					continue;
				}
				/*FALLTHROUGH*/
			case '\'':
			case ':':
			case '/':
			case '+':
			case '@':
				if (!q)
				{
					q = 1;
					sfprintf(op, "<P CLASS=\"");
				}
				/*FALLTHROUGH*/
			case '.':
			case ',':
				sfputc(op, c);
				if (SPACE(s))
					sfprintf(op, "&nbsp;");
				continue;
			case '\\':
				if (!(c = *s++))
				{
					flags |= MSG_SPLICE;
					break;
				}
				if (c != 'n' && c != 't')
				{
					if (!q)
					{
						q = 1;
						sfprintf(op, "<P CLASS=\"");
					}
					sfputc(op, '\\');
					encode(op, c);
					if (c == 'b')
					{
						for (;;)
						{
							if (!(c = *s++) || c == '"')
							{
								s--;
								break;
							}
							if (c == '?')
							{
								if (*s != '?')
								{
									s--;
									break;
								}
								sfputc(op, c);
								sfputc(op, *s++);
								continue;
							}
							if (c == '\\')
							{
								if (!*s)
									break;
								sfputc(op, c);
								if (*s == 'a' || *s == 'b' || *s == '0')
								{
									sfputc(op, *s++);
									break;
								}
								c = *s++;
							}
							encode(op, c);
						}
					}
					else if (isdigit(c) && isdigit(*s))
					{
						sfputc(op, *s++);
						if (isdigit(*s))
							sfputc(op, *s++);
					}
					if (SPACE(s))
						sfprintf(op, "&nbsp;");
					continue;
				}
				/*FALLTHROUGH*/
			case ' ':
			case '\t':
				while (isspace(*s) || *s == '\\' && (*(s + 1) == 'n' || *(s + 1) == 't') && s++)
					s++;
				if (*s == '"')
				{
					if (q)
					{
						q = 0;
						sfprintf(op, " \">");
					}
					else
						sfprintf(op, "<BR>");
					continue;
				}
				c = ' ';
				/*FALLTHROUGH*/
			default:
				if (q)
				{
					q = 0;
					sfprintf(op, "\">");
				}
				sfputc(op, c);
				continue;
			}
			break;
		}
	}
	sfprintf(op, "</OL>\n");
	sfprintf(op, "</BODY></HTML>\n");
	error_info.line = 0;
}

int
main(int argc, char** argv)
{
	int		flags = 0;
	Convert_f	convert = msg2html;

	NoP(argc);
	error_info.id = "msgcvt";
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'h':
			convert = msg2html;
			continue;
		case 'm':
			convert = html2msg;
			continue;
		case 'r':
			flags |= MSG_RAW;
			continue;
		case '?':
			error(ERROR_USAGE|4, "%s", opt_info.arg);
			continue;
		case ':':
			error(2, "%s", opt_info.arg);
			continue;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors)
		error(ERROR_USAGE|4, "%s", optusage(NiL));
	(*convert)(sfstdin, sfstdout, flags);
	return error_info.errors != 0;
}
