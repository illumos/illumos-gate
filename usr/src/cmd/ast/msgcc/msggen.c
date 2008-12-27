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
"[-?\n@(#)$Id: msggen (AT&T Research) 2002-03-11 $\n]"
USAGE_LICENSE
"[+NAME?msggen - generate a machine independent formatted message catalog]"
"[+DESCRIPTION?\bmsggen\b merges the message text source files \amsgfile\a"
"	into a machine independent formatted message catalog \acatfile\a."
"	The file \acatfile\a will be created if it does not already exist."
"	If \acatfile\a does exist, its messages will be included in the new"
"	\acatfile\a. If set and message numbers collide, the new message"
"	text defined in \amsgfile\a will replace the old message text"
"	currently contained in \acatfile\a. Non-ASCII characters must be"
"	UTF-8 encoded. \biconv\b(1) can be used to convert to/from UTF-8.]"
"[f:format?List the \bprintf\b(3) format signature for each message in"
"	\acatfile\a. A format signature is one line containing one character"
"	per format specification:]{"
"		[c?char]"
"		[d?double]"
"		[D?long double]"
"		[f?float]"
"		[h?short]"
"		[i?int]"
"		[j?long long]"
"		[l?long]"
"		[p?void*]"
"		[s?string]"
"		[t?ptrdiff_t]"
"		[z?size_t]"
"		[???unknown]"
"}"
"[l:list?List \acatfile\a in UTF-8 \amsgfile\a form.]"
"[s:set?Convert the \acatfile\a operand to a message set number and"
"	print the number on the standard output.]"
"[+EXTENDED DESCRIPTION?Message text source files are in \bgencat\b(1)"
"	format, defined as follows. Note that the fields of a message text"
"	source line are separated by a single blank character. Any other"
"	blank characters are considered as being part of the subsequent"
"	field. The \bNL_*\b constants are defined in one or both of"
"	\b<limits.h>\b and \b<nl_types.h>\b.]{"
"		[+$ \acomment\a?A line beginning with \b$\b followed by a"
"			blank character is treated as a comment.]"
"		[+$delset \an\a \acomment\a?This line deletes message set"
"			\an\a from an existing message catalog. \an\a"
"			denotes the set number [1, \bNL_SETMAX\b]]. Any"
"			text following the set number is treated as a"
"			comment.]"
"		[+$quote \ac\a?This line specifies an optional quote"
"			character \ac\a, which can be used to surround"
"			\amessage-text\a so that trailing spaces or"
"			empty messages are visible in a message source"
"			line. By default, or if an empty \b$quote\b"
"			directive is supplied, no quoting of \amessage-text\a"
"			will be recognized.]"
"		[+$set \an\a \acomment\a?This line specifies the set"
"			identifier of the following messages until the next"
"			\b$set\b or end-of-file appears. \an\a denotes the set"
"			identifier, which is defined as a number in the range"
"			[1, \bNL_SETMAX\b]]. Set numbers need not be"
"			contiguous. Any text following the set identifier is"
"			treated as a comment. If no \b$set\b directive is"
"			specified in a 	message text source file, all messages"
"			will be located in message set \b1\b.]"
"		[+$translation \aidentification\a \aYYYY-MM-DD\a[,...]]?Append"
"			translation info to the message catalog header. Only"
"			the newest date for a given \aidentification\a"
"			is retained in the catalog. Multiple translation lines"
"			are combined into a single \b,\b separated list.]"
"		[+\am\a \amessage-text\a?\am\a denotes the message identifier,"
"			which is defined as a number in the range"
"			[1, \bNL_MSGMAX\b]]. The message-text is stored in the"
"			message catalogue with the set identifier specified by"
"			the last \b$set\b directive, and with message"
"			identifier \am\a. If the \amessage-text\a is empty,"
"			and a blank character field separator is present, an"
"			empty string is stored in the message catalogue. If a"
"			message source line has a message number, but neither"
"			a field separator nor \amessage-text\a, the existing"
"			message with that number (if any) is deleted from the"
"			catalogue. Message identifiers need not be contiguous."
"			There are no \amessage-text\a length restrictions.]"
"}"

"\n"
"\ncatfile [ msgfile ]\n"
"\n"

"[+SEE ALSO?\bgencat\b(1), \biconv\b(1), \bmsgcc\b(1), \btranslate\b(1),"
"	\bfmtfmt\b(3)]"
;

#include <ast.h>
#include <ctype.h>
#include <ccode.h>
#include <error.h>
#include <mc.h>

typedef struct Xl_s
{
	struct Xl_s*	next;
	char*		date;
	char		name[1];
} Xl_t;

/*
 * append s to the translation list
 */

static Xl_t*
translation(Xl_t* xp, register char* s)
{
	register Xl_t*	px;
	register char*	t;
	char*		d;
	char*		e;

	do
	{
		for (; isspace(*s); s++);
		for (d = e = 0, t = s; *t; t++)
			if (*t == ',')
			{
				e = t;
				*e++ = 0;
				break;
			}
			else if (isspace(*t))
				d = t;
		if (d)
		{
			*d++ = 0;
			for (px = xp; px; px = px->next)
				if (streq(px->name, s))
				{
					if (strcoll(px->date, d) < 0)
					{
						free(px->date);
						if (!(px->date = strdup(d)))
							error(ERROR_SYSTEM|3, "out of space [translation]");
					}
					break;
				}
			if (!px)
			{
				if (!(px = newof(0, Xl_t, 1, strlen(s))) || !(px->date = strdup(d)))
					error(ERROR_SYSTEM|3, "out of space [translation]");
				strcpy(px->name, s);
				px->next = xp;
				xp = px;
			}
		}
	} while (s = e);
	return xp;
}

/*
 * sfprintf() with ccmaps(from,to)
 */

static int
ccsfprintf(int from, int to, Sfio_t* sp, const char* format, ...)
{
	va_list		ap;
	Sfio_t*		tp;
	char*		s;
	int		n;

	va_start(ap, format);
	if (from == to)
		n = sfvprintf(sp, format, ap);
	else if (tp = sfstropen())
	{
		n = sfvprintf(tp, format, ap);
		s = sfstrbase(tp);
		ccmaps(s, n, from, to);
		n = sfwrite(sp, s, n);
		sfstrclose(tp);
	}
	else
		n = -1;
	return n;
}

int
main(int argc, char** argv)
{
	register Mc_t*	mc;
	register char*	s;
	register char*	t;
	register int	c;
	register int	q;
	register int	i;
	int		num;
	char*		b;
	char*		e;
	char*		catfile;
	char*		msgfile;
	Sfio_t*		sp;
	Sfio_t*		mp;
	Sfio_t*		tp;
	Xl_t*		px;
	Xl_t*		bp;

	Xl_t*		xp = 0;
	int		format = 0;
	int		list = 0;
	int		set = 0;

	NoP(argc);
	error_info.id = "msggen";
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'f':
			format = list = 1;
			continue;
		case 'l':
			list = 1;
			continue;
		case 's':
			set = 1;
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
	if (error_info.errors || !(catfile = *argv++))
		error(ERROR_USAGE|4, "%s", optusage(NiL));

	/*
	 * set and list only need catfile
	 */

	if (set)
	{
		sfprintf(sfstdout, "%d\n", mcindex(catfile, NiL, NiL, NiL));
		return error_info.errors != 0;
	}
	else if (list)
	{
		if (!(sp = sfopen(NiL, catfile, "r")))
			error(ERROR_SYSTEM|3, "%s: cannot read catalog", catfile);
		if (!(mc = mcopen(sp)))
			error(ERROR_SYSTEM|3, "%s: catalog content error", catfile);
		sfclose(sp);
		if (format)
		{
			for (set = 1; set <= mc->num; set++)
				if (mc->set[set].num)
				{
					sfprintf(sfstdout, "$set %d\n", set);
					for (num = 1; num <= mc->set[set].num; num++)
						if (s = mc->set[set].msg[num])
							sfprintf(sfstdout, "%d \"%s\"\n", num, fmtfmt(s));
				}
		}
		else
		{
			if (*mc->translation)
			{
				ccsfprintf(CC_NATIVE, CC_ASCII, sfstdout, "$translation ");
				sfprintf(sfstdout, "%s", mc->translation);
				ccsfprintf(CC_NATIVE, CC_ASCII, sfstdout, "\n");
			}
			ccsfprintf(CC_NATIVE, CC_ASCII, sfstdout, "$quote \"\n");
			for (set = 1; set <= mc->num; set++)
				if (mc->set[set].num)
				{
					ccsfprintf(CC_NATIVE, CC_ASCII, sfstdout, "$set %d\n", set);
					for (num = 1; num <= mc->set[set].num; num++)
						if (s = mc->set[set].msg[num])
						{
							ccsfprintf(CC_NATIVE, CC_ASCII, sfstdout, "%d \"", num);
							while (c = *s++)
							{
								/*INDENT...*/

			switch (c)
			{
			case 0x22: /* " */
			case 0x5C: /* \ */
				sfputc(sfstdout, 0x5C);
				break;
			case 0x07: /* \a */
				c = 0x61;
				sfputc(sfstdout, 0x5C);
				break;
			case 0x08: /* \b */
				c = 0x62;
				sfputc(sfstdout, 0x5C);
				break;
			case 0x0A: /* \n */
				c = 0x6E;
				sfputc(sfstdout, 0x5C);
				break;
			case 0x0B: /* \v */
				c = 0x76;
				sfputc(sfstdout, 0x5C);
				break;
			case 0x0C: /* \f */
				c = 0x66;
				sfputc(sfstdout, 0x5C);
				break;
			case 0x0D: /* \r */
				c = 0x72;
				sfputc(sfstdout, 0x5C);
				break;
			}

								/*...UNDENT*/
								sfputc(sfstdout, c);
							}
							ccsfprintf(CC_NATIVE, CC_ASCII, sfstdout, "\"\n");
						}
				}
		}
		mcclose(mc);
		return error_info.errors != 0;
	}
	else if (!(msgfile = *argv++) || *argv)
		error(3, "exactly one message file must be specified");

	/*
	 * open the files and handles
	 */

	if (!(tp = sfstropen()))
		error(ERROR_SYSTEM|3, "out of space [string stream]");
	if (!(mp = sfopen(NiL, msgfile, "r")))
		error(ERROR_SYSTEM|3, "%s: cannot read message file", msgfile);
	sp = sfopen(NiL, catfile, "r");
	if (!(mc = mcopen(sp)))
		error(ERROR_SYSTEM|3, "%s: catalog content error", catfile);
	if (sp)
		sfclose(sp);
	xp = translation(xp, mc->translation);

	/*
	 * read the message file
	 */

	q = 0;
	set = 1;
	error_info.file = msgfile;
	while (s = sfgetr(mp, '\n', 1))
	{
		error_info.line++;
		if (!*s)
			continue;
		if (*s == '$')
		{
			if (!*++s || isspace(*s))
				continue;
			for (t = s; *s && !isspace(*s); s++);
			if (*s)
				*s++ = 0;
			if (streq(t, "delset"))
			{
				while (isspace(*s))
					s++;
				num = (int)strtol(s, NiL, 0);
				if (num < mc->num && mc->set[num].num)
					for (i = 1; i <= mc->set[num].num; i++)
						mcput(mc, num, i, NiL);
			}
			else if (streq(t, "quote"))
				q = *s ? *s : 0;
			else if (streq(t, "set"))
			{
				while (isspace(*s))
					s++;
				num = (int)strtol(s, &e, 0);
				if (e != s)
					set = num;
				else
					error(2, "set number expected");
			}
			else if (streq(t, "translation"))
				xp = translation(xp, s);
		}
		else
		{
			t = s + sfvalue(mp);
			num = (int)strtol(s, &e, 0);
			if (e != s)
			{
				s = e;
				if (!*s)
				{
					if (mcput(mc, set, num, NiL))
						error(2, "(%d,%d): cannot delete message", set, num);
				}
				else if (isspace(*s++))
				{
					if (t > (s + 1) && *(t -= 2) == '\\')
					{
						sfwrite(tp, s, t - s);
						while (s = sfgetr(mp, '\n', 0))
						{
							error_info.line++;
							t = s + sfvalue(mp);
							if (t <= (s + 1) || *(t -= 2) != '\\')
								break;
							sfwrite(tp, s, t - s);
						}
						if (!(s = sfstruse(tp)))
							error(ERROR_SYSTEM|3, "out of space");
					}
					if (q)
					{
						if (*s++ != q)
						{
							error(2, "(%d,%d): %c quote expected", set, num, q);
							continue;
						}
						b = t = s;
						while (c = *s++)
						{
							if (c == '\\')
							{
								c = chresc(s - 1, &e);
								s = e;
								if (c)
									*t++ = c;
								else
									error(1, "nul character ignored");
							}
							else if (c == q)
								break;
							else
								*t++ = c;
						}
						if (*s)
						{
							error(2, "(%d,%d): characters after quote not expected", set, num);
							continue;
						}
						*t = 0;
						s = b;
					}
					if (mcput(mc, set, num, s))
						error(2, "(%d,%d): cannot add message", set, num);
				}
				else
					error(2, "message text expected");
			}
			else
				error(2, "message number expected");
		}
	}
	error_info.file = 0;
	error_info.line = 0;

	/*
	 * fix up the translation record
	 */

	if (xp)
	{
		t = "";
		for (;;)
		{
			for (bp = 0, px = xp; px; px = px->next)
				if (px->date && (!bp || strcoll(bp->date, px->date) < 0))
					bp = px;
			if (!bp)
				break;
			sfprintf(tp, "%s%s %s", t, bp->name, bp->date);
			t = ", ";
			bp->date = 0;
		}
		if (!(mc->translation = sfstruse(tp)))
			error(ERROR_SYSTEM|3, "out of space");
	}

	/*
	 * dump the catalog to a local temporary
	 * rename if no errors
	 */

	if (!(s = pathtemp(NiL, 0, "", error_info.id, NiL)) || !(sp = sfopen(NiL, s, "w")))
		error(ERROR_SYSTEM|3, "%s: cannot write catalog file", catfile);
	if (mcdump(mc, sp) || mcclose(mc) || sfclose(sp))
	{
		remove(s);
		error(ERROR_SYSTEM|3, "%s: temporary catalog file write error", s);
	}
	remove(catfile);
	if (rename(s, catfile))
		error(ERROR_SYSTEM|3, "%s: cannot rename from temporary catalog file %s", catfile, s);
	return error_info.errors != 0;
}
