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
 *
 * C message catalog preprocessor
 */

static const char usage[] =
"[-?\n@(#)$Id: msgcpp (AT&T Research) 2002-03-11 $\n]"
USAGE_LICENSE
"[+NAME?msgcpp - C language message catalog preprocessor]"
"[+DESCRIPTION?\bmsgcpp\b is a C language message catalog preprocessor."
"	It accepts \bcpp\b(1) style options and arguments. \bmsgcpp\b"
"	preprocesses an input C source file and emits keyed lines to the"
"	output, usually for further processing by \bmsgcc\b(1). \bmsgcc\b"
"	output is in the \bgencat\b(1) syntax. Candidate message text is"
"	determined by arguments to the \bast\b \b<error.h>\b and"
"	\b<option.h>\b functions. The \bmsgcpp\b keyed output lines are:]{"
"	[+cmd \acommand\a?\acommand\a is a candidate for \b--??keys\b"
"		option string generation. Triggered by"
"		\bb_\b\acommand\a\b(int argc,\b in the input.]"
"	[+def \aname\a \astring\a?\aname\a is a candidate variable with"
"		string value \astring\a.]"
"	[+str \astring\a?\astring\a should be entered into the catalog.]"
"	[+var \aname\a?If \bdef\b \aname\a occurs then its \astring\a value"
"		should be entered into the catalog.]"
"	}"
"[+?The input source file is preprocessed with the \bpp:allpossible\b"
"	option on. This enables non-C semantics; all source should first"
"	be compiled error-free with a real compiler before running \bmsgcpp\b."
"	The following changes are enabled for the top level files (i.e.,"
"	included file behavior is not affected):]{"
"		[+(1)?All \b#if\b, \b#ifdef\b and \b#ifndef\b branches"
"			are enabled.]"
"		[+(2)?The first definition for a macro is retained, even when"
"			subsequent \b#define\b statements would normally"
"			redefine the macro. \b#undef\b must be used to"
"			redefine a macro.]"
"		[+(3)?Macro calls with an improper number of arguments are"
"			silently ignored.]"
"		[+(4)?\b#include\b on non-existent headers are silently"
"			ignored.]"
"		[+(5)?Invalid C source characters are silently ignored.]"
"	}"
"[+?\b\"msgcat.h\"\b is included if it exists. This file may contain macro"
"	definitions for functions that translate string arguments. If \afoo\a"
"	is a function that translates its string arguments then include the"
"	line \b#define \b\afoo\a\b _TRANSLATE_\b in \bmsgcat.h\b or specify"
"	the option \b-D\b\afoo\a\b=_TRANSLATE_\b. If \abar\a is a function"
"	that translates string arguments if the first argument is \bstderr\b"
"	then use either \b#define \b\abar\a\b _STDIO_\b or"
"	\b-D\b\abar\a\b=_STDIO_\b.]"
"[+?The macro \b_BLD_msgcat\b is defined to be \b1\b. As an alternative to"
"	\bmsgcat.h\b, \b_TRANSLATE_\b definitions could be placed inside"
"	\b#ifdef _BLD_msgcat\b ... \b#endif\b.]"

"\n"
"\n[ input [ output ] ]\n"
"\n"

"[+SEE ALSO?\bcc\b(1), \bcpp\b(1), \bgencat\b(1), \bmsggen\b(1),"
"	\bmsgcc\b(1), \bmsgcvt\b(1)]"
;

#include <ast.h>
#include <error.h>

#include "pp.h"
#include "ppkey.h"

#define T_STDERR	(T_KEYWORD+1)
#define T_STDIO		(T_KEYWORD+2)
#define T_TRANSLATE	(T_KEYWORD+3)

#define OMIT		"*@(\\[[-+]*\\?*\\]|\\@\\(#\\)|Copyright \\(c\\)|\\\\000|\\\\00[!0-9]|\\\\0[!0-9])*"

static struct ppkeyword	keys[] =
{
	"char",		T_CHAR,
	"int",		T_INT,
	"sfstderr",	T_STDERR,
	"stderr",	T_STDERR,
	"_STDIO_",	T_STDIO,
	"_TRANSLATE_",	T_TRANSLATE,
	0,		0
};

static int
msgppargs(char** argv, int last)
{
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 0:
			break;
		case '?':
			if (!last)
			{
				opt_info.again = 1;
				return 1;
			}
			error(ERROR_USAGE|4, "%s", opt_info.arg);
			break;
		case ':':
			if (!last)
			{
				opt_info.again = 1;
				return 1;
			}
			error(2, "%s", opt_info.arg);
			continue;
		default:
			if (!last)
			{
				opt_info.again = 1;
				return 1;
			}
			continue;
		}
		break;
	}
	return argv[opt_info.index] != 0;
}

int
main(int argc, char** argv)
{
	register char*	s;
	register int	x;
	register int	c;
	Sfio_t*		tmp;

	NoP(argc);
	if (s = strrchr(*argv, '/'))
		s++;
	else
		s = *argv;
	error_info.id = s;
	ppop(PP_DEFAULT, PPDEFAULT);
	optjoin(argv, msgppargs, ppargs, NiL);
	if (strlen(s) >= 5 && *(s + 3) != 'c')
	{
		ppop(PP_PLUSPLUS, 1);
		ppop(PP_NOHASH, 1);
		ppop(PP_PROBE, "CC");
	}
	ppop(PP_SPACEOUT, 0);
	ppop(PP_COMPILE, keys);
	ppop(PP_OPTION, "allpossible");
	ppop(PP_OPTION, "catliteral");
	ppop(PP_OPTION, "modern");
	ppop(PP_OPTION, "readonly");
	ppop(PP_DEFINE, "_BLD_msgcat=1");
	ppop(PP_DEFINE, "const=");
	ppop(PP_DEFINE, "errorf=_TRANSLATE_");
	ppop(PP_DEFINE, "register=");
	ppop(PP_DEFINE, "sfstderr=sfstderr");
	ppop(PP_DEFINE, "stderr=stderr");
	ppop(PP_DEFINE, "_(m)=_TRANSLATE_(m)");
	ppop(PP_DEFINE, "__(m)=_TRANSLATE_(m)");
	ppop(PP_DEFINE, "gettxt(i,m)=_TRANSLATE_(m)");
	ppop(PP_DEFINE, "gettext(m)=_TRANSLATE_(m)");
	ppop(PP_DEFINE, "dgettext(d,m)=_TRANSLATE_(m)");
	ppop(PP_DEFINE, "dcgettext(d,m,c)=_TRANSLATE_(m)");
	ppop(PP_DEFINE, "ERROR_catalog(m)=_TRANSLATE_(m)");
	ppop(PP_DEFINE, "ERROR_dictionary(m)=_TRANSLATE_(m)");
	ppop(PP_DEFINE, "ERROR_translate(l,i,c,m)=_TRANSLATE_(m)");
	ppop(PP_DEFINE, "error(l,f,...)=_TRANSLATE_(f)");
	ppop(PP_DEFINE, "errormsg(t,l,f,...)=_TRANSLATE_(f)");
	ppop(PP_DIRECTIVE, "include \"msgcat.h\"");
	ppop(PP_OPTION, "noreadonly");
	ppop(PP_INIT);
	if (!(tmp = sfstropen()))
		error(ERROR_SYSTEM|3, "out of space");
	x = 0;
	for (;;)
	{
		c = pplex();
	again:
		switch (c)
		{
		case 0:
			break;
		case T_TRANSLATE:
			switch (c = pplex())
			{
			case '(':
				x = 1;
				break;
			case ')':
				if ((c = pplex()) != '(')
				{
					x = 0;
					goto again;
				}
				x = 1;
				break;
			default:
				x = 0;
				goto again;
			}
			continue;
		case '(':
			if (x > 0)
				x++;
			continue;
		case ')':
			if (x > 0)
				x--;
			continue;
		case T_STDIO:
			if ((c = pplex()) != '(' || (c = pplex()) != T_STDERR || (c = pplex()) != ',')
			{
				x = 0;
				goto again;
			}
			x = 1;
			continue;
		case T_STRING:
			if (x > 0 && !strmatch(pp.token, OMIT))
				sfprintf(sfstdout, "str \"%s\"\n", pp.token);
			continue;
		case T_ID:
			s = pp.symbol->name;
			if (x > 0)
			{
				if ((c = pplex()) == '+' && ppisinteger(c = pplex()))
					sfprintf(sfstdout, "var %s %s\n", pp.token, s);
				else
					sfprintf(sfstdout, "var %s\n", s);
			}
			else if (s[0] == 'b' && s[1] == '_' && s[2])
			{
				if ((c = pplex()) == '(' && (c = pplex()) == T_INT && (c = pplex()) == T_ID && (c = pplex()) == ',' && (c = pplex()) == T_CHAR && (c = pplex()) == '*')
					sfprintf(sfstdout, "cmd %s\n", s + 2);
				else
					goto again;
			}
			else
			{
				if ((c = pplex()) == '[')
				{
					if (ppisinteger(c = pplex()))
						c = pplex();
					if (c != ']')
						goto again;
					c = pplex();
				}
				if (c == '=' && (c = pplex()) == T_STRING && !strmatch(pp.token, OMIT))
				{
					sfprintf(sfstdout, "def %s \"%s\"\n", s, pp.token);
					sfprintf(tmp, "#define %s \"%s\"\n", s, pp.token);
					if (!(s = sfstruse(tmp)))
						error(ERROR_SYSTEM|3, "out of space");
					ppinput(s, "string", 0);
				}
				else
					goto again;
			}
			continue;
		default:
			continue;
		}
		break;
	}
	ppop(PP_DONE);
	return error_info.errors != 0;
}
