/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1986-2008 AT&T Intellectual Property          *
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
 * common preprocessor command line argument parse
 * called by optjoin()
 */

static const char usage[] =
"[-?\n@(#)$Id: cpp (AT&T Research) 2007-03-11 $\n]"
USAGE_LICENSE
"[+NAME?cpp - C language preprocessor]"
"[+DESCRIPTION?\bcpp\b is the preprocessor for all C language dialects. It is"
"	a standalone version of the \blibpp\b(3) preprocessor library. The"
"	C dialect implemented by \bcpp\b is determined by probing \bcc\b(1)"
"	using \bprobe\b(1). The path of the emulated compiler can be changed"
"	by the \b-D-X\b command line option.]"
"[+?If \aoutput\a is omitted then the standard output is written; if \ainput\a"
"	is also omitted then the standard input is read. NOTE: this is an"
"	ancient, non-standard, non-intuitiive file operand syntax that is"
"	required by \bcc\b(1); use shell file name expansion at your peril.]"
"[+?\bcpp\b specific options are set by the \b-D-\b and \b-I-\b options.]"

"[C:comments?Pass comments to the output. By default comments are omitted.]"
"[D:define?Define the macro \aname\a to have \avalue\a; \b1\b is assumed if"
"	\b=\b\avalue\a is omitted. If \aname\a begins with \b:\b then it is"
"	interpreted as a \blibpp\b(3) \b#pragma pp:\b statement; if \aname\a"
"	begins with \b%\b then it is interpreted as a \blibpp\b(3) \b#\b"
"	directive statement; if \aname\a begins with \b-\b or \b+\b then it is"
"	interpreted as a \blibpp\b(3) option; \b-\b turns the option on,"
"	\b+\b turns it off. Most options have a \b#pragma\b counterpart that"
"	is listed with the option definition. Right, this is ugly, but its the"
"	only portable way to pass options through \bcc\b(1) to"
"	\bcpp\b:]:[name[=value]]]{"
"	[+-D-C, pp::compatibility?Preprocess for K&R compatibility.]"
"	[+-D-D\alevel\a, \bpp::debug\b \alevel\a?Set the debug trace level."
"		Higher levels produce more output. Levels higher than 3"
"		enabled only in \b-g\b compiled versions.]"
"	[+-D-F\aname\a?Set the main input file name to \aname\a. This only"
"		affects error message and line sync output.]"
"	[+-D-H, pp::hosted?All directories are hosted; compatibility"
"		warning messages from hosted directory headers are suppressed.]"
"	[+-D-I, pp::cdir?All directories contain C headers; used only with"
"		\b-D-+\b.]"
"	[+-D-K, pp::keyargs?Enable the non-standard \aname=value\a macro"
"		argument mode.]"
"	[+-D-L\b[\aid\a]], \bpp::lineid\b [\aid\a]]?Set the line sync directive"
"		id to \aid\a or null if omitted.]"
"	[+-D-M, pp::nomultiple?Disable multiple include detection.]"
"	[+-D-P, pp::passthrough?Enable the non-standard passthrough mode; may"
"		be useful for processing non-C input.]"
"	[+-D-Q, pp::dump?Dump macro definitions to the output so that the"
"		output may be passed through \bcpp\b again. Used for"
"		generating precompiled headers.]"
"	[+-D-R, pp::transition?Enable the transition preprocessing mode. Used"
"		for compilers that can't make up their semantics between"
"		K&R and ISO.]"
"	[+-D-S, pp::strict?Enable strict preprocessing semantics and warnings."
"		Works with any mode (compatibiliy, transition,"
"		or the default ISO).]"
"	[+-D-T\atest\a, \bpp::test\b \atest\a?Enable implementation specific"
"		test code according to \atest\a.]"
"	[+-D-W, pp::warn?Enable warnings in non-hosted files.]"
"	[+-D-X\b[\acc\a]]?Preprocess for the compiler \acc\a which must be"
"		an executable path or an executable on \b$PATH\b.]"
"	[+-D-Y, pp::pedantic?Enable pedantic \bpp::warn\b warnings in"
"		non-hosted files.]"
"	[+-D-Z, pp::pool?Enable pool mode. See \blibpp\b(3).]"
"	[+-D-d?List canonicalized \b#define\b statements for non-predefined"
"		macros in the output. ]"
"	[+-D-m?List canonicalized \b#define\b statements for all macros. All"
"		other output is disabled.]"
"	[+-D-+, pp::plusplus?Preprocess for the C++ dialect.]"
"}"
"[I:include?Append \adirectory\a to the list of directories searched for"
"	\b#include\b files. If \adirectory\a is \b-\b then: (1) \b-I\b"
"	directories before \b-I-\b are searched only for \"...\" include"
"	files; (2) \b-I\b directories after \b-I-\b are searched for"
"	\"...\" and <...> include files; (3) the directory \b.\b is searched"
"	only if it is explicitly specified by a \b-I\b option.]:?[directory]{"
"	[+-I-C\adirectory\a, \bpp::cdir\b \adirectory\a?Mark \adirectory\a"
"		as a C header directory. Used with \bpp:plusplus\b.]"
"	[+-I-D[\afile\a]]?Read the default \bprobe\b(1) definitions from"
"		\afile\a, or ignore the default definitions if \afile\a"
"		is omitted.]"
"	[+-I-H\adirectory\a, \bpp::hostdir\b \adirectory\a?Mark \adirectory\a"
"		as a hosted directory. Headers from hosted directories have"
"		compatibility warnings disabled.]"
"	[+-I-I\aheader\a, \bpp::ignore\b \aheader\a?Add \aheader\a to the"
"		list of ignored headers.]"
"	[+-I-M\afile\a?\afile\a contains a sequence of \aheader\a"
"		[= \"\amap\a\" ]] lines, where \aheader\a is either <\aname\a>"
"		or \"\aname\a\", and \"\amap\a\" is an explicit binding"
"		for \aheader\a. \aheader\a is ignored if = \"\amap\a\" is"
"		omitted.]"
"	[+-I-R\afile\a?Include \afile\a but do not emit text or line syncs.]"
"	[+-I-S\adirectory\a?Add \adirectory\a to the default standard include"
"		directory list.]"
"	[+-I-T\afile\a?Include \afile\a and emit text to the output file.]"
"}"
"[M:dependencies?Generate \bmake\b(1) dependencies. Not needed with"
"	\bnmake\b(1). \b-M\b may be followed by optional \aflags\a to change"
"	dependency output styles:]{"
"	[+D?Generate dependencies in a separate \b.d\b file. Preprocessed"
"		output is still written to \aoutput\a, or the standard output"
"		if \aoutput\a is omitted.]"
"	[+G?Generate missing dependencies too.]"
"	[+M?Only generate local header dependencies; \ahosted\a headers are"
"		omitted. Note that \ahosted\a headers are determined by"
"		\b-I-H\b and the \bpp:hosted\b and \bpp:hostdir\b pragmas;"
"		no special distiction is made between \"\" and <> \binclude\b"
"		styles.]"
"}"
"[P!:sync?Emit line syncs.]"
"[U:undefine?Remove the definition for the macro \aname\a.]:[name]"

"[A:assert?Enter the assertion via \b#assert\b for system V"
"	compatibility.]:[assertion]"
"[E:preprocess?Ignored for compatibility with ancient compilers.]"
"[H:include-reference?Emit \b#include\b file paths on the standard error,"
"	one per line, indented to show nesting.]"
"[T?If not \bgcc\b(1) then truncate identifiers to \alength\a"
"	characters for compatibility with old AT&T (I guess only Lucent needs"
"	them now) compilers.]#?[length]"
"[V:version?Emit the \blibpp\b(3) version.]"
"[X:argmode?Enable \aname\a=\avalue\a macro arguments for \beasel\b(1)"
"	compatibility.]"
"[Y:standard?Add \adirectory\a to the list searched for"
"	\b#include\b \b<...>\b files.]:[directory]"

"\n"
"\n[ input [ output ] ]\n"
"\n"

"[+SEE ALSO?\bcc\b(1), \bgcc\b(1), \blibpp\b(3)]"
;

#include "pplib.h"

#include <ctype.h>

/*
 * convert lint comments to pragmas
 */

static void
pplint(char* head, char* comment, char* tail, int line)
{
	NoP(line);
	if (strmatch(comment, "(ARGSUSED|PRINTFLIKE|PROTOLIB|SCANFLIKE|VARARGS)*([0-9])|CONSTCOND|CONSTANTCOND|CONSTANTCONDITION|EMPTY|FALLTHRU|FALLTHROUGH|LINTLIBRARY|LINTED*|NOTREACHED"))
	{
		strncopy(pp.token, comment, MAXTOKEN);
		ppprintf("\n#%s %s:%s\n", dirname(PRAGMA), pp.pass, pp.token);
		ppline(error_info.line, NiL);
	}
}

/*
 * if last!=0 then argv[opt_info.index]==0 with return(0)
 * else if argv[opt_info.index]==0 then return(0)
 * otherwise argv[opt_info.index] is the first unrecognized
 * option with return(1)
 *
 * use last=0 if the preprocessor is combined with other passes
 * so that unknown options may be interpreted for those passes
 */

int
ppargs(char** argv, int last)
{
	register char*	s;
	register int	c;
	register int	n;
	char*		p;

	/*
	 * check the args and initialize
	 */

	if (!error_info.id)
		error_info.id = "cpp";
	for (;;)
	{
		for (; c = optget(argv, usage); last = 0) switch (c)
		{
		case 'C':
			ppop(PP_COMMENT, ppcomment);
			break;
		case 'D':
			/*
			 * this allows single arg pp option extensions
			 * without touching cc
			 * (not all cc wrappers have -W...)
			 */

			switch (*(s = opt_info.arg))
			{
			case '-':
			case '+':
				n = (*s++ == '-');
				while (c = *s++) switch (c)
				{
				case 'C':
					ppop(PP_COMPATIBILITY, n);
					break;
				case 'D':
					if (n && ((c = strtol(s, &p, 0)) || p != s))
					{
						s = p;
						n = c;
					}
					ppop(PP_DEBUG, -n);
					break;
				case 'F':
					ppop(PP_FILENAME, n ? s : NiL);
					goto hasarg;
				case 'H':
					ppop(PP_HOSTDIR, "-", n);
					break;
				case 'I':
					ppop(PP_CDIR, "-", n);
					break;
				case 'K':
					ppop(PP_KEYARGS, n);
					break;
				case 'L':
					ppop(PP_LINEID, n && *s ? s : "line");
					goto hasarg;
				case 'M':
					ppop(PP_MULTIPLE, !n);
					break;
				case 'P':
					ppop(PP_PASSTHROUGH, n);
					break;
				case 'Q':
					ppop(PP_DUMP, n);
					break;
				case 'R':
					ppop(PP_TRANSITION, n);
					break;
				case 'S':
					ppop(PP_STRICT, n);
					break;
				case 'T':
					ppop(PP_TEST, s);
					goto hasarg;
				case 'V':
					ppop(PP_VENDOR, "-", n);
					break;
				case 'W':
					ppop(PP_WARN, n);
					break;
				case 'X':
					ppop(PP_PROBE, n && *s ? s : 0);
					goto hasarg;
				case 'Y':
					ppop(PP_PEDANTIC, n);
					break;
				case 'Z':
					ppop(PP_POOL, n);
					break;
				case 'd':
					pp.option |= DEFINITIONS;
					break;
				case 'm':
					pp.state |= NOTEXT;
					pp.option |= KEEPNOTEXT|DEFINITIONS|PREDEFINITIONS;
					pp.linesync = 0;
					break;
				case '+':
					ppop(PP_PLUSPLUS, n);
					break;
				default:
					if (pp.optarg)
					{
						if ((c = (*pp.optarg)(n, c, s)) > 0) goto hasarg;
						else if (!c) break;
					}
					error(1, "%c%s: unknown -D option overload", n ? '-' : '+', s - 1);
					goto hasarg;
				}
			hasarg:
				break;
			case ':':
				ppop(PP_OPTION, s + 1);
				break;
			case '%':
				ppop(PP_DIRECTIVE, s + 1);
				break;
			case '_':
				if (strmatch(s, "__GNUC__*"))
					pp.arg_style |= STYLE_gnu;
				else if (strmatch(s, "__(ANSI|STDC|STRICT)__*") || !(pp.arg_style & STYLE_gnu) && strmatch(s, "__STRICT_ANSI__*"))
					ppop(PP_STRICT, 1);
				else if (strmatch(s, "__cplusplus*"))
					ppop(PP_PLUSPLUS, 1);
				/*FALLTHROUGH*/
			default:
				ppop(PP_DEFINE, s);
				break;
			}
			break;
		case 'E':
			/* historically ignored */
			break;
		case 'I':
			if (!(s = opt_info.arg))
			{
				/*
				 * some compilers interpret `-I ...' as
				 * `-I-S' and arg ... while others interpret
				 * it as `-I...'
				 */

				p = "-S";
				if ((s = argv[opt_info.index]) && ((n = *s++) == '-' || n == '+') && *s++ == 'D')
				{
					if (isalpha(*s) || *s == '_')
						while (isalnum(*++s) || *s == '_');
					if (*s && *s != '=' && *s != '-' && *s != '+')
						p = argv[opt_info.index++];
				}
				s = p;
			}
			switch (*s)
			{
			case '-':
			case '+':
				n = *(p = s++) == '-';
				c = *s++;
				if (!n && !*s) s = 0;
				switch (c)
				{
				case 0:
					ppop(PP_LOCAL);
					break;
				case 'C':
					ppop(PP_CDIR, s, n);
					break;
				case 'D':
					ppop(PP_DEFAULT, s);
					break;
				case 'H':
					ppop(PP_HOSTDIR, s, n);
					break;
				case 'I':
					ppop(PP_IGNORE, s);
					break;
				case 'M':
					ppop(PP_IGNORELIST, s);
					break;
				case 'R':
					ppop(PP_READ, s);
					break;
				case 'S':
					ppop(PP_STANDARD, s);
					break;
				case 'T':
					ppop(PP_TEXT, s);
					break;
				case 'V':
					ppop(PP_VENDOR, s, n);
					break;
				default:
					error(1, "%s: unknown -I option overload", p);
					break;
				}
				break;
			default:
				ppop(PP_INCLUDE, s);
				break;
			}
			break;
		case 'M':
			for (n = PP_deps; argv[opt_info.index]; opt_info.offset++)
			{
				switch (argv[opt_info.index][opt_info.offset])
				{
				case 'D':
					n |= PP_deps_file;
					continue;
				case 'G':
					n |= PP_deps_generated;
					continue;
				case 'M':
					n |= PP_deps_local;
					continue;
				}
				break;
			}
			ppop(PP_FILEDEPS, n);
			break;
		case 'P':
			ppop(PP_LINE, (PPLINESYNC)0);
			break;
		case 'U':
			ppop(PP_UNDEF, opt_info.arg);
			break;

		/*
		 * System V CCS compatibility
		 */

		case 'A':
			if (isalpha(opt_info.arg[0]) || opt_info.arg[0] == '_' || opt_info.arg[0] == '$')
				ppop(PP_ASSERT, opt_info.arg);
			break;
		case 'H':
			ppop(PP_INCREF, ppincref);
			break;
		case 'T':
			if (!(pp.arg_style & STYLE_gnu))
				ppop(PP_TRUNCATE, TRUNCLENGTH);
			/* else enable ANSI trigraphs -- default */
			break;
		case 'V':
			error(0, "%s", pp.version);
			break;
		case 'X':
			pp.arg_mode = (*(opt_info.arg + 1) || pp.arg_mode && pp.arg_mode != *opt_info.arg) ? '-' : *opt_info.arg;
			break;
		case 'Y':
			if (*(s = opt_info.arg) && *(s + 1) == ',')
			{
				if (*s != 'I') break;
				s += 2;
			}
			ppop(PP_STANDARD, s);
			break;

		/*
		 * errors
		 */

		case '?':
			error(ERROR_USAGE|4, "%s", opt_info.arg);
			break;
		case ':':
			if (!last)
			{
				opt_info.again = 1;
				return(1);
			}

			/*
			 * cross your fingers
			 */

			if (!(s = argv[opt_info.index]))
				error(3, "%s", opt_info.arg);
			if (opt_info.offset == 2 && (pp.arg_style & STYLE_gnu))
			{
				p = argv[opt_info.index + 1];
				if (streq(s, "-$"))
				{
					ppop(PP_OPTION, "noid \"$\"");
					goto ignore;
				}
				else if (streq(s, "-dD"))
				{
					pp.option |= DEFINITIONS;
					goto ignore;
				}
				else if (streq(s, "-dM"))
				{
					pp.state |= NOTEXT;
					pp.option |= KEEPNOTEXT|DEFINITIONS|PREDEFINITIONS;
					pp.linesync = 0;
					goto ignore;
				}
				else if (streq(s, "-imacros"))
				{
					if (p)
					{
						ppop(PP_READ, p);
						opt_info.index++;
						opt_info.offset = 0;
					}
					goto ignore;
				}
				else if (streq(s, "-include"))
				{
					if (p)
					{
						ppop(PP_TEXT, p);
						opt_info.index++;
						opt_info.offset = 0;
					}
					opt_info.offset = 0;
					goto ignore;
				}
				else if (strneq(s, "-lang-", 6))
				{
					s += 6;
					if (streq(s, "c"))
						c = 0;
					else if (streq(s, "c++"))
						c = 1;
					else if (streq(s, "objc"))
						c = 2;
					else if (streq(s, "objc++"))
						c = 3;
					ppop(PP_PLUSPLUS, c & 1);
					if (c & 2)
						ppop(PP_DIRECTIVE, "pragma pp:map \"/#(pragma )?import>/\" \"/#(pragma )?import(.*)/__STDPP__IMPORT__(\\2)/\"\n\
#macdef __STDPP__IMPORT__(x)\n\
#pragma pp:noallmultiple\n\
#include x\n\
#pragma pp:allmultiple\n\
#endmac");
					goto ignore;
				}
				else if (streq(s, "-lint"))
				{
					ppop(PP_COMMENT, pplint);
					goto ignore;
				}
			}
			s += opt_info.offset - 1;
			if (strmatch(s, "i*.h"))
				ppop((pp.arg_style & STYLE_gnu) || s[1] == '/' ? PP_READ : PP_TEXT, s + 1);
			else if (strmatch(s, "*@(nostandard|nostdinc)*"))
				ppop(PP_STANDARD, "");
			else if (strmatch(s, "*@(exten|xansi)*|std"))
			{
				ppop(PP_COMPATIBILITY, 0);
				ppop(PP_TRANSITION, 1);
			}
			else if (strmatch(s, "*@(ansi|conform|pedantic|stand|std1|strict[!-])*"))
			{
				ppop(PP_COMPATIBILITY, 0);
				ppop(PP_STRICT, 1);
				if (strmatch(s, "*pedantic*"))
					ppop(PP_PEDANTIC, 1);
			}
			else if (strmatch(s, "*@(trans)*"))
			{
				ppop(PP_COMPATIBILITY, 1);
				ppop(PP_TRANSITION, 1);
			}
			else if (strmatch(s, "*@(classic|compat|std0|tradition|[kK][n&+][rR])*"))
			{
				ppop(PP_COMPATIBILITY, 1);
				ppop(PP_TRANSITION, 0);
			}
			else if (strmatch(s, "*@(plusplus|++)*"))
				ppop(PP_PLUSPLUS, 1);
			else if (strmatch(s, "*@(warn)*"))
				ppop(PP_WARN, 1);

			/*
			 * ignore unknown options
			 * the probe info takes care of these
			 * fails if an option value is in the next arg
			 * and this is the last option
			 */

			if (argv[opt_info.index + 1] && argv[opt_info.index + 1][0] != '-' && argv[opt_info.index + 2] && argv[opt_info.index + 2][0] == '-')
			{
				opt_info.index++;
				opt_info.offset = 0;
			}
		ignore:
			while (argv[opt_info.index][opt_info.offset]) opt_info.offset++;
			break;
		}
		if (!(s = argv[opt_info.index])) return(0);
		switch (pp.arg_file)
		{
		case 0:
			if (*s != '-' || *(s + 1)) ppop(PP_INPUT, s);
			break;
		case 1:
			if (*s != '-' || *(s + 1)) ppop(PP_OUTPUT, s);
			break;
		default:
			if (!last) return(1);
			error(1, "%s: extraneous argument ignored", s);
			break;
		}
		pp.arg_file++;
		if (!argv[++opt_info.index]) return(0);

		/*
		 * old versions allow options after file args
		 */
	}
}
