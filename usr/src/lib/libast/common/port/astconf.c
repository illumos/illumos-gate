/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped

/*
 * string interface to confstr(),pathconf(),sysconf(),sysinfo()
 * extended to allow some features to be set per-process
 */

static const char id[] = "\n@(#)$Id: getconf (AT&T Research) 2009-07-02 $\0\n";

#include "univlib.h"

#include <ast.h>
#include <error.h>
#include <fs3d.h>
#include <ctype.h>
#include <regex.h>
#include <proc.h>

#include "conftab.h"
#include "FEATURE/libpath"

#ifndef DEBUG_astconf
#define DEBUG_astconf		0
#endif

#ifndef _pth_getconf
#undef	ASTCONF_system
#define ASTCONF_system		0
#endif

#if _sys_systeminfo
# if !_lib_sysinfo
#   if _lib_systeminfo
#     define _lib_sysinfo	1
#     define sysinfo(a,b,c)	systeminfo(a,b,c)
#   else
#     if _lib_syscall && _sys_syscall
#       include <sys/syscall.h>
#       if defined(SYS_systeminfo)
#         define _lib_sysinfo	1
#         define sysinfo(a,b,c)	syscall(SYS_systeminfo,a,b,c)
#       endif
#     endif
#   endif
# endif
#else
# undef	_lib_sysinfo
#endif

#define CONF_ERROR	(CONF_USER<<0)
#define CONF_READONLY	(CONF_USER<<1)
#define CONF_ALLOC	(CONF_USER<<2)
#define CONF_GLOBAL	(CONF_USER<<3)

#define DEFAULT(o)	((state.std||!dynamic[o].ast)?dynamic[o].std:dynamic[o].ast)
#define INITIALIZE()	do{if(!state.data)synthesize(NiL,NiL,NiL);}while(0)
#define STANDARD(v)	(streq(v,"standard")||streq(v,"strict")||streq(v,"posix")||streq(v,"xopen"))

#define MAXVAL		256

#if MAXVAL <= UNIV_SIZE
#undef	MAXVAL
#define	MAXVAL		(UNIV_SIZE+1)
#endif

#ifndef _UNIV_DEFAULT
#define _UNIV_DEFAULT	"att"
#endif

static char	null[1];
static char	root[2] = "/";

typedef struct Feature_s
{
	struct Feature_s*next;
	const char*	name;
	char*		value;
	char*		std;
	char*		ast;
	short		length;
	short		standard;
	unsigned int	flags;
	short		op;
} Feature_t;

typedef struct
{
	Conf_t*		conf;
	const char*	name;
	unsigned int	flags;
	short		call;
	short		standard;
	short		section;
} Lookup_t;

static Feature_t	dynamic[] =
{
#define OP_conformance	0
	{
		&dynamic[OP_conformance+1],
		"CONFORMANCE",
		"ast",
		"standard",
		"ast",
		11,
		CONF_AST,
		0,
		OP_conformance
	},
#define OP_fs_3d	1
	{
		&dynamic[OP_fs_3d+1],
		"FS_3D",
		&null[0],
		"0",
		0,
		5,
		CONF_AST,
		0,
		OP_fs_3d
	},
#define OP_getconf	2
	{
		&dynamic[OP_getconf+1],
		"GETCONF",
#ifdef _pth_getconf
		_pth_getconf,
#else
		&null[0],
#endif
		0,
		0,
		7,
		CONF_AST,
		CONF_READONLY,
		OP_getconf
	},
#define OP_hosttype	3
	{
		&dynamic[OP_hosttype+1],
		"HOSTTYPE",
		HOSTTYPE,
		0,
		0,
		8,
		CONF_AST,
		CONF_READONLY,
		OP_hosttype
	},
#define OP_libpath	4
	{
		&dynamic[OP_libpath+1],
		"LIBPATH",
#ifdef CONF_LIBPATH
		CONF_LIBPATH,
#else
		&null[0],
#endif
		0,
		0,
		7,
		CONF_AST,
		0,
		OP_libpath
	},
#define OP_libprefix	5
	{
		&dynamic[OP_libprefix+1],
		"LIBPREFIX",
#ifdef CONF_LIBPREFIX
		CONF_LIBPREFIX,
#else
		"lib",
#endif
		0,
		0,
		9,
		CONF_AST,
		0,
		OP_libprefix
	},
#define OP_libsuffix	6
	{
		&dynamic[OP_libsuffix+1],
		"LIBSUFFIX",
#ifdef CONF_LIBSUFFIX
		CONF_LIBSUFFIX,
#else
		".so",
#endif
		0,
		0,
		9,
		CONF_AST,
		0,
		OP_libsuffix
	},
#define OP_path_attributes	7
	{
		&dynamic[OP_path_attributes+1],
		"PATH_ATTRIBUTES",
#if _WINIX
		"c",
#else
		&null[0],
#endif
		&null[0],
		0,
		15,
		CONF_AST,
		CONF_READONLY,
		OP_path_attributes
	},
#define OP_path_resolve	8
	{
		&dynamic[OP_path_resolve+1],
		"PATH_RESOLVE",
		&null[0],
		"physical",
		"metaphysical",
		12,
		CONF_AST,
		0,
		OP_path_resolve
	},
#define OP_universe	9
	{
		0,
		"UNIVERSE",
		&null[0],
		"att",
		0,
		8,
		CONF_AST,
		0,
		OP_universe
	},
	{
		0
	}
};

typedef struct
{

	const char*	id;
	const char*	name;
	Feature_t*	features;

	int		std;

	/* default initialization from here down */

	int		prefix;
	int		synthesizing;

	char*		data;
	char*		last;

	Feature_t*	recent;

	Ast_confdisc_f	notify;

} State_t;

static State_t	state = { "getconf", "_AST_FEATURES", dynamic, -1 };

static char*	feature(const char*, const char*, const char*, unsigned int, Error_f);

/*
 * return fmtbuf() copy of s
 */

static char*
buffer(char* s)
{
	return strcpy(fmtbuf(strlen(s) + 1), s);
}

/*
 * synthesize state for fp
 * fp==0 initializes from getenv(state.name)
 * value==0 just does lookup
 * otherwise state is set to value
 */

static char*
synthesize(register Feature_t* fp, const char* path, const char* value)
{
	register char*		s;
	register char*		d;
	register char*		v;
	register char*		p;
	register int		n;

#if DEBUG_astconf
	if (fp)
		error(-2, "astconf synthesize name=%s path=%s value=%s fp=%p%s", fp->name, path, value, fp, state.synthesizing ? " SYNTHESIZING" : "");
#endif
	if (state.synthesizing)
		return null;
	if (!state.data)
	{
		char*		se;
		char*		de;
		char*		ve;

		state.prefix = strlen(state.name) + 1;
		n = state.prefix + 3 * MAXVAL;
		if (s = getenv(state.name))
			n += strlen(s) + 1;
		n = roundof(n, 32);
		if (!(state.data = newof(0, char, n, 0)))
			return 0;
		state.last = state.data + n - 1;
		strcpy(state.data, state.name);
		state.data += state.prefix - 1;
		*state.data++ = '=';
		if (s)
			strcpy(state.data, s);
		ve = state.data;
		state.synthesizing = 1;
		for (;;)
		{
			for (s = ve; isspace(*s); s++);
			for (d = s; *d && !isspace(*d); d++);
			for (se = d; isspace(*d); d++);
			for (v = d; *v && !isspace(*v); v++);
			for (de = v; isspace(*v); v++);
			if (!*v)
				break;
			for (ve = v; *ve && !isspace(*ve); ve++);
			if (*ve)
				*ve = 0;
			else
				ve = 0;
			*de = 0;
			*se = 0;
			feature(s, d, v, 0, 0);
			*se = ' ';
			*de = ' ';
			if (!ve)
				break;
			*ve++ = ' ';
		}
		state.synthesizing = 0;
	}
	if (!fp)
		return state.data;
	if (!state.last)
	{
		if (!value)
			return 0;
		n = strlen(value);
		goto ok;
	}
	s = (char*)fp->name;
	n = fp->length;
	d = state.data;
	for (;;)
	{
		while (isspace(*d))
			d++;
		if (!*d)
			break;
		if (strneq(d, s, n) && isspace(d[n]))
		{
			if (!value)
			{
				for (d += n + 1; *d && !isspace(*d); d++);
				for (; isspace(*d); d++);
				for (s = d; *s && !isspace(*s); s++);
				n = s - d;
				value = (const char*)d;
				goto ok;
			}
			for (s = p = d + n + 1; *s && !isspace(*s); s++);
			for (; isspace(*s); s++);
			for (v = s; *s && !isspace(*s); s++);
			n = s - v;
			if ((!path || *path == *p && strlen(path) == (v - p - 1) && !memcmp(path, p, v - p - 1)) && strneq(v, value, n))
				goto ok;
			for (; isspace(*s); s++);
			if (*s)
				for (; *d = *s++; d++);
			else if (d != state.data)
				d--;
			break;
		}
		for (; *d && !isspace(*d); d++);
		for (; isspace(*d); d++);
		for (; *d && !isspace(*d); d++);
		for (; isspace(*d); d++);
		for (; *d && !isspace(*d); d++);
	}
	if (!value)
	{
		if (!fp->op)
		{
			if (fp->flags & CONF_ALLOC)
				fp->value[0] = 0;
			else
				fp->value = null;
		}
		return 0;
	}
	if (!value[0])
		value = "0";
	if (!path || !path[0] || path[0] == '/' && !path[1])
		path = "-";
	n += strlen(path) + strlen(value) + 3;
	if (d + n >= state.last)
	{
		int	c;
		int	i;

		i = d - state.data;
		state.data -= state.prefix;
		c = n + state.last - state.data + 3 * MAXVAL;
		c = roundof(c, 32);
		if (!(state.data = newof(state.data, char, c, 0)))
			return 0;
		state.last = state.data + c - 1;
		state.data += state.prefix;
		d = state.data + i;
	}
	if (d != state.data)
		*d++ = ' ';
	for (s = (char*)fp->name; *d = *s++; d++);
	*d++ = ' ';
	for (s = (char*)path; *d = *s++; d++);
	*d++ = ' ';
	for (s = (char*)value; *d = *s++; d++);
#if DEBUG_astconf
	error(-3, "astconf synthesize %s", state.data - state.prefix);
#endif
	setenviron(state.data - state.prefix);
	if (state.notify)
		(*state.notify)(NiL, NiL, state.data - state.prefix);
	n = s - (char*)value - 1;
 ok:
	if (!(fp->flags & CONF_ALLOC))
		fp->value = 0;
	if (n == 1 && (*value == '0' || *value == '-'))
		n = 0;
	if (!(fp->value = newof(fp->value, char, n, 1)))
		fp->value = null;
	else
	{
		fp->flags |= CONF_ALLOC;
		memcpy(fp->value, value, n);
		fp->value[n] = 0;
	}
	return fp->value;
}

/*
 * initialize the value for fp
 * if command!=0 then it is checked for on $PATH
 * synthesize(fp,path,succeed) called on success
 * otherwise synthesize(fp,path,fail) called
 */

static void
initialize(register Feature_t* fp, const char* path, const char* command, const char* succeed, const char* fail)
{
	register char*	p;
	register int	ok = 1;

#if DEBUG_astconf
	error(-2, "astconf initialize name=%s path=%s command=%s succeed=%s fail=%s fp=%p%s", fp->name, path, command, succeed, fail, fp, state.synthesizing ? " SYNTHESIZING" : "");
#endif
	switch (fp->op)
	{
	case OP_conformance:
		ok = getenv("POSIXLY_CORRECT") != 0;
		break;
	case OP_hosttype:
		ok = 1;
		break;
	case OP_path_attributes:
		ok = 1;
		break;
	case OP_path_resolve:
		ok = fs3d(FS3D_TEST);
		break;
	case OP_universe:
		ok = streq(_UNIV_DEFAULT, DEFAULT(OP_universe));
		/*FALLTHROUGH...*/
	default:
		if (p = getenv("PATH"))
		{
			register int	r = 1;
			register char*	d = p;
			Sfio_t*		tmp;

#if DEBUG_astconf
			error(-2, "astconf initialize name=%s ok=%d PATH=%s", fp->name, ok, p);
#endif
			if (tmp = sfstropen())
			{
				for (;;)
				{
					switch (*p++)
					{
					case 0:
						break;
					case ':':
						if (command && (fp->op != OP_universe || !ok))
						{
							if (r = p - d - 1)
							{
								sfwrite(tmp, d, r);
								sfputc(tmp, '/');
								sfputr(tmp, command, 0);
								if ((d = sfstruse(tmp)) && !eaccess(d, X_OK))
								{
									ok = 1;
									if (fp->op != OP_universe)
										break;
								}
							}
							d = p;
						}
						r = 1;
						continue;
					case '/':
						if (r)
						{
							r = 0;
							if (fp->op == OP_universe)
							{
								if (p[0] == 'u' && p[1] == 's' && p[2] == 'r' && p[3] == '/')
									for (p += 4; *p == '/'; p++);
								if (p[0] == 'b' && p[1] == 'i' && p[2] == 'n')
								{
									for (p += 3; *p == '/'; p++);
									if (!*p || *p == ':')
										break;
								}
							}
						}
						if (fp->op == OP_universe)
						{
							if (strneq(p, "xpg", 3) || strneq(p, "5bin", 4))
							{
								ok = 1;
								break;
							}
							if (strneq(p, "bsd", 3) || strneq(p, "ucb", 3))
							{
								ok = 0;
								break;
							}
						}
						continue;
					default:
						r = 0;
						continue;
					}
					break;
				}
				sfclose(tmp);
			}
			else
				ok = 1;
		}
		break;
	}
#if DEBUG_astconf
	error(-1, "AHA#%d state.std=%d %s [%s] std=%s ast=%s value=%s ok=%d", __LINE__,  state.std, fp->name, ok ? succeed : fail, fp->std, fp->ast, fp->value, ok);
#endif
	synthesize(fp, path, ok ? succeed : fail);
}

/*
 * format synthesized value
 */

static char*
format(register Feature_t* fp, const char* path, const char* value, unsigned int flags, Error_f conferror)
{
	register Feature_t*	sp;
	register int		n;

#if DEBUG_astconf
	error(-2, "astconf format name=%s path=%s value=%s flags=%04x fp=%p%s", fp->name, path, value, flags, fp, state.synthesizing ? " SYNTHESIZING" : "");
#endif
	if (value)
		fp->flags &= ~CONF_GLOBAL;
	else if (fp->flags & CONF_GLOBAL)
		return fp->value;
	switch (fp->op)
	{

	case OP_conformance:
		if (value && STANDARD(value))
			value = fp->std;
		n = state.std = streq(fp->value, fp->std);
#if DEBUG_astconf
		error(-1, "AHA#%d state.std=%d %s [%s] std=%s ast=%s value=%s", __LINE__,  state.std, fp->name, value, fp->std, fp->ast, fp->value);
#endif
		if (!synthesize(fp, path, value))
			initialize(fp, path, NiL, fp->std, fp->value);
#if DEBUG_astconf
		error(-1, "AHA#%d state.std=%d %s [%s] std=%s ast=%s value=%s", __LINE__,  state.std, fp->name, value, fp->std, fp->ast, fp->value);
#endif
		if (!n && STANDARD(fp->value))
		{
			state.std = 1;
			for (sp = state.features; sp; sp = sp->next)
				if (sp->std && sp->op && sp->op != OP_conformance)
					astconf(sp->name, path, sp->std);
		}
#if DEBUG_astconf
		error(-1, "AHA#%d state.std=%d %s [%s] std=%s ast=%s value=%s", __LINE__,  state.std, fp->name, value, fp->std, fp->ast, fp->value);
#endif
		break;

	case OP_fs_3d:
		fp->value = fs3d(value ? value[0] ? FS3D_ON : FS3D_OFF : FS3D_TEST) ? "1" : null;
		break;

	case OP_hosttype:
		break;

	case OP_path_attributes:
#ifdef _PC_PATH_ATTRIBUTES
		{
			register char*	s;
			register char*	e;
			intmax_t	v;

			/*
			 * _PC_PATH_ATTRIBUTES is a bitmap for 'a' to 'z'
			 */

			if ((v = pathconf(path, _PC_PATH_ATTRIBUTES)) == -1L)
				return 0;
			s = fp->value;
			e = s + sizeof(fp->value) - 1;
			for (n = 'a'; n <= 'z'; n++)
				if (v & (1 << (n - 'a')))
				{
					*s++ = n;
					if (s >= e)
						break;
				}
			*s = 0;
		}
#endif
		break;

	case OP_path_resolve:
		if (!synthesize(fp, path, value))
			initialize(fp, path, NiL, "logical", DEFAULT(OP_path_resolve));
		break;

	case OP_universe:
#if _lib_universe
		if (getuniverse(fp->value) < 0)
			strcpy(fp->value, DEFAULT(OP_universe));
		if (value)
			setuniverse(value);
#else
#ifdef UNIV_MAX
		n = 0;
		if (value)
		{
			while (n < univ_max && !streq(value, univ_name[n])
				n++;
			if (n >= univ_max)
			{
				if (conferror)
					(*conferror)(&state, &state, 2, "%s: %s: universe value too large", fp->name, value);
				return 0;
			}
		}
#ifdef ATT_UNIV
		n = setuniverse(n + 1);
		if (!value && n > 0)
			setuniverse(n);
#else
		n = universe(value ? n + 1 : U_GET);
#endif
		if (n <= 0 || n >= univ_max)
			n = 1;
		strcpy(fp->value, univ_name[n - 1]);
#else
		if (value && streq(path, "="))
		{
			if (state.synthesizing)
			{
				if (!(fp->flags & CONF_ALLOC))
					fp->value = 0;
				n = strlen(value);
				if (!(fp->value = newof(fp->value, char, n, 1)))
					fp->value = null;
				else
				{
					fp->flags |= CONF_ALLOC;
					memcpy(fp->value, value, n);
					fp->value[n] = 0;
				}
			}
			else
				synthesize(fp, path, value);
		}
		else
			initialize(fp, path, "echo", DEFAULT(OP_universe), "ucb");
#endif
#endif
		break;

	default:
		synthesize(fp, path, value);
		break;

	}
	if (streq(path, "="))
		fp->flags |= CONF_GLOBAL;
	return fp->value;
}

/*
 * value==0 get feature name
 * value!=0 set feature name
 * 0 returned if error or not defined; otherwise previous value
 */

static char*
feature(const char* name, const char* path, const char* value, unsigned int flags, Error_f conferror)
{
	register Feature_t*	fp;
	register int		n;

	if (value && (streq(value, "-") || streq(value, "0")))
		value = null;
	for (fp = state.features; fp && !streq(fp->name, name); fp = fp->next);
#if DEBUG_astconf
	error(-2, "astconf feature name=%s path=%s value=%s flags=%04x fp=%p%s", name, path, value, flags, fp, state.synthesizing ? " SYNTHESIZING" : "");
#endif
	if (!fp)
	{
		if (!value)
			return 0;
		if (state.notify && !(*state.notify)(name, path, value))
			return 0;
		n = strlen(name);
		if (!(fp = newof(0, Feature_t, 1, n + 1)))
		{
			if (conferror)
				(*conferror)(&state, &state, 2, "%s: out of space", name);
			return 0;
		}
		fp->op = -1;
		fp->name = (const char*)fp + sizeof(Feature_t);
		strcpy((char*)fp->name, name);
		fp->length = n;
		fp->std = &null[0];
		fp->next = state.features;
		state.features = fp;
	}
	else if (value)
	{
		if (fp->flags & CONF_READONLY)
		{
			if (conferror)
				(*conferror)(&state, &state, 2, "%s: cannot set readonly symbol", fp->name);
			return 0;
		}
		if (state.notify && !streq(fp->value, value) && !(*state.notify)(name, path, value))
			return 0;
	}
	else
		state.recent = fp;
	return format(fp, path, value, flags, conferror);
}

/*
 * binary search for name in conf[]
 */

static int
lookup(register Lookup_t* look, const char* name, unsigned int flags)
{
	register Conf_t*	mid = (Conf_t*)conf;
	register Conf_t*	lo = mid;
	register Conf_t*	hi = mid + conf_elements;
	register int		v;
	register int		c;
	char*			e;
	const Prefix_t*		p;

	static Conf_t		num;

	look->flags = 0;
	look->call = -1;
	look->standard = (flags & ASTCONF_AST) ? CONF_AST : -1;
	look->section = -1;
	while (*name == '_')
		name++;
 again:
	for (p = prefix; p < &prefix[prefix_elements]; p++)
		if (strneq(name, p->name, p->length) && ((c = name[p->length] == '_' || name[p->length] == '(' || name[p->length] == '#') || (v = isdigit(name[p->length]) && name[p->length + 1] == '_')))
		{
			if (p->call < 0)
			{
				if (look->standard >= 0)
					break;
				look->standard = p->standard;
			}
			else
			{
				if (look->call >= 0)
					break;
				look->call = p->call;
			}
			if (name[p->length] == '(' || name[p->length] == '#')
			{
				look->conf = &num;
				strncpy((char*)num.name, name, sizeof(num.name));
				num.call = p->call;
				num.flags = *name == 'C' ? CONF_STRING : 0;
				num.op = (short)strtol(name + p->length + 1, &e, 10);
				if (name[p->length] == '(' && *e == ')')
					e++;
				if (*e)
					break;
				return 1;
			}
			name += p->length + c;
			if (look->section < 0 && !c && v)
			{
				look->section = name[0] - '0';
				name += 2;
			}
			goto again;
		}
#if HUH_2006_02_10
	if (look->section < 0)
		look->section = 1;
#endif
	look->name = name;
#if DEBUG_astconf
	error(-2, "astconf normal name=%s standard=%d section=%d call=%d flags=%04x elements=%d", look->name, look->standard, look->section, look->call, flags, conf_elements);
#endif
	c = *((unsigned char*)name);
	while (lo <= hi)
	{
		mid = lo + (hi - lo) / 2;
#if DEBUG_astconf
		error(-3, "astconf lookup name=%s mid=%s", name, mid->name);
#endif
		if (!(v = c - *((unsigned char*)mid->name)) && !(v = strcmp(name, mid->name)))
		{
			hi = mid;
			lo = (Conf_t*)conf;
			do
			{
				if ((look->standard < 0 || look->standard == mid->standard) &&
				    (look->section < 0 || look->section == mid->section) &&
				    (look->call < 0 || look->call == mid->call))
					goto found;
			} while (mid-- > lo && streq(mid->name, look->name));
			mid = hi;
			hi = lo + conf_elements - 1;
			while (++mid < hi && streq(mid->name, look->name))
			{
				if ((look->standard < 0 || look->standard == mid->standard) &&
				    (look->section < 0 || look->section == mid->section) &&
				    (look->call < 0 || look->call == mid->call))
					goto found;
			}
			break;
		}
		else if (v > 0)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return 0;
 found:
	if (look->call < 0 && look->standard >= 0 && (look->section <= 1 || (mid->flags & CONF_MINMAX)))
		look->flags |= CONF_MINMAX;
	look->conf = mid;
#if DEBUG_astconf
	error(-2, "astconf lookup name=%s standard=%d:%d section=%d:%d call=%d:%d", look->name, look->standard, mid->standard, look->section, mid->section, look->call, mid->call);
#endif
	return 1;
}

/*
 * return a tolower'd copy of s
 */

static char*
fmtlower(register const char* s)
{
	register int	c;
	register char*	t;
	char*		b;

	b = t = fmtbuf(strlen(s) + 1);
	while (c = *s++)
	{
		if (isupper(c))
			c = tolower(c);
		*t++ = c;
	}
	*t = 0;
	return b;
}

/*
 * print value line for p
 * if !name then value prefixed by "p->name="
 * if (flags & CONF_MINMAX) then default minmax value used
 */

static char*
print(Sfio_t* sp, register Lookup_t* look, const char* name, const char* path, int listflags, Error_f conferror)
{
	register Conf_t*	p = look->conf;
	register unsigned int	flags = look->flags;
	char*			call;
	char*			f;
	const char*		s;
	int			i;
	int			n;
	int			olderrno;
	int			drop;
	int			defined;
	intmax_t		v;
	char			buf[PATH_MAX];
	char			flg[16];

	if (!name && !(p->flags & CONF_STRING) && (p->flags & (CONF_FEATURE|CONF_LIMIT|CONF_MINMAX)) && (p->flags & (CONF_LIMIT|CONF_PREFIXED)) != CONF_LIMIT)
		flags |= CONF_PREFIXED;
	olderrno = errno;
	errno = 0;
#if DEBUG_astconf
	error(-1, "astconf name=%s:%s:%s standard=%d section=%d call=%s op=%d flags=|%s%s%s%s%s:|%s%s%s%s%s%s%s%s%s%s"
		, name, look->name, p->name, p->standard, p->section, prefix[p->call + CONF_call].name, p->op
		, (flags & CONF_FEATURE) ? "FEATURE|" : ""
		, (flags & CONF_LIMIT) ? "LIMIT|" : ""
		, (flags & CONF_MINMAX) ? "MINMAX|" : ""
		, (flags & CONF_PREFIXED) ? "PREFIXED|" : ""
		, (flags & CONF_STRING) ? "STRING|" : ""
		, (p->flags & CONF_DEFER_CALL) ? "DEFER_CALL|" : ""
		, (p->flags & CONF_DEFER_MM) ? "DEFER_MM|" : ""
		, (p->flags & CONF_FEATURE) ? "FEATURE|" : ""
		, (p->flags & CONF_LIMIT_DEF) ? "LIMIT_DEF|" : (p->flags & CONF_LIMIT) ? "LIMIT|" : ""
		, (p->flags & CONF_MINMAX_DEF) ? "MINMAX_DEF|" : (p->flags & CONF_MINMAX) ? "MINMAX|" : ""
		, (p->flags & CONF_NOUNDERSCORE) ? "NOUNDERSCORE|" : ""
		, (p->flags & CONF_PREFIXED) ? "PREFIXED|" : ""
		, (p->flags & CONF_PREFIX_ONLY) ? "PREFIX_ONLY|" : ""
		, (p->flags & CONF_STANDARD) ? "STANDARD|" : ""
		, (p->flags & CONF_STRING) ? "STRING|" : ""
		, (p->flags & CONF_UNDERSCORE) ? "UNDERSCORE|" : ""
		);
#endif
	flags |= CONF_LIMIT_DEF|CONF_MINMAX_DEF;
	if (conferror && name)
	{
		if ((p->flags & CONF_PREFIX_ONLY) && look->standard < 0)
			goto bad;
		if (!(flags & CONF_MINMAX) || !(p->flags & CONF_MINMAX))
		{
			switch (p->call)
			{
			case CONF_pathconf:
				if (path == root)
				{
					(*conferror)(&state, &state, 2, "%s: path expected", name);
					goto bad;
				}
				break;
			default:
				if (path != root)
				{
					(*conferror)(&state, &state, 2, "%s: path not expected", name);
					goto bad;
				}
				break;
			}
#ifdef _pth_getconf
			if (p->flags & CONF_DEFER_CALL)
				goto bad;
#endif
		}
		else
		{
			if (path != root)
			{
				(*conferror)(&state, &state, 2, "%s: path not expected", name);
				goto bad;
			}
#ifdef _pth_getconf
			if ((p->flags & CONF_DEFER_MM) || !(p->flags & CONF_MINMAX_DEF))
				goto bad;
#endif
		}
		if (look->standard >= 0 && (name[0] != '_' && ((p->flags & CONF_UNDERSCORE) || look->section <= 1) || name[0] == '_' && (p->flags & CONF_NOUNDERSCORE)) || look->standard < 0 && name[0] == '_')
			goto bad;
	}
	s = 0;
	defined = 1;
	switch (i = (p->op < 0 || (flags & CONF_MINMAX) && (p->flags & CONF_MINMAX_DEF)) ? 0 : p->call)
	{
	case CONF_confstr:
		call = "confstr";
#if _lib_confstr
		if (!(v = confstr(p->op, buf, sizeof(buf))))
		{
			defined = 0;
			v = -1;
			errno = EINVAL;
		}
		else if (v > 0)
		{
			buf[sizeof(buf) - 1] = 0;
			s = (const char*)buf;
		}
		else
			defined = 0;
		break;
#else
		goto predef;
#endif
	case CONF_pathconf:
		call = "pathconf";
#if _lib_pathconf
		if ((v = pathconf(path, p->op)) < 0)
			defined = 0;
		break;
#else
		goto predef;
#endif
	case CONF_sysconf:
		call = "sysconf";
#if _lib_sysconf
		if ((v = sysconf(p->op)) < 0)
			defined = 0;
		break;
#else
		goto predef;
#endif
	case CONF_sysinfo:
		call = "sysinfo";
#if _lib_sysinfo
		if ((v = sysinfo(p->op, buf, sizeof(buf))) >= 0)
		{
			buf[sizeof(buf) - 1] = 0;
			s = (const char*)buf;
		}
		else
			defined = 0;
		break;
#else
		goto predef;
#endif
	default:
		call = "synthesis";
		errno = EINVAL;
		v = -1;
		defined = 0;
		break;
	case 0:
		call = 0;
		if (p->standard == CONF_AST)
		{
			if (streq(p->name, "RELEASE") && (i = open("/proc/version", O_RDONLY)) >= 0)
			{
				n = read(i, buf, sizeof(buf) - 1);
				close(i);
				if (n > 0 && buf[n - 1] == '\n')
					n--;
				if (n > 0 && buf[n - 1] == '\r')
					n--;
				buf[n] = 0;
				if (buf[0])
				{
					v = 0;
					s = buf;
					break;
				}
			}
		}
		if (p->flags & CONF_MINMAX_DEF)
		{
			if (!((p->flags & CONF_LIMIT_DEF)))
				flags |= CONF_MINMAX;
			listflags &= ~ASTCONF_system;
		}
	predef:
		if (look->standard == CONF_AST)
		{
			if (streq(p->name, "VERSION"))
			{
				v = ast.version;
				break;
			}
		}
		if (flags & CONF_MINMAX)
		{
			if ((p->flags & CONF_MINMAX_DEF) && (!(listflags & ASTCONF_system) || !(p->flags & CONF_DEFER_MM)))
			{
				v = p->minmax.number;
				s = p->minmax.string;
				break;
			}
		}
		else if ((p->flags & CONF_LIMIT_DEF) && (!(listflags & ASTCONF_system) || !(p->flags & CONF_DEFER_CALL)))
		{
			v = p->limit.number;
			s = p->limit.string;
			break;
		}
		flags &= ~(CONF_LIMIT_DEF|CONF_MINMAX_DEF);
		v = -1;
		errno = EINVAL;
		defined = 0;
		break;
	}
	if (!defined)
	{
		if (!errno)
		{
			if ((p->flags & CONF_FEATURE) || !(p->flags & (CONF_LIMIT|CONF_MINMAX)))
				flags &= ~(CONF_LIMIT_DEF|CONF_MINMAX_DEF);
		}
		else if (flags & CONF_PREFIXED)
			flags &= ~(CONF_LIMIT_DEF|CONF_MINMAX_DEF);
		else if (errno != EINVAL || !i)
		{
			if (!sp)
			{
				if (conferror)
				{
					if (call)
						(*conferror)(&state, &state, ERROR_SYSTEM|2, "%s: %s error", p->name, call);
					else if (!(listflags & ASTCONF_system))
						(*conferror)(&state, &state, 2, "%s: unknown name", p->name);
				}
				goto bad;
			}
			else
			{
				flags &= ~(CONF_LIMIT_DEF|CONF_MINMAX_DEF);
				flags |= CONF_ERROR;
			}
		}
	}
	errno = olderrno;
	if ((listflags & ASTCONF_defined) && !(flags & (CONF_LIMIT_DEF|CONF_MINMAX_DEF)))
		goto bad;
	if ((drop = !sp) && !(sp = sfstropen()))
		goto bad;
	if (listflags & ASTCONF_table)
	{
		f = flg;
		if (p->flags & CONF_DEFER_CALL)
			*f++ = 'C';
		if (p->flags & CONF_DEFER_MM)
			*f++ = 'D';
		if (p->flags & CONF_FEATURE)
			*f++ = 'F';
		if (p->flags & CONF_LIMIT)
			*f++ = 'L';
		if (p->flags & CONF_MINMAX)
			*f++ = 'M';
		if (p->flags & CONF_NOSECTION)
			*f++ = 'N';
		if (p->flags & CONF_PREFIXED)
			*f++ = 'P';
		if (p->flags & CONF_STANDARD)
			*f++ = 'S';
		if (p->flags & CONF_UNDERSCORE)
			*f++ = 'U';
		if (p->flags & CONF_NOUNDERSCORE)
			*f++ = 'V';
		if (p->flags & CONF_PREFIX_ONLY)
			*f++ = 'W';
		if (f == flg)
			*f++ = 'X';
		*f = 0;
		sfprintf(sp, "%*s %*s %d %2s %4d %6s ", sizeof(p->name), p->name, sizeof(prefix[p->standard].name), prefix[p->standard].name, p->section, prefix[p->call + CONF_call].name, p->op, flg);
		if (p->flags & CONF_LIMIT_DEF)
		{
			if (p->limit.string)
				sfprintf(sp, "L[%s] ", (listflags & ASTCONF_quote) ? fmtquote(p->limit.string, "\"", "\"", strlen(p->limit.string), FMT_SHELL) : p->limit.string);
			else
				sfprintf(sp, "L[%I*d] ", sizeof(p->limit.number), p->limit.number);
		}
		if (p->flags & CONF_MINMAX_DEF)
		{
			if (p->minmax.string)
				sfprintf(sp, "M[%s] ", (listflags & ASTCONF_quote) ? fmtquote(p->minmax.string, "\"", "\"", strlen(p->minmax.string), FMT_SHELL) : p->minmax.string);
			else
				sfprintf(sp, "M[%I*d] ", sizeof(p->minmax.number), p->minmax.number);
		}
		if (flags & CONF_ERROR)
			sfprintf(sp, "error");
		else if (defined)
		{
			if (s)
				sfprintf(sp, "%s", (listflags & ASTCONF_quote) ? fmtquote(s, "\"", "\"", strlen(s), FMT_SHELL) : s);
			else if (v != -1)
				sfprintf(sp, "%I*d", sizeof(v), v);
			else
				sfprintf(sp, "%I*u", sizeof(v), v);
		}
		sfprintf(sp, "\n");
	}
	else
	{
		if (!(flags & CONF_PREFIXED) || (listflags & ASTCONF_base))
		{
			if (!name)
			{
				if ((p->flags & (CONF_PREFIXED|CONF_STRING)) == (CONF_PREFIXED|CONF_STRING) && (!(listflags & ASTCONF_base) || p->standard != CONF_POSIX))
				{
					if ((p->flags & CONF_UNDERSCORE) && !(listflags & ASTCONF_base))
						sfprintf(sp, "_");
					sfprintf(sp, "%s", (listflags & ASTCONF_lower) ? fmtlower(prefix[p->standard].name) : prefix[p->standard].name);
					if (p->section > 1)
						sfprintf(sp, "%d", p->section);
					sfprintf(sp, "_");
				}
				sfprintf(sp, "%s=", (listflags & ASTCONF_lower) ? fmtlower(p->name) : p->name);
			}
			if (flags & CONF_ERROR)
				sfprintf(sp, "error");
			else if (defined)
			{
				if (s)
					sfprintf(sp, "%s", (listflags & ASTCONF_quote) ? fmtquote(s, "\"", "\"", strlen(s), FMT_SHELL) : s);
				else if (v != -1)
					sfprintf(sp, "%I*d", sizeof(v), v);
				else
					sfprintf(sp, "%I*u", sizeof(v), v);
			}
			else
				sfprintf(sp, "undefined");
			if (!name)
				sfprintf(sp, "\n");
		}
		if (!name && !(listflags & ASTCONF_base) && !(p->flags & CONF_STRING) && (p->flags & (CONF_FEATURE|CONF_MINMAX)))
		{
			if (p->flags & CONF_UNDERSCORE)
				sfprintf(sp, "_");
			sfprintf(sp, "%s", (listflags & ASTCONF_lower) ? fmtlower(prefix[p->standard].name) : prefix[p->standard].name);
			if (p->section > 1)
				sfprintf(sp, "%d", p->section);
			sfprintf(sp, "_%s=", (listflags & ASTCONF_lower) ? fmtlower(p->name) : p->name);
			if (v != -1)
				sfprintf(sp, "%I*d", sizeof(v), v);
			else if (defined)
				sfprintf(sp, "%I*u", sizeof(v), v);
			else
				sfprintf(sp, "undefined");
			sfprintf(sp, "\n");
		}
	}
	if (drop)
	{
		if (call = sfstruse(sp))
			call = buffer(call);
		else
			call = "[ out of space ]";
		sfclose(sp);
		return call;
	}
 bad:
	return (listflags & ASTCONF_error) ? (char*)0 : null;
}

/*
 * return read stream to native getconf utility
 */

static Sfio_t*
nativeconf(Proc_t** pp, const char* operand)
{
#ifdef _pth_getconf
	Sfio_t*		sp;
	char*		cmd[3];
	long		ops[2];

#if DEBUG_astconf
	error(-2, "astconf defer %s %s", _pth_getconf, operand);
#endif
	cmd[0] = (char*)state.id;
	cmd[1] = (char*)operand;
	cmd[2] = 0;
	ops[0] = PROC_FD_DUP(open("/dev/null",O_WRONLY,0), 2, PROC_FD_CHILD);
	ops[1] = 0;
	if (*pp = procopen(_pth_getconf, cmd, environ, ops, PROC_READ))
	{
		if (sp = sfnew(NiL, NiL, SF_UNBOUND, (*pp)->rfd, SF_READ))
		{
			sfdisc(sp, SF_POPDISC);
			return sp;
		}
		procclose(*pp);
	}
#endif
	return 0;
}

/*
 * value==0 gets value for name
 * value!=0 sets value for name and returns previous value
 * path==0 implies path=="/"
 *
 * settable return values are in permanent store
 * non-settable return values copied to a tmp fmtbuf() buffer
 *
 *	if (streq(astgetconf("PATH_RESOLVE", NiL, NiL, 0, 0), "logical"))
 *		our_way();
 *
 *	universe = astgetconf("UNIVERSE", NiL, "att", 0, 0);
 *	astgetconf("UNIVERSE", NiL, universe, 0, 0);
 *
 * if (flags&ASTCONF_error)!=0 then error return value is 0
 * otherwise 0 not returned
 */

#define ALT	16

char*
astgetconf(const char* name, const char* path, const char* value, int flags, Error_f conferror)
{
	register char*	s;
	int		n;
	Lookup_t	look;
	Sfio_t*		tmp;

#if __OBSOLETE__ < 20080101
	if (pointerof(flags) == (void*)errorf)
	{
		conferror = errorf;
		flags = ASTCONF_error;
	}
	else if (conferror && conferror != errorf)
		conferror = 0;
#endif
	if (!name)
	{
		if (path)
			return null;
		if (!(name = value))
		{
			if (state.data)
			{
				Ast_confdisc_f	notify;

#if _HUH20000515 /* doesn't work for shell builtins */
				free(state.data - state.prefix);
#endif
				state.data = 0;
				notify = state.notify;
				state.notify = 0;
				INITIALIZE();
				state.notify = notify;
			}
			return null;
		}
		value = 0;
	}
	INITIALIZE();
	if (!path)
		path = root;
	if (state.recent && streq(name, state.recent->name) && (s = format(state.recent, path, value, flags, conferror)))
		return s;
	if (lookup(&look, name, flags))
	{
		if (value)
		{
		ro:
			errno = EINVAL;
			if (conferror)
				(*conferror)(&state, &state, 2, "%s: cannot set value", name);
			return (flags & ASTCONF_error) ? (char*)0 : null;
		}
		return print(NiL, &look, name, path, flags, conferror);
	}
	if ((n = strlen(name)) > 3 && n < (ALT + 3))
	{
		if (streq(name + n - 3, "DEV"))
		{
			if (tmp = sfstropen())
			{
				sfprintf(tmp, "/dev/");
				for (s = (char*)name; s < (char*)name + n - 3; s++)
					sfputc(tmp, isupper(*s) ? tolower(*s) : *s);
				if ((s = sfstruse(tmp)) && !access(s, F_OK))
				{
					if (value)
						goto ro;
					s = buffer(s);
					sfclose(tmp);
					return s;
				}
				sfclose(tmp);
			}
		}
		else if (streq(name + n - 3, "DIR"))
		{
			Lookup_t		altlook;
			char			altname[ALT];

			static const char*	dirs[] = { "/usr/lib", "/usr", null };

			strcpy(altname, name);
			altname[n - 3] = 0;
			if (lookup(&altlook, altname, flags))
			{
				if (value)
				{
					errno = EINVAL;
					if (conferror)
						(*conferror)(&state, &state, 2, "%s: cannot set value", altname);
					return (flags & ASTCONF_error) ? (char*)0 : null;
				}
				return print(NiL, &altlook, altname, path, flags, conferror);
			}
			for (s = altname; *s; s++)
				if (isupper(*s))
					*s = tolower(*s);
			if (tmp = sfstropen())
			{
				for (n = 0; n < elementsof(dirs); n++)
				{
					sfprintf(tmp, "%s/%s/.", dirs[n], altname);
					if ((s = sfstruse(tmp)) && !access(s, F_OK))
					{
						if (value)
							goto ro;
						s = buffer(s);
						sfclose(tmp);
						return s;
					}
				}
				sfclose(tmp);
			}
		}
	}
	if ((look.standard < 0 || look.standard == CONF_AST) && look.call <= 0 && look.section <= 1 && (s = feature(look.name, path, value, flags, conferror)))
		return s;
	errno = EINVAL;
	if (conferror && !(flags & ASTCONF_system))
		(*conferror)(&state, &state, 2, "%s: unknown name", name);
	return (flags & ASTCONF_error) ? (char*)0 : null;
}

/*
 * astconf() never returns 0
 */

char*
astconf(const char* name, const char* path, const char* value)
{
	return astgetconf(name, path, value, 0, 0);
}

/*
 * set discipline function to be called when features change
 * old discipline function returned
 */

Ast_confdisc_f
astconfdisc(Ast_confdisc_f new_notify)
{
	Ast_confdisc_f	old_notify;

	INITIALIZE();
	old_notify = state.notify;
	state.notify = new_notify;
	return old_notify;
}

/*
 * list all name=value entries on sp
 * path==0 implies path=="/"
 */

void
astconflist(Sfio_t* sp, const char* path, int flags, const char* pattern)
{
	char*		s;
	char*		f;
	char*		call;
	Feature_t*	fp;
	Lookup_t	look;
	regex_t		re;
	regdisc_t	redisc;
	int		olderrno;
	char		flg[8];
#ifdef _pth_getconf_a
	Proc_t*		proc;
	Sfio_t*		pp;
#endif

	INITIALIZE();
	if (!path)
		path = root;
	else if (access(path, F_OK))
	{
		errorf(&state, &state, 2, "%s: not found", path);
		return;
	}
	olderrno = errno;
	look.flags = 0;
	if (!(flags & (ASTCONF_read|ASTCONF_write|ASTCONF_parse)))
		flags |= ASTCONF_read|ASTCONF_write;
	else if (flags & ASTCONF_parse)
		flags |= ASTCONF_write;
	if (!(flags & (ASTCONF_matchcall|ASTCONF_matchname|ASTCONF_matchstandard)))
		pattern = 0;
	if (pattern)
	{
		memset(&redisc, 0, sizeof(redisc));
		redisc.re_version = REG_VERSION;
		redisc.re_errorf = (regerror_t)errorf;
		re.re_disc = &redisc;
		if (regcomp(&re, pattern, REG_DISCIPLINE|REG_EXTENDED|REG_LENIENT|REG_NULL))
			return;
	}
	if (flags & ASTCONF_read)
	{
		for (look.conf = (Conf_t*)conf; look.conf < (Conf_t*)&conf[conf_elements]; look.conf++)
		{
			if (pattern)
			{
				if (flags & ASTCONF_matchcall)
				{
					if (regexec(&re, prefix[look.conf->call + CONF_call].name, 0, NiL, 0))
						continue;
				}
				else if (flags & ASTCONF_matchname)
				{
					if (regexec(&re, look.conf->name, 0, NiL, 0))
						continue;
				}
				else if (flags & ASTCONF_matchstandard)
				{
					if (regexec(&re, prefix[look.conf->standard].name, 0, NiL, 0))
						continue;
				}
			}
			print(sp, &look, NiL, path, flags, errorf);
		}
#ifdef _pth_getconf_a
		if (pp = nativeconf(&proc, _pth_getconf_a))
		{
			call = "GC";
			while (f = sfgetr(pp, '\n', 1))
			{
				for (s = f; *s && *s != '=' && *s != ':' && !isspace(*s); s++);
				if (*s)
					for (*s++ = 0; isspace(*s); s++);
				if (!lookup(&look, f, flags))
				{
					if (flags & ASTCONF_table)
					{
						if (look.standard < 0)
							look.standard = 0;
						if (look.section < 1)
							look.section = 1;
						sfprintf(sp, "%*s %*s %d %2s %4d %5s %s\n", sizeof(conf[0].name), f, sizeof(prefix[look.standard].name), prefix[look.standard].name, look.section, call, 0, "N", s);
					}
					else if (flags & ASTCONF_parse)
						sfprintf(sp, "%s %s - %s\n", state.id, f, s); 
					else
						sfprintf(sp, "%s=%s\n", f, (flags & ASTCONF_quote) ? fmtquote(s, "\"", "\"", strlen(s), FMT_SHELL) : s);
				}
			}
			sfclose(pp);
			procclose(proc);
		}
#endif
	}
	if (flags & ASTCONF_write)
	{
		call = "AC";
		for (fp = state.features; fp; fp = fp->next)
		{
			if (pattern)
			{
				if (flags & ASTCONF_matchcall)
				{
					if (regexec(&re, call, 0, NiL, 0))
						continue;
				}
				else if (flags & ASTCONF_matchname)
				{
					if (regexec(&re, fp->name, 0, NiL, 0))
						continue;
				}
				else if (flags & ASTCONF_matchstandard)
				{
					if (regexec(&re, prefix[fp->standard].name, 0, NiL, 0))
						continue;
				}
			}
			if (!(s = feature(fp->name, path, NiL, 0, 0)) || !*s)
				s = "0";
			if (flags & ASTCONF_table)
			{
				f = flg;
				if (fp->flags & CONF_ALLOC)
					*f++ = 'A';
				if (fp->flags & CONF_READONLY)
					*f++ = 'R';
				if (f == flg)
					*f++ = 'X';
				*f = 0;
				sfprintf(sp, "%*s %*s %d %2s %4d %5s %s\n", sizeof(conf[0].name), fp->name, sizeof(prefix[fp->standard].name), prefix[fp->standard].name, 1, call, 0, flg, s);
			}
			else if (flags & ASTCONF_parse)
				sfprintf(sp, "%s %s - %s\n", state.id, (flags & ASTCONF_lower) ? fmtlower(fp->name) : fp->name, fmtquote(s, "\"", "\"", strlen(s), FMT_SHELL)); 
			else
				sfprintf(sp, "%s=%s\n", (flags & ASTCONF_lower) ? fmtlower(fp->name) : fp->name, (flags & ASTCONF_quote) ? fmtquote(s, "\"", "\"", strlen(s), FMT_SHELL) : s);
		}
	}
	if (pattern)
		regfree(&re);
	errno = olderrno;
}
