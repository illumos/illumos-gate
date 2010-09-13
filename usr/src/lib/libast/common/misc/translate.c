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
 * AT&T Research and SCO
 * ast l10n message translation
 */

#include "lclib.h"

#include <cdt.h>
#include <error.h>
#include <mc.h>
#include <nl_types.h>

#ifndef DEBUG_trace
#define DEBUG_trace		0
#endif

#define NOCAT			((nl_catd)-1)
#define GAP			100

typedef	struct 
{	
	Dtlink_t	link;		/* dictionary link		*/
	Dt_t*		messages;	/* message dictionary handle	*/
	nl_catd		cat;		/* message catalog handle	*/
	int		debug;		/* special debug locale		*/
	const char*	locale;		/* message catalog locale	*/	
	char		name[1];	/* catalog name			*/
} Catalog_t;

typedef struct
{	
	Dtlink_t	link;		/* dictionary link		*/
	Catalog_t*	cat;		/* current catalog pointer	*/
	int		set;		/* set number			*/
	int		seq;		/* sequence number		*/
	char		text[1];	/* message text			*/
} Message_t;

typedef struct
{
	Sfio_t*		sp;		/* temp string stream		*/
	int		off;		/* string base offset		*/
} Temp_t;

typedef struct
{
	Dtdisc_t	message_disc;	/* message dict discipline	*/
	Dtdisc_t	catalog_disc;	/* catalog dict discipline	*/
	Dt_t*		catalogs;	/* catalog dictionary handle	*/
	Sfio_t*		tmp;		/* temporary string stream	*/
	const char*	debug;		/* debug locale name		*/
	int		error;		/* no dictionaries!		*/
	char		null[1];	/* null string			*/
} State_t;

static State_t	state =
{
	{	offsetof(Message_t, text),	0,	0	},
	{	offsetof(Catalog_t, name),	0,	0	},
};

static int
tempget(Sfio_t* sp)
{
	if (sfstrtell(sp) > sfstrsize(sp) / 2)
		sfstrseek(sp, 0, SEEK_SET);
	return sfstrtell(sp);
}

static char*
tempuse(Sfio_t* sp, int off)
{
	sfputc(sp, 0);
	return sfstrbase(sp) + off;
}

/*
 * add msg to dict
 */

static int
entry(Dt_t* dict, int set, int seq, const char* msg)
{
	Message_t*	mp;

	if (!(mp = newof(0, Message_t, 1, strlen(msg))))
		return 0;
	strcpy(mp->text, msg);
	mp->set = set;
	mp->seq = seq;
	if (!dtinsert(dict, mp))
	{
		free(mp);
		return 0;
	}
#if DEBUG_trace > 1
sfprintf(sfstderr, "AHA#%d:%s set %d seq %d msg `%s'\n", __LINE__, __FILE__, set, seq, msg);
#endif
	return 1;
}

/*
 * find catalog in locale and return catopen() descriptor
 */

static nl_catd
find(const char* locale, const char* catalog)
{
	char		path[PATH_MAX];
#if DEBUG_trace
	const char*	ocatalog = catalog;
#endif

	if (mcfind(path, locale, catalog, LC_MESSAGES, 0))
		catalog = (const char*)path;
#if DEBUG_trace
sfprintf(sfstderr, "AHA#%d:%s %s %s %s\n", __LINE__, __FILE__, locale, ocatalog, catalog);
#endif
	return catopen(catalog, NL_CAT_LOCALE);
}

/*
 * initialize the catalog s by loading in the default locale messages
 */

static Catalog_t*
init(register char* s)
{
	register Catalog_t*	cp;
	register char*		u;
	register int		n;
	register int		m;
	nl_catd			d;

	/*
	 * insert into the catalog dictionary
	 */

	if (!(cp = newof(0, Catalog_t, 1, strlen(s))))
		return 0;
	strcpy(cp->name, s);
	if (!dtinsert(state.catalogs, cp))
	{
		free(cp);
		return 0;
	}
	cp->cat = NOCAT;

	/*
	 * locate the default locale catalog
	 */

	ast.locale.set |= AST_LC_internal;
	u = setlocale(LC_MESSAGES, NiL);
	setlocale(LC_MESSAGES, "C");
	if ((d = find("C", s)) != NOCAT)
	{
		/*
		 * load the default locale messages
		 * this assumes one mesage set for ast (AST_MESSAGE_SET)
		 * different packages can share the same message catalog
		 * name by using different message set numbers
		 * see <mc.h> mcindex()
		 *
		 * this method requires a scan of each catalog, and the
		 * catalogs do not advertize the max message number, so
		 * we assume there are no messages after a gap of GAP
		 * missing messages
		 */

		if (cp->messages = dtopen(&state.message_disc, Dtset))
		{
			n = m = 0;
			for (;;)
			{
				n++;
				if ((s = catgets(d, AST_MESSAGE_SET, n, state.null)) != state.null && entry(cp->messages, AST_MESSAGE_SET, n, s))
					m = n;
				else if ((n - m) > GAP)
					break;
			}
			if (!m)
			{
				dtclose(cp->messages);
				cp->messages = 0;
			}
		}
		catclose(d);
	}
	setlocale(LC_MESSAGES, u);
	ast.locale.set &= ~AST_LC_internal;
	return cp;
}

/*
 * return the C locale message pointer for msg in cat
 * cat may be a : separated list of candidate names
 */

static Message_t*
match(const char* cat, const char* msg)
{
	register char*	s;
	register char*	t;
	Catalog_t*	cp;
	Message_t*	mp;
	size_t		n;

	char		buf[1024];

	s = (char*)cat;
	for (;;)
	{
		if (t = strchr(s, ':'))
		{
			if (s == (char*)cat)
			{
				if ((n = strlen(s)) >= sizeof(buf))
					n = sizeof(buf) - 1;
				s = (char*)memcpy(buf, s, n);
				s[n] = 0;
				t = strchr(s, ':');
			}
			*t = 0;
		}
		if (*s && ((cp = (Catalog_t*)dtmatch(state.catalogs, s)) || (cp = init(s))) && cp->messages && (mp = (Message_t*)dtmatch(cp->messages, msg)))
		{
			mp->cat = cp;
			return mp;
		}
		if (!t)
			break;
		s = t + 1;
	}
	return 0;
}

/*
 * translate() is called with four arguments:
 *
 *	loc	the LC_MESSAGES locale name
 *	cmd	the calling command name
 *	cat	the catalog name, possibly a : separated list
 *		"libFOO"	FOO library messages
 *		"libshell"	ksh command messages
 *		"SCRIPT"	script SCRIPT application messages
 *	msg	message text to be translated
 *
 * the translated message text is returned on success
 * otherwise the original msg is returned
 *
 * The first time translate() is called (for a non-C locale) 
 * it creates the state.catalogs dictionary. A dictionary entry
 * (Catalog_t) is made each time translate() is called with a new
 * cmd:cat argument. 
 * 
 * The X/Open interface catgets() is used to obtain a translated 
 * message. Its arguments include the message catalog name
 * and the set/sequence numbers within the catalog. An additional 
 * dictionary, with entries of type Message_t, is needed for 
 * mapping untranslated message strings to the set/sequence numbers 
 * needed by catgets().  A separate Message_t dictionary is maintained
 * for each Catalog_t.
 */   

char*
translate(const char* loc, const char* cmd, const char* cat, const char* msg)
{
	register char*	r;
	char*		t;
	int		p;
	int		oerrno;
	Catalog_t*	cp;
	Message_t*	mp;

	oerrno = errno;
	r = (char*)msg;

	/*
	 * quick out
	 */

	if (!cmd && !cat)
		goto done;
	if (cmd && (t = strrchr(cmd, '/')))
		cmd = (const char*)(t + 1);

	/*
	 * initialize the catalogs dictionary
	 */

	if (!state.catalogs)
	{
		if (state.error)
			goto done;
		if (!(state.tmp = sfstropen()))
		{
			state.error = 1;
			goto done;
		}
		if (!(state.catalogs = dtopen(&state.catalog_disc, Dtset)))
		{
			sfclose(state.tmp);
			state.error = 1;
			goto done;
		}
		if (streq(loc, "debug"))
			state.debug = loc;
	}

	/*
	 * get the message
	 * or do we have to spell it out for you
	 */

	if ((!cmd || !(mp = match(cmd, msg))) &&
	    (!cat || !(mp = match(cat, msg))) &&
	    (!error_info.catalog || !(mp = match(error_info.catalog, msg))) &&
	    (!ast.id || !(mp = match(ast.id, msg))) ||
	     !(cp = mp->cat))
	{
#if DEBUG_trace > 1
sfprintf(sfstderr, "AHA#%d:%s cmd %s cat %s:%s id %s msg `%s'\n", __LINE__, __FILE__, cmd, cat, error_info.catalog, ast.id, msg);
#endif
		goto done;
	}

	/*
	 * adjust for the current locale
	 */

#if DEBUG_trace
sfprintf(sfstderr, "AHA#%d:%s cp->locale `%s' %p loc `%s' %p\n", __LINE__, __FILE__, cp->locale, cp->locale, loc, loc);
#endif
	if (cp->locale != loc)
	{
		cp->locale = loc;
		if (cp->cat != NOCAT)
			catclose(cp->cat);
		if ((cp->cat = find(cp->locale, cp->name)) == NOCAT)
			cp->debug = streq(cp->locale, "debug");
		else
			cp->debug = 0;
#if DEBUG_trace
sfprintf(sfstderr, "AHA#%d:%s cp->cat %p cp->debug %d NOCAT %p\n", __LINE__, __FILE__, cp->cat, cp->debug, NOCAT);
#endif
	}
	if (cp->cat == NOCAT)
	{
		if (cp->debug)
		{
			p = tempget(state.tmp);
			sfprintf(state.tmp, "(%s,%d,%d)", cp->name, mp->set, mp->seq);
			r = tempuse(state.tmp, p);
		}
		else if (ast.locale.set & AST_LC_debug)
		{
			p = tempget(state.tmp);
			sfprintf(state.tmp, "(%s,%d,%d)%s", cp->name, mp->set, mp->seq, r);
			r = tempuse(state.tmp, p);
		}
		goto done;
	}

	/*
	 * get the translated message
	 */

	r = catgets(cp->cat, mp->set, mp->seq, msg);
	if (ast.locale.set & AST_LC_translate)
		sfprintf(sfstderr, "translate locale=%s catalog=%s set=%d seq=%d \"%s\" => \"%s\"\n", cp->locale, cp->name, mp->set, mp->seq, msg, r == (char*)msg ? "NOPE" : r);
	if (r != (char*)msg)
	{
		if (streq(r, (char*)msg))
			r = (char*)msg;
		else if (strcmp(fmtfmt(r), fmtfmt(msg)))
		{
			sfprintf(sfstderr, "locale %s catalog %s message %d.%d \"%s\" does not match \"%s\"\n", cp->locale, cp->name, mp->set, mp->seq, r, msg);
			r = (char*)msg;
		}
	}
	if (ast.locale.set & AST_LC_debug)
	{
		p = tempget(state.tmp);
		sfprintf(state.tmp, "(%s,%d,%d)%s", cp->name, mp->set, mp->seq, r);
		r = tempuse(state.tmp, p);
	}
 done:
	if (r == (char*)msg && loc == state.debug)
	{
		p = tempget(state.tmp);
		sfprintf(state.tmp, "(%s,%s,%s,\"%s\")", loc, cmd, cat, r);
		r = tempuse(state.tmp, p);
	}
	errno = oerrno;
	return r;
}
