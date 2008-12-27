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
 * preprocessor stacked input stream support
 */

#include "pplib.h"


/*
 * convert path to native representation
 */

#if 0
#include "../../lib/libast/path/pathnative.c" /* drop in 2002 */
#else
/* Modified by gisburn 2006-08-18 for OpenSolaris ksh93-integration */
#include "../../libast/common/path/pathnative.c"
#endif

static char*
native(register const char* s)
{
	register int		c;
	register struct ppfile* xp;
	int			m;
	int			n;

	static Sfio_t*		np;
	static Sfio_t*		qp;

	if (!s)
		return 0;
	if (!np && !(np = sfstropen()) || !qp && !(qp = sfstropen()))
		return (char*)s;
	n = PATH_MAX;
	do
	{
		m = n;
		n = pathnative(s, sfstrrsrv(np, m), m);
	} while (n > m);
	sfstrseek(np, n, SEEK_CUR);
	s = (const char*)sfstruse(np);
	for (;;)
	{
		switch (c = *s++)
		{
		case 0:
			break;
		case '\\':
		case '"':
			sfputc(qp, '\\');
			/*FALLTHROUGH*/
		default:
			sfputc(qp, c);
			continue;
		}
		break;
	}
	if (!(xp = ppsetfile(sfstruse(qp))))
		return (char*)s;
	return xp->name;
}

/*
 * push stream onto input stack
 * used by the PUSH_type macros
 */

void
pppush(register int t, register char* s, register char* p, int n)
{
	register struct ppinstk*	cur;

	PUSH(t, cur);
	cur->line = error_info.line;
	cur->file = error_info.file;
	switch (t)
	{
	case IN_FILE:
		if (pp.option & NATIVE)
			s = native(s);
		cur->flags |= IN_newline;
		cur->fd = n;
		cur->hide = ++pp.hide;
		cur->symbol = 0;
#if CHECKPOINT
		if ((pp.mode & (DUMP|INIT)) == DUMP)
		{
			cur->index = newof(0, struct ppindex, 1, 0);
			if (pp.lastindex) pp.lastindex->next = cur->index;
			else pp.firstindex = cur->index;
			pp.lastindex = cur->index;
			cur->index->file = pp.original;
			cur->index->begin = ppoffset();
		}
#endif
		n = 1;
#if CHECKPOINT
		if (!(pp.mode & DUMP))
#endif
		if (!cur->prev->prev && !(pp.state & COMPILE) && isatty(0))
			cur->flags |= IN_flush;
#if ARCHIVE
		if (pp.member)
		{
			switch (pp.member->archive->type & (TYPE_BUFFER|TYPE_CHECKPOINT))
			{
			case 0:
#if CHECKPOINT
				cur->buflen = pp.member->size;
#endif
				p = (cur->buffer = oldof(0, char, 0, pp.member->size + PPBAKSIZ + 1)) + PPBAKSIZ;
				if (sfseek(pp.member->archive->info.sp, pp.member->offset, SEEK_SET) != pp.member->offset)
					error(3, "%s: archive seek error", pp.member->archive->name);
				if (sfread(pp.member->archive->info.sp, p, pp.member->size) != pp.member->size)
					error(3, "%s: archive read error", pp.member->archive->name);
				pp.member = 0;
				break;
			case TYPE_BUFFER:
#if CHECKPOINT
			case TYPE_CHECKPOINT|TYPE_BUFFER:
				cur->buflen = pp.member->size;
#endif
				p = cur->buffer = pp.member->archive->info.buffer + pp.member->offset;
				cur->flags |= IN_static;
				pp.member = 0;
				break;
#if CHECKPOINT
			case TYPE_CHECKPOINT:
				p = cur->buffer = "";
				cur->flags |= IN_static;
				break;
#endif
			}
			cur->flags |= IN_eof|IN_newline;
			cur->fd = -1;
		}
		else
#endif
		{
			if (lseek(cur->fd, 0L, SEEK_END) > 0 && !lseek(cur->fd, 0L, SEEK_SET))
				cur->flags |= IN_regular;
			errno = 0;
#if PROTOTYPE
			if (!(pp.option & NOPROTO) && !(pp.test & TEST_noproto) && ((pp.state & (COMPATIBILITY|TRANSITION)) == COMPATIBILITY || (pp.option & PLUSPLUS) || (pp.mode & EXTERNALIZE)) && (cur->buffer = pppopen(NiL, cur->fd, NiL, NiL, NiL, NiL, (PROTO_HEADER|PROTO_RETAIN)|(((pp.mode & EXTERNALIZE) || (pp.option & PROTOTYPED)) ? PROTO_FORCE : PROTO_PASS)|((pp.mode & EXTERNALIZE) ? PROTO_EXTERNALIZE : 0)|((pp.mode & MARKC) ? PROTO_PLUSPLUS : 0))))
			{
				*(p = cur->buffer - 1) = 0;
				cur->buffer -= PPBAKSIZ;
				cur->flags |= IN_prototype;
				cur->fd = -1;
			}
			else
#endif
			*(p = (cur->buffer = oldof(0, char, 0, PPBUFSIZ + PPBAKSIZ + 1)) + PPBAKSIZ) = 0;
		}
		if (pp.incref && !(pp.mode & INIT))
			(*pp.incref)(error_info.file, s, error_info.line - 1, PP_SYNC_PUSH);
		if (pp.macref || (pp.option & IGNORELINE))
			cur->flags |= IN_ignoreline;
		cur->prefix = pp.prefix;
		/*FALLTHROUGH*/
	case IN_BUFFER:
	case IN_INIT:
	case IN_RESCAN:
		pushcontrol();
		cur->control = pp.control;
		*pp.control = 0;
		cur->vendor = pp.vendor;
		if (cur->type != IN_RESCAN)
		{
			if (cur->type == IN_INIT)
				pp.mode |= MARKHOSTED;
			error_info.file = s;
			error_info.line = n;
		}
		if (pp.state & HIDDEN)
		{
			pp.state &= ~HIDDEN;
			pp.hidden = 0;
			if (!(pp.state & NOTEXT) && pplastout() != '\n')
				ppputchar('\n');
		}
		pp.state |= NEWLINE;
		if (pp.mode & HOSTED) cur->flags |= IN_hosted;
		else cur->flags &= ~IN_hosted;
		if (pp.mode & (INIT|MARKHOSTED))
		{
			pp.mode |= HOSTED;
			pp.flags |= PP_hosted;
		}
		switch (cur->type)
		{
		case IN_FILE:
			if (!(pp.mode & (INIT|MARKHOSTED)))
			{
				pp.mode &= ~HOSTED;
				pp.flags &= ~PP_hosted;
			}
#if CATSTRINGS
			if (pp.state & JOINING) pp.state |= HIDDEN|SYNCLINE;
			else
#endif
			if (pp.linesync)
				(*pp.linesync)(error_info.line, error_info.file);
#if ARCHIVE && CHECKPOINT
			if (pp.member)
				ppload(NiL);
#endif
			if (pp.mode & MARKC)
			{
				cur->flags |= IN_c;
				pp.mode &= ~MARKC;
				if (!(cur->prev->flags & IN_c))
				{
					debug((-7, "PUSH in=%s next=%s [%s]", ppinstr(pp.in), pptokchr(*pp.in->nextchr), pp.in->nextchr));
					PUSH_BUFFER("C", "extern \"C\" {\n", 1);
					return;
				}
			}
			else if (cur->prev->flags & IN_c)
			{
				debug((-7, "PUSH in=%s next=%s [%s]", ppinstr(pp.in), pptokchr(*pp.in->nextchr), pp.in->nextchr));
				PUSH_BUFFER("C", "extern \"C++\" {\n", 1);
				return;
			}
			break;
		case IN_BUFFER:
			cur->buffer = p = strdup(p);
			break;
		default:
			cur->buffer = p;
			break;
		}
		cur->nextchr = p;
		break;
#if DEBUG
	default:
		error(PANIC, "use PUSH_<%d>(...) instead of pppush(IN_<%d>, ...)", cur->type, cur->type);
		break;
#endif
	}
	debug((-7, "PUSH in=%s next=%s", ppinstr(pp.in), pptokchr(*pp.in->nextchr)));
}

/*
 * external buffer push
 */

void
ppinput(char* b, char* f, int n)
{
	PUSH_BUFFER(f, b, n);
}

/*
 * return expanded value of buffer p
 */

char*
ppexpand(register char* p)
{
	register char*		m;
	register int		n;
	register int		c;
	long			restore;
	char*			pptoken;
	char*			ppmactop;
	struct ppmacstk*	nextmacp;
	struct ppinstk*		cur;

	debug((-7, "before expand: %s", p));
	if (ppmactop = pp.mactop)
	{
		nextmacp = pp.macp->next;
		nextframe(pp.macp, pp.mactop);
	}
	restore = pp.state & (COLLECTING|DISABLE|STRIP);
	pp.state &= ~restore;
	pp.mode &= ~MARKMACRO;
	PUSH_STRING(p);
	cur = pp.in;
	pp.in->flags |= IN_expand;
	pptoken = pp.token;
	n = 2 * MAXTOKEN;
	pp.token = p = oldof(0, char, 0, n);
	m = p + MAXTOKEN;
	for (;;)
	{
		if (pplex())
		{
			if ((pp.token = pp.toknxt) > m)
			{
				c = pp.token - p;
				p = newof(p, char, n += MAXTOKEN, 0);
				m = p + n - MAXTOKEN;
				pp.token = p + c;
			}
			if (pp.mode & MARKMACRO)
			{
				pp.mode &= ~MARKMACRO;
				*pp.token++ = MARK;
				*pp.token++ = 'X';
			}
		}
		else if (pp.in == cur)
			break;
	}
	*pp.token = 0;
	if (ppmactop)
		pp.macp->next = nextmacp;
	debug((-7, "after expand: %s", p));
	pp.token = pptoken;
	pp.state |= restore;
	pp.in = pp.in->prev;
	return p;
}

#if CHECKPOINT

#define LOAD_FUNCTION	(1<<0)
#define LOAD_MULTILINE	(1<<1)
#define LOAD_NOEXPAND	(1<<2)
#define LOAD_PREDICATE	(1<<3)
#define LOAD_READONLY	(1<<4)
#define LOAD_VARIADIC	(1<<5)

/*
 * macro definition dump
 */

static int
dump(const char* name, char* v, void* handle)
{
	register struct ppmacro*	mac;
	register struct ppsymbol*	sym = (struct ppsymbol*)v;
	register int			flags;

	NoP(name);
	NoP(handle);
	if ((mac = sym->macro) && !(sym->flags & (SYM_BUILTIN|SYM_PREDEFINED)))
	{
		ppprintf("%s", sym->name);
		ppputchar(0);
		flags = 0;
		if (sym->flags & SYM_FUNCTION) flags |= LOAD_FUNCTION;
		if (sym->flags & SYM_MULTILINE) flags |= LOAD_MULTILINE;
		if (sym->flags & SYM_NOEXPAND) flags |= LOAD_NOEXPAND;
		if (sym->flags & SYM_PREDICATE) flags |= LOAD_PREDICATE;
		if (sym->flags & SYM_READONLY) flags |= LOAD_READONLY;
		if (sym->flags & SYM_VARIADIC) flags |= LOAD_VARIADIC;
		ppputchar(flags);
		if (sym->flags & SYM_FUNCTION)
		{
			ppprintf("%d", mac->arity);
			ppputchar(0);
			if (mac->arity)
			{
				ppprintf("%s", mac->formals);
				ppputchar(0);
			}
		}
		ppprintf("%s", mac->value);
		ppputchar(0);
	}
	return(0);
}

/*
 * dump macro definitions for quick loading via ppload()
 */

void
ppdump(void)
{
	register struct ppindex*	ip;
	unsigned long			macro_offset;
	unsigned long			index_offset;

	/*
	 * NOTE: we assume '\0' does not occur in valid preprocessed output
	 */

	ppputchar(0);

	/*
	 * output global flags
	 */

	macro_offset = ppoffset();
	ppputchar(0);

	/*
	 * output macro definitions
	 */

	hashwalk(pp.symtab, 0, dump, NiL);
	ppputchar(0);

	/*
	 * output include file index
	 */

	index_offset = ppoffset();
	ip = pp.firstindex;
	while (ip)
	{
		ppprintf("%s", ip->file->name);
		ppputchar(0);
		if (ip->file->guard != INC_CLEAR && ip->file->guard != INC_IGNORE && ip->file->guard != INC_TEST)
			ppprintf("%s", ip->file->guard->name);
		ppputchar(0);
		ppprintf("%lu", ip->begin);
		ppputchar(0);
		ppprintf("%lu", ip->end);
		ppputchar(0);
		ip = ip->next;
	}
	ppputchar(0);

	/*
	 * output offset directory
	 */

	ppprintf("%010lu", macro_offset);
	ppputchar(0);
	ppprintf("%010lu", index_offset);
	ppputchar(0);
	ppflushout();
}

/*
 * load text and macro definitions from a previous ppdump()
 * s is the string argument from the pragma (including quotes)
 */

void
ppload(register char* s)
{
	register char*		b;
	register Sfio_t*	sp;
	int			m;
	char*			g;
	char*			t;
	unsigned long		n;
	unsigned long		p;
	unsigned long		macro_offset;
	unsigned long		index_offset;
	unsigned long		file_offset;
	unsigned long		file_size;
	unsigned long		keep_begin;
	unsigned long		keep_end;
	unsigned long		skip_end;
	unsigned long		next_begin;
	unsigned long		next_end;
	struct ppfile*		fp;
	struct ppsymbol*	sym;
	struct ppmacro*		mac;

	char*			ip = 0;

	pp.mode |= LOADING;
	if (!(pp.state & STANDALONE))
		error(3, "checkpoint load in standalone mode only");
#if ARCHIVE
	if (pp.member)
	{
		sp = pp.member->archive->info.sp;
		file_offset = pp.member->offset;
		file_size = pp.member->size;
		if (sfseek(sp, file_offset + 22, SEEK_SET) != file_offset + 22 || !(s = sfgetr(sp, '\n', 1)))
			error(3, "checkpoint magic error");
	}
	else
#endif
	{
		if (pp.in->type != IN_FILE)
			error(3, "checkpoint load from files only");
		if (pp.in->flags & IN_prototype)
			pp.in->fd = pppdrop(pp.in->buffer + PPBAKSIZ);
		file_offset = 0;
		if (pp.in->fd >= 0)
		{
			if (!(sp = sfnew(NiL, NiL, SF_UNBOUND, pp.in->fd, SF_READ)))
				error(3, "checkpoint read error");
			file_size = sfseek(sp, 0L, SEEK_END);
		}
		else
		{
			file_size = pp.in->buflen;
			if (!(sp = sfnew(NiL, pp.in->buffer + ((pp.in->flags & IN_static) ? 0 : PPBAKSIZ), file_size, -1, SF_READ|SF_STRING)))
				error(3, "checkpoint read error");
		}
	}
	if (!streq(s, pp.checkpoint))
		error(3, "checkpoint version %s does not match %s", s, pp.checkpoint);

	/*
	 * get the macro and index offsets
	 */

	p = file_offset + file_size - 22;
	if ((n = sfseek(sp, p, SEEK_SET)) != p)
		error(3, "checkpoint directory seek error");
	if (!(t = sfreserve(sp, 22, 0)))
		error(3, "checkpoint directory read error");
	macro_offset = file_offset + strtol(t, &t, 10);
	index_offset = file_offset + strtol(t + 1, NiL, 10);

	/*
	 * read the include index
	 */

	if (sfseek(sp, index_offset, SEEK_SET) != index_offset)
		error(3, "checkpoint index seek error");
	if (!(s = sfreserve(sp, n - index_offset, 0)))
		error(3, "checkpoint index read error");
	if (sfset(sp, 0, 0) & SF_STRING)
		b = s;
	else if (!(b = ip = memdup(s, n - index_offset)))
		error(3, "checkpoint index alloc error");

	/*
	 * loop on the index and copy the non-ignored chunks to the output
	 */

	ppcheckout();
	p = PPBUFSIZ - (pp.outp - pp.outbuf);
	keep_begin = 0;
	keep_end = 0;
	skip_end = 0;
	while (*b)
	{
		fp = ppsetfile(b);
		while (*b++);
		g = b;
		while (*b++);
		next_begin = strtol(b, &t, 10);
		next_end = strtol(t + 1, &t, 10);
if (pp.test & 0x0200) error(2, "%s: %s p=%lu next=<%lu,%lu> keep=<%lu,%lu> skip=<-,%lu> guard=%s", keyname(X_CHECKPOINT), fp->name, p, next_begin, next_end, keep_begin, keep_end, skip_end, fp->guard == INC_CLEAR ? "[CLEAR]" : fp->guard == INC_TEST ? "[TEST]" : fp->guard == INC_IGNORE ? "[IGNORE]" : fp->guard->name);
		b = t + 1;
		if (next_begin >= skip_end)
		{
			if (!ppmultiple(fp, INC_TEST))
			{
if (pp.test & 0x0100) error(2, "%s: %s IGNORE", keyname(X_CHECKPOINT), fp->name);
				if (!keep_begin && skip_end < next_begin)
					keep_begin = skip_end;
				if (keep_begin)
				{
				flush:
					if (sfseek(sp, file_offset + keep_begin, SEEK_SET) != file_offset + keep_begin)
						error(3, "checkpoint data seek error");
					n = next_begin - keep_begin;
if (pp.test & 0x0100) error(2, "%s: copy <%lu,%lu> n=%lu p=%lu", keyname(X_CHECKPOINT), keep_begin, next_begin - 1, n, p);
					while (n > p)
					{
						if (sfread(sp, pp.outp, p) != p)
							error(3, "checkpoint data read error");
						PPWRITE(PPBUFSIZ);
						pp.outp = pp.outbuf;
						n -= p;
						p = PPBUFSIZ;
					}
					if (n)
					{
						if (sfread(sp, pp.outp, n) != n)
							error(3, "checkpoint data read error");
						pp.outp += n;
						p -= n;
					}
					keep_begin = 0;
					if (keep_end <= next_end)
						keep_end = 0;
				}
				skip_end = next_end;
			}
			else if (!keep_begin)
			{
				if (skip_end)
				{
					keep_begin = skip_end;
					skip_end = 0;
				}
				else keep_begin = next_begin;
				if (keep_end < next_end)
					keep_end = next_end;
			}
		}
		if (*g && fp->guard != INC_IGNORE)
			fp->guard = ppsymset(pp.symtab, g);
	}
	if (keep_end)
	{
		if (!keep_begin)
			keep_begin = skip_end > next_end ? skip_end : next_end;
		next_begin = next_end = keep_end;
		g = b;
		goto flush;
	}
if (pp.test & 0x0100) error(2, "%s: loop", keyname(X_CHECKPOINT));

	/*
	 * read the compacted definitions
	 */

	if (sfseek(sp, macro_offset, SEEK_SET) != macro_offset)
		error(3, "checkpoint macro seek error");
	if (!(s = sfreserve(sp, index_offset - macro_offset, 0)))
		error(3, "checkpoint macro read error");

	/*
	 * read the flags
	 */

	while (*s)
	{
#if _options_dumped_
		if (streq(s, "OPTION")) /* ... */;
		else
#endif
		error(3, "%-.48s: unknown flags in checkpoint file", s);
	}
	s++;

	/*
	 * unpack and enter the definitions
	 */

	while (*s)
	{
		b = s;
		while (*s++);
		m = *s++;
		sym = ppsymset(pp.symtab, b);
		if (sym->macro)
		{
			if (m & LOAD_FUNCTION)
			{
				if (*s++ != '0')
					while (*s++);
				while (*s++);
			}
if (pp.test & 0x1000) error(2, "checkpoint SKIP %s=%s [%s]", sym->name, s, sym->macro->value);
			while (*s++);
		}
		else
		{
			ppfsm(FSM_MACRO, b);
			sym->flags = 0;
			if (m & LOAD_FUNCTION) sym->flags |= SYM_FUNCTION;
			if (m & LOAD_MULTILINE) sym->flags |= SYM_MULTILINE;
			if (m & LOAD_NOEXPAND) sym->flags |= SYM_NOEXPAND;
			if (m & LOAD_PREDICATE) sym->flags |= SYM_PREDICATE;
			if (m & LOAD_READONLY) sym->flags |= SYM_READONLY;
			if (m & LOAD_VARIADIC) sym->flags |= SYM_VARIADIC;
			mac = sym->macro = newof(0, struct ppmacro, 1, 0);
			if (sym->flags & SYM_FUNCTION)
			{
				for (n = 0; *s >= '0' && *s <= '9'; n = n * 10 + *s++ - '0');
				if (*s++) error(3, "%-.48: checkpoint macro arity botched", sym->name);
				if (mac->arity = n)
				{
					b = s;
					while (*s++);
					mac->formals = (char*)memcpy(oldof(0, char, 0, s - b), b, s - b);
				}
			}
			b = s;
			while (*s++);
			mac->size = s - b - 1;
			mac->value = (char*)memcpy(oldof(0, char, 0, mac->size + 1), b, mac->size + 1);
if (pp.test & 0x1000) error(2, "checkpoint LOAD %s=%s", sym->name, mac->value);
		}
	}

	/*
	 * we are now at EOF
	 */

	if (ip)
	{
		pp.in->fd = -1;
		free(ip);
	}
#if ARCHIVE
	if (pp.member) pp.member = 0;
	else
#endif
	{
		sfclose(sp);
		pp.in->flags |= IN_eof|IN_newline;
		pp.in->nextchr = pp.in->buffer + PPBAKSIZ;
		*pp.in->nextchr++ = 0;
		*pp.in->nextchr = 0;
	}
	pp.mode &= ~LOADING;
}

#endif
