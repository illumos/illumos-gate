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
 * preprocessor lexical analyzer
 * standalone and tokenizing lexer combined in one source
 * define CPP=1 for standalone
 */

#include "pplib.h"
#include "ppfsm.h"

#if CPP

/*
 * standalone entry point
 */

#define PPCPP_T		void

#define START		QUICK
#define INMACRO(x)	INQMACRO(x)
#define DOSTRIP()	(st&STRIP)

#if DEBUG & TRACE_debug
static int		hit[LAST-TERMINAL+2];
#endif

#define BACKIN()	(ip--)
#define BACKOUT()	(op=tp)
#define CACHE()		do{CACHEINX();CACHEOUTX();st=pp.state;if(!pp.hidden)spliced=0;}while(0)
#define CACHEIN()	do{CACHEINX();st=pp.state;if(!pp.hidden)spliced=0;}while(0)
#define CACHEINX()	do{ip=pp.in->nextchr;}while(0)
#define CACHEOUT()	do{CACHEOUTX();st=pp.state;if(!pp.hidden)spliced=0;}while(0)
#define CACHEOUTX()	do{tp=op=pp.outp;xp=pp.oute;if(sp)sp=op;}while(0)
#define GETCHR()	(*(unsigned char*)ip++)
#define LASTCHR()	(*(ip-1))
#define LASTOUT()	((op>pp.outbuf)?*(op-1):pp.lastout)
#define SKIPIN()	(ip++)
#define PUTCHR(c)	(*op++=(c))
#define SETCHR(c)	(*op=(c))
#define SYNC()		do{SYNCINX();SYNCOUTX();pp.state=st;}while(0)
#define SYNCIN()	do{SYNCINX();pp.state=st;}while(0)
#define SYNCINX()	do{pp.in->nextchr=ip;}while(0)
#define SYNCOUT()	do{SYNCOUTX();pp.state=st;}while(0)
#define SYNCOUTX()	do{if(sp)op=tp=sp;pp.outp=op;}while(0)
#define UNGETCHR(c)	(*--ip=(c))

#define PPCHECKOUT()	do{if(op>xp){{PPWRITE(PPBUFSIZ);if(pp.outbuf==pp.outb){pp.outbuf+=PPBUFSIZ;xp=pp.oute+=PPBUFSIZ;}else{pp.outbuf-=PPBUFSIZ;memcpy(pp.outbuf,xp,op-xp);xp=pp.oute-=PPBUFSIZ;op-=2*PPBUFSIZ;}}}}while(0)
#define PPCHECKOUTSP()	do{if(op>xp){if(sp)op=sp;else{PPWRITE(PPBUFSIZ);if(pp.outbuf==pp.outb){pp.outbuf+=PPBUFSIZ;xp=pp.oute+=PPBUFSIZ;}else{pp.outbuf-=PPBUFSIZ;memcpy(pp.outbuf,xp,op-xp);xp=pp.oute-=PPBUFSIZ;op-=2*PPBUFSIZ;}}}}while(0)
#define PPCHECKOUTTP()	do{if(op>xp){{PPWRITE(PPBUFSIZ);if(pp.outbuf==pp.outb){pp.outbuf+=PPBUFSIZ;xp=pp.oute+=PPBUFSIZ;}else{pp.outbuf-=PPBUFSIZ;memcpy(pp.outbuf,xp,op-xp);xp=pp.oute-=PPBUFSIZ;op-=2*PPBUFSIZ;}}tp=op;}}while(0)

#define PPSYNCLINE()	do { \
		if ((st & (ADD|HIDDEN)) && !(*pp.control & SKIP)) \
		{ \
		    if (spliced) \
		    { \
			error_info.line += spliced; \
			spliced = 0; \
		    } \
		    else \
		    { \
			if (st & ADD) \
			{ \
				st &= ~ADD; \
				m = pp.addp - pp.addbuf; \
				pp.addp = pp.addbuf; \
				memcpy(op, pp.addbuf, m); \
				op += m; \
				PPCHECKOUT(); \
			} \
			if (pp.linesync) \
			{ \
				if ((st & SYNCLINE) || pp.hidden >= MAXHIDDEN) \
				{ \
					pp.hidden = 0; \
					st &= ~(HIDDEN|SYNCLINE); \
					if (error_info.line) \
					{ \
						if (LASTOUT() != '\n') \
							PUTCHR('\n'); \
						SYNCOUT(); \
						(*pp.linesync)(error_info.line, error_info.file); \
						CACHEOUT(); \
					} \
				} \
				else \
				{ \
					m = pp.hidden; \
					pp.hidden = 0; \
					st &= ~HIDDEN; \
					while (m-- > 0) \
						PUTCHR('\n'); \
				} \
			} \
			else \
			{ \
				pp.hidden = 0; \
				st &= ~HIDDEN; \
				PUTCHR('\n'); \
			} \
		    } \
		} \
	} while (0)

#if POOL

/*
 * <wait.h> is poison here so pool moved to the end
 */

static void	poolstatus(void);
static void	pool(void);

#endif

#else

/*
 * return next pp token
 *
 * NOTE: pp.token points to at least MAXTOKEN*2 chars and is
 *       truncated back to MAXTOKEN on EOB
 */

#define PPCPP_T		int
#define ppcpp		pplex

#define START		TOKEN
#define INMACRO(x)	INTMACRO(x)
#define DOSTRIP()	((st&STRIP)||pp.level==1&&(st&(COMPILE|JOINING))==COMPILE&&!(pp.option&PRESERVE))

#define st		pp.state
#define tp		pp.token
#define xp		&pp.token[MAXTOKEN]

#define BACKIN()	(ip--)
#define BACKOUT()	(op=pp.token)
#define CACHE()		do{CACHEIN();CACHEOUT();}while(0)
#define CACHEIN()	(ip=pp.in->nextchr)
#define CACHEOUT()	(op=pp.token)
#define GETCHR()	(*(unsigned char*)ip++)
#define LASTCHR()	(*(ip-1))
#define PUTCHR(c)	(*op++=(c))
#define SETCHR(c)	(*op=(c))
#define SKIPIN()	(ip++)
#define SYNC()		do{SYNCIN();SYNCOUT();}while(0)
#define SYNCIN()	(pp.in->nextchr=ip)
#define SYNCOUT()	(pp.toknxt=op)
#define UNGETCHR(c)	(*--ip=(c))

#endif

PPCPP_T
ppcpp(void)
{
	register short*		rp;
	register char*		ip;
	register int		state;
	register int		c;
	register char*		op;
	char*			bp;
	int			n;
	int			m;
	int			quot;
	int			quotquot;
	int			comdelim = 0;
	int			comstart = 0;
	int			comwarn = 0;
	char*			s;
	struct ppsymbol*	sym;
#if CPP
	register long		st;
	char*			tp;
	char*			xp;
	char*			sp = 0;
	int			qual = 0;
	int			spliced = 0;
#else
	int			qual;
#endif

#if CPP
#if POOL
 fsm_pool:
#endif
#else
	count(pplex);
#endif
	error_info.indent++;
	pp.level++;
	CACHE();
#if !CPP
 fsm_top:
	qual = 0;
#endif
 fsm_start:
#if CPP
	PPCHECKOUTSP();
	tp = op;
#endif
	state = START;
 fsm_begin:
	bp = ip;
	do
	{
		rp = fsm[state];
 fsm_get:
		while (!(state = rp[c = GETCHR()]));
 fsm_next:
		;
	} while (state > 0);
	if (((state = ~state) != S_COMMENT || pp.comment || c == '/' && !INCOMMENT(rp)) && (n = ip - bp - 1) > 0)
	{
		ip = bp;
#if CPP
		if (op == tp && (st & (ADD|HIDDEN)) && !(st & PASSTHROUGH) && !(pp.option & PRESERVE))
			switch (TERM(state))
			{
			case S_SHARP:
				break;
			case S_CHRB:
			case S_NL:
				if (*ip == '\n')
					break;
				/*FALLTHROUGH*/
			default:
				if ((pp.option & PRESERVE) && !(st & NEWLINE) && c != '\n')
					break;
				PPSYNCLINE();
				tp = op;
				break;
			}
#endif
		MEMCPY(op, ip, n);
		ip++;
	}
	count(terminal);
#if CPP && (DEBUG & TRACE_debug)
	hit[(state & SPLICE) ? (elementsof(hit) - 1) : (TERM(state) - TERMINAL)]++;
#endif
 fsm_terminal:
	debug((-9, "TERM %s > %s%s%s |%-*.*s|%s|", pplexstr(INDEX(rp)), pplexstr(state), (st & NEWLINE) ? "|NEWLINE" : "", (st & SKIPCONTROL) ? "|SKIP" : "", op - tp, op - tp, tp, pptokchr(c)));
	switch (TERM(state))
	{

#if !CPP
	case S_CHR:
		PUTCHR(c);
		break;
#endif

	case S_CHRB:
		BACKIN();
#if CPP
		st &= ~NEWLINE;
		pp.in->flags |= IN_tokens;
		count(token);
		goto fsm_start;
#else
		c = *tp;
		break;
#endif

	case S_COMMENT:
		switch (c)
		{
		case '\n':
			if (!INCOMMENTXX(rp))
			{
				qual = 0;
				if (!comstart) comstart = comdelim = error_info.line;
				error_info.line++;
				if (pp.comment) PUTCHR(c);
				else BACKOUT();
#if CPP
				rp = fsm[COM2];
				bp = ip;
				goto fsm_get;
#else
				state = COM2;
				goto fsm_begin;
#endif
			}
			else if (comwarn < 0 && !(pp.mode & HOSTED))
				error(1, "/* appears in // comment");
			break;
		case '*':
			if (!comwarn && !(pp.mode & HOSTED))
			{
				if (INCOMMENTXX(rp)) comwarn = -1;
				else if (comstart && comstart != error_info.line)
				{
					if (qual || comdelim < error_info.line - 1)
					{
						error(1, "/* appears in /* ... */ comment starting at line %d", comstart);
						comwarn = 1;
					}
					else comdelim = error_info.line;
				}
			}
 fsm_comment:
			PUTCHR(c);
#if CPP
			rp = fsm[INCOMMENTXX(rp) ? COM5 : COM3];
			bp = ip;
			goto fsm_get;
#else
			state = INCOMMENTXX(rp) ? COM5 : COM3;
			goto fsm_begin;
#endif
		case '/':
			if (!INCOMMENT(rp))
			{
				if (!(pp.mode & HOSTED))
					error(1, "*/ appears outside of comment");
				BACKIN();
#if CPP
				st &= ~NEWLINE;
				pp.in->flags |= IN_tokens;
				count(token);
				goto fsm_start;
#else
				c = '*';
				if (!pp.comment) PUTCHR(c);
				goto fsm_token;
#endif
			}
			else if (INCOMMENTXX(rp))
			{
				if (!(pp.mode & HOSTED))
				{
					if (comwarn < 0) comwarn = 0;
					else if (!comwarn)
					{
						comwarn = 1;
						error(1, "*/ appears in // comment");
					}
				}
				goto fsm_comment;
			}
			break;
		case EOF:
			BACKIN();
			if (!(pp.mode & HOSTED))
			{
				if (comstart) error(2, "unterminated /* ... */ comment starting at line %d", comstart);
				else if (INCOMMENTXX(rp)) error(2, "unterminated // ... comment");
				else error(2, "unterminated /* ... */ comment");
			}
			break;
		}
#if CPP
		if (!pp.comment || sp)
		{
#if COMPATIBLE
			if (!(pp.state & COMPATIBILITY) || *bp == ' ' || *bp == '\t')
#endif
			{
				BACKOUT();
				PUTCHR(' ');
				tp = op;
			}
		}
		else if (pp.in->type & IN_TOP)
#else
		if (pp.comment && !(st & (COLLECTING|DIRECTIVE|JOINING)) && !(*pp.control & SKIP) && (pp.in->type & IN_TOP))
#endif
		{
			st &= ~HIDDEN;
			pp.hidden = 0;
			*(op - (c != '\n')) = 0;
			m = (op - (c != '\n') - tp > MAXTOKEN - 6) ? (error_info.line - MAXHIDDEN) : 0;
			BACKOUT();
			SYNC();
			while (*tp != '/') tp++;
			(*pp.comment)(c == '\n' ? "//" : "/*", tp + 2, c == '\n' ? "" : (st & HEADER) ? "*/\n" : "*/", comstart ? comstart : error_info.line);
			CACHE();
			comstart = m;
		}
		if (comstart)
		{
			st |= HIDDEN;
			pp.hidden += error_info.line - comstart;
			comstart = 0;
		}
		qual = comwarn = comdelim = 0;
		BACKOUT();
		if (c == '\n') goto fsm_newline;
		if ((st & PASSTHROUGH) && ((st & (HIDDEN|NEWLINE)) || *ip == '\n'))
		{
			if (*ip == '\n')
				ip++;
			goto fsm_newline;
		}
#if COMPATIBLE
		if ((st & (COMPATIBILITY|TRANSITION)) == COMPATIBILITY) st &= ~NEWLINE;
#endif
#if !CPP
		if (pp.level > 1 && !(st & (NOSPACE|SKIPCONTROL)))
		{
#if COMPATIBLE
			c = ((st & (COMPATIBILITY|DEFINITION)) == ((COMPATIBILITY|DEFINITION))) ? '\t' : ' ';
#else
			c = ' ';
#endif
			goto fsm_return;
		}
#endif
		goto fsm_start;

	case S_EOB:
		if (c)
		{
			if (state = fsm[TERMINAL][INDEX(rp)+1])
				goto fsm_terminal;
#if CPP
#if POOL
			if (pp.pool.input)
			{
				BACKIN();
				SYNC();
				pool();
				CACHE();
				goto fsm_pool;
			}
#endif
			SYNCOUT();
			return;
#else
			BACKIN();
			c = 0;
			goto fsm_return;
#endif
		}
		{
			register struct ppinstk*	cur = pp.in;
			register struct ppinstk*	prv = pp.in->prev;

#if CPP
			if (sp) op = sp;
#endif
			switch (cur->type)
			{
			case IN_BUFFER:
			case IN_INIT:
			case IN_RESCAN:
#if CPP
				if (prv)
#else
				if (!(st & PASSEOF) && prv)
#endif
				{
					if (cur->type == IN_RESCAN || cur->type == IN_BUFFER)
					{
 fsm_pop:
#if PROTOTYPE
						if (cur->flags & IN_prototype)
							pppclose(cur->buffer + PPBAKSIZ);
						else
#endif
						if (!(cur->flags & IN_static))
							free(cur->buffer);
					}
					while (pp.control-- != cur->control)
						error(2, "#%s on line %d has no #%s", dirname(IF), GETIFLINE(pp.control+1), dirname(ENDIF));
					st |= NEWLINE;
					error_info.file = cur->file;
					error_info.line = cur->line;
					pp.hidden = 0;
#if CPP
					spliced = 0;
#endif
					if (cur->flags & IN_hosted)
					{
						pp.mode |= HOSTED;
						pp.flags |= PP_hosted;
					}
					else
					{
						pp.mode &= ~HOSTED;
						pp.flags &= ~PP_hosted;
					}
#if !CPP && CATSTRINGS
					if (st & JOINING) st |= HIDDEN|SYNCLINE;
					else
#endif
					{
						st &= ~(HIDDEN|SYNCLINE);
						switch (cur->type)
						{
						case IN_BUFFER:
						case IN_INIT:
							if (!prv->prev) break;
							/*FALLTHROUGH*/
						case IN_FILE:
						case IN_RESCAN:
							if (prv->type == IN_FILE || cur->type == IN_FILE && (prv->type == IN_RESCAN || prv->type == IN_MULTILINE))
							{
								if (pp.linesync && (cur->type != IN_RESCAN || (cur->flags & IN_sync)))
								{
									POP();
									SYNCOUT();
									(*pp.linesync)(error_info.line, error_info.file);
									CACHEOUT();
									prv = pp.in;
								}
							}
#if DEBUG
							else if (!prv->prev)
							{
								/*UNDENT*/
	c = 0;
#if DEBUG & TRACE_count
	if (pp.test & TEST_count)
	{
		c = 1;
		sfprintf(sfstderr, "\n");
		sfprintf(sfstderr, "%7d: pplex calls\n", pp.counter.pplex);
		sfprintf(sfstderr, "%7d: terminal states\n", pp.counter.terminal);
		sfprintf(sfstderr, "%7d: emitted tokens\n", pp.counter.token);
		sfprintf(sfstderr, "%7d: input stream pushes\n", pp.counter.push);
		sfprintf(sfstderr, "%7d: macro candidates\n", pp.counter.candidate);
		sfprintf(sfstderr, "%7d: macro expansions\n", pp.counter.macro);
		sfprintf(sfstderr, "%7d: function macros\n", pp.counter.function);
	}
#endif
#if CPP && (DEBUG & TRACE_debug)
	if (pp.test & TEST_hit)
	{
		c = 1;
		sfprintf(sfstderr, "\n");
		if (hit[elementsof(hit) - 1])
			sfprintf(sfstderr, "%7d: SPLICE\n", hit[elementsof(hit) - 1]);
		for (n = 0; n < elementsof(hit) - 1; n++)
			if (hit[n])
				sfprintf(sfstderr, "%7d: %s\n", hit[n], pplexstr(TERMINAL + n));
	}
#endif
	if (pp.test & (TEST_hashcount|TEST_hashdump))
	{
		c = 1;
		sfprintf(sfstderr, "\n");
		hashdump(NiL, (pp.test & TEST_hashdump) ? HASH_BUCKET : 0);
	}
	if (c) sfprintf(sfstderr, "\n");
								/*INDENT*/
							}
#endif
							break;
						}
					}
#if CHECKPOINT
					if (cur->index)
					{
						SYNCOUT();
						cur->index->end = ppoffset();
						cur->index = 0;
						CACHEOUT();
					}
#endif
					POP();
					bp = ip;
					tp = op;
					goto fsm_get;
				}
				c = EOF;
				break;
			case IN_COPY:
				if (prv)
				{
					error_info.line = cur->line;
					if (!(prv->symbol->flags & SYM_MULTILINE))
						prv->symbol->flags |= SYM_DISABLED;
					POP();
					bp = ip;
					goto fsm_get;
				}
				c = EOF;
				break;
			case IN_EXPAND:
				if (prv)
				{
					error_info.line = cur->line;
					free(cur->buffer);
					POP();
					bp = ip;
					goto fsm_get;
				}
				c = EOF;
				break;
			case IN_FILE:
				FGET(c, c, tp, xp);
				if (c == EOB)
				{
#if CPP
					if ((st & (NOTEXT|HIDDEN)) == HIDDEN && LASTOUT() != '\n')
						PUTCHR('\n');
					if (prv)
#else
					if (st & EOF2NL)
					{
						st &= ~EOF2NL;
						*(ip - 1) = c = '\n';
					}
					else if (!(st & (FILEPOP|PASSEOF)) && prv)
#endif
					{
						if (!(cur->flags & IN_newline))
						{
							cur->flags |= IN_newline;
							if ((pp.mode & (HOSTED|PEDANTIC)) == PEDANTIC && LASTCHR() != '\f' && LASTCHR() != CC_sub)
								error(1, "file does not end with %s", pptokchr('\n'));
							*(ip - 1) = c = '\n';
						}
						else
						{
							if (!(cur->flags & (IN_noguard|IN_tokens)) && cur->symbol)
								ppmultiple(ppsetfile(error_info.file), cur->symbol);
							if (cur->fd >= 0)
								close(cur->fd);
							if (pp.incref && !(pp.mode & INIT))
							{
								SYNCOUT();
								(*pp.incref)(error_info.file, cur->file, error_info.line - 1, PP_SYNC_POP);
								CACHEOUT();
							}
							goto fsm_pop;
						}
					}
					else
						c = EOF;
				}
				break;
			case IN_MACRO:
			case IN_MULTILINE:
#if !CPP
				if (!(st & PASSEOF))
#endif
#if COMPATIBLE
				if (prv && (!INMACRO(rp) || (st & (COMPATIBILITY|TRANSITION)) == COMPATIBILITY && ppismac(*prv->nextchr)))
#else
				if (prv && !INMACRO(rp))
#endif
				{
					if (cur->type == IN_MULTILINE)
					{
						while (pp.control-- != cur->control)
							error(2, "#%s on line %d has no #%s", dirname(IF), GETIFLINE(pp.control+1), dirname(ENDIF));
						free(cur->buffer);
						error_info.file = cur->file;
						error_info.line = cur->line;
						if (pp.linesync)
						{
							SYNCOUT();
							(*pp.linesync)(error_info.line, error_info.file);
							CACHEOUT();
						}
					}
					cur->symbol->flags &= ~SYM_DISABLED;
					if (cur->symbol->flags & SYM_FUNCTION)
						popframe(pp.macp);
					POP();
#if CPP
					if (!(st & COMPATIBILITY) && ppisidig(*(op - 1)) && ppisidig(*ip)) UNGETCHR(' ');
#endif
					bp = ip;
					goto fsm_get;
				}
				c = EOF;
				break;
			case IN_QUOTE:
				if (prv)
				{
					error_info.line = cur->line;
					st &= ~(ESCAPE|QUOTE);
					POP();
					c = '"';
				}
				else c = EOF;
				break;
			case IN_SQUOTE:
				if (prv)
				{
					error_info.line = cur->line;
					st &= ~(ESCAPE|SQUOTE);
					POP();
					c = '\'';
				}
				else c = EOF;
				break;
			case IN_STRING:
#if CPP
				if (prv)
#else
				if (!(st & PASSEOF) && !(cur->flags & IN_expand) && prv)
#endif
				{
					if (cur->flags & IN_disable) st |= DISABLE;
					else st &= ~DISABLE;
					POP();
					bp = ip;
					goto fsm_get;
				}
				c = EOF;
				break;
			default:
				c = EOF;
				break;
			}
		}
		bp = ip - 1;
		if (state = rp[c]) goto fsm_next;
		goto fsm_get;

#if !CPP
	case S_HUH:
		if (INOPSPACE(rp))
		{
			if (c == '=')
			{
#if PROTOTYPE
				if (pp.in->flags & IN_prototype) PUTCHR(c);
				else
				{
#endif
					while (*(op - 1) == ' ' || *(op - 1) == '\t') op--;
					PUTCHR(c);
					if (st & (STRICT|WARN)) error(1, "%-*.*s: space ignored in operator", op - tp, op - tp, tp);
#if PROTOTYPE
				}
#endif
				switch (*tp)
				{
				case '/':
					c = T_DIVEQ;
					break;
				case '%':
					c = T_MODEQ;
					break;
				case '&':
					c = T_ANDEQ;
					break;
				case '*':
					c = T_MPYEQ;
					break;
				case '+':
					c = T_ADDEQ;
					break;
				case '-':
					c = T_SUBEQ;
					break;
				case '^':
					c = T_XOREQ;
					break;
				case '|':
					c = T_OREQ;
					break;
				case '<':
					c = T_LSHIFTEQ;
					break;
				case '>':
					c = T_RSHIFTEQ;
					break;
				}
			}
			else
			{
				BACKIN();
				switch (c = *tp)
				{
				case '<':
					c = T_LSHIFT;
					break;
				case '>':
					c = T_RSHIFT;
					break;
				}
			}
		}
		else if (pp.level > 1 || (pp.option & PRESERVE)) PUTCHR(c);
		else if (tp == op)
		{
			if (pp.in->type != IN_BUFFER)
			{
				if (!(pp.option & ALLPOSSIBLE))
					error(1, "%s: invalid character ignored", pptokchr(c));
				goto fsm_top;
			}
			PUTCHR(c);
		}
		else if (*tp == ':')
		{
			PUTCHR(c);
			if (c == '=') error(2, "real programmers use =");
			else c = '+';
		}
		else
		{
			BACKIN();
			c = *tp;
		}
		break;
#endif

	case S_QUAL:
		if ((state = NEXT(state)) != LIT1)
		{
			rp = fsm[state];
			bp = ip;
#if CPP
			qual = 1;
#if COMPATIBLE
			if (!(st & COMPATIBILITY) || c != 'u' && c != 'U')
#endif
				PUTCHR(c);
#else
			switch (c)
			{
			case 'f':
			case 'F':
				qual |= N_FLOAT;
#if COMPATIBLE
				if (!(st & COMPATIBILITY))
#endif
				PUTCHR(c);
				break;
			case 'l':
			case 'L':
				qual |= N_LONG;
				PUTCHR(c);
				break;
			case 'u':
			case 'U':
				qual |= N_UNSIGNED;
#if COMPATIBLE
				if (!(st & COMPATIBILITY))
#endif
				PUTCHR(c);
				break;
			default:
				PUTCHR(c);
				break;
			}
#endif
			goto fsm_get;
		}
#if !CPP
		qual |= N_WIDE;
		if (DOSTRIP()) BACKOUT();
#endif
		/*FALLTHROUGH*/

	case S_LITBEG:
#if CPP
		quot = c;
		rp = fsm[LIT1];
		if (op == tp)
		{
			PPSYNCLINE();
			tp = op;
		}
#else
		if ((quot = c) == '<')
		{
			if (!(st & HEADER) || (pp.option & (HEADEREXPAND|HEADEREXPANDALL)) && pp.in->type != IN_FILE && pp.in->type != IN_BUFFER && pp.in->type != IN_INIT && pp.in->type != IN_RESCAN)
			{
				PUTCHR(c);
				bp = ip;
				rp = fsm[LT1];
				goto fsm_get;
			}
			quot = '>';
			rp = fsm[HDR1];
		}
		else rp = fsm[LIT1];
		if (!DOSTRIP())
#endif
		PUTCHR(c);
		bp = ip;
		goto fsm_get;

	case S_LITEND:
		n = 1;
		if (c != quot)
		{
			if (c != '\n' && c != EOF)
			{
				if (st & (QUOTE|SQUOTE))
				{
					if (!(st & ESCAPE))
					{
						st |= ESCAPE;
						quotquot = c;
					}
					else if (c == quotquot) st &= ~ESCAPE;
				}
				PUTCHR(c);
				bp = ip;
				goto fsm_get;
			}
#if CPP
			if ((st & PASSTHROUGH) || (pp.option & PRESERVE))
			{
				if (c == '\n') goto fsm_newline;
				bp = ip;
				goto fsm_start;
			}
#endif
			m = (st & SKIPCONTROL) && (pp.mode & HOSTED) ? -1 : 1;
			if (c == '\n' && quot == '\'' && (pp.option & STRINGSPAN)) n = 0;
			else
#if COMPATIBLE && !CPP
			if ((st & (COMPATIBILITY|DEFINITION)) != (COMPATIBILITY|DEFINITION))
#endif
			{
				switch (quot)
				{
				case '"':
					if (c == '\n')
					{
						if (!(pp.option & STRINGSPAN) || (st & (COMPATIBILITY|STRICT)) == STRICT)
							error(m, "%s in string", pptokchr(c));
						error_info.line++;
						if (!(pp.option & STRINGSPAN))
						{
							PUTCHR('\\');
							c = 'n';
						}
						else if (pp.option & STRINGSPLIT)
						{
							PUTCHR('\\');
							PUTCHR('n');
							PUTCHR('"');
							PUTCHR('\n');
							c = '"';
						}
						PUTCHR(c);
						bp = ip;
						goto fsm_get;
					}
					error(m, "%s in string", pptokchr(c));
					c = '\n';
					break;
				case '\'':
					if (!(st & DIRECTIVE) || !(pp.mode & (HOSTED|RELAX)))
						error(m, "%s in character constant", pptokchr(c));
					break;
				case '>':
					error(m, "%s in header constant", pptokchr(c));
					break;
				default:
					error(m, "%s in %c quote", pptokchr(c), quot);
					break;
				}
#if !CPP
				if (!DOSTRIP())
#endif
				PUTCHR(quot);
			}
			if (c == '\n')
			{
				UNGETCHR(c);
				c = quot;
			}
		}
		else if (st & (SQUOTE|QUOTE))
		{
			if (!(st & ESCAPE))
			{
				st |= ESCAPE;
				quotquot = c;
			}
			else if (c == quotquot) st &= ~ESCAPE;
			PUTCHR('\\');
			PUTCHR(c);
			bp = ip;
			goto fsm_get;
		}
#if CPP
		else PUTCHR(c);
#else
		else if (!DOSTRIP()) PUTCHR(c);
#endif
#if CATSTRINGS
#if CPP
		if (c == '"' && !(st & (COLLECTING|NOTEXT|PASSTHROUGH|SKIPCONTROL)) && (pp.mode & CATLITERAL))
#else
		if (c == '"' && pp.level == 1 && !(st & (COLLECTING|JOINING|NOTEXT|SKIPCONTROL)) && (pp.mode & CATLITERAL))
#endif
		{
			char*	pptoken;
			long	ppstate;

			pptoken = pp.token;
			pp.token = pp.catbuf;
			*pp.token++ = 0;
			ppstate = (st & STRIP);
			if (DOSTRIP())
				ppstate |= ADD|QUOTE;
			st |= JOINING;
			st &= ~(NEWLINE|STRIP);

			/*
			 * revert to the top level since string
			 * concatenation crosses file boundaries
			 * (allowing intervening directives)
			 */

			pp.level = 0;
			SYNCIN();
			m = n = 0;
			for (;;)
			{
				switch (c = pplex())
				{
				case '\n':
					m++;
					continue;
				case ' ':
					*pp.catbuf = ' ';
					continue;
				case T_WSTRING:
#if !CPP
					qual = N_WIDE;
#endif
					if (ppstate & ADD)
						ppstate &= ~ADD;
					else if (m == n || !(st & SPACEOUT))
						op--;
					else
					{
						n = m;
						*(op - 1) = '\\';
						*op++ = '\n';
					}
					STRCOPY(op, pp.token + 2 + (*pp.token == ' '), s);
					continue;
				case T_STRING:
					if (ppstate & ADD)
						ppstate &= ~ADD;
					else if (m == n || !(st & SPACEOUT))
						op--;
					else
					{
						n = m;
						*(op - 1) = '\\';
						*op++ = '\n';
					}
					STRCOPY(op, pp.token + 1 + (*pp.token == ' '), s);
					continue;
				case 0:
					m = error_info.line ? (error_info.line - 1) : 0;
					*pp.token = 0;
					/*FALLTHROUGH*/
				default:
					if (m)
					{
						if (--m)
						{
							pp.state |= HIDDEN|SYNCLINE;
							pp.hidden += m;
						}
#if COMPATIBLE
						if ((st & COMPATIBILITY) && c == '#' && *(pp.token - 1))
						{
							*(pp.token + 3) = *(pp.token + 2);
							*(pp.token + 2) = *(pp.token + 1);
							*(pp.token + 1) = *pp.token;
							*pp.token = *(pp.token - 1);
						}
						error_info.line--;
						*--pp.token = '\n';
#endif
					}
					else if (*(pp.token - 1))
						pp.token--;
					if (ppisidig(*pp.token))
						*op++ = ' ';
					if (pp.in->type == IN_MACRO && (s = strchr(pp.token, MARK)) && !*(s + 1))
					{
						*(s + 1) = MARK;
						*(s + 2) = 0;
					}
					PUSH_STRING(pp.token);
					pp.state &= ~(JOINING|NEWLINE);
					pp.state |= ppstate & ~(ADD|QUOTE);
					if ((ppstate & (ADD|QUOTE)) == QUOTE)
						op--;
					break;
				}
				break;
			}
			pp.token = pptoken;
			CACHEIN();
			pp.level = 1;
#if !CPP
			c = T_STRING | qual;
			break;
#endif
		}
#endif
#if CPP
		if (n && !(st & (PASSTHROUGH|SKIPCONTROL|NOTEXT)) && c == '\'' && (op - tp) <= 2 && !(pp.mode & (HOSTED|RELAX)))
			error(1, "empty character constant");
		if (pp.option & PRESERVE)
			st &= ~ESCAPE;
		else
			st &= ~(ESCAPE|NEWLINE);
		pp.in->flags |= IN_tokens;
		count(token);
		goto fsm_start;
#else
		st &= ~ESCAPE;
		switch (quot)
		{
		case '\'':
			if (n && !(st & NOTEXT) && (op - tp) <= (DOSTRIP() ? 0 : 2) && !(pp.mode & (HOSTED|RELAX)))
				error(1, "empty character constant");
			c = T_CHARCONST | qual;
			break;
		case '>':
			c = T_HEADER;
			break;
		default:
			if (c == quot)
				c = T_STRING | qual;
			break;
		}
		break;
#endif

	case S_LITESC:
		if (st & (COLLECTING|DIRECTIVE|QUOTE|SQUOTE))
		{
			if (st & ESCAPE)
			{
				PUTCHR('\\');
				if (c == quot) PUTCHR('\\');
			}
			PUTCHR(c);
		}
#if CPP
		else if (st & PASSTHROUGH) PUTCHR(c);
#endif
		else if (pp.option & PRESERVE) PUTCHR(c);
		else switch (c)
		{
		case 'b':
		case 'f':
		case 'n':
		case 'r':
		case 't':
		case '\\':
		case '\'':
		case '"':
		case '?':
			PUTCHR(c);
			break;
#if COMPATIBLE
		case '8':
		case '9':
			if (!(st & COMPATIBILITY)) goto unknown;
			if (st & STRICT) error(1, "%c: invalid character in octal character escape", c);
			/*FALLTHROUGH*/
#endif
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
			n = c - '0';
			for (m = 0; m < 2; m++)
			{
				GET(c, c, tp, xp);
				switch (c)
				{
#if COMPATIBLE
				case '8':
				case '9':
					if (!(st & COMPATIBILITY))
					{
						UNGETCHR(c);
						break;
					}
					if (st & STRICT) error(1, "%c: invalid character in octal character escape", c);
					/*FALLTHROUGH*/
#endif
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
					n = (n << 3) + c - '0';
					continue;
				default:
					UNGETCHR(c);
					break;
				}
				break;
			}
			if (n & ~0777) error(1, "octal character constant too large");
			goto octal;
		case 'a':
			if (pp.option & MODERN)
			{
				PUTCHR(c);
				break;
			}
#if COMPATIBLE
			if (st & COMPATIBILITY) goto unknown;
#endif
			n = CC_bel;
			goto octal;
		case 'v':
			if (pp.option & MODERN)
			{
				PUTCHR(c);
				break;
			}
			n = CC_vt;
			goto octal;
		case 'E':
			if (st & (COMPATIBILITY|STRICT)) goto unknown;
			n = CC_esc;
			goto octal;
		case 'x':
#if COMPATIBLE
			if (st & COMPATIBILITY) goto unknown;
#endif
			n = 0;
			for (m = 0; m < 3; m++)
			{
				GET(c, c, tp, xp);
				switch (c)
				{
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					n = (n << 4) + c - '0';
					continue;
				case 'a':
				case 'b':
				case 'c':
				case 'd':
				case 'e':
				case 'f':
					n = (n << 4) + c - 'a' + 10;
					continue;
				case 'A':
				case 'B':
				case 'C':
				case 'D':
				case 'E':
				case 'F':
					n = (n << 4) + c - 'A' + 10;
					continue;
				default:
					if (!m) error(1, "\\x%c: invalid character in hexadecimal character constant", c);
					UNGETCHR(c);
					break;
				}
				break;
			}
			if (n & ~0777) error(1, "hexadecimal character constant too large");
		octal:
			PUTCHR(((n >> 6) & 07) + '0');
			PUTCHR(((n >> 3) & 07) + '0');
			PUTCHR((n & 07) + '0');
			break;
		default:
		unknown:
			if (st & (STRICT|WARN)) error(1, "\\%c: non-standard character constant", c);
			PUTCHR(c);
			break;
		}
		state = LIT1;
		goto fsm_begin;

	case S_MACRO:
		BACKIN();
#if CPP
		if (st & (DISABLE|SKIPCONTROL|SKIPMACRO))
		{
			if (st & SKIPMACRO)
				pp.mode |= MARKMACRO;
			st &= ~(NEWLINE|SKIPMACRO);
			pp.in->flags |= IN_tokens;
			count(token);
			goto fsm_start;
		}
		count(candidate);
		SETCHR(0);
		switch (state = INDEX(rp))
		{
		case HIT0:
			tp = op - 1;
			break;
		case HITN:
			bp = tp;
			tp = op - ((pp.truncate && pp.truncate < (HITN - HIT0)) ? (pp.truncate - 1) : (HITN - HIT0));
			while (tp > bp && ppisidig(*(tp - 1))) tp--;
			break;
		default:
			bp = tp;
			if ((tp = op - (state - HIT0)) > bp && *(tp - 1) == 'L') tp--;
			break;
		}
		if (sym = ppsymref(pp.symtab, tp))
		{
			SYNCIN();
			n = ppcall(sym, 0);
			CACHEIN();
			if (n >= 0)
			{
				BACKOUT();
				if (!n)
				{
					if (sp) op = sp;
					else
					{
						s = ip;
						ip = sym->macro->value;
						c = sym->macro->size;
						while (c > 0)
						{
							if (op + c < xp + PPBUFSIZ) n = c;
							else n = xp + PPBUFSIZ - op;
							MEMCPY(op, ip, n);
							c -= n;
							PPCHECKOUT();
						}
						ip = s;
					}
				}
				else if ((sym->flags & SYM_MULTILINE) && pp.linesync)
				{
					SYNCOUT();
					if (!(state & NEWLINE))
						ppputchar('\n');
					(*pp.linesync)(error_info.line, error_info.file);
					CACHEOUT();
				}
			}
		}
		pp.in->flags |= IN_tokens;
		goto fsm_start;
#else
		if (st & (COLLECTING|DEFINITION|DISABLE|SKIPCONTROL|SKIPMACRO))
		{
			if (st & SKIPMACRO)
				pp.mode |= MARKMACRO;
			st &= ~(NEWLINE|NOEXPAND|SKIPMACRO);
			c = T_ID;
			if (pp.level == 1)
			{
				pp.in->flags |= IN_tokens;
				if (st & NOTEXT)
				{
					BACKOUT();
					goto fsm_top;
				}
				if (st & COMPILE)
				{
					SETCHR(0);
					if (pp.truncate && (op - tp) > pp.truncate) tp[pp.truncate] = 0;
					sym = (pp.option & NOHASH) ? ppsymref(pp.symtab, tp) : ppsymset(pp.symtab, tp);
 fsm_noise:
					if (pp.symbol = sym)
					{
						if ((sym->flags & SYM_KEYWORD) && (!pp.truncate || (op - tp) <= pp.truncate || (tp[pp.truncate] = '_', tp[pp.truncate + 1] = 0, pp.symbol = sym = (pp.option & NOHASH) ? ppsymref(pp.symtab, tp) : ppsymset(pp.symtab, tp), 0)))
						{
							c = ((struct ppsymkey*)sym)->lex;
							/*UNDENT*/

#define ADVANCE()	do{if(pp.toknxt<op)pp.token=pp.toknxt;}while(0)

#define NOISE_BRACE		01
#define NOISE_NOSPACEOUT	02
#define NOISE_PAREN		04

	if ((pp.option & NOISE) && ppisnoise(c))
	{
		if (c != T_NOISE)
		{
			int		p;
			int		f;
			char*		pptoken;
			PPCOMMENT	ppcomment;

			SYNCIN();
			pp.toknxt = op;
			f = 0;
			if (!(pp.state & SPACEOUT))
			{
				pp.state |= SPACEOUT;
				f |= NOISE_NOSPACEOUT;
			}
			ppcomment = pp.comment;
			pp.comment = 0;
			op = (pptoken = tp) + MAXTOKEN;
			switch (c)
			{
			case T_X_GROUP:
				m = p = 0;
				quot = 1;
				for (;;)
				{
					ADVANCE();
					switch (c = pplex())
					{
					case '(':
					case '{':
						if (!p)
						{
							if (c == '(')
							{
								if (f & NOISE_PAREN)
								{
									ungetchr(c);
									*--pp.toknxt = 0;
									break;
								}
								f |= NOISE_PAREN;
								p = ')';
							}
							else
							{
								f |= NOISE_BRACE|NOISE_PAREN;
								p = '}';
							}
							n = 1;
							m = c;
						}
						else if (c == m) n++;
						quot = 0;
						continue;
					case ')':
					case '}':
						if (c == p && --n <= 0)
						{
							if (c == '}') break;
							m = '\n';
							p = 0;
						}
						quot = 0;
						continue;
					case ' ':
						continue;
					case '\n':
						error_info.line++;
						if (!m) m = '\n';
						continue;
					case 0:
						break;
					case T_ID:
						if (quot) continue;
						/*FALLTHROUGH*/
					default:
						if (m == '\n')
						{
							/*
							 * NOTE: token expanded again
							 */

							s = pp.toknxt;
							while (s > pp.token) ungetchr(*--s);
							*(pp.toknxt = s) = 0;
							break;
						}
						continue;
					}
					break;
				}
				break;
			case T_X_LINE:
				for (;;)
				{
					ADVANCE();
					switch (pplex())
					{
					case 0:
						break;
					case '\n':
						error_info.line++;
						break;
					default:
						continue;
					}
					break;
				}
				break;
			case T_X_STATEMENT:
				for (;;)
				{
					ADVANCE();
					switch (pplex())
					{
					case 0:
						break;
					case ';':
						ungetchr(';');
						*(pp.toknxt = pp.token) = 0;
						break;
					default:
						continue;
					}
					break;
				}
				break;
			}
			pp.comment = ppcomment;
			if (f & NOISE_NOSPACEOUT)
				pp.state &= ~SPACEOUT;
			CACHEIN();
			tp = pptoken;
			op = pp.toknxt;
			c = T_NOISES;
		}
		if (pp.option & NOISEFILTER)
		{
			BACKOUT();
			goto fsm_top;
		}
	}

							/*INDENT*/
						}
						else if ((pp.option & NOISE) && c == T_ID && strneq(tp, "__builtin_", 10))
						{
							hashlook(pp.symtab, tp, HASH_DELETE, NiL);
							pp.symbol = sym = (struct ppsymbol*)ppkeyset(pp.symtab, tp);
							sym->flags |= SYM_KEYWORD;
							c = ((struct ppsymkey*)sym)->lex = T_BUILTIN;
						}
					}
				}
				goto fsm_symbol;
			}
			goto fsm_check;
		}
		if (pp.level == 1)
		{
			st &= ~(NEWLINE|PASSEOF);
			pp.in->flags |= IN_tokens;
		}
		else st &= ~PASSEOF;
		count(candidate);
		SETCHR(0);
		if (sym = ppsymref(pp.symtab, tp))
		{
			SYNCIN();
			c = ppcall(sym, 1);
			CACHEIN();
			if (c >= 0)
			{
				BACKOUT();
				if ((sym->flags & SYM_MULTILINE) && pp.linesync)
				{
					SYNCOUT();
					(*pp.linesync)(error_info.line, error_info.file);
					CACHEOUT();
				}
				goto fsm_top;
			}
		}
		c = T_ID;
		if (pp.level == 1)
		{
			if (st & NOTEXT)
			{
				BACKOUT();
				goto fsm_top;
			}
			if (st & COMPILE)
			{
				if (pp.truncate && (op - tp) > pp.truncate)
				{
					tp[pp.truncate] = 0;
					sym = 0;
				}
				if (!sym)
				{
					if (!(pp.option & NOHASH)) sym = ppsymset(pp.symtab, tp);
					else if (!(sym = ppsymref(pp.symtab, tp))) goto fsm_symbol;
				}
				goto fsm_noise;
			}
			goto fsm_symbol;
		}
		goto fsm_check;
#endif

	case S_SHARP:
		if (c == '(')
		{
			pp.in->flags |= IN_tokens;
			if ((st & STRICT) && pp.in->type != IN_MACRO && pp.in->type != IN_MULTILINE)
			{
				if (!(pp.mode & HOSTED)) error(1, "non-standard reference to #(...)");
				if (st & STRICT)
				{
					PUTCHR(c);
#if CPP
					st &= ~NEWLINE;
					count(token);
					goto fsm_start;
#else
					break;
#endif
				}
			}
			if (st & (COLLECTING|DEFINITION|DISABLE|SKIPCONTROL))
			{
				PUTCHR(c);
#if CPP
				st &= ~NEWLINE;
				count(token);
				goto fsm_start;
#else
				st &= ~NOEXPAND;
				break;
#endif
			}
			op--;
			SYNC();
			ppbuiltin();
			CACHE();
#if CPP
			count(token);
			goto fsm_start;
#else
			goto fsm_top;
#endif
		}
		BACKIN();
#if CPP
		if (!(st & NEWLINE) || !(pp.in->type & IN_TOP))
		{
 fsm_nondirective:
			st &= ~NEWLINE;
			pp.in->flags |= IN_tokens;
			count(token);
			goto fsm_start;
		}
		if (*(s = tp) != '#')
		{
#if COMPATIBLE
			if ((st & (COMPATIBILITY|TRANSITION)) == COMPATIBILITY) goto fsm_nondirective;
#endif
			while (*s == ' ' || *s == '\t') s++;
			if (*s != '#') goto fsm_nondirective;
		}
		BACKOUT();
#else
		if (!(st & NEWLINE) || (st & DEFINITION) || !(pp.in->type & IN_TOP))
		{
			if (c == '#')
			{
				SKIPIN();
				if (!(st & DEFINITION))
					PUTCHR(c);
				c = T_TOKCAT;
			}
			else if (pp.level == 1 && !(st & (JOINING|SPACEOUT)) && !(pp.option & PRESERVE))
			{
				char*		pptoken;
				char*		oop;
				PPCOMMENT	ppcomment;

				SYNCIN();
				pp.toknxt = oop = op;
				pp.state |= SPACEOUT;
				ppcomment = pp.comment;
				pp.comment = 0;
				op = (pptoken = tp) + MAXTOKEN;
				for (;;)
				{
					ADVANCE();
					switch (pplex())
					{
					case 0:
						break;
					case '\n':
						error_info.line++;
						break;
					default:
						continue;
					}
					break;
				}
				pp.comment = ppcomment;
				pp.state &= ~SPACEOUT;
				CACHEIN();
				tp = pptoken;
				*--op = 0;
				op = oop;
				if (pp.pragma && !(st & NOTEXT))
				{
					*s = 0;
					SYNC();
					(*pp.pragma)(NiL, NiL, NiL, tp, 1);
					CACHE();
				}
				if (!c) BACKIN();
				goto fsm_top;
			}
			else c = '#';
			break;
		}
		if ((st & (COLLECTING|STRICT)) == (COLLECTING|STRICT))
			error(1, "directives in macro call arguments are not portable");
#endif
		if (c == '#' && pp.in->type == IN_RESCAN)
		{
			/*
			 * pass line to pp.pragma VERBATIM
			 */
			
			SKIPIN();
			s = pp.valbuf;
			while ((c = GETCHR()) && c != '\n')
				if ((*s++ = c) == MARK) SKIPIN();
			if (pp.pragma && !(st & NOTEXT))
			{
				*s = 0;
				SYNC();
				(*pp.pragma)(NiL, NiL, NiL, pp.valbuf, 1);
				CACHE();
			}
			if (!c) BACKIN();
#if CPP
			goto fsm_start;
#else
			goto fsm_top;
#endif
		}
		SYNC();
		ppcontrol();
		CACHE();
#if CPP
		if (st & (NOTEXT|SKIPCONTROL))
		{
			if (!sp)
			{
				PPCHECKOUTTP();
				sp = tp;
			}
		}
		else if (sp)
		{
			tp = op = sp;
			sp = 0;
		}
		goto fsm_start;
#else
		goto fsm_top;
#endif

	case S_NL:
#if CPP
		if (op == tp && !(st & JOINING) && pp.in->type == IN_FILE && !(pp.option & PRESERVE))
		{
			st |= NEWLINE|HIDDEN;
			pp.hidden++;
			error_info.line++;
			goto fsm_start;
		}
#endif
 fsm_newline:
#if CPP
		if (sp)
			op = sp;
		else if (!(pp.in->flags & IN_noguard))
		{
			while (tp < op)
				if ((c = *tp++) != ' ' && c != '\t')
				{
					pp.in->flags |= IN_tokens;
					break;
				}
			c = '\n';
		}
		st |= NEWLINE;
		error_info.line++;
		if (*ip == '\n' && *(ip + 1) != '\n' && !pp.macref && !(st & (ADD|HIDDEN)))
		{
			ip++;
			PUTCHR('\n');
			error_info.line++;
		}
		if ((st & NOTEXT) && ((pp.mode & FILEDEPS) || (pp.option & (DEFINITIONS|PREDEFINITIONS))))
			BACKOUT();
		else
		{
			debug((-5, "token[%d] %03o = %s [line=%d]", pp.level, c, pptokchr(c), error_info.line));
			PUTCHR('\n');
			PPSYNCLINE();
			if (sp)
			{
				PPCHECKOUT();
				sp = op;
			}
		}
		goto fsm_start;
#else
		st |= NEWLINE;
		if (pp.level == 1)
		{
			error_info.line++;
			if (!(st & (JOINING|SPACEOUT)))
			{
				debug((-5, "token[%d] %03o = %s [line=%d]", pp.level, c, pptokchr(c), error_info.line));
				BACKOUT();
				goto fsm_top;
			}
		}
		BACKOUT();
		if (st & SKIPCONTROL)
		{
			error_info.line++;
			st |= HIDDEN;
			pp.hidden++;
			goto fsm_start;
		}
		PUTCHR(c = '\n');
		goto fsm_return;
#endif

#if !CPP
	case S_TOK:
		PUTCHR(c);
		c = TYPE(state) | qual;
		break;

	case S_TOKB:
		BACKIN();
		c = TYPE(state) | qual;
		break;
#endif

	case S_VS:
		PUTCHR(c);
#if !CPP
		if (st & NOVERTICAL)
		{
			error(1, "%s invalid in directives", pptokchr(c));
			st &= ~NOVERTICAL;
		}
#endif
#if COMPATIBLE
		if (st & COMPATIBILITY) st |= NEWLINE;
#endif
#if CPP
		if (!(pp.in->flags & IN_noguard))
			while (tp < op)
				if ((c = *tp++) != ' ' && c != '\t')
				{
					pp.in->flags |= IN_tokens;
					break;
				}
		goto fsm_start;
#else
		bp = ip;
		rp = fsm[WS1];
		goto fsm_get;
#endif

#if !CPP
	case S_WS:
#if COMPATIBLE
		if ((st & (COMPATIBILITY|TRANSITION)) == COMPATIBILITY) st &= ~NEWLINE;
#endif
		if (pp.level == 1)
		{
			if ((st & (COMPATIBILITY|SPACEOUT)) && !(st & TRANSITION))
			{
				if (st & (COMPILE|NOTEXT))
				{
#if CATSTRINGS
					if ((st & (JOINING|NOTEXT|SPACEOUT)) != SPACEOUT)
#else
					if ((st & (NOTEXT|SPACEOUT)) != SPACEOUT)
#endif
					{
						BACKOUT();
						bp = ip - 1;
						rp = fsm[START];
						if (state = rp[c]) goto fsm_next;
						goto fsm_get;
					}
				}
				else
#if CATSTRINGS
				if (!(st & JOINING))
#endif
				{
					tp = op;
					bp = ip - 1;
					rp = fsm[START];
					if (state = rp[c]) goto fsm_next;
					goto fsm_get;
				}
				BACKIN();
				c = ' ';
				goto fsm_return;
			}
			BACKOUT();
			bp = ip - 1;
			rp = fsm[START];
			if (state = rp[c]) goto fsm_next;
			goto fsm_get;
		}
		if (st & (NOSPACE|SKIPCONTROL))
		{
			BACKOUT();
			bp = ip - 1;
			rp = fsm[START];
			if (state = rp[c]) goto fsm_next;
			goto fsm_get;
		}
		if (c != '\n')
		{
			BACKIN();
			c = ' ';
		}
		if (!(pp.option & PRESERVE))
		{
			BACKOUT();
			PUTCHR(c);
		}
		goto fsm_return;
#endif

	default:
		if (state & SPLICE)
		{
			switch (c)
			{
			case MARK:
				/*
				 * internal mark
				 */

				switch (pp.in->type)
				{
				case IN_BUFFER:
				case IN_FILE:
#if !CPP
				case IN_INIT:
#if CATSTRINGS
					if ((st & JOINING) && (!INQUOTE(rp) || quot != '"') || pp.level > 1 && (rp == fsm[START] || INQUOTE(rp)))
#else
					if (pp.level > 1 && (rp == fsm[START] || INQUOTE(rp)))
#endif
						PUTCHR(c);
#endif
					break;
				default:
					switch (GETCHR())
					{
					case 'A':
						if (!(st & (DEFINITION|DISABLE)))
						{
							c = GETCHR();
							SYNCIN();
							if (pp.macp->arg[c - ARGOFFSET][-1])
								PUSH_EXPAND(pp.macp->arg[c - ARGOFFSET], pp.macp->line);
							else
								PUSH_COPY(pp.macp->arg[c - ARGOFFSET], pp.macp->line);
							CACHEIN();
							bp = ip;
							goto fsm_get;
						}
						/*FALLTHROUGH*/
					case 'C':
						c = GETCHR() - ARGOFFSET;
						if (!*(s = pp.macp->arg[c]) && (pp.in->symbol->flags & SYM_VARIADIC) && pp.in->symbol->macro->arity == (c + 1))
						{
							s = ip - 3;
							while (--op > tp && --s > bp && ppisidig(*s));
						}
						else
						{
							SYNCIN();
							PUSH_COPY(s, pp.macp->line);
							CACHEIN();
						}
						bp = ip;
						goto fsm_get;
					case 'F':
						error_info.file = (char*)strtoul(ip, &s, 16);
						debug((-6, "actual sync: file = \"%s\"", error_info.file));
						bp = ip = s + 1;
						goto fsm_get;
					case 'L':
						error_info.line = strtoul(ip, &s, 16);
						debug((-6, "actual sync: line = %d", error_info.line));
						bp = ip = s + 1;
						goto fsm_get;
					case 'Q':
						c = GETCHR();
						SYNCIN();
						PUSH_QUOTE(pp.macp->arg[c - ARGOFFSET], pp.macp->line);
						CACHEIN();
						bp = ip - 1;
						if (st & (COLLECTING|EOF2NL|JOINING)) rp = fsm[START];
						if (state = rp[c = '"']) goto fsm_next;
						goto fsm_get;
					case 'S':
						c = GETCHR();
						SYNCIN();
						PUSH_SQUOTE(pp.macp->arg[c - ARGOFFSET], pp.macp->line);
						CACHEIN();
						bp = ip - 1;
						if (st & COLLECTING) rp = fsm[START];
						if (state = rp[c = '\'']) goto fsm_next;
						goto fsm_get;
					case 'X':
						if (pp.in->type != IN_COPY)
							st |= SKIPMACRO;
						if (pp.level <= 1)
						{
							bp = ip;
							goto fsm_get;
						}
						if (pp.in->type == IN_EXPAND)
						{
							st &= ~SKIPMACRO;
							PUTCHR(c);
							PUTCHR('X');
						}
						c = GETCHR();
						break;
					case 0:
						if ((state &= ~SPLICE) >= TERMINAL) goto fsm_terminal;
						goto fsm_begin;
					default:
#if DEBUG
						error(PANIC, "invalid mark op `%c'", LASTCHR());
						/*FALLTHROUGH*/
					case MARK:
#endif
#if CATSTRINGS
						if ((st & (JOINING|QUOTE)) == JOINING)
						{
							if (!INQUOTE(rp))
								PUTCHR(c);
						}
						else
#endif
#if CPP
						if (rp != fsm[START] && !INQUOTE(rp))
							UNGETCHR(c);
#else
						if (rp != fsm[START] && !INQUOTE(rp))
							UNGETCHR(c);
						else if (pp.level > 1)
							PUTCHR(c);
#endif
						break;
					}
					break;
				}
				break;
			case '?':
				/*
				 * trigraph
				 */

				if (pp.in->type == IN_FILE)
				{
					GET(c, n, tp, xp);
					if (n == '?')
					{
						GET(c, n, tp, xp);
						if (c = trigraph[n])
						{
							if ((st & WARN) && (st & (COMPATIBILITY|TRANSITION)) && !(pp.mode & HOSTED) && !INCOMMENT(rp))
								error(1, "trigraph conversion %c%c%c -> %c%s", '?', '?', n, c, (st & TRANSITION) ? "" : " inhibited");
#if COMPATIBLE
							if ((st & (COMPATIBILITY|TRANSITION)) != COMPATIBILITY)
							{
#endif
							*(bp = ip - 1) = c;
							if (state = rp[c]) goto fsm_next;
							goto fsm_get;
#if COMPATIBLE
							}
#endif
						}
						if (n != EOB) BACKIN();
						UNGETCHR(c = '?');
					}
					else if (n != EOB) BACKIN();
				}
				break;
			case '%':
			case '<':
			case ':':
				/*
				 * digraph = --trigraph
				 */

				if (pp.in->type == IN_FILE && (pp.option & PLUSPLUS))
				{
					m = 0;
					GET(c, n, tp, xp);
					switch (n)
					{
					case '%':
						if (c == '<') m = '{';
						break;
					case '>':
						if (c == '%') m = '}';
						else if (c == ':') m = ']';
						break;
					case ':':
						if (c == '%') m = '#';
						else if (c == '<') m = '[';
						break;
					}
					if (m)
					{
						if ((st & WARN) && (st & (COMPATIBILITY|TRANSITION)) && !(pp.mode & HOSTED) && !INCOMMENT(rp))
							error(1, "digraph conversion %c%c -> %c%s", c, n, m, (st & TRANSITION) ? "" : " inhibited");
#if COMPATIBLE
						if ((st & (COMPATIBILITY|TRANSITION)) != COMPATIBILITY)
						{
#endif
						*(bp = ip - 1) = c = m;
						if (state = rp[c]) goto fsm_next;
						goto fsm_get;
#if COMPATIBLE
						}
#endif
					}
					if (n != EOB) BACKIN();
				}
				break;
			case '\\':
				/*
				 * line splice
				 */

				if (pp.in->type == IN_FILE && (!(pp.option & PLUSSPLICE) || !INCOMMENTXX(rp)))
				{
					m = 0;
					GET(c, n, tp, xp);
					if ((pp.option & SPLICESPACE) && !INQUOTE(rp))
						while (n == ' ')
						{
							GET(c, n, tp, xp);
							m = 1;
						}
					if (n == '\r')
					{
						GET(c, n, tp, xp);
						if (n != '\n' && n != EOB)
							BACKIN();
					}
					if (n == '\n')
					{
#if CPP
						if (INQUOTE(rp))
						{
							if ((pp.option & STRINGSPLIT) && quot == '"')
							{
								PUTCHR(quot);
								PUTCHR(n);
								PUTCHR(quot);
							}
							else if (*pp.lineid)
							{
								PUTCHR(c);
								PUTCHR(n);
							}
							else
							{
								st |= HIDDEN;
								pp.hidden++;
							}
						}
						else
#else
#if COMPATIBLE
						if (!INQUOTE(rp) && (st & (COMPATIBILITY|DEFINITION|TRANSITION)) == (COMPATIBILITY|DEFINITION))
						{
							if (op == tp)
							{
								st |= HIDDEN;
								pp.hidden++;
								error_info.line++;
								if (st & SPACEOUT)
									goto fsm_start;
								c = (pp.option & SPLICECAT) ? '\t' : ' ';
								PUTCHR(c);
								goto fsm_check;
							}
							UNGETCHR(n);
							state &= ~SPLICE;
							goto fsm_terminal;
						}
#endif
#endif
						{
							st |= HIDDEN;
							pp.hidden++;
						}
#if CPP
						spliced++;
#else
						error_info.line++;
#endif
						bp = ip;
						goto fsm_get;
					}
					else if ((n == 'u' || n == 'U') && !INQUOTE(rp))
					{
						PUTCHR(c);
						PUTCHR(n);
						bp = ip;
						goto fsm_get;
					}
#if COMPATIBLE
					else if ((st & (COMPATIBILITY|TRANSITION)) == COMPATIBILITY && (n == '"' || n == '\'') && !INQUOTE(rp))
					{
						PUTCHR(c);
						PUTCHR(n);
						bp = ip;
						goto fsm_get;
					}
#endif
					else if (n != EOB)
						BACKIN();
					if (m && INSPACE(rp))
						UNGETCHR(c);
				}
#if COMPATIBLE
				else if ((st & (COMPATIBILITY|TRANSITION)) == COMPATIBILITY && !INQUOTE(rp))
				{
					GET(c, n, tp, xp);
					if (n == '"' || n == '\'')
					{
						PUTCHR(c);
						PUTCHR(n);
						bp = ip;
						goto fsm_get;
					}
					if (n != EOB)
						BACKIN();
				}
#endif
				break;
			case '\r':
				/*
				 * barf
				 */

				if (pp.in->type == IN_FILE)
				{
					GET(c, n, tp, xp);
					if (n == '\n')
					{
						*(bp = ip - 1) = c = n;
						if (state = rp[c]) goto fsm_next;
						goto fsm_get;
					}
					if (n != EOB) BACKIN();
				}
				break;
			case CC_sub:
				/*
				 * barf & puke
				 */

				if ((pp.option & ZEOF) && pp.in->type == IN_FILE)
				{
					pp.in->flags |= IN_eof;
					c = 0;
					state = S_EOB;
					goto fsm_terminal;
				}
				break;
			}
			if ((state &= ~SPLICE) >= TERMINAL)
				goto fsm_terminal;
			PUTCHR(c);
			goto fsm_begin;
		}
#if CPP
		if (INOPSPACE(rp))
		{
			BACKIN();
			goto fsm_start;
		}
#endif
		PUTCHR(c);
		bp = ip;
		goto fsm_get;
	}
#if !CPP
 fsm_token:
	st &= ~NEWLINE;
	if (pp.level == 1)
	{
		pp.in->flags |= IN_tokens;
		if (st & NOTEXT)
		{
			BACKOUT();
			goto fsm_top;
		}
 fsm_symbol:
		count(token);
	}
 fsm_check:
	if (st & SKIPCONTROL)
	{
		BACKOUT();
		goto fsm_start;
	}
 fsm_return:
#if CPP
	error_info.line += spliced;
#endif
	SETCHR(0);
	debug((-5, "token[%d] %03o = %s", pp.level, c, pptokstr(tp, 0)));
	SYNC();
	pp.level--;
	error_info.indent--;
	return c;
#endif
}

#if CPP && POOL

#include <ls.h>
#include <wait.h>

/*
 * output pool status on exit
 */

static void
poolstatus(void)
{
	error(ERROR_OUTPUT|0, pp.pool.output, "%d", error_info.errors != 0);
}

/*
 * loop on < input output >
 */

static void
pool(void)
{
	char*	ifile;
	char*	ofile;

	ppflushout();
	if (!sfnew(sfstdin, NiL, SF_UNBOUND, pp.pool.input, SF_READ))
		error(ERROR_SYSTEM|3, "cannot dup pool input");

	/*
	 * kick the -I cache
	 */

	ppsearch(".", T_STRING, SEARCH_EXISTS);

	/*
	 * loop on < input output >
	 */

	pp.pool.input = 0;
	while (ifile = sfgetr(sfstdin, '\n', 1))
	{
		if (!(ofile = strchr(ifile, ' ')))
			error(3, "%s: pool output file expected", ifile);
		*ofile++ = 0;
		waitpid(0, NiL, WNOHANG);
		switch (fork())
		{
		case -1:
			error(ERROR_SYSTEM|3, "cannot fork pool");
		case 0:
			atexit(poolstatus);
			error_info.errors = 0;
			error_info.warnings = 0;
			close(0);
			if (open(ifile, O_RDONLY))
				error(ERROR_SYSTEM|3, "%s: cannot read", ifile);
			close(1);
			if (open(ofile, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH) != 1)
				error(ERROR_SYSTEM|3, "%s: cannot create", ofile);
			pp.outfile = ofile;
			pathcanon(ifile, 0);
			ifile = ppsetfile(ifile)->name;
#if CHECKPOINT
			if (pp.mode & DUMP)
			{
				if (!pp.pragma)
					error(3, "#%s must be enabled for checkpoints", dirname(PRAGMA));
				(*pp.pragma)(dirname(PRAGMA), pp.pass, keyname(X_CHECKPOINT), pp.checkpoint, 1);
			}
#endif
			PUSH_FILE(ifile, 0);
			return;
		}
	}
	while (wait(NiL) != -1);
}

#endif
