/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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
#include	"sfhdr.h"

/*	The main engine for reading formatted data
**
**	Written by Kiem-Phong Vo.
*/

#define MAXWIDTH	(int)(((uint)~0)>>1)	/* max amount to scan	*/

/*
 * pull in a private strtold()
 */

#include "sfstrtof.h"

/* refresh stream buffer - taking care of unseekable/share streams too */
#if __STD_C
static void _sfbuf(Sfio_t* f, int* peek)
#else
static void _sfbuf(f, peek)
Sfio_t*	f;
int*	peek;
#endif
{
	if(f->next >= f->endb)
	{	if(*peek) 	/* try peeking for a share stream if possible */
		{	f->mode |= SF_RV;
			if(SFFILBUF(f,-1) > 0)
			{	f->mode |= SF_PEEK;
				return;
			}
			*peek = 0;	/* can't peek, back to normal reads */
		}
		(void)SFFILBUF(f,-1);
	}
}

/* buffer used during scanning of a double value or a multi-byte
   character. the fields mirror certain local variables in sfvscanf.  */
typedef struct _scan_s
{	int	error;	/* get set by _sfdscan if no value specified	*/
	int	inp;	/* last input character read			*/
	int	width;	/* field width					*/
	Sfio_t	*f;	/* stream being scanned				*/
	uchar	*d, *endd, *data;	/* local buffering system	*/
	int	peek;	/* != 0 if unseekable/share stream		*/
	int	n_input;/* number of input bytes processed		*/
} Scan_t;

/* ds != 0 for scanning double values */
#define SCinit(sc,ds)	((sc)->inp = (sc)->error = -1, (sc)->f = f, \
			 ((sc)->width = (ds) ? width : -1), \
			 (sc)->d = d, (sc)->endd = endd, (sc)->data = data, \
			 (sc)->peek = peek, (sc)->n_input = n_input)
#define SCend(sc,ds)	(inp = (sc)->inp, f = (sc)->f, \
			 (width = (ds) ? (sc)->width : width), \
			 d = (sc)->d, endd = (sc)->endd, data = (sc)->data, \
			 peek = (sc)->peek, n_input = (sc)->n_input)

#if __STD_C
static int _scgetc(void* arg, int flag)
#else
static int _scgetc(arg, flag)
void*	arg;
int	flag;
#endif
{
	Scan_t	*sc = (Scan_t*)arg;

	if (flag)
	{	sc->error = flag;
		return 0;
	}

	/* if width >= 0, do not allow to exceed width number of bytes */
	if(sc->width == 0)
	{	sc->inp = -1;
		return 0;
	}

	if(sc->d >= sc->endd) /* refresh local buffer */
	{	sc->n_input += sc->d - sc->data;
		if(sc->peek)
			SFREAD(sc->f, sc->data, sc->d - sc->data);
		else	sc->f->next = sc->d;

		_sfbuf(sc->f, &sc->peek);
		sc->data = sc->d = sc->f->next;
		sc->endd = sc->f->endb;

		if(sc->d >= sc->endd)
		{	sc->inp = -1;
			return 0;
		}
	}

	if((sc->width -= 1) >= 0) /* from _sfdscan */
		return (sc->inp = (int)(*sc->d++));
	else	return ((int)(*sc->d++));
}

/* structure to match characters in a character class */
typedef struct _accept_s
{	char	ok[SF_MAXCHAR+1];
	int	yes;
	char	*form, *endf;
#if _has_multibyte
	wchar_t	wc;
#endif
} Accept_t;

#if __STD_C
static char* _sfsetclass(const char* form, Accept_t* ac, int flags)
#else
static char* _sfsetclass(form, ac, flags)
char*		form;	/* format string			*/
Accept_t*	ac;	/* values of accepted characters	*/
int		flags;	/* SFFMT_LONG for wchar_t		*/
#endif
{
	int		c, endc, n;
	SFMBDCL(mbs)

	if(*form == '^') /* complementing this set */
	{	ac->yes = 0;
		form += 1;
	}
	else	ac->yes = 1;

	for(c = 0; c <= SF_MAXCHAR; ++c)
		ac->ok[c] = !ac->yes;

	if(*form == ']' || *form == '-') /* special first char */
	{	ac->ok[*form] = ac->yes;
		form += 1;
	}
	ac->form = (char*)form;

	if(flags&SFFMT_LONG)
		SFMBCLR(&mbs);
	for(n = 1; *form != ']'; form += n)
	{	if((c = *((uchar*)form)) == 0)
			return NIL(char*);

		if(*(form+1) == '-')
		{	endc = *((uchar*)(form+2));
#if _has_multibyte
			if(c >= 128 || endc >= 128 ) /* range must be ascii */
				goto one_char;
#endif
			for(; c <= endc; ++c)
				ac->ok[c] = ac->yes;
			n = 3;
		}
		else
		{ one_char:
#if _has_multibyte /* true multi-byte chars must be checked differently */
			if((flags&SFFMT_LONG) && (n = (int)SFMBLEN(form,&mbs)) <= 0)
				return NIL(char*);
			if(n == 1)
#endif
				ac->ok[c] = ac->yes;
		}
	}

	ac->endf = (char*)form;
	return (char*)(form+1);
}

#if _has_multibyte
#if __STD_C
static int _sfwaccept(wchar_t wc, Accept_t* ac)
#else
static int _sfwaccept(wc, ac)
wchar_t		wc;
Accept_t*	ac;
#endif
{
	int		endc, c, n;
	wchar_t		fwc;
	char		*form = ac->form;
	SFMBDCL(mbs)

	SFMBCLR(&mbs);
	for(n = 1; *form != ']'; form += n)
	{	if((c = *((uchar*)form)) == 0)
			return 0;

		if(*(form+1) == '-')
		{	endc = *((uchar*)(form+2));
			if(c >= 128 || endc >= 128 ) /* range must be ascii */
				goto one_char;
			n = 3;
		}
		else
		{ one_char:
			if((n = mbrtowc(&fwc, form, ac->endf-form, &mbs)) > 1 &&
			   wc == fwc )
				return ac->yes;
		}
	}

	return !ac->yes;
}

#if _has_multibyte == 1
#define SFgetwc(sc,wc,fmt,ac,mbs)	_sfgetwc(sc,wc,fmt,ac,(Void_t*)(mbs))
#else
#define SFgetwc(sc,wc,fmt,ac,mbs)	_sfgetwc(sc,wc,fmt,ac,NIL(Void_t*))
#endif

#if __STD_C
static int _sfgetwc(Scan_t* sc, wchar_t* wc, int fmt, Accept_t* ac, Void_t *mbs)
#else
static int _sfgetwc(sc, wc, fmt, ac, mbs)
Scan_t*		sc;	/* the scanning handle		*/
wchar_t*	wc;	/* to return a scanned wchar_t	*/
int		fmt;	/* %s, %c, %[			*/
Accept_t*	ac;	/* accept handle for %[		*/
Void_t*		mbs;	/* multibyte parsing state	*/
#endif
{
	int	n, v;
	char	b[16]; /* assuming that SFMBMAX <= 16! */

	/* shift left data so that there will be more room to back up on error.
	   this won't help streams with small buffers - c'est la vie! */
	if(sc->d > sc->f->data && (n = sc->endd - sc->d) > 0 && n < SFMBMAX)
	{	memcpy(sc->f->data, sc->d, n);
		if(sc->f->endr == sc->f->endb)
			sc->f->endr = sc->f->data+n;
		if(sc->f->endw == sc->f->endb)
			sc->f->endw = sc->f->data+n;
		sc->f->endb = sc->f->data+n;
		sc->d = sc->data = sc->f->data;
		sc->endd = sc->f->endb;
		if(!mbs) sc->f->endb = sc->endd; /* stop cc's "unused mbs" warning */
	}

	for(n = 0; n < SFMBMAX; )
	{	if((v = _scgetc((Void_t*)sc, 0)) <= 0)
			goto no_match;
		else	b[n++] = v;

		if(mbrtowc(wc, b, n, (mbstate_t*)mbs) == (size_t)(-1))
			goto no_match;  /* malformed multi-byte char */
		else
		{	/* multi-byte char converted successfully */
			if(fmt == 'c')
				return 1;
			else if(fmt == 's')
			{	if(n > 1 || (n == 1 && !isspace(b[0]) ) )
					return 1;
				else	goto no_match;
			}
			else if(fmt == '[')
			{	if((n == 1 && ac->ok[b[0]]) ||
				   (n  > 1 && _sfwaccept(*wc,ac)) )
					return 1;
				else	goto no_match;
			}
			else /* if(fmt == '1') match a single wchar_t */
			{	if(*wc == ac->wc)
					return 1;
				else	goto no_match;
			}
		}
	}

no_match: /* this unget is lossy on a stream with small buffer */
	if((sc->d -= n) < sc->data)
		sc->d = sc->data;
	return 0;
}
#endif /*_has_multibyte*/


#if __STD_C
int sfvscanf(Sfio_t* f, reg const char* form, va_list args)
#else
int sfvscanf(f,form,args)
Sfio_t*		f;		/* file to be scanned */
reg char*	form;		/* scanning format */
va_list		args;
#endif
{
	reg int		inp, shift, base, width;
	ssize_t		size;
	int		fmt, flags, dot, n_assign, v, n, n_input;
	char		*sp;

	Accept_t	acc;

	Argv_t		argv;
	Sffmt_t		*ft;
	Fmt_t		*fm, *fmstk;

	Fmtpos_t*	fp;
	char		*oform;
	va_list		oargs;
	int		argp, argn;

	int		decimal = 0, thousand = 0;

#if _has_multibyte
	wchar_t		wc;
	SFMBDCL(fmbs)
	SFMBDCL(mbs)
#endif

	Void_t*		value;	/* location to assign scanned value */
	char*		t_str;
	ssize_t		n_str;

	/* local buffering system */
	Scan_t		scd;
	uchar		*d, *endd, *data;
	int		peek;
#define SFbuf(f)	(_sfbuf(f,&peek), (data = d = f->next), (endd = f->endb) )
#define SFlen(f)	(d - data)
#define SFinit(f)	((peek = f->extent < 0 && (f->flags&SF_SHARE)), SFbuf(f) )
#define SFend(f)	((n_input += SFlen(f)), \
			 (peek ? SFREAD(f,(Void_t*)data,SFlen(f)) : ((f->next = d),0)) )
#define SFgetc(f,c)	((c) = (d < endd || (SFend(f), SFbuf(f), d < endd)) ? \
				(int)(*d++) : -1 )
#define SFungetc(f,c)	(d -= 1)

	SFMTXDECL(f);

	SFCVINIT();	/* initialize conversion tables */

	SFMTXENTER(f,-1);

	if(!form || f->mode != SF_READ && _sfmode(f,SF_READ,0) < 0)
		SFMTXRETURN(f, -1);
	SFLOCK(f,0);

	SFinit(f); /* initialize local buffering system */

	n_assign = n_input = 0; inp = -1;

	fmstk = NIL(Fmt_t*);
	ft = NIL(Sffmt_t*);

	fp = NIL(Fmtpos_t*);
	argn = -1;
	oform = (char*)form;
	va_copy(oargs,args);

	SFSETLOCALE(&decimal, &thousand);

loop_fmt:
	SFMBCLR(&fmbs);
	while((fmt = *form++))
	{	if(fmt != '%')
		{	if(isspace(fmt))
			{	if(fmt != '\n' || !(f->flags&SF_LINE))
					fmt = -1;
				for(;;)
				{	if(SFgetc(f,inp) < 0 || inp == fmt)
						goto loop_fmt;
					else if(!isspace(inp))
					{	SFungetc(f,inp);
						goto loop_fmt;
					}
				}
			}
			else
			{ match_1:
#if _has_multibyte
				if((n = (int)mbrtowc(&wc,form-1,SFMBMAX,&fmbs)) <= 0)
					goto pop_fmt;
				if(n > 1)
				{	acc.wc = wc;
					SCinit(&scd,0); SFMBCLR(&mbs);
					v = SFgetwc(&scd, &wc, '1', &acc, &mbs);
					SCend(&scd,0);
					if(v == 0)
						goto pop_fmt;
					form += n-1;
				}
				else
#endif
				if(SFgetc(f,inp) != fmt)
				{	if(inp < 0)
						goto done;
					SFungetc(f,inp);
					goto pop_fmt;
				}
			}
			continue;
		}

		if(*form == '%')
		{	form += 1;
			do SFgetc(f,inp); while(isspace(inp)); /* skip starting blanks */
			SFungetc(f,inp);
			goto match_1;
		}

		if(*form == '\0')
			goto pop_fmt;

		if(*form == '*')
		{	flags = SFFMT_SKIP;
			form += 1;
		}
		else	flags = 0;

		/* matching some pattern */
		base = 10; size = -1;
		width = dot = 0;
		t_str = NIL(char*); n_str = 0;
		value = NIL(Void_t*);
		argp = -1;

	loop_flags:	/* LOOP FOR FLAGS, WIDTH, BASE, TYPE */
		switch((fmt = *form++) )
		{
		case LEFTP : /* get the type which is enclosed in balanced () */
			t_str = (char*)form;
			for(v = 1;;)
			{	switch(*form++)
				{
				case 0 :	/* not balanceable, retract */
					form = t_str;
					t_str = NIL(char*);
					n_str = 0;
					goto loop_flags;
				case LEFTP :	/* increasing nested level */
					v += 1;
					continue;
				case RIGHTP :	/* decreasing nested level */
					if((v -= 1) != 0)
						continue;
					if(*t_str != '*' )
						n_str = (form-1) - t_str;
					else
					{	t_str = (*_Sffmtintf)(t_str+1,&n);
						if(*t_str == '$')
						{	if(!fp &&
							   !(fp = (*_Sffmtposf)(f,oform,oargs,ft,1)) )
								goto pop_fmt;
							n = FP_SET(n,argn);
						}
						else	n = FP_SET(-1,argn);

						if(fp)
						{	t_str = fp[n].argv.s;
							n_str = fp[n].ft.size;
						}
						else if(ft && ft->extf )
						{	FMTSET(ft, form,args,
								LEFTP, 0, 0, 0,0,0,
								NIL(char*),0);
							n = (*ft->extf)
							      (f,(Void_t*)&argv,ft);
							if(n < 0)
								goto pop_fmt;
							if(!(ft->flags&SFFMT_VALUE) )
								goto t_arg;
							if((t_str = argv.s) &&
							   (n_str = (int)ft->size) < 0)
								n_str = strlen(t_str);
						}
						else
						{ t_arg:
							if((t_str = va_arg(args,char*)) )
								n_str = strlen(t_str);
						}
					}
					goto loop_flags;
				}
			}

		case '#' : /* alternative format */
			flags |= SFFMT_ALTER;
			goto loop_flags;

		case '.' : /* width & base */
			dot += 1;
			if(isdigit(*form))
			{	fmt = *form++;
				goto dot_size;
			}
			else if(*form == '*')
			{	form = (*_Sffmtintf)(form+1,&n);
				if(*form == '$')
				{	form += 1;
					if(!fp &&
					   !(fp = (*_Sffmtposf)(f,oform,oargs,ft,1)) )
						goto pop_fmt;
					n = FP_SET(n,argn);
				}
				else	n = FP_SET(-1,argn);

				if(fp)
					v = fp[n].argv.i;
				else if(ft && ft->extf )
				{	FMTSET(ft, form,args, '.',dot, 0, 0,0,0,
						NIL(char*), 0);
					if((*ft->extf)(f, (Void_t*)(&argv), ft) < 0)
						goto pop_fmt;
					if(ft->flags&SFFMT_VALUE)
						v = argv.i;
					else	v = (dot <= 2) ? va_arg(args,int) : 0;
				}
				else	v = (dot <= 2) ? va_arg(args,int) : 0;
				if(v < 0)
					v = 0;
				goto dot_set;
			}
			else	goto loop_flags;
			
		case '0' : case '1' : case '2' : case '3' : case '4' :
		case '5' : case '6' : case '7' : case '8' : case '9' :
		dot_size :
			for(v = fmt-'0'; isdigit(*form); ++form)
				v = v*10 + (*form - '0');

			if(*form == '$')
			{	form += 1;
				if(!fp && !(fp = (*_Sffmtposf)(f,oform,oargs,ft,1)) )
					goto pop_fmt;
				argp = v-1;
				goto loop_flags;
			}

		dot_set :
			if(dot == 0 || dot == 1)
				width = v;
			else if(dot == 2)
				base = v;
			goto loop_flags;

		case 'z' : /* ssize_t or object size */
		case 'I' : /* object size */
			size = -1; flags = (flags & ~SFFMT_TYPES) | SFFMT_IFLAG;
			if(*form == '*')
			{	form = (*_Sffmtintf)(form+1,&n);
				if(*form == '$')
				{	form += 1;
					if(!fp &&
					   !(fp = (*_Sffmtposf)(f,oform,oargs,ft,1)))
						goto pop_fmt;
					n = FP_SET(n,argn);
				}
				else	n = FP_SET(-1,argn);

				if(fp)	/* use position list */
					size = fp[n].argv.i;
				else if(ft && ft->extf )
				{	FMTSET(ft, form,args, 'I',sizeof(int), 0, 0,0,0,
						NIL(char*), 0);
					if((*ft->extf)(f, (Void_t*)(&argv), ft) < 0)
						goto pop_fmt;
					if(ft->flags&SFFMT_VALUE)
						size = argv.i;
					else	size = va_arg(args,int);
				}
				else	size = va_arg(args,int);
			}
			else if (fmt == 'z')
				flags = (flags&~SFFMT_TYPES) | SFFMT_ZFLAG;
			else if(isdigit(*form))
				for(size = 0, n = *form; isdigit(n); n = *++form)
					size = size*10 + (n - '0');
			goto loop_flags;

		case 'l' :
			size = -1; flags &= ~SFFMT_TYPES;
			if(*form == 'l')
			{	form += 1;
				flags |= SFFMT_LLONG;
			}
			else	flags |= SFFMT_LONG;
			goto loop_flags;
		case 'h' :
			size = -1; flags &= ~SFFMT_TYPES;
			if(*form == 'h')
			{	form += 1;
				flags |= SFFMT_SSHORT;
			}
			else	flags |= SFFMT_SHORT;
			goto loop_flags;
		case 'L' :
			size = -1; flags = (flags&~SFFMT_TYPES) | SFFMT_LDOUBLE;
			goto loop_flags;
		case 'j' :
			size = -1; flags = (flags&~SFFMT_TYPES) | SFFMT_JFLAG;
			goto loop_flags;
		case 't' :
			size = -1; flags = (flags&~SFFMT_TYPES) | SFFMT_TFLAG;
			goto loop_flags;
		case QUOTE :
			if(thousand > 0)
				flags |= SFFMT_THOUSAND;
			goto loop_flags;
		}

		/* set object size for scalars */
		if(flags & SFFMT_TYPES)
		{	if((_Sftype[fmt]&(SFFMT_INT|SFFMT_UINT)) || fmt == 'n')
			{	if(flags&SFFMT_LONG)
					size = sizeof(long);
				else if(flags&SFFMT_SHORT)
					size = sizeof(short);
				else if(flags&SFFMT_SSHORT)
					size = sizeof(char);
				else if(flags&SFFMT_TFLAG)
					size = sizeof(ptrdiff_t);
				else if(flags&SFFMT_ZFLAG) 
					size = sizeof(size_t);
				else if(flags&(SFFMT_LLONG|SFFMT_JFLAG) )
					size = sizeof(Sflong_t);
				else if(flags&SFFMT_IFLAG)
				{	if(size <= 0 ||
					   size == sizeof(Sflong_t)*CHAR_BIT )
						size = sizeof(Sflong_t);
				}
				else if(size < 0)
					size = sizeof(int);
			}
			else if(_Sftype[fmt]&SFFMT_FLOAT)
			{	if(flags&(SFFMT_LONG|SFFMT_LLONG))
					size = sizeof(double);
				else if(flags&SFFMT_LDOUBLE)
					size = sizeof(Sfdouble_t);
				else if(flags&SFFMT_IFLAG)
				{	if(size <= 0)
						size = sizeof(Sfdouble_t);
				}
				else if(size < 0)
					size = sizeof(float);
			}
			else if(_Sftype[fmt]&SFFMT_CHAR)
			{
#if _has_multibyte
				if((flags&SFFMT_LONG) || fmt == 'C')
				{	size = sizeof(wchar_t) > sizeof(int) ?
						sizeof(wchar_t) : sizeof(int);
				} else
#endif
				if(size < 0)
					size = sizeof(int);
			}
		}

		argp = FP_SET(argp,argn);
		if(fp)
		{	if(!(fp[argp].ft.flags&SFFMT_SKIP) )
			{	n_assign += 1;
				value = fp[argp].argv.vp;
				size = fp[argp].ft.size;
				if(ft && ft->extf && fp[argp].ft.fmt != fp[argp].fmt)
					fmt = fp[argp].ft.fmt;
			}
			else	flags |= SFFMT_SKIP;
		}
		else if(ft && ft->extf)
		{	FMTSET(ft, form,args, fmt, size,flags, width,0,base, t_str,n_str);
			SFend(f); SFOPEN(f,0);
			v = (*ft->extf)(f, (Void_t*)&argv, ft);
			SFLOCK(f,0); SFbuf(f);

			if(v < 0)
				goto pop_fmt;
			else if(v > 0) /* extf comsumed v input bytes */
			{	n_input += v;
				if(!(ft->flags&SFFMT_SKIP) )
					n_assign += 1;
				continue;
			}
			else /* if(v == 0): extf did not use input stream */
			{	FMTGET(ft, form,args, fmt, size, flags, width,n,base);

				if((ft->flags&SFFMT_VALUE) && !(ft->flags&SFFMT_SKIP) )
					value = argv.vp;
			}
		}

		if(_Sftype[fmt] == 0) /* unknown pattern */
			goto pop_fmt;

		if(fmt == '!')
		{	if(!fp)
				fp = (*_Sffmtposf)(f,oform,oargs,ft,1);
			else	goto pop_fmt;

			if(!(argv.ft = va_arg(args,Sffmt_t*)) )
				continue;
			if(!argv.ft->form && ft ) /* change extension functions */
			{	if(ft->eventf &&
				   (*ft->eventf)(f,SF_DPOP,(Void_t*)form,ft) < 0)
					continue;
				fmstk->ft = ft = argv.ft;
			}
			else			/* stack a new environment */
			{	if(!(fm = (Fmt_t*)malloc(sizeof(Fmt_t))) )
					goto done;

				ft = fm->ft = argv.ft;
				SFMBSET(ft->mbs, &fmbs);
				if(ft->form)
				{	fm->form = (char*)form; SFMBCPY(&fm->mbs,&fmbs);
					va_copy(fm->args,args);

					fm->oform = oform;
					va_copy(fm->oargs,oargs);
					fm->argn = argn;
					fm->fp = fp;

					form = ft->form; SFMBCLR(ft->mbs);
					va_copy(args,ft->args);
					argn = -1;
					fp = NIL(Fmtpos_t*);
					oform = (char*)form;
					va_copy(oargs,args);
				}
				else	fm->form = NIL(char*);

				fm->eventf = ft->eventf;
				fm->next = fmstk;
				fmstk = fm;
			}
			continue;
		}

		/* get the address to assign value */
		if(!value && !(flags&SFFMT_SKIP) )
			value = va_arg(args,Void_t*);

		if(fmt == 'n') /* return length of consumed input */
		{
#if !_ast_intmax_long
			if(size == sizeof(Sflong_t) )
				*((Sflong_t*)value) = (Sflong_t)(n_input+SFlen(f));
			else
#endif
			if(size == sizeof(long) )
				*((long*)value) = (long)(n_input+SFlen(f));
			else if(size == sizeof(short) )
				*((short*)value) = (short)(n_input+SFlen(f));
			else if(size == sizeof(uchar))
				*((uchar*)value) = (uchar)(n_input+SFlen(f));
			else	*((int*)value) = (int)(n_input+SFlen(f));
			continue;
		}

		/* if get here, start scanning input */
		if(width == 0)
			width = fmt == 'c' ? 1 : MAXWIDTH;

		/* define the first input character */
		if(fmt == 'c' || fmt == '[' || fmt == 'C' )
			SFgetc(f,inp);
		else
		{	do	{ SFgetc(f,inp); }
			while(isspace(inp)); /* skip starting blanks */
		}
		if(inp < 0)
			goto done;

		if(_Sftype[fmt] == SFFMT_FLOAT)
		{	SFungetc(f,inp); SCinit(&scd,1);
			argv.ld = _sfdscan((Void_t*)(&scd), _scgetc);
			SCend(&scd,1);

			if(scd.error >= 0)
			{	if(inp >= 0)
					SFungetc(f, inp);
				goto pop_fmt;
			}

			if(value)
			{
#if !_ast_fltmax_double
				if(size == sizeof(Sfdouble_t))
					*((Sfdouble_t*)value) = argv.ld;
				else
#endif
				if(size == sizeof(double))
					*((double*)value) = (double)argv.ld;
				else	*((float*)value) = (float)argv.ld;

				n_assign += 1;
			}
		}
		else if(_Sftype[fmt] == SFFMT_UINT || fmt == 'p')
		{	if(inp == '-')
			{	SFungetc(f,inp);
				goto pop_fmt;
			}
			else	goto int_cvt;
		}
		else if(_Sftype[fmt] == SFFMT_INT)
		{ int_cvt:
			if(inp == '-' || inp == '+')
			{	if(inp == '-')
					flags |= SFFMT_MINUS;
				while(--width > 0 && SFgetc(f,inp) >= 0)
					if(!isspace(inp))
						break;
			}
			if(inp < 0)
				goto done;

			if(fmt == 'o')
				base = 8;
			else if(fmt == 'x' || fmt == 'X' || fmt == 'p')
				base = 16;
			else if(fmt == 'i' && inp == '0') /* self-described data */
			{	base = 8;
				if(width > 1) /* peek to see if it's a base-16 */
				{	if(SFgetc(f,inp) >= 0)
					{	if(inp == 'x' || inp == 'X')
							base = 16;
						SFungetc(f,inp);
					}
					inp = '0';
				}
			}

			/* now convert */
			argv.lu = 0;
			if(base == 16)
			{	sp = (char*)_Sfcv36;
				shift = 4;
				if(sp[inp] >= 16)
				{	SFungetc(f,inp);
					goto pop_fmt;
				}
				if(inp == '0' && --width > 0)
				{	/* skip leading 0x or 0X */
					if(SFgetc(f,inp) >= 0 &&
					   (inp == 'x' || inp == 'X') && --width > 0)
						SFgetc(f,inp);
				}
				if(inp >= 0 && sp[inp] < 16)
					goto base_shift;
			}
			else if(base == 10)
			{	for(n = v = 0;; )
				{	/* fast base 10 conversion */
#define TEN(x) (((x) << 3) + ((x) << 1) )
					if (inp >= '0' && inp <= '9')
					{	argv.lu = TEN(argv.lu) + (inp-'0');
						n += 1;
					}
					else if(inp == thousand)
					{	if((v && n != 3) || (!v && n > 3) )
							break;
						v = 1; n = 0;
					}
					else	break;
					if((width -= 1) <= 0 || SFgetc(f,inp) < 0)
						break;
				}
				if (!n && !v)
				{	SFungetc(f,inp);
					goto pop_fmt;
				}

				if(fmt == 'i' && inp == '#' && !(flags&SFFMT_ALTER) )
				{	base = (int)argv.lu;
					if(base < 2 || base > SF_RADIX)
						goto pop_fmt;
					argv.lu = 0;
					sp = (char*)(base <= 36 ? _Sfcv36 : _Sfcv64);
					if(--width > 0 &&
					   SFgetc(f,inp) >= 0 && sp[inp] < base)
						goto base_conv;
				}
			}
			else
			{	/* other bases */
				sp = (char*)(base <= 36 ? _Sfcv36 : _Sfcv64);
				if(base < 2 || base > SF_RADIX || sp[inp] >= base)
				{	SFungetc(f,inp);
					goto pop_fmt;
				}

			base_conv: /* check for power of 2 conversions */
				if((base & ~(base-1)) == base)
				{	if(base < 8)
						shift = base <  4 ? 1 : 2;
					else if(base < 32)
						shift = base < 16 ? 3 : 4;
					else	shift = base < 64 ? 5 : 6;

			base_shift:	do
					{ argv.lu = (argv.lu << shift) + sp[inp];
					} while(--width > 0 &&
					        SFgetc(f,inp) >= 0 && sp[inp] < base);
				}
				else
				{	do
					{ argv.lu = (argv.lu * base) + sp[inp];
					} while(--width > 0 &&
						SFgetc(f,inp) >= 0 && sp[inp] < base);
				}
			}

			if(flags&SFFMT_MINUS)
				argv.ll = -argv.ll;

			if(value)
			{	n_assign += 1;

				if(fmt == 'p')
#if _more_void_int
					*((Void_t**)value) = (Void_t*)((ulong)argv.lu);
#else
					*((Void_t**)value) = (Void_t*)((uint)argv.lu);
#endif
#if !_ast_intmax_long
				else if(size == sizeof(Sflong_t))
					*((Sflong_t*)value) = argv.ll;
#endif
				else if(size == sizeof(long))
				{	if(fmt == 'd' || fmt == 'i')
						*((long*)value) = (long)argv.ll;
					else	*((ulong*)value) = (ulong)argv.lu;
				}
				else if(size == sizeof(short))
				{	if(fmt == 'd' || fmt == 'i')
						*((short*)value) = (short)argv.ll;
					else	*((ushort*)value) = (ushort)argv.lu;
				}
				else if(size == sizeof(char) )
				{	if(fmt == 'd' || fmt == 'i')
						*((char*)value) = (char)argv.ll;
					else	*((uchar*)value) = (uchar)argv.lu;
				}
				else
				{	if(fmt == 'd' || fmt == 'i')
						*((int*)value) = (int)argv.ll;
					else	*((uint*)value) = (uint)argv.lu;
				}
			}
		}
		else if(fmt == 'C' || fmt == 'S')
		{	fmt = fmt == 'C' ? 'c' : 's';
			flags = (flags & ~SFFMT_TYPES) | SFFMT_LONG;
			goto do_string;
		}
		else if(fmt == 's' || fmt == 'c' || fmt == '[' )
		{ do_string:	
			if(value)
			{	if(size < 0)
					size = MAXWIDTH;
				if(fmt != 'c')
					size -= 1;
#if _has_multibyte
				if(flags&SFFMT_LONG)
					argv.ws = (wchar_t*)value;
				else
#endif
					argv.s = (char*)value;
			}
			else	size = 0;

			if(fmt == '[' && !(form = _sfsetclass(form,&acc,flags)) )
			{	SFungetc(f,inp);
				goto pop_fmt;
			}

			n = 0; /* count number of scanned characters */
#if _has_multibyte
			if(flags&SFFMT_LONG)
			{	SFungetc(f,inp); SCinit(&scd,0); SFMBCLR(&mbs);
				for(; width > 0; --width)
				{	if(SFgetwc(&scd,&wc,fmt,&acc,&mbs) == 0)
						break;
					if((n += 1) <= size)
						*argv.ws++ = wc;
				}
				SCend(&scd,0);
			}
			else
#endif

			if(fmt == 's')
			{	do
				{	if(isspace(inp))
						break;
					if((n += 1) <= size)
						*argv.s++ = inp;
				} while(--width > 0 && SFgetc(f,inp) >= 0);
			}
			else if(fmt == 'c')
			{	do
			 	{	if((n += 1) <= size)
						*argv.s++ = inp;
				} while(--width > 0 && SFgetc(f,inp) >= 0);
			}
			else /* if(fmt == '[') */
			{	do
				{	if(!acc.ok[inp])
					{	if(n > 0 || (flags&SFFMT_ALTER) )
							break;
						else
						{	SFungetc(f,inp);
							goto pop_fmt;
						}
					}
					if((n += 1) <= size)
						*argv.s++ = inp;
				} while(--width > 0 && SFgetc(f,inp) >= 0);
			}

			if(value && (n > 0 || fmt == '[') )
			{	n_assign += 1;
				if(fmt != 'c' && size >= 0)
				{
#if _has_multibyte
					if(flags&SFFMT_LONG)
						*argv.ws = 0;
					else
#endif
						*argv.s = 0;
				}
			}
		}

		if(width > 0 && inp >= 0)
			SFungetc(f,inp);
	}

pop_fmt:
	if(fp)
	{	free(fp);
		fp = NIL(Fmtpos_t*);
	}
	while((fm = fmstk) ) /* pop the format stack and continue */
	{	if(fm->eventf)
		{	if(!form || !form[0])
				(*fm->eventf)(f,SF_FINAL,NIL(Void_t*),ft);
			else if((*fm->eventf)(f,SF_DPOP,(Void_t*)form,ft) < 0)
				goto loop_fmt;
		}

		fmstk = fm->next;
		if((form = fm->form) )
		{	SFMBCPY(&fmbs,&fm->mbs);
			va_copy(args, fm->args);
			oform = fm->oform;
			va_copy(oargs,fm->oargs);
			argn = fm->argn;
			fp = fm->fp;
		}
		ft = fm->ft;
		free(fm);
		if(form && form[0])
			goto loop_fmt;
	}

done:
	if(fp)
		free(fp);
	while((fm = fmstk) )
	{	if(fm->eventf)
			(*fm->eventf)(f,SF_FINAL,NIL(Void_t*),fm->ft);
		fmstk = fm->next;
		free(fm);
	}

	SFend(f);

	SFOPEN(f,0);

	if(n_assign == 0 && inp < 0)
		n_assign = -1;

	SFMTXRETURN(f,n_assign);
}
