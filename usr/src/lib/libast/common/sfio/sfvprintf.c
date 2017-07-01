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
#include	"sfhdr.h"

/*	The engine for formatting data.
**	1. Argument positioning is done in sftable.c so any changes
**	   made here should be reflected in sftable.c as well.
**	2. For internationalization, Sfio only supports I/O of multibyte strings.
**	   However, this code does provide minimal support so that Stdio functions
**	   such as fwprintf/swprintf can be emulated (see stdvwprintf()).
**
**	Written by Kiem-Phong Vo.
*/
#define HIGHBITI	(~((~((uint)0)) >> 1))
#define HIGHBITL	(~((~((Sfulong_t)0)) >> 1))

#define SFFMT_PREFIX	(SFFMT_MINUS|SFFMT_SIGN|SFFMT_BLANK)

#define FPRECIS		6	/* default precision for floats 	*/

#if _PACKAGE_ast
#include <ccode.h>
#else
/* characters when using ebcdic or ascii */
#if _chr_ebcdic
#define CC_vt			013	/* vertical tab	*/
#define CC_esc			047	/* escape	*/
#define CC_bel			057	/* bell		*/
#else
#define CC_vt			013	/* vertical tab	*/
#define CC_esc			033	/* escape	*/
#define CC_bel			007	/* bell		*/
#endif /* _chr_ebcdic */
#endif /* _PACKAGE_ast */

#if __STD_C
static int chr2str(char* buf, int v)
#else
static int chr2str(buf, v)
char*	buf;
int	v;
#endif
{
	if(isprint(v) && v != '\\')
	{	*buf++ = v;
		return 1;
	}
	else
	{	*buf++ = '\\';
		switch(v)
		{ case CC_bel:	*buf++ = 'a'; return 2;
		  case CC_vt:	*buf++ = 'v'; return 2;
		  case CC_esc:	*buf++ = 'E'; return 2;
		  case '\b':	*buf++ = 'b'; return 2;
		  case '\f':	*buf++ = 'f'; return 2;
		  case '\n':	*buf++ = 'n'; return 2;
		  case '\r':	*buf++ = 'r'; return 2;
		  case '\t':	*buf++ = 't'; return 2;
		  case '\\':	*buf++ = '\\'; return 2;
		  default:	*buf++ = '0' + ((v >> 6) & 03);
				*buf++ = '0' + ((v >> 3) & 07);
				*buf++ = '0' + ((v >> 0) & 07);
				return 4;
		}
	}
}

/* On some platform(s), large functions are not compilable.
** In such a case, the below macro should be defined non-zero so that
** some in-lined macros will be made smaller, trading time for space.
*/
#if !defined(_sffmt_small) && defined(_UTS)
#define _sffmt_small	1
#endif

#if __STD_C
int sfvprintf(Sfio_t* f, const char* form, va_list args)
#else
int sfvprintf(f,form,args)
Sfio_t*	f;		/* file to print to	*/
char*	form;		/* format to use	*/
va_list	args;		/* arg list if !argf	*/
#endif
{
	int		n, v, w, k, n_s, base, fmt, flags;
	Sflong_t	lv;
	char		*sp, *ssp, *endsp, *ep, *endep;
	int		dot, width, precis, sign, decpt;
#if _PACKAGE_ast
	int		scale;
#endif
	ssize_t		size;
	Sfdouble_t	dval;
	Void_t*		valp;
	char		*tls[2], **ls;	/* for %..[separ]s		*/
	char*		t_str;		/* stuff between ()		*/
	ssize_t		n_str;		/* its length			*/

	Argv_t		argv;		/* for extf to return value	*/
	Sffmt_t		*ft;		/* format environment		*/
	Fmt_t		*fm, *fmstk;	/* stack contexts		*/

	char*		oform;		/* original format string	*/
	va_list		oargs;		/* original arg list		*/
	Fmtpos_t*	fp;		/* arg position list		*/
	int		argp, argn;	/* arg position and number	*/

#define SLACK		1024
	char		buf[SF_MAXDIGITS+SLACK], tmp[SF_MAXDIGITS+1], data[SF_GRAIN];
	int		decimal = 0, thousand = 0;

#if _has_multibyte
	wchar_t*	wsp;
	SFMBDCL(fmbs)			/* state of format string	*/
	SFMBDCL(mbs)			/* state of some string		*/
#ifdef mbwidth
	char*		osp;
	int		n_w, wc;
#endif
#endif

	/* local io system */
	int		o, n_output;
#define SMputc(f,c)	{ if((o = SFFLSBUF(f,c)) >= 0 ) n_output += 1; \
			  else		{ SFBUF(f); goto done; } \
			}
#define SMnputc(f,c,n)	{ if((o = SFNPUTC(f,c,n)) > 0 ) n_output += 1; \
			  if(o != n)	{ SFBUF(f); goto done; } \
			}
#define SMwrite(f,s,n)	{ if((o = SFWRITE(f,(Void_t*)s,n)) > 0 ) n_output += o; \
			  if(o != n)	{ SFBUF(f); goto done; } \
			}
#if _sffmt_small /* these macros are made smaller at some performance cost */
#define SFBUF(f)
#define SFINIT(f)	(n_output = 0)
#define SFEND(f)
#define SFputc(f,c)	SMputc(f,c)
#define SFnputc(f,c,n)	SMnputc(f,c,n)
#define SFwrite(f,s,n)	SMwrite(f,s,n)
#else
	uchar	*d, *endd;
#define SFBUF(f)	(d = f->next, endd = f->endb)
#define SFINIT(f)	(SFBUF(f), n_output = 0)
#define SFEND(f)	((n_output += d - f->next), (f->next = d))
#define SFputc(f,c)	{ if(d < endd) 	  { *d++ = (uchar)c; } \
	  		  else		  { SFEND(f); SMputc(f,c); SFBUF(f); } \
	  		}
#define SFnputc(f,c,n)	{ if(d+n <= endd) { while(n--) *d++ = (uchar)(c); } \
			  else		  { SFEND(f); SMnputc(f,c,n); SFBUF(f); } \
			}
#define SFwrite(f,s,n)	{ if(d+n <= endd) { while(n--) *d++ = (uchar)(*s++); } \
			  else 		  { SFEND(f); SMwrite(f,s,n); SFBUF(f); } \
			}
#endif /* _sffmt_small */

	SFMTXDECL(f);

	SFCVINIT();	/* initialize conversion tables */

	SFMTXENTER(f,-1);

	if(!form)
		SFMTXRETURN(f, -1);

	/* make sure stream is in write mode and buffer is not NULL */
	if(f->mode != SF_WRITE && _sfmode(f,SF_WRITE,0) < 0)
		SFMTXRETURN(f, -1);

	SFLOCK(f,0);

	if(!f->data && !(f->flags&SF_STRING))
	{	f->data = f->next = (uchar*)data;
		f->endb = f->data+sizeof(data);
	}
	SFINIT(f);

	tls[1] = NIL(char*);

	fmstk = NIL(Fmt_t*);
	ft = NIL(Sffmt_t*);

	oform = (char*)form;
	va_copy(oargs,args);
	argn = -1;
	fp = NIL(Fmtpos_t*);

loop_fmt :
	SFMBCLR(&fmbs); /* clear multibyte states to parse the format string */
	while((n = *form) )
	{	if(n != '%') /* collect the non-pattern chars */
		{	sp = (char*)form;
			do
			{	if((n = SFMBLEN(form, &fmbs)) <= 0)
				{	n = 1;
					SFMBCLR(&fmbs);
				}
			} while(*(form += n) && *form != '%');

			n = form-sp;
			SFwrite(f,sp,n);
			continue;
		}
		else	form += 1;

		flags = 0;
#if _PACKAGE_ast
		scale = 0;
#endif
		size = width = precis = base = n_s = argp = -1;
		ssp = _Sfdigits;
		endep = ep = NIL(char*);
		endsp = sp = buf+(sizeof(buf)-1);
		t_str = NIL(char*);
		n_str = dot = 0;

	loop_flags:	/* LOOP FOR \0, %, FLAGS, WIDTH, PRECISION, BASE, TYPE */
		switch((fmt = *form++) )
		{
		case '\0':
			SFputc(f,'%');
			goto pop_fmt;
		case '%' :
			SFputc(f,'%');
			continue;

		case LEFTP : /* get the type enclosed in balanced parens */
			t_str = (char*)form;
			for(v = 1;;)
			{	switch(*form++)
				{
				case 0 :	/* not balancable, retract */
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
						n_str = (form-1)-t_str;
					else
					{	t_str = (*_Sffmtintf)(t_str+1,&n);
						if(*t_str == '$')
						{	if(!fp &&
							   !(fp = (*_Sffmtposf)(f,oform,oargs,ft,0)) )
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

		case '-' :
			flags = (flags & ~(SFFMT_CENTER|SFFMT_ZERO)) | SFFMT_LEFT;
			goto loop_flags;
		case '0' :
			if(!(flags&(SFFMT_LEFT|SFFMT_CENTER)) )
				flags |= SFFMT_ZERO;
			goto loop_flags;
		case ' ' :
			if(!(flags&SFFMT_SIGN) )
				flags |= SFFMT_BLANK;
			goto loop_flags;
		case '+' :
			flags = (flags & ~SFFMT_BLANK) | SFFMT_SIGN;
			goto loop_flags;
		case '=' :
			flags = (flags & ~(SFFMT_LEFT|SFFMT_ZERO)) | SFFMT_CENTER;
			goto loop_flags;
		case '#' :
			flags |= SFFMT_ALTER;
			goto loop_flags;
		case QUOTE:
			SFSETLOCALE(&decimal,&thousand);
			if(thousand > 0)
				flags |= SFFMT_THOUSAND;
			goto loop_flags;
		case ',':
			SFSETLOCALE(&decimal,&thousand);
			if(thousand < 0)
				thousand = fmt;
			flags |= SFFMT_THOUSAND;
			goto loop_flags;

		case '.' :
			dot += 1;
			if(dot == 1)
			{	/* so base can be defined without setting precis */
				if(*form != '.')
					precis = 0;
			}
			else if(dot == 2)
			{	base = 0; /* for %s,%c */
				v = form[0] == 'l' ? form[1] : form[0];
				if(v == 'c' || v == 'C' || v == 's' || v == 'S')
					goto loop_flags;
				if(*form && !isalnum(*form))
				{	v = form[1] == 'l' ? form[2] : form[1];
					if(v == 'c' || v == 'C' || v == 's' || v == 'S')
					{	if(*form == '*')
							goto do_star;
						else
						{	base = *form++;
							goto loop_flags;
						}
					}
				}
			}

			if(isdigit(*form) )
			{	fmt = *form++;
				goto dot_size;
			}
			else if(*form != '*')
				goto loop_flags;
		do_star:
			form += 1; /* fall thru for '*' */
		/* FALLTHROUGH */
		case '*' :
			form = (*_Sffmtintf)(form,&n);
			if(*form == '$')
			{	form += 1;
				if(!fp && !(fp = (*_Sffmtposf)(f,oform,oargs,ft,0)) )
					goto pop_fmt;
				n = FP_SET(n,argn);
			}
			else	n = FP_SET(-1,argn);

			if(fp)
				v = fp[n].argv.i;
			else if(ft && ft->extf)
			{	FMTSET(ft, form,args, '.',dot, 0, 0,0,0, NIL(char*), 0);
				if((*ft->extf)(f, (Void_t*)(&argv), ft) < 0)
					goto pop_fmt;
				fmt = ft->fmt;
				flags = (flags&~SFFMT_TYPES) | (ft->flags&SFFMT_TYPES);
				if(ft->flags&SFFMT_VALUE)
					v = argv.i;
				else	v = (dot <= 2) ? va_arg(args,int) : 0;
			}
			else	v = dot <= 2 ? va_arg(args,int) : 0;
			goto dot_set;

		case '1' : case '2' : case '3' :
		case '4' : case '5' : case '6' :
		case '7' : case '8' : case '9' :
		dot_size :
			for(v = fmt - '0'; isdigit(*form); ++form)
				v = v*10 + (*form - '0');
			if(*form == '$')
			{	form += 1;
				if(!fp && !(fp = (*_Sffmtposf)(f,oform,oargs,ft,0)) )
					goto pop_fmt;
				argp = v-1;
				goto loop_flags;
			}
		dot_set :
			if(dot == 0)
			{	if((width = v) < 0)
				{	width = -width;
					flags = (flags & ~(SFFMT_CENTER|SFFMT_ZERO)) | SFFMT_LEFT;
				}
			}
			else if(dot == 1)
				precis = v;
			else if(dot == 2)
				base = v;
			goto loop_flags;

		case 'I' : /* object length */
			size = -1; flags = (flags & ~SFFMT_TYPES) | SFFMT_IFLAG;
			if(isdigit(*form) )
			{	for(size = 0, n = *form; isdigit(n); n = *++form)
					size = size*10 + (n - '0');
			}
			else if(*form == '*')
			{	form = (*_Sffmtintf)(form+1,&n);
				if(*form == '$')
				{	form += 1;
					if(!fp &&
					   !(fp = (*_Sffmtposf)(f,oform,oargs,ft,0)))
						goto pop_fmt;
					n = FP_SET(n,argn);
				}
				else	n = FP_SET(-1,argn);

				if(fp)	/* use position list */
					size = fp[n].argv.i;
				else if(ft && ft->extf)
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
			size = -1; flags = (flags & ~SFFMT_TYPES) | SFFMT_LDOUBLE;
			goto loop_flags;

		case 'j' :
			size = -1; flags = (flags&~SFFMT_TYPES) | SFFMT_JFLAG;
			goto loop_flags;
		case 'z' :
			size = -1; flags = (flags&~SFFMT_TYPES) | SFFMT_ZFLAG;
			goto loop_flags;
		case 't' :
			size = -1; flags = (flags&~SFFMT_TYPES) | SFFMT_TFLAG;
			goto loop_flags;
		default:
			break;
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
			{	if(flags&SFFMT_LDOUBLE)
					size = sizeof(Sfdouble_t);
				else if(flags&(SFFMT_LONG|SFFMT_LLONG))
					size = sizeof(double);
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
		{	if(ft && ft->extf && fp[argp].ft.fmt != fp[argp].fmt)
				fmt = fp[argp].ft.fmt;
			argv = fp[argp].argv;
			size = fp[argp].ft.size;
		}
		else if(ft && ft->extf )	/* extended processing */
		{	FMTSET(ft, form,args, fmt, size,flags, width,precis,base,
				t_str,n_str);
			SFEND(f); SFOPEN(f,0);
			v = (*ft->extf)(f, (Void_t*)(&argv), ft);
			SFLOCK(f,0); SFBUF(f);

			if(v < 0)	/* no further processing */
				goto pop_fmt;
			else if(v > 0)	/* extf output v bytes */
			{	n_output += v;
				continue;
			}
			else		/* extf did not output */
			{	FMTGET(ft, form,args, fmt, size,flags, width,precis,base);

				if(!(ft->flags&SFFMT_VALUE))
					goto arg_list;
				else if(_Sftype[fmt]&(SFFMT_INT|SFFMT_UINT) )
				{	if(size == sizeof(short))
					{	if(_Sftype[fmt]&SFFMT_INT)
							argv.i = argv.h;
						else	argv.i = argv.uh;
					}
					else if(size == sizeof(char))
					{	if(_Sftype[fmt]&SFFMT_INT)
							argv.i = argv.c;
						else	argv.i = argv.uc;
					}
				}
				else if(_Sftype[fmt]&SFFMT_FLOAT )
				{	if(size == sizeof(float) )
						argv.d = argv.f;
				}
				else if(_Sftype[fmt]&SFFMT_CHAR)
				{	if(base < 0)
						argv.i = (int)argv.c;
				}
			}
		}
		else
		{ arg_list:
			switch(_Sftype[fmt])
			{ case SFFMT_INT:
			  case SFFMT_UINT:
#if !_ast_intmax_long
				if(size == sizeof(Sflong_t))
					argv.ll = va_arg(args, Sflong_t);
				else
#endif
				if(size == sizeof(long) )
					argv.l = va_arg(args, long);
				else	argv.i = va_arg(args, int);
				break;
			 case SFFMT_FLOAT:
#if !_ast_fltmax_double
				if(size == sizeof(Sfdouble_t))
					argv.ld = va_arg(args,Sfdouble_t);
				else
#endif
					argv.d  = va_arg(args,double);
				break;
			 case SFFMT_POINTER:
					argv.vp = va_arg(args,Void_t*);
				break;
			 case SFFMT_CHAR:
				if(base >= 0)
					argv.s = va_arg(args,char*);
#if _has_multibyte
				else if((flags & SFFMT_LONG) || fmt == 'C')
				{	if(sizeof(wchar_t) <= sizeof(uint) )
						argv.wc = (wchar_t)va_arg(args,uint);
					else	argv.wc = va_arg(args,wchar_t);
				}
#endif
				else	argv.i = va_arg(args,int);
				break;
			 default: /* unknown pattern */
				break;
			}
		}

		switch(fmt)	/* PRINTF DIRECTIVES */
		{
		default :	/* unknown directive */
			form -= 1;
			argn -= 1;
			continue;

		case '!' :	/* stacking a new environment */
			if(!fp)
				fp = (*_Sffmtposf)(f,oform,oargs,ft,0);
			else	goto pop_fmt;

			if(!argv.ft)
				goto pop_fmt;
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

		case 'S':
			flags = (flags & ~(SFFMT_TYPES|SFFMT_LDOUBLE)) | SFFMT_LONG;
		/* FALLTHROUGH */
		case 's':
#if _has_multibyte && defined(mbwidth)
			wc = (flags & SFFMT_LDOUBLE) && mbwide();
#endif
			if(base >= 0)	/* list of strings */
			{	if(!(ls = argv.sp) || !ls[0])
					continue;
			}
			else
			{	if(!(sp = argv.s))
				{	sp = "(null)";
					flags &= ~SFFMT_LONG;
				}
#if _PACKAGE_ast
		str_cvt:
				if(scale)
				{	size = base = -1;
					flags &= ~SFFMT_LONG;
				}
#endif
				ls = tls; tls[0] = sp;
			}
			for(sp = *ls;;)
			{	/* v: number of bytes  w: print width of those v bytes */
#if _has_multibyte
				if(flags & SFFMT_LONG)
				{	v = 0;
#ifdef mbwidth
					w = 0;
#endif
					SFMBCLR(&mbs);
					for(n = 0, wsp = (wchar_t*)sp;; ++wsp, ++n)
					{	if((size >= 0 && n >= size) ||
						   (size <  0 && *wsp == 0) )
							break;
						if((n_s = wcrtomb(buf, *wsp, &mbs)) <= 0)
							break;
#ifdef mbwidth
						if(wc)
						{	n_w = mbwidth(*wsp);
							if(precis >= 0 && (w+n_w) > precis )
								break;
							w += n_w;
						}
						else
#endif
						if(precis >= 0 && (v+n_s) > precis )
							break;
						v += n_s;
					}
#ifdef mbwidth
					if(!wc)
						w = v;
#endif
				}
#if _has_multibyte && defined(mbwidth)
				else if (wc)
				{	w = 0;
					SFMBCLR(&mbs);
					ssp = sp;
					for(;;)
					{	if((size >= 0 && w >= size) ||
						   (size <  0 && *ssp == 0) )
							break;
						osp = ssp;
						n = mbchar(osp);
						n_w = mbwidth(n);
						if(precis >= 0 && (w+n_w) > precis )
							break;
						w += n_w;
						ssp = osp;
					}
					v = ssp - sp;
				}
#endif
				else
#endif
				{	if((v = size) < 0)
						for(v = 0; sp[v]; ++v)
							if(v == precis)
								break;
					if(precis >= 0 && v > precis)
						v = precis;
					w = v;
				}

				if((n = width - w) > 0 && !(flags&SFFMT_LEFT) )
				{	if(flags&SFFMT_CENTER)
					{	n -= (k = n/2);
						SFnputc(f, ' ', k);
					}
					else
					{
						SFnputc(f, ' ', n);
						n = 0;
					}
				}
#if _has_multibyte
				if(flags & SFFMT_LONG)
				{	SFMBCLR(&mbs);
					for(wsp = (wchar_t*)sp; w > 0; ++wsp, --w)
					{	if((n_s = wcrtomb(buf, *wsp, &mbs)) <= 0)
							break;
						sp = buf; SFwrite(f, sp, n_s);
					}
				}
				else
#endif
					{ SFwrite(f,sp,v); }
				if(n > 0)
					{ SFnputc(f,' ',n); }
				if(!(sp = *++ls))
					break;
				else if(base > 0)
					{ SFputc(f,base); }
			}
			continue;

		case 'C':
			flags = (flags & ~(SFFMT_TYPES|SFFMT_LDOUBLE)) | SFFMT_LONG;
		/* FALLTHROUGH */
		case 'c':
#if _has_multibyte && defined(mbwidth)
			wc = (flags & SFFMT_LDOUBLE) && mbwide();
#endif
			if(precis <= 0) /* # of times to repeat a character */
				precis = 1;
#if _has_multibyte
			if(flags & SFFMT_LONG)
			{	if(base >= 0)
				{	if(!(wsp = (wchar_t*)argv.s) )
						continue;
					for(size = 0; wsp[size]; ++size)
						;
				}
				else
				{	wsp = &argv.wc;
					size = 1;
				}
			}
			else
#endif
			{	if(base >= 0)
				{	if(!(sp = argv.s) )
						continue;
					size = strlen(sp);
				}
				else
				{	argv.c = (char)(argv.i);
					sp = &argv.c;
					size = 1;
				}
			}

			while(size > 0)
			{
#if _has_multibyte
				if(flags&SFFMT_LONG)
				{	SFMBCLR(&mbs);
					if((n_s = wcrtomb(buf, *wsp++, &mbs)) <= 0)
						break;
#ifdef mbwidth
					if(wc)
						n_s = mbwidth(*(wsp - 1));
#endif
					n = width - precis*n_s; /* padding amount */
				}
				else
#endif
				if(flags&SFFMT_ALTER)
				{	n_s = chr2str(buf, *sp++);
					n = width - precis*n_s;
				}
				else
				{	fmt = *sp++;
					n = width - precis;
				}

				if(n > 0 && !(flags&SFFMT_LEFT) )
				{	if(flags&SFFMT_CENTER)
					{	n -= (k = n/2);
						SFnputc(f, ' ', k);
					}
					else
					{	SFnputc(f, ' ', n);
						n = 0;
					}
				}

				v = precis; /* need this because SFnputc may clear it */
#if _has_multibyte
				if(flags&SFFMT_LONG)
				{	for(; v > 0; --v)
						{ ssp = buf; k = n_s; SFwrite(f,ssp,k); }
				}
				else
#endif
				if(flags&SFFMT_ALTER)
				{	for(; v > 0; --v)
						{ ssp = buf; k = n_s; SFwrite(f,ssp,k); }
				}
				else
				{	SFnputc(f, fmt, v);
				}

				if(n > 0)
					{ SFnputc(f,' ',n); };

				if((size -= 1) > 0 && base > 0)
					{ SFputc(f,base); }
			}
			continue;

		case 'n':	/* return current output length */
			SFEND(f);
#if !_ast_intmax_long
			if(size == sizeof(Sflong_t) )
				*((Sflong_t*)argv.vp) = (Sflong_t)n_output;
			else
#endif
			if(size == sizeof(long))
				*((long*)argv.vp) = (long)n_output;
			else if(size == sizeof(short) )
				*((short*)argv.vp) = (short)n_output;
			else if(size == sizeof(uchar) )
				*((uchar*)argv.vp) = (uchar)n_output;
			else	*((int*)argv.vp) = (int)n_output;

			continue;

		case 'p':	/* pointer value */
			fmt = 'x';
			base = 16; n_s = 15; n = 4;
			flags = (flags&~(SFFMT_SIGN|SFFMT_BLANK|SFFMT_ZERO))|SFFMT_ALTER;
#if _more_void_int
			lv = (Sflong_t)((Sfulong_t)argv.vp);
			goto long_cvt;
#else
			v = (int)((uint)argv.vp);
			goto int_cvt;
#endif
		case 'o':
			base = 8; n_s = 7; n = 3;
			flags &= ~(SFFMT_SIGN|SFFMT_BLANK);
			goto int_arg;
		case 'X':
			ssp = "0123456789ABCDEF";
		/* FALLTHROUGH */
		case 'x':
			base = 16; n_s = 15; n = 4;
			flags &= ~(SFFMT_SIGN|SFFMT_BLANK);
			goto int_arg;
		case 'i':
#if _PACKAGE_ast
			if((flags&SFFMT_ALTER) && base < 0)
			{	flags &= ~SFFMT_ALTER;
				scale = 1024;
			}
#endif
			fmt = 'd';
			goto d_format;
		case 'u':
			flags &= ~(SFFMT_SIGN|SFFMT_BLANK);
		/* FALLTHROUGH */
		case 'd':
		d_format:
#if _PACKAGE_ast
			if((flags&SFFMT_ALTER) && base < 0)
			{	flags &= ~SFFMT_ALTER;
				scale = 1000;
			}
#endif
			if(base < 2 || base > SF_RADIX)
				base = 10;
			if((base&(n_s = base-1)) == 0)
			{	if(base < 8)
					n = base <  4 ? 1 : 2;
				else if(base < 32)
					n = base < 16 ? 3 : 4;
				else	n = base < 64 ? 5 : 6;
			}
			else	n_s = base == 10 ? -1 : 0;

		int_arg:
#if !_ast_intmax_long ||  _more_long_int || _more_void_int
			if(size == sizeof(Sflong_t))
			{	lv = argv.ll;
				goto long_cvt;
			}
			else if(sizeof(long) < sizeof(Sflong_t) && size == sizeof(long))
			{	if(fmt == 'd')
					lv = (Sflong_t)argv.l;
				else	lv = (Sflong_t)argv.ul;
			long_cvt:
#if _PACKAGE_ast
				if(scale)
				{	sp = fmtscale(lv, scale);
#if _has_multibyte && defined(mbwidth)
					wc = 0;
#endif
					goto str_cvt;
				}
#endif
				if(lv == 0 && precis == 0)
					break;
				if(lv < 0 && fmt == 'd' )
				{	flags |= SFFMT_MINUS;
					if(lv == HIGHBITL) /* avoid overflow */
					{	lv = (Sflong_t)(HIGHBITL/base);
						*--sp = _Sfdigits[HIGHBITL -
								  ((Sfulong_t)lv)*base];
					}
					else	lv = -lv;
				}
				if(n_s < 0)	/* base 10 */
				{	Sflong_t	nv;
					sfucvt(lv,sp,nv,ssp,Sflong_t,Sfulong_t);
				}
				else if(n_s > 0) /* base power-of-2 */
				{	do
					{	*--sp = ssp[lv&n_s];
					} while((lv = ((Sfulong_t)lv) >> n) );
				}
				else		/* general base */
				{	do
					{	*--sp = ssp[((Sfulong_t)lv)%base];
					} while((lv = ((Sfulong_t)lv)/base) );
				}
			} else
#endif
			if(sizeof(short) < sizeof(int) && size == sizeof(short) )
			{	if(fmt == 'd')
					v = (int)((short)argv.i);
				else	v = (int)((ushort)argv.i);
				goto int_cvt;
			}
			else if(size == sizeof(char))
			{	if(fmt != 'd')
					v = (int)((uchar)argv.i);
				else
				{
#if _key_signed
					v = (int)((signed char)argv.i);
#else
					if(argv.i < 0)
						v = -((int)((char)(-argv.i)));
					else	v =  ((int)((char)( argv.i)));
#endif
				}
				goto int_cvt;
			}
			else
			{	v = argv.i;
			int_cvt:
#if _PACKAGE_ast
				if(scale)
				{	sp = fmtscale(v, scale);
#if _has_multibyte && defined(mbwidth)
					wc = 0;
#endif
					goto str_cvt;
				}
#endif
				if(v == 0 && precis == 0)
					break;
				if(v < 0 && fmt == 'd' )
				{	flags |= SFFMT_MINUS;
					if(v == HIGHBITI) /* avoid overflow */
					{	v = (int)(HIGHBITI/base);
						*--sp = _Sfdigits[HIGHBITI -
								  ((uint)v)*base];
					}
					else	v = -v;
				}
				if(n_s < 0)	/* base 10 */
				{	sfucvt(v,sp,n,ssp,int,uint);
				}
				else if(n_s > 0) /* base power-of-2 */
				{	do
					{	*--sp = ssp[v&n_s];
					} while((v = ((uint)v) >> n) );
				}
				else /* n_s == 0, general base */
				{	do
					{	*--sp = ssp[((uint)v)%base];
					} while((v = ((uint)v)/base) );
				}
			}

			if(n_s < 0 && (flags&SFFMT_THOUSAND) && (n = endsp-sp) > 3)
			{	if((n %= 3) == 0)
					n = 3;
 				for(ep = buf+SLACK, endep = ep + n; ; )
				{	while(ep < endep)
						*ep++ = *sp++;
					if(sp == endsp)
						break;
					if(sp <= endsp-3)
						*ep++ = thousand;
					endep = ep+3;
				}
				sp = buf+SLACK;
				endsp = ep;
			}

			/* zero padding for precision if have room in buffer */
			if(precis > 0 && (precis -= (endsp-sp)) < (sp-buf)-64)
				while(precis-- > 0)
					*--sp = '0';

			if(flags&SFFMT_ALTER) /* prefix */
			{	if(fmt == 'o')
				{	if(*sp != '0')
						*--sp = '0';
				}
				else
				{	if(width > 0 && (flags&SFFMT_ZERO))
					{	/* do 0 padding first */
						if(fmt == 'x' || fmt == 'X')
							n = 0;
						else if(dot < 2)
							n = width;
						else	n = base < 10 ? 2 : 3;
						n += (flags&(SFFMT_MINUS|SFFMT_SIGN)) ?
							1 : 0;
						n = width - (n + (endsp-sp));
						while(n-- > 0)
							*--sp = '0';
					}
					if(fmt == 'x' || fmt == 'X')
					{	*--sp = (char)fmt;
						*--sp = '0';
					}
					else if(dot >= 2)
					{	/* base#value notation */
						*--sp = '#';
						if(base < 10)
							*--sp = (char)('0'+base);
						else
						{	*--sp = _Sfdec[(base <<= 1)+1];
							*--sp = _Sfdec[base];
						}
					}
				}
			}

			break;

		case 'g': case 'G': /* these ultimately become %e or %f */
		case 'a': case 'A':
		case 'e': case 'E':
		case 'f': case 'F':
#if !_ast_fltmax_double
			if(size == sizeof(Sfdouble_t) )
			{	v = SFFMT_LDOUBLE;
				valp = &argv.ld;
				dval = argv.ld;
			}
			else
#endif
			{	v = 0;
				valp = &argv.d;
				dval = argv.d;
			}

			if(fmt == 'e' || fmt == 'E' && (v |= SFFMT_UPPER))
			{	v |= SFFMT_EFORMAT;
				n = (precis = precis < 0 ? FPRECIS : precis)+1;
				ep = _sfcvt(valp,tmp+1,sizeof(tmp)-1, min(n,SF_FDIGITS),
					    &decpt, &sign, &n_s, v);
				goto e_format;
			}
			else if(fmt == 'f' || fmt == 'F' && (v |= SFFMT_UPPER))
			{	precis = precis < 0 ? FPRECIS : precis;
				ep = _sfcvt(valp,tmp+1,sizeof(tmp)-1, min(precis,SF_FDIGITS),
					    &decpt, &sign, &n_s, v);
				goto f_format;
			}
			else if(fmt == 'a' || fmt == 'A' && (v |= SFFMT_UPPER))
			{	v |= SFFMT_AFORMAT;
				if(precis < 0)
				{	if(v & SFFMT_LDOUBLE)
						precis = 2*(sizeof(Sfdouble_t) - 2);
					else	precis = 2*(sizeof(double) - 2);
				}
				n = precis + 1;
				ep = _sfcvt(valp,tmp+1,sizeof(tmp)-1, min(n,SF_FDIGITS),
					    &decpt, &sign, &n_s, v);

				sp = endsp = buf+1;	/* reserve space for sign */
				*endsp++ = '0';
				*endsp++ = fmt == 'a' ? 'x' : 'X';
				if (!isxdigit(*ep))
					goto infinite;
				goto a_format;
			}
			else /* 'g' or 'G' format */
			{	precis = precis < 0 ? FPRECIS : precis == 0 ? 1 : precis;
				if(fmt == 'G')
					v |= SFFMT_UPPER;
				v |= SFFMT_EFORMAT;
				ep = _sfcvt(valp,tmp+1,sizeof(tmp)-1, min(precis,SF_FDIGITS),
					    &decpt, &sign, &n_s, v);
				if(dval == 0.)
					decpt = 1;
				else if(*ep == 'I')
					goto infinite;

				if(!(flags&SFFMT_ALTER))
				{	/* zap trailing 0s */
					if((n = n_s) > precis)
						n = precis;
					while((n -= 1) >= 1 && ep[n] == '0')
						;
					n += 1;
				}
				else	n = precis;

				if(decpt < -3 || decpt > precis)
				{	precis = n-1;
					goto e_format;
				}
				else
				{	precis = n - decpt;
					goto f_format;
				}
			}

		e_format: /* build the x.yyyy string */
			if(isalpha(*ep))
				goto infinite;
			sp = endsp = buf+1;	/* reserve space for sign */
		a_format:
			*endsp++ = *ep ? *ep++ : '0';

			SFSETLOCALE(&decimal,&thousand);
			if(precis > 0 || (flags&SFFMT_ALTER))
				*endsp++ = decimal;
			ssp = endsp;
			endep = ep+precis;
			while((*endsp++ = *ep++) && ep <= endep)
				;
			precis -= (endsp -= 1) - ssp;

			/* build the exponent */
			ep = endep = buf+(sizeof(buf)-1);
			if(dval != 0.)
			{	if((n = decpt - 1) < 0)
					n = -n;
				while(n > 9)
				{	v = n; n /= 10;	
					*--ep = (char)('0' + (v - n*10));
				}
			}
			else	n = 0;
			*--ep = (char)('0' + n);
			if(endep-ep <= 1)	/* at least 2 digits */
				*--ep = '0';

			/* the e/Exponent separator and sign */
			*--ep = (decpt > 0 || dval == 0.) ? '+' : '-';
			*--ep = fmt == 'a' ? 'p' : fmt == 'A' ? 'P' :
				isupper(fmt) ? 'E' : 'e';

			goto end_aefg;

		f_format: /* data before the decimal point */
			if(isalpha(*ep))
			{
			infinite:
				flags &= ~SFFMT_ZERO;
				endsp = (sp = ep)+sfslen();
				ep = endep;
				precis = 0;
				goto end_aefg;
			}

			SFSETLOCALE(&decimal,&thousand);
			endsp = sp = buf+1;	/* save a space for sign */
			endep = ep+decpt;
			if(decpt > 3 && (flags&SFFMT_THOUSAND) )
			{	if((n = decpt%3) == 0)
					n = 3;
				while(ep < endep && (*endsp++ = *ep++) )
				{	if(--n == 0 && (ep <= endep-3) )
					{	*endsp++ = thousand;
						n = 3;
					}
				}
			}
			else
			{	while(ep < endep && (*endsp++ = *ep++))
					;
			}
			if(endsp == sp)
				*endsp++ = '0';

			if(precis > 0 || (flags&SFFMT_ALTER))
				*endsp++ = decimal;

			if((n = -decpt) > 0)
			{	/* output zeros for negative exponent */
				ssp = endsp + min(n,precis);
				precis -= n;
				while(endsp < ssp)
					*endsp++ = '0';
			}

			ssp = endsp;
			endep = ep+precis;
			while((*endsp++ = *ep++) && ep <= endep)
				;
			precis -= (endsp -= 1) - ssp;
			ep = endep;
		end_aefg:
			flags |= SFFMT_FLOAT;
			if(sign)
				flags |= SFFMT_MINUS;
			break;
		}

		if(flags == 0 && width <= 0)
			goto do_output;

		if(flags&SFFMT_PREFIX)
			fmt = (flags&SFFMT_MINUS) ? '-' : (flags&SFFMT_SIGN) ? '+' : ' ';

		n = (endsp-sp) + (endep-ep) + (precis <= 0 ? 0 : precis) +
		    ((flags&SFFMT_PREFIX) ? 1 : 0);
		if((v = width-n) <= 0)
			v = 0;
		else if(!(flags&SFFMT_ZERO)) /* right padding */
		{	if(flags&SFFMT_LEFT)
				v = -v;
			else if(flags&SFFMT_PREFIX) /* blank padding, output prefix now */
			{	*--sp = fmt;
				flags &= ~SFFMT_PREFIX;
			}
		}

		if(flags&SFFMT_PREFIX) /* put out the prefix */
		{	SFputc(f,fmt);
			if(fmt != ' ')
				flags |= SFFMT_ZERO;
		}

		if((n = v) > 0) /* left padding */
		{	v = (flags&SFFMT_ZERO) ? '0' : ' ';
			SFnputc(f,v,n);
		}

		if((n = precis) > 0 && !(flags&SFFMT_FLOAT))
		{	/* padding for integer precision */
			SFnputc(f,'0',n);
			precis = 0;
		}

	do_output:
		if((n = endsp-sp) > 0)
			SFwrite(f,sp,n);

		if(flags&(SFFMT_FLOAT|SFFMT_LEFT))
		{	/* SFFMT_FLOAT: right padding for float precision */
			if((n = precis) > 0)
				SFnputc(f,'0',n);

			/* SFFMT_FLOAT: the exponent of %eE */
			if((n = endep - (sp = ep)) > 0)
				SFwrite(f,sp,n);

			/* SFFMT_LEFT: right padding */
			if((n = -v) > 0)
				{ SFnputc(f,' ',n); }
		}
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

	SFEND(f);

	n = f->next - f->data;
	if((sp = (char*)f->data) == data)
		f->endw = f->endr = f->endb = f->data = NIL(uchar*);
	f->next = f->data;

	if((((flags = f->flags)&SF_SHARE) && !(flags&SF_PUBLIC) ) ||
	   (n > 0 && (sp == data || (flags&SF_LINE) ) ) )
		(void)SFWRITE(f,(Void_t*)sp,n);
	else	f->next += n;

	SFOPEN(f,0);
	SFMTXRETURN(f, n_output);
}
