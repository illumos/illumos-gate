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
#include	"FEATURE/float"

/*	Dealing with $ argument addressing stuffs.
**
**	Written by Kiem-Phong Vo.
*/

#if __STD_C
static char* sffmtint(const char* str, int* v)
#else
static char* sffmtint(str, v)
char*	str;
int*	v;
#endif
{	
	for(*v = 0; isdigit(*str); ++str)
		*v = *v * 10 + (*str - '0');
	*v -= 1;
	return (char*)str;
}

#if __STD_C
static Fmtpos_t* sffmtpos(Sfio_t* f,const char* form,va_list args,Sffmt_t* ft,int type)
#else
static Fmtpos_t* sffmtpos(f,form,args,ft,type)
Sfio_t*		f;
char*		form;
va_list		args;
Sffmt_t*	ft;
int		type;	/* >0: scanf, =0: printf, -1: internal	*/
#endif
{
	int		base, fmt, flags, dot, width, precis;
	ssize_t		n_str, size;
	char		*t_str, *sp;
	int		v, n, skip, dollar, decimal, thousand;
	Sffmt_t		savft;
	Fmtpos_t*	fp;	/* position array of arguments	*/
	int		argp, argn, maxp, need[FP_INDEX];
#if _has_multibyte
	SFMBDCL(fmbs)
#endif

	if(type < 0)
		fp = NIL(Fmtpos_t*);
	else if(!(fp = sffmtpos(f,form,args,ft,-1)) )
		return NIL(Fmtpos_t*);

	dollar = decimal = thousand = 0; argn = maxp = -1;
	SFMBCLR(&fmbs);
	while((n = *form) )
	{	if(n != '%') /* collect the non-pattern chars */
		{	sp = (char*)form;
			for(;;)
			{	form += SFMBLEN(form, &fmbs);
				if(*form == 0 || *form == '%')
					break;
			}
			continue;
		}
		else	form += 1;
		if(*form == 0)
			break;
		else if(*form == '%')
		{	form += 1;
			continue;
		}

		if(*form == '*' && type > 0) /* skip in scanning */
		{	skip = 1;
			form += 1;
			argp = -1;
		}
		else /* get the position of this argument */
		{	skip = 0;
			sp = sffmtint(form,&argp);
			if(*sp == '$')
			{	dollar = 1;
				form = sp+1;
			}
			else	argp = -1;
		}

		flags = dot = 0;
		t_str = NIL(char*); n_str = 0;
		size = width = precis = base = -1;
		for(n = 0; n < FP_INDEX; ++n)
			need[n] = -1;

	loop_flags:	/* LOOP FOR \0, %, FLAGS, WIDTH, PRECISION, BASE, TYPE */
		switch((fmt = *form++) )
		{
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
					n_str = form-t_str;
					if(*t_str == '*')
					{	t_str = sffmtint(t_str+1,&n);
						if(*t_str == '$')
							dollar = 1;
						else	n = -1;
						if((n = FP_SET(n,argn)) > maxp)
							maxp = n;
						if(fp && fp[n].ft.fmt == 0)
						{	fp[n].ft.fmt = LEFTP;
							fp[n].ft.form = (char*)form;
						}
						need[FP_STR] = n;
					}
					goto loop_flags;
				}
			}

		case '-' :
			flags |= SFFMT_LEFT;
			flags &= ~SFFMT_ZERO;
			goto loop_flags;
		case '0' :
			if(!(flags&SFFMT_LEFT) )
				flags |= SFFMT_ZERO;
			goto loop_flags;
		case ' ' :
			if(!(flags&SFFMT_SIGN) )
				flags |= SFFMT_BLANK;
			goto loop_flags;
		case '+' :
			flags |= SFFMT_SIGN;
			flags &= ~SFFMT_BLANK;
			goto loop_flags;
		case '#' :
			flags |= SFFMT_ALTER;
			goto loop_flags;
		case QUOTE:
			SFSETLOCALE(&decimal,&thousand);
			if(thousand > 0)
				flags |= SFFMT_THOUSAND;
			goto loop_flags;

		case '.' :
			if((dot += 1) == 2)
				base = 0; /* for %s,%c */
			if(isdigit(*form))
			{	fmt = *form++;
				goto dot_size;
			}
			else if(*form != '*')
				goto loop_flags;
			else	form += 1; /* drop thru below */
			/* FALLTHROUGH */
		case '*' :
			form = sffmtint(form,&n);
			if(*form == '$' )
			{	dollar = 1;
				form += 1;
			}
			else	n = -1;
			if((n = FP_SET(n,argn)) > maxp)
				maxp = n;
			if(fp && fp[n].ft.fmt == 0)
			{	fp[n].ft.fmt = '.';
				fp[n].ft.size = dot;
				fp[n].ft.form = (char*)form;
			}
			if(dot <= 2)
				need[dot] = n;
			goto loop_flags;

		case '1' : case '2' : case '3' :
		case '4' : case '5' : case '6' :
		case '7' : case '8' : case '9' :
		dot_size :
			for(v = fmt - '0', fmt = *form; isdigit(fmt); fmt = *++form)
				v = v*10 + (fmt - '0');
			if(dot == 0)
				width = v;
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
			{	form = sffmtint(form+1,&n);
				if(*form == '$' )
				{	dollar = 1;
					form += 1;
				}
				else	n = -1;
				if((n = FP_SET(n,argn)) > maxp)
					maxp = n;
				if(fp && fp[n].ft.fmt == 0)
				{	fp[n].ft.fmt = 'I';
					fp[n].ft.size = sizeof(int);
					fp[n].ft.form = (char*)form;
				}
				need[FP_SIZE] = n;
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

		if(skip)
			continue;

		if((argp = FP_SET(argp,argn)) > maxp)
			maxp = argp;

		if(dollar && fmt == '!')
			return NIL(Fmtpos_t*);

		if(fp && fp[argp].ft.fmt == 0)
		{	fp[argp].ft.form = (char*)form;
			fp[argp].ft.fmt = fp[argp].fmt = fmt;
			fp[argp].ft.size = size;
			fp[argp].ft.flags = flags;
			fp[argp].ft.width = width;
			fp[argp].ft.precis = precis;
			fp[argp].ft.base = base;
			fp[argp].ft.t_str = t_str;
			fp[argp].ft.n_str = n_str;
			for(n = 0; n < FP_INDEX; ++n)
				fp[argp].need[n] = need[n];
		}
	}

	if(!fp) /* constructing position array only */
	{	if(!dollar || !(fp = (Fmtpos_t*)malloc((maxp+1)*sizeof(Fmtpos_t))) )
			return NIL(Fmtpos_t*);
		for(n = 0; n <= maxp; ++n)
			fp[n].ft.fmt = 0;
		return fp;
	}

	/* get value for positions */
	if(ft)
		memcpy(&savft, ft, sizeof(*ft));
	for(n = 0; n <= maxp; ++n)
	{	if(fp[n].ft.fmt == 0) /* gap: pretend it's a 'd' pattern */
		{	fp[n].ft.fmt = 'd';
			fp[n].ft.width = 0;
			fp[n].ft.precis = 0;
			fp[n].ft.base = 0;
			fp[n].ft.size = 0;
			fp[n].ft.t_str = 0;
			fp[n].ft.n_str = 0;
			fp[n].ft.flags = 0;
			for(v = 0; v < FP_INDEX; ++v)
				fp[n].need[v] = -1;
		}

		if(ft && ft->extf)
		{	fp[n].ft.version = ft->version;
			fp[n].ft.extf = ft->extf;
			fp[n].ft.eventf = ft->eventf;
			if((v = fp[n].need[FP_WIDTH]) >= 0 && v < n)
				fp[n].ft.width = fp[v].argv.i;
			if((v = fp[n].need[FP_PRECIS]) >= 0 && v < n)
				fp[n].ft.precis = fp[v].argv.i;
			if((v = fp[n].need[FP_BASE]) >= 0 && v < n)
				fp[n].ft.base = fp[v].argv.i;
			if((v = fp[n].need[FP_STR]) >= 0 && v < n)
				fp[n].ft.t_str = fp[v].argv.s;
			if((v = fp[n].need[FP_SIZE]) >= 0 && v < n)
				fp[n].ft.size = fp[v].argv.i;

			memcpy(ft,&fp[n].ft,sizeof(Sffmt_t));
			va_copy(ft->args,args);
			ft->flags |= SFFMT_ARGPOS;
			v = (*ft->extf)(f, (Void_t*)(&fp[n].argv), ft);
			va_copy(args,ft->args);
			memcpy(&fp[n].ft,ft,sizeof(Sffmt_t));
			if(v < 0)
			{	memcpy(ft,&savft,sizeof(Sffmt_t));
				ft = NIL(Sffmt_t*);
			}

			if(!(fp[n].ft.flags&SFFMT_VALUE) )
				goto arg_list;
			else if(_Sftype[fp[n].ft.fmt]&(SFFMT_INT|SFFMT_UINT) )
			{	if(fp[n].ft.size == sizeof(short))
				{	if(_Sftype[fp[n].ft.fmt]&SFFMT_INT)
						fp[n].argv.i = fp[n].argv.h;
					else	fp[n].argv.i = fp[n].argv.uh;
				}
				else if(fp[n].ft.size == sizeof(char))
				{	if(_Sftype[fp[n].ft.fmt]&SFFMT_INT)
						fp[n].argv.i = fp[n].argv.c;
					else	fp[n].argv.i = fp[n].argv.uc;
				}
			}
			else if(_Sftype[fp[n].ft.fmt]&SFFMT_FLOAT )
			{	if(fp[n].ft.size == sizeof(float) )
					fp[n].argv.d = fp[n].argv.f;
			}
		}
		else
		{ arg_list:
			if(fp[n].ft.fmt == LEFTP)
			{	fp[n].argv.s = va_arg(args, char*);
				fp[n].ft.size = strlen(fp[n].argv.s);
			}
			else if(fp[n].ft.fmt == '.' || fp[n].ft.fmt == 'I')
				fp[n].argv.i = va_arg(args, int);
			else if(fp[n].ft.fmt == '!')
			{	if(ft)
					memcpy(ft,&savft,sizeof(Sffmt_t));
				fp[n].argv.ft = ft = va_arg(args, Sffmt_t*);
				if(ft->form)
					ft = NIL(Sffmt_t*);
				if(ft)
					memcpy(&savft,ft,sizeof(Sffmt_t));
			}
			else if(type > 0) /* from sfvscanf */
				fp[n].argv.vp = va_arg(args, Void_t*);
			else switch(_Sftype[fp[n].ft.fmt])
			{ case SFFMT_INT:
			  case SFFMT_UINT:
#if !_ast_intmax_long
				if(size == sizeof(Sflong_t) )
					fp[n].argv.ll = va_arg(args, Sflong_t);
				else
#endif
				if(size == sizeof(long) )
					fp[n].argv.l = va_arg(args, long);
				else	fp[n].argv.i = va_arg(args, int);
				break;
			  case SFFMT_FLOAT:
#if !_ast_fltmax_double
				if(size == sizeof(Sfdouble_t) )
					fp[n].argv.ld = va_arg(args,Sfdouble_t);
				else
#endif
					fp[n].argv.d  = va_arg(args,double);
				break;
	 		  case SFFMT_POINTER:
					fp[n].argv.vp = va_arg(args,Void_t*);
				break;
			  case SFFMT_CHAR:
				if(fp[n].ft.base >= 0)
					fp[n].argv.s = va_arg(args,char*);
#if _has_multibyte
				else if((fp[n].ft.flags & SFFMT_LONG) ||
					fp[n].ft.fmt == 'C' )
				{	if(sizeof(wchar_t) <= sizeof(int) )
					     fp[n].argv.wc = (wchar_t)va_arg(args,int);
					else fp[n].argv.wc = va_arg(args,wchar_t);
				}
#endif
					/* observe promotion rule */
				else	fp[n].argv.i = va_arg(args,int);
				break;
			  default: /* unknown pattern */
				break;
			}
		}
	}

	if(ft)
		memcpy(ft,&savft,sizeof(Sffmt_t));
	return fp;
}

static const unsigned char	flt_nan[] = { _ast_flt_nan_init };
static const unsigned char	flt_inf[] = { _ast_flt_inf_init };
static const unsigned char	dbl_nan[] = { _ast_dbl_nan_init };
static const unsigned char	dbl_inf[] = { _ast_dbl_inf_init };
#ifdef _ast_ldbl_nan_init
static const unsigned char	ldbl_nan[] = { _ast_ldbl_nan_init };
static const unsigned char	ldbl_inf[] = { _ast_ldbl_inf_init };
#endif

/* function to initialize conversion tables */
static int sfcvinit()
{	reg int		d, l;

	for(d = 0; d <= SF_MAXCHAR; ++d)
	{	_Sfcv36[d] = SF_RADIX;
		_Sfcv64[d] = SF_RADIX;
	}

	/* [0-9] */
	for(d = 0; d < 10; ++d)
	{	_Sfcv36[(uchar)_Sfdigits[d]] = d;
		_Sfcv64[(uchar)_Sfdigits[d]] = d;
	}

	/* [a-z] */
	for(; d < 36; ++d)
	{	_Sfcv36[(uchar)_Sfdigits[d]] = d;
		_Sfcv64[(uchar)_Sfdigits[d]] = d;
	}

	/* [A-Z] */
	for(l = 10; d < 62; ++l, ++d)
	{	_Sfcv36[(uchar)_Sfdigits[d]] = l;
		_Sfcv64[(uchar)_Sfdigits[d]] = d;
	}

	/* remaining digits */
	for(; d < SF_RADIX; ++d)
	{	_Sfcv36[(uchar)_Sfdigits[d]] = d;
		_Sfcv64[(uchar)_Sfdigits[d]] = d;
	}

	_Sftype['d'] = _Sftype['i'] = SFFMT_INT;
	_Sftype['u'] = _Sftype['o'] = _Sftype['x'] = _Sftype['X'] = SFFMT_UINT;
	_Sftype['e'] = _Sftype['E'] = _Sftype['a'] = _Sftype['A'] =
	_Sftype['g'] = _Sftype['G'] = _Sftype['f'] = SFFMT_FLOAT;
	_Sftype['s'] = _Sftype['n'] = _Sftype['p'] = _Sftype['!'] = SFFMT_POINTER;
	_Sftype['c'] = SFFMT_CHAR;
	_Sftype['['] = SFFMT_CLASS;
#if _has_multibyte
	_Sftype['S'] = SFFMT_POINTER;
	_Sftype['C'] = SFFMT_CHAR;
#endif

	/* IEEE floating point computed constants */

	memcpy((char*)&_Sffnan, (char*)flt_nan, sizeof(_Sffnan));
	memcpy((char*)&_Sffinf, (char*)flt_inf, sizeof(_Sffinf));
	memcpy((char*)&_Sfdnan, (char*)dbl_nan, sizeof(_Sfdnan));
	memcpy((char*)&_Sfdinf, (char*)dbl_inf, sizeof(_Sfdinf));
#ifdef _ast_ldbl_nan_init
	memcpy((char*)&_Sflnan, (char*)ldbl_nan, sizeof(_Sflnan));
	memcpy((char*)&_Sflinf, (char*)ldbl_inf, sizeof(_Sflinf));
#else
	memcpy((char*)&_Sflnan, (char*)dbl_nan, sizeof(_Sfdnan));
	memcpy((char*)&_Sflinf, (char*)dbl_inf, sizeof(_Sfdinf));
#endif

	return 1;
}

/* table for floating point and integer conversions */
#include	"FEATURE/sfinit"
