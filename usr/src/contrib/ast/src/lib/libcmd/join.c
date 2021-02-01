/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2012 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * David Korn
 * Glenn Fowler
 * AT&T Research
 *
 * join
 */

static const char usage[] =
"[-?\n@(#)$Id: join (AT&T Research) 2009-12-10 $\n]"
USAGE_LICENSE
"[+NAME?join - relational database operator]"
"[+DESCRIPTION?\bjoin\b performs an \aequality join\a on the files \afile1\a "
	"and \afile2\a and writes the resulting joined files to standard "
	"output.  By default, a field is delimited by one or more spaces "
	"and tabs with leading spaces and/or tabs ignored.  The \b-t\b option "
	"can be used to change the field delimiter.]"
"[+?The \ajoin field\a is a field in each file on which files are compared. "
	"By default \bjoin\b writes one line in the output for each pair "
	"of lines in \afiles1\a and \afiles2\a that have identical join "
	"fields.  The default output line consists of the join field, "
	"then the remaining fields from \afile1\a, then the remaining "
	"fields from \afile2\a, but this can be changed with the \b-o\b "
	"option.  The \b-a\b option can be used to add unmatched lines "
	"to the output.  The \b-v\b option can be used to output only "
	"unmatched lines.]"
"[+?The files \afile1\a and \afile2\a must be ordered in the collating "
	"sequence of \bsort -b\b on the fields on which they are to be "
	"joined otherwise the results are unspecified.]"
"[+?If either \afile1\a or \afile2\a is \b-\b, \bjoin\b "
        "uses standard input starting at the current location.]"

"[e:empty]:[string?Replace empty output fields in the list selected with"
"	\b-o\b with \astring\a.]"
"[o:output]:[list?Construct the output line to comprise the fields specified "
	"in a blank or comma separated list \alist\a.  Each element in "
	"\alist\a consists of a file number (either 1 or 2), a period, "
	"and a field number or \b0\b representing the join field.  "
	"As an obsolete feature multiple occurrences of \b-o\b can "
	"be specified.]"
"[t:separator|tabs]:[delim?Use \adelim\a as the field separator for both input"
"	and output.]"
"[1:j1]#[field?Join on field \afield\a of \afile1\a.  Fields start at 1.]"
"[2:j2]#[field?Join on field \afield\a of \afile2\a.  Fields start at 1.]"
"[j:join]#[field?Equivalent to \b-1\b \afield\a \b-2\b \afield\a.]"
"[a:unpairable]#[fileno?Write a line for each unpairable line in file"
"	\afileno\a, where \afileno\a is either 1 or 2, in addition to the"
"	normal output.  If \b-a\b options appear for both 1 and 2, then "
	"all unpairable lines will be output.]"
"[v:suppress]#[fileno?Write a line for each unpairable line in file"
"	\afileno\a, where \afileno\a is either 1 or 2, instead of the normal "
	"output.  If \b-v\b options appear for both 1 and 2, then "
	"all unpairable lines will be output.] ]"
"[i:ignorecase?Ignore case in field comparisons.]"
"[B!:mmap?Enable memory mapped reads instead of buffered.]"

"[+?The following obsolete option forms are also recognized: \b-j\b \afield\a"
"	is equivalent to \b-1\b \afield\a \b-2\b \afield\a, \b-j1\b \afield\a"
"	is equivalent to \b-1\b \afield\a, and \b-j2\b \afield\a is"
"	equivalent to \b-2\b \afield\a.]"

"\n"
"\nfile1 file2\n"
"\n"
"[+EXIT STATUS?]{"
	"[+0?Both files processed successfully.]"
	"[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bcut\b(1), \bcomm\b(1), \bpaste\b(1), \bsort\b(1), \buniq\b(1)]"
;

#include <cmd.h>
#include <sfdisc.h>

#if _hdr_wchar && _hdr_wctype && _lib_iswctype

#include <wchar.h>
#include <wctype.h>

#else

#include <ctype.h>

#ifndef iswspace
#define iswspace(x)	isspace(x)
#endif

#endif

#define C_FILE1		001
#define C_FILE2		002
#define C_COMMON	004
#define C_ALL		(C_FILE1|C_FILE2|C_COMMON)

#define NFIELD		10
#define JOINFIELD	2

#define S_DELIM		1
#define S_SPACE		2
#define S_NL		3
#define S_WIDE		4

typedef struct Field_s
{
	char*		beg;
	char*		end;
} Field_t;

typedef struct File_s
{
	Sfio_t*		iop;
	char*		name;
	char*		recptr;
	int		reclen;
	int		field;
	int		fieldlen;
	int		nfields;
	int		maxfields;
	int		spaces;
	int		hit;
	int		discard;
	Field_t*	fields;
} File_t;

typedef struct Join_s
{
	unsigned char	state[1<<CHAR_BIT];
	Sfio_t*		outfile;
	int*		outlist;
	int		outmode;
	int		ooutmode;
	char*		nullfield;
	char*		delimstr;
	int		delim;
	int		delimlen;
	int		buffered;
	int		ignorecase;
	int		mb;
	char*		same;
	int		samesize;
	Shbltin_t*	context;
	File_t		file[2];
} Join_t;

static void
done(register Join_t* jp)
{
	if (jp->file[0].iop && jp->file[0].iop != sfstdin)
		sfclose(jp->file[0].iop);
	if (jp->file[1].iop && jp->file[1].iop != sfstdin)
		sfclose(jp->file[1].iop);
	if (jp->outlist)
		free(jp->outlist);
	if (jp->file[0].fields)
		free(jp->file[0].fields);
	if (jp->file[1].fields)
		free(jp->file[1].fields);
	if (jp->same)
		free(jp->same);
	free(jp);
}

static Join_t*
init(void)
{
	register Join_t*	jp;
	register int		i;

	setlocale(LC_ALL, "");
	if (jp = newof(0, Join_t, 1, 0))
	{
		if (jp->mb = mbwide())
			for (i = 0x80; i <= 0xff; i++)
				jp->state[i] = S_WIDE;
		jp->state[' '] = jp->state['\t'] = S_SPACE;
		jp->state['\n'] = S_NL;
		jp->delim = -1;
		jp->nullfield = 0;
		if (!(jp->file[0].fields = newof(0, Field_t, NFIELD + 1, 0)) ||
		    !(jp->file[1].fields = newof(0, Field_t, NFIELD + 1, 0)))
		{
			done(jp);
			return 0;
		}
		jp->file[0].maxfields = NFIELD;
		jp->file[1].maxfields = NFIELD;
		jp->outmode = C_COMMON;
	}
	return jp;
}

static int
getolist(Join_t* jp, const char* first, char** arglist)
{
	register const char*	cp = first;
	char**			argv = arglist;
	register int		c;
	int*			outptr;
	int*			outmax;
	int			nfield = NFIELD;
	char*			str;

	outptr = jp->outlist = newof(0, int, NFIELD + 1, 0);
	outmax = outptr + NFIELD;
	while (c = *cp++)
	{
		if (c==' ' || c=='\t' || c==',')
			continue;
		str = (char*)--cp;
		if (*cp=='0' && ((c=cp[1])==0 || c==' ' || c=='\t' || c==','))
		{
			str++;
			c = JOINFIELD;
			goto skip;
		}
		if (cp[1]!='.' || (*cp!='1' && *cp!='2') || (c=strtol(cp+2,&str,10)) <=0)
		{
			error(2,"%s: invalid field list",first);
			break;
		}
		c--;
		c <<=2;
		if (*cp=='2')
			c |=1;
	skip:
		if (outptr >= outmax)
		{
			jp->outlist = newof(jp->outlist, int, 2 * nfield + 1, 0);
			outptr = jp->outlist + nfield;
			nfield *= 2;
			outmax = jp->outlist + nfield;
		}
		*outptr++ = c;
		cp = str;
	}
	/* need to accept obsolescent command syntax */
	while (cp = *argv)
	{
		if (cp[1]!='.' || (*cp!='1' && *cp!='2'))
		{
			if (*cp=='0' && cp[1]==0)
			{
				c = JOINFIELD;
				goto skip2;
			}
			break;
		}
		str = (char*)cp;
		c = strtol(cp+2, &str,10);
		if (*str || --c<0)
			break;
		argv++;
		c <<= 2;
		if (*cp=='2')
			c |=1;
	skip2:
		if (outptr >= outmax)
		{
			jp->outlist = newof(jp->outlist, int, 2 * nfield + 1, 0);
			outptr = jp->outlist + nfield;
			nfield *= 2;
			outmax = jp->outlist + nfield;
		}
		*outptr++ = c;
	}
	*outptr = -1;
	return argv-arglist;
}

/*
 * read in a record from file <index> and split into fields
 */
static unsigned char*
getrec(Join_t* jp, int index, int discard)
{
	register unsigned char*	sp = jp->state;
	register File_t*	fp = &jp->file[index];
	register Field_t*	field = fp->fields;
	register Field_t*	fieldmax = field + fp->maxfields;
	register char*		cp;
	register int		n;
	char*			tp;

	if (sh_checksig(jp->context))
		return 0;
	if (discard && fp->discard)
		sfraise(fp->iop, SFSK_DISCARD, NiL);
	fp->spaces = 0;
	fp->hit = 0;
	if (!(cp = sfgetr(fp->iop, '\n', 0)))
	{
		jp->outmode &= ~(1<<index);
		return 0;
	}
	fp->recptr = cp;
	fp->reclen = sfvalue(fp->iop);
	if (jp->delim == '\n')	/* handle new-line delimiter specially */
	{
		field->beg = cp;
		cp += fp->reclen;
		field->end = cp - 1;
		field++;
	}
	else
		do /* separate into fields */
		{
			if (field >= fieldmax)	
			{
				n = 2 * fp->maxfields;
				fp->fields = newof(fp->fields, Field_t, n + 1, 0);
				field = fp->fields + fp->maxfields;
				fp->maxfields = n;
				fieldmax = fp->fields + n;
			}
			field->beg = cp;
			if (jp->delim == -1)
			{
				switch (sp[*(unsigned char*)cp])
				{
				case S_SPACE:
					cp++;
					break;
				case S_WIDE:
					tp = cp;
					if (iswspace(mbchar(tp)))
					{
						cp = tp;
						break;
					}
					/*FALLTHROUGH*/
				default:
					goto next;
				}
				fp->spaces = 1;
				if (jp->mb)
					for (;;)
					{
						switch (sp[*(unsigned char*)cp++])
						{
						case S_SPACE:
							continue;
						case S_WIDE:
							tp = cp - 1;
							if (iswspace(mbchar(tp)))
							{
								cp = tp;
								continue;
							}
							break;
						}
						break;
					}
				else
					while (sp[*(unsigned char*)cp++]==S_SPACE);
				cp--;
			}
		next:
			if (jp->mb)
			{
				for (;;)
				{
					tp = cp;
					switch (n = sp[*(unsigned char*)cp++])
					{
					case 0:
						continue;
					case S_WIDE:
						cp--;
						n = mbchar(cp);
						if (n == jp->delim)
						{
							n = S_DELIM;
							break;
						}
						if (jp->delim == -1 && iswspace(n))
						{
							n = S_SPACE;
							break;
						}
						continue;
					}
					break;
				}
				field->end = tp;
			}
			else
			{
				while (!(n = sp[*(unsigned char*)cp++]));
				field->end = cp - 1;
			}
			field++;
		} while (n != S_NL);
	fp->nfields = field - fp->fields;
	if ((n = fp->field) < fp->nfields)
	{
		cp = fp->fields[n].beg;
		/* eliminate leading spaces */
		if (fp->spaces)
		{
			if (jp->mb)
				for (;;)
				{
					switch (sp[*(unsigned char*)cp++])
					{
					case S_SPACE:
						continue;
					case S_WIDE:
						tp = cp - 1;
						if (iswspace(mbchar(tp)))
						{
							cp = tp;
							continue;
						}
						break;
					}
					break;
				}
			else
				while (sp[*(unsigned char*)cp++]==S_SPACE);
			cp--;
		}
		fp->fieldlen = fp->fields[n].end - cp;
		return (unsigned char*)cp;
	}
	fp->fieldlen = 0;
	return (unsigned char*)"";
}

#if DEBUG_TRACE
static unsigned char* u1;
#define getrec(p,n,d)	(u1 = getrec(p, n, d), sfprintf(sfstdout, "[G%d#%d@%I*d:%-.8s]", __LINE__, n, sizeof(Sfoff_t), sftell(p->file[n].iop), u1), u1)
#endif

/*
 * print field <n> from file <index>
 */
static int
outfield(Join_t* jp, int index, register int n, int last)
{
	register File_t*	fp = &jp->file[index];
	register char*		cp;
	register char*		cpmax;
	register int		size;
	register Sfio_t*	iop = jp->outfile;
	char*			tp;

	if (n < fp->nfields)
	{
		cp = fp->fields[n].beg;
		cpmax = fp->fields[n].end + 1;
	}
	else
		cp = 0;
	if ((n = jp->delim) == -1)
	{
		if (cp && fp->spaces)
		{
			register unsigned char*	sp = jp->state;

			/*eliminate leading spaces */
			if (jp->mb)
				for (;;)
				{
					switch (sp[*(unsigned char*)cp++])
					{
					case S_SPACE:
						continue;
					case S_WIDE:
						tp = cp - 1;
						if (iswspace(mbchar(tp)))
						{
							cp = tp;
							continue;
						}
						break;
					}
					break;
				}
			else
				while (sp[*(unsigned char*)cp++]==S_SPACE);
			cp--;
		}
		n = ' ';
	}
	else if (jp->delimstr)
		n = -1;
	if (last)
		n = '\n';
	if (cp)
		size = cpmax - cp;
	else
		size = 0;
	if (n == -1)
	{
		if (size<=1)
		{
			if (jp->nullfield && sfputr(iop, jp->nullfield, -1) < 0)
				return -1;
		}
		else if (sfwrite(iop, cp, size) < 0)
			return -1;
		if (sfwrite(iop, jp->delimstr, jp->delimlen) < 0)
			return -1;
	}
	else if (size <= 1)
	{
		if (!jp->nullfield)
			sfputc(iop, n);
		else if (sfputr(iop, jp->nullfield, n) < 0)
			return -1;
	}
	else
	{
		last = cp[size-1];
		cp[size-1] = n;
		if (sfwrite(iop, cp, size) < 0)
			return -1;
		cp[size-1] = last;
	}
	return 0;
}

#if DEBUG_TRACE
static int i1,i2,i3;
#define outfield(p,i,n,f)	(sfprintf(sfstdout, "[F%d#%d:%d,%d]", __LINE__, i1=i, i2=n, i3=f), outfield(p, i1, i2, i3))
#endif

static int
outrec(register Join_t* jp, int mode)
{
	register File_t*	fp;
	register int		i;
	register int		j;
	register int		k;
	register int		n;
	int*			out;

	if (mode < 0 && jp->file[0].hit++)
		return 0;
	if (mode > 0 && jp->file[1].hit++)
		return 0;
	if (out = jp->outlist)
	{
		while ((n = *out++) >= 0)
		{
			if (n == JOINFIELD)
			{
				i = mode >= 0;
				j = jp->file[i].field;
			}
			else
			{
				i = n & 1;
				j = (mode<0 && i || mode>0 && !i) ?
					jp->file[i].nfields :
					n >> 2;
			}
			if (outfield(jp, i, j, *out < 0) < 0)
				return -1;
		}
		return 0;
	}
	k = jp->file[0].nfields;
	if (mode >= 0)
		k += jp->file[1].nfields - 1;
	for (i=0; i<2; i++)
	{
		fp = &jp->file[i];
		if (mode>0 && i==0)
		{
			k -= (fp->nfields - 1);
			continue;
		}
		n = fp->field;
		if (mode||i==0)
		{
			/* output join field first */
			if (outfield(jp,i,n,!--k) < 0)
				return -1;
			if (!k)
				return 0;
			for (j=0; j<n; j++)
			{
				if (outfield(jp,i,j,!--k) < 0)
					return -1;
				if (!k)
					return 0;
			}
			j = n + 1;
		}
		else
			j = 0;
		for (;j<fp->nfields; j++)
		{
			if (j!=n && outfield(jp,i,j,!--k) < 0)
				return -1;
			if (!k)
				return 0;
		}
	}
	return 0;
}

#if DEBUG_TRACE
#define outrec(p,n)	(sfprintf(sfstdout, "[R#%d,%d,%lld,%lld:%-.*s{%d}:%-.*s{%d}]", __LINE__, i1=n, lo, hi, jp->file[0].fieldlen, cp1, jp->file[0].hit, jp->file[1].fieldlen, cp2, jp->file[1].hit), outrec(p, i1))
#endif

static int
join(Join_t* jp)
{
	register unsigned char*	cp1;
	register unsigned char*	cp2;
	register int		n1;
	register int		n2;
	register int		n;
	register int		cmp;
	register int		same;
	int			o2;
	Sfoff_t			lo = -1;
	Sfoff_t			hi = -1;

	if ((cp1 = getrec(jp, 0, 0)) && (cp2 = getrec(jp, 1, 0)) || (cp2 = 0))
	{
		n1 = jp->file[0].fieldlen;
		n2 = jp->file[1].fieldlen;
		same = 0;
		for (;;)
		{
			n = n1 < n2 ? n1 : n2;
#if DEBUG_TRACE
			if (!n && !(cmp = n1 < n2 ? -1 : (n1 > n2)) || n && !(cmp = (int)*cp1 - (int)*cp2) && !(cmp = jp->ignorecase ? strncasecmp((char*)cp1, (char*)cp2, n) : memcmp(cp1, cp2, n)))
				cmp = n1 - n2;
sfprintf(sfstdout, "[C#%d:%d(%c-%c),%d,%lld,%lld%s]", __LINE__, cmp, *cp1, *cp2, same, lo, hi, (jp->outmode & C_COMMON) ? ",COMMON" : "");
			if (!cmp)
#else
			if (!n && !(cmp = n1 < n2 ? -1 : (n1 > n2)) || n && !(cmp = (int)*cp1 - (int)*cp2) && !(cmp = jp->ignorecase ? strncasecmp((char*)cp1, (char*)cp2, n) : memcmp(cp1, cp2, n)) && !(cmp = n1 - n2))
#endif
			{
				if (!(jp->outmode & C_COMMON))
				{
					if (cp1 = getrec(jp, 0, 1))
					{
						n1 = jp->file[0].fieldlen;
						same = 1;
						continue;
					}
					if ((jp->ooutmode & (C_FILE1|C_FILE2)) != C_FILE2)
						break;
					if (sfseek(jp->file[0].iop, (Sfoff_t)-jp->file[0].reclen, SEEK_CUR) < 0 || !(cp1 = getrec(jp, 0, 0)))
					{
						error(ERROR_SYSTEM|2, "%s: seek error", jp->file[0].name);
						return -1;
					}
				}
				else if (outrec(jp, 0) < 0)
					return -1;
				else if (lo < 0 && (jp->outmode & C_COMMON))
				{
					if ((lo = sfseek(jp->file[1].iop, (Sfoff_t)0, SEEK_CUR)) < 0)
					{
						error(ERROR_SYSTEM|2, "%s: seek error", jp->file[1].name);
						return -1;
					}
					lo -= jp->file[1].reclen;
				}
				if (cp2 = getrec(jp, 1, lo < 0))
				{
					n2 = jp->file[1].fieldlen;
					continue;
				}
#if DEBUG_TRACE
sfprintf(sfstdout, "[2#%d:0,%lld,%lld]", __LINE__, lo, hi);
#endif
			}
			else if (cmp > 0)
			{
				if (same)
				{
					same = 0;
				next:
					if (n2 > jp->samesize)
					{
						jp->samesize = roundof(n2, 16);
						if (!(jp->same = newof(jp->same, char, jp->samesize, 0)))
						{
							error(ERROR_SYSTEM|2, "out of space");
							return -1;
						}
					}
					memcpy(jp->same, cp2, o2 = n2);
					if (!(cp2 = getrec(jp, 1, 0)))
						break;
					n2 = jp->file[1].fieldlen;
					if (n2 == o2 && *cp2 == *jp->same && !memcmp(cp2, jp->same, n2))
						goto next;
					continue;
				}
				if (hi >= 0)
				{
					if (sfseek(jp->file[1].iop, hi, SEEK_SET) != hi)
					{
						error(ERROR_SYSTEM|2, "%s: seek error", jp->file[1].name);
						return -1;
					}
					hi = -1;
				}
				else if ((jp->outmode & C_FILE2) && outrec(jp, 1) < 0)
					return -1;
				lo = -1;
				if (cp2 = getrec(jp, 1, 1))
				{
					n2 = jp->file[1].fieldlen;
					continue;
				}
#if DEBUG_TRACE
sfprintf(sfstdout, "[2#%d:0,%lld,%lld]", __LINE__, lo, hi);
#endif
			}
			else if (same)
			{
				same = 0;
				if (!(cp1 = getrec(jp, 0, 0)))
					break;
				n1 = jp->file[0].fieldlen;
				continue;
			}
			if (lo >= 0)
			{
				if ((hi = sfseek(jp->file[1].iop, (Sfoff_t)0, SEEK_CUR)) < 0 ||
				    (hi -= jp->file[1].reclen) < 0 ||
				    sfseek(jp->file[1].iop, lo, SEEK_SET) != lo ||
				    !(cp2 = getrec(jp, 1, 0)))
				{
					error(ERROR_SYSTEM|2, "%s: seek error", jp->file[1].name);
					return -1;
				}
				n2 = jp->file[1].fieldlen;
				lo = -1;
				if (jp->file[1].discard)
					sfseek(jp->file[1].iop, (Sfoff_t)-1, SEEK_SET);
			}
			else if (!cp2)
				break;
			else if ((jp->outmode & C_FILE1) && outrec(jp, -1) < 0)
				return -1;
			if (!(cp1 = getrec(jp, 0, 1)))
				break;
			n1 = jp->file[0].fieldlen;
		}
	}
#if DEBUG_TRACE
sfprintf(sfstdout, "[X#%d:?,%p,%p,%d,%d,%d%s]", __LINE__, cp1, cp2, cmp, lo, hi, (jp->outmode & C_COMMON) ? ",COMMON" : "");
#endif
	if (cp2)
	{
		if (hi >= 0 &&
		    sfseek(jp->file[1].iop, (Sfoff_t)0, SEEK_CUR) < hi &&
		    sfseek(jp->file[1].iop, hi, SEEK_SET) != hi)
		{
			error(ERROR_SYSTEM|2, "%s: seek error", jp->file[1].name);
			return -1;
		}
#if DEBUG_TRACE
sfprintf(sfstdout, "[O#%d:%02o:%02o]", __LINE__, jp->ooutmode, jp->outmode);
#endif
		cp1 = (!cp1 && cmp && hi < 0 && !jp->file[1].hit && ((jp->ooutmode ^ C_ALL) <= 1 || jp->outmode == 2)) ? cp2 : getrec(jp, 1, 0);
		cmp = 1;
		n = 1;
	}
	else
	{
		cmp = -1;
		n = 0;
	}
#if DEBUG_TRACE
sfprintf(sfstdout, "[X#%d:%d,%p,%p,%d,%02o,%02o%s]", __LINE__, n, cp1, cp2, cmp, jp->ooutmode, jp->outmode, (jp->outmode & C_COMMON) ? ",COMMON" : "");
#endif
	if (!cp1 || !(jp->outmode & (1<<n)))
	{
		if (cp1 && jp->file[n].iop == sfstdin)
			sfseek(sfstdin, (Sfoff_t)0, SEEK_END);
		return 0;
	}
	if (outrec(jp, cmp) < 0)
		return -1;
	do
	{
		if (!getrec(jp, n, 1))
			return 0;
	} while (outrec(jp, cmp) >= 0);
	return -1;
}

int
b_join(int argc, char** argv, Shbltin_t* context)
{
	register int		n;
	register char*		cp;
	register Join_t*	jp;
	char*			e;

#if !DEBUG_TRACE
	cmdinit(argc, argv, context, ERROR_CATALOG, ERROR_NOTIFY);
#endif
	if (!(jp = init()))
		error(ERROR_system(1),"out of space");
	jp->context = context;
	for (;;)
	{
		switch (n = optget(argv, usage))
		{
 		case 'j':
			/*
			 * check for obsolete "-j1 field" and "-j2 field"
			 */

			if (opt_info.offset == 0)
			{
				cp = argv[opt_info.index - 1];
				for (n = strlen(cp) - 1; n > 0 && cp[n] != 'j'; n--);
				n = cp[n] == 'j';
			}
			else
				n = 0;
			if (n)
			{
				if (opt_info.num!=1 && opt_info.num!=2)
					error(2,"-jfileno field: fileno must be 1 or 2");
				n = '0' + opt_info.num;
				if (!(cp = argv[opt_info.index]))
				{
					argc = 0;
					break;
				}
				opt_info.num = strtol(cp, &e, 10);
				if (*e)
				{
					argc = 0;
					break;
				}
				opt_info.index++;
			}
			else
			{
				jp->file[0].field = (int)(opt_info.num-1);
				n = '2';
			}
			/*FALLTHROUGH*/
 		case '1':
		case '2':
			if (opt_info.num <=0)
				error(2,"field number must positive");
			jp->file[n-'1'].field = (int)(opt_info.num-1);
			continue;
		case 'v':
			jp->outmode &= ~C_COMMON;
			/*FALLTHROUGH*/
		case 'a':
			if (opt_info.num!=1 && opt_info.num!=2)
				error(2,"%s: file number must be 1 or 2", opt_info.name);
			jp->outmode |= 1<<(opt_info.num-1);
			continue;
		case 'e':
			jp->nullfield = opt_info.arg;
			continue;
		case 'o':
			/* need to accept obsolescent command syntax */
			n = getolist(jp, opt_info.arg, argv+opt_info.index);
			opt_info.index += n;
			continue;
		case 't':
			jp->state[' '] = jp->state['\t'] = 0;
			if (jp->mb)
			{
				cp = opt_info.arg;
				jp->delim = mbchar(cp);
				if ((n = cp - opt_info.arg) > 1)
				{
					jp->delimlen = n;
					jp->delimstr = opt_info.arg;
					continue;
				}
			}
			n = *(unsigned char*)opt_info.arg;
			jp->state[n] = S_DELIM;
			jp->delim = n;
			continue;
		case 'i':
			jp->ignorecase = !opt_info.num;
			continue;
		case 'B':
			jp->buffered = !opt_info.num;
			continue;
		case ':':
			error(2, "%s", opt_info.arg);
			break;
		case '?':
			done(jp);
			error(ERROR_usage(2), "%s", opt_info.arg);
			break;
		}
		break;
	}
	argv += opt_info.index;
	argc -= opt_info.index;
	if (error_info.errors || argc!=2)
	{
		done(jp);
		error(ERROR_usage(2),"%s", optusage(NiL));
	}
	jp->ooutmode = jp->outmode;
	jp->file[0].name = cp = *argv++;
	if (streq(cp,"-"))
	{
		if (sfseek(sfstdin,(Sfoff_t)0,SEEK_CUR) < 0)
		{
			if (sfdcseekable(sfstdin))
				error(ERROR_warn(0),"%s: seek may fail",cp);
			else
				jp->file[0].discard = 1;
		}
		jp->file[0].iop = sfstdin;
	}
	else if (!(jp->file[0].iop = sfopen(NiL, cp, "r")))
	{
		done(jp);
		error(ERROR_system(1),"%s: cannot open",cp);
	}
	jp->file[1].name = cp = *argv;
	if (streq(cp,"-"))
	{
		if (sfseek(sfstdin,(Sfoff_t)0,SEEK_CUR) < 0)
		{
			if (sfdcseekable(sfstdin))
				error(ERROR_warn(0),"%s: seek may fail",cp);
			else
				jp->file[1].discard = 1;
		}
		jp->file[1].iop = sfstdin;
	}
	else if (!(jp->file[1].iop = sfopen(NiL, cp, "r")))
	{
		done(jp);
		error(ERROR_system(1),"%s: cannot open",cp);
	}
	if (jp->buffered)
	{
		sfsetbuf(jp->file[0].iop, jp->file[0].iop, SF_UNBOUND);
		sfsetbuf(jp->file[1].iop, jp->file[1].iop, SF_UNBOUND);
	}
	jp->outfile = sfstdout;
	if (!jp->outlist)
		jp->nullfield = 0;
	if (join(jp) < 0)
	{
		done(jp);
		error(ERROR_system(1),"write error");
	}
	else if (jp->file[0].iop==sfstdin || jp->file[1].iop==sfstdin)
		sfseek(sfstdin,(Sfoff_t)0,SEEK_END);
	done(jp);
	return error_info.errors;
}
