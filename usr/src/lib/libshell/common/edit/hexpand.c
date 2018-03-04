/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2010 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * bash style history expansion
 *
 * Author:
 * Karsten Fleischer
 * Omnium Software Engineering
 * An der Luisenburg 7
 * D-51379 Leverkusen
 * Germany
 *
 * <K.Fleischer@omnium.de>
 */


#include "defs.h"
#include "edit.h"

#if ! SHOPT_HISTEXPAND

NoN(hexpand)

#else

static char *modifiers = "htrepqxs&";
static int mod_flags[] = { 0, 0, 0, 0, HIST_PRINT, HIST_QUOTE, HIST_QUOTE|HIST_QUOTE_BR, 0, 0 };

#define	DONE()	{flag |= HIST_ERROR; cp = 0; stakseek(0); goto done;}

struct subst
{
	char *str[2];	/* [0] is "old", [1] is "new" string */
};


/* 
 * parse an /old/new/ string, delimiter expected as first char.
 * if "old" not specified, keep sb->str[0]
 * if "new" not specified, set sb->str[1] to empty string
 * read up to third delimeter char, \n or \0, whichever comes first.
 * return adress is one past the last valid char in s:
 * - the address containing \n or \0 or
 * - one char beyond the third delimiter
 */

static char *parse_subst(const char *s, struct subst *sb)
{
	char	*cp,del;
	int	off,n = 0;

	/* build the strings on the stack, mainly for '&' substition in "new" */
	off = staktell();

	/* init "new" with empty string */
	if(sb->str[1])
		free(sb->str[1]);
	sb->str[1] = strdup("");

	/* get delimiter */
	del = *s;

	cp = (char*) s + 1;

	while(n < 2)
	{
		if(*cp == del || *cp == '\n' || *cp == '\0')
		{
			/* delimiter or EOL */
			if(staktell() != off)
			{
				/* dupe string on stack and rewind stack */
				stakputc('\0');
				if(sb->str[n])
					free(sb->str[n]);
				sb->str[n] = strdup(stakptr(off));
				stakseek(off);
			}
			n++;

			/* if not delimiter, we've reached EOL. Get outta here. */
			if(*cp != del)
				break;
		}
		else if(*cp == '\\')
		{
			if(*(cp+1) == del)	/* quote delimiter */
			{
				stakputc(del);
				cp++;
			}
			else if(*(cp+1) == '&' && n == 1)
			{		/* quote '&' only in "new" */
				stakputc('&');
				cp++;
			}
			else
				stakputc('\\');
		}
		else if(*cp == '&' && n == 1 && sb->str[0])
			/* substitute '&' with "old" in "new" */
			stakputs(sb->str[0]);
		else
			stakputc(*cp);
		cp++;
	}

	/* rewind stack */
	stakseek(off);

	return cp;
}

/*
 * history expansion main routine
 */

int hist_expand(const char *ln, char **xp)
{
	int	off,	/* stack offset */
		q,	/* quotation flags */
		p,	/* flag */
		c,	/* current char */
		flag=0;	/* HIST_* flags */
	Sfoff_t	n,	/* history line number, counter, etc. */
		i,	/* counter */
		w[2];	/* word range */
	char	*sp,	/* stack pointer */
		*cp,	/* current char in ln */
		*str,	/* search string */
		*evp,	/* event/word designator string, for error msgs */
		*cc=0,	/* copy of current line up to cp; temp ptr */
		hc[3],	/* default histchars */
		*qc="\'\"`";	/* quote characters */
	Sfio_t	*ref=0,	/* line referenced by event designator */
		*tmp=0,	/* temporary line buffer */
		*tmp2=0;/* temporary line buffer */
	Histloc_t hl;	/* history location */
	static Namval_t *np = 0;	/* histchars variable */
	static struct subst	sb = {0,0};	/* substition strings */
	static Sfio_t	*wm=0;	/* word match from !?string? event designator */

	if(!wm)
		wm = sfopen(NULL, NULL, "swr");

	hc[0] = '!';
	hc[1] = '^';
	hc[2] = 0;
	if((np = nv_open("histchars",sh.var_tree,0)) && (cp = nv_getval(np)))
	{
		if(cp[0])
		{
			hc[0] = cp[0];
			if(cp[1])
			{
				hc[1] = cp[1];
				if(cp[2])
					hc[2] = cp[2];
			}
		}
	}

	/* save shell stack */
	if(off = staktell())
		sp = stakfreeze(0);

	cp = (char*)ln;

	while(cp && *cp)
	{
		/* read until event/quick substitution/comment designator */
		if((*cp != hc[0] && *cp != hc[1] && *cp != hc[2]) 
		   || (*cp == hc[1] && cp != ln))
		{
			if(*cp == '\\')	/* skip escaped designators */
				stakputc(*cp++);
			else if(*cp == '\'') /* skip quoted designators */
			{
				do
					stakputc(*cp);				
				while(*++cp && *cp != '\'');
			}
			stakputc(*cp++);
			continue;
		}

		if(hc[2] && *cp == hc[2]) /* history comment designator, skip rest of line */
		{
			stakputc(*cp++);
			stakputs(cp);
			DONE();
		}

		n = -1;
		str = 0;
		flag &= HIST_EVENT; /* save event flag for returning later */
		evp = cp;
		ref = 0;

		if(*cp == hc[1]) /* shortcut substitution */
		{
			flag |= HIST_QUICKSUBST;
			goto getline;
		}

		if(*cp == hc[0] && *(cp+1) == hc[0]) /* refer to line -1 */
		{
			cp += 2;
			goto getline;
		}

		switch(c = *++cp) {
		case ' ':
		case '\t':
		case '\n':
		case '\0':
		case '=':
		case '(':
			stakputc(hc[0]);
			continue;
		case '#': /* the line up to current position */
			flag |= HIST_HASH;
			cp++;
			n = staktell(); /* terminate string and dup */
			stakputc('\0');
			cc = strdup(stakptr(0));
			stakseek(n); /* remove null byte again */
			ref = sfopen(ref, cc, "s"); /* open as file */
			n = 0; /* skip history file referencing */
			break;
		case '-': /* back reference by number */
			if(!isdigit(*(cp+1)))
				goto string_event;
			cp++;
			/* FALLTHROUGH */
		case '0': /* reference by number */
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			n = 0;
			while(isdigit(*cp))
				n = n * 10 + (*cp++) - '0';
			if(c == '-')
				n = -n;
			break;
		case '$':
			n = -1;
		case ':':
			break;
		case '?':
			cp++;
			flag |= HIST_QUESTION;
			/* FALLTHROUGH */
		string_event:
		default:
			/* read until end of string or word designator/modifier */
			str = cp;
			while(*cp)
			{
				cp++;
				if((!(flag&HIST_QUESTION) &&
				   (*cp == ':' || isspace(*cp)
				    || *cp == '^' || *cp == '$'
				    || *cp == '*' || *cp == '-'
				    || *cp == '%')
				   )
				   || ((flag&HIST_QUESTION) && (*cp == '?' || *cp == '\n')))
				{
					c = *cp;
					*cp = '\0';
				}
			}
			break;
		}

getline:
		flag |= HIST_EVENT;
		if(str)	/* !string or !?string? event designator */
		{

			/* search history for string */
			hl = hist_find(sh.hist_ptr, str,
				       sh.hist_ptr->histind,
				       flag&HIST_QUESTION, -1);
			if((n = hl.hist_command) == -1)
				n = 0;	/* not found */
		}
		if(n)
		{
			if(n < 0) /* determine index for backref */
				n = sh.hist_ptr->histind + n;
			/* search and use history file if found */
			if(n > 0 && hist_seek(sh.hist_ptr, n) != -1)
				ref = sh.hist_ptr->histfp;

		}
		if(!ref)
		{
			/* string not found or command # out of range */
			c = *cp;
			*cp = '\0';
			errormsg(SH_DICT, ERROR_ERROR, "%s: event not found", evp);
			*cp = c;
			DONE();
		}

		if(str) /* string search: restore orig. line */
		{
			if(flag&HIST_QUESTION)
				*cp++ = c; /* skip second question mark */
			else
				*cp = c;
		}

		/* colon introduces either word designators or modifiers */
		if(*(evp = cp) == ':')
			cp++;

		w[0] = 0; /* -1 means last word, -2 means match from !?string? */
		w[1] = -1; /* -1 means last word, -2 means suppress last word */

		if(flag & HIST_QUICKSUBST) /* shortcut substitution */
			goto getsel;

		n = 0;
		while(n < 2)
		{
			switch(c = *cp++) {
			case '^': /* first word */
				if(n == 0)
				{
					w[0] = w[1] = 1;
					goto skip;
				}
				else
					goto skip2;
			case '$': /* last word */
				w[n] = -1;
				goto skip;
			case '%': /* match from !?string? event designator */
				if(n == 0)
				{
					if(!str)
					{
						w[0] = 0;
						w[1] = -1;
						ref = wm;
					}
					else
					{
						w[0] = -2;
						w[1] = sftell(ref) + hl.hist_char;
					}
					sfseek(wm, 0, SEEK_SET);
					goto skip;
				}
				/* FALLTHROUGH */
			default:
			skip2:
				cp--;
				n = 2;
				break;
			case '*': /* until last word */
				if(n == 0)
					w[0] = 1;
				w[1] = -1;
			skip:
				flag |= HIST_WORDDSGN;
				n = 2;
				break;
			case '-': /* until last word or specified index */
				w[1] = -2;
				flag |= HIST_WORDDSGN;
				n = 1;
				break;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9': /* specify index */
				if((*evp == ':') || w[1] == -2)
				{
					w[n] = c - '0';
					while(isdigit(c=*cp++))
						w[n] = w[n] * 10 + c - '0';
					flag |= HIST_WORDDSGN;
					if(n == 0)
						w[1] = w[0];
					n++;
				}
				else
					n = 2;
				cp--;
				break;
			}
		}

		if(w[0] != -2 && w[1] > 0 && w[0] > w[1])
		{
			c = *cp;
			*cp = '\0';
			errormsg(SH_DICT, ERROR_ERROR, "%s: bad word specifier", evp);
			*cp = c;
			DONE();
		}

		/* no valid word designator after colon, rewind */
		if(!(flag & HIST_WORDDSGN) && (*evp == ':'))
			cp = evp;

getsel:
		/* open temp buffer, let sfio do the (re)allocation */
		tmp = sfopen(NULL, NULL, "swr");

		/* push selected words into buffer, squash 
		   whitespace into single blank or a newline */
		n = i = q = 0;

		while((c = sfgetc(ref)) > 0)
		{
			if(isspace(c))
			{
				flag |= (c == '\n' ? HIST_NEWLINE : 0);
				continue;
			}

			if(n >= w[0] && ((w[0] != -2) ? (w[1] < 0 || n <= w[1]) : 1))
			{
				if(w[0] < 0)
					sfseek(tmp, 0, SEEK_SET);
				else
					i = sftell(tmp);

				if(i > 0)
					sfputc(tmp, flag & HIST_NEWLINE ? '\n' : ' ');

				flag &= ~HIST_NEWLINE;
				p = 1;
			}
			else
				p = 0;

			do
			{
				cc = strchr(qc, c);
				q ^= cc ? 1<<(int)(cc - qc) : 0;
				if(p)
					sfputc(tmp, c);
			}
			while((c = sfgetc(ref)) > 0  && (!isspace(c) || q));

			if(w[0] == -2 && sftell(ref) > w[1])
				break;

			flag |= (c == '\n' ? HIST_NEWLINE : 0);
			n++;
		}
		if(w[0] != -2 && w[1] >= 0 && w[1] >= n)
		{
			c = *cp;
			*cp = '\0';
			errormsg(SH_DICT, ERROR_ERROR, "%s: bad word specifier", evp);
			*cp = c;
			DONE();
		}
		else if(w[1] == -2)	/* skip last word */
			sfseek(tmp, i, SEEK_SET);

		/* remove trailing newline */
		if(sftell(tmp))
		{
			sfseek(tmp, -1, SEEK_CUR);
			if(sfgetc(tmp) == '\n')
				sfungetc(tmp, '\n');
		}

		sfputc(tmp, '\0');

		if(str)
		{
			if(wm)
				sfclose(wm);
			wm = tmp;
		}

		if(cc && (flag&HIST_HASH))
		{
			/* close !# temp file */
			sfclose(ref);
			flag &= ~HIST_HASH;
			free(cc);
			cc = 0;
		}

		evp = cp;

		/* selected line/words are now in buffer, now go for the modifiers */
		while(*cp == ':' || (flag & HIST_QUICKSUBST))
		{
			if(flag & HIST_QUICKSUBST)
			{
				flag &= ~HIST_QUICKSUBST;
				c = 's';
				cp--;
			}
			else
				c = *++cp;

			sfseek(tmp, 0, SEEK_SET);
			tmp2 = sfopen(tmp2, NULL, "swr");

			if(c == 'g') /* global substitution */
			{
				flag |= HIST_GLOBALSUBST;
				c = *++cp;
			}

			if(cc = strchr(modifiers, c))
				flag |= mod_flags[cc - modifiers];
			else
			{
				errormsg(SH_DICT, ERROR_ERROR, "%c: unrecognized history modifier", c);
				DONE();
			}

			if(c == 'h' || c == 'r') /* head or base */
			{
				n = -1;
				while((c = sfgetc(tmp)) > 0)
				{	/* remember position of / or . */
					if((c == '/' && *cp == 'h') || (c == '.' && *cp == 'r'))
						n = sftell(tmp2);
					sfputc(tmp2, c);
				}
				if(n > 0)
				{	 /* rewind to last / or . */
					sfseek(tmp2, n, SEEK_SET);
					/* end string there */
					sfputc(tmp2, '\0');
				}
			}
			else if(c == 't' || c == 'e') /* tail or suffix */
			{
				n = 0;
				while((c = sfgetc(tmp)) > 0)
				{	/* remember position of / or . */
					if((c == '/' && *cp == 't') || (c == '.' && *cp == 'e'))
						n = sftell(tmp);
				}
				/* rewind to last / or . */
				sfseek(tmp, n, SEEK_SET);
				/* copy from there on */
				while((c = sfgetc(tmp)) > 0)
					sfputc(tmp2, c);
			}
			else if(c == 's' || c == '&')
			{
				cp++;

				if(c == 's')
				{
					/* preset old with match from !?string? */
					if(!sb.str[0] && wm)
						sb.str[0] = strdup(sfsetbuf(wm, (Void_t*)1, 0));
					cp = parse_subst(cp, &sb);
				}

				if(!sb.str[0] || !sb.str[1])
				{
					c = *cp;
					*cp = '\0';
					errormsg(SH_DICT, ERROR_ERROR, 
						 "%s%s: no previous substitution", 
						(flag & HIST_QUICKSUBST) ? ":s" : "",
						evp);
					*cp = c;
					DONE();
				}

				/* need pointer for strstr() */
				str = sfsetbuf(tmp, (Void_t*)1, 0);

				flag |= HIST_SUBSTITUTE;
				while(flag & HIST_SUBSTITUTE)
				{
					/* find string */
					if(cc = strstr(str, sb.str[0]))
					{	/* replace it */
						c = *cc;
						*cc = '\0';
						sfputr(tmp2, str, -1);
						sfputr(tmp2, sb.str[1], -1);
						*cc = c;
						str = cc + strlen(sb.str[0]);
					}
					else if(!sftell(tmp2))
					{	/* not successfull */
						c = *cp;
						*cp = '\0';
						errormsg(SH_DICT, ERROR_ERROR,
							 "%s%s: substitution failed",
							(flag & HIST_QUICKSUBST) ? ":s" : "",
							evp);
						*cp = c;
						DONE();
					}
					/* loop if g modifier specified */
					if(!cc || !(flag & HIST_GLOBALSUBST))
						flag &= ~HIST_SUBSTITUTE;
				}
				/* output rest of line */
				sfputr(tmp2, str, -1);
				if(*cp)
					cp--;
			}

			if(sftell(tmp2))
			{ /* if any substitions done, swap buffers */
				if(wm != tmp)
					sfclose(tmp);
				tmp = tmp2;
				tmp2 = 0;
			}
			cc = 0;
			if(*cp)
				cp++;
		}

		/* flush temporary buffer to stack */
		if(tmp)
		{
			sfseek(tmp, 0, SEEK_SET);

			if(flag & HIST_QUOTE)
				stakputc('\'');

			while((c = sfgetc(tmp)) > 0)
			{
				if(isspace(c))
				{
					flag = flag & ~HIST_NEWLINE;

					/* squash white space to either a 
					   blank or a newline */
					do
						flag |= (c == '\n' ? HIST_NEWLINE : 0);
					while((c = sfgetc(tmp)) > 0 && isspace(c));

					sfungetc(tmp, c);

					c = (flag & HIST_NEWLINE) ? '\n' : ' ';

					if(flag & HIST_QUOTE_BR)
					{
						stakputc('\'');
						stakputc(c);
						stakputc('\'');
					}
					else
						stakputc(c);
				}
				else if((c == '\'') && (flag & HIST_QUOTE))
				{
					stakputc('\'');
					stakputc('\\');
					stakputc(c);
					stakputc('\'');
				}
				else
					stakputc(c);
			}
			if(flag & HIST_QUOTE)
				stakputc('\'');
		}
	}

	stakputc('\0');

done:
	if(cc && (flag&HIST_HASH))
	{
		/* close !# temp file */
		sfclose(ref);
		free(cc);
		cc = 0;
	}

	/* error? */
	if(staktell() && !(flag & HIST_ERROR))
		*xp = strdup(stakfreeze(1));

	/* restore shell stack */
	if(off)
		stakset(sp,off);
	else
		stakseek(0);

	/* drop temporary files */

	if(tmp && tmp != wm)
		sfclose(tmp);
	if(tmp2)
		sfclose(tmp2);

	return (flag & HIST_ERROR ? HIST_ERROR : flag & HIST_FLAG_RETURN_MASK);
}

#endif
