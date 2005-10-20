/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fcntl.h>
#include <locale.h>
#include <stdlib.h>
#include "codeset.h"
#include <ctype.h>
#include <string.h>
#include <memory.h>
#include <malloc.h>
#include <sys/param.h>		/* for MAXPATHLEN */
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>

#define	TRAILER ".ci"


struct	_code_set_info _code_set_info = {
	NULL,
	CODESET_NONE, 	/* no codeset */
	NULL, 		/* not defined */
	0,
};

/* tolower()  and toupper() conversion table 
 * is hidden here to avoid being placed in the 
 * extern  .sa file in the dynamic version of libc
 */	

char _ctype_ul[] = { 0,

/*	 0	 1	 2	 3	 4	 5	 6	 7  */
	'\000',	'\001',	'\002',	'\003',	'\004',	'\005',	'\006',	'\007',
	'\010',	'\011',	'\012',	'\013',	'\014',	'\015',	'\016',	'\017',
	'\020',	'\021',	'\022',	'\023',	'\024',	'\025',	'\026',	'\027',
	'\030',	'\031',	'\032',	'\033',	'\034',	'\035',	'\036',	'\037',
	' ',	'!',	'"',	'#',	'$',	'%',	'&',	'\'',
	'(',	')',	'*',	'+',	',',	'-',	'.',	'/',
	'0',	'1',	'2',	'3',	'4',	'5',	'6',	'7',
	'8',	'9',	':',	';',	'<',	'=',	'>',	'?',
	'@',	'a',	'b',	'c',	'd',	'e',	'f',	'g',
	'h',	'i',	'j',	'k',	'l',	'm',	'n',	'o',
	'p',	'q',	'r',	's',	't',	'u',	'v',	'w',
	'x',	'y',	'z',	'[',	'\\',	']',	'^',	'_',
	'`',	'A',	'B',	'C',	'D',	'E',	'F',	'G',
	'H',	'I',	'J',	'K',	'L',	'M',	'N',	'O',
	'P',	'Q',	'R',	'S',	'T',	'U',	'V',	'W',
	'X',	'Y',	'Z',	'{',	'|',	'}',	'~',	'\177',
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
};

/* following layout is:
 * LC_NUMERIC LC_TIME LC_MONETARY LANGINFO LC_COLLATE LC_MESSAGES
 */
char _locales[MAXLOCALE - 1][MAXLOCALENAME + 1] ;

char _my_time[MAXLOCALENAME + 1];

/* The array Default holds the systems notion of default locale. It is normally
 * found in {LOCALE}/.default and moved to here. Note there is only one
 * default locale spanning all categories
 */

static char Default[MAXLOCALENAME+1];

struct	langinfo _langinfo;
struct	dtconv *_dtconv = NULL;

static	char *realmonths = NULL;
static	char *realdays = NULL;
static	char *realfmts = NULL;
static  short lang_succ = ON;	/* setlocale success */


/* Set the values here to guarantee stdio use of the 
   decimal point
 */
static struct lconv lconv_arr = {
	".", "", "", "", "", 
	"", "", "", "", "",
	CHAR_MAX, CHAR_MAX, CHAR_MAX, CHAR_MAX, 
	CHAR_MAX, CHAR_MAX, CHAR_MAX, CHAR_MAX
};

/* lconv is externally defined by ANSI C */
struct	lconv *lconv = &lconv_arr;

static	char *lconv_numeric_str = NULL;
static 	char *lconv_monetary_str = NULL;

int	openlocale(char *, int, char *, char *);
int	getlocale_ctype(char *, char *, char *);
char	*getlocale_numeric(char *, struct lconv *, char *);
void	init_statics(void);
static char	*getlocale_monetary(char *, struct lconv *, char *);
static char	*getstr(char *, char **);
static char	*getgrouping(char *, char **);
static char	*getnum(char  *, char *);
static char	*getbool(char *, char *);
static void	set_default(void);

char *
setlocale(int category, char *locale)
{
	static char buf[MAXLOCALE*(MAXLOCALENAME + 1) + 1];
		/* buffer for current LC_ALL value */
	int nonuniform;
	short ret;
	char my_ctype[CTYPE_SIZE];	/* local copy */
	struct lconv my_lconv;		/* local copy */
	char *my_lconv_numeric_str;
	char *my_lconv_monetary_str;
	int i;
	char *p;


	 /* initialize my_lconv to lconv */
        memcpy(&my_lconv, lconv, sizeof(my_lconv));

	/*
	 *  Following code is to avoid static initialisation of
	 *  strings which would otherwise blow up "xstr".
	 */
	if (_locales[0][0] == '\0')
		init_statics();

	if (locale == NULL) {
		if (category == LC_ALL) {
			/*
			 * Assume all locales are set to the same value.  Then
			 * scan through the locales to see if any are
			 * different.  If they are the same, return the common
			 * value; otherwise, construct a "composite" value.
			 */
			nonuniform = 0;	/* assume all locales set the same */
			for (i = 0; i < MAXLOCALE - 2; i++) {
				if (strcmp(_locales[i], _locales[i + 1]) != 0) {
					nonuniform = 1;
					break;
				}
			}
			if (nonuniform) {
				/*
				 * They're not all the same.  Construct a list
				 * of all the locale values, in order,
				 * separated by slashes.  Return that value.
				 */
				(void) strcpy(buf, _locales[0]);
				for (i = 1; i < MAXLOCALE - 1; i++) {
					(void) strcat(buf, "/");
					(void) strcat(buf, _locales[i]);
				}
				return (buf);
			} else {
				/*
				 * They're all the same; any one you return is
				 * OK.
				 */
				return (_locales[0]);
			}
		} else
			return (_locales[category - 1]);
	}

	switch (category) {

	case LC_ALL:
		if (strchr(locale, '/') != NULL) {
			/*
			 * Composite value; extract each category.
			 */
			if (strlen(locale) > sizeof buf - 1)
				return (NULL);	/* too long */
			(void) strcpy(buf, locale);
			p = buf;

			/*
			 * LC_CTYPE and LC_NUMERIC are set here.
			 * Others locales won't be set here,
			 * they will be just marked.
			 */
			for (i = 0; i < MAXLOCALE - 1; i++) {
				p = strtok(p, "/");
				if (p == NULL)
					return (NULL);	/* missing item */
				switch (i) {

				case LC_CTYPE - 1:
					if (setlocale(LC_CTYPE,p) == NULL)
						return (NULL);
					break;
				case LC_NUMERIC - 1:
					if (setlocale(LC_NUMERIC,p) == NULL)
						return (NULL);
					break;
				case LC_TIME - 1:
					if (setlocale(LC_TIME,p) == NULL)
						return (NULL);
					break;
				case LC_MONETARY - 1:
					if (setlocale(LC_MONETARY,p) == NULL)
						return (NULL);
					break;
				case LANGINFO - 1:
					if (setlocale(LANGINFO,p) == NULL)
						return (NULL);
					break;
				case LC_COLLATE - 1:
					if (setlocale(LC_COLLATE,p) == NULL)
						return (NULL);
					break;
				case LC_MESSAGES - 1:
					if (setlocale(LC_MESSAGES,p) == NULL)
						return (NULL);
					break;
				}
				p = NULL;
			}
			if (strtok((char *)NULL, "/") != NULL)
				return (NULL);	/* extra stuff at end */
		}

	/* If category = LC_ALL, Drop through to test each individual
  	 * category, one at a time. Note default rules where env vars
	 * are not set
	 */

	case LC_CTYPE:
		if ((ret = getlocale_ctype(locale , my_ctype,
		    _locales[LC_CTYPE - 1])) < 0)
			return (NULL);
		if (ret) {
		      (void) memcpy(_ctype_, my_ctype, CTYPE_SIZE/2);
		      (void) memcpy(_ctype_ul, my_ctype+(CTYPE_SIZE/2), CTYPE_SIZE/2); 
		}
		if (category != LC_ALL)
			break;

	case LC_NUMERIC:
		if ((my_lconv_numeric_str =
		    getlocale_numeric(locale, &my_lconv,
		      _locales[LC_NUMERIC - 1])) == NULL)
			return (NULL);
		if (*my_lconv_numeric_str) {
			if (lconv_numeric_str != NULL)
				free((malloc_t)lconv_numeric_str);
			lconv_numeric_str = my_lconv_numeric_str;
			memcpy(lconv, my_lconv, sizeof(my_lconv));
		}
		if (category != LC_ALL)
			break;

	case LC_TIME:
		if ((ret = openlocale("LC_TIME", LC_TIME, locale,
		      _locales[LC_TIME -1])) < 0)
			return (NULL);
		if (ret)
			(void) close(ret);
		if (category != LC_ALL)
			break;

	case LC_MONETARY:
		if ((my_lconv_monetary_str =
		    getlocale_monetary(locale, &my_lconv,
		      _locales[LC_MONETARY - 1])) == NULL)
			return (NULL);
		if (*my_lconv_monetary_str) {
			if (lconv_monetary_str != NULL)
				free((malloc_t)lconv_monetary_str);
			lconv_monetary_str = my_lconv_monetary_str;
			memcpy(lconv, &my_lconv, sizeof(my_lconv));
		}
		if (category != LC_ALL)
			break;

	case LANGINFO:
		if ((ret = openlocale("LANGINFO", LANGINFO, locale,
		      _locales[LANGINFO - 1])) < 0) {
			lang_succ = OFF;
			return (NULL);
		}
		if (ret) {
			lang_succ = OFF;
			(void) close(ret);
		}
		if (category != LC_ALL)
			break;

	case LC_COLLATE:
		if ((ret = openlocale("LC_COLLATE", LC_COLLATE, locale,
		      _locales[LC_COLLATE - 1])) < 0)
			return (NULL);
		if (ret) {
			(void) close(ret);
		}
		if (category != LC_ALL)
			break;

	case LC_MESSAGES:
		if ((ret = openlocale("LC_MESSAGES", LC_MESSAGES, locale,
		      _locales[LC_MESSAGES - 1])) < 0)
			return (NULL);
		if (ret) {
			(void) close(ret);
		}
	}
	return (setlocale(category, (char *)NULL));
}

int
getlocale_ctype(char *locale, char *ctypep, char *newlocale)
{
	int fd;

	if ((fd = openlocale("LC_CTYPE", LC_CTYPE, locale, newlocale)) > 0) {
		if (read(fd, (char *)ctypep, CTYPE_SIZE) != CTYPE_SIZE) {
			(void) close(fd);
			fd = -1;
		}
		(void) close(fd);
	}
	return (fd);
}

/* open and load the numeric information */

char *
getlocale_numeric(char *locale, struct lconv *lconvp, char *newlocale)
{
	int fd;
	struct stat buf;
	char *str;
	char *p;

	if ((fd = openlocale("LC_NUMERIC", LC_NUMERIC, locale, newlocale)) < 0)
		return (NULL);
	if (fd == 0)
		return "";
	if ((fstat(fd, &buf)) != 0)
		return (NULL);
	if ((str = (char*)malloc((unsigned)buf.st_size + 2)) == NULL)
		return (NULL);

	if ((read(fd, str, (int)buf.st_size)) != buf.st_size) {
		free((malloc_t)str);
		return (NULL);
	}

	/* Set last character of str to '\0' */
	p = &str[buf.st_size];
	*p++ = '\n';
	*p = '\0';

	/* p will "walk thru" str */
	p = str;

	p = getstr(p, &lconvp->decimal_point);
	if (p == NULL)
		goto fail;
	p = getstr(p, &lconvp->thousands_sep);
	if (p == NULL)
		goto fail;
	p = getgrouping(p, &lconvp->grouping);
	if (p == NULL)
		goto fail;
	(void) close(fd);

	return (str);

fail:
	(void) close(fd);
	free((malloc_t)str);
	return (NULL);
}


static char *
getlocale_monetary(char *locale, struct lconv *lconvp, char *newlocale)
{
	int fd;
	struct stat buf;
	char *str;
	char *p;

	if ((fd = openlocale("LC_MONETARY", LC_MONETARY, locale, newlocale)) < 0)
		return (NULL);
	if (fd == 0)
		return ("");
	if ((fstat(fd, &buf)) != 0)
		return (NULL);
	if ((str = (char*)malloc((unsigned)buf.st_size + 2)) == NULL)
		return (NULL);

	if ((read(fd, str, (int)buf.st_size)) != buf.st_size) {
		free((malloc_t)str);
		return (NULL);
	}

	/* Set last character of str to '\0' */
	p = &str[buf.st_size];
	*p++ = '\n';
	*p = '\0';

	/* p will "walk thru" str */
	p = str;

	p = getstr(p, &lconvp->int_curr_symbol);
	if (p == NULL)
		goto fail;
	p = getstr(p, &lconvp->currency_symbol);
	if (p == NULL)
		goto fail;
	p = getstr(p, &lconvp->mon_decimal_point);
	if (p == NULL)
		goto fail;
	p = getstr(p, &lconvp->mon_thousands_sep);
	if (p == NULL)
		goto fail;
	p = getgrouping(p, &lconvp->mon_grouping);
	if (p == NULL)
		goto fail;
	p = getstr(p, &lconvp->positive_sign);
	if (p == NULL)
		goto fail;
	p = getstr(p, &lconvp->negative_sign);
	if (p == NULL)
		goto fail;
	p = getnum(p, &lconvp->frac_digits);
	if (p == NULL)
		goto fail;
	p = getbool(p, &lconvp->p_cs_precedes);
	if (p == NULL)
		goto fail;
	p = getbool(p, &lconvp->p_sep_by_space);
	if (p == NULL)
		goto fail;
	p = getbool(p, &lconvp->n_cs_precedes);
	if (p == NULL)
		goto fail;
	p = getbool(p, &lconvp->n_sep_by_space);
	if (p == NULL)
		goto fail;
	p = getnum(p, &lconvp->p_sign_posn);
	if (p == NULL)
		goto fail;
	p = getnum(p, &lconvp->n_sign_posn);
	if (p == NULL)
		goto fail;
	(void) close(fd);

	return (str);

fail:
	(void) close(fd);
	free((malloc_t)str);
	return (NULL);
}

static char *
getstr(char *p, char **strp)
{
	*strp = p;
	p = strchr(p, '\n');
	if (p == NULL)
		return (NULL);	/* no end-of-line */
	*p++ = '\0';
	return (p);
}

static char *
getgrouping(char *p, char **groupingp)
{
	int c;

	if (*p == '\0')
		return (NULL);	/* no grouping */
	*groupingp = p;
	while ((c = *p) != '\n') {
		if (c == '\0')
			return (NULL);	/* no end-of-line */
		if (c >= '0' && c <= '9')
			*p++ = c - '0';
		else
			*p++ = '\177';
	}
	*p++ = '\0';
	return (p);
}

static char *
getnum(char *p, char *nump)
{
	int num;
	int c;

	if (*p == '\0')
		return (NULL);	/* no number */
	if (*p == '\n')
		*nump = '\177';	/* blank line - no value */
	else {
		num = 0;
		while ((c = *p) != '\n') {
			if (c < '0' || c > '9')
				return (NULL);	/* bad number */
			num = num*10 + c - '0';
			p++;
		}
		*nump = num;
	}
	*p++ = '\0';
	return (p);
}

static char *
getbool(char *p, char *boolp)
{

	if (*p == '\0')
		return (NULL);	/* no number */
	if (*p == '\n')
		*boolp = '\177';	/* blank line - no value */
	else {
		switch (*p++) {

		case 'y':
		case 'Y':
		case 't':
		case 'T':
			*boolp = 1;	/* true */
			break;

		case 'n':
		case 'N':
		case 'f':
		case 'F':
			*boolp = 0;	/* false */
			break;

		default:
			return (NULL);	/* bad boolean */
		}
		if (*p != '\n')
			return (NULL);	/* noise at end of line */
	}
	*p++ = '\0';
	return (p);
}

/*
 * Open a locale file.  First, check the value of "locale"; if it's a null
 * string, first check the environment variable with the same name as the
 * category, and then check the environment variable "LANG".  If neither of
 * them are set to non-null strings, use the LC_default env.var and if this
 * has no meaning then assume we are running in the C locale. It is expected
 * That LC_default is set across the whole system. If the resulting locale is
 * longer than MAXLOCALENAME characters, reject it.  Then, try looking in the
 * per-machine locale directory for the file in question; if it's not found
 * there, try looking in the shared locale directory.
 * If there is no work to do, that is, the last setting of locales is equal
 * to the current request, then we don't do anything, and exit with value 0.
 * Copy the name of the locale used into "newlocale".
 * Exit with positive value if we opened a file
 * Exit with -1 if an error occured (invalid locale).
 * Exit with 0 if there is no need to look at the disk file.
 * (Assumption - there is always at least one fd open before setlocale
 *  is called)
 */
int
openlocale(char *category, int cat_id, char *locale, char *newlocale)
{
	char pathname[MAXPATHLEN], *defp;
	int fd, fd2;
	struct _code_header code_header;
	char *my_info;

	if (*locale == '\0') {
		locale = getenv(category);
		if (locale == NULL || *locale == '\0') {
			locale = getenv("LANG");
			if (locale == NULL || *locale == '\0') {
				if (*Default == '\0') {
					defp = getenv("LC_default");
					if (defp == NULL || *defp == '\0')
						strcpy(Default,"C");
					else
						strcpy(Default, defp);
				}
				locale = Default;
			}
		}
	}
	if (strcmp(locale,_locales[cat_id-1]) == 0) {
		(void) strcpy(newlocale, locale);
		return (0);
	}
	if (strlen(locale) > MAXLOCALENAME)
		return (-1);

	(void) strcpy(pathname, PRIVATE_LOCALE_DIR);
	(void) strcat(pathname, category);
	(void) strcat(pathname, "/");
	(void) strcat(pathname, locale);
	if ((fd = open(pathname, O_RDONLY)) < 0 && errno == ENOENT) {
		(void) strcpy(pathname, LOCALE_DIR);
		(void) strcat(pathname, category);
		(void) strcat(pathname, "/");
		(void) strcat(pathname, locale);
		fd = open(pathname, O_RDONLY);
	}
	if (fd >= 0)
		(void) strcpy(newlocale, locale);
	/*
	 * bug id 1072740; if by some chance the actual fd we're going to
	 * return is 0, change it to be some non-zero descriptor, because
	 * returning 0 means something different.  If '0' is the only 
	 * descriptor left, return an error.
	 */
	if (fd == 0) {
		int dupfd;
	
		if ((dupfd = dup(fd)) < 1) {
			(void) close(fd);
			fd = -1;
		} else {
			(void) close(fd);
			fd = dupfd;
		}
	}

	if (cat_id == LC_CTYPE) {

		/* Go and get the trailer file */

		(void) strcat(pathname, TRAILER);
		fd2 = open(pathname, O_RDONLY);
                if ( fd2 == 0 ) {
                        fd2 = dup(fd2);
                        close(0);
                }
       
		if (fd2 == -1)  {
			set_default();
			return (fd);
		}

		/*
		 * ctype trailer file  exists - read it
		 */

		if (read (fd2, (char *)&code_header, sizeof (code_header)) !=
						    sizeof (code_header)) {
			/*
			 * File format not correct
			 */
			 set_default();
			 close(fd2);
			 return (-1);
		}
		/*
		 * set up trailer file
		 */
		 strcpy(_code_set_info.code_name, code_header.code_name);
		 _code_set_info.code_id = code_header.code_id;
		 if (_code_set_info.code_info != NULL)
			free (_code_set_info.code_info);
		 if (code_header.code_info_size > 0)  {
			my_info = malloc(code_header.code_info_size);
			if (read (fd2, (char *)my_info, 
			 code_header.code_info_size) != 
		 	 code_header.code_info_size) { 
					close(fd2);
					set_default();
					return (-1);
				}
			_code_set_info.code_info = my_info;
		 }
		 else {
		 /* 
		  * We have a corrupted file too 
		  */
			_code_set_info.code_info = NULL;
			close(fd2);
			set_default();
			return (-1);
		 }
		 close (fd2);
	}
	return (fd);
}

struct	lconv *
localeconv(void)
{
	return (lconv);
}

struct	dtconv *
localdtconv(void)
{
	char *p;
	short i;

	char *rawmonths = "Jan\nFeb\nMar\nApr\nMay\nJun\nJul\nAug\nSep\nOct\nNov\nDec\nJanuary\nFebruary\nMarch\nApril\nMay\nJune\nJuly\nAugust\nSeptember\nOctober\nNovember\nDecember";

	char *rawdays = "Sun\nMon\nTue\nWed\nThu\nFri\nSat\nSunday\nMonday\nTuesday\nWednesday\nThursday\nFriday\nSaturday";

char *rawfmts = "%H:%M:%S\n%m/%d/%y\n%a %b %e %T %Z %Y\nAM\nPM\n%A, %B %e, %Y\n";

	/* fix for bugid 1067574 ... robinson */
        (void)getlocale_time();

	if (_dtconv == NULL) {

		/* We malloc both the space for the dtconv struct and the
		 * copy of the strings above because this program is later run
		 * through xstr and the resultant strings are put in read-only
		 * text segment. Therefore we cannot write to the original
		 * raw strings but we can to their copies.
		 */

		_dtconv = (struct dtconv*)malloc(sizeof (struct dtconv));
		if (_dtconv == NULL)
			return (NULL);
		if ((realmonths = malloc(strlen(rawmonths)+1)) == NULL)
			return (NULL);
		strcpy(realmonths, rawmonths);
		if ((realdays = malloc(strlen(rawdays)+1)) == NULL)
			return (NULL);
		strcpy(realdays, rawdays);
		if ((realfmts = malloc(strlen(rawfmts)+1)) == NULL)
			return (NULL);
		strcpy(realfmts, rawfmts);

		/* p will "walk thru" str */

		p = realmonths;

		for (i = 0; i < 12; i++)
			p = getstr(p, &(_dtconv->abbrev_month_names[i]));

		for (i = 0; i < 12; i++)
			p = getstr(p, &(_dtconv->month_names[i]));
		p = realdays;
		for (i= 0; i < 7; i++)
			p = getstr(p, &(_dtconv->abbrev_weekday_names[i]));
		for (i = 0; i < 7; i++)
			p = getstr(p, &(_dtconv->weekday_names[i]));
		p = realfmts;
		p = getstr(p, &_dtconv->time_format);
		p = getstr(p, &_dtconv->sdate_format);
		p = getstr(p, &_dtconv->dtime_format);
		p = getstr(p, &_dtconv->am_string);
		p = getstr(p, &_dtconv->pm_string);
		p = getstr(p, &_dtconv->ldate_format);
	}

	return (_dtconv);
}


static void
set_default(void)
{

	strcpy(_code_set_info.code_name, Default);
	_code_set_info.code_id = CODESET_NONE;
	if (_code_set_info.code_info != NULL)
		free (_code_set_info.code_info);
	_code_set_info.code_info = NULL;
	_code_set_info.open_flag = 0;
}

void
init_statics(void)
{

	short i;

	for (i=0; i<MAXLOCALE-1;i++)
		strcpy(_locales[i],"C");
	strcpy(_code_set_info.code_name, "default");
	strcpy(_my_time,"C");
	_langinfo.yesstr = "yes";
	_langinfo.nostr = "no";
}
