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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * locale -- get current locale information
 *
 * Copyright 1991, 1993 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * locale: get locale-specific information
 * usage:  locale [-a|-m]
 *         locale [-ck] name ...
 */

/*
 * New members added in the struct lconv by IEEE Std 1003.1-2001
 * are always activated in the locale object.
 * See <iso/locale_iso.h>.
 */
#define	_LCONV_C99

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <stddef.h>
#include <nl_types.h>
#include <langinfo.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>

#define	LC_LOCDEF	999	/* Random number! */

#define	LOCALE_DIR		"/usr/lib/locale/"
#define	CHARMAP_DIR		"/usr/lib/localedef/src/"
#define	CHARMAP_NAME	"charmap.src"

#define	GET_LOCALE	0
#define	GET_CHARMAP	1
#define	CSSIZE	128

#ifndef isblank
#define	isblank(c)	((__ctype + 1)[c] & _B)
#endif

enum types {
	TYPE_STR,	/* char * */
	TYPE_GROUP,	/* char *, for mon_grouping, and grouping */
	TYPE_INT,	/* int */
	TYPE_CHR,	/* char, printed as signed integer */
	TYPE_PCHR,	/* char, printed as printable character */
	TYPE_CTP,	/* ctype entry */
	TYPE_CNVL,	/* convert to lower */
	TYPE_CNVU,	/* convert to upper */
	TYPE_COLLEL	/* print the multi-character collating elements */
};

static int	print_locale_info(char *keyword, int cflag, int kflag);
static int	print_category(int category, int cflag, int kflag);
static int	print_keyword(char *name, int cflag, int kflag);
static void	usage(void);
static void	print_all_info(int);
static void	print_cur_locale(void);
static void	outstr(char *s);
static void	outchar(int);
static void	prt_ctp(char *);
static void	prt_cnv(char *);
static void	prt_collel(char *);
static char	get_escapechar(void);
static char	get_commentchar(void);

static char	*save_loc;

/*
 * yes/no is not in the localeconv structure for xpg style.
 * We dummy up a new structure for purposes of the code below.
 * If YESEXPR is available per XPG4, we use it.
 * Otherwise, use YESSTR, the old method with less functionality from XPG3.
 */
struct yesno {
	char	*yes_expr;
	char	*no_expr;
	char	*yes_str;
	char	*no_str;
};

struct dtconv {
	char	*date_time_format;
	char	*date_format;
	char	*time_format;
	char	*time_format_ampm;
	char	*am_string;
	char	*pm_string;
	char	*abbrev_day_names[7];
	char	*day_names[7];
	char	*abbrev_month_names[12];
	char	*month_names[12];
	char	*era;
	char	*era_d_fmt;
	char	*era_d_t_fmt;
	char	*era_t_fmt;
	char	*alt_digits;
};

struct localedef {
	char	*charmap;
	char	*code_set_name;
	char	escape_char;
	char	comment_char;
	int		mb_cur_max;
	int		mb_cur_min;
};

static struct yesno *
getyesno(void)
{
	static struct yesno	yn;
	static int	loaded = 0;

	if (loaded) {
		return (&yn);
		/* NOTREACHED */
	}

	yn.yes_expr = strdup(nl_langinfo(YESEXPR));
	yn.no_expr = strdup(nl_langinfo(NOEXPR));
	yn.yes_str = strdup(nl_langinfo(YESSTR));
	yn.no_str = strdup(nl_langinfo(NOSTR));

	loaded = 1;
	return (&yn);
}

static struct dtconv *
localedtconv(void)
{
	static struct dtconv	_dtconv;
	static int				loaded = 0;

	if (loaded) {
		return (&_dtconv);
		/* NOTREACHED */
	}

	_dtconv.date_time_format = strdup(nl_langinfo(D_T_FMT));
	_dtconv.date_format = strdup(nl_langinfo(D_FMT));
	_dtconv.time_format = strdup(nl_langinfo(T_FMT));
	_dtconv.time_format_ampm = strdup(nl_langinfo(T_FMT_AMPM));
	_dtconv.am_string = strdup(nl_langinfo(AM_STR));
	_dtconv.pm_string = strdup(nl_langinfo(PM_STR));
	_dtconv.abbrev_day_names[0] = strdup(nl_langinfo(ABDAY_1));
	_dtconv.abbrev_day_names[1] = strdup(nl_langinfo(ABDAY_2));
	_dtconv.abbrev_day_names[2] = strdup(nl_langinfo(ABDAY_3));
	_dtconv.abbrev_day_names[3] = strdup(nl_langinfo(ABDAY_4));
	_dtconv.abbrev_day_names[4] = strdup(nl_langinfo(ABDAY_5));
	_dtconv.abbrev_day_names[5] = strdup(nl_langinfo(ABDAY_6));
	_dtconv.abbrev_day_names[6] = strdup(nl_langinfo(ABDAY_7));
	_dtconv.day_names[0] = strdup(nl_langinfo(DAY_1));
	_dtconv.day_names[1] = strdup(nl_langinfo(DAY_2));
	_dtconv.day_names[2] = strdup(nl_langinfo(DAY_3));
	_dtconv.day_names[3] = strdup(nl_langinfo(DAY_4));
	_dtconv.day_names[4] = strdup(nl_langinfo(DAY_5));
	_dtconv.day_names[5] = strdup(nl_langinfo(DAY_6));
	_dtconv.day_names[6] = strdup(nl_langinfo(DAY_7));
	_dtconv.abbrev_month_names[0] = strdup(nl_langinfo(ABMON_1));
	_dtconv.abbrev_month_names[1] = strdup(nl_langinfo(ABMON_2));
	_dtconv.abbrev_month_names[2] = strdup(nl_langinfo(ABMON_3));
	_dtconv.abbrev_month_names[3] = strdup(nl_langinfo(ABMON_4));
	_dtconv.abbrev_month_names[4] = strdup(nl_langinfo(ABMON_5));
	_dtconv.abbrev_month_names[5] = strdup(nl_langinfo(ABMON_6));
	_dtconv.abbrev_month_names[6] = strdup(nl_langinfo(ABMON_7));
	_dtconv.abbrev_month_names[7] = strdup(nl_langinfo(ABMON_8));
	_dtconv.abbrev_month_names[8] = strdup(nl_langinfo(ABMON_9));
	_dtconv.abbrev_month_names[9] = strdup(nl_langinfo(ABMON_10));
	_dtconv.abbrev_month_names[10] = strdup(nl_langinfo(ABMON_11));
	_dtconv.abbrev_month_names[11] = strdup(nl_langinfo(ABMON_12));
	_dtconv.month_names[0] = strdup(nl_langinfo(MON_1));
	_dtconv.month_names[1] = strdup(nl_langinfo(MON_2));
	_dtconv.month_names[2] = strdup(nl_langinfo(MON_3));
	_dtconv.month_names[3] = strdup(nl_langinfo(MON_4));
	_dtconv.month_names[4] = strdup(nl_langinfo(MON_5));
	_dtconv.month_names[5] = strdup(nl_langinfo(MON_6));
	_dtconv.month_names[6] = strdup(nl_langinfo(MON_7));
	_dtconv.month_names[7] = strdup(nl_langinfo(MON_8));
	_dtconv.month_names[8] = strdup(nl_langinfo(MON_9));
	_dtconv.month_names[9] = strdup(nl_langinfo(MON_10));
	_dtconv.month_names[10] = strdup(nl_langinfo(MON_11));
	_dtconv.month_names[11] = strdup(nl_langinfo(MON_12));
	_dtconv.era = strdup(nl_langinfo(ERA));
	_dtconv.era_d_fmt = strdup(nl_langinfo(ERA_D_FMT));
	_dtconv.era_d_t_fmt = strdup(nl_langinfo(ERA_D_T_FMT));
	_dtconv.era_t_fmt = strdup(nl_langinfo(ERA_T_FMT));
	_dtconv.alt_digits = strdup(nl_langinfo(ALT_DIGITS));

	loaded = 1;
	return (&_dtconv);
}

static struct localedef *
localeldconv(void)
{
	static struct localedef	_locdef;
	static int	loaded = 0;

	if (loaded) {
		return (&_locdef);
		/* NOTREACHED */
	}

	_locdef.charmap = strdup(nl_langinfo(CODESET));
	_locdef.code_set_name = strdup(nl_langinfo(CODESET));
	_locdef.mb_cur_max = MB_CUR_MAX;
	_locdef.mb_cur_min = 1;
	_locdef.escape_char = get_escapechar();
	_locdef.comment_char = get_commentchar();

	loaded = 1;
	return (&_locdef);
}

/*
 * The locale_name array also defines a canonical ordering for the categories.
 * The function tocanon() translates the LC_* manifests to their canonical
 * values.
 */
static struct locale_name {
	char	*name;
	int 	category;
} locale_name[] = {
	{"LC_CTYPE",	LC_CTYPE},
	{"LC_NUMERIC",	LC_NUMERIC},
	{"LC_TIME",		LC_TIME},
	{"LC_COLLATE",	LC_COLLATE},
	{"LC_MONETARY",	LC_MONETARY},
	{"LC_MESSAGES",	LC_MESSAGES},
	{"LC_ALL",		LC_ALL},
	NULL
};

/*
 * The structure key contains all keywords string name,
 * symbolic name, category, and type (STR INT ...)
 * the type will decide the way the value of the item be printed out
 */
static struct key {
	char		*name;
	void		*(*structure)(void);
	int			offset;
	int			count;
	int			category;
	enum types	type;
} key[] = {

#define	SPECIAL		0, 0, 0,
	{"lower",	SPECIAL	LC_CTYPE,	TYPE_CTP},
	{"upper",	SPECIAL	LC_CTYPE,	TYPE_CTP},
	{"alpha",	SPECIAL	LC_CTYPE,	TYPE_CTP},
	{"digit",	SPECIAL	LC_CTYPE,	TYPE_CTP},
	{"space",	SPECIAL	LC_CTYPE,	TYPE_CTP},
	{"cntrl",	SPECIAL	LC_CTYPE,	TYPE_CTP},
	{"punct",	SPECIAL	LC_CTYPE,	TYPE_CTP},
	{"graph",	SPECIAL	LC_CTYPE,	TYPE_CTP},
	{"print",	SPECIAL	LC_CTYPE,	TYPE_CTP},
	{"xdigit",	SPECIAL	LC_CTYPE,	TYPE_CTP},
	{"blank",	SPECIAL	LC_CTYPE,	TYPE_CTP},

	{"tolower",	SPECIAL	LC_CTYPE,	TYPE_CNVL},
	{"toupper",	SPECIAL	LC_CTYPE,	TYPE_CNVU},

	{"collating-element",	0, 0, 0, LC_COLLATE,	TYPE_COLLEL},
	{"character-collation",	0, 1, 0, LC_COLLATE,	TYPE_COLLEL},

#define	dt(member, count) \
		(void *(*)(void))localedtconv, \
		offsetof(struct dtconv, member), \
		count, \
		LC_TIME, \
		TYPE_STR
	{"d_t_fmt",	dt(date_time_format, 1)},
	{"d_fmt",	dt(date_format, 1)},
	{"t_fmt",	dt(time_format, 1)},
	{"t_fmt_ampm",	dt(time_format_ampm, 1)},
	{"am_pm",	dt(am_string, 2)},
	{"day",		dt(day_names, 7)},
	{"abday",	dt(abbrev_day_names, 7)},
	{"mon",		dt(month_names, 12)},
	{"abmon",	dt(abbrev_month_names, 12)},
	{"era",		dt(era, 1)},
	{"era_d_fmt",	dt(era_d_fmt, 1)},
	{"era_d_t_fmt",	dt(era_d_t_fmt, 1)},
	{"era_t_fmt",	dt(era_t_fmt, 1)},
	{"alt_digits",	dt(alt_digits, 1)},

#undef dt

#define	lc(member, locale, type) \
		(void *(*)(void))localeconv, \
		offsetof(struct lconv, member), \
		1, \
		locale, \
		type
{"decimal_point",	lc(decimal_point, 	LC_NUMERIC, TYPE_STR) },
{"thousands_sep",	lc(thousands_sep, 	LC_NUMERIC, TYPE_STR) },
{"grouping",		lc(grouping,		LC_NUMERIC, TYPE_GROUP)},
{"int_curr_symbol",	lc(int_curr_symbol,	LC_MONETARY, TYPE_STR)},
{"currency_symbol",	lc(currency_symbol,	LC_MONETARY, TYPE_STR)},
{"mon_decimal_point",	lc(mon_decimal_point,	LC_MONETARY, TYPE_STR)},
{"mon_thousands_sep",	lc(mon_thousands_sep,	LC_MONETARY, TYPE_STR)},
{"mon_grouping",	lc(mon_grouping,	LC_MONETARY, TYPE_GROUP)},
{"positive_sign",	lc(positive_sign,	LC_MONETARY, TYPE_STR)},
{"negative_sign",	lc(negative_sign,	LC_MONETARY, TYPE_STR)},

{"int_frac_digits",	lc(int_frac_digits,	LC_MONETARY, TYPE_CHR)},
{"frac_digits",		lc(frac_digits,		LC_MONETARY, TYPE_CHR)},
{"p_cs_precedes",	lc(p_cs_precedes,	LC_MONETARY, TYPE_CHR)},
{"p_sep_by_space",	lc(p_sep_by_space,	LC_MONETARY, TYPE_CHR)},
{"n_cs_precedes",	lc(n_cs_precedes,	LC_MONETARY, TYPE_CHR)},
{"n_sep_by_space",	lc(n_sep_by_space,	LC_MONETARY, TYPE_CHR)},
{"p_sign_posn",		lc(p_sign_posn,		LC_MONETARY, TYPE_CHR)},
{"n_sign_posn",		lc(n_sign_posn,		LC_MONETARY, TYPE_CHR)},
{"int_p_cs_precedes",	lc(int_p_cs_precedes,	LC_MONETARY, TYPE_CHR)},
{"int_p_sep_by_space",	lc(int_p_sep_by_space,	LC_MONETARY, TYPE_CHR)},
{"int_n_cs_precedes",	lc(int_n_cs_precedes,	LC_MONETARY, TYPE_CHR)},
{"int_n_sep_by_space",	lc(int_n_sep_by_space,	LC_MONETARY, TYPE_CHR)},
{"int_p_sign_posn",	lc(int_p_sign_posn,	LC_MONETARY, TYPE_CHR)},
{"int_n_sign_posn",	lc(int_n_sign_posn,	LC_MONETARY, TYPE_CHR)},

#undef lc
#define	lc(member) \
		(void *(*)(void))getyesno, \
		offsetof(struct yesno, member), \
		1, \
		LC_MESSAGES, \
		TYPE_STR
	{"yesexpr",		lc(yes_expr)},
	{"noexpr",		lc(no_expr)},
	{"yesstr",		lc(yes_str)},
	{"nostr",		lc(no_str)},
#undef lc

	/*
	 * Following keywords have no official method of obtaining them
	 */
#define	ld(member, locale, type) \
		(void *(*)(void))localeldconv, \
		offsetof(struct localedef, member), \
		1, \
		locale, \
		type
	{"charmap",		ld(charmap,		LC_LOCDEF, TYPE_STR)},
	{"code_set_name",	ld(code_set_name,	LC_LOCDEF, TYPE_STR)},
	{"escape_char",		ld(escape_char,		LC_LOCDEF, TYPE_PCHR)},
	{"comment_char",	ld(comment_char,	LC_LOCDEF, TYPE_PCHR)},
	{"mb_cur_max",		ld(mb_cur_max,		LC_LOCDEF, TYPE_INT)},
	{"mb_cur_min",		ld(mb_cur_min,		LC_LOCDEF, TYPE_INT)},
#undef ld

	{NULL,			NULL,			0, 0}
};

static char escapec;

int
main(int argc, char **argv)
{
	int		c;
	int		retval = 0;
	int		cflag, kflag, aflag, mflag;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	cflag = kflag = aflag = mflag = 0;

	while ((c = getopt(argc, argv, "amck")) != EOF) {
		switch (c) {
		case 'a':
			aflag = 1;
			break;
		case 'm':
			mflag = 1;
			break;
		case 'c':
			cflag = 1;
			break;
		case 'k':
			kflag = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
			break;
		}
	}

	/* -a OR -m OR (-c and/or -k) */
	if ((aflag && mflag) || ((aflag || mflag) && (cflag || kflag))) {
		usage();
		/* NOTREACHED */
	}

	escapec = get_escapechar();

	if (aflag) {
		print_all_info(GET_LOCALE);
		/* NOTREACHED */
	}

	if (mflag) {
		print_all_info(GET_CHARMAP);
		/* NOTREACHED */
	}

	if (optind == argc && !cflag && !kflag) {
		print_cur_locale();
		/* NOTREACHED */
	}
	if (optind == argc) {
		usage();
		/* NOTREACHED */
	}

	for (; optind < argc; optind++) {
		retval += print_locale_info(argv[optind], cflag, kflag);
	}
	return (retval);
}

/*
 * No options or operands.
 * Print out the current locale names from the environment, or implied.
 * Variables directly set in the environment are printed as-is, those
 * implied are printed in quotes.
 * The strings are printed ``appropriately quoted for possible later re-entry
 * to the shell''.  We use the routine outstr to do this -- however we
 * want the shell escape character, the backslash, not the locale escape
 * character, so we quietly save and restore the locale escape character.
 */
static void
print_cur_locale(void)
{
	char	*lc_allp;
	char	*env, *eff;
	int		i;

	if ((env = getenv("LANG")) != NULL) {
		(void) printf("LANG=%s\n", env);
	} else {
		(void) printf("LANG=\n");
	}

	lc_allp = getenv("LC_ALL");

	for (i = 0; i < LC_ALL; i++) {
		(void) printf("%s=", locale_name[i].name);
		eff = setlocale(i, NULL);
		if (eff == NULL) {
			eff = "";
		}
		env = getenv(locale_name[i].name);

		if (env == NULL) {
			(void) putchar('"');
			outstr(eff);
			(void) putchar('"');
		} else {
			if (strcmp(env, eff) != 0) {
				(void) putchar('"');
				outstr(eff);
				(void) putchar('"');
			} else {
				outstr(eff);
			}
		}
		(void) putchar('\n');
	}

	(void) printf("LC_ALL=");
	if (lc_allp != NULL) {
		outstr(lc_allp);
	}
	(void) putchar('\n');
	exit(0);
}

static int	num_of_loc = 0;
static int	num_of_entries = 0;
static char	**entries = NULL;

static void
add_loc_entry(char *loc)
{
#define	_INC_NUM	10
	char	*s;

	if (num_of_loc >= num_of_entries) {
		char	**tmp;
		num_of_entries += _INC_NUM;
		tmp = realloc(entries, sizeof (char *) * num_of_entries);
		if (tmp == NULL) {
			/* restoring original locale */
			(void) setlocale(LC_ALL, save_loc);
			(void) fprintf(stderr,
			    gettext("locale: cannot allocate buffer"));
			exit(1);
		}
		entries = tmp;
	}
	s = strdup(loc);
	if (s == NULL) {
		/* restoring original locale */
		(void) setlocale(LC_ALL, save_loc);
		(void) fprintf(stderr,
		    gettext("locale: cannot allocate buffer"));
		exit(1);
	}
	entries[num_of_loc] = s;

	num_of_loc++;
}

static int
loccmp(const char **str1, const char **str2)
{
	return (strcmp(*str1, *str2));
}

static void
show_loc_entry(void)
{
	int	i;

	qsort(entries, num_of_loc, sizeof (char *),
	    (int (*)(const void *, const void *))loccmp);
	for (i = 0; i < num_of_loc; i++) {
		(void) printf("%s\n", entries[i]);
	}
}

static void
check_loc(char *loc)
{
	int	cat;

	/* first, try LC_ALL */
	if (setlocale(LC_ALL, loc) != NULL) {
		/* succeeded */
		add_loc_entry(loc);
		return;
	}

	/*
	 * LC_ALL failed.
	 * try each category.
	 */
	for (cat = 0; cat <= _LastCategory; cat++) {
		if (setlocale(cat, loc) != NULL) {
			/* succeeded */
			add_loc_entry(loc);
			return;
		}
	}

	/* loc is not a valid locale */
}

/*
 * print_all_info(): Print out all the locales and
 *                   charmaps supported by the system
 */
static void
print_all_info(int flag)
{
	struct dirent	*direntp;
	DIR				*dirp;
	char			*filename;		/* filename[PATH_MAX] */
	char			*p;

	if ((filename = malloc(PATH_MAX)) == NULL) {
		(void) fprintf(stderr,
		    gettext("locale: cannot allocate buffer"));
		exit(1);
	}

	(void) memset(filename, 0, PATH_MAX);

	if (flag == GET_LOCALE) {
		/* save the current locale */
		save_loc = setlocale(LC_ALL, NULL);

		(void) strcpy(filename, LOCALE_DIR);
		add_loc_entry("POSIX");
	} else {						/* CHARMAP */
		(void) strcpy(filename, CHARMAP_DIR);
	}

	if ((dirp = opendir(filename)) == NULL) {
		if (flag == GET_LOCALE)
			exit(0);
		else {					/* CHARMAP */
			(void) fprintf(stderr, gettext(
			    "locale: charmap information not available.\n"));
			exit(2);
		}
	}

	p = filename + strlen(filename);
	while ((direntp = readdir(dirp)) != NULL) {
		struct stat stbuf;

		(void) strcpy(p, direntp->d_name);
		if (stat(filename, &stbuf) < 0) {
			continue;
		}

		if (flag == GET_LOCALE) {
			if (S_ISDIR(stbuf.st_mode) &&
			    (direntp->d_name[0] != '.') &&
			    /* "POSIX" has already been printed out */
			    strcmp(direntp->d_name, "POSIX") != 0) {
				check_loc(direntp->d_name);
			}
		} else {			/* CHARMAP */
			if (S_ISDIR(stbuf.st_mode) &&
			    direntp->d_name[0] != '.') {
				struct dirent	*direntc;
				DIR		*dirc;
				char		*charmap;
				char		*c;

				if ((charmap = malloc(PATH_MAX)) == NULL) {
					(void) fprintf(stderr,
				    gettext("locale: cannot allocate buffer"));
					exit(1);
				}

				(void) memset(charmap, 0, PATH_MAX);

				(void) strcpy(charmap, filename);

				if ((dirc = opendir(charmap)) == NULL) {
					exit(0);
				}

				c = charmap + strlen(charmap);
				*c++ = '/';
				while ((direntc = readdir(dirc)) != NULL) {
					struct stat stbuf;

					(void) strcpy(c, direntc->d_name);
					if (stat(charmap, &stbuf) < 0) {
						continue;
					}

					if (S_ISREG(stbuf.st_mode) &&
						(strcmp(direntc->d_name,
							CHARMAP_NAME) == 0) &&
						(direntc->d_name[0] != '.')) {
						(void) printf("%s/%s\n",
							p, direntc->d_name);
					}
				}
				(void) closedir(dirc);
				free(charmap);
			}
		}
	}
	if (flag == GET_LOCALE) {
		/* restore the saved loc */
		(void) setlocale(LC_ALL, save_loc);
		show_loc_entry();
	}
	(void) closedir(dirp);
	free(filename);
	exit(0);
}

/*
 * Print out the keyword value or category info.
 * Call print_category() to print the entire locale category, if the name
 * given is recognized as a category.
 * Otherwise, assume that it is a keyword, and call print_keyword().
 */
static int
print_locale_info(char *name, int cflag, int kflag)
{
	int i;

	for (i = 0; locale_name[i].name != NULL; i++) {
		if (strcmp(locale_name[i].name, name) == 0) {
			/*
			 * name is a category name
			 * print out all keywords in this category
			 */
			return (print_category(locale_name[i].category,
				cflag, kflag));
		}
	}

	/* The name is a keyword name */
	return (print_keyword(name, cflag, kflag));
}

/*
 * Print out the value of the keyword
 */
static int
print_keyword(char *name, int cflag, int kflag)
{
	int		i, j;
	int		first_flag = 1;
	int		found = 0;

	for (i = 0; key[i].name != NULL; i++) {
		if (strcmp(key[i].name, name) != 0) {
			continue;
		}

		found = 1;
		if (first_flag && cflag && key[i].category != LC_LOCDEF) {
			/* print out this category's name */
			(void) printf("%s\n",
				locale_name[key[i].category].name);
		}
		if (kflag) {
			(void) printf("%s=", name);
		}
		switch (key[i].type) {

		/*
		 * The grouping fields are a set of bytes, each of which
		 * is the numeric value of the next group size, terminated
		 * by a \0, or by CHAR_MAX
		 */
		case TYPE_GROUP:
			{
				void	*s;
				char	*q;
				int		first = 1;

				s = (*key[i].structure)();
				/* LINTED */
				q = *(char **)((char *)s + key[i].offset);
				if (*q == '\0') {
					(void) printf("-1");
					break;
				}
				while (*q != '\0' && *q != CHAR_MAX) {
					if (!first) {
						(void) putchar(';');
					}
					first = 0;
					(void) printf("%u",
					    *(unsigned char *)q++);
				}
				/* CHAR_MAX: no further grouping performed. */
				if (!first) {
					(void) putchar(';');
				}
				if (*q == CHAR_MAX) {
					(void) printf("-1");
				} else {
					(void) putchar('0');
				}
			}
			break;

		/*
		 * Entries like decimal_point states ``the decimal-point
		 * character...'' not string.  However, it is a char *.
		 * This assumes single, narrow, character.
		 * Should it permit multibyte characters?
		 * Should it permit a whole string, in that case?
		 */
		case TYPE_STR:
			{
				void	*s;
				char	**q;

				s = (*key[i].structure)();
				/* LINTED */
				q = (char **)((char *)s + key[i].offset);
				for (j = 0; j < key[i].count; j++) {
					if (j != 0) {
						(void) printf(";");
					}
					if (kflag) {
						(void) printf("\"");
						outstr(q[j]);
						(void) printf("\"");
					} else {
						(void) printf("%s", q[j]);
					}
				}
			}
			break;

		case TYPE_INT:
			{
				void	*s;
				int		*q;

				s = (*key[i].structure)();
				/* LINTED */
				q = (int *)((char *)s + key[i].offset);
				(void) printf("%d", *q);
			}
			break;

		/*
		 * TYPE_CHR: Single byte integer.
		 */
		case TYPE_CHR:
			{
				void	*s;
				char	*q;

				s = (*key[i].structure)();
				q = (char *)((char *)s + key[i].offset);
				if (*q == CHAR_MAX) {
					(void) printf("-1");
				} else {
					(void) printf("%u",
					    *(unsigned char *)q);
				}
			}
			break;

		/*
		 * TYPE_PCHR: Single byte, printed as a character if printable
		 */
		case TYPE_PCHR:
			{
				void	*s;
				char	*q;

				s = (*key[i].structure)();
				q = (char *)((char *)s + key[i].offset);
				if (isprint(*(unsigned char *)q)) {
					if (kflag) {
						(void) printf("\"");
						if ((*q == '\\') ||
							(*q == ';') ||
							(*q == '"')) {
							(void) putchar(escapec);
							(void) printf("%c",
							*(unsigned char *)q);
						} else {
							(void) printf("%c",
							*(unsigned char *)q);
						}
						(void) printf("\"");
					} else {
						(void) printf("%c",
						    *(unsigned char *)q);
					}
				} else if (*q == (char)-1) {
					/* In case no signed chars */
					(void) printf("-1");
				} else {
					(void) printf("%u",
					    *(unsigned char *)q);
				}
			}
			break;

		case TYPE_CTP:
			{
				prt_ctp(key[i].name);
			}
			break;

		case TYPE_CNVU:
			{
				prt_cnv(key[i].name);
			}
			break;

		case TYPE_CNVL:
			{
				prt_cnv(key[i].name);
			}
			break;

		case TYPE_COLLEL:
			{
				prt_collel(key[i].name);
			}
			break;
		}
	}
	if (found) {
		(void) printf("\n");
		return (0);
	} else {
		(void) fprintf(stderr,
		    gettext("Unknown keyword name '%s'.\n"), name);
		return (1);
	}
}

/*
 * Strings being outputed have to use an unambiguous format --  escape
 * any potentially bad output characters.
 * The standard says that any control character shall be preceeded by
 * the escape character.  But it doesn't say that you can format that
 * character at all.
 * Question: If the multibyte character contains a quoting character,
 * should that *byte* be escaped?
 */
static void
outstr(char *s)
{
	wchar_t	ws;
	int		c;
	size_t	mbcurmax = MB_CUR_MAX;

	while (*s != '\0') {
		c = mbtowc(&ws, s, mbcurmax);
		if (c < 0) {
			s++;
		} else if (c == 1) {
			outchar(*s++);
		} else {
			for (; c > 0; c--) {
				(void) putchar(*s++);
			}
		}
	}
}

static void
outchar(int c)
{
	unsigned char	uc;

	uc = (unsigned char) c;

	if ((uc == '\\') || (uc == ';') || (uc == '"')) {
		(void) putchar(escapec);
		(void) putchar(uc);
	} else if (iscntrl(uc)) {
		(void) printf("%cx%02x", escapec, uc);
	} else {
		(void) putchar(uc);
	}
}

/*
 * print_category(): Print out all the keyword's value
 *                  in the given category
 */
static int
print_category(int category, int cflag, int kflag)
{
	int		i;
	int		retval = 0;

	if (category == LC_ALL) {
		retval += print_category(LC_CTYPE, cflag, kflag);
		retval += print_category(LC_NUMERIC, cflag, kflag);
		retval += print_category(LC_TIME, cflag, kflag);
		retval += print_category(LC_COLLATE, cflag, kflag);
		retval += print_category(LC_MONETARY, cflag, kflag);
		retval += print_category(LC_MESSAGES, cflag, kflag);
	} else {
		if (cflag) {
			(void) printf("%s\n",
			    locale_name[category].name);
		}

		for (i = 0; key[i].name != NULL; i++) {
			if (key[i].category == category) {
				retval += print_keyword(key[i].name, 0, kflag);
			}
		}
	}
	return (retval);
}

/*
 * usage message for locale
 */
static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "Usage: locale [-a|-m]\n"
	    "       locale [-ck] name ...\n"));
	exit(2);
}

static void
prt_ctp(char *name)
{
	int		idx, i, mem;
	int		first = 1;

	static const char	*reg_names[] = {
		"upper", "lower", "alpha", "digit", "space", "cntrl",
		"punct", "graph", "print", "xdigit", "blank", NULL
	};
	for (idx = 0; reg_names[idx] != NULL; idx++) {
		if (strcmp(name, reg_names[idx]) == 0) {
			break;
		}
	}
	if (reg_names[idx] == NULL) {
		return;
	}

	for (i = 0; i < CSSIZE; i++) {
		mem = 0;
		switch (idx) {
		case 0:
			mem = isupper(i);
			break;
		case 1:
			mem = islower(i);
			break;
		case 2:
			mem = isalpha(i);
			break;
		case 3:
			mem = isdigit(i);
			break;
		case 4:
			mem = isspace(i);
			break;
		case 5:
			mem = iscntrl(i);
			break;
		case 6:
			mem = ispunct(i);
			break;
		case 7:
			mem = isgraph(i);
			break;
		case 8:
			mem = isprint(i);
			break;
		case 9:
			mem = isxdigit(i);
			break;
		case 10:
			mem = isblank(i);
			break;
		}
		if (mem) {
			if (!first) {
				(void) putchar(';');
			}
			first = 0;
			(void) printf("\"");
			outchar(i);
			(void) printf("\"");
		}
	}
}

static void
prt_cnv(char *name)
{
	int		idx, i, q;
	int		first = 1;

	static const char	*reg_names[] = {
		"toupper", "tolower", NULL
	};
	for (idx = 0; reg_names[idx] != NULL; idx++) {
		if (strcmp(name, reg_names[idx]) == 0) {
			break;
		}
	}
	if (reg_names[idx] == NULL) {
		return;
	}

	for (i = 0; i < CSSIZE; i++) {
		switch (idx) {
		case 0:
			q = toupper(i);
			if (q == i) {
				continue;
			}
			if (!first) {
				(void) putchar(';');
			}
			first = 0;
			/* BEGIN CSTYLED */
			(void) printf("\"<'");
			/* END CSTYLED */
			outchar(i);
			(void) printf("','");
			outchar(q);
			(void) printf("'>\"");
			break;
		case 1:
			q = tolower(i);
			if (q == i) {
				continue;
			}
			if (!first) {
				(void) putchar(';');
			}
			first = 0;
			/* BEGIN CSTYLED */
			(void) printf("\"<'");
			/* END CSTYLED */
			outchar(i);
			(void) printf("','");
			outchar(q);
			(void) printf("'>\"");
			break;
		}
	}
}

/*
 * prt_collel(): Stub for the collate class which does nothing.
 */
/* ARGSUSED */
static void
prt_collel(char *name)
{
}

static char
get_escapechar(void)
{
	return ('\\');
}

static char
get_commentchar(void)
{
	return ('#');
}
