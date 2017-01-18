%{
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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <sys/param.h>
#include <ctype.h>
#include <stdio.h>
#include <search.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/kbd.h>
#include <sys/kbio.h>

#define	ALL	-1	/* special symbol for all tables */

static char	keytable_dir[] = "/usr/share/lib/keytables/type_%d/";
static char	layout_prefix[] = "layout_";

struct keyentry {
	struct keyentry	*ke_next;
	struct kiockeymap ke_entry;
};

typedef struct keyentry keyentry;

static keyentry *firstentry;
static keyentry *lastentry;

struct dupentry {
	struct dupentry *de_next;
	int	de_station;
	int	de_otherstation;
};

typedef struct dupentry dupentry;

static dupentry *firstduplicate;
static dupentry *lastduplicate;

static dupentry *firstswap;
static dupentry *lastswap;

static char	*infilename;
static FILE	*infile;
static int	lineno;
static int	begline;

static char	*strings[16] = {
	"\033[H",		/* HOMEARROW */
	"\033[A",		/* UPARROW */
	"\033[B",		/* DOWNARROW */
	"\033[D",		/* LEFTARROW */
	"\033[C",		/* RIGHTARROW */
};

static int	nstrings = 5;	/* start out with 5 strings */

typedef enum {
	SM_INVALID,	/* this shift mask is invalid for this keyboard */
	SM_NORMAL,	/* "normal", valid shift mask */
	SM_NUMLOCK,	/* "Num Lock" shift mask */
	SM_UP		/* "Up" shift mask */
} smtype_t;

typedef struct {
	int	sm_mask;
	smtype_t sm_type;
} smentry_t;

static	smentry_t shiftmasks[] = {
	{ 0,		SM_NORMAL },
	{ SHIFTMASK,	SM_NORMAL },
	{ CAPSMASK,	SM_NORMAL },
	{ CTRLMASK,	SM_NORMAL },
	{ ALTGRAPHMASK,	SM_NORMAL },
	{ NUMLOCKMASK,	SM_NUMLOCK },
	{ UPMASK,	SM_UP },
};


#define	NSHIFTS	(sizeof (shiftmasks) / sizeof (shiftmasks[0]))

static void	enter_mapentry(int station, keyentry *entrylistp);
static keyentry *makeentry(int tablemask, int entry);
static int	loadkey(int kbdfd, keyentry *kep);
static int	dupkey(int kbdfd, dupentry *dep, int shiftmask);
static int	swapkey(int kbdfd, dupentry *dep, int shiftmask);
static int	yylex();
extern int	yyparse(void);
static int	readesc(FILE *stream, int delim, int single_char);
static int	wordcmp(const void *w1, const void *w2);
static int	yyerror(char *msg);
static void	usage(void);
static void	set_layout(char *arg);
static FILE	*open_mapping_file(char *pathbuf, char *name,
			boolean_t explicit_name, int type);

int
main(int argc, char **argv)
{
	int kbdfd;
	int type;
	int layout;
	/* maxint is 8 hex digits. */
	char layout_filename[sizeof(layout_prefix)+8];
	char pathbuf[MAXPATHLEN];
	int shift;
	struct kiockeymap mapentry;
	keyentry *kep;
	dupentry *dep;
	boolean_t explicit_name;

	while(++argv, --argc) {
		if(argv[0][0] != '-') break;
		switch(argv[0][1]) {
		case 'e':
			/* -e obsolete, silently ignore */
			break;
		case 's':
			if (argc != 2) {
				usage();
				/* NOTREACHED */
			}
			set_layout(argv[1]);
			exit(0);
		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (argc > 1) usage();

	if ((kbdfd = open("/dev/kbd", O_WRONLY)) < 0) {
		/* perror("loadkeys: /dev/kbd"); */
		return (1);
	}

	if (ioctl(kbdfd, KIOCTYPE, &type) < 0) {
		/*
		 * There may not be a keyboard connected,
		 * return silently
		 */
		return (1);
	}

	if (argc == 0) {
		/* If no keyboard detected, exit silently. */
		if (type == -1)
			return (0);

		if (ioctl(kbdfd, KIOCLAYOUT, &layout) < 0) {
			perror("loadkeys: ioctl(KIOCLAYOUT)");
			return (1);
		}

		(void) sprintf(layout_filename,
				"%s%.2x", layout_prefix, layout);
		infilename = layout_filename;
		explicit_name = B_FALSE;
	} else {
		infilename = argv[0];
		explicit_name = B_TRUE;
	}

	infile = open_mapping_file(pathbuf, infilename, explicit_name, type);
	if (infile == NULL) return (1);

	infilename = pathbuf;

	lineno = 0;
	begline = 1;
	yyparse();
	fclose(infile);

	/*
	 * See which shift masks are valid for this keyboard.
	 * We do that by trying to get the entry for keystation 0 and that
	 * shift mask; if the "ioctl" fails, we assume it's because the shift
	 * mask is invalid.
	 */
	for (shift = 0; shift < NSHIFTS; shift++) {
		mapentry.kio_tablemask =
		    shiftmasks[shift].sm_mask;
		mapentry.kio_station = 0;
		if (ioctl(kbdfd, KIOCGKEY, &mapentry) < 0)
			shiftmasks[shift].sm_type = SM_INVALID;
	}

	for (kep = firstentry; kep != NULL; kep = kep->ke_next) {
		if (kep->ke_entry.kio_tablemask == ALL) {
			for (shift = 0; shift < NSHIFTS; shift++) {
				switch (shiftmasks[shift].sm_type) {

				case SM_INVALID:
					continue;

				case SM_NUMLOCK:
					/*
					 * Defaults to NONL, not to a copy of
					 * the base entry.
					 */
					if (kep->ke_entry.kio_entry != HOLE)
						kep->ke_entry.kio_entry = NONL;
					break;

				case SM_UP:
					/*
					 * Defaults to NOP, not to a copy of
					 * the base entry.
					 */
					if (kep->ke_entry.kio_entry != HOLE)
						kep->ke_entry.kio_entry = NOP;
					break;
				}
				kep->ke_entry.kio_tablemask =
				    shiftmasks[shift].sm_mask;
				if (!loadkey(kbdfd, kep))
					return (1);
			}
		} else {
			if (!loadkey(kbdfd, kep))
				return (1);
		}
	}

	for (dep = firstswap; dep != NULL; dep = dep->de_next) {
		for (shift = 0; shift < NSHIFTS; shift++) {
			if (shiftmasks[shift].sm_type != SM_INVALID) {
				if (!swapkey(kbdfd, dep,
				    shiftmasks[shift].sm_mask))
					return (0);
			}
		}
	}

	for (dep = firstduplicate; dep != NULL; dep = dep->de_next) {
		for (shift = 0; shift < NSHIFTS; shift++) {
			if (shiftmasks[shift].sm_type != SM_INVALID) {
				if (!dupkey(kbdfd, dep,
				    shiftmasks[shift].sm_mask))
					return (0);
			}
		}
	}

	close(kbdfd);
	return (0);
}

static void
usage()
{
	(void) fprintf(stderr, "usage: loadkeys [ file ]\n");
	exit(1);
}

static void
set_layout(char *arg)
{
	int layout;
	int ret;
	int kbdfd;

	layout = (int) strtol(arg, &arg, 0);
	if (*arg != '\0') {
		fprintf(stderr, "usage:  loadkeys -s layoutnumber\n");
		exit(1);
	}

	if ((kbdfd = open("/dev/kbd", O_WRONLY)) < 0) {
		perror("/dev/kbd");
		exit(1);
	}

	ret = ioctl(kbdfd, KIOCSLAYOUT, layout);
	if (ret == -1) {
		perror("KIOCSLAYOUT");
	}

	close(kbdfd);
}

/*
 * Attempt to find the specified mapping file.  Return a FILE * if found,
 * else print a message on stderr and return NULL.
 */
FILE *
open_mapping_file(char *pathbuf, char *name, boolean_t explicit_name, int type)
{
	/* If the user specified the name, try it "raw". */
	if (explicit_name) {
		strcpy(pathbuf, name);
		infile = fopen(pathbuf, "r");
		if (infile) return (infile);
		if (errno != ENOENT) goto fopen_fail;
	}

	/* Everything after this point applies only to relative names. */
	if (*name == '/') goto fopen_fail;

	/* Try the type-qualified directory name. */
	sprintf(pathbuf, keytable_dir, type);
	if ((int)(strlen(pathbuf) + strlen(name) + 1) >= MAXPATHLEN) {
		(void) fprintf(stderr, "loadkeys: Name %s is too long\n",
				name);
		return (NULL);
	}
	(void) strcat(pathbuf, name);
	if ((infile = fopen(pathbuf, "r")) != NULL)
		return (infile);

fopen_fail:
	(void) fprintf(stderr, "loadkeys: ");
	perror(name);
	return (NULL);
}

/*
 * We have a list of entries for a given keystation, and the keystation number
 * for that keystation; put that keystation number into all the entries in that
 * list, and chain that list to the end of the main list of entries.
 */
static void
enter_mapentry(station, entrylistp)
	int station;
	keyentry *entrylistp;
{
	register keyentry *kep;

	if (lastentry == NULL)
		firstentry = entrylistp;
	else
		lastentry->ke_next = entrylistp;
	kep = entrylistp;
	for (;;) {
		kep->ke_entry.kio_station = (u_char)station;
		if (kep->ke_next == NULL) {
			lastentry = kep;
			break;
		}
		kep = kep->ke_next;
	}
}

/*
 * Allocate and fill in a new entry.
 */
static keyentry *
makeentry(tablemask, entry)
	int tablemask;
	int entry;
{
	register keyentry *kep;
	register int index;

	if ((kep = (keyentry *) malloc((unsigned)sizeof (keyentry))) == NULL)
		yyerror("out of memory for entries");
	kep->ke_next = NULL;
	kep->ke_entry.kio_tablemask = tablemask;
	kep->ke_entry.kio_station = 0;
	kep->ke_entry.kio_entry = entry;
	index = entry - STRING;
	if (index >= 0 && index <= 15)
		(void) strncpy(kep->ke_entry.kio_string, strings[index],
		    KTAB_STRLEN);
	return (kep);
}

/*
 * Make a set of entries for a keystation that indicate that that keystation's
 * settings should be copied from another keystation's settings.
 */
static void
duplicate_mapentry(station, otherstation)
	int station;
	int otherstation;
{
	register dupentry *dep;

	if ((dep = (dupentry *) malloc((unsigned)sizeof (dupentry))) == NULL)
		yyerror("out of memory for entries");

	if (lastduplicate == NULL)
		firstduplicate = dep;
	else
		lastduplicate->de_next = dep;
	lastduplicate = dep;
	dep->de_next = NULL;
	dep->de_station = station;
	dep->de_otherstation = otherstation;
}

/*
 * Make a set of entries for a keystation that indicate that that keystation's
 * settings should be swapped with another keystation's settings.
 */
static void
swap_mapentry(station, otherstation)
	int station;
	int otherstation;
{
	register dupentry *dep;

	if ((dep = (dupentry *) malloc((unsigned)sizeof (dupentry))) == NULL)
		yyerror("out of memory for entries");

	if (lastswap == NULL)
		firstswap = dep;
	else
		lastswap->de_next = dep;
	lastswap = dep;
	dep->de_next = NULL;
	dep->de_station = station;
	dep->de_otherstation = otherstation;
}

static int
loadkey(kbdfd, kep)
	int kbdfd;
	register keyentry *kep;
{
	if (ioctl(kbdfd, KIOCSKEY, &kep->ke_entry) < 0) {
		perror("loadkeys: ioctl(KIOCSKEY)");
		return (0);
	}
	return (1);
}

static int
dupkey(kbdfd, dep, shiftmask)
	int kbdfd;
	register dupentry *dep;
	int shiftmask;
{
	struct kiockeymap entry;

	entry.kio_tablemask = shiftmask;
	entry.kio_station = dep->de_otherstation;
	if (ioctl(kbdfd, KIOCGKEY, &entry) < 0) {
		perror("loadkeys: ioctl(KIOCGKEY)");
		return (0);
	}
	entry.kio_station = dep->de_station;
	if (ioctl(kbdfd, KIOCSKEY, &entry) < 0) {
		perror("loadkeys: ioctl(KIOCSKEY)");
		return (0);
	}
	return (1);
}



static int
swapkey(kbdfd, dep, shiftmask)
	int kbdfd;
	register dupentry *dep;
	int shiftmask;
{
	struct kiockeymap entry1, entry2;

	entry1.kio_tablemask = shiftmask;
	entry1.kio_station = dep->de_station;
	if (ioctl(kbdfd, KIOCGKEY, &entry1) < 0) {
		perror("loadkeys: ioctl(KIOCGKEY)");
		return (0);
	}
	entry2.kio_tablemask = shiftmask;
	entry2.kio_station = dep->de_otherstation;
	if (ioctl(kbdfd, KIOCGKEY, &entry2) < 0) {
		perror("loadkeys: ioctl(KIOCGKEY)");
		return (0);
	}
	entry1.kio_station = dep->de_otherstation;
	if (ioctl(kbdfd, KIOCSKEY, &entry1) < 0) {
		perror("loadkeys: ioctl(KIOCSKEY)");
		return (0);
	}
	entry2.kio_station = dep->de_station;
	if (ioctl(kbdfd, KIOCSKEY, &entry2) < 0) {
		perror("loadkeys: ioctl(KIOCSKEY)");
		return (0);
	}
	return (1);
}
%}

%term TABLENAME INT CHAR CHARSTRING CONSTANT FKEY KEY SAME AS SWAP WITH

%union {
	keyentry *keyentry;
	int	number;
};

%type <keyentry>	entrylist entry
%type <number>		CHARSTRING CHAR INT CONSTANT FKEY TABLENAME
%type <number>		code expr term number

%%

table:
	table line
|	/* null */
;

line:
	KEY number entrylist '\n'
		{
		enter_mapentry($2, $3);
		}
|	KEY number SAME AS number '\n'
		{
		duplicate_mapentry($2, $5);
		}
|	SWAP number WITH number '\n'
		{
		swap_mapentry($2, $4);
		}
|	'\n'
;

entrylist:
	entrylist entry
		{
		/*
		 * Append this entry to the end of the entry list.
		 */
		register keyentry *kep;
		kep = $1;
		for (;;) {
			if (kep->ke_next == NULL) {
				kep->ke_next = $2;
				break;
			}
			kep = kep->ke_next;
		}
		$$ = $1;
		}
|	entry
		{
		$$ = $1;
		}
;

entry:
	TABLENAME code
		{
		$$ = makeentry($1, $2);
		}
;

code:
	CHARSTRING
		{
		$$ = $1;
		}
|	CHAR
		{
		$$ = $1;
		}
|	INT
		{
		$$ = $1;
		}
|	'('
		{
		$$ = '(';
		}
|	')'
		{
		$$ = ')';
		}
|	'+'
		{
		$$ = '+';
		}
|	expr
		{
		$$ = $1;
		}
;

expr:
	term
		{
		$$ = $1;
		}
|	expr '+' term
		{
		$$ = $1 + $3;
		}
;

term:
	CONSTANT
		{
		$$ = $1;
		}
|	FKEY '(' number ')'
		{
		if ($3 < 1 || $3 > 16)
			yyerror("invalid function key number");
		$$ = $1 + $3 - 1;
		}
;

number:
	INT
		{
		$$ = $1;
		}
|	CHAR
		{
		if (isdigit($1))
			$$ = $1 - '0';
		else
			yyerror("syntax error");
		}
;

%%

typedef struct {
	char	*w_string;
	int	w_type;		/* token type */
	int	w_lval;		/* yylval for this token */
} word_t;

/*
 * Table must be in alphabetical order.
 */
word_t	wordtab[] = {
	{ "all",	TABLENAME,	ALL },
	{ "alt",	CONSTANT,	ALT },
	{ "altg",	TABLENAME,	ALTGRAPHMASK },
	{ "altgraph",	CONSTANT,	ALTGRAPH },
	{ "as",		AS,		0 },
	{ "base",	TABLENAME,	0 },
	{ "bf",		FKEY,		BOTTOMFUNC },
	{ "buckybits",	CONSTANT,	BUCKYBITS },
	{ "caps",	TABLENAME,	CAPSMASK },
	{ "capslock",	CONSTANT,	CAPSLOCK },
	{ "compose",	CONSTANT,	COMPOSE },
	{ "ctrl",	TABLENAME,	CTRLMASK },
	{ "downarrow",	CONSTANT,	DOWNARROW },
	{ "error",	CONSTANT,	ERROR },
	{ "fa_acute",	CONSTANT,	FA_ACUTE },
	{ "fa_apostrophe", CONSTANT,	FA_APOSTROPHE },
	{ "fa_breve",	CONSTANT,	FA_BREVE },
	{ "fa_caron",	CONSTANT,	FA_CARON },
	{ "fa_cedilla",	CONSTANT,	FA_CEDILLA },
	{ "fa_cflex",	CONSTANT,	FA_CFLEX },
	{ "fa_dacute",	CONSTANT,	FA_DACUTE },
	{ "fa_dot",	CONSTANT,	FA_DOT },
	{ "fa_grave",	CONSTANT,	FA_GRAVE },
	{ "fa_macron",	CONSTANT,	FA_MACRON },
	{ "fa_ogonek",	CONSTANT,	FA_OGONEK },
	{ "fa_ring",	CONSTANT,	FA_RING },
	{ "fa_slash",	CONSTANT,	FA_SLASH },
	{ "fa_tilde",	CONSTANT,	FA_TILDE },
	{ "fa_umlaut",	CONSTANT,	FA_UMLAUT },
	{ "hole",	CONSTANT,	HOLE },
	{ "homearrow",	CONSTANT,	HOMEARROW },
	{ "idle",	CONSTANT,	IDLE },
	{ "key",	KEY,		0 },
	{ "leftarrow",	CONSTANT,	LEFTARROW },
	{ "leftctrl",	CONSTANT,	LEFTCTRL },
	{ "leftshift",	CONSTANT,	LEFTSHIFT },
	{ "lf",		FKEY,		LEFTFUNC },
	{ "metabit",	CONSTANT,	METABIT },
	{ "nonl",	CONSTANT,	NONL },
	{ "nop",	CONSTANT,	NOP },
	{ "numl",	TABLENAME,	NUMLOCKMASK },
	{ "numlock",	CONSTANT,	NUMLOCK },
	{ "oops",	CONSTANT,	OOPS },
	{ "pad0",	CONSTANT,	PAD0 },
	{ "pad1",	CONSTANT,	PAD1 },
	{ "pad2",	CONSTANT,	PAD2 },
	{ "pad3",	CONSTANT,	PAD3 },
	{ "pad4",	CONSTANT,	PAD4 },
	{ "pad5",	CONSTANT,	PAD5 },
	{ "pad6",	CONSTANT,	PAD6 },
	{ "pad7",	CONSTANT,	PAD7 },
	{ "pad8",	CONSTANT,	PAD8 },
	{ "pad9",	CONSTANT,	PAD9 },
	{ "paddot",	CONSTANT,	PADDOT },
	{ "padenter",	CONSTANT,	PADENTER },
	{ "padequal",	CONSTANT,	PADEQUAL },
	{ "padminus",	CONSTANT,	PADMINUS },
	{ "padplus",	CONSTANT,	PADPLUS },
	{ "padsep",	CONSTANT,	PADSEP },
	{ "padslash",	CONSTANT,	PADSLASH },
	{ "padstar",	CONSTANT,	PADSTAR },
	{ "reset",	CONSTANT,	RESET },
	{ "rf",		FKEY,		RIGHTFUNC },
	{ "rightarrow",	CONSTANT,	RIGHTARROW },
	{ "rightctrl",	CONSTANT,	RIGHTCTRL },
	{ "rightshift",	CONSTANT,	RIGHTSHIFT },
	{ "same",	SAME,		0 },
	{ "shift",	TABLENAME,	SHIFTMASK },
	{ "shiftkeys",	CONSTANT,	SHIFTKEYS },
	{ "shiftlock",	CONSTANT,	SHIFTLOCK },
	{ "string",	CONSTANT,	STRING },
	{ "swap",	SWAP,		0 },
	{ "systembit",	CONSTANT,	SYSTEMBIT },
	{ "tf",		FKEY,		TOPFUNC },
	{ "up",		TABLENAME,	UPMASK },
	{ "uparrow",	CONSTANT,	UPARROW },
	{ "with",	WITH,		0 },
};

#define	NWORDS		(sizeof (wordtab) / sizeof (wordtab[0]))

static int
yylex()
{
	register int c;
	char tokbuf[256+1];
	register char *cp;
	register int tokentype;

	while ((c = getc(infile)) == ' ' || c == '\t')
		;
	if (begline) {
		lineno++;
		begline = 0;
		if (c == '#') {
			while ((c = getc(infile)) != EOF && c != '\n')
				;
		}
	}
	if (c == EOF)
		return (0);	/* end marker */
	if (c == '\n') {
		begline = 1;
		return (c);
	}

	switch (c) {

	case '\'':
		tokentype = CHAR;
		if ((c = getc(infile)) == EOF)
			yyerror("unterminated character constant");
		if (c == '\n') {
			(void) ungetc(c, infile);
			yylval.number = '\'';
		} else {
			switch (c) {

			case '\'':
				yyerror("null character constant");
				break;

			case '\\':
				yylval.number = readesc(infile, '\'', 1);
				break;

			default:
				yylval.number = c;
				break;
			}
			if ((c = getc(infile)) == EOF || c == '\n')
				yyerror("unterminated character constant");
			else if (c != '\'')
				yyerror("only one character allowed in character constant");
		}
		break;

	case '"':
		if ((c = getc(infile)) == EOF)
			yyerror("unterminated string constant");
		if (c == '\n') {
			(void) ungetc(c, infile);
			tokentype = CHAR;
			yylval.number = '"';
		} else {
			tokentype = CHARSTRING;
			cp = &tokbuf[0];
			do {
				if (cp > &tokbuf[256])
					yyerror("line too long");
				if (c == '\\')
					c = readesc(infile, '"', 0);
				*cp++ = (char)c;
			} while ((c = getc(infile)) != EOF && c != '\n' &&
				c != '"');
			if (c != '"')
				yyerror("unterminated string constant");
			*cp = '\0';
			if (nstrings == 16)
				yyerror("too many strings");
			if ((int) strlen(tokbuf) > KTAB_STRLEN)
				yyerror("string too long");
			strings[nstrings] = strdup(tokbuf);
			yylval.number = STRING+nstrings;
			nstrings++;
		}
		break;

	case '(':
	case ')':
	case '+':
		tokentype = c;
		break;

	case '^':
		if ((c = getc(infile)) == EOF)
			yyerror("missing newline at end of line");
		tokentype = CHAR;
		if (c == ' ' || c == '\t' || c == '\n') {
			/*
			 * '^' by itself.
			 */
			yylval.number = '^';
		} else {
			yylval.number = c & 037;
			if ((c = getc(infile)) == EOF)
				yyerror("missing newline at end of line");
			if (c != ' ' && c != '\t' && c != '\n')
				yyerror("invalid control character");
		}
		(void) ungetc(c, infile);
		break;

	default:
		cp = &tokbuf[0];
		do {
			if (cp > &tokbuf[256])
				yyerror("line too long");
			*cp++ = (char)c;
		} while ((c = getc(infile)) != EOF && (isalnum(c) || c == '_'));
		if (c == EOF)
			yyerror("newline missing");
		(void) ungetc(c, infile);
		*cp = '\0';
		if (strlen(tokbuf) == 1) {
			tokentype = CHAR;
			yylval.number = (unsigned char)tokbuf[0];
		} else if (strlen(tokbuf) == 2 && tokbuf[0] == '^') {
			tokentype = CHAR;
			yylval.number = (unsigned char)(tokbuf[1] & 037);
		} else {
			word_t word;
			register word_t *wptr;
			char *ptr;

			for (cp = &tokbuf[0]; (c = *cp) != '\0'; cp++) {
				if (isupper(c))
					*cp = tolower(c);
			}
			word.w_string = tokbuf;
			wptr = (word_t *)bsearch((char *)&word,
			    (char *)wordtab, NWORDS, sizeof (word_t),
			    wordcmp);
			if (wptr != NULL) {
				yylval.number = wptr->w_lval;
				tokentype = wptr->w_type;
			} else {
				yylval.number = strtol(tokbuf, &ptr, 0);
				if (ptr == tokbuf)
					yyerror("syntax error");
				else
					tokentype = INT;
			}
			break;
		}
	}

	return (tokentype);
}

static int
readesc(stream, delim, single_char)
	FILE *stream;
	int delim;
	int single_char;
{
	register int c;
	register int val;
	register int i;

	if ((c = getc(stream)) == EOF || c == '\n')
		yyerror("unterminated character constant");

	if (c >= '0' && c <= '7') {
		val = 0;
		i = 1;
		for (;;) {
			val = val*8 + c - '0';
			if ((c = getc(stream)) == EOF || c == '\n')
				yyerror("unterminated character constant");
			if (c == delim)
				break;
			i++;
			if (i > 3) {
				if (single_char)
					yyerror("escape sequence too long");
				else
					break;
			}
			if (c < '0' || c > '7') {
				if (single_char)
					yyerror("illegal character in escape sequence");
				else
					break;
			}
		}
		(void) ungetc(c, stream);
	} else {
		switch (c) {

		case 'n':
			val = '\n';
			break;

		case 't':
			val = '\t';
			break;

		case 'b':
			val = '\b';
			break;

		case 'r':
			val = '\r';
			break;

		case 'v':
			val = '\v';
			break;

		case '\\':
			val = '\\';
			break;

		default:
			if (c == delim)
				val = delim;
			else
				yyerror("illegal character in escape sequence");
		}
	}
	return (val);
}

static int
wordcmp(const void *w1, const void *w2)
{
	return (strcmp(
		((const word_t *)w1)->w_string,
		((const word_t *)w2)->w_string));
}

static int
yyerror(msg)
	char *msg;
{
	(void) fprintf(stderr, "%s, line %d: %s\n", infilename, lineno, msg);
	exit(1);
}
