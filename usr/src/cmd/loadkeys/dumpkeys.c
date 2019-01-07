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
 * Copyright (c) 1988 by Sun Microsystems, Inc.
 */

#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/kbd.h>
#include <sys/kbio.h>
#include <errno.h>

typedef enum {
	SM_INVALID,	/* this shift mask is invalid for this keyboard */
	SM_NORMAL,	/* "normal", valid shift mask */
	SM_NUMLOCK,	/* "Num Lock" shift mask */
	SM_UP		/* "Up" shift mask */
} smtype_t;

typedef struct {
	char	*sm_name;
	int	sm_mask;
	smtype_t sm_type;
} smentry_t;


smentry_t shiftmasks[] = {
	{ "base",	0,		SM_NORMAL },
	{ "shift",	SHIFTMASK,	SM_NORMAL },
	{ "caps",	CAPSMASK,	SM_NORMAL },
	{ "ctrl",	CTRLMASK,	SM_NORMAL },
	{ "altg",	ALTGRAPHMASK,	SM_NORMAL },
	{ "numl",	NUMLOCKMASK,	SM_NUMLOCK },
	{ "up",		UPMASK,		SM_UP },
};

#define	NSHIFTS	(sizeof (shiftmasks) / sizeof (shiftmasks[0]))

static void	printentry(struct kiockeymap *kio);
static void	printchar(int character, int delim);

/*ARGSUSED*/
int
main(int argc, char **argv)
{
	register int kbdfd;
	register int keystation;
	register int shift;
	int ktype;
	struct kiockeymap keyentry[NSHIFTS];
	register int allsame;

	if ((kbdfd = open("/dev/kbd", O_WRONLY)) < 0) {
		perror("dumpkeys: /dev/kbd");
		return (1);
	}
	if (ioctl(kbdfd, KIOCTYPE, &ktype) < 0) {
		perror("dumpkeys: ioctl(KIOCTYPE)");
		return (1);
	}
	/* if no keyboard detected, or ascii terminal, exit silently */
	if (ktype == KB_ASCII || ktype < 0)
		exit(0);

	/*
	 * See which shift masks are valid for this keyboard.
	 * We do that by trying to get the entry for keystation 0 and that
	 * shift mask; if the "ioctl" fails, we assume it's because the shift
	 * mask is invalid.
	 */
	for (shift = 0; shift < NSHIFTS; shift++) {
		keyentry[shift].kio_tablemask =
		    shiftmasks[shift].sm_mask;
		keyentry[shift].kio_station = 0;
		if (ioctl(kbdfd, KIOCGKEY, &keyentry[shift]) < 0)
			shiftmasks[shift].sm_type = SM_INVALID;
	}

	/*
	 * Loop until we get an EINVAL, so we don't have to know
	 * how big the table might be.
	 */
	for (keystation = 0; ; keystation++) {
		for (shift = 0; shift < NSHIFTS; shift++) {
			if (shiftmasks[shift].sm_type != SM_INVALID) {
				keyentry[shift].kio_tablemask =
				    shiftmasks[shift].sm_mask;
				keyentry[shift].kio_station = keystation;
				if (ioctl(kbdfd, KIOCGKEY,
				    &keyentry[shift]) < 0) {
					if (errno == EINVAL)
						return (0);
					perror("dumpkeys: KIOCGKEY");
					return (1);
				}
			}
		}

		(void) printf("key %d\t", keystation);

		/*
		 * See if all the "normal" entries (all but the Num Lock and Up
		 * entries) are the same.
		 */
		allsame = 1;
		for (shift = 1; shift < NSHIFTS; shift++) {
			if (shiftmasks[shift].sm_type == SM_NORMAL) {
				if (keyentry[0].kio_entry
				    != keyentry[shift].kio_entry) {
					allsame = 0;
					break;
				}
			}
		}

		if (allsame) {
			/*
			 * All of the "normal" entries are the same; just print
			 * "all".
			 */
			(void) printf(" all ");
			printentry(&keyentry[0]);
		} else {
			/*
			 * The normal entries aren't all the same; print them
			 * individually.
			 */
			for (shift = 0; shift < NSHIFTS; shift++) {
				if (shiftmasks[shift].sm_type == SM_NORMAL) {
					(void) printf(" %s ",
					    shiftmasks[shift].sm_name);
					printentry(&keyentry[shift]);
				}
			}
		}
		if (allsame && keyentry[0].kio_entry == HOLE) {
			/*
			 * This key is a "hole"; if either the Num Lock or Up
			 * entry isn't a "hole", print it.
			 */
			for (shift = 0; shift < NSHIFTS; shift++) {
				switch (shiftmasks[shift].sm_type) {

				case SM_NUMLOCK:
				case SM_UP:
					if (keyentry[shift].kio_entry
					    != HOLE) {
						(void) printf(" %s ",
						    shiftmasks[shift].sm_name);
						printentry(&keyentry[shift]);
					}
					break;
				}
			}
		} else {
			/*
			 * This entry isn't a "hole"; if the Num Lock entry
			 * isn't NONL (i.e, if Num Lock actually does
			 * something) print it, and if the Up entry isn't NOP
			 * (i.e., if up transitions on this key actually do
			 * something) print it.
			 */
			for (shift = 0; shift < NSHIFTS; shift++) {
				switch (shiftmasks[shift].sm_type) {

				case SM_NUMLOCK:
					if (keyentry[shift].kio_entry
					    != NONL) {
						(void) printf(" %s ",
						    shiftmasks[shift].sm_name);
						printentry(&keyentry[shift]);
					}
					break;

				case SM_UP:
					if (keyentry[shift].kio_entry
					    != NOP) {
						(void) printf(" %s ",
						    shiftmasks[shift].sm_name);
						printentry(&keyentry[shift]);
					}
					break;
				}
			}
		}
		(void) printf("\n");
	}
}

static char *shiftkeys[] = {
	"capslock",
	"shiftlock",
	"leftshift",
	"rightshift",
	"leftctrl",
	"rightctrl",
	"meta",			/* not used */
	"top",			/* not used */
	"cmd",			/* reserved */
	"altgraph",
	"alt",
	"numlock",
};

#define	NSHIFTKEYS	(sizeof (shiftkeys) / sizeof (shiftkeys[0]))

static char *buckybits[] = {
	"metabit",
	"systembit",
};

#define	NBUCKYBITS	(sizeof (buckybits) / sizeof (buckybits[0]))

static char *funnies[] = {
	"nop",
	"oops",
	"hole",
	"",			/* not used */
	"",			/* not used */
	"",			/* not used */
	"reset",
	"error",
	"idle",
	"compose",
	"nonl",
};

#define	NFUNNIES	(sizeof (funnies) / sizeof (funnies[0]))

static char *fa_class[] = {
	"fa_umlaut",
	"fa_cflex",
	"fa_tilde",
	"fa_cedilla",
	"fa_acute",
	"fa_grave",
	"fa_macron",
	"fa_breve",
	"fa_dot",
	"fa_slash",
	"fa_ring",
	"fa_apostrophe",
	"fa_dacute",
	"fa_ogonek",
	"fa_caron"
};

#define	NFA_CLASS	(sizeof (fa_class) / sizeof (fa_class[0]))

typedef struct {
	char	*string;
	char	*name;
} builtin_string_t;

builtin_string_t builtin_strings[] = {
	{ "\033[H",	"homearrow" },
	{ "\033[A",	"uparrow" },
	{ "\033[B",	"downarrow" },
	{ "\033[D",	"leftarrow" },
	{ "\033[C",	"rightarrow" },
};

#define	NBUILTIN_STRINGS	(sizeof (builtin_strings) / \
					sizeof (builtin_strings[0]))

static char	*fkeysets[] = {
	"lf",
	"rf",
	"tf",
	"bf",
};

#define	NFKEYSETS	(sizeof (fkeysets) / sizeof (fkeysets[0]))

static char	*padkeys[] = {
	"padequal",
	"padslash",
	"padstar",
	"padminus",
	"padsep",
	"pad7",
	"pad8",
	"pad9",
	"padplus",
	"pad4",
	"pad5",
	"pad6",
	"pad1",
	"pad2",
	"pad3",
	"pad0",
	"paddot",
	"padenter",
};

#define	NPADKEYS	(sizeof (padkeys) / sizeof (padkeys[0]))

static void
printentry(struct kiockeymap *kio)
{
	int entry = (kio->kio_entry & 0x1F);
	int fkeyset;
	int i;
	int c;

	switch (KEYFLAGS(kio->kio_entry)) {

	case 0x0:
		if (kio->kio_entry == '"')
			(void) printf("'\"'");	/* special case */
		else if (kio->kio_entry == ' ')
			(void) printf("' '");	/* special case */
		else
			printchar((int)kio->kio_entry, '\'');
		break;

	case SHIFTKEYS:
		if (entry < NSHIFTKEYS)
			(void) printf("shiftkeys+%s", shiftkeys[entry]);
		else
			(void) printf("%#4x", kio->kio_entry);
		break;

	case BUCKYBITS:
		if (entry < NBUCKYBITS)
			(void) printf("buckybits+%s", buckybits[entry]);
		else
			(void) printf("%#4x", kio->kio_entry);
		break;

	case FUNNY:
		if (entry < NFUNNIES)
			(void) printf("%s", funnies[entry]);
		else
			(void) printf("%#4x", kio->kio_entry);
		break;

	case FA_CLASS:
		if (entry < NFA_CLASS)
			(void) printf("%s", fa_class[entry]);
		else
			(void) printf("%#4x", kio->kio_entry);
		break;

	case STRING:
		if (entry < NBUILTIN_STRINGS && strncmp(kio->kio_string,
		    builtin_strings[entry].string, KTAB_STRLEN) == 0)
			(void) printf("string+%s", builtin_strings[entry].name);
		else {
			(void) printf("\"");
			for (i = 0;
			    i < KTAB_STRLEN && (c = kio->kio_string[i]) != '\0';
			    i++)
				printchar(c, '"');
			(void) printf("\"");
		}
		break;

	case FUNCKEYS:
		fkeyset = (int)(kio->kio_entry & 0xF0) >> 4;
		if (fkeyset < NFKEYSETS)
			(void) printf("%s(%d)", fkeysets[fkeyset],
			    (entry & 0x0F) + 1);
		else
			(void) printf("%#4x", kio->kio_entry);
		break;

	case PADKEYS:
		if (entry < NPADKEYS)
			(void) printf("%s", padkeys[entry]);
		else
			(void) printf("%#4x", kio->kio_entry);
		break;

	default:
		(void) printf("%#4x", kio->kio_entry);
		break;
	}
}

static void
printchar(int character, int delim)
{
	switch (character) {

	case '\n':
		(void) printf("'\\n'");
		break;

	case '\t':
		(void) printf("'\\t'");
		break;

	case '\b':
		(void) printf("'\\b'");
		break;

	case '\r':
		(void) printf("'\\r'");
		break;

	case '\v':
		(void) printf("'\\v'");
		break;

	case '\\':
		(void) printf("'\\\\'");
		break;

	default:
		if (isprint(character)) {
			if (character == delim)
				(void) printf("'\\'");
			(void) printf("%c", character);
		} else {
			if (character < 040)
				(void) printf("^%c", character + 0100);
			else if (character <= 0xff)
				(void) printf("'\\%.3o'", character);
			else
				(void) printf("%#4x", character);
		}
		break;
	}
}
