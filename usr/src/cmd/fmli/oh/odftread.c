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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *      All Rights Reserved
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.15 */

#include <stdio.h>
#include <ctype.h>
#include <malloc.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "wish.h"
#include "typetab.h"
#include "optabdefs.h"
#include "detabdefs.h"
#include "retcds.h"
#include "mio.h"
#include "terror.h"
#include "sizes.h"

/* This function reads the External Object Detection Function Table,
 * or "oddfoot" as it is known in conversation.
 * If the oddfoot exists, then it replaces the internal oddfoot.
 *
 * The structure of the external oddfoot is:
 *
 * [LINUM] OBJTYPE DEFAULT-ODI DEFAULT-MASK FUNCTION-TYPE [ARGUMENTS]
 * where:
 * LINUM is an optional decimal line number that is ignored.
 * OBJTYPE is the internal OTS name of the object.
 * DEFAULT-ODI is a string of default Object Dependent Information
 * DEFAULT-MASK is a hex number to be or'ed in with the object's mask.
 * FUNCTION-TYPE is an integer, one of:
 *	 	F_INT (4)	 Detect by internal detection function.
 *		F_SHELL (5)	 Detect by forking a process with a shell
 *		F_EXEC	(6)	 Detect by forking a process
 *		F_PARTS (7)	 Detect by part names
 *		F_DPARTS (8) Detect by the existance of parts
 *      F_MAGIC (9)  Detect by magic numbers 
 * ARGUMENTS are possible arguments to the function being called:
 *		F_INT	argument is a hex number,telling which internal function should
 *				be used.
 *		F_SHELL and F_EXEC, argument is a string, indicating a path.
 *		F_PARTS and F_DPARTS do not need arguments
 *		F_MAGIC a list of pairs of numbers.  The first number of each pair
 *				is an offset, the second is a byte value.  Numbers may be in
 *				hex, octal, or decimal according to the normal conventions
 *				(0xnumber, 0number, or number).
 *				For example: 0x01 033 0x02 041.  There is a limit of MAXMAGIC
 *				magic pairs.
 */


char	*expand();

static bool	Already_read = FALSE;	/* only do it once */

static long	Normal_mag_offset[] = {0L, 1L, -1L};

/* magic number info 0 0177 1 0105 2 0114 3 0106*/
static long	O1[] = {0L, 2047L, -1L};
static long	O2[] = {0L, 1L, -1L};
static long	O3[] = {0L, 1L, -1L};
static long	O4[] = {0L, 1L, -1L};
static long	O5[] = {0L, 1L, -1L};
static long	O6[] = {0L, 1L, -1L};
static long	O8[] = {0L, 1L, 2L, 3L, 17L, -1L};
static long	O9[] = {0L, 1L, 2L, 3L, 16L, -1L};

static char	B1[] = {5, 2 }; 
static char	B2[] = {1, 0150 }; 
static char	B3[] = {1, 0151 }; 
static char	B4[] = {1, 0160 }; 
static char	B5[] = {1, 0161 }; /* >> CHANGED FROM 1,1061 abs7/6/88 << */
static char	B6[] = {1, 015 };
static char	B7[] = {0114, 01 };
static char	B8[] = {0177, 0105, 0114, 0106, 02 };

extern struct odft_entry Detab[MAXODFT];

struct odft_entry FMLI_detab[MAXODFT] = {
	{ "MDIRECTORY",	"",		0,	8, 	0, NULL, NULL,	NULL },
	{ "DIRECTORY",	"",		0,	8,  	0, NULL, NULL,	NULL },
	{ "MENU",	"",		0,	7,	0, NULL, NULL,	NULL },
	{ "FORM",	"",		0,	7, 	0, NULL, NULL,	NULL },
	{ "TEXT",	"",		0,	7, 	0, NULL, NULL,	NULL },
	{ "STRUCT_1.0",	"",		0,	7, 	0, NULL, NULL,	NULL },
	{ "UCALC_1.0",	"",		0,	7, 	0, NULL, NULL,	NULL },
/*  dmd 6/13/89
	{ "MAIL_OUT",	"",		0,	4,	10,NULL, NULL,	NULL },
	{ "MAIL_IN",	"",		0,	4,	9, NULL, NULL, 	NULL },
*/
	{ "ASCII",	"",		0,	4,	0, NULL, NULL, 	NULL },
	{ "XED_5.208",	"",		0,	9,	0, NULL, O1,	B1 },
	{ "EXECUTABLE",	"TYPE=3B2/ELF",	0,	9,	0, NULL, O8,	B8  },
	{ "EXECUTABLE",	"TYPE=386/ELF",	0,	9,	0, NULL, O9,	B8  },
	{ "EXECUTABLE",	"TYPE=3B20",	0,	9,	0, NULL, O2,	B2  },
	{ "EXECUTABLE",	"TYPE=3B20",	0,	9,	0, NULL, O3,	B3  },
	{ "EXECUTABLE",	"TYPE=3B5/3B2",	0,	9,	0, NULL, O4,	B4  },
	{ "EXECUTABLE",	"TYPE=3B5/3B2",	0,	9,	0, NULL, O5,	B5  },
	{ "EXECUTABLE",	"TYPE=Z80",	0,	9,	0, NULL, O6,	B6  },
#ifdef i386
	{ "EXECUTABLE", "TYPE=386",	0,	9,	0, NULL, O2,	B7 },
#endif
	{ "TRANSFER",	"",		0,	4,	3, NULL, NULL, 	NULL },
	{ "ASCII",	"",	 	0,	4,	1, NULL, NULL, 	NULL },
	{ "UNKNOWN",	"TYPE=COREDUMP",4000,	4,	4, NULL, NULL, 	NULL },
	{ "UNKNOWN",	"TYPE=ARCHIVE",	0,	4,	5, NULL, NULL, 	NULL },
	{ "ASCII",	"",		200,	4,	6, NULL, NULL, 	NULL },
	{ "XED_5.208",	"",	 	200,	4,	7, NULL, NULL, 	NULL },
	{ "UNKNOWN",	"",		0,	4,	8, NULL, NULL, 	NULL },
	{ "",		"",		0,	0,	0, NULL, NULL, 	NULL }
};

extern int Vflag;

int
odftread()
{
    if (Already_read)
	return(0);
    Already_read = TRUE;
    if (!Vflag) {
	/*
	 * table is hard-coded for "FACE" FMLI 
	 */
	register int i;

	for (i = 0; i < MAXODFT && FMLI_detab[i].objtype[0] != '\0';i++)
	    Detab[i] = FMLI_detab[i];
	Detab[i].objtype[0] = '\0';
    }
    else {
	register int i, moffset;
	char *p, *q, buf[PATHSIZ];
	char *b;
	char	*tmpstr;
	FILE *fp;
	int offset = 0, magic;
	long magic_offset[MAXMAGIC+1];
	char magic_bytes[MAXMAGIC];
	char	*get_skip();
	char	*tab_parse();
	long	tab_long();

	p = expand("$OASYS/info/OH/externals/detect.tab");
	fp = fopen(p, "r");
	free(p);
	if (fp == NULL)
	    fatal(MISSING, "detect.tab");
	tmpstr = NULL;
	while (get_skip(buf, PATHSIZ, fp) != NULL) {
	    /* flush optional line number */
	    for (b = buf; *b == '\t' || isdigit(*b); b++)
		;
	    b = tab_parse(&tmpstr, b);
	    strncpy(Detab[offset].objtype, tmpstr, OTYPESIZ);
	    if (b) {
		char	*unbackslash();

		b = tab_parse(&Detab[offset].defodi, b);
		p = unbackslash(Detab[offset].defodi);
		if (p[0] == '"')
		    memshift(p, p + 1, strlen(p));
		p += strlen(p) - 1;
		if (p[0] == '"')
		    p[0] = '\0';
	    }
	    Detab[offset].defmask = tab_long(&b, 16);
	    if (b && *b)
		Detab[offset].func_type = tab_long(&b, 16);
	    else {
#ifdef _DEBUG
		_debug(stderr, "BAD ODFT '%s'\n", Detab[offset].objtype);
#endif
		error(MUNGED, "heuristics table");
		continue;
	    }
	    switch (Detab[offset].func_type) {
	    case F_INT:
		Detab[offset].intern_func = tab_long(&b, 0);
		break;
	    case F_SHELL:
	    case F_EXEC:
		b = tab_parse(&tmpstr, b);
		Detab[offset].extern_func = tmpstr;
		tmpstr = NULL;
		break;
	    case F_PARTS:
	    case F_DPARTS:
		break;
	    case F_MAGIC:
		p = b;
		magic = 0;
		while (*p && magic < MAXMAGIC) {
		    moffset = strtol(p, &q, 0);
		    if (p == q)	/* strtol failed */
			break;
		    p = q;
		    while (*q && isspace(*q))
			q++;
		    if (*q == '"') {
			q++;
			while (*q && *q != '"' && magic < MAXMAGIC-1) {
			    magic_bytes[magic] = *q;
			    magic_offset[magic] = moffset++;
			    magic++;
			    q++;
			}
			if (*q)
			    q++;
		    } else {
			magic_offset[magic] = moffset;
			magic_bytes[magic] = (char) strtol(p,&q,0);
			if (p == q) {
			    p = '\0';
			    break;
			} else
			    p = q;
			magic++;
		    }
		}
		if (magic == 0) {
#ifdef _DEBUG
		    _debug(stderr, "BAD ODFT '%s' MAGIC: %s\n", Detab[offset].objtype, q);
#endif
		    error(MUNGED, "heuristics magic number");
		    continue;
		}
		magic_offset[magic] = -1L;

		/* for efficiency, the most common magic number
		 * case, 0, 1, -1, is coded up.
		 */

		if (magic == 2 && magic_offset[0] == 0L &&
		    magic_offset[1] == 1L) {
		    Detab[offset].magic_offset = &(Normal_mag_offset[0]);
		}
		else {
		    Detab[offset].magic_offset = (long *)calloc(magic+1, sizeof(long));
		    for (i = 0; i < magic+1; i++)
			Detab[offset].magic_offset[i] = magic_offset[i];
		}
		Detab[offset].magic_bytes = calloc(magic, sizeof(char));
		for (i = 0; i < magic; i++)
		    Detab[offset].magic_bytes[i] = magic_bytes[i];
		break;
	    default:
#ifdef _DEBUG
		_debug(stderr, "ODFT '%s' BAD FUNCTION: %d\n", Detab[offset].objtype, Detab[offset].func_type);
#endif
		error(MUNGED, "heuristics table function");
		continue;
	    }
	    offset++;
	}
	fclose(fp);
	Detab[offset].objtype[0] = '\0';
	if (tmpstr)
	    free(tmpstr);
    }
    return(0);
}
