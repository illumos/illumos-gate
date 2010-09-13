/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	All Rights Reserved
 */

/*
 *	Copyright (c) 1987, 1988 Microsoft Corporation
 *	All Rights Reserved
 */

/*
 *	Copyright (c) 1979 Regents of the University of California
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include "a.out.h"
#include <ctype.h>
#include <wchar.h>
#include <wctype.h>
#include <libelf.h>
#include <sys/elf.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <widec.h>
#include <gelf.h>
#include <errno.h>


#define	NOTOUT		0
#define	AOUT		1
#define	ELF		4

struct aexec ahdr;

/* used to maintain a list of program sections to look in */
typedef struct sec_name {
	char	*name;
	struct	sec_name *next;
} sec_name_t;

/*
 * function prototypes
 */
static void	Usage();
static void	find(long);
static int	ismagic(int, struct aexec *, FILE *);
static int	tryelf(FILE *);
static int	dirt(int, int);


/*
 * Strings - extract strings from an object file for whatever
 *
 * The algorithm is to look for sequences of "non-junk" characters
 * The variable "minlen" is the minimum length string printed.
 * This helps get rid of garbage.
 * Default minimum string length is 4 characters.
 *
 */

#define	DEF_MIN_STRING	4

static	int	tflg;
static	char	t_format;
static	int	aflg;
static	int	minlength = 0;
static	int	isClocale = 0;
static	char    *buf = NULL;
static	char	*tbuf = NULL;
static	size_t	buf_size = 0;
static	int	rc = 0; /* exit code */

/*
 * Returns 0 when sections have been successfully looked through,
 * otherwise returns 1.
 */
static int
look_in_sections(char *file, sec_name_t *seclistptr)
{
	int		fd = fileno(stdin);
	int		found_sec;
	int		rc = 0;
	Elf		*elf;
	GElf_Ehdr	ehdr;
	Elf_Scn		*scn;
	GElf_Shdr	shdr;

	(void) lseek(fd, 0L, 0);
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (gelf_getehdr(elf, &ehdr) == (GElf_Ehdr *)NULL) {
		(void) fprintf(stderr, "%s: %s\n", file, elf_errmsg(-1));
		(void) elf_end(elf);
		return (1);
	}
	scn = 0;
	while ((scn = elf_nextscn(elf, scn)) != 0) {
		found_sec = 0;
		if (gelf_getshdr(scn, &shdr) == (GElf_Shdr *)0) {
			(void) fprintf(stderr, "%s: %s\n", file,
			    elf_errmsg(-1));
			rc = 1;
			continue;
		}

		if (seclistptr != NULL) {
			char	*scn_name;

			/* Only look in the specified section(s). */
			if ((scn_name = elf_strptr(elf, ehdr.e_shstrndx,
			    (size_t)shdr.sh_name)) == (char *)NULL) {
				(void) fprintf(stderr, "%s: %s\n", file,
				    elf_errmsg(-1));
				rc = 1;
				continue;
			} else {
				sec_name_t	*sptr;

				for (sptr = seclistptr; sptr != NULL;
				    sptr = sptr->next) {
					if (strcmp(scn_name, sptr->name) == 0) {
						found_sec = 1;
						break;
					}
				}
			}
		} else {
			/*
			 * Look through program sections that are
			 * loaded in memory.
			 */
			if ((shdr.sh_flags & SHF_ALLOC) &&
			    (shdr.sh_type == SHT_PROGBITS)) {
				found_sec = 1;
			}
		}
		if (found_sec == 1) {
			(void) fseek(stdin, (long)shdr.sh_offset, 0);
			find((long)shdr.sh_size);
		}
	}
	return (rc);
}

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int		hsize;
	int		htype;
	char		*locale;
	int		opt;
	int		i;
	sec_name_t	*seclistptr = NULL;
	sec_name_t	*seclistendptr;
	sec_name_t	*sptr;

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	locale = setlocale(LC_CTYPE, NULL);
	if ((strcmp(locale, "C") == 0) ||
		(strcmp(locale, "POSIX") == 0)) {
		isClocale = 1;
	}

	/* check for non-standard "-" option */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-") == 0) {
			aflg++;
			while (i < argc) {
				argv[i] = argv[i+1];
				i++;
			}
			argc--;
		}
	}

	/* get options */
	while ((opt = getopt(argc, argv, "1234567890an:N:ot:")) != -1) {
		switch (opt) {
			case 'a':
				aflg++;
				break;

			case 'n':
				minlength = (int)strtol(optarg, (char **)NULL,
				    10);
				break;

			case 'N':
				if (((sptr = malloc(sizeof (sec_name_t)))
				    == NULL) || ((sptr->name = strdup(optarg))
				    == NULL)) {
					(void) fprintf(stderr, gettext(
					    "Cannot allocate memory: "
					    "%s\n"), strerror(errno));
					exit(1);
				}
				if (seclistptr == NULL) {
					seclistptr = sptr;
					seclistptr->next = NULL;
					seclistendptr = sptr;
				} else {
					seclistendptr->next = sptr;
					seclistendptr = sptr;
				}
				break;

			case 'o':
				tflg++;
				t_format = 'd';
				break;

			case 't':
				tflg++;
				t_format = *optarg;
				if (t_format != 'd' && t_format != 'o' &&
				    t_format != 'x')
				{
					(void) fprintf(stderr,
					gettext("Invalid format\n"));
					Usage();
				}
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
			case '9':
				minlength *= 10;
				minlength += opt - '0';
				break;

			default:
				Usage();
		}
	}

	/* if min string not specified, use default */
	if (!minlength)
		minlength = DEF_MIN_STRING;


	/* dynamic allocation of char buffer array */
	buf = (char *)malloc(BUFSIZ);
	if (buf == NULL) {
		(void) fprintf(stderr, gettext("Cannot allocate memory: %s\n"),
		    strerror(errno));
		exit(1);
	}
	buf_size = BUFSIZ;
	tbuf = buf;


	/* for each file operand */
	do {
		if (argv[optind] != NULL) {
			if (freopen(argv[optind], "r", stdin) == NULL) {
				perror(argv[optind]);
				rc = 1;
				optind++;
				continue;
			}
			optind++;
		} else
			aflg++;

		if (aflg)
			htype =  NOTOUT;
		else {
			hsize = fread((char *)&ahdr, sizeof (char),
					sizeof (ahdr), stdin);
			htype = ismagic(hsize, &ahdr, stdin);
		}
		switch (htype) {
			case AOUT:
				(void) fseek(stdin, (long)ADATAPOS(&ahdr), 0);
				find((long)ahdr.xa_data);
				continue;

			case ELF:
				/*
				 * Will take care of COFF M32 and i386 also
				 * As well as ELF M32, i386 and Sparc (32-
				 * and 64-bit)
				 */
				rc = look_in_sections(argv[optind - 1],
				    seclistptr);
				continue;

			case NOTOUT:
			default:
				if (!aflg)
					(void) fseek(stdin, (long)0, 0);
				find(LONG_MAX);
				continue;
		}
	} while (argv[optind] != NULL);

	return (rc);
}

static void
find(cnt)
	long cnt;
{
	int	c;
	int	cc;
	int	cr;

	cc = 0;
	for (c = ~EOF; (cnt > 0) && (c != EOF); cnt--) {
		c = getc(stdin);
		if (!(cr = dirt(c, cc))) {
			if (cc >= minlength) {
				if (tflg) {
					switch (t_format) {
					case 'd':
						(void) printf("%7ld ",
						    ftell(stdin) - cc - 1);
						break;

					case 'o':
						(void) printf("%7lo ",
						    ftell(stdin) - cc - 1);
						break;

					case 'x':
						(void) printf("%7lx ",
						    ftell(stdin) - cc - 1);
						break;
					}
				}

				if (cc >= buf_size)
					buf[buf_size-1] = '\0';
				else
					buf[cc] = '\0';
				(void) puts(buf);
			}
			cc = 0;
		}
		cc += cr;
	}
}

static int
dirt(c, cc)
int	c;
int	cc;
{
	char	mbuf[MB_LEN_MAX + 1];
	int	len, len1, i;
	wchar_t	wc;
	int	r_val;

	if (isascii(c)) {
	    if (isprint(c)) {
		/*
		 * If character count is greater than dynamic
		 * char buffer size, then increase char buffer size.
		 */
		if (cc >= (buf_size-2)) {
		    if (tbuf != NULL) {
			buf_size += BUFSIZ;
			tbuf = (char *)realloc(buf, buf_size);
			if (tbuf == NULL) {
			    (void) fprintf(stderr,
				gettext("Cannot allocate memory: %s\n"),
				strerror(errno));
			    buf_size -= BUFSIZ;
			    rc = 1;
			    return (0);
			} else {
			    buf = tbuf;
			}
		    } else {
			return (0);
		    }
		}
		buf[cc] = c;
		return (1);
	}
	    return (0);
	}

	if (isClocale)
		return (0);

	r_val = 0;
	mbuf[0] = c;
	for (len = 1; len < (unsigned int)MB_CUR_MAX; len++) {
		if ((signed char)
			(mbuf[len] = getc(stdin)) == -1)
			break;
	}
	mbuf[len] = 0;

	if ((len1 = mbtowc(&wc, mbuf, len)) <= 0) {
		len1 = 1;
		goto _unget;
	}

	if (iswprint(wc)) {
		if ((cc + len1) >= (buf_size-2)) {
			if (tbuf != NULL) {
			    buf_size += BUFSIZ;
			    tbuf = (char *)realloc(buf, buf_size);
			    if (tbuf == NULL) {
				(void) fprintf(stderr,
				    gettext("Cannot allocate memory: %s\n"),
				    strerror(errno));
				buf_size -= BUFSIZ;
				rc = 1;
				return (0);
			    }
			    buf = tbuf;
			} else {
			    return (0);
			}
		}
		for (i = 0; i < len1; i++, cc++)
				buf[cc] = mbuf[i];
		r_val = len1;
	}

_unget:
	for (len--; len >= len1; len--)
		(void) ungetc(mbuf[len], stdin);
	return (r_val);
}


static int
ismagic(hsize, hdr, fp)
	int hsize;
	struct aexec *hdr;
	FILE *fp;
{
	switch (hdr->xa_magic) {
		case A_MAGIC1:
		case A_MAGIC2:
		case A_MAGIC3:
		case A_MAGIC4:
			if (hsize < sizeof (struct aexec))
				return (NOTOUT);
			else
				return (AOUT);
		default:
			break;
	}
	return (tryelf(fp));
}


static int
tryelf(fp)
FILE *fp;
{
	int fd;
	Elf *elf;
	GElf_Ehdr ehdr;

	fd = fileno(fp);

	if ((elf_version(EV_CURRENT)) == EV_NONE) {
		(void) fprintf(stderr, "%s\n", elf_errmsg(-1));
		return (NOTOUT);
	}

	(void) lseek(fd, 0L, 0);

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		(void) fprintf(stderr, "%s\n", elf_errmsg(-1));
		return (NOTOUT);
	}

	switch (elf_kind(elf)) {
		case ELF_K_AR:
			/*
			 * This should try to run strings on each element
			 * of the archive.  For now, just search entire
			 * file (-a), as strings has always done
			 * for archives.
			 */
		case ELF_K_NONE:
		(void) elf_end(elf);
		return (NOTOUT);
	}

	if (gelf_getehdr(elf, &ehdr) == (GElf_Ehdr *)NULL) {
		(void) fprintf(stderr, "%s\n", elf_errmsg(-1));
		(void) elf_end(elf);
		return (NOTOUT);
	}

	if ((ehdr.e_type == ET_CORE) || (ehdr.e_type == ET_NONE)) {
		(void) elf_end(elf);
		return (NOTOUT);
	}

	(void) elf_end(elf);

	return (ELF);

}


static void
Usage()
{
	(void) fprintf(stderr, gettext(
	    "Usage: strings [-a | -] [-t format | -o] [-n number | -number]"
	    "\n\t[-N name] [file]...\n"));
	exit(1);
}
