/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * iconv(1) command.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <iconv.h>
#include <libintl.h>
#include <langinfo.h>
#include <locale.h>
#include "charmap.h"

#include <assert.h>

const char *progname;

char *from_cs;
char *to_cs;
int debug;
int cflag;	/* skip invalid characters */
int sflag;	/* silent */
int lflag;	/* list conversions */

void iconv_file(FILE *, const char *);
extern int list_codesets(void);

iconv_t ich;	/* iconv(3c) lib handle */
size_t (*pconv)(const char **iptr, size_t *ileft,
		char **optr, size_t *oleft);

size_t
lib_iconv(const char **iptr, size_t *ileft, char **optr, size_t *oleft)
{
	return (iconv(ich, iptr, ileft, optr, oleft));
}

void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage: %s [-cs] [-f from-codeset] [-t to-codeset] "
	    "[file ...]\n"), progname);
	(void) fprintf(stderr, gettext("\t%s -l\n"), progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	FILE *fp;
	char *fslash, *tslash;
	int c;

	yydebug = 0;
	progname = getprogname();

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "cdlsf:t:")) != EOF) {
		switch (c) {
		case 'c':
			cflag++;
			break;
		case 'd':
			debug++;
			break;
		case 'l':
			lflag++;
			break;
		case 's':
			sflag++;
			break;
		case 'f':
			from_cs = optarg;
			break;
		case 't':
			to_cs = optarg;
			break;
		case '?':
			usage();
		}
	}

	if (lflag) {
		if (from_cs != NULL || to_cs != NULL || optind != argc)
			usage();
		exit(list_codesets());
	}

	if (from_cs == NULL)
		from_cs = nl_langinfo(CODESET);
	if (to_cs == NULL)
		to_cs = nl_langinfo(CODESET);

	/*
	 * If either "from" or "to" contains a slash,
	 * then we're using charmaps.
	 */
	fslash = strchr(from_cs, '/');
	tslash = strchr(to_cs, '/');
	if (fslash != NULL || tslash != NULL) {
		charmap_init(to_cs, from_cs);
		pconv = cm_iconv;
		if (debug)
			charmap_dump();
	} else {
		ich = iconv_open(to_cs, from_cs);
		if (ich == ((iconv_t)-1)) {
			switch (errno) {
			case EINVAL:
				(void) fprintf(stderr,
				    _("Not supported %s to %s\n"),
				    from_cs, to_cs);
				break;
			default:
				(void) fprintf(stderr,
				    _("iconv_open failed: %s\n"),
				    strerror(errno));
				break;
			}
			exit(1);
		}
		pconv = lib_iconv;
	}

	if (optind == argc ||
	    (optind == argc - 1 && 0 == strcmp(argv[optind], "-"))) {
		iconv_file(stdin, "stdin");
		exit(warnings ? 1 : 0);
	}

	for (; optind < argc; optind++) {
		fp = fopen(argv[optind], "r");
		if (fp == NULL) {
			perror(argv[optind]);
			exit(1);
		}
		iconv_file(fp, argv[optind]);
		(void) fclose(fp);
	}
	exit(warnings ? 1 : 0);
}

/*
 * Conversion buffer sizes:
 *
 * The input buffer has room to prepend one mbs character if needed for
 * handling a left-over at the end of a previous conversion buffer.
 *
 * Conversions may grow or shrink data, so using a larger output buffer
 * to reduce the likelihood of leftover input buffer data in each pass.
 */
#define	IBUFSIZ	(MB_LEN_MAX + BUFSIZ)
#define	OBUFSIZ	(2 * BUFSIZ)

void
iconv_file(FILE *fp, const char *fname)
{
	static char ibuf[IBUFSIZ];
	static char obuf[OBUFSIZ];
	const char *iptr;
	char *optr;
	off64_t offset;
	size_t ileft, oleft, ocnt;
	int iconv_errno;
	int nr, nw, rc;

	offset = 0;
	ileft = 0;
	iptr = ibuf + MB_LEN_MAX;

	while ((nr = fread(ibuf+MB_LEN_MAX, 1, BUFSIZ, fp)) > 0) {

		assert(iptr <= ibuf+MB_LEN_MAX);
		assert(ileft <= MB_LEN_MAX);
		ileft += nr;
		offset += nr;

		optr = obuf;
		oleft = OBUFSIZ;

		/*
		 * Note: the *pconv function is either iconv(3c) or our
		 * private equivalent when using charmaps. Both update
		 * ileft, oleft etc. even when conversion stops due to
		 * an illegal sequence or whatever, so we need to copy
		 * the partially converted buffer even on error.
		 */
	iconv_again:
		rc = (*pconv)(&iptr, &ileft, &optr, &oleft);
		iconv_errno = errno;

		ocnt = OBUFSIZ - oleft;
		if (ocnt > 0) {
			nw = fwrite(obuf, 1, ocnt, stdout);
			if (nw != ocnt) {
				perror("fwrite");
				exit(1);
			}
		}
		optr = obuf;
		oleft = OBUFSIZ;

		if (rc == (size_t)-1) {
			switch (iconv_errno) {

			case E2BIG:	/* no room in output buffer */
				goto iconv_again;

			case EINVAL:	/* incomplete sequence on input */
				if (debug) {
					(void) fprintf(stderr,
			_("Incomplete sequence in %s at offset %lld\n"),
					    fname, offset - ileft);
				}
				/*
				 * Copy the remainder to the space reserved
				 * at the start of the input buffer.
				 */
				assert(ileft > 0);
				if (ileft <= MB_LEN_MAX) {
					char *p = ibuf+MB_LEN_MAX-ileft;
					(void) memmove(p, iptr, ileft);
					iptr = p;
					continue; /* read again */
				}
				/*
				 * Should not see ileft > MB_LEN_MAX,
				 * but if we do, handle as EILSEQ.
				 */
				/* FALLTHROUGH */

			case EILSEQ:	/* invalid sequence on input */
				if (!sflag) {
					(void) fprintf(stderr,
			_("Illegal sequence in %s at offset %lld\n"),
					    fname, offset - ileft);
					(void) fprintf(stderr,
			_("bad seq: \\x%02x\\x%02x\\x%02x\n"),
					    iptr[0] & 0xff,
					    iptr[1] & 0xff,
					    iptr[2] & 0xff);
				}
				assert(ileft > 0);
				/* skip one */
				iptr++;
				ileft--;
				assert(oleft > 0);
				if (!cflag) {
					*optr++ = '?';
					oleft--;
				}
				goto iconv_again;

			default:
				(void) fprintf(stderr,
			_("iconv error (%s) in file $s at offset %lld\n"),
				    strerror(iconv_errno), fname,
				    offset - ileft);
				break;
			}
		}

		/* normal iconv return */
		ileft = 0;
		iptr = ibuf + MB_LEN_MAX;
	}

	/*
	 * End of file
	 * Flush any shift encodings.
	 */
	iptr = NULL;
	ileft = 0;
	optr = obuf;
	oleft = OBUFSIZ;
	(*pconv)(&iptr, &ileft, &optr, &oleft);
	ocnt = OBUFSIZ - oleft;
	if (ocnt > 0) {
		nw = fwrite(obuf, 1, ocnt, stdout);
		if (nw != ocnt) {
			perror("fwrite");
			exit(1);
		}
	}
}
