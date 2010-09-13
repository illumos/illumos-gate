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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <tnf/tnf.h>
#include <errno.h>
#include <stdlib.h>
#include <libintl.h>
#include <locale.h>

#include "state.h"

static caddr_t	g_file_base;	/* base address of file 	*/
static char	*g_cmdname;	/* name of this command		*/
static int	g_raw = B_FALSE;	/* output format */
static int	g_status = EXIT_SUCCESS; /* exit status (from stdlib.h) */
static const char	*print_unsigned = "%u";
static const char	*print_unsigned64 = "%llu";

#define	OFF(p)	(p - g_file_base)

static void describe_array		(tnf_datum_t);
static void describe_brief		(tnf_datum_t);
static void describe_record		(tnf_datum_t);
static void describe_struct		(tnf_datum_t);
static void describe_type		(tnf_datum_t);
static void read_tnf_file		(int, char *);
static void usage			(void);
static void scanargs			(int, char **, int *, char ***);

int
main(int ac, char *av[])
{
	int 	numfiles;	/* number of files to be printed */
	char 	**filenames;	/* start of file names list 	*/
	int	i;

	/* internationalization stuff */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	g_cmdname = av[0];
	scanargs(ac, av, &numfiles, &filenames);
	for (i = 0; i < numfiles; i++) {
		read_tnf_file(g_raw, filenames[i]);
	}

	if (!g_raw) {
		if (table_get_num_elements() > 0) {
			print_c_header();
			print_sorted_events();
		}
	}

	exit(g_status);

	return (0);
}

static void
scanargs(int argc, char **argv, int *nfiles, char ***files)
{
	int c;
	int errflg = B_FALSE;
	char *optstr = "rx";

	while ((c = getopt(argc, argv, optstr)) != EOF) {
		switch (c) {
		case 'r':
			g_raw = B_TRUE;
			break;
		case 'x':
			print_unsigned = "0x%x";
			print_unsigned64 = "0x%llx";
			break;
		case '?':
			errflg = B_TRUE;
			break;
		}
	}
	*files = &argv[optind];
	*nfiles = argc - optind;
	if (*nfiles <= 0) {
	    errflg = B_TRUE;
	}
	if (errflg) {
		usage();
	}
}


static void
read_tnf_file(int raw, char *path)
{
	int 		fd;
	struct stat 	st;
	caddr_t 	p, curr_p, end_p;
	TNF		*tnf;
	tnf_errcode_t	err;
	tnf_datum_t	record;
	void (*desc_func)(tnf_datum_t) = describe_c_record;

	if ((fd = open(path, O_RDONLY, 0777)) == -1) {
		(void) fprintf(stderr, gettext("%s: cannot open %s\n"),
		    g_cmdname, path);
		g_status = EXIT_FAILURE;
		return;
	}
	if (fstat(fd, &st) != 0) {
		(void) fprintf(stderr, gettext("%s: fstat error on %s\n"),
		    g_cmdname, path);
		(void) close(fd);
		g_status = EXIT_FAILURE;
		return;
	}
	if (st.st_size == 0) {
		(void) fprintf(stderr, gettext("%s: %s is empty\n"),
		    g_cmdname, path);
		(void) close(fd);
		g_status = EXIT_FAILURE;
		return;
	}
	if ((p = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0))
	    == (caddr_t)-1) {
		(void) fprintf(stderr, gettext("%s: mmap error on %s\n"),
		    g_cmdname, path);
		(void) close(fd);
		g_status = EXIT_FAILURE;
		return;
	}

	if (raw)
		g_file_base = p;		/* for OFF() */

	if (*p == 0) {
		/*
		 * magic word is 0 - catch the error if entire file is zero.
		 * tnf_reader_begin() will catch the "not a TNF file" error.
		 */
		curr_p = p;
		end_p = p + st.st_size;
		while ((curr_p < end_p) && (*curr_p == 0))
			curr_p++;
		if (curr_p == end_p) {
			(void) fprintf(stderr,
				gettext("%s: %s is an empty TNF file\n"),
				g_cmdname, path);
			(void) munmap(p, st.st_size);
			(void) close(fd);
			return;
		}
	}

	if ((err = tnf_reader_begin(p, st.st_size, &tnf)) != TNF_ERR_NONE) {
		(void) fprintf(stderr, gettext("%s: error in %s: %s\n"),
		    g_cmdname, path, tnf_error_message(err));
		(void) munmap(p, st.st_size);
		(void) close(fd);
		g_status = EXIT_FAILURE;
		return;
	}

	/* Describe file header */
	record = tnf_get_file_header(tnf);
	if (raw) {
		describe_record(record);
		desc_func = describe_record;
	}

	/* Describe all other records */
	while ((record = tnf_get_next_record(record)) != TNF_DATUM_NULL)
		desc_func(record);

	/* Don't munmap for cooked output because we access records later */
	if (raw)
		(void) munmap(p, st.st_size);
	(void) close(fd);
}

static void
describe_record(tnf_datum_t datum)
{
	(void) printf("0x%-8x: {\n", OFF(tnf_get_raw(datum)));

	switch (tnf_get_kind(datum)) {

	case TNF_K_STRUCT:
		describe_struct(datum);
		break;
	case TNF_K_STRING:
	case TNF_K_ARRAY:
		describe_array(datum);
		break;
	case TNF_K_TYPE:
		describe_type(datum);
		break;
	default:
		fail(0, gettext("illegal record at %x (%d)"),
			tnf_get_raw(datum), tnf_get_kind(datum));
		break;
	}

	(void) printf("\t}\n");
}

void
describe_scalar(tnf_datum_t datum)
{
	switch (tnf_get_kind(datum)) {

	case TNF_K_CHAR:
		(void) printf("%c", tnf_get_char(datum));
		break;
	case TNF_K_INT8:
		(void) printf("%d", tnf_get_int8(datum));
		break;
	case TNF_K_UINT8:
		(void) printf(print_unsigned, (tnf_uint8_t)tnf_get_int8(datum));
		break;
	case TNF_K_INT16:
		(void) printf("%d", tnf_get_int16(datum));
		break;
	case TNF_K_UINT16:
		(void) printf(print_unsigned,
			(tnf_uint16_t)tnf_get_int16(datum));
		break;
	case TNF_K_INT32:
		(void) printf("%d", (int)tnf_get_int32(datum));
		break;
	case TNF_K_UINT32:
		if ((tnf_type_get_property(tnf_get_type(datum), TNF_N_OPAQUE))
				!= TNF_DATUM_NULL) {
			/* XXX */
			(void) printf("0x%x",
				(tnf_uint32_t)tnf_get_int32(datum));
		} else {
			(void) printf(print_unsigned,
				(tnf_uint32_t)tnf_get_int32(datum));
		}
		break;
	case TNF_K_INT64:
		/* lint not updated, it complains: malformed format string */
		(void) printf("%lld", 	tnf_get_int64(datum));
		break;
	case TNF_K_UINT64:
		if ((tnf_type_get_property(tnf_get_type(datum), TNF_N_OPAQUE))
			!= TNF_DATUM_NULL) {
			(void) printf("0x%llx",
				(tnf_uint64_t)tnf_get_int64(datum));
		} else {
		/* lint not updated, it complains: malformed format string */
			(void) printf(print_unsigned64,
					(tnf_uint64_t)tnf_get_int64(datum));
		}
		break;
	case TNF_K_FLOAT32:
		(void) printf("%f", tnf_get_float32(datum));
		break;
	case TNF_K_FLOAT64:
		(void) printf("%f", tnf_get_float64(datum));
		break;
	case TNF_K_SCALAR:
		(void) printf("unhandled scalar");
		break;
	default:
		fail(0, gettext("not a scalar"));
		break;
	}
}

static void
describe_struct(tnf_datum_t datum)
{
	unsigned n, i;
	char *slotname;

	n = tnf_get_slot_count(datum);
	for (i = 0; i < n; i++) {
		slotname = tnf_get_slot_name(datum, i);
		(void) printf("%24s ", slotname);
		describe_brief(tnf_get_slot_indexed(datum, i));
		(void) printf("\n");
		/* tag_arg heuristic */
		if ((i == 0) && tnf_is_record(datum)) {
			tnf_datum_t tag_arg;

			if ((tag_arg = tnf_get_tag_arg(datum))
			    != TNF_DATUM_NULL) {
				(void) printf("%24s ", TNF_N_TAG_ARG);
				describe_brief(tag_arg);
				(void) printf("\n");
			}
		}
	}
}

static void
describe_array(tnf_datum_t datum)
{
	unsigned n, i;

	describe_struct(datum);	/* XXX */

	if (tnf_is_string(datum))
		(void) printf("%24s \"%s\"\n", "chars", tnf_get_chars(datum));
	else {
		n = tnf_get_element_count(datum);
		for (i = 0; i < n; i++) {
			(void) printf("%24d ", i);
			describe_brief(tnf_get_element(datum, i));
			(void) printf("\n");
		}
	}
}

static void
describe_type(tnf_datum_t datum)
{
	describe_struct(datum);
}

static void
describe_brief(tnf_datum_t datum)
{
	if (datum == TNF_DATUM_NULL) /* allowed */
		(void) printf("0x%-8x <NULL>", 0);

	else if (tnf_is_scalar(datum))
		describe_scalar(datum);

	else if (tnf_is_record(datum)) {

		(void) printf("0x%-8x ",
			OFF(tnf_get_raw(datum))); /* common */

		switch (tnf_get_kind(datum)) {
		case TNF_K_TYPE:
			(void) printf("%s", tnf_type_get_name(datum));
			break;
		case TNF_K_STRING:
			(void) printf("\"%s\"", tnf_get_chars(datum));
			break;
		default:
			(void) printf("<%s>", tnf_get_type_name(datum));
		}
	} else
		fail(0, gettext("inline aggregate slots/elements unhandled"));
}

void
fail(int do_perror, char *message, ...)
{
	va_list args;

	va_start(args, message);
	(void) fprintf(stderr, gettext("%s: "), g_cmdname);
	(void) vfprintf(stderr, message, args);
	va_end(args);
	if (do_perror)
		(void) fprintf(stderr, gettext(": %s"), strerror(errno));
	(void) fprintf(stderr, gettext("\n"));
	exit(EXIT_FAILURE);
}

static void
usage(void)
{
	(void) fprintf(stderr,
			gettext("Usage: %s [-r] <tnf_file> [<tnf_file> ...]\n"),
			g_cmdname);
	exit(EXIT_FAILURE);
}
