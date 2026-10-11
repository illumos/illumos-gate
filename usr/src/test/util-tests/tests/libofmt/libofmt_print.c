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
 * Copyright 2026 Jason King
 */

/*
 * Tests of the layout of libofmt's output, in particular how a field that
 * doesn't fit in its column is absorbed by the padding of the fields that
 * follow it, for both left (the default) and right (OFMT_RIGHTJUST)
 * justified output.
 *
 * libofmt writes to stdout, so each test redirects stdout to a temporary
 * file while it prints, then compares what was written with the expected
 * output.
 */

#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ofmt.h>
#include <sys/sysmacros.h>

#define	NVALS	4

typedef struct row {
	const char	*r_vals[NVALS];
} row_t;

typedef struct ofmt_test {
	const char		*ot_desc;
	const ofmt_field_t	*ot_fields;
	const char		*ot_fieldstr;	/* NULL for all fields */
	uint_t			ot_flags;
	const row_t		*ot_rows;
	uint_t			ot_nrows;
	const char		*ot_expected;
} ofmt_test_t;

static boolean_t
row_cb(ofmt_arg_t *arg, char *buf, uint_t buflen)
{
	const row_t *r = arg->ofmt_cbarg;

	if (arg->ofmt_id >= NVALS)
		return (B_FALSE);

	(void) strlcpy(buf, r->r_vals[arg->ofmt_id], buflen);
	return (B_TRUE);
}

/*
 * Right justified fields are printed as "%*s ", so each column is one
 * wider than of_width. The name 'ERR' exactly fills its column.
 */
static const ofmt_field_t rj_fields[] = {
	{ "A",		4,	0,	row_cb },
	{ "ERR",	3,	1,	row_cb },
	{ "B",		4,	2,	row_cb },
	{ "C",		4,	3,	row_cb },
	{ NULL,		0,	0,	NULL }
};

/*
 * The same layout, left justified. Left justified fields are printed as
 * "%-*s", so of_width includes the separating space.
 */
static const ofmt_field_t lj_fields[] = {
	{ "A",		5,	0,	row_cb },
	{ "ERR",	4,	1,	row_cb },
	{ "B",		5,	2,	row_cb },
	{ "C",		5,	3,	row_cb },
	{ NULL,		0,	0,	NULL }
};

/* Each row is a set of field values, indexed by of_id */
#define	ROWS(r)	.ot_rows = (r), .ot_nrows = ARRAY_SIZE(r)

static const row_t rows_fit[] = { { { "w", "0", "1", "2" } } };
static const row_t rows_fill[] = { { { "x", "123", "1", "2" } } };
static const row_t rows_lj_fill[] = { { { "x", "1234", "1", "2" } } };
static const row_t rows_over[] = { { { "y", "12345", "1", "2" } } };
static const row_t rows_over2[] = { { { "z", "1234567", "1", "2" } } };
static const row_t rows_carry[] = { { { "v", "12345", "123", "2" } } };
static const row_t rows_huge[] = { { { "u", "1234567890", "1", "2" } } };
static const row_t rows_lastwide[] = { { { "w", "0", "1", "123456" } } };
static const row_t rows_rj_multi[] = {
	{ { "u", "1234567890", "1", "2" } },
	{ { "w", "0", "1", "2" } },
	{ { "x", "123", "1", "2" } },
};
static const row_t rows_lj_multi[] = {
	{ { "z", "1234567", "1", "2" } },
	{ { "w", "0", "1", "2" } },
};
static const row_t rows_select[] = {
	{ { "x", "123", "1", "2" } },
	{ { "y", "12345", "1", "2" } },
};
static const row_t rows_parsable[] = { { { "w", "12345", "1:2", "" } } };

#define	RJ_HDR	"   A ERR    B    C\n"
#define	LJ_HDR	"A    ERR B    C\n"

static const ofmt_test_t tests[] = {
	{
		.ot_desc = "right justified: values fit, a name fills its "
		    "column",
		.ot_fields = rj_fields,
		.ot_flags = OFMT_RIGHTJUST,
		ROWS(rows_fit),
		.ot_expected = RJ_HDR
		    "   w   0    1    2\n"
	},
	{
		.ot_desc = "right justified: field exactly fills its column",
		.ot_fields = rj_fields,
		.ot_flags = OFMT_RIGHTJUST,
		ROWS(rows_fill),
		.ot_expected = RJ_HDR
		    "   x 123    1    2\n"
	},
	{
		.ot_desc = "right justified: overflow absorbed by next field",
		.ot_fields = rj_fields,
		.ot_flags = OFMT_RIGHTJUST,
		ROWS(rows_over),
		.ot_expected = RJ_HDR
		    "   y 12345  1    2\n"
	},
	{
		.ot_desc = "right justified: overflow absorbed by two fields",
		.ot_fields = rj_fields,
		.ot_flags = OFMT_RIGHTJUST,
		ROWS(rows_over2),
		.ot_expected = RJ_HDR
		    "   z 1234567 1   2\n"
	},
	{
		.ot_desc = "right justified: overflow carried over a field "
		    "that can't absorb it",
		.ot_fields = rj_fields,
		.ot_flags = OFMT_RIGHTJUST,
		ROWS(rows_carry),
		.ot_expected = RJ_HDR
		    "   v 12345 123   2\n"
	},
	{
		.ot_desc = "right justified: overflow too large to absorb",
		.ot_fields = rj_fields,
		.ot_flags = OFMT_RIGHTJUST,
		ROWS(rows_huge),
		.ot_expected = RJ_HDR
		    "   u 1234567890 1 2\n"
	},
	{
		.ot_desc = "right justified: last field wider than its column",
		.ot_fields = rj_fields,
		.ot_flags = OFMT_RIGHTJUST,
		ROWS(rows_lastwide),
		.ot_expected = RJ_HDR
		    "   w   0    1 123456\n"
	},
	{
		.ot_desc = "right justified: overflow doesn't carry to the "
		    "next line",
		.ot_fields = rj_fields,
		.ot_flags = OFMT_RIGHTJUST,
		ROWS(rows_rj_multi),
		.ot_expected = RJ_HDR
		    "   u 1234567890 1 2\n"
		    "   w   0    1    2\n"
		    "   x 123    1    2\n"
	},
	{
		.ot_desc = "right justified: selected fields",
		.ot_fields = rj_fields,
		.ot_fieldstr = "err,c",
		.ot_flags = OFMT_RIGHTJUST,
		ROWS(rows_select),
		.ot_expected = "ERR    C\n"
		    "123    2\n"
		    "12345  2\n"
	},
	{
		.ot_desc = "left justified: all fields fit",
		.ot_fields = lj_fields,
		.ot_flags = 0,
		ROWS(rows_fit),
		.ot_expected = LJ_HDR
		    "w    0   1    2\n"
	},
	{
		.ot_desc = "left justified: field fills its column but "
		    "the separator",
		.ot_fields = lj_fields,
		.ot_flags = 0,
		ROWS(rows_fill),
		.ot_expected = LJ_HDR
		    "x    123 1    2\n"
	},
	{
		.ot_desc = "left justified: field exactly fills its column",
		.ot_fields = lj_fields,
		.ot_flags = 0,
		ROWS(rows_lj_fill),
		.ot_expected = LJ_HDR
		    "x    1234 1   2\n"
	},
	{
		.ot_desc = "left justified: overflow absorbed by next field",
		.ot_fields = lj_fields,
		.ot_flags = 0,
		ROWS(rows_over),
		.ot_expected = LJ_HDR
		    "y    12345 1  2\n"
	},
	{
		.ot_desc = "left justified: overflow absorbed by two fields",
		.ot_fields = lj_fields,
		.ot_flags = 0,
		ROWS(rows_over2),
		.ot_expected = LJ_HDR
		    "z    1234567 1 2\n"
	},
	{
		.ot_desc = "left justified: overflow doesn't carry to the "
		    "next line",
		.ot_fields = lj_fields,
		.ot_flags = 0,
		ROWS(rows_lj_multi),
		.ot_expected = LJ_HDR
		    "z    1234567 1 2\n"
		    "w    0   1    2\n"
	},
	{
		.ot_desc = "parsable",
		.ot_fields = rj_fields,
		.ot_fieldstr = "a,err,b,c",
		.ot_flags = OFMT_PARSABLE | OFMT_RIGHTJUST,
		ROWS(rows_parsable),
		.ot_expected = "w:12345:1\\:2:\n"
	},
};

/*
 * Print s, marking the end of each line with '|' so trailing spaces are
 * visible.
 */
static void
print_marked(const char *s)
{
	for (; *s != '\0'; s++) {
		if (*s == '\n')
			(void) fputc('|', stderr);
		(void) fputc(*s, stderr);
	}
}

/*
 * Run the test, returning the output it wrote to stdout in *outp (which
 * the caller must free).
 */
static bool
run_test(const ofmt_test_t *t, char **outp)
{
	char		errbuf[OFMT_BUFSIZE];
	ofmt_handle_t	ofmt;
	ofmt_status_t	st;
	FILE		*tmp;
	long		len;
	char		*out;
	int		saved;

	if ((tmp = tmpfile()) == NULL)
		err(EXIT_FAILURE, "failed to create temporary file");

	/*
	 * Redirect stdout before ofmt_open(), since it sizes its output
	 * (e.g. how often the header repeats) from the terminal, if stdout
	 * is one.
	 */
	(void) fflush(stdout);
	if ((saved = dup(STDOUT_FILENO)) < 0 ||
	    dup2(fileno(tmp), STDOUT_FILENO) < 0)
		err(EXIT_FAILURE, "failed to redirect stdout");

	st = ofmt_open(t->ot_fieldstr, t->ot_fields, t->ot_flags, 0, &ofmt);
	if (st == OFMT_SUCCESS) {
		for (uint_t i = 0; i < t->ot_nrows; i++)
			ofmt_print(ofmt, (void *)&t->ot_rows[i]);
	}

	(void) fflush(stdout);
	if (dup2(saved, STDOUT_FILENO) < 0)
		err(EXIT_FAILURE, "failed to restore stdout");
	(void) close(saved);

	if (st != OFMT_SUCCESS) {
		warnx("TEST FAILED: %s: ofmt_open failed: %s", t->ot_desc,
		    ofmt_strerror(ofmt, st, errbuf, sizeof (errbuf)));
		ofmt_close(ofmt);
		(void) fclose(tmp);
		return (false);
	}
	ofmt_close(ofmt);

	if (fseek(tmp, 0, SEEK_END) != 0 || (len = ftell(tmp)) < 0)
		err(EXIT_FAILURE, "failed to size output");
	rewind(tmp);

	if ((out = calloc(1, len + 1)) == NULL)
		err(EXIT_FAILURE, "failed to allocate memory");
	if (len > 0 && fread(out, len, 1, tmp) != 1)
		err(EXIT_FAILURE, "failed to read output");
	(void) fclose(tmp);

	*outp = out;
	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		const ofmt_test_t *t = &tests[i];
		char *out;

		if (!run_test(t, &out)) {
			ret = EXIT_FAILURE;
			continue;
		}

		if (strcmp(out, t->ot_expected) == 0) {
			(void) printf("TEST PASSED: %s\n", t->ot_desc);
		} else {
			warnx("TEST FAILED: %s", t->ot_desc);
			(void) fprintf(stderr, "expected:\n");
			print_marked(t->ot_expected);
			(void) fprintf(stderr, "actual:\n");
			print_marked(out);
			ret = EXIT_FAILURE;
		}

		free(out);
	}

	if (ret == EXIT_SUCCESS)
		(void) printf("All tests passed successfully!\n");

	return (ret);
}
