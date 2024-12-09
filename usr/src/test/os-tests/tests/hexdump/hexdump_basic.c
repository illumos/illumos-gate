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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Basic tests for the common hexdump routine.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/ilstr.h>
#include <sys/hexdump.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/stdbool.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#define	DATADIR	"/opt/os-tests/tests/hexdump/data"

const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("transaction,contents,fail");
}

typedef struct test {
	const char		*name;
	hexdump_flag_t		flags;
	uint8_t			width;
	uint8_t			grouping;
	uint64_t		addr;
	uint8_t			indent;
	uint8_t			marker;
} test_t;

test_t tests[] = {
	{
		.name = "basic",
	}, {
		.name = "header",
		.flags = HDF_HEADER,
	}, {
		.name = "address",
		.flags = HDF_ADDRESS,
	}, {
		.name = "ascii",
		.flags = HDF_ASCII,
	}, {
		.name = "dedup",
		.flags = HDF_DEDUP,
	}, {
		.name = "doublespace",
		.flags = HDF_DOUBLESPACE,
	}, {
		.name = "address+header",
		.flags = HDF_ADDRESS | HDF_HEADER,
	}, {
		.name = "default",
		.flags = HDF_DEFAULT,
	}, {
		.name = "marker1",
		.flags = HDF_DEFAULT | HDF_DEDUP,
		.marker = 5
	}, {
		.name = "addr1",
		.flags = HDF_DEFAULT | HDF_DEDUP,
		.addr = 0x876543
	}, {
		.name = "addr2",
		.flags = HDF_DEFAULT | HDF_DEDUP,
		.addr = 0xffff8
	}, {
		.name = "align1",
		.flags = HDF_DEFAULT | HDF_DEDUP | HDF_ALIGN,
		.addr = 0x876543
	}, {
		.name = "indent",
		.flags = HDF_DEFAULT | HDF_DEDUP,
		.indent = 3
	}, {
		.name = "group2",
		.flags = HDF_DEFAULT | HDF_DEDUP,
		.addr = 0x876543,
		.grouping = 2,
	}, {
		.name = "group4",
		.flags = HDF_DEFAULT | HDF_DEDUP,
		.addr = 0x876543,
		.grouping = 4,
	}, {
		.name = "group8",
		.flags = HDF_DEFAULT | HDF_DEDUP,
		.addr = 0x876543,
		.grouping = 8,
	}, {
		.name = "width12",
		.flags = HDF_DEFAULT | HDF_DEDUP,
		.addr = 0x876543,
		.width = 12,
		.grouping = 4
	}, {
		.name = "wide1",
		.flags = HDF_ADDRESS | HDF_HEADER,
		.addr = 0x876543,
		.width = 32,
		.grouping = 8
	}, {
		.name = "narrow1",
		.flags = HDF_DEFAULT | HDF_DOUBLESPACE,
		.addr = 0x876543,
		.width = 4,
		.grouping = 2
	}, {
		.name = "narrow2",
		.flags = HDF_DEFAULT | HDF_DEDUP,
		.addr = 0x876543,
		.width = 1,
		.grouping = 1
	}
};

static char *flagdescr[] = {
	"HEADER",
	"ADDRESS",
	"ASCII",
	"ALIGN",
	"DEDUP",
	"DOUBLESPACE",
};

static void
descr(test_t *t, ilstr_t *i)
{
	ilstr_append_str(i, "=============================================\n");
	ilstr_aprintf(i, "[%s] w=%u g=%u a=0x%x - ",
	    t->name, t->width, t->grouping, t->addr);

	int flags = t->flags;
	bool first = true;
	while (flags != 0) {
		int b = fls(flags);
		if (b == 0)
			break;
		b--;
		VERIFY3S(b, <, ARRAY_SIZE(flagdescr));
		if (first)
			first = false;
		else
			ilstr_append_char(i, ' ');
		ilstr_aprintf(i, "%s", flagdescr[b]);
		flags &= ~(1<< b);
	}
	ilstr_append_char(i, '\n');
	ilstr_append_str(i, "=============================================\n");
}

static int
cb(void *arg, uint64_t addr __unused, const char *str, size_t l)
{
	ilstr_t *i = arg;

	ilstr_append_str(i, str);
	ilstr_append_char(i, '\n');

	return (0);
}

static void
run(test_t *t, uint8_t *data, size_t len, ilstr_t *i)
{
	hexdump_t hd;

	descr(t, i);

	hexdump_init(&hd);
	if (t->width != 0)
		hexdump_set_width(&hd, t->width);
	if (t->grouping != 0)
		hexdump_set_grouping(&hd, t->grouping);
	if (t->addr != 0)
		hexdump_set_addr(&hd, t->addr);
	if (t->indent != 0)
		hexdump_set_indent(&hd, t->indent);
	if (t->marker != 0)
		hexdump_set_marker(&hd, t->marker);

	VERIFY0(hexdumph(&hd, data, len, t->flags, cb, (void *)i));

	hexdump_fini(&hd);

	VERIFY3U(ilstr_errno(i), ==, ILSTR_ERROR_OK);
}

static uint8_t *
mapfile(const char *filename, size_t *lenp)
{
	uint8_t *p;
	struct stat st;
	int fd;

	if ((fd = open(filename, O_RDONLY)) == -1)
		err(EXIT_FAILURE, "could not open '%s'", filename);

	if (fstat(fd, &st) == -1)
		err(EXIT_FAILURE, "failed to stat '%s'", filename);

	p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		err(EXIT_FAILURE, "failed to mmap 0x%lx bytes from '%s'",
		    st.st_size, filename);

	VERIFY0(close(fd));

	*lenp = st.st_size;
	return (p);
}

static void __PRINTFLIKE(2) __NORETURN
usage(int ec, const char *fmt, ...)
{
	va_list ap;

	if (fmt != NULL) {
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
		(void) fprintf(stderr, "\n");
	}

	(void) fprintf(stderr,
	    "Usage:\n"
	    "    -d <directory>  specify data directory\n"
	    "                    (default: %s)\n"
	    "    -g              generate baseline files\n"
	    "    -h              show usage\n"
	    "    -t <test>       run just the test named <test>\n"
	    "    -v              send test output to stdout\n",
	    DATADIR);
	exit(ec);
}

int
main(int argc, char **argv)
{
	uint8_t *data;
	const char *datadir = DATADIR;
	char buf[MAXPATHLEN + 1];
	const char *test = NULL;
	ilstr_t testout;
	uint_t failures = 0;
	size_t maplen;
	int c;

	enum {
		MODE_TEST,
		MODE_GENERATE,
		MODE_DUMP
	} testmode = MODE_TEST;

	while ((c = getopt(argc, argv, ":d:ght:v")) != -1) {
		switch (c) {
		case 'd':
			datadir = optarg;
			break;
		case 'g':
			testmode = MODE_GENERATE;
			break;
		case 'h':
			usage(0, NULL);
		case 't':
			test = optarg;
			break;
		case 'v':
			testmode = MODE_DUMP;
			break;
		case ':':
			usage(EXIT_FAILURE,
			    "Option -%c requires an operand\n", optopt);
		case '?':
			usage(EXIT_FAILURE, "Unknown option: -%c", optopt);
		}
	}

	if (snprintf(buf, sizeof (buf), "%s/_input", datadir) >= sizeof (buf))
		errx(EXIT_FAILURE, "Overflow building data dir path");

	data = mapfile(buf, &maplen);

	ilstr_init(&testout, 0);

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		if (test != NULL && strcmp(test, tests[i].name) != 0)
			continue;

		if (snprintf(buf, sizeof (buf), "%s/%s", datadir,
		    tests[i].name) >= sizeof (buf)) {
			errx(EXIT_FAILURE, "Overflow building output path");
		}

		run(&tests[i], data, maplen, &testout);

		switch (testmode) {
		case MODE_TEST: {
			uint8_t *refdata;
			size_t reflen;

			refdata = mapfile(buf, &reflen);

			if (ilstr_len(&testout) != reflen ||
			    memcmp(ilstr_cstr(&testout), refdata,
			    reflen) != 0) {
				failures++;
				(void) fprintf(stderr,
				    "Hexdump '%s' output mismatch",
				    tests[i].name);
				(void) fprintf(stderr, "== Expected:\n%s\n",
				    refdata);
				(void) fprintf(stderr, "== Got:\n%s\n",
				    ilstr_cstr(&testout));
			}

			VERIFY0(munmap(refdata, reflen));
			break;
		}
		case MODE_GENERATE: {
			FILE *fp;

			fp = fopen(buf, "w");
			if (fp == NULL)
				err(EXIT_FAILURE, "Failed to create %s", buf);
			(void) fprintf(fp, "%s", ilstr_cstr(&testout));
			VERIFY0(fclose(fp));
			break;
		}
		case MODE_DUMP:
			(void) fprintf(stdout, "%s\n", ilstr_cstr(&testout));
			break;
		}
		ilstr_reset(&testout);
	}

	ilstr_fini(&testout);

	VERIFY0(munmap(data, maplen));

	if (testmode == MODE_TEST && failures == 0)
		(void) printf("All hexdump tests have passed.\n");

	return (failures > 0 ? EXIT_FAILURE : 0);
}
