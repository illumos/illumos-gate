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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Take the error number definitions from a foreign system and generate a
 * translation table that converts illumos native error numbers to foreign
 * system error numbers.
 */

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <sys/sysmacros.h>
#include <libcmdutils.h>
#include <libnvpair.h>

nvlist_t *native_errors;
nvlist_t *foreign_errors;

struct override {
	const char *ovr_from;
	const char *ovr_to;
} overrides[] = {
	{ "ENOTSUP", "ENOSYS" },
	{ 0 }
};

static const char *
lookup_override(const char *from)
{
	int i;

	for (i = 0; overrides[i].ovr_from != NULL; i++) {
		if (strcmp(overrides[i].ovr_from, from) == 0) {
			return (overrides[i].ovr_to);
		}
	}

	return (NULL);
}

static int
parse_int(const char *number, int *rval)
{
	long n;
	char *endpos;

	errno = 0;
	if ((n = strtol(number, &endpos, 10)) == 0 && errno != 0) {
		return (-1);
	}

	if (endpos != NULL && *endpos != '\0') {
		errno = EINVAL;
		return (-1);
	}

	if (n > INT_MAX || n < INT_MIN) {
		errno = EOVERFLOW;
		return (-1);
	}

	*rval = (int)n;
	return (0);
}

static int
errnum_add(nvlist_t *nvl, const char *name, const char *number)
{
	int val;

	if (nvlist_exists(nvl, name)) {
		(void) fprintf(stderr, "ERROR: duplicate definition: %s -> "
		    "%s\n", name, number);
		errno = EEXIST;
		return (-1);
	}

	/*
	 * Try and parse the error number:
	 */
	if (parse_int(number, &val) == 0) {
		/*
		 * The name refers to a number.
		 */
		if (nvlist_add_int32(nvl, name, val) != 0) {
			(void) fprintf(stderr, "ERROR: nvlist_add_int32: %s\n",
			    strerror(errno));
			return (-1);
		}
	} else {
		/*
		 * The name refers to another definition.
		 */
		if (nvlist_add_string(nvl, name, number) != 0) {
			(void) fprintf(stderr, "ERROR: nvlist_add_string: %s\n",
			    strerror(errno));
			return (-1);
		}
	}

	return (0);
}

static int
errnum_max(nvlist_t *nvl)
{
	int max = 0;
	nvpair_t *nvp = NULL;

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		if (nvpair_type(nvp) != DATA_TYPE_INT32) {
			continue;
		}

		max = MAX(fnvpair_value_int32(nvp), max);
	}

	return (max);
}

static int
errname_by_num(nvlist_t *nvl, int num, const char **name)
{
	nvpair_t *nvp = NULL;

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		if (nvpair_type(nvp) != DATA_TYPE_INT32) {
			continue;
		}

		if (fnvpair_value_int32(nvp) == num) {
			*name = nvpair_name(nvp);
			return (0);
		}
	}

	errno = ENOENT;
	return (-1);
}

static int
errno_by_name(nvlist_t *nvl, const char *name, int *rval, const char **rname)
{
	nvpair_t *nvp = NULL;

	if (nvlist_lookup_nvpair(nvl, name, &nvp) != 0) {
		errno = ENOENT;
		return (-1);
	}

	if (nvpair_type(nvp) == DATA_TYPE_STRING) {
		return (errno_by_name(nvl, fnvpair_value_string(nvp), rval,
		    rname));
	} else {
		*rval = fnvpair_value_int32(nvp);
		if (rname != NULL) {
			*rname = name;
		}
		return (0);
	}
}

static int
process_line(const char *line, nvlist_t *nvl)
{
	custr_t *nam = NULL, *num = NULL;
	const char *c = line;

	if (custr_alloc(&nam) != 0 || custr_alloc(&num) != 0) {
		int en = errno;

		custr_free(nam);
		custr_free(num);

		errno = en;
		return (-1);
	}

	/*
	 * Valid lines begin with "#define":
	 */
	if (*c++ != '#' || *c++ != 'd' || *c++ != 'e' || *c++ != 'f' ||
	    *c++ != 'i' || *c++ != 'n' || *c++ != 'e') {
		return (0);
	}

	/*
	 * Eat whitespace:
	 */
	for (;;) {
		if (*c == '\0') {
			return (0);
		}

		if (*c != ' ' && *c != '\t') {
			break;
		}

		c++;
	}

	/*
	 * Read error number token:
	 */
	for (;;) {
		if (*c == '\0') {
			return (0);
		}

		if (*c == ' ' || *c == '\t') {
			break;
		}

		if (custr_appendc(nam, *c) != 0) {
			return (-1);
		}

		c++;
	}

	/*
	 * Eat whitespace:
	 */
	for (;;) {
		if (*c == '\0') {
			return (0);
		}

		if (*c != ' ' && *c != '\t') {
			break;
		}

		c++;
	}

	/*
	 * Read error number token:
	 */
	for (;;) {
		if (*c == '\0') {
			break;
		}

		if (*c == ' ' || *c == '\t') {
			break;
		}

		if (custr_appendc(num, *c) != 0) {
			return (-1);
		}

		c++;
	}

	return (errnum_add(nvl, custr_cstr(nam), custr_cstr(num)));
}

static int
read_file_into_list(const char *path, nvlist_t *nvl)
{
	int rval = 0, en = 0;
	FILE *f;
	custr_t *cu = NULL;

	if (custr_alloc(&cu) != 0) {
		return (-1);
	}

	if ((f = fopen(path, "r")) == NULL) {
		custr_free(cu);
		return (-1);
	}

	for (;;) {
		int c;

		errno = 0;
		switch (c = fgetc(f)) {
		case '\n':
		case EOF:
			if (errno != 0) {
				en = errno;
				rval = -1;
				goto out;
			}
			if (process_line(custr_cstr(cu), nvl) != 0) {
				en = errno;
				rval = -1;
				goto out;
			}
			custr_reset(cu);
			if (c == EOF) {
				goto out;
			}
			break;

		case '\r':
		case '\0':
			/*
			 * Ignore these characters.
			 */
			break;

		default:
			if (custr_appendc(cu, c) != 0) {
				en = errno;
				rval = -1;
				goto out;
			}
			break;
		}
	}

out:
	(void) fclose(f);
	custr_free(cu);
	errno = en;
	return (rval);
}

int
main(int argc, char **argv)
{
	int max;
	int fval;
	int c;

	if (nvlist_alloc(&native_errors, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_alloc(&foreign_errors, NV_UNIQUE_NAME, 0) != 0) {
		err(1, "could not allocate memory");
	}

	while ((c = getopt(argc, argv, ":N:F:")) != -1) {
		switch (c) {
		case 'N':
			if (read_file_into_list(optarg, native_errors) != 0) {
				err(1, "could not read file: %s", optarg);
			}
			break;

		case 'F':
			if (read_file_into_list(optarg, foreign_errors) != 0) {
				err(1, "could not read file: %s", optarg);
			}
			break;

		case ':':
			errx(1, "option -%c requires an operand", c);
			break;

		case '?':
			errx(1, "option -%c unrecognised", c);
			break;
		}
	}

	/*
	 * Print an array entry for each error number:
	 */
	max = errnum_max(native_errors);
	for (fval = 0; fval <= max; fval++) {
		const char *fname;
		const char *tname = NULL;
		int32_t tval;
		const char *msg = NULL;
		const char *comma = (fval != max) ? "," : "";

		if (errname_by_num(native_errors, fval, &fname) == -1) {
			fname = NULL;
		}

		if (fval == 0) {
			/*
			 * The error number "0" is special: it means no worries.
			 */
			msg = "No Error";
			tval = 0;
		} else if (fname == NULL) {
			/*
			 * There is no defined name for this error number; it
			 * is unused.
			 */
			msg = "Unused Number";
			tval = -1;
		} else {
			/*
			 * Check if we want to override the name of this error
			 * in the foreign error number lookup:
			 */
			const char *oname = lookup_override(fname);

			/*
			 * Do the lookup:
			 */
			if (errno_by_name(foreign_errors, oname != NULL ?
			    oname : fname, &tval, &tname) != 0) {
				/*
				 * There was no foreign error number by that
				 * name.
				 */
				tname = "No Analogue";
				tval = -2;
			}
		}

		if (msg == NULL) {
			size_t flen = strlen(fname);
			size_t tlen = strlen(tname);
			const char *t = flen > 7 ? "\t" : "\t\t";
			const char *tt = tlen < 7 ? "\t\t\t" : tlen < 15 ?
			    "\t\t" : "\t";

			(void) fprintf(stdout, "\t%d%s\t/* %3d: %s%s--> %3d: "
			    "%s%s*/\n", tval, comma, fval, fname, t, tval,
			    tname, tt);
		} else {
			const char *t = "\t\t\t\t\t";

			(void) fprintf(stdout, "\t%d%s\t/* %3d: %s%s*/\n", tval,
			    comma, fval, msg, t);
		}
	}

	(void) nvlist_free(native_errors);
	(void) nvlist_free(foreign_errors);

	return (0);
}
