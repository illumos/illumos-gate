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
 * Print the current working directory of an arbitrary process or core file.
 * While this uses libproc, it always does this read only, which is in the
 * spirit of the original pwdx that just read from /proc directly and didn't
 * support additional options.
 */

#include <err.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stdbool.h>
#include <libproc.h>
#include <locale.h>
#include <stdio.h>
#include <wchar.h>

#define	EXIT_USAGE	2

typedef enum {
	PWDX_CWD	= 1 << 0,
	PWDX_MOUNT	= 1 << 1,
	PWDX_REST	= 1 << 2,
	PWDX_QUIET	= 1 << 3
} pwdx_output_t;

static void
pwdx_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  pwdx [-m] [-q | -v] { pid | core } "
	    "...\n");
	(void) fprintf(stderr, "Print process and core current working "
	    "directory\n"
	    "\t-m\t\tshow mountpoint path\n"
	    "\t-q\t\tonly output paths\n"
	    "\t-v\t\toutput verbose mount information\n");
}

static void
pwdx_escape(char c)
{
	(void) printf("\\%c%c%c", '0' + ((c >> 6) & 07), '0' + ((c >> 3) & 07),
	    '0' + (c & 07));
}

/*
 * We have a string that represents a path which is really an arbitrary byte
 * string. It may or may not be safe for the user to actually interpret if
 * we send it to a shell. So we go through and break this into multi-byte
 * characters and if they are printable, print them. If they are not, then we
 * write an escape sequence out byte by byte. We use the octal escape sequence,
 * not because we like it, but because that's consistent with pargs, ls, etc.
 */
static void
pwdx_puts(const char *str, bool newline)
{
	size_t slen = strlen(str), off = 0;

	while (off < slen) {
		wchar_t wc;
		int ret = mbtowc(&wc, str + off, slen - off);

		if (ret < 0) {
			pwdx_escape(str[off]);
			off++;
			continue;
		} else if (ret == 0) {
			break;
		}

		if (iswprint(wc)) {
			(void) putwchar(wc);
		} else {
			for (int i = 0; i < ret; i++) {
				pwdx_escape(str[off + i]);
			}
		}

		off += ret;
	}

	if (newline) {
		(void) putchar('\n');
	}
}

static bool
pwdx(const char *str, pwdx_output_t output)
{
	int err;
	bool ret = false;
	struct ps_prochandle *P;
	prcwd_t *cwd = NULL;
	const psinfo_t *info;

	P = proc_arg_grab(str, PR_ARG_ANY, PGRAB_RDONLY, &err);
	if (P == NULL) {
		warnx("failed to open %s: %s", str, Pgrab_error(err));
		return (false);
	}

	info = Ppsinfo(P);
	if (info == NULL) {
		warn("failed to get psinfo from %s", str);
		goto out;
	}

	if (Pcwd(P, &cwd) != 0) {
		warn("failed to read cwd of %s", str);
		goto out;
	}

	if ((output & PWDX_QUIET) == 0) {
		if (Pstate(P) == PS_DEAD) {
			(void) printf("core '%s' of ", str);
		}
		(void) printf("%" _PRIdID ":\t", info->pr_pid);
	}

	if ((output & PWDX_CWD) != 0) {
		pwdx_puts(cwd->prcwd_cwd, true);
	} else {
		if (cwd->prcwd_mntpt[0] != '\0') {
			pwdx_puts(cwd->prcwd_mntpt, true);
		} else {
			(void) puts("<unknown>");
		}
	}

	if (output & PWDX_REST) {
		const char *spec, *point;

		if (cwd->prcwd_mntspec[0] == '\0') {
			spec = "unknown";
		} else {
			spec = cwd->prcwd_mntspec;
		}

		if (cwd->prcwd_mntpt[0] == '\0') {
			point = "unknown";
		} else {
			point = cwd->prcwd_mntpt;
		}

		(void) printf("\tMountpoint ");
		pwdx_puts(point, false);
		(void) printf(" on ");
		pwdx_puts(spec, true);
		(void) printf("\tFilesystem %s (ID: 0x%" PRIx64 ")\n",
		    cwd->prcwd_fsname, cwd->prcwd_fsid);
	}

	ret = true;

out:
	Pcwd_free(cwd);
	Pfree(P);
	return (ret);
}

int
main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;
	pwdx_output_t output = PWDX_CWD;
	int c;

	(void) setlocale(LC_ALL, "");

	while ((c = getopt(argc, argv, ":mqv")) != -1) {
		switch (c) {
		case 'm':
			output |= PWDX_MOUNT;
			output &= ~PWDX_CWD;
			break;
		case 'q':
			if (output & PWDX_REST) {
				errx(EXIT_USAGE, "only one of -q and -v may be "
				    "specified");
			}
			output |= PWDX_QUIET;
			break;
		case 'v':
			if (output & PWDX_QUIET) {
				errx(EXIT_USAGE, "only one of -q and -v may be "
				    "specified");
			}
			output |= PWDX_CWD | PWDX_MOUNT | PWDX_REST;
			break;
		case ':':
			pwdx_usage("option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
			pwdx_usage("unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		errx(EXIT_FAILURE, "at least one process must be specified");
	}

	for (int i = 0; i < argc; i++) {
		if (!pwdx(argv[i], output))
			ret = EXIT_FAILURE;
	}

	return (ret);
}
