/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2002 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Dieter Baron and Thomas Klausner.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *	contributors may be used to endorse or promote products derived
 *	from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _getopt_clip = getopt_clip
#pragma weak _getopt_long = getopt_long
#pragma weak _getopt_long_only = getopt_long_only

#include "lint.h"
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "_libc_gettext.h"

static int optreset = 0;	/* keep track of first entry to getopt() */
#define	PRINT_ERROR	((opterr) && (*options != ':'))
#define	FLAG_IS_SET(flag) 	((flags & flag) != 0)	/* is flag turned on? */

/* Determine if an argument is required for this long option */
#define	LONGOPT_REQUIRES_ARG(longopt) \
		((((longopt).has_arg == optional_argument) && \
			(!FLAG_IS_SET(FLAG_OPTIONAL_ARGS))) || \
			((longopt).has_arg == required_argument))

#define	FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define	FLAG_ALLARGS	0x02	/* treat non-options as args to option "1" */
#define	FLAG_LONGONLY	0x04	/* operate as getopt_long_only() */
#define	FLAG_OPTIONAL_ARGS 0x08	/* allow optional arguments to options */
#define	FLAG_REQUIRE_EQUIVALENTS 0x10 /* require short<->long equivalents */
#define	FLAG_ABBREV	0x20 	/* long option abbreviation allowed. */
#define	FLAG_W_SEMICOLON 0x40 	/* Support for W; in optstring */
#define	FLAG_PLUS_DASH_START 0x80	/* leading '+' or '-' in optstring */

/* return values */
#define	BADCH		(int)'?'
#define	BADARG		((*options == ':') ? (int)':' : (int)'?')
#define	INORDER 	(int)1

#define	EMSG		""

static int getopt_internal(int, char * const *, const char *,
				const struct option *, int *, uint_t);
static int parse_long_options(int nargc, char * const *nargv, const char *,
				const struct option *, int *, int,
				uint_t flags);
static int gcd(int, int);
static void permute_args(int, int, int, char * const *);

static char *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
static int nonopt_start = -1; /* first non option argument (for permute) */
static int nonopt_end = -1;   /* first option after non options (for permute) */

/*
 * Generalized error message output.
 *
 * NOTE ON ERROR MESSAGES: All the error messages in this file
 * use %s (not %c) because they are all routed through warnx_getopt(),
 * which takes a string argument. Character arguments passed
 * to warnxchar() are converted to strings automatically before
 * being passed to warnx_getopt().
 */
static void
warnx_getopt(const char *argv0, const char *msg, const char *arg) {
	char errbuf[256];
	(void) snprintf(errbuf, sizeof (errbuf), msg, argv0, arg);
	(void) write(2, errbuf, strlen(errbuf));
	(void) write(2, "\n", 1);
}

/*
 * Generalized error message output.
 */
static void
warnxchar(const char *argv0, const char *msg, const char c) {
	char charbuf[2];
	charbuf[0] = c;
	charbuf[1] = '\0';
	warnx_getopt(argv0, msg, charbuf);
}

/*
 * Generalized error message output.
 */
static void
warnxlen(const char *argv0, const char *msg, int argLen, const char *arg) {
	char argbuf[256];
	(void) strncpy(argbuf, arg, argLen);
	argbuf[argLen < (sizeof (argbuf)-1)? argLen:(sizeof (argbuf)-1)] = '\0';
	warnx_getopt(argv0, msg, argbuf);
}

/*
 * Compute the greatest common divisor of a and b.
 */
static int
gcd(int a, int b)
{
	int c;

	c = a % b;
	while (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	return (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
static void
permute_args(int panonopt_start, int panonopt_end, int opt_end,
	char * const *nargv)
{
	int cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	char *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	for (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		for (j = 0; j < cyclelen; j++) {
			if (pos >= panonopt_end)
				pos -= nnonopts;
			else
				pos += nopts;
			swap = nargv[pos];
			((char **)nargv)[pos] = nargv[cstart];
			((char **)nargv)[cstart] = swap;
		}
	}
} /* permute_args() */

/*
 * Verify that each short option (character flag) has a long equivalent,
 * and that each long option has a short option equivalent. Note that
 * multiple long options can map to the same character.
 *
 * This behavior is defined by Sun's CLIP specification (11/12/02),
 * and currently getopt_clip() is the only getopt variant that
 * requires it.
 *
 * If error output is enabled and an error is found, this function
 * prints ONE error message (the first error found) and returns an
 * error value.
 *
 * ASSUMES: options != NULL
 * ASSUMES: long_options may be NULL
 *
 * Returns < 0 if an error is found
 * Returns >= 0 on success
 */
static int
/* LINTED: argument unused in function: nargc */
verify_short_long_equivalents(int nargc,
				char *const *nargv,
				const char *options,
				const struct option *long_options,
				uint_t flags) {
	int short_i = 0;
	int long_i = 0;
	int equivFound = 0;
	int ch = 0;

	/*
	 * Find a long option for each short option
	 */
	equivFound = 1;
	for (short_i = 0; equivFound && (options[short_i] != 0); ++short_i) {
		ch = options[short_i];

		if (ch == ':') {
			continue;
		}
		if (FLAG_IS_SET(FLAG_W_SEMICOLON) &&
			(ch == 'W') && (options[short_i+1] == ';')) {
			/* W; is a special case */
			++short_i;
			continue;
		}

		equivFound = 0;
		if (long_options != NULL) {
			for (long_i = 0; ((!equivFound) &&
					(long_options[long_i].name != NULL));
								++long_i) {
				equivFound = (ch == long_options[long_i].val);
			}
		}
		if ((!equivFound) && (PRINT_ERROR)) {
			warnxchar(nargv[0],
				_libc_gettext(
				"%s: equivalent long option required -- %s"),
				ch);
		}
	} /* short_i */

	/*
	 * Find a short option for each long option. Note that if we came
	 * out of the above loop with equivFound==0, we are already done.
	 */
	if (equivFound && (long_options != NULL)) {
		for (long_i = 0; (equivFound &&
				(long_options[long_i].name != NULL));
								++long_i) {
			equivFound = ((long_options[long_i].val != 0) &&
				(strchr(options, long_options[long_i].val)
								!= NULL));

			if ((!equivFound) && (PRINT_ERROR)) {
				warnx_getopt(nargv[0],
					_libc_gettext(
				"%s: equivalent short option required -- %s"),
					long_options[long_i].name);
			}
		} /* for long_i */
	}

	return (equivFound? 0:-1);
} /* verify_short_long_equivalents() */

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
static int
parse_long_options(int nargc, char * const *nargv, const char *options,
	const struct option *long_options, int *idx, int short_too,
	uint_t flags)
{
	char *current_argv = NULL;
	char *argv_equal_ptr = NULL;
	size_t current_argv_len = 0;
	size_t long_option_len = 0;
	int i = 0;
	int match = 0;

	current_argv = place;
	match = -1;

	optind++;

	if ((argv_equal_ptr = strchr(current_argv, '=')) != NULL) {
		/* argument found (--option=arg) */
		current_argv_len = (argv_equal_ptr - current_argv);
		argv_equal_ptr++;
	} else {
		current_argv_len = strlen(current_argv);
	}

	for (i = 0; (long_options[i].name != NULL); i++) {

		/* find matching long option */
		if (strncmp(current_argv, long_options[i].name,
		    current_argv_len) != 0) {
			continue;	/* no match  */
		}
		long_option_len = strlen(long_options[i].name);
		if ((!FLAG_IS_SET(FLAG_ABBREV)) &&
		    (long_option_len > current_argv_len)) {
			continue;	/* Abbreviations are disabled */
		}

		if (long_option_len == current_argv_len) {
			/* exact match */
			match = i;
			break;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		if (short_too && current_argv_len == 1)
			continue;

		if (match == -1)	/* partial match */
			match = i;
		else {
			/* ambiguous abbreviation */
			if (PRINT_ERROR) {
				warnxlen(nargv[0],
				    _libc_gettext(
				    "%s: ambiguous option -- %s"),
				    (int)current_argv_len,
				    current_argv);
			}
			optopt = 0;
			return (BADCH);
		}
	} /* for i */
	if (match != -1) {		/* option found */
		if ((long_options[match].has_arg == no_argument) &&
		    (argv_equal_ptr != NULL)) {
			if (PRINT_ERROR) {
				warnxlen(nargv[0],
				    _libc_gettext(
				"%s: option doesn't take an argument -- %s"),
				    (int)current_argv_len,
				    current_argv);
			}
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			if (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			else
				optopt = 0;
			return (BADARG);
		}
		if (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			if (argv_equal_ptr != NULL) {
				optarg = argv_equal_ptr;
			} else if (LONGOPT_REQUIRES_ARG(long_options[match])) {
				/* The next argv must be the option argument */
				if (optind < nargc) {
					optarg = nargv[optind];
				}
				++optind; /* code below depends on this */
			}
		}
		if (LONGOPT_REQUIRES_ARG(long_options[match]) &&
		    (optarg == NULL)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			if (PRINT_ERROR) {
				warnx_getopt(nargv[0],
				    _libc_gettext(
				"%s: option requires an argument -- %s"),
				    current_argv);
			}
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			if (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			else
				optopt = 0;
			--optind;
			return (BADARG);
		}
	} else {			/* unknown option */
		if (short_too) {
			--optind;
			return (-1);
		}
		if (PRINT_ERROR) {
			warnx_getopt(nargv[0],
			    _libc_gettext("%s: illegal option -- %s"),
			    current_argv);
		}
		optopt = 0;
		return (BADCH);
	}
	if (idx)
		*idx = match;
	if (long_options[match].flag != NULL) {
		*long_options[match].flag = long_options[match].val;
		return (0);
	} else {
		optopt = long_options[match].val;
		return (optopt);
	}
} /* parse_long_options() */

/*
 * getopt_internal() --
 *	Parse argc/argv argument vector.  Called by user level routines.
 *
 * This implements all of the getopt_long(), getopt_long_only(),
 * getopt_clip() variants.
 */
static int
getopt_internal(int nargc, char * const *nargv, const char *options,
	const struct option *long_options, int *idx, uint_t flags)
{
	char *oli;				/* option letter list index */
	int optchar, short_too;
	static int posixly_correct = -1;

	if (options == NULL)
		return (-1);

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	if (posixly_correct == -1) {
		posixly_correct = (getenv("POSIXLY_CORRECT") != NULL);
	}
	if (FLAG_IS_SET(FLAG_PLUS_DASH_START)) {
		/*
		 * + or - at start of optstring takes precedence
		 * over POSIXLY_CORRECT.
		 */
		if (*options == '+') {
			/*
			 * leading + means POSIX-compliant; first non-option
			 * ends option list. Therefore, don't permute args.
			 */
			posixly_correct = 1;
		} else if (*options == '-') {
			posixly_correct = 0;
			flags |= FLAG_ALLARGS;
		}
		if ((*options == '+') || (*options == '-')) {
			options++;
		}
	} /* if FLAG_PLUS_DASH_START */

	if (posixly_correct) {
		flags &= ~FLAG_PERMUTE;
		flags &= ~FLAG_ALLARGS;
		flags &= ~FLAG_OPTIONAL_ARGS;
	}

	/*
	 * Some programs (like GNU cvs) set optind to 0 to restart
	 * option processing. Work around this braindamage.
	 *
	 * The above problem comes from using global variables. We
	 * should avoid their use in the future.
	 */
	if (optind == 0) {
		optind = optreset = 1;
	}

	optarg = NULL;
	optopt = 0;

	if (optreset) {
		nonopt_start = nonopt_end = -1;
	}

	/*
	 * On the first call, make sure that there is a short equivalent
	 * for each long option, and vice versa. This is required by
	 * Sun's CLIP specification (11/12/02).
	 */
	if ((optind == 1) && FLAG_IS_SET(FLAG_REQUIRE_EQUIVALENTS)) {
		if (verify_short_long_equivalents(
		    nargc, nargv, options, long_options, flags) < 0) {
			/* function printed any necessary messages */
			errno = EINVAL;		/* invalid argument */
			return (-1);
		}
	}

start:
	if (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		if (optind >= nargc) {		/* end of argument vector */
			place = EMSG;
			if (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;

			} else if (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			return (-1);
		}
		if ((*(place = nargv[optind]) != '-') || (place[1] == '\0')) {
			place = EMSG;		/* found non-option */
			if (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option '\1'
				 */
				optarg = nargv[optind++];
				return (INORDER);
			}
			if (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				return (-1);
			}
			/* do permutation */
			if (nonopt_start == -1)
				nonopt_start = optind;
			else if (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			goto start;
		}
		if (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * Check for "--" or "--foo" with no long options
		 * but if place is simply "-" leave it unmolested.
		 */
		if (place[1] != '\0' && *++place == '-' &&
		    (place[1] == '\0' || long_options == NULL)) {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			if (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			return (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- or we are getopt_long_only()
	 */
	if (long_options != NULL && place != nargv[optind] &&
	    (*place == '-' || (FLAG_IS_SET(FLAG_LONGONLY)))) {
		short_too = 0;
		if (*place == '-')
			place++;		/* --foo long option */
		else if (*place != ':' && strchr(options, *place) != NULL)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargc, nargv, options,
		    long_options, idx, short_too, flags);
		if (optchar != -1) {
			place = EMSG;
			return (optchar);
		}
	}

	if ((optchar = (int)*place++) == (int)':' ||
	    (oli = strchr(options, optchar)) == NULL) {
		/*
		 * If the user didn't specify '-' as an option,
		 * assume it means -1 as POSIX specifies.
		 */
		if (optchar == (int)'-')
			return (-1);
		/* option letter unknown or ':' */
		if (!*place)
			++optind;
		if (PRINT_ERROR)
			warnxchar(nargv[0],
			    _libc_gettext("%s: illegal option -- %s"),
			    optchar);
		optopt = optchar;
		return (BADCH);
	}
	if (FLAG_IS_SET(FLAG_W_SEMICOLON) &&
	    (long_options != NULL) && (optchar == 'W') && (oli[1] == ';')) {
		/* -W long-option */
		/* LINTED: statement has no consequent: if */
		if (*place) {			/* no space */
			/* NOTHING */;
		} else if (++optind >= nargc) {	/* no long-option after -W */
			place = EMSG;
			if (PRINT_ERROR)
				warnxchar(nargv[0],
				    _libc_gettext(
				"%s: option requires an argument -- %s"),
				    optchar);
			optopt = optchar;
			return (BADARG);
		} else {			/* white space */
			place = nargv[optind];
		}
		optchar = parse_long_options(
		    nargc, nargv, options, long_options,
		    idx, 0, flags);

		/*
		 * PSARC 2003/645 - Match GNU behavior, set optarg to
		 * the long-option.
		 */
		if (optarg == NULL) {
			optarg = nargv[optind-1];
		}
		place = EMSG;
		return (optchar);
	}
	if (*++oli != ':') {			/* doesn't take argument */
		if (!*place)
			++optind;
	} else {				/* takes (optional) argument */
		optarg = NULL;
		if (*place) {			/* no white space */
			optarg = place;
		/* XXX: disable test for :: if PC? (GNU doesn't) */
		} else if (!(FLAG_IS_SET(FLAG_OPTIONAL_ARGS) &&
		    (oli[1] == ':'))) {
			/* arg is required (not optional) */

			if (++optind >= nargc) {	/* no arg */
				place = EMSG;
				if (PRINT_ERROR) {
					warnxchar(nargv[0],
					    _libc_gettext(
				"%s: option requires an argument -- %s"),
					    optchar);
				}
				optopt = optchar;
				return (BADARG);
			} else
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* return valid option letter */
	optopt = optchar;		/* preserve getopt() behavior */
	return (optchar);
} /* getopt_internal() */

/*
 * getopt_long() --
 *	Parse argc/argv argument vector.
 *
 * Requires that long options be preceded with a two dashes
 * (e.g., --longoption).
 */
int
getopt_long(int nargc, char *const *nargv,
		const char *optstring,
		const struct option *long_options, int *long_index)
{

	return (getopt_internal(
	    nargc, nargv, optstring, long_options, long_index,
	    FLAG_PERMUTE
	    | FLAG_OPTIONAL_ARGS
	    | FLAG_ABBREV
	    | FLAG_W_SEMICOLON
	    | FLAG_PLUS_DASH_START));
} /* getopt_long() */

/*
 * getopt_long_only() --
 *	Parse argc/argv argument vector.
 *
 * Long options may be preceded with a single dash (e.g., -longoption)
 */
int
getopt_long_only(int nargc, char *const *nargv,
		const char *optstring,
		const struct option *long_options, int *long_index)
{

	return (getopt_internal(
	    nargc, nargv, optstring, long_options, long_index,
	    FLAG_PERMUTE
	    | FLAG_OPTIONAL_ARGS
	    | FLAG_ABBREV
	    | FLAG_W_SEMICOLON
	    | FLAG_PLUS_DASH_START
	    | FLAG_LONGONLY));
} /* getopt_long_only() */

/*
 * getopt_clip() --
 *	Parse argc/argv argument vector, requiring compliance with
 * 	Sun's CLIP specification (11/12/02)
 *
 * o Does not allow arguments to be optional (optional_argument is
 *   treated as required_argument).
 *
 * o Does not allow long options to be abbreviated on the command line
 *
 * o Does not allow long argument to be preceded by a single dash
 *   (Double-dash '--' is required)
 *
 * o Stops option processing at the first non-option
 *
 * o Requires that every long option have a short-option (single
 *   character) equivalent and vice-versa. If a short option or
 *   long option without an equivalent is found, an error message
 *   is printed and -1 is returned on the first call, and errno
 *   is set to EINVAL.
 *
 * o Leading + or - in optstring is ignored, and opstring is
 *   treated as if it began after the + or - .
 */
int
getopt_clip(int nargc, char *const *nargv,
		const char *optstring,
		const struct option *long_options, int *long_index)
{
	return getopt_internal(
	    nargc, nargv, optstring, long_options, long_index,
		/*
		 * no permutation,
		 * no optional args,
		 * no long-only,
		 * no abbreviations
		 * no support for +- at start of optstring
		 * yes support for "W;" in optstring
		 */
	    FLAG_W_SEMICOLON
	    | FLAG_REQUIRE_EQUIVALENTS);
} /* getopt_clip() */
