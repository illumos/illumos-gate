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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2025 Oxide Computer Company
 */

#include <mdb/mdb_types.h>
#include <mdb/mdb_argvec.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_stdlib.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb.h>

#include <alloca.h>

#define	AV_DEFSZ	16	/* Initial size of argument vector */
#define	AV_GROW		2	/* Multiplier for growing argument vector */

void
mdb_argvec_create(mdb_argvec_t *vec)
{
	vec->a_data = NULL;
	vec->a_nelems = 0;
	vec->a_size = 0;
}

void
mdb_argvec_destroy(mdb_argvec_t *vec)
{
	if (vec->a_data != NULL) {
		mdb_argvec_reset(vec);
		mdb_free(vec->a_data, sizeof (mdb_arg_t) * vec->a_size);
	}
}

void
mdb_argvec_append(mdb_argvec_t *vec, const mdb_arg_t *arg)
{
	if (vec->a_nelems >= vec->a_size) {
		size_t size = vec->a_size ? vec->a_size * AV_GROW : AV_DEFSZ;
		void *data = mdb_alloc(sizeof (mdb_arg_t) * size, UM_NOSLEEP);

		if (data == NULL) {
			warn("failed to grow argument vector");
			longjmp(mdb.m_frame->f_pcb, MDB_ERR_NOMEM);
		}

		bcopy(vec->a_data, data, sizeof (mdb_arg_t) * vec->a_size);
		mdb_free(vec->a_data, sizeof (mdb_arg_t) * vec->a_size);

		vec->a_data = data;
		vec->a_size = size;
	}

	bcopy(arg, &vec->a_data[vec->a_nelems++], sizeof (mdb_arg_t));
}

void
mdb_argvec_reset(mdb_argvec_t *vec)
{
	size_t nelems = vec->a_nelems;
	mdb_arg_t *arg;

	for (arg = vec->a_data; nelems != 0; nelems--, arg++) {
		if (arg->a_type == MDB_TYPE_STRING && arg->a_un.a_str != NULL)
			strfree((char *)arg->a_un.a_str);
	}

	vec->a_nelems = 0;
}

void
mdb_argvec_zero(mdb_argvec_t *vec)
{
#ifdef DEBUG
	size_t i;

	for (i = 0; i < vec->a_size; i++) {
		vec->a_data[i].a_type = UMEM_UNINITIALIZED_PATTERN;
		vec->a_data[i].a_un.a_val =
		    ((u_longlong_t)UMEM_UNINITIALIZED_PATTERN << 32) |
		    ((u_longlong_t)UMEM_UNINITIALIZED_PATTERN);
	}
#endif
	vec->a_nelems = 0;
}

void
mdb_argvec_copy(mdb_argvec_t *dst, const mdb_argvec_t *src)
{
	if (src->a_nelems > dst->a_size) {
		mdb_arg_t *data =
		    mdb_alloc(sizeof (mdb_arg_t) * src->a_nelems, UM_NOSLEEP);

		if (data == NULL) {
			warn("failed to grow argument vector");
			longjmp(mdb.m_frame->f_pcb, MDB_ERR_NOMEM);
		}

		if (dst->a_data != NULL)
			mdb_free(dst->a_data, sizeof (mdb_arg_t) * dst->a_size);

		dst->a_data = data;
		dst->a_size = src->a_nelems;
	}

	bcopy(src->a_data, dst->a_data, sizeof (mdb_arg_t) * src->a_nelems);
	dst->a_nelems = src->a_nelems;
}

static int
argvec_process_subopt(const mdb_opt_t *opt, const mdb_arg_t *arg)
{
	mdb_subopt_t *sop;
	const char *start;
	const char *next;
	char error[32];
	size_t len;
	uint_t value = 0;
	uint_t i;

	start = arg->a_un.a_str;

	for (i = 0; ; i++) {
		next = strchr(start, ',');

		if (next == NULL)
			len = strlen(start);
		else
			len = next - start;

		/*
		 * Record the index of the subopt if a match if found.
		 */
		for (sop = opt->opt_subopts; sop->sop_flag; sop++) {
			if (strlen(sop->sop_str) == len &&
			    strncmp(sop->sop_str, start, len) == 0) {
				value |= sop->sop_flag;
				sop->sop_index = i;
				goto found;
			}
		}
		(void) mdb_snprintf(error, len + 1, "%s", start);
		warn("invalid option for -%c: \"%s\"\n", opt->opt_char, error);

		return (-1);

found:
		if (next == NULL)
			break;
		start = next + 1;
	}

	*((uint_t *)opt->opt_valp) = value;

	return (0);
}


static int
argvec_process_opt(const mdb_opt_t *opt, const mdb_arg_t *arg)
{
	uint64_t ui64;
	uintptr_t uip;

	switch (opt->opt_type) {
	case MDB_OPT_SETBITS:
		*((uint_t *)opt->opt_valp) |= opt->opt_bits;
		break;

	case MDB_OPT_CLRBITS:
		*((uint_t *)opt->opt_valp) &= ~opt->opt_bits;
		break;

	case MDB_OPT_STR:
		if (arg->a_type != MDB_TYPE_STRING) {
			warn("string argument required for -%c\n",
			    opt->opt_char);
			return (-1);
		}
		*((const char **)opt->opt_valp) = arg->a_un.a_str;
		break;

	case MDB_OPT_UINTPTR_SET:
		*opt->opt_flag = TRUE;
		/* FALLTHROUGH */
	case MDB_OPT_UINTPTR:
		uip = (uintptr_t)mdb_argtoull(arg);
		*((uintptr_t *)opt->opt_valp) = uip;
		break;

	case MDB_OPT_UINT64:
		ui64 = (uint64_t)mdb_argtoull(arg);
		*((uint64_t *)opt->opt_valp) = ui64;
		break;

	case MDB_OPT_SUBOPTS:
		if (arg->a_type != MDB_TYPE_STRING) {
			warn("string argument required for -%c\n",
			    opt->opt_char);
			return (-1);
		}
		return (argvec_process_subopt(opt, arg));

	default:
		warn("internal: bad opt=%p type=%hx\n",
		    (void *)opt, opt->opt_type);
		return (-1);
	}

	return (0);
}

static const mdb_opt_t *
argvec_findopt(const mdb_opt_t *opts, char c)
{
	const mdb_opt_t *optp;

	for (optp = opts; optp->opt_char != 0; optp++) {
		if (optp->opt_char == c)
			return (optp);
	}

	return (NULL);
}

static int
argvec_getopts(const mdb_opt_t *opts, const mdb_arg_t *argv, int argc)
{
	const mdb_opt_t *optp;
	const mdb_arg_t *argp;

	mdb_arg_t arg;

	const char *p;
	int i;
	int nargs;	/* Number of arguments consumed in an iteration */

	for (i = 0; i < argc; i++, argv++) {
		/*
		 * Each option must begin with a string argument whose first
		 * character is '-' and has additional characters afterward.
		 */
		if (argv->a_type != MDB_TYPE_STRING ||
		    argv->a_un.a_str[0] != '-' || argv->a_un.a_str[1] == '\0')
			return (i);

		/*
		 * The special prefix '--' ends option processing.
		 */
		if (strncmp(argv->a_un.a_str, "--", 2) == 0)
			return (i);

		for (p = &argv->a_un.a_str[1]; *p != '\0'; p++) {
			/*
			 * Locate an option struct whose opt_char field
			 * matches the current option letter.
			 */
			if ((optp = argvec_findopt(opts, *p)) == NULL) {
				warn("illegal option -- %c\n", *p);
				return (i);
			}

			/*
			 * Require an argument for strings, immediate
			 * values, subopt-lists and callback functions
			 * which require arguments.
			 */
			if (optp->opt_type == MDB_OPT_STR ||
			    optp->opt_type == MDB_OPT_UINTPTR ||
			    optp->opt_type == MDB_OPT_UINTPTR_SET ||
			    optp->opt_type == MDB_OPT_SUBOPTS ||
			    optp->opt_type == MDB_OPT_UINT64) {
				/*
				 * More text after the option letter:
				 * forge a string argument from remainder.
				 */
				if (p[1] != '\0') {
					arg.a_type = MDB_TYPE_STRING;
					arg.a_un.a_str = ++p;
					argp = &arg;
					p += strlen(p) - 1;

					nargs = 0;
				/*
				 * Otherwise use the next argv element as
				 * the argument if there is one.
				 */
				} else if (++i == argc) {
					warn("option requires an "
					    "argument -- %c\n", *p);
					return (i - 1);
				} else {
					argp = ++argv;
					nargs = 1;
				}
			} else {
				argp = NULL;
				nargs = 0;
			}

			/*
			 * Perform type-specific handling for this option.
			 */
			if (argvec_process_opt(optp, argp) == -1)
				return (i - nargs);
		}
	}

	return (i);
}

int
mdb_getopts(int argc, const mdb_arg_t *argv, ...)
{
	/*
	 * For simplicity just declare enough options on the stack to handle
	 * a-z and A-Z and an extra terminator.
	 */
	mdb_opt_t opts[53], *op = &opts[0];
	va_list alist;
	int c, i = 0;
	mdb_subopt_t *sop;

	va_start(alist, argv);

	for (i = 0; i < (sizeof (opts) / sizeof (opts[0]) - 1); i++, op++) {
		if ((c = va_arg(alist, int)) == 0)
			break; /* end of options */

		op->opt_char = (char)c;
		op->opt_type = va_arg(alist, uint_t);

		if (op->opt_type == MDB_OPT_SETBITS ||
		    op->opt_type == MDB_OPT_CLRBITS) {
			op->opt_bits = va_arg(alist, uint_t);
		} else if (op->opt_type == MDB_OPT_UINTPTR_SET) {
			op->opt_flag = va_arg(alist, boolean_t *);
		} else if (op->opt_type == MDB_OPT_SUBOPTS) {
			op->opt_subopts = va_arg(alist, mdb_subopt_t *);

			for (sop = op->opt_subopts; sop->sop_flag; sop++)
				sop->sop_index = -1;
		}

		op->opt_valp = va_arg(alist, void *);
	}

	bzero(&opts[i], sizeof (mdb_opt_t));
	va_end(alist);

	return (argvec_getopts(opts, argv, argc));
}

u_longlong_t
mdb_argtoull(const mdb_arg_t *arg)
{
	switch (arg->a_type) {
	case MDB_TYPE_STRING:
		return (mdb_strtoull(arg->a_un.a_str));
	case MDB_TYPE_IMMEDIATE:
		return (arg->a_un.a_val);
	case MDB_TYPE_CHAR:
		return (arg->a_un.a_char);
	}
	/* NOTREACHED */
	return (0);
}

/*
 * The old adb breakpoint and watchpoint routines did not accept any arguments;
 * all characters after the verb were concatenated to form the string callback.
 * This utility function concatenates all arguments in argv[] into a single
 * string to simplify the implementation of these legacy routines.
 */
char *
mdb_argv_to_str(int argc, const mdb_arg_t *argv)
{
	char *s = NULL;
	size_t n = 0;
	int i;

	for (i = 0; i < argc; i++) {
		if (argv[i].a_type == MDB_TYPE_STRING)
			n += strlen(argv[i].a_un.a_str);
	}

	if (n != 0) {
		s = mdb_zalloc(n + argc, UM_SLEEP);

		for (i = 0; i < argc - 1; i++, argv++) {
			(void) strcat(s, argv->a_un.a_str);
			(void) strcat(s, " ");
		}

		(void) strcat(s, argv->a_un.a_str);
	}

	return (s);
}
