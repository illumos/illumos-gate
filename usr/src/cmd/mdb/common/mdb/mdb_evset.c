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
 */

#include <mdb/mdb_target.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb.h>

#include <libproc.h>
#include <string.h>

/*ARGSUSED*/
void
cmd_event(mdb_tgt_t *t, int vid, void *s)
{
	if (s != NULL && mdb_eval(s) == -1)
		mdb_warn("failed to eval [ %d ] command \"%s\"", vid, s);
}

int
cmd_evset(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t setb = 0, clrb = 0;
	const char *opt_c = NULL;
	uint_t opt_F = FALSE;
	uintptr_t opt_n = 0;

	int *idv = mdb_zalloc(sizeof (int) * (argc + 1), UM_SLEEP | UM_GC);
	int idc = 0;

	int status = DCMD_OK;
	const char *p;
	void *data;
	int argi;

	if (flags & DCMD_ADDRSPEC)
		idv[idc++] = (int)(intptr_t)addr;

	/*
	 * Perform an initial pass through argv: we accumulate integer ids into
	 * idv, and compute a group of bits to set and a group to clear.
	 */
	while (argc != 0 && (argi = mdb_getopts(argc, argv,
	    'c', MDB_OPT_STR, &opt_c,
	    'd', MDB_OPT_SETBITS, MDB_TGT_SPEC_AUTODIS, &setb,
	    'D', MDB_OPT_SETBITS, MDB_TGT_SPEC_AUTODEL, &setb,
	    'e', MDB_OPT_SETBITS, MDB_TGT_SPEC_DISABLED, &clrb,
	    'F', MDB_OPT_SETBITS, TRUE, &opt_F,
	    'n', MDB_OPT_UINTPTR, &opt_n,
	    's', MDB_OPT_SETBITS, MDB_TGT_SPEC_AUTOSTOP, &setb,
	    't', MDB_OPT_SETBITS, MDB_TGT_SPEC_TEMPORARY, &setb,
	    'T', MDB_OPT_SETBITS, MDB_TGT_SPEC_STICKY, &setb,
	    NULL)) != argc) {

		argv += argi; /* advance past elements processed by getopts */
		argc -= argi; /* decrement argc by number of args processed */

		if (argv->a_type == MDB_TYPE_STRING) {
			if (argv->a_un.a_str[0] == '+') {
				for (p = argv->a_un.a_str + 1; *p != '\0'; ) {
					switch (*p++) {
					case 'd':
						clrb |= MDB_TGT_SPEC_AUTODIS;
						break;
					case 'D':
						clrb |= MDB_TGT_SPEC_AUTODEL;
						break;
					case 'e':
						setb |= MDB_TGT_SPEC_DISABLED;
						break;
					case 's':
						clrb |= MDB_TGT_SPEC_AUTOSTOP;
						break;
					case 't':
						clrb |= MDB_TGT_SPEC_TEMPORARY;
						break;
					case 'T':
						clrb |= MDB_TGT_SPEC_STICKY;
						break;
					default:
						mdb_warn("illegal option -- "
						    "+%c\n", p[-1]);
						return (DCMD_USAGE);
					}
				}
			} else if (argv->a_un.a_str[0] != '-') {
				idv[idc++] = (int)(intmax_t)
				    mdb_strtonum(argv->a_un.a_str, 10);
			} else
				return (DCMD_USAGE);
		} else
			idv[idc++] = (int)(intmax_t)argv->a_un.a_val;

		argc--;
		argv++;
	}

	if (idc == 0) {
		mdb_warn("expected one or more event IDs to be specified\n");
		return (DCMD_USAGE);
	}

	/*
	 * If -n was not specified, then -d means "disable now" instead of
	 * meaning "set auto-disable after n hits".
	 */
	if (opt_n == 0 && (setb & MDB_TGT_SPEC_AUTODIS))
		setb = (setb & ~MDB_TGT_SPEC_AUTODIS) | MDB_TGT_SPEC_DISABLED;

	while (idc-- != 0) {
		mdb_tgt_spec_desc_t sp;
		int id = *idv++;

		bzero(&sp, sizeof (mdb_tgt_spec_desc_t));
		(void) mdb_tgt_vespec_info(mdb.m_target, id, &sp, NULL, 0);
		data = sp.spec_data;

		if (opt_F == FALSE && (sp.spec_flags & MDB_TGT_SPEC_HIDDEN)) {
			mdb_warn("cannot modify event %d: internal "
			    "debugger event\n", id);
			status = DCMD_ERR;
			continue;
		}

		sp.spec_flags |= setb;
		sp.spec_flags &= ~clrb;

		if (opt_c && !(sp.spec_flags & MDB_TGT_SPEC_HIDDEN)) {
			if (opt_c[0] != '\0')
				sp.spec_data = strdup(opt_c);
			else
				sp.spec_data = NULL;
		}

		if (opt_n)
			sp.spec_limit = opt_n;

		if (mdb_tgt_vespec_modify(mdb.m_target, id, sp.spec_flags,
		    sp.spec_limit, sp.spec_data) == -1) {
			mdb_warn("failed to modify event %d", id);
			data = sp.spec_data;
			status = DCMD_ERR;
		}

		if (opt_c && data && !(sp.spec_flags & MDB_TGT_SPEC_HIDDEN))
			strfree(data);
	}

	return (status);
}

/*
 * Utility routine for performing the stock argument processing that is common
 * among the dcmds that create event specifiers.  We parse out the standard set
 * of event property options from the command-line, and return a copy of the
 * argument list to the caller that consists solely of the remaining non-option
 * arguments.  If a parsing error occurs, NULL is returned.
 */
static const mdb_arg_t *
ev_getopts(uintmax_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    uint_t *evflags, char **opt_c, uint_t *opt_i, uint_t *opt_l,
    uint64_t *opt_L, uintptr_t *opt_n, uint_t *opt_o, uint_t *opt_p,
    uint_t *rwx)
{
	uint_t setb = 0, clrb = 0;
	const char *p;
	int argi;

	mdb_arg_t *av;
	int ac = 0;

	/* keep lint happy */
	*opt_p = FALSE;

	av = mdb_alloc(sizeof (mdb_arg_t) * (argc + 2), UM_SLEEP | UM_GC);

	/*
	 * If an address was specified, take it as an additional immediate
	 * value argument by adding it to the argument list.
	 */
	if (flags & DCMD_ADDRSPEC) {
		av[ac].a_type = MDB_TYPE_IMMEDIATE;
		av[ac++].a_un.a_val = addr;
	}

	/*
	 * Now call mdb_getopts repeatedly to parse the argument list.  We need
	 * to handle '+[a-z]' processing manually, and we also manually copy
	 * each non-option argument into the av[] array as we encounter them.
	 */
	while (argc != 0 && (argi = mdb_getopts(argc, argv,
	    'c', MDB_OPT_STR, opt_c,
	    'd', MDB_OPT_SETBITS, MDB_TGT_SPEC_AUTODIS, &setb,
	    'D', MDB_OPT_SETBITS, MDB_TGT_SPEC_AUTODEL, &setb,
	    'e', MDB_OPT_SETBITS, MDB_TGT_SPEC_DISABLED, &clrb,
	    'i', MDB_OPT_SETBITS, TRUE, opt_i,
	    'n', MDB_OPT_UINTPTR, opt_n,
	    'o', MDB_OPT_SETBITS, TRUE, opt_o,
#ifdef _KMDB
	    'p', MDB_OPT_SETBITS, TRUE, opt_p,
#endif
	    'r', MDB_OPT_SETBITS, MDB_TGT_WA_R, rwx,
	    's', MDB_OPT_SETBITS, MDB_TGT_SPEC_AUTOSTOP, &setb,
	    'l', MDB_OPT_SETBITS, TRUE, opt_l,
	    'L', MDB_OPT_UINT64, opt_L,
	    't', MDB_OPT_SETBITS, MDB_TGT_SPEC_TEMPORARY, &setb,
	    'T', MDB_OPT_SETBITS, MDB_TGT_SPEC_STICKY, &setb,
	    'w', MDB_OPT_SETBITS, MDB_TGT_WA_W, rwx,
	    'x', MDB_OPT_SETBITS, MDB_TGT_WA_X, rwx, NULL)) != argc) {

		argv += argi; /* advance past elements processed by getopts */
		argc -= argi; /* decrement argc by number of args processed */

		if (argv->a_type == MDB_TYPE_STRING) {
			if (argv->a_un.a_str[0] == '+') {
				for (p = argv->a_un.a_str + 1; *p != '\0'; ) {
					switch (*p++) {
					case 'd':
						clrb |= MDB_TGT_SPEC_AUTODIS;
						break;
					case 'D':
						clrb |= MDB_TGT_SPEC_AUTODEL;
						break;
					case 'e':
						setb |= MDB_TGT_SPEC_DISABLED;
						break;
					case 's':
						clrb |= MDB_TGT_SPEC_AUTOSTOP;
						break;
					case 't':
						clrb |= MDB_TGT_SPEC_TEMPORARY;
						break;
					case 'T':
						clrb |= MDB_TGT_SPEC_STICKY;
						break;
					default:
						mdb_warn("illegal option -- "
						    "+%c\n", p[-1]);
						return (NULL);
					}
				}
			} else if (argv->a_un.a_str[0] != '-') {
				av[ac++] = *argv;
			} else
				return (NULL);
		} else
			av[ac++] = *argv;

		argc--;
		argv++;
	}

	/*
	 * If no arguments were found on the command-line, return NULL to
	 * indicate that the caller should return DCMD_USAGE.
	 */
	if (ac == 0)
		return (NULL);

	/*
	 * If -n was not specified, then -d means "disable now" instead of
	 * meaning "set auto-disable after n hits".
	 */
	if (opt_n == 0 && (setb & MDB_TGT_SPEC_AUTODIS))
		setb = (setb & ~MDB_TGT_SPEC_AUTODIS) | MDB_TGT_SPEC_DISABLED;

	/*
	 * Return the final set of flags, and terminate the argument array
	 * with a NULL string argument.
	 */
	*evflags = setb & ~clrb;

	av[ac].a_type = MDB_TYPE_STRING;
	av[ac].a_un.a_str = NULL;

	return (av);
}

/*
 * Utility function for modifying the spec_data and spec_limit properties of an
 * event specifier.  We use this for handling the -c and -n options below.
 */
static void
ev_setopts(mdb_tgt_t *t, int id, const char *opt_c, uintptr_t opt_n)
{
	mdb_tgt_spec_desc_t sp;

	(void) mdb_tgt_vespec_info(t, id, &sp, NULL, 0);

	if (opt_c != NULL)
		sp.spec_data = strdup(opt_c);
	if (opt_n != 0)
		sp.spec_limit = opt_n;

	if (mdb_tgt_vespec_modify(t, id, sp.spec_flags,
	    sp.spec_limit, sp.spec_data) == -1) {
		mdb_warn("failed to modify event %d", id);
		if (opt_c != NULL)
			strfree(sp.spec_data);
	}
}

int
cmd_bp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char *opt_c = NULL;
	uint_t opt_i = FALSE;
	uint_t opt_l = FALSE;
	uint64_t opt_L = 0;
	uintptr_t opt_n = 0;
	uint_t opt_o = FALSE;
	uint_t opt_p = FALSE;
	uint_t opt_rwx = 0;
	int status = DCMD_OK;
	int id;

	if ((argv = ev_getopts(addr, flags, argc, argv, &flags, &opt_c, &opt_i,
	    &opt_l, &opt_L, &opt_n, &opt_o, &opt_p, &opt_rwx)) == NULL ||
	    opt_i || opt_o || opt_rwx != 0 || opt_l || opt_L != 0 || opt_p)
		return (DCMD_USAGE);

	while (argv->a_type != MDB_TYPE_STRING || argv->a_un.a_str != NULL) {
		if (argv->a_type == MDB_TYPE_STRING) {
			id = mdb_tgt_add_sbrkpt(mdb.m_target, argv->a_un.a_str,
			    flags, cmd_event, NULL);
		} else {
			id = mdb_tgt_add_vbrkpt(mdb.m_target, argv->a_un.a_val,
			    flags, cmd_event, NULL);
		}

		if (id == 0) {
			mdb_warn("failed to add breakpoint at %s",
			    argv->a_type == MDB_TYPE_STRING ? argv->a_un.a_str :
			    numtostr(argv->a_un.a_val, mdb.m_radix,
			    NTOS_UNSIGNED | NTOS_SHOWBASE));
			status = DCMD_ERR;

		} else if (opt_c || opt_n)
			ev_setopts(mdb.m_target, id, opt_c, opt_n);

		argv++;
	}

	return (status);
}


int
cmd_sigbp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char *opt_c = NULL;
	uint_t opt_i = FALSE;
	uint_t opt_l = FALSE;
	uint64_t opt_L = 0;
	uintptr_t opt_n = 0;
	uint_t opt_o = FALSE;
	uint_t opt_p = FALSE;
	uint_t opt_rwx = 0;
	int status = DCMD_OK;
	int id, sig;

	if ((argv = ev_getopts(addr, flags, argc, argv, &flags, &opt_c, &opt_i,
	    &opt_l, &opt_L, &opt_n, &opt_o, &opt_p, &opt_rwx)) == NULL ||
	    opt_i || opt_l || opt_L != 0 || opt_o || opt_p || opt_rwx != 0)
		return (DCMD_USAGE);

	while (argv->a_type != MDB_TYPE_STRING || argv->a_un.a_str != NULL) {
		if (argv->a_type == MDB_TYPE_STRING) {
			if (proc_str2sig(argv->a_un.a_str, &sig) == -1) {
				mdb_warn("invalid signal name -- %s\n",
				    argv->a_un.a_str);
				status = DCMD_ERR;
				argv++;
				continue;
			}
		} else
			sig = (int)(intmax_t)argv->a_un.a_val;

		if ((id = mdb_tgt_add_signal(mdb.m_target, sig, flags,
		    cmd_event, NULL)) == 0) {
			mdb_warn("failed to trace signal %d", sig);
			status = DCMD_ERR;
		} else if (opt_c || opt_n)
			ev_setopts(mdb.m_target, id, opt_c, opt_n);

		argv++;
	}

	return (status);
}

int
cmd_sysbp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char *opt_c = NULL;
	uint_t opt_i = FALSE;
	uint_t opt_l = FALSE;
	uint64_t opt_L = 0;
	uintptr_t opt_n = 0;
	uint_t opt_o = FALSE;
	uint_t opt_p = FALSE;
	uint_t opt_rwx = 0;
	int status = DCMD_OK;
	int id, sysnum;

	if ((argv = ev_getopts(addr, flags, argc, argv, &flags, &opt_c, &opt_i,
	    &opt_l, &opt_L, &opt_n, &opt_o, &opt_p, &opt_rwx)) == NULL ||
	    (opt_i && opt_o) || opt_l || opt_L != 0 || opt_p || opt_rwx != 0)
		return (DCMD_USAGE);

	while (argv->a_type != MDB_TYPE_STRING || argv->a_un.a_str != NULL) {
		if (argv->a_type == MDB_TYPE_STRING) {
			if (proc_str2sys(argv->a_un.a_str, &sysnum) == -1) {
				mdb_warn("invalid system call name -- %s\n",
				    argv->a_un.a_str);
				status = DCMD_ERR;
				argv++;
				continue;
			}
		} else
			sysnum = (int)(intmax_t)argv->a_un.a_val;

		if (opt_o) {
			id = mdb_tgt_add_sysexit(mdb.m_target, sysnum,
			    flags, cmd_event, NULL);
		} else {
			id = mdb_tgt_add_sysenter(mdb.m_target, sysnum,
			    flags, cmd_event, NULL);
		}

		if (id == 0) {
			mdb_warn("failed to trace system call %d", sysnum);
			status = DCMD_ERR;
		} else if (opt_c || opt_n)
			ev_setopts(mdb.m_target, id, opt_c, opt_n);

		argv++;
	}

	return (status);
}

int
cmd_fltbp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char *opt_c = NULL;
	uint_t opt_i = FALSE;
	uint_t opt_l = FALSE;
	uint64_t opt_L = 0;
	uintptr_t opt_n = 0;
	uint_t opt_o = FALSE;
	uint_t opt_p = FALSE;
	uint_t opt_rwx = 0;
	int status = DCMD_OK;
	int id, fltnum;

	if ((argv = ev_getopts(addr, flags, argc, argv, &flags, &opt_c,
	    &opt_i, &opt_l, &opt_L, &opt_n, &opt_o, &opt_p,
	    &opt_rwx)) == NULL || opt_i || opt_l || opt_L != 0 || opt_o ||
	    opt_p || opt_rwx != 0)
		return (DCMD_USAGE);

	while (argv->a_type != MDB_TYPE_STRING || argv->a_un.a_str != NULL) {
		if (argv->a_type == MDB_TYPE_STRING) {
			if (proc_str2flt(argv->a_un.a_str, &fltnum) == -1) {
				mdb_warn("invalid fault name -- %s\n",
				    argv->a_un.a_str);
				status = DCMD_ERR;
				argv++;
				continue;
			}
		} else
			fltnum = (int)(intmax_t)argv->a_un.a_val;

		id = mdb_tgt_add_fault(mdb.m_target, fltnum,
		    flags, cmd_event, NULL);

		if (id == 0) {
			mdb_warn("failed to trace fault %d", fltnum);
			status = DCMD_ERR;
		} else if (opt_c || opt_n)
			ev_setopts(mdb.m_target, id, opt_c, opt_n);

		argv++;
	}

	return (status);
}

/*ARGSUSED*/
int
cmd_wp(uintptr_t x, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_addr_t addr = mdb_get_dot();
	char *opt_c = NULL;
	uint_t opt_i = FALSE;
	uint_t opt_l = FALSE;
	uint64_t opt_L = 0;
	uintptr_t opt_n = 0;
	uint_t opt_o = FALSE;
	uint_t opt_p = FALSE;
	uint_t opt_rwx = 0;
	int id;
	char buf[MDB_SYM_NAMLEN];
	GElf_Sym gsym;
	int size;

	if ((argv = ev_getopts(addr, flags, argc, argv, &flags, &opt_c, &opt_i,
	    &opt_l, &opt_L, &opt_n, &opt_o, &opt_p, &opt_rwx)) == NULL ||
	    opt_o || (opt_p && opt_i))
		return (DCMD_USAGE);

#ifndef _KMDB
	if (opt_i)
		return (DCMD_USAGE);
#endif

	if (argv->a_type != MDB_TYPE_IMMEDIATE)
		return (DCMD_USAGE);

	if (opt_rwx == 0) {
		mdb_warn("at least one of -r, -w, or -x must be specified\n");
		return (DCMD_USAGE);
	}

	if ((opt_l) + (opt_L > 0) + (mdb.m_dcount != 1) > 1) {
		mdb_warn("only one of -l, -L, or command count can be "
		    "specified\n");
		return (DCMD_ABORT);
	}

	if (opt_l) {
		if (mdb_lookup_by_addr(addr, MDB_SYM_EXACT, buf,
		    sizeof (buf), &gsym) == -1) {
			mdb_warn("failed to lookup symbol at %p", addr);
			return (DCMD_ERR);
		}

		if (gsym.st_size == 0) {
			mdb_warn("cannot set watchpoint: symbol '%s' has zero "
			    "size\n", buf);
			return (DCMD_ERR);
		}
		size = gsym.st_size;
	} else if (opt_L != 0) {
		size = opt_L;
	} else
		size = mdb.m_dcount;

	if (opt_p) {
		id = mdb_tgt_add_pwapt(mdb.m_target, addr, size, opt_rwx,
		    flags, cmd_event, NULL);
	} else if (opt_i) {
		id = mdb_tgt_add_iowapt(mdb.m_target, addr, size, opt_rwx,
		    flags, cmd_event, NULL);
	} else {
		id = mdb_tgt_add_vwapt(mdb.m_target, addr, size, opt_rwx,
		    flags, cmd_event, NULL);
	}

	if (id == 0) {
		mdb_warn("failed to set watchpoint at %p", addr);
		return ((opt_l || opt_L) ? DCMD_ERR : DCMD_ABORT);
	}

	if (opt_c || opt_n)
		ev_setopts(mdb.m_target, id, opt_c, opt_n);

	/*
	 * We use m_dcount as an argument; don't loop. We ignore this
	 * restriction with the -l and -L options, since we read the size from
	 * the symbol and don't rely on the count.
	 */
	return ((opt_l || opt_L) ? DCMD_OK : DCMD_ABORT);
}

/*ARGSUSED*/
int
cmd_oldbp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char *s = mdb_argv_to_str(argc, argv);

	if (mdb_tgt_add_vbrkpt(mdb.m_target, addr, 0, cmd_event, s) == 0) {
		mdb_warn("failed to add breakpoint");
		if (s != NULL)
			strfree(s);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
oldwp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv, uint_t rwx)
{
	char *s = mdb_argv_to_str(argc, argv);

	if (mdb_tgt_add_vwapt(mdb.m_target, addr, mdb.m_dcount, rwx, 0,
	    cmd_event, s) == 0) {
		mdb_warn("failed to add watchpoint");
		if (s != NULL)
			strfree(s);
		return (DCMD_ABORT);
	}

	return (DCMD_ABORT); /* we use m_dcount as an argument; don't loop */
}

int
cmd_oldwpr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (oldwp(addr, flags, argc, argv, MDB_TGT_WA_R));
}

int
cmd_oldwpw(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (oldwp(addr, flags, argc, argv, MDB_TGT_WA_W));
}

int
cmd_oldwpx(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (oldwp(addr, flags, argc, argv, MDB_TGT_WA_X));
}

static const char _evset_help[] =
"+/-d     disable specifier when hit count reaches limit (+d to unset);\n"
"         if -n is not present with -d, specifier is disabled immediately\n\n"
"+/-D     delete specifier when hit count reaches limit (+D to unset);\n"
"+/-e     enable specifier (+e or -d to disable)\n"
"+/-s     stop target when hit count reaches limit (+s to unset)\n"
"+/-t     delete specifier the next time the target stops (+t to unset)\n"
"+/-T     sticky bit: ::delete all will not remove specifier (+T to unset)\n\n"
"-c cmd   execute \"cmd\" each time the corresponding event occurs\n"
"-n count set limit for -D, -d, or -s to \"count\" (default 1)\n\n";

void
bp_help(void)
{
	mdb_printf(_evset_help);
	mdb_printf("addr     set breakpoint at specified virtual address\n");
	mdb_printf("sym      set deferred breakpoint at specified symbol\n");
}

void
evset_help(void)
{
	mdb_printf(_evset_help);
	mdb_printf("addr/id  set properties of specified event ids\n");
}

void
fltbp_help(void)
{
	mdb_printf(_evset_help);
	mdb_printf("flt      fault name (see <sys/fault.h>) or number\n");
}

void
sigbp_help(void)
{
	mdb_printf(_evset_help);
	mdb_printf("SIG      signal name (see signal(3HEAD)) or number\n");
}

void
sysbp_help(void)
{
	mdb_printf(_evset_help);
	mdb_printf("-i       trace system call on entry into kernel (default)\n"
	    "-o       trace system call on exit from kernel\n\n"
	    "syscall  system call name (see <sys/syscall.h>) or number\n");
}

void
wp_help(void)
{
	mdb_printf(_evset_help);
	mdb_printf(
#ifdef _KMDB
	    "-p       treat addr as a physical address\n"
	    "-i       treat addr as an I/O port address\n"
#endif
	    "-l       use size of addr's type for watched region\n"
	    "-L size  set size of watched region (default 1)\n"
	    "-r       trace read access to watched region\n"
	    "-w       trace write access to watched region\n"
	    "-x       trace execute access to watched region\n\n"
	    "addr     address for base of watched region\n"
	    "repeat   size of watched region (equivalent to -L)\n");
}
