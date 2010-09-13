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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * (k)adb Macro Aliases
 *
 * Provides aliases for popular ADB macros.  These macros, which have been
 * removed from the workspace, were documented in various locations, and need
 * continued support.  While we don't provide the same output format that was
 * provided by the original macros, we do map the macro names to the equivalent
 * MDB functionality.
 */

#include <mdb/mdb_debug.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb.h>

typedef struct mdb_macalias {
	const char *ma_name;
	const char *ma_defn;
} mdb_macalias_t;

static const mdb_macalias_t mdb_macaliases[] = {
	{ "bufctl",		"::bufctl" },
	{ "bufctl_audit",	"::bufctl -v" },
	{ "cpu",		"::cpuinfo -v" },
	{ "cpun",		"::cpuinfo -v" },
	{ "cpus",		"::walk cpu |::cpuinfo -v" },
	{ "devinfo",		"::print struct dev_info" },
	{ "devinfo.minor",	"::minornodes" },
	{ "devinfo.next",	"::walk devi_next |::devinfo -s" },
	{ "devinfo.parent",	"::walk devinfo_parents |::devinfo -s" },
	{ "devinfo.prop",	"::devinfo" },
	{ "devinfo.sibling",	"::walk devinfo_siblings |::devinfo -s" },
	{ "devinfo_brief",	"::devinfo -s" },
	{ "devinfo_major",	"::devbindings -s" },
	{ "devnames_major",	"::devnames -m" },
	{ "devt",		"::devt" },
	{ "devt2snode",		"::dev2snode" },
	{ "findthreads",	"::walk thread |::thread" },
	{ "major2snode",	"::major2snode" },
	{ "mblk",		"::mblk -v" },
	{ "modctl.brief",	"::modctl" },
	{ "modules",		"::modinfo" },
	{ "mount",		"::fsinfo" },
	{ "msgbuf",		"::msgbuf" },
	{ "mutex",		"::mutex" },
	{ "panicbuf",		"::panicinfo" },
	{ "pid2proc",		"::pid2proc |::print proc_t" },
	{ "proc2u",		"::print proc_t p_user" },
	{ "procargs",		"::print proc_t p_user.u_psargs" },
	{ "queue",		"::queue -v" },
	{ "sema",		"::print sema_impl_t" },
	{ "stackregs",		"::stackregs" },
	{ "stacktrace",		"::stackregs" },
#if defined(__sparc)
	{ "systemdump",		"0>pc;0>npc;nopanicdebug/W 1;:c" },
#elif defined(__i386)
	{ "systemdump",		"0>eip;nopanicdebug/W 1;:c" },
#else
	{ "systemdump",		"0>rip;nopanicdebug/W 1;:c" },
#endif
	{ "thread",		"::print kthread_t" },
	{ "threadlist",		"::threadlist -v" },
	{ "u",			"::print user_t" },
	{ "utsname",		"utsname::print" },
	{ NULL }
};

void
mdb_macalias_create(void)
{
	int i;

	(void) mdb_nv_create(&mdb.m_macaliases, UM_SLEEP);

	for (i = 0; mdb_macaliases[i].ma_name != NULL; i++) {
		const mdb_macalias_t *ma = &mdb_macaliases[i];
		(void) mdb_nv_insert(&mdb.m_macaliases, ma->ma_name, NULL,
		    (uintptr_t)ma->ma_defn, MDB_NV_RDONLY | MDB_NV_EXTNAME |
		    MDB_NV_PERSIST);
	}
}

const char *
mdb_macalias_lookup(const char *name)
{
	mdb_var_t *v;

	if ((v = mdb_nv_lookup(&mdb.m_macaliases, name)) == NULL)
		return (NULL);

	return (MDB_NV_COOKIE(v));
}

/*ARGSUSED*/
int
cmd_macalias_list(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int i;

	if (flags & DCMD_ADDRSPEC || argc != 0)
		return (DCMD_USAGE);

	mdb_printf("%<u>%-20s%</u> %<u>%-59s%</u>\n",
	    "MACRO", "NATIVE EQUIVALENT");

	for (i = 0; mdb_macaliases[i].ma_name != NULL; i++) {
		const mdb_macalias_t *ma = &mdb_macaliases[i];
		mdb_printf("%-20s %s\n", ma->ma_name, ma->ma_defn);
	}

	return (DCMD_OK);
}

void
mdb_macalias_destroy(void)
{
	mdb_nv_destroy(&mdb.m_macaliases);
}
