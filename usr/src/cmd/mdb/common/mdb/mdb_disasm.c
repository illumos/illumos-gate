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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_disasm_impl.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb.h>

int
mdb_dis_select(const char *name)
{
	mdb_var_t *v = mdb_nv_lookup(&mdb.m_disasms, name);

	if (v != NULL) {
		mdb.m_disasm = mdb_nv_get_cookie(v);
		return (0);
	}

	if (mdb.m_target == NULL) {
		if (mdb.m_defdisasm != NULL)
			strfree(mdb.m_defdisasm);
		mdb.m_defdisasm = strdup(name);
		return (0);
	}

	return (set_errno(EMDB_NODIS));
}

mdb_disasm_t *
mdb_dis_create(mdb_dis_ctor_f *ctor)
{
	mdb_disasm_t *dp = mdb_zalloc(sizeof (mdb_disasm_t), UM_SLEEP);

	if ((dp->dis_module = mdb.m_lmod) == NULL)
		dp->dis_module = &mdb.m_rmod;

	if (ctor(dp) == 0) {
		mdb_var_t *v = mdb_nv_lookup(&mdb.m_disasms, dp->dis_name);

		if (v != NULL) {
			dp->dis_ops->dis_destroy(dp);
			mdb_free(dp, sizeof (mdb_disasm_t));
			(void) set_errno(EMDB_DISEXISTS);
			return (NULL);
		}

		(void) mdb_nv_insert(&mdb.m_disasms, dp->dis_name, NULL,
		    (uintptr_t)dp, MDB_NV_RDONLY | MDB_NV_SILENT);

		if (mdb.m_disasm == NULL) {
			mdb.m_disasm = dp;
		} else if (mdb.m_defdisasm != NULL &&
		    strcmp(mdb.m_defdisasm, dp->dis_name) == 0) {
			mdb.m_disasm = dp;
			strfree(mdb.m_defdisasm);
			mdb.m_defdisasm = NULL;
		}

		return (dp);
	}

	mdb_free(dp, sizeof (mdb_disasm_t));
	return (NULL);
}

void
mdb_dis_destroy(mdb_disasm_t *dp)
{
	mdb_var_t *v = mdb_nv_lookup(&mdb.m_disasms, dp->dis_name);

	ASSERT(v != NULL);
	mdb_nv_remove(&mdb.m_disasms, v);
	dp->dis_ops->dis_destroy(dp);
	mdb_free(dp, sizeof (mdb_disasm_t));

	if (mdb.m_disasm == dp)
		(void) mdb_dis_select("default");
}

mdb_tgt_addr_t
mdb_dis_ins2str(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    char *buf, size_t len, mdb_tgt_addr_t addr)
{
	return (dp->dis_ops->dis_ins2str(dp, t, as, buf, len, addr));
}

mdb_tgt_addr_t
mdb_dis_previns(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t addr, uint_t n)
{
	return (dp->dis_ops->dis_previns(dp, t, as, addr, n));
}

mdb_tgt_addr_t
mdb_dis_nextins(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t addr)
{
	return (dp->dis_ops->dis_nextins(dp, t, as, addr));
}

/*ARGSUSED*/
int
cmd_dismode(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags & DCMD_ADDRSPEC) || argc > 1)
		return (DCMD_USAGE);

	if (argc != 0) {
		const char *name;

		if (argv->a_type == MDB_TYPE_STRING)
			name = argv->a_un.a_str;
		else
			name = numtostr(argv->a_un.a_val, 10, NTOS_UNSIGNED);

		if (mdb_dis_select(name) == -1) {
			warn("failed to set disassembly mode");
			return (DCMD_ERR);
		}
	}

	mdb_printf("disassembly mode is %s (%s)\n",
	    mdb.m_disasm->dis_name, mdb.m_disasm->dis_desc);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
print_dis(mdb_var_t *v, void *ignore)
{
	mdb_disasm_t *dp = mdb_nv_get_cookie(v);

	mdb_printf("%-24s - %s\n", dp->dis_name, dp->dis_desc);
	return (0);
}

/*ARGSUSED*/
int
cmd_disasms(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	mdb_nv_sort_iter(&mdb.m_disasms, print_dis, NULL, UM_SLEEP | UM_GC);
	return (DCMD_OK);
}

/*ARGSUSED*/
static void
defdis_destroy(mdb_disasm_t *dp)
{
	/* Nothing to do here */
}

/*ARGSUSED*/
static mdb_tgt_addr_t
defdis_ins2str(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    char *buf, size_t len, mdb_tgt_addr_t addr)
{
	return (addr);
}

/*ARGSUSED*/
static mdb_tgt_addr_t
defdis_previns(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t addr, uint_t n)
{
	return (addr);
}

/*ARGSUSED*/
static mdb_tgt_addr_t
defdis_nextins(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t addr)
{
	return (addr);
}

static const mdb_dis_ops_t defdis_ops = {
	defdis_destroy,
	defdis_ins2str,
	defdis_previns,
	defdis_nextins
};

static int
defdis_create(mdb_disasm_t *dp)
{
	dp->dis_name = "default";
	dp->dis_desc = "default no-op disassembler";
	dp->dis_ops = &defdis_ops;

	return (0);
}

mdb_dis_ctor_f *const mdb_dis_builtins[] = {
#if defined(__amd64)
	ia32_create,
	amd64_create,
#elif defined(__i386)
	ia32_create,
#endif
	defdis_create,
	NULL
};
