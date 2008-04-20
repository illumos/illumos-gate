/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Proc Service API Interposition Layer
 *
 * In order to allow multiple MDB targets to make use of librtld_db, we
 * provide an interposition layer for functions in the proc_service.h API
 * that are used by librtld_db.  Each of the functions used by librtld_db
 * can be conveniently expressed in terms of the MDB target API, so this
 * layer simply selects the appropriate target, invokes the corresponding
 * target API function, and then translates the error codes appropriately.
 * We expect that each proc_service entry point will be invoked with a
 * cookie (struct ps_prochandle *) which matches either a known MDB target,
 * or the value of a target's t->t_pshandle.  This allows us to re-vector
 * calls to the proc service API around libproc (which also contains an
 * implementation of the proc_service API) like this:
 *
 * Linker map:
 * +---------+   +---------+   +------------+      Legend:
 * |   MDB   | ->| libproc | ->| librtld_db |      <1> function in this file
 * +---------+   +---------+   +------------+      <2> function in libproc
 * ps_pread<1>   ps_pread<2>   call ps_pread() --+
 *                                               |
 * +---------------------------------------------+
 * |
 * +-> ps_pread<1>(P, ...)
 *       t = mdb_tgt_from_pshandle(P);
 *       mdb_tgt_vread(t, ...);
 *
 * If we are debugging a user process, we then make these calls (which form
 * the equivalent of libproc's proc_service implementation):
 *
 * mdb_tgt_vread() -> proc target t->t_vread() -> libproc.so`Pread()
 *
 * If we are debugging a user process through a kernel crash dump (kproc
 * target), we make these calls:
 *
 * mdb_tgt_vread() -> kproc target t->t_vread() -> mdb_tgt_aread(kvm target) ->
 * 	kvm target t->t_aread() -> libkvm.so`kvm_aread()
 *
 * This design allows us to support both kproc's use of librtld_db, as well
 * as libproc's use of librtld_db, but it does lead to one unfortunate problem
 * in the creation of a proc target: when the proc target invokes libproc to
 * construct a ps_prochandle, and libproc in turn invokes librtld_db, MDB does
 * not yet know what ps_prochandle has been allocated inside of libproc since
 * this call has not yet returned.  We also can't translate this ps_prochandle
 * to the target itself, since that target isn't ready to handle requests yet;
 * we actually need to pass the call back through to libproc.  In order to
 * do that, we use libdl to lookup the address of libproc's definition of the
 * various functions (RTLD_NEXT on the link map chain) and store these in the
 * ps_ops structure below.  If we ever fail to translate a ps_prochandle to
 * an MDB target, we simply pass the call through to libproc.
 */

#include <proc_service.h>
#include <dlfcn.h>

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb.h>

static struct {
	ps_err_e (*ps_pread)(struct ps_prochandle *,
	    psaddr_t, void *, size_t);
	ps_err_e (*ps_pwrite)(struct ps_prochandle *,
	    psaddr_t, const void *, size_t);
	ps_err_e (*ps_pglobal_lookup)(struct ps_prochandle *,
	    const char *, const char *, psaddr_t *);
	ps_err_e (*ps_pglobal_sym)(struct ps_prochandle *P,
	    const char *, const char *, ps_sym_t *);
	ps_err_e (*ps_pauxv)(struct ps_prochandle *,
	    const auxv_t **);
	ps_err_e (*ps_pbrandname)(struct ps_prochandle *,
	    char *, size_t);
	ps_err_e (*ps_pdmodel)(struct ps_prochandle *,
	    int *);
} ps_ops;

static mdb_tgt_t *
mdb_tgt_from_pshandle(void *P)
{
	mdb_tgt_t *t;

	for (t = mdb_list_next(&mdb.m_tgtlist); t; t = mdb_list_next(t)) {
		if (t == P || t->t_pshandle == P)
			return (t);
	}

	return (NULL);
}

/*
 * Read from the specified target virtual address.
 */
ps_err_e
ps_pread(struct ps_prochandle *P, psaddr_t addr, void *buf, size_t size)
{
	mdb_tgt_t *t = mdb_tgt_from_pshandle(P);

	if (t == NULL)
		return (ps_ops.ps_pread(P, addr, buf, size));

	if (mdb_tgt_vread(t, buf, size, addr) != size)
		return (PS_BADADDR);

	return (PS_OK);
}

/*
 * Write to the specified target virtual address.
 */
ps_err_e
ps_pwrite(struct ps_prochandle *P, psaddr_t addr, const void *buf, size_t size)
{
	mdb_tgt_t *t = mdb_tgt_from_pshandle(P);

	if (t == NULL)
		return (ps_ops.ps_pwrite(P, addr, buf, size));

	if (mdb_tgt_vwrite(t, buf, size, addr) != size)
		return (PS_BADADDR);

	return (PS_OK);
}

/*
 * Search for a symbol by name and return the corresponding address.
 */
ps_err_e
ps_pglobal_lookup(struct ps_prochandle *P, const char *object,
    const char *name, psaddr_t *symp)
{
	mdb_tgt_t *t = mdb_tgt_from_pshandle(P);
	GElf_Sym sym;

	if (t == NULL)
		return (ps_ops.ps_pglobal_lookup(P, object, name, symp));

	if (mdb_tgt_lookup_by_name(t, object, name, &sym, NULL) == 0) {
		*symp = (psaddr_t)sym.st_value;
		return (PS_OK);
	}

	return (PS_NOSYM);
}

/*
 * Search for a symbol by name and return the corresponding symbol data.
 * If we're compiled _LP64, we just call mdb_tgt_lookup_by_name and return
 * because ps_sym_t is defined to be an Elf64_Sym, which is the same as a
 * GElf_Sym.  In the _ILP32 case, we have to convert mdb_tgt_lookup_by_name's
 * result back to a ps_sym_t (which is an Elf32_Sym).
 */
ps_err_e
ps_pglobal_sym(struct ps_prochandle *P, const char *object,
    const char *name, ps_sym_t *symp)
{
	mdb_tgt_t *t = mdb_tgt_from_pshandle(P);
#if defined(_ILP32)
	GElf_Sym sym;

	if (t == NULL)
		return (ps_ops.ps_pglobal_sym(P, object, name, symp));

	if (mdb_tgt_lookup_by_name(t, object, name, &sym, NULL) == 0) {
		symp->st_name = (Elf32_Word)sym.st_name;
		symp->st_value = (Elf32_Addr)sym.st_value;
		symp->st_size = (Elf32_Word)sym.st_size;
		symp->st_info = ELF32_ST_INFO(
		    GELF_ST_BIND(sym.st_info), GELF_ST_TYPE(sym.st_info));
		symp->st_other = sym.st_other;
		symp->st_shndx = sym.st_shndx;
		return (PS_OK);
	}

#elif defined(_LP64)
	if (t == NULL)
		return (ps_ops.ps_pglobal_sym(P, object, name, symp));

	if (mdb_tgt_lookup_by_name(t, object, name, symp, NULL) == 0)
		return (PS_OK);
#endif

	return (PS_NOSYM);
}

/*
 * Report a debug message.  We allow proc_service API clients to report
 * messages via our debug stream if the MDB_DBG_PSVC token is enabled.
 */
void
ps_plog(const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	mdb_dvprintf(MDB_DBG_PSVC, format, alist);
	va_end(alist);
}

/*
 * Return the auxv structure from the process being examined.
 */
ps_err_e
ps_pauxv(struct ps_prochandle *P, const auxv_t **auxvp)
{
	mdb_tgt_t *t = mdb_tgt_from_pshandle(P);

	if (t == NULL)
		return (ps_ops.ps_pauxv(P, auxvp));

	if (mdb_tgt_auxv(t, auxvp) != 0)
		return (PS_ERR);

	return (PS_OK);
}

ps_err_e
ps_pbrandname(struct ps_prochandle *P, char *buf, size_t len)
{
	mdb_tgt_t *t = mdb_tgt_from_pshandle(P);
	const auxv_t *auxv;

	if (t == NULL)
		return (ps_ops.ps_pbrandname(P, buf, len));

	if (mdb_tgt_auxv(t, &auxv) != 0)
		return (PS_ERR);

	while (auxv->a_type != AT_NULL) {
		if (auxv->a_type == AT_SUN_BRANDNAME)
			break;
		auxv++;
	}
	if (auxv->a_type == AT_NULL)
		return (PS_ERR);

	if (mdb_tgt_readstr(t, MDB_TGT_AS_VIRT,
	    buf, len, auxv->a_un.a_val) <= 0)
		return (PS_ERR);

	return (PS_OK);
}

/*
 * Return the data model of the target.
 */
ps_err_e
ps_pdmodel(struct ps_prochandle *P, int *dm)
{
	mdb_tgt_t *t = mdb_tgt_from_pshandle(P);

	if (t == NULL)
		return (ps_ops.ps_pdmodel(P, dm));

	switch (mdb_tgt_dmodel(t)) {
	case MDB_TGT_MODEL_LP64:
		*dm = PR_MODEL_LP64;
		return (PS_OK);
	case MDB_TGT_MODEL_ILP32:
		*dm = PR_MODEL_ILP32;
		return (PS_OK);
	}

	return (PS_ERR);
}

/*
 * Stub function in case we cannot find the necessary symbols from libproc.
 */
static ps_err_e
ps_fail(struct ps_prochandle *P)
{
	mdb_dprintf(MDB_DBG_PSVC, "failing call to pshandle %p\n", (void *)P);
	return (PS_BADPID);
}

/*
 * Initialization function for the proc service interposition layer: we use
 * libdl to look up the next definition of each function in the link map.
 */
void
mdb_pservice_init(void)
{
	if ((ps_ops.ps_pread = (ps_err_e (*)())
	    dlsym(RTLD_NEXT, "ps_pread")) == NULL)
		ps_ops.ps_pread = (ps_err_e (*)())ps_fail;

	if ((ps_ops.ps_pwrite = (ps_err_e (*)())
	    dlsym(RTLD_NEXT, "ps_pwrite")) == NULL)
		ps_ops.ps_pwrite = (ps_err_e (*)())ps_fail;

	if ((ps_ops.ps_pglobal_lookup = (ps_err_e (*)())
	    dlsym(RTLD_NEXT, "ps_pglobal_lookup")) == NULL)
		ps_ops.ps_pglobal_lookup = (ps_err_e (*)())ps_fail;

	if ((ps_ops.ps_pglobal_sym = (ps_err_e (*)())
	    dlsym(RTLD_NEXT, "ps_pglobal_sym")) == NULL)
		ps_ops.ps_pglobal_sym = (ps_err_e (*)())ps_fail;

	if ((ps_ops.ps_pauxv = (ps_err_e (*)())
	    dlsym(RTLD_NEXT, "ps_pauxv")) == NULL)
		ps_ops.ps_pauxv = (ps_err_e (*)())ps_fail;

	if ((ps_ops.ps_pbrandname = (ps_err_e (*)())
	    dlsym(RTLD_NEXT, "ps_pbrandname")) == NULL)
		ps_ops.ps_pbrandname = (ps_err_e (*)())ps_fail;

	if ((ps_ops.ps_pdmodel = (ps_err_e (*)())
	    dlsym(RTLD_NEXT, "ps_pdmodel")) == NULL)
		ps_ops.ps_pdmodel = (ps_err_e (*)())ps_fail;
}
