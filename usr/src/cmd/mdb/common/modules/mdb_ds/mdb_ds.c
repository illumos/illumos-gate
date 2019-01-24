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

/*
 * MDB developer support module.  This module is loaded automatically when the
 * proc target is initialized and the target is mdb itself.  In the future, we
 * should document these facilities in the answerbook to aid module developers.
 */

#define	_MDB
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_target_impl.h>
#include <kmdb/kmdb_wr_impl.h>
#include <mdb/mdb.h>

static const mdb_t *
get_mdb(void)
{
	static mdb_t m;

	if (mdb_readvar(&m, "mdb") == -1)
		mdb_warn("failed to read mdb_t state");

	return (&m);
}

static int
cmd_stack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char sep[] =
	    "-----------------------------------------------------------------";

	if (flags & DCMD_ADDRSPEC) {
		char buf[MDB_NV_NAMELEN + 1];
		uintptr_t sp, pc;
		mdb_idcmd_t idc;
		mdb_frame_t f;
		mdb_cmd_t c;
		mdb_arg_t *ap;
		size_t i;

		if (mdb_vread(&f, sizeof (f), addr) == -1) {
			mdb_warn("failed to read frame at %p", addr);
			return (DCMD_ERR);
		}

		bzero(&c, sizeof (mdb_cmd_t));

		if (mdb_vread(&c, sizeof (c), (uintptr_t)f.f_cp) < 0 ||
		    mdb_vread(&idc, sizeof (idc), (uintptr_t)c.c_dcmd) < 0 ||
		    mdb_readstr(buf, sizeof (buf), (uintptr_t)idc.idc_name) < 1)
			(void) strcpy(buf, "?");

		mdb_printf("+>\tframe <%u> %p (%s", f.f_id, addr, buf);
		ap = mdb_alloc(c.c_argv.a_nelems * sizeof (mdb_arg_t), UM_GC);

		if (ap != NULL && mdb_vread(ap, c.c_argv.a_nelems *
		    sizeof (mdb_arg_t), (uintptr_t)c.c_argv.a_data) > 0) {
			for (i = 0; i < c.c_argv.a_nelems; i++) {
				switch (ap[i].a_type) {
				case MDB_TYPE_STRING:
					if (mdb_readstr(buf, sizeof (buf),
					    (uintptr_t)ap[i].a_un.a_str) > 0)
						mdb_printf(" %s", buf);
					else
						mdb_printf(" <str=%a>",
						    ap[i].a_un.a_str);
					break;
				case MDB_TYPE_IMMEDIATE:
					mdb_printf(" $[ 0x%llx ]",
					    ap[i].a_un.a_val);
					break;
				case MDB_TYPE_CHAR:
					mdb_printf(" '%c'", ap[i].a_un.a_char);
					break;
				default:
					mdb_printf(" <type=%d>", ap[i].a_type);
				}
			}
		}

		mdb_printf(")\n\tf_list = %-?p\tf_cmds = %p\n",
		    addr + OFFSETOF(mdb_frame_t, f_list),
		    addr + OFFSETOF(mdb_frame_t, f_cmds));
		mdb_printf("\tf_istk = %-?p\tf_ostk = %p\n",
		    addr + OFFSETOF(mdb_frame_t, f_istk),
		    addr + OFFSETOF(mdb_frame_t, f_ostk));
		mdb_printf("\tf_wcbs = %-?p\tf_mblks = %p\n",
		    f.f_wcbs, f.f_mblks);
		mdb_printf("\tf_pcmd = %-?p\tf_pcb = %p\n",
		    f.f_pcmd, addr + OFFSETOF(mdb_frame_t, f_pcb));
		mdb_printf("\tf_cp = %-?p\t\tf_flags = 0x%x\n\n",
		    f.f_cp, f.f_flags);

#if defined(__sparc)
		sp = ((uintptr_t *)f.f_pcb)[1];
		pc = ((uintptr_t *)f.f_pcb)[2];
#elif defined(__amd64)
		sp = ((uintptr_t *)f.f_pcb)[5];
		pc = ((uintptr_t *)f.f_pcb)[7];
#elif defined(__i386)
		sp = ((uintptr_t *)f.f_pcb)[3];
		pc = ((uintptr_t *)f.f_pcb)[5];
#else
#error	Unknown ISA
#endif
		if (pc != 0)
			mdb_printf("      [ %0?lr %a() ]\n", sp, pc);

		mdb_set_dot(sp);
		mdb_inc_indent(8);
		mdb_eval("<.$C0");
		mdb_dec_indent(8);
		mdb_printf("%s\n", sep);

	} else {
		mdb_printf("%s\n", sep);
		(void) mdb_walk_dcmd("mdb_frame", "mdb_stack", argc, argv);
	}

	return (DCMD_OK);
}

static int
cmd_frame(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags & DCMD_ADDRSPEC) && argc == 0)
		return (cmd_stack(addr, flags, argc, argv));

	return (DCMD_USAGE);
}

/*ARGSUSED*/
static int
cmd_iob(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_iob_t iob;
	mdb_io_t io;

	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%?s %6s %6s %?s %s\n",
		    "IOB", "NBYTES", "FLAGS", "IOP", "OPS");
	}

	if (mdb_vread(&iob, sizeof (iob), addr) == -1 ||
	    mdb_vread(&io, sizeof (io), (uintptr_t)iob.iob_iop) == -1) {
		mdb_warn("failed to read iob at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%?p %6lu %6x %?p %a\n", addr, (ulong_t)iob.iob_nbytes,
	    iob.iob_flags, iob.iob_iop, io.io_ops);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_in(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_printf("%p\n", get_mdb()->m_in);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_out(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_printf("%p\n", get_mdb()->m_out);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_err(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_printf("%p\n", get_mdb()->m_err);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_target(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t t;

	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC))
		addr = (uintptr_t)get_mdb()->m_target;

	if (mdb_vread(&t, sizeof (t), addr) != sizeof (t)) {
		mdb_warn("failed to read target at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("+>\ttarget %p (%a)\n", addr, t.t_ops);

	mdb_printf("\tt_active = %-?p\tt_idle = %p\n",
	    addr + OFFSETOF(mdb_tgt_t, t_active),
	    addr + OFFSETOF(mdb_tgt_t, t_idle));
	mdb_printf("\tt_xdlist = %-?p\tt_module = %a\n",
	    addr + OFFSETOF(mdb_tgt_t, t_xdlist), t.t_module);
	mdb_printf("\tt_pshandle = %-?p\tt_data = %p\n",
	    t.t_pshandle, t.t_data);
	mdb_printf("\tt_status = %-?p\tt_matched = %p\n",
	    addr + OFFSETOF(mdb_tgt_t, t_status), t.t_matched);
	mdb_printf("\tt_flags = %-?x\tt_vecnt = 0t%u\n", t.t_flags, t.t_vecnt);
	mdb_printf("\tt_vepos = %-?d\tt_veneg = %d\n\n", t.t_vepos, t.t_veneg);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_sespec(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_sespec_t se;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&se, sizeof (se), addr) != sizeof (se)) {
		mdb_warn("failed to read sespec at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("+>\tsespec %p (%a)\n", addr, se.se_ops);

	mdb_printf("\tse_selist = %-?p\tse_velist = %p\n",
	    addr + OFFSETOF(mdb_sespec_t, se_selist),
	    addr + OFFSETOF(mdb_sespec_t, se_velist));

	mdb_printf("\tse_data = %-?p\tse_refs = %u\n",
	    se.se_data, se.se_refs);
	mdb_printf("\tse_state = %-?d\tse_errno = %d\n\n",
	    se.se_state, se.se_errno);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_vespec(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_vespec_t ve;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&ve, sizeof (ve), addr) != sizeof (ve)) {
		mdb_warn("failed to read vespec at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("+>\tvespec %p (id %d)\n", addr, ve.ve_id);
	mdb_printf("\tve_list = %-?p\tve_flags = 0x%x\n",
	    addr + OFFSETOF(mdb_vespec_t, ve_list), ve.ve_flags);
	mdb_printf("\tve_se = %-?p\tve_refs = %u\n", ve.ve_se, ve.ve_refs);
	mdb_printf("\tve_hits = %-?u\tve_lim = %u\n", ve.ve_hits, ve.ve_limit);
	mdb_printf("\tve_data = %-?p\tve_callback = %a\n",
	    ve.ve_data, ve.ve_callback);
	mdb_printf("\tve_args = %-?p\tve_dtor = %a\n\n",
	    ve.ve_args, ve.ve_dtor);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_wr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char path[MAXPATHLEN];
	kmdb_wr_t wn;
	char dir;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&wn, sizeof (wn), addr) != sizeof (wn)) {
		mdb_warn("failed to read wr node at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-9s %3s %?s %s\n",
		    "COMMAND", "ERR", "MODCTL", "NAME");
	}

	dir = "><"[WR_ISACK(&wn) != 0];
	switch (WR_TASK(&wn)) {
	case WNTASK_DMOD_LOAD: {
		kmdb_wr_load_t dlr;

		if (mdb_vread(&dlr, sizeof (dlr), addr) != sizeof (dlr)) {
			mdb_warn("failed to read kmdb_wr_load_t at %p", addr);
			return (DCMD_ERR);
		}

		if (mdb_readstr(path, sizeof (path),
		    (uintptr_t)dlr.dlr_fname) < 0) {
			mdb_warn("failed to read path name at %p",
			    dlr.dlr_fname);
			*path = '\0';
		}

		mdb_printf("%cload     %3d %?p %s\n", dir, dlr.dlr_errno,
		    dlr.dlr_modctl, path);
		break;
	}

	case WNTASK_DMOD_LOAD_ALL:
		mdb_printf("%cload all %3d\n", dir, wn.wn_errno);
		break;

	case WNTASK_DMOD_UNLOAD: {
		kmdb_wr_unload_t dur;

		if (mdb_vread(&dur, sizeof (dur), addr) != sizeof (dur)) {
			mdb_warn("failed to read kmdb_wr_unload_t at %p", addr);
			return (DCMD_ERR);
		}

		if (mdb_readstr(path, sizeof (path),
		    (uintptr_t)dur.dur_modname) < 0) {
			mdb_warn("failed to read module name at %p",
			    dur.dur_modname);
			*path = '\0';
		}

		mdb_printf("%cunload   %3d %?p %s\n", dir, dur.dur_errno,
		    dur.dur_modctl, path);
		break;
	}

	case WNTASK_DMOD_PATH_CHANGE: {
		kmdb_wr_path_t dpth;
		uintptr_t pathp;
		int first = 1;

		if (mdb_vread(&dpth, sizeof (dpth), addr) != sizeof (dpth)) {
			mdb_warn("failed to read kmdb_wr_path_t at %p", addr);
			return (DCMD_ERR);
		}

		mdb_printf("%cpath chg %3d ", dir, dpth.dpth_errno);
		for (;;) {
			if (mdb_vread(&pathp, sizeof (pathp),
			    (uintptr_t)dpth.dpth_path) != sizeof (pathp)) {
				mdb_warn("failed to read path pointer at %p",
				    dpth.dpth_path);
				break;
			}

			dpth.dpth_path++;

			if (pathp == 0)
				break;

			if (mdb_readstr(path, sizeof (path), pathp) < 0) {
				mdb_warn("failed to read path at %p", pathp);
				*path = '\0';
			}

			mdb_printf("%s%s", (first ? "" : "\n             "),
			    path);
			first = 0;
		}
		mdb_printf("\n");
		break;
	}

	default:
		mdb_warn("unknown task type %d\n", wn.wn_task);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
iob_stack_walk_init(mdb_walk_state_t *wsp)
{
	mdb_iob_stack_t stk;

	if (mdb_vread(&stk, sizeof (stk), wsp->walk_addr) == -1) {
		mdb_warn("failed to read iob_stack at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)stk.stk_top;
	return (WALK_NEXT);
}

static int
iob_stack_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	mdb_iob_t iob;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&iob, sizeof (iob), addr) == -1) {
		mdb_warn("failed to read iob at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)iob.iob_next;
	return (wsp->walk_callback(addr, &iob, wsp->walk_cbdata));
}

static int
frame_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0)
		wsp->walk_addr = (uintptr_t)get_mdb()->m_flist.ml_prev;

	return (WALK_NEXT);
}

static int
frame_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	mdb_frame_t f;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&f, sizeof (f), addr) == -1) {
		mdb_warn("failed to read frame at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)f.f_list.ml_prev;
	return (wsp->walk_callback(addr, &f, wsp->walk_cbdata));
}

static int
target_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0)
		wsp->walk_addr = (uintptr_t)get_mdb()->m_target;

	return (WALK_NEXT);
}

static int
target_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	mdb_tgt_t t;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&t, sizeof (t), addr) == -1) {
		mdb_warn("failed to read target at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)t.t_tgtlist.ml_next;
	return (wsp->walk_callback(addr, &t, wsp->walk_cbdata));
}

static int
sespec_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	mdb_sespec_t s;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&s, sizeof (s), addr) == -1) {
		mdb_warn("failed to read sespec at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)s.se_selist.ml_next;
	return (wsp->walk_callback(addr, &s, wsp->walk_cbdata));
}

static int
vespec_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	mdb_vespec_t v;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&v, sizeof (v), addr) == -1) {
		mdb_warn("failed to read vespec at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)v.ve_list.ml_next;
	return (wsp->walk_callback(addr, &v, wsp->walk_cbdata));
}

static int
se_matched_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	mdb_sespec_t s;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&s, sizeof (s), addr) == -1) {
		mdb_warn("failed to read sespec at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)s.se_matched;
	return (wsp->walk_callback(addr, &s, wsp->walk_cbdata));
}

static const mdb_dcmd_t dcmds[] = {
	{ "mdb_stack", "?", "print debugger stack", cmd_stack },
	{ "mdb_frame", ":", "print debugger frame", cmd_frame },
	{ "mdb_iob", ":", "print i/o buffer information", cmd_iob },
	{ "mdb_in", NULL, "print stdin iob", cmd_in },
	{ "mdb_out", NULL, "print stdout iob", cmd_out },
	{ "mdb_err", NULL, "print stderr iob", cmd_err },
	{ "mdb_tgt", "?", "print current target", cmd_target },
	{ "mdb_sespec", ":", "print software event specifier", cmd_sespec },
	{ "mdb_vespec", ":", "print virtual event specifier", cmd_vespec },
	{ "kmdb_wr", NULL, "print a work queue entry", cmd_wr },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "mdb_frame", "iterate over mdb_frame stack",
		frame_walk_init, frame_walk_step, NULL },
	{ "mdb_iob_stack", "iterate over mdb_iob_stack elements",
		iob_stack_walk_init, iob_stack_walk_step, NULL },
	{ "mdb_tgt", "iterate over active targets",
		target_walk_init, target_walk_step, NULL },
	{ "mdb_sespec", "iterate over software event specifiers",
		NULL, sespec_walk_step, NULL },
	{ "mdb_vespec", "iterate over virtual event specifiers",
		NULL, vespec_walk_step, NULL },
	{ "se_matched", "iterate over matched software event specifiers",
		NULL, se_matched_walk_step, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	char buf[256];
	uintptr_t addr;
	int rcount;
	GElf_Sym sym;

	if (mdb_lookup_by_name("mdb", &sym) == -1) {
		mdb_warn("failed to read mdb state structure");
		return (NULL);
	}

	if (sym.st_size != sizeof (mdb_t)) {
		mdb_printf("mdb: WARNING: mdb_ds may not match mdb "
		    "implementation (mdb_t mismatch)\n");
	}

	if (mdb_readvar(&addr, "_mdb_abort_str") != -1 && addr != 0 &&
	    mdb_readstr(buf, sizeof (buf), addr) > 0)
		mdb_printf("mdb: debugger failed with error: %s\n", buf);

	if (mdb_readvar(&rcount, "_mdb_abort_rcount") != -1 && rcount != 0)
		mdb_printf("mdb: WARNING: resume executed %d times\n", rcount);

	return (&modinfo);
}
