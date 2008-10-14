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

#include <sys/types.h>
#include <sys/mdb_modapi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>

#include <sys/nsctl/nsctl.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>

#include <sys/nsctl/sv.h>
#include <sys/nsctl/sv_impl.h>

#include <sys/nsctl/nsvers.h>

/*
 * Walker for an array of sv_dev_t structures.
 * A global walk is assumed to start at sv_devs.
 */

struct sv_dev_winfo {
	uintptr_t start;
	uintptr_t end;
};


static int
sv_dev_winit(mdb_walk_state_t *wsp)
{
	struct sv_dev_winfo *winfo;
	sv_dev_t *sv_devs;
	int sv_max_devices;

	winfo = mdb_zalloc(sizeof (struct sv_dev_winfo), UM_SLEEP);

	if (mdb_readvar(&sv_devs, "sv_devs") == -1) {
		mdb_warn("failed to read 'sv_devs'");
		mdb_free(winfo,  sizeof (struct sv_dev_winfo));
		return (WALK_ERR);
	}

	if (mdb_readvar(&sv_max_devices, "sv_max_devices") == -1) {
		mdb_warn("failed to read 'sv_max_devices'");
		mdb_free(winfo, sizeof (struct sv_dev_winfo));
		return (WALK_ERR);
	}

	winfo->start = (uintptr_t)sv_devs;
	winfo->end = (uintptr_t)(sv_devs + sv_max_devices);

	if (wsp->walk_addr == NULL)
		wsp->walk_addr = winfo->start;

	wsp->walk_data = winfo;
	return (WALK_NEXT);
}


static int
sv_dev_wstep(mdb_walk_state_t *wsp)
{
	struct sv_dev_winfo *winfo = wsp->walk_data;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (wsp->walk_addr >= winfo->end)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr += sizeof (sv_dev_t);
	return (status);
}


static void
sv_dev_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct sv_dev_winfo));
}


/*
 * Walker for an sv hash chain.
 * Global walks are disallowed.
 */

static int
sv_hash_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	wsp->walk_data = mdb_zalloc(sizeof (sv_dev_t), UM_SLEEP);

	return (WALK_NEXT);
}


static int
sv_hash_wstep(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data,
	    sizeof (sv_dev_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read sv_dev at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((sv_dev_t *)wsp->walk_data)->sv_hash);
	return (status);
}


static void
sv_hash_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (sv_dev_t));
}


/*
 * Walker for an array of sv_maj_t structures.
 * A global walk is assumed to start at sv_majors.
 */

sv_maj_t *sv_majors[SV_MAJOR_HASH_CNT + 1] = {0};

static int
sv_maj_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		if (mdb_readvar(&sv_majors, "sv_majors") == -1) {
			mdb_warn("failed to read 'sv_majors'");
			return (WALK_ERR);
		}
	} else {
		sv_majors[0] = (sv_maj_t *)wsp->walk_addr;
	}

	wsp->walk_addr = (uintptr_t)&sv_majors[0];
	wsp->walk_data = mdb_zalloc(sizeof (sv_maj_t), UM_SLEEP);

	return (WALK_NEXT);
}


static int
sv_maj_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t addr;
	int status = DCMD_OK;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (wsp->walk_addr >= (uintptr_t)&sv_majors[SV_MAJOR_HASH_CNT])
		return (WALK_DONE);

	for (addr = *(uintptr_t *)wsp->walk_addr; addr;
		addr = (uintptr_t)(((sv_maj_t *)wsp->walk_data)->sm_next)) {

		if (mdb_vread(wsp->walk_data, sizeof (sv_maj_t), addr)
							!= sizeof (sv_maj_t)) {
			mdb_warn("failed to read sv_maj at %p", addr);
			status = DCMD_ERR;
			break;
		}

		status = wsp->walk_callback(addr, wsp->walk_data,
						wsp->walk_cbdata);
		if (status != DCMD_OK)
			break;
	}

	wsp->walk_addr += sizeof (sv_maj_t *);
	return (status);
}


static void
sv_maj_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (sv_maj_t));
}


/*
 * Walker for an sv gclient chain.
 * A global walk is assumed to start at sv_gclients.
 */

static int
sv_gclient_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "sv_gclients") == -1) {
		mdb_warn("unable to read 'sv_gclients'");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_zalloc(sizeof (sv_gclient_t), UM_SLEEP);

	return (WALK_NEXT);
}


static int
sv_gclient_wstep(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data,
	    sizeof (sv_gclient_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read sv_gclient at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((sv_gclient_t *)wsp->walk_data)->sg_next);
	return (status);
}


static void
sv_gclient_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (sv_gclient_t));
}


/*
 * Display a single sv_glcient_t structure.
 * If called with no address, performs a global walk of all sv_gclients.
 */
static int
sv_gclient(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	sv_gclient_t sg;
	char name[64];

	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		/*
		 * paranoid mode on: qualify walker name with module name
		 * using '`' syntax.
		 */
		if (mdb_walk_dcmd("sv`sv_gclient",
		    "sv`sv_gclient", argc, argv) == -1) {
			mdb_warn("failed to walk 'sv_gclient'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&sg, sizeof (sg), addr) != sizeof (sg)) {
		mdb_warn("failed to read sv_gclient at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8T%-?s  %8T%-16s  %8T%s\n",
		    "ADDR", "NEXT", "ID", "NAME");
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)sg.sg_name) == -1) {
		mdb_warn("failed to read sv_gclient name at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%p  %8T%p  %8T%llx  %8T%s",
	    addr, sg.sg_next, sg.sg_id, name);

	return (DCMD_OK);
}


/*
 * Display a single sv_maj_t structure.
 * If called with no address, performs a global walk of all sv_majs.
 * -a : all (i.e. display all devices, even if disabled
 * -v : verbose
 */
static int
sv_maj(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	sv_maj_t *maj;
	int a_opt, v_opt;
	int i;

	a_opt = v_opt = FALSE;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &a_opt,
	    'v', MDB_OPT_SETBITS, TRUE, &v_opt) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		/*
		 * paranoid mode on: qualify walker name with module name
		 * using '`' syntax.
		 */
		if (mdb_walk_dcmd("sv`sv_maj", "sv`sv_maj", argc, argv) == -1) {
			mdb_warn("failed to walk 'sv_maj'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8T%s\n", "ADDR", "INUSE");
	}

	maj = mdb_zalloc(sizeof (*maj), UM_GC);
	if (mdb_vread(maj, sizeof (*maj), addr) != sizeof (*maj)) {
		mdb_warn("failed to read sv_maj at %p", addr);
		return (DCMD_ERR);
	}

	if (!a_opt && maj->sm_inuse == 0)
		return (DCMD_OK);

	mdb_printf("%?p  %8T%d\n", addr, maj->sm_inuse);

	if (!v_opt)
		return (DCMD_OK);

	/*
	 * verbose - print the rest of the structure as well.
	 */

	mdb_inc_indent(4);
	mdb_printf("\n");

	mdb_printf("dev_ops: %a (%p)\n", maj->sm_dev_ops, maj->sm_dev_ops);
	mdb_printf("flag: %08x %8Tsequence: %d %8Tmajor: %d\n",
		maj->sm_flag, maj->sm_seq, maj->sm_major);

	mdb_printf("function pointers:\n");
	mdb_inc_indent(4);
	mdb_printf("%-20a%-20a%\n%-20a%-20a%\n%-20a%-20a%\n%-20a%-20a%\n",
		maj->sm_open, maj->sm_close,
		maj->sm_read, maj->sm_write,
		maj->sm_aread, maj->sm_awrite,
		maj->sm_strategy, maj->sm_ioctl);
	mdb_dec_indent(4);


	mdb_printf("hash chain:\n");
	mdb_inc_indent(4);
	for (i = 0; i < SV_MINOR_HASH_CNT; i++) {
		mdb_printf("%?p", maj->sm_hash[i]);
		mdb_printf(((i % 4) == 3) ? "\n" : " %8T");
	}
	mdb_printf("\n\n");
	mdb_dec_indent(4);
	mdb_dec_indent(4);
	return (DCMD_OK);
}


/*
 * Display a sv_dev_t hash chain.
 * Requires an address.
 * Same options as sv_dev().
 */
static int
sv_hash(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	/*
	 * paranoid mode on: qualify walker name with module name
	 * using '`' syntax.
	 */
	if (mdb_pwalk_dcmd("sv`sv_hash", "sv`sv_dev", argc, argv, addr) == -1) {
		mdb_warn("failed to walk sv_dev hash chain");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}


/*
 * Display a single sv_dev_t structure.
 * If called with no address, performs a global walk of all sv_devs.
 * -a : all (i.e. display all devices, even if disabled
 * -v : verbose
 */

const mdb_bitmask_t sv_flag_bits[] = {
	{ "NSC_DEVICE", NSC_DEVICE, NSC_DEVICE },
	{ "NSC_CACHE", NSC_CACHE, NSC_CACHE },
	{ NULL, 0, 0 }
};

static int
sv_dev(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	sv_dev_t *svp;
	int a_opt, v_opt;
	int dev_t_chars;

	a_opt = v_opt = FALSE;
	dev_t_chars = sizeof (dev_t) * 2;	/* # chars to display dev_t */

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &a_opt,
	    'v', MDB_OPT_SETBITS, TRUE, &v_opt) != argc)
		return (DCMD_USAGE);

	svp = mdb_zalloc(sizeof (*svp), UM_GC);

	if (!(flags & DCMD_ADDRSPEC)) {
		/*
		 * paranoid mode on: qualify walker name with module name
		 * using '`' syntax.
		 */
		if (mdb_walk_dcmd("sv`sv_dev", "sv`sv_dev", argc, argv) == -1) {
			mdb_warn("failed to walk 'sv_dev'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8T%-*s  %8T%s\n", "ADDR",
		    dev_t_chars, "DEV", "STATE");
	}

	if (mdb_vread(svp, sizeof (*svp), addr) != sizeof (*svp)) {
		mdb_warn("failed to read sv_dev at %p", addr);
		return (DCMD_ERR);
	}

	if (!a_opt && svp->sv_state == SV_DISABLE)
		return (DCMD_OK);

	mdb_printf("%?p  %8T%0*lx  %8T", addr, dev_t_chars, svp->sv_dev);

	if (svp->sv_state == SV_DISABLE)
		mdb_printf("disabled");
	else if (svp->sv_state == SV_PENDING)
		mdb_printf("pending");
	else if (svp->sv_state == SV_ENABLE)
		mdb_printf("enabled");

	mdb_printf("\n");

	if (!v_opt)
		return (DCMD_OK);

	/*
	 * verbose - print the rest of the structure as well.
	 */

	mdb_inc_indent(4);
	mdb_printf("\n");

	mdb_printf("hash chain: 0x%p  %8Tlock: 0x%p  %8Tolock: 0x%p\n",
	    svp->sv_hash,
	    addr + OFFSETOF(sv_dev_t, sv_lock),
	    addr + OFFSETOF(sv_dev_t, sv_olock));

	mdb_printf("fd: 0x%p  %8T\n", svp->sv_fd);

	mdb_printf("maxfbas: %d  %8Tnblocks: %d  %8Tstate: %d\n",
	    svp->sv_maxfbas, svp->sv_nblocks, svp->sv_state);

	mdb_printf("gclients: 0x%llx  %8Tgkernel: 0x%llx\n",
	    svp->sv_gclients, svp->sv_gkernel);

	mdb_printf("openlcnt: %d  %8Ttimestamp: 0x%lx\n",
	    svp->sv_openlcnt, svp->sv_timestamp);

	mdb_printf("flags: 0x%08x <%b>\n",
	    svp->sv_flag, svp->sv_flag, sv_flag_bits);

	mdb_printf("lh: 0x%p  %8Tpending: 0x%p\n",
	    svp->sv_lh, svp->sv_pending);

	mdb_dec_indent(4);
	return (DCMD_OK);
}


/*
 * Display general sv module information.
 */

#define	sv_get_print(kvar, str, fmt, val)		\
	if (mdb_readvar(&(val), #kvar) == -1) {		\
		mdb_dec_indent(4);			\
		mdb_warn("unable to read '" #kvar "'");	\
		return (DCMD_ERR);			\
	}						\
	mdb_printf("%-20s" fmt "\n", str ":", val)

/* ARGSUSED */
static int
sv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	clock_t clock;
	int maj, min, mic, baseline, i;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_readvar(&maj, "sv_major_rev") == -1) {
		mdb_warn("unable to read 'sv_major_rev'");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&min, "sv_minor_rev") == -1) {
		mdb_warn("unable to read 'sv_minor_rev'");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&mic, "sv_micro_rev") == -1) {
		mdb_warn("unable to read 'sv_micro_rev'");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&baseline, "sv_baseline_rev") == -1) {
		mdb_warn("unable to read 'sv_baseline_rev'");
		return (DCMD_ERR);
	}

	mdb_printf("SV module version: kernel %d.%d.%d.%d; mdb %d.%d.%d.%d\n",
	    maj, min, mic, baseline,
	    ISS_VERSION_MAJ, ISS_VERSION_MIN, ISS_VERSION_MIC, ISS_VERSION_NUM);
	mdb_inc_indent(4);

	sv_get_print(sv_config_time, "last config time", "0x%lx", clock);
	sv_get_print(sv_stats_on, "stats on", "%d", i);
	sv_get_print(sv_debug, "debug", "%d", i);
	sv_get_print(sv_max_devices, "max sv devices", "%d", i);

	mdb_dec_indent(4);
	return (DCMD_OK);
}


/*
 * MDB module linkage information:
 */

static const mdb_dcmd_t dcmds[] = {
	{ "sv", NULL, "display sv module info", sv },
	{ "sv_dev", "?[-av]", "list sv_dev structure", sv_dev },
	{ "sv_gclient", "?", "list sv_gclient structure", sv_gclient },
	{ "sv_hash", ":[-av]", "display sv_dev hash chain", sv_hash },
	{ "sv_maj", "?[-av]", "list sv_maj structure", sv_maj },
	{ NULL }
};


static const mdb_walker_t walkers[] = {
	{ "sv_dev", "walk array of sv_dev structures",
	    sv_dev_winit, sv_dev_wstep, sv_dev_wfini },
	{ "sv_gclient", "walk sb_gclient chain",
	    sv_gclient_winit, sv_gclient_wstep, sv_gclient_wfini },
	{ "sv_hash", "walk sv_dev hash chain",
	    sv_hash_winit, sv_hash_wstep, sv_hash_wfini },
	{ "sv_maj", "walk array of sv_maj structures",
	    sv_maj_winit, sv_maj_wstep, sv_maj_wfini },
	{ NULL }
};


static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};


const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
