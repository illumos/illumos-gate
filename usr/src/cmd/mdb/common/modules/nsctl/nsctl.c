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
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/ddi.h>

#include <sys/mdb_modapi.h>

#define	__NSC_GEN__
#include <sys/nsc_thread.h>
#include <sys/nsctl/nsc_dev.h>
#include <sys/nsctl/nsc_gen.h>
#include <sys/nsctl/nsc_mem.h>
#include <sys/nsctl/nsctl.h>
#include <sys/nsctl/nsc_disk.h>


/*
 * Data struct for the complex walks.
 */

struct complex_args {
	int		argc;
	mdb_arg_t	*argv;
};


/*
 * Bit definitions
 */

#define	NSC_RW_BITS	\
	{ "NSC_READ", NSC_READ, NSC_READ },	\
	{ "NSC_WRITE", NSC_WRITE, NSC_WRITE }


static const mdb_bitmask_t nsc_bhflag_bits[] = {
	NSC_RW_BITS,
	{ "NSC_PINNABLE", NSC_PINNABLE, NSC_PINNABLE },
	{ "NSC_NOBLOCK", NSC_NOBLOCK, NSC_NOBLOCK },
	{ "NSC_HALLOCATED", NSC_HALLOCATED, NSC_HALLOCATED },
	{ "NSC_HACTIVE", NSC_HACTIVE, NSC_HACTIVE },
	{ "NSC_BCOPY", NSC_BCOPY, NSC_BCOPY },
	{ "NSC_PAGEIO", NSC_PAGEIO, NSC_PAGEIO },
	{ "NSC_ABUF", NSC_ABUF, NSC_ABUF },
	{ "NSC_MIXED", NSC_MIXED, NSC_MIXED },
	{ "NSC_WRTHRU", NSC_WRTHRU, NSC_WRTHRU },
	{ "NSC_FORCED_WRTHRU", NSC_FORCED_WRTHRU, NSC_FORCED_WRTHRU },
	{ "NSC_NOCACHE", NSC_NOCACHE, NSC_NOCACHE },
	{ "NSC_QUEUE", NSC_QUEUE, NSC_QUEUE },
	{ "NSC_RDAHEAD", NSC_RDAHEAD, NSC_RDAHEAD },
	{ "NSC_NO_FORCED_WRTHRU", NSC_NO_FORCED_WRTHRU, NSC_NO_FORCED_WRTHRU },
	{ "NSC_METADATA", NSC_METADATA, NSC_METADATA },
	{ "NSC_SEQ_IO", NSC_SEQ_IO, NSC_SEQ_IO },
	{ NULL, 0, 0 }
};


static const mdb_bitmask_t nsc_fdflag_bits[] = {
	NSC_RW_BITS,
	{ NULL, 0, 0 }
};


static const mdb_bitmask_t nsc_fdmode_bits[] = {
	{ "NSC_MULTI", NSC_MULTI, NSC_MULTI },
	{ NULL, 0, 0 }
};


static const mdb_bitmask_t nsc_type_bits[] = {
	/* types */
	{ "NSC_NULL", NSC_NULL, NSC_NULL },
	{ "NSC_DEVICE", NSC_DEVICE, NSC_DEVICE },
	{ "NSC_FILE", NSC_FILE, NSC_FILE },
	{ "NSC_CACHE", NSC_CACHE, NSC_CACHE },
	{ "NSC_VCHR", NSC_VCHR, NSC_VCHR },
	{ "NSC_NCALL", NSC_NCALL, NSC_NCALL },

	/* type flags */
	{ "NSC_ANON", NSC_ANON, NSC_ANON },

	/* ids */
	{ "NSC_RAW_ID", NSC_RAW_ID, NSC_RAW_ID },
	{ "NSC_FILE_ID", NSC_FILE_ID, NSC_FILE_ID },
	{ "NSC_FREEZE_ID", NSC_FREEZE_ID, NSC_FREEZE_ID },
	{ "NSC_VCHR_ID", NSC_VCHR_ID, NSC_VCHR_ID },
	{ "NSC_NCALL_ID", NSC_NCALL_ID, NSC_NCALL_ID },
	{ "NSC_SDBC_ID", NSC_SDBC_ID, NSC_SDBC_ID },
	{ "NSC_RDCLR_ID", NSC_RDCLR_ID, NSC_RDCLR_ID },
	{ "NSC_RDCL_ID", NSC_RDCL_ID, NSC_RDCL_ID },
	{ "NSC_IIR_ID", NSC_IIR_ID, NSC_IIR_ID },
	{ "NSC_II_ID", NSC_II_ID, NSC_II_ID },
	{ "NSC_RDCHR_ID", NSC_RDCHR_ID, NSC_RDCHR_ID },
	{ "NSC_RDCH_ID", NSC_RDCH_ID, NSC_RDCH_ID },
	{ NULL, 0, 0 }
};


static const mdb_bitmask_t nsc_availpend_bits[] = {
	NSC_RW_BITS,
	{ "_NSC_OPEN", _NSC_OPEN, _NSC_OPEN },
	{ "_NSC_CLOSE", _NSC_CLOSE, _NSC_CLOSE },
	{ "_NSC_PINNED", _NSC_PINNED, _NSC_PINNED },
	{ "_NSC_ATTACH", _NSC_ATTACH, _NSC_ATTACH },
	{ "_NSC_DETACH", _NSC_DETACH, _NSC_DETACH },
	{ "_NSC_OWNER", _NSC_OWNER, _NSC_OWNER },
	{ NULL, 0, 0 }
};


static const mdb_bitmask_t nsc_ioflag_bits[] = {
	{ "NSC_REFCNT", NSC_REFCNT, NSC_REFCNT },
	{ "NSC_FILTER", NSC_FILTER, NSC_FILTER },
	{ NULL, 0, 0 }
};


static const mdb_bitmask_t nstset_flag_bits[] = {
	{ "NST_SF_KILL", NST_SF_KILL, NST_SF_KILL },
	{ NULL, 0, 0 }
};


static const mdb_bitmask_t nst_flag_bits[] = {
	{ "NST_TF_INUSE", NST_TF_INUSE, NST_TF_INUSE },
	{ "NST_TF_ACTIVE", NST_TF_ACTIVE, NST_TF_ACTIVE },
	{ "NST_TF_PENDING", NST_TF_PENDING, NST_TF_PENDING },
	{ "NST_TF_DESTROY", NST_TF_DESTROY, NST_TF_DESTROY },
	{ "NST_TF_KILL", NST_TF_KILL, NST_TF_KILL },
	{ NULL, 0, 0 }
};


/*
 * Global data.
 */

static nsc_mem_t type_mem[20];
static int complex_walk;
static int complex_hdr;


/* ---------------------------------------------------------------------- */

/*
 * Walker for an nsc_io chain.
 * A global walk is assumed to start at _nsc_io_top.
 */

static int
nsc_io_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "_nsc_io_top") == -1) {
		mdb_warn("unable to read '_nsc_io_top'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


static int
nsc_io_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t next;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	next = wsp->walk_addr + OFFSETOF(nsc_io_t, next);

	if (mdb_vread(&wsp->walk_addr, sizeof (uintptr_t), next) == -1) {
		mdb_warn("failed to read nsc_io_t.next at %p", next);
		return (WALK_DONE);
	}

	return (status);
}


/* ---------------------------------------------------------------------- */

/*
 * Walker for an nsc_dev chain.
 * A global walk is assumed to start at _nsc_dev_top.
 */

static int
nsc_dev_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "_nsc_dev_top") == -1) {
		mdb_warn("unable to read '_nsc_dev_top'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


static int
nsc_dev_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t next;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	next = wsp->walk_addr + OFFSETOF(nsc_dev_t, nsc_next);

	if (mdb_vread(&wsp->walk_addr, sizeof (uintptr_t), next) == -1) {
		mdb_warn("failed to read nsc_dev_t.nsc_next at %p", next);
		return (WALK_DONE);
	}

	return (status);
}


/* ARGSUSED */

static void
nsc_dev_wfini(mdb_walk_state_t *wsp)
{
	complex_walk = 0;
}


/* ---------------------------------------------------------------------- */

/*
 * Walker for a chain of nsc_devval_t structures.
 * Global walks start from _nsc_devval_top;
 */

static int
nsc_devval_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "_nsc_devval_top") == -1) {
		mdb_warn("unable to read '_nsc_devval_top'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


static int
nsc_devval_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t devval = wsp->walk_addr;
	int status;

	if (!devval)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* move on to next devval */

	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
	    devval + OFFSETOF(nsc_devval_t, dv_next)) == -1) {
		mdb_warn("failed to read nsc_devval_t.dv_next");
		return (WALK_ERR);
	}

	return (status);
}


/* ---------------------------------------------------------------------- */

/*
 * Walker for a chain of nsc_fd_t structures.
 * No global walks.
 */

static int
nsc_fd_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("nsc_fd doesn't support global walks");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


static int
nsc_fd_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t fd = wsp->walk_addr;
	int status;

	if (!fd)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* move on to next fd */

	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
	    fd + OFFSETOF(nsc_fd_t, sf_next)) == -1) {
		mdb_warn("failed to read nsc_fd_t.sf_next");
		return (WALK_ERR);
	}

	return (status);
}


/* ---------------------------------------------------------------------- */

/*
 * Walker for a chain of nsc_iodev_t structures.
 * No global walks.
 */

static int
nsc_iodev_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("nsc_iodev doesn't support global walks");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


static int
nsc_iodev_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t iodev = wsp->walk_addr;
	int status;

	if (!iodev)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
	    iodev + OFFSETOF(nsc_iodev_t, si_next)) == -1) {
		mdb_warn("failed to read nsc_iodev_t.si_next");
		return (WALK_ERR);
	}

	return (status);
}


/* ---------------------------------------------------------------------- */

/*
 * Walker for a chain of nsc_service_t structures.
 * Global walks start at _nsc_services.
 */

static int
nsc_service_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "_nsc_services") == -1) {
		mdb_warn("unable to read '_nsc_services'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


static int
nsc_service_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t service = wsp->walk_addr;
	int status;

	if (!service)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* move on to next service */

	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
	    service + OFFSETOF(nsc_service_t, s_next)) == -1) {
		mdb_warn("failed to read nsc_service_t.s_next");
		return (WALK_ERR);
	}

	return (status);
}


/* ---------------------------------------------------------------------- */

/*
 * Walker for a chain of nsc_svc_t structures.
 * No global walks.
 */

static int
nsc_svc_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("nsc_svc does not support global walks");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


static int
nsc_svc_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t svc = wsp->walk_addr;
	int status;

	if (!svc)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* move on to next svc */

	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
	    svc + OFFSETOF(nsc_svc_t, svc_next)) == -1) {
		mdb_warn("failed to read nsc_svc_t.svc_next");
		return (WALK_ERR);
	}

	return (status);
}


/* ---------------------------------------------------------------------- */

/*
 * Walker for a chain of nsc_val_t structures.
 * No global walks.
 */

static int
nsc_val_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("nsc_val doesn't support global walks");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


static int
nsc_val_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t val = wsp->walk_addr;
	int status;

	if (!val)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* move on to next val */

	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
	    val + OFFSETOF(nsc_val_t, sv_next)) == -1) {
		mdb_warn("failed to read nsc_val_t.sv_next");
		return (WALK_ERR);
	}

	return (status);
}


/* ---------------------------------------------------------------------- */

/*
 * Walker for a chain of nstset_t structures.
 * Global walks start at _nst_sets.
 */

static int
nstset_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "nst_sets") == -1) {
		mdb_warn("unable to read 'nst_sets'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


static int
nstset_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t set = wsp->walk_addr;
	int status;

	if (!set)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* move on to next set */

	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
	    set + OFFSETOF(nstset_t, set_next)) == -1) {
		mdb_warn("failed to read nstset_t.set_next");
		return (WALK_ERR);
	}

	return (status);
}


/* ---------------------------------------------------------------------- */

/*
 * Walker for a chain of nsthread_t structures.
 * No global walks.
 */

static int
nsthread_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("nsthread does not support global walks");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


static int
nsthread_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t thread = wsp->walk_addr;
	int status;

	if (!thread)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* move on to next iodev */

	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
	    thread + OFFSETOF(nsthread_t, tp_chain)) == -1) {
		mdb_warn("failed to read nsthread_t.tp_chain");
		return (WALK_ERR);
	}

	return (status);
}


/* ---------------------------------------------------------------------- */

/*
 * Walker for nsthread_t free/reuse chain.
 * No global walks.
 */

static int
nst_free_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("nst_free does not support global walks");
		return (WALK_ERR);
	}

	/* store starting address */

	wsp->walk_data = (void *)wsp->walk_addr;

	/* move on to next thread */

	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
	    wsp->walk_addr + OFFSETOF(nsthread_t, tp_link.q_forw)) == -1) {
		mdb_warn("failed to read nsthread_t.tp_link.q_forw");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


static int
nst_free_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t thread = wsp->walk_addr;
	int status;

	if (!thread)
		return (WALK_DONE);

	if (thread == (uintptr_t)wsp->walk_data)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* move on to next thread */

	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
	    thread + OFFSETOF(nsthread_t, tp_link.q_forw)) == -1) {
		mdb_warn("failed to read nsthread_t.tp_link.q_forw");
		return (WALK_ERR);
	}

	return (status);
}


/* ---------------------------------------------------------------------- */

/*
 * Walker for a chain of nsc_mem_t structures.
 * Global walks start at _nsc_mem_top.
 */

static int
nsc_mem_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "_nsc_mem_top") == -1) {
		mdb_warn("unable to read '_nsc_mem_top'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


static int
nsc_mem_wstep(mdb_walk_state_t *wsp)
{
	uintptr_t mem = wsp->walk_addr;
	int status;

	if (!mem)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* move on to next mem */

	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
	    mem + OFFSETOF(nsc_mem_t, next)) == -1) {
		mdb_warn("failed to read nsc_mem_t.next");
		return (WALK_ERR);
	}

	return (status);
}


/* ---------------------------------------------------------------------- */

struct {
	char	*name;
	int	id;
} io_ids[] = {
	{ "NSC_RAW_ID", NSC_RAW_ID },
	{ "NSC_FILE_ID", NSC_FILE_ID },
	{ "NSC_FREEZE_ID", NSC_FREEZE_ID },
	{ "NSC_SDBC_ID", NSC_SDBC_ID },
	{ "NSC_RDCLR_ID", NSC_RDCLR_ID },
	{ "NSC_RDCL_ID", NSC_RDCL_ID },
	{ "NSC_IIR_ID", NSC_IIR_ID },
	{ "NSC_II_ID", NSC_II_ID },
	{ "NSC_RDCHR_ID", NSC_RDCHR_ID },
	{ "NSC_RDCH_ID", NSC_RDCH_ID },
	{ NULL, 0 }
};


static char *
nsc_io_id(const int id)
{
	int i;

	for (i = 0; io_ids[i].name != NULL; i++) {
		if (io_ids[i].id == id) {
			return (io_ids[i].name);
		}
	}

	return ("unknown");
}


/*
 * Display a single nsc_io_t structure.
 * If called with no address, performs a global walk of all nsc_ios.
 */
static int
nsc_io(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char io_name[128];
	nsc_io_t *io;
	int v_opt;

	v_opt = 0;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &v_opt) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("nsctl`nsc_io",
		    "nsctl`nsc_io", argc, argv) == -1) {
			mdb_warn("failed to walk 'nsc_io'");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	io = mdb_zalloc(sizeof (*io), UM_SLEEP | UM_GC);
	memset(io_name, 0, sizeof (io_name));

	if (mdb_vread(io, sizeof (*io), addr) != sizeof (*io)) {
		mdb_warn("failed to read nsc_io at %p", addr);
		return (DCMD_ERR);
	}

	if (io->name) {
		if (mdb_readstr(io_name, sizeof (io_name),
		    (uintptr_t)io->name) == -1) {
			mdb_warn("failed to read nsc_io_t.name");
			return (DCMD_ERR);
		}
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8Tid       fl  ref abuf name\n", "io");
	}

	mdb_printf("%0?p  %8T%08x %2x %4d %4d %s\n",
	    addr, io->id, io->flag, io->refcnt, io->abufcnt, io_name);

	if (!v_opt)
		return (DCMD_OK);

	mdb_inc_indent(4);

	mdb_printf("id: %08x <%s>\n", io->id, nsc_io_id(io->id));

	mdb_printf("provide: %08x <%b>\n", io->provide,
	    io->provide, nsc_type_bits);

	mdb_printf("flag: %08x <%b>\n", io->flag, io->flag, nsc_ioflag_bits);

	mdb_printf("pend: %d\n", io->pend);

	mdb_dec_indent(4);

	return (DCMD_OK);
}


/* ---------------------------------------------------------------------- */

/*
 * Display a single nsc_dev_t structure.
 * If called with no address, performs a global walk of all nsc_devs.
 */
static int
nsc_dev(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char path[NSC_MAXPATH+1];
	nsc_devval_t *dv;
	nsc_dev_t *dev;
	uintptr_t dev_pend;
	int a_opt, v_opt;

	a_opt = v_opt = 0;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &a_opt,
	    'v', MDB_OPT_SETBITS, TRUE, &v_opt) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_printf("Active device structures:\n");

		if (mdb_walk_dcmd("nsctl`nsc_dev",
		    "nsctl`nsc_dev", argc, argv) == -1) {
			mdb_warn("failed to walk 'nsc_dev'");
			return (DCMD_ERR);
		}

		if (a_opt) {
			if (mdb_readvar(&dev_pend, "_nsc_dev_pend") == -1) {
				mdb_warn("failed to read _nsc_dev_pend");
				return (DCMD_ERR);
			}

			mdb_printf("\nPending device structures:");

			if (dev_pend) {
				mdb_printf("\n");

				if (mdb_pwalk_dcmd("nsctl`nsc_dev",
				    "nsctl`nsc_dev", argc, argv,
				    dev_pend) == -1) {
					mdb_warn("failed to walk "
					    "pending dev structs");
					return (DCMD_ERR);
				}
			} else {
				mdb_printf(" none\n");
			}
		}

		return (DCMD_OK);
	}

	memset(path, 0, sizeof (path));
	dev = mdb_zalloc(sizeof (*dev), UM_SLEEP | UM_GC);

	if (mdb_vread(dev, sizeof (*dev), addr) != sizeof (*dev)) {
		mdb_warn("failed to read nsc_dev at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_readstr(path, sizeof (path), (uintptr_t)dev->nsc_path) == -1) {
		mdb_warn("failed to read nsc_path at %p", dev->nsc_path);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8Tref pend rpnd wait path\n", "dev");
	}

	mdb_printf("%0?p  %8T%3d %4d %4d %4d %s\n",
	    addr, dev->nsc_refcnt, dev->nsc_pend, dev->nsc_rpend,
	    dev->nsc_wait, path);

	if (!v_opt)
		return (DCMD_OK);

	mdb_inc_indent(4);

	mdb_printf("next: %0?p  %8Tclose: %0?p\n",
	    dev->nsc_next, dev->nsc_close);

	mdb_printf("list: %0?p  %8Tlock: %0?p\n",
	    dev->nsc_list, addr + OFFSETOF(nsc_dev_t, nsc_lock));

	mdb_printf("cv: %0?p  %8Tpath: %0?p  %8Tphash: %016llx\n",
	    addr + OFFSETOF(nsc_dev_t, nsc_cv),
	    dev->nsc_path, dev->nsc_phash);

	mdb_printf("drop: %d  %8Treopen: %d\n",
	    dev->nsc_drop, dev->nsc_reopen);

	if (dev->nsc_values) {
		dv = mdb_zalloc(sizeof (*dv), UM_SLEEP | UM_GC);
		if (mdb_vread(dv, sizeof (*dv), (uintptr_t)dev->nsc_values) !=
		    sizeof (*dv)) {
			mdb_warn("unable to read nsc_dev_t.nsc_values");
			mdb_dec_indent(4);
			return (DCMD_ERR);
		}

		if (dv->dv_values) {
			mdb_printf("device/values: (nsc_devval: %0?p)\n",
			    dev->nsc_values);

			mdb_inc_indent(4);

			if (mdb_pwalk_dcmd("nsctl`nsc_val", "nsctl`nsc_val",
			    0, NULL, (uintptr_t)dv->dv_values) == -1) {
				mdb_dec_indent(8);
				return (DCMD_ERR);
			}

			mdb_dec_indent(4);
		}
	}

	mdb_dec_indent(4);

	return (DCMD_OK);
}


/* ---------------------------------------------------------------------- */

/*
 * Display a single nsc_devval_t structure.
 * If called with no address, performs a global walk of all nsc_devs.
 */
static int
nsc_devval(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nsc_devval_t *dv;
	int a_opt;

	a_opt = 0;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &a_opt) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("nsctl`nsc_devval",
		    "nsctl`nsc_devval", argc, argv) == -1) {
			mdb_warn("failed to walk 'nsc_devval'");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	dv = mdb_zalloc(sizeof (*dv), UM_SLEEP | UM_GC);

	if (mdb_vread(dv, sizeof (*dv), addr) != sizeof (*dv)) {
		mdb_warn("failed to read nsc_devval at %p", addr);
		return (DCMD_ERR);
	}

	if (!a_opt && !dv->dv_values) {
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8T%?-s  %8Tpath\n", "devval", "phash");
	}

	mdb_printf("%0?p  %8T%016llx  %8T%s\n", addr,
	    dv->dv_phash, dv->dv_path);

	mdb_inc_indent(4);

	if (dv->dv_values) {
		if (mdb_pwalk_dcmd("nsctl`nsc_val", "nsctl`nsc_val",
		    0, NULL, (uintptr_t)dv->dv_values) == -1) {
			return (DCMD_ERR);
		}
	} else {
		mdb_printf("No values\n");
	}

	mdb_dec_indent(4);

	return (DCMD_OK);
}


/* ---------------------------------------------------------------------- */

/*
 * Part 2 callback for the all devices and fds walk.  Called per iodev.
 */
/* ARGSUSED */
static int
nsc_fd_iodev(uintptr_t addr, const void *data, void *cbdata)
{
	struct complex_args *fdall = cbdata;
	struct nsc_fd_t *fd;

	if (mdb_vread(&fd, sizeof (fd),
	    addr + OFFSETOF(nsc_iodev_t, si_open)) == -1) {
		mdb_warn("unable to read nsc_iodev_t.si_open");
		return (WALK_ERR);
	}

	if (fd != NULL) {
		if (mdb_pwalk_dcmd("nsctl`nsc_fd", "nsctl`nsc_fd",
		    fdall->argc, fdall->argv, (uintptr_t)fd) == -1)
			return (WALK_ERR);
	}

	return (WALK_NEXT);
}


/*
 * Part 1 callback for the all devices and fds walk.  Called per device.
 */
/* ARGSUSED */
static int
nsc_fd_dev(uintptr_t addr, const void *data, void *cbdata)
{
	struct complex_args *fdall = cbdata;
	nsc_iodev_t *iodev;
	nsc_fd_t *fd;

	if (mdb_vread(&iodev, sizeof (iodev),
	    addr + OFFSETOF(nsc_dev_t, nsc_list)) == -1) {
		mdb_warn("unable to read nsc_dev_t.nsc_list at %p", addr);
		return (WALK_ERR);
	}

	/* walk iodev chains */

	if (iodev != NULL) {
		if (mdb_pwalk("nsctl`nsc_iodev",
		    nsc_fd_iodev, fdall, (uintptr_t)iodev) == -1)
			return (WALK_ERR);
	}

	/* walk nsc_close (closing fds) chains */

	if (mdb_vread(&fd, sizeof (fd),
	    addr + OFFSETOF(nsc_dev_t, nsc_close)) == -1) {
		mdb_warn("unable to read nsc_dev_t.nsc_close at %p", addr);
		return (WALK_ERR);
	}

	if (fd != NULL) {
		if (mdb_pwalk_dcmd("nsctl`nsc_fd", "nsctl`nsc_fd",
		    fdall->argc, fdall->argv, (uintptr_t)fd) == -1)
			return (WALK_ERR);
	}

	return (WALK_NEXT);
}


/*
 * Walk all devices and fds in the system.
 */
static int
nsc_fd_all(int argc, const mdb_arg_t *argv)
{
	struct complex_args fdall;

	fdall.argc = argc;
	fdall.argv = (mdb_arg_t *)argv;

	complex_walk = 1;
	complex_hdr = 0;

	if (mdb_walk("nsctl`nsc_dev", nsc_fd_dev, &fdall) == -1) {
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}



/*
 * Display an nsd_fd_t structure, or walk all devices and fds in the system.
 */
static int
nsc_fd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char io_name[128], *io_namep;
	char path[NSC_MAXPATH+1];
	uintptr_t pathp;
	nsc_fd_t *fd;
	nsc_io_t *io;
	int v_opt;
	int hdr;

	v_opt = 0;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &v_opt) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		return (nsc_fd_all(argc, argv));
	}

	memset(path, 0, sizeof (path));
	fd = mdb_zalloc(sizeof (*fd), UM_SLEEP | UM_GC);
	memset(io_name, 0, sizeof (io_name));

	if (mdb_vread(fd, sizeof (*fd), addr) != sizeof (*fd)) {
		mdb_warn("failed to read nsc_fd at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&pathp, sizeof (pathp),
	    (uintptr_t)fd->sf_dev + OFFSETOF(nsc_dev_t, nsc_path)) !=
	    sizeof (pathp)) {
		mdb_warn("failed to read nsc_dev.nsc_path");
		return (DCMD_ERR);
	}

	if (mdb_readstr(path, sizeof (path), pathp) == -1) {
		mdb_warn("failed to read nsc_path");
		return (DCMD_ERR);
	}

	if (fd->sf_iodev) {
		if (mdb_vread(&io, sizeof (io),
		    (uintptr_t)fd->sf_iodev + OFFSETOF(nsc_iodev_t, si_io)) !=
		    sizeof (io)) {
			mdb_warn("failed to read nsc_iodev.si_io");
			return (DCMD_ERR);
		}

		if (mdb_vread(&io_namep, sizeof (io_namep),
		    (uintptr_t)io + OFFSETOF(nsc_io_t, name)) !=
		    sizeof (io_namep)) {
			mdb_warn("failed to read nsc_io_t.name");
			return (DCMD_ERR);
		}

		if (mdb_readstr(io_name, sizeof (io_name),
		    (uintptr_t)io_namep) == -1) {
			mdb_warn("failed to read nsc_io_t.name string");
			return (DCMD_ERR);
		}
	}

	hdr = 0;
	if (complex_walk) {
		if (!complex_hdr) {
			complex_hdr = 1;
			hdr = 1;
		}
	} else if (DCMD_HDRSPEC(flags)) {
		hdr = 1;
	}

	if (hdr) {
		mdb_printf("%-?s  %8T%-?s  %8T%-8s  %-?s\n",
		    "fd", "dev", "io", "cd");
		mdb_printf("    %-?s  %8Trv pend av path\n", "arg");
	}

	mdb_printf("%0?p  %8T%0?p  %8T%-8s  %p\n",
	    addr, fd->sf_dev, io_name, fd->sf_cd);
	mdb_printf("    %0?p  %8T%2d %4x %2x %s\n",
	    fd->sf_arg, fd->sf_reserve, fd->sf_pend,
	    fd->sf_avail, path);

	if (!v_opt)
		return (DCMD_OK);

	mdb_inc_indent(4);

	mdb_printf("open type: %08x <%b>\n", fd->sf_type,
	    fd->sf_type, nsc_type_bits);

	mdb_printf("avail: %08x <%b>\n", fd->sf_avail,
	    fd->sf_avail, nsc_availpend_bits);

	mdb_printf("flag: %08x <%b>\n", fd->sf_flag,
	    fd->sf_flag, nsc_fdflag_bits);

	mdb_printf("rsrv mode: %08x <%b>\n", fd->sf_mode,
	    fd->sf_mode, nsc_fdmode_bits);

	mdb_printf("open lbolt: %?x  %8Treopen: %d\n", fd->sf_lbolt,
	    fd->sf_reopen);

	mdb_dec_indent(4);

	return (DCMD_OK);
}


/* ---------------------------------------------------------------------- */

/*
 * Callback for the all devices and iodevs walk.  Called per device.
 */
/* ARGSUSED */
static int
nsc_iodev_dev(uintptr_t addr, const void *data, void *cbdata)
{
	struct complex_args *iodevall = cbdata;
	uintptr_t iodev;

	if (mdb_vread(&iodev, sizeof (iodev),
	    addr + OFFSETOF(nsc_dev_t, nsc_list)) == -1) {
		mdb_warn("unable to read nsc_dev_t.nsc_list at %p", addr);
		return (WALK_ERR);
	}

	/* walk iodev chains */

	if (iodev != NULL) {
		if (mdb_pwalk_dcmd("nsctl`nsc_iodev", "nsctl`nsc_iodev",
		    iodevall->argc, iodevall->argv, iodev) == -1)
			return (WALK_ERR);
	}

	return (WALK_NEXT);
}


/*
 * Walk all devices and iodevs in the system.
 */
static int
nsc_iodev_all(int argc, const mdb_arg_t *argv)
{
	struct complex_args iodevall;

	iodevall.argc = argc;
	iodevall.argv = (mdb_arg_t *)argv;

	complex_walk = 1;
	complex_hdr = 0;

	if (mdb_walk("nsctl`nsc_dev", nsc_iodev_dev, &iodevall) == -1) {
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}


/*
 * Display an nsc_iodev_t structure, or walk all devices and
 * iodevs in the system.
 */
static int
nsc_iodev(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char io_name[128], *io_namep;
	char path[NSC_MAXPATH+1];
	nsc_iodev_t *iodev;
	uintptr_t pathp;
	int v_opt;
	int hdr;

	v_opt = 0;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &v_opt) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		return (nsc_iodev_all(argc, argv));
	}

	memset(path, 0, sizeof (path));
	iodev = mdb_zalloc(sizeof (*iodev), UM_SLEEP | UM_GC);
	memset(io_name, 0, sizeof (io_name));

	if (mdb_vread(iodev, sizeof (*iodev), addr) != sizeof (*iodev)) {
		mdb_warn("failed to read nsc_iodev at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&pathp, sizeof (pathp),
	    (uintptr_t)iodev->si_dev + OFFSETOF(nsc_dev_t, nsc_path)) !=
	    sizeof (pathp)) {
		mdb_warn("failed to read nsc_dev.nsc_path");
		return (DCMD_ERR);
	}

	if (mdb_readstr(path, sizeof (path), pathp) == -1) {
		mdb_warn("failed to read nsc_path");
		return (DCMD_ERR);
	}

	if (mdb_vread(&io_namep, sizeof (io_namep),
	    (uintptr_t)iodev->si_io + OFFSETOF(nsc_io_t, name)) !=
	    sizeof (io_namep)) {
		mdb_warn("failed to read nsc_io_t.name");
		return (DCMD_ERR);
	}

	if (mdb_readstr(io_name, sizeof (io_name),
	    (uintptr_t)io_namep) == -1) {
		mdb_warn("failed to read nsc_io_t.name string");
		return (DCMD_ERR);
	}

	hdr = 0;
	if (complex_walk) {
		if (!complex_hdr) {
			complex_hdr = 1;
			hdr = 1;
		}
	} else if (DCMD_HDRSPEC(flags)) {
		hdr = 1;
	}

	if (hdr) {
		mdb_printf("%-?s  %8T%-?s  ref %-8s path\n",
		    "iodev", "dev", "io");
	}

	mdb_printf("%0?p  %8T%0?p  %3d %-8s %s\n",
	    addr, iodev->si_dev, iodev->si_refcnt, io_name, path);

	if (!v_opt)
		return (DCMD_OK);

	mdb_inc_indent(4);

	mdb_printf("open fds: %?p  %8Tactive ios: %?p\n",
	    iodev->si_open, iodev->si_active);

	mdb_printf("busy: %d  %8Trsrv pend: %d\n",
	    iodev->si_busy, iodev->si_rpend);

	mdb_printf("pend: %08x <%b>\n", iodev->si_pend,
	    iodev->si_pend, nsc_availpend_bits);

	mdb_printf("avail: %08x <%b>\n", iodev->si_avail,
	    iodev->si_avail, nsc_availpend_bits);

	mdb_dec_indent(4);

	return (DCMD_OK);
}


/* ---------------------------------------------------------------------- */

/*
 * Display an nsc_service_t structure, or walk all services.
 */
static int
nsc_service(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nsc_service_t *service;
	char s_name[32];
	int v_opt;

	v_opt = 0;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &v_opt) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("nsctl`nsc_service",
		    "nsctl`nsc_service", argc, argv) == -1) {
			mdb_warn("failed to walk 'nsc_service'");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	service = mdb_zalloc(sizeof (*service), UM_SLEEP | UM_GC);

	if (mdb_vread(service, sizeof (*service), addr) != sizeof (*service)) {
		mdb_warn("failed to read nsc_service at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8Tname\n", "service");
	}

	memset(s_name, 0, sizeof (s_name));
	if (service->s_name) {
		if (mdb_readstr(s_name, sizeof (s_name),
		    (uintptr_t)service->s_name) == -1) {
			mdb_warn("failed to read nsc_io_t.name");
			return (DCMD_ERR);
		}
	}

	mdb_printf("%0?p  %8T%s\n", addr, s_name);

	if (!v_opt)
		return (DCMD_OK);

	mdb_inc_indent(4);

	mdb_printf("servers:\n");
	if (service->s_servers == NULL) {
		mdb_printf("<none>\n");
	} else {
		mdb_inc_indent(4);
		if (mdb_pwalk_dcmd("nsctl`nsc_svc", "nsctl`nsc_svc",
		    argc, argv, (uintptr_t)service->s_servers) == -1) {
			mdb_dec_indent(8);
			return (DCMD_ERR);
		}
		mdb_dec_indent(4);
	}

	mdb_printf("clients:\n");
	if (service->s_clients == NULL) {
		mdb_printf("<none>\n");
	} else {
		mdb_inc_indent(4);
		if (mdb_pwalk_dcmd("nsctl`nsc_svc", "nsctl`nsc_svc",
		    argc, argv, (uintptr_t)service->s_clients) == -1) {
			mdb_dec_indent(8);
			return (DCMD_ERR);
		}
		mdb_dec_indent(4);
	}

	mdb_dec_indent(4);

	return (DCMD_OK);
}


/* ---------------------------------------------------------------------- */

/*
 * Display an nsc_svc_t structure.
 */
/*ARGSUSED*/
static int
nsc_svc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nsc_svc_t *svc;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	svc = mdb_zalloc(sizeof (*svc), UM_SLEEP | UM_GC);

	if (mdb_vread(svc, sizeof (*svc), addr) != sizeof (*svc)) {
		mdb_warn("failed to read nsc_svc at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8T%-?s  %8Tfunc\n", "svc", "service");
	}

	mdb_printf("%0?p  %8T%0?p  %8T%a\n", addr, svc->svc_svc, svc->svc_fn);
	return (DCMD_OK);
}


/* ---------------------------------------------------------------------- */

/*
 * Display a single nsc_val_t structure.
 * If called with no address, performs a global walk of all nsc_devs.
 */
/* ARGSUSED3 */
static int
nsc_val(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nsc_val_t *vp;

	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("nsc_val requires an address");
		return (DCMD_ERR);
	}

	vp = mdb_zalloc(sizeof (*vp), UM_SLEEP | UM_GC);

	if (mdb_vread(vp, sizeof (*vp), addr) != sizeof (*vp)) {
		mdb_warn("failed to read nsc_val at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8T%8-s  %8Tname\n", "val", "value");
	}

	mdb_printf("%0?p  %8T%08x  %8T%s\n", addr, vp->sv_value, vp->sv_name);

	return (DCMD_OK);
}


/* ---------------------------------------------------------------------- */

/*
 * Display an nstset_t structure, or walk all sets.
 */

static int
nstset(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nstset_t *set;
	int f_opt, r_opt, t_opt, v_opt;

	f_opt = r_opt = t_opt = v_opt = 0;

	if (mdb_getopts(argc, argv,
	    'f', MDB_OPT_SETBITS, TRUE, &f_opt,		/* free list */
	    'r', MDB_OPT_SETBITS, TRUE, &r_opt,		/* reuse list */
	    't', MDB_OPT_SETBITS, TRUE, &t_opt,		/* all threads */
	    'v', MDB_OPT_SETBITS, TRUE, &v_opt) != argc)
		return (DCMD_USAGE);

	/* displaying threads implies verbose */
	if (f_opt || r_opt || t_opt)
		v_opt = 1;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("nsctl`nstset",
		    "nsctl`nstset", argc, argv) == -1) {
			mdb_warn("failed to walk 'nstset'");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	set = mdb_zalloc(sizeof (*set), UM_SLEEP | UM_GC);

	if (mdb_vread(set, sizeof (*set), addr) != sizeof (*set)) {
		mdb_warn("failed to read nstset at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8T  live   nthr flag name\n", "set");
	}

	mdb_printf("%0?p  %8T%6d %6d %4x %s\n", addr,
	    set->set_nlive, set->set_nthread, set->set_flag, set->set_name);

	if (!v_opt)
		return (DCMD_OK);

	mdb_inc_indent(4);

	mdb_printf("chain: %0?p  %8Tpending: %4d  res_cnt: %4d\n",
	    set->set_chain, set->set_pending, set->set_res_cnt);

	if (set->set_reuse.q_forw == set->set_reuse.q_back &&
	    (uintptr_t)set->set_reuse.q_forw ==
	    (addr + OFFSETOF(nstset_t, set_reuse))) {
		mdb_printf("reuse.forw: %-?s  %8Treuse.back: %s\n",
		    "empty", "empty");
	} else {
		mdb_printf("reuse.forw: %0?p  %8Treuse.back: %0?p\n",
		    set->set_reuse.q_forw, set->set_reuse.q_back);

		/* display all threads in reuse list */
		if (r_opt &&
		    mdb_pwalk_dcmd("nsctl`nst_free", "nsctl`nsthread",
		    0, (const mdb_arg_t *)NULL,
		    (addr + OFFSETOF(nstset_t, set_reuse))) == -1) {
			mdb_dec_indent(4);
			return (DCMD_ERR);
		}
	}

	if (set->set_free.q_forw == set->set_free.q_back &&
	    (uintptr_t)set->set_free.q_forw ==
	    (addr + OFFSETOF(nstset_t, set_free))) {
		mdb_printf("free.forw:  %-?s  %8Tfree.back:  %s\n",
		    "empty", "empty");
	} else {
		mdb_printf("free.forw:  %0?p  %8Tfree.back:  %0?p\n",
		    set->set_free.q_forw, set->set_free.q_back);

		/* display all threads in free list */
		if (f_opt &&
		    mdb_pwalk_dcmd("nsctl`nst_free", "nsctl`nsthread",
		    0, (const mdb_arg_t *)NULL,
		    (addr + OFFSETOF(nstset_t, set_free))) == -1) {
			mdb_dec_indent(4);
			return (DCMD_ERR);
		}
	}

	mdb_printf("flag: %08x <%b>\n",
	    set->set_flag, set->set_flag, nstset_flag_bits);

	/* display all threads in set */
	if (t_opt) {
		mdb_printf("all threads in set:\n");
		if (mdb_pwalk_dcmd("nsctl`nsthread", "nsctl`nsthread",
		    0, (const mdb_arg_t *)NULL,
		    (uintptr_t)set->set_chain) == -1) {
			mdb_dec_indent(4);
			return (DCMD_ERR);
		}
	}

	mdb_dec_indent(4);

	return (DCMD_OK);
}


/* ---------------------------------------------------------------------- */

/*
 * Callback for the all nstsets and threads walk.  Called per set.
 */
/* ARGSUSED */
static int
nst_thr_set(uintptr_t addr, const void *data, void *cbdata)
{
	struct complex_args *thrall = cbdata;
	char set_name[48];
	uintptr_t tp;

	if (mdb_vread(&tp, sizeof (tp),
	    addr + OFFSETOF(nstset_t, set_chain)) == -1) {
		mdb_warn("unable to read nstset_t.set_chain at %p", addr);
		return (WALK_ERR);
	}

	memset(set_name, 0, sizeof (set_name));

	if (mdb_readstr(set_name, sizeof (set_name),
	    addr + OFFSETOF(nstset_t, set_name)) == -1) {
		mdb_warn("unable to read nstset_t.set_name at %p", addr);
	}

	mdb_printf("nstset: %0?p (%s)\n", addr, set_name);

	/* walk thread chains */

	if (tp != NULL) {
		if (mdb_pwalk_dcmd("nsctl`nsthread", "nsctl`nsthread",
		    thrall->argc, thrall->argv, tp) == -1)
			return (WALK_ERR);
	} else
		mdb_printf("    no threads\n");

	mdb_printf("\n");

	return (WALK_NEXT);
}


/*
 * Walk all nstsets and threads in the system.
 */
static int
nst_thr_all(int argc, const mdb_arg_t *argv)
{
	struct complex_args thrall;

	thrall.argc = argc;
	thrall.argv = (mdb_arg_t *)argv;

	if (mdb_walk("nsctl`nstset", nst_thr_set, &thrall) == -1)
		return (DCMD_ERR);

	return (DCMD_OK);
}


/*
 * Display an nsthread_t structure, or walk all threads.
 */

static int
nsthread(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t thrpend;
	nsthread_t *tp;
	int a_opt, v_opt;
	int rc;

	a_opt = v_opt = 0;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &a_opt,
	    'v', MDB_OPT_SETBITS, TRUE, &v_opt) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if ((rc = nst_thr_all(argc, argv)) != DCMD_OK)
			return (rc);

		if (a_opt) {
			if (mdb_readvar(&thrpend, "nst_pending") == -1) {
				mdb_warn("unable to read 'nst_pending'");
				return (DCMD_ERR);
			}

			if (thrpend) {
				mdb_printf("\nPending threads:\n");

				if (mdb_pwalk_dcmd("nsctl`nsthread",
				    "nsctl`nsthread", argc, argv,
				    thrpend) == -1) {
					mdb_warn("failed to walk 'nsthread'");
					return (DCMD_ERR);
				}
			}
		}

		return (DCMD_OK);
	}

	tp = mdb_zalloc(sizeof (*tp), UM_SLEEP | UM_GC);

	if (mdb_vread(tp, sizeof (*tp), addr) != sizeof (*tp)) {
		mdb_warn("failed to read nsthread at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8Tflag %-?s  %8Tfunc\n", "thread", "arg");
	}

	mdb_printf("%0?p  %8T%4x %0?p  %8T%a\n",
	    addr, tp->tp_flag, tp->tp_arg, tp->tp_func);

	if (!v_opt)
		return (DCMD_OK);

	mdb_inc_indent(4);

	mdb_printf("set: %0?p  %8Tchain: %0?p\n",
	    tp->tp_set, tp->tp_chain);

	mdb_printf("link.forw: %0?p  %8Tlink.back: %0?p\n",
	    tp->tp_link.q_forw, tp->tp_link.q_back);

	mdb_printf("flag: %08x <%b>\n",
	    tp->tp_flag, tp->tp_flag, nst_flag_bits);

	mdb_dec_indent(4);

	return (DCMD_OK);
}


/* ---------------------------------------------------------------------- */

static void
nsc_rmap(char *name)
{
	nsc_rmmap_t slot;
	uintptr_t addr;
	int nslot;
	char *cp;

	if (mdb_readvar(&addr, name) == -1) {
		mdb_warn("unable to read rmap '%s'", name);
		return;
	}

	if (mdb_vread(&slot, sizeof (slot), addr) != sizeof (slot)) {
		mdb_warn("unable to read rmap '%s' slot 0", name);
		return;
	}

	mdb_printf("\nmap name		offset      size    nslot\n");
	mdb_printf("%16s     %9d %9d    %5d\n",
	    slot.name, slot.offset, slot.size, slot.inuse);

	nslot = slot.inuse;
	mdb_printf("\nslot name	       offset      size    inuse\n");

	while (--nslot) {
		addr += sizeof (slot);

		if (mdb_vread(&slot, sizeof (slot), addr) != sizeof (slot)) {
			mdb_warn("unable to read rmap '%s' slot @ %p",
			    name, addr);
			return;
		}

		if (!slot.inuse || !slot.size)
			continue;

		for (cp = slot.name; *cp; cp++)
			if (*cp == ':')
				*cp = ' ';

		mdb_printf("%16s     %9d %9d %08x\n",
		    slot.name, slot.offset, slot.size, slot.inuse);
	}
}


static void
nsc_rmhdr(void)
{
	nsc_rmhdr_t *rmhdr = mdb_zalloc(sizeof (*rmhdr), UM_SLEEP | UM_GC);
	uintptr_t addr;

	if (mdb_readvar(&addr, "_nsc_rmhdr_ptr") == -1) {
		mdb_warn("unable to read _nsc_rmhdr_ptr");
		return;
	}

	if (!addr) {
		mdb_printf("\n\nGlobal header not initialised\n");
		return;
	}

	if (mdb_vread(rmhdr, sizeof (*rmhdr), addr) != sizeof (*rmhdr)) {
		mdb_warn("unable to read global header at %p", addr);
		return;
	}

	mdb_printf("\n\nglobal header    (magic %08x, version %d, size %d)\n",
	    rmhdr->magic, rmhdr->ver, rmhdr->size);

	nsc_rmap("_nsc_global_map");
}


static nsc_mem_t *
memptr(int type, int flag)
{
	int i;

	type &= NSC_MEM_GLOBAL;

	if (type)
		flag = 0;

	if (!type && !flag)
		return (&type_mem[0]);

	for (i = 1; i < (sizeof (type_mem) / sizeof (nsc_mem_t)); i++) {
		if (!type_mem[i].flag && !type_mem[i].type) {
			type_mem[i].flag = flag;
			type_mem[i].type = type;
			return (&type_mem[i]);
		}

		if (type_mem[i].flag == flag && type_mem[i].type == type)
			return (&type_mem[i]);
	}

	return (&type_mem[i]);
}


#define	typename(t)	\
		(((t) & NSC_MEM_GLOBAL) ? "gbl" : " - ")

#define	memname(t)	\
		(((t) & NSC_MEM_GLOBAL) ? "nsc_global" : "system kmem")

static void
nsc_mem_type(const int first, nsc_mem_t *mp)
{
	char *type, *name;

	if (first) {
		mdb_printf("\nregion	   typ  f      ");
		mdb_printf("used       hwm    pgs  alloc  free\n");
	}

	type = typename(mp->type);
	name = memname(mp->type);

	mdb_printf("%16s %s %2x %9d %9d %6d  %5d %5d\n",
	    name, type, mp->flag, mp->used, mp->hwm, mp->pagehwm,
	    mp->nalloc, mp->nfree);
}


static int
nsc_mem_all(int argc, const mdb_arg_t *argv, int v_opt)
{
	int first;
	int i;

	memset(type_mem, 0, sizeof (type_mem));

	if (mdb_walk_dcmd("nsctl`nsc_mem",
	    "nsctl`nsc_mem", argc, argv) == -1) {
		mdb_warn("unable to walk 'nsc_mem'");
		return (DCMD_ERR);
	}

	for (first = 1, i = 0;
	    i < (sizeof (type_mem) / sizeof (nsc_mem_t)); first = 0, i++) {
		if (type_mem[i].nalloc || type_mem[i].hwm) {
			nsc_mem_type(first, &type_mem[i]);
		}
	}

	if (v_opt)
		nsc_rmhdr();

	return (DCMD_OK);
}


static int
nsc_mem(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char name[16], *type, *cp;
	nsc_mem_t mem, *mp;
	int v_opt;

	v_opt = 0;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &v_opt) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		return (nsc_mem_all(argc, argv, v_opt));
	}

	if (mdb_vread(&mem, sizeof (mem), addr) != sizeof (mem)) {
		mdb_warn("failed to read nsc_mem_t at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)mem.name) == -1) {
		mdb_warn("failed to read nsc_mem_t.name at %p", addr);
		return (DCMD_ERR);
	}

	if (!mem.nalloc && !mem.hwm && !v_opt)
		return (DCMD_OK);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("name	     typ  f      ");
		mdb_printf("used       hwm   pgs alloc  free     base\n");
	}

	type = typename(mem.type);
	mp = memptr(mem.type, mem.flag);

	for (cp = name; *cp; cp++)
		if (*cp == ':')
			*cp = ' ';

	mdb_printf("%-16s %s %2x %9d %9d %5d %5d %5d %0?p\n",
	    name, type, mem.flag, mem.used, mem.hwm, mem.pagehwm,
	    mem.nalloc, mem.nfree, mem.base);

	mp->used += mem.used;
	mp->hwm += mem.hwm;
	mp->pagehwm += mem.pagehwm;
	mp->nalloc += mem.nalloc;
	mp->nfree += mem.nfree;

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
nsc_vec(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nsc_vec_t *vec;

	vec = mdb_zalloc(sizeof (*vec), UM_SLEEP | UM_GC);
	if (mdb_vread(vec, sizeof (*vec), addr) != sizeof (*vec)) {
		mdb_warn("failed to read nsc_vec at %p", addr);
		return (DCMD_ERR);
	}
	mdb_printf("nsc_vec_t @ 0x%p = {\n", addr);
	mdb_inc_indent(4);
	mdb_printf("sv_addr: %p\n", vec->sv_addr);
	mdb_printf("sv_vme:  %lu\n", vec->sv_vme);
	mdb_printf("sv_len:  %d\n", vec->sv_len);
	mdb_dec_indent(4);
	mdb_printf("};\n");
	if (vec->sv_addr)
		return (DCMD_OK);
	else
		return (DCMD_ERR);
}

/* ---------------------------------------------------------------------- */
/*
 * Display an nsc_buf_t structure.
 */

#ifdef NSC_MULTI_TERABYTE
#define	STRCONV	"ll"
#else
#define	STRCONV	""
#endif

/* ARGSUSED */
static int
nsc_buf(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nsc_buf_t *bh;
	nsc_vec_t *v;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	bh = mdb_zalloc(sizeof (*bh), UM_SLEEP | UM_GC);

	if (mdb_vread(bh, sizeof (*bh), addr) != sizeof (*bh)) {
		mdb_warn("failed to read nsc_buf at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("nsc_buf_t @ 0x%p = {\n", addr);
	mdb_inc_indent(4);
	mdb_printf("sb_fd:    0x%p\n", bh->sb_fd);
	mdb_printf("sb_pos:   0x%" STRCONV "x\n", bh->sb_pos);
	mdb_printf("sb_len:   0x%" STRCONV "x\n", bh->sb_len);
	mdb_printf("sb_flag:  0x%08x <%b>\n", bh->sb_flag,
	    bh->sb_flag, nsc_bhflag_bits);
	mdb_printf("sb_error: %d\n", bh->sb_error);
#ifdef NSC_MULTI_TERABYTE
	mdb_printf("sb_user:  0x%p\n", bh->sb_user);
#else
	mdb_printf("sb_user:  0x%x\n", bh->sb_user);
#endif
	mdb_printf("sb_vec:   0x%p\n", bh->sb_vec);
	v = bh->sb_vec++;
	while (nsc_vec((uintptr_t)v, flags, argc, argv) == DCMD_OK)
		v++;

	mdb_dec_indent(4);
	mdb_printf("};\n");

	return (DCMD_OK);
}

/* ---------------------------------------------------------------------- */

/* ARGSUSED */
static int
nsc_dbuf(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nsc_dbuf_t *bh;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	bh = mdb_zalloc(sizeof (*bh), UM_SLEEP | UM_GC);

	if (mdb_vread(bh, sizeof (*bh), addr) != sizeof (*bh)) {
		mdb_warn("failed to read nsc_dbuf at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("nsc_dbuf_t @ 0x%p = {\n", addr);
	mdb_inc_indent(4);
	mdb_printf("db_disc:    0x%p\n", bh->db_disc);
	mdb_printf("db_addr:    0x%p\n", bh->db_addr);
	mdb_printf("db_next:    0x%p\n", bh->db_next);
	mdb_printf("db_maxfbas: 0x%d\n", bh->db_maxfbas);


	mdb_dec_indent(4);
	mdb_printf("};\n");

	return (DCMD_OK);
}
/* ---------------------------------------------------------------------- */

/*
 * MDB module linkage information:
 */

static const mdb_dcmd_t dcmds[] = {
#if 0
	{ "nsctl", NULL, "display nsctl module info", nsctl },
#endif
	{ "nsc_buf", ":", "list nsc_buf structure", nsc_buf },
	{ "nsc_dbuf", ":", "list nsc_dbuf structure", nsc_dbuf },
	{ "nsc_dev", "?[-av]", "list nsc_dev structure", nsc_dev },
	{ "nsc_devval", "?[-a]", "list nsc_devval structure", nsc_devval },
	{ "nsc_fd", "?[-v]", "list nsc_fd structure", nsc_fd },
	{ "nsc_iodev", "?[-v]", "list nsc_iodev structure", nsc_iodev },
	{ "nsc_io", "?[-v]", "list nsc_io structure", nsc_io },
	{ "nsc_mem", "?[-v]", "list nsc_mem structure", nsc_mem },
	{ "nsc_svc", ":", "list nsc_svc structure", nsc_svc },
	{ "nsc_service", "?[-v]", "list nsc_service structure", nsc_service },
	{ "nsc_val", ":", "list nsc_val structure", nsc_val },
	{ "nstset", "?[-frtv]", "list nstset structure", nstset },
	{ "nsthread", "?[-av]", "list nsthread structure", nsthread },
	{ NULL }
};


static const mdb_walker_t walkers[] = {
	{ "nsc_dev", "walk nsc_dev chain",
	    nsc_dev_winit, nsc_dev_wstep, nsc_dev_wfini, NULL },
	{ "nsc_devval", "walk nsc_devval chain",
	    nsc_devval_winit, nsc_devval_wstep, NULL, NULL },
	{ "nsc_fd", "walk nsc_fd chain",
	    nsc_fd_winit, nsc_fd_wstep, NULL, NULL },
	{ "nsc_io", "walk nsc_io chain",
	    nsc_io_winit, nsc_io_wstep, NULL, NULL },
	{ "nsc_iodev", "walk nsc_iodev chain",
	    nsc_iodev_winit, nsc_iodev_wstep, NULL, NULL },
	{ "nsc_mem", "walk nsc_mem chain",
	    nsc_mem_winit, nsc_mem_wstep, NULL, NULL },
	{ "nsc_service", "walk nsc_service chain",
	    nsc_service_winit, nsc_service_wstep, NULL, NULL },
	{ "nsc_svc", "walk nsc_svc chain",
	    nsc_svc_winit, nsc_svc_wstep, NULL, NULL },
	{ "nsc_val", "walk nsc_val chain",
	    nsc_val_winit, nsc_val_wstep, NULL, NULL },
	{ "nstset", "walk nstset chain",
	    nstset_winit, nstset_wstep, NULL, NULL },
	{ "nsthread", "walk nsthread chain",
	    nsthread_winit, nsthread_wstep, NULL, NULL },
	{ "nst_free", "walk nsthread free/reuse list",
	    nst_free_winit, nst_free_wstep, NULL, NULL },
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
