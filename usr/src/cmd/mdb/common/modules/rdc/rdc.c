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

#include <sys/nsctl/nsctl.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>

#include <rpc/auth.h>
#include <rpc/auth_unix.h>
#include <rpc/auth_des.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <rpc/svc_soc.h>

/* HACK HACK  so we can bring in rdc_io.h and friends */
#define	nstset_t	char

#include <sys/nsctl/rdc.h>
#include <sys/nsctl/rdc_prot.h>
#include <sys/nsctl/rdc_ioctl.h>
#include <sys/nsctl/rdc_io.h>
#include <sys/nsctl/rdc_bitmap.h>

#include <sys/nsctl/nsvers.h>


/*
 * Walker for an array of rdc_k_info_t structures.
 * A global walk is assumed to start at rdc_k_info.
 */

struct rdc_kinfo_winfo {
	uintptr_t start;
	uintptr_t end;
};

char bitstr[33] = { '0' };

static int
rdc_k_info_winit(mdb_walk_state_t *wsp)
{
	struct rdc_kinfo_winfo *winfo;
	rdc_k_info_t *rdc_k_info;
	int rdc_max_sets;

	winfo = mdb_zalloc(sizeof (struct rdc_kinfo_winfo), UM_SLEEP);

	if (mdb_readvar(&rdc_k_info, "rdc_k_info") == -1) {
		mdb_warn("failed to read 'rdc_k_info'");
		mdb_free(winfo,  sizeof (struct rdc_kinfo_winfo));
		return (WALK_ERR);
	}

	if (mdb_readvar(&rdc_max_sets, "rdc_max_sets") == -1) {
		mdb_warn("failed to read 'rdc_max_sets'");
		mdb_free(winfo, sizeof (struct rdc_kinfo_winfo));
		return (WALK_ERR);
	}

	winfo->start = (uintptr_t)rdc_k_info;
	winfo->end = (uintptr_t)(rdc_k_info + rdc_max_sets);

	if (wsp->walk_addr == NULL)
		wsp->walk_addr = winfo->start;

	wsp->walk_data = winfo;
	return (WALK_NEXT);
}


static int
rdc_k_info_wstep(mdb_walk_state_t *wsp)
{
	struct rdc_kinfo_winfo *winfo = wsp->walk_data;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (wsp->walk_addr >= winfo->end)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr += sizeof (rdc_k_info_t);
	return (status);
}


static void
rdc_k_info_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct rdc_kinfo_winfo));
}

/*
 * Walker for an array of rdc_u_info_t structures.
 * A global walk is assumed to start at rdc_u_info.
 */

struct rdc_uinfo_winfo {
	uintptr_t start;
	uintptr_t end;
};


static int
rdc_u_info_winit(mdb_walk_state_t *wsp)
{
	struct rdc_uinfo_winfo *winfo;
	rdc_u_info_t *rdc_u_info;
	int rdc_max_sets;

	winfo = mdb_zalloc(sizeof (struct rdc_uinfo_winfo), UM_SLEEP);

	if (mdb_readvar(&rdc_u_info, "rdc_u_info") == -1) {
		mdb_warn("failed to read 'rdc_u_info'");
		mdb_free(winfo,  sizeof (struct rdc_uinfo_winfo));
		return (WALK_ERR);
	}

	if (mdb_readvar(&rdc_max_sets, "rdc_max_sets") == -1) {
		mdb_warn("failed to read 'rdc_max_sets'");
		mdb_free(winfo, sizeof (struct rdc_uinfo_winfo));
		return (WALK_ERR);
	}

	winfo->start = (uintptr_t)rdc_u_info;
	winfo->end = (uintptr_t)(rdc_u_info + rdc_max_sets);

	if (wsp->walk_addr == NULL)
		wsp->walk_addr = winfo->start;

	wsp->walk_data = winfo;
	return (WALK_NEXT);
}


static int
rdc_u_info_wstep(mdb_walk_state_t *wsp)
{
	struct rdc_uinfo_winfo *winfo = wsp->walk_data;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (wsp->walk_addr >= winfo->end)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr += sizeof (rdc_u_info_t);
	return (status);
}


static void
rdc_u_info_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct rdc_uinfo_winfo));
}

/*
 * Walker for the rdc_if chain.
 * A global walk is assumed to start at rdc_if_top.
 */

static int
rdc_if_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "rdc_if_top") == -1) {
		mdb_warn("unable to read 'rdc_if_top'");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_zalloc(sizeof (rdc_if_t), UM_SLEEP);

	return (WALK_NEXT);
}


static int
rdc_if_wstep(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data,
	    sizeof (rdc_if_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read rdc_if at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((rdc_if_t *)wsp->walk_data)->next);
	return (status);
}


static void
rdc_if_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (rdc_if_t));
}

/*
 * Displays the asynchronous sleep q on the server.
 */
/*ARGSUSED*/
static int
rdc_sleepq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_sleepq_t sq;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);
	while (addr) {
		if (mdb_vread(&sq, sizeof (sq), addr) != sizeof (sq)) {
			mdb_warn("failed to read rdc_sleepq at %p", addr);
			return (DCMD_ERR);
		}
		mdb_printf("sequence number %u  qpos %d \n", sq.seq, sq.qpos);
		addr = (uintptr_t)sq.next;
	}
	return (DCMD_OK);
}

/*
 * display the header info for the pending diskq requests
 */
/*ARGSUSED*/
static int
rdc_iohdr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	io_hdr hdr;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	while (addr) {
		if (mdb_vread(&hdr, sizeof (io_hdr), addr) != sizeof (io_hdr)) {
			mdb_warn("failed to read io_hdr at %p", addr);
			return (DCMD_ERR);
		}
		mdb_printf("iohdr: type %d pos %d qpos %d len %d flag 0x%x"
		" iostatus %x setid %d next %p\n", hdr.dat.type, hdr.dat.pos,
		hdr.dat.qpos, hdr.dat.len, hdr.dat.flag, hdr.dat.iostatus,
		hdr.dat.setid, hdr.dat.next);

		addr = (uintptr_t)hdr.dat.next;
	}
	return (DCMD_OK);
}

/*
 * Display a krdc->group.
 * Requires an address.
 */
/*ARGSUSED*/
static int
rdc_group(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct rdc_group *group;
	disk_queue	*dq;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);


	group = mdb_zalloc(sizeof (*group), UM_GC);

	if (mdb_vread(group, sizeof (*group), addr) != sizeof (*group)) {
		mdb_warn("failed to read rdc_group at %p", addr);
		return (DCMD_ERR);
	}
#ifdef XXXJET
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8T%-8s  %8T%s\n", "ADDR", "MAJOR", "INUSE");
	}
#endif
	mdb_printf("count: %d  %8Twriter: %d  %8T flags: %d\n",
	    group->count, group->rdc_writer, group->flags);
	mdb_printf("thread num %d\n", group->rdc_thrnum);

	dq = &group->diskq;
	if (RDC_IS_MEMQ(group)) {
		mdb_printf("queue type: Memory based\n");
	} else if (RDC_IS_DISKQ(group)) {
		mdb_printf("queue type: Disk based  %8Tqstate 0x%x\n",
		    QSTATE(dq));
	}
	mdb_printf("ra_queue head: 0x%p  %8Ttail 0x%p\n",
	    group->ra_queue.net_qhead, group->ra_queue.net_qtail);
	mdb_printf("ra_queue blocks: %d  %8Titems %d\n",
	    group->ra_queue.blocks, group->ra_queue.nitems);
	mdb_printf("ra_queue blockhwm: %d itemhwm: %d\n",
	    group->ra_queue.blocks_hwm, group->ra_queue.nitems_hwm);
	mdb_printf("ra_queue hwmhit: %d qfillsleep: %d\n",
	    group->ra_queue.hwmhit, group->ra_queue.qfill_sleeping);
	mdb_printf("ra_queue throttle: %ld\n",
	    group->ra_queue.throttle_delay);

	if (RDC_IS_DISKQ(group)) {
		mdb_printf("head: %d %8Tnxtio: %d  %8Ttail %d %8Tlastail: %d\n",
		    QHEAD(dq), QNXTIO(dq), QTAIL(dq), LASTQTAIL(dq));
		mdb_printf("coalbounds: %d %8Tqwrap: %d\n", QCOALBOUNDS(dq),
		    QWRAP(dq));
		mdb_printf("blocks: %d  %8Titems %d qfflags 0x%x \n",
		    QBLOCKS(dq), QNITEMS(dq), group->ra_queue.qfflags);
		mdb_printf("diskq throttle: %ld %8Tflags: %x\n",
		    dq->throttle_delay, group->flags);
		mdb_printf("disk queue nitems_hwm: %d %8Tblocks_hwm: %d\n",
		    dq->nitems_hwm, dq->blocks_hwm);
		mdb_printf("diskqfd:   0x%p %8Tdisqrsrv: %d lastio: 0x%p\n",
		    group->diskqfd, group->diskqrsrv, dq->lastio);
		mdb_printf("outstanding req %d iohdrs 0x%p iohdrs_last 0x%p\n",
		    dq->hdrcnt, dq->iohdrs, dq->hdr_last);
	}
	mdb_printf("seq: %u\n", group->seq);
	mdb_printf("seqack: %u\n", group->seqack);
	mdb_printf("sleepq: 0x%p\n", group->sleepq);
	mdb_printf("asyncstall %d\n", group->asyncstall);
	mdb_printf("asyncdis %d\n", group->asyncdis);

	mdb_inc_indent(4);
	if (group->sleepq) {
		rdc_sleepq((uintptr_t)group->sleepq, DCMD_ADDRSPEC,
		    0, 0);
	}
	mdb_dec_indent(4);

	return (DCMD_OK);
}


/*
 * Display a krdc->lsrv.
 * Requires an address.
 */
/*ARGSUSED*/
static int
rdc_srv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_srv_t *lsrv;
	char name[MAX_RDC_HOST_SIZE];

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);


	lsrv = mdb_zalloc(sizeof (*lsrv), UM_GC);

	if (mdb_vread(lsrv, sizeof (*lsrv), addr) != sizeof (*lsrv)) {
		mdb_warn("failed to read rdc_srv at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_readstr(name, sizeof (name),
		(uintptr_t)lsrv->ri_hostname) == -1) {
		mdb_warn("failed to read ri_hostname name at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("host: %s  %16Tri_knconf 0x%p\n", name, lsrv->ri_knconf);

	mdb_printf("ri_addr: 0x%p  %8Tsecdata 0x%p\n",
	    addr + OFFSETOF(rdc_srv_t, ri_addr), lsrv->ri_secdata);

	return (DCMD_OK);
}

/*
 * Display a rdc_if_t.
 * Requires an address.
 */
static int
rdc_if(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_if_t *ifp;

	if (!(flags & DCMD_ADDRSPEC)) {
		/*
		 * paranoid mode on: qualify walker name with module name
		 * using '`' syntax.
		 */
		if (mdb_walk_dcmd("rdc`rdc_if",
			"rdc`rdc_if", argc, argv) == -1) {
			mdb_warn("failed to walk 'rdc_if'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	ifp = mdb_zalloc(sizeof (*ifp), UM_GC);

	if (mdb_vread(ifp, sizeof (*ifp), addr) != sizeof (*ifp)) {
		mdb_warn("failed to read rdc_srv at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("next: 0x%p  %8Tsrv 0x%p\n", ifp->next, ifp->srv);
	mdb_printf("if_addr: 0x%p  %8Tr_ifaddr 0x%p\n",
	    addr + OFFSETOF(rdc_if_t, ifaddr),
	    addr + OFFSETOF(rdc_if_t, r_ifaddr));
	mdb_printf("if_down: %d  %8Tprimary %d  %8Tsecondary  %d\n",
		ifp->if_down, ifp->isprimary, ifp->issecondary);
	mdb_printf("version %d  %8Tnoping  %d\n", ifp->rpc_version,
		ifp->no_ping);
	mdb_printf("\n");

	return (DCMD_OK);
}


/*
 * Display a rdc_buf_t
 * Requires an address.
 */
/*ARGSUSED*/
static int
rdc_buf(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_buf_t *buf;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);


	buf = mdb_zalloc(sizeof (*buf), UM_GC);

	if (mdb_vread(buf, sizeof (*buf), addr) != sizeof (*buf)) {
		mdb_warn("failed to read rdc_buf at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("nsc_buf fd: 0x%p  %8Tvec 0x%p\n",
	    buf->rdc_bufh.sb_fd, buf->rdc_bufh.sb_vec);

	mdb_printf("nsc_buf pos: %d  %8Tlen %d\n",
	    buf->rdc_bufh.sb_pos, buf->rdc_bufh.sb_len);

	mdb_printf("nsc_buf flag: 0x%x  %8Terror %d\n",
	    buf->rdc_bufh.sb_flag, buf->rdc_bufh.sb_error);

	mdb_printf("anon_buf : 0x%p  %8Tfd 0x%p  %8Tbufp  0x%p\n",
	    buf->rdc_anon, buf->rdc_fd, buf->rdc_bufp);

	mdb_printf("vsize: %d  %8Tflags 0x%x\n",
	    buf->rdc_vsize, buf->rdc_flags);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
rdc_aio(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_aio_t *aio;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	aio = mdb_zalloc(sizeof (*aio), UM_GC);

	if (mdb_vread(aio, sizeof (*aio), addr) != sizeof (*aio)) {
		mdb_warn("failed to read rdc_aio at %p", addr);
		return (DCMD_ERR);
	}
	mdb_printf("rdc_aio next: %p %8T nsc_buf: %p %8T nsc_qbuf %p\n",
	    aio->next, aio->handle, aio->qhandle);
	mdb_printf("pos: %d len: %d qpos: %d flag: %x iostatus: %d index: %d"
	    " seq: %d\n", aio->pos, aio->len, aio->qpos, aio->flag,
	    aio->iostatus, aio->index, aio->seq);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
rdc_dset(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_net_dataset_t *dset;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	dset = mdb_zalloc(sizeof (*dset), UM_GC);

	if (mdb_vread(dset, sizeof (*dset), addr) != sizeof (*dset)) {
		mdb_warn("failed to read dset at %p", addr);
		return (DCMD_ERR);
	}
	mdb_printf("dset id: %d %8T dset inuse: %d %8T dset delpend: %d\n",
	    dset->id, dset->inuse, dset->delpend);
	mdb_printf("dset items: %d %8T dset head %p %8T dset tail %p \n",
	    dset->nitems, dset->head, dset->tail);
	mdb_printf("dset pos %d %8T dset len %d\n", dset->pos, dset->fbalen);

	return (DCMD_OK);
}
/*
 * Display a single rdc_k_info structure.
 * If called with no address, performs a global walk of all rdc_k_info.
 * -a : all (i.e. display all devices, even if disabled
 * -v : verbose
 */

const mdb_bitmask_t sv_flag_bits[] = {
	{ "NSC_DEVICE", NSC_DEVICE, NSC_DEVICE },
	{ "NSC_CACHE", NSC_CACHE, NSC_CACHE },
	{ NULL, 0, 0 }
};

static int
rdc_kinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *rdc_u_info, *urdc;
	int a_opt, v_opt;
	int dev_t_chars;

	a_opt = v_opt = FALSE;
	dev_t_chars = sizeof (dev_t) * 2;	/* # chars to display dev_t */

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &a_opt,
	    'v', MDB_OPT_SETBITS, TRUE, &v_opt) != argc)
		return (DCMD_USAGE);

	krdc = mdb_zalloc(sizeof (*krdc), UM_GC);
	urdc = mdb_zalloc(sizeof (*urdc), UM_GC);

	if (!(flags & DCMD_ADDRSPEC)) {
		/*
		 * paranoid mode on: qualify walker name with module name
		 * using '`' syntax.
		 */
		if (mdb_walk_dcmd("rdc`rdc_kinfo",
			"rdc`rdc_kinfo", argc, argv) == -1) {
			mdb_warn("failed to walk 'rdc_kinfo'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8T%-*s  %8T%s\n", "ADDR",
		    dev_t_chars, "TFLAG", "STATE");
	}

	if (mdb_vread(krdc, sizeof (*krdc), addr) != sizeof (*krdc)) {
		mdb_warn("failed to read rdc_k_info at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_readvar(&rdc_u_info, "rdc_u_info") == -1) {
		mdb_warn("failed to read 'rdc_u_info'");
		return (DCMD_ERR);
	}

	urdc = &rdc_u_info[krdc->index];

	if (!a_opt && ((krdc->type_flag & RDC_CONFIGURED) == 0))
		return (DCMD_OK);

	mdb_printf("%?p  %8T%0*lx  %8T", addr, dev_t_chars, krdc->type_flag);


	if (krdc->type_flag & RDC_DISABLEPEND)
		mdb_printf(" disable pending");
	if (krdc->type_flag &  RDC_ASYNCMODE)
		mdb_printf(" async");
	if (krdc->type_flag & RDC_RESUMEPEND)
		mdb_printf(" resume pending");
	if (krdc->type_flag & RDC_BUSYWAIT)
		mdb_printf(" busywait");
#ifdef RDC_SMALLIO
	if (krdc->type_flag & RDC_SMALLIO)
		mdb_printf(" smallio");
#endif

	mdb_printf("\n");

	if (!v_opt)
		return (DCMD_OK);

	/*
	 * verbose - print the rest of the structure as well.
	 */

	mdb_inc_indent(4);

	mdb_printf("index: %d  %8Trindex: %d  %8Tbusyc: %d  %8Tmaxfbas:  %d\n",
	    krdc->index, krdc->remote_index, krdc->busy_count, krdc->maxfbas);

	mdb_printf("info_dev:  0x%p %8Tiodev: 0x%p  %8T %8T vers %d\n",
	krdc->devices, krdc->iodev, krdc->rpc_version);

	mdb_printf("iokstats:  0x%p\n", krdc->io_kstats);
	mdb_printf("group:  0x%p %8Tgroup_next:  0x%p\n",
		krdc->group, krdc->group_next);
	mdb_printf("group lock: 0x%p aux_state: %d\n",
	    &krdc->group->lock, krdc->aux_state);

	mdb_inc_indent(4);
	if (krdc->type_flag & RDC_ASYNCMODE) {
		rdc_group((uintptr_t)krdc->group, DCMD_ADDRSPEC, 0, 0);
	}
	mdb_dec_indent(4);

	mdb_printf("servinfo:  0x%p %8Tintf:  0x%p\nbitmap: 0x%p  %8T"
	    "bitmap_ref:  0x%p\n",
	    krdc->lsrv, krdc->intf, krdc->dcio_bitmap, krdc->bitmap_ref);

	mdb_printf("bmap_size:  %d %8Tbmaprsrv: %d%8T bmap_write:  %d\n",
	    krdc->bitmap_size, krdc->bmaprsrv, krdc->bitmap_write);

	mdb_printf("bitmapfd:  0x%p %8Tremote_fd: 0x%p  %8T\n", krdc->bitmapfd,
	    krdc->remote_fd);

	mdb_printf("net_dataset:  0x%p %8Tdisk_status: %d  %8T\n",
	    krdc->net_dataset, krdc->disk_status);

	mdb_printf("many:  0x%p %8Tmulti: 0x%p  %8T\n", krdc->many_next,
	    krdc->multi_next);

	mdb_printf("rdc_uinfo: 0x%p\n\n", urdc);
	mdb_dec_indent(4);
	return (DCMD_OK);
}


static int
rdc_uinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_u_info_t *urdc;
	rdc_k_info_t *rdc_k_info, *krdc, krdc1;
	rdc_group_t grp;
	disk_queue *dqp = NULL;
	int a_opt, v_opt;
	int dev_t_chars;
	int rdcflags;

	a_opt = v_opt = FALSE;
	dev_t_chars = sizeof (dev_t) * 2;	/* # chars to display dev_t */

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &a_opt,
	    'v', MDB_OPT_SETBITS, TRUE, &v_opt) != argc)
		return (DCMD_USAGE);

	urdc = mdb_zalloc(sizeof (*urdc), UM_GC);
	krdc = mdb_zalloc(sizeof (*krdc), UM_GC);

	if (!(flags & DCMD_ADDRSPEC)) {
		/*
		 * paranoid mode on: qualify walker name with module name
		 * using '`' syntax.
		 */
		if (mdb_walk_dcmd("rdc`rdc_uinfo",
			"rdc`rdc_uinfo", argc, argv) == -1) {
			mdb_warn("failed to walk 'rdc_uinfo'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s  %8T%-*s  %8T%s\n", "ADDR",
		    dev_t_chars, "FLAG", "STATE");
	}

	if (mdb_vread(urdc, sizeof (*urdc), addr) != sizeof (*urdc)) {
		mdb_warn("failed to read rdc_u_info at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_readvar(&rdc_k_info, "rdc_k_info") == -1) {
		mdb_warn("failed to read 'rdc_k_info'");
		return (DCMD_ERR);
	}

	krdc = &rdc_k_info[urdc->index];

	if (!a_opt && ((urdc->flags & RDC_ENABLED) == 0))
		return (DCMD_OK);


	if (mdb_vread(&krdc1, sizeof (krdc1),
	    (uintptr_t)krdc) != sizeof (krdc1)) {
		mdb_warn("failed to read 'rdc_k_info1'");
		return (DCMD_ERR);
	}

	if (krdc1.group) {
		if (mdb_vread(&grp, sizeof (grp),
		    (uintptr_t)krdc1.group) != sizeof (grp)) {
			mdb_warn("failed to read group info ");
			return (DCMD_ERR);
		}
		dqp = &grp.diskq;
	}

	rdcflags = (urdc->flags | urdc->sync_flags | urdc->bmap_flags);
	mdb_printf("%?p  %8T%0*lx  %8T", addr, dev_t_chars, rdcflags);


	if (rdcflags & RDC_PRIMARY)
		mdb_printf(" primary");
	if (rdcflags &  RDC_SLAVE)
		mdb_printf(" slave");
	if (rdcflags &  RDC_SYNCING)
		mdb_printf(" syncing");
	if (rdcflags &  RDC_SYNC_NEEDED)
		mdb_printf(" sync_need");
	if (rdcflags &  RDC_RSYNC_NEEDED)
		mdb_printf(" rsync_need");
	if (rdcflags & RDC_LOGGING)
		mdb_printf(" logging");
	if (rdcflags & RDC_QUEUING)
		mdb_printf(" queuing");
	if (rdcflags & RDC_DISKQ_FAILED)
		mdb_printf(" diskq failed");
	if (rdcflags & RDC_VOL_FAILED)
		mdb_printf(" vol failed");
	if (rdcflags & RDC_BMP_FAILED)
		mdb_printf(" bmp failed");
	if (rdcflags & RDC_ASYNC)
		mdb_printf(" async");
	if (rdcflags & RDC_CLR_AFTERSYNC)
		mdb_printf(" clr_bitmap_aftersync");
	if (dqp) {
		if (IS_QSTATE(dqp, RDC_QNOBLOCK))
			mdb_printf(" noblock");
	}
#ifdef RDC_SMALLIO
	if (rdcflags & RDC_SMALLIO)
		mdb_printf(" smallio");
#endif

	mdb_printf("\n");

	if (!v_opt)
		return (DCMD_OK);

	/*
	 * verbose - print the rest of the structure as well.
	 */

	mdb_inc_indent(4);
	mdb_printf("\n");

	mdb_printf("primary: %s  %8Tfile: %s  \nbitmap: %s  ",
	    urdc->primary.intf, urdc->primary.file, urdc->primary.bitmap);
	mdb_printf("netbuf: 0x%p\n", addr + OFFSETOF(rdc_set_t, primary));
	mdb_printf("secondary: %s  %8Tfile: %s  \nbitmap: %s  ",
	    urdc->secondary.intf, urdc->secondary.file, urdc->secondary.bitmap);
	mdb_printf("netbuf: 0x%p\n", addr + OFFSETOF(rdc_set_t, secondary));

	mdb_printf("sflags:  %d %8Tbflags: %d%8T mflags:  %d\n",
		urdc->sync_flags, urdc->bmap_flags, urdc->mflags);
	mdb_printf("index:  %d %8Tsync_pos: %d%8T vsize:  %d\n",
		urdc->index, urdc->sync_pos, urdc->volume_size);
	mdb_printf("setid:  %d %8Tbits set:  %d %8Tautosync: %d\n",
		urdc->setid, urdc->bits_set, urdc->autosync);
	mdb_printf("maxqfbas:  %d %8Tmaxqitems: %d\n",
		urdc->maxqfbas, urdc->maxqitems);
	mdb_printf("netconfig:  %p\n", urdc->netconfig);
	mdb_printf("group:  %s %8TdirectIO: %s\n",
		urdc->group_name, urdc->direct_file);
	mdb_printf("diskqueue: %s ", urdc->disk_queue);
	if (dqp) {
		mdb_printf("diskqsize: %d\n", QSIZE(dqp));
	} else {
		mdb_printf("\n");
	}
	mdb_printf("rdc_k_info: 0x%p\n", krdc);
	mdb_printf("\n");
	mdb_dec_indent(4);

	mdb_printf("\n");
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
rdc_infodev(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_info_dev_t *infodev;
	_rdc_info_dev_t *infp;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	infodev = mdb_zalloc(sizeof (*infodev), UM_GC);
	infp = mdb_zalloc(sizeof (*infp), UM_GC);

	if (mdb_vread(infodev, sizeof (*infodev), addr) != sizeof (*infodev)) {
		mdb_warn("failed to read rdc_infodev at 0x%p\n", addr);
		return (DCMD_ERR);
	}

	infp = &infodev->id_cache_dev;
	mdb_inc_indent(4);

	mdb_printf("id_next: 0x%p\n", infodev->id_next);
	mdb_printf("id_cache_dev:\n");

	mdb_inc_indent(4);
	mdb_printf("bi_fd: 0x%p %8Tbi_iodev: 0x%p %8Tbi_krdc 0x%p\n",
	    infp->bi_fd, infp->bi_iodev, infp->bi_krdc);
	mdb_printf("bi_rsrv: %d %8Tbi_orsrv: %d %8Tbi_failed: %d %8T\n"
	    "bi_ofailed: %d %8Tbi_flag: %d\n", infp->bi_rsrv, infp->bi_orsrv,
	    infp->bi_failed, infp->bi_ofailed, infp->bi_flag);

	infp = &infodev->id_raw_dev;

	mdb_dec_indent(4);
	mdb_printf("id_cache_dev:\n");
	mdb_inc_indent(4);

	mdb_printf("bi_fd: 0x%p %8Tbi_iodev: 0x%p %8Tbi_krdc 0x%p\n",
	    infp->bi_fd, infp->bi_iodev, infp->bi_krdc);
	mdb_printf("bi_rsrv: %d %8Tbi_orsrv: %d %8Tbi_failed: %d %8T\n"
	    "bi_ofailed: %d %8Tbi_flag: %d\n", infp->bi_rsrv, infp->bi_orsrv,
	    infp->bi_failed, infp->bi_ofailed, infp->bi_flag);

	mdb_dec_indent(4);

	mdb_printf("id_sets: %d %8Tid_release: %d %8Tid_flag %d",
	    infodev->id_sets, infodev->id_release, infodev->id_flag);

	if (infodev->id_flag & RDC_ID_CLOSING) {
		mdb_printf("closing");
	}
	mdb_printf("\n");

	mdb_dec_indent(4);
	return (DCMD_OK);
}

/*
 * Display general sv module information.
 */

#define	rdc_get_print(kvar, str, fmt, val)		\
	if (mdb_readvar(&(val), #kvar) == -1) {		\
		mdb_dec_indent(4);			\
		mdb_warn("unable to read '" #kvar "'");	\
		return (DCMD_ERR);			\
	}						\
	mdb_printf("%-20s" fmt "\n", str ":", val)

/*ARGSUSED*/
static int
rdc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int maj, min, mic, baseline, i;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_readvar(&maj, "sndr_major_rev") == -1) {
		mdb_warn("unable to read 'sndr_major_rev'");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&min, "sndr_minor_rev") == -1) {
		mdb_warn("unable to read 'sndr_minor_rev'");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&mic, "sndr_micro_rev") == -1) {
		mdb_warn("unable to read 'sndr_micro_rev'");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&baseline, "sndr_baseline_rev") == -1) {
		mdb_warn("unable to read 'sndr_baseline_rev'");
		return (DCMD_ERR);
	}

	mdb_printf("Remote Mirror module version: kernel %d.%d.%d.%d; "
		    "mdb %d.%d.%d.%d\n", maj, min, mic, baseline,
	    ISS_VERSION_MAJ, ISS_VERSION_MIN, ISS_VERSION_MIC, ISS_VERSION_NUM);
	mdb_inc_indent(4);

	rdc_get_print(rdc_debug, "debug", "%d", i);
	rdc_get_print(rdc_bitmap_mode, "bitmap mode", "%d", i);
	rdc_get_print(rdc_max_sets, "max sndr devices", "%d", i);
	rdc_get_print(rdc_rpc_tmout, "client RPC timeout", "%d", i);
	rdc_get_print(rdc_health_thres, "health threshold", "%d", i);
	rdc_get_print(MAX_RDC_FBAS, "max trans fba", "%d", i);

	mdb_dec_indent(4);
	return (DCMD_OK);
}

static int
rdc_k2u(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *rdc_u_info, *urdc;
	int rc;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	krdc = mdb_zalloc(sizeof (*krdc), UM_GC);
	urdc = mdb_zalloc(sizeof (*urdc), UM_GC);

	if (mdb_vread(krdc, sizeof (*krdc), addr) != sizeof (*krdc)) {
		mdb_warn("failed to read krdc at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_readvar(&rdc_u_info, "rdc_u_info") == -1) {
		mdb_warn("failed to read 'rdc_u_info'");
		return (DCMD_ERR);
	}

	urdc = &rdc_u_info[krdc->index];

	rc = rdc_uinfo((uintptr_t)urdc, DCMD_ADDRSPEC, argc, argv);
	return (rc);
}

static int
rdc_u2k(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_u_info_t *urdc;
	rdc_k_info_t *rdc_k_info, *krdc;
	int rc;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	urdc = mdb_zalloc(sizeof (*urdc), UM_GC);
	krdc = mdb_zalloc(sizeof (*krdc), UM_GC);

	if (mdb_vread(urdc, sizeof (*urdc), addr) != sizeof (*urdc)) {
		mdb_warn("failed to read urdc at %p\n", addr);
		return (DCMD_ERR);
	}

	if (mdb_readvar(&rdc_k_info, "rdc_k_info") == -1) {
		mdb_warn("failed to read 'rdc_k_info'");
		return (DCMD_ERR);
	}

	krdc = &rdc_k_info[urdc->index];

	rc = rdc_kinfo((uintptr_t)krdc, DCMD_ADDRSPEC, argc, argv);
	return (rc);
}

#ifdef DEBUG
/*
 * This routine is used to set the seq field in the rdc_kinfo->group
 * structure. Used to test that the queue code handles the integer
 * overflow correctly.
 * Takes two arguments index and value.
 * The index is the index into the kinfo structure array and
 * the value is the new value to set into the seq field.
 */
/*ARGSUSED*/
static int
rdc_setseq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_k_info_t *rdc_k_info;
	rdc_group_t *group;
	int index;
	uint_t val;
	uintptr_t pokeaddr;

	if (argc != 2) {
		mdb_warn("must have two arguments, index and value\n");
		return (DCMD_ERR);
	}

	index = (int)mdb_strtoull(argv[0].a_un.a_str);
	val = (uint_t)mdb_strtoull(argv[1].a_un.a_str);

	/*
	 * Find out where in memory the seq field.
	 * The structure offset first.
	 */

	if (mdb_readvar(&rdc_k_info, "rdc_k_info") == -1) {
		mdb_warn("failed to read 'rdc_k_info'");
		return (DCMD_ERR);
	}
	pokeaddr = (uintptr_t)&rdc_k_info[index].group;
	if (mdb_vread(&group, sizeof (rdc_group_t *), pokeaddr) !=
	    sizeof (rdc_group_t *)) {
		mdb_warn("failed to fetch the group structure for set %d\n",
		    index);
		return (DCMD_ERR);
	}
	pokeaddr = (uintptr_t)(&group->seq);
	if (mdb_vwrite(&val, sizeof (val), pokeaddr) != sizeof (val)) {
		mdb_warn("failed to write seq at %p\n", pokeaddr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}


/*
 * This routine is used to set the seqack field in the rdc_kinfo->group
 * structure. Used to test that the queue code handles the integer
 * overflow correctly.
 * Takes two arguments index and value.
 * The index is the index into the kinfo structure array and
 * the value is the new value to set into the seqack field.
 */
/*ARGSUSED*/
static int
rdc_setseqack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_k_info_t *rdc_k_info;
	rdc_group_t *group;
	int index;
	uint_t val;
	uintptr_t pokeaddr;

	if (argc != 2) {
		mdb_warn("must have two arguments, index and value\n");
		return (DCMD_ERR);
	}

	index = (int)mdb_strtoull(argv[0].a_un.a_str);
	val = (uint_t)mdb_strtoull(argv[1].a_un.a_str);

	/*
	 * Find out where in memory the seqack field.
	 * The structure offset first.
	 */

	if (mdb_readvar(&rdc_k_info, "rdc_k_info") == -1) {
		mdb_warn("failed to read 'rdc_k_info'");
		return (DCMD_ERR);
	}
	pokeaddr = (uintptr_t)&rdc_k_info[index].group;
	if (mdb_vread(&group, sizeof (rdc_group_t *), pokeaddr) !=
	    sizeof (rdc_group_t *)) {
		mdb_warn("failed to fetch the group structure for set %d\n",
		    index);
		return (DCMD_ERR);
	}
	pokeaddr = (uintptr_t)(&group->seqack);
	if (mdb_vwrite(&val, sizeof (val), pokeaddr) != sizeof (val)) {
		mdb_warn("failed to write seqack at %p\n", pokeaddr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * random define printing stuff, just does the define, and print the result
 */
/*ARGSUSED*/
static int
fba_to_log_num(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int num;
	if (argc < 1) {
		mdb_warn("must have an argument\n");
		return (DCMD_ERR);
	}
	num = (int)mdb_strtoull(argv[0].a_un.a_str);
	num = FBA_TO_LOG_NUM(num);
	mdb_printf("LOG NUM: %d (0x%x)", num, num);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
log_to_fba_num(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int num;
	if (argc < 1) {
		mdb_warn("must have an argument\n");
		return (DCMD_ERR);
	}
	num = (int)mdb_strtoull(argv[0].a_un.a_str);
	num = LOG_TO_FBA_NUM(num);
	mdb_printf("LOG NUM: %d (0x%x)", num, num);

	return (DCMD_OK);
}

static int
bmap_bit_isset(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int st;
	int i, num;
	rdc_k_info_t *krdc;
	unsigned char *bmap;
	unsigned char *bmaddr;
	int bmsize;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (argc < 1) {
		mdb_warn("must have an argument\n");
		return (DCMD_ERR);
	}
	krdc = mdb_zalloc(sizeof (*krdc), UM_GC);

	if (mdb_vread(krdc, sizeof (*krdc), addr) != sizeof (*krdc)) {
		mdb_warn("failed to read rdc_k_info at %p", addr);
		return (DCMD_ERR);
	}

	bmaddr = krdc->dcio_bitmap;
	bmsize = krdc->bitmap_size;
	bmap = mdb_zalloc(bmsize, UM_GC);
	if (mdb_vread(bmap, bmsize, (uintptr_t)bmaddr) != bmsize) {
		mdb_warn("failed to read bitmap");
		return (DCMD_ERR);
	}

	num = (int)mdb_strtoull(argv[0].a_un.a_str);
	st = FBA_TO_LOG_NUM(num);
	i = BMAP_BIT_ISSET(bmap, st);
	mdb_printf(" BIT (%d) for %x %s set (%02x)", st, num, i?"IS":"IS NOT",
	    bmap[IND_BYTE(st)] & 0xff);

	return (DCMD_OK);
}

static int
bmap_bitref_isset(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int num, st, i;
	rdc_k_info_t *krdc;
	unsigned char *brefbyte;
	unsigned int *brefint;
	void *bradder;
	int brsize;
	size_t refcntsize = sizeof (unsigned char);
	struct bm_ref_ops *refops;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (argc < 1) {
		mdb_warn("must have an argument\n");
		return (DCMD_ERR);
	}

	krdc = mdb_zalloc(sizeof (*krdc), UM_GC);

	if (mdb_vread(krdc, sizeof (*krdc), addr) != sizeof (*krdc)) {
		mdb_warn("failed to read rdc_k_info at %p", addr);
		return (DCMD_ERR);
	}

	bradder = krdc->bitmap_ref;
	refops = mdb_zalloc(sizeof (*refops), UM_GC);
	if (mdb_vread(refops, sizeof (*refops), (uintptr_t)krdc->bm_refs) !=
	    sizeof (*refops)) {
		mdb_warn("failed to read bm_refops at %p", krdc->bm_refs);
		return (DCMD_ERR);
	}
	refcntsize = refops->bmap_ref_size;
	brsize = krdc->bitmap_size * BITS_IN_BYTE * refcntsize;
	if (refcntsize == sizeof (unsigned char)) {
		brefbyte = mdb_zalloc(brsize, UM_GC);
		if (mdb_vread(brefbyte, brsize, (uintptr_t)bradder) != brsize) {
			mdb_warn("failed to read bitmap");
			return (DCMD_ERR);
		}
	} else {
		brefint = mdb_zalloc(brsize, UM_GC);
		if (mdb_vread(brefint, brsize, (uintptr_t)bradder) != brsize) {
			mdb_warn("failed to read bitmap");
			return (DCMD_ERR);
		}
	}

	num = (int)mdb_strtoull(argv[0].a_un.a_str);
	st = FBA_TO_LOG_NUM(num);
	if (refcntsize == sizeof (unsigned char))
		i = brefbyte[st];
	else
		i = brefint[st];

	mdb_printf("BITREF (%d) for %x %s set (%02x)", st, num, i?"IS":"IS NOT",
	    i);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
ind_byte(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int num;

	if (argc < 1) {
		mdb_warn("must have an argument\n");
		return (DCMD_ERR);
	}
	num = FBA_TO_LOG_NUM((int)mdb_strtoull(argv[0].a_un.a_str));
	mdb_printf("IND_BYTE: %d", IND_BYTE(num));

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
ind_bit(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int num;

	if (argc < 1) {
		mdb_warn("must have an argument\n");
		return (DCMD_ERR);
	}
	num = FBA_TO_LOG_NUM((int)mdb_strtoull(argv[0].a_un.a_str));
	mdb_printf("IND_BIT: %d 0x%x", IND_BIT(num), IND_BIT(num));

	return (DCMD_OK);
}

static char *
print_bit(uint_t bitmask)
{
	int bitval = 1;
	int i;

	bitstr[32] = '\0';

	for (i = 31; i >= 0; i--) {
		if (bitmask & bitval) {
			bitstr[i] = '1';
		} else {
			bitstr[i] = '0';
		}
		bitval *= 2;
	}
	return (bitstr);
}

/*ARGSUSED*/
static int
rdc_bitmask(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t bitmask = 0;
	int first, st, en, pos, len;

	if (argc < 2) {
		mdb_warn("must have 2 args (pos, len)\n");
		return (DCMD_ERR);
	}
	pos = (int)mdb_strtoull(argv[0].a_un.a_str);
	len = (int)mdb_strtoull(argv[1].a_un.a_str);

	if (len <= 0) {
		mdb_printf("non positive len specified");
		return (DCMD_ERR);
	}

	if ((len - pos) > 2048) {
		mdb_printf("len out of range, 32 bit bitmask");
		return (DCMD_ERR);
	}

	first = st = FBA_TO_LOG_NUM(pos);
	en = FBA_TO_LOG_NUM(pos + len - 1);
	while (st <= en) {
		BMAP_BIT_SET((uchar_t *)&bitmask, st - first);
		st++;
	}

	mdb_printf("bitmask for POS: %d LEN: %d : 0x%08x (%s)", pos, len,
	    bitmask & 0xffffffff, print_bit(bitmask));
	return (DCMD_OK);

}

/*
 * Dump the bitmap of the krdc structure indicated by the index
 * argument. Used by the ZatoIchi tests.
 */
/*ARGSUSED*/
static int
rdc_bmapdump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_k_info_t *rdc_k_info;
	int index;
	uintptr_t bmapaddr;
	uintptr_t bmapdata;
	unsigned char *data;
	int bmapsize;
	int i;
	int st = 0;
	int en = 0;

	if (argc < 1) {
		mdb_warn("must have index argument\n");
		return (DCMD_ERR);
	}

	i = argc;
	if (i == 3) {
		en = (int)mdb_strtoull(argv[2].a_un.a_str);
		en = FBA_TO_LOG_NUM(en);
		i--;
	}
	if (i == 2) {
		st = (int)mdb_strtoull(argv[1].a_un.a_str);
		st = FBA_TO_LOG_NUM(st);
	}

	index = (int)mdb_strtoull(argv[0].a_un.a_str);
	/*
	 * Find out where in memory the rdc_k_kinfo array starts
	 */
	if (mdb_readvar(&rdc_k_info, "rdc_k_info") == -1) {
		mdb_warn("failed to read 'rdc_k_info'");
		return (DCMD_ERR);
	}
	bmapaddr = (uintptr_t)(&rdc_k_info[index].bitmap_size);
	if (mdb_vread(&bmapsize, sizeof (bmapsize), bmapaddr)
	    != sizeof (bmapsize)) {
		mdb_warn("failed to read dcio_bitmap at %p\n", bmapaddr);
		return (DCMD_ERR);
	}

	bmapaddr = (uintptr_t)(&rdc_k_info[index].dcio_bitmap);
	if (mdb_vread(&bmapdata, sizeof (bmapdata), bmapaddr)
	    != sizeof (bmapdata)) {
		mdb_warn("failed to read dcio_bitmap at %p\n", bmapaddr);
		return (DCMD_ERR);
	}
	data = mdb_zalloc(bmapsize, UM_SLEEP);

	if (mdb_vread(data, bmapsize, bmapdata) != bmapsize) {
		mdb_warn("failed to read the bitmap data\n");
		mdb_free(data, bmapsize);
		return (DCMD_ERR);
	}
	mdb_printf("bitmap data address 0x%p bitmap size %d\n"
	    "kinfo 0x%p\n", bmapdata, bmapsize, &rdc_k_info[index]);

	if ((st < 0) || ((st/8) > bmapsize) || (en < 0)) {
		mdb_warn("offset is out of range st %d bms %d en %d",
		    st, bmapsize, en);
		return (DCMD_ERR);
	}
	if (((en/8) > bmapsize) || (en == 0))
		en = bmapsize * 8;

	mdb_printf("bit start pos: %d bit end pos: %d\n\n", st, en);
	st /= 8;
	en /= 8;
	for (i = st; i < en; i++) {
		mdb_printf("%02x ", data[i] & 0xff);
		if ((i % 16) == 15) {
			int s = LOG_TO_FBA_NUM((i-15)*8);
			int e = LOG_TO_FBA_NUM(((i+1)*8)) - 1;
			mdb_printf(" fbas: %x - %x\n", s, e);
		}
	}
	mdb_printf("\n");
	mdb_free(data, bmapsize);
	return (DCMD_OK);
}

/*
 * dump the bitmap reference count
 */
/*ARGSUSED*/
static int
rdc_brefdump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rdc_k_info_t *rdc_k_info;
	int index;
	uintptr_t bmapaddr;
	uintptr_t bmapdata;
	unsigned char *data;
	int bmapsize;
	int i;
	int st = 0;
	int en = 0;

	if (argc < 1) {
		mdb_warn("must have index argument\n");
		return (DCMD_ERR);
	}
	index = (int)mdb_strtoull(argv[0].a_un.a_str);

	i = argc;
	if (i == 3) {
		en = (int)mdb_strtoull(argv[2].a_un.a_str);
		en = FBA_TO_LOG_NUM(en);
		i--;

	}
	if (i == 2) {
		st = (int)mdb_strtoull(argv[1].a_un.a_str);
		st = FBA_TO_LOG_NUM(st);
	}

	/*
	 * Find out where in memory the rdc_k_kinfo array starts
	 */
	if (mdb_readvar(&rdc_k_info, "rdc_k_info") == -1) {
		mdb_warn("failed to read 'rdc_k_info'");
		return (DCMD_ERR);
	}
	bmapaddr = (uintptr_t)(&rdc_k_info[index].bitmap_size);

	if (mdb_vread(&bmapsize, sizeof (bmapsize), bmapaddr)
	    != sizeof (bmapsize)) {
		mdb_warn("failed to read dcio_bitmap at %p\n", bmapaddr);
		return (DCMD_ERR);
	}

	bmapsize *= 8;
	bmapaddr = (uintptr_t)(&rdc_k_info[index].bitmap_ref);

	if (mdb_vread(&bmapdata, sizeof (bmapdata), bmapaddr)
	    != sizeof (bmapdata)) {
		mdb_warn("failed to read dcio_bitmap at %p\n", bmapaddr);
		return (DCMD_ERR);
	}
	data = mdb_zalloc(bmapsize, UM_SLEEP);

	if (mdb_vread(data, bmapsize, bmapdata) != bmapsize) {
		mdb_warn("failed to read the bitmap data\n");
		mdb_free(data, bmapsize);
		return (DCMD_ERR);
	}
	mdb_printf("bitmap data address 0x%p bitmap size %d\n"
	    "kinfo 0x%p\n", bmapdata, bmapsize, &rdc_k_info[index]);

	if ((st < 0) || (st > bmapsize) || (en < 0)) {
		mdb_warn("offset is out of range");
	}
	if ((en > bmapsize) || (en == 0))
		en = bmapsize;

	mdb_printf("bit start pos: %d bit end pos: %d\n\n", st, en);

	for (i = st; i < en; i++) {
		mdb_printf("%02x ", data[i] & 0xff);
		if ((i % 16) == 15) {
			int s = LOG_TO_FBA_NUM(i-15);
			int e = LOG_TO_FBA_NUM(i+1) - 1;
			mdb_printf(" fbas: 0x%x - 0x%x \n", s, e);
		}
	}
	mdb_printf("\n");
	mdb_free(data, bmapsize);
	return (DCMD_OK);
}

static int
rdc_bmapnref(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_printf("\nRDC bitmap info\n");
	rdc_bmapdump(addr, flags, argc, argv);
	mdb_printf("RDC bitmap reference count info\n");
	rdc_brefdump(addr, flags, argc, argv);
	return (DCMD_OK);
}

#endif
/*
 * MDB module linkage information:
 */

static const mdb_dcmd_t dcmds[] = {
	{ "rdc", NULL, "display sndr module info", rdc },
	{ "rdc_buf", "?[-v]", "rdc_buf structure", rdc_buf },
	{ "rdc_kinfo", "?[-av]", "rdc_k_info structure", rdc_kinfo },
	{ "rdc_uinfo", "?[-av]", "rdc_u_info structure", rdc_uinfo },
	{ "rdc_group", "?", "rdc group structure", rdc_group },
	{ "rdc_srv", "?", "rdc_srv structure", rdc_srv },
	{ "rdc_if", "?", "rdc_if structure", rdc_if },
	{ "rdc_infodev", "?", "rdc_info_dev structure", rdc_infodev },
	{ "rdc_k2u", "?", "rdc_kinfo to rdc_uinfo", rdc_k2u },
	{ "rdc_u2k", "?", "rdc_uinfo to rdc_kinfo", rdc_u2k },
	{ "rdc_aio", "?", "rdc_aio structure", rdc_aio},
	{ "rdc_iohdr", "?", "rdc_iohdr structure", rdc_iohdr},
#ifdef DEBUG
	{ "rdc_setseq", "?", "Write seq field in group", rdc_setseq },
	{ "rdc_setseqack", "?", "Write seqack field in group", rdc_setseqack },
	{ "rdc_dset", "?", "Dump dset info", rdc_dset },
	{ "rdc_bmapdump", "?", "Dump bitmap", rdc_bmapdump },
	{ "rdc_brefdump", "?", "Dump bitmap reference count", rdc_brefdump },
	{ "rdc_bmapnref", "?", "Dump bitmap and ref count", rdc_bmapnref },
	{ "rdc_fba2log", "?", "fba to log num", fba_to_log_num },
	{ "rdc_log2fba", "?", "log to fba num", log_to_fba_num },
	{ "rdc_bitisset", "?", "check bit set", bmap_bit_isset },
	{ "rdc_brefisset", "?", "check bit ref set", bmap_bitref_isset },
	{ "rdc_indbyte", "?", "print indbyte", ind_byte },
	{ "rdc_indbit", "?", "print indbit", ind_bit },
	{ "rdc_bitmask", "?", "print bitmask for pos->len", rdc_bitmask },
#endif
	{ NULL }
};


static const mdb_walker_t walkers[] = {
	{ "rdc_kinfo", "walk the rdc_k_info array",
	    rdc_k_info_winit, rdc_k_info_wstep, rdc_k_info_wfini },
	{ "rdc_uinfo", "walk the rdc_u_info array",
	    rdc_u_info_winit, rdc_u_info_wstep, rdc_u_info_wfini },
	{ "rdc_if", "walk rdc_if chain",
	    rdc_if_winit, rdc_if_wstep, rdc_if_wfini },
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
