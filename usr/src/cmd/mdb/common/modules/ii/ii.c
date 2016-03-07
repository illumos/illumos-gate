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

#include <stddef.h>

#include <sys/types.h>
#include <sys/mdb_modapi.h>

#include <sys/nsctl/nsctl.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>


#include <sys/nsctl/dsw.h>
#include <sys/nsctl/dsw_dev.h>

#include <sys/nsctl/nsvers.h>


const mdb_bitmask_t bi_flags_bits[] = {
	{ "DSW_GOLDEN", DSW_GOLDEN, DSW_GOLDEN },
	{ "DSW_COPYINGP", DSW_COPYINGP, DSW_COPYINGP },
	{ "DSW_COPYINGM", DSW_COPYINGM, DSW_COPYINGM },
	{ "DSW_COPYINGS", DSW_COPYINGS, DSW_COPYINGS },
	{ "DSW_COPYINGX", DSW_COPYINGX, DSW_COPYINGX },
	{ "DSW_BMPOFFLINE", DSW_BMPOFFLINE, DSW_BMPOFFLINE },
	{ "DSW_SHDOFFLINE", DSW_SHDOFFLINE, DSW_SHDOFFLINE },
	{ "DSW_MSTOFFLINE", DSW_MSTOFFLINE, DSW_MSTOFFLINE },
	{ "DSW_OVROFFLINE", DSW_OVROFFLINE, DSW_OVROFFLINE },
	{ "DSW_TREEMAP", DSW_TREEMAP, DSW_TREEMAP },
	{ "DSW_OVERFLOW", DSW_OVERFLOW, DSW_OVERFLOW },
	{ "DSW_SHDEXPORT", DSW_SHDEXPORT, DSW_SHDEXPORT },
	{ "DSW_SHDIMPORT", DSW_SHDIMPORT, DSW_SHDIMPORT },
	{ "DSW_VOVERFLOW", DSW_VOVERFLOW, DSW_VOVERFLOW },
	{ "DSW_HANGING", DSW_HANGING, DSW_HANGING },
	{ "DSW_CFGOFFLINE", DSW_CFGOFFLINE, DSW_CFGOFFLINE },
	{ "DSW_OVRHDRDRTY", DSW_OVRHDRDRTY, DSW_OVRHDRDRTY },
	{ "DSW_RESIZED", DSW_RESIZED, DSW_RESIZED },
	{ "DSW_FRECLAIM", DSW_FRECLAIM, DSW_FRECLAIM },
	{ NULL, 0, 0 }
};

const mdb_bitmask_t bi_state_bits[] = {
	{ "DSW_IOCTL", DSW_IOCTL, DSW_IOCTL },
	{ "DSW_CLOSING", DSW_CLOSING, DSW_CLOSING },
	{ "DSW_MSTTARGET", DSW_MSTTARGET, DSW_MSTTARGET },
	{ "DSW_MULTIMST", DSW_MULTIMST, DSW_MULTIMST },
	{ NULL, 0, 0 }
};
static uintptr_t nextaddr;
/*
 * Display a ii_fd_t
 * Requires an address.
 */
/*ARGSUSED*/
static int
ii_fd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ii_fd_t fd;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&fd, sizeof (fd), addr) != sizeof (fd)) {
		mdb_warn("failed to read ii_fd_t at 0x%p", addr);
		return (DCMD_ERR);
	}

	mdb_inc_indent(4);
	mdb_printf("ii_info: 0x%p ii_bmp: %d ii_shd: %d ii_ovr: %d ii_optr: "
	    "0x%p\nii_oflags: 0x%x\n", fd.ii_info, fd.ii_bmp, fd.ii_shd,
	    fd.ii_ovr, fd.ii_optr, fd.ii_oflags);
	mdb_dec_indent(4);

	return (DCMD_OK);
}

/*
 * displays a ii_info_dev structure.
 */
/*ARGSUSED*/
static int
ii_info_dev(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_ii_info_dev_t ipdev;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&ipdev, sizeof (ipdev), addr) != sizeof (ipdev)) {
		mdb_warn("failed to read ii_info_dev_t at 0x%p", addr);
		return (DCMD_ERR);
	}

	mdb_inc_indent(4);
	mdb_printf("bi_fd: 0x%p bi_iodev: 0x%p bi_tok: 0x%p\n",
	    ipdev.bi_fd, ipdev.bi_iodev, ipdev.bi_tok);
	mdb_printf("bi_ref: %d bi_rsrv: %d bi_orsrv: %d\n",
	    ipdev.bi_ref, ipdev.bi_rsrv, ipdev.bi_orsrv);

	/*
	 * use nsc_fd to dump the fd details.... if present.
	 */
	if (ipdev.bi_fd) {
		mdb_printf("nsc_fd structure:\n");
		mdb_inc_indent(4);
		mdb_call_dcmd("nsc_fd", (uintptr_t)(ipdev.bi_fd),
		    flags, 0, NULL);
		mdb_dec_indent(4);
	}
	mdb_dec_indent(4);
	return (DCMD_OK);
}

/*
 * Displays an _ii_overflow structure
 */
/*ARGSUSED*/
static int
ii_overflow(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_ii_overflow_t ii_overflow;

	nextaddr = 0;
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&ii_overflow, sizeof (ii_overflow), addr)
		!= sizeof (ii_overflow)) {
		mdb_warn("failed to read ii_overflow_t at 0x%p", addr);
		return (DCMD_ERR);
	}

	mdb_inc_indent(4);
	mdb_printf("_ii_overflow at 0x%p\n", addr);
	mdb_printf("_ii_doverflow_t\n");
	mdb_inc_indent(4);
	mdb_printf("ii_dvolname: %s\n", ii_overflow.ii_volname);
	mdb_printf("ii_dhmagic: %x\n", ii_overflow.ii_hmagic);
	mdb_printf("ii_dhversion: %x\n", ii_overflow.ii_hversion);
	mdb_printf("ii_ddrefcnt: %x\n", ii_overflow.ii_drefcnt);
	mdb_printf("ii_dflags: %x\n", ii_overflow.ii_flags);
	mdb_printf("ii_dfreehead: %x\n", ii_overflow.ii_freehead);
	mdb_printf("ii_dnchunks: %x\n", ii_overflow.ii_nchunks);
	mdb_printf("ii_dunused: %x\n", ii_overflow.ii_unused);
	mdb_printf("ii_dused: %x\n", ii_overflow.ii_used);
	mdb_printf("ii_urefcnt: %x\n", ii_overflow.ii_urefcnt);
	mdb_dec_indent(4);

	mdb_printf("ii_mutex: %x\n", ii_overflow.ii_mutex);
	mdb_printf("ii_kstat_mutex: %x\n", ii_overflow.ii_kstat_mutex);
	mdb_printf("ii_crefcnt: %d\n", ii_overflow.ii_crefcnt);
	mdb_printf("ii_detachcnt: %d\n", ii_overflow.ii_detachcnt);
	mdb_printf("ii_next: %x\n", ii_overflow.ii_next);

	mdb_printf("Overflow volume:\n");
	if (ii_overflow.ii_dev)
		ii_info_dev((uintptr_t)ii_overflow.ii_dev, flags, 0, NULL);

	mdb_printf("  ii_ioname: %s\n", &ii_overflow.ii_ioname);
	mdb_dec_indent(4);

	nextaddr = (uintptr_t)ii_overflow.ii_next;
	return (DCMD_OK);
}
/*ARGSUSED*/
static int
ii_info(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_ii_info_t ii_info = {0};
	char string[DSW_NAMELEN];

	nextaddr = 0;
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&ii_info, sizeof (ii_info), addr) != sizeof (ii_info)) {
		mdb_warn("failed to read ii_info_t at 0x%p", addr);
		return (DCMD_ERR);
	}

	mdb_printf(
		"bi_next: 0x%p\n"
		"bi_head: 0x%p\t"
		"bi_sibling: 0x%p\n"
		"bi_master: 0x%p\t"
		"bi_nextmst: 0x%p\n",
		ii_info.bi_next, ii_info.bi_head, ii_info.bi_sibling,
		ii_info.bi_master, ii_info.bi_nextmst);

	mdb_printf("bi_mutex: 0x%p\n", ii_info.bi_mutex);

	/*
	 * Print out all the fds by using ii_info_dev
	 */
	mdb_printf("Cache master:\n");
	if (ii_info.bi_mstdev)
		ii_info_dev((uintptr_t)ii_info.bi_mstdev, flags, 0, NULL);

	mdb_printf("Raw master:\n");
	if (ii_info.bi_mstrdev)
		ii_info_dev((uintptr_t)ii_info.bi_mstrdev, flags, 0, NULL);

	mdb_printf("Cache shadow:\n");
	ii_info_dev((uintptr_t)(addr + offsetof(_ii_info_t, bi_shddev)),
	    flags, 0, NULL);

	mdb_printf("Raw shadow:\n");
	ii_info_dev((uintptr_t)(addr + offsetof(_ii_info_t, bi_shdrdev)),
	    flags, 0, NULL);

	mdb_printf("Bitmap:\n");
	ii_info_dev((uintptr_t)(addr + offsetof(_ii_info_t, bi_bmpdev)),
	    flags, 0, NULL);

	mdb_printf("bi_keyname: %-*s\n", DSW_NAMELEN, ii_info.bi_keyname);
	mdb_printf("bi_bitmap: 0x%p\n", ii_info.bi_bitmap);

	if ((ii_info.bi_cluster == NULL) ||
	    (mdb_vread(&string, sizeof (string), (uintptr_t)ii_info.bi_cluster)
		!= sizeof (string)))
		string[0] = 0;
	mdb_printf("bi_cluster: %s\n", string);

	if ((ii_info.bi_group == NULL) ||
	    (mdb_vread(&string, sizeof (string), (uintptr_t)ii_info.bi_group)
			!= sizeof (string)))
		string[0] = 0;
	mdb_printf("bi_group: %s\n", string);

	mdb_printf("bi_busy: 0x%p\n", ii_info.bi_busy);

	mdb_printf("bi_shdfba: %0x\t", ii_info.bi_shdfba);
	mdb_printf("bi_shdbits: %0x\n", ii_info.bi_shdbits);
	mdb_printf("bi_copyfba: %0x\t", ii_info.bi_copyfba);
	mdb_printf("bi_copybits: %0x\n", ii_info.bi_copybits);

	mdb_printf("bi_size: %0x\n", ii_info.bi_size);

	mdb_printf("bi_flags: 0x%x <%b>\n",
		ii_info.bi_flags, ii_info.bi_flags, bi_flags_bits);

	mdb_printf("bi_state: 0x%x <%b>\n",
		ii_info.bi_state, ii_info.bi_state, bi_state_bits);

	mdb_printf("bi_disabled: %d\n", ii_info.bi_disabled);
	mdb_printf("bi_ioctl: %d\n", ii_info.bi_ioctl);
	mdb_printf("bi_release: %d\t", ii_info.bi_release);
	mdb_printf("bi_rsrvcnt: %d\n", ii_info.bi_rsrvcnt);

	mdb_printf("bi_copydonecv: %x\t", ii_info.bi_copydonecv);
	mdb_printf("bi_reservecv: %x\n", ii_info.bi_reservecv);
	mdb_printf("bi_releasecv: %x\t", ii_info.bi_releasecv);
	mdb_printf("bi_closingcv: %x\n", ii_info.bi_closingcv);
	mdb_printf("bi_ioctlcv: %x\t", ii_info.bi_ioctlcv);
	mdb_printf("bi_busycv: %x\n", ii_info.bi_busycv);
	mdb_call_dcmd("rwlock", (uintptr_t)(addr +
	    offsetof(_ii_info_t, bi_busyrw)), flags, 0, NULL);
	mdb_printf("bi_bitmap_ops: 0x%p\n", ii_info.bi_bitmap_ops);

	mdb_printf("bi_rsrvmutex: %x\t", ii_info.bi_rsrvmutex);
	mdb_printf("bi_rlsemutex: %x\n", ii_info.bi_rlsemutex);
	mdb_printf("bi_bmpmutex: %x\n", ii_info.bi_bmpmutex);

	mdb_printf("bi_mstchks: %d\t", ii_info.bi_mstchks);
	mdb_printf("bi_shdchks: %d\n", ii_info.bi_shdchks);
	mdb_printf("bi_shdchkused: %d\t", ii_info.bi_shdchkused);
	mdb_printf("bi_shdfchk: %d\n", ii_info.bi_shdfchk);

	mdb_printf("bi_overflow\n");
	if (ii_info.bi_overflow)
		ii_overflow((uintptr_t)ii_info.bi_overflow, flags, 0, NULL);

	mdb_printf("bi_iifd:\n");
	if (ii_info.bi_iifd)
		(void) ii_fd((uintptr_t)ii_info.bi_iifd, flags, 0, NULL);

	mdb_printf("bi_throttle_unit: %d\t", ii_info.bi_throttle_unit);
	mdb_printf("bi_throttle_delay: %d\n", ii_info.bi_throttle_delay);

	mdb_printf("bi_linkrw:\n");
	mdb_call_dcmd("rwlock", (uintptr_t)(addr +
	    offsetof(_ii_info_t, bi_linkrw)), flags, 0, NULL);

	mdb_printf("bi_chksmutex: %x\n", ii_info.bi_chksmutex);
	mdb_printf("bi_locked_pid: %x\n", ii_info.bi_locked_pid);
	mdb_printf("bi_kstat: 0x%p\n", ii_info.bi_kstat);
	/* ii_kstat_info_t bi_kstat_io; */

	nextaddr = (uintptr_t)ii_info.bi_next;
	return (DCMD_OK);
}

/*
 * This should be a walker surely.
 */
/*ARGSUSED*/
static int
ii_info_all(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t myaddr;
	/*
	 * we use the global address.
	 */
	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	if (mdb_readsym(&myaddr, sizeof (myaddr), "_ii_info_top") !=
	    sizeof (myaddr)) {
		return (DCMD_ERR);
	}

	mdb_printf("_ii_info_top contains 0x%lx\n", myaddr);

	while (myaddr) {
		ii_info(myaddr, DCMD_ADDRSPEC, 0, NULL);
		myaddr = nextaddr;
	}
	return (DCMD_OK);
}

/*
 * Display general ii module information.
 */

#define	ii_get_print(kvar, str, fmt, val)		\
	if (mdb_readvar(&(val), #kvar) == -1) {		\
		mdb_dec_indent(4);			\
		mdb_warn("unable to read '" #kvar "'");	\
		return (DCMD_ERR);			\
	}						\
	mdb_printf("%-20s" fmt "\n", str ":", val)

/* ARGSUSED */
static int
ii(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int maj, min, mic, baseline, i;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_readvar(&maj, "dsw_major_rev") == -1) {
		mdb_warn("unable to read 'dsw_major_rev'");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&min, "dsw_minor_rev") == -1) {
		mdb_warn("unable to read 'dsw_minor_rev'");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&mic, "dsw_micro_rev") == -1) {
		mdb_warn("unable to read 'dsw_micro_rev'");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&baseline, "dsw_baseline_rev") == -1) {
		mdb_warn("unable to read 'dsw_baseline_rev'");
		return (DCMD_ERR);
	}

	mdb_printf("Point-in-Time Copy module version: kernel %d.%d.%d.%d; "
	    "mdb %d.%d.%d.%d\n", maj, min, mic, baseline,
	    ISS_VERSION_MAJ, ISS_VERSION_MIN, ISS_VERSION_MIC, ISS_VERSION_NUM);

	mdb_inc_indent(4);
	ii_get_print(ii_debug, "debug", "%d", i);
	ii_get_print(ii_bitmap, "bitmaps", "%d", i);
	mdb_dec_indent(4);

	return (DCMD_OK);
}


/*
 * MDB module linkage information:
 */

static const mdb_dcmd_t dcmds[] = {
{ "ii", NULL, "display ii module info", ii },
{ "ii_fd", NULL, "display ii_fd structure", ii_fd },
{ "ii_info", NULL, "display ii_info structure", ii_info },
{ "ii_info_all", NULL, "display all ii_info structures", ii_info_all },
{ "ii_info_dev", NULL, "display ii_info_dev structure", ii_info_dev},
{ "ii_overflow", NULL, "display ii_overflow structure", ii_overflow},
{ NULL }
};


static const mdb_walker_t walkers[] = {
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
