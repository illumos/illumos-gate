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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/machparam.h>
#include <vm/as.h>
#include <vm/hat_sfmmu.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_target.h>
#include <mdb/mdb_ctf.h>

/*
 * sfmmu mdb support
 */

#define	SFMMU_VTOP_DBG_SYMBOL	1
#define	SFMMU_VTOP_DBG_VERBOSE	2
#define	SFMMU_VTOP_DBG_DEBUG	4
#define	SFMMU_VTOP_DBG_ALL	(SFMMU_VTOP_DBG_SYMBOL|SFMMU_VTOP_DBG_VERBOSE|\
				SFMMU_VTOP_DBG_DEBUG)

#define	SFMMU_VTOP_DBG_SYM	if (sfmmu_vtop_dbg & SFMMU_VTOP_DBG_SYMBOL) \
				    mdb_printf
#define	SFMMU_VTOP_DBG_VRB	if (sfmmu_vtop_dbg & SFMMU_VTOP_DBG_VERBOSE) \
				    mdb_printf
#define	SFMMU_VTOP_DBG_DBG	if (sfmmu_vtop_dbg & SFMMU_VTOP_DBG_DEBUG) \
				    mdb_printf

#define	SFMMU_VTOP_READSYM(dest, synm, where) \
	if (mdb_readsym(&(dest), sizeof (dest), (synm)) == -1) \
		mdb_warn("%s: couldn't find or read '%s'\n", (where), (synm));

struct hme_blks_max {
	struct hme_blk	hmx_hmeblk;
	struct sf_hment	hmx_hmes[NHMENTS - 1];
};

int sfmmu_vtop(uintptr_t, uint_t, int, const mdb_arg_t *);
static int sfmmu_vtop_common(struct as *, uintptr_t, physaddr_t *);
static int sfmmu_vtop_impl(uintptr_t, sfmmu_t *, sfmmu_t *, physaddr_t *);
static void sfmmu_vtop_print_hmeblk(struct hme_blk *);
static struct sf_hment *mdb_sfmmu_hblktohme(struct hme_blk *, caddr_t, int *);

int sfmmu_vtop_dbg_wanted = 0;	/* set this as desired */
int sfmmu_vtop_dbg = 0;

/*
 * ::sfmmu_vtop [[-v] -a as]
 * Extended version of the vtop builtin. The optional <as> argument is
 * used as base address space for translating a virtual address into a
 * physical address. The verbose option ("-v") shows intermediate
 * translation steps. If <as> or kas is ommitted, the builtin ::vtop
 * dcmd is called.
 */
int
sfmmu_vtop(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int ret;
	struct as *asp = NULL;
	char *asnmp = NULL;
	int verbose = 0;
	physaddr_t paddr;

	sfmmu_vtop_dbg = sfmmu_vtop_dbg_wanted;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'a', MDB_OPT_STR, &asnmp,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (verbose != 0 && asnmp == NULL) {
		mdb_warn("-v requires -a option\n");
		return (DCMD_USAGE);
	}

	if (verbose != 0 && (sfmmu_vtop_dbg & SFMMU_VTOP_DBG_VERBOSE) == 0) {
		sfmmu_vtop_dbg |= SFMMU_VTOP_DBG_VERBOSE;
	}

	if (asnmp != NULL) {
		GElf_Sym sym;

		SFMMU_VTOP_DBG_DBG("asnmp=%p asnm=%s\n", asnmp, asnmp);
		if (strcmp(asnmp, "kas") == 0) {
			if (mdb_lookup_by_name("kas", &sym) == -1) {
				mdb_warn("couldn't find 'kas'\n");
				return (DCMD_ERR);
			} else {
				asp = (struct as *)sym.st_value;
				SFMMU_VTOP_DBG_SYM("kas &sym=%p\n", &sym);
			}
		} else {
			asp = (struct as *)mdb_strtoull(asnmp);
		}
		SFMMU_VTOP_DBG_DBG("asp=0x%p\n", asp);
	}

	if (asp == 0) {
		SFMMU_VTOP_DBG_DBG("sfmmu_vtop: call standard vtop\n");
		return (mdb_call_dcmd("vtop", addr, flags, argc, argv));
	}

	if ((ret = sfmmu_vtop_common(asp, addr, &paddr)) == -1L) {
		mdb_printf("no mapping found for addr=%p\n", addr);
		return (DCMD_ERR);
	}

	if (ret == 0) {
		mdb_printf("address space %p: virtual %lr mapped to physical "
		    "%llr", asp, addr, paddr);
	} else {
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
sfmmu_vtop_common(struct as *asp, uintptr_t addr, physaddr_t *pap)
{
	struct as mas;
	struct as *masp = &mas;
	sfmmu_t *hatp;
	sfmmu_t mhat;
	sfmmu_t *mhatp = &mhat;
	int ret;

	if (mdb_vread(masp, sizeof (mas), (uintptr_t)asp) == -1) {
		mdb_warn("couldn't read as at %p\n", asp);
		return (DCMD_ERR);
	}

	hatp = masp->a_hat;

	SFMMU_VTOP_DBG_DBG("hatp=%p addr=%p masp=%p\n", hatp, addr, masp);

	if (mdb_vread(mhatp, sizeof (mhat), (uintptr_t)hatp) == -1) {
		mdb_warn("couldn't read hat at %p\n", hatp);
		return (DCMD_ERR);
	}
	if (mhatp->sfmmu_as != asp) {
		mdb_warn("%p is not a valid address space\n", asp);
		return (DCMD_ERR);
	}

	ret = sfmmu_vtop_impl(addr, hatp, mhatp, pap);

	return (ret);
}

static int
sfmmu_vtop_impl(uintptr_t addr, sfmmu_t *sfmmup, sfmmu_t *msfmmup,
    physaddr_t *pap)
{
	struct hmehash_bucket *uhme_hash;
	struct hmehash_bucket *khme_hash;
	int uhmehash_num;
	int khmehash_num;
	sfmmu_t *ksfmmup;
	struct hmehash_bucket mbucket;
	struct hmehash_bucket *hmebp;
	struct hmehash_bucket *shmebp;
	hmeblk_tag hblktag;
	int hmeshift;
	int hashno = 1;
	struct hme_blk *hmeblkp = NULL;
	struct hme_blks_max mhmeblkmax;
	intptr_t thmeblkp;
	struct sf_hment *sfhmep;
	int i;
	ism_blk_t mism_blk;
	ism_map_t *ism_map;
	ism_blk_t *ism_blkp;
	ism_blk_t *sism_blkp;
	sfmmu_t *ism_hatid = NULL;
	int sfhmeinx = 0;
	tte_t tte;
	pfn_t pfn;
	pfn_t start_pfn;
	page_t *pp;
	int ret = -1;

	SFMMU_VTOP_READSYM(uhme_hash, "uhme_hash", "sfmmu_vtop_impl");
	SFMMU_VTOP_DBG_DBG("uhme_hash=%p\t", uhme_hash);
	SFMMU_VTOP_READSYM(uhmehash_num, "uhmehash_num", "sfmmu_vtop_impl");
	SFMMU_VTOP_DBG_DBG("uhmehash_num=%lx\n", uhmehash_num);
	SFMMU_VTOP_READSYM(khme_hash, "khme_hash", "sfmmu_vtop_impl");
	SFMMU_VTOP_DBG_DBG("khme_hash=%p\t", khme_hash);
	SFMMU_VTOP_READSYM(khmehash_num, "khmehash_num", "sfmmu_vtop_impl");
	SFMMU_VTOP_DBG_DBG("khmehash_num=%lx\n", khmehash_num);
	SFMMU_VTOP_READSYM(ksfmmup, "ksfmmup", "sfmmu_vtop_impl");
	SFMMU_VTOP_DBG_DBG("ksfmmup=%p\n", ksfmmup);

	ism_blkp = sism_blkp = msfmmup->sfmmu_iblk;
	while (ism_blkp != NULL && ism_hatid == NULL) {
		SFMMU_VTOP_DBG_DBG("ism_blkp=%p\n", ism_blkp);
		if (mdb_vread(&mism_blk, sizeof (mism_blk),
		    (uintptr_t)ism_blkp) == -1) {
			mdb_warn("couldn't read ism_blk at %p\n", ism_blkp);
			return (DCMD_ERR);
		}
		ism_blkp = &mism_blk;
		ism_map = ism_blkp->iblk_maps;
		for (i = 0; i < ISM_MAP_SLOTS && ism_map[i].imap_ismhat; i++) {
			if ((caddr_t)addr >= ism_start(ism_map[i]) &&
			    (caddr_t)addr < ism_end(ism_map[i])) {
				sfmmup = ism_hatid = ism_map[i].imap_ismhat;
				addr = (caddr_t)addr - ism_start(ism_map[i]);
				SFMMU_VTOP_DBG_VRB("ism_blkp=%p inx=%d\n",
				    sism_blkp, i);
				SFMMU_VTOP_DBG_DBG("ism map=%p ism hat=%p "
				    "addr=%llx\n",
				    (caddr_t)&ism_map[i] - (caddr_t)ism_blkp
				    + (caddr_t)sism_blkp, sfmmup, addr);
				break;
			}
		}
		ism_blkp = sism_blkp = ism_blkp->iblk_next;
	}

	hblktag.htag_id = sfmmup;
	do {
		SFMMU_VTOP_DBG_DBG("-hashno=%d-\n", hashno);
		hmeshift = HME_HASH_SHIFT(hashno);
		SFMMU_VTOP_DBG_DBG("hmeshift=%d\n", hmeshift);
		hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
		hblktag.htag_rehash = hashno;

#ifdef __sparcv9
		SFMMU_VTOP_DBG_DBG("hblktag=%lx %lx\n",
		    (uint64_t)hblktag.htag_tag[0],
		    (uint64_t)hblktag.htag_tag[1]);
#else
		SFMMU_VTOP_DBG_DBG("hblktag=%llx\n",
		    (uint64_t)hblktag.htag_tag);
#endif

		hmebp = shmebp = HME_HASH_FUNCTION(sfmmup, addr, hmeshift);
		SFMMU_VTOP_DBG_DBG("hmebp=%p\n", hmebp);

		if (mdb_vread(&mbucket, sizeof (mbucket),
		    (uintptr_t)hmebp) == -1) {
			mdb_warn("couldn't read mbucket at %p\n", hmebp);
			return (DCMD_ERR);
		}

		hmebp = &mbucket;

		for (hmeblkp = hmebp->hmeblkp; hmeblkp;
		    hmeblkp = hmeblkp->hblk_next) {

			SFMMU_VTOP_DBG_DBG("hmeblkp=%p\n", hmeblkp);

			if (hmeblkp == NULL)
				break;

			if (mdb_vread(&mhmeblkmax, sizeof (struct hme_blk),
			    (uintptr_t)hmeblkp) == -1) {
				mdb_warn("couldn't read hme_blk at %p\n",
				    hmeblkp);
				return (DCMD_ERR);
			}

			thmeblkp = (uintptr_t)hmeblkp;
			hmeblkp = &mhmeblkmax.hmx_hmeblk;

			if (HTAGS_EQ(hmeblkp->hblk_tag, hblktag)) {
				/* found hme_blk */
				break;
			}
		}

		if (hmeblkp != NULL) {
			sfmmu_vtop_print_hmeblk(hmeblkp);

			sfhmep = mdb_sfmmu_hblktohme(hmeblkp, (caddr_t)addr,
			    &sfhmeinx);

			SFMMU_VTOP_DBG_DBG("sfhmeinx=%d ", sfhmeinx);

			if (sfhmeinx > 0) {
				thmeblkp += sizeof (struct hme_blk) +
				    sizeof (struct sf_hment) * (sfhmeinx - 1);

				if (mdb_vread(sfhmep, sizeof (struct sf_hment),
				    thmeblkp) == -1) {
					mdb_warn("couldn't read msfhme at %p\n",
					    sfhmep);
					return (DCMD_ERR);
				}
			}

			SFMMU_VTOP_DBG_VRB("sfmmup=%p hmebp=%p hmeblkp=%p\n",
			    sfmmup, shmebp, thmeblkp);

			tte = sfhmep->hme_tte;
			SFMMU_VTOP_DBG_VRB("tte=%llx ", tte.ll);
			if (TTE_IS_VALID(&tte)) {
				start_pfn = TTE_TO_TTEPFN(&tte);
				*pap = (start_pfn << MMU_PAGESHIFT) +
				    (addr & TTE_PAGE_OFFSET(tte.tte_size));
				pfn = *pap >> MMU_PAGESHIFT;
				pp = (sfhmep->hme_page != 0) ?
				    sfhmep->hme_page + (pfn - start_pfn) : 0;
				SFMMU_VTOP_DBG_VRB("pfn=%lx pp=%p\n", pfn, pp);
				ret = 0;
			}
			break;
		}

		hashno++;

	} while (HME_REHASH(msfmmup) && (hashno <= MAX_HASHCNT));

	return (ret);
}

static void
sfmmu_vtop_print_hmeblk(struct hme_blk *hmeblkp)
{

	if ((sfmmu_vtop_dbg & SFMMU_VTOP_DBG_DEBUG) == 0)
		return;

	mdb_printf("    hblk_nextpa=%llx\n", hmeblkp->hblk_nextpa);
#ifdef __sparcv9
	mdb_printf("    hblktag=%lx %lx\n", hmeblkp->hblk_tag.htag_tag[0],
	    hmeblkp->hblk_tag.htag_tag[1]);
#else
	mdb_printf("    hblktag=%llx\n", hmeblkp->hblk_tag.htag_tag);
#endif
	mdb_printf("    hblk_next=%p\n", hmeblkp->hblk_next);
	mdb_printf("    hblk_shadow=%p\n", hmeblkp->hblk_shadow);
	mdb_printf("    hblk_span=%d\n", hmeblkp->hblk_span);
	mdb_printf("    hblk_ttesz=%d\n", hmeblkp->hblk_ttesz);
	if (hmeblkp->hblk_shw_bit == 0) {
		mdb_printf("    hblk_hmecnt=%d\n", hmeblkp->hblk_hmecnt);
		mdb_printf("    hblk_vcnt=%d\n", hmeblkp->hblk_vcnt);
	} else {
		mdb_printf("    hblk_shw_mask=%x\n", hmeblkp->hblk_shw_mask);
	}
}

static struct sf_hment *
mdb_sfmmu_hblktohme(struct hme_blk *hmeblkp, caddr_t addr, int *hmenump)
{
	int index = 0;

	if (get_hblk_ttesz(hmeblkp) == TTE8K) {
		index = (((uintptr_t)addr >> MMU_PAGESHIFT) & (NHMENTS-1));
	}

	if (hmenump) {
		*hmenump = index;
	}

	return (&hmeblkp->hblk_hme[index]);
}

/*
 * ::memseg_list dcmd
 */
/*ARGSUSED*/
int
memseg_list(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct memseg ms;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_pwalk_dcmd("memseg", "memseg_list",
		    0, NULL, 0) == -1) {
			mdb_warn("can't walk memseg");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%?s %?s %?s %?s %?s%</u>\n", "ADDR",
		    "PAGES", "EPAGES", "BASE", "END");

	if (mdb_vread(&ms, sizeof (struct memseg), addr) == -1) {
		mdb_warn("can't read memseg at %#lx", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0?lx %0?lx %0?lx %0?lx %0?lx\n", addr,
	    ms.pages, ms.epages, ms.pages_base, ms.pages_end);

	return (DCMD_OK);
}

/*
 * walk the memseg structures
 */
int
memseg_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr != (uintptr_t)NULL) {
		mdb_warn("memseg only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_readvar(&wsp->walk_addr, "memsegs") == -1) {
		mdb_warn("symbol 'memsegs' not found");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (struct memseg), UM_SLEEP);
	return (WALK_NEXT);

}

int
memseg_walk_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == 0) {
		return (WALK_DONE);
	}

	if (mdb_vread(wsp->walk_data, sizeof (struct memseg),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct memseg at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((struct memseg *)wsp->walk_data)->next);

	return (status);
}

void
memseg_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct memseg));
}

int
platform_vtop(uintptr_t addr, struct as *asp, physaddr_t *pap)
{
	int rv;

	sfmmu_vtop_dbg = sfmmu_vtop_dbg_wanted;

	SFMMU_VTOP_DBG_DBG("platform_vtop: called.\n");

	if (asp == NULL) {
		return (DCMD_ERR);
	}

	if ((rv = sfmmu_vtop_common(asp, addr, pap)) == 0) {
		mdb_printf("address space %p: ", asp);
	}

	return (rv);
}

/*
 * ::tsbinfo help
 */
void
tsbinfo_help(void)
{
	mdb_printf("-l\tlist valid TSB entries.\n"
	    "-a\tlist all TSB entries.  Can only be used with -l.\n");
}

/*
 * ::tsbinfo dcmd
 */
int
tsbinfo_list(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t lflag = 0, aflag = 0;
	struct tsb_info tsbinfo;
	unsigned int entries = 0;
	struct tsbe *tsbp, *tsbend, *tsbstart;
	caddr_t va;
	uintptr_t pa;
	uint_t tsbbytes;
	char tsbsize[16];
#define	FLAGS_SIZE	sizeof ("RELOC,FLUSH,SWAPPED")
	char tsbflags[FLAGS_SIZE + 1];

	static const mdb_bitmask_t ttesz_mask_bits[] = {
		{ "8K", TSB8K, TSB8K },
		{ "64K", TSB64K, TSB64K },
		{ "512K", TSB512K, TSB512K },
		{ "4M", TSB4M, TSB4M },
		{ "32M", TSB32M, TSB32M },
		{ "256M", TSB256M, TSB256M },
		{ NULL, 0, 0 }
	};

	static const mdb_bitmask_t flags_bits[] = {
		{ "RELOC", TSB_RELOC_FLAG, TSB_RELOC_FLAG },
		{ "FLUSH", TSB_FLUSH_NEEDED, TSB_FLUSH_NEEDED },
		{ "SWAPPED", TSB_SWAPPED, TSB_SWAPPED },
		{ NULL, 0, 0 }
	};

	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv,
	    'l', MDB_OPT_SETBITS, TRUE, &lflag,
	    'a', MDB_OPT_SETBITS, TRUE, &aflag,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}

	/* -a only valid with -l */
	if (aflag && !lflag) {
		return (DCMD_USAGE);
	}

	/* Print header? */
	if (DCMD_HDRSPEC(flags) || lflag) {
		mdb_printf("%<u>%-?s %-?s %-8s %-*s %s%</u>\n", "TSBINFO",
		    "TSB", "SIZE", FLAGS_SIZE, "FLAGS", "TTE SIZES");
	}

	if (mdb_vread(&tsbinfo, sizeof (struct tsb_info), addr) == -1) {
		mdb_warn("failed to read struct tsb_info at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0?lx ", addr);

	/* Print a "-" if the TSB is swapped out. */
	if ((tsbinfo.tsb_flags & TSB_SWAPPED) == 0) {
		mdb_printf("%0?lx ", tsbinfo.tsb_va);
	} else {
		mdb_printf("%0?-s ", "-");
	}

	tsbbytes = TSB_BYTES(tsbinfo.tsb_szc);

#define	KB 1024
#define	MB (KB*KB)
	if (tsbbytes >= MB) {
		mdb_snprintf(tsbsize, sizeof (tsbsize), "%dM", tsbbytes / MB);
	} else {
		mdb_snprintf(tsbsize, sizeof (tsbsize), "%dK", tsbbytes / KB);
	}
#undef MB
#undef KB
	mdb_printf("%-8s ", tsbsize);

	if (tsbinfo.tsb_flags == 0) {
		mdb_printf("%-*s ", FLAGS_SIZE, "-");
	} else {
		mdb_snprintf(tsbflags, sizeof (tsbflags), "%b",
		    tsbinfo.tsb_flags, flags_bits);
		mdb_printf("%-*s ", FLAGS_SIZE, tsbflags);
	}

	mdb_printf("%b\n", tsbinfo.tsb_ttesz_mask, ttesz_mask_bits);

	/* Print TSB entries? */
	if (lflag) {

		if ((tsbinfo.tsb_flags & TSB_SWAPPED) == 0) {

			entries = TSB_ENTRIES(tsbinfo.tsb_szc);

			tsbp = mdb_alloc(sizeof (struct tsbe) * entries,
			    UM_SLEEP);

			if (mdb_vread(tsbp, sizeof (struct tsbe) * entries,
			    (uintptr_t)tsbinfo.tsb_va) == -1) {
				mdb_warn("failed to read TSB at %p",
				    tsbinfo.tsb_va);
				return (DCMD_ERR);
			}

			mdb_printf(
			    "TSB @ %lx (%d entries)\n"
			    "%-?s %-17s %s\n"
			    "%<u>%-?s %1s %1s %-11s "
			    "%1s %1s %1s %1s %1s %1s %8s "
			    "%1s %1s %1s %1s %1s %1s %1s "
			    "%1s %1s %1s %1s %1s %1s%</u>\n",
			    tsbinfo.tsb_va, entries, "", "TAG", "TTE",
			    "ADDR", "I", "L", "VA 63:22",
			    "V", "S", "N", "I", "H", "S", "PA 42:13",
			    "N", "U", "R", "W", "E", "X", "L",
			    "P", "V", "E", "P", "W", "G");

			tsbend = tsbp + entries;
			for (tsbstart = tsbp; tsbp < tsbend; tsbp++) {
				if (aflag ||
				    (tsbp->tte_tag.tag_invalid == 0)) {

					va = (caddr_t)
					    (((uint64_t)tsbp->tte_tag.tag_vahi
					    << 32) +
					    tsbp->tte_tag.tag_valo);
					pa = (tsbp->tte_data.tte_pahi << 19) +
					    tsbp->tte_data.tte_palo;
					mdb_printf("%0?lx %-1u %-1u %011lx "
					    "%1u %-1u %-1u %-1u %-1u %1u %08x "
					    "%1u %1u %1u %1u %1u %1u %1u "
					    "%1u %1u %1u %1u %1u %1u\n",
					    tsbinfo.tsb_va + (tsbp - tsbstart)
					    * sizeof (struct tsbe),
					    tsbp->tte_tag.tag_invalid,
					    tsbp->tte_tag.tag_locked, va,
					    tsbp->tte_data.tte_val,
					    tsbp->tte_data.tte_size,
					    tsbp->tte_data.tte_nfo,
					    tsbp->tte_data.tte_ie,
					    tsbp->tte_data.tte_hmenum,
#ifdef sun4v
					    0,
#else
					    tsbp->tte_data.tte_size2,
#endif
					    pa,
					    tsbp->tte_data.tte_no_sync,
					    tsbp->tte_data.tte_suspend,
					    tsbp->tte_data.tte_ref,
					    tsbp->tte_data.tte_wr_perm,
#ifdef sun4v
					    0,
#else
					    tsbp->tte_data.tte_exec_synth,
#endif
					    tsbp->tte_data.tte_exec_perm,
					    tsbp->tte_data.tte_lock,
					    tsbp->tte_data.tte_cp,
					    tsbp->tte_data.tte_cv,
					    tsbp->tte_data.tte_se,
					    tsbp->tte_data.tte_priv,
					    tsbp->tte_data.tte_hwwr,
#ifdef sun4v
					    0
#else
					    tsbp->tte_data.tte_glb
#endif
					    /*CSTYLED*/
					    );
				}
			}

			mdb_printf("\n"); /* blank line for readability */

			mdb_free(tsbstart, sizeof (struct tsbe) * entries);

		} else {

			mdb_printf("TSB swapped out\n");
		}
	}

	return (DCMD_OK);
}
