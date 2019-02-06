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

/*
 * Multidata dcmds and walkers, part of the genunix mdb module,
 * and operate on core Multidata structures.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include <sys/types.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/stream.h>
#include <sys/modctl.h>
#include <sys/strft.h>
#include <sys/sysmacros.h>

#include <sys/multidata.h>
#include <sys/multidata_impl.h>
#include <sys/pattr.h>

#include "mmd.h"

/*
 * Structure for passing internal variables.
 */
typedef struct mmd_data_s {
	uint_t	flags;		/* see flags values below */
	uint_t	counter;	/* scratch counter */
} mmd_data_t;

#define	MMD_VERBOSE	0x1	/* multidata: provide more info */
#define	MMD_STATS	0x2	/* multidata: provide statistics */
#define	PD_HDR		0x4	/* pdesc: count header region */
#define	PD_PLD		0x8	/* pdesc: count payload region(s) */
#define	PD_ATTR		0x10	/* pdesc: count local attributes */
#define	PD_REM_NOCNT	0x20	/* pdesc: do not count removed pdesc */

/*
 * Structure to support circular, doubly-linked list (ql_t) walker.
 */
typedef struct q_walk_s {
	char *qw_name;		/* name of opaque list structure */
	uintptr_t qw_head;	/* address of list head */
	void *qw_data;		/* opaque data structure */
	uint_t qw_sz;		/* size of opaque data structure */
	uint_t qw_off;		/* ql_t offset in opaque data structure */
	uint_t qw_step;		/* walk_step has been called */
	uint_t qw_iprint;	/* initial print */
} q_walk_t;

static int pdesc_slab_print(uintptr_t, q_walk_t *, mmd_data_t *);
static int pdesc_print(uintptr_t, q_walk_t *, mmd_data_t *);
static int pdesc_count(uintptr_t, q_walk_t *, mmd_data_t *);
static int pattr_print(uintptr_t, q_walk_t *, mmd_data_t *);
static int pattr_count(uintptr_t, q_walk_t *, mmd_data_t *);
static int multidata_stats(uintptr_t addr, multidata_t *);

#define	VA_OFF(x, o)	(((uchar_t *)(x) + (o)))

/*
 * A dcmd which prints a summary of a multidata_t structure.
 */
/* ARGSUSED */
int
multidata(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mmd_data_t data;
	multidata_t mmd;
	char str[32] = "-";
	int i = 0;

	bzero(&data, sizeof (data));
	if (!(flags & DCMD_ADDRSPEC) || mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, MMD_VERBOSE, &data.flags,
	    's', MDB_OPT_SETBITS, MMD_STATS, &data.flags, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&mmd, sizeof (mmd), addr) == -1) {
		mdb_warn("failed to read multidata_t structure at %p", addr);
		return (DCMD_ERR);
	}

	if (mmd.mmd_magic != MULTIDATA_MAGIC)
		mdb_printf("Incorrect Multidata magic number at %p\n",
		    VA_OFF(addr, offsetof(multidata_t, mmd_magic)));

	mdb_printf("\n");
	if (data.flags & MMD_STATS) {
		if ((i = multidata_stats(addr, &mmd)) != DCMD_OK)
			return (i);
	}

	mdb_printf("%<b>%-5s %-?s %-4s %-?s %-4s %-4s %-4s %-?s%</b>",
	    "PDESC", "PATTBL", "HBUF", "HBUF", "PBUF", "PBUF", "PBUF", "PBUF");
	mdb_printf("\n");
	mdb_printf("%<b>%<u>%-5s %-?s %-4s %-?s %-4s %-4s %-4s %-?s%</u>%</b>",
	    "CNT", "ADDRESS", "REF", "ADDRESS", "REF", "CNT", "IDX",
	    "ADDRESS(ES)");
	mdb_printf("\n");

	if (mmd.mmd_pattbl != 0)
		mdb_snprintf(str, sizeof (str), "%016p", mmd.mmd_pattbl);

	i = 0;
	mdb_printf("%-5d %-16s %-4d %016p %-4d %-4d %-4d %016p\n",
	    mmd.mmd_pd_cnt, str, mmd.mmd_hbuf_ref, mmd.mmd_hbuf,
	    mmd.mmd_pbuf_ref, mmd.mmd_pbuf_cnt, i, mmd.mmd_pbuf[i]);

	for (++i; i < mmd.mmd_pbuf_cnt; i++)
		mdb_printf("%-54s %-4d %016p\n", "", i, mmd.mmd_pbuf[i]);

	if (!(data.flags & MMD_VERBOSE))
		return (DCMD_OK);

	/* Walk packet descriptor slab list */
	if (mdb_pwalk("pdesc_slab", (mdb_walk_cb_t)pdesc_slab_print,
	    &data, (uintptr_t)VA_OFF(addr, offsetof(multidata_t,
	    mmd_pd_slab_q))) == -1) {
		mdb_warn("couldn't walk pdesc_slab_t list");
		return (DCMD_ERR);
	}

	/* Walk packet descriptor list */
	data.counter = 0;
	if (mdb_pwalk("pdesc", (mdb_walk_cb_t)pdesc_print,
	    &data, (uintptr_t)VA_OFF(addr, offsetof(multidata_t,
	    mmd_pd_q))) == -1) {
		mdb_warn("couldn't walk pdesc_t list");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * Print additional Multidata statistics
 */
static int
multidata_stats(uintptr_t addr, multidata_t *mmd)
{
	mblk_t mp;
	uint_t i = 0, j = 0, k = 0, sz = 0;
	mmd_data_t data;
	uintptr_t patbkt;

	bzero(&data, sizeof (data));

	if (mmd->mmd_hbuf != 0) {
		if (mdb_vread(&mp, sizeof (mp),
		    (uintptr_t)mmd->mmd_hbuf) == -1) {
			mdb_warn("couldn't read mblk_t at %p", mmd->mmd_hbuf);
			return (DCMD_ERR);
		}

		i++;
		sz = MBLKL(&mp);
	}

	k += sz;	/* total bytes */
	j += i;		/* total buffers */

	mdb_printf("%<b>%<u>BUFFER STATS%</b>%</u>\n");
	mdb_printf("Header:\t\t\t%-4d% buffer,\t%-12d bytes\n", i, sz);

	for (i = 0, sz = 0; i < mmd->mmd_pbuf_cnt; i++) {
		if (mdb_vread(&mp, sizeof (mp),
		    (uintptr_t)mmd->mmd_pbuf[i]) == -1) {
			mdb_warn("couldn't read mblk_t at %p",
			    mmd->mmd_pbuf[i]);
			return (DCMD_ERR);
		}
		sz += MBLKL(&mp);
	}

	k += sz;	/* total bytes */
	j += i;		/* total buffers */

	mdb_printf("%<u>Payload:\t\t%-4d buffers,\t%-12d bytes%</u>\n", i, sz);
	mdb_printf("Total:\t\t\t%-4d buffers,\t%-12d bytes\n\n", j, k);

	mdb_printf("%<b>%<u>PACKET DESCRIPTOR STATS%</u>%</b>\n");

	/*
	 * Total claimed packet descriptors
	 */
	data.flags = 0;
	data.counter = 0;
	if (mdb_pwalk("pdesc", (mdb_walk_cb_t)pdesc_count, &data,
	    (uintptr_t)VA_OFF(addr, offsetof(multidata_t, mmd_pd_q))) == -1) {
		mdb_warn("couldn't walk pdesc_t list");
		return (DCMD_ERR);
	}
	i = data.counter;	/* claimed */
	mdb_printf("Total claimed:\t\t%-4d", i);

	/*
	 * Total active header references
	 */
	data.flags = (PD_HDR | PD_REM_NOCNT);
	data.counter = 0;
	if (mdb_pwalk("pdesc", (mdb_walk_cb_t)pdesc_count, &data,
	    (uintptr_t)VA_OFF(addr, offsetof(multidata_t, mmd_pd_q))) == -1) {
		mdb_warn("couldn't walk pdesc_t list");
		return (DCMD_ERR);
	}
	mdb_printf("\tActive header refs:\t%-12d bytes\n", data.counter);

	/*
	 * Total active packet descriptors
	 */
	data.flags = PD_REM_NOCNT;
	data.counter = 0;
	if (mdb_pwalk("pdesc", (mdb_walk_cb_t)pdesc_count, &data,
	    (uintptr_t)VA_OFF(addr, offsetof(multidata_t, mmd_pd_q))) == -1) {
		mdb_warn("couldn't walk pdesc_t list");
		return (DCMD_ERR);
	}
	k = data.counter;	/* active */
	mdb_printf("Active:\t\t\t%-4d", data.counter);

	/*
	 * Total active payload references
	 */
	data.flags = (PD_PLD | PD_REM_NOCNT);
	data.counter = 0;
	if (mdb_pwalk("pdesc", (mdb_walk_cb_t)pdesc_count, &data,
	    (uintptr_t)VA_OFF(addr, offsetof(multidata_t, mmd_pd_q))) == -1) {
		mdb_warn("couldn't walk pdesc_t list");
		return (DCMD_ERR);
	}
	mdb_printf("\t%<u>Active payload refs:\t%-12d bytes%</u>\n",
	    data.counter);

	/*
	 * Number of removed packet descriptors (claimed - active)
	 */
	mdb_printf("Removed:\t\t%-4d", i - k);

	/*
	 * Total active header and payload references
	 */
	data.flags = (PD_PLD | PD_HDR | PD_REM_NOCNT);
	data.counter = 0;
	if (mdb_pwalk("pdesc", (mdb_walk_cb_t)pdesc_count, &data,
	    (uintptr_t)VA_OFF(addr, offsetof(multidata_t, mmd_pd_q))) == -1) {
		mdb_warn("couldn't walk pdesc_t list");
		return (DCMD_ERR);
	}
	mdb_printf("\tTotal:\t\t\t%-12d bytes\n\n", data.counter);

	mdb_printf("%<b>%<u>ACTIVE ATTRIBUTE STATS%</u>%</b>\n");

	/*
	 * Count local attributes
	 */
	data.flags = (PD_ATTR | PD_REM_NOCNT);
	data.counter = 0;
	if (mdb_pwalk("pdesc", (mdb_walk_cb_t)pdesc_count, &data,
	    (uintptr_t)VA_OFF(addr, offsetof(multidata_t, mmd_pd_q))) == -1) {
		mdb_warn("couldn't walk pdesc_t list");
		return (DCMD_ERR);
	}
	mdb_printf("Local:\t\t\t%-4d", data.counter);

	/*
	 * Count global attributes
	 */
	data.counter = 0;
	patbkt = (uintptr_t)mmd->mmd_pattbl;
	if (patbkt != 0) {
		uint_t pattbl_sz;

		/* Figure out the size of hash table */
		mdb_readvar(&pattbl_sz, "pattbl_sz");

		/* Walk each bucket and count its contents */
		for (i = 0; i < (pattbl_sz * sizeof (patbkt_t));
		    i += sizeof (patbkt_t)) {
			if (mdb_pwalk("pattr",
			    (mdb_walk_cb_t)pattr_count, &data,
			    patbkt + i + offsetof(patbkt_t,
			    pbkt_pattr_q)) == -1) {
				mdb_warn("couldn't walk pattr_t list");
				return (DCMD_ERR);
			}
		}
	}
	mdb_printf("\tGlobal:\t\t\t%-4d\n", data.counter);
	mdb_printf("\n");

	return (DCMD_OK);
}

/*
 * Print the contents of a packet descriptor slab (pdesc_slab_t) structure.
 */
/* ARGSUSED */
static int
pdesc_slab_print(uintptr_t addr, q_walk_t *qwp, mmd_data_t *data)
{
	pdesc_slab_t *slab;
	uint_t pdslab_sz, slab_sz;

	/* Figure out how many descriptors in a slab */
	mdb_readvar(&pdslab_sz, "pdslab_sz");

	/* This shouldn't be true, unless something awful has happened */
	if (pdslab_sz < 1) {
		mdb_warn("incorrect pdslab_sz (0)");
		pdslab_sz = 1;
	}

	/* Read in the entire slab chunk; may be of use one day */
	slab_sz = PDESC_SLAB_SIZE(pdslab_sz);
	slab = mdb_alloc(slab_sz, UM_SLEEP);

	if (mdb_vread(slab, slab_sz, addr) == -1) {
		mdb_free(slab, slab_sz);
		mdb_warn("failed to read pdesc_slab_t at %p", addr);
		return (WALK_ERR);
	}

	if (!qwp->qw_step)
		mdb_printf("\n%<b>%<u>%-?s %7s %7s%</u>%</b>\n",
		    "PDESC SLAB ADDR", "SIZE", "CLAIMED");

	mdb_printf("%016p %7d %7d\n", addr, slab->pds_sz, slab->pds_used);

	mdb_free(slab, slab_sz);

	return (WALK_NEXT);
}

/*
 * Generic packet descriptor (pdesc_t) counting routine.
 */
/* ARGSUSED */
static int
pdesc_count(uintptr_t addr, q_walk_t *qwp, mmd_data_t *data)
{
	pdesc_t pd;
	int i;
	uint_t f = data->flags;

	if (mdb_vread(&pd, sizeof (pd), addr) == -1) {
		mdb_warn("failed to read pdesc_t at %p", addr);
		return (WALK_ERR);
	}

	if (pd.pd_magic != PDESC_MAGIC)
		mdb_printf("Incorrect pdesc magic number at %p\n",
		    VA_OFF(addr, offsetof(pdesc_t, pd_magic)));

	if (f == 0) {
		/* No flags set, count all pdescs */
		data->counter++;
	} else if (f == PD_REM_NOCNT && !(pd.pd_pdi.flags & PDESC_REM_DEFER)) {
		/* Count only active (skip removed) pdescs */
		data->counter++;
	} else if (f & PD_ATTR) {
		uint_t pattbl_sz;
		uintptr_t patbkt = (uintptr_t)pd.pd_pattbl;
		mmd_data_t attr_data;

		/* Count local attributes */
		if ((!(f & PD_REM_NOCNT) || ((f & PD_REM_NOCNT) &&
		    !(pd.pd_pdi.flags & PDESC_REM_DEFER))) && patbkt != 0) {

			/* Figure out the size of hash table */
			mdb_readvar(&pattbl_sz, "pattbl_sz");

			attr_data.counter = 0;
			/* Walk each bucket and count its contents */
			for (i = 0; i < (pattbl_sz * sizeof (patbkt_t));
			    i += sizeof (patbkt_t)) {
				if (mdb_pwalk("pattr",
				    (mdb_walk_cb_t)pattr_count, &attr_data,
				    patbkt + i + offsetof(patbkt_t,
				    pbkt_pattr_q)) == -1) {
					mdb_warn("couldn't walk pattr_t list");
					return (WALK_ERR);
				}
			}
			data->counter += attr_data.counter;
		}
	} else {
		if (f & PD_HDR) {
			/* Count header span referenced by pdesc */
			if (!(f & PD_REM_NOCNT) || ((f & PD_REM_NOCNT) &&
			    !(pd.pd_pdi.flags & PDESC_REM_DEFER)))
				data->counter += PDESC_HDRL(&pd.pd_pdi);
		}

		if (f & PD_PLD) {
			/* Count payload span referenced by pdesc */
			if (!(f & PD_REM_NOCNT) || ((f & PD_REM_NOCNT) &&
			    !(pd.pd_pdi.flags & PDESC_REM_DEFER))) {
				for (i = 0; i < pd.pd_pdi.pld_cnt; i++)
					data->counter += PDESC_PLD_SPAN_SIZE(
					    &pd.pd_pdi, i);
			}
		}
	}

	return (WALK_NEXT);
}

/*
 * Print the contents of a packet descriptor (pdesc_t) structure.
 */
/* ARGSUSED */
static int
pdesc_print(uintptr_t addr, q_walk_t *qwp, mmd_data_t *data)
{
	pdesc_t pd;
	int i = 0;
	char str[32] = "-";
	static const mdb_bitmask_t pd_flags_bits[] = {
		{ "H", PDESC_HBUF_REF, PDESC_HBUF_REF },
		{ "P", PDESC_PBUF_REF, PDESC_PBUF_REF },
		{ "R", PDESC_REM_DEFER, PDESC_REM_DEFER },
		{ NULL, 0, 0 }
	};

	if (mdb_vread(&pd, sizeof (pd), addr) == -1) {
		mdb_warn("failed to read pdesc_t at %p", addr);
		return (WALK_ERR);
	}

	if (pd.pd_magic != PDESC_MAGIC)
		mdb_printf("Incorrect pdesc magic number at %p\n",
		    VA_OFF(addr, offsetof(pdesc_t, pd_magic)));

	if (!qwp->qw_step) {
		mdb_printf("\n");
		mdb_printf("%<b>%-3s %-16s %-16s %-4s %-4s %-4s %-4s %-4s %-4s "
		    "%-4s %-6s%</b>",
		    "", "PDESC", "PATTBL", "HDR", "HDR",
		    "HDR", "HDR", "PLD", "PBUF", "PLD", "");
		mdb_printf("\n");
		mdb_printf(
		    "%<b>%<u>%-3s %-16s %-16s %-4s %-4s %-4s %-4s %-4s %-4s "
		    "%-4s %-6s%</u>%</b>",
		    "NO.", "ADDRESS", "ADDRESS", "SIZE", "HEAD",
		    "LEN", "TAIL", "CNT", "IDX", "SIZE", "FLAGS");
		mdb_printf("\n");
	}

	if (pd.pd_pattbl != 0)
		mdb_snprintf(str, sizeof (str), "%016p", pd.pd_pattbl);

	mdb_printf("%-3d %016p %-16s %-4d %-4d %-4d %-4d %-4d %-4d %-4d %-6b\n",
	    ++data->counter, addr, str,
	    PDESC_HDRSIZE(&pd.pd_pdi), PDESC_HDRHEAD(&pd.pd_pdi),
	    PDESC_HDRL(&pd.pd_pdi), PDESC_HDRTAIL(&pd.pd_pdi),
	    pd.pd_pdi.pld_cnt, pd.pd_pdi.pld_ary[i].pld_pbuf_idx,
	    PDESC_PLD_SPAN_SIZE(&pd.pd_pdi, i), pd.pd_pdi.flags, pd_flags_bits);

	for (++i; i < pd.pd_pdi.pld_cnt; i++)
		mdb_printf("%-62s %-4d %-4d\n",
		    "", pd.pd_pdi.pld_ary[i].pld_pbuf_idx,
		    PDESC_PLD_SPAN_SIZE(&pd.pd_pdi, i));

	return (WALK_NEXT);
}

/*
 * General purpose ql_t walk_init routine.
 */
static int
mmdq_walk_init(mdb_walk_state_t *wsp, char *name, uintptr_t qh,
    uint_t sz, uint_t ql_off)
{
	q_walk_t *qwp;
	ql_t ql;

	/* Caller must have supplied an address */
	if (wsp->walk_addr == 0)
		return (WALK_ERR);

	qwp = mdb_alloc(sizeof (*qwp), UM_SLEEP);
	qwp->qw_name = name;
	qwp->qw_head = qh;
	qwp->qw_data = sz > 0 ? mdb_alloc(sz, UM_SLEEP) : NULL;
	qwp->qw_sz = sz;
	qwp->qw_off = ql_off;
	qwp->qw_step = FALSE;
	qwp->qw_iprint = TRUE;

	wsp->walk_data = qwp;

	if (mdb_vread(qwp->qw_data, qwp->qw_sz, wsp->walk_addr) == -1) {
		mdb_warn("failed to read %s at %p", qwp->qw_name,
		    wsp->walk_addr);
		mmdq_walk_fini(wsp);
		return (WALK_ERR);
	}

	bcopy((uchar_t *)qwp->qw_data + qwp->qw_off, &ql, sizeof (ql));
	if (qh == (uintptr_t)ql.ql_next) {
		mmdq_walk_fini(wsp);
		return (WALK_DONE);
	}

	wsp->walk_addr = (uintptr_t)ql.ql_next;

	return (WALK_NEXT);
}

/*
 * General purpose ql_t walk_step routine.
 */
int
mmdq_walk_step(mdb_walk_state_t *wsp)
{
	q_walk_t *qwp = (q_walk_t *)wsp->walk_data;
	int status = WALK_NEXT;
	ql_t ql;

	/* We've wrapped around the circular list */
	if (qwp->qw_step && wsp->walk_addr == qwp->qw_head)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	if (mdb_vread(qwp->qw_data, qwp->qw_sz, wsp->walk_addr) == -1) {
		mdb_warn("failed to read %s at %p", qwp->qw_name,
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	/* Go forward to the next one */
	bcopy((uchar_t *)qwp->qw_data + qwp->qw_off, &ql, sizeof (ql));
	wsp->walk_addr = (uintptr_t)ql.ql_next;

	/* We've done the first walk */
	qwp->qw_step = TRUE;

	return (status);
}

/*
 * General purpose ql_t walk_fini routine.
 */
void
mmdq_walk_fini(mdb_walk_state_t *wsp)
{
	q_walk_t *qwp = (q_walk_t *)wsp->walk_data;

	if (qwp->qw_data != NULL)
		mdb_free(qwp->qw_data, qwp->qw_sz);

	mdb_free(qwp, sizeof (*qwp));
}

/*
 * Packet descriptor slab (pdesc_slab_t) walker initialization routine.
 */
int
pdesc_slab_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t q_head;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	/*
	 * If we're called from multidata dcmd, then we're passed in
	 * the address of ql_t head; otherwise we'd have to get the
	 * address ourselves.
	 */
	if (wsp->walk_cbdata == NULL) {
		pdesc_slab_t slab;

		/* Read in pdesc_slab_t */
		if (mdb_vread(&slab, sizeof (slab), wsp->walk_addr) == -1) {
			mdb_warn("failed to read pdesc_slab_t at %p",
			    wsp->walk_addr);
			return (WALK_ERR);
		}

		/* pdesc_slab_t head is inside multidata_t */
		q_head = (uintptr_t)VA_OFF(slab.pds_mmd,
		    offsetof(multidata_t, mmd_pd_slab_q));
	} else
		q_head = wsp->walk_addr;

	/* Pass it on to our generic ql_t walker init */
	return (mmdq_walk_init(wsp, "pdesc_slab_t", q_head,
	    sizeof (pdesc_slab_t), offsetof(pdesc_slab_t, pds_next)));
}

/*
 * A dcmd which returns a multidata_t pointer from a pdesc_slab_t structure.
 */
/* ARGSUSED */
int
slab2multidata(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pdesc_slab_t slab;

	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&slab, sizeof (slab), addr) == -1) {
		mdb_warn("couldn't read pdesc_slab_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%p\n", slab.pds_mmd);

	return (DCMD_OK);
}

/*
 * Packet descriptor (pdesc_t) walker initialization routine.
 */
int
pdesc_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t q_head;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	/*
	 * If we're called from multidata dcmd, then we're passed in
	 * the address of ql_t head; otherwise we'd have to get the
	 * address ourselves.
	 */
	if (wsp->walk_cbdata == NULL) {
		pdesc_t pd;
		pdesc_slab_t slab;

		/* First we get pdsec_t */
		if (mdb_vread(&pd, sizeof (pd), wsp->walk_addr) == -1) {
			mdb_warn("failed to read pdesc_t at %p",
			    wsp->walk_addr);
			return (WALK_ERR);
		}

		/* And then the pdesc_slab_t */
		if (mdb_vread(&slab, sizeof (slab),
		    (uintptr_t)pd.pd_slab) == -1) {
			mdb_warn("failed to read pdesc_slab_t at %p",
			    (uintptr_t)pd.pd_slab);
			return (WALK_ERR);
		}

		/* pdesc_t head is inside multidata_t */
		q_head = (uintptr_t)VA_OFF(slab.pds_mmd,
		    offsetof(multidata_t, mmd_pd_q));
	} else
		q_head = wsp->walk_addr;

	/* Pass it on to our generic ql_t walker init */
	return (mmdq_walk_init(wsp, "pdesc_t", q_head,
	    sizeof (pdesc_t), offsetof(pdesc_t, pd_next)));
}

/*
 * A dcmd which prints the attribute hash table.
 */
/* ARGSUSED */
int
pattbl(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mmd_data_t data;
	uint_t pattbl_sz;
	int i, j;

	bzero(&data, sizeof (data));
	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	/* Figure out the size of hash table */
	mdb_readvar(&pattbl_sz, "pattbl_sz");

	mdb_printf("\n");
	mdb_printf("%<b>%<u>%-3s %-16s %-16s %-12s %-3s %-16s %-5s%</u>%</b>\n",
	    "BKT", "PATBKT ADDR", "PATTR ADDR", "TYPE", "LEN", "BUF ADDR",
	    "FLAGS");

	/* Walk each bucket and print its contents */
	for (i = 0, j = 0; i < (pattbl_sz * sizeof (patbkt_t));
	    i += sizeof (patbkt_t)) {

		mdb_printf("%-3d %016p ", j++, addr + i);

		if (mdb_pwalk("pattr", (mdb_walk_cb_t)pattr_print, &data,
		    addr + i + offsetof(patbkt_t, pbkt_pattr_q)) == -1) {
			mdb_warn("couldn't walk pattr_t list");
			return (DCMD_ERR);
		}
		mdb_printf("\n");
	}
	mdb_printf("\n");

	return (DCMD_OK);
}

typedef struct pattr_type_s {
	char *name;	/* attribute name */
	uint_t type;	/* attribute type value */
} pattr_type_t;

/*
 * Generic packet attribute (pattr_t) counting routine.
 */
/* ARGSUSED */
static int
pattr_count(uintptr_t addr, q_walk_t *qwp, mmd_data_t *data)
{
	pattr_t pattr;

	if (mdb_vread(&pattr, sizeof (pattr), addr) == -1) {
		mdb_warn("failed to read pattr_t at %p", addr);
		return (WALK_ERR);
	}

	if (pattr.pat_magic != PATTR_MAGIC)
		mdb_printf("Incorrect pattr magic number at %p\n",
		    VA_OFF(addr, offsetof(pattr_t, pat_magic)));

	data->counter++;

	return (WALK_NEXT);
}

/*
 * Print the contents of a packet attribute (pattr_t) structure.
 */
/* ARGSUSED */
static int
pattr_print(uintptr_t addr, q_walk_t *qwp, mmd_data_t *data)
{
	pattr_t pattr;
	int i;
	char *pa_name = "UNKNOWN";
	static const pattr_type_t pa_type[] = {
		{ "DSTADDRSAP", PATTR_DSTADDRSAP },
		{ "SRCADDRSAP", PATTR_SRCADDRSAP },
		{ "HCKSUM", PATTR_HCKSUM }
	};
	static const mdb_bitmask_t pa_flags_bits[] = {
		{ "R", PATTR_REM_DEFER, PATTR_REM_DEFER },
		{ "P", PATTR_PERSIST, PATTR_PERSIST },
		{ NULL, 0, 0 }
	};

	if (mdb_vread(&pattr, sizeof (pattr), addr) == -1) {
		mdb_warn("failed to read pattr_t at %p", addr);
		return (WALK_ERR);
	}

	if (pattr.pat_magic != PATTR_MAGIC)
		mdb_printf("Incorrect pattr magic number at %p\n",
		    VA_OFF(addr, offsetof(pattr_t, pat_magic)));

	/* Find a matching string */
	for (i = 0; i < (sizeof (pa_type) / sizeof (*pa_type)); i++) {
		if (pa_type[i].type == pattr.pat_type)
			pa_name = pa_type[i].name;
	}

	if (!qwp->qw_iprint) {
		mdb_printf("\n");
		mdb_inc_indent(21);
	}

	mdb_printf("%016p %x:%-10s %-3d %016p %-5b", addr, pattr.pat_type,
	    pa_name, pattr.pat_buflen - sizeof (pattr), addr + sizeof (pattr),
	    pattr.pat_flags, pa_flags_bits);

	if (!qwp->qw_iprint)
		mdb_dec_indent(21);
	else
		qwp->qw_iprint = FALSE;

	return (WALK_NEXT);
}

/*
 * Packet attribute (pattr_t) walker initialization routine.
 */
int
pattr_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t q_head;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	/*
	 * If we're called from pattbl dcmd, then we're passed in
	 * the address of ql_t head; otherwise we'd have to get the
	 * address ourselves.
	 */
	if (wsp->walk_cbdata == NULL) {
		pattr_t pattr;

		if (mdb_vread(&pattr, sizeof (pattr), wsp->walk_addr) == -1) {
			mdb_warn("failed to read pattr_t at %p",
			    wsp->walk_addr);
			return (WALK_ERR);
		}

		q_head = (uintptr_t)VA_OFF(pattr.pat_lock,
		    -offsetof(patbkt_t, pbkt_lock)) +
		    offsetof(patbkt_t, pbkt_pattr_q);
	} else
		q_head = wsp->walk_addr;

	/* Pass it on to our generic ql_t walker init */
	return (mmdq_walk_init(wsp, "pattr_t", q_head,
	    sizeof (pattr_t), offsetof(pattr_t, pat_next)));
}

/*
 * A dcmd which returns a multidata_t pointer from a pattr_t.
 */
/* ARGSUSED */
int
pattr2multidata(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pattr_t pattr;

	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&pattr, sizeof (pattr), addr) == -1) {
		mdb_warn("couldn't read pattr_t at %p", addr);
		return (DCMD_ERR);
	}

	if (pattr.pat_magic != PATTR_MAGIC) {
		mdb_warn("Incorrect pattr magic number at %p",
		    VA_OFF(addr, offsetof(pattr_t, pat_magic)));
		return (DCMD_ERR);
	}

	mdb_printf("%p\n", pattr.pat_mmd);

	return (DCMD_OK);
}

/*
 * A dcmd which returns a pdesc_slab_t from a pdesc_t.
 */
/* ARGSUSED */
int
pdesc2slab(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pdesc_t pd;

	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&pd, sizeof (pd), addr) == -1) {
		mdb_warn("couldn't read pdesc_t at %p", addr);
		return (DCMD_ERR);
	}

	if (pd.pd_magic != PDESC_MAGIC) {
		mdb_warn("Incorrect pdesc magic number at %p",
		    VA_OFF(addr, offsetof(pdesc_t, pd_magic)));
		return (DCMD_ERR);
	}

	mdb_printf("%p\n", pd.pd_slab);

	return (DCMD_OK);
}

/*
 * A dcmd which verifies the integrity of a pdesc_t.
 */
/* ARGSUSED */
int
pdesc_verify(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	multidata_t mmd;
	pdesc_t pd;
	pdescinfo_t *pdi = &pd.pd_pdi;
	pdesc_slab_t slab;
	mblk_t hbuf, pbuf[MULTIDATA_MAX_PBUFS];
	uint_t i, idx;
	boolean_t valid = B_TRUE;
	struct pld_ary_s *pa;

	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&pd, sizeof (pd), addr) == -1) {
		mdb_warn("couldn't read pdesc_t at %p", addr);
		return (DCMD_ERR);
	}

	if (pd.pd_magic != PDESC_MAGIC) {
		mdb_warn("Incorrect pdesc magic number at %p\n",
		    VA_OFF(addr, offsetof(pdesc_t, pd_magic)));
		return (DCMD_ERR);
	}

	if (mdb_vread(&slab, sizeof (slab), (uintptr_t)pd.pd_slab) == -1) {
		mdb_warn("couldn't read pdesc_slab_t at %p", pd.pd_slab);
		return (DCMD_ERR);
	}

	if (mdb_vread(&mmd, sizeof (mmd), (uintptr_t)slab.pds_mmd) == -1) {
		mdb_warn("couldn't read multidata_t at %p", slab.pds_mmd);
		return (DCMD_ERR);
	}

	if (mmd.mmd_magic != MULTIDATA_MAGIC)
		mdb_printf("Incorrect Multidata magic number at %p\n",
		    VA_OFF(slab.pds_mmd, offsetof(multidata_t, mmd_magic)));

	if (mmd.mmd_hbuf != 0 &&
	    mdb_vread(&hbuf, sizeof (hbuf), (uintptr_t)mmd.mmd_hbuf) == -1) {
		mdb_warn("couldn't read mblk_t at %p", mmd.mmd_hbuf);
		return (DCMD_ERR);
	}

	if (mmd.mmd_pbuf_cnt > MULTIDATA_MAX_PBUFS) {
		mdb_warn("Multidata pbuf count exceeds %d\n",
		    MULTIDATA_MAX_PBUFS);
		return (DCMD_ERR);
	} else if (pdi->pld_cnt > mmd.mmd_pbuf_cnt) {
		mdb_warn("descriptor pbuf count exceeds Multidata "
		    "pbuf count %d\n", mmd.mmd_pbuf_cnt);
		return (DCMD_ERR);
	}

	if (mmd.mmd_pbuf_cnt > 0) {
		for (i = 0; i < mmd.mmd_pbuf_cnt; i++) {
			if (mdb_vread(&pbuf[i], sizeof (mblk_t),
			    (uintptr_t)mmd.mmd_pbuf[i]) == -1) {
				mdb_warn("couldn't read mblk_t at %p",
				    mmd.mmd_pbuf[i]);
				return (DCMD_ERR);
			}
		}
	}

	/* It should have at least one buffer reference */
	if (!(pdi->flags & PDESC_HAS_REF)) {
		mdb_warn("descriptor has no buffer reference indicator "
		    "in flags (0x%x)\n", pdi->flags);
		return (DCMD_ERR);
	} else if (!(pdi->flags & PDESC_PBUF_REF) && pdi->pld_cnt > 0) {
		mdb_warn("descriptor has no pbuf reference indicator in "
		    "flags (0x%x); but pld_cnt is %d\n", pdi->flags,
		    pdi->pld_cnt);
		return (DCMD_ERR);
	}

	/* Bounds check the header fragment, if any */
	if (!((pdi->flags & PDESC_HBUF_REF) && pdi->hdr_rptr != 0 &&
	    pdi->hdr_wptr != 0 && pdi->hdr_base != 0 &&
	    pdi->hdr_lim != 0 && pdi->hdr_lim >= pdi->hdr_base &&
	    pdi->hdr_wptr >= pdi->hdr_rptr && pdi->hdr_base <= pdi->hdr_rptr &&
	    pdi->hdr_lim >= pdi->hdr_wptr && pdi->hdr_base >= hbuf.b_rptr &&
	    MBLKIN(&hbuf, (pdi->hdr_base - hbuf.b_rptr),
	    PDESC_HDRSIZE(pdi)))) {
		mdb_warn("descriptor has invalid header fragment\n");
		return (DCMD_ERR);
	}

	i = 0;
	pa = &pdi->pld_ary[0];
	/* Bounds check the payload fragment, if any */
	while (valid && i < pdi->pld_cnt) {
		valid = (((idx = pa->pld_pbuf_idx) < mmd.mmd_pbuf_cnt) &&
		    pa->pld_rptr != NULL && pa->pld_wptr != NULL &&
		    pa->pld_wptr >= pa->pld_rptr &&
		    pa->pld_rptr >= pbuf[idx].b_rptr &&
		    MBLKIN(&pbuf[idx], (pa->pld_rptr - pbuf[idx].b_rptr),
			PDESC_PLD_SPAN_SIZE(pdi, i)));

		if (!valid) {
			mdb_warn("descriptor has invalid payload fragment\n");
			return (DCMD_ERR);
		}

		/* advance to next entry */
		i++;
		pa++;
	}

	return (DCMD_OK);
}
