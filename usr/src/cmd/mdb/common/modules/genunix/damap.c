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

#include <mdb/mdb_modapi.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/damap_impl.h>

#include "damap.h"

void
damap_help(void)
{
	mdb_printf("Print the damap at the address given.\n");
	mdb_printf("\n");
	mdb_printf("EXAMPLE: SCSI: To display the SCSI tgtmap damaps ");
	mdb_printf("associated with a scsi HBA driver iport dip:\n");
	mdb_printf("\n");
	mdb_printf("::devbindings -q <driver_name>\n");
	mdb_printf("\n");
	mdb_printf("<iport-dip>::print struct dev_info devi_driver_data|");
	mdb_printf("::print scsi_hba_tran_t tran_tgtmap|");
	mdb_printf("::print impl_scsi_tgtmap_t ");
	mdb_printf("tgtmap_dam[0] tgtmap_dam[1]|::damap\n");
}

static char *
local_strdup(const char *s)
{
	if (s)
		return (strcpy(mdb_alloc(strlen(s) + 1, UM_SLEEP), s));
	else
		return (NULL);
}

static void
local_strfree(const char *s)
{
	if (s)
		mdb_free((void *)s, strlen(s) + 1);
}

static void
bitset_free(bitset_t *bs, int embedded)
{
	if (bs == NULL)
		return;
	if (bs->bs_set && bs->bs_words)
		mdb_free(bs->bs_set, bs->bs_words * sizeof (ulong_t));
	if (!embedded)
		mdb_free(bs, sizeof (*bs));	/* not embedded, free */
}

static bitset_t *
bitset_get(uintptr_t bsaddr)
{
	bitset_t	*bs;

	bs = mdb_zalloc(sizeof (*bs), UM_SLEEP);
	if (mdb_vread(bs, sizeof (*bs), bsaddr) == -1) {
		mdb_warn("couldn't read bitset 0x%p", bsaddr);
		bitset_free(bs, 0);
		return (NULL);
	}

	bsaddr = (uintptr_t)bs->bs_set;
	bs->bs_set = mdb_alloc(bs->bs_words * sizeof (ulong_t), UM_SLEEP);
	if (mdb_vread(bs->bs_set,
	    bs->bs_words * sizeof (ulong_t), bsaddr) == -1) {
		mdb_warn("couldn't read bitset bs_set 0x%p", bsaddr);
		bitset_free(bs, 0);
		return (NULL);
	}
	return (bs);

}

static void
damap_free(struct dam *dam, void **kdamda, int kdamda_n)
{
	int			i;
	struct i_ddi_soft_state *ss;
	dam_da_t		*da;

	if (dam) {
		/* free in dam_da_t softstate */
		ss = (struct i_ddi_soft_state *)dam->dam_da;
		if (ss) {
			if (ss->n_items && ss->array) {
				for (i = 0; i < ss->n_items; i++) {
					da = ss->array[i];
					if (da == NULL)
						continue;
					local_strfree(da->da_addr);
					mdb_free(da, sizeof (*da));
				}
			}

			mdb_free(ss, sizeof (*ss));
		}

		/* free dam_active/stable/report_set embedded in dam */
		bitset_free(&dam->dam_report_set, 1);
		bitset_free(&dam->dam_stable_set, 1);
		bitset_free(&dam->dam_active_set, 1);

		/* free dam_name */
		local_strfree(dam->dam_name);

		/* free dam */
		mdb_free(dam, sizeof (*dam));
	}

	if (kdamda)
		mdb_free(kdamda, kdamda_n * sizeof (void *));
}

/*
 * The dam implementation uses a number of different abstractions. Given a
 * pointer to a damap_t, this function make an mdb instantiation of the dam -
 * many, but not all, of the different abstractions used in the dam
 * implementation are also instantiated in mdb. This means that callers of
 * damap_get can perform some (but not all) types of structure pointer
 * traversals.
 */
struct dam *
damap_get(uintptr_t damaddr, void ***pkdamda, int *pkdamda_n)
{
	/* variables that hold instantiation read from kernel */
	struct dam		kdam;
	char			kstring[MAXPATHLEN];
	struct i_ddi_soft_state kss;
	void			**kssarray = NULL;
	int			array_sz = 0;

	/* variables that hold mdb instantiation */
	struct dam		*dam = NULL;
	struct i_ddi_soft_state *ss;
	bitset_t		*bs;
	dam_da_t		*da;

	int			i;

	/* read kernel: dam */
	if (mdb_vread(&kdam, sizeof (kdam), damaddr) == -1) {
		mdb_warn("couldn't read dam 0x%p", damaddr);
		goto err;
	}

	/* read kernel: dam->dam_name */
	mdb_readstr(kstring, sizeof (kstring), (uintptr_t)kdam.dam_name);

	/* read kernel: dam->dam_da (softstate) */
	if (mdb_vread(&kss, sizeof (kss), (uintptr_t)kdam.dam_da) == -1) {
		mdb_warn("couldn't read dam dam_da 0x%p",
		    (uintptr_t)kdam.dam_da);
		goto err;
	}

	/* read kernel ((struct i_ddi_soft_state *)dam->dam_da)->array */
	array_sz = kss.n_items * sizeof (void *);
	kssarray = mdb_alloc(array_sz, UM_SLEEP);
	if (mdb_vread(kssarray, array_sz, (uintptr_t)kss.array) == -1) {
		mdb_warn("couldn't read dam dam_da array 0x%p",
		    (uintptr_t)kss.array);
		goto err;
	}

	/*
	 * Produce mdb instantiation of kernel data structures.
	 *
	 * Structure copy kdam to dam, then clear out pointers in dam (some
	 * will be filled in by mdb instantiation code below).
	 */
	dam = mdb_zalloc(sizeof (*dam), UM_SLEEP);
	*dam = kdam;
	dam->dam_name = NULL;

	dam->dam_active_set.bs_set = NULL;
	dam->dam_stable_set.bs_set = NULL;
	dam->dam_report_set.bs_set = NULL;

	dam->dam_da = NULL;
	/* dam_addr_hash, dam_taskqp, dam_kstatp left as kernel addresses */

	/* fill in dam_name */
	dam->dam_name = local_strdup(kstring);

	/* fill in dam_active/stable/report_set embedded in the dam */
	bs = bitset_get(damaddr + (offsetof(struct dam, dam_active_set)));
	if (bs) {
		dam->dam_active_set = *bs;
		mdb_free(bs, sizeof (*bs));
	}
	bs = bitset_get(damaddr + (offsetof(struct dam, dam_stable_set)));
	if (bs) {
		dam->dam_stable_set = *bs;
		mdb_free(bs, sizeof (*bs));
	}
	bs = bitset_get(damaddr + (offsetof(struct dam, dam_report_set)));
	if (bs) {
		dam->dam_report_set = *bs;
		mdb_free(bs, sizeof (*bs));
	}

	/* fill in dam_da_t softstate */
	ss = mdb_zalloc(sizeof (struct i_ddi_soft_state), UM_SLEEP);
	*ss = kss;
	ss->next = NULL;
	ss->array = mdb_zalloc(array_sz, UM_SLEEP);
	dam->dam_da = ss;
	for (i = 0; i < kss.n_items; i++) {
		if (kssarray[i] == NULL)
			continue;
		da = ss->array[i] = mdb_zalloc(sizeof (*da), UM_SLEEP);
		if (mdb_vread(da, sizeof (*da), (uintptr_t)kssarray[i]) == -1) {
			mdb_warn("couldn't read dam dam_da %d 0x%p", i,
			    (uintptr_t)kss.array);
			goto err;
		}
		/* da_nvl, da_ppriv_rpt, da_nvl_rpt left as kernel addresses */

		/* read kernel: da->da_addr */
		mdb_readstr(kstring, sizeof (kstring), (uintptr_t)da->da_addr);
		da->da_addr = local_strdup(kstring);
	}

	/* return array of kernel dam_da_t pointers associated with each id */
	*pkdamda = kssarray;
	*pkdamda_n = array_sz / sizeof (void *);

	/* return pointer to mdb instantiation of the dam */
	return (dam);

err:	damap_free(dam, kssarray, array_sz / sizeof (void *));
	*pkdamda = NULL;
	*pkdamda_n = 0;
	return (NULL);
}

/*ARGSUSED*/
static void
damap_print(struct dam *dam, void **kdamda, int kdamda_n)
{
	struct i_ddi_soft_state	*ss;
	dam_da_t		*da;
	int			i;

	mdb_printf("%s:\n", dam->dam_name);

	ss = (struct i_ddi_soft_state *)dam->dam_da;
	if (ss == NULL)
		return;

	if ((ss->n_items == 0) || (ss->array == NULL))
		return;

	for (i = 0; i < ss->n_items; i++) {
		da = ss->array[i];
		if (da == NULL)
			continue;

		/* Print index and address. */
		mdb_printf("  %3d: %s [", i, da->da_addr);

		/* Print shorthand of Active/Stable/Report set membership */
		if (BT_TEST(dam->dam_active_set.bs_set, i))
			mdb_printf("A");
		else
			mdb_printf(".");
		if (BT_TEST(dam->dam_stable_set.bs_set, i))
			mdb_printf("S");
		else
			mdb_printf(".");
		if (BT_TEST(dam->dam_report_set.bs_set, i))
			mdb_printf("R");
		else
			mdb_printf(".");

		/* Print the reference count and priv */
		mdb_printf("] %2d %0?lx %0?lx\n",
		    da->da_ref, da->da_cfg_priv, da->da_ppriv);

		mdb_printf("\t\t\t\t%p::print -ta dam_da_t\n", kdamda[i]);
	}
}

/*ARGSUSED*/
int
damap(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct dam	*dam;
	void		**kdamda;
	int		kdamda_n;

	dam = damap_get(addr, &kdamda, &kdamda_n);
	if (dam == NULL)
		return (DCMD_ERR);

	damap_print(dam, kdamda, kdamda_n);
	damap_free(dam, kdamda, kdamda_n);
	return (DCMD_OK);
}
