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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/async.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pcicmu/pcicmu.h>
#include <sys/machsystm.h>
#include <sys/kstat.h>

static kstat_t *pcmu_create_picN_kstat(char *, int, int, int,
	pcmu_kev_mask_t *);

void
pcmu_kstat_create(pcmu_t *pcmu_p)
{
	pcmu_add_upstream_kstat(pcmu_p);
}

void
pcmu_kstat_destroy(pcmu_t *pcmu_p)
{
	pcmu_rem_upstream_kstat(pcmu_p);
}

void
pcmu_create_name_kstat(char *name, pcmu_ksinfo_t *pp, pcmu_kev_mask_t *ev)
{
	int	i;

	for (i = 0; i < NUM_OF_PICS; i++) {
		pp->pic_name_ksp[i] = pcmu_create_picN_kstat(name,
		    i, pp->pic_shift[i], pp->pic_no_evs, ev);

		if (pp->pic_name_ksp[i] == NULL) {
			cmn_err(CE_WARN, "pci: unable to create name kstat");
		}
	}
}

void
pcmu_delete_name_kstat(pcmu_ksinfo_t *pp)
{
	int	i;

	if (pp == NULL) {
		return;
	}
	for (i = 0; i < NUM_OF_PICS; i++) {
		if (pp->pic_name_ksp[i] != NULL)
			kstat_delete(pp->pic_name_ksp[i]);
	}
}

/*
 * Create the picN kstat. Returns a pointer to the
 * kstat which the driver must store to allow it
 * to be deleted when necessary.
 */
static kstat_t *
pcmu_create_picN_kstat(char *mod_name, int pic, int pic_shift,
    int num_ev, pcmu_kev_mask_t *ev_array)
{
	struct kstat_named *pic_named_data;
	int	inst = 0;
	int	event;
	char	pic_name[30];
	kstat_t	*picN_ksp = NULL;

	(void) sprintf(pic_name, "pic%d", pic);
	if ((picN_ksp = kstat_create(mod_name, inst, pic_name,
	    "bus", KSTAT_TYPE_NAMED, num_ev, 0)) == NULL) {
		cmn_err(CE_WARN, "%s %s : kstat create failed",
		    mod_name, pic_name);

		/*
		 * It is up to the calling function to delete any kstats
		 * that may have been created already. We just
		 * return NULL to indicate an error has occured.
		 */
		return (NULL);
	}

	pic_named_data = (struct kstat_named *)picN_ksp->ks_data;

	/*
	 * Write event names and their associated pcr masks. The
	 * last entry in the array (clear_pic) is added seperately
	 * below as the pic value must be inverted.
	 */
	for (event = 0; event < num_ev - 1; event++) {
		pic_named_data[event].value.ui64 =
		    (ev_array[event].pcr_mask << pic_shift);

		kstat_named_init(&pic_named_data[event],
		    ev_array[event].event_name, KSTAT_DATA_UINT64);
	}

	/*
	 * add the clear_pic entry.
	 */
	pic_named_data[event].value.ui64 =
	    (uint64_t)~(ev_array[event].pcr_mask << pic_shift);

	kstat_named_init(&pic_named_data[event],
	    ev_array[event].event_name, KSTAT_DATA_UINT64);

	kstat_install(picN_ksp);
	return (picN_ksp);
}

/*
 * Create the "counters" kstat.
 */
kstat_t *pcmu_create_cntr_kstat(pcmu_t *pcmu_p, char *name,
	int num_pics, int (*update)(kstat_t *, int),
	void *cntr_addr_p)
{
	struct kstat_named *counters_named_data;
	struct kstat	*counters_ksp;
	dev_info_t	*dip = pcmu_p->pcmu_dip;
	char		*drv_name = (char *)ddi_driver_name(dip);
	int		drv_instance = ddi_get_instance(dip);
	char		pic_str[10];
	int		i;

	/*
	 * Size of kstat is num_pics + 1 as it
	 * also contains the %pcr
	 */
	if ((counters_ksp = kstat_create(name, drv_instance,
	    "counters", "bus", KSTAT_TYPE_NAMED, num_pics + 1,
	    KSTAT_FLAG_WRITABLE)) == NULL) {
		cmn_err(CE_WARN, "%s%d counters kstat_create failed",
		    drv_name, drv_instance);
		return (NULL);
	}

	counters_named_data = (struct kstat_named *)(counters_ksp->ks_data);

	/* initialize the named kstats */
	kstat_named_init(&counters_named_data[0], "pcr", KSTAT_DATA_UINT64);

	for (i = 0; i < num_pics; i++) {
		(void) sprintf(pic_str, "pic%d", i);
		kstat_named_init(&counters_named_data[i+1],
		    pic_str, KSTAT_DATA_UINT64);
	}

	/*
	 * Store the register offset's in the kstat's
	 * private field so that they are available
	 * to the update function.
	 */
	counters_ksp->ks_private = (void *)cntr_addr_p;
	counters_ksp->ks_update = update;
	kstat_install(counters_ksp);
	return (counters_ksp);
}

/*
 * kstat update function. Handles reads/writes
 * from/to kstat.
 */
int
pcmu_cntr_kstat_update(kstat_t *ksp, int rw)
{
	struct kstat_named	*data_p;
	pcmu_cntr_addr_t	*cntr_addr_p = ksp->ks_private;
	uint64_t	pic;

	data_p = (struct kstat_named *)ksp->ks_data;
	if (rw == KSTAT_WRITE) {
		*cntr_addr_p->pcr_addr = data_p[0].value.ui64;
		return (0);
	} else {
		pic = *cntr_addr_p->pic_addr;
		data_p[0].value.ui64 = *cntr_addr_p->pcr_addr;

		/* pic0 : lo 32 bits */
		data_p[1].value.ui64 = (pic <<32) >> 32;
		/* pic1 : hi 32 bits */
		data_p[2].value.ui64 = pic >> 32;
	}
	return (0);
}

/*
 * kstat update function using physical addresses.
 */
int
pcmu_cntr_kstat_pa_update(kstat_t *ksp, int rw)
{
	struct kstat_named	*data_p;
	pcmu_cntr_pa_t *cntr_pa_p = (pcmu_cntr_pa_t *)ksp->ks_private;
	uint64_t	pic;

	data_p = (struct kstat_named *)ksp->ks_data;

	if (rw == KSTAT_WRITE) {
		stdphysio(cntr_pa_p->pcr_pa, data_p[0].value.ui64);
		return (0);
	} else {
		pic = lddphysio(cntr_pa_p->pic_pa);
		data_p[0].value.ui64 = lddphysio(cntr_pa_p->pcr_pa);

		/* pic0 : lo 32 bits */
		data_p[1].value.ui64 = (pic << 32) >> 32;
		/* pic1 : hi 32 bits */
		data_p[2].value.ui64 = pic >> 32;
	}
	return (0);
}


/*
 * Matched with pcmu_add_upstream_kstat()
 */
void
pcmu_rem_upstream_kstat(pcmu_t *pcmu_p)
{
	if (pcmu_p->pcmu_uksp != NULL)
		kstat_delete(pcmu_p->pcmu_uksp);
	pcmu_p->pcmu_uksp = NULL;
}
