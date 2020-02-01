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
#include <sys/kstat.h>
#include "n2piupc_acc.h"
#include "n2piupc_tables.h"
#include "n2piupc.h"
#include "n2piupc_biterr.h"

#define	PIC_STR_LEN	5	/* Size of a PICx name string. */

static int n2piupc_create_name_kstat(n2piu_grp_t *grp);
static void n2piupc_delete_name_kstats(kstat_t **name_kstats_pp,
    int num_kstats);
static kstat_t *n2piupc_create_cntr_kstat(char *name, int dev_inst,
    int (*update)(kstat_t *, int), n2piu_ksinfo_t *ksinfop, int num_pics);
static int n2piupc_kstat_update(kstat_t *ksp, int rw);
static kstat_t *n2piupc_create_picN_kstat(char *mod_name, int pic,
    uint64_t mask, int num_ev, n2piu_event_t *ev_array);
static int n2piupc_write(n2piupc_t *n2piupc_p, int regid, uint64_t data);

/*
 * One-time initialization for this module.
 */
int
n2piupc_kstat_init()
{
	n2piu_grp_t **grp_pp;
	n2piu_grp_t *grp_p;

	N2PIUPC_DBG2("n2piupc: kstat_init: enter\n");

	/*
	 * Initialize the name kstats for each group, drawing upon the table
	 * for values.
	 */
	for (grp_pp = leaf_grps; *grp_pp != NULL; grp_pp++) {

		grp_p = *grp_pp;

		N2PIUPC_DBG2("Setting up group for %s\n", grp_p->grp_name);

		/* Create basic pic event-type pair. */
		grp_p->name_kstats_pp = kmem_zalloc((grp_p->num_counters *
		    sizeof (kstat_t)), KM_SLEEP);
		if (n2piupc_create_name_kstat(grp_p) != DDI_SUCCESS) {
			n2piupc_kstat_fini();
			N2PIUPC_DBG1("n2piupc: init: failure exit\n");
			return (DDI_FAILURE);
		}
	}

	N2PIUPC_DBG2("n2piupc: kstat_init: success exit\n");

	return (DDI_SUCCESS);
}

/*
 * Per-instance initialization for this module.
 */
int
n2piupc_kstat_attach(n2piupc_t *n2piupc_p)
{
	n2piu_grp_t **grp_pp;
	n2piu_grp_t *grp_p;
	n2piu_ksinfo_t *ksinfo_p;

	int i;

	N2PIUPC_DBG2("n2piupc: kstat_attach %d: enter\n",
	    ddi_get_instance(n2piupc_p->n2piupc_dip));

	/* Initialize biterr module.  Save opaque result. */
	if (n2piupc_biterr_attach(&n2piupc_p->n2piupc_biterr_p) != DDI_SUCCESS)
		goto err;

	/* Set up kstats for each group. */
	for (i = 0, grp_pp = leaf_grps; *grp_pp != NULL; i++, grp_pp++) {

		grp_p = *grp_pp;

		/*
		 * ksinfo_p keeps all info needed by n2piupc_kstat_update,
		 * which is fired off asynchronously on demand by the kstat
		 * framework.
		 */
		ksinfo_p = (n2piu_ksinfo_t *)kmem_zalloc(
		    sizeof (n2piu_ksinfo_t), KM_SLEEP);

		ksinfo_p->n2piupc_p = n2piupc_p;
		ksinfo_p->grp_p  = grp_p;

		/* Also save in state structure, for later cleanup. */
		n2piupc_p->n2piupc_ksinfo_p[i] = ksinfo_p;

		/* Create counter kstats */
		ksinfo_p->cntr_ksp = n2piupc_create_cntr_kstat(grp_p->grp_name,
		    ddi_get_instance(n2piupc_p->n2piupc_dip),
		    n2piupc_kstat_update, ksinfo_p, grp_p->num_counters);
		if (ksinfo_p->cntr_ksp == NULL)
			goto err;
	}

	/*
	 * Special treatment for bit err registers: enable them so they start
	 * counting now.
	 */
	if (n2piupc_write(n2piupc_p, leaf_grps[BIT_ERR_GRP]->regsel_p->regoff,
	    BTERR_CTR_ENABLE) != SUCCESS) {
		goto err;
	}

	N2PIUPC_DBG2("n2piupc: kstat_attach: success exit\n");
	return (DDI_SUCCESS);
err:
	n2piupc_kstat_detach(n2piupc_p);
	N2PIUPC_DBG2("n2piupc: kstat_attach: failure exit\n");
	return (DDI_FAILURE);
}

/*
 * Create the name kstats for each group.
 */
static int
n2piupc_create_name_kstat(n2piu_grp_t *grp_p)
{
	int i;

	for (i = 0; i < grp_p->num_counters; i++) {
		grp_p->name_kstats_pp[i] = n2piupc_create_picN_kstat(
		    grp_p->grp_name, i,
		    grp_p->regsel_p->fields_p[i].event_offset,
		    grp_p->regsel_p->fields_p[i].num_events,
		    grp_p->regsel_p->fields_p[i].events_p);

		if (grp_p->name_kstats_pp[i] == NULL)
			return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Create the picN kstat. Returns a pointer to the
 * kstat which the driver must store to allow it
 * to be deleted when necessary.
 */
static kstat_t *
n2piupc_create_picN_kstat(char *mod_name, int pic, uint64_t ev_offset,
    int num_ev, n2piu_event_t *ev_array)
{
	int event;
	char pic_name[PIC_STR_LEN];
	kstat_t	*picN_ksp = NULL;
	struct kstat_named *pic_named_data;


	(void) snprintf(pic_name, PIC_STR_LEN, "pic%1d", pic);

	if ((picN_ksp = kstat_create(mod_name, 0, pic_name,
	    "bus", KSTAT_TYPE_NAMED, num_ev, 0)) == NULL) {
		cmn_err(CE_WARN, "%s %s : kstat create failed",
		    mod_name, pic_name);
		return (NULL);
	}

	/* NOTE: Number of events is assumed to always be non-zero. */

	pic_named_data = (struct kstat_named *)picN_ksp->ks_data;

	/*
	 * Fill up data section of the kstat
	 * Write event names and their associated pcr masks.
	 * num_ev - 1 is because CLEAR_PIC is added separately.
	 */
	for (event = 0; event < num_ev - 1; event++) {
		pic_named_data[event].value.ui64 =
		    ev_array[event].value << ev_offset;

		kstat_named_init(&pic_named_data[event],
		    ev_array[event].name, KSTAT_DATA_UINT64);
	}

	/*
	 * add the clear_pic entry
	 */
	pic_named_data[event].value.ui64 =
	    (uint64_t)~(ev_array[event].value << ev_offset);

	kstat_named_init(&pic_named_data[event], ev_array[event].name,
	    KSTAT_DATA_UINT64);

	kstat_install(picN_ksp);

	return (picN_ksp);
}

/*
 * Create the "counters" kstat.
 */
static kstat_t *
n2piupc_create_cntr_kstat(char *name, int dev_inst,
    int (*update)(kstat_t *, int), n2piu_ksinfo_t *ksinfop, int num_pics)
{
	int i;
	char pic_str[PIC_STR_LEN];
	struct kstat *counters_ksp;
	struct kstat_named *counters_named_data;

	N2PIUPC_DBG2("n2piupc_create_cntr_kstat: name: %s instance: %d\n",
	    name, dev_inst);

	/*
	 * Size of kstat is num_pics + 1. extra one for pcr.
	 */

	if ((counters_ksp = kstat_create(name, dev_inst, "counters", "bus",
	    KSTAT_TYPE_NAMED, num_pics + 1, KSTAT_FLAG_WRITABLE)) == NULL) {
		cmn_err(CE_WARN, "%s%d: kstat_create for %s counters failed",
		    NAMEINST(ksinfop->n2piupc_p->n2piupc_dip), name);
		return (NULL);
	}

	counters_named_data = (struct kstat_named *)(counters_ksp->ks_data);
	kstat_named_init(&counters_named_data[0], "pcr", KSTAT_DATA_UINT64);

	for (i = 0; i < num_pics; i++) {
		(void) snprintf(pic_str, PIC_STR_LEN, "pic%1d", i);

		kstat_named_init(&counters_named_data[i+1], pic_str,
		    KSTAT_DATA_UINT64);
	}

	/*
	 * Store the reg type and other info. in the kstat's private field
	 * so that they are available to the update function.
	 */
	counters_ksp->ks_private = (void *)ksinfop;
	counters_ksp->ks_update = update;

	kstat_install(counters_ksp);

	return (counters_ksp);
}

/* Higher-level register write, hides SW abstractions. */
static int
n2piupc_write(n2piupc_t *n2piupc_p, int regid, uint64_t data)
{
	int rval = SUCCESS;

	switch (regid) {
	case SW_N2PIU_BITERR_SEL:
	case SW_N2PIU_BITERR_CLR:
		rval = n2piupc_biterr_write(n2piupc_p, regid, data);
		break;

	default:
		if (n2piupc_set_perfreg(n2piupc_p->n2piupc_handle,
		    regid, data) != H_EOK)
			rval = EIO;
		break;
	}

	N2PIUPC_DBG1("n2piupc_write: status:%d\n", rval);
	return (rval);
}


/* Higher-level register read, hides SW abstractions. */
static int
n2piupc_read(n2piupc_t *n2piupc_p, int regid, uint64_t *data)
{
	int rval = SUCCESS;

	N2PIUPC_DBG2("n2piupc_read enter: regid:%d\n", regid);

	/* This "register" is a layered SW-implemented reg. */
	switch (regid) {
	case SW_N2PIU_BITERR_CNT1_DATA:
	case SW_N2PIU_BITERR_CNT2_DATA:
	case SW_N2PIU_BITERR_SEL:
		rval = n2piupc_biterr_read(n2piupc_p, regid, data);
		break;

	default:
		if (n2piupc_get_perfreg(n2piupc_p->n2piupc_handle,
		    regid, data) != H_EOK)
			rval = EIO;
		break;
	}

	N2PIUPC_DBG1("n2piupc_read exit: data:0x%lx, status:%d\n", *data,
	    rval);

	return (rval);
}


/*
 * Program a performance counter.
 *
 * reggroup is which type of counter.
 * counter is the counter number.
 * event is the event to program for that counter.
 */
static int
n2piupc_perfcnt_program(n2piupc_t *n2piupc_p, n2piu_grp_t *grp_p,
    uint64_t new_events)
{
	uint64_t old_events;
	int rval = SUCCESS;
	uint64_t event_mask;
	int counter;

	N2PIUPC_DBG1(
	    "n2piupc_perfcnt_program enter: new_events:0x%" PRIx64 "\n",
	    new_events);

	if ((rval = n2piupc_read(n2piupc_p, grp_p->regsel_p->regoff,
	    &old_events)) != SUCCESS) {
		N2PIUPC_DBG1(
		    "Read of old event data failed, select reg offset:%ld\n",
		    grp_p->regsel_p->regoff);
		goto done_pgm;
	}

	N2PIUPC_DBG1("  old_events:0x%" PRIx64 "\n", old_events);

	for (counter = 0; counter < grp_p->num_counters; counter++) {

		if (grp_p->counters_p[counter].zero_regoff == NO_REGISTER)
			continue;

		event_mask = grp_p->regsel_p->fields_p[counter].event_mask <<
		    grp_p->regsel_p->fields_p[counter].event_offset;

		N2PIUPC_DBG1(
		    "grp:%s, counter:%d, zero_regoff:0x%lx, "
		    "event_mask:0x%" PRIx64 ", old&mask:0x%lx, "
		    "new&mask:0x%lx\n",
		    grp_p->grp_name, counter,
		    grp_p->counters_p[counter].zero_regoff,
		    event_mask, old_events & event_mask,
		    new_events & event_mask);

		if ((old_events & event_mask) ==
		    (new_events & event_mask))
			continue;

		N2PIUPC_DBG1("Zeroing counter %d\n", counter);
		if ((rval = n2piupc_write(n2piupc_p,
		    grp_p->counters_p[counter].zero_regoff,
		    grp_p->counters_p[counter].zero_value)) != SUCCESS)
			goto done_pgm;
	}

	if (old_events != new_events) {
		N2PIUPC_DBG1("old != new, setting event reg %ld to 0x%lx\n",
		    grp_p->regsel_p->regoff, new_events);
		if ((rval = n2piupc_write(n2piupc_p, grp_p->regsel_p->regoff,
		    new_events)) != SUCCESS) {
			N2PIUPC_DBG1(
			    "Write of new event data failed, "
			    "select reg offset: %ld\n",
			    grp_p->regsel_p->regoff);
			goto done_pgm;
		}
	}
done_pgm:
	N2PIUPC_DBG1("n2piupc_perfcnt_program: returning status %d.\n", rval);
	return (rval);
}

/*
 * kstat update function. Handles reads/writes
 * from/to kstat.
 */
static int
n2piupc_kstat_update(kstat_t *ksp, int rw)
{
	struct kstat_named *data_p;
	int counter;
	n2piu_ksinfo_t *ksinfop = ksp->ks_private;
	n2piu_grp_t *grp_p = ksinfop->grp_p;
	n2piupc_t *n2piupc_p = ksinfop->n2piupc_p;

	data_p = (struct kstat_named *)ksp->ks_data;

	if (rw == KSTAT_WRITE) {

		N2PIUPC_DBG2("n2piupc_kstat_update: wr %ld\n",
		    data_p[0].value.ui64);

		/*
		 * Fields without programmable events won't be zeroed as
		 * n2piupc_perfcnt_program is what zeros them.
		 */

		/* This group has programmable events. */
		if (grp_p->regsel_p->regoff != NO_REGISTER) {

			N2PIUPC_DBG2("write: regoff has valid register\n");
			if (n2piupc_perfcnt_program(n2piupc_p, grp_p,
			    data_p[0].value.ui64) != SUCCESS)
				return (EIO);
		}

	} else {	/* Read the event register and all of the counters. */

		/* This group has programmable events. */
		if (grp_p->regsel_p->regoff != NO_REGISTER) {

			N2PIUPC_DBG2("read: regoff has valid register\n");
			if (n2piupc_read(n2piupc_p, grp_p->regsel_p->regoff,
			    &data_p[0].value.ui64) != SUCCESS)
				return (EIO);
		} else
			data_p[0].value.ui64 = 0ull;

		N2PIUPC_DBG2("n2piupc_kstat_update: rd event %ld",
		    data_p[0].value.ui64);

		for (counter = 0; counter < grp_p->num_counters; counter++) {
			if (n2piupc_read(n2piupc_p,
			    grp_p->counters_p[counter].regoff,
			    &data_p[counter + 1].value.ui64) != SUCCESS)
				return (EIO);

			N2PIUPC_DBG2("cntr%d, off:0x%lx, val:0x%ld", counter,
			    grp_p->counters_p[counter].regoff,
			    data_p[counter + 1].value.ui64);
		}
	}
	return (SUCCESS);
}

void
n2piupc_kstat_fini()
{
	n2piu_grp_t **grp_pp;
	n2piu_grp_t *grp_p;
	int j;

	N2PIUPC_DBG2("n2piupc_kstat_fini called\n");

	for (j = 0, grp_pp = leaf_grps; *grp_pp != NULL; j++, grp_pp++) {
		grp_p = *grp_pp;
		if (grp_p->name_kstats_pp != NULL) {
			n2piupc_delete_name_kstats(grp_p->name_kstats_pp,
			    grp_p->num_counters);
			kmem_free(grp_p->name_kstats_pp,
			    grp_p->num_counters * sizeof (kstat_t));
			grp_p->name_kstats_pp = NULL;
		}
	}
}

static void
n2piupc_delete_name_kstats(kstat_t **name_kstats_pp, int num_kstats)
{
	int i;

	if (name_kstats_pp != NULL) {
		for (i = 0; i < num_kstats; i++) {
			if (name_kstats_pp[i] != NULL)
				kstat_delete(name_kstats_pp[i]);
		}
	}
}

void
n2piupc_kstat_detach(n2piupc_t *n2piupc_p)
{
	n2piu_grp_t **grp_pp;
	int i;

	N2PIUPC_DBG2("n2piupc_kstat_detach called\n");

	for (i = 0, grp_pp = leaf_grps; *grp_pp != NULL; i++, grp_pp++) {
		if (n2piupc_p->n2piupc_ksinfo_p[i] != NULL) {
			if (n2piupc_p->n2piupc_ksinfo_p[i]->cntr_ksp != NULL)
				kstat_delete(
				    n2piupc_p->n2piupc_ksinfo_p[i]->cntr_ksp);
			kmem_free(n2piupc_p->n2piupc_ksinfo_p[i],
			    sizeof (n2piu_ksinfo_t));
		}

	}

	n2piupc_biterr_detach(n2piupc_p->n2piupc_biterr_p);
}
