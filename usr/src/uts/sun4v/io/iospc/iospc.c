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

/*
 * IO Performance Counter Driver
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include "iospc.h"

/* Debugging level. */
#ifdef DEBUG
int iospc_debug = 0;
#endif /* DEBUG */

/* State structure anchor. */
void *iospc_state_p;

static int iospc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int iospc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int iospc_create_name_kstat(iospc_grp_t *grp);
static void iospc_delete_name_kstats(kstat_t **name_kstats_pp,
    int num_kstats);
static kstat_t *iospc_create_cntr_kstat(char *name, int dev_inst,
    int (*update)(kstat_t *, int), iospc_ksinfo_t *ksinfop, int num_pics);
static int iospc_kstat_update(kstat_t *ksp, int rw);
static kstat_t *iospc_create_picN_kstat(char *mod_name, int pic,
    uint64_t mask, int num_ev, iospc_event_t *ev_array);

iospc_grp_t **iospc_leaf_grps = NULL;
int iospc_kstat_inited = 0;
kmutex_t iospc_mutex;

static struct dev_ops iospc_ops = {
	DEVO_REV,
	0,
	nulldev,
	nulldev,
	nulldev,
	iospc_attach,
	iospc_detach,
	nodev,
	NULL,
	NULL,
	nodev
};

extern struct mod_ops mod_driverops;

static struct modldrv md = {
	&mod_driverops,
	"IO Perf Counter Driver",
	&iospc_ops,
};

static struct modlinkage ml = {
	MODREV_1,
	(void *)&md,
	NULL
};

/*
 * One-time module-wide initialization.
 */
int
_init(void)
{
	int rval;

	/* Initialize per-leaf soft state pointer. */
	if ((rval = ddi_soft_state_init(&iospc_state_p,
	    sizeof (iospc_t), 1)) != DDI_SUCCESS)
		return (rval);

	/* If all checks out, install the module. */
	if ((rval = mod_install(&ml)) != DDI_SUCCESS) {
		ddi_soft_state_fini(&iospc_state_p);
		return (rval);
	}
	mutex_init(&iospc_mutex, NULL, MUTEX_DRIVER, NULL);
	return (DDI_SUCCESS);
}

/*
 * One-time module-wide cleanup, after last detach is done.
 */
int
_fini(void)
{
	int rval;

	/*
	 * Remove the module first as this operation is the only thing here
	 * which can fail.
	 */
	rval = mod_remove(&ml);
	if (rval != DDI_SUCCESS)
		return (rval);

	if (iospc_leaf_grps != NULL) {
		iospc_kstat_fini();
		mutex_enter(&iospc_mutex);
		iospc_kstat_inited = 0;
		(void) rfios_unbind_group();
		iospc_leaf_grps = NULL;
		mutex_exit(&iospc_mutex);
	}

	mutex_destroy(&iospc_mutex);

	/* Free px soft state */
	ddi_soft_state_fini(&iospc_state_p);

	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ml, modinfop));
}

/*
 * Per-instance initialization.  Suspend/resume not supported.
 */
static int
iospc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	iospc_t *iospc_p;
	int instance = ddi_get_instance(dip);
	char *ptr;

	IOSPC_DBG2("iospc: iospc_attach: enter\n");
	switch (cmd) {
	case DDI_RESUME:
	case DDI_ATTACH:
		/* Initialize one-time kstat structures. */
		mutex_enter(&iospc_mutex);
		if (!iospc_kstat_inited) {
			if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
			    0, "compatible", &ptr)) != DDI_PROP_SUCCESS)
				goto bad_property;

			if ((strcmp(ptr, "SUNW,ktios-pr") == 0) ||
			    (strcmp(ptr, "SUNW,rfios-pr") == 0)) {
				iospc_leaf_grps = rfios_bind_group();
			} else {
				ddi_prop_free(ptr);
				goto bad_property;
			}

			ddi_prop_free(ptr);

			if (iospc_kstat_init() != DDI_SUCCESS)
				goto bad_kstat_init;

			iospc_kstat_inited++;
		}
		mutex_exit(&iospc_mutex);

		if (ddi_soft_state_zalloc(iospc_state_p, instance) !=
		    DDI_SUCCESS) {
			goto bad_softstate;
		}

		iospc_p = (iospc_t *)ddi_get_soft_state(iospc_state_p,
		    instance);

		iospc_p->iospc_dip = dip;

		/* Set up kstats. */

		if (iospc_kstat_attach(iospc_p) != DDI_SUCCESS)
			goto bad_kstat_attach;

		IOSPC_DBG2("iospc: iospc_attach: exit SUCCESS\n");

		return (DDI_SUCCESS);

bad_kstat_attach:
		(void) ddi_soft_state_free(iospc_state_p, instance);
bad_softstate:
		iospc_kstat_fini();
bad_kstat_init:
bad_property:
		mutex_enter(&iospc_mutex);
		IOSPC_DBG2("iospc: iospc_attach: exit FAILURE\n");
		return (DDI_FAILURE);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * Per-instance cleanup.  Suspend/resume not supported.
 */
static int
iospc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);

	IOSPC_DBG2("iospc: iospc_detach: enter\n");
	iospc_t *iospc_p = (iospc_t *)ddi_get_soft_state(
	    iospc_state_p, instance);

	switch (cmd) {
	case DDI_SUSPEND:
	case DDI_DETACH:
		iospc_kstat_detach(iospc_p);
		(void) ddi_soft_state_free(iospc_state_p, instance);

		IOSPC_DBG2("iospc: iospc_detach: exit - SUCCESS\n");
		return (DDI_SUCCESS);

	default:
		IOSPC_DBG2("iospc: iospc_detach: exit - FAILURE\n");
		return (DDI_FAILURE);
	}
}

#define	PIC_STR_LEN	5	/* Size of a PICx name string. */

/*
 * One-time initialization for this module.
 */
int
iospc_kstat_init()
{
	iospc_grp_t **grp_pp;
	iospc_grp_t *grp_p;

	IOSPC_DBG2("iospc: kstat_init: enter\n");

	/*
	 * Initialize the name kstats for each group, drawing upon the table
	 * for values.
	 */
	for (grp_pp = iospc_leaf_grps; *grp_pp != NULL; grp_pp++) {

		grp_p = *grp_pp;

		IOSPC_DBG2("Setting up group for %s\n", grp_p->grp_name);

		/* Create basic pic event-type pair. */
		grp_p->name_kstats_pp = kmem_zalloc((grp_p->num_counters *
		    sizeof (kstat_t)), KM_SLEEP);
		if (iospc_create_name_kstat(grp_p) != DDI_SUCCESS) {
			iospc_kstat_fini();
			IOSPC_DBG1("iospc: init: failure exit\n");
			return (DDI_FAILURE);
		}
	}

	IOSPC_DBG2("iospc: kstat_init: success exit\n");

	return (DDI_SUCCESS);
}

/*
 * Per-instance initialization for this module.
 */
int
iospc_kstat_attach(iospc_t *iospc_p)
{
	iospc_grp_t **grp_pp;
	iospc_grp_t *grp_p;
	iospc_ksinfo_t *ksinfo_p;

	int i;

	IOSPC_DBG2("iospc: kstat_attach %d: enter\n",
	    ddi_get_instance(iospc_p->iospc_dip));

	/* Set up kstats for each group. */
	for (i = 0, grp_pp = iospc_leaf_grps; *grp_pp != NULL; i++, grp_pp++) {

		if (i >= IOSPC_MAX_NUM_GRPS)
			goto err;

		grp_p = *grp_pp;

		/*
		 * ksinfo_p keeps all info needed by iospc_kstat_update,
		 * which is fired off asynchronously on demand by the kstat
		 * framework.
		 */
		ksinfo_p = (iospc_ksinfo_t *)kmem_zalloc(
		    sizeof (iospc_ksinfo_t), KM_SLEEP);

		ksinfo_p->iospc_p = iospc_p;
		ksinfo_p->grp_p  = grp_p;

		/* Also save in state structure, for later cleanup. */
		iospc_p->iospc_ksinfo_p[i] = ksinfo_p;

		/* Create counter kstats */
		ksinfo_p->cntr_ksp = iospc_create_cntr_kstat(grp_p->grp_name,
		    ddi_get_instance(iospc_p->iospc_dip),
		    iospc_kstat_update, ksinfo_p, grp_p->num_counters);

		if (ksinfo_p->cntr_ksp == NULL)
			goto err;

		if (grp_p->access_init(iospc_p, ksinfo_p) != SUCCESS)
			goto err;
	}

	IOSPC_DBG2("iospc: kstat_attach: success exit\n");
	return (DDI_SUCCESS);
err:
	iospc_kstat_detach(iospc_p);
	IOSPC_DBG2("iospc: kstat_attach: failure exit\n");
	return (DDI_FAILURE);
}

/*
 * Create the name kstats for each group.
 */
static int
iospc_create_name_kstat(iospc_grp_t *grp_p)
{
	int i;

	for (i = 0; i < grp_p->num_counters; i++) {
		grp_p->name_kstats_pp[i] = iospc_create_picN_kstat(
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
iospc_create_picN_kstat(char *mod_name, int pic, uint64_t ev_offset,
    int num_ev, iospc_event_t *ev_array)
{
	int event;
	char pic_name[PIC_STR_LEN];
	kstat_t	*picN_ksp = NULL;
	struct kstat_named *pic_named_data;

	(void) snprintf(pic_name, PIC_STR_LEN, "pic%1d", pic);

	if ((picN_ksp = kstat_create(mod_name, 0, pic_name,
	    "bus", KSTAT_TYPE_NAMED, num_ev, 0)) == NULL) {
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
iospc_create_cntr_kstat(char *name, int dev_inst,
    int (*update)(kstat_t *, int), iospc_ksinfo_t *ksinfop, int num_pics)
{
	int i;
	char pic_str[PIC_STR_LEN];
	struct kstat *counters_ksp;
	struct kstat_named *counters_named_data;

	IOSPC_DBG2("iospc_create_cntr_kstat: name: %s instance: %d\n",
	    name, dev_inst);

	/*
	 * Size of kstat is num_pics + 1. extra one for pcr.
	 */

	if ((counters_ksp = kstat_create(name, dev_inst, "counters", "bus",
	    KSTAT_TYPE_NAMED, num_pics + 1, KSTAT_FLAG_WRITABLE)) == NULL) {
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

/*
 * Program a performance counter.
 *
 * reggroup is which type of counter.
 * counter is the counter number.
 * event is the event to program for that counter.
 */
static int
iospc_perfcnt_program(iospc_t *iospc_p, iospc_grp_t *grp_p,
    iospc_ksinfo_t *ksinfo_p, uint64_t new_events)
{
	uint64_t old_events;
	int rval = SUCCESS;
	uint64_t event_mask;
	int counter;

	IOSPC_DBG1(
	    "iospc_perfcnt_program enter: new_events:0x%" PRIx64 "\n",
	    new_events);

	if ((rval = grp_p->access(iospc_p, ksinfo_p->arg, IOSPC_REG_READ,
	    grp_p->regsel_p->regoff, &old_events)) != SUCCESS)
		goto done_pgm;

	IOSPC_DBG1("  old_events:0x%" PRIx64 "\n", old_events);

	for (counter = 0; counter < grp_p->num_counters; counter++) {

		if (grp_p->counters_p[counter].zero_regoff == NO_REGISTER)
			continue;

		event_mask = grp_p->regsel_p->fields_p[counter].event_mask <<
		    grp_p->regsel_p->fields_p[counter].event_offset;

		IOSPC_DBG1(
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

		IOSPC_DBG1("Zeroing counter %d\n", counter);

		if ((rval = grp_p->access(iospc_p, ksinfo_p->arg,
		    IOSPC_REG_WRITE, grp_p->counters_p[counter].zero_regoff,
		    &grp_p->counters_p[counter].zero_value)) != SUCCESS)
			goto done_pgm;
	}

	if (old_events != new_events) {

		IOSPC_DBG1("old != new, setting event reg %ld to 0x%lx\n",
		    grp_p->regsel_p->regoff, new_events);

		if ((rval = grp_p->access(iospc_p, ksinfo_p->arg,
		    IOSPC_REG_WRITE, grp_p->regsel_p->regoff, &new_events))
		    != SUCCESS) {
			IOSPC_DBG1(
			    "Write of new event data failed, "
			    "select reg offset: %ld\n",
			    grp_p->regsel_p->regoff);
			goto done_pgm;
		}
	}
done_pgm:
	IOSPC_DBG1("iospc_perfcnt_program: returning status %d.\n", rval);
	return (rval);
}

/*
 * kstat update function. Handles reads/writes
 * from/to kstat.
 */
static int
iospc_kstat_update(kstat_t *ksp, int rw)
{
	struct kstat_named *data_p;
	int counter;
	iospc_ksinfo_t *ksinfop = ksp->ks_private;
	iospc_grp_t *grp_p = ksinfop->grp_p;
	iospc_t *iospc_p = ksinfop->iospc_p;

	data_p = (struct kstat_named *)ksp->ks_data;

	if (rw == KSTAT_WRITE) {

		IOSPC_DBG2("iospc_kstat_update: wr %ld\n",
		    data_p[0].value.ui64);

		/*
		 * Fields without programmable events won't be zeroed as
		 * iospc_perfcnt_program is what zeros them.
		 */

		/* This group has programmable events. */
		if (grp_p->regsel_p->regoff != NO_REGISTER) {

			IOSPC_DBG2("write: regoff has valid register\n");
			if (iospc_perfcnt_program(iospc_p, grp_p, ksinfop,
			    data_p[0].value.ui64) != SUCCESS)
				return (EIO);
		}

	} else {	/* Read the event register and all of the counters. */

		/* This group has programmable events. */
		if (grp_p->regsel_p->regoff != NO_REGISTER) {

			IOSPC_DBG2("read: regoff has valid register\n");

			if (grp_p->access(iospc_p, ksinfop->arg, IOSPC_REG_READ,
			    grp_p->regsel_p->regoff, &data_p[0].value.ui64)
			    != SUCCESS)
				return (EIO);
		} else
			data_p[0].value.ui64 = 0ull;

		IOSPC_DBG2("iospc_kstat_update: rd event %lx\n",
		    data_p[0].value.ui64);

		for (counter = 0; counter < grp_p->num_counters; counter++) {

			if (grp_p->access(iospc_p, ksinfop->arg, IOSPC_REG_READ,
			    grp_p->counters_p[counter].regoff,
			    &data_p[counter + 1].value.ui64) != SUCCESS)
				return (EIO);

			IOSPC_DBG2("cntr%d, off:0x%lx, val:0x%lx\n", counter,
			    grp_p->counters_p[counter].regoff,
			    data_p[counter + 1].value.ui64);
		}
	}
	return (SUCCESS);
}

void
iospc_kstat_fini()
{
	iospc_grp_t **grp_pp;
	iospc_grp_t *grp_p;
	int j;

	IOSPC_DBG2("iospc_kstat_fini called\n");

	for (j = 0, grp_pp = iospc_leaf_grps; *grp_pp != NULL; j++, grp_pp++) {
		grp_p = *grp_pp;
		if (grp_p->name_kstats_pp != NULL) {
			iospc_delete_name_kstats(grp_p->name_kstats_pp,
			    grp_p->num_counters);
			kmem_free(grp_p->name_kstats_pp,
			    grp_p->num_counters * sizeof (kstat_t));
			grp_p->name_kstats_pp = NULL;
		}
	}
}

static void
iospc_delete_name_kstats(kstat_t **name_kstats_pp, int num_kstats)
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
iospc_kstat_detach(iospc_t *iospc_p)
{
	iospc_grp_t **grp_pp;
	iospc_grp_t *grp_p;
	int i;

	IOSPC_DBG2("iospc_kstat_detach called\n");

	for (i = 0, grp_pp = iospc_leaf_grps; *grp_pp != NULL; i++, grp_pp++) {

		if (i >= IOSPC_MAX_NUM_GRPS)
			return;

		grp_p = *grp_pp;
		if (iospc_p->iospc_ksinfo_p[i] != NULL) {

			grp_p->access_fini(iospc_p, iospc_p->iospc_ksinfo_p[i]);

			if (iospc_p->iospc_ksinfo_p[i]->cntr_ksp != NULL)
				kstat_delete(
				    iospc_p->iospc_ksinfo_p[i]->cntr_ksp);
			kmem_free(iospc_p->iospc_ksinfo_p[i],
			    sizeof (iospc_ksinfo_t));
		}

	}
}
