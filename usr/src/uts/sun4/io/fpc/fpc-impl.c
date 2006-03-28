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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/disp.h>
#include <fpc.h>
#include <fpc-impl.h>

#define	BOUNDS_CHECK_FAILS(arg, max)	((arg < 0) && (arg >= max))

static int this_node = 0;
node_data_t node_data[NUM_LEAVES];

int fpc_debug = 0;

static int counters_per_type[MAX_REG_TYPES] = {
	NUM_JBC_COUNTERS,
	NUM_IMU_COUNTERS,
	NUM_MMU_COUNTERS,
	NUM_TLU_COUNTERS,
	NUM_LPU_COUNTERS
};

static int first_reg_of_type[MAX_REG_TYPES];

static uint64_t event_field_mask[NUM_TOTAL_COUNTERS] = {
	JBC_PIC0_EVT_MASK,		/* JBC counter 0 */
	JBC_PIC1_EVT_MASK,		/* JBC counter 1 */
	IMU_PIC0_EVT_MASK,		/* IMU counter 0 */
	IMU_PIC1_EVT_MASK,		/* IMU counter 1 */
	MMU_PIC0_EVT_MASK,		/* MMU counter 0 */
	MMU_PIC1_EVT_MASK,		/* MMU counter 1 */
	TLU_PIC0_EVT_MASK,		/* TLU counter 0 */
	TLU_PIC1_EVT_MASK,		/* TLU counter 1 */
	TLU_PIC2_EVT_MASK,		/* TLU counter 2 */
	LPU_PIC0_EVT_MASK,		/* LPU counter 1 */
	LPU_PIC1_EVT_MASK		/* LPU counter 2 */
};

/* Offsets of the fields shown in event_field_masks. */
static int event_field_offset[NUM_TOTAL_COUNTERS] = {
	PIC0_EVT_SEL_SHIFT,		/* JBC counter 0 */
	PIC1_EVT_SEL_SHIFT,		/* JBC counter 1 */
	PIC0_EVT_SEL_SHIFT,		/* IMU counter 0 */
	PIC1_EVT_SEL_SHIFT,		/* IMU counter 1 */
	PIC0_EVT_SEL_SHIFT,		/* MMU counter 0 */
	PIC1_EVT_SEL_SHIFT,		/* MMU counter 1 */
	PIC0_EVT_SEL_SHIFT,		/* TLU counter 0 */
	PIC1_EVT_SEL_SHIFT,		/* TLU counter 1 */
	PIC2_EVT_SEL_SHIFT,		/* TLU counter 2 */
	PIC0_EVT_SEL_SHIFT,		/* LPU counter 1 */
	PIC2_EVT_SEL_SHIFT		/* LPU counter 2 */
};

/* For determining platform suitability at _init time. */
int
fpc_init_platform_check()
{
	return (fpc_platform_check());
}

/*ARGSUSED*/
void
fpc_common_node_setup(dev_info_t *dip, int *index_p)
{
	char pathname[MAXPATHLEN];

	(void) ddi_pathname(dip, pathname);
	node_data[this_node].name =
	    kmem_zalloc(strlen(pathname)+1, KM_SLEEP);
	(void) strcpy(node_data[this_node].name, pathname);
	mutex_init(&node_data[this_node].mutex, NULL, MUTEX_DRIVER, NULL);
	*index_p = this_node++;
}

int
fpc_perfcnt_module_init(dev_info_t *fpc_dip, int *avail)
{
	int i;
	dev_info_t *dip;

	*avail = 0;

	for (i = 1; i < MAX_REG_TYPES; i++) {
		first_reg_of_type[i] =
		    first_reg_of_type[i-1] + counters_per_type[i-1];
	}

	/*
	 * Look thru first level of device tree only.
	 * Assume there can be no more than NUM_LEAVES nodes in the system.
	 */
	dip = ddi_root_node();
	for (dip = ddi_get_child(dip);
	    ((dip != NULL) && (this_node < NUM_LEAVES));
	    dip = ddi_get_next_sibling(dip)) {
		if (fpc_platform_node_init(dip, avail) != SUCCESS)
			return (DDI_FAILURE);
	}

	return ((*avail) ? fpc_platform_module_init(fpc_dip) : DDI_FAILURE);
}

int
fpc_perfcnt_module_fini(dev_info_t *dip)
{
	int i;

	for (i = 0; i < NUM_LEAVES; i++) {
		fpc_platform_node_fini(node_data[i].plat_data_p);
		if (node_data[i].name != NULL) {
			kmem_free(node_data[i].name,
			    strlen(node_data[i].name) + 1);
			mutex_destroy(&node_data[i].mutex);
		}
	}

	fpc_platform_module_fini(dip);
	return (DDI_SUCCESS);
}

char
*fpc_get_dev_name_by_number(int index)
{
	return (node_data[index].name);
}

void *
fpc_get_platform_data_by_number(int index)
{
	return (node_data[index].plat_data_p);
}


int
fpc_set_platform_data_by_number(int index, void *data_p)
{
	node_data[index].plat_data_p = data_p;
	return (SUCCESS);
}


static int
fpc_get_mutex_by_number(int index, kmutex_t **mutex_pp)
{
	*mutex_pp = &node_data[index].mutex;
	return (SUCCESS);
}


static int
fpc_get_counter_reg_index(fire_perfcnt_t regtype, int counter)
{
	FPC_DBG1(
	    "fpc_get_counter_reg_index: regtype:%d, counter:%d, bounds:%d\n",
	    regtype, counter, counters_per_type[regtype]);
	if (BOUNDS_CHECK_FAILS(counter, counters_per_type[regtype]))
		return (-1);
	FPC_DBG1("returning: %d\n", first_reg_of_type[regtype] + counter);
	return (first_reg_of_type[regtype] + counter);
}


/*
 * Program a performance counter.
 *
 * reggroup is which type of counter.
 * counter is the counter number.
 * event is the event to program for that counter.
 */
int
fpc_perfcnt_program(int devnum, fire_perfcnt_t reggroup,
    uint64_t new_events)
{
	int counter_index;
	fire_perfreg_handle_t firehdl;
	kmutex_t *mutex_p;
	uint64_t old_events;
	int rval = SUCCESS;
	uint64_t zero = 0ull;
	int num_counters, counter;

	FPC_DBG1("fpc_perfcnt_program enter:\n");
	FPC_DBG1("  devnum:%d, reggroup:%d, new_events:0x%" PRIx64 "\n",
	    devnum, reggroup, new_events);

	if ((firehdl = fpc_get_perfreg_handle(devnum)) ==
	    (fire_perfreg_handle_t)-1)
		return (EIO);

	num_counters = counters_per_type[reggroup];

	if (fpc_get_mutex_by_number(devnum, &mutex_p) != DDI_SUCCESS) {
		(void) fpc_free_counter_handle(firehdl);
		return (EIO);
	}

	mutex_enter(mutex_p);

	if ((rval = fpc_event_io(firehdl, reggroup, &old_events, IS_READ)) !=
	    SUCCESS) {
		FPC_DBG1("Read of old event data failed, group:%d\n", reggroup);
		goto done_pgm;
	}

	for (counter = 0; counter < num_counters; counter++) {

		counter_index = fpc_get_counter_reg_index(reggroup, counter);

		if ((old_events & event_field_mask[counter_index]) ==
		    (new_events & event_field_mask[counter_index]))
			continue;

		FPC_DBG1("Zeroing counter %d\n", counter_index);
		if ((rval = fpc_counter_io(firehdl, reggroup, counter_index,
		    &zero, IS_WRITE)) != SUCCESS)
			goto done_pgm;
	}

	if (old_events != new_events) {
		if ((rval =
		    fpc_event_io(firehdl, reggroup, &new_events, IS_WRITE)) !=
		    SUCCESS) {
			FPC_DBG1("Write of new event data failed, group:%d\n",
			    reggroup);
			goto done_pgm;
		}
	}
done_pgm:
	mutex_exit(mutex_p);
	(void) fpc_free_counter_handle(firehdl);
	return (rval);
}


/*
 * Read a performance counter.
 *
 * reggroup is which type of counter.
 * event_p returns the event programmed for that counter.
 * values returns the counter values.
 */
int
fpc_perfcnt_read(int devnum, fire_perfcnt_t reggroup,
    uint64_t *event_p, uint64_t values[NUM_MAX_COUNTERS])
{
	fire_perfreg_handle_t firehdl;
	int counter_index;
	kmutex_t *mutex_p;
	int rval;
	int num_counters, counter;

	FPC_DBG1("fpc_perfcnt_read: devnum:%d\n", devnum);
	num_counters = counters_per_type[reggroup];

	if ((firehdl = fpc_get_perfreg_handle(devnum)) ==
	    (fire_perfreg_handle_t)-1)
		return (EIO);

	if (fpc_get_mutex_by_number(devnum, &mutex_p) != DDI_SUCCESS)
		return (EIO);

	mutex_enter(mutex_p);

	if ((rval = fpc_event_io(firehdl, reggroup, event_p, IS_READ)) !=
	    SUCCESS)
		goto done_read;

	for (counter = 0; counter < num_counters; counter++) {
		counter_index = fpc_get_counter_reg_index(reggroup, counter);

		if ((rval = fpc_counter_io(firehdl, reggroup, counter_index,
		    &values[counter], IS_READ)) != SUCCESS)
			goto done_read;

		FPC_DBG1("Read_counter %d / %d, status:%d, value returned:0x%"
		    PRIx64 "\n", reggroup, counter, rval, values[counter]);
	}

done_read:
	mutex_exit(mutex_p);
	(void) fpc_free_counter_handle(firehdl);
	return (rval);
}
