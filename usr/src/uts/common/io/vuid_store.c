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
 * Copyright (c) 1985-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Vuid_store.c - Implement the vuid_store.h event storage interface.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/disp.h>
#include <sys/vuid_event.h>
#include <sys/vuid_state.h>
#include <sys/vuid_store.h>

static void vuid_destroy_seg();
static Vuid_seg * vuid_copy_seg();
static Vuid_seg * vuid_find_seg();
static Vuid_value * vuid_add_value();
static Vuid_value * vuid_find_value();

#ifdef	_KERNEL
#define	vuid_alloc(bytes) \
	kmem_alloc((bytes), servicing_interrupt())
#define	vuid_free(ptr, bytes)	kmem_free((ptr), (bytes))
#else
#define	vuid_alloc(bytes)	malloc((bytes))
#define	vuid_free(ptr, bytes)	free((ptr))
#endif	/* _KERNEL */

void
vuid_set_value(client_state_ptr, event)
	Vuid_state *client_state_ptr;
	register Firm_event *event;
{
	Vuid_seg **state_ptr = (Vuid_seg **)client_state_ptr;
	Vuid_seg *state = *state_ptr;
	register Vuid_seg *seg;
	register Vuid_value *val_node;
	register Vuid_value *pair_val_node;
	register ushort_t offset = vuid_id_offset(event->id);
	register ushort_t pair = event->pair;
	int	int_bit, val_original;

	/* Get (search for) seg from state assoicated with event */
	if ((seg = vuid_find_seg(state, vuid_id_addr(event->id))) ==
	    VUID_SEG_NULL) {
		/* Allocate and initialize new seg for event */
		seg = (Vuid_seg *) vuid_alloc(sizeof (*seg));
		bzero((caddr_t)seg, sizeof (*seg));
		seg->addr = vuid_id_addr(event->id);
		/* Add the seg to state */
		*state_ptr = seg;
		seg->next = state;
	}
	int_bit = vuid_get_int_bit(seg, offset);
	/* See if no value node and event value is not boolean */
	if ((!int_bit) && vuid_int_value(event->value)) {
		(void) vuid_add_value(seg, offset);
		int_bit = 1;
	}
	/* If boolean event then set boolean bit */
	if (!int_bit) {
		if (event->value)
			vuid_set_boolean_bit(seg, offset);
		else
			vuid_clear_boolean_bit(seg, offset);
	} else {
		/* Get (search for) value node (should be there) */
		val_node = vuid_find_value(seg, offset);
		val_original = val_node->value;
		val_node->value = event->value;
		switch (event->pair_type) {

		case FE_PAIR_DELTA:
			/* See if value node for pair */
			if (!vuid_get_int_bit(seg, pair))
				(void) vuid_add_value(seg, pair);
			/* Get (search for) value node (should be there) */
			pair_val_node = vuid_find_value(seg, pair);
			/* Set pair value to difference */
			pair_val_node->value = event->value - val_original;
			break;

		case FE_PAIR_ABSOLUTE:
			/* See if value node for pair */
			if (!vuid_get_int_bit(seg, pair))
				(void) vuid_add_value(seg, pair);
			/* Get (search for) value node (should be there) */
			pair_val_node = vuid_find_value(seg, pair);
			/* Add event value to pair value */
			pair_val_node->value += event->value;
			break;

		default:
			{}
		}
	}
	/* Recursively call vuid_set_value if there is an associated pair */
	if (event->pair_type == FE_PAIR_SET) {
		Firm_event pair_event;

		pair_event = *event;
		pair_event.id = vuid_id_addr(event->id) | pair;
		pair_event.pair_type = FE_PAIR_NONE;
		pair_event.pair = 0;
		vuid_set_value(client_state_ptr, &pair_event);
	}
}

int
vuid_get_value(client_state, id)
	Vuid_state client_state;
	ushort_t id;
{
	Vuid_seg *state = vuid_cstate_to_state(client_state);
	register Vuid_seg *seg;
	Vuid_value *val_node;
	register ushort_t offset = vuid_id_offset(id);

	/* Get (search for) seg from state assoicated with id */
	if ((seg = vuid_find_seg(state, vuid_id_addr(id))) == VUID_SEG_NULL)
		return (0);
	/* If boolean event (i.e., no ints bit on) then return boolean value */
	if (!vuid_get_int_bit(seg, offset))
		return (vuid_get_boolean_bit(seg, offset) != 0);
	else {
		/* Get (search for) value node and return value */
		val_node = vuid_find_value(seg, offset);
		return (val_node->value);
	}
}

void
vuid_destroy_state(client_state)
	Vuid_state client_state;
{
	Vuid_seg *state = vuid_cstate_to_state(client_state);
	register Vuid_seg *seg;
	Vuid_seg *seg_next;

	for (seg = state; seg; seg = seg_next) {
		seg_next = seg->next;
		vuid_destroy_seg(seg);
	}
}

static void
vuid_destroy_seg(seg)
	Vuid_seg *seg;
{
	register Vuid_value *val_node;
	Vuid_value *val_node_next;

	for (val_node = seg->list; val_node; val_node = val_node_next) {
		val_node_next = val_node->next;
		vuid_free((caddr_t)val_node, sizeof (Vuid_value));
	}
	vuid_free((caddr_t)seg, sizeof (Vuid_seg));
}

Vuid_state
vuid_copy_state(client_state)
	Vuid_state client_state;
{
	Vuid_seg *state = vuid_cstate_to_state(client_state);
	register Vuid_seg *seg;
	Vuid_seg *new_first_seg = VUID_SEG_NULL;
	register Vuid_seg *new_previous_seg = VUID_SEG_NULL;
	register Vuid_seg *new_seg;

	for (seg = state; seg; seg = seg->next) {
		new_seg = vuid_copy_seg(seg);
		/* Remember first seg as state */
		if (new_first_seg == VUID_SEG_NULL)
			new_first_seg = new_seg;
		/* Link segs together */
		if (new_previous_seg != VUID_SEG_NULL)
			new_previous_seg->next = new_seg;
		/* Remember seg for linking later */
		new_previous_seg = new_seg;
	}
	return ((Vuid_state) new_first_seg);
}

static Vuid_seg *
vuid_copy_seg(seg)
	Vuid_seg *seg;
{
	register Vuid_value *val_node;
	Vuid_seg *new_seg;
	register Vuid_value *new_previous_val = VUID_VALUE_NULL;
	register Vuid_value *new_val;

	/* Allocate and initialize new seg for event */
	new_seg = (Vuid_seg *) vuid_alloc(sizeof (*seg));
	*new_seg = *seg;
	/* Terminate new pointer with null */
	new_seg->next = VUID_SEG_NULL;
	new_seg->list = VUID_VALUE_NULL;
	/* Copy list elements */
	for (val_node = seg->list; val_node; val_node = val_node->next) {
		new_val = (Vuid_value *) vuid_alloc(sizeof (*new_val));
		*new_val = *val_node;
		new_val->next = VUID_VALUE_NULL;
		/* Remember first value as head of list */
		if (new_seg->list == VUID_VALUE_NULL)
			new_seg->list = new_val;
		/* Link vals together */
		if (new_previous_val != VUID_VALUE_NULL)
			new_previous_val->next = new_val;
		/* Remember val for linking later */
		new_previous_val = new_val;
	}
	return (new_seg);
}

static Vuid_seg *
vuid_find_seg(state, addr)
	Vuid_seg *state;
	ushort_t addr;
{
	register Vuid_seg *seg;

	for (seg = state; seg; seg = seg->next) {
		if (seg->addr == addr)
			return (seg);
	}
	return (VUID_SEG_NULL);
}

static Vuid_value *
vuid_find_value(seg, offset)
	Vuid_seg *seg;
	ushort_t offset;
{
	register Vuid_value *val_node;

	for (val_node = seg->list; val_node; val_node = val_node->next) {
		if (vuid_id_offset(val_node->offset) == offset)
			return (val_node);
	}
	return (VUID_VALUE_NULL);
}

static Vuid_value *
vuid_add_value(seg, offset)
	Vuid_seg *seg;
	ushort_t offset;
{
	Vuid_value *list_tmp;
	Vuid_value *val_node;

	/* Allocate and initialize new value node for event */
	val_node = (Vuid_value *) vuid_alloc(sizeof (*val_node));
	bzero((caddr_t)val_node, sizeof (*val_node));
	val_node->offset = offset;
	/* Add the value node to list */
	list_tmp = seg->list;
	seg->list = val_node;
	val_node->next = list_tmp;
	vuid_set_int_bit(seg, offset);
	/* Clear boolean bit for event */
	vuid_clear_boolean_bit(seg, offset);
	return (val_node);
}
