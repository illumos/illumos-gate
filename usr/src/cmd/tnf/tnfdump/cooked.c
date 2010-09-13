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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <tnf/tnf.h>
#include <errno.h>
#include <libintl.h>

#include "state.h"

#define	STREQ(s1, s2, n)	(strncmp(s1, s2, n) == 0)

#define	IS_64BIT(kind)	((1 << kind) &	\
				((1 << TNF_K_UINT64) | (1 << TNF_K_INT64)))

#define	PROBE_TYPE	"tnf_probe_type"

static void print_event			(entry_t *ent);
static void insert_event		(tnf_datum_t, tnf_datum_t);
static void describe_c_brief		(tnf_datum_t);
static void describe_target		(tnf_datum_t);
static void describe_c_struct		(tnf_datum_t);
static void describe_probe_type		(tnf_datum_t);
static void describe_event		(tnf_datum_t, tnf_datum_t, hrtime_t);

static hrtime_t		base_time = 0;

void
print_c_header(void)
{
	(void) printf("%16s %16s %5s %5s %10s %3s %-25s %s\n",
		"----------------", "----------------", "-----", "-----",
		"----------", "---", "-------------------------",
		"------------------------");
	(void) printf("%16s %16s %5s %5s %10s %3s %-25s %s\n",
		"Elapsed (ms)", "Delta (ms)", "PID", "LWPID",
		"   TID    ", "CPU", "Probe Name", "Data / Description . . .");
	(void) printf("%16s %16s %5s %5s %10s %3s %-25s %s\n",
		"----------------", "----------------", "-----", "-----",
		"----------", "---", "-------------------------",
		"------------------------");
}

static void
print_event(entry_t *ent)
{
	tnf_datum_t	evt, sched;
	hrtime_t	normalized_time;

	evt = ent->record;
	sched = tnf_get_tag_arg(evt);
	if (sched == TNF_DATUM_NULL) {
		/*
		 * should never happen because it had a schedule
		 * record earlier
		 */
		fail(0, gettext("event without a schedule record"));
	}
	normalized_time = ent->time - base_time;
	describe_event(evt, sched, normalized_time);
}

void
print_sorted_events(void)
{
	entry_t 	*ent;

	table_sort();
	ent = table_get_entry_indexed(0);
	if (ent) {
		base_time = ent->time;
	}
	table_print(&print_event);
}

void
describe_c_record(tnf_datum_t datum)
{
	char		*name_str;
	tnf_datum_t	schedule_rec;

	switch (tnf_get_kind(datum)) {

	case TNF_K_STRUCT:
		/* print only event records */
		schedule_rec = tnf_get_tag_arg(datum);
		if (schedule_rec != TNF_DATUM_NULL) {
			/* event record */
			insert_event(datum, schedule_rec);
		}
		break;
	case TNF_K_STRING:
	case TNF_K_ARRAY:
		/* Skip arrays at top level */
		break;
	case TNF_K_TYPE:
		name_str = tnf_get_type_name(datum);
		/* REMIND: filter based on property */
		if (STREQ(name_str, PROBE_TYPE, strlen(name_str)))
			describe_probe_type(datum);
		break;
	default:
		fail(0, gettext("illegal record at %x (%d)"),
			tnf_get_raw(datum), tnf_get_kind(datum));
		break;
	}

}

static void
describe_probe_type(tnf_datum_t datum)
{
	unsigned 	n, i;
	char 		*slotname;
	size_t		slot_len;

	n = tnf_get_slot_count(datum);
#if 0
	/* print the OUTPUT PAD */
	(void) printf("%16s %14s %5s %5s %8s %3s %-25s",
			"-", "-", "-", "-", "-", "-", "-");
#endif
	(void) printf("probe\t");
	for (i = 0; i < n; i++) {
		slotname = tnf_get_slot_name(datum, i);
		slot_len = strlen(slotname);

		/* print all fields except ... */
		if ((!STREQ(slotname, TNF_N_TAG, slot_len)) &&
			(!STREQ(slotname, TNF_N_PROPERTIES, slot_len)) &&
			(!STREQ(slotname, TNF_N_SLOT_TYPES, slot_len)) &&
			(!STREQ(slotname, TNF_N_TYPE_SIZE, slot_len)) &&
			(!STREQ(slotname, TNF_N_SLOT_NAMES, slot_len))) {
				(void) printf(" ");
				(void) printf("%s: ", slotname);
				describe_c_brief(tnf_get_slot_indexed(datum,
							i));
		}
	}
	(void) printf("\n");
}

static void
insert_event(tnf_datum_t datum, tnf_datum_t schedule_rec)
{
	tnf_datum_t	temp;
	hrtime_t	evt_time;
	unsigned	time_delta = 0;
	entry_t		element;

	temp = tnf_get_slot_named(schedule_rec, TNF_N_TIME_BASE);
	evt_time = tnf_get_int64(temp);
	temp = tnf_get_slot_named(datum, TNF_N_TIME_DELTA);
	time_delta = (unsigned) tnf_get_int32(temp);
	evt_time = evt_time + time_delta;

	element.time = evt_time;
	element.record = datum;
	table_insert(&element);
}

#define	K_TID	"tnf_kthread_id"
#define	CPUID	"cpuid"

static void
describe_event(tnf_datum_t datum, tnf_datum_t schedule_rec, hrtime_t evt_time)
{
	unsigned 	n, i;
	char 		*slotname, *eventname, *tidtype;
	tnf_datum_t	temp;
	int		lwpid = 0, pid = 0;
	int		start_slots = 0;
	static hrtime_t	last_time = 0;
	unsigned long long	tid = 0;

	temp = tnf_get_slot_named(schedule_rec, TNF_N_TID);
	if (IS_64BIT(tnf_get_kind(temp))) {
		tid = tnf_get_int64(temp);
	} else {
		tid = (unsigned int)tnf_get_int32(temp);
	}
	tidtype = tnf_get_type_name(temp);

	temp = tnf_get_slot_named(schedule_rec, TNF_N_LWPID);
	lwpid = tnf_get_int32(temp);
	temp = tnf_get_slot_named(schedule_rec, TNF_N_PID);
	pid = tnf_get_int32(temp);

	/* XXX should use TNF_N_KERNEL_SCHEDULE, TNF_N_USER_SCHEDULE */
	if (strcmp(tidtype, K_TID) == 0) {
		int 	cpuid;
		/* XXX Assumes cpuid always exists in kernel schedule */
		cpuid = tnf_get_int32(tnf_get_slot_named(schedule_rec, CPUID));
		/* print the OUTPUT schedule record for Kernel case */
		(void) printf("%16.6f %16.6f %5u %5u 0x%-8llx %3d",
			evt_time / 1000000.0,
			(evt_time - last_time)/1000000.0,
			pid, lwpid, tid, cpuid);
	} else {
		/* print the OUTPUT schedule record */
		(void) printf("%16.6f %16.6f %5u %5u %10llu %3s",
			evt_time / 1000000.0,
			(evt_time - last_time)/1000000.0,
			pid, lwpid, tid, "-");
	}
	/* print the tag */
	eventname = tnf_type_get_name(tnf_get_slot_named(datum, TNF_N_TAG));
	(void) printf(" %-25s", eventname);

	/* heuristic - start of data is after TIME_DELTA field */
	start_slots = tnf_get_slot_index(datum, TNF_N_TIME_DELTA);
	start_slots++;

	n = tnf_get_slot_count(datum);

	/* print the rest of the fields */
	for (i = start_slots; i < n; i++) {
		(void) printf(" ");
		slotname = tnf_get_slot_name(datum, i);
		(void) printf("%s: ", slotname);
		describe_target(tnf_get_slot_indexed(datum, i));
	}
	(void) printf("\n");
	last_time = evt_time;
}

static void
describe_c_struct(tnf_datum_t datum)
{
	unsigned 	n, i, tag_index;
	char 		*slotname;

	n = tnf_get_slot_count(datum);

	/* print the tag */
	(void) printf(" ");
	(void) printf("%s: ", "type");
	describe_c_brief(tnf_get_slot_named(datum, TNF_N_TAG));
	tag_index = tnf_get_slot_index(datum, TNF_N_TAG);

	for (i = 0; i < n; i++) {
		/* print the rest of the members */
		if (i != tag_index) {
			(void) printf(" ");
			slotname = tnf_get_slot_name(datum, i);
			(void) printf("%s: ", slotname);
			describe_target(tnf_get_slot_indexed(datum, i));
		}
	}
}

static void
describe_c_brief(tnf_datum_t datum)
{
	if (datum == TNF_DATUM_NULL) /* allowed */
		(void) printf("0x%-8x <NULL>", 0);

	else if (tnf_is_scalar(datum))
		describe_scalar(datum);

	else if (tnf_is_record(datum)) {

		switch (tnf_get_kind(datum)) {
		case TNF_K_TYPE:
			(void) printf("%s", tnf_type_get_name(datum));
			break;
		case TNF_K_STRING:
			(void) printf("\"%s\"", tnf_get_chars(datum));
			break;
		default:
			(void) printf("<%s>", tnf_get_type_name(datum));
		}
	} else
		fail(0, gettext("inline aggregate slots/elements unhandled"));
}

static void
describe_target(tnf_datum_t datum)
{
	if (datum == TNF_DATUM_NULL) /* allowed */
		(void) printf("0x%-8x <NULL>", 0);

	else if (tnf_is_scalar(datum))
		describe_scalar(datum);

	else if (tnf_is_record(datum)) {

		switch (tnf_get_kind(datum)) {
		case TNF_K_STRUCT:
			(void) printf("{");
			describe_c_struct(datum);
			(void) printf(" }");
			break;
		case TNF_K_TYPE:
			(void) printf("%s", tnf_type_get_name(datum));
			break;
		case TNF_K_STRING:
			(void) printf("\"%s\"", tnf_get_chars(datum));
			break;
		default:
			(void) printf("<%s>", tnf_get_type_name(datum));
		}
	} else
		fail(0, gettext("inline aggregate slots/elements unhandled"));
}
