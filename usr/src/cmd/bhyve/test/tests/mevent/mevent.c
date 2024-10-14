/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

#include "../../../common/mevent.c"
#include "testlib.h"

/*
 * Returns by reference the number of events on the global and change lists.
 *
 * Used by tests that wish to ensure that the event count changes as suggested
 * by mevent_add() and mevent_delete().  Note that a delete does not immediately
 * delete an event.  Events that are pending delete are included in the change
 * list until the next pass through the change list to process pending changes.
 */
void
test_mevent_count_lists(int *ret_global, int *ret_change, int *ret_del_pending)
{
	struct mevent *mevp;
	int global = 0;
	int change = 0;
	int del_pending = 0;

	mevent_qlock();

	LIST_FOREACH(mevp, &global_head, me_list) {
		global++;
		VERBOSE(("on global: type %d fd %d state %d", mevp->me_type,
		    mevp->me_fd, mevp->me_state));
	}

	LIST_FOREACH(mevp, &change_head, me_list) {
		change++;
		if (mevp->me_state == EV_DELETE) {
			del_pending++;
		}
		VERBOSE(("on change: type %d fd %d state %d", mevp->me_type,
		    mevp->me_fd, mevp->me_state));
	}

	mevent_qunlock();

	*ret_global = global;
	*ret_change = change;
	*ret_del_pending = del_pending;
}

void
set_mevent_file_poll_interval_ms(int ms)
{
	mevent_file_poll_interval_ms = ms;
}
