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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <assert.h>
#include <syslog.h>
#include <synch.h>
#include <sys/time.h>
#include <sys/asynch.h>
#include <umem.h>
#include <strings.h>

#include "iscsi_conn.h"
#include "iscsi_cmd.h"
#include "target.h"
#include "utility.h"

static pthread_mutex_t	cmd_mutex;
static int		cmd_ttt;

/*
 * []----
 * | iscsi_cmd_init -- called at the beginning of time to initialize locks
 * []----
 */
void
iscsi_cmd_init()
{
	(void) pthread_mutex_init(&cmd_mutex, NULL);
	cmd_ttt = 0;
}

/*
 * []----
 * | iscsi_cmd_alloc -- allocate space for new command
 * []----
 */
iscsi_cmd_t *
iscsi_cmd_alloc(iscsi_conn_t *c, int op)
{
	iscsi_cmd_t *cmd = umem_cache_alloc(iscsi_cmd_cache, UMEM_DEFAULT);

	if (cmd == NULL) {
		queue_prt(mgmtq, Q_CONN_ERRS, "Failed to get command buf\n");
		return (NULL);
	}

	bzero(cmd, sizeof (*cmd));
	(void) pthread_mutex_lock(&cmd_mutex);
	cmd->c_ttt = cmd_ttt++;
	(void) pthread_mutex_unlock(&cmd_mutex);

	(void) pthread_mutex_lock(&c->c_mutex);
	cmd->c_opcode		= op;
	cmd->c_statsn		= c->c_statsn;
	cmd->c_state		= CmdAlloc;
	if (c->c_cmd_head == NULL) {
		c->c_cmd_head = cmd;
		assert(c->c_cmd_tail == NULL);
		c->c_cmd_tail = cmd;
	} else {
		c->c_cmd_tail->c_next = cmd;
		cmd->c_prev = c->c_cmd_tail;
		c->c_cmd_tail = cmd;
	}
	cmd->c_allegiance = c;
	cmd->c_t_start = gethrtime();
	c->c_cmds_active++;
	(void) pthread_mutex_unlock(&c->c_mutex);

	return (cmd);
}

/*
 * []----
 * | iscsi_cmd_find -- search for a specific command and return it
 * |
 * | XXX Need to switch to use an AVL tree.
 * []----
 */
iscsi_cmd_t *
iscsi_cmd_find(iscsi_conn_t *c, uint32_t val, find_type_t type)
{
	iscsi_cmd_t	*cmd = NULL;

	(void) pthread_mutex_lock(&c->c_mutex);
	for (cmd = c->c_cmd_head; cmd; cmd = cmd->c_next) {

		/*
		 * Depending on type determine correct matching value.
		 * Only return a hit if the command hasn't already been
		 * freed.
		 */
		if ((((type == FindTTT) && (cmd->c_ttt == val)) ||
		    ((type == FindITT) && (cmd->c_itt == val))) &&
		    (cmd->c_state != CmdFree))
			break;
	}
	(void) pthread_mutex_unlock(&c->c_mutex);

	return (cmd);
}

/*
 * []----
 * | iscsi_cmd_free -- mark a command as freed.
 * []----
 */
void
iscsi_cmd_free(iscsi_conn_t *c, iscsi_cmd_t *cmd)
{
	hrtime_t	h	= gethrtime();

	assert(cmd->c_state != CmdFree);
	cmd->c_state		= CmdFree;
	cmd->c_t_completion	= h - cmd->c_t_start;
	c->c_cmds_avg_sum	+= cmd->c_t_completion;
	c->c_cmds_avg_cnt++;
	/* decrement active count here */
	c->c_cmds_active--;
}

/*
 * Find all duplicated t10_cmd and shoot an event
 */
void
iscsi_cancel_dups(iscsi_cmd_t *cmd, t10_cmd_event_t e)
{
	t10_cmd_t	*c2free;
	t10_cmd_t	*nc;

	/* Run the list */
	c2free = cmd->c_t10_cmd;
	while (c2free != NULL) {
		nc = c2free->c_cmd_next;
		t10_cmd_shoot_event(c2free, e);
		c2free = nc;
	}
}

/*
 * []----
 * | iscsi_cmd_cancel -- mark a command as canceled
 * |
 * | We don't actually stop commands in flight. We only prevent the canceled
 * | commands from returning status and/or data to the initiator. At the
 * | connection layer if a command is canceled nothing will be sent on the
 * | wire and at that point the command is marked CmdFree so that future calls
 * | to cmd_remove will actually free the space.
 * |
 * | NOTE: connection mutex must be held during this call.
 * []----
 */
void
iscsi_cmd_cancel(iscsi_conn_t *c, iscsi_cmd_t *cmd)
{
	assert(pthread_mutex_trylock(&c->c_mutex) != 0);
	if (cmd->c_state == CmdAlloc) {
		cmd->c_state = CmdCanceled;
		if (cmd->c_t10_cmd != NULL) {
			if (cmd->c_t10_dup)
				iscsi_cancel_dups(cmd, T10_Cmd_T6);
			else
				t10_cmd_shoot_event(cmd->c_t10_cmd, T10_Cmd_T6);
		}
	}
}

/*
 * []----
 * | iscsi_cmd_remove -- actually free space allocated to commands
 * |
 * | According to the iSCSI specification the target must kept resources
 * | around until the initiator sends a command with a status serial
 * | number higher than the held resource. This is so that an initiator
 * | can request data again if needed. During the processing of each new
 * | command this routine is called to free old commands.
 * []----
 */
void
iscsi_cmd_remove(iscsi_conn_t *c, uint32_t statsn)
{
	iscsi_cmd_t	*cmd, *n;
	iscsi_cmd_t	*cmd_free = NULL;

	(void) pthread_mutex_lock(&c->c_mutex);
	for (cmd = c->c_cmd_head; cmd; ) {
		/*
		 * If the StatusSN for this command is less than the incoming
		 * StatusSN and the command has been freed remove it from
		 * list. Don't bother with commands that are in the state of
		 * CmdCanceled. Once the I/O has been completed the command
		 * is passed back to the connection handler where the state
		 * will be noticed and then the command will be freed. At that
		 * point the next incoming command with a valid expected
		 * status serial number will free the memory.
		 */
		if (sna_lt(cmd->c_statsn, statsn)) {
			if (cmd->c_state == CmdFree) {
				if (c->c_cmd_head == cmd) {
					c->c_cmd_head = cmd->c_next;
					if (c->c_cmd_head == NULL)
						c->c_cmd_tail = NULL;
				} else {
					n = cmd->c_prev;
					n->c_next = cmd->c_next;
					if (cmd->c_next != NULL)
						cmd->c_next->c_prev = n;
					else {
						assert(c->c_cmd_tail == cmd);
						c->c_cmd_tail = n;
					}
				}

				/*
				 * Place on local command free list, to free
				 * once mutex is released
				 */
				n = cmd->c_next;
				cmd->c_next = cmd_free;
				cmd_free = cmd;
				cmd = n;
			} else {
				cmd = cmd->c_next;
			}
		} else {
			break;
		}
	}
	(void) pthread_mutex_unlock(&c->c_mutex);

	/*
	 * Deallocate command free list
	 */
	cmd = cmd_free;
	while (cmd != NULL) {
		n = cmd->c_next;
		if (cmd->c_scb_extended)
			free(cmd->c_scb_extended);
		if (cmd->c_data_alloc == True) {
			free(cmd->c_data);
			cmd->c_data = NULL;
		}
		umem_cache_free(iscsi_cmd_cache, cmd);
		cmd = n;
	}
}

/*
 * []----
 * | iscsi_cmd_window -- return the number of available commands
 * |
 * | There are currently 7 different places where this routine is called.
 * | In some cases and command is allocated which will be freed shortly and
 * | in others no command is held. This is why the number of commands found
 * | will be decremented if larger than 0. Since the daemon doesn't have
 * | any hard limits on the number of commands being supported this is more
 * | arbitrary and the command window size is used for debugging other
 * | initiators.
 * |
 * | NOTE: connection mutex must be held during this call.
 * []----
 */
int
iscsi_cmd_window(iscsi_conn_t *c)
{
	int			cnt;

	assert(pthread_mutex_trylock(&c->c_mutex) != 0);
	if (c->c_cmds_avg_cnt == 0) {

		/*
		 * If there are no outstanding commands clear the averages
		 * so that the initiator can start again.
		 */
		c->c_cmds_avg_sum = 0;
		c->c_cmds_avg_cnt = 0;
		cnt = c->c_maxcmdsn - c->c_cmds_active;

	} else if ((c->c_cmds_avg_sum / c->c_cmds_avg_cnt) >= NANOSEC) {

		/*
		 * It would appear things are taking a real long time to
		 * complete on our end. Close down the command window to
		 * prevent the initiator from timing out commands.
		 */
		cnt = (c->c_cmds_active >= c->c_maxcmdsn) ? 0 :
		    (c->c_maxcmdsn - c->c_cmds_active) / 2;

	} else {
		cnt = (c->c_cmds_active >= c->c_maxcmdsn) ? 0 :
		    c->c_maxcmdsn - c->c_cmds_active;
	}

	return (cnt);
}

void
iscsi_cmd_delayed_store(iscsi_cmd_t *cmd, t10_cmd_t *t)
{
	iscsi_delayed_t	*d, *n;
	iscsi_delayed_t	*l	= NULL;

	if ((d = (iscsi_delayed_t *)calloc(1, sizeof (*d))) == NULL) {
		syslog(LOG_ERR, "Failed to allocate space for delayed I/O");
		queue_prt(cmd->c_allegiance->c_mgmtq, Q_CONN_ERRS,
		    "CON%x  Failed calloc for delayed I/O",
		    cmd->c_allegiance->c_num);
		t10_cmd_shoot_event(t, T10_Cmd_T5);
		return;
	}

	d->id_offset	= T10_DATA_OFFSET(t);
	d->id_t10_cmd	= t;

	for (n = cmd->c_t10_delayed; n; n = n->id_next) {
		l = n;
		if (d->id_offset < n->id_offset) {
			if (n->id_prev == NULL) {
				d->id_next = n;
				n->id_prev = d;
				cmd->c_t10_delayed = d;
			} else {
				d->id_prev = n->id_prev;
				d->id_prev->id_next = d;
				n->id_prev = d;
				d->id_next = n;
			}
			return;
		}
	}

	if (l == NULL) {
		cmd->c_t10_delayed = d;
	} else {
		l->id_next = d;
		d->id_prev = l;
	}
}

void
iscsi_cmd_delayed_remove(iscsi_cmd_t *cmd, iscsi_delayed_t *d)
{
	if (cmd->c_t10_delayed == d) {
		cmd->c_t10_delayed = d->id_next;
		if (d->id_next)
			d->id_next->id_prev = NULL;
	} else {
		d->id_prev->id_next = d->id_next;
		if (d->id_next != NULL)
			d->id_next->id_prev = d->id_prev;
	}
	free(d);
}
