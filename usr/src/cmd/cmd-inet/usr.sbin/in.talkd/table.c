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
 *
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved.
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California.
 * All Rights Reserved.
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Routines to handle insertion, deletion, etc on the table
 * of requests kept by the daemon. Nothing fancy here, linear
 * search on a double-linked list. A time is kept with each
 * entry so that overly old invitations can be eliminated.
 *
 * Consider this a mis-guided attempt at modularity
 */

#include <sys/time.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include "talkd_impl.h"

#define	MAX_ID 16000 /* << 2^15 so I don't have sign troubles */

typedef struct table_entry TABLE_ENTRY;

struct table_entry {
    CTL_MSG request;
    long time;
    TABLE_ENTRY *next;
    TABLE_ENTRY *last;
};

static struct timeval tp;
static TABLE_ENTRY *table = NULL;

static void delete(TABLE_ENTRY *ptr);

/*
 * Look in the table for an invitation that matches the current
 * request looking for an invitation.
 */

CTL_MSG *
find_match(CTL_MSG *request)
{
	TABLE_ENTRY *ptr;
	TABLE_ENTRY *prevp;
	long current_time;

	(void) gettimeofday(&tp, NULL);
	current_time = tp.tv_sec;

	ptr = table;

	if (debug) {
		(void) printf("Entering Look-Up with : \n");
		print_request(request);
	}

	while (ptr != NULL) {

		if ((ptr->time - current_time) > MAX_LIFE) {
		/* the entry is too old */
			if (debug) {
				(void) printf("Deleting expired entry : \n");
				print_request(&ptr->request);
			}
			prevp = ptr;
			ptr = ptr->next;
			delete(prevp);
			continue;
		}

		if (debug)
			print_request(&ptr->request);

		if (strcmp(request->l_name, ptr->request.r_name) == 0 &&
		    strcmp(request->r_name, ptr->request.l_name) == 0 &&
		    ptr->request.type == LEAVE_INVITE) {
			return (&ptr->request);
		}

		ptr = ptr->next;
	}

	return (NULL);
}

/*
 * Look for an identical request, as opposed to a complimentary
 * one as find_match does.
 */

CTL_MSG *
find_request(CTL_MSG *request)
{
	TABLE_ENTRY *ptr;
	TABLE_ENTRY *prevp;
	long current_time;

	(void) gettimeofday(&tp, NULL);
	current_time = tp.tv_sec;

	/*
	 * See if this is a repeated message, and check for
	 * out of date entries in the table while we are it.
	 */

	ptr = table;

	if (debug) {
		(void) printf("Entering find_request with : \n");
		print_request(request);
	}

	while (ptr != NULL) {

		if ((ptr->time - current_time) > MAX_LIFE) {
			/* the entry is too old */
			if (debug) {
				(void) printf("Deleting expired entry : \n");
				print_request(&ptr->request);
			}
			prevp = ptr;
			ptr = ptr->next;
			delete(prevp);
			continue;
		}

		if (debug)
			print_request(&ptr->request);

		if (strcmp(request->r_name, ptr->request.r_name) == 0 &&
		    strcmp(request->l_name, ptr->request.l_name) == 0 &&
		    request->type == ptr->request.type &&
		    request->pid == ptr->request.pid) {

			/* update the time if we 'touch' it */
			ptr->time = current_time;
			return (&ptr->request);
		}

		ptr = ptr->next;
	}

	return (NULL);
}

void
insert_table(CTL_MSG *request, CTL_RESPONSE *response)
{
	TABLE_ENTRY *ptr;
	long current_time;

	(void) gettimeofday(&tp, NULL);
	current_time = tp.tv_sec;

	response->id_num = request->id_num = new_id();

	/*
	 * Insert a new entry into the top of the list.
	 */
	ptr = (TABLE_ENTRY *) malloc(sizeof (TABLE_ENTRY));

	if (ptr == NULL) {
		print_error("malloc in insert_table");
	}

	ptr->time = current_time;
	ptr->request = *request;

	ptr->next = table;
	if (ptr->next != NULL) {
		ptr->next->last = ptr;
	}
	ptr->last = NULL;
	table = ptr;
}

/*
 * Generate a unique non-zero sequence number.
 */

int
new_id(void)
{
	static int current_id = 0;

	current_id = (current_id + 1) % MAX_ID;

	/* 0 is reserved, helps to pick up bugs */
	if (current_id == 0)
		current_id = 1;

	return (current_id);
}

/*
 * Delete the invitation with id 'id_num'.
 */

int
delete_invite(int id_num)
{
	TABLE_ENTRY *ptr;

	ptr = table;

	if (debug)
		(void) printf("Entering delete_invite with %d\n", id_num);

	while (ptr != NULL && ptr->request.id_num != id_num) {
		if (debug)
			print_request(&ptr->request);
		ptr = ptr->next;
	}

	if (ptr != NULL) {
		delete(ptr);
		return (SUCCESS);
	}

	return (NOT_HERE);
}

/*
 * Classic delete from a double-linked list.
 */

static void
delete(TABLE_ENTRY *ptr)
{
	if (debug) {
		(void) printf("Deleting : ");
		print_request(&ptr->request);
	}
	if (table == ptr) {
		table = ptr->next;
	} else if (ptr->last != NULL) {
		ptr->last->next = ptr->next;
	}

	if (ptr->next != NULL) {
		ptr->next->last = ptr->last;
	}

	free(ptr);
}
