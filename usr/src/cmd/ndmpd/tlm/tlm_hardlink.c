/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/syslog.h>
#include "tlm.h"
#include "tlm_proto.h"

#define	HL_DBG_INIT		0x0001
#define	HL_DBG_CLEANUP	0x0002
#define	HL_DBG_GET	0x0004
#define	HL_DBG_ADD	0x0008

static int hardlink_q_dbg = -1;


struct hardlink_q *
hardlink_q_init()
{
	struct hardlink_q *qhead;

	qhead = (struct hardlink_q *)malloc(sizeof (struct hardlink_q));
	if (qhead) {
		SLIST_INIT(qhead);
	}

	if (hardlink_q_dbg & HL_DBG_INIT)
		NDMP_LOG(LOG_DEBUG, "qhead = %p", qhead);

	return (qhead);
}

void
hardlink_q_cleanup(struct hardlink_q *hl_q)
{
	struct hardlink_node *hl;

	if (hardlink_q_dbg & HL_DBG_CLEANUP)
		NDMP_LOG(LOG_DEBUG, "(1): qhead = %p", hl_q);

	if (!hl_q)
		return;

	while (!SLIST_EMPTY(hl_q)) {
		hl = SLIST_FIRST(hl_q);

		if (hardlink_q_dbg & HL_DBG_CLEANUP)
			NDMP_LOG(LOG_DEBUG, "(2): remove node, inode = %lu",
			    hl->inode);

		SLIST_REMOVE_HEAD(hl_q, next_hardlink);

		/* remove the temporary file */
		if (hl->is_tmp) {
			if (hl->path) {
				NDMP_LOG(LOG_DEBUG, "(3): remove temp file %s",
				    hl->path);
				if (remove(hl->path)) {
					NDMP_LOG(LOG_DEBUG,
					    "error removing temp file");
				}
			} else {
				NDMP_LOG(LOG_DEBUG, "no link name, inode = %lu",
				    hl->inode);
			}
		}

		if (hl->path)
			free(hl->path);
		free(hl);
	}

	free(hl_q);
}

/*
 * Return 0 if a list node has the same inode, and initialize offset and path
 * with the information in the list node.
 * Return -1 if no matching node is found.
 */
int
hardlink_q_get(struct hardlink_q *hl_q, unsigned long inode,
    unsigned long long *offset, char **path)
{
	struct hardlink_node *hl;

	if (hardlink_q_dbg & HL_DBG_GET)
		NDMP_LOG(LOG_DEBUG, "(1): qhead = %p, inode = %lu",
		    hl_q, inode);

	if (!hl_q)
		return (-1);

	SLIST_FOREACH(hl, hl_q, next_hardlink) {
		if (hardlink_q_dbg & HL_DBG_GET)
			NDMP_LOG(LOG_DEBUG, "(2): checking, inode = %lu",
			    hl->inode);

		if (hl->inode != inode)
			continue;

		if (offset)
			*offset = hl->offset;

		if (path)
			*path = hl->path;

		return (0);
	}

	return (-1);
}

/*
 * Add a node to hardlink_q.  Reject a duplicated entry.
 *
 * Return 0 if successful, and -1 if failed.
 */
int
hardlink_q_add(struct hardlink_q *hl_q, unsigned long inode,
    unsigned long long offset, char *path, int is_tmp_file)
{
	struct hardlink_node *hl;

	if (hardlink_q_dbg & HL_DBG_ADD)
		NDMP_LOG(LOG_DEBUG,
		    "(1): qhead = %p, inode = %lu, path = %p (%s)",
		    hl_q, inode, path, path? path : "(--)");

	if (!hl_q)
		return (-1);

	if (!hardlink_q_get(hl_q, inode, 0, 0)) {
		NDMP_LOG(LOG_DEBUG, "hardlink (inode = %lu) exists in queue %p",
		    inode, hl_q);
		return (-1);
	}

	hl = (struct hardlink_node *)malloc(sizeof (struct hardlink_node));
	if (!hl)
		return (-1);

	hl->inode = inode;
	hl->offset = offset;
	hl->is_tmp = is_tmp_file;
	if (path)
		hl->path = strdup(path);
	else
		hl->path = NULL;

	if (hardlink_q_dbg & HL_DBG_ADD)
		NDMP_LOG(LOG_DEBUG,
		    "(2): added node, inode = %lu, path = %p (%s)",
		    hl->inode, hl->path, hl->path? hl->path : "(--)");

	SLIST_INSERT_HEAD(hl_q, hl, next_hardlink);

	return (0);
}

int
hardlink_q_dump(struct hardlink_q *hl_q)
{
	struct hardlink_node *hl;

	if (!hl_q)
		return (0);

	(void) printf("Dumping hardlink_q, head = %p:\n", (void *) hl_q);

	SLIST_FOREACH(hl, hl_q, next_hardlink)
		(void) printf(
		    "\t node = %lu, offset = %llu, path = %s, is_tmp = %d\n",
		    hl->inode, hl->offset, hl->path? hl->path : "--",
		    hl->is_tmp);

	return (0);
}
