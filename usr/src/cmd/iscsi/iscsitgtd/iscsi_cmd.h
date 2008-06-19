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

#ifndef _TARGET_CMD_H
#define	_TARGET_CMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Block comment which describes the contents of this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/avl.h>
#include <aio.h>

#include <iscsitgt_impl.h>
#include "t10.h"

#define	CMD_MAXOUTSTANDING 16

typedef enum {
	FindTTT,
	FindITT
} find_type_t;

typedef enum {
	CmdAlloc,
	CmdCanceled,
	CmdFree
} cmd_state_t;

typedef struct iscsi_delayed {
	struct iscsi_delayed	*id_prev,
				*id_next;
	t10_cmd_t		*id_t10_cmd;
	size_t			id_offset;
} iscsi_delayed_t;

typedef struct iscsi_cmd {
	struct iscsi_cmd	*c_next;
	struct iscsi_cmd	*c_prev;

	/*
	 * Always kept in network byte order since we only
	 * store this field
	 */
	uint32_t		c_itt;

	uint32_t		c_opcode;
	uint32_t		c_ttt;
	uint32_t		c_cmdsn;
	uint32_t		c_datasn;
	uint32_t		c_statsn;
	uint32_t		c_dlen_expected;

	Boolean_t		c_writeop;
	uint32_t		c_lun;

	/*
	 * Default storage for SCB which is the most common size to day.
	 */
	uint8_t			c_scb_default[16];

	/*
	 * If the CDB is larger than 16 bytes an Alternate Header Segment
	 * is used and memory allocated which is pointed to by the following
	 */
	uint8_t			*c_scb_extended;

	/*
	 * Points at the appropriate memory area for the SCB
	 */
	uint8_t			*c_scb;
	uint32_t		c_scb_len;

	cmd_state_t		c_state;
	uint32_t		c_status;

	/*
	 * When ImmediateData==Yes it'll be read in to a buffer
	 * allocated by the connection. This will be free'd when the
	 * callback is done which means the SAM-3 layer is finished with
	 * the data.
	 */
	char			*c_data;
	size_t			c_data_len;
	off_t			c_offset_out;

	/*
	 * Arrange for the PDUs to always be sent in order. If DataPDUInOrder
	 * is True this is a *must* according to the specification. There's
	 * also a need that the final flag bit not be sent unless all other
	 * packets have been, regardless of order. Without keeping a complicated
	 * bitmap of which packets have been sent for this second case we
	 * just order things always.
	 */
	off_t			c_offset_in;
	iscsi_delayed_t		*c_t10_delayed;

	Boolean_t		c_data_alloc;

	void			(*c_dataout_cb)(t10_cmd_t *cmd, char *data,
				    size_t *xfer);

	/*
	 * Used to hold the interface pointer when we've got an R2T
	 * for this command. This is needed because memory is allocated
	 * normally by the emulation layer and we can copy directly to that
	 * instead of allocating our own buffer.
	 */
	t10_cmd_t		*c_t10_cmd;
	uint32_t		c_t10_dup;

	/*
	 * Used by the session layer to send packets out the same
	 * connection.
	 */
	struct iscsi_conn	*c_allegiance;

	hrtime_t		c_t_start,
				c_t_completion;

} iscsi_cmd_t;


void iscsi_cmd_init();
iscsi_cmd_t *iscsi_cmd_alloc(struct iscsi_conn *c, int opcode);
iscsi_cmd_t *iscsi_cmd_find(struct iscsi_conn *c, uint32_t x,
    find_type_t type);
void iscsi_cmd_free(struct iscsi_conn *c, iscsi_cmd_t *cmd);
void iscsi_cmd_cancel(struct iscsi_conn *c, iscsi_cmd_t *cmd);
void iscsi_cmd_remove(struct iscsi_conn *c, uint32_t statsn);
int iscsi_cmd_window(struct iscsi_conn *c);
void iscsi_cmd_delayed_store(iscsi_cmd_t *cmd, t10_cmd_t *t);
void iscsi_cmd_delayed_remove(iscsi_cmd_t *cmd, iscsi_delayed_t *d);
void iscsi_cancel_dups(iscsi_cmd_t *, t10_cmd_event_t);

#ifdef __cplusplus
}
#endif

#endif /* _TARGET_CMD_H */
