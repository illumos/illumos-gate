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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * dcam_reg.c
 *
 * dcam1394 driver.  Control register access support.
 */

#include <sys/1394/targets/dcam1394/dcam_reg.h>


/*
 * dcam_reg_read
 */
int
dcam_reg_read(dcam_state_t *soft_state, dcam1394_reg_io_t *arg)
{
	cmd1394_cmd_t	*cmdp;

	if (t1394_alloc_cmd(soft_state->sl_handle, 1, &cmdp) != DDI_SUCCESS) {
		return (-1);
	}

	cmdp->cmd_type = CMD1394_ASYNCH_RD_QUAD;
	cmdp->cmd_addr = 0x0000FFFFF0F00000 |
	    (uint64_t)(arg->offs & 0x00000FFC);
	cmdp->cmd_options = CMD1394_BLOCKING;

#ifdef GRAPHICS_DELAY
	/*
	 * This delay should not be necessary, but was added for some
	 * unknown reason.  Should it ever be determined that it
	 * is necessary, this delay should be reenabled.
	 */
	delay(drv_usectohz(500));
#endif

	if (t1394_read(soft_state->sl_handle, cmdp) != DDI_SUCCESS) {
		(void) t1394_free_cmd(soft_state->sl_handle, 0, &cmdp);
		return (-1);
	}

	if (cmdp->cmd_result != DDI_SUCCESS) {
		(void) t1394_free_cmd(soft_state->sl_handle, 0, &cmdp);
		return (-1);
	}

	/* perform endian adjustment */
	cmdp->cmd_u.q.quadlet_data = T1394_DATA32(cmdp->cmd_u.q.quadlet_data);
	arg->val = cmdp->cmd_u.q.quadlet_data;

	(void) t1394_free_cmd(soft_state->sl_handle, 0, &cmdp);

	return (0);
}


/*
 * dcam_reg_write
 */
int
dcam_reg_write(dcam_state_t *soft_state, dcam1394_reg_io_t *arg)
{
	cmd1394_cmd_t	*cmdp;

	if (t1394_alloc_cmd(soft_state->sl_handle, 0, &cmdp) != DDI_SUCCESS) {
		return (-1);
	}

	cmdp->cmd_type = CMD1394_ASYNCH_WR_QUAD;
	cmdp->cmd_addr = 0x0000FFFFF0F00000 |
	    (uint64_t)(arg->offs & 0x00000FFC);
	cmdp->cmd_options = CMD1394_BLOCKING;

	/* perform endian adjustment */
	cmdp->cmd_u.q.quadlet_data = T1394_DATA32(arg->val);

#ifdef GRAPHICS_DELAY
	/*
	 * See the description in dcam_reg_read() above.
	 */
	delay(drv_usectohz(500));
#endif

	if (t1394_write(soft_state->sl_handle, cmdp) != DDI_SUCCESS) {
		(void) t1394_free_cmd(soft_state->sl_handle, 0, &cmdp);
		return (-1);
	}

	if (cmdp->cmd_result != DDI_SUCCESS) {
		(void) t1394_free_cmd(soft_state->sl_handle, 0, &cmdp);
		return (-1);
	}

	(void) t1394_free_cmd(soft_state->sl_handle, 0, &cmdp);

	return (0);
}
