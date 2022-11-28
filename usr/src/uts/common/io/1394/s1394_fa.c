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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * s1394_fa.c
 *    1394 Services Layer Fixed Address Support Routines
 *    Currently used for FCP support.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/types.h>
#include <sys/kmem.h>

#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>

static void s1394_fa_completion_cb(cmd1394_cmd_t *cmd);

/*
 * s1394_fa_claim_addr_blk()
 *    Claim fixed address block.
 */
int
s1394_fa_claim_addr(s1394_hal_t *hal, s1394_fa_type_t type,
    s1394_fa_descr_t *descr)
{
	t1394_alloc_addr_t	addr;
	s1394_fa_hal_t		*falp = &hal->hal_fa[type];
	int			ret;

	/* Might have been claimed already */
	if (falp->fal_addr_blk != NULL) {
		return (DDI_SUCCESS);
	}

	falp->fal_descr = descr;

	bzero(&addr, sizeof (addr));
	addr.aa_type = T1394_ADDR_FIXED;
	addr.aa_address = descr->fd_addr;
	addr.aa_length = descr->fd_size;
	addr.aa_enable = descr->fd_enable;
	addr.aa_evts = descr->fd_evts;
	addr.aa_arg = hal;

	ret = s1394_claim_addr_blk(hal, &addr);
	if (ret == DDI_SUCCESS) {
		falp->fal_addr_blk = (s1394_addr_space_blk_t *)addr.aa_hdl;
	}

	return (ret);
}

/*
 * s1394_fa_free_addr_blk()
 *    Free fixed address block.
 */
void
s1394_fa_free_addr(s1394_hal_t *hal, s1394_fa_type_t type)
{
	s1394_fa_hal_t		*falp = &hal->hal_fa[type];

	/* Might have been freed already */
	if (falp->fal_addr_blk != NULL) {
		(void) s1394_free_addr_blk(hal, falp->fal_addr_blk);
		falp->fal_addr_blk = NULL;
	}
}

/*
 * s1394_fa_list_add()
 *    Add target to the list of FA clients.
 *    target_list_rwlock should be writer-held.
 */
void
s1394_fa_list_add(s1394_hal_t *hal, s1394_target_t *target,
    s1394_fa_type_t type)
{
	s1394_fa_hal_t	*fal = &hal->hal_fa[type];

	if (fal->fal_head == NULL) {
		ASSERT(fal->fal_tail == NULL);
		fal->fal_head = fal->fal_tail = target;
	} else {
		fal->fal_tail->target_fa[type].fat_next = target;
		fal->fal_tail = target;
	}
	fal->fal_gen++;
}

/*
 * s1394_fa_list_remove()
 *    Remove target from the list of FA clients.
 *    target_list_rwlock should be writer-held.
 */
int
s1394_fa_list_remove(s1394_hal_t *hal, s1394_target_t *target,
    s1394_fa_type_t type)
{
	s1394_fa_hal_t	*fal = &hal->hal_fa[type];
	s1394_target_t	*curp, **nextp, *prevp = NULL;

	for (nextp = &fal->fal_head; (curp = *nextp) != NULL; ) {
		if (curp == target) {
			*nextp = target->target_fa[type].fat_next;
			if (target == fal->fal_tail) {
				fal->fal_tail = prevp;
			}
			fal->fal_gen++;
			return (DDI_SUCCESS);
		}
		nextp = &curp->target_fa[type].fat_next;
		prevp = curp;
	}
	return (DDI_FAILURE);
}

/*
 * s1394_fa_list_is_empty()
 *    Returns B_TRUE if the target list is empty
 *    target_list_rwlock should be at least reader-held.
 */
boolean_t
s1394_fa_list_is_empty(s1394_hal_t *hal, s1394_fa_type_t type)
{
	s1394_fa_hal_t	*fal = &hal->hal_fa[type];

	return (fal->fal_head == NULL);
}

/*
 * s1394_fa_list_gen()
 *    Returns list generation number.
 *    target_list_rwlock should be at least reader-held.
 */
uint_t
s1394_fa_list_gen(s1394_hal_t *hal, s1394_fa_type_t type)
{
	s1394_fa_hal_t	*fal = &hal->hal_fa[type];

	return (fal->fal_gen);
}

/*
 * s1394_fa_init_cmd()
 *    initialize the FA specific part of the command
 */
void
s1394_fa_init_cmd(s1394_cmd_priv_t *s_priv, s1394_fa_type_t type)
{
	s_priv->cmd_ext_type = S1394_CMD_EXT_FA;
	s_priv->cmd_ext.fa.type = type;
}

/*
 * s1394_fa_convert_cmd()
 *    convert an FA command (with a relative address) to a regular 1394 command
 */
void
s1394_fa_convert_cmd(s1394_hal_t *hal, cmd1394_cmd_t *cmd)
{
	s1394_fa_cmd_priv_t *fa_priv = S1394_GET_FA_CMD_PRIV(cmd);

	cmd->cmd_addr += hal->hal_fa[fa_priv->type].fal_descr->fd_conv_base;
	fa_priv->completion_callback = cmd->completion_callback;
	fa_priv->callback_arg = cmd->cmd_callback_arg;
	cmd->completion_callback = s1394_fa_completion_cb;
	cmd->cmd_callback_arg = hal;
}

/*
 * s1394_fa_restore_cmd()
 *    opposite of s1394_fa_convert_cmd(): regular 1394 command to FA command
 */
void
s1394_fa_restore_cmd(s1394_hal_t *hal, cmd1394_cmd_t *cmd)
{
	s1394_fa_cmd_priv_t *fa_priv = S1394_GET_FA_CMD_PRIV(cmd);

	ASSERT(fa_priv->type < S1394_FA_NTYPES);

	cmd->cmd_addr -= hal->hal_fa[fa_priv->type].fal_descr->fd_conv_base;
	cmd->completion_callback = fa_priv->completion_callback;
	cmd->cmd_callback_arg = fa_priv->callback_arg;
}

/*
 * s1394_fa_check_restore_cmd()
 *    if a command has FA extension, do s1394_fa_restore_cmd()
 */
void
s1394_fa_check_restore_cmd(s1394_hal_t *hal, cmd1394_cmd_t *cmd)
{
	s1394_cmd_priv_t *s_priv = S1394_GET_CMD_PRIV(cmd);

	if (s_priv->cmd_ext_type == S1394_CMD_EXT_FA) {
		s1394_fa_restore_cmd(hal, cmd);
	}
}

/*
 * s1394_fa_completion_cb()
 *    FA completion callback: restore command and call original callback
 */
static void
s1394_fa_completion_cb(cmd1394_cmd_t *cmd)
{
	s1394_hal_t	*hal = cmd->cmd_callback_arg;

	s1394_fa_restore_cmd(hal, cmd);

	if (cmd->completion_callback) {
		cmd->completion_callback(cmd);
	}
}
