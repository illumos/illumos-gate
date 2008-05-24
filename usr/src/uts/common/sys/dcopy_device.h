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

#ifndef _SYS_DCOPY_DEVICE_H
#define	_SYS_DCOPY_DEVICE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/dcopy.h>

/*
 * private command state. Space for this structure should be allocated during
 * (*cb_cmd_alloc). The DMA driver must set dp_private in dcopy_cmd_t to point
 * to the memory it allocated. Other than pr_device_cmd_private, the DMA driver
 * should not touch any of the fields in this structure. pr_device_cmd_private
 * is a private pointer for the DMA engine to use.
 */
struct dcopy_cmd_priv_s {
	/*
	 * we only init the state used to track a command which blocks when it
	 * actually blocks. pr_block_init tells us when we need to clean it
	 * up during a cmd_free.
	 */
	boolean_t		pr_block_init;

	/* dcopy_poll blocking state */
	list_node_t		pr_poll_list_node;
	volatile boolean_t	pr_wait;
	kmutex_t		pr_mutex;
	kcondvar_t		pr_cv;

	/* back pointer to the command */
	dcopy_cmd_t		pr_cmd;

	/* shortcut to the channel we're on */
	struct dcopy_channel_s	*pr_channel;

	/* DMA driver private pointer */
	void			*pr_device_cmd_private;
};

/* cb_version */
#define	DCOPY_DEVICECB_V0	0

typedef struct dcopy_device_chaninfo_s {
	uint_t	di_chan_num;
} dcopy_device_chaninfo_t;

typedef struct dcopy_device_cb_s {
	int	cb_version;
	int	cb_res1;

	/* allocate/free a DMA channel. See dcopy.h for return status  */
	int	(*cb_channel_alloc)(void *device_private,
		    dcopy_handle_t handle, int flags, uint_t size,
		    dcopy_query_channel_t *info, void *channel_private);
	void	(*cb_channel_free)(void *channel_private);

	/* allocate/free a command. See dcopy.h for return status  */
	int	(*cb_cmd_alloc)(void *channel_private, int flags,
		    dcopy_cmd_t *cmd);
	void	(*cb_cmd_free)(void *channel_private, dcopy_cmd_t *cmd);

	/*
	 * post a command/poll for command status. See dcopy.h for return
	 * status
	 */
	int	(*cb_cmd_post)(void *channel_private, dcopy_cmd_t cmd);
	int	(*cb_cmd_poll)(void *channel_private, dcopy_cmd_t cmd);

	/*
	 * if dcopy_device_unregister() returns DCOPY_PENDING, dcopy will
	 * call this routine when all the channels are no longer being
	 * used and have been free'd up. e.g. it's safe for the DMA driver
	 * to detach.
	 *   status = DCOPY_SUCCESS || DCOPY_FAILURE
	 */
	void	(*cb_unregister_complete)(void *device_private, int status);
} dcopy_device_cb_t;


typedef struct dcopy_device_info_s {
	dev_info_t		*di_dip;
	dcopy_device_cb_t	*di_cb; /* must be a static array */
	uint_t			di_num_dma;
	uint_t			di_maxxfer;
	uint_t			di_capabilities;
	uint64_t		di_id;
} dcopy_device_info_t;

typedef struct dcopy_device_s *dcopy_device_handle_t;

/* dcopy_device_notify() status */
#define	DCOPY_COMPLETION	0

/*
 * dcopy_device_register()
 *   register the DMA device with dcopy.
 *    return status => DCOPY_FAILURE, DCOPY_SUCCESS
 */
int dcopy_device_register(void *device_private, dcopy_device_info_t *info,
    dcopy_device_handle_t *handle);

/*
 * dcopy_device_unregister()
 *   try to unregister the DMA device with dcopy. If the DMA engines are
 *   still being used by upper layer modules, DCOPY_PENDING will be returned.
 *    return status => DCOPY_FAILURE, DCOPY_SUCCESS, DCOPY_PENDING
 *      if DCOPY_PENDING, (*cb_unregister_complete)() will be called when
 *      completed.
 */
int dcopy_device_unregister(dcopy_device_handle_t *handle);

/*
 * dcopy_device_channel_notify()
 *   Notify dcopy of an event.
 *     dcopy_handle_t handle => what was passed into (*cb_alloc)()
 *     status => DCOPY_COMPLETION
 */
void dcopy_device_channel_notify(dcopy_handle_t handle, int status);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_DCOPY_DEVICE_H */
