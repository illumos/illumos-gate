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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DCOPY_H
#define	_SYS_DCOPY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * *** This interface is for private use by the IP stack only ***
 */

/* Private dcopy/uioa interface for dcopy to enable/disable dcopy KAPI */
extern void uioa_dcopy_enable();
extern void uioa_dcopy_disable();

/* Function return status */
#define	DCOPY_FAILURE		(-1)
#define	DCOPY_SUCCESS		(0)
#define	DCOPY_NORESOURCES	(1) /* _alloc & _cmd_alloc, _cmd_post only */
#define	DCOPY_PENDING		(0x10) /* dcopy_poll(), dcopy_unregister() */
#define	DCOPY_COMPLETED		(0x20) /* dcopy_poll() only */


/* dq_version */
#define	DCOPY_QUERY_V0	0

typedef struct dcopy_query_s {
	int		dq_version; /* DCOPY_QUERY_V0 */
	uint_t		dq_num_channels; /* number of dma channels */
} dcopy_query_t;

/*
 * dcopy_query()
 *   query for the number of DMA engines usable in the system.
 */
void dcopy_query(dcopy_query_t *query);


typedef struct dcopy_channel_s *dcopy_handle_t;

/* dcopy_alloc() and dcopy_cmd_alloc() common flags */
#define	DCOPY_SLEEP	(0)
#define	DCOPY_NOSLEEP	(1 << 0)

/*
 * dcopy_alloc()
 *   Allocate a DMA channel which is used for posting DMA requests. Note: this
 *   does not give the caller exclusive access to the DMA engine. Commands
 *   posted to a channel will complete in order.
 *     flags - (DCOPY_SLEEP, DCOPY_NOSLEEP)
 *     returns => DCOPY_FAILURE, DCOPY_SUCCESS, DCOPY_NORESOURCES
 */
int dcopy_alloc(int flags, dcopy_handle_t *handle);

/*
 * dcopy_free()
 *   Free the DMA channel. The client can no longer use the handle to post or
 *   poll for status on posts which were previously done on this channel.
 */
void dcopy_free(dcopy_handle_t *handle);

/* dq_version */
#define	DCOPY_QUERY_CHANNEL_V0	0

/* Per DMA channel info */
typedef struct dcopy_query_channel_s {
	int		qc_version; /* DCOPY_QUERY_CHANNEL_V0 */

	/* Does DMA channel support DCA */
	boolean_t	qc_dca_supported;

	/* device id and device specific capabilities */
	uint64_t	qc_id;
	uint64_t	qc_capabilities;

	/*
	 * DMA channel size. This may not be the same as the number of posts
	 * that the DMA channel can handle since a post may consume 1 or more
	 * entries.
	 */
	uint64_t	qc_channel_size;

	/* DMA channel number within the device. Not unique across devices */
	uint64_t	qc_chan_num;
} dcopy_query_channel_t;

/*
 * dcopy_query_channel()
 *   query DMA engines capabilities
 */
void dcopy_query_channel(dcopy_handle_t handle, dcopy_query_channel_t *query);


/* dp_version */
#define	DCOPY_CMD_V0	0

/* dp_cmd */
#define	DCOPY_CMD_COPY	0x1

/* dp_flags */
/*
 * DCOPY_CMD_QUEUE
 *    Hint to queue up the post but don't notify the DMA engine. This can be
 *    used as an optimization when multiple posts are going to be queued up and
 *    you only want notify the DMA engine after the last post. Note, this does
 *    not mean the DMA engine won't process the request since it could notice
 *    it anyway.
 * DCOPY_CMD_NOSTAT
 *    Don't generate a status. If this flag is used, You cannot poll for
 *    completion status on this command. This can be a useful performance
 *    optimization if your posting multiple commands and just want to poll on
 *    the last command.
 * DCOPY_CMD_DCA
 *    If DCA is supported, direct this and all future command data (until the
 *    next command with DCOPY_POST_DCA set) to the processor specified in
 *    dp_dca_id. This flag is ignored if DCA is not supported.
 * DCOPY_CMD_INTR
 *    Generate an interrupt when command completes. This flag is required if
 *    the caller is going to call dcopy_cmd_poll(() with DCOPY_POLL_BLOCK set
 *    for this command.
 * DCOPY_CMD_NOWAIT
 *    Return error instead of busy waiting if resource is not available.
 * DCOPY_CMD_NOSRCSNP
 *    Disable source cache snooping.
 * DCOPY_CMD_NODSTSNP
 *    Disable destination cache snooping.
 * DCOPY_CMD_LOOP
 *    For CBv1, generate a loop descriptor list, used to support FIPE driver.
 * DCOPY_CMD_SYNC
 *    Reserved for internal use.
 */
#define	DCOPY_CMD_NOFLAGS	(0)
#define	DCOPY_CMD_QUEUE		(1 << 0)
#define	DCOPY_CMD_NOSTAT	(1 << 1)
#define	DCOPY_CMD_DCA		(1 << 2)
#define	DCOPY_CMD_INTR		(1 << 3)
#define	DCOPY_CMD_NOWAIT	(1 << 4)
#define	DCOPY_CMD_NOSRCSNP	(1 << 5)
#define	DCOPY_CMD_NODSTSNP	(1 << 6)
#define	DCOPY_CMD_LOOP		(1 << 7)
#define	DCOPY_CMD_SYNC		(1 << 30)

typedef struct dcopy_cmd_copy_s {
	uint64_t	cc_source; /* Source physical address */
	uint64_t	cc_dest; /* Destination physical address */
	size_t		cc_size;
} dcopy_cmd_copy_t;

typedef union dcopy_cmd_u {
	dcopy_cmd_copy_t	copy;
} dcopy_cmd_u_t;

typedef struct dcopy_cmd_priv_s *dcopy_cmd_priv_t;

struct dcopy_cmd_s {
	uint_t			dp_version; /* DCOPY_CMD_V0 */
	uint_t			dp_flags;
	uint64_t		dp_cmd;
	dcopy_cmd_u_t   	dp;
	uint32_t		dp_dca_id;
	dcopy_cmd_priv_t	dp_private;
};
typedef struct dcopy_cmd_s *dcopy_cmd_t;


/*
 * dcopy_cmd_alloc() specific flags
 *   DCOPY_ALLOC_LINK - when set, the caller passes in a previously alloced
 *     command in cmd. dcopy_cmd_alloc() will allocate a new command and
 *     link it to the old command. The caller can use this to build a
 *     chain of commands, keeping only the last cmd alloced. calling
 *     dcopy_cmd_free() with the last cmd alloced in the chain will free all of
 *     the commands in the chain. dcopy_cmd_post() and dcopy_cmd_poll() have
 *     no knowledge of a chain of commands.  It's only used for alloc/free.
 */
#define	DCOPY_ALLOC_LINK	(1 << 16)

/*
 * dcopy_cmd_alloc()
 *   allocate a command. A command can be re-used after it completes.
 *     flags - (DCOPY_SLEEP || DCOPY_NOSLEEP), DCOPY_ALLOC_LINK
 *     returns => DCOPY_FAILURE, DCOPY_SUCCESS, DCOPY_NORESOURCES
 */
int dcopy_cmd_alloc(dcopy_handle_t handle, int flags, dcopy_cmd_t *cmd);

/*
 * dcopy_cmd_free()
 *   free the command. This call cannot be called after dcopy_free().
 */
void dcopy_cmd_free(dcopy_cmd_t *cmd);

/*
 * dcopy_cmd_post()
 *   post a command (allocated from dcopy_cmd_alloc()) to the DMA channel
 *     returns => DCOPY_FAILURE, DCOPY_SUCCESS, DCOPY_NORESOURCES
 */
int dcopy_cmd_post(dcopy_cmd_t cmd);

/* dcopy_cmd_poll() flags */
#define	DCOPY_POLL_NOFLAGS	(0)
#define	DCOPY_POLL_BLOCK	(1 << 0)

/*
 * dcopy_cmd_poll()
 *   poll on completion status of a previous post. This call cannot be called
 *   after dcopy_free().
 *
 *   if flags == DCOPY_POLL_NOFLAGS, return status can be DCOPY_FAILURE,
 *   DCOPY_PENDING, or DCOPY_COMPLETED.
 *
 *   if flags & DCOPY_POLL_BLOCK, return status can be DCOPY_FAILURE or
 *   DCOPY_COMPLETED. DCOPY_POLL_BLOCK can only be set in base context.
 *
 *   The command cannot be re-used or freed until the command has completed
 *   (e.g. DCOPY_FAILURE or DCOPY_COMPLETED).
 */
int dcopy_cmd_poll(dcopy_cmd_t cmd, int flags);


#ifdef __cplusplus
}
#endif

#endif /* _SYS_DCOPY_H */
