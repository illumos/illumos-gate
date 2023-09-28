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

/*
 * dcopy.c
 *    dcopy misc module
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/atomic.h>


#include <sys/dcopy.h>
#include <sys/dcopy_device.h>


/* Number of entries per channel to allocate */
uint_t dcopy_channel_size = 1024;


typedef struct dcopy_list_s {
	list_t			dl_list;
	kmutex_t		dl_mutex;
	uint_t			dl_cnt; /* num entries on list */
} dcopy_list_t;

/* device state for register/unregister */
struct dcopy_device_s {
	/* DMA device drivers private pointer */
	void			*dc_device_private;

	/* to track list of channels from this DMA device */
	dcopy_list_t		dc_devchan_list;
	list_node_t		dc_device_list_node;

	/*
	 * dc_removing_cnt track how many channels still have to be freed up
	 * before it's safe to allow the DMA device driver to detach.
	 */
	uint_t			dc_removing_cnt;
	dcopy_device_cb_t	*dc_cb;

	dcopy_device_info_t	dc_info;

};

typedef struct dcopy_stats_s {
	kstat_named_t	cs_bytes_xfer;
	kstat_named_t	cs_cmd_alloc;
	kstat_named_t	cs_cmd_post;
	kstat_named_t	cs_cmd_poll;
	kstat_named_t	cs_notify_poll;
	kstat_named_t	cs_notify_pending;
	kstat_named_t	cs_id;
	kstat_named_t	cs_capabilities;
} dcopy_stats_t;

/* DMA channel state */
struct dcopy_channel_s {
	/* DMA driver channel private pointer */
	void			*ch_channel_private;

	/* shortcut to device callbacks */
	dcopy_device_cb_t	*ch_cb;

	/*
	 * number of outstanding allocs for this channel. used to track when
	 * it's safe to free up this channel so the DMA device driver can
	 * detach.
	 */
	uint64_t		ch_ref_cnt;

	/* state for if channel needs to be removed when ch_ref_cnt gets to 0 */
	boolean_t		ch_removing;

	list_node_t		ch_devchan_list_node;
	list_node_t		ch_globalchan_list_node;

	/*
	 * per channel list of commands actively blocking waiting for
	 * completion.
	 */
	dcopy_list_t		ch_poll_list;

	/* pointer back to our device */
	struct dcopy_device_s	*ch_device;

	dcopy_query_channel_t	ch_info;

	kstat_t			*ch_kstat;
	dcopy_stats_t		ch_stat;
};

/*
 * If grabbing both device_list mutex & globalchan_list mutex,
 * Always grab globalchan_list mutex before device_list mutex
 */
typedef struct dcopy_state_s {
	dcopy_list_t		d_device_list;
	dcopy_list_t		d_globalchan_list;
} dcopy_state_t;
dcopy_state_t *dcopy_statep;


/* Module Driver Info */
static struct modlmisc dcopy_modlmisc = {
	&mod_miscops,
	"dcopy kernel module"
};

/* Module Linkage */
static struct modlinkage dcopy_modlinkage = {
	MODREV_1,
	&dcopy_modlmisc,
	NULL
};

static int dcopy_init();
static void dcopy_fini();

static int dcopy_list_init(dcopy_list_t *list, size_t node_size,
    offset_t link_offset);
static void dcopy_list_fini(dcopy_list_t *list);
static void dcopy_list_push(dcopy_list_t *list, void *list_node);
static void *dcopy_list_pop(dcopy_list_t *list);

static void dcopy_device_cleanup(dcopy_device_handle_t device,
    boolean_t do_callback);

static int dcopy_stats_init(dcopy_handle_t channel);
static void dcopy_stats_fini(dcopy_handle_t channel);


/*
 * _init()
 */
int
_init()
{
	int e;

	e = dcopy_init();
	if (e != 0) {
		return (e);
	}

	return (mod_install(&dcopy_modlinkage));
}


/*
 * _info()
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&dcopy_modlinkage, modinfop));
}


/*
 * _fini()
 */
int
_fini()
{
	int e;

	e = mod_remove(&dcopy_modlinkage);
	if (e != 0) {
		return (e);
	}

	dcopy_fini();

	return (e);
}

/*
 * dcopy_init()
 */
static int
dcopy_init()
{
	int e;


	dcopy_statep = kmem_zalloc(sizeof (*dcopy_statep), KM_SLEEP);

	/* Initialize the list we use to track device register/unregister */
	e = dcopy_list_init(&dcopy_statep->d_device_list,
	    sizeof (struct dcopy_device_s),
	    offsetof(struct dcopy_device_s, dc_device_list_node));
	if (e != DCOPY_SUCCESS) {
		goto dcopyinitfail_device;
	}

	/* Initialize the list we use to track all DMA channels */
	e = dcopy_list_init(&dcopy_statep->d_globalchan_list,
	    sizeof (struct dcopy_channel_s),
	    offsetof(struct dcopy_channel_s, ch_globalchan_list_node));
	if (e != DCOPY_SUCCESS) {
		goto dcopyinitfail_global;
	}

	return (0);

dcopyinitfail_global:
	dcopy_list_fini(&dcopy_statep->d_device_list);
dcopyinitfail_device:
	kmem_free(dcopy_statep, sizeof (*dcopy_statep));

	return (-1);
}


/*
 * dcopy_fini()
 */
static void
dcopy_fini()
{
	/*
	 * if mod_remove was successfull, we shouldn't have any
	 * devices/channels to worry about.
	 */
	ASSERT(list_head(&dcopy_statep->d_globalchan_list.dl_list) == NULL);
	ASSERT(list_head(&dcopy_statep->d_device_list.dl_list) == NULL);

	dcopy_list_fini(&dcopy_statep->d_globalchan_list);
	dcopy_list_fini(&dcopy_statep->d_device_list);
	kmem_free(dcopy_statep, sizeof (*dcopy_statep));
}


/* *** EXTERNAL INTERFACE *** */
/*
 * dcopy_query()
 */
void
dcopy_query(dcopy_query_t *query)
{
	query->dq_version = DCOPY_QUERY_V0;
	query->dq_num_channels = dcopy_statep->d_globalchan_list.dl_cnt;
}


/*
 * dcopy_alloc()
 */
/*ARGSUSED*/
int
dcopy_alloc(int flags, dcopy_handle_t *handle)
{
	dcopy_handle_t channel;
	dcopy_list_t *list;


	/*
	 * we don't use the dcopy_list_* code here because we need to due
	 * some non-standard stuff.
	 */

	list = &dcopy_statep->d_globalchan_list;

	/*
	 * if nothing is on the channel list, return DCOPY_NORESOURCES. This
	 * can happen if there aren't any DMA device registered.
	 */
	mutex_enter(&list->dl_mutex);
	channel = list_head(&list->dl_list);
	if (channel == NULL) {
		mutex_exit(&list->dl_mutex);
		return (DCOPY_NORESOURCES);
	}

	/*
	 * increment the reference count, and pop the channel off the head and
	 * push it on the tail. This ensures we rotate through the channels.
	 * DMA channels are shared.
	 */
	channel->ch_ref_cnt++;
	list_remove(&list->dl_list, channel);
	list_insert_tail(&list->dl_list, channel);
	mutex_exit(&list->dl_mutex);

	*handle = (dcopy_handle_t)channel;
	return (DCOPY_SUCCESS);
}


/*
 * dcopy_free()
 */
void
dcopy_free(dcopy_handle_t *channel)
{
	dcopy_device_handle_t device;
	dcopy_list_t *list;
	boolean_t cleanup = B_FALSE;


	ASSERT(*channel != NULL);

	/*
	 * we don't need to add the channel back to the list since we never
	 * removed it. decrement the reference count.
	 */
	list = &dcopy_statep->d_globalchan_list;
	mutex_enter(&list->dl_mutex);
	(*channel)->ch_ref_cnt--;

	/*
	 * if we need to remove this channel, and the reference count is down
	 * to 0, decrement the number of channels which still need to be
	 * removed on the device.
	 */
	if ((*channel)->ch_removing && ((*channel)->ch_ref_cnt == 0)) {
		device = (*channel)->ch_device;
		mutex_enter(&device->dc_devchan_list.dl_mutex);
		device->dc_removing_cnt--;
		if (device->dc_removing_cnt == 0) {
			cleanup = B_TRUE;
		}
		mutex_exit(&device->dc_devchan_list.dl_mutex);
	}
	mutex_exit(&list->dl_mutex);

	/*
	 * if there are no channels which still need to be removed, cleanup the
	 * device state and call back into the DMA device driver to tell them
	 * the device is free.
	 */
	if (cleanup) {
		dcopy_device_cleanup(device, B_TRUE);
	}

	*channel = NULL;
}


/*
 * dcopy_query_channel()
 */
void
dcopy_query_channel(dcopy_handle_t channel, dcopy_query_channel_t *query)
{
	*query = channel->ch_info;
}


/*
 * dcopy_cmd_alloc()
 */
int
dcopy_cmd_alloc(dcopy_handle_t handle, int flags, dcopy_cmd_t *cmd)
{
	dcopy_handle_t channel;
	dcopy_cmd_priv_t priv;
	int e;


	channel = handle;

	atomic_inc_64(&channel->ch_stat.cs_cmd_alloc.value.ui64);
	e = channel->ch_cb->cb_cmd_alloc(channel->ch_channel_private, flags,
	    cmd);
	if (e == DCOPY_SUCCESS) {
		priv = (*cmd)->dp_private;
		priv->pr_channel = channel;
		/*
		 * we won't initialize the blocking state until we actually
		 * need to block.
		 */
		priv->pr_block_init = B_FALSE;
	}

	return (e);
}


/*
 * dcopy_cmd_free()
 */
void
dcopy_cmd_free(dcopy_cmd_t *cmd)
{
	dcopy_handle_t channel;
	dcopy_cmd_priv_t priv;


	ASSERT(*cmd != NULL);

	priv = (*cmd)->dp_private;
	channel = priv->pr_channel;

	/* if we initialized the blocking state, clean it up too */
	if (priv->pr_block_init) {
		cv_destroy(&priv->pr_cv);
		mutex_destroy(&priv->pr_mutex);
	}

	channel->ch_cb->cb_cmd_free(channel->ch_channel_private, cmd);
}


/*
 * dcopy_cmd_post()
 */
int
dcopy_cmd_post(dcopy_cmd_t cmd)
{
	dcopy_handle_t channel;
	int e;


	channel = cmd->dp_private->pr_channel;

	atomic_inc_64(&channel->ch_stat.cs_cmd_post.value.ui64);
	if (cmd->dp_cmd == DCOPY_CMD_COPY) {
		atomic_add_64(&channel->ch_stat.cs_bytes_xfer.value.ui64,
		    cmd->dp.copy.cc_size);
	}
	e = channel->ch_cb->cb_cmd_post(channel->ch_channel_private, cmd);
	if (e != DCOPY_SUCCESS) {
		return (e);
	}

	return (DCOPY_SUCCESS);
}


/*
 * dcopy_cmd_poll()
 */
int
dcopy_cmd_poll(dcopy_cmd_t cmd, int flags)
{
	dcopy_handle_t channel;
	dcopy_cmd_priv_t priv;
	int e;


	priv = cmd->dp_private;
	channel = priv->pr_channel;

	/*
	 * if the caller is trying to block, they needed to post the
	 * command with DCOPY_CMD_INTR set.
	 */
	if ((flags & DCOPY_POLL_BLOCK) && !(cmd->dp_flags & DCOPY_CMD_INTR)) {
		return (DCOPY_FAILURE);
	}

	atomic_inc_64(&channel->ch_stat.cs_cmd_poll.value.ui64);

repoll:
	e = channel->ch_cb->cb_cmd_poll(channel->ch_channel_private, cmd);
	if (e == DCOPY_PENDING) {
		/*
		 * if the command is still active, and the blocking flag
		 * is set.
		 */
		if (flags & DCOPY_POLL_BLOCK) {

			/*
			 * if we haven't initialized the state, do it now. A
			 * command can be re-used, so it's possible it's
			 * already been initialized.
			 */
			if (!priv->pr_block_init) {
				priv->pr_block_init = B_TRUE;
				mutex_init(&priv->pr_mutex, NULL, MUTEX_DRIVER,
				    NULL);
				cv_init(&priv->pr_cv, NULL, CV_DRIVER, NULL);
				priv->pr_cmd = cmd;
			}

			/* push it on the list for blocking commands */
			priv->pr_wait = B_TRUE;
			dcopy_list_push(&channel->ch_poll_list, priv);

			mutex_enter(&priv->pr_mutex);
			/*
			 * it's possible we already cleared pr_wait before we
			 * grabbed the mutex.
			 */
			if (priv->pr_wait) {
				cv_wait(&priv->pr_cv, &priv->pr_mutex);
			}
			mutex_exit(&priv->pr_mutex);

			/*
			 * the command has completed, go back and poll so we
			 * get the status.
			 */
			goto repoll;
		}
	}

	return (e);
}

/* *** END OF EXTERNAL INTERFACE *** */

/*
 * dcopy_list_init()
 */
static int
dcopy_list_init(dcopy_list_t *list, size_t node_size, offset_t link_offset)
{
	mutex_init(&list->dl_mutex, NULL, MUTEX_DRIVER, NULL);
	list_create(&list->dl_list, node_size, link_offset);
	list->dl_cnt = 0;

	return (DCOPY_SUCCESS);
}


/*
 * dcopy_list_fini()
 */
static void
dcopy_list_fini(dcopy_list_t *list)
{
	list_destroy(&list->dl_list);
	mutex_destroy(&list->dl_mutex);
}


/*
 * dcopy_list_push()
 */
static void
dcopy_list_push(dcopy_list_t *list, void *list_node)
{
	mutex_enter(&list->dl_mutex);
	list_insert_tail(&list->dl_list, list_node);
	list->dl_cnt++;
	mutex_exit(&list->dl_mutex);
}


/*
 * dcopy_list_pop()
 */
static void *
dcopy_list_pop(dcopy_list_t *list)
{
	list_node_t *list_node;

	mutex_enter(&list->dl_mutex);
	list_node = list_head(&list->dl_list);
	if (list_node == NULL) {
		mutex_exit(&list->dl_mutex);
		return (list_node);
	}
	list->dl_cnt--;
	list_remove(&list->dl_list, list_node);
	mutex_exit(&list->dl_mutex);

	return (list_node);
}


/* *** DEVICE INTERFACE *** */
/*
 * dcopy_device_register()
 */
int
dcopy_device_register(void *device_private, dcopy_device_info_t *info,
    dcopy_device_handle_t *handle)
{
	struct dcopy_channel_s *channel;
	struct dcopy_device_s *device;
	int e;
	int i;


	/* initialize the per device state */
	device = kmem_zalloc(sizeof (*device), KM_SLEEP);
	device->dc_device_private = device_private;
	device->dc_info = *info;
	device->dc_removing_cnt = 0;
	device->dc_cb = info->di_cb;

	/*
	 * we have a per device channel list so we can remove a device in the
	 * future.
	 */
	e = dcopy_list_init(&device->dc_devchan_list,
	    sizeof (struct dcopy_channel_s),
	    offsetof(struct dcopy_channel_s, ch_devchan_list_node));
	if (e != DCOPY_SUCCESS) {
		goto registerfail_devchan;
	}

	/*
	 * allocate state for each channel, allocate the channel,  and then add
	 * the devices dma channels to the devices channel list.
	 */
	for (i = 0; i < info->di_num_dma; i++) {
		channel = kmem_zalloc(sizeof (*channel), KM_SLEEP);
		channel->ch_device = device;
		channel->ch_removing = B_FALSE;
		channel->ch_ref_cnt = 0;
		channel->ch_cb = info->di_cb;

		e = info->di_cb->cb_channel_alloc(device_private, channel,
		    DCOPY_SLEEP, dcopy_channel_size, &channel->ch_info,
		    &channel->ch_channel_private);
		if (e != DCOPY_SUCCESS) {
			kmem_free(channel, sizeof (*channel));
			goto registerfail_alloc;
		}

		e = dcopy_stats_init(channel);
		if (e != DCOPY_SUCCESS) {
			info->di_cb->cb_channel_free(
			    &channel->ch_channel_private);
			kmem_free(channel, sizeof (*channel));
			goto registerfail_alloc;
		}

		e = dcopy_list_init(&channel->ch_poll_list,
		    sizeof (struct dcopy_cmd_priv_s),
		    offsetof(struct dcopy_cmd_priv_s, pr_poll_list_node));
		if (e != DCOPY_SUCCESS) {
			dcopy_stats_fini(channel);
			info->di_cb->cb_channel_free(
			    &channel->ch_channel_private);
			kmem_free(channel, sizeof (*channel));
			goto registerfail_alloc;
		}

		dcopy_list_push(&device->dc_devchan_list, channel);
	}

	/* add the device to device list */
	dcopy_list_push(&dcopy_statep->d_device_list, device);

	/*
	 * add the device's dma channels to the global channel list (where
	 * dcopy_alloc's come from)
	 */
	mutex_enter(&dcopy_statep->d_globalchan_list.dl_mutex);
	mutex_enter(&dcopy_statep->d_device_list.dl_mutex);
	channel = list_head(&device->dc_devchan_list.dl_list);
	while (channel != NULL) {
		list_insert_tail(&dcopy_statep->d_globalchan_list.dl_list,
		    channel);
		dcopy_statep->d_globalchan_list.dl_cnt++;
		channel = list_next(&device->dc_devchan_list.dl_list, channel);
	}
	mutex_exit(&dcopy_statep->d_device_list.dl_mutex);
	mutex_exit(&dcopy_statep->d_globalchan_list.dl_mutex);

	*handle = device;

	/* last call-back into kernel for dcopy KAPI enabled */
	uioa_dcopy_enable();

	return (DCOPY_SUCCESS);

registerfail_alloc:
	channel = list_head(&device->dc_devchan_list.dl_list);
	while (channel != NULL) {
		/* remove from the list */
		channel = dcopy_list_pop(&device->dc_devchan_list);
		ASSERT(channel != NULL);

		dcopy_list_fini(&channel->ch_poll_list);
		dcopy_stats_fini(channel);
		info->di_cb->cb_channel_free(&channel->ch_channel_private);
		kmem_free(channel, sizeof (*channel));
	}

	dcopy_list_fini(&device->dc_devchan_list);
registerfail_devchan:
	kmem_free(device, sizeof (*device));

	return (DCOPY_FAILURE);
}


/*
 * dcopy_device_unregister()
 */
/*ARGSUSED*/
int
dcopy_device_unregister(dcopy_device_handle_t *handle)
{
	struct dcopy_channel_s *channel;
	dcopy_device_handle_t device;
	boolean_t device_busy;

	/* first call-back into kernel for dcopy KAPI disable */
	uioa_dcopy_disable();

	device = *handle;
	device_busy = B_FALSE;

	/*
	 * remove the devices dma channels from the global channel list (where
	 * dcopy_alloc's come from)
	 */
	mutex_enter(&dcopy_statep->d_globalchan_list.dl_mutex);
	mutex_enter(&device->dc_devchan_list.dl_mutex);
	channel = list_head(&device->dc_devchan_list.dl_list);
	while (channel != NULL) {
		/*
		 * if the channel has outstanding allocs, mark it as having
		 * to be removed and increment the number of channels which
		 * need to be removed in the device state too.
		 */
		if (channel->ch_ref_cnt != 0) {
			channel->ch_removing = B_TRUE;
			device_busy = B_TRUE;
			device->dc_removing_cnt++;
		}
		dcopy_statep->d_globalchan_list.dl_cnt--;
		list_remove(&dcopy_statep->d_globalchan_list.dl_list, channel);
		channel = list_next(&device->dc_devchan_list.dl_list, channel);
	}
	mutex_exit(&device->dc_devchan_list.dl_mutex);
	mutex_exit(&dcopy_statep->d_globalchan_list.dl_mutex);

	/*
	 * if there are channels which still need to be removed, we will clean
	 * up the device state after they are freed up.
	 */
	if (device_busy) {
		return (DCOPY_PENDING);
	}

	dcopy_device_cleanup(device, B_FALSE);

	*handle = NULL;
	return (DCOPY_SUCCESS);
}


/*
 * dcopy_device_cleanup()
 */
static void
dcopy_device_cleanup(dcopy_device_handle_t device, boolean_t do_callback)
{
	struct dcopy_channel_s *channel;

	/*
	 * remove all the channels in the device list, free them, and clean up
	 * the state.
	 */
	mutex_enter(&dcopy_statep->d_device_list.dl_mutex);
	channel = list_head(&device->dc_devchan_list.dl_list);
	while (channel != NULL) {
		device->dc_devchan_list.dl_cnt--;
		list_remove(&device->dc_devchan_list.dl_list, channel);
		dcopy_list_fini(&channel->ch_poll_list);
		dcopy_stats_fini(channel);
		channel->ch_cb->cb_channel_free(&channel->ch_channel_private);
		kmem_free(channel, sizeof (*channel));
		channel = list_head(&device->dc_devchan_list.dl_list);
	}

	/* remove it from the list of devices */
	list_remove(&dcopy_statep->d_device_list.dl_list, device);

	mutex_exit(&dcopy_statep->d_device_list.dl_mutex);

	/*
	 * notify the DMA device driver that the device is free to be
	 * detached.
	 */
	if (do_callback) {
		device->dc_cb->cb_unregister_complete(
		    device->dc_device_private, DCOPY_SUCCESS);
	}

	dcopy_list_fini(&device->dc_devchan_list);
	kmem_free(device, sizeof (*device));
}


/*
 * dcopy_device_channel_notify()
 */
/*ARGSUSED*/
void
dcopy_device_channel_notify(dcopy_handle_t handle, int status)
{
	struct dcopy_channel_s *channel;
	dcopy_list_t *poll_list;
	dcopy_cmd_priv_t priv;
	int e;


	ASSERT(status == DCOPY_COMPLETION);
	channel = handle;

	poll_list = &channel->ch_poll_list;

	/*
	 * when we get a completion notification from the device, go through
	 * all of the commands blocking on this channel and see if they have
	 * completed. Remove the command and wake up the block thread if they
	 * have. Once we hit a command which is still pending, we are done
	 * polling since commands in a channel complete in order.
	 */
	mutex_enter(&poll_list->dl_mutex);
	if (poll_list->dl_cnt != 0) {
		priv = list_head(&poll_list->dl_list);
		while (priv != NULL) {
			atomic_inc_64(&channel->
			    ch_stat.cs_notify_poll.value.ui64);
			e = channel->ch_cb->cb_cmd_poll(
			    channel->ch_channel_private,
			    priv->pr_cmd);
			if (e == DCOPY_PENDING) {
				atomic_inc_64(&channel->
				    ch_stat.cs_notify_pending.value.ui64);
				break;
			}

			poll_list->dl_cnt--;
			list_remove(&poll_list->dl_list, priv);

			mutex_enter(&priv->pr_mutex);
			priv->pr_wait = B_FALSE;
			cv_signal(&priv->pr_cv);
			mutex_exit(&priv->pr_mutex);

			priv = list_head(&poll_list->dl_list);
		}
	}

	mutex_exit(&poll_list->dl_mutex);
}


/*
 * dcopy_stats_init()
 */
static int
dcopy_stats_init(dcopy_handle_t channel)
{
#define	CHANSTRSIZE	20
	char chanstr[CHANSTRSIZE];
	dcopy_stats_t *stats;
	int instance;
	char *name;


	stats = &channel->ch_stat;
	name = (char *)ddi_driver_name(channel->ch_device->dc_info.di_dip);
	instance = ddi_get_instance(channel->ch_device->dc_info.di_dip);

	(void) snprintf(chanstr, CHANSTRSIZE, "channel%d",
	    (uint32_t)channel->ch_info.qc_chan_num);

	channel->ch_kstat = kstat_create(name, instance, chanstr, "misc",
	    KSTAT_TYPE_NAMED, sizeof (dcopy_stats_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (channel->ch_kstat == NULL) {
		return (DCOPY_FAILURE);
	}
	channel->ch_kstat->ks_data = stats;

	kstat_named_init(&stats->cs_bytes_xfer, "bytes_xfer",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->cs_cmd_alloc, "cmd_alloc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->cs_cmd_post, "cmd_post",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->cs_cmd_poll, "cmd_poll",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->cs_notify_poll, "notify_poll",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->cs_notify_pending, "notify_pending",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->cs_id, "id",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->cs_capabilities, "capabilities",
	    KSTAT_DATA_UINT64);

	kstat_install(channel->ch_kstat);

	channel->ch_stat.cs_id.value.ui64 = channel->ch_info.qc_id;
	channel->ch_stat.cs_capabilities.value.ui64 =
	    channel->ch_info.qc_capabilities;

	return (DCOPY_SUCCESS);
}


/*
 * dcopy_stats_fini()
 */
static void
dcopy_stats_fini(dcopy_handle_t channel)
{
	kstat_delete(channel->ch_kstat);
}
/* *** END OF DEVICE INTERFACE *** */
