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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <aio.h>
#include <sys/aio.h>
#include <sys/asynch.h>
#include <stddef.h>
#include <strings.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/avl.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ucontext.h>

#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/generic/inquiry.h>

#include "target.h"
#include "queue.h"
#include "t10.h"
#include "t10_spc.h"
#include "utility.h"

/*
 * []------------------------------------------------------------------[]
 * | This file contains methods which isolate a transport from device   |
 * | emulation. The first part of the file contains method which are	|
 * | called by the transport to start commands or deliver data. The	|
 * | transport does not know anything about what emulation is being	|
 * | done. The emulation layer receieves cdb's and nows nothing about	|
 * | the transport. This is how it should be. There are a few special	|
 * | cases to deal with transports which have a notion of immediate	|
 * | data, but we're isolating that from the emulation layer.		|
 * []------------------------------------------------------------------[]
 */

/*
 * Forward declarations
 */
static Boolean_t t10_find_lun(t10_targ_impl_t *t, int lun, t10_cmd_t *);
static void *lu_runner(void *v);
static Boolean_t t10_lu_initialize(t10_lu_common_t *lu, char *basedir);
static void *t10_aio_done(void *v);
static Boolean_t lu_remove_cmds(msg_t *m, void *v);
static void cmd_common_free(t10_lu_impl_t *lu, t10_cmd_t *cmd);
static Boolean_t load_params(t10_lu_common_t *lu, char *basedir);
static Boolean_t fallocate(int fd, off64_t len);
/* ---- These are AVL comparison routines ---- */
static int find_lu_by_num(const void *v1, const void *v2);
static int find_lu_by_guid(const void *v1, const void *v2);
static int find_lu_by_targ(const void *v1, const void *v2);
static int find_cmd_by_addr(const void *v1, const void *v2);

/*
 * Global variables
 */
static avl_tree_t	lu_list;
static pthread_mutex_t	lu_list_mutex;
static int		lu_id;
target_queue_t		*mgmtq;
static pthread_mutex_t	t10_mutex;
static int		t10_num;
static sema_t		t10_sema;

/*
 * []----
 * | t10_init -- called once at the beginning of time to initialize globals
 * []----
 */
void
t10_init(target_queue_t *q)
{
	pthread_t	junk;

	mgmtq = q;
	(void) pthread_mutex_init(&lu_list_mutex, NULL);
	(void) pthread_mutex_init(&t10_mutex, NULL);
	(void) sema_init(&t10_sema, 0, USYNC_THREAD, NULL);
	avl_create(&lu_list, find_lu_by_guid, sizeof (t10_lu_common_t),
	    offsetof(t10_lu_common_t, l_all_luns));
	(void) pthread_create(&junk, NULL, t10_aio_done, NULL);
}

/*ARGSUSED*/
static void *
t10_aio_done(void *v)
{
	aio_result_t	*result;
	t10_aio_t	*a;

	do {
		if (sema_wait(&t10_sema) != 0) {
			queue_prt(mgmtq, Q_STE_ERRS,
			    "SAM-  same_wait returned error");
			continue;
		}

		if ((result = aiowait(NULL)) == (aio_result_t *)-1) {
			if (errno == EINVAL) {
				queue_prt(mgmtq, Q_STE_ERRS,
				    "SAM-  aiowait returned EINVAL");
				/*
				 * It's possible for aiowait to return
				 * prematurely. So, post another semaphore,
				 * sleep for a second, and try the wait
				 * again.
				 */
				(void) sema_post(&t10_sema);
				(void) sleep(1);
				continue;
			} else
				break;
		} else {
			a = (t10_aio_t *)result;
		}
		if ((a != NULL) && (a->a_aio_cmplt != NULL)) {
			(*a->a_aio_cmplt)(a->a_id);
		} else {
			queue_prt(mgmtq, Q_STE_ERRS,
			    "SAM   aiowait returned results, but is NULL");
		}
	/*CONSTANTCONDITION*/
	} while (1);

	return (NULL);
}

/*
 * []------------------------------------------------------------------[]
 * | Methods called by transports to interface with SAM-3		|
 * []------------------------------------------------------------------[]
 */

/*
 * []----
 * | t10_handle_create -- Create the I_T nexus
 * |
 * | NOTES:
 * | max_out can be set to 0 if the transport wishes to wait for all of
 * | the data before receiving a DATAOUT message. Fibre Channel will most
 * | likely set this to 0, whereas iSCSI will set max_out to the value
 * | of MaxRecvDataSegment.
 * | (*datain_cb)() is called, on the LU thread, when the emulation
 * | module needs data *and* t10_send_cmd was called with opt_data_len, but
 * | no opt_data.
 * []----
 */
t10_targ_handle_t
t10_handle_create(char *targ, int trans_version, int tpg, int max_out,
    target_queue_t *tq, void (*datain_cb)(t10_cmd_t *, char *, size_t *))
{
	t10_targ_impl_t	*t = calloc(1, sizeof (t10_targ_impl_t));

	if (t == NULL)
		return (NULL);

	(void) pthread_mutex_lock(&t10_mutex);
	t->s_targ_num		= t10_num++;
	(void) pthread_mutex_unlock(&t10_mutex);
	t->s_targ_base		= strdup(targ);
	t->s_trans_vers		= trans_version;
	t->s_maxout		= max_out;
	t->s_to_transport	= tq;
	t->s_dataout_cb		= datain_cb;

	/*
	 * Once we actually support two or more transports it would be
	 * possible for a collision between the underlying transports
	 * target port group values since one wouldn't necessarily know
	 * anything about the other. We'll use the upper bits of the
	 * target port group value to separate them.
	 * If we were to support many transports and with one then running
	 * out of bit space we'd need to change the allocation method. Since
	 * these values aren't stored anywhere and just used by initiators
	 * to determine relative path numbering there's no issue with changing
	 * this later if need be.
	 */
	switch (trans_version) {
	case T10_TRANS_ISCSI:
		t->s_tp_grp	= 0x0000 | tpg;
		break;

	case T10_TRANS_FC:
		t->s_tp_grp	= 0x8000 | tpg;
		break;
	}

	avl_create(&t->s_open_lu, find_lu_by_num, sizeof (t10_lu_impl_t),
	    offsetof(t10_lu_impl_t, l_open_targ_node));

	(void) pthread_mutex_init(&t->s_mutex, NULL);
	return ((t10_targ_handle_t)t);
}

void
t10_handle_disable(t10_targ_handle_t tp)
{
	t10_targ_impl_t	*t		= (t10_targ_impl_t *)tp;
	t10_lu_impl_t	*l;
	t10_shutdown_t	s;
	int		lu_per_targ	= 0;

	(void) pthread_mutex_lock(&t->s_mutex);
	if (avl_numnodes(&t->s_open_lu) != 0) {

		s.t_q = queue_alloc();
		l = avl_first(&t->s_open_lu);
		while (l != NULL) {

			s.t_lu = l;
			queue_message_set(l->l_common->l_from_transports, 0,
			    msg_shutdown, (void *)&s);
			queue_message_free(queue_message_get(s.t_q));
			lu_per_targ++;
			l = AVL_NEXT(&t->s_open_lu, l);
		}
		queue_prt(mgmtq, Q_STE_NONIO,
		    "SAM%x  Sent %d shutdown requests for %s",
		    t->s_targ_num, lu_per_targ, t->s_targ_base);
		queue_free(s.t_q, NULL);
	}
	(void) pthread_mutex_unlock(&t->s_mutex);
}

void
t10_handle_destroy(t10_targ_handle_t tp)
{
	t10_targ_impl_t	*t		= (t10_targ_impl_t *)tp;
	t10_lu_impl_t	*l;
	t10_cmd_t	*c,
			*c2free;
	int		fast_free	= 0;

	(void) pthread_mutex_lock(&t->s_mutex);
	if (avl_numnodes(&t->s_open_lu) != 0) {
		while ((l = avl_first(&t->s_open_lu)) != NULL) {
			avl_remove(&t->s_open_lu, l);

			(void) pthread_mutex_lock(&l->l_cmd_mutex);
			if (avl_numnodes(&l->l_cmds) != 0) {
				c = avl_first(&l->l_cmds);
				while (c != NULL) {
					if (c->c_state ==
					    T10_Cmd_DataOut_Sent) {
						c2free = c;
						c = AVL_NEXT(&l->l_cmds, c);
						fast_free++;
						cmd_common_free(l, c2free);
						free(c2free);
					} else if (c->c_state ==
					    T10_Cmd_Canceled) {
						c2free = c;
						c = AVL_NEXT(&l->l_cmds, c);
						cmd_common_free(l, c2free);
						fast_free++;
					} else {
						queue_prt(mgmtq, Q_STE_NONIO,
						    "SAM%x  cmd->c_state %d, "
						    "trans_id 0x%x",
						    t->s_targ_num,
						    c->c_state,
						    c->c_trans_id);
						c = AVL_NEXT(&l->l_cmds, c);
					}
				}
				queue_prt(mgmtq, Q_STE_NONIO,
				    "SAM%x  FastFree %d ... "
				    "Waiting for %d cmds to drain",
				    t->s_targ_num, fast_free,
				    avl_numnodes(&l->l_cmds));
				if (avl_numnodes(&l->l_cmds) != 0) {
					l->l_wait_for_drain = True;
					while (l->l_wait_for_drain == True) {
						(void) pthread_cond_wait(
						    &l->l_cmd_cond,
						    &l->l_cmd_mutex);
					}
				}
			}
			(void) pthread_mutex_unlock(&l->l_cmd_mutex);
			avl_destroy(&l->l_cmds);
			free(l);
		}
	}
	avl_destroy(&t->s_open_lu);
	(void) pthread_mutex_unlock(&t->s_mutex);

	free(t->s_targ_base);
	free(t);
}

/*
 * []----
 * | t10_cmd_create -- creates a command pointer
 * |
 * | If an error occurs, a sense condition buffer will be created that can
 * | be sent back to the initiator. The only time this should occur is during
 * | LU setup and we've run out of resources like not having enough file
 * | descriptors to open the backing store. If the cmdp is NULL, then there's
 * | not even enough memory to create a command buffer and the transport
 * | should shutdown it's connection a cleanly as possible.
 * []----
 */
Boolean_t
t10_cmd_create(t10_targ_handle_t t, int lun_number, uint8_t *cdb,
    size_t cdb_len, transport_t trans_id, t10_cmd_t **cmdp)
{
	t10_cmd_t	*cmd	= NULL;

	*cmdp = NULL;
	if (t == NULL)
		goto error;

	if ((cmd = (t10_cmd_t *)calloc(1, sizeof (t10_cmd_t))) == NULL)
		goto error;

	if ((cmd->c_cdb = (uint8_t *)malloc(cdb_len)) == NULL)
		goto error;

	cmd->c_trans_id	= trans_id;
	*cmdp		= cmd;
	if (t10_find_lun((t10_targ_impl_t *)t, lun_number, cmd) == False)
		goto error;

	(void) pthread_mutex_lock(&cmd->c_lu->l_cmd_mutex);
	avl_add(&cmd->c_lu->l_cmds, (void *)cmd);
	cmd->c_state	= T10_Cmd_Alloc;
	(void) pthread_mutex_unlock(&cmd->c_lu->l_cmd_mutex);
	bcopy(cdb, cmd->c_cdb, cdb_len);
	cmd->c_cdb_len	= cdb_len;

	return (True);

error:
	cmd->c_state = T10_Cmd_Errored;
	if (cmd->c_cdb) {
		free(cmd->c_cdb);
		cmd->c_cdb = NULL;
	}

	/*
	 * If we haven't set up the argument pointer, then free the memory
	 * that had been allocated to the command.
	 */
	if (*cmdp == NULL)
		free(cmd);
	return (False);
}

/*
 * []----
 * | t10_send_cmd -- send the give command to appropriate LUN emulation
 * |
 * | NOTE: emul_id is only provided for DATA_OUT commands (write ops)
 * | which have multiple phases to complete the request. The emulation
 * | module will provide this value when it requests more data to be
 * | sent.
 * []----
 */
/*ARGSUSED*/
Boolean_t
t10_cmd_send(t10_targ_handle_t t, t10_cmd_t *cmd, char *opt_data,
    size_t opt_data_len)
{
	if (cmd == NULL)
		return (False);

	cmd->c_data	= opt_data;
	cmd->c_data_len	= opt_data_len;

	queue_message_set(cmd->c_lu->l_common->l_from_transports, 0,
	    msg_cmd_send, (void *)cmd);

	return (True);
}

/*ARGSUSED*/
Boolean_t
t10_cmd_data(t10_targ_handle_t t, t10_cmd_t *cmd, size_t offset, char *data,
    size_t data_len)
{
	cmd->c_data	= data;
	cmd->c_data_len	= data_len;
	cmd->c_offset	= offset;

	queue_message_set(cmd->c_lu->l_common->l_from_transports, 0,
	    msg_cmd_data_out, (void *)cmd);

	return (True);
}

void
t10_cmd_state(t10_cmd_t *c, t10_cmd_event_t e)
{
	t10_lu_impl_t	*lu = c->c_lu;

	if (c->c_state == T10_Cmd_Errored) {
		free(c);
		return;
	}
	(void) pthread_mutex_lock(&lu->l_cmd_mutex);
	switch (e) {
	case T10_Cmd_Event_DataOut_Sent:
		switch (c->c_state) {
		case T10_Cmd_DataOut:
			c->c_state = T10_Cmd_DataOut_Sent;
			break;

		default:
			assert(0);
		}
		break;

	case T10_Cmd_Event_DataIn_Recv:
		switch (c->c_state) {
		case T10_Cmd_DataOut_Sent:
			c->c_state = T10_Cmd_DataOut;
			break;

		default:
			assert(0);
		}
		break;

	case T10_Cmd_Event_Canceled:
		switch (c->c_state) {
		case T10_Cmd_Free:
			assert(0);

		default:
			c->c_state = T10_Cmd_Canceled;
			break;
		}
		break;

	case T10_Cmd_Event_Release:
		cmd_common_free(lu, c);
		free(c);
		if ((lu->l_wait_for_drain == True) &&
		    (avl_numnodes(&lu->l_cmds) == 0)) {
			lu->l_wait_for_drain = False;
			(void) pthread_cond_signal(&lu->l_cmd_cond);
		}
		break;

	default:
		assert(0);
	}
	(void) pthread_mutex_unlock(&lu->l_cmd_mutex);
}

/*
 * []----
 * | t10_task_mgmt -- handle SAM-3 task management needs
 * []----
 */
/*ARGSUSED*/
Boolean_t
t10_task_mgmt(t10_targ_handle_t t1, TaskOp_t op, int opt_lun, void *tag)
{
	t10_targ_impl_t	*t = (t10_targ_impl_t *)t1;
	t10_lu_impl_t	search,
			*lu;

	switch (op) {
	case InventoryChange:
		if ((lu = avl_first(&t->s_open_lu)) != NULL) {
			do {
				/*CSTYLED*/
				queue_message_set(lu->l_common->l_from_transports,
				    0, msg_targ_inventory_change, (void *)lu);
			} while ((lu = AVL_NEXT(&t->s_open_lu, lu)) != NULL);
		}
		return (True);

	case ResetTarget:
		if ((lu = avl_first(&t->s_open_lu)) != NULL) {
			do {
				/*CSTYLED*/
				queue_message_set(lu->l_common->l_from_transports,
				    Q_HIGH, msg_reset_lu, (void *)lu);
			} while ((lu = AVL_NEXT(&t->s_open_lu, lu)) != NULL);
			return (True);
		} else
			return (False);

	case ResetLun:
		search.l_targ_lun = opt_lun;
		if ((lu = avl_find(&t->s_open_lu, (void *)&search, NULL)) !=
		    NULL) {
			queue_message_set(lu->l_common->l_from_transports,
			    Q_HIGH, msg_reset_lu, (void *)lu);
			return (True);
		} else
			return (False);
		break;

	case CapacityChange:
		search.l_targ_lun = opt_lun;
		if ((lu = avl_find(&t->s_open_lu, (void *)&search, NULL)) !=
		    NULL) {
			queue_message_set(lu->l_common->l_from_transports,
			    Q_HIGH, msg_lu_capacity_change,
			    (void *)(uintptr_t)opt_lun);
			return (True);
		} else
			return (False);
		break;

	default:
		return (False);
	}
}


/*
 * []----
 * | t10_targ_stat -- Return stats on each LU associated with target.
 * []----
 */
void
t10_targ_stat(t10_targ_handle_t t1, char **buf)
{
	t10_targ_impl_t	*t = (t10_targ_impl_t *)t1;
	t10_lu_impl_t	*itl;
	char		lb[32],
			*p;

	/*
	 * It's possible for the management interfaces to request stats
	 * even though a connection is not up and running.
	 */
	if (t == NULL)
		return;

	itl = avl_first(&t->s_open_lu);
	while (itl) {
		buf_add_tag(buf, XML_ELEMENT_LUN, Tag_Start);
		(void) snprintf(lb, sizeof (lb), "%d", itl->l_common->l_num);
		buf_add_tag(buf, lb, Tag_String);

		(void) snprintf(lb, sizeof (lb), "%lld", itl->l_cmds_read);
		xml_add_tag(buf, XML_ELEMENT_READCMDS, lb);
		(void) snprintf(lb, sizeof (lb), "%lld", itl->l_cmds_write);
		xml_add_tag(buf, XML_ELEMENT_WRITECMDS, lb);
		(void) snprintf(lb, sizeof (lb), "%lld", itl->l_sects_read);
		xml_add_tag(buf, XML_ELEMENT_READBLKS, lb);
		(void) snprintf(lb, sizeof (lb), "%lld", itl->l_sects_write);
		xml_add_tag(buf, XML_ELEMENT_WRITEBLKS, lb);

		switch (itl->l_common->l_state) {
		case lu_online:
			p = TGT_STATUS_ONLINE;
			break;
		case lu_offline:
			p = TGT_STATUS_OFFLINE;
			break;
		case lu_errored:
			p = TGT_STATUS_ERRORED;
			break;
		}
		xml_add_tag(buf, XML_ELEMENT_STATUS, p);

		buf_add_tag(buf, XML_ELEMENT_LUN, Tag_End);
		itl = AVL_NEXT(&t->s_open_lu, itl);
	}
}

/*
 * []----
 * | t10_thick_provision -- fill the backing store with real blocks
 * |
 * | The backing store is initially created as a hole-y file. The only
 * | thing wrong with leaving the files hole-y is that if a system
 * | administrator over provisions the storage at some point a client
 * | will attempt to write to a block and receive an error unless the
 * | administrator adds more backing store before that event. Now, depending
 * | on the client a write error isn't fatal. However, for file systems
 * | like UFS and ZFS, they can not currently deal with getting a write
 * | error when it's their metadata and panic. That's not good. The concept
 * | of "Thin Provisioning" is relatively new so we'll normally preallocate
 * | the space, but have the option of doing the "Thin Provisioning".
 * []----
 */
Boolean_t
t10_thick_provision(char *target, int lun, target_queue_t *q)
{
	t10_targ_handle_t	t;
	t10_cmd_t		*cmd		= NULL;
	uint8_t			cdb[16];	/* ---- fake buffer ---- */
	diskaddr_t		offset		= 0;
	size_t			size,
				sync_size;
	msg_t			*m		= NULL;
	target_queue_t		*rq		= NULL;
	char			path[MAXPATHLEN];
	xml_node_t		*n1;
	Boolean_t		rval		= False;
	struct statvfs		fs;

	/*
	 * To guarantee that everything has been setup correctly
	 * we'll just use the standard interfaces. Otherwise we'd need
	 * to duplicate the code and therefore offer the chance of
	 * having something fixed/change in one location that isn't
	 * in another. Obvious right?
	 */
	if ((t = t10_handle_create(target, 0, 0, 0, q, NULL)) == NULL) {
		queue_prt(mgmtq, Q_STE_ERRS, "STE%x  Failed to create handle",
		    lun);
		return (False);
	}
	if (t10_cmd_create(t, lun, cdb, sizeof (cdb), 0, &cmd) == False) {
		queue_prt(mgmtq, Q_STE_ERRS, "STE%x  Failed to create cmd",
		    lun);
		goto error;
	}

	/*
	 * Attempt to see if there is enough space currently for the LU.
	 * The initialization might still fail with out of space because someone
	 * else is consuming space while the initialization is occuring.
	 * Nothing we can do about that.
	 */
	if (fstatvfs(cmd->c_lu->l_common->l_fd, &fs) != 0) {
		queue_prt(mgmtq, Q_STE_ERRS, "STE%x  statvfs failed for LU",
		    lun);
		goto error;
	} else if ((fs.f_frsize * fs.f_bfree) < cmd->c_lu->l_common->l_size) {
		queue_prt(mgmtq, Q_STE_ERRS, "STE%x  Not enough space for LU",
		    lun);
		goto error;
	}

	if (fallocate(cmd->c_lu->l_common->l_fd, cmd->c_lu->l_common->l_size) ==
	    False) {
		/*
		 * The lu_runner will use this buffer to copy data.
		 */
		sync_size = 1024 * 1024;
		if ((cmd->c_data = malloc(sync_size)) == NULL)
			goto error;

		while ((offset < cmd->c_lu->l_common->l_size) && (rq == NULL)) {
			size = min(cmd->c_lu->l_common->l_size - offset,
			    sync_size);
			cmd->c_offset	= offset;
			cmd->c_data_len	= size;
			/*CSTYLED*/
			queue_message_set(cmd->c_lu->l_common->l_from_transports, 0,
			    msg_thick_provo, (void *)cmd);
			while ((m = queue_message_get(q)) != NULL) {
				switch (m->msg_type) {
				case msg_thick_provo:
					if ((int)(intptr_t)m->msg_data != 0) {

						/*
						 * An error occurred during
						 * initialization which mean we
						 * need to remove this target.
						 */
						queue_prt(mgmtq, Q_STE_ERRS,
						    "STE%x  received data "
						    "error at 0x%llx", lun,
						    offset);
						goto error;
					}
					break;

				case msg_shutdown:
					queue_prt(mgmtq, Q_STE_NONIO,
					    "---- Thick provo got shutdown");
					rq = (target_queue_t *)m->msg_data;
					queue_message_free(m);
					continue; /* don't use break */

				default:
					assert(0);
				}
				break;
			}
			queue_message_free(m);
			offset		+= size;
		}
	} else {
		queue_prt(mgmtq, Q_STE_NONIO, "STE%x  fallocate worked", lun);
	}

	/*
	 * A forced shutdown is still considered a successful completion.
	 * Write errors and malloc failures constitute a failure.
	 */
	rval = True;

	/* ---- Completed successfully ---- */
	if (rq == NULL) {

		/*
		 * Now that the initialization is complete, update the params
		 * file to indicate the status is online. Once done, send a
		 * message to the LU thread indicating same.
		 */
		(void) snprintf(path, sizeof (path), "%s/%s/%s%d",
		    target_basedir, cmd->c_lu->l_targ->s_targ_base, PARAMBASE,
		    lun);

		if ((n1 = xml_find_child(cmd->c_lu->l_common->l_root,
		    XML_ELEMENT_STATUS)) == NULL) {
			queue_prt(mgmtq, Q_STE_ERRS,
			    "STE%x  couldn't find <status>", lun);
			goto error;
		}

		if (xml_update_value_str(n1, XML_ELEMENT_STATUS,
		    TGT_STATUS_ONLINE) == False) {
			queue_prt(mgmtq, Q_STE_ERRS,
			    "STE%x  Could update <status> to online", lun);
			goto error;
		}

		if (xml_dump2file(cmd->c_lu->l_common->l_root, path) ==
		    False) {
			queue_prt(mgmtq, Q_STE_ERRS,
			    "STE%x  failed to dump out params", lun);
			goto error;
		}

		queue_message_set(cmd->c_lu->l_common->l_from_transports, 0,
		    msg_lu_online, 0);
	}

error:
	if (cmd != NULL) {
		if (cmd->c_data != NULL)
			free(cmd->c_data);
		t10_cmd_state(cmd, T10_Cmd_Event_Release);
	}
	if (t != NULL) {
		t10_handle_disable(t);
		t10_handle_destroy(t);
	}
	if (rq != NULL) {
		queue_message_set(rq, 0, msg_shutdown_rsp, 0);
	}

	return (rval);
}

/*
 * []------------------------------------------------------------------[]
 * | Methods called by emulation modules to interface with SAM-3	|
 * []------------------------------------------------------------------[]
 */

/*
 * []----
 * | trans_send_datain -- send data to transport
 * |
 * | NOTES:
 * | (1) offset is only valid when a transport has set max_out to a non-zero
 * |     value.
 * | (2) The emulation code must free the memory, if it was allocated, when
 * |     the transport is finished with it. The callback routine is used
 * |     to provide the emulation code the notification. The callback will
 * |     not be run on the same thread as the emulation code so appropriate
 * |     locking may be required by the emulation code.
 * | (3) If the boolean 'last' is True it means that the transport can
 * |     assume the data out is finished with a CMD_SUCCESS and no futher
 * |     communication from the emulation layer will occur.
 * []----
 */
Boolean_t
trans_send_datain(t10_cmd_t *cmd, char *data, size_t data_len, size_t offset,
    void (*callback)(emul_handle_t e), Boolean_t last, emul_handle_t id)
{
	t10_cmd_t	*c;

	if (last == False) {

		if ((c = calloc(1, sizeof (*c))) == NULL)
			return (False);
		bcopy(cmd, c, sizeof (*c));
		if ((c->c_cdb = (uint8_t *)malloc(c->c_cdb_len)) == NULL) {
			free(c);
			return (False);
		}
		bcopy(cmd->c_cdb, c->c_cdb, c->c_cdb_len);

		(void) pthread_mutex_lock(&cmd->c_lu->l_cmd_mutex);
		c->c_state = T10_Cmd_Alloc;
		avl_add(&c->c_lu->l_cmds, (void *)c);
		(void) pthread_mutex_unlock(&cmd->c_lu->l_cmd_mutex);

	} else
		c = cmd;

#ifdef FULL_DEBUG
	queue_prt(mgmtq, Q_STE_IO,
	    "SAM%x  LUN%d DataIn %d, offset %d, Last %s",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    data_len, offset, last == True ? "true" : "false");
#endif

	(void) pthread_mutex_lock(&cmd->c_lu->l_cmd_mutex);
	c->c_state		= T10_Cmd_DataIn;
	(void) pthread_mutex_unlock(&cmd->c_lu->l_cmd_mutex);
	c->c_emul_complete	= callback;
	c->c_emul_id		= id;
	c->c_data		= data;
	c->c_data_len		= data_len;
	c->c_offset		= offset;
	c->c_last		= last;

	queue_message_set(c->c_lu->l_to_transport, 0, msg_cmd_data_in,
	    (void *)c);
	return (True);
}

/*
 * []----
 * | trans_rqst_dataout -- Request data from transport for command
 * |
 * | If the transport has indicated that data is immediately available,
 * | which is common for iSCSI, then we'll copy that data into the buffer
 * | and call the emulation modules datain function directly.
 * []----
 */
Boolean_t
trans_rqst_dataout(t10_cmd_t *cmd, char *data, size_t data_len, size_t offset,
    emul_cmd_t emul_id)
{
	size_t	max_xfer;

	cmd->c_emul_id = emul_id;
	/*
	 * Transport supports immediate data on writes. Currently
	 * on the iSCSI protocol has this feature.
	 * XXX Should all of this be done in the transport?
	 */
	if (cmd->c_data_len) {
#ifdef FULL_DEBUG
		queue_prt(mgmtq, Q_STE_IO,
		    "SAM%x  LUN%d DataOut rqst w/ immed, data_len %d",
		    cmd->c_lu->l_targ->s_targ_num,
		    cmd->c_lu->l_common->l_num, data_len);
#endif
		if (cmd->c_data == NULL) {

			/*
			 * When there's data available, but no buffer it
			 * means the transport has decided to leave the
			 * data on the socket and will read it in
			 * when called.
			 */
			max_xfer = data_len;
			assert(cmd->c_lu->l_targ->s_dataout_cb != NULL);
			(*cmd->c_lu->l_targ->s_dataout_cb)(cmd, data,
			    &max_xfer);

		} else {

			/*
			 * The data is already in the command buffer so
			 * we need to copy it out.
			 */
			max_xfer = MIN(cmd->c_data_len - cmd->c_resid,
			    data_len);
			bcopy(cmd->c_data + cmd->c_resid, data, max_xfer);
			cmd->c_resid = cmd->c_data_len - max_xfer;

			/*
			 * It's expected since the transport allocated
			 * the space, this routine will free the memory
			 * instead.
			 */
			(*cmd->c_lu->l_targ->s_dataout_cb)(cmd, data,
			    &max_xfer);
			cmd->c_data = NULL;

		}
		cmd->c_data_len = 0;
		(void) pthread_mutex_lock(&cmd->c_lu->l_cmd_mutex);
		cmd->c_state	= T10_Cmd_DataOut;
		(void) pthread_mutex_unlock(&cmd->c_lu->l_cmd_mutex);
		(*cmd->c_lu->l_data)(cmd, emul_id, offset, data, max_xfer);
		return (True);
	}

#ifdef FULL_DEBUG
	queue_prt(mgmtq, Q_STE_IO,
	    "SAM%x  LUN%d DataOut Rqst data_len %d",
	    cmd->c_lu->l_targ->s_targ_num,
	    cmd->c_lu->l_common->l_num, data_len);
#endif

	assert(cmd->c_data == NULL);

	(void) pthread_mutex_lock(&cmd->c_lu->l_cmd_mutex);
	cmd->c_state	= T10_Cmd_DataOut;
	(void) pthread_mutex_unlock(&cmd->c_lu->l_cmd_mutex);
	cmd->c_data	= data;
	cmd->c_data_len	= data_len;
	cmd->c_offset	= offset;
	cmd->c_resid	= 0;

	/*
	 * Short cut. There's no reason to call the transport if the
	 * emulation code hasn't requested any data. If that's the
	 * case just call the emulation codes data function.
	 */
	if (data_len == 0)
		(*cmd->c_lu->l_data)(cmd, emul_id, offset, data, max_xfer);
	else
		queue_message_set(cmd->c_lu->l_to_transport, 0,
		    msg_cmd_data_rqst, (void *)cmd);
	return (True);
}

/*
 * []----
 * | trans_send_complete -- notify transport command has finished.
 * |
 * | This routine is called either for when the emulation has completed
 * | a command which doesn't have a data in phase so we can't use the 'last'
 * | flag or there's been an error.
 * | The sense data is expected to be created by calling spc_create_sense(),
 * | the memory for that sense data will be freed when the transport calls
 * | t10_destroy_cmd().
 * |
 * | NOTE [1]: If the t10_status equals STATUS_BUSY the command queue for this
 * | ITL will be examined. If there are commands in progress the status will
 * | be changed to STATUS_QFULL
 * |
 * | NOTE [2]: Do not access 'cmd' after calling this function. The transport
 * | may receive the command, act on it, and then call
 * | t10_cmd_state(cmd, T10_Cmd_Event_Release) before this function returns
 * | thereby allowing 'cmd' to be freed and the space reallocated.
 * []----
 */
void
trans_send_complete(t10_cmd_t *cmd, int t10_status)
{
#ifdef FULL_DEBUG
	struct scsi_extended_sense	e;
#endif

	(void) pthread_mutex_lock(&cmd->c_lu->l_cmd_mutex);
	cmd->c_state		= T10_Cmd_Complete;

	/*
	 * XXX Get the exact chapter and verse from the T10 documents.
	 * translate a STATUS_BUSY to STATUS_QFULL if there are outstanding
	 * commands in the queue.
	 */
	if ((t10_status == STATUS_BUSY) &&
	    (avl_numnodes(&cmd->c_lu->l_cmds) != 0)) {
		t10_status	= STATUS_QFULL;
	}

	(void) pthread_mutex_unlock(&cmd->c_lu->l_cmd_mutex);

	cmd->c_cmd_status	= t10_status;
	cmd->c_last		= True;
	cmd->c_data_len		= 0;
	cmd->c_data		= 0;

#ifdef FULL_DEBUG
	if (t10_status != STATUS_GOOD) {
		if (cmd->c_cmd_sense != NULL) {
			bcopy(&cmd->c_cmd_sense[2], &e, sizeof (e));
			queue_prt(mgmtq, Q_STE_ERRS,
			    "SAM%x  LUN%d key_sense=0x%x, "
			    "ASC=0x%x, ASCQ=0x%x",
			    cmd->c_lu->l_targ->s_targ_num,
			    cmd->c_lu->l_common->l_num,
			    e.es_key, e.es_add_code, e.es_qual_code);
		} else {
			queue_prt(mgmtq, Q_STE_ERRS,
			    "SAM%x  LUN%d key_sense=0x%x",
			    cmd->c_lu->l_targ->s_targ_num,
			    cmd->c_lu->l_common->l_num, t10_status);
		}
	}
#endif

	queue_message_set(cmd->c_lu->l_to_transport, 0, msg_cmd_cmplt,
	    (void *)cmd);
}

void
trans_aiowrite(t10_cmd_t *cmd, char *data, size_t data_len, off_t offset,
    aio_result_t *aiop)
{
	t10_aio_t	*taio;

	if (aiowrite(cmd->c_lu->l_common->l_fd, data, data_len, offset, 0,
	    aiop) == -1) {
		taio = (t10_aio_t *)aiop;
		taio->a_aio.aio_return = -1;
		(*taio->a_aio_cmplt)(taio->a_id);
	} else
		(void) sema_post(&t10_sema);
}

void
trans_aioread(t10_cmd_t *cmd, char *data, size_t data_len, off_t offset,
    aio_result_t *aiop)
{
	t10_aio_t	*taio;

	if (aioread(cmd->c_lu->l_common->l_fd, data, data_len, offset, 0,
	    aiop) == -1) {
		taio = (t10_aio_t *)aiop;
		taio->a_aio.aio_return = -1;
		(*taio->a_aio_cmplt)(taio->a_id);
	} else
		(void) sema_post(&t10_sema);
}

/*
 * []----
 * | trans_params_area -- return dtype params using a command pointer
 * |
 * | Lock down the ITL structure from change so that we can cleanly access
 * | the params area. This is needed to deal with the transport closing
 * | a connection while commands are in flight. When those commands finish
 * | cleanup work needs to be done. Yet, the logical unit common area
 * | can already be released since it doesn't know there's something to wait
 * | for.
 * []----
 */
void *
trans_params_area(t10_cmd_t *cmd)
{
	void	*p	= NULL;

	(void) pthread_mutex_lock(&cmd->c_lu->l_mutex);
	if (cmd->c_lu->l_common != NULL)
		p = cmd->c_lu->l_common->l_dtype_params;
	(void) pthread_mutex_unlock(&cmd->c_lu->l_mutex);
	return (p);
}

/*
 * []------------------------------------------------------------------[]
 * | Support routines for Routing and Task Management			|
 * []------------------------------------------------------------------[]
 */

/*
 * []----
 * | t10_find_lun -- Locate a per target LUN structure
 * |
 * | Finds per I_T_L structure. If this is the first time that this structure
 * | has been accessed we allocate the structure and add it to the global
 * | LUN structure. If that structure has never been accessed before it is
 * | created along with a thread to handle the queue.
 * []----
 */
/*ARGSUSED*/
static Boolean_t
t10_find_lun(t10_targ_impl_t *t, int lun, t10_cmd_t *cmd)
{
	t10_lu_impl_t		*l		= NULL,
				search;
	avl_index_t		wc		= 0, /* where common */
				wt		= 0; /* where target */
	char			*guid		= NULL;
	t10_lu_common_t		lc,
				*common		= NULL;
	xml_node_t		*n		= NULL,
				*n1;
	xmlTextReaderPtr	r		= NULL;
	char			path[MAXPATHLEN];
	int			xml_fd		= -1;

	bzero(&lc, sizeof (lc));

	/*
	 * Only l_num is used by the AVL search routines so that's
	 * the only thing we'll set.
	 */
	search.l_targ_lun = lun;

	if ((l = avl_find(&t->s_open_lu, (void *)&search, &wt)) != NULL) {

		/*
		 * This should be the normal fast path. At some point it
		 * might be good to look at optimizing this even more.
		 * If we know for example that the LUN numbers are sequential
		 * and there's fewer than 64 an array of pointers would be
		 * even faster than an AVL tree and not take up to much space.
		 */
		cmd->c_lu = l;
		return (True);
	}

	/*
	 * First access for this I_T_L so we need to allocate space for it.
	 */
	if ((l = calloc(1, sizeof (*l))) == NULL) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		return (False);
	}

	/*
	 * Initialize the various local fields. Certain fields will not be
	 * initialized until we've got the common LUN pointer.
	 */
	(void) pthread_mutex_init(&l->l_cmd_mutex, NULL);
	(void) pthread_mutex_init(&l->l_mutex, NULL);
	(void) pthread_cond_init(&l->l_cmd_cond, NULL);
	avl_create(&l->l_cmds, find_cmd_by_addr, sizeof (t10_cmd_t),
	    offsetof(t10_cmd_t, c_cmd_avl));

	l->l_wait_for_drain	= False;
	l->l_to_transport	= t->s_to_transport;
	l->l_targ		= t;
	l->l_targ_lun		= lun;

	/*
	 * To locate the common LUN structure we need to find the GUID
	 * for this LUN. That's the only parsing this section of code will
	 * do to the params file.
	 */
	(void) snprintf(path, sizeof (path), "%s/%s/%s%d",
	    target_basedir, t->s_targ_base, PARAMBASE, lun);

	(void) pthread_mutex_lock(&lu_list_mutex);
	if ((xml_fd = open(path, O_RDONLY)) < 0) {
		(void) pthread_mutex_unlock(&lu_list_mutex);
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		/* ---- ACCESS DENIED - INVALID LU IDENTIFIER ---- */
		spc_sense_ascq(cmd, 0x20, 0x9);
		goto error;
	}
	if ((r = (xmlTextReaderPtr)xmlReaderForFd(xml_fd, NULL, NULL,
	    0)) != NULL) {
		while (xmlTextReaderRead(r) == 1)
			if (xml_process_node(r, &n) == False)
				break;
	} else {
		(void) pthread_mutex_unlock(&lu_list_mutex);
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		goto error;
	}

	(void) close(xml_fd);
	/*
	 * Set xml_fd back to -1 so that if an error occurs later we don't
	 * attempt to close a file descriptor that another thread might have
	 * opened.
	 */
	xml_fd = -1;

	xmlTextReaderClose(r);
	xmlFreeTextReader(r);
	r = NULL;

	if (xml_find_value_str(n, XML_ELEMENT_GUID, &guid) == False) {
		(void) pthread_mutex_unlock(&lu_list_mutex);
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		goto error;
	}

	if (strcmp(guid, "0") == 0) {
		free(guid);
		if (util_create_guid(&guid) == False) {
			(void) pthread_mutex_unlock(&lu_list_mutex);
			spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
			goto error;
		}
		if ((n1 = xml_find_child(n, XML_ELEMENT_GUID)) == NULL) {
			(void) pthread_mutex_unlock(&lu_list_mutex);
			spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
			goto error;
		}
		if (xml_update_value_str(n1, XML_ELEMENT_GUID, guid) == False) {
			(void) pthread_mutex_unlock(&lu_list_mutex);
			spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
			goto error;
		}
		if (xml_dump2file(n, path) == False) {
			(void) pthread_mutex_unlock(&lu_list_mutex);
			spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
			goto error;
		}
	}

	if (xml_decode_bytes(guid, &lc.l_guid, &lc.l_guid_len) == False) {
		(void) pthread_mutex_unlock(&lu_list_mutex);
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		goto error;
	}

	/*
	 * See if the common LUN for this GUID already exists.
	 */
	wc = 0;
	if ((common = avl_find(&lu_list, (void *)&lc, &wc)) == NULL) {

		/*
		 * The GUID wasn't found, so create a new LUN structure
		 * and thread.
		 */
		if ((common = calloc(1, sizeof (*common))) == NULL) {
			(void) pthread_mutex_unlock(&lu_list_mutex);
			spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
			goto error;
		}

		common->l_from_transports = queue_alloc();
		common->l_num		= lun;
		common->l_internal_num	= lu_id++;
		common->l_guid		= lc.l_guid;
		common->l_guid_len	= lc.l_guid_len;
		common->l_fd		= -1; /* not open yet */
		common->l_mmap		= MAP_FAILED;

		(void) pthread_mutex_init(&common->l_common_mutex, NULL);

		(void) snprintf(path, sizeof (path), "%s/%s", target_basedir,
		    t->s_targ_base);
		if (t10_lu_initialize(common, path) == False) {
			queue_prt(mgmtq, Q_STE_ERRS,
			    "SAM%x  FAILED to initialize LU %d",
			    t->s_targ_num, lun);
			(void) pthread_mutex_unlock(&lu_list_mutex);
			spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
			goto error;
		}

		avl_create(&common->l_all_open, find_lu_by_targ,
		    sizeof (t10_lu_impl_t),
		    offsetof(t10_lu_impl_t, l_open_lu_node));

		avl_insert(&lu_list, (void *)common, wc);
		(void) pthread_create(&common->l_thr_id, NULL, lu_runner,
		    (void *)common);
		queue_prt(mgmtq, Q_STE_NONIO,
		    "SAM%x  LU[%d.%d] Created new LU thread 0x%x",
		    t->s_targ_num, common->l_internal_num, common->l_num,
		    common->l_thr_id);

	} else {

		/*
		 * If there's a common LU structure already we free
		 * the guid which was created for the search. If an error
		 * occurs the guid space will be freed in the error handling
		 * code. If a new LU is created though we don't free the guid
		 * since the LU needs the information.
		 */
		free(lc.l_guid);
		lc.l_guid = NULL;
		queue_prt(mgmtq, Q_STE_NONIO,
		    "SAM%x  Found existing LU[%d.%d]", t->s_targ_num,
		    common->l_internal_num, common->l_num);
	}
	(void) pthread_mutex_lock(&common->l_common_mutex);
	(void) avl_find(&common->l_all_open, (void *)l, &wc);
	avl_insert(&common->l_all_open, (void *)l, wc);
	(void) pthread_mutex_unlock(&common->l_common_mutex);

	(void) pthread_mutex_unlock(&lu_list_mutex);

	/*
	 * Now add this I_T_L to the targets list of open LUNs so that
	 * in the future we can get access through the AVL tree.
	 * We wait to add the LU to the target list until now so that we don't
	 * have to delete the node in case an error occurs.
	 */
	avl_insert(&t->s_open_lu, (void *)l, wt);

	(void) pthread_mutex_lock(&l->l_mutex);
	l->l_common = common;
	(void) pthread_mutex_unlock(&l->l_mutex);

	/*
	 * The common LU thread is responsible for filling in the command
	 * functions and table.
	 */
	queue_message_set(common->l_from_transports, 0, msg_lu_add, (void *)l);

	free(guid);
	xml_tree_free(n);

	cmd->c_lu = l;
	return (True);

error:
	if (guid)
		free(guid);
	if (xml_fd != -1)
		(void) close(xml_fd);
	if (r) {
		xmlTextReaderClose(r);
		xmlFreeTextReader(r);
	}
	if (n)
		xml_tree_free(n);
	if (l)
		free(l);
	if (lc.l_guid)
		free(lc.l_guid);
	if (common)
		free(common);
	return (False);
}

static Boolean_t
t10_lu_initialize(t10_lu_common_t *lu, char *basedir)
{
	char	*str	= NULL;

	if (load_params(lu, basedir) == False)
		return (False);

	if (xml_find_value_str(lu->l_root, XML_ELEMENT_DTYPE, &str) == True) {
		if (strcmp(str, TGT_TYPE_DISK) == 0) {
			lu->l_dtype = DTYPE_DIRECT;
			if (sbc_init_common(lu) == False)
				goto error;
		} else if (strcmp(str, TGT_TYPE_RAW) == 0) {
			lu->l_dtype = DTYPE_UNKNOWN;
			if (raw_init_common(lu) == False)
				goto error;
		} else if (strcmp(str, TGT_TYPE_TAPE) == 0) {
			lu->l_dtype = DTYPE_SEQUENTIAL;
			if (ssc_init_common(lu) == False)
				goto error;
		} else if (strcmp(str, TGT_TYPE_OSD) == 0) {
			lu->l_dtype = DTYPE_OSD;
			if (osd_init_common(lu) == False)
				goto error;
		}
		if (lu->l_dtype_params == NULL)
			goto error;
		free(str);
	} else
		goto error;

	return (True);
error:
	if (str != NULL)
		free(str);
	return (False);
}

/*
 * []----
 * | lu_runner -- The workhorse for each LU
 * |
 * | This routine is the guts of the Task Router and Task Set for SAM-3.
 * []----
 */
static void *
lu_runner(void *v)
{
	t10_lu_common_t	*lu = (t10_lu_common_t *)v;
	msg_t		*m;
	t10_lu_impl_t	*itl;
	t10_cmd_t	*cmd;
	char		*data,
			*path;
	size_t		data_len,
			new_size,
			offset;
	ssize_t		cc;
	void		*provo_err;
	t10_shutdown_t	*s;

	util_title(mgmtq, Q_STE_NONIO, lu->l_internal_num, "Start LU");
	while ((m = queue_message_get(lu->l_from_transports)) != NULL) {

		switch (m->msg_type) {
		case msg_cmd_send:
			cmd = (t10_cmd_t *)m->msg_data;
			if (cmd->c_lu->l_status) {
				spc_sense_create(cmd, cmd->c_lu->l_status, 0);
				spc_sense_ascq(cmd, cmd->c_lu->l_asc,
				    cmd->c_lu->l_ascq);
				/*
				 * Clear out the per LU values before
				 * calling trans_send_complete(). It's
				 * possible for the transport to handle
				 * this command and free it before returning.
				 */
				cmd->c_lu->l_status	= 0;
				cmd->c_lu->l_asc	= 0;
				cmd->c_lu->l_ascq	= 0;
				trans_send_complete(cmd, STATUS_CHECK);
			} else {
				lu->l_curr		= cmd;
				(*cmd->c_lu->l_cmd)(cmd, cmd->c_cdb,
						    cmd->c_cdb_len);
				lu->l_curr		= NULL;
			}
			break;

		case msg_cmd_data_out:
			cmd		= (t10_cmd_t *)m->msg_data;
			data		= cmd->c_data;
			data_len	= cmd->c_data_len;
			offset		= cmd->c_offset;

			/*
			 * We clear the c_data_len here because if the
			 * emulation routine processes the data and still
			 * needs more it will call trans_rqst_datain()
			 * which will look at c_data_len to see if there
			 * was immediate data available from the transport.
			 * In this case we've already processed the data
			 * and need to request more from the transport.
			 * c_data is set to NULL because there's an assert
			 * in trans_rqst_datain() checking that c_data is
			 * indeed null.
			 */
			cmd->c_data_len	= 0;
			cmd->c_data	= NULL;

			lu->l_curr		= cmd;
			(*cmd->c_lu->l_data)(cmd, cmd->c_emul_id,
			    offset, data, data_len);
			lu->l_curr		= NULL;
			break;

		case msg_lu_add:
			itl = (t10_lu_impl_t *)m->msg_data;
			switch (lu->l_dtype) {
				case DTYPE_DIRECT:
					sbc_init_per(itl);
					break;

				case DTYPE_SEQUENTIAL:
					ssc_init_per(itl);
					break;

				case DTYPE_OSD:
					osd_init_per(itl);
					break;

				case DTYPE_UNKNOWN:
					raw_init_per(itl);
					break;
			}
			break;

		case msg_reset_lu:
			queue_reset(lu->l_from_transports);
			(void) pthread_mutex_lock(&lu->l_common_mutex);
			itl = avl_first(&lu->l_all_open);
			do {
				/*
				 * The current implementation is that we
				 * have a shared queue for each LU. That means
				 * if we reset a LU all I_T nexus' must
				 * receive a CHECK_CONDITION on their next
				 * command.
				 */
				switch (lu->l_dtype) {
				case DTYPE_DIRECT:
					sbc_fini_per(itl);
					sbc_init_per(itl);
					break;

				case DTYPE_SEQUENTIAL:
					ssc_fini_per(itl);
					ssc_init_per(itl);
					break;

				case DTYPE_UNKNOWN:
					raw_fini_per(itl);
					raw_init_per(itl);
					break;

				case DTYPE_OSD:
					osd_fini_per(itl);
					osd_init_per(itl);
				}

				itl = AVL_NEXT(&lu->l_all_open, itl);
			} while (itl != NULL);
			(void) pthread_mutex_unlock(&lu->l_common_mutex);
			break;

		case msg_shutdown:

			s = (t10_shutdown_t *)m->msg_data;
			itl = s->t_lu;
			(void) pthread_mutex_lock(&lu_list_mutex);
			(void) pthread_mutex_lock(&lu->l_common_mutex);
			assert(avl_find(&lu->l_all_open, (void *)itl, NULL) !=
			    NULL);
			avl_remove(&lu->l_all_open, (void *)itl);

			queue_walker_free(lu->l_from_transports,
			    lu_remove_cmds, (void *)itl);
			switch (lu->l_dtype) {
			case DTYPE_DIRECT:
				sbc_fini_per(itl);
				break;

			case DTYPE_SEQUENTIAL:
				ssc_fini_per(itl);
				break;

			case DTYPE_OSD:
				osd_fini_per(itl);
				break;

			case DTYPE_UNKNOWN:
				raw_fini_per(itl);
				break;
			}
			/*
			 * Don't remove reference to l_common area until after
			 * the emulation routines are finished since they
			 * are likely to reference l_dtype_params.
			 */
			(void) pthread_mutex_lock(&itl->l_mutex);
			itl->l_common = NULL;
			(void) pthread_mutex_unlock(&itl->l_mutex);

			queue_message_set(s->t_q, 0, msg_shutdown_rsp,
			    (void *)(uintptr_t)itl->l_targ_lun);
			if (avl_numnodes(&lu->l_all_open) == 0) {
				queue_prt(mgmtq, Q_STE_NONIO,
				    "LU_%x  No remaining targets for LU(%d)",
				    lu->l_internal_num, lu->l_fd);
				if (lu->l_mmap != MAP_FAILED)
					(void) munmap(lu->l_mmap,
					    lu->l_size);
				if (close(lu->l_fd) != 0)
					queue_prt(mgmtq, Q_STE_ERRS,
					    "LU_%x  Failed to close fd, "
					    "errno=%d", lu->l_internal_num,
					    errno);
				switch (lu->l_dtype) {
				case DTYPE_DIRECT:
					sbc_fini_common(lu);
					break;

				case DTYPE_SEQUENTIAL:
					ssc_fini_common(lu);
					break;

				case DTYPE_UNKNOWN:
					raw_fini_common(lu);
					break;
				}
				avl_remove(&lu_list, (void *)lu);
				util_title(mgmtq, Q_STE_NONIO,
				    lu->l_internal_num, "End LU");
				queue_free(lu->l_from_transports, NULL);
				(void) pthread_mutex_unlock(
				    &lu->l_common_mutex);
				(void) pthread_mutex_unlock(&lu_list_mutex);
				xml_tree_free(lu->l_root);
				free(lu->l_pid);
				free(lu->l_vid);
				free(lu->l_guid);
				free(lu);
				queue_message_free(m);
				pthread_exit(NULL);
			}
			(void) pthread_mutex_unlock(&lu->l_common_mutex);
			(void) pthread_mutex_unlock(&lu_list_mutex);
			break;

		case msg_targ_inventory_change:
			itl = (t10_lu_impl_t *)m->msg_data;
			itl->l_status	= KEY_UNIT_ATTENTION;
			/*
			 * SPC-3 revision 21c, section 4.5.6, Table 28
			 * When LU inventory changes need to report
			 * a REPORTED LUNS DATA HAS CHANGED event.
			 */
			itl->l_asc	= 0x3f;
			itl->l_ascq	= 0x0e;
			queue_prt(mgmtq, Q_STE_NONIO,
			    "LU_%x  Received InventoryChange for %d",
			    lu->l_internal_num, itl->l_common->l_num);
			break;

		case msg_thick_provo:
			cmd	= (t10_cmd_t *)m->msg_data;
			if (lu->l_mmap != MAP_FAILED) {

				/*
				 * If the file at c_offset is currently
				 * unallocated we'll read in that buffer
				 * which will be zeros and then write it
				 * back out which will force the underlying
				 * filesystem to allocate the blocks.
				 * If someone has already issued a write
				 * to this area we'll then just cause a
				 * useless, but safe read/write to occur.
				 */
				lu->l_curr		= cmd;
				lu->l_curr_provo	= True;
				bcopy((char *)lu->l_mmap + cmd->c_offset,
				    cmd->c_data, cmd->c_data_len);
				cmd->c_lu->l_cmds_read++;
				cmd->c_lu->l_sects_read +=
					cmd->c_data_len / 512;
				bcopy(cmd->c_data,
				    (char *)lu->l_mmap + cmd->c_offset,
				    cmd->c_data_len);
				cmd->c_lu->l_cmds_write++;
				cmd->c_lu->l_sects_write +=
					cmd->c_data_len / 512;
				lu->l_curr		= NULL;
				lu->l_curr_provo	= False;
				provo_err		= 0;

			} else {
				if ((cc = pread(lu->l_fd, cmd->c_data,
				    cmd->c_data_len, cmd->c_offset)) < 0) {
					queue_prt(mgmtq, Q_STE_ERRS,
					    "LU_%x  pread errno=%d", lu->l_num,
					    errno);
				} else if (pwrite(lu->l_fd, cmd->c_data, cc,
				    cmd->c_offset) != cc) {
					queue_prt(mgmtq, Q_STE_ERRS,
					    "LU_%x  pwrite errno=%d",
					    lu->l_num, errno);
				}
				provo_err = (cc == cmd->c_data_len) ?
					(void *)0 : (void *)1;
			}
			/*
			 * acknowledge this op and wait for next
			 */
			queue_message_set(cmd->c_lu->l_to_transport, 0,
			    msg_thick_provo, provo_err);
			break;

		case msg_lu_capacity_change:
			new_size = lseek(lu->l_fd, 0, SEEK_END);
			queue_prt(mgmtq, Q_STE_NONIO,
			    "LU_%x  Capacity Change from 0x%llx to 0x%llx",
			    lu->l_internal_num, lu->l_size, new_size);
			if ((path = malloc(MAXPATHLEN)) == NULL)
				break;

			(void) snprintf(path, MAXPATHLEN, "%s/%s",
			    target_basedir, itl->l_targ->s_targ_base);
			(void) load_params(lu, path);
			free(path);
			switch (lu->l_dtype) {
			case DTYPE_DIRECT:
				sbc_task_mgmt(lu, CapacityChange);
				break;

			case DTYPE_SEQUENTIAL:
				ssc_task_mgmt(lu, CapacityChange);
				break;
			}
			(void) pthread_mutex_lock(&lu->l_common_mutex);
			itl = avl_first(&lu->l_all_open);
			while (itl != NULL) {
				itl->l_status	= KEY_UNIT_ATTENTION;
				itl->l_asc	= SPC_ASC_CAP_CHANGE;
				itl->l_ascq	= SPC_ASCQ_CAP_CHANGE;
				itl = AVL_NEXT(&lu->l_all_open, itl);
			}
			(void) pthread_mutex_unlock(&lu->l_common_mutex);
			break;

		case msg_lu_online:
			queue_prt(mgmtq, Q_STE_NONIO,
			    "LU_%x  Received online event", lu->l_internal_num);
			if ((path = malloc(MAXPATHLEN)) == NULL)
				break;

			(void) pthread_mutex_lock(&lu->l_common_mutex);
			itl = avl_first(&lu->l_all_open);
			(void) pthread_mutex_unlock(&lu->l_common_mutex);
			(void) snprintf(path, MAXPATHLEN, "%s/%s",
			    target_basedir, itl->l_targ->s_targ_base);
			(void) load_params(lu, path);
			free(path);
			switch (lu->l_dtype) {
			case DTYPE_DIRECT:
				sbc_task_mgmt(lu, DeviceOnline);
				break;

			case DTYPE_SEQUENTIAL:
				ssc_task_mgmt(lu, DeviceOnline);
				break;
			}
			(void) pthread_mutex_lock(&lu->l_common_mutex);
			itl = avl_first(&lu->l_all_open);
			while (itl != NULL) {
				switch (lu->l_dtype) {
				case DTYPE_DIRECT:
					sbc_init_per(itl);
					break;

				case DTYPE_SEQUENTIAL:
					ssc_init_per(itl);
					break;
				}
				itl = AVL_NEXT(&lu->l_all_open, itl);
			}
			(void) pthread_mutex_unlock(&lu->l_common_mutex);
			break;

		}
		queue_message_free(m);
	}

	return (NULL);
}

/*
 * []----
 * | lu_buserr_handler -- deal with SIGBUS on mmap'd files
 * |
 * | Normally SIGBUS's are a real bad thing. With this project, which uses
 * | mmap'd files that start out as hole-y, can represent more space than
 * | the underlying storage has available. This is good and considered a
 * | feature for "Thin Provisioning". However, this means that if the
 * | administrator isn't on the ball the storage can fill up. Because of the
 * | asynchronous nature of writing to a mmap'd file the OS will send a SIGBUS
 * | to the thread which caused the problem. The thread will then locate its
 * | data structure and in turn signal the initiator that a problem occurred.
 * | Since we can't restart we're we left off because the out of space
 * | condition is still present another thread is started to handle other
 * | commands for the logical unit. The current thread will then exit.
 * |
 * | NOTE:
 * | If for any reason this routine doesn't find what's it's expecting to
 * | assert() will be called to create a core. This routine will only recover
 * | from the expected case of a SIGBUS, otherwise something real bad has
 * | happened and we need to see the core.
 * []----
 */
/*ARGSUSED*/
void
lu_buserr_handler(int sig, siginfo_t *sip, void *v)
{
	t10_lu_common_t	*lu;
	pthread_t	id = pthread_self();
	char		*fa;

	if (pthread_mutex_trylock(&lu_list_mutex) != 0) {
		assert(0);
		return;
	}
	lu = avl_first(&lu_list);
	while (lu != NULL) {
		if (lu->l_thr_id == id)
			break;
		lu = AVL_NEXT(&lu_list, lu);
	}
	(void) pthread_mutex_unlock(&lu_list_mutex);

	if ((lu == NULL) || (lu->l_curr == NULL)) {
		queue_prt(mgmtq, Q_STE_ERRS,
		    "SAM%x  BUS ERROR and couldn't find logical unit",
		    lu->l_num);
		assert(0);
		return;
	}

	if (lu->l_mmap == MAP_FAILED) {
		queue_prt(mgmtq, Q_STE_ERRS,
		    "SAM%x  BUS ERROR and device not mmap'd", lu->l_num);
		assert(0);
		return;
	}

	fa = (char *)sip->__data.__fault.__addr;
	if ((fa < (char *)lu->l_mmap) ||
	    (fa > ((char *)lu->l_mmap + lu->l_size))) {
		queue_prt(mgmtq, Q_STE_ERRS,
		    "SAM%x  BUS ERROR occurred outsize of mmap bounds",
		    lu->l_num);
		assert(0);
		return;
	}

	if (lu->l_curr_provo == True) {
		lu->l_curr_provo = False;
		queue_message_set(lu->l_curr->c_lu->l_to_transport, 0,
		    msg_thick_provo, (void *)1);
	} else {
		spc_sense_create(lu->l_curr, KEY_MEDIUM_ERROR, 0);
		spc_sense_ascq(lu->l_curr, SPC_ASC_WRITE_ERROR,
		    SPC_ASCQ_WRITE_ERROR);
		trans_send_complete(lu->l_curr, STATUS_CHECK);
	}

	queue_prt(mgmtq, Q_STE_ERRS,
	    "SAM%x  Caught an out-of-space issue", lu->l_num);

	/*
	 * Now restart another thread to pick up where we've left off with
	 * processing commands for this logical unit.
	 */
	(void) pthread_create(&lu->l_thr_id, NULL, lu_runner, (void *)lu);
	pthread_exit((void *)0);
}

/*
 * []----
 * | lu_remove_cmds -- look for and free commands for a given ITL
 * []----
 */
static Boolean_t
lu_remove_cmds(msg_t *m, void *v)
{
	t10_lu_impl_t	*lu = (t10_lu_impl_t *)v;
	t10_cmd_t	*c;

	switch (m->msg_type) {
	case msg_cmd_send:
	case msg_cmd_data_out:
		c = (t10_cmd_t *)m->msg_data;
		if (c->c_lu == lu) {
			queue_prt(mgmtq, Q_STE_NONIO,
			    "SAM%x  LUN %d, removed command during lu_remove",
			    c->c_lu->l_targ->s_targ_num, lu->l_common->l_num);
			t10_cmd_state(c, T10_Cmd_Event_Release);
			return (True);
		}
		break;
	}
	return (False);
}

/*
 * []----
 * | load_params -- load parameters and open LU backing store
 * |
 * | This routine can be called multiple times and will free and release
 * | previous resources.
 * []----
 */
static Boolean_t
load_params(t10_lu_common_t *lu, char *basedir)
{
	char			file[MAXPATHLEN],
				*str;
	int			oflags		= O_RDWR|O_LARGEFILE|O_NDELAY;
	Boolean_t		mmap_lun	= True;
	xml_node_t		*node		= NULL;
	int			version_maj	= XML_VERS_LUN_MAJ,
				version_min	= XML_VERS_LUN_MIN,
				xml_fd;
	xmlTextReaderPtr	r;

	/*
	 * Clean up from previous call to this function. This occurs if
	 * the LU has grown since it was last opened.
	 */
	if (lu->l_mmap != MAP_FAILED)
		munmap(lu->l_mmap, lu->l_size);
	if (lu->l_root != NULL) {
		xml_tree_free(lu->l_root);
		lu->l_root = NULL;
	}
	if (lu->l_fd != -1)
		close(lu->l_fd);

	(void) snprintf(file, sizeof (file), "%s/%s%d", basedir, PARAMBASE,
			lu->l_num);

	if ((xml_fd = open(file, O_RDONLY)) < 0)
		return (False);
	if ((r = (xmlTextReaderPtr)xmlReaderForFd(xml_fd, NULL, NULL,
	    0)) != NULL) {
		while (xmlTextReaderRead(r) == 1)
			if (xml_process_node(r, &node) == False)
				break;
		lu->l_root = node;
	} else
		return (False);

	(void) close(xml_fd);
	xmlTextReaderClose(r);
	xmlFreeTextReader(r);

	if (validate_version(node, &version_maj, &version_min) == False)
		goto error;

	if (xml_find_value_str(node, XML_ELEMENT_PID, &lu->l_pid) == False)
		goto error;

	if (xml_find_value_str(node, XML_ELEMENT_VID, &lu->l_vid) == False)
		goto error;

	/*
	 * If there's no <status> tag it just means this is an older param
	 * file and there's no need to treat it as an error. Just mark
	 * the device as online.
	 */
	if (xml_find_value_str(node, XML_ELEMENT_STATUS, &str) == True) {
		if (strcmp(str, TGT_STATUS_ONLINE) == 0)
			lu->l_state = lu_online;
		else if (strcmp(str, TGT_STATUS_OFFLINE) == 0)
			lu->l_state = lu_offline;
		else if (strcmp(str, TGT_STATUS_ERRORED) == 0)
			lu->l_state = lu_errored;
		free(str);
	} else
		lu->l_state = lu_online;

	/*
	 * If offline, we need to check to see if there's an initialization
	 * thread running for this lun. If not, start one.
	 */
	if ((lu->l_state == lu_offline) &&
	    (thick_provo_chk_thr(strrchr(basedir, '/') + 1, lu->l_num) ==
	    False)) {
		queue_prt(mgmtq, Q_STE_NONIO,
		    "LU_%d  No initialization thread running", lu->l_num);
		if (thin_provisioning == False) {
			thick_provo_t	*tp;
			pthread_t	junk;

			if ((tp = calloc(1, sizeof (*tp))) != NULL) {
				tp->targ_name = strdup(strrchr(basedir, '/')) +
				    1;
				tp->lun	= lu->l_num;
				tp->q	= queue_alloc();
				(void) pthread_create(&junk, NULL,
				    thick_provo_start, tp);
				/* ---- wait for start message ---- */
				queue_message_free(queue_message_get(tp->q));
			}
		}
	}

	/*
	 * The default is to disable the fast write acknowledgement which
	 * can be overridden in a couple of ways. First, see if the global
	 * fast-write-ack is enabled, then check the per logical unit flags.
	 * The per LU bit is settable via a SCSI command.
	 */
	lu->l_fast_write_ack = False;
	(void) xml_find_value_boolean(main_config, XML_ELEMENT_FAST,
	    &lu->l_fast_write_ack);
	(void) xml_find_value_boolean(node, XML_ELEMENT_FAST,
	    &lu->l_fast_write_ack);
	if (lu->l_fast_write_ack == False)
		oflags |= O_SYNC;

	/*
	 * Object-based Storage Devices currently use directories to
	 * represent the partitions and files in those directories to
	 * represent user objects and collections. Therefore, there's
	 * not just a single file to be opened, but potentially thousands.
	 * Therefore, stop here if we've got an OSD dtype.
	 */
	if (xml_find_value_str(node, XML_ELEMENT_DTYPE, &str) == False)
		goto error;
	if (strcmp(str, TGT_TYPE_OSD) == 0) {
		free(str);
		return (True);
	} else
		free(str);

	(void) snprintf(file, sizeof (file), "%s/%s%d", basedir, LUNBASE,
	    lu->l_num);
	if ((lu->l_fd = open(file, oflags)) == -1)
		goto error;

#ifndef	_LP64
	/*
	 * Since the address space is so limited on 32bit machines
	 * disable mmap'ing the file by default.
	 */
	mmap_lun	= False;
#endif
	(void) xml_find_value_boolean(node, XML_ELEMENT_MMAP_LUN, &mmap_lun);
	if (xml_find_value_str(node, XML_ELEMENT_SIZE, &str) == True) {
		lu->l_size = strtoll(str, NULL, 0) * 512LL;
		free(str);
	} else
		goto error;

	if (mmap_lun == True) {
		/*
		 * st_size will be wrong if the device is a block device
		 * but that's okay since you can't mmap in a block device.
		 * A block device will fall back to using AIO operations.
		 */
		lu->l_mmap = mmap(0, lu->l_size, PROT_READ|PROT_WRITE,
		    MAP_SHARED|MAP_ALIGN, lu->l_fd, 0);
	} else {

		/*
		 * Since the default case will be to mmap
		 * in all files someone has asked that this
		 * lun not be mmap.
		 */
		lu->l_mmap = MAP_FAILED;
	}
	return (True);
error:
	if (lu->l_root)
		xml_tree_free(lu->l_root);
	if (lu->l_pid)
		free(lu->l_pid);
	if (lu->l_vid)
		free(lu->l_vid);
	if (lu->l_fd != -1)
		(void) close(lu->l_fd);
	return (False);
}

/*
 * []----
 * | cmd_common_free -- frees data stored in the cmd used in two different spots
 * |
 * | NOTE: The mutex which protects c_state must be held when this routine
 * | is called.
 * []----
 */
static void
cmd_common_free(t10_lu_impl_t *lu, t10_cmd_t *cmd)
{
	if (cmd->c_state != T10_Cmd_Free) {
		avl_remove(&lu->l_cmds, cmd);
		cmd->c_state = T10_Cmd_Free;
	}

	cmd->c_data	= 0;
	cmd->c_data_len = 0;

	if (cmd->c_emul_complete != NULL) {
		(*cmd->c_emul_complete)(cmd->c_emul_id);
		cmd->c_emul_complete = NULL;
	}
	if (cmd->c_cdb) {
		free(cmd->c_cdb);
		cmd->c_cdb = NULL;
	}
	if (cmd->c_cmd_sense) {
		free(cmd->c_cmd_sense);
		cmd->c_cmd_sense = NULL;
	}
}

/*
 * []----
 * | fallocate -- allocate blocks for file via file system interface
 * |
 * | This is a faster approach to allocating the blocks for a file.
 * | Instead of reading and then writing each block which will force the
 * | file system to allocate the data we simply ask the file system to
 * | allocate the space. Unfortunately not all file systems support this
 * | feature.
 * []----
 */
static Boolean_t
fallocate(int fd, off64_t len)
{
#ifdef FALLOCATE_SUPPORTED
#if defined(_LARGEFILE64_SOURCE) && !defined(_LP64)
	struct flock64 lck;

	lck.l_whence	= 0;
	lck.l_start	= 0;
	lck.l_len	= len;
	lck.l_type	= F_WRLCK;

	if (fcntl(fd, F_ALLOCSP64, &lck) == -1)
		return (False);
	else
		return (True);
#else
	struct flock lck;

	lck.l_whence	= 0;
	lck.l_start	= 0;
	lck.l_len	= len;
	lck.l_type	= F_WRLCK;

	if (fcntl(fd, F_ALLOCSP, &lck) == -1)
		return (False);
	else
		return (True);
#endif
#else
	return (False);
#endif
}

/*
 * []----
 * | find_lu_by_num -- AVL comparison which looks at LUN
 * []----
 */
static int
find_lu_by_num(const void *v1, const void *v2)
{
	t10_lu_impl_t	*l1	= (t10_lu_impl_t *)v1,
			*l2	= (t10_lu_impl_t *)v2;

	if (l1->l_targ_lun < l2->l_targ_lun)
		return (-1);
	if (l1->l_targ_lun > l2->l_targ_lun)
		return (1);
	return (0);
}

/*
 * []----
 * | find_lu_by_guid -- AVL comparison which looks at GUID
 * []----
 */
static int
find_lu_by_guid(const void *v1, const void *v2)
{
	t10_lu_common_t	*l1	= (t10_lu_common_t *)v1,
			*l2	= (t10_lu_common_t *)v2;
	int		i;

	if (l1->l_guid_len != l2->l_guid_len) {
		return ((l1->l_guid_len < l2->l_guid_len) ? -1 : 1);
	}
	for (i = 0; i < l1->l_guid_len; i++) {
		if (l1->l_guid[i] != l2->l_guid[i]) {
			return ((l1->l_guid[i] < l2->l_guid[i]) ? -1 : 1);
		}
	}
	return (0);
}

/*
 * []----
 * | find_lu_by_targ -- AVL comparison which looks at the target
 * |
 * | NOTE:
 * | The target value is the memory address of the per target structure.
 * | Therefore, it's not persistent in any manner, nor can any association
 * | be made between the target value and the initiator. It will be unique
 * | however which is all that we're looking for.
 * []----
 */
static int
find_lu_by_targ(const void *v1, const void *v2)
{
	t10_lu_impl_t	*l1	= (t10_lu_impl_t *)v1,
			*l2	= (t10_lu_impl_t *)v2;

	if ((uint64_t)(uintptr_t)l1->l_targ < (uint64_t)(uintptr_t)l2->l_targ)
		return (-1);
	else if ((uint64_t)(uintptr_t)l1->l_targ >
	    (uint64_t)(uintptr_t)l2->l_targ)
		return (1);
	else
		return (0);
}

/*
 * []----
 * | find_cmd_by_addr -- AVL comparison using the simplist of methods
 * []----
 */
static int
find_cmd_by_addr(const void *v1, const void *v2)
{
	uint64_t	cmd1	= (uint64_t)(uintptr_t)v1,
			cmd2	= (uint64_t)(uintptr_t)v2;

	if (cmd1 < cmd2)
		return (-1);
	else if (cmd1 > cmd2)
		return (1);
	else
		return (0);
}
