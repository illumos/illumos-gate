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

#include <picl.h>
#include <syslog.h>
#include <strings.h>
#include <alloca.h>
#include <pthread.h>
#include <synch.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>
#include <picltree.h>
#include <signal.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <libnvpair.h>
#include "fru_tag.h"
#include "fru_data_impl.h"
#include "fru_data.h"
#include "picld_pluginutil.h"

#pragma	init(frudata_plugin_register) /* .init section */

static	void		frudata_plugin_init(void);
static	void		frudata_plugin_fini(void);
static	container_tbl_t *container_table[TABLE_SIZE];

/*
 * Locking Stragtegy :
 * calling thread should hold the cont_tbl_lock during the course
 * of container table lookup. release the cont_tbl_lock on lookup
 * failure or on the condition wait.
 *
 * thread holding the container object rwlock should release lock
 * and signal to unblock threads blocked on the condition variable
 * upon i/o completion.
 *
 */

static pthread_mutex_t	cont_tbl_lock = PTHREAD_MUTEX_INITIALIZER;

static int add_row_to_table(hash_obj_t *, picl_nodehdl_t,
				packet_t *, container_tbl_t *);

static picld_plugin_reg_t frudata_reg_info = {
		PICLD_PLUGIN_VERSION_1,
		PICLD_PLUGIN_NON_CRITICAL,
		"SUNW_piclfrudata",
		frudata_plugin_init,	/* init entry point */
		frudata_plugin_fini	/* cleanup entry point */
};

/* initialization function */
static void
frudata_plugin_register(void)
{
	/* register plugin with daemon */
	if (picld_plugin_register(&frudata_reg_info) != PICL_SUCCESS) {
		syslog(LOG_ERR, "SUNW_piclfrudata plugin registration failed");
	}
}

static int
map_access_err(int err)
{
	switch (err) {
	case	ENFILE	:
		return (PICL_PROPEXISTS);
	case	EAGAIN	:
		return (PICL_NOSPACE);
	case	EPERM	:
		return (PICL_PERMDENIED);
	case	EEXIST	:
		return (PICL_PROPEXISTS);
	default	:
		return (PICL_FAILURE);
	}
}

/*
 * unlock_container_lock() should be always called by the thread holding the
 * container object lock. it will signal block thread waiting on the condition
 * variable.
 */

static void
unlock_container_lock(container_tbl_t	*cont_hash)
{
	(void) pthread_rwlock_unlock(&cont_hash->rwlock);
	(void) pthread_mutex_lock(&cont_tbl_lock);
	(void) pthread_cond_signal(&cont_hash->cond_var);
	(void) pthread_mutex_unlock(&cont_tbl_lock);
}


/* volatile callback read routine */
/* ARGSUSED */
static int
frudata_read_callback(ptree_rarg_t *rarg, void *buf)
{
	return (PICL_SUCCESS);
}

/*
 * called to get hash object for specified node and object type from
 * hash table.
 */
static container_tbl_t *
lookup_container_table(picl_nodehdl_t nodehdl, int object_type)
{
	int		index_to_hash;
	int		retval = PICL_SUCCESS;
	container_tbl_t	*first_hash;
	container_tbl_t	*next_hash;
	picl_nodehdl_t	parenthdl = 0;

	switch (object_type) {
	case	SECTION_NODE:
		retval = ptree_get_propval_by_name(nodehdl, PICL_PROP_PARENT,
		    &parenthdl, sizeof (picl_nodehdl_t));
		break;
	case	SEGMENT_NODE:
		retval = ptree_get_propval_by_name(nodehdl, PICL_PROP_PARENT,
		    &parenthdl, sizeof (picl_nodehdl_t));
		retval = ptree_get_propval_by_name(parenthdl, PICL_PROP_PARENT,
		    &parenthdl, sizeof (picl_nodehdl_t));
		break;
	case	CONTAINER_NODE :
		parenthdl = nodehdl;
		break;
	default	:
		return (NULL);
	}

	if (retval != PICL_SUCCESS) {
		return (NULL);
	}

	index_to_hash	= (parenthdl % TABLE_SIZE);

	first_hash	= container_table[index_to_hash];

	for (next_hash = first_hash; next_hash != NULL;
	    next_hash = next_hash->next) {
		if (parenthdl == next_hash->picl_hdl) {
			return (next_hash);
		}
	}
	return (NULL);
}

static int
lock_readwrite_lock(container_tbl_t *cont_obj, int operation)
{
	/* if write operation */
	if (operation == PICL_WRITE) {
		return (pthread_rwlock_trywrlock(&cont_obj->rwlock));
	}
	/* read operation */
	return (pthread_rwlock_tryrdlock(&cont_obj->rwlock));
}

/*
 * lock the container table, do lookup for the container object
 * in the container table. if container object found try to lock
 * the container object, if lock on container object is busy wait
 * on condition variable till the thread holding the container
 * object lock signal it.
 */

static container_tbl_t *
lock_container_lock(picl_nodehdl_t nodehdl, int object_type, int operation)
{
	container_tbl_t	*cont_obj = NULL;

	(void) pthread_mutex_lock(&cont_tbl_lock);

	while (((cont_obj = lookup_container_table(nodehdl, object_type)) !=
	    NULL) && (lock_readwrite_lock(cont_obj, operation) == EBUSY)) {
		pthread_cond_wait(&cont_obj->cond_var, &cont_tbl_lock);
	}

	(void) pthread_mutex_unlock(&cont_tbl_lock);

	return (cont_obj);
}

static hash_obj_t *
lookup_node_object(picl_nodehdl_t nodehdl, int	object_type,
    container_tbl_t *cont_tbl)
{
	int		index_to_hash;
	hash_obj_t	*first_hash;
	hash_obj_t	*next_hash;


	index_to_hash	= (nodehdl % TABLE_SIZE);

	first_hash	= &cont_tbl->hash_obj[index_to_hash];

	for (next_hash = first_hash->next; next_hash != NULL;
	    next_hash = next_hash->next) {
		if ((nodehdl == next_hash->picl_hdl) &&
		    (object_type == next_hash->object_type)) {
			return (next_hash);
		}
	}
	return (NULL);
}

/*
 * called to add newly created container hash table into container hash table.
 *
 */
static void
add_tblobject_to_container_tbl(container_tbl_t	*cont_tbl)
{
	int		cnt;
	int		index_to_hash;
	hash_obj_t	*hash_ptr;

	index_to_hash	= ((cont_tbl->picl_hdl) % TABLE_SIZE);

	cont_tbl->next	= container_table[index_to_hash];
	container_table[index_to_hash] = cont_tbl;
	hash_ptr	= cont_tbl->hash_obj;

	/* initialize the bucket of this container hash table. */

	for (cnt = 0; cnt < TABLE_SIZE; cnt++) {
		hash_ptr->next = NULL;
		hash_ptr->prev = NULL;
		hash_ptr++;
	}
	if (cont_tbl->next != NULL) {
		cont_tbl->next->prev = cont_tbl;
	}
}

static void
add_nodeobject_to_hashtable(hash_obj_t	*hash_obj, container_tbl_t *cont_tbl)
{
	int		index_to_hash;
	hash_obj_t	*hash_table;

	index_to_hash	= ((hash_obj->picl_hdl) % TABLE_SIZE);
	hash_table	= &cont_tbl->hash_obj[index_to_hash];

	hash_obj->next	= hash_table->next;
	hash_table->next = hash_obj;

	if (hash_obj->next != NULL) {
		hash_obj->next->prev = hash_obj;
	}
}

static container_tbl_t *
alloc_container_table(picl_nodehdl_t nodehdl)
{
	container_tbl_t		*cont_tbl;

	cont_tbl = malloc(sizeof (container_tbl_t));
	if (cont_tbl == NULL) {
		return (NULL);
	}

	cont_tbl->picl_hdl = nodehdl;

	cont_tbl->hash_obj = malloc(sizeof (hash_obj_t[TABLE_SIZE]));
	cont_tbl->next =	NULL;
	cont_tbl->prev =	NULL;

	if (cont_tbl->hash_obj == NULL) {
		(void) free(cont_tbl);
		return (NULL);
	}

	(void) pthread_rwlock_init(&cont_tbl->rwlock, NULL);
	(void) pthread_cond_init(&cont_tbl->cond_var, NULL);

	return (cont_tbl);
}

/*
 * called to allocate container node object for container property and a
 * container table.
 */

static hash_obj_t *
alloc_container_node_object(picl_nodehdl_t nodehdl)
{
	hash_obj_t		*hash_obj;
	fru_access_hdl_t	acc_hdl;
	container_node_t	*cont_node;

	/* open the container (call fruaccess) */
	acc_hdl = fru_open_container(nodehdl);
	if (acc_hdl == (container_hdl_t)0) {
		return (NULL);
	}

	/* allocate container node object */
	cont_node	= malloc(sizeof (container_node_t));
	if (cont_node == NULL) {
		return (NULL);
	}

	/* allocate container hash object */
	hash_obj	= malloc(sizeof (hash_obj_t));
	if (hash_obj == NULL) {
		(void) free(cont_node);
		return (NULL);
	}

	cont_node->cont_hdl	=	acc_hdl; /* fruaccess handle */
	cont_node->section_list	=	NULL;
	hash_obj->picl_hdl	=	nodehdl; /* picl node handle */
	hash_obj->object_type	=	CONTAINER_NODE;
	hash_obj->u.cont_node	=	cont_node;
	hash_obj->next		=	NULL;
	hash_obj->prev		=	NULL;

	return (hash_obj);
}

/*
 * called to allocate node object for section node.
 */

static hash_obj_t *
alloc_section_node_object(picl_nodehdl_t  nodehdl, section_t  *section)
{
	hash_obj_t		*hash_obj;
	section_node_t		*sec_node;

	/* allocate section node object */
	sec_node = malloc(sizeof (section_node_t));
	if (sec_node	== NULL) {
		return (NULL);
	}

	/* allocate section hash object */
	hash_obj = malloc(sizeof (hash_obj_t));
	if (hash_obj == NULL) {
		(void) free(sec_node);
		return (NULL);
	}

	sec_node->section_hdl	=	section->handle; /* fruaccess hdl. */
	sec_node->segment_list	=	NULL;
	sec_node->next		=	NULL;
	sec_node->num_of_segment =	-1;

	hash_obj->picl_hdl	=	nodehdl; /* picl node handle */
	hash_obj->object_type	=	SECTION_NODE;
	hash_obj->u.sec_node	=	sec_node;
	hash_obj->next		=	NULL;
	hash_obj->prev		=	NULL;

	return (hash_obj);
}

/*
 * called to allocate segment node object.
 */

static hash_obj_t *
alloc_segment_node_object(picl_nodehdl_t nodehdl, segment_t *segment)
{
	hash_obj_t	*hash_obj;
	segment_node_t	*seg_node;

	/* allocate segment node object */
	seg_node = malloc(sizeof (segment_node_t));
	if (seg_node == NULL) {
		return (NULL);
	}

	/* allocate segment hash object */
	hash_obj = malloc(sizeof (hash_obj_t));
	if (hash_obj == NULL) {
		free(seg_node);
		return (NULL);
	}

	/* fruaccess handle */
	seg_node->segment_hdl	= segment->handle;
	seg_node->packet_list	= NULL;
	seg_node->next		= NULL;
	seg_node->num_of_pkt	= -1;

	/* picl node handle */
	hash_obj->picl_hdl	= nodehdl;
	hash_obj->object_type	= SEGMENT_NODE;
	hash_obj->u.seg_node	= seg_node;
	hash_obj->next		= NULL;
	hash_obj->prev		= NULL;

	return (hash_obj);
}

/*
 * called to allocate node object for packet.
 */

static hash_obj_t *
alloc_packet_node_object(picl_nodehdl_t	nodehdl, packet_t *packet)
{
	hash_obj_t	*hash_obj;
	packet_node_t	*pkt_node;

	/* allocate packet node object */
	pkt_node = malloc(sizeof (packet_node_t));
	if (pkt_node == NULL) {
		return (NULL);
	}

	/* allocate packet hash object */
	hash_obj = malloc(sizeof (hash_obj_t));
	if (hash_obj == NULL) {
		free(pkt_node);
		return (NULL);
	}

	/* fruaccess handle */
	pkt_node->pkt_handle	= packet->handle;
	pkt_node->next		= NULL;

	hash_obj->picl_hdl	= nodehdl;	/* picl node handle */
	hash_obj->object_type	= PACKET_NODE;
	hash_obj->u.pkt_node	= pkt_node;
	hash_obj->next		= NULL;
	hash_obj->prev		= NULL;

	return (hash_obj);
}

/* add new section hash object to the section list */
static void
add_to_section_list(hash_obj_t  *container_hash, hash_obj_t *sect_hash)
{
	hash_obj_t	*next_hash;

	sect_hash->u.sec_node->container_hdl = container_hash->picl_hdl;
	if (container_hash->u.cont_node->section_list == NULL) {
		container_hash->u.cont_node->section_list = sect_hash;
		return;
	}

	for (next_hash = container_hash->u.cont_node->section_list;
	    next_hash->u.sec_node->next != NULL;
	    next_hash = next_hash->u.sec_node->next) {
		;
	}

	next_hash->u.sec_node->next = sect_hash;
}

/* add new segment hash object to the existing list */

static void
add_to_segment_list(hash_obj_t *parent_obj, hash_obj_t *child_obj)
{
	hash_obj_t	*next_hash;

	child_obj->u.seg_node->sec_nodehdl = parent_obj->picl_hdl;
	if (parent_obj->u.sec_node->segment_list == NULL) {
		parent_obj->u.sec_node->segment_list = child_obj;
		return;
	}

	for (next_hash = parent_obj->u.sec_node->segment_list;
	    next_hash->u.seg_node->next != NULL;
	    next_hash = next_hash->u.seg_node->next) {
		;
	}
	next_hash->u.seg_node->next = child_obj;
}

/*
 * called to add packet node object to the existing packet list.
 */
static void
add_to_packet_list(hash_obj_t *parent_obj, hash_obj_t *child_obj)
{
	hash_obj_t	*next_hash;

	if (parent_obj->u.seg_node->packet_list == NULL) {
		parent_obj->u.seg_node->packet_list = child_obj;
		return;
	}

	for (next_hash = parent_obj->u.seg_node->packet_list;
	    next_hash->u.pkt_node->next != NULL;
	    next_hash = next_hash->u.pkt_node->next) {
		;
	}
	next_hash->u.pkt_node->next = child_obj;
}

/*
 * free the packet hash list.
 */

static void
free_packet_list(hash_obj_t	*hash_obj, container_tbl_t *cont_tbl)
{
	hash_obj_t	*next_obj;
	hash_obj_t	*free_obj;

	/* packet hash object list */
	next_obj = hash_obj->u.seg_node->packet_list;
	while (next_obj != NULL) {
		free_obj = next_obj;
		next_obj = next_obj->u.pkt_node->next;
		if (free_obj->prev == NULL) { /* first node object */
			cont_tbl->hash_obj[(free_obj->picl_hdl %
			    TABLE_SIZE)].next = free_obj->next;
			if (free_obj->next != NULL) {
				free_obj->next->prev = NULL;
			}
		} else {
			free_obj->prev->next = free_obj->next;
			if (free_obj->next != NULL) {
				free_obj->next->prev = free_obj->prev;
			}
		}

		free(free_obj->u.pkt_node);
		free(free_obj);
	}
	hash_obj->u.seg_node->packet_list = NULL;
}

/*
 * free the segment hash node object.
 */

static void
free_segment_node(hash_obj_t *hash_obj, picl_nodehdl_t nodehdl,
    container_tbl_t *cont_tbl)
{
	hash_obj_t	*prev_hash_obj;
	hash_obj_t	*next_obj;

	/* segment hash object list */
	next_obj = hash_obj->u.sec_node->segment_list;
	if (next_obj == NULL) {
		return;
	}

	/* find the segment hash from the segment list to be deleted. */
	if (next_obj->picl_hdl == nodehdl) {
		hash_obj->u.sec_node->segment_list =
		    next_obj->u.seg_node->next;
	} else {
		while (next_obj != NULL) {
			if (next_obj->picl_hdl != nodehdl) {
				prev_hash_obj = next_obj;
				next_obj = next_obj->u.seg_node->next;
			} else {
				prev_hash_obj->u.seg_node->next =
				    next_obj->u.seg_node->next;
				break;
			}
		}

		if (next_obj == NULL) {
			return;
		}

	}

	if (next_obj->prev == NULL) {
		cont_tbl->hash_obj[(next_obj->picl_hdl % TABLE_SIZE)].next =
		    next_obj->next;
		if (next_obj->next != NULL)
			next_obj->next->prev = NULL;
	} else {
		next_obj->prev->next = next_obj->next;
		if (next_obj->next != NULL) {
			next_obj->next->prev = next_obj->prev;
		}
	}

	free_packet_list(next_obj, cont_tbl);
	free(next_obj->u.seg_node);
	free(next_obj);
}


/*
 * Description : frudata_delete_segment is called when volatile property
 *              delete_segment under class segment is accessed.
 *
 * Arguments   : ptree_warg_t is holds node handle of segment node and property
 *              handle of delete_segment property.
 */

/* ARGSUSED */
static int
frudata_delete_segment(ptree_warg_t *warg, const void *buf)
{
	int		retval;
	int		num_of_segment;
	int		num_of_pkt;
	int		pkt_cnt;
	int		count;
	packet_t	*pkt_buf;
	segment_t	*seg_buffer;
	hash_obj_t	*seg_hash;
	hash_obj_t	*pkt_hash;
	hash_obj_t	*hash_obj;
	fru_segdesc_t	*desc;
	picl_nodehdl_t	sec_nodehdl;
	container_tbl_t	*cont_tbl;
	fru_access_hdl_t seg_acc_hdl;
	fru_access_hdl_t new_sec_acc_hdl;

	cont_tbl = lock_container_lock(warg->nodeh, SEGMENT_NODE, PICL_WRITE);
	if (!cont_tbl) {
		return (PICL_FAILURE);
	}

	/* segment hash */
	hash_obj = lookup_node_object(warg->nodeh, SEGMENT_NODE, cont_tbl);
	if (hash_obj == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	/* fruaccess segment handle */
	seg_acc_hdl	= hash_obj->u.seg_node->segment_hdl;

	/* call fruaccess to get new section handle */
	if (fru_delete_segment(seg_acc_hdl, &new_sec_acc_hdl, &warg->cred)
	    == -1) {
		unlock_container_lock(cont_tbl);
		return (map_access_err(errno));
	}

	if (ptree_delete_node(warg->nodeh) != PICL_SUCCESS) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	if (ptree_destroy_node(warg->nodeh) != PICL_SUCCESS) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}


	/* get section node handle */
	sec_nodehdl = hash_obj->u.seg_node->sec_nodehdl;
	/* get section hash */
	hash_obj = lookup_node_object(sec_nodehdl, SECTION_NODE, cont_tbl);
	if (hash_obj == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	free_segment_node(hash_obj, warg->nodeh, cont_tbl);

	hash_obj->u.sec_node->num_of_segment = 0;

	/* call fruaccess with new section handle */
	num_of_segment = fru_get_num_segments(new_sec_acc_hdl, &warg->cred);
	if (num_of_segment <= 0) {
		unlock_container_lock(cont_tbl);
		return (PICL_SUCCESS);
	}

	seg_buffer = alloca(sizeof (segment_t) * num_of_segment);
	if (seg_buffer == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	/* get all the segments */
	retval = fru_get_segments(new_sec_acc_hdl, seg_buffer,
	    num_of_segment, &warg->cred);
	if (retval == -1) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	seg_hash = hash_obj->u.sec_node->segment_list;
	if (seg_hash == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_SUCCESS);
	}

	/* rebuild the segment list */
	for (count = 0; count < num_of_segment; count++) {
		desc	= (fru_segdesc_t *)&seg_buffer[count].descriptor;
		if (!(desc->field.field_perm & SEGMENT_READ)) {
			seg_hash = seg_hash->u.seg_node->next;
			continue;
		}

		if (desc->field.opaque) {
			seg_hash = seg_hash->u.seg_node->next;
			continue;
		}

		hash_obj->u.sec_node->num_of_segment++;

		seg_hash->u.seg_node->segment_hdl = seg_buffer[count].handle;

		num_of_pkt = fru_get_num_packets(seg_buffer[count].handle,
		    &warg->cred);
		if (num_of_pkt <= 0) {
			seg_hash = seg_hash->u.seg_node->next;
			continue;
		}

		pkt_buf	= alloca(sizeof (packet_t) * num_of_pkt);
		if (pkt_buf == NULL) {
			unlock_container_lock(cont_tbl);
			return (PICL_FAILURE);
		}

		retval = fru_get_packets(seg_buffer[count].handle, pkt_buf,
		    num_of_pkt, &warg->cred);
		if (retval == -1) {
			seg_hash = seg_hash->u.seg_node->next;
			continue;
		}

		pkt_hash = seg_hash->u.seg_node->packet_list;
		if (pkt_hash == NULL) {
			seg_hash = seg_hash->u.seg_node->next;
			continue;
		}

		/* rebuild the packet list */
		for (pkt_cnt = 0; pkt_cnt < num_of_pkt; pkt_cnt++) {
			pkt_hash->u.pkt_node->pkt_handle =
			    pkt_buf[pkt_cnt].handle;
			pkt_hash = pkt_hash->u.pkt_node->next;
		}

		seg_hash = seg_hash->u.seg_node->next;
		if (seg_hash == NULL) {
			break;
		}
	}

	/* updated with new section handle */
	hash_obj->u.sec_node->section_hdl = new_sec_acc_hdl;

	unlock_container_lock(cont_tbl);

	return (PICL_SUCCESS);
}

/*
 * Description : frudata_read_payload is called when volatile property
 *              payload is read.
 *
 * Arguments    : ptree_rarg_t  holds node handle of the table property.
 *              and property handle of the payload cell.
 *              p_buf contains payload data when function returns.
 *
 * Returns      : PICL_SUCCESS on success.
 *              PICL_FAILURE on failure.
 */

static int
frudata_read_payload(ptree_rarg_t *rarg, void *buf)
{
	int		num_bytes;
	hash_obj_t	*hash_obj;
	fru_access_hdl_t pkt_acc_hdl;
	container_tbl_t	*cont_tbl;


	cont_tbl = lock_container_lock(rarg->nodeh, SEGMENT_NODE, PICL_READ);
	if (!cont_tbl) {
		return (PICL_FAILURE);
	}

	hash_obj = lookup_node_object(rarg->proph, PACKET_NODE, cont_tbl);
	if (hash_obj == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	pkt_acc_hdl = hash_obj->u.pkt_node->pkt_handle;

	num_bytes = fru_get_payload(pkt_acc_hdl, buf,
	    hash_obj->u.pkt_node->paylen, &rarg->cred);
	if (num_bytes != hash_obj->u.pkt_node->paylen) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	unlock_container_lock(cont_tbl);

	return (PICL_SUCCESS);
}

/*
 * Description : frudata_write_payload is called when payload property cell
 *              is accessed.
 *
 * Arguments    : ptree_warg_t holds node handle of the packet-table.
 *              and property handle of the payload cell.
 *              p_buf contains payload data.
 *
 * Returns      : PICL_SUCCESS on success.
 *
 */

static int
frudata_write_payload(ptree_warg_t *warg, const void *buf)
{
	int		retval;
	hash_obj_t	*hash_obj;
	fru_access_hdl_t pkt_acc_hdl;
	container_tbl_t	*cont_tbl;

	cont_tbl = lock_container_lock(warg->nodeh, SEGMENT_NODE, PICL_WRITE);
	if (!cont_tbl) {
		return (PICL_FAILURE);
	}

	hash_obj = lookup_node_object(warg->proph, PACKET_NODE, cont_tbl);
	if (hash_obj == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	pkt_acc_hdl = hash_obj->u.pkt_node->pkt_handle;

	retval = fru_update_payload(pkt_acc_hdl, buf,
	    hash_obj->u.pkt_node->paylen,
	    &pkt_acc_hdl, &warg->cred);
	if (retval == -1) {
		unlock_container_lock(cont_tbl);
		return (map_access_err(errno));
	}

	hash_obj->u.pkt_node->pkt_handle = pkt_acc_hdl;

	unlock_container_lock(cont_tbl);

	return (PICL_SUCCESS);
}

/*
 * callback volatile function is called when tag volatile property
 * is accessed. this routine holds a read lock over the hash table
 * and do a lookup over the property handle i.e property handle of
 * the tag property passed in rarg parameter.
 * tag value is copied into the buffer (void *buf).
 */

static int
frudata_read_tag(ptree_rarg_t	*rarg, void *buf)
{
	int		retval;
	hash_obj_t	*hash_obj;
	picl_prophdl_t	rowproph;
	container_tbl_t	*cont_tbl;

	cont_tbl = lock_container_lock(rarg->nodeh, SEGMENT_NODE, PICL_READ);
	if (!cont_tbl) {
		return (PICL_FAILURE);
	}

	retval = ptree_get_next_by_row(rarg->proph, &rowproph);
	if (retval != PICL_SUCCESS) {
		unlock_container_lock(cont_tbl);
		return (retval);
	}

	hash_obj = lookup_node_object(rowproph, PACKET_NODE, cont_tbl);
	if (hash_obj == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	(void) memcpy(buf, &hash_obj->u.pkt_node->tag, sizeof (tag_t));

	unlock_container_lock(cont_tbl);
	return (PICL_SUCCESS);
}


/*
 * Description : create_packet_table() is called by fru_delete_packet_row(),
 *              to create a packet-table volatile property. it's called after
 *              deleting the packet-table. fru_delete_packet_row() calls
 *              frudata_read_packet_table() to add rows into the table.
 */

static int
create_packet_table(picl_nodehdl_t seghdl, picl_prophdl_t *thdl)
{
	int			retval;
	picl_prophdl_t		tblhdl;
	picl_nodehdl_t		prophdl;
	ptree_propinfo_t	prop;

	retval = ptree_create_table(&tblhdl);
	if (retval != PICL_SUCCESS) {
		return (retval);
	}

	prop.version = PTREE_PROPINFO_VERSION;
	prop.piclinfo.type =  PICL_PTYPE_TABLE;
	prop.piclinfo.accessmode = PICL_READ|PICL_WRITE;
	prop.piclinfo.size = sizeof (picl_prophdl_t);
	prop.read = NULL;
	prop.write = NULL;
	(void) strcpy(prop.piclinfo.name, PICL_PROP_PACKET_TABLE);

	retval = ptree_create_and_add_prop(seghdl, &prop, &tblhdl,
	    &prophdl);
	if (retval != PICL_SUCCESS) {
		return (retval);
	}

	/* hold the table handle */
	*thdl = tblhdl;

	return (PICL_SUCCESS);
}

/*
 * Description : frudata_delete_packet is called when write operation is
 *		performed on tag volatile property.
 *
 *
 * Arguments    : ptree_warg_t holds node handle to the segment node.
 *              and property handle of the tag cell in the packet table to be
 *		deleted.
 *              buf contains the tag data + plus DELETE_KEY_TAG
 *
 * Returns      : PICL_SUCCESS on success
 *
 */

static int
frudata_delete_packet(ptree_warg_t *warg, const void *buf)
{
	int		count = 0;
	int		retval;
	int		num_of_pkt;
	uint64_t	tag;
	packet_t	*packet;
	hash_obj_t	*seg_hash_obj;
	hash_obj_t	*pkt_hash_obj;
	container_tbl_t	*cont_tbl;
	picl_prophdl_t	tblhdl;
	picl_prophdl_t	rowproph;
	fru_access_hdl_t new_seg_acc_hdl;

	cont_tbl = lock_container_lock(warg->nodeh, SEGMENT_NODE, PICL_WRITE);
	if (!cont_tbl) {
		return (PICL_FAILURE);
	}

	/* get the payload property handle */
	retval = ptree_get_next_by_row(warg->proph, &rowproph);
	if (retval != PICL_SUCCESS) {
		unlock_container_lock(cont_tbl);
		return (retval);
	}

	/* do lookup on payload property handle */
	pkt_hash_obj = lookup_node_object(rowproph, PACKET_NODE, cont_tbl);
	if (pkt_hash_obj == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	/* verify the tag */
	tag = pkt_hash_obj->u.pkt_node->tag.raw_data;
	tag &= FRUDATA_DELETE_TAG_MASK;
	tag |= FRUDATA_DELETE_TAG_KEY;
	if (*(uint64_t *)buf != tag) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	/* call fruaccess module */
	retval = fru_delete_packet(pkt_hash_obj->u.pkt_node->pkt_handle,
	    &new_seg_acc_hdl, &warg->cred);
	if (retval == -1) {
		unlock_container_lock(cont_tbl);
		return (map_access_err(errno));
	}

	/* delete the packet table */
	retval = ptree_get_prop_by_name(warg->nodeh, PICL_PROP_PACKET_TABLE,
	    &tblhdl);
	if (retval != PICL_SUCCESS) {
		unlock_container_lock(cont_tbl);
		return (retval);
	}

	retval = ptree_delete_prop(tblhdl);
	if (retval != PICL_SUCCESS) {
		unlock_container_lock(cont_tbl);
		return (retval);
	}

	retval = ptree_destroy_prop(tblhdl);
	if (retval != PICL_SUCCESS) {
		unlock_container_lock(cont_tbl);
		return (retval);
	}


	seg_hash_obj = lookup_node_object(warg->nodeh, SEGMENT_NODE,
	    cont_tbl);
	if (seg_hash_obj == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	/* free all packet hash object */
	free_packet_list(seg_hash_obj, cont_tbl);

	/* recreate the packet table */
	retval = create_packet_table(warg->nodeh, &tblhdl);
	if (retval != PICL_SUCCESS) {
		unlock_container_lock(cont_tbl);
		return (retval);
	}

	seg_hash_obj->u.seg_node->segment_hdl = new_seg_acc_hdl;

	seg_hash_obj->u.seg_node->num_of_pkt = 0;

	num_of_pkt = fru_get_num_packets(new_seg_acc_hdl, &warg->cred);
	if (num_of_pkt == -1) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	if (num_of_pkt == 0) {
		unlock_container_lock(cont_tbl);
		return (PICL_SUCCESS);
	}

	packet = alloca(sizeof (packet_t) * num_of_pkt);
	if (packet == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	retval = fru_get_packets(new_seg_acc_hdl, packet,
	    num_of_pkt, &warg->cred);
	if (retval == -1) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	/* rebuild the packet hash object */
	for (count = 0; count < num_of_pkt; count++) {
		(void) add_row_to_table(seg_hash_obj, tblhdl, packet+count,
		    cont_tbl);
	}

	seg_hash_obj->u.seg_node->num_of_pkt = num_of_pkt;

	(void) ptree_update_propval_by_name(warg->nodeh, PICL_PROP_NUM_TAGS,
	    &num_of_pkt, sizeof (uint32_t));

	unlock_container_lock(cont_tbl);

	return (PICL_SUCCESS);
}

/*
 * called from frudata_delete_packet(), frudata_add_packet(),
 * frudata_read_packet() callback routine to add packet into
 * the packet table. it also create hash node object for each
 * individual packet and add the object to the packet list.
 */

static int
add_row_to_table(hash_obj_t *seg_obj, picl_nodehdl_t tblhdl, packet_t *pkt,
    container_tbl_t *cont_tbl)
{
	int			retval;
	int			paylen;
	size_t			tag_size;
	hash_obj_t		*hash_obj;
	fru_tagtype_t		tagtype;
	picl_prophdl_t		prophdl[NUM_OF_COL_IN_PKT_TABLE];
	ptree_propinfo_t	prop;

	prop.version = PTREE_PROPINFO_VERSION;

	prop.piclinfo.type =  PICL_PTYPE_BYTEARRAY;
	prop.piclinfo.accessmode = PICL_READ|PICL_WRITE|PICL_VOLATILE;
	prop.piclinfo.size = sizeof (fru_tag_t);
	prop.read = frudata_read_tag;
	prop.write = frudata_delete_packet;

	/* tag property node */
	(void) strcpy(prop.piclinfo.name, PICL_PROP_TAG);

	paylen = get_payload_length((void *)&pkt->tag);
	if (paylen < 0) {
		return (PICL_FAILURE);
	}

	retval = ptree_create_prop(&prop, NULL, &prophdl[0]);
	if (retval != PICL_SUCCESS) {
		return (retval);
	}


	/* payload property node */
	prop.piclinfo.type =  PICL_PTYPE_BYTEARRAY;
	prop.piclinfo.size = paylen;
	(void) strcpy(prop.piclinfo.name, PICL_PROP_PAYLOAD);
	prop.piclinfo.accessmode = PICL_READ|PICL_WRITE|PICL_VOLATILE;
	prop.read = frudata_read_payload;
	prop.write = frudata_write_payload;

	retval = ptree_create_prop(&prop, NULL, &prophdl[1]);
	if (retval != PICL_SUCCESS) {
		return (retval);
	}

	hash_obj = alloc_packet_node_object(prophdl[1], pkt);
	if (hash_obj == NULL) {
		return (PICL_FAILURE);
	}

	retval = ptree_add_row_to_table(tblhdl, NUM_OF_COL_IN_PKT_TABLE,
	    prophdl);
	if (retval != PICL_SUCCESS) {
		free(hash_obj);
		return (retval);
	}

	tagtype = get_tag_type((fru_tag_t *)&pkt->tag);
	if (tagtype == -1) {
		return (PICL_FAILURE);
	}

	tag_size = get_tag_size(tagtype);
	if (tag_size == (size_t)-1) {
		return (PICL_FAILURE);
	}

	hash_obj->u.pkt_node->paylen = paylen;
	hash_obj->u.pkt_node->tag.raw_data = 0;
	(void) memcpy(&hash_obj->u.pkt_node->tag, &pkt->tag, tag_size);

	add_nodeobject_to_hashtable(hash_obj, cont_tbl);

	add_to_packet_list(seg_obj, hash_obj);

	return (PICL_SUCCESS);
}

/*
 * called from frudata_read_segment() callback routine. it's called after
 * creating the packet table under class segment. this routine reads the
 * segment data to get total number of packets in the segments and add
 * the tag and payload data into the table. it calls add_row_to_table
 * routine to add individual row into the packet table.
 */

static int
frudata_read_packet(picl_nodehdl_t nodeh, picl_prophdl_t *tblhdl,
    container_tbl_t *cont_tbl, door_cred_t *cred)
{
	int		cnt;
	int		retval;
	int		num_of_pkt;
	packet_t	*packet;
	hash_obj_t	*hash_obj;
	fru_access_hdl_t seg_acc_hdl;

	hash_obj = lookup_node_object(nodeh, SEGMENT_NODE, cont_tbl);
	if (hash_obj == NULL) {
		return (PICL_FAILURE);
	}

	if (hash_obj->u.seg_node->num_of_pkt == -1) {
		/* get the access handle */
		seg_acc_hdl = hash_obj->u.seg_node->segment_hdl;
		/* get total number of packets */
		num_of_pkt = fru_get_num_packets(seg_acc_hdl, cred);
		if (num_of_pkt < 0) {
			hash_obj->u.seg_node->num_of_pkt = 0;
			return (map_access_err(errno));
		}

		if (num_of_pkt == 0) {
			hash_obj->u.seg_node->num_of_pkt = 0;
			return (0);
		}

		/* allocate buffer */
		packet = alloca(sizeof (packet_t) * num_of_pkt);
		if (packet == NULL) {
			hash_obj->u.seg_node->num_of_pkt = 0;
			return (0);
		}

		/* get all the packet into the packet buffer */
		retval = fru_get_packets(seg_acc_hdl, packet, num_of_pkt, cred);
		if (retval == -1) {
			return (0);
		}

		/* add payload and tag into the table. */
		for (cnt = 0; cnt < num_of_pkt; cnt++) {
			(void) add_row_to_table(hash_obj, *tblhdl, packet+cnt,
			    cont_tbl);
		}

		hash_obj->u.seg_node->num_of_pkt = num_of_pkt;
	}
	return (0);
}


/*
 * Description  : frudata_add_packet is called when add-packet volatile
 *              property is accessed.
 *
 * Arguments    : ptree_warg_t holds node handle of the segment node and
 *              property handle of add-packet property.
 *              p_buf- contains packet data to be added.
 *
 * Return       : PICL_SUCCESS on success.
 *
 */

/* ARGSUSED */
static int
frudata_add_packet(ptree_warg_t *warg, const void *buf)
{
	size_t		tag_size;
	int		paylen;
	int		retval;
	int		num_of_pkt;
	int		cnt;
	packet_t	packet;
	packet_t	*pkt_buf;
	hash_obj_t	*hash_obj;
	hash_obj_t	*pkt_hash;
	container_tbl_t	*cont_tbl;
	fru_tagtype_t	tagtype;
	picl_prophdl_t	tblhdl;
	fru_access_hdl_t seg_acc_hdl;
	fru_access_hdl_t new_seg_acc_hdl;

	cont_tbl = lock_container_lock(warg->nodeh, SEGMENT_NODE, PICL_WRITE);
	if (!cont_tbl) {
		return (PICL_FAILURE);
	}

	hash_obj = lookup_node_object(warg->nodeh, SEGMENT_NODE, cont_tbl);
	if (hash_obj == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	seg_acc_hdl = hash_obj->u.seg_node->segment_hdl;

	tagtype = get_tag_type((void *)buf);
	if (tagtype == -1) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	tag_size = get_tag_size(tagtype);
	if (tag_size == (size_t)-1) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	paylen = get_payload_length((void *)buf);
	if (paylen == -1) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	packet.tag = 0;
	(void) memcpy(&packet.tag, buf, tag_size);

	retval = fru_append_packet(seg_acc_hdl, &packet, (char *)buf + tag_size,
	    paylen, &new_seg_acc_hdl, &warg->cred);
	if (retval == -1) {
		unlock_container_lock(cont_tbl);
		return (map_access_err(errno));
	}

	retval = ptree_get_propval_by_name(warg->nodeh,
	    PICL_PROP_PACKET_TABLE, &tblhdl, sizeof (picl_prophdl_t));
	if (retval != PICL_SUCCESS) {
		unlock_container_lock(cont_tbl);
		return (retval);
	}
	retval = add_row_to_table(hash_obj, tblhdl, &packet, cont_tbl);
	if (retval != PICL_SUCCESS) {
		unlock_container_lock(cont_tbl);
		return (retval);
	}

	num_of_pkt = fru_get_num_packets(new_seg_acc_hdl, &warg->cred);
	if (num_of_pkt == -1) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	pkt_buf = alloca(sizeof (packet_t) * num_of_pkt);
	if (pkt_buf == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	retval = fru_get_packets(new_seg_acc_hdl, pkt_buf,
	    num_of_pkt, &warg->cred);
	if (retval == -1) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	pkt_hash	= hash_obj->u.seg_node->packet_list;
	if (pkt_hash == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	for (cnt = 0; cnt < num_of_pkt; cnt++) {
		pkt_hash->u.pkt_node->pkt_handle = pkt_buf[cnt].handle;
		pkt_hash = pkt_hash->u.pkt_node->next;
	}

	hash_obj->u.seg_node->num_of_pkt = num_of_pkt;

	(void) ptree_update_propval_by_name(warg->nodeh, PICL_PROP_NUM_TAGS,
	    &num_of_pkt, sizeof (uint32_t));

	unlock_container_lock(cont_tbl);

	return (PICL_SUCCESS);
}

static void
freeup(picl_nodehdl_t nodeh)
{
	(void) ptree_delete_node(nodeh);
	(void) ptree_destroy_node(nodeh);
}

/*
 * called by frudata_read_segment() and fru_data_add_segment() callback routine.
 * it's called to create a segment node and all it's property beneith the
 * segment node in the picl tree.
 */

static int
create_segment_node(hash_obj_t *sec_obj, picl_nodehdl_t sec_node,
    segment_t *segment, container_tbl_t *cont_tbl, door_cred_t *cred)
{

	int			retval;
	char			segname[SEG_NAME_LEN + 1];
	uint32_t		numoftags = 0;
	uint32_t		protection;
	hash_obj_t		*hash_obj;
	picl_nodehdl_t		nodehdl;
	picl_prophdl_t		prophdl;
	picl_nodehdl_t		tblhdl;
	ptree_propinfo_t	prop;

	(void) strlcpy(segname, segment->name, SEG_NAME_LEN + 1);
	segname[SEG_NAME_LEN] = '\0';

	if (!(isprint(segname[0]) || isprint(segname[1]))) {
		return (PICL_FAILURE);
	}

	if (ptree_create_node(segname, PICL_CLASS_SEGMENT, &nodehdl)
	    != PICL_SUCCESS) {
		return (PICL_FAILURE);
	}


	/* create property node */
	prop.version = PTREE_PROPINFO_VERSION;
	prop.piclinfo.accessmode = PICL_READ;
	prop.read		= NULL;
	prop.write		= NULL;

	prop.piclinfo.type =  PICL_PTYPE_UNSIGNED_INT;
	prop.piclinfo.size = sizeof (uint32_t);

	/* descriptor property */
	(void) strcpy(prop.piclinfo.name, PICL_PROP_DESCRIPTOR);
	if (ptree_create_and_add_prop(nodehdl, &prop, &segment->descriptor,
	    &prophdl) != PICL_SUCCESS) {
		freeup(nodehdl);
		return (PICL_FAILURE);
	}


	/* offset property */
	(void) strcpy(prop.piclinfo.name, PICL_PROP_OFFSET);
	if (ptree_create_and_add_prop(nodehdl, &prop, &segment->offset,
	    &prophdl) != PICL_SUCCESS) {
		freeup(nodehdl);
		return (PICL_FAILURE);
	}


	/* length property */
	(void) strcpy(prop.piclinfo.name, PICL_PROP_LENGTH);
	if (ptree_create_and_add_prop(nodehdl, &prop, &segment->length,
	    &prophdl) != PICL_SUCCESS) {
		freeup(nodehdl);
		return (PICL_FAILURE);
	}

	/* Number of Tags */
	(void) strcpy(prop.piclinfo.name, PICL_PROP_NUM_TAGS);
	if (ptree_create_and_add_prop(nodehdl, &prop, &numoftags, &prophdl)
	    != PICL_SUCCESS) {
		freeup(nodehdl);
		return (PICL_FAILURE);
	}

	if (create_packet_table(nodehdl, &tblhdl) != PICL_SUCCESS) {
		freeup(nodehdl);
		return (PICL_FAILURE);
	}

	retval = ptree_get_propval_by_name(sec_node,
	    PICL_PROP_PROTECTED, &protection, sizeof (uint32_t));
	if (retval != PICL_SUCCESS) {
		freeup(nodehdl);
		return (PICL_FAILURE);
	}

	if (protection == 0) {	/* to be added only read/write section */
		/* delete segment volatile property */
		prop.piclinfo.type =  PICL_PTYPE_UNSIGNED_INT;
		prop.piclinfo.size = sizeof (uint32_t);
		prop.piclinfo.accessmode = PICL_WRITE|PICL_VOLATILE;
		prop.write = frudata_delete_segment;
		prop.read = frudata_read_callback;

		(void) strcpy(prop.piclinfo.name, PICL_PROP_DELETE_SEGMENT);
		if (ptree_create_and_add_prop(nodehdl, &prop, NULL, &prophdl)
		    != PICL_SUCCESS) {
			freeup(nodehdl);
			return (PICL_FAILURE);
		}


		/* add packet volatile property */
		prop.piclinfo.type =  PICL_PTYPE_BYTEARRAY;
		prop.piclinfo.size = segment->length; /* segment length */
		prop.piclinfo.accessmode = PICL_READ|PICL_WRITE|PICL_VOLATILE;
		prop.read = frudata_read_callback;
		prop.write = frudata_add_packet;

		(void) strcpy(prop.piclinfo.name, PICL_PROP_ADD_PACKET);
		if (ptree_create_and_add_prop(nodehdl, &prop, NULL, &prophdl)
		    != PICL_SUCCESS) {
			freeup(nodehdl);
			return (PICL_FAILURE);
		}
	}

	if (ptree_add_node(sec_node, nodehdl) != PICL_SUCCESS) {
		freeup(nodehdl);
		return (PICL_FAILURE);
	}

	hash_obj = alloc_segment_node_object(nodehdl, segment);
	if (hash_obj == NULL) {
		freeup(nodehdl);
		return (PICL_FAILURE);
	}

	add_nodeobject_to_hashtable(hash_obj, cont_tbl);

	add_to_segment_list(sec_obj, hash_obj);

	retval = frudata_read_packet(nodehdl, &tblhdl, cont_tbl, cred);
	if (retval != 0) {
		return (PICL_SUCCESS);
	}

	(void) ptree_update_propval_by_name(nodehdl, PICL_PROP_NUM_TAGS,
	    &hash_obj->u.seg_node->num_of_pkt, sizeof (uint32_t));

	return (PICL_SUCCESS);
}

/*
 * Description  :frudata_read_segment is called when num_segment volatile
 *              property is accessed.
 *
 * Arguments    : ptree_rarg_t  contains node handle of the section node.
 *                      and property node of num_segments.
 *              void * will hold number of segment.
 *
 * Returns      : PICL_SUCCESS on success.
 *              PICL_FAILURE on failure.
 */

static int
frudata_read_segment(ptree_rarg_t *rarg, void *buf)
{
	int		num_of_segment;
	int		cnt;
	int		retval;
	segment_t	*segment;
	hash_obj_t	*hash_obj;
	fru_segdesc_t	*desc;
	fru_access_hdl_t sec_acc_hdl;
	container_tbl_t	*cont_tbl;

	cont_tbl = lock_container_lock(rarg->nodeh, SECTION_NODE, PICL_READ);
	if (!cont_tbl) {
		return (PICL_FAILURE);
	}

	hash_obj = lookup_node_object(rarg->nodeh, SECTION_NODE, cont_tbl);
	if (hash_obj == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	if (hash_obj->u.sec_node->num_of_segment == -1) {
		sec_acc_hdl	= hash_obj->u.sec_node->section_hdl;

		hash_obj->u.sec_node->num_of_segment = 0;

		num_of_segment = fru_get_num_segments(sec_acc_hdl,
		    &rarg->cred);
		if (num_of_segment < 0) {
			*(int *)buf = 0;
			unlock_container_lock(cont_tbl);
			return (PICL_FAILURE);
		}

		if (num_of_segment == 0) {
			*(int *)buf = 0;
			unlock_container_lock(cont_tbl);
			return (PICL_SUCCESS);
		}

		segment = alloca(sizeof (segment_t) * num_of_segment);
		if (segment == NULL) {
			*(int *)buf = 0;
			unlock_container_lock(cont_tbl);
			return (PICL_SUCCESS);
		}

		retval = fru_get_segments(sec_acc_hdl, segment,
		    num_of_segment, &rarg->cred);
		if (retval == -1) {
			*(int *)buf = 0;
			unlock_container_lock(cont_tbl);
			return (PICL_SUCCESS);
		}

		for (cnt = 0; cnt < num_of_segment; cnt++) {

			desc	= (fru_segdesc_t *)&segment[cnt].descriptor;
			if (!(desc->field.field_perm & SEGMENT_READ)) {
				continue;
			}

			/* if opaque segment don't create segment node */
			if (desc->field.opaque) {
				continue;
			}
			(void) create_segment_node(hash_obj, rarg->nodeh,
			    &segment[cnt], cont_tbl, &rarg->cred);
			hash_obj->u.sec_node->num_of_segment++;
		}
	}

	/* return number of segment in the section */
	*(int *)buf = hash_obj->u.sec_node->num_of_segment;

	unlock_container_lock(cont_tbl);

	return (PICL_SUCCESS);
}


/*
 * Description : frudata_add_segment is called when volatile property
 *              add_segment under class node section is accessed.
 *
 * Arguments    : ptree_warg_t  holds node handle for the section node.
 *              property handle for the add_segment property.
 *
 * Returns      : PICL_SUCCESS on success.
 *              PICL_FAILURE on failure.
 */

static int
frudata_add_segment(ptree_warg_t *warg, const void *buf)
{
	int		retval;
	int		cnt;
	int		num_of_segment;
	segment_t	*seg_buf;
	segment_t	segment;
	hash_obj_t	*seg_hash;
	hash_obj_t	*hash_obj;
	container_tbl_t	*cont_tbl;
	fru_segdef_t	*seg_def;
	fru_segdesc_t	*desc;
	fru_access_hdl_t new_sec_acc_hdl;

	seg_def	= (fru_segdef_t *)buf;

	/* initialize segment_t */
	segment.handle	= 0;
	(void) memcpy(segment.name, seg_def->name, SEG_NAME_LEN);
	segment.descriptor =  seg_def->desc.raw_data;
	segment.length	= seg_def->size;	/* segment length */
	segment.offset = seg_def->address;	/* segment offset */

	desc    = (fru_segdesc_t *)&segment.descriptor;
	if (!(desc->field.field_perm & SEGMENT_READ)) {
		return (PICL_PERMDENIED);
	}

	cont_tbl = lock_container_lock(warg->nodeh, SECTION_NODE, PICL_WRITE);
	if (!cont_tbl) {
		return (PICL_FAILURE);
	}

	hash_obj = lookup_node_object(warg->nodeh, SECTION_NODE, cont_tbl);
	if (hash_obj == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	/* call fruaccess module, get the new section handle. */
	retval = fru_add_segment(hash_obj->u.sec_node->section_hdl,
	    &segment, &new_sec_acc_hdl, &warg->cred);
	if (retval == -1) {
		unlock_container_lock(cont_tbl);
		return (map_access_err(errno));
	}

	/* call access module with new section handle */
	num_of_segment = fru_get_num_segments(new_sec_acc_hdl, &warg->cred);

	seg_buf	= alloca(sizeof (segment_t) * num_of_segment);
	if (seg_buf == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	retval = fru_get_segments(new_sec_acc_hdl, seg_buf,
	    num_of_segment, &warg->cred);
	if (retval ==  -1) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	segment.offset	= seg_buf[(num_of_segment -1)].offset;
	segment.handle = seg_buf[(num_of_segment-1)].handle;

	(void) create_segment_node(hash_obj, warg->nodeh, &segment,
	    cont_tbl, &warg->cred);

	/* rebuild  segment list */
	seg_hash = hash_obj->u.sec_node->segment_list;
	if (seg_hash == NULL) {
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	hash_obj->u.sec_node->num_of_segment = 0;

	for (cnt = 0; cnt < num_of_segment; cnt++) {
		desc	= (fru_segdesc_t *)&seg_buf[cnt].descriptor;
		if (!(desc->field.field_perm & SEGMENT_READ)) {
			continue;
		}

		/* if opaque segment don't create segment node */
		if (desc->field.opaque) {
			continue;
		}

		seg_hash->u.seg_node->segment_hdl =
		    seg_buf[cnt].handle;
		seg_hash = seg_hash->u.seg_node->next;
		hash_obj->u.sec_node->num_of_segment++;
	}

	/* update with new section handle */
	hash_obj->u.sec_node->section_hdl = new_sec_acc_hdl;

	unlock_container_lock(cont_tbl);

	return (PICL_SUCCESS);
}

/*
 * called from frudata_write_section() callback routine to create
 * section node and all the  property under class section. it also
 * allocate hash node object for each section in the container and
 * add the section node object in the section list.
 */

static int
create_section_node(picl_nodehdl_t nodehdl, int section_count,
    section_t *section, container_tbl_t *cont_tbl)
{
	char		sec_name[SECNAMESIZE];
	hash_obj_t	*hash_obj;
	hash_obj_t	*cont_hash;
	picl_nodehdl_t	chld_node;
	picl_prophdl_t	prophdl;
	ptree_propinfo_t prop;

	(void) snprintf(sec_name, SECNAMESIZE, "section%d", section_count);

	if (ptree_create_node(sec_name, PICL_CLASS_SECTION, &chld_node)
	    != PICL_SUCCESS) {
		return (PICL_FAILURE);
	}
	prop.version		= PTREE_PROPINFO_VERSION;
	prop.piclinfo.type	= PICL_PTYPE_UNSIGNED_INT;
	prop.piclinfo.accessmode = PICL_READ;
	prop.piclinfo.size	= sizeof (uint32_t);
	prop.read		= NULL;
	prop.write		= NULL;

	/* offset */
	(void) strcpy(prop.piclinfo.name, PICL_PROP_OFFSET);
	if (ptree_create_and_add_prop(chld_node, &prop, &section->offset,
	    &prophdl) != PICL_SUCCESS) {
		freeup(chld_node);
		return (PICL_FAILURE);
	}

	/* length */
	(void) strcpy(prop.piclinfo.name, PICL_PROP_LENGTH);
	if (ptree_create_and_add_prop(chld_node, &prop, &section->length,
	    &prophdl) != PICL_SUCCESS) {
		freeup(chld_node);
		return (PICL_FAILURE);
	}


	/* protected */
	(void) strcpy(prop.piclinfo.name, PICL_PROP_PROTECTED);
	if (ptree_create_and_add_prop(chld_node, &prop, &section->protection,
	    &prophdl) != PICL_SUCCESS) {
		freeup(chld_node);
		return (PICL_FAILURE);
	}

	prop.piclinfo.accessmode	= PICL_READ|PICL_VOLATILE;
	prop.read	= frudata_read_segment;

	(void) strcpy(prop.piclinfo.name, PICL_PROP_NUM_SEGMENTS);

	if (ptree_create_and_add_prop(chld_node, &prop, NULL, &prophdl)
	    != PICL_SUCCESS) {
		freeup(chld_node);
		return (PICL_FAILURE);
	}


	prop.piclinfo.type = PICL_PTYPE_BYTEARRAY;
	prop.piclinfo.size = sizeof (fru_segdef_t);

	prop.piclinfo.accessmode = PICL_WRITE|PICL_READ|PICL_VOLATILE;
	prop.write = frudata_add_segment; /* callback routine */
	prop.read = frudata_read_callback;

	(void) strcpy(prop.piclinfo.name, PICL_PROP_ADD_SEGMENT);
	/* add-segment prop if read/write section */
	if (section->protection == 0) {
		if (ptree_create_and_add_prop(chld_node, &prop, NULL, &prophdl)
		    != PICL_SUCCESS) {
			freeup(chld_node);
			return (PICL_FAILURE);
		}
	}

	if (ptree_add_node(nodehdl, chld_node) != PICL_SUCCESS) {
		freeup(chld_node);
		return (PICL_FAILURE);
	}

	/* lookup for container handle */
	cont_hash = lookup_node_object(nodehdl, CONTAINER_NODE, cont_tbl);
	if (cont_hash == NULL) {
		freeup(chld_node);
		return (PICL_FAILURE);
	}

	hash_obj = alloc_section_node_object(chld_node, section);
	if (hash_obj == NULL) {
		freeup(chld_node);
		return (PICL_FAILURE);
	}

	add_nodeobject_to_hashtable(hash_obj, cont_tbl);

	add_to_section_list(cont_hash, hash_obj);
	return (PICL_SUCCESS);
}


/*
 * Description  :frudata_write_section is called when volatile container
 *              property is accessed. it reads the section table associated
 *              with the specified node handle(container) in ptree_rarg_t.
 *              it calls search_root_node to search the node handle to open the
 *              device associated with the node handle. it creates section
 *              node and it's associated property. it also creates
 *              volatile property num_segments.
 *
 * Argument     : ptree_rarg_t  : contains node handle of fru container the
 *                                                      container.
 *              property handle of the container.
 *
 * Return       : PICL_SUCCESS  on success.
 *
 */

/* ARGSUSED */

static int
frudata_write_section(ptree_warg_t *warg, const void *buf)
{
	int		retval;
	int		num_of_section;
	int		count;
	section_t	*section;
	hash_obj_t	*hash_obj;
	container_tbl_t	*cont_tbl = NULL;
	fru_access_hdl_t cont_acc_hdl;

	(void) pthread_mutex_lock(&cont_tbl_lock);

	/*
	 * if lookup succeed return from this function with PICL_SUCCESS
	 * because first write operation has already occurred on this container,
	 * it also means that the container has been already initialzed.
	 */

	cont_tbl = lookup_container_table(warg->nodeh, CONTAINER_NODE);
	if (cont_tbl != NULL) { /* found the hash obj in the hash table */
		(void) pthread_mutex_unlock(&cont_tbl_lock);
		return (PICL_SUCCESS);
	}

	/*
	 * lookup failed that means this is first write on the
	 * container property. allocate a new container hash table for this
	 * new container and add to the cont_tbl hash table.
	 */

	cont_tbl = alloc_container_table(warg->nodeh);
	if (cont_tbl == NULL) {
		(void) pthread_mutex_unlock(&cont_tbl_lock);
		return (map_access_err(errno));
	}

	hash_obj = alloc_container_node_object(warg->nodeh);
	if (hash_obj == NULL) {
		(void) pthread_mutex_unlock(&cont_tbl_lock);
		free(cont_tbl->hash_obj);
		free(cont_tbl);
		return (map_access_err(errno));
	}

	/* add container table object to container table */
	add_tblobject_to_container_tbl(cont_tbl);

	/* add the hash object to container hash table. */
	add_nodeobject_to_hashtable(hash_obj, cont_tbl);

	while (pthread_rwlock_trywrlock(&cont_tbl->rwlock) == EBUSY) {
		pthread_cond_wait(&cont_tbl->cond_var, &cont_tbl_lock);
	}

	(void) pthread_mutex_unlock(&cont_tbl_lock);

	/* fruaccess  handle */
	cont_acc_hdl	= hash_obj->u.cont_node->cont_hdl;

	num_of_section = fru_get_num_sections(cont_acc_hdl, &warg->cred);

	if (num_of_section == -1) {
		free(hash_obj);
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	section	= alloca(num_of_section * sizeof (section_t));

	retval = fru_get_sections(cont_acc_hdl, section,
	    num_of_section, &warg->cred);
	if (retval == -1) {
		free(hash_obj);
		unlock_container_lock(cont_tbl);
		return (PICL_FAILURE);
	}

	hash_obj->u.cont_node->num_of_section = num_of_section;

	for (count = 0; count < num_of_section; count++) {
		(void) create_section_node(warg->nodeh, count,
		    section + count, cont_tbl);
	}

	unlock_container_lock(cont_tbl);

	return (PICL_SUCCESS);
}

/* create container and add-segment property */

static int
create_container_prop(picl_nodehdl_t	fruhdl)
{
	int			retval;
	picl_prophdl_t		prophdl;
	ptree_propinfo_t	prop;

	prop.version = PTREE_PROPINFO_VERSION;
	prop.piclinfo.type = PICL_PTYPE_UNSIGNED_INT;
	prop.piclinfo.size = sizeof (uint32_t);
	prop.piclinfo.accessmode = PICL_WRITE|PICL_VOLATILE;
	(void) strcpy(prop.piclinfo.name, PICL_PROP_CONTAINER);
	prop.read =  frudata_read_callback;
	prop.write = frudata_write_section; /* callback routine */

	/* create a property */
	retval = ptree_create_and_add_prop(fruhdl, &prop, NULL, &prophdl);

	return (retval);
}

/* search for FRUDataAvailable and create container and add segment property */

static void
create_frudata_props(picl_prophdl_t fruhdl)
{
	int		retval;
	picl_nodehdl_t chldhdl;
	picl_nodehdl_t tmphdl;

	for (retval = ptree_get_propval_by_name(fruhdl, PICL_PROP_CHILD,
	    &chldhdl, sizeof (picl_nodehdl_t)); retval != PICL_PROPNOTFOUND;
	    retval = ptree_get_propval_by_name(chldhdl, PICL_PROP_PEER,
	    &chldhdl, sizeof (picl_nodehdl_t))) {
		if (retval != PICL_SUCCESS)
			return;

		/* Does it have a FRUDataAvailable property */
		retval = ptree_get_prop_by_name(chldhdl,
		    PICL_PROP_FRUDATA_AVAIL, &tmphdl);
		if (retval == PICL_SUCCESS) {
			(void) create_container_prop(chldhdl);
		}

		/* Traverse tree recursively */
		(void) create_frudata_props(chldhdl);
	}
}

/*
 * Search for the frutree config file from the platform specific
 * directory to the common directory.
 *
 * The size of outfilename must be PATH_MAX
 */
static int
get_config_file(char *outfilename)
{
	char    nmbuf[SYS_NMLN];
	char    pname[PATH_MAX];

	if (sysinfo(SI_PLATFORM, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, FRUDATA_CONFFILE_NAME, nmbuf);
		if (access(pname, R_OK) == 0) {
			(void) strlcpy(outfilename, pname, PATH_MAX);
			return (0);
		}
	}

	if (sysinfo(SI_MACHINE, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, FRUDATA_CONFFILE_NAME, nmbuf);
		if (access(pname, R_OK) == 0) {
			(void) strlcpy(outfilename, pname, PATH_MAX);
			return (0);
		}
	}

	(void) snprintf(pname, PATH_MAX, "%s/%s", PICLD_COMMON_PLUGIN_DIR,
	    FRUDATA_CONFFILE_NAME);
	if (access(pname, R_OK) == 0) {
		(void) strlcpy(outfilename, pname, PATH_MAX);
		return (0);
	}
	return (-1);
}

/*
 * called from delete_frudata_props(), this routine delete the section node
 * and free's the section hash object. it calls free_segment_node() to
 * delete segment node beneath it.
 */

static void
free_section_node(hash_obj_t	*sec_hash, container_tbl_t *cont_tbl)
{
	hash_obj_t	*seg_hash;

	for (seg_hash = sec_hash->u.sec_node->segment_list; seg_hash != NULL;
	    seg_hash = seg_hash->u.seg_node->next) {
		free_segment_node(seg_hash, seg_hash->picl_hdl, cont_tbl);
	}

	if (sec_hash->prev == NULL) {
		cont_tbl->hash_obj[(sec_hash->picl_hdl % TABLE_SIZE)].next =
		    sec_hash->next;
		if (sec_hash->next != NULL) {
			sec_hash->next->prev = NULL;
		}
	} else {
		sec_hash->prev->next = sec_hash->next;
		if (sec_hash->next != NULL) {
			sec_hash->next->prev = sec_hash->prev;
		}
	}

	/* delete & destroy section node */
	(void) ptree_delete_node(sec_hash->picl_hdl);
	(void) ptree_destroy_node(sec_hash->picl_hdl);

	free(sec_hash->u.sec_node);
	free(sec_hash);
}

/*
 * called from delete_frudata_props(), this routine free's the container
 * hash object.
 */

static void
unlink_container_node(container_tbl_t	*cont_hash)
{
	if (cont_hash->prev == NULL) {
		container_table[(cont_hash->picl_hdl % TABLE_SIZE)] =
		    cont_hash->next;
		if (cont_hash->next != NULL) {
			cont_hash->next->prev = NULL;
		}
	} else {
		cont_hash->prev->next = cont_hash->next;
		if (cont_hash->next != NULL) {
			cont_hash->next->prev = cont_hash->prev;
		}
	}
}

/*
 * called from frudata_event_handler() to free the corresponding hash object
 * of the removed fru.
 */

static void
delete_frudata_props(picl_nodehdl_t	fru_hdl)
{
	hash_obj_t	*cont_hash;
	hash_obj_t	*free_obj;
	hash_obj_t	*sec_hash;
	container_tbl_t	*cont_tbl;

	(void) pthread_mutex_lock(&cont_tbl_lock);

	cont_tbl = lookup_container_table(fru_hdl, CONTAINER_NODE);
	if (cont_tbl == NULL) {
		(void) pthread_mutex_unlock(&cont_tbl_lock);
		return;
	}

	/* remove the container object from the container table */
	unlink_container_node(cont_tbl);

	(void) pthread_cond_broadcast(&cont_tbl->cond_var);

	(void) pthread_mutex_unlock(&cont_tbl_lock);

	/*
	 * waiting/blocking calling thread for all I/O in
	 * progress to complete. don't free the container
	 * hash before all I/O is complete.
	 */
	(void) pthread_rwlock_wrlock(&cont_tbl->rwlock);

	(void) pthread_rwlock_unlock(&cont_tbl->rwlock);


	cont_hash = lookup_node_object(fru_hdl, CONTAINER_NODE, cont_tbl);
	if (cont_hash == NULL) {
		return;
	}

	free_obj = cont_hash->u.cont_node->section_list;
	/* walk through the section list */
	for (sec_hash = free_obj; sec_hash != NULL; free_obj = sec_hash) {
		sec_hash = sec_hash->u.sec_node->next;
		free_section_node(free_obj, cont_tbl);
	}
	(void) fru_close_container(cont_hash->u.cont_node->cont_hdl);

	free(cont_hash->u.cont_node);
	free(cont_hash);

	free(cont_tbl->hash_obj);
	free(cont_tbl);
}

/*
 * called when there is any state-change in location, fru, port nodes.
 * this event handler handles only location state-changes.
 */
/* ARGSUSED */
static void
frudata_state_change_evhandler(const char *event_name, const void *event_arg,
    size_t size, void *cookie)
{
	int rc;
	nvlist_t *nvlp;
	ptree_propinfo_t prop;
	picl_nodehdl_t	loch, fruh;
	picl_prophdl_t	proph, prophdl;
	char *present_state, *last_state;
	char name[PICL_PROPNAMELEN_MAX];

	if (strcmp(event_name, PICLEVENT_STATE_CHANGE) != 0)
		return;

	if (nvlist_unpack((char *)event_arg, size, &nvlp, 0)) {
		return;
	}

	if (nvlist_lookup_uint64(nvlp, PICLEVENTARG_NODEHANDLE,
	    &loch)  == -1) {
		nvlist_free(nvlp);
		return;
	}

	if (ptree_get_propval_by_name(loch, PICL_PROP_CLASSNAME, name,
	    sizeof (name)) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}

	/* handle only location events */
	if (strcmp(name, PICL_CLASS_LOCATION) != 0) {
		nvlist_free(nvlp);
		return;
	}

	if (nvlist_lookup_string(nvlp, PICLEVENTARG_STATE,
	    &present_state)) {
		nvlist_free(nvlp);
		return;
	}

	rc = ptree_get_propval_by_name(loch, PICL_PROP_CHILD,
	    &fruh, sizeof (picl_nodehdl_t));
	if (rc != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}

	/* fru removed */
	if (strcmp(present_state, PICLEVENTARGVAL_EMPTY) == 0) {
		delete_frudata_props(fruh);
		nvlist_free(nvlp);
		return;
	}

	if (nvlist_lookup_string(nvlp, PICLEVENTARG_LAST_STATE,
	    &last_state)) {
		nvlist_free(nvlp);
		return;
	}

	/* fru added */
	if ((strcmp(last_state, PICLEVENTARGVAL_EMPTY) == 0) ||
	    (strcmp(last_state, PICLEVENTARGVAL_UNKNOWN) == 0)) {
		rc = ptree_get_prop_by_name(fruh, PICL_PROP_FRUDATA_AVAIL,
		    &proph);
		if (rc != PICL_SUCCESS) {
			if (fru_is_data_available(fruh) == 0) {
				nvlist_free(nvlp);
				return;
			}
			/* create the property */
			prop.version = PTREE_PROPINFO_VERSION;
			prop.piclinfo.type =  PICL_PTYPE_VOID;
			prop.piclinfo.accessmode = PICL_READ;
			prop.piclinfo.size =  0;
			(void) strncpy(prop.piclinfo.name,
			    PICL_PROP_FRUDATA_AVAIL,
			    sizeof (prop.piclinfo.name));

			rc = ptree_create_prop(&prop, NULL, &prophdl);
			if (rc != PICL_SUCCESS) {
				nvlist_free(nvlp);
				return;
			}
			rc = ptree_add_prop(fruh,  prophdl);
			if (rc != PICL_SUCCESS) {
				nvlist_free(nvlp);
				return;
			}
		}
		(void) create_container_prop(fruh);
	}
	nvlist_free(nvlp);
}

/*
 * called when event is posted when is fru is either added or removed from
 * the picltree.
 */

/* ARGSUSED */
static void
frudata_event_handler(const char *event_name, const void *event_arg,
    size_t size, void *cookie)
{
	int		retval;
	char		fullfilename[PATH_MAX];
	picl_nodehdl_t	fru_picl_hdl;
	picl_nodehdl_t	roothdl;

	if (strcmp(event_name, PICL_FRU_REMOVED) == 0) {

		retval = nvlist_lookup_uint64((nvlist_t *)event_arg,
		    PICLEVENTARG_FRUHANDLE, &fru_picl_hdl);
		if (retval != PICL_SUCCESS) {
			return;
		}

		/* free the hash object */
		delete_frudata_props(fru_picl_hdl);

	} else  if (strcmp(event_name, PICL_FRU_ADDED) == 0) {
		/*
		 * reparse the configuration file to create
		 * FRUDevicePath Prop.
		 */
		(void) get_config_file(fullfilename);
		retval = ptree_get_root(&roothdl);
		if (retval != PICL_SUCCESS) {
			return;
		}

		(void) picld_pluginutil_parse_config_file(roothdl,
		    fullfilename);

		retval = nvlist_lookup_uint64((nvlist_t *)event_arg,
		    PICLEVENTARG_PARENTHANDLE, &fru_picl_hdl);
		if (retval != PICL_SUCCESS) {
			return;
		}

		/* create container property */
		create_frudata_props(fru_picl_hdl);
	}
}

/*
 * Function : plugin_init() is called by daemon. this routine is specified
 *		while registering with daemon. it performs the initialization
 *		of plugin module.
 */

static void
frudata_plugin_init(void)
{
	int		retval;
	int		count;
	char		fullfilename[PATH_MAX];
	picl_nodehdl_t	fru_nodehdl;
	picl_nodehdl_t	roothdl;

	retval = ptree_get_root(&roothdl);
	if (retval != PICL_SUCCESS) {
		return;
	}

	(void) ptree_register_handler(PICL_FRU_ADDED,
	    frudata_event_handler, NULL);

	(void) ptree_register_handler(PICL_FRU_REMOVED,
	    frudata_event_handler, NULL);

	(void) ptree_register_handler(PICLEVENT_STATE_CHANGE,
	    frudata_state_change_evhandler, NULL);

	(void) pthread_mutex_lock(&cont_tbl_lock);
	for (count = 0; count < TABLE_SIZE; count++) {
		container_table[count] = NULL;
	}
	(void) pthread_mutex_unlock(&cont_tbl_lock);

	(void) get_config_file(fullfilename);

	(void) picld_pluginutil_parse_config_file(roothdl, fullfilename);

	retval = ptree_get_node_by_path(FRUTREE_PATH, &fru_nodehdl);

	if (retval != PICL_SUCCESS) {
		return;
	}

	create_frudata_props(fru_nodehdl);

}

static void
free_packet_hash_object(hash_obj_t *pkt_obj)
{
	hash_obj_t	*tmp_obj;

	while (pkt_obj != NULL) {
		tmp_obj = pkt_obj->u.pkt_node->next;
		free(pkt_obj->u.pkt_node);
		free(pkt_obj);
		pkt_obj = tmp_obj;
	}
}

static void
free_segment_hash_object(hash_obj_t *seg_obj)
{
	hash_obj_t	*tmp_obj;

	while (seg_obj != NULL) {
		free_packet_hash_object(seg_obj->u.seg_node->packet_list);
		tmp_obj = seg_obj->u.seg_node->next;
		free(seg_obj->u.seg_node);
		free(seg_obj);
		seg_obj = tmp_obj;
	}
}

static void
free_hash_objects(hash_obj_t *sec_obj)
{
	hash_obj_t	*tmp_obj;

	while (sec_obj != NULL) {
		free_segment_hash_object(sec_obj->u.sec_node->segment_list);
		tmp_obj = sec_obj->u.sec_node->next;
		free(sec_obj->u.sec_node);
		free(sec_obj);
		sec_obj = tmp_obj;
	}
}

/*
 * called from frudata_plugin_fini() this routine walks through
 * the hash table to free each and very hash object in the hash table.
 */

static void
free_hash_table(void)
{
	int		cnt;
	picl_nodehdl_t	nodehdl;
	hash_obj_t	*next_obj;
	hash_obj_t	*sec_obj;
	container_tbl_t	*cont_tbl;

	for (cnt = 0; cnt < TABLE_SIZE; cnt++) {

		while (container_table[cnt]) {

			(void) pthread_mutex_lock(&cont_tbl_lock);

			cont_tbl = container_table[cnt];
			nodehdl = cont_tbl->picl_hdl;

			cont_tbl = lookup_container_table(nodehdl,
			    CONTAINER_NODE);
			if (cont_tbl == NULL) {
				(void) pthread_mutex_unlock(&cont_tbl_lock);
				break;
			}

			unlink_container_node(cont_tbl);

			pthread_cond_broadcast(&cont_tbl->cond_var);

			(void) pthread_mutex_unlock(&cont_tbl_lock);

			/*
			 * waiting/blocking calling thread for all I/O in
			 * progress to complete. don't free the container
			 * hash until all I/O is complete.
			 */
			(void) pthread_rwlock_wrlock(&cont_tbl->rwlock);

			(void) pthread_rwlock_unlock(&cont_tbl->rwlock);

			next_obj = cont_tbl->hash_obj->next;
			if (next_obj == NULL) {
				break;
			}

			if (next_obj->object_type == CONTAINER_NODE) {
				sec_obj = next_obj->u.cont_node->section_list;
				free_hash_objects(sec_obj);
			}

			free(next_obj->u.cont_node);
			free(next_obj);
			container_table[cnt] = cont_tbl->next;

			free(cont_tbl);
		}
	}
}

/*
 * called by the daemon and perform frudata cleanup. hold the write lock
 * over the entire hash table to free each and every hash object.
 */

static void
frudata_plugin_fini(void)
{

	free_hash_table();

	(void) ptree_unregister_handler(PICL_FRU_ADDED,
	    frudata_event_handler, NULL);

	(void) ptree_unregister_handler(PICL_FRU_REMOVED,
	    frudata_event_handler, NULL);

	(void) ptree_unregister_handler(PICLEVENT_STATE_CHANGE,
	    frudata_state_change_evhandler, NULL);
}
