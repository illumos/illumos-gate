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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * s1394_bus_reset.c
 *    1394 Services Layer Bus Reset Routines
 *    These routines handle all of the tasks relating to 1394 bus resets
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>
#include <sys/1394/ieee1394.h>
#include <sys/1394/ieee1212.h>

static uint8_t selfid_speed(s1394_selfid_pkt_t *s);

static int selfid_num_ports(s1394_selfid_pkt_t *s);

static int selfid_port_type(s1394_selfid_pkt_t *s, int port);

static void s1394_hal_stack_push(s1394_hal_t *hal, void *o);

static void *s1394_hal_stack_pop(s1394_hal_t *hal);

static void s1394_hal_queue_insert(s1394_hal_t *hal, void *o);

static void *s1394_hal_queue_remove(s1394_hal_t *hal);

static void s1394_node_number_list_add(s1394_hal_t *hal, int node_num);

static void s1394_speed_map_fill_speed_N(s1394_hal_t *hal, int min_spd);

static void s1394_speed_map_initialize(s1394_hal_t *hal);

int s1394_ignore_invalid_gap_cnt = 0; /* patch for invalid gap_cnts */

/*
 * Gap_count look-up table (See IEEE P1394a Table C-2) - Draft 3.0
 * (modified from original table IEEE 1394-1995 8.4.6.2)
 */
static int gap_count[MAX_HOPS + 1] = {
	0, 5, 7, 8, 10, 13, 16, 18, 21,
	24, 26, 29, 32, 35, 37, 40, 43,
	46, 48, 51, 54, 57, 59, 62
};

/*
 * s1394_parse_selfid_buffer()
 *    takes the SelfID data buffer and parses it, testing whether each packet
 *    is valid (has a correct inverse packet) and setting the pointers in
 *    selfid_ptrs[] to the appropriate offsets within the buffer.
 */
int
s1394_parse_selfid_buffer(s1394_hal_t *hal, void *selfid_buf_addr,
    uint32_t selfid_size)
{
	s1394_selfid_pkt_t *s;
	uint32_t	   *data;
	uint_t		   i = 0;
	uint_t		   j = 0;
	boolean_t	   error = B_FALSE;
	int		   valid_pkt_id;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	data = (uint32_t *)selfid_buf_addr;

	if (selfid_size == 0) {
		/* Initiate a bus reset */
		s1394_initiate_hal_reset(hal, CRITICAL);

		/* Set error status */
		error = B_TRUE;

		/* Release HAL lock and return */
		goto parse_buffer_done;
	}

	/* Convert bytes to quadlets */
	selfid_size = selfid_size >> 2;

	while (j < selfid_size) {
		valid_pkt_id = ((data[j] & IEEE1394_SELFID_PCKT_ID_MASK) >>
		    IEEE1394_SELFID_PCKT_ID_SHIFT);

		s = (s1394_selfid_pkt_t *)(&data[j]);

		/* Test if packet has valid inverse quadlet */
		if (IEEE1394_SELFID_ISVALID(s) &&
		    (valid_pkt_id == IEEE1394_SELFID_PCKT_ID_VALID)) {

			hal->selfid_ptrs[i] = s;

			/* While this packet contains multiple quadlets */
			j += 2;

			while (IEEE1394_SELFID_ISMORE(s)) {
				valid_pkt_id =
				    ((data[j] & IEEE1394_SELFID_PCKT_ID_MASK) >>
				    IEEE1394_SELFID_PCKT_ID_SHIFT);

				s = (s1394_selfid_pkt_t *)(&data[j]);

				/* Test if packet has valid inverse quadlet */
				if (IEEE1394_SELFID_ISVALID(s) &&
				    (valid_pkt_id ==
					IEEE1394_SELFID_PCKT_ID_VALID)) {
					j += 2;
				} else {
					/* Initiate a bus reset */
					s1394_initiate_hal_reset(hal, CRITICAL);

					/* Set error status */
					error = B_TRUE;

					/* Release HAL lock and return */
					goto parse_buffer_done;
				}
			}
			i++;
		} else {
			/* Initiate a bus reset */
			s1394_initiate_hal_reset(hal, CRITICAL);

			/* Set error status */
			error = B_TRUE;

			/* Release HAL lock and return */
			goto parse_buffer_done;
		}
	}

	hal->number_of_nodes = i;

parse_buffer_done:
	if (error == B_TRUE)
		return (DDI_FAILURE);
	else
		return (DDI_SUCCESS);
}

/*
 * s1394_sort_selfids()
 *    takes the selfid_ptrs[] in the HAL struct and sorts them by node number,
 *    using a heapsort.
 */
void
s1394_sort_selfids(s1394_hal_t *hal)
{
	s1394_selfid_pkt_t *current;
	uint_t		   number_of_nodes;
	int		   i;
	int		   j;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	number_of_nodes = hal->number_of_nodes;

	/* We start at one because the root has no parent to check */
	for (i = 1; i < number_of_nodes; i++) {
		current = hal->selfid_ptrs[i];
		j = i;
		while ((j > 0) && (IEEE1394_SELFID_PHYID(current) >
		    IEEE1394_SELFID_PHYID(hal->selfid_ptrs[j / 2]))) {
			hal->selfid_ptrs[j] = hal->selfid_ptrs[j / 2];
			hal->selfid_ptrs[j / 2] = current;
			j = j / 2;
		}
	}

	for (i = number_of_nodes - 1; i > 0; i--) {
		current = hal->selfid_ptrs[i];
		hal->selfid_ptrs[i] = hal->selfid_ptrs[0];
		hal->selfid_ptrs[0] = current;
		j = 0;
		while (2 * j + 1 < i) {
			if (2 * j + 2 >= i) {
				if (IEEE1394_SELFID_PHYID(current) <
				    IEEE1394_SELFID_PHYID(
					hal->selfid_ptrs[2 * j + 1])) {
					hal->selfid_ptrs[j] =
					    hal->selfid_ptrs[2 * j + 1];
					hal->selfid_ptrs[2 * j + 1] = current;
					j = 2 * j + 1;
				}
				break;
			}

			if (IEEE1394_SELFID_PHYID(hal->selfid_ptrs[2 * j + 1]) >
			    IEEE1394_SELFID_PHYID(
				hal->selfid_ptrs[2 * j + 2])) {
				if (IEEE1394_SELFID_PHYID(current) <
				    IEEE1394_SELFID_PHYID(
					hal->selfid_ptrs[2 * j + 1])) {
					hal->selfid_ptrs[j] =
					    hal->selfid_ptrs[2 * j + 1];
					hal->selfid_ptrs[2 * j + 1] = current;
					j = 2 * j + 1;
				} else {
					break;
				}
			} else {
				if (IEEE1394_SELFID_PHYID(current) <
				    IEEE1394_SELFID_PHYID(
					hal->selfid_ptrs[2 * j + 2])) {
					hal->selfid_ptrs[j] =
					    hal->selfid_ptrs[2 * j + 2];
					hal->selfid_ptrs[2 * j + 2] = current;
					j = 2 * j + 2;
				} else {
					break;
				}
			}
		}
	}
}

/*
 * selfid_speed()
 *    examines the "sp" bits for a given packet (see IEEE 1394-1995 4.3.4.1)
 *    and returns the node's speed capabilities.
 */
static uint8_t
selfid_speed(s1394_selfid_pkt_t *s)
{
	uint32_t sp;

	sp = ((s->spkt_data & IEEE1394_SELFID_SP_MASK) >>
	    IEEE1394_SELFID_SP_SHIFT);

	switch (sp) {
	case IEEE1394_S100:
	case IEEE1394_S200:
	case IEEE1394_S400:
		return (sp);

	/*
	 * To verify higher speeds we should look at PHY register #3
	 * on this node.  This will need to be done to support P1394b
	 */
	default:
		return (IEEE1394_S400);
	}
}

/*
 * selfid_num_ports()
 *    determines whether a packet is multi-part or single, and from this it
 *    calculates the number of ports which have been specified.
 *    (See IEEE 1394-1995 4.3.4.1)
 */
static int
selfid_num_ports(s1394_selfid_pkt_t *s)
{
	int	p = 3;

	while (IEEE1394_SELFID_ISMORE(s)) {
		p += 8;
		s++;
	}

	/* Threshold the number of ports at the P1394A defined maximum */
	/* (see P1394A Draft 3.0 - Section 8.5.1) */
	if (p > IEEE1394_MAX_NUM_PORTS)
		p = IEEE1394_MAX_NUM_PORTS;

	return (p);
}

/*
 * selfid_port_type()
 *    determines what type of node the specified port connects to.
 *    (See IEEE 1394-1995 4.3.4.1)
 */
static int
selfid_port_type(s1394_selfid_pkt_t *s, int port)
{
	int	block;
	int	offset = IEEE1394_SELFID_PORT_OFFSET_FIRST;

	if (port > 2) {
		/* Calculate which quadlet and bits for this port */
		port -= 3;
		block = (port >> 3) + 1;
		port = port % 8;
		/* Move to the correct quadlet */
		s += block;
		offset = IEEE1394_SELFID_PORT_OFFSET_OTHERS;
	}

	/* Shift by appropriate number of bits and mask */
	return ((s->spkt_data >> (offset - 2 * port)) & 0x00000003);
}

/*
 * s1394_init_topology_tree()
 *    frees any config rom's allocated in the topology tree before zapping it.
 *    If it gets a bus reset before the tree is marked processed, there will
 *    be memory allocated for cfgrom's being read. If there is no tree copy,
 *    topology would still be topology tree from the previous generation and
 *    if we bzero'd the tree, we will have a memory leak. To avoid this leak,
 *    walk through the tree and free any config roms in nodes that are NOT
 *    matched. (For matched nodes, we ensure that nodes in old and topology
 *    tree point to the same area of memory.)
 */
void
s1394_init_topology_tree(s1394_hal_t *hal, boolean_t copied,
    ushort_t number_of_nodes)
{
	s1394_node_t	*node;
	uint32_t	*config_rom;
	uint_t		tree_size;
	int		i;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	/*
	 * if copied is false, we want to free any cfgrom memory that is
	 * not referenced to in both topology and old trees. However, we
	 * don't use hal->number_of_nodes as the number of nodes to look at.
	 * The reason being we could be seeing the bus reset before the
	 * state is appropriate for a tree copy (which need
	 * toplogy_tree_processed to be true) and some nodes might have
	 * departed in this generation and hal->number_of_nodes reflects
	 * the number of nodes in this generation. Use number_of_nodes that
	 * gets passed into this routine as the actual number of nodes to
	 * look at.
	 */
	if (copied == B_FALSE) {
		/* Free any cfgrom alloced and zap the node */
		for (i = 0; i < number_of_nodes; i++) {
			node = &hal->topology_tree[i];
			config_rom = node->cfgrom;
			if (config_rom != NULL) {
				if (CFGROM_NEW_ALLOC(node) == B_TRUE) {
					kmem_free((void *)config_rom,
					    IEEE1394_CONFIG_ROM_SZ);
				}
			}
		}
	}

	tree_size = hal->number_of_nodes * sizeof (s1394_node_t);
	bzero((void *)hal->topology_tree, tree_size);
}

/*
 * s1394_topology_tree_build()
 *    takes the selfid_ptrs[] and builds the topology_tree[] by examining
 *    the node numbers (the order in which the nodes responded to SelfID).
 *    It sets the port pointers, leaf label, parent port, and
 *    s1394_selfid_packet_t pointer in each node.
 */
int
s1394_topology_tree_build(s1394_hal_t *hal)
{
	s1394_node_t	*tmp;
	uint32_t	number_of_nodes;
	boolean_t	push_to_orphan_stack = B_FALSE;
	boolean_t	found_parent = B_FALSE;
	boolean_t	found_connection = B_FALSE;
	int		i;
	int		j;

	/*
	 * The method for building the tree is described in IEEE 1394-1995
	 * (Annex E.3.4).  We use an "Orphan" stack to keep track of Child
	 * nodes which have yet to find their Parent node.
	 */

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	number_of_nodes = hal->number_of_nodes;

	/* Flush the Stack */
	hal->hal_stack_depth = -1;

	/* For each node on the bus initialize its topology_tree entry */
	for (i = 0; i < number_of_nodes; i++) {
		/* Make sure that node numbers are correct */
		if (i != IEEE1394_SELFID_PHYID(hal->selfid_ptrs[i])) {
			/* Initiate a bus reset */
			s1394_initiate_hal_reset(hal, CRITICAL);

			return (DDI_FAILURE);
		}

		hal->topology_tree[i].selfid_packet = hal->selfid_ptrs[i];
		hal->topology_tree[i].parent_port = (char)NO_PARENT;
		hal->topology_tree[i].is_a_leaf = 1;
		hal->topology_tree[i].node_num = (uchar_t)i;
	}

	for (i = 0; i < number_of_nodes; i++) {
		/* Current node has no parent yet */
		found_parent = B_FALSE;

		/* Current node has no connections yet */
		found_connection = B_FALSE;

		/* Initialize all ports on this node */
		for (j = 0; j < IEEE1394_MAX_NUM_PORTS; j++)
			hal->topology_tree[i].phy_port[j] = NULL;

		/* For each port on the node - highest to lowest */
		for (j = selfid_num_ports(hal->selfid_ptrs[i]) - 1;
		    j >= 0; j--) {
			if (selfid_port_type(hal->selfid_ptrs[i], j) ==
			    IEEE1394_SELFID_PORT_TO_PARENT) {

				found_connection = B_TRUE;
				if (found_parent == B_FALSE) {
					push_to_orphan_stack = B_TRUE;
					hal->topology_tree[i].parent_port =
					    (char)j;
					found_parent = B_TRUE;

				} else {
					/* Initiate a bus reset */
					s1394_initiate_hal_reset(hal, CRITICAL);

					return (DDI_FAILURE);
				}
			} else if (selfid_port_type(hal->selfid_ptrs[i], j) ==
			    IEEE1394_SELFID_PORT_TO_CHILD) {

				found_connection = B_TRUE;
				tmp = (s1394_node_t *)s1394_hal_stack_pop(hal);
				if (tmp == NULL) {
					/* Initiate a bus reset */
					s1394_initiate_hal_reset(hal, CRITICAL);

					return (DDI_FAILURE);
				}

				hal->topology_tree[i].phy_port[j] = tmp;
				hal->topology_tree[i].is_a_leaf = 0;
				tmp->phy_port[tmp->parent_port] =
				    &hal->topology_tree[i];
			}
		}

		/* If current node has no parents or children - Invalid */
		if ((found_connection == B_FALSE) && (number_of_nodes > 1)) {
			/* Initiate a bus reset */
			s1394_initiate_hal_reset(hal, CRITICAL);

			return (DDI_FAILURE);
		}

		/* Push it on the "Orphan" stack if it has no parent yet */
		if (push_to_orphan_stack == B_TRUE) {
			push_to_orphan_stack = B_FALSE;
			s1394_hal_stack_push(hal, &hal->topology_tree[i]);
		}
	}

	/* If the stack is not empty, then something has gone seriously wrong */
	if (hal->hal_stack_depth != -1) {
		/* Initiate a bus reset */
		s1394_initiate_hal_reset(hal, CRITICAL);

		return (DDI_FAILURE);
	}

	/* New topology tree is now valid */
	hal->topology_tree_valid = B_TRUE;

	return (DDI_SUCCESS);
}

/*
 * s1394_hal_stack_push()
 *    checks that the stack is not full, and puts the pointer on top of the
 *    HAL's stack if it isn't.  This routine is used only by the
 *    h1394_self_ids() interrupt.
 */
static void
s1394_hal_stack_push(s1394_hal_t *hal, void *obj)
{
	if (hal->hal_stack_depth < IEEE1394_MAX_NODES - 1) {
		hal->hal_stack_depth++;
		hal->hal_stack[hal->hal_stack_depth] = obj;
	}
}

/*
 * s1394_hal_stack_pop()
 *    checks that the stack is not empty, and pops and returns the pointer
 *    from the top of the HAL's stack if it isn't.  This routine is used
 *    only by the h1394_self_ids() interrupt.
 */
static void *
s1394_hal_stack_pop(s1394_hal_t *hal)
{
	if (hal->hal_stack_depth > -1) {
		hal->hal_stack_depth--;
		return (hal->hal_stack[hal->hal_stack_depth + 1]);

	} else {
		return (NULL);
	}
}

/*
 * s1394_hal_queue_insert()
 *    checks that the queue is not full, and puts the object in the front
 *    of the HAL's queue if it isn't.  This routine is used only by the
 *    h1394_self_ids() interrupt.
 */
static void
s1394_hal_queue_insert(s1394_hal_t *hal, void *obj)
{
	if (((hal->hal_queue_front + 1) % IEEE1394_MAX_NODES) ==
	    hal->hal_queue_back) {
		return;
	} else {
		hal->hal_queue[hal->hal_queue_front] = obj;
		hal->hal_queue_front = (hal->hal_queue_front + 1) %
		    IEEE1394_MAX_NODES;
	}
}


/*
 * s1394_hal_queue_remove()
 *    checks that the queue is not empty, and pulls the object off the back
 *    of the HAL's queue (and returns it) if it isn't.  This routine is used
 *    only by the h1394_self_ids() interrupt.
 */
static void *
s1394_hal_queue_remove(s1394_hal_t *hal)
{
	void	*tmp;

	if (hal->hal_queue_back == hal->hal_queue_front) {
		return (NULL);
	} else {
		tmp = hal->hal_queue[hal->hal_queue_back];
		hal->hal_queue_back = (hal->hal_queue_back + 1) %
		    IEEE1394_MAX_NODES;
		return (tmp);
	}
}


/*
 * s1394_node_number_list_add()
 *    checks that the node_number_list is not full and puts the node number
 *    in the list.  The function is used primarily by s1394_speed_map_fill()
 *    to keep track of which connections need to be set in the speed_map[].
 *    This routine is used only by the h1394_self_ids() interrupt.
 */
static void
s1394_node_number_list_add(s1394_hal_t *hal, int node_num)
{
	if (hal->hal_node_number_list_size >= IEEE1394_MAX_NODES - 1) {
		return;
	}

	hal->hal_node_number_list[hal->hal_node_number_list_size] = node_num;
	hal->hal_node_number_list_size++;
}

/*
 * s1394_topology_tree_mark_all_unvisited()
 *    is used to initialize the topology_tree[] prior to tree traversals.
 *    It resets the "visited" flag for each node in the tree.
 */
void
s1394_topology_tree_mark_all_unvisited(s1394_hal_t *hal)
{
	uint_t	number_of_nodes;
	int	i;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	number_of_nodes = hal->number_of_nodes;
	for (i = 0; i < number_of_nodes; i++)
		CLEAR_NODE_VISITED(&hal->topology_tree[i]);
}

/*
 * s1394_old_tree_mark_all_unvisited()
 *    is used to initialize the old_tree[] prior to tree traversals.  It
 *    resets the "visited" flag for each node in the tree.
 */
void
s1394_old_tree_mark_all_unvisited(s1394_hal_t *hal)
{
	uint_t	number_of_nodes;
	int	i;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	number_of_nodes = hal->old_number_of_nodes;
	for (i = 0; i < number_of_nodes; i++)
		CLEAR_NODE_VISITED(&hal->old_tree[i]);
}

/*
 * s1394_old_tree_mark_all_unmatched()
 *    is used to initialize the old_tree[] prior to tree traversals.  It
 *    resets the "matched" flag for each node in the tree.
 */
void
s1394_old_tree_mark_all_unmatched(s1394_hal_t *hal)
{
	uint_t	number_of_nodes;
	int	i;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	number_of_nodes = hal->old_number_of_nodes;

	for (i = 0; i < number_of_nodes; i++)
	    CLEAR_NODE_MATCHED(&hal->old_tree[i]);
}

/*
 * s1394_copy_old_tree()
 *    switches the pointers for old_tree[] and topology_tree[].
 */
void
s1394_copy_old_tree(s1394_hal_t *hal)
{
	s1394_node_t	*temp;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	temp = hal->old_tree;
	hal->old_tree = hal->topology_tree;
	hal->topology_tree = temp;

	hal->old_number_of_nodes = hal->number_of_nodes;
	hal->old_node_id = hal->node_id;
	hal->old_generation_count = hal->generation_count;

	/* Old tree is now valid and filled also */
	hal->old_tree_valid = B_TRUE;
}


/*
 * s1394_match_tree_nodes()
 *    uses the information contained in the SelfID packets of the nodes in
 *    both the old_tree[] and the topology_tree[] to determine which new
 *    nodes correspond to old nodes.  Starting with the local node, we
 *    compare both old and new node's ports.  Assuming that only one bus
 *    reset has occurred, any node that was connected to another in the old
 *    bus and is still connected to another in the new bus must be connected
 *    (physically) to the same node.  Using this information, we can rebuild
 *    and match the old nodes to new ones.  Any nodes which aren't matched
 *    are either departing or arriving nodes and must be handled appropriately.
 */
void
s1394_match_tree_nodes(s1394_hal_t *hal)
{
	s1394_node_t	*tmp;
	uint_t		hal_node_num;
	uint_t		hal_node_num_old;
	int		i;
	int		port_type;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	/* To ensure that the queue is empty */
	hal->hal_queue_front = hal->hal_queue_back = 0;

	/* Set up the first matched nodes (which are our own local nodes) */
	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);
	hal_node_num_old = IEEE1394_NODE_NUM(hal->old_node_id);
	hal->topology_tree[hal_node_num].old_node =
	    &hal->old_tree[hal_node_num_old];
	hal->old_tree[hal_node_num_old].cur_node =
	    &hal->topology_tree[hal_node_num];

	/* Put the node on the queue */
	s1394_hal_queue_insert(hal, &hal->topology_tree[hal_node_num]);

	/* While the queue is not empty, remove a node */
	while (hal->hal_queue_front != hal->hal_queue_back) {
		tmp = (s1394_node_t *)s1394_hal_queue_remove(hal);

	    /* Mark both old and new nodes as "visited" */
	    SET_NODE_VISITED(tmp);
	    SET_NODE_VISITED(tmp->old_node);
	    tmp->old_node->cur_node = tmp;

	    /* Mark old and new nodes as "matched" */
	    SET_NODE_MATCHED(tmp);
	    SET_NODE_MATCHED(tmp->old_node);
	    s1394_copy_cfgrom(tmp, tmp->old_node);

	    /* s1394_copy_cfgrom() clears "matched" for some cases... */
	    if ((tmp->cfgrom != NULL && CONFIG_ROM_GEN(tmp->cfgrom) <= 1) ||
		NODE_MATCHED(tmp) == B_TRUE) {
		/* Move the target list over to the new node and update */
		/* the node info. */
			s1394_target_t *t;

			rw_enter(&hal->target_list_rwlock, RW_WRITER);
			t = tmp->target_list = tmp->old_node->target_list;
			while (t != NULL) {
				t->on_node = tmp;
				t = t->target_sibling;
			}
			rw_exit(&hal->target_list_rwlock);
		}

		for (i = 0; i < selfid_num_ports(tmp->selfid_packet); i++) {
			port_type = selfid_port_type(tmp->selfid_packet, i);

			/* Is the new port connected? */
			if ((port_type == IEEE1394_SELFID_PORT_TO_CHILD) ||
			    (port_type == IEEE1394_SELFID_PORT_TO_PARENT)) {
				port_type = selfid_port_type(
				    tmp->old_node->selfid_packet, i);

				/* Is the old port connected? */
				if ((port_type ==
					IEEE1394_SELFID_PORT_TO_CHILD) ||
				    (port_type ==
					IEEE1394_SELFID_PORT_TO_PARENT)) {
					/* Found a match, check if */
					/* we've already visited it */
					if (!NODE_VISITED(tmp->phy_port[i])) {
						tmp->phy_port[i]->old_node =
						    tmp->old_node->phy_port[i];
						s1394_hal_queue_insert(hal,
						    tmp->phy_port[i]);
					}
				}
			}
		}
	}
}

/*
 * s1394_topology_tree_calculate_diameter()
 *    does a depth-first tree traversal, tracking at each branch the first
 *    and second deepest paths though that branch's children.  The diameter
 *    is given by the maximum of these over all branch nodes
 */
int
s1394_topology_tree_calculate_diameter(s1394_hal_t *hal)
{
	s1394_node_t	*current;
	uint_t		number_of_nodes;
	int		i;
	int		start;
	int		end;
	boolean_t	done;
	boolean_t	found_a_child;
	int		distance = 0;
	int		diameter = 0;
	int		local_diameter = 0;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	number_of_nodes = hal->number_of_nodes;

	/* Initialize topology tree */
	for (i = 0; i < number_of_nodes; i++) {
		hal->topology_tree[i].max_1st = 0;
		hal->topology_tree[i].max_2nd = 0;
		hal->topology_tree[i].last_port_checked = 0;
	}

	/* Start at the root node */
	current = s1394_topology_tree_get_root_node(hal);

	/* Flush the stack before we start */
	hal->hal_stack_depth = -1;

	do {
		done		= B_FALSE;
		found_a_child	= B_FALSE;
		start		= current->last_port_checked;
		end		= selfid_num_ports(current->selfid_packet);

		/* Check every previously unchecked port for children */
		for (i = start; i < end; i++) {
			current->last_port_checked++;
			/* If there is a child push it on the stack */
			if (selfid_port_type(current->selfid_packet, i) ==
			    IEEE1394_SELFID_PORT_TO_CHILD) {
				found_a_child = B_TRUE;
				s1394_hal_stack_push(hal, current);
				current = current->phy_port[i];
				break;
			}
		}

		/* If we reach here and the stack is empty, we're done */
		if (hal->hal_stack_depth == -1) {
			done = B_TRUE;
			continue;
		}

		/* If no children were found, we're at a leaf */
		if (found_a_child == B_FALSE) {
			distance = current->max_1st + 1;
			/* Pop the child and set the appropriate fields */
			current = s1394_hal_stack_pop(hal);
			if (distance > current->max_1st) {
				current->max_2nd = current->max_1st;
				current->max_1st = (uchar_t)distance;

			} else if (distance > current->max_2nd) {
				current->max_2nd = (uchar_t)distance;
			}

			/* Update maximum distance (diameter), if necessary */
			local_diameter = current->max_1st + current->max_2nd;
			if (local_diameter > diameter)
				diameter = local_diameter;
		}
	} while (done == B_FALSE);

	return (diameter);
}

/*
 * s1394_gap_count_optimize()
 *    looks in a table to find the appropriate gap_count for a given diameter.
 *    (See above - gap_count[])
 */
int
s1394_gap_count_optimize(int diameter)
{
	if ((diameter >= 0) && (diameter <= MAX_HOPS)) {
		return (gap_count[diameter]);
	} else {
		cmn_err(CE_NOTE, "Too may point-to-point links on the 1394"
		    " bus - If new devices have recently been added, remove"
		    " them.");
		return (gap_count[MAX_HOPS]);
	}
}

/*
 * s1394_get_current_gap_count()
 *    looks at all the SelfID packets to determine the current gap_count on
 *    the 1394 bus.  If the gap_counts differ from node to node, it initiates
 *    a bus reset and returns -1.
 */
int
s1394_get_current_gap_count(s1394_hal_t *hal)
{
	int	i;
	int	gap_count = -1;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	/* Grab the first gap_count in the SelfID packets */
	gap_count = IEEE1394_SELFID_GAP_CNT(hal->selfid_ptrs[0]);

	/* Compare it too all the rest */
	for (i = 1; i < hal->number_of_nodes; i++) {
		if (gap_count !=
		    IEEE1394_SELFID_GAP_CNT(hal->selfid_ptrs[i])) {

			/* Inconsistent gap counts */
			if (s1394_ignore_invalid_gap_cnt == 0) {
				/* Initiate a bus reset */
				s1394_initiate_hal_reset(hal, CRITICAL);
			}

			return (-1);
		}
	}

	return (gap_count);
}

/*
 * s1394_speed_map_fill()
 *    determines, for each pair of nodes, the maximum speed at which those
 *    nodes can communicate.  The speed of each node as well as the speed of
 *    any intermediate nodes on a given path must be accounted for, as the
 *    minimum speed on a given edge determines the maximum speed for all
 *    communications across that edge.
 *    In the method we implement below, a current minimum speed is selected.
 *    With this minimum speed in mind, we create subgraphs of the original
 *    bus which contain only edges that connect two nodes whose speeds are
 *    equal to or greater than the current minimum speed.  Then, for each of
 *    the subgraphs, we visit every node, keeping a list of the nodes we've
 *    visited.  When this list is completed, we can fill in the entries in
 *    the speed map which correspond to a pairs of these nodes.  Doing this
 *    for each subgraph and then for each speed we progressively fill in the
 *    parts of the speed map which weren't previously filled in.
 */
void
s1394_speed_map_fill(s1394_hal_t *hal)
{
	uint_t	number_of_nodes;
	int	i;
	int	j;
	int	node_num;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	number_of_nodes = hal->number_of_nodes;
	s1394_speed_map_initialize(hal);

	/* Mark all speed = IEEE1394_S100 nodes in the Speed Map */
	for (i = 0; i < number_of_nodes; i++) {
		if (selfid_speed(hal->topology_tree[i].selfid_packet) ==
		    IEEE1394_S100) {
			hal->slowest_node_speed = IEEE1394_S100;
			node_num = IEEE1394_SELFID_PHYID(
			    hal->topology_tree[i].selfid_packet);
			for (j = 0; j < number_of_nodes; j++) {
				if (j != node_num) {
					hal->speed_map[node_num][j] =
					    IEEE1394_S100;
					hal->speed_map[j][node_num] =
					    IEEE1394_S100;
				}
			}
		}
	}

	s1394_speed_map_fill_speed_N(hal, IEEE1394_S200);
	s1394_speed_map_fill_speed_N(hal, IEEE1394_S400);

	/* Fill in the diagonal */
	for (i = 0; i < number_of_nodes; i++) {
		hal->speed_map[i][i] =
		    selfid_speed(hal->topology_tree[i].selfid_packet);
	}
}

/*
 * s1394_speed_map_fill_speed_N(),
 *    given a minimum link speed, creates subgraphs of the original bus which
 *    contain only the necessary edges (see speed_map_fill() above).  For each
 *    of the subgraphs, it visits and fills in the entries in the speed map
 *    which correspond to a pair of these nodes.
 */
static void
s1394_speed_map_fill_speed_N(s1394_hal_t *hal, int min_spd)
{
	s1394_node_t	*tmp;
	uint_t		number_of_nodes;
	int		i;
	int		j;
	int		k;
	int		size;
	int		ix_a, ix_b;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	number_of_nodes = hal->number_of_nodes;

	/* Prepare the topology tree */
	s1394_topology_tree_mark_all_unvisited(hal);

	/* To ensure that the queue is empty */
	hal->hal_queue_front = hal->hal_queue_back = 0;

	for (i = 0; i < number_of_nodes; i++) {
		/* If the node's speed == min_spd and it hasn't been visited */
		if (!NODE_VISITED(&hal->topology_tree[i]) &&
		    (selfid_speed(hal->topology_tree[i].selfid_packet) ==
			min_spd)) {

			if (min_spd < hal->slowest_node_speed)
				hal->slowest_node_speed = (uint8_t)min_spd;

			SET_NODE_VISITED(&hal->topology_tree[i]);
			s1394_hal_queue_insert(hal, &hal->topology_tree[i]);

			while (hal->hal_queue_front != hal->hal_queue_back) {
				tmp = (s1394_node_t *)s1394_hal_queue_remove(
				    hal);
				/* Add node number to the list */
				s1394_node_number_list_add(hal,
				    IEEE1394_SELFID_PHYID(tmp->selfid_packet));

				for (j = 0; j < IEEE1394_MAX_NUM_PORTS; j++) {
					if ((tmp->phy_port[j] != NULL) &&
					    (!NODE_VISITED(tmp->phy_port[j]))) {
						if (selfid_speed(
						    tmp->phy_port[j]->
						    selfid_packet) >= min_spd) {
							SET_NODE_VISITED(
							    tmp->phy_port[j]);
							s1394_hal_queue_insert(
							    hal,
							    tmp->phy_port[j]);
						}
					}
				}
			}

			/* For each pair, mark speed_map as min_spd */
			size = hal->hal_node_number_list_size;
			for (j = 0; j < size; j++) {
				for (k = 0; k < size; k++) {
					if (j != k) {
						ix_a = hal->
						    hal_node_number_list[j];
						ix_b = hal->
						    hal_node_number_list[k];
						hal->speed_map[ix_a][ix_b] =
						    (uint8_t)min_spd;
					}
				}
			}

			/* Flush the Node Number List */
			hal->hal_node_number_list_size = 0;
		}
	}
}

/*
 * s1394_speed_map_initialize()
 *    fills in the speed_map with IEEE1394_S100's and SPEED_MAP_INVALID's in
 *    the appropriate places.  These will be overwritten by
 *    s1394_speed_map_fill().
 */
static void
s1394_speed_map_initialize(s1394_hal_t *hal)
{
	uint_t	number_of_nodes;
	int	i, j;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	number_of_nodes = hal->number_of_nodes;
	for (i = 0; i < number_of_nodes; i++) {
		for (j = 0; j < number_of_nodes; j++) {
			if (i != j)
				hal->speed_map[i][j] = IEEE1394_S100;
			else
				hal->speed_map[i][j] = SPEED_MAP_INVALID;
		}
	}
}

/*
 * s1394_speed_map_get()
 *    queries the speed_map[] for a given pair of nodes.
 */
uint8_t
s1394_speed_map_get(s1394_hal_t *hal, uint_t from_node, uint_t to_node)
{
	/* If it's not a valid node, then return slowest_node_speed */
	if (to_node >= hal->number_of_nodes) {
		/* Send at fastest speed everyone will see */
		return (hal->slowest_node_speed);
	}
	/* else return the correct maximum speed */
	return (hal->speed_map[from_node][to_node]);
}

/*
 * s1394_update_speed_map_link_speeds()
 *    takes into account information from Config ROM queries.  Any P1394A
 *    device can have a link with a different speed than its PHY.  In this
 *    case, the slower speed must be accounted for in order for communication
 *    with the remote node to work.
 */
void
s1394_update_speed_map_link_speeds(s1394_hal_t *hal)
{
	uint32_t bus_capabilities;
	uint8_t	 link_speed;
	uint_t	 number_of_nodes;
	int	 i, j;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	number_of_nodes = hal->number_of_nodes;

	for (i = 0; i < number_of_nodes; i++) {

		/* Skip invalid config ROMs */
		if (CFGROM_VALID(&hal->topology_tree[i])) {

			ASSERT(hal->topology_tree[i].cfgrom);

			bus_capabilities = hal->topology_tree[i].
			    cfgrom[IEEE1212_NODE_CAP_QUAD];

			/* Skip if Bus_Info_Block generation is 0 */
			/* because it isn't a P1394a device */
			if ((bus_capabilities & IEEE1394_BIB_GEN_MASK) != 0) {
				link_speed = (bus_capabilities &
				    IEEE1394_BIB_LNK_SPD_MASK);

				for (j = 0; j < number_of_nodes; j++) {
					/* Update if link_speed is slower */
					if (hal->speed_map[i][j] > link_speed) {
						hal->speed_map[i][j] =
						    link_speed;
						hal->speed_map[j][i] =
						    link_speed;
					}

					if (link_speed <
					    hal->slowest_node_speed)
						hal->slowest_node_speed =
						    link_speed;
				}
			}
		}
	}
}

/*
 * s1394_get_isoch_rsrc_mgr()
 *    looks at the SelfID packets to determine the Isochronous Resource
 *    Manager's node ID.  The IRM is the highest numbered node with both
 *    the "L"-bit and the "C"-bit in its SelfID packets turned on.  If no
 *    IRM is found on the bus, then -1 is returned.
 */
int
s1394_get_isoch_rsrc_mgr(s1394_hal_t *hal)
{
	int	i;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	for (i = hal->number_of_nodes - 1; i >= 0; i--) {
		/* Highest numbered node with L=1 and C=1 */
		if ((IEEE1394_SELFID_ISLINKON(hal->selfid_ptrs[i])) &&
		    (IEEE1394_SELFID_ISCONTENDER(hal->selfid_ptrs[i]))) {
			return (i);
		}
	}

	/* No Isochronous Resource Manager */
	return (-1);
}

/*
 * s1394_physical_arreq_setup_all()
 *    is used to enable the physical filters for the link.  If a target has
 *    registered physical space allocations, then the corresponding node's
 *    bit is set.  This is done for all targets on a HAL (usually after bus
 *    reset).
 */
void
s1394_physical_arreq_setup_all(s1394_hal_t *hal)
{
	s1394_target_t	*curr_target;
	uint64_t	mask = 0;
	uint32_t	node_num;
	uint_t		generation;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	mutex_enter(&hal->topology_tree_mutex);
	generation = hal->generation_count;
	rw_enter(&hal->target_list_rwlock, RW_READER);

	curr_target = hal->target_head;
	while (curr_target != NULL) {
		if ((curr_target->on_node != NULL) &&
		    (curr_target->physical_arreq_enabled != 0)) {
			node_num = curr_target->on_node->node_num;
			mask = mask | (1 << node_num);
		}
		curr_target = curr_target->target_next;
	}
	rw_exit(&hal->target_list_rwlock);
	mutex_exit(&hal->topology_tree_mutex);

	/*
	 * Since it is cleared to 0 on bus reset, set the bits for all
	 * nodes.  This call returns DDI_FAILURE if the generation passed
	 * is invalid or if the HAL is shutdown.  In either case, it is
	 * acceptable to simply ignore the result and return.
	 */
	(void) HAL_CALL(hal).physical_arreq_enable_set(
	    hal->halinfo.hal_private, mask, generation);
}

/*
 * s1394_physical_arreq_set_one()
 *    is used to enable the physical filters for the link.  If a target has
 *    registered physical space allocations, then the corresponding node's
 *    bit is set.  This is done for one target.
 */
void
s1394_physical_arreq_set_one(s1394_target_t *target)
{
	s1394_hal_t	*hal;
	uint64_t	mask = 0;
	uint32_t	node_num;
	uint_t		generation;

	/* Find the HAL this target resides on */
	hal = target->on_hal;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	mutex_enter(&hal->topology_tree_mutex);
	rw_enter(&hal->target_list_rwlock, RW_READER);

	if ((target->on_node != NULL) &&
	    (target->physical_arreq_enabled != 0)) {
		node_num = target->on_node->node_num;
		mask = mask | (1 << node_num);

		generation = hal->generation_count;

		rw_exit(&hal->target_list_rwlock);
		mutex_exit(&hal->topology_tree_mutex);

		/*
		 * Set the bit corresponding to this node.  This call
		 * returns DDI_FAILURE if the generation passed
		 * is invalid or if the HAL is shutdown.  In either case,
		 * it is acceptable to simply ignore the result and return.
		 */
		(void) HAL_CALL(hal).physical_arreq_enable_set(
		    hal->halinfo.hal_private, mask, generation);
	} else {
		rw_exit(&hal->target_list_rwlock);
		mutex_exit(&hal->topology_tree_mutex);
	}
}

/*
 * s1394_physical_arreq_clear_one()
 *    is used to disable the physical filters for OpenHCI.  If a target frees
 *    up the last of its registered physical space, then the corresponding
 *    node's bit is cleared.  This is done for one target.
 */
void
s1394_physical_arreq_clear_one(s1394_target_t *target)
{
	s1394_hal_t	*hal;
	uint64_t	mask = 0;
	uint32_t	node_num;
	uint_t		generation;

	/* Find the HAL this target resides on */
	hal = target->on_hal;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	mutex_enter(&hal->topology_tree_mutex);
	rw_enter(&hal->target_list_rwlock, RW_READER);

	if ((target->on_node != NULL) &&
	    (target->physical_arreq_enabled == 0)) {
		node_num = target->on_node->node_num;
		mask = mask | (1 << node_num);

		generation = hal->generation_count;

		rw_exit(&hal->target_list_rwlock);
		mutex_exit(&hal->topology_tree_mutex);

		/*
		 * Set the bit corresponding to this node.  This call
		 * returns DDI_FAILURE if the generation passed
		 * is invalid or if the HAL is shutdown.  In either case,
		 * it is acceptable to simply ignore the result and return.
		 */
		(void) HAL_CALL(hal).physical_arreq_enable_clr(
		    hal->halinfo.hal_private, mask, generation);
	} else {
		rw_exit(&hal->target_list_rwlock);
		mutex_exit(&hal->topology_tree_mutex);
	}
}

/*
 * s1394_topology_tree_get_root_node()
 *    returns the last entry in topology_tree[] as this must always be the
 *    root node.
 */
s1394_node_t *
s1394_topology_tree_get_root_node(s1394_hal_t *hal)
{
	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	return (&hal->topology_tree[hal->number_of_nodes - 1]);
}
