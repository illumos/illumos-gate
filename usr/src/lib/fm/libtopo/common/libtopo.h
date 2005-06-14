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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBTOPO_H
#define	_LIBTOPO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libnvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * System Topology Modeling Library generic interfaces
 *
 * Note: The contents of this file are private to the implementation of the
 * Solaris system and FMD subsystem and are subject to change at any time
 * without notice.  Applications and drivers using these interfaces will fail
 * to run on future releases.  These interfaces should not be used for any
 * purpose until they are publicly documented for use outside of Sun.
 *
 * Library libtopo is intended as a simple, extensible, library for
 * capturing hardware topology information.  System topology is
 * abstracted in a tree of "topology nodes" or "tnode_t"s.  The
 * topology tree is constructed by combining static topology
 * information from ".topo" files with instance information collected
 * by enumerators.  An enumerator is software either built-in to or
 * loaded by libtopo to search for and enumerate hardware components
 * present in the system.  Parsing the static information in the
 * system's ".topo" files produces a topology tree including many
 * possible topologies.  Enumerators then refine the topology tree to
 * include only those hardware components actually present in the
 * system.
 */

/*
 * A topology tree node is an opaque tnode_t.
 */
typedef struct tnode tnode_t;

/*
 * A topology consumer can traverse the entire topology tree.
 * Consumers first must acquire a pointer to the root of the tree.
 * There are two ways to do this, for example:
 *
 * root = topo_next_sibling(NULL, NULL); or
 * root = topo_next_child(NULL, NULL);
 *
 * Consumers should call topo_tree_release() with the acquired root
 * when the topology tree (including any node properties) is no longer
 * needed.
 */
tnode_t *topo_parent(tnode_t *);
tnode_t *topo_next_sibling(tnode_t *, tnode_t *);
tnode_t *topo_next_child(tnode_t *, tnode_t *);

void topo_tree_release(tnode_t *);

/*
 * Each topo node includes a name, representing a specific type of
 * hardware component.  The name of a given node may be retrieved via
 * this function...
 */
const char *topo_name(tnode_t *);

/*
 * In addition to a name, topo nodes have instance information.  Topo
 * nodes resulting from parsing .topo files have either specific
 * instance numbers or allowed ranges of instance numbers, indicating
 * that the hardware components may or may not be present.  Consider a
 * very simple system that has a motherboard and up to four I/O
 * controllers.  The .topo file for such a system might look like
 * this:
 *
 *	/mb0/io[0-3]
 *
 * Parsing this .topo file results in a topology tree with two nodes,
 * one with a specific instance number and one with an allowed range.
 *
 *	[mb 0]
 *	 |
 *	 |
 *	[io 0-3]
 *
 * The topo_get_instance_num() interface retrieves the instance number
 * of a topo node.  If the instance number for the node is set, the
 * instance number is returned.  If the instance number for the node
 * is not set, the value -1 is returned.  The range of allowed
 * instances can then be determined with topo_get_instance_range().
 * If this function is called for a node with a set instance number
 * the min and max returned will both be -1.
 *
 * After the .topo file is parsed the "io" enumerator is called to
 * refine the tree.  The enumerator is provided with a pointer to the
 * tnode_t for the io topo node.  If, for example, the system in
 * question has only two I/O controllers, with instances 1 and 3, the
 * enumerator will twice call topo_set_instance_num().  The first time
 * it will provide the given tnode_t * and the instance number 1.  The
 * second time it will provide the given tnode_t * and the instance
 * number 3.  After the enumerator makes these calls the topology tree
 * looks like this:
 *
 *	    [mb 0]
 *	    /   \ \______
 *	   /     \       \
 *	[io 0-3]  [io 1]  [io 3]
 *
 *  When all enumerators have completed their work, the library makes
 *  a final pass through the topology tree and eliminates nodes
 *  without set instance numbers.  The final topology tree for our
 *  example looks like:
 *
 *	    [mb 0]
 *	     |   \
 *	     |    \
 *	  [io 1]  [io 3]
 */
int topo_get_instance_num(tnode_t *);
void topo_get_instance_range(tnode_t *, int *, int *);
tnode_t *topo_set_instance_num(tnode_t *, int);

/*
 *  An enumerator may also instigate expansion of the topology tree
 *  from a given node.  A call to topo_load() forces the library to
 *  look for a .topo file to parse with the given basename, and if it
 *  finds one, parses it and adds topology nodes as children to the
 *  node given as the second argument.
 */
tnode_t *topo_load(const char *, tnode_t *);


/*
 * The libtopo library allows named properties to be attached to a
 * topo node.  A property is simply a string.  Libtopo does not
 * interpret property values in any way, it merely maintains the
 * association between the property and the node.  Properties are
 * established via topo_set_prop().  A specific property's string
 * value may be obtained with topo_get_prop().  A consumer may iterate
 * through the properties attached to a node in the following manner:
 *
 *	const char *propn = NULL;
 *
 *	while ((propn = topo_next_prop(topo_node, propn)) != NULL)
 *		printf("%s=%s", propn, topo_get_prop(topo_node, propn));
 */
const char *topo_get_prop(tnode_t *, const char *);
const char *topo_next_prop(tnode_t *, const char *);
int topo_set_prop(tnode_t *, const char *, const char *);

/*
 * For quick lookups, libtopo indexes all properties set on all topo
 * nodes.  The topo_find_propval() interface may be used to iterate
 * through all ALL topo nodes having a property that matches both the
 * requested name and requested value.  The initial call can be made
 * from any topo node (the first argument must be a valid non-NULL
 * tnode_t pointer anywhere in the current topology tree) and 'more'
 * should point to a NULL value.  Multiple matches can be found by
 * making successive calls to the function, sending the 'more' cookie
 * back to the function untouched.  The function returns a pointer to
 * the matching node or NULL if no further matches exist in the
 * topology tree.
 */
tnode_t *topo_find_propval(tnode_t *, const char *, const char *,
    void **);

/*
 * The entire topology tree can be visited with a callback to a
 * consumer function using topo_walk().  The second argument is a flag
 * specifying whether to visit a node before or after its children.
 */
#define	TOPO_VISIT_SELF_FIRST		1
#define	TOPO_VISIT_CHILDREN_FIRST	2

void topo_walk(tnode_t *, int, void *, void (*cb)(tnode_t *, void *));

/*
 *  A topology node can be represented both as a path and an FMRI.
 *  The topo_hc_path() and topo_hc_fmri() functions provide a path to
 *  or FMRI describing, respectively, the specified node.  The
 *  topo_hc_path() function allocates space, the caller should use
 *  topo_free_path() to de-allocate that space when it's finished with
 *  the path.  The topo_hc_fmri() function allocates an nvlist.  The
 *  caller should use topo_free_fmri() to de-allocate this space when
 *  its finished with the FMRI.
 *
 *  A consumer may also use topo_find_path() to search for the
 *  topology node corresponding to a provided hc path.  The first
 *  argument must be a valid non-NULL tnode_t pointer anywhere in the
 *  current topology tree.
 */
char *topo_hc_path(tnode_t *);
nvlist_t *topo_hc_fmri(tnode_t *);

tnode_t *topo_find_path(tnode_t *, char *);

void topo_free_path(char *);
void topo_free_fmri(nvlist_t *);

/*
 *  The topo_init() function must be called once by a consumer to
 *  initialize the topology library.  This routine must be called
 *  prior to attempting to access any topo nodes.  A set of paths to
 *  be searched for .topo files may optionally be provided (the first
 *  argument is the number of paths provided, the second argument is
 *  an array of path strings).  If no paths are provided, the library
 *  by default searches first in /usr/lib/fm/topo/`uname -i`, and
 *  second in /usr/lib/fm/topo.
 *
 *  The topo_fini() function should be called when libtopo functions
 *  are no longer needed and all topology trees have been released.  The
 *  topo_reset() function resets all enumerators but leaves other libtopo
 *  state (such as memory and out methods) unscathed.  The topo_reset()
 *  function can be used to ensure an ensuing topology snapshot is not
 *  created from any cached enumerator state.
 */
void topo_init(int, const char **);
void topo_fini(void);
void topo_reset(void);

/*
 *  The topo library does not presume it may write to the stdout or
 *  stderr of its consumer.  Instead, error and debugging messages
 *  from the library are buffered.
 *
 *  Debugging output from libtopo may be enabled/disabled by calling
 *  these functions.  The flags argument is reserved for future use and
 *  should always be zero.  This output is disabled by default.  An output
 *  method must be established to display or otherwise capture the
 *  output.  See topo_set_out_method() below.
 */
void topo_debug_on(uint_t flags);
void topo_debug_off(void);

/*
 *  Retrieve the current line in the message buffer.
 */
const char *topo_errbuf(void);

/*
 *  Flags to control writes to the message buffer (via
 *  topo_out()).  One or more flags may be bitwise ORd together.
 *  Writes with TOPO_DEBUG set will only make it to the buffer (and
 *  further captured via the output method) if topo_debug_on() has been
 *  called.
 */
#define	TOPO_ERR	0x1
#define	TOPO_DEBUG	0x2

/*
 *  Write data to the message buffer.  The first argument is a flag
 *  that determines what calls succeed in getting data into the buffer.
 */
void topo_out(int flag, char *format, ...);

/*
 *  Interface manipulation
 *	Allow override of defaults for:
 *
 *	no-fail, zeroed memory allocator/de-allocator (topo_set_mem_methods)
 *
 *	Function for displaying or otherwise capturing the contents of the
 *	message buffer. (topo_set_out_method)
 */
void topo_set_mem_methods(void * (*zallocfn)(size_t), void (*freefn)(void *));
void topo_set_out_method(void (*outfn)(const char *));

/*
 *  Given the name of a driver, topo can search out module information
 *  and create a 'mod' scheme FMRI representing the driver as
 *  an ASRU.  As part of determining this FMRI's contents, the FRU FMRI
 *  for the driver is also determined, and will be returned in the frup
 *  argument if it is non-NULL.
 *
 *  Use topo_free_fmri() to de-allocate the space assigned to FMRIs
 *  retrieved using these functions.  No topology node is necessary to
 *  obtain this information.
 */
nvlist_t *topo_driver_asru(const char *, nvlist_t **frup);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBTOPO_H */
