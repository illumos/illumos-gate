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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RSMAPI_H
#define	_RSMAPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <poll.h>
#include <sys/param.h>
#include <sys/rsm/rsm_common.h>
#include <sys/rsm/rsmapi_common.h>

typedef enum {
	RSM_MAP_NONE = 0x0,
	RSM_MAP_FIXED = 0x1,
	RSM_MAP_RESERVED = 0x2
}rsm_attribute_t;

/*
 * Topology data structures - The primary structure is struct rsm_topology_t
 *
 * The key interconnect data required for segment operations includes the
 * cluster nodeids and the controllers (name, hardware address); with
 * the fundamental constraint that the controller specified for a segment
 * import must have a physical connection with the contorller used in the
 * export of the segment. To facilitate applications in the establishment
 * of proper and efficient export and import policies, a delineation of the
 * interconnect topology is provided by these data structures.
 *
 */


#define	RSM_CONNECTION_ACTIVE	3


typedef struct rsm_topology_hdr {
	rsm_node_id_t		local_nodeid;
	uint_t			local_cntlr_count;
} rsm_topology_hdr_t;


typedef struct rsm_connections_hdr {
	char		cntlr_name[MAXNAMELEN]; /* <cntlr_type><unit> */
	rsm_addr_t	local_hwaddr;
	int		remote_cntlr_count;
} rsm_connections_hdr_t;


/*
 * The remote cntrlname element should be used for matching with the
 * cntrlname of an exported segment.
 *
 * An application must not attempt to use a connection unless the
 * the connection_state element of struct rsm_remote_cntlr_t is equal to
 * RSM_CONNECTION_ACTIVE
 */
typedef struct rsm_remote_cntlr {
	rsm_node_id_t		remote_nodeid;
	char			remote_cntlrname[MAXNAMELEN];
	rsm_addr_t		remote_hwaddr;
	uint_t			connection_state;
} rsm_remote_cntlr_t;


/*
 * The actual size of the remote_cntlr array is equal to the remote_cntlr_count
 * of the rsm_connections_hdr_t struct.
 */
typedef struct rsm_connection {
	rsm_connections_hdr_t	hdr;
	rsm_remote_cntlr_t	remote_cntlr[1];
} rsm_connections_t;


/*
 * A pointer to an instance of this structure type is returned by a call
 * to rsm_get_interconnect_topology().  The actual size of the connections
 * array is equal to the local_cntlr_count of the rsm_topology_hdr_t struct.
 */
typedef struct rsm_topology {
	rsm_topology_hdr_t	topology_hdr;
	rsm_connections_t	*connections[1];
} rsm_topology_t;

/*
 * function templates:
 */

int rsm_get_controller(char *name, rsmapi_controller_handle_t *controller);

int rsm_get_controller_attr(rsmapi_controller_handle_t chdl,
    rsmapi_controller_attr_t *attr);

int rsm_release_controller(rsmapi_controller_handle_t controller);

/*
 * Export side memory segment operations
 */
int rsm_memseg_export_create(rsmapi_controller_handle_t controller,
    rsm_memseg_export_handle_t *memseg,
    void *vaddr, size_t size, uint_t flags);


int rsm_memseg_export_destroy(rsm_memseg_export_handle_t memseg);



int rsm_memseg_export_rebind(rsm_memseg_export_handle_t memseg,
    void *vaddr, offset_t off, size_t size);



int rsm_memseg_export_publish(rsm_memseg_export_handle_t memseg,
    rsm_memseg_id_t *segment_id,
    rsmapi_access_entry_t access_list[],
    uint_t access_list_length);


int rsm_memseg_export_unpublish(rsm_memseg_export_handle_t memseg);

int rsm_memseg_export_republish(rsm_memseg_export_handle_t memseg,
    rsmapi_access_entry_t access_list[],
    uint_t access_list_length);







/*
 * import side memory segment operations:
 */

int rsm_memseg_import_connect(rsmapi_controller_handle_t controller,
    rsm_node_id_t node_id,
    rsm_memseg_id_t segment_id,
    rsm_permission_t perm,
    rsm_memseg_import_handle_t *im_memseg);


int rsm_memseg_import_disconnect(rsm_memseg_import_handle_t im_memseg);



/*
 * import side memory segment operations (read access functions):
 */
int rsm_memseg_import_get8(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint8_t *datap,
    ulong_t rep_cnt);
int rsm_memseg_import_get16(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint16_t *datap,
    ulong_t rep_cnt);
int rsm_memseg_import_get32(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint32_t *datap,
    ulong_t rep_cnt);
int rsm_memseg_import_get64(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint64_t *datap,
    ulong_t rep_cnt);
int rsm_memseg_import_get(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    void *dst_addr,
    size_t length);

int rsm_memseg_import_getv(rsm_scat_gath_t *);



/*
 * import side memory segment operations (write access functions):
 */
int rsm_memseg_import_put8(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint8_t *datap,
    ulong_t rep_cnt);
int rsm_memseg_import_put16(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint16_t *datap,
    ulong_t rep_cnt);
int rsm_memseg_import_put32(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint32_t *datap,
    ulong_t rep_cnt);
int rsm_memseg_import_put64(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint64_t *datap,
    ulong_t rep_cnt);
int rsm_memseg_import_put(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    void *src_addr,
    size_t length);

int rsm_memseg_import_putv(rsm_scat_gath_t *);


/*
 * import side memory segment operations (mapping):
 */
int rsm_memseg_import_map(rsm_memseg_import_handle_t im_memseg,
    void **address,
    rsm_attribute_t attr,
    rsm_permission_t perm,
    off_t offset, size_t length);




int rsm_memseg_import_unmap(rsm_memseg_import_handle_t im_memseg);



/*
 * import side memory segment operations (barriers):
 */

int rsm_memseg_import_init_barrier(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_type_t type,
    rsmapi_barrier_t *barrier);


int rsm_memseg_import_open_barrier(rsmapi_barrier_t *barrier);


int rsm_memseg_import_close_barrier(rsmapi_barrier_t *barrier);

int rsm_memseg_import_order_barrier(rsmapi_barrier_t *barrier);

int rsm_memseg_import_destroy_barrier(rsmapi_barrier_t *barrier);

int rsm_memseg_import_get_mode(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_mode_t *mode);

int rsm_memseg_import_set_mode(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_mode_t mode);




int rsm_intr_signal_post(void * im_memseg, uint_t flags);

int rsm_intr_signal_wait(void * im_memseg, int timeout);

int rsm_memseg_get_pollfd(void *, struct pollfd *);
int rsm_memseg_release_pollfd(void *);

int rsm_get_interconnect_topology(rsm_topology_t **);
void rsm_free_interconnect_topology(rsm_topology_t *);

int rsm_create_localmemory_handle(rsmapi_controller_handle_t,
    rsm_localmemory_handle_t *,
    caddr_t, size_t);

int rsm_free_localmemory_handle(rsmapi_controller_handle_t,
    rsm_localmemory_handle_t);

int rsm_get_segmentid_range(const char *, rsm_memseg_id_t *, uint32_t *);

int rsm_intr_signal_wait_pollfd(struct pollfd [], nfds_t, int, int *);

#ifdef	__cplusplus
}
#endif

#endif	/* _RSMAPI_H */
