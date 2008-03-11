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

#ifndef	_SYS_XENDEV_H
#define	_SYS_XENDEV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/hypervisor.h>
#include <sys/taskq.h>
#ifdef	XPV_HVM_DRIVER
#include <public/io/ring.h>
#include <public/event_channel.h>
#include <public/grant_table.h>
#endif
#include <xen/sys/xenbus_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Xen device class codes
 */
typedef enum {
	XEN_INVAL = -1,
	XEN_CONSOLE = 0,
	XEN_VNET,
	XEN_VBLK,
	XEN_XENBUS,
	XEN_DOMCAPS,
	XEN_BALLOON,
	XEN_EVTCHN,
	XEN_PRIVCMD,
	XEN_LASTCLASS
} xendev_devclass_t;

/*
 * Hotplug request sent to userland event handler.
 */
typedef enum {
	XEN_HP_ADD,
	XEN_HP_REMOVE
} xendev_hotplug_cmd_t;

/*
 * Hotplug status.
 *
 * In fact, the Xen tools can write any arbitrary string into the
 * hotplug-status node. We represent the known values here - anything
 * else will be 'Unrecognized'.
 */
typedef enum {
	Unrecognized,
	Connected
} xendev_hotplug_state_t;

struct xendev_ppd {
	int			xd_evtchn;
	struct intrspec		xd_ispec;
	xendev_devclass_t	xd_devclass;
	domid_t			xd_domain;
	int			xd_vdevnum;
	struct xenbus_device	xd_xsdev;
	struct xenbus_watch	xd_hp_watch;
	struct xenbus_watch	xd_bepath_watch;
	kmutex_t		xd_lk;
	ddi_callback_id_t	xd_oe_ehid;
	ddi_callback_id_t	xd_hp_ehid;
	ddi_taskq_t		*xd_oe_taskq;
	ddi_taskq_t		*xd_hp_taskq;
};

#define	XS_OE_STATE	"SUNW,xendev:otherend_state"
#define	XS_HP_STATE	"SUNW,xendev:hotplug_state"

/*
 * A device with xd_vdevnum == VDEV_NOXS does not participate in
 * xenstore.
 */
#define	VDEV_NOXS	(-1)

void	xendev_enum_class(dev_info_t *, xendev_devclass_t);
void	xendev_enum_all(dev_info_t *, boolean_t);
xendev_devclass_t	xendev_nodename_to_devclass(char *);
int	xendev_devclass_ipl(xendev_devclass_t);
struct intrspec *xendev_get_ispec(dev_info_t *, uint_t);
void	xvdi_suspend(dev_info_t *);
int	xvdi_resume(dev_info_t *);
int	xvdi_alloc_evtchn(dev_info_t *);
int	xvdi_bind_evtchn(dev_info_t *, evtchn_port_t);
void	xvdi_free_evtchn(dev_info_t *);
int	xvdi_add_event_handler(dev_info_t *, char *,
	void (*)(dev_info_t *, ddi_eventcookie_t, void *, void *));
void	xvdi_remove_event_handler(dev_info_t *, char *);
int	xvdi_get_evtchn(dev_info_t *);
int	xvdi_get_vdevnum(dev_info_t *);
char	*xvdi_get_xsname(dev_info_t *);
char	*xvdi_get_oename(dev_info_t *);
domid_t	xvdi_get_oeid(dev_info_t *);
void	xvdi_dev_error(dev_info_t *, int, char *);
void	xvdi_fatal_error(dev_info_t *, int, char *);
void	xvdi_notify_oe(dev_info_t *);
int	xvdi_post_event(dev_info_t *, xendev_hotplug_cmd_t);
struct  xenbus_device *xvdi_get_xsd(dev_info_t *);
int	xvdi_switch_state(dev_info_t *, xenbus_transaction_t, XenbusState);
dev_info_t	*xvdi_create_dev(dev_info_t *, xendev_devclass_t,
    domid_t, int);
int	xvdi_init_dev(dev_info_t *);
void	xvdi_uninit_dev(dev_info_t *);
dev_info_t	*xvdi_find_dev(dev_info_t *, xendev_devclass_t, domid_t, int);

/*
 * common ring interfaces
 */

/*
 * we need the pad between ring index
 * and the real ring containing requests/responses,
 * so that we can map comif_sring_t structure to
 * any xxxif_sring_t structure defined via macros in ring.h
 */
#define	SRINGPAD		48

typedef struct comif_sring {
	RING_IDX req_prod, req_event;
	RING_IDX rsp_prod, rsp_event;
	uint8_t  pad[SRINGPAD];
	/*
	 * variable length
	 * stores real request/response entries
	 * entry size is fixed per ring
	 */
	char ring[1];
} comif_sring_t;

typedef struct comif_ring_fe {
	/*
	 * keep the member names as defined in ring.h
	 * in order to make use of the pre-defined macros
	 */
	RING_IDX req_prod_pvt;
	RING_IDX rsp_cons;
	unsigned int nr_ents;
	comif_sring_t *sring;
} comif_ring_fe_t;

typedef struct comif_ring_be {
	/*
	 * keep the member names as defined in ring.h
	 * in order to make use of the pre-defined macros
	 */
	RING_IDX rsp_prod_pvt;
	RING_IDX req_cons;
	unsigned int nr_ents;
	comif_sring_t  *sring;
} comif_ring_be_t;

typedef union comif_ring {
	comif_ring_fe_t fr;
	comif_ring_be_t br;
} comif_ring_t;

typedef struct xendev_req {
	unsigned long next;
	void *req;
} xendev_req_t;

typedef struct xendev_ring {
	ddi_dma_handle_t xr_dma_hdl;
	ddi_acc_handle_t xr_acc_hdl;
	grant_handle_t xr_grant_hdl;
	caddr_t xr_vaddr;
	paddr_t xr_paddr;
	grant_ref_t xr_gref;
	int xr_entry_size;
	int xr_frontend;
	comif_ring_t xr_sring;
} xendev_ring_t;

int	xvdi_alloc_ring(dev_info_t *, size_t, size_t, grant_ref_t *,
	xendev_ring_t **);
void	xvdi_free_ring(xendev_ring_t *);
int	xvdi_map_ring(dev_info_t *, size_t, size_t, grant_ref_t,
	xendev_ring_t **);
void	xvdi_unmap_ring(xendev_ring_t *);
uint_t	xvdi_ring_avail_slots(xendev_ring_t *);
int	xvdi_ring_has_unconsumed_requests(xendev_ring_t *);
int	xvdi_ring_has_incomp_request(xendev_ring_t *);
int	xvdi_ring_has_unconsumed_responses(xendev_ring_t *);
void*	xvdi_ring_get_request(xendev_ring_t *);
int	xvdi_ring_push_request(xendev_ring_t *);
void*	xvdi_ring_get_response(xendev_ring_t *);
int	xvdi_ring_push_response(xendev_ring_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_XENDEV_H */
