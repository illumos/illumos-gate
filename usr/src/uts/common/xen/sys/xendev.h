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

#ifndef	_SYS_XENDEV_H
#define	_SYS_XENDEV_H


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
 * Xenbus property interfaces, initialized by framework
 */
#define	XBP_HP_STATUS		"hotplug-status"	/* backend prop: str */
#define	XBV_HP_STATUS_CONN	"connected"		/* backend prop val */
#define	XBP_DEV_TYPE		"device-type"		/* backend prop: str */
#define	XBV_DEV_TYPE_CD		"cdrom"			/* backend prop val */

/*
 * Xenbus property interfaces, initialized by backend disk driver
 */
#define	XBP_SECTORS	"sectors"		/* backend prop: uint64 */
#define	XBP_INFO	"info"			/* backend prop: uint */
#define	XBP_FB		"feature-barrier"	/* backend prop: boolean int */

/*
 * Xenbus property interfaces, initialized by frontend disk driver
 */
#define	XBP_RING_REF	"ring-ref"		/* frontend prop: long */
#define	XBP_EVENT_CHAN	"event-channel"		/* frontend prop: long */
#define	XBP_PROTOCOL	"protocol"		/* frontend prop: string */

/*
 * Xenbus CDROM property interfaces, used by backend and frontend
 *
 * XBP_MEDIA_REQ_SUP
 *	- Backend xenbus property located at:
 *		backend/vbd/<domU_id>/<domU_dev>/media-req-sup
 *	- Set by the backend, consumed by the frontend.
 *	- Cosumed by the frontend.
 *	- A boolean integer property indicating backend support
 *	  for the XBP_MEDIA_REQ property.
 *
 * XBP_MEDIA_REQ
 *	- Frontend xenbus property located at:
 *		/local/domain/<domU_id>/device/vbd/<domU_dev>/media-req
 *	- Set and consumed by both the frontend and backend.
 *	- Possible values:
 *		XBV_MEDIA_REQ_NONE, XBV_MEDIA_REQ_LOCK, and XBV_MEDIA_REQ_EJECT
 *	- Only applies to CDROM devices.
 *
 * XBV_MEDIA_REQ_NONE
 * 	- XBP_MEDIA_REQ property valud
 *	- Set and consumed by both the frontend and backend.
 *	- Indicates that there are no currently outstanding media requet
 *	  operations.
 *
 * XBV_MEDIA_REQ_LOCK
 * 	- XBP_MEDIA_REQ property valud
 *	- Set by the frontend, consumed by the backend.
 *	- Indicates to the backend that the currenct media is locked
 *	  and changes to the media (via xm block-configure for example)
 *	  should not be allowed.
 *
 * XBV_MEDIA_REQ_EJECT
 * 	- XBP_MEDIA_REQ property valud
 *	- Set by the frontend, consumed by the backend.
 *	- Indicates to the backend that the currenct media should be ejected.
 *	  This means that the backend should close it's connection to
 *	  the frontend device, close it's current backing store device/file,
 *	  and then set the media-req property to XBV_MEDIA_REQ_NONE.  (to
 *	  indicate that the eject operation is complete.)
 */
#define	XBP_MEDIA_REQ_SUP	"media-req-sup"	/* backend prop: boolean int */
#define	XBP_MEDIA_REQ		"media-req"	/* frontend prop: str */
#define	XBV_MEDIA_REQ_NONE	"none"		/* frontend prop val */
#define	XBV_MEDIA_REQ_LOCK	"lock"		/* frontend prop val */
#define	XBV_MEDIA_REQ_EJECT	"eject"		/* frontend prop val */

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
	XEN_BLKTAP,
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
	kmutex_t		xd_evt_lk;
	int			xd_evtchn;
	struct intrspec		xd_ispec;

	xendev_devclass_t	xd_devclass;
	domid_t			xd_domain;
	int			xd_vdevnum;

	kmutex_t		xd_ndi_lk;
	struct xenbus_device	xd_xsdev;
	struct xenbus_watch	xd_hp_watch;
	struct xenbus_watch	xd_bepath_watch;
	ddi_callback_id_t	xd_oe_ehid;
	ddi_callback_id_t	xd_hp_ehid;
	ddi_taskq_t		*xd_oe_taskq;
	ddi_taskq_t		*xd_hp_taskq;
	ddi_taskq_t		*xd_xb_watch_taskq;
	list_t			xd_xb_watches;
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
	void (*)(dev_info_t *, ddi_eventcookie_t, void *, void *),
	void *arg);
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

extern int xvdi_add_xb_watch_handler(dev_info_t *, const char *,
    const char *, xvdi_xb_watch_cb_t cb, void *);
extern void xvdi_remove_xb_watch_handlers(dev_info_t *);

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
