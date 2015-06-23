/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#define	DEF_EVENT_STRUCT  /* Needed for emlxs_events.h in emlxs_event.h */
#include <emlxs.h>


/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_EVENT_C);


static uint32_t emlxs_event_check(emlxs_port_t *port, emlxs_event_t *evt);
static void emlxs_event_destroy(emlxs_hba_t *hba, emlxs_event_entry_t *entry);

extern void
emlxs_null_func() {}


static uint32_t
emlxs_event_check(emlxs_port_t *port, emlxs_event_t *evt)
{
	emlxs_hba_t *hba = HBA;

	/* Check if the event is being requested */
	if ((hba->event_mask & evt->mask)) {
		return (1);
	}

#ifdef SAN_DIAG_SUPPORT
	if ((port->sd_event_mask & evt->mask)) {
		return (1);
	}
#endif /* SAN_DIAG_SUPPORT */

	return (0);

} /* emlxs_event_check() */


extern uint32_t
emlxs_event_queue_create(emlxs_hba_t *hba)
{
	emlxs_event_queue_t *eventq = &EVENTQ;
	ddi_iblock_cookie_t iblock;

	/* Clear the queue */
	bzero(eventq, sizeof (emlxs_event_queue_t));

	cv_init(&eventq->lock_cv, NULL, CV_DRIVER, NULL);

	if (!(hba->intr_flags & EMLXS_MSI_ENABLED)) {
		/* Get the current interrupt block cookie */
		(void) ddi_get_iblock_cookie(hba->dip, (uint_t)EMLXS_INUMBER,
		    &iblock);

		/* Create the mutex lock */
		mutex_init(&eventq->lock, NULL, MUTEX_DRIVER, (void *)iblock);
	}
#ifdef  MSI_SUPPORT
	else {
		/* Create event mutex lock */
		mutex_init(&eventq->lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(hba->intr_arg));
	}
#endif

	return (1);

} /* emlxs_event_queue_create() */


extern void
emlxs_event_queue_destroy(emlxs_hba_t *hba)
{
	emlxs_port_t *vport;
	emlxs_event_queue_t *eventq = &EVENTQ;
	uint32_t i;
	uint32_t wakeup = 0;

	mutex_enter(&eventq->lock);

	/* Clear all event masks and broadcast a wakeup */
	/* to clear any sleeping threads */
	if (hba->event_mask) {
		hba->event_mask = 0;
		hba->event_timer = 0;
		wakeup = 1;
	}

	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);

		if (vport->sd_event_mask) {
			vport->sd_event_mask = 0;
			wakeup = 1;
		}
	}

	if (wakeup) {
		cv_broadcast(&eventq->lock_cv);

		mutex_exit(&eventq->lock);
		BUSYWAIT_MS(10);
		mutex_enter(&eventq->lock);
	}

	/* Destroy the remaining events */
	while (eventq->first) {
		emlxs_event_destroy(hba, eventq->first);
	}

	mutex_exit(&eventq->lock);

	/* Destroy the queue lock */
	mutex_destroy(&eventq->lock);
	cv_destroy(&eventq->lock_cv);

	/* Clear the queue */
	bzero(eventq, sizeof (emlxs_event_queue_t));

	return;

} /* emlxs_event_queue_destroy() */


/* Event queue lock must be held */
static void
emlxs_event_destroy(emlxs_hba_t *hba, emlxs_event_entry_t *entry)
{
	emlxs_event_queue_t *eventq = &EVENTQ;
	emlxs_port_t *port;
	uint32_t missed = 0;

	port = (emlxs_port_t *)entry->port;

	eventq->count--;
	if (eventq->count == 0) {
		eventq->first = NULL;
		eventq->last = NULL;
	} else {
		if (entry->prev) {
			entry->prev->next = entry->next;
		}
		if (entry->next) {
			entry->next->prev = entry->prev;
		}
		if (eventq->first == entry) {
			eventq->first = entry->next;
		}
		if (eventq->last == entry) {
			eventq->last = entry->prev;
		}
	}

	entry->prev = NULL;
	entry->next = NULL;

	if ((entry->evt->mask == EVT_LINK) ||
	    (entry->evt->mask == EVT_RSCN)) {
		if (!(entry->flag & EMLXS_DFC_EVENT_DONE)) {
			hba->hba_event.missed++;
			missed = 1;
		}
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_dequeued_msg,
	    "%s[%d]: flag=%x missed=%d cnt=%d",
	    entry->evt->label, entry->id, entry->flag, missed, eventq->count);

	/* Call notification handler */
	if (entry->evt->destroy != emlxs_null_func) {
		entry->evt->destroy(entry);
	}

	/* Free context buffer */
	if (entry->bp && entry->size) {
		kmem_free(entry->bp, entry->size);
	}

	/* Free entry buffer */
	kmem_free(entry, sizeof (emlxs_event_entry_t));

	return;

} /* emlxs_event_destroy() */


extern void
emlxs_event(emlxs_port_t *port, emlxs_event_t *evt, void *bp, uint32_t size)
{
	emlxs_hba_t *hba = HBA;
	emlxs_event_queue_t *eventq = &EVENTQ;
	emlxs_event_entry_t *entry;
	uint32_t i;
	uint32_t mask;

	if (emlxs_event_check(port, evt) == 0) {
		goto failed;
	}

	/* Create event entry */
	if (!(entry = (emlxs_event_entry_t *)kmem_alloc(
	    sizeof (emlxs_event_entry_t), KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s: Unable to allocate event entry.", evt->label);

		goto failed;
	}

	/* Initialize */
	bzero(entry, sizeof (emlxs_event_entry_t));

	entry->evt = evt;
	entry->port = (void *)port;
	entry->bp = bp;
	entry->size = size;

	mutex_enter(&eventq->lock);

	/* Set the event timer */
	entry->timestamp = hba->timer_tics;
	if (evt->timeout) {
		entry->timer = entry->timestamp + evt->timeout;
	}

	/* Eventq id starts with 1 */
	if (eventq->next_id == 0) {
		eventq->next_id = 1;
	}

	/* Set the event id */
	entry->id = eventq->next_id++;

	/* Set last event table */
	mask = evt->mask;
	for (i = 0; i < 32; i++) {
		if (mask & 0x01) {
			eventq->last_id[i] = entry->id;
		}
		mask >>= 1;
	}

	/* Put event on bottom of queue */
	entry->next = NULL;
	if (eventq->count == 0) {
		entry->prev = NULL;
		eventq->first = entry;
		eventq->last = entry;
	} else {
		entry->prev = eventq->last;
		entry->prev->next = entry;
		eventq->last = entry;
	}
	eventq->count++;

	if ((entry->evt->mask == EVT_LINK) ||
	    (entry->evt->mask == EVT_RSCN)) {
		hba->hba_event.new++;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_queued_msg,
	    "%s[%d]: bp=%p size=%d cnt=%d", entry->evt->label,
	    entry->id, bp, size, eventq->count);

	/* Broadcast the event */
	cv_broadcast(&eventq->lock_cv);

	mutex_exit(&eventq->lock);

	return;

failed:

	if (bp && size) {
		kmem_free(bp, size);
	}

	return;

} /* emlxs_event() */


extern void
emlxs_timer_check_events(emlxs_hba_t *hba)
{
	emlxs_config_t *cfg = &CFG;
	emlxs_event_queue_t *eventq = &EVENTQ;
	emlxs_event_entry_t *entry;
	emlxs_event_entry_t *next;

	if (!cfg[CFG_TIMEOUT_ENABLE].current) {
		return;
	}

	if ((hba->event_timer > hba->timer_tics)) {
		return;
	}

	if (eventq->count) {
		mutex_enter(&eventq->lock);

		entry = eventq->first;
		while (entry) {
			if ((!entry->timer) ||
			    (entry->timer > hba->timer_tics)) {
				entry = entry->next;
				continue;
			}

			/* Event timed out, destroy it */
			next = entry->next;
			emlxs_event_destroy(hba, entry);
			entry = next;
		}

		mutex_exit(&eventq->lock);
	}

	/* Set next event timer check */
	hba->event_timer = hba->timer_tics + EMLXS_EVENT_PERIOD;

	return;

} /* emlxs_timer_check_events() */


extern void
emlxs_log_rscn_event(emlxs_port_t *port, uint8_t *payload, uint32_t size)
{
	uint8_t *bp;
	uint32_t *ptr;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_rscn_event) == 0) {
		return;
	}

	if (size > MAX_RSCN_PAYLOAD) {
		size = MAX_RSCN_PAYLOAD;
	}

	size += sizeof (uint32_t);

	/* Save a copy of the payload for the event log */
	if (!(bp = (uint8_t *)kmem_alloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s: Unable to allocate buffer.", emlxs_rscn_event.label);

		return;
	}

	/*
	 * Buffer Format:
	 *	word[0] = DID of the RSCN
	 *	word[1] = RSCN Payload
	 */
	ptr = (uint32_t *)bp;
	*ptr++ = port->did;
	bcopy(payload, (char *)ptr, (size - sizeof (uint32_t)));

	emlxs_event(port, &emlxs_rscn_event, bp, size);

	return;

} /* emlxs_log_rscn_event() */


extern void
emlxs_log_vportrscn_event(emlxs_port_t *port, uint8_t *payload, uint32_t size)
{
	uint8_t *bp;
	uint8_t *ptr;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_vportrscn_event) == 0) {
		return;
	}

	if (size > MAX_RSCN_PAYLOAD) {
		size = MAX_RSCN_PAYLOAD;
	}

	size += sizeof (NAME_TYPE);

	/* Save a copy of the payload for the event log */
	if (!(bp = (uint8_t *)kmem_alloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s: Unable to allocate buffer.",
		    emlxs_vportrscn_event.label);

		return;
	}

	/*
	 * Buffer Format:
	 *	word[0 - 4] = WWPN of the RSCN
	 *	word[5] = RSCN Payload
	 */
	ptr = bp;
	bcopy(&port->wwpn, ptr, sizeof (NAME_TYPE));
	ptr += sizeof (NAME_TYPE);
	bcopy(payload, ptr, (size - sizeof (NAME_TYPE)));

	emlxs_event(port, &emlxs_vportrscn_event, bp, size);

	return;

} /* emlxs_log_vportrscn_event() */


extern uint32_t
emlxs_flush_ct_event(emlxs_port_t *port, uint32_t rxid)
{
	emlxs_hba_t *hba = HBA;
	emlxs_event_queue_t *eventq = &EVENTQ;
	emlxs_event_entry_t *entry;
	uint32_t *ptr;
	uint32_t found = 0;

	mutex_enter(&eventq->lock);

	for (entry = eventq->first; entry != NULL; entry = entry->next) {
		if ((entry->port != port) ||
		    (entry->evt != &emlxs_ct_event)) {
			continue;
		}

		ptr = (uint32_t *)entry->bp;
		if (rxid == *ptr) {
			/* This will prevent a CT exchange abort */
			/* in emlxs_ct_event_destroy() */
			entry->flag |= EMLXS_DFC_EVENT_DONE;

			emlxs_event_destroy(hba, entry);
			found = 1;
			break;
		}
	}

	mutex_exit(&eventq->lock);

	return (found);

} /* emlxs_flush_ct_event() */


extern uint32_t
emlxs_log_ct_event(emlxs_port_t *port, uint8_t *payload, uint32_t size,
    uint32_t rxid)
{
	uint8_t *bp;
	uint32_t *ptr;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_ct_event) == 0) {
		return (1);
	}

	if (size > MAX_CT_PAYLOAD) {
		size = MAX_CT_PAYLOAD;
	}

	size += sizeof (uint32_t);

	/* Save a copy of the payload for the event log */
	if (!(bp = (uint8_t *)kmem_alloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s: Unable to allocate buffer.", emlxs_ct_event.label);

		return (1);
	}

	/*
	 * Buffer Format:
	 *	word[0] = RXID tag for outgoing reply to this CT request
	 *	word[1] = CT Payload
	 */
	ptr = (uint32_t *)bp;
	*ptr++ = rxid;
	bcopy(payload, (char *)ptr, (size - sizeof (uint32_t)));

	emlxs_event(port, &emlxs_ct_event, bp, size);

	return (0);

} /* emlxs_log_ct_event() */


extern void
emlxs_ct_event_destroy(emlxs_event_entry_t *entry)
{
	emlxs_port_t *port = (emlxs_port_t *)entry->port;
	emlxs_hba_t *hba = HBA;
	uint32_t rxid;

	if (!(entry->flag & EMLXS_DFC_EVENT_DONE)) {

		rxid = *(uint32_t *)entry->bp;

		/* Abort exchange */
		emlxs_thread_spawn(hba, emlxs_abort_ct_exchange,
		    entry->port, (void *)(unsigned long)rxid);
	}

	return;

} /* emlxs_ct_event_destroy() */


extern void
emlxs_log_link_event(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	uint8_t *bp;
	dfc_linkinfo_t *linkinfo;
	uint8_t *byte;
	uint8_t *linkspeed;
	uint8_t *liptype;
	uint8_t *resv1;
	uint8_t *resv2;
	uint32_t size;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_link_event) == 0) {
		return;
	}

	size = sizeof (dfc_linkinfo_t) + sizeof (uint32_t);

	/* Save a copy of the buffer for the event log */
	if (!(bp = (uint8_t *)kmem_alloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s: Unable to allocate buffer.", emlxs_link_event.label);

		return;
	}

	/*
	 * Buffer Format:
	 *	word[0] = Linkspeed:8
	 *	word[0] = LIP_type:8
	 *	word[0] = resv1:8
	 *	word[0] = resv2:8
	 *	word[1] = dfc_linkinfo_t data
	 */
	byte = (uint8_t *)bp;
	linkspeed = &byte[0];
	liptype = &byte[1];
	resv1 = &byte[2];
	resv2 = &byte[3];
	linkinfo = (dfc_linkinfo_t *)&byte[4];

	*resv1 = 0;
	*resv2 = 0;

	if (hba->state <= FC_LINK_DOWN) {
		*linkspeed = 0;
		*liptype = 0;
	} else {
		/* Set linkspeed */
		if (hba->linkspeed == LA_2GHZ_LINK) {
			*linkspeed = HBA_PORTSPEED_2GBIT;
		} else if (hba->linkspeed == LA_4GHZ_LINK) {
			*linkspeed = HBA_PORTSPEED_4GBIT;
		} else if (hba->linkspeed == LA_8GHZ_LINK) {
			*linkspeed = HBA_PORTSPEED_8GBIT;
		} else if (hba->linkspeed == LA_10GHZ_LINK) {
			*linkspeed = HBA_PORTSPEED_10GBIT;
		} else if (hba->linkspeed == LA_16GHZ_LINK) {
			*linkspeed = HBA_PORTSPEED_16GBIT;
		} else {
			*linkspeed = HBA_PORTSPEED_1GBIT;
		}

		/* Set LIP type */
		*liptype = port->lip_type;
	}

	bzero(linkinfo, sizeof (dfc_linkinfo_t));

	linkinfo->a_linkEventTag = hba->link_event_tag;
	linkinfo->a_linkUp = HBASTATS.LinkUp;
	linkinfo->a_linkDown = HBASTATS.LinkDown;
	linkinfo->a_linkMulti = HBASTATS.LinkMultiEvent;

	if (hba->state <= FC_LINK_DOWN) {
		linkinfo->a_linkState = LNK_DOWN;
		linkinfo->a_DID = port->prev_did;
	} else if (hba->state < FC_READY) {
		linkinfo->a_linkState = LNK_DISCOVERY;
	} else {
		linkinfo->a_linkState = LNK_READY;
	}

	if (linkinfo->a_linkState != LNK_DOWN) {
		if (hba->topology == TOPOLOGY_LOOP) {
			if (hba->flag & FC_FABRIC_ATTACHED) {
				linkinfo->a_topology = LNK_PUBLIC_LOOP;
			} else {
				linkinfo->a_topology = LNK_LOOP;
			}

			linkinfo->a_alpa = port->did & 0xff;
			linkinfo->a_DID = linkinfo->a_alpa;
			linkinfo->a_alpaCnt = port->alpa_map[0];

			if (linkinfo->a_alpaCnt > 127) {
				linkinfo->a_alpaCnt = 127;
			}

			bcopy((void *)&port->alpa_map[1], linkinfo->a_alpaMap,
			    linkinfo->a_alpaCnt);
		} else {
			if (port->node_count == 1) {
				linkinfo->a_topology = LNK_PT2PT;
			} else {
				linkinfo->a_topology = LNK_FABRIC;
			}

			linkinfo->a_DID = port->did;
		}
	}

	bcopy(&hba->wwpn, linkinfo->a_wwpName, 8);
	bcopy(&hba->wwnn, linkinfo->a_wwnName, 8);

	emlxs_event(port, &emlxs_link_event, bp, size);

	return;

} /* emlxs_log_link_event() */


extern void
emlxs_log_dump_event(emlxs_port_t *port, uint8_t *buffer, uint32_t size)
{
	emlxs_hba_t *hba = HBA;
	uint8_t *bp;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_dump_event) == 0) {
#ifdef DUMP_SUPPORT
		/* Schedule a dump thread */
		emlxs_dump(hba, EMLXS_DRV_DUMP, 0, 0);
#endif /* DUMP_SUPPORT */
		return;
	}

	if (buffer && size) {
		/* Save a copy of the buffer for the event log */
		if (!(bp = (uint8_t *)kmem_alloc(size, KM_NOSLEEP))) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
			    "%s: Unable to allocate buffer.",
			    emlxs_dump_event.label);

			return;
		}

		bcopy(buffer, bp, size);
	} else {
		bp = NULL;
		size = 0;
	}

	emlxs_event(port, &emlxs_dump_event, bp, size);

	return;

} /* emlxs_log_dump_event() */


extern void
emlxs_log_temp_event(emlxs_port_t *port, uint32_t type, uint32_t temp)
{
	emlxs_hba_t *hba = HBA;
	uint32_t *bp;
	uint32_t size;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_temp_event) == 0) {
#ifdef DUMP_SUPPORT
		/* Schedule a dump thread */
		emlxs_dump(hba, EMLXS_TEMP_DUMP, type, temp);
#endif /* DUMP_SUPPORT */
		return;
	}

	size = 2 * sizeof (uint32_t);

	if (!(bp = (uint32_t *)kmem_alloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s: Unable to allocate buffer.", emlxs_temp_event.label);

		return;
	}

	bp[0] = type;
	bp[1] = temp;

	emlxs_event(port, &emlxs_temp_event, bp, size);

	return;

} /* emlxs_log_temp_event() */



extern void
emlxs_log_fcoe_event(emlxs_port_t *port, menlo_init_rsp_t *init_rsp)
{
	emlxs_hba_t *hba = HBA;
	uint8_t *bp;
	uint32_t size;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_fcoe_event) == 0) {
		return;
	}

	/* Check if this is a FCOE adapter */
	if (hba->model_info.device_id != PCI_DEVICE_ID_HORNET) {
		return;
	}

	size = sizeof (menlo_init_rsp_t);

	if (!(bp = (uint8_t *)kmem_alloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s: Unable to allocate buffer.", emlxs_fcoe_event.label);

		return;
	}

	bcopy((uint8_t *)init_rsp, bp, size);

	emlxs_event(port, &emlxs_fcoe_event, bp, size);

	return;

} /* emlxs_log_fcoe_event() */


extern void
emlxs_log_async_event(emlxs_port_t *port, IOCB *iocb)
{
	uint8_t *bp;
	uint32_t size;

	if (emlxs_event_check(port, &emlxs_async_event) == 0) {
		return;
	}

	/* ASYNC_STATUS_CN response size */
	size = 64;

	if (!(bp = (uint8_t *)kmem_alloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s: Unable to allocate buffer.", emlxs_async_event.label);

		return;
	}

	bcopy((uint8_t *)iocb, bp, size);

	emlxs_event(port, &emlxs_async_event, bp, size);

	return;

} /* emlxs_log_async_event() */


extern uint32_t
emlxs_get_dfc_eventinfo(emlxs_port_t *port, HBA_EVENTINFO *eventinfo,
    uint32_t *eventcount, uint32_t *missed)
{
	emlxs_hba_t *hba = HBA;
	emlxs_event_queue_t *eventq = &EVENTQ;
	emlxs_event_entry_t *entry;
	uint32_t max_events;
	dfc_linkinfo_t *linkinfo;
	uint32_t *word;
	uint8_t *byte;
	uint8_t linkspeed;
	uint8_t liptype;
	fc_affected_id_t *aid;
	uint32_t events;
	uint8_t format;

	if (!eventinfo || !eventcount || !missed) {
		return (DFC_ARG_NULL);
	}

	max_events = *eventcount;
	*eventcount = 0;
	*missed = 0;

	mutex_enter(&eventq->lock);

	/* Account for missed events */
	if (hba->hba_event.new > hba->hba_event.missed) {
		hba->hba_event.new -= hba->hba_event.missed;
	} else {
		hba->hba_event.new = 0;
	}

	*missed = hba->hba_event.missed;
	hba->hba_event.missed = 0;

	if (!hba->hba_event.new) {
		hba->hba_event.last_id = eventq->next_id - 1;
		mutex_exit(&eventq->lock);
		return (0);
	}

	/* A new event has occurred since last acquisition */

	events = 0;
	entry = eventq->first;
	while (entry && (events < max_events)) {

		/* Skip old events */
		if (entry->id <= hba->hba_event.last_id) {
			entry = entry->next;
			continue;
		}

		/* Process this entry */
		switch (entry->evt->mask) {
		case EVT_LINK:
			byte = (uint8_t *)entry->bp;
			linkspeed = byte[0];
			liptype = byte[1];
			linkinfo = (dfc_linkinfo_t *)&byte[4];

			if (linkinfo->a_linkState == LNK_DOWN) {
				eventinfo->EventCode =
				    HBA_EVENT_LINK_DOWN;
				eventinfo->Event.Link_EventInfo.
				    PortFcId = linkinfo->a_DID;
				eventinfo->Event.Link_EventInfo.
				    Reserved[0] = 0;
				eventinfo->Event.Link_EventInfo.
				    Reserved[1] = 0;
				eventinfo->Event.Link_EventInfo.
				    Reserved[2] = 0;
			} else {
				eventinfo->EventCode =
				    HBA_EVENT_LINK_UP;
				eventinfo->Event.Link_EventInfo.
				    PortFcId = linkinfo->a_DID;

				if ((linkinfo->a_topology ==
				    LNK_PUBLIC_LOOP) ||
				    (linkinfo->a_topology ==
				    LNK_LOOP)) {
					eventinfo->Event.
					    Link_EventInfo.
					    Reserved[0] = 2;
				} else {
					eventinfo->Event.
					    Link_EventInfo.
					    Reserved[0] = 1;
				}

				eventinfo->Event.Link_EventInfo.
				    Reserved[1] = liptype;
				eventinfo->Event.Link_EventInfo.
				    Reserved[2] = linkspeed;
			}

			eventinfo++;
			events++;
			hba->hba_event.new--;
			break;

		case EVT_RSCN:
			word = (uint32_t *)entry->bp;
			eventinfo->EventCode = HBA_EVENT_RSCN;
			eventinfo->Event.RSCN_EventInfo.PortFcId =
			    word[0] & 0xFFFFFF;
			/* word[1] is the RSCN payload command */

			aid = (fc_affected_id_t *)&word[2];
			format = aid->aff_format;

			switch (format) {
			case 0:	/* Port */
				eventinfo->Event.RSCN_EventInfo.
				    NPortPage =
				    aid->aff_d_id & 0x00ffffff;
				break;

			case 1:	/* Area */
				eventinfo->Event.RSCN_EventInfo.
				    NPortPage =
				    aid->aff_d_id & 0x00ffff00;
				break;

			case 2:	/* Domain */
				eventinfo->Event.RSCN_EventInfo.
				    NPortPage =
				    aid->aff_d_id & 0x00ff0000;
				break;

			case 3:	/* Network */
				eventinfo->Event.RSCN_EventInfo.
				    NPortPage = 0;
				break;
			}

			eventinfo->Event.RSCN_EventInfo.Reserved[0] =
			    0;
			eventinfo->Event.RSCN_EventInfo.Reserved[1] =
			    0;

			eventinfo++;
			events++;
			hba->hba_event.new--;
			break;
		}

		hba->hba_event.last_id = entry->id;
		entry = entry->next;
	}

	/* Return number of events acquired */
	*eventcount = events;

	mutex_exit(&eventq->lock);

	return (0);

} /* emlxs_get_dfc_eventinfo() */


void
emlxs_get_dfc_event(emlxs_port_t *port, emlxs_dfc_event_t *dfc_event,
    uint32_t sleep)
{
	emlxs_hba_t *hba = HBA;
	emlxs_event_queue_t *eventq = &EVENTQ;
	emlxs_event_entry_t *entry;
	uint32_t found;
	uint32_t mask;
	uint32_t i;
	uint32_t size = 0;
	uint32_t rc;

	if (dfc_event->dataout && dfc_event->size) {
		size = dfc_event->size;
	}
	dfc_event->size = 0;

	/* Calculate the event index */
	mask = dfc_event->event;
	for (i = 0; i < 32; i++) {
		if (mask & 0x01) {
			break;
		}

		mask >>= 1;
	}

	if (i == 32) {
		return;
	}

	mutex_enter(&eventq->lock);

wait_for_event:

	/* Check if no new event has occurred */
	if (dfc_event->last_id == eventq->last_id[i]) {
		if (!sleep) {
			mutex_exit(&eventq->lock);
			return;
		}

		/* While event is still active and */
		/* no new event has been logged */
		while ((dfc_event->event & hba->event_mask) &&
		    (dfc_event->last_id == eventq->last_id[i])) {

			rc = cv_wait_sig(&eventq->lock_cv, &eventq->lock);

			/* Check if thread was killed by kernel */
			if (rc == 0) {
				dfc_event->pid = 0;
				dfc_event->event = 0;
				mutex_exit(&eventq->lock);
				return;
			}
		}

		/* If the event is no longer registered then */
		/* return immediately */
		if (!(dfc_event->event & hba->event_mask)) {
			mutex_exit(&eventq->lock);
			return;
		}
	}

	/* !!! An event has occurred since last_id !!! */

	/* Check if event data is not being requested */
	if (!size) {
		/* If so, then just return the last event id */
		dfc_event->last_id = eventq->last_id[i];

		mutex_exit(&eventq->lock);
		return;
	}

	/* !!! The requester wants the next event buffer !!! */

	found = 0;
	entry = eventq->first;
	while (entry) {
		if ((entry->id > dfc_event->last_id) &&
		    (entry->evt->mask == dfc_event->event)) {
			found = 1;
			break;
		}

		entry = entry->next;
	}

	if (!found) {
		/* Update last_id to the last known event */
		dfc_event->last_id = eventq->last_id[i];

		/* Try waiting again if we can */
		goto wait_for_event;
	}

	/* !!! Next event found !!! */

	/* Copy the context buffer to the buffer provided */
	if (entry->bp && entry->size) {
		if (entry->size < size) {
			size = entry->size;
		}

		bcopy((void *)entry->bp, dfc_event->dataout, size);

		/* Event has been retrieved by DFCLIB */
		entry->flag |= EMLXS_DFC_EVENT_DONE;

		dfc_event->size = size;
	}

	dfc_event->last_id = entry->id;

	mutex_exit(&eventq->lock);

	return;

} /* emlxs_get_dfc_event() */


uint32_t
emlxs_kill_dfc_event(emlxs_port_t *port, emlxs_dfc_event_t *dfc_event)
{
	emlxs_hba_t *hba = HBA;
	emlxs_event_queue_t *eventq = &EVENTQ;

	mutex_enter(&eventq->lock);
	dfc_event->pid = 0;
	dfc_event->event = 0;
	cv_broadcast(&eventq->lock_cv);
	mutex_exit(&eventq->lock);

	return (0);

} /* emlxs_kill_dfc_event() */


#ifdef SAN_DIAG_SUPPORT
extern void
emlxs_log_sd_basic_els_event(emlxs_port_t *port, uint32_t subcat,
    HBA_WWN *portname, HBA_WWN *nodename)
{
	struct sd_plogi_rcv_v0	*bp;
	uint32_t		size;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_sd_els_event) == 0) {
		return;
	}

	size = sizeof (struct sd_plogi_rcv_v0);

	if (!(bp = (struct sd_plogi_rcv_v0 *)kmem_alloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s: Unable to allocate buffer.", emlxs_sd_els_event.label);

		return;
	}

	/*
	 * we are using version field to store subtype, libdfc
	 * will fix this up before returning data to app.
	 */
	bp->sd_plogir_version = subcat;
	bcopy((uint8_t *)portname, (uint8_t *)&bp->sd_plogir_portname,
	    sizeof (HBA_WWN));
	bcopy((uint8_t *)nodename, (uint8_t *)&bp->sd_plogir_nodename,
	    sizeof (HBA_WWN));

	emlxs_event(port, &emlxs_sd_els_event, bp, size);

	return;

} /* emlxs_log_sd_basic_els_event() */


extern void
emlxs_log_sd_prlo_event(emlxs_port_t *port, HBA_WWN *remoteport)
{
	struct sd_prlo_rcv_v0	*bp;
	uint32_t		size;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_sd_els_event) == 0) {
		return;
	}

	size = sizeof (struct sd_prlo_rcv_v0);

	if (!(bp = (struct sd_prlo_rcv_v0 *)kmem_alloc(size,
	    KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s PRLO: Unable to allocate buffer.",
		    emlxs_sd_els_event.label);

		return;
	}

	/*
	 * we are using version field to store subtype, libdfc
	 * will fix this up before returning data to app.
	 */
	bp->sd_prlor_version = SD_ELS_SUBCATEGORY_PRLO_RCV;
	bcopy((uint8_t *)remoteport, (uint8_t *)&bp->sd_prlor_remoteport,
	    sizeof (HBA_WWN));

	emlxs_event(port, &emlxs_sd_els_event, bp, size);

	return;

} /* emlxs_log_sd_prlo_event() */


extern void
emlxs_log_sd_lsrjt_event(emlxs_port_t *port, HBA_WWN *remoteport,
    uint32_t orig_cmd, uint32_t reason, uint32_t reason_expl)
{
	struct sd_lsrjt_rcv_v0	*bp;
	uint32_t		size;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_sd_els_event) == 0) {
		return;
	}

	size = sizeof (struct sd_lsrjt_rcv_v0);

	if (!(bp = (struct sd_lsrjt_rcv_v0 *)kmem_alloc(size,
	    KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s LSRJT: Unable to allocate buffer.",
		    emlxs_sd_els_event.label);

		return;
	}

	/*
	 * we are using version field to store subtype, libdfc
	 * will fix this up before returning data to app.
	 */
	bp->sd_lsrjtr_version = SD_ELS_SUBCATEGORY_LSRJT_RCV;
	bcopy((uint8_t *)remoteport, (uint8_t *)&bp->sd_lsrjtr_remoteport,
	    sizeof (HBA_WWN));
	bp->sd_lsrjtr_original_cmd = orig_cmd;
	bp->sd_lsrjtr_reasoncode = reason;
	bp->sd_lsrjtr_reasoncodeexpl = reason_expl;

	emlxs_event(port, &emlxs_sd_els_event, bp, size);

	return;

} /* emlxs_log_sd_lsrjt_event() */


extern void
emlxs_log_sd_fc_bsy_event(emlxs_port_t *port, HBA_WWN *remoteport)
{
	struct sd_pbsy_rcv_v0	*bp;
	uint32_t		size;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_sd_fabric_event) == 0) {
		return;
	}

	size = sizeof (struct sd_pbsy_rcv_v0);

	if (!(bp = (struct sd_pbsy_rcv_v0 *)kmem_alloc(size,
	    KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s BSY: Unable to allocate buffer.",
		    emlxs_sd_fabric_event.label);

		return;
	}

	/*
	 * we are using version field to store subtype, libdfc
	 * will fix this up before returning data to app.
	 */
	if (remoteport == NULL)
		bp->sd_pbsyr_evt_version = SD_FABRIC_SUBCATEGORY_FABRIC_BUSY;
	else
	{
		bp->sd_pbsyr_evt_version = SD_FABRIC_SUBCATEGORY_PORT_BUSY;
		bcopy((uint8_t *)remoteport, (uint8_t *)&bp->sd_pbsyr_rport,
		    sizeof (HBA_WWN));
	}

	emlxs_event(port, &emlxs_sd_fabric_event, bp, size);

	return;

} /* emlxs_log_sd_fc_bsy_event() */


extern void
emlxs_log_sd_fc_rdchk_event(emlxs_port_t *port, HBA_WWN *remoteport,
    uint32_t lun, uint32_t opcode, uint32_t fcp_param)
{
	struct sd_fcprdchkerr_v0	*bp;
	uint32_t			size;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_sd_fabric_event) == 0) {
		return;
	}

	size = sizeof (struct sd_fcprdchkerr_v0);

	if (!(bp = (struct sd_fcprdchkerr_v0 *)kmem_alloc(size,
	    KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s RDCHK: Unable to allocate buffer.",
		    emlxs_sd_fabric_event.label);

		return;
	}

	/*
	 * we are using version field to store subtype, libdfc
	 * will fix this up before returning data to app.
	 */
	bp->sd_fcprdchkerr_version = SD_FABRIC_SUBCATEGORY_FCPRDCHKERR;
	bcopy((uint8_t *)remoteport, (uint8_t *)&bp->sd_fcprdchkerr_rport,
	    sizeof (HBA_WWN));
	bp->sd_fcprdchkerr_lun = lun;
	bp->sd_fcprdchkerr_opcode = opcode;
	bp->sd_fcprdchkerr_fcpiparam = fcp_param;

	emlxs_event(port, &emlxs_sd_fabric_event, bp, size);

	return;

} /* emlxs_log_sd_rdchk_event() */


extern void
emlxs_log_sd_scsi_event(emlxs_port_t *port, uint32_t type,
    HBA_WWN *remoteport, int32_t lun)
{
	struct sd_scsi_generic_v0	*bp;
	uint32_t			size;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_sd_scsi_event) == 0) {
		return;
	}

	size = sizeof (struct sd_scsi_generic_v0);

	if (!(bp = (struct sd_scsi_generic_v0 *)kmem_alloc(size,
	    KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s: Unable to allocate buffer.",
		    emlxs_sd_scsi_event.label);

		return;
	}

	/*
	 * we are using version field to store subtype, libdfc
	 * will fix this up before returning data to app.
	 */
	bp->sd_scsi_generic_version = type;
	bcopy((uint8_t *)remoteport, (uint8_t *)&bp->sd_scsi_generic_rport,
	    sizeof (HBA_WWN));
	bp->sd_scsi_generic_lun = lun;

	emlxs_event(port, &emlxs_sd_scsi_event, bp, size);

	return;

} /* emlxs_log_sd_scsi_event() */


extern void
emlxs_log_sd_scsi_check_event(emlxs_port_t *port, HBA_WWN *remoteport,
    uint32_t lun, uint32_t cmdcode, uint32_t sensekey,
    uint32_t asc, uint32_t ascq)
{
	struct sd_scsi_checkcond_v0	*bp;
	uint32_t			size;

	/* Check if the event is being requested */
	if (emlxs_event_check(port, &emlxs_sd_scsi_event) == 0) {
		return;
	}

	size = sizeof (struct sd_scsi_checkcond_v0);

	if (!(bp = (struct sd_scsi_checkcond_v0 *)kmem_alloc(size,
	    KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_event_debug_msg,
		    "%s CHECK: Unable to allocate buffer.",
		    emlxs_sd_scsi_event.label);

		return;
	}

	/*
	 * we are using version field to store subtype, libdfc
	 * will fix this up before returning data to app.
	 */
	bp->sd_scsi_checkcond_version = SD_SCSI_SUBCATEGORY_CHECKCONDITION;
	bcopy((uint8_t *)remoteport, (uint8_t *)&bp->sd_scsi_checkcond_rport,
	    sizeof (HBA_WWN));
	bp->sd_scsi_checkcond_lun = lun;
	bp->sd_scsi_checkcond_cmdcode = cmdcode;
	bp->sd_scsi_checkcond_sensekey = sensekey;
	bp->sd_scsi_checkcond_asc = asc;
	bp->sd_scsi_checkcond_ascq = ascq;

	emlxs_event(port, &emlxs_sd_scsi_event, bp, size);

	return;

} /* emlxs_log_sd_scsi_check_event() */


void
emlxs_get_sd_event(emlxs_port_t *port, emlxs_dfc_event_t *dfc_event,
    uint32_t sleep)
{
	emlxs_hba_t *hba = HBA;
	emlxs_event_queue_t *eventq = &EVENTQ;
	emlxs_event_entry_t *entry;
	uint32_t found;
	uint32_t mask;
	uint32_t i;
	uint32_t size = 0;
	uint32_t rc;

	if (dfc_event->dataout && dfc_event->size) {
		size = dfc_event->size;
	}
	dfc_event->size = 0;

	/* Calculate the event index */
	mask = dfc_event->event;
	for (i = 0; i < 32; i++) {
		if (mask & 0x01) {
			break;
		}

		mask >>= 1;
	}

	if (i == 32) {
		return;
	}

	mutex_enter(&eventq->lock);

wait_for_event:

	/* Check if no new event has ocurred */
	if (dfc_event->last_id == eventq->last_id[i]) {
		if (!sleep) {
			mutex_exit(&eventq->lock);
			return;
		}

		/* While event is active and no new event has been logged */
		while ((dfc_event->event & port->sd_event_mask) &&
		    (dfc_event->last_id == eventq->last_id[i])) {
			rc = cv_wait_sig(&eventq->lock_cv, &eventq->lock);

			/* Check if thread was killed by kernel */
			if (rc == 0) {
				dfc_event->pid = 0;
				dfc_event->event = 0;
				mutex_exit(&eventq->lock);
				return;
			}
		}

		/* If the event is no longer registered then return */
		if (!(dfc_event->event & port->sd_event_mask)) {
			mutex_exit(&eventq->lock);
			return;
		}
	}

	/* !!! An event has occurred since last_id !!! */

	/* Check if event data is not being requested */
	if (!size) {
		/* If so, then just return the last event id */
		dfc_event->last_id = eventq->last_id[i];

		mutex_exit(&eventq->lock);
		return;
	}

	/* !!! The requester wants the next event buffer !!! */

	found = 0;
	entry = eventq->first;
	while (entry) {
		if ((entry->id > dfc_event->last_id) &&
		    (entry->port == (void *)port) &&
		    (entry->evt->mask == dfc_event->event)) {
			found = 1;
			break;
		}

		entry = entry->next;
	}

	if (!found) {
		/* Update last_id to the last known event */
		dfc_event->last_id = eventq->last_id[i];

		/* Try waiting again if we can */
		goto wait_for_event;
	}

	/* !!! Next event found !!! */

	/* Copy the context buffer to the buffer provided */
	if (entry->bp && entry->size) {
		if (entry->size < size) {
			size = entry->size;
		}

		bcopy((void *)entry->bp, dfc_event->dataout, size);

		/* Event has been retrieved by SANDIAG */
		entry->flag |= EMLXS_SD_EVENT_DONE;

		dfc_event->size = size;
	}

	dfc_event->last_id = entry->id;

	mutex_exit(&eventq->lock);

	return;

} /* emlxs_get_sd_event */
#endif /* SAN_DIAG_SUPPORT */
