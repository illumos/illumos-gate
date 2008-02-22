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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IPMI entities are a strange beast.  A reasonable assumption for those
 * unfamiliar with the spec would be that there was a command to iterate over
 * all entities, and a command to iterate over sensors associated with each
 * entity.  Instead, the entire IPMI world is derived from the SDR repository.
 * Entities only exist in the sense that they are referenced by a SDR record.
 *
 * In addition, entities can be associated into groups, and determining entity
 * presence is quite complicated.  The IPMI spec dedicates an entire chapter
 * (40) to the process of handling sensor associations.
 *
 * The above logic is implemented via the ipmi_entity_present() function.  We
 * make a first pass over the SDR repository to discover entities, creating
 * entity groups and associating SDR records with the each.
 *
 * We don't currently support device-relative entities.
 */

#include <libipmi.h>
#include <ipmi_impl.h>
#include <stddef.h>

typedef struct ipmi_entity_sdr {
	ipmi_list_t			ies_list;
	const char			*ies_name;
	ipmi_sdr_t			*ies_sdr;
} ipmi_entity_sdr_t;

typedef struct ipmi_entity_impl {
	ipmi_list_t			ie_list;
	ipmi_entity_t			ie_entity;
	struct ipmi_entity_impl		*ie_parent;
	ipmi_hash_link_t		ie_link;
	ipmi_list_t			ie_child_list;
	ipmi_list_t			ie_sdr_list;
} ipmi_entity_impl_t;

#define	ENTITY_TO_IMPL(ep)	\
	((ipmi_entity_impl_t *)((char *)(ep) - \
	offsetof(ipmi_entity_impl_t, ie_entity)))

static int
ipmi_entity_add_assoc(ipmi_handle_t *ihp, ipmi_entity_impl_t *eip,
    uint8_t id, uint8_t instance)
{
	ipmi_entity_impl_t *cp;
	ipmi_entity_t search;

	search.ie_type = id;
	search.ie_instance = instance;

	if ((cp = ipmi_hash_lookup(ihp->ih_entities, &search)) == NULL) {
		if ((cp = ipmi_zalloc(ihp,
		    sizeof (ipmi_entity_impl_t))) == NULL)
			return (-1);

		cp->ie_entity.ie_type = id;
		cp->ie_entity.ie_instance = instance;

		ipmi_hash_insert(ihp->ih_entities, cp);
	}

	if (cp->ie_parent != NULL) {
		/*
		 * This should never happen.  However, we want to be tolerant of
		 * pathologically broken IPMI implementations, so we ignore this
		 * error, and the first parent wins.
		 */
		return (0);
	}

	cp->ie_parent = eip;
	ipmi_list_append(&eip->ie_child_list, cp);
	eip->ie_entity.ie_children++;

	return (0);
}

static int
ipmi_entity_sdr_parse(ipmi_sdr_t *sdrp, uint8_t *id, uint8_t *instance,
    boolean_t *logical)
{
	switch (sdrp->is_type) {
	case IPMI_SDR_TYPE_FULL_SENSOR:
		{
			ipmi_sdr_full_sensor_t *fsp =
			    (ipmi_sdr_full_sensor_t *)sdrp->is_record;
			*id = fsp->is_fs_entity_id;
			*instance = fsp->is_fs_entity_instance;
			*logical = fsp->is_fs_entity_logical;
			break;
		}

	case IPMI_SDR_TYPE_COMPACT_SENSOR:
		{
			ipmi_sdr_compact_sensor_t *csp =
			    (ipmi_sdr_compact_sensor_t *)sdrp->is_record;
			*id = csp->is_cs_entity_id;
			*instance = csp->is_cs_entity_instance;
			*logical = csp->is_cs_entity_logical;
			break;
		}

	case IPMI_SDR_TYPE_EVENT_ONLY:
		{
			ipmi_sdr_event_only_t *eop =
			    (ipmi_sdr_event_only_t *)sdrp->is_record;
			*id = eop->is_eo_entity_id;
			*instance = eop->is_eo_entity_instance;
			*logical = eop->is_eo_entity_logical;
			break;
		}

	case IPMI_SDR_TYPE_ENTITY_ASSOCIATION:
		{
			ipmi_sdr_entity_association_t *eap =
			    (ipmi_sdr_entity_association_t *)sdrp->is_record;
			*id = eap->is_ea_entity_id;
			*instance = eap->is_ea_entity_instance;
			*logical = B_TRUE;
			break;
		}

	case IPMI_SDR_TYPE_GENERIC_LOCATOR:
		{
			ipmi_sdr_generic_locator_t *glp =
			    (ipmi_sdr_generic_locator_t *)sdrp->is_record;
			*id = glp->is_gl_entity;
			*instance = glp->is_gl_instance;
			*logical = B_FALSE;
			break;
		}

	case IPMI_SDR_TYPE_FRU_LOCATOR:
		{
			ipmi_sdr_fru_locator_t *flp =
			    (ipmi_sdr_fru_locator_t *)sdrp->is_record;
			*id = flp->is_fl_entity;
			*instance = flp->is_fl_instance;
			*logical = B_FALSE;
			break;
		}

	case IPMI_SDR_TYPE_MANAGEMENT_LOCATOR:
		{
			ipmi_sdr_management_locator_t *mlp =
			    (ipmi_sdr_management_locator_t *)sdrp->is_record;
			*id = mlp->is_ml_entity_id;
			*instance = mlp->is_ml_entity_instance;
			*logical = B_FALSE;
			break;
		}

	default:
		return (-1);
	}

	return (0);
}

/*
 * This function is responsible for gathering all entities, inserting them into
 * the global hash, and establishing any associations.
 */
/*ARGSUSED*/
static int
ipmi_entity_visit(ipmi_handle_t *ihp, const char *name, ipmi_sdr_t *sdrp,
    void *unused)
{
	uint8_t id, instance;
	boolean_t logical;
	ipmi_entity_t search;
	ipmi_entity_impl_t *eip;
	ipmi_entity_sdr_t *esp;

	if (ipmi_entity_sdr_parse(sdrp, &id, &instance, &logical) != 0)
		return (0);

	search.ie_type = id;
	search.ie_instance = instance;

	if ((eip = ipmi_hash_lookup(ihp->ih_entities, &search)) == NULL) {
		if ((eip = ipmi_zalloc(ihp,
		    sizeof (ipmi_entity_impl_t))) == NULL)
			return (-1);

		eip->ie_entity.ie_type = id;
		eip->ie_entity.ie_instance = instance;

		ipmi_hash_insert(ihp->ih_entities, eip);
	}

	eip->ie_entity.ie_logical |= logical;

	if (sdrp->is_type == IPMI_SDR_TYPE_ENTITY_ASSOCIATION) {
		uint8_t start, end;
		uint8_t i, type;

		ipmi_sdr_entity_association_t *eap =
		    (ipmi_sdr_entity_association_t *)sdrp->is_record;

		if (eap->is_ea_range) {

			type = eap->is_ea_sub[0].is_ea_sub_id;
			start = eap->is_ea_sub[0].is_ea_sub_instance;
			end = eap->is_ea_sub[1].is_ea_sub_instance;

			if (type != 0) {
				for (i = start; i <= end; i++) {
					if (ipmi_entity_add_assoc(ihp, eip,
					    type, i) != 0)
						return (-1);
				}
			}

			type = eap->is_ea_sub[2].is_ea_sub_id;
			start = eap->is_ea_sub[2].is_ea_sub_instance;
			end = eap->is_ea_sub[3].is_ea_sub_instance;

			if (type != 0) {
				for (i = start; i <= end; i++) {
					if (ipmi_entity_add_assoc(ihp, eip,
					    type, i) != 0)
						return (-1);
				}
			}
		} else {
			for (i = 0; i < 4; i++) {
				type = eap->is_ea_sub[i].is_ea_sub_id;
				instance = eap->is_ea_sub[i].is_ea_sub_instance;

				if (type == 0)
					continue;

				if (ipmi_entity_add_assoc(ihp, eip, type,
				    instance) != 0)
					return (-1);
			}
		}
	} else {
		if ((esp = ipmi_zalloc(ihp,
		    sizeof (ipmi_entity_sdr_t))) == NULL)
			return (-1);

		esp->ies_sdr = sdrp;
		esp->ies_name = name;
		ipmi_list_append(&eip->ie_sdr_list, esp);
	}

	return (0);
}

/*
 * Given a SDR record, return boolean values indicating whether the sensor
 * indicates explicit presence.
 *
 * XXX this should really share code with entity_present()
 */
int
ipmi_entity_present_sdr(ipmi_handle_t *ihp, ipmi_sdr_t *sdrp,
    boolean_t *valp)
{
	uint16_t mask;
	uint8_t number, sensor_type, reading_type;
	ipmi_sdr_compact_sensor_t *csp;
	ipmi_sdr_full_sensor_t *fsp;
	ipmi_sensor_reading_t *srp;

	switch (sdrp->is_type) {
	case IPMI_SDR_TYPE_COMPACT_SENSOR:
		csp = (ipmi_sdr_compact_sensor_t *)sdrp->is_record;
		number = csp->is_cs_number;
		sensor_type = csp->is_cs_type;
		reading_type = csp->is_cs_reading_type;
		break;

	case IPMI_SDR_TYPE_FULL_SENSOR:
		fsp = (ipmi_sdr_full_sensor_t *)sdrp->is_record;
		number = fsp->is_fs_number;
		sensor_type = fsp->is_fs_type;
		reading_type = fsp->is_fs_reading_type;
		break;

	default:
		*valp = B_FALSE;
		return (0);
	}

	switch (reading_type) {
	case IPMI_RT_PRESENT:
		mask = IPMI_SR_PRESENT_ASSERT;
		break;

	case IPMI_RT_SPECIFIC:
		switch (sensor_type) {
		case IPMI_ST_PROCESSOR:
			mask = IPMI_EV_PROCESSOR_PRESENT;
			break;

		case IPMI_ST_POWER_SUPPLY:
			mask = IPMI_EV_POWER_SUPPLY_PRESENT;
			break;

		case IPMI_ST_MEMORY:
			mask = IPMI_EV_MEMORY_PRESENT;
			break;

		case IPMI_ST_BAY:
			mask = IPMI_EV_BAY_PRESENT;
			break;

		default:
			*valp = B_FALSE;
			return (0);
		}
		break;

	default:
		*valp = B_FALSE;
		return (0);
	}

	/*
	 * If we've reached here, then we have a dedicated sensor that
	 * indicates presence.
	 */
	if ((srp = ipmi_get_sensor_reading(ihp, number)) == NULL) {
		if (ipmi_errno(ihp) == EIPMI_NOT_PRESENT) {
			*valp = B_FALSE;
			return (0);
		}

		return (-1);
	}

	*valp = (srp->isr_state & mask) != 0;
	return (0);
}

/*
 * This function follows the procedure documented in section 40 of the spec.
 * To quote the conclusion from section 40.2:
 *
 * 	Thus, the steps to detecting an Entity are:
 *
 * 	a) Scan the SDRs for sensors associated with the entity.
 *
 * 	b) If there is an active sensor that includes a presence bit, or the
 *	   entity has an active Entity Presence sensor, use the sensor to
 *	   determine the presence of the entity.
 *
 * 	c) Otherwise, check to see that there is at least one active sensor
 *	   associated with the entity.  Do this by doing 'Get Sensor Readings'
 *	   to the sensors associated with the entity until a scanning sensor is
 *	   found.
 *
 * 	d) If there are no active sensors directly associated with the entity,
 *	   check the SDRs to see if the entity is a container entity in an
 *	   entity-association.  If so, check to see if any of the contained
 *	   entities are present, if so, assume the container entity exists.
 *	   Note that this may need to be iterative, since it's possible to have
 *	   multi-level entity associations.
 *
 * 	e) If there are no active sensors for the entity, and the entity is not
 *	   the container entity in an active entity-assocation, then the entity
 *         is present if (sic) there there is a FRU device for the entity, and
 *         the FRU device is present.
 *
 *	It should not be considered an error if a FRU device locator record is
 *	present for a FRU device, but the FRU device is not there.
 *
 */
int
ipmi_entity_present(ipmi_handle_t *ihp, ipmi_entity_t *ep, boolean_t *valp)
{
	/* LINTED - alignment */
	ipmi_entity_impl_t *eip = ENTITY_TO_IMPL(ep);
	ipmi_entity_impl_t *cp;
	ipmi_entity_sdr_t *esp;
	ipmi_sdr_t *sdrp;
	uint16_t mask;
	uint8_t number, sensor_type, reading_type;
	ipmi_sensor_reading_t *srp;
	ipmi_sdr_compact_sensor_t *csp;
	ipmi_sdr_full_sensor_t *fsp;
	ipmi_sdr_fru_locator_t *frup;
	char *frudata;

	/*
	 * Search the sensors for a present sensor or a discrete sensor that
	 * indicates presence.
	 */
	for (esp = ipmi_list_next(&eip->ie_sdr_list); esp != NULL;
	    esp = ipmi_list_next(esp)) {
		sdrp = esp->ies_sdr;
		switch (sdrp->is_type) {
		case IPMI_SDR_TYPE_COMPACT_SENSOR:
			csp = (ipmi_sdr_compact_sensor_t *)sdrp->is_record;
			number = csp->is_cs_number;
			sensor_type = csp->is_cs_type;
			reading_type = csp->is_cs_reading_type;
			break;

		case IPMI_SDR_TYPE_FULL_SENSOR:
			fsp = (ipmi_sdr_full_sensor_t *)sdrp->is_record;
			number = fsp->is_fs_number;
			sensor_type = fsp->is_fs_type;
			reading_type = fsp->is_fs_reading_type;
			break;

		default:
			continue;
		}

		switch (reading_type) {
		case IPMI_RT_PRESENT:
			mask = IPMI_SR_PRESENT_ASSERT;
			break;

		case IPMI_RT_SPECIFIC:
			switch (sensor_type) {
			case IPMI_ST_PROCESSOR:
				mask = IPMI_EV_PROCESSOR_PRESENT;
				break;

			case IPMI_ST_POWER_SUPPLY:
				mask = IPMI_EV_POWER_SUPPLY_PRESENT;
				break;

			case IPMI_ST_MEMORY:
				mask = IPMI_EV_MEMORY_PRESENT;
				break;

			case IPMI_ST_BAY:
				mask = IPMI_EV_BAY_PRESENT;
				break;

			default:
				continue;
			}
			break;

		default:
			continue;
		}

		/*
		 * If we've reached here, then we have a dedicated sensor that
		 * indicates presence.
		 */
		if ((srp = ipmi_get_sensor_reading(ihp, number)) == NULL) {
			if (ipmi_errno(ihp) == EIPMI_NOT_PRESENT) {
				*valp = B_FALSE;
				return (0);
			}

			return (-1);
		}

		*valp = (srp->isr_state & mask) != 0;
		return (0);
	}

	/*
	 * No explicit presence sensor was found.  See if there is at least one
	 * active sensor associated with the entity.
	 */
	for (esp = ipmi_list_next(&eip->ie_sdr_list); esp != NULL;
	    esp = ipmi_list_next(esp)) {
		sdrp = esp->ies_sdr;
		switch (sdrp->is_type) {
		case IPMI_SDR_TYPE_COMPACT_SENSOR:
			csp = (ipmi_sdr_compact_sensor_t *)sdrp->is_record;
			number = csp->is_cs_number;
			break;

		case IPMI_SDR_TYPE_FULL_SENSOR:
			fsp = (ipmi_sdr_full_sensor_t *)sdrp->is_record;
			number = fsp->is_fs_number;
			break;

		default:
			continue;
		}

		if ((srp = ipmi_get_sensor_reading(ihp, number)) == NULL) {
			if (ipmi_errno(ihp) == EIPMI_NOT_PRESENT)
				continue;

			return (-1);
		}

		if (srp->isr_scanning_enabled) {
			*valp = B_TRUE;
			return (0);
		}
	}

	/*
	 * If this entity has children, then it is present if any of its
	 * children are present.
	 */
	for (cp = ipmi_list_next(&eip->ie_child_list); cp != NULL;
	    cp = ipmi_list_next(cp)) {
		if (ipmi_entity_present(ihp, &cp->ie_entity, valp) != 0)
			return (-1);

		if (*valp)
			return (0);
	}

	/*
	 * If the FRU device is present, then the entity is present.
	 */
	for (esp = ipmi_list_next(&eip->ie_sdr_list); esp != NULL;
	    esp = ipmi_list_next(esp)) {
		sdrp = esp->ies_sdr;
		if (sdrp->is_type != IPMI_SDR_TYPE_FRU_LOCATOR)
			continue;

		frup = (ipmi_sdr_fru_locator_t *)sdrp->is_record;
		if (ipmi_fru_read(ihp, frup, &frudata) >= 0) {
			ipmi_free(ihp, frudata);
			*valp = B_TRUE;
			return (0);
		}

		if (ipmi_errno(ihp) != EIPMI_NOT_PRESENT)
			return (-1);
	}

	*valp = B_FALSE;
	return (0);
}

static int
ipmi_entity_refresh(ipmi_handle_t *ihp)
{
	if (ipmi_hash_first(ihp->ih_entities) != NULL &&
	    !ipmi_sdr_changed(ihp))
		return (0);

	if (ipmi_sdr_iter(ihp, ipmi_entity_visit, NULL) != 0)
		return (-1);

	return (0);
}

int
ipmi_entity_iter(ipmi_handle_t *ihp, int (*func)(ipmi_handle_t *,
    ipmi_entity_t *, void *), void *data)
{
	ipmi_entity_impl_t *eip;
	int ret;

	if (ipmi_entity_refresh(ihp) != 0)
		return (-1);

	for (eip = ipmi_hash_first(ihp->ih_entities); eip != NULL;
	    eip = ipmi_hash_next(ihp->ih_entities, eip)) {
		if (eip->ie_parent != NULL)
			continue;

		if ((ret = func(ihp, &eip->ie_entity, data)) != 0)
			return (ret);
	}

	return (0);
}

int
ipmi_entity_iter_sdr(ipmi_handle_t *ihp, ipmi_entity_t *ep,
    int (*func)(ipmi_handle_t *, ipmi_entity_t *, const char *, ipmi_sdr_t *,
    void *), void *data)
{
	/* LINTED - alignment */
	ipmi_entity_impl_t *eip = ENTITY_TO_IMPL(ep);
	ipmi_entity_sdr_t *isp;
	int ret;

	for (isp = ipmi_list_next(&eip->ie_sdr_list); isp != NULL;
	    isp = ipmi_list_next(isp)) {
		if ((ret = func(ihp, ep, isp->ies_name,
		    isp->ies_sdr, data)) != 0)
			return (ret);
	}

	return (0);
}

int
ipmi_entity_iter_children(ipmi_handle_t *ihp, ipmi_entity_t *ep,
    int (*func)(ipmi_handle_t *, ipmi_entity_t *, void *), void *data)
{
	/* LINTED - alignment */
	ipmi_entity_impl_t *eip = ENTITY_TO_IMPL(ep);
	ipmi_entity_impl_t *cp;
	int ret;

	for (cp = ipmi_list_next(&eip->ie_child_list); cp != NULL;
	    cp = ipmi_list_next(cp)) {
		if ((ret = func(ihp, &cp->ie_entity, data)) != 0)
			return (ret);
	}

	return (0);
}

ipmi_entity_t *
ipmi_entity_parent(ipmi_handle_t *ihp, ipmi_entity_t *ep)
{
	/* LINTED - alignment */
	ipmi_entity_impl_t *eip = ENTITY_TO_IMPL(ep);

	if (eip->ie_parent == NULL) {
		(void) ipmi_set_error(ihp, EIPMI_NOT_PRESENT, NULL);
		return (NULL);
	}

	return (&eip->ie_parent->ie_entity);
}

ipmi_entity_t *
ipmi_entity_lookup(ipmi_handle_t *ihp, uint8_t type, uint8_t instance)
{
	ipmi_entity_t search;
	ipmi_entity_impl_t *eip;

	if (ipmi_entity_refresh(ihp) != 0)
		return (NULL);

	search.ie_type = type;
	search.ie_instance = instance;

	if ((eip = ipmi_hash_lookup(ihp->ih_entities, &search)) == NULL) {
		(void) ipmi_set_error(ihp, EIPMI_NOT_PRESENT, NULL);
		return (NULL);
	}

	return (&eip->ie_entity);
}

ipmi_entity_t *
ipmi_entity_lookup_sdr(ipmi_handle_t *ihp, const char *name)
{
	ipmi_sdr_t *sdrp;
	uint8_t id, instance;
	boolean_t logical;

	if ((sdrp = ipmi_sdr_lookup(ihp, name)) == NULL)
		return (NULL);

	if (ipmi_entity_sdr_parse(sdrp, &id, &instance, &logical) != 0) {
		(void) ipmi_set_error(ihp, EIPMI_NOT_PRESENT,
		    "SDR record %s has no associated entity", name);
		return (NULL);
	}

	return (ipmi_entity_lookup(ihp, id, instance));
}

static const void *
ipmi_entity_hash_convert(const void *p)
{
	const ipmi_entity_impl_t *eip = p;

	return (&eip->ie_entity);
}

static ulong_t
ipmi_entity_hash_compute(const void *p)
{
	const ipmi_entity_t *ep = p;

	return ((ep->ie_type << 8) | ep->ie_instance);
}

static int
ipmi_entity_hash_compare(const void *a, const void *b)
{
	const ipmi_entity_t *ea = a;
	const ipmi_entity_t *eb = b;

	if (ea->ie_type == eb->ie_type &&
	    ea->ie_instance == eb->ie_instance)
		return (0);
	else
		return (-1);
}

int
ipmi_entity_init(ipmi_handle_t *ihp)
{
	if ((ihp->ih_entities = ipmi_hash_create(ihp,
	    offsetof(ipmi_entity_impl_t, ie_link),
	    ipmi_entity_hash_convert,
	    ipmi_entity_hash_compute,
	    ipmi_entity_hash_compare)) == NULL)
		return (-1);

	return (0);
}

void
ipmi_entity_clear(ipmi_handle_t *ihp)
{
	ipmi_entity_impl_t *eip;
	ipmi_entity_sdr_t *esp;

	while ((eip = ipmi_hash_first(ihp->ih_entities)) != NULL) {
		while ((esp = ipmi_list_next(&eip->ie_sdr_list)) != NULL) {
			ipmi_list_delete(&eip->ie_sdr_list, esp);
			ipmi_free(ihp, esp);
		}
		ipmi_hash_remove(ihp->ih_entities, eip);
		ipmi_free(ihp, eip);
	}
}

void
ipmi_entity_fini(ipmi_handle_t *ihp)
{
	if (ihp->ih_entities != NULL) {
		ipmi_entity_clear(ihp);
		ipmi_hash_destroy(ihp->ih_entities);
	}
}
