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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <exacct.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <limits.h>
#include <poll.h>
#include <pool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <thread.h>
#include <time.h>
#include <unistd.h>

#include <libxml/tree.h>

#include <sys/mman.h>
#include <sys/pool.h>
#include <sys/pool_impl.h>
#include <sys/priocntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "dict.h"

#include "pool_internal.h"
#include "pool_impl.h"
#include "pool_kernel_impl.h"

/*
 * libpool kernel Manipulation Routines
 *
 * pool_kernel.c implements the kernel manipulation routines used by the
 * libpool kernel datastore. The functions are grouped into the following
 * logical areas
 *
 */

/*
 * Device snapshot transfer buffer size
 */
#define	KERNEL_SNAPSHOT_BUF_SZ	65535

/*
 * Kernel result set's initial size. 8 is probably large enough for
 * most queries. Queries requiring more space are accomodated using
 * realloc on a per result set basis.
 */
#define	KERNEL_RS_INITIAL_SZ	8

/*
 * Property manipulation macros
 */
#define	KERNEL_PROP_RDONLY	0x1

/*
 * Information required to evaluate qualifying elements for a query
 */
struct query_obj {
	const pool_conf_t *conf;
	const pool_elem_t *src;
	const char *src_attr;
	pool_elem_class_t classes;
	pool_value_t **props;
	pool_knl_result_set_t *rs;
};

/*
 * Identifies a pool element with a processor set id
 */
typedef struct pool_set_xref {
	pool_knl_pool_t	*psx_pool;
	uint_t		psx_pset_id;
	struct pool_set_xref *psx_next;
} pool_set_xref_t;

/*
 * Controls exacct snapshot load into libpool data structure
 */
typedef struct pool_snap_load {
	int *psl_changed;
	pool_set_xref_t *psl_xref;
	pool_elem_t *psl_system;
	pool_knl_resource_t *psl_pset;
} pool_snap_load_t;

/*
 * Information about an XML document which is being constructed
 */
struct knl_to_xml {
	xmlDocPtr ktx_doc;
	xmlNodePtr ktx_node;
};

/*
 * Undo structure processing. The following structures are all used to
 * allow changes to the libpool snapshot and kernel following an
 * unsuccessful commit.
 */
typedef struct pool_create_undo {
	pool_create_t pcu_ioctl;
	pool_elem_t *pcu_elem;
} pool_create_undo_t;

typedef struct pool_destroy_undo {
	pool_destroy_t pdu_ioctl;
	pool_elem_t *pdu_elem;
} pool_destroy_undo_t;

typedef struct pool_assoc_undo {
	pool_assoc_t pau_ioctl;
	pool_elem_t *pau_assoc;
	pool_elem_t *pau_oldres;
	pool_elem_t *pau_newres;
} pool_assoc_undo_t;

typedef struct pool_dissoc_undo {
	pool_dissoc_t pdu_ioctl;
	pool_elem_t *pdu_dissoc;
	pool_elem_t *pdu_oldres;
	pool_elem_t *pdu_newres;
} pool_dissoc_undo_t;

typedef struct pool_xtransfer_undo {
	pool_xtransfer_t pxu_ioctl;
	pool_elem_t *pxu_src;
	pool_elem_t *pxu_tgt;
	pool_component_t **pxu_rl;
} pool_xtransfer_undo_t;

typedef struct pool_propput_undo {
	pool_propput_t ppu_ioctl;
	pool_elem_t *ppu_elem;
	nvlist_t *ppu_alist;
	nvlist_t *ppu_blist;
	uchar_t ppu_doioctl;
} pool_propput_undo_t;

typedef struct pool_proprm_undo {
	pool_proprm_t pru_ioctl;
	pool_elem_t *pru_elem;
	pool_value_t pru_oldval;
} pool_proprm_undo_t;

extern const char *dtd_location;

extern const char *element_class_tags[];
extern const char pool_info_location[];

/*
 * These functions are defined in pool_xml.c and represent the minimum
 * XML support required to allow a pool kernel configuration to be
 * exported as an XML document.
 */
extern int pool_xml_set_attr(xmlNodePtr, xmlChar *, const pool_value_t *);
extern int pool_xml_set_prop(xmlNodePtr, xmlChar *, const pool_value_t *);
extern void xml_init(void);
extern xmlNodePtr node_create(xmlNodePtr, const xmlChar *);
extern void pool_error_func(void *, const char *, ...);
/*
 * Utilities
 */
static int load_group(pool_conf_t *, pool_knl_elem_t *, ea_object_t *,
    pool_snap_load_t *);
static void pool_knl_elem_free(pool_knl_elem_t *, int);
static int pool_knl_put_xml_property(pool_elem_t *, xmlNodePtr, const char *,
    const pool_value_t *);
static int pool_knl_snap_load_push(pool_snap_load_t *, pool_knl_pool_t *);
static int pool_knl_snap_load_update(pool_snap_load_t *, int, uint_t);
static int pool_knl_snap_load_remove(pool_snap_load_t *, int, uint_t);
static nvpair_t *pool_knl_find_nvpair(nvlist_t *, const char *);
static int pool_knl_nvlist_add_value(nvlist_t *, const char *,
    const pool_value_t *);
static int pool_knl_recover(pool_conf_t *);
static uint64_t hash_id(const pool_elem_t *);
static int blocking_open(const char *, int);

/*
 * Connections
 */
static void pool_knl_connection_free(pool_knl_connection_t *);

/*
 * Configuration
 */
static int pool_knl_close(pool_conf_t *);
static int pool_knl_validate(const pool_conf_t *, pool_valid_level_t);
static int pool_knl_commit(pool_conf_t *);
static int pool_knl_export(const pool_conf_t *, const char *,
    pool_export_format_t);
static int pool_knl_rollback(pool_conf_t *);
static pool_result_set_t *pool_knl_exec_query(const pool_conf_t *,
    const pool_elem_t *, const char *, pool_elem_class_t, pool_value_t **);
static int pool_knl_remove(pool_conf_t *);
static char *pool_knl_get_binding(pool_conf_t *, pid_t);
static int pool_knl_set_binding(pool_conf_t *, const char *, idtype_t, id_t);
static char *pool_knl_get_resource_binding(pool_conf_t *,
    pool_resource_elem_class_t, pid_t);
static int pool_knl_res_transfer(pool_resource_t *, pool_resource_t *,
    uint64_t);
static int pool_knl_res_xtransfer(pool_resource_t *, pool_resource_t *,
    pool_component_t **);

/*
 * Result Sets
 */
static pool_knl_result_set_t *pool_knl_result_set_alloc(const pool_conf_t *);
static int pool_knl_result_set_append(pool_knl_result_set_t *,
    pool_knl_elem_t *);
static int pool_knl_result_set_realloc(pool_knl_result_set_t *);
static void pool_knl_result_set_free(pool_knl_result_set_t *);
static pool_elem_t *pool_knl_rs_next(pool_result_set_t *);
static pool_elem_t *pool_knl_rs_prev(pool_result_set_t *);
static pool_elem_t *pool_knl_rs_first(pool_result_set_t *);
static pool_elem_t *pool_knl_rs_last(pool_result_set_t *);
static int pool_knl_rs_set_index(pool_result_set_t *, int);
static int pool_knl_rs_get_index(pool_result_set_t *);
static int pool_knl_rs_count(pool_result_set_t *);
static int pool_knl_rs_close(pool_result_set_t *);

/*
 * Element (and sub-type)
 */
static pool_knl_elem_t *pool_knl_elem_wrap(pool_conf_t *, pool_elem_class_t,
    pool_resource_elem_class_t, pool_component_elem_class_t);
static pool_elem_t *pool_knl_elem_create(pool_conf_t *, pool_elem_class_t,
    pool_resource_elem_class_t, pool_component_elem_class_t);
static int pool_knl_elem_remove(pool_elem_t *);
static int pool_knl_set_container(pool_elem_t *, pool_elem_t *);
static pool_elem_t *pool_knl_get_container(const pool_elem_t *);
/*
 * Pool element specific
 */
static int pool_knl_pool_associate(pool_t *, const pool_resource_t *);
static int pool_knl_pool_dissociate(pool_t *, const pool_resource_t *);

/*
 * Resource elements specific
 */
static int pool_knl_resource_is_system(const pool_resource_t *);
static int pool_knl_resource_can_associate(const pool_resource_t *);

/* Properties */
static pool_value_class_t pool_knl_get_property(const pool_elem_t *,
    const char *, pool_value_t *);
static pool_value_class_t pool_knl_get_dynamic_property(const pool_elem_t *,
    const char *, pool_value_t *);
static int pool_knl_put_property(pool_elem_t *, const char *,
    const pool_value_t *);
static int pool_knl_rm_property(pool_elem_t *, const char *);
static pool_value_t **pool_knl_get_properties(const pool_elem_t *, uint_t *);

/*
 * Logging
 */
static int log_item_commit(log_item_t *);
static int log_item_undo(log_item_t *);
static int log_item_release(log_item_t *);

/*
 * Utilities
 */

/*
 * load_group() updates the library configuration with the kernel
 * snapshot supplied in ep. The function is designed to be called
 * recursively. This function depends implicitly on the ordering of
 * the data provided in ep. Changes to the ordering of data in ep must
 * be matched by changes to this function.
 */
int
load_group(pool_conf_t *conf, pool_knl_elem_t *elem, ea_object_t *ep,
    pool_snap_load_t *psl)
{
	ea_object_t *eo;
	pool_knl_elem_t *old_elem;
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;
	int ret = PO_SUCCESS;

	if ((ep->eo_catalog & EXD_DATA_MASK) == EXD_GROUP_SYSTEM) {
		if ((elem = pool_knl_elem_wrap(conf, PEC_SYSTEM, PREC_INVALID,
		    PCEC_INVALID)) == NULL)
			return (PO_FAIL);
		if (nvlist_alloc(&elem->pke_properties, NV_UNIQUE_NAME_TYPE,
		    0) != 0) {
			pool_knl_elem_free(elem, PO_FALSE);
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		/*
		 * Check to see if we already have an element
		 * for this data. If we have, free the newly
		 * created elem and continue with the old one
		 */
		if ((old_elem = dict_get(prov->pkc_elements, elem)) != NULL) {
			nvlist_free(old_elem->pke_properties);
			old_elem->pke_properties = elem->pke_properties;
			pool_knl_elem_free(elem, PO_FALSE);
			elem = old_elem;
		} else {
			if (dict_put(prov->pkc_elements, elem, elem) != NULL) {
				pool_knl_elem_free(elem, PO_TRUE);
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
		}
		psl->psl_system = (pool_elem_t *)elem;
	}

	for (eo = ep->eo_group.eg_objs; eo != NULL; eo = eo->eo_next) {
		int data;
		pool_knl_elem_t *prop_elem = NULL;

		data = (eo->eo_catalog & EXD_DATA_MASK);

		switch (data) {
		case EXD_SYSTEM_TSTAMP:
		case EXD_POOL_TSTAMP:
		case EXD_PSET_TSTAMP:
		case EXD_CPU_TSTAMP:
			if (eo->eo_item.ei_uint64 > prov->pkc_lotime) {
				if (eo->eo_item.ei_uint64 > prov->pkc_ltime)
					prov->pkc_ltime = eo->eo_item.ei_uint64;
				if (psl->psl_changed) {
					switch (data) {
					case EXD_SYSTEM_TSTAMP:
						*psl->psl_changed |= POU_SYSTEM;
						break;
					case EXD_POOL_TSTAMP:
						*psl->psl_changed |= POU_POOL;
						break;
					case EXD_PSET_TSTAMP:
						*psl->psl_changed |= POU_PSET;
						break;
					case EXD_CPU_TSTAMP:
						*psl->psl_changed |= POU_CPU;
						break;
					}
				}
			}
			break;
		case EXD_SYSTEM_PROP:
		case EXD_POOL_PROP:
		case EXD_PSET_PROP:
		case EXD_CPU_PROP:
			if (data == EXD_PSET_PROP) {
				prop_elem = elem;
				elem = (pool_knl_elem_t *)psl->psl_pset;
			}
			nvlist_free(elem->pke_properties);
			if (nvlist_unpack(eo->eo_item.ei_raw,
			    eo->eo_item.ei_size, &elem->pke_properties, 0) !=
			    0) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			elem->pke_ltime = prov->pkc_ltime;
			if (data == EXD_PSET_PROP) {
				elem = prop_elem;
			}
			break;
		case EXD_POOL_POOLID:
			if (nvlist_alloc(&elem->pke_properties,
			    NV_UNIQUE_NAME_TYPE, 0) != 0) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			if (nvlist_add_int64(elem->pke_properties,
			    "pool.sys_id",
			    (int64_t)eo->eo_item.ei_uint32) != 0) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			if ((old_elem = dict_get(prov->pkc_elements, elem)) !=
			    NULL) {
				nvlist_free(old_elem->pke_properties);
				old_elem->pke_properties = elem->pke_properties;
				pool_knl_elem_free(elem, PO_FALSE);
				elem = old_elem;
			} else {
				if (dict_put(prov->pkc_elements, elem, elem) !=
				    NULL) {
					pool_knl_elem_free(elem, PO_TRUE);
					pool_seterror(POE_SYSTEM);
					return (PO_FAIL);
				}
			}
			if (pool_knl_snap_load_push(psl,
			    (pool_knl_pool_t *)elem) != PO_SUCCESS) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			((pool_knl_pool_t *)elem)->pkp_assoc[PREC_PSET] = NULL;
			break;
		case EXD_POOL_PSETID:
			if (pool_knl_snap_load_update(psl, EXD_POOL_PSETID,
			    eo->eo_item.ei_uint32) != PO_SUCCESS) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			break;
		case EXD_PSET_PSETID:
			if (nvlist_alloc(&elem->pke_properties,
			    NV_UNIQUE_NAME_TYPE, 0) != 0) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			if (nvlist_add_int64(elem->pke_properties,
			    "pset.sys_id",
			    (int64_t)eo->eo_item.ei_uint32) != 0) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			if ((old_elem = dict_get(prov->pkc_elements, elem)) !=
			    NULL) {
				nvlist_free(old_elem->pke_properties);
				old_elem->pke_properties = elem->pke_properties;
				pool_knl_elem_free(elem, PO_FALSE);
				elem = old_elem;
			} else {
				if (dict_put(prov->pkc_elements, elem, elem) !=
				    NULL) {
					pool_knl_elem_free(elem, PO_TRUE);
					pool_seterror(POE_SYSTEM);
					return (PO_FAIL);
				}
			}
			psl->psl_pset = (pool_knl_resource_t *)elem;
			if (pool_knl_snap_load_remove(psl, data,
			    eo->eo_item.ei_uint32) != PO_SUCCESS) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			break;
		case EXD_CPU_CPUID:
			if (nvlist_alloc(&elem->pke_properties,
			    NV_UNIQUE_NAME_TYPE, 0) != 0) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			if (nvlist_add_int64(elem->pke_properties,
			    "cpu.sys_id",
			    (int64_t)eo->eo_item.ei_uint32) != 0) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			if ((old_elem = dict_get(prov->pkc_elements, elem)) !=
			    NULL) {
				nvlist_free(old_elem->pke_properties);
				old_elem->pke_properties = elem->pke_properties;
				old_elem->pke_parent = elem->pke_parent;
				pool_knl_elem_free(elem, PO_FALSE);
				elem = old_elem;
			} else {
				if (dict_put(prov->pkc_elements, elem, elem) !=
				    NULL) {
					pool_knl_elem_free(elem, PO_TRUE);
					pool_seterror(POE_SYSTEM);
					return (PO_FAIL);
				}
			}
			break;
		case EXD_GROUP_POOL:
			if ((elem = pool_knl_elem_wrap(conf, PEC_POOL,
			    PREC_INVALID, PCEC_INVALID)) == NULL)
				return (PO_FAIL);
			if (pool_set_container(psl->psl_system,
			    (pool_elem_t *)elem) != PO_SUCCESS) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			break;
		case EXD_GROUP_PSET:
			if ((elem = pool_knl_elem_wrap(conf, PEC_RES_COMP,
			    PREC_PSET, PCEC_INVALID)) == NULL)
				return (PO_FAIL);
			if (pool_set_container(psl->psl_system,
			    (pool_elem_t *)elem) != PO_SUCCESS) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			break;
		case EXD_GROUP_CPU:
			if ((elem = pool_knl_elem_wrap(conf, PEC_COMP,
			    PREC_INVALID, PCEC_CPU)) == NULL)
				return (PO_FAIL);
			if (pool_set_container((pool_elem_t *)psl->psl_pset,
			    (pool_elem_t *)elem) != PO_SUCCESS) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			break;
		default:
			break;
		}


		if (eo->eo_type == EO_GROUP) {
			if ((ret = load_group(conf, elem, eo, psl)) == PO_FAIL)
				break;
		}
	}
	return (ret);
}

/*
 * Push a snapshot entry onto the list of pools in the snapshot.
 */
int
pool_knl_snap_load_push(pool_snap_load_t *psl, pool_knl_pool_t *pkp)
{
	pool_set_xref_t *psx;

	if ((psx = malloc(sizeof (pool_set_xref_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	(void) memset(psx, 0, sizeof (pool_set_xref_t));
	psx->psx_pool = pkp;
	/*
	 * Push onto the list of pools
	 */
	psx->psx_next = psl->psl_xref;
	psl->psl_xref = psx;

	return (PO_SUCCESS);
}

/*
 * Update the current cross-reference for the supplied type of
 * resource.
 */
int
pool_knl_snap_load_update(pool_snap_load_t *psl, int type, uint_t id)
{
	switch (type) {
	case EXD_POOL_PSETID:
		psl->psl_xref->psx_pset_id = id;
		break;
	default:
		return (PO_FAIL);
	}

	return (PO_SUCCESS);
}

/*
 * Remove a resource entry with the supplied type and id from the
 * snapshot list when it is no longer required.
 */
int
pool_knl_snap_load_remove(pool_snap_load_t *psl, int type, uint_t id)
{
	pool_set_xref_t *current, *prev, *next;

	for (prev = NULL, current = psl->psl_xref; current != NULL;
	    current = next) {
		switch (type) {
		case EXD_PSET_PSETID:
			if (current->psx_pset_id == id)
				current->psx_pool->pkp_assoc[PREC_PSET] =
				    psl->psl_pset;
			break;
		default:
			return (PO_FAIL);
		}
		next = current->psx_next;
		if (current->psx_pool->pkp_assoc[PREC_PSET] != NULL) {
			if (prev != NULL) {
				prev->psx_next = current->psx_next;
			} else {
				psl->psl_xref = current->psx_next;
			}
			free(current);
		} else
			prev = current;
	}

	return (PO_SUCCESS);
}

/*
 * Return the nvpair with the supplied name from the supplied list.
 *
 * NULL is returned if the name cannot be found in the list.
 */
nvpair_t *
pool_knl_find_nvpair(nvlist_t *l, const char *name)
{
	nvpair_t *pair;

	for (pair = nvlist_next_nvpair(l, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(l, pair)) {
		if (strcmp(nvpair_name(pair), name) == 0)
			break;
	}
	return (pair);
}

/*
 * Close the configuration. There are a few steps to closing a configuration:
 * - Close the pseudo device
 * - Free the data provider
 * Returns PO_SUCCESS/PO_FAIL
 */
int
pool_knl_close(pool_conf_t *conf)
{
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;

	if (close(prov->pkc_fd) < 0) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	/*
	 * Rollback any pending changes before freeing the prov. This
	 * ensures there are no memory leaks from pending transactions.
	 * However, don't rollback when we've done a temporary pool since the
	 * pool/resources haven't really been committed in this case.
	 * They will all be freed in pool_knl_connection_free and we don't
	 * want to double free them.
	 */
	if (!(conf->pc_prov->pc_oflags & PO_TEMP))
		(void) pool_knl_rollback(conf);
	pool_knl_connection_free(prov);
	return (PO_SUCCESS);
}

/*
 * Remove elements in this map (previously identified as "dead") from
 * the configuration map (prov->pkc_elements).
 */

/* ARGSUSED1 */
static void
remove_dead_elems(const void *key, void **value, void *cl)
{
	pool_knl_elem_t *pke = (pool_knl_elem_t *)key;
	pool_conf_t *conf = TO_CONF(TO_ELEM(pke));
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;

	assert(dict_remove(prov->pkc_elements, pke) != NULL);
#ifdef DEBUG
	dprintf("remove_dead_elems:\n");
	pool_elem_dprintf(TO_ELEM(pke));
#endif	/* DEBUG */
	pool_knl_elem_free(pke, PO_TRUE);
}

/*
 * Find elements which were not updated the last time that
 * load_group() was called. Add those elements into a separate map
 * (passed in cl) which will be later used to remove these elements
 * from the configuration map.
 */
/* ARGSUSED1 */
static void
find_dead_elems(const void *key, void **value, void *cl)
{
	pool_knl_elem_t *pke = (pool_knl_elem_t *)key;
	pool_conf_t *conf = TO_CONF(TO_ELEM(pke));
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;
	dict_hdl_t *dead_map = (dict_hdl_t *)cl;

	if (pke->pke_ltime < prov->pkc_ltime)
		(void) dict_put(dead_map, pke, pke);
}

/*
 * Update the snapshot held by the library. This function acts as the
 * controller for the snapshot update procedure. Then snapshot is
 * actually updated in multiple phases by the load_group() function
 * (which updates existing elements and creates new elements as
 * required) and then by find_dead_elems and remove_dead_elems
 * (respectively responsible for identifying elements which are to be
 * removed and then removing them).
 *
 * Returns PO_SUCCESS
 */
int
pool_knl_update(pool_conf_t *conf, int *changed)
{
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;
	pool_query_t query = {0};
	ea_object_t *ep;
	dict_hdl_t *dead_map;
	pool_snap_load_t psl = { NULL };

	/*
	 * Ensure the library snapshot is consistent, if there are any
	 * outstanding transactions return failure.
	 */
	if (log_size(prov->pkc_log) != 0) {
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	/*
	 * Query the kernel for a snapshot of the configuration state. Use
	 * load_group to allocate the user-land representation of the
	 * data returned in the snapshot.
	 */
	/* LINTED E_CONSTANT_CONDITION */
	while (1) {
		if (ioctl(prov->pkc_fd, POOL_QUERY, &query) < 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		if ((query.pq_io_buf = calloc(1,
		    (query.pq_io_bufsize < KERNEL_SNAPSHOT_BUF_SZ) ?
		    query.pq_io_bufsize * 2 : query.pq_io_bufsize)) == NULL) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		if (ioctl(prov->pkc_fd, POOL_QUERY, &query) < 0) {
			free(query.pq_io_buf);
			if (errno != ENOMEM) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			query.pq_io_bufsize = 0;
			query.pq_io_buf = NULL;
		} else
			break;
	}
	if (ea_unpack_object(&ep, EUP_NOALLOC, query.pq_io_buf,
	    query.pq_io_bufsize) != EO_GROUP) {
		free(query.pq_io_buf);
		pool_seterror(POE_DATASTORE);
		return (PO_FAIL);
	}
	/*
	 * Update the library snapshot
	 */
	psl.psl_changed = changed;
	prov->pkc_lotime = prov->pkc_ltime;
	if (load_group(conf, NULL, ep, &psl) != PO_SUCCESS) {
		free(query.pq_io_buf);
		ea_free_object(ep, EUP_NOALLOC);
		return (PO_FAIL);
	}

	free(query.pq_io_buf);
	ea_free_object(ep, EUP_NOALLOC);
	/*
	 * Now search the dictionary for items that must be removed because
	 * they were neither created nor updated.
	 */
	if ((dead_map = dict_new((int (*)(const void *, const void *))
	    pool_elem_compare, (uint64_t (*)(const void *))hash_id)) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	dict_map(prov->pkc_elements, find_dead_elems, dead_map);

	if (dict_length(dead_map) > 0) {
		dict_map(dead_map, remove_dead_elems, NULL);
	}
	dict_free(&dead_map);

	return (PO_SUCCESS);
}

/*
 * Rely on the kernel to always keep a kernel configuration valid.
 * Returns PO_SUCCESS
 */
/* ARGSUSED */
int
pool_knl_validate(const pool_conf_t *conf, pool_valid_level_t level)
{
	return ((conf->pc_state == POF_INVALID) ? PO_FAIL : PO_SUCCESS);
}

/*
 * Process all the outstanding transactions in the log. If the processing
 * fails, then attempt to rollback and "undo" the changes.
 */
int
pool_knl_commit(pool_conf_t *conf)
{
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;
	int lock = 1;

	/*
	 * Lock the kernel state for the commit
	 */
	if (ioctl(prov->pkc_fd, POOL_COMMIT, lock) < 0) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	lock = 0;
	/*
	 * If the state is LS_FAIL, then try to recover before
	 * performing the commit.
	 */
	if (prov->pkc_log->l_state == LS_FAIL) {
		if (pool_knl_recover(conf) == PO_FAIL) {
			/*
			 * Unlock the kernel state for the
			 * commit. Assert that this * can't fail,
			 * since if it ever does fail the library is
			 * unusable.
			 */
			assert(ioctl(prov->pkc_fd, POOL_COMMIT, lock) >= 0);
		}
	}
	/*
	 * Commit the log
	 */
	if (log_walk(prov->pkc_log, log_item_commit) != PO_SUCCESS) {
		(void) pool_knl_recover(conf);
		/*
		 * Unlock the kernel state for the commit. Assert that
		 * this can't fail, since if it ever does fail the
		 * library is unusable.
		 */
		assert(ioctl(prov->pkc_fd, POOL_COMMIT, lock) >= 0);
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	/*
	 * Unlock the kernel state for the commit. Assert that this
	 * can't fail, since if it ever does fail the library is
	 * unusable.
	 */
	assert(ioctl(prov->pkc_fd, POOL_COMMIT, lock) >= 0);
	/*
	 * Release the log resources
	 */
	(void) log_walk(prov->pkc_log, log_item_release);
	log_empty(prov->pkc_log);
	return (PO_SUCCESS);
}

/*
 * prop_build_cb() is designed to be called from
 * pool_walk_properties(). The property value is used to put an XML
 * property on the supplied ktx_node. This is an essential part of the
 * mechanism used to export a kernel configuration in libpool XML
 * form.
 */
/* ARGSUSED */
static int
prop_build_cb(pool_conf_t *UNUSED, pool_elem_t *pe, const char *name,
    pool_value_t *pval, void *user)
{
	struct knl_to_xml *info = (struct knl_to_xml *)user;

	return (pool_knl_put_xml_property((pool_elem_t *)pe, info->ktx_node,
	    name, pval));
}

/*
 * Duplicate some of the functionality from pool_xml_put_property()
 * (see pool_xml.c) to allow a kernel configuration to add XML nodes
 * to an XML tree which represents the kernel configuration. This is
 * an essential part of the mechanism used to export a kernel
 * configuration in libpool XML form.
 */
int
pool_knl_put_xml_property(pool_elem_t *pe, xmlNodePtr node, const char *name,
    const pool_value_t *val)
{

	/*
	 * "type" is a special attribute which is not visible ever outside of
	 * libpool. Use the specific type accessor function.
	 */
	if (strcmp(name, c_type) == 0) {
		return (pool_xml_set_attr(node, BAD_CAST name,
		    val));
	}
	if (is_ns_property(pe, name) != NULL) {	/* in ns */
		if (pool_xml_set_attr(node,
		    BAD_CAST property_name_minus_ns(pe, name), val) == PO_FAIL)
			return (pool_xml_set_prop(node, BAD_CAST name,
			    val));
	} else
		return (pool_xml_set_prop(node, BAD_CAST name, val));
	return (PO_SUCCESS);
}

/*
 * Export the kernel configuration as an XML file. The configuration
 * is used to build an XML document in memory. This document is then
 * saved to the supplied location.
 */
int
pool_knl_export(const pool_conf_t *conf, const char *location,
    pool_export_format_t fmt)
{
	xmlNodePtr node_comment;
	xmlNodePtr system;
	int ret;
	pool_t **ps;
	pool_resource_t **rs;
	uint_t nelem;
	int i;
	struct knl_to_xml info;
	char_buf_t *cb = NULL;
	xmlValidCtxtPtr cvp;

	xml_init();


	switch (fmt) {
	case POX_NATIVE:
		info.ktx_doc = xmlNewDoc(BAD_CAST "1.0");
		(void) xmlCreateIntSubset(info.ktx_doc, BAD_CAST "system",
		    BAD_CAST "-//Sun Microsystems Inc//DTD Resource "
		    "Management All//EN",
		    BAD_CAST dtd_location);

		if ((cvp = xmlNewValidCtxt()) == NULL) {
			xmlFreeDoc(info.ktx_doc);
			pool_seterror(POE_DATASTORE);
			return (PO_FAIL);
		}
		/*
		 * Call xmlValidateDocument() to force the parsing of
		 * the DTD. Ignore errors and warning messages as we
		 * know the document isn't valid.
		 */
		(void) xmlValidateDocument(cvp, info.ktx_doc);
		xmlFreeValidCtxt(cvp);
		if ((info.ktx_node = node_create(NULL, BAD_CAST "system")) ==
		    NULL) {
			xmlFreeDoc(info.ktx_doc);
			pool_seterror(POE_DATASTORE);
			return (PO_FAIL);
		}

		system = info.ktx_node;
		info.ktx_doc->_private = (void *)conf;

		(void) xmlDocSetRootElement(info.ktx_doc, info.ktx_node);
		(void) xmlSetProp(info.ktx_node, BAD_CAST c_ref_id,
		    BAD_CAST "dummy");
		if ((node_comment = xmlNewDocComment(info.ktx_doc,
		    BAD_CAST "\nConfiguration for pools facility. Do NOT"
		    " edit this file by hand - use poolcfg(1)"
		    " or libpool(3POOL) instead.\n")) == NULL) {
			xmlFreeDoc(info.ktx_doc);
			pool_seterror(POE_DATASTORE);
			return (PO_FAIL);
		}
		if (xmlAddPrevSibling(info.ktx_node, node_comment) == NULL) {
			xmlFree(node_comment);
			xmlFreeDoc(info.ktx_doc);
			pool_seterror(POE_DATASTORE);
			return (PO_FAIL);
		}
		if (pool_walk_any_properties((pool_conf_t *)conf,
		    pool_conf_to_elem(conf), &info, prop_build_cb, 1) ==
		    PO_FAIL) {
			xmlFreeDoc(info.ktx_doc);
			return (PO_FAIL);
		}
		if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL) {
			xmlFreeDoc(info.ktx_doc);
			return (PO_FAIL);
		}
		/*
		 * Now add pool details
		 */
		if ((ps = pool_query_pools(conf, &nelem, NULL)) != NULL) {
			for (i = 0; i < nelem; i++) {
				pool_elem_t *elem = TO_ELEM(ps[i]);
				uint_t nreselem;
				const char *sep = "";
				int j;

				if (elem_is_tmp(elem))
					continue;

				if ((info.ktx_node = node_create(system,
				    BAD_CAST element_class_tags
				    [pool_elem_class(elem)])) == NULL) {
					free(ps);
					free_char_buf(cb);
					xmlFreeDoc(info.ktx_doc);
					pool_seterror(POE_DATASTORE);
					return (PO_FAIL);
				}
				if (pool_walk_any_properties(
				    (pool_conf_t *)conf,
				    elem, &info, prop_build_cb, 1) == PO_FAIL) {
					free(ps);
					free_char_buf(cb);
					xmlFreeDoc(info.ktx_doc);
					return (PO_FAIL);
				}
				/*
				 * TODO: pset specific res manipulation
				 */
				if ((rs = pool_query_pool_resources(conf, ps[i],
				    &nreselem, NULL)) == NULL) {
					free(ps);
					free_char_buf(cb);
					xmlFreeDoc(info.ktx_doc);
					pool_seterror(POE_INVALID_CONF);
					return (PO_FAIL);
				}
				if (set_char_buf(cb, "") == PO_FAIL) {
					free(rs);
					free(ps);
					free_char_buf(cb);
					xmlFreeDoc(info.ktx_doc);
					return (PO_FAIL);
				}
				for (j = 0; j < nreselem; j++) {
					pool_elem_t *reselem = TO_ELEM(rs[j]);
					if (append_char_buf(cb, "%s%s_%d", sep,
					    pool_elem_class_string(reselem),
					    (int)elem_get_sysid(reselem)) ==
					    PO_FAIL) {
						free(rs);
						free(ps);
						free_char_buf(cb);
						xmlFreeDoc(info.ktx_doc);
						return (PO_FAIL);
					}
					sep = " ";
				}
				free(rs);
				(void) xmlSetProp(info.ktx_node, BAD_CAST "res",
				    BAD_CAST cb->cb_buf);
				if (set_char_buf(cb, "%s_%d",
				    pool_elem_class_string(elem),
				    (int)elem_get_sysid(elem)) == PO_FAIL) {
					free(ps);
					free_char_buf(cb);
					xmlFreeDoc(info.ktx_doc);
					return (PO_FAIL);
				}
				(void) xmlSetProp(info.ktx_node,
				    BAD_CAST c_ref_id,
				    BAD_CAST  cb->cb_buf);
			}
			free(ps);
		}
		/*
		 * Now add resource details (including components)
		 */
		if ((rs = pool_query_resources(conf, &nelem, NULL)) != NULL) {
			for (i = 0; i < nelem; i++) {
				pool_elem_t *elem = TO_ELEM(rs[i]);
				pool_component_t **cs = NULL;
				uint_t ncompelem;
				int j;

				if (elem_is_tmp(elem))
					continue;

				if ((info.ktx_node = node_create(system,
				    BAD_CAST element_class_tags
				    [pool_elem_class(elem)])) == NULL) {
					free(rs);
					free_char_buf(cb);
					xmlFreeDoc(info.ktx_doc);
					pool_seterror(POE_DATASTORE);
					return (PO_FAIL);
				}
				if (pool_walk_any_properties(
				    (pool_conf_t *)conf,
				    elem, &info, prop_build_cb, 1) == PO_FAIL) {
					free(rs);
					free_char_buf(cb);
					xmlFreeDoc(info.ktx_doc);
					return (PO_FAIL);
				}
				if (set_char_buf(cb, "%s_%d",
				    pool_elem_class_string(elem),
				    (int)elem_get_sysid(elem)) == PO_FAIL) {
					free(rs);
					free_char_buf(cb);
					xmlFreeDoc(info.ktx_doc);
					return (PO_FAIL);
				}
				(void) xmlSetProp(info.ktx_node,
				    BAD_CAST c_ref_id,
				    BAD_CAST  cb->cb_buf);
				if ((cs = pool_query_resource_components(conf,
				    rs[i], &ncompelem, NULL)) != NULL) {
					xmlNodePtr resource = info.ktx_node;

					for (j = 0; j < ncompelem; j++) {
						pool_elem_t *compelem =
						    TO_ELEM(cs[j]);
						if ((info.ktx_node =
						    node_create(resource,
						    BAD_CAST element_class_tags
						    [pool_elem_class(
						    compelem)])) == NULL) {
							pool_seterror(
							    POE_DATASTORE);
							free(rs);
							free(cs);
							free_char_buf(cb);
							xmlFreeDoc(info.
							    ktx_doc);
							return (PO_FAIL);
						}
						if (pool_walk_any_properties(
						    (pool_conf_t *)conf,
						    compelem, &info,
						    prop_build_cb, 1) ==
						    PO_FAIL) {
							free(rs);
							free(cs);
							free_char_buf(cb);
							xmlFreeDoc(info.
							    ktx_doc);
							return (PO_FAIL);
						}
						if (set_char_buf(cb, "%s_%d",
						    pool_elem_class_string(
						    compelem),
						    (int)elem_get_sysid(
						    compelem)) == PO_FAIL) {
							free(rs);
							free(cs);
							free_char_buf(cb);
							xmlFreeDoc(info.
							    ktx_doc);
							return (PO_FAIL);
						}
						(void) xmlSetProp(info.ktx_node,
						    BAD_CAST c_ref_id,
						    BAD_CAST  cb->cb_buf);
					}
					free(cs);
				}
			}
			free(rs);
		}
		free_char_buf(cb);
		/*
		 * Set up the message handlers prior to calling
		 * xmlValidateDocument()
		 */
		if ((cvp = xmlNewValidCtxt()) == NULL) {
			xmlFreeDoc(info.ktx_doc);
			pool_seterror(POE_DATASTORE);
			return (PO_FAIL);
		}
		cvp->error    = pool_error_func;
		cvp->warning  = pool_error_func;
		if (xmlValidateDocument(cvp, info.ktx_doc) == 0) {
			xmlFreeValidCtxt(cvp);
			xmlFreeDoc(info.ktx_doc);
			pool_seterror(POE_INVALID_CONF);
			return (PO_FAIL);
		}
		xmlFreeValidCtxt(cvp);
		ret = xmlSaveFormatFile(location, info.ktx_doc, 1);
		xmlFreeDoc(info.ktx_doc);
		if (ret == -1) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		return (PO_SUCCESS);
	default:
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
}

/*
 * Rollback the changes to the kernel
 */
int
pool_knl_recover(pool_conf_t *conf)
{
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;

	prov->pkc_log->l_state = LS_RECOVER;
	if (log_reverse_walk(prov->pkc_log, log_item_undo) != PO_SUCCESS) {
		dprintf("Library configuration consistency error\n");
		prov->pkc_log->l_state = LS_FAIL;
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	prov->pkc_log->l_state = LS_DO;
	return (PO_SUCCESS);
}

/*
 * Rollback the changes to the configuration
 */
int
pool_knl_rollback(pool_conf_t *conf)
{
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;

	prov->pkc_log->l_state = LS_UNDO;
	if (log_reverse_walk(prov->pkc_log, log_item_undo) != PO_SUCCESS) {
		dprintf("Kernel configuration consistency error\n");
		(void) log_walk(prov->pkc_log, log_item_release);
		log_empty(prov->pkc_log);
		prov->pkc_log->l_state = LS_FAIL;
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	(void) log_walk(prov->pkc_log, log_item_release);
	log_empty(prov->pkc_log);
	prov->pkc_log->l_state = LS_DO;
	return (PO_SUCCESS);
}

/*
 * Callback used to build the result set for a query. Each invocation will
 * supply a candidate element for inclusion. The element is filtered by:
 * - class
 * - properties
 * If the element "matches" the target, then it is added to the result
 * set, otherwise it is ignored.
 */
/* ARGSUSED1 */
static void
build_result_set(const void *key, void **value, void *cl)
{
	struct query_obj *qo = (struct query_obj *)cl;
	pool_knl_elem_t *pke = (pool_knl_elem_t *)key;

	/*
	 * Check to see if it's the right class of element
	 */
	if (qo->classes & (1 << pool_elem_class((pool_elem_t *)key))) {
		int i;
		/*
		 * Now check to see if the src element is correct. If no src
		 * element is supplied, ignore this check
		 */
		if (qo->src) {
			pool_knl_elem_t *parent;

			for (parent = pke; parent != NULL;
			    parent = parent->pke_parent) {
				if (parent == (pool_knl_elem_t *)qo->src)
					break;
			}
			if (parent == NULL)
				return;
		}
		/*
		 * Now check for property matches (if there are any specified)
		 */
		if (qo->props) {
			int matched = PO_TRUE;
			for (i = 0; qo->props[i] != NULL; i++) {
				pool_value_t val = POOL_VALUE_INITIALIZER;

				if (pool_get_property(TO_CONF(TO_ELEM(pke)),
				    (pool_elem_t *)pke,
				    pool_value_get_name(qo->props[i]), &val) ==
				    POC_INVAL) {
					matched = PO_FALSE;
					break;
				} else {
					if (pool_value_equal(qo->props[i],
					    &val) != PO_TRUE) {
						matched = PO_FALSE;
						break;
					}
				}
			}
			if (matched == PO_TRUE)
				(void) pool_knl_result_set_append(qo->rs,
				    (pool_knl_elem_t *)key);
		} else {
			(void) pool_knl_result_set_append(qo->rs,
			    (pool_knl_elem_t *)key);
		}
	}
}

/*
 * Execute the supplied query and return a result set which contains
 * all qualifying elements.
 */
pool_result_set_t *
pool_knl_exec_query(const pool_conf_t *conf, const pool_elem_t *src,
    const char *src_attr, pool_elem_class_t classes, pool_value_t **props)
{
	pool_knl_result_set_t *rs;
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;
	struct query_obj qo;
	int matched = PO_TRUE;

	/*
	 * Have a buffer at this point, that we can use
	 */
	if ((rs = pool_knl_result_set_alloc(conf)) == NULL) {
		return (NULL);
	}
	qo.conf = conf;
	qo.src = src;
	qo.src_attr = src_attr;
	qo.classes = classes;
	qo.props = props;
	qo.rs = rs;
	if (src_attr != NULL) {
		pool_knl_pool_t *pkp = (pool_knl_pool_t *)src;

		/*
		 * Note: This logic is resource specific and must be
		 * extended for additional resource types.
		 */
		/*
		 * Check for property matches (if there are any specified)
		 */
		if (props) {
			int i;

			for (i = 0; props[i] != NULL; i++) {
				pool_value_t val = POOL_VALUE_INITIALIZER;

				if (pool_get_property(conf,
				    (pool_elem_t *)pkp->pkp_assoc[PREC_PSET],
				    pool_value_get_name(props[i]), &val) ==
				    POC_INVAL) {
					matched = PO_FALSE;
					break;
				} else {
					if (pool_value_equal(props[i],
					    &val) != PO_TRUE) {
						matched = PO_FALSE;
						break;
					}
				}
			}
		}

		if (matched == PO_TRUE)
			(void) pool_knl_result_set_append(rs,
			    (pool_knl_elem_t *)pkp->pkp_assoc[PREC_PSET]);
	} else
		dict_map(prov->pkc_elements, build_result_set, &qo);

	if (rs->pkr_count == 0)
		pool_seterror(POE_INVALID_SEARCH);
	return ((pool_result_set_t *)rs);
}

/*
 * Callback function intended to be used from pool_walk_pools(). If
 * the supplied pool is not the default pool attempt to destroy it.
 */
/*ARGSUSED*/
static int
destroy_pool_cb(pool_conf_t *conf, pool_t *pool, void *unused)
{
	if (elem_is_default(TO_ELEM(pool)) != PO_TRUE)
		return (pool_destroy(conf, pool));
	/*
	 * Return PO_SUCCESS even though we don't delete the default
	 * pool so that the walk continues
	 */
	return (PO_SUCCESS);
}

/*
 * Remove the configuration details. This means remove all elements
 * apart from the system elements.
 */
int
pool_knl_remove(pool_conf_t *conf)
{
	uint_t i, nelem;
	pool_resource_t **resources;

	conf->pc_state = POF_DESTROY;
	if ((resources = pool_query_resources(conf, &nelem, NULL)) != NULL) {
		for (i = 0; i < nelem; i++) {
			if (resource_is_system(resources[i]) == PO_FALSE)
				if (pool_resource_destroy(conf, resources[i]) !=
				    PO_SUCCESS) {
					pool_seterror(POE_INVALID_CONF);
					return (PO_FAIL);
				}
		}
		free(resources);
	}
	(void) pool_walk_pools(conf, conf, destroy_pool_cb);
	if (pool_conf_commit(conf, PO_FALSE) != PO_SUCCESS)
		return (PO_FAIL);

	if (pool_conf_close(conf) != PO_SUCCESS)
		return (PO_FAIL);

	return (PO_SUCCESS);
}

/*
 * Determine the name of the pool to which the supplied pid is
 * bound. If it cannot be determined return NULL.
 */
char *
pool_knl_get_binding(pool_conf_t *conf, pid_t pid)
{
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;
	const char *sval;
	char *name = NULL;
	pool_bindq_t bindq;
	pool_value_t *props[] = { NULL, NULL };
	uint_t nelem = 0;
	pool_t **pools;
	pool_value_t val = POOL_VALUE_INITIALIZER;

	props[0] = &val;

	bindq.pb_o_id_type = P_PID;
	bindq.pb_o_id = pid;
	if (ioctl(prov->pkc_fd, POOL_BINDQ, &bindq) < 0) {
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}

	if (pool_value_set_name(props[0], "pool.sys_id") != PO_SUCCESS) {
		return (NULL);
	}
	pool_value_set_int64(props[0], bindq.pb_i_id);
	if ((pools = pool_query_pools(conf, &nelem, props)) == NULL) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	if (nelem != 1) {
		free(pools);
		pool_seterror(POE_INVALID_CONF);
		return (NULL);
	}
	if (pool_get_ns_property(TO_ELEM(pools[0]), c_name, props[0])
	    == POC_INVAL) {
		free(pools);
		return (NULL);
	}
	if (pool_value_get_string(props[0], &sval) != PO_SUCCESS) {
		free(pools);
		return (NULL);
	}
	if ((name = strdup(sval)) == NULL) {
		free(pools);
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	return (name);
}

/*
 * Bind idtype id to the pool name.
 */
int
pool_knl_set_binding(pool_conf_t *conf, const char *pool_name, idtype_t idtype,
    id_t id)
{
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;
	pool_bind_t bind;
	pool_t *pool;
	int ret;

	if ((pool = pool_get_pool(conf, pool_name)) == NULL)
		return (PO_FAIL);

	bind.pb_o_id_type = idtype;
	bind.pb_o_id = id;
	bind.pb_o_pool_id = elem_get_sysid(TO_ELEM(pool));

	while ((ret = ioctl(prov->pkc_fd, POOL_BIND, &bind)) < 0 &&
	    errno == EAGAIN)
		;
	if (ret < 0) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * pool_knl_get_resource_binding() returns the binding for a pid to
 * the supplied type of resource. If a binding cannot be determined,
 * NULL is returned.
 */
char *
pool_knl_get_resource_binding(pool_conf_t *conf,
    pool_resource_elem_class_t type, pid_t pid)
{
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;
	const char *sval;
	char *name = NULL;
	pool_bindq_t bindq;
	pool_value_t *props[] = { NULL, NULL };
	uint_t nelem = 0;
	pool_t **pools;
	pool_resource_t **resources;
	pool_value_t val = POOL_VALUE_INITIALIZER;

	props[0] = &val;
	bindq.pb_o_id_type = P_PID;
	bindq.pb_o_id = pid;
	if (ioctl(prov->pkc_fd, POOL_BINDQ, &bindq) < 0) {
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}

	if (pool_value_set_name(props[0], "pool.sys_id") != PO_SUCCESS) {
		return (NULL);
	}
	pool_value_set_int64(props[0], bindq.pb_i_id);
	if ((pools = pool_query_pools(conf, &nelem, props)) == NULL) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	if (nelem != 1) {
		free(pools);
		pool_seterror(POE_INVALID_CONF);
		return (NULL);
	}

	if (pool_value_set_string(props[0], pool_resource_type_string(type)) !=
	    PO_SUCCESS ||
	    pool_value_set_name(props[0], c_type) != PO_SUCCESS) {
		free(pools);
		return (NULL);
	}

	if ((resources = pool_query_pool_resources(conf, pools[0], &nelem,
	    NULL)) == NULL) {
		free(pools);
		pool_seterror(POE_INVALID_CONF);
		return (NULL);
	}
	free(pools);
	if (nelem != 1) {
		free(resources);
		pool_seterror(POE_INVALID_CONF);
		return (NULL);
	}
	if (pool_get_ns_property(TO_ELEM(resources[0]), c_name, props[0]) ==
	    POC_INVAL) {
		free(resources);
		return (NULL);
	}
	free(resources);
	if (pool_value_get_string(props[0], &sval) != PO_SUCCESS) {
		return (NULL);
	}
	if ((name = strdup(sval)) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	return (name);
}

/*
 * Allocate the required library data structure and initialise it.
 */
pool_knl_elem_t *
pool_knl_elem_wrap(pool_conf_t *conf, pool_elem_class_t class,
    pool_resource_elem_class_t res_class,
    pool_component_elem_class_t comp_class)
{
	pool_knl_elem_t *elem;
	pool_elem_t *pe;

	switch (class) {
	case PEC_SYSTEM:
		if ((elem = malloc(sizeof (pool_knl_system_t))) == NULL) {
			pool_seterror(POE_SYSTEM);
			return (NULL);
		}
		(void) memset(elem, 0, sizeof (pool_knl_system_t));
		break;
	case PEC_POOL:
		if ((elem = malloc(sizeof (pool_knl_pool_t))) == NULL) {
			pool_seterror(POE_SYSTEM);
			return (NULL);
		}
		(void) memset(elem, 0, sizeof (pool_knl_pool_t));
		break;
	case PEC_RES_COMP:
	case PEC_RES_AGG:
		if ((elem = malloc(sizeof (pool_knl_resource_t))) == NULL) {
			pool_seterror(POE_SYSTEM);
			return (NULL);
		}
		(void) memset(elem, 0, sizeof (pool_knl_resource_t));
		break;
	case PEC_COMP:
		if ((elem = malloc(sizeof (pool_knl_component_t))) == NULL) {
			pool_seterror(POE_SYSTEM);
			return (NULL);
		}
		(void) memset(elem, 0, sizeof (pool_knl_component_t));
		break;
	default:
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	pe = TO_ELEM(elem);
	pe->pe_conf = conf;
	pe->pe_class = class;
	pe->pe_resource_class = res_class;
	pe->pe_component_class = comp_class;
	/* Set up the function pointers for element manipulation */
	pe->pe_get_prop = pool_knl_get_property;
	pe->pe_put_prop = pool_knl_put_property;
	pe->pe_rm_prop = pool_knl_rm_property;
	pe->pe_get_props = pool_knl_get_properties;
	pe->pe_remove = pool_knl_elem_remove;
	pe->pe_get_container = pool_knl_get_container;
	pe->pe_set_container = pool_knl_set_container;
	/*
	 * Specific initialisation for different types of element
	 */
	if (class == PEC_POOL) {
		pool_knl_pool_t *pp = (pool_knl_pool_t *)elem;
		pp->pp_associate = pool_knl_pool_associate;
		pp->pp_dissociate = pool_knl_pool_dissociate;
		pp->pkp_assoc[PREC_PSET] = (pool_knl_resource_t *)
		    resource_by_sysid(conf, PS_NONE, "pset");
	}
	if (class == PEC_RES_COMP || class == PEC_RES_AGG) {
		pool_knl_resource_t *pr = (pool_knl_resource_t *)elem;
		pr->pr_is_system = pool_knl_resource_is_system;
		pr->pr_can_associate = pool_knl_resource_can_associate;
	}
#if DEBUG
	if (dict_put(((pool_knl_connection_t *)conf->pc_prov)->pkc_leaks,
	    elem, elem) != NULL)
		assert(!"leak map put failed");
	dprintf("allocated %p\n", elem);
#endif	/* DEBUG */
	return (elem);
}

/*
 * Allocate a new pool_knl_elem_t in the supplied configuration of the
 * specified class.
 * Returns element pointer/NULL
 */
pool_elem_t *
pool_knl_elem_create(pool_conf_t *conf, pool_elem_class_t class,
    pool_resource_elem_class_t res_class,
    pool_component_elem_class_t comp_class)
{
	pool_knl_elem_t *elem;
	pool_create_undo_t *create;
	pool_knl_connection_t *prov = (pool_knl_connection_t *)conf->pc_prov;
	static int id = -3;
	char_buf_t *cb;

	if ((elem = pool_knl_elem_wrap(conf, class, res_class, comp_class)) ==
	    NULL)
		return (NULL);

	/*
	 * Allocate an nvlist to hold properties
	 */
	if (nvlist_alloc(&elem->pke_properties, NV_UNIQUE_NAME_TYPE, 0) != 0) {
		pool_knl_elem_free(elem, PO_FALSE);
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	/*
	 * Allocate a temporary ID and name until the element is
	 * created for real
	 */
	if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL) {
		pool_knl_elem_free(elem, PO_TRUE);
		return (NULL);
	}
	if (set_char_buf(cb, "%s.sys_id",
	    pool_elem_class_string((pool_elem_t *)elem)) != PO_SUCCESS) {
		pool_knl_elem_free(elem, PO_TRUE);
		free_char_buf(cb);
		return (NULL);
	}
	(void) nvlist_add_int64(elem->pke_properties, cb->cb_buf, id--);
	if (set_char_buf(cb, "%s.name",
	    pool_elem_class_string((pool_elem_t *)elem)) != PO_SUCCESS) {
		pool_knl_elem_free(elem, PO_TRUE);
		free_char_buf(cb);
		return (NULL);
	}
	(void) nvlist_add_string(elem->pke_properties, cb->cb_buf, "");
	/*
	 * If it's a resource class, it will need an initial size
	 */
	if (class == PEC_RES_COMP || class == PEC_RES_AGG) {
		if (set_char_buf(cb, "%s.size",
		    pool_elem_class_string((pool_elem_t *)elem)) !=
		    PO_SUCCESS) {
			pool_knl_elem_free(elem, PO_TRUE);
			free_char_buf(cb);
			return (NULL);
		}
		(void) nvlist_add_uint64(elem->pke_properties, cb->cb_buf, 0);
	}
	free_char_buf(cb);

	/*
	 * Register the newly created element
	 */
	if (dict_put(prov->pkc_elements, elem, elem) != NULL) {
		pool_knl_elem_free(elem, PO_TRUE);
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}

	if (prov->pkc_log->l_state != LS_DO)
		return ((pool_elem_t *)elem);

	/*
	 * The remaining logic is setting up the arguments for the
	 * POOL_CREATE ioctl and appending the details into the log.
	 */
	if ((create = malloc(sizeof (pool_create_undo_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	create->pcu_ioctl.pc_o_type = class;
	switch (class) {
	case PEC_SYSTEM:
		pool_seterror(POE_BADPARAM);
		free(create);
		return (NULL);
	case PEC_POOL: /* NO-OP */
		break;
	case PEC_RES_COMP:
	case PEC_RES_AGG:
		create->pcu_ioctl.pc_o_sub_type = res_class;
		break;
	case PEC_COMP:
		create->pcu_ioctl.pc_o_sub_type = comp_class;
		break;
	default:
		pool_seterror(POE_BADPARAM);
		free(create);
		return (NULL);
	}

	create->pcu_elem = (pool_elem_t *)elem;

	if (log_append(prov->pkc_log, POOL_CREATE, (void *)create) !=
	    PO_SUCCESS) {
		free(create);
		return (NULL);
	}
	return ((pool_elem_t *)elem);
}

/*
 * Remove the details of the element from our userland copy and destroy
 * the element (if appropriate) in the kernel.
 */
int
pool_knl_elem_remove(pool_elem_t *pe)
{
	pool_knl_connection_t *prov;
	pool_destroy_undo_t *destroy;

	prov = (pool_knl_connection_t *)(TO_CONF(pe))->pc_prov;

	if (dict_remove(prov->pkc_elements, pe) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	if (prov->pkc_log->l_state != LS_DO) {
		return (PO_SUCCESS);
	}

	/*
	 * The remaining logic is setting up the arguments for the
	 * POOL_DESTROY ioctl and appending the details into the log.
	 */
	if ((destroy = malloc(sizeof (pool_destroy_undo_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	destroy->pdu_ioctl.pd_o_type = pool_elem_class(pe);

	if (destroy->pdu_ioctl.pd_o_type == PEC_RES_COMP ||
	    destroy->pdu_ioctl.pd_o_type == PEC_RES_AGG)
		destroy->pdu_ioctl.pd_o_sub_type = pool_resource_elem_class(pe);

	if (destroy->pdu_ioctl.pd_o_type == PEC_COMP)
		destroy->pdu_ioctl.pd_o_sub_type =
		    pool_component_elem_class(pe);

	destroy->pdu_elem = pe;

	if (log_append(prov->pkc_log, POOL_DESTROY, (void *)destroy) !=
	    PO_SUCCESS) {
		free(destroy);
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * Set the parent of the supplied child to the supplied parent
 */
int
pool_knl_set_container(pool_elem_t *pp, pool_elem_t *pc)
{
	pool_knl_elem_t *pkp = (pool_knl_elem_t *)pp;
	pool_knl_elem_t *pkc = (pool_knl_elem_t *)pc;

	pkc->pke_parent = pkp;
	return (PO_SUCCESS);
}

/*
 * TODO: Needed for msets and ssets.
 */
/* ARGSUSED */
int
pool_knl_res_transfer(pool_resource_t *src, pool_resource_t *tgt,
    uint64_t size) {
	return (PO_FAIL);
}

/*
 * Transfer resource components from one resource set to another.
 */
int
pool_knl_res_xtransfer(pool_resource_t *src, pool_resource_t *tgt,
    pool_component_t **rl) {
	pool_elem_t *src_e = TO_ELEM(src);
	pool_elem_t *tgt_e = TO_ELEM(tgt);
	pool_xtransfer_undo_t *xtransfer;
	size_t size;
	pool_knl_connection_t *prov =
	    (pool_knl_connection_t *)TO_CONF(src_e)->pc_prov;

	if (prov->pkc_log->l_state != LS_DO) {
		/*
		 * Walk the Result Set and move the resource components
		 */
		for (size = 0; rl[size] != NULL; size++) {
			if (pool_set_container(TO_ELEM(tgt),
			    TO_ELEM(rl[size])) == PO_FAIL) {
				return (PO_FAIL);
			}
		}
		return (PO_SUCCESS);
	}

	/*
	 * The remaining logic is setting up the arguments for the
	 * POOL_XTRANSFER ioctl and appending the details into the log.
	 */
	if ((xtransfer = malloc(sizeof (pool_xtransfer_undo_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}

	if (pool_elem_class(src_e) == PEC_RES_COMP) {
		xtransfer->pxu_ioctl.px_o_id_type =
		    pool_resource_elem_class(src_e);
	} else {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}


	for (xtransfer->pxu_ioctl.px_o_complist_size = 0;
	    rl[xtransfer->pxu_ioctl.px_o_complist_size] != NULL;
	    xtransfer->pxu_ioctl.px_o_complist_size++)
		/* calculate the size using the terminating NULL */;
	if ((xtransfer->pxu_ioctl.px_o_comp_list =
		calloc(xtransfer->pxu_ioctl.px_o_complist_size,
		sizeof (id_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	if ((xtransfer->pxu_rl = calloc(
	    xtransfer->pxu_ioctl.px_o_complist_size + 1,
	    sizeof (pool_component_t *))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	(void) memcpy(xtransfer->pxu_rl, rl,
	    xtransfer->pxu_ioctl.px_o_complist_size *
	    sizeof (pool_component_t *));
	xtransfer->pxu_src = src_e;
	xtransfer->pxu_tgt = tgt_e;

	if (log_append(prov->pkc_log, POOL_XTRANSFER, (void *)xtransfer) !=
	    PO_SUCCESS) {
		free(xtransfer);
		return (PO_FAIL);
	}
	for (size = 0; rl[size] != NULL; size++) {
		if (pool_set_container(TO_ELEM(tgt), TO_ELEM(rl[size])) ==
		    PO_FAIL) {
			return (PO_FAIL);
		}
	}
	return (PO_SUCCESS);
}

/*
 * Return the parent of an element.
 */
pool_elem_t *
pool_knl_get_container(const pool_elem_t *pe)
{
	pool_knl_elem_t *pke = (pool_knl_elem_t *)pe;

	return ((pool_elem_t *)pke->pke_parent);
}

/*
 * Note: This function is resource specific, needs extending for other
 * resource types
 */
int
pool_knl_resource_is_system(const pool_resource_t *pr)
{
	switch (pool_resource_elem_class(TO_ELEM(pr))) {
	case PREC_PSET:
		return (PSID_IS_SYSSET(
		    elem_get_sysid(TO_ELEM(pr))));
	default:
		return (PO_FALSE);
	}
}

/*
 * Note: This function is resource specific, needs extending for other
 * resource types
 */
int
pool_knl_resource_can_associate(const pool_resource_t *pr)
{
	switch (pool_resource_elem_class(TO_ELEM(pr))) {
	case PREC_PSET:
		return (PO_TRUE);
	default:
		return (PO_FALSE);
	}
}

/*
 * pool_knl_pool_associate() associates the supplied resource to the
 * supplied pool.
 *
 * Returns: PO_SUCCESS/PO_FAIL
 */
int
pool_knl_pool_associate(pool_t *pool, const pool_resource_t *resource)
{
	pool_knl_connection_t *prov;
	pool_knl_pool_t *pkp = (pool_knl_pool_t *)pool;
	pool_resource_elem_class_t res_class =
	    pool_resource_elem_class(TO_ELEM(resource));
	pool_assoc_undo_t *assoc;
	pool_knl_resource_t *orig_res = pkp->pkp_assoc[res_class];

	/*
	 * Are we allowed to associate with this target?
	 */
	if (pool_knl_resource_can_associate(resource) == PO_FALSE) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	prov = (pool_knl_connection_t *)(TO_CONF(TO_ELEM(pool)))->pc_prov;

	if (prov->pkc_log->l_state != LS_DO) {
		pkp->pkp_assoc[res_class] = (pool_knl_resource_t *)resource;
		return (PO_SUCCESS);
	}

	/*
	 * The remaining logic is setting up the arguments for the
	 * POOL_ASSOC ioctl and appending the details into the log.
	 */
	if ((assoc = malloc(sizeof (pool_assoc_undo_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	assoc->pau_assoc = TO_ELEM(pool);
	assoc->pau_oldres = (pool_elem_t *)orig_res;
	assoc->pau_newres = TO_ELEM(resource);

	assoc->pau_ioctl.pa_o_id_type = res_class;

	if (log_append(prov->pkc_log, POOL_ASSOC, (void *)assoc) !=
	    PO_SUCCESS) {
		free(assoc);
		pkp->pkp_assoc[res_class] = orig_res;
		return (PO_FAIL);
	}
	pkp->pkp_assoc[res_class] = (pool_knl_resource_t *)resource;
	return (PO_SUCCESS);
}

/*
 * pool_knl_pool_dissociate() dissociates the supplied resource from
 * the supplied pool.
 *
 * Returns: PO_SUCCESS/PO_FAIL
 */
int
pool_knl_pool_dissociate(pool_t *pool, const pool_resource_t *resource)
{
	pool_knl_connection_t *prov;
	pool_dissoc_undo_t *dissoc;
	pool_knl_pool_t *pkp = (pool_knl_pool_t *)pool;
	pool_resource_t *default_res = (pool_resource_t *)get_default_resource(
	    resource);
	pool_resource_elem_class_t res_class =
	    pool_resource_elem_class(TO_ELEM(resource));

	prov = (pool_knl_connection_t *)(TO_CONF(TO_ELEM(pool)))->pc_prov;

	if (prov->pkc_log->l_state != LS_DO) {
		pkp->pkp_assoc[res_class] = (pool_knl_resource_t *)default_res;
		return (PO_SUCCESS);
	}
	/*
	 * The remaining logic is setting up the arguments for the
	 * POOL_DISSOC ioctl and appending the details into the log.
	 */
	if ((dissoc = malloc(sizeof (pool_dissoc_undo_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	dissoc->pdu_dissoc = TO_ELEM(pool);
	dissoc->pdu_oldres = TO_ELEM(resource);
	dissoc->pdu_newres = TO_ELEM(default_res);

	dissoc->pdu_ioctl.pd_o_id_type = res_class;

	if (log_append(prov->pkc_log, POOL_DISSOC, (void *)dissoc) !=
	    PO_SUCCESS) {
		free(dissoc);
		pkp->pkp_assoc[res_class] = (pool_knl_resource_t *)resource;
		return (PO_FAIL);
	}

	/*
	 * Update our local copy
	 */
	pkp->pkp_assoc[res_class] = (pool_knl_resource_t *)default_res;
	return (PO_SUCCESS);
}

/*
 * Allocate a data provider for the supplied configuration and optionally
 * discover resources.
 * The data provider is the cross over point from the "abstract" configuration
 * functions into the data representation specific manipulation routines.
 * This function sets up all the required pointers to create a kernel aware
 * data provider.
 * Returns PO_SUCCESS/PO_FAIL
 */
int
pool_knl_connection_alloc(pool_conf_t *conf, int oflags)
{
	pool_knl_connection_t *prov;

	if ((prov = malloc(sizeof (pool_knl_connection_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	(void) memset(prov, 0, sizeof (pool_knl_connection_t));
	/*
	 * Initialise data members
	 */
	prov->pc_name = strdup("kernel");
	prov->pc_store_type = KERNEL_DATA_STORE;
	prov->pc_oflags = oflags;
	/*
	 * Initialise function pointers
	 */
	prov->pc_close = pool_knl_close;
	prov->pc_validate = pool_knl_validate;
	prov->pc_commit = pool_knl_commit;
	prov->pc_export = pool_knl_export;
	prov->pc_rollback = pool_knl_rollback;
	prov->pc_exec_query = pool_knl_exec_query;
	prov->pc_elem_create = pool_knl_elem_create;
	prov->pc_remove = pool_knl_remove;
	prov->pc_res_xfer = pool_knl_res_transfer;
	prov->pc_res_xxfer = pool_knl_res_xtransfer;
	prov->pc_get_binding = pool_knl_get_binding;
	prov->pc_set_binding = pool_knl_set_binding;
	prov->pc_get_resource_binding = pool_knl_get_resource_binding;
	/*
	 * Associate the provider to it's configuration
	 */
	conf->pc_prov = (pool_connection_t *)prov;
	/*
	 * End of common initialisation
	 */
	/*
	 * Attempt to open the pseudo device, if the configuration is opened
	 * readonly then try to open an info device, otherwise try to open
	 * the writeable device.
	 */
	if (oflags & PO_RDWR) {
		if ((prov->pkc_fd = blocking_open(pool_dynamic_location(),
		    O_RDWR)) < 0) {
			free(prov);
			conf->pc_prov = NULL;
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
	} else {
		if ((prov->pkc_fd = open(pool_info_location, O_RDWR)) < 0) {
			free(prov);
			conf->pc_prov = NULL;
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
	}
	/*
	 * Allocate the element dictionary
	 */
	if ((prov->pkc_elements = dict_new((int (*)(const void *, const void *))
	    pool_elem_compare, (uint64_t (*)(const void *))hash_id)) == NULL) {
		(void) close(prov->pkc_fd);
		free(prov);
		conf->pc_prov = NULL;
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
#if DEBUG
	if ((prov->pkc_leaks = dict_new(NULL, NULL)) == NULL) {
		dict_free(&prov->pkc_elements);
		(void) close(prov->pkc_fd);
		free(prov);
		conf->pc_prov = NULL;
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
#endif	/* DEBUG */
	/*
	 * Allocate the transaction log
	 */
	if ((prov->pkc_log = log_alloc(conf)) == NULL) {
#if DEBUG
		dict_free(&prov->pkc_leaks);
#endif	/* DEBUG */
		dict_free(&prov->pkc_elements);
		(void) close(prov->pkc_fd);
		free(prov);
		conf->pc_prov = NULL;
		return (PO_FAIL);
	}
	/*
	 * At this point the configuration provider has been initialized,
	 * mark the configuration as valid so that the various routines
	 * which rely on a valid configuration will work correctly.
	 */
	conf->pc_state = POF_VALID;
	/*
	 * Update the library snapshot from the kernel
	 */
	if (pool_knl_update(conf, NULL) != PO_SUCCESS) {
#if DEBUG
		dict_free(&prov->pkc_leaks);
#endif	/* DEBUG */
		dict_free(&prov->pkc_elements);
		(void) close(prov->pkc_fd);
		free(prov);
		conf->pc_prov = NULL;
		conf->pc_state = POF_INVALID;
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

#if DEBUG
static void
pool_knl_elem_printf_cb(const void *key, void **value, void *cl)
{
	pool_knl_elem_t *pke = (pool_knl_elem_t *)key;
	dict_hdl_t *map = (dict_hdl_t *)cl;

	dprintf("leak elem:%p\n", pke);
	if (pke->pke_properties != NULL) {
		nvlist_print(stdout, pke->pke_properties);
	} else
		dprintf("no properties\n");
	assert(dict_get(map, pke) == NULL);
}
#endif	/* DEBUG */
/*
 * pool_knl_elem_free() releases the resources associated with the
 * supplied element.
 */
static void
pool_knl_elem_free(pool_knl_elem_t *pke, int freeprop)
{
#if DEBUG
	pool_conf_t *conf = TO_CONF(TO_ELEM(pke));
	if (dict_remove(((pool_knl_connection_t *)conf->pc_prov)->pkc_leaks,
	    pke) == NULL)
		dprintf("%p, wasn't in the leak map\n", pke);
	if (freeprop == PO_TRUE) {
		pool_elem_dprintf(TO_ELEM(pke));
	}
	dprintf("released %p\n", pke);
#endif	/* DEBUG */
	if (freeprop == PO_TRUE) {
		nvlist_free(pke->pke_properties);
	}
	free(pke);
}

/*
 * pool_knl_elem_free_cb() is designed to be used with
 * dict_map(). When a connection is freed, this function is used to
 * free all element resources.
 */
/* ARGSUSED1 */
static void
pool_knl_elem_free_cb(const void *key, void **value, void *cl)
{
	pool_knl_elem_t *pke = (pool_knl_elem_t *)key;

#ifdef DEBUG
	dprintf("pool_knl_elem_free_cb:\n");
	dprintf("about to release %p ", pke);
	pool_elem_dprintf(TO_ELEM(pke));
#endif	/* DEBUG */
	pool_knl_elem_free(pke, PO_TRUE);
}

/*
 * Free the resources for a kernel data provider.
 */
void
pool_knl_connection_free(pool_knl_connection_t *prov)
{
	if (prov->pkc_log != NULL) {
		(void) log_walk(prov->pkc_log, log_item_release);
		log_free(prov->pkc_log);
	}
	if (prov->pkc_elements != NULL) {
		dict_map(prov->pkc_elements, pool_knl_elem_free_cb, NULL);
#if DEBUG
		dprintf("dict length is %llu\n", dict_length(prov->pkc_leaks));
		dict_map(prov->pkc_leaks, pool_knl_elem_printf_cb,
		    prov->pkc_elements);
		assert(dict_length(prov->pkc_leaks) == 0);
		dict_free(&prov->pkc_leaks);
#endif	/* DEBUG */
		dict_free(&prov->pkc_elements);
	}
	free((void *)prov->pc_name);
	free(prov);
}

/*
 * Return the specified property value.
 *
 * POC_INVAL is returned if an error is detected and the error code is updated
 * to indicate the cause of the error.
 */
pool_value_class_t
pool_knl_get_property(const pool_elem_t *pe, const char *name,
    pool_value_t *val)
{
	pool_knl_elem_t *pke = (pool_knl_elem_t *)pe;
	nvpair_t *pair;
	const pool_prop_t *prop;

	if ((prop = provider_get_prop(pe, name)) != NULL)
		if (prop_is_stored(prop) == PO_FALSE)
			return (pool_knl_get_dynamic_property(pe, name, val));

	if ((pair = pool_knl_find_nvpair(pke->pke_properties, name)) == NULL) {
		pool_seterror(POE_BADPARAM);
		return (POC_INVAL);
	}

	if (pool_value_from_nvpair(val, pair) == PO_FAIL) {
		return (POC_INVAL);
	}

	return (pool_value_get_type(val));
}

/*
 * Return the specified property value.
 *
 * If a property is designated as dynamic, then this function will
 * always try to return the latest value of the property from the
 * kernel.
 *
 * POC_INVAL is returned if an error is detected and the error code is updated
 * to indicate the cause of the error.
 */
pool_value_class_t
pool_knl_get_dynamic_property(const pool_elem_t *pe, const char *name,
    pool_value_t *val)
{
	pool_knl_connection_t *prov;
	pool_propget_t propget = { 0 };
	nvlist_t *proplist;
	nvpair_t *pair;

	propget.pp_o_id_type = pool_elem_class(pe);
	if (pool_elem_class(pe) == PEC_RES_COMP ||
	    pool_elem_class(pe) == PEC_RES_AGG)
		propget.pp_o_id_subtype = pool_resource_elem_class(pe);
	if (pool_elem_class(pe) == PEC_COMP)
		propget.pp_o_id_subtype =
		    (pool_resource_elem_class_t)pool_component_elem_class(pe);

	propget.pp_o_id = elem_get_sysid(pe);
	propget.pp_o_prop_name_size = strlen(name);
	propget.pp_o_prop_name = (char *)name;
	propget.pp_i_bufsize = KERNEL_SNAPSHOT_BUF_SZ;
	propget.pp_i_buf = malloc(KERNEL_SNAPSHOT_BUF_SZ);
	bzero(propget.pp_i_buf, KERNEL_SNAPSHOT_BUF_SZ);

	prov = (pool_knl_connection_t *)(TO_CONF(pe))->pc_prov;
	if (ioctl(prov->pkc_fd, POOL_PROPGET, &propget) < 0) {
		free(propget.pp_i_buf);
		pool_seterror(POE_SYSTEM);
		return (POC_INVAL);
	}
	if (nvlist_unpack(propget.pp_i_buf, propget.pp_i_bufsize,
	    &proplist, 0) != 0) {
		free(propget.pp_i_buf);
		pool_seterror(POE_SYSTEM);
		return (POC_INVAL);
	}
	free(propget.pp_i_buf);

	if ((pair = nvlist_next_nvpair(proplist, NULL)) == NULL) {
		nvlist_free(proplist);
		pool_seterror(POE_SYSTEM);
		return (POC_INVAL);
	}

	if (pool_value_from_nvpair(val, pair) == PO_FAIL) {
		nvlist_free(proplist);
		return (POC_INVAL);
	}
	nvlist_free(proplist);
	return (pool_value_get_type(val));
}

/*
 * Update the specified property value.
 *
 * PO_FAIL is returned if an error is detected and the error code is updated
 * to indicate the cause of the error.
 */
int
pool_knl_put_property(pool_elem_t *pe, const char *name,
    const pool_value_t *val)
{
	pool_knl_elem_t *pke = (pool_knl_elem_t *)pe;
	pool_knl_connection_t *prov =
	    (pool_knl_connection_t *)(TO_CONF(pe))->pc_prov;
	nvpair_t *bp, *ap;
	pool_propput_undo_t *propput;
	nvlist_t *bl = NULL;
	const pool_prop_t *prop;

	if ((bp = pool_knl_find_nvpair(pke->pke_properties, name)) != NULL) {
		if (nvlist_alloc(&bl, NV_UNIQUE_NAME_TYPE, 0) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		if (nvlist_add_nvpair(bl, bp) != 0) {
			nvlist_free(bl);
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
	}
	if (pool_knl_nvlist_add_value(pke->pke_properties, name, val) !=
	    PO_SUCCESS)
		return (PO_FAIL);

	if (prov->pkc_log->l_state != LS_DO) {
		nvlist_free(bl);
		return (PO_SUCCESS);
	}
	/*
	 * The remaining logic is setting up the arguments for the
	 * POOL_PROPPUT ioctl and appending the details into the log.
	 */
	if ((propput = malloc(sizeof (pool_propput_undo_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	(void) memset(propput, 0, sizeof (pool_propput_undo_t));
	propput->ppu_blist = bl;

	ap = pool_knl_find_nvpair(pke->pke_properties, name);

	if (nvlist_alloc(&propput->ppu_alist, NV_UNIQUE_NAME_TYPE, 0) != 0) {
		nvlist_free(propput->ppu_blist);
		free(propput);
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	if (nvlist_add_nvpair(propput->ppu_alist, ap) != 0) {
		nvlist_free(propput->ppu_blist);
		nvlist_free(propput->ppu_alist);
		free(propput);
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}

	if (nvlist_pack(propput->ppu_alist,
	    (char **)&propput->ppu_ioctl.pp_o_buf,
	    &propput->ppu_ioctl.pp_o_bufsize, NV_ENCODE_NATIVE, 0) != 0) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	nvlist_free(propput->ppu_alist);
	propput->ppu_ioctl.pp_o_id_type = pool_elem_class(pe);
	if (pool_elem_class(pe) == PEC_RES_COMP ||
	    pool_elem_class(pe) == PEC_RES_AGG)
		propput->ppu_ioctl.pp_o_id_sub_type =
		    pool_resource_elem_class(pe);
	if (pool_elem_class(pe) == PEC_COMP)
		propput->ppu_ioctl.pp_o_id_sub_type =
		    (pool_resource_elem_class_t)pool_component_elem_class(pe);

	propput->ppu_elem = pe;
	if ((prop = provider_get_prop(propput->ppu_elem, name)) != NULL) {
		if (prop_is_readonly(prop) == PO_TRUE)
			propput->ppu_doioctl |= KERNEL_PROP_RDONLY;
	}

	if (log_append(prov->pkc_log, POOL_PROPPUT, (void *)propput) !=
	    PO_SUCCESS) {
		nvlist_free(propput->ppu_blist);
		free(propput);
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * Remove the specified property value.
 *
 * PO_FAIL is returned if an error is detected and the error code is
 * updated to indicate the cause of the error.
 */
int
pool_knl_rm_property(pool_elem_t *pe, const char *name)
{
	pool_knl_elem_t *pke = (pool_knl_elem_t *)pe;
	pool_knl_connection_t *prov =
	    (pool_knl_connection_t *)(TO_CONF(pe))->pc_prov;
	pool_proprm_undo_t *proprm;

	if (pool_knl_find_nvpair(pke->pke_properties, name) == NULL) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	if ((proprm = malloc(sizeof (pool_proprm_undo_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	(void) memset(proprm, 0, sizeof (pool_proprm_undo_t));
	proprm->pru_oldval.pv_class = POC_INVAL;
	(void) pool_get_property(TO_CONF(pe), pe, name, &proprm->pru_oldval);

	if (prov->pkc_log->l_state != LS_DO) {
		free(proprm);
		(void) nvlist_remove_all(pke->pke_properties, (char *)name);
		return (PO_SUCCESS);
	}
	/*
	 * The remaining logic is setting up the arguments for the
	 * POOL_PROPRM ioctl and appending the details into the log.
	 */

	proprm->pru_ioctl.pp_o_id_type = pool_elem_class(pe);
	if (pool_elem_class(pe) == PEC_RES_COMP ||
	    pool_elem_class(pe) == PEC_RES_AGG)
		proprm->pru_ioctl.pp_o_id_sub_type =
		    pool_resource_elem_class(pe);

	if (pool_elem_class(pe) == PEC_COMP)
		proprm->pru_ioctl.pp_o_id_sub_type =
		    (pool_resource_elem_class_t)pool_component_elem_class(pe);

	proprm->pru_ioctl.pp_o_prop_name_size = strlen(name);
	proprm->pru_ioctl.pp_o_prop_name =
	    (char *)pool_value_get_name(&proprm->pru_oldval);
	proprm->pru_elem = pe;

	if (log_append(prov->pkc_log, POOL_PROPRM, (void *)proprm) !=
	    PO_SUCCESS) {
		free(proprm);
		return (PO_FAIL);
	}

	(void) nvlist_remove_all(pke->pke_properties, (char *)name);
	return (PO_SUCCESS);
}

/*
 * Return a NULL terminated array of pool_value_t which represents all
 * of the properties stored for an element
 *
 * Return NULL on failure. It is the caller's responsibility to free
 * the returned array of values.
 */
pool_value_t **
pool_knl_get_properties(const pool_elem_t *pe, uint_t *nprops)
{
	nvpair_t *pair;
	pool_value_t **result;
	pool_knl_elem_t *pke = (pool_knl_elem_t *)pe;
	int i = 0;

	*nprops = 0;

	for (pair = nvlist_next_nvpair(pke->pke_properties, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(pke->pke_properties, pair))
		(*nprops)++;
	if ((result = calloc(*nprops + 1, sizeof (pool_value_t *))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	for (pair = nvlist_next_nvpair(pke->pke_properties, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(pke->pke_properties, pair), i++) {
		result[i] = pool_value_alloc();
		if (pool_value_from_nvpair(result[i], pair) == PO_FAIL) {
			while (i-- >= 0)
				pool_value_free(result[i]);
			free(result);
			return (NULL);
		}
	}
	return (result);
}

/*
 * Append an entry to a result set. Reallocate the array used to store
 * results if it's full.
 * Returns PO_SUCCESS/PO_FAIL
 */
int
pool_knl_result_set_append(pool_knl_result_set_t *rs, pool_knl_elem_t *pke)
{
	if (rs->pkr_count == rs->pkr_size)
		if (pool_knl_result_set_realloc(rs) != PO_SUCCESS)
			return (PO_FAIL);

	rs->pkr_list[rs->pkr_count++] = pke;

	return (PO_SUCCESS);
}

/*
 * Resize the array used to store results. A simple doubling strategy
 * is used.
 * Returns PO_SUCCESS/PO_FAIL
 */
int
pool_knl_result_set_realloc(pool_knl_result_set_t *rs)
{
	pool_knl_elem_t **old_list = rs->pkr_list;
	int new_size = rs->pkr_size * 2;

	if ((rs->pkr_list = realloc(rs->pkr_list,
	    new_size * sizeof (pool_knl_elem_t *))) == NULL) {
		rs->pkr_list = old_list;
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	rs->pkr_size = new_size;

	return (PO_SUCCESS);
}

/*
 * Allocate a result set. The Result Set stores the result of a query.
 * Returns pool_knl_result_set_t pointer/NULL
 */
pool_knl_result_set_t *
pool_knl_result_set_alloc(const pool_conf_t *conf)
{
	pool_knl_result_set_t *rs;

	if ((rs = malloc(sizeof (pool_knl_result_set_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	(void) memset(rs, 0, sizeof (pool_knl_result_set_t));
	rs->pkr_size = KERNEL_RS_INITIAL_SZ;
	if (pool_knl_result_set_realloc(rs) == PO_FAIL) {
		free(rs);
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	rs->prs_conf = conf;
	rs->prs_index = -1;
	rs->prs_active = PO_TRUE;
	/* Fix up the result set accessor functions to the knl specfic ones */
	rs->prs_next = pool_knl_rs_next;
	rs->prs_prev = pool_knl_rs_prev;
	rs->prs_first = pool_knl_rs_first;
	rs->prs_last = pool_knl_rs_last;
	rs->prs_get_index = pool_knl_rs_get_index;
	rs->prs_set_index = pool_knl_rs_set_index;
	rs->prs_close = pool_knl_rs_close;
	rs->prs_count = pool_knl_rs_count;
	return (rs);
}

/*
 * Free a result set. Ensure that the resources are all released at
 * this point.
 */
void
pool_knl_result_set_free(pool_knl_result_set_t *rs)
{
	free(rs->pkr_list);
	free(rs);
}
/*
 * Return the next element in a result set.
 * Returns pool_elem_t pointer/NULL
 */
pool_elem_t *
pool_knl_rs_next(pool_result_set_t *set)
{
	pool_knl_result_set_t *kset = (pool_knl_result_set_t *)set;

	if (kset->prs_index == kset->pkr_count - 1)
		return (NULL);
	return ((pool_elem_t *)kset->pkr_list[++kset->prs_index]);
}

/*
 * Return the previous element in a result set.
 * Returns pool_elem_t pointer/NULL
 */
pool_elem_t *
pool_knl_rs_prev(pool_result_set_t *set)
{
	pool_knl_result_set_t *kset = (pool_knl_result_set_t *)set;

	if (kset->prs_index < 0)
		return (NULL);
	return ((pool_elem_t *)kset->pkr_list[kset->prs_index--]);
}

/*
 * Sets the current index in a result set.
 * Returns PO_SUCCESS/PO_FAIL
 */
int
pool_knl_rs_set_index(pool_result_set_t *set, int index)
{
	pool_knl_result_set_t *kset = (pool_knl_result_set_t *)set;

	if (index < 0 || index >= kset->pkr_count) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	kset->prs_index = index;
	return (PO_SUCCESS);
}

/*
 * Return the current index in a result set.
 * Returns current index
 */
int
pool_knl_rs_get_index(pool_result_set_t *set)
{
	pool_knl_result_set_t *kset = (pool_knl_result_set_t *)set;

	return (kset->prs_index);
}

/*
 * Return the first element in a result set.
 * Returns pool_elem_t pointer/NULL
 */
pool_elem_t *
pool_knl_rs_first(pool_result_set_t *set)
{
	pool_knl_result_set_t *kset = (pool_knl_result_set_t *)set;

	return ((pool_elem_t *)kset->pkr_list[0]);
}

/*
 * Return the last element in a result set.
 * Returns pool_elem_t pointer/NULL
 */
pool_elem_t *
pool_knl_rs_last(pool_result_set_t *set)
{
	pool_knl_result_set_t *kset = (pool_knl_result_set_t *)set;

	return ((pool_elem_t *)kset->pkr_list[kset->pkr_count - 1]);
}

/*
 * Return the number of results in a result set.
 * Returns result count
 */
int
pool_knl_rs_count(pool_result_set_t *set)
{
	pool_knl_result_set_t *kset = (pool_knl_result_set_t *)set;

	return (kset->pkr_count);
}


/*
 * Close a result set. Free the resources
 * Returns PO_SUCCESS/PO_FAIL
 */
int
pool_knl_rs_close(pool_result_set_t *set)
{
	pool_knl_result_set_t *kset = (pool_knl_result_set_t *)set;

	pool_knl_result_set_free(kset);
	return (PO_SUCCESS);
}

/*
 * Commit an individual transaction log item(). This processing is
 * essential to the pool_conf_commit() logic. When pool_conf_commit()
 * is invoked, the pending transaction log for the configuration is
 * walked and all pending changes to the kernel are invoked. If a
 * change succeeds it is marked in the log as successful and
 * processing continues, if it fails then failure is returned and the
 * log will be "rolled back" to undo changes to the library snapshot
 * and the kernel.
 */
int
log_item_commit(log_item_t *li)
{
	pool_knl_connection_t *prov =
	    (pool_knl_connection_t *)li->li_log->l_conf->pc_prov;
	pool_create_undo_t *create;
	pool_destroy_undo_t *destroy;
	pool_assoc_undo_t *assoc;
	pool_dissoc_undo_t *dissoc;
	pool_propput_undo_t *propput;
	pool_proprm_undo_t *proprm;
	pool_xtransfer_undo_t *xtransfer;
	char_buf_t *cb;
	size_t size;
	pool_elem_t *pair;
	pool_value_t val = POOL_VALUE_INITIALIZER;
	int ret;

	switch (li->li_op) {
	case POOL_CREATE:
		create = (pool_create_undo_t *)li->li_details;
		if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL)
			return (PO_FAIL);
		if (set_char_buf(cb, "%s.sys_id",
		    pool_elem_class_string(create->pcu_elem)) != PO_SUCCESS) {
			free_char_buf(cb);
			return (PO_FAIL);
		}
#ifdef DEBUG
		dprintf("log_item_commit: POOL_CREATE, remove from dict\n");
		pool_elem_dprintf(create->pcu_elem);
#endif	/* DEBUG */
		/*
		 * May not need to remove the element if it was
		 * already destroyed before commit. Just cast the
		 * return to void.
		 */
		(void) dict_remove(prov->pkc_elements,
		    (pool_knl_elem_t *)create->pcu_elem);

		if (ioctl(prov->pkc_fd, POOL_CREATE, &create->pcu_ioctl) < 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		/*
		 * Now that we have created our element in the kernel,
		 * it has a valid allocated system id. Remove the
		 * element from the element dictionary, using the
		 * current key, and then re-insert under the new key.
		 */
#ifdef DEBUG
		pool_elem_dprintf(create->pcu_elem);
#endif	/* DEBUG */
		assert(nvlist_add_int64(
		    ((pool_knl_elem_t *)create->pcu_elem)->pke_properties,
		    cb->cb_buf, create->pcu_ioctl.pc_i_id) == 0);
		free_char_buf(cb);
		assert(dict_put(prov->pkc_elements, create->pcu_elem,
		    create->pcu_elem) == NULL);
		/*
		 * If the element has a pair in the static
		 * configuration, update it with the sys_id
		 */
		if ((pair = pool_get_pair(create->pcu_elem)) != NULL) {
			pool_value_set_int64(&val, create->pcu_ioctl.pc_i_id);
			assert(pool_put_any_ns_property(pair, c_sys_prop, &val)
			    == PO_SUCCESS);
		}
		li->li_state = LS_UNDO;
		break;
	case POOL_DESTROY:
		destroy = (pool_destroy_undo_t *)li->li_details;

		destroy->pdu_ioctl.pd_o_id = elem_get_sysid(destroy->pdu_elem);

		/*
		 * It may be that this element was created in the last
		 * transaction. In which case POOL_CREATE, above, will
		 * have re-inserted the element in the dictionary. Try
		 * to remove it just in case this has occurred.
		 */
		(void) dict_remove(prov->pkc_elements,
		    (pool_knl_elem_t *)destroy->pdu_elem);
		while ((ret = ioctl(prov->pkc_fd, POOL_DESTROY,
		    &destroy->pdu_ioctl)) < 0 && errno == EAGAIN)
			;
		if (ret < 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
#ifdef DEBUG
		dprintf("log_item_commit: POOL_DESTROY\n");
		pool_elem_dprintf(destroy->pdu_elem);
#endif	/* DEBUG */
		li->li_state = LS_UNDO;
		break;
	case POOL_ASSOC:
		assoc = (pool_assoc_undo_t *)li->li_details;

		assoc->pau_ioctl.pa_o_pool_id =
		    elem_get_sysid(assoc->pau_assoc);
		assoc->pau_ioctl.pa_o_res_id =
		    elem_get_sysid(assoc->pau_newres);
		while ((ret = ioctl(prov->pkc_fd, POOL_ASSOC,
		    &assoc->pau_ioctl)) < 0 && errno == EAGAIN)
			;
		if (ret < 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		li->li_state = LS_UNDO;
		break;
	case POOL_DISSOC:
		dissoc = (pool_dissoc_undo_t *)li->li_details;

		dissoc->pdu_ioctl.pd_o_pool_id =
		    elem_get_sysid(dissoc->pdu_dissoc);

		while ((ret = ioctl(prov->pkc_fd, POOL_DISSOC,
		    &dissoc->pdu_ioctl)) < 0 && errno == EAGAIN)
			;
		if (ret < 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		li->li_state = LS_UNDO;
		break;
	case POOL_TRANSFER:
		li->li_state = LS_UNDO;
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	case POOL_XTRANSFER:
		xtransfer = (pool_xtransfer_undo_t *)li->li_details;

		xtransfer->pxu_ioctl.px_o_src_id =
		    elem_get_sysid(xtransfer->pxu_src);
		xtransfer->pxu_ioctl.px_o_tgt_id =
		    elem_get_sysid(xtransfer->pxu_tgt);
		for (size = 0; xtransfer->pxu_rl[size] != NULL; size ++) {
			xtransfer->pxu_ioctl.px_o_comp_list[size] =
			    elem_get_sysid(TO_ELEM(xtransfer->pxu_rl[size]));
#ifdef DEBUG
			dprintf("log_item_commit: POOL_XTRANSFER\n");
			pool_elem_dprintf(TO_ELEM(xtransfer->pxu_rl[size]));
#endif	/* DEBUG */
		}

		/*
		 * Don't actually transfer resources if the configuration
		 * is in POF_DESTROY state. This is to prevent problems
		 * relating to transferring off-line CPUs. Instead rely
		 * on the POOL_DESTROY ioctl to transfer the CPUS.
		 */
		if (li->li_log->l_conf->pc_state != POF_DESTROY &&
		    ioctl(prov->pkc_fd, POOL_XTRANSFER,
		    &xtransfer->pxu_ioctl) < 0) {
#ifdef DEBUG
			dprintf("log_item_commit: POOL_XTRANSFER, ioctl "
			    "failed\n");
#endif	/* DEBUG */
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		li->li_state = LS_UNDO;
		break;
	case POOL_PROPPUT:
		propput = (pool_propput_undo_t *)li->li_details;

		if (pool_elem_class(propput->ppu_elem) != PEC_SYSTEM) {
			propput->ppu_ioctl.pp_o_id =
			    elem_get_sysid(propput->ppu_elem);
		}
		/*
		 * Some properties, e.g. pset.size, are read-only in the
		 * kernel and attempting to change them will fail and cause
		 * problems. Although this property is read-only through the
		 * public interface, the library needs to modify it's value.
		 */
		if ((propput->ppu_doioctl & KERNEL_PROP_RDONLY) == 0) {
			if (ioctl(prov->pkc_fd, POOL_PROPPUT,
			    &propput->ppu_ioctl) < 0) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
		}
		li->li_state = LS_UNDO;
		break;
	case POOL_PROPRM:
		proprm = (pool_proprm_undo_t *)li->li_details;

		if (pool_elem_class(proprm->pru_elem) != PEC_SYSTEM) {
			proprm->pru_ioctl.pp_o_id =
			    elem_get_sysid(proprm->pru_elem);
		}
		if (ioctl(prov->pkc_fd, POOL_PROPRM, &proprm->pru_ioctl) < 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		li->li_state = LS_UNDO;
		break;
	default:
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * Undo an individual transaction log item(). This processing is
 * essential to the pool_conf_commit() and pool_conf_rollback()
 * logic. Changes to the libpool snapshot and the kernel are carried
 * out separately. The library snapshot is updated synchronously,
 * however the kernel update is delayed until the user calls
 * pool_conf_commit().
 *
 * When undoing transactions, library changes will be undone unless
 * this invocation is as a result of a commit failure, in which case
 * the log state will be LS_RECOVER. Kernel changes will only be
 * undone if they are marked as having been done, in which case the
 * log item state will be LS_UNDO.
 */
int
log_item_undo(log_item_t *li)
{
	pool_knl_connection_t *prov =
	    (pool_knl_connection_t *)li->li_log->l_conf->pc_prov;
	pool_create_undo_t *create;
	pool_destroy_undo_t *destroy;
	pool_assoc_undo_t *assoc;
	pool_dissoc_undo_t *dissoc;
	pool_propput_undo_t *propput;
	pool_proprm_undo_t *proprm;
	pool_xtransfer_undo_t *xtransfer;
	char_buf_t *cb;
	size_t size;
	pool_destroy_t u_destroy;
	pool_create_t u_create;
	pool_assoc_t u_assoc;
	pool_xtransfer_t u_xtransfer;
	pool_propput_t u_propput;
	pool_proprm_t u_proprm;
	pool_conf_t *conf = li->li_log->l_conf;
	nvpair_t *pair;
	nvlist_t *tmplist;
	int ret;

	if (li->li_log->l_state != LS_RECOVER) {
	switch (li->li_op) {
	case POOL_CREATE:
		create = (pool_create_undo_t *)li->li_details;

		(void) dict_remove(prov->pkc_elements, create->pcu_elem);
#ifdef DEBUG
		dprintf("log_item_undo: POOL_CREATE\n");
		assert(create->pcu_elem != NULL);
		dprintf("log_item_undo: POOL_CREATE %p\n", create->pcu_elem);
		pool_elem_dprintf(create->pcu_elem);
#endif	/* DEBUG */
		pool_knl_elem_free((pool_knl_elem_t *)create->pcu_elem,
		    PO_TRUE);
		break;
	case POOL_DESTROY:
		destroy = (pool_destroy_undo_t *)li->li_details;

		assert(dict_put(prov->pkc_elements, destroy->pdu_elem,
		    destroy->pdu_elem) == NULL);
		break;
	case POOL_ASSOC:
		assoc = (pool_assoc_undo_t *)li->li_details;

		if (assoc->pau_oldres != NULL)
			((pool_knl_pool_t *)assoc->pau_assoc)->pkp_assoc
			    [pool_resource_elem_class(assoc->pau_oldres)] =
			    (pool_knl_resource_t *)assoc->pau_oldres;
		break;
	case POOL_DISSOC:
		dissoc = (pool_dissoc_undo_t *)li->li_details;

		if (dissoc->pdu_oldres != NULL)
			((pool_knl_pool_t *)dissoc->pdu_dissoc)->pkp_assoc
			    [pool_resource_elem_class(dissoc->pdu_oldres)] =
			    (pool_knl_resource_t *)dissoc->pdu_oldres;
		break;
	case POOL_TRANSFER:
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	case POOL_XTRANSFER:
		xtransfer = (pool_xtransfer_undo_t *)li->li_details;

		for (size = 0; xtransfer->pxu_rl[size] != NULL; size++) {
			pool_value_t val = POOL_VALUE_INITIALIZER;
			uint64_t src_size;
			uint64_t tgt_size;

			if (pool_set_container(xtransfer->pxu_src,
			    TO_ELEM(xtransfer->pxu_rl[size])) == PO_FAIL) {
				return (PO_FAIL);
			}
			/*
			 * Maintain the library view of the size
			 */
			if (resource_get_size(pool_elem_res(xtransfer->pxu_src),
			    &src_size) != PO_SUCCESS ||
			    resource_get_size(pool_elem_res(xtransfer->pxu_tgt),
			    &tgt_size) != PO_SUCCESS) {
				pool_seterror(POE_BADPARAM);
				return (PO_FAIL);
			}
			src_size++;
			tgt_size--;
			pool_value_set_uint64(&val, src_size);
			(void) pool_put_any_ns_property(xtransfer->pxu_src,
			    c_size_prop, &val);
			pool_value_set_uint64(&val, tgt_size);
			(void) pool_put_any_ns_property(xtransfer->pxu_tgt,
			    c_size_prop, &val);
		}
		break;
	case POOL_PROPPUT:
		propput = (pool_propput_undo_t *)li->li_details;

		if ((propput->ppu_doioctl & KERNEL_PROP_RDONLY) == 0) {
			if (propput->ppu_blist != NULL) {
				if (nvlist_merge(
				    ((pool_knl_elem_t *)propput->ppu_elem)->
				    pke_properties, propput->ppu_blist, 0)
				    != 0) {
					pool_seterror(POE_SYSTEM);
					return (PO_FAIL);
				}
			} else {
				if (nvlist_unpack(propput->ppu_ioctl.pp_o_buf,
				    propput->ppu_ioctl.pp_o_bufsize,
				    &propput->ppu_alist, 0) != 0) {
					pool_seterror(POE_SYSTEM);
					return (PO_FAIL);
				}
				pair = nvlist_next_nvpair(propput->ppu_alist,
				    NULL);
				(void) nvlist_remove_all(((pool_knl_elem_t *)
				    propput->ppu_elem)->pke_properties,
				    nvpair_name(pair));
				nvlist_free(propput->ppu_alist);
			}
		}
		break;
	case POOL_PROPRM:
		proprm = (pool_proprm_undo_t *)li->li_details;

		if (pool_value_get_type(&proprm->pru_oldval) != POC_INVAL) {
			if (pool_put_property(conf, proprm->pru_elem,
			    proprm->pru_ioctl.pp_o_prop_name,
			    &proprm->pru_oldval) != PO_SUCCESS) {
				return (PO_FAIL);
			}
		}
		break;
	default:
		return (PO_FAIL);
	}
	}
	/*
	 * Only try to undo the state of the kernel if we modified it.
	 */
	if (li->li_state == LS_DO) {
		return (PO_SUCCESS);
	}

	switch (li->li_op) {
	case POOL_CREATE:
		create = (pool_create_undo_t *)li->li_details;

		u_destroy.pd_o_type = create->pcu_ioctl.pc_o_type;
		u_destroy.pd_o_sub_type = create->pcu_ioctl.pc_o_sub_type;
		u_destroy.pd_o_id = create->pcu_ioctl.pc_i_id;

		while ((ret = ioctl(prov->pkc_fd, POOL_DESTROY,
		    &u_destroy)) < 0 && errno == EAGAIN)
			;
		if (ret < 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		li->li_state = LS_DO;
		break;
	case POOL_DESTROY:
		destroy = (pool_destroy_undo_t *)li->li_details;

		u_create.pc_o_type = destroy->pdu_ioctl.pd_o_type;
		u_create.pc_o_sub_type = destroy->pdu_ioctl.pd_o_sub_type;

		if (ioctl(prov->pkc_fd, POOL_CREATE, &u_create) < 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}

		if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL) {
			return (PO_FAIL);
		}
		if (set_char_buf(cb, "%s.sys_id",
		    pool_elem_class_string(destroy->pdu_elem)) != PO_SUCCESS) {
			free_char_buf(cb);
			return (PO_FAIL);
		}
		(void) nvlist_add_int64(
		    ((pool_knl_elem_t *)destroy->pdu_elem)->pke_properties,
		    cb->cb_buf, u_create.pc_i_id);
		free_char_buf(cb);
		if (dict_put(prov->pkc_elements, destroy->pdu_elem,
		    destroy->pdu_elem) != NULL) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		/*
		 * Now we need to reset all the properties and
		 * associations in the kernel for this newly created
		 * replacement.
		 */
		u_propput.pp_o_id_type = destroy->pdu_ioctl.pd_o_type;
		u_propput.pp_o_id_sub_type = destroy->pdu_ioctl.pd_o_sub_type;
		u_propput.pp_o_id = u_create.pc_i_id;
		u_propput.pp_o_buf = NULL;
		/*
		 * Remove the read-only properties before attempting
		 * to restore the state of the newly created property
		 */
		(void) nvlist_dup(((pool_knl_elem_t *)destroy->pdu_elem)->
		    pke_properties, &tmplist, 0);
		for (pair = nvlist_next_nvpair(tmplist, NULL); pair != NULL;
		    pair = nvlist_next_nvpair(tmplist, pair)) {
			const pool_prop_t *prop;
			char *name = nvpair_name(pair);
			if ((prop = provider_get_prop(destroy->pdu_elem,
			    name)) != NULL)
				if (prop_is_readonly(prop) == PO_TRUE)
					(void) nvlist_remove_all(tmplist, name);
		}
		if (nvlist_pack(tmplist, (char **)&u_propput.pp_o_buf,
		    &u_propput.pp_o_bufsize, NV_ENCODE_NATIVE, 0) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		nvlist_free(tmplist);
		if (ioctl(prov->pkc_fd, POOL_PROPPUT, &u_propput) < 0) {
			free(u_propput.pp_o_buf);
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		free(u_propput.pp_o_buf);
		/*
		 * Now reset the associations for all the resource
		 * types if the thing which we are recreating is a
		 * pool
		 *
		 * TODO: This is resource specific and must be
		 * extended for additional resource types.
		 */
		if (destroy->pdu_ioctl.pd_o_type == PEC_POOL) {
			u_assoc.pa_o_pool_id = u_create.pc_i_id;
			u_assoc.pa_o_res_id =
			    elem_get_sysid(
			    TO_ELEM(((pool_knl_pool_t *)destroy->pdu_elem)->
			    pkp_assoc[PREC_PSET]));
			u_assoc.pa_o_id_type = PREC_PSET;

			if (ioctl(prov->pkc_fd, POOL_ASSOC, &u_assoc) < 0) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
		}
		li->li_state = LS_DO;
		break;
	case POOL_ASSOC:
		assoc = (pool_assoc_undo_t *)li->li_details;

		u_assoc.pa_o_pool_id = elem_get_sysid(assoc->pau_assoc);
		u_assoc.pa_o_res_id = elem_get_sysid(assoc->pau_oldres);
		u_assoc.pa_o_id_type = assoc->pau_ioctl.pa_o_id_type;

		while ((ret = ioctl(prov->pkc_fd, POOL_ASSOC, &u_assoc)) < 0 &&
		    errno == EAGAIN)
			;
		if (ret < 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		li->li_state = LS_DO;
		break;
	case POOL_DISSOC:
		dissoc = (pool_dissoc_undo_t *)li->li_details;

		u_assoc.pa_o_pool_id = elem_get_sysid(dissoc->pdu_dissoc);
		u_assoc.pa_o_res_id = elem_get_sysid(dissoc->pdu_oldres);
		u_assoc.pa_o_id_type = dissoc->pdu_ioctl.pd_o_id_type;

		while ((ret = ioctl(prov->pkc_fd, POOL_ASSOC, &u_assoc)) < 0 &&
		    errno == EAGAIN)
			;
		if (ret < 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		li->li_state = LS_DO;
		break;
	case POOL_TRANSFER:
		li->li_state = LS_DO;
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	case POOL_XTRANSFER:
		xtransfer = (pool_xtransfer_undo_t *)li->li_details;

		(void) memcpy(&u_xtransfer, &xtransfer->pxu_ioctl,
		    sizeof (pool_xtransfer_t));
		u_xtransfer.px_o_src_id = elem_get_sysid(xtransfer->pxu_tgt);
		u_xtransfer.px_o_tgt_id = elem_get_sysid(xtransfer->pxu_src);

		if (ioctl(prov->pkc_fd, POOL_XTRANSFER, &u_xtransfer) < 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		li->li_state = LS_DO;
		break;
	case POOL_PROPPUT:
		propput = (pool_propput_undo_t *)li->li_details;

		if ((propput->ppu_doioctl & KERNEL_PROP_RDONLY) == 0) {
			if (propput->ppu_blist) {
				(void) memcpy(&u_propput, &propput->ppu_ioctl,
				    sizeof (pool_propput_t));
				u_propput.pp_o_id =
				    elem_get_sysid(propput->ppu_elem);
				u_propput.pp_o_buf = NULL;
				if (nvlist_pack(propput->ppu_blist,
				    (char **)&u_propput.pp_o_buf,
				    &u_propput.pp_o_bufsize,
				    NV_ENCODE_NATIVE, 0) != 0) {
					pool_seterror(POE_SYSTEM);
					return (PO_FAIL);
				}
				if (ioctl(prov->pkc_fd, POOL_PROPPUT,
				    &u_propput) < 0) {
					free(u_propput.pp_o_buf);
					pool_seterror(POE_SYSTEM);
					return (PO_FAIL);
				}
				free(u_propput.pp_o_buf);
			} else {
				if (nvlist_unpack(propput->
				    ppu_ioctl.pp_o_buf,
				    propput->ppu_ioctl.pp_o_bufsize,
				    &propput->ppu_alist, 0) != 0) {
					pool_seterror(POE_SYSTEM);
					return (PO_FAIL);
				}
				u_proprm.pp_o_id_type =
				    propput->ppu_ioctl.pp_o_id_type;
				u_proprm.pp_o_id_sub_type =
				    propput->ppu_ioctl.pp_o_id_sub_type;
				u_proprm.pp_o_id =
				    elem_get_sysid(propput->ppu_elem);
				pair = nvlist_next_nvpair(propput->ppu_alist,
				    NULL);
				u_proprm.pp_o_prop_name = nvpair_name(pair);
				u_proprm.pp_o_prop_name_size =
				    strlen(u_proprm.pp_o_prop_name);

				if (provider_get_prop(propput->ppu_elem,
				    u_proprm.pp_o_prop_name) == NULL) {
					if (ioctl(prov->pkc_fd, POOL_PROPRM,
					    &u_proprm) < 0) {
						nvlist_free(propput->ppu_alist);
						pool_seterror(POE_SYSTEM);
						return (PO_FAIL);
					}
				}
				nvlist_free(propput->ppu_alist);
			}
		}
		li->li_state = LS_DO;
		break;
	case POOL_PROPRM:
		proprm = (pool_proprm_undo_t *)li->li_details;

		u_propput.pp_o_id_type = proprm->pru_ioctl.pp_o_id_type;
		u_propput.pp_o_id_sub_type =
		    proprm->pru_ioctl.pp_o_id_sub_type;
		u_propput.pp_o_id = elem_get_sysid(proprm->pru_elem);
		u_propput.pp_o_buf = NULL;
		/*
		 * Only try to remove the appropriate property
		 */
		if (nvlist_alloc(&tmplist, NV_UNIQUE_NAME_TYPE, 0) !=
		    0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		if (pool_knl_nvlist_add_value(tmplist,
		    pool_value_get_name(&proprm->pru_oldval),
		    &proprm->pru_oldval) != PO_SUCCESS)
			return (PO_FAIL);

		if (nvlist_pack(tmplist,
		    (char **)&u_propput.pp_o_buf, &u_propput.pp_o_bufsize,
		    NV_ENCODE_NATIVE, 0) != 0) {
			nvlist_free(tmplist);
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		nvlist_free(tmplist);
		if (ioctl(prov->pkc_fd, POOL_PROPPUT, &u_propput) < 0) {
			free(u_propput.pp_o_buf);
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		free(u_propput.pp_o_buf);
		li->li_state = LS_DO;
		break;
	default:
		return (PO_FAIL);
	}
		return (PO_SUCCESS);
}

/*
 * A log item stores state about the transaction it represents. This
 * function releases the resources associated with the transaction and
 * used to store the transaction state.
 */
int
log_item_release(log_item_t *li)
{
	pool_create_undo_t *create;
	pool_destroy_undo_t *destroy;
	pool_assoc_undo_t *assoc;
	pool_dissoc_undo_t *dissoc;
	pool_propput_undo_t *propput;
	pool_proprm_undo_t *proprm;
	pool_xtransfer_undo_t *xtransfer;

	switch (li->li_op) {
	case POOL_CREATE:
		create = (pool_create_undo_t *)li->li_details;

		free(create);
		break;
	case POOL_DESTROY:
		destroy = (pool_destroy_undo_t *)li->li_details;

#ifdef DEBUG
		dprintf("log_item_release: POOL_DESTROY\n");
#endif	/* DEBUG */

		if (li->li_state == LS_UNDO) {
#ifdef DEBUG
			pool_elem_dprintf(destroy->pdu_elem);
#endif	/* DEBUG */
			pool_knl_elem_free((pool_knl_elem_t *)destroy->
			    pdu_elem, PO_TRUE);
		}
		free(destroy);
		break;
	case POOL_ASSOC:
		assoc = (pool_assoc_undo_t *)li->li_details;

		free(assoc);
		break;
	case POOL_DISSOC:
		dissoc = (pool_dissoc_undo_t *)li->li_details;

		free(dissoc);
		break;
	case POOL_TRANSFER:
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	case POOL_XTRANSFER:
		xtransfer = (pool_xtransfer_undo_t *)li->li_details;

		free(xtransfer->pxu_rl);
		free(xtransfer->pxu_ioctl.px_o_comp_list);
		free(xtransfer);
		break;
	case POOL_PROPPUT:
		propput = (pool_propput_undo_t *)li->li_details;

		nvlist_free(propput->ppu_blist);
		free(propput->ppu_ioctl.pp_o_buf);
		free(propput);
		break;
	case POOL_PROPRM:
		proprm = (pool_proprm_undo_t *)li->li_details;

		free(proprm);
		break;
	default:
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * pool_knl_nvlist_add_value() adds a pool_value_t to an nvlist.
 */
int
pool_knl_nvlist_add_value(nvlist_t *list, const char *name,
    const pool_value_t *pv)
{
	uint64_t uval;
	int64_t ival;
	double dval;
	uchar_t dval_b[sizeof (double)];
	uchar_t bval;
	const char *sval;
	pool_value_class_t type;
	char *nv_name;

	if ((type = pool_value_get_type(pv)) == POC_INVAL) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	nv_name = (char *)name;

	switch (type) {
	case POC_UINT:
		if (pool_value_get_uint64(pv, &uval) == POC_INVAL) {
			return (PO_FAIL);
		}
		if (nvlist_add_uint64(list, nv_name, uval) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		break;
	case POC_INT:
		if (pool_value_get_int64(pv, &ival) == POC_INVAL) {
			return (PO_FAIL);
		}
		if (nvlist_add_int64(list, nv_name, ival) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		break;
	case POC_DOUBLE:
		if (pool_value_get_double(pv, &dval) == POC_INVAL) {
			return (PO_FAIL);
		}
		/*
		 * Since there is no support for doubles in the
		 * kernel, store the double value in a byte array.
		 */
		(void) memcpy(dval_b, &dval, sizeof (double));
		if (nvlist_add_byte_array(list, nv_name, dval_b,
		    sizeof (double)) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		break;
	case POC_BOOL:
		if (pool_value_get_bool(pv, &bval) == POC_INVAL) {
			return (PO_FAIL);
		}
		if (nvlist_add_byte(list, nv_name, bval) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		break;
	case POC_STRING:
		if (pool_value_get_string(pv, &sval) == POC_INVAL) {
			return (PO_FAIL);
		}
		if (nvlist_add_string(list, nv_name, (char *)sval) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		break;
	default:
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * hash_id() hashes all elements in a pool configuration using the
 * "sys_id" property. Not all elements have a "sys_id" property,
 * however elem_get_sysid() caters for this by always returning a
 * constant value for those elements. This isn't anticipated to lead
 * to a performance degradation in the hash, since those elements
 * which are likely to be most prevalent in a configuration do have
 * "sys_id" as a property.
 */
uint64_t
hash_id(const pool_elem_t *pe)
{
	id_t id;

	id = elem_get_sysid(pe);
	return (hash_buf(&id, sizeof (id)));
}

/*
 *  blocking_open() guarantees access to the pool device, if open()
 * is failing with EBUSY.
 */
int
blocking_open(const char *path, int oflag)
{
	int fd;

	while ((fd = open(path, oflag)) == -1 && errno == EBUSY)
		(void) poll(NULL, 0, 1 * MILLISEC);

	return (fd);
}
