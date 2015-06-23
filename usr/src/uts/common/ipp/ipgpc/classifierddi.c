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

#include <sys/systm.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <ipp/ipp.h>
#include <ipp/ipp_config.h>
#include <ipp/ipgpc/classifier.h>
#include <inet/ip.h>
#include <net/if.h>
#include <inet/ip_if.h>
#include <inet/ipp_common.h>

/* DDI file for ipgpc ipp module */

/* protects against multiple configs  */
static kmutex_t ipgpc_config_lock;

static int ipgpc_create_action(ipp_action_id_t, nvlist_t **, ipp_flags_t);
static int ipgpc_modify_action(ipp_action_id_t, nvlist_t **, ipp_flags_t);
static int ipgpc_destroy_action(ipp_action_id_t, ipp_flags_t);
static int ipgpc_info(ipp_action_id_t aid, int (*)(nvlist_t *, void *), void *,
    ipp_flags_t);
static int ipgpc_invoke_action(ipp_action_id_t, ipp_packet_t *);

ipp_ops_t ipgpc_ops = {
	IPPO_REV,
	ipgpc_create_action,	/* ippo_action_create */
	ipgpc_modify_action,	/* ippo_action_modify */
	ipgpc_destroy_action,	/* ippo_action_destroy */
	ipgpc_info,		/* ippo_action_info */
	ipgpc_invoke_action	/* ippo_action_invoke */
};

extern struct mod_ops mod_ippops;

/*
 * Module linkage information for the kernel.
 */
static struct modlipp modlipp = {
	&mod_ippops,
	"IP Generic Packet Classifier (ipgpc) module 1.0",
	&ipgpc_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlipp,
	NULL
};

#define	__FN__	"_init"
int
_init(
	void)
{
	int rc;

	if (ipgpc_action_exist) {
		return (EBUSY);
	}
	/* init mutexes */
	mutex_init(&ipgpc_config_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ipgpc_fid_list_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ipgpc_cid_list_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ipgpc_table_list_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ipgpc_ds_table_id.lock, NULL, MUTEX_DRIVER, NULL);

	if ((rc = mod_install(&modlinkage)) != 0) {
		/* clean up after fail */
		mutex_destroy(&ipgpc_config_lock);
		mutex_destroy(&ipgpc_fid_list_lock);
		mutex_destroy(&ipgpc_cid_list_lock);
		mutex_destroy(&ipgpc_table_list_lock);
		mutex_destroy(&ipgpc_ds_table_id.lock);
	}

	return (rc);
}
#undef	__FN__

#define	__FN__	"_fini"
int
_fini(
	void)
{
	int rc;

	if (ipgpc_action_exist) {
		return (EBUSY);
	}

	if ((rc = mod_remove(&modlinkage)) != 0) {
		return (rc);
	}
	/* destroy mutexes */
	mutex_destroy(&ipgpc_config_lock);
	mutex_destroy(&ipgpc_fid_list_lock);
	mutex_destroy(&ipgpc_cid_list_lock);
	mutex_destroy(&ipgpc_table_list_lock);
	mutex_destroy(&ipgpc_ds_table_id.lock);
	return (rc);
}
#undef	__FN__

#define	__FN__	"_info"
int
_info(
	struct	modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
#undef	__FN__

/*
 * ipgpc_create_action(aid, nvlpp, flags)
 *
 * creates a single instance of ipgpc, if one does not exist.  If an action
 * instance already exists, fail with EBUSY
 *
 * if nvlpp contains the name IPP_ACTION_STATS_ENABLE, then process it and
 * determine if global stats should be collected
 *
 * the ipgpc_config_lock is taken to block out any other creates or destroys
 * the are issued while the create is taking place
 */
/* ARGSUSED */
static int
ipgpc_create_action(ipp_action_id_t aid, nvlist_t **nvlpp, ipp_flags_t flags)
{
	int rc;
	uint32_t stat;
	nvlist_t *nvlp;

	nvlp = *nvlpp;
	*nvlpp = NULL;		/* nvlist should be NULL when this returns */

	/* only one ipgpc action instance can be loaded at once */
	if (ipgpc_action_exist) {
		nvlist_free(nvlp);
		return (EBUSY);
	} else {
		mutex_enter(&ipgpc_config_lock);
		if (ipgpc_action_exist) {
			nvlist_free(nvlp);
			mutex_exit(&ipgpc_config_lock);
			return (EBUSY);
		}
		/* check for action param IPP_ACTION_STATS_ENABLE */
		if ((rc = nvlist_lookup_uint32(nvlp, IPP_ACTION_STATS_ENABLE,
		    &stat)) != 0) {
			ipgpc_gather_stats = B_FALSE; /* disabled by default */
		} else {
			ipgpc_gather_stats = (boolean_t)stat;
		}
		if ((rc = ipgpc_initialize(aid)) != 0) {
			ipgpc0dbg(("ipgpc_create_action: ipgpc_intialize " \
			    "error %d", rc));
			ipgpc_destroy(IPP_DESTROY_REF);
			ipgpc_action_exist = B_FALSE;
			nvlist_free(nvlp);
			mutex_exit(&ipgpc_config_lock);
			return (rc);
		}
		ipgpc_action_exist = B_TRUE;
		nvlist_free(nvlp);
		mutex_exit(&ipgpc_config_lock);
		return (0);
	}
}

/*
 * ipgpc_modify_action
 *
 * modify an instance of ipgpc
 *
 * nvlpp will contain the configuration type to switch off of.  Use this
 * to determine what modification should be made.  If the modification fails,
 * return the appropriate error.
 */
/* ARGSUSED */
static int
ipgpc_modify_action(ipp_action_id_t aid, nvlist_t **nvlpp, ipp_flags_t flags)
{
	nvlist_t *nvlp;
	int rc = 0;
	uint8_t config_type;
	uint32_t stat;
	char *name;
	int32_t filter_instance;
	ipgpc_filter_t *filter;
	ipgpc_class_t *aclass;

	nvlp = *nvlpp;
	*nvlpp = NULL;		/* nvlist should be NULL when this returns */

	if ((rc = nvlist_lookup_byte(nvlp, IPP_CONFIG_TYPE, &config_type))
	    != 0) {
		nvlist_free(nvlp);
		ipgpc0dbg(("ipgpc_modify_action: invalid configuration type"));
		return (EINVAL);
	}

	switch (config_type) {
	case IPP_SET:		/* set an action parameter */
		if ((rc = nvlist_lookup_uint32(nvlp, IPP_ACTION_STATS_ENABLE,
		    &stat)) != 0) {
			nvlist_free(nvlp);
			ipgpc0dbg(("ipgpc_modify_action: invalid IPP_SET " \
			    "parameter"));
			return (EINVAL);
		} else {
			ipgpc_gather_stats = (boolean_t)stat;
		}
		break;
	case CLASSIFIER_ADD_FILTER: /* add a filter */
		filter = kmem_zalloc(sizeof (ipgpc_filter_t), KM_SLEEP);
		if ((rc = ipgpc_parse_filter(filter, nvlp)) != 0) {
			ipgpc0dbg(("ipgpc_modify_action: invalid filter"));
			ipgpc_filter_destructor(filter);
			kmem_free(filter, sizeof (ipgpc_filter_t));
			break;
		}
		/* parse class name */
		if ((rc = nvlist_lookup_string(nvlp, CLASSIFIER_CLASS_NAME,
		    &name)) != 0) {
			ipgpc0dbg(("ipgpc_modify_action: class name missing"));
			ipgpc_filter_destructor(filter);
			kmem_free(filter, sizeof (ipgpc_filter_t));
			break;
		}
		rc = ipgpc_addfilter(filter, name, flags);
		if (rc != 0) {
			ipgpc_filter_destructor(filter);
		}
		kmem_free(filter, sizeof (ipgpc_filter_t));
		break;
	case CLASSIFIER_ADD_CLASS: /* add a class */
		aclass = kmem_zalloc(sizeof (ipgpc_class_t), KM_SLEEP);
		if ((rc = ipgpc_parse_class(aclass, nvlp)) != 0) {
			ipgpc0dbg(("ipgpc_modify_action: invalid class"));
			kmem_free(aclass, sizeof (ipgpc_class_t));
			break;
		}
		rc = ipgpc_addclass(aclass, flags);
		kmem_free(aclass, sizeof (ipgpc_class_t));
		break;
	case CLASSIFIER_REMOVE_FILTER: /* remove a filter */
		/* parse filter name */
		if ((rc = nvlist_lookup_string(nvlp, CLASSIFIER_FILTER_NAME,
		    &name)) != 0) {
			ipgpc0dbg(("ipgpc_modify_action: filtername missing"));
			break;
		}
		/* parse optional filter_instance */
		if (nvlist_lookup_int32(nvlp, IPGPC_FILTER_INSTANCE,
		    &filter_instance) != 0) {
			filter_instance = -1;
		}
		rc = ipgpc_removefilter(name, filter_instance, flags);
		break;
	case CLASSIFIER_REMOVE_CLASS: /* remove a class */
		/* parse class name */
		if ((rc = nvlist_lookup_string(nvlp, CLASSIFIER_CLASS_NAME,
		    &name)) != 0) {
			ipgpc0dbg(("ipgpc_modify_action: class name missing"));
			break;
		}
		rc = ipgpc_removeclass(name, flags);
		break;
	case CLASSIFIER_MODIFY_FILTER: /* modify a filter */
		rc = ipgpc_modifyfilter(&nvlp, flags);
		break;
	case CLASSIFIER_MODIFY_CLASS: /* modify a class */
		rc = ipgpc_modifyclass(&nvlp, flags);
		break;
	default:		/* invalid config type */
		nvlist_free(nvlp);
		ipgpc0dbg(("ipgpc_modify_action:invalid configuration type %u",
		    config_type));
		return (EINVAL);
	}
	nvlist_free(nvlp);	/* free the list */
	return (rc);		/* nvlist is passed back NULL */
}

/*
 * ipgpc_destroy_action(aid, flags)
 *
 * action destructor for ipgpc
 *
 * Destroys an instance of the ipgpc action, if one exists. The
 * ipgpc_action_lock is taken to block out any other destroys or creates
 * that might be issued while the action is being destroyed
 */
/* ARGSUSED */
static int
ipgpc_destroy_action(ipp_action_id_t aid, ipp_flags_t flags)
{
	/* only destroy action if it exists */
	if (ipgpc_action_exist == B_TRUE) {
		mutex_enter(&ipgpc_config_lock);
		if (ipgpc_action_exist == B_FALSE) {
			mutex_exit(&ipgpc_config_lock);
			return (EBUSY);
		}
		ipgpc_action_exist = B_FALSE;
		ipgpc_destroy(flags);
		mutex_exit(&ipgpc_config_lock);
	}
	return (0);
}

/*
 * ipgpc_info(aid, fn, arg)
 *
 * configuration quering function for ipgpc
 *
 * passes back the configuration of ipgpc through allocated nvlists
 * all action paramaters, classes and filters are built into nvlists
 * and passed to the function pointer fn with arg
 */
/* ARGSUSED */
static int
ipgpc_info(ipp_action_id_t aid, int (*fn)(nvlist_t *, void *), void *arg,
    ipp_flags_t flags)
{
	int rc;

	/* set parameters */
	if ((rc = ipgpc_params_info(fn, arg)) != 0) {
		return (rc);
	}

	/* set all classes */
	if ((rc = ipgpc_classes_info(fn, arg)) != 0) {
		return (rc);
	}

	/* set all filters */
	if ((rc = ipgpc_filters_info(fn, arg)) != 0) {
		return (rc);
	}
	return (0);
}

/*
 * ipgpc_invoke_action(aid, packet)
 *
 * packet processing function for ipgpc
 *
 * given packet the selector information is parsed and the classify
 * function is called with those selectors.  The classify function will
 * return either a class or NULL, which represents a memory error and
 * ENOMEM is returned.  If the class returned is not NULL, the class and next
 * action, associated with that class, are added to packet
 */
/* ARGSUSED */
static int
ipgpc_invoke_action(ipp_action_id_t aid, ipp_packet_t *packet)
{
	ipgpc_class_t *out_class;
	hrtime_t start, end;
	mblk_t *mp = NULL;
	ip_priv_t *priv = NULL;
	ill_t *ill = NULL;
	ipha_t *ipha;
	ip_proc_t callout_pos;
	int af;
	int rc;
	ipgpc_packet_t pkt;
	uint_t ill_idx;

	/* extract packet data */
	mp = ipp_packet_get_data(packet);
	ASSERT(mp != NULL);

	priv = (ip_priv_t *)ipp_packet_get_private(packet);
	ASSERT(priv != NULL);

	callout_pos = priv->proc;
	ill_idx = priv->ill_index;

	/* If we don't get an M_DATA, then return an error */
	if (mp->b_datap->db_type != M_DATA) {
		if ((mp->b_cont != NULL) &&
		    (mp->b_cont->b_datap->db_type == M_DATA)) {
			mp = mp->b_cont; /* jump over the M_CTL into M_DATA */
		} else {
			ipgpc0dbg(("ipgpc_invoke_action: no data\n"));
			atomic_inc_64(&ipgpc_epackets);
			return (EINVAL);
		}
	}

	/*
	 * Translate the callout_pos into the direction the packet is traveling
	 */
	if (callout_pos != IPP_LOCAL_IN) {
		if (callout_pos & IPP_LOCAL_OUT) {
			callout_pos = IPP_LOCAL_OUT;
		} else if (callout_pos & IPP_FWD_IN) {
			callout_pos = IPP_FWD_IN;
		} else {	/* IPP_FWD_OUT */
			callout_pos = IPP_FWD_OUT;
		}
	}

	/* parse the packet from the message block */
	ipha = (ipha_t *)mp->b_rptr;
	/* Determine IP Header Version */
	if (IPH_HDR_VERSION(ipha) == IPV4_VERSION) {
		parse_packet(&pkt, mp);
		af = AF_INET;
	} else {
		parse_packet6(&pkt, mp);
		af = AF_INET6;
	}

	pkt.direction = callout_pos; /* set packet direction */

	/* The ill_index could be 0 when called from forwarding (read) path */
	if (ill_idx > 0)
		ill = ill_lookup_on_ifindex_global_instance(ill_idx, B_FALSE);

	if (ill != NULL) {
		/*
		 * Since all IPP actions in an IPMP group are performed
		 * relative to the IPMP group interface, if this is an
		 * underlying interface in an IPMP group, use the IPMP
		 * group interface's index.
		 */
		if (IS_UNDER_IPMP(ill))
			pkt.if_index = ipmp_ill_get_ipmp_ifindex(ill);
		else
			pkt.if_index = ill->ill_phyint->phyint_ifindex;
		/* Got the field from the ILL, go ahead and refrele */
		ill_refrele(ill);
	} else {
		/* unknown if_index */
		pkt.if_index = IPGPC_UNSPECIFIED;
	}

	if (ipgpc_debug > 5) {
		/* print pkt under high debug level */
#ifdef	IPGPC_DEBUG
		print_packet(af, &pkt);
#endif
	}
	if (ipgpc_debug > 3) {
		start = gethrtime(); /* start timer */
	}

	/* classify this packet */
	out_class = ipgpc_classify(af, &pkt);

	if (ipgpc_debug > 3) {
		end = gethrtime(); /* stop timer */
	}

	/* ipgpc_classify will only return NULL if a memory error occured */
	if (out_class == NULL) {
		atomic_inc_64(&ipgpc_epackets);
		return (ENOMEM);
	}

	ipgpc1dbg(("ipgpc_invoke_action: class = %s", out_class->class_name));
	/* print time to classify(..) */
	ipgpc2dbg(("ipgpc_invoke_action: time = %lld nsec\n", (end - start)));

	if ((rc = ipp_packet_add_class(packet, out_class->class_name,
	    out_class->next_action)) != 0) {
		atomic_inc_64(&ipgpc_epackets);
		ipgpc0dbg(("ipgpc_invoke_action: ipp_packet_add_class " \
		    "failed with error %d", rc));
		return (rc);
	}
	return (ipp_packet_next(packet, IPP_ACTION_CONT));
}
