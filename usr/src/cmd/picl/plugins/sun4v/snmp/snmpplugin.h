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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SNMPPLUGIN_H
#define	_SNMPPLUGIN_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The /physical-platform node
 */
#define	PICL_NODE_PHYSPLAT		"physical-platform"

/*
 * List of volatile property OIDs to lookup and update when needed
 */
typedef struct {
	picl_prophdl_t  prop;
	char		*oidstr;
	int		row;
	int		proptype;
} vol_prophdl_t;

/*
 * Types of volatile properties (proptype values)
 */
#define	VPT_PLATOPSTATE		1
#define	VPT_NUMSENSOR		2
#define	VPT_BINSENSOR		3
#define	VPT_ALARMSTATE		4
#define	VPT_BATTERYSTATUS	5

/*
 * Storage related and miscellaneous definitions
 */
#define	N_ELEMS_IN_VOLPROP_BLOCK	512
#define	N_ELEMS_IN_NODE_BLOCK		256
#define	NODE_BLOCK_SHIFT		8
#define	DEFAULT_SLOT_TYPE		"slot"

/*
 * Local macros and property ids
 */
#define	ADD_NODE(cl)							\
{									\
	if (ptree_create_and_add_node(parenth, node_name, cl,		\
	    &nodeh) != PICL_SUCCESS) {					\
		log_msg(LOG_ERR, SNMPP_ADD_NODE_FAIL, node_name, cl);	\
		return (0);						\
	}								\
}

#define	CHECK_LINKRESET(errp, retval)		\
	if ((errp) && (*errp == ECANCELED)) {	\
		return (retval);		\
	}

#define	CHECK_LINKRESET_VOID(errp)		\
	if ((errp) && (*errp == ECANCELED)) {	\
		return;				\
	}

#define	min(x, y)	((x) < (y) ? (x) : (y))

typedef enum {
	PP_SERIAL_NUM = 1,
	PP_SLOT_TYPE,
	PP_STATE,
	PP_OPSTATUS,
	PP_BATT_STATUS,
	PP_TEMPERATURE,
	PP_VOLTAGE,
	PP_CURRENT,
	PP_SPEED,
	PP_SENSOR_VALUE,
	PP_BASE_UNITS,
	PP_EXPONENT,
	PP_RATE_UNITS,
	PP_CONDITION,
	PP_EXPECTED,
	PP_REPLACEABLE,
	PP_HOTSWAPPABLE,
	PP_IS_FRU,
	PP_HW_REVISION,
	PP_FW_REVISION,
	PP_MFG_NAME,
	PP_MODEL_NAME,
	PP_DESCRIPTION,
	PP_LABEL
} sp_propid_t;

/*
 * Plugin global routines
 */
void snmpplugin_init(void);
void snmpplugin_fini(void);

/*
 * Plugin messages
 */
#define	SNMPP_NO_ROOT			\
    gettext("PICL snmpplugin: cannot get picl tree root (ret=%d)\n")

#define	SNMPP_CANT_INIT			\
    gettext("PICL snmpplugin: cannot initialize snmp service\n")

#define	SNMPP_CANT_CREATE_PHYSPLAT	\
    gettext("PICL snmpplugin: cannot create physical-platform root (ret=%d)\n")

#define	SNMPP_CANT_CREATE_TREE_BUILDER	\
    gettext("PICL snmpplugin: cannot create thr to handle hotplugs (ret=%d)\n")

#define	SNMPP_NO_ENTPHYSNAME		\
    gettext("PICL snmpplugin: cannot get entPhysicalName (row=%d)\n")

#define	SNMPP_ADD_NODE_FAIL		\
    gettext("PICL snmpplugin: couldn't add node %s (class=%d)\n")

#define	SNMPP_UNSUPP_SENSOR_CLASS	\
    gettext("PICL snmpplugin: sunPlatSensorClass %d unsupported (row=%d)\n")

#define	SNMPP_UNKNOWN_ENTPHYSCLASS	\
    gettext("PICL snmpplugin: entPhysicalClass %d unknown (row=%d)\n")

#define	SNMPP_NO_MEM			\
    gettext("PICL snmpplugin: failed to allocate %d bytes\n")

#define	SNMPP_CANT_FIND_VOLPROP		\
    gettext("PICL snmpplugin: cannot find volatile property (proph=%lx)\n")

#define	SNMPP_INV_PLAT_EQUIP_OPSTATE	\
    gettext("PICL snmpplugin: invalid sunPlatEquipmentOpState %d (row=%d)\n")

#define	SNMPP_INV_PLAT_BINSNSR_CURRENT	\
    gettext("PICL snmpplugin: invalid sunPlatBinarySensorCurrent %d (row=%d)\n")

#define	SNMPP_NO_SLOT_TYPE		\
    gettext("PICL snmpplugin: no acceptable slot types (row=%d)\n")

#define	SNMPP_CANT_INIT_PROPINFO	\
    gettext("PICL snmpplugin: cannot init picl propinfo (err=%d)\n")

#define	SNMPP_CANT_ADD_PROP		\
    gettext("PICL snmpplugin: cannot add property, err=%d (node=%lx)\n")

#define	SNMPP_CANT_INIT_STR_PROPINFO	\
    gettext("PICL snmpplugin: cannot init picl str propinfo (err=%d)\n")

#define	SNMPP_CANT_ADD_STR_PROP		\
    gettext("PICL snmpplugin: cannot add string property (err=%d, node=%lx)\n")

#define	SNMPP_CANT_INIT_VOID_PROPINFO	\
    gettext("PICL snmpplugin: cannot init picl void propinfo (err=%d)\n")

#define	SNMPP_CANT_ADD_VOID_PROP	\
    gettext("PICL snmpplugin: cannot add void property (err=%d, node=%lx)\n")

#define	SNMPP_CANT_INIT_INT_PROPINFO	\
    gettext("PICL snmpplugin: cannot init picl int propinfo (err=%d)\n")

#define	SNMPP_CANT_ADD_INT_PROP	\
    gettext("PICL snmpplugin: cannot add int property (err=%d, node=%lx)\n")

#define	SNMPP_CANT_FETCH_OBJECT_VAL	\
    gettext("PICL snmpplugin: cannot fetch object value " \
	"(err=%d, OID=<%s>, row=%d)\n")

#define	SNMPP_LINK_RESET	\
    gettext("PICL snmpplugin: snmp ds reset happened, rebuilding tree\n")

#define	SIGACT_FAILED	\
    gettext("PICL snmpplugin: Failed to install signal handler for %s: %s\n")

#ifdef SNMPPLUGIN_DEBUG
#define	SNMPPLUGIN_DBLOCK_SZ		4096
#define	SNMPPLUGIN_DMAX_LINE		80
#define	LOGINIT()			snmpplugin_log_init()
#define	LOGPRINTF(s)			snmpplugin_log(s)
#define	LOGPRINTF1(s, a1)		snmpplugin_log(s, a1)
#define	LOGPRINTF2(s, a1, a2)		snmpplugin_log(s, a1, a2)
#else
#define	LOGINIT()
#define	LOGPRINTF(s)
#define	LOGPRINTF1(s, a1)
#define	LOGPRINTF2(s, a1, a2)
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SNMPPLUGIN_H */
