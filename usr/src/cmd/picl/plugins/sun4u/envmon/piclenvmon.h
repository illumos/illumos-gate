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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PICLENVMON_H
#define	_PICLENVMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Log message texts
 */
#define	EM_INIT_FAILED		gettext("SUNW_piclenvmon: init failed!")
#define	EM_MISSING_NODE		gettext("SUNW_piclenvmon: no %s node!")
#define	EM_SC_NODE_INCOMPLETE	\
	gettext("SUNW_piclenvmon: SC node devfs-path property missing")
#define	EM_SC_NODE_MISSING	\
	gettext("SUNW_piclenvmon: failed to locate SC device node")
#define	EM_EVREG_FAILED	\
	gettext("SUNW_piclenvmon: failed to register for events %x")
#define	EM_NODE_ACCESS		\
	gettext("SUNW_piclenvmon: couldn't access \"%s\", " \
	    "type %d, PICL err %d")
#define	EM_SYS_ERR		gettext("SUNW_piclenvmon: %s: %s")
#define	EM_EV_MISSING_ARG	\
	gettext("SUNW_piclenvmon: missing %s in ADD_FRU/REMOVE_FRU event")
#define	EM_INVALID_COLOR	\
	gettext("SUNW_piclenvmon: invalid LED color 0x%x returned for %s")

/*
 * define for super-user uid - used in credential checking
 */
#define	SUPER_USER		((uid_t)0)

/*
 * Constants for distinquishing environmental monitor types
 */
#define	ENVMON_VOLT_SENS	0
#define	ENVMON_VOLT_IND		1
#define	ENVMON_AMP_SENS		2
#define	ENVMON_AMP_IND		3
#define	ENVMON_TEMP_SENS	4
#define	ENVMON_TEMP_IND		5
#define	ENVMON_FAN_SENS		6
#define	ENVMON_FAN_IND		7
#define	ENVMON_LED_IND		8
#define	ENVMON_KEY_SWITCH	9
#define	ENVMON_CHASSIS		10

/*
 * ENVMONTYPES is the total of all the environmental monitor types. Needs
 * to be incrementee everytime a new type is added.
 */
#define	ENVMONTYPES		11

/*
 * number of key-switches supported
 */
#define	N_KEY_SWITCHES		1

/*
 * nomenclature names used to identify LED significance
 */
#define	LED_ACT		"ACT"
#define	LED_SERVICE	"SERVICE"
#define	LED_OK2RM	"OK2RM"
#define	LED_LOCATE	"LOCATE"

#define	KEYSWITCH_NAME		"keyswitch"
#define	CHASSIS_SERIAL_NUMBER	"chassis_serial_number"

/*
 * Config file name
 */
#define	ENVMON_CONFFILE_NAME	"piclenvmon.conf"

typedef int (*ptree_vol_rdfunc_t)(ptree_rarg_t *arg, void *buf);
typedef int (*ptree_vol_wrfunc_t)(ptree_warg_t *arg, const void *buf);

typedef struct node_el {
	picl_nodehdl_t		nodeh;
	struct node_el		*next;
} node_el_t;

typedef struct node_list {
	node_el_t	*head;
	node_el_t	*tail;
} node_list_t;

/*
 * index entry for looking up sensor handle
 */
typedef struct {
	int		maxnum;	/* number of entries in handles array */
	int		num;	/* number of entries in being used */
	uchar_t		*fru_types;
	envmon_handle_t	*envhandles;
	picl_prophdl_t	*piclprhdls;
} handle_array_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _PICLENVMON_H */
