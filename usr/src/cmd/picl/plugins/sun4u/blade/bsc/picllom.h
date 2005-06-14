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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PICLLOM_H
#define	_PICLLOM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Log message texts
 */
#define	EM_INIT_FAILED		gettext("SUNW_picllom: init failed!\n")
#define	EM_MISSING_NODE		gettext("SUNW_picllom: no %s node!\n")
#define	EM_LOM_MISSING		\
	gettext("SUNW_picllom: Lights Out Module missing!\n")
#define	EM_LOM_NODE_MISSING	\
	gettext("SUNW_picllom: failed to locate LOM device node\n")
#define	EM_LOM_DUPLICATE	\
	gettext("SUNW_picllom: more than one LOM device node found\n")
#define	EM_CREATE_FAILED	\
	gettext("SUNW_picllom: failed to create %s node\n")
#define	EM_NO_LED_MEM		\
	gettext("SUNW_picllom: couldn't get memory for LED nodes\n")
#define	EM_LOMINFO_TREE_FAILED	\
	gettext("SUNW_picllom: failed to initialize lom nodes\n")
#define	EM_SYS_ERR		gettext("SUNW_picllom: %s: %s\n")
#define	EM_NO_CONFIG		\
	gettext("SUNW_picllom: no config file picllom.conf")

/*
 * define for super-user uid - used in credential checking
 */
#define	SUPER_USER		((uid_t)0)

/*
 * CPU temperature sensor labels
 * prtdiag relies on the labels "ambient" and "die" when reporting CPU temp.
 */
#define	CPU_ENCLOSURE		"Enclosure"
#define	CPU_AMBIENT		"Ambient"
#define	CPU_DIE			"Die"

/*
 * Constants for some PICL properties
 */
#define	PICL_VOLTS_SHUTDOWN	"VoltageShutdown"

/*
 * Config file name
 */
#define	LOM_CONFFILE_NAME	"picllom.conf"

/*
 * lom device mnior name
 */
#define	LOM_DEV_MINOR_NAME	":lom"

typedef int16_t tempr_t;

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

#ifdef	__cplusplus
}
#endif

#endif	/* _PICLLOM_H */
