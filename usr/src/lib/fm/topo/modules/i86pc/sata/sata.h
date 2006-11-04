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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SATA_H
#define	_SATA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <fm/libtopo.h>

/* Topo plugin version */
#define	SATA_VERSION			1

/* The names of the two nodes the plugin creates: */
#define	SATA_DISK			DISK /* from topo_hc.h */

#define	TOPO_STORAGE_PGROUP		"storage"

/* Properties added to the "storage" pgroup: */
#define	TOPO_STORAGE_LOGICAL_DISK_NAME	"logical-disk"
#define	TOPO_STORAGE_MODEL		"disk-model"
#define	TOPO_STORAGE_MANUFACTURER	"disk-manufacturer"
#define	TOPO_STORAGE_SERIAL_NUM		"disk-serial-number"
#define	TOPO_STORAGE_FIRMWARE_REV	"disk-firmware-revision"
#define	TOPO_STORAGE_CAPACITY		"disk-capacity-in-bytes"

/* Properties added to the machine-specific properties pgroup */
#define	SATA_IND_NAME			"indicator-name"
#define	SATA_IND_ACTION			"indicator-action"
#define	SATA_INDRULE_STATES		"indicator-rule-states"
#define	SATA_INDRULE_ACTIONS		"indicator-rule-actions"

#ifndef MAX
#define	MAX(x, y)	((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define	MIN(x, y)	((x) < (y) ? (x) : (y))
#endif

#define	MAX_PROPERTIES			10
#define	MAX_INDICATORS			10
#define	MAX_SATA_DEV_PROPS		48 + 1 /* the terminator */
#define	MAX_ACTION_RULES		10

/*
 * The sata_dev_prop structure captures information about the disk and
 * indicators associated with that disk. The actions specified are
 * processed by fmd(1M) modules (DEs/Agents) that perform the actions
 * when the disk states transition according to the action_ruleset
 * entries.
 */
typedef struct sata_dev_prop {
	const char *ap_node;
	const char *label;
	struct props {
		const char *name;
		const char *value;
	} properties[MAX_PROPERTIES + 1];
	struct disk_indicator {
		const char *indicator;
		const char *action;
	} indicators[MAX_INDICATORS + 1];
} sata_dev_prop_t;

typedef struct action_ruleset {
	const char	*states;	/* "start>end" */
	const char	*actions;	/* "action['&'action]* */
} action_ruleset_t;

struct sata_machine_specific_properties {
	/*
	 * The SMBIOS Product Name to which these properties apply
	 */
	const char *machname;
	/*
	 * The private pgroup on the node to which to properties will
	 * be added
	 */
	const char *pgroup;
	sata_dev_prop_t		sata_dev_props[MAX_SATA_DEV_PROPS];
	action_ruleset_t	action_rules[MAX_ACTION_RULES];
};

#ifdef __cplusplus
}
#endif

#endif /* _SATA_H */
