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

#ifndef	_SYS_DDI_HP_H
#define	_SYS_DDI_HP_H

/*
 * Sun DDI hotplug support definitions
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ddi_hp_cn_state_t
 *
 * Typedef of generic hotplug state machine for Hotplug Connection (CN)
 */
typedef enum {
	DDI_HP_CN_STATE_EMPTY		= 0x1000, /* Empty */
	DDI_HP_CN_STATE_PRESENT		= 0x2000, /* A Device Present */
	DDI_HP_CN_STATE_POWERED		= 0x3000, /* Powered */
	DDI_HP_CN_STATE_ENABLED		= 0x4000, /* Enabled */
	DDI_HP_CN_STATE_PORT_EMPTY	= 0x5000, /* PORT Empty */
	DDI_HP_CN_STATE_PORT_PRESENT	= 0x6000, /* A Device Node Present */
	DDI_HP_CN_STATE_OFFLINE		= 0x7000, /* Driver not attached */
	DDI_HP_CN_STATE_ATTACHED	= 0x8000, /* Device driver attached */
	DDI_HP_CN_STATE_MAINTENANCE	= 0x9000, /* Device in maintenance */
	DDI_HP_CN_STATE_ONLINE		= 0xa000  /* Device is ready */
} ddi_hp_cn_state_t;

/*
 * ddi_hp_cn_type_t
 *
 * Typedef for Hotplug Connection (CN) types.
 */
typedef enum {
	DDI_HP_CN_TYPE_VIRTUAL_PORT	= 0x1,	/* Virtual Hotplug Port */
	DDI_HP_CN_TYPE_PCI		= 0x2,	/* PCI bus slot */
	DDI_HP_CN_TYPE_PCIE		= 0x3	/* PCI Express slot */
} ddi_hp_cn_type_t;

#define	DDI_HP_CN_TYPE_STR_PORT "Virtual-Port"
/*
 * The value set to ddi_hp_cn_info_t->cn_num_dpd_on in the case of the
 * connection does not depend on any other connections.
 */
#define	DDI_HP_CN_NUM_NONE	-1

/*
 * ddi_hp_cn_info_t
 *
 * Hotplug Connection (CN) information structure
 */
typedef struct ddi_hp_cn_info {
	char			*cn_name;	/* Name of the Connection */
	/*
	 * Connection number.
	 */
	int			cn_num;
	/*
	 * Depend-on connection number;
	 * The connection number on which this connection is depending on.
	 * If this connection does not depend on any other connections
	 * under the same parent node, then it's cn_num_dpd_on is set to
	 * DDI_HP_CN_NUM_NONE.
	 */
	int			cn_num_dpd_on;

	ddi_hp_cn_type_t	cn_type;	/* Type: Port, PCI, PCIE, ... */

	/*
	 * Description string for types of Connection. Set by bus software
	 * and read by users only.
	 */
	char			*cn_type_str;
	/*
	 * The child device of this Port.
	 * It is NULL if this is a Connector.
	 */
	dev_info_t		*cn_child;

	ddi_hp_cn_state_t	cn_state;	/* Hotplug Connection state */
	time32_t		cn_last_change;	/* Last time state changed. */
} ddi_hp_cn_info_t;

typedef struct ddi_hp_property {
	char	*nvlist_buf;
	size_t	buf_size;
} ddi_hp_property_t;

#if defined(_SYSCALL32)
typedef struct ddi_hp_property32 {
	caddr32_t	nvlist_buf;
	uint32_t	buf_size;
} ddi_hp_property32_t;
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDI_HP_H */
