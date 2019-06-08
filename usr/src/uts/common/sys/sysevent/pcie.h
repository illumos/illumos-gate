/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#ifndef _SYS_SYSEVENT_PCIE_H
#define	_SYS_SYSEVENT_PCIE_H

/*
 * PCIe System Event payloads
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Event schema for ESC_PCIE_LINK_STATE
 *
 *	Event Class	- EC_PCIE
 *	Event Sub-Class	- ESC_PCIE_LINK_STATE
 *
 *	Attribute Name	- PCIE_EV_DETECTOR_PATH
 *	Attribute Type	- SE_DATA_TYPE_STRING
 *	Attribute Value	- [devfs path of the node that detected the change]
 *
 *	Attribute Name	- PCIE_EV_CHILD_PATH
 *	Attribute Type	- SE_DATA_TYPE_STRING
 *	Attribute Value	- [devfs path of the updated child]
 *
 *	Attribute Name	- PCIE_EV_DETECTOR_FLAGS
 *	Attribute Type	- SE_DATA_TYPE_UINT64
 *	Attribute Value	- [PCIe flags that indicate the type of change]
 */

#define	PCIE_EV_DETECTOR_PATH	"detector_path"
#define	PCIE_EV_CHILD_PATH	"child_path"
#define	PCIE_EV_DETECTOR_FLAGS	"detector_flags"

#define	PCIE_EV_DETECTOR_FLAGS_LBMS	0x01
#define	PCIE_EV_DETECTOR_FLAGS_LABS	0x02

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SYSEVENT_PCIE_H */
