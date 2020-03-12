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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2020 Joyent, Inc.
 */

#ifndef _TOPO_HC_H
#define	_TOPO_HC_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Allowable hardware component names for hc FMRIs
 */
#define	BANK		"bank"
#define	BAY		"bay"
#define	BLADE		"blade"
#define	BRANCH		"branch"
#define	CMP		"CMP"
#define	CENTERPLANE	"centerplane"
#define	CHASSIS		"chassis"
#define	CHIP		"chip"
#define	CHIPSET		"chipset"
#define	CORE		"core"
#define	STRAND		"strand"
#define	CHIP_SELECT	"chip-select"
#define	CONTROLLER	"controller"
#define	CPU		"cpu"
#define	CPUBOARD	"cpuboard"
#define	DIMM		"dimm"
#define	DISK		"disk"
#define	DRAM		"dram"
#define	DRAMCHANNEL	"dram-channel"
#define	FAN		"fan"
#define	FANBOARD	"fanboard"
#define	FANMODULE	"fanmodule"
#define	HBA		"hba"
#define	HOSTBRIDGE	"hostbridge"
#define	INTERCONNECT	"interconnect"
#define	IOBOARD		"ioboard"
#define	IPORT		"iport"
#define	MEMBOARD	"memboard"
#define	MEMORYBUFFER	"memory-buffer"
#define	MEMORYCONTROL	"memory-controller"
#define	MICROCORE	"micro-core"
#define	MOTHERBOARD	"motherboard"
#define	NIU		"niu"
#define	NIUFN		"niufn"
#define	NVME		"nvme"
#define	PCI_BUS		"pcibus"
#define	PCI_DEVICE	"pcidev"
#define	PCI_FUNCTION    "pcifn"
#define	PCIEX_BUS	"pciexbus"
#define	PCIEX_DEVICE	"pciexdev"
#define	PCIEX_FUNCTION  "pciexfn"
#define	PCIEX_ROOT	"pciexrc"
#define	PCIEX_SWUP	"pciexswu"
#define	PCIEX_SWDWN	"pciexswd"
#define	PORT		"port"
#define	POWERBOARD	"powerboard"
#define	POWERMODULE	"powermodule"
#define	PSU		"psu"
#define	RANK		"rank"
#define	RECEPTACLE	"receptacle"
#define	RISER		"riser"
#define	SASEXPANDER	"sas-expander"
#define	SHELF		"shelf"
#define	SCSI_DEVICE	"scsi-device"
#define	SES_ENCLOSURE	"ses-enclosure"
#define	SLOT		"slot"
#define	SMP_DEVICE	"smp-device"
#define	SP		"sp"
#define	SUBCHASSIS	"subchassis"
#define	SYSTEMBOARD	"systemboard"
#define	TRANSCEIVER	"transceiver"
#define	UFM		"ufm"
#define	USB_DEVICE	"usb-device"
#define	XAUI		"xaui"
#define	XFP		"xfp"

/*
 * Allowable hc node property group and property names
 */
#define	TOPO_PGROUP_IO		"io"
#define	TOPO_IO_DEVTYPE		"devtype"
#define	TOPO_IO_DRIVER		"driver"
#define	TOPO_IO_INSTANCE	"instance"
#define	TOPO_IO_MODULE		"module"
#define	TOPO_IO_DEV		"dev"
#define	TOPO_IO_DEVID		"devid"
#define	TOPO_IO_DEV_PATH	"devfs-path"
#define	TOPO_IO_AP_PATH		"ap-path"
#define	TOPO_IO_PHYS_PATH	"phys-path"

#define	TOPO_PGROUP_PCI		"pci"
#define	TOPO_PCI_VENDID		"vendor-id"
#define	TOPO_PCI_VENDNM		"vendor-name"
#define	TOPO_PCI_SUBSYSNM	"subsystem-name"
#define	TOPO_PCI_DEVID		"device-id"
#define	TOPO_PCI_DEVNM		"device-name"
#define	TOPO_PCI_EXCAP		"extended-capabilities"
#define	TOPO_PCI_BDF		"BDF"
#define	TOPO_PCI_CLASS		"class-code"
#define	TOPO_PCI_AADDR		"assigned-addresses"

#define	TOPO_PCI_MAX_WIDTH	"link-maximum-width"
#define	TOPO_PCI_CUR_WIDTH	"link-current-width"
#define	TOPO_PCI_MAX_SPEED	"link-maximum-speed"
#define	TOPO_PCI_CUR_SPEED	"link-current-speed"
#define	TOPO_PCI_SUP_SPEED	"link-supported-speeds"
#define	TOPO_PCI_ADMIN_SPEED	"link-admin-target-speed"

#define	TOPO_PGROUP_BINDING	"binding"
#define	TOPO_BINDING_OCCUPANT	"occupant-path"
#define	TOPO_BINDING_DRIVER	"driver"
#define	TOPO_BINDING_DEVCTL	"devctl"
#define	TOPO_BINDING_ENCLOSURE	"enclosure"
#define	TOPO_BINDING_SLOT	"slot"
#define	TOPO_BINDING_PORT	"port"
#define	TOPO_BINDING_PARENT_DEV	"parent-device"

#define	TOPO_PGROUP_STORAGE	"storage"
#define	TOPO_STORAGE_INITIATOR_PORT	"initiator-port"
#define	TOPO_STORAGE_INITIATOR_PORT_PM	"initiator-port-pm"
#define	TOPO_STORAGE_TARGET_PORT	"target-port"
#define	TOPO_STORAGE_TARGET_PORT_L0ID	"target-port-l0id"
#define	TOPO_STORAGE_TARGET_PORT_L0IDS	"target-port-l0ids"
#define	TOPO_STORAGE_ATTACHED_PORT	"attached-port"
#define	TOPO_STORAGE_TARGET_PORT_PM	"target-port-pm"
#define	TOPO_STORAGE_ATTACHED_PORT_PM	"attached-port-pm"
#define	TOPO_STORAGE_DEVID		"devid"
#define	TOPO_STORAGE_LUN64		"lun64"
#define	TOPO_STORAGE_DEVICE_TYPE	"inquiry-device-type"
#define	TOPO_STORAGE_MANUFACTURER	"manufacturer"
#define	TOPO_STORAGE_MODEL		"model"
#define	TOPO_STORAGE_FIRMWARE_REV	"firmware-revision"
#define	TOPO_STORAGE_SAS_PHY_MASK	"receptacle-pm"
#define	TOPO_STORAGE_SAS_CONNECTOR_TYPE	"sas-connector-type"

#define	TOPO_PGROUP_SES		"ses"
/* Applied  any SES standard related topo node. */
#define	TOPO_PROP_NODE_ID	"node-id"
#define	TOPO_PROP_TARGET_PATH	"target-path"
#define	TOPO_PROP_SES_DEVID	"ses-devid"
#define	TOPO_PROP_SES_DEV_PATH	"ses-devfs-path"
#define	TOPO_PROP_SES_PHYS_PATH	"ses-phys-path"
#define	TOPO_PROP_SES_TARGET_PORT "ses-target-port"

#define	TOPO_PGROUP_SMP		"smp"
/* host SMP target related info for an expander node. */
#define	TOPO_PROP_SMP_DEVID	"smp-devid"
#define	TOPO_PROP_SMP_DEV_PATH	"smp-devfs-path"
#define	TOPO_PROP_SMP_PHYS_PATH	"smp-phys-path"
#define	TOPO_PROP_SMP_TARGET_PORT	"smp-target-port"
#define	TOPO_PROP_SAS_ADDR	"sas-address"
#define	TOPO_PROP_PHY_COUNT	"phy-count"
#define	TOPO_PROP_PATHS		"paths"
#define	TOPO_PROP_CHASSIS_TYPE	"chassis-type"
#define	TOPO_PROP_SAS_PHY_MASK	"phy-mask"
#define	TOPO_PROP_SAS_CONNECTOR_TYPE	"sas-connector-type"

#define	TOPO_PGROUP_PORT	"port"
#define	TOPO_PROP_PORT_TYPE	"type"
#define	TOPO_PROP_PORT_TYPE_SFF	"sff"
#define	TOPO_PROP_PORT_TYPE_USB	"usb"
#define	TOPO_PROP_PORT_TYPE_UNKNOWN	"unknown"

#define	TOPO_PGROUP_TRANSCEIVER	"transceiver"
#define	TOPO_PROP_TRANSCEIVER_TYPE	"type"
#define	TOPO_PROP_TRANSCEIVER_USABLE	"usable"

#define	TOPO_PGROUP_SFF_TRANSCEIVER	"sff-transceiver"
#define	TOPO_PORT_SFF_TRANSCEIVER_VENDOR	"vendor"
#define	TOPO_PORT_SFF_TRANSCEIVER_PN	"part-number"
#define	TOPO_PORT_SFF_TRANSCEIVER_REV	"revision"
#define	TOPO_PORT_SFF_TRANSCEIVER_SN	"serial-number"

#define	TOPO_PGROUP_USB_PORT	"usb-port"
#define	TOPO_PROP_USB_PORT_LPORTS	"logical-ports"
#define	TOPO_PROP_USB_PORT_VERSIONS	"usb-versions"
#define	TOPO_PROP_USB_PORT_TYPE		"port-type"
#define	TOPO_PROP_USB_PORT_ATTRIBUTES	"port-attributes"
#define	TOPO_PROP_USB_PORT_A_VISIBLE	"user-visible"
#define	TOPO_PROP_USB_PORT_A_CONNECTED	"port-connected"
#define	TOPO_PROP_USB_PORT_A_DISCONNECTED	"port-disconnected"
#define	TOPO_PROP_USB_PORT_A_EXTERNAL	"external-port"
#define	TOPO_PROP_USB_PORT_A_INTERNAL	"internal-port"
#define	TOPO_PROP_USB_PORT_NATTRS	5

#define	TOPO_PGROUP_USB_PROPS	"usb-properties"
#define	TOPO_PGROUP_USB_PROPS_VID	"usb-vendor-id"
#define	TOPO_PGROUP_USB_PROPS_PID	"usb-product-id"
#define	TOPO_PGROUP_USB_PROPS_REV	"usb-revision-id"
#define	TOPO_PGROUP_USB_PROPS_VNAME	"usb-vendor-name"
#define	TOPO_PGROUP_USB_PROPS_PNAME	"usb-product-name"
#define	TOPO_PGROUP_USB_PROPS_SN	"usb-serialno"
#define	TOPO_PGROUP_USB_PROPS_VERSION	"usb-version"
#define	TOPO_PGROUP_USB_PROPS_SPEED	"usb-speed"
#define	TOPO_PGROUP_USB_PROPS_PORT	"usb-port"
#define	TOPO_PGROUP_USB_PROPS_SUPPORTED_SPEEDS	"usb-supported-speeds"
#define	TOPO_PGROUP_USB_PROPS_MIN_SPEED	"usb-minimum-speed"


/*
 * These properties will exist on nodes enumerated by the ipmi module. They
 * are consumed by the fac_prov_ipmi module
 */
#define	TOPO_PROP_IPMI_ENTITY_ID	"entity-id"
#define	TOPO_PROP_IPMI_ENTITY_INST	"entity-instance"

/*
 * This property can be statically set in a map file and is consumed by the
 * fac_prov_ipmi module.
 */
#define	TOPO_PROP_IPMI_ENTITY_LIST	"entity-list"

/*
 * These properties can be used to describe the network configuration of a
 * given hardware components.  They're currently used to describe the
 * network config on the service processor (sp)
 */
#define	TOPO_PGROUP_NETCFG		"network-config"
#define	TOPO_PROP_NETCFG_MACADDR	"mac-address"
#define	TOPO_PROP_NETCFG_VLAN_ID	"vlan-id"
#define	TOPO_PROP_NETCFG_IPV4_ADDR	"ipv4-address"
#define	TOPO_PROP_NETCFG_IPV4_SUBNET	"ipv4-subnet"
#define	TOPO_PROP_NETCFG_IPV4_GATEWAY	"ipv4-gateway"
#define	TOPO_PROP_NETCFG_IPV4_TYPE	"ipv4-config-type"
#define	TOPO_PROP_NETCFG_IPV6_ADDR	"ipv6-address"
#define	TOPO_PROP_NETCFG_IPV6_ROUTES	"ipv6-routes"
#define	TOPO_PROP_NETCFG_IPV6_TYPE	"ipv6-config-type"

/* Possible values for TOPO_PROP_NETCFG_TYPE */
#define	TOPO_NETCFG_TYPE_UNKNOWN	"unknown"
#define	TOPO_NETCFG_TYPE_STATIC		"static"
#define	TOPO_NETCFG_TYPE_DHCP		"dhcp"

#define	TOPO_PGROUP_SLOT		"slot"
#define	TOPO_PROP_SLOT_TYPE		"slot-type"

#define	TOPO_PGROUP_DIMM_SLOT		"dimm-slot"
#define	TOPO_PROP_DIMM_SLOT_FORM	"form-factor"
#define	TOPO_DIMM_SLOT_FORM_DIMM	"DIMM"
#define	TOPO_DIMM_SLOT_FORM_SODIMM	"SODIMM"
#define	TOPO_DIMM_SLOT_FORM_FBDIMM	"FBDIMM"

#define	TOPO_PGROUP_DIMM_PROPS		"dimm-properties"
#define	TOPO_PROP_DIMM_TYPE
#define	TOPO_DIMM_TYPE_UNKNOWN		"UNKNOWN"
#define	TOPO_DIMM_TYPE_DDR		"DDR"
#define	TOPO_DIMM_TYPE_DDR2		"DDR2"
#define	TOPO_DIMM_TYPE_DDR3		"DDR3"
#define	TOPO_DIMM_TYPE_DDR4		"DDR4"
#define	TOPO_DIMM_TYPE_LPDDR		"LPDDR"
#define	TOPO_DIMM_TYPE_LPDDR2		"LPDDR2"
#define	TOPO_DIMM_TYPE_LPDDR3		"LPDDR3"
#define	TOPO_DIMM_TYPE_LPDDR4		"LPDDR4"

#define	TOPO_PGROUP_MOTHERBOARD		"motherboard-properties"
#define	TOPO_PROP_MB_MANUFACTURER	"manufacturer"
#define	TOPO_PROP_MB_PRODUCT		"product-id"
#define	TOPO_PROP_MB_ASSET		"asset-tag"
#define	TOPO_PROP_MB_FIRMWARE_VENDOR	"firmware-vendor"
#define	TOPO_PROP_MB_FIRMWARE_RELDATE	"firmware-release-date"

#define	TOPO_PGROUP_UFM			"ufm-properties"
#define	TOPO_PROP_UFM_DESCR		"ufm-description"

#define	TOPO_PGROUP_UFM_SLOT		"ufm-slot-properties"
#define	TOPO_PROP_UFM_SLOT_VERSION	"ufm-slot-version"
#define	TOPO_PROP_UFM_SLOT_MODE		"ufm-slot-mode"
#define	TOPO_PROP_UFM_SLOT_ACTIVE	"ufm-slot-active"

#define	TOPO_PGROUP_DATALINK		"datalink"
#define	TOPO_PGROUP_DATALINK_PMAC	"primary-mac-address"
#define	TOPO_PGROUP_DATALINK_LINK_SPEED		"link-speed"
#define	TOPO_PGROUP_DATALINK_LINK_STATUS	"link-status"
#define	TOPO_PGROUP_DATALINK_LINK_STATUS_UP	"up"
#define	TOPO_PGROUP_DATALINK_LINK_STATUS_DOWN	"down"
#define	TOPO_PGROUP_DATALINK_LINK_STATUS_UNKNOWN	"unknown"
#define	TOPO_PGROUP_DATALINK_LINK_DUPLEX	"link-duplex"
#define	TOPO_PGROUP_DATALINK_LINK_DUPLEX_FULL	"full"
#define	TOPO_PGROUP_DATALINK_LINK_DUPLEX_HALF	"half"
#define	TOPO_PGROUP_DATALINK_LINK_DUPLEX_UNKNOWN	"unknown"
#define	TOPO_PGROUP_DATALINK_LINK_NAME		"link-name"

#define	TOPO_PGROUP_NVME		"nvme-properties"
#define	TOPO_PROP_NVME_VER		"nvme-version"

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_HC_H */
