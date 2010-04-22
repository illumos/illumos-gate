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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_SCSI_IMPL_SCSI_SAS_H
#define	_SYS_SCSI_IMPL_SCSI_SAS_H

#include <sys/types.h>
#include <sys/scsi/impl/usmp.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)
/*
 * Phymap support
 */
typedef struct __sas_phymap    sas_phymap_t;
typedef enum { PHYMAP_MODE_SIMPLE } sas_phymap_mode_t;
typedef void (*sas_phymap_activate_cb_t)
		(void *phymap_priv, char *ua, void **ua_privp);
typedef void (*sas_phymap_deactivate_cb_t)
		(void *phymap_priv, char *ua, void *ua_priv);

extern int	sas_phymap_create(dev_info_t		*hba_dip,
				int			settle_usec,
				sas_phymap_mode_t	mode,
				void			*mode_argument,
				void			*phymap_priv,
				sas_phymap_activate_cb_t activate_cb,
				sas_phymap_deactivate_cb_t deactivate_cb,
				sas_phymap_t		**phymapp);
void		sas_phymap_destroy(sas_phymap_t		*phymap);

extern int	sas_phymap_phy_add(sas_phymap_t		*phymap,
				int			phy,
				uint64_t		local_sas_address,
				uint64_t		remote_sas_address);
extern int	sas_phymap_phy_rem(sas_phymap_t		*phymap,
				int			phy);

extern char	*sas_phymap_lookup_ua(sas_phymap_t	*phymap,
				uint64_t		local_sas_address,
				uint64_t		remote_sas_address);
extern void	*sas_phymap_lookup_uapriv(sas_phymap_t	*phymap,
				char			*ua);

extern char	*sas_phymap_phy2ua(sas_phymap_t		*phymap,
				int			phy);
void		sas_phymap_ua_free(char	*);

extern int	sas_phymap_uahasphys(sas_phymap_t	*phymap,
				char			*ua);

typedef struct __sas_phymap_phys	sas_phymap_phys_t;
extern sas_phymap_phys_t *sas_phymap_ua2phys(sas_phymap_t *phymap,
				char			*ua);
extern int	sas_phymap_phys_next(sas_phymap_phys_t	*phys);
void		sas_phymap_phys_free(sas_phymap_phys_t	*phys);
#endif /* defined(_KERNEL) */



#define	KSTAT_SAS_PHY_CLASS	"SAS_phy_stat"
/*
 * Format of the ks_name field for SAS Phy Stat
 *
 * driver_name.initiator_port_SAS_address.initiator_port_instance_number.phyid
 * Example: pmcs.5000c50000d756aa.2.0
 *
 * driver_name:
 *     driver name from di_driver_name() on SAS initiator port devinfo node.
 *
 * initiator_port_SAS_address:
 *     SAS address of the initiator port that phy stat is reported for.
 *
 * initiator_port_instance_number:
 *     instance number of the initiator port that phy stat is reported for.
 *
 * phyid:
 *     prop phyIdentifier under initiator port node.
 */

/* Port Protocol - kstat structure definition */
typedef struct sas_port_protocol_stats {
	kstat_named_t	seconds_since_last_reset;
	kstat_named_t	input_requests;
	kstat_named_t	output_requests;
	kstat_named_t	control_requests;
	kstat_named_t	input_megabytes;
	kstat_named_t	output_megabytes;
} sas_port_protocol_stats_t;

/* Port - kstat structure definition */
typedef struct sas_port_stats {
	kstat_named_t	seconds_since_last_reset;
	kstat_named_t	tx_frames;
	kstat_named_t	tx_words;
	kstat_named_t	rx_frames;
	kstat_named_t	rx_words;
} sas_port_stats_t;

/* PHY - kstat structure definition */
typedef struct sas_phy_stats {
	kstat_named_t	seconds_since_last_reset;
	kstat_named_t	tx_frames;
	kstat_named_t	tx_words;
	kstat_named_t	rx_frames;
	kstat_named_t	rx_words;
	kstat_named_t	invalid_dword_count;
	kstat_named_t	running_disparity_error_count;
	kstat_named_t	loss_of_dword_sync_count;
	kstat_named_t	phy_reset_problem_count;
} sas_phy_stats_t;

/*
 * Supported Protocol property
 */
#define	SAS_PROTOCOL_SSP	0x00000001
#define	SAS_PROTOCOL_STP	0x00000010
#define	SAS_PROTOCOL_SMP	0x00000100
#define	SAS_PROTOCOL_SATA	0x00001000


/*
 * Definition - Negotiated Physical Link Rate
 * Based on Table 288 (Section 10.4.3.10) of the spec (SAS-2 r-15), these
 * constants represent "Negotiated physical link rate"
 * (and implicitly the State of the phy).
 */
#define	SAS_LINK_RATE_UNKNOWN		0x0 /* Phy is enabled. */
					    /* Speed is unknown */
#define	SAS_LINK_RATE_DISABLED		0x1 /* Phy is disabled. */
					    /* Speed is undefined */
#define	SAS_LINK_RATE_FAILED		0x2 /* Phy is enabled. */
					    /* Failed speed negotiation. */
#define	SAS_LINK_RATE_SATASPINUP	0x3 /* Phy is enabled. */
					    /* Detected a SATA device and */
					    /* entered the SATA Spinup hold */
					    /* state */
#define	SAS_LINK_RATE_SATAPORTSEL	0x4 /* Phy enabled. */
					    /* The phy is attached to a */
					    /* Port Selector (SATA-2.6). */
#define	SAS_LINK_RATE_RESET_IN_PROGRESS	0x5 /* Phy is enabled. */
					    /* Expander is performing SMP */
					    /* PHY CONTROL Link/Hard Reset */
#define	SAS_LINK_RATE_PHY_UNSUPPORTED	0x6 /* Phy is enabled. */
					    /* Unsupported phy settings */
#define	SAS_LINK_RATE_RESERVED		0x7 /* Undefined. Reserved. */
#define	SAS_LINK_RATE_1_5GBIT		0x8 /* Phy enabled at 1.5 GBit/sec */
#define	SAS_LINK_RATE_3GBIT		0x9 /* Phy enabled at 3 GBit/sec */
#define	SAS_LINK_RATE_6GBIT		0xA /* Phy enabled at 6 GBit/sec. */


/*
 * Definition - "phy-info" property
 *
 * The property is an nvlist_array that represents an array of the
 * nvlists on a per HBA basis. The individual elements of the array
 * (the nvlists) represent the following properties for each phy of the HBA
 */
#define	SAS_PHY_INFO		"phy-info"		/* Phy property name */
#define	SAS_PHY_INFO_NVL	"phy-info-nvl"		/* NVL array name */

#define	SAS_PHY_ID		"PhyIdentifier"		/* DATA_TYPE_UINT8 */
#define	SAS_NEG_LINK_RATE	"NegotiatedLinkRate"	/* DATA_TYPE_INT8 */
#define	SAS_PROG_MIN_LINK_RATE	"ProgrammedMinLinkRate"	/* DATA_TYPE_INT8 */
#define	SAS_HW_MIN_LINK_RATE	"HardwareMinLinkRate"	/* DATA_TYPE_INT8 */
#define	SAS_PROG_MAX_LINK_RATE	"ProgrammedMaxLinkRate"	/* DATA_TYPE_INT8 */
#define	SAS_HW_MAX_LINK_RATE	"HardwareMaxLinkRate"	/* DATA_TYPE_INT8 */


/*
 * Phy-mask property names for the target port, attached port and receptacle
 */
#define	SCSI_ADDR_PROP_TARGET_PORT_PM	"target-port-pm"
#define	SCSI_ADDR_PROP_ATTACHED_PORT_PM	"attached-port-pm"
#define	SCSI_HBA_PROP_RECEPTACLE_PM	"receptacle-pm"

/*
 * Target port depth property names - Indicates the number of expanders
 * between the initiator port and the target port
 */
#define	SCSI_ADDR_PROP_TARGET_PORT_DEPTH	"target-port-depth"


/*
 * Event definitions
 */
/* Event Class */
#define	EC_HBA				"EC_hba"

/* Event Sub-Class */
#define	ESC_SAS_HBA_PORT_BROADCAST	"ESC_sas_hba_port_broadcast"
/* Event Types for above Subclass */
#define	SAS_PORT_BROADCAST_CHANGE	"port_broadcast_change"
#define	SAS_PORT_BROADCAST_SES		"port_broadcast_ses"
#define	SAS_PORT_BROADCAST_D24_0	"port_broadcast_d24_0"
#define	SAS_PORT_BROADCAST_D27_4	"port_broadcast_d27_4"
#define	SAS_PORT_BROADCAST_D01_4	"port_broadcast_d01_4"
#define	SAS_PORT_BROADCAST_D04_7	"port_broadcast_d04_7"
#define	SAS_PORT_BROADCAST_D16_7	"port_broadcast_d16_7"
#define	SAS_PORT_BROADCAST_D29_7	"port_broadcast_d29_7"

/* Event Sub-Class */
#define	ESC_SAS_PHY_EVENT		"ESC_sas_phy_event"
/* Event Types for above Subclass */
#define	SAS_PHY_ONLINE			"port_online"
#define	SAS_PHY_OFFLINE			"port_offline"
#define	SAS_PHY_REMOVE			"port_remove"

/* Event Payload Names */
#define	SAS_DRV_INST			"driver_instance"
#define	SAS_PORT_ADDR			"port_address"
#define	SAS_DEVFS_PATH			"devfs_path"
#define	SAS_EVENT_TYPE			"event_type"
#define	SAS_LINK_RATE			"link_rate"
/* SAS_PHY_ID - Defined Above */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_IMPL_SCSI_SAS_H */
