/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_CONFIG_H
#define	_EMLXS_CONFIG_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	EMLXS_CFG_STR_SIZE	32
#define	EMLXS_CFG_HELP_SIZE	80

typedef struct emlxs_config
{
	char		string[EMLXS_CFG_STR_SIZE];
	uint32_t	low;
	uint32_t	hi;
	uint32_t	def;
	uint32_t	current;
	uint32_t	flags;
	char		help[EMLXS_CFG_HELP_SIZE];
} emlxs_config_t;


typedef enum emlxs_cfg_parm
{
	CFG_CONSOLE_NOTICES,	/* console-notices */
	CFG_CONSOLE_WARNINGS,	/* console-warnings */
	CFG_CONSOLE_ERRORS,	/* console-errors */
	CFG_CONSOLE_DEBUGS,	/* console-debugs (hidden) */
	CFG_LOG_NOTICES,	/* log-notices */
	CFG_LOG_WARNINGS,	/* log-warnings */
	CFG_LOG_ERRORS,		/* log-errors */
	CFG_LOG_DEBUGS,		/* log-debugs (hidden) */
	CFG_NUM_IOCBS,		/* num-iocbs */
	CFG_MAX_XFER_SIZE,	/* max-xfer-size */
	CFG_UB_BUFS,		/* ub-bufs */
	CFG_NETWORK_ON,		/* network-on */
	CFG_ACK0,		/* ack0 */
	CFG_TOPOLOGY,		/* topology */
	CFG_LINK_SPEED,		/* link-speed */
	CFG_NUM_NODES,		/* num-nodes */
	CFG_CR_DELAY,		/* cr-delay */
	CFG_CR_COUNT,		/* cr-count */
	CFG_ASSIGN_ALPA,	/* assign-alpa */
	CFG_ADISC_SUPPORT,	/* adisc-support */
	CFG_PM_SUPPORT,		/* pm-support */
	CFG_PM_IDLE,		/* pm-idle */
	CFG_FW_CHECK,		/* fw-check (hidden) */
	CFG_TRI_REQUIRED,	/* tri-required (hidden) */
	CFG_DISC_TIMEOUT,	/* discovery-timeout (hidden) */
	CFG_LINKUP_TIMEOUT,	/* linkup-timeout (hidden) */
	CFG_LINKUP_DELAY,	/* linkup-delay */
	CFG_OFFLINE_TIMEOUT,	/* offline-timeout (hidden) */
	CFG_LILP_ENABLE,	/* enable-lilp (hidden) */
	CFG_PCI_MAX_READ,	/* pci-max-read */
	CFG_HEARTBEAT_ENABLE,	/* heartbeat-enable (hidden) */
	CFG_RESET_ENABLE,	/* reset-enable (hidden) */
	CFG_TIMEOUT_ENABLE,	/* timeout-enable (hidden) */
	CFG_NUM_IOTAGS,		/* num-iotags (hidden) */
#ifdef NODE_THROTTLE_SUPPORT
	CFG_TGT_DEPTH,		/* target-depth */
#endif /* NODE_THROTTLE_SUPPORT */

	CFG_MEM_DYNAMIC,	/* mem-dynamic (hidden) */

#ifdef FMA_SUPPORT
	CFG_FM_CAPS,		/* fm-capable (hidden) */
#endif	/* FMA_SUPPORT */


#ifdef MAX_RRDY_SUPPORT
	CFG_MAX_RRDY,		/* max-rrdy (hidden) */
#endif	/* MAX_RRDY_SUPPORT */

#ifdef MSI_SUPPORT
	CFG_MSI_MODE,		/* msi-mode (hidden) */
#endif	/* MSI_SUPPORT */

	CFG_SLI_MODE,		/* sli-mode (hidden) */
	CFG_NPIV_ENABLE,	/* enable-npiv */
	CFG_VPORT_RESTRICTED,	/* vport-restrict-login */
	CFG_NPIV_DELAY,		/* enable-npiv-delay (hidden) */

#ifdef DHCHAP_SUPPORT
	CFG_AUTH_ENABLE, 	/* enable-auth */
	CFG_AUTH_E2E,		/* auth-e2e */
	CFG_AUTH_NPIV,		/* auth-npiv (hidden) */
	CFG_AUTH_TMO,    	/* auth-tmo (hidden) */
	CFG_AUTH_MODE,   	/* auth-mode (hidden) */
	CFG_AUTH_BIDIR, 	/* auth-bidir (hidden) */
	CFG_AUTH_TYPE,   	/* auth-type (hidden) */
	CFG_AUTH_HASH,   	/* auth-hash (hidden) */
	CFG_AUTH_GROUP,  	/* auth-group (hidden) */
	CFG_AUTH_INTERVAL,  	/* auth-interval (hidden) */
#endif	/* DHCHAP_SUPPORT */

#ifdef SFCT_SUPPORT
	CFG_DTM_ENABLE,		/* enable-dtm (hidden) */
	CFG_TARGET_MODE,	/* target-mode */
	CFG_VPORT_MODE_MASK,	/* vport-mode-mask (hidden) */
	CFG_FCT_QDEPTH,		/* fct-queue-depth */
#endif /* SFCT_SUPPORT */
	CFG_NUM_WQ,		/* num-wq (hidden) */
	CFG_PERSIST_LINKDOWN,	/* persist-linkdown */
	CFG_ENABLE_PATCH,	/* enable-patch (hidden) */
	CFG_FAST_TGT_RESET,	/* fast-tgt-reset (hidden) */
	CFG_FAST_TGT_RESET_TMR,	/* fast-tgt-reset-timer (hidden) */

	CFG_FCF_SOLICIT_DELAY,	/* fcf-solicit-delay (hidden) */
	CFG_FCF_FAILOVER_DELAY,	/* fcf-failover-delay (hidden) */
	CFG_FCF_RESOLICIT_DELAY, /* fcf-resolicit-delay (hidden) */
	CFG_FCF_RPI_IDLE_TIMEOUT, /* fcf-rpi-idle-timeout (hidden) */

	CFG_DELAY_DISCOVERY,	/* delay-discovery (hidden) */
	CFG_RQD_MODE,		/* rqd (hidden) */
	CFG_PERF_HINT,		/* perf-hint (hidden) */

	NUM_CFG_PARAM

} emlxs_cfg_parm_t;

#define	PARM_HIDDEN	0x80000000



#ifdef DEF_ICFG

/*
 * The entries in this array must be in the exact order
 * defined in emlxs_cfg_parm_t
 */
emlxs_config_t  emlxs_cfg[] = {
	/* CFG_CONSOLE_NOTICES */
	{"console-notices",
		0, 0xffffffff, 0, 0,
		PARM_DYNAMIC | PARM_HEX,
	"Verbose mask for notice messages to the console."},

	/* CFG_CONSOLE_WARNINGS */
	{"console-warnings",
		0, 0xffffffff, 0, 0,
		PARM_DYNAMIC | PARM_HEX,
	"Verbose mask for warning messages to the console."},

	/* CFG_CONSOLE_ERRORS */
	{"console-errors",
		0, 0xffffffff, 0, 0,
		PARM_DYNAMIC | PARM_HEX,
	"Verbose mask for error messages to the console."},

	/* CFG_CONSOLE_DEBUGS */
	{"console-debugs",
		0, 0xffffffff, 0, 0,
		PARM_DYNAMIC | PARM_HEX | PARM_HIDDEN,
	"Verbose mask for debugging messages to the console."},

	/* CFG_LOG_NOTICES */
	{"log-notices",
		0, 0xffffffff, 0xffffffff, 0,
		PARM_DYNAMIC | PARM_HEX,
	"Verbose mask for notice messages to the messages file."},

	/* CFG_LOG_WARNINGS */
	{"log-warnings",
		0, 0xffffffff, 0xffffffff, 0,
		PARM_DYNAMIC | PARM_HEX,
	"Verbose mask for warning messages to the messages file."},

	/* CFG_LOG_ERRORS */
	{"log-errors",
		0, 0xffffffff, 0xffffffff, 0,
		PARM_DYNAMIC | PARM_HEX,
	"Verbose mask for error messages to the messages file."},

	/* CFG_LOG_DEBUGS */
	{"log-debugs",
		0, 0xffffffff, 0, 0,
		PARM_DYNAMIC | PARM_HEX | PARM_HIDDEN,
	"Verbose mask for debugging messages to the messages file."},


	/* CFG_NUM_IOCBS */
	{"num-iocbs",
		128, 10240, 1024, 0,
		PARM_DYNAMIC_RESET,
	"Number of IOCB buffers the driver should allocate."},

	/* CFG_MAX_XFER_SIZE */
	{"max-xfer-size",
		131072, 1388544, 339968, 0,
		0,
	"Sets maximum bytes per IO the driver can transfer."},

	/* CFG_UB_BUFS */
	{"ub-bufs",
		40, 16320, 1000, 0,
		0,
	"Number of unsolicited buffers the driver should allocate."},

	/* IP specific parameters */

	/* CFG_NETWORK_ON */
	{"network-on",
		0, 1, 1, 0,
		PARM_BOOLEAN,
	"Enable IP processing. "
		"[0=Disabled, 1=Enabled]"},

	/* Fibre Channel specific parameters */

	/* CFG_ACK0 */
	{"ack0",
		0, 1, 0, 0,
		PARM_DYNAMIC_LINK | PARM_BOOLEAN,
	"Enables ACK0 support. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_TOPOLOGY */
	{"topology",
		0, 6, 0, 0,
		PARM_DYNAMIC_LINK,
	"Select Fibre Channel topology. "
		"[0=Loop->PTP, 2=PTP, 4=Loop, 6=PTP->Loop]"},

	/* CFG_LINK_SPEED */
	{"link-speed",
		0, 16, 0, 0,
		PARM_DYNAMIC_LINK,
	"Select link speed. "
		"[0=Auto, 1=1Gb, 2=2Gb, 4=4Gb, 8=8Gb, 16Gb]"},

	/* CFG_NUM_NODES */
	{"num-nodes",
		0, 4096, 0, 0,
		PARM_DYNAMIC_RESET,
	"Number of remote FC nodes the driver will support. "
		"[0=no_limit, else must be >2]"},

	/* CFG_CR_DELAY */
	{"cr-delay",
		0, 63, 0, 0,
		PARM_DYNAMIC_LINK,
	"A count of milliseconds after which "
		"an interrupt response is generated"},

	/* CFG_CR_COUNT */
	{"cr-count",
		1, 255, 1, 0,
		PARM_DYNAMIC_LINK,
	"A count of I/O completions after "
		"which an interrupt response is generated"},

	/* CFG_ASSIGN_ALPA */
	{"assign-alpa",
		0, 0xef, 0, 0,
		PARM_DYNAMIC_LINK | PARM_HEX,
	"Assigns a preferred ALPA to the port. Only used in Loop topology."},

	/* CFG_ADISC_SUPPORT */
	{"adisc-support",
		0, 2, 1, 0,
		PARM_DYNAMIC,
	"Sets the Fibre Channel ADISC login support level. "
		"[0=None, 1=Partial, 2=Full]"},

	/* CFG_PM_SUPPORT */
	{"pm-support",
		0, 1, 0, 0,
		PARM_BOOLEAN,
	"Enables power management support. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_PM_IDLE */
	{"pm-idle",
		0, 3600, 300, 0,
		PARM_DYNAMIC | PARM_HIDDEN,
	"Sets power management idle timeout value (seconds)."},

	/* CFG_FW_CHECK */
	{"fw-check",
		0, 7, 1, 0,
		PARM_DYNAMIC_RESET | PARM_HEX | PARM_HIDDEN,
	"Enables firmware revision checking. "
		"[0=Off 1=Sun-only 2=All 4=kern-update]"},

	/* CFG_TRI_REQUIRED */
	{"tri-required",
		0, 1, 0, 0,
		PARM_DYNAMIC | PARM_BOOLEAN | PARM_HIDDEN,
	"Requires Task Retry Id support by a remote device "
		"for FCP-2 error recovery."},

	/* CFG_DISC_TIMEOUT */
	{"discovery-timeout",
		0, 600, 25, 0,
		PARM_DYNAMIC | PARM_HIDDEN,
	"Sets the discovery timeout period (seconds) "
		"for managing FCP-2 devices."},

	/* CFG_LINKUP_TIMEOUT */
	{"linkup-timeout",
		0, 10, 2, 0,
		PARM_DYNAMIC | PARM_HIDDEN,
	"Sets the linkup timeout period (seconds)."},

	/* CFG_LINKUP_DELAY */
	{"linkup-delay",
		0, 60, 10, 0,
		PARM_DYNAMIC_RESET,
	"Sets the driver wait period (seconds) "
		"for a linkup after initialization."},

	/* CFG_OFFLINE_TIMEOUT */
	{"offline-timeout",
		0, 600, 45, 0,
		PARM_DYNAMIC | PARM_HIDDEN,
	"Sets the offline timeout period (seconds)."},

	/* CFG_LILP_ENABLE */
	{"enable-lilp",
		0, 1, 1, 0,
		PARM_DYNAMIC_RESET | PARM_BOOLEAN | PARM_HIDDEN,
	"Enables LIRP/LILP support in the driver. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_PCI_MAX_READ */
	{"pci-max-read",
		512, 4096, 2048, 0,
		PARM_DYNAMIC_RESET,
	"Sets the PCI-X max memory read byte count. "
		"[512,1024,2048 or 4096]"},

	/* CFG_HEARTBEAT_ENABLE */
	{"heartbeat-enable",
		0, 1, 1, 0,
		PARM_DYNAMIC | PARM_BOOLEAN | PARM_HIDDEN,
	"Enables driver's mailbox heartbeat to the adapter. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_RESET_ENABLE */
	{"reset-enable",
		0, 1, 1, 0,
		PARM_DYNAMIC | PARM_BOOLEAN | PARM_HIDDEN,
	"Enables driver's ability to reset the adapter. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_TIMEOUT_ENABLE */
	{"timeout-enable",
		0, 1, 1, 0,
		PARM_DYNAMIC | PARM_BOOLEAN | PARM_HIDDEN,
	"Enables driver's ability to timeout commands. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_NUM_IOTAGS */
	{"num-iotags",
		0, 4096, 0, 0,
		PARM_DYNAMIC_RESET | PARM_HIDDEN,
	"Sets number of outstanding IO's. "
		"[0=max determined by type of HBA]"},

#ifdef NODE_THROTTLE_SUPPORT
	/* CFG_TGT_DEPTH */
	{"target-depth",
		0, MAX_NODE_THROTTLE, 512, 0,
		PARM_DYNAMIC_LINK,
	"Sets remote FCP target queue depth. "
		"[0=no_limit, N=Maximum active IO's]"},
#endif /* NODE_THROTTLE_SUPPORT */

	/* CFG_MEM_DYNAMIC */
	{"mem-dynamic",
		0, 86400, 180, 0,
		PARM_DYNAMIC_RESET | PARM_HIDDEN,
	"Enables dynamic memory pools "
		"[0=Disabled, 1-N=Enabled w/cleaning every N secs]"},

#ifdef FMA_SUPPORT
	/* CFG_FM_CAPS */
	{"fm-capable",
		0, 0xF, 0xB, 0,
		PARM_HEX | PARM_HIDDEN,
	"Sets FMA capabilities. "
		"[bit 3:errcb, 2:dmachk, 1:accchk, 0:ereport]"},
#endif	/* FMA_SUPPORT */


#ifdef MAX_RRDY_SUPPORT
	/* CFG_MAX_RRDY */
	{"max-rrdy",
		0, 255, 2, 0,
		PARM_DYNAMIC_RESET | PARM_HIDDEN,
	"Sets maximum number RRDY's for the adapter on private loop."},
#endif	/* MAX_RRDY_SUPPORT */

#ifdef MSI_SUPPORT
	/* CFG_MSI_MODE */
	{"msi-mode",
		0, 3, 3, 0,
		PARM_HIDDEN,
	"Sets the default MSI mode in driver. "
		"[0=Off 1=Single-MSI 2=Multi-MSI 3=Auto]"},
#endif	/* MSI_SUPPORT */

	/* CFG_SLI_MODE */
	{"sli-mode",
		0, 4, 0, 0,
		PARM_DYNAMIC_RESET | PARM_HIDDEN,
	"Sets default SLI mode. "
		"[0=Auto, 2=SLI2-remove all vports first, 3=SLI3, 4=SLI4]"},

	/* CFG_NPIV_ENABLE */
	{"enable-npiv",
		0, 1, 0, 0,
		PARM_DYNAMIC_RESET | PARM_BOOLEAN,
	"Enables NPIV. [0=Disabled-remove all vports first, "
		"[1=Enabled-requires SLI3+]"},

	/* CFG_VPORT_RESTRICTED */
	{"vport-restrict-login",
		0, 1, 1, 0,
		PARM_DYNAMIC_LINK | PARM_BOOLEAN,
	"Restricts login to virtual ports to conserve resources. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_NPIV_DELAY */
	{"enable-npiv-delay",
		0, 1, 1, 0,
		PARM_DYNAMIC | PARM_HIDDEN,
	"Enable FDISC/NS command delay from vports to switch. "
		"[0=Disabled, 1=Enabled]"},

#ifdef DHCHAP_SUPPORT
	/* CFG_AUTH_ENABLE */
	{"enable-auth",
		0, 1, 0, 0,
		PARM_DYNAMIC_LINK | PARM_BOOLEAN,
	"Enables DHCHAP support in the driver. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_AUTH_E2E */
	{"auth-e2e",
		0, 1, 0, 0,
		PARM_DYNAMIC_LINK | PARM_BOOLEAN | PARM_HIDDEN,
	"Enables end-to-end DHCHAP support in the driver. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_AUTH_NPIV */
	{"auth-npiv",
		0, 1, 0, 0,
		PARM_DYNAMIC_LINK | PARM_BOOLEAN | PARM_HIDDEN,
	"Enables DHCHAP support for virtual ports. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_AUTH_TMO */
	{"auth-tmo",
		20, 999, 45, 0,
		PARM_DYNAMIC_LINK | PARM_HIDDEN,
	"Sets authentication timeout value. (seconds)"},

	/* CFG_AUTH_MODE */
	{"auth-mode",
		1, 3, 1, 0,
		PARM_DYNAMIC_LINK | PARM_HIDDEN,
	"Sets authentication mode. "
		"[1=Disabled, 2=Active, 3=Passive]"},

	/* CFG_AUTH_BIDIR */
	{"auth-bidir",
		0, 1, 0, 0,
		PARM_DYNAMIC_LINK | PARM_BOOLEAN | PARM_HIDDEN,
	"Sets authentication bidirectional mode. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_AUTH_TYPE */
	{"auth-type",
		0, 0x1111, 0x1000, 0,
		PARM_DYNAMIC_LINK | PARM_HEX | PARM_HIDDEN,
	"Sets authentication type priorities[4]. "
		"[0=Undef, 1=DHCHAP]"},

	/* CFG_AUTH_HASH */
	{"auth-hash",
		0, 0x2222, 0x1200, 0,
		PARM_DYNAMIC_LINK | PARM_HEX | PARM_HIDDEN,
	"Sets authentication hash priorities[4]. "
		"[0=Undef, 1=MD5, 2=SHA1]"},

	/* CFG_AUTH_GROUP */
	{"auth-group",
		0, 0x55555555, 0x54321000, 0,
		PARM_DYNAMIC_LINK | PARM_HEX | PARM_HIDDEN,
	"Sets auth group priorities[8]. "
		"[0=Undef,1=NULL,2=1024,3=1280,4=1536,5=2048]"},

	/* CFG_AUTH_INTERVAL */
	{"auth-interval",
		0, 3600, 300, 0,
		PARM_DYNAMIC_LINK | PARM_HIDDEN,
	"Sets re-authentication interval. (minutes)"},

#endif	/* DHCHAP_SUPPORT */

#ifdef SFCT_SUPPORT
	/* CFG_DTM_ENABLE */
	{"enable-dtm",
		0, 1, 0, 0,
		PARM_BOOLEAN | PARM_HIDDEN,
	"Enables dynamic target mode. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_TARGET_MODE */
	{"target-mode",
		0, 1, 0, 0,
		PARM_BOOLEAN,
		/* PARM_DYNAMIC - Depending on enable-dtm */
	"Enables target mode support in driver. "
		"[0=Disabled, 1=Enabled]"},

	/* CFG_VPORT_MODE_MASK */
	{"vport-mode-mask",
		1, 3, 1, 0,
		PARM_HEX | PARM_HIDDEN,
	"Sets default vport mode mask. "
		"[0x1=Initiator, 0x2=Target (enable-dtm=1 reqd)"},

#ifdef FYI
	/* These parameters can be added to conf file at user's discretion */
	/* Supercedes "vport-mode-mask" for vport N */
	/* vport0-mode-mask is not supported */
	{"vportN-mode-mask",	/* (where N = 1 to max VPI) */
		1, 3, 1, 0,
		PARM_HEX | PARM_HIDDEN,
	"Sets vportN mode mask. "
		"[0x1=Initiator, 0x2=Target (enable-dtm=1 reqd)"},
#endif /* FYI */

	/* CFG_FCT_QDEPTH */
	{"fct-queue-depth",
		0, 4096, 0, 0,
		PARM_BOOLEAN,
	"Queue depth of target mode port. "
		"[0=max determined by type of HBA]"},
#endif /* SFCT_SUPPORT */

	/* CFG_NUM_WQ */
	{"num-wq",
		1, EMLXS_MAX_WQS_PER_EQ, 1, 0,
		PARM_DYNAMIC_RESET | PARM_HIDDEN,
	"Defines number of Work Queues (WQs) per EQ."},

	/* CFG_PERSIST_LINKDOWN */
	{"persist-linkdown",
		0, 1, 0, 0,
		PARM_DYNAMIC_RESET | PARM_BOOLEAN,
	"Set link persistently down. "
		"[0=Disabled, 1=Enabled]."},

	/* CFG_ENABLE_PATCH */
	{"enable-patch",
		0, 0xFFFFFFFF, DEFAULT_PATCHES, 0,
		PARM_DYNAMIC | PARM_HEX | PARM_HIDDEN,
	"Enables patches in driver."},

	/* CFG_FAST_TGT_RESET */
	{"fast-tgt-reset",
		0, 1, 0, 0,
		PARM_DYNAMIC_RESET | PARM_BOOLEAN | PARM_HIDDEN,
	"Enables alternative target reset processing. "
		"[0=Disabled 1=Enabled]"},

	/* CFG_FAST_TGT_RESET_TMR */
	{"fast-tgt-reset-timer",
		0, 60, 10, 0,
		PARM_DYNAMIC_RESET | PARM_BOOLEAN | PARM_HIDDEN,
	"RSCN notification timer for fast target reset. "
		"[0=Disabled 1-60=seconds]"},

	/* CFG_FCF_SOLICIT_DELAY */
	{"fcf-solicit-delay",
		0, 60, 3, 0,
		PARM_DYNAMIC | PARM_HIDDEN,
	"Sets delay after FCF solicit request before reading FCF table. "
		"[0-60=seconds]"},

	/* CFG_FCF_FAILOVER_DELAY */
	{"fcf-failover-delay",
		0, 60, 0, 0,
		PARM_DYNAMIC | PARM_HIDDEN,
	"Sets delay before attempting failover to a new FCF. "
		"[0-60=seconds]"},

	/* CFG_FCF_RESOLICIT_DELAY */
	{"fcf-resolicit-delay",
		0, 60, 3, 0,
		PARM_DYNAMIC | PARM_HIDDEN,
	"Sets delay after total FCF failure before resoliciting. "
		"[0-60=seconds]"},

	/* CFG_FCF_RPI_IDLE_TIMEOUT */
	{"fcf-rpi-idle-timeout",
		1, 30, 2, 0,
		PARM_DYNAMIC | PARM_HIDDEN,
	"Sets timeout period of an idle reserved RPI. "
		"[1-30=seconds]"},

	/* CFG_DELAY_DISCOVERY */
	{"delay-discovery",
		0, 2, 1, 0,
		PARM_DYNAMIC | PARM_BOOLEAN | PARM_HIDDEN,
	"Clean Address to delay discovery."
		"[0=Disabled 1=Enabled not 1st linkup 2=Enabled]"},

	/* CFG_RQD_MODE */
	{"rqd-mode",
		0, 1, 1, 0,
		PARM_DYNAMIC | PARM_BOOLEAN | PARM_HIDDEN,
	"Request Recovery Qualifier delay."
		"[0=Disabled 1=Enabled]"},

	/* CFG_PERF_HINT */
	{"perf-hint",
		0, 1, 1, 0,
		PARM_DYNAMIC | PARM_BOOLEAN | PARM_HIDDEN,
	"Use performance hints if applicable."
		"[0=Disabled 1=Enabled]"},

};

#endif	/* DEF_ICFG */

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_CONFIG_H */
