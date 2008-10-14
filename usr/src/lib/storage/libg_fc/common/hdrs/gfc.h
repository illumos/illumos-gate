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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Generic Fibre Channel Library definitions
 */

/*
 * I18N message number ranges
 *  This file: 19500 - 19999
 *  Shared common messages: 1 - 1999
 */

#ifndef	_GFC_H
#define	_GFC_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Put your include files here
 */
#include 	<sys/types.h>
#include 	<sys/fibre-channel/fcio.h>
#include	<sys/sunmdi.h>
#include	<sys/scsi/generic/inquiry.h>
/*
 * sys/fc4/fcio.h includes sys/fc4/fcal_linkapp.h.  The following #define
 * keeps from actually including the contents of sys/fc4/fcal_linkapp.h
 * since that file contains the same structure definitions as sys/fc4/fcio.h.
 */
#define		_SYS_FC4_FCAL_LINKAPP_H
#include	<sys/fc4/fcio.h>


/* Defines */
#define		WWN_S_LEN	17 	/* NULL terminated string */
#define		WWN_SIZE	8
#define		MAX_HBA_PORT	256

/* Constants used by g_wwn_in_dev_list() */
#define		MATCH_NODE_WWN	0
#define		MATCH_PORT_WWN	1

/*
 * The masks defined below are for the Fibre channel transport and FCAs.
 * Mask names starting with FC4 are for the non-fabric fibre channel driver
 * stack and those starting with FC are for the fabric fibre channel driver
 * stack.
 *
 * The transport values are represented in the low order 16 bits and FCA
 * values represented in the high order 16 bits.
 *
 * The notation used is as shown below :
 * (starting from the low order byte)
 * Byte 1 - holds the non-fabric FC transport driver defines
 * Byte 2 - holds the fabric FC transport driver defines
 * Byte 3 - holds the non-fabric FC FCA defines
 * Byte 4 - holds the fabric FC FCA defines
 */
/* Recognized Transport categories */
#define	FC4_SF_XPORT	0x00000001
#define	FC4_IFP_XPORT	0x00000002
#define	FC_GEN_XPORT	0x00000100

/* Transport masks */
#define	FC4_XPORT_MASK	0x000000FF
#define	FC_XPORT_MASK	0x0000FF00
#define	XPORT_MASK	(FC_XPORT_MASK | FC4_XPORT_MASK)

/* Recognized Fibre Channel Adapters */
#define	FC4_SOCAL_FCA	0x00010000
#define	FC4_PCI_FCA	0x00020000
#define	FC_PCI_FCA	0x02000000

/* FCA masks */
#define	FC4_FCA_MASK	0x00FF0000
#define	FC_FCA_MASK	0xFF000000
#define	FCA_MASK	(FC_FCA_MASK | FC4_FCA_MASK)

/*
 * Disk ports
 */
#define	PORT_B			0x00
#define	PORT_A			0x01
#define	FC_PORT_A		0x00
#define	FC_PORT_B		0x01
#define	PORT_A_B		0x02

/* Constants used by g_set_port_state() */
#define	PORT_OFFLINE	0
#define	PORT_ONLINE	1

/* Constants used by g_loopback_mode() */
#define	NO_LPBACK		0x00
#define	EXT_LPBACK		0x01
#define	INT_LPBACK		0x02

/* Constants for port state */
#define	PORT_CONNECTED		0x00
#define	PORT_NOTCONNECTED	0x01

/* Extended pathinfo node states */
#define	MDI_PATHINFO_STATE_TRANSIENT			0x00010000
#define	MDI_PATHINFO_STATE_USER_DISABLE			0x00100000
#define	MDI_PATHINFO_STATE_DRV_DISABLE			0x00200000
#define	MDI_PATHINFO_STATE_DRV_DISABLE_TRANSIENT	0x00400000
#define	MDI_PATHINFO_STATE_MASK				0x0000FFFF
#define	MDI_PATHINFO_EXT_STATE_MASK			0xFFF00000

/*
 * Error inq dtype for g_get_dev_list partial failure.
 * choose E0 since Solaris has #define DTYPE_MASK 0x1F.
 */
#define	GFC_ERR_INQ_DTYPE	(0xFF & ~DTYPE_MASK)

/* Exported Variables */
extern uchar_t g_switch_to_alpa[];
extern uchar_t g_sf_alpa_to_switch[];


/* Exported Structures */

/*	Device Map	*/
typedef struct	al_rls {
	char			driver_path[MAXNAMELEN];
	uint_t			al_ha;
	struct rls_payload	payload;
	struct al_rls		*next;
} AL_rls;


/* Multi path list */
struct	dlist	{
	char	*dev_path;
	char	*logical_path;
	struct	dlist *multipath;
	struct	dlist *next;
	struct	dlist *prev;
};


/* Individual drive state */
typedef struct g_disk_state_struct {
	uint_t		num_blocks;		 /* Capacity */
	char		physical_path[MAXNAMELEN];	/* First one found */
	struct dlist	*multipath_list;
	char		node_wwn_s[WWN_S_LEN];	 /* NULL terminated str */
	int		persistent_reserv_flag;
	int		persistent_active, persistent_registered;
	int		d_state_flags[2];	 /* Disk state */
	int		port_a_valid;		 /* If disk state is valid */
	int		port_b_valid;		 /* If disk state is valid */
	char		port_a_wwn_s[WWN_S_LEN]; /* NULL terminated string */
	char		port_b_wwn_s[WWN_S_LEN]; /* NULL terminated string */
} G_disk_state;


typedef	struct hotplug_disk_list {
	struct dlist		*seslist;
	struct dlist		*dlhead;
	char			box_name[33];
	char			dev_name[MAXPATHLEN];
	char			node_wwn_s[17];
	int			tid;
	int			slot;
	int			f_flag; /* Front flag */
	int			dev_type;
	int			dev_location; /* device in A5000 or not */
	int			busy_flag;
	int			reserve_flag;
	struct hotplug_disk_list	*next;
	struct hotplug_disk_list	*prev;
} Hotplug_Devlist;

typedef struct l_inquiry_inq_2 {
	uchar_t inq_2_reladdr	: 1,	/* relative addressing */
		inq_wbus32	: 1,	/* 32 bit wide data xfers */
		inq_wbus16	: 1,	/* 16 bit wide data xfers */
		inq_sync	: 1,	/* synchronous data xfers */
		inq_linked	: 1,	/* linked commands */
		inq_res1	: 1,	/* reserved */
		inq_cmdque	: 1,	/* command queueing */
		inq_sftre	: 1;	/* Soft Reset option */
} L_inq_2;
typedef struct l_inquiry_inq_3 {
	uchar_t inq_3_reladdr	: 1,	/* relative addressing */
		inq_SIP_2	: 3,	/* Interlocked Protocol */
		inq_3_linked	: 1,	/* linked commands */
		inq_trandis	: 1,	/* Transfer Disable */
		inq_3_cmdque	: 1,	/* command queueing */
		inq_SIP_3	: 1;	/* Interlocked Protocol */
} L_inq_3;

typedef struct l_inquiry_struct {
	/*
	 * byte 0
	 *
	 * Bits 7-5 are the Peripheral Device Qualifier
	 * Bits 4-0 are the Peripheral Device Type
	 *
	 */
	uchar_t	inq_dtype;
	/* byte 1 */
	uchar_t	inq_rmb		: 1,	/* removable media */
		inq_qual	: 7;	/* device type qualifier */

	/* byte 2 */
	uchar_t	inq_iso		: 2,	/* ISO version */
		inq_ecma	: 3,	/* ECMA version */
		inq_ansi	: 3;	/* ANSI version */

	/* byte 3 */
#define	inq_aerc inq_aenc	/* SCSI-3 */
	uchar_t	inq_aenc	: 1,	/* async event notification cap. */
		inq_trmiop	: 1,	/* supports TERMINATE I/O PROC msg */
		inq_normaca	: 1,	/* Normal ACA Supported */
				: 1,	/* reserved */
		inq_rdf		: 4;	/* response data format */

	/* bytes 4-7 */
	uchar_t	inq_len;		/* additional length */
	uchar_t			: 8;	/* reserved */
	uchar_t			: 2,	/* reserved */
		inq_port	: 1,	/* Only defined when dual_p set */
		inq_dual_p	: 1,	/* Dual Port */
		inq_mchngr	: 1,	/* Medium Changer */
		inq_SIP_1	: 3;	/* Interlocked Protocol */

	union {
		L_inq_2 inq_2;
		L_inq_3 inq_3;
	} ui;


	/* bytes 8-35 */

	uchar_t	inq_vid[8];		/* vendor ID */

	uchar_t	inq_pid[16];		/* product ID */

	uchar_t	inq_revision[4];	/* product revision level */

	/*
	 * Bytes 36-55 are vendor-specific parameter bytes
	 */

	/* SSA specific definitions */
	/* bytes 36 - 39 */
#define	inq_ven_specific_1 inq_firmware_rev
	uchar_t	inq_firmware_rev[4];	/* firmware revision level */

	/* bytes 40 - 51 */
	uchar_t	inq_serial[12];		/* serial number, not used any more */

	/* bytes 52-53 */
	uchar_t	inq_res2[2];

	/* byte 54, 55 */
	uchar_t	inq_ssa_ports;		/* number of ports */
	uchar_t	inq_ssa_tgts;		/* number of targets */

	/*
	 * Bytes 56-95 are reserved.
	 */
	uchar_t	inq_res3[40];
	/*
	 * 96 to 'n' are vendor-specific parameter bytes
	 */
	uchar_t	inq_box_name[32];
	uchar_t	inq_avu[256];
} L_inquiry;


typedef struct wwn_list_struct {
	char	*logical_path;
	char	*physical_path;
	char	node_wwn_s[WWN_S_LEN];	/* NULL terminated string */
	uchar_t	w_node_wwn[WWN_SIZE];
	char	port_wwn_s[WWN_S_LEN];	/* NULL terminated string */
	uchar_t	device_type;	/* disk or tape (Peripheral Device Type) */
	struct	wwn_list_struct	*wwn_prev;
	struct	wwn_list_struct	*wwn_next;
} WWN_list;


/* HBA port list */
typedef struct portlist {
	int hbacnt;
	char *physpath[MAX_HBA_PORT];
} portlist_t;
/* union for capturing sf and fp strucures */
typedef union gfc_port_dev_u {
	sf_al_addr_pair_t	priv_port; /* private loop */
	fc_port_dev_t		pub_port;  /* fabric/public loop */
} gfc_port_dev_ut;


/* FC device sturcure with topology */
typedef struct gfc_port_dev_info {
	uint32_t	port_topology;
	gfc_port_dev_ut gfc_port_dev;
} gfc_port_dev_info_t;


/* strucure for FC map */
typedef struct gfc_map {
	int	count;
	gfc_port_dev_info_t	*dev_addr;
	gfc_port_dev_info_t	hba_addr;
} gfc_map_t;

/* g_dev_map_init related declaration */

typedef void *gfc_dev_t; /* opaque type for map device */
typedef void *gfc_prop_t; /* opaque type for map device property */

#define	MAP_FORMAT_STANDARD	0
#define	MAP_FORMAT_LILP		0x00000001
#define	MAP_XPORT_PROP_ONLY	0x00000010

/* property name for g_dev_prop_lookup */
#define	PORT_WWN_PROP "port-wwn"
#define	NODE_WWN_PROP "node-wwn"
#define	INQ_DTYPE_PROP "inq-dtype"
#define	PORT_ADDR_PROP "port-addr"
#define	HARD_ADDR_PROP "hard-addr"

/* property type for g_dev_prop_next */
#define	GFC_PROP_TYPE_BOOLEAN	0
#define	GFC_PROP_TYPE_INT	1
#define	GFC_PROP_TYPE_STRING	2
#define	GFC_PROP_TYPE_BYTES	3
#define	GFC_PROP_TYPE_UNKNOWN	4

typedef struct mp_pathinfo {
	mdi_pathinfo_state_t path_state;
	char	path_class[MAXNAMELEN];
	char	path_hba[MAXPATHLEN];
	char	path_dev[MAXPATHLEN];
	char	path_addr[MAXNAMELEN];
} mp_pathinfo_t;

/* structure for mpxio pathlist */
typedef struct mp_pathlist {
	uint_t		path_count;
	mp_pathinfo_t	*path_info;
} mp_pathlist_t;

/*
 * Prototypes of Exported functions which are defined in libg_fc
 * They are all CONTRACT PRIVATE
 */

#if defined(__STDC__)

extern int	g_dev_start(char *, int);
extern int	g_dev_stop(char *, struct wwn_list_struct *, int);
extern int	g_force_lip(char *, int);
extern int	g_forcelip_all(struct hotplug_disk_list *);
extern void	g_free_multipath(struct dlist *);
extern void	g_free_wwn_list(struct wwn_list_struct **);
extern int	g_get_dev_map(char *, gfc_map_t *, int);
extern int	g_get_lilp_map(char *, gfc_map_t *, int);
extern int	g_get_inq_dtype(char *, la_wwn_t, uchar_t *);
extern int	g_get_dev_list(char *, fc_port_dev_t **, int *);
extern int	g_wwn_in_dev_list(char *, la_wwn_t, int);
extern char 	*g_get_dev_or_bus_phys_name(char *);
extern char 	*g_get_errString(int);
extern int	g_get_inquiry(char *, L_inquiry *);
extern int	g_get_serial_number(char *, uchar_t *, size_t *);
extern int	g_get_limited_map(char *, struct lilpmap *, int);
extern int	g_get_multipath(char *, struct dlist **,
		struct wwn_list_struct *, int);
extern int	g_get_nexus_path(char *, char **);
extern char 	*g_get_physical_name_from_link(char *);
extern char 	*g_get_physical_name(char *);
extern int	g_get_wwn(char *, uchar_t *, uchar_t *, int *, int);
extern int	g_get_wwn_list(struct wwn_list_struct **, int);
extern int	g_i18n_catopen(void);
extern int	g_offline_drive(struct dlist *, int);
extern void	g_online_drive(struct dlist *, int);
extern int	g_rdls(char *, struct al_rls **, int);
extern uint_t	g_get_path_type(char *);
extern int	g_get_host_params(char *, fc_port_dev_t *, int);
extern int	g_port_offline(char *);
extern int	g_port_online(char *);
extern int	g_get_port_path(char *, portlist_t *);
extern void	g_free_portlist(portlist_t *);
extern int	g_loopback_mode(char *, int);
extern int	g_get_port_state(char *, int *, int);
extern int	g_get_fca_port_topology(char *, uint32_t *, int);
extern int	g_dev_login(char *, la_wwn_t);
extern int	g_dev_logout(char *, la_wwn_t);
extern int	g_get_pathlist(char *, struct mp_pathlist *);
extern int	g_failover(char *, char *);

/* g_dev_map_init related routines. */
extern gfc_dev_t	g_dev_map_init(char *, int *, int);
extern void		g_dev_map_fini(gfc_dev_t);
extern int		g_get_map_topology(gfc_dev_t, uint_t *);
extern gfc_dev_t	g_get_first_dev(gfc_dev_t, int *);
extern gfc_dev_t	g_get_next_dev(gfc_dev_t, int *);
extern int	g_dev_prop_lookup_bytes(gfc_dev_t, const char *, int *,
		uchar_t **);
extern int g_dev_prop_lookup_ints(gfc_dev_t, const char *, int **);
extern int g_dev_prop_lookup_strings(gfc_dev_t, const char *, char **);
extern gfc_prop_t g_get_first_dev_prop(gfc_dev_t, int *);
extern gfc_prop_t g_get_next_dev_prop(gfc_prop_t, int *);
extern char *g_get_dev_prop_name(gfc_prop_t, int *);
extern int g_get_dev_prop_type(gfc_prop_t, int *);
extern int g_get_dev_prop_bytes(gfc_prop_t, int *, uchar_t **);
extern int g_get_dev_prop_ints(gfc_prop_t, int **);
extern int g_get_dev_prop_strings(gfc_prop_t, char **);
extern int g_stms_path_disable(char *, char *);
extern int g_stms_path_enable(char *, char *);
extern int g_stms_path_disable_all(char *);
extern int g_stms_path_enable_all(char *);
extern int g_stms_get_path_state(char *, char *, int *, int *);


#else /* __STDC__ */

extern int	g_dev_start();
extern int	g_dev_stop();
extern int	g_force_lip();
extern int	g_forcelip_all();
extern void	g_free_multipath();
extern void	g_free_wwn_list();
extern int	g_get_inq_dtype();
extern int	g_get_dev_list();
extern int	g_wwn_in_dev_list();
extern int	g_get_dev_map();
extern int	g_get_lilp_map();
extern char 	*g_get_dev_or_bus_phys_name();
extern char 	*g_get_errString();
extern int	g_get_inquiry();
extern int	g_get_serial_number();
extern int	g_get_limited_map();
extern int	g_get_multipath();
extern int	g_get_nexus_path();
extern int	g_get_wwn_list();
extern int	g_offline_drive();
extern void	g_online_drive();
extern char 	*g_get_physical_name();
extern char 	*g_get_physical_name_from_link();
extern int	g_get_wwn();
extern int	g_i18n_catopen();
extern int	g_rdls();
extern uint_t	g_get_path_type();
extern int	g_get_host_params();
extern int	g_port_offline();
extern int	g_port_online();
extern int	g_get_port_path();
extern void	g_free_portlist();
extern int	g_loopback_mode();
extern int	g_get_port_state();
extern int	g_get_fca_port_topology();
extern int	g_dev_login();
extern int	g_dev_logout();
extern int	g_get_pathlist();
extern int	g_failover();

/* g_dev_map_init related routines. */
extern gfc_dev_t	g_dev_map_init();
extern void		g_dev_map_fini();
extern int		g_get_map_topology();
extern gfc_dev_t	g_get_first_dev();
extern gfc_dev_t	g_get_next_dev();
extern int	g_dev_prop_lookup_bytes();
extern int g_dev_prop_lookup_ints();
extern int g_dev_prop_lookup_strings();
extern gfc_prop_t g_get_first_dev_prop();
extern gfc_prop_t g_get_next_dev_prop();
extern char *g_get_dev_prop_name();
extern int g_get_dev_prop_type();
extern int g_get_dev_prop_bytes();
extern int g_get_dev_prop_ints();
extern int g_get_dev_prop_strings();
extern int g_stms_path_disable();
extern int g_stms_path_enable();
extern int g_stms_path_disable_all();
extern int g_stms_path_enable_all();
extern int g_stms_get_path_state();

#endif /* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif /* _GFC_H */
