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

#ifndef	_G_STATE_H
#define	_G_STATE_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Include any headers you depend on.
 */

/*
 * I18N message number ranges
 *  This file: 19000 - 19499
 *  Shared common messages: 1 - 1999
 */

#include	<libdevice.h>
#include	<sys/fibre-channel/fcio.h>
#include	<sys/sunmdi.h>
/*
 * sys/fc4/fcio.h includes sys/fc4/fcal_linkapp.h.  The following #define
 * keeps from actually including the contents of sys/fc4/fcal_linkapp.h
 * since that file contains the same structure definitions as sys/fc4/fcio.h.
 */
#define	_SYS_FC4_FCAL_LINKAPP_H
#include	<sys/fc4/fcio.h>
#include	<sys/devctl.h>
#include	<g_scsi.h>
#include	<sys/scsi/generic/commands.h>
#include	<libnvpair.h>
#include	<libdevinfo.h>

#define	MAXPATHSTATE	5

#include 	<gfc.h>

/* hotplug defines */
#define	SENA		1
#define	NON_SENA	0
/* format parameters to dump() */
#define	HEX_ONLY	0	/* Print Hex only */
#define	HEX_ASCII	1	/* Print Hex and Ascii */
/* Persistent Reservation */
#define	ACTION_READ_KEYS	0x00
#define	ACTION_READ_RESERV	0x01
#define	ACTION_REGISTER		0x00
#define	ACTION_RESERVE		0x01
#define	ACTION_RELEASE		0x02
#define	ACTION_CLEAR		0x03
#define	ACTION_PREEMPT		0x04
#define	ACTION_PREEMPT_CLR	0x05

/* Some constants for fabric/public loops */
#define	AREA_DOMAIN_ID		0x00FFFF00

/* Max number of retries */
#define	RETRY_FCIO_IOCTL	360
#define	RETRY_FCP_IOCTL		360
#define	RETRY_OBJECT_OPEN	5
#define	RETRY_PATHLIST		1

/* Wait times in microseconds */
#define	WAIT_FCIO_IOCTL		250000 /* 1/4 of a second */
#define	WAIT_FCP_IOCTL		250000 /* 1/4 of a second */
#define	WAIT_OBJECT_OPEN	10000  /* 1/100 of a sec. */

/* Defines for VS inq_port field on standard page (bit 5 Byte 6 */
#define	PATH_PRIMARY		0x0
#define	PATH_FAILOVER		0x1

/*
 * Macro for deallocating memory pointed by dev_addr pointer
 * of gfc_map_t structure.
 * It is defined here to make available at any place from
 * luxadm, liba5k and libg_fc.
 *
 * Note: The macro will try to free any non-NULL dev_addr.
 *       So, dev_addr ptr needs to be initialized to NULL.
 *
 *       map.dev_addr = (gfc_port_dev_info_t *)NULL
 *       map->dev_addr = (gfc_port_dev_info_t *)NULL.
 */
#define	FREE_DEV_ADDR(D_PTR)	if (D_PTR != NULL) {\
					free((void *)D_PTR);\
					D_PTR = (gfc_port_dev_info_t *)NULL;\
				}

/* Constants and macros used by the g_get_path_type() function */
#define	SLASH		"/"
#define	DEV_PREFIX	"/devices/"	/* base pathname for devfs names */
#define	DEV_PREFIX_LEN	9		/* Length of DEV_PREFIX string */
					/* Can do a strlen and generalize */
					/* but this is is easier */
#define	DEVICES_DIR	"/devices"

/* Defines for minor names used to append to devfs paths */
#define	SSD_MINOR_NAME		":c,raw"
#define	ST_MINOR_NAME		":n"

/* Defines for ssd driver name passed to root tree search routines */
#define	SSD_DRVR_NAME	"ssd"
#define	ST_DRVR_NAME	"st"

/*
 * Property names
 */
#define	PORT_WWN_PROP	"port-wwn"
#define	NODE_WWN_PROP	"node-wwn"
#define	LUN_GUID_PROP	"client-guid"
#define	LUN_PROP	"lun"

typedef struct	read_keys_struct {
	int		rk_generation;
	int		rk_length;
	int		rk_key[256];
} Read_keys;

typedef struct	read_reserv_struct {
	int		rr_generation;
	int		rr_length;
} Read_reserv;

/*
 * mplist structure typedef to support multipath
 */
typedef struct mplist_struct {
	char *devpath;
	struct mplist_struct *next;
} Mplist;

/* wwn_list_found to track previous calls to g_get_wwn */
typedef struct wwn_list_found_struct {
	uchar_t	node_wwn[WWN_SIZE];
	uchar_t	port_wwn[WWN_SIZE];
	struct	wwn_list_found_struct	*wwn_next;
} WWN_list_found;

/* Function prototyes defined for libg_fc modules */
/* genf.c */
extern void	*g_zalloc(int);
extern char	*g_alloc_string(char *);
extern void	g_destroy_data(void *);
extern void	g_dump(char *, uchar_t *, int, int);
extern int	g_object_open(char *, int);
extern char	*g_scsi_find_command_name(int);
extern void	g_scsi_printerr(struct uscsi_cmd *,
		struct scsi_extended_sense *, int, char msg_string[], char *);
extern int	g_get_machineArch(int *);
extern boolean_t g_enclDiskChk(char *, char *);

/* hot.c */
extern void	g_ll_to_str(uchar_t *, char *);
extern void	g_free_hotplug_dlist(struct hotplug_disk_list **);

/* map.c */
extern int	g_string_to_wwn(uchar_t *, uchar_t *);
extern int	g_get_perf_statistics(char *, uchar_t *);
extern int	g_get_port_multipath(char *, struct dlist **, int);
extern int	g_device_in_map(gfc_map_t *, int);
extern int	g_start(char *);
extern int	g_stop(char *, int);
extern int	g_reserve(char *);
extern int	g_release(char *);
extern int	g_issue_fcio_ioctl(int, fcio_t *, int);
extern void	g_sort_wwn_list(struct wwn_list_struct **);
extern void	g_free_wwn_list_found(struct wwn_list_found_struct **);

/* cmd.c */
extern int	cmd(int, struct uscsi_cmd *, int);

/* io.c */
extern int	g_scsi_persistent_reserve_in_cmd(int, uchar_t *, int, uchar_t);
extern int	g_scsi_send_diag_cmd(int, uchar_t *, int);
extern int	g_scsi_rec_diag_cmd(int, uchar_t *, int, uchar_t);
extern int	g_scsi_writebuffer_cmd(int, int, uchar_t *, int, int, int);
extern int	g_scsi_readbuffer_cmd(int, uchar_t *, int, int);
extern int	g_scsi_inquiry_cmd(int, uchar_t *, int);
extern int	g_scsi_log_sense_cmd(int, uchar_t *, int, uchar_t);
extern int	g_scsi_mode_select_cmd(int, uchar_t *, int, uchar_t);
extern int	g_scsi_mode_sense_cmd(int, uchar_t *, int, uchar_t, uchar_t);
extern int	g_scsi_read_capacity_cmd(int, uchar_t *, int);
extern int	g_scsi_read_capacity_1016_cmd(int, struct scsi_capacity_16 *,
			int);
extern int	g_scsi_release_cmd(int);
extern int	g_scsi_reserve_cmd(int);
extern int	g_scsi_start_cmd(int);
extern int	g_scsi_stop_cmd(int, int);
extern int	g_scsi_tur(int);
extern int	g_scsi_reset(int);
extern int	g_devid_get(char *, ddi_devid_t *, di_node_t root,
			const char *);

/* mpath.c */
extern int	g_get_lun_str(char *, char *, int);
extern int	g_get_lun_number(char *);
extern int	g_get_pathcount(char *);
extern int	g_devices_get_all(struct wwn_list_struct **);

#ifdef	__cplusplus
}
#endif

#endif	/* _G_STATE_H */
