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

#ifndef _SYS_UWB_UWBAI_H
#define	_SYS_UWB_UWBAI_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This header file includes interfaces for UWB radio controller drivers.
 */

/*
 * A uwb device handle is returned by uwb_device_attach() on success. The
 * handle is opaque to the client uwba driver. The implimentation structure is
 * uwba_dev
 */
typedef	struct uwb_dev_handle	*uwb_dev_handle_t;


/*
 * UWBA function return values
 */
#define	UWB_SUCCESS		0	/* call success			  */
#define	UWB_FAILURE		-1	/* unspecified UWBA or HCD error  */
#define	UWB_NO_RESOURCES	-2	/* no resources available	  */
#define	UWB_NO_BANDWIDTH	-3	/* no bandwidth available	  */
#define	UWB_NOT_SUPPORTED	-4	/* function not supported by HCD  */
#define	UWB_PIPE_ERROR		-5	/* error occured on the pipe	  */
#define	UWB_INVALID_PIPE	-6	/* pipe handle passed is invalid  */
#define	UWB_NO_FRAME_NUMBER	-7	/* frame No or ASAP not specified */
#define	UWB_INVALID_START_FRAME	-8	/* starting UWB frame not valid	  */
#define	UWB_HC_HARDWARE_ERROR	-9	/* UWB host controller error	  */
#define	UWB_INVALID_REQUEST	-10	/* request had invalid values	  */
#define	UWB_INVALID_CONTEXT	-11	/* sleep flag in interrupt context */
#define	UWB_INVALID_VERSION	-12	/* invalid version specified	  */
#define	UWB_INVALID_ARGS	-13	/* invalid func args specified	  */
#define	UWB_INVALID_PERM	-14	/* privileged operation		  */
#define	UWB_BUSY		-15	/* busy condition		  */
#define	UWB_PARSE_ERROR		-18



/* Max wait time for each uwb cmd */
#define	UWB_CMD_TIMEOUT (ddi_get_lbolt() + drv_usectohz(10000000))


/*
 * Radio controller driver registion
 */
void	uwb_dev_attach(dev_info_t *, uwb_dev_handle_t *, uint_t,
    int (*)(uwb_dev_handle_t, mblk_t *, uint16_t));
void uwb_dev_detach(uwb_dev_handle_t);

/* UWB COMMON INTERFACES */
int	uwb_do_ioctl(uwb_dev_handle_t, int, intptr_t, int);
int	uwb_parse_evt_notif(uint8_t *, int, uwb_dev_handle_t);
int	uwb_scan_channel(uwb_dev_handle_t, uint8_t);
int	uwb_reset_dev(dev_info_t *);
int	uwb_init_phy(dev_info_t *);
int	uwb_stop_beacon(dev_info_t *);
int	uwb_start_beacon(dev_info_t *, uint8_t);
int	uwb_get_mac_addr(dev_info_t *, uint8_t *);
int	uwb_get_dev_addr(dev_info_t *, uint16_t *);
int	uwb_set_dev_addr(dev_info_t *, uint16_t);
uint8_t	uwb_allocate_channel(dev_info_t *);

int	uwb_dev_disconnect(dev_info_t *);
int	uwb_dev_reconnect(dev_info_t *);

int	uwb_dev_online(dev_info_t *);
int	uwb_dev_offline(dev_info_t *);

dev_info_t *uwb_get_dip(uwb_dev_handle_t);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_UWB_UWBAI_H */
