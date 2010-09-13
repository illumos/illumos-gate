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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_1394_H1394_H
#define	_SYS_1394_H1394_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * h1394.h
 *    Contains the structure and error codes used to communicate
 *    between the HAL and the rest of the 1394 Software Framework
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/note.h>

#include <sys/1394/cmd1394.h>
#include <sys/1394/id1394.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	H1394_CLEANUP_LEVEL7	7
#define	H1394_CLEANUP_LEVEL6	6
#define	H1394_CLEANUP_LEVEL5	5
#define	H1394_CLEANUP_LEVEL4	4
#define	H1394_CLEANUP_LEVEL3	3
#define	H1394_CLEANUP_LEVEL2	2
#define	H1394_CLEANUP_LEVEL1	1
#define	H1394_CLEANUP_LEVEL0	0

/* h1394_phy_t */
typedef enum {
	H1394_PHY_1995	= 0,
	H1394_PHY_1394A	= 1
} h1394_phy_t;

/* h1394_error_t */
typedef enum {
	H1394_LOCK_RESP_ERR		= 1,
	H1394_POSTED_WR_ERR		= 2,
	H1394_SELF_INITIATED_SHUTDOWN	= 3,
	H1394_CYCLE_TOO_LONG		= 4
} h1394_error_t;

/*
 * h1394_posted_wr_err_t
 *    The upper 16 bits contain the source id (bus/node) of the source node,
 *    the lower 48 bits contain the address that the error occured at.
 */
typedef struct h1394_posted_wr_err_s {
	uint64_t	addr;
} h1394_posted_wr_err_t;

/*
 * h1394_node_pwr_flags_t
 *    Node power flags info
 */
typedef enum {
	H1394_NODE_PWR_FLAGS_NONE	= (1 << 1),
	H1394_BUS_PWRD_NODES_ONE_MORE	= (1 << 2),
	H1394_BUS_PWRD_NODES_ONE_LESS	= (1 << 3),
	H1394_ACTIVE_NODES_ONE_MORE	= (1 << 4),
	H1394_ACTIVE_NODES_ONE_LESS	= (1 << 5)
} h1394_node_pwr_flags_t;

/*
 * h1394_addr_type_t
 *    h1394_addr_map.addr_type
 */
typedef enum {
	H1394_ADDR_POSTED_WRITE	= 0,
	H1394_ADDR_NORMAL	= 1,
	H1394_ADDR_CSR		= 2,
	H1394_ADDR_PHYSICAL	= 3,
	H1394_ADDR_RESERVED	= 4
} h1394_addr_type_t;

/* h1394_mblk_t */
typedef struct h1394_mblk_s {
	mblk_t		*curr_mblk;
	unsigned char	*curr_offset;
	uint_t		length;
	mblk_t		*next_mblk;
	unsigned char	*next_offset;
} h1394_mblk_t;

/* h1394_cmd_priv_t */
typedef struct h1394_cmd_priv_s {
	uint_t		speed;
	uint_t		ack_tstamp;
	uint_t		recv_tstamp;
	uint_t		bus_generation;
	h1394_mblk_t	mblk;
	void		*hal_overhead;
} h1394_cmd_priv_t;

_NOTE(SCHEME_PROTECTS_DATA("Used by a single thread", h1394_cmd_priv_s \
	h1394_mblk_s::next_mblk h1394_mblk_s::next_offset))

/* h1394_evts_t */
typedef struct h1394_evts_s {
	uint_t	hal_version;
	uint_t	reserved;
	void	(*shutdown)(void *hal_private);
	int	(*send_phy_configuration_packet)(void *hal_private,
		    cmd1394_cmd_t *phy_pkt, h1394_cmd_priv_t *cmd_private,
		    int *result);
	int	(*read)(void *hal_private, cmd1394_cmd_t *req,
		    h1394_cmd_priv_t *cmd_private, int *result);
	int	(*read_response)(void *hal_private, cmd1394_cmd_t *resp,
		    h1394_cmd_priv_t *cmd_private, int *result);
	int	(*write)(void *hal_private, cmd1394_cmd_t *req,
		    h1394_cmd_priv_t *cmd_private, int *result);
	int	(*write_response)(void *hal_private, cmd1394_cmd_t *resp,
		    h1394_cmd_priv_t *cmd_private, int *result);
	void	(*response_complete)(void *hal_private, cmd1394_cmd_t *resp,
		    h1394_cmd_priv_t *cmd_private);
	int	(*lock)(void *hal_private, cmd1394_cmd_t *req,
		    h1394_cmd_priv_t *cmd_private, int *result);
	int	(*lock_response)(void *hal_private, cmd1394_cmd_t *resp,
		    h1394_cmd_priv_t *cmd_private, int *result);
	int	(*alloc_isoch_dma)(void *hal_private,
		    id1394_isoch_dmainfo_t *idi, void **hal_idma_handle,
		    int *result);
	void	(*free_isoch_dma)(void *hal_private,
		    void *hal_isoch_dma_handle);
	int	(*start_isoch_dma)(void *hal_private,
		    void *hal_isoch_dma_handle,
		    id1394_isoch_dma_ctrlinfo_t *idma_ctrlinfo, uint_t flags,
		    int *result);
	void	(*stop_isoch_dma)(void *hal_private, void *hal_isoch_dma_handle,
		    int *result);
	int	(*update_isoch_dma)(void *hal_private,
		    void *hal_isoch_dma_handle,
		    id1394_isoch_dma_updateinfo_t *idma_updateinfo,
		    uint_t flags, int *result);
	int	(*update_config_rom)(void *hal_private, void *local_buf,
		    uint_t quadlet_count);
	int	(*bus_reset)(void *hal_private);
	int	(*short_bus_reset)(void *hal_private);
	int	(*set_contender_bit)(void *hal_private);
	int	(*set_root_holdoff_bit)(void *hal_private);
	int	(*set_gap_count)(void *hal_private, uint_t gap_count);
	int	(*csr_read)(void *hal_private, uint_t offset, uint32_t *data);
	int	(*csr_write)(void *hal_private, uint_t offset, uint32_t data);
	int	(*csr_cswap32)(void *hal_private, uint_t generation,
		    uint_t offset, uint32_t compare, uint32_t swap,
		    uint32_t *old);
	int	(*physical_arreq_enable_set)(void *hal_private, uint64_t mask,
		    uint_t generation);
	int	(*physical_arreq_enable_clr)(void *hal_private, uint64_t mask,
		    uint_t generation);
	void	(*node_power_state_change)(void *hal_private,
		    h1394_node_pwr_flags_t nodeflags);
} h1394_evts_t;
/* Version value for h1394_evts_t */
#define	H1394_EVTS_V1			1

#define	HAL_CALL(hal)			(hal)->halinfo.hal_events

/* Result field returned by read/write/lock requests */
#define	H1394_STATUS_NO_ERROR		0
#define	H1394_STATUS_INVALID_BUSGEN	1
#define	H1394_STATUS_EMPTY_TLABEL	2
#define	H1394_STATUS_NOMORE_SPACE	3
#define	H1394_STATUS_INTERNAL_ERROR	4

/* h1394_addr_map_t */
typedef struct h1394_addr_map_s {
	uint64_t		address;
	uint64_t		length;
	h1394_addr_type_t	addr_type;
} h1394_addr_map_t;

/* h1394_halinfo_t */
typedef struct h1394_halinfo_s {
	void			*hal_private;
	dev_info_t		*dip;
	h1394_evts_t		hal_events;
	ddi_iblock_cookie_t	hw_interrupt;

	/* Buffer attributes */
	ddi_device_acc_attr_t	acc_attr;
	ddi_dma_attr_t		dma_attr;

	/* Type of PHY on HAL */
	h1394_phy_t		phy;

	uint_t			hal_overhead; /* in bytes */
	uint32_t   		bus_capabilities;
	uint64_t		guid;
	uint32_t		node_capabilities;

	/*
	 * The maximum value generation can have before
	 * it rolls over (inclusive)
	 */
	uint_t			max_generation;

	/* Description of the 1394 Address Space */
	h1394_addr_map_t	*addr_map;
	uint_t			addr_map_num_entries;

	/* Description of the reserved spaces */
	h1394_addr_map_t	*resv_map;
	uint_t			resv_map_num_entries;
} h1394_halinfo_t;


/* Calls to Services layer during HAL driver _init() and _fini() */
int h1394_init(struct modlinkage  *modlp);
void h1394_fini(struct modlinkage  *modlp);


/* Calls to Services layer during HAL driver attach/detach */
int h1394_attach(h1394_halinfo_t *halinfo, ddi_attach_cmd_t cmd,
    void **sl_private);

int h1394_detach(void **sl_private, ddi_detach_cmd_t cmd);


/* Calls to Services layer during HW interrupt processing */
void h1394_cmd_is_complete(void *sl_private, cmd1394_cmd_t *command_id,
    uint32_t cmd_type, int status);
/* Command types (passed to h1394_command_is_complete) */
#define	H1394_AT_REQ		0
#define	H1394_AT_RESP		1
/* Command statuses (passed to h1394_command_is_complete) */
#define	H1394_CMD_SUCCESS		0x00	/* ack_complete */
#define	H1394_CMD_ETIMEOUT		0x01	/* evt_missing_ack */
#define	H1394_CMD_EBUSRESET		0x02	/* evt_flushed */
#define	H1394_CMD_EDEVICE_BUSY		0x03	/* ack_busy_? */
#define	H1394_CMD_EDATA_ERROR		0x04	/* ack_data_error */
#define	H1394_CMD_ETYPE_ERROR		0x05	/* ack_type_error */
#define	H1394_CMD_EADDR_ERROR		0x06	/* resp_address_error */
#define	H1394_CMD_ERSRC_CONFLICT	0x07	/* resp_conflict_error */
#define	H1394_CMD_EDEVICE_POWERUP	0x08	/* ack_tardy */
#define	H1394_CMD_EDEVICE_ERROR		0x09	/* device error */
#define	H1394_CMD_EUNKNOWN_ERROR	0x0A	/* unknown error type */

void h1394_bus_reset(void *sl_private, void **selfid_buf_addr);

void h1394_self_ids(void *sl_private, void *selfid_buf_addr,
    uint32_t selfid_size, uint32_t node_id, uint32_t generation_count);

void h1394_write_request(void *sl_private, cmd1394_cmd_t *req);

void h1394_read_request(void *sl_private, cmd1394_cmd_t *req);

void h1394_lock_request(void *sl_private, cmd1394_cmd_t *req);

int h1394_alloc_cmd(void *sl_private, uint_t flags, cmd1394_cmd_t **cmdp,
    h1394_cmd_priv_t **hal_priv_ptr);
/* Flags for h1394_alloc_cmd() */
#define	H1394_ALLOC_CMD_SLEEP		0x00000000 /* can sleep allocating */
#define	H1394_ALLOC_CMD_NOSLEEP		0x00000001 /* don't sleep allocating */

int h1394_free_cmd(void *sl_private, cmd1394_cmd_t **cmdp);
int h1394_ioctl(void *sl_private, int cmd, intptr_t arg, int mode,
    cred_t *cred_p, int *rval_p);

void h1394_phy_packet(void *sl_private, uint32_t *packet_data,
    uint_t quadlet_count, uint_t timestamp);

void h1394_error_detected(void *sl_private, h1394_error_t type, void *arg);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_H1394_H */
