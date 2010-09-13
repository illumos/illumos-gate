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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_1394_S1394_H
#define	_SYS_1394_S1394_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * s1394.h
 *    Contains all of the structures used (internally) by the 1394
 *    Software Framework
 */

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/callb.h>
#include <sys/note.h>

#include <sys/1394/s1394_impl.h>
#include <sys/1394/t1394.h>
#include <sys/1394/h1394.h>
#include <sys/1394/cmd1394.h>
#include <sys/1394/ieee1212.h>
#include <sys/1394/ieee1394.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* SelfID buffer size */
#define	S1394_SELFID_BUF_SIZE		8192

/* Maximum number of allocated commands per target */
#define	MAX_NUMBER_ALLOC_CMDS		256

/* Maximum number of lock retries */
#define	MAX_NUMBER_OF_LOCK_RETRIES	256

#define	S1394_INITIAL_STATES		2

/* Invalid entry in the Speed Map */
#define	SPEED_MAP_INVALID		0xFF

/* Invalid node num */
#define	S1394_INVALID_NODE_NUM		0x3F

/* Node state */
#define	S1394_NODE_OFFLINE		1
#define	S1394_NODE_ONLINE		2

/* Where are commands inserted onto the pending Q? */
#define	S1394_PENDING_Q_FRONT		1
#define	S1394_PENDING_Q_REAR		2

/* Number of self-initiated bus resets until HAL fails */
#define	NUM_BR_FAIL			5

/* Reasons for Self-Initiated Bus Reset */
#define	NON_CRITICAL			0
#define	CRITICAL			1

/* Bus Mgr (IRM) defines */
#define	ROOT_HOLDOFF			(1 << 0)
#define	GAP_COUNT			(1 << 1)

/* Root Node has no parents */
#define	NO_PARENT			-1

/* Maximum number of Hops between Nodes on the Bus */
#define	MAX_HOPS			23

/* Invalid lo and hi addresses used in s1394_init_addr_space() */
#define	ADDR_LO_INVALID			0x0000000000000001
#define	ADDR_HI_INVALID			0x0000000000000000

/* Time to delay after CYCLE_TOO_LONG before enabling cycle master */
#define	CYCLE_MASTER_TIMER		1000	/* 1 second */

/* Size of directory stack used during config rom scan */
#define	S1394_DIR_STACK_SIZE		16

/*
 * P1394a (Draft 2.x) proposes to disallow a
 * Config ROM "generation" to be repeated within
 * a 60 second window.
 * Because of that, this value should not be set
 * to any value smaller than 5 seconds without
 * another method in place to ensure that this
 * "generation" reuse can not happen.
 */

/*
 * Time delay (in ms) from Config ROM update to
 * software-initiated bus reset.
 */
#define	CONFIG_ROM_UPDATE_DELAY		5000	/* 5 seconds */

#define	S1394_ROOT_TEXT_LEAF_SZ		36
#define	S1394_ROOT_TEXT_LEAF_QUAD_SZ	9
#define	S1394_ROOT_TEXT_KEY		0x81

#define	S1394_NODE_UNIQUE_ID_SZ		12
#define	S1394_NODE_UNIQUE_ID_QUAD_SZ	3
#define	S1394_NODE_UNIQUE_ID_KEY	0x8D

#define	S1394_UNIT_DIR_SZ		56
#define	S1394_UNIT_DIR_QUAD_SZ		14
#define	S1394_UNIT_DIR_KEY		0xD1

/* The Organizationally Unique Identifier for Sun Microsystems, Inc. */
#define	S1394_SUNW_OUI			0x080020

/* Number of retries in reading the Config ROM */
#define	CFGROM_READ_RETRIES		5

/* Delay time between reads of the Config ROM */
#define	CFGROM_READ_DELAY		20000	/* 20ms */

/* Error message for serious HBA hardware shutdowns */
#define	HALT_ERROR_MESSAGE	"%s%d: Unexpected Error: Shutting down HBA -" \
	" Hardware disabled until next reboot"

/* Command Transaction Type */
#define	S1394_CMD_READ		0
#define	S1394_CMD_WRITE		1
#define	S1394_CMD_LOCK		2

/* Channel allocations */
#define	S1394_CHANNEL_ALLOC_HI	1
#define	S1394_CHANNEL_ALLOC_LO	0

/* Maximum number of bus resets allowed in isoch rsrc alloc */
#define	S1394_ISOCH_ALLOC_RETRIES	5

#define	ADDR_RESERVED		1

/* Flags used by the used tree (red-black tree) */
#define	BLACK			0
#define	RED			1
#define	LEFT			0
#define	RIGHT			1

/* Isoch Bandwidth Allocation Units conversion */
#define	ISOCH_SPEED_FACTOR_S100		16
#define	ISOCH_SPEED_FACTOR_S200		8
#define	ISOCH_SPEED_FACTOR_S400		4

/* TNF probes */
#define	S1394_TNF_SL			"1394 s1394 "
#define	S1394_TNF_SL_ERROR		"1394 s1394 error "
#define	S1394_TNF_SL_STACK		"1394 s1394 stacktrace "
#define	S1394_TNF_SL_ARREQ_STACK	"1394 s1394 arreq stacktrace "
#define	S1394_TNF_SL_ARREQ_ERROR	"1394 s1394 arreq error "
#define	S1394_TNF_SL_ATREQ_STACK	"1394 s1394 atreq stacktrace "
#define	S1394_TNF_SL_ATREQ_ERROR	"1394 s1394 atreq error "
#define	S1394_TNF_SL_ATRESP_STACK	"1394 s1394 atresp stacktrace "
#define	S1394_TNF_SL_ATRESP_ERROR	"1394 s1394 atresp error "
#define	S1394_TNF_SL_ATREQ_ATRESP_STACK	"1394 s1394 atreq atresp stacktrace "
#define	S1394_TNF_SL_ATREQ_ATRESP_ERROR	"1394 s1394 atreq atresp error "
#define	S1394_TNF_SL_BR_STACK		"1394 s1394 bus_reset stacktrace "
#define	S1394_TNF_SL_BR_ERROR		"1394 s1394 bus_reset error "
#define	S1394_TNF_SL_IOCTL_STACK	"1394 s1394 ioctl stacktrace "
#define	S1394_TNF_SL_HOTPLUG_STACK	"1394 s1394 hotplug stacktrace "
#define	S1394_TNF_SL_HOTPLUG_ERROR	"1394 s1394 hotplug error "
#define	S1394_TNF_SL_NX1394_STACK	"1394 s1394 nx1394 stacktrace "
#define	S1394_TNF_SL_CSR_ERROR		"1394 s1394 csr error "
#define	S1394_TNF_SL_CSR_STACK		"1394 s1394 csr stacktrace "
#define	S1394_TNF_SL_BR_CSR_STACK	"1394 s1394 bus_reset csr stacktrace "
#define	S1394_TNF_SL_CFGROM_ERROR	"1394 s1394 cfgrom error "
#define	S1394_TNF_SL_CFGROM_STACK	"1394 s1394 cfgrom stacktrace "
#define	S1394_TNF_SL_ISOCH_ERROR	"1394 s1394 isoch error "
#define	S1394_TNF_SL_ISOCH_STACK	"1394 s1394 isoch stacktrace "
#define	S1394_TNF_SL_NEXUS_ERROR	"1394 s1394 nexus error "
#define	S1394_TNF_SL_NEXUS_STACK	"1394 s1394 nexus stacktrace "
#define	S1394_TNF_SL_FA_STACK		"1394 s1394 FA stacktrace "
#define	S1394_TNF_SL_FA_ERROR		"1394 s1394 FA error "
#define	S1394_TNF_SL_FCP_STACK		"1394 s1394 FCP stacktrace "
#define	S1394_TNF_SL_FCP_ERROR		"1394 s1394 FCP error "
#define	S1394_TNF_SL_CMP_STACK		"1394 s1394 CMP stacktrace "
#define	S1394_TNF_SL_CMP_ERROR		"1394 s1394 CMP error "

/* s1394_hal_state_t */
typedef enum {
	S1394_HAL_INIT,
	S1394_HAL_RESET,
	S1394_HAL_NORMAL,
	S1394_HAL_DREQ,
	S1394_HAL_SHUTDOWN
} s1394_hal_state_t;

/* s1394_isoch_cec_type_t */
typedef enum {
	S1394_SINGLE		= 1,
	S1394_PEER_TO_PEER	= 2
} s1394_isoch_cec_type_t;

/* s1394_isoch_cec_state_t */
typedef enum {
	ISOCH_CEC_FREE		= (1 << 0),
	ISOCH_CEC_JOIN		= (1 << 1),
	ISOCH_CEC_LEAVE		= (1 << 2),
	ISOCH_CEC_SETUP		= (1 << 3),
	ISOCH_CEC_TEARDOWN	= (1 << 4),
	ISOCH_CEC_START		= (1 << 5),
	ISOCH_CEC_STOP		= (1 << 6)
} s1394_isoch_cec_state_t;

/* s1394_status_t */
typedef enum {
	S1394_NOSTATUS		= (1 << 0),
	S1394_LOCK_FAILED	= (1 << 1),
	S1394_CMD_ALLOC_FAILED	= (1 << 2),
	S1394_XFER_FAILED	= (1 << 3),
	S1394_UNKNOWN		= (1 << 4),
	S1394_CMD_INFLIGHT	= (1 << 5)
} s1394_status_t;

/* s1394_free_cfgrom_t */
typedef enum {
	S1394_FREE_CFGROM_BOTH,
	S1394_FREE_CFGROM_NEW,
	S1394_FREE_CFGROM_OLD
} s1394_free_cfgrom_t;

typedef struct s1394_node_s		s1394_node_t;
typedef struct s1394_target_s		s1394_target_t;
typedef struct s1394_hal_s		s1394_hal_t;
typedef struct s1394_addr_space_blk_s	s1394_addr_space_blk_t;
typedef struct s1394_config_rom_s	s1394_config_rom_t;
typedef struct s1394_kstat_s		s1394_kstat_t;
typedef struct s1394_isoch_cec_s	s1394_isoch_cec_t;
typedef struct s1394_isoch_cec_member_s	s1394_isoch_cec_member_t;

/* cfgrom_dir_t */
typedef struct {
	ushort_t		dir_start;
	ushort_t		dir_size;
	ushort_t		dir_next_quad;
} cfgrom_dir_t;

/* s1394_selfid_pkt_t */
typedef struct s1394_selfid_pkt_s {
	uint32_t		spkt_data;
	uint32_t		spkt_inverse;
} s1394_selfid_pkt_t;

/* s1394_node_t */
struct s1394_node_s {
	s1394_selfid_pkt_t	*selfid_packet;
	s1394_node_t		*phy_port[IEEE1394_MAX_NUM_PORTS];
	s1394_node_t		*old_node;
	s1394_node_t		*cur_node;
	s1394_target_t		*target_list;
	ushort_t		cfgrom_size;		/* in quads */
	ushort_t		cfgrom_valid_size;	/* in quads */
	uchar_t			link_active;
	uchar_t			node_num;
	uchar_t			max_1st;
	uchar_t			max_2nd;
	uchar_t			last_port_checked;
	uchar_t			parent_port;
	uchar_t			is_a_leaf;
	/* All fields above can be zero'd while initing the topology tree */
	uint32_t		*cfgrom;
#define	node_guid_hi		cfgrom[3]
#define	node_guid_lo		cfgrom[4]
#define	node_root_dir		cfgrom[5]
	uint_t			node_state;
	uint_t			cfgrom_state;
	uint_t			bus_enum_flags;
	/* fields dir_stack through expected_dir_quad constitute dir stack */
	cfgrom_dir_t		dir_stack[S1394_DIR_STACK_SIZE];
	ushort_t		cur_dir_start;
	ushort_t		cur_dir_size;
	char			dir_stack_top;
	uchar_t			expected_type;
	uchar_t			expected_dir_quad;
	ushort_t		cfgrom_quad_to_read;
	ushort_t		cfgrom_quad_read_cnt; /* if rdg blk */
	uchar_t			rescan_cnt;
	uchar_t			cfgrom_read_fails;
	uchar_t			cfgrom_read_delay;	/* in ms */
};

/* defines used during enumeration */
#define	NODE_DIR_SIZE(data)		((data) & 0xff)
#define	NODE_DIR_START(data)		(((data) >> 8) & 0xff)
#define	NODE_DIR_QUAD(data)		(((data) >> 16) & 0xff)

/* defines for link_active */
#define	SET_LINK_ACTIVE(n)	((n)->link_active = 1)
#define	CLEAR_LINK_ACTIVE(n) 	((n)->link_active = 0)
#define	LINK_ACTIVE(n)			\
		(((n)->link_active == 0) ? B_FALSE : B_TRUE)
/* defines for state */
#define	S1394_NODE_CONSUMING_PWR	0x00000001
#define	S1394_NODE_ACTIVE		0x00000010
#define	S1394_NODE_BUS_PWR_CONSUMER(n)		\
	((IEEE1394_SELFID_POWER((n)->selfid_packet) > 0x3) ? B_TRUE : B_FALSE)

/* defines for cfgrom_state */
#define	S1394_CFGROM_NEW_ALLOC		0x00000001 /* fresh alloc */
#define	S1394_CFGROM_BIB_READ		0x00000002 /* bus info blocks read */
#define	S1394_CFGROM_ALL_READ		0x00000004 /* read all of it */
#define	S1394_CFGROM_BLK_READ_OK	0x00000008 /* can be read in blocks */
#define	S1394_CFGROM_GEN_CHANGED	0x00000010 /* config rom gen changed */
#define	S1394_CFGROM_PARSED		0x00000020 /* rom enumerated */
#define	S1394_CFGROM_DIR_STACK_OFF	0x00000040 /* dir stack turned off */
#define	S1394_CFGROM_SIZE_IS_CRCSIZE	0x00000080 /* crc size == cfgrom size */

#define	S1394_CFGROM_READ_MASK	(S1394_CFGROM_BIB_READ | S1394_CFGROM_ALL_READ)

#define	S1394_VALID_MASK			\
	(S1394_CFGROM_READ_MASK | S1394_CFGROM_BLK_READ_OK | \
	S1394_CFGROM_GEN_CHANGED | S1394_CFGROM_PARSED)

#define	CLEAR_CFGROM_STATE(n)	((n)->cfgrom_state &= ~S1394_VALID_MASK)
#define	CFGROM_VALID(n)				\
	((((n)->cfgrom_state & S1394_CFGROM_READ_MASK) != 0 && (n)->cfgrom != \
	    NULL) ? B_TRUE : B_FALSE)

/* macros for cfgrom_state */
#define	SET_CFGROM_NEW_ALLOC(n)	((n)->cfgrom_state |= S1394_CFGROM_NEW_ALLOC)
#define	CLEAR_CFGROM_NEW_ALLOC(n) ((n)->cfgrom_state &= ~S1394_CFGROM_NEW_ALLOC)
#define	CFGROM_NEW_ALLOC(n)			\
	(((n)->cfgrom_state & S1394_CFGROM_NEW_ALLOC) != 0 ? B_TRUE : B_FALSE)

#define	SET_CFGROM_BIB_READ(n)	((n)->cfgrom_state |= S1394_CFGROM_BIB_READ)
#define	CLEAR_CFGROM_BIB_READ(n) ((n)->cfgrom_state &= ~S1394_CFGROM_BIB_READ)
#define	CFGROM_BIB_READ(n)			\
	(((n)->cfgrom_state & S1394_CFGROM_BIB_READ) != 0 ? B_TRUE : B_FALSE)

#define	SET_CFGROM_ALL_READ(n)	((n)->cfgrom_state |= S1394_CFGROM_ALL_READ)
#define	CLEAR_CFGROM_ALL_READ(n)	((n)->cfgrom_state &= \
	~S1394_CFGROM_ALL_READ)
#define	CFGROM_ALL_READ(n)				\
	(((n)->cfgrom_state & S1394_CFGROM_ALL_READ) != 0 ? B_TRUE : B_FALSE)

#define	SET_CFGROM_BLK_READ_OK(n)		\
	((n)->cfgrom_state |= S1394_CFGROM_BLK_READ_OK)
#define	CLEAR_CFGROM_BLK_READ_OK(n)		\
	((n)->cfgrom_state &= ~S1394_CFGROM_BLK_READ_OK)
#define	CFGROM_BLK_READ_OK(n)			\
	(((n)->cfgrom_state & S1394_CFGROM_BLK_READ_OK) != 0 : B_TRUE : B_FALSE)

#define	SET_CFGROM_GEN_CHANGED(n)		\
	((n)->cfgrom_state |= S1394_CFGROM_GEN_CHANGED)
#define	CLEAR_CFGROM_GEN_CHANGED(n)		\
	((n)->cfgrom_state &= ~S1394_CFGROM_GEN_CHANGED)
#define	CFGROM_GEN_CHANGED(n)			\
	(((n)->cfgrom_state & S1394_CFGROM_GEN_CHANGED) != 0 ? B_TRUE : B_FALSE)

#define	SET_CFGROM_PARSED(n)	((n)->cfgrom_state |= S1394_CFGROM_PARSED)
#define	CLEAR_CFGROM_PARSED(n)	((n)->cfgrom_state &= ~S1394_CFGROM_PARSED)
#define	CFGROM_PARSED(n)			\
	(((n)->cfgrom_state & S1394_CFGROM_PARSED) != 0 ? B_TRUE : B_FALSE)

#define	SET_CFGROM_DIR_STACK_OFF(n)		\
	((n)->cfgrom_state |= S1394_CFGROM_DIR_STACK_OFF)
#define	CLEAR_CFGROM_DIR_STACK_OFF(n)		\
	((n)->cfgrom_state &= ~S1394_CFGROM_DIR_STACK_OFF)
#define	CFGROM_DIR_STACK_OFF(n)			\
	(((n)->cfgrom_state & S1394_CFGROM_DIR_STACK_OFF) != 0 ? B_TRUE : \
	    B_FALSE)

#define	SET_CFGROM_SIZE_IS_CRCSIZE(n)		\
	((n)->cfgrom_state |= S1394_CFGROM_SIZE_IS_CRCSIZE)
#define	CLEAR_CFGROM_SIZE_IS_CRCSIZE(n)		\
	((n)->cfgrom_state &= ~S1394_CFGROM_SIZE_IS_CRCSIZE)
#define	CFGROM_SIZE_IS_CRCSIZE(n)			\
	(((n)->cfgrom_state & S1394_CFGROM_SIZE_IS_CRCSIZE) != 0 ? B_TRUE : \
	    B_FALSE)

/* defines for bus_enum_flags */
#define	S1394_NODE_VISITED		0x00000001
#define	S1394_NODE_MATCHED		0x00000010

/* macros that set/clear bus_enum_flags */
#define	SET_NODE_VISITED(n)	((n)->bus_enum_flags |= S1394_NODE_VISITED)
#define	CLEAR_NODE_VISITED(n)	((n)->bus_enum_flags &= ~S1394_NODE_VISITED)
#define	NODE_VISITED(n)				\
	(((n)->bus_enum_flags & S1394_NODE_VISITED) != 0 ? B_TRUE : B_FALSE)

#define	SET_NODE_MATCHED(n)	((n)->bus_enum_flags |= S1394_NODE_MATCHED)
#define	CLEAR_NODE_MATCHED(n)	((n)->bus_enum_flags &= ~S1394_NODE_MATCHED)
#define	NODE_MATCHED(n)				\
	(((n)->bus_enum_flags & S1394_NODE_MATCHED) != 0 ? B_TRUE : B_FALSE)

#define	SET_NODE_IDENTIFIED(n)	((n)->bus_enum_flags |= S1394_NODE_IDENTIFIED)
#define	CLEAR_NODE_IDENTIFIED(n) ((n)->bus_enum_flags &= ~S1394_NODE_IDENTIFIED)
#define	NODE_IDENTIFIED(n)			\
	(((n)->bus_enum_flags & S1394_NODE_IDENTIFIED) != 0 ? B_TRUE : B_FALSE)

/*
 * s1394_fa_type_t - FA types, used as index into target_fa and hal_fa
 */
typedef enum {
	S1394_FA_TYPE_FCP_CTL,		/* FCP controller */
	S1394_FA_TYPE_FCP_TGT,		/* FCP target */
	S1394_FA_TYPE_CMP_OMPR,		/* CMP oMPR */
	S1394_FA_TYPE_CMP_IMPR,		/* CMP iMPR */
	S1394_FA_NTYPES,		/* should remain the last field */
	S1394_FA_TYPE_CMP = S1394_FA_TYPE_CMP_OMPR	/* common CMP type */
} s1394_fa_type_t;


/*
 * s1394_fa_descr_t - FA type descriptor
 */
typedef struct s1394_fa_descr_s {
	uint64_t		fd_addr;	/* address space  */
	size_t			fd_size;	/* address space size */
	t1394_addr_enable_t	fd_enable;	/* access types */
	t1394_addr_evts_t	fd_evts;	/* event callbacks */
	uint64_t		fd_conv_base;	/* address conversion base */
} s1394_fa_descr_t;

/*
 * s1394_fcp_target_t - per-target data required for FCP support
 */
typedef struct s1394_fcp_target_s {
	t1394_fcp_evts_t	fc_evts;
} s1394_fcp_target_t;

/*
 * s1394_cmp_target_t - per-target data required for CMP support
 */
typedef struct s1394_cmp_target_s {
	t1394_cmp_evts_t	cm_evts;
} s1394_cmp_target_t;

/*
 * s1394_fa_target_t - per-target data required for fixed address support
 */
typedef struct s1394_fa_target_s {
	s1394_target_t		*fat_next;	/* next in the list */
	/* type-specific data */
	union {
		s1394_fcp_target_t	fcp;
		s1394_cmp_target_t	cmp;
	} fat_u;
} s1394_fa_target_t;

/* s1394_target_t - fields protected by the HAL's target_list_rwlock */
struct s1394_target_s {
	int			target_version;

	dev_info_t		*target_dip;

	/* Pointers to the node and HAL on which the target exists */
	s1394_node_t		*on_node;
	s1394_hal_t		*on_hal;

	s1394_target_t		*target_next;
	s1394_target_t		*target_prev;

	/* target_list is a copy of target_list pointer in the node */
	s1394_target_t		*target_list;
	s1394_target_t		*target_sibling;

	uint_t			unit_dir;

	/* The max_payload sizes - max and current conditions */
	uint_t			dev_max_payload;
	uint_t			current_max_payload;

	/* Number of asynch command target has allocated */
	uint_t			target_num_cmds;

	/*
	 * Are physical AR requests allowed from this target's node?
	 * This field keeps track of the number of allocated blocks
	 * of physical memory the target has.
	 */
	uint_t			physical_arreq_enabled;

	uint_t			target_state;

	/* FCP controller and target */
	s1394_fa_target_t	target_fa[S1394_FA_NTYPES];
};
#define	S1394_TARG_HP_NODE		0x00000001	/* on a hp node */
#define	S1394_TARG_GONE			0x00000002	/* unplugged */
#define	S1394_TARG_USING_BUS_PWR	0x00000004	/* consuming pwr now */
#define	S1394_TARG_BUS_PWR_CONSUMER	0x00000008	/* power consumer */
#define	S1394_TARG_ACTIVE		0x00000010	/* active */

/*
 * s1394_fa_hal_t - per-hal data required for fixed address support
 */
typedef struct s1394_fa_hal_s {
	/*
	 * each hal keeps a list of registered fixed address clients
	 */
	s1394_target_t		*fal_head;
	s1394_target_t		*fal_tail;
	uint_t			fal_gen;	/* list generation */

	s1394_fa_descr_t	*fal_descr;	/* type descriptor */
	s1394_addr_space_blk_t	*fal_addr_blk;	/* address space block */
} s1394_fa_hal_t;

/*
 * s1394_cmp_hal_t - per-hal data required for fixed address support
 */
typedef struct s1394_cmp_hal_s {
	/* oMPR */
	krwlock_t		cmp_ompr_rwlock;
	uint32_t		cmp_ompr_val;
	/* iMPR */
	krwlock_t		cmp_impr_rwlock;
	uint32_t		cmp_impr_val;
} s1394_cmp_hal_t;

/* s1394_hal_t */
struct s1394_hal_s {
	s1394_hal_t		*hal_next;
	s1394_hal_t		*hal_prev;

	/* Target list */
	s1394_target_t		*target_head;
	s1394_target_t		*target_tail;
	krwlock_t		target_list_rwlock;

	/* halinfo structure given at attach time */
	h1394_halinfo_t		halinfo;

	boolean_t		hal_was_suspended;

	/* Bus reset thread */
	kthread_t		*br_thread;
	kmutex_t		br_thread_mutex;
	kcondvar_t		br_thread_cv;
	uint_t			br_thread_ev_type;
	uint32_t		br_cfgrom_read_gen;
	kmutex_t		br_cmplq_mutex;
	kcondvar_t		br_cmplq_cv;
	cmd1394_cmd_t		*br_cmplq_head;
	cmd1394_cmd_t		*br_cmplq_tail;

	s1394_hal_state_t	hal_state;

	/* kstats - kernel statistics for the Services Layer */
	s1394_kstat_t		*hal_kstats;
	kstat_t			*hal_ksp;

	/* CSR STATE register bits (DREQ and ABDICATE) */
	uint_t			disable_requests_bit;
	uint_t			abdicate_bus_mgr_bit;

	boolean_t		initiated_bus_reset;
	int			initiated_br_reason;
	uint32_t		num_bus_reset_till_fail;

	/* IRM and Bus Manager */
	int			IRM_node;
	kmutex_t		bus_mgr_node_mutex;
	kcondvar_t		bus_mgr_node_cv;
	int			bus_mgr_node;
	boolean_t		incumbent_bus_mgr;
	timeout_id_t		bus_mgr_timeout_id;
	timeout_id_t		bus_mgr_query_timeout_id;

	/* 1394 Bus stats */
	int			gap_count;
	int			optimum_gap_count;
	uint8_t			slowest_node_speed;

	/* Local Config ROM */
	kmutex_t		local_config_rom_mutex;
	uint32_t		*local_config_rom;
	uint32_t		*temp_config_rom_buf;
	s1394_config_rom_t	*root_directory;
	uint_t			free_space;
	uint_t			config_rom_update_amount;
	boolean_t		config_rom_timer_set;
	timeout_id_t		config_rom_timer;

	/* Cycle Master - CYCLE_TOO_LONG timer */
	kmutex_t		cm_timer_mutex;
	boolean_t		cm_timer_set;
	timeout_id_t		cm_timer;

	/* Incoming (AR) request and 1394 address space */
	kmutex_t		addr_space_free_mutex;
	s1394_addr_space_blk_t	*addr_space_free_list;
	kmutex_t		addr_space_used_mutex;
	s1394_addr_space_blk_t	*addr_space_used_tree;
	uint64_t		physical_addr_lo;
	uint64_t		physical_addr_hi;
	uint64_t		csr_addr_lo;
	uint64_t		csr_addr_hi;
	uint64_t		normal_addr_lo;
	uint64_t		normal_addr_hi;
	uint64_t		posted_write_addr_lo;
	uint64_t		posted_write_addr_hi;

	/* Outgoing (AT) request queues */
	kmutex_t		outstanding_q_mutex;
	cmd1394_cmd_t		*outstanding_q_head;
	cmd1394_cmd_t		*outstanding_q_tail;
	kmutex_t		pending_q_mutex;
	cmd1394_cmd_t		*pending_q_head;
	cmd1394_cmd_t		*pending_q_tail;

	/* SelfID buffers */
	void			*selfid_buf0;
	void			*selfid_buf1;
	int			current_buffer;
	s1394_selfid_pkt_t	*selfid_ptrs[IEEE1394_MAX_NODES];

	/* Topology trees and local bus stats */
	kmutex_t		topology_tree_mutex;
	uint32_t		cfgroms_being_read;
	s1394_node_t		*topology_tree;
	s1394_node_t		*old_tree;
	uint32_t		generation_count;
	ushort_t		number_of_nodes;
	ushort_t		node_id;
	boolean_t		topology_tree_valid;
	boolean_t		topology_tree_processed;
	uint32_t		old_generation_count;
	ushort_t		old_number_of_nodes;
	ushort_t		old_node_id;
	s1394_node_t		current_tree[IEEE1394_MAX_NODES];
	s1394_node_t		last_valid_tree[IEEE1394_MAX_NODES];
	boolean_t		old_tree_valid;

	/* TOPOLOGY_MAP backing store buffer */
	uint32_t		*CSR_topology_map;

	/* Speed Map */
	uint8_t		speed_map[IEEE1394_MAX_NODES][IEEE1394_MAX_NODES];

	/* Stack, Queue, and Node Number list */
	void 			*hal_stack[IEEE1394_MAX_NODES];
	int			hal_stack_depth;
	void 			*hal_queue[IEEE1394_MAX_NODES];
	int   			hal_queue_front;
	int   			hal_queue_back;
	int			hal_node_number_list[IEEE1394_MAX_NODES];
	int 			hal_node_number_list_size;

	/* Isoch CEC list */
	kmutex_t		isoch_cec_list_mutex;
	s1394_isoch_cec_t	*isoch_cec_list_head;
	s1394_isoch_cec_t	*isoch_cec_list_tail;

	struct kmem_cache	*hal_kmem_cachep;

	ndi_event_hdl_t		hal_ndi_event_hdl;

	callb_cpr_t		hal_cprinfo;

	/* FCP controllers and targets */
	s1394_fa_hal_t		hal_fa[S1394_FA_NTYPES];

	/* CMP support */
	s1394_cmp_hal_t		hal_cmp;
};

_NOTE(SCHEME_PROTECTS_DATA("No lock needed to start/stop timer", \
	s1394_hal_s::cm_timer))

/* defines for br_thread_ev_type */
#define	BR_THR_CFGROM_SCAN		0x00000001	/* start reading */
#define	BR_THR_GO_AWAY			0x00000002	/* clean & exit */

/*
 * FCP command and response address space
 */
#define	IEC61883_FCP_BASE_ADDR	0xFFFFF0000B00
#define	IEC61883_FCP_CMD_ADDR	IEC61883_FCP_BASE_ADDR
#define	IEC61883_FCP_CMD_SIZE	0x200
#define	IEC61883_FCP_RESP_ADDR	(IEC61883_FCP_CMD_ADDR + IEC61883_FCP_CMD_SIZE)
#define	IEC61883_FCP_RESP_SIZE	0x200
#define	IEC61883_FCP_END_ADDR (IEC61883_FCP_RESP_ADDR + IEC61883_FCP_RESP_SIZE)

/* CMP master plugs */
#define	IEC61883_CMP_OMPR_ADDR		0xFFFFF0000900
#define	IEC61883_CMP_IMPR_ADDR		0xFFFFF0000980
#define	IEC61883_CMP_OMPR_INIT_VAL	0xBFFFFF00
#define	IEC61883_CMP_IMPR_INIT_VAL	0x80FFFF00
#define	IEC61883_CMP_OMPR_LOCK_MASK	0x3FFFFF00
#define	IEC61883_CMP_IMPR_LOCK_MASK	0x00FFFF00

/* s1394_addr_space_blk_t */
struct s1394_addr_space_blk_s {
	/* Pointers and coloring for Red-Black tree */
	s1394_addr_space_blk_t		*asb_parent;
	s1394_addr_space_blk_t		*asb_left;
	s1394_addr_space_blk_t		*asb_right;
	uint32_t			asb_color;
	boolean_t			free_kmem_bufp;

	/* Addr Blk info - callbacks, permissions, backing store, etc. */
	uint64_t			addr_lo;
	uint64_t			addr_hi;
	uint32_t			addr_reserved;
	t1394_addr_enable_t		addr_enable;
	t1394_addr_type_t		addr_type;
	t1394_addr_evts_t		addr_events;
	caddr_t				kmem_bufp;
	void				*addr_arg;
};

/* s1394_config_rom_t */
struct s1394_config_rom_s {
	boolean_t		cfgrom_used;
	uint32_t		cfgrom_addr_lo;
	uint32_t		cfgrom_addr_hi;

	uint_t			root_dir_offset;

	s1394_config_rom_t	*cfgrom_next;
	s1394_config_rom_t	*cfgrom_prev;
};

/* s1394_kstat_t */
struct s1394_kstat_s {
	/* Asynch Receive (AR) requests */
	uint_t			arreq_quad_rd;
	uint_t			arreq_blk_rd;
	uint_t			arreq_quad_wr;
	uint_t			arreq_blk_wr;
	uint_t			arreq_lock32;
	uint_t			arreq_lock64;

	uint_t			arreq_blk_rd_size;
	uint_t			arreq_blk_wr_size;

	uint_t			arreq_posted_write_error;

	/* Failure responses to AR requests (sent) */
	uint_t			arresp_quad_rd_fail;
	uint_t			arresp_blk_rd_fail;
	uint_t			arresp_quad_wr_fail;
	uint_t			arresp_blk_wr_fail;
	uint_t			arresp_lock32_fail;
	uint_t			arresp_lock64_fail;

	/* Asynch Transmit (AT) requests */
	uint_t			atreq_quad_rd;
	uint_t			atreq_blk_rd;
	uint_t			atreq_quad_wr;
	uint_t			atreq_blk_wr;
	uint_t			atreq_lock32;
	uint_t			atreq_lock64;

	uint_t			atreq_blk_rd_size;
	uint_t			atreq_blk_wr_size;

	/* Failure responses to AT requests (received) */
	uint_t			atresp_quad_rd_fail;
	uint_t			atresp_blk_rd_fail;
	uint_t			atresp_quad_wr_fail;
	uint_t			atresp_blk_wr_fail;
	uint_t			atresp_lock32_fail;
	uint_t			atresp_lock64_fail;


	/* Allocate & free requests */
	uint_t			cmd_alloc;
	uint_t			cmd_alloc_fail;
	uint_t			cmd_free;
	uint_t			addr_phys_alloc;
	uint_t			addr_posted_alloc;
	uint_t			addr_normal_alloc;
	uint_t			addr_csr_alloc;
	uint_t			addr_alloc_fail;
	uint_t			addr_space_free;

	/* Bus reset and miscellaneous */
	uint_t			bus_reset;
	uint_t			selfid_complete;
	uint_t			selfid_buffer_error;
	uint_t			pending_q_insert;
	uint64_t		guid;
};

_NOTE(SCHEME_PROTECTS_DATA("Statistics", \
	s1394_kstat_s::{arreq_blk_rd arreq_blk_wr arreq_quad_rd arreq_quad_wr \
	cmd_free selfid_buffer_error arreq_posted_write_error}))

/* s1394_isoch_cec_t */
struct s1394_isoch_cec_s {
	s1394_isoch_cec_t		*cec_next;
	s1394_isoch_cec_t		*cec_prev;

	kmutex_t			isoch_cec_mutex;

	/* Isoch CEC member list */
	s1394_isoch_cec_type_t		cec_type;
	s1394_isoch_cec_member_t	*cec_member_list_head;
	s1394_isoch_cec_member_t	*cec_member_list_tail;
	s1394_isoch_cec_member_t	*cec_member_talker;

	/* Properties given in t1394_alloc_isoch_cec() */
	t1394_isoch_cec_props_t		cec_alloc_props;

	/* Current state of Isoch CEC */
	uint_t				filter_min_speed;
	uint_t				filter_max_speed;
	uint_t				filter_current_speed;
	uint64_t			filter_channel_mask;
	uint_t				bandwidth;
	t1394_cec_options_t		cec_options;
	s1394_isoch_cec_state_t		state_transitions;
	boolean_t			in_callbacks;
	boolean_t			in_fail_callbacks;
	kcondvar_t			in_callbacks_cv;
	boolean_t			cec_want_wakeup;

	boolean_t			realloc_valid;
	boolean_t			realloc_failed;
	t1394_isoch_rsrc_error_t	realloc_fail_reason;
	uint_t				realloc_chnl_num;
	uint_t				realloc_bandwidth;
	uint_t				realloc_speed;
};
#define	CEC_IN_ANY_CALLBACKS(cec)	(((cec)->in_callbacks == B_TRUE) || \
					((cec)->in_fail_callbacks == B_TRUE))

#define	CEC_TRANSITION_LEGAL(cec, tran)	((cec)->state_transitions & (tran))
#define	CEC_SET_LEGAL(cec, tran)	((cec)->state_transitions |= (tran))
#define	CEC_SET_ILLEGAL(cec, tran)	((cec)->state_transitions &= ~(tran))


/* s1394_isoch_cec_member_t */
struct s1394_isoch_cec_member_s {
	s1394_isoch_cec_member_t	*cec_mem_next;
	s1394_isoch_cec_member_t	*cec_mem_prev;

	/* Events for Isoch CEC member - given in t1394_join_isoch_cec() */
	t1394_isoch_cec_evts_t		isoch_cec_evts;
	opaque_t			isoch_cec_evts_arg;
	uint64_t			req_channel_mask;
	uint_t				req_max_speed;
	t1394_jii_options_t		cec_mem_options;
	s1394_target_t			*cec_mem_target;
};

/* cmd1394_fa_cmd_priv_t - per-command data for fixed address support */
typedef struct s1394_fa_cmd_priv_s {
	s1394_fa_type_t		type;
	void			(*completion_callback)();
	opaque_t		callback_arg;
} s1394_fa_cmd_priv_t;

/* s1394_cmd_priv_t */
typedef struct s1394_cmd_priv_s {
	/* Services Layer private structure for asynch commands */
	cmd1394_cmd_t		*cmd_priv_next;
	cmd1394_cmd_t		*cmd_priv_prev;

	uint32_t		cmd_priv_xfer_type;
	s1394_target_t		*sent_by_target;
	s1394_hal_t		*sent_on_hal;

	int			lock_req_step;
	int			temp_num_retries;

	size_t			data_remaining;

	kmutex_t		blocking_mutex;
	kcondvar_t		blocking_cv;
	boolean_t		blocking_flag;

	boolean_t		cmd_in_use;
	boolean_t		posted_write;
	boolean_t		arreq_valid_addr;

	/*
	 * Commands can be extended to support additional functionality.
	 * The only extension at this time is FA (currently used only for FCP).
	 * The downside here is that every command should carry FA overhead
	 * even if the target doesn't use FA. However, alternative approaches
	 * would require separate allocation of FA overhead per command, which
	 * complicates the code and fragments the memory -- seems not worth it
	 * given that FA overhead is just a few bytes and there's a limit of
	 * 256 commands per target.
	 */
	int			cmd_ext_type;
	union {
		s1394_fa_cmd_priv_t	fa;
	} cmd_ext;

	h1394_cmd_priv_t	hal_cmd_private;
} s1394_cmd_priv_t;
#define	S1394_GET_CMD_PRIV(cmd)	\
	((s1394_cmd_priv_t *)((uchar_t *)(cmd) + sizeof (cmd1394_cmd_t)))

/* command extension types */
enum {
	S1394_CMD_EXT_FA	= 1
};
#define	S1394_GET_FA_CMD_PRIV(cmd)	(&(S1394_GET_CMD_PRIV(cmd)->cmd_ext.fa))

#define	S1394_IS_CMD_FCP(s_priv) \
	((s_priv->cmd_ext.fa.type == S1394_FA_TYPE_FCP_CTL) || \
	(s_priv->cmd_ext.fa.type == S1394_FA_TYPE_FCP_TGT))

_NOTE(SCHEME_PROTECTS_DATA("Unique per command", \
	s1394_cmd_priv_s::cmd_priv_xfer_type))


/* s1394_state_t */
typedef struct s1394_state_s {
	/* HAL list */
	kmutex_t	hal_list_mutex;
	s1394_hal_t	*hal_head;
	s1394_hal_t	*hal_tail;
} s1394_state_t;

/* Service Layer Global State Pointer */
extern   s1394_state_t  *s1394_statep;


/* 1394 Services Layer Internals - 1394 Address Space Routines */
int s1394_request_addr_blk(s1394_hal_t *hal, t1394_alloc_addr_t *addr_allocp);

int s1394_claim_addr_blk(s1394_hal_t *hal, t1394_alloc_addr_t *addr_allocp);

int s1394_free_addr_blk(s1394_hal_t *hal, s1394_addr_space_blk_t *blk);

int s1394_reserve_addr_blk(s1394_hal_t *hal, t1394_alloc_addr_t *addr_allocp);

int s1394_init_addr_space(s1394_hal_t *hal);

void s1394_destroy_addr_space(s1394_hal_t *hal);

void s1394_free_list_insert(s1394_hal_t *hal, s1394_addr_space_blk_t *new_blk);

s1394_addr_space_blk_t *s1394_used_tree_search(s1394_hal_t *hal,
    uint64_t addr);

s1394_addr_space_blk_t *s1394_used_tree_delete(s1394_hal_t *hal,
    s1394_addr_space_blk_t *z);

boolean_t s1394_is_posted_write(s1394_hal_t *hal, uint64_t addr);

boolean_t s1394_is_physical_addr(s1394_hal_t *hal, uint64_t addr);

boolean_t s1394_is_csr_addr(s1394_hal_t *hal, uint64_t addr);

boolean_t s1394_is_normal_addr(s1394_hal_t *hal, uint64_t addr);

/* 1394 Services Layer Internals - Asynchronous Communications Routines */
int s1394_alloc_cmd(s1394_hal_t *hal, uint_t flags, cmd1394_cmd_t **cmdp);

int s1394_free_cmd(s1394_hal_t *hal, cmd1394_cmd_t **cmdp);

int s1394_xfer_asynch_command(s1394_hal_t *hal, cmd1394_cmd_t *cmd, int *err);

int s1394_setup_asynch_command(s1394_hal_t *hal, s1394_target_t *target,
    cmd1394_cmd_t *cmd, uint32_t xfer_type, int *err);

void s1394_insert_q_asynch_cmd(s1394_hal_t *hal, cmd1394_cmd_t *cmd);

void s1394_remove_q_asynch_cmd(s1394_hal_t *hal, cmd1394_cmd_t *cmd);

void s1394_atreq_cmd_complete(s1394_hal_t *hal, cmd1394_cmd_t *req,
    int status);

void s1394_atresp_cmd_complete(s1394_hal_t *hal, cmd1394_cmd_t *resp,
    int status);

int s1394_send_response(s1394_hal_t *hal, cmd1394_cmd_t *resp);

int s1394_compare_swap(s1394_hal_t *hal, s1394_target_t *target,
    cmd1394_cmd_t *cmd);

int s1394_split_lock_req(s1394_hal_t *hal, s1394_target_t *target,
    cmd1394_cmd_t *cmd);

void s1394_pending_q_insert(s1394_hal_t *hal, cmd1394_cmd_t *cmd, uint_t flags);

void s1394_resend_pending_cmds(s1394_hal_t *hal);

/* 1394 Services Layer Internals - Bus Reset Routines */
int s1394_parse_selfid_buffer(s1394_hal_t *hal, void *selfid_buf_addr,
    uint32_t selfid_size);

void s1394_sort_selfids(s1394_hal_t *hal);

void s1394_init_topology_tree(s1394_hal_t *hal, boolean_t copied,
    ushort_t number_of_nodes);

int s1394_topology_tree_build(s1394_hal_t *hal);

void s1394_topology_tree_mark_all_unvisited(s1394_hal_t *hal);

void s1394_old_tree_mark_all_unvisited(s1394_hal_t *hal);

void s1394_old_tree_mark_all_unmatched(s1394_hal_t *hal);

void s1394_copy_old_tree(s1394_hal_t *hal);

void s1394_match_tree_nodes(s1394_hal_t *hal);

int s1394_topology_tree_calculate_diameter(s1394_hal_t *hal);

int s1394_gap_count_optimize(int diameter);

int s1394_get_current_gap_count(s1394_hal_t *hal);

void s1394_speed_map_fill(s1394_hal_t *hal);

uint8_t s1394_speed_map_get(s1394_hal_t *hal, uint32_t from_node,
    uint32_t to_node);

void s1394_update_speed_map_link_speeds(s1394_hal_t *hal);

int s1394_get_isoch_rsrc_mgr(s1394_hal_t *hal);

void s1394_physical_arreq_setup_all(s1394_hal_t *hal);

void s1394_physical_arreq_set_one(s1394_target_t *target);

void s1394_physical_arreq_clear_one(s1394_target_t *target);

s1394_node_t *s1394_topology_tree_get_root_node(s1394_hal_t *hal);

/* 1394 Services Layer Internals - CSR and Config ROM Routines */
int s1394_setup_CSR_space(s1394_hal_t *hal);

void s1394_CSR_topology_map_update(s1394_hal_t *hal);

void s1394_CSR_topology_map_disable(s1394_hal_t *hal);

int s1394_init_local_config_rom(s1394_hal_t *hal);

void s1394_destroy_local_config_rom(s1394_hal_t *hal);

int s1394_add_config_rom_entry(s1394_hal_t *hal, uint8_t key,
    uint32_t *buffer, uint_t size, void **handle, int *status);

int s1394_remove_config_rom_entry(s1394_hal_t *hal, void **handle,
    int *status);

void s1394_update_config_rom_callback(void *arg);

/* In s1394_dev_disc.c */
void s1394_br_thread(s1394_hal_t *hal);

void s1394_free_cfgrom(s1394_hal_t *hal, s1394_node_t *node,
    s1394_free_cfgrom_t options);

void s1394_copy_cfgrom(s1394_node_t *to, s1394_node_t *from);

int s1394_read_rest_of_cfgrom(s1394_hal_t *hal, s1394_node_t *node,
    s1394_status_t *status);

void s1394_cfgrom_parse_unit_dir(uint32_t *unit_dir, uint32_t *addr_hi,
    uint32_t *addr_lo, uint32_t *size_hi, uint32_t *size_lo);

boolean_t s1394_valid_cfgrom(s1394_hal_t *hal, s1394_node_t *node);

boolean_t s1394_valid_dir(s1394_hal_t *hal, s1394_node_t *node, uint32_t key,
    uint32_t *dir);

void s1394_get_maxpayload(s1394_target_t *target, uint_t *dev_max_payload,
    uint_t *current_max_payload);

int s1394_lock_tree(s1394_hal_t *hal);

void s1394_unlock_tree(s1394_hal_t *hal);

/* 1394 Services Layer Driver - Hotplug Routines */
dev_info_t *s1394_devi_find(dev_info_t *pdip, char *name, char *caddr);

int s1394_update_devinfo_tree(s1394_hal_t *hal, s1394_node_t *node);

int s1394_offline_node(s1394_hal_t *hal, s1394_node_t *node);

int s1394_process_topology_tree(s1394_hal_t *hal, int *wait_for_cbs,
    uint_t *wait_gen);

int s1394_process_old_tree(s1394_hal_t *hal);

void s1394_add_target_to_node(s1394_target_t *target);

void s1394_remove_target_from_node(s1394_target_t *target);

/* fixed address support */
int s1394_fa_claim_addr(s1394_hal_t *hal, s1394_fa_type_t type,
    s1394_fa_descr_t *descr);

void s1394_fa_free_addr(s1394_hal_t *hal, s1394_fa_type_t type);

void s1394_fa_list_add(s1394_hal_t *hal, s1394_target_t *target,
    s1394_fa_type_t type);

int s1394_fa_list_remove(s1394_hal_t *hal, s1394_target_t *target,
    s1394_fa_type_t type);

boolean_t s1394_fa_list_is_empty(s1394_hal_t *hal, s1394_fa_type_t type);

uint_t s1394_fa_list_gen(s1394_hal_t *hal, s1394_fa_type_t type);

void s1394_fa_init_cmd(s1394_cmd_priv_t *s_priv, s1394_fa_type_t type);

void s1394_fa_convert_cmd(s1394_hal_t *hal, cmd1394_cmd_t *cmd);

void s1394_fa_restore_cmd(s1394_hal_t *hal, cmd1394_cmd_t *cmd);

void s1394_fa_check_restore_cmd(s1394_hal_t *hal, cmd1394_cmd_t *cmd);

/* FCP */
int s1394_fcp_hal_init(s1394_hal_t *hal);

int s1394_fcp_register_ctl(s1394_target_t *target, t1394_fcp_evts_t *evts);

int s1394_fcp_register_tgt(s1394_target_t *target, t1394_fcp_evts_t *evts);

int s1394_fcp_unregister_ctl(s1394_target_t *target);

int s1394_fcp_unregister_tgt(s1394_target_t *target);

int s1394_fcp_write_check_cmd(cmd1394_cmd_t *cmd);

/* CMP */
int s1394_cmp_register(s1394_target_t *target, t1394_cmp_evts_t *evts);

int s1394_cmp_unregister(s1394_target_t *target);

int s1394_cmp_read(s1394_target_t *target, t1394_cmp_reg_t reg, uint32_t *valp);

int s1394_cmp_cas(s1394_target_t *target, t1394_cmp_reg_t reg, uint32_t arg_val,
    uint32_t new_val, uint32_t *old_valp);

/* 1394 Services Layer Internals - Isochronous Communication Routines */
void s1394_isoch_rsrc_realloc(s1394_hal_t *hal);

void s1394_isoch_rsrc_realloc_notify(s1394_hal_t *hal);

int s1394_channel_alloc(s1394_hal_t *hal, uint32_t channel_mask,
    uint_t generation, uint_t flags, uint32_t *old_channels, int *result);

int s1394_channel_free(s1394_hal_t *hal, uint32_t channel_mask,
    uint_t generation, uint_t flags, uint32_t *old_channels, int *result);

int s1394_bandwidth_alloc(s1394_hal_t *hal, uint32_t bw_alloc_units,
    uint_t generation, int *result);

uint_t s1394_compute_bw_alloc_units(s1394_hal_t *hal, uint_t bandwidth,
    uint_t speed);

int s1394_bandwidth_free(s1394_hal_t *hal, uint32_t bw_alloc_units,
    uint_t generation, int *result);

void s1394_isoch_cec_list_insert(s1394_hal_t *hal, s1394_isoch_cec_t *cec);

void s1394_isoch_cec_list_remove(s1394_hal_t *hal, s1394_isoch_cec_t *cec);

void s1394_isoch_cec_member_list_insert(s1394_hal_t *hal,
    s1394_isoch_cec_t *cec, s1394_isoch_cec_member_t *member);

void s1394_isoch_cec_member_list_remove(s1394_hal_t *hal,
    s1394_isoch_cec_t *cec, s1394_isoch_cec_member_t *member);

/* 1394 Services Layer Internals - Miscellaneous Routines */
void s1394_cleanup_for_detach(s1394_hal_t *hal, uint_t cleanup_level);

void s1394_hal_shutdown(s1394_hal_t *hal, boolean_t disable_hal);

void s1394_initiate_hal_reset(s1394_hal_t *hal, int reason);

boolean_t s1394_on_br_thread(s1394_hal_t *hal);

void s1394_destroy_br_thread(s1394_hal_t *hal);

void s1394_tickle_bus_reset_thread(s1394_hal_t *hal);

void s1394_block_on_asynch_cmd(cmd1394_cmd_t *cmd);

int s1394_HAL_asynch_error(s1394_hal_t *hal, cmd1394_cmd_t *cmd,
    s1394_hal_state_t state);

boolean_t s1394_mblk_too_small(cmd1394_cmd_t *cmd);

boolean_t s1394_address_rollover(cmd1394_cmd_t *cmd);

uint_t s1394_stoi(char *p, int len, int base);

uint_t s1394_CRC16(uint_t *d, uint_t crc_length);

uint_t s1394_CRC16_old(uint_t *d, uint_t crc_length);

int s1394_ioctl(s1394_hal_t *hal, int cmd, intptr_t arg, int mode,
    cred_t *cred_p, int *rval_p);

void s1394_check_pwr_mgmt(s1394_hal_t *hal, s1394_target_t *target,
    boolean_t add);

int s1394_kstat_init(s1394_hal_t *hal);

int s1394_kstat_delete(s1394_hal_t *hal);

int s1394_kstat_update(kstat_t *ksp, int rw);

void s1394_addr_alloc_kstat(s1394_hal_t *hal, uint64_t addr);

void s1394_print_node_info(s1394_hal_t *hal);

s1394_hal_t *s1394_dip_to_hal(dev_info_t *dip);

s1394_target_t *s1394_target_from_dip(s1394_hal_t *hal, dev_info_t *tdip);
s1394_target_t *s1394_target_from_dip_locked(s1394_hal_t *hal,
    dev_info_t *tdip);

void s1394_destroy_timers(s1394_hal_t *hal);

void s1394_cycle_too_long_callback(void *arg);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_S1394_H */
