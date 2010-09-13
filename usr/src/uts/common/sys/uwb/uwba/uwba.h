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

#ifndef _SYS_UWB_UWBA_H
#define	_SYS_UWB_UWBA_H

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * UWBA private header file.
 */

#include <sys/note.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/list.h>
#include <sys/bitset.h>
#include <sys/bitmap.h>

#include <sys/uwb/uwb.h>
#include <sys/uwb/uwbai.h>

/* For logging. */
#define	UWBA_LOG_DEBUG		2
#define	UWBA_LOG_LOG		1
#define	UWBA_LOG_CONSOLE	0

#define	offsetof(s, m)	((size_t)(&(((s *)0)->m)))
#define	isdigit(ch) ((ch >= '0') && (ch <= '9'))

#define	UWB_RAW_RESULT_CODE_SIZE	5  /* size of RCEB + bResultCode */
#define	UWB_RAW_RCCB_HEAD_SIZE		4  /* size of RCCB */

#define	UWB_RAW_BEVENTTYPE_OFFSET	0  /* offset of bEventType */
#define	UWB_RAW_WEVENT_OFFSET		1  /* offset of wEvent */
#define	UWB_RAW_BEVENTCONTEXT_OFFSET	3  /* offset of bEventContext */
#define	UWB_RAW_BRESULTCODE_OFFSET	4  /* offset of bResultCode */



#define	UWB_CTXT_ID_TOP		0xfe	/* top context id */
#define	UWB_CTXT_ID_BOTTOM	0x1	/* bottom context id */
#define	UWB_CTXT_ID_NOTIF	0x0	/* notification context id */
#define	UWB_CTXT_ID_UNVALID	0xff	/* invalid context id */


#define	UWB_INVALID_EVT_CODE 0x7ffe	/* invalid evt/notif code */
#define	UWB_INVALID_EVT_SIZE 0x7fff	/* invalid evt length */

#define	UWB_MAX_NOTIF_NUMBER 10		/* Max notifications in a notif_list */

#define	UWB_MAX_CDEV_NUMBER 32		/* Max client radio device */

/*
 * Offset of data rates Bits in PHY Capability Bitmap.
 * [ECMA, 16.8.16, table 112]
 */
#define	UWB_RATE_OFFSET_BASE 16
/* the offset of data rate 53.3Mbps in PHY capability bitmap */
#define	UWB_RATE_OFFSET_53 UWB_RATE_OFFSET_BASE
#define	UWB_RATE_OFFSET_80 (UWB_RATE_OFFSET_BASE + 1) /* 80Mbps */
#define	UWB_RATE_OFFSET_106 (UWB_RATE_OFFSET_BASE + 2)
#define	UWB_RATE_OFFSET_160 (UWB_RATE_OFFSET_BASE + 3)
#define	UWB_RATE_OFFSET_200 (UWB_RATE_OFFSET_BASE + 4)
#define	UWB_RATE_OFFSET_320 (UWB_RATE_OFFSET_BASE + 5)
#define	UWB_RATE_OFFSET_400 (UWB_RATE_OFFSET_BASE + 6)
#define	UWB_RATE_OFFSET_480 (UWB_RATE_OFFSET_BASE + 7)

typedef int  (*uwb_rccb_handler_t)(uwb_dev_handle_t, uwb_rccb_cmd_t *);
#define	UWB_RCCB_NULL_HANDLER ((uwb_rccb_handler_t)0)

#define	UWB_STATE_IDLE		0
#define	UWB_STATE_BEACON	1
#define	UWB_STATE_SCAN		2

/* radio client device */
typedef struct uwba_client_dev {
	uint8_t			bChannelNumber;
	uint8_t			bBeaconType;
	uint16_t		wBPSTOffset;
	uwb_beacon_frame_t	beacon_frame;
	list_node_t		dev_node;
} uwba_client_dev_t;

/* Command result from the radio controller */
typedef struct uwb_cmd_result {
	uwb_rceb_head_t rceb;

	/* Cmd result data from device when cmd is finished. */
	uint8_t		buf[1];
} uwb_cmd_result_t;


typedef struct uwb_cmd_result_wrapper {
	/* Length of a uwb cmd_result */
	int			length;

	uwb_cmd_result_t	*cmd_result;
} uwb_cmd_result_wrapper_t;

typedef struct uwb_notif_wrapper {
	/* Length of uwb notifcation */
	int		length;
	uwb_rceb_notif_t	*notif;

	list_node_t	notif_node;
} uwb_notif_wrapper_t;



typedef struct uwba_dev {
	/* dip of the uwb radio controller device */
	dev_info_t	*dip;

	/* Dev and instance */
	char		*devinst;

	kmutex_t	dev_mutex;

	/* send cmd to the device */
	int	(*send_cmd)(uwb_dev_handle_t, mblk_t *, uint16_t);

	/* current command block */
	uwb_rccb_cmd_t	curr_rccb;

	/* wait for cmd complete and the cmd result available */
	kcondvar_t	cmd_result_cv;
	kcondvar_t	cmd_handler_cv;

	/* filled by uwb_fill_cmd_result in rc driver's cmd call back */
	uwb_cmd_result_wrapper_t cmd_result_wrap;

	/*
	 * set to TRUE when start to do cmd ioctl;
	 * set to FALSE when put_cmd and exit cmd ioctl
	 */
	boolean_t	cmd_busy;

	/* Device state */
	uint8_t		dev_state;

	/* Beacon or scan channel */
	uint8_t		channel;

	/* Device address */
	uint16_t	dev_addr;

	/* notifications from radio controller device */
	list_t		notif_list;

	/* the current number of notifications in the notif_list */
	int		notif_cnt;

	/* client radio devices found through beacons by this radio host */
	list_t		client_dev_list;

	/* the current number of devices in dev_list */
	int		client_dev_cnt;

	/* context id is maintained by uwba */
	uint8_t		ctxt_id;	/* current command context id */
	bitset_t	ctxt_bits;	/* command context bit map */

	/* PHY capability bitmap, saved from PHY capability IE */
	ulong_t		phy_cap_bm;

	/* list node of a uwb radio host device */
	list_node_t	uwba_dev_node;
} uwba_dev_t;

_NOTE(MUTEX_PROTECTS_DATA(uwba_dev_t::dev_mutex, uwba_dev_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(uwba_dev_t::{
	dip
	devinst
	send_cmd
	phy_cap_bm
	notif_cnt
	dev_state
	dip
	ctxt_id
	ctxt_bits
	notif_list
	cmd_result_wrap
	client_dev_cnt
	channel
	dev_addr
}))


typedef struct uwba_evt_size {
	/* length of a evt/notif structure, impact by alignment */
	uint8_t	struct_len;

	/*
	 * offset of the length member of an event/notif struct.
	 * if zero, means there is no variable buf length member
	 * in this struct
	 */
	uint16_t	buf_len_offset;
} uwba_evt_size_t;
typedef struct uwba_channel_range {
	/* First channel in the specific bandgroup */
	uint8_t base;

	/* Length since this first channel in the bandgroup */
	uint8_t offset;
}  uwba_channel_range_t;

#define	UWB_RESULT_CODE_SIZE	(sizeof (uwb_rceb_result_code_t))

/* str_t is the struct type of the notif/evt */
#define	UWB_EVT_RCEB_SZ		(sizeof (uwb_rceb_t))

/* the size after excluded the rceb head */
#define	UWB_EVT_END_SZ(stru_t)	(sizeof (stru_t) - sizeof (uwb_rceb_t))

#define	UWB_EVT_NO_BUF_LEN_OFFSET	0

/* Offset of wBeaconInfoLength in uwb_rceb_beacon_t */
#define	UWB_BEACONINFOLEN_OFFSET 10

/* Offset of BeaconInfo from bChannelNumber in uwb_rceb_beacon_t */
#define	UWB_BEACONINFO_OFFSET 8

/*
 * UWB radio controller device list
 */
void	uwba_dev_add_to_list(uwba_dev_t *);
void	uwba_dev_rm_from_list(uwba_dev_t *);
void	uwba_alloc_uwb_dev(dev_info_t *, uwba_dev_t **, uint_t);
void	uwba_free_uwb_dev(uwba_dev_t *);
uwb_dev_handle_t uwba_dev_search(dev_info_t *);

/*
 * Context ID operations
 */
void	uwba_init_ctxt_id(uwba_dev_t *);
void	uwba_fini_ctxt_id(uwba_dev_t *);
uint8_t	uwba_get_ctxt_id(uwba_dev_t *);
void	uwba_free_ctxt_id(uwba_dev_t *, uint8_t);

void		uwba_fill_rccb_head(uwba_dev_t *, uint16_t, mblk_t *);
uint16_t	uwba_get_evt_code(uint8_t *, int);
uint16_t	uwba_get_evt_size(uint8_t *, int, uint16_t);

void	uwba_put_cmd_result(uwba_dev_t *, void *, uint16_t);
int	uwba_add_notif_to_list(uwba_dev_t *, void *, uint16_t);

/*
 * Parse events/notifications from radio controller device
 */
int	uwba_parse_data(char *,	uchar_t *, size_t, void *, size_t);
int	uwba_parse_rceb(uint8_t *, size_t,	void *, size_t);
int	uwba_parse_dev_addr_mgmt(uint8_t *, int, uwb_rceb_dev_addr_mgmt_t *);
int	uwba_parse_get_ie(uwb_dev_handle_t, uint8_t *,
	int, uwb_rceb_get_ie_t *);
int	uwba_parse_beacon_rcv(uwb_dev_handle_t, uint8_t *,
	int, uwb_rceb_beacon_t *);
int	uwba_parse_bpoie_chg(uwb_dev_handle_t, uint8_t *,
	int, uwb_rceb_bpoie_change_t *);
uint8_t uwba_allocate_channel(uwb_dev_handle_t);
uint8_t *uwba_find_ie(uwb_dev_handle_t, uint_t, uint8_t *, uint16_t);

void uwba_copy_rccb(uwb_rccb_cmd_t *, uwb_rccb_cmd_t *);

uwba_client_dev_t *uwba_find_cdev_by_channel(uwba_dev_t *, uint8_t);

/* Debug/message log */
void	uwba_log(uwba_dev_t *, uint_t, char *, ...);
const char *uwba_event_msg(uint16_t);

/* Turn a little endian byte array to a uint32_t */
#define	LE_TO_UINT32(src, off, des) \
{ \
	uint32_t tmp; \
	des = src[off + 3]; \
	des = des << 24; \
	tmp = src[off + 2]; \
	des |= tmp << 16; \
	tmp = src[off + 1]; \
	des |= tmp << 8; \
	des |= src[off]; \
}

/* Turn a uint32_t to a little endian byte array */
#define	UINT32_TO_LE(src, off, des) \
{ \
	des[off + 0] = 0xff & src; \
	des[off + 1] = 0xff & (src >> 8); \
	des[off + 2] = 0xff & (src >> 16); \
	des[off + 3] = 0xff & (src >> 24); \
}

/* Turn a little endian byte array to a uint16_t */
#define	LE_TO_UINT16(src, off, des) \
{ \
	des = src[off + 1]; \
	des = des << 8; \
	des |= src[off]; \
}

/* Turn a uint16_t to alittle endian byte array */
#define	UINT16_TO_LE(src, off, des) \
{ \
	des[off + 0] = 0xff & src; \
	des[off + 1] = 0xff & (src >> 8); \
}


/* Max string length for the driver name and instance number. */
#define	UWB_MAXSTRINGLEN 255


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_UWB_UWBA_H */
