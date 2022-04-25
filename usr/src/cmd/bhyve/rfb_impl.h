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
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _RFB_IMPL_H
#define	_RFB_IMPL_H

#include <stdatomic.h>
#include <stdbool.h>
#include <zlib.h>
#include <sys/types.h>
#include <sys/list.h>

#include "mevent.h"

/*
 * The ProtocolVersion message consists of 12 bytes interpreted as a string of
 * ASCII characters in the format "RFB xxx.yyy\n" where xxx and yyy are the
 * major and minor version numbers, padded with zeros.
 */
#define	RFB_VERSION			"RFB 003.008\n"
#define	RFB_VERSION_LEN			(sizeof (RFB_VERSION) - 1)

_Static_assert(RFB_VERSION_LEN == 12, "RFB_VERSION length incorrect");

/* Keep synchronised with pci_fbuf.c */
#define	RFB_MAX_WIDTH			1920
#define	RFB_MAX_HEIGHT			1200

#define	RFB_MAX_CLIENTS			10

/* Framebuffer pixel format */
#define	RFB_PIX_BPP			32
#define	RFB_PIX_DEPTH			24
#define	RFB_PIX_RSHIFT			16
#define	RFB_PIX_GSHIFT			8
#define	RFB_PIX_BSHIFT			0
#define	RFB_PIX_RMAX			255
#define	RFB_PIX_GMAX			255
#define	RFB_PIX_BMAX			255

#define	RFB_ZLIB_BUFSZ			(RFB_MAX_WIDTH * RFB_MAX_HEIGHT * 4)

#define	RFB_PIX_PER_CELL		32
#define	RFB_PIXCELL_SHIFT		5
#define	RFB_PIXCELL_MASK		0x1f
#define	RFB_SENDALL_THRESH		25

#define	RFB_SEL_DELAY_US		10000
#define	RFB_SCREEN_REFRESH_DELAY	33300   /* 30 Hz */
#define	RFB_SCREEN_POLL_DELAY		(RFB_SCREEN_REFRESH_DELAY / 2)

/* Client-to-server message types */
#define	RFBP_CS_SET_PIXEL_FORMAT	0
#define	RFBP_CS_SET_ENCODINGS		2
#define	RFBP_CS_UPDATE_REQUEST		3
#define	RFBP_CS_KEY_EVENT		4
#define	RFBP_CS_POINTER_EVENT		5
#define	RFBP_CS_CUT_TEXT		6
#define	RFBP_CS_QEMU			255
#define	RFBP_CS_QEMU_KEVENT		0

/* Server-to-client message types */
#define	RFBP_SC_UPDATE			0
#define	RFBP_SC_SET_COLOURMAP_ENTRIES	1
#define	RFBP_SC_BELL			2
#define	RFBP_SC_CUT_TEXT		3

/* Encodings */
#define	RFBP_ENCODING_RAW		0
#define	RFBP_ENCODING_ZLIB		6
/* Pseudo-encodings */
#define	RFBP_ENCODING_RESIZE		-223
#define	RFBP_ENCODING_EXT_KEVENT	-258	/* QEMU ext. key event */
#define	RFBP_ENCODING_DESKTOP_NAME	-307

/* Security types */
#define	RFBP_SECURITY_INVALID		0
#define	RFBP_SECURITY_NONE		1
#define	RFBP_SECURITY_VNC_AUTH		2

#define	RFBP_SECURITY_VNC_AUTH_LEN	16
#define	RFBP_SECURITY_VNC_PASSWD_LEN	8

typedef enum rfb_loglevel {
	RFB_LOGDEBUG,
	RFB_LOGWARN,
	RFB_LOGERR
} rfb_loglevel_t;

typedef enum rfb_encodings {
	RFB_ENCODING_RAW		= (1ULL << 0),
	RFB_ENCODING_ZLIB		= (1ULL << 1),
	RFB_ENCODING_RESIZE		= (1ULL << 2),
	RFB_ENCODING_EXT_KEVENT		= (1ULL << 3),
	RFB_ENCODING_DESKTOP_NAME	= (1ULL << 4)
} rfb_encodings_t;

typedef enum rfb_cver {
	RFB_CVER_3_3,
	RFB_CVER_3_7,
	RFB_CVER_3_8
} rfb_cver_t;

typedef struct rfb_pixfmt {
	uint8_t			rp_bpp;
	uint8_t			rp_depth;
	uint8_t			rp_bigendian;
	uint8_t			rp_truecolour;
	uint16_t		rp_r_max;
	uint16_t		rp_g_max;
	uint16_t		rp_b_max;
	uint8_t			rp_r_shift;
	uint8_t			rp_g_shift;
	uint8_t			rp_b_shift;
	uint8_t			rp_pad[3];
} __packed rfb_pixfmt_t;

/* Server-to-client message formats */

typedef struct rfb_server_info {
	uint16_t		rsi_width;
	uint16_t		rsi_height;
	rfb_pixfmt_t		rsi_pixfmt;
	uint32_t		rsi_namelen;
} __packed rfb_server_info_t;

typedef struct rfb_server_update_msg {
	uint8_t			rss_type;
	uint8_t			rss_pad;
	uint16_t		rss_numrects;
} __packed rfb_server_update_msg_t;

typedef struct rfb_rect_hdr {
	uint16_t		rr_x;
	uint16_t		rr_y;
	uint16_t		rr_width;
	uint16_t		rr_height;
	uint32_t		rr_encoding;
} __packed rfb_rect_hdr_t;

/* Client-to-server message formats */

typedef struct rfb_cs_pixfmt_msg  {
	uint8_t			rp_pad[3];
	rfb_pixfmt_t		rp_pixfmt;
} __packed rfb_cs_pixfmt_msg_t;

typedef struct rfb_cs_update_msg {
	uint8_t			rum_incremental;
	uint16_t		rum_x;
	uint16_t		rum_y;
	uint16_t		rum_width;
	uint16_t		rum_height;
} __packed rfb_cs_update_msg_t;

typedef struct rfb_cs_encodings_msg {
	uint8_t			re_pad;
	uint16_t		re_numencs;
} __packed rfb_cs_encodings_msg_t;

typedef struct rfb_cs_key_event_msg {
	uint8_t			rke_down;
	uint16_t		rke_pad;
	uint32_t		rke_sym;
} __packed rfb_cs_key_event_msg_t;

typedef struct rfb_cs_pointer_event_msg {
	uint8_t			rpe_button;
	uint16_t		rpe_x;
	uint16_t		rpe_y;
} __packed rfb_cs_pointer_event_msg_t;

typedef struct rfb_cs_cut_text_msg {
	uint8_t			rct_padding[3];
	uint32_t		rct_length;
} __packed rfb_cs_cut_text_msg_t;

typedef struct rfb_cs_qemu_msg {
	uint8_t			rq_subtype;
} __packed rfb_cs_qemu_msg_t;

typedef struct rfb_cs_qemu_extended_key_msg {
	uint16_t		rqek_down;
	uint32_t		rqek_sym;
	uint32_t		rqek_code;
} __packed rfb_cs_qemu_extended_key_msg_t;

/* Client/server data structures */

typedef struct rfb_server {
	list_node_t		rs_node;
	int			rs_fd;
	const char		*rs_name;
	const char		*rs_password;

	struct mevent		*rs_connevent;

	uint_t			rs_clientcount;
	pthread_mutex_t		rs_clientlock;
	list_t			rs_clients;

	bool			rs_exclusive;

	rfb_pixfmt_t		rs_pixfmt;
} rfb_server_t;

typedef struct rfb_client {
	list_node_t		rc_node;
	uint_t			rc_instance;

	int			rc_fd;
	rfb_server_t		*rc_s;
	rfb_server_info_t	rc_sinfo;
	pthread_t		rc_rx_tid;
	pthread_t		rc_tx_tid;

	int			rc_width;
	int			rc_height;
	size_t			rc_cells;
	uint32_t		*rc_crc;
	uint32_t		*rc_crc_tmp;
	z_stream		rc_zstream;
	uint8_t			*rc_zbuf;

	struct bhyvegc_image	rc_gci;

	rfb_cver_t		rc_cver;
	rfb_encodings_t		rc_encodings;

	atomic_bool		rc_closing;
	atomic_bool		rc_pending;
	atomic_bool		rc_input_detected;
	atomic_bool		rc_crc_reset;
	atomic_bool		rc_send_fullscreen;

	bool			rc_custom_pixfmt;
	bool			rc_keyevent_sent;
} rfb_client_t;

#endif	/* _RFB_IMPL_H */
