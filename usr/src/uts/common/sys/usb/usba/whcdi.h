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

#ifndef	_SYS_USB_WHCDI_H
#define	_SYS_USB_WHCDI_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/usba_types.h>
#include <sys/usb/usba/wusba.h>
#include <sys/usb/usba/wusba_io.h>
#include <sys/usb/usba/wa.h>	/* for wusb_secrt_data_t */


/*
 * This file contains data structures and functions that might be
 * shared by HWA and WHCI drivers.
 */

typedef struct wusb_hc_cc_list {
	wusb_cc_t		cc;
	struct wusb_hc_cc_list	*next;
} wusb_hc_cc_list_t;

struct wusb_hc_data;

typedef struct wusb_dev_info {
	struct wusb_hc_data	*wdev_hc; /* the HC this device attaches */
	uint8_t			wdev_cdid[16];
	uint16_t		wdev_addr;
	uint16_t		wdev_state;
	uint8_t			wdev_is_newconn;
	uint8_t			wdev_beacon_attr;
	usb_pipe_handle_t	wdev_ph;	/* used before authenticated */
	wusb_secrt_data_t	wdev_secrt_data;
	usb_uwb_cap_descr_t	*wdev_uwb_descr;
	wusb_cc_t		*wdev_cc;
	uint8_t			wdev_ptk[16];
	uint8_t			wdev_tkid[3];
	timeout_id_t		wdev_trust_timer; /* TrustTimeout timer */
	uint8_t			wdev_active;
} wusb_dev_info_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_dev_info::wdev_addr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_dev_info::wdev_uwb_descr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_dev_info::wdev_hc))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_dev_info::wdev_secrt_data))

/*
 * According to WUSB 1.0 spec, WUSB hosts can support up to 127 devices.
 * To comply with USB bus convention that bus address 1 is assigned
 * to the host controller device, the addresses assigned to WUSB devices
 * would start from 2. So the max device number is reduced to 126.
 */
#define	WUSB_MAX_PORTS		126

#define	WUSB_CHILD_ZAP		0x1

typedef struct wusb_hc_data {
	dev_info_t		*hc_dip;
	void			*hc_private_data;
	uint8_t			hc_chid[16];
	uint8_t			hc_cluster_id;
	uint8_t			hc_num_mmcies;
	kmutex_t		hc_mutex;
	wusb_ie_header_t	**hc_mmcie_list;

	boolean_t		hc_newcon_enabled;

	/* save the often used IEs so as not to allocate them each time */
	wusb_ie_keepalive_t		hc_alive_ie;

	/* children info structures */
	uint8_t			hc_num_ports;
	wusb_dev_info_t		**hc_dev_infos;
	dev_info_t		**hc_children_dips;
	size_t			hc_cd_list_length;
	usba_device_t		**hc_usba_devices;

	/* for bus unconfig */
	uint8_t			hc_children_state[WUSB_MAX_PORTS + 1];

	/* child connection functions */
	void	(*disconnect_dev)(dev_info_t *, usb_port_t);
	void	(*reconnect_dev)(dev_info_t *, usb_port_t);
	int	(*create_child)(dev_info_t *, usb_port_t);
	int	(*destroy_child)(dev_info_t *, usb_port_t);

	/*
	 * some necessary host functions:
	 * Both HWA and HCI must implement these entries to support basic
	 * host controller operations.
	 */
	int	(*set_encrypt)(dev_info_t *, usb_port_t, uint8_t);
	int	(*set_ptk)(dev_info_t *, usb_key_descr_t *, size_t, usb_port_t);
	int	(*set_gtk)(dev_info_t *, usb_key_descr_t *, size_t);
	int	(*set_device_info)(dev_info_t *, wusb_dev_info_t *, usb_port_t);
	int	(*set_cluster_id) (dev_info_t *, uint8_t id);
	int	(*set_stream_idx) (dev_info_t *, uint8_t idx);
	int	(*set_wusb_mas)	(dev_info_t *, uint8_t *data);
	int	(*add_mmc_ie)	(dev_info_t *, uint8_t interval, uint8_t rcnt,
				uint8_t iehdl, uint16_t len, uint8_t *data);
	int	(*rem_mmc_ie)	(dev_info_t *, uint8_t iehdl);
	int	(*stop_ch)	(dev_info_t *, uint32_t time);
	int	(*set_num_dnts)	(dev_info_t *, uint8_t interval, uint8_t nslot);
	int	(*get_time)	(dev_info_t *, uint8_t timetype,
				uint16_t timelen, uint32_t *time);

	/* host addr in MAC layer */
	uint16_t		hc_addr;

	/* beaconing channel */
	uint8_t			hc_channel;

	/* reserved MASes. bitmaps */
	uint8_t			hc_mas[WUSB_SET_WUSB_MAS_LEN];

	/* connection context list for the host */
	wusb_hc_cc_list_t	*hc_cc_list;

	/* group temporal key */
	usb_key_descr_t		hc_gtk;
	uint8_t			hc_gtk_padding[15];
} wusb_hc_data_t;

_NOTE(MUTEX_PROTECTS_DATA(wusb_hc_data_t::hc_mutex, wusb_dev_info_t))
_NOTE(MUTEX_PROTECTS_DATA(wusb_hc_data_t::hc_mutex, wusb_hc_data_t))

_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::hc_num_ports))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::hc_num_mmcies))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::hc_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::hc_gtk))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::add_mmc_ie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::rem_mmc_ie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::set_cluster_id))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::set_encrypt))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::set_gtk))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::set_ptk))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::set_num_dnts))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::set_stream_idx))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::set_wusb_mas))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::stop_ch))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::create_child))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::destroy_child))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::disconnect_dev))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::reconnect_dev))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_hc_data_t::get_time))

_NOTE(SCHEME_PROTECTS_DATA("local use only",
				wusb_ie_host_disconnect::bLength))
_NOTE(SCHEME_PROTECTS_DATA("local use only",
				wusb_ie_host_disconnect::bIEIdentifier))
_NOTE(SCHEME_PROTECTS_DATA("local use only",
				wusb_ccm_nonce::sfn))
/*
 * WUSB 1.0 4.3.8.5 says the range of cluster id is in 0x80-0xfe,
 * we limit the maximum WUSB host controller numbers to 31 now,
 * and take the upper portion of this range as the broadcast
 * cluster id
 */
#define	WUSB_CLUSTER_ID_COUNT		31
#define	WUSB_MIN_CLUSTER_ID		0xe0

#define	WUSB_TRUST_TIMEOUT	4 /* WUSB 4.15.1 TrustTimeout = 4s */
#define	WUSB_TRUST_TIMEOUT_US	WUSB_TRUST_TIMEOUT * MICROSEC

#define	WUSB_PERIODIC_ENDPOINT(endpoint) (((endpoint->bmAttributes & \
	USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR) ||\
	((endpoint->bmAttributes &\
	USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH))

#define	WUSB_ISOC_ENDPOINT(endpoint) (((endpoint->bmAttributes &\
	USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH))

#define	WUSB_INTR_ENDPOINT(endpoint) (((endpoint->bmAttributes &\
	USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR))

/* helper functions */
uint8_t	wusb_hc_get_cluster_id();
void	wusb_hc_free_cluster_id(uint8_t id);
int	wusb_hc_get_iehdl(wusb_hc_data_t *hc_data, wusb_ie_header_t *hdr,
	uint8_t *iehdl);
void	wusb_hc_free_iehdl(wusb_hc_data_t *hc_data, uint8_t iehdl);

uint_t	wusb_hc_is_dev_connected(wusb_hc_data_t *hc_data, uint8_t *cdid,
	usb_port_t *port);
uint_t	wusb_hc_is_addr_valid(wusb_hc_data_t *hc_data, uint8_t addr,
	usb_port_t *port);
usb_port_t	wusb_hc_get_free_port(wusb_hc_data_t *hc_data);

/* device notification support */
int	wusb_hc_ack_conn(wusb_hc_data_t *hc_data, usb_port_t port);
int	wusb_hc_ack_disconn(wusb_hc_data_t *hc_data, uint8_t addr);
void	wusb_hc_rm_ack(wusb_hc_data_t *hc_data);
int	wusb_hc_send_keepalive_ie(wusb_hc_data_t *hc_data, uint8_t addr);
int	wusb_hc_auth_dev(wusb_hc_data_t *hc_data, usb_port_t port,
	usb_pipe_handle_t ph, uint8_t ifc, wusb_secrt_data_t *secrt_data);
int	wusb_hc_handle_port_connect(wusb_hc_data_t *hc_data, usb_port_t port,
	usb_pipe_handle_t ph, uint8_t ifc, wusb_secrt_data_t *secrt_data);
void	wusb_hc_handle_dn_connect(wusb_hc_data_t *hc_data,
	usb_pipe_handle_t ph, uint8_t ifc, uint8_t *data, size_t len,
	wusb_secrt_data_t *secrt_data);
void	wusb_hc_handle_dn_disconnect(wusb_hc_data_t *hc_data, uint8_t addr,
	uint8_t *data, size_t len);

/* wusb common device function */
int	wusb_create_child_devi(dev_info_t *dip, char *node_name,
	usba_hcdi_ops_t *usba_hcdi_ops, dev_info_t *usb_root_hub_dip,
	usb_port_status_t port_status, usba_device_t *usba_device,
	dev_info_t **child_dip);
int	wusb_get_dev_security_descr(usb_pipe_handle_t ph,
	wusb_secrt_data_t *secrt_data);
int	wusb_get_bos_cloud(dev_info_t *child_dip, usba_device_t *child_ud);
int	wusb_get_rc_dev_by_hc(dev_info_t *dip, dev_t *dev);

int16_t	wusb_get_ccm_encryption_value(wusb_secrt_data_t *secrt_data);

/* device dynamical configuration functions */
void	wusb_hc_disconnect_dev(wusb_hc_data_t *hc_data, usb_port_t port);
void	wusb_hc_reconnect_dev(wusb_hc_data_t *hc_data, usb_port_t port);
int	wusb_hc_create_child(wusb_hc_data_t *hc_data, usb_port_t port);
int	wusb_hc_destroy_child(wusb_hc_data_t *hc_data, usb_port_t port);

/* WUSB HC common requests */
int	wusb_hc_set_cluster_id(wusb_hc_data_t *hc_data, uint8_t cluster_id);

int	wusb_hc_set_stream_idx(wusb_hc_data_t *hc_data, uint8_t stream_idx);

int	wusb_hc_set_wusb_mas(wusb_hc_data_t *hc_data, uint8_t *data);

int	wusb_hc_add_mmc_ie(wusb_hc_data_t *hc_data, uint8_t interval,
	uint8_t rcnt, uint8_t iehdl, uint16_t len, uint8_t *data);

int	wusb_hc_remove_mmc_ie(wusb_hc_data_t *hc_data, uint8_t iehdl);
void	wusb_hc_rem_ie(wusb_hc_data_t *hc_data, wusb_ie_header_t *ieh);

int	wusb_hc_stop_ch(wusb_hc_data_t *hc_data, uint32_t timeoff);

int	wusb_hc_set_num_dnts(wusb_hc_data_t *hc_data, uint8_t interval,
	uint8_t nslots);

int	wusb_hc_get_time(wusb_hc_data_t *hc_data, uint8_t time_type,
	uint16_t len, uint32_t *time);

int	wusb_hc_add_host_info(wusb_hc_data_t *hc_data, uint8_t stream_idx);

void	wusb_hc_rem_host_info(wusb_hc_data_t *hc_data);

int	wusb_hc_send_host_disconnect(wusb_hc_data_t *hc_data);

int	wusb_hc_set_device_info(wusb_hc_data_t *hc_data, usb_port_t port);

/* WUSB HC connection context list operations */
void	wusb_hc_add_cc(wusb_hc_cc_list_t **cc_list, wusb_hc_cc_list_t *new_cc);
void	wusb_hc_rem_cc(wusb_hc_cc_list_t **cc_list, wusb_cc_t *old_cc);
void	wusb_hc_free_cc_list(wusb_hc_cc_list_t *cc_list);
wusb_cc_t *wusb_hc_cc_matched(wusb_hc_cc_list_t *cc_list, uint8_t *cdid);

/* security functions */
int	wusb_dev_set_encrypt(usb_pipe_handle_t ph, uint8_t value);
int	wusb_enable_dev_encrypt(wusb_hc_data_t *hc, wusb_dev_info_t *dev_info);
int	wusb_dev_set_key(usb_pipe_handle_t ph, uint8_t key_index,
	usb_key_descr_t *key, size_t klen);
int	wusb_hc_set_encrypt(wusb_hc_data_t *hc_data, usb_port_t port,
	uint8_t type);
int	wusb_hc_set_ptk(wusb_hc_data_t *hc_data, uint8_t *key_data,
	usb_port_t port);
int	wusb_hc_set_gtk(wusb_hc_data_t *hc_data, uint8_t *key_data,
	uint8_t *tkid);

/* crypto functions */
int	PRF(const uchar_t *key, size_t klen, wusb_ccm_nonce_t *nonce,
	const uchar_t *adata, size_t alen,
	const uchar_t *bdata, size_t blen,
	uchar_t *out, size_t bitlen);

#define	PRF_64(key, klen, nonce, adata, alen, bdata, blen, out)	\
	PRF(key, klen, nonce, adata, alen, bdata, blen, out, 64)

#define	PRF_128(key, klen, nonce, adata, alen, bdata, blen, out)	\
	PRF(key, klen, nonce, adata, alen, bdata, blen, out, 128)

#define	PRF_256(key, klen, nonce, adata, alen, bdata, blen, out)	\
	PRF(key, klen, nonce, adata, alen, bdata, blen, out, 256)

int	wusb_gen_random_nonce(wusb_hc_data_t *hc_data,
	wusb_dev_info_t *dev_info, uchar_t *rbuf);

int	wusb_4way_handshake(wusb_hc_data_t *hc_data, usb_port_t port,
	usb_pipe_handle_t ph, uint8_t ifc);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_WHCDI_H */
