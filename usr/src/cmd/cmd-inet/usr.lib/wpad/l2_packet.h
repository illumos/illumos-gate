/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 * Sun elects to license this software under the BSD license.
 * See README for more details.
 */
#ifndef __L2_PACKET_H
#define	__L2_PACKET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <net/if.h>
#include <libdlpi.h>

#define	IEEE80211_MTU_MAX	2304

struct l2_packet_data {
	dlpi_handle_t	dh;	/* dlpi handle for EAPOL frames */
	char		ifname[DLPI_LINKNAME_MAX];
	uint8_t		own_addr[IEEE80211_ADDR_LEN];
	void		(*rx_callback)(void *, unsigned char *,
	    unsigned char *, size_t);
	void		*rx_callback_ctx;
};

#pragma pack(1)
struct l2_ethhdr {
	uint8_t h_dest[IEEE80211_ADDR_LEN];
	uint8_t h_source[IEEE80211_ADDR_LEN];
	uint16_t h_proto;
};
#pragma pack()

struct l2_packet_data *l2_packet_init(
	const char *, unsigned short,
	void (*rx_callback)(void *, unsigned char *,
			    unsigned char *, size_t),
	void *);
void l2_packet_deinit(struct l2_packet_data *);

int l2_packet_get_own_addr(struct l2_packet_data *, uint8_t *);
int l2_packet_send(struct l2_packet_data *, uint8_t *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* __L2_PACKET_H */
