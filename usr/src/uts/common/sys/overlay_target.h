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
 * Copyright (c) 2015 Joyent, Inc.
 */

#ifndef _OVERLAY_TARGET_H
#define	_OVERLAY_TARGET_H

/*
 * Overlay device varpd ioctl interface (/dev/overlay)
 */

#include <sys/types.h>
#include <sys/ethernet.h>
#include <netinet/in.h>
#include <sys/overlay_common.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct overlay_target_point {
	uint8_t		otp_mac[ETHERADDRL];
	struct in6_addr	otp_ip;
	uint16_t	otp_port;
} overlay_target_point_t;

#define	OVERLAY_TARG_IOCTL	(('o' << 24) | ('v' << 16) | ('t' << 8))

#define	OVERLAY_TARG_INFO	(OVERLAY_TARG_IOCTL | 0x01)

typedef enum overlay_targ_info_flags {
	OVERLAY_TARG_INFO_F_ACTIVE = 0x01,
	OVERLAY_TARG_INFO_F_DEGRADED = 0x02
} overlay_targ_info_flags_t;

/*
 * Get target information about an overlay device
 */
typedef struct overlay_targ_info {
	datalink_id_t		oti_linkid;
	uint32_t		oti_needs;
	uint64_t		oti_flags;
	uint64_t		oti_vnetid;
} overlay_targ_info_t;

/*
 * Declare an association between a given varpd instance and a datalink.
 */
#define	OVERLAY_TARG_ASSOCIATE	(OVERLAY_TARG_IOCTL | 0x02)

typedef struct overlay_targ_associate {
	datalink_id_t		ota_linkid;
	uint32_t		ota_mode;
	uint64_t		ota_id;
	uint32_t		ota_provides;
	overlay_target_point_t	ota_point;
} overlay_targ_associate_t;

/*
 * Remove an association from a device. If the device has already been started,
 * this implies OVERLAY_TARG_DEGRADE.
 */
#define	OVERLAY_TARG_DISASSOCIATE	(OVERLAY_TARG_IOCTL | 0x3)

/*
 * Tells the kernel that while a varpd instance still exists, it basically isn't
 * making any forward progress, so the device should consider itself degraded.
 */
#define	OVERLAY_TARG_DEGRADE	(OVERLAY_TARG_IOCTL | 0x4)

typedef struct overlay_targ_degrade {
	datalink_id_t	otd_linkid;
	uint32_t	otd_pad;
	char		otd_buf[OVERLAY_STATUS_BUFLEN];
} overlay_targ_degrade_t;

/*
 * Tells the kernel to remove the degraded status that it set on a device.
 */
#define	OVERLAY_TARG_RESTORE	(OVERLAY_TARG_IOCTL | 0x5)

typedef struct overlay_targ_id {
	datalink_id_t	otid_linkid;
} overlay_targ_id_t;

/*
 * The following ioctls are all used to support dynamic lookups from userland,
 * generally serviced by varpd.
 *
 * The way this is designed to work is that user land will have threads sitting
 * in OVERLAY_TARG_LOOKUP ioctls waiting to service requests. A thread will sit
 * waiting for work for up to approximately one second of time before they will
 * be sent back out to user land to give user land a chance to clean itself up
 * or more generally, come back into the kernel for work. Once these threads
 * return, they will have a request with which more action can be done. The
 * following ioctls can all be used to answer the request.
 *
 *	OVERLAY_TARG_RESPOND - overlay_targ_resp_t
 *
 *		The overlay_targ_resp_t has the appropriate information from
 *		which a reply can be generated. The information is filled into
 *		an overlay_targ_point_t as appropriate based on the
 *		overlay_plugin_dest_t type.
 *
 *
 *	OVERLAY_TARG_DROP - overlay_targ_resp_t
 *
 *		The overlay_targ_resp_t should identify a request for which to
 *		drop a packet.
 *
 *
 * 	OVERLAY_TARG_INJECT - overlay_targ_pkt_t
 *
 * 		The overlay_targ_pkt_t injects a fully formed packet into the
 * 		virtual network. It may either be identified by its data link id
 * 		or by the request id. If both are specified, the
 * 		datalink id will be used. Note, that an injection is not
 * 		considered a reply and if this corresponds to a requeset, then
 * 		that individual packet must still be dropped.
 *
 *
 * 	OVERLAY_TARG_PKT - overlay_targ_pkt_t
 *
 * 		This ioctl can be used to copy data from a given request into a
 * 		user buffer. This can be used in combination with
 * 		OVERLAY_TARG_INJECT to implemnt services such as a proxy-arp.
 *
 *
 * 	OVERLAY_TARG_RESEND - overlay_targ_pkt_t
 *
 * 		This ioctl is similar to the OVERLAY_TARG_INJECT, except instead
 * 		of receiving it on the local mac handle, it queues it for
 * 		retransmission again. This is useful if you have a packet that
 * 		was originally destined for some broadcast or multicast address
 * 		that you now want to send to a unicast address.
 */
#define	OVERLAY_TARG_LOOKUP	(OVERLAY_TARG_IOCTL | 0x10)
#define	OVERLAY_TARG_RESPOND	(OVERLAY_TARG_IOCTL | 0x11)
#define	OVERLAY_TARG_DROP	(OVERLAY_TARG_IOCTL | 0x12)
#define	OVERLAY_TARG_INJECT	(OVERLAY_TARG_IOCTL | 0x13)
#define	OVERLAY_TARG_PKT	(OVERLAY_TARG_IOCTL | 0x14)
#define	OVERLAY_TARG_RESEND	(OVERLAY_TARG_IOCTL | 0x15)

typedef struct overlay_targ_lookup {
	uint64_t	otl_dlid;
	uint64_t	otl_reqid;
	uint64_t	otl_varpdid;
	uint64_t	otl_vnetid;
	uint64_t	otl_hdrsize;
	uint64_t	otl_pktsize;
	uint8_t		otl_srcaddr[ETHERADDRL];
	uint8_t		otl_dstaddr[ETHERADDRL];
	uint32_t	otl_dsttype;
	uint32_t	otl_sap;
	int32_t		otl_vlan;
} overlay_targ_lookup_t;

typedef struct overlay_targ_resp {
	uint64_t	otr_reqid;
	overlay_target_point_t otr_answer;
} overlay_targ_resp_t;

typedef struct overlay_targ_pkt {
	uint64_t	otp_linkid;
	uint64_t	otp_reqid;
	uint64_t	otp_size;
	void		*otp_buf;
} overlay_targ_pkt_t;

#ifdef _KERNEL

typedef struct overlay_targ_pkt32 {
	uint64_t	otp_linkid;
	uint64_t	otp_reqid;
	uint64_t	otp_size;
	caddr32_t	otp_buf;
} overlay_targ_pkt32_t;

#endif /* _KERNEL */

/*
 * This provides a way to get a list of active overlay devices independently
 * from dlmgmtd. At the end of the day the kernel always knows what will exist
 * and this allows varpd which is an implementation of libdladm not to end up
 * needing to call back into dlmgmtd via libdladm and create an unfortunate
 * dependency cycle.
 */

#define	OVERLAY_TARG_LIST	(OVERLAY_TARG_IOCTL | 0x20)

typedef struct overlay_targ_list {
	uint32_t	otl_nents;
	uint32_t	otl_ents[];
} overlay_targ_list_t;

/*
 * The following family of ioctls all manipulate the target cache of a given
 * device.
 *
 * 	OVERLAY_TARG_CACHE_GET - overlay_targ_cache_t
 *
 * 		The overlay_targ_cache_t should be have its link identifier and
 * 		the desired mac address filled in. On return, it will fill in
 * 		the otc_dest member, if the entry exists in the table.
 *
 *
 * 	OVERLAY_TARG_CACHE_SET - overlay_targ_cache_t
 *
 * 		The cache table entry of the mac address referred to by otc_mac
 * 		and otd_linkid will be filled in with the details provided by in
 * 		the otc_dest member.
 *
 * 	OVERLAY_TARG_CACHE_REMOVE - overlay_targ_cache_t
 *
 * 		Removes the cache entry identified by otc_mac from the table.
 * 		Note that this does not stop any in-flight lookups or deal with
 * 		any data that is awaiting a lookup.
 *
 *
 * 	OVERLAY_TARG_CACHE_FLUSH - overlay_targ_cache_t
 *
 * 		Similar to OVERLAY_TARG_CACHE_REMOVE, but functions on the
 * 		entire table identified by otc_linkid. All other parameters are
 * 		ignored.
 *
 *
 * 	OVERLAY_TARG_CACHE_ITER - overlay_targ_cache_iter_t
 *
 * 		Iterates over the contents of a target cache identified by
 * 		otci_linkid. Iteration is guaranteed to be exactly once for
 * 		items which are in the hashtable at the beginning and end of
 * 		iteration. For items which are added or removed after iteration
 * 		has begun, only at most once semantics are guaranteed. Consumers
 * 		should ensure that otci_marker is zeroed before starting
 * 		iteration and should preserve its contents across calls.
 *
 * 		Before calling in, otci_count should be set to the number of
 * 		entries that space has been allocated for in otci_ents. The
 * 		value will be updated to indicate the total number written out.
 */

#define	OVERLAY_TARG_CACHE_GET		(OVERLAY_TARG_IOCTL | 0x30)
#define	OVERLAY_TARG_CACHE_SET		(OVERLAY_TARG_IOCTL | 0x31)
#define	OVERLAY_TARG_CACHE_REMOVE	(OVERLAY_TARG_IOCTL | 0x32)
#define	OVERLAY_TARG_CACHE_FLUSH	(OVERLAY_TARG_IOCTL | 0x33)
#define	OVERLAY_TARG_CACHE_ITER		(OVERLAY_TARG_IOCTL | 0x34)

/*
 * This is a pretty arbitrary number that we're constraining ourselves to
 * for iteration. Basically the goal is to make sure that we can't have a user
 * ask us to allocate too much memory on their behalf at any time. A more
 * dynamic form may be necessary some day.
 */
#define	OVERLAY_TARGET_ITER_MAX	500

#define	OVERLAY_TARGET_CACHE_DROP	0x01

typedef struct overlay_targ_cache_entry {
	uint8_t			otce_mac[ETHERADDRL];
	uint16_t		otce_flags;
	overlay_target_point_t	otce_dest;
} overlay_targ_cache_entry_t;

typedef struct overlay_targ_cache {
	datalink_id_t			otc_linkid;
	overlay_targ_cache_entry_t	otc_entry;
} overlay_targ_cache_t;

typedef struct overlay_targ_cache_iter {
	datalink_id_t			otci_linkid;
	uint32_t			otci_pad;
	uint64_t			otci_marker;
	uint16_t			otci_count;
	uint8_t				otci_pad2[3];
	overlay_targ_cache_entry_t	otci_ents[];
} overlay_targ_cache_iter_t;

#ifdef __cplusplus
}
#endif

#endif /* _OVERLAY_TARGET_H */
