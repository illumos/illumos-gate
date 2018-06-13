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
 * Copyright 2019 Joyent, Inc.  All rights reserved.
 */

/*
 * Decode SVP (SmartDC VxLAN Protocol) packets
 */

#include <inttypes.h>
#include <sys/crc32.h>
#include <uuid/uuid.h>
#include <stdio.h>
#include <stdarg.h>
#include <libvarpd_svp_prot.h>
#include "snoop.h"

/*
 * String size large enough for an IPv6 address + / + a 3 digit (or less)
 * prefix length
 */
#define	ADDRSTR_LEN (INET6_ADDRSTRLEN + 4)

/*
 * Large enough for all currently known status strings as well as a
 * 16-bit hex value.
 */
#define	STATUSSTR_LEN	32

/*
 * Large enough for all currently known op strings, as well as a
 * 16-bit hex value.
 */
#define	OPSTR_LEN	32

/*
 * Large enough for VL3 types and bulk types, as well as a 32-bit
 * hex value.
 */
#define	TYPESTR_LEN	32

static uint32_t svp_crc32_tab[] = { CRC32_TABLE };

#define STR(_x, _buf, _len)				\
	case _x:					\
		(void) strlcpy(_buf, #_x, _len);	\
		break

static void
svp_op_str(uint16_t op, char *buf, size_t buflen)
{
	switch (op) {
	STR(SVP_R_UNKNOWN, buf, buflen);
	STR(SVP_R_PING, buf, buflen);
	STR(SVP_R_PONG, buf, buflen);
	STR(SVP_R_VL2_REQ, buf, buflen);
	STR(SVP_R_VL2_ACK, buf, buflen);
	STR(SVP_R_VL3_REQ, buf, buflen);
	STR(SVP_R_VL3_ACK, buf, buflen);
	STR(SVP_R_BULK_REQ, buf, buflen);
	STR(SVP_R_BULK_ACK, buf, buflen);
	STR(SVP_R_LOG_REQ, buf, buflen);
	STR(SVP_R_LOG_ACK, buf, buflen);
	STR(SVP_R_LOG_RM, buf, buflen);
	STR(SVP_R_LOG_RM_ACK, buf, buflen);
	STR(SVP_R_SHOOTDOWN, buf, buflen);
	default:
		(void) snprintf(buf, buflen, "0x%hx", op);
	}
}

static void
svp_status_str(uint16_t status, char *buf, size_t buflen)
{
	switch (status) {
	STR(SVP_S_OK, buf, buflen);
	STR(SVP_S_FATAL, buf, buflen);
	STR(SVP_S_NOTFOUND, buf, buflen);
	STR(SVP_S_BADL3TYPE, buf, buflen);
	STR(SVP_S_BADBULK, buf, buflen);
	default:
		(void) snprintf(buf, buflen, "0x%hx", status);
	}
}

static void
svp_vl3_type_str(uint32_t type, char *buf, size_t buflen)
{
	switch (type) {
	STR(SVP_VL3_IP, buf, buflen);
	STR(SVP_VL3_IPV6, buf, buflen);
	default:
		(void) snprintf(buf, buflen, "0x%x", type);
	}
}

static void
svp_bulk_type_str(uint32_t type, char *buf, size_t buflen)
{
	switch (type) {
	STR(SVP_BULK_VL2, buf, buflen);
	STR(SVP_BULK_VL3, buf, buflen);
	default:
		(void) snprintf(buf, buflen, "0x%x", type);
	}
}

static void
svp_log_type_str(uint32_t type, char *buf, size_t buflen)
{
	switch (type) {
	STR(SVP_LOG_VL2, buf, buflen);
	STR(SVP_LOG_VL3, buf, buflen);
	default:
		(void) snprintf(buf, buflen, "0x%x", type);
	}
}
#undef STR

static void
svp_addr_str(void *addrp, uint8_t *prefixp, char *buf, size_t buflen)
{
	struct in_addr v4;
	int af = AF_INET6;

	if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)addrp)) {
		af = AF_INET;
		IN6_V4MAPPED_TO_INADDR((struct in6_addr *)addrp, &v4);
		addrp = &v4;
	}

	if (inet_ntop(af, addrp, buf, buflen) == NULL) {
		uint8_t *p = addrp;
		size_t i;

		(void) strlcpy(buf, "0x", buflen);
		for (i = 0; i < 16; i++) {
			(void) snprintf(buf + 2 + i * 2,
			    sizeof (buf) - 2 - i * 2, "%02hhx", p[i]);
		}
	}

	if (prefixp != NULL && *prefixp != 128) {
		char buf2[5]; /* / + 3 digits + NUL */

		if (af == AF_INET)
			*prefixp -= 96;

		(void) snprintf(buf2, sizeof (buf2), "/%hhu", *prefixp);
		(void) strlcat(buf, buf2, buflen);
	}
}

static boolean_t
svp_check_crc(char *data, int len)
{
	svp_req_t *req = (svp_req_t *)data;
	uint32_t save_crc = req->svp_crc32;
	uint32_t crc = -1U;

	req->svp_crc32 = 0;
	CRC32(crc, (uint8_t *)data, len, -1U, svp_crc32_tab);
	crc = ~crc;
	req->svp_crc32 = save_crc;

	return (ntohl(save_crc) == crc ? B_TRUE : B_FALSE);
}

static void
do_svp_vl2_req(void *data, int len)
{
	svp_vl2_req_t *vl2 = data;

	show_printf("MAC = %s", ether_ntoa((struct ether_addr *)vl2->sl2r_mac));
	show_printf("Virtual network id = %u", ntohl(vl2->sl2r_vnetid));
}

static void
do_svp_vl2_ack(void *data, int len)
{
	svp_vl2_ack_t *vl2a = data;
	char status[STATUSSTR_LEN];
	char addr[ADDRSTR_LEN];

	svp_status_str(ntohs(vl2a->sl2a_status), status, sizeof (status));
	svp_addr_str(vl2a->sl2a_addr, NULL, addr, sizeof (addr));

	show_printf("Status = %s", status);
	show_printf("UL3 Address = %s", addr);
	show_printf("UL3 Port = %hu", ntohs(vl2a->sl2a_port));
}

static void
do_svp_vl3_req(void *data, int len)
{
	svp_vl3_req_t *req = data;
	char type[TYPESTR_LEN];
	char addr[ADDRSTR_LEN];

	svp_vl3_type_str(ntohl(req->sl3r_type), type, sizeof (type));
	svp_addr_str(req->sl3r_ip, NULL, addr, sizeof (addr));

	show_printf("Virtual network id = %u", ntohl(req->sl3r_vnetid));
	show_printf("Type = %s", type);
	show_printf("VL3 Address = %s", addr);
}

static void
do_svp_vl3_ack(void *data, int len)
{
	svp_vl3_ack_t *vl3a = data;
	char status[STATUSSTR_LEN];
	char addr[ADDRSTR_LEN];

	svp_status_str(ntohl(vl3a->sl3a_status), status, sizeof (status));
	svp_addr_str(vl3a->sl3a_uip, NULL, addr, sizeof (addr));

	show_printf("Status = %s", status);
	show_printf("MAC = %s",
	    ether_ntoa((struct ether_addr *)vl3a->sl3a_mac));
	show_printf("UL3 Address = %s", addr);
	show_printf("UL3 Port = %hu", ntohs(vl3a->sl3a_uport));
}

static void
do_svp_bulk_req(void *data, int len)
{
	svp_bulk_req_t *req = data;
	char type[TYPESTR_LEN];

	if (len < sizeof (svp_bulk_req_t)) {
		show_printf("SVP_R_BULK_REQ runt");
		return;
	}

	svp_bulk_type_str(ntohl(req->svbr_type), type, sizeof (type));
	show_printf("Type = %s", type);
}

static void
do_svp_bulk_ack(void *data, int len)
{
	svp_bulk_ack_t *ack = data;
	char status[STATUSSTR_LEN];
	char type[TYPESTR_LEN];

	svp_status_str(ntohl(ack->svba_status), status, sizeof (status));
	svp_bulk_type_str(ntohl(ack->svba_type), type, sizeof (type));

	show_printf("Status = %s", status);
	show_printf("Type = %s", type);

	/*
	 * Currently the data format is undefined (see libvarp_svp_prot.h),
	 * so there is nothing else we can display.
	 */
}

static void
do_svp_log_req(void *data, int len)
{
	svp_log_req_t *svlr = data;
	char addr[ADDRSTR_LEN];

	svp_addr_str(svlr->svlr_ip, NULL, addr, sizeof (addr));

	show_printf("Count = %u", ntohl(svlr->svlr_count));
	show_printf("Address = %s", addr);
}

static void
do_svp_log_ack(void *data, int len)
{
	svp_log_ack_t *ack = data;
	union {
		svp_log_vl2_t *vl2;
		svp_log_vl3_t *vl3;
		uint32_t	*vtype;
		void		*vd;
	} u;
	size_t total = 0, rlen = 0;
	uint8_t prefixlen;
	boolean_t is_host;
	char status[STATUSSTR_LEN];
	char typestr[TYPESTR_LEN];
	char uuid[UUID_PRINTABLE_STRING_LENGTH];
	char addr[ADDRSTR_LEN];

	u.vd = (ack + 1);

	svp_status_str(ntohl(ack->svla_status), status, sizeof (status));

	show_printf("Status = %s", status);
	len -= sizeof (*ack);

	while (len > 0) {
		uint32_t type;

		if (len < sizeof (uint32_t)) {
			show_printf("    Trailing runt");
			break;
		}

		type = ntohl(*u.vtype);
		svp_log_type_str(type, typestr, sizeof (typestr));

		switch (type) {
		case SVP_LOG_VL2:
			rlen = sizeof (svp_log_vl2_t);
			break;
		case SVP_LOG_VL3:
			rlen = sizeof (svp_log_vl3_t);
			break;
		default:
			/*
			 * If we don't know the type of log record we have,
			 * we cannot determine the size of the record, so we
			 * cannot continue past this.
			 */
			show_printf("Log %-4zu: Log type = %s", ++total,
			    typestr);
			return;
		}

		if (len < rlen) {
			show_printf("Log %-4zu %s runt", ++total, typestr);
			return;
		}

		/* These are the same in SVP_LOG_VL2 and SVP_LOG_VL3 records */
		show_printf("Log %-4zu Log type = %s", ++total, typestr);

		uuid_parse(uuid, u.vl2->svl2_id);
		show_printf("%8s UUID = %s", "", uuid);

		switch (type) {
		case SVP_LOG_VL2:
			show_printf("%8s MAC = %s", "",
			    ether_ntoa((struct ether_addr *)u.vl2->svl2_mac));
			show_printf("%8s Vnet = %u", "",
			    ntohl(u.vl2->svl2_vnetid));
			u.vl2++;
			break;
		case SVP_LOG_VL3:
			svp_addr_str(u.vl3->svl3_ip, NULL, addr, sizeof (addr));

			show_printf("%8s VLAN = %hu", "",
			    ntohs(u.vl3->svl3_vlan));
			show_printf("%8s Address = %s", "", addr);
			show_printf("%8s Vnet = %u", "",
			    ntohl(u.vl3->svl3_vnetid));
			u.vl3++;
			break;
		}

		len -= rlen;
		show_space();
	}
	show_printf("Total log records = %zu", total);
}

static void
do_svp_lrm_req(void *data, int len)
{
	/*
	 * Sized large enough to hold the expected size message
	 * (formatted below) if there's a length mismatch.
	 */
	char mismatch_str[64] = { 0 };
	svp_lrm_req_t *req = data;
	size_t expected_sz = sizeof (*req);
	size_t i, n;

	n = ntohl(req->svrr_count);

	/* IDs are 16-byte UUIDs */
	expected_sz += n * UUID_LEN;
	if (len != expected_sz) {
		(void) snprintf(mismatch_str, sizeof (mismatch_str),
		    " (expected %zu bytes, actual size is %d bytes)",
		    expected_sz, len);
	}
	show_printf("ID Count = %u%s", n, mismatch_str);
	if (len != expected_sz)
		return;

	for (i = 0; i < n; i++) {
		char uuid[UUID_PRINTABLE_STRING_LENGTH];

		uuid_parse(uuid, &req->svrr_ids[UUID_LEN * i]);
		show_printf("%-4s %s", (i == 0) ? "IDs:" : "", uuid);
	}
}

static void
do_svp_lrm_ack(void *data, int len)
{
	svp_lrm_ack_t *ack = data;
	char status[STATUSSTR_LEN];

	svp_status_str(ntohl(ack->svra_status), status, sizeof (status));
	show_printf("Status = %s", status);
}

static void
do_svp_shootdown(void *data, int len)
{
	svp_shootdown_t *sd = data;

	show_printf("Vnet = %u", ntohl(sd->svsd_vnetid));
	show_printf("MAC Address = %s",
	    ether_ntoa((struct ether_addr *)sd->svsd_mac));
}

static struct svp_len_tbl {
	uint16_t slt_op;
	size_t	slt_len;
} svp_len_tbl[] = {
	{ SVP_R_UNKNOWN,	0 },
	{ SVP_R_PING,		0 },
	{ SVP_R_PONG,		0 },
	{ SVP_R_VL2_REQ,	sizeof (svp_vl2_req_t) },
	{ SVP_R_VL2_ACK,	sizeof (svp_vl2_ack_t) },
	{ SVP_R_VL3_REQ,	sizeof (svp_vl3_req_t) },
	{ SVP_R_VL3_ACK,	sizeof (svp_vl3_ack_t) },
	{ SVP_R_BULK_REQ,	sizeof (svp_bulk_req_t) },
	{ SVP_R_BULK_ACK,	sizeof (svp_bulk_ack_t) },
	{ SVP_R_LOG_REQ,	sizeof (svp_log_req_t) },
	{ SVP_R_LOG_ACK,	0 },
	{ SVP_R_LOG_RM,		sizeof (svp_lrm_req_t) },
	{ SVP_R_LOG_RM_ACK,	sizeof (svp_lrm_ack_t) },
	{ SVP_R_SHOOTDOWN,	sizeof (svp_shootdown_t) },
};

static boolean_t
svp_check_runt(uint16_t op, int len)
{
	if (op > SVP_R_SHOOTDOWN)
		return (B_FALSE);

	if (len < svp_len_tbl[op].slt_len) {
		char opstr[OPSTR_LEN];

		svp_op_str(op, opstr, sizeof (opstr));
		show_printf("%s Runt", opstr);
		show_space();
		return (B_TRUE);
	}
	return (B_FALSE);
}

int
interpret_svp(int flags, char *data, int fraglen)
{
	svp_req_t *req = (svp_req_t *)data;
	char opstr[OPSTR_LEN];
	uint16_t op;
	boolean_t crc_ok;

	if (fraglen < sizeof (svp_req_t)) {
		if (flags & F_SUM)
			(void) snprintf(get_sum_line(), MAXLINE,
			    "SVP RUNT");
		if (flags & F_DTAIL)
			show_header("SVP RUNT:  ", "Short packet", fraglen);

		return (fraglen);
	}

	op = ntohs(req->svp_op);
	svp_op_str(op, opstr, sizeof (opstr));

	crc_ok = svp_check_crc(data, fraglen);

	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "SVP V=%hu OP=%s ID=%u%s", ntohs(req->svp_ver), opstr,
		    ntohl(req->svp_id), crc_ok ? "" : " (BAD CRC)");
	}

	if (flags & F_DTAIL) {
		show_header("SVP:    ", "SVP Header", sizeof (svp_req_t));
		show_space();
		show_printf("Version = %hu", ntohs(req->svp_ver));
		show_printf("Op = %s", opstr);
		show_printf("Packet length = %u bytes%s", ntohl(req->svp_size),
		    (ntohl(req->svp_size) == fraglen - sizeof (*req)) ?
		    "" : " (mismatch)");
		show_printf("Id = %u", ntohl(req->svp_id));
		show_printf("CRC = %x%s", ntohl(req->svp_crc32),
		    crc_ok ? "" : " (bad)");
		show_space();

		req++;
		fraglen -= sizeof (*req);

		/*
		 * Since we cannot know the length of an unknown op,
		 * svp_check_runt() returns B_TRUE for both truncated packets
		 * and unknown packets -- we have nothing meaningful besides
		 * the header we could print anyway.
		 */
		if (svp_check_runt(op, fraglen))
			return (fraglen);

		switch (op) {
		case SVP_R_VL2_REQ:
			do_svp_vl2_req(req, fraglen);
			break;
		case SVP_R_VL2_ACK:
			do_svp_vl2_ack(req, fraglen);
			break;
		case SVP_R_VL3_REQ:
			do_svp_vl3_req(req, fraglen);
			break;
		case SVP_R_VL3_ACK:
			do_svp_vl3_ack(req, fraglen);
			break;
		case SVP_R_BULK_REQ:
			do_svp_bulk_req(req, fraglen);
			break;
		case SVP_R_BULK_ACK:
			do_svp_bulk_ack(req, fraglen);
			break;
		case SVP_R_LOG_REQ:
			do_svp_log_req(req, fraglen);
			break;
		case SVP_R_LOG_ACK:
			do_svp_log_ack(req, fraglen);
			break;
		case SVP_R_LOG_RM:
			do_svp_lrm_req(req, fraglen);
			break;
		case SVP_R_LOG_RM_ACK:
			do_svp_lrm_ack(req, fraglen);
			break;
		case SVP_R_SHOOTDOWN:
			do_svp_shootdown(req, fraglen);
			break;
		}

		show_space();
	}

	return (0);
}
