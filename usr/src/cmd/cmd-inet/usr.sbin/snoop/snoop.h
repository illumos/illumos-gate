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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SNOOP_H
#define	_SNOOP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS	*/

#include <rpc/types.h>
#include <sys/pfmod.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/pppoe.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Flags to control packet info display
 */
#define	F_NOW		0x00000001	/* display in realtime */
#define	F_SUM		0x00000002	/* display summary line */
#define	F_ALLSUM	0x00000004	/* display all summary lines */
#define	F_DTAIL		0x00000008	/* display detail lines */
#define	F_TIME		0x00000010	/* display time */
#define	F_ATIME		0x00000020	/* display absolute time */
#define	F_RTIME		0x00000040	/* display relative time */
#define	F_DROPS		0x00000080	/* display drops */
#define	F_LEN		0x00000100	/* display pkt length */
#define	F_NUM		0x00000200	/* display pkt number */
#define	F_WHO		0x00000400	/* display src/dst */

#define	MAXLINE		(1088)		/* max len of detail line */

#define	MAX_HDRTRAILER	(64)		/* max hdr/trailer packet slack */

/*
 * The RPC XID cache structure.
 * When analyzing RPC protocols we
 * have to cache the xid of the RPC
 * request together with the program
 * number, proc, version etc since this
 * information is missing in the reply
 * packet.  Using the xid in the reply
 * we can lookup this previously stashed
 * information in the cache.
 *
 * For RPCSEC_GSS flavor, some special processing is
 * needed for the argument interpretation based on its
 * control procedure and service type.  This information
 * is stored in the cache table during interpretation of
 * the rpc header and will be referenced later when the rpc
 * argument is interpreted.
 */
#define	XID_CACHE_SIZE 256
struct cache_struct {
	int xid_num;	/* RPC transaction id */
	int xid_frame;	/* Packet number */
	int xid_prog;	/* RPC program number */
	int xid_vers;	/* RPC version number */
	int xid_proc;	/* RPC procedure number */
	unsigned int xid_gss_proc; /* control procedure */
	int xid_gss_service; /* none, integ, priv */
} xid_cache[XID_CACHE_SIZE];


/*
 * The following macros advance the pointer passed to them.  They
 * assume they are given a char *.
 */
#define	GETINT8(v, ptr) { \
	(v) = (*(ptr)++); \
}

#define	GETINT16(v, ptr) { \
	(v) = *(ptr)++ << 8; \
	(v) |= *(ptr)++; \
}

#define	GETINT32(v, ptr) { \
	(v) = *(ptr)++ << 8; \
	(v) |= *(ptr)++; (v) <<= 8; \
	(v) |= *(ptr)++; (v) <<= 8; \
	(v) |= *(ptr)++; \
}

/*
 * Used to print nested protocol layers.  For example, an ip datagram included
 * in an icmp error, or a PPP packet included in an LCP protocol reject..
 */
extern char *prot_nest_prefix;

extern char *get_sum_line(void);
extern char *get_detail_line(int, int);
extern struct timeval prev_time;
extern char *getflag(int, int, char *, char *);
extern void show_header(char *, char *, int);
extern void xdr_init(char *, int);
extern char *get_line(int, int);
extern int get_line_remain(void);
extern char getxdr_char(void);
extern char showxdr_char(char *);
extern uchar_t getxdr_u_char(void);
extern uchar_t showxdr_u_char(char *);
extern short getxdr_short(void);
extern short showxdr_short(char *);
extern ushort_t getxdr_u_short(void);
extern ushort_t showxdr_u_short(char *);
extern long getxdr_long(void);
extern long showxdr_long(char *);
extern ulong_t getxdr_u_long(void);
extern ulong_t showxdr_u_long(char *);
extern longlong_t getxdr_longlong(void);
extern longlong_t showxdr_longlong(char *);
extern u_longlong_t getxdr_u_longlong(void);
extern u_longlong_t showxdr_u_longlong(char *);
extern char *getxdr_opaque(char *, int);
extern char *getxdr_string(char *, int);
extern char *showxdr_string(int, char *);
extern char *getxdr_bytes(uint_t *);
extern void xdr_skip(int);
extern int getxdr_pos(void);
extern void setxdr_pos(int);
extern char *getxdr_context(char *, int);
extern char *showxdr_context(char *);
extern enum_t getxdr_enum(void);
extern void show_space(void);
extern void show_trailer(void);
extern char *getxdr_date(void);
extern char *showxdr_date(char *);
extern char *getxdr_date_ns(void);
char *format_time(int64_t sec, uint32_t nsec);
extern char *showxdr_date_ns(char *);
extern char *getxdr_hex(int);
extern char *showxdr_hex(int, char *);
extern bool_t getxdr_bool(void);
extern bool_t showxdr_bool(char *);
extern char *concat_args(char **, int);
extern int pf_compile(char *, int);
extern void compile(char *, int);
extern void load_names(char *);
extern void cap_open_read(char *);
extern void cap_open_write(char *);
extern void cap_read(int, int, int, void (*)(), int);
extern void cap_close(void);
extern int check_device(char **, int *);
extern void initdevice(char *, ulong_t, ulong_t, struct timeval *,
    struct Pf_ext_packetfilt *, int);
extern void net_read(int, int, void (*)(), int);
extern void click(int);
extern void show_pktinfo(int, int, char *, char *, struct timeval *,
		struct timeval *, int, int);
extern void show_line(char *);
extern char *getxdr_time(void);
extern char *showxdr_time(char *);
extern char *addrtoname(int, void *);
extern char *show_string(const char *, int, int);
extern void pr_err(char *, ...);
extern void check_retransmit(char *, ulong_t);
extern char *nameof_prog(int);
extern char *getproto(int);
extern uint8_t print_ipv6_extensions(int, uint8_t **, uint8_t *, int *, int *);
extern void protoprint(int, int, ulong_t, int, int, int, char *, int);
extern char *getportname(int, in_port_t);

extern void interpret_arp(int, struct arphdr *, int);
extern void interpret_bparam(int, int, int, int, int, char *, int);
extern void interpret_dns(int, int, const uchar_t *, int);
extern void interpret_mount(int, int, int, int, int, char *, int);
extern void interpret_nfs(int, int, int, int, int, char *, int);
extern void interpret_nfs3(int, int, int, int, int, char *, int);
extern void interpret_nfs4(int, int, int, int, int, char *, int);
extern void interpret_nfs4_cb(int, int, int, int, int, char *, int);
extern void interpret_nfs_acl(int, int, int, int, int, char *, int);
extern void interpret_nis(int, int, int, int, int, char *, int);
extern void interpret_nisbind(int, int, int, int, int, char *, int);
extern void interpret_nisp_cb(int, int, int, int, int, char *, int);
extern void interpret_nisplus(int, int, int, int, int, char *, int);
extern void interpret_nlm(int, int, int, int, int, char *, int);
extern void interpret_pmap(int, int, int, int, int, char *, int);
extern int interpret_reserved(int, int, in_port_t, in_port_t, char *, int);
extern void interpret_rquota(int, int, int, int, int, char *, int);
extern void interpret_rstat(int, int, int, int, int, char *, int);
extern void interpret_solarnet_fw(int, int, int, int, int, char *, int);
extern void interpret_ldap(int, char *, int, int, int);
extern void interpret_icmp(int, struct icmp *, int, int);
extern void interpret_icmpv6(int, icmp6_t *, int, int);
extern int interpret_ip(int, struct ip *, int);
extern int interpret_ipv6(int, ip6_t *, int);
extern int interpret_ppp(int, uchar_t *, int);
extern int interpret_pppoe(int, poep_t *, int);
extern void init_ldap(void);
extern boolean_t arp_for_ether(char *, struct ether_addr *);
extern char *ether_ouiname(uint32_t);
char *tohex(char *p, int len);
extern char *printether(struct ether_addr *);
extern char *print_ethertype(int);

/*
 * Describes characteristics of the Media Access Layer.
 * The mac_type is one of the supported DLPI media
 * types (see <sys/dlpi.h>).
 * The mtu_size is the size of the largest frame.
 * The header length is returned by a function to
 * allow for variable header size - for ethernet it's
 * just a constant 14 octets.
 * The interpreter is the function that "knows" how
 * to interpret the frame.
 */
typedef struct interface {
	uint_t	mac_type;
	uint_t	mtu_size;
	uint_t	(*header_len)(char *);
	uint_t 	(*interpreter)(int, char *, int, int);
	uint_t	mac_hdr_fixed_size;
} interface_t;

#define	IF_HDR_FIXED	0
#define	IF_HDR_VAR	1

extern interface_t INTERFACES[], *interface;
extern char *device;

extern char *dlc_header;

/*
 * Global error recovery routine: used to reset snoop variables after
 * catastrophic failure.
 */
void snoop_recover(void);

/*
 * Global alarm handler structure for managing multiple alarms within
 * snoop.
 */
static struct snoop_handler;
typedef struct snoop_handler {
	struct snoop_handler *s_next;		/* next alarm handler */
	time_t s_time;				/* time to fire */
	void (*s_handler)();			/* alarm handler */
} snoop_handler_t;

#define	SNOOP_MAXRECOVER	20	/* maxium number of recoveries */
#define	SNOOP_ALARM_GRAN	3	/* alarm() timeout multiplier */

/*
 * Global alarm handler management routine.
 */
extern int snoop_alarm(int s_sec, void (*s_handler)());

#ifdef __cplusplus
}
#endif

#endif	/* _SNOOP_H */
