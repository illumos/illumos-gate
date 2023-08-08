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
 *
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2021 Joyent, Inc.
 * Copyright 2023 RackTop Systems, Inc.
 */

#ifndef	_SNOOP_H
#define	_SNOOP_H

#include <rpc/types.h>
#include <sys/pfmod.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/bufmod.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/pppoe.h>
#include <libdlpi.h>
#include <note.h>

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

/*
 * Transient port structure. See TFTP interpreter.
 */
struct ttable {
	int t_port;
	int blksize;
	int (*t_proc)(int, void *, int);
};

extern int add_transient(int port, int (*proc)(int, void *, int));
extern struct ttable *is_transient(int port);
extern void del_transient(int port);

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
extern struct cache_struct {
	int xid_num;	/* RPC transaction id */
	int xid_frame;	/* Packet number */
	int xid_prog;	/* RPC program number */
	int xid_vers;	/* RPC version number */
	int xid_proc;	/* RPC procedure number */
	unsigned int xid_gss_proc; /* control procedure */
	int xid_gss_service; /* none, integ, priv */
} xid_cache[XID_CACHE_SIZE];

extern char *tkp, *sav_tkp;
extern char *token;
extern enum tokentype {
	EOL,
	ALPHA,
	NUMBER,
	FIELD,
	ADDR_IP,
	ADDR_ETHER,
	SPECIAL,
	ADDR_IP6,
	ADDR_AT
} tokentype;
extern uint_t tokenval;

enum direction { ANY, TO, FROM };
extern enum direction dir;

extern int eaddr;	/* need ethernet addr */
extern int opstack;	/* operand stack depth */

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
extern int want_packet(uchar_t *, int, int);
extern void set_vlan_id(int);
extern struct timeval prev_time;
extern void process_pkt(struct sb_hdr *, char *, int, int);
extern char *getflag(int, int, char *, char *);
extern void show_header(char *, char *, int);
extern void show_count(void);
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
extern void cap_write(struct sb_hdr *, char *, int, int);
extern void cap_open_read(const char *);
extern void cap_open_write(const char *);
extern void cap_open_wr_multi(const char *, size_t, off_t);
extern void cap_read(int, int, int, void (*)(), int);
extern void cap_close(void);
extern boolean_t open_datalink(dlpi_handle_t *, const char *, const char *);
extern void init_datalink(dlpi_handle_t, ulong_t, ulong_t, struct timeval *,
    struct Pf_ext_packetfilt *);
extern void net_read(dlpi_handle_t, size_t, int, void (*)(), int);
extern void click(int);
extern void show_pktinfo(int, int, char *, char *, struct timeval *,
		struct timeval *, int, int);
extern void show_line(char *);
/*PRINTFLIKE1*/
extern void show_printf(char *fmt, ...)
    __PRINTFLIKE(1);
extern char *getxdr_time(void);
extern char *showxdr_time(char *);
extern char *addrtoname(int, const void *);
extern char *show_string(const char *, int, int);
extern void pr_err(const char *, ...);
extern void pr_errdlpi(dlpi_handle_t, const char *, int);
extern void check_retransmit(char *, ulong_t);
extern char *nameof_prog(int);
extern char *getproto(int);
extern uint8_t print_ipv6_extensions(int, uint8_t **, uint8_t *, int *, int *);
extern void protoprint(int, int, ulong_t, int, int, int, char *, int);
extern char *getportname(int, in_port_t);

extern void interpret_arp(int, struct arphdr *, int);
extern void interpret_bparam(int, int, int, int, int, char *, int);
extern void interpret_dns(int, int, const uchar_t *, int, int);
extern void interpret_mount(int, int, int, int, int, char *, int);
extern void interpret_nfs(int, int, int, int, int, char *, int);
extern void interpret_nfs3(int, int, int, int, int, char *, int);
extern void interpret_nfs4(int, int, int, int, int, char *, int);
extern void interpret_nfs4_cb(int, int, int, int, int, char *, int);
extern void interpret_nfs_acl(int, int, int, int, int, char *, int);
extern void interpret_nis(int, int, int, int, int, char *, int);
extern void interpret_nisbind(int, int, int, int, int, char *, int);
extern void interpret_nlm(int, int, int, int, int, char *, int);
extern void interpret_pmap(int, int, int, int, int, char *, int);
extern int interpret_reserved(int, int, in_port_t, in_port_t, char *, int);
extern void interpret_rquota(int, int, int, int, int, char *, int);
extern void interpret_rstat(int, int, int, int, int, char *, int);
extern void interpret_solarnet_fw(int, int, int, int, int, char *, int);
extern void interpret_ldap(int, char *, int, int, int);
extern void interpret_icmp(int, struct icmp *, int, int);
extern void interpret_icmpv6(int, icmp6_t *, int, int);
extern int interpret_ip(int, const struct ip *, int);
extern int interpret_ipv6(int, const ip6_t *, int);
extern int interpret_ppp(int, uchar_t *, int);
extern int interpret_pppoe(int, poep_t *, int);
struct tcphdr;
extern int interpret_tcp(int, struct tcphdr *, int, int);
struct udphdr;
extern int interpret_udp(int, struct udphdr *, int, int);
extern int interpret_esp(int, uint8_t *, int, int);
extern int interpret_ah(int, uint8_t *, int, int);
struct sctp_hdr;
extern void interpret_sctp(int, struct sctp_hdr *, int, int);
extern void interpret_mip_cntrlmsg(int, uchar_t *, int);
struct dhcp;
extern int interpret_dhcp(int, struct dhcp *, int);
extern int interpret_dhcpv6(int, const uint8_t *, int);
struct tftphdr;
extern int interpret_tftp(int, void *, int);
extern int interpret_http(int, char *, int);
struct ntpdata;
extern int interpret_ntp(int, struct ntpdata *, int);
extern void interpret_netbios_ns(int, uchar_t *, int);
extern void interpret_netbios_datagram(int, uchar_t *, int);
extern void interpret_netbios_ses(int, uchar_t *, int);
extern int interpret_slp(int, void *, int);
struct rip;
extern int interpret_rip(int, struct rip *, int);
struct rip6;
extern int interpret_rip6(int, struct rip6 *, int);
extern int interpret_socks_call(int, char *, int);
extern int interpret_socks_reply(int, char *, int);
extern int interpret_trill(int, struct ether_header **, char *, int *);
extern int interpret_isis(int, char *, int, boolean_t);
extern int interpret_bpdu(int, char *, int);
extern int interpret_vxlan(int, char *, int);
extern int interpret_svp(int, char *, int);
extern void init_ldap(void);
extern boolean_t arp_for_ether(char *, struct ether_addr *);
extern char *ether_ouiname(uint32_t);
extern char *tohex(char *p, int len);
extern char *printether(struct ether_addr *);
extern char *print_ethertype(int);
extern const char *arp_htype(int);
extern int valid_rpc(char *, int);

/*
 * Describes characteristics of the Media Access Layer.
 * The mac_type is one of the supported DLPI media
 * types (see <sys/dlpi.h>).
 * The mtu_size is the size of the largest frame.
 * network_type_offset is where the network type
 * is located in the link layer header.
 * The header length is returned by a function to
 * allow for variable header size - for ethernet it's
 * just a constant 14 octets.
 * The interpreter is the function that "knows" how
 * to interpret the frame.
 * try_kernel_filter tells snoop to first try a kernel
 * filter (because the header size is fixed, or if it could
 * be of variable size where the variable size is easy for a kernel
 * filter to handle, for example, Ethernet and VLAN tags)
 * and only use a user space filter if the filter expression
 * cannot be expressed in kernel space.
 */
typedef uint_t (interpreter_fn_t)(int, char *, int, int);
typedef uint_t (headerlen_fn_t)(char *, size_t);
typedef struct interface {
	uint_t		mac_type;
	uint_t		mtu_size;
	uint_t		network_type_offset;
	size_t		network_type_len;
	uint_t		network_type_ip;
	uint_t		network_type_ipv6;
	headerlen_fn_t	*header_len;
	interpreter_fn_t *interpreter;
	boolean_t	try_kernel_filter;
} interface_t;

extern interface_t INTERFACES[], *interface;
extern char *dlc_header;
extern char *src_name, *dst_name;
extern char *prot_prefix;
extern char *prot_nest_prefix;
extern char *prot_title;

/* Keep track of how many nested IP headers we have. */
extern unsigned int encap_levels, total_encap_levels;

extern int quitting;
extern boolean_t Iflg, Pflg, fflg, rflg;

/*
 * Global error recovery routine: used to reset snoop variables after
 * catastrophic failure.
 */
void snoop_recover(void);

/*
 * Global alarm handler structure for managing multiple alarms within
 * snoop.
 */
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

/*
 * The next two definitions do not take into account the length
 * of the underlying link header.  In order to use them, you must
 * add link_header_len to them.  The reason it is not done here is
 * that later these macros are used to initialize a table.
 */
#define	IPV4_TYPE_HEADER_OFFSET 9
#define	IPV6_TYPE_HEADER_OFFSET 6

#ifdef __cplusplus
}
#endif

#endif	/* _SNOOP_H */
