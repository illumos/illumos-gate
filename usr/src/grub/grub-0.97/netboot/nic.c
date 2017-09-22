/**************************************************************************
Etherboot -  Network Bootstrap Program

Literature dealing with the network protocols:
	ARP - RFC826
	RARP - RFC903
        IP - RFC791
	UDP - RFC768
	BOOTP - RFC951, RFC2132 (vendor extensions)
	DHCP - RFC2131, RFC2132 (options)
	TFTP - RFC1350, RFC2347 (options), RFC2348 (blocksize), RFC2349 (tsize)
	RPC - RFC1831, RFC1832 (XDR), RFC1833 (rpcbind/portmapper)
	NFS - RFC1094, RFC1813 (v3, useful for clarifications, not implemented)
	IGMP - RFC1112, RFC2113, RFC2365, RFC2236, RFC3171

**************************************************************************/
#include "etherboot.h"
#include "grub.h"
#include "nic.h"
#include "elf.h" /* FOR EM_CURRENT */
#include "bootp.h"
#include "if_arp.h"
#include "tftp.h"
#include "timer.h"
#include "ip.h"
#include "udp.h"

/* Currently no other module uses rom, but it is available */
struct rom_info		rom;
struct arptable_t	arptable[MAX_ARP];
#ifdef MULTICAST_LEVEL2
unsigned long last_igmpv1 = 0;
struct igmptable_t	igmptable[MAX_IGMP];
#endif
static unsigned long	netmask;
/* Used by nfs.c */
char *hostname = "";
int hostnamelen = 0;
/* Used by fsys_tftp.c */
int use_bios_pxe = 0;
static uint32_t xid;
static unsigned char *end_of_rfc1533 = NULL;
static const unsigned char broadcast[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static const in_addr zeroIP = { 0L };
static char rfc1533_venddata[MAX_RFC1533_VENDLEN];
static unsigned char rfc1533_cookie[4] = { RFC1533_COOKIE };
static unsigned char rfc1533_cookie_bootp[5] = { RFC1533_COOKIE, RFC1533_END };
static unsigned char rfc1533_cookie_dhcp[] = { RFC1533_COOKIE };
static int dhcp_reply;
static in_addr dhcp_server = { 0L };
static in_addr dhcp_addr = { 0L };

static const unsigned char dhcpdiscover[] = {
	RFC2132_MSG_TYPE, 1, DHCPDISCOVER,
	RFC2132_MAX_SIZE, 2,	/* request as much as we can */
	ETH_MAX_MTU / 256, ETH_MAX_MTU % 256,
	/* Vendor class identifier */
#ifdef SOLARIS_NETBOOT
	RFC2132_VENDOR_CLASS_ID,32,'P','X','E','C','l','i','e','n','t',':',
	'A','r','c','h',':','0','0','0','0','0',':','U','N','D','I',':',
	'0','0','2','0','0','1',
#else
	RFC2132_VENDOR_CLASS_ID, 10, 'G', 'R', 'U', 'B', 'C', 'l', 'i', 'e', 'n', 't',
#endif
	RFC2132_PARAM_LIST, 4, RFC1533_NETMASK, RFC1533_GATEWAY,
	RFC1533_HOSTNAME, RFC1533_EXTENSIONPATH, RFC1533_END
};
static const unsigned char dhcprequest [] = {
	RFC2132_MSG_TYPE,1,DHCPREQUEST,
	RFC2132_SRV_ID,4,0,0,0,0,
	RFC2132_REQ_ADDR,4,0,0,0,0,
	RFC2132_MAX_SIZE,2,	/* request as much as we can */
	ETH_MAX_MTU / 256, ETH_MAX_MTU % 256,
	/* Vendor class identifier */
#ifdef SOLARIS_NETBOOT
	RFC2132_VENDOR_CLASS_ID,32,'P','X','E','C','l','i','e','n','t',':',
	'A','r','c','h',':','0','0','0','0','0',':','U','N','D','I',':',
	'0','0','2','0','0','1',
#else
	RFC2132_VENDOR_CLASS_ID, 10, 'G', 'R', 'U', 'B', 'C', 'l', 'i', 'e', 'n', 't',
#endif
	RFC2132_PARAM_LIST,
	/* 4 standard + 2 vendortags */
	4 + 2,
	/* Standard parameters */
	RFC1533_NETMASK, RFC1533_GATEWAY,
	RFC1533_HOSTNAME, RFC1533_EXTENSIONPATH,
	/* Etherboot vendortags */
	RFC1533_VENDOR_MAGIC,
	RFC1533_VENDOR_CONFIGFILE,
	RFC1533_END
};

/* See nic.h */
int user_abort = 0;
int network_ready = 0;

#ifdef	REQUIRE_VCI_ETHERBOOT
int	vci_etherboot;
#endif

char *bootfile = NULL;
configfile_origin_t configfile_origin = CFG_HARDCODED;
char *vendor_configfile = NULL;
char vendor_configfile_len;

static void update_network_configuration(void);

static int dummy(void *unused __unused)
{
	return (0);
}

/* Careful.  We need an aligned buffer to avoid problems on machines
 * that care about alignment.  To trivally align the ethernet data
 * (the ip hdr and arp requests) we offset the packet by 2 bytes.
 * leaving the ethernet data 16 byte aligned.  Beyond this
 * we use memmove but this makes the common cast simple and fast.
 */
static char	packet[ETH_FRAME_LEN + ETH_DATA_ALIGN] __aligned(16);

struct nic	nic =
{
	{
		0,				/* dev.disable */
		{
			0,
			0,
			PCI_BUS_TYPE,
		},				/* dev.devid */
		0,				/* index */
		0,				/* type */
		PROBE_FIRST,			/* how_pobe */
		PROBE_NONE,			/* to_probe */
		0,				/* failsafe */
		0,				/* type_index */
		{},				/* state */
	},
	(int (*)(struct nic *, int))dummy,      /* poll */
	(void (*)(struct nic *, const char *,
		unsigned int, unsigned int,
		const char *))dummy,		/* transmit */
	(void (*)(struct nic *, irq_action_t))dummy, /* irq */
	0,					/* flags */
	&rom,					/* rom_info */
	arptable[ARP_CLIENT].node,		/* node_addr */
	packet + ETH_DATA_ALIGN,		/* packet */
	0,					/* packetlen */
	0,			/* ioaddr */
	0,			/* irqno */
	NULL,					/* priv_data */
};



int grub_eth_probe(void)
{
	static int probed = 0;
	struct dev *dev;

	EnterFunction("grub_eth_probe");

	if (probed)
		return 1;

	network_ready = 0;
	grub_memset((char *)arptable, 0, MAX_ARP * sizeof(struct arptable_t));
	dev = &nic.dev;
	dev->how_probe = -1;
	dev->type = NIC_DRIVER;
	dev->failsafe = 1;
	rom = *((struct rom_info *)ROM_INFO_LOCATION);

	probed = (eth_probe(dev) == PROBE_WORKED);

	LeaveFunction("grub_eth_probe");
	return probed;
}

int eth_probe(struct dev *dev)
{
	return probe(dev);
}

int eth_poll(int retrieve)
{
	return ((*nic.poll)(&nic, retrieve));
}

void eth_transmit(const char *d, unsigned int t, unsigned int s, const void *p)
{
	(*nic.transmit)(&nic, d, t, s, p);
	if (t == IP) twiddle();
}

void eth_disable(void)
{
#ifdef MULTICAST_LEVEL2
	int i;
	for(i = 0; i < MAX_IGMP; i++) {
		leave_group(i);
	}
#endif
	disable(&nic.dev);
}

void eth_irq (irq_action_t action)
{
	(*nic.irq)(&nic,action);
}

/**************************************************************************
IPCHKSUM - Checksum IP Header
**************************************************************************/
uint16_t ipchksum(const void *data, unsigned long length)
{
	unsigned long sum;
	unsigned long i;
	const uint8_t *ptr;

	/* In the most straight forward way possible,
	 * compute an ip style checksum.
	 */
	sum = 0;
	ptr = data;
	for(i = 0; i < length; i++) {
		unsigned long value;
		value = ptr[i];
		if (i & 1) {
			value <<= 8;
		}
		/* Add the new value */
		sum += value;
		/* Wrap around the carry */
		if (sum > 0xFFFF) {
			sum = (sum + (sum >> 16)) & 0xFFFF;
		}
	}
	return (~cpu_to_le16(sum)) & 0xFFFF;
}

uint16_t add_ipchksums(unsigned long offset, uint16_t sum, uint16_t new)
{
	unsigned long checksum;
	sum = ~sum & 0xFFFF;
	new = ~new & 0xFFFF;
	if (offset & 1) {
		/* byte swap the sum if it came from an odd offset 
		 * since the computation is endian independant this
		 * works.
		 */
		new = bswap_16(new);
	}
	checksum = sum + new;
	if (checksum > 0xFFFF) {
		checksum -= 0xFFFF;
	}
	return (~checksum) & 0xFFFF;
}

/**************************************************************************
DEFAULT_NETMASK - Return default netmask for IP address
**************************************************************************/
static inline unsigned long default_netmask(void)
{
	int net = ntohl(arptable[ARP_CLIENT].ipaddr.s_addr) >> 24;
	if (net <= 127)
		return(htonl(0xff000000));
	else if (net < 192)
		return(htonl(0xffff0000));
	else
		return(htonl(0xffffff00));
}

/**************************************************************************
IP_TRANSMIT - Send an IP datagram
**************************************************************************/
static int await_arp(int ival, void *ptr,
	unsigned short ptype, struct iphdr *ip __unused, struct udphdr *udp __unused)
{
	struct	arprequest *arpreply;
	if (ptype != ARP)
		return 0;
	if (nic.packetlen < ETH_HLEN + sizeof(struct arprequest))
		return 0;
	arpreply = (struct arprequest *)&nic.packet[ETH_HLEN];

	if (arpreply->opcode != htons(ARP_REPLY)) 
		return 0;
	if (memcmp(arpreply->sipaddr, ptr, sizeof(in_addr)) != 0)
		return 0;
	memcpy(arptable[ival].node, arpreply->shwaddr, ETH_ALEN);
	return 1;
}

int ip_transmit(int len, const void *buf)
{
	unsigned long destip;
	struct iphdr *ip;
	struct arprequest arpreq;
	int arpentry, i;
	int retry;

	ip = (struct iphdr *)buf;
	destip = ip->dest.s_addr;
	if (destip == IP_BROADCAST) {
		eth_transmit(broadcast, IP, len, buf);
#ifdef MULTICAST_LEVEL1 
	} else if ((destip & htonl(MULTICAST_MASK)) == htonl(MULTICAST_NETWORK)) {
		unsigned char multicast[6];
		unsigned long hdestip;
		hdestip = ntohl(destip);
		multicast[0] = 0x01;
		multicast[1] = 0x00;
		multicast[2] = 0x5e;
		multicast[3] = (hdestip >> 16) & 0x7;
		multicast[4] = (hdestip >> 8) & 0xff;
		multicast[5] = hdestip & 0xff;
		eth_transmit(multicast, IP, len, buf);
#endif
	} else {
		if (((destip & netmask) !=
		     (arptable[ARP_CLIENT].ipaddr.s_addr & netmask)) &&
		    arptable[ARP_GATEWAY].ipaddr.s_addr)
			destip = arptable[ARP_GATEWAY].ipaddr.s_addr;
		for(arpentry = 0; arpentry<MAX_ARP; arpentry++)
			if (arptable[arpentry].ipaddr.s_addr == destip) break;
		if (arpentry == MAX_ARP) {
			printf("%@ is not in my arp table!\n", destip);
			return(0);
		}
		for (i = 0; i < ETH_ALEN; i++)
			if (arptable[arpentry].node[i])
				break;
		if (i == ETH_ALEN) {	/* Need to do arp request */
			arpreq.hwtype = htons(1);
			arpreq.protocol = htons(IP);
			arpreq.hwlen = ETH_ALEN;
			arpreq.protolen = 4;
			arpreq.opcode = htons(ARP_REQUEST);
			memcpy(arpreq.shwaddr, arptable[ARP_CLIENT].node, ETH_ALEN);
			memcpy(arpreq.sipaddr, &arptable[ARP_CLIENT].ipaddr, sizeof(in_addr));
			memset(arpreq.thwaddr, 0, ETH_ALEN);
			memcpy(arpreq.tipaddr, &destip, sizeof(in_addr));
			for (retry = 1; retry <= MAX_ARP_RETRIES; retry++) {
				long timeout;
				eth_transmit(broadcast, ARP, sizeof(arpreq),
					&arpreq);
				timeout = rfc2131_sleep_interval(TIMEOUT, retry);
				if (await_reply(await_arp, arpentry,
					arpreq.tipaddr, timeout)) goto xmit;
			}
			return(0);
		}
xmit:
		eth_transmit(arptable[arpentry].node, IP, len, buf);
	}
	return 1;
}

void build_ip_hdr(unsigned long destip, int ttl, int protocol, int option_len,
	int len, const void *buf)
{
	struct iphdr *ip;
	ip = (struct iphdr *)buf;
	ip->verhdrlen = 0x45;
	ip->verhdrlen += (option_len/4);
	ip->service = 0;
	ip->len = htons(len);
	ip->ident = 0;
	ip->frags = 0; /* Should we set don't fragment? */
	ip->ttl = ttl;
	ip->protocol = protocol;
	ip->chksum = 0;
	ip->src.s_addr = arptable[ARP_CLIENT].ipaddr.s_addr;
	ip->dest.s_addr = destip;
	ip->chksum = ipchksum(buf, sizeof(struct iphdr) + option_len);
}

static uint16_t udpchksum(struct iphdr *ip, struct udphdr *udp)
{
	struct udp_pseudo_hdr pseudo;
	uint16_t checksum;

	/* Compute the pseudo header */
	pseudo.src.s_addr  = ip->src.s_addr;
	pseudo.dest.s_addr = ip->dest.s_addr;
	pseudo.unused      = 0;
	pseudo.protocol    = IP_UDP;
	pseudo.len         = udp->len;

	/* Sum the pseudo header */
	checksum = ipchksum(&pseudo, 12);

	/* Sum the rest of the udp packet */
	checksum = add_ipchksums(12, checksum, ipchksum(udp, ntohs(udp->len)));
	return checksum;
}


void build_udp_hdr(unsigned long destip, 
	unsigned int srcsock, unsigned int destsock, int ttl,
	int len, const void *buf)
{
	struct iphdr *ip;
	struct udphdr *udp;
	ip = (struct iphdr *)buf;
	build_ip_hdr(destip, ttl, IP_UDP, 0, len, buf);
	udp = (struct udphdr *)((char *)buf + sizeof(struct iphdr));
	udp->src = htons(srcsock);
	udp->dest = htons(destsock);
	udp->len = htons(len - sizeof(struct iphdr));
	udp->chksum = 0;
	if ((udp->chksum = udpchksum(ip, udp)) == 0)
		udp->chksum = 0xffff;
}


/**************************************************************************
UDP_TRANSMIT - Send an UDP datagram
**************************************************************************/
int udp_transmit(unsigned long destip, unsigned int srcsock,
	unsigned int destsock, int len, const void *buf)
{
	build_udp_hdr(destip, srcsock, destsock, 60, len, buf);
	return ip_transmit(len, buf);
}

/**************************************************************************
QDRAIN - clear the nic's receive queue
**************************************************************************/
static int await_qdrain(int ival __unused, void *ptr __unused,
	unsigned short ptype __unused, 
	struct iphdr *ip __unused, struct udphdr *udp __unused)
{
	return 0;
}

void rx_qdrain(void)
{
	/* Clear out the Rx queue first.  It contains nothing of interest,
	 * except possibly ARP requests from the DHCP/TFTP server.  We use
	 * polling throughout Etherboot, so some time may have passed since we
	 * last polled the receive queue, which may now be filled with
	 * broadcast packets.  This will cause the reply to the packets we are
	 * about to send to be lost immediately.  Not very clever.  */
	await_reply(await_qdrain, 0, NULL, 0);
}

/**
 * rarp
 *
 * Get IP address by rarp. Just copy from etherboot
 **/
static int await_rarp(int ival, void *ptr, unsigned short ptype, 
		      struct iphdr *ip, struct udphdr *udp)
{
	struct arprequest *arpreply;
	if (ptype != RARP)
		return 0;
	if (nic.packetlen < ETH_HLEN + sizeof(struct arprequest))
		return 0;
	arpreply = (struct arprequest *)&nic.packet[ETH_HLEN];
	if (arpreply->opcode != htons(RARP_REPLY))
		return 0;
	if (memcmp(arpreply->thwaddr, ptr, ETH_ALEN) == 0){
		memcpy(arptable[ARP_SERVER].node, arpreply->shwaddr, ETH_ALEN);
		memcpy(&arptable[ARP_SERVER].ipaddr, arpreply->sipaddr, sizeof(in_addr));
		memcpy(&arptable[ARP_CLIENT].ipaddr, arpreply->tipaddr, sizeof(in_addr));
		memset(&arptable[ARP_GATEWAY].ipaddr, 0, sizeof(in_addr));
		return 1;
	}
	return 0;
}

int rarp(void)
{
	int retry;

	/* arp and rarp requests share the same packet structure. */
	struct arprequest rarpreq;

	if(!grub_eth_probe())
		return 0;
	network_ready = 0;

	memset(&rarpreq, 0, sizeof(rarpreq));

	rarpreq.hwtype = htons(1);
	rarpreq.protocol = htons(IP);
	rarpreq.hwlen = ETH_ALEN;
	rarpreq.protolen = 4;
	rarpreq.opcode = htons(RARP_REQUEST);
	memcpy(&rarpreq.shwaddr, arptable[ARP_CLIENT].node, ETH_ALEN);
	/* sipaddr is already zeroed out */
	memcpy(&rarpreq.thwaddr, arptable[ARP_CLIENT].node, ETH_ALEN);
	/* tipaddr is already zeroed out */

	for (retry = 0; retry < MAX_ARP_RETRIES; ++retry) {
		long timeout;
		eth_transmit(broadcast, RARP, sizeof(rarpreq), &rarpreq);

		timeout = rfc2131_sleep_interval(TIMEOUT, retry);
		if (await_reply(await_rarp, 0, rarpreq.shwaddr, timeout))
			break;
		if (user_abort)
			return 0;
	}

	if (retry == MAX_ARP_RETRIES) {
		return (0);
	}

	network_ready = 1;
  	update_network_configuration();
	return (1);
}

/**
 * bootp
 *
 * Get IP address by bootp, segregate from bootp in etherboot.
 **/
static int await_bootp(int ival __unused, void *ptr __unused,
	unsigned short ptype __unused, struct iphdr *ip __unused, 
	struct udphdr *udp)
{
	struct	bootp_t *bootpreply;
	int len;		/* Length of vendor */

	if (!udp) {
		return 0;
	}
	bootpreply = (struct bootp_t *)
		&nic.packet[ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr)];
	len = nic.packetlen - (ETH_HLEN + sizeof(struct iphdr) + 
		sizeof(struct udphdr) + sizeof(struct bootp_t) - BOOTP_VENDOR_LEN);
	if (len < 0) {
		return 0;
	}
	if (udp->dest != htons(BOOTP_CLIENT))
		return 0;
	if (bootpreply->bp_op != BOOTP_REPLY)
		return 0;
	if (bootpreply->bp_xid != xid)
		return 0;
	if (memcmp((char *)&bootpreply->bp_siaddr, (char *)&zeroIP, sizeof(in_addr)) == 0)
		return 0;
	if ((memcmp(broadcast, bootpreply->bp_hwaddr, ETH_ALEN) != 0) &&
	    (memcmp(arptable[ARP_CLIENT].node, bootpreply->bp_hwaddr, ETH_ALEN) != 0)) {
		return 0;
	}

#ifdef SOLARIS_NETBOOT
	/* fill in netinfo */
	dhcpack_length = len + sizeof (struct bootp_t) - BOOTP_VENDOR_LEN;
	memcpy((char *)dhcpack_buf, (char *)bootpreply, dhcpack_length);
#endif

	arptable[ARP_CLIENT].ipaddr.s_addr = bootpreply->bp_yiaddr.s_addr;
	netmask = default_netmask();
	arptable[ARP_SERVER].ipaddr.s_addr = bootpreply->bp_siaddr.s_addr;
	memset(arptable[ARP_SERVER].node, 0, ETH_ALEN);  /* Kill arp */
	arptable[ARP_GATEWAY].ipaddr.s_addr = bootpreply->bp_giaddr.s_addr;
	memset(arptable[ARP_GATEWAY].node, 0, ETH_ALEN);  /* Kill arp */
	bootfile = bootpreply->bp_file;
	memcpy((char *)rfc1533_venddata, (char *)(bootpreply->bp_vend), len);
	decode_rfc1533(rfc1533_venddata, 0, len, 1);
	return(1);
}

int bootp(void)
{
	int retry;
	struct bootpip_t ip;
	unsigned long  starttime;
	
	EnterFunction("bootp");

	if(!grub_eth_probe())
		return 0;
	network_ready = 0;

	memset(&ip, 0, sizeof(struct bootpip_t));
	ip.bp.bp_op = BOOTP_REQUEST;
	ip.bp.bp_htype = 1;
	ip.bp.bp_hlen = ETH_ALEN;
	starttime = currticks();
	/* Use lower 32 bits of node address, more likely to be
	   distinct than the time since booting */
	memcpy(&xid, &arptable[ARP_CLIENT].node[2], sizeof(xid));
	ip.bp.bp_xid = xid += htonl(starttime);
	/* bp_secs defaults to zero */
	memcpy(ip.bp.bp_hwaddr, arptable[ARP_CLIENT].node, ETH_ALEN);
	memcpy(ip.bp.bp_vend, rfc1533_cookie_bootp, sizeof(rfc1533_cookie_bootp)); /* request RFC-style options */

	for (retry = 0; retry < MAX_BOOTP_RETRIES; ) {
		long timeout;

		rx_qdrain();

		udp_transmit(IP_BROADCAST, BOOTP_CLIENT, BOOTP_SERVER,
			sizeof(struct bootpip_t), &ip);
		timeout = rfc2131_sleep_interval(TIMEOUT, retry++);
		if (await_reply(await_bootp, 0, NULL, timeout)){
			network_ready = 1;
			return(1);
		}
		if (user_abort)
			return 0;
		ip.bp.bp_secs = htons((currticks()-starttime)/TICKS_PER_SEC);
	}
	return(0);
}

/**
 * dhcp
 *
 * Get IP address by dhcp, segregate from bootp in etherboot.
 **/
static int await_dhcp(int ival __unused, void *ptr __unused,
	unsigned short ptype __unused, struct iphdr *ip __unused, 
	struct udphdr *udp)
{
	struct	dhcp_t *dhcpreply;
	int len;

	if (!udp) {
		return 0;
	}
	dhcpreply = (struct dhcp_t *)
		&nic.packet[ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr)];
	len = nic.packetlen - (ETH_HLEN + sizeof(struct iphdr) + 
		sizeof(struct udphdr) + sizeof(struct dhcp_t) - DHCP_OPT_LEN);
	if (len < 0){
		return 0;
	}
	if (udp->dest != htons(BOOTP_CLIENT))
		return 0;
	if (dhcpreply->bp_op != BOOTP_REPLY)
		return 0;
	if (dhcpreply->bp_xid != xid)
		return 0;
	if (memcmp((char *)&dhcpreply->bp_siaddr, (char *)&zeroIP, sizeof(in_addr)) == 0)
		return 0;
	if ((memcmp(broadcast, dhcpreply->bp_hwaddr, ETH_ALEN) != 0) &&
	    (memcmp(arptable[ARP_CLIENT].node, dhcpreply->bp_hwaddr, ETH_ALEN) != 0)) {
		return 0;
	}

#ifdef SOLARIS_NETBOOT
	/* fill in netinfo */
	dhcpack_length = len + sizeof (struct dhcp_t) - DHCP_OPT_LEN;
	memcpy((char *)dhcpack_buf, (char *)dhcpreply, dhcpack_length);
#endif
	arptable[ARP_CLIENT].ipaddr.s_addr = dhcpreply->bp_yiaddr.s_addr;
	dhcp_addr.s_addr = dhcpreply->bp_yiaddr.s_addr;
	netmask = default_netmask();
	arptable[ARP_SERVER].ipaddr.s_addr = dhcpreply->bp_siaddr.s_addr;
	memset(arptable[ARP_SERVER].node, 0, ETH_ALEN);  /* Kill arp */
	arptable[ARP_GATEWAY].ipaddr.s_addr = dhcpreply->bp_giaddr.s_addr;
	memset(arptable[ARP_GATEWAY].node, 0, ETH_ALEN);  /* Kill arp */
	bootfile = dhcpreply->bp_file;
	memcpy((char *)rfc1533_venddata, (char *)(dhcpreply->bp_vend), len);
	decode_rfc1533(rfc1533_venddata, 0, len, 1);
	return(1);
}

int dhcp(void)
{
	int retry;
	int reqretry;
	struct dhcpip_t ip;
	unsigned long  starttime;

	/* try bios pxe stack first */
	if (dhcp_undi())
		return 1;

	if(!grub_eth_probe())
		return 0;

	network_ready = 0;

	memset(&ip, 0, sizeof(ip));
	ip.bp.bp_op = BOOTP_REQUEST;
	ip.bp.bp_htype = 1;
	ip.bp.bp_hlen = ETH_ALEN;
	starttime = currticks();
	/* Use lower 32 bits of node address, more likely to be
	   distinct than the time since booting */
	memcpy(&xid, &arptable[ARP_CLIENT].node[2], sizeof(xid));
	ip.bp.bp_xid = xid += htonl(starttime);
	memcpy(ip.bp.bp_hwaddr, arptable[ARP_CLIENT].node, ETH_ALEN);
	memcpy(ip.bp.bp_vend, rfc1533_cookie_dhcp, sizeof rfc1533_cookie_dhcp); /* request RFC-style options */
	memcpy(ip.bp.bp_vend + sizeof rfc1533_cookie_dhcp, dhcpdiscover, sizeof dhcpdiscover);

	for (retry = 0; retry < MAX_BOOTP_RETRIES; ) {
		long timeout;

		rx_qdrain();

		udp_transmit(IP_BROADCAST, BOOTP_CLIENT, BOOTP_SERVER,
			     sizeof(ip), &ip);
		timeout = rfc2131_sleep_interval(TIMEOUT, retry++);
		if (await_reply(await_dhcp, 0, NULL, timeout)) {
			/* If not a DHCPOFFER then must be just a
			   BOOTP reply, be backward compatible with
			   BOOTP then. Jscott report a bug here, but I
			   don't know how it happened */
			if (dhcp_reply != DHCPOFFER){
				network_ready = 1;
				return(1);
			}
			dhcp_reply = 0;
			memcpy(ip.bp.bp_vend, rfc1533_cookie_dhcp, sizeof rfc1533_cookie_dhcp);
			memcpy(ip.bp.bp_vend + sizeof rfc1533_cookie_dhcp, dhcprequest, sizeof dhcprequest);
			/* Beware: the magic numbers 9 and 15 depend on
			   the layout of dhcprequest */
			memcpy(&ip.bp.bp_vend[9], &dhcp_server, sizeof(in_addr));
			memcpy(&ip.bp.bp_vend[15], &dhcp_addr, sizeof(in_addr));
			for (reqretry = 0; reqretry < MAX_BOOTP_RETRIES; ) {
				udp_transmit(IP_BROADCAST, BOOTP_CLIENT, BOOTP_SERVER,
					     sizeof(ip), &ip);
				dhcp_reply=0;
				timeout = rfc2131_sleep_interval(TIMEOUT, reqretry++);
				if (await_reply(await_dhcp, 0, NULL, timeout))
					if (dhcp_reply == DHCPACK){
						network_ready = 1;
						return(1);
					}
				if (user_abort)
					return 0;
			}
		}
		if (user_abort)
			return 0;
		ip.bp.bp_secs = htons((currticks()-starttime)/TICKS_PER_SEC);
	}
	return(0);
}

#ifdef MULTICAST_LEVEL2
static void send_igmp_reports(unsigned long now)
{
	int i;
	for(i = 0; i < MAX_IGMP; i++) {
		if (igmptable[i].time && (now >= igmptable[i].time)) {
			struct igmp_ip_t igmp;
			igmp.router_alert[0] = 0x94;
			igmp.router_alert[1] = 0x04;
			igmp.router_alert[2] = 0;
			igmp.router_alert[3] = 0;
			build_ip_hdr(igmptable[i].group.s_addr, 
				1, IP_IGMP, sizeof(igmp.router_alert), sizeof(igmp), &igmp);
			igmp.igmp.type = IGMPv2_REPORT;
			if (last_igmpv1 && 
				(now < last_igmpv1 + IGMPv1_ROUTER_PRESENT_TIMEOUT)) {
				igmp.igmp.type = IGMPv1_REPORT;
			}
			igmp.igmp.response_time = 0;
			igmp.igmp.chksum = 0;
			igmp.igmp.group.s_addr = igmptable[i].group.s_addr;
			igmp.igmp.chksum = ipchksum(&igmp.igmp, sizeof(igmp.igmp));
			ip_transmit(sizeof(igmp), &igmp);
#ifdef	MDEBUG
			printf("Sent IGMP report to: %@\n", igmp.igmp.group.s_addr);
#endif
			/* Don't send another igmp report until asked */
			igmptable[i].time = 0;
		}
	}
}

static void process_igmp(struct iphdr *ip, unsigned long now)
{
	struct igmp *igmp;
	int i;
	unsigned iplen = 0;
	if (!ip || (ip->protocol == IP_IGMP) ||
		(nic.packetlen < sizeof(struct iphdr) + sizeof(struct igmp))) {
		return;
	}
	iplen = (ip->verhdrlen & 0xf)*4;
	igmp = (struct igmp *)&nic.packet[sizeof(struct iphdr)];
	if (ipchksum(igmp, ntohs(ip->len) - iplen) != 0)
		return;
	if ((igmp->type == IGMP_QUERY) && 
		(ip->dest.s_addr == htonl(GROUP_ALL_HOSTS))) {
		unsigned long interval = IGMP_INTERVAL;
		if (igmp->response_time == 0) {
			last_igmpv1 = now;
		} else {
			interval = (igmp->response_time * TICKS_PER_SEC)/10;
		}
		
#ifdef	MDEBUG
		printf("Received IGMP query for: %@\n", igmp->group.s_addr);
#endif			       
		for(i = 0; i < MAX_IGMP; i++) {
			uint32_t group = igmptable[i].group.s_addr;
			if ((group == 0) || (group == igmp->group.s_addr)) {
				unsigned long time;
				time = currticks() + rfc1112_sleep_interval(interval, 0);
				if (time < igmptable[i].time) {
					igmptable[i].time = time;
				}
			}
		}
	}
	if (((igmp->type == IGMPv1_REPORT) || (igmp->type == IGMPv2_REPORT)) &&
		(ip->dest.s_addr == igmp->group.s_addr)) {
#ifdef	MDEBUG
		printf("Received IGMP report for: %@\n", igmp->group.s_addr);
#endif			       
		for(i = 0; i < MAX_IGMP; i++) {
			if ((igmptable[i].group.s_addr == igmp->group.s_addr) &&
				igmptable[i].time != 0) {
				igmptable[i].time = 0;
			}
		}
	}
}

void leave_group(int slot)
{
	/* Be very stupid and always send a leave group message if 
	 * I have subscribed.  Imperfect but it is standards
	 * compliant, easy and reliable to implement.
	 *
	 * The optimal group leave method is to only send leave when,
	 * we were the last host to respond to a query on this group,
	 * and igmpv1 compatibility is not enabled.
	 */
	if (igmptable[slot].group.s_addr) {
		struct igmp_ip_t igmp;
		igmp.router_alert[0] = 0x94;
		igmp.router_alert[1] = 0x04;
		igmp.router_alert[2] = 0;
		igmp.router_alert[3] = 0;
		build_ip_hdr(htonl(GROUP_ALL_HOSTS),
			1, IP_IGMP, sizeof(igmp.router_alert), sizeof(igmp), &igmp);
		igmp.igmp.type = IGMP_LEAVE;
		igmp.igmp.response_time = 0;
		igmp.igmp.chksum = 0;
		igmp.igmp.group.s_addr = igmptable[slot].group.s_addr;
		igmp.igmp.chksum = ipchksum(&igmp.igmp, sizeof(igmp));
		ip_transmit(sizeof(igmp), &igmp);
#ifdef	MDEBUG
		printf("Sent IGMP leave for: %@\n", igmp.igmp.group.s_addr);
#endif	
	}
	memset(&igmptable[slot], 0, sizeof(igmptable[0]));
}

void join_group(int slot, unsigned long group)
{
	/* I have already joined */
	if (igmptable[slot].group.s_addr == group)
		return;
	if (igmptable[slot].group.s_addr) {
		leave_group(slot);
	}
	/* Only join a group if we are given a multicast ip, this way
	 * code can be given a non-multicast (broadcast or unicast ip)
	 * and still work... 
	 */
	if ((group & htonl(MULTICAST_MASK)) == htonl(MULTICAST_NETWORK)) {
		igmptable[slot].group.s_addr = group;
		igmptable[slot].time = currticks();
	}
}
#else
#define send_igmp_reports(now);
#define process_igmp(ip, now)
#endif

/**************************************************************************
AWAIT_REPLY - Wait until we get a response for our request
************f**************************************************************/
int await_reply(reply_t reply, int ival, void *ptr, long timeout)
{
	unsigned long time, now;
	struct	iphdr *ip;
	unsigned iplen = 0;
	struct	udphdr *udp;
	unsigned short ptype;
	int result;

	user_abort = 0;

	time = timeout + currticks();
	/* The timeout check is done below.  The timeout is only checked if
	 * there is no packet in the Rx queue.  This assumes that eth_poll()
	 * needs a negligible amount of time.  
	 */
	for (;;) {
		now = currticks();
		send_igmp_reports(now);
		result = eth_poll(1);
		if (result == 0) {
			/* We don't have anything */
		
			/* Check for abort key only if the Rx queue is empty -
			 * as long as we have something to process, don't
			 * assume that something failed.  It is unlikely that
			 * we have no processing time left between packets.  */
			poll_interruptions();
			/* Do the timeout after at least a full queue walk.  */
			if ((timeout == 0) || (currticks() > time) || user_abort == 1) {
				break;
			}
			continue;
		}

		/* We have something! */
	
		/* Find the Ethernet packet type */
		if (nic.packetlen >= ETH_HLEN) {
			ptype = ((unsigned short) nic.packet[12]) << 8
				| ((unsigned short) nic.packet[13]);
		} else continue; /* what else could we do with it? */
		/* Verify an IP header */
		ip = 0;
		if ((ptype == IP) && (nic.packetlen >= ETH_HLEN + sizeof(struct iphdr))) {
			unsigned ipoptlen;
			ip = (struct iphdr *)&nic.packet[ETH_HLEN];
			if ((ip->verhdrlen < 0x45) || (ip->verhdrlen > 0x4F)) 
				continue;
			iplen = (ip->verhdrlen & 0xf) * 4;
			if (ipchksum(ip, iplen) != 0)
				continue;
			if (ip->frags & htons(0x3FFF)) {
				static int warned_fragmentation = 0;
				if (!warned_fragmentation) {
					printf("ALERT: got a fragmented packet - reconfigure your server\n");
					warned_fragmentation = 1;
				}
				continue;
			}
			if (ntohs(ip->len) > ETH_MAX_MTU)
				continue;

			ipoptlen = iplen - sizeof(struct iphdr);
			if (ipoptlen) {
				/* Delete the ip options, to guarantee
				 * good alignment, and make etherboot simpler.
				 */
				memmove(&nic.packet[ETH_HLEN + sizeof(struct iphdr)], 
					&nic.packet[ETH_HLEN + iplen],
					nic.packetlen - ipoptlen);
				nic.packetlen -= ipoptlen;
			}
		}
		udp = 0;
		if (ip && (ip->protocol == IP_UDP) && 
		    (nic.packetlen >= ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))) {
			udp = (struct udphdr *)&nic.packet[ETH_HLEN + sizeof(struct iphdr)];
			
			/* Make certain we have a reasonable packet length */
			if (ntohs(udp->len) > (ntohs(ip->len) - iplen))
				continue;

			if (udp->chksum && udpchksum(ip, udp)) {
				printf("UDP checksum error\n");
				continue;
			}
		}
		result = reply(ival, ptr, ptype, ip, udp);
		if (result > 0) {
			return result;
		}
		
		/* If it isn't a packet the upper layer wants see if there is a default
		 * action.  This allows us reply to arp and igmp queryies.
		 */
		if ((ptype == ARP) &&
		    (nic.packetlen >= ETH_HLEN + sizeof(struct arprequest))) {
			struct	arprequest *arpreply;
			unsigned long tmp;
			
			arpreply = (struct arprequest *)&nic.packet[ETH_HLEN];
			memcpy(&tmp, arpreply->tipaddr, sizeof(in_addr));
			if ((arpreply->opcode == htons(ARP_REQUEST)) &&
			    (tmp == arptable[ARP_CLIENT].ipaddr.s_addr)) {
				arpreply->opcode = htons(ARP_REPLY);
				memcpy(arpreply->tipaddr, arpreply->sipaddr, sizeof(in_addr));
				memcpy(arpreply->thwaddr, arpreply->shwaddr, ETH_ALEN);
				memcpy(arpreply->sipaddr, &arptable[ARP_CLIENT].ipaddr, sizeof(in_addr));
				memcpy(arpreply->shwaddr, arptable[ARP_CLIENT].node, ETH_ALEN);
				eth_transmit(arpreply->thwaddr, ARP,
					     sizeof(struct  arprequest),
					     arpreply);
#ifdef	MDEBUG
				memcpy(&tmp, arpreply->tipaddr, sizeof(in_addr));
				printf("Sent ARP reply to: %@\n",tmp);
#endif	/* MDEBUG */
			}
		}
		process_igmp(ip, now);
	}
	return(0);
}

#ifdef	REQUIRE_VCI_ETHERBOOT
/**************************************************************************
FIND_VCI_ETHERBOOT - Looks for "Etherboot" in Vendor Encapsulated Identifiers
On entry p points to byte count of VCI options
**************************************************************************/
static int find_vci_etherboot(unsigned char *p)
{
	unsigned char	*end = p + 1 + *p;

	for (p++; p < end; ) {
		if (*p == RFC2132_VENDOR_CLASS_ID) {
			if (strncmp("Etherboot", p + 2, sizeof("Etherboot") - 1) == 0)
				return (1);
		} else if (*p == RFC1533_END)
			return (0);
		p += TAG_LEN(p) + 2;
	}
	return (0);
}
#endif	/* REQUIRE_VCI_ETHERBOOT */

/**
 * decode_rfc1533
 *
 * Decodes RFC1533 header
 **/
int decode_rfc1533(unsigned char *p, unsigned int block, unsigned int len, int eof)
{
	static unsigned char *extdata = NULL, *extend = NULL;
	unsigned char        *extpath = NULL;
	unsigned char        *endp;

	if (block == 0) {
		end_of_rfc1533 = NULL;
		if (memcmp(p, rfc1533_cookie, sizeof(rfc1533_cookie)))
			return(0); /* no RFC 1533 header found */
		p += 4;
		endp = p + len;
	} else {
		if (block == 1) {
			if (memcmp(p, rfc1533_cookie, sizeof(rfc1533_cookie)))
				return(0); /* no RFC 1533 header found */
			p += 4;
			len -= 4; }
		if (extend + len <= (unsigned char *)
		    rfc1533_venddata + sizeof(rfc1533_venddata)) {
			memcpy(extend, p, len);
			extend += len;
		} else {
			printf("Overflow in vendor data buffer! Aborting...\n");
			*extdata = RFC1533_END;
			return(0);
		}
		p = extdata; endp = extend;
	}
	if (!eof)
		return 1;
	while (p < endp) {
		unsigned char c = *p;
		if (c == RFC1533_PAD) {
			p++;
			continue;
		}
		else if (c == RFC1533_END) {
			end_of_rfc1533 = endp = p;
			continue;
		}
		else if (c == RFC1533_NETMASK)
			memcpy(&netmask, p+2, sizeof(in_addr));
		else if (c == RFC1533_GATEWAY) {
			/* This is a little simplistic, but it will
			   usually be sufficient.
			   Take only the first entry */
			if (TAG_LEN(p) >= sizeof(in_addr))
				memcpy(&arptable[ARP_GATEWAY].ipaddr, p+2, sizeof(in_addr));
		}
		else if (c == RFC1533_EXTENSIONPATH)
			extpath = p;
		else if (c == RFC2132_MSG_TYPE)
			dhcp_reply=*(p+2);
		else if (c == RFC2132_SRV_ID)
			memcpy(&dhcp_server, p+2, sizeof(in_addr));
		else if (c == RFC1533_HOSTNAME) {
			hostname = p + 2;
			hostnamelen = *(p + 1);
		}
		else if (c == RFC1533_VENDOR_CONFIGFILE){
			int l = TAG_LEN (p);
	  
			/* Eliminate the trailing NULs according to RFC 2132.  */
			while (*(p + 2 + l - 1) == '\000' && l > 0)
				l--;
	  
			/* XXX: Should check if LEN is less than the maximum length
			   of CONFIG_FILE. This kind of robustness will be a goal
			   in GRUB 1.0.  */
			memcpy (config_file, p + 2, l);
			config_file[l] = 0;
			vendor_configfile = p + 2;
			vendor_configfile_len = l;
			configfile_origin = CFG_150;
		}
		else {
			;
		}
		p += TAG_LEN(p) + 2;
	}
	extdata = extend = endp;
	if (block <= 0 && extpath != NULL) {
		char fname[64];
		if (TAG_LEN(extpath) >= sizeof(fname)){
			printf("Overflow in vendor data buffer! Aborting...\n");
			*extdata = RFC1533_END;
			return(0);
		}
		memcpy(fname, extpath+2, TAG_LEN(extpath));
		fname[(int)TAG_LEN(extpath)] = '\0';
		printf("Loading BOOTP-extension file: %s\n",fname);
		tftp_file_read(fname, decode_rfc1533);
	}
	return 1;	/* proceed with next block */
}


/* FIXME double check TWO_SECOND_DIVISOR */
#define TWO_SECOND_DIVISOR (RAND_MAX/TICKS_PER_SEC)
/**************************************************************************
RFC2131_SLEEP_INTERVAL - sleep for expotentially longer times (base << exp) +- 1 sec)
**************************************************************************/
long rfc2131_sleep_interval(long base, int exp)
{
	unsigned long tmo;
#ifdef BACKOFF_LIMIT
	if (exp > BACKOFF_LIMIT)
		exp = BACKOFF_LIMIT;
#endif
	tmo = (base << exp) + (TICKS_PER_SEC - (random()/TWO_SECOND_DIVISOR));
	return tmo;
}

#ifdef MULTICAST_LEVEL2
/**************************************************************************
RFC1112_SLEEP_INTERVAL - sleep for expotentially longer times, up to (base << exp)
**************************************************************************/
long rfc1112_sleep_interval(long base, int exp)
{
	unsigned long divisor, tmo;
#ifdef BACKOFF_LIMIT
	if (exp > BACKOFF_LIMIT)
		exp = BACKOFF_LIMIT;
#endif
	divisor = RAND_MAX/(base << exp);
	tmo = random()/divisor;
	return tmo;
}
#endif /* MULTICAST_LEVEL_2 */
/* ifconfig - configure network interface.  */
int
ifconfig (char *ip, char *sm, char *gw, char *svr)
{
  in_addr tmp;
  
  if (sm) 
    {
      if (! inet_aton (sm, &tmp))
	return 0;
      
      netmask = tmp.s_addr;
    }
  
  if (ip) 
    {
      if (! inet_aton (ip, &arptable[ARP_CLIENT].ipaddr)) 
	return 0;
      
      if (! netmask && ! sm) 
	netmask = default_netmask ();
    }
  
  if (gw && ! inet_aton (gw, &arptable[ARP_GATEWAY].ipaddr)) 
    return 0;

  /* Clear out the ARP entry.  */
  grub_memset (arptable[ARP_GATEWAY].node, 0, ETH_ALEN);
  
  if (svr && ! inet_aton (svr, &arptable[ARP_SERVER].ipaddr)) 
    return 0;

  /* Likewise.  */
  grub_memset (arptable[ARP_SERVER].node, 0, ETH_ALEN);
  
  if (ip || sm)
    {
      if (IP_BROADCAST == (netmask | arptable[ARP_CLIENT].ipaddr.s_addr)
	  || netmask == (netmask | arptable[ARP_CLIENT].ipaddr.s_addr)
	  || ! netmask)
	network_ready = 0;
      else
	network_ready = 1;
    }
  
  update_network_configuration();
  return 1;
}

/*
 * print_network_configuration
 *
 * Output the network configuration. It may broke the graphic console now.:-(
 */
void print_network_configuration (void)
{
	EnterFunction("print_network_configuration");
	if (! network_ready)
		grub_printf ("Network interface not initialized yet.\n");
	else {
		if (hostnamelen == 0)
			etherboot_printf ("Hostname: not set\n");
		else
			etherboot_printf ("Hostname: %s\n", hostname);

		etherboot_printf ("Address: %@\n", arptable[ARP_CLIENT].ipaddr.s_addr);
		etherboot_printf ("Netmask: %@\n", netmask);
		etherboot_printf ("Gateway: %@\n", arptable[ARP_GATEWAY].ipaddr.s_addr);
		etherboot_printf ("Server: %@\n", arptable[ARP_SERVER].ipaddr.s_addr);
		if (vendor_configfile == NULL) {
			etherboot_printf ("Site Option 150: not set\n");
		} else {
			/*
			 * vendor_configfile points into the packet and
			 * is not NULL terminated, so it needs to be
			 * patched up before printing it out
			 */
			char c = vendor_configfile[vendor_configfile_len];
			vendor_configfile[vendor_configfile_len] = '\0';
			etherboot_printf ("Site Option 150: %s\n",
			    vendor_configfile);
			vendor_configfile[vendor_configfile_len] = c;
		}

		if (bootfile == NULL)
			etherboot_printf ("BootFile: not set\n");
		else
			etherboot_printf ("BootFile: %s\n", bootfile);

		etherboot_printf ("GRUB menu file: %s", config_file);
		switch (configfile_origin) {
		case CFG_HARDCODED:
			etherboot_printf (" from hardcoded default\n");
			break;
		case CFG_150:
			etherboot_printf (" from Site Option 150\n");
			break;
		case CFG_MAC:
			etherboot_printf (" inferred from system MAC\n");
			break;
		case CFG_BOOTFILE:
			etherboot_printf (" inferred from BootFile\n");
			break;
		default:
			etherboot_printf ("\n");
		}
	}
	LeaveFunction("print_network_configuration");
}

/*
 * update_network_configuration
 *
 * Update network configuration for diskless clients (Solaris only)
 */
static void update_network_configuration (void)
{
#ifdef SOLARIS_NETBOOT
  	struct sol_netinfo {
	  	uint8_t sn_infotype;
		uint8_t sn_mactype;
		uint8_t sn_maclen;
	  	uint8_t sn_padding;
		unsigned long sn_ciaddr;
		unsigned long sn_siaddr;
		unsigned long sn_giaddr;
		unsigned long sn_netmask;
		uint8_t sn_macaddr[1];
	} *sip;

	if (! network_ready)
	  	return;

	sip = (struct sol_netinfo *)dhcpack_buf;
	sip->sn_infotype = 0xf0;	/* something not BOOTP_REPLY */
	sip->sn_mactype = 4;		/* DL_ETHER */
	sip->sn_maclen = ETH_ALEN;
	sip->sn_ciaddr = arptable[ARP_CLIENT].ipaddr.s_addr;
	sip->sn_siaddr = arptable[ARP_SERVER].ipaddr.s_addr;
	sip->sn_giaddr = arptable[ARP_GATEWAY].ipaddr.s_addr;
	sip->sn_netmask = netmask;
	memcpy(sip->sn_macaddr, arptable[ARP_CLIENT].node, ETH_ALEN);
	dhcpack_length = sizeof (*sip) + sip->sn_maclen - 1;
#endif /* SOLARIS_NETBOOT */
}

/**
 * cleanup_net
 *
 * Mark network unusable, and disable NICs
 */
void cleanup_net (void)
{
	if (network_ready){
		/* Stop receiving packets.  */
		if (use_bios_pxe)
			undi_pxe_disable();
		else
			eth_disable ();
		network_ready = 0;
	}
}

/*******************************************************************
 * dhcp implementation reusing the BIOS pxe stack
 */
static void
dhcp_copy(struct dhcp_t *dhcpreply)
{
	unsigned long time;
	int ret, len = DHCP_OPT_LEN;

	/* fill in netinfo */
	dhcpack_length = sizeof (struct dhcp_t);
	memcpy((char *)dhcpack_buf, (char *)dhcpreply, dhcpack_length);

	memcpy(arptable[ARP_CLIENT].node, dhcpreply->bp_hwaddr, ETH_ALEN);
	arptable[ARP_CLIENT].ipaddr.s_addr = dhcpreply->bp_yiaddr.s_addr;
	dhcp_addr.s_addr = dhcpreply->bp_yiaddr.s_addr;
	netmask = default_netmask();
	arptable[ARP_SERVER].ipaddr.s_addr = dhcpreply->bp_siaddr.s_addr;
	memset(arptable[ARP_SERVER].node, 0, ETH_ALEN);  /* Kill arp */
	arptable[ARP_GATEWAY].ipaddr.s_addr = dhcpreply->bp_giaddr.s_addr;
	memset(arptable[ARP_GATEWAY].node, 0, ETH_ALEN);  /* Kill arp */
	bootfile = dhcpreply->bp_file;
	memcpy((char *)rfc1533_venddata, (char *)(dhcpreply->bp_vend), len);
	decode_rfc1533(rfc1533_venddata, 0, len, 1);
}

int dhcp_undi(void)
{
	struct dhcp_t *dhcpreply;

	if (!undi_bios_pxe((void **)&dhcpreply))
		return 0;

	dhcp_copy(dhcpreply);
	network_ready = 1;
	use_bios_pxe = 1;
	return (1);
}
