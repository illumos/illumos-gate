#ifndef	_IP_H
#define	_IP_H

/* We need 'uint16_t' */
#include "types.h"
/* We need 'in_addr' */
#include "in.h"

struct iphdr {
	uint8_t  verhdrlen;
	uint8_t  service;
	uint16_t len;
	uint16_t ident;
	uint16_t frags;
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t chksum;
	in_addr src;
	in_addr dest;
};

extern void build_ip_hdr(unsigned long __destip, int __ttl, int __protocol, 
			 int __option_len, int __len, const void * __buf);

extern int ip_transmit(int __len, const void * __buf);

extern uint16_t ipchksum(const void * __data, unsigned long __length);

extern uint16_t add_ipchksums(unsigned long __offset, uint16_t __sum, 
			      uint16_t __new);





#endif	/* _IP_H */
