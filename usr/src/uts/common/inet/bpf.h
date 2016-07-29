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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_INET_BPF_H
#define	_INET_BPF_H

#ifdef	__cplusplus
extern "C" {
#endif


#ifdef	_KERNEL

#include <sys/types.h>

/*
 * Clone bpf_insn definition so that consumers don't need net/bpf.h to reason
 * about struct sizing.
 */
typedef struct ip_bpf_insn {
	uint16_t	code;
	uint8_t		jt;
	uint8_t		jf;
	uint32_t	k;
} ip_bpf_insn_t;

extern uint32_t ip_bpf_filter(ip_bpf_insn_t *, uchar_t *, uint_t, uint_t);
extern boolean_t ip_bpf_validate(ip_bpf_insn_t *, uint_t);


#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_BPF_H */
