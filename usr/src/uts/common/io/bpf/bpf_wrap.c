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

#include <sys/types.h>
#include <net/bpf.h>
#include <inet/bpf.h>

/*
 * With BPF filter validation and evaluation moved into the 'ip' module, these
 * wrapper functions are provided to expose the original interface.
 */

uint_t
bpf_filter(struct bpf_insn *pc, uchar_t *p, uint_t wirelen, uint_t buflen)
{
	return ((uint_t)ip_bpf_filter((ip_bpf_insn_t *)pc, p, wirelen, buflen));
}

int
bpf_validate(struct bpf_insn *f, int len)
{
	return ((int)ip_bpf_validate((ip_bpf_insn_t *)f, (uint_t)len));
}
