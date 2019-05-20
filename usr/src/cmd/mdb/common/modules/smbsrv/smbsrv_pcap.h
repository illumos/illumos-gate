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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMBSRV_PCAP_H
#define	_SMBSRV_PCAP_H

extern void smbsrv_pcap_close();
extern int smbsrv_pcap_open(char *);

extern int smbsrv_pcap_dump(struct mbuf_chain *, int32_t,
    smb_inaddr_t *, uint16_t, smb_inaddr_t *, uint16_t,
    hrtime_t, boolean_t);

#endif /* _SMBSRV_PCAP_H */
