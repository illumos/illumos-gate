/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef _DEFS_H
#define	_DEFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <zone.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/sockio.h>
#include <stropts.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <net/pfkeyv2.h>
#include <netinet/if_ether.h>
#include <net/if_types.h>
#include <net/if_dl.h>

#include <netinet/dhcp.h>
#include <dhcpagent_util.h>
#include <dhcpagent_ipc.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <assert.h>

#include <ipmp_mpathd.h>
#include <inetcfg.h>

#ifdef __cplusplus
}
#endif

#endif /* _DEFS_H */
