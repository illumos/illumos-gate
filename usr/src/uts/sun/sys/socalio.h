/*
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

#ifndef _SYS_SOCALIO_H
#define	_SYS_SOCALIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/fc4/fcio.h>

/*
 * socalio.h - SOC+ Driver user I/O interface dfinitions
 */

#define	FCIO_BYPASS_DEV		(FIOC|176)
#define	FCIO_ADISC_ELS		(FIOC|178)
#define	FCIO_FORCE_OFFLINE	(FIOC|179)
#define	FCIO_LOADUCODE		(FIOC|180)
#define	FCIO_DUMPXRAM		(FIOC|181)
#define	FCIO_DUMPXRAMBUF	(FIOC|182)
#define	FCIO_LOOPBACK_INTERNAL	(FIOC|190)
#define	FCIO_LOOPBACK_MANUAL	(FIOC|191)
#define	FCIO_NO_LOOPBACK	(FIOC|192)
#define	FCIO_LOOPBACK_FRAME	(FIOC|193)
#define	FCIO_DIAG_NOP		(FIOC|194)
#define	FCIO_DIAG_RAW		(FIOC|195)
#define	FCIO_DIAG_XRAM		(FIOC|196)
#define	FCIO_DIAG_SOC		(FIOC|197)
#define	FCIO_DIAG_HCB		(FIOC|198)
#define	FCIO_DIAG_SOCLB		(FIOC|199)
#define	FCIO_DIAG_SRDSLB	(FIOC|200)
#define	FCIO_DIAG_EXTLB		(FIOC|201)

struct adisc_payload {
	uint_t   adisc_magic;
	uint_t   adisc_hardaddr;
	uchar_t  adisc_portwwn[8];
	uchar_t  adisc_nodewwn[8];
	uint_t   adisc_dest;
};

struct fclb {
	uchar_t  outbound_frame[24];
	uchar_t  inbound_frame[24];
};


#ifdef __cplusplus
}
#endif

#endif /* !_SYS_SOCALIO_H */
