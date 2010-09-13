/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IPW2100_H
#define	_SYS_IPW2100_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Intel Wireless PRO/2100 mini-PCI adapter driver
 * ipw2100.h: common definitions and interface to user land application
 */
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#define	IPW2100_DRV_NAME  "ipw"
#define	IPW2100_DRV_DESC  "Intel Wireless 2100"

/*
 * Debug functionalities
 */
#define	IPW2100_DBG_INIT	(0x00000001)  /* initialization */
#define	IPW2100_DBG_GLD		(0x00000002)  /* GLD */
#define	IPW2100_DBG_WIFI	(0x00000004)  /* WiFi */
#define	IPW2100_DBG_DMA		(0x00000008)  /* DMA */
#define	IPW2100_DBG_CSR		(0x00000010)  /* low-level CSR access */
#define	IPW2100_DBG_FW		(0x00000020)  /* uc & fw */
#define	IPW2100_DBG_RING	(0x00000040)  /* ring operations */
#define	IPW2100_DBG_IOCTL	(0x00000080)  /* ioctl */
#define	IPW2100_DBG_INT		(0x00000100)  /* interrupt */
#define	IPW2100_DBG_TABLE	(0x00000200)  /* ipw2100 tables */
#define	IPW2100_DBG_HWCAP	(0x00001000)  /* hardware capabilities */
#define	IPW2100_DBG_SOFTINT	(0x00008000)  /* softinterrupt */
#define	IPW2100_DBG_STATISTIC	(0x00010000)  /* statistic */
#define	IPW2100_DBG_FATAL	(0x00020000)  /* interrup report error */
#define	IPW2100_DBG_BRUSSELS	(0x00040000)  /* brussels support */

extern uint32_t ipw2100_debug;
extern void	ipw2100_dbg(dev_info_t *dip, int level, const char *fmt, ...);

#ifdef	DEBUG
#define	IPW2100_DBG(l, x)	do {				\
	_NOTE(CONSTANTCONDITION)				\
	if ((l) & ipw2100_debug) 				\
	    ipw2100_dbg x;		 			\
	_NOTE(CONSTANTCONDITION)				\
} while (0)
#else
#define	IPW2100_DBG(l, x)
#endif

#define	IPW2100_WARN(x)   ipw2100_dbg x
#define	IPW2100_REPORT(x) ipw2100_dbg x

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IPW2100_H */
