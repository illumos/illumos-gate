/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright(c) 2004
 *	Damien Bergamini <damien.bergamini@free.fr>. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_IPW2200_H
#define	_SYS_IPW2200_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Intel Wireless PRO/2200 mini-pci adapter drier
 * ipw2200.h: common definitions and interface to user land application
 */
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#define	IPW2200_DRV_NAME  "iwi"
#define	IPW2200_DRV_DESC  "Intel Wireless 2200/2915"

/*
 * Debug functionalities
 */
#define	IPW2200_DBG_INIT	(0x00000001)  /* initialization */
#define	IPW2200_DBG_GLD		(0x00000002)  /* GLD */
#define	IPW2200_DBG_WIFI	(0x00000004)  /* WiFi */
#define	IPW2200_DBG_DMA		(0x00000008)  /* DMA */
#define	IPW2200_DBG_CSR		(0x00000010)  /* low-level CSR access */
#define	IPW2200_DBG_FW		(0x00000020)  /* uc & fw */
#define	IPW2200_DBG_RING	(0x00000040)  /* ring operations */
#define	IPW2200_DBG_IOCTL	(0x00000080)  /* ioctl */
#define	IPW2200_DBG_INT		(0x00000100)  /* interrupt */
#define	IPW2200_DBG_TABLE	(0x00000200)  /* ipw2200 tables */
#define	IPW2200_DBG_RX		(0x00000400)  /* rx */
#define	IPW2200_DBG_TX		(0x00000800)  /* tx */
#define	IPW2200_DBG_HWCAP	(0x00001000)  /* hardware capabilities */
#define	IPW2200_DBG_NOTIF	(0x00002000)  /* ipw2200 notification */
#define	IPW2200_DBG_SCAN	(0x00004000)  /* scan results */
#define	IPW2200_DBG_SOFTINT	(0x00008000)  /* soft interrupt */
#define	IPW2200_DBG_FATAL	(0x00010000)  /* interrupt report error */
#define	IPW2200_DBG_SUSPEND	(0x00020000)  /* suspend resume */
#define	IPW2200_DBG_BRUSSELS	(0x00040000)  /* brussels support */

extern uint32_t ipw2200_debug;
extern void	ipw2200_dbg(dev_info_t *dip, int level, const char *fmt, ...);

#ifdef	DEBUG
#define	IPW2200_DBG(l, x)	do {				\
	_NOTE(CONSTANTCONDITION)				\
	if ((l) & ipw2200_debug)				\
		ipw2200_dbg x;					\
	_NOTE(CONSTANTCONDITION)				\
} while (0)
#else
#define	IPW2200_DBG(l, x)
#endif

#define	IPW2200_WARN(x)   ipw2200_dbg x
#define	IPW2200_REPORT(x) ipw2200_dbg x

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IPW2200_H */
