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
 *
 * Copyright (c) 2002-2006 Neterion, Inc.
 */

#ifndef XGE_DEBUG_H
#define XGE_DEBUG_H

#include "xge-os-pal.h"

__EXTERN_BEGIN_DECLS

/* to make some gcc versions happier */
#ifndef __func__
#define __func__ __FUNCTION__
#endif

#ifdef XGE_DEBUG_FP
#define XGE_DEBUG_FP_DEVICE	0x1
#define XGE_DEBUG_FP_CHANNEL	0x2
#define XGE_DEBUG_FP_FIFO	0x4
#define XGE_DEBUG_FP_RING	0x8
#endif

/**
 * enum xge_debug_level_e
 * @XGE_NONE: debug disabled
 * @XGE_ERR: all errors going to be logged out
 * @XGE_TRACE: all errors plus all kind of verbose tracing print outs
 *                 going to be logged out. Very noisy.
 *
 * This enumeration going to be used to switch between different
 * debug levels during runtime if DEBUG macro defined during
 * compilation. If DEBUG macro not defined than code will be
 * compiled out.
 */
typedef enum xge_debug_level_e {
	XGE_NONE   = 0,
	XGE_TRACE  = 1,
	XGE_ERR    = 2,
} xge_debug_level_e;

#define XGE_DEBUG_MODULE_MASK_DEF	0x00003030
#define XGE_DEBUG_LEVEL_DEF		XGE_ERR

#if defined(XGE_DEBUG_TRACE_MASK) || defined(XGE_DEBUG_ERR_MASK)

extern unsigned int *g_module_mask;
extern int *g_level;

#ifndef XGE_DEBUG_TRACE_MASK
#define XGE_DEBUG_TRACE_MASK 0
#endif

#ifndef XGE_DEBUG_ERR_MASK
#define XGE_DEBUG_ERR_MASK 0
#endif

/*
 * @XGE_COMPONENT_HAL_CONFIG: do debug for xge core config module
 * @XGE_COMPONENT_HAL_FIFO: do debug for xge core fifo module
 * @XGE_COMPONENT_HAL_RING: do debug for xge core ring module
 * @XGE_COMPONENT_HAL_CHANNEL: do debug for xge core channel module
 * @XGE_COMPONENT_HAL_DEVICE: do debug for xge core device module
 * @XGE_COMPONENT_HAL_DMQ: do debug for xge core DMQ module
 * @XGE_COMPONENT_HAL_UMQ: do debug for xge core UMQ module
 * @XGE_COMPONENT_HAL_SQ: do debug for xge core SQ module
 * @XGE_COMPONENT_HAL_SRQ: do debug for xge core SRQ module
 * @XGE_COMPONENT_HAL_CRQ: do debug for xge core CRQ module
 * @XGE_COMPONENT_HAL_LRQ: do debug for xge core LRQ module
 * @XGE_COMPONENT_HAL_LCQ: do debug for xge core LCQ module
 * @XGE_COMPONENT_CORE: do debug for xge KMA core module
 * @XGE_COMPONENT_OSDEP: do debug for xge KMA os dependent parts
 * @XGE_COMPONENT_LL: do debug for xge link layer module
 * @XGE_COMPONENT_ALL: activate debug for all modules with no exceptions
 *
 * This enumeration going to be used to distinguish modules
 * or libraries during compilation and runtime.  Makefile must declare
 * XGE_DEBUG_MODULE_MASK macro and set it to proper value.
 */
#define XGE_COMPONENT_HAL_CONFIG		0x00000001
#define	XGE_COMPONENT_HAL_FIFO			0x00000002
#define	XGE_COMPONENT_HAL_RING			0x00000004
#define	XGE_COMPONENT_HAL_CHANNEL		0x00000008
#define	XGE_COMPONENT_HAL_DEVICE		0x00000010
#define	XGE_COMPONENT_HAL_MM			0x00000020
#define	XGE_COMPONENT_HAL_QUEUE		        0x00000040
#define	XGE_COMPONENT_HAL_STATS		        0x00000100
#ifdef XGEHAL_RNIC
#define	XGE_COMPONENT_HAL_DMQ		        0x00000200
#define	XGE_COMPONENT_HAL_UMQ		        0x00000400
#define	XGE_COMPONENT_HAL_SQ		        0x00000800
#define	XGE_COMPONENT_HAL_SRQ		        0x00001000
#define	XGE_COMPONENT_HAL_CQRQ		        0x00002000
#define	XGE_COMPONENT_HAL_LRQ		        0x00004000
#define	XGE_COMPONENT_HAL_LCQ		        0x00008000
#define	XGE_COMPONENT_HAL_POOL		        0x00010000
#endif

	/* space for CORE_XXX */
#define	XGE_COMPONENT_OSDEP			0x10000000
#define	XGE_COMPONENT_LL			0x20000000
#define	XGE_COMPONENT_ALL			0xffffffff

#ifndef XGE_DEBUG_MODULE_MASK
#error "XGE_DEBUG_MODULE_MASK macro must be defined for DEBUG mode..."
#endif

#ifndef __GNUC__
#ifdef XGE_TRACE_INTO_CIRCULAR_ARR
        #define xge_trace_aux(fmt) xge_os_vatrace(g_xge_os_tracebuf, fmt)
#else
        #define xge_trace_aux(fmt) xge_os_vaprintf(fmt)
#endif

/**
 * xge_debug
 * @level: level of debug verbosity.
 * @fmt: printf like format string
 *
 * Provides logging facilities. Can be customized on per-module
 * basis or/and with debug levels. Input parameters, except
 * module and level, are the same as posix printf. This function
 * may be compiled out if DEBUG macro was never defined.
 * See also: xge_debug_level_e{}.
 */
#define xge_debug(module, level, fmt) { \
if (((level >= XGE_TRACE && ((module & XGE_DEBUG_TRACE_MASK) == module)) || \
    (level >= XGE_ERR && ((module & XGE_DEBUG_ERR_MASK) == module))) && \
    level >= *g_level && module & *g_module_mask) { \
                xge_trace_aux(fmt); \
	} \
}
#else /* __GNUC__ */

#ifdef XGE_TRACE_INTO_CIRCULAR_ARR
        #define xge_trace_aux(fmt...) xge_os_trace(g_xge_os_tracebuf, fmt)
#else
        #define xge_trace_aux(fmt...) xge_os_printf(fmt)
#endif

#define xge_debug(module, level, fmt...) { \
if (((level >= XGE_TRACE && ((module & XGE_DEBUG_TRACE_MASK) == module)) || \
    (level >= XGE_ERR && ((module & XGE_DEBUG_ERR_MASK) == module))) && \
    level >= *g_level && module & *g_module_mask) { \
                xge_trace_aux(fmt); \
	} \
}
#endif /* __GNUC__ */

#if (XGE_COMPONENT_HAL_STATS & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_stats(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_STATS;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_stats(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_STATS, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_stats(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_stats(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_QUEUE & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_queue(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_QUEUE;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_queue(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_QUEUE, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_queue(xge_debug_level_e level, char *fmt,
...) {}
#else /* __GNUC__ */
#define xge_debug_queue(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_MM & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_mm(xge_debug_level_e level, char *fmt, ...)
{
	u32 module = XGE_COMPONENT_HAL_MM;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_mm(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_MM, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_mm(xge_debug_level_e level, char *fmt, ...)
{}
#else /* __GNUC__ */
#define xge_debug_mm(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_CONFIG & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_config(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_CONFIG;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_config(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_CONFIG, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_config(xge_debug_level_e level, char *fmt,
...) {}
#else /* __GNUC__ */
#define xge_debug_config(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_FIFO & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_fifo(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_FIFO;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_fifo(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_FIFO, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_fifo(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_fifo(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_RING & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_ring(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_RING;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_ring(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_RING, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_ring(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_ring(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_CHANNEL & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_channel(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_CHANNEL;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_channel(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_CHANNEL, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_channel(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_channel(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_DEVICE & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_device(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_DEVICE;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_device(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_DEVICE, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_device(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_device(level, fmt...)
#endif /* __GNUC__ */
#endif

#ifdef XGEHAL_RNIC

#if (XGE_COMPONENT_HAL_DMQ & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_dmq(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_DMQ;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_dmq(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_DMQ, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_dmq(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_dmq(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_UMQ & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_umq(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_UMQ;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_umq(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_UMQ, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_umq(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_umq(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_SQ & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_sq(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_SQ;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_sq(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_SQ, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_sq(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_sq(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_SRQ & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_srq(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_SRQ;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_srq(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_SRQ, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_srq(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_srq(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_CQRQ & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_cqrq(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_CQRQ;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_cqrq(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_CQRQ, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_cqrq(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_cqrq(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_LRQ & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_lrq(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_LRQ;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_lrq(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_LRQ, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_lrq(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_lrq(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_LCQ & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_lcq(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_LCQ;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_lcq(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_LCQ, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_lcq(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_lcq(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_HAL_POOL & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_pool(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_HAL_POOL;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_pool(level, fmt...) \
	xge_debug(XGE_COMPONENT_HAL_POOL, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_pool(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_pool(level, fmt...)
#endif /* __GNUC__ */
#endif

#endif

#if (XGE_COMPONENT_OSDEP & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_osdep(xge_debug_level_e level, char *fmt, ...) {
	u32 module = XGE_COMPONENT_OSDEP;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_osdep(level, fmt...) \
	xge_debug(XGE_COMPONENT_OSDEP, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_osdep(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_osdep(level, fmt...)
#endif /* __GNUC__ */
#endif

#if (XGE_COMPONENT_LL & XGE_DEBUG_MODULE_MASK)
#ifndef __GNUC__
static inline void xge_debug_ll(xge_debug_level_e level, char *fmt, ...)
{
	u32 module = XGE_COMPONENT_LL;
	xge_debug(module, level, fmt);
}
#else /* __GNUC__ */
#define xge_debug_ll(level, fmt...) \
	xge_debug(XGE_COMPONENT_LL, level, fmt)
#endif /* __GNUC__ */
#else
#ifndef __GNUC__
static inline void xge_debug_ll(xge_debug_level_e level, char *fmt, ...) {}
#else /* __GNUC__ */
#define xge_debug_ll(level, fmt...)
#endif /* __GNUC__ */
#endif

#else

static inline void xge_debug_stats(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_queue(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_mm(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_config(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_fifo(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_ring(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_channel(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_device(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_dmq(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_umq(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_sq(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_srq(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_cqrq(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_lrq(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_lcq(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_pool(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_hal(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_osdep(xge_debug_level_e level, char *fmt, ...) {}
static inline void xge_debug_ll(xge_debug_level_e level, char *fmt, ...) {}

#endif /* end of XGE_DEBUG_*_MASK */

#ifdef XGE_DEBUG_ASSERT

/**
 * xge_assert
 * @test: C-condition to check
 * @fmt: printf like format string
 *
 * This function implements traditional assert. By default assertions
 * are enabled. It can be disabled by defining XGE_DEBUG_ASSERT macro in
 * compilation
 * time.
 */
#define xge_assert(test) { \
        if (!(test)) xge_os_bug("bad cond: "#test" at %s:%d\n", \
	__FILE__, __LINE__); }
#else
#define xge_assert(test)
#endif /* end of XGE_DEBUG_ASSERT */

__EXTERN_END_DECLS

#endif /* XGE_DEBUG_H */
