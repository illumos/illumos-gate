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
 * Copyright 2025 Oxide Computer Company
 */


#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/list.h>
#include <sys/time.h>
#include <sys/varargs.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>

static kmutex_t t4_debug_lock;
static list_t t4_debug_msgs;
static uint_t t4_debug_size;
/* Rough counter of allocation failures during cxgb_printf() */
static uint64_t t4_debug_alloc_fail;

/*
 * Max ring buffer size for debug logs.  Defaults to 16KiB.
 *
 * If set to 0, no debug messages will be stored, nor will the t4-dbgmsg SDT
 * probe be fired.
 *
 * If set to < 0, then messages will be logged through the legacy cmn_err()
 * behavior (and the SDT probe is also skipped).
 */
int t4_debug_max_size = 16384;

typedef struct t4_dbgmsg {
	list_node_t	tdm_node;
	hrtime_t	tdm_when;
	dev_info_t	*tdm_dip;
	char		tdm_msg[];
} t4_dbgmsg_t;

static inline uint_t
t4_dbgmsg_sz(int sz)
{
	ASSERT(sz >= 0);
	return (sizeof (t4_dbgmsg_t) + sz + 1);
}

static uint_t
t4_debug_free(t4_dbgmsg_t *msg)
{
	const uint_t free_sz = t4_dbgmsg_sz(strlen(msg->tdm_msg));
	kmem_free(msg, free_sz);

	return (free_sz);
}

void
cxgb_printf(dev_info_t *dip, int level, const char *fmt, ...)
{
	va_list adx;

	if (t4_debug_max_size == 0) {
		/* User has opted out of debug messages completely */
		return;
	} else if (t4_debug_max_size < 0) {
		/* User has opted into old cmn_err() behavior */
		char pfmt[128];

		(void) snprintf(pfmt, sizeof (pfmt), "%s%d: %s",
		    ddi_driver_name(dip), ddi_get_instance(dip), fmt);

		va_start(adx, fmt);
		vcmn_err(level, pfmt, adx);
		va_end(adx);

		return;
	}

	va_start(adx, fmt);
	const int size = vsnprintf(NULL, 0, fmt, adx);
	va_end(adx);

	const uint_t alloc_sz = t4_dbgmsg_sz(size);
	t4_dbgmsg_t *msg = kmem_alloc(alloc_sz, KM_NOSLEEP);
	if (msg == NULL) {
		/*
		 * Just note the failure and bail if the system is so pressed
		 * for memory.
		 */
		DTRACE_PROBE1(t4__dbgmsg__alloc_fail, dev_info_t *, dip);
		t4_debug_alloc_fail++;
		return;
	}
	msg->tdm_when = gethrtime();
	msg->tdm_dip = dip;

	va_start(adx, fmt);
	(void) vsnprintf(msg->tdm_msg, size + 1, fmt, adx);
	va_end(adx);

	DTRACE_PROBE2(t4__dbgmsg, dev_info_t *, dip, char *, msg->tdm_msg);

	mutex_enter(&t4_debug_lock);
	list_insert_tail(&t4_debug_msgs, msg);
	t4_debug_size += alloc_sz;
	while (t4_debug_size > t4_debug_max_size && t4_debug_size != 0) {
		msg = list_remove_head(&t4_debug_msgs);
		t4_debug_size -= t4_debug_free(msg);
	}
	mutex_exit(&t4_debug_lock);
}

void
t4_debug_init(void)
{
	mutex_init(&t4_debug_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&t4_debug_msgs, sizeof (t4_dbgmsg_t),
	    offsetof(t4_dbgmsg_t, tdm_node));
}

void
t4_debug_fini(void)
{
	t4_dbgmsg_t *msg;

	while ((msg = list_remove_head(&t4_debug_msgs)) != NULL) {
		t4_debug_size -= t4_debug_free(msg);
	}
	mutex_destroy(&t4_debug_lock);
}
