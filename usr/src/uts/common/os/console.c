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
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/console.h>
#include <sys/consdev.h>
#include <sys/promif.h>
#include <sys/note.h>
#include <sys/polled_io.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/taskq.h>
#include <sys/log.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/fs/snode.h>
#include <sys/termios.h>
#include <sys/tem_impl.h>

#define	MINLINES	10
#define	MAXLINES	48
#define	LOSCREENLINES	34
#define	HISCREENLINES	48

#define	MINCOLS		10
#define	MAXCOLS		120
#define	LOSCREENCOLS	80
#define	HISCREENCOLS	120

vnode_t *console_vnode;
taskq_t *console_taskq;

/*
 * The current set of polled I/O routines (if any)
 */
struct cons_polledio *cons_polledio;

/*
 * Console I/O Routines
 *
 * In the event that kernel messages are generated with cmn_err(9F) or printf()
 * early in boot, after a panic, in resource-constrained situations, or sent
 * through /dev/console to the wscons driver, we may be called upon to render
 * characters directly to the frame buffer using the underlying prom_*()
 * routines.  These in turn may attempt to use PROM services directly, or may
 * use a kernel console emulator if one is available.  Unfortunately, if PROM
 * services are being used by the kernel on a multi-CPU system, these routines
 * might be called while another CPU is simultaneously accessing a frame buffer
 * memory mapping (perhaps through the X server).  This situation may not be
 * supported by the frame buffer hardware.
 *
 * To handle this situation, we implement a two-phase locking scheme which we
 * use to protect accesses to the underlying prom_*() rendering routines.  The
 * common-code functions console_hold() and console_rele() are used to gain
 * exclusive access to the console from within the kernel.  We use a standard
 * r/w lock in writer-mode only to implement the kernel lock.  We use an r/w
 * lock instead of a mutex here because character rendering is slow and hold
 * times will be relatively long, and there is no point in adaptively spinning.
 * These routines may be called recursively, in which case subsequent calls
 * just increment the console_depth hold count.  Once exclusive access is
 * gained, we grab the frame buffer device node and block further mappings to
 * it by holding the specfs node lock and the device node's lock.  We then
 * observe if any mappings are present by examining the specfs node's s_mapcnt
 * (non-clone mmaps) and the devinfo node's devi_ref count (clone opens).
 *
 * Then, around each character rendering call, the routines console_enter()
 * and console_exit() are used to inform the platform code that we are
 * accessing the character rendering routines.  These platform routines can
 * then examine the "busy" flag returned by console_enter() and briefly stop
 * the other CPUs so that they cannot access the frame buffer hardware while
 * we are busy rendering characters.  This mess can all be removed when the
 * impossible dream of a unified kernel console emulator is someday realized.
 */

static krwlock_t console_lock;
static uint_t console_depth;
static int console_busy;

extern void pm_cfb_check_and_powerup(void);
extern void pm_cfb_rele(void);

static int
console_hold(void)
{
	if (panicstr != NULL)
		return (console_busy); /* assume exclusive access in panic */

	if (rw_owner(&console_lock) != curthread)
		rw_enter(&console_lock, RW_WRITER);

	if (console_depth++ != 0)
		return (console_busy); /* lock is being entered recursively */

	pm_cfb_check_and_powerup();

#ifdef _HAVE_TEM_FIRMWARE
	if (consmode == CONS_FW && ncpus > 1 && fbvp != NULL) {
		struct snode *csp = VTOS(VTOS(fbvp)->s_commonvp);

		mutex_enter(&csp->s_lock);
		console_busy = csp->s_mapcnt != 0;

		if (csp->s_mapcnt == 0 && fbdip != NULL) {
			mutex_enter(&DEVI(fbdip)->devi_lock);
			console_busy = DEVI(fbdip)->devi_ref != 0;
		}
	}
#endif /* _HAVE_TEM_FIRMWARE */
	return (console_busy);
}

static void
console_rele(void)
{
	if (panicstr != NULL)
		return; /* do not modify lock states if we are panicking */

	ASSERT(RW_WRITE_HELD(&console_lock));
	ASSERT(console_depth != 0);

	if (--console_depth != 0)
		return; /* lock is being dropped recursively */

#ifdef _HAVE_TEM_FIRMWARE
	if (consmode == CONS_FW && ncpus > 1 && fbvp != NULL) {
		struct snode *csp = VTOS(VTOS(fbvp)->s_commonvp);

		ASSERT(MUTEX_HELD(&csp->s_lock));
		if (csp->s_mapcnt == 0 && fbdip != NULL)
			mutex_exit(&DEVI(fbdip)->devi_lock);

		mutex_exit(&csp->s_lock);
	}
#endif /* _HAVE_TEM_FIRMWARE */
	pm_cfb_rele();
	console_busy = 0;
	rw_exit(&console_lock);
}

static void
console_getprop(dev_t dev, dev_info_t *dip, char *name, ushort_t *sp)
{
	uchar_t *data;
	uint_t len;
	uint_t i;

	*sp = 0;
	if (ddi_prop_lookup_byte_array(dev, dip, 0, name, &data, &len) ==
	    DDI_PROP_SUCCESS) {
		for (i = 0; i < len; i++) {
			if (data[i] < '0' || data[i] > '9')
				break;
			*sp = *sp * 10 + data[i] - '0';
		}
		ddi_prop_free(data);
	}
}

/*
 * Gets the number of rows and columns (in char's) and the
 * width and height (in pixels) of the console.
 */
void
console_get_size(ushort_t *r, ushort_t *c, ushort_t *x, ushort_t *y)
{
	int rel_needed = 0;
	dev_info_t *dip;
	dev_t dev;

	/*
	 * If we have loaded the console IO stuff, then ask for the screen
	 * size properties from the layered terminal emulator.  Else ask for
	 * them from the root node, which will eventually fall through to the
	 * options node and get them from the prom.
	 */
	if (rwsconsvp == NULL || consmode == CONS_FW) {
		dip = ddi_root_node();
		dev = DDI_DEV_T_ANY;
	} else {
		dev = rwsconsvp->v_rdev; /* layering is wc -> tem */
		dip = e_ddi_hold_devi_by_dev(dev, 0);
		rel_needed = 1;
	}

	/*
	 * If we have not initialized a console yet and don't have a root
	 * node (ie. we have not initialized the DDI yet) return our default
	 * size for the screen.
	 */
	if (dip == NULL) {
		*r = LOSCREENLINES;
		*c = LOSCREENCOLS;
		*x = *y = 0;
		return;
	}

	console_getprop(DDI_DEV_T_ANY, dip, "screen-#columns", c);
	console_getprop(DDI_DEV_T_ANY, dip, "screen-#rows", r);
	console_getprop(DDI_DEV_T_ANY, dip, "screen-width", x);
	console_getprop(DDI_DEV_T_ANY, dip, "screen-height", y);

	if (*c < MINCOLS)
		*c = LOSCREENCOLS;
	else if (*c > MAXCOLS)
		*c = HISCREENCOLS;

	if (*r < MINLINES)
		*r = LOSCREENLINES;
	else if (*r > MAXLINES)
		*r = HISCREENLINES;

	if (rel_needed)
		ddi_release_devi(dip);
}

typedef struct console_msg {
	size_t	cm_size;
	char	cm_text[1];
} console_msg_t;

/*
 * If we can't access the console stream, fall through to PROM, which redirects
 * it back into to terminal emulator as appropriate.  The console stream should
 * be available after consconfig runs.
 */
static void
console_putmsg(console_msg_t *cm)
{
	int busy, spl;
	ssize_t res;

	ASSERT(taskq_member(console_taskq, curthread));

	if (rconsvp == NULL || panicstr ||
	    vn_rdwr(UIO_WRITE, console_vnode, cm->cm_text, strlen(cm->cm_text),
	    0, UIO_SYSSPACE, FAPPEND, (rlim64_t)LOG_HIWAT, kcred, &res) != 0) {

		busy = console_hold();
		spl = console_enter(busy);

		prom_printf("%s", cm->cm_text);

		console_exit(busy, spl);
		console_rele();
	}

	kmem_free(cm, cm->cm_size);
}

void
console_vprintf(const char *fmt, va_list adx)
{
	console_msg_t *cm;
	size_t len = vsnprintf(NULL, 0, fmt, adx);
	int busy, spl;

	if (console_taskq != NULL && rconsvp != NULL && panicstr == NULL &&
	    (cm = kmem_alloc(sizeof (*cm) + len, KM_NOSLEEP)) != NULL) {
		cm->cm_size = sizeof (*cm) + len;
		(void) vsnprintf(cm->cm_text, len + 1, fmt, adx);
		if (taskq_dispatch(console_taskq, (task_func_t *)console_putmsg,
		    cm, TQ_NOSLEEP) != 0)
			return;
		kmem_free(cm, cm->cm_size);
	}

	busy = console_hold();
	spl = console_enter(busy);

	prom_vprintf(fmt, adx);

	console_exit(busy, spl);
	console_rele();
}

/*PRINTFLIKE1*/
void
console_printf(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	console_vprintf(fmt, adx);
	va_end(adx);
}

/*
 * Avoid calling this function.
 *
 * Nothing in the kernel besides the wscons driver (wc) uses this
 * function. It may hopefully one day be removed altogether.
 * If a wayward module calls this they will pass through to PROM,
 * get redirected into the kernel emulator as appropriate.
 */
void
console_puts(const char *s, size_t n)
{
	int busy, spl;

	busy = console_hold();
	spl = console_enter(busy);

	prom_writestr(s, n);

	console_exit(busy, spl);
	console_rele();
}

/*
 * Let this function just go straight through to the PROM, since
 * we are called in early boot prior to the kernel terminal
 * emulator being available, and prior to the PROM stdout redirect
 * vector being set.
 */
static void
console_putc(int c)
{
	int busy = console_hold();
	int spl = console_enter(busy);

	if (c == '\n')
		prom_putchar('\r');
	prom_putchar(c);

	console_exit(busy, spl);
	console_rele();
}

/*
 * Read a string from the console device.  We only permit synchronous
 * conversation between the kernel and a console user early in boot prior to
 * the initialization of rconsvp.
 */
void
console_gets(char *s, size_t len)
{
	char *p = s;
	char *q = s + len - 1;
	int c;

	ASSERT(rconsvp == NULL);
	(void) console_hold();

	for (;;) {
		switch (c = (prom_getchar() & 0x7f)) {
		case 0x7f: /* DEL */
			if (p == s)
				break;
			console_putc(c);
			c = '\b';
			/*FALLTHRU*/

		case '\b':
			if (p == s)
				break;
			console_putc('\b');
			console_putc(' ');
			/*FALLTHRU*/

		case '#': /* historical backspace alias */
			console_putc(c);
			if (p > s)
				p--;
			break;

		case CTRL('u'):
			console_putc(c);
			console_putc('\n');
			p = s;
			break;

		case '\r':
		case '\n':
			console_putc('\n');
			goto done;

		default:
			if (p < q) {
				console_putc(c);
				*p++ = c;
			} else
				console_putc('\a');
		}
	}
done:
	console_rele();
	*p = '\0';
}

/*
 * Read a character from the console device.  Synchronous conversation between
 * the kernel and a console user is only permitted early in boot prior to the
 * initialization of rconsvp.
 */
int
console_getc(void)
{
	int c;

	ASSERT(rconsvp == NULL);
	c = prom_getchar();

	if (c == '\r')
		c = '\n';

	console_putc(c);
	return (c);
}
