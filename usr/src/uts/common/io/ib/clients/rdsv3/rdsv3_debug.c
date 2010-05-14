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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/time.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

/*
 * This file contains the debug defines and routines.
 * Debugging information is collected in a circular kernel buffer. Debug
 * messages with level lower than rdsv3dbglvl are ignored. The size of the
 * of the debug buffer can be changed by setting 'rdsv3_debug_buf_size' in
 * bytes in /etc/system.
 *
 * The debug buffer can be cleared by setting 'rdsv3_clear_debug_buf_flag = 1'
 * on a running system.
 */

#define	RDSV3_DEBUG_SIZE_EXTRA_ALLOC	8
#define	RDSV3_MIN_DEBUG_BUF_SIZE		0x1000
#define	RDSV3_FUNCNAME_LEN		40
#define	RDSV3_PRINTBUF_LEN		4096
#ifdef	DEBUG
#define	RDSV3_DEBUG_BUF_SIZE		0x200000	/* 2M size */
#else
#define	RDSV3_DEBUG_BUF_SIZE		0x2000
#endif	/* DEBUG */

/* Max length of a debug statement */
#define	RDSV3_PRINT_BUF_LEN	4096

static int rdsv3_suppress_dprintf;	/* Suppress debug printing */
static int rdsv3_buffer_dprintf = 1;	/* Use debug buffer (0 == console) */
static int rdsv3_debug_buf_size = RDSV3_DEBUG_BUF_SIZE; /* Sz of Debug buf */
static int rdsv3_allow_intr_msgs = 0;	/* log "intr" messages */
char *rdsv3_debug_buf = NULL;	/* The Debug Buf */
char *rdsv3_buf_sptr, *rdsv3_buf_eptr;	/* debug buffer temp pointer */
int rdsv3_clear_debug_buf_flag = 0;	/* Clear debug buffer */
uint_t	rdsv3dbglvl = RDSV3_LOG_L4;

/*
 * Print Buffer protected by mutex for debug stuff. The mutex also
 * ensures serializing debug messages.
 */
static kmutex_t	rdsv3_debug_mutex;
static char	rdsv3_print_buf[RDSV3_PRINT_BUF_LEN];

/* Function Prototypes */
static void	rdsv3_clear_print_buf();

/* RDS logging init */
void
rdsv3_logging_initialization()
{
	boolean_t flag = B_FALSE;

	mutex_init(&rdsv3_debug_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&rdsv3_debug_mutex);

	if (rdsv3_debug_buf_size <= RDSV3_DEBUG_SIZE_EXTRA_ALLOC) {
		rdsv3_debug_buf_size = RDSV3_MIN_DEBUG_BUF_SIZE;
		flag = B_TRUE;
	}

	/* if it is less that RDSV3_MIN_DEBUG_BUF_SIZE, adjust it */
	rdsv3_debug_buf_size = max(RDSV3_MIN_DEBUG_BUF_SIZE,
	    rdsv3_debug_buf_size);

	rdsv3_debug_buf = (char *)kmem_alloc(rdsv3_debug_buf_size, KM_SLEEP);
	rdsv3_clear_print_buf();
	mutex_exit(&rdsv3_debug_mutex);

	if (flag == B_TRUE) {
		RDSV3_DPRINTF2("RDS", "rdsv3_debug_buf_size was too small, "
		    "adjusted to %x", rdsv3_debug_buf_size);
	}
}


/* RDS logging destroy */
void
rdsv3_logging_destroy()
{
	mutex_enter(&rdsv3_debug_mutex);
	if (rdsv3_debug_buf) {
		kmem_free(rdsv3_debug_buf, rdsv3_debug_buf_size);
		rdsv3_debug_buf = NULL;
	}
	mutex_exit(&rdsv3_debug_mutex);
	mutex_destroy(&rdsv3_debug_mutex);
}


/*
 * debug, log, and console message handling
 */

/*
 * clear the RDS debug buffer
 */
static void
rdsv3_clear_print_buf()
{
	ASSERT(MUTEX_HELD(&rdsv3_debug_mutex));
	if (rdsv3_debug_buf) {
		rdsv3_buf_sptr = rdsv3_debug_buf;
		rdsv3_buf_eptr = rdsv3_debug_buf + rdsv3_debug_buf_size -
		    RDSV3_DEBUG_SIZE_EXTRA_ALLOC;

		bzero(rdsv3_debug_buf, rdsv3_debug_buf_size);
	}
}


static void
rdsv3_vlog(char *name, uint_t level, char *fmt, va_list ap)
{
	char	*label = (name == NULL) ? "rds" : name;
	char	*msg_ptr;
	size_t	len;

	mutex_enter(&rdsv3_debug_mutex);

	/* if not using logging scheme; quit */
	if (rdsv3_suppress_dprintf || (rdsv3_debug_buf == NULL)) {
		mutex_exit(&rdsv3_debug_mutex);
		return;
	}

	/* If user requests to clear debug buffer, go ahead */
	if (rdsv3_clear_debug_buf_flag != 0) {
		rdsv3_clear_print_buf();
		rdsv3_clear_debug_buf_flag = 0;
	}

	/*
	 * put "label" into the buffer
	 */
	len = snprintf(rdsv3_print_buf, RDSV3_FUNCNAME_LEN, "%s:\t", label);

	msg_ptr = rdsv3_print_buf + len;
	len += vsnprintf(msg_ptr, RDSV3_PRINT_BUF_LEN - len - 2, fmt, ap);

	len = min(len, RDSV3_PRINT_BUF_LEN - 2);
	ASSERT(len == strlen(rdsv3_print_buf));
	rdsv3_print_buf[len++] = '\n';
	rdsv3_print_buf[len] = '\0';

	/*
	 * stuff the message in the debug buf
	 */
	if (rdsv3_buffer_dprintf) {

		/*
		 * overwrite >>>> that might be over the end of the
		 * the buffer
		 */
		*rdsv3_buf_sptr = '\0';

		if (rdsv3_buf_sptr + len > rdsv3_buf_eptr) {
			size_t left = (uintptr_t)rdsv3_buf_eptr -
			    (uintptr_t)rdsv3_buf_sptr;

			bcopy((caddr_t)rdsv3_print_buf,
			    (caddr_t)rdsv3_buf_sptr, left);
			bcopy((caddr_t)rdsv3_print_buf + left,
			    (caddr_t)rdsv3_debug_buf, len - left);
			rdsv3_buf_sptr = rdsv3_debug_buf + len - left;
		} else {
			bcopy((caddr_t)rdsv3_print_buf, rdsv3_buf_sptr, len);
			rdsv3_buf_sptr += len;
		}

		/* add marker */
		(void) sprintf(rdsv3_buf_sptr, ">>>>");
	}

	/*
	 * LINTR, L5-L2 message may go to the rdsv3_debug_buf
	 * L1 messages will go to the /var/adm/messages (debug & non-debug).
	 * L0 messages will go to console (debug & non-debug).
	 */
	switch (level) {
	case RDSV3_LOG_LINTR:
	case RDSV3_LOG_L5:
	case RDSV3_LOG_L4:
	case RDSV3_LOG_L3:
	case RDSV3_LOG_L2:
		if (!rdsv3_buffer_dprintf) {
			cmn_err(CE_CONT, "^%s", rdsv3_print_buf);
		}
		break;
	case RDSV3_LOG_L1:
		if (!rdsv3_buffer_dprintf) {
			cmn_err(CE_CONT, "^%s", rdsv3_print_buf);
		} else {
			/* go to messages file */
			cmn_err(CE_CONT, "!%s", rdsv3_print_buf);
		}
		break;
	case RDSV3_LOG_L0:
		/* Strip the "\n" added earlier */
		if (rdsv3_print_buf[len - 1] == '\n') {
			rdsv3_print_buf[len - 1] = '\0';
		}
		if (msg_ptr[len - 1] == '\n') {
			msg_ptr[len - 1] = '\0';
		}
		/* go to console */
		cmn_err(CE_CONT, "^%s", rdsv3_print_buf);
		break;
	}

	mutex_exit(&rdsv3_debug_mutex);
}

void
rdsv3_dprintf_intr(char *name, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rdsv3_vlog(name, RDSV3_LOG_LINTR, fmt, ap);
	va_end(ap);
}

/*
 * Check individual subsystem err levels
 */
#define	RDSV3_CHECK_ERR_LEVEL(level)		\
	if (rdsv3dbglvl < level)		\
		return;				\

void
rdsv3_dprintf5(char *name, char *fmt, ...)
{
	va_list ap;

	RDSV3_CHECK_ERR_LEVEL(RDSV3_LOG_L5);

	va_start(ap, fmt);
	rdsv3_vlog(name, RDSV3_LOG_L5, fmt, ap);
	va_end(ap);
}

void
rdsv3_dprintf4(char *name, char *fmt, ...)
{
	va_list ap;

	RDSV3_CHECK_ERR_LEVEL(RDSV3_LOG_L4);

	va_start(ap, fmt);
	rdsv3_vlog(name, RDSV3_LOG_L4, fmt, ap);
	va_end(ap);
}

void
rdsv3_dprintf3(char *name, char *fmt, ...)
{
	va_list ap;

	RDSV3_CHECK_ERR_LEVEL(RDSV3_LOG_L3);

	va_start(ap, fmt);
	rdsv3_vlog(name, RDSV3_LOG_L3, fmt, ap);
	va_end(ap);
}

void
rdsv3_dprintf2(char *name, char *fmt, ...)
{
	va_list ap;

	RDSV3_CHECK_ERR_LEVEL(RDSV3_LOG_L2);

	va_start(ap, fmt);
	rdsv3_vlog(name, RDSV3_LOG_L2, fmt, ap);
	va_end(ap);
}

void
rdsv3_dprintf1(char *name, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rdsv3_vlog(name, RDSV3_LOG_L1, fmt, ap);
	va_end(ap);
}


/*
 * Function:
 *      rdsv3_dprintf0
 * Input:
 *      name	- Name of the function generating the debug message
 *  	fmt	- The message to be displayed.
 * Output:
 *      none
 * Returns:
 *      none
 * Description:
 *  	A generic log function to display RDS debug messages.
 */
void
rdsv3_dprintf0(char *name, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rdsv3_vlog(name, RDSV3_LOG_L0, fmt, ap);
	va_end(ap);
}

/* For ofed rdstrace */
void
rdsv3_trace(char *name, uint8_t lvl, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rdsv3_vlog(name, lvl, fmt, ap);
	va_end(ap);
}

#define	DEFAULT_RATELIMIT_INTERVAL	5
#define	DEFAULT_RATELIMIT_BURST	10

struct ratelimit_state {
	clock_t interval;
	int burst;
	int printed;
	int missed;
	hrtime_t begin;
	kmutex_t lock;
};

#define	DEFINE_RATELIMIT_STATE(name, interval, burst)		\
	static struct ratelimit_state name = {interval, burst, }

DEFINE_RATELIMIT_STATE(rdsv3_printk_ratelimit_state,
    DEFAULT_RATELIMIT_INTERVAL,
    DEFAULT_RATELIMIT_BURST);

int
rdsv3_printk_ratelimit(void)
{
	struct ratelimit_state *rs = &rdsv3_printk_ratelimit_state;
	hrtime_t current = gethrtime();
	int rtn = 0;

	if (rs->interval) {
		return (1);
	}
	mutex_enter(&rs->lock);
	if (!rs->begin) {
		rs->begin = current;
	}
	if (current < rs->begin + TICK_TO_NSEC(rs->interval)) {
		if (rs->missed) {
			RDSV3_DPRINTF0("rdsv3_printk_ratelimit: ",
			    "%d callbacks suppressed\n", rs->missed);
			rs->begin = 0;
			rs->printed = 0;
			rs->missed = 0;
		}
	}
	if (rs->burst && rs->burst > rs->printed) {
		rs->printed++;
		rtn = 1;
	} else {
		rs->missed++;
	}
	mutex_exit(&rs->lock);
	return (rtn);
}
