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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ib/clients/rds/rdsib_debug.h>

/*
 * This file contains the debug defines and routines.
 * Debugging information is collected in a circular kernel buffer. Debug
 * messages with level lower than rdsdbglvl are ignored. The size of the
 * of the debug buffer can be changed by setting 'rds_debug_buf_size' in
 * bytes in /etc/system.
 *
 * The debug buffer can be cleared by setting 'rds_clear_debug_buf_flag = 1'
 * on a running system.
 */

#define	RDS_DEBUG_SIZE_EXTRA_ALLOC	8
#define	RDS_MIN_DEBUG_BUF_SIZE		0x1000
#define	RDS_FUNCNAME_LEN		40
#define	RDS_PRINTBUF_LEN		4096
#ifdef	DEBUG
#define	RDS_DEBUG_BUF_SIZE		0x10000
#else
#define	RDS_DEBUG_BUF_SIZE		0x2000
#endif	/* DEBUG */

/* Max length of a debug statement */
#define	RDS_PRINT_BUF_LEN	4096

int	rds_suppress_dprintf;		/* Suppress debug printing */
int	rds_buffer_dprintf = 1;		/* Use debug buffer (0 == console) */
int	rds_debug_buf_size = RDS_DEBUG_BUF_SIZE; /* Sz of Debug buf */
int	rds_allow_intr_msgs = 0;	/* log "intr" messages */
char	*rds_debug_buf = NULL;		/* The Debug Buf */
char	*rds_buf_sptr, *rds_buf_eptr;	/* debug buffer temp pointer */
int	rds_clear_debug_buf_flag = 0;	/* Clear debug buffer */
extern uint_t	rdsdbglvl;

/*
 * Print Buffer protected by mutex for debug stuff. The mutex also
 * ensures serializing debug messages.
 */
static kmutex_t	rds_debug_mutex;
static char	rds_print_buf[RDS_PRINT_BUF_LEN];

/* Function Prototypes */
static void	rds_clear_print_buf();

/* RDS logging init */
void
rds_logging_initialization()
{
	boolean_t flag = B_FALSE;

	mutex_init(&rds_debug_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&rds_debug_mutex);

	if (rds_debug_buf_size <= RDS_DEBUG_SIZE_EXTRA_ALLOC) {
		rds_debug_buf_size = RDS_MIN_DEBUG_BUF_SIZE;
		flag = B_TRUE;
	}

	/* if it is less that RDS_MIN_DEBUG_BUF_SIZE, adjust it */
	rds_debug_buf_size = max(RDS_MIN_DEBUG_BUF_SIZE,
	    rds_debug_buf_size);

	rds_debug_buf = (char *)kmem_alloc(rds_debug_buf_size, KM_SLEEP);
	rds_clear_print_buf();
	mutex_exit(&rds_debug_mutex);

	if (flag == B_TRUE) {
		RDS_DPRINTF2("RDS", "rds_debug_buf_size was too small, "
		    "adjusted to %x", rds_debug_buf_size);
	}
}


/* RDS logging destroy */
void
rds_logging_destroy()
{
	mutex_enter(&rds_debug_mutex);
	if (rds_debug_buf) {
		kmem_free(rds_debug_buf, rds_debug_buf_size);
		rds_debug_buf = NULL;
	}
	mutex_exit(&rds_debug_mutex);
	mutex_destroy(&rds_debug_mutex);
}


/*
 * debug, log, and console message handling
 */

/*
 * clear the RDS debug buffer
 */
static void
rds_clear_print_buf()
{
	ASSERT(MUTEX_HELD(&rds_debug_mutex));
	if (rds_debug_buf) {
		rds_buf_sptr = rds_debug_buf;
		rds_buf_eptr = rds_debug_buf + rds_debug_buf_size -
		    RDS_DEBUG_SIZE_EXTRA_ALLOC;

		bzero(rds_debug_buf, rds_debug_buf_size);
	}
}


static void
rds_vlog(char *name, uint_t level, char *fmt, va_list ap)
{
	char	*label = (name == NULL) ? "rds" : name;
	char	*msg_ptr;
	size_t	len;

	mutex_enter(&rds_debug_mutex);

	/* if not using logging scheme; quit */
	if (rds_suppress_dprintf || (rds_debug_buf == NULL)) {
		mutex_exit(&rds_debug_mutex);
		return;
	}

	/* If user requests to clear debug buffer, go ahead */
	if (rds_clear_debug_buf_flag != 0) {
		rds_clear_print_buf();
		rds_clear_debug_buf_flag = 0;
	}

	/*
	 * put "label" into the buffer
	 */
	len = snprintf(rds_print_buf, RDS_FUNCNAME_LEN, "%s:\t", label);

	msg_ptr = rds_print_buf + len;
	len += vsnprintf(msg_ptr, RDS_PRINT_BUF_LEN - len - 2, fmt, ap);

	len = min(len, RDS_PRINT_BUF_LEN - 2);
	ASSERT(len == strlen(rds_print_buf));
	rds_print_buf[len++] = '\n';
	rds_print_buf[len] = '\0';

	/*
	 * stuff the message in the debug buf
	 */
	if (rds_buffer_dprintf) {

		/*
		 * overwrite >>>> that might be over the end of the
		 * the buffer
		 */
		*rds_buf_sptr = '\0';

		if (rds_buf_sptr + len > rds_buf_eptr) {
			size_t left = (uintptr_t)rds_buf_eptr -
			    (uintptr_t)rds_buf_sptr;

			bcopy((caddr_t)rds_print_buf,
			    (caddr_t)rds_buf_sptr, left);
			bcopy((caddr_t)rds_print_buf + left,
			    (caddr_t)rds_debug_buf, len - left);
			rds_buf_sptr = rds_debug_buf + len - left;
		} else {
			bcopy((caddr_t)rds_print_buf, rds_buf_sptr, len);
			rds_buf_sptr += len;
		}

		/* add marker */
		(void) sprintf(rds_buf_sptr, ">>>>");
	}

	/*
	 * LINTR, L5-L2 message may go to the rds_debug_buf
	 * L1 messages will go to the /var/adm/messages (debug & non-debug).
	 * L0 messages will go to console (debug & non-debug).
	 */
	switch (level) {
	case RDS_LOG_LINTR:
	case RDS_LOG_L5:
	case RDS_LOG_L4:
	case RDS_LOG_L3:
	case RDS_LOG_L2:
		if (!rds_buffer_dprintf) {
			cmn_err(CE_CONT, "^%s", rds_print_buf);
		}
		break;
	case RDS_LOG_L1:
		if (!rds_buffer_dprintf) {
			cmn_err(CE_CONT, "^%s", rds_print_buf);
		} else {
			/* go to messages file */
			cmn_err(CE_CONT, "!%s", rds_print_buf);
		}
		break;
	case RDS_LOG_L0:
		/* Strip the "\n" added earlier */
		if (rds_print_buf[len - 1] == '\n') {
			rds_print_buf[len - 1] = '\0';
		}
		if (msg_ptr[len - 1] == '\n') {
			msg_ptr[len - 1] = '\0';
		}
		/* go to console */
		cmn_err(CE_CONT, "^%s", rds_print_buf);
		break;
	}

	mutex_exit(&rds_debug_mutex);
}

void
rds_dprintf_intr(char *name, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rds_vlog(name, RDS_LOG_LINTR, fmt, ap);
	va_end(ap);
}

/*
 * Check individual subsystem err levels
 */
#define	RDS_CHECK_ERR_LEVEL(level)		\
	if (rdsdbglvl < level)			\
		return;				\

void
rds_dprintf5(char *name, char *fmt, ...)
{
	va_list ap;

	RDS_CHECK_ERR_LEVEL(RDS_LOG_L5);

	va_start(ap, fmt);
	rds_vlog(name, RDS_LOG_L5, fmt, ap);
	va_end(ap);
}

void
rds_dprintf4(char *name, char *fmt, ...)
{
	va_list ap;

	RDS_CHECK_ERR_LEVEL(RDS_LOG_L4);

	va_start(ap, fmt);
	rds_vlog(name, RDS_LOG_L4, fmt, ap);
	va_end(ap);
}

void
rds_dprintf3(char *name, char *fmt, ...)
{
	va_list ap;

	RDS_CHECK_ERR_LEVEL(RDS_LOG_L3);

	va_start(ap, fmt);
	rds_vlog(name, RDS_LOG_L3, fmt, ap);
	va_end(ap);
}

void
rds_dprintf2(char *name, char *fmt, ...)
{
	va_list ap;

	RDS_CHECK_ERR_LEVEL(RDS_LOG_L2);

	va_start(ap, fmt);
	rds_vlog(name, RDS_LOG_L2, fmt, ap);
	va_end(ap);
}

void
rds_dprintf1(char *name, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rds_vlog(name, RDS_LOG_L1, fmt, ap);
	va_end(ap);
}


/*
 * Function:
 *      rds_dprintf0
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
rds_dprintf0(char *name, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rds_vlog(name, RDS_LOG_L0, fmt, ap);
	va_end(ap);
}
