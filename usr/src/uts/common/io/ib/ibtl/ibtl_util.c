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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ibtf_util.c
 *
 * This file contains the IBTF module's helper/utility functions.
 * - IBTF logging support
 */

#include <sys/ib/ibtl/impl/ibtl.h>

static char ibtf_util[] = "ibtl_util";

/* Function Prototypes */
static void	ibtf_clear_print_buf();

/*
 * Print Buffer protected by mutex for debug stuff. The mutex also
 * ensures serializing debug messages.
 */
static kmutex_t	ibtf_print_mutex;
static char	ibtf_print_buf[IBTL_PRINT_BUF_LEN];

/*
 * Debug Stuff.
 */
uint_t	ibtf_errlevel = IBTF_LOG_L5;
uint_t	ibgen_errlevel = IBTF_LOG_L2;
uint_t	ibtl_errlevel = IBTF_LOG_L2;
uint_t	ibcm_errlevel = IBTF_LOG_L2;
uint_t	ibdm_errlevel = IBTF_LOG_L2;
uint_t	ibnex_errlevel = IBTF_LOG_L2;

#define	IBTF_DEBUG_SIZE_EXTRA_ALLOC	8
#define	IBTF_MIN_DEBUG_BUF_SIZE		0x1000
#ifdef	DEBUG
#define	IBTF_DEBUG_BUF_SIZE		0x10000
#else
#define	IBTF_DEBUG_BUF_SIZE		0x2000
#endif	/* DEBUG */

int	ibtf_suppress_dprintf;		/* Suppress debug printing */
int	ibtf_buffer_dprintf = 1;	/* Use a debug print buffer */
int	ibtf_debug_buf_size = IBTF_DEBUG_BUF_SIZE; /* Sz of Debug buf */
int	ibtf_allow_intr_msgs = 0;	/* log "intr" messages */
char	*ibtf_debug_buf = NULL;		/* The Debug Buf */
char	*ibtf_buf_sptr, *ibtf_buf_eptr;	/* debug buffer temp pointer */
int	ibtf_clear_debug_buf_flag = 0;	/* Clear debug buffer */
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", ibtf_debug_buf_size))

longlong_t ibtl_ib2usec_tbl[64];	/* time conversion table */
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", ibtl_ib2usec_tbl))

_NOTE(MUTEX_PROTECTS_DATA(ibtf_print_mutex, ibtf_buf_sptr ibtf_buf_eptr))

/*
 * Function:
 *	ibtl_ib2usec_init
 * Input:
 *	none
 * Output:
 *	none
 * Returns:
 *	none
 * Description:
 *	Initialize ibtl_ib2usec_tbl[64] for use by ibt_usec2ib and ibt_ib2usec.
 */
void
ibtl_ib2usec_init(void)
{
	int i;

	for (i = 0; i < 64; i++) {
		if (i < 51) {		/* shift first to avoid underflow */
			ibtl_ib2usec_tbl[i] = ((1LL << i) << 12LL) / 1000LL;
		} else if (i < 61) {	/* divide first to avoid overflow */
			ibtl_ib2usec_tbl[i] = ((1LL << i) / 1000LL) << 12LL;
		} else {		/* max'ed out, so use MAX LONGLONG */
			ibtl_ib2usec_tbl[i] = 0x7FFFFFFFFFFFFFFFLL;
		}
#if !defined(_LP64)
		if (ibtl_ib2usec_tbl[i] > LONG_MAX)
			ibtl_ib2usec_tbl[i] = LONG_MAX;
#endif
	}
}

/*
 * Function:
 *      ibt_usec2ib
 * Input:
 *      time_val - Time in microsecs.
 * Output:
 *      none
 * Returns:
 *      Nearest IB Timeout Exponent value.
 * Description:
 *      This function converts the standard input time in microseconds to
 *      IB's 6 bits of timeout exponent, calculated based on
 *      time = 4.096us * 2 ^ exp.  This is done by searching through
 *	the ibtl_ib2usec_tbl for the closest value >= time_val.
 */
ib_time_t
ibt_usec2ib(clock_t time_val)
{
	int i;

	IBTF_DPRINTF_L3(ibtf_util, "ibt_usec2ib(%ld)", time_val);

	/* First, leap through the table by 4 entries at a time */
	for (i = 0; (i + 4) < 64 && ibtl_ib2usec_tbl[i + 4] < time_val; i += 4)
		;
	/* Find the return value; it's now between i and i + 4, inclusive */
	while (ibtl_ib2usec_tbl[i] < time_val)
		i++;
	return (i);
}


/*
 * Function:
 *      ibt_ib2usec
 * Input:
 *      ib_time    - IB Timeout Exponent value.
 * Output:
 *      none
 * Returns:
 *      Standard Time is microseconds.
 * Description:
 *      This function converts the input IB timeout exponent (6 bits) to
 *      standard time in microseconds, calculated based on
 *	time = 4.096us * 2 ^ exp.
 *	This is implemented as a simple index into ibtl_ib2usec_tbl[].
 */
clock_t
ibt_ib2usec(ib_time_t ib_time)
{
	IBTF_DPRINTF_L3(ibtf_util, "ibt_ib2usec(%d)", ib_time);

	return ((clock_t)ibtl_ib2usec_tbl[ib_time & IB_TIME_EXP_MASK]);
}


/* IBTF logging init */
void
ibtl_logging_initialization()
{
	boolean_t flag = B_FALSE;

	IBTF_DPRINTF_L3(ibtf_util, "ibtl_logging_initialization:");

	mutex_init(&ibtf_print_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&ibtf_print_mutex);

	if (ibtf_debug_buf_size <= IBTF_DEBUG_SIZE_EXTRA_ALLOC) {
		ibtf_debug_buf_size = IBTF_MIN_DEBUG_BUF_SIZE;
		flag = B_TRUE;
	}

	/* if it is less that IBTF_MIN_DEBUG_BUF_SIZE, adjust it */
	ibtf_debug_buf_size = max(IBTF_MIN_DEBUG_BUF_SIZE,
	    ibtf_debug_buf_size);

	ibtf_debug_buf = (char *)kmem_alloc(ibtf_debug_buf_size, KM_SLEEP);
	ibtf_clear_print_buf();
	mutex_exit(&ibtf_print_mutex);

	if (flag == B_TRUE) {
		IBTF_DPRINTF_L2(ibtf_util, "ibtf_debug_buf_size was too small "
		    "%x, adjusted to %x", ibtf_debug_buf_size,
		    IBTF_MIN_DEBUG_BUF_SIZE);
	}
}


/* IBTF logging destroy */
void
ibtl_logging_destroy()
{
	IBTF_DPRINTF_L3(ibtf_util, "ibtl_logging_destroy");

	mutex_enter(&ibtf_print_mutex);
	if (ibtf_debug_buf) {
		kmem_free(ibtf_debug_buf, ibtf_debug_buf_size);
		ibtf_debug_buf = NULL;
	}
	mutex_exit(&ibtf_print_mutex);
	mutex_destroy(&ibtf_print_mutex);
}


/*
 * debug, log, and console message handling
 */

/*
 * clear the IBTF trace buffer
 */
static void
ibtf_clear_print_buf()
{
	ASSERT(MUTEX_HELD(&ibtf_print_mutex));
	if (ibtf_debug_buf) {
		ibtf_buf_sptr = ibtf_debug_buf;
		ibtf_buf_eptr = ibtf_debug_buf + ibtf_debug_buf_size -
		    IBTF_DEBUG_SIZE_EXTRA_ALLOC;

		bzero(ibtf_debug_buf, ibtf_debug_buf_size);
	}
}


static void
ibtf_vlog(char *name, uint_t level, char *fmt, va_list ap)
{
	char	*label = (name == NULL) ? "ibtl" : name;
	char	*msg_ptr;
	size_t	len;

	mutex_enter(&ibtf_print_mutex);

	/* if not using logging scheme; quit */
	if (ibtf_suppress_dprintf || (ibtf_debug_buf == NULL)) {
		mutex_exit(&ibtf_print_mutex);
		return;
	}

	/* if level doesn't match, we are done */
	if ((level < IBTF_LOG_L0) || (level > IBTF_LOG_LINTR)) {
		mutex_exit(&ibtf_print_mutex);
		return;
	}

	/* If user requests to clear debug buffer, go ahead */
	if (ibtf_clear_debug_buf_flag != 0) {
		ibtf_clear_print_buf();
		ibtf_clear_debug_buf_flag = 0;
	}

	/*
	 * Check if we have a valid buf size?
	 * Suppress logging to ibtf_buffer if so.
	 */
	if (ibtf_debug_buf_size <= 0) {
		ibtf_buffer_dprintf = 0;
	}

	/*
	 * put "label" into the buffer
	 */
	len = snprintf(ibtf_print_buf, IBTL_DRVNAME_LEN, "%s:\t", label);

	msg_ptr = ibtf_print_buf + len;
	len += vsnprintf(msg_ptr, IBTL_PRINT_BUF_LEN - len - 2, fmt, ap);

	len = min(len, IBTL_PRINT_BUF_LEN - 2);
	ASSERT(len == strlen(ibtf_print_buf));
	ibtf_print_buf[len++] = '\n';
	ibtf_print_buf[len] = '\0';

	/*
	 * stuff the message in the debug buf
	 */
	if (ibtf_buffer_dprintf) {

		/*
		 * overwrite >>>> that might be over the end of the
		 * the buffer
		 */
		*ibtf_buf_sptr = '\0';

		if (ibtf_buf_sptr + len > ibtf_buf_eptr) {
			size_t left = ibtf_buf_eptr - ibtf_buf_sptr;

			bcopy((caddr_t)ibtf_print_buf,
			    (caddr_t)ibtf_buf_sptr, left);
			bcopy((caddr_t)ibtf_print_buf + left,
			    (caddr_t)ibtf_debug_buf, len - left);
			ibtf_buf_sptr = ibtf_debug_buf + len - left;
		} else {
			bcopy((caddr_t)ibtf_print_buf, ibtf_buf_sptr, len);
			ibtf_buf_sptr += len;
		}

		/* add marker */
		(void) sprintf(ibtf_buf_sptr, ">>>>");
	}

	/*
	 * LINTR, L5-L2 message may go to the ibtf_debug_buf
	 * L1 messages will go to the log buf in non-debug kernels and
	 * to console and log buf in debug kernels
	 * L0 messages are warnings and will go to console and log buf
	 */
	switch (level) {
	case IBTF_LOG_LINTR:
	case IBTF_LOG_L5:
	case IBTF_LOG_L4:
	case IBTF_LOG_L3:
	case IBTF_LOG_L2:
		if (!ibtf_buffer_dprintf) {
			cmn_err(CE_CONT, "^%s", ibtf_print_buf);
		}
		break;
	case IBTF_LOG_L1:
#ifdef DEBUG
		cmn_err(CE_CONT, "%s", ibtf_print_buf);
#else
		if (!ibtf_buffer_dprintf) {
			cmn_err(CE_CONT, "^%s", ibtf_print_buf);
		}
#endif
		break;
	case IBTF_LOG_L0:
		/* Strip the "\n" added earlier */
		if (ibtf_print_buf[len - 1] == '\n') {
			ibtf_print_buf[len - 1] = '\0';
		}
		if (msg_ptr[len - 1] == '\n') {
			msg_ptr[len - 1] = '\0';
		}
		cmn_err(CE_WARN, ibtf_print_buf);
		break;
	}

	mutex_exit(&ibtf_print_mutex);
}


void
ibtl_dprintf_intr(char *name, char *fmt, ...)
{
	va_list ap;

	/* only log messages if "ibtf_allow_intr_msgs" is set */
	if (!ibtf_allow_intr_msgs)
		return;

	va_start(ap, fmt);
	ibtf_vlog(name, IBTF_LOG_LINTR, fmt, ap);
	va_end(ap);
}


/*
 * Check individual subsystem err levels
 */
#define	IBTL_CHECK_ERR_LEVEL(level)			\
	if (strncmp(name, "ibgen", 5) == 0) {		\
		if (ibgen_errlevel < level)		\
			return;				\
	} else if (strncmp(name, "ibtl", 4) == 0) {	\
		if (ibtl_errlevel < level)		\
			return;				\
	} else if (strncmp(name, "ibcm", 4) == 0) {	\
		if (ibcm_errlevel < level)		\
			return;				\
	} else if (strncmp(name, "ibdm", 4) == 0) {	\
		if (ibdm_errlevel < level)		\
			return;				\
	} else if (strncmp(name, "ibnex", 5) == 0) {	\
		if (ibnex_errlevel < level)		\
			return;				\
	}

void
ibtl_dprintf5(char *name, char *fmt, ...)
{
	va_list ap;

	/* check if global errlevel matches or not */
	if (ibtf_errlevel < IBTF_LOG_L5)
		return;

	IBTL_CHECK_ERR_LEVEL(IBTF_LOG_L5);

	va_start(ap, fmt);
	ibtf_vlog(name, IBTF_LOG_L5, fmt, ap);
	va_end(ap);
}

void
ibtl_dprintf4(char *name, char *fmt, ...)
{
	va_list ap;

	/* check if global errlevel matches or not */
	if (ibtf_errlevel < IBTF_LOG_L4)
		return;

	IBTL_CHECK_ERR_LEVEL(IBTF_LOG_L4);

	va_start(ap, fmt);
	ibtf_vlog(name, IBTF_LOG_L4, fmt, ap);
	va_end(ap);
}


void
ibtl_dprintf3(char *name, char *fmt, ...)
{
	va_list ap;

	/* check if global errlevel matches or not */
	if (ibtf_errlevel < IBTF_LOG_L3)
		return;

	IBTL_CHECK_ERR_LEVEL(IBTF_LOG_L3);

	va_start(ap, fmt);
	ibtf_vlog(name, IBTF_LOG_L3, fmt, ap);
	va_end(ap);
}


void
ibtl_dprintf2(char *name, char *fmt, ...)
{
	va_list ap;

	/* check if global errlevel matches or not */
	if (ibtf_errlevel < IBTF_LOG_L2)
		return;

	IBTL_CHECK_ERR_LEVEL(IBTF_LOG_L2);

	va_start(ap, fmt);
	ibtf_vlog(name, IBTF_LOG_L2, fmt, ap);
	va_end(ap);
}


void
ibtl_dprintf1(char *name, char *fmt, ...)
{
	va_list ap;

	/* check if global errlevel matches or not */
	if (ibtf_errlevel < IBTF_LOG_L1)
		return;

	va_start(ap, fmt);
	ibtf_vlog(name, IBTF_LOG_L1, fmt, ap);
	va_end(ap);
}


/*
 * Function:
 *      ibtf_dprintf0
 * Input:
 *      name	- Name of the subsystem generating the debug message
 *	fmt	- The message to be displayed.
 * Output:
 *      none
 * Returns:
 *      none
 * Description:
 *	A generic log function to display IBTF debug messages.
 */
void
ibtl_dprintf0(char *name, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ibtf_vlog(name, IBTF_LOG_L0, fmt, ap);
	va_end(ap);
}
