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

/*
 * This file is more or less the same as the Solaris IBTL debug
 * implementation. The debug functions and conf variables are
 * similar. One significant change is :
 * 	sol_ofs_supress_above_l2
 * This has to be set to 0, in /etc/system to enable debug prints
 * above level 2.
 */
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ib/clients/of/sol_ofs/sol_ofs_common.h>

#define	SOL_OFS_PRINT_BUF_LEN		4096
#define	SOL_OFS_DEBUG_BUF_SIZE		0x10000
#define	SOL_OFS_DEBUG_EXTRA_SIZE	8
#define	SOL_OFS_LOG_L5			5
#define	SOL_OFS_LOG_L4			4
#define	SOL_OFS_LOG_L3			3
#define	SOL_OFS_LOG_L2			2
#define	SOL_OFS_LOG_L1			1
#define	SOL_OFS_LOG_L0			0

static kmutex_t	sol_ofs_debug_mutex;
static char	sol_ofs_print_buf[SOL_OFS_PRINT_BUF_LEN];
static char	*sol_ofs_debug_sptr = NULL;
static char	*sol_ofs_debug_eptr = NULL;

char	*sol_ofs_debug_buf = NULL;
int	sol_ofs_clear_debug_buf_flag = 0;
int	sol_ofs_debug_buf_size = SOL_OFS_DEBUG_BUF_SIZE;
int	sol_ofs_suppress_dprintf = 0;
int	sol_ofs_buffer_dprintf = 1;
int	sol_ofs_supress_above_l2 = 1;

int	sol_ucma_errlevel = 2;		/* sol_ucma driver */
int	sol_uverbs_errlevel = 2;	/* sol_uverbs driver */
int	sol_umad_errlevel = 2;		/* sol_umad driver */

int	sol_rdmacm_errlevel = 2;	/* rdmacm part of sol_ofs */
int	sol_kverbs_errlevel = 2;	/* kverbs part of sol_ofs */
/* sol_ofs module (except rdmacm and kverbs) */
int	sol_ofs_module_errlevel = 2;

/* Global error levels for all OF related modules */
int	sol_of_errlevel = 2;

static void
sol_ofs_clear_dbg_buf()
{
	ASSERT(MUTEX_HELD(&sol_ofs_debug_mutex));
	if (sol_ofs_debug_buf) {
		sol_ofs_debug_sptr = sol_ofs_debug_buf;
		sol_ofs_debug_eptr = sol_ofs_debug_buf +
		    sol_ofs_debug_buf_size - SOL_OFS_DEBUG_EXTRA_SIZE;
		bzero(sol_ofs_debug_sptr, sol_ofs_debug_buf_size);
	}
}

/*
 * sol_ofs_dprintf_init() and sol_ofs_dprintf_fini() must be called
 * from the _init of the sol_ofs module.
 */
void
sol_ofs_dprintf_init()
{
	char	*dbg_buf;

	mutex_init(&sol_ofs_debug_mutex, NULL, MUTEX_DRIVER, NULL);

	if (sol_ofs_debug_buf_size < SOL_OFS_DEBUG_EXTRA_SIZE) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "sol_ofs:\t debug buf size 0x%x too small, "
		    "setting to 0x%x", sol_ofs_debug_buf_size,
		    SOL_OFS_DEBUG_BUF_SIZE);
#endif
		sol_ofs_debug_buf_size = SOL_OFS_DEBUG_BUF_SIZE;
	}

	dbg_buf = kmem_zalloc(sol_ofs_debug_buf_size, KM_SLEEP);
	mutex_enter(&sol_ofs_debug_mutex);
	sol_ofs_debug_buf = dbg_buf;
	sol_ofs_clear_dbg_buf();
	mutex_exit(&sol_ofs_debug_mutex);
}

void
sol_ofs_dprintf_fini()
{
	char	*dbg_buf;

	mutex_enter(&sol_ofs_debug_mutex);
	dbg_buf = sol_ofs_debug_buf;
	sol_ofs_debug_buf = NULL;
	mutex_exit(&sol_ofs_debug_mutex);

	kmem_free(dbg_buf, sol_ofs_debug_buf_size);
	mutex_destroy(&sol_ofs_debug_mutex);
}

static void
sol_ofs_dprintf_vlog(char *name, uint_t level, char *fmt, va_list ap)
{
	char	*label = (name == NULL) ? "sol_ofs_ulp" : name;
	char	*msg_ptr;
	size_t	len;

	mutex_enter(&sol_ofs_debug_mutex);
	/* if not using logging scheme; quit */
	if (sol_ofs_suppress_dprintf || (sol_ofs_debug_buf == NULL)) {
		mutex_exit(&sol_ofs_debug_mutex);
		return;
	}
	/* if level doesn't match, we are done */
	if (level > SOL_OFS_LOG_L5) {
		mutex_exit(&sol_ofs_debug_mutex);
		return;
	}

	/* If user requests to clear debug buffer, go ahead */
	if (sol_ofs_clear_debug_buf_flag) {
		sol_ofs_clear_dbg_buf();
		sol_ofs_clear_debug_buf_flag = 0;
	}

	/* Skip printing to buffer, if too small */
	if (sol_ofs_debug_buf_size <= 0) {
		sol_ofs_buffer_dprintf = 0;
	}

	/* Put label and debug info into buffer */
	len = snprintf((char *)sol_ofs_print_buf, SOL_OFS_DRV_NAME_LEN,
	    "%s:\t", label);
	msg_ptr = (char *)sol_ofs_print_buf + len;
	len += vsnprintf(msg_ptr, SOL_OFS_PRINT_BUF_LEN - len - 2, fmt, ap);
	len = min(len, SOL_OFS_PRINT_BUF_LEN - 2);
	ASSERT(len == strlen(sol_ofs_print_buf));
	sol_ofs_print_buf[len++] = '\n';
	sol_ofs_print_buf[len] = '\0';

	/* Stuff into debug buffer */
	if (sol_ofs_buffer_dprintf) {
		/*
		 * overwrite >>>> that might be over the end of the
		 * buffer.
		 */
		*sol_ofs_debug_sptr = '\0';

		if (sol_ofs_debug_sptr + len > sol_ofs_debug_eptr) {
			size_t left;

			left = sol_ofs_debug_eptr - sol_ofs_debug_sptr;
			bcopy((caddr_t)sol_ofs_print_buf,
			    (caddr_t)sol_ofs_debug_sptr, left);
			bcopy((caddr_t)sol_ofs_print_buf + left,
			    (caddr_t)sol_ofs_debug_buf, len - left);
			sol_ofs_debug_sptr = sol_ofs_debug_buf + len - left;
		} else {
			bcopy((caddr_t)sol_ofs_print_buf,
			    (caddr_t)sol_ofs_debug_sptr, len);
			sol_ofs_debug_sptr += len;
		}
	}

	/*
	 * L5-L2 message may go to the sol_ofs_debug_buf
	 * L1 messages will go to the log buf in non-debug kernels and
	 * to console and log buf in debug kernels
	 * L0 messages are warnings and will go to console and log buf
	 */
	switch (level) {
	case SOL_OFS_LOG_L5:
	case SOL_OFS_LOG_L4:
	case SOL_OFS_LOG_L3:
	case SOL_OFS_LOG_L2:
		if (!sol_ofs_buffer_dprintf) {
			cmn_err(CE_CONT, "^%s", sol_ofs_print_buf);
		}
		break;
	case SOL_OFS_LOG_L1 :
#ifdef	DEBUG
		cmn_err(CE_CONT, "%s", sol_ofs_print_buf);
#else
		if (!sol_ofs_buffer_dprintf) {
			cmn_err(CE_CONT, "^%s", sol_ofs_print_buf);
		}
#endif
		break;
	case SOL_OFS_LOG_L0 :
		/* Strip the "\n" added earlier */
		if (sol_ofs_print_buf[len - 1] == '\n') {
			sol_ofs_print_buf[len - 1] = '\0';
		}
		if (msg_ptr[len - 1] == '\n') {
			msg_ptr[len - 1] = '\0';
		}
		cmn_err(CE_WARN, sol_ofs_print_buf);
		break;
	}

	mutex_exit(&sol_ofs_debug_mutex);
}

/* Check individual error levels */
#define	SOL_OFS_CHECK_ERR_LEVEL(level)			\
	if (!(uint_t)strncmp(name, "sol_ucma", 8)) {	\
		if (sol_ucma_errlevel < level)		\
			return;				\
	} else if (!(uint_t)strncmp(name, "sol_rdmacm", 10)) {	\
		if (sol_rdmacm_errlevel < level)	\
			return;				\
	} else if (!(uint_t)strncmp(name, "sol_uverbs", 10)) {	\
		if (sol_uverbs_errlevel < level)	\
			return;				\
	} else if (!(uint_t)strncmp(name, "sol_umad", 8)) {	\
		if (sol_umad_errlevel < level)		\
			return;				\
	} else if (!(uint_t)strncmp(name, "sol_ofs_mod", 12)) {	\
		if (sol_ofs_module_errlevel < level)	\
			return;				\
	} else if (strncmp(name, "sol_kverbs", 10) == 0) {	\
		if (sol_kverbs_errlevel < level)		\
			return;				\
	} else if (sol_of_errlevel < level)		\
		return;

void
sol_ofs_dprintf_l5(char *name, char *fmt, ...)
{
	va_list	ap;

	if (sol_ofs_supress_above_l2)
		return;
	SOL_OFS_CHECK_ERR_LEVEL(SOL_OFS_LOG_L5);

	va_start(ap, fmt);
	sol_ofs_dprintf_vlog(name, SOL_OFS_LOG_L5, fmt, ap);
	va_end(ap);
}

void
sol_ofs_dprintf_l4(char *name, char *fmt, ...)
{
	va_list	ap;

	if (sol_ofs_supress_above_l2)
		return;
	SOL_OFS_CHECK_ERR_LEVEL(SOL_OFS_LOG_L4);

	va_start(ap, fmt);
	sol_ofs_dprintf_vlog(name, SOL_OFS_LOG_L4, fmt, ap);
	va_end(ap);
}

void
sol_ofs_dprintf_l3(char *name, char *fmt, ...)
{
	va_list	ap;

	if (sol_ofs_supress_above_l2)
		return;
	SOL_OFS_CHECK_ERR_LEVEL(SOL_OFS_LOG_L3);

	va_start(ap, fmt);
	sol_ofs_dprintf_vlog(name, SOL_OFS_LOG_L3, fmt, ap);
	va_end(ap);
}

void
sol_ofs_dprintf_l2(char *name, char *fmt, ...)
{
	va_list	ap;

	SOL_OFS_CHECK_ERR_LEVEL(SOL_OFS_LOG_L2);

	va_start(ap, fmt);
	sol_ofs_dprintf_vlog(name, SOL_OFS_LOG_L2, fmt, ap);
	va_end(ap);
}

void
sol_ofs_dprintf_l1(char *name, char *fmt, ...)
{
	va_list	ap;

	SOL_OFS_CHECK_ERR_LEVEL(SOL_OFS_LOG_L1);

	va_start(ap, fmt);
	sol_ofs_dprintf_vlog(name, SOL_OFS_LOG_L1, fmt, ap);
	va_end(ap);
}

void
sol_ofs_dprintf_l0(char *name, char *fmt, ...)
{
	va_list	ap;

	if (sol_of_errlevel < SOL_OFS_LOG_L0)
		return;

	va_start(ap, fmt);
	sol_ofs_dprintf_vlog(name, SOL_OFS_LOG_L1, fmt, ap);
	va_end(ap);
}
