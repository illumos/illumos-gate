/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1996-1998, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stddef.h>
#include <stdio.h>
#include <sys/param.h>
#include <config_admin.h>
#include <memory.h>
#include <sys/types.h>
#include <time.h>
#include "mema_test.h"

typedef u_longlong_t pbuf_t;

/*
 * Test for stuck-at fault and transitional faults
 *   Algorithm:
 *         for i = 0 to npages
 *              write(0x55)
 *         for npages to 0
 *              read_compare(0x55)
 *              write(0xaa)
 *         for 0 to number of pages
 *              read_compare(0xaa)
 *              write(0x55)
 *              read_compare(0x55)
 *
 * stuck-at fault is detected because each cell have a 1 and a 0 is read
 * transitional fault is detected because after each 0 to 1 and 1 to 0
 * transition the value is check to be sure that the cell is not frozen.
 */

/*
 * The following strings are subject of stderr output and
 * gettext() is not used for them.
 */
static const char err_sum[] = "total error %u\n";
static const char nts_msg[] = "Normal test started\n";
static const char ntf_msg[] = "Normal test finished\n";
static const char qts_msg[] = "Quick test started\n";
static const char qtf_msg[] = "Quick test finished\n";
static const char ets_msg[] = "Extended test started\n";
static const char etf_msg[] = "Extended test finished\n";
static const char m1_msg[] = "    March 1, ";
static const char m2_msg[] = "    March 2, ";
static const char m3_msg[] = "    March 3, ";
static const char m4_msg[] = "    March 4, ";
static const char wr_msg[] = "write. ";
static const char rd_cmp_msg[] = "read/compare. ";
static const char rpt_rd_cmp_msg[] = "repeated read/compare. ";
static const char ml_rd_cmp_msg[] = "mixed line read/compare. ";
static const char ln_rd_cmp_msg[] = "line read/compare. ";
static const char report_msg[] = "%s%s%d%% complete.\n";
static const char pg_header_msg[] = "    Errors at page address: 0x%x.\n";
static const char rd_err_msg[] = "    Error reading page at address: 0x%x.\n";
static const char wr_err_msg[] = "    Error writing page at address: 0x%x.\n";
static const
char mem_err_msg[] = "      Offset: 0x%x, data written/read: 0x%2x/0x%2x.\n";

/*
 * Macros do deal with test conditions.
 */
#define	TEST_END(END_MSG) \
			if ((handle->max_errors != 0) &&\
				(handle->max_errors == total_errors)) {\
				mtest_message(handle, (END_MSG));\
				error_summary(handle, total_errors);\
				SET_CONDITION(handle, cond);\
				return (MTEST_DONE);\
			}

static void
error_summary(mtest_handle_t handle, uint_t total_errors)
{
	char msgbuf[100];

	(void) sprintf(msgbuf, err_sum, total_errors);
	mtest_message(handle, msgbuf);
}


static void
error_print(char *writebuf, char *readbuf, mtest_handle_t handle, long pageno,
	uint_t *total_errorsp)
{
	char msgbuf[100];
	size_t offset;

	(void) sprintf(msgbuf, pg_header_msg, PAGE_SIZE(handle) * pageno);
	mtest_message(handle, msgbuf);

	for (offset = 0; offset < PAGE_SIZE(handle); offset++) {
		if ((handle->max_errors != 0) &&
		    (readbuf[offset] != writebuf[offset]) &&
		    (handle->max_errors == *total_errorsp))
			return;
		else {
			(*total_errorsp)++;
			(void) sprintf(msgbuf, mem_err_msg, offset,
			    writebuf[offset], readbuf[offset]);
			mtest_message(handle, msgbuf);
		}
	}
}

int
memory_test_normal(
	mtest_handle_t handle)
{
	pbuf_t *patternbuf1;
	pbuf_t *patternbuf2;
	pbuf_t *readbuf;
	long npages, pageno;
	struct mtest_error errbuf;
	uint_t total_errors;
	cfga_cond_t cond;
	time_t time_rep;
	char msgbuf[100];

	patternbuf1 = (pbuf_t *)mtest_allocate_page_buf(handle);
	patternbuf2 = (pbuf_t *)mtest_allocate_page_buf(handle);
	readbuf = (pbuf_t *)mtest_allocate_page_buf(handle);
	if (patternbuf1 == NULL || patternbuf2 == NULL || readbuf == NULL) {
		return (MTEST_LIB_ERROR);
	}

	mtest_message(handle, nts_msg);
	npages = BANK_SIZE(handle) / PAGE_SIZE(handle);

	total_errors = 0;
	cond = CFGA_COND_OK;

	(void) memset((void *)patternbuf1, 0x55, PAGE_SIZE(handle));
	(void) memset((void *)patternbuf2, 0xaa, PAGE_SIZE(handle));

	time_rep = time(NULL) + REPORT_SEC;

	for (pageno = 0; pageno < npages; pageno++) {
		if (mtest_write(handle, (void *)patternbuf1, pageno, 0, 0)
		    == -1) {
			(void) sprintf(msgbuf, wr_err_msg, pageno);
			mtest_message(handle, msgbuf);
			return (MTEST_DEV_ERROR);
		}
		if ((time(NULL) >= time_rep) || (pageno == npages - 1) ||
		    (pageno == 0)) {
			(void) sprintf(msgbuf, report_msg, m1_msg, wr_msg,
			    ((pageno + 1) * 100) / npages);
			mtest_message(handle, msgbuf);
			time_rep = time(NULL) + REPORT_SEC;
		}
	}
	for (pageno = npages-1; pageno >= 0; pageno--) {
		if (mtest_read(handle, (void *)readbuf, pageno, 0, 0, &errbuf)
		    == -1) {
			(void) sprintf(msgbuf, rd_err_msg, pageno);
			mtest_message(handle, msgbuf);
			return (MTEST_DEV_ERROR);
		}
		if (errbuf.error_type != MTEST_ERR_NONE) {
			if (errbuf.error_type == MTEST_ERR_CE &&
			    cond != CFGA_COND_FAILED)
				cond = CFGA_COND_FAILING;
			else
				cond = CFGA_COND_FAILED;
			total_errors++;
			/*
			 * Keep going if max errors is 0 or limit not
			 * reached.
			 */
			TEST_END(ntf_msg);
		}
		if (memcmp((void *)patternbuf1, (void *)readbuf,
		    PAGE_SIZE(handle)) != 0) {
			cond = CFGA_COND_FAILED;
			error_print((void *)patternbuf1, (void *)readbuf,
			    handle, pageno, &total_errors);
			TEST_END(ntf_msg);
		}
		if (mtest_write(handle, (void *)patternbuf2, pageno, 0, 0)
		    == -1) {
			(void) sprintf(msgbuf, wr_err_msg, pageno);
			mtest_message(handle, msgbuf);
			return (MTEST_DEV_ERROR);
		}
		if ((time(NULL) >= time_rep) || (pageno == npages - 1) ||
		    (pageno == 0)) {
			(void) sprintf(msgbuf, report_msg, m1_msg, rd_cmp_msg,
			    ((npages - pageno) * 100) / npages);
			mtest_message(handle, msgbuf);
			time_rep = time(NULL) + REPORT_SEC;
		}
	}
	/* March 2 (repeated) */
	for (pageno = 0; pageno < npages; pageno++) {
		if (mtest_read(handle, (void *)readbuf, pageno, 0, 0, &errbuf)
		    == -1) {
			(void) sprintf(msgbuf, rd_err_msg, pageno);
			mtest_message(handle, msgbuf);
			return (MTEST_DEV_ERROR);
		}
		if (errbuf.error_type != MTEST_ERR_NONE) {
			if (errbuf.error_type == MTEST_ERR_CE &&
			    cond != CFGA_COND_FAILED)
				cond = CFGA_COND_FAILING;
			else
				cond = CFGA_COND_FAILED;
			total_errors++;
			TEST_END(ntf_msg);
		}
		if (memcmp((void *)patternbuf2, (void *)readbuf,
		    PAGE_SIZE(handle)) != 0) {
			cond = CFGA_COND_FAILED;
			error_print((void *)patternbuf2, (void *)readbuf,
			    handle, pageno, &total_errors);
			TEST_END(ntf_msg);
		}
		if (mtest_write(handle, (void *)patternbuf1, pageno, 0, 0)
		    == -1) {
			(void) sprintf(msgbuf, wr_err_msg, pageno);
			mtest_message(handle, msgbuf);
			return (MTEST_DEV_ERROR);
		}
		if (mtest_read(handle, (void *)readbuf, pageno, 0, 0, &errbuf)
		    == -1) {
			(void) sprintf(msgbuf, rd_err_msg, pageno);
			mtest_message(handle, msgbuf);
			return (MTEST_DEV_ERROR);
		}
		if (errbuf.error_type != MTEST_ERR_NONE) {
			if (errbuf.error_type == MTEST_ERR_CE &&
			    cond != CFGA_COND_FAILED)
				cond = CFGA_COND_FAILING;
			else
				cond = CFGA_COND_FAILED;
			total_errors++;
			TEST_END(ntf_msg);
		}
		if (memcmp((void *)patternbuf1, (void *)readbuf,
		    PAGE_SIZE(handle)) != 0) {
			cond = CFGA_COND_FAILED;
			error_print((void *)patternbuf1, (void *)readbuf,
			    handle, pageno, &total_errors);
			TEST_END(ntf_msg);
		}
		if ((time(NULL) >= time_rep) || (pageno == npages - 1) ||
		    (pageno == 0)) {
			(void) sprintf(msgbuf, report_msg, m2_msg,
			    rpt_rd_cmp_msg, ((pageno + 1) * 100) / npages);
			mtest_message(handle, msgbuf);
			time_rep = time(NULL) + REPORT_SEC;
		}
	}
	mtest_message(handle, ntf_msg);
	error_summary(handle, total_errors);
	SET_CONDITION(handle, cond);
	return (MTEST_DONE);
}

/* this test look only for stuck-at fault */
int
memory_test_quick(
	mtest_handle_t handle)
{
	pbuf_t *patternbuf1;
	pbuf_t *patternbuf2;
	pbuf_t *readbuf;
	long npages, pageno;
	struct mtest_error errbuf;
	uint_t total_errors;
	cfga_cond_t cond;
	time_t time_rep;
	char msgbuf[100];

	patternbuf1 = (pbuf_t *)mtest_allocate_page_buf(handle);
	patternbuf2 = (pbuf_t *)mtest_allocate_page_buf(handle);
	readbuf = (pbuf_t *)mtest_allocate_page_buf(handle);
	if (patternbuf1 == NULL || patternbuf2 == NULL || readbuf == NULL) {
		return (MTEST_LIB_ERROR);
	}

	mtest_message(handle, qts_msg);
	npages = BANK_SIZE(handle) / PAGE_SIZE(handle);

	total_errors = 0;
	cond = CFGA_COND_OK;

	(void) memset((void *)patternbuf1, 0x55, PAGE_SIZE(handle));
	(void) memset((void *)patternbuf2, 0xaa, PAGE_SIZE(handle));

	time_rep = time(NULL) + REPORT_SEC;

	for (pageno = 0; pageno < npages; pageno++) {
		if (mtest_write(handle, (void *)patternbuf1, pageno, 0, 0)
		    == -1) {
			(void) sprintf(msgbuf, wr_err_msg, pageno);
			mtest_message(handle, msgbuf);
			return (MTEST_DEV_ERROR);
		}
		if ((time(NULL) >= time_rep) || (pageno == npages - 1) ||
		    (pageno == 0)) {
			(void) sprintf(msgbuf, report_msg, m1_msg, wr_msg,
			    ((pageno + 1) * 100) / npages);
			mtest_message(handle, msgbuf);
			time_rep = time(NULL) + REPORT_SEC;
		}
	}

	for (pageno = npages-1; pageno >= 0; pageno--) {
		if (mtest_read(handle, (void *)readbuf, pageno, 0, 0, &errbuf)
		    == -1) {
			(void) sprintf(msgbuf, rd_err_msg, pageno);
			mtest_message(handle, msgbuf);
			return (MTEST_DEV_ERROR);
		}
		if (errbuf.error_type != MTEST_ERR_NONE) {
			if (errbuf.error_type == MTEST_ERR_CE &&
			    cond != CFGA_COND_FAILED)
				cond = CFGA_COND_FAILING;
			else
				cond = CFGA_COND_FAILED;
			total_errors++;
			/*
			 * Keep going if max errors is 0 or limit not
			 * reached.
			 */
			TEST_END(qtf_msg);
		}
		if (memcmp((void *)patternbuf1, (void *)readbuf,
		    PAGE_SIZE(handle)) != 0) {
			cond = CFGA_COND_FAILED;
			error_print((void *)patternbuf1, (void *)readbuf,
			    handle, pageno, &total_errors);
			TEST_END(qtf_msg);
		}
		if (mtest_write(handle, (void *)patternbuf2, pageno, 0, 0)
		    == -1) {
			(void) sprintf(msgbuf, wr_err_msg, pageno);
			mtest_message(handle, msgbuf);
			return (MTEST_DEV_ERROR);
		}
		if ((time(NULL) >= time_rep) || (pageno == npages - 1) ||
		    (pageno == 0)) {
			(void) sprintf(msgbuf, report_msg, m1_msg, rd_cmp_msg,
			    ((npages - pageno) * 100) / npages);
			mtest_message(handle, msgbuf);
			time_rep = time(NULL) + REPORT_SEC;
		}
	}
	/* March 2 */
	for (pageno = 0; pageno < npages; pageno++) {
		if (mtest_read(handle, (void *)readbuf, pageno, 0, 0, &errbuf)
		    == -1) {
			(void) sprintf(msgbuf, rd_err_msg, pageno);
			mtest_message(handle, msgbuf);
			return (MTEST_DEV_ERROR);
		}
		if (errbuf.error_type != MTEST_ERR_NONE) {
			if (errbuf.error_type == MTEST_ERR_CE &&
			    cond != CFGA_COND_FAILED)
				cond = CFGA_COND_FAILING;
			else
				cond = CFGA_COND_FAILED;
			total_errors++;
			TEST_END(qtf_msg);
		}
		if (memcmp((void *)patternbuf2, (void *)readbuf,
		    PAGE_SIZE(handle)) != 0) {
			cond = CFGA_COND_FAILED;
			error_print((void *)patternbuf2, (void *)readbuf,
			    handle, pageno, &total_errors);
			TEST_END(qtf_msg);
		}
		if ((time(NULL) >= time_rep) || (pageno == npages - 1) ||
		    (pageno == 0)) {
			(void) sprintf(msgbuf, report_msg, m2_msg, rd_cmp_msg,
			    ((pageno + 1) * 100) / npages);
			mtest_message(handle, msgbuf);
			time_rep = time(NULL) + REPORT_SEC;
		}
	}
	mtest_message(handle, qtf_msg);
	error_summary(handle, total_errors);
	SET_CONDITION(handle, cond);
	return (MTEST_DONE);
}


/* look for stuck-at, transition, coupling fault: inversion, idempotent */
int
memory_test_extended(
	mtest_handle_t handle)
{
	pbuf_t *patternbuf0, *patternbuf1;
	pbuf_t *readbuf0, *readbuf1, *readbuf2;
	long npages, pageno;
	long line;
	struct mtest_error errbuf;
	uint_t total_errors;
	cfga_cond_t cond;
	time_t time_rep;
	char msgbuf[100];

	patternbuf0 = (pbuf_t *)mtest_allocate_page_buf(handle);
	patternbuf1 = (pbuf_t *)mtest_allocate_page_buf(handle);
	readbuf0 = (pbuf_t *)mtest_allocate_page_buf(handle);
	readbuf1 = (pbuf_t *)mtest_allocate_page_buf(handle);
	readbuf2 = (pbuf_t *)mtest_allocate_page_buf(handle);
	if (patternbuf0 == NULL || patternbuf1 == NULL ||
	    readbuf0 == NULL || readbuf1 == NULL || readbuf2 == NULL) {
		return (MTEST_LIB_ERROR);
	}

	mtest_message(handle, ets_msg);
	npages = BANK_SIZE(handle) / PAGE_SIZE(handle);

	total_errors = 0;
	cond = CFGA_COND_OK;

	(void) memset((void *)patternbuf0, 0x55, PAGE_SIZE(handle));
	(void) memset((void *)patternbuf1, 0xaa, PAGE_SIZE(handle));

	time_rep = time(NULL) + REPORT_SEC;

	for (pageno = 0; pageno < npages; pageno++) {
		if (mtest_write(handle, (void *)patternbuf0, pageno, 0, 0)
		    == -1) {
			(void) sprintf(msgbuf, wr_err_msg, pageno);
			mtest_message(handle, msgbuf);
			return (MTEST_DEV_ERROR);
		}
		if ((time(NULL) >= time_rep) || (pageno == npages - 1) ||
		    (pageno == 0)) {
			(void) sprintf(msgbuf, report_msg, m1_msg, wr_msg,
			    ((pageno + 1) * 100) / npages);
			mtest_message(handle, msgbuf);
			time_rep = time(NULL) + REPORT_SEC;
		}
	}

	/*
	 * Line tests take 5-9 time longer and the reprting interval
	 * should be extended 3-5 times.
	 */

	/* March 1 */
	for (pageno = npages-1; pageno >= 0; pageno--) {
		for (line = (LINES_PER_PAGE(handle) - 1); line >= 0; line--) {
			if (mtest_read(handle, (void *)readbuf0, pageno,
			    line, 1, &errbuf) == -1) {
				(void) sprintf(msgbuf, rd_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
			if (errbuf.error_type != MTEST_ERR_NONE) {
				if (errbuf.error_type == MTEST_ERR_CE &&
				    cond != CFGA_COND_FAILED)
					cond = CFGA_COND_FAILING;
				else
					cond = CFGA_COND_FAILED;
				total_errors++;
				/*
				 * Keep going if max errors is 0 or limit not
				 * reached.
				 */
				TEST_END(ntf_msg);
			}
			if (mtest_write(handle, (void*)patternbuf1, pageno,
			    line, 1) == -1) {
				(void) sprintf(msgbuf, wr_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
			if (mtest_read(handle, (void *)readbuf1, pageno,
			    line, 1, &errbuf) == -1) {
				(void) sprintf(msgbuf, rd_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
			if (errbuf.error_type != MTEST_ERR_NONE) {
				if (errbuf.error_type == MTEST_ERR_CE &&
				    cond != CFGA_COND_FAILED)
					cond = CFGA_COND_FAILING;
				else
					cond = CFGA_COND_FAILED;
				total_errors++;
				TEST_END(ntf_msg);
			}
			if (mtest_write(handle, (void*)patternbuf0, pageno,
			    line, 1) == -1) {
				(void) sprintf(msgbuf, wr_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
			if (mtest_read(handle, (void *)readbuf2, pageno,
			    line, 1, &errbuf) == -1) {
				(void) sprintf(msgbuf, rd_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
			if (errbuf.error_type != MTEST_ERR_NONE) {
				if (errbuf.error_type == MTEST_ERR_CE &&
				    cond != CFGA_COND_FAILED)
					cond = CFGA_COND_FAILING;
				else
					cond = CFGA_COND_FAILED;
				total_errors++;
				TEST_END(ntf_msg);
			}
			if (mtest_write(handle, (void*)patternbuf1, pageno,
			    line, 1) == -1) {
				(void) sprintf(msgbuf, wr_err_msg, pageno);
				return (MTEST_DEV_ERROR);
			}
		}	/* line */
		if (memcmp((void *)patternbuf0, (void *)readbuf0,
		    PAGE_SIZE(handle)) != 0) {
			cond = CFGA_COND_FAILED;
			error_print((void *)patternbuf0, (void *)readbuf0,
			    handle, pageno, &total_errors);
			TEST_END(ntf_msg);
		}
		if (memcmp((void *)patternbuf1, (void *)readbuf1,
			PAGE_SIZE(handle)) != 0) {
			cond = CFGA_COND_FAILED;
			error_print((void *)patternbuf1, (void *)readbuf1,
			    handle, pageno, &total_errors);
			TEST_END(ntf_msg);
		}
		if (memcmp((void *)patternbuf0, (void *)readbuf2,
			PAGE_SIZE(handle)) != 0) {
			cond = CFGA_COND_FAILED;
			error_print((void *)patternbuf0, (void *)readbuf2,
			    handle, pageno, &total_errors);
			TEST_END(ntf_msg);
		}
		if ((time(NULL) >= time_rep) || (pageno == npages - 1) ||
		    (pageno == 0)) {
			(void) sprintf(msgbuf, report_msg, m1_msg,
			    ml_rd_cmp_msg, ((npages - pageno) * 100) / npages);
			mtest_message(handle, msgbuf);
			time_rep = time(NULL) + REPORT_SEC * 3;
		}
	}	/* page */

	/* March 2 */
	for (pageno = npages-1; pageno >= 0; pageno--) {
		for (line = (LINES_PER_PAGE(handle) - 1); line >= 0; line--) {
			if (mtest_read(handle, (void *)readbuf0, pageno,
			    line, 1, &errbuf) == -1) {
				(void) sprintf(msgbuf, rd_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
			if (errbuf.error_type != MTEST_ERR_NONE) {
				if (errbuf.error_type == MTEST_ERR_CE &&
				    cond != CFGA_COND_FAILED)
					cond = CFGA_COND_FAILING;
				else
					cond = CFGA_COND_FAILED;
				total_errors++;
				/*
				 * Keep going if max errors is 0 or limit not
				 * reached.
				 */
				TEST_END(ntf_msg);
			}
			if (mtest_write(handle, (void*)patternbuf0, pageno,
			    line, 1) == -1) {
				(void) sprintf(msgbuf, wr_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
			if (mtest_write(handle, (void*)patternbuf1, pageno,
			    line, 1) == -1) {
				(void) sprintf(msgbuf, wr_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
		}
		if (memcmp((void *)patternbuf1, (void *)readbuf0,
			PAGE_SIZE(handle)) != 0) {
			cond = CFGA_COND_FAILED;
			total_errors++;
		}
		if ((time(NULL) >= time_rep) || (pageno == npages - 1) ||
		    (pageno == 0)) {
			(void) sprintf(msgbuf, report_msg, m2_msg,
			    ln_rd_cmp_msg, ((npages - pageno) * 100) / npages);
			mtest_message(handle, msgbuf);
			time_rep = time(NULL) + REPORT_SEC * 3;
		}
	}	/* page */

	/* March 3 */
	for (pageno = 0; pageno < npages; pageno++) {
		for (line = 0; line < LINES_PER_PAGE(handle); line++) {
			if (mtest_read(handle, (void *)readbuf0, pageno,
			    line, 1, &errbuf) == -1) {
				(void) sprintf(msgbuf, rd_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
			if (errbuf.error_type != MTEST_ERR_NONE) {
				if (errbuf.error_type == MTEST_ERR_CE &&
				    cond != CFGA_COND_FAILED)
					cond = CFGA_COND_FAILING;
				else
					cond = CFGA_COND_FAILED;
				total_errors++;
				TEST_END(ntf_msg);
			}
			if (mtest_write(handle, (void*)patternbuf0, pageno,
			    line, 1) == -1) {
				(void) sprintf(msgbuf, wr_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
			if (mtest_write(handle, (void*)patternbuf1, pageno,
			    line, 1) == -1) {
				(void) sprintf(msgbuf, wr_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
			if (mtest_write(handle, (void*)patternbuf0, pageno,
			    line, 1) == -1) {
				(void) sprintf(msgbuf, wr_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
		}
		if (memcmp((void *)patternbuf1, (void *)readbuf0,
			PAGE_SIZE(handle)) != 0) {
			cond = CFGA_COND_FAILED;
			error_print((void *)patternbuf1, (void *)readbuf0,
			    handle, pageno, &total_errors);
			TEST_END(ntf_msg);
		}
		if ((time(NULL) >= time_rep) || (pageno == npages - 1) ||
		    (pageno == 0)) {
			(void) sprintf(msgbuf, report_msg, m3_msg,
			    ml_rd_cmp_msg, ((pageno + 1) * 100) / npages);
			mtest_message(handle, msgbuf);
			time_rep = time(NULL) + REPORT_SEC * 3;
		}
	}	/* page */

	/* March 4 */
	for (pageno = 0; pageno < npages; pageno++) {
		for (line = 0; line < LINES_PER_PAGE(handle); line++) {
			if (mtest_read(handle, (void *)readbuf0, pageno,
			    line, 1, &errbuf) == -1) {
				(void) sprintf(msgbuf, rd_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
			if (errbuf.error_type != MTEST_ERR_NONE) {
				if (errbuf.error_type == MTEST_ERR_CE &&
				    cond != CFGA_COND_FAILED)
					cond = CFGA_COND_FAILING;
				else
					cond = CFGA_COND_FAILED;
				total_errors++;
				TEST_END(ntf_msg);
			}
			if (mtest_write(handle, (void*)patternbuf1, pageno,
			    line, 1) == -1) {
				(void) sprintf(msgbuf, wr_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
			if (mtest_write(handle, (void*)patternbuf0, pageno,
			    line, 1) == -1) {
				(void) sprintf(msgbuf, wr_err_msg, pageno);
				mtest_message(handle, msgbuf);
				return (MTEST_DEV_ERROR);
			}
		}
		if (memcmp((void *)patternbuf0, (void *)readbuf0,
			PAGE_SIZE(handle)) != 0) {
			cond = CFGA_COND_FAILED;
			error_print((void *)patternbuf0, (void *)readbuf0,
			    handle, pageno, &total_errors);
			TEST_END(ntf_msg);
		}
		if ((time(NULL) >= time_rep) || (pageno == npages - 1) ||
		    (pageno == 0)) {
			(void) sprintf(msgbuf, report_msg, m4_msg,
			    ln_rd_cmp_msg, ((pageno + 1) * 100) / npages);
			mtest_message(handle, msgbuf);
			time_rep = time(NULL) + REPORT_SEC * 3;
		}
	}	/* page */
	mtest_message(handle, etf_msg);
	error_summary(handle, total_errors);
	SET_CONDITION(handle, cond);
	return (MTEST_DONE);
}
