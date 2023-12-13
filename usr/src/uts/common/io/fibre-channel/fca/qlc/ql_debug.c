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

/* Copyright 2015 QLogic Corporation */

/*
 * Copyright (c) 2008, 2011, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Qlogic ISP22xx/ISP23xx/ISP24xx FCA driver source
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2015 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#include <ql_apps.h>
#include <ql_api.h>
#include <ql_debug.h>

static int ql_flash_errlog_store(ql_adapter_state_t *, uint32_t *);

/*
 * Global Data.
 */
uint32_t	el_message_number = 0;
uint32_t	ql_enable_ellock = 0;

extern int	getpcstack(pc_t *, int);
extern char	*kobj_getsymname(uintptr_t, ulong_t *);

/*
 * ql_dump_buffer
 *	 Outputs buffer.
 *
 * Input:
 *	 string:	Null terminated string (no newline at end).
 *	 buffer:	buffer address.
 *	 wd_size:	word size 8 bits
 *	 count:		number of words.
 */
void
ql_dump_buffer(uint8_t *b8, uint8_t wd_size, uint32_t count)
{
	uint32_t	cnt;
	char		str[256], *sp;
	uint32_t	*b32 = (uint32_t *)b8;
	uint16_t	*b16 = (uint16_t *)b8;

	sp = &str[0];

	switch (wd_size) {
	case 32:
		cmn_err(CE_CONT, "         0         4         8         C\n");
		cmn_err(CE_CONT, "----------------------------------------\n");

		for (cnt = 1; cnt <= count; cnt++) {
			(void) sprintf(sp, "%10x", *b32++);
			sp += 10;
			if (cnt % 4 == 0) {
				cmn_err(CE_CONT, "%s\n", str);
				sp = &str[0];
			}
		}
		break;
	case 16:
		cmn_err(CE_CONT, "     0     2     4     6     8     A     C"
		    "     E\n");
		cmn_err(CE_CONT, "------------------------------------------"
		    "------\n");

		for (cnt = 1; cnt <= count; cnt++) {
			(void) sprintf(sp, "%6x", *b16++);
			sp += 6;
			if (cnt % 8 == 0) {
				cmn_err(CE_CONT, "%s\n", str);
				sp = &str[0];
			}
		}
		break;
	case 8:
		cmn_err(CE_CONT, "   0   1   2   3   4   5   6   7   8   9   "
		    "A   B   C   D   E   F\n");
		cmn_err(CE_CONT, "---------------------------------"
		    "-------------------------------\n");

		for (cnt = 1; cnt <= count; cnt++) {
			(void) sprintf(sp, "%4x", *b8++);
			sp += 4;
			if (cnt % 16 == 0) {
				cmn_err(CE_CONT, "%s\n", str);
				sp = &str[0];
			}
		}
		break;
	default:
		break;
	}
	if (sp != &str[0]) {
		cmn_err(CE_CONT, "%s\n", str);
	}
}

/*
 * ql_el_msg
 *	Extended logging message
 *
 * Input:
 *	ha:	adapter state pointer.
 *	fn:	function name.
 *	ce:	level
 *	...:	Variable argument list.
 *
 * Context:
 *	Kernel/Interrupt context.
 */
void
ql_el_msg(ql_adapter_state_t *ha, const char *fn, int ce, ...)
{
	char		*s, *fmt, *fmt1;
	/*
	 * EL_BUFFER_RESERVE 256 is the max # of bytes
	 * that driver's log could be collected.
	 * add 3 more buytes for safely maniplulation.
	 */
	char			buf[EL_BUFFER_RESERVE + 3];
	char			buf1[QL_LOG_LENGTH];
	size_t			tmp, rval, rval1, left;
	va_list			vl;
	ql_trace_desc_t		*desc;
	ql_trace_entry_t	*entry;
	uint32_t		cindex, count;
	timespec_t		time;

	if (ha == NULL && (ha = ql_hba.first->base_address) == NULL) {
		return;
	}

	desc = ha->ql_trace_desc;

	(void) bzero((void *)&buf[0], EL_BUFFER_RESERVE + 3);
	fmt1 = &buf[0];

	TRACE_BUFFER_LOCK(ha);

	/* locate the entry to be filled out */
	cindex = desc->nindex;
	entry = &desc->trace_buffer[cindex];

	count = desc->count;

	desc->end = desc->nindex;
	desc->nindex++;

	if (desc->nindex == desc->nentries) {
		desc->nindex = 0;
	}

	if (desc->csize < desc->nentries) {
		desc->csize++;
	} else {
		/*
		 * once wrapped, csize is fixed.
		 * so we have to adjust start point
		 */
		desc->start = desc->nindex;
	}

	gethrestime(&time);

	rval = snprintf(fmt1, (size_t)EL_BUFFER_RESERVE,
	    QL_BANG "%d=>QEL %s(%d,%d,%d):: %s, ", count, QL_NAME,
	    ha->instance, ha->vp_index, ha->pci_function_number, fn);

	rval1 = rval;

	va_start(vl, ce);
	s = va_arg(vl, char *);

	fmt = fmt1 + rval;

	tmp = vsnprintf(fmt,
	    (size_t)(uint32_t)((int)EL_BUFFER_RESERVE - rval), s, vl);

	va_end(vl);

	rval += tmp;

	if (rval > QL_LOG_LENGTH - 1) {
		left = rval - (QL_LOG_LENGTH - 1);

		/* store the remaining string */
		(void) strncpy(buf1, fmt1 + (QL_LOG_LENGTH - 1), left);

		(void) strncpy(entry->buf, fmt1, (QL_LOG_LENGTH - 1));
		entry->buf[QL_LOG_LENGTH - 1] = '\n';

		bcopy((void *)&time, (void *)&entry->hs_time,
		    sizeof (timespec_t));

		/*
		 * remaining msg will be stored in the nex entry
		 * with same timestamp and same sequence number
		 */
		cindex = desc->nindex;
		entry = &desc->trace_buffer[cindex];

		desc->end = desc->nindex;
		desc->nindex++;

		if (desc->nindex == desc->nentries) {
			desc->nindex = 0;
		}

		if (desc->csize < desc->nentries) {
			desc->csize++;
		} else {
			desc->start = desc->nindex;
		}

		(void) strncpy(&entry->buf[0], fmt1, rval1);
		(void) strncpy(&entry->buf[rval1], &buf1[0], left);
		entry->buf[rval1 + left] = 0;

		bcopy((void *)&time, (void *)&entry->hs_time,
		    sizeof (timespec_t));

		if (CFG_IST(ha, CFG_ENABLE_EXTENDED_LOGGING)) {
			cmn_err(ce, fmt1);
		}

		desc->count++;

		TRACE_BUFFER_UNLOCK(ha);
		return;
	}

	desc->count++;
	bcopy((void *)&time, (void *)&entry->hs_time,
	    sizeof (timespec_t));

	(void) strncpy(entry->buf, fmt1, sizeof (entry->buf));
	entry->buf[rval] = 0;

	TRACE_BUFFER_UNLOCK(ha);

	if (CFG_IST(ha, CFG_ENABLE_EXTENDED_LOGGING)) {
		cmn_err(ce, fmt1);
	}
}

/*
 * ql_dbg_msg
 *	Extended logging message
 *
 * Input:
 *	ha:	adapter state pointer.
 *	fn:	function name.
 *	ce:	level
 *	...:	Variable argument list.
 *
 * Context:
 *	Kernel/Interrupt context.
 */
void
ql_dbg_msg(ql_adapter_state_t *ha, const char *fn, int ce, ...)
{
	uint32_t	el_msg_num;
	char		*s;
	char		fmt[EL_BUFFER_RESERVE];
	va_list		vl;

	va_start(vl, ce);

	s = va_arg(vl, char *);

	if (ql_enable_ellock) {
		/*
		 * Used when messages are *maybe* being lost.  Adds
		 * a unique number to the message to one can see if
		 * any messages have been dropped. NB: This slows
		 * down the driver, which may make the issue disappear.
		 */
		GLOBAL_EL_LOCK();
		el_msg_num = ++el_message_number;
		GLOBAL_EL_UNLOCK();
		if (ha == NULL) {
			(void) snprintf(fmt, EL_BUFFER_RESERVE, "QLP%d: %s, "
			    "%s", el_msg_num, fn, s);
		} else {
			(void) snprintf(fmt, EL_BUFFER_RESERVE, "QLP%d: %s"
			    "(%d,%d,%d): %s", el_msg_num, fn, ha->instance,
			    ha->vp_index, ha->pci_function_number, s);
		}
	} else {
		if (ha == NULL) {
			(void) snprintf(fmt, EL_BUFFER_RESERVE, "QLP: %s, "
			    "%s", fn, s);
		} else {
			(void) snprintf(fmt, EL_BUFFER_RESERVE, "QLP: %s"
			    "(%d,%d,%d): %s", fn, ha->instance, ha->vp_index,
			    ha->pci_function_number, s);
		}
	}

	vcmn_err(ce, fmt, vl);

	va_end(vl);
}

/*
 * ql_stacktrace
 *	Prints out current stack
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel/Interrupt context.
 */
void
ql_stacktrace(ql_adapter_state_t *ha)
{
	int	depth, i;
	pc_t	pcstack[DEBUG_STK_DEPTH];
	char	*sym = NULL;
	ulong_t	off;

	depth = getpcstack(&pcstack[0], DEBUG_STK_DEPTH);

	cmn_err(CE_CONT, "%s(%d,%d): ---------- \n", QL_NAME, ha->instance,
	    ha->vp_index);
	for (i = 0; i < MIN(depth, DEBUG_STK_DEPTH); i++) {
		sym = kobj_getsymname((uintptr_t)pcstack[i], &off);

		if (sym == NULL) {
			cmn_err(CE_CONT, "%s(%d,%d): sym is NULL\n", QL_NAME,
			    ha->instance, ha->vp_index);
		} else {
			cmn_err(CE_CONT, "%s(%d,%d): %s+%lx\n", QL_NAME,
			    ha->instance, ha->vp_index, sym ? sym : "?", off);
		}
	}
	cmn_err(CE_CONT, "%s(%d,%d): ---------- \n", QL_NAME, ha->instance,
	    ha->vp_index);
}

/*
 * ql_flash_errlog
 *	Adds error to flash error log.
 *	Entry Layout:
 *		uint32_t TimeStamp;
 *		uint16_t CodeData[4];
 *
 * Input:
 *	ha:	adapter state pointer.
 *	code:	Error code
 *	d1-d3:	Error code data
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel/Interrupt context.
 */
int
ql_flash_errlog(ql_adapter_state_t *ha, uint16_t code, uint16_t d1,
    uint16_t d2, uint16_t d3)
{
	char		*s;
	uint32_t	marker[2], fdata[2], faddr;
	int		rval;

	QL_PRINT_3(ha, "started\n");

	if (ha->flash_errlog_start == 0) {
		return (QL_NOT_SUPPORTED);
	}

	EL(ha, "code=%xh, d1=%xh, d2=%xh, d3=%xh\n", code, d1, d2, d3);

	/*
	 * If marker not already found, locate or write marker.
	 */
	if (!(ha->flags & FLASH_ERRLOG_MARKER)) {

		/* Create marker. */
		marker[0] = CHAR_TO_LONG(ha->fw_subminor_version,
		    ha->fw_minor_version, ha->fw_major_version, 'S');

		/*
		 * Version should be of the format: YYYYMMDD-v.vv
		 */
		if ((strlen(QL_VERSION) > 9) && (QL_VERSION[8] == '-')) {
			s = &QL_VERSION[9];
		} else {
			s = QL_VERSION;
		}

		for (marker[1] = 0; *s != '\0'; s++) {
			if (*s >= '0' && *s <= '9') {
				marker[1] <<= 4;
				marker[1] |= *s - '0';
			} else if (*s != '.') {
				break;
			}
		}

		/* Locate marker. */
		ha->flash_errlog_ptr = ha->flash_errlog_start;
		for (;;) {
			faddr = ha->flash_data_addr | ha->flash_errlog_ptr;
			(void) ql_24xx_read_flash(ha, faddr++, &fdata[0]);
			(void) ql_24xx_read_flash(ha, faddr++, &fdata[1]);
			if (fdata[0] == 0xffffffff && fdata[1] == 0xffffffff) {
				break;
			}
			(void) ql_24xx_read_flash(ha, faddr++, &fdata[0]);
			(void) ql_24xx_read_flash(ha, faddr++, &fdata[1]);
			ha->flash_errlog_ptr += FLASH_ERRLOG_ENTRY_SIZE;
			if (ha->flash_errlog_ptr >=
			    ha->flash_errlog_start + FLASH_ERRLOG_SIZE) {
				EL(ha, "log full\n");
				return (QL_MEMORY_FULL);
			}
			if (fdata[0] == marker[0] && fdata[1] == marker[1]) {
				ha->flags |= FLASH_ERRLOG_MARKER;
				break;
			}
		}

		/* No marker, write it. */
		if (!(ha->flags & FLASH_ERRLOG_MARKER)) {
			ha->flags |= FLASH_ERRLOG_MARKER;
			rval = ql_flash_errlog_store(ha, marker);
			if (rval != QL_SUCCESS) {
				EL(ha, "failed marker write=%xh\n", rval);
				return (rval);
			}
		}
	}

	/*
	 * Store error.
	 */
	fdata[0] = SHORT_TO_LONG(d1, code);
	fdata[1] = SHORT_TO_LONG(d3, d2);
	rval = ql_flash_errlog_store(ha, fdata);
	if (rval != QL_SUCCESS) {
		EL(ha, "failed error write=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_flash_errlog_store
 *	Stores error to flash.
 *	Entry Layout:
 *		uint32_t TimeStamp;
 *		uint16_t CodeData[4];
 *
 * Input:
 *	ha:			adapter state pointer.
 *	fdata:			Error code plus data.
 *	ha->flash_errlog_ptr:	Current Flash error pointer.
 *
 * Output:
 *	ha->flash_errlog_ptr:	updated pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel/Interrupt context.
 */
static int
ql_flash_errlog_store(ql_adapter_state_t *ha, uint32_t *fdata)
{
	int		rval;
	uint64_t	time;
	uint32_t	d1, d2, faddr;

	QL_PRINT_3(ha, "started\n");

	/* Locate first empty entry */
	for (;;) {
		if (ha->flash_errlog_ptr >=
		    ha->flash_errlog_start + FLASH_ERRLOG_SIZE) {
			EL(ha, "log full\n");
			return (QL_MEMORY_FULL);
		}

		faddr = ha->flash_data_addr | ha->flash_errlog_ptr;
		ha->flash_errlog_ptr += FLASH_ERRLOG_ENTRY_SIZE;
		(void) ql_24xx_read_flash(ha, faddr, &d1);
		(void) ql_24xx_read_flash(ha, faddr + 1, &d2);
		if (d1 == 0xffffffff && d2 == 0xffffffff) {
			(void) drv_getparm(TIME, &time);

			/* Enable flash write. */
			if ((rval = ql_24xx_unprotect_flash(ha)) !=
			    QL_SUCCESS) {
				EL(ha, "unprotect_flash failed, rval=%xh\n",
				    rval);
				return (rval);
			}

			(void) ql_24xx_write_flash(ha, faddr++, LSD(time));
			(void) ql_24xx_write_flash(ha, faddr++, MSD(time));
			(void) ql_24xx_write_flash(ha, faddr++, *fdata++);
			(void) ql_24xx_write_flash(ha, faddr++, *fdata);

			/* Enable flash write-protection. */
			ql_24xx_protect_flash(ha);
			break;
		}
	}

	QL_PRINT_3(ha, "done\n");

	return (QL_SUCCESS);
}
