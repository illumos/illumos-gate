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
 * Copyright 2026 Oxide Computer Company
 */

#ifndef _PAYLOAD_COMMON_H_
#define	_PAYLOAD_COMMON_H_

#define	MEM_TOTAL_SZ	(64 * 1024 * 1024)

/* 2MiB-page entries for identity-mapped table at 2MiB */
#define	MEM_LOC_PAGE_TABLE_2M	0x200000
#define	MEM_LOC_PAGE_TABLE_1G	0x204000
#define	MEM_LOC_PAGE_TABLE_512G	0x205000
#define	MEM_LOC_GDT		0x206000
#define	MEM_LOC_TSS		0x206200
#define	MEM_LOC_IDT		0x207000
#define	MEM_LOC_HEAP		0x400000
#define	MEM_LOC_STACK		0x7fff00
#define	MEM_LOC_PAYLOAD		0x800000
#define	MEM_LOC_ROM		0xffff000

/* IO port set aside for emitting test result */
#define	IOP_TEST_RESULT		0xef00U

/* IO port set aside for emitting test message strings */
#define	IOP_TEST_MSG		0xef08U

/* IO port set aside for emitting test value */
#define	IOP_TEST_VALUE		0xef10U

/*
 * IO port set aside for reporting an exception taken by the payload with
 * handlers installed via idt_init().
 *
 * The exception handler writes (as a 32-bit OUT) the guest-physical address of
 * a `struct payload_exc_report` describing the exception.  If the exception is
 * resumable (as marked by exc_set_resumable()), the handler returns from it
 * once the OUT has been fulfilled.  Otherwise it halts, and the harness fails
 * the test.
 */
#define	IOP_TEST_EXC		0xef18U

/* IO port set aside for inputting test param(s) */
#define	IOP_TEST_PARAM		IOP_TEST_PARAM0
#define	IOP_TEST_PARAM0		0xef20U
#define	IOP_TEST_PARAM1		0xef21U
#define	IOP_TEST_PARAM2		0xef22U
#define	IOP_TEST_PARAM3		0xef23U

/* Expected values emitted through IOP_TEST_RESULT */
#define	TEST_RESULT_PASS	0
#define	TEST_RESULT_FAIL	1

/*
 * Sentinel for "no exception" where an exception vector (uint8_t) is expected.
 */
#define	EXC_NONE		0xffU

#ifndef _ASM

#include <sys/types.h>

/*
 * Exception details reported via IOP_TEST_EXC.
 *
 * Must match `exc_report` in payload_utils.S
 */
struct payload_exc_report {
	uint64_t	per_errcode;
	uint64_t	per_rip;
	uint8_t		per_vector;
	uint8_t		per_resumable;
};

#endif /* _ASM */

#endif /* _PAYLOAD_COMMON_H_ */
