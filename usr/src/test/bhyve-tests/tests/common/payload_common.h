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
 * Copyright 2023 Oxide Computer Company
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
#define	MEM_LOC_STACK		0x400000
#define	MEM_LOC_PAYLOAD		0x800000
#define	MEM_LOC_ROM		0xffff000

/* IO port set aside for emitting test result */
#define	IOP_TEST_RESULT		0xef00U

/* IO port set aside for emitting test message strings */
#define	IOP_TEST_MSG		0xef08U

/* IO port set aside for emitting test value */
#define	IOP_TEST_VALUE		0xef10U

/* IO port set aside for inputting test param(s) */
#define	IOP_TEST_PARAM		IOP_TEST_PARAM0
#define	IOP_TEST_PARAM0		0xef20U
#define	IOP_TEST_PARAM1		0xef21U
#define	IOP_TEST_PARAM2		0xef22U
#define	IOP_TEST_PARAM3		0xef23U

/* Expected values emitted through IOP_TEST_RESULT */
#define	TEST_RESULT_PASS	0
#define	TEST_RESULT_FAIL	1

#endif /* _PAYLOAD_COMMON_H_ */
