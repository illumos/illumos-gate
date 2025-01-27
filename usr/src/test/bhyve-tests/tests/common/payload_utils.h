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

#ifndef _PAYLOAD_UTILS_H_
#define	_PAYLOAD_UTILS_H_

#include <sys/types.h>
#include <stdbool.h>

void outb(uint16_t, uint8_t);
void outw(uint16_t, uint16_t);
void outl(uint16_t, uint32_t);
uint8_t inb(uint16_t);
uint16_t inw(uint16_t);
uint32_t inl(uint16_t);
uint64_t rdmsr(uint32_t);
void wrmsr(uint32_t, uint64_t);
void cpuid(uint32_t, uint32_t, uint32_t *);
uint64_t rdtsc(void);
void ud2a(void);
void setcr4(uint64_t);
uint64_t getcr4(void);
void setxcr(uint32_t, uint64_t);
uint64_t getxcr(uint32_t);

void test_result_pass(void);
void test_result_fail(void);
void test_msg(const char *);

#define	__STR2(x)	#x
#define	__STR(x)	__STR2(x)

#define	TEST_ABORT(msg)							\
	do {								\
		test_msg(__FILE__ ":" __STR(__LINE__) " - " msg);	\
		test_result_fail();					\
	} while (0)

#endif /* _PAYLOAD_UTILS_H_ */
