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

#ifndef _COMMON_H_
#define	_COMMON_H_

void name_test_vm(const char *, char *);
struct vmctx *create_test_vm(const char *);
int alloc_memseg(struct vmctx *, int, size_t, const char *);
int open_drv_test(void);
bool check_instance_usable(const char *);
bool check_instance_exists(const char *);
int destroy_instance(const char *);
bool cpu_vendor_amd(void);

#define	PROT_ALL	(PROT_READ | PROT_WRITE | PROT_EXEC)

#endif /* _COMMON_H_ */
