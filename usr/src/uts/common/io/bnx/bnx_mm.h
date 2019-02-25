/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_BNX_MM_H
#define	_BNX_MM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/atomic.h>

#define	mm_read_barrier() membar_consumer()
#define	mm_write_barrier() membar_producer()

#include "lm.h"
#include "lm5706.h"

#define	FLUSHPOSTEDWRITES(_lmdevice)					\
	{								\
		volatile uint32_t dummy;				\
		REG_RD((_lmdevice), pci_config.pcicfg_int_ack_cmd, &dummy); \
	}

#ifdef __cplusplus
}
#endif

#endif	/* _BNX_MM_H */
