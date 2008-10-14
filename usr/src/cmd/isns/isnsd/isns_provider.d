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

provider isns {
	probe connection__accepted(uintptr_t);
	probe msg__received(uintptr_t);
	probe msg__responded(uintptr_t);
	probe operation__type(uintptr_t, uint32_t);
	probe mgmt__request__received();
	probe mgmt__request__responded();
	probe mgmt__operation__type(uint32_t);
	probe mgmt__object__type(uint32_t);
};

#pragma D attributes Private/Private/ISA provider isns provider
#pragma D attributes Private/Private/Unknown provider isns module
#pragma D attributes Private/Private/Unknown provider isns function
#pragma D attributes Private/Private/ISA provider isns name
#pragma D attributes Private/Private/ISA provider isns args
