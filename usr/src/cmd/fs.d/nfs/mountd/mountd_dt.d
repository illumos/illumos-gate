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

provider mountd {
	probe hashset(int, float);
	probe e__nb__enqueue(void);
	probe nb_set_enqueue(void);
	probe log_host(char *);
	probe log_no_host(void);
	probe logging_cleared(int);
	probe logged_in_thread(void);
	probe name_by_verbose(void);
	probe name_by_in_thread(void);
	probe name_by_lazy(void);
	probe name_by_addrlist(void);
	probe name_by_netgroup(void);
};

#pragma D attributes Private/Private/Common provider mountd provider
#pragma D attributes Private/Private/Common provider mountd module
#pragma D attributes Private/Private/Common provider mountd function
#pragma D attributes Private/Private/Common provider mountd name
#pragma D attributes Private/Private/Common provider mountd args
