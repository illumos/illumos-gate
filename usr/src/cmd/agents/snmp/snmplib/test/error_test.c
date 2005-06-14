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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include "error.h"


static void application_end()
{
}


main(int agrc, char *argv[])
{
	error_init(argv[0], application_end);

	error("first message");
	error("tata\n");
	error("\n");
	error("titi\n");
	error("\n\n");
	error("toto\n\n\n");
	error("\n\n\n");

	error_open("/tmp/error_test.log");

	error("second message");
	error("tata\n");
	error("\n");
	error("titi\n");
	error("\n\n");
	error("toto\n\n\n");
	error("\n\n\n");

/*
 *	error_close_stderr();
 */

	error("third message");
	error("tata\n");
	error("\n");
	error("titi\n");
	error("\n\n");
	error("toto\n\n\n");
	error("\n\n\n");

	error_exit("end of this sample program");
}
