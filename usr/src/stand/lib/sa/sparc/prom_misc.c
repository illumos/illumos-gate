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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/salib.h>
#include <sys/promimpl.h>

#pragma ident	"%Z%%M%	%I%	%E% SMI"

void
prom_create_encoded_prop(char *propname, void *prop_data, int prop_datalen,
    enum encode_how how)
{
	char encode_bytes_command[] =	"my-self >r  0 to my-self"
					" push-package"
					" encode-bytes  2swap property"
					" pop-package"
					" r> to my-self";
	char encode_string_command[] =	"my-self >r  0 to my-self"
					" push-package"
					" encode-string  2swap property"
					" pop-package"
					" r> to my-self";
	char *command;
	static pnode_t cn = OBP_NONODE;

	if (cn == OBP_NONODE) {
		cn = prom_finddevice("/chosen");
		if (cn == OBP_BADNODE)
			prom_panic("prom_create_encoded_prop: no /chosen\n");
	}

	if (how == ENCODE_BYTES) {
		command = encode_bytes_command;
	} else {
		assert(how == ENCODE_STRING);
		command = encode_string_command;
	}

	prom_interpret(command, (uint_t)cn, prop_datalen,
	    (uintptr_t)prop_data, strlen(propname), (uintptr_t)propname);
}
