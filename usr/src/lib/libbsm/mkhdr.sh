#!/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Automagically generate the audit_uevents.h header file.
#
DATABASE=audit_event.txt
HEADER_FILE=audit_uevents.h

cat <<EOF > $HEADER_FILE
/*
 * Copyright (c) 1993-2001, Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#ifndef	_BSM_AUDIT_UEVENTS_H
#define	_BSM_AUDIT_UEVENTS_H

#pragma ident	"%Z%$HEADER_FILE	%I%	%E% SMI"

/*
 * User level audit event numbers.
 *
 *     0		Reserved as an invalid event number.
 *     1 - 2047		Reserved for the Solaris Kernel events.
 *  2048 - 32767	Reserved for the Solaris TCB programs.
 * 32768 - 65535	Available for third party TCB applications.
 *
 */

#ifdef	__cplusplus
extern "C" {
#endif

EOF

nawk -F: '{if ((NF == 4) && substr($1,0,1) != "#")
		if ($1 >= 2048) {
			printf("#define	%s	",$2)
			if (length($2) < 8)
				printf("	")
			if (length($2) < 16)
				printf("	")
			printf("%s	/* =%s %s */\n",$1,$4,$3)
		}
	  }' \
< $DATABASE >> $HEADER_FILE

cat <<EOF >> $HEADER_FILE

#ifdef	__cplusplus
}
#endif

#endif	/* _BSM_AUDIT_UEVENTS_H */
EOF

exit 0
