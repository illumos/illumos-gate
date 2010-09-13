#!/usr/bin/sh
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Build-time script to generate the sd_iob_implX.c files.
#
START="$1"
END="$2"
FILE="$3"

awk '
/#define.*_SD_DEFAULT_IOBUFS/ {
	num = $3;
printf("/* start = %d, end = %d, num %d */\n", start, end, num);
	if (num > end) {
		num = end;
	}
printf("/* start = %d, end = %d, num %d */\n", start, end, num);
}

END {
	printf("/* start = %d, end = %d, num %d */\n", start, end, num);
	printf("#include <sys/types.h>\n");
	printf("#include <sys/param.h>\n");
	printf("#include <sys/ksynch.h>\n");
	printf("#include <sys/kmem.h>\n");
	printf("#include <sys/stat.h>\n");
	printf("#include <sys/buf.h>\n");
	printf("#include <sys/open.h>\n");
	printf("#include <sys/conf.h>\n");
	printf("#include <sys/file.h>\n");
	printf("#include <sys/cmn_err.h>\n");
	printf("#include <sys/errno.h>\n");
	printf("#include <sys/debug.h>\n");
	printf("#include <sys/ddi.h>\n");
	printf("#include <sys/nsc_thread.h>\n");
	printf("#include <sys/nsctl/sd_bcache.h>\n");
	printf("#include <sys/nsctl/sd_trace.h>\n");
	printf("#include <ns/sdbc/sd_io.h>\n");
	printf("#include <ns/sdbc/sd_iob.h>\n");

	n = start;
	while (n < num) {
		printf("IOB_DCB(%d)", n);
		n = n + 1;

		if (n % 4) {
			printf(" ");
		} else {
			printf("\n");
			if (!((n - start) % 2048) && (n < num))
				printf("static int _cscope_brkline%d;\n", n);
		}
	}
}' start=$START end=$END incdir=`dirname $FILE` $FILE

exit 0
