#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#ident	"%Z%%M%	%I%	%E% SMI"

BEGIN {FS = ":" }

(substr($1,1,1) != "+") {
   if ($0 ~ /^[ 	]*$/) {
      printf("Warning!  Group file, line %d, is blank\n", NR)
   } else {
      if (NF != 4) {
         printf("Warning!  Group file, line ");
	 printf("%d, does not have 4 fields: %s\n", NR, $0);
      }
      if ($1 !~ /[A-Za-z0-9]/) {
         printf("Warning!  Group file, line ");
	 printf("%d, nonalphanumeric group id: %s\n", NR, $0)
      }
      if ($2 != "" && $2 != "*") {
#         if ("'$C2'" != "true") {
#            printf("Warning!  Group file, line ");
#	    printf("%d, group has password: %s\n", NR, $0);
#         } else {
#            if ("#$"$1 != $2)
#            printf("Warning!  Group file, line ");
#	    printf("%d, group has invalid field for C2:\n%s\n", NR, $0)
#	 }
      }
      if ($3 !~ /[0-9]/) {
         printf("Warning!  Group file, line ");
	 printf("%d, nonnumeric group id: %s\n", NR, $0)
      }
   }
}
