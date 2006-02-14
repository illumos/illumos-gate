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

#   First line is for a yellow pages entry in the password file.
BEGIN {FS = ":" }
{
   if (substr($1,1,1) != "+") {
      if ($0 ~ /^[ 	]*$/) {
	 printf("\nWarning!  Password file, line %d, is blank\n", NR)
      } else {
         if (NF != 7) {
	    printf("\nWarning!  Password file, line %d,", NR);
	    printf("does not have 7 fields: \n\t%s\n", $0)
         }
         if ($1 !~ /[A-Za-z0-9]/) {
	    printf("\nWarning!  Password file, line %d,", NR);
	    printf("nonalphanumeric user name: \n\t%s\n", $0)
         }
#         if ($2 == "") {
#	    printf("\nWarning!  Password file, line %d,", NR);
#	    printf("no password: \n\t%s\n", $0)
#         }
#         if ("${C2}" == "true" && $2 ~ /^##/ && "##"$1 != $2) {
#	    printf("\nWarning!  Password file, line %d,", NR);
#	    printf("invalid password field for C2: \n\t%s\n", $0)
#         }
         if ($3 !~ /[0-9]/) {
	    printf("\nWarning!  Password file, line %d,", NR);
	    printf("nonnumeric user id: \n\t%s\n", $0)
         }
#        if ($3 == "0" && $1 != "root") {
#	    printf("\nWarning!  Password file, line %d,", NR);
#	    printf("user %s has uid = 0 and is not root\n\t%s\n", $1, $0)
#	 }
         if ($4 !~ /[0-9]/) {
		printf("\nWarning!  Password file, line %d,", NR);
		printf("nonnumeric group id: \n\t%s\n", $0)
	 }
         if ($6 !~ /^\//) {
		printf("\nWarning!  Password file, line %d,", NR);
		printf("invalid login directory: \n\t%s\n", $0)
	 }
      }
   }
}
