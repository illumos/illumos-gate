#
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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# This test checks whether ksh93 (like ksh88) generates calls a
# CHLD/SIGCHLD trap for background jobs and _not_ for foreground jobs.
#
# This was reported as CR #6722134 ("*ksh93* (20080624_snapshot)
# doesn't execute CHLD trap"):
# -- snip --
# With "set -o monitor" on and "set -o notify" off, ksh88 executes the CHLD
# trap while waiting for interactive input when a background job completes.
# ksh93 appears not to execute the CHLD trap when a background job terminates.
# Probably related:  I noticed that with no CHLD trap set, but -o monitor and
# -o notify set, there should be a similar asynchronous job completion notice.
# It works in ksh88 but not in this ksh93 build.
# -- snip --
#

# test setup
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors < 127 && Errors++ ))
}
alias err_exit='err_exit $LINENO'

set -o nounset
Command=${0##*/}
integer Errors=0


##
## test one:
##
s="$($SHELL -c '
set -o errexit
integer i

trap "print got_child" SIGCHLD

sleep 5 &
sleep 7 &
for ((i=0 ; i < 15 ; i++)) ; do
      print $i
      sleep 1
      
      # external, non-background command for which a SIGCHLD should
      # _not_ be fired
      /bin/true >/dev/null
done
print "loop finished"
wait
print "done"
' 2>&1 )" || err_exit "test loop failed."

[[ "$s" == ~(Er)$'14\nloop finished\ndone' ]] || err_exit "Expected '14\nloop finished\ndone' at the end of the output, got ${s}."
[[ "$s" == ~(El)$'0\n1\n2' ]] || err_exit "Expected '0\n1\n2' as at the beginning of the output, got ${s}."

integer count
(( count=$(fgrep "got_child" <<< "$s" | wc -l) )) || err_exit "counting failed."
(( count == 2 )) || err_exit "Expected count==2, got count==${count}."


##
## test two:
## (same as test "one" except that this test has one more "sleep" child)
##
s="$($SHELL -c '
set -o errexit
integer i

trap "print got_child" SIGCHLD

sleep 5 &
sleep 7 &
sleep 9 &
for ((i=0 ; i < 15 ; i++)) ; do
      print $i
      sleep 1
      
      # external, non-background command for which a SIGCHLD should
      # _not_ be fired
      /bin/true >/dev/null
done
print "loop finished"
wait
print "done"
' 2>&1 )" || err_exit "test loop failed."

[[ "$s" == ~(Er)$'14\nloop finished\ndone' ]] || err_exit "Expected '14\nloop finished\ndone' at the end of the output, got ${s}."
[[ "$s" == ~(El)$'0\n1\n2' ]] || err_exit "Expected '0\n1\n2' as at the beginning of the output, got ${s}."

(( count=$(fgrep "got_child" <<< "$s" | wc -l) )) || err_exit "counting failed."
(( count == 3 )) || err_exit "Expected count==3, got count==${count}."


# tests done
exit $((Errors))
