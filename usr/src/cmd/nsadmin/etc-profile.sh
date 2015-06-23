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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2015 Nexenta Systems, Inc. All rights reserved.

# The profile that all logins get before using their own .profile.

trap ""  2 3
export LOGNAME PATH

if [ "$TERM" = "" ]
then
	if [ `uname -p` = "i386" ]; then
		TERM=sun-color
	else
		TERM=sun
	fi
	export TERM
fi

#	Login and -su shells get /etc/profile services.
#	-rsh is given its environment in its .profile.

case "$0" in
-sh | -ksh | -ksh93 | -jsh | -bash | -zsh)

	if [ ! -f .hushlogin ]
	then
		/usr/sbin/quota
		#	Allow the user to break the Message-Of-The-Day only.
		trap "trap '' 2"  2
		/bin/cat -s /etc/motd
		trap "" 2

		/bin/mail -E
		case $? in
		0) 
			echo "You have new mail."
		  	;;
		2) 
			echo "You have mail."
		   	;;
		esac
	fi
esac

umask 022
trap  2 3
