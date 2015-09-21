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
# Copyright 2015 Gary Mills
# Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 

# 
#	Copyright (c) 1988 AT&T
#	  All Rights Reserved
#
 
# 
# University Copyright- Copyright (c) 1982, 1986, 1988
# The Regents of the University of California
# All Rights Reserved
# 
# University Acknowledgment- Portions of this document are derived from
# software developed by the University of California, Berkeley, and its
# contributors.
#
 
rm -f keyname.c
/usr/bin/print "#include	\"curses_inc.h\"\n" > keyname.c
/usr/bin/print "static	char	*keystrings[] =\n\t\t{" >> keyname.c
{
    grep -v 'KEY_F(' keycaps | awk '{ print $5, $4 }' | sed -e 's/,//g' -e 's/KEY_//'
    # These three aren't in keycaps
    echo '0401 BREAK\n0530 SRESET\n0531 RESET'
} |  sort -n | awk '
    {
	print "\t\t    \"" $2 "\",	/* " $1 " */"
    }
' >> keyname.c

LAST=`tail -1 keyname.c | awk -F'"' '{print $2}'`
cat << ! >> keyname.c
		};

char	*
keyname(int key)
{
	static	char	buf[16];

	if (key >= 0400) {
		int	i;

		if ((key == 0400) || (key > KEY_${LAST}))
			return ("UNKNOWN KEY");
		if (key > 0507)
			i = key - (0401 + ((0507 - 0410) + 1));
		else
			if (key >= 0410) {
				(void) sprintf(buf, "KEY_F(%d)", key - 0410);
				goto ret_buf;
			} else
				i = key - 0401;
		(void) sprintf(buf, "KEY_%s", keystrings[i]);
		goto ret_buf;
	}

	if (key >= 0200) {
#ifdef SYSV
		if (SHELLTTYS.c_cflag & CS8)
#else	/* SYSV */
		if (SHELLTTY.c_cflag & CS8)
#endif	/* SYSV */
			(void) sprintf(buf, "%c", key);
		else
			(void) sprintf(buf, "M-%s", unctrl(key & 0177));
		goto ret_buf;
	}

	if (key < 0) {
		(void) sprintf(buf, "%d", key);
ret_buf:
		return (buf);
	}

	return (unctrl(key));
}
!
exit 0
