#!/usr/bin/sh

# Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved

# University Copyright- Copyright (c) 1982, 1986, 1988
# The Regents of the University of California
# All Rights Reserved
#
# University Acknowledgment- Portions of this document are derived from
# software developed by the University of California, Berkeley, and its
# contributors.

#ident	"%Z%%M%	%I%	%E% SMI"


PATH=/bin:/usr/bin:/usr/ucb
case $1 in
-T*)	t=$1
	shift ;;
*)	t=-T$TERM
esac
case $t in
-T450)			exec t450 $*;;
-T300)			exec t300 $*;;
-T300S|-T300s)		exec t300s $*;;
-Tver)			exec lpr -Pversatec -g $*;;
-Tvar)			exec lpr -Pvarian -g $*;;
-Ttek|-T4014|-T)	exec tek $* ;;
-T4013)			exec t4013 $* ;;
-Tbitgraph|-Tbg)	exec bgplot $*;;
-Tgigi|-Tvt125)		exec gigiplot $*;;
-Taed)			exec aedplot $*;;
-Thp7221|-Thp7|-Th7)	exec hp7221plot $*;;
-Thp|-T2648|-T2648a|-Thp2648|-Thp2648a|h8)
			exec hpplot $*;;
-Tip|-Timagen)		exec implot $*;;
-Tdumb|un|unknown)	exec dumbplot $*;;
*)  			exec crtplot $*;;
esac
