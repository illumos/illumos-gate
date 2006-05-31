#!/sbin/sh
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

#ident	"%Z%%M%	%I%	%E% SMI"

case "$MACH" in
  "i386" )
	echo "# IP Filter pfil autopush setup
#
# See the autopush(1M) manpage for more information.
#
# Format of the entries in this file is:
#
#major  minor lastminor modules

#iprb	-1	0	pfil
#elxl	-1	0	pfil
#e1000g	-1	0	pfil
#bge	-1	0	pfil
#nf	-1	0	pfil
#fa	-1	0	pfil
#ci	-1	0	pfil
#el	-1	0	pfil
#ipdptp	-1	0	pfil
#lane	-1	0	pfil
#dnet	-1	0	pfil
#pcelx	-1	0	pfil
#spwr	-1	0	pfil
#ce	-1	0	pfil

" > pfil.ap
	;;
  "sparc" )
	echo "# IP Filter pfil autopush setup
#
# See autopush(1M) manpage for more information.
#
# Format of the entries in this file is:
#
#major  minor lastminor modules

#le	-1	0	pfil
#qe	-1	0	pfil
#hme	-1	0	pfil
#qfe	-1	0	pfil
#eri	-1	0	pfil
#ce	-1	0	pfil
#e1000g	-1	0	pfil
#bge	-1	0	pfil
#be	-1	0	pfil
#vge	-1	0	pfil
#ge	-1	0	pfil
#nf	-1	0	pfil
#fa	-1	0	pfil
#ci	-1	0	pfil
#el	-1	0	pfil
#ipdptp	-1	0	pfil
#lane	-1	0	pfil
#dmfe	-1	0	pfil
" >pfil.ap
	;;
  * )
	echo "Unknown architecture."
	exit 1
	;;
esac

