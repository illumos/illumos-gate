#!/bin/ksh -p
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Some of the files in the perl distribution are uuencoded, or contain uuencoded
# data.  Some of the sequences of uuencoded data look like SCCS keywords, i.e.
# "%<letter>%", so it is necessary to prevent the keywords from being expanded.
# The SCCS 'y' flag can be added to the SCCS files to prevent keyword expansion
# when the file is retrieved.  However due to bugs in SCCS and wx we can't
# always be sure that these flags are propagated correctly.  This script checks
# the files passed on its command-line to make sure they have not been subject
# to incorrect keyword expansion, which in the case of perl will not necessarily
# result in a build-time error, as the files are copied verbatim into the proto
# area.
#

# Split out the directory and file components of each path on the command-line.
for dirfile in $*; do
	dir=${dirfile%/*}
	file=${dirfile##*/}
	sfile="SCCS/s.$file"

	# Create a new environment, so we pop back to the old directory.
	(
		# Check everything exists.
		if [[ ! -d $dir ]]; then
			printf 'Invalid directory: %s\n' $dir
			exit 1
		fi
		cd $dir || exit 1 

		# Source builds might not have the SCCS directory present.
		if [[ ! -f $sfile ]]; then
			continue;
		fi

		#
		# Compare the plaintext file with the version extracted from
		# SCCS with keyword expansion prevented; fix everything up if
		# the two don't match.
		#
		fetch='no'
		if [[ ! -f $file ]]; then
			fetch='yes'
		elif [[ $(sccs get -kp $file 2>/dev/null | cksum) \
		    != $(cat $file | cksum) ]]; then
			printf 'Warning: expanded SCCS keywords in %s fixed\n' \
			    $dirfile
			fetch='yes'
		fi
		if [[ $fetch = 'yes' ]]; then
			sccs admin -fy $file
			sccs get $file 2>/dev/null
		fi
	)
done
