{
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
	#ident	"%Z%%M%	%I%	%E% SMI"

	if (first_time == 0 && ($1 == "probe" || match($1, "---")))
		next;
	else
		first_time = 1;

	time = $1;
	thread = $5;
	type = $7;
	val = pval = "";
	for (i = 8; i <= NF; i++) {
		if (pval == "cip:")
			val = val " " sprintf("%x", $i);
		else
			val = val " " $i;
		pval=$i
	}

	if (match(type, "_end")) {
		type = substr(type, 1, match(type, "_end") - 1);

		if (int(start[thread "" type]) == 0) {
			printf("Warning: missing match line %d: %s\n", NR, $0);
			next;
		}

		total[type]++;
		alltotal++;

		elapsed = time - start[thread "" type];
		vchar = "";
		if (longest[type] < elapsed) {
			longest[type] = elapsed;
			vchar = "*";
		}
		if (verbose) {
			printf("\t\top: %s thread: %d elapsed %f%s%s\n",
				type, thread, elapsed, val, vchar);
		}
		average[type] = (average[type] + elapsed)/total[type];
		averagedepth[type] = (averagedepth[type] + depth[type])/total[type];

		allaverage= (allaverage + alldepth)/alltotal;

		depth[type]--;
		alldepth--;
		start[thread "" type] = 0;

	} else {
		if (match(type, "_start")) {
			type = substr(type, 1, match(type, "_start") - 1);
		}
		start[thread "" type] = time;
		depth[type]++;
		if (maxdepth[type] < depth[type])
			maxdepth[type] = depth[type];

		alldepth++;
		if (allmaxdepth < alldepth)
			allmaxdepth = alldepth;
	}
}

END {
	printf("\n");
	for (types in total) {
		printf("op: %d %s: avg: %8.8f worst: %8.8f\n",
			total[types], types, average[types], longest[types]);
		printf("	avg concurrency: %8.8f greatest concurrency %8.8f\n\n",
			averagedepth[types], maxdepth[types]);
	}
	printf("Totals: avg concurrency: %8.8f greatest concurrency %8.8f\n",
		allaverage, allmaxdepth);
}
