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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2025 Oxide Computer Company
#
# Create two files from a list of input strings.
#
# new_list.c:
#     contains an array of characters indexed into by perror and
#     strerror and an array of strings for strerrorname_np.
#     -> _sys_nerrs, _sys_nindex and _sys_err_names
#
# errlst.c:
#     contains an array of pointers to strings for compatibility
#     with existing user programs that reference it directly;
#     errlst.c references the strings indirectly using a library private symbol,
#     __sys_errs[], in order to get relative relocations.
#     -> _sys_errs, _sys_index, _sys_num_err, sys_errlist[]
#
# Since the 64 bit ABI doesn't define the old symbols, the second file is left
# out of 64 bit libraries.

BEGIN	{
	FS = "\t"

	# This is the number of entries for the legacy sys_errlist[].
	# This cannot change as old binaries may reference the copy
	# relocated sys_errlist, and the data to which it points, directly. New
	# code should always use perror(), strerror() et al., and that is the
	# only interface available in the 64-bit library. This is not the only
	# check to guard against unintended changes, there are also constraints
	# in the libc mapfile that will cause a link failure if the size
	# changes.
	legacynum = 151

	newfile = "new_list.c"
	oldfile = "errlst.c"

	print "#pragma weak _sys_errlist = sys_errlist" >oldfile
	print "#pragma weak __sys_errs = _sys_errs" >oldfile
	print "#include \"lint.h\"\n" >oldfile
	# We need to include the errors strings proper in the
	# C source for gettext; the macro C allows us to embed
	# them as a comment.
	print "#define\tC(x)\n" >oldfile

	print "#include \"lint.h\"" >newfile
	print "#include <sys/isa_defs.h>" >newfile
	print "#include <errno.h>" >newfile
	print "" >newfile
}

/^[0-9]+/ {
	aname[$1] = $2
	astr[$1] = $3
	if ($1 > max)
		max = $1
}

function genlists(outfile, v_index, v_errs, v_num) {
	for (j = 0; j <= max; ++j) {
		if (astr[j] == "")
			astr[j] = sprintf("Error %d", j)
	}

	k = 0
	printf "const int %s[%s] = {\n", v_index, max + 1 >outfile
	for (j = 0; j <= max; ++j) {
		printf "\t%d,\n", k >outfile
		k += length(astr[j]) + 1
	}
	print "};\n" >outfile

	print "/* This is one long string */" >outfile
	printf "const char %s[%d] =\n", v_errs, k >outfile
	for (j = 0; j <= max; ++j)
		printf "\t\"%s\\0\"\n", astr[j] >outfile
	print ";\n" >outfile
	printf "const int %s = %d;\n\n", v_num, max + 1 >outfile
}

/^== End of legacy/ {
	#
	# Generate the legacy lists that have become part of the ABI
	# and must not change.
	#

	# Check that the legacy sys_errlist[] is the correct size.
	if (max != legacynum) {
		printf "awk: ERROR! sys_errlist[] != %d entries\n", legacynum
		printf "Please read comments in"
		printf " usr/src/lib/libc/port/gen/errlist\n"
		exit 1
	}


	genlists(oldfile, "_sys_index", "_sys_errs", "_sys_num_err")
	print "#undef sys_nerr" >oldfile
	print "#pragma weak _sys_nerr = _sys_num_err" >oldfile
	print "#pragma weak sys_nerr = _sys_num_err" >oldfile

	k = 0
	print "const char *sys_errlist[] = {" >oldfile
	for (j = 0; j <= max; ++j) {
		printf "\t&_sys_errs[%d], C(\"%s\")\n", k, astr[j] \
		    >oldfile
		k += length(astr[j]) + 1
	}
	print "};\n" >oldfile
}

END	{
	#
	# Generate the new lists that are used internally by libc and
	# do not form part of the ABI.
	#

	genlists(newfile, "_sys_nindex", "_sys_nerrs", "_sys_num_nerr")

	#
	# This stanza is used to generate the array of names for mapping
	# an errno to its constant (e.g. "ENOENT").
	#

	printf "const char *_sys_err_names[%d] = {\n", max + 1 >newfile
	printf "\t[0] = \"0\",\n" >newfile
	for (j = 1; j <= max; ++j)
	{
		if (aname[j] == "" || aname[j] == "SKIP")
			continue
		printf "\t[%s] = \"%s\",\n", aname[j], aname[j] >newfile
	}
	print "};\n" > newfile
}
