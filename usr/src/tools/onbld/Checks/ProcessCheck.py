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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# Copyright 2018 OmniOS Community Edition (OmniOSce) Association.

#
# Wrap a command-line check tool in a pythonic API
#

import subprocess
import tempfile

def processcheck(command, args, inpt, output):
	'''Run a checking command, command, with arguments as args.
	Input is provided by inpt (an iterable), error output is
	written to output (a stream-like entity).

	Return a tuple (error, handle), where handle is a file handle
	(you must close it), containing output from the command.'''

	#
	# We use a tempfile for output, rather than a pipe, so we
	# don't deadlock with the child if both pipes fill.
	#
	try:
		tmpfile = tempfile.TemporaryFile(prefix=command, mode="w+b")
	except EnvironmentError as e:
		output.write("Could not create temporary file: %s\n" % e)
		return (3, None)

	try:
		p = subprocess.Popen([command] + args,
				     stdin=subprocess.PIPE, stdout=tmpfile,
				     stderr=subprocess.STDOUT, close_fds=False)
	except OSError as e:
		output.write("Could not execute %s: %s\n" % (command, e))
		return (3, None)

	for line in inpt:
		p.stdin.write(line)

	p.stdin.close()

	ret = p.wait()
	tmpfile.seek(0)

	return (ret < 0 and 1 or ret, tmpfile)
