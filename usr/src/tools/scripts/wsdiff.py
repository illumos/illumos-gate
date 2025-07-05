#!@TOOLS_PYTHON@ -Es
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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

#
# wsdiff(1) is a tool that can be used to determine which compiled objects
# have changed as a result of a given source change. Developers backporting
# new features, RFEs and bug fixes need to be able to identify the set of
# patch deliverables necessary for feature/fix realization on a patched system.
#
# The tool works by comparing objects in two trees/proto areas (one build with,
# and without the source changes.
#
# Using wsdiff(1) is fairly simple:
#	- Bringover to a fresh workspace
#	- Perform a full non-debug build (clobber if workspace isn't fresh)
#	- Move the proto area aside, call it proto.old, or something.
#	- Integrate your changes to the workspace
#	- Perform another full non-debug clobber build.
#	- Use wsdiff(1) to see what changed:
#		$ wsdiff proto.old proto
#
# By default, wsdiff will print the list of changed objects / deliverables to
# stdout. If a results file is specified via -r, the list of differing objects,
# and details about why wsdiff(1) thinks they are different will be logged to
# the results file.
#
# By invoking nightly(1) with the -w option to NIGHTLY_FLAGS, nightly(1) will
# use wsdiff(1) to report on what objects changed since the last build.
#
# For patch deliverable purposes, it's advised to have nightly do a clobber,
# non-debug build.
#
# Think about the results. Was something flagged that you don't expect? Go look
# at the results file to see details about the differences.
#
# Use the -i option in conjunction with -v and -V to dive deeper and have
# wsdiff(1) report with more verbosity.
#
# Usage: wsdiff [-dstuvV] [-U lines] [-r results ] [-i filelist ] old new
#
# Where "old" is the path to the proto area build without the changes, and
# "new" is the path to the proto area built with the changes. The following
# options are supported:
#
#       -d      Print debug messages about the progress
#       -i      Tell wsdiff which objects to compare via an input file list
#       -r      Log results and observed differences
#       -s      Produce sorted list of differences
#       -t      Use onbld tools in $SRC/tools
#       -u      Produce unified diff output
#       -U      Produce unified diff output with <lines> lines of context
#       -v      Do not truncate observed diffs in results
#       -V      Log *all* ELF sect diffs vs. logging the first diff found

from __future__ import print_function
import datetime, fnmatch, getopt, os, profile, io, subprocess
import re, resource, select, shutil, signal, string, struct, sys, tempfile
import time, threading
from stat import *

PY3 = sys.version_info[0] == 3

# Human readable diffs truncated by default if longer than this
# Specifying -v on the command line will override
diffs_sz_thresh = 4096
diff_args = ''

# Lock name	 Provides exclusive access to
# --------------+------------------------------------------------
# output_lock	 standard output or temporary file (difference())
# log_lock	 the results file (log_difference())
# wset_lock	 changedFiles list (workerThread())
output_lock = threading.Lock()
log_lock = threading.Lock()
wset_lock = threading.Lock()

# Variable for thread control
keep_processing = True

# Default search path for wsdiff
wsdiff_path = [ "/usr/bin",
		"/usr/ccs/bin",
		"/lib/svc/bin",
		"/opt/onbld/bin" ]

# These are objects that wsdiff will notice look different, but will not report.
# Existence of an exceptions list, and adding things here is *dangerous*,
# and therefore the *only* reasons why anything would be listed here is because
# the objects do not build deterministically, yet we *cannot* fix this.
#
wsdiff_exceptions = [
]

# Path to genunix, used for finding the proto root, and for CTF diff
genunix = "kernel/amd64/genunix"

if PY3:
	def getoutput(cmd):
		import shlex, tempfile
		f, fpath = tempfile.mkstemp()
		status = os.system("{ " + cmd + "; } >" +
			shlex.quote(fpath) + " 2>&1")
		returncode = os.WEXITSTATUS(status)
		with os.fdopen(f, mode="r", errors="ignore") as tfile:
			output = tfile.read()
		os.unlink(fpath)
		if output[-1:] == '\n':
			output = output[:-1]
		return returncode, output
else:
	import commands
	getoutput = commands.getstatusoutput

#####
# Logging routines
#

# Debug message to be printed to the screen, and the log file
def debug(msg) :

	# Add prefix to highlight debugging message
	msg = "## " + msg
	if debugon :
		output_lock.acquire()
		print(msg)
		sys.stdout.flush()
		output_lock.release()
		if logging :
			log_lock.acquire()
			print(msg, file=log)
			log.flush()
			log_lock.release()

# Informational message to be printed to the screen, and the log file
def info(msg) :

	output_lock.acquire()
	print(msg)
	sys.stdout.flush()
	output_lock.release()
	if logging :
		log_lock.acquire()
		print(msg, file=log)
		log.flush()
		log_lock.release()

# Error message to be printed to the screen, and the log file
def error(msg) :

	output_lock.acquire()
	print("ERROR: " + msg, file=sys.stderr)
	sys.stderr.flush()
	output_lock.release()
	if logging :
		log_lock.acquire()
		print("ERROR: " + msg, file=log)
		log.flush()
		log_lock.release()

# Informational message to be printed only to the log, if there is one.
def v_info(msg) :

	if logging :
		log_lock.acquire()
		print(msg, file=log)
		log.flush()
		log_lock.release()

#
# Flag a detected file difference
# Display the fileName to stdout, and log the difference
#
def difference(f, dtype, diffs) :

	if f in wsdiff_exceptions :
		return

	output_lock.acquire()
	if o_sorted :
		differentFiles.append(f)
	else:
		print(f)
		sys.stdout.flush()
	output_lock.release()

	log_difference(f, dtype, diffs)

#
# Do the actual logging of the difference to the results file
#
def log_difference(f, dtype, diffs) :

	if logging :
		log_lock.acquire()
		print(f, file=log)
		print("NOTE: " + dtype + " difference detected.", file=log)

		difflen = len(diffs)
		if difflen > 0 :
			print('', file=log)

			if not vdiffs and difflen > diffs_sz_thresh :
				print(diffs[:diffs_sz_thresh], file=log)
				print("... truncated due to length: " +
				      "use -v to override ...", file=log)
			else :
				print(diffs, file=log)
			print('\n', file=log)
		log.flush()
		log_lock.release()


#####
# diff generating routines
#

#
# Return human readable diffs from two files
#
def diffFileData(tmpf1, tmpf2) :

	binaries = False

	# Filter the data through od(1) if the data is detected
	# as being binary
	if isBinary(tmpf1) or isBinary(tmpf2) :
		binaries = True
		tmp_od1 = tmpf1 + ".od"
		tmp_od2 = tmpf2 + ".od"

		cmd = od_cmd + " -c -t x4" + " " + tmpf1 + " > " + tmp_od1
		os.system(cmd)
		cmd = od_cmd + " -c -t x4" + " " + tmpf2 + " > " + tmp_od2
		os.system(cmd)

		tmpf1 = tmp_od1
		tmpf2 = tmp_od2

	dcmd = "{} {} {} {}".format(diff_cmd, diff_args, tmpf1, tmpf2)
	try:
		rc, data = getoutput(dcmd)
		if rc == 0:
			# No differences found
			data = ''
		# If producing unified output, strip the first two lines
		# which just show the temporary file names.
		if diff_args:
			data = data.split("\n", 2)[-1]

		# Remove the temp files as we no longer need them.
		if binaries :
			try:
				os.unlink(tmp_od1)
				os.unlink(tmp_od2)
			except OSError as e:
				error("diffFileData: unlink failed {}"
				    .format(e))
	except:
		error("failed to get output of command: " + dcmd)

		# Send exception for the failed command up
		raise
		return

	return data

#####
# Misc utility functions
#

# Prune off the leading prefix from string s
def str_prefix_trunc(s, prefix) :
	snipLen = len(prefix)
	return s[snipLen:]

#
# Prune off leading proto path goo (if there is one) to yield
# the deliverable's eventual path relative to root
# e.g. proto.base/root_sparc/usr/src/cmd/prstat => usr/src/cmd/prstat
#
def fnFormat(fn) :
	global baseWsRoot, ptchWsRoot

	if (baseWsRoot and
	    len(os.path.commonprefix([fn, baseWsRoot])) == len(baseWsRoot)):
		return fn[len(baseWsRoot) + 1:]

	if (ptchWsRoot and
	    len(os.path.commonprefix([fn, ptchWsRoot])) == len(ptchWsRoot)):
		return fn[len(ptchWsRoot) + 1:]

	# Fall back to looking for the expected root_<arch>[-nd] string

	pos = fn.find("root_" + arch)
	if pos == -1 :
		return fn

	pos = fn.find("/", pos)
	if pos == -1 :
		return fn

	return fn[pos + 1:]

#
# Find the path to a proto root given the name of a file or directory under it
# e.g. proto.base/root_i386-nd/usr/bin => proto.base/root_i386-nd
#      root/usr/bin => root
#
def protoroot(fn):
	root = fn.rstrip('/')
	while len(root) > 1:
		if os.path.isfile(os.path.join(root, genunix)):
			return root
		root = os.path.dirname(root)

	# genunix was not found, try and determine the root by checking for
	# the expected root_<arch>[-nd] string

	pos = fn.find("root_" + arch)
	if pos == -1:
		return None

	pos = fn.find("/", pos)
	if pos == -1:
		return fn

	return fn[:pos]

#####
# Usage / argument processing
#

#
# Display usage message
#
def usage() :
	sys.stdout.flush()
	print("""Usage: wsdiff [-dstuvV] [-U lines] [-r results ] [-i filelist ] old new
        -d      Print debug messages about the progress
        -i      Tell wsdiff which objects to compare via an input file list
        -r      Log results and observed differences
        -s      Produce sorted list of differences
        -t      Use onbld tools in $SRC/tools
        -u      Produce unified diff output
        -U      Produce unified diff output with <lines> lines of context
        -v      Do not truncate observed diffs in results
        -V      Log *all* ELF sect diffs vs. logging the first diff found""",
	    file=sys.stderr)
	sys.exit(1)

#
# Process command line options
#
def args() :

	global debugon
	global logging
	global vdiffs
	global reportAllSects
	global o_sorted
	global diff_args

	validOpts = 'di:r:uU:vVst?'

	baseRoot = ""
	ptchRoot = ""
	fileNamesFile = ""
	results = ""
	localTools = False

	# getopt.getopt() returns:
	#	an option/value tuple
	#	a list of remaining non-option arguments
	#
	# A correct wsdiff invocation will have exactly two non option
	# arguments, the paths to the base (old), ptch (new) proto areas
	try:
		optlist, args = getopt.getopt(sys.argv[1:], validOpts)
	except getopt.error as val:
		usage()

	if len(args) != 2 :
		usage();

	for opt,val in optlist :
		if opt == '-d' :
			debugon = True
		elif opt == '-i' :
			fileNamesFile = val
		elif opt == '-r' :
			results = val
			logging = True
		elif opt == '-s' :
			o_sorted = True
		elif opt == '-u' :
			diff_args = '-u'
		elif opt == '-U' :
			diff_args = '-U' + str(val)
		elif opt == '-v' :
			vdiffs = True
		elif opt == '-V' :
			reportAllSects = True
		elif opt == '-t':
			localTools = True
		else:
			usage()

	baseRoot = args[0]
	ptchRoot = args[1]

	if len(baseRoot) == 0 or len(ptchRoot) == 0 :
		usage()

	if logging and len(results) == 0 :
		usage()

	if vdiffs and not logging :
		error("The -v option requires a results file (-r)")
		sys.exit(1)

	if reportAllSects and not logging :
		error("The -V option requires a results file (-r)")
		sys.exit(1)

	# alphabetical order
	return	baseRoot, fileNamesFile, localTools, ptchRoot, results

#####
# File identification
#

#
# Identify the file type.
# If it's not ELF, use the file extension to identify
# certain file types that require special handling to
# compare. Otherwise just return a basic "ASCII" type.
#
def getTheFileType(f) :

	extensions = { 'a'	:	'ELF Object Archive',
		       'jar'	:	'Java Archive',
		       'html'	:	'HTML',
		       'ln'	:	'Lint Library',
		       'db'	:	'Sqlite Database' }

	try:
		if os.stat(f)[ST_SIZE] == 0 :
			return 'ASCII'
	except:
		error("failed to stat " + f)
		return 'Error'

	if isELF(f) == 1 :
		return 'ELF'

	fnamelist = f.split('.')
	if len(fnamelist) > 1 :	# Test the file extension
		extension = fnamelist[-1]
		if extension in extensions.keys():
			return extensions[extension]

	return 'ASCII'

#
# Return non-zero if "f" is an ELF file
#
elfmagic = b'\177ELF'
def isELF(f) :
	try:
		with open(f, mode='rb') as fd:
			magic = fd.read(len(elfmagic))

		if magic == elfmagic :
			return 1
	except:
		pass
	return 0

#
# Return non-zero is "f" is binary.
# Consider the file to be binary if it contains any null characters
#
def isBinary(f) :
	try:
		with open(f, mode='rb') as fd:
			s = fd.read()

		if s.find(b'\0') == -1 :
			return 0
	except:
		pass
	return 1

#####
# Directory traversal and file finding
#

#
# Return a sorted list of files found under the specified directory
#
def findFiles(d) :
	for path, subdirs, files in os.walk(d) :
		files.sort()
		for name in files :
			yield os.path.join(path, name)

#
# Examine all files in base, ptch
#
# Return a list of files appearing in both proto areas,
# a list of new files (files found only in ptch) and
# a list of deleted files (files found only in base)
#
def protoCatalog(base, ptch) :

	compFiles = []		# List of files in both proto areas
	ptchList = []		# List of file in patch proto area

	newFiles = []		# New files detected
	deletedFiles = []	# Deleted files

	debug("Getting the list of files in the base area");
	baseFilesList = list(findFiles(base))
	baseStringLength = len(base)
	debug("Found " + str(len(baseFilesList)) + " files")

	debug("Getting the list of files in the patch area");
	ptchFilesList = list(findFiles(ptch))
	ptchStringLength = len(ptch)
	debug("Found " + str(len(ptchFilesList)) + " files")

	# Inventory files in the base proto area
	debug("Determining the list of regular files in the base area");
	for fn in baseFilesList :
		if os.path.islink(fn) :
			continue

		fileName = fn[baseStringLength:]
		compFiles.append(fileName)
	debug("Found " + str(len(compFiles)) + " files")

	# Inventory files in the patch proto area
	debug("Determining the list of regular files in the patch area");
	for fn in ptchFilesList :
		if os.path.islink(fn) :
			continue

		fileName = fn[ptchStringLength:]
		ptchList.append(fileName)
	debug("Found " + str(len(ptchList)) + " files")

	# Deleted files appear in the base area, but not the patch area
	debug("Searching for deleted files by comparing the lists")
	for fileName in compFiles :
		if not fileName in ptchList :
			deletedFiles.append(fileName)
	debug("Found " + str(len(deletedFiles)) + " deleted files")

	# Eliminate "deleted" files from the list of objects appearing
	# in both the base and patch proto areas
	debug("Eliminating deleted files from the list of objects")
	for fileName in deletedFiles :
		try:
			compFiles.remove(fileName)
		except:
			error("filelist.remove() failed")
	debug("List for comparison reduced to " + str(len(compFiles))
	    + " files")

	# New files appear in the patch area, but not the base
	debug("Getting the list of newly added files")
	for fileName in ptchList :
		if not fileName in compFiles :
			newFiles.append(fileName)
	debug("Found " + str(len(newFiles)) + " new files")

	return compFiles, newFiles, deletedFiles

#
# Examine the files listed in the input file list
#
# Return a list of files appearing in both proto areas,
# a list of new files (files found only in ptch) and
# a list of deleted files (files found only in base)
#
def flistCatalog(base, ptch, flist) :
	compFiles = []		# List of files in both proto areas
	newFiles = []		# New files detected
	deletedFiles = []	# Deleted files

	try:
		fd = open(flist, "r")
	except:
		error("could not open: " + flist)
		cleanup(1)

	files = []
	files = fd.readlines()
	fd.close()

	for f in files :
		ptch_present = True
		base_present = True

		if f == '\n' :
			continue

		# the fileNames have a trailing '\n'
		f = f.rstrip()

		# The objects in the file list have paths relative
		# to $ROOT or to the base/ptch directory specified on
		# the command line.
		# If it's relative to $ROOT, we'll need to add back the
		# root_`uname -p` goo we stripped off in fnFormat()
		if os.path.exists(base + f) :
			fn = f;
		elif os.path.exists(base + "root_" + arch + "/" + f) :
			fn = "root_" + arch + "/" + f
		else :
			base_present = False

		if base_present :
			if not os.path.exists(ptch + fn) :
				ptch_present = False
		else :
			if os.path.exists(ptch + f) :
				fn = f
			elif os.path.exists(ptch + "root_" + arch + "/" + f) :
				fn = "root_" + arch + "/" + f
			else :
				ptch_present = False

		if os.path.islink(base + fn) :	# ignore links
			base_present = False
		if os.path.islink(ptch + fn) :
			ptch_present = False

		if base_present and ptch_present :
			compFiles.append(fn)
		elif base_present :
			deletedFiles.append(fn)
		elif ptch_present :
			newFiles.append(fn)
		else :
			if (os.path.islink(base + fn) and
			    os.path.islink(ptch + fn)) :
				continue
			error(f + " in file list, but not in either tree. " +
			    "Skipping...")

	return compFiles, newFiles, deletedFiles


#
# Build a fully qualified path to an external tool/utility.
# Consider the default system locations. For onbld tools, if
# the -t option was specified, we'll try to use built tools in $SRC tools,
# and otherwise, we'll fall back on /opt/onbld/
#
def find_tool(tool) :

	# First, check what was passed
	if os.path.exists(tool) :
		return tool

	# Next try in wsdiff path
	for pdir in wsdiff_path :
		location = pdir + "/" + tool
		if os.path.exists(location) :
			return location + " "

		location = pdir + "/" + arch + "/" + tool
		if os.path.exists(location) :
			return location + " "

	error("Could not find path to: " + tool);
	sys.exit(1);


#####
# ELF file comparison helper routines
#

#
# Return a dictionary of ELF section types keyed by section name
#
def get_elfheader(f) :

	header = {}

	rc, hstring = getoutput(elfdump_cmd + " -c " + f)

	if len(hstring) == 0 :
		error("Failed to dump ELF header for " + f)
		raise
		return

	# elfdump(1) dumps the section headers with the section name
	# following "sh_name:", and the section type following "sh_type:"
	sections = hstring.split("Section Header")
	for sect in sections :
		datap = sect.find("sh_name:");
		if datap == -1 :
			continue
		section = sect[datap:].split()[1]
		datap = sect.find("sh_type:");
		if datap == -1 :
			error("Could not get type for sect: " + section +
			      " in " + f)
		sh_type = sect[datap:].split()[2]
		header[section] = sh_type

	return header

#
# Extract data in the specified ELF section from the given file
#
def extract_elf_section(f, section) :

	rc, data = getoutput(dump_cmd + " -sn " + section + " " + f)

	if len(data) == 0 :
		error(dump_cmd + "yielded no data on section " + section +
		    " of " + f)
		raise
		return

	# dump(1) displays the file name to start...
	# get past it to the data itself
	dbegin = data.find(":") + 1
	data = data[dbegin:];

	return (data)

#
# Return a (hopefully meaningful) human readable set of diffs
# for the specified ELF section between f1 and f2
#
# Depending on the section, various means for dumping and diffing
# the data may be employed.
#

text_sections = [ '.text', '.init', '.fini' ]

# Helper to generate the requireed commands for diffing two .SUNW_ctf
# sections.
def diff_ctf(f1, f2):

	# Find genunix so that it can be used for parent CTF data when
	# appropriate.
	if diff_ctf.genunix1 is None:
		global genunix, baseWsRoot, ptchWsRoot

		if (baseWsRoot and ptchWsRoot and
		    os.path.isfile(os.path.join(baseWsRoot, genunix)) and
		    os.path.isfile(os.path.join(ptchWsRoot, genunix))):
			diff_ctf.genunix1 = os.path.join(baseWsRoot, genunix)
			diff_ctf.genunix2 = os.path.join(ptchWsRoot, genunix)
			debug("CTF: Found {}".format(diff_ctf.genunix1))
			debug("CTF: Found {}".format(diff_ctf.genunix2))
		else:
			# Could not find genunix, do the best we can.
			error("diff_ctf: Could not find genunix. " +
			    "CTF diffs will be less useful.")
			diff_ctf.genunix1 = diff_ctf.genunix2 = False

	# Determine if this is a merged file from genunix by looking
	# at the parent
	rc, data = getoutput("{} -h {}".format(ctfdump_cmd, f1))
	if rc != 0:
		error("Could not read CTF header: {}".format(data))
		return (None, None)

	parent = None
	for line in data.split('\n'):
		if line.strip().startswith('cth_parname'):
			try:
				parent = line.split('=')[1].strip()
				break
			except:
				pass

	cmd1 = cmd2 = "{} -c ".format(ctfdump_cmd)
	if parent == "genunix":
		if diff_ctf.genunix1 and diff_ctf.genunix2:
			cmd1 += "-p {} ".format(diff_ctf.genunix1)
			cmd2 += "-p {} ".format(diff_ctf.genunix2)
	elif parent is None or (len(parent) > 0 and parent != "(anon)"):
		error("Unknown CTF Parent: {}".format(parent))
		return (None, None)

	cmd1 += f1
	cmd2 += f2

	return (cmd1, cmd2)

diff_ctf.genunix1 = None
diff_ctf.genunix2 = None

def diff_elf_section(f1, f2, section, sh_type) :

	t = threading.current_thread()
	tmpFile1 = tmpDir1 + os.path.basename(f1) + t.name
	tmpFile2 = tmpDir2 + os.path.basename(f2) + t.name

	if ((sh_type == "SHT_RELA") or
	    (sh_type == "SHT_REL")): # relocation section
		cmd1 = elfdump_cmd + " -r " + f1 + " > " + tmpFile1
		cmd2 = elfdump_cmd + " -r " + f2 + " > " + tmpFile2
	elif (section == ".group") :
		cmd1 = elfdump_cmd + " -g " + f1 + " > " + tmpFile1
		cmd2 = elfdump_cmd + " -g " + f2 + " > " + tmpFile2
	elif (section == ".hash") :
		cmd1 = elfdump_cmd + " -h " + f1 + " > " + tmpFile1
		cmd2 = elfdump_cmd + " -h " + f2 + " > " + tmpFile2
	elif (section == ".dynamic") :
		cmd1 = elfdump_cmd + " -d " + f1 + " > " + tmpFile1
		cmd2 = elfdump_cmd + " -d " + f2 + " > " + tmpFile2
	elif (section == ".got") :
		cmd1 = elfdump_cmd + " -G " + f1 + " > " + tmpFile1
		cmd2 = elfdump_cmd + " -G " + f2 + " > " + tmpFile2
	elif (section == ".SUNW_cap") :
		cmd1 = elfdump_cmd + " -H " + f1 + " > " + tmpFile1
		cmd2 = elfdump_cmd + " -H " + f2 + " > " + tmpFile2
	elif (section == ".interp") :
		cmd1 = elfdump_cmd + " -i " + f1 + " > " + tmpFile1
		cmd2 = elfdump_cmd + " -i " + f2 + " > " + tmpFile2
	elif (section == ".symtab" or section == ".dynsym") :
		cmd1 = (elfdump_cmd + " -s -N " + section + " " + f1 +
		    " > " + tmpFile1)
		cmd2 = (elfdump_cmd + " -s -N " + section + " " + f2 +
		    " > " + tmpFile2)
	elif (section in text_sections) :
		# dis sometimes complains when it hits something it doesn't
		# know how to disassemble. Just ignore it, as the output
		# being generated here is human readable, and we've already
		# correctly flagged the difference.
		cmd1 = (dis_cmd + " -t " + section + " " + f1 +
		       " 2>/dev/null | grep -v disassembly > " + tmpFile1)
		cmd2 = (dis_cmd + " -t " + section + " " + f2 +
		       " 2>/dev/null | grep -v disassembly > " + tmpFile2)
	elif (section == ".SUNW_ctf"):
		(cmd1, cmd2) = diff_ctf(f1, f2)
		if not cmd1:
			return ""
		cmd1 += " > {}".format(tmpFile1)
		cmd2 += " > {}".format(tmpFile2)

	else :
		cmd1 = (elfdump_cmd + " -w " + tmpFile1 + " -N " +
		       section + " " + f1)
		cmd2 = (elfdump_cmd + " -w " + tmpFile2 + " -N " +
		       section + " " + f2)

	os.system(cmd1)
	os.system(cmd2)

	data = diffFileData(tmpFile1, tmpFile2)

	# remove temp files as we no longer need them
	try:
		os.unlink(tmpFile1)
		os.unlink(tmpFile2)
	except OSError as e:
		error("diff_elf_section: unlink failed {}".format(e))

	return (data)

#
# compare the relevant sections of two ELF binaries
# and report any differences
#
# Returns: 1 if any differenes found
#          0 if no differences found
#	  -1 on error
#

# Sections deliberately not considered when comparing two ELF
# binaries. Differences observed in these sections are not considered
# significant where patch deliverable identification is concerned.
sections_to_skip = [ ".SUNW_signature",
		     ".comment",
		     ".debug",
		     ".plt",
		     ".rela.bss",
		     ".rela.plt",
		     ".line",
		     ".note",
		     ".compcom",
		     ".SUNW_dof",
		     ]

sections_preferred = [ ".SUNW_ctf",
		       ".rodata.str1.8",
		       ".rodata.str1.1",
		       ".rodata",
		       ".data1",
		       ".data",
		       ".text",
		       ]

# Some sections must always be extracted and diffed to check that there are
# real differences.
sections_to_always_diff = [ ".SUNW_ctf" ]

def compareElfs(base, ptch, quiet) :

	global logging

	try:
		base_header = get_elfheader(base)
	except:
		return
	sections = list(base_header.keys())
	sections.sort()

	try:
		ptch_header = get_elfheader(ptch)
	except:
		return
	e2_only_sections = list(ptch_header.keys())
	e2_only_sections.sort()

	e1_only_sections = []

	fileName = fnFormat(base)

	# Derive the list of ELF sections found only in
	# either e1 or e2.
	for sect in sections :
		if not sect in e2_only_sections :
			e1_only_sections.append(sect)
		else :
			e2_only_sections.remove(sect)

	if len(e1_only_sections) > 0 :
		if quiet :
			return 1

		data = ""
		if logging :
			slist = ""
			for sect in e1_only_sections :
				slist = slist + sect + "\t"
			data = ("ELF sections found in " +
				base + " but not in " + ptch +
				"\n\n" + slist)

		difference(fileName, "ELF", data)
		return 1

	if len(e2_only_sections) > 0 :
		if quiet :
			return 1

		data = ""
		if logging :
			slist = ""
			for sect in e2_only_sections :
				slist = slist + sect + "\t"
			data = ("ELF sections found in " +
				ptch + " but not in " + base +
				"\n\n" + slist)

		difference(fileName, "ELF", data)
		return 1

	# Look for preferred sections, and put those at the
	# top of the list of sections to compare
	for psect in sections_preferred :
		if psect in sections :
			sections.remove(psect)
			sections.insert(0, psect)

	# Compare ELF sections
	first_section = True
	for sect in sections :

		if sect in sections_to_skip :
			continue

		try:
			s1 = extract_elf_section(base, sect);
		except:
			return

		try:
			s2 = extract_elf_section(ptch, sect);
		except:
			return

		if len(s1) != len (s2) or s1 != s2:
			if not quiet or sect in sections_to_always_diff:
				sh_type = base_header[sect]
				data = diff_elf_section(base, ptch,
							sect, sh_type)

				if len(data) == 0:
					continue # No differences

			if not quiet:
				# If all ELF sections are being reported, then
				# invoke difference() to flag the file name to
				# stdout only once. Any other section
				# differences should be logged to the results
				# file directly
				if not first_section :
					log_difference(fileName,
					    "ELF " + sect, data)
				else :
					difference(fileName, "ELF " + sect,
					    data)

			if not reportAllSects :
				return 1
			first_section = False

	return 0

#####
# recursively remove 2 directories
#
# Used for removal of temporary directory strucures (ignores any errors).
#
def clearTmpDirs(dir1, dir2) :

	if os.path.isdir(dir1) > 0 :
		shutil.rmtree(dir1, True)

	if os.path.isdir(dir2) > 0 :
		shutil.rmtree(dir2, True)


#####
# Archive object comparison
#
# Returns 1 if difference detected
#         0 if no difference detected
#        -1 on error
#
def compareArchives(base, ptch, fileType) :

	fileName = fnFormat(base)
	t = threading.current_thread()
	ArchTmpDir1 = tmpDir1 + os.path.basename(base) + t.name
	ArchTmpDir2 = tmpDir2 + os.path.basename(base) + t.name

	#
	# Be optimistic and first try a straight file compare
	# as it will allow us to finish up quickly.
	#
	if compareBasic(base, ptch, True, fileType) == 0 :
		return 0

	try:
		os.makedirs(ArchTmpDir1)
		os.makedirs(ArchTmpDir2)
	except OSError as e:
		error("compareArchives: makedir failed {}".format(e))
		return -1

	# copy over the objects to the temp areas, and
	# unpack them
	baseCmd = "cp -fp " + base + " " + ArchTmpDir1
	rc, output = getoutput(baseCmd)
	if rc != 0:
		error(baseCmd + " failed: " + output)
		clearTmpDirs(ArchTmpDir1, ArchTmpDir2)
		return -1

	ptchCmd = "cp -fp " + ptch + " " + ArchTmpDir2
	rc, output = getoutput(ptchCmd)
	if rc != 0:
		error(ptchCmd + " failed: " + output)
		clearTmpDirs(ArchTmpDir1, ArchTmpDir2)
		return -1

	bname = fileName.split('/')[-1]
	if fileType == "Java Archive" :
		baseCmd = ("cd " + ArchTmpDir1 + "; " + "jar xf " + bname +
			  "; rm -f " + bname + " META-INF/MANIFEST.MF")
		ptchCmd = ("cd " + ArchTmpDir2 + "; " + "jar xf " + bname +
			  "; rm -f " + bname + " META-INF/MANIFEST.MF")
	elif fileType == "ELF Object Archive" :
		baseCmd = ("cd " + ArchTmpDir1 + "; " + "/usr/ccs/bin/ar x " +
			  bname + "; rm -f " + bname)
		ptchCmd = ("cd " + ArchTmpDir2 + "; " + "/usr/ccs/bin/ar x " +
			  bname + "; rm -f " + bname)
	else :
		error("unexpected file type: " + fileType)
		clearTmpDirs(ArchTmpDir1, ArchTmpDir2)
		return -1

	os.system(baseCmd)
	os.system(ptchCmd)

	baseFlist = list(findFiles(ArchTmpDir1))
	ptchFlist = list(findFiles(ArchTmpDir2))

	# Trim leading path off base/ptch file lists
	flist = []
	for fn in baseFlist :
		flist.append(str_prefix_trunc(fn, ArchTmpDir1))
	baseFlist = flist

	flist = []
	for fn in ptchFlist :
		flist.append(str_prefix_trunc(fn, ArchTmpDir2))
	ptchFlist = flist

	for fn in ptchFlist :
		if not fn in baseFlist :
			difference(fileName, fileType,
				   fn + " added to " + fileName)
			clearTmpDirs(ArchTmpDir1, ArchTmpDir2)
			return 1

	for fn in baseFlist :
		if not fn in ptchFlist :
			difference(fileName, fileType,
				   fn + " removed from " + fileName)
			clearTmpDirs(ArchTmpDir1, ArchTmpDir2)
			return 1

		differs = compareOneFile((ArchTmpDir1 + fn),
		    (ArchTmpDir2 + fn), True)
		if differs :
			difference(fileName, fileType,
				   fn + " in " + fileName + " differs")
			clearTmpDirs(ArchTmpDir1, ArchTmpDir2)
			return 1

	clearTmpDirs(ArchTmpDir1, ArchTmpDir2)
	return 0

#####
# (Basic) file comparison
#
# Returns 1 if difference detected
#         0 if no difference detected
#        -1 on error
#
def compareBasic(base, ptch, quiet, fileType) :

	fileName = fnFormat(base);

	if quiet and os.stat(base)[ST_SIZE] != os.stat(ptch)[ST_SIZE] :
		return 1

	try:
		with open(base, 'rb') as fh:
			baseData = fh.read()
	except:
		error("could not open " + base)
		return -1

	try:
		with open(ptch, 'rb') as fh:
			ptchData = fh.read()
	except:
		error("could not open " + ptch)
		return -1

	if quiet :
		if baseData != ptchData :
			return 1
	else :
		if len(baseData) != len(ptchData) or baseData != ptchData :
			diffs = diffFileData(base, ptch)
			difference(fileName, fileType, diffs)
			return 1
	return 0


#####
# Compare two objects by producing a data dump from
# each object, and then comparing the dump data
#
# Returns: 1 if a difference is detected
#          0 if no difference detected
#         -1 upon error
#
def compareByDumping(base, ptch, quiet, fileType) :

	fileName = fnFormat(base);
	t = threading.current_thread()
	tmpFile1 = tmpDir1 + os.path.basename(base) + t.name
	tmpFile2 = tmpDir2 + os.path.basename(ptch) + t.name

	if fileType == "Lint Library" :
		baseCmd = (lintdump_cmd + " -ir " + base +
			  " | egrep -v '(LINTOBJ|LINTMOD):'" +
			  " | grep -v PASS[1-3]:" +
			  " > " + tmpFile1)
		ptchCmd = (lintdump_cmd + " -ir " + ptch +
			  " | egrep -v '(LINTOBJ|LINTMOD):'" +
			  " | grep -v PASS[1-3]:" +
			  " > " + tmpFile2)
	elif fileType == "Sqlite Database" :
		baseCmd = ("echo .dump | " + sqlite_cmd + " -init /dev/null " +
                           base + " > " + tmpFile1)
		ptchCmd = ("echo .dump | " + sqlite_cmd + " -init /dev/null " +
                           ptch + " > " + tmpFile2)

	os.system(baseCmd)
	os.system(ptchCmd)

	try:
		with open(tmpFile1, 'rb') as fh:
			baseData = fh.read()
	except:
		error("could not open: " + tmpFile1)
		return

	try:
		with open(tmpFile2, 'rb') as fh:
			ptchData = fh.read()
	except:
		error("could not open: " + tmpFile2)
		return

	ret = 0

	if len(baseData) != len(ptchData) or baseData != ptchData :
		if not quiet :
			data = diffFileData(tmpFile1, tmpFile2);
		ret = 1

	# Remove the temporary files now.
	try:
		os.unlink(tmpFile1)
		os.unlink(tmpFile2)
	except OSError as e:
		error("compareByDumping: unlink failed {}".format(e))

	return ret

#####
#
# SIGINT signal handler. Changes thread control variable to tell the threads
# to finish their current job and exit.
#
def discontinue_processing(signl, frme):
	global keep_processing

	print("Caught Ctrl-C, stopping the threads", file=sys.stderr)
	keep_processing = False

	return 0

#####
#
# worker thread for changedFiles processing
#
class workerThread(threading.Thread) :
	def run(self):
		global wset_lock
		global changedFiles
		global baseRoot
		global ptchRoot
		global keep_processing

		while (keep_processing) :
			# grab the lock to changedFiles and remove one member
			# and process it
			wset_lock.acquire()
			try :
				fn = changedFiles.pop()
			except IndexError :
				# there is nothing more to do
				wset_lock.release()
				return
			wset_lock.release()

			base = baseRoot + fn
			ptch = ptchRoot + fn

			compareOneFile(base, ptch, False)


#####
# Compare two objects. Detect type changes.
# Vector off to the appropriate type specific
# compare routine based on the type.
#
def compareOneFile(base, ptch, quiet) :

	# Verify the file types.
	# If they are different, indicate this and move on
	btype = getTheFileType(base)
	ptype = getTheFileType(ptch)

	if btype == 'Error' or ptype == 'Error' :
		return -1

	fileName = fnFormat(base)

	if (btype != ptype) :
		if not quiet :
			difference(fileName, "file type",
			    btype + " to " + ptype)
		return 1
	else :
		fileType = btype

	if (fileType == 'ELF') :
		return compareElfs(base, ptch, quiet)

	elif (fileType == 'Java Archive' or fileType == 'ELF Object Archive') :
		return compareArchives(base, ptch, fileType)

	elif (fileType == 'HTML') :
		return compareBasic(base, ptch, quiet, fileType)

	elif ( fileType == 'Lint Library' ) :
		return compareByDumping(base, ptch, quiet, fileType)

	elif ( fileType == 'Sqlite Database' ) :
		return compareByDumping(base, ptch, quiet, fileType)

	else :
		# it has to be some variety of text file
		return compareBasic(base, ptch, quiet, fileType)

# Cleanup and self-terminate
def cleanup(ret) :

	debug("Performing cleanup (" + str(ret) + ")")
	if os.path.isdir(tmpDir1) > 0 :
		shutil.rmtree(tmpDir1)

	if os.path.isdir(tmpDir2) > 0 :
		shutil.rmtree(tmpDir2)

	if logging :
		log.close()

	sys.exit(ret)

def main() :

	# Log file handle
	global log

	# Globals relating to command line options
	global logging, vdiffs, reportAllSects

	# Named temporary files / directories
	global tmpDir1, tmpDir2

	# Command paths
	global lintdump_cmd, elfdump_cmd, dump_cmd, dis_cmd, od_cmd, \
	    diff_cmd, sqlite_cmd, ctfdump_cmd

	# Default search path
	global wsdiff_path

	# Essentially "uname -p"
	global arch

	# changed files for worker thread processing
	global changedFiles

	global baseRoot, ptchRoot, baseWsRoot, ptchWsRoot

	# Sort the list of files from a temporary file
	global o_sorted
	global differentFiles

	# Debugging indicator
	global debugon

	# Some globals need to be initialized
	debugon = logging = vdiffs = reportAllSects = o_sorted = False

	# Process command line arguments
	# Return values are returned from args() in alpha order
	# (Yes, python functions can return multiple values (ewww))
	# Note that args() also set the globals:
	#	logging to True if verbose logging (to a file) was enabled
	#	vdiffs to True if logged differences aren't to be truncated
	#	reportAllSects to True if all ELF section differences are to
	#	be reported
	#
	baseRoot, fileNamesFile, localTools, ptchRoot, results = args()

	#
	# Set up the results/log file
	#
	if logging :
		try:
			log = open(results, "w")
		except:
			logging = False
			error("failed to open log file: {}".format(log))
			sys.exit(1)

		v_info("# This file was produced by wsdiff")
		dateTimeStr= time.strftime('# %Y-%m-%d at %H:%M:%S',
		    time.localtime())
		v_info(dateTimeStr)

	# Changed files (used only for the sorted case)
	if o_sorted :
		differentFiles = []

	#
	# Build paths to the tools required tools
	#
	# Try to look for tools in $SRC/tools if the "-t" option
	# was specified
	#
	rc, arch = getoutput("uname -p")
	arch = arch.rstrip()
	if localTools :
		try:
			src = os.environ['SRC']
		except:
			error("-t specified, but $SRC not set. " +
			    "Cannot find $SRC/tools")
			src = ""
		if len(src) > 0 :
			wsdiff_path.insert(0,
			    src + "/tools/proto/opt/onbld/bin")

	lintdump_cmd = find_tool("lintdump")
	elfdump_cmd = find_tool("elfdump")
	dump_cmd = find_tool("dump")
	od_cmd = find_tool("od")
	dis_cmd = find_tool("dis")
	diff_cmd = find_tool("diff")
	sqlite_cmd = find_tool("sqlite")
	ctfdump_cmd = find_tool("ctfdump")

	#
	# Set resource limit for number of open files as high as possible.
	# This might get handy with big number of threads.
	#
	(nofile_soft, nofile_hard) = resource.getrlimit(resource.RLIMIT_NOFILE)
	try:
		resource.setrlimit(resource.RLIMIT_NOFILE,
		    (nofile_hard, nofile_hard))
	except:
		error("cannot set resource limits for number of open files")
		sys.exit(1)

	#
	# validate the base and patch paths
	#
	baseRoot = os.path.abspath(baseRoot) + os.sep
	ptchRoot = os.path.abspath(ptchRoot) + os.sep

	if not os.path.exists(baseRoot) :
		error("old proto area: {} does not exist".format(baseRoot))
		sys.exit(1)

	if not os.path.exists(ptchRoot) :
		error("new proto area: {} does not exist".format(ptchRoot))
		sys.exit(1)

	#
	# attempt to find the workspace root directory for the proto area
	#
	baseWsRoot = protoroot(baseRoot)
	ptchWsRoot = protoroot(ptchRoot)
	debug("base workspace root: {}".format(baseWsRoot))
	debug("ptch workspace root: {}".format(ptchWsRoot))

	#
	# log some information identifying the run
	#
	v_info("Old proto area: {}".format(baseRoot))
	v_info("New proto area: {}".format(ptchRoot))
	v_info("Results file: {}".format(results))
	v_info("")

	#
	# Set up the temporary directories / files
	# Could use python's tmpdir routines, but these should
	# be easier to identify / keep around for debugging
	pid = os.getpid()
	tmpDir1 = "/tmp/wsdiff_tmp1_" + str(pid) + "/"
	tmpDir2 = "/tmp/wsdiff_tmp2_" + str(pid) + "/"
	try:
		os.makedirs(tmpDir1)
		os.makedirs(tmpDir2)
	except OSError as e:
		error("main: makedir failed {}".format(e))

	# Derive a catalog of new, deleted, and to-be-compared objects
	# either from the specified base and patch proto areas, or from
	# from an input file list
	newOrDeleted = False

	if fileNamesFile != "" :
		changedFiles, newFiles, deletedFiles = \
			      flistCatalog(baseRoot, ptchRoot, fileNamesFile)
	else :
		changedFiles, newFiles, deletedFiles = \
				protoCatalog(baseRoot, ptchRoot)

	if len(newFiles) > 0 :
		newOrDeleted = True
		info("\nNew objects found: ")

		if o_sorted :
			newFiles.sort()
		for fn in newFiles :
			info(fnFormat(fn))

	if len(deletedFiles) > 0 :
		newOrDeleted = True
		info("\nObjects removed: ")

		if o_sorted :
			deletedFiles.sort()
		for fn in deletedFiles :
			info(fnFormat(fn))

	if newOrDeleted :
		info("\nChanged objects: ")
	if o_sorted :
		debug("The list will appear after the processing is done")

	# Here's where all the heavy lifting happens
	# Perform a comparison on each object appearing in
	# both proto areas. compareOneFile will examine the
	# file types of each object, and will vector off to
	# the appropriate comparison routine, where the compare
	# will happen, and any differences will be reported / logged

	# determine maximum number of worker threads by using
	# DMAKE_MAX_JOBS environment variable set by nightly(1)
	# or get number of CPUs in the system
	try:
		max_threads = int(os.environ['DMAKE_MAX_JOBS'])
	except:
		max_threads = os.sysconf("SC_NPROCESSORS_ONLN")
		# If we cannot get number of online CPUs in the system
		# run unparallelized otherwise bump the number up 20%
		# to achieve best results.
		if max_threads == -1 :
			max_threads = 1
		else :
			max_threads += int(max_threads/5)

	# Set signal handler to attempt graceful exit
	debug("Setting signal handler")
	signal.signal( signal.SIGINT, discontinue_processing )

	# Create and unleash the threads
	# Only at most max_threads must be running at any moment
	mythreads = []
	debug("Spawning " + str(max_threads) + " threads");
	for i in range(max_threads) :
		thread = workerThread()
		mythreads.append(thread)
		mythreads[i].start()

	# Wait for the threads to finish and do cleanup if interrupted
	debug("Waiting for the threads to finish")
	while True:
		if not True in [thread.is_alive() for thread in mythreads]:
		    break
		else:
		    # Some threads are still going
		    time.sleep(1)

	# Interrupted by SIGINT
	if keep_processing == False :
		cleanup(1)

	# If the list of differences was sorted it is stored in an array
	if o_sorted :
		differentFiles.sort()
		for f in differentFiles :
			info(fnFormat(f))

	# We're done, cleanup.
	cleanup(0)

if __name__ == '__main__' :
	try:
		main()
	except KeyboardInterrupt :
		cleanup(1);
