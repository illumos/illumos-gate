########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1994-2012 AT&T Intellectual Property          #
#                      and is licensed under the                       #
#                 Eclipse Public License, Version 1.0                  #
#                    by AT&T Intellectual Property                     #
#                                                                      #
#                A copy of the License is available at                 #
#          http://www.eclipse.org/org/documents/epl-v10.html           #
#         (with md5 checksum b35adb5213ca9657e911e9befb180842)         #
#                                                                      #
#              Information and Software Systems Research               #
#                            AT&T Research                             #
#                           Florham Park NJ                            #
#                                                                      #
#                 Glenn Fowler <gsf@research.att.com>                  #
#                                                                      #
########################################################################
### this script contains archaic constructs that work with all sh variants ###
# package - source and binary package control
# Glenn Fowler <gsf@research.att.com>

command=package

case $-:$BASH_VERSION in
*x*:[0123456789]*)	: bash set -x is broken :; set +ex ;;
esac

# ksh checks -- ksh between 2007-11-05 and 2011-11-11 conflict with new -lcmd -- wea culpa
checksh()
{
	egrep 'Version.*(88|1993)' $1 >/dev/null 2>&1 ||
	$1 -c '(( .sh.version >= 20111111 ))' >/dev/null 2>&1
}

case $_AST_BIN_PACKAGE_:$SHELL:$0 in
1:*:*|*:/bin/sh:*)
	;;
*:*/*:*/*)
	_AST_BIN_PACKAGE_=1 # prevent non-interactive sh .rc referencing bin/package recursion #
	export _AST_BIN_PACKAGE_
	if	checksh $SHELL
	then	: no -lcmd conflict :
	else	case " $* " in
		*" debug "*|*" DEBUG "*|*" show "*)
			echo $command: $SHELL: warning: possible -lcmd conflict -- falling back to /bin/sh >&2
			;;
		esac
		SHELL=/bin/sh
		export SHELL
		exec $SHELL "$0" "$@"
	fi
	;;
esac

LC_ALL=C
export LC_ALL

src="cmd contrib etc lib"
use="/usr/common /exp /usr/local /usr/add-on /usr/addon /usr/tools /usr /opt"
usr="/home"
lib="" # nee /usr/local/lib /usr/local/shlib
ccs="/usr/kvm /usr/ccs/bin"
org="gnu GNU"
makefiles="Mamfile Nmakefile nmakefile Makefile makefile"
env="HOSTTYPE NPROC PACKAGEROOT INSTALLROOT PATH"
checksum=md5sum
checksum_commands="$checksum md5"
checksum_empty="d41d8cd98f00b204e9800998ecf8427e"

package_use='=$HOSTTYPE=$PACKAGEROOT=$INSTALLROOT=$EXECROOT=$CC='

PACKAGE_admin_tail_timeout=${PACKAGE_admin_tail_timeout:-"1m"}

CROSS=0

admin_db=admin.db
admin_env=admin.env
admin_ditto="ditto --checksum --delete --verbose"
admin_ditto_update=--update
admin_ditto_skip="OFFICIAL|core|old|*.core|*.tmp|.nfs*"
admin_list='PACKAGE.$type.lst'
admin_ping="ping -c 1 -w 5"

default_url=default.url
MAKESKIP=${MAKESKIP:-"*[-.]*"}
RATZ=ratz
SED=
TAR=tar
TARFLAGS=xv
TARPROBE=B
TR=

all_types='*.*|sun4'		# all but sun4 match *.*

case `(getopts '[-][123:xyz]' opt --xyz; echo 0$opt) 2>/dev/null` in
0123)	USAGE=$'
[-?
@(#)$Id: package (AT&T Research) 2012-06-28 $
]'$USAGE_LICENSE$'
[+NAME?package - source and binary package control]
[+DESCRIPTION?The \bpackage\b command controls source and binary
    packages. It is a \bsh\b(1) script coded for maximal portability. All
    package files are in the \b$PACKAGEROOT\b directory tree.
    \b$PACKAGEROOT\b must at minumum contain a \bbin/package\b command or a
    \blib/package\b directory. Binary package files are in the
    \b$INSTALLROOT\b (\b$PACKAGEROOT/arch/\b\ahosttype\a) tree, where
    \ahosttpe\a=`\bpackage\b`. All \aactions\a but \bhost\b and \buse\b
    require the current directory to be under \b$PACKAGEROOT\b. See
    \bDETAILS\b for more information.]
[+?Note that no environment variables need be set by the user;
    \bpackage\b determines the environment based on the current working
    directory. The \buse\b action starts a \bsh\b(1) with the environment
    initialized. \bCC\b, \bCCFLAGS\b, \bHOSTTYPE\b and \bSHELL\b may be set
    by explicit command argument assignments to override the defaults.]
[+?Packages are composed of components. Each component is built and
    installed by an \bast\b \bnmake\b(1) makefile. Each package is also
    described by an \bnmake\b makefile that lists its components and
    provides a content description. The package makefile and component
    makefiles provide all the information required to read, write, build
    and install packages.]
[+?Package recipients only need \bsh\b(1) and \bcc\b(1) to build and
    install source packages, and \bsh\b to install binary packages.
    \bnmake\b and \bksh93\b are required to write new packages. An
    \b$INSTALLROOT/bin/cc\b script may be supplied for some architectures.
    This script supplies a reasonable set of default options for compilers
    that accept multiple dialects or generate multiple object/executable
    formats.]
[+?The command arguments are composed of a sequence of words: zero or
    more \aqualifiers\a, one \aaction\a, and zero or more action-specific
    \aarguments\a, and zero or more \aname=value\a definitions. \apackage\a
    names a particular package. The naming scheme is a \b-\b separated
    hierarchy; the leftmost parts describe ownership, e.g.,
    \bgnu-fileutils\b, \bast-base\b. If no packages are specified then all
    packages are operated on. \boptget\b(3) documentation options are also
    supported. The default with no arguments is \bhost type\b.]
[+?The qualifiers are:]
    {
        [+authorize \aname\a?Remote authorization user name or license
            acceptance phrase.]
        [+debug|environment?Show environment and actions but do not
            execute.]
        [+flat?Collapse \b$INSTALLROOT\b { bin fun include lib } onto
            \b$PACKAGEROOT\b.]
        [+force?Force the action to override saved state.]
        [+never?Run make -N and show other actions.]
        [+only?Only operate on the specified packages.]
        [+password \apassword\a?Remote authorization or license
	    acceptance password.]
        [+quiet?Do not list captured action output.]
        [+show?Run make -n and show other actions.]
        [+verbose?Provide detailed action output.]
        [+DEBUG?Trace the package script actions in detail.]
    }
[+?The actions are:]
    {
        [+admin\b [\ball\b]] [\bdb\b \afile\a]] [\bon\b \apattern\a]][\aaction\a ...]]?Apply
            \aaction\a ... to the hosts listed in \afile\a. If \afile\a is
            omitted then \badmin.db\b is assumed. The caller must have
            \brcp\b(1) and \brsh\b(1) or \bscp\b(1) and \bssh\b(1) access
            to the hosts. Output for \aaction\a is saved per-host in the
            file \aaction\a\b.log/\b\ahost\a. Logs can be viewed by
            \bpackage admin\b [\bon\b \ahost\a]] \bresults\b [\aaction\a]].
            By default only local PACKAGEROOT hosts are selected from
            \afile\a; \ball\b selects all hosts. \bon\b \apattern\a selects
            only hosts matching the \b|\b separated \apattern\a. \afile\a
            contains four types of lines. Blank lines and lines beginning
            with \b#\b are ignored. Lines starting with \aid\a=\avalue\a
            are variable assignments. Set admin_ping to local conventions
            if \"'$admin_ping$'\" fails. If a package list is not specified
            on the command line the \aaction\a applies to all packages; a
            variable assigment \bpackage\b=\"\alist\a\" applies \aaction\a
            to the packages in \alist\a for subsequent hosts in \afile\a.
            The remaining line type is a host description consisting of 6
            tab separated fields. The first 3 are mandatory; the remaining
            3 are updated by the \badmin\b action. \afile\a is saved in
            \afile\a\b.old\b before update. The fields are:]
            {
                [+hosttype?The host type as reported by
                    \"\bpackage\b\".]
                [+[user@]]host?The host name and optionally user name
                    for \brcp\b(1) and \brsh\b(1) access.]
                [+[remote::[[master]]::]]]]PACKAGEROOT?The absolute remote package
                    root directory and optionally the remote protocol (rsh
                    or ssh) if the directory is on a different server than
                    the master package root directory. If
                    \blib/package/admin/'$admin_env$'\b exists under this
                    directory then it is sourced by \bsh\b(1) before
                    \aaction\a is done. If this field begins with \b-\b
                    then the host is ignored. If this field contains \b:\b
                    then \bditto\b(1) is used to sync the remote \bsrc\b
                    directory hierarchy to the local one. If [\amaster\a]]:
		    is specified then the sync is deferred to the \amaster\a
		    host. If \amaster\a is omitted (two :) then the sync is
		    disabled. These directories must exist on the remote side:
		    \blib/package\b, \bsrc/cmd\b, \bsrc/lib\b.]
                [+date?\aYYMMDD\a of the last action.]
                [+time?Elapsed wall time for the last action.]
                [+M T W?The \badmin\b action \bmake\b, \btest\b and
                    \bwrite\b action error counts. A non-numeric value in
                    any of these fields disables the corresponding action.]
	    	[+owner?The owner contact information.]
		[+attributes?\aname=value\a attributes. Should at least contain
		    \bcc\b=\acompiler-version\a.]
            }
	[+clean | clobber?Delete the \barch/\b\aHOSTTYPE\a hierarchy; this
	    deletes all generated files and directories for \aHOSTTYPE\a.
	    The heirarchy can be rebuilt by \bpackage make\b.]
        [+contents\b [ \apackage\a ... ]]?List description and
            components for \apackage\a on the standard output.]
        [+copyright\b [ \apackage\a ... ]]?List the general copyright
            notice(s) for \apackage\a on the standard output. Note that
            individual components in \apackage\a may contain additional or
            replacement notices.]
        [+export\b [ \avariable\a ...]]?List \aname\a=\avalue\a for
            \avariable\a, one per line. If the \bonly\b attribute is
            specified then only the variable values are listed. If no
	    variables are specified then \b'$env$'\b are assumed.]
        [+help\b [ \aaction\a ]]?Display help text on the standard
            error (standard output for \aaction\a).]
        [+host\b [ \aattribute\a ... ]]?List
            architecture/implementation dependent host information on the
            standard output. \btype\b is listed if no attributes are
            specified. Information is listed on a single line in
            \aattribute\a order. The attributes are:]
            {
                [+canon \aname\a?An external host type name to be
                    converted to \bpackage\b syntax.]
                [+cpu?The number of cpus; 1 if the host is not a
                    multiprocessor.]
                [+name?The host name.]
                [+rating?The cpu rating in pseudo mips; the value is
                    useful useful only in comparisons with rating values of
                    other hosts. Other than a vax rating (mercifully) fixed
                    at 1, ratings can vary wildly but consistently from
                    vendor mips ratings. \bcc\b(1) may be required to
                    determine the rating.]
                [+type?The host type, usually in the form
                    \avendor\a.\aarchitecture\a, with an optional trailing
                    -\aversion\a. The main theme is that type names within
                    a family of architectures are named in a similar,
                    predictable style. OS point release information is
                    avoided as much as possible, but vendor resistance to
                    release incompatibilities has for the most part been
                    futile.]
            }
        [+html\b [ \aaction\a ]]?Display html help text on the standard
            error (standard output for \aaction\a).]
        [+install\b [ \aarchitecture\a ... ]] \adirectory\a [ \apackage\a ... ]]?Copy
            the package binary hierarchy to \adirectory\a. If
            \aarchitecture\a is omitted then all architectures are
            installed. If \bflat\b is specified then exactly one
            \aarchitecture\a must be specified; this architecture will be
            installed in \adirectory\a without the \barch/\b\aHOSTTYPE\a
            directory prefixes. Otherwise each architecture will be
            installed in a separate \barch/\b\aHOSTTYPE\a subdirectory of
            \adirectory\a. The \aarchitecture\a \b-\b names the current
            architecture. \adirectory\a must be an existing directory. If
            \apackage\a is omitted then all binary packages are installed.
            This action requires \bnmake\b.]
        [+license\b [ \apackage\a ... ]]?List the source license(s) for
            \apackage\a on the standard output. Note that individual
            components in \apackage\a may contain additional or replacement
            licenses.]
        [+list\b [ \apackage\a ... ]]?List the name, version and
            prerequisites for \apackage\a on the standard output.]
        [+make\b [ \apackage\a ]] [ \aoption\a ... ]] [ \atarget\a ... ]]?Build
	    and install. The default \atarget\a is \binstall\b, which makes
	    and installs \apackage\a. If the standard output is a terminal
	    then the output is also captured in
            \b$INSTALLROOT/lib/package/gen/make.out\b. The build is done in
            the \b$INSTALLROOT\b directory tree viewpathed on top of the
            \b$PACKAGEROOT\b directory tree. If \bflat\b is specified then
            the \b$INSTALLROOT\b { bin fun include lib } directories are
            linked to the same directories in the package root. Only one
            architecture may be \bflat\b. Leaf directory names matching the
            \b|\b-separated shell pattern \b$MAKESKIP\b are ignored. The
            \bview\b action is done before making. \aoption\a operands are
	    passed to the underlying make command.]
        [+read\b [ \apackage\a ... | \aarchive\a ... ]]?Read the named
            package or archive(s). Must be run from the package root
            directory. Archives are searched for in \b.\b and
            \blib/package/tgz\b. Each package archive is read only once.
            The file \blib/package/tgz/\b\apackage\a[.\atype\a]]\b.tim\b
            tracks the read time. See the \bwrite\b action for archive
            naming conventions. Text file archive member are assumed to be
            ASCII or UTF-8 encoded.]
        [+regress?\bdiff\b(1) the current and previous \bpackage test\b
            results.]
        [+release\b [ [\aCC\a]]\aYY-MM-DD\a [ [\acc\a]]\ayy-mm-dd\a ]]]] [ \apackage\a ]]?Display
            recent changes for the date range [\aCC\a]]\aYY-MM-DD\a (up to
        [\acc\a]]\ayy-mm-dd\a.), where \b-\b means lowest (or highest.)
            If no dates are specified then changes for the last 4 months
            are listed. \apackage\a may be a package or component name.]
        [+remove\b [ \apackage\a ]]?Remove files installed for
            \apackage\a.]
        [+results\b [ \bfailed\b ]] [ \bpath\b ]] [ \bold\b ]] [\bmake\b | \btest\b | \bwrite\b ]]?List
            results and interesting messages captured by the most recent
            \bmake\b (default), \btest\b or \bwrite\b action. \bold\b
            specifies the previous results, if any (current and previous
            results are retained.) \b$HOME/.pkgresults\b, if it exists,
            must contain an \begrep\b(1) expression of result lines to be
            ignored. \bfailed\b lists failures only and \bpath\b lists the
            results file path name only.]
        [+setup\b [ beta ]] [ binary ]] [ source ]] [ \aarchitecture\a ... ]] [ \aurl\a ]] [ \apackage\a ... ]]?This
            action initializes the current directory as a package root, runs the
            \bupdate\b action to download new or out of date packages, and runs the
            \bread\b action on those packages. If \bflat\b is specified then the
            \b$INSTALLROOT\b { bin fun include lib } directories are linked to the
            same directories in the package root. Only one architecture may be
            \bflat\b. See the \bupdate\b and \bread\b action descriptions for
            argument details.]
        [+test\b [ \apackage\a ]]?Run the regression tests for
            \apackage\a. If the standard output is a terminal then the
            output is also captured in
            \b$INSTALLROOT/lib/package/gen/test.out\b. In general a package
            must be made before it can be tested. Components tested with
            the \bregress\b(1) command require \bksh93\b. If \bonly\b is
	    also specified then only the listed package components are
	    tested, otherwise the closure of the components is tested.]
        [+update\b [ beta ]] [ binary ]] [ source ]] [\aarchitecture\a ... ]] [ \aurl\a ]] [ \apackage\a ... ]]?Download
            the latest release of the selected and required packages from \aurl\a
            (e.g., \bhttp://www.research.att.com/sw/download\b) into the directory
            \b$PACKAGEROOT/lib/package/tgz\b. \bbeta\b acesses beta packages;
            download these at your own risk. If \aarchitecture\a is omitted then
            only architectures already present in the \btgz\b directory will be
            downloaded. If \aarchitecture\a is \b-\b then all posted architectures
            will be downloaded. If \aurl\a matches \b*.url\b then it is interpreted
            as a file containing shell variable assignments for \burl\b,
            \bauthorize\b and \bpassword\b. If \aurl\a is omitted then the
            definitions for \burl\b, \bauthorize\b and \bpassword\b in
            \b$PACKAGEROOT/lib/package/tgz/default.url\b, if it exists, are used.
            If \b$PACKAGEROOT/lib/package/tgz/default.url\b does not exist then it
            is initialized with the current \burl\b, \bauthorize\b and \bpassword\b
            values and read permission for the current user only. If \apackage\a is
            omitted then only packages already present in the tgz directory will be
            downloaded. If \apackage\a is \b-\b then all posted packages will be
            downloaded. If \bsource\b and \bbinary\b are omitted then both source
            and binary packages will be downloaded. If \bonly\b is specified then
            only the named packages are updated; otherwise the closure of required
            packages is updated. This action requires \bwget\b(1), \blynx\b(1),
            \bcurl\b(1) or a shell that supports io to
	    \b/dev/tcp/\b\ahost\a/\aport\a.]
        [+use\b [ \auid\a | \apackage\a | . [ 32 | 64 ]] | 32 | 64 | - ]] [ command ...]]?Run
            \acommand\a, or an interactive shell if \acommand\a is omitted,
            with the environment initialized for using the package (can you
            say \ashared\a \alibrary\a or \adll\a without cussing?) If
            \auid\a or \apackage\a or \a.\a is specified then it is used
	    to determine a \b$PACKAGEROOT\b, possibly different from
	    the current directory. For example, to try out bozo`s package:
            \bpackage use bozo\b. The \buse\b action may be run from any
            directory. If the file \b$INSTALLROOT/lib/package/profile\b is
            readable then it is sourced to initialize the environment. 32 or 64
	    implies \b$PACKAGEROOT\b of . and specifies the target architecture
	    word size (which may be silently ignored.)]
        [+verify\b [ \apackage\a ]]?Verify installed binary files
            against the checksum files in
            \b$INSTALLROOT/lib/\b\apackage\a\b/gen/*.sum\b. The checksum
            files contain mode, user and group information. If the checksum
            matches for a given file then the mode, user and group are
            changed as necessary to match the checksum entry. A warning is
            printed on the standard error for each mismatch. Requires the
            \bast\b package \bcksum\b(1) command.]
        [+view\b?Initialize the architecture specific viewpath
            hierarchy. If \bflat\b is specified then the \b$INSTALLROOT\b {
            bin fun include lib } directories are linked to the same
            directories in the package root. Only one architecture may be
            \bflat\b. The \bmake\b action implicitly calls this action.]
        [+write\b [\aformat\a]] \atype\a ... [ \apackage\a ...]]?Write
            a package archive for \apackage\a. All work is done in the
            \b$PACKAGEROOT/lib/package\b directory. \aformat\a-specific
            files are placed in the \aformat\a subdirectory. A
            \apackage\a[.\atype\a]]\b.tim\b file in this directory tracks
            the write time and prevents a package from being read in the
            same root it was written. If more than one file is generated
            for a particular \aformat\a then those files are placed in the
            \aformat\a/\apackage\a subdirectory. File names in the
            \aformat\a subdirectory will contain the package name, a
            \ayyyy-mm-dd\a date, and for binary packages, \aHOSTTYPE\a. If
            \apackage\a is omitted then an ordered list of previously
            written packages is generated. If \bonly\b is specified then
            only the named packages will be written; otherwise prerequisite
            packages are written first. Package components must be listed
            in \apackage\a\b.pkg\b. \aformat\a may be one of:]
            {
                [+cyg?Generate a \bcygwin\b package.]
                [+exp?Generate an \bexptools\b maintainer source
                    archive and \aNPD\a file, suitable for \bexpmake\b(1)]
                [+lcl?Generate a package archive suitable for
                    restoration into the local source tree (i.e., the
                    source is not annotated for licencing.)]
                [+pkg?Generate a \bpkgmk\b(1) package suitable for
                    \bpkgadd\b(1).]
                [+rpm?Generate an \brpm\b(1) package.]
                [+tgz?Generate a \bgzip\b(1) \btar\b(1) package
                    archive. This is the default.]
                [+tst?Generate a \btgz\b format package archive in the
		    \btst\b subdirectory. Version state files are not updated.]
            }
        [+?\btype\b specifies the package type which must be one of
            \bsource\b, \bbinary\b or \bruntime\b. A source package
            contains the source needed to build the corresponding binary
            package. A binary package includes the libraries and headers
            needed for compiling and linking against the public interfaces.
            A runtime package contains the commands and required dynamic
            libraries.]
        [+?A package may be either a \bbase\b or \bdelta\b. A base
            package contains a complete copy of all components. A delta
            package contains only changes from a previous base package.
            Delta recipients must have the \bast\b \bpax\b(1) command (in
            the \bast-base\b package.) If neither \bbase\b nor \bdelta\b is
            specified, then the current base is overwritten if there are no
            deltas referring to the current base. Only the \btgz\b and
            \blcl\b formats support \bdelta\b. If \bbase\b is specified
            then a new base and two delta archives are generated: one delta
            to generate the new base from the old, and one delta to
            generate the old base from the new; the old base is then
            removed. If \bdelta\b is specified then a new delta referring
            to the current base is written.]
        [+?\apackage\a\b.pkg\b may reference other packages. By default
            a pointer to those packages is written. The recipient \bpackage
            read\b will then check that all required packages have been
            downloaded. If \bclosure\b is specified then the components for
            all package references are included in the generated package.
            This may be useful for \blcl\b and versioning.]
        [+?All formats but \blcl\b annotate each \bsource\b file (not
            already annotated) with a license comment as it is written to
            the package archive using \bproto\b(1).]
    }
[+DETAILS?The package directory hierarchy is rooted at
    \b$PACKAGEROOT\b. All source and binaries reside under this tree. A two
    level viewpath is used to separate source and binaries. The top view is
    architecture specific, the bottom view is shared source. All building
    is done in the architecture specific view; no source view files are
    intentionally changed. This means that many different binary
    architectures can be made from a single copy of the source.]
[+?Independent \b$PACKAGEROOT\b hierarchies can be combined by
    appending \b$INSTALLROOT:$PACKAGEROOT\b pairs to \bVPATH\b. The
    \bVPATH\b viewing order is from left to right. Each \b$PACKAGEROOT\b
    must have a \b$PACKAGEROOT/lib/package\b directory.]
[+?Each package contains one or more components. Component source for
    the \afoo\a command is in \b$PACKAGEROOT/src/cmd/\b\afoo\a, and source
    for the \abar\a library is in \b$PACKAGEROOT/src/lib/lib\b\abar\a. This
    naming is for convenience only; the underlying makefiles handle
    inter-component build order. The \bINIT\b component, which contains
    generic package support files, is always made first, then the
    components named \bINIT\b*, then the component order determined by the
    closure of component makefile dependencies.]
[+?\b$PACKAGEROOT/lib/package\b contains package specific files. The
    package naming convention is \agroup\a[-\apart\a]]; e.g., \bast-base\b,
    \bgnu-fileutils\b. The *\b.pkg\b files are ast \bnmake\b(1) makefiles
    that contain the package name, package components, references to other
    packages, and a short package description. *\b.pkg\b files are used by
    \bpackage write\b to generate new source and binary packages.]
[+?\b$PACKAGEROOT/lib/package/\b\agroup\a\b.lic\b files contain license
    information that is used by the \bast\b \bproto\b(1) and \bnmake\b(1)
    commands to generate source and binary license strings. \agroup\a is
    determined by the first \b:PACKAGE:\b operator name listed in the
    component \bnmake\b makefile. \agroup\a\b.lic\b files are part of the
    licensing documentation. Each component may have its own \bLICENSE\b file
    that overrides the \agroup\a\b.lic\b file. The full text of the licenses
    are in the \b$PACKAGEROOT/lib/package/LICENSES\b and
    \b$INSTALLROOT/lib/package/LICENSES\b directories.]
[+?A few files are generated in \b$PACKAGEROOT/lib/package/gen\b and
    \b$INSTALLROOT/lib/package/gen\b. \apackage\a\b.ver\b contains one line
    consisting of \apackage version release\a \b1\b for the most recent
    instance of \apackage\a read into \b$PACKAGEROOT\b, where \apackage\a
    is the package name, \aversion\a is the \aYYYY-MM-DD\a base version,
    and \arelease\a is \aversion\a for the base release or \aYYYY-MM-DD\a
    for delta releases. \apackage\a\b.req\b contains *\b.ver\b entries for
    the packages required by \apackage\a, except that the fourth field is
    \b0\b instead of \b1\b. All packages except \bINIT\b require the
    \bINIT\b package. A simple sort of \apackage\a\b.pkg\b and *\b.ver\b
    determines if the required package have been read in. Finally,
    \apackage\a\b.README\b and \apackage\a\a.html\b contain the README text
    for \apackage\a and all its components. Included are all changes added
    to the component \bRELEASE\b, \bCHANGES\b or \bChangeLog\b files dated
    since the two most recent base releases. Component \bRELEASE\b files
    contain tag lines of the form [\aYY\a]]\aYY-MM-DD\a [ \atext\a ]] (or
    \bdate\b(1) format dates) followed by README text, in reverse
    chronological order (newer entries at the top of the file.) \bpackage
    release\b lists this information, and \bpackage contents ...\b lists
    the descriptions and components.]
[+?\b$HOSTYPE\b names the current binary architecture and is determined
    by the output of \bpackage\b (no arguments.) The \b$HOSTTYPE\b naming
    scheme is used to separate incompatible executable and object formats.
    All architecture specific binaries are placed under \b$INSTALLROOT\b
    (\b$PACKAGEROOT/arch/$HOSTTYPE\b.) There are a few places that match
    against \b$HOSTTYPE\b when making binaries; these are limited to
    makefile compiler workarounds, e.g., if \b$HOSTTYPE\b matches \bhp.*\b
    then turn off the optimizer for these objects. All other architecture
    dependent logic is handled either by the \bast\b \biffe\b(1) command or
    by component specific configure scripts. Explicit \b$HOSTYPE\b
    values matching *,*cc*[,-*,...]] optionally set the default \bCC\b and
    \bCCFLAGS\b. This is handy for build farms that support different
    compilers on the same architecture.]
[+?Each component contains an \bast\b \bnmake\b(1) makefile (either
    \bNmakefile\b or \bMakefile\b) and a \bMAM\b (make abstract machine)
    file (\bMamfile\b.) A Mamfile contains a portable makefile description
    that is used by \bmamake\b(1) to simulate \bnmake\b. Currently there is
    no support for old-make/gnu-make makefiles; if the binaries are just
    being built then \bmamake\b will suffice; if source or makefile
    modifications are anticipated then \bnmake\b (in the \bast-base\b
    package) should be used. Mamfiles are automatically generated by
    \bpackage write\b.]
[+?Most component C source is prototyped. If \b$CC\b (default value
    \bcc\b) is not a prototyping C compiler then \bpackage make\b runs
    \bproto\b(1) on portions of the \b$PACKAGEROOT/src\b tree and places
    the converted output files in the \b$PACKAGEROOT/proto/src\b tree.
    Converted files are then viewpathed over the original source.
    \bproto\b(1) converts an ANSI C subset to code that is compatible with
    K&R, ANSI, and C++ dialects.]
[+?All scripts and commands under \b$PACKAGEROOT\b use \b$PATH\b
    relative pathnames (via the \bast\b \bpathpath\b(3) function); there
    are no imbedded absolute pathnames. This means that binaries generated
    under \b$PACKAGEROOT\b may be copied to a different root; users need
    only change their \b$PATH\b variable to reference the new installation
    root \bbin\b directory. \bpackage install\b installs binary packages in
    a new \b$INSTALLROOT\b.]

[ qualifier ... ] [ action ] [ arg ... ] [ n=v ... ]

[+SEE ALSO?\bautoconfig\b(1), \bcksum\b(1), \bexecrate\b(1), \bexpmake\b(1),
	\bgzip\b(1), \bmake\b(1), \bmamake\b(1), \bnmake\b(1), \bpax\b(1),
	\bpkgadd\b(1), \bpkgmk\b(1), \bproto\b(1), \bratz\b(1), \brpm\b(1),
	\bsh\b(1), \btar\b(1), \boptget\b(3)]
'
	case $* in
	help)	set -- --man ;;
	esac
	while	getopts -a $command "$USAGE" OPT
	do	:
	done
	shift $OPTIND-1
	;;
esac

# check the args

case $AR in
'')	AR=ar ;;
esac
case $CC in
'')	CC=cc ;;
esac
case $LD in
'')	LD=ld ;;
esac
case $NM in
'')	NM=nm ;;
esac

action=
admin_all=1
admin_on=
authorize=
bit=
exec=
flat=0
force=0
global=
hi=
html=0
ifs=${IFS-'
	 '}
lo=
make=
makeflags='-k -K'
nmakeflags=
nmakesep=
nl="
"
noexec=
only=0
output=
package_src=
password=
quiet=0
show=:
tab="        "
verbose=0
AUTHORIZE=
DEBUG=
HURL=
PROTOROOT=-
SHELLMAGIC=-

unset FIGNORE BINDIR DLLDIR ETCDIR FUNDIR INCLUDEDIR LIBDIR LOCALEDIR MANDIR SHAREDIR 2>/dev/null || true

while	:
do	case $# in
	0)	set host type ;;
	esac
	case $1 in
	admin|clean|clobber|contents|copyright|export|host|install|license|list|make|read|regress|release|remove|results|setup|test|update|use|verify|view|write|TEST)
		action=$1
		shift
		break
		;;
	authorize)
		case $# in
		1)	echo $command: $1: authorization user name argument expected >&2; exit 1 ;;
		esac
		shift
		authorize=$1
		shift
		continue
		;;
	debug|environment)
		exec=echo make=echo show=echo
		;;
	flat)	flat=1
		;;
	force)	force=1
		;;
	never)	exec=echo noexec=-N
		;;
	only)	only=1
		;;
	password)
		case $# in
		1)	echo $command: $1: authorization password argument expected >&2; exit 1 ;;
		esac
		shift
		password=$1
		shift
		continue
		;;
	quiet)	quiet=1
		;;
	show)	exec=echo noexec=-n
		;;
	verbose)verbose=1
		;;
	DEBUG)	DEBUG=1
		PS4='+$LINENO:$SECONDS+ '
		set -x
		;;
	help|HELP|html|man|--[?m]*)
		case $1 in
		help)	code=0
			case $2 in
			'')	exec 1>&2 ;;
			esac
			;;
		html)	code=0 html=1
			;;
		*)	code=2
			exec 1>&2
			;;
		esac
		case $html in
		1)	bO="<HTML>
<HEAD>
<TITLE>$2 package installation instructions</TITLE>
<HEAD>
<BODY bgcolor=white link=teal vlink=dimgray>"
			eO='</BODY>
</HTML>'
			bH="<CENTER><H3><FONT face=courier color=red>"
			eH='</FONT></H3></CENTER>'
			bP='<P>'
			bL='<P><TABLE cellpadding=0 cellspacing=2>'
			bL2='<P><TABLE border=0 cellpadding=0 cellspacing=2>'
			eL='</TABLE><P>'
			bT='<TR><TD align=right valign=top><B>'
			bD='</B></TD><TD align=left>'	eD='</TD></TR>'
			bB='<B>'			eB='</B>'
			bI='<I>'			eI='</I>'
			bX='<PRE>'			eX='</PRE>'
			bF='<TT>'			eF='</TT>'
			Camp='&amp;'
			Mcurl='<A href=../../man/man1/curl.html>curl</A>(1)'
			Mdate='<A href=../../man/man1/date.html>date</A>(1)'
			Mfile='<A href=../../man/man1/file.html>file</A>(1)'
			Mgunzip='<A href=../../man/man1/gzip.html>gunzip</A>(1)'
			Mhurl='<A href=../../man/man1/hurl.html>hurl</A>(1)'
			Mlynx='<A href=../../man/man1/lynx.html>lynx</A>(1)'
			Mnmake='<A href=../../man/man1/nmake.html>nmake</A>(1)'
			Mpackage='<A href=../../man/man1/package.html>package</A>(1)'
			Mproto='<A href=../../man/man1/proto.html>proto</A>(1)'
			Mratz='<A href=../../man/man1/ratz.html>ratz</A>'
			Mtar='<A href=../../man/man1/tar.html>tar</A>(1)'
			Mwget='<A href=../../man/man1/wget.html>wget</A>(1)'
			;;
		*)	bO=''				eO=''
			bH=''				eH=':'
			bP=''
			bL=''				eL=''
			bL2=''
			bT='  '
			bD=' '				eD=''
			bB=''				eB=''
			bI=''				eI=''
			bX=''				eX=''
			bF='"'				eF='"'
			Camp='&'
			Mcurl='curl(1)'
			Mdate='date(1)'
			Mfile='file(1)'
			Mgunzip='gunzip(1)'
			Mhurl='hurl(1)'
			Mlynx='lynx(1)'
			Mnmake='nmake(1)'
			Mpackage='package(1)'
			Mproto='proto(1)'
			Mratz='ratz'
			Mtar='tar(1)'
			Mwget='wget(1)'
			;;
		esac
		case $2 in
		binary)	echo "${bO}
${bH}Binary Package Installation Instructions${eH}
${bL}
${bT}(1)${bD}Do not install packages as ${bI}root/super-user${eI}. Although some components may
      have setuid executables, few must be owned by ${bI}root${eI}. These are best
      changed manually when the security implications are understood.${eD}
${bT}(2)${bD}Choose a package root directory and cd to it. This will be a local work
      area for all packages.${eD}
${bT}(3)${bD}These instructions bypass the ${bI}click to download${eI} package links on the
      download site. If you already clicked, or if your system does not have
      ${Mcurl}, ${Mhurl}, ${Mlynx} or ${Mwget} then use the alternate instructions
      for (3),(4),(5) in plan ${bB}B${eB} below. Plan ${bB}B${eB} installs the ${Mhurl}
      script which works with ksh and modern bash. The top level URL is:${bX}
		URL=http://www.research.att.com/sw/download${eX}${eD}
${bT}(4)${bD}If the ${bB}bin/package${eB} script does not exist then run:${bX}
		test -d bin || mkdir bin
		url=\$URL/package
		(wget -O - \$url||curl -L \$url||hurl \$url) > bin/package
		chmod +x bin/package${eX}${eD}
${bT}(5)${bD}Determine the list of package names you want from the download site, then
      use the ${Mpackage} command to do the actual download:${bX}
		bin/package authorize \"${bI}NAME${eI}\" password \"${bI}PASSWORD${eI}\" \\
			setup binary \$URL ${bI}PACKAGE${eI} ...${eX}
      (Refer to the ${bB}AUTHORIZATION${eB} paragraph on the main download page for
      ${bI}NAME${eI}/${bI}PASSWORD${eI} details.)  This downloads the closure of the latest
      binary package(s); covered and up-to-date packages are not downloaded again unless
      ${bB}package force ...${eB} is specified. Package content is verified using ${bB}${checksum}${eB}.
      If the package root will contain only one architecture then you can install in ${bB}bin${eB} and
      ${bB}lib${eB} instead of ${bB}arch/${eB}${bI}HOSTTYPE${eI}${bB}/bin${eB} and ${bB}arch/${eB}${bI}HOSTTYPE${eI}${bB}/lib${eB} by running this
      instead:${bX}
		bin/package authorize \"${bI}NAME${eI}\" password \"${bI}PASSWORD${eI}\" \\
			flat setup binary \$URL ${bB}PACKAGE${eB} ...${eX}
      To update the same packages from the same URL run:${bX}
		bin/package setup binary${eX}${eD}
${bT}(6)${bD}The packaged binaries are position independent, i.e., they do not
      contain hard-coded paths. However, commands with related files, like
      ${Mfile} and ${Mnmake}, require the path of the bin directory to be
      exported in ${bB}PATH${eb}.${eD}
${bT}(7)${bD}You can run the binaries directly from the package root, or you can
      install them in a public root (requires the ${bI}AT${Camp}T${eI} ${Mnmake} command):${bX}
		bin/package flat install ${bI}DIRECTORY PACKAGE${eI}${eX}
      This will install in ${bI}DIRECTORY${eI}${bB}/bin${eB} and ${bI}DIRECTORY${eI}${bB}/lib${eB}. If you want to
      preserve the ${bB}arch/${eB}${bI}HOSTTYPE${eI} hierarchy under ${bI}DIRECTORY${eI} then omit the
      ${bB}flat${eB} argument. If you don't have ${Mnmake} then the following will do a
      flat install:${bX}
		cd \$INSTALLROOT
		cp -p -r bin lib include ${bI}DIRECTORY${eI}${eX}${eD}
${bT}(8)${bD}To summarize, after the first time, the download cycle for the latest
      binary release is:${bX}
		bin/package setup binary${eX}${eD}${eL}

${bH}Binary Package Installation Instructions -- Plan B${eH}
${bL}
${bT}(3)${bD}Create the subdirectory ${bB}lib/package/tgz${eB} and download all package archives
      into that directory.${eD}
${bT}(4)${bD}If the ${bB}bin/package${eB} script does not exist then manually read the ${bB}INIT${eB}
      binary package:${bX}
		gunzip < lib/package/tgz/INIT.${bI}YYYY-MM-DD.HOSTTYPE${eI}.tgz |
			${TAR} ${TARFLAGS}f -${eX}
      Note that some browsers automatically unzip downloaded without warning.
      If the gunzip fails try:
		${TAR} ${TARFLAGS}f -${eX} lib/package/tgz/INIT.${bI}YYYY-MM-DD.HOSTTYPE${eI}.tgz
      If your system does not have ${Mtar} or ${Mgunzip} then download the ${Mratz}
      binary package:${bX}
		mkdir bin
		cp lib/package/tgz/ratz.${bI}YYYY-MM-DD.HOSTTYPE${eI}.exe bin/ratz
		chmod +x bin/ratz
		bin/ratz -lm < lib/package/tgz/INIT.${bI}YYYY-MM-DD/HOSTTYPE${eI}.tgz
${bT}(5)${bD}Read all unread package archive(s):${bX}
		bin/package read${eX}
      Both source and binary packages will be read by this step.${eD}${eL}${eO}"
			;;
		intro)	echo "${bO}
${bH}Package Hierarchy Details${eH}
${bP}
The package directory hierarchy is rooted at ${bB}\$PACKAGEROOT${eB}. All source and
binaries reside under this tree. A two level viewpath is used to separate
source and binaries. The top view is architecture specific, the bottom view
is shared source. All building is done in the architecture specific view;
no source view files are intentionally changed. This means that many
different binary architectures can be made from a single copy of the source.
${bP}
Each package contains one or more components. Component source for the ${bI}FOO${eI}
command is in ${bB}\$PACKAGEROOT/src/cmd/${eB}${bI}FOO${eI}, and source for the ${bI}BAR${eI} library is
in ${bB}\$PACKAGEROOT/src/lib/lib${eB}${bI}BAR${eI}. This naming is for convenience only; the
underlying makefiles handle inter-component build order. The ${bB}INIT${eB} component,
which contains generic package support files, is always made first, then the
components named ${bB}INIT${eB}*, then the order determined by the closure of component
makefile dependencies.
${bP}
${bB}\$PACKAGEROOT/lib/package${eB} contains package specific files. The package naming
convention is ${bI}GROUP${eI}[${bI}-PART${eI}]; e.g., ${bB}ast-base${eB}, ${bB}gnu-fileutils${eB}. The *${bB}.pkg${eB} files
are ${bB}ast${eB} ${Mnmake} makefiles that contain the package name, package components,
references to other packages, and a short package description. *${bB}.pkg${eB} files
are used by ${bF}package write${eF} to generate new source and binary packages.
${bP}
${bB}\$PACKAGEROOT/lib/package/${eB}${bI}GROUP${eI}${bB}.lic${eB} files contain license information that
is used by the ${bB}ast${eB} ${Mproto} and ${Mnmake} commands to generate source and
binary license strings. ${bI}GROUP${eI} is determined by the first ${bB}:PACKAGE:${eB} operator
name listed in the component ${bB}nmake${eB} makefile. ${bI}GROUP${eI}${bB}.lic${eB} files are part of the
licensing documentation.  Each component may have its own ${bB}LICENSE${eB} file that
overrides the ${bI}GROUP${eI}${bB}.lic${eB} file.  The full text of the licenses are in the
${bB}\$PACKAGEROOT/lib/package/LICENSES${eB} and ${bB}\$INSTALLROOT/lib/package/LICENSES${eB}
directories.
${bP}
A few files are generated in ${bB}\$PACKAGEROOT/lib/package/gen${eB} and
${bB}\$INSTALLROOT/lib/package/gen${eB}. ${bI}PACKAGE${eI}${bB}.ver${eB} contains one line consisting of${bX}
	${bI}PACKAGE VERSION RELEASE${eI} 1${eX}
for the most recent instance of ${bI}PACKAGE${eI} read into ${bB}\$PACKAGEROOT${eB}, where
${bI}PACKAGE${eI} is the package name, ${bI}VERSION${eI} is the ${bI}YYYY-MM-DD${eI} base version,
and ${bI}RELEASE${eI} is ${bI}VERSION${eI} for the base release or ${bI}YYYY-MM-DD${eI} for delta releases.
${bI}PACKAGE${eI}${bB}.req${eB} contains *${bB}.ver${eB} entries for the packages required by
${bI}PACKAGE${eI}, except that the fourth field is 0 instead of 1. All packages
except ${bB}INIT${eB} and ${Mratz} require the ${bB}INIT${eB} package. A simple sort of ${bI}PACKAGE${eI}${bB}.pkg${eB}
and *${bB}.ver${eB} determines if the required package have been read in. Finally,
${bI}PACKAGE${eI}${bB}.README${eB} contains the ${bB}README${eB} text for ${bI}PACKAGE${eI} and all its
components. Included are all changes added to the component ${bB}RELEASE${eB},
${bB}CHANGES${eB} or ${bB}ChangeLog${eB} files dated since the two most recent base
releases. Component ${bB}RELEASE${eB} files contain tag lines of the form
[${bI}CC${eI}]${bI}YY-MM-DD${eI} [ ${bI}TEXT${eI} ] (or ${Mdate} format dates) followed by README
text, in reverse chronological order (newer entries at the top of the
file.) ${bF}package release${eF} generates this information, and
${bF}package contents ...${eF} lists the descriptions and components.
${bP}
${bB}\$HOSTYPE${eB} names the current binary architecture and is determined by the
output of ${bF}package${eF} (no arguments.) The ${bB}\$HOSTTYPE${eB} naming scheme is used
to separate incompatible executable and object formats. All architecture
specific binaries are placed under ${bB}\$INSTALLROOT${eB} (${bB}\$PACKAGEROOT/arch/\$HOSTTYPE${eB}.)
There are a few places that match against ${bB}\$HOSTTYPE${eB} when making binaries; these
are limited to makefile compiler workarounds, e.g., if ${bB}\$HOSTTYPE${eB} matches
'hp.*' then turn off the optimizer for these objects. All other architecture
dependent logic is handled either by ${bB}\$INSTALLROOT/bin/iffe${eB} or by component
specific configure scripts. Explicit ${bB}\$HOSTYPE${eB} values matching *,*cc*[,-*,...]
optionally set the default ${bB}CC${eB} and ${bB}CCFLAGS${eB}. This is handy for build
farms that support different compilers on the same architecture.
${bP}
Each component contains an ${bB}ast${eB} ${Mnmake} makefile (either ${bB}Nmakefile${eB} or ${bB}Makefile${eB})
and a ${bI}MAM${eI} (make abstract machine) file (${bB}Mamfile${eB}.) A Mamfile contains a portable
makefile description that is used by ${bB}\$INSTALLROOT/bin/mamake${eB} to simulate
${bB}nmake${eB}. Currently there is no support for old-make/gnu-make makefiles; if
the binaries are just being built then ${bB}mamake${eB} will suffice; if source or
makefile modifications are anticipated then ${bB}nmake${eB} (from the ${bB}ast-open${eB} or
${bB}ast-base${eB} package) should be used. Mamfiles are automatically generated by
${bF}package write${eF}.
${bP}
Most component C source is prototyped. If ${bB}\$CC${eB} (default value ${bB}cc${eB}) is not a
prototyping C compiler then ${bF}package make${eF} runs ${Mproto} on portions of the
${bB}\$PACKAGEROOT/src${eB} tree and places the converted output files in the
${bB}\$PACKAGEROOT/proto/src${eB} tree. Converted files are then viewpathed over the
original source. The ${bB}ast${eB} ${Mproto} command converts an ANSI C subset to code
that is compatible with K&R, ANSI, and C++ dialects.
${bP}
All scripts and commands under ${bB}\$PACKAGEROOT${eB} use ${bB}\$PATH${eB} relative pathnames;
there are no imbedded absolute pathnames. This means that binaries generated
under ${bB}\$PACKAGEROOT${eB} may be copied to a different root; users need only change
their ${bB}\$PATH${eB} variable to reference the new instalation root bin directory.
${bF}package install${eF} installs binary packages in a new ${bB}\$INSTALLROOT${eB}.
${eO}"
			;;
		source)	echo "${bO}
${bH}Source Package Installation Instructions${eH}
${bL}
${bT}(1)${bD}Do not install packages as ${bI}root/super-user${eI}. Although some components may
      have setuid executables, few must be owned by ${bI}root${eI}. These are best
      changed manually when the security implications are understood.${eD}
${bT}(2)${bD}Choose a package root directory and cd to it. This will be a local work
      area for all packages.
${bT}(3)${bD}These instructions bypass the ${bI}click to download${eI} package links on the
      download site. If you already clicked, or if your system does not have
      ${Mcurl}, ${Mhurl}, ${Mlynx} or ${Mwget} then use the alternate instructions
      for (3),(4),(5) in plan ${bB}B${eB} below. Plan ${bB}B${eB} installs the ${Mhurl}
      script which works with ksh and modern bash. The top level URL is:${bX}
		URL=http://www.research.att.com/sw/download${eX}${eD}
${bT}(4)${bD}If the ${bB}bin/package${eB} script does not exist then run:${bX}
		test -d bin || mkdir bin
		url=\$URL/package
		(wget -O - \$url||curl -L \$url||hurl \$url) > bin/package
		chmod +x bin/package${eX}${eD}
${bT}(5)${bD}Determine the list of package names you want from the download site, then
      use the ${Mpackage} command to do the actual download:${bX}
		bin/package authorize \"${bI}NAME${eI}\" password \"${bI}PASSWORD${eI}\" \\
			setup source \$URL ${bB}PACKAGE${eB} ...${eX}
      (Refer to the ${bB}AUTHORIZATION${eB} paragraph on the main download page for
      ${bI}NAME${eI}/${bI}PASSWORD${eI} details.)  This downloads the closure of the latest
      source package(s); covered and up-to-date packages are not downloaded again unless
      ${bB}package force ...${eB} is specified. Package content is verified using ${bB}${checksum}${eB}.
      If the package root will contain only one architecture then you can install in ${bB}bin${eB} and
      ${bB}lib${eB} instead of ${bB}arch/${eB}${bI}HOSTTYPE${eI}${bB}/bin${eB} and ${bB}arch/${eB}${bI}HOSTTYPE${eI}${bB}/lib${eB} by running this
      instead:${bX}
		bin/package authorize \"${bI}NAME${eI}\" password \"${bI}PASSWORD${eI}\" \\
			flat setup source \$URL ${bB}PACKAGE${eB} ...${eX}
      To update the same packages from the same URL run:${bX}
		bin/package setup source${eX}${eD}
${bT}(6)${bD}Build and install; all generated files are placed under ${bB}arch/${eB}${bI}HOSTTYPE${eI}
      (${bB}\$INSTALLROOT${eB}), where ${bI}HOSTTYPE${eI} is the output of ${bB}bin/package${eB} (with no
      arguments.) ${bI}name=value${eI} arguments are supported; ${bB}CC${eB} and ${bB}debug=1${eB} (compile
      with -g instead of -O) are likely candidates. The output is written to
      the terminal and captured in ${bB}\$INSTALLROOT/lib/package/gen/make.out${eB}:${bX}
		bin/package make${eX}${eD}
${bT}(7)${bD}List make results and interesting errors:${bX}
		bin/package results${eX}
      Run the regression tests:${bX}
		bin/package test${eX}
      List test results and errors:${bX}
		bin/package results test${eX}${eD}
${bT}(8)${bD}The generated binaries are position independent, i.e., they do not
      contain hard-coded paths. However, commands with related files, like
      ${Mfile} and ${Mnmake}, require the path of the bin directory to be
      exported in ${bB}PATH${eb}.${eD}
${bT}(9)${bD}You can run the binaries directly from the package root, or you can
      install them in a public root after you are satisfied with the make and
      test actions (requires the ${bI}AT${Camp}T${eI} ${Mnmake} command):${bX}
		bin/package flat install ${bI}DIRECTORY PACKAGE${eI}${eX}
      This will install in ${bI}DIRECTORY${eI}${bB}/bin${eB} and ${bI}DIRECTORY${eI}${bB}/lib${eB}. If you want to
      preserve the ${bB}arch/${eB}${bI}HOSTTYPE${eI} hierarchy under ${bI}DIRECTORY${eI} then omit the
      ${bB}flat${eB} argument. If you don't have ${Mnmake} then the following will do a
      flat install:${bX}
		cd \$INSTALLROOT
		cp -p -r bin lib include ${bI}DIRECTORY${eI}${eX}${eD}
${bT}(10)${bD}To summarize, after the first time the download, build, and test cycle
      for the latest source release is:${bX}
		bin/package setup source
		bin/package make
		bin/package test${eX}${eD}${eL}

${bH}Source Package Installation Instructions -- Plan B${eH}
${bL}
${bT}(3)${bD}Create the subdirectory ${bB}lib/package/tgz${eB} and download all package archives
      into that directory.${eD}
${bT}(4)${bD}If the ${bB}bin/package${eB} script does not exist then manually read the ${bB}INIT${eB}
      source package:${bX}
		gunzip < lib/package/tgz/INIT.${bI}YYYY-MM-DD${eI}.tgz | ${TAR} ${TARFLAGS}f -${eX}
      Note that some browsers automatically unzip downloaded without warning.
      If the gunzip fails try:
		${TAR} ${TARFLAGS}f -${eX} lib/package/tgz/INIT.${bI}YYYY-MM-DD${eI}.tgz
      If your system does not have ${Mtar} or ${Mgunzip} then download the ${Mratz}
      source package, compile it, and manually read the ${bB}INIT${eB}
      source package:${bX}
		mkdir bin
		cp lib/package/tgz/ratz.${bI}YYYY-MM-DD${eI}.c lib/package/tgz/ratz.c
		cc -o bin/ratz lib/package/tgz/ratz.c
		bin/ratz -lm < lib/package/tgz/INIT.${bI}YYYY-MM-DD${eI}.tgz
${bT}(5)${bD}Read all unread package archive(s):${bX}
		bin/package read${eX}
      Both source and binary packages will be read by this step.${eD}${eL}${eO}"
			;;
		*)	echo "Usage: $command [ qualifier ... ] [ action ] [ arg ... ] [ n=v ... ]

   The $command command controls source and binary packages. It must be run
   within the package root directory tree. See \"$command help intro\" for
   details. In the following, PACKAGE names either a package or a component
   within a package; if omitted, all packages are operated on. The default
   action is \"host type\".

   qualifier:
	authorize NAME Remote authorization name or license acceptance phrase.
	debug|environment Show environment and actions; do not execute.
	flat    Collapse \$INSTALLROOT { bin fun include lib } onto \$PACKAGEROOT.
	force	Force the action to override saved state.
	never	Run make -N; otherwise show other actions.
	only	Only operate on the specified packages.
	password PASSWORD Remote authorization or license acceptance password.
	quiet	Do not list captured make and test action output.
	show	Run make -n; otherwise show other actions.
	DEBUG	Trace the package script actions in detail for debugging.
   action:
	admin [ all ] [ db FILE ] [ on PATTERN ] [ action ... ]
		Apply ACTION ... to the hosts listed in FILE. If FILE is
		omitted then "admin.db" is assumed. The caller must have rcp(1)
		and rsh(1) or scp(1) and ssh(1) access to the hosts. Output
		for the action is saved per-host in ACTION.log/HOST. Logs
		can be viewed by \"package admin [on HOST] results [ACTION]\".
		By default only local PACKAGEROOT hosts are selected from FILE;
		\"all\" selects all hosts. \"on PATTERN\" selects only
		hosts matching the | separated PATTERN. FILE contains four
		types of lines. Blank lines and lines beginning with # are
		ignored. Lines starting with id=value are variable assignments.
		Set admin_ping to local conventions if \"$admin_ping\" fails.
		If a package list is not specified on the command line the
		action applies to all packages; a variable assigment
		package=list applies action to the packages in list for
		subsequent hosts in FILE. The remaining line type is a host
		description consisting of 6 tab separated fields. The first 3
		are mandatory; the remaining 3 are updated by the admin action:
		   hosttype
			   The host type as reported by package.
		   [user@]host
			   The host name and optionally user name for rcp(1)
			   and rsh(1) access.
		   [remote:[[master]:]]PACKAGEROOT
			   The absolute remote package root directory and
			   optionally the remote prorocol (rsh or ssh) if
			   the directory is on a different server than the
			   master package root directory. If
			   lib/package/admin/$admin_env exists under
			   this directory then it is sourced by sh(1)
			   before ACTION is done. If this field begins with -
			   then the host is ignored. If this field contains
			   : then ditto(1) is used to sync the remote src
			   directory hierarchy to the local one. If [master]:
			   is specified then the sync is deferred to the
			   master host. If master is omitted (two :) then
			   the sync is disabled. These directories must exist
			   on the remote side: lib/package, src/cmd, src/lib.
		   date    YYMMDD of the last action.
		   date    Elapsed wall time of the last action.
		   M T W   The admin action make, test and write action error
			   counts. A non-numeric value in any of these fields
			   disables the corresponding action.
	    	   owner   The owner contact information.
		   attributes
		           NAME=VALUE attributes. Should at least contain
			   cc=compiler-version.
	clean | clobber
	    Delete the arch/HOSTTYPE hierarchy; this deletes all generated
	    files and directories for HOSTTYPE. The heirarchy can be rebuilt
	    by package make.]
	contents [ package ... ]
		List description and components for PACKAGE on the standard
		output.
	copyright [ package ... ]
		List the general copyright notice(s) for PACKAGE on the
		standard output. Note that individual components in PACKAGE
		may contain additional or replacement notices.
	export [ VARIABLE ... ]
		List NAME=VALUE for each VARIABLE, one per line. If the
		\"only\" attribute is specified then only the variable
		values are listed. If no variables are specified then
		$env are assumed.
	help [ ACTION ]
		Display help text on the standard error [ standard output
		for ACTION ].
	host [ canon cpu name rating type ... ]
		List architecture/implementation dependent host information
		on the standard output. type is listed if no attributes are
		specified. Information is listed on a single line in attributes
		order. The attributes are:
		   canon   The next argument is a host type name to be
			   converted to package syntax.
		   cpu     The number of cpus; 1 if the host is not a
			   multiprocessor.
		   name    The host name.
		   rating  The cpu rating in pseudo mips; the value is useful
			   useful only in comparisons with rating values of
			   other hosts. Other than a vax rating fixed at 1,
			   ratings can vary wildly but consistently from
			   vendor mips ratings. cc(1) may be required to
			   determine the rating.
	           type    The host type, usually of the form
			   vendor.architecture, with an optional trailing
			   -version. The main theme is that type names within
			   a family of architectures are named in a similar,
			   predictable style. Os point release information is
			   avoided as much as possible, but vendor resistance
			   to release incompatibilities has for the most part
			   been futile.
	html [ ACTION ]
		Display html help text on the standard error [ standard output
		for ACTION ].
	install [ ARCHITECTURE ... ] DIR [ PACKAGE ... ]
		Copy the package binary hierarchy to DIR. If ARCHITECTURE is
		omitted then all architectures are installed. If the \"flat\"
		attribute is specified then exactly one ARCHITECTURE must be
		specified; this architecture will be installed in DIR without
		the \"arch/HOSTTYPE\" directory prefixes. Otherwise each
		architecture will be installed in a separate \"arch/HOSTTYPE\"
		subdirectory of DIR. The ARCHITECTURE - names the current
		architecture. DIR must be an existing directory. If PACKAGE
		is omitted then all binary packages are installed. This action
		requires nmake.
	license [ package ... ]
		List the source license(s) for PACKAGE on the standard output.
		Note that individual components in PACKAGE may contain
		additional or replacement licenses.
	list [ PACKAGE ... ]
		List the name, version and prerequisites for PACKAGE on the
		standard output.
	make [ PACKAGE ] [ OPTION ... ] [ TARGET ... ]
		Build and install. The default TARGET is install, which
		makes and installs all packages. If the standard output
		is a terminal then the output is also captured in
		\$INSTALLROOT/lib/package/gen/make.out. The build is done
		in the \$INSTALLROOT directory tree viewpathed on top of
		the \$PACKAGEROOT directory tree. If \"flat\" is specified then
		the \$INSTALLROOT { bin fun include lib } directories are
		linked to the same directories in the package root. Only
		one architecture may be flat. Leaf directory names matching
		the |-separated shell pattern \$MAKESKIP are ignored. The
		view action is done before making. OPTION operands are
		passed to the underlying make command.
	read [ package ... | archive ... ]
		Read the named package archive(s). Must be run from the
		package root directory. Archives are searched for in .
		and lib/package/tgz. Each package is read only once. The
		file lib/package/tgz/package[.type].tim tracks the read time.
		See the write action for archive naming conventions. Text
		file archive member are assumed to be ASCII or UTF-8 encoded.
	regress diff(1) the current and previous package test results.
	release [ [CC]YY-MM-DD [ [cc]yy-mm-dd ] ] [ package ]
		Display recent changes since [CC]YY-MM-DD (up to [cc]yy-mm-dd),
		where - means lowest (or highest.) If no dates are specified
		then changes for the last 4 months are listed. PACKAGE may
		be a package or component name.
	remove PACKAGE
		Remove files installed for PACKAGE.
	results [ path ] [ old ] [ make | test ]
		List results and interesting messages captured by the most
		recent make (default), test or write action. old specifies the
		previous results, if any (current and previous results are
		retained.) $HOME/.pkgresults, if it exists, must contain an
		egrep(1) expression of result lines to be ignored. failed lists
		failures only and path lists the results file path only.
	setup [ beta ] [ binary ] [ source ] [ ARCHITECTURE ... ] [ URL ] [ PACKAGE ... ]
		The action initializes the current directory as a package root,
		runs the update action to download new or out of date packages,
		and runs the read action on those packages. If \"flat\" is
		specified then the \$INSTALLROOT { bin fun include lib }
		directories are linked to the same directories in the package
		root. Only one architecture may be flat. See the update and
		read actions for argument details.
	test [ PACKAGE ]
		Run the regression tests for PACKAGE. If the standard output
		is a terminal then the output is also captured in
		\$INSTALLROOT/lib/package/gen/test.out. In general a package
		must be made before it can be tested. Components tested with
		the \bregress\b(1) command require \bksh93\b. If only is
		also specified then only the listed package components are
		tested, otherwise the closure of the components is tested.
	update [ beta ] [ binary ] [ source ] [ ARCHITECTURE ... ] [ URL ] [ PACKAGE ... ]
		Download the latest release of the selected and required
		packages from URL (e.g.,
		http://www.research.att.com/sw/download) into the directory
		\$PACKAGEROOT/lib/package/tgz. beta acesses beta packages;
		download these at your own risk. If ARCHITECTURE is omitted
		then only architectures already present in the tgz directory
		will be downloaded. If ARCHITECTURE is - then all posted
		architectures will be downloaded. If URL matches *.url then
		it is interpreted as a file containing shell variable
		assignments for url, authorize and password. If URL is
		omitted then the definitions for url, authorize and password
		in \$PACKAGEROOT/lib/package/tgz/$default_url, if it exists,
		are used. If \$PACKAGEROOT/lib/package/tgz/$default_url does
		not exist then it is initialized with the current url,
		authorize and password values and read permission for the
		current user only. If PACKAGE is omitted then only
		packages already present in the tgz directory will be
		downloaded. If PACKAGE is - then all posted packages will be
		downloaded. If source and binary are omitted then both source
		and binary packages will be downloaded. If \bonly\b is
		specified then only the named packages are updated; otherwise
		the closure of required packages is updated. This action
		requires wget(1), lynx(1), curl(1) or a shell that supports
		io to /dev/tcp/HOST/PORT.
   	use [ uid | PACKAGE | . [ 32 | 64 ] | 32 | 64 | - ] [ COMMAND ... ]
   		Run COMMAND or an interactive shell if COMMAND is omitted, with
		the environment initialized for using the package (can you say
		shared library without cussing?) If uid or PACKAGE or . is
		specified then it is used to determine a \$PACKAGEROOT,
		possibly different from the current directory. For example, to
		try out bozo's package: \"package use bozo\". In this case the
		command may be run from any directory. If the file
		\$INSTALLROOT/lib/package/profile is readable then it is
		sourced to initialize the environment. 32 or 64 implies
		\$PACKAGEROOT of . and specifies the target architecture word
		size (which may be silently ignored.)
	verify [ PACKAGE ]
		Verify installed binary files against the checksum files in
		\$INSTALLROOT/lib/package/gen/*.sum. The checksum files contain
		mode, user and group information. If the checksum matches
		for a given file then the mode, user and group are changed
		as necessary to match the checksum entry. A warning is printed
		on the standard error for each mismatch. Requires the ast
		package cksum(1) command.
	view
		Initialize the architecture specific viewpath hierarchy. The
		make action implicitly calls this action. If \"flat\" is specified
		then the \$INSTALLROOT { bin fun include lib } directories are
		linked to the same directories in the package root. Only one
		architecture may be flat.
	write [closure] [cyg|exp|lcl|pkg|rpm|tgz|tst] [base|delta]
			[binary|runtime|source] PACKAGE
		Write a package archive for PACKAGE. All work is done in the
		\$PACKAGEROOT/lib/package directory. FORMAT-specific files
		are placed in the FORMAT subdirectory. A PACKAGE[.TYPE].tim
		file in this directory tracksthe write time and prevents a
		package from being read in the same root it was written. If
		more than one file is generated for a particular FORMAT then
		those files are placed in the FORMAT/PACKAGE subdirectory.
		File names in the FORMAT subdirectory will contain the package
		name, a YYYY-MM-DD date, and for binary packages, HOSTTYPE.
		If PACKAGE is omitted then an ordered list of previously
		written packages is generated. If \"only\" is specified then
		only the named packages will be written; otherwise
		prerequisite packages are written first. Package components
		must be listed in PACKAGE.pkg. FORMAT may be one of:
		   cyg  generate a cygwin package
		   exp  generate an exptools(1) maintainer source archive
		        and NPD file in the exp subdirectory, suitable for
			expmake(1); support files are placed in the
			exp/PACKAGE subdirectory
		   lcl	generate a package archive or delta in the lcl
			subdirectory, suitable for restoration into the
			primary source tree (no source licence annotation)
		   pkg	generate a pkgmk(1) package, suitable for pkgadd(1)
		   rpm  generate an rpm(1) package
		   tgz  generate a gzip(1) tar(1) package archive; this is
			the default
		   tst  generate tgz FORMAT package archive in the tst
			subdirectory; version state files are not updated
		The package type must be one of source, binary or runtime.
		A source package contains the source needed to build the
		corresponding binary package. A binary package includes the
		libraries and headers needed for compiling and linking
		against the public interfaces. A runtime package contains
		the commands and required dynamic libraries.  A package may
		be either a base or delta. A base package contains a
		complete copy of all components.  A delta package contains
		only changes from a previous base package. Delta recipients
		must have the ast pax(1) command (in the ast-base package.)
		If neither base nor delta is specified, then the current
		base is overwritten if there are no deltas referring to the
		current base. Only the tgz and lcl formats support delta.
		If base is specified then a new base and two delta archives
		are generated: one delta to generate the new base from the
		old, and one delta to generate the old base from the new;
		the old base is then removed. If delta is specified then a
		new delta referring to the current base is written.
		package.pkg may reference other packages. By default a
		pointer to those packages is written. The recipient package
		read will then check that all required packages have been
		downloaded. If closure is specified then the components for
		all package references are included in the generated
		package.  This may be useful for lcl and versioning.  All
		formats but lcl annotate each source file (not already
		annotated) with a license comment as it is written to the
		package archive using proto(1).
   name=value:
	variable definition: typically CC=cc or CCFLAGS=-g."
			;;
		esac
		exit $code
		;;
	*=*)	set DEFAULT host type "$@"
		;;
	*)	echo "Usage: $command [ options ] [ qualifier ... ] [ action ] [ arg ... ] [ n=v ... ]" >&2
		exit 2
		;;
	esac
	global="$global $1"
	shift
done

# gather HOSTTYPE *,* options
# 	,*cc*,-*,...	set CC and CCFLAGS

hostopts()
{
	_ifs_=$IFS
	IFS=,
	set '' $HOSTTYPE
	IFS=$_ifs_
	shift
	while	:
	do	case $# in
		0|1)	break ;;
		esac
		shift
		case $1 in
		*cc*)	CC=$1
			while	:
			do	case $# in
				0|1)	break ;;
				esac
				case $2 in
				-*)	case $assign_CCFLAGS in
					?*)	assign_CCFLAGS="$assign_CCFLAGS " ;;
					esac
					assign_CCFLAGS="$assign_CCFLAGS$2"
					shift
					;;
				*)	break
					;;
				esac
			done
			;;
		esac
	done
}

# collect command line targets and definitions

case $_PACKAGE_HOSTTYPE_ in
?*)	HOSTTYPE=$_PACKAGE_HOSTTYPE_
	KEEP_HOSTTYPE=1
	;;
*)	KEEP_HOSTTYPE=0
	;;
esac
KEEP_PACKAGEROOT=0
KEEP_SHELL=0
USER_VPATH=
args=
assign=
assign_CCFLAGS=
for i
do	case $i in
	*:*=*)	args="$args $i"
		continue
		;;
	*=*)	eval `echo ' ' "$i" | sed 's,^[ 	]*\([^=]*\)=\(.*\),n=\1 v='\''\2'\'','`
		;;
	esac
	case $i in
	AR=*|LD=*|NM=*)
		assign="$assign $n='$v'"
		eval $n='$'v
		;;
	CC=*)	eval $n='$'v
		;;
	CCFLAGS=*)
		eval $n='$'v
		assign_CCFLAGS="CCFLAGS=\"\$CCFLAGS\""
		;;
	HOSTTYPE=*)
		eval $n='$'v
		case $HOSTTYPE in
		?*)	KEEP_HOSTTYPE=1 ;;
		esac
		;;
	HURL=*)	eval $n='$'v
		;;
	PACKAGEROOT=*)
		eval $n='$'v
		case $PACKAGEROOT in
		?*)	KEEP_PACKAGEROOT=1 ;;
		esac
		;;
	SHELL=*)eval $n='$'v
		case $SHELL in
		?*)	KEEP_SHELL=1 ;;
		esac
		;;
	TAR=*)	eval $n='$'v
		;;
	TARFLAGS=*)
		eval $n='$'v
		;;
	VPATH=*)eval USER_$n='$'v
		;;
	'debug=1')
		makeflags="$makeflags --debug-symbols"
		;;
	'strip=1')
		makeflags="$makeflags --strip-symbols"
		;;
	*=*)	assign="$assign $n='$v'"
		;;
	*)	args="$args $i"
		;;
	esac
done
case $HOSTTYPE in
*,*)	hostopts $HOSTTYPE ;;
esac
case $assign_CCFLAGS in
?*)	assign="$assign $assign_CCFLAGS"
esac
case $CC in
''|cc)	;;
*)	export CC ;;
esac

# grab action specific args

case $action in
admin)	while	:
	do	case $# in
		0)	set list
			break
			;;
		esac
		case $1 in
		all)	admin_all=1
			;;
		db)	case $# in
			1)	echo $command: $action: $1: db file argument expected >&2
				exit 1
				;;
			esac
			shift
			admin_db=$1
			;;
		on)	case $# in
			1)	echo $command: $action: $1: host pattern argument expected >&2
				exit 1
				;;
			esac
			shift
			admin_on=$1
			;;
		*)	break
			;;
		esac
		shift
	done
	admin_action=$1
	admin_args=$*
	for i
	do	case $i in
		debug|environment|force|never|only|quiet|show|DEBUG)
			;;
		*)	admin_action=$i
			break
			;;
		esac
	done
	;;
setup)	PACKAGEROOT=${PWD:-`pwd`}
	export PACKAGEROOT
	KEEP_PACKAGEROOT=1
	;;
use)	case $1 in
	.|32|64)case $1 in
		32|64)	bit=$1 ;;
		esac
		shift

		# HOSTTYPE specific setup

		case $HOSTTYPE in
		win32.*)sys=uwin
			wow=`uname -i`
			case $bit in
			32)	case $HOSTTYPE in
				*-64)	HOSTTYPE=${HOSTTYPE%-64} ;;
				esac
				case $wow in
				*/32)	;;
				*)	vpath / /$bit ;;
				esac
				;;
			64)	case $HOSTTYPE in
				*-64)	;;
				*)	HOSTTYPE=$HOSTTYPE-64 ;;
				esac
				case $wow in
				*/32)	echo $command: cannot build $bit-bit on $wow $sys >&2; exit 2 ;;
				*)	vpath / /$bit ;;
				esac
				;;
			esac
			case $bit in
			'')	PS1="($sys) " ;;
			*)	PS1="($sys-$bit) " ;;
			esac

			$exec umask 002
			$exec unset MAKESKIP

			$exec export P=$PWD
			$exec export A=$P/arch/$HOSTTYPE

			$exec export CDPATH=:..:$A/src/cmd:$A/src/lib:$A/src/uwin:$P/lib/package
			$exec export INSTALLROOT=$A
			$exec export PACKAGEROOT=$P
			$exec export PATH=$A/bin:$P/bin:$PATH
			$exec export PS1="$PS1"
			$exec export VPATH=$A:$P
			$exec export nativepp=/usr/lib

			if	test '' != "$INSTALLROOT" -a -d $INSTALLROOT/include/ast
			then	$exec export PACKAGE_ast=$INSTALLROOT
			elif	test -d ${PWD%/*}/ast/arch/$HOSTTYPE
			then	$exec export PACKAGE_ast=${PWD%/*}/ast/arch/$HOSTTYPE
			fi

			# run the command

			case $# in
			0)	case $show in
				':')	$exec exec $SHELL ;;
				esac
				;;
			*)	$exec exec $SHELL -c "$@"
				;;
			esac
			exit
			;;
		esac
		PACKAGEROOT=${PWD:-`pwd`}
		$show export PACKAGEROOT
	esac
	;;
esac

# true if arg is a valid PACKAGEROOT

packageroot() # dir
{
	test -d $1/lib/$command -o -x $1/bin/$command
}

# true if arg is executable

executable() # [!] command
{
	case $1 in
	'!')	test ! -x "$2" -a ! -x "$2.exe"; return ;;
	*)	test -x "$1" -o -x "$1.exe"; return ;;
	esac
}

# initialize SHELLMAGIC
# tangible proof of cygwin's disdain for unix (well, this and execrate)

shellmagic()
{
	case $SHELLMAGIC in
	'')	;;
	-)	if	test -f /emx/bin/sh.exe
		then	SHELLMAGIC='#!/emx/bin/sh.exe'$nl
		elif	test -f /bin/env.exe
		then	SHELLMAGIC='#!/bin/env sh'$nl
		else	SHELLMAGIC=
		fi
		;;
	esac
}

# true if arg is executable command on $PATH

onpath() # command
{
	_onpath_b=$1
	case $_onpath_b in
	/*)	if	executable $_onpath_b
		then	_onpath_=$_onpath_b
			return 0
		fi
		return 1
		;;
	esac
	IFS=':'
	set '' $PATH
	IFS=$ifs
	shift
	for _onpath_d
	do	case $_onpath_d in
		'')	_onpath_d=. ;;
		esac
		if	executable "$_onpath_d/$_onpath_b"
		then	_onpath_=$_onpath_d/$_onpath_b
			return 0
		fi
	done
	return 1
}

# true if no nmake or nmake not from AT&T or nmake too old

nonmake() # nmake
{
	_nonmake_version=`( $1 -n -f - 'print $(MAKEVERSION:@/.*AT&T.* //:/-//G:@/.* .*/19960101/)' . ) </dev/null 2>/dev/null || echo 19840919`
	if	test $_nonmake_version -lt 20001031
	then	return 0
	fi
	return 1
}

# determine local host attributes

hostinfo() # attribute ...
{
	case $DEBUG in
	1)	set -x ;;
	esac
	map=
	something=
	path=$PATH
	for i in $ccs
	do	PATH=$PATH:$i
	done
	for i in $use
	do	for j in $org
		do	PATH=$PATH:$i/$j/bin
		done
		PATH=$PATH:$i/bin
	done
	# LD_LIBRARY_PATH may be out of sync with PATH here
	case $SED in
	'')	SED=sed
		$SED 1d < /dev/null > /dev/null 2>&1 ||
		for dir in /bin /usr/bin
		do	if	test -x $dir/$SED
			then	SED=$dir/$SED
				break
			fi
		done
		TR=tr
		$TR < /dev/null > /dev/null 2>&1 ||
		for dir in /bin /usr/bin
		do	if	test -x $dir/$TR
			then	TR=$dir/$TR
				break
			fi
		done
		;;
	esac
	case $PACKAGE_PATH in
	?*)	for i in `echo $PACKAGE_PATH | $SED 's,:, ,g'`
		do	PATH=$PATH:$i/bin
		done
		;;
	esac

	# validate the args

	canon=
	cc=$CC
	for info
	do	case $canon in
		-)	canon=$info
			;;
		*)	case $info in
			*/*|*[cC][cC])
				cc=$info
				;;
			canon)	canon=-
				something=1
				;;
			cpu|name|rating|type)
				something=1
				;;
			*)	echo "$command: $action: $info: unknown attribute" >&2
				exit 1
				;;
			esac
			;;
		esac
	done
	case $canon in
	-)	echo "$command: $action: canon: host type name expected" >&2
		exit 1
		;;
	esac
	case $something in
	"")	set "$@" type ;;
	esac
	case $DEBUG in
	'')	exec 9>&2
		exec 2>/dev/null
		;;
	esac

	# compute the info

	_hostinfo_=
	for info
	do
	case $info in
	cpu)	case $NPROC in
		[123456789]*)
			_hostinfo_="$_hostinfo_ $NPROC"
			continue
			;;
		esac
		cpu=`grep -ic '^processor[ 	][ 	]*:[ 	]*[0123456789]' /proc/cpuinfo`
		case $cpu in
		[123456789]*)
			_hostinfo_="$_hostinfo_ $cpu"
			continue
			;;
		esac
		cpu=1
		# exact match
		set							\
			hinv			'^Processor [0123456789]'	\
			psrinfo			'on-line'		\
			'cat /reg/LOCAL_MACHINE/Hardware/Description/System/CentralProcessor'					'.'			\
			'cat /proc/registry/HKEY_LOCAL_MACHINE/Hardware/Description/System/CentralProcessor'			'.'			\

		while	:
		do	case $# in
			0)	break ;;
			esac
			i=`$1 2>/dev/null | grep -c "$2"`
			case $i in
			[123456789]*)
				cpu=$i
				break
				;;
			esac
			shift;shift
		done
		case $cpu in
		0|1)	set						\
			/bin/mpstat

			while	:
			do	case $# in
				0)	break ;;
				esac
				if	executable $1
				then	case `$1 | grep -ic '^cpu '` in
					1)	cpu=`$1 | grep -ic '^ *[0123456789][0123456789]* '`
						break
						;;
					esac
				fi
				shift
			done
			;;
		esac
		case $cpu in
		0|1)	# token match
			set						\
			/usr/kvm/mpstat			'cpu[0123456789]'	\
			/usr/etc/cpustatus		'enable'	\
			/usr/alliant/showsched		'CE'		\
			'ls /config/hw/system/cpu'	'cpu'		\
			prtconf				'cpu-unit'	\

			while	:
			do	case $# in
				0)	break ;;
				esac
				i=`$1 2>/dev/null | $TR ' 	' '

' | grep -c "^$2"`
				case $i in
				[123456789]*)
					cpu=$i
					break
					;;
				esac
				shift;shift
			done
			;;
		esac
		case $cpu in
		0|1)	# special match
			set						\
									\
			hinv						\
			'/^[0123456789][0123456789]* .* Processors*$/'		\
			'/[ 	].*//'					\
									\
			/usr/bin/hostinfo				\
			'/^[0123456789][0123456789]* .* physically available\.*$/'	\
			'/[ 	].*//'					\

			while	:
			do	case $# in
				0)	break ;;
				esac
				i=`$1 2>/dev/null | $SED -e "${2}!d" -e "s${3}"`
				case $i in
				[123456789]*)
					cpu=$i
					break
					;;
				esac
				shift;shift;shift
			done
			;;
		esac
		case $cpu in
		0|1)	cpu=`(
			cd ${TMPDIR:-/tmp}
			tmp=hi$$
			trap 'rm -f $tmp.*' 0 1 2
			cat > $tmp.c <<!
#include <stdio.h>
#include <pthread.h>
int main()
{
	printf("%d\n", pthread_num_processors_np());
	return 0;
}
!
			for o in -lpthread ''
			do	if	$CC $o -O -o $tmp.exe $tmp.c $o >/dev/null 2>&1 ||
					gcc $o -O -o $tmp.exe $tmp.c $o >/dev/null 2>&1
				then	./$tmp.exe
					break
				fi
			done
			)`
			case $cpu in
			[0123456789]*)	;;
			*)	cpu=1 ;;
			esac
			;;
		esac
		_hostinfo_="$_hostinfo_ $cpu"
		;;
	name)	_name_=`hostname || uname -n || cat /etc/whoami || echo local`
		_hostinfo_="$_hostinfo_ $_name_"
		;;
	rating)	for rating in `grep -i ^bogomips /proc/cpuinfo 2>/dev/null | $SED -e 's,.*:[ 	]*,,' -e 's,\(...*\)\..*,\1,' -e 's,\(\..\).*,\1,'`
		do	case $rating in
			[0123456789]*)	break ;;
			esac
		done
		case $rating in
		[0123456789]*)	;;
		*)	cd ${TMPDIR:-/tmp}
			tmp=hi$$
			trap 'rm -f $tmp.*' 0 1 2
			cat > $tmp.c <<!
#include <stdio.h>
#include <sys/types.h>
#if TD || TZ
#include <sys/time.h>
#else
extern time_t	time();
#endif
int main()
{
	register unsigned long	i;
	register unsigned long	j;
	register unsigned long	k;
	unsigned long		l;
	unsigned long		m;
	unsigned long		t;
	int			x;
#if TD || TZ
	struct timeval		b;
	struct timeval		e;
#if TZ
	struct timezone		z;
#endif
#endif
	l = 500;
	m = 890;
	x = 0;
	for (;;)
	{
#if TD || TZ
#if TZ
		gettimeofday(&b, &z);
#else
		gettimeofday(&b);
#endif
#else
		t = (unsigned long)time((time_t*)0);
#endif
		k = 0;
		for (i = 0; i < l; i++)
			for (j = 0; j < 50000; j++)
				k += j;
#if TD || TZ
#if TZ
		gettimeofday(&e, &z);
#else
		gettimeofday(&e);
#endif
		t = (e.tv_sec - b.tv_sec) * 1000 + (e.tv_usec - b.tv_usec) / 1000;
		if (!x++ && t < 1000)
		{
			t = 10000 / t;
			l = (l * t) / 10;
			continue;
		}
#else
		t = ((unsigned long)time((time_t*)0) - t) * 1000;
		if (!x++ && t < 20000)
		{
			t = 200000l / t;
			l = (l * t) / 10;
			continue;
		}
#endif
#if PR
		printf("[ k=%lu l=%lu m=%lu t=%lu ] ", k, l, m, t);
#endif
		if (t == 0)
			t = 1;
		break;
	}
	printf("%lu\n", ((l * m) / 10) / t);
	return k == 0;
}
!
			rating=
			for o in -DTZ -DTD ''
			do	if	$CC $o -O -o $tmp.exe $tmp.c >/dev/null 2>&1 ||
					gcc $o -O -o $tmp.exe $tmp.c >/dev/null 2>&1
				then	rating=`./$tmp.exe`
					break
				fi
			done
			case $rating in
			[0123456789]*)	;;
			*)	rating=1 ;;
			esac
			;;
		esac
		_hostinfo_="$_hostinfo_ $rating"
		;;
	type|canon)
		case $CROSS:$canon in
		0:)	case $cc in
			cc)	case $KEEP_HOSTTYPE:$HOSTTYPE in
				0:?*)	if	test -d ${PACKAGEROOT:-.}/arch/$HOSTTYPE
					then	KEEP_HOSTTYPE=1
					fi
					;;
				esac
				;;
			esac
			case $KEEP_HOSTTYPE in
			1)	_hostinfo_="$_hostinfo_ $HOSTTYPE"
				continue
				;;
			esac
			;;
		esac
		case $cc in
		/*)	a=`$cc -dumpmachine $CCFLAGS 2>/dev/null`
			case $a in
			'')	case $CCFLAGS in
				?*)	a=`$cc -dumpmachine 2>/dev/null` ;;
				esac
				;;
			esac
			case $a in
			''|*' '*|*/*:*)
				;;
			*.*-*)	_hostinfo_="$_hostinfo_ $a"
				continue
				;;
			*-*-*)	case $canon in
				'')	canon=$a ;;
				esac
				;;
			*)	_hostinfo_="$_hostinfo_ $a"
				continue
				;;
			esac
			;;
		esac
		IFS=:
		set /$IFS$PATH
		IFS=$ifs
		shift
		f=../lib/hostinfo/typemap
		for i
		do	case $i in
			"")	i=. ;;
			esac
			case $canon in
			'')	case $cc in
				/*|cc)	;;
				*)	if	executable $i/$cc
					then	a=`$i/$cc -dumpmachine $CCFLAGS 2>/dev/null`
						case $a in
						'')	case $CCFLAGS in
							?*)	a=`$cc -dumpmachine 2>/dev/null` ;;
							esac
							;;
						esac
						case $a in
						''|*' '*|*/*:*)
							;;
						*-*)	canon=$a
							;;
						*)	_hostinfo_="$_hostinfo_ $a"
							continue 2
							;;
						esac
					fi
					;;
				esac
				;;
			esac
			if	test -f "$i/$f"
			then	map="`grep -v '^#' $i/$f` $map"
			fi
		done

		# inconsistent -dumpmachine filtered here

		case -${canon}- in
		--|*-powerpc-*)
			h=`hostname || uname -n || cat /etc/whoami`
			case $h in
			'')	h=local ;;
			esac
			a=`arch || uname -m || att uname -m || uname -s || att uname -s`
			case $a in
			*[\ \	]*)	a=`echo $a | $SED "s/[ 	]/-/g"` ;;
			esac
			case $a in
			'')	a=unknown ;;
			esac
			m=`mach || machine || uname -p || att uname -p`
			case $m in
			*[\ \	]*)	m=`echo $m | $SED "s/[ 	]/-/g"` ;;
			esac
			case $m in
			'')	m=unknown ;;
			esac
			x=`uname -a || att uname -a`
			case $x in
			'')	x="unknown $host unknown unknown unknown unknown unknown" ;;
			esac
			set "" $h $a $m $x
			expected=$1 host=$2 arch=$3 mach=$4 os=$5 sys=$6 rel=$7 ver=$8
			;;
		*)	case $canon in
			*-*)	IFS=-
				set "" $canon
				shift
				IFS=$ifs
				case $# in
				2)	host= mach= arch=$1 os=$2 sys= rel= ;;
				*)	host= mach=$2 arch=$1 os=$3 sys= rel= ;;
				esac
				case $os in
				[abcdefghijklmnopqrstuvwxyz]*[0123456789])
					eval `echo $os | $SED -e 's/^\([^0123456789.]*\)\.*\(.*\)/os=\1 rel=\2/'`
					;;
				esac
				;;
			*)	arch=$canon mach= os= sys= rel=
				;;
			esac
			;;
		esac
		type=unknown
		case $host in
		*.*)	host=`echo $host | $SED -e 's/\..*//'` ;;
		esac
		case $mach in
		unknown)
			mach=
			;;
		[Rr][0123][0123456789][0123456789][0123456789])
			mach=mips1
			;;
		[Rr][4][0123456789][0123456789][0123456789])
			mach=mips2
			;;
		[Rr][56789][0123456789][0123456789][0123456789]|[Rr][123456789][0123456789][0123456789][0123456789][0123456789])
			mach=mips4
			;;
		pc)	arch=i386
			mach=
			;;
		[Pp][Oo][Ww][Ee][Rr][Pp][Cc])
			arch=ppc
			mach=
			;;
		*)	case $arch in
			34[0123456789][0123456789])
				os=ncr
				arch=i386
				;;
			esac
			;;
		esac
		case $canon in
		'')	set						\
									\
			/NextDeveloper		-d	next	-	\
			/config/hw/system/cpu	-d	tandem	mach	\

			while	:
			do	case $# in
				0)	break ;;
				esac
				if	test $2 $1
				then	os=$3
					case $4 in
					arch)	mach=$arch ;;
					mach)	arch=$mach ;;
					esac
					break
				fi
				shift;shift;shift;shift
			done
			;;
		esac
		case $os in
		AIX*|aix*)
			type=ibm.risc
			;;
		HP-UX)	case $arch in
			9000/[78]*)
				type=hp.pa
				;;
			*/*)	type=hp.`echo $arch | $SED 's,/,_,g'`
				;;
			*)	type=hp.$arch
				;;
			esac
			;;
		[Ii][Rr][Ii][Xx]*)
			set xx `hinv | $SED -e '/^CPU:/!d' -e 's/CPU:[ 	]*\([^ 	]*\)[ 	]*\([^ 	]*\).*/\1 \2/' -e q | $TR ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz`
			shift
			type=$1
			n=
			case $2 in
			r[0123][0123456789][0123456789][0123456789])
				n=1
				;;
			r[4][0123][0123456789][0123456789])
				n=2
				;;
			r[4][456789][0123456789][0123456789]|r[5][0123456789][0123456789][0123456789])
				n=3
				;;
			r[6789][0123456789][0123456789][0123456789]|r[123456789][0123456789][0123456789][0123456789][0123456789])
				n=4
				;;
			esac
			case $rel in
			[01234].*|5.[012]|5.[012].*)
				case $n in
				1)	;;
				*)	n=2 ;;
				esac
				;;
			5.*)	case $n in
				2)	n=3 ;;
				esac
				;;
			esac
			if	executable $cc
			then	a=$cc
			else	IFS=:
				set /$IFS$PATH
				IFS=$ifs
				shift
				for i
				do	a=$i/$cc
					if	executable $a
					then	break
					fi
				done
			fi
			split='
'
			a=`strings $a < /dev/null | $SED -e 's/[^abcdefghijklmnopqrstuvwxyz0123456789]/ /g' -e 's/[ 	][ 	]*/\'"$split"'/g' | $SED -e "/^${type}[0123456789]$/!d" -e "s/^${type}//" -e q`
			case $a in
			[0123456789])	n=$a ;;
			esac
			case $n in
			4)	a=`$cc -${type}3 2>&1`
				case $a in
				*unknown*|*install*|*conflict*)
					;;
				*)	n=3
					;;
				esac
				;;
			esac
			a=`$cc -show F0oB@r.c 2>&1`
			case $n:$a in
			[!2]:*mips2*)	n=2 ;;
			[!23]:*mips3*)	n=3 ;;
			[!234]:*mips4*)	n=4 ;;
			esac
			case $n:$a in
			[!2]:*[Oo]32*)	abi=-o32 ;;
			[!3]:*[Nn]32*)	abi=-n32 ;;
			esac
			mach=${type}$n
			type=sgi.$mach
			;;
		OSx*|SMP*|pyramid)
			type=pyr
			;;
		OS/390)	type=mvs.390
			;;
		[Ss][Cc][Oo]*)
			type=sco
			;;
		[Ss]ol*)
			v=`echo $rel | $SED -e 's/^[25]\.//' -e 's/\.[^.]*$//'`
			case $v in
			[6789]|[1-9][0-9])
				;;
			*)	v=
				;;
			esac
			case $arch in
			'')	case $mach in
				'')	arch=sun4 ;;
				*)	arch=$mach ;;
				esac
				;;
			esac
			case $arch in
			sparc)	arch=sun4 ;;
			esac
			type=sol$v.$arch
			;;
		[Ss]un*)type=`echo $arch | $SED -e 's/\(sun.\).*/\1/'`
			case $type in
			sparc)	type=sun4 ;;
			esac
			case $rel in
			[01234]*)
				;;
			'')	case $os in
				*[Oo][Ss])
					;;
				*)	type=sol.$type
					;;
				esac
				;;
			*)	case $type in
				'')	case $mach in
					sparc*)	type=sun4 ;;
					*)	type=$mach ;;
					esac
					;;
				esac
				v=`echo $rel | $SED -e 's/^[25]\.//' -e 's/\.[^.]*$//'`
				case $v in
				[6789]|[1-9][0-9])
					;;
				*)	v=
					;;
				esac
				type=sol$v.$type
				;;
			esac
			case $type in
			sun*|*.*)
				;;
			*)	type=sun.$type
				;;
			esac
			;;
		[Uu][Nn][Ii][Xx]_[Ss][Vv])
			type=unixware
			;;
		UTS*|uts*)
			if	test -x /bin/u370 -o -x /bin/u390
			then	type=uts.390
			else	case $arch in
				'')	arch=$mach ;;
				esac
				type=uts.$arch
			fi
			;;
		$host)	type=$arch
			case $type in
			*.*|*[0123456789]*86|*68*)
				;;
			*)	case $mach in
				*[0123456789]*86|*68*|mips)
					type=$type.$mach
					;;
				esac
				;;
			esac
			;;
		unknown)
			case $arch in
			?*)	case $arch in
				sun*)	mach= ;;
				esac
				type=$arch
				case $mach in
				?*)	type=$type.$mach ;;
				esac
				;;
			esac
			;;
		*)	case $ver in
			FTX*|ftx*)
				case $mach in
				*[0123456789][abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]*)
					mach=`echo $mach | $SED -e 's/[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]*$//'`
					;;
				esac
				type=stratus.$mach
				;;
			*)	case $arch in
				[Oo][Ss][-/.]2)
					type=os2
					arch=$rel
					;;
				*)	type=`echo $os | $SED -e 's/[0123456789].*//' -e 's/[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_0123456789.].*//'`
					;;
				esac
				case $type in
				[Cc][Yy][Gg][Ww][Ii][Nn]_*)
					type=cygwin
					;;
				[Uu][Ww][Ii][Nn]*|[Ww]indows_[0123456789][0123456789]|[Ww]indows_[Nn][Tt])
					type=win32
					arch=`echo $arch | $SED -e 's/_[^_]*$//'`
					;;
				esac
				case $arch in
				'')	case $mach in
					?*)	type=$type.$mach ;;
					esac
					;;
				*)	type=$type.$arch ;;
				esac
				;;
			esac
		esac
		case $type in
		[0123456789]*)
			case $mach in
			?*)	type=$mach ;;
			esac
			case $type in
			*/MC)	type=ncr.$type ;;
			esac
			;;
		*.*)	;;
		*[0123456789]*86|*68*)
			case $rel in
			[34].[0123456789]*)
				type=att.$type
				;;
			esac
			;;
		[abcdefghijklmnopqrstuvwxyz]*[0123456789])
			;;
		[abcdefghijklmnopqrstuvwxyz]*)	case $mach in
			$type)	case $ver in
				Fault*|fault*|FAULT*)
					type=ft.$type
					;;
				esac
				;;
			?*)	case $arch in
				'')	type=$type.$mach ;;
				*)	type=$type.$arch ;;
				esac
				;;
			esac
			;;
		esac
		case $type in
		*[-_]32|*[-_]64|*[-_]128)
			bits=`echo $type | $SED 's,.*[-_],,'`
			type=`echo $type | $SED 's,[-_][0-9]*$,,'`
			;;
		*)	bits=
			;;
		esac
		type=`echo $type | $SED -e 's%[-+/].*%%' | $TR ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz`
		case $type in
		*.*)	lhs=`echo $type | $SED -e 's/\..*//'`
			rhs=`echo $type | $SED -e 's/.*\.//'`
			case $rhs in
			[x0123456789]*86)	rhs=i$rhs ;;
			68*)			rhs=m$rhs ;;
			esac
			case $rhs in
			i[x23456789]86|i?[x23456789]86|*86pc)
						rhs=i386 ;;
			powerpc)		rhs=ppc ;;
			s[0123456789]*[0123456789]x)
						rhs=`echo $rhs | $SED -e 's/x$/-64/'` ;;
			esac
			case $rhs in
			arm[abcdefghijklmnopqrstuvwxyz_][0123456789]*)
						rhs=arm ;;
			hppa)			rhs=pa ;;
			esac
			case $lhs in
			?*coff|?*dwarf|?*elf)
				case $lhs in
				?*coff)	x=coff ;;
				?*dwarf)x=coff ;;
				?*elf)	x=elf ;;
				esac
				lhs=`echo ${lhs}XXX | $SED -e "s/${x}XXX//"`
				;;
			esac
			case $lhs in
			bsdi)			lhs=bsd ;;
			darwin)			case $rel in
						[01234567].*)	lhs=${lhs}7 ;;
						esac
						;;
			freebsd)		case $rel in
						[01234].*)	lhs=${lhs}4 ;;
						[123456789]*.*)	lhs=${lhs}`echo $rel | $SED -e 's/\..*//'` ;;
						esac
						;;
			hpux)			lhs=hp ;;
			mvs)			rhs=390 ;;
			esac
			case $lhs in
			'')			type=$rhs ;;
			$rhs)			type=$lhs ;;
			*)			type=$lhs.$rhs ;;
			esac
			;;
		esac
		case $type in
		sgi.mips*)
			case $mach in
			mips2)	type=sgi.$mach
				abi=-o32
				;;
			mips3)	type=sgi.$mach
				abi=-n32
				;;
			mips[456789])
				type=sgi.$mach
				case $abi in
				*-n32) ;;
				*) abi=-64 ;;
				esac
				;;
			*)	pwd=`pwd`
				cd ${TMPDIR:-/tmp}
				tmp=hi$$
				trap 'rm -f $tmp.*' 0 1 2
				cat > $tmp.a.c <<!
extern int b();
int main() { return b(); }
!
				cat > $tmp.b.c <<!
int b() { return 0; }
!
				abi=
				if	$cc -c $tmp.a.c
				then	for i in -n32 -o32 -64
					do	if	$cc $i -c $tmp.b.c &&
							$cc -o $tmp.exe $tmp.a.o $tmp.b.o
						then	abi=$i
							for i in 2 3 4 5 6 7 8 9
							do	case $i:$abi in
								2:-n32|2:-64|3:-64)
									continue
									;;
								esac
								if	$cc $abi -mips$i -c $tmp.b.c &&
									$cc -o $tmp.exe $tmp.a.o $tmp.b.o
								then	type=`echo $type | $SED -e 's/.$//'`$i
									break
								fi
							done
							break
						fi
					done
				fi </dev/null >/dev/null 2>&1
				rm -f $tmp.*
				trap - 0 1 2
				cd $pwd
				;;
			esac
			case $type$abi in
			sgi.mips2-o32)
				;;
			sgi.mips3)
				type=$type-o32
				;;
			sgi.mips3-n32)
				;;
			sgi.mips4)
				type=$type-o32
				;;
			sgi.mips[456789]-64)
				;;
			*)	type=$type$abi
				;;
			esac
			;;
		*)	case $bits in
			'')	case `file /bin/sh 2>/dev/null` in
				*universal*64*)
					pwd=`pwd`
					cd ${TMPDIR:-/tmp}
					tmp=hi$$
					trap 'rm -f $tmp.*' 0 1 2
					cat > $tmp.a.c <<!
int main() { return 0; }
!
					if	$cc -o $tmp.a.exe $tmp.a.c
					then	case `file $tmp.a.exe` in
						*64*)	bits=64 ;;
						esac
					fi </dev/null >/dev/null 2>&1
					rm -f $tmp.*
					trap - 0 1 2
					cd $pwd
					;;
				esac
				;;
			esac
			;;
		esac
		case $bits in
		32)	case $type in
			*.i386)	bits= ;;
			esac
			;;
		esac
		case $bits in
		?*)	type=$type-$bits ;;
		esac

		# last chance mapping

		set "" "" $map
		while	:
		do	case $# in
			[012])	break ;;
			esac
			shift;shift
			eval "	case \$type in
				$1)	type=\$2; break ;;
				esac"
		done
		_hostinfo_="$_hostinfo_ $type"
		;;
	esac
	done
	set '' $_hostinfo_
	shift
	_hostinfo_=$*

	# restore the global state

	PATH=$path
	case $DEBUG in
	'')	exec 2>&9
		exec 9>&-
		;;
	esac
}

# info message

note() # message ...
{
	echo $command: "$@" >&2
}

# cc checks
#
#	CC: compiler base name name
#	cc: full path, empty if not found

checkcc()
{
	cc=
	if	onpath $CC
	then	cc=$_onpath_
	else	case $CC in
		cc)	if	onpath gcc
			then	CC=gcc
				cc=$_onpath_
			fi
			;;
		esac
	fi
	case $cc in
	'')	case $action in
		make|test)	note "$CC: not found"; exit 1 ;;
		*)		note "warning: $CC: not found" ;;
		esac
		;;
	esac
}

# some actions have their own PACKAGEROOT or kick out early

case $action in
host)	eval u=$package_use
	case $u in
	$PACKAGE_USE)
		;;
	*)	if	onpath $0
		then	case $_onpath_ in
			*/arch/$HOSTTYPE/bin/package)
				KEEP_HOSTTYPE=1
				;;
			*)	KEEP_HOSTTYPE=0
				;;
			esac
		else	KEEP_HOSTTYPE=0
		fi
		;;
	esac
	hostinfo $args
	echo $_hostinfo_
	exit 0
	;;
export|setup|use)
	x=
	;;
*)	x=
	eval u=$package_use
	case $u in
	$PACKAGE_USE)
		case :$PATH: in
		*:$INSTALLROOT/bin:*)
			case $LIBPATH: in
			$INSTALLROOT/bin:$INSTALLROOT/lib:*)
				case $SHLIB_PATH: in
				$INSTALLROOT/lib:*)
					x=1
					;;
				esac
				;;
			esac
			;;
		esac
		;;
	esac
	;;
esac
run=-
case $x in
1)	: accept the current package use environment

	OK=ok
	KSH=$EXECROOT/bin/ksh
	MAKE=nmake
	NMAKE=$EXECROOT/bin/$MAKE
	SUM=$EXECROOT/bin/sum
	TEE=$EXECROOT/bin/tee
	INITROOT=$PACKAGEROOT/src/cmd/INIT
	checkcc
	;;
*)	hosttype=
	case $KEEP_PACKAGEROOT in
	0)	case $action in
		use)	PACKAGEROOT=
			case $show in
			echo)	exec=echo make=echo show=echo ;;
			esac
			set '' $args
			shift
			case $# in
			0)	;;
			*)	case $1 in
				-|.)	;;
				/*)	PACKAGEROOT=$1
					;;
				*)	i=`echo ~$1`
					if	packageroot $i
					then	PACKAGEROOT=$i
					else	for i in `echo $HOME | sed -e 's,/[^/]*$,,'` $usr $use
						do	if	packageroot $i/$1
							then	PACKAGEROOT=$i/$1
								break
							fi
						done
						case $PACKAGEROOT in
						'')	hosttype=$1 ;;
						esac
					fi
					;;
				esac
				shift
				;;
			esac
			run="$@"
			;;
		esac
		case $PACKAGEROOT in
		'')	PACKAGEROOT=${PWD:-`pwd`} ;;
		esac

		# . must be within the PACKAGEROOT tree

		i=X$PACKAGEROOT
		IFS=/
		set $i
		IFS=$ifs
		while	:
		do	i=$1
			shift
			case $i in
			X)	break ;;
			esac
		done
		case $PACKAGEROOT in
		//*)	d=/ ;;
		*)	d= ;;
		esac
		case $1 in
		home)	k=1 ;;
		*)	k=0 ;;
		esac
		for i
		do	case $i in
			'')	continue ;;
			esac
			d=$d/$i
			case $k in
			2)	k=1
				;;
			1)	k=0
				;;
			0)	case $i in
				arch)	k=2
					;;
				*)	if	packageroot $d
					then	PACKAGEROOT=$d
					fi
					;;
				esac
				;;
			esac
		done
		;;
	esac
	INITROOT=$PACKAGEROOT/src/cmd/INIT
	$show PACKAGEROOT=$PACKAGEROOT
	$show export PACKAGEROOT
	export PACKAGEROOT

	# initialize the architecture environment

	case $KEEP_HOSTTYPE in
	0)	hostinfo type
		HOSTTYPE=$_hostinfo_
		;;
	1)	_PACKAGE_HOSTTYPE_=$HOSTTYPE
		export _PACKAGE_HOSTTYPE_
		;;
	esac
	$show HOSTTYPE=$HOSTTYPE
	$show export HOSTTYPE
	export HOSTTYPE
	INSTALLROOT=$PACKAGEROOT/arch/$HOSTTYPE
	case $action in
	admin|install|make|read|remove|test|verify|view|write)
		;;
	*)	if	test ! -d $INSTALLROOT
		then	INSTALLROOT=$PACKAGEROOT
		fi
		;;
	esac
	$show INSTALLROOT=$INSTALLROOT
	$show export INSTALLROOT
	export INSTALLROOT

	# check the basic package hierarchy

	case $action in
	export|use)
		packageroot $PACKAGEROOT || {
			echo "$command: $PACKAGEROOT: invalid package root directory" >&2
			exit 1
		}
		case $KEEP_HOSTTYPE:$hosttype in
		0:?*)	if	test -d ${PACKAGEROOT:-.}/arch/$hosttype
			then	KEEP_HOSTTYPE=1
				HOSTTYPE=$hosttype
			else	echo "$command: $hosttype: package root not found" >&2
				exit 1
			fi
			;;
		esac
		;;
	*)	packageroot $PACKAGEROOT || {
			case $KEEP_PACKAGEROOT in
			1)	;;
			*)	echo "$command: $PACKAGEROOT: must be in the package root directory tree" >&2
				exit 1
				;;
			esac
		}

		case $action in
		admin)	;;
		*)	for i in arch arch/$HOSTTYPE
			do	test -d $PACKAGEROOT/$i || $exec mkdir $PACKAGEROOT/$i || exit
			done
			for i in lib
			do	test -d $INSTALLROOT/$i || $exec mkdir $INSTALLROOT/$i || exit
			done
			;;
		esac

		# no $INITROOT means INIT already installed elsewhere

		if	test -d $INITROOT
		then
			# update the basic package commands

			for i in execrate ignore mamprobe silent
			do	test -h $PACKAGEROOT/bin/$i 2>/dev/null ||
				case `ls -t $INITROOT/$i.sh $PACKAGEROOT/bin/$i 2>/dev/null` in
				"$INITROOT/$i.sh"*)
					note update $PACKAGEROOT/bin/$i
					shellmagic
					case $SHELLMAGIC in
					'')	$exec cp $INITROOT/$i.sh $PACKAGEROOT/bin/$i || exit
						;;
					*)	case $exec in
						'')	{
							echo "$SHELLMAGIC"
							cat $INITROOT/$i.sh
							} > $PACKAGEROOT/bin/$i || exit
							;;
						*)	echo "{
echo \"$SHELLMAGIC\"
cat $INITROOT/$i.sh
} > $PACKAGEROOT/bin/$i"
							;;
						esac
						;;
					esac
					$exec chmod +x $PACKAGEROOT/bin/$i || exit
					;;
				esac
			done
		fi
		;;
	esac
	path=$PATH
	PATH=$INSTALLROOT/bin:$PACKAGEROOT/bin:$PATH
	checkcc
	PATH=$path
	case $cc in
	?*)	if	test -f $INITROOT/hello.c
		then
			# check if $CC (full path $cc) is a cross compiler

			(
				cd /tmp || exit 3
				cp $INITROOT/hello.c pkg$$.c || exit 3
				$cc -o pkg$$.exe pkg$$.c > pkg$$.e 2>&1 || {
					if $cc -Dnew=old -o pkg$$.exe pkg$$.c > /dev/null 2>&1
					then	echo "$command: ${warn}$CC: must be a C compiler (not C++)" >&2
					else	cat pkg$$.e
						echo "$command: ${warn}$CC: failed to compile and link $INITROOT/hello.c -- is it a C compiler?" >&2
					fi
					exit 2
				}
				if ./pkg$$.exe >/dev/null 2>&1
				then	code=0
				else	code=1
				fi
				rm -f pkg$$.*
				exit $code
			)
			code=$?
			case $code in
			1)	CROSS=1 ;;
			esac
		fi
		;;
	esac
	EXECTYPE=$HOSTTYPE
	EXECROOT=$INSTALLROOT
	case $CROSS in
	0) 	# dll hackery -- why is this so complicated?

		abi=
		case $HOSTTYPE in
		sgi.mips[0123456789]*)
			x=rld
			if	executable /lib32/$x || executable /lib64/$x
			then	case $INSTALLROOT in
				*/sgi.mips[0123456789]*)
					u=`echo $INSTALLROOT | sed -e 's,-[^-/]*$,,' -e 's,.$,,'`
					;;
				*)	u=
					;;
				esac
				for a in "n=2 v= l=" "n=3 v=N32 l=lib32" "n=4-n32 v=N32 l=lib32" "n=4 v=64 l=lib64"
				do	eval $a
					case $v in
					N32)	case $n:$HOSTTYPE in
						*-n32:*-n32)	;;
						*-n32:*)	continue ;;
						*:*-n32)	continue ;;
						esac
						;;
					esac
					case $l in
					?*)	if	executable ! /$l/$x
						then	continue
						fi
						;;
					esac
					case $u in
					'')	case $HOSTTYPE in
						sgi.mips$n|sgi.mips$n-*)
							abi="$abi 'd=$INSTALLROOT v=$v'"
							;;
						*)	continue
							;;
						esac
						;;
					*)	if	test -d $u$n
						then	abi="$abi 'd=$u$n v=$v'"
						fi
						;;
					esac
				done
			fi
			;;
		esac
		case $abi in
		'')	abi="'d=$INSTALLROOT v='" ;;
		esac
		p=0
		eval "
			for a in $abi
			do	eval \$a
				eval \"
					case \\\$LD_LIBRARY\${v}_PATH: in
					\\\$d/lib:*)
						;;
					*)	x=\\\$LD_LIBRARY\${v}_PATH
						case \\\$x in
						''|:*)	;;
						*)	x=:\\\$x ;;
						esac
						LD_LIBRARY\${v}_PATH=\$d/lib\\\$x
						export LD_LIBRARY\${v}_PATH
						p=1
						;;
					esac
				\"
			done
		"
		case $LD_LIBRARY_PATH in
		'')	;;
		*)	for d in $lib
			do	case $HOSTTYPE in
				*64)	if	test -d ${d}64
					then	d=${d}64
					fi
					;;
				esac
				case :$LD_LIBRARY_PATH: in
				*:$d:*)	;;
				*)	if	test -d $d
					then	LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$d
						p=1
					fi
					;;
				esac
			done
			;;
		esac
		case $p in
		1)	$show LD_LIBRARY_PATH=$LD_LIBRARY_PATH
			$show export LD_LIBRARY_PATH
			export LD_LIBRARY_PATH
			;;
		esac
		case $LIBPATH: in
		$INSTALLROOT/bin:$INSTALLROOT/lib:*)
			;;
		*)	case $LIBPATH in
			'')	LIBPATH=/usr/lib:/lib ;;
			esac
			LIBPATH=$INSTALLROOT/bin:$INSTALLROOT/lib:$LIBPATH
			$show LIBPATH=$LIBPATH
			$show export LIBPATH
			export LIBPATH
			;;
		esac
		case $SHLIB_PATH: in
		$INSTALLROOT/lib:*)
			;;
		*)	SHLIB_PATH=$INSTALLROOT/lib${SHLIB_PATH:+:$SHLIB_PATH}
			$show SHLIB_PATH=$SHLIB_PATH
			$show export SHLIB_PATH
			export SHLIB_PATH
			;;
		esac
		case $DYLD_LIBRARY_PATH: in
		$INSTALLROOT/lib:*)
			;;
		*)	DYLD_LIBRARY_PATH=$INSTALLROOT/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}
			$show DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH
			$show export DYLD_LIBRARY_PATH
			export DYLD_LIBRARY_PATH
			;;
		esac
		case $_RLD_ROOT in
		$INSTALLROOT/arch*)	;;
		':')	_RLD_ROOT=$INSTALLROOT/arch:/ ;;
		/|*:/)	_RLD_ROOT=$INSTALLROOT/arch:$_RLD_ROOT ;;
		*)	_RLD_ROOT=$INSTALLROOT/arch:$_RLD_ROOT:/ ;;
		esac
		$show _RLD_ROOT=$_RLD_ROOT
		$show export _RLD_ROOT
		export _RLD_ROOT

		# now set up PATH
		#
		# NOTE: PACKAGEROOT==INSTALLROOT is possible for binary installations

		case $PATH: in
		$PACKAGEROOT/bin:*)
			;;
		*)	PATH=$PACKAGEROOT/bin:$PATH
			;;
		esac
		case $PATH: in
		$INSTALLROOT/bin:*)
			;;
		*)	PATH=$INSTALLROOT/bin:$PATH
			;;
		esac
		$show PATH=$PATH
		$show export PATH
		export PATH
		;;
	*)	for i in package proto nmake
		do	if	onpath $i
			then	EXECROOT=`echo $_onpath_ | sed -e 's,//*[^/]*//*[^/]*$,,'`
				EXECTYPE=`echo $EXECROOT | sed -e 's,.*/,,'`
				break
			fi
		done
		case $HOSTTYPE in
		$EXECTYPE)
			OCC=$CC
			CC=cc
			hostinfo type
			EXECTYPE=$_hostinfo_
			case $HOSTTYPE in
			$EXECTYPE)
				echo "$command: $CC: seems to be a cross-compiler" >&2
				echo "$command: set HOSTTYPE to something other than the native $EXECTYPE" >&2
				exit 1
				;;
			esac
			;;
		esac
		$show EXECTYPE=$EXECTYPE
		$show export EXECTYPE
		export EXECTYPE
		;;
	esac
	$show EXECROOT=$EXECROOT
	$show export EXECROOT
	export EXECROOT

	# use these if possible

	OK=ok
	KSH=$EXECROOT/bin/ksh
	MAKE=nmake
	NMAKE=$EXECROOT/bin/$MAKE
	SUM=$EXECROOT/bin/sum
	TEE=$EXECROOT/bin/tee

	# grab a decent default shell

	case $KEEP_SHELL in
	0)	executable "$SHELL" || SHELL=
		case $SHELL in
		?*)	checksh $SHELL || SHELL= ;;
		esac
		case $SHELL in
		''|/bin/*|/usr/bin/*)
			case $SHELL in
			'')	SHELL=/bin/sh ;;
			esac
			for i in ksh sh bash
			do	if	onpath $i && checksh $_onpath_
				then	SHELL=$_onpath_
					break
				fi
			done
			;;
		*/*ksh)	if	executable $KSH
			then	SHELL=$KSH
			fi
			;;
		esac
		;;
	esac

	# $SHELL must be /bin/sh compatible

	case $SHELL in
	/bin/sh);;
	'')	SHELL=/bin/sh
		;;
	*)	$SHELL -c 'trap "exit 0" 0; exit 1' 2>/dev/null
		case $? in
		1)	SHELL=/bin/sh
			;;
		*)	# catch (our own) pipe/socket configuration mismatches
			$SHELL -c "date | $SHELL -c 'read x'"
			case $? in
			0)	;;
			*)	SHELL=/bin/sh ;;
			esac
			;;
		esac
		;;
	esac
	export SHELL
	$show SHELL=$SHELL
	$show export SHELL
	COSHELL=$SHELL
	export COSHELL
	$show COSHELL=$COSHELL
	$show export COSHELL

	# tame the environment

	case $action in
	use)	;;
	*)	ENV=
		ERROR_OPTIONS=
		export ENV ERROR_OPTIONS
		;;
	esac

	# finalize the views

	case $USER_VPATH in
	'')	case $VPATH in
		?*)	IFS=':'
			set '' $VPATH
			shift
			IFS=$ifs
			USER_VPATH=
			for i
			do	case $i in
				*/arch/$HOSTTYPE)	;;
				*/arch/*/*)		;;
				*/arch/*)		continue ;;
				esac
				if	packageroot $i
				then	case $USER_VPATH in
					'')	USER_VPATH=$i ;;
					?*)	USER_VPATH=$USER_VPATH:$i ;;
					esac
				fi
			done
		esac
		;;
	esac
	case $USER_VPATH in
	?*)	IFS=':'
		set '' $USER_VPATH
		shift
		IFS=$ifs
		USER_VPATH=
		USER_VPATH_CHAIN=
		p=$PACKAGEROOT
		for i
		do	case $i in
			''|$PACKAGEROOT|$INSTALLROOT)
				;;
			?*)	USER_VPATH=$USER_VPATH:$i
				USER_VPATH_CHAIN="$USER_VPATH_CHAIN $p $i"
				p=$i
				case $PROTOROOT in
				-)	executable $i/bin/mamake && PROTOROOT= ;;
				esac
				;;
			esac
		done
		;;
	esac
	;;
esac

PACKAGESRC=$PACKAGEROOT/lib/package
PACKAGEBIN=$INSTALLROOT/lib/package
case $action:$run in
use:-)	set '' $args
	shift
	case $# in
	0)	;;
	*)	shift ;;
	esac
	run="$@"
	;;
esac

# HOSTTYPE specific package profile

if	test -r $INSTALLROOT/lib/package/profile
then	. $INSTALLROOT/lib/package/profile
fi

# more cygwin hassles

case $HOSTTYPE in
cygwin.*)
	lose=
	case $CYGWIN in
	*nontsec*)
		lose=ntsec
		;;
	*ntsec*);;
	*)	exe=/tmp/pkg$$.exe
		rm -f $exe
		: > $exe
		if	test -x $exe
		then	lose=ntsec
		fi
		;;
	esac
	case $CYGWIN in
	*nobinmode*)
		case $lose in
		'')	lose=binmode ;;
		*)	lose="$lose binmode" ;;
		esac
		;;
	esac
	case $lose in
	?*)	echo "$command: $HOSTTYPE: export '$lose' in CYGWIN or languish in windows" >&2
		exit 1
		;;
	esac
	;;
esac

# set up the view state

VIEW_bin=$INSTALLROOT VIEW_src=$PACKAGEROOT VIEW_all="$INSTALLROOT $PACKAGEROOT"
if	(vpath $INSTALLROOT $PACKAGEROOT $USER_VPATH_CHAIN) >/dev/null 2>&1 &&
	 vpath $INSTALLROOT $PACKAGEROOT $USER_VPATH_CHAIN
then	$show vpath $INSTALLROOT $PACKAGEROOT $USER_VPATH_CHAIN
else	VPATH=$INSTALLROOT:$PACKAGEROOT$USER_VPATH
	$show VPATH=$VPATH
	$show export VPATH
	export VPATH
	IFS=':'
	set '' $VPATH
	shift
	IFS=$ifs
	for i
	do	case $i in
		*/arch/*/*)
			VIEW_src="$VIEW_src $i"
			;;
		*/arch/*)
			VIEW_bin="$VIEW_bin $i"
			;;
		*)
			VIEW_src="$VIEW_src $i"
			;;
		esac
		VIEW_all="$VIEW_all $i"
	done
fi

# return 0 if arg in src|bin|all view

view() # [test] [-|type] [src|bin|all] file
{
	case $1 in
	-[dfsx])_view_T_=$1; shift ;;
	*)	_view_T_=-f ;;
	esac
	case $1 in
	-)	_view_t_= ;;
	*)	_view_t_=$1 ;;
	esac
	shift
	case $1 in
	all)	shift; _view_v_=$VIEW_all ;;
	bin)	shift; _view_v_=$VIEW_bin ;;
	src)	shift; _view_v_=$VIEW_src ;;
	*)	_view_v_=$VIEW_all ;;
	esac
	case $1 in
	/*)	if	test $_view_T_ $1
		then	_view_=$1
			return 0
		fi
		;;
	*)	for _view_d_ in $_view_v_
		do	if	test $_view_T_ $_view_d_/$1
			then	_view_=$_view_d_/$1
				return 0
			fi
		done
		;;
	esac
	_view_=
	case $_view_t_ in
	?*)	echo $command: $1: $_view_t_ not found >&2 ;;
	esac
	return 1
}

# determine the package and targets

case $action in
admin)	case $admin_action in
	results)action=$admin_action
		set '' $admin_args
		shift;shift
		admin_args="admin $*"
		case $admin_on in
		'')	target=$admin_args ;;
		*)	target="on $admin_on $admin_args" ;;
		esac
		;;
	esac
	;;
release)set '' $args
	target=
	while	:
	do	shift
		case $1 in
		-|[0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789]|[0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789])
			target="$target $1"
			;;
		*)	break
			;;
		esac
	done
	package=$*
	;;
setup)	# { update read } with optional (bin|fun|include|lib) symlinks
	# flat option sets up { bin fun include lib } symlinks from
	# $INSTALLROOT to $PACKAGEROOT

	# . is the package root

	set '' $args
	shift
	types=
	url=
	while	:
	do	case $# in
		0)	break ;;
		esac
		case $1 in
		--)	shift
			break
			;;
		flat)	flat=1 # backwards compatibility -- documentation dropped
			;;
		*://*|*.url)
			url=$1
			shift
			break
			;;
		*)	types="$types $1"
			;;
		esac
		shift
	done
	if	test ! -d $PACKAGEROOT/lib/package/tgz
	then	$exec mkdir -p $PACKAGEROOT/lib/package/tgz || exit
	fi
	case " $types " in
	*" source "*)
		case " $* " in
		'  ')	;;
		*" INIT "*)
			;;
		*)	view - all src/cmd/INIT ||
			set INIT "$@"
			;;
		esac
		;;
	esac
	packages=`$0 $global authorize "$authorize" password "$password" update setup $types $url "$@" PACKAGEROOT=$PACKAGEROOT`
	case $packages in
	?*)	$0 $global read $packages PACKAGEROOT=$PACKAGEROOT
	esac
	exit
	;;
*)	package=
	target=
	set '' $args
	while	:
	do	shift
		case $# in
		0)	break ;;
		esac
		case $1 in
		''|-)	target="$target $package"
			package=
			;;
		*)	if	view - src "lib/package/$1.pkg"
			then	package="$package $1"
			else	target="$target $package $1"
				package=
			fi
			;;
		esac
	done
	;;
esac

# flatten -- assumes symlink support

case $flat in
1)	case $action in
	make|read|setup|update|use|view)
		if	test ! -d $INSTALLROOT
		then	$exec mkdir -p $INSTALLROOT || exit
		fi
		for i in bin include lib fun man share
		do	if	test ! -d $INSTALLROOT/../../$i
			then	$exec mkdir $INSTALLROOT/../../$i
			fi
			if	test ! -d $INSTALLROOT/$i
			then	if	test ! -h $INSTALLROOT/$i
				then	$exec ln -s ../../$i $INSTALLROOT/$i
				fi
			elif	test ! -h $INSTALLROOT/$i
			then	for x in $INSTALLROOT/$i/.[a-z]* $INSTALLROOT/$i/*
				do	if	test -f $x -o -d $x
					then	if	test ! -d $INSTALLROOT/$i/$x || test ! -d $INSTALLROOT/../../$i/$x
						then	$exec mv $x $INSTALLROOT/../../$i
						fi
					fi
				done
				$exec rm -rf $INSTALLROOT/$i
				$exec ln -s ../../$i $INSTALLROOT/$i
			fi
		done
		;;
	esac
	;;
esac

# check that cmd args are up to date a.out's

checkaout()	# cmd ...
{
	case $PROTOROOT in
	-)	PROTOROOT=
		case $* in
		ratz)	if	test -f $INITROOT/ratz.c -a -w $PACKAGEROOT
			then	test -f $INITROOT/hello.c || {
					cat > $INITROOT/hello.c <<'!'
#ifndef printf
#include <stdio.h>
#endif
int main() { int new = 0; printf("hello world\n"); return new;}
!
				}
				test -f $INITROOT/p.c || {
					cat > $INITROOT/p.c <<'!'
/*
 * small test for prototyping cc
 */

int main(int argc, char** argv) { return argc || argv; }
!
				}
			fi
			;;
		esac
		test -f $INITROOT/hello.c -a -f $INITROOT/p.c -a -w $PACKAGEROOT || {
			for i
			do	onpath $i || {
					echo "$command: $i: command not found" >&2
					return 1
				}
			done
			return 0
		}
		case $cc in
		'')	_PACKAGE_cc=0
			;;
		*)	_PACKAGE_cc=1
			test -f $INITROOT/hello.c -a -f $INITROOT/p.c || {
				echo "$command: $INITROOT: INIT package source not found" >&2
				return 1
			}
			executable $INSTALLROOT/bin/nmake || {
				# check for prototyping cc
				# NOTE: proto.c must be K&R compatible

				$CC -c $INITROOT/p.c >/dev/null 2>&1
				c=$?
				rm -f p.*
				test 0 != "$c" && {
					checkaout proto || return
					PROTOROOT=$PACKAGEROOT/proto
					$show PROTOROOT=$PACKAGEROOT/proto
					export PROTOROOT
					INITPROTO=$PROTOROOT/src/cmd/INIT
					note proto convert $PACKAGEROOT/src into $PROTOROOT/src
					if	test -d $PACKAGEROOT/src/cmd/nmake
					then	dirs="src/cmd/INIT src/lib/libast src/lib/libardir src/lib/libcoshell src/lib/libpp src/cmd/probe src/cmd/cpp src/cmd/nmake"
					else	dirs="src"
					fi
					(
						if	test -f $PROTOROOT/UPDATE
						then	newer="-newer $PROTOROOT/UPDATE"
						else	newer=""
						fi
						case $exec in
						'')	cd $PACKAGEROOT
							find $dirs -name '*.[CcHh]' $newer -print | proto -v -L - -C proto
							;;
						*)	$exec cd $PACKAGEROOT
							$exec "find $dirs -name '*.[CcHh]' $newer -print | proto -L - -C proto"
							;;
						esac
						$exec touch $PROTOROOT/UPDATE
					)
					if	(vpath $INSTALLROOT - $INSTALLROOT $PROTOROOT $PROTOROOT $PACKAGEROOT) >/dev/null 2>&1 &&
						 vpath $INSTALLROOT - $INSTALLROOT $PROTOROOT $PROTOROOT $PACKAGEROOT
					then	$show vpath $INSTALLROOT $PROTOROOT $PROTOROOT $PACKAGEROOT $USER_VPATH_CHAIN
					else	VPATH=$INSTALLROOT:$PROTOROOT:$PACKAGEROOT$USER_VPATH
						$show VPATH=$VPATH
						export VPATH
					fi
				}
			}
			for i in arch arch/$HOSTTYPE arch/$HOSTTYPE/bin
			do	test -d $PACKAGEROOT/$i || $exec mkdir $PACKAGEROOT/$i || return
			done
			;;
		esac
		;;
	esac
	case $_PACKAGE_cc in
	'')	case $cc in
		'')	_PACKAGE_cc=0 ;;
		*)	_PACKAGE_cc=1 ;;
		esac
		;;
	esac
	for i
	do	eval j=\$_PACKAGE_AOUT_$i
		case $j in
		'')	eval _PACKAGE_AOUT_$i=1 ;;
		*)	continue ;;
		esac
		k=$_PACKAGE_cc
		if	test -f $INITROOT/$i.c
		then	k=${k}1
		else	k=${k}0
		fi
		if	executable $EXECROOT/bin/$i
		then	k=${k}1
		else	k=${k}0
		fi
		: $k : compiler : source : binary :
		case $k in
		*00)	view - bin/$i && continue ;;
		esac
		case $k in
		000)	echo "$command: $i: not found: download the INIT package $HOSTTYPE binary to continue" >&2
			return 1
			;;
		010)	echo "$command: $i: not found: set CC=C-compiler or download the INIT package $HOSTTYPE binary to continue" >&2
			return 1
			;;
		100)	echo "$command: $i: not found: download the INIT package source or $HOSTTYPE binary to continue" >&2
			return 1
			;;
		110)	case $CROSS in
			1)	echo "$command: $i: not found: make the local $EXECTYPE binary package before $HOSTTYPE" >&2
				return 1
				;;
			esac
			;;
		?01)	: accept binary
			continue
			;;
		011)	: accept binary
			continue
			;;
		??1)	case $CROSS in
			1)	continue ;;
			esac
			;;
		esac
		case `ls -t $INITROOT/$i.c $INSTALLROOT/bin/$i 2>/dev/null` in
		"$INITROOT/$i.c"*)
			note update $INSTALLROOT/bin/$i
			if	test proto != "$i" && executable $INSTALLROOT/bin/proto
			then	case $exec in
				'')	$INSTALLROOT/bin/proto -p $INITROOT/$i.c > $i.c || return ;;
				*)	$exec "$INSTALLROOT/bin/proto -p $INITROOT/$i.c > $i.c" ;;
				esac
				$exec $CC $CCFLAGS -o $INSTALLROOT/bin/$i $i.c || return
				$exec rm -f $i.c
			else	if	test ! -d $INSTALLROOT/bin
				then	for j in arch arch/$HOSTTYPE arch/$HOSTTYPE/bin
					do	test -d $PACKAGEROOT/$j || $exec mkdir $PACKAGEROOT/$j || return
					done
				fi
				if	test '' != "$PROTOROOT" -a -f $INITPROTO/$i.c
				then	$exec $CC $CCFLAGS -o $INSTALLROOT/bin/$i $INITPROTO/$i.c || return
				else	$exec $CC $CCFLAGS -o $INSTALLROOT/bin/$i $INITROOT/$i.c || return
				fi
				case $i:$exec in
				proto:)	test -d $INSTALLROOT/include || mkdir $INSTALLROOT/include
					$INSTALLROOT/bin/proto -f /dev/null > $i.c
					cmp -s $i.c $INSTALLROOT/include/prototyped.h 2>/dev/null || cp $i.c $INSTALLROOT/include/prototyped.h
					rm $i.c
					;;
				esac
			fi
			test -f $i.o && $exec rm -f $i.o
			i=$PATH
			PATH=/bin
			PATH=$i
			;;
		esac
	done
	return 0
}

# check package requirements against received packages

requirements() # source|binary [ package ]
{
	case $1 in
	binary)	r=$VIEW_BIN ;;
	source)	r=$VIEW_SRC ;;
	*)	r=$VIEW_ALL ;;
	esac
	shift
	case $1 in
	'')	x= ;;
	*)	x=$* ;;
	esac
	set ''
	for d in $r
	do	set "$@" $d/gen/*.ver
		case $x in
		'')	set "$@" $d/gen/*.req
			;;
		*)	for p in $x
			do	set "$@" $d/gen/$p.req
			done
			;;
		esac
	done
	shift
	e=0
	x=$*
	y=
	n=
	set ''
	for i in $x
	do	p=`echo $i | sed -e 's,.*/,,' -e 's,\....$,,'`
		if	test -f $i
		then	set "$@" $i
			y="$y $p"
		else	case $p in
			'*')	;;
			*)	n="$n $p" ;;
			esac
		fi
	done
	for i in $n
	do	case " $y " in
		*" $i "*)
			;;
		*)	echo "$command: $i: must read or write package" >&2
			e=1
			;;
		esac
	done
	case $e in
	1)	exit 1 ;;
	esac
	shift
	test 0 != "$#" && release=`sort -r "$@" | {
		q=
		e=0
		o=
		while	read p v r s
		do	q="$q
$v $r"
			case $p in
			$o)	continue ;;
			esac
			case $s in
			0)	e=1
				case $r in
				base)	echo "$command: base package $p.$v or newer required" >&2 ;;
				*)	echo "$command: delta package $p.$v.$r or newer required" >&2 ;;
				esac
				;;
			esac
			o=$p
		done
		case $e in
		0)	echo "$q" | sort | { read v r; read v r; echo $v; } ;;
		1)	echo ERROR ;;
		esac
	}`
	case $release in
	ERROR)	case $force in
		0)	exit 1 ;;
		esac
		;;
	?*)	eval `echo $release | sed -e 's,\(.*\)-\(.*\)-\(.*\),yy=\1 mm=\2 dd=\3,'`
		# slide back 4 months
		case $mm in
		01)	mm=09 dd=1 ;;
		02)	mm=10 dd=1 ;;
		03)	mm=11 dd=1 ;;
		04)	mm=12 dd=1 ;;
		05)	mm=01 dd=0 ;;
		06)	mm=02 dd=0 ;;
		07)	mm=03 dd=0 ;;
		08)	mm=04 dd=0 ;;
		09)	mm=05 dd=0 ;;
		10)	mm=06 dd=0 ;;
		11)	mm=07 dd=0 ;;
		12)	mm=08 dd=0 ;;
		esac
		case $dd in
		1)	yy=`expr $yy - 1` ;;
		esac
		release=$yy-$mm-01
		count=1
		lo=$release
		release="-f $release -r $count"
		;;
	esac
}

# write ordered package prerequisite list to the standard output

order() # [ package ]
{
	_order_t_=lib/package/tgz
	case $action in
	binary)	_order_a_=.$HOSTTYPE ;;
	*)	_order_a_= ;;
	esac
	_order_n_=$#
	case $_order_n_ in
	0)	_order_p_=
		for _order_v_ in $VIEW_all
		do	for _order_f_ in $_order_v_/lib/package/*.pkg
			do	if	test -f $_order_f_
				then	_order_p_="$_order_p_ $_order_f_"
				fi
			done
		done
		set '' $_order_p_
		shift
	esac
	{
	if	test ratz != "$*"
	then	for _order_f_ in ratz INIT
		do	if	view -s - src $_order_t_/$_order_f_$_order_a_.tim
			then	echo $_order_f_ $_order_f_
			fi
		done
	fi
	for _order_f_
	do	while	:
		do	view - src $_order_f_ && break
			case $_order_f_ in
			*.pkg)	;;
			*)	_order_f_=$_order_f_.pkg; view - src $_order_f_ && break ;;
			esac
			case $_order_f_ in
			*/*)	;;
			*)	_order_f_=lib/package/$_order_f_; view - src $_order_f_ && break ;;
			esac
			echo "$command: $_order_f_: not a package" >&2
			continue 2
		done
		_order_f_=$_view_
		_order_p_=`echo $_order_f_ | sed -e 's,.*/,,' -e 's,\.pkg$,,'`
		case $_order_n_ in
		0)	view -s - src $_order_t_/$_order_p_$_order_a_.tim || continue ;;
		esac
		echo $_order_p_ $_order_p_
		case $_order_p_ in
		INIT|ratz)
			;;
		*)	echo INIT $_order_p_
			;;
		esac
		{
		req= req_sep=
		op=::
		while	read line
		do	IFS=' 	\\'
			set '' $line
			IFS=$ifs
			while	:
			do	shift
				case $# in
				0)	break ;;
				esac
				case $1 in
				:*:)	op=$1
					;;
				INIT|'$('*|*')')
					;;
				*)	case $op in
					:REQUIRES:)
						req="$req$req_sep$1"
						req_sep=" "
						;;
					esac
					;;
				esac
			done
		done
		for _order_i_ in $req
		do	if	view - src lib/package/$_order_i_.pkg
			then	case $_order_u_ in
				0)	view -s - src $_order_t_/$_order_i_$_order_a_.tim || continue ;;
				esac
				echo $_order_i_ $_order_i_; echo INIT $_order_i_; echo $_order_i_ $_order_p_
			fi
		done
		} < $_order_f_
	done
	} | tsort
}

# generate the package component list in _components_

components() # [ package ]
{
	_components_=
	for p
	do	case $p in
		'')	;;
		INIT)	case " $_components_ " in
			*" $p "*)	;;
			*)		_components_="$_components_ $p" ;;
			esac
			;;
		*)	if	view - src lib/package/$p.pkg
			then	p=$_view_
				op=::
				exec < $p
				while	read line
				do	IFS=' 	\\'
					set '' $line
					IFS=$ifs
					while	:
					do	shift
						case $# in
						0)	break ;;
						esac
						case $1 in
						:*:)	op=$1
							;;
						INIT|'$('*|*')')
							;;
						*)	case $op in
							:PACKAGE:)
								case " $_components_ " in
								*" $1 "*)	;;
								*)		_components_="$_components_ $1" ;;
								esac
								;;
							esac
							;;
						esac
					done
				done
				exec < /dev/null
			elif	test -d $PACKAGEROOT/src/cmd/$p -o -d $PACKAGEROOT/src/lib/$p
			then	_components_="$_components_ $p"
			else	echo "$command: $p: package or component not found" >&2
				exit 1
			fi
			;;
		esac
	done
}

# list main environment values

showenv()
{
	case $1 in
	''|make)for __i__ in CC SHELL $env
		do	eval echo $__i__='$'$__i__
		done
		;;
	esac
}

# capture command output

capture() # file command ...
{
	case $make:$noexec in
	:)	case $action in
		install|make|view)
			o=$action
			;;
		*)	case $package in
			''|*' '*)
				o=$action
				;;
			*)	o=$package
				;;
			esac
			;;
		esac
		case $action in
		write)	d=$PACKAGESRC/gen ;;
		*)	d=$PACKAGEBIN/gen ;;
		esac
		test -d $d || $exec mkdir $d
		o=$d/$o
		case $o in
		$output)o=$o.out
			s=
			;;
		*)	output=$o
			if	test -f $o.old
			then	mv $o.old $o.out.1
				if	test -f $o.out
				then	mv $o.out $o.out.2
				fi
			elif	test -f $o.out
			then	for i in `ls -t $o.out.? 2>/dev/null`
				do	break
				done
				case $i in
				*.1)	i=2 ;;
				*.2)	i=3 ;;
				*.3)	i=4 ;;
				*.4)	i=5 ;;
				*.5)	i=6 ;;
				*.6)	i=7 ;;
				*.7)	i=8 ;;
				*.8)	i=9 ;;
				*)	i=1 ;;
				esac
				mv $o.out $o.out.$i
			fi
			o=$o.out
			: > $o
			note $action output captured in $o
			s="$command: $action start at `date` in $INSTALLROOT"
			case $quiet in
			0)	trap "echo \"$command: $action done  at \`date\`\" in $INSTALLROOT 2>&1 | \$TEE -a $o" 0 1 2 ;;
			*)	trap "echo \"$command: $action done  at \`date\`\" in $INSTALLROOT >> $o" 0 1 2 ;;
			esac
			;;
		esac
		case $quiet in
		0)	if	executable ! $TEE
			then	TEE=tee
			fi
			{
				case $s in
				?*)	echo "$s"  ;;
				esac
				showenv $action
				"$@"
			} < /dev/null 2>&1 | $TEE -a $o
			;;
		*)	{
				case $s in
				?*)	echo "$s"  ;;
				esac
				showenv $action
				"$@"
			} < /dev/null > $o 2>&1
			;;
		esac
		;;
	*)	$make "$@"
		;;
	esac
}

package_install() # dest sum
{
	dest=$1 sum=$2
	ot=
	code=0
	sed -e '/ /!d' -e 's,[^ ]* ,,' -e 's, \(arch/[^/]*\)/, \1 ,' -e '/ arch\//!s,^[^ ]* [^ ]* [^ ]*,& .,' -e 's,/\([^ /]*\)$, \1,' $sum |
	while	read mode user group arch dir file
	do	case $flat:$arch in
		1:*|?:.)t=$dest/$dir ;;
		*)	t=$dest/$arch/$dir ;;
		esac
		case $t in
		$ot)	;;
		*)	if	test ! -d "$t"
			then	$exec mkdir -p "$t" || exit
			fi
			ot=$t
			;;
		esac
		case $file in
		?*)	case $arch in
			.)	f=$dir/$file ;;
			*)	f=$arch/$dir/$file ;;
			esac
			if	test -f "$f"
			then	t=$t/$file
				case $quiet in
				0)	echo "$t" ;;
				esac
				$exec cp -f "$f" "$t" || code=1
				$exec chmod $mode "$t" || code=1
			fi
			;;
		esac
	done
	return $code
}

package_verify() # sum
{
	$exec $SUM -cp $1
}

make_recurse() # dir
{
	for _make_recurse_j in $makefiles
	do	if	view - $1/$_make_recurse_j
		then	return
		fi
	done
	if	test -d $1
	then	case $exec in
		'')	echo :MAKE: > $1/Makefile || exit ;;
		*)	$exec "echo :MAKE: > $1/Makefile" ;;
		esac
	fi
}

get() # host path [ file size ]
{
	case $HURL in
	'')	HURL=.
		for i in wget lynx curl
		do	if	onpath $i
			then	HURL=$i
				break;
			fi
		done
		AUTHORIZE="User-Agent: package AT&T Research\\r\\n"
		case $HURL:$authorize in
		.:?*)	AUTHORIZE="${AUTHORIZE}Authorization: Basic `print -n -r -- $authorize:$password | uuencode -h -x base64`\\r\\n" ;;
		esac
		;;
	esac
	getfd=8
	case $3 in
	'')	case $HURL in
		.)	host=$1
			path=$2
			while	:
			do	eval "exec $getfd<> /dev/tcp/$host/80" || exit
				case $path in
				/*)	;;
				*)	path=/$path ;;
				esac
				print "GET $path HTTP/1.0\\r\\nHost: $host\\r\\n$AUTHORIZE\\r" >&$getfd
				cat <&8 > get.tmp
				got=`sed -e 1q get.tmp`
				case $got in
				*" "200" "*)
					got=`sed -e '1,/^.$/d' -e '/^[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWYZ]/!d' get.tmp`
					: > get.err
					code=0
					break
					;;
				*" "30[123]" "*)
					got=`sed -e '/^Location: /!d' -e 's,^Location: \(.*\)://\([^/]*\)\(/.*\),prot='\''\1'\'' host='\''\2'\'' path='\''\3'\'',' get.tmp`
					case $got in
					'')	rm get.tmp
						echo "$command: $action: $url: redirect error" >&2
						exit 1
						;;
					esac
					eval $got
					;;
				*)	rm get.tmp
					echo "$command: $action: $url: $got" >&2
					echo '' "$got" > get.err
					code=1
					break
					;;
				esac
			done
			;;
		curl)	case $authorize in
			'')	curl -s -L -o get.tmp http://$1/$2 2> get.err; code=$? ;;
			*)	curl -s -L -o get.tmp -u "$authorize":"$password" http://$1/$2 2> get.err; code=$? ;;
			esac
			got=`grep '^[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWYZ]' get.tmp 2>/dev/null`
			case $code in
			0)	if	grep '^<H1>Authorization Required</H1>' get.tmp > get.err
				then	code=1
				fi
				;;
			esac
			;;
		hurl)	case $authorize in
			'')	hurl http://$1/$2 > get.tmp 2> get.err; code=$? ;;
			*)	hurl -a "$authorize":"$password" http://$1/$2 > get.tmp 2> get.err; code=$? ;;
			esac
			got=`grep '^[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWYZ]' get.tmp`
			;;
		lynx)	case $authorize in
			'')	lynx -source http://$1/$2 > get.tmp 2> get.err; code=$? ;;
			*)	lynx -source -auth "$authorize":"$password" http://$1/$2 > get.tmp 2> get.err; code=$? ;;
			esac
			got=`grep '^[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWYZ]' get.tmp`
			;;
		wget)	wget -nv -O get.tmp ${authorize:+--http-user="$authorize"} ${password:+--http-passwd="$password"} http://$1/$2 2> get.err
			code=$?
			got=`grep '^[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWYZ]' get.tmp 2>/dev/null`
			;;
		*)	echo $command: $action: $HURL: url get command not found >&2
			exit 1
			;;
		esac
		if	test 0 != "$code"
		then	case `cat get.err get.tmp 2>/dev/null` in
			*[Aa][Uu][Tt][Hh][Oo][Rr][Ii][SsZz]*|*[Dd][Ee][Nn][Ii][Ee][Dd]*)
				echo $command: $action: authorization required -- see $url for license acceptance authorization name and password >&2
				;;
			*)	cat get.err
				;;
			esac
			rm -f get.tmp get.err
			echo $command: $action: $2: download failed >&2
			exit 1
		fi
		rm -f get.tmp get.err
		;;
	*)	case $exec in
		'')	echo "$3 ($4 bytes):" >&2
			case $HURL in
			.)	eval "exec $getfd<> /dev/tcp/$1/80" || exit
				path=$2/$3
				case $path in
				/*)	;;
				*)	path=/$path ;;
				esac
				print "GET $path HTTP/1.0\\r\\nHost: $host\\r\\n$AUTHORIZE\\r" >&$getfd
				read got <&$getfd
				case $got in
				*" 200 "*)
					code=0
					: > get.err
					;;
				*)	echo '' "$got" > get.err
					code=1
					;;
				esac
				while	read got <&$getfd
				do	case $got in
					''|?)	break ;;
					esac
				done
				cat <&$getfd > get.tmp
				;;
			curl)	case $authorize in
				'')	curl -s -L -o get.tmp http://$1/$2/$3 2> get.err; code=$? ;;
				*)	curl -s -L -o get.tmp -u "$authorize":"$password" http://$1/$2/$3 2> get.err; code=$?
				esac
				case $code in
				0)	if	grep '^<H1>Authorization Required</H1>' get.tmp > get.err
					then	code=1
					fi
					;;
				esac
				;;
			hurl)	case $authorize in
				'')	ksh -x hurl http://$1/$2/$3 > get.tmp 2> get.err; code=$? ;;
				*)	ksh -x hurl -a "$authorize":"$password" http://$1/$2/$3 > get.tmp 2> get.err; code=$? ;;
				esac
				;;
			lynx)	case $authorize in
				'')	lynx -source http://$1/$2/$3 > get.tmp 2> get.err; code=$? ;;
				*)	lynx -source -auth "$authorize":"$password" http://$1/$2/$3 > get.tmp 2> get.err; code=$? ;;
				esac
				;;
			wget)	wget -nv -O get.tmp ${authorize:+--http-user="$authorize"} ${password:+--http-passwd="$password"} http://$1/$2/$3 2> get.err
				code=$?
				;;
			*)	echo $command: $action: $HURL: url get command not found >&2
				exit 1
				;;
			esac
			if	test 0 != "$code"
			then	case `cat get.err get.tmp` in
				*[Aa][Uu][Tt][Hh][Oo][Rr][Ii][SsZz]*|*[Dd][Ee][Nn][Ii][Ee][Dd]*)
					echo $command: $action: authorization required -- see $url for license acceptance authorization name and password >&2
					;;
				*)	cat get.err
					;;
				esac
				rm get.tmp get.err
				echo $command: $action: $3: download failed >&2
				exit 1
			fi
			rm get.err
			case $checksum:$5 in
			:*|*:-)	z=`wc -c < get.tmp`
				case " $z " in
				*" $4 "*)
					;;
				*)	rm -f get.tmp
					echo $command: $3: download error: expected $4 bytes, got $z >&2
					exit 1
					;;
				esac
				;;
			*)	z=`$checksum < get.tmp | sed -e 's,^[ 	][ 	]*,,' -e 's,[ 	].*,,'`
				case " $z " in
				*" $5 "*)
					;;
				*)	rm -f get.tmp
					echo $command: $3: download $checksum error: expected $5, got $z >&2
					exit 1
					;;
				esac
				;;
			esac
			mv get.tmp $3 || exit
			;;
		*)	echo "$3 ($4 bytes)" >&2
			;;
		esac
	esac
}

# generate copyright notice

copyright()
{
	if	test -f $1.lic
	then	echo $1 package general copyright notice
		echo
		proto -c'#' -p -s -l $1.lic -o type=verbose,author='*' /dev/null
		return 0
	fi
	case $1 in
	*-*)	eval `echo '' $1 | sed 's/\([^-]*\)-\(.*\)/__j__="\1" __i__="\2"/'`
		if	copyright $__i__ || copyright $__j__
		then	return 0
		fi
		;;
	esac
	return 1
}

# run remote make on host

remote() # host no-exec-background
{
	host=$1
	background=$2
	eval name=\$${host}_name user=\$${host}_user snarf=\$${host}_snarf type=\$${host}_type rsh=\$${host}_rsh root=\$${host}_root keep=\$${host}_keep log=\$${host}_log
	case $keep in
	1*)	;;
	*)	return ;;
	esac
	case $host in
	$main)	;;
	*)	case $exec in
		'')	exec > $admin_log/$log 2>&1 ;;
		*)	echo "exec > $admin_log/$log 2>&1" ;;
		esac
		;;
	esac
	if	$admin_ping $name >/dev/null 2>&1 || $admin_ping $name >/dev/null 2>&1
	then	cmd=". ./.profile"
		case $root in
		.)	root=
			;;
		*)	cmd="$cmd && cd $root"
			root=$root/
			;;
		esac
		cmd="$cmd && { test -f lib/package/admin/$admin_env && . ./lib/package/admin/$admin_env || true ;} && PATH=\${PWD:-\`pwd\`}/bin:\$PATH \${SHELL:-/bin/sh} -c 'package $admin_args PACKAGEROOT=\${PWD:-\`pwd\`} HOSTTYPE=$type VPATH='"
		case $admin_binary in
		'')	snarf= ;;
		esac
		case $snarf in
		'')	$exec $rsh $user$name "$cmd" $background
			;;
		*?)	rcp=`echo $rsh | sed 's/\(.\).*/\1/'`cp
			case $background in
			?*)	$exec "{" ;;
			esac
			$exec $rsh $user$name "$cmd"
			eval lst=$admin_list
			case $admin_pkgs in
			'')	filter=cat ;;
			*)	filter="egrep lib/package/tgz/($admin_pkgs)\\." ;;
			esac
			if	$exec $rcp $user$name:${root}lib/package/tgz/$lst $PACKAGESRC/tgz
			then	$exec $rcp `$filter $PACKAGESRC/tgz/$lst | sed "s,^,$user$name:,"` $PACKAGESRC/tgz
			else	echo "$command: $user$name:${root}lib/package/tgz/$lst: not found" >&2
			fi
			case $background in
			?*)	$exec "} $background" ;;
			esac
			;;
		esac
	else	echo "$command: $name: down" >&2
	fi
}

# update package_src

checksrc()
{
	case $package_src in
	'')	package_src=$src
		for _i_ in `cd $PACKAGESRC; ls *.def *.lic *.pkg 2>/dev/null | sed 's/[-.].*//'`
		do	case " $package_src " in
			*" $_i_ "*)
				;;
			*)	package_src="$package_src $_i_"
				;;
			esac
		done
		;;
	esac
}

# check for native ascii 0:yes 1:no

__isascii__=

isascii()
{
	case $__isascii__ in
	'')	case `echo A | od -o | sed -e 's/[ 	]*$//' -e '/[ 	]/!d' -e 's/.*[ 	]//'` in
		005101|040412)	__isascii__=0 ;;
		*)		__isascii__=1 ;;
		esac
	esac
	return $__isascii__
}

case $action in

admin)	while	test ! -f $admin_db
	do	case $admin_db in
		/*)	echo $command: $action: $admin_db: data file not found >&2
			exit 1
			;;
		esac
		view file src lib/package/admin/$admin_db || exit 1
		admin_db=$_view_
	done
	admin_components=
	case $admin_action in
	list)	cat $admin_db
		exit
		;;
	test)	set $admin_args
		while	:
		do	case $# in
			1)	break ;;
			esac
			shift
			case $1 in
			*=*)	;;
			*)	admin_components=-$1
				break
				;;
			esac
		done
		;;
	esac
	: all work done in $PACKAGESRC/admin
	cd $PACKAGESRC/admin || exit
	checksrc
	packages=
	admin_log=${admin_action}${admin_components}.log
	exec < $admin_db || exit
	test -d $admin_log || $exec mkdir $admin_log || exit
	case $admin_on in
	'')	admin_on="*" ;;
	esac
	hostname=
	hosts=
	logs=
	local_hosts=
	local_types=
	pids=
	remote_hosts=
	sync_hosts=
	admin_host=_admin_host_
	admin_out=
	case " $admin_args " in
	*" write binary "*|*" write "*" binary "*)
		admin_binary=1
		;;
	*)	admin_binary=
		;;
	esac
	case $only in
	1)	admin_args="only $admin_args" ;;
	esac
	trap 'kill $pids >/dev/null 2>&1' 1 2 3 15
	index=0
	while	read type host root date time make test write owner attributes
	do	case $type in
		''|'#'*);;
		*=*)	eval "$type $host $root $date $time $make $test $write $owner $attributes"
			;;
		*)	case $admin_action in
			make|test|write)
				eval f='$'$admin_action
				case $f in
				*[!0123456789]*)	continue ;;
				esac
				;;
			esac
			rsh=rsh
			case $host in
			*@*)	IFS=@
				set '' $host
				IFS=$ifs
				user=${2}@
				host=$3
				;;
			*)	user=
				;;
			esac
			: type=$type host=$host root=$root date=$date time=$time make=$make test=$test write=$write :
			name=$host
			host=`echo $name | sed 's,[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789],__,g'`
			eval x='$'${host}_index
			eval ${host}_index=1
			case $x in
			1)	i=0
				while	:
				do	case $i in
					$index)	h=''
						break
						;;
					esac
					i=`expr $i + 1`
					eval h='$'${admin_host}${i}_name
					case $h in
					$host)	host=${admin_host}${i}
						eval user='$'${host}_user root='$'${host}_rsh:$host:'$'${host}_root
						break
						;;
					esac
				done
				;;
			esac
			case $root in
			*:$name:*)root=`echo '' $root | sed 's,:.*,:,'` ;;
			esac
			case $root in
			*:*:*)	index=`expr $index + 1`
				host=${admin_host}$index
				;;
			*:*)	case " $sync_hosts " in
				*" $name ${admin_host}"*)
					set '' '' $sync_hosts
					while	:
					do	shift
						shift
						case $1 in
						$name)	host=$2
							break
							;;
						esac
					done
					;;
				*)	index=`expr $index + 1`
					host=${admin_host}$index
					sync_hosts="$sync_hosts $name $host"
					;;
				esac
				;;
			*)	index=`expr $index + 1`
				host=${admin_host}$index
				;;
			esac
			case $root in
			-*)	continue
				;;
			*:*)	case $admin_all in
				0)	continue ;;
				esac
				case $root in
				*:)	root=${root}. ;;
				esac
				IFS=:
				set '' $root
				IFS=$ifs
				sync=$host
				case $hostname in
				'')	hostinfo name
					hostname=$_hostinfo_
					;;
				esac
				shift
				case $# in
				0)	;;
				1)	root=$1
					;;
				2)	rsh=$1 root=$2
					;;
				*)	rsh=$1 sync=$2 root=$3
					case $sync in
					${admin_host}*)
						;;
					?*)	case " $sync_hosts " in
						*" $sync ${admin_host}"*)
							set '' '' $sync_hosts
							while	:
							do	shift
								shift
								case $1 in
								$sync)	sync=$2
									break
									;;
								esac
							done
							;;
						*)	index=`expr $index + 1`
							x=${admin_host}$index
							sync_hosts="$sync_hosts $sync $x"
							sync=$x
							;;
						esac
						;;
					esac
					;;
				esac
				;;
			*)	sync=
				;;
			esac
			case $name in
			$admin_on)
				keep=1
				;;
			*)	case " $admin_on " in
				*" $name "*)	keep=1 ;;
				*)		keep=0 ;;
				esac
				;;
			esac
			case " $admin_out " in
			*" $name "*)
				log=$name.$type
				;;
			*)	admin_out="$admin_out $name"
				log=$name
				;;
			esac
			case $sync in
			'')	local_types="$local_types $type" ;;
			esac
			case $sync in
			$host)	remote_hosts="$remote_hosts $host"
				;;
			?*)	eval ${sync}_share=\"\$${sync}_share $host\"
				;;
			'')	local_hosts="$local_hosts $host"
				;;
			esac
			eval ${host}_name='$'name ${host}_type='$'type ${host}_user='$'user ${host}_sync='$'sync ${host}_snarf='$'sync ${host}_rsh='$'rsh ${host}_root='$'root ${host}_keep='$'keep ${host}_log='$'log
			;;
		esac
	done
	p=
	for i in $admin_args
	do	p="$i $p"
	done
	admin_pkgs=
	for i in $p
	do	if	view - src "lib/package/$i.pkg"
		then	case $admin_pkgs in
			'')	admin_pkgs="$i" ;;
			*)	admin_pkgs="$admin_pkgs|$i" ;;
			esac
		fi
	done
	: "admin_binary :" $admin_binary
	: "admin_args   :" $admin_args
	: "admin_pkgs   :" $admin_pkgs
	: "admin_on     :" "$admin_on"
	: "local_hosts  :" $local_hosts
	: "local_types  :" $local_types
	: "remote_hosts :" $remote_hosts
	: "sync_hosts   :" $sync_hosts
	: "sync_share   :" $sync_share
	case $admin_binary in
	1)	admin_bin_types=
		admin_bin_main=
		for main in $local_hosts $remote_hosts
		do	eval share=\$${main}_share keep=\$${main}_keep
			case $keep in
			0*)	continue ;;
			esac
			for host in $main $share
			do	case " $admin_bin_hosts " in
				*" $host "*)
					continue
					;;
				esac
				eval type=\$${host}_type
				case " $admin_bin_types " in
				*" $type "*)
					continue
					;;
				esac
				case " $types " in
				"  ")	;;
				*" $type "*)
					;;
				*)	continue
					;;
				esac
				admin_bin_hosts="$admin_bin_hosts $host"
				admin_bin_types="$admin_bin_types $type"
				case " $admin_bin_hosts " in
				*" $main "*)
					;;
				*)	case " $admin_bin_main " in
					*" $main "*)
						;;
					*)	admin_bin_main="$admin_bin_main $main"
						;;
					esac
					;;
				esac
			done
		done
		local=
		remote=
		for host in $admin_bin_main $admin_bin_hosts
		do	case " $local_hosts " in
			*" $host "*)
				local="$local $host"
				;;
			*)	case " $remote_hosts " in
				*" $host "*)
					remote="$remote $host"
					;;
				esac
				;;
			esac
		done
		local_hosts=$local
		remote_hosts=$remote
		;;
	esac
	for host in $remote_hosts $local_hosts
	do	eval share=\$${host}_share
		case $share in
		?*)	while	:
			do	oshare=$share
				for s in $share
				do	eval r='$'${s}_share
					case $r in
					?*)	case " $share " in
						*" $r "*)	;;
						*)		share="$share $r" ;;
						esac
						;;
					esac
				done
				case $share in
				$oshare)	eval ${host}_share="'$share'"
						break
						;;
				esac
			done
			;;
		esac
	done
	for host in $remote_hosts
	do	eval type=\$${host}_type
		case " $local_types " in
		*" $type "*)
			eval ${host}_snarf=
			;;
		esac
		eval name=\$${host}_name keep=\$${host}_keep share=\$${host}_share
		for share in $share
		do	eval type=\$${share}_type keep=\$keep\$${share}_keep
			case " $local_types " in
			*" $type "*)
				eval ${share}_snarf=
				;;
			esac
		done
		case $keep in
		0*1*)	keep=2$keep ;;
		*1*)	;;
		*)	keep=0 ;;
		esac
		eval ${host}_keep=$keep
	done
	for host in $remote_hosts $local_hosts
	do	eval name=\$${host}_name user=\$${host}_user type=\$${host}_type sync=\$${host}_sync snarf=\$${host}_snarf share=\$${host}_share rsh=\$${host}_rsh root=\$${host}_root keep=\$${host}_keep
		case $keep in
		0*)	continue ;;
		esac
		case $sync in
		'')	case $admin_action in
			ditto)	continue ;;
			esac
			case $admin_binary in
			1)	case $keep in
				1*|?*1*);;
				*)	continue ;;
				esac
				;;
			esac
			;;
		esac
		eval main_log='$'${host}_log
		main=
		share_keep=
		for i in $host $share
		do	eval n='$'${i}_name t='$'${i}_type q='$'${i}_sync s='$'${i}_snarf l='$'${i}_log k='$'${i}_keep
			case $main:$k in
			:*)	;;
			*:0)	continue ;;
			esac
			case $admin_binary in
			1)	case $s:$q in
				:?*)	continue ;;
				esac
				case " $admin_bin_hosts " in
				*" $i "*)
					;;
				*)	continue
					;;
				esac
				;;
			esac
			case $main in
			'')	main=$i ;;
			*)	share_keep="$share_keep $i" ;;
			esac
			echo package "$admin_args" "[ $n $t ]"
			case $exec in
			'')	: > $admin_log/$l ;;
			*)	$exec ": > $admin_log/$l" ;;
			esac
		done
		host=$main
		share=$share_keep
		case $force in
		0)	admin_ditto_update=--update ;;
		*)	admin_ditto_update= ;;
		esac
		case $exec in
		'')	{
			case $admin_binary:$sync in
			:?*)	eval syncname='$'${sync}_name
				test -x $PACKAGEROOT/bin/package && $admin_ditto $admin_ditto_update --remote=$rsh --expr="name=='package'" $PACKAGEROOT/bin $user$syncname:$root/bin
				test -d $PACKAGESRC && $admin_ditto $admin_ditto_update --remote=$rsh --expr="if(level>1&&path!='LICENSES/*')status=SKIP;path=='LICENSES*|*.(pkg|lic|def)'" $PACKAGESRC $user$syncname:$root/lib/package
				for dir in $package_src
				do	case $MAKESKIP in
					'')	expr="--expr=if(name=='$admin_ditto_skip')status=SKIP" ;;
					*)	expr="--expr=if(name=='$admin_ditto_skip'||level==1&&name=='$MAKESKIP')status=SKIP" ;;
					esac
					test -d $PACKAGEROOT/src/$dir && $admin_ditto $admin_ditto_update --remote=$rsh "$expr" $PACKAGEROOT/src/$dir $user$syncname:$root/src/$dir
				done
				;;
			esac
			case $admin_action in
			ditto)	;;
			?*)	pids=
				set '' $host $share
				while	:
				do	shift
					case $# in
					0)	break
						;;
					1)	remote $1
						;;
					*)	remote $1 &
						pids="$pids $!"
						;;
					esac
				done
				case $pids in
				?*)	wait $pids ;;
				esac
				;;
			esac
			} < /dev/null > $admin_log/$main_log 2>&1 &
			pids="$pids $!"
			;;
		*)	echo "{"
			case $admin_binary:$sync in
			:?*)	eval syncname='$'${sync}_name
				test -d $PACKAGESRC && echo $admin_ditto $admin_ditto_update --remote=$rsh --expr="if(level>1)status=SKIP;name=='*.(pkg|lic|def)'" $PACKAGESRC $user$syncname:$root/lib/package
				for dir in $package_src
				do	case $MAKESKIP in
					'')	expr="--expr=if(name=='$admin_ditto_skip')status=SKIP" ;;
					*)	expr="--expr=if(name=='$admin_ditto_skip'||level==1&&name=='$MAKESKIP')status=SKIP" ;;
					esac
					test -d $PACKAGEROOT/src/$dir && echo $admin_ditto $admin_ditto_update --remote=$rsh "$expr" $PACKAGEROOT/src/$dir $user$syncname:$root/src/$dir
				done
				;;
			esac
			case $admin_action in
			ditto)	;;
			?*)	pids=
				set '' $host $share
				while	:
				do	shift
					case $# in
					0)	break
						;;
					1)	remote $1
						;;
					*)	remote $1 "&"
						pids=1
						;;
					esac
				done
				case $pids in
				1)	echo wait ;;
				esac
				;;
			esac
			echo "} < /dev/null > $admin_log/$main_log 2>&1 &"
			;;
		esac
		eval name='$'${main}_name
		hosts="$hosts $name"
		logs="$logs $main_log"
		for share in $share
		do	eval keep=\$${share}_keep
			case $keep in
			1)	eval name='$'${share}_name log='$'${share}_log
				hosts="$hosts $name"
				logs="$logs $log"
				;;
			esac
		done
	done
	case $exec in
	'')	# track the progress
		case $quiet in
		0)	cd $admin_log
			tail -t $PACKAGE_admin_tail_timeout -f $logs
			cd ..
			;;
		esac
		# wait for the remote actions to complete
		wait
		trap - 1 2 3 15
		# update the db
		exec < $admin_db || exit
		exec 9>&1
		D=`date +%y%m%d`
		while	read line
		do	set -- $line
			case $1 in
			''|'#'*|*=*)
				;;
			*)	case " $hosts " in
				*" $2 "*)
					: ast date command assumed :
					E=`eval date -E \`egrep '[ 	](start|done)[ 	][ 	]*at[ 	]' $admin_log/$2 | sed -e 's/.*[ 	][ 	]*at[ 	][ 	]*//' -e 's/[ 	][ 	]*in[ 	].*$//' -e 's/.*/"&"/'\``
					M=$6 T=$7 W=$8
					case $admin_action in
					make|view)
						M=`egrep -c ']:.* (\*\*\*.* code|don'\''t know) | \*\*\* termination code ' $admin_log/$2` ;;
					test)	T=`grep -ci 'fail[es]' $admin_log/$2` ;;
					*)	W=`grep '^[abcdefghijklmnopqrstuvwxyz][abcdefghijklmnopqrstuvwxyz]*:.' $admin_log/$2 | egrep -cv 'start at|done  at|output captured|warning:|: package not found|whence: command not found'` ;;
					esac
					case $1 in
					?|??|???|????|?????|??????|???????)
						t1='		'
						;;
					????????|?????????|??????????|???????????|????????????|?????????????|??????????????|???????????????)
						t1='	'
						;;
					*)	t1=''
						;;
					esac
					case $2 in
					?|??|???|????|?????|??????|???????)
						t2='	'
						;;
					*)	t2=''
						;;
					esac
					case $3 in
					?|??|???|????|?????|??????|???????)
						t3='	'
						;;
					*)	t3=''
						;;
					esac
					case $E in
					?????)	E=" $E" ;;
					????)	E="  $E" ;;
					???)	E="   $E" ;;
					??)	E="    $E" ;;
					?)	E="     $E" ;;
					esac
					case $M in
					???)	M="$M" ;;
					??)	M=" $M" ;;
					?)	M="  $M" ;;
					'')	M="  0" ;;
					esac
					case $T in
					???)	T="$T" ;;
					??)	T=" $T" ;;
					?)	T="  $T" ;;
					'')	T="  0" ;;
					esac
					case $W in
					???)	W="$W" ;;
					??)	W=" $W" ;;
					?)	W="  $W" ;;
					'')	W="  0" ;;
					esac
					A=$1$t1
					H=$2$t2
					R=$3$t3
					case $# in
					[0-8])	O=
						K=
						;;
					*)	shift 8
						O=$1
						K=$2
						case $O in
						''|?|??|???)	K="	$K" ;;
						esac
						case $# in
						[0-2])	;;
						*)	K="$K $*" ;;
						esac
						;;
					esac
					echo "$A	$H	$R	$D	$E	$M $T $W $O	$K"
					echo "$A	$H	$R	$D	$E	$M $T $W $O	$K" >&9
					continue
					;;
				esac
				;;
			esac
			echo "$line"
		done > $admin_db.new
		mv $admin_db $admin_db.old
		mv $admin_db.new $admin_db
		;;
	esac
	;;

clean|clobber)
	cd $PACKAGEROOT
	$exec rm -rf $INSTALLROOT
	exit
	;;

contents|list)
	# all work in $PACKAGESRC

	cd $PACKAGESRC

	# generate the package list

	set '' $target $package
	shift
	argc=$#
	case $# in
	0)	set '' *.pkg
		case $2 in
		'*.pkg')
			echo $command: $action: no packages >&2
			exit 1
			;;
		esac
		set '' `echo $* | sed 's,\.pkg,,g'`
		shift
		;;
	esac
	sep="$nl    "
	echo packages in $PACKAGEROOT
	case $action in
	list)	echo
		echo "NAME${nl}VERSION${nl}RELEASE${nl}TYPE${nl}STATUS${nl}REQUIRES${nl}----${nl}-------${nl}-------${nl}----${nl}------${nl}--------" | pr -6 -a -o4 -t
		;;
	esac
	{
	omit=:
	for pkg
	do	if	test ! -f $pkg.pkg
		then	echo $command: $action: $pkg: not a package >&2
		else	if	test -f gen/$pkg.ver
			then	set '' `cat gen/$pkg.ver`
				case $3 in
				$2)	ver=base ;;
				*)	ver=$3 ;;
				esac
				if	test -s tgz/$pkg.tim
				then	sts=local
				else	sts=
				fi
			else	ver=
				sts=unwritten
			fi
			typ=
			txt=
			cmp= cmp_sep=
			req= req_sep=
			op=::
			exec < $pkg.pkg
			while	read line
			do	IFS=' 	\\'
				set '' $line
				IFS=$ifs
				while	:
				do	shift
					case $# in
					0)	break ;;
					esac
					case $1 in
					:*:)	op=$1
						;;
					INIT|'$('*|*')')
						;;
					*)	case $op in
						:DESCRIPTION:)
							txt="$txt$sep$line"
							break
							;;
						:PACKAGE:)
							cmp="$cmp$cmp_sep$1"
							cmp_sep=$nl
							;;
						:REQUIRES:)
							req="$req$req_sep$1"
							req_sep=" "
							;;
						esac
						;;
					esac
				done
			done
			exec < /dev/null
			case $txt in
			?*)	txt="$nl$txt" ;;
			esac
			case :$ver: in
			*::*)	;;
			*)	case $action in
				list)	case $sts in
					'')	case `ls -t "tgz/$pkg.$ver.base" "tgz/$pkg.tim" 2>/dev/null` in
						"tgz/$pkg.tim"*)
							sts=read
							;;
						*)	sts=unread
							;;
						esac
						;;
					esac
					echo "$pkg${nl}$ver${nl}base${nl}$typ${nl}$sts${nl}$req"
					case $typ in
					'')	omit=$omit$pkg.$ver.base: ;;
					esac
					;;
				*)	case $req in
					?*)	req=": $req" ;;
					esac
					echo
					echo $pkg $ver $req "$txt"
					case $cmp in
					?*)	echo "${sep}Components in this package:$nl"
						echo "$cmp" | pr -4 -o4 -t ;;
					esac
					;;
				esac
				;;
			esac
		fi
	done
	case $argc:$action in
	0:list)	if	test -d tgz
		then	cd tgz
			# f:file p:package v:version r:release t:type u:update
			for f in `find . -name '*?[_.][0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789][_.]*' -print | sed 's,^\./,,' | sort -r`
			do	eval `echo "$f" | sed -e 's,\.c$,,' -e 's,\.gz$,,' -e 's,\.exe$,,' -e 's,\.tgz$,,' -e 's,\([^_.]*\)[_.]\([0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789]\)[_.]\([0123456789][0123456789][0123456789][0123456789][^_.]*\)[_.]*\(.*\),p=\1 v=\2 r=\3 t=\4,' -e 's,\([^_.]*\)[_.]\([0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789]\)[_.]*\(.*\),p=\1 v=\2 r=base t=\3,'`
				case $t in
				'')	case $omit in
					*:$p.$v.$r:*)	continue ;;
					esac
					u=$p.tim
					;;
				*)	u=$p.$t.tim
					;;
				esac
				if	test -s "$u"
				then	s=local
				elif	test -f "$u"
				then	case `ls -t "$f" "$u" 2>/dev/null` in
					"$u"*)	s=read ;;
					*)	s=unread ;;
					esac
				else	s=unread
				fi
				echo "$p$nl$v$nl$r$nl$t$nl$s$nl"
			done
		fi
		;;
	esac
	} |
	case $action in
	list)	pr -6 -a -o4 -t | sort -u ;;
	*)	cat ;;
	esac
	case $argc in
	0)	if	test -d $PACKAGEROOT/arch
		then	echo
			echo architectures in $PACKAGEROOT
			echo
			for i in `ls $PACKAGEROOT/arch`
			do	if	test -f $PACKAGEROOT/arch/$i/lib/package/gen/host
				then	h=`cat $PACKAGEROOT/arch/$i/lib/package/gen/host`
				else	h=
				fi
				echo $i
				echo $h
				echo
				echo
			done | pr -4 -a -o4 -t
		fi
		;;
	esac
	;;

copyright)
	# all work in $PACKAGESRC

	cd $PACKAGESRC

	# generate the package list

	set '' $target $package
	shift
	argc=$#
	case $# in
	0)	set '' `echo *.lic | sed 's,\.lic,,g'`
		shift
		case $1 in
		'*')	echo $command: $action: no packages >&2
			exit 1
			;;
		esac
		;;
	esac
	checkaout proto || exit
	for i
	do	copyright $i
	done
	;;

export)	case $INSTALLROOT in
	$PACKAGEROOT)
		INSTALLROOT=$INSTALLROOT/arch/$HOSTTYPE
		;;
	esac
	case $only in
	0)	v='$i=' ;;
	*)	v= ;;
	esac
	set '' $target $package
	case $# in
	1)	set '' $env ;;
	esac
	while	:
	do	case $# in
		1)	break ;;
		esac
		shift
		i=$1
		eval echo ${v}'$'${i}
	done
	;;

install)cd $PACKAGEROOT
	set '' $package
	shift
	case $only in
	0)	set '' `order "$@"`
		shift
		;;
	esac
	case $# in
	0)	echo "$command: at least one package name expected" >&2
		exit 1
		;;
	esac
	package=$*
	requirements - $package
	set '' $target
	shift
	case $1 in
	flat)	flat=1 # backwards compatibility -- documentation dropped
		shift
		;;
	esac
	case $# in
	0)	echo "$command: $action: target directory argument expected" >&2
		exit 1
		;;
	esac
	target=
	while	:
	do	case $# in
		1)	directory=$1
			break
			;;
		esac
		target="$target $1"
		shift
	done
	if	test ! -d $directory
	then	echo "$command: $action: $directory: target directory not found" >&2
		exit 1
	fi
	case $target in
	'')	cd arch
		set '' *
		shift
		target=$*
		cd ..
		;;
	esac
	code=0
	makecheck=1
	for a in $target
	do	case $a in
		-)	a=$HOSTTYPE ;;
		esac
		case $flat:$a in
		1:*|?:.)dest=$directory
			;;
		*)	dest=$directory/arch/$a
			if	test "" = "$exec" -a ! -d $dest
			then	mkdir -p $dest || {
					echo "$command: $dest: destination directory must exist" >&2
					exit 1
				}
			fi
			;;
		esac
		for i in $package
		do	if	test "ratz" = "$i"
			then	: skip
			elif	test -f arch/$a/lib/package/gen/$i.sum
			then	package_install $directory arch/$a/lib/package/gen/$i.sum || code=1
			elif	test ! -d arch/$a/bin
			then	echo "$command: $a: invalid architecture" >&2
			elif	test ! -d $dest
			then	echo "$command: $dest: destination directory must exist" >&2
			else	if	test "" != "$makecheck"
				then	if	onpath $MAKE
					then	MAKE=$_onpath_
					else	echo "$command: $MAKE: not found" >&2
						exit 1
					fi
					makecheck=
				fi
				if	test "" != "$exec"
				then	(
						trap - 0 1 2 15
						echo "=== $i installation manifest ==="
						cd arch/$a
						(
						cd lib/package
						INSTALLROOT=$PACKAGEROOT/arch/$a
						VPATH=$INSTALLROOT:$PACKAGEROOT:$VPATH
						export INSTALLROOT VPATH
						$MAKE -s $makeflags -f $i.pkg $qualifier list.installed $assign
						) | sort -u
					)
				else	(
						set -
						cd arch/$a
						(
						cd lib/package
						INSTALLROOT=$PACKAGEROOT/arch/$a
						VPATH=$INSTALLROOT:$PACKAGEROOT:$VPATH
						export INSTALLROOT VPATH
						echo lib/$command
						$MAKE -s $makeflags -f $i.pkg $qualifier list.installed $assign
						) | sort -u | pax -drw -ps $dest
					)
				fi
			fi
		done
	done
	exit $code
	;;

license)# all work in $PACKAGESRC/LICENSES

	cd $PACKAGESRC/LICENSES || exit

	# generate the package list

	set '' $target $package
	shift
	argc=$#
	case $# in
	0)	set '' *
		shift
		case $1 in
		'*')	echo $command: $action: no licenses >&2
			exit 1
			;;
		esac
		;;
	*)	checkaout proto || exit
		a=
		for i
		do	while	:
			do	if	test -f ../$i.lic
				then	j=`proto -df -l ../$i.lic -o query=type /dev/null 2>/dev/null`
					case $j in
					?*)	if	test -f $j
						then	case " $a " in
							*" $j "*)	;;
							*)		a="$a $j" ;;
							esac
						fi
						break
						;;
					esac
				fi
				case $i in
				*-*)	i=`echo $i | sed 's/-[^-]*$//'`
					;;
				*)	echo "$command: $i: package license not found" >&2
					break
					;;
				esac
			done
		done
		set '' $a
		shift
		;;
	esac
	for i
	do	case $exec in
		'')	echo
			echo "		--- $i source license ---"
			echo
			cat $i
			;;
		*)	echo $PACKAGESRC/LICENSES/$i
			;;
		esac
	done
	;;

make|view)
	cd $PACKAGEROOT
	case $package in
	'')	lic="lib/package/*.lic"
		;;
	*) 	for i in $package
		do	lic="$lic lib/package/$i.lic"
			case $i in
			*-*)	lic="$lic lib/package/"`echo $i | sed 's,-.*,,'`".lic" ;;
			esac
		done
		;;
	esac
	checksrc
	requirements source $package
	components $package
	package=$_components_

	# check for some required commands

	must="$AR"
	warn="$NM yacc bison"
	test="$must $warn"
	have=
	IFS=:
	set /$IFS$PATH
	IFS=$ifs
	shift
	for t in $test
	do	if	executable $t
		then	have="$have $t"
		fi
	done
	for d
	do	for t in $test
		do	case " $have " in
			*" $t "*)
				;;
			*)	if	executable $d/$t
				then	have="$have $t"
				fi
				;;
			esac
		done
	done
	case " $have " in
	*" bison "*)	;;
	*" yacc "*)	have="$have bison" ;;
	esac
	case " $have " in
	*" yacc "*)	;;
	*" bison "*)	have="$have yacc" ;;
	esac
	for t in $test
	do	case " $have " in
		*" $t "*)
			;;
		*)	case " $must " in
			*" $t "*)
				echo "$command: $t: not found -- must be on PATH to $action" >&2
				exit 1
				;;
			*)	echo "$command: warning: $t: not found -- some $action actions may fail" >&2
				;;
			esac
			;;
		esac
	done

	# verify the top view

	if	test ! -d $PACKAGEROOT/src
	then	note no source packages to make
		exit 0
	elif	test ! -d $INSTALLROOT/src
	then	note initialize the $INSTALLROOT view
	fi
	for i in arch arch/$HOSTTYPE
	do	test -d $PACKAGEROOT/$i || $exec mkdir $PACKAGEROOT/$i || exit
	done
	for i in bin bin/$OK bin/$OK/lib fun include lib lib/package lib/package/gen src man man/man1 man/man3 man/man8
	do	test -d $INSTALLROOT/$i || $exec mkdir $INSTALLROOT/$i || exit
	done
	make_recurse src
	o= k=
	for i in $makefiles
	do	case $o in
		?*)	o="$o -o" k="$k|" ;;
		esac
		o="$o -name $i"
		k="$k$i"
	done
	o="( $o ) -print"
	for d in $package_src
	do	i=src/$d
		if	test -d $i
		then	test -d $INSTALLROOT/$i || $exec mkdir $INSTALLROOT/$i || exit
			make_recurse $i
			for j in `cd $i; find . $o 2>/dev/null | sed -e 's,^\./,,' -e '/\//!d' -e 's,/[^/]*$,,' | sort -u`
			do	case $j in
				$k|$MAKESKIP) continue ;;
				esac
				test -d $INSTALLROOT/$i/$j ||
				$exec mkdir -p $INSTALLROOT/$i/$j || exit
			done
		fi
	done
	def=
	for i in $lic
	do	test -f $i || continue
		cmp -s $i $INSTALLROOT/$i 2>/dev/null ||
		$exec cp $PACKAGEROOT/$i $INSTALLROOT/$i
		for j in `grep '^. .*\.def$' $i`
		do	case $j in
			.)	;;
			*)	case " $def " in
				*" $i "*)	;;
				*)		def="$def $i" ;;
				esac
				;;
			esac
		done
	done
	for i in $def
	do	i=lib/package/$i
		test -f $i || continue
		cmp -s $i $INSTALLROOT/$i 2>/dev/null ||
		$exec cp $PACKAGEROOT/$i $INSTALLROOT/$i
	done

	# check $CC and { ar cc ld ldd } intercepts

	h="${HOSTTYPE} ${HOSTTYPE}.*"
	case $HOSTTYPE in
	*.*)	t=`echo $HOSTTYPE | sed 's/[.][^.]*//'`
		h="$h $t"
		;;
	*)	t=$HOSTTYPE
		;;
	esac
	case $t in
	*[0123456789])
		t=`echo $t | sed 's/[0123456789]*$//'`
		h="$h $t"
		;;
	esac
	case $CC in
	cc)	c=cc
		b=$INSTALLROOT/bin/$c
		t=$INSTALLROOT/lib/package/gen/$c.tim
		intercept=0
		for k in $h
		do	for s in $INITROOT/$c.$k
			do	test -x "$s" || continue
				if	cmp -s "$s" "$b" >/dev/null 2>&1
				then	intercept=1
					break 2
				fi
				case `ls -t "$t" "$b" "$s" 2>/dev/null` in
				$t*)	;;
				$b*)	cc=$b
					;;
				$s*)	cd $INSTALLROOT/lib/package/gen
					tmp=pkg$$
					eval '$'exec echo "'int main(){return 0;}' > $tmp.c"
					if	$exec $s -o $tmp.exe $tmp.c >/dev/null 2>&1 &&
						test -x $tmp.exe
					then	case $HOSTTYPE in
						*.mips*)$s -version >/dev/null 2>&1 || s= ;;
						esac
						case $s in
						?*)	$exec sed "s/^HOSTTYPE=.*/HOSTTYPE=$HOSTTYPE/" < "$s" > "$b" || exit
							$exec chmod +x "$b" || exit
							cc=$b
							intercept=1
							note update $b
							;;
						esac
					fi
					$exec rm -f $tmp.*
					$exec touch "$t"
					cd $PACKAGEROOT
					;;
				esac
				break 2
			done
		done
		case $intercept in
		1)	c=ld
			b=$INSTALLROOT/bin/$c
			for k in $h
			do	for s in $INITROOT/$c.$k
				do	test -x "$s" || continue
					case `ls -t "$b" "$s" 2>/dev/null` in
					$b*)	;;
					$s*)	$exec cp "$s" "$b"
						note update $b
						;;
					esac
				done
			done
			;;
		esac
		;;
	esac
	c=ldd
	b=$INSTALLROOT/bin/$c
	for t in $h
	do	s=$INITROOT/$c.$t
		test -x "$s" || continue
		onpath $c ||
		case `ls -t "$b" "$s" 2>/dev/null` in
		$b*)	;;
		$s*)	$exec cp "$s" "$b"
			note update $b
			;;
		esac
	done
# following code stubbed out just in case ar.ibm.risc is needed
#	c=ar
#	b=$INSTALLROOT/bin/$c
#	for t in $h
#	do	s=$INITROOT/$c.$t
#		test -x "$s" || continue
#		onpath $c ||
#		case `ls -t "$b" "$s" 2>/dev/null` in
#		$b*)	;;
#		$s*)	x=`$s -tv /foo/bar.a 2>&1 | egrep -i 'option|usage'`
#			case $x in
#			'')	$exec cp "$s" "$b"
#				note update $b
#				;;
#			esac
#			;;
#		esac
#	done
	case $cc in
	/*)	;;
	*)	echo "$command: $CC: not found -- set CC=C-compiler" >&2
		exit 1
		;;
	esac
	case $exec in
	'')	cd $INSTALLROOT/lib/package/gen
		tmp=pkg$$
		echo 'int main(){return 0;}' > $tmp.c
		if	$CC -o $tmp.exe $tmp.c > /dev/null 2> $tmp.err &&
			test -x $tmp.exe
		then	: ok
		else	echo "$command: $CC: failed to compile this program:" >&2
			cat $tmp.c >&2
			if	test -s $tmp.err
			then	cat $tmp.err >&2
			else	echo "$command: $CC: not a C compiler" >&2
			fi
			rm -f $tmp.*
			exit 1
		fi
		rm -f $tmp.*
		cd $PACKAGEROOT
		;;
	esac

	# remember the default $CC

	case $CC in
	cc)	;;
	*)	if	test -x $INSTALLROOT/bin/cc
		then	case `sed 1q $INSTALLROOT/bin/cc` in
			": $CC :")
				CC=cc
				export CC
				;;
			*)	assign="$assign CC=\"\$CC\""
				;;
			esac
		else	case $CROSS in
			1)	assign="$assign CC=\"\$CC\""
				;;
			*)	case $exec in
				'')	{
					echo ": $CC :"
					echo "$CC \"\$@\""
					} > $INSTALLROOT/bin/cc
					chmod +x $INSTALLROOT/bin/cc
					;;
				*)	note generate a $INSTALLROOT/bin/cc wrapper for $CC
					;;
				esac
				CC=cc
				export CC
				;;
			esac
		fi
		;;
	esac

	# no $INITROOT means INIT already installed elsewhere

	if	test -d $INITROOT
	then
		# update probe scripts

		for i in lib/probe lib/probe/C lib/probe/C/make
		do	test -d $INSTALLROOT/$i || $exec mkdir $INSTALLROOT/$i || exit
		done
		i=$INSTALLROOT/lib/probe/C/make/probe
		j=$INITROOT/C+probe
		k=$INITROOT/make.probe
		case `ls -t $i $j $k 2>/dev/null` in
		$i*)	;;
		*)	if	test -f $j -a -f $k
			then	note update $i
				shellmagic
				case $exec in
				'')	{
					case $SHELLMAGIC in
					?*)	echo "$SHELLMAGIC" ;;
					esac
					cat $j $k
					} > $i || exit
					;;
				*)	echo "{
echo $SHELLMAGIC
cat $j $k
} > $i"
					;;
				esac
				$exec chmod +x $i || exit
			fi
			;;
		esac
	fi

	# initialize a few mamake related commands

	checkaout mamake proto ratz release || exit

	# execrate if necessary

	if	(execrate) >/dev/null 2>&1
	then	execrate=execrate
		$make cd $INSTALLROOT/bin
		for i in chmod chgrp cmp cp ln mv rm
		do	if	test ! -x $OK/$i -a -x /bin/$i.exe
			then	shellmagic
				case $exec in
				'')	echo "$SHELLMAGIC"'execrate /bin/'$i' "$@"' > $OK/$i
					chmod +x $OK/$i
					;;
				*)	$exec echo \'"$SHELLMAGIC"'execrate /bin/'$i' "$@"'\'' >' $OK/$i
					$exec chmod +x $OK/$i
					;;
				esac
			fi
		done
		PATH=$INSTALLROOT/bin/$OK:$PATH
		export PATH
	else	execrate=
	fi
	case $action in
	view)	exit 0 ;;
	esac

	# all work under $INSTALLROOT/src

	$make cd $INSTALLROOT/src

	# record the build host name

	case $noexec in
	'')	hostinfo name
		echo "$_hostinfo_" | sed 's,\..*,,' > $PACKAGEBIN/gen/host
		;;
	esac

	# make in parallel if possible

	case $NPROC in
	'')	hostinfo cpu
		case $_hostinfo_ in
		0|1)	;;
		*)	NPROC=$_hostinfo_
			$show NPROC=$NPROC
			$show export NPROC
			export NPROC
			;;
		esac
		;;
	esac

	# separate flags from target list

	case $target in
	*-*)	a=
		for t in $target
		do	case $t in
			-[eiknFKNV]*|--*-symbols)
				makeflags="$makeflags $t"
				;;
			-*)	nmakeflags="$nmakeflags $t"
				;;
			*)	a="$a $t"
				;;
			esac
		done
		target=$a
		;;
	esac

	# generate nmake first if possible

	if	executable ! $NMAKE && test -d $PACKAGEROOT/src/cmd/nmake
	then	if	nonmake $MAKE
		then	note make $NMAKE with mamake
			c=$CC
			a=$assign
			case $HOSTTYPE in
			win32*|cygwin*)
				CC="$CC -D_BLD_STATIC"
				accept="libast"
				case $assign in
				*' CC='*)	;;
				*)		assign="$assign CC=\"\$CC\"" ;;
				esac
				;;
			*)	accept=nmake
				;;
			esac
			eval capture mamake \$makeflags \$nmakeflags \$noexec install nmake $assign
			assign=$a
			CC=$c
			case $make$noexec in
			'')	if	executable ! $NMAKE
				then	echo "$command: $action: errors making $NMAKE" >&2
					exit 1
				fi
				;;
			*)	make=echo
				;;
			esac
			if	test '' != "$PROTOROOT"
			then	if	(vpath $INSTALLROOT - $PROTOROOT - $INSTALLROOT $PACKAGEROOT) >/dev/null 2>&1 &&
					 vpath $INSTALLROOT - $PROTOROOT - $INSTALLROOT $PACKAGEROOT
				then	$show vpath $INSTALLROOT $PACKAGEROOT $USER_VPATH_CHAIN
				else	VPATH=$INSTALLROOT:$PACKAGEROOT$USER_VPATH
					$show VPATH=$VPATH
					export VPATH
				fi
			fi
			note believe generated files for $accept
			eval capture \$NMAKE \$makeflags \$nmakeflags \$noexec recurse believe \$nmakesep $accept $assign
			$exec touch $INSTALLROOT/bin/.paths
			note make the remaining targets with $NMAKE
		else	eval capture $MAKE \$makeflags \$nmakeflags \$noexec install nmake $assign
			case $make$noexec in
			'')	if	executable ! $NMAKE
				then	echo "$command: $action: errors making $NMAKE" >&2
					exit 1
				fi
				;;
			*)	make=echo
				;;
			esac
		fi
	fi

	# generate ksh next if possible

	if	nonmake $MAKE
	then	: no need to generate ksh next -- it could be the only package
	elif	test "$KEEP_SHELL" != 1 -a -d $PACKAGEROOT/src/cmd/ksh93 && executable ! $KSH
	then	eval capture nmake $nmakeflags \$makeflags \$noexec install ksh93 $assign
		case $make$noexec in
		'')	if	executable ! $KSH
			then	echo "$command: $action: errors making $KSH" >&2
				exit 1
			fi
			;;
		*)	make=echo
			;;
		esac
	fi

	# mamprobe data should have been generated by this point

	case $exec in
	'')	if	test ! -f $INSTALLROOT/bin/.paths -o -w $INSTALLROOT/bin/.paths
		then	N='
'
			b= f= h= n= p= u= B= L=
			if	test -f $INSTALLROOT/bin/.paths
			then	exec < $INSTALLROOT/bin/.paths
				while	read x
				do	case $x in
					'#'?*)		case $h in
							'')	h=$x ;;
							esac
							;;
					*BUILTIN_LIB=*)	b=$x
							;;
					*FPATH=*)	f=$x
							;;
					*PLUGIN_LIB=*)	p=$x
							;;
					*)		case $u in
							?*)	u=$u$N ;;
							esac
							u=$u$x
							;;
					esac
				done
			fi
			ifs=$IFS
			m=
			case $p in
			?*)	b=
				;;
			esac
			case $b in
			?*)	IFS='='
				set $b
				IFS=$ifs
				shift
				p="PLUGIN_LIB=$*"
				case $b in
				[Nn][Oo]*)	p=no$p ;;
				esac
				m=1
				;;
			esac
			case $f in
			'')	f="FPATH=../fun"
				m=1
				;;
			esac
			case $h in
			'')	h='# use { no NO } prefix to permanently disable #' ;;
			esac
			case $p in
			'')	p="PLUGIN_LIB=cmd"
				if	grep '^setv mam_cc_DIALECT .* EXPORT=[AD]LL' $INSTALLROOT/lib/probe/C/mam/* >/dev/null 2>&1
				then	p=no$p
				fi
				m=1
				;;
			esac
			case $m in
			1)	case $u in
				?*)	u=$N$u ;;
				esac
				echo "$h$N$p$N$f$N$u" > $INSTALLROOT/bin/.paths
				;;
			esac
		fi
		;;
	esac

	# run from separate copies since nmake and ksh may be rebuilt

	case $EXECROOT in
	$INSTALLROOT)
		$make cd $INSTALLROOT/bin
		if	executable /bin/cp
		then	cp=/bin/cp
		else	cp=cp
		fi
		if	executable /bin/mv
		then	mv=/bin/mv
		else	mv=mv
		fi
		if	executable /bin/rm
		then	rm=/bin/rm
		else	rm=rm
		fi
		for i in \
			ksh nmake tee cp ln mv rm \
			*ast*.dll *cmd*.dll *dll*.dll *shell*.dll
		do	executable $i && {
				cmp -s $i $OK/$i 2>/dev/null || {
					test -f $OK/$i &&
					$exec $execrate $rm $OK/$i </dev/null
					test -f $OK/$i &&
					$exec $execrate $mv $OK/$i $OK/$i.old </dev/null
					test -f $OK/$i &&
					case $exec:$i in
					:nmake|:ksh)
						echo "$command: $OK/$i: cannot update [may be in use by a running process] remove manually and try again" >&2
						exit 1
						;;
					esac
					$exec $execrate $cp $i $OK/$i
				}
			}
		done
		if	test -f ../lib/make/makerules.mo
		then	cmp -s ../lib/make/makerules.mo $OK/lib/makerules.mo ||
			$exec $execrate $cp -p ../lib/make/makerules.mo $OK/lib/makerules.mo ||
			$exec $execrate $cp ../lib/make/makerules.mo $OK/lib/makerules.mo
		fi
		if	executable $OK/nmake
		then	MAKE="$INSTALLROOT/bin/$OK/nmake LOCALRULESPATH=$INSTALLROOT/bin/$OK/lib"
		fi
		if	executable $OK/tee
		then	TEE=$INSTALLROOT/bin/$OK/tee
		fi
		if	test "$KEEP_SHELL" != 1 && executable $OK/ksh
		then	SHELL=$INSTALLROOT/bin/$OK/ksh
			export SHELL
			COSHELL=$SHELL
			export COSHELL
		fi
		case :$PATH: in
		*:$INSTALLROOT/bin/$OK:*)
			;;
		*)	PATH=$INSTALLROOT/bin/$OK:$PATH
			export PATH
			;;
		esac
		$make cd $INSTALLROOT/src
		;;
	esac

	# fall back to mamake if nmake not found or too old

	if	nonmake $MAKE
	then	note make with mamake
		case $target in
		'')	target="install" ;;
		esac
		eval capture mamake \$makeflags \$noexec \$target $assign
	else	case $target in
		'')	target="install cc-" ;;
		esac
		eval capture \$MAKE \$makeflags \$nmakeflags \$noexec recurse \$target \$nmakesep \$package $assign
	fi
	;;

read)	case ${PWD:-`pwd`} in
	$PACKAGEROOT)
		;;
	*)	echo "$command: must be in package root directory" >&2
		exit 1
		;;
	esac
	PAX=
	if	onpath pax
	then	case `$_onpath_ -rw --?meter 2>&1` in
		*--meter*)	PAX=pax ;;
		esac
	fi
	code=0
	i=
	x=
	remove=
	touch=
	set '' $target
	case $2 in
	lcl|tgz)tgz=$2
		shift 2
		target=$*
		;;
	*)	tgz=tgz
		;;
	esac
	set '' $package $target
	case $# in
	1)	verbose=:
		set '' `ls lib/package/$tgz/*?[_.][0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789][_.]* 2>/dev/null`
		;;
	*)	verbose=
		;;
	esac
	shift
	files=
	for f
	do	if	test -f "$f"
		then	: ok
		elif	test -f "lib/package/$tgz/$f"
		then	f=lib/package/$tgz/$f
		else	set '' `ls -r ${f}[_.][0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789][_.]* 2>/dev/null`
			if	test '' != "$2" -a -f "$2"
			then	f=$2
			else	set '' `ls -r lib/package/$tgz/${f}[_.][0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789][_.]* 2>/dev/null`
				if	test '' != "$2" -a -f "$2"
				then	f=$2
				else	echo "$command: $f: package archive not found" >&2
					continue
				fi
			fi
		fi
		files="$files $f"
	done
	case $files in
	'')	echo "$command: lib/package/$tgz: no package archives" >&2
		exit 1
		;;
	esac
	set '' `ls -r $files 2>/dev/null`
	shift
	f1= f2= f3= f4=
	for f
	do	case $f in
		ratz.*|*/ratz.*)
			f1="$f1 $f"
			;;
		INIT.*|*/INIT.*)
			f2="$f2 $f"
			;;
		INIT*|*/INIT*)
			f3="$f3 $f"
			;;
		*)	f4="$f4 $f"
			;;
		esac
	done
	gen=
	set '' $f1 $f2 $f3 $f4
	while	:
	do	shift
		case $# in
		0)	break ;;
		esac
		f=$1
		case $f in
		*.gz)	: standalone packages unbundled manually
			continue
			;;
		*.md5)	: tarball checksum
			continue
			;;
		*?[_.][0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789][_.]*)
			;;
		*)	echo "$command: $f: not a package archive" >&2
			code=1
			continue
			;;
		esac
		case $f in
		*/*)	eval `echo "$f" | sed -e 's,\(.*/\)\(.*\),d=\1 a=\2,'` ;;
		*)	d= a=$f ;;
		esac
		# f:file d:dir a:base p:package v:version r:release t:type
		eval `echo "$a" | sed -e 's,\.c$,,' -e 's,\.gz$,,' -e 's,\.exe$,,' -e 's,\.tgz$,,' -e 's,\([^_.]*\)[_.]\([0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789]\)[_.]\([0123456789][0123456789][0123456789][0123456789][^_.]*\)[_.]*\(.*\),p=\1 v=\2 r=\3 t=\4,' -e 's,\([^_.]*\)[_.]\([0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789]\)[_.]*\(.*\),p=\1 v=\2 r=base t=\3,'`
		case $r in
		base)	y=$p.base ;;
		*)	y=$p.delta ;;
		esac
		case " $x " in
		*" $y "*)
			continue
			;;
		esac
		case $t in
		'')	w=$PACKAGESRC
			q=
			Q=
			m=
			;;
		*)	w=$PACKAGEROOT/arch/$t/lib/package
			q=".$t"
			Q="_$t"
			m="[_.]$t"
			;;
		esac
		u=$d$p$q.tim
		if	test -s "$u"
		then	continue
		else	case $force in
			0)	case `ls -t "$f" "$u" 2>/dev/null` in
				"$u"*)	case $verbose in
					1)	note $p already read ;;
					esac
					continue
					;;
				esac
				;;
			esac
		fi
		case $p in
		INIT)	if	test -f $PACKAGEROOT/bin/package
			then	$exec mv $PACKAGEROOT/bin/package $PACKAGEROOT/bin/package.old
			fi
			;;
		esac
		z=
		case $r in
		base)	# base archive
			if	test ratz = "$p"
			then	# ratz packages are not archives
				case $t in
				'')	for i in src src/cmd src/cmd/INIT
					do	test -d $PACKAGEROOT/$i || $exec mkdir $PACKAGEROOT/$i || exit
					done
					$exec cp $f $PACKAGEROOT/src/cmd/INIT/$p.c
					;;
				*)	for i in arch arch/$t arch/$t/bin
					do	test -d $PACKAGEROOT/$i || $exec mkdir $PACKAGEROOT/$i || exit
					done
					$exec cp $f $PACKAGEROOT/arch/$t/bin/$p &&
					$exec chmod +x $PACKAGEROOT/arch/$t/bin/$p
					;;
				esac
			elif	test "" != "$PAX"
			then	$exec pax -L --from=ascii --local -m -ps -rvf "$f" || {
					code=1
					continue
				}
			else	if	onpath gunzip && onpath $TAR && isascii
				then	case $TARPROBE in
					?*)	for i in $TARPROBE
						do	if	$TAR ${i}f - /dev/null > /dev/null 2>&1
							then	TARFLAGS=$TARFLAGS$i
							fi
						done
						TARPROBE=
						;;
					esac
					if	gunzip -l < "$f" > /dev/null 2>&1
					then	case $exec in
						'')	$exec gunzip < "$f" | $TAR ${TARFLAGS}f - ;;
						*)	$exec "gunzip < $f | $TAR ${TARFLAGS}f -" ;;
						esac || {
							code=1
							continue
						}
					else	$exec $TAR ${TARFLAGS}f "$f" || {
							code=1
							continue
						}
					fi
				else	checkaout ratz && onpath ratz || {
						code=1
						continue
					}
					RATZ=$_onpath_
					case $exec in
					'')	echo $f:
						$exec $RATZ -lm < "$f"
						;;
					*)	$exec "$RATZ -lm < $f"
						;;
					esac || {
						code=1
						continue
					}
				fi
				if	test -f $PACKAGEBIN/gen/$p.sum
				then	while	read md5 mode usr grp file
					do	case $file in
						-*)	file=./$file ;;
						esac
						case $mode in
						[01234567][01234567][01234567][01234567])
							case $grp in
							-)	;;
							*)	$exec chgrp $grp "$file" ;;
							esac
							case $usr in
							-)	;;
							*)	$exec chown $usr "$file" ;;
							esac
							$exec chmod $mode "$file"
							;;
						esac
					done < $PACKAGEBIN/gen/$p.sum
				fi
			fi
			;;
		*)	# delta archive
			test "" != "$PAX" || {
				echo "$command: $f: pax required to read delta archive" >&2
				code=1
				continue
			}
			case `echo "$v:
$r:" | sort` in
			$r:*)	y=$p.base
				b=${d}${p}_${r}${Q}.tgz
				test -f "$b" || b=${d}${p}.${r}${q}.tgz
				test -f "$b" || {
					case " $gen " in
					*" $b "*)
						;;
					*)	case $# in
						1)	echo "$command: $f: base archive $b required to read delta" >&2
							code=1
							;;
						*)	shift
							y=$1
							shift
						set '' $y $f "$@"
						esac
						continue
						;;
					esac
				}
				# -m with delta bug fixed 2005-02-08
				$exec pax -L --from=ascii --local -ps -rvf "$f" -z "$b" || {
					code=1
					continue
				}
				note $f: generate new base $d$p.$v$q.tgz
				$exec pax -rf "$f" -z "$b" -wf $d$p.$v$q.tgz -x tgz || {
					code=1
					continue
				}
				case $exec in
				'')	echo $p $v $v 1 > $w/gen/$p.ver
					;;
				*)	z=$d${p}[_.]$v$q.tgz
					$exec "echo $p $v $v 1 > $w/gen/$p.ver"
					gen="$gen $d$p.$v$q.tgz"
					;;
				esac
				case " $remove " in
				*" $f "*)	;;
				*)		remove="$remove $f" ;;
				esac
				;;
			*)	b=${d}${p}_${v}${Q}.tgz
				test -f "$b" || b=${d}${p}.${v}${q}.tgz
				test -f "$b" || {
					case " $gen " in
					*" $b "*)
						;;
					*)	case $# in
						1)	echo "$command: $f: base archive $b required to read delta" >&2
							code=1
							;;
						*)	shift
							y=$1
							shift
							set '' $y $f "$@"
						esac
						continue
						;;
					esac
				}
				# -m with delta bug fixed 2005-02-08
				$exec pax -L --from=ascii --local -ps -rvf "$f" -z "$b" || {
					code=1
					continue
				}
				;;
			esac
			;;
		*)	echo "$command: $f: unknown archive type" >&2
			code=1
			continue
			;;
		esac

		# check for ini files

		if	executable $w/$p.ini
		then	$exec $w/$p.ini read || {
				code=1
				continue
			}
		fi

		# add to the obsolete list

		k=
		for i in `ls $d$p[_.][0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789][_.]????$m* $z 2>/dev/null`
		do	case $i in
			*.md5)	continue
				;;
			$d${p}[_.][0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789][_.][0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789]$m*)
				;;
			$d${p}[_.][0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789]$m*)
				continue
				;;
			esac
			case $k in
			?*)	case " $remove " in
				*" $k "*)	;;
				*)		remove="$remove $k" ;;
				esac
				;;
			esac
			k=$i
		done
		x="$x $y"
		case " $touch " in
		*" $u "*)	;;
		*)		touch="$touch $u" ;;
		esac
	done
	if	test ! -f $PACKAGEROOT/bin/package -a -f $PACKAGEROOT/bin/package.old
	then	$exec cp $PACKAGEROOT/bin/package.old $PACKAGEROOT/bin/package
	fi

	# drop obsolete archives

	case $remove in
	?*)	$exec rm -f $remove ;;
	esac

	# mark the updated archives

	case $touch in
	?*)	sleep 1; $exec touch $touch ;;
	esac

	# check the requirements

	case $code$exec in
	0)	requirements - $x ;;
	esac
	exit $code
	;;

regress)if	test ! -d $PACKAGEBIN/gen
	then	echo "$command: 'package make' and 'package test' required for regression" >&2
		exit 1
	fi
	dir=$PACKAGEBIN/gen
	cd $dir
	for s in out old
	do	case `ls -t regress.$s test.$s 2>/dev/null` in
		regress*)
			;;
		test*)	if	test -f regress.$s
			then	$exec mv regress.$s regress.old
			fi
			case $exec in
			'')	egrep -i '\*\*\*|FAIL|^TEST.* [123456789][0123456789]* error|core.*dump' test.$s |
				sed 	-e '/\*\*\* [0123456789]/d' \
					-e '/^TEST.\//s,/[^ ]*/,,' \
					-e 's,[ 	][ 	]*$,,' \
					-e 's/[0123456789][0123456789]*:* \([abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789 ]*([abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789 ]*[Cc][Oo][Rr][Ee][abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789 ]*)\)/\1/' \
					-e 's/\.sh failed at .* with /.sh failed /' \
					> regress.$s
				;;
			*)	$exec filter test failures from $dir/test.$s to $dir/regress.$s
				;;
			esac
			;;
		esac
	done
	if	test -f regress.out -a -f regress.old
	then	$exec diff -b regress.out regress.old
	else	echo "$command: at least 2 test runs required for regression" >&2
			exit 1
	fi
	;;

release)count= lo= hi=
	checksrc
	checkaout release || exit
	requirements source $package
	components $package
	package=$_components_
	set '' $target
	shift
	case $# in
	0)	;;
	*)	case $1 in
		-|[0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789]|[0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789])
			case $1 in
			-)	lo= release= ;;
			*)	lo=$1 release="-f $1" ;;
			esac
			shift
			case $1 in
			-|[0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789]|[0123456789][0123456789][0123456789][0123456789]-[0123456789][0123456789]-[0123456789][0123456789])
				case $1 in
				-)	hi= ;;
				*)	hi=$1 release="$release -t $1" ;;
				esac
				shift
				;;
			esac
			;;
		[0123456789]|[0123456789][0123456789]|[0123456789][0123456789][0123456789]|[0123456789][0123456789][0123456789][0123456789]|[0123456789][0123456789][0123456789][0123456789][0123456789]*)
			count=$1
			release="-r $count"
			shift
			;;
		esac
		;;
	esac
	case $# in
	0)	case $package in
		'')	package=* ;;
		esac
		;;
	*)	case $package in
		'')	package=$*
			;;
		*)	echo $command: $*: lo-date hi-date arguments expected >&2
			exit 1
			;;
		esac
		;;
	esac
	echo
	case $count:$lo:$hi in
	::)	echo "All recorded changes follow." ;;
	1::)	echo "Changes since the last release follow." ;;
	?*::)	echo "Changes since the last $count releases follow." ;;
	1:?*:)	echo "Changes since $lo or the last release follow." ;;
	*:?*:*)	echo "Changes since $lo follow." ;;
	*::?*)	echo "Changes before $hi follow." ;;
	*)	echo "Changes between $lo and $hi follow." ;;
	esac
	x=
	for r in $INSTALLROOT $PACKAGEROOT
	do	for s in $package_src
		do	d=$r/src/$s
			if	test -d $d
			then	cd $d
				for i in $package
				do	if	test -h $i 2>/dev/null
					then	continue
					fi
					case " $x " in
					*" $i "*)	continue ;;
					esac
					for f in RELEASE CHANGES ChangeLog
					do	if	test -f $i/$f
						then	$exec release $release $i/$f
							x="$x $i"
							for f in $i/*/$f
							do	if	test -f $f
								then	$exec release $release $f
								fi
							done
							break
						fi
					done
				done
			fi
		done
	done
	;;

remove)	echo "$command: $action: not implemented yet" >&2
	exit 1
	;;

results)set '' $target
	shift
	def=make
	dir=$PACKAGEBIN/gen
	case $verbose in
	0)	filter=yes ;;
	*)	filter=cat ;;
	esac
	path=0
	suf=out
	on=
	while	:
	do	case $# in
		0)	break ;;
		esac
		case $1 in
		--)	shift
			break
			;;
		admin)	dir=$PACKAGESRC/admin
			;;
		error*|fail*)
			filter=errors
			;;
		make|test|view|write)
			def=$1
			case $filter:$1:$SHELL in
			errors:*:*)	;;
			*:test:*/ksh*)	filter=rt ;;
			esac
			;;
		old)	suf=old
			;;
		on)	case $# in
			1)	echo $command: $action: $1: host pattern argument expected >&2
				exit 1
				;;
			esac
			shift
			case $on in
			?*)	on="$on|" ;;
			esac
			on="$on$1"
			;;
		path)	path=1
			;;
		test)	def=test
			filter=rt
			;;
		*)	break
			;;
		esac
		shift
	done
	case $dir in
	*/admin)case $on in
		'')	on="*" ;;
		*)	on="@($on)" ;;
		esac
		def=$def.log/$on
		;;
	esac
	case $# in
	0)	set "$def" ;;
	esac
	m=
	t=
	for i
	do	k=0
		eval set '""' $i - $i.$suf - $dir/$i - $dir/$i.$suf -
		shift
		for j
		do	case $j in
			-)	case $k in
				1)	continue 2 ;;
				esac
				;;
			*)	if	test -f $j
				then	k=1
					case /$j in
					*/test.*)	t="$t $j" ;;
					*)		m="$m $j" ;;
					esac
				fi
				;;
			esac
		done
		echo "$command: $i action output not found" >&2
		exit 1
	done
	sep=
	case $t in
	?*)	case $path in
		0)	for j in $t
			do	echo "$sep==> $j <=="
				sep=$nl
				case $filter in
				cat)	$exec cat $j
					;;
				errors)	$exec egrep -i '\*\*\*|FAIL[ES]|^TEST.* [123456789][0123456789]* error|core.*dump' $j | sed -e '/^TEST.\//s,/[^ ]*/,,'
					;;
				rt)	$exec $KSH rt - $j
					;;
				*)	$exec egrep -i '^TEST|FAIL' $j
					;;
				esac
			done
			;;
		1)	echo $t
			;;
		esac
		;;
	esac
	case $m in
	?*)	case $path in
		0)	case $filter in
			cat)	cat $m
				;;
			*)	if	test -f $HOME/.pkgresults
				then	i="`cat $HOME/.pkgresults`"
					case $i in
					'|'*)	;;
					*)	i="|$i" ;;
					esac
				else	i=
				fi
				for j in $m
				do	echo "$sep==> $j <=="
					sep=$nl
					case $filter in
					errors)	$exeg egrep '^pax:|\*\*\*' $j
						;;
					*)	$exec egrep -iv '^($||[\+\[]|cc[^-:]|kill |make.*(file system time|has been replaced)|so|[0123456789]+ error|uncrate |[0123456789]+ block|ar: creat|iffe: test: |conf: (check|generate|test)|[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_][abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789]*=|gsf@research|ar:.*warning|cpio:|ld:.*(duplicate symbol|to obtain more information)|[0123456789]*$|(checking|creating|touch) [/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789])| obsolete predefined symbol | is (almost always misused|dangerous|deprecated|not implemented)| trigraph| assigned to | cast .* different size| integer overflow .*<<| optimization may be attained | passed as |::__builtin|pragma.*prototyped|^creating.*\.a$|warning.*not optimized|exceeds size thresh|ld:.*preempts|is unchanged|with value >=|(-l|lib)\*|/(ast|sys)/(dir|limits|param|stropts)\.h.*redefined|usage|base registers|`\.\.\.` obsolete'"$i" $j |
						$exec grep :
						;;
					esac
				done
				;;
			esac
			;;
		1)	echo $m
			;;
		esac
	esac
	;;

test)	requirements source $package
	components $package
	package=$_components_
	case $only in
	0)	only= ;;
	1)	only=--recurse=only ;;
	esac

	# must have nmake

	if	nonmake $MAKE
	then	echo $command: $action: must have $MAKE to test >&2
		exit 1
	fi

	# all work under $INSTALLROOT/src

	$make cd $INSTALLROOT/src

	# disable core dumps (could be disasterous over nfs)

	(ulimit -c 0) > /dev/null 2>&1 && ulimit -c 0

	# do the tests

	eval capture \$MAKE \$makeflags \$noexec \$only recurse test \$target \$nmakesep \$package $assign
	;;

update)	# download the latest release.version for selected packages

	# all work in $PACKAGEROOT/lib/package/tgz

	if	test ! -d $PACKAGEROOT/lib/package/tgz
	then	$exec mkdir -p $PACKAGEROOT/lib/package/tgz || exit
		$exec cd $PACKAGEROOT/lib/package/tgz
	else	cd $PACKAGEROOT/lib/package/tgz
	fi

	# get the architectures, update query url, and packages

	set '' $args
	op=update
	tgz=tgz
	source=
	binary=
	setup=
	types=
	url=
	urlfile=$default_url
	while	:
	do	shift
		case $# in
		0)	break ;;
		esac
		case $1 in
		--)	shift
			break
			;;
		beta)	op=beta
			tgz=beta
			;;
		binary)	binary=1
			;;
		setup)	setup=1
			;;
		source)	source=1
			;;
		*://*)	url=$1
			shift
			break
			;;
		*.url)	urlfile=$1
			if	test ! -s $urlfile
			then	echo $command: $urlfile: not found >&2; exit 1
			fi
			break
			;;
		$all_types)
			binary=1
			types="$types $1"
			;;
		*)	break
			;;
		esac
	done
	case $source:$binary in
	:)	source=1 binary=1
		;;
	:1)	case $types in
		'')	types=$HOSTTYPE ;;
		esac
		;;
	esac
	case $url in
	'')	case $urlfile in
		$default_url)
			if	test ! -s $urlfile
			then	echo $command: url argument expected >&2; exit 1
			fi
			;;
		*)	default_url=
			;;
		esac
		url=
		if	grep '^url=' $urlfile >/dev/null
		then	a=$authorize
			p=$password
			case $urlfile in
			*/*)	;;
			*)	urlfile=./$urlfile ;;
			esac
			. $urlfile
			case $a:$p in
			$authorize:$password)
				default_url=
				;;
			*)	case $a in
				?*)	authorize=$a ;;
				esac
				case $p in
				?*)	password=$p ;;
				esac
				;;
			esac
		else	url=`cat $urlfile`
		fi
		;;
	esac
	case $exec in
	?*)	default_url= ;;
	esac

	# get the update list

	eval `echo $url | sed 's,\(.*\)://\([^/]*\)/\(.*\),prot=\"\1\" host=\"\2\" dir=\"\3\",'`
	get $host $dir/$op.html

	# get/check the package names

	case " $* " in
	*" - "*)case $source in
		1)	source_packages=$* ;;
		*)	source_packages= ;;
		esac
		case $binary in
		1)	binary_packages=$* ;;
		*)	binary_packages= ;;
		esac
		package_hit=$*
		;;
	"  ")	nl="
"
		case $source in
		1)	p=
			for f in `ls *.????-??-??.* 2>/dev/null`
			do	case $f in
				*.????-??-??.????-??-??.*.*)
					;;
				*.????-??-??.????-??-??.*)
					p=$p$nl$f
					;;
				*.????-??-??.*.*)
					;;
				*.????-??-??.*)
					p=$p$nl$f
					;;
				esac
			done
			set '' `echo "$p" | sed 's,\..*,,' | sort -u`
			shift
			source_packages=$*
			;;
		*)	source_packages=
			;;
		esac
		case $binary in
		1)	p=
			for f in `ls *.????-??-??.* 2>/dev/null`
			do	case $f in
				*.????-??-??.????-??-??.*.*)
					p=$p$nl$f
					;;
				*.????-??-??.????-??-??.*)
					;;
				*.????-??-??.*.*)
					p=$p$nl$f
					;;
				*.????-??-??.*)
					;;
				esac
			done
			set '' `echo "$p" | sed 's,\..*,,' | sort -u`
			shift
			binary_packages=$*
			;;
		*)	binary_packages=
			;;
		esac
		package_hit="$source_packages $binary_packages"
		;;
	*)	case $source in
		1)	source_packages=$* ;;
		*)	source_packages= ;;
		esac
		case $binary in
		1)	binary_packages=$* ;;
		*)	binary_packages= ;;
		esac
		package_hit=
		;;
	esac

	# get the latest updates

	types_test=
	types_local=
	dir=$dir/$tgz
	case $default_url in
	?*)	echo "url='$url' authorize='$authorize' password='$password'" > $default_url
		case $authorize in
		?*)	chmod go-rwx $default_url ;;
		esac
		;;
	esac
	echo "$got" > got.tmp
	case $only in
	0)	exec < got.tmp
		covered=
		while	read name suffix type base base_size delta delta_size sync sync_size requires covers base_sum delta_sum sync_sum comment
		do	case $requires in
			''|-*)	continue ;;
			esac
			IFS=:
			set '' $requires
			IFS=$ifs
			case $type in
			-)	case " $source_packages " in
				*" $name "*|*" - "*)
					for name
					do	case " $source_packages " in
						*" $name "*)
							;;
						*)	source_packages="$source_packages $name"
							covered=$covered:$covers
							;;
						esac
					done
					;;
				esac
				;;
			*)	case " $binary_packages " in
				*" $name "*|*" - "*)
					for name
					do	case " $binary_packages " in
						*" $name "*)
							;;
						*)	binary_packages="$binary_packages $name"
							covered=$covered:$covers
							;;
						esac
					done
					;;
				esac
				;;
			esac
		done
		case $covered in
		?*)	x=$source_packages
			source_packages=
			for name in $x
			do	case :$covered: in
				*:$name:*)	;;
				*)		source_packages="$source_packages $name" ;;
				esac
			done
			x=$binary_packages
			binary_packages=
			for name in $x
			do	case :$covered: in
				*:$name:*)	;;
				*)		binary_packages="$binary_packages $name" ;;
				esac
			done
			;;
		esac
		;;
	esac
	checksum=
	for i in $checksum_commands
	do	case `( $i ) < /dev/null 2> /dev/null` in
		${checksum_empty}|${checksum_empty}[\ \	]*)
			checksum=$i
			break
			;;
		esac
	done
	case $checksum in
	'')	echo $command: warning: '{' $checksum_commands '}' command not found -- only download sizes will be checked >&2 ;;
	esac
	exec < got.tmp
	while	read name suffix type base base_size delta delta_size sync sync_size requires covers base_sum delta_sum sync_sum comment
	do	case $verbose in
		1)	case $type in
			-)	i= ;;
			*)	i=.$type ;;
			esac
			j="$name.$base$i.$suffix"
			case $delta in
			-)	j="$j -" ;;
			*)	j="$j $name.$base.$delta$i.$suffix" ;;
			esac
			case $sync in
			-)	j="$j -" ;;
			*)	j="$j $name.$base.$sync$i.$suffix" ;;
			esac
			echo $command: $j $base_size:$base_sum $delta_size:$delta_sum $sync_size:$sync_sum $requires >&2
		esac
		case " $package_hit " in
		*" $name "*|*" - "*)
			;;
		*)	package_hit="$package_hit $name"
			;;
		esac
		case $type in
		-)	case " $source_packages " in
			*" $name "*|*" - "*)
				if	test -s $name.tim
				then	continue
				fi
				lcl=$name.$base.$suffix
				if	test -f $lcl
				then	case $checksum:$base_sum in
					:*|*:-)	size=`wc -c < $lcl | sed 's, ,,g'` sum=$base_sum ;;
					*)	size=$base_size sum=`$checksum < $lcl | sed -e 's,^[ 	][ 	]*,,' -e 's,[ 	].*,,'` ;;
					esac
				else	size=X sum=X
				fi
				if	test "0" != "$force" -a "X-" = "X$delta" -o "$base_size" != "$size" -o "$base_sum" != "$sum"
				then	rmt=
					case $sync:$sync_size in
					-*|*[-:])
						;;
					*)	lcl=$name.$base.$sync.$suffix
						if	test -f $lcl
						then	rmt=1
							get $host $dir $lcl $sync_size $sync_sum
						fi
						;;
					esac
					case $base:$base_size in
					-*|*[-:])
						;;
					*)	case $rmt in
						'')	lcl=$name.$base.$suffix
							get $host $dir $lcl $base_size $base_sum
							;;
						esac
						;;
					esac
				fi
				case $delta:$delta_size in
				-*|*[-:])
					;;
				*)	lcl=$name.$delta.$base.$suffix
					if	test -f $lcl
					then	case $checksum:$delta_sum in
						:*|*:-)	size=`wc -c < $lcl | sed 's, ,,g'` sum=$delta_sum ;;
						*)	size=$base_size sum=`$checksum < $lcl | sed -e 's,^[ 	][ 	]*,,' -e 's,[ 	].*,,'` ;;
						esac
					else	size=X sum=X
					fi
					if	test "0" != "$force" -o "$delta_size" != "$size" -o "$delta_sum" != "$sum"
					then	get $host $dir $lcl $delta_size $delta_sum
					fi
					;;
				esac
				;;
			esac
			;;
		*)	case " $binary_packages " in
			*" $name "*|*" - "*)
				if	test -s $name.$type.tim
				then	continue
				fi
				case " $types " in
				*" - "*);;
				"  ")	case " $types_test " in
					*" $type "*)
						;;
					*)	types_test="$types_test $type"
						for i in *.????-??-??.$type.* *.????-??-??.????-??-??.$type.*
						do	if	test -f $i
							then	types_local="$types_local $type"
							fi
							break
						done
						;;
					esac
					case " $types_local " in
					*" $type "*)
						;;
					*)	continue
						;;
					esac
					;;
				*)	case " $types " in
					*" $type "*)
						;;
					*)	continue
						;;
					esac
					;;
				esac
				lcl=$name.$base.$type.$suffix
				if	test -f $lcl
				then	case $checksum:$base_sum in
					:*|*:-)	size=`wc -c < $lcl | sed 's, ,,g'` sum=$base_sum ;;
					*)	size=$base_size sum=`$checksum < $lcl | sed -e 's,^[ 	][ 	]*,,' -e 's,[ 	].*,,'` ;;
					esac
				else	size=X sum=X
				fi
				if	test "0" != "$force" -a "X-" = "X$delta" -o "$base_size" != "$size" -o "$base_sum" != "$sum"
				then	rmt=
					case $sync:$sync_size in
					-*|*[-:])
						;;
					*)	lcl=$name.$base.$sync.$type.$suffix
						if	test -f $lcl
						then	rmt=1
							get $host $dir $lcl $sync_size $sync_sum
						fi
						;;
					esac
					case $base:$base_size in
					-*|*[-:])
						;;
					*)	case $rmt in
						'')	lcl=$name.$base.$type.$suffix
							get $host $dir $lcl $base_size $base_sum
							;;
						esac
						;;
					esac
				fi
				case $delta:$delta_size in
				-*|*[-:])
					;;
				*)	lcl=$name.$delta.$base.$type.$suffix
					if	test -f $lcl
					then	sum=`$checksum < $lcl | sed -e 's,^[ 	][ 	]*,,' -e 's,[ 	].*,,'`
					else	sum=X
					fi
					if	test -f $lcl
					then	case $checksum:$delta_sum in
						:*|*:-)	size=`wc -c < $lcl | sed 's, ,,g'` sum=$delta_sum ;;
						*)	size=$base_size sum=`$checksum < $lcl | sed -e 's,^[ 	][ 	]*,,' -e 's,[ 	].*,,'` ;;
						esac
					else	size=X sum=X
					fi
					if	test "0" != "$force" -o "$delta_size" != "$size" -o "$delta_sum" != "$sum"
					then	get $host $dir $lcl $delta_size $delta_sum
					fi
					;;
				esac
				;;
			esac
			;;
		esac
	done
	closure=
	for name in $source_packages $binary_packages
	do	case $name in
		-)	;;
		*)	case " $package_hit " in
			*" $name "*)
				case $setup in
				1)	case " $closure " in
					*" $name "*)
						;;
					*)	closure="$closure $name"
						;;
					esac
					;;
				esac
				;;
			*)	echo $command: $name: unknown package >&2
				;;
			esac
			;;
		esac
	done
	exec <&-
	rm -f got.tmp
	case $closure in
	?*)	echo $closure ;;
	esac
	;;

use)	# finalize the environment

	x=:..
	for d in `( cd $PACKAGEROOT; ls src/*/Makefile src/*/Nmakefile 2>/dev/null | sed 's,/[^/]*$,,' | sort -u )`
	do	x=$x:$INSTALLROOT/$d
	done
	x=$x:$INSTALLROOT
	case $CDPATH: in
	$x:*)	;;
	*)	CDPATH=$x:$CDPATH
		$show CDPATH=$CDPATH
		$show export CDPATH
		export CDPATH
		;;
	esac
	P=$PACKAGEROOT
	$show P=$P
	$show export P
	export P
	A=$INSTALLROOT
	$show A=$A
	$show export A
	export A
	case $NPROC in
	'')	hostinfo cpu
		case $_hostinfo_ in
		0|1)	;;
		*)	NPROC=$_hostinfo_
			$show NPROC=$NPROC
			$show export NPROC
			export NPROC
			;;
		esac
		;;
	esac
	eval PACKAGE_USE=$package_use
	export PACKAGE_USE

	# run the command

	case $run in
	'')	case $show in
		':')	$exec exec $SHELL ;;
		esac
		;;
	*)	$exec exec $SHELL -c "$run"
		;;
	esac
	;;

verify)	cd $PACKAGEROOT
	requirements binary $package
	if	executable ! $SUM
	then	echo "$command: $action: $SUM command required" >&2
		exit 1
	fi
	case $target in
	'')	cd arch
		set '' *
		shift
		target=$*
		cd ..
		;;
	esac
	code=0
	for a in $target
	do	case $package in
		'')	set '' arch/$a/lib/package/gen/*.sum
			shift
			if	test -f $1
			then	for i
				do	package_verify $i || code=1
				done
			else	echo "$command: warning: $a: no binary packages" >&2
			fi
			;;
		*)	for i in $package
			do	if	test -f arch/$a/lib/package/gen/$i.sum
				then	package_verify arch/$a/lib/package/gen/$i.sum || code=1
				else	echo "$command: warning: $a: no binary package for $i" >&2
				fi
			done
			;;
		esac
	done
	exit $code
	;;

write)	set '' $target
	shift
	action=
	list=
	qualifier=
	while	:
	do	case $1 in
		base|closure|delta|exp|lcl|pkg|rpm|tgz)
			qualifier="$qualifier $1"
			;;
		binary)	action=$1
			type=$HOSTTYPE
			eval list=$PACKAGESRC/tgz/$admin_list
			;;
		cyg)	qualifier="$qualifier $1"
			assign="$assign closure=1"
			only=1
			;;
		runtime|source)
			action=$1
			;;
		tst)	qualifier="$qualifier tgz"
			assign="$assign copyright=0 'PACKAGEDIR=\$(PACKAGESRC)/tst'"
			;;
		nocopyright)
			assign="$assign copyright=0"
			;;
		*)	break
			;;
		esac
		shift
	done
	case $action in
	'')	echo "$command: binary or source operand expected" >&2
		exit 1
		;;
	esac
	set '' "$@" $package
	shift
	case $only in
	0)	set '' `order "$@"`
		shift
		;;
	esac
	case $# in
	0)	echo "$command: at least one package name expected" >&2
		exit 1
		;;
	esac
	if	nonmake $MAKE
	then	echo "$command: must have $MAKE to generate archives" >&2
		exit 1
	fi

	# all work under $PACKAGEBIN

	$make cd $PACKAGEBIN
	case $list in
	?*)	$exec rm -f $list ;;
	esac

	# go for it

	for package
	do	if	view - all $package.pkg || view - all lib/package/$package.pkg
		then	eval capture \$MAKE \$makeflags -X ignore \$noexec -f \$package.pkg \$qualifier \$action $assign
		else	echo "$command: $package: not a package" >&2
		fi
	done
	;;

TEST)	set '' $target $package
	shift
	case $1 in
	binary|source)
		action=$1
		shift
		;;
	esac
	order "$@"
	;;

*)	echo "$command: $action: internal error" >&2
	exit 1
	;;

esac
