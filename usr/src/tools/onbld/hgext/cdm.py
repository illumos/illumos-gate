#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2
#  as published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

#
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2008, 2011 Richard Lowe
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
# Copyright (c) 2014, Joyent, Inc.
#

'''OpenSolaris extensions to Mercurial

    This extension contains a number of commands to help you work with
the OpenSolaris consolidations.  It provides commands to check your
changes against the various style rules used for OpenSolaris, to
backup and restore your changes, to generate code reviews, and to
prepare your changes for integration.


The Parent

    To provide a uniform notion of parent workspace regardless of
filesystem-based access, Cadmium uses the highest numbered changeset
on the current branch that is also in the parent workspace to
represent the parent workspace.


The Active List

    Many Cadmium commands operate on the active list, the set of
files ('active files') you have changed in this workspace in relation
to its parent workspace, and the metadata (commentary, primarily)
associated with those changes.


NOT Files

    Many of Cadmium's commands to check that your work obeys the
various stylistic rules of the OpenSolaris consolidations (such as
those run by 'hg nits') allow files to be excluded from this checking
by means of NOT files kept in the .hg/cdm/ directory of the Mercurial
repository for one-time exceptions, and in the exception_lists
directory at the repository root for permanent exceptions.  (For ON,
these would mean one in $CODEMGR_WS and one in
$CODEMGR_WS/usr/closed).

    These files are in the same format as the Mercurial hgignore
file, a description of which is available in the hgignore(5) manual
page.


Common Tasks

  - Show diffs relative to parent workspace               - pdiffs
  - Check source style rules                              - nits
  - Run pre-integration checks                            - pbchk
  - Collapse all your changes into a single changeset     - recommit
'''

import atexit, os, re, sys, stat, termios


#
# Adjust the load path based on the location of cdm.py and the version
# of python into which it is being loaded.  This assumes the normal
# onbld directory structure, where cdm.py is in
# lib/python(version)?/onbld/hgext/.  If that changes so too must
# this.
#
# This and the case below are not equivalent.  In this case we may be
# loading a cdm.py in python2.X/ via the lib/python/ symlink but need
# python2.Y in sys.path.
#
sys.path.insert(1, os.path.join(os.path.dirname(__file__), "..", "..", "..",
                                "python%d.%d" % sys.version_info[:2]))

#
# Add the relative path from cdm.py to usr/src/tools to the load path,
# such that a cdm.py loaded from the source tree uses the modules also
# within the source tree.
#
sys.path.insert(2, os.path.join(os.path.dirname(__file__), "..", ".."))

from onbld.Scm import Version
from onbld.Scm import Ignore
from mercurial import util

try:
    Version.check_version()
except Version.VersionMismatch, badversion:
    raise util.Abort("Version Mismatch:\n %s\n" % badversion)

from mercurial import cmdutil, node, patch

from onbld.Scm.WorkSpace import WorkSpace, WorkList
from onbld.Scm.Backup import CdmBackup
from onbld.Checks import Cddl, Comments, Copyright, CStyle, HdrChk
from onbld.Checks import JStyle, Keywords, ManLint, Mapfile


def yes_no(ui, msg, default):
    if default:
        prompt = ' [Y/n]:'
        defanswer = 'y'
    else:
        prompt = ' [y/N]:'
        defanswer = 'n'

    if Version.at_least("1.4"):
        index = ui.promptchoice(msg + prompt, ['&yes', '&no'],
                                default=['y', 'n'].index(defanswer))
        resp = ('y', 'n')[index]
    else:
        resp = ui.prompt(msg + prompt, ['&yes', '&no'], default=defanswer)

    return resp[0] in ('Y', 'y')


def buildfilelist(ws, parent, files):
    '''Build a list of files in which we're interested.

    If no files are specified take files from the active list relative
    to 'parent'.

    Return a list of 2-tuples the first element being a path relative
    to the current directory and the second an entry from the active
    list, or None if an explicit file list was given.'''

    if files:
        return [(path, None) for path in sorted(files)]
    else:
        active = ws.active(parent=parent)
        return [(ws.filepath(e.name), e) for e in sorted(active)]
buildfilelist = util.cachefunc(buildfilelist)


def not_check(repo, cmd):
    '''return a function which returns boolean indicating whether a file
    should be skipped for CMD.'''

    #
    # The ignore routines need a canonical path to the file (relative to the
    # repo root), whereas the check commands get paths relative to the cwd.
    #
    # Wrap our argument such that the path is canonified before it is checked.
    #
    def canonified_check(ignfunc):
        def f(path):
            cpath = util.canonpath(repo.root, repo.getcwd(), path)
            return ignfunc(cpath)
        return f

    ignorefiles = []

    for f in [repo.join('cdm/%s.NOT' % cmd),
               repo.wjoin('exception_lists/%s' % cmd)]:
        if os.path.exists(f):
            ignorefiles.append(f)

    if ignorefiles:
        ign = Ignore.ignore(repo.root, ignorefiles)
        return canonified_check(ign)
    else:
        return util.never


def abort_if_dirty(ws):
    '''Abort if the workspace has uncommitted changes, merges,
    branches, or has Mq patches applied'''

    if ws.modified():
        raise util.Abort('workspace has uncommitted changes')
    if ws.merged():
        raise util.Abort('workspace contains uncommitted merge')
    if ws.branched():
        raise util.Abort('workspace contains uncommitted branch')
    if ws.mq_applied():
        raise util.Abort('workspace has Mq patches applied')


#
# Adding a reference to WorkSpace from a repo causes a circular reference
# repo <-> WorkSpace.
#
# This prevents repo, WorkSpace and members thereof from being garbage
# collected.  Since transactions are aborted when the transaction object
# is collected, and localrepo holds a reference to the most recently created
# transaction, this prevents transactions from cleanly aborting.
#
# Instead, we hold the repo->WorkSpace association in a dictionary, breaking
# that dependence.
#
wslist = {}


def reposetup(ui, repo):
    if repo.local() and repo not in wslist:
        wslist[repo] = WorkSpace(repo)

        if ui.interactive() and sys.stdin.isatty():
            ui.setconfig('hooks', 'preoutgoing.cdm_pbconfirm',
                         'python:hgext_cdm.pbconfirm')


def pbconfirm(ui, repo, hooktype, source):
    def wrapper(settings=None):
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, settings)

    if source == 'push':
        if not yes_no(ui, "Are you sure you wish to push?", False):
            return 1
        else:
            settings = termios.tcgetattr(sys.stdin.fileno())
            orig = list(settings)
            atexit.register(wrapper, orig)
            settings[3] = settings[3] & (~termios.ISIG) # c_lflag
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, settings)


def cdm_pdiffs(ui, repo, *pats, **opts):
    '''diff workspace against its parent

    Show differences between this workspace and its parent workspace
    in the same manner as 'hg diff'.

    For a description of the changeset used to represent the parent
    workspace, see The Parent in the extension documentation ('hg help
    cdm').
    '''

    act = wslist[repo].active(opts.get('parent'))
    if not act.revs:
        return

    #
    # If no patterns were specified, either explicitly or via -I or -X
    # use the active list files to avoid a workspace walk.
    #
    if pats or opts.get('include') or opts.get('exclude'):
        matchfunc = wslist[repo].matcher(pats=pats, opts=opts)
    else:
        matchfunc = wslist[repo].matcher(files=act.files())

    opts = patch.diffopts(ui, opts)
    diffs = wslist[repo].diff(act.parenttip.node(), act.localtip.node(),
                              match=matchfunc, opts=opts)
    if diffs:
        ui.write(diffs)


def cdm_list(ui, repo, **opts):
    '''list active files (those changed in this workspace)

    Display a list of files changed in this workspace as compared to
    its parent workspace.

    File names are displayed one-per line, grouped by manner in which
    they changed (added, modified, removed).  Information about
    renames or copies is output in parentheses following the file
    name.

    For a description of the changeset used to represent the parent
    workspace, see The Parent in the extension documentation ('hg help
    cdm').

    Output can be filtered by change type with --added, --modified,
    and --removed.  By default, all files are shown.
    '''

    act = wslist[repo].active(opts['parent'])
    wanted = set(x for x in ('added', 'modified', 'removed') if opts[x])
    changes = {}

    for entry in act:
        if wanted and (entry.change not in wanted):
            continue

        if entry.change not in changes:
            changes[entry.change] = []
        changes[entry.change].append(entry)

    for change in sorted(changes.keys()):
        ui.write(change + ':\n')

        for entry in sorted(changes[change]):
            if entry.is_renamed():
                ui.write('\t%s (renamed from %s)\n' % (entry.name,
                                                      entry.parentname))
            elif entry.is_copied():
                ui.write('\t%s (copied from %s)\n' % (entry.name,
                                                      entry.parentname))
            else:
                ui.write('\t%s\n' % entry.name)


def cdm_bugs(ui, repo, parent=None):
    '''show all bug IDs referenced in changeset comments'''

    act = wslist[repo].active(parent)

    for elt in set(filter(Comments.isBug, act.comments())):
        ui.write(elt + '\n')


def cdm_comments(ui, repo, parent=None):
    '''show changeset commentary for all active changesets'''
    act = wslist[repo].active(parent)

    for elt in act.comments():
        ui.write(elt + '\n')


def cdm_renamed(ui, repo, parent=None):
    '''show renamed active files

    Renamed files are shown in the format::

       new-name old-name

    One pair per-line.
    '''

    act = wslist[repo].active(parent)

    for entry in sorted(filter(lambda x: x.is_renamed(), act)):
        ui.write('%s %s\n' % (entry.name, entry.parentname))


def cdm_comchk(ui, repo, **opts):
    '''check active changeset comment formatting

    Check that active changeset comments conform to O/N rules.

    Each comment line must contain either one bug or ARC case ID
    followed by its synopsis, or credit an external contributor.
    '''

    active = wslist[repo].active(opts.get('parent'))

    ui.write('Comments check:\n')

    check_db = not opts.get('nocheck')
    return Comments.comchk(active.comments(), check_db=check_db, output=ui)


def cdm_cddlchk(ui, repo, *args, **opts):
    '''check for a valid CDDL header comment in all active files.

    Check active files for a valid Common Development and Distribution
    License (CDDL) block comment.

    Newly added files are checked for a copy of the CDDL header
    comment.  Modified files are only checked if they contain what
    appears to be an existing CDDL header comment.

    Files can be excluded from this check using the cddlchk.NOT file.
    See NOT Files in the extension documentation ('hg help cdm').
    '''

    filelist = buildfilelist(wslist[repo], opts.get('parent'), args)
    exclude = not_check(repo, 'cddlchk')
    lenient = True
    ret = 0

    ui.write('CDDL block check:\n')

    for f, e in filelist:
        if e and e.is_removed():
            continue
        elif (e or opts.get('honour_nots')) and exclude(f):
            ui.status('Skipping %s...\n' % f)
            continue
        elif e and e.is_added():
            lenient = False
        else:
            lenient = True

        fh = open(f, 'r')
        ret |= Cddl.cddlchk(fh, lenient=lenient, output=ui)
        fh.close()
    return ret


def cdm_manlintchk(ui, repo, *args, **opts):
    '''check for mandoc lint

    Check for man page formatting errors.

    Files can be excluded from this check using the manlint.NOT
    file.  See NOT Files in the extension documentation ('hg help
    cdm').
    '''

    filelist = buildfilelist(wslist[repo], opts.get('parent'), args)
    exclude = not_check(repo, 'manlint')
    ret = 0

    # Man pages are identified as having a suffix starting with a digit.
    ManfileRE = re.compile(r'.*\.[0-9][a-z]*$', re.IGNORECASE)

    ui.write('Man format check:\n')

    for f, e in filelist:
        if e and e.is_removed():
            continue
        elif (not ManfileRE.match(f)):
            continue
        elif (e or opts.get('honour_nots')) and exclude(f):
            ui.status('Skipping %s...\n' % f)
            continue

        fh = open(f, 'r')
        ret |= ManLint.manlint(fh, output=ui, picky=True)
        fh.close()
    return ret


def cdm_mapfilechk(ui, repo, *args, **opts):
    '''check for a valid mapfile header block in active files

    Check that all link-editor mapfiles contain the standard mapfile
    header comment directing the reader to the document containing
    Solaris object versioning rules (README.mapfile).

    Files can be excluded from this check using the mapfilechk.NOT
    file.  See NOT Files in the extension documentation ('hg help
    cdm').
    '''

    filelist = buildfilelist(wslist[repo], opts.get('parent'), args)
    exclude = not_check(repo, 'mapfilechk')
    ret = 0

    # We are interested in examining any file that has the following
    # in its final path segment:
    #    - Contains the word 'mapfile'
    #    - Begins with 'map.'
    #    - Ends with '.map'
    # We don't want to match unless these things occur in final path segment
    # because directory names with these strings don't indicate a mapfile.
    # We also ignore files with suffixes that tell us that the files
    # are not mapfiles.
    MapfileRE = re.compile(r'.*((mapfile[^/]*)|(/map\.+[^/]*)|(\.map))$',
        re.IGNORECASE)
    NotMapSuffixRE = re.compile(r'.*\.[ch]$', re.IGNORECASE)

    ui.write('Mapfile comment check:\n')

    for f, e in filelist:
        if e and e.is_removed():
            continue
        elif (not MapfileRE.match(f)) or NotMapSuffixRE.match(f):
            continue
        elif (e or opts.get('honour_nots')) and exclude(f):
            ui.status('Skipping %s...\n' % f)
            continue

        fh = open(f, 'r')
        ret |= Mapfile.mapfilechk(fh, output=ui)
        fh.close()
    return ret


def cdm_copyright(ui, repo, *args, **opts):
    '''check each active file for a current and correct copyright notice

    Check that all active files have a correctly formed copyright
    notice containing the current year.

    See the Non-Formatting Considerations section of the OpenSolaris
    Developer's Reference for more info on the correct form of
    copyright notice.
    (http://hub.opensolaris.org/bin/view/Community+Group+on/devref_7#H723NonFormattingConsiderations)

    Files can be excluded from this check using the copyright.NOT file.
    See NOT Files in the extension documentation ('hg help cdm').
    '''

    filelist = buildfilelist(wslist[repo], opts.get('parent'), args)
    exclude = not_check(repo, 'copyright')
    ret = 0

    ui.write('Copyright check:\n')

    for f, e in filelist:
        if e and e.is_removed():
            continue
        elif (e or opts.get('honour_nots')) and exclude(f):
            ui.status('Skipping %s...\n' % f)
            continue

        fh = open(f, 'r')
        ret |= Copyright.copyright(fh, output=ui)
        fh.close()
    return ret


def cdm_hdrchk(ui, repo, *args, **opts):
    '''check active C header files conform to the O/N header rules

    Check that any added or modified C header files conform to the O/N
    header rules.

    See the section 'HEADER STANDARDS' in the hdrchk(1) manual page
    for more information on the rules for O/N header file formatting.

    Files can be excluded from this check using the hdrchk.NOT file.
    See NOT Files in the extension documentation ('hg help cdm').
    '''

    filelist = buildfilelist(wslist[repo], opts.get('parent'), args)
    exclude = not_check(repo, 'hdrchk')
    ret = 0

    ui.write('Header format check:\n')

    for f, e in filelist:
        if e and e.is_removed():
            continue
        elif not f.endswith('.h'):
            continue
        elif (e or opts.get('honour_nots')) and exclude(f):
            ui.status('Skipping %s...\n' % f)
            continue

        fh = open(f, 'r')
        ret |= HdrChk.hdrchk(fh, lenient=True, output=ui)
        fh.close()
    return ret


def cdm_cstyle(ui, repo, *args, **opts):
    '''check active C source files conform to the C Style Guide

    Check that any added or modified C source file conform to the C
    Style Guide.

    See the C Style Guide for more information about correct C source
    formatting.
    (http://hub.opensolaris.org/bin/download/Community+Group+on/WebHome/cstyle.ms.pdf)

    Files can be excluded from this check using the cstyle.NOT file.
    See NOT Files in the extension documentation ('hg help cdm').
    '''

    filelist = buildfilelist(wslist[repo], opts.get('parent'), args)
    exclude = not_check(repo, 'cstyle')
    ret = 0

    ui.write('C style check:\n')

    for f, e in filelist:
        if e and e.is_removed():
            continue
        elif not (f.endswith('.c') or f.endswith('.h')):
            continue
        elif (e or opts.get('honour_nots')) and exclude(f):
            ui.status('Skipping %s...\n' % f)
            continue

        fh = open(f, 'r')
        ret |= CStyle.cstyle(fh, output=ui,
                             picky=True, check_posix_types=True,
                             check_continuation=True)
        fh.close()
    return ret


def cdm_jstyle(ui, repo, *args, **opts):
    '''check active Java source files for common stylistic errors

    Files can be excluded from this check using the jstyle.NOT file.
    See NOT Files in the extension documentation ('hg help cdm').
    '''

    filelist = buildfilelist(wslist[repo], opts.get('parent'), args)
    exclude = not_check(repo, 'jstyle')
    ret = 0

    ui.write('Java style check:\n')

    for f, e in filelist:
        if e and e.is_removed():
            continue
        elif not f.endswith('.java'):
            continue
        elif (e or opts.get('honour_nots')) and exclude(f):
            ui.status('Skipping %s...\n' % f)
            continue

        fh = open(f, 'r')
        ret |= JStyle.jstyle(fh, output=ui, picky=True)
        fh.close()
    return ret


def cdm_permchk(ui, repo, *args, **opts):
    '''check the permissions of each active file

    Check that the file permissions of each added or modified file do not
    contain the executable bit.

    Files can be excluded from this check using the permchk.NOT file.
    See NOT Files in the extension documentation ('hg help cdm').
    '''

    filelist = buildfilelist(wslist[repo], opts.get('parent'), args)
    exclude = not_check(repo, 'permchk')
    exeFiles = []

    ui.write('File permission check:\n')

    for f, e in filelist:
        if e and e.is_removed():
            continue
        elif (e or opts.get('honour_nots')) and exclude(f):
            ui.status('Skipping %s...\n' % f)
            continue

        mode = stat.S_IMODE(os.stat(f)[stat.ST_MODE])
        if mode & stat.S_IEXEC:
            exeFiles.append(f)

    if len(exeFiles) > 0:
        ui.write('Warning: the following active file(s) have executable mode '
            '(+x) permission set,\nremove unless intentional:\n')
        for fname in exeFiles:
            ui.write("  %s\n" % fname)

    return len(exeFiles) > 0


def cdm_tagchk(ui, repo, **opts):
    '''check modification of workspace tags

    Check for any modification of the repository's .hgtags file.

    With the exception of the gatekeepers, nobody should introduce or
    modify a repository's tags.
    '''

    active = wslist[repo].active(opts.get('parent'))

    ui.write('Checking for new tags:\n')

    if ".hgtags" in active:
        tfile = wslist[repo].filepath('.hgtags')
        ptip = active.parenttip.rev()

        ui.write('Warning: Workspace contains new non-local tags.\n'
                 'Only gatekeepers should add or modify such tags.\n'
                 'Use the following commands to revert these changes:\n'
                 '  hg revert -r%d %s\n'
                 '  hg commit %s\n'
                 'You should also recommit before integration\n' %
                 (ptip, tfile, tfile))

        return 1

    return 0


def cdm_branchchk(ui, repo, **opts):
    '''check for changes in number or name of branches

    Check that the workspace contains only a single head, that it is
    on the branch 'default', and that no new branches have been
    introduced.
    '''

    ui.write('Checking for multiple heads (or branches):\n')

    heads = set(repo.heads())
    parents = set([x.node() for x in wslist[repo].workingctx().parents()])

    #
    # We care if there's more than one head, and those heads aren't
    # identical to the dirstate parents (if they are identical, it's
    # an uncommitted merge which mergechk will catch, no need to
    # complain twice).
    #
    if len(heads) > 1 and heads != parents:
        ui.write('Workspace has multiple heads (or branches):\n')
        for head in [repo.changectx(head) for head in heads]:
            ui.write("  %d:%s\t%s\n" %
                (head.rev(), str(head), head.description().splitlines()[0]))
        ui.write('You must merge and recommit.\n')
        return 1

    ui.write('\nChecking for branch changes:\n')

    if repo.dirstate.branch() != 'default':
        ui.write("Warning: Workspace tip has named branch: '%s'\n"
                 "Only gatekeepers should push new branches.\n"
                 "Use the following commands to restore the branch name:\n"
                 "  hg branch [-f] default\n"
                 "  hg commit\n"
                 "You should also recommit before integration\n" %
                 (repo.dirstate.branch()))
        return 1

    branches = repo.branchtags().keys()
    if len(branches) > 1:
        ui.write('Warning: Workspace has named branches:\n')
        for t in branches:
            if t == 'default':
                continue
            ui.write("\t%s\n" % t)

        ui.write("Only gatekeepers should push new branches.\n"
                 "Use the following commands to remove extraneous branches.\n"
                 "  hg branch [-f] default\n"
                 "  hg commit"
                 "You should also recommit before integration\n")
        return 1

    return 0


def cdm_keywords(ui, repo, *args, **opts):
    '''check active files for SCCS keywords

    Check that any added or modified files do not contain SCCS keywords
    (#ident lines, etc.).

    Files can be excluded from this check using the keywords.NOT file.
    See NOT Files in the extension documentation ('hg help cdm').
    '''

    filelist = buildfilelist(wslist[repo], opts.get('parent'), args)
    exclude = not_check(repo, 'keywords')
    ret = 0

    ui.write('Keywords check:\n')

    for f, e in filelist:
        if e and e.is_removed():
            continue
        elif (e or opts.get('honour_nots')) and exclude(f):
            ui.status('Skipping %s...\n' % f)
            continue

        fh = open(f, 'r')
        ret |= Keywords.keywords(fh, output=ui)
        fh.close()
    return ret


#
# NB:
#    There's no reason to hook this up as an invokable command, since
#    we have 'hg status', but it must accept the same arguments.
#
def cdm_outchk(ui, repo, **opts):
    '''Warn the user if they have uncommitted changes'''

    ui.write('Checking for uncommitted changes:\n')

    st = wslist[repo].modified()
    if st:
        ui.write('Warning: the following files have uncommitted changes:\n')
        for elt in st:
            ui.write('   %s\n' % elt)
        return 1
    return 0


def cdm_mergechk(ui, repo, **opts):
    '''Warn the user if their workspace contains merges'''

    active = wslist[repo].active(opts.get('parent'))

    ui.write('Checking for merges:\n')

    merges = filter(lambda x: len(x.parents()) == 2 and x.parents()[1],
                   active.revs)

    if merges:
        ui.write('Workspace contains the following merges:\n')
        for rev in merges:
            desc = rev.description().splitlines()
            ui.write('  %s:%s\t%s\n' %
                     (rev.rev() or "working", str(rev),
                      desc and desc[0] or "*** uncommitted change ***"))
        return 1
    return 0


def run_checks(ws, cmds, *args, **opts):
    '''Run CMDS (with OPTS) over active files in WS'''

    ret = 0

    for cmd in cmds:
        name = cmd.func_name.split('_')[1]
        if not ws.ui.configbool('cdm', name, True):
            ws.ui.status('Skipping %s check...\n' % name)
        else:
            ws.ui.pushbuffer()
            result = cmd(ws.ui, ws.repo, honour_nots=True, *args, **opts)
            output = ws.ui.popbuffer()

            ret |= result

            if not ws.ui.quiet or result != 0:
                ws.ui.write(output, '\n')
    return ret


def cdm_nits(ui, repo, *args, **opts):
    '''check for stylistic nits in active files

    Check each active file for basic stylistic errors.

    The following checks are run over each active file (see 'hg help
    <check>' for more information about each):

      - copyright  (copyright statements)
      - cstyle     (C source style)
      - hdrchk     (C header style)
      - jstyle     (java source style)
      - manlint    (man page formatting)
      - mapfilechk (link-editor mapfiles)
      - permchk    (file permissions)
      - keywords   (SCCS keywords)

    With the global -q/--quiet option, only provide output for those
    checks which fail.
    '''

    cmds = [cdm_copyright,
        cdm_cstyle,
        cdm_hdrchk,
        cdm_jstyle,
        cmd_manlintchk,
        cdm_mapfilechk,
        cdm_permchk,
        cdm_keywords]

    return run_checks(wslist[repo], cmds, *args, **opts)


def cdm_pbchk(ui, repo, **opts):
    '''run pre-integration checks on this workspace

    Check this workspace for common errors prior to integration.

    The following checks are run over the active list (see 'hg help
    <check>' for more information about each):

      - branchchk  (addition/modification of branches)
      - comchk     (changeset descriptions)
      - copyright  (copyright statements)
      - cstyle     (C source style)
      - hdrchk     (C header style)
      - jstyle     (java source style)
      - keywords   (SCCS keywords)
      - manlint    (man page formatting)
      - mapfilechk (link-editor mapfiles)
      - permchk    (file permissions)
      - tagchk     (addition/modification of tags)

    Additionally, the workspace is checked for outgoing merges (which
    should be removed with 'hg recommit'), and uncommitted changes.

    With the global -q/--quiet option, only provide output for those
    checks which fail.
    '''

    #
    # The current ordering of these is that the commands from cdm_nits
    # run first in the same order as they would in cdm_nits, then the
    # pbchk specifics are run.
    #
    cmds = [cdm_copyright,
        cdm_cstyle,
        cdm_hdrchk,
        cdm_jstyle,
        cdm_manlintchk,
        cdm_mapfilechk,
        cdm_permchk,
        cdm_keywords,
        cdm_comchk,
        cdm_tagchk,
        cdm_branchchk,
        cdm_outchk,
        cdm_mergechk]

    return run_checks(wslist[repo], cmds, **opts)


def cdm_recommit(ui, repo, **opts):
    '''replace outgoing changesets with a single equivalent changeset

    Replace all outgoing changesets with a single changeset containing
    equivalent changes.  This removes uninteresting changesets created
    during development that would only serve as noise in the gate.

    Any changed file that is now identical in content to that in the
    parent workspace (whether identical in history or otherwise) will
    not be included in the new changeset.  Any merges information will
    also be removed.

    If no files are changed in comparison to the parent workspace, the
    outgoing changesets will be removed, but no new changeset created.

    recommit will refuse to run if the workspace contains more than
    one outgoing head, even if those heads are on the same branch.  To
    recommit with only one branch containing outgoing changesets, your
    workspace must be on that branch and at that branch head.

    recommit will prompt you to take a backup if your workspace has
    been changed since the last backup was taken.  In almost all
    cases, you should allow it to take one (the default).

    recommit cannot be run if the workspace contains any uncommitted
    changes, applied Mq patches, or has multiple outgoing heads (or
    branches).
    '''

    ws = wslist[repo]

    if not os.getcwd().startswith(repo.root):
        raise util.Abort('recommit is not safe to run with -R')

    abort_if_dirty(ws)

    wlock = repo.wlock()
    lock = repo.lock()

    try:
        parent = ws.parent(opts['parent'])
        between = repo.changelog.nodesbetween(ws.findoutgoing(parent))[2]
        heads = set(between) & set(repo.heads())

        if len(heads) > 1:
            ui.warn('Workspace has multiple outgoing heads (or branches):\n')
            for head in sorted(map(repo.changelog.rev, heads), reverse=True):
                ui.warn('\t%d\n' % head)
            raise util.Abort('you must merge before recommitting')

        #
        # We can safely use the worklist here, as we know (from the
        # abort_if_dirty() check above) that the working copy has not been
        # modified.
        #
        active = ws.active(parent)

        if filter(lambda b: len(b.parents()) > 1, active.bases()):
            raise util.Abort('Cannot recommit a merge of two non-outgoing '
                             'changesets')

        if len(active.revs) <= 0:
            raise util.Abort("no changes to recommit")

        if len(active.files()) <= 0:
            ui.warn("Recommitting %d active changesets, but no active files\n" %
                    len(active.revs))

        #
        # During the course of a recommit, any file bearing a name
        # matching the source name of any renamed file will be
        # clobbered by the operation.
        #
        # As such, we ask the user before proceeding.
        #
        bogosity = [f.parentname for f in active if f.is_renamed() and
                    os.path.exists(repo.wjoin(f.parentname))]
        if bogosity:
            ui.warn("The following file names are the original name of a "
                    "rename and also present\n"
                    "in the working directory:\n")

            for fname in bogosity:
                ui.warn("  %s\n" % fname)

            if not yes_no(ui, "These files will be removed by recommit."
                          "  Continue?",
                          False):
                raise util.Abort("recommit would clobber files")

        user = opts['user'] or ui.username()
        comments = '\n'.join(active.comments())

        message = cmdutil.logmessage(opts) or ui.edit(comments, user)
        if not message:
            raise util.Abort('empty commit message')

        bk = CdmBackup(ui, ws, backup_name(repo.root))
        if bk.need_backup():
            if yes_no(ui, 'Do you want to backup files first?', True):
                bk.backup()

        oldtags = repo.tags()
        clearedtags = [(name, nd, repo.changelog.rev(nd), local)
                for name, nd, local in active.tags()]

        ws.squishdeltas(active, message, user=user)
    finally:
        lock.release()
        wlock.release()

    if clearedtags:
        ui.write("Removed tags:\n")
        for name, nd, rev, local in sorted(clearedtags,
                                           key=lambda x: x[0].lower()):
            ui.write("  %5s:%s:\t%s%s\n" % (rev, node.short(nd),
                                            name, (local and ' (local)' or '')))

        for ntag, nnode in sorted(repo.tags().items(),
                                  key=lambda x: x[0].lower()):
            if ntag in oldtags and ntag != "tip":
                if oldtags[ntag] != nnode:
                    ui.write("tag '%s' now refers to revision %d:%s\n" %
                             (ntag, repo.changelog.rev(nnode),
                              node.short(nnode)))


def do_eval(cmd, files, root, changedir=True):
    if not changedir:
        os.chdir(root)

    for path in sorted(files):
        dirn, base = os.path.split(path)

        if changedir:
            os.chdir(os.path.join(root, dirn))

        os.putenv('workspace', root)
        os.putenv('filepath', path)
        os.putenv('dir', dirn)
        os.putenv('file', base)
        os.system(cmd)


def cdm_eval(ui, repo, *command, **opts):
    '''run specified command for each active file

    Run the command specified on the command line for each active
    file, with the following variables present in the environment:

      :$file:      -  active file basename.
      :$dir:       -  active file dirname.
      :$filepath:  -  path from workspace root to active file.
      :$workspace: -  full path to workspace root.

    For example:

      hg eval 'echo $dir; hg log -l3 $file'

    will show the last the 3 log entries for each active file,
    preceded by its directory.
    '''

    act = wslist[repo].active(opts['parent'])
    cmd = ' '.join(command)
    files = [x.name for x in act if not x.is_removed()]

    do_eval(cmd, files, repo.root, not opts['remain'])


def cdm_apply(ui, repo, *command, **opts):
    '''apply specified command to all active files

    Run the command specified on the command line over each active
    file.

    For example 'hg apply "wc -l"' will output a count of the lines in
    each active file.
    '''

    act = wslist[repo].active(opts['parent'])

    if opts['remain']:
        appnd = ' $filepath'
    else:
        appnd = ' $file'

    cmd = ' '.join(command) + appnd
    files = [x.name for x in act if not x.is_removed()]

    do_eval(cmd, files, repo.root, not opts['remain'])


def cdm_reparent(ui, repo, parent):
    '''reparent your workspace

    Update the 'default' path alias that is used as the default source
    for 'hg pull' and the default destination for 'hg push' (unless
    there is a 'default-push' alias).  This is also the path all
    Cadmium commands treat as your parent workspace.
    '''

    def append_new_parent(parent):
        fp = None
        try:
            fp = repo.opener('hgrc', 'a', atomictemp=True)
            if fp.tell() != 0:
                fp.write('\n')
            fp.write('[paths]\n'
                     'default = %s\n\n' % parent)
            fp.rename()
        finally:
            if fp and not fp.closed:
                fp.close()

    def update_parent(path, line, parent):
        line = line - 1 # The line number we're passed will be 1-based
        fp = None

        try:
            fp = open(path)
            data = fp.readlines()
        finally:
            if fp and not fp.closed:
                fp.close()

        #
        # line will be the last line of any continued block, go back
        # to the first removing the continuation as we go.
        #
        while data[line][0].isspace():
            data.pop(line)
            line -= 1

        assert data[line].startswith('default')

        data[line] = "default = %s\n" % parent
        if data[-1] != '\n':
            data.append('\n')

        try:
            fp = util.atomictempfile(path, 'w', 0644)
            fp.writelines(data)
            fp.rename()
        finally:
            if fp and not fp.closed:
                fp.close()

    from mercurial import config
    parent = ui.expandpath(parent)

    if not os.path.exists(repo.join('hgrc')):
        append_new_parent(parent)
        return

    cfg = config.config()
    cfg.read(repo.join('hgrc'))
    source = cfg.source('paths', 'default')

    if not source:
        append_new_parent(parent)
        return
    else:
        path, target = source.rsplit(':', 1)

        if path != repo.join('hgrc'):
            raise util.Abort("Cannot edit path specification not in repo hgrc\n"
                             "default path is from: %s" % source)

        update_parent(path, int(target), parent)


def backup_name(fullpath):
    '''Create a backup directory name based on the specified path.

    In most cases this is the basename of the path specified, but
    certain cases are handled specially to create meaningful names'''

    special = ['usr/closed']

    fullpath = fullpath.rstrip(os.path.sep).split(os.path.sep)

    #
    # If a path is 'special', we append the basename of the path to
    # the path element preceding the constant, special, part.
    #
    # Such that for instance:
    #     /foo/bar/onnv-fixes/usr/closed
    #  has a backup name of:
    #     onnv-fixes-closed
    #
    for elt in special:
        elt = elt.split(os.path.sep)
        pathpos = len(elt)

        if fullpath[-pathpos:] == elt:
            return "%s-%s" % (fullpath[-pathpos - 1], elt[-1])
    else:
        return fullpath[-1]


def cdm_backup(ui, repo, if_newer=False):
    '''backup workspace changes and metadata

    Create a backup copy of changes made in this workspace as compared
    to its parent workspace, as well as important metadata of this
    workspace.

    NOTE: Only changes as compared to the parent workspace are backed
    up.  If you lose this workspace and its parent, you will not be
    able to restore a backup into a clone of the grandparent
    workspace.

    By default, backups are stored in the cdm.backup/ directory in
    your home directory.  This is configurable using the cdm.backupdir
    configuration variable, for example:

      hg backup --config cdm.backupdir=/net/foo/backups

    or place the following in an appropriate hgrc file::

      [cdm]
      backupdir = /net/foo/backups

    Backups have the same name as the workspace in which they were
    taken, with '-closed' appended in the case of O/N's usr/closed.
    '''

    name = backup_name(repo.root)
    bk = CdmBackup(ui, wslist[repo], name)

    wlock = repo.wlock()
    lock = repo.lock()

    try:
        if if_newer and not bk.need_backup():
            ui.status('backup is up-to-date\n')
        else:
            bk.backup()
    finally:
        lock.release()
        wlock.release()


def cdm_restore(ui, repo, backup, **opts):
    '''restore workspace from backup

    Restore this workspace from a backup (taken by 'hg backup').

    If the specified backup directory does not exist, it is assumed to
    be relative to the cadmium backup directory (~/cdm.backup/ by
    default).

    For example::

      % hg restore on-rfe - Restore the latest backup of ~/cdm.backup/on-rfe
      % hg restore -g3 on-rfe - Restore the 3rd backup of ~/cdm.backup/on-rfe
      % hg restore /net/foo/backup/on-rfe - Restore from an explicit path
    '''

    if not os.getcwd().startswith(repo.root):
        raise util.Abort('restore is not safe to run with -R')

    abort_if_dirty(wslist[repo])

    if opts['generation']:
        gen = int(opts['generation'])
    else:
        gen = None

    if os.path.exists(backup):
        backup = os.path.abspath(backup)

    wlock = repo.wlock()
    lock = repo.lock()

    try:
        bk = CdmBackup(ui, wslist[repo], backup)
        bk.restore(gen)
    finally:
        lock.release()
        wlock.release()


def cdm_webrev(ui, repo, **opts):
    '''generate web-based code review and optionally upload it

    Generate a web-based code review using webrev(1) and optionally
    upload it.  All known arguments are passed through to webrev(1).
    '''

    webrev_args = ""
    for key in opts.keys():
        if opts[key]:
            if type(opts[key]) == type(True):
                webrev_args += '-' + key + ' '
            else:
                webrev_args += '-' + key + ' ' + opts[key] + ' '

    retval = os.system('webrev ' + webrev_args)
    if retval != 0:
        return retval - 255

    return 0


def cdm_debugcdmal(ui, repo, *pats, **opts):
    '''dump the active list for the sake of debugging/testing'''

    ui.write(wslist[repo].active(opts['parent']).as_text(pats))


def cdm_changed(ui, repo, *pats, **opts):
    '''mark a file as changed in the working copy

    Maintain a list of files checked for modification in the working
    copy.  If the list exists, most cadmium commands will only check
    the working copy for changes to those files, rather than checking
    the whole workspace (this does not apply to committed changes,
    which are always seen).

    Since this list functions only as a hint as to where in the
    working copy to look for changes, entries that have not actually
    been modified (in the working copy, or in general) are not
    problematic.


    Note: If such a list exists, it must be kept up-to-date.


    Renamed files can be added with reference only to their new name:
      $ hg mv foo bar
      $ hg changed bar

    Without arguments, 'hg changed' will list all files recorded as
    altered, such that, for instance:
      $ hg status $(hg changed)
      $ hg diff $(hg changed)
    Become useful (generally faster than their unadorned counterparts)

    To create an initially empty list:
      $ hg changed -i
    Until files are added to the list it is equivalent to saying
    "Nothing has been changed"

    Update the list based on the current active list:
      $ hg changed -u
    The old list is emptied, and replaced with paths from the
    current active list.

    Remove the list entirely:
      $ hg changed -d
    '''

    def modded_files(repo, parent):
        out = wslist[repo].findoutgoing(wslist[repo].parent(parent))
        outnodes = repo.changelog.nodesbetween(out)[0]

        files = set()
        for n in outnodes:
            files.update(repo.changectx(n).files())

        files.update(wslist[repo].status().keys())
        return files

    #
    # specced_pats is convenient to treat as a boolean indicating
    # whether any file patterns or paths were specified.
    #
    specced_pats = pats or opts['include'] or opts['exclude']
    if len(filter(None, [opts['delete'], opts['update'], opts['init'],
                         specced_pats])) > 1:
        raise util.Abort("-d, -u, -i and patterns are mutually exclusive")

    wl = WorkList(wslist[repo])

    if (not wl and specced_pats) or opts['init']:
        wl.delete()
        if yes_no(ui, "Create a list based on your changes thus far?", True):
            map(wl.add, modded_files(repo, opts.get('parent')))

    if opts['delete']:
        wl.delete()
    elif opts['update']:
        wl.delete()
        map(wl.add, modded_files(repo, opts.get('parent')))
        wl.write()
    elif opts['init']:       # Any possible old list was deleted above
        wl.write()
    elif specced_pats:
        sources = []

        match = wslist[repo].matcher(pats=pats, opts=opts)
        for abso in repo.walk(match):
            if abso in repo.dirstate:
                wl.add(abso)
                #
                # Store the source name of any copy.  We use this so
                # both the add and delete of a rename can be entered
                # into the WorkList with only the destination name
                # explicitly being mentioned.
                #
                fctx = wslist[repo].workingctx().filectx(abso)
                rn = fctx.renamed()
                if rn:
                    sources.append(rn[0])
            else:
                ui.warn("%s is not version controlled -- skipping\n" %
                        match.rel(abso))

        if sources:
            for fname, chng in wslist[repo].status(files=sources).iteritems():
                if chng == 'removed':
                    wl.add(fname)
        wl.write()
    else:
        for elt in sorted(wl.list()):
            ui.write("%s\n" % wslist[repo].filepath(elt))


cmdtable = {
    'apply': (cdm_apply, [('p', 'parent', '', 'parent workspace'),
                          ('r', 'remain', None, 'do not change directory')],
              'hg apply [-p PARENT] [-r] command...'),
    '^backup|bu': (cdm_backup, [('t', 'if-newer', None,
                             'only backup if workspace files are newer')],
               'hg backup [-t]'),
    'branchchk': (cdm_branchchk, [('p', 'parent', '', 'parent workspace')],
                  'hg branchchk [-p PARENT]'),
    'bugs': (cdm_bugs, [('p', 'parent', '', 'parent workspace')],
             'hg bugs [-p PARENT]'),
    'cddlchk': (cdm_cddlchk, [('p', 'parent', '', 'parent workspace')],
                'hg cddlchk [-p PARENT]'),
    'changed': (cdm_changed, [('d', 'delete', None, 'delete the file list'),
                              ('u', 'update', None, 'mark all changed files'),
                              ('i', 'init', None, 'create an empty file list'),
                              ('p', 'parent', '', 'parent workspace'),
                              ('I', 'include', [],
                               'include names matching the given patterns'),
                              ('X', 'exclude', [],
                               'exclude names matching the given patterns')],
                'hg changed -d\n'
                'hg changed -u\n'
                'hg changed -i\n'
                'hg changed [-I PATTERN...] [-X PATTERN...] [FILE...]'),
    'comchk': (cdm_comchk, [('p', 'parent', '', 'parent workspace'),
                            ('N', 'nocheck', None,
                             'do not compare comments with databases')],
               'hg comchk [-p PARENT]'),
    'comments': (cdm_comments, [('p', 'parent', '', 'parent workspace')],
                 'hg comments [-p PARENT]'),
    'copyright': (cdm_copyright, [('p', 'parent', '', 'parent workspace')],
                  'hg copyright [-p PARENT]'),
    'cstyle': (cdm_cstyle, [('p', 'parent', '', 'parent workspace')],
               'hg cstyle [-p PARENT]'),
    'debugcdmal': (cdm_debugcdmal, [('p', 'parent', '', 'parent workspace')],
                   'hg debugcdmal [-p PARENT] [FILE...]'),
    'eval': (cdm_eval, [('p', 'parent', '', 'parent workspace'),
                        ('r', 'remain', None, 'do not change directory')],
             'hg eval [-p PARENT] [-r] command...'),
    'hdrchk': (cdm_hdrchk, [('p', 'parent', '', 'parent workspace')],
               'hg hdrchk [-p PARENT]'),
    'jstyle': (cdm_jstyle, [('p', 'parent', '', 'parent workspace')],
               'hg jstyle [-p PARENT]'),
    'keywords': (cdm_keywords, [('p', 'parent', '', 'parent workspace')],
                 'hg keywords [-p PARENT]'),
    '^list|active': (cdm_list, [('p', 'parent', '', 'parent workspace'),
                                ('a', 'added', None, 'show added files'),
                                ('m', 'modified', None, 'show modified files'),
                                ('r', 'removed', None, 'show removed files')],
                    'hg list [-amrRu] [-p PARENT]'),
    'manlint': (cdm_manlintchk, [('p', 'parent', '', 'parent workspace')],
                'hg manlint [-p PARENT]'),
    'mapfilechk': (cdm_mapfilechk, [('p', 'parent', '', 'parent workspace')],
                'hg mapfilechk [-p PARENT]'),
    '^nits': (cdm_nits, [('p', 'parent', '', 'parent workspace')],
             'hg nits [-p PARENT]'),
    '^pbchk': (cdm_pbchk, [('p', 'parent', '', 'parent workspace'),
                           ('N', 'nocheck', None, 'skip database checks')],
              'hg pbchk [-N] [-p PARENT]'),
    'permchk': (cdm_permchk, [('p', 'parent', '', 'parent workspace')],
                'hg permchk [-p PARENT]'),
    '^pdiffs': (cdm_pdiffs, [('p', 'parent', '', 'parent workspace'),
                             ('a', 'text', None, 'treat all files as text'),
                             ('g', 'git', None, 'use extended git diff format'),
                             ('w', 'ignore-all-space', None,
                              'ignore white space when comparing lines'),
                             ('b', 'ignore-space-change', None,
                              'ignore changes in the amount of white space'),
                             ('B', 'ignore-blank-lines', None,
                              'ignore changes whose lines are all blank'),
                             ('U', 'unified', 3,
                              'number of lines of context to show'),
                             ('I', 'include', [],
                              'include names matching the given patterns'),
                             ('X', 'exclude', [],
                              'exclude names matching the given patterns')],
               'hg pdiffs [OPTION...] [-p PARENT] [FILE...]'),
    '^recommit|reci': (cdm_recommit, [('p', 'parent', '', 'parent workspace'),
                                      ('m', 'message', '',
                                       'use <text> as commit message'),
                                      ('l', 'logfile', '',
                                       'read commit message from file'),
                                      ('u', 'user', '',
                                       'record user as committer')],
                       'hg recommit [-m TEXT] [-l FILE] [-u USER] [-p PARENT]'),
    'renamed': (cdm_renamed, [('p', 'parent', '', 'parent workspace')],
                'hg renamed [-p PARENT]'),
    'reparent': (cdm_reparent, [], 'hg reparent PARENT'),
    '^restore': (cdm_restore, [('g', 'generation', '', 'generation number')],
                 'hg restore [-g GENERATION] BACKUP'),
    'tagchk': (cdm_tagchk, [('p', 'parent', '', 'parent workspace')],
               'hg tagchk [-p PARENT]'),
    'webrev': (cdm_webrev, [('C', 'C', '', 'ITS priority file'),
                            ('D', 'D', '', 'delete remote webrev'),
                            ('I', 'I', '', 'ITS configuration file'),
                            ('i', 'i', '', 'include file'),
                            ('N', 'N', None, 'suppress comments'),
                            ('n', 'n', None, 'do not generate webrev'),
                            ('O', 'O', None, 'OpenSolaris mode'),
                            ('o', 'o', '', 'output directory'),
                            ('p', 'p', '', 'use specified parent'),
                            ('t', 't', '', 'upload target'),
                            ('U', 'U', None, 'upload the webrev'),
                            ('w', 'w', '', 'use wx active file')],
               'hg webrev [WEBREV_OPTIONS]'),
}
