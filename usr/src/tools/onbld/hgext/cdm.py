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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

'''workspace extensions for mercurial

This extension contains a number of commands to help you work within
the OpenSolaris consolidations.

Common uses:

Show diffs relative to parent workspace			- pdiffs
Check source style rules				- nits
Run pre-putback checks					- pbchk
Collapse all your changes into a single changeset	- recommit'''


#
# NB: This assumes the normal directory structure, with this
#     extension 2 levels below .../lib/python.
#
#     If you change that, change this
#
import sys, os
sys.path.insert(1, "%s/../../" % os.path.dirname(__file__))

from onbld.Scm import Version
from mercurial import util

try:
    Version.check_version()
except Version.VersionMismatch, badversion:
    raise util.Abort("Version Mismatch:\n %s\n" % badversion)

import ConfigParser
from mercurial import cmdutil, node

from onbld.Scm.WorkSpace import WorkSpace, ActiveEntry
from onbld.Scm.Backup import CdmBackup
from onbld.Checks import Cddl, Comments, Copyright, CStyle, HdrChk
from onbld.Checks import JStyle, Keywords, Rti, onSWAN


def yes_no(ui, msg, default):
    if default:
        prompt = ' [Y/n]:'
        defanswer = 'y'
    else:
        prompt = ' [y/N]:'
        defanswer = 'n'

    if ui.interactive and sys.stdin.isatty():
        resp = ui.prompt(msg + prompt, r'([Yy(es)?|[Nn]o?)?',
                         default=defanswer)
        if not resp:
            return default
        elif resp[0] in ['Y', 'y']:
            return True
        else:
            return False
    else:
        return default

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


def cdm_pdiffs(ui, repo, parent=None):
    '''list workspace diffs relative to parent workspace

    The parent tip is taken to be the latest revision shared between
    us and the parent workspace.'''
    diffs = wslist[repo].pdiff(parent)
    if diffs:
        ui.write(diffs)


def cdm_list(ui, repo, **opts):
    '''list files changed relative to parent workspace

    The parent tip is taken to be the latest revision shared between
    us and the parent workspace.'''

    wanted = []

    if opts['added']:
        wanted.append(ActiveEntry.ADDED)
    if opts['modified']:
        wanted.append(ActiveEntry.MODIFIED)
    if opts['removed']:
        wanted.append(ActiveEntry.REMOVED)

    act = wslist[repo].active(opts['parent'])
    chngmap = {ActiveEntry.MODIFIED: 'modified',
               ActiveEntry.ADDED: 'added',
               ActiveEntry.REMOVED: 'removed'}

    lst = {}
    for entry in act:
        if wanted and (entry.change not in wanted):
            continue

        chngstr = chngmap[entry.change]
        if chngstr not in lst:
            lst[chngstr] = []
        lst[chngstr].append(entry)

    for chng in sorted(lst.keys()):
        ui.write(chng + ':\n')
        for elt in sorted(lst[chng]):
            if elt.is_renamed():
                ui.write('\t%s (renamed from %s)\n' % (elt.name,
                                                      elt.parentname))
            elif elt.is_copied():
                ui.write('\t%s (copied from %s)\n' % (elt.name,
                                                      elt.parentname))
            else:
                ui.write('\t%s\n' % elt.name)


def cdm_arcs(ui, repo, parent=None):
    'show all ARC cases in checkin comments'
    act = wslist[repo].active(parent)

    # We take a set of the appropriate comments to eliminate duplicates.
    for elt in set(filter(Comments.isARC, act.comments())):
        ui.write(elt + '\n')


def cdm_bugs(ui, repo, parent=None):
    'show all bug IDs in checkin comments'
    act = wslist[repo].active(parent)

    for elt in set(filter(Comments.isBug, act.comments())):
        ui.write(elt + '\n')


def cdm_comments(ui, repo, parent=None):
    'show checkin comments for active files'
    act = wslist[repo].active(parent)

    for elt in act.comments():
        ui.write(elt + '\n')


def cdm_renamed(ui, repo, parent=None):
    '''show renamed active files

    Renamed files are shown in the format

       newname oldname

    One pair per-line.'''

    act = wslist[repo].active(parent)

    for entry in sorted(filter(lambda x: x.is_renamed(), act)):
        ui.write('%s %s\n' % (entry.name, entry.parentname))


def cdm_comchk(ui, repo, **opts):
    '''check checkin comments for active files

    Check that checkin comments conform to O/N rules.'''

    active = opts.get('active') or wslist[repo].active(opts['parent'])

    ui.write('Comments check:\n')

    check_db = not opts['nocheck']
    return Comments.comchk(active.comments(), check_db=check_db, output=ui)


def cdm_cddlchk(ui, repo, **opts):
    '''check for a valid CDDL block in active files

    See http://www.opensolaris.org/os/community/on/devref_toc/devref_7/#7_2_3_nonformatting_considerations
    for more info.'''

    active = opts.get('active') or wslist[repo].active(opts['parent'])

    ui.write('CDDL block check:\n')

    lenient = True
    ret = 0

    for entry in sorted(active):
        if entry.is_removed():
            continue
        elif entry.is_added():
            lenient = False
        else:
            lenient = True

        path = wslist[repo].filepath(entry.name)
        fh = open(path, 'r')
        ret |= Cddl.cddlchk(fh, lenient=lenient, output=ui)
        fh.close()
    return ret


def cdm_copyright(ui, repo, **opts):
    '''check active files for valid copyrights

    Check that all active files have a valid copyright containing the
    current year (and *only* the current year).
    See http://www.opensolaris.org/os/project/muskoka/on_dev/golden_rules.txt
    for more info.'''

    active = opts.get('active') or wslist[repo].active(opts['parent'])

    ui.write('Copyright check:\n')

    ret = 0

    for entry in sorted(active):
        if entry.is_removed():
            continue

        path = wslist[repo].filepath(entry.name)

        fh = open(path, 'r')
        ret |= Copyright.copyright(fh, output=ui)
        fh.close()
    return ret


def cdm_hdrchk(ui, repo, **opts):
    '''check active header files conform to O/N rules'''

    active = opts.get('active') or wslist[repo].active(opts['parent'])

    ui.write('Header format check:\n')

    ret = 0

    for entry in sorted(active):
        if entry.is_removed():
            continue

        path = wslist[repo].filepath(entry.name)

        if entry.name.endswith('.h'):
            fh = open(path, 'r')
            ret |= HdrChk.hdrchk(fh, lenient=True, output=ui)
            fh.close()
    return ret


def cdm_cstyle(ui, repo, **opts):
    '''check active C source files conform to the C Style Guide

    See http://opensolaris.org/os/community/documentation/getting_started_docs/cstyle.ms.pdf'''

    active = opts.get('active') or wslist[repo].active(opts['parent'])

    ui.write('C style check:\n')

    ret = 0

    for entry in sorted(active):
        if entry.is_removed():
            continue

        path = wslist[repo].filepath(entry.name)

        if entry.name.endswith('.c') or entry.name.endswith('.h'):
            fh = open(path, 'r')
            ret |= CStyle.cstyle(fh, output=ui,
                                 picky=True, check_posix_types=True,
                                 check_continuation=True)
            fh.close()
    return ret


def cdm_jstyle(ui, repo, **opts):
    'check active Java source files for common stylistic errors'

    active = opts.get('active') or wslist[repo].active(opts['parent'])

    ui.write('Java style check:\n')

    ret = 0

    for entry in sorted(active):
        if entry.is_removed():
            continue

        path = wslist[repo].filepath(entry.name)

        if entry.name.endswith('.java'):
            fh = open(path, 'r')
            ret |= JStyle.jstyle(fh, output=ui, picky=True)
            fh.close()
    return ret


def cdm_permchk(ui, repo, **opts):
    '''check active files permission - warn +x (execute) mode'''

    active = opts.get('active') or wslist[repo].active(opts['parent'])

    ui.write('File permission check:\n')

    exeFiles = []
    for entry in sorted(active):
        if entry.is_removed():
            continue

        path = wslist[repo].filepath(entry.name)

        if active.localtip.manifest().execf(path):
            exeFiles.append(path)

    if len(exeFiles) > 0:
        ui.write('Warning: the following active file(s) have executable mode '
            '(+x) permission set,\nremove unless intentional:\n')
        for fname in exeFiles:
            ui.write("  %s\n" % fname)

    return len(exeFiles) > 0


def cdm_tagchk(ui, repo, **opts):
    '''check if .hgtags is active and issue warning

    Tag sharing among repositories is restricted to gatekeepers'''

    active = opts.get('active') or wslist[repo].active(opts['parent'])

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
    '''check if multiple heads (or branches) are present, or if
    branch changes are made'''

    active = opts.get('active') or wslist[repo].active(opts['parent'])

    ui.write('Checking for multiple heads (or branches):\n')

    heads = set(repo.heads())
    parents = set([x.node() for x in repo.workingctx().parents()])

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

    if active.localtip.branch() != 'default':
        ui.write("Warning: Workspace tip has named branch: '%s'\n"
                 "Only gatekeepers should push new branches.\n"
                 "Use the following commands to restore the branch name:\n"
                 "  hg branch [-f] default\n"
                 "  hg commit\n"
                 "You should also recommit before integration\n" %
                 (active.localtip.branch()))
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


def cdm_rtichk(ui, repo, **opts):
    '''check active bug/RFEs for approved RTIs

    Only works on SWAN.'''

    if opts['nocheck']:
        ui.status('Skipping RTI checks...\n')
        return 0

    if not onSWAN():
        ui.write('RTI checks only work on SWAN, skipping...\n')
        return 0

    active = opts.get('active') or wslist[repo].active(opts['parent'])

    ui.write('RTI check:\n')

    bugs = []

    for com in active.comments():
        match = Comments.isBug(com)
        if match and match.group(1) not in bugs:
            bugs.append(match.group(1))

    # RTI normalizes the gate path for us
    return int(not Rti.rti(bugs, gatePath=opts['parent'], output=ui))


def cdm_keywords(ui, repo, **opts):
    '''check source files do not contain SCCS keywords'''

    active = opts.get('active') or wslist[repo].active(opts['parent'])

    ui.write('Keywords check:\n')

    ret = 0
    for entry in sorted(active):
        if entry.is_removed():
            continue

        path = wslist[repo].filepath(entry.name)
        fh = open(path, 'r')
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

    active = opts.get('active') or wslist[repo].active(opts['parent'])

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


def run_checks(ws, cmds, **opts):
    '''Run CMDS (with OPTS) over active files in WS'''
    active = ws.active(opts['parent'])

    ret = 0

    for cmd in cmds:
        name = cmd.func_name.split('_')[1]
        if not ws.ui.configbool('cdm', name, True):
            ws.ui.status('Skipping %s check...\n' % name)
        else:
            ws.ui.pushbuffer()

            result = cmd(ws.ui, ws.repo, active=active, **opts)
            ret |= result

            output = ws.ui.popbuffer()
            if not ws.ui.quiet or result != 0:
                ws.ui.write(output, '\n')
    return ret


def cdm_nits(ui, repo, **opts):
    '''check for stylistic nits in active files

    Run cddlchk, copyright, cstyle, hdrchk, jstyle, permchk, and
    keywords checks.'''

    cmds = [cdm_cddlchk,
        cdm_copyright,
        cdm_cstyle,
        cdm_hdrchk,
        cdm_jstyle,
        cdm_permchk,
        cdm_keywords]

    return run_checks(wslist[repo], cmds, **opts)


def cdm_pbchk(ui, repo, **opts):
    '''pre-putback check all active files

    Run cddlchk, comchk, copyright, cstyle, hdrchk, jstyle, permchk, tagchk,
    branchchk, keywords and rtichk checks.  Additionally, warn about
    uncommitted changes.'''

    #
    # The current ordering of these is that the commands from cdm_nits
    # run first in the same order as they would in cdm_nits.  Then the
    # pbchk specifics run
    #
    cmds = [cdm_cddlchk,
        cdm_copyright,
        cdm_cstyle,
        cdm_hdrchk,
        cdm_jstyle,
        cdm_permchk,
        cdm_keywords,
        cdm_comchk,
        cdm_tagchk,
        cdm_branchchk,
        cdm_rtichk,
        cdm_outchk,
        cdm_mergechk]

    return run_checks(wslist[repo], cmds, **opts)


def cdm_recommit(ui, repo, **opts):
    '''compact outgoing deltas into a single, conglomerate delta'''

    if not os.getcwd().startswith(repo.root):
        raise util.Abort('recommit is not safe to run with -R')

    if wslist[repo].modified():
        raise util.Abort('workspace has uncommitted changes')

    if wslist[repo].merged():
        raise util.Abort('workspace contains uncommitted merge')

    if wslist[repo].branched():
        raise util.Abort('workspace contains uncommitted branch')

    if wslist[repo].mq_applied():
        raise util.Abort("workspace has Mq patches applied")

    wlock = repo.wlock()
    lock = repo.lock()

    heads = repo.heads()
    if len(heads) > 1:
        ui.warn('Workspace has multiple heads (or branches):\n')
        for head in heads:
            ui.warn('\t%d\n' % repo.changelog.rev(head))
        raise util.Abort('you must merge before recommitting')

    active = wslist[repo].active(opts['parent'])

    if len(active.revs) <= 0:
        raise util.Abort("no changes to recommit")

    if len(active.files()) <= 0:
        ui.warn("Recommitting %d active changesets, but no active files\n" %
                len(active.revs))

    #
    # During the course of a recommit, any file bearing a name matching the
    # source name of any renamed file will be clobbered by the operation.
    #
    # As such, we ask the user before proceeding.
    #
    bogosity = [f.parentname for f in active if f.is_renamed() and
                os.path.exists(repo.wjoin(f.parentname))]

    if bogosity:
        ui.warn("The following file names are the original name of a rename "
                "and also present\n"
                "in the working directory:\n")
        for fname in bogosity:
            ui.warn("  %s\n" % fname)
        if not yes_no(ui, "These files will be removed by recommit.  Continue?",
                      False):
            raise util.Abort("recommit would clobber files")

    user = opts['user'] or ui.username()

    message = cmdutil.logmessage(opts) or ui.edit('\n'.join(active.comments()),
                                                  user)
    if not message:
        raise util.Abort('empty commit message')

    name = backup_name(repo.root)
    bk = CdmBackup(ui, wslist[repo], name)
    if bk.need_backup():
        if yes_no(ui, 'Do you want to backup files first?', True):
            bk.backup()

    oldtags = repo.tags()
    clearedtags = [(name, nd, repo.changelog.rev(nd), local)
            for name, nd, local in active.tags()]

    wslist[repo].squishdeltas(active, message, user=user)

    if clearedtags:
        ui.write("Removed tags:\n")
        for name, nd, rev, local in clearedtags:
            ui.write("  %s %s:%s%s\n" % (name, rev, node.short(nd),
                                         (local and ' (local)') or ''))

    for ntag, nnode in repo.tags().items():
        if ntag in oldtags and ntag != "tip":
            if oldtags[ntag] != nnode:
                ui.write("tag %s now refers to revision %d:%s\n" %
                         (ntag, repo.changelog.rev(nnode), node.short(nnode)))


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
    '''run cmd for each active file

    cmd can refer to:
      $file      -	active file basename.
      $dir       -	active file dirname.
      $filepath  -	path from workspace root to active file.
      $workspace -	full path to workspace root.

    For example "hg eval 'echo $dir; hg log -l3 $file'" will show the last
    the 3 log entries for each active file, preceded by its directory.'''

    act = wslist[repo].active(opts['parent'])
    cmd = ' '.join(command)
    files = [x.name for x in act if not x.is_removed()]

    do_eval(cmd, files, repo.root, not opts['remain'])


def cdm_apply(ui, repo, *command, **opts):
    '''apply cmd to all active files

    For example 'hg apply wc -l' outputs a line count of active files.'''

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

    Updates the 'default' path.'''

    filename = repo.join('hgrc')

    cp = util.configparser()
    try:
        cp.read(filename)
    except ConfigParser.ParsingError, inst:
        raise util.Abort('failed to parse %s\n%s' % (filename, inst))

    try:
        fh = open(filename, 'w')
    except IOError, e:
        raise util.Abort('Failed to open workspace configuration: %s' % e)

    if not cp.has_section('paths'):
        cp.add_section('paths')
    cp.set('paths', 'default', parent)
    cp.write(fh)
    fh.close()


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
    '''make backup copies of all workspace changes

    Backups will be stored in ~/cdm.backup/<basename of workspace>.'''

    name = backup_name(repo.root)
    bk = CdmBackup(ui, wslist[repo], name)

    if if_newer and not bk.need_backup():
        ui.status('backup is up-to-date\n')
    else:
        bk.backup()


def cdm_restore(ui, repo, backup, **opts):
    '''restore workspace from backup

    Restores a workspace from the specified backup directory and generation
    (which defaults to the latest).'''

    if not os.getcwd().startswith(repo.root):
        raise util.Abort('restore is not safe to run with -R')
    if wslist[repo].modified():
        raise util.Abort('Workspace has uncommitted changes')
    if wslist[repo].merged():
        raise util.Abort('Workspace has an uncommitted merge')
    if wslist[repo].branched():
        raise util.Abort('Workspace has an uncommitted branch')

    if opts['generation']:
        gen = int(opts['generation'])
    else:
        gen = None

    if os.path.exists(backup):
        backup = os.path.abspath(backup)

    bk = CdmBackup(ui, wslist[repo], backup)
    bk.restore(gen)

cmdtable = {
    'apply': (cdm_apply, [('p', 'parent', '', 'parent workspace'),
                          ('r', 'remain', None, 'do not change directories')],
              'hg apply [-p PARENT] [-r] command...'),
    'arcs': (cdm_arcs, [('p', 'parent', '', 'parent workspace')],
             'hg arcs [-p PARENT]'),
    '^backup|bu': (cdm_backup, [('t', 'if-newer', None,
                             'only backup if workspace files are newer')],
               'hg backup [-t]'),
    'branchchk': (cdm_branchchk, [('p', 'parent', '', 'parent workspace')],
                  'hg branchchk [-p PARENT]'),
    'bugs': (cdm_bugs, [('p', 'parent', '', 'parent workspace')],
             'hg bugs [-p PARENT]'),
    'cddlchk': (cdm_cddlchk, [('p', 'parent', '', 'parent workspace')],
                'hg cddlchk [-p PARENT]'),
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
    'eval': (cdm_eval, [('p', 'parent', '', 'parent workspace'),
                        ('r', 'remain', None, 'do not change directories')],
             'hg eval [-p PARENT] [-r] command...'),
    'hdrchk': (cdm_hdrchk, [('p', 'parent', '', 'parent workspace')],
               'hg hdrchk [-p PARENT]'),
    'jstyle': (cdm_jstyle, [('p', 'parent', '', 'parent workspace')],
               'hg jstyle [-p PARENT]'),
    'keywords': (cdm_keywords, [('p', 'parent', '', 'parent workspace')],
                 'hg keywords [-p PARENT]'),
    '^list|active': (cdm_list, [('p', 'parent', '', 'parent workspace'),
                                ('r', 'removed', None, 'show removed files'),
                                ('a', 'added', None, 'show added files'),
                                ('m', 'modified', None, 'show modified files')],
                    'hg list [-amrRu] [-p PARENT]'),
    '^nits': (cdm_nits, [('p', 'parent', '', 'parent workspace')],
             'hg nits [-p PARENT]'),
    '^pbchk': (cdm_pbchk, [('p', 'parent', '', 'parent workspace'),
                           ('N', 'nocheck', None, 'skip RTI check')],
              'hg pbchk [-N] [-p PARENT]'),
    'permchk': (cdm_permchk, [('p', 'parent', '', 'parent workspace')],
                'hg permchk [-p PARENT]'),
    '^pdiffs': (cdm_pdiffs, [('p', 'parent', '', 'parent workspace')],
               'hg pdiffs [-p PARENT]'),
    '^recommit|reci': (cdm_recommit, [('p', 'parent', '', 'parent workspace'),
                                      ('f', 'force', None, 'force operation'),
                                      ('m', 'message', '',
                                       'use <text> as commit message'),
                                      ('l', 'logfile', '',
                                       'read commit message from file'),
                                      ('u', 'user', '',
                                       'record user as committer')],
                       'hg recommit [-f] [-p PARENT]'),
    'renamed': (cdm_renamed, [('p', 'parent', '', 'parent workspace')],
                'hg renamed [-p PARENT]'),
    'reparent': (cdm_reparent, [], 'hg reparent PARENT'),
    '^restore': (cdm_restore, [('g', 'generation', '', 'generation number')],
                 'hg restore [-g GENERATION] BACKUP'),
    'rtichk': (cdm_rtichk, [('p', 'parent', '', 'parent workspace'),
                            ('N', 'nocheck', None, 'skip RTI check')],
               'hg rtichk [-N] [-p PARENT]'),
    'tagchk': (cdm_tagchk, [('p', 'parent', '', 'parent workspace')],
               'hg tagchk [-p PARENT]'),
}
