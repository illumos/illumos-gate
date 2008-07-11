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

#
# Theory:
#
# Workspaces have a non-binding parent/child relationship.
# All important operations apply to the changes between the two.
#
# However, for the sake of remote operation, the 'parent' of a
# workspace is not seen as a literal entity, instead the figurative
# parent contains the last changeset common to both parent and child,
# as such the 'parent tip' is actually nothing of the sort, but instead a
# convenient imitation.
#
# Any change made to a workspace is a change to a file therein, such
# changes can be represented briefly as whether the file was
# modified/added/removed as compared to the parent workspace, whether
# the file has a different name in the parent and if so, whether it
# was renamed or merely copied.  Each changed file has an
# associated ActiveEntry.
#
# The ActiveList being a list ActiveEntrys can thus present the entire
# change in workspace state between a parent and its child, and is the
# important bit here (in that if it is incorrect, everything else will
# be as incorrect, or more)
#

import cStringIO
import os
from mercurial import hg, patch, cmdutil, util, node, repo
from mercurial import revlog, repair
from hgext import mq


class ActiveEntry(object):
    '''Representation of the changes made to a single file.

    MODIFIED   - Contents changed, but no other changes were made
    ADDED      - File is newly created
    REMOVED    - File is being removed

    Copies are represented by an Entry whose .parentname is non-nil

    Truly copied files have non-nil .parentname and .renamed = False
    Renames have non-nil .parentname and .renamed = True

    Do not access any of this information directly, do so via the

    .is_<change>() methods.'''

    MODIFIED = 1
    ADDED = 2
    REMOVED = 3

    def __init__(self, name):
        self.name = name
        self.change = None
        self.parentname = None
        # As opposed to copied (or neither)
        self.renamed = False
        self.comments = []

    #
    # ActiveEntrys sort by the name of the file they represent.
    #
    def __cmp__(self, other):
        return cmp(self.name, other.name)

    def is_added(self):
        return self.change == self.ADDED

    def is_modified(self):
        return self.change == self.MODIFIED

    def is_removed(self):
        return self.change == self.REMOVED

    def is_renamed(self):
        return self.parentname and self.renamed

    def is_copied(self):
        return self.parentname and not self.renamed


class ActiveList(object):
    '''Complete representation of workspace change.

    In practice, a container for ActiveEntrys, and methods to build them,
    update them, and deal with them en masse.'''

    def __init__(self, ws, parenttip, revs=None):
        self._active = {}
        self.ws = ws

        self.revs = revs

        self.base = None
        self.parenttip = parenttip

        #
        # If we couldn't find a parenttip, the two repositories must
        # be unrelated (Hg catches most of this, but this case is valid for it
        # but invalid for us)
        #
        if self.parenttip == None:
            raise util.Abort('repository is unrelated')
        self.localtip = None

        if revs:
            self.base = revs[0]
            self.localtip = revs[-1]

        self._comments = []

        self._build(revs)

    def _build(self, revs):
        if not revs:
            return

        status = self.ws.status(self.parenttip.node(), self.localtip.node())

        files = []
        for ctype in status.values():
            files.extend(ctype)

        #
        # When a file is renamed, two operations actually occur.
        # A file copy from source to dest and a removal of source.
        #
        # These are represented as two distinct entries in the
        # changectx and status (one on the dest file for the
        # copy, one on the source file for the remove).
        #
        # Since these are unconnected in both the context and
        # status we can only make the association by explicitly
        # looking for it.
        #
        # We deal with this thusly:
        #
        # We maintain a dict dest -> source of all copies
        # (updating dest as appropriate, but leaving source alone).
        #
        # After all other processing, we mark as renamed any pair
        # where source is on the removed list.
        #
        copies = {}

        #
        # Walk revs looking for renames and adding files that
        # are in both change context and status to the active
        # list.
        #
        for ctx in revs:
            desc = ctx.description().splitlines()

            self._comments.extend(desc)

            for fname in ctx.files():
                #
                # We store comments per-entry as well, for the sake of
                # webrev and similar.  We store twice to avoid the problems
                # of uniquifying comments for the general list (and possibly
                # destroying multi-line entities in the process).
                #
                if fname not in self:
                    self._addentry(fname)
                self[fname].comments.extend(desc)

                try:
                    fctx = ctx.filectx(fname)
                except revlog.LookupError:
                    continue

                #
                # NB: .renamed() is a misnomer, this actually checks
                #     for copies.
                #
                rn = fctx.renamed()
                if rn:
                    #
                    # If the source file is a known copy we know its
                    # ancestry leads us to the parent.
                    # Otherwise make sure the source file is known to
                    # be in the parent, we need not care otherwise.
                    #
                    # We detect cycles at a later point.  There is no
                    # reason to continuously handle them.
                    #
                    if rn[0] in copies:
                        copies[fname] = copies[rn[0]]
                    elif rn[0] in self.parenttip.manifest():
                        copies[fname] = rn[0]

        #
        # Walk the copy list marking as copied any non-cyclic pair
        # where the destination file is still present in the local
        # tip (to avoid ephemeral changes)
        #
        # Where source is removed, mark as renamed, and remove the
        # AL entry for the source file
        #
        for fname, oldname in copies.iteritems():
            if fname == oldname or fname not in self.localtip.manifest():
                continue

            self[fname].parentname = oldname

            if oldname in status['removed']:
                self[fname].renamed = True
                if oldname in self:
                    del self[oldname]

        #
        # Walk the active list setting the change type for each active
        # file.
        #
        # In the case of modified files that are not renames or
        # copies, we do a content comparison, and drop entries that
        # are not actually modified.
        #
        # We walk a copy of the AL such that we can drop entries
        # within the loop.
        #
        for entry in self._active.values():
            if entry.name not in files:
                del self[entry.name]
                continue

            if entry.name in status['added']:
                entry.change = ActiveEntry.ADDED
            elif entry.name in status['removed']:
                entry.change = ActiveEntry.REMOVED
            elif entry.name in status['modified']:
                entry.change = ActiveEntry.MODIFIED

            #
            # There are cases during a merge where a file will be in
            # the status return as modified, but in reality be an
            # addition (ie, not in the parenttip).
            #
            # We need to check whether the file is actually present
            # in the parenttip, and set it as an add, if not.
            #
            if entry.name not in self.parenttip.manifest():
                entry.change = ActiveEntry.ADDED
            elif entry.is_modified() and not entry.parentname:
                if not self.filecmp(entry):
                    del self[entry.name]
                    continue

            assert entry.change

    def __contains__(self, fname):
        return fname in self._active

    def __getitem__(self, key):
        return self._active[key]

    def __setitem__(self, key, value):
        self._active[key] = value

    def __delitem__(self, key):
        del self._active[key]

    def __iter__(self):
        for entry in self._active.values():
            yield entry

    def _addentry(self, fname):
        if fname not in self:
            self[fname] = ActiveEntry(fname)

    #
    # Return list of files represented in this AL,
    # including the parent file of a rename
    #
    def files(self):
        ret = self._active.keys()

        ret.extend([x.parentname for x in self
                    if x.parentname and x.parentname not in ret])
        return ret

    def comments(self):
        return self._comments

    #
    # It's not uncommon for a child workspace to itself contain the
    # merge of several other children, with initial branch points in
    # the parent (possibly from the cset a project gate was created
    # from, for instance).
    #
    # Immediately after recommit, this leaves us looking like this:
    #
    #     *   <- recommitted changeset (real tip)
    #     |
    #     | *  <- Local tip
    #     |/|
    #     * |  <- parent tip
    #     | |\
    #     | | |
    #     | | |\
    #     | | | |
    #     | * | |  <- Base
    #     |/_/__/
    #
    #     [left-most is parent, next is child, right two being
    #     branches in child, intermediate merges parent->child
    #     omitted]
    #
    # Obviously stripping base (the first child-specific delta on the
    # main child workspace line) doesn't remove the vestigial branches
    # from other workspaces (or in-workspace branches, or whatever)
    #
    # In reality, what we need to strip in a recommit is any
    # child-specific branch descended from the parent (rather than
    # another part of the child).  Note that this by its very nature
    # includes the branch representing the 'main' child workspace.
    #
    # We calculate these by walking from base (which is guaranteed to
    # be the oldest child-local cset) to localtip searching for
    # changesets with only one parent cset, and where that cset is not
    # part of the active list (and is therefore outgoing).
    #
    def bases(self):
        '''Find the bases that in combination define the "old"
        side of a recommitted set of changes, based on AL'''

        get = util.cachefunc(lambda r: self.ws.repo.changectx(r).changeset())

        # We don't rebuild the AL So the AL local tip is the old tip
        revrange = "%s:%s" % (self.base.rev(), self.localtip.rev())

        changeiter = cmdutil.walkchangerevs(self.ws.repo.ui, self.ws.repo,
                                            [], get, {'rev': [revrange]})[0]

        hold = []
        ret = []
        alrevs = [x.rev() for x in self.revs]
        for st, rev, fns in changeiter:
            n = self.ws.repo.changelog.node(rev)
            if st == 'add':
                if rev in alrevs:
                    hold.append(n)
            elif st == 'iter':
                if n not in hold:
                    continue

                p = self.ws.repo.changelog.parents(n)
                if p[1] != node.nullid:
                    continue

                if self.ws.repo.changectx(p[0]).rev() not in alrevs:
                    ret.append(n)
        return ret

    def tags(self):
        '''Find tags that refer to a changeset in the ActiveList,
           returning a list of 3-tuples (tag, node, is_local) for each.

           We return all instances of a tag that refer to such a node,
           not just that which takes precedence.'''

        if os.path.exists(self.ws.repo.join('localtags')):
            l = self.ws.repo.opener('localtags').readlines()
            ltags = [x.rstrip().split(' ') for x in l]
        else:
            ltags = []

        # We want to use the tags file from the localtip
        if '.hgtags' in self.localtip.manifest():
            f = self.localtip.filectx('.hgtags')
            rtags = [x.rstrip().split(' ') for x in f.data().splitlines()]
        else:
            rtags = []

        nodes = [node.hex(n.node()) for n in self.revs]
        tags = []

        for nd, name in rtags:
            if nd in nodes:
                tags.append((name, self.ws.repo.lookup(nd), False))

        for nd, name in ltags:
            if nd in nodes:
                tags.append((name, self.ws.repo.lookup(nd), True))

        return tags

    def filecmp(self, entry):
        '''Compare two revisions of two files

        Return True if file changed, False otherwise.

        The fast path compares file metadata, slow path is a
        real comparison of file content.'''

        parentfile = self.parenttip.filectx(entry.parentname or entry.name)
        localfile = self.localtip.filectx(entry.name)

        #
        # NB: Keep these ordered such as to make every attempt
        #     to short-circuit the more time consuming checks.
        #
        if parentfile.size() != localfile.size():
            return True

        if parentfile.fileflags() != localfile.fileflags():
            return True

        if parentfile.cmp(localfile.data()):
            return True


class WorkSpace(object):

    def __init__(self, repository):
        self.repo = repository
        self.ui = self.repo.ui
        self.name = self.repo.root

        parent = self.repo.ui.expandpath('default')
        if parent == 'default':
            parent = None
        self.parentrepo = parent

        self.activecache = {}
        self.outgoingcache = {}

    def parent(self, spec=None):
        '''Return canonical workspace parent, either SPEC if passed,
        or default parent otherwise'''
        return spec or self.parentrepo

    def _localtip(self, bases, heads):
        '''Return a tuple (changectx, workingctx) representing the most
        representative head to act as the local tip.

        If the working directory is modified, the changectx is its
        tipmost local parent (or tipmost parent, if neither is
        local), and the workingctx is non-null.

        If the working directory is clean, the workingctx is null.
        The changectx is the tip-most local head on the current branch.
        If this can't be determined for some reason (e.g., the parent
        repo is inacessible), changectx is the tip-most head on the
        current branch.

        If the workingctx is non-null it is the actual local tip (and would
        be the local tip in any generated ActiveList, for instance),
        the better parent revision is returned also to aid callers needing
        a real changeset to act as a surrogate for an uncommitted change.'''

        def tipmost_of(nodes):
            return sorted(nodes, cmp=lambda x, y: cmp(x.rev(), y.rev()))[-1]

        #
        # We need a full set of outgoing nodes such that we can limit
        # local branch heads to those which are outgoing
        #
        outnodes = self.repo.changelog.nodesbetween(bases, heads)[0]
        wctx = self.repo.workingctx()

        #
        # A modified working context is seen as a proto-branch, where
        # the 'heads' from our view are the parent revisions of that
        # context.
        # (and the working head is it)
        #
        if (wctx.files() or len(wctx.parents()) > 1 or
            wctx.branch() != wctx.parents()[0].branch()):
            heads = wctx.parents()
        else:
            heads = [self.repo.changectx(n) for n in heads]
            wctx = None

        localchoices = [n for n in heads if n.node() in outnodes]
        return (tipmost_of(localchoices or heads), wctx)

    def _parenttip(self, localtip, parent=None):
        '''Find the closest approximation of the parents tip, as best
        as we can.

        In parent-less workspaces returns our tip (given the best
        we can do is deal with uncommitted changes)'''

        def tipmost_shared(head, outnodes):
            '''Return the tipmost node on the same branch as head that is not
            in outnodes.

            We walk from head to the bottom of the workspace (revision
            0) collecting nodes not in outnodes during the add phase
            and return the first node we see in the iter phase that
            was previously collected.

            See the docstring of mercurial.cmdutil.walkchangerevs()
            for the phased approach to the iterator returned.  The
            important part to note is that the 'add' phase gathers
            nodes, which the 'iter' phase then iterates through.'''

            get = util.cachefunc(lambda r: self.repo.changectx(r).changeset())
            changeiter = cmdutil.walkchangerevs(self.repo.ui, self.repo, [],
                                                get, {'rev': ['%s:0' % head],
                                                      'follow': True})[0]
            seen = []
            for st, rev, fns in changeiter:
                n = self.repo.changelog.node(rev)
                if st == 'add':
                    if n not in outnodes:
                        seen.append(n)
                elif st == 'iter':
                    if n in seen:
                        return rev
            return None

        tipctx, wctx = localtip
        parent = self.parent(parent)
        outgoing = None

        if parent:
            outgoing = self.findoutgoing(parent)

        if wctx:
            possible_branches = wctx.parents()
        else:
            possible_branches = [tipctx]

        nodes = self.repo.changelog.nodesbetween(outgoing)[0]
        ptips = map(lambda x: tipmost_shared(x.rev(), nodes), possible_branches)
        return self.repo.changectx(sorted(ptips)[-1])

    def status(self, base=None, head=None):
        '''Translate from the hg 6-tuple status format to a hash keyed
        on change-type'''
        states = ['modified', 'added', 'removed', 'deleted', 'unknown',
              'ignored']
        chngs = self.repo.status(base, head)
        return dict(zip(states, chngs))

    #
    # Cache findoutgoing results
    #
    def findoutgoing(self, parent):
        ret = []
        if parent in self.outgoingcache:
            ret = self.outgoingcache[parent]
        else:
            self.ui.pushbuffer()
            try:
                pws = hg.repository(self.ui, parent)
                ret = self.repo.findoutgoing(pws)
            except repo.RepoError:
                self.ui.warn(
                    "Warning: Parent workspace %s is not accessible\n" % parent)
                self.ui.warn("active list will be incomplete\n\n")

            self.outgoingcache[parent] = ret
            self.ui.popbuffer()

        return ret

    def modified(self):
        '''Return a list of files modified in the workspace'''
        wctx = self.repo.workingctx()
        return sorted(wctx.files() + wctx.deleted()) or None

    def merged(self):
        '''Return boolean indicating whether the workspace has an uncommitted
        merge'''
        wctx = self.repo.workingctx()
        return len(wctx.parents()) > 1

    def branched(self):
        '''Return boolean indicating whether the workspace has an
        uncommitted named branch'''

        wctx = self.repo.workingctx()
        return wctx.branch() != wctx.parents()[0].branch()

    def active(self, parent=None):
        '''Return an ActiveList describing changes between workspace
        and parent workspace (including uncommitted changes).
        If workspace has no parent ActiveList will still describe any
        uncommitted changes'''

        parent = self.parent(parent)
        if parent in self.activecache:
            return self.activecache[parent]

        if parent:
            outgoing = self.findoutgoing(parent)
        else:
            outgoing = []       # No parent, no outgoing nodes

        branchheads = self.repo.heads(start=self.repo.dirstate.parents()[0])
        ourhead, workinghead = self._localtip(outgoing, branchheads)

        if len(branchheads) > 1:
            self.ui.warn('The current branch has more than one head, '
                         'using %s\n' % ourhead.rev())

        if workinghead:
            parents = workinghead.parents()
            ctxs = [self.repo.changectx(n) for n in
                    self.repo.changelog.nodesbetween(outgoing,
                                                     [h.node() for h in
                                                      parents])[0]]
            ctxs.append(workinghead)
        else:
            ctxs = [self.repo.changectx(n) for n in
                    self.repo.changelog.nodesbetween(outgoing,
                                                     [ourhead.node()])[0]]

        act = ActiveList(self, self._parenttip((ourhead, workinghead), parent),
                         ctxs)

        self.activecache[parent] = act
        return act

    def pdiff(self, parent=None):
        'Return diffs relative to PARENT, as best as we can make out'

        parent = self.parent(parent)
        act = self.active(parent)

        #
        # act.localtip maybe nil, in the case of uncommitted local
        # changes.
        #
        if not act.revs:
            return

        ret = cStringIO.StringIO()
        patch.diff(self.repo, act.parenttip.node(), act.localtip.node(),
                   fp=ret)
        return ret.getvalue()

    #
    # Theory:
    #
    # We wish to go from a single series of consecutive changesets
    # (possibly including merges with the parent) to a single
    # changeset faithfully representing contents and copy history.
    #
    # We achieve this in a somewhat confusing fashion.
    #
    # - Sanity check the workspace
    # - Update the workspace to tip
    # - Enter into the dirstate the sum total of file contents in the
    #   to-be-squished changesets
    # - Commit this in-progress change (which has no changes at all,
    #   in reality) On top of the effective parent tip.
    # - Strip the child-local branch(es) (see ActiveList.bases())
    #
    def squishdeltas(self, active, message, user=None):
        '''Create a single conglomerate changeset, with log message MESSAGE
        containing the changes from ACTIVE.  USER, if set, is used
        as the author name.

        The old changes are removed.'''

        def strip_tags(nodes):
            '''Remove any tags referring to the specified nodes.'''

            if os.path.exists(self.repo.join('localtags')):
                fh = self.repo.opener('localtags').readlines()
                tags = [t for t in fh if t.split(' ')[0] not in nodes]
                fh = self.repo.opener('localtags', 'w', atomictemp=True)
                fh.writelines(tags)
                fh.rename()

            if os.path.exists(self.repo.wjoin('.hgtags')):
                fh = self.repo.wopener('.hgtags', 'rb').readlines()
                tags = [t for t in fh if t.split(' ')[0] not in nodes]
                fh = self.repo.wopener('.hgtags', 'wb', atomictemp=True)
                fh.writelines(tags)
                fh.rename()

        wlock = self.repo.wlock()
        lock = self.repo.lock()

        #
        # The files involved need to be present in the workspace and
        # not otherwise molested, rather than the workspace not being
        # modified we also need to prevent files being deleted (but
        # left versioned) too.
        #
        # The easiest way to achieve this is to update the working
        # copy to tip.
        #
        self.clean()

        try:
            strip_tags([node.hex(ctx.node()) for ctx in active.revs])
        except EnvironmentError, e:
            raise util.Abort('Could not recommit tags: %s\n' % e)

        #
        # For copied files, we need to enter the copy into the
        # dirstate before we force the commit such that the
        # file logs of both branches (old and new) contain
        # representation of the copy.
        #
        parentman = active.parenttip.manifest()
        for entry in active:
            if not entry.is_renamed() and not entry.is_copied():
                continue

            assert entry.parentname in parentman, \
                ("parentname '%s' (of '%s') not in parent" %
                 (entry.parentname, entry.name))

            #
            # If the source file exists, and used to be versioned
            # this will cause this to become a true copy
            # (re-introducing the source file)
            #
            # We bandaid this, by removing the source file in this
            # case.  If we're here, the user has already agreed to this
            # from above.
            #
            if (entry.is_renamed() and
                os.path.exists(self.repo.wjoin(entry.parentname))):
                os.unlink(self.repo.wjoin(entry.parentname))

            self.repo.copy(entry.parentname, entry.name)

        if active.files():
            extra = {'branch': active.localtip.branch()}
            self.repo.commit(files=active.files(), text=message,
                             user=user, p1=active.parenttip.node(), p2=None,
                             extra=extra)
            wsstate = "recommitted changeset"
            self.clean()
        else:
            #
            # If all we're doing is stripping the old nodes, we want to
            # update the working copy such that we're not at a revision
            # that's about to go away.
            #
            wsstate = "tip changeset"
            self.clean(rev=active.parenttip.node())

        # Silence all the strip and update fun
        self.ui.pushbuffer()

        #
        # We must strip away the old representation of the child
        # branch(es).  This may involve stripping a theoretically
        # large number of branches in certain cases
        #
        bases = active.bases()
        try:
            try:
                for basenode in bases:
                    repair.strip(self.ui, self.repo, basenode, backup=False)
            except:
                #
                # If this fails, it may leave us in a surprising place in
                # the history.
                #
                # We want to warn the user that something went wrong,
                # and what will happen next, re-raise the exception, and
                # bring the working copy back into a consistent state
                # (which the finally block will do)
                #
                self.ui.warn("stripping failed, your workspace will have "
                             "superfluous heads.\n"
                             "your workspace has been updated to the "
                             "%s.\n" % wsstate)
                raise               # Re-raise the exception
        finally:
            #
            # We need to remove Hg's undo information (used for rollback),
            # since it refers to data that will probably not exist after
            # the strip.
            #

            self.clean()
            self.repo.dirstate.write() # Flush the dirstate
            self.repo.invalidate()     # Invalidate caches

            if os.path.exists(self.repo.sjoin('undo')):
                try:
                    os.unlink(self.repo.sjoin('undo'))
                except EnvironmentError, e:
                    raise util.Abort('failed to remove undo data: %s\n' % e)

            self.ui.popbuffer()

    def filepath(self, path):
        'Return the full path to a workspace file.'
        return self.repo.pathto(path)

    def clean(self, rev=None):
        '''Bring workspace up to REV (or tip) forcefully (discarding in
        progress changes)'''
        if rev != None:
            rev = self.repo.lookup(rev)
        else:
            rev = self.repo.changelog.tip()

        wlock = self.repo.wlock()
        hg.clean(self.repo, rev, show_stats=False)

    def mq_applied(self):
        '''True if the workspace has Mq patches applied'''
        q = mq.queue(self.ui, self.repo.join(''))
        return q.applied
