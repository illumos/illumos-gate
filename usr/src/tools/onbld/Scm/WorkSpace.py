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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
from mercurial import cmdutil, context, hg, node, patch, repair, util
from hgext import mq

from onbld.Scm import Version

#
# Mercurial >= 1.2 has its exception types in a mercurial.error
# module, prior versions had them in their associated modules.
#
if Version.at_least("1.2"):
    from mercurial import error
    HgRepoError = error.RepoError
    HgLookupError = error.LookupError
else:
    from mercurial import repo, revlog
    HgRepoError = repo.RepoError
    HgLookupError = revlog.LookupError


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
                except HgLookupError:
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

    def files(self):
        '''Return the list of pathnames of all files touched by this
        ActiveList

        Where files have been renamed, this will include both their
        current name and the name which they had in the parent tip.
        '''

        ret = self._active.keys()
        ret.extend([x.parentname for x in self
                    if x.is_renamed() and x.parentname not in ret])
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

        def colliding_tags(iterable, nodes, local):
            for nd, name in [line.rstrip().split(' ', 1) for line in iterable]:
                if nd in nodes:
                    yield (name, self.ws.repo.lookup(nd), local)

        tags = []
        nodes = set(node.hex(ctx.node()) for ctx in self.revs)

        if os.path.exists(self.ws.repo.join('localtags')):
            fh = self.ws.repo.opener('localtags')
            tags.extend(colliding_tags(fh, nodes, True))
            fh.close()

        # We want to use the tags file from the localtip
        if '.hgtags' in self.localtip:
            data = self.localtip.filectx('.hgtags').data().splitlines()
            tags.extend(colliding_tags(data, nodes, False))

        return tags

    def prune_tags(self, data):
        '''Return a copy of data, which should correspond to the
        contents of a Mercurial tags file, with any tags that refer to
        changesets which are components of the ActiveList removed.'''

        nodes = set(node.hex(ctx.node()) for ctx in self.revs)
        return [t for t in data if t.split(' ', 1)[0] not in nodes]

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

        if parentfile.flags() != localfile.flags():
            return True

        if parentfile.cmp(localfile.data()):
            return True

    def context(self, message, user):
        '''Return a Mercurial context object representing the entire
        ActiveList as one change.'''
        return activectx(self, message, user)


class activectx(context.memctx):
    '''Represent an ActiveList as a Mercurial context object.

    Part of the  WorkSpace.squishdeltas implementation.'''

    def __init__(self, active, message, user):
        '''Build an activectx object.

          active  - The ActiveList object used as the source for all data.
          message - Changeset description
          user    - Committing user'''

        def filectxfn(repository, ctx, fname):
            fctx = active.localtip.filectx(fname)
            data = fctx.data()

            #
            # .hgtags is a special case, tags referring to active list
            # component changesets should be elided.
            #
            if fname == '.hgtags':
                data = '\n'.join(active.prune_tags(data.splitlines()))

            return context.memfilectx(fname, data, 'l' in fctx.flags(),
                                      'x' in fctx.flags(),
                                      active[fname].parentname)

        self.__active = active
        parents = (active.parenttip.node(), node.nullid)
        extra = {'branch': active.localtip.branch()}
        context.memctx.__init__(self, active.ws.repo, parents, message,
                                active.files(), filectxfn, user=user,
                                extra=extra)

    def modified(self):
        return [entry.name for entry in self.__active if entry.is_modified()]

    def added(self):
        return [entry.name for entry in self.__active if entry.is_added()]

    def removed(self):
        ret = [entry.name for entry in self.__active if entry.is_removed()]
        ret.extend([x.parentname for x in self.__active if x.is_renamed()])
        return ret

    def files(self):
        return self.__active.files()


class WorkSpace(object):

    def __init__(self, repository):
        self.repo = repository
        self.ui = self.repo.ui
        self.name = self.repo.root

        self.activecache = {}

    def parent(self, spec=None):
        '''Return the canonical workspace parent, either SPEC (which
        will be expanded) if provided or the default parent
        otherwise.'''

        if spec:
            return self.ui.expandpath(spec)

        p = self.ui.expandpath('default')
        if p == 'default':
            return None
        else:
            return p

    def _localtip(self, outgoing, wctx):
        '''Return the most representative changeset to act as the
        localtip.

        If the working directory is modified (has file changes, is a
        merge, or has switched branches), this will be a workingctx.

        If the working directory is unmodified, this will be the most
        recent (highest revision number) local (outgoing) head on the
        current branch, if no heads are determined to be outgoing, it
        will be the most recent head on the current branch.
        '''

        #
        # A modified working copy is seen as a proto-branch, and thus
        # our only option as the local tip.
        #
        if (wctx.files() or len(wctx.parents()) > 1 or
            wctx.branch() != wctx.parents()[0].branch()):
            return wctx

        heads = self.repo.heads(start=wctx.parents()[0].node())
        headctxs = [self.repo.changectx(n) for n in heads]
        localctxs = [c for c in headctxs if c.node() in outgoing]

        ltip = sorted(localctxs or headctxs, key=lambda x: x.rev())[-1]

        if len(heads) > 1:
            self.ui.warn('The current branch has more than one head, '
                         'using %s\n' % ltip.rev())

        return ltip

    def _parenttip(self, heads, outgoing):
        '''Return the highest-numbered, non-outgoing changeset that is
        an ancestor of a changeset in heads.

        This is intended to find the most recent changeset on a given
        branch that is shared between a parent and child workspace,
        such that it can act as a stand-in for the parent workspace.
        '''

        def tipmost_shared(head, outnodes):
            '''Return the tipmost node on the same branch as head that is not
            in outnodes.

            We walk from head to the bottom of the workspace (revision
            0) collecting nodes not in outnodes during the add phase
            and return the first node we see in the iter phase that
            was previously collected.

            If no node is found (all revisions >= 0 are outgoing), the
            only possible parenttip is the null node (node.nullid)
            which is returned explicitly.

            See the docstring of mercurial.cmdutil.walkchangerevs()
            for the phased approach to the iterator returned.  The
            important part to note is that the 'add' phase gathers
            nodes, which the 'iter' phase then iterates through.'''

            opts = {'rev': ['%s:0' % head.rev()],
                    'follow': True}
            get = util.cachefunc(lambda r: self.repo.changectx(r).changeset())
            changeiter = cmdutil.walkchangerevs(self.repo.ui, self.repo, [],
                                                get, opts)[0]
            seen = []
            for st, rev, fns in changeiter:
                n = self.repo.changelog.node(rev)
                if st == 'add':
                    if n not in outnodes:
                        seen.append(n)
                elif st == 'iter':
                    if n in seen:
                        return rev
            return self.repo.changelog.rev(node.nullid)

        nodes = set(outgoing)
        ptips = map(lambda x: tipmost_shared(x, nodes), heads)
        return self.repo.changectx(sorted(ptips)[-1])

    def status(self, base='.', head=None):
        '''Translate from the hg 6-tuple status format to a hash keyed
        on change-type'''

        states = ['modified', 'added', 'removed', 'deleted', 'unknown',
              'ignored']

        chngs = self.repo.status(base, head)
        return dict(zip(states, chngs))

    def findoutgoing(self, parent):
        '''Return the base set of outgoing nodes.

        A caching wrapper around mercurial.localrepo.findoutgoing().
        Complains (to the user), if the parent workspace is
        non-existent or inaccessible'''

        self.ui.pushbuffer()
        try:
            try:
                ui = self.ui
                if hasattr(cmdutil, 'remoteui'):
                    ui = cmdutil.remoteui(ui, {})
                pws = hg.repository(ui, parent)
                return self.repo.findoutgoing(pws)
            except HgRepoError:
                self.ui.warn("Warning: Parent workspace '%s' is not "
                             "accessible\n"
                             "active list will be incomplete\n\n" % parent)
                return []
        finally:
            self.ui.popbuffer()
    findoutgoing = util.cachefunc(findoutgoing)

    def modified(self):
        '''Return a list of files modified in the workspace'''
        wctx = self.workingctx()
        return sorted(wctx.files() + wctx.deleted()) or None

    def merged(self):
        '''Return boolean indicating whether the workspace has an uncommitted
        merge'''
        wctx = self.workingctx()
        return len(wctx.parents()) > 1

    def branched(self):
        '''Return boolean indicating whether the workspace has an
        uncommitted named branch'''

        wctx = self.workingctx()
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
            outnodes = self.repo.changelog.nodesbetween(outgoing)[0]
        else:
            outgoing = []       # No parent, no outgoing nodes
            outnodes = []

        localtip = self._localtip(outnodes, self.workingctx())

        if localtip.rev() is None:
            heads = localtip.parents()
        else:
            heads = [localtip]

        ctxs = [self.repo.changectx(n) for n in
                self.repo.changelog.nodesbetween(outgoing,
                                                 [h.node() for h in heads])[0]]

        if localtip.rev() is None:
            ctxs.append(localtip)

        act = ActiveList(self, self._parenttip(heads, outnodes), ctxs)

        self.activecache[parent] = act
        return act

    def pdiff(self, pats, opts, parent=None):
        'Return diffs relative to PARENT, as best as we can make out'

        parent = self.parent(parent)
        act = self.active(parent)

        #
        # act.localtip maybe nil, in the case of uncommitted local
        # changes.
        #
        if not act.revs:
            return

        matchfunc = cmdutil.match(self.repo, pats, opts)
        opts = patch.diffopts(self.ui, opts)

        return self.diff(act.parenttip.node(), act.localtip.node(),
                         match=matchfunc, opts=opts)

    def squishdeltas(self, active, message, user=None):
        '''Create a single conglomerate changeset based on a given
        active list.  Removes the original changesets comprising the
        given active list, and any tags pointing to them.

        Operation:

          - Commit an activectx object representing the specified
            active list,

          - Remove any local tags pointing to changesets in the
            specified active list.

          - Remove the changesets comprising the specified active
            list.

          - Remove any metadata that may refer to changesets that were
            removed.

        Calling code is expected to hold both the working copy lock
        and repository lock of the destination workspace
        '''

        def strip_local_tags(active):
            '''Remove any local tags referring to the specified nodes.'''

            if os.path.exists(self.repo.join('localtags')):
                fh = None
                try:
                    fh = self.repo.opener('localtags')
                    tags = active.prune_tags(fh)
                    fh.close()

                    fh = self.repo.opener('localtags', 'w', atomictemp=True)
                    fh.writelines(tags)
                    fh.rename()
                finally:
                    if fh and not fh.closed:
                        fh.close()

        if active.files():
            for entry in active:
                #
                # Work around Mercurial issue #1666, if the source
                # file of a rename exists in the working copy
                # Mercurial will complain, and remove the file.
                #
                # We preemptively remove the file to avoid the
                # complaint (the user was asked about this in
                # cdm_recommit)
                #
                if entry.is_renamed():
                    path = self.repo.wjoin(entry.parentname)
                    if os.path.exists(path):
                        os.unlink(path)

            self.repo.commitctx(active.context(message, user))
            wsstate = "recommitted"
            destination = self.repo.changelog.tip()
        else:
            #
            # If all we're doing is stripping the old nodes, we want to
            # update the working copy such that we're not at a revision
            # that's about to go away.
            #
            wsstate = "tip"
            destination = active.parenttip.node()

        self.clean(destination)

        #
        # Tags were elided by the activectx object.  Local tags,
        # however, must be removed manually.
        #
        try:
            strip_local_tags(active)
        except EnvironmentError, e:
            raise util.Abort('Could not recommit tags: %s\n' % e)

        # Silence all the strip and update fun
        self.ui.pushbuffer()

        #
        # Remove the active lists component changesets by stripping
        # the base of any active branch (of which there may be
        # several)
        #
        bases = active.bases()
        try:
            try:
                for basenode in bases:
                    #
                    # Any cached information about the repository is
                    # likely to be invalid during the strip.  The
                    # caching of branch tags is especially
                    # problematic.
                    #
                    self.repo.invalidate()
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
                             "%s changeset.\n" % wsstate)
                raise               # Re-raise the exception
        finally:
            self.clean()
            self.repo.dirstate.write() # Flush the dirstate
            self.repo.invalidate()     # Invalidate caches

            #
            # We need to remove Hg's undo information (used for rollback),
            # since it refers to data that will probably not exist after
            # the strip.
            #
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

        hg.clean(self.repo, rev, show_stats=False)

    def mq_applied(self):
        '''True if the workspace has Mq patches applied'''
        q = mq.queue(self.ui, self.repo.join(''))
        return q.applied

    def workingctx(self):
        return self.repo.changectx(None)

    def diff(self, node1=None, node2=None, match=None, opts=None):
        ret = cStringIO.StringIO()
        try:
            for chunk in patch.diff(self.repo, node1, node2, match=match,
                                    opts=opts):
                ret.write(chunk)
        finally:
            # Workaround Hg bug 1651
            if not Version.at_least("1.3"):
                self.repo.dirstate.invalidate()

        return ret.getvalue()
