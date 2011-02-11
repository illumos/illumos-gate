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
# Copyright 2008, 2011, Richard Lowe
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
# The ActiveList, being a list of ActiveEntry objects, can thus
# present the entire change in workspace state between a parent and
# its child and is the important bit here (in that if it is incorrect,
# everything else will be as incorrect, or more)
#

import cStringIO
import os
from mercurial import cmdutil, context, error, hg, node, patch, repair, util
from hgext import mq

from onbld.Scm import Version


#
# Mercurial 1.6 moves findoutgoing into a discover module
#
if Version.at_least("1.6"):
    from mercurial import discovery


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

    MODIFIED = intern('modified')
    ADDED = intern('added')
    REMOVED = intern('removed')

    def __init__(self, name, change):
        self.name = name
        self.change = intern(change)

        assert change in (self.MODIFIED, self.ADDED, self.REMOVED)

        self.parentname = None
        # As opposed to copied (or neither)
        self.renamed = False
        self.comments = []

    def __cmp__(self, other):
        return cmp(self.name, other.name)

    def is_added(self):
        '''Return True if this ActiveEntry represents an added file'''
        return self.change is self.ADDED

    def is_modified(self):
        '''Return True if this ActiveEntry represents a modified file'''
        return self.change is self.MODIFIED

    def is_removed(self):
        '''Return True if this ActiveEntry represents a removed file'''
        return self.change is self.REMOVED

    def is_renamed(self):
        '''Return True if this ActiveEntry represents a renamed file'''
        return self.parentname and self.renamed

    def is_copied(self):
        '''Return True if this ActiveEntry represents a copied file'''
        return self.parentname and not self.renamed


class ActiveList(object):
    '''Complete representation of change between two changesets.

    In practice, a container for ActiveEntry objects, and methods to
    create them, and deal with them as a group.'''

    def __init__(self, ws, parenttip, revs=None):
        '''Initialize the ActiveList

        parenttip is the revision with which to compare (likely to be
        from the parent), revs is a topologically sorted list of
        revisions ending with the revision to compare with (likely to
        be the child-local revisions).'''

        assert parenttip is not None

        self.ws = ws
        self.revs = revs
        self.parenttip = parenttip
        self.localtip = None

        self._active = {}
        self._comments = []

        if revs:
            self.localtip = revs[-1]
            self._build()

    def _status(self):
        '''Return the status of any file mentioned in any of the
        changesets making up this active list.'''

        files = set()
        for c in self.revs:
            files.update(c.files())

        #
        # Any file not in the parenttip or the localtip is ephemeral
        # and can be ignored. Mercurial will complain regarding these
        # files if the localtip is a workingctx, so remove them in
        # that case.
        #
        # Compare against the dirstate because a workingctx manifest
        # is created on-demand and is particularly expensive.
        #
        if self.localtip.rev() is None:
            for f in files.copy():
                if f not in self.parenttip and f not in self.ws.repo.dirstate:
                    files.remove(f)

        return self.ws.status(self.parenttip, self.localtip, files=files)

    def _build(self):
        '''Construct ActiveEntry objects for each changed file.

        This works in 3 stages:

          - Create entries for every changed file with
            semi-appropriate change type

          - Track renames/copies, and set change comments (both
            ActiveList-wide, and per-file).

          - Cleanup
            - Drop circular renames
            - Drop the removal of the old name of any rename
            - Drop entries for modified files that haven't actually changed'''

        #
        # Keep a cache of filectx objects (keyed on pathname) so that
        # we can avoid opening filelogs numerous times.
        #
        fctxcache = {}

        def oldname(ctx, fname):
            '''Return the name 'fname' held prior to any possible
            rename/copy in the given changeset.'''
            try:
                if fname in fctxcache:
                    octx = fctxcache[fname]
                    fctx = ctx.filectx(fname, filelog=octx.filelog())
                else:
                    fctx = ctx.filectx(fname)
                    #
                    # workingfilectx objects may not refer to the
                    # right filelog (in case of rename).  Don't cache
                    # them.
                    #
                    if not isinstance(fctx, context.workingfilectx):
                        fctxcache[fname] = fctx
            except error.LookupError:
                return None

            rn = fctx.renamed()
            return rn and rn[0] or fname

        status = self._status()
        self._active = dict((fname, ActiveEntry(fname, kind))
                            for fname, kind in status.iteritems()
                            if kind in ('modified', 'added', 'removed'))

        #
        # We do two things:
        #    - Gather checkin comments (for the entire ActiveList, and
        #      per-file)
        #    - Set the .parentname of any copied/renamed file
        #
        # renames/copies:
        #   We walk the list of revisions backward such that only files
        #   that ultimately remain active need be considered.
        #
        #   At each iteration (revision) we update the .parentname of
        #   any active file renamed or copied in that revision (the
        #   current .parentname if set, or .name otherwise, reflects
        #   the name of a given active file in the revision currently
        #   being looked at)
        #
        for ctx in reversed(self.revs):
            desc = ctx.description().splitlines()
            self._comments = desc + self._comments
            cfiles = set(ctx.files())

            for entry in self:
                fname = entry.parentname or entry.name
                if fname not in cfiles:
                    continue

                entry.comments = desc + entry.comments

                #
                # We don't care about the name history of any file
                # that ends up being removed, since that trumps any
                # possible renames or copies along the way.
                #
                # Changes that we may care about involving an
                # intermediate name of a removed file will appear
                # separately (related to the eventual name along
                # that line)
                #
                if not entry.is_removed():
                    entry.parentname = oldname(ctx, fname)

        for entry in self._active.values():
            #
            # For any file marked as copied or renamed, clear the
            # .parentname if the copy or rename is cyclic (source ==
            # destination) or if the .parentname did not exist in the
            # parenttip.
            #
            # If the parentname is marked as removed, set the renamed
            # flag and remove any ActiveEntry we may have for the
            # .parentname.
            #
            if entry.parentname:
                if (entry.parentname == entry.name or
                    entry.parentname not in self.parenttip):
                    entry.parentname = None
                elif status.get(entry.parentname) == 'removed':
                    entry.renamed = True

                    if entry.parentname in self:
                        del self[entry.parentname]

            #
            # There are cases during a merge where a file will be seen
            # as modified by status but in reality be an addition (not
            # in the parenttip), so we have to check whether the file
            # is in the parenttip and set it as an addition, if not.
            #
            # If a file is modified (and not a copy or rename), we do
            # a full comparison to the copy in the parenttip and
            # ignore files that are parts of active revisions but
            # unchanged.
            #
            if entry.name not in self.parenttip:
                entry.change = ActiveEntry.ADDED
            elif entry.is_modified():
                if not self._changed_file(entry.name):
                    del self[entry.name]

    def __contains__(self, fname):
        return fname in self._active

    def __getitem__(self, key):
        return self._active[key]

    def __setitem__(self, key, value):
        self._active[key] = value

    def __delitem__(self, key):
        del self._active[key]

    def __iter__(self):
        return self._active.itervalues()

    def files(self):
        '''Return the list of pathnames of all files touched by this
        ActiveList

        Where files have been renamed, this will include both their
        current name and the name which they had in the parent tip.
        '''

        ret = self._active.keys()
        ret.extend(x.parentname for x in self if x.is_renamed())
        return set(ret)

    def comments(self):
        '''Return the full set of changeset comments associated with
        this ActiveList'''

        return self._comments

    def bases(self):
        '''Return the list of changesets that are roots of the ActiveList.

        This is the set of active changesets where neither parent
        changeset is itself active.'''

        revset = set(self.revs)
        return filter(lambda ctx: not [p for p in ctx.parents() if p in revset],
                      self.revs)

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

    def _changed_file(self, path):
        '''Compare the parent and local versions of a given file.
        Return True if file changed, False otherwise.

        Note that this compares the given path in both versions, not the given
        entry; renamed and copied files are compared by name, not history.

        The fast path compares file metadata, slow path is a
        real comparison of file content.'''

        if ((path in self.parenttip) != (path in self.localtip)):
            return True

        parentfile = self.parenttip.filectx(path)
        localfile = self.localtip.filectx(path)

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

    def as_text(self, paths):
        '''Return the ActiveList as a block of text in a format
        intended to aid debugging and simplify the test suite.

        paths should be a list of paths for which file-level data
        should be included.  If it is empty, the whole active list is
        included.'''

        cstr = cStringIO.StringIO()

        cstr.write('parent tip: %s:%s\n' % (self.parenttip.rev(),
                                            self.parenttip))
        if self.localtip:
            rev = self.localtip.rev()
            cstr.write('local tip:  %s:%s\n' %
                       (rev is None and "working" or rev, self.localtip))
        else:
            cstr.write('local tip:  None\n')

        cstr.write('entries:\n')
        for entry in self:
            if paths and self.ws.filepath(entry.name) not in paths:
                continue

            cstr.write('  - %s\n' % entry.name)
            cstr.write('    parentname: %s\n' % entry.parentname)
            cstr.write('    change: %s\n' % entry.change)
            cstr.write('    renamed: %s\n' % entry.renamed)
            cstr.write('    comments:\n')
            cstr.write('      ' + '\n      '.join(entry.comments) + '\n')
            cstr.write('\n')

        return cstr.getvalue()


class WorkList(object):
    '''A (user-maintained) list of files changed in this workspace as
    compared to any parent workspace.

    Internally, the WorkList is stored in .hg/cdm/worklist as a list
    of file pathnames, one per-line.

    This may only safely be used as a hint regarding possible
    modifications to the working copy, it should not be relied upon to
    suggest anything about committed changes.'''

    def __init__(self, ws):
        '''Load the WorkList for the specified WorkSpace from disk.'''

        self._ws = ws
        self._repo = ws.repo
        self._file = os.path.join('cdm', 'worklist')
        self._files = set()
        self._valid = False

        if os.path.exists(self._repo.join(self._file)):
            self.load()

    def __nonzero__(self):
        '''A WorkList object is true if it was loaded from disk,
        rather than freshly created.
        '''

        return self._valid

    def list(self):
        '''List of pathnames contained in the WorkList
        '''

        return list(self._files)

    def status(self):
        '''Return the status (in tuple form) of files from the
        WorkList as they are in the working copy
        '''

        match = self._ws.matcher(files=self.list())
        return self._repo.status(match=match)

    def add(self, fname):
        '''Add FNAME to the WorkList.
        '''

        self._files.add(fname)

    def write(self):
        '''Write the WorkList out to disk.
        '''

        dirn = os.path.split(self._file)[0]

        if dirn and not os.path.exists(self._repo.join(dirn)):
            try:
                os.makedirs(self._repo.join(dirn))
            except EnvironmentError, e:
                raise util.Abort("Couldn't create directory %s: %s" %
                                 (self._repo.join(dirn), e))

        fh = self._repo.opener(self._file, 'w', atomictemp=True)

        for name in self._files:
            fh.write("%s\n" % name)

        fh.rename()
        fh.close()

    def load(self):
        '''Read in the WorkList from disk.
        '''

        fh = self._repo.opener(self._file, 'r')
        self._files = set(l.rstrip('\n') for l in fh)
        self._valid = True
        fh.close()

    def delete(self):
        '''Empty the WorkList

        Remove the on-disk WorkList and clear the file-list of the
        in-memory copy
        '''

        if os.path.exists(self._repo.join(self._file)):
            os.unlink(self._repo.join(self._file))

        self._files = set()
        self._valid = False


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
        ret = set(entry.name for entry in self.__active if entry.is_removed())
        ret.update(set(x.parentname for x in self.__active if x.is_renamed()))
        return list(ret)

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

    def parenttip(self, heads, outgoing):
        '''Return the highest-numbered, non-outgoing changeset that is
        an ancestor of a changeset in heads.

        This returns the most recent changeset on a given branch that
        is shared between a parent and child workspace, in effect the
        common ancestor of the chosen local tip and the parent
        workspace.
        '''

        def tipmost_shared(head, outnodes):
            '''Return the changeset on the same branch as head that is
            not in outnodes and is closest to the tip.

            Walk outgoing changesets from head to the bottom of the
            workspace (revision 0) and return the the first changeset
            we see that is not in outnodes.

            If none is found (all revisions >= 0 are outgoing), the
            only possible parenttip is the null node (node.nullid)
            which is returned explicitly.
            '''
            for ctx in self._walkctxs(head, self.repo.changectx(0),
                                      follow=True,
                                      pick=lambda c: c.node() not in outnodes):
                return ctx

            return self.repo.changectx(node.nullid)

        nodes = set(outgoing)
        ptips = map(lambda x: tipmost_shared(x, nodes), heads)
        return sorted(ptips, key=lambda x: x.rev(), reverse=True)[0]

    def status(self, base='.', head=None, files=None):
        '''Translate from the hg 6-tuple status format to a hash keyed
        on change-type'''

        states = ['modified', 'added', 'removed', 'deleted', 'unknown',
                  'ignored']

        match = self.matcher(files=files)
        chngs = self.repo.status(base, head, match=match)

        ret = {}
        for paths, change in zip(chngs, states):
            ret.update((f, change) for f in paths)
        return ret

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
                if Version.at_least("1.6"):
                    return discovery.findoutgoing(self.repo, pws)
                else:
                    return self.repo.findoutgoing(pws)
            except error.RepoError:
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

    def active(self, parent=None, thorough=False):
        '''Return an ActiveList describing changes between workspace
        and parent workspace (including uncommitted changes).
        If the workspace has no parent, ActiveList will still describe any
        uncommitted changes.

        If thorough is True use neither the WorkList nor any cached
        results (though the result of this call will be cached for
        future, non-thorough, calls).'''

        parent = self.parent(parent)

        #
        # Use the cached copy if we can (we have one, and weren't
        # asked to be thorough)
        #
        if not thorough and parent in self.activecache:
            return self.activecache[parent]

        #
        # outbases: The set of outgoing nodes with no outgoing ancestors
        # outnodes: The full set of outgoing nodes
        #
        if parent:
            outbases = self.findoutgoing(parent)
            outnodes = self.repo.changelog.nodesbetween(outbases)[0]
        else:               # No parent, no outgoing nodes
            outbases = []
            outnodes = []

        wctx = self.workingctx(worklist=not thorough)
        localtip = self._localtip(outnodes, wctx)

        if localtip.rev() is None:
            heads = localtip.parents()
        else:
            heads = [localtip]

        parenttip = self.parenttip(heads, outnodes)

        #
        # If we couldn't find a parenttip, the two repositories must
        # be unrelated (Hg catches most of this, but this case is
        # valid for it but invalid for us)
        #
        if parenttip == None:
            raise util.Abort('repository is unrelated')

        headnodes = [h.node() for h in heads]
        ctxs = [self.repo.changectx(n) for n in
                self.repo.changelog.nodesbetween(outbases, headnodes)[0]]

        if localtip.rev() is None:
            ctxs.append(localtip)

        act = ActiveList(self, parenttip, ctxs)
        self.activecache[parent] = act

        return act

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
        # Remove the previous child-local changes by stripping the
        # nodes that form the base of the ActiveList (removing their
        # children in the process).
        #
        try:
            try:
                for base in active.bases():
                    #
                    # Any cached information about the repository is
                    # likely to be invalid during the strip.  The
                    # caching of branch tags is especially
                    # problematic.
                    #
                    self.repo.invalidate()
                    repair.strip(self.ui, self.repo, base.node(), backup=False)
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

    def workingctx(self, worklist=False):
        '''Return a workingctx object representing the working copy.

        If worklist is true, return a workingctx object created based
        on the status of files in the workspace's worklist.'''

        wl = WorkList(self)

        if worklist and wl:
            return context.workingctx(self.repo, changes=wl.status())
        else:
            return self.repo.changectx(None)

    def matcher(self, pats=None, opts=None, files=None):
        '''Return a match object suitable for Mercurial based on
        specified criteria.

        If files is specified it is a list of pathnames relative to
        the repository root to be matched precisely.

        If pats and/or opts are specified, these are as to
        cmdutil.match'''

        of_patterns = pats is not None or opts is not None
        of_files = files is not None
        opts = opts or {}       # must be a dict

        assert not (of_patterns and of_files)

        if of_patterns:
            return cmdutil.match(self.repo, pats, opts)
        elif of_files:
            return cmdutil.matchfiles(self.repo, files)
        else:
            return cmdutil.matchall(self.repo)

    def diff(self, node1=None, node2=None, match=None, opts=None):
        '''Return the diff of changes between two changesets as a string'''

        #
        # Retain compatibility by only calling diffopts() if it
        # obviously has not already been done.
        #
        if isinstance(opts, dict):
            opts = patch.diffopts(self.ui, opts)

        ret = cStringIO.StringIO()
        for chunk in patch.diff(self.repo, node1, node2, match=match,
                                opts=opts):
            ret.write(chunk)

        return ret.getvalue()

    if Version.at_least("1.6"):
        def copy(self, src, dest):
            '''Copy a file from src to dest
            '''

            self.workingctx().copy(src, dest)
    else:
        def copy(self, src, dest):
            '''Copy a file from src to dest
            '''

            self.repo.copy(src, dest)


    if Version.at_least("1.4"):

        def _walkctxs(self, base, head, follow=False, pick=None):
            '''Generate changectxs between BASE and HEAD.

            Walk changesets between BASE and HEAD (in the order implied by
            their relation), following a given branch if FOLLOW is a true
            value, yielding changectxs where PICK (if specified) returns a
            true value.

            PICK is a function of one argument, a changectx.'''

            chosen = {}

            def prep(ctx, fns):
                chosen[ctx.rev()] = not pick or pick(ctx)

            opts = {'rev': ['%s:%s' % (base.rev(), head.rev())],
                    'follow': follow}
            matcher = cmdutil.matchall(self.repo)

            for ctx in cmdutil.walkchangerevs(self.repo, matcher, opts, prep):
                if chosen[ctx.rev()]:
                    yield ctx
    else:

        def _walkctxs(self, base, head, follow=False, pick=None):
            '''Generate changectxs between BASE and HEAD.

            Walk changesets between BASE and HEAD (in the order implied by
            their relation), following a given branch if FOLLOW is a true
            value, yielding changectxs where PICK (if specified) returns a
            true value.

            PICK is a function of one argument, a changectx.'''

            opts = {'rev': ['%s:%s' % (base.rev(), head.rev())],
                    'follow': follow}

            changectx = self.repo.changectx
            getcset = util.cachefunc(lambda r: changectx(r).changeset())

            #
            # See the docstring of mercurial.cmdutil.walkchangerevs() for
            # the phased approach to the iterator returned.  The important
            # part to note is that the 'add' phase gathers nodes, which
            # the 'iter' phase then iterates through.
            #
            changeiter = cmdutil.walkchangerevs(self.ui, self.repo,
                                                [], getcset, opts)[0]

            matched = {}
            for st, rev, fns in changeiter:
                if st == 'add':
                    ctx = changectx(rev)
                    if not pick or pick(ctx):
                        matched[rev] = ctx
                elif st == 'iter':
                    if rev in matched:
                        yield matched[rev]
