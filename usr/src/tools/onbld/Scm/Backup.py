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
# Copyright 2008, 2011, Richard Lowe
#


'''
Workspace backup

Backup format is:
   backupdir/
      wsname/
         generation#/
            dirstate (handled by CdmUncommittedBackup)
                File containing dirstate nodeid (the changeset we need
                to update the workspace to after applying the bundle).
                This is the node to which the working copy changes
                (see 'diff', below) will be applied if applicable.

            bundle (handled by CdmCommittedBackup)
                An Hg bundle containing outgoing committed changes.

            nodes (handled by CdmCommittedBackup)
                A text file listing the full (hex) nodeid of all nodes in
                bundle, used by need_backup.

            diff (handled by CdmUncommittedBackup)
                A Git-formatted diff containing uncommitted changes.

            renames (handled by CdmUncommittedBackup)
                A list of renames in the working copy that have to be
                applied manually, rather than by the diff.

            metadata.tar.gz (handled by CdmMetadataBackup)
                $CODEMGR_WS/.hg/hgrc
                $CODEMGR_WS/.hg/localtags
                $CODEMGR_WS/.hg/patches (Mq data)

            clear.tar.gz (handled by CdmClearBackup)
                <short node>/
                    copies of each modified or added file, as it is in
                    this head.

                 ... for each outgoing head

                working/
                     copies of each modified or added file in the
                     working copy if any.

         latest -> generation#
            Newest backup generation.

All files in a given backup generation, with the exception of
dirstate, are optional.
'''

import grp, os, pwd, shutil, tarfile, time, traceback
from cStringIO import StringIO

from mercurial import changegroup, cmdutil, error, node, patch, util
from onbld.Scm import Version


class CdmNodeMissing(util.Abort):
    '''a required node is not present in the destination workspace.

    This may occur both in the case where the bundle contains a
    changeset which is a child of a node not present in the
    destination workspace (because the destination workspace is not as
    up-to-date as the source), or because the source and destination
    workspace are not related.

    It may also happen in cases where the uncommitted changes need to
    be applied onto a node that the workspace does not possess even
    after application of the bundle (on a branch not present
    in the bundle or destination workspace, for instance)'''

    def __init__(self, msg, name):
        #
        # If e.name is a string 20 characters long, it is
        # assumed to be a node.  (Mercurial makes this
        # same assumption, when creating a LookupError)
        #
        if isinstance(name, str) and len(name) == 20:
            n = node.short(name)
        else:
            n = name

        util.Abort.__init__(self, "%s: changeset '%s' is missing\n"
                            "Your workspace is either not "
                            "sufficiently up to date,\n"
                            "or is unrelated to the workspace from "
                            "which the backup was taken.\n" % (msg, n))


class CdmTarFile(tarfile.TarFile):
    '''Tar file access + simple comparison to the filesystem, and
    creation addition of files from Mercurial filectx objects.'''

    def __init__(self, *args, **kwargs):
        tarfile.TarFile.__init__(self, *args, **kwargs)
        self.errorlevel = 2

    def members_match_fs(self, rootpath):
        '''Compare the contents of the tar archive to the directory
        specified by rootpath.  Return False if they differ.

        Every file in the archive must match the equivalent file in
        the filesystem.

        The existence, modification time, and size of each file are
        compared, content is not.'''

        def _member_matches_fs(member, rootpath):
            '''Compare a single member to its filesystem counterpart'''
            fpath = os.path.join(rootpath, member.name)

            if not os.path.exists(fpath):
                return False
            elif ((os.path.isfile(fpath) != member.isfile()) or
                  (os.path.isdir(fpath) != member.isdir()) or
                  (os.path.islink(fpath) != member.issym())):
                return False

            #
            # The filesystem may return a modification time with a
            # fractional component (as a float), whereas the tar format
            # only stores it to the whole second, perform the comparison
            # using integers (truncated, not rounded)
            #
            elif member.mtime != int(os.path.getmtime(fpath)):
                return False
            elif not member.isdir() and member.size != os.path.getsize(fpath):
                return False
            else:
                return True

        for elt in self:
            if not _member_matches_fs(elt, rootpath):
                return False

        return True

    def addfilectx(self, filectx, path=None):
        '''Add a filectx object to the archive.

        Use the path specified by the filectx object or, if specified,
        the PATH argument.

        The size, modification time, type and permissions of the tar
        member are taken from the filectx object, user and group id
        are those of the invoking user, user and group name are those
        of the invoking user if information is available, or "unknown"
        if it is not.
        '''

        t = tarfile.TarInfo(path or filectx.path())
        t.size = filectx.size()
        t.mtime = filectx.date()[0]
        t.uid = os.getuid()
        t.gid = os.getgid()

        try:
            t.uname = pwd.getpwuid(t.uid).pw_name
        except KeyError:
            t.uname = "unknown"

        try:
            t.gname = grp.getgrgid(t.gid).gr_name
        except KeyError:
            t.gname = "unknown"

        #
        # Mercurial versions symlinks by setting a flag and storing
        # the destination path in place of the file content.  The
        # actual contents (in the tar), should be empty.
        #
        if 'l' in filectx.flags():
            t.type = tarfile.SYMTYPE
            t.mode = 0777
            t.linkname = filectx.data()
            data = None
        else:
            t.type = tarfile.REGTYPE
            t.mode = 'x' in filectx.flags() and 0755 or 0644
            data = StringIO(filectx.data())

        self.addfile(t, data)


class CdmCommittedBackup(object):
    '''Backup of committed changes'''

    def __init__(self, backup, ws):
        self.ws = ws
        self.bu = backup
        self.files = ('bundle', 'nodes')

    def _outgoing_nodes(self, parent):
        '''Return a list of all outgoing nodes in hex format'''

        if parent:
            outgoing = self.ws.findoutgoing(parent)
            nodes = self.ws.repo.changelog.nodesbetween(outgoing)[0]
            return map(node.hex, nodes)
        else:
            return []

    def backup(self):
        '''Backup committed changes'''
        parent = self.ws.parent()

        if not parent:
            self.ws.ui.warn('Workspace has no parent, committed changes will '
                            'not be backed up\n')
            return

        out = self.ws.findoutgoing(parent)
        if not out:
            return

        cg = self.ws.repo.changegroup(out, 'bundle')
        changegroup.writebundle(cg, self.bu.backupfile('bundle'), 'HG10BZ')

        outnodes = self._outgoing_nodes(parent)
        if not outnodes:
            return

        fp = None
        try:
            try:
                fp = self.bu.open('nodes', 'w')
                fp.write('%s\n' % '\n'.join(outnodes))
            except EnvironmentError, e:
                raise util.Abort("couldn't store outgoing nodes: %s" % e)
        finally:
            if fp and not fp.closed:
                fp.close()

    def restore(self):
        '''Restore committed changes from backup'''

        if not self.bu.exists('bundle'):
            return

        bpath = self.bu.backupfile('bundle')
        f = None
        try:
            try:
                f = self.bu.open('bundle')
                bundle = changegroup.readbundle(f, bpath)
                self.ws.repo.addchangegroup(bundle, 'strip',
                                            'bundle:%s' % bpath)
            except EnvironmentError, e:
                raise util.Abort("couldn't restore committed changes: %s\n"
                                 "   %s" % (bpath, e))
            except error.LookupError, e:
                raise CdmNodeMissing("couldn't restore committed changes",
                                                 e.name)
        finally:
            if f and not f.closed:
                f.close()

    def need_backup(self):
        '''Compare backup of committed changes to workspace'''

        if self.bu.exists('nodes'):
            f = None
            try:
                try:
                    f = self.bu.open('nodes')
                    bnodes = set(line.rstrip('\r\n') for line in f.readlines())
                    f.close()
                except EnvironmentError, e:
                    raise util.Abort("couldn't open backup node list: %s" % e)
            finally:
                if f and not f.closed:
                    f.close()
        else:
            bnodes = set()

        outnodes = set(self._outgoing_nodes(self.ws.parent()))

        #
        # If there are outgoing nodes not in the prior backup we need
        # to take a new backup; it's fine if there are nodes in the
        # old backup which are no longer outgoing, however.
        #
        if not outnodes <= bnodes:
            return True

        return False

    def cleanup(self):
        '''Remove backed up committed changes'''

        for f in self.files:
            self.bu.unlink(f)


class CdmUncommittedBackup(object):
    '''Backup of uncommitted changes'''

    def __init__(self, backup, ws):
        self.ws = ws
        self.bu = backup
        self.wctx = self.ws.workingctx(worklist=True)

    def _clobbering_renames(self):
        '''Return a list of pairs of files representing renames/copies
        that clobber already versioned files.  [(old-name new-name)...]
        '''

        #
        # Note that this doesn't handle uncommitted merges
        # as CdmUncommittedBackup itself doesn't.
        #
        parent = self.wctx.parents()[0]

        ret = []
        for fname in self.wctx.added() + self.wctx.modified():
            rn = self.wctx.filectx(fname).renamed()
            if rn and fname in parent:
                ret.append((rn[0], fname))
        return ret

    def backup(self):
        '''Backup uncommitted changes'''

        if self.ws.merged():
            raise util.Abort("Unable to backup an uncommitted merge.\n"
                             "Please complete your merge and commit")

        dirstate = node.hex(self.wctx.parents()[0].node())

        fp = None
        try:
            try:
                fp = self.bu.open('dirstate', 'w')
                fp.write(dirstate + '\n')
                fp.close()
            except EnvironmentError, e:
                raise util.Abort("couldn't save working copy parent: %s" % e)

            try:
                fp = self.bu.open('renames', 'w')
                for cons in self._clobbering_renames():
                    fp.write("%s %s\n" % cons)
                fp.close()
            except EnvironmentError, e:
                raise util.Abort("couldn't save clobbering copies: %s" % e)

            try:
                fp = self.bu.open('diff', 'w')
                match = self.ws.matcher(files=self.wctx.files())
                fp.write(self.ws.diff(opts={'git': True}, match=match))
            except EnvironmentError, e:
                raise util.Abort("couldn't save working copy diff: %s" % e)
        finally:
            if fp and not fp.closed:
                fp.close()

    def _dirstate(self):
        '''Return the desired working copy node from the backup'''
        fp = None
        try:
            try:
                fp = self.bu.open('dirstate')
                dirstate = fp.readline().strip()
            except EnvironmentError, e:
                raise util.Abort("couldn't read saved parent: %s" % e)
        finally:
            if fp and not fp.closed:
                fp.close()

        return dirstate

    def restore(self):
        '''Restore uncommitted changes'''
        dirstate = self._dirstate()

        #
        # Check that the patch's parent changeset exists.
        #
        try:
            n = node.bin(dirstate)
            self.ws.repo.changelog.lookup(n)
        except error.LookupError, e:
            raise CdmNodeMissing("couldn't restore uncommitted changes",
                                 e.name)

        try:
            self.ws.clean(rev=dirstate)
        except util.Abort, e:
            raise util.Abort("couldn't update to saved node: %s" % e)

        if not self.bu.exists('diff'):
            return

        #
        # There's a race here whereby if the patch (or part thereof)
        # is applied within the same second as the clean above (such
        # that modification time doesn't change) and if the size of
        # that file does not change, Hg may not see the change.
        #
        # We sleep a full second to avoid this, as sleeping merely
        # until the next second begins would require very close clock
        # synchronization on network filesystems.
        #
        time.sleep(1)

        files = {}
        try:
            diff = self.bu.backupfile('diff')
            try:
                fuzz = patch.patch(diff, self.ws.ui, strip=1,
                                   cwd=self.ws.repo.root, files=files)
                if fuzz:
                    raise util.Abort('working copy diff applied with fuzz')
            except Exception, e:
                raise util.Abort("couldn't apply working copy diff: %s\n"
                                 "   %s" % (diff, e))
        finally:
            if Version.at_least("1.7"):
                cmdutil.updatedir(self.ws.ui, self.ws.repo, files)
            else:
                patch.updatedir(self.ws.ui, self.ws.repo, files)

        if not self.bu.exists('renames'):
            return

        #
        # We need to re-apply name changes where the new name
        # (rename/copy destination) is an already versioned file, as
        # Hg would otherwise ignore them.
        #
        try:
            fp = self.bu.open('renames')
            for line in fp:
                source, dest = line.strip().split()
                self.ws.copy(source, dest)
        except EnvironmentError, e:
            raise util.Abort('unable to open renames file: %s' % e)
        except ValueError:
            raise util.Abort('corrupt renames file: %s' %
                             self.bu.backupfile('renames'))

    def need_backup(self):
        '''Compare backup of uncommitted changes to workspace'''
        cnode = self.wctx.parents()[0].node()
        if self._dirstate() != node.hex(cnode):
            return True

        fd = None
        match = self.ws.matcher(files=self.wctx.files())
        curdiff = self.ws.diff(opts={'git': True}, match=match)

        try:
            if self.bu.exists('diff'):
                try:
                    fd = self.bu.open('diff')
                    backdiff = fd.read()
                    fd.close()
                except EnvironmentError, e:
                    raise util.Abort("couldn't open backup diff %s\n"
                                     "   %s" % (self.bu.backupfile('diff'), e))
            else:
                backdiff = ''

            if backdiff != curdiff:
                return True

            currrenamed = self._clobbering_renames()
            bakrenamed = None

            if self.bu.exists('renames'):
                try:
                    fd = self.bu.open('renames')
                    bakrenamed = [tuple(line.strip().split(' ')) for line in fd]
                    fd.close()
                except EnvironmentError, e:
                    raise util.Abort("couldn't open renames file %s: %s\n" %
                                     (self.bu.backupfile('renames'), e))

            if currrenamed != bakrenamed:
                return True
        finally:
            if fd and not fd.closed:
                fd.close()

        return False

    def cleanup(self):
        '''Remove backed up uncommitted changes'''

        for f in ('dirstate', 'diff', 'renames'):
            self.bu.unlink(f)


class CdmMetadataBackup(object):
    '''Backup of workspace metadata'''

    def __init__(self, backup, ws):
        self.bu = backup
        self.ws = ws
        self.files = ('hgrc', 'localtags', 'patches', 'cdm')

    def backup(self):
        '''Backup workspace metadata'''

        tarpath = self.bu.backupfile('metadata.tar.gz')

        #
        # Files is a list of tuples (name, path), where name is as in
        # self.files, and path is the absolute path.
        #
        files = filter(lambda (name, path): os.path.exists(path),
                       zip(self.files, map(self.ws.repo.join, self.files)))

        if not files:
            return

        try:
            tar = CdmTarFile.gzopen(tarpath, 'w')
        except (EnvironmentError, tarfile.TarError), e:
            raise util.Abort("couldn't open %s for writing: %s" %
                             (tarpath, e))

        try:
            for name, path in files:
                try:
                    tar.add(path, name)
                except (EnvironmentError, tarfile.TarError), e:
                    #
                    # tarfile.TarError doesn't include the tar member or file
                    # in question, so we have to do so ourselves.
                    #
                    if isinstance(e, tarfile.TarError):
                        errstr = "%s: %s" % (name, e)
                    else:
                        errstr = str(e)

                    raise util.Abort("couldn't backup metadata to %s:\n"
                                     "  %s" % (tarpath, errstr))
        finally:
            tar.close()

    def old_restore(self):
        '''Restore workspace metadata from an pre-tar backup'''

        for fname in self.files:
            if self.bu.exists(fname):
                bfile = self.bu.backupfile(fname)
                wfile = self.ws.repo.join(fname)

                try:
                    shutil.copy2(bfile, wfile)
                except EnvironmentError, e:
                    raise util.Abort("couldn't restore metadata from %s:\n"
                                     "   %s" % (bfile, e))

    def tar_restore(self):
        '''Restore workspace metadata (from a tar-style backup)'''

        if not self.bu.exists('metadata.tar.gz'):
            return

        tarpath = self.bu.backupfile('metadata.tar.gz')

        try:
            tar = CdmTarFile.gzopen(tarpath)
        except (EnvironmentError, tarfile.TarError), e:
            raise util.Abort("couldn't open %s: %s" % (tarpath, e))

        try:
            for elt in tar:
                try:
                    tar.extract(elt, path=self.ws.repo.path)
                except (EnvironmentError, tarfile.TarError), e:
                    # Make sure the member name is in the exception message.
                    if isinstance(e, tarfile.TarError):
                        errstr = "%s: %s" % (elt.name, e)
                    else:
                        errstr = str(e)

                    raise util.Abort("couldn't restore metadata from %s:\n"
                                     "   %s" %
                                     (tarpath, errstr))
        finally:
            if tar and not tar.closed:
                tar.close()

    def restore(self):
        '''Restore workspace metadata'''

        if self.bu.exists('hgrc'):
            self.old_restore()
        else:
            self.tar_restore()

    def _walk(self):
        '''Yield the repo-relative path to each file we operate on,
        including each file within any affected directory'''

        for elt in self.files:
            path = self.ws.repo.join(elt)

            if not os.path.exists(path):
                continue

            if os.path.isdir(path):
                for root, dirs, files in os.walk(path, topdown=True):
                    yield root

                    for f in files:
                        yield os.path.join(root, f)
            else:
                yield path

    def need_backup(self):
        '''Compare backed up workspace metadata to workspace'''

        def strip_trailing_pathsep(pathname):
            '''Remove a possible trailing path separator from PATHNAME'''
            return pathname.endswith('/') and pathname[:-1] or pathname

        if self.bu.exists('metadata.tar.gz'):
            tarpath = self.bu.backupfile('metadata.tar.gz')
            try:
                tar = CdmTarFile.gzopen(tarpath)
            except (EnvironmentError, tarfile.TarError), e:
                raise util.Abort("couldn't open metadata tarball: %s\n"
                                 "   %s" % (tarpath, e))

            if not tar.members_match_fs(self.ws.repo.path):
                tar.close()
                return True

            tarnames = map(strip_trailing_pathsep, tar.getnames())
            tar.close()
        else:
            tarnames = []

        repopath = self.ws.repo.path
        if not repopath.endswith('/'):
            repopath += '/'

        for path in self._walk():
            if path.replace(repopath, '', 1) not in tarnames:
                return True

        return False

    def cleanup(self):
        '''Remove backed up workspace metadata'''
        self.bu.unlink('metadata.tar.gz')


class CdmClearBackup(object):
    '''A backup (in tar format) of complete source files from every
    workspace head.

    Paths in the tarball are prefixed by the revision and node of the
    head, or "working" for the working directory.

    This is done purely for the benefit of the user, and as such takes
    no part in restore or need_backup checking, restore always
    succeeds, need_backup always returns False
    '''

    def __init__(self, backup, ws):
        self.bu = backup
        self.ws = ws

    def _branch_pairs(self):
        '''Return a list of tuples (parenttip, localtip) for each
        outgoing head.  If the working copy contains modified files,
        it is a head, and neither of its parents are.
        '''

        parent = self.ws.parent()

        if parent:
            outgoing = self.ws.findoutgoing(parent)
            outnodes = set(self.ws.repo.changelog.nodesbetween(outgoing)[0])

            heads = [self.ws.repo.changectx(n) for n in self.ws.repo.heads()
                     if n in outnodes]
        else:
            heads = []
            outnodes = []

        wctx = self.ws.workingctx()
        if wctx.files():        # We only care about file changes.
            heads = filter(lambda x: x not in wctx.parents(), heads) + [wctx]

        pairs = []
        for head in heads:
            if head.rev() is None:
                c = head.parents()
            else:
                c = [head]

            pairs.append((self.ws.parenttip(c, outnodes), head))
        return pairs

    def backup(self):
        '''Save a clear copy of each source file modified between each
        head and that head's parenttip (see WorkSpace.parenttip).
        '''

        tarpath = self.bu.backupfile('clear.tar.gz')
        branches = self._branch_pairs()

        if not branches:
            return

        try:
            tar = CdmTarFile.gzopen(tarpath, 'w')
        except (EnvironmentError, tarfile.TarError), e:
            raise util.Abort("Could not open %s for writing: %s" %
                             (tarpath, e))

        try:
            for parent, child in branches:
                tpath = child.node() and node.short(child.node()) or "working"

                for fname, change in self.ws.status(parent, child).iteritems():
                    if change not in ('added', 'modified'):
                        continue

                    try:
                        tar.addfilectx(child.filectx(fname),
                                       os.path.join(tpath, fname))
                    except ValueError, e:
                        crev = child.rev()
                        if crev is None:
                            crev = "working copy"
                        raise util.Abort("Could not backup clear file %s "
                                         "from %s: %s\n" % (fname, crev, e))
        finally:
            tar.close()

    def cleanup(self):
        '''Cleanup a failed Clear backup.

        Remove the clear tarball from the backup directory.
        '''

        self.bu.unlink('clear.tar.gz')

    def restore(self):
        '''Clear backups are never restored, do nothing'''
        pass

    def need_backup(self):
        '''Clear backups are never compared, return False (no backup needed).

        Should a backup actually be needed, one of the other
        implementation classes would notice in any situation we would.
        '''

        return False


class CdmBackup(object):
    '''A backup of a given workspace'''

    def __init__(self, ui, ws, name):
        self.ws = ws
        self.ui = ui
        self.backupdir = self._find_backup_dir(name)

        #
        # The order of instances here controls the order the various operations
        # are run.
        #
        # There's some inherent dependence, in that on restore we need
        # to restore committed changes prior to uncommitted changes
        # (as the parent revision of any uncommitted changes is quite
        # likely to not exist until committed changes are restored).
        # Metadata restore can happen at any point, but happens last
        # as a matter of convention.
        #
        self.modules = [x(self, ws) for x in [CdmCommittedBackup,
                                              CdmUncommittedBackup,
                                              CdmClearBackup,
                                              CdmMetadataBackup]]

        if os.path.exists(os.path.join(self.backupdir, 'latest')):
            generation = os.readlink(os.path.join(self.backupdir, 'latest'))
            self.generation = int(os.path.split(generation)[1])
        else:
            self.generation = 0

    def _find_backup_dir(self, name):
        '''Find the path to an appropriate backup directory based on NAME'''

        if os.path.isabs(name):
            return name

        if self.ui.config('cdm', 'backupdir'):
            backupbase = os.path.expanduser(self.ui.config('cdm', 'backupdir'))
        else:
            home = None

            try:
                home = os.getenv('HOME') or pwd.getpwuid(os.getuid()).pw_dir
            except KeyError:
                pass                    # Handled anyway

            if not home:
                raise util.Abort('Could not determine your HOME directory to '
                                 'find backup path')

            backupbase = os.path.join(home, 'cdm.backup')

        backupdir = os.path.join(backupbase, name)

        # If backupdir exists, it must be a directory.
        if (os.path.exists(backupdir) and not os.path.isdir(backupdir)):
            raise util.Abort('%s exists but is not a directory' % backupdir)

        return backupdir

    def _update_latest(self, gen):
        '''Update latest symlink to point to the current generation'''
        linkpath = os.path.join(self.backupdir, 'latest')

        if os.path.lexists(linkpath):
            os.unlink(linkpath)

        os.symlink(str(gen), linkpath)

    def _create_gen(self, gen):
        '''Create a new backup generation'''
        try:
            os.makedirs(os.path.join(self.backupdir, str(gen)))
            self._update_latest(gen)
        except EnvironmentError, e:
            raise util.Abort("Couldn't create backup generation %s: %s" %
                             (os.path.join(self.backupdir, str(gen)), e))

    def backupfile(self, path):
        '''return full path to backup file FILE at GEN'''
        return os.path.join(self.backupdir, str(self.generation), path)

    def unlink(self, name):
        '''Unlink the specified path from the backup directory.
        A no-op if the path does not exist.
        '''

        fpath = self.backupfile(name)
        if os.path.exists(fpath):
            os.unlink(fpath)

    def open(self, name, mode='r'):
        '''Open the specified file in the backup directory'''
        return open(self.backupfile(name), mode)

    def exists(self, name):
        '''Return boolean indicating wether a given file exists in the
        backup directory.'''
        return os.path.exists(self.backupfile(name))

    def need_backup(self):
        '''Compare backed up changes to workspace'''
        #
        # If there's no current backup generation, or the last backup was
        # invalid (lacking the dirstate file), we need a backup regardless
        # of anything else.
        #
        if not self.generation or not self.exists('dirstate'):
            return True

        for x in self.modules:
            if x.need_backup():
                return True

        return False

    def backup(self):
        '''Take a backup of the current workspace

        Calling code is expected to hold both the working copy lock
        and repository lock.'''

        if not os.path.exists(self.backupdir):
            try:
                os.makedirs(self.backupdir)
            except EnvironmentError, e:
                raise util.Abort('Could not create backup directory %s: %s' %
                                 (self.backupdir, e))

        self.generation += 1
        self._create_gen(self.generation)

        try:
            for x in self.modules:
                x.backup()
        except Exception, e:
            if isinstance(e, KeyboardInterrupt):
                self.ws.ui.warn("Interrupted\n")
            else:
                self.ws.ui.warn("Error: %s\n" % e)
                show_traceback = self.ws.ui.configbool('ui', 'traceback',
                                                       False)

                #
                # If it's not a 'normal' error, we want to print a stack
                # trace now in case the attempt to remove the partial
                # backup also fails, and raises a second exception.
                #
                if (not isinstance(e, (EnvironmentError, util.Abort))
                    or show_traceback):
                    traceback.print_exc()

            for x in self.modules:
                x.cleanup()

            os.rmdir(os.path.join(self.backupdir, str(self.generation)))
            self.generation -= 1

            if self.generation != 0:
                self._update_latest(self.generation)
            else:
                os.unlink(os.path.join(self.backupdir, 'latest'))

            raise util.Abort('Backup failed')

    def restore(self, gen=None):
        '''Restore workspace from backup

        Restores from backup generation GEN (defaulting to the latest)
        into workspace WS.

        Calling code is expected to hold both the working copy lock
        and repository lock of the destination workspace.'''

        if not os.path.exists(self.backupdir):
            raise util.Abort('Backup directory does not exist: %s' %
                             (self.backupdir))

        if gen:
            if not os.path.exists(os.path.join(self.backupdir, str(gen))):
                raise util.Abort('Backup generation does not exist: %s' %
                                 (os.path.join(self.backupdir, str(gen))))
            self.generation = int(gen)

        if not self.generation: # This is OK, 0 is not a valid generation
            raise util.Abort('Backup has no generations: %s' % self.backupdir)

        if not self.exists('dirstate'):
            raise util.Abort('Backup %s/%s is incomplete (dirstate missing)' %
                             (self.backupdir, self.generation))

        try:
            for x in self.modules:
                x.restore()
        except util.Abort, e:
            raise util.Abort('Error restoring workspace:\n'
                             '%s\n'
                             'Workspace may be partially restored' % e)
