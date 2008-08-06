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

'''
Workspace backup

Backup format is:
   backupdir/
      wsname/
         generation#/
            dirstate (handled by CdmUncommittedBackup)
                File containing dirstate nodeid (the tip we expect to be at
                after applying the bundle).

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

         latest -> generation#
            Newest backup generation.

All files in a given backup generation, with the exception of
dirstate, are optional.
'''

import os, pwd, shutil, traceback, tarfile, time
from mercurial import changegroup, patch, node, util
from cStringIO import StringIO


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
        if outnodes:
            fp = None
            try:
                try:
                    fp = open(self.bu.backupfile('nodes'), 'w')
                    fp.write('%s\n' % '\n'.join(outnodes))
                except EnvironmentError, e:
                    raise util.Abort("couldn't store outgoing nodes: %s" % e)
            finally:
                if fp and not fp.closed:
                    fp.close()

    def restore(self):
        '''Restore committed changes from backup'''
        bfile = self.bu.backupfile('bundle')

        if os.path.exists(bfile):
            f = None
            try:
                try:
                    f = open(bfile, 'r')
                    bundle = changegroup.readbundle(f, bfile)
                    self.ws.repo.addchangegroup(bundle, 'strip',
                                                'bundle:%s' % bfile)
                except EnvironmentError, e:
                    raise util.Abort("couldn't restore committed changes: %s\n"
                                     "   %s" % (bfile, e))
            finally:
                if f and not f.closed:
                    f.close()

    def need_backup(self):
        '''Compare backup of committed changes to workspace'''

        if os.path.exists(self.bu.backupfile('nodes')):
            f = None
            try:
                try:
                    f = open(self.bu.backupfile('nodes'))
                    bnodes = set([line.rstrip('\r\n')
                                  for line in f.readlines()])
                    f.close()
                except EnvironmentError, e:
                    raise util.Abort("couldn't open backup node list: %s" % e)
            finally:
                if f and not f.closed:
                    f.close()
        else:
            bnodes = set()

        outnodes = set(self._outgoing_nodes(self.ws.parent()))
        if outnodes != bnodes:
            return True

        return False

    def cleanup(self):
        '''Remove backed up committed changes'''

        for fname in self.files:
            if os.path.exists(self.bu.backupfile(fname)):
                os.unlink(self.bu.backupfile(fname))


class CdmUncommittedBackup(object):
    '''Backup of uncommitted changes'''

    def __init__(self, backup, ws):
        self.ws = ws
        self.bu = backup

    def _clobbering_renames(self):
        '''Return a list of pairs of files representing renames/copies
        that clobber already versioned files.  [(oldname newname)...]'''

        #
        # Note that this doesn't handle uncommitted merges
        # as CdmUncommittedBackup itself doesn't.
        #
        wctx = self.ws.repo.workingctx()
        parent = wctx.parents()[0]

        ret = []
        for fname in wctx.added() + wctx.modified():
            rn = wctx.filectx(fname).renamed()
            if rn and fname in parent:
                ret.append((rn[0], fname))
        return ret

    def backup(self):
        '''Backup uncommitted changes'''

        if self.ws.merged():
            raise util.Abort("Unable to backup an uncommitted merge.\n"
                             "Please complete your merge and commit")

        dirstate = node.hex(self.ws.repo.changectx().node())

        fp = None
        try:
            try:
                fp = open(self.bu.backupfile('dirstate'), 'w')
                fp.write(dirstate + '\n')
            except EnvironmentError, e:
                raise util.Abort("couldn't save working copy parent: %s" % e)
        finally:
            if fp and not fp.closed:
                fp.close()

        try:
            try:
                fp = open(self.bu.backupfile('renames'), 'w')
                for cons in self._clobbering_renames():
                    fp.write("%s %s\n" % cons)
            except EnvironmentError, e:
                raise util.Abort("couldn't save clobbering copies: %s" % e)
        finally:
            if fp and not fp.closed:
                fp.close()

        try:
            try:
                fp = open(self.bu.backupfile('diff'), 'w')
                patch.diff(self.ws.repo, fp=fp,
                           opts=patch.diffopts(self.ws.ui, opts={'git': True}))
            except EnvironmentError, e:
                raise util.Abort("couldn't save working copy diff: %s" % e)
        finally:
            if fp and not fp.closed:
                fp.close()

    def _dirstate(self):
        '''Return the current working copy node'''
        fp = None
        try:
            try:
                fp = open(self.bu.backupfile('dirstate'))
                dirstate = fp.readline().strip()
                return dirstate
            except EnvironmentError, e:
                raise util.Abort("couldn't read saved parent: %s" % e)
        finally:
            if fp and not fp.closed:
                fp.close()

    def restore(self):
        '''Restore uncommitted changes'''
        diff = self.bu.backupfile('diff')
        dirstate = self._dirstate()

        try:
            self.ws.clean(rev=dirstate)
        except util.Abort, e:
            raise util.Abort("couldn't update to saved node: %s" % e)

        if not os.path.exists(diff):
            return

        #
        # There's a race here whereby if the patch (or part thereof)
        # is applied within the same second as the clean above (such
        # that mtime doesn't change) and if the size of that file
        # does not change, Hg may not see the change.
        #
        # We sleep a full second to avoid this, as sleeping merely
        # until the next second begins would require very close clock
        # synchronization on network filesystems.
        #
        time.sleep(1)

        files = {}
        try:
            try:
                fuzz = patch.patch(diff, self.ws.ui, strip=1,
                                   cwd=self.ws.repo.root, files=files)
                if fuzz:
                    raise util.Abort('working copy diff applied with fuzz')
            except Exception, e:
                raise util.Abort("couldn't apply working copy diff: %s\n"
                                 "   %s" % (diff, e))
        finally:
            patch.updatedir(self.ws.ui, self.ws.repo, files)

        if not os.path.exists(self.bu.backupfile('renames')):
            return

        #
        # We need to re-apply name changes where the new name
        # (rename/copy destination) is an already versioned file, as
        # Hg would otherwise ignore them.
        #
        try:
            fp = open(self.bu.backupfile('renames'))
            for line in fp:
                source, dest = line.strip().split()
                self.ws.repo.copy(source, dest)
        except EnvironmentError, e:
            raise util.Abort('unable to open renames file: %s' % e)
        except ValueError:
            raise util.Abort('corrupt renames file: %s' %
                             self.bu.backupfile('renames'))

    def need_backup(self):
        '''Compare backup of uncommitted changes to workspace'''
        if self._dirstate() != node.hex(self.ws.repo.changectx().node()):
            return True

        curdiff = StringIO()
        diff = self.bu.backupfile('diff')
        fd = None

        patch.diff(self.ws.repo, fp=curdiff,
                   opts=patch.diffopts(self.ws.ui, opts={'git': True}))

        if os.path.exists(diff):
            try:
                try:
                    fd = open(diff)
                    backdiff = fd.read()
                except EnvironmentError, e:
                    raise util.Abort("couldn't open backup diff %s\n"
                                     "   %s" % (diff, e))
            finally:
                if fd and not fd.closed:
                    fd.close()
        else:
            backdiff = ''

        if backdiff != curdiff.getvalue():
            return True


        currrenamed = self._clobbering_renames()
        bakrenamed = None

        if os.path.exists(self.bu.backupfile('renames')):
            try:
                try:
                    fd = open(self.bu.backupfile('renames'))
                    bakrenamed = [line.strip().split(' ') for line in fd]
                except EnvironmentError, e:
                    raise util.Abort("couldn't open renames file %s: %s\n" %
                                     (self.bu.backupfile('renames'), e))
            finally:
                if fd and not fd.closed:
                    fd.close()

            if currrenamed != bakrenamed:
                return True

        return False

    def cleanup(self):
        '''Remove backed up uncommitted changes'''
        for fname in ('dirstate', 'diff', 'renames'):
            if os.path.exists(self.bu.backupfile(fname)):
                os.unlink(self.bu.backupfile(fname))


class CdmMetadataBackup(object):
    '''Backup of workspace metadata'''

    def __init__(self, backup, ws):
        self.bu = backup
        self.ws = ws
        self.files = ('hgrc', 'localtags', 'patches', 'cdm')

    def backup(self):
        '''Backup workspace metadata'''

        tar = None

        try:
            try:
                tar = tarfile.open(self.bu.backupfile('metadata.tar.gz'),
                                   'w:gz')
                tar.errorlevel = 2
            except (EnvironmentError, tarfile.TarError), e:
                raise util.Abort("couldn't open %s for writing: %s" %
                                 (self.bu.backupfile('metadata.tar.gz'), e))

            try:
                for elt in self.files:
                    fpath = self.ws.repo.join(elt)
                    if os.path.exists(fpath):
                        tar.add(fpath, elt)
            except (EnvironmentError, tarfile.TarError), e:
                #
                # tarfile.TarError doesn't include the tar member or file
                # in question, so we have to do so ourselves.
                #
                if isinstance(e, tarfile.TarError):
                    error = "%s: %s" % (elt, e)
                else:
                    error = str(e)

                raise util.Abort("couldn't backup metadata to %s:\n"
                                 "  %s" %
                                 (self.bu.backupfile('metadata.tar.gz'),
                                  error))
        finally:
            if tar and not tar.closed:
                tar.close()

    def old_restore(self):
        '''Restore workspace metadata from an pre-tar backup'''

        for fname in self.files:
            bfile = self.bu.backupfile(fname)
            wfile = self.ws.repo.join(fname)

            if os.path.exists(bfile):
                try:
                    shutil.copy2(bfile, wfile)
                except EnvironmentError, e:
                    raise util.Abort("couldn't restore metadata from %s:\n"
                                     "   %s" % (bfile, e))

    def tar_restore(self):
        '''Restore workspace metadata (from a tar-style backup)'''

        if os.path.exists(self.bu.backupfile('metadata.tar.gz')):
            tar = None

            try:
                try:
                    tar = tarfile.open(self.bu.backupfile('metadata.tar.gz'))
                    tar.errorlevel = 2
                except (EnvironmentError, tarfile.TarError), e:
                    raise util.Abort("couldn't open %s: %s" %
                                 (self.bu.backupfile('metadata.tar.gz'), e))

                try:
                    for elt in tar:
                        tar.extract(elt, path=self.ws.repo.path)
                except (EnvironmentError, tarfile.TarError), e:
                    # Make sure the member name is in the exception message.
                    if isinstance(e, tarfile.TarError):
                        error = "%s: %s" % (elt.name, e)
                    else:
                        error = str(e)

                    raise util.Abort("couldn't restore metadata from %s:\n"
                                     "   %s" %
                                     (self.bu.backupfile('metadata.tar.gz'),
                                      error))
            finally:
                if tar and not tar.closed:
                    tar.close()

    def restore(self):
        '''Restore workspace metadata'''

        if os.path.exists(self.bu.backupfile('hgrc')):
            self.old_restore()
        else:
            self.tar_restore()

    def need_backup(self):
        '''Compare backed up workspace metadata to workspace'''

        if os.path.exists(self.bu.backupfile('metadata.tar.gz')):
            try:
                tar = tarfile.open(self.bu.backupfile('metadata.tar.gz'))
                tar.errorlevel = 2
            except (EnvironmentError, tarfile.TarError), e:
                raise util.Abort("couldn't open metadata tarball: %s\n"
                                 "   %s" %
                                 (self.bu.backupfile('metadata.tar.gz'), e))

            for elt in tar:
                fpath = self.ws.repo.join(elt.name)
                if not os.path.exists(fpath):
                    return True     # File in tar, not workspace

                if elt.isdir():     # Don't care about directories
                    continue

                if (elt.mtime != os.path.getmtime(fpath) or
                    elt.size != os.path.getsize(fpath)):
                    return True

            tarnames = tar.getnames()
            tar.close()
        else:
            tarnames = []

        for mfile in self.files:
            fpath = self.ws.repo.join(mfile)

            if os.path.isdir(fpath):
                # Directories in tarfile always end with a '/'
                if not mfile.endswith('/'):
                    mfile += '/'

                if mfile not in tarnames:
                    return True

                for root, dirs, files in os.walk(fpath, topdown=True):
                    for elt in files:
                        path = os.path.join(root, elt)

                        rpath = self.ws.repo.path
                        if not rpath.endswith('/'):
                            rpath += '/'

                        path = path.replace(rpath, '', 1)
                        if path not in tarnames:
                            return True # In workspace not tar
            else:
                if os.path.exists(fpath) and mfile not in tarnames:
                    return True

        return False

    def cleanup(self):
        '''Remove backed up workspace metadata'''
        if os.path.exists(self.bu.backupfile('metadata.tar.gz')):
            os.unlink(self.bu.backupfile('metadata.tar.gz'))


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
                                              CdmMetadataBackup]]


        if os.path.exists(os.path.join(self.backupdir, 'latest')):
            generation = os.readlink(os.path.join(self.backupdir, 'latest'))
            self.generation = int(os.path.split(generation)[1])
        else:
            self.generation = 0

    def _find_backup_dir(self, name):
        '''Find the path to an appropriate backup directory based on NAME'''
        backupdir = None
        backupbase = None

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

    def backupfile(self, path):
        '''return full path to backup file FILE at GEN'''
        return os.path.join(self.backupdir, str(self.generation), path)

    def update_latest(self, gen):
        '''Update latest symlink to point to the current generation'''
        linkpath = os.path.join(self.backupdir, 'latest')

        if os.path.lexists(linkpath):
            os.unlink(linkpath)

        os.symlink(str(gen), linkpath)

    def create_gen(self, gen):
        '''Create a new backup generation'''
        try:
            os.makedirs(os.path.join(self.backupdir, str(gen)))
            self.update_latest(gen)
        except EnvironmentError, e:
            raise util.Abort("Couldn't create backup generation %s: %s" %
                             (os.path.join(self.backupdir, str(gen)), e))

    def need_backup(self):
        '''Compare backed up changes to workspace'''
        #
        # If there's no current backup generation, or the last backup was
        # invalid (lacking the dirstate file), we need a backup regardless
        # of anything else.
        #
        if (not self.generation or
            not os.path.exists(self.backupfile('dirstate'))):
            return True

        for x in self.modules:
            if x.need_backup():
                return True

        return False

    def backup(self):
        '''Take a backup of the current workspace'''

        if not os.path.exists(self.backupdir):
            try:
                os.makedirs(self.backupdir)
            except EnvironmentError, e:
                raise util.Abort('Could not create backup directory %s: %s' %
                                 (self.backupdir, e))

        self.generation += 1
        self.create_gen(self.generation)

        #
        # Lock the repo, so the backup can be consistent.  We need the
        # wlock too to make sure the dirstate parent doesn't change
        # underneath us.
        #

        lock = self.ws.repo.lock()
        wlock = self.ws.repo.lock()

        try:
            for x in self.modules:
                x.backup()
        except Exception, e:
            if isinstance(e, KeyboardInterrupt):
                self.ws.ui.warn("Interrupted\n")
            else:
                self.ws.ui.warn("Error: %s\n" % e)

                #
                # If it's not a 'normal' error, we want to print a stack
                # trace now in case the attempt to remove the partial
                # backup also fails, and raises a second exception.
                #
                if (not isinstance(e, (EnvironmentError, util.Abort))
                    or self.ws.ui.traceback):
                    traceback.print_exc()

            for x in self.modules:
                x.cleanup()

            os.rmdir(os.path.join(self.backupdir, str(self.generation)))
            self.generation -= 1

            if self.generation != 0:
                self.update_latest(self.generation)
            else:
                os.unlink(os.path.join(self.backupdir, 'latest'))

            raise util.Abort('Backup failed')

    def restore(self, gen=None):
        '''Restore workspace from backup

        Restores from backup generation GEN (defaulting to the latest)
        into workspace WS.'''

        wlock = self.ws.repo.wlock()
        lock = self.ws.repo.lock()

        if not os.path.exists(self.backupdir):
            raise util.Abort('Backup directory does not exist: %s' %
                             (self.backupdir))

        if gen:
            if not os.path.exists(os.path.join(self.backupdir, str(gen))):
                raise util.Abort('Backup generation does not exist: %s' %
                                 (os.path.join(self.backupdir, str(gen))))
            self.generation = int(gen)

        if not self.generation: # This is ok, 0 is not a valid generation
            raise util.Abort('Backup has no generations: %s' % self.backupdir)

        if not os.path.exists(self.backupfile('dirstate')):
            raise util.Abort('Backup %s/%s is incomplete (dirstate missing)' %
                             (self.backupdir, self.generation))

        try:
            for x in self.modules:
                x.restore()
        except util.Abort, e:
            raise util.Abort('Error restoring workspace:\n'
                             '%s\n'
                             'Workspace will be partially restored' % e)
