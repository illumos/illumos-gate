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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

"""Boot Environment classes used by beadm."""

import datetime

class BootEnvironment:
    """Boot Environment object that is used by beadm to manage command line
    options, arguments and the log."""

    def __init__(self):
        self.trgt_rpool = None
        self.trgt_be_name_or_snapshot = None
        self.src_be_name_or_snapshot = None
        self.properties = {}
        self.log_id = None
        self.log = None
        self.msg_buf = {}
        self.description = None

class listBootEnvironment:
    """Base class for beadm list
    Determine the BE's to display. Prints command output according to option:
    -d - dataset
    -s - snapshot
    -a - all (both dataset and snapshot)
    <none> - only BE information
    The -H option produces condensed, parseable output
        The ';' delimits each field in the output.  BEs with multiple
        datasets will have multiple lines in the output.
    """

    def list(self, be_list, ddh, be_name):
        """ print all output for beadm list command
        be_list - list of all BEs
        ddh - if True, Do not Display Headers - just parseable data
        be_name - user-specified BE, if any

        returns 0 for success
        side effect: beadm list output printed to stdout
        """

        #If we're listing Headers, initialize the array holding the
        #column widths with the header widths themselves.  Later on,
        #the data in this array will get adjusted as we process actual
        #row data and find that a piece of data is wider than its
        #column header.
        bemaxout = [0 for i in range(len(self.hdr[0]))]
        if not ddh:
            #iterate all header rows since their fields may not
            #be of equal length.
            for header in self.hdr:
                icol = 0
                for hc in header:
                    if len(hc) + 1 > bemaxout[icol]:
                        bemaxout[icol] = len(hc) + 1
                    icol += 1

        #collect BEs
        beout = {}     #matrix of output text [row][attribute]
        beoutname = {} #list of BE names [row]
        be_space = {}  #space used totals for BE [BE name]['space_used','ibei']
        ibe = 0        #BE index
        spacecol = -1  #to contain column where space used is displayed
        for be in be_list:
            if 'orig_be_name' in be:
                cur_be = be['orig_be_name']
                cur_be_obj = be

            #if BE name specified, collect matching BEs
            if be_name is not None and not self.beMatch(be, be_name): 
                continue
            attrs = ()
            #identify BE|dataset|snapshot attributes
            att = ''
            for att in ('orig_be_name', 'dataset', 'snap_name'):
                if att in be and att in self.lattrs:
                    attrs = self.lattrs[att]
                    if att == 'orig_be_name':
                        be_space[cur_be] = {}
                        be_space[cur_be]['space_used'] = 0
                        be_space[cur_be]['ibe'] = ibe
                        if not ddh and len(cur_be) + 1 > bemaxout[0]:
                            bemaxout[0] = len(cur_be) + 1
                    break
            beout[ibe] = {}
            beoutname[ibe] = cur_be

            icol = 0 #first column
            for at in attrs:
                #for option -s, withhold subordinate datasets
                if self.__class__.__name__ == 'SnapshotList' and \
                    att == 'snap_name' and  'snap_name' in be and \
                    '/' in be[att]:
                    break
                #convert output to readable format and save
                save = self.getAttr(at, be, ddh, cur_be_obj)
                beout[ibe][at] = save
                #maintain maximum column widths
                if not ddh and len(save) + 1 > bemaxout[icol]:
                    bemaxout[icol] = len(save) + 1
                #sum all snapshots for BE
                if at == 'space_used' and 'space_used' in be:
                    spacecol = icol
                icol += 1 #next column
            ibe += 1
            if 'space_used' in be:
                #sum all snapshots and datasets for BE in 'beadm list'
                if isinstance(self, BEList):
                    be_space[cur_be]['space_used'] += be.get('space_used')
                elif cur_be in be_space and \
                    ('space_used' not in be_space[cur_be] or 
                        be_space[cur_be]['space_used'] == 0):
                    #list space used separately for other options
                    be_space[cur_be]['space_used'] = be.get('space_used')

        #output format total lengths for each BE with any snapshots
        for cur_be in be_space:
            save = self.getSpaceValue(be_space[cur_be]['space_used'], ddh)
            ibe = be_space[cur_be]['ibe']
            beout[ibe]['space_used'] = save
            #expand column if widest column entry
            if (spacecol != -1) and \
               (not ddh and len(save) + 1 > bemaxout[spacecol]):
                bemaxout[spacecol] = len(save) + 1

        #print headers in columns
        if not ddh:
            for header in self.hdr:
                outstr = ''
                for icol in range(len(header)):
                    outstr += header[icol].ljust(bemaxout[icol])
                if outstr != '': 
                    print outstr

        #print collected output in columns
        outstr = ''
        prev_be = None
        cur_be = None
        for ibe in beout: #index output matrix
            if beoutname[ibe] != None: 
                cur_be = beoutname[ibe]
            #find attributes for BE type
            curtype = None
            for att in ('orig_be_name', 'dataset', 'snap_name'):
                if att in beout[ibe]:
                    attrs = self.lattrs[att]
                    curtype = att
                    break

            if curtype == None: #default to BE
                curtype = 'orig_be_name'
                if 'orig_be_name' in self.lattrs:
                    attrs = self.lattrs['orig_be_name']
                else: attrs = ()

            if not ddh:
                if prev_be != cur_be and cur_be != None:
                    #for -d,-s,-a, print BE alone on line
                    if self.__class__.__name__ != 'BEList':
                        print cur_be
                    prev_be = cur_be

            #print for one BE/snapshot/dataset
            icol = 0 #first column

            #if this is a 'dataset' or 'snap_name', start line with BE 
            #name token
            if ddh and curtype != 'orig_be_name':
                outstr = cur_be

            for at in attrs: #for each attribute specified in table
                if ddh: #add separators for parsing
                    if outstr != '': 
                        outstr += ';' #attribute separator
                    if at in beout[ibe] and beout[ibe][at] != '-' and \
                        beout[ibe][at] != '':
                        outstr += beout[ibe][at]
                else: #append text justified in column
                    if at in beout[ibe]:
                        outstr += beout[ibe][at].ljust(bemaxout[icol])
                icol += 1 #next column

            if outstr != '': 
                print outstr
            outstr = ''

        return 0

    def beMatch(self, be, be_name):
        """find match on user-specified BE."""

        if 'orig_be_name' in be:
            return be.get('orig_be_name') == be_name
        if 'dataset' in be:
            if be.get('dataset') == be_name: 
                return True
            out = be.get('dataset').split("/")
            return out[0] == be_name
        if 'snap_name' in be:
            if be.get('snap_name') == be_name: 
                return True
            out = be.get('snap_name').split('@')
            if out[0] == be_name: 
                return True
            out = be.get('snap_name').split('/')
            return out[0] == be_name
        return False

    def getAttr(self, at, be, ddh, beobj):
        """
        Extract information by attribute and format for printing
        returns '?' if normally present attribute not found - error.
        """
        if at == 'blank': 
            return ' '
        if at == 'dash': 
            return '-'
        if at == 'orig_be_name':
            if at not in be: 
                return '-'
            ret = be[at]
            if ddh or self.__class__.__name__ == 'BEList':
                return ret
            return '   ' + ret #indent
        if at == 'snap_name':
            if at not in be: 
                return '-'
            if self.__class__.__name__ == 'CompleteList':
                ret = self.prependRootDS(be[at], beobj)
            else: 
                ret = be[at]
            if ddh: 
                return ret
            return '   ' + ret #indent
        if at == 'dataset':
            if at not in be: 
                return '-'
            if self.__class__.__name__ == 'DatasetList' or \
               self.__class__.__name__ == 'CompleteList':
                ret = self.prependRootDS(be[at], beobj)
            else: 
                ret = be[at]
            if ddh: 
                return ret
            return '   ' + ret #indent
        if at == 'active':
            if at not in be: 
                return '-'
            ret = ''
            if 'active' in be and be['active']: 
                ret += 'N'
            if 'active_boot' in be and be['active_boot']: 
                ret += 'R'
            if ret == '': 
                return '-'
            return ret
        if at == 'mountpoint':
            if at not in be: 
                return '-'
            if 'mounted' not in be or not be['mounted']: 
                return '-'
            return be[at]
        if at == 'space_used':
            if at not in be: 
                return '0'
            return self.getSpaceValue(be[at], ddh)
        if at == 'mounted':
            if at not in be: 
                return '-'
            return be[at]
        if at == 'date':
            if at not in be: 
                return '?'
            if ddh: 
                return str(be[at]) #timestamp in seconds
            sec = str(datetime.datetime.fromtimestamp(be[at]))
            return sec[0:len(sec)-3] #trim seconds
        if at == 'policy':
            if at not in be: 
                return '?'
            return be[at]
        if at == 'root_ds':
            if at not in be: 
                return '?'
            if ddh or self.__class__.__name__ == 'BEList':
                return be[at]
            return '   ' + be[at]
        if at == 'uuid_str':
            if at not in be: 
                return '-'
            return be[at]
        #default case - no match on attribute
        return be[at]

    def getSpaceValue(self, num, ddh):
        """Readable formatting for disk space size."""

        if ddh: 
            return str(num) #return size in bytes as string

        kilo = 1024.0
        mega = 1048576.0
        giga = 1073741824.0
        tera = 1099511627776.0

        if num == None: 
            return '0'
        if num < kilo: 
            return str(num) + 'B'
        if num < mega: 
            return str('%.1f' % (num / kilo)) + 'K'
        if num < giga: 
            return str('%.2f' % (num / mega)) + 'M'
        if num < tera: 
            return str('%.2f' % (num / giga)) + 'G'
        return str('%.2f' % (num / tera)) + 'T'

    def prependRootDS(self, val, beobj):
        """Prepend root dataset name with BE name stripped."""

        root_ds = beobj.get('root_ds')
        return root_ds[0:root_ds.rfind('/')+1] + val


"""Top level "beadm list" derived classes defined here.
        Only table definition is done here - all methods are in the base class.
        Tables driving list:
                hdr - list of text to output for each column
                lattrs - dictionary of attributes
                        Each entry specifies either BE, dataset, snapshot with
                        an attribute key:
                                orig_be_name - for BEs
                                dataset - for datasets
                                snap_name - for snapshots
                        Each list item in entry indicates specific datum for 
                        column
                Number of hdr columns must equal number of lattrs entries
                        unless ddh (dontDisplayHeaders) is true.
"""
class BEList(listBootEnvironment):
    """specify header and attribute information for BE-only output"""

    def __init__(self, ddh):
        """Init function for the class."""
        self.hdr = \
            ('BE','Active','Mountpoint','Space','Policy','Created'), \
            ('--','------','----------','-----','------','-------')
        if ddh:
            self.lattrs = {'orig_be_name':('orig_be_name', 'uuid_str', 
                           'active', 'mountpoint', 'space_used', 'policy', 
                           'date')}
        else:
            self.lattrs = {'orig_be_name':('orig_be_name', 'active', 
                           'mountpoint', 'space_used', 'policy', 'date')}

class DatasetList(listBootEnvironment):
    """
    specify header and attribute information for dataset output,
    -d option
    """
    def __init__(self, ddh):
        """Init function for the class."""

        self.hdr = \
            ('BE/Dataset','Active','Mountpoint','Space','Policy','Created'), \
            ('----------','------','----------','-----','------','-------')
        if ddh:
            self.lattrs = { \
                'orig_be_name':('orig_be_name', 'root_ds', 'active', 
                'mountpoint', 'space_used', 'policy', 'date'), \
                'dataset':('dataset', 'dash', 'mountpoint', 'space_used', 
                'policy', 'date')}
        else:
            self.lattrs = { \
                'orig_be_name':('root_ds', 'active', 'mountpoint', 
                'space_used', 'policy', 'date'), \
                'dataset':('dataset', 'dash', 'mountpoint', 'space_used', 
                'policy', 'date')}

class SnapshotList(listBootEnvironment):
    """
    specify header and attribute information for snapshot output,
    -s option
    """
    def __init__(self, ddh):
        """Init function for the class."""

        self.hdr = \
            ('BE/Snapshot','Space','Policy','Created'), \
            ('-----------','-----','------','-------')
        self.lattrs = {'snap_name':('snap_name', 'space_used', 'policy',
                                    'date')}

class CompleteList(listBootEnvironment):
    """
    specify header and attribute information for BE and/or dataset and/or
    snapshot output,
    -a or -ds options 
    """
    def __init__(self, ddh):
        """Init function for the class."""

        self.hdr = \
    ('BE/Dataset/Snapshot','Active','Mountpoint','Space','Policy','Created'), \
    ('-------------------','------','----------','-----','------','-------')
        if ddh:
            self.lattrs = { \
                'orig_be_name':('orig_be_name', 'root_ds', 'active',
                'mountpoint', 'space_used', 'policy', 'date'),
                'dataset':('dataset', 'dash', 'mountpoint', 'space_used',
                'policy', 'date'),
                'snap_name':('snap_name', 'dash', 'dash', 'space_used',
                'policy', 'date')}
        else:
            self.lattrs = { \
                'orig_be_name':('root_ds', 'active', 'mountpoint',
                                'space_used', 'policy', 'date'), \
                'dataset':('dataset', 'dash', 'mountpoint', 'space_used',
                'policy', 'date'),
                'snap_name':('snap_name', 'dash', 'dash', 'space_used',
                'policy', 'date')}
