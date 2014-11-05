#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE
#
# Copyright (c) 2014, Joyent, Inc.
#

'''
Process our ignore/exception_list file format.

The format is broadly similar, if not identical, to .gitignore and .hgignore
files.
'''

import re
import fnmatch

RE_SYNTAX = re.compile(r'^syntax:\s*(.*)\s*$')

#
# It is important that this module not rely on Mercurial
#

def _read_ignore_file(ignorefile):
    '''Read an ignore file and return an array of regular expressions
    to match ignored paths.'''

    syntax = 'regex'
    ignore_list = []
    lc = 0

    with open(ignorefile, 'r') as f:
        for l in f:
            lc += 1
            # Remove comments and blank lines
            l = l.split('#', 2)[0].strip()
            if l == '':
                continue
            # Process "syntax:" lines
            m = RE_SYNTAX.match(l)
            if m:
                syntax = m.group(1)
                continue
            # All other lines are considered patterns
            if (syntax == 'glob'):
                ignore_list.append(re.compile('.*' + fnmatch.translate(l)))
            elif (syntax == 'regex'):
                ignore_list.append(re.compile(l))
            else:
                raise Exception('%s:%d: syntax "%s" is not supported' %
                    (ignorefile, lc, syntax))

    return ignore_list

def ignore(root, ignorefiles):
    # If we aren't provided any ignore files, we'll never ignore
    # any paths:
    if (len(ignorefiles) < 1):
        return lambda x: False

    ignore_list = []
    for ignorefile in ignorefiles:
        ignore_list.extend(_read_ignore_file(ignorefile))

    # If the ignore files contained no patterns, we'll never ignore
    # any paths:
    if (len(ignore_list) < 1):
        return lambda x: False

    def _ignore_func(path):
        for regex in ignore_list:
            if (regex.match(path)):
                return True
        return False

    return _ignore_func
