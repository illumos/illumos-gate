#!/usr/bin/env python
# SPDX_License-Identifier: MIT
#
# Copyright (C) 2018 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>
#

"""
///
// Sparse source files may contain documentation inside block-comments
// specifically formatted::
//
// 	///
// 	// Here is some doc
// 	// and here is some more.
//
// More precisely, a doc-block begins with a line containing only ``///``
// and continues with lines beginning by ``//`` followed by either a space,
// a tab or nothing, the first space after ``//`` is ignored.
//
// For functions, some additional syntax must be respected inside the
// block-comment::
//
// 	///
// 	// <mandatory short one-line description>
// 	// <optional blank line>
// 	// @<1st parameter's name>: <description>
// 	// @<2nd parameter's name>: <long description
// 	// <tab>which needs multiple lines>
// 	// @return: <description> (absent for void functions)
// 	// <optional blank line>
// 	// <optional long multi-line description>
// 	int somefunction(void *ptr, int count);
//
// Inside the description fields, parameter's names can be referenced
// by using ``@<parameter name>``. A function doc-block must directly precede
// the function it documents. This function can span multiple lines and
// can either be a function prototype (ending with ``;``) or a
// function definition.
//
// Some future versions will also allow to document structures, unions,
// enums, typedefs and variables.
//
// This documentation can be extracted into a .rst document by using
// the *autodoc* directive::
//
// 	.. c:autodoc:: file.c
//

"""

import re

class Lines:
	def __init__(self, lines):
		# type: (Iterable[str]) -> None
		self.index = 0
		self.lines = lines
		self.last = None
		self.back = False

	def __iter__(self):
		# type: () -> Lines
		return self

	def memo(self):
		# type: () -> Tuple[int, str]
		return (self.index, self.last)

	def __next__(self):
		# type: () -> Tuple[int, str]
		if not self.back:
			self.last = next(self.lines).rstrip()
			self.index += 1
		else:
			self.back = False
		return self.memo()
	def next(self):
		return self.__next__()

	def undo(self):
		# type: () -> None
		self.back = True

def readline_multi(lines, line):
	# type: (Lines, str) -> str
	try:
		while True:
			(n, l) = next(lines)
			if not l.startswith('//\t'):
				raise StopIteration
			line += '\n' + l[3:]
	except:
		lines.undo()
	return line

def readline_delim(lines, delim):
	# type: (Lines, Tuple[str, str]) -> Tuple[int, str]
	try:
		(lineno, line) = next(lines)
		if line == '':
			raise StopIteration
		while line[-1] not in delim:
			(n, l) = next(lines)
			line += ' ' + l.lstrip()
	except:
		line = ''
	return (lineno, line)


def process_block(lines):
	# type: (Lines) -> Dict[str, Any]
	info = { }
	tags = []
	desc = []
	state = 'START'

	(n, l) = lines.memo()
	#print('processing line ' + str(n) + ': ' + l)

	## is it a single line comment ?
	m = re.match(r"^///\s+(.+)$", l)	# /// ...
	if m:
		info['type'] = 'single'
		info['desc'] = (n, m.group(1).rstrip())
		return info

	## read the multi line comment
	for (n, l) in lines:
		#print('state %d: %4d: %s' % (state, n, l))
		if l.startswith('// '):
			l = l[3:]					## strip leading '// '
		elif l.startswith('//\t') or l == '//':
			l = l[2:]					## strip leading '//'
		else:
			lines.undo()				## end of doc-block
			break

		if state == 'START':			## one-line short description
			info['short'] = (n ,l)
			state = 'PRE-TAGS'
		elif state == 'PRE-TAGS':		## ignore empty line
			if l != '':
				lines.undo()
				state = 'TAGS'
		elif state == 'TAGS':			## match the '@tagnames'
			m = re.match(r"^@([\w-]*)(:?\s*)(.*)", l)
			if m:
				tag = m.group(1)
				sep = m.group(2)
				## FIXME/ warn if sep != ': '
				l = m.group(3)
				l = readline_multi(lines, l)
				tags.append((n, tag, l))
			else:
				lines.undo()
				state = 'PRE-DESC'
		elif state == 'PRE-DESC':		## ignore the first empty lines
			if l != '':					## or first line of description
				desc = [n, l]
				state = 'DESC'
		elif state == 'DESC':			## remaining lines -> description
			desc.append(l)
		else:
			pass

	## fill the info
	if len(tags):
		info['tags'] = tags
	if len(desc):
		info['desc'] = desc

	## read the item (function only for now)
	(n, line) = readline_delim(lines, (')', ';'))
	if len(line):
		line = line.rstrip(';')
		#print('function: %4d: %s' % (n, line))
		info['type'] = 'func'
		info['func'] = (n, line)
	else:
		info['type'] = 'bloc'

	return info

def process_file(f):
	# type: (TextIOWrapper) -> List[Dict[str, Any]]
	docs = []
	lines = Lines(f)
	for (n, l) in lines:
		#print("%4d: %s" % (n, l))
		if l.startswith('///'):
			info = process_block(lines)
			docs.append(info)

	return docs

def decorate(l):
	# type: (str) -> str
	l = re.sub(r"@(\w+)", "**\\1**", l)
	return l

def convert_to_rst(info):
	# type: (Dict[str, Any]) -> List[Tuple[int, str]]
	lst = []
	#print('info= ' + str(info))
	typ = info.get('type', '???')
	if typ == '???':
		## uh ?
		pass
	elif typ == 'bloc':
		if 'short' in info:
			(n, l) = info['short']
			lst.append((n, l))
		if 'desc' in info:
			desc = info['desc']
			n = desc[0] - 1
			desc.append('')
			for i in range(1, len(desc)):
				l = desc[i]
				lst.append((n+i, l))
				# auto add a blank line for a list
				if re.search(r":$", desc[i]) and re.search(r"\S", desc[i+1]):
					lst.append((n+i, ''))

	elif typ == 'func':
		(n, l) = info['func']
		l = '.. c:function:: ' + l
		lst.append((n, l + '\n'))
		if 'short' in info:
			(n, l) = info['short']
			l = l[0].capitalize() + l[1:].strip('.')
			l = '\t' + l + '.'
			lst.append((n, l + '\n'))
		if 'tags' in info:
			for (n, name, l) in info.get('tags', []):
				if name != 'return':
					name = 'param ' + name
				l = decorate(l)
				l = '\t:%s: %s' % (name, l)
				l = '\n\t\t'.join(l.split('\n'))
				lst.append((n, l))
			lst.append((n+1, ''))
		if 'desc' in info:
			desc = info['desc']
			n = desc[0]
			r = ''
			for l in desc[1:]:
				l = decorate(l)
				r += '\t' + l + '\n'
			lst.append((n, r))
	return lst

def extract(f, filename):
	# type: (TextIOWrapper, str) -> List[Tuple[int, str]]
	res = process_file(f)
	res = [ i for r in res for i in convert_to_rst(r) ]
	return res

def dump_doc(lst):
	# type: (List[Tuple[int, str]]) -> None
	for (n, lines) in lst:
		for l in lines.split('\n'):
			print('%4d: %s' % (n, l))
			n += 1

if __name__ == '__main__':
	""" extract the doc from stdin """
	import sys

	dump_doc(extract(sys.stdin, '<stdin>'))


from sphinx.ext.autodoc import AutodocReporter
import docutils
import os
class CDocDirective(docutils.parsers.rst.Directive):
	required_argument = 1
	optional_arguments = 1
	has_content = False
	option_spec = {
	}

	def run(self):
		env = self.state.document.settings.env
		filename = os.path.join(env.config.cdoc_srcdir, self.arguments[0])
		env.note_dependency(os.path.abspath(filename))

		## create a (view) list from the extracted doc
		lst = docutils.statemachine.ViewList()
		f = open(filename, 'r')
		for (lineno, lines) in extract(f, filename):
			for l in lines.split('\n'):
				lst.append(l.expandtabs(8), filename, lineno)
				lineno += 1

		## let parse this new reST content
		memo = self.state.memo
		save = memo.reporter, memo.title_styles, memo.section_level
		memo.reporter = AutodocReporter(lst, memo.reporter)
		node = docutils.nodes.section()
		try:
			self.state.nested_parse(lst, 0, node, match_titles=1)
		finally:
			memo.reporter, memo.title_styles, memo.section_level = save
		return node.children

def setup(app):
	app.add_config_value('cdoc_srcdir', None, 'env')
	app.add_directive_to_domain('c', 'autodoc', CDocDirective)

	return {
		'version': '1.0',
		'parallel_read_safe': True,
	}

# vim: tabstop=4
