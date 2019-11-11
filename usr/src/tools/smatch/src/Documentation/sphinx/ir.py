#!/usr/bin/env python
# SPDX_License-Identifier: MIT
#
# Copyright (C) 2018 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>
#

"""
///
// To document the instructions used in the intermediate representation
// a new domain is defined: 'ir' with a directive::
//
//	.. op: <OP_NAME>
//		<description of OP_NAME>
//		...
//
// This is equivalent to using a definition list but with the name
// also placed in the index (with 'IR instruction' as descriptions).

"""

import docutils
import sphinx

class IROpDirective(docutils.parsers.rst.Directive):

	# use the first line of content as the argument, this allow
	# to not have to write a blanck line after the directive
	final_argument_whitespace = True
	required_argument = 0
	#optional_arguments = 0
	has_content = True

	objtype = None

	def run(self):
		self.env = self.state.document.settings.env

		source = self.state.document
		lineno = self.lineno
		text = self.content
		name = text[0]

		node = docutils.nodes.section()
		node['ids'].append(name)
		node.document = source

		index = '.. index:: pair: %s; IR instruction' % name
		content = docutils.statemachine.ViewList()
		content.append(index, source, lineno)
		content.append(''   , source, lineno)
		content.append(name , source, lineno)
		content.append(''   , source, lineno)
		self.state.nested_parse(content, self.content_offset, node)

		defnode = docutils.nodes.definition()
		self.state.nested_parse(text[1:], self.content_offset, defnode)
		node.append(defnode)

		return [node]

class IRDomain(sphinx.domains.Domain):

    """IR domain."""
    name = 'ir'

def setup(app):
	app.add_domain(IRDomain)
	app.add_directive_to_domain('ir', 'op', IROpDirective)

	return {
		'version': '1.0',
		'parallel_read_safe': True,
	}

# vim: tabstop=4
