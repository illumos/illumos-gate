How to write sparse documentation
=================================

Introduction
------------


The documentation for Sparse is written in plain text augmented with
either `reStructuredText`_ (.rst) or `MarkDown`_ (.md) markup. These
files can be organized hierarchically, allowing a good structuring
of the documentation.
Sparse uses `Sphinx`_ to format this documentation in several formats,
like HTML or PDF.

All documentation related files are in the ``Documentation/`` directory.
In this directory you can use ``make html`` or ``make man`` to generate
the documentation in HTML or manpage format. The generated files can then
be found in the ``build/`` sub-directory.

The root of the documentation is the file ``index.rst`` which mainly
lists the names of the files with real documentation.

.. _Sphinx: http://www.sphinx-doc.org/
.. _reStructuredText: http://docutils.sourceforge.net/rst.html
.. _MarkDown: https://en.wikipedia.org/wiki/Markdown


.. _rest-markup:

Minimal reST cheatsheet
-----------------------

Basic inline markup is:

* ``*italic*`` gives *italic*
* ``**bold**`` gives **bold**
* ````mono```` gives ``mono``

Headings are created by underlining the title with a punctuation
character; it can also be optionally overlined::

	#############
	Major heading
	#############

	Minor heading
	-------------

Any punctuation character can be used and the levels are automatically
determined from their nesting. However, the convention is to use:

* ``#`` with overline for parts
* ``*`` with overline for chapters
* ``=`` for sections
* ``-`` for subsections
* ``^`` for subsubsections


Lists can be created like this::

	* this is a bulleted list
	* with the second item
	  on two lines
	* nested lists are supported

		* subitem
		* another subitem

	* and here is the fourth item

	#. this is an auto-numbered list
	#. with two items

	1. this is an explicitly numbered list
	2. with two items


Definition lists are created with a simple indentation, like::

	term, concept, whatever
		Definition, must be indented and
		continue here.

		It can also have several paragraphs.

Literal blocks are introduced with ``::``, either at the end of the
preceding paragraph or on its own line, and indented text::

	This is a paragraph introducing a literal block::

		This is the literal block.
		It can span several lines.

		It can also consist of several paragraphs.

Code examples with syntax highlighting use the *code-block* directive.
For example::

	.. code-block:: c

		int foo(int a)
		{
			return a + 1;
		}

will give:

.. code-block:: c

	int foo(int a)
	{
		return a + 1;
	}


Autodoc
-------

.. highlight:: none
.. c:autodoc:: Documentation/sphinx/cdoc.py

For example, a doc-block like::

	///
	// increment a value
	//
	// @val: the value to increment
	// @return: the incremented value
	//
	// This function is to be used to increment a
	// value.
	//
	// It's strongly encouraged to use this
	// function instead of open coding a simple
	// ``++``.
	int inc(int val)

will be displayed like this:

.. c:function:: int inc(int val)
	:noindex:

	:param val: the value to increment
	:return: the incremented value

	This function is to be used to increment a
	value.

	It's strongly encouraged to use this
	function instead of open coding a simple
	``++``.

Intermediate Representation
---------------------------
.. c:autodoc:: Documentation/sphinx/ir.py
