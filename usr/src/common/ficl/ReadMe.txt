FICL 4.1.0
October 2010

________
OVERVIEW

Ficl is a complete programming language interpreter designed to be embedded
into other systems (including firmware based ones) as a command, macro,
and development prototype language.  Ficl stands for "Forth Inspired
Command Language".

For more information, please see the "doc" directory.
For release notes, please see "doc/releases.html".

____________
INSTALLATION

Ficl builds out-of-the-box on the following platforms:
	* NetBSD, FreeBSD: use "Makefile".
	* Linux: use "Makefile.linux", but it should work with
	  "Makefile" as well.
	* Win32: use "ficl.dsw" / "ficl.dsp".
To port to other platforms, we suggest you start with the generic
"Makefile" and the "unix.c" / "unix.h" platform-specific implementation
files.  (And please--feel free to submit your portability changes!)

(Note: Ficl used to build under RiscOS, but we broke everything
for the 4.0 release.  Please fix it and send us the diffs!)

____________
FICL LICENSE

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
