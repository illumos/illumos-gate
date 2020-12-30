.H 1 ksh93
KSH-93 is the most recent version of the KornShell Language
described in
"The KornShell Command and Programming Language,"
by Morris Bolsky and David Korn of AT&T Bell Laboratories, ISBN 0-13-182700-6.
The KornShell is a shell programming language,
which is upward compatible with "sh" (the Bourne Shell),
and is intended to conform to the IEEE P1003.2/ISO 9945.2 Shell and
Utilities standard.
KSH-93 provides an enhanced programming environment in
addition to the major command-entry features of the BSD
shell "csh".  With KSH-93, medium-sized programming tasks can be
performed at shell-level without a significant loss in performance.
In addition, "sh" scripts can be run on KSH-93 without modification.
.P
The code should conform to the IEEE POSIX 1003.1 standard and to the
proposed ANSI-C standard so that it should be portable to all
such systems.  Like the previous version, KSH-88,
it is designed to accept eight bit character sets
transparently, thereby making it internationally compatible.
It can support multi-byte characters sets with some characteristics
of the character set given at run time.
.P
KSH-93 provides the following features, many of which were also inherent
in KSH-88:
.BL
.LI
Enhanced Command Re-entry Capability:  The KSH-93 history
function records commands entered at any shell level and stores
them, up to a user-specified limit, even after you log off.
This allows you to re-enter long commands with a few keystrokes
- even those commands you entered yesterday.
The history file allows for eight bit characters in
commands and supports essentially unlimited size histories.
.LI
In-line Editing: In "sh", the only way to fix mistyped
commands is to backspace or retype the line. KSH-93 allows you
to edit a command line using a choice of EMACS-TC or "vi"
functions.
You can use the in-line editors to complete filenames as
you type them.
You may also use this editing feature when entering
command lines from your history file.
A user can capture keystrokes and rebind keys to customize the
editing interface.
.LI
Extended I/O Capabilities:  KSH-93 provides several I/O
capabilities not available in "sh", including the ability to:
.BL
.LI
specify a file descriptor for input and output
.LI
start up and run co-processes
.LI
produce a prompt at the terminal before a read
.LI
easily format and interpret responses to a menu
.LI
echo lines exactly as output without escape processing
.LI
format output using printf formats.
.LI
read and echo lines ending in "\e".
.LE
.LI
Improved performance: KSH-93 executes many scripts faster
than the System V Bourne shell. A major reason for this is
that many of the standard utilities are built-in.
To reduce the time to initiate a command, KSH-93 allows
commands to be added as built-ins at run time
on systems that support dynamic loading such as System V Release 4.
.LI
Arithmetic: KSH-93 allows you to do integer arithmetic in any
base from two to sixty-four.  You can also do double
precision floating point arithmetic.
Almost the complete set of C language operators are available
with the same syntax and precedence.
Arithmetic expressions can be used to as an argument expansion 
or as a separate command.
In addition there is an arithmetic for command that works
like the for statement in C.
.LI
Arrays: KSH-93 supports both indexed and associative arrays.
The subscript for an indexed array is an arithmetic expression,
whereas, the subscript for an associative array is a string.
.LI
Shell Functions and Aliases: Two mechanisms - functions and
aliases - can be used to assign a user-selected identifier to
an existing command or shell script.
Functions allow local variables and provide scoping
for exception handling.
Functions can be searched for and loaded on first reference the
way scripts are.
.LI
Substring Capabilities:  KSH-93 allows you to create a
substring of any given string either by specifying the starting
offset and length, or by stripping off leading
or trailing substrings during parameter substitution.
You can also specify attributes, such as upper and lower case,
field width, and justification to shell variables.
.LI
More pattern matching capabilities:  KSH-93 allows you to specify
extended regular expressions for file and string matches.
.LI
KSH-93 uses a hierarchal name space for variables.
Compound variables can be defined and variables can
be passed by reference.  In addition, each variable
can have one or more disciplines associated with
it to intercept assignments and references.
.LI
Improved debugging:  KSH-93 can generate line numbers on execution
traces.  Also, I/O redirections are now traced.
There is a DEBUG trap that gets evaluated before each command
so that errors can be localized.
.LI
Job Control: On systems that support job control, including
System V Release 4, KSH-93
provides a job-control mechanism almost identical to that of
the BSD "csh", version 4.1.
This feature allows you
to stop and restart programs, and to move programs between the
foreground and the background.
.LI
Added security:
KSH-93 can execute scripts which do not have read permission
and scripts which have the setuid and/or setgid set when
invoked by name, rather than as an argument to the shell.
It is possible to log or control the execution of setuid and/or
setgid scripts.
The noclobber option prevents you from accidentally erasing
a file by redirecting to an existing file.
.LI
KSH-93 can be extended by adding built-in commands at run time.
In addition, KSH-93 can be used as a library that can
be embedded into an application to allow scripting.
.LE
Documentation for KSH-93 consists of an "Introduction to KSH-93",
"Compatibility with the Bourne Shell" and a manual page and a
README file.  In addition, the "New KornShell Command and Programming
Language," book is available from Prentice Hall.

