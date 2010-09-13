.ds DT July 9, 1993  \" use troff -mm
.nr C 3
.nr N 2
.SA 1  \"  right justified
.TL "311466-6713" "49059-6"  \" charging case filing case
Guidelines for writing \f5ksh-93\fP built-in commands
.AU "David G. Korn" DGK FP 11267 8062 D-237 "(research!dgk)"
.AF
.TM  11267-930???-93  \"  technical memo + TM numbers
.MT 4
.AS 2   \" abstract start for TM
One of the features of \f5ksh93\fP, the latest version of \f5ksh\fP,
is the ability to add built-in commands at run time.
This feature only works on operating systems that have the ability
to load and link code into the current process at run time.
Some examples of the systems that have this feature
are System V Release 4, Solaris, Sun OS, HP-UX Release 8 and above,
AIX 3.2 and above, and Microsoft Windows systems. 
.P
This memo describes how to write and compile programs
to can be loaded into \f5ksh\fP at run  time as built-in
commands.
.AE   \" abstract end
.OK Shell "Command interpreter" Language UNIX  \" keyword
.MT 1  \"  memo type
.H 1 INTRODUCTION
A built-in command is executed without creating a separate process.
Instead, the command is invoked as a C function by \f5ksh\fP. 
If this function has no side effects in the shell process,
then the behavior of this built-in is identical to that of
the equivalent stand-alone command.  The primary difference
in this case is performance.  The overhead of process creation
is eliminated.  For commands of short duration, the effect
can be dramatic.  For example, on SUN OS 4.1, the time do
run \f5wc\fP on a small file of about 1000 bytes, runs
about 50 times faster as a built-in command.
.P
In addition, built-in commands that have side effects on the
shell environment can be written.
This is usually done to extend the application domain for
shell programming.  For example, an X-windows extension
that makes heavy use of the shell variable namespace
was added as a group of built-ins commands that
are added at run time.
The result is a windowing shell that can be used to write
X-windows applications.
.P
While there are definite advantages to adding built-in
commands, there are some disadvantages as well.
Since the built-in command and \f5ksh\fP share the same
address space, a coding error in the built-in program
may affect the behavior of \f5ksh\fP; perhaps causing
it to core dump or hang.
Debugging is also more complex since your code is now
a part of a larger entity.
The isolation provided by a separate process
guarantees that all resources used by the command
will be freed when the command completes.
Also, since the address space of \f5ksh\fP will be larger,
this may increase the time it takes \f5ksh\fP to fork() and
exec() a non-builtin command.
It makes no sense to add a built-in command that takes
a long time to run or that is run only once, since the performance
benefits will be negligible.
Built-ins that have side effects in the current shell
environment have the disadvantage of increasing the
coupling between the built-in and \f5ksh\fP making
the overall system less modular and more monolithic.
.P
Despite these drawbacks, in many cases extending
\f5ksh\fP by adding built-in
commands makes sense and allows reuse of the shell
scripting ability in an application specific domain.
This memo describes how to write \f5ksh\fP extensions. 
.H 1 "WRITING BUILT-IN COMMANDS"
There is a development kit available for writing \f5ksh\fP
built-ins.  The development kit has three directories,
\f5include\fP, \f5lib\fP, and \f5bin\fP.
The \f5include\fP directory contains a sub-directory
named \f5ast\fP that contains interface prototypes
for functions that you can call from built-ins.  The \f5lib\fP
directory contains the \fBast\fP library\*F
.FS
\fBast\fP stands for Advanced Software Technology
.FE
and a library named \fBlibcmd\fP that contains a version
of several of the standard POSIX\*(Rf
.RS
.I "POSIX \- Part 2: Shell and Utilities,"
IEEE Std 1003.2-1992, ISO/IEC 9945-2:1993.
.RF
utilities that can be made run time built-ins.
It is best to set the value of the environment variable
\fB\s-1PACKAGE_\s+1ast\fP to the pathname of the directory
containing the development kit.
Users of \f5nmake\fP\*(Rf
.RS
Glenn Fowler,
Nmake reference needed
.RF
2.3 and above will then be able to
use the rule
.nf
.in .5i
\f5:PACKAGE:	ast\fP
.in
.fi
in their makefiles and not have to specify any \f5-I\fP switches
to the compiler.
.P
A built-in command has a calling convention similar to
the \f5main\fP function of a program,
.nf
.in .5i
\f5int main(int argc, char *argv[])\fP.
.in
.fi
However, instead of \f5main\fP, you must use the function name
\f5b_\fP\fIname\fP, where \fIname\fP is the name
of the built-in you wish to define.
The built-in function takes a third
\f5void*\fP  argument which you can define as \f5NULL\fP. 
Instead of \f5exit\fP, you need to use \f5return\fP
to terminate your command.
The return value, will become the exit status of the command.
.P
The steps necessary to create and add a run time built-in are
illustrated in the following simple example.
Suppose, you wish to add a built-in command named \f5hello\fP
which requires one argument and prints the word hello followed
by its argument.  First, write the following program in the file
\f5hello.c\fP:
.nf
.in .5i
\f5#include     <stdio.h>
int b_hello(int argc, char *argv[], void *context)
{
        if(argc != 2)
        {
                fprintf(stderr,"Usage: hello arg\en");
                return(2);
        }
        printf("hello %s\en",argv[1]);
        return(0);
}\fP
.in
.fi
.P
Next, the program needs to be compiled.
On some systems it is necessary to specify a compiler
option to produce position independent code
for dynamic linking.
If you do not compile with \f5nmake\fP
it is important to specify the a special include directory
when compiling built-ins. 
.nf
.in .5i
\f5cc -pic -I$PACKAGE_ast/include -c hello.c\fP
.in
.fi
since the special version of \f5<stdio.h>\fP
in the development kit is required.
This command generates \f5hello.o\fP in the current
directory.
.P
On some systems, you cannot load \f5hello.o\fP directly,
you must build a shared library instead.
Unfortunately, the method for generating a shared library
differs with operating system.
However, if you are building with the AT\&T \f5nmake\fP
program you can use the \f5:LIBRARY:\fP rule to specify
this in a system independent fashion. 
In addition, if you have several built-ins, it is desirable
to build a shared library that contains them all.
.P
The final step is using the built-in.
This can be done with the \f5ksh\fP command \f5builtin\fP.
To load the shared library \f5hello.so\fP and to add
the built-in \f5hello\fP, invoke the command,
.nf
.in .5i
\f5builtin -f hello hello\fP
.in
.fi
The suffix for the shared library can be omitted in
which case the shell will add an appropriate suffix
for the system that it is loading from.
Once this command has been invoked, you can invoke \f5hello\fP
as you do any other command. 
.P
It is often desirable to make a command \fIbuilt-in\fP
the first time that it is referenced.  The first
time \f5hello\fP is invoked, \f5ksh\fP should load and execute it,
whereas for subsequent invocations \f5ksh\fP should just execute the built-in.
This can be done by creating a file named \f5hello\fP
with the following contents:
.nf
.in .5i
\f5function hello
{
        unset -f hello
        builtin -f hello hello
        hello "$@"
}\fP
.in
.fi
This file \f5hello\fP needs to be placed in a directory that is
in your \fB\s-1FPATH\s+1\fP variable.  In addition, the full
pathname for \f5hello.so\fP should be used in this script
so that the run time loader will be able to find this shared library
no matter where the command \f5hello\fP is invoked.
.H 1 "CODING REQUIREMENTS AND CONVENTIONS"
As mentioned above, the entry point for built-ins must be of
the form \f5b_\fP\fIname\fP.
Your built-ins can call functions from the standard C library,
the \fBast\fP library, interface functions provided by \f5ksh\fP,
and your own functions.
You should avoid using any global symbols beginning with
.BR sh_ ,
.BR nv_ ,
and
.B ed_ 
since these are used by \f5ksh\fP itself.
In addition, \f5#define\fP constants in \f5ksh\fP interface
files, use symbols beginning with \fBSH_\fP to that you should
avoid using names beginning with \fBSH_\fP.
.H 2 "Header Files"
The development kit provides a portable interface
to the C library and to libast.
The header files in the development kit are compatible with
K&R C\*(Rf,
.RS
Brian W. Kernighan and Dennis M. Ritchie,
.IR "The C Programming Language" ,
Prentice Hall, 1978.
.RF
ANSI-C\*(Rf,
.RS
American National Standard for Information Systems \- Programming
Language \- C, ANSI X3.159-1989.
.RF
and C++\*(Rf.
.RS
Bjarne Stroustroup,
.IR "C++" ,
Addison Wesley, xxxx
.RF
.P
The best thing to do is to include the header file \f5<shell.h>\fP.
This header file causes the \f5<ast.h>\fP header, the
\f5<error.h>\fP header and the \f5<stak.h>\fP
header to be included as well as defining prototypes
for functions that you can call to get shell
services for your builtins.
The header file \f5<ast.h>\fP
provides prototypes for many \fBlibast\fP functions
and all the symbol and function definitions from the
ANSI-C headers, \f5<stddef.h>\fP,
\f5<stdlib.h>\fP, \f5<stdarg.h>\fP, \f5<limits.h>\fP,
and \f5<string.h>\fP.
It also provides all the symbols and definitions for the
POSIX\*(Rf
.RS
.I "POSIX \- Part 1: System Application Program Interface,"
IEEE Std 1003.1-1990, ISO/IEC 9945-1:1990.
.RF
headers \f5<sys/types.h>\fP, \f5<fcntl.h>\fP, and
\f5<unistd.h>\fP.
You should include \f5<ast.h>\fP instead of one or more of
these headers.
The \f5<error.h>\fP header provides the interface to the error
and option parsing routines defined below.
The \f5<stak.h>\fP header provides the interface to the memory
allocation routines described below.
.P
Programs that want to use the information in \f5<sys/stat.h>\fP
should include the file \f5<ls.h>\fP instead.
This provides the complete POSIX interface to \f5stat()\fP
related functions even on non-POSIX systems.
.P
.H 2 "Input/Output"
\f5ksh\fP uses \fBsfio\fP,
the Safe/Fast I/O library\*(Rf,
.RS
David Korn and Kiem-Phong Vo,
.IR "SFIO - A Safe/Fast Input/Output library,"
Proceedings of the Summer Usenix,
pp. , 1991.
.RF
to perform all I/O operations.
The \fBsfio\fP library, which is part of \fBlibast\fP,
provides a superset of the functionality provided by the standard
I/O library defined in ANSI-C.
If none of the additional functionality is required,
and if you are not familiar with \fBsfio\fP and
you do not want to spend the time learning it,
then you can use \fBsfio\fP via the \fBstdio\fP library
interface.  The development kit contains the header \f5<stdio.h>\fP
which maps \fBstdio\fP calls to \fBsfio\fP calls.
In most instances the mapping is done
by macros or inline functions so that there is no overhead.
The man page for the \fBsfio\fP library is in an Appendix.
.P
However, there are some very nice extensions and
performance improvements in \fBsfio\fP
and if you plan any major extensions I recommend
that you use it natively.
.H 2 "Error Handling"
For error messages it is best to use the \fBast\fP library
function \f5errormsg()\fP rather that sending output to
\f5stderr\fP or the equivalent \f5sfstderr\fP directly.
Using \f5errormsg()\fP will make error message appear
more uniform to the user.
Furthermore, using \f5errormsg()\fP should make it easier
to do error message translation for other locales
in future versions of \f5ksh\fP.
.P
The first argument to
\f5errormsg()\fP specifies the dictionary in which the string
will be searched for translation.
The second argument to \f5errormsg()\fP contains that error type
and value.  The third argument is a \fIprintf\fP style format
and the remaining arguments are arguments to be printed
as part of the message.  A new-line is inserted at the
end of each message and therefore, should not appear as
part of the format string.
The second argument should be one of the following:
.VL .5i
.LI \f5ERROR_exit(\fP\fIn\fP\f5)\fP:
If \fIn\fP is not-zero, the builtin will exit value \fIn\fP after
printing the message.
.LI \f5ERROR_system(\fP\fIn\fP\f5)\fP:
Exit builtin with exit value \fIn\fP after printing the message.
The message will display the message corresponding to \f5errno\fP
enclosed within \f5[\ ]\fP at the end of the message.
.LI \f5ERROR_usage(\fP\fIn\fP\f5)\fP:
Will generate a usage message and exit.  If \fIn\fP is non-zero,
the exit value will be 2.  Otherwise the exit value will be 0.
.LI \f5ERROR_debug(\fP\fIn\fP\f5)\fP:
Will print a level \fIn\fP debugging message and will then continue.
.LI \f5ERROR_warn(\fP\fIn\fP\f5)\fP:
Prints a warning message. \fIn\fP is ignored.
.H 2 "Option Parsing"
The first thing that a built-in should do is to check
the arguments for correctness and to print any usage
messages on standard error.
For consistency with the rest of \f5ksh\fP, it is best
to use the \f5libast\fP functions \f5optget()\fP and
\f5optusage()\fPfor this
purpose.
The header \f5<error.h>\fP included prototypes for
these functions.
The \f5optget()\fP function is similar to the
System V C library function \f5getopt()\fP,
but provides some additional capabilities.
Built-ins that use \f5optget()\fP provide a more
consistent user interface.
.P
The \f5optget()\fP function is invoked as
.nf
.in .5i
\f5int optget(char *argv[], const char *optstring)\fP
.in
.fi
where \f5argv\fP is the argument list and \f5optstring\fP
is a string that specifies the allowable arguments and
additional information that is used to format \fIusage\fP
messages.
In fact a complete man page in \f5troff\fP or \f5html\fP
can be generated by passing a usage string as described
by the \f5getopts\fP command.
Like \f5getopt()\fP,
single letter options are represented by the letter itself,
and options that take a string argument are followed by the \f5:\fP
character.
Option strings have the following special characters:
.VL .5i
.LI \f5:\fP
Used after a letter option to indicate that the option
takes an option argument.
The variable \f5opt_info.arg\fP will point to this
value after the given argument is encountered.
.LI \f5#\fP
Used after a letter option to indicate that the option
can only take a numerical value.
The variable \f5opt_info.num\fP will contain this
value after the given argument is encountered.
.LI \f5?\fP
Used after a \f5:\fP or \f5#\fP (and after the optional \f5?\fP)
to indicate the the
preceding option argument is not required.
.LI \f5[\fP...\f5]\fP
After a \f5:\fP or \f5#\fP, the characters contained
inside the brackets are used to identify the option
argument when generating a \fIusage\fP message. 
.LI \fIspace\fP
The remainder of the string will only be used when generating
usage messages.
.LE
.P
The \f5optget()\fP function returns the matching option letter if
one of the legal option is matched.
Otherwise, \f5optget()\fP returns
.VL .5i
.LI \f5':'\fP
If there is an error.  In this case the variable \f5opt_info.arg\fP
contains the error string.
.LI \f50\fP
Indicates the end of options.
The variable \f5opt_info.index\fP contains the number of arguments
processed.
.LI \f5'?'\fP
A usage message has been required.
You normally call \f5optusage()\fP to generate and display
the usage message.
.LE
.P
The following is an example of the option parsing portion
of the \f5wc\fP utility.
.nf
.in +5
\f5#include <shell.h>
while(1) switch(n=optget(argv,"xf:[file]"))
{
	case 'f':
		file = opt_info.arg;
		break;
	case ':':
		error(ERROR_exit(0), opt_info.arg);
		break;
	case '?':
		error(ERROR_usage(2), opt_info.arg);
		break;
}\fP
.in
.fi
.H 2 "Storage Management"
It is important that any memory used by your built-in
be returned.  Otherwise, if your built-in is called frequently,
\f5ksh\fP will eventually run out of memory.
You should avoid using \f5malloc()\fP for memory that must
be freed before returning from you built-in, because by default,
\f5ksh\fP will terminate you built-in in the event of an
interrupt and the memory will not be freed.
.P
The best way to to allocate variable sized storage is
through calls to the \fBstak\fP library
which is included in \fBlibast\fP
and which is used extensively by \f5ksh\fP itself.
Objects allocated with the \f5stakalloc()\fP
function are freed when you function completes
or aborts. 
The \fBstak\fP library provides a convenient way to
build variable length strings and other objects dynamically.
The man page for the \fBstak\fP library is contained
in the Appendix.
.P
Before \f5ksh\fP calls each built-in command, it saves
the current stack location and restores it after
it returns.
It is not necessary to save and restore the stack
location in the \f5b_\fP entry function, 
but you may want to write functions that use this stack
are restore it when leaving the function.
The following coding convention will do this in
an efficient manner:
.nf
.in .5i
\fIyourfunction\fP\f5()
{
        char	*savebase;
        int	saveoffset;
        if(saveoffset=staktell())
        	savebase = stakfreeze(0);
        \fP...\f5
        if(saveoffset)
        	stakset(savebase,saveoffset);
        else
        	stakseek(0);
}\fP
.in
.fi
.H 1 "CALLING \f5ksh\fP SERVICES"
Some of the more interesting applications are those that extend
the functionality of \f5ksh\fP in application specific directions.
A prime example of this is the X-windows extension which adds
builtins to create and delete widgets.
The \fBnval\fP library is used to interface with the shell
name space.
The \fBshell\fP library is used to access other shell services.
.H 2 "The nval library"
A great deal of power is derived from the ability to use
portions of the hierarchal variable namespace provided by \f5ksh-93\fP
and turn these names into active objects.
.P
The \fBnval\fP library is used to interface with shell
variables.
A man page for this file is provided in an Appendix.
You need to include the header \f5<nval.h>\fP
to access the functions defined in the \fBnval\fP library.
All the functions provided by the \fBnval\fP library begin
with the prefix \f5nv_\fP.
Each shell variable is an object in an associative table
that is referenced by name.
The type \f5Namval_t*\fP is pointer to a shell variable. 
To operate on a shell variable, you first get a handle
to the variable with the \f5nv_open()\fP function
and then supply the handle returned as the first
argument of the function that provides an operation
on the variable.
You must call \f5nv_close()\fP when you are finished
using this handle so that the space can be freed once
the value is unset.
The two most frequent operations are to get the value of
the variable, and to assign value to the variable.
The \f5nv_getval()\fP returns a pointer the the
value of the variable.
In some cases the pointer returned is to a region that
will be overwritten by the next \f5nv_getval()\fP call
so that if the value isn't used immediately, it should
be copied.
Many variables can also generate a numeric value.
The \f5nv_getnum()\fP function returns a numeric
value for the given variable pointer, calling the
arithmetic evaluator if necessary.
.P
The \f5nv_putval()\fP function is used to assign a new
value to a given variable.
The second argument to \f5putval()\fP is the value
to be assigned
and the third argument is a \fIflag\fP which
is used in interpreting the second argument.
.P
Each shell variable can have one or more attributes.
The \f5nv_isattr()\fP is used to test for the existence
of one or more attributes.
See the appendix for a complete list of attributes.
.P
By default, each shell variable passively stores the string you
give with with \f5nv_putval()\fP, and returns the value
with \f5getval()\fP.  However, it is possible to turn
any node into an active entity by assigning functions
to it that will be called whenever \f5nv_putval()\fP
and/or \f5nv_getval()\fP is called.
In fact there are up to five functions that can 
associated with each variable to override the
default actions.
The type \f5Namfun_t\fP is used to define these functions.
Only those that are non-\f5NULL\fP override the
default actions.
To override the default actions, you must allocate an
instance of \f5Namfun_t\fP, and then assign
the functions that you wish to override.
The \f5putval()\fP
function is called by the \f5nv_putval()\fP function.
A \f5NULL\fP for the \fIvalue\fP argument
indicates a request to unset the variable.
The \fItype\fP argument might contain the \f5NV_INTEGER\fP
bit so you should be prepared to do a conversion if
necessary.
The \f5getval()\fP
function is called by \f5nv_getval()\fP
value and must return a string.
The \f5getnum()\fP
function is called by by the arithmetic evaluator
and must return double.
If omitted, then it will call \f5nv_getval()\fP and
convert the result to a number.
.P
The functionality of a variable can further be increased
by adding discipline functions that
can be associated with the variable.
A discipline function allows a script that uses your
variable to define functions whose name is
\fIvarname\fP\f5.\fP\fIdiscname\fP
where \fIvarname\fP is the name of the variable, and \fIdiscname\fP
is the name of the discipline.
When the user defines such a function, the \f5settrap()\fP
function will be called with the name of the discipline and
a pointer to the parse tree corresponding to the discipline
function.
The application determines when these functions are actually
executed.
By default, \f5ksh\fP defines \f5get\fP,
\f5set\fP, and \f5unset\fP as discipline functions.
.P
In addition, it is possible to provide a data area that
will be passed as an argument to
each of these functions whenever any of these functions are called.
To have private data, you need to define and allocate a structure
that looks like
.nf
.in .5i
\f5struct \fIyours\fP
{
        Namfun_t	fun;
	\fIyour_data_fields\fP;
};\fP
.in
.fi
.H 2 "The shell library"
There are several functions that are used by \f5ksh\fP itself
that can also be called from built-in commands.
The man page for these routines are in the Appendix.
.P
The \f5sh_addbuiltin()\fP function can be used to add or delete
builtin commands.  It takes the name of the built-in, the
address of the function that implements the built-in, and
a \f5void*\fP pointer that will be passed to this function
as the third agument whenever it is invoked.
If the function address is \f5NULL\fP, the specified built-in
will be deleted.  However, special built-in functions cannot
be deleted or modified.
.P
The \f5sh_fmtq()\fP function takes a string and returns
a string that is quoted as necessary so that it can
be used as shell input.
This function is used to implement the \f5%q\fP option
of the shell built-in \f5printf\fP command.
.P
The \f5sh_parse()\fP function returns a parse tree corresponding
to a give file stream.  The tree can be executed by supplying
it as the first argument to
the \f5sh_trap()\fP function and giving a value of \f51\fP as the
second argument. 
Alternatively, the \f5sh_trap()\fP function can parse and execute
a string by passing the string as the first argument and giving \f50\fP
as the second argument.
.P
The \f5sh_isoption()\fP function can be used to set to see whether one
or more of the option settings is enabled.
