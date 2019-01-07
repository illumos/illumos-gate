Why hacking on sparse
=====================

1. sparse is small.  
   The full project compiles in less than 10 seconds on old and not performing laptop.
2. sparse is fast.  
   Typically, sparse can check a C file 1/10 of time it takes for gcc to generate object files.
3. sparse can digest the full kernel source files.  
   With sparse-llvm, sparse uses llvm as back end to emit real machine code.

New developer hacking on sparse
==============================


* All sparse warning messages should include the option how
   to disable it.  
       e.g. "pre-process.c:20*:28: warning: Variable length array is used."
       should be something like   
        "pre-process.c:20*:28: warning: Variable length array is
used. (-Wno-vla)"
* extend test-inspect to inspect more AST fields.
* extend test-inspect to inspect instructions.
* adding architecture handling in sparse similar to cgcc
* parallel processing of test-suite
* Howto: fix the kernel rcu related checker warnings
* option to disable AST level inline.
* debug: debug version of sparse do all the verification double check
* test suite: verify and compare IR (suggested by Dibyendu Majumdar)
* checker error output database

For experienced developers
==========================

* merge C type on incremental declare of C type and function prototype.
* move attribute out of ctype to allow easier to add new attribute.
* serialize, general object walking driven by data structures.
* serialize, write sparse byte code into file
* serialize, load sparse byte code from file.
* symbol index/linker, know which symbol in which byte code file.
* inline function in instruction level
* cross function checking
* debug: optimization step by step log
* debug: fancy animation of CFG
* phi node location (Luc has patch)
* revisit crazy programmer warning, invalid SSA form.
* ptrlist, looping while modify inside the loop.
* dead code elimination using ssa
* constant propagation using ssa.
* x86/arm back end instruction set define
* register allocation.
* emit x86/arm machine level code

