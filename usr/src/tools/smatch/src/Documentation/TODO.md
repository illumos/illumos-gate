TODO
====

Essential
---------
* SSA is broken by simplify_loads() & branches rewriting/simplification
* attributes of struct, union & enums are ignored (and possibly in other
  cases too).
* add support for bitwise enums

Documentation
-------------
* document the extensions
* document the API
* document the limitations of modifying ptrlists during list walking
* document the data structures
* document flow of data / architecture / code structure

Core
----
* if a variable has its address taken but in an unreachable BB then
  its MOD_ADDRESSABLE may be wrong and it won't be SSA converted.
  - let kill_insn() check killing of SYMADDR,
  - add the sym into a list and
  - recalculate the addressability before memops's SSA conversion
* bool_ctype should be split into internal 1-bit / external 8-bit
* Previous declarations and the definition need to be merged. For example,
  in the code here below, the function definition is **not** static:
  ```
	static void foo(void);
	void foo(void) { ... }
  ```

Testsuite
--------
* there are more than 50 failing tests. They should be fixed
  (but most are non-trivial to fix).

Misc
----
* GCC's -Wenum-compare / clangs's -Wenum-conversion -Wassign-enum
* parse __attribute_((fallthrough))
* add support for __builtin_unreachable()
* add support for format(printf())  (WIP by Ben Dooks)
* make use of UNDEFs (issues warnings, simplification, ... ?)
* add a pass to inline small functions during simplification.

Optimization
------------
* the current way of doing CSE uses a lot of time
* add SSA based DCE
* add SSA based PRE
* Add SSA based SCCP
* use better/more systematic use of internal verification framework

IR
--
* OP_SET should return a bool, always
* add IR instructions for va_arg() & friends
* add a possibility to import of file in "IR assembly"
* dump the symtable
* dump the CFG

LLVM
----
* fix ...

Internal backends
-----------------
* add some basic register allocation
* add a pass to transform 3-addresses code to 2-addresses
* what can be done for x86?

Longer term/to investigate
--------------------------
* better architecture handling than current machine.h + target.c
* attributes are represented as ctypes's alignment, modifiers & contexts
  but plenty of attributes doesn't fit, for example they need arguments.
  * format(printf, ...),
  * section("...")
  * assume_aligned(alignment[, offsert])
  * error("message"), warning("message")
  * ...
* should support "-Werror=..." ?
* All warning messages should include the option how to disable it.
  For example:
  	"warning: Variable length array is used."
  should be something like:
	"warning: Variable length array is used. (-Wno-vla)"
* ptrlists must have elements be removed while being iterated but this
  is hard to insure it is not done.
* having 'struct symbol' used to represent symbols *and* types is
  quite handy but it also creates lots of problems and complications
* Possible mixup of symbol for a function designator being not a pointer?
  This seems to make evaluation of function pointers much more complex
  than needed.
* extend test-inspect to inspect more AST fields.
* extend test-inspect to inspect instructions.
