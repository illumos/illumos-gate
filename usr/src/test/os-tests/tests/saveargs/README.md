# Tests for **libsaveargs**

## Tests in the test suite

### functional

A set of programs with a variety of paths through the argument-passing ABI.
Verifying that `pstack(1)` can display arguments (testing the plumbing through
`libproc(3LIB)`).

Each program is expected to display its arguments as they truly are and then
flush `stdout` to indicate to the test runner that the stack is ready.

### testmatch

A stub program that tests the matcher against a variety of
function prologues (assembled from `data.S`)

## Other tests

There are further tests in `usr/src/lib/libsaveargs/tests`, most usefully
`dump` which given an object displays what **libsaveargs** thinks of
each function symbol in that object.
