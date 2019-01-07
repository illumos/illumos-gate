#define A(x) L##x
A('a')
A("bc")
/*
 * check-name: wide char token-pasting
 * check-description: Used to cause infinite recursion.
 * check-command: sparse -E $file
 *
 * check-output-start

L'a'
L"bc"
 * check-output-end
 */

