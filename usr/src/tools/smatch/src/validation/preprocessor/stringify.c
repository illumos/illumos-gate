#define A(x) #x
A('a')
A("a")
A(a)
A(\n)
A('\n')
A("\n")
A('"')
A("a\nb")
A(L"a\nb")
A('\12')
/*
 * check-name: Preprocessor #14
 * check-command: sparse -E $file
 *
 * check-output-start

"'a'"
"\"a\""
"a"
"\n"
"'\\n'"
"\"\\n\""
"'\"'"
"\"a\\nb\""
"L\"a\\nb\""
"'\\12'"
 * check-output-end
 */
