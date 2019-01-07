/*
 * Each iteration of the scanning of "SCAN()" re-evaluates the recursive
 * B->A->B expansion.
 *
 * Did I already mention that the C preprocessor language
 * is a perverse thing?
 */

#define LP (

#define A() B LP )
#define B() A LP )

#define SCAN(x) x

A()                     // B ( )
SCAN( A() )             // A ( )
SCAN(SCAN( A() ))       // B ( )
SCAN(SCAN(SCAN( A() ))) // A ( )
/*
 * check-name: Preprocessor #3
 * check-description: Sparse used to get this wrong, outputting A third, not B.
 * check-command: sparse -E $file
 *
 * check-output-start

B ( )
A ( )
B ( )
A ( )
 * check-output-end
 */
