static void foo(int x)
{
	__context__(0);		// OK
	__context__(x, 0);	// OK
	__context__ (x, 1);	// OK

	__context__(x);		// KO: no const expr
	__context__(1,x);	// KO: no const expr

	__context__;		// KO: no expression at all
	__context__(;		// KO: no expression at all

	__context__ 0;		// KO: need parens
	__context__ x, 0;	// KO: need parens
	__context__(x, 0;	// KO: unmatched parens
	__context__ x, 0);	// KO: unmatched parens
	__context__(0;		// KO: unmatched parens
	__context__ 0);		// KO: unmatched parens

	__context__();		// KO: no expression at all
	__context__(,0);	// KO: no expression at all
	__context__(x,);	// KO: no expression at all
	__context__(,);		// KO: no expression at all
}

/*
 * check-name: context-stmt
 * check-command: sparse -Wno-context $file
 *
 * check-error-start
context-stmt.c:10:20: error: Expected ( after __context__ statement
context-stmt.c:10:20: error: got ;
context-stmt.c:11:21: error: expression expected after '('
context-stmt.c:11:21: error: got ;
context-stmt.c:11:21: error: Expected ) at end of __context__ statement
context-stmt.c:11:21: error: got ;
context-stmt.c:13:21: error: Expected ( after __context__ statement
context-stmt.c:13:21: error: got 0
context-stmt.c:14:21: error: Expected ( after __context__ statement
context-stmt.c:14:21: error: got x
context-stmt.c:15:25: error: Expected ) at end of __context__ statement
context-stmt.c:15:25: error: got ;
context-stmt.c:16:21: error: Expected ( after __context__ statement
context-stmt.c:16:21: error: got x
context-stmt.c:17:22: error: Expected ) at end of __context__ statement
context-stmt.c:17:22: error: got ;
context-stmt.c:18:21: error: Expected ( after __context__ statement
context-stmt.c:18:21: error: got 0
context-stmt.c:20:21: error: expression expected after '('
context-stmt.c:20:21: error: got )
context-stmt.c:21:21: error: expression expected after '('
context-stmt.c:21:21: error: got ,
context-stmt.c:22:23: error: expression expected after ','
context-stmt.c:22:23: error: got )
context-stmt.c:23:21: error: expression expected after '('
context-stmt.c:23:21: error: got ,
context-stmt.c:23:22: error: expression expected after ','
context-stmt.c:23:22: error: got )
context-stmt.c:7:21: error: bad constant expression
context-stmt.c:8:23: error: bad constant expression
 * check-error-end
 */
