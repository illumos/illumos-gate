# regression tests for the msgcc utility

TEST 01 'basics'
	EXEC -c t.c
		NOTE 'pp:allpossible'
		INPUT t.c $'
			#include <foo-bar.h>
			void f(void)
			{
			#if 0
				error(1, "foo bar");
			#else
				errormsg(locale, 2, "%s: bar foo");
			#endif
			}
		'
		OUTPUT t.mso $'str "foo bar"\nstr "%s: bar foo"'
		OUTPUT -
	EXEC -Dfprintf=_STDIO_ -c t.c
		NOTE 'ignore readonly redefinitions'
		INPUT t.c $'
			#define stderr foo
			void f(void)
			{
				fprintf(stderr, "foo bar");
			}
		'
		OUTPUT t.mso $'str "foo bar"'
