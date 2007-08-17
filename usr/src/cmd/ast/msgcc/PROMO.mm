.H 1 msgcc
.B msgcc
and
.B msgcpp
extract message text from C source for
.BR gencat (1)
message catalogs.
.BR msggen (1)
is a
.BR gencat (1)
replacement that generates machine independent binary message
catalogs that are compatible with the
.B ast
.BR catgets (3)
implementation.
.B catgets
also supports native message catalogs where available.
.BR msgcvt (1)
and
.BR msgadmin (1)
are administrative commands that support machine translation
of C locale message catalogs.
