.xx title="astsa"
.MT 4
.TL

.H 1 "astsa"
.B astsa
implements a small subset of the
.B ast
library for other
.B ast
standalone commands and libraries using X/Open interfaces. 
.P
To get better performance and functionality, consider using any of
the full-featured ast-* packages at
.DS
.xx link="http://www.research.att.com/sw/download/"
.DE
.P
astsa.omk is an old make makefile that builds the headers and objects
and defines these variables for use in other makefiles
.VL 12
.LI
.B ASTSA_GEN
point -I to these
.LI
.B ASTSA_HDRS
point -I to these
.LI
.B AST_OBJS
link against these
.LE
The astsa files may be combined in a single directory with other ast
standalone packages.
