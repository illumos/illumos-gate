# The third argument to match() is a GNU-specific extension, so the
# two following tests have been replaced with similar ones that use
# RSTART and RLENGTH:
#
# match($0, /([Nn]ew) Value +[\([]? *([[:upper:]]+)/, f) {
# 	print "re1", NR, f[1], f[2]
# }
# 
# match($0, /([][])/, f) {
# 	print "re2", NR, f[1]
# }

match($0, /([Nn]ew)/) {
	print "re1.1", NR, substr($0, RSTART, RLENGTH)
}

match($0, /[\([] *([[:upper:]]+)/) {
	print "re1.2", NR, substr($0, RSTART+1, RLENGTH-1)
}

match($0, /([][])/) {
	print "re2", NR, substr($0, RSTART, RLENGTH)
}

/[]]/ {
	print "re3", NR, $0
}

/[\[]/ {
	print "re4", NR, $0
}

/[[]/ {
	print "re5", NR, $0
}

/[][]/ {
	print "re6", NR, $0
}

/[\([][[:upper:]]*/ {
	print "re7", NR, $0
}

/[\([]/ {
	print "re8", NR, $0
}
