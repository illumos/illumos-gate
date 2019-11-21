static unsigned a(unsigned b, unsigned c) { (c << 1 | b & 1 << 1) >> 1; }

/*
 * check-name: catch crashes during AND-OR simplifications
 */
