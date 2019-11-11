char *caddv(char *p, int o) { char *r = p; r = r + o; return r; }
void *vaddv(void *p, int o) { void *r = p; r = r + o; return r; }
int  *iaddv(int  *p, int o) { int  *r = p; r = r + o; return r; }

char *caddc(char *p, int o) { char *r = p; r = r + 3; return r; }
void *vaddc(void *p, int o) { void *r = p; r = r + 3; return r; }
int  *iaddc(int  *p, int o) { int  *r = p; r = r + 3; return r; }

char *cincv(char *p, int o) { char *r = p; r += o; return r; }
void *vincv(void *p, int o) { void *r = p; r += o; return r; }
int  *iincv(int  *p, int o) { int  *r = p; r += o; return r; }

char *cincc(char *p, int o) { char *r = p; r += 3; return r; }
void *vincc(void *p, int o) { void *r = p; r += 3; return r; }
int  *iincc(int  *p, int o) { int  *r = p; r += 3; return r; }


char *ciniaddv(char *p, int o) { char *r = p + o; return r; }
void *viniaddv(void *p, int o) { void *r = p + o; return r; }
int  *iiniaddv(int  *p, int o) { int  *r = p + o; return r; }

char *ciniaddc(char *p, int o) { char *r = p + 3; return r; }
void *viniaddc(void *p, int o) { void *r = p + 3; return r; }
int  *iiniaddc(int  *p, int o) { int  *r = p + 3; return r; }

char *ciniincv(char *p, int o) { char *r = p += o; return r; }
void *viniincv(void *p, int o) { void *r = p += o; return r; }
int  *iiniincv(int  *p, int o) { int  *r = p += o; return r; }

char *ciniincc(char *p, int o) { char *r = p += 3; return r; }
void *viniincc(void *p, int o) { void *r = p += 3; return r; }
int  *iiniincc(int  *p, int o) { int  *r = p += 3; return r; }


char *cretaddv(char *p, int o) { return p + o; }
void *vretaddv(void *p, int o) { return p + o; }
int  *iretaddv(int  *p, int o) { return p + o; }

char *cretaddc(char *p, int o) { return p + 3; }
void *vretaddc(void *p, int o) { return p + 3; }
int  *iretaddc(int  *p, int o) { return p + 3; }

char *cretincv(char *p, int o) { return p += o; }
void *vretincv(void *p, int o) { return p += o; }
int  *iretincv(int  *p, int o) { return p += o; }

char *cretincc(char *p, int o) { return p += 3; }
void *vretincc(void *p, int o) { return p += 3; }
int  *iretincc(int  *p, int o) { return p += 3; }

/*
 * check-name: pointer-add
 * check-command: sparsec -Wno-decl -c $file -o r.o
 */
