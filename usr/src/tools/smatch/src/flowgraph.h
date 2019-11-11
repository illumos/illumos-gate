#ifndef FLOWGRAPH_H
#define FLOWGRAPH_H

#include <stdbool.h>

struct entrypoint;
struct basic_block;

int cfg_postorder(struct entrypoint *ep);
void domtree_build(struct entrypoint *ep);
bool domtree_dominates(struct basic_block *a, struct basic_block *b);

#endif
