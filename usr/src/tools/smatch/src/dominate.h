#ifndef DOMINATE_H
#define DOMINATE_H

struct entrypoint;
struct basic_block_list;

void idf_compute(struct entrypoint *ep, struct basic_block_list **idf, struct basic_block_list *alpha);


// For debugging only
void idf_dump(struct entrypoint *ep);

#endif
