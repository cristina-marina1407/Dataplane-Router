// Postelnicu Cristina-Marina 323CA
#ifndef TRIE_H
#define TRIE_H

#include "protocols.h"
#include <arpa/inet.h>

typedef struct trie_node_t {
	struct trie_node_t *left;
	struct trie_node_t *right;
	struct route_table_entry *route;
} trie_node_t;

trie_node_t* trie_create();
void trie_insert(trie_node_t *root, struct route_table_entry *route);
struct route_table_entry* trie_search(trie_node_t *root, uint32_t ip);
void trie_free(trie_node_t *root);

#endif
