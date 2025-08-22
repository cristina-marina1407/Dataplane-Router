// Postelnicu Cristina-Marina 323CA
#include "trie.h"
#include "lib.h"
#include <stdlib.h>
#include <stdint.h>


/* Function to create a new trie node */
trie_node_t* trie_create() {
	trie_node_t *node = malloc(sizeof(trie_node_t));
	node->left = NULL;
	node->right = NULL;
	node->route = NULL;
	return node;
}

/* Function to insert a route into the trie */
void trie_insert(trie_node_t *root, struct route_table_entry *route) {
	trie_node_t *current_node = root;

	uint32_t prefix = htonl(route->prefix);
	uint32_t mask = htonl(route->mask);

	for (int i = 31; i >= 0; i--) {
		if (!(mask & (1 << i))) {
			break;
		}
		int bit = (prefix >> i) & 1;
		if (bit == 0) {
			if (!current_node->left) {
				current_node->left = trie_create();
			}
			current_node = current_node->left;
		} else {
			if (!current_node->right) {
				current_node->right = trie_create();
			}
			current_node = current_node->right;
		}
	}
	current_node->route = route;
}

/* Function to search for the best matching route in the trie */
struct route_table_entry* trie_search(trie_node_t *root, uint32_t ip) {
	trie_node_t *current_node = root;
	struct route_table_entry *best_match = NULL;

	uint32_t next_ip = ntohl(ip);

	for (int i = 31; i >= 0; i--) {
		if (current_node->route) {
			best_match = current_node->route;
		}

		int bit = (next_ip >> i) & 1;
		if (bit == 0) {
			if (!current_node->left) {
				break;
			}
			current_node = current_node->left;
		} else {
			if (!current_node->right) {
				break;
			}
			current_node = current_node->right;
		}
	}
	return best_match;
}

/* Function to free the memory used by the trie */
void trie_free(trie_node_t *root) {
	if (!root) return;
	trie_free(root->left);
	trie_free(root->right);
	free(root);
}
