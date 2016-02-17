#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef struct _CacheEntry {
    unsigned char *domain;
    unsigned int ix;
} CacheEntry;

struct {
    CacheEntry *table;
    int size;
} cache;

int hash_code(unsigned char *domain) {
    int i = 0;
    for ( ; *domain; domain++ ) {
	i += *domain;
    }
    return i % cache.size;
}

/**
 * Look up a given domain and return its associated access code (>=0),
 * or -1 if not found.
 */
int lookup_cache(unsigned char *domain) {
    if ( cache.table ) {
	int i = hash_code( domain );
	if ( cache.table[i].domain &&
	     strcmp( (char*)  domain, (char*) cache.table[i].domain ) == 0 ) {
	    return cache.table[i].ix;
	}
    }
    return -1;
}

void add_cache(unsigned char *domain,unsigned int ix) {
    if ( cache.table == 0 ) {
	cache.size = 1024;
	cache.table = (CacheEntry*) calloc( cache.size, sizeof( CacheEntry ) );
    }
    int i = hash_code( domain );
    if ( cache.table[i].domain ) {
	free( cache.table[i].domain );
    }
    cache.table[i].domain =  (unsigned char*) strdup( (char*) domain );
    cache.table[i].ix = ix;
}
