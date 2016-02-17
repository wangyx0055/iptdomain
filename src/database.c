#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * This file implements a "database" of "bad" domains, loaded from
 * ".acl" files of a fairly strict format; each domain to block is
 * written on a line starting with a period, immediately followed by
 * the domain to block, then an optional comment.
 *
 * The database is populated by using the call sequence:
 * 1. start_domain_database_loading();
 * 2. load_domains( filename ); // repeated
 * N. end_domain_database_loading();
 *
 * The final call triggers a reordering of domains so as to support
 * binary search in reverse text order, for matching domain suffixes.
 * See the function `tail_compare` for details.
 */

/**
 * This is the Entry type for the "database", which basically is an
 * array of these. The domain pointer will point at a domain name in
 * the loaded ".acl" file, and length is the domain name length.
 */
typedef struct _Entry {
    int length;
    unsigned char *domain;
} Entry;

/**
 * This is the domain name database root structure. It holds a pointer
 * to the array of Entry records, the fill of that array, and the
 * allocated size for that array (no lesser than the fill, of course).
 */
static struct {
    Entry *table;
    int fill;
    int size;
} database = { 0, 0, 0 };

/**
 * This function compares strings backwars; the last k bytes of string
 * (a,na) versus string (b,nb). It also holds '.' as the least of
 * characters, so as to ensure that refined/extended domain names are
 * comparatively greater that their base domain names.
 */
static int tail_compare(unsigned char *a,unsigned char *b,int k) {
    while ( k-- > 0 ) {
	int c = *(--a) - *(--b);
	if ( c != 0) {
	    if ( *a == '.' ) {
		return -1;
	    }
	    if ( *b == '.' ) {
		return 1;
	    }
	    return c;
	}
    }
    return 0;
}

/**
 * Extend the domain name table to allow additions.
 */
#define STARTSIZE 100000
static void grow() {
    if ( database.table ) {
	Entry *old = database.table;
	int s = database.size;
	database.size += 100000;
	database.table = (Entry*) calloc( database.size, sizeof( Entry ) );
	memcpy( database.table, old, s * sizeof( Entry ) );
	free( old );
    } else {
	database.table = (Entry*) calloc( STARTSIZE, sizeof( Entry ) );
	database.size = STARTSIZE;
    }
}

/**
 * Determine the index for given domain. This matches computes a tail
 * match between the given domain and the databse domains, returning
 * the index for the matching database entry, or (-index-1) to
 * indicate insertion point. In lookup mode, a database entry being a
 * tail domain part of the given domain is also considered a match.
 */
static int index_domain(unsigned char *domain,int n,int lookup) {
    int lo = 0;
    int hi = database.fill;
    while ( lo < hi ) {
	int m = ( lo + hi ) / 2;
	Entry *p = &database.table[ m ];
	int k = p->length;
	if ( n < k ) {
	    k = n;
	}
	int q = tail_compare( p->domain + p->length, domain + n, k );
#if 0
	fprintf( stderr, "%s %d %d %d\n", domain, k, m, q );
#endif
	if ( q == 0 ) {
	    if ( p->length < n ) {
		// table entry shorter => new entry after, or match on lookup
		if ( lookup && *(domain+n-k-1) == '.' ) {
		    return m;
		}
		lo = m + 1;
	    } else if ( p->length > n ) {
		// table entry longer  => new entry before
		hi = m;
	    } else {
		// equal
		return m;
	    }
	} else if ( q < 0 ) {
	    // new entry after
	    lo = m + 1;
	} else {
	    // new entry before
	    hi = m;
	}
    }
    return -lo - 1;
}

/**
 * Determine the length of a "word"
 */
static int wordlen(unsigned char *p) {
    unsigned char *q = p;
    while ( *q > ' ' ) {
	q++;
    }
    return q - p;
}

#if 0
static void add_domain(char *domain) {
    if ( database.fill >= database.size ) {
	grow();
    }
    int length = wordlen( domain );
    int i = index_domain( domain, length, 0 );
    if ( i < 0 ) {
	i = -i-1;
	int tail = database.fill - i;
	if ( tail ) {
	    memmove( &database.table[ i+1 ],
		     &database.table[i],
		     tail * sizeof( Entry ) );
	}
	database.table[ i ].domain = domain;
	database.table[ i ].length = length;
	database.fill++;
    } else {
	char *p1 = strndup( domain, length );
	char *p2 = strndup( database.table[i].domain,
			    database.table[i].length );
	fprintf( stderr, "fill = %d %d %s  == %s\n",
		 i, database.fill, p1, p2 );
	free( p1 );
	free( p2 );
    }
}
#endif 

static void fast_add_domain(unsigned char *domain,int length) {
    int fill = database.fill;
    if ( fill >= database.size ) {
	grow();
    }
    database.table[ fill ].length = length;
    database.table[ fill ].domain = domain;
    database.fill++;
}

static int table_order(Entry *a,Entry *b) {
    int k = ( a->length < b->length )? a->length : b->length;
    int c = tail_compare( a->domain + a->length,
			  b->domain + b->length, k );
    if ( c != 0 ) {
	return c;
    }
    return a->length - b->length;
}

/**
 * External call to check a given domain.
 */
unsigned int check_domain(unsigned char *domain) {
    int i = index_domain( domain, wordlen( domain ), 1 );
    return ( i < 0 )? 0 : ( i + 1 );
}

void start_domain_database_loading(void) {
}

#if 0
static void dump_table() {
    fprintf( stderr, "Table fill=%d size=%d\n", database.fill, database.size );
    int i = 0;
    for ( ; i < database.fill; i++ ) {
	char *p = strndup( database.table[i].domain,
			   database.table[i].length );
	fprintf( stderr, "[%d] %d %p %s\n",
		 i, database.table[i].length, database.table[i].domain, p );
	free( p );
    }
}
#endif

void end_domain_database_loading(void) {
    qsort( database.table, database.fill, sizeof( Entry ),
	   (__compar_fn_t) table_order );
    //dump_table();
}

/**
 * Load BAD domain names from file. The file is line based where data
 * lines consist of domain name starting with period and ending with
 * space or newline, and other lines ignored.
 */
void load_domains(char *file) {
    struct stat info;
    unsigned char *data;
    //fprintf( stderr, "state(\"%s\",&info)\n", file );
    if ( stat( file, &info ) ) {
	perror( file );
	exit( 1 );
    }
    int n = info.st_size;
    data = (unsigned char *) malloc( n );
    //fprintf( stderr, "open(\"%s\",)\n", file );
    int fd = open( file, O_RDONLY );
    if ( fd < 0 ) {
	perror( file );
	exit( 1 );
    }
    //fprintf( stderr, "Loading %s\n", file );
    unsigned char *end = data;
    while ( n > 0 ) {
	int k = read( fd, end, n );
	if ( k == 0 ) {
	    fprintf( stderr, "Premature EOF for %s\n", file );
	    exit( 1 );
	}
	end += k;
	n -= k;
    }
    //fprintf( stderr, "processing %s %p %p\n", file, data, end );
    unsigned char *p = data;
#if 0
    int count = 0;
#endif
    while( p < end ) {
#if 0
	if ( ( ++count % 10000 ) == 0 ) {
	    fprintf( stderr, "%d rules\n", count );
	}
#endif
	if ( *p == '.' ) {
	    unsigned char *domain = ++p;
	    while ( *p > ' ' ) {
		p++;
	    }
	    fast_add_domain( domain, p - domain );
	}
	while ( p < end && *p != '\n' ) {
	    p++;
	}
	p++;
    }
    close( fd );
}
