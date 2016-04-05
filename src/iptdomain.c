#include <linux/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>

// Caching of verdicts
unsigned int lookup_cache(unsigned char *domain);
void add_cache(unsigned char *domain,unsigned int ix);
int hash_code(unsigned char *domain);

// Bad domains database
unsigned int check_domain(unsigned char *domain);
void load_domains(char *file);
void start_domain_database_loading(void);
void end_domain_database_loading(void);

/**
 * Return packet id, or 0 (on error).
 */
static u_int32_t get_packet_id(struct nfq_data *tb) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr( tb );
    return ( ph )? ntohl( ph->packet_id ) : 0;
}

/**
 * Return a pointer to a textual representation of the given IP
 * address. This uses an internal buffer that gets clobbered upon each
 * call.
 */
static unsigned char *tell_ip(u_int32_t ip) {
    static unsigned char THEIP[20];
    unsigned char *b = (unsigned char *)&ip;
    sprintf( (char*) THEIP, "%d.%d.%d.%d%c", b[0], b[1], b[2], b[3], 0 );
    return THEIP;
}

/**
 * Return the destination IP address from a packet.
 */
static u_int32_t get_dest_ip4(unsigned char *data) {
    return ((struct ip *) data)->ip_dst.s_addr;
}

/**
 * Return the start of the TCP data.
 */
static unsigned char*get_tcp_data(unsigned char *data) {
    unsigned char *p = data + sizeof( struct ip );
    return p + (((struct tcphdr *) p)->th_off) * 4;
}

/**
 * Print details of a packet to stderr.
 */
static void view_payload(unsigned char *data,int length) {
    u_int32_t ip4 = get_dest_ip4( data );
    struct tcphdr *tcp = (struct tcphdr *) data + sizeof( struct ip );
    u_int16_t port = ntohs( tcp->th_dport );
    u_int8_t syn = tcp->th_flags;
    unsigned char *body = get_tcp_data( data ) ;
    length -= body - data;
#define END 400
    unsigned char * end = body + ( ( length > END )? END : length );
    fprintf( stderr, "%s %d %d %d ", tell_ip( ip4 ), syn, port, length );
    while ( body < end ) {
	unsigned char c = *body++;
	if ( c < ' ' || c >= 127 || 1 ) {
	    fprintf( stderr, "%02x ", c );
	} else {
	    fprintf( stderr, "%c", c );
	}
    }
    fprintf( stderr, "\n" );
}

/**
 * This is a temporary buffer for holding extracted domain names. It
 * is used both by ssl_host and http_host
 */
static unsigned char buffer[1000];

#define DEBUG 0

/**
 * Return the host name of an SSL 'Client Hello' record with SNI
 * extension, or 0 when not found. This clobbers the buffer.
 */
static unsigned char *ssl_host(unsigned char *data,int length) {
    // Check that it's a "Client Hello" message
    unsigned char *p = get_tcp_data( data );
    // +12 skips the SSL record preamble;
    if ( p[0] != 0x16 || p[1] != 0x03 || p[5] != 0x01 || p[6] != 0x00 ) {
	return 0;
    }
    // record_length = 256 * p[3] + p[4]
    // handshake_message_length = 256 * p[7] + p[8]
    if ( 256 * p[3] + p[4] != 256 * p[7] + p[8] + 4 ) {
	return 0;
    }
#if DEBUG
    fprintf( stderr, "Client Hello\n" );
#endif
    // Note minor version p[2] is not checked
    for ( ;; ) {
	if ( p[9] != 0x03 || p[10] != 0x03 ) { // TLS 1.2 (?ralph?)
	    break;
	}
	//fprintf( stderr, "TLS 1.2\n" );
	unsigned int i = 43 + p[43] + 1;
	if ( i >= length ) {
	    break;
	}
	i += ( 256 * p[i] ) + p[i+1] + 2;
	if ( i >= length ) {
	    break;
	}
	i += p[i] + 1;
	if ( i >= length ) {
	    break;
	}
	unsigned int extensions_length = ( 256 * p[i] ) + p[i+1];
	i += 2;
	if ( i + extensions_length >= length ) {
	    break;
	}
	int k = 0;
	//fprintf( stderr, "TLS 1.2 %d %d\n", i, extensions_length );
	while ( k < extensions_length ) {
	    unsigned int type = ( 256 * p[i+k] ) + p[i+k+1];
	    k += 2;
	    unsigned int length = ( 256 * p[i+k] ) + p[i+k+1];
	    k += 2;
	    //fprintf( stderr, "Extension %d %d\n", k-4, type );
	    if ( type == 0 ) { // Server Name
		if ( p[i+k+2] ) {
		    break; // Name badness
		}
		unsigned int name_length = ( 256 * p[i+k+3] ) + p[i+k+4];
		unsigned char *path = &p[i+k+5];
		memcpy( buffer, path, name_length );
		buffer[ name_length ] = '\0';
		//fprintf( stderr, "SSL name %d %s\n", name_length, buffer );
		return buffer;
	    }
	    k += length;
	}
	break;
    }
    // This point is reached on "missing or bad SNI"
    // and for non TLS 1.2 packets.
    view_payload( data, length );
    strcpy( (char*) buffer, "domain.not.found" );
    return buffer;
}

/**
 * HTTP traffic includes a data packet with the host name as a
 * "Host:" attribute.
 */
static unsigned char *http_host(unsigned char *data,int length) {
    unsigned char *body = get_tcp_data( data );
    if ( ( strncmp( (char*) body, "GET ", 4 ) != 0 ) &&
	 ( strncmp( (char*) body, "POST ", 5 ) != 0 ) ) {
	return 0;
    }
    unsigned char *end = data + length - 6;
    int check = 0;
    for ( ; body < end; body++ ) {
	if ( check ) {
	    if ( strncmp( (char*) body, "Host:", 5 ) == 0 ) {
		body += 5;
		for( ; body < end; body++ ) if ( *body != ' ' ) break;
		unsigned char *start = body;
		int n = 0;
		for( ; body < end; n++, body++ ) if ( *body <= ' ' ) break;
		if ( n < 5 ) {
		    return 0;
		}
		memcpy( buffer, start, n );
		buffer[ n ] = '\0';
		return buffer;
	    }
	    if ( strncmp( (char*) body, "\r\n", 2 ) == 0 ) {
		break;
	    }
	    for( ; body < end; body++ ) if ( *body == '\n' ) break;
	    if ( body >= end ) {
		break;
	    }
	}
	check = ( *body == '\n' );
    }
    strcpy( (char*) buffer, "domain.not.found" );
    return buffer;
}

/**
 * Callback function to handle a packet.
 */
static int handle_packet(
    struct nfq_q_handle *qh,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa, void *code )
{
    u_int32_t id = get_packet_id( nfa );
    unsigned char *data;
    int length = nfq_get_payload( nfa, &data );
    int verdict = NF_ACCEPT;
#if DEBUG
    view_payload( data, length );
    u_int32_t ip4 = get_dest_ip4( data );
#endif
    if ( length >= 90 ) {
#if DEBUG
	char *tag = "HTTP";
#endif
	unsigned char *host = http_host( data, length );
	if ( host == 0 ) {
#if DEBUG
	    tag = "SSL";
#endif
	    host = ssl_host( data, length );
	}
	if ( host ) {
	    unsigned char *p = host; // host points at the static buffer
	    for ( ; *p; p++ ) {
		if ( *p == '.' ) {
		    continue;
		}
		if ( *p > '9' || *p < '0' ) {
		    break;
		}
	    }
	    if ( *p == 0 ) {
		strcpy( (char*) ( buffer + strlen( (char*) host ) ),
			".ip.address.found" );
	    }
	    int i = lookup_cache( host );
#if DEBUG
	    fprintf( stderr, "%s %s %s cache %d\n",
		     tell_ip( ip4 ), tag, host, i );
#endif
	    if ( i < 0 ) {
		unsigned int ix = check_domain( host );
		add_cache( host, ix );
		fprintf( stderr, "%s check %d\n", host, ix );
		if ( ix > 0 ) {
		    verdict = NF_DROP;
		}
	    } else if ( i > 0 ) {
		verdict = NF_DROP;
	    }
	} else {
#if DEBUG
	    fprintf( stderr, "%s no host\n", tell_ip( ip4 ) );
#endif
	}
    } else {
#if DEBUG
      fprintf( stderr, "%s short packet %d\n", tell_ip( ip4 ), length );
#endif
    }
    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

/**
 * Program main function.
 */
int main(int argc, char **argv) {
    start_domain_database_loading();
    int n = 1;
    for ( ; n < argc; n++ ) {
	fprintf( stderr, "Loading blacklist %s\n", argv[ n ] );
	load_domains( argv[ n ] );
    }
    end_domain_database_loading();

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    int THEQUEUE = 99;
    char buf[4096] __attribute__ ((aligned));
    
    if ( getenv( "IPTDOMAIN_QUEUE" ) ) {
	sscanf( getenv( "IPTDOMAIN_QUEUE" ), "%d",&THEQUEUE );
	if ( THEQUEUE < 0 || THEQUEUE >= 65536 ) {
	    THEQUEUE = 99;
	}
    }

    //fprintf( stderr, "opening library handle\n");
    h = nfq_open();
    if ( !h ) {
	fprintf(stderr, "error during nfq_open()\n");
	exit(1);
    }
    
    //fprintf( stderr, "unbinding any existing nf_queue handler\n" );
    if ( nfq_unbind_pf(h, AF_INET) < 0 ) {
	fprintf(stderr, "error during nfq_unbind_pf()\n");
	exit(1);
    }
    
    //fprintf( stderr, "binding nfnetlink_queue as nf_queue handler\n" );
    if ( nfq_bind_pf(h, AF_INET) < 0 ) {
	fprintf(stderr, "error during nfq_bind_pf()\n");
	exit(1);
    }

    fprintf( stderr, "Binding to netfilter queue '%d'\n", THEQUEUE );
    qh = nfq_create_queue( h,  THEQUEUE, &handle_packet, NULL );
    if ( !qh ) {
	fprintf(stderr, "error during nfq_create_queue()\n");
	exit(1);
    }
    
    //fprintf( stderr, "setting copy_packet mode\n" );
    if ( nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff ) < 0) {
	fprintf(stderr, "can't set packet_copy mode\n");
	exit(1);
    }
    
    fd = nfq_fd( h );
    
    while ( ( rv = recv(fd, buf, sizeof(buf), 0) ) && rv >= 0 ) {
	//printf( "pkt received\n" );
	nfq_handle_packet(h, buf, rv);
    }
    
    fprintf( stderr, "Detaching from queue %d\n", THEQUEUE);
    nfq_destroy_queue(qh);
    
    //fprintf( stderr, "closing library handle\n");
    nfq_close( h );
    
    exit( 0 );
}
