/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "ferret.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "util-housekeeping.h"
#include "stack-tcpchecksum.h"
#include "stack-smells.h"

#include <ctype.h>
#include <string.h>
#include <assert.h>

static void tcp_housekeeping(struct Housekeeping *housekeeper, void *housekeeping_data, time_t now, struct NetFrame *frame);
extern void VALIDATE(int exp);

enum {
	TCP_FIN=1,
	TCP_SYN=2,
	TCP_RST=4,
	TCP_PSH=8,
	TCP_ACK=16,
	TCP_URG=32,
};

enum {
	TCP_LOOKUP,
	TCP_CREATE,
	TCP_DESTROY,
};

static void tcp_syn(struct Ferret *ferret, struct NetFrame *frame)
{
	UNUSEDPARM(ferret);UNUSEDPARM(frame);
}
static void tcp_synack(struct Ferret *ferret, struct NetFrame *frame)
{
	UNUSEDPARM(ferret);UNUSEDPARM(frame);
}
static void tcp_fin(struct Ferret *ferret, struct NetFrame *frame)
{
	UNUSEDPARM(ferret);UNUSEDPARM(frame);
}

FERRET_PARSER reverse_parser(FERRET_PARSER forward)
{
	if (parse_http_request == forward)
		return (FERRET_PARSER)parse_http_response;
	if (parse_rdp_request == forward)
		return (FERRET_PARSER)parse_rdp_response;
	if (process_simple_smtp_request == forward)
		return (FERRET_PARSER)process_simple_smtp_response;
	if (parse_ssl_request == forward)
		return (FERRET_PARSER)parse_ssl_response;
	if (parse_dcerpc_request == forward)
		return (FERRET_PARSER)parse_dcerpc_response;
	if (parse_smb_request == forward)
		return (FERRET_PARSER)parse_smb_response;


	return 0;
}


/**
 * Runs a heuristic over the packet data to see if it looks like the HTTP 
 * protocol. This is because we can't rely upon HTTP running on port 80,
 * it can run on any arbitrary port */
static int 
smellslike_httprequest(const unsigned char *data, unsigned length)
{
	unsigned i;
	unsigned method;
	unsigned url;

	for (i=0; i<length && isspace(data[i]); i++)
		;
	method = i;
	while (i<length && !isspace(data[i]))
		i++;
	if (i>10)
		return 0;
	while (i<length && isspace(data[i]))
		i++;
	url = i;
	while (i<length && data[i] != '\n')
		i++;

	if (i>0 && data[i] == '\n') {
		i--;

		if (i>0 && data[i] == '\r')
			i--;

		if (i>10 && strnicmp((const char*)&data[i-7], "HTTP/1.0", 8) == 0)
			return 1;
		if (i>10 && strnicmp((const char*)&data[i-7], "HTTP/1.1", 8) == 0)
			return 1;
		if (i>10 && strnicmp((const char*)&data[i-7], "HTTP/0.9", 8) == 0)
			return 1;
		
	}

	return 0;
}

int smellslike_msn_messenger(const unsigned char *data, unsigned length)
{
	unsigned i=0;
	unsigned method;
	unsigned method_length=0;
	unsigned parms;
	unsigned non_printable_count = 0;
	unsigned line_length;

	if (smellslike_httprequest(data, length))
		return 0;


	method = i;
	while (i<length && !isspace(data[i]))
		i++, method_length++;;
	while (i<length && data[i] != '\n' && isspace(data[i]))
		i++;
	parms = i;
	while (i<length && data[i] != '\n')
		i++;
	line_length = i;

	for (i=0; i<length; i++)
		if (!(isprint(data[i]) || isspace(data[i])))
			non_printable_count++;


	if (method_length == 3 && data[line_length] == '\n' && non_printable_count == 0)
		return 1;

	return 0;
}

static unsigned tcp_record_hash(struct TCPRECORD *rec)
{
	unsigned i;
	unsigned hash=0;

	for (i=0; i<16; i++) {
		hash += rec->ip_dst[i];
		hash += rec->ip_src[i] << 8;
	}
	hash += rec->tcp_dst;
	hash += rec->tcp_src << 8;

	return hash;
}
static unsigned tcp_record_equals(struct TCPRECORD *left, struct TCPRECORD *right)
{
	unsigned i;
	unsigned bytes=16;
	if (left->ip_ver != right->ip_ver)
		return 0;

	if (left->ip_ver == 0)
		bytes = 4;


	for (i=0; i<bytes; i++) {
		if (left->ip_src[i] != right->ip_src[i])
			return 0;
		if (left->ip_dst[i] != right->ip_dst[i])
			return 0;
	}
	if (left->tcp_dst != right->tcp_dst)
		return 0;
	if (left->tcp_src != right->tcp_src)
		return 0;

	return 1;
}
static struct TCPRECORD *
tcp_lookup_session(
	struct FerretEngine *eng, 
	struct NetFrame *frame, 
	unsigned ipver, 
	const void *ipsrc, const void *ipdst, 
	unsigned portsrc, unsigned portdst, 
	unsigned seqno, 
	unsigned is_creating)
{
	static const size_t MAX_SESSIONS = (sizeof(eng->sessions)/sizeof(eng->sessions[0]));
	struct TCPRECORD rec = {0};
	struct TCPRECORD **r_index;
	struct TCPRECORD *sess;

	/* Set the current session to NULL, in case something happens */
	eng->current = 0;

	/* TODO Add support for IPv6 later, unfortunately we are only
	 * supporting IPv4 sessions right now */
	if (ipver != 0) {
		return 0;
	}


	/* Create a pseudo-record to compare against */
	rec.ip_ver = ipver;
	memcpy(rec.ip_dst, ipdst, 4);
	memcpy(rec.ip_src, ipsrc, 4);
	rec.tcp_dst = (unsigned short)portdst;
	rec.tcp_src = (unsigned short)portsrc;

	/* Do a hash lookup */
	r_index = &eng->sessions[tcp_record_hash(&rec) % MAX_SESSIONS];
	sess = *r_index;

	/* Follow the linked-list from that hash point
	 * [rdg] FIXED: This was originally a normal linked list ending in
	 * a NULL pointer. However, I changed it to a doubly linked list
	 * that becomes circular. Thus, the orignal code that kept going until
	 * it hit a NULL went into an infinite loop. I changed it so that it
	 * would now stop once it reached its starting point. I think there
	 * are other bits of the code ethat likewise need to change. */
	while (sess && !tcp_record_equals(sess, &rec)) {
		sess = sess->next;
		if (sess == *r_index) {
			sess = NULL;
		}
	}

	if (sess == NULL) {
		if (is_creating != TCP_CREATE)
			return NULL;

		/* If not found, create the session */
		eng->session_count++;
		sess = (struct TCPRECORD*)malloc(sizeof(*sess));
		memcpy(sess, &rec, sizeof(rec));
		sess->seqno = seqno;
		sess->a3 = 0xa3a4a5a6;

		/* Insert into the doubly-linked list */
		if (*r_index == NULL) {
			*r_index = sess;
			sess->next = sess;
			sess->prev = sess;
		} else {
			sess->next = (*r_index)->next;
			sess->next->prev = sess;
			sess->prev = (*r_index);
			sess->prev->next = sess;
		}

		/* Add to the housekeeping list. We'll set this to call us back in 5-minutes. */
		housekeeping_remember(eng->housekeeper, frame->time_secs+5*90, tcp_housekeeping, sess, &sess->housekeeping_entry);

	} else if (is_creating == TCP_DESTROY) {
		/*
		 * MODE: DELETE this record
		 */
		unsigned i;

		/* Unlink from the housekeeping system */
		housekeeping_remove(eng->housekeeper, &sess->housekeeping_entry);

		/* Do a "close" on the TCP connection, and the reverse connection as well */
		if (sess->parser)
			sess->parser(sess, frame, TCP_CLOSE, 0);

		/* Remove the record from the list */
		sess->next->prev = sess->prev;
		sess->prev->next = sess->next;
		if (*r_index == sess)
			*r_index = sess->next;
		if (*r_index == sess)
			*r_index = NULL;
		sess->next = NULL;
		sess->prev = NULL;

		/* Make sure the reverse doesn't point back to us */
		if (sess->reverse && sess->reverse->reverse == sess)
			sess->reverse->reverse = 0;

		/* Clean up the fragmentation buffers
		 * TODO: we need to separately process these fragments */
		if (sess->segments != NULL)
			; /*FRAMERR(frame, "%s: discarding segment data\n", "TCP");*/
		tcpfrag_delete_all(&sess->segments);

		/* Free the string reassemblers */
		for (i=0; i<sizeof(sess->str)/sizeof(sess->str[0]); i++)
			strfrag_finish(&sess->str[i]);

		/* Free the memory */
		if (sess->a3 != 0xa3a4a5a6)
			printf("err\n");
		free(sess);
		sess = NULL;
		eng->session_count--;
	}


	eng->current = sess;
	return sess;
}


extern unsigned smellslike_aim_oscar(const unsigned char *px, unsigned length);

/**
 * Run various heuristics on the TCP connection in order to figure out a likely
 * protocol parser for it.
 */
FERRET_PARSER tcp_smellslike(const unsigned char *px, unsigned length, const struct NetFrame *frame)
{
	unsigned src_port = frame->src_port;
	unsigned dst_port = frame->dst_port;
	struct SmellsSSL smell;
	struct SmellsDCERPC dcerpc;

	if (smellslike_httprequest(px, length))
		return (FERRET_PARSER)parse_http_request;

	smell.state = 0;
	if (smellslike_ssl_request(frame, &smell, px, length))
		return (FERRET_PARSER)parse_ssl_request;

	dcerpc.state = 0;
	if (smellslike_msrpc_toserver(&dcerpc, px, length))
		return (FERRET_PARSER)parse_dcerpc_request;

	if ((src_port == 5190 || dst_port == 5190) && length > 6 && px[0] == 0x2a && 1 <= px[1] && px[1] <= 5)
		return (FERRET_PARSER)parse_aim_oscar;

	/* I'm not sure why, but I saw AIM traffic across port 443, but not SSL
	 * encrypted. I assume that the AIM client does this in order to avoid
	 * being firewalled. */
	if ((src_port == 443 || dst_port == 443) && length > 6 && px[0] == 0x2a && 1 <= px[1] && px[1] <= 5 && smellslike_aim_oscar(px, length))
		return (FERRET_PARSER)parse_aim_oscar;

	if ((src_port == 443 && dst_port > 1024) || (dst_port == 443 && src_port > 1024))
		return (FERRET_PARSER)parse_ssl_request;
	if ((src_port == 465 && dst_port > 1024) || (dst_port == 465 && src_port > 1024))
		return (FERRET_PARSER)parse_ssl_request;
	if ((src_port == 993 && dst_port > 1024) || (dst_port == 993 && src_port > 1024))
		return (FERRET_PARSER)parse_ssl_request;
	if ((src_port == 995 && dst_port > 1024) || (dst_port == 995 && src_port > 1024))
		return (FERRET_PARSER)parse_ssl_request;

	return NULL;
}


/**
 * This is called every 5-minutes on a TCP connection in order to clean up
 * closed or inactive connections.
 */
static void 
tcp_housekeeping(struct Housekeeping *housekeeper, void *housekeeping_data, time_t now, struct NetFrame *frame)
{
	struct TCPRECORD *sess = (struct TCPRECORD*)housekeeping_data;

	/* If there has been activity since the last housekeeping check,
	 * then re-register this to be 5 minutes from the last activity */
	if (sess->last_activity + 5*60 > now) {
		housekeeping_remember(housekeeper, sess->last_activity + 5*60, tcp_housekeeping, sess, &sess->housekeeping_entry);
		return;
	}

	
	/* Free the TCP connections */
	/*if (sess->reverse) {
		struct TCPRECORD *reverse = sess->reverse;
		tcp_lookup_session(reverse->eng, frame, reverse->ip_ver, reverse->ip_src, reverse->ip_dst, reverse->tcp_src, reverse->tcp_dst, reverse->seqno, TCP_DESTROY);
	}*/
	tcp_lookup_session(sess->eng, frame, sess->ip_ver, sess->ip_src, sess->ip_dst, sess->tcp_src, sess->tcp_dst, sess->seqno, TCP_DESTROY);
}


/**
 * This function processes acknowledgements. The primary idea behind this
 * function is to see if we've missed any packets on a TCP connection,
 * such as when monitoring wireless networks. When we miss packets,
 * we have to figure out how to repair our TCP state. One easy
 * way is to simply delete the connect and start over again.
 */
static void 
tcp_ack_data(struct Ferret *ferret, struct NetFrame *frame, unsigned seqno)
{
	struct TCPRECORD *sess;
	struct FerretEngine *eng = ferret->eng[ferret->engine_count - 1];
	unsigned i;

	/*
	 * Lookup the REVERSE TCP connection
	 */
	sess = NULL;
	for (i=0; i<ferret->engine_count; i++) {
		sess = tcp_lookup_session(	ferret->eng[i], 
									frame, 
									frame->ipver, 
									&frame->dst_ipv4, 
									&frame->src_ipv4, 
									frame->dst_port, 
									frame->src_port, 
									seqno, 
									TCP_LOOKUP);
		if (sess != NULL) {
			eng = ferret->eng[i];
			break;
		}
	}
	if (sess == NULL)
		return;

	/*
	 * Test to see if the acknowledgement number is past the end of the
	 * the next expected sequence number 
	 */
	if ((int)(seqno - sess->seqno) > 0) {
		/* Oops, we've missed a packet. Therefore, we need to flush the 
		 * state of this system and remove the record. The only things
		 * that we'll remember are:
		 * 1. the associated connection going the reverse direction
		 * 2. the protocol parser associated with this connection
		 */
		FERRET_PARSER parser = sess->parser;
		struct TCPRECORD *reverse = sess->reverse;


		/* Destroy the TCP connection and remove it from our table */
		VALIDATE(sess->eng != 0);
		tcp_lookup_session(sess->eng, frame, sess->ip_ver, sess->ip_src, sess->ip_dst, sess->tcp_src, sess->tcp_dst, sess->seqno, TCP_DESTROY);

		/* Now recreate the connection */
		eng = ferret->eng[ferret->engine_count - 1]; /* use the latest engine block */
		sess = tcp_lookup_session(eng, frame, frame->ipver, &frame->dst_ipv4, &frame->src_ipv4, frame->dst_port, frame->src_port, seqno, TCP_CREATE);
		if (sess) {
			sess->eng = eng;
			sess->parser = parser;
			sess->reverse = reverse;
			if (sess->reverse)
				sess->reverse->reverse = sess;
		}
	}
}

/**
 *
 */
static void
tcp_data_parse(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned seqno, unsigned is_frag)
{
	unsigned i;

	/*
	 * MISSING FRAGMENT
	 * 
	 * This tests to see if there is a discontinuity. If the current seqno
	 * is greater than the next-expected-seqno, then we have a missing
	 * fragment somewhere. Therefore, we need to add the fragment to the 
	 * queue to be processed when (if ever) the missing fragment arrives
	 */
	if (SEQ_FIRST_BEFORE_SECOND(sess->seqno, seqno)) {

		if (SEQ_FIRST_BEFORE_SECOND(sess->seqno+1999000, seqno)) {
			/* This fragment is too far in the future, so discard it */
			FRAMERR(frame, "tcp: orphan fragment\n");
			/* defcon2008/dump002.pcap(93562)
			 * This packet goes over 100,000 bytes in the future passed
			 * missed fragment before retransmitting it */
			return;
		}

		/* Don't remember this fragment if it's coming from the remembered
		 * fragment queue */
		if (is_frag)
			return;

		/* Remeber this segment so that we can process it later when we 
		 * get something appropriate. */
		tcpfrag_add(&(sess->segments), px, length, seqno);
		return;

	}
	
	
	/* 
	 * PREVIOUS FRAGMENT and RETRANSMISSION
	 *
	 * This tests to see end of this fragment is a sequence number that
	 * we've already processed. This will be the case on repeated
	 * transmissions of the same packet as well.
	 */
	if (SEQ_FIRST_BEFORE_SECOND(seqno+length, sess->seqno) || seqno+length == sess->seqno) {
		/* This fragment is completely before the current one, therefore
		 * we can completely ignore it */
		return;
	}


	/* 
	 * OVERLAPPING FRAGMENT 
	 *
	 * This tests the case where the current fragment starts somewhere
	 * in the middle of something we've already processed. There is still
	 * some new data, so we just ignore the old bit.
	 */
	if (SEQ_FIRST_BEFORE_SECOND(seqno, sess->seqno)) {
		/* Regress: ferret-regress-00001-tcp-overlap.pcap frame 20 */
		unsigned sublen = sess->seqno - seqno;
		seqno += sublen;
		length -= sublen;
		px += sublen;
	}


	/* TEMP: change this to an assert */
	if (sess->seqno != seqno)
		FRAMERR(frame, "programming error\n");

	/*
	 * PARSE THE DATA WITH A PROTOCOL PARSER
	 */
	if (sess->parser)
		sess->parser(sess, frame, px, length);
	sess->seqno = seqno+length;

	/* STRING RE-ASSEMBLER:
	 *	If we are in the middle of parsing a string from the packet,
	 *  then it's currently pointing into the packet that's about to
	 *	disappear. Therefore, we need to allocate a backing store
	 *	for it that will be preserved along with the TCP stream so
	 *	that the packet can disappear */
	for (i=0; i<sizeof(sess->str)/sizeof(sess->str[0]); i++) {
		if (sess->str[i].length && sess->str[i].backing_store == NULL)
			strfrag_force_backing_store(&sess->str[i]);
	}

	if (sess->layer7_proto == 0)
		sess->layer7_proto = frame->layer7_protocol;
}

/**
 * This is the primary function called to analyze a bit of data from a 
 * TCP connection.
 */
static void 
tcp_data(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned seqno, unsigned ackno)
{
	struct TCPRECORD *sess;
	struct FerretEngine *eng = ferret->eng[ferret->engine_count - 1];
	unsigned i;

	UNUSEDPARM(ackno);


	/*
	 * Lookup (or create) a TCP session object. This is an object in a
	 * SINGLE direction of a TCP flow.
	 */
	/* Look for the session in one of our eng instances */
	sess = NULL;
	for (i=0; i<ferret->engine_count; i++) {
		sess = tcp_lookup_session(ferret->eng[i], frame, frame->ipver, &frame->src_ipv4, &frame->dst_ipv4, frame->src_port, frame->dst_port, seqno, TCP_LOOKUP);
		if (sess != NULL) {
			eng = ferret->eng[i];
			break;
		}
	}

	/* If not found, create it in the newest instance */
	if (sess == NULL) {
		struct TCPRECORD *reverse;

		/* Create a new TCP session record */
		sess = tcp_lookup_session(ferret->eng[ferret->engine_count-1], frame, frame->ipver, &frame->src_ipv4, &frame->dst_ipv4, frame->src_port, frame->dst_port, seqno, TCP_CREATE);
		sess->eng = eng;

	
		/* If there is a reverse connection, let's get a pointer to it to 
		 * make request/response processing easier */
		reverse = tcp_lookup_session(ferret->eng[ferret->engine_count-1], frame, frame->ipver, &frame->dst_ipv4, &frame->src_ipv4, frame->dst_port, frame->src_port, ackno, TCP_LOOKUP);
		if (reverse) {
			sess->reverse = reverse;
			sess->parser = reverse_parser(reverse->parser);
			if (sess->reverse->reverse == NULL)
				sess->reverse->reverse = sess;
		}
	}

	/* If it's still NULL, we got a problem */
	if (!sess)
		return; /* TODO: handle packets that cannot be assigned a state object */

	VALIDATE(sess->reverse == 0 || sess->reverse->reverse == sess);

	/* Record the last time we saw a data packet. We will use this value
	 * in order to determine when we should age out the TCP connection,
	 * where the oldest inactive connections will be those that get aged out
	 * first. */
	sess->last_activity = frame->time_secs;

	/*
	 * Figure out what the TCP connection contains
	 */
	if (sess->parser == NULL)
		sess->parser = tcp_smellslike(px, length, frame);

	if (sess->parser == NULL) {
		if ((frame->dst_port == 5050) 
			|| (frame->src_port == 5050 && length > 4 && memcmp(px, "YMSG", 4))) {
			if (frame->dst_port == 5050)
				sess->parser = stack_tcp_ymsg_client_request;
			else
				sess->parser = stack_tcp_ymsg_server_response;
		}

		if (frame->src_port == 1863 || frame->dst_port == 1863) {
			if (smellslike_msn_messenger(px, length)) {
				if (frame->src_port == 1863)
					sess->parser = process_msnms_server_response;
				else
					sess->parser = process_simple_msnms_client_request;
			}
		}

		if (frame->src_port == 110)
			sess->parser = parse_pop3_response;
		else if (frame->dst_port == 110)
			sess->parser = parse_pop3_request;

		if (frame->src_port == 3389)
			sess->parser = parse_rdp_response;
		else if (frame->dst_port == 3389)
			sess->parser = parse_rdp_request;

		if (frame->src_port == 25)
			sess->parser = process_simple_smtp_response;
		else if (frame->dst_port == 25)
			sess->parser = process_simple_smtp_request;
	}

	/*
	 * Now parse the data
	 */
	tcp_data_parse(sess, frame, px, length, seqno, 0);

	/*
	 * Take care of remaining fragments that attach to this one
	 */
	while (sess->segments && (int)(sess->seqno-sess->segments->seqno)>=0) {
		/* Regress: ferret-regress-00002-tcp-missing.pcap
		 *  the case where a saved fragment overlaps with existing fragment */
		px = sess->segments->px;
		length = sess->segments->length;
		seqno = sess->segments->seqno;

		tcp_data_parse(sess, frame, px, length, seqno, 1);

		tcpfrag_delete(&sess->segments);
	}
	
	/* Now forget the current processor */
	eng->current = 0;
}

void process_tcp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct {
		unsigned src_port;
		unsigned dst_port;
		unsigned seqno;
		unsigned ackno;
		unsigned header_length;
		unsigned flags;
		unsigned window;
		unsigned checksum;
		unsigned urgent;
	} tcp;

	ferret->statistics.tcp++;
	frame->layer4_protocol = LAYER4_TCP;

	if (length == 0) {
		FRAMERR(frame, "tcp: frame empty\n");
		frame->layer4_protocol = LAYER4_TCP_CORRUPT;
		return;
	}
	if (length < 20) {
		FRAMERR(frame, "tcp: frame too short\n");
		frame->layer4_protocol = LAYER4_TCP_CORRUPT;
		return;
	}

/*
	    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

	tcp.src_port = ex16be(px+0);
	tcp.dst_port = ex16be(px+2);
	tcp.seqno = ex32be(px+4);
	tcp.ackno = ex32be(px+8);
	tcp.header_length = px[12]>>2;
	tcp.flags = px[13];
	tcp.window = ex16be(px+14);
	tcp.checksum = ex16be(px+16);
	tcp.urgent = ex16be(px+18);

	frame->src_port = tcp.src_port;
	frame->dst_port = tcp.dst_port;

	if (tcp.header_length < 20) {
		/* Regress: defcon2008\dump027.pcap(39901) */
		//FRAMERR(frame, "tcp: header too short, expected length=20, found length=%d\n", tcp.header_length);
		frame->layer4_protocol = LAYER4_TCP_CORRUPT;
		return;
	}
	if (tcp.header_length > length) {
		//FRAMERR(frame, "tcp: header too short, expected length=%d, found length=%d\n", tcp.header_length, length);
		frame->layer4_protocol = LAYER4_TCP_CORRUPT;
		return;
	}
	if ((tcp.flags & 0x20) && tcp.urgent > 0) {
		FRAMERR(frame, "tcp: found %d bytes of urgent data\n", tcp.urgent);
		frame->layer4_protocol = LAYER4_TCP_CORRUPT;
		return;
	}

	/* Check the checksum */
	if (0) if (!validate_tcp_checksum(px, length, frame->src_ipv4, frame->dst_ipv4)) {
		/* Regress: defcon2008-msnmsgr.pcap(24066) */
		ferret->statistics.errs_tcp_checksum++;		
		frame->layer4_protocol = LAYER4_TCP_XSUMERR;
		return;
	}

	/*TODO: need to check checksum */

	if (tcp.header_length > 20) {
		unsigned o = 20;
		unsigned max = tcp.header_length;

		while (o < tcp.header_length) {
			unsigned tag = px[o++];
			unsigned len;

			if (tag == 0)
				break;
			if (tag == 1)
				continue;

			if (o >= max) {
				FRAMERR(frame, "tcp: options too long\n");
				break;
			}
			len = px[o++];

			if (len < 2) {
				FRAMERR(frame, "tcp: invalid length field\n");
				break;
			}
			if (o+len-2 > max) {
				FRAMERR(frame, "tcp: options too long\n");
				break;
			}

			switch (tag) {
			case 0x02: /* max seg size */
				if (len != 4)
					FRAMERR(frame, "tcp: unknown length: option=%d, length=%d\n", tag, len);
				break;
			case 0x04: /* SACK permitted */
				if (len != 2)
					FRAMERR(frame, "tcp: unknown length: option=%d, length=%d\n", tag, len);
				break;
			case 0x05: /* SACK */
				break;
			case 0x08: /*timestamp*/
				break;
			case 0x03: /*window scale*/
				break;
			default:
				FRAMERR(frame, "tcp: unknown option=%d, length=%d\n", tag, len);
			}

			o += len-2;
		}
	}


	SAMPLE(ferret,"TCP", JOT_NUM("flags", tcp.flags));

	frame->sess = tcp_lookup_session(ferret->eng[0], 
									frame, 
									frame->ipver, 
									&frame->src_ipv4, 
									&frame->dst_ipv4, 
									frame->src_port, 
									frame->dst_port, 
									tcp.seqno, 
									TCP_LOOKUP);
	if (frame->sess && frame->sess->layer7_proto)
		frame->layer7_protocol = frame->sess->layer7_proto;
	else {
		if (tcp.src_port == 80 || tcp.dst_port == 80)
			frame->layer7_protocol = LAYER7_HTTP;
		else if (tcp.src_port == 443 || tcp.dst_port == 443)
			frame->layer7_protocol = LAYER7_SSL;
		else if (tcp.src_port == 25 || tcp.dst_port == 25)
			frame->layer7_protocol = LAYER7_SMTP;
		else if (tcp.src_port == 139 || tcp.dst_port == 139)
			frame->layer7_protocol = LAYER7_SMB;
		else if (tcp.src_port == 445 || tcp.dst_port == 445)
			frame->layer7_protocol = LAYER7_SMB;
		else if (tcp.src_port == 110 || tcp.dst_port == 110)
			frame->layer7_protocol = LAYER7_POP3;
		else if (tcp.src_port == 135 || tcp.dst_port == 135)
			frame->layer7_protocol = LAYER7_DCERPC;
	}

	/* Process an "acknowledgement". Among other things, this will identify
	 * when packets have been missed: if the other side claims to have
	 * received a packet, but we never saw it, then we know that it was
	 * dropped somewhere on the network (probably because we are getting
	 * a weak signal via wireless). */
	if (tcp.flags & TCP_ACK) {
		tcp_ack_data(ferret, frame, tcp.ackno);
	}

	switch (tcp.flags & 0x3F) {
	case TCP_SYN:
		tcp_syn(ferret, frame);
		break;
	case TCP_SYN|TCP_ACK:
		tcp_synack(ferret, frame);
		break;
	case TCP_FIN:
	case TCP_FIN|TCP_ACK:
	case TCP_FIN|TCP_ACK|TCP_PSH:
		tcp_fin(ferret, frame);
		break;
	case TCP_ACK:
	case TCP_ACK|TCP_PSH:
		if (length > tcp.header_length)
			tcp_data(ferret, frame, px+tcp.header_length, length-tcp.header_length, tcp.seqno, tcp.ackno);
		break;
	case TCP_RST:
	case TCP_RST|TCP_ACK:
		break;
	case 0x40|TCP_ACK:
		break;
	case TCP_RST|TCP_ACK|TCP_FIN:
	case TCP_RST|TCP_ACK|TCP_PSH:
		break;
	default:
		FRAMERR(frame, "tcp: unexpected combo of flags: 0x%03x\n", tcp.flags);
	}

	/*
	 * KLUDGE:
	 */
	if (frame->layer7_protocol == 0) {
		if (frame->dst_port == 443 || frame->src_port == 443)
			frame->layer7_protocol = LAYER7_SSL;
		if ((frame->dst_port == 3260 && frame->src_port > 1024)
		 || (frame->src_port == 3260 && frame->dst_port > 1024))
			frame->layer7_protocol = LAYER7_ISCSI;
		if ((frame->dst_port == 21 && frame->src_port > 1024)
		 || (frame->src_port == 21 && frame->dst_port > 1024))
			frame->layer7_protocol = LAYER7_FTP;
		if ((frame->dst_port == 143 && frame->src_port > 1024)
		 || (frame->src_port == 143 && frame->dst_port > 1024))
			frame->layer7_protocol = LAYER7_IMAP;
	}
}

void strfrag_xfer(struct StringReassembler *dst, struct StringReassembler *src)
{
	/* Transfer from one string to another. We often call this when the
	 * we really just want to re-use one of the string reassembly buffers
	 * on the connection to store data across packets. */
	if (dst->length)
		strfrag_init(dst);
	memcpy(dst, src, sizeof(*dst));
	memset(src, 0, sizeof(*src));
}
void strfrag_copy(struct StringReassembler *dst, struct StringReassembler *src)
{
	/* Make a copy of one string to another.
	 * If they both point into the current packet, then we don't need to
	 * allocate memory. Otherwise, we need to duplicate the backing-store */
	if (dst->length)
		strfrag_init(dst);
	strfrag_append(dst, src->the_string, src->length);
	if (src->backing_store)
		strfrag_force_backing_store(dst);
}

void strfrag_init(struct StringReassembler *strfrag)
{
	if (strfrag->backing_store)
		free(strfrag->backing_store);
	memset(strfrag, 0, sizeof(*strfrag));

	/* TODO: we should just set the ->length field to zero to
	 * improve performance */
}

void strfrag_finish(struct StringReassembler *strfrag)
{
	if (strfrag->backing_store)
		free(strfrag->backing_store);
	memset(strfrag, 0, sizeof(*strfrag));
}

void strfrag_append(struct StringReassembler *strfrag, const unsigned char *px, unsigned length)
{
	if (length == 0)
		return;

	if (strfrag->length == 0) {
		/* Initial condition: we create the first object by pointing
		 * into the packet */
		strfrag->the_string = px;
		strfrag->length = length;

		assert(strfrag->backing_store == 0);
		return;
	}

	if (strfrag->backing_store) {
		/* We have a backing store, so we need to re-alloc the memory and
		 * copy the new data onto the end of it, then reset the string
		 * point to the newly allocated memory */
		unsigned char *new_store = (unsigned char *)malloc(length + strfrag->length + 1);

		/* Copy the old string */
		memcpy(	new_store, 
				strfrag->the_string, 
				strfrag->length);

		/* Append the new string */
		memcpy(	new_store + strfrag->length,
				px,
				length);

		/* Nul-terminate just to make debugging easier */
		new_store[strfrag->length + length] = '\0';

		/* Now free the old string and replace it with the new string, including
		 * making the static pointer point to the new string */
		free(strfrag->backing_store);
		strfrag->backing_store = new_store;
		strfrag->the_string = new_store;
		strfrag->length += length;
		return;
	}


	if (strfrag->the_string + strfrag->length != px) {
		/* WHOOPS. This shouldn't happen, but it looks like a programmer
		 * is combining multiple un-connected segments together.
		 * This forces us to create a backing store to combine the 
		 * disconnected fragments into a single string */
		strfrag_force_backing_store(strfrag);
		strfrag_append(strfrag, px, length);
		return;
	}

	/* It looks like we are still pointing to the same packet. Therefore, 
	 * all we have to do is just increase the length of the string
	 * that we are already pointing to */
	strfrag->length += length;
}

void strfrag_force_backing_store(struct StringReassembler *strfrag)
{
	/* This is likely called AFTER we have parsed a TCP application,
	 * but aren't through parsing a string. Therefore, we need to
	 * copy the fragment of the string out of the current packet and
	 * place it into a allocated memory. */

	/* If we already have a backing-store, then do nothing. This means
	 * the process is 'idempotent': we can repeatedly call this function
	 * without worrying if it's already been called */
	if (strfrag->backing_store)
		return;

	/* Allocate memory for the store. I'm going to allocate an extra byte
	 * for a nul-terminator, not because any of the parsers rely upon 
	 * nul terminated strings, but because it makes debugging easier.
	 */
	strfrag->backing_store = (unsigned char*)malloc(strfrag->length+1);

	/* Copy over the string from the current packet */
	memcpy(strfrag->backing_store, strfrag->the_string, strfrag->length);

	/* Nul-terminate */
#if RELEASE
	strfrag->backing_store[strfrag->length] = 'Q'; /*force non-nul termination to detect bugs*/
#else
	strfrag->backing_store[strfrag->length] = '\0';
#endif

	/* Change the pointer from pointing into the packet to now point to
	 * the allocated string */
	strfrag->the_string = strfrag->backing_store;
}

