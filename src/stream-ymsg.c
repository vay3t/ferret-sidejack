/* Copyright (c) 2008 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "platform.h"
#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "ferret.h"

extern void process_ymsg_client_request(
		struct TCPRECORD *sess, 
		struct NetFrame *frame, 
		struct StringReassembler *ymsg_packet);
extern void process_ymsg_server_response(
		struct TCPRECORD *sess, 
		struct NetFrame *frame, 
		struct StringReassembler *ymsg_packet);


/*
     <------- 4B -------><------- 4B -------><---2B--->
    +-------------------+-------------------+---------+
    |   Y   M   S   G   |      version      | pkt_len |
    +---------+---------+---------+---------+---------+
    | service |      status       |    session_id     |
    +---------+-------------------+-------------------+
    |                                                 |
    :                    D A T A                      :
    |                   0 - 65535*                    |
    +-------------------------------------------------+
*/
void stack_tcp_ymsg_client_request(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned state = sess->layer7_state;
	struct StringReassembler *ymsg_packet = sess->str+0;

	frame->layer7_protocol = LAYER7_YMSG;

	while (offset < length)
	switch (state) {
	case 0:
		strfrag_init(ymsg_packet);
		/* fall through */
	case 1: case 2: case 3:
		if (px[offset] == "YMSG"[state])
			state++;
		else
			state = 0;
		offset++;
		break;
	case 4: case 5: 
		sess->layer7.ymsg.version <<= 8;
		sess->layer7.ymsg.version &= 0xffff;
		sess->layer7.ymsg.version |= px[offset];
		offset++;
		state++;
		break;
	case 6: case 7:
		offset++;
		state++;
		break;
	case 8: case 9:
		sess->layer7_length_remaining <<= 8;
		sess->layer7_length_remaining &= 0xFFFF;
		sess->layer7_length_remaining |= px[offset];
		offset++;
		state++;
		break;
	case 10: case 11:
		sess->layer7.ymsg.service <<= 8;
		sess->layer7.ymsg.service &= 0xFFFF;
		sess->layer7.ymsg.service |= px[offset];
		offset++;
		state++;
		break;
	case 12: case 13: case 14: case 15:
		sess->layer7.ymsg.status <<= 8;
		sess->layer7.ymsg.status &= 0xFFFFffff;
		sess->layer7.ymsg.status |= px[offset];
		offset++;
		state++;
		break;
	case 16: case 17: case 18: case 19:
		sess->layer7.ymsg.session_id <<= 8;
		sess->layer7.ymsg.session_id &= 0xFFFFffff;
		sess->layer7.ymsg.session_id |= px[offset];
		offset++;
		state++;
		break;
	case 20:
		{
			unsigned chunk_len = sess->layer7_length_remaining;
			if (chunk_len > length-offset)
				chunk_len = length-offset;
		
			strfrag_append(ymsg_packet, px+offset, chunk_len);
			sess->layer7_length_remaining -= chunk_len;
			offset += chunk_len;

			if (sess->layer7_length_remaining == 0) {
				process_ymsg_client_request(sess, frame, ymsg_packet);
				strfrag_init(ymsg_packet);
				state = 0;
			}
		}
		break;
	}

	sess->layer7_state = state;
}

void stack_tcp_ymsg_server_response(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned state = sess->layer7_state;
	struct StringReassembler *ymsg_packet = sess->str+0;

	frame->layer7_protocol = LAYER7_YMSG;

	while (offset < length)
	switch (state) {
	case 0:
		strfrag_init(ymsg_packet);
		/* fall through */
	case 1: case 2: case 3:
		if (px[offset] == "YMSG"[state])
			state++;
		else
			state = 0;
		offset++;
		break;
	case 4: case 5: 
		sess->layer7.ymsg.version <<= 8;
		sess->layer7.ymsg.version &= 0xffff;
		sess->layer7.ymsg.version |= px[offset];
		offset++;
		state++;
		break;
	case 6: case 7:
		offset++;
		state++;
		break;
	case 8: case 9:
		sess->layer7_length_remaining <<= 8;
		sess->layer7_length_remaining &= 0xFFFF;
		sess->layer7_length_remaining |= px[offset];
		offset++;
		state++;
		break;
	case 10: case 11:
		sess->layer7.ymsg.service <<= 8;
		sess->layer7.ymsg.service &= 0xFFFF;
		sess->layer7.ymsg.service |= px[offset];
		offset++;
		state++;
		break;
	case 12: case 13: case 14: case 15:
		sess->layer7.ymsg.status <<= 8;
		sess->layer7.ymsg.status &= 0xFFFFffff;
		sess->layer7.ymsg.status |= px[offset];
		offset++;
		state++;
		break;
	case 16: case 17: case 18: case 19:
		sess->layer7.ymsg.session_id <<= 8;
		sess->layer7.ymsg.session_id &= 0xFFFFffff;
		sess->layer7.ymsg.session_id |= px[offset];
		offset++;
		state++;
		break;
	case 20:
		{
			unsigned chunk_len = sess->layer7_length_remaining;
			if (chunk_len > length-offset)
				chunk_len = length-offset;
		
			strfrag_append(ymsg_packet, px+offset, chunk_len);
			sess->layer7_length_remaining -= chunk_len;
			offset += chunk_len;

			if (sess->layer7_length_remaining == 0) {
				process_ymsg_server_response(sess, frame, ymsg_packet);
				strfrag_init(ymsg_packet);
				state = 0;
			}
		}
		break;
	}

	sess->layer7_state = state;
}


