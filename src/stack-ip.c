/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "ferret.h"

void process_ip(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	struct {
		unsigned version;
		unsigned header_length;
		unsigned total_length;
		unsigned fragment_length;
		unsigned tos;
		unsigned id;
		unsigned flags;
		unsigned fragment_offset;
		unsigned ttl;
		unsigned protocol;
		unsigned checksum;
		unsigned src_ip;
		unsigned dst_ip;
	} ip;

	ferret->statistics.ipv4++;
	frame->layer3_protocol = LAYER3_IP;

	if (length == 0) {
		FRAMERR(frame, "ip: frame empty\n");
		return;
	}


	ip.version = px[0]>>4;
	ip.header_length = (px[0]&0xF) * 4;
	ip.tos = ex16be(px+1);
	ip.total_length = ex16be(px+2);
	ip.id = ex16be(px+4);
	ip.flags = px[6]&0xE0;
	ip.fragment_offset = (ex16be(px+6) & 0x3FFF) << 3;
	ip.ttl = px[8];
	ip.protocol = px[9];
	ip.checksum = ex16be(px+10);
	ip.src_ip = ex32be(px+12);
	ip.dst_ip = ex32be(px+16);

    if (ip.fragment_offset != 0)
		return;

    /* Figure out packet distribution */
    if (ip.total_length <= 512) {
        if (ip.total_length <= 128) {
            if (ip.total_length <= 64)
            	ferret->statistics.ip4size.size64++;
            else
            	ferret->statistics.ip4size.size128++;
        } else if (ip.total_length <= 256) {
        	ferret->statistics.ip4size.size256++;
        } else
        	ferret->statistics.ip4size.size512++;

    } else {
        if (ip.total_length <= 1024)
        	ferret->statistics.ip4size.size1024++;
        else
        	ferret->statistics.ip4size.size1500++;
    }

	frame->src_ipv4 = ip.src_ip;
	frame->dst_ipv4 = ip.dst_ip;

	if (ip.version != 4) {
		FRAMERR(frame, "ip: version=%d, expected version=4\n", ip.version);
		return;
	}
	if (ip.header_length < 20) {
		FRAMERR(frame, "ip: header length=%d, expected length>=20\n", ip.header_length);
		return;
	}
	if (ip.header_length > length) {
		FRAMERR(frame, "ip: header length=%d, expected length>=%d\n", length, ip.header_length);
		return;
	}

	if (ip.header_length > 20) {
		unsigned o = 20;
		unsigned max = ip.header_length;

		while (o < ip.header_length) {
			unsigned tag = px[o++];
			unsigned len;

			if (tag == 0)
				break;
			if (tag == 1)
				continue;

			if (o >= max) {
				FRAMERR(frame, "ip: options too long\n");
				break;
			}
			len = px[o++];

			if (len < 2) {
				FRAMERR(frame, "ip: invalid length field\n");
				break;
			}
			if (o+len-2 > max) {
				FRAMERR(frame, "ip: options too long\n");
				break;
			}

			switch (tag) {
			case 0x94: /* alert */
				if (len != 4)
					FRAMERR(frame, "ip: bad length, option=%d, length=%d\n", tag, len);
				if (ex16be(px+o) != 0)
					FRAMERR(frame, "ip: bad value, option=%d, length=%d\n", tag, len);
				break;
			default:
				FRAMERR(frame, "ip: unknown option=%d, length=%d\n", tag, len);
			}

			o += len-2;
		}
	}

	if (ip.total_length < ip.header_length) {
		FRAMERR(frame, "ip: total_length less than header length\n");
		return;
	}

	if (length > ip.total_length) {
		if (length-ip.total_length == 4)
			ferret->statistics.remaining_4++; /*hints that an FCS trails*/
		length = ip.total_length;
	}

	offset += ip.header_length;
	if (offset > length) {
		FRAMERR(frame, "ip: header too short, missing %d bytes\n", ip.header_length - length);
		return;
	}


	switch (ip.protocol) {
	case 0x01: /* ICMP */
		process_icmp(ferret, frame, px+offset, length-offset);
		break;
	case 0x02: /* IGMP */
		process_igmp(ferret, frame, px+offset, length-offset);
		break;
	case 0x11: /* UDP */
		process_udp(ferret, frame, px+offset, length-offset);
		break;
	case 0x06:
		process_tcp(ferret, frame, px+offset, length-offset);
		break;
	case 47: /* GRE - Generic Router Encapsulation Protocol */
		process_gre(ferret, frame, px+offset, length-offset);
		break;
	case 50: /* ESP - Encapsulated Security Protocol */
		break;
	case 41: /* IPv6 inside IPv4 */
		process_ipv6(ferret, frame, px+offset, length-offset);
		break;
	default:
		FRAMERR(frame, "ip: unknown protocol=%d\n", ip.protocol);
	}

}

