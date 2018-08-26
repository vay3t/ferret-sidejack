/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	POINT TO POINT PROTOCOL

  PPP is used as as a VPN protocol (PPTP). We can grab the username (and
  possible the password hash) of the logon.

  PPP is also used as PPoE. This protocol is used to tunnel over an 
  Ethernet connection.

*/
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include <string.h>

void process_pptp_linkcontrol(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned code;
	unsigned id;

	if (length < 4) {
		FRAMERR_TRUNCATED(frame, "gre");
		return;
	}

	code = px[0];
	id = px[1];
	length = ex16be(px+2);

	SAMPLE(ferret,"PPP", JOT_NUM("link-control-code", code));
}

void process_pptp_chap(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned code;
	unsigned id;
	unsigned sublength;
	unsigned offset;

	if (length < 4) {
		FRAMERR_TRUNCATED(frame, "gre");
		return;
	}

	code = px[0];
	id = px[1];
	sublength = ex16be(px+2);
	if (sublength < 4) {
		FRAMERR_BADVAL(frame, "ppp-chap", sublength);
		return;
	}
	offset = 4;

	if (length > sublength)
		length = sublength;

	SAMPLE(ferret,"PPP", JOT_NUM("chap-code", code));
	switch (code) {
	case 1: /* challenge */
		{
			unsigned value_size;
			const unsigned char *value;

			if (offset+1 >= length) {
				FRAMERR_TRUNCATED(frame, "ppp-chap");
				return;
			}
			value_size = px[offset++];
			if (value_size > length-offset)
				value_size = length-offset;
			value = px+offset;
			offset += value_size;

			switch (value_size) {
			case 16:
				JOTDOWN(ferret,
					JOT_SZ("proto","PPP"),
					JOT_SZ("auth","MS-CHAPv2"),
					JOT_HEXSTR("challenge", value, value_size),
					JOT_PRINT("name", px+offset, length-offset),
					0);
				break;
			case 8:
				JOTDOWN(ferret,
					JOT_SZ("proto","PPP"),
					JOT_SZ("auth","MS-CHAPv1"),
					JOT_HEXSTR("challenge", value, value_size),
					JOT_PRINT("name", px+offset, length-offset),
					0);
				break;
			default:
				FRAMERR_BADVAL(frame, "ppp-chap", value_size);
			}

		}
		break;
	default:
		FRAMERR(frame, "PPP: auth unknown code\n");
	}


}
void parse_ppoe_discovery(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned ver;
	unsigned type;
	unsigned code;
	unsigned payload_length;
	unsigned session_id;

	if (length < 4) {
		FRAMERR_TRUNCATED(frame, "PPoE");
		return;
	}

	ver = px[0]>>4;
	type = px[0]&0x0F;
	code = px[1];
	session_id = ex16be(px+2);
	payload_length = ex16be(px+4);

	switch ((ver<<12) | (type<<8) | code) {
	case 0x1109:
		JOTDOWN(ferret,
			JOT_SZ("proto","PPPoE"),
			JOT_SZ("code","discovery"),
			0);
		break;
	default:
		FRAMERR_BADVAL(frame, "PPPoE-discovery-code", code);
		break;
	}

}

void process_pptp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned protocol;

	if (length < 4) {
		FRAMERR_TRUNCATED(frame, "gre");
		return;
	}

	if (ex16be(px) == 0xFF03) {
		px+=2;
		length-=2;
	}

	protocol = ex16be(px);
	SAMPLE(ferret,"PPP", JOT_NUM("packet-type", protocol));
	switch (protocol) {
	case 0xc021: /* Link Control Protocol */
		process_pptp_linkcontrol(ferret, frame, px+2, length-2);
		break;
	case 0xc223: /* PPP CHAP - Challenge Handshake Authentication protocol */
		process_pptp_chap(ferret, frame, px+2, length-2);
		break;
	default:
		; /*FRAMERR_UNKNOWN_UNSIGNED(frame, "ppp", protocol);*/
	}


}

