/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "util-base64.h"
#include "util-hamster.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>





void parse_dcerpc_request(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct PARSE *parse = &sess->parse;
	struct HTTPREQUEST *req = &sess->layer7.httpreq;

	UNUSEDPARM(req); UNUSEDPARM(parse);

	sess->layer7_proto = LAYER7_DCERPC;
	frame->layer7_protocol = LAYER7_DCERPC;
}

void parse_dcerpc_response(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct PARSE *parse = &sess->parse;
	struct HTTPREQUEST *req = &sess->layer7.httpreq;

	UNUSEDPARM(req); UNUSEDPARM(parse);

	sess->layer7_proto = LAYER7_DCERPC;
	frame->layer7_protocol = LAYER7_DCERPC;
}




