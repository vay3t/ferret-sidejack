/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	SESSION INITIATION PROTOCOL

  This protocol starts a VoIP connection. We can find out the phone
  number of the person making the call, as well as information about
  who they are making calls to.

  With SIP will be the an embedded protocol that will tell us about
  the multi-media session that will be set up. We will need to decode
  that as well in order to then grab the audio session of the phone
  call.

*/
#include "platform.h"
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "util-memcasecmp.h"
#include "dgram-sip.h"
#include <string.h>
#include <ctype.h>




enum SIP_METHOD {
	SIP_METHOD_UNKNOWN,
	SIP_METHOD_INVITE,
	SIP_METHOD_REGISTER,
};

struct SIP {
	enum SIP_METHOD method;
};


/****************************************************************************
 ****************************************************************************/
int
field_is_number(const struct Field *field, unsigned offset)
{
	if (field->length > offset && isdigit(field->px[offset]&0xFF))
		return 1;
	else
		return 0;
}

/****************************************************************************
 ****************************************************************************/
uint64_t
field_next_number(const struct Field *field, unsigned *inout_offset)
{
	unsigned offset;
	uint64_t result = 0;

	if (inout_offset)
		offset = *inout_offset;
	else
		offset = 0;

	while (offset < field->length && isdigit(field->px[offset]&0xFF)) {
		result = result * 10 + (field->px[offset] - '0');
		offset++;

	}

	/* strip trailing whitespace after the number */
	while (isspace(field->px[offset]&0xFF))
		offset++;

	if (inout_offset)
		*inout_offset = offset;
	return result;
}

/****************************************************************************
 ****************************************************************************/
int
field_equals_nocase(const char *name, const struct Field *field)
{
	unsigned i;

	for (i=0; i<field->length && name[i]; i++)
		if (tolower(name[i]&0xFF) != tolower(field->px[i]))
			return 0;
	if (i != field->length)
		return 0;
	return 1;
}

/****************************************************************************
 ****************************************************************************/
static int
match(const char *sz, const unsigned char *name, unsigned name_length)
{
	if (memcasecmp(name, sz, name_length) == 0 && sz[name_length] == '\0')
		return 1;
	else
		return 0;
}

/****************************************************************************
 ****************************************************************************/
static enum SIP_METHOD
sip_get_method(const unsigned char *px, unsigned length)
{
	unsigned name_length;
	
	/* name is all the chars up to the first space */
	for (name_length = 0; name_length < length && !isspace(px[name_length]); name_length++)
		;

	if (match("INVITE", px, name_length)) {
		return SIP_METHOD_INVITE;
	} else if (match("REGISTER", px, name_length)) {
		return SIP_METHOD_REGISTER;
	} else
		return SIP_METHOD_UNKNOWN;
}

/****************************************************************************
 ****************************************************************************/
static int
sip_get_header(const char *in_name, const unsigned char *px, unsigned length, struct Field *field)
{
	unsigned offset = 0;

	while (offset < length) {
		unsigned i;
		unsigned line_length;
		unsigned name_length;
		unsigned value_offset;
		unsigned next_offset;

		/* Find the end of the line */
		for (i=0; offset+i<length && px[offset+i] != '\n'; i++)
			;
		next_offset = offset+i+1;

		/*
		 * Skip the method
		 */
		if (offset == 0) {
			offset = next_offset;
			continue;
		}

		/* Find the total length of the line minus space at end */
		line_length = i;
		while (line_length > 0 && isspace(px[offset+line_length-1]))
			line_length--;

		/*
		 * Find the name
		 */
		name_length = 0;
		while (name_length < line_length && px[offset+name_length] != ':')
			name_length++;
		if (!match(in_name, px+offset, name_length)) {
			offset = next_offset;
			continue;
		}

		/*
		 * Grab the value
		 */
		value_offset = name_length;
		if (value_offset < line_length && px[offset+value_offset] == ':')
			value_offset++;
		while (value_offset < line_length && isspace(px[offset+value_offset]))
			value_offset++;
 
		field->px = (const char*)px+offset+value_offset;
		field->length = line_length-value_offset;

		return 1; /* found */
	}

	field->px = "";
	field->length = 0;
	return 0;
}


/****************************************************************************
 ****************************************************************************/
void
sip_INVITE_request(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct Field field;
	struct Field content_type = {0,0};
	unsigned content_offset = length;
	uint64_t content_length = 0;
	
	/*
	 * Find the end of the header (the start of the content)
	 */
	{
		unsigned i, is_eol = 0;
		for (i=0; i<length; i++) {
			if (px[i] == '\n') {
				if (is_eol) {
					content_offset = i+1;
					break;
				} else
					is_eol = 1;
			} else if (px[i] == '\r')
				;
			else
				is_eol = 0;
		}
	}

	/*
	 * Get the content length
	 */
	content_length = length - content_offset;
	if (sip_get_header("Content-Length", px, length, &field)) {
		if (field_is_number(&field,0)) {
			content_length = field_next_number(&field,0);
			if (content_length > length - content_offset)
				content_length = length - content_offset;
		}
	}

	/*
	 * Get the Content-type
	 */
	if (sip_get_header("Content-Type", px, length, &content_type)) {
	}

	if (field_equals_nocase("application/sdp", &content_type)) {
		parse_sdp_invite_request(ferret, frame, px+content_offset, (unsigned)content_length);
	} else if (content_type.length) {
		/*application/dtmf-relay*/
		/*application/dtmf*/
		printf("%s: %.*s\n", "Content-Type", content_type.length, content_type.px);
	}
}

/****************************************************************************
 ****************************************************************************/
void
parse_dgram_sip_request(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	enum SIP_METHOD method;

	frame->layer7_protocol = LAYER7_SIP;

	method = sip_get_method(px, length);

	switch (method) {
	case SIP_METHOD_INVITE:
		sip_INVITE_request(ferret, frame, px, length);
		break;
	case SIP_METHOD_REGISTER:
	case SIP_METHOD_UNKNOWN:
	default:
		;
	}
}

/****************************************************************************
 ****************************************************************************/
void
parse_dgram_sip_response(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	frame->layer7_protocol = LAYER7_SIP;

	UNUSEDPARM(ferret);UNUSEDPARM(frame);UNUSEDPARM(px);UNUSEDPARM(length);
}


