/*
 *  bMessage (MAP) format helpers
 *
 *  Copyright (C) 2010, 2011  Bartosz Szatkowski <bulislaw@linux.com>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdio.h>
#include <glib.h>
#include <string.h>

#define MAX_ENVELOPES_NUM 3

#define BMSG_VERSION_1_0 "1.0"

#define BMSG_READ "READ"
#define BMSG_UNREAD "UNREAD"

#define BMSG_EMAIL "EMAIL"
#define BMSG_SMS "SMS_GSM"
#define BMSG_CDMA "SMS_CDMA"
#define BMSG_MMS "MMS"

/*
 * As stated in MAP errata bmessage-body-content-length-property should be
 * length of: "BEGIN:MSG<CRLF>" + <message content> + "END:MSG<CRLF>"
 */
#define BMESSAGE_BASE_LEN (9 + 2 + 2 + 7 + 2)

struct bmsg_vcard {
	char *version;
	char *n;
	char *fn;
	char *tel;
	char *email;
};

struct bmsg_content {
	gint32 part_id;
	unsigned int len;
	char *encoding;
	char *charset;
	char *lang;
	char *content;
};

struct bmsg_envelope {
	GList *recipients;
	struct bmsg_content *content;
};

struct bmsg {
	char *version;
	char *status;
	char *type;
	char *folder;
	GList *originators;
	GArray *envelopes;
};

void bmsg_init(struct bmsg *msg, const char *version, const char *status,
					const char *type, const char *folder);
void bmsg_destroy(struct bmsg *msg);
void bmsg_add_originator(struct bmsg *msg, const char *version,
				const char *name, const char *fullname,
				const char *tel, const char *email);
gboolean bmsg_add_envelope(struct bmsg *msg);
gboolean bmsg_add_content(struct bmsg *msg, gint32 part_id, char *encoding,
			char *charset, char *lang, const char* content);
struct bmsg * bmsg_parse(char *string);
char * bmsg_text(struct bmsg *msg);
