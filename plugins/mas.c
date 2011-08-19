/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2010-2011  Nokia Corporation
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <glib.h>
#include <openobex/obex.h>
#include <fcntl.h>

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "service.h"
#include "mimetype.h"
#include "filesystem.h"
#include "dbus.h"

#include "messages.h"

/* Channel number according to bluez doc/assigned-numbers.txt */
#define MAS_CHANNEL	16

#define MAS_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>		\
<record>								\
  <attribute id=\"0x0001\">						\
    <sequence>								\
      <uuid value=\"0x1132\"/>						\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0004\">						\
    <sequence>								\
      <sequence>							\
        <uuid value=\"0x0100\"/>					\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0003\"/>					\
        <uint8 value=\"%u\" name=\"channel\"/>				\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0008\"/>					\
      </sequence>							\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0009\">						\
    <sequence>								\
      <sequence>							\
        <uuid value=\"0x1134\"/>					\
        <uint16 value=\"0x0100\" name=\"version\"/>			\
      </sequence>							\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0100\">						\
    <text value=\"%s\" name=\"name\"/>					\
  </attribute>								\
									\
  <attribute id=\"0x0315\">						\
    <uint8 value=\"0x00\"/>						\
  </attribute>								\
									\
  <attribute id=\"0x0316\">						\
    <uint8 value=\"0x02\"/>						\
  </attribute>								\
</record>"

#define XML_DECL "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"

/* Building blocks for x-obex/folder-listing */
#define FL_DTD "<!DOCTYPE folder-listing SYSTEM \"obex-folder-listing.dtd\">"
#define FL_BODY_BEGIN "<folder-listing version=\"1.0\">"
#define FL_BODY_EMPTY "<folder-listing version=\"1.0\"/>"
#define FL_PARENT_FOLDER_ELEMENT "<parent-folder/>"
#define FL_FOLDER_ELEMENT "<folder name=\"%s\"/>"
#define FL_BODY_END "</folder-listing>"

#define ML_BODY_BEGIN "<MAP-msg-listing version=\"1.0\">"
#define ML_BODY_END "</MAP-msg-listing>"

/* Tags needed to retrieve and set application parameters */
enum aparam_tag {
	MAXLISTCOUNT_TAG	= 0x01,
	STARTOFFSET_TAG		= 0x02,
	FILTERMESSAGETYPE_TAG	= 0x03,
	FILTERPERIODBEGIN_TAG	= 0x04,
	FILTERPERIODEND_TAG	= 0x05,
	FILTERREADSTATUS_TAG	= 0x06,
	FILTERRECIPIENT_TAG	= 0x07,
	FILTERORIGINATOR_TAG	= 0x08,
	FILTERPRIORITY_TAG	= 0x09,
	ATTACHMENT_TAG		= 0x0A,
	TRANSPARENT_TAG		= 0x0B,
	RETRY_TAG		= 0x0C,
	NEWMESSAGE_TAG		= 0x0D,
	NOTIFICATIONSTATUS_TAG	= 0x0E,
	MASINSTANCEID_TAG	= 0x0F,
	PARAMETERMASK_TAG	= 0x10,
	FOLDERLISTINGSIZE_TAG	= 0x11,
	MESSAGESLISTINGSIZE_TAG	= 0x12,
	SUBJECTLENGTH_TAG	= 0x13,
	CHARSET_TAG		= 0x14,
	FRACTIONREQUEST_TAG	= 0x15,
	FRACTIONDELIVER_TAG	= 0x16,
	STATUSINDICATOR_TAG	= 0x17,
	STATUSVALUE_TAG		= 0x18,
	MSETIME_TAG		= 0x19,
	INVALID_TAG		= 0x100,
};

enum aparam_type {
	APT_UINT8,
	APT_UINT16,
	APT_UINT32,
	APT_STR
};

static const struct aparam_def {
	enum aparam_tag tag;
	const char *name;
	enum aparam_type type;
} aparam_defs[] = {
	{ MAXLISTCOUNT_TAG,		"MAXLISTCOUNT",
		APT_UINT16					},
	{ STARTOFFSET_TAG,		"STARTOFFSET",
		APT_UINT16					},
	{ FILTERMESSAGETYPE_TAG,	"FILTERMESSAGETYPE",
		APT_UINT8					},
	{ FILTERPERIODBEGIN_TAG,	"FILTERPERIODBEGIN",
		APT_STR						},
	{ FILTERPERIODEND_TAG,		"FILTERPERIODEND",
		APT_STR						},
	{ FILTERREADSTATUS_TAG,		"FILTERREADSTATUS",
		APT_UINT8					},
	{ FILTERRECIPIENT_TAG,		"FILTERRECIPIENT",
		APT_STR						},
	{ FILTERORIGINATOR_TAG,		"FILTERORIGINATOR",
		APT_STR						},
	{ FILTERPRIORITY_TAG,		"FILTERPRIORITY",
		APT_UINT8					},
	{ ATTACHMENT_TAG,		"ATTACHMENT",
		APT_UINT8					},
	{ TRANSPARENT_TAG,		"TRANSPARENT",
		APT_UINT8					},
	{ RETRY_TAG,			"RETRY",
		APT_UINT8					},
	{ NEWMESSAGE_TAG,		"NEWMESSAGE",
		APT_UINT8					},
	{ NOTIFICATIONSTATUS_TAG,	"NOTIFICATIONSTATUS",
		APT_UINT8					},
	{ MASINSTANCEID_TAG,		"MASINSTANCEID",
		APT_UINT8					},
	{ PARAMETERMASK_TAG,		"PARAMETERMASK",
		APT_UINT32					},
	{ FOLDERLISTINGSIZE_TAG,	"FOLDERLISTINGSIZE",
		APT_UINT16					},
	{ MESSAGESLISTINGSIZE_TAG,	"MESSAGESLISTINGSIZE",
		APT_UINT16					},
	{ SUBJECTLENGTH_TAG,		"SUBJECTLENGTH",
		APT_UINT8					},
	{ CHARSET_TAG,			"CHARSET",
		APT_UINT8					},
	{ FRACTIONREQUEST_TAG,		"FRACTIONREQUEST",
		APT_UINT8					},
	{ FRACTIONDELIVER_TAG,		"FRACTIONDELIVER",
		APT_UINT8					},
	{ STATUSINDICATOR_TAG,		"STATUSINDICATOR",
		APT_UINT8					},
	{ STATUSVALUE_TAG,		"STATUSVALUE",
		APT_UINT8					},
	{ MSETIME_TAG,			"MSETIME",
		APT_STR						},
	{ INVALID_TAG,			NULL,
		0						},
};

struct aparam_entry {
	enum aparam_tag tag;
	union {
		uint32_t val32u;
		uint16_t val16u;
		uint8_t val8u;
		char *valstr;
	};
};

/* This comes from OBEX specs */
struct aparam_header {
	uint8_t tag;
	uint8_t len;
	uint8_t val[0];
} __attribute__ ((packed));

struct mas_session {
	struct mas_request *request;
	void *backend_data;
	gboolean ap_sent;
	gboolean finished;
	gboolean nth_call;
	GString *buffer;
	GString *apbuf;
	GHashTable *inparams;
	GHashTable *outparams;
};

static const uint8_t MAS_TARGET[TARGET_SIZE] = {
			0xbb, 0x58, 0x2b, 0x40, 0x42, 0x0c, 0x11, 0xdb,
			0xb0, 0xde, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66  };

static int find_aparam_tag(uint8_t tag)
{
	int i;

	for (i = 0; aparam_defs[i].tag != INVALID_TAG; ++i) {
		if (aparam_defs[i].tag == tag)
			return i;
	}

	return -1;
}

static void aparams_entry_free(gpointer val)
{
	struct aparam_entry *entry = val;
	int tago;

	tago = find_aparam_tag(entry->tag);

	if (tago < 0)
		goto notagdata;

	if (aparam_defs[tago].type == APT_STR)
		g_free(entry->valstr);

notagdata:
	g_free(entry);
}

static void aparams_free(GHashTable *aparams)
{
	if (!aparams)
		return;

	g_hash_table_destroy(aparams);
}

static GHashTable *aparams_new(void)
{
	GHashTable *aparams;

	aparams = g_hash_table_new_full(NULL, NULL, NULL, aparams_entry_free);

	return aparams;
}

/* Add/replace value of given tag in parameters table. If val is null, then
 * remove selected parameter.
 */
static gboolean aparams_write(GHashTable *params, enum aparam_tag tag,
								gpointer val)
{
	struct aparam_entry *param;
	int tago;
	union {
		char *valstr;
		uint16_t val16u;
		uint32_t val32u;
		uint8_t val8u;
	} *e = val;

	tago = find_aparam_tag(tag);

	if (tago < 0)
		return FALSE;

	param = g_new0(struct aparam_entry, 1);
	param->tag = tag;

	/* XXX: will it free string? */
	g_hash_table_remove(params, GINT_TO_POINTER(tag));

	if (!val)
		return TRUE;

	switch (aparam_defs[tago].type) {
	case APT_STR:
		param->valstr = g_strdup(e->valstr);
		break;
	case APT_UINT16:
		param->val16u = e->val16u;
		break;
	case APT_UINT32:
		param->val32u = e->val32u;
		break;
	case APT_UINT8:
		param->val8u = e->val8u;
		break;
	default:
		goto failed;
	}

	g_hash_table_insert(params, GINT_TO_POINTER(tag), param);

	return TRUE;
failed:
	g_free(param);
	return FALSE;
}

static void aparams_dump(gpointer tag, gpointer val, gpointer user_data)
{
	struct aparam_entry *param = val;
	int tago;

	tago = find_aparam_tag(GPOINTER_TO_INT(tag));

	switch (aparam_defs[tago].type) {
	case APT_STR:
		DBG("%-30s %s", aparam_defs[tago].name, param->valstr);
		break;
	case APT_UINT16:
		DBG("%-30s %08x", aparam_defs[tago].name, param->val16u);
		break;
	case APT_UINT32:
		DBG("%-30s %08x", aparam_defs[tago].name, param->val32u);
		break;
	case APT_UINT8:
		DBG("%-30s %08x", aparam_defs[tago].name, param->val8u);
		break;
	}
}

static gboolean aparams_read(GHashTable *params, enum aparam_tag tag,
								gpointer val)
{
	struct aparam_entry *param;
	int tago;
	union {
		char *valstr;
		uint16_t val16u;
		uint32_t val32u;
		uint8_t val8u;
	} *e = val;

	param = g_hash_table_lookup(params, GINT_TO_POINTER(tag));

	if (!param)
		return FALSE;

	if (!val)
		goto nooutput;

	tago = find_aparam_tag(tag);

	switch (aparam_defs[tago].type) {
	case APT_STR:
		e->valstr = param->valstr;
		break;
	case APT_UINT16:
		e->val16u = param->val16u;
		break;
	case APT_UINT32:
		e->val32u = param->val32u;
		break;
	case APT_UINT8:
		e->val8u = param->val8u;
		break;
	default:
		return FALSE;
	}

nooutput:
	return TRUE;
}

static GHashTable *parse_aparam(const uint8_t *buffer, uint32_t hlen)
{
	GHashTable *aparams;
	struct aparam_header *hdr;
	uint32_t len = 0;
	uint16_t val16;
	uint32_t val32;
	union {
		char *valstr;
		uint16_t val16u;
		uint32_t val32u;
		uint8_t val8u;
	} entry;
	int tago;

	aparams = aparams_new();
	if (!aparams)
		return NULL;

	while (len < hlen) {
		hdr = (void *) buffer + len;

		tago = find_aparam_tag(hdr->tag);

		if (tago < 0)
			goto skip;

		switch (aparam_defs[tago].type) {
		case APT_STR:
			entry.valstr = g_try_malloc0(hdr->len + 1);
			if (entry.valstr)
				memcpy(entry.valstr, hdr->val, hdr->len);
			break;
		case APT_UINT16:
			if (hdr->len != 2)
				goto failed;
			memcpy(&val16, hdr->val, sizeof(val16));
			entry.val16u = GUINT16_FROM_BE(val16);
			break;
		case APT_UINT32:
			if (hdr->len != 4)
				goto failed;
			memcpy(&val32, hdr->val, sizeof(val32));
			entry.val32u = GUINT32_FROM_BE(val32);
			break;
		case APT_UINT8:
			if (hdr->len != 1)
				goto failed;
			entry.val8u = hdr->val[0];
			break;
		default:
			goto failed;
		}
		aparams_write(aparams, hdr->tag, &entry);
skip:
		len += hdr->len + sizeof(struct aparam_header);
	}

	g_hash_table_foreach(aparams, aparams_dump, NULL);

	return aparams;
failed:
	aparams_free(aparams);

	return NULL;
}

static GString *revparse_aparam(GHashTable *aparams)
{
	struct aparam_header hdr;
	gpointer key;
	gpointer value;
	uint16_t val16;
	uint32_t val32;
	union {
		char *valstr;
		uint16_t val16u;
		uint32_t val32u;
		uint8_t val8u;
	} entry;
	int tago;
	GHashTableIter iter;
	GString *buffer = NULL;

	if (!aparams)
		return NULL;

	g_hash_table_iter_init(&iter, aparams);
	buffer = g_string_new("");

	while (g_hash_table_iter_next(&iter, &key, &value)) {

		tago = find_aparam_tag(GPOINTER_TO_INT(key));

		if (tago < 0)
			goto failed;

		hdr.tag = aparam_defs[tago].tag;
		aparams_read(aparams, GPOINTER_TO_INT(key), &entry);

		switch (aparam_defs[tago].type) {
		case APT_STR:
			hdr.len = strlen(entry.valstr);
			g_string_append_len(buffer, (gpointer)&hdr,
							sizeof(hdr));
			g_string_append_len(buffer, entry.valstr, hdr.len);
			break;
		case APT_UINT16:
			hdr.len = 2;
			val16 = GUINT16_TO_BE(entry.val16u);
			g_string_append_len(buffer, (gpointer)&hdr,
							sizeof(hdr));
			g_string_append_len(buffer, (gpointer)&val16,
							sizeof(entry.val16u));
			break;
		case APT_UINT32:
			hdr.len = 4;
			val32 = GUINT32_TO_BE(entry.val32u);
			g_string_append_len(buffer, (gpointer)&hdr,
							sizeof(hdr));
			g_string_append_len(buffer, (gpointer)&val32,
							sizeof(entry.val32u));
			break;
		case APT_UINT8:
			hdr.len = 1;
			g_string_append_len(buffer, (gpointer)&hdr,
							sizeof(hdr));
			g_string_append_len(buffer, (gpointer)&entry.val8u,
							sizeof(entry.val8u));
			break;
		default:
			goto failed;
		}

	}

	return buffer;

failed:
	g_string_free(buffer, TRUE);

	return NULL;
}

static int get_params(struct obex_session *os, obex_object_t *obj,
					struct mas_session *mas)
{
	const uint8_t *buffer;
	GHashTable *inparams = NULL;
	ssize_t rsize;

	rsize = obex_aparam_read(os, obj, &buffer);

	if (rsize > 0) {
		inparams = parse_aparam(buffer, rsize);
		if (inparams == NULL) {
			DBG("Error when parsing parameters!");
			return -EBADR;
		}
	}

	if (inparams == NULL)
		inparams = aparams_new();

	mas->inparams = inparams;
	mas->outparams = aparams_new();

	return 0;
}

static void reset_request(struct mas_session *mas)
{
	if (mas->buffer) {
		g_string_free(mas->buffer, TRUE);
		mas->buffer = NULL;
	}
	if (mas->apbuf) {
		g_string_free(mas->apbuf, TRUE);
		mas->apbuf = NULL;
	}

	aparams_free(mas->inparams);
	aparams_free(mas->outparams);
	mas->ap_sent = FALSE;
	mas->nth_call = FALSE;
	mas->finished = FALSE;
}

static void mas_clean(struct mas_session *mas)
{
	reset_request(mas);
	g_free(mas);
}

static void *mas_connect(struct obex_session *os, int *err)
{
	struct mas_session *mas;

	DBG("");

	mas = g_new0(struct mas_session, 1);

	*err = messages_connect(&mas->backend_data);
	if (*err < 0)
		goto failed;

	manager_register_session(os);

	return mas;

failed:
	g_free(mas);

	return NULL;
}

static void mas_disconnect(struct obex_session *os, void *user_data)
{
	struct mas_session *mas = user_data;

	DBG("");

	manager_unregister_session(os);
	messages_disconnect(mas->backend_data);

	mas_clean(mas);
}

static int mas_get(struct obex_session *os, obex_object_t *obj, void *user_data)
{
	struct mas_session *mas = user_data;
	const char *type = obex_get_type(os);
	const char *name = obex_get_name(os);
	int ret;

	DBG("GET: name %s type %s mas %p",
			name, type, mas);

	if (type == NULL)
		return -EBADR;

	ret = get_params(os, obj, mas);
	if (ret < 0)
		goto failed;

	ret = obex_get_stream_start(os, name);
	if (ret < 0)
		goto failed;

	return 0;

failed:
	reset_request(mas);

	return ret;
}

static int mas_put(struct obex_session *os, obex_object_t *obj, void *user_data)
{
	struct mas_session *mas = user_data;
	const char *type = obex_get_type(os);
	const char *name = obex_get_name(os);
	int ret;

	DBG("PUT: name %s type %s mas %p", name, type, mas);

	if (type == NULL)
		return -EBADR;

	ret = get_params(os, obj, mas);
	if (ret < 0)
		goto failed;

	ret = obex_put_stream_start(os, name);
	if (ret < 0)
		goto failed;

	return 0;

failed:
	reset_request(mas);

	return ret;
}

/* FIXME: Preserve whitespaces */
static void g_string_append_escaped_printf(GString *string, const gchar *format,
		...)
{
	va_list ap;
	char *escaped;

	va_start(ap, format);
	escaped = g_markup_vprintf_escaped(format, ap);
	g_string_append(string, escaped);
	g_free(escaped);
	va_end(ap);
}

static const char *yesorno(gboolean a)
{
	if (a)
		return "yes";

	return "no";
}

static void get_messages_listing_cb(void *session, int err,
		uint16_t size, gboolean newmsg,
		const struct messages_message *entry,
		void *user_data)
{
	struct mas_session *mas = user_data;
	uint32_t parametermask = 0xFFFF;
	uint16_t max = 1024;
	uint8_t newmsg_byte;
	char timestr[21];
	time_t t;

	aparams_read(mas->inparams, MAXLISTCOUNT_TAG, &max);

	if (err < 0 && err != -EAGAIN) {
		obex_object_set_io_flags(mas, G_IO_ERR, err);
		return;
	}

	if (!mas->nth_call) {
		if (max)
			g_string_append(mas->buffer, ML_BODY_BEGIN);
		mas->nth_call = TRUE;
	}

	if (!entry) {
		if (max)
			g_string_append(mas->buffer, ML_BODY_END);
		mas->finished = TRUE;

		newmsg_byte = newmsg ? 1 : 0;
		aparams_write(mas->outparams, NEWMESSAGE_TAG, &newmsg_byte);
		aparams_write(mas->outparams, MESSAGESLISTINGSIZE_TAG, &size);
		time(&t);
		strftime(timestr, sizeof(*timestr), "%Y%m%dT%H%M%S%z",
				localtime(&t));
		aparams_write(mas->outparams, MSETIME_TAG, &timestr);

		goto proceed;
	}

	aparams_read(mas->inparams, PARAMETERMASK_TAG, &parametermask);
	if (parametermask == 0)
		parametermask = 0xFFFF;

	g_string_append(mas->buffer, "<msg");

	g_string_append_escaped_printf(mas->buffer, " handle=\"%s\"",
								entry->handle);

	if (parametermask & PMASK_SUBJECT && entry->mask & PMASK_SUBJECT)
		g_string_append_escaped_printf(mas->buffer, " subject=\"%s\"",
				entry->subject);

	if (parametermask & PMASK_DATETIME &&
			entry->mask & PMASK_DATETIME)
		g_string_append_escaped_printf(mas->buffer, " datetime=\"%s\"",
				entry->datetime);

	if (parametermask & PMASK_SENDER_NAME &&
			entry->mask & PMASK_SENDER_NAME)
		g_string_append_escaped_printf(mas->buffer,
						" sender_name=\"%s\"",
						entry->sender_name);

	if (parametermask & PMASK_SENDER_ADDRESSING &&
			entry->mask & PMASK_SENDER_ADDRESSING)
		g_string_append_escaped_printf(mas->buffer,
						" sender_addressing=\"%s\"",
						entry->sender_addressing);

	if (parametermask & PMASK_REPLYTO_ADDRESSING &&
			entry->mask & PMASK_REPLYTO_ADDRESSING)
		g_string_append_escaped_printf(mas->buffer,
						" replyto_addressing=\"%s\"",
						entry->replyto_addressing);

	if (parametermask & PMASK_RECIPIENT_NAME &&
			entry->mask & PMASK_RECIPIENT_NAME)
		g_string_append_escaped_printf(mas->buffer,
						" recipient_name=\"%s\"",
						entry->recipient_name);

	if (parametermask & PMASK_RECIPIENT_ADDRESSING &&
			entry->mask & PMASK_RECIPIENT_ADDRESSING)
		g_string_append_escaped_printf(mas->buffer,
						" recipient_addressing=\"%s\"",
						entry->recipient_addressing);

	if (parametermask & PMASK_TYPE &&
			entry->mask & PMASK_TYPE)
		g_string_append_escaped_printf(mas->buffer, " type=\"%s\"",
				entry->type);

	if (parametermask & PMASK_RECEPTION_STATUS &&
			entry->mask & PMASK_RECEPTION_STATUS)
		g_string_append_escaped_printf(mas->buffer,
						" reception_status=\"%s\"",
						entry->reception_status);

	if (parametermask & PMASK_SIZE &&
			entry->mask & PMASK_SIZE)
		g_string_append_escaped_printf(mas->buffer, " size=\"%s\"",
				entry->size);

	if (parametermask & PMASK_ATTACHMENT_SIZE &&
			entry->mask & PMASK_ATTACHMENT_SIZE)
		g_string_append_escaped_printf(mas->buffer,
						" attachment_size=\"%s\"",
						entry->attachment_size);

	if (parametermask & PMASK_TEXT &&
			entry->mask & PMASK_TEXT)
		g_string_append_escaped_printf(mas->buffer, " text=\"%s\"",
				yesorno(entry->text));

	if (parametermask & PMASK_READ &&
			entry->mask & PMASK_READ)
		g_string_append_escaped_printf(mas->buffer, " read=\"%s\"",
				yesorno(entry->read));

	if (parametermask & PMASK_SENT &&
			entry->mask & PMASK_SENT)
		g_string_append_escaped_printf(mas->buffer, " sent=\"%s\"",
				yesorno(entry->sent));

	if (parametermask & PMASK_PROTECTED &&
			entry->mask & PMASK_PROTECTED)
		g_string_append_escaped_printf(mas->buffer, " protected=\"%s\"",
				yesorno(entry->protect));

	if (parametermask & PMASK_PRIORITY &&
			entry->mask & PMASK_PRIORITY)
		g_string_append_escaped_printf(mas->buffer, " priority=\"%s\"",
				yesorno(entry->priority));

	g_string_append(mas->buffer, "/>\n");

proceed:
	if (err != -EAGAIN)
		obex_object_set_io_flags(mas, G_IO_IN, 0);
}

static void get_message_cb(void *session, int err, gboolean fmore,
	const char *chunk, void *user_data)
{
	struct mas_session *mas = user_data;
	uint8_t fmore_byte;

	DBG("");

	if (err < 0 && err != -EAGAIN) {
		obex_object_set_io_flags(mas, G_IO_ERR, err);
		return;
	}

	if (!chunk) {
		mas->finished = TRUE;

		if (aparams_read(mas->inparams, FRACTIONREQUEST_TAG, NULL)) {
			fmore_byte = fmore ? 1 : 0;
			aparams_write(mas->outparams, FRACTIONDELIVER_TAG,
									&fmore);
		}

		goto proceed;
	}

	g_string_append(mas->buffer, chunk);

proceed:
	if (err != -EAGAIN)
		obex_object_set_io_flags(mas, G_IO_IN, 0);
}

static void get_folder_listing_cb(void *session, int err, uint16_t size,
					const char *name, void *user_data)
{
	struct mas_session *mas = user_data;
	uint16_t max = 1024;

	if (err < 0 && err != -EAGAIN) {
		obex_object_set_io_flags(mas, G_IO_ERR, err);
		return;
	}

	aparams_read(mas->inparams, MAXLISTCOUNT_TAG, &max);

	if (max == 0) {
		if (!err != -EAGAIN)
			aparams_write(mas->outparams, FOLDERLISTINGSIZE_TAG,
					&size);
		if (!name)
			mas->finished = TRUE;
		goto proceed;
	}

	if (!mas->nth_call) {
		g_string_append(mas->buffer, XML_DECL);
		g_string_append(mas->buffer, FL_DTD);
		if (!name) {
			g_string_append(mas->buffer, FL_BODY_EMPTY);
			mas->finished = TRUE;
			goto proceed;
		}
		g_string_append(mas->buffer, FL_BODY_BEGIN);
		mas->nth_call = TRUE;
	}

	if (!name) {
		g_string_append(mas->buffer, FL_BODY_END);
		mas->finished = TRUE;
		goto proceed;
	}

	if (g_strcmp0(name, "..") == 0)
		g_string_append(mas->buffer, FL_PARENT_FOLDER_ELEMENT);
	else
		g_string_append_escaped_printf(mas->buffer, FL_FOLDER_ELEMENT,
									name);

proceed:
	if (err != -EAGAIN)
		obex_object_set_io_flags(mas, G_IO_IN, err);
}

static int mas_setpath(struct obex_session *os, obex_object_t *obj,
		void *user_data)
{
	const char *name;
	uint8_t *nonhdr;
	struct mas_session *mas = user_data;

	if (OBEX_ObjectGetNonHdrData(obj, &nonhdr) != 2) {
		error("Set path failed: flag and constants not found!");
		return -EBADR;
	}

	name = obex_get_name(os);

	DBG("SETPATH: name %s nonhdr 0x%x%x", name, nonhdr[0], nonhdr[1]);

	if ((nonhdr[0] & 0x02) != 0x02) {
		DBG("Error: requested directory creation");
		return -EBADR;
	}

	return messages_set_folder(mas->backend_data, name, nonhdr[0] & 0x01);
}

static void *folder_listing_open(const char *name, int oflag, mode_t mode,
				void *driver_data, size_t *size, int *err)
{
	struct mas_session *mas = driver_data;
	/* 1024 is the default when there was no MaxListCount sent */
	uint16_t max = 1024;
	uint16_t offset = 0;

	if (oflag != O_RDONLY) {
		*err = -EBADR;
		return NULL;
	}

	DBG("name = %s", name);

	mas->apbuf = NULL;
	mas->buffer = NULL;

	aparams_read(mas->inparams, MAXLISTCOUNT_TAG, &max);
	aparams_read(mas->inparams, STARTOFFSET_TAG, &offset);

	*err = messages_get_folder_listing(mas->backend_data, name, max, offset,
			get_folder_listing_cb, mas);

	mas->buffer = g_string_new("");

	if (*err < 0)
		return NULL;
	else
		return mas;
}

static void *msg_listing_open(const char *name, int oflag, mode_t mode,
				void *driver_data, size_t *size, int *err)
{
	struct mas_session *mas = driver_data;
	struct messages_filter filter = { 0, };
	uint16_t max = 1024;
	uint16_t offset = 0;

	DBG("");

	if (oflag != O_RDONLY) {
		*err = -EBADR;
		return NULL;
	}

	mas->apbuf = NULL;
	mas->buffer = NULL;

	aparams_read(mas->inparams, MAXLISTCOUNT_TAG, &max);
	aparams_read(mas->inparams, STARTOFFSET_TAG, &offset);
	aparams_read(mas->inparams, PARAMETERMASK_TAG, &filter.parameter_mask);
	aparams_read(mas->inparams, FILTERMESSAGETYPE_TAG, &filter.type);
	aparams_read(mas->inparams, FILTERPERIODBEGIN_TAG, &filter.period_begin);
	aparams_read(mas->inparams, FILTERPERIODEND_TAG, &filter.period_end);
	aparams_read(mas->inparams, FILTERREADSTATUS_TAG, &filter.read_status);
	aparams_read(mas->inparams, FILTERRECIPIENT_TAG, &filter.recipient);
	aparams_read(mas->inparams, FILTERORIGINATOR_TAG, &filter.originator);
	aparams_read(mas->inparams, FILTERPRIORITY_TAG, &filter.priority);

	*err = messages_get_messages_listing(mas->backend_data, name, max,
			offset, &filter,
			get_messages_listing_cb, mas);

	mas->buffer = g_string_new("");

	if (*err < 0)
		return NULL;
	else
		return mas;
}

static void *message_open(const char *name, int oflag, mode_t mode,
				void *driver_data, size_t *size, int *err)
{
	struct mas_session *mas = driver_data;
	unsigned long flags;
	uint8_t freq;
	uint8_t charset = 0;

	DBG("");

	if (oflag != O_RDONLY) {
		DBG("Message pushing unsupported");
		*err = -EINVAL;

		return NULL;
	}

	if (aparams_read(mas->inparams, FRACTIONREQUEST_TAG, &freq)) {
		flags |= MESSAGES_FRACTION;
		if (freq & 0x01)
			flags |= MESSAGES_NEXT;
	}

	aparams_read(mas->inparams, CHARSET_TAG, &charset);
	if (charset & 0x01)
		flags |= MESSAGES_UTF8;

	*err = messages_get_message(mas->backend_data, name, 0,
			get_message_cb, mas);

	mas->buffer = g_string_new("");

	if (*err < 0)
		return NULL;
	else
		return mas;
}

static void *any_open(const char *name, int oflag, mode_t mode,
				void *driver_data, size_t *size, int *err)
{
	DBG("");

	*err = -EINVAL;

	return NULL;
}

static ssize_t any_write(void *object, const void *buf, size_t count)
{
	DBG("");

	return count;
}

static ssize_t any_get_next_header(void *object, void *buf, size_t mtu,
								uint8_t *hi)
{
	struct mas_session *mas = object;

	DBG("");

	if (mas->buffer->len == 0 && !mas->finished)
		return -EAGAIN;

	*hi = OBEX_HDR_APPARAM;

	if (!mas->ap_sent) {
		mas->ap_sent = TRUE;
		mas->apbuf = revparse_aparam(mas->outparams);
	}

	return string_read(mas->apbuf, buf, mtu);
}

static ssize_t any_read(void *obj, void *buf, size_t count)
{
	struct mas_session *mas = obj;
	ssize_t len;

	DBG("");

	len = string_read(mas->buffer, buf, count);

	if (len == 0 && !mas->finished)
		return -EAGAIN;

	return len;
}

static int any_close(void *obj)
{
	struct mas_session *mas = obj;

	DBG("");

	if (!mas->finished)
		messages_abort(mas->backend_data);

	reset_request(mas);

	return 0;
}

static struct obex_service_driver mas = {
	.name = "Message Access server",
	.service = OBEX_MAS,
	.channel = MAS_CHANNEL,
	.record = MAS_RECORD,
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.connect = mas_connect,
	.get = mas_get,
	.put = mas_put,
	.setpath = mas_setpath,
	.disconnect = mas_disconnect,
};

static struct obex_mime_type_driver mime_map = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = NULL,
	.open = any_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_message = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/message",
	.get_next_header = any_get_next_header,
	.open = message_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_folder_listing = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-obex/folder-listing",
	.get_next_header = any_get_next_header,
	.open = folder_listing_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_msg_listing = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/MAP-msg-listing",
	.get_next_header = any_get_next_header,
	.open = msg_listing_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_notification_registration = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/MAP-NotificationRegistration",
	.open = any_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_message_status = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/messageStatus",
	.open = any_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_message_update = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/MAP-messageUpdate",
	.open = any_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver *map_drivers[] = {
	&mime_map,
	&mime_message,
	&mime_folder_listing,
	&mime_msg_listing,
	&mime_notification_registration,
	&mime_message_status,
	&mime_message_update,
	NULL
};

static int mas_init(void)
{
	int err;
	int i;

	err = messages_init();
	if (err < 0)
		return err;

	for (i = 0; map_drivers[i] != NULL; ++i) {
		err = obex_mime_type_driver_register(map_drivers[i]);
		if (err < 0)
			goto failed;
	}

	err = obex_service_driver_register(&mas);
	if (err < 0)
		goto failed;

	return 0;

failed:
	for (--i; i >= 0; --i)
		obex_mime_type_driver_unregister(map_drivers[i]);

	messages_exit();

	return err;
}

static void mas_exit(void)
{
	int i;

	obex_service_driver_unregister(&mas);

	for (i = 0; map_drivers[i] != NULL; ++i)
		obex_mime_type_driver_unregister(map_drivers[i]);

	messages_exit();
}

OBEX_PLUGIN_DEFINE(mas, mas_init, mas_exit)
