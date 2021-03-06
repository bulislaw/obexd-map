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

#include "bmsg.h"

static void string_append_glist(void *list_item, void *list)
{
	GString *buf = list;

	g_string_append(buf, list_item);
}

static void envelope_destroy(struct bmsg_envelope *env)
{
	if (env->recipients) {
		g_list_foreach(env->recipients, (GFunc) g_free, NULL);
		g_list_free(env->recipients);
	}

	if (env->content == NULL)
		return;

	g_free(env->content->encoding);
	g_free(env->content->charset);
	g_free(env->content->lang);
	g_free(env->content->content);
	g_free(env->content);
}

void bmsg_init(struct bmsg *msg, const char *version, const char *status,
		const char *type, const char *folder)
{
	msg->version = g_strdup(version);
	msg->status = g_strdup(status);
	msg->type = g_strdup(type);
	msg->folder = g_strdup(folder);
	msg->envelopes = g_array_sized_new(FALSE, TRUE,
					sizeof(struct bmsg_envelope *),
					MAX_ENVELOPES_NUM);
}

void bmsg_destroy(struct bmsg *msg)
{
	unsigned i;

	g_free(msg->version);
	g_free(msg->status);
	g_free(msg->type);
	g_free(msg->folder);

	if (msg->originators) {
		g_list_foreach(msg->originators, (GFunc) g_free, NULL);
		g_list_free(msg->originators);
	}

	if (msg->envelopes == NULL)
		return;

	for (i = 0; i < msg->envelopes->len; i++) {
		struct bmsg_envelope *tmp = g_array_index(msg->envelopes,
						struct bmsg_envelope *, i);

		envelope_destroy(tmp);
		g_free(tmp);
	}

	g_array_free(msg->envelopes, TRUE);

	g_free(msg);
}

void bmsg_add_originator(struct bmsg *msg, struct phonebook_contact *contact)
{
	GString *vcard = g_string_new("");

	phonebook_add_contact(vcard, contact, 0, FORMAT_VCARD21);
	msg->originators = g_list_append(msg->originators,
						g_string_free(vcard, FALSE));
}

gboolean bmsg_add_envelope(struct bmsg *msg)
{
	struct bmsg_envelope *tmp;

	if (msg->envelopes->len == MAX_ENVELOPES_NUM)
		return FALSE;

	if (msg->envelopes->len && g_array_index(msg->envelopes,
				struct bmsg_envelope *,
				msg->envelopes->len - 1)->content != NULL)
		 return FALSE;

	tmp = g_new0(struct bmsg_envelope, 1);

	g_array_append_val(msg->envelopes, tmp);

	return TRUE;
}

void bmsg_add_recipient(struct bmsg *msg, struct phonebook_contact *contact)
{
	struct bmsg_envelope *top_env;
	GString *vcard;

	if (msg->envelopes->len == 0)
		return;

	top_env = g_array_index(msg->envelopes, struct bmsg_envelope *,
						msg->envelopes->len - 1);

	vcard = g_string_new("");
	phonebook_add_contact(vcard, contact, 0, FORMAT_VCARD21);

	top_env->recipients = g_list_append(top_env->recipients,
						g_string_free(vcard, FALSE));
}

gboolean bmsg_add_content(struct bmsg *msg, gint32 part_id, char *encoding,
			char *charset, char *lang, const char *content)
{
	struct bmsg_envelope *tmp;
	struct bmsg_content *cont;

	if (content == NULL)
		return FALSE;

	if (msg->envelopes->len == 0)
		return FALSE;

	tmp = g_array_index(msg->envelopes, struct bmsg_envelope *,
						msg->envelopes->len - 1);

	if (tmp->content != NULL)
		return FALSE;

	cont = g_new0(struct bmsg_content, 1);
	cont->part_id = part_id;

	if (encoding)
		cont->encoding = g_strdup(encoding);

	if (charset)
		cont->charset = g_strdup(charset);

	if (lang)
		cont->lang = g_strdup(lang);

	cont->content = g_strdup(content);

	tmp->content = cont;

	return TRUE;
}

static GString *parse_content(struct bmsg_content *cont)
{
	GString *buf = g_string_new("");

	g_string_append_printf(buf, "BEGIN:BBODY\r\n");

	if (cont->part_id != -1)
		g_string_append_printf(buf, "PARTID:%d\r\n", cont->part_id);

	if (cont->encoding != NULL)
		g_string_append_printf(buf, "ENCODING:%s\r\n", cont->encoding);

	if (cont->charset != NULL)
		g_string_append_printf(buf, "CHARSET:%s\r\n", cont->charset);

	if (cont->lang != NULL)
		g_string_append_printf(buf, "LANGUAGE:%s\r\n", cont->lang);

	if (cont->len > 0)
		g_string_append_printf(buf, "LENGTH:%d\r\n", cont->len);
	else
		g_string_append_printf(buf, "LENGTH:%d\r\n",
							strlen(cont->content) +
							BMESSAGE_BASE_LEN);

	g_string_append_printf(buf, "BEGIN:MSG\r\n%s\r\nEND:MSG\r\n",
								cont->content);
	g_string_append_printf(buf, "END:BBODY\r\n");

	return buf;
}

static GString *parse_envelope(struct bmsg *msg, unsigned num)
{
	GString *buf;
	struct bmsg_envelope *env;
	GString *tmp;

	if (num >= msg->envelopes->len)
		return NULL;

	buf = g_string_new("");

	env = g_array_index(msg->envelopes, struct bmsg_envelope *, num);

	g_string_append_printf(buf, "BEGIN:BENV\r\n");
	g_list_foreach(env->recipients, string_append_glist, buf);

	tmp = parse_envelope(msg, num + 1);
	if (tmp == NULL) {
		if (env->content == NULL) {
			g_string_free(buf, TRUE);

			return NULL;
		}

		tmp = parse_content(env->content);
	}

	g_string_append_printf(buf, "%s", tmp->str);
	g_string_free(tmp, TRUE);

	g_string_append_printf(buf, "END:BENV\r\n");

	return buf;
}

char *bmsg_text(struct bmsg *msg)
{
	GString *buf = g_string_new("");
	GString *env;
	char *ret;

	g_string_append_printf(buf, "BEGIN:BMSG\r\n");

	g_string_append_printf(buf, "VERSION:%s\r\n", msg->version);
	g_string_append_printf(buf, "STATUS:%s\r\n", msg->status);
	g_string_append_printf(buf, "TYPE:%s\r\n", msg->type);
	g_string_append_printf(buf, "FOLDER:%s\r\n", msg->folder);

	g_list_foreach(msg->originators, string_append_glist, buf);

	env = parse_envelope(msg, 0);
	if (env == NULL) {
		g_string_free(buf, TRUE);

		return NULL;
	}

	g_string_append_printf(buf, "%s", env->str);
	g_string_free(env, TRUE);

	g_string_append_printf(buf, "END:BMSG\r\n");

	ret = g_strdup(buf->str);
	g_string_free(buf, TRUE);

	return ret;
}
