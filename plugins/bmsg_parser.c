#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "log.h"

#include "bmsg_parser.h"

static struct {
	enum bmsg_encoding encoding;
	char *s;
} bmsg_encodings[] = {
	{ BMSG_E_8BIT, "8BIT" },
	{ BMSG_E_G_7BIT, "G-7BIT" },
	{ BMSG_E_G_7BITEXT, "G-7BITEXT" },
	{ BMSG_E_G_UCS2, "G-UCS2" },
	{ BMSG_E_G_8BIT, "G-8BIT" },
	{ BMSG_E_C_8BIT, "C-8BIT" },
	{ BMSG_E_C_EPM, "C-EPM" },
	{ BMSG_E_C_7ASCII, "C-7ASCII" },
	{ BMSG_E_C_IA5, "C-IA5" },
	{ BMSG_E_C_UNICODE, "C-UNICODE" },
	{ BMSG_E_C_SJIS, "C-SJIS" },
	{ BMSG_E_C_KOREAN, "C-KOREAN" },
	{ BMSG_E_C_LATINHEB, "C-LATINHEB" },
	{ BMSG_E_C_LATIN, "C-LATIN" }
};

static struct {
	enum bmsg_language language;
	char *s;
} bmsg_languages[] = {
	{ BMSG_L_TURKISH, "TURKISH" },
	{ BMSG_L_SPANISH, "SPANISH" },
	{ BMSG_L_PORTUGUESE, "PORTUGUESE" },
	{ BMSG_L_UNKNOWN, "UNKNOWN" },
	{ BMSG_L_ENGLISH, "ENGLISH" },
	{ BMSG_L_FRENCH, "FRENCH" },
	{ BMSG_L_JAPANESE, "JAPANESE" },
	{ BMSG_L_KOREAN, "KOREAN" },
	{ BMSG_L_CHINESE, "CHINESE" },
	{ BMSG_L_HEBREW, "HEBREW" }
};

static int bmsg_parser_begin_bmsg(struct bmsg_parser *);
static int bmsg_parser_version(struct bmsg_parser *);
static int bmsg_parser_status(struct bmsg_parser *);
static int bmsg_parser_type(struct bmsg_parser *);
static int bmsg_parser_folder(struct bmsg_parser *);
static int bmsg_parser_originator(struct bmsg_parser *);
static int bmsg_parser_vcard(struct bmsg_parser *);
static int bmsg_parser_begin_envelope(struct bmsg_parser *);
static int bmsg_parser_recipient(struct bmsg_parser *);
static int bmsg_parser_begin_body(struct bmsg_parser *);
static int bmsg_parser_part_id(struct bmsg_parser *);
static int bmsg_parser_encoding(struct bmsg_parser *);
static int bmsg_parser_charset(struct bmsg_parser *);
static int bmsg_parser_language(struct bmsg_parser *);
static int bmsg_parser_length(struct bmsg_parser *);

enum bmsg_parser_state {
	BMSG_STATE_BEGIN_BMSG,
	BMSG_STATE_VERSION,
	BMSG_STATE_STATUS,
	BMSG_STATE_TYPE,
	BMSG_STATE_FOLDER,
	BMSG_STATE_ORIGINATOR,
	BMSG_STATE_VCARD,
	BMSG_STATE_BEGIN_ENVELOPE,
	BMSG_STATE_RECIPIENT,
	BMSG_STATE_BEGIN_BODY,
	BMSG_STATE_PART_ID,
	BMSG_STATE_ENCODING,
	BMSG_STATE_CHARSET,
	BMSG_STATE_LANGUAGE,
	BMSG_STATE_LENGTH,
	BMSG_STATE_BEGIN_MSG,
	BMSG_STATE_NSTATES
};

int (*actions[BMSG_STATE_NSTATES])(struct bmsg_parser *) = {
	 bmsg_parser_begin_bmsg,
	 bmsg_parser_version,
	 bmsg_parser_status,
	 bmsg_parser_type,
	 bmsg_parser_folder,
	 bmsg_parser_originator,
	 bmsg_parser_vcard,
	 bmsg_parser_begin_envelope,
	 bmsg_parser_recipient,
	 bmsg_parser_begin_body,
	 bmsg_parser_part_id,
	 bmsg_parser_encoding,
	 bmsg_parser_charset,
	 bmsg_parser_language,
	 bmsg_parser_length,
	 NULL
};

struct bmsg_parser {
	struct bmsg_bmsg *bmsg;
	enum bmsg_parser_state state;
	enum bmsg_parser_state unwind_state;
	gboolean finished;
	char *input;
	char *eol;
	ssize_t nleft;
	struct bmsg_bmsg_vcard *vcard;
};

static int match_full_line(struct bmsg_parser *pd, const char *pattern)
{
	size_t len;

	len = pd->eol - pd->input;

	if (strncmp(pattern, pd->input, len) != 0)
		return -1;

	len += 2;
	pd->input += len;
	pd->nleft -= len;

	return 0;
}

static ssize_t match_with_param(struct bmsg_parser *pd, const char *pattern,
								char **param)
{
	size_t len;
	size_t plen;
	size_t vlen;

	len = pd->eol - pd->input;
	plen = strlen(pattern);

	if (plen > len || strncmp(pattern, pd->input, plen) != 0)
		return -1;

	vlen = len - plen;
	*param = pd->input + plen;

	len += 2;
	pd->input += len;
	pd->nleft -= len;

	return vlen;
}

static int bmsg_parser_begin_bmsg(struct bmsg_parser *pd)
{
	if (match_full_line(pd, "BEGIN:BMSG"))
		return -1;

	pd->state = BMSG_STATE_VERSION;

	return 0;
}

static int bmsg_parser_version(struct bmsg_parser *pd)
{
	char *ver;
	ssize_t len;

	len = match_with_param(pd, "VERSION:", &ver);
	if (len < 0 || strncmp(ver, "1.0", len) != 0)
		return -1;

	pd->state = BMSG_STATE_STATUS;

	return 0;
}

static int bmsg_parser_status(struct bmsg_parser *pd)
{
	char *status;
	ssize_t len;

	pd->state = BMSG_STATE_TYPE;

	len = match_with_param(pd, "STATUS:", &status);
	if (len < 0)
		return -1;

	if (strncmp(status, "READ", len) == 0)
		pd->bmsg->read = TRUE;
	else if (strncmp(status, "UNREAD", len) == 0)
		pd->bmsg->read = FALSE;
	else
		return -1;

	pd->state = BMSG_STATE_TYPE;

	return 0;
}

static int bmsg_parser_type(struct bmsg_parser *pd)
{
	char *type;
	ssize_t len;

	len = match_with_param(pd, "TYPE:", &type);
	if (len < 0)
		return -1;

	if (strncmp(type, "SMS_GSM", len) == 0)
		pd->bmsg->type = BMSG_T_SMS_GSM;
	else if (strncmp(type, "SMS_CDMA", len) == 0)
		pd->bmsg->type = BMSG_T_SMS_CDMA;
	else if (strncmp(type, "EMAIL", len) == 0)
		pd->bmsg->type = BMSG_T_EMAIL;
	else if (strncmp(type, "MMS", len) == 0)
		pd->bmsg->type = BMSG_T_MMS;
	else
		return -1;

	pd->state = BMSG_STATE_FOLDER;

	return 0;
}

static int bmsg_parser_folder(struct bmsg_parser *pd)
{
	char *folder;
	ssize_t len;

	len = match_with_param(pd, "FOLDER:", &folder);
	if (len < 0)
		return -1;

	pd->bmsg->folder = g_strndup(folder, len);
	pd->state = BMSG_STATE_ORIGINATOR;

	return 0;
}

static int bmsg_parser_originator(struct bmsg_parser *pd)
{
	if (match_full_line(pd, "BEGIN:VCARD") == 0) {
		pd->vcard = g_new0(struct bmsg_bmsg_vcard, 1);
		pd->bmsg->originators = g_slist_append(pd->bmsg->originators,
								pd->vcard);
		pd->state = BMSG_STATE_VCARD;
		pd->unwind_state = BMSG_STATE_ORIGINATOR;
	} else {
		pd->state = BMSG_STATE_BEGIN_ENVELOPE;
	}

	return 0;
}

static int bmsg_parser_vcard(struct bmsg_parser *pd)
{
	/* FIXME: This could be more sophisticated, e.g. support folding or
	 * preprocess N field */
	ssize_t len;
	char *val;

	if ((len = match_with_param(pd, "VERSION:", &val)) >= 0) {
		if (strncmp(val, "2.1", len) == 0)
			pd->vcard->version = BMSG_VCARD_21;
		else if (strncmp(val, "3.0", len) == 0)
			pd->vcard->version = BMSG_VCARD_30;
		else
			return -1;
	} else if ((len = match_with_param(pd, "FN:", &val)) >= 0) {
		if (pd->vcard->fn == NULL)
			pd->vcard->fn = g_strndup(val, len);
	} else if ((len = match_with_param(pd, "N:", &val)) >= 0) {
		if (pd->vcard->n == NULL)
			pd->vcard->n = g_strndup(val, len);
	} else if ((len = match_with_param(pd, "TEL:", &val)) >= 0) {
		if (pd->vcard->tel == NULL)
			pd->vcard->tel = g_strndup(val, len);
	} else if ((len = match_with_param(pd, "EMAIL:", &val)) >= 0) {
		if (pd->vcard->email == NULL)
			pd->vcard->email = g_strndup(val, len);
	} else if (match_full_line(pd, "END:VCARD") == 0) {
		pd->state = pd->unwind_state;
	} else {
		return -1;
	}

	return 0;
}

static int bmsg_parser_begin_envelope(struct bmsg_parser *pd)
{
	if (match_full_line(pd, "BEGIN:BENV") != 0) {
		if (pd->bmsg->nenvelopes == 0)
			return -1;

		pd->state = BMSG_STATE_BEGIN_BODY;

		return 0;
	}

	if (pd->bmsg->nenvelopes >= BMSG_NENVELOPES_MAX)
		return -1;

	++pd->bmsg->nenvelopes;
	pd->state = BMSG_STATE_RECIPIENT;

	return 0;
}

static int bmsg_parser_recipient(struct bmsg_parser *pd)
{
	if (match_full_line(pd, "BEGIN:VCARD") == 0) {
		int i;

		pd->vcard = g_new0(struct bmsg_bmsg_vcard, 1);
		i = pd->bmsg->nenvelopes - 1;
		pd->bmsg->recipients[i] = g_slist_append(pd->bmsg->recipients[i],
								pd->vcard);
		pd->state = BMSG_STATE_VCARD;
		pd->unwind_state = BMSG_STATE_RECIPIENT;
	} else {
		pd->state = BMSG_STATE_BEGIN_ENVELOPE;
	}

	return 0;
}

static int bmsg_parser_begin_body(struct bmsg_parser *pd)
{
	if (match_full_line(pd, "BEGIN:BBODY") != 0)
		return -1;

	pd->state = BMSG_STATE_PART_ID;

	return 0;
}

static int bmsg_parser_part_id(struct bmsg_parser *pd)
{
	ssize_t len;
	char *val, *s, *e;
	unsigned long id;

	len = match_with_param(pd, "PARTID:", &val);
	if (len < 0)
		goto cont;

	if (!isdigit(val[0]))
		return -1;

	s = g_strndup(val, len);
	id = strtoul(val, &e, 10);
	g_free(s);

	if (*e != '\0')
		return -1;
	if (id > 65535)
		return -1;

	pd->bmsg->part_id = id;

cont:
	pd->state = BMSG_STATE_ENCODING;

	return 0;
}

static int bmsg_parser_encoding(struct bmsg_parser *pd)
{
	ssize_t len;
	char *val;
	unsigned int i;

	len = match_with_param(pd, "ENCODING:", &val);
	if (len < 0)
		goto cont;

	for (i = 0; i < sizeof(bmsg_encodings)/sizeof(bmsg_encodings[0]); ++i) {
		if (strncmp(val, bmsg_encodings[i].s, len) == 0) {
			pd->bmsg->encoding = bmsg_encodings[i].encoding;
			goto cont;
		}
	}

	return -1;	/* No matching encoding */

cont:
	pd->state = BMSG_STATE_CHARSET;

	return 0;
}

static int bmsg_parser_charset(struct bmsg_parser *pd)
{
	ssize_t len;
	char *val;

	len = match_with_param(pd, "CHARSET:", &val);
	if (len < 0)
		goto cont;

	if (strncmp(val, "UTF-8", len) != 0)
		return -1;

	pd->bmsg->charset = BMSG_C_UTF8;
cont:
	pd->state = BMSG_STATE_LANGUAGE;

	return 0;
}

static int bmsg_parser_language(struct bmsg_parser *pd)
{
	ssize_t len;
	char *val;
	unsigned int i;

	len = match_with_param(pd, "LANGUAGE:", &val);
	if (len < 0)
		goto cont;

	for (i = 0; i < sizeof(bmsg_languages)/sizeof(bmsg_languages[0]); ++i) {
		if (strncmp(val, bmsg_languages[i].s, len) == 0) {
			pd->bmsg->language = bmsg_languages[i].language;
			goto cont;
		}
	}

	return -1;	/* No matching language */

cont:
	pd->state = BMSG_STATE_LENGTH;

	return 0;
}

static int bmsg_parser_length(struct bmsg_parser *pd)
{
	ssize_t len;
	char *val, *s, *e;
	unsigned long length;

	len = match_with_param(pd, "LENGTH:", &val);
	if (len < 0)
		return -1;

	if (!isdigit(val[0]))
		return -1;

	s = g_strndup(val, len);

	length = strtoul(s, &e, 10);
	if (*e != '\0')
		return -1;

	g_free(s);

	pd->bmsg->length = length;
	pd->state = BMSG_STATE_BEGIN_MSG;

	return 0;
}

struct bmsg_bmsg *bmsg_new(void)
{
	struct bmsg_bmsg *bmsg = g_new0(struct bmsg_bmsg, 1);

	bmsg->part_id = -1;

	return bmsg;
}

static void bmsg_vcard_free(gpointer data)
{
	struct bmsg_bmsg_vcard *vc = data;

	g_free(vc->fn);
	g_free(vc->n);
	g_free(vc->tel);
	g_free(vc->email);
	g_free(vc);
}

void bmsg_free(struct bmsg_bmsg *bmsg)
{
	if (bmsg == NULL)
		return;

	g_slist_free_full(bmsg->originators, bmsg_vcard_free);

	while (bmsg->nenvelopes) {
		--bmsg->nenvelopes;
		g_slist_free_full(bmsg->recipients[bmsg->nenvelopes],
							bmsg_vcard_free);
	}

	g_free(bmsg->folder);
	g_free(bmsg);
}

struct bmsg_parser *bmsg_parser_new(void)
{
	struct bmsg_parser *pd;

	pd = g_new0(struct bmsg_parser, 1);
	pd->bmsg = bmsg_new();

	return pd;
}

int bmsg_parser_process(struct bmsg_parser *pd, char **data, size_t len)
{
	int ret;

	if (pd->finished)
		return 0;

	pd->input = *data;
	pd->nleft = len;

	for (;;) {
		DBG("for %d %p", pd->state, actions[pd->state]);
		if (actions[pd->state] == NULL) {
			pd->finished = TRUE;
			ret = 0;
			break;
		}

		pd->eol = g_strstr_len(pd->input, pd->nleft, "\r\n");
		if (pd->eol == NULL) {
			ret = 1;
			break;
		}

		ret = actions[pd->state](pd);
		if (ret < 0) {
			char *tmp;

			tmp = pd->input;
			if ((pd->input - *data) > 20)
				tmp = pd->input - 20;
			else
				tmp = *data;

			/* FIXME: no zero */
			DBG("bmsg parsing error, state %d, context: %.40s",
								pd->state, tmp);

			pd->finished = TRUE;
			break;
		}
	}

	*data = pd->input;

	return ret;
}

struct bmsg_bmsg *bmsg_parser_get_bmsg(struct bmsg_parser *pd)
{
	struct bmsg_bmsg *bmsg;

	if (!pd->finished)
		return NULL;

	bmsg = pd->bmsg;
	pd->bmsg = NULL;

	return bmsg;
}

void bmsg_parser_free(struct bmsg_parser *pd)
{
	if (pd == NULL)
		return;

	bmsg_free(pd->bmsg);
	g_free(pd);
}

static gboolean match_and_move(char **buf, char *pattern, size_t *len)
{
	size_t plen = strlen(pattern);

	if (*len < plen)
		return FALSE;

	if (strncmp(*buf, pattern, plen) == 0) {
		*buf += plen;
		*len -= plen;
		return TRUE;
	}

	return FALSE;
}

gboolean bmsg_parser_tail_correct(struct bmsg_bmsg *bmsg, char *tail, size_t len)
{
	int nenv = bmsg->nenvelopes;
	char *t = tail;

	if (!match_and_move(&t, "END:BBODY\r\n", &len))
		return FALSE;

	while (nenv-- > 0)
		if (!match_and_move(&t, "END:BENV\r\n", &len))
			return FALSE;

	if (!match_and_move(&t, "END:BMSG\r\n", &len))
		return FALSE;

	if (len != 0)
		return FALSE;

	return TRUE;
}

