#ifndef BMSG_PARSER_H
#define BMSG_PARSER_H 1

#define BMSG_NENVELOPES_MAX 3

/* As MAP errata accepted proposal says, LENGTH of bMsg shall include initial
 * "BEGIN:MSG\r\n", the "\r\n" terminating actual data and "END:MSG\r\n".
 */
#define MSG_BLOCK_OVERHEAD (9 + 2 + 2 + 7 + 2)


enum bmsg_type {
	BMSG_T_UNSPECIFIED,
	BMSG_T_SMS_GSM,
	BMSG_T_SMS_CDMA,
	BMSG_T_EMAIL,
	BMSG_T_MMS
};

enum bmsg_encoding {
	BMSG_E_UNSPECIFIED,
	BMSG_E_8BIT,
	BMSG_E_G_7BIT,
	BMSG_E_G_7BITEXT,
	BMSG_E_G_UCS2,
	BMSG_E_G_8BIT,
	BMSG_E_C_8BIT,
	BMSG_E_C_EPM,
	BMSG_E_C_7ASCII,
	BMSG_E_C_IA5,
	BMSG_E_C_UNICODE,
	BMSG_E_C_SJIS,
	BMSG_E_C_KOREAN,
	BMSG_E_C_LATINHEB,
	BMSG_E_C_LATIN
};

enum bmsg_language {
	BMSG_L_UNSPECIFIED,
	BMSG_L_TURKISH,
	BMSG_L_SPANISH,
	BMSG_L_PORTUGUESE,
	BMSG_L_UNKNOWN,
	BMSG_L_ENGLISH,
	BMSG_L_FRENCH,
	BMSG_L_JAPANESE,
	BMSG_L_KOREAN,
	BMSG_L_CHINESE,
	BMSG_L_HEBREW
};

enum bmsg_charset {
	BMSG_C_UNSPECIFIED,
	BMSG_C_UTF8
};

enum bmsg_vcard_version {
	BMSG_VCARD_21,
	BMSG_VCARD_30
};

struct bmsg_bmsg_vcard {
	enum bmsg_vcard_version version;
	char *n;
	char *fn;
	char *tel;
	char *email;
};

struct bmsg_bmsg {
	gboolean read;
	enum bmsg_type type;
	char *folder;
	GSList *originators;
	int nenvelopes;
	GSList *recipients[BMSG_NENVELOPES_MAX];
	long int part_id;
	enum bmsg_encoding encoding;
	enum bmsg_charset charset;
	enum bmsg_language language;
	size_t length;
};

struct bmsg_parser;

struct bmsg_bmsg *bmsg_new(void);
void bmsg_free(struct bmsg_bmsg *bmsg);
struct bmsg_parser *bmsg_parser_new(void);
int bmsg_parser_process(struct bmsg_parser *pd, char **data, size_t len);
struct bmsg_bmsg *bmsg_parser_get_bmsg(struct bmsg_parser *pd);
void bmsg_parser_free(struct bmsg_parser *pd);
gboolean bmsg_parser_tail_correct(struct bmsg_bmsg *bmsg, char *tail, size_t len);


#endif
