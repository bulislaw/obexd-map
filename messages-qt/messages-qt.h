#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

typedef void (*messages_qt_callback_t)(int id, void *user_data);

int messages_qt_init(void);
void messages_qt_exit(void);
int messages_qt_set_deleted(const char *handle, gboolean deleted);
int messages_qt_set_read(const char *handle, gboolean read);
void messages_qt_insert_message_abort(void *p);
int messages_qt_insert_message(void **p, const char *remote, const char *body,
						const char *folder,
						messages_qt_callback_t callback,
						void *user_data);

#ifdef __cplusplus
}
#endif
