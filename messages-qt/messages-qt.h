#include <glib.h>

int messages_qt_init(void);
void messages_qt_exit(void);
int messages_qt_set_deleted(const char *handle, gboolean deleted);
int messages_qt_set_read(const char *handle, gboolean read);
