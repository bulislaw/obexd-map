#define _BSD_SOURCE

#include <QCoreApplication>
#include <QDebug>
#include <stdarg.h>
#include <string.h>
#include "messages-qt.h"

extern "C" {
#include <glib.h>

void obex_debug(char *format, ...)
{
	va_list ap;
	QString str;

	va_start(ap, format);

	str.vsprintf(format, ap);
	qDebug() << str;

	va_end(ap);
}

}

void usage(char *argv0)
{
	qDebug() << "Usage: ";
	qDebug() << "\t" << argv0 << "pushmessage REMOTE BODY FOLDER";
	qDebug() << "\t" << argv0 << "setisread HANDLE 0|1";
	qDebug() << "\t" << argv0 << "setdeleted HANDLE 0|1";

	exit(EXIT_FAILURE);
}

void callback(int ret, void *)
{
	if (ret < 0) {
		qDebug() << strerror(-ret);
		return;
	}

	qDebug() << "Id:" << ret;

	QCoreApplication::exit();
}

GMainLoop *loop;

gboolean timeout_dot(void *)
{
	putchar('.');
	fflush(stdout);

	return TRUE;
}

gboolean timeout_process(void *)
{
	puts("Starting");
	fflush(stdout);
	for (int i = 0; i < 20000; ++i) {
		QCoreApplication::processEvents(QEventLoop::WaitForMoreEvents | QEventLoop::AllEvents);
	}
	puts("Quitting");
	fflush(stdout);
	g_main_loop_quit(loop);

	return FALSE;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		usage(argv[0]);

	if (messages_qt_init() < 0) {
		qDebug() << "messages_qt_init() failed!";
		return EXIT_FAILURE;
	}

	QString command(argv[1]);
	int ret;

	if (command == QString("pushmessage")) {
		if (argc != 5)
			usage(argv[0]);
		ret = messages_qt_insert_message(argv[2], argv[3], argv[4],
								callback, NULL);
		qDebug() << strerror(-ret);
		if (ret == 0)
			QCoreApplication::exec();
	} else if (command == QString("setisread")) {
		if (argc != 4)
			usage(argv[0]);
		ret = messages_qt_set_read(argv[2], argv[3][0] == '1');
		qDebug() << strerror(-ret);
	} else if (command == QString("setdeleted")) {
		if (argc != 4)
			usage(argv[0]);
		ret = messages_qt_set_deleted(argv[2], argv[3][0] == '1');
		qDebug() << strerror(-ret);
	} else if (command == QString("looptest")) {
		loop = g_main_loop_new(NULL, FALSE);
		g_timeout_add_seconds(5, timeout_process, NULL);
		g_timeout_add_seconds(1, timeout_dot, NULL);
		g_main_loop_run(loop);
	} else {
		usage(argv[0]);
	}

	messages_qt_exit();
}
