#include <QObject>
#include <CommHistory/Event>
#include <glib.h>

extern "C" {
#include "messages-qt.h"
}

namespace CommHistory {
	class GroupModel;
	class EventModel;
	class Group;
};

class MessagesManager : public QObject {
	Q_OBJECT

public:
	MessagesManager() :
		groupModel(NULL),
		eventModel(NULL),
		event(NULL),
		group(NULL)
	{ }

	int addMessage(const char *remote, const char *body, const char *folder,
						messages_qt_callback_t callback,
						gpointer user_data);

private:
	messages_qt_callback_t callback;
	void *user_data;

	CommHistory::GroupModel *groupModel;
	CommHistory::EventModel *eventModel;
	CommHistory::Event *event;
	CommHistory::Group *group;

	QString remoteUid;
	QString messageBody;
	CommHistory::Event::EventDirection direction;

	void cleanup();
	void abort(int err);

private slots:
	void eventsCommitted(const QList<CommHistory::Event> &ids, bool success);
	void groupsCommitted(const QList<int> &ids, bool success);
	void modelReady(bool success);
};
