#include <QObject>
#include <CommHistory/Event>
#include <CommHistory/GroupModel>
#include <CommHistory/EventModel>

namespace CommHistory {
	class Group;
};

typedef void (*MessagePusherCallback)(int ret, void *user_data);

class MessagePusher : public QObject {
	Q_OBJECT

public:
	static int push(const char *remote, const char *body,
					const char *folder,
					MessagePusherCallback callback = NULL,
					void *user_data = NULL);

private:
	MessagePusherCallback callback;
	void *user_data;

	CommHistory::GroupModel groupModel;
	CommHistory::EventModel eventModel;

	int groupId;
	int eventId;

	QString remoteUid;
	QString messageBody;
	CommHistory::Event::EventDirection direction;

	MessagePusher();
	void abort(int err);

private slots:
	void eventsCommitted(const QList<CommHistory::Event> &ids, bool success);
	void groupsCommitted(const QList<int> &ids, bool success);
	void modelReady(bool success);
};
