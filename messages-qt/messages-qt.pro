TEMPLATE = lib
CONFIG += staticlib link_pkgconfig

TARGET = messages-qt
DEPENDPATH += . ../plugins ../src
INCLUDEPATH += . ../plugins ../src
PKGCONFIG += glib-2.0
PKGCONFIG += commhistory

# Input
SOURCES += messages-qt.cpp messagepusher.cpp messageupdater.cpp
HEADERS += messages-qt.h messagepusher.h messageupdater.h
HEADERS += messages-qt-log.h

mc.target = maintainer-clean
mc.commands = 
mc.depends = 

QMAKE_EXTRA_TARGETS += mc
