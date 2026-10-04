import QtQuick

// Gate mark drawn with rectangles so the bar slot stays sharp at icon size.
Item {
  id: root

  property real iconSize: 11
  property color color: "white"
  property color badgeColor: "#ff5a36"
  property bool connected: false
  property bool failed: false

  width: iconSize
  height: iconSize
  implicitWidth: iconSize
  implicitHeight: iconSize

  Rectangle {
    x: 0
    y: parent.height * 0.18
    width: parent.width
    height: Math.max(1, parent.height * 0.12)
    radius: height / 2
    color: root.color
  }

  Rectangle {
    x: 0
    y: parent.height * 0.18
    width: Math.max(1, parent.width * 0.16)
    height: parent.height * 0.64
    radius: width / 2
    color: root.color
  }

  Rectangle {
    x: parent.width - width
    y: parent.height * 0.18
    width: Math.max(1, parent.width * 0.16)
    height: parent.height * 0.64
    radius: width / 2
    color: root.color
  }

  Rectangle {
    anchors.horizontalCenter: parent.horizontalCenter
    y: parent.height * 0.46
    width: parent.width * 0.42
    height: Math.max(1, parent.height * 0.1)
    radius: height / 2
    color: root.color
    opacity: root.connected ? 1 : 0.35
  }

  Rectangle {
    anchors.horizontalCenter: parent.horizontalCenter
    anchors.bottom: parent.bottom
    width: Math.max(2, parent.width * 0.22)
    height: width
    radius: width / 2
    color: root.failed ? root.badgeColor : root.color
    opacity: root.connected || root.failed ? 1 : 0.35
  }
}
