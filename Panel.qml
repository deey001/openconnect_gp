import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "openconnect-gp"
  ipcTarget: "openconnect-gp"

  readonly property string ocgpBin: "/usr/local/bin/ocgp"
  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property color dim: Qt.darker(foreground, 1.45)
  readonly property color iconColor: {
    if (stateName === "error") return urgent
    if (stateName === "connected" || stateName === "connecting") return foreground
    return dim
  }

  property string stateName: "disconnected"
  property string portal: ""
  property string username: ""
  property string gateway: ""
  property string ipv4: ""
  property string message: ""
  property string usernameLabel: "Username"
  property string passwordLabel: "Password"
  property var routes: []
  property var extraRoutes: []
  property bool acting: false
  property int phraseIndex: 0
  property string focusSection: "header"
  property bool cursorActive: false
  property string pendingSecret: ""
  property var saveQueue: []

  readonly property var phrases: ["Opening the gate", "Asking the portal", "Leaving home traffic home", "Pinning split routes", "Checking the routes"]
  readonly property var sections: passwordVisible
    ? ["header", "portal", "username", "password", "code", "routes", "action"]
    : ["header", "portal", "username", "routes", "action"]
  readonly property bool passwordVisible: stateName !== "connected"
  readonly property bool up: stateName === "connected" || stateName === "connecting"
  readonly property string heroStatus: {
    if (stateName === "connecting") return phrases[phraseIndex % phrases.length]
    if (stateName === "connected") return ipv4 !== "" ? ipv4 : "Split tunnel"
    if (stateName === "error") return "Failed"
    return "Offline"
  }

  function sectionHasCursor(name) {
    return cursorActive && focusSection === name
  }

  function refreshStatus() {
    if (!statusProc.running) statusProc.running = true
  }

  function applyStatus(text) {
    var data
    try {
      data = JSON.parse(text)
    } catch (error) {
      return
    }
    if (!data) return
    stateName = String(data.state || "disconnected")
    if (!portalField.activeFocus) portal = String(data.portal || "")
    if (!usernameField.activeFocus) username = String(data.username || "")
    gateway = String(data.gateway || "")
    ipv4 = String(data.ipv4 || "")
    routes = data.routes || []
    extraRoutes = data.extra_routes || []
    if (!routesField.activeFocus) routesField.text = extraRoutes.join(", ")
    if (stateName !== "connecting") message = String(data.message || "")
  }

  function saveKey(key, value) {
    saveQueue.push([key, value])
    pumpSave()
  }

  function pumpSave() {
    if (saveProc.running || saveQueue.length === 0) return
    var item = saveQueue.shift()
    saveProc.command = [ocgpBin, "config", "set", item[0], item[1]]
    saveProc.running = true
  }

  function runPrelogin() {
    if (portal === "" || preloginProc.running) return
    preloginProc.running = true
  }

  function connectTunnel() {
    if (acting || stateName === "connected") return
    if (usernameField.text.trim() === "") {
      message = "Username missing"
      usernameField.forceActiveFocus()
      return
    }
    if (passwordField.text === "") {
      message = "Password missing"
      passwordField.forceActiveFocus()
      return
    }
    acting = true
    stateName = "connecting"
    message = ""
    pendingSecret = JSON.stringify({
      password: passwordField.text,
      code: codeField.text
    }) + "\n"
    passwordField.text = ""
    codeField.text = ""
    actionProc.command = [ocgpBin, "connect"]
    actionProc.stdinEnabled = true
    actionProc.running = true
  }

  function disconnectTunnel() {
    if (acting) return
    acting = true
    stateName = "connecting"
    message = ""
    actionProc.command = [ocgpBin, "disconnect"]
    actionProc.stdinEnabled = false
    actionProc.running = true
  }

  function toggleTunnel() {
    if (stateName === "connected") disconnectTunnel()
    else connectTunnel()
  }

  function connectBrowser() {
    if (acting || stateName === "connected") return
    if (usernameField.text.trim() === "") {
      message = "Username missing"
      usernameField.forceActiveFocus()
      return
    }
    acting = true
    stateName = "connecting"
    message = ""
    pendingSecret = ""
    actionProc.command = [ocgpBin, "connect", "--browser"]
    actionProc.stdinEnabled = false
    actionProc.running = true
  }

  function moveCursor(dy) {
    cursorActive = true
    var index = sections.indexOf(focusSection)
    if (index < 0) index = 0
    index = index + dy
    if (index < 0) index = 0
    if (index > sections.length - 1) index = sections.length - 1
    focusSection = sections[index]
  }

  function activateCursor() {
    if (focusSection === "header" || focusSection === "action") toggleTunnel()
    else if (focusSection === "portal") portalField.forceActiveFocus()
    else if (focusSection === "username") usernameField.forceActiveFocus()
    else if (focusSection === "password") passwordField.forceActiveFocus()
    else if (focusSection === "code") codeField.forceActiveFocus()
    else if (focusSection === "routes") routesField.forceActiveFocus()
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  Timer {
    interval: 2000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refreshStatus()
  }

  Timer {
    interval: 1600
    running: root.stateName === "connecting"
    repeat: true
    onTriggered: root.phraseIndex = root.phraseIndex + 1
  }

  Process {
    id: statusProc
    command: [root.ocgpBin, "status"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyStatus(text)
    }
  }

  Process {
    id: preloginProc
    command: [root.ocgpBin, "prelogin"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          root.usernameLabel = String(data.username_label || "Username")
          root.passwordLabel = String(data.password_label || "Password")
        } catch (error) {
          return
        }
      }
    }
  }

  Process {
    id: saveProc
    onExited: function(code) {
      if (code !== 0) root.message = "Could not save that setting"
      root.pumpSave()
      root.refreshStatus()
    }
  }

  Process {
    id: actionProc
    onStarted: {
      if (root.pendingSecret !== "") {
        actionProc.write(root.pendingSecret)
        root.pendingSecret = ""
      }
    }
    stderr: StdioCollector {
      id: actionErrors
      waitForEnd: true
    }
    stdout: StdioCollector {
      id: actionOutput
      waitForEnd: true
    }
    onExited: function(code) {
      root.acting = false
      if (code !== 0) {
        var err = (actionErrors.text || actionOutput.text || "Connection failed").trim()
        root.message = err
        root.stateName = "error"
      }
      root.refreshStatus()
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    iconComponent: Component {
      Item {
        VpnIcon {
          anchors.centerIn: parent
          iconSize: Style.space(11)
          color: root.iconColor
          badgeColor: root.urgent
          connected: root.stateName === "connected"
          failed: root.stateName === "error"
        }
      }
    }
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) root.toggleTunnel()
      else if (buttonCode === Qt.MiddleButton) root.refreshStatus()
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(420))
    contentHeight: panel.fittedContentHeight(column.implicitHeight)

    onOpenChanged: if (open) root.runPrelogin()

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: portalField.activeFocus || usernameField.activeFocus || passwordField.activeFocus || codeField.activeFocus || routesField.activeFocus
      onMoveRequested: function(dx, dy) {
        if (dy !== 0) root.moveCursor(dy)
      }
      onActivateRequested: if (root.cursorActive) root.activateCursor()
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "t" || t === "T") root.toggleTunnel()
        if (t === "r" || t === "R") root.refreshStatus()
      }

      Column {
        id: column
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: Style.space(12)

        Item {
          width: parent.width
          implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight, powerSwitch.implicitHeight)

          VpnIcon {
            id: heroIcon
            iconSize: Style.font.display
            color: root.foreground
            badgeColor: root.urgent
            connected: root.stateName === "connected"
            failed: root.stateName === "error"
            opacity: root.up ? 1 : 0.45
          }

          ToggleSwitch {
            id: powerSwitch
            checked: root.up
            busy: root.acting || root.stateName === "connecting"
            hasCursor: root.sectionHasCursor("header")
            foreground: root.foreground
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            onHovered: function(on) { if (on) { root.cursorActive = true; root.focusSection = "header" } }
            onToggled: root.toggleTunnel()
          }

          Column {
            id: heroLabels
            anchors.left: heroIcon.right
            anchors.leftMargin: Style.space(14)
            anchors.right: powerSwitch.left
            anchors.rightMargin: Style.space(12)
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(2)

            Text {
              text: "GlobalProtect"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
              width: parent.width
              elide: Text.ElideRight
            }

            Text {
              text: root.heroStatus.toUpperCase()
              textFormat: Text.PlainText
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
              font.letterSpacing: 1.1
              width: parent.width
              elide: Text.ElideRight
            }
          }
        }

        PanelSeparator { foreground: root.foreground }

        FieldLabel {
          text: "PORTAL"
          hot: root.sectionHasCursor("portal")
          labelColor: root.dim
          labelFont: root.fontFamily
        }
        TextField {
          id: portalField
          width: parent.width
          text: root.portal
          placeholderText: "vpn.example.com"
          foreground: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          hasCursor: root.sectionHasCursor("portal")
          onTextEdited: root.portal = text
          onEditingFinished: {
            if (text.trim() !== "") root.saveKey("portal", text.trim())
            root.runPrelogin()
          }
          Keys.onEscapePressed: function(event) { focus = false; event.accepted = true }
        }

        FieldLabel {
          text: root.usernameLabel.toUpperCase()
          hot: root.sectionHasCursor("username")
          labelColor: root.dim
          labelFont: root.fontFamily
        }
        TextField {
          id: usernameField
          width: parent.width
          text: root.username
          placeholderText: "name or DOMAIN\\name"
          foreground: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          hasCursor: root.sectionHasCursor("username")
          onTextEdited: root.username = text
          onEditingFinished: root.saveKey("username", text.trim())
          Keys.onEscapePressed: function(event) { focus = false; event.accepted = true }
        }

        FieldLabel {
          visible: root.passwordVisible
          text: root.passwordLabel.toUpperCase()
          hot: root.sectionHasCursor("password")
          labelColor: root.dim
          labelFont: root.fontFamily
        }
        TextField {
          id: passwordField
          visible: root.passwordVisible
          width: parent.width
          password: true
          placeholderText: "Not saved"
          foreground: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          hasCursor: root.sectionHasCursor("password")
          onAccepted: root.connectTunnel()
          Keys.onEscapePressed: function(event) { focus = false; event.accepted = true }
        }

        FieldLabel {
          visible: root.passwordVisible
          text: "CODE IF ASKED"
          hot: root.sectionHasCursor("code")
          labelColor: root.dim
          labelFont: root.fontFamily
        }
        TextField {
          id: codeField
          visible: root.passwordVisible
          width: parent.width
          password: true
          placeholderText: "OTP, blank if none"
          foreground: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          hasCursor: root.sectionHasCursor("code")
          onAccepted: root.connectTunnel()
          Keys.onEscapePressed: function(event) { focus = false; event.accepted = true }
        }

        PanelSeparator { foreground: root.foreground }

        FieldLabel {
          text: root.stateName === "connected" ? "SPLIT ROUTES" : "EXTRA ROUTES"
          hot: root.sectionHasCursor("routes")
          labelColor: root.dim
          labelFont: root.fontFamily
        }

        Text {
          visible: root.stateName === "connected"
          width: parent.width
          text: root.routes.length ? root.routes.join("\n") : "None yet"
          textFormat: Text.PlainText
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          wrapMode: Text.Wrap
        }

        TextField {
          id: routesField
          width: parent.width
          placeholderText: "10.0.0.0/8, 192.168.0.0/16"
          foreground: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          hasCursor: root.sectionHasCursor("routes")
          onEditingFinished: root.saveKey("extra_routes", text.trim())
          Keys.onEscapePressed: function(event) { focus = false; event.accepted = true }
        }

        Text {
          visible: root.gateway !== "" && root.stateName === "connected"
          width: parent.width
          text: "Gateway " + root.gateway
          textFormat: Text.PlainText
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }

        Text {
          visible: root.message !== ""
          width: parent.width
          text: root.message
          textFormat: Text.PlainText
          color: root.urgent
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.Wrap
        }

        Button {
          width: parent.width
          text: root.stateName === "connected" ? "Disconnect" : (root.acting ? "Working" : "Connect")
          hasCursor: root.sectionHasCursor("action")
          foreground: root.foreground
          fontFamily: root.fontFamily
          enabled: !root.acting
          onClicked: root.toggleTunnel()
          onHovered: function(on) { if (on) { root.cursorActive = true; root.focusSection = "action" } }
        }

        Button {
          visible: root.passwordVisible
          width: parent.width
          text: "Browser sign-in"
          foreground: root.foreground
          fontFamily: root.fontFamily
          enabled: !root.acting
          onClicked: root.connectBrowser()
        }

        Text {
          width: parent.width
          text: "Split tunnel. The default route stays on this machine."
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.Wrap
        }
      }
    }
  }

  component FieldLabel: Text {
    property color labelColor: "#c8c8c8"
    property string labelFont: "monospace"
    property bool hot: false
    textFormat: Text.PlainText
    color: labelColor
    font.family: labelFont
    font.pixelSize: Style.font.caption
    font.bold: true
    font.letterSpacing: 1.1
    opacity: hot ? 1 : 0.7
  }
}
