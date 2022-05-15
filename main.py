from screen import *
from Custom_Widgets.Widgets import *


def change_vol_icon(button, volume_val):
    if volume_val > 70:
        button.setIcon(QIcon(":/icons/icons/volume-2.svg"))
    elif 30 < volume_val < 71:
        button.setIcon(QIcon(":/icons/icons/volume-1.svg"))
    elif 0 < volume_val < 31:
        button.setIcon(QIcon(":/icons/icons/volume.svg"))
    elif volume_val == 0:
        button.setIcon(QIcon(":/icons/icons/volume-x.svg"))


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        QMainWindow.__init__(self)
        self.parent = parent
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        # add Json Stylesheet to app
        loadJsonStyle(self, self.ui)
        # set Data and Time in footer
        timer = QTimer(self)
        timer.timeout.connect(self.showtime)
        timer.start()
        # change weekend color
        saturday_format = self.ui.calendarWidget.weekdayTextFormat(Qt.Saturday)
        saturday_format.setForeground(QBrush(QColor(200, 80, 112), Qt.SolidPattern))
        self.ui.calendarWidget.setWeekdayTextFormat(Qt.Saturday, saturday_format)
        sunday_format = self.ui.calendarWidget.weekdayTextFormat(Qt.Sunday)
        sunday_format.setForeground(QBrush(QColor(255, 70, 110), Qt.SolidPattern))
        self.ui.calendarWidget.setWeekdayTextFormat(Qt.Sunday, sunday_format)
        # Show Center Menu
        self.ui.btnSettings.clicked.connect(lambda: self.ui.center_menu.expandMenu())
        self.ui.btnInfo.clicked.connect(lambda: self.ui.center_menu.expandMenu())
        self.ui.btnHelp.clicked.connect(lambda: self.ui.center_menu.expandMenu())
        # Close Center Menu
        self.ui.closeCenterMenuBtn.clicked.connect(lambda: self.ui.center_menu.collapseMenu())
        # Show Right Menu
        self.ui.btnProfile.clicked.connect(lambda: self.ui.right_menu_container.expandMenu())
        self.ui.btnMore.clicked.connect(lambda: self.ui.right_menu_container.expandMenu())
        # Close Right Menu
        self.ui.closeRightMenuBtn.clicked.connect(lambda: self.ui.right_menu_container.collapseMenu())
        # Close Notification
        self.ui.closeNotificationBtn.clicked.connect(lambda: self.ui.popup_notification_container.collapseMenu())
        # Adapt for Volume Slider Change
        self.ui.volumeSlider.valueChanged.connect(self.adapt_volume)
        self.ui.volumeSlider_2.valueChanged.connect(self.adapt_volume_2)
        # Mute Volume on Click Volume Button
        self.ui.btnVolume.clicked.connect(self.control_volume_mute)
        self.ui.btnVolume_2.clicked.connect(self.control_volume_mute_2)

    def adapt_volume(self):
        current_val = self.ui.volumeSlider.value()
        self.ui.labelVolume.setText(str(current_val))
        change_vol_icon(self.ui.btnVolume, current_val)

    def adapt_volume_2(self):
        current_val = self.ui.volumeSlider_2.value()
        self.ui.labelVolume_2.setText(str(current_val))
        change_vol_icon(self.ui.btnVolume_2, current_val)

    def control_volume_mute(self):
        if self.ui.btnVolume.isChecked():
            self.ui.btnVolume.setIcon(QIcon(":/icons/icons/volume-x.svg"))
            self.ui.volumeSlider.setDisabled(True)
        else:
            self.ui.volumeSlider.setDisabled(False)
            change_vol_icon(self.ui.btnVolume, self.ui.volumeSlider.value())

    def control_volume_mute_2(self):
        if self.ui.btnVolume_2.isChecked():
            self.ui.btnVolume_2.setIcon(QIcon(":/icons/icons/volume-x.svg"))
            self.ui.volumeSlider_2.setDisabled(True)
        else:
            self.ui.volumeSlider_2.setDisabled(False)
            change_vol_icon(self.ui.btnVolume_2, self.ui.volumeSlider_2.value())

    def showtime(self):
        DateTime = QDateTime.currentDateTime()
        date_str = DateTime.toString("dd/MM/yyyy")
        time_str = DateTime.toString("hh:mm AP")
        self.ui.dateShowLabel.setText("Date: " + date_str)
        self.ui.timeShowLabel.setText("Time: " + time_str)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
