package main

import (
	"fmt"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/widgets"
	"os"
	"strconv"
	"strings"
)

// Define a Settings struct to hold the settings for the application
type Settings struct {
	protocols string // list of protocols to capture
	save      bool   // whether to save captured packets to file
	time      int    // how long to capture packets (in milliseconds)
	promisc   bool   // whether to turn the promiscuous mode on
}

func main() {
	// Initialize Qt application
	app := widgets.NewQApplication(len(os.Args), os.Args)

	// Create the main window and set its title
	mainWindow := widgets.NewQMainWindow(nil, 0)
	mainWindow.SetWindowTitle("My Application")

	// Create table widget to display captured packets
	tableWidget := widgets.NewQTableWidget2(0, 10, nil)
	tableWidget.SetVerticalScrollBarPolicy(core.Qt__ScrollBarAlwaysOn)
	tableWidget.SetHorizontalScrollBarPolicy(core.Qt__ScrollBarAlwaysOn)

	// Create header view for the table widget
	headerView := widgets.NewQHeaderView(core.Qt__Horizontal, tableWidget)
	headerView.SetSectionResizeMode(widgets.QHeaderView__ResizeToContents)
	headerView.SetFixedHeight(25)
	headerView.SetStretchLastSection(true)

	// Create the menu bar and add a File menu with three actions
	menuBar := mainWindow.MenuBar()
	fileMenu := menuBar.AddMenu2("File")

	// Define a new instance of Settings struct to store the user's settings
	settings := new(Settings)

	// Add a "Start" action to the File menu that triggers the packet capture process
	startAction := fileMenu.AddAction("Start")
	startAction.ConnectTriggered(func(bool) {
		go Sniff(tableWidget, settings)
	})

	// Add a "Settings" action to the File menu that displays a dialog to configure the application's settings
	settingsAction := fileMenu.AddAction("Settings")
	settingsAction.ConnectTriggered(func(bool) {
		// Create a new dialog window to display the settings options
		dialog := widgets.NewQDialog(mainWindow, core.Qt__Dialog)
		dialog.SetWindowTitle("Settings")
		dialogLayout := widgets.NewQVBoxLayout2(dialog)

		// Create a group box for selecting which protocols to capture
		protocolBox := widgets.NewQGroupBox2("Protocols to capture:", nil)
		protocolLayout := widgets.NewQVBoxLayout2(protocolBox)

		// Create check boxes for each protocol
		tcpCheckbox := widgets.NewQCheckBox2("TCP", nil)
		udpCheckbox := widgets.NewQCheckBox2("UDP", nil)
		sctpCheckbox := widgets.NewQCheckBox2("SCTP", nil)
		icmp4Checkbox := widgets.NewQCheckBox2("ICMP4", nil)
		icmp6Checkbox := widgets.NewQCheckBox2("ICMP6", nil)
		allCheckbox := widgets.NewQCheckBox2("All", nil)

		// Add the checkboxes to the protocol layout
		protocolLayout.AddWidget(tcpCheckbox, 0, core.Qt__AlignLeft)
		protocolLayout.AddWidget(udpCheckbox, 0, core.Qt__AlignLeft)
		protocolLayout.AddWidget(sctpCheckbox, 0, core.Qt__AlignLeft)
		protocolLayout.AddWidget(icmp4Checkbox, 0, core.Qt__AlignLeft)
		protocolLayout.AddWidget(icmp6Checkbox, 0, core.Qt__AlignLeft)
		protocolLayout.AddWidget(allCheckbox, 0, core.Qt__AlignLeft)

		// Create a checkbox for whether to save the captured packets to a file
		saveLabel := widgets.NewQLabel2("Save:", dialog, 0)
		saveCheckbox := widgets.NewQCheckBox2("Save", nil)

		// Create a promisc for whether to turn the promiscuous mode on
		promiscLabel := widgets.NewQLabel2("Promiscuous mode:", dialog, 0)
		promiscCheckbox := widgets.NewQCheckBox2("Promisc", nil)

		// Create a label and a line edit widget for capturing time settings
		timeLabel := widgets.NewQLabel2("Time to capture(ms):", dialog, 0)
		timeEdit := widgets.NewQLineEdit(dialog)

		// Add widgets to dialog layout
		dialogLayout.AddWidget(saveLabel, 0, 0)
		dialogLayout.AddWidget(saveCheckbox, 0, 0)
		dialogLayout.AddWidget(promiscLabel, 0, 0)
		dialogLayout.AddWidget(promiscCheckbox, 0, 0)
		dialogLayout.AddWidget(timeLabel, 0, 0)
		dialogLayout.AddWidget(timeEdit, 0, 0)
		dialogLayout.AddWidget(protocolBox, 0, 0)

		// Create a "Done" button and add it to the dialog layout
		button := widgets.NewQPushButton2("Done", nil)
		dialogLayout.AddWidget(button, 0, 0)

		// Connect the "Done" button to a function that handles the dialog input and closes the dialog
		button.ConnectClicked(func(bool) {
			// Set the protocols setting based on user input
			if allCheckbox.IsChecked() {
				settings.protocols = "all"
			} else {
				var protocolList []string
				if tcpCheckbox.IsChecked() {
					protocolList = append(protocolList, "tcp")
				}
				if udpCheckbox.IsChecked() {
					protocolList = append(protocolList, "udp")
				}
				if sctpCheckbox.IsChecked() {
					protocolList = append(protocolList, "sctp")
				}
				if icmp4Checkbox.IsChecked() {
					protocolList = append(protocolList, "icmp4")
				}
				if icmp6Checkbox.IsChecked() {
					protocolList = append(protocolList, "icmp6")
				}
				settings.protocols = strings.Join(protocolList, " or ")
			}

			// Set the save setting based on user input
			if saveCheckbox.IsChecked() {
				settings.save = true
			} else {
				settings.save = false
			}

			// Set the promisc setting based on user input
			if promiscCheckbox.IsChecked() {
				settings.promisc = true
			} else {
				settings.promisc = false
			}

			// Set the time setting based on user input
			if time := timeEdit.Text(); time != "" {
				timeInt, err := strconv.Atoi(time)
				if err != nil {
					fmt.Println(err)
				} else {
					settings.time = timeInt
				}
			}

			// Close the dialog
			dialog.Close()

		})

		// Execute the dialog
		dialog.Exec()
	})
	// Create an "Exit" action for the file menu and connect it to the QuitDefault function of the application
	exitAction := fileMenu.AddAction("Exit")
	exitAction.ConnectTriggered(func(bool) {
		app.QuitDefault()
	})

	// Create table headers and add them to the table widget
	tableWidget.SetHorizontalHeader(headerView)
	tableWidget.VerticalHeader().SetVisible(true)

	item1 := widgets.NewQTableWidgetItem2("Time", 0)
	item2 := widgets.NewQTableWidgetItem2("Protocol", 0)
	item3 := widgets.NewQTableWidgetItem2("Size", 0)
	item4 := widgets.NewQTableWidgetItem2("SrcIP", 0)
	item5 := widgets.NewQTableWidgetItem2("DstIP", 0)
	item6 := widgets.NewQTableWidgetItem2("SrcPort", 0)
	item7 := widgets.NewQTableWidgetItem2("DstPost", 0)
	item8 := widgets.NewQTableWidgetItem2("Truncated", 0)
	item9 := widgets.NewQTableWidgetItem2("Data", 0)

	tableWidget.SetHorizontalHeaderItem(0, item1)
	tableWidget.SetHorizontalHeaderItem(1, item2)
	tableWidget.SetHorizontalHeaderItem(2, item3)
	tableWidget.SetHorizontalHeaderItem(3, item4)
	tableWidget.SetHorizontalHeaderItem(4, item5)
	tableWidget.SetHorizontalHeaderItem(5, item6)
	tableWidget.SetHorizontalHeaderItem(6, item7)
	tableWidget.SetHorizontalHeaderItem(7, item8)
	tableWidget.SetHorizontalHeaderItem(8, item9)

	mainWindow.SetCentralWidget(tableWidget)

	// Show table widget
	mainWindow.Show()

	// Run Qt application
	app.Exec()
}
