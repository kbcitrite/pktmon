# PacketCapture - Windows Packet Capture GUI
PacketCapture provides a GUI for viewing real-time packet captures in Windows using the built-in pktmon.exe tool.

# Usage
Because pktmon.exe requires elevated rights PacketCapture.exe will require administrative rights to run.

Once opened, there are two buttons on the first row to start or stop a trace, a text box that performs regex searches in the info field, and a checkbox to enable or disable auto-scroll:  

![First Row](images/firstrow.png)

The second row includes two sets of text and list boxes where you can add ports or IP addresses to filter on:  

![Second Row](images/secondrow.png)

Clicking Start will stop any running pktmon trace and begin a new one, adding any filters in the listboxes (or none if empty) and display the output in the datagrid:  

![Data Grid](images/events.png)

Check the 'Auto Scroll' box to automatically scroll to new events as they're logged.