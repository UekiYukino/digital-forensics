# usb_lookup

This program is used to parse USB entries from the `setupapi.dev.log` file which tracks the device connections on a Windows machine</br>
This file is locate at `C:\Windows\INF\setupapi.dev.log` on a Windows 7 and higher systems.

#### Usage:
Run the program using `python <[path_to_program]>`</br>
`Eg: python .\usb_lookup.py`</br>
Then, provide the path to your Setup API log location when the program ask for it.


#### Note:
The program current only works for Windows 7 and higher setupapi logs
