# network_connections

This script is going to extract connected network from a Windows system, which is stored in the `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` of the registry.</br>
Then, it will try to make an API call to Wigle API and query the MAC address to get the location.

#### Wigle API
In order to get the credentials needed for the script, sign up for an account at https://wigle.net/</br>
After you signed in, Select `Account` option under the `Tools` navigation bar 


#### Note
This script need Administrative privilege in order to work properly
