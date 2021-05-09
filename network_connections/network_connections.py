from winreg import *
import requests
import json


def val2addr(val):
    """Retrieve a MAC address value from hex bytes in the Windows Registry"""
    addr = []
    for ch in val:
        try:
            # Try to format and add each of the character of the hex binary to address string
            addr.append("{:02x}".format(ch))
        except:
            continue
    return ":".join(addr[0:6])


def printNets():
    """Received Registry value of connected network"""
    # Look for the connected network in the Windows Registry
    net = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged"
    key = OpenKey(HKEY_LOCAL_MACHINE, net)
    print("[+] Joined Networks: ")

    networks = {}
    counter = 0

    # Generate first 100 index (100 oldest connections)
    for i in range(100):
        try:
            # Enumerate keys using its' index in the registry
            guid = EnumKey(key, i)
            # Open the registry key
            netKey = OpenKey(key, str(guid))

            # Enumerate the key value
            addr = EnumValue(netKey, 5)[1]
            name = EnumValue(netKey, 4)[1]
            CloseKey(netKey)
            mac = val2addr(addr)
            print("|_[+] {} ~ {}".format(name, mac))
            networks[name] = mac
            counter += 1
        except:
            continue
    print("[*] Total Network count: {}".format(counter))
    return networks, counter


def query_mac(mac, api_name, api_token):
    """Make api call to the Wigle api database to retrieve network location base on MAC address"""
    query_url = "https://api.wigle.net/api/v2/network/search?netid={}".format(
        mac)
    req = requests.get(query_url, auth=(api_name, api_token))
    return req.json()


if __name__ == "__main__":
    # Get network that the computer has connected
    networks_dict, count = printNets()
    # Ask user if they want to query the Wigle database
    options = input(
        "Do you want to query Wigle database for the networks location?(y/n) ")

    if options == "y":
        # Start counter for network that query successfully on Wigle
        finished_network = 0

        # Ask user for their credentials and output location
        api_name = input("Enter your api_name for Wigle: ")
        api_token = input("Enter your api_token for Wigle: ")
        out_file = input(
            "Enter your output file name (default: result.json): ") or "result.json"

        # Iterate through the MAC address dictionary and query MAC address against the Wigle database
        for mac in networks_dict.values():
            w_reply = query_mac(
                mac, api_name, api_token)

            # Append result to the file if the query is successful
            if w_reply["success"] == True:
                finished_network += 1
                with open(out_file, "a") as json_output:
                    json.dump(w_reply, json_output)
            # Escape loops and message user if daily query is exceeded
            elif w_reply["message"] == "too many queries today":
                print("[-] Daily query exceeded!")
                break
        print("Finish querying for {}/{} networks! File stored in {}".format(
            finished_network, count, out_file))
    else:
        print("[+] Exiting!")
