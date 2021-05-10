from winreg import *
import requests
import json
import sys
import os


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
    if req.status_code == 200:
        return req.json()
    elif req.status_code == 401:
        print("[-] Invalid credentials!")
        sys.exit(1)
    else:
        print("[-] Exit with status code {}".format(req.status_code))
        sys.exit(1)


if __name__ == "__main__":
    # Get network that the computer has connected
    networks_dict, count = printNets()
    # Ask user if they want to query the Wigle database
    options = input(
        "Do you want to query Wigle database for the networks location? (y/n) ")

    if options == "y":
        # Create a list to store successful queries
        finished_network = []

        # Ask user for their credentials and output location
        api_name = input("Enter your api_name for Wigle: ")
        api_token = input("Enter your api_token for Wigle: ")
        out_file = input(
            "Enter your output file name (default: result.json): ") or "result.json"

        json_result = []
        # Iterate through the MAC address dictionary and query MAC address against the Wigle database
        for mac in networks_dict.values():
            print("[+] Querying for {}...".format(mac))
            w_reply = query_mac(
                mac, api_name, api_token)

            # Append result to the file if the query is successful
            if w_reply["success"] == True:
                finished_network.append[mac]
                print("[+] {} finished".format(mac))
                json_result.append(w_reply)

            # Escape loops and message user if daily query is exceeded
            elif w_reply["message"] == "too many queries today":
                print("[-] Daily query exceeded!")
                break
        print("Finish querying for {}/{} networks!".format(
            len(finished_network), count))

        # Write the results to a file if the result is not empty
        if json_result:
            with open(out_file, "w") as json_output:
                json.dump(json_result, json_output, indent=3)
            print("[+] File store in {}\\".format(os.getcwd(), out_file))

        # Process the unsearched results
        unsearched = []
        for name, address in networks_dict.items():
            if address not in finished_network:
                unsearched.append({name: address})
        with open("unsearched.json", "w") as left_over:
            json.dump(unsearched, left_over, indent=3)
        print(
            "[*] Unsearched addresses will be store in {}\unsearched.json".format(os.getcwd()))

    else:
        print("[+] Exiting!")
