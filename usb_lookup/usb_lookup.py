import requests
import sys
import os
import re


def get_vendor_info():
    """Making request to Linux usb information database to retrieve devices information
    : Input: None
    : Output: List of devices and their ids"""

    # Making request to linux usb database
    try:
        print("[+] Retrieving information from database...")
        req = requests.get("http://www.linux-usb.org/usb.ids")
    except:
        print("[-] Could not establish connection! Please try again later!")
        sys.exit(1)

    # Store plaintext data in a string
    usb_data = req.text
    device_info = []
    for line in usb_data.splitlines():

        # Filter results
        # Break if reach other contents list
        if line == "# List of known device classes, subclasses and protocols":
            break
        # Ignore comment lines
        elif line.startswith("#") or line == "":
            continue

        device_info.append(line)
    return device_info


def parse_database_info():
    """Parsing device information on the website to a dictionary
    : Input: None (data is parse from the get_vendor_info() function)
    : Output: A dictionary with vendor ID as the keys and its product as the value"""
    device_info = get_vendor_info()

    vendor_dict = {}
    for info in device_info:
        # Extract id and name information from the device information data
        id_info = info.split("  ")[0]
        name_info = info.split("  ")[1]

        # If the information is not tabed -> vendor information
        if not info.startswith("\t"):
            vendor_dict[id_info] = {}
            vendor_dict[id_info]["name"] = name_info
            vendor_dict[id_info]["products"] = {}
            # Store current vendor id to a parameter
            current_vendor = id_info

        # Process product information
        else:
            # Use the current vendor key to identify which product belong to which vendor
            vendor_dict[current_vendor]["products"][id_info.replace(
                "\t", "")] = name_info
    return vendor_dict


def usb_lookup(vendor_id, product_id, vendor_dict):
    """Lookup USB information using its vendor ID and product ID
    : Input: vendor id, product id and vendor dictionary to lookup
    : Output: vendor name and product name"""
    # Lookup the vendor using vendor_id
    try:
        vendor = vendor_dict[vendor_id]["name"]
    except:
        vendor = "Vendor name not found!"

    # Look up the product using product_id
    try:
        product = vendor_dict[vendor_id]["products"][product_id]
    except:
        product = "Product name not found!"
    return vendor, product


def process_device_info(device_dict):
    """Using regular expression to segregate parameter from the device string
    : Input: Devices dictionary with device string as the key
    : Output: A list of devices information"""

    devices = []
    # for device in device_dict.keys():
    for device, date in device_dict.items():
        # Pre-declare parameters
        vid = ""
        pid = ""
        rev = ""
        uid = ""
        # Compile regex to capture desired information
        # (?:) Use to ignore group capture
        # Capture vendor info
        vendor_capture = re.compile(r"(?:(?:ven)|(?:vid))_(.*?)&")
        vendor_id = vendor_capture.search(device)
        if vendor_id:
            vid = vendor_id.group(1)

        # Capture product info
        product_capture = re.compile(
            r"(?:(?:pid)|(?:dev)|(?:prod))_(.*?)(&|\\)")
        product_id = product_capture.search(device)
        if product_id:
            pid = product_id.group(1)

        # Capture revision info
        revision_capture = re.compile(r"(?:(?:mi)|(?:rev))_(.*?)(\\|,)")
        revision_id = revision_capture.search(device)
        if revision_id:
            rev = revision_id.group(1)

        # Capture uid info
        uid = device.split("\\")[2]
        if vid != "" or pid != "":
            devices.append({"Vendor ID": vid, "Product ID": pid,
                            "Revision": rev, "UID": uid, "First Installation Date": date})
    return devices


def parse_device_from_log(log_file):
    """Parsing the api log file for important data
    : Input: Path to the api log file
    : Output: A dictionary contain the device information string and its install date"""
    # Start declare a dictionary for storing result
    device_dict = {}

    with open(log_file, "r") as api_log:
        for line in api_log:
            # Search for string that indicate installation of new devices
            if "device install (hardware initiated)" in line.lower() and ("ven" in line.lower() or "vid" in line.lower()):
                # Extract information from the line with indicator and the next line which contains the install date
                device_info = line.split(
                    "-")[1].lower().replace("]", "").strip()
                date_install = next(api_log).split(
                    "start")[1].strip().lower()

                # Only add the records that start with "usb" for usb information
                if device_info.startswith("usb"):
                    device_dict[device_info] = date_install
    return device_dict


def parse_device_winxp(log_file):
    """Parsing the api log file from Windows XP for important data 
    : Input: Path to the api log file (Windows XP)
    : Output: A dictionary contain the device information string and its install date"""
    # Initialize device dictionary
    device_dict = {}
    with open(log_file, "r") as api_log:
        for line in api_log:
            # Search for string that indicate installation of new devices
            if "driver install]" in line.lower():
                # Extract the install date and the string after that which indicate the hardware that is installed
                date_install = " ".join(line.split(" ")[
                                        :3]).replace("[", "").strip()
                device_info = next(api_log).split(" ")[-1].strip()

                # Only extract the devices that start with "usb"
                if device_info.startswith("usb"):
                    device_dict[device_info] = date_install
    return device_dict


def main():
    """The main function
    : This function is going to parse the information from log file then look up on the USB database to display informative output"""
    # As user for the log file location
    log_file = input("Enter the path to your log file: ")

    # Check to see if file exist
    if not os.path.isfile(log_file):
        print("[-] Error! File does not exist!")
        sys.exit(1)

    # Prompting users for log type
    win_version = input("Is the log file from Windows XP? (y/n) ")
    while win_version.lower() != ("y" or "n"):
        print("[-] Invalid option! Only (y/n) is allow")
        win_version = input("Is the log file from Windows XP? (y/n) ")

    # Use WinXP parser if the log is from Windows XP system
    if win_version.lower() == "y":
        devices_dict = parse_device_winxp(log_file)

    # Else (From Windows 7 or higher) -> Parse it normally
    else:
        # Parsing device infromation from log file
        devices_dict = parse_device_from_log(log_file)

    # Escape if no entry for USB is found
    if not devices_dict:
        print("[-] Could not find any entry for USB! Exiting...")
        sys.exit(1)
    # Parsing information from the web page and process the information
    vendor_dict = parse_database_info()
    devices = process_device_info(devices_dict)
    for device in devices:
        # Print banner to separate results
        print("{:=^50}".format(""))

        # Lookup the Vendor ID and Product ID to get their names
        vendor, product = usb_lookup(
            device["Vendor ID"], device["Product ID"], vendor_dict)
        print("Vendor Name: {}".format(vendor))
        print("Product Name: {}".format(product))

        # Print out the data received from device string
        for info, data in device.items():
            print("{}: {}".format(info, data))
    print("{:=^50}".format(""))


if __name__ == "__main__":
    main()
